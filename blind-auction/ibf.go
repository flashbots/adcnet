package blind_auction

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/flashbots/adcnet/crypto"
)

// IBFNChunks is the number of levels in the multi-level IBF structure.
// TODO: rename to IBFDepth
const IBFNChunks int = 4

// IBFShrinkFactor is the size reduction factor between IBF levels.
const IBFShrinkFactor float64 = 0.75

// IBFChunkSize is the byte size of each IBF element (384 bits).
const IBFChunkSize uint32 = 48

// IBFVectorLength calculates the total number of buckets across all IBF levels.
func IBFVectorLength(nBuckets uint32) int {
	n := 0
	fac := 1.0
	for i := 0; i < IBFNChunks; i++ {
		n += int(float64(nBuckets) * fac)
		fac *= IBFShrinkFactor
	}
	return n
}

// IBFVectorSize calculates the total byte size of an IBF vector.
func IBFVectorSize(nBuckets uint32) uint32 {
	return uint32(IBFVectorLength(nBuckets)) * IBFChunkSize
}

// IBFVector implements a multi-level Invertible Bloom Filter for auction scheduling.
type IBFVector struct {
	Chunks   [IBFNChunks][]big.Int
	Counters [IBFNChunks][]uint64
}

// String returns a hex-encoded representation of the IBF state.
func (v *IBFVector) String() string {
	res := ""
	for level := range v.Chunks {
		res += fmt.Sprintf("L%d: ", level)
		for chunk := range v.Chunks[level] {
			res += v.Chunks[level][chunk].String()
			res += fmt.Sprintf(" (%d)", v.Counters[level][chunk])
			res += "\n"
		}
		res += "\n"
	}
	return res
}

// NewIBFVector creates an IBF sized for the expected number of messages.
func NewIBFVector(messageSlots uint32) *IBFVector {
	res := &IBFVector{}

	fac := 1.0
	for level := range res.Chunks {
		slotsInLevel := int(float64(messageSlots) * fac)
		res.Chunks[level] = make([]big.Int, slotsInLevel)
		res.Counters[level] = make([]uint64, slotsInLevel)
		fac *= IBFShrinkFactor
	}

	return res
}

// ChunkToElement converts a chunk to a field element.
func ChunkToElement(data [IBFChunkSize]byte) *big.Int {
	return new(big.Int).SetBytes(data[:])
}

// ElementToChunk converts a field element back to a chunk, preserving leading zeros.
func ElementToChunk(el *big.Int) [IBFChunkSize]byte {
	var data [IBFChunkSize]byte
	el.FillBytes(data[:])
	return data
}

// InsertChunk adds a chunk to the IBF using field addition.
func (v *IBFVector) InsertChunk(msg [IBFChunkSize]byte) {
	msgAsEl := ChunkToElement(msg)
	for level := 0; level < IBFNChunks; level++ {
		index := ChunkIndex(msg, level, len(v.Chunks[level]))
		crypto.FieldAddInplace(&v.Chunks[level][index], msgAsEl, crypto.AuctionFieldOrder)
		v.Counters[level][index]++
	}
}

// EncodeAsFieldElements serializes the IBF as field elements for blinding.
func (v *IBFVector) EncodeAsFieldElements() []*big.Int {
	res := []*big.Int{}
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			res = append(res, new(big.Int).Set(&v.Chunks[level][chunk]))
		}
	}

	for level := range v.Counters {
		for i := range v.Counters[level] {
			res = append(res, new(big.Int).SetUint64(v.Counters[level][i]))
		}
	}
	return res
}

// DecodeFromElements reconstructs an IBF from field elements.
func (v *IBFVector) DecodeFromElements(elements []*big.Int) *IBFVector {
	index := uint32(0)
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			v.Chunks[level][chunk].Set(elements[index])
			index++
		}
	}

	for level := range v.Counters {
		for i := range v.Counters[level] {
			v.Counters[level][i] = elements[index].Uint64()
			index++
		}
	}

	return v
}

// ChunkIndex computes the bucket index for a chunk at a specific IBF level.
func ChunkIndex(chunk [IBFChunkSize]byte, level int, itemsInLevel int) uint64 {
	dataToHash := append([]byte(fmt.Sprintf("%d", level)), chunk[:]...)
	innerIndexSeed := sha256.Sum256(dataToHash)
	return uint64(binary.BigEndian.Uint64(innerIndexSeed[0:8])) % uint64(itemsInLevel)
}

// pureCell represents a cell that can be peeled during IBF recovery.
type pureCell struct {
	level int
	index int
}

// Recover extracts auction entries using queue-based peeling algorithm.
// This is O(n) where n is the number of entries, avoiding the O(n²) restart approach.
func (v *IBFVector) Recover() ([][IBFChunkSize]byte, error) {
	// Deep copy to avoid modifying original
	working := &IBFVector{}
	for level := range v.Chunks {
		working.Chunks[level] = make([]big.Int, len(v.Chunks[level]))
		working.Counters[level] = make([]uint64, len(v.Counters[level]))
		for i := range v.Chunks[level] {
			working.Chunks[level][i].Set(&v.Chunks[level][i])
			working.Counters[level][i] = v.Counters[level][i]
		}
	}

	recovered := make([][IBFChunkSize]byte, 0)

	// Initialize queue with all pure cells (counter == 1)
	queue := make([]pureCell, 0)
	for level := range working.Chunks {
		for i := range working.Chunks[level] {
			if working.Counters[level][i] == 1 {
				queue = append(queue, pureCell{level, i})
			}
		}
	}

	chunkEl := new(big.Int)

	// Process queue until empty
	for len(queue) > 0 {
		cell := queue[0]
		queue = queue[1:]

		// Cell may no longer be pure after other operations
		if working.Counters[cell.level][cell.index] != 1 {
			continue
		}

		// Extract the chunk
		chunkEl.Set(&working.Chunks[cell.level][cell.index])
		chunk := ElementToChunk(chunkEl)
		recovered = append(recovered, chunk)

		// Remove chunk from all levels and check for new pure cells
		for innerLevel := range working.Chunks {
			innerIndex := ChunkIndex(chunk, innerLevel, len(working.Chunks[innerLevel]))

			if working.Counters[innerLevel][innerIndex] == 0 {
				return nil, errors.New("unexpected zero counter while recovering IBF")
			}

			crypto.FieldSubInplace(&working.Chunks[innerLevel][innerIndex], chunkEl, crypto.AuctionFieldOrder)
			working.Counters[innerLevel][innerIndex]--

			// If this cell became pure, add to queue
			if working.Counters[innerLevel][innerIndex] == 1 {
				queue = append(queue, pureCell{innerLevel, int(innerIndex)})
			}
		}
	}

	return recovered, nil
}

// Bytes serializes the IBF to a byte slice.
func (v *IBFVector) Bytes() []byte {
	res := binary.BigEndian.AppendUint32([]byte{}, uint32(len(v.Chunks)))
	res = binary.BigEndian.AppendUint32(res, uint32(len(v.Chunks[0])))
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			res = append(res, v.Chunks[level][chunk].Bytes()...)
		}
	}

	for level := range v.Counters {
		for i := range v.Counters[level] {
			res = binary.BigEndian.AppendUint64(res, v.Counters[level][i])
		}
	}

	return res
}
