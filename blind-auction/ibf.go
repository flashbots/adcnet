package blind_auction

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/flashbots/adcnet/crypto"
)

// IBLTNChunks is the number of levels in the multi-level IBLT structure.
// TODO: rename to IBLTDepth
const IBLTNChunks int = 4

// IBLTShrinkFactor is the size reduction factor between IBLT levels.
const IBLTShrinkFactor float64 = 0.75

// IBLTChunkSize is the byte size of each IBLT element (384 bits).
const IBLTChunkSize uint32 = 48

// IBLTVectorLength calculates the total number of buckets across all IBLT levels.
func IBLTVectorLength(nBuckets uint32) int {
	n := 0
	fac := 1.0
	for i := 0; i < IBLTNChunks; i++ {
		n += int(float64(nBuckets) * fac)
		fac *= IBLTShrinkFactor
	}
	return n
}

// IBLTVectorSize calculates the total byte size of an IBLT vector.
func IBLTVectorSize(nBuckets uint32) uint32 {
	return uint32(IBLTVectorLength(nBuckets)) * IBLTChunkSize
}

// IBLTVector implements a multi-level Invertible Bloom Lookup Table for auction scheduling.
type IBLTVector struct {
	Chunks   [IBLTNChunks][]big.Int
	Counters [IBLTNChunks][]uint64
}

// String returns a hex-encoded representation of the IBLT state.
func (v *IBLTVector) String() string {
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

// NewIBLTVector creates an IBLT sized for the expected number of messages.
func NewIBLTVector(messageSlots uint32) *IBLTVector {
	res := &IBLTVector{}

	fac := 1.0
	for level := range res.Chunks {
		slotsInLevel := int(float64(messageSlots) * fac)
		res.Chunks[level] = make([]big.Int, slotsInLevel)
		res.Counters[level] = make([]uint64, slotsInLevel)
		fac *= IBLTShrinkFactor
	}

	return res
}

// ChunkToElement converts a chunk to a field element.
func ChunkToElement(data [IBLTChunkSize]byte) *big.Int {
	return new(big.Int).SetBytes(data[:])
}

// ElementToChunk converts a field element back to a chunk, preserving leading zeros.
func ElementToChunk(el *big.Int) [IBLTChunkSize]byte {
	var data [IBLTChunkSize]byte
	el.FillBytes(data[:])
	return data
}

// InsertChunk adds a chunk to the IBLT using field addition.
func (v *IBLTVector) InsertChunk(msg [IBLTChunkSize]byte) {
	msgAsEl := ChunkToElement(msg)
	for level := 0; level < IBLTNChunks; level++ {
		index := ChunkIndex(msg, level, len(v.Chunks[level]))
		crypto.FieldAddInplace(&v.Chunks[level][index], msgAsEl, crypto.AuctionFieldOrder)
		v.Counters[level][index]++
	}
}

// EncodeAsFieldElements serializes the IBLT as field elements for blinding.
func (v *IBLTVector) EncodeAsFieldElements() []*big.Int {
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

// DecodeFromElements reconstructs an IBLT from field elements.
func (v *IBLTVector) DecodeFromElements(elements []*big.Int) *IBLTVector {
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

// ChunkIndex computes the bucket index for a chunk at a specific IBLT level.
func ChunkIndex(chunk [IBLTChunkSize]byte, level int, itemsInLevel int) uint64 {
	dataToHash := append([]byte(fmt.Sprintf("%d", level)), chunk[:]...)
	innerIndexSeed := sha256.Sum256(dataToHash)
	return uint64(binary.BigEndian.Uint64(innerIndexSeed[0:8])) % uint64(itemsInLevel)
}

// pureCell represents a cell that can be peeled during IBLT recovery.
type pureCell struct {
	level int
	index int
}

// Recover extracts auction entries using queue-based peeling algorithm.
// This is O(n) where n is the number of entries, avoiding the O(n²) restart approach.
func (v *IBLTVector) Recover() ([][IBLTChunkSize]byte, error) {
	// Deep copy to avoid modifying original
	working := &IBLTVector{}
	for level := range v.Chunks {
		working.Chunks[level] = make([]big.Int, len(v.Chunks[level]))
		working.Counters[level] = make([]uint64, len(v.Counters[level]))
		for i := range v.Chunks[level] {
			working.Chunks[level][i].Set(&v.Chunks[level][i])
			working.Counters[level][i] = v.Counters[level][i]
		}
	}

	recovered := make([][IBLTChunkSize]byte, 0)

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
				return nil, errors.New("unexpected zero counter while recovering IBLT")
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

// Bytes serializes the IBLT to a byte slice.
func (v *IBLTVector) Bytes() []byte {
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
