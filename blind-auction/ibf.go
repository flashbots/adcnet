package blind_auction

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/flashbots/adcnet/crypto"
)

// IBFNChunks defines the number of levels in the multi-level IBF structure.
const IBFNChunks int = 4

// IBFShrinkFactor defines the size reduction factor between IBF levels.
const IBFShrinkFactor float64 = 0.75

// IBFChunkSize defines the byte size of each IBF element (384 bits for AuctionFieldOrder).
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

// IBFVector implements a multi-level Invertible Bloom Filter for distributed auction scheduling.
// The IBF is secret-shared across servers and reconstructed after threshold decryption.
type IBFVector struct {
	Chunks   [IBFNChunks][][IBFChunkSize]byte
	Counters [IBFNChunks][]uint64
}

// String returns a hex-encoded representation of the IBF state.
func (v *IBFVector) String() string {
	res := ""
	for level := range v.Chunks {
		res += fmt.Sprintf("L%d: ", level)
		for chunk := range v.Chunks[level] {
			res += hex.EncodeToString(v.Chunks[level][chunk][:])
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
		res.Chunks[level] = make([][IBFChunkSize]byte, slotsInLevel)
		res.Counters[level] = make([]uint64, slotsInLevel)
		fac *= IBFShrinkFactor
	}

	return res
}

// ChunkToElement converts a chunk to a field element in AuctionFieldOrder.
func ChunkToElement(data [IBFChunkSize]byte) *big.Int {
	return new(big.Int).SetBytes(data[:])
}

// ElementToChunk converts a field element back to a chunk, preserving leading zeros.
func ElementToChunk(el *big.Int) [IBFChunkSize]byte {
	var data [IBFChunkSize]byte
	el.FillBytes(data[:])
	return data
}

// InsertChunk adds a chunk to the IBF using field addition in AuctionFieldOrder.
func (v *IBFVector) InsertChunk(msg [IBFChunkSize]byte) {
	msgAsEl := ChunkToElement(msg)
	for level := 0; level < IBFNChunks; level++ {
		index := ChunkIndex(msg, level, len(v.Chunks[level]))

		currentEl := ChunkToElement(v.Chunks[level][index])
		crypto.FieldAddInplace(currentEl, msgAsEl, crypto.AuctionFieldOrder)
		v.Chunks[level][index] = ElementToChunk(currentEl)
		v.Counters[level][index] += 1
	}
}

// EncodeAsFieldElements serializes the IBF as field elements for secret sharing.
// Operates in AuctionFieldOrder (384-bit) for compatibility with the protocol.
func (v *IBFVector) EncodeAsFieldElements() []*big.Int {
	res := []*big.Int{}
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			res = append(res, ChunkToElement(v.Chunks[level][chunk]))
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
			v.Chunks[level][chunk] = ElementToChunk(elements[index])
			index += 1
		}
	}

	for level := range v.Counters {
		for i := range v.Counters[level] {
			v.Counters[level][i] = elements[index].Uint64()
			index += 1
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

// Recover extracts auction entries from the reconstructed IBF using the peeling algorithm.
// Called after threshold decryption to determine next round's message scheduling.
func (v *IBFVector) Recover() ([][IBFChunkSize]byte, error) {
	// Create a copy of the IBF to work with during recovery
	workingCopy := &IBFVector{}

	// Deep copy chunks and counters
	for level := range v.Chunks {
		workingCopy.Chunks[level] = make([][IBFChunkSize]byte, len(v.Chunks[level]))
		workingCopy.Counters[level] = make([]uint64, len(v.Counters[level]))

		for i := range v.Chunks[level] {
			copy(workingCopy.Chunks[level][i][:], v.Chunks[level][i][:])
			workingCopy.Counters[level][i] = v.Counters[level][i]
		}
	}

	// Store recovered elements
	recovered := make([][IBFChunkSize]byte, 0)

	// Keep track of whether we made progress in the current iteration
	madeProgress := true

	// Continue peeling until no more progress can be made
	for madeProgress {
		madeProgress = false

		// Check each level for pure cells (counter = 1)
		for level := range workingCopy.Chunks {
			for i := range workingCopy.Chunks[level] {
				// Found a pure cell
				if workingCopy.Counters[level][i] == 1 {
					// Get the chunk from this cell
					chunk := workingCopy.Chunks[level][i]

					// Record this chunk as recovered
					recovered = append(recovered, chunk)
					chunkAsEl := ChunkToElement(chunk)

					// Remove this chunk from all levels to continue peeling
					for innerLevel := range workingCopy.Chunks {
						innerIndex := ChunkIndex(chunk, innerLevel, len(workingCopy.Chunks[innerLevel]))

						// Decrement the counter
						if workingCopy.Counters[innerLevel][innerIndex] == 0 {
							return nil, errors.New("unexpected zero counter while recovering IBF")
						}

						// Remove the chunk from this cell
						currentEl := ChunkToElement(workingCopy.Chunks[innerLevel][innerIndex])
						crypto.FieldSubInplace(currentEl, chunkAsEl, crypto.AuctionFieldOrder)
						workingCopy.Chunks[innerLevel][innerIndex] = ElementToChunk(currentEl)

						workingCopy.Counters[innerLevel][innerIndex]--
					}

					// We made progress in this iteration
					madeProgress = true

					// Since we modified the IBF, start checking from the beginning again
					break
				}
			}

			if madeProgress {
				break
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
			res = append(res, v.Chunks[level][chunk][:]...)
		}
	}

	for level := range v.Counters {
		for i := range v.Counters[level] {
			res = binary.BigEndian.AppendUint64(res, v.Counters[level][i])
		}
	}

	return res
}
