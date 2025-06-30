package blind_auction

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/flashbots/adcnet/crypto"
)

const IBFNChunks int = 3 // TODO: rename to levels
const IBFShrinkFactor float64 = 0.75
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

// IBFVector implements an Invertible Bloom Filter for auction data.
// Recovery success depends on collision probability.
// No integrity protection; vulnerable to bit manipulation.
type IBFVector struct {
	Chunks   [IBFNChunks][][IBFChunkSize]byte
	Counters [IBFNChunks][]uint64
}

// String returns a human-readable representation of the IBF.
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

// NewIBFVector creates a new IBF with the specified number of message slots.
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

// Clone creates a deep copy of the IBF vector.
func (v *IBFVector) Clone() *IBFVector {
	newCopy := &IBFVector{}
	for level := range v.Chunks {
		newCopy.Counters[level] = make([]uint64, len(v.Counters[level]))
		copy(newCopy.Counters[level], v.Counters[level])

		newCopy.Chunks[level] = make([][IBFChunkSize]byte, len(v.Chunks[level]))
		for i := range v.Chunks[level] {
			copy(newCopy.Chunks[level][i][:], v.Chunks[level][i][:])
		}
	}

	return newCopy
}

// Bytes serializes the IBF vector to a byte slice.
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

// InsertChunk inserts a chunk into the IBF at appropriate positions across all levels.
func (v *IBFVector) InsertChunk(msg [IBFChunkSize]byte) {
	for level := 0; level < IBFNChunks; level++ {
		dataToHash := append([]byte(fmt.Sprintf("%d", level)), msg[:]...)
		indexSeed := sha256.Sum256(dataToHash)
		index := uint64(binary.BigEndian.Uint64(indexSeed[0:8])) % uint64(len(v.Chunks[level]))

		crypto.XorInplace(v.Chunks[level][index][:], msg[:])
		v.Counters[level][index] += 1
	}
}

func (v *IBFVector) EncodeAsFieldElements() []*big.Int {
	res := []*big.Int{}
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			res = append(res, new(big.Int).SetBytes(v.Chunks[level][chunk][:]))
		}
	}

	// Blind counters using derived values from the pad
	for level := range v.Counters {
		for i := range v.Counters[level] {
			res = append(res, new(big.Int).SetUint64(v.Counters[level][i]))
		}
	}
	return res
}

// DecodeFromElements decodes elements into an IBF vector
func (v *IBFVector) DecodeFromElements(elements []*big.Int) *IBFVector {
	index := uint32(0)
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			copy(v.Chunks[level][chunk][:], elements[index].Bytes())
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

/*
// UnionInplace merges another IBF into this one by XORing chunks and adding counters.
func (v *IBFVector) UnionInplace(other *IBFVector) *IBFVector {
	for level := range v.Counters {
		for chunk := range v.Chunks[level] {
			crypto.XorInplace(v.Chunks[level][chunk][:], other.Chunks[level][chunk][:])
			v.Counters[level][chunk] = AddBlindedCounters(v.Counters[level][chunk], other.Counters[level][chunk])
		}
	}

	return v
}
*/

// Recover attempts to extract all elements from the IBF.
// No guarantee of complete recovery or detection of missing elements.
func (v *IBFVector) Recover() [][IBFChunkSize]byte {
	// Create a copy of the IBF to work with during recovery
	// so we don't modify the original
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

					// Remove this chunk from all levels to continue peeling
					for innerLevel := range workingCopy.Chunks {
						dataToHash := append([]byte(fmt.Sprintf("%d", innerLevel)), chunk[:]...)
						innerIndexSeed := sha256.Sum256(dataToHash)
						innerIndex := uint64(binary.BigEndian.Uint64(innerIndexSeed[0:8])) % uint64(len(v.Chunks[innerLevel]))

						// XOR out the chunk from this cell
						crypto.XorInplace(workingCopy.Chunks[innerLevel][innerIndex][:], chunk[:])

						// Decrement the counter
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

	return recovered
}
