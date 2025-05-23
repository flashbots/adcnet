package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/flashbots/adcnet/crypto"
)

const IBFNChunks int = 3 // TODO: rename to levels
const IBFShrinkFactor float64 = 0.75
const IBFChunkSize uint32 = 48

func IBFVectorLength(nBuckets uint32) int {
	n := 0
	fac := 1.0
	for i := 0; i < IBFNChunks; i++ {
		n += int(float64(nBuckets) * fac)
		fac *= IBFShrinkFactor
	}
	return n
}

func IBFVectorSize(nBuckets uint32) uint32 {
	return uint32(IBFVectorLength(nBuckets)) * IBFChunkSize
}

type IBFVector struct {
	Chunks   [IBFNChunks][][IBFChunkSize]byte
	Counters [IBFNChunks][]uint64
}

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

func (v *IBFVector) InsertChunk(msg [IBFChunkSize]byte) {
	for level := 0; level < IBFNChunks; level++ {
		dataToHash := append([]byte(fmt.Sprintf("%d", level)), msg[:]...)
		indexSeed := sha256.Sum256(dataToHash)
		index := uint64(binary.BigEndian.Uint64(indexSeed[0:8])) % uint64(len(v.Chunks[level]))

		crypto.XorInplace(v.Chunks[level][index][:], msg[:])
		v.Counters[level][index] += 1
	}
}

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

func (v *IBFVector) EncryptInplace(ibfVectorPad AuctionPad, counterBlinders CountersPad) {
	index := uint32(0)
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			crypto.XorInplace(v.Chunks[level][chunk][:], ibfVectorPad[index:index+IBFChunkSize])
			index += IBFChunkSize
		}
	}

	// Blind counters using derived values from the pad
	counterPadIndex := 0
	for level := range v.Counters {
		for i := range v.Counters[level] {
			// Blind the counter
			v.Counters[level][i] = BlindCounter(v.Counters[level][i], counterBlinders[counterPadIndex])

			counterPadIndex++
		}
	}
}

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

func (v *IBFVector) Encrypt(ibfVectorPad []byte, counterBlinders CountersPad) *IBFVector {
	res := v.Clone()
	res.EncryptInplace(ibfVectorPad, counterBlinders)
	return res
}

func (v *IBFVector) DecryptInplace(ibfVectorPad []byte, counterBlinders CountersPad) {
	index := uint32(0)
	for level := range v.Chunks {
		for chunk := range v.Chunks[level] {
			crypto.XorInplace(v.Chunks[level][chunk][:], ibfVectorPad[index:index+IBFChunkSize])
			index += IBFChunkSize
		}
	}

	// Unblind counters
	counterPadIndex := 0
	for level := range v.Counters {
		for i := range v.Counters[level] {
			v.Counters[level][i] = uint64(UnblindCounter(v.Counters[level][i], counterBlinders[counterPadIndex]))
			counterPadIndex += 1
		}
	}
}

func (v *IBFVector) Decrypt(ibfVectorPad []byte, counterBlinders CountersPad) *IBFVector {
	// TODO: deep copy
	res := &(*v)
	res.DecryptInplace(ibfVectorPad, counterBlinders)
	return res
}

func (v *IBFVector) UnionInplace(other *IBFVector) {
	for level := range v.Counters {
		for chunk := range v.Chunks[level] {
			crypto.XorInplace(v.Chunks[level][chunk][:], other.Chunks[level][chunk][:])
			v.Counters[level][chunk] = AddBlindedCounters(v.Counters[level][chunk], other.Counters[level][chunk])
		}
	}
}

func (v *IBFVector) Union(other *IBFVector) *IBFVector {
	// TODO: deep copy
	res := &(*v)
	res.UnionInplace(other)
	return res
}

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
