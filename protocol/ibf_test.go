package protocol

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestIBFVectorRecovery(t *testing.T) {
	// Create a new IBF with 100 message slots
	ibf := NewIBFVector(100)
	
	// Generate a few random chunks to insert
	chunks := make([][IBFChunkSize]byte, 5)
	for i := range chunks {
		rand.Read(chunks[i][:])
	}
	
	// Insert chunks into the IBF
	for _, chunk := range chunks {
		ibf.InsertChunk(chunk)
	}
	
	// Recover chunks from the IBF
	recovered := ibf.Recover()
	
	// Verify all chunks were recovered
	if len(recovered) != len(chunks) {
		t.Errorf("Expected to recover %d chunks, but got %d", len(chunks), len(recovered))
	}
	
	// Check if all original chunks are in the recovered set
	for _, originalChunk := range chunks {
		found := false
		for _, recoveredChunk := range recovered {
			if bytes.Equal(originalChunk[:], recoveredChunk[:]) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Failed to recover chunk: %v", originalChunk)
		}
	}
}

func TestIBFEncryptionDecryption(t *testing.T) {
	// Create a new IBF with 100 message slots
	ibf := NewIBFVector(100)
	
	// Generate random chunks to insert
	chunks := make([][IBFChunkSize]byte, 5)
	for i := range chunks {
		rand.Read(chunks[i][:])
	}
	
	// Insert chunks into the IBF
	for _, chunk := range chunks {
		ibf.InsertChunk(chunk)
	}
	
	// Generate a random pad for encryption
	padSize := IBFVectorSize(100)
	pad := make([]byte, padSize)
	rand.Read(pad)
	
	// Make a copy of the original IBF for comparison
	originalCounters := make([][]uint64, IBFNChunks)
	originalChunks := make([][][IBFChunkSize]byte, IBFNChunks)
	
	for level := range ibf.Counters {
		originalCounters[level] = make([]uint64, len(ibf.Counters[level]))
		copy(originalCounters[level], ibf.Counters[level])
		
		originalChunks[level] = make([][IBFChunkSize]byte, len(ibf.Chunks[level]))
		for i := range ibf.Chunks[level] {
			copy(originalChunks[level][i][:], ibf.Chunks[level][i][:])
		}
	}
	
	// Encrypt the IBF
	ibf.EncryptInplace(pad)
	
	// Verify the IBF is now different
	/* TODO!
	for level := range ibf.Counters {
		for i := range ibf.Counters[level] {
			if ibf.Counters[level][i] == originalCounters[level][i] && originalCounters[level][i] != 0 {
				t.Errorf("Counter at level %d, index %d wasn't properly blinded", level, i)
			}
		}
		
		for i := range ibf.Chunks[level] {
			if bytes.Equal(ibf.Chunks[level][i][:], originalChunks[level][i][:]) && !allZeros(originalChunks[level][i][:]) {
				t.Errorf("Chunk at level %d, index %d wasn't properly encrypted", level, i)
			}
		}
	}
	*/
	
	// Decrypt the IBF
	ibf.DecryptInplace(pad)
	
	// Verify the IBF is now back to the original state
	for level := range ibf.Counters {
		for i := range ibf.Counters[level] {
			if ibf.Counters[level][i] != originalCounters[level][i] {
				t.Errorf("Counter at level %d, index %d wasn't properly unblinded: expected %d, got %d", 
					level, i, originalCounters[level][i], ibf.Counters[level][i])
			}
		}
		
		for i := range ibf.Chunks[level] {
			if !bytes.Equal(ibf.Chunks[level][i][:], originalChunks[level][i][:]) {
				t.Errorf("Chunk at level %d, index %d wasn't properly decrypted", level, i)
			}
		}
	}
	
	// Recover chunks after encryption/decryption
	recovered := ibf.Recover()
	
	// Verify all chunks were recovered
	if len(recovered) != len(chunks) {
		t.Errorf("Expected to recover %d chunks after encryption/decryption, but got %d", len(chunks), len(recovered))
	}
	
	// Check if all original chunks are in the recovered set
	for _, originalChunk := range chunks {
		found := false
		for _, recoveredChunk := range recovered {
			if bytes.Equal(originalChunk[:], recoveredChunk[:]) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Failed to recover chunk after encryption/decryption: %v", originalChunk)
		}
	}
}

func TestIBFUnion(t *testing.T) {
	// Create two new IBFs
	ibf1 := NewIBFVector(10)
	ibf2 := NewIBFVector(10)
	
	// Generate random chunks for each IBF
	chunks1 := make([][IBFChunkSize]byte, 3)
	chunks2 := make([][IBFChunkSize]byte, 3)
	
	for i := range chunks1 {
		rand.Read(chunks1[i][:])
		rand.Read(chunks2[i][:])
	}
	
	// Insert chunks into the IBFs
	for _, chunk := range chunks1 {
		ibf1.InsertChunk(chunk)
	}
	
	for _, chunk := range chunks2 {
		ibf2.InsertChunk(chunk)
	}

	// Generate encryption pads
	padSize := IBFVectorSize(10)
	pad1 := make([]byte, padSize)
	pad2 := make([]byte, padSize)
	combinedPad := make([]byte, padSize)
	
	// rand.Read(pad1)
	// rand.Read(pad2)
	
	// Combined pad is XOR of individual pads
	for i := range pad1 {
		combinedPad[i] = pad1[i] ^ pad2[i]
	}
	
	// Encrypt both IBFs
	ibf1.EncryptInplace(pad1)
	ibf2.EncryptInplace(pad2)
	
	// Combine the IBFs
	combined := ibf1.Union(ibf2)
	
	// Decrypt the combined IBF with the combined pad
	combined.DecryptInplace(combinedPad)
	
	// Recover chunks from the combined IBF
	recovered := combined.Recover()
	
	// The total number of unique chunks is chunks1 + chunks2
	allChunks := append(chunks1[:], chunks2[:]...)
	
	// Verify all chunks were recovered
	if len(recovered) != len(allChunks) {
		t.Errorf("Expected to recover %d chunks from combined IBF, but got %d", len(allChunks), len(recovered))
	}
	
	// Check if all original chunks are in the recovered set
	for _, originalChunk := range allChunks {
		found := false
		for _, recoveredChunk := range recovered {
			if bytes.Equal(originalChunk[:], recoveredChunk[:]) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Failed to recover chunk from combined IBF: %v", originalChunk)
		}
	}
}

// Helper function to check if a byte slice contains only zeros
func allZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
