package protocol

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
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

	originalIBF := ibf.Clone()

	counterPads, _ := GenCounterBlinders([]byte{1}, int(IBFVectorLength(100)))

	// Encrypt the IBF
	ibf.EncryptInplace(pad, counterPads)

	// Verify the IBF is now different
	for level := range ibf.Counters {
		for i := range ibf.Counters[level] {
			if ibf.Counters[level][i] == originalIBF.Counters[level][i] && originalIBF.Counters[level][i] != 0 {
				t.Errorf("Counter at level %d, index %d wasn't properly blinded", level, i)
			}
		}

		for i := range ibf.Chunks[level] {
			if bytes.Equal(ibf.Chunks[level][i][:], originalIBF.Chunks[level][i][:]) && !allZeros(originalIBF.Chunks[level][i][:]) {
				t.Errorf("Chunk at level %d, index %d wasn't properly encrypted", level, i)
			}
		}
	}

	// Decrypt the IBF
	ibf.DecryptInplace(pad, counterPads)

	// Verify the IBF is now back to the original state
	for level := range ibf.Counters {
		for i := range ibf.Counters[level] {
			if ibf.Counters[level][i] != originalIBF.Counters[level][i] {
				t.Errorf("Counter at level %d, index %d wasn't properly unblinded: expected %d, got %d",
					level, i, originalIBF.Counters[level][i], ibf.Counters[level][i])
			}
		}

		for i := range ibf.Chunks[level] {
			if !bytes.Equal(ibf.Chunks[level][i][:], originalIBF.Chunks[level][i][:]) {
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

	rand.Read(pad1)
	rand.Read(pad2)

	counterPads1, _ := GenCounterBlinders([]byte{1}, IBFVectorLength(10))
	counterPads2, _ := GenCounterBlinders([]byte{2}, IBFVectorLength(10))

	// Combined pad is XOR of individual pads
	for i := range pad1 {
		combinedPad[i] = pad1[i] ^ pad2[i]
	}

	// Encrypt both IBFs
	ibf1.EncryptInplace(pad1, counterPads1)
	ibf2.EncryptInplace(pad2, counterPads2)

	// Combine the IBFs
	combined := ibf1.Union(ibf2)

	combinedCounterPads := make([]uint64, len(counterPads1))
	UnionCounterPadsInplace(combinedCounterPads, counterPads1)
	UnionCounterPadsInplace(combinedCounterPads, counterPads2)

	// Decrypt the combined IBF with the combined pad
	combined.DecryptInplace(combinedPad, combinedCounterPads)

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

func TestCountersE2E(t *testing.T) {
	client1server1SharedKey := make([]byte, 32)
	client2server1SharedKey := make([]byte, 32)

	auctionPad := make([]byte, IBFVectorSize(10))

	rand.Read(client1server1SharedKey)
	rand.Read(client2server1SharedKey)

	nCounters := IBFVectorLength(10)

	// Client 1
	client1server1counterBlinders, _ := GenCounterBlinders(client1server1SharedKey, nCounters)

	client1Message := AuctionDataFromMessage([]byte("abdc"), 5)
	client1AuctionIBF := NewIBFVector(10)
	client1AuctionIBF.InsertChunk(client1Message.EncodeToChunk())
	client1AuctionIBF.EncryptInplace(auctionPad, client1server1counterBlinders)

	// Client 2
	client2server1counterBlinders, _ := GenCounterBlinders(client2server1SharedKey, nCounters)

	client2Message := AuctionDataFromMessage([]byte("abde"), 6)
	client2AuctionIBF := NewIBFVector(10)
	client2AuctionIBF.InsertChunk(client2Message.EncodeToChunk())
	client2AuctionIBF.EncryptInplace(auctionPad, client2server1counterBlinders)

	// Aggregator
	aggregatorIBFVector := NewIBFVector(10)
	aggregatorIBFVector.UnionInplace(client1AuctionIBF)
	aggregatorIBFVector.UnionInplace(client2AuctionIBF)

	// Server
	serverIBFVector := NewIBFVector(10)
	serverIBFVector.UnionInplace(aggregatorIBFVector)

	serverCounterBlinders := make([]uint64, nCounters)
	client1server1counterBlinders2, _ := GenCounterBlinders(client1server1SharedKey, nCounters)
	UnionCounterPadsInplace(serverCounterBlinders, client1server1counterBlinders2)

	client2server1counterBlinders2, _ := GenCounterBlinders(client2server1SharedKey, nCounters)
	UnionCounterPadsInplace(serverCounterBlinders, client2server1counterBlinders2)

	unblindedAuction := serverIBFVector.Decrypt(auctionPad, serverCounterBlinders)
	chunks := unblindedAuction.Recover()
	require.Equal(t, 2, len(chunks))

	require.Contains(t, chunks, client1Message.EncodeToChunk())
	require.Contains(t, chunks, client2Message.EncodeToChunk())
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
