package blind_auction

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/require"
)

func TestIBLTVectorRecovery(t *testing.T) {
	// Create a new IBLT with 100 message slots
	iblt := NewIBLTVector(100)

	// Generate a few random chunks to insert
	chunks := make([][IBLTChunkSize]byte, 20)
	for i := range chunks {
		rand.Read(chunks[i][:])
	}

	// Insert chunks into the IBLT
	for _, chunk := range chunks {
		iblt.InsertChunk(chunk)
	}

	// Recover chunks from the IBLT
	recovered, err := iblt.Recover()
	require.NoError(t, err, iblt)

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

func TestIBLTUnion(t *testing.T) {
	// Create two new IBLTs
	iblt1 := NewIBLTVector(14)
	iblt2 := NewIBLTVector(14)

	// Generate random chunks for each IBLT
	chunks1 := make([][IBLTChunkSize]byte, IBLTNChunks)
	chunks2 := make([][IBLTChunkSize]byte, IBLTNChunks)

	for i := range chunks1 {
		rand.Read(chunks1[i][:])
		rand.Read(chunks2[i][:])
	}

	// Insert chunks into the IBLTs
	for _, chunk := range chunks1 {
		iblt1.InsertChunk(chunk)
	}

	for _, chunk := range chunks2 {
		iblt2.InsertChunk(chunk)
	}

	iblt1els := iblt1.EncodeAsFieldElements()
	iblt2els := iblt2.EncodeAsFieldElements()

	// Combine the IBLTs
	combined := iblt1els
	for i := range iblt2els {
		crypto.FieldAddInplace(combined[i], iblt2els[i], crypto.AuctionFieldOrder)
	}

	// Recover chunks from the combined IBLT
	combinedIblt := NewIBLTVector(14).DecodeFromElements(combined)

	recovered, err := combinedIblt.Recover()
	require.NoError(t, err, "%s, %s, %s", iblt1.String(), iblt2.String(), combinedIblt.String())

	// The total number of unique chunks is chunks1 + chunks2
	allChunks := append(chunks1[:], chunks2[:]...)

	// Verify all chunks were recovered
	if len(recovered) != len(allChunks) {
		t.Errorf("Expected to recover %d chunks from combined IBLT, but got %d", len(allChunks), len(recovered))
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
			t.Errorf("Failed to recover chunk from combined IBLT: %v", originalChunk)
		}
	}
}
