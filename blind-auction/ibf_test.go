package blind_auction

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/flashbots/adcnet/crypto"
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

	ibf1els := ibf1.EncodeAsFieldElements()
	ibf2els := ibf2.EncodeAsFieldElements()

	// Combine the IBFs
	combined := ibf1els
	for i := range ibf2els {
		crypto.FieldAddInplace(combined[i], ibf2els[i], crypto.AuctionFieldOrder)
	}

	// Recover chunks from the combined IBF
	ibf2 = ibf2.DecodeFromElements(combined)
	fmt.Println(ibf2.String())

	recovered := ibf2.Recover()

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
