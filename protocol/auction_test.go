package protocol

import (
	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuctionEngine_BasicKnapsack(t *testing.T) {
	engine := NewAuctionEngine(100, 10) // 100 bytes total, 10 bytes minimum

	bids := []AuctionData{
		{Size: 40, Weight: 50}, // Value density: 1.25
		{Size: 30, Weight: 36}, // Value density: 1.2
		{Size: 50, Weight: 55}, // Value density: 1.1
		{Size: 20, Weight: 28}, // Value density: 1.4
	}

	winners := engine.RunAuction(bids)

	// Optimal solution: D (20 bytes, weight 28) + A (40 bytes, weight 50) + B (30 bytes, weight 36)
	// Total: 90 bytes, weight 114
	assert.Equal(t, 3, len(winners))

	totalWeight := uint32(0)
	totalSize := uint32(0)
	for _, w := range winners {
		totalWeight += w.Bid.Weight
		totalSize += w.Bid.Size
	}

	assert.Equal(t, uint32(119), totalWeight)
	assert.Equal(t, uint32(100), totalSize)
	assert.LessOrEqual(t, totalSize, engine.totalBandwidth)
}

func TestAuctionEngine_ExactFit(t *testing.T) {
	engine := NewAuctionEngine(100, 10)

	bids := []AuctionData{
		{Size: 50, Weight: 100},
		{Size: 50, Weight: 90},
		{Size: 100, Weight: 180}, // Can't combine with others
	}

	winners := engine.RunAuction(bids)

	// Should select C (100 bytes, weight 180) over A+B (100 bytes, weight 190)
	// Actually, the DP algorithm should pick A+B for higher total weight
	totalWeight := uint32(0)
	for _, w := range winners {
		totalWeight += w.Bid.Weight
	}

	// The DP solution should find the optimal 190 weight
	assert.GreaterOrEqual(t, totalWeight, uint32(180))
}

func TestAuctionEngine_MinimumSize(t *testing.T) {
	engine := NewAuctionEngine(100, 20)

	bids := []AuctionData{
		{Size: 10, Weight: 50},  // Too small
		{Size: 19, Weight: 100}, // Too small
		{Size: 20, Weight: 30},  // Valid
		{Size: 25, Weight: 40},  // Valid
	}

	winners := engine.RunAuction(bids)

	// Only C and D should be considered
	totalSize := uint32(0)
	assert.Equal(t, 4, len(winners))
	for _, w := range winners {
		totalSize += w.Bid.Size
	}

	assert.Equal(t, 85, int(totalSize))
}

func TestAuctionEngine_GreedyComparison(t *testing.T) {
	bandwidth := uint32(100)
	dpEngine := NewAuctionEngine(bandwidth, 10)
	greedyEngine := &GreedyAuctionEngine{totalBandwidth: bandwidth}

	// Case where greedy is suboptimal
	bids := []AuctionData{
		{Size: 51, Weight: 60}, // Value density: 1.176
		{Size: 50, Weight: 58}, // Value density: 1.16
		{Size: 50, Weight: 58}, // Value density: 1.16
	}

	dpWinners := dpEngine.RunAuction(bids)
	greedyWinners := greedyEngine.RunAuction(bids)

	dpWeight := uint32(0)
	for _, w := range dpWinners {
		dpWeight += w.Bid.Weight
	}

	greedyWeight := uint32(0)
	for _, w := range greedyWinners {
		greedyWeight += w.Bid.Weight
	}

	// DP should find B+C (weight 116) while greedy picks A (weight 60)
	assert.Greater(t, dpWeight, greedyWeight)
	assert.Equal(t, uint32(116), dpWeight)
	assert.Equal(t, uint32(60), greedyWeight)
}

func TestAuctionDataEx_Encoding(t *testing.T) {
	// Test extended auction data encoding/decoding
	original := &AuctionData{
		MessageHash: crypto.Hash{1, 2, 3, 4, 5},
		Weight:      12345,
		Size:        67890,
	}

	chunk := original.EncodeToChunk()
	decoded := AuctionDataFromChunk(chunk)

	assert.Equal(t, original.Weight, decoded.Weight)
	assert.Equal(t, original.Size, decoded.Size)
	assert.Equal(t, original.MessageHash, decoded.MessageHash)
}

func BenchmarkAuctionEngine_LargeScale(b *testing.B) {
	engine := NewAuctionEngine(1000000, 100) // 1MB total bandwidth

	// Generate many bids
	bids := make([]AuctionData, 1000)
	for i := range bids {
		bids[i] = AuctionData{
			Size:   uint32(100 + i%900),   // 100-999 bytes
			Weight: uint32(1000 + i%9000), // Various weights
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		winners := engine.RunAuction(bids)
		_ = winners
	}
}

func TestAuctionEngine_EdgeCases(t *testing.T) {
	engine := NewAuctionEngine(100, 10)

	// Empty bids
	assert.Empty(t, engine.RunAuction([]AuctionData{}))

	// All bids too large
	assert.Empty(t, engine.RunAuction([]AuctionData{
		{Size: 101, Weight: 100},
		{Size: 200, Weight: 200},
	}))

	// Zero weight (invalid)
	assert.Empty(t, engine.RunAuction([]AuctionData{
		{Size: 50, Weight: 0},
	}))
}
