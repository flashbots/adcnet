package blind_auction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// AuctionData represents a client's bid for message transmission in the next round.
// The MessageHash binds the bid to a specific message without revealing content.
type AuctionData struct {
	MessageHash [32]byte
	Weight      uint32
	Size        uint32
}

// EncodeToChunk serializes auction data into a 48-byte chunk for IBF insertion.
func (a *AuctionData) EncodeToChunk() [IBFChunkSize]byte {
	var res [IBFChunkSize]byte
	binary.BigEndian.PutUint32(res[0:4], a.Weight)
	binary.BigEndian.PutUint32(res[4:8], a.Size)
	copy(res[8:40], a.MessageHash[:])
	return res
}

// AuctionDataFromChunk deserializes auction data from an IBF chunk.
func AuctionDataFromChunk(chunk [IBFChunkSize]byte) *AuctionData {
	var res AuctionData

	copy(res.MessageHash[:], chunk[8:40])
	res.Weight = binary.BigEndian.Uint32(chunk[0:4])
	res.Size = binary.BigEndian.Uint32(chunk[4:8])

	return &res
}

// AuctionDataFromMessage creates auction data binding a message to its bid weight.
// Used by clients when preparing bids for the next round.
func AuctionDataFromMessage(msg []byte, weight uint32) *AuctionData {
	return &AuctionData{
		MessageHash: sha256.Sum256(msg),
		Weight:      weight,
		Size:        uint32(len(msg)),
	}
}

// AuctionWinner represents a winning bid with its message slot allocation for the next round.
type AuctionWinner struct {
	Bid      AuctionData
	SlotIdx  uint32 // Starting byte offset in message vector
	SlotSize uint32 // Allocated bandwidth in bytes
}

// AuctionEngine determines winning bids after IBF reconstruction.
// Uses dynamic programming to solve the knapsack problem for optimal bandwidth allocation.
type AuctionEngine struct {
	totalBandwidth uint32
	minMessageSize uint32
}

// NewAuctionEngine creates an auction engine with bandwidth and size constraints.
func NewAuctionEngine(totalBandwidth, minMessageSize uint32) *AuctionEngine {
	return &AuctionEngine{
		totalBandwidth: totalBandwidth,
		minMessageSize: minMessageSize,
	}
}

// RunAuction selects winning bids to maximize total weight within bandwidth constraints.
// Determines message placement for the next communication round.
func (e *AuctionEngine) RunAuction(bids []AuctionData) []AuctionWinner {
	if len(bids) == 0 {
		return nil
	}

	// Filter out invalid bids
	validBids := make([]AuctionData, 0, len(bids))
	for _, bid := range bids {
		if bid.Size < e.minMessageSize {
			bid.Size = e.minMessageSize
		}
		if bid.Size <= e.totalBandwidth && bid.Weight > 0 {
			validBids = append(validBids, bid)
		}
	}

	if len(validBids) == 0 {
		return nil
	}

	// Use dynamic programming knapsack for optimal packing
	winners := e.knapsackPacking(validBids)

	// Assign slot indices
	currentIdx := uint32(0)
	for i := range winners {
		winners[i].SlotIdx = currentIdx
		currentIdx += winners[i].SlotSize
	}

	return winners
}

// knapsackPacking solves the 0-1 knapsack problem to maximize total bid weight.
// Ensures optimal bandwidth utilization for the next communication round.
func (e *AuctionEngine) knapsackPacking(bids []AuctionData) []AuctionWinner {
	n := len(bids)
	capacity := e.totalBandwidth

	// Create DP table: dp[i][w] = max weight using first i items with capacity w
	dp := make([]uint32, capacity+1)
	parent := make([][]int, n+1)
	for i := range parent {
		parent[i] = make([]int, capacity+1)
		for j := range parent[i] {
			parent[i][j] = -1
		}
	}

	// Fill DP table
	for i := 0; i < n; i++ {
		// Process in reverse to avoid using same item twice
		newDp := make([]uint32, capacity+1)
		copy(newDp, dp)

		for w := int(capacity); w >= int(bids[i].Size); w-- {
			// Include current bid
			includeValue := dp[w-int(bids[i].Size)] + bids[i].Weight

			if includeValue > newDp[w] {
				newDp[w] = includeValue
				parent[i+1][w] = i
			}
		}
		dp = newDp
	}

	// Backtrack to find selected items
	winners := []AuctionWinner{}
	w := int(capacity)

	// Find the solution by backtracking
	selected := make([]bool, n)
	for i := n; i > 0 && w > 0; i-- {
		if parent[i][w] != -1 {
			idx := parent[i][w]
			selected[idx] = true
			w -= int(bids[idx].Size)
		}
	}

	// Build winners list
	for i, bid := range bids {
		if selected[i] {
			winners = append(winners, AuctionWinner{
				Bid:      bid,
				SlotSize: bid.Size,
			})
		}
	}

	// Sort winners by message hash for deterministic slot assignment across all servers
	sort.Slice(winners, func(i, j int) bool {
		return bytes.Compare(winners[i].Bid.MessageHash[:], winners[j].Bid.MessageHash[:]) < 0
	})

	return winners
}

// GreedyAuctionEngine provides a simpler greedy algorithm for testing and comparison.
// Not used in production; the main AuctionEngine provides optimal allocation.
type GreedyAuctionEngine struct {
	totalBandwidth uint32
}

// RunAuction selects bids greedily by weight/size ratio.
func (e *GreedyAuctionEngine) RunAuction(bids []AuctionData) []AuctionWinner {
	// Sort by weight/size ratio (value density)
	sorted := make([]AuctionData, len(bids))
	copy(sorted, bids)

	sort.Slice(sorted, func(i, j int) bool {
		// Higher weight/size ratio is better
		ratioI := float64(sorted[i].Weight) / float64(sorted[i].Size)
		ratioJ := float64(sorted[j].Weight) / float64(sorted[j].Size)
		return ratioI > ratioJ
	})

	winners := []AuctionWinner{}
	usedBandwidth := uint32(0)

	for _, bid := range sorted {
		if usedBandwidth+bid.Size <= e.totalBandwidth {
			winners = append(winners, AuctionWinner{
				Bid:      bid,
				SlotIdx:  usedBandwidth,
				SlotSize: bid.Size,
			})
			usedBandwidth += bid.Size
		}
	}

	return winners
}
