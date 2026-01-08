package protocol

import (
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
)

// ADCNetConfig provides configuration parameters for ADCNet components.
type ADCNetConfig struct {
	// AuctionSlots is the number of slots in the IBF for auction data.
	AuctionSlots uint32 `json:"auction_slots"`

	// MessageLength is the maximum byte capacity of the message vector.
	// Actual per-round length is determined by auction results.
	MessageLength int `json:"message_length"`

	// MinClients is the minimum number of clients for anonymity.
	MinClients uint32 `json:"min_clients"`

	// RoundDuration is the time duration of each protocol round.
	RoundDuration time.Duration `json:"round_duration,string"`

	// RoundsPerWindow defines rounds per participation window for rate limiting.
	RoundsPerWindow uint32 `json:"rounds_per_window"`
}

// AuctionSlotsForConfig calculates total IBF vector size for the configuration.
func AuctionSlotsForConfig(c *ADCNetConfig) uint32 {
	return 2 * blind_auction.IBFVectorSize(c.AuctionSlots)
}

// AuctionResult indicates whether a client won an auction slot.
type AuctionResult struct {
	// ShouldSend indicates if the client won a slot.
	ShouldSend bool

	// MessageStartIndex is the byte offset where the message should be placed.
	MessageStartIndex int

	// TotalAllocated indicates how many total bytes have been allocated by the auction
	TotalAllocated int
}
