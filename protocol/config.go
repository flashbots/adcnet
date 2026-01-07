package protocol

import (
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
)

// ADCNetConfig provides configuration parameters for ADCNet components.
type ADCNetConfig struct {
	// AuctionSlots is the number of slots in the IBF for auction data.
	AuctionSlots uint32

	// MessageLength is the byte length of the message vector.
	MessageLength int

	// MinClients is the minimum number of clients for anonymity.
	MinClients uint32

	// RoundDuration is the time duration of each protocol round.
	RoundDuration time.Duration

	// RoundsPerWindow defines rounds per participation window for rate limiting.
	RoundsPerWindow uint32
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
}
