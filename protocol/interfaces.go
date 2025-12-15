package protocol

import (
	"context"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
)

// Client broadcasts anonymous messages using auction-based scheduling.
type Client interface {
	// PrepareMessage creates a blinded message for the current round.
	PrepareMessage(ctx context.Context, round int,
		previousRoundOutput *RoundBroadcast,
		message []byte,
		auctionData *blind_auction.AuctionData) (*ClientRoundMessage, bool, error)
}

// Aggregator combines client messages to reduce bandwidth requirements.
type Aggregator interface {
	// AggregateClientMessages combines messages from multiple clients for a round.
	// Verifies signatures and authorization before aggregation.
	AggregateClientMessages(round int,
		msgs []*Signed[ClientRoundMessage],
		authorizedClients map[string]bool) (*AggregatedClientMessages, error)

	// AggregateAggregates combines messages from lower-level aggregators.
	AggregateAggregates(round int,
		msgs []*AggregatedClientMessages) (*AggregatedClientMessages, error)
}

// Server removes its blinding contribution from aggregated messages.
type Server interface {
	// UnblindAggregate removes this server's blinding factors from aggregated messages.
	UnblindAggregate(currentRound int,
		aggregate *AggregatedClientMessages,
		previousRoundAuction *blind_auction.IBFVector) (*ServerPartialDecryptionMessage, error)

	// UnblindPartialMessages combines all server unblinding contributions
	// to produce the final broadcast containing messages and auction results.
	UnblindPartialMessages(msgs []*ServerPartialDecryptionMessage) (*RoundBroadcast, error)
}

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
