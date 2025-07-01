package protocol

import (
	"context"
	"math/big"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

// Client participates in anonymous broadcast with auction-based scheduling.
// Security: Assumes TEE for DoS prevention only, not for privacy.
// Privacy depends on honest aggregators and at least one honest server.
type Client interface {
	// RegisterServerPublicKey registers a server's public key and establishes
	// a shared secret with that server using Diffie-Hellman key exchange.
	RegisterServerPublicKey(serverID string, publicKey crypto.PublicKey) error

	// PrepareMessage prepares a message for the current round with auction data.
	// Returns the prepared message, a boolean indicating if the message should be sent
	// (based on auction results), and any error.
	PrepareMessage(ctx context.Context, round int,
		previousRoundOutput *Signed[ServerRoundData],
		message []byte,
		auctionData *blind_auction.AuctionData) (*ClientRoundMessage, bool, error)

	// ProcessRoundData processes the broadcast from the server to extract
	// messages and auction results.
	ProcessRoundData(ctx context.Context, round int,
		roundData *Signed[ServerRoundData]) ([]byte, error)

	// GetTimesParticipated returns the number of times this client has
	// participated in the current window for rate limiting.
	GetTimesParticipated() uint32

	// GetPublicKey returns the client's public key.
	GetPublicKey() crypto.PublicKey
}

// Aggregator defines the interface for an ADCNet aggregator that collects and
// combines client messages before forwarding to anytrust servers.
type Aggregator interface {
	// ReceiveClientMessage processes a message from a client.
	ReceiveClientMessage(ctx context.Context, message *Signed[ClientRoundMessage]) error

	// ReceiveAggregatorMessage processes a message from another aggregator.
	ReceiveAggregatorMessage(ctx context.Context, message *Signed[AggregatedClientMessages]) error

	// AggregateMessages combines all received messages for the current round.
	AggregateMessages(ctx context.Context, round int) (*Signed[AggregatedClientMessages], error)

	// Reset prepares the aggregator for the next round.
	Reset(round int) error

	// GetPublicKey returns the aggregator's public key.
	GetPublicKey() crypto.PublicKey

	// GetLevel returns the level of this aggregator in the aggregation tree.
	GetLevel() uint32
}

// Server provides anonymity in anytrust model.
// Security: System remains private if at least one server is honest.
// Assumption: Servers don't collude to break anonymity.
type Server interface {
	// RegisterClient establishes a shared secret with a client after verifying
	// their TEE attestation.
	RegisterClient(ctx context.Context, clientPK crypto.PublicKey, attestation []byte) error

	// RegisterAggregator records an aggregator's public key.
	RegisterAggregator(ctx context.Context, aggregatorBlob *AggregatorRegistrationBlob) error

	// RegisterServer adds another server to the anytrust group.
	RegisterServer(ctx context.Context, serverBlob *ServerRegistrationBlob) error

	// UnblindAggregate creates a partial decryption by removing this server's
	// blinding factors from an aggregated message.
	UnblindAggregate(ctx context.Context,
		aggregate *Signed[AggregatedClientMessages]) (*Signed[ServerPartialDecryptionMessage], error)

	// DeriveRoundOutput combines unblinded shares from all anytrust servers
	// to produce the final broadcast message with auction results.
	DeriveRoundOutput(ctx context.Context,
		shares []*ServerPartialDecryptionMessage) (*Signed[ServerRoundData], error)

	// GetPublicKey returns the server's public key.
	GetPublicKey() crypto.PublicKey

	// IsLeader returns whether this server is the leader.
	IsLeader() bool
}

// NetworkTransport defines the interface for network communication between
// ADCNet components.
type NetworkTransport interface {
	// SendToAggregator sends a client message to an aggregator.
	SendToAggregator(ctx context.Context, aggregatorID string,
		message *Signed[ClientRoundMessage]) error

	// SendAggregateToAggregator sends an aggregated message to another aggregator.
	SendAggregateToAggregator(ctx context.Context, aggregatorID string,
		message *Signed[AggregatedClientMessages]) error

	// SendShareToServer sends a partial decryption to a server.
	SendShareToServer(ctx context.Context, serverID string,
		message *Signed[ServerPartialDecryptionMessage]) error

	// SendAggregateToServer sends an aggregated message to a server.
	SendAggregateToServer(ctx context.Context, serverID string,
		message *Signed[AggregatedClientMessages]) error

	// FetchRoundData retrieves round data from a server.
	FetchRoundData(ctx context.Context, serverID string, round int) (*Signed[ServerRoundData], error)

	// BroadcastToClients broadcasts round data to all clients.
	BroadcastToClients(ctx context.Context, message *Signed[ServerRoundData]) error

	// RegisterMessageHandler registers a handler for incoming messages.
	RegisterMessageHandler(handler func([]byte) error) error
}

// TEE interface for Trusted Execution Environment operations.
// Used only for DoS prevention, rate limiting, and auction integrity.
// TEE compromise affects liveness, not privacy.
type TEE interface {
	// Attest produces an attestation of the code running in the TEE.
	Attest() ([]byte, error)

	// VerifyAttestation verifies an attestation from another party.
	VerifyAttestation(attestation []byte) (bool, error)

	// SealData encrypts data for storage outside the TEE.
	SealData(data []byte) ([]byte, error)

	// UnsealData decrypts data that was previously sealed by this TEE instance.
	UnsealData(sealedData []byte) ([]byte, error)

	// GenerateKeys generates cryptographic keys for the client within the TEE.
	GenerateKeys() (crypto.PublicKey, crypto.PrivateKey, error)

	// Sign signs data with the private key stored in the TEE.
	Sign(data []byte) (crypto.Signature, error)
}

// ADCNetConfig provides configuration parameters for ADCNet components.
type ADCNetConfig struct {
	// RoundDuration is the time duration of each protocol round.
	RoundDuration time.Duration

	// AuctionSlots is the number of message slots in the broadcast.
	AuctionSlots uint32

	// MessageSize is the size of message vector in bytes.
	MessageSize uint32

	MessageFieldOrder *big.Int

	// MinClients is the minimum number of clients required for a round, in
	// order to prevent deannonymization.
	MinClients uint32

	MinServers uint32

	// RoundsPerWindow defines how many rounds are in a participation window
	// for SPAM prevention.
	RoundsPerWindow uint32
}
