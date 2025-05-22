package protocol

import (
	"context"
	"time"

	"github.com/ruteri/go-zipnet/crypto"
)

// Client defines the interface for a ZIPNet client that participates in the
// anonymous broadcast network by sending messages with auction-based scheduling.
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
		auctionData *AuctionData) (*ClientRoundMessage, bool, error)

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

// Aggregator defines the interface for a ZIPNet aggregator that collects and
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

// Server defines the interface for a ZIPNet anytrust server that provides
// anonymity guarantees for the broadcast network.
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

// CryptoProvider defines the interface for cryptographic operations required
// by the ZIPNet protocol.
type CryptoProvider interface {
	// DeriveSharedSecret derives a shared secret between two parties.
	DeriveSharedSecret(privateKey crypto.PrivateKey,
		otherPublicKey crypto.PublicKey) (crypto.SharedKey, error)

	// KDF derives keys from a master key for IBF and message vectors.
	KDF(masterKey crypto.SharedKey, round uint64,
		context []byte, ibfPadLength, msgVecPadLength int) ([]byte, []byte, error)

	// Sign signs data with a private key.
	Sign(privateKey crypto.PrivateKey, data []byte) (crypto.Signature, error)

	// Verify verifies a signature using a public key.
	Verify(publicKey crypto.PublicKey, data []byte,
		signature crypto.Signature) error

	// Hash computes a cryptographic hash of data.
	Hash(data []byte) (crypto.Hash, error)

	// RatchetKey rotates a key for forward secrecy.
	RatchetKey(key crypto.SharedKey) (crypto.SharedKey, error)
}

// NetworkTransport defines the interface for network communication between
// ZIPNet components.
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

// TEE defines the interface for a Trusted Execution Environment.
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

// ZIPNetConfig provides configuration parameters for ZIPNet components.
type ZIPNetConfig struct {
	// RoundDuration is the time duration of each protocol round.
	RoundDuration time.Duration

	// MessageSlots is the number of message slots in the broadcast.
	MessageSlots uint32

	// MessageSize is the size of each message slot in bytes.
	MessageSize uint32

	// MinClients is the minimum number of clients required for a round.
	MinClients uint32

	// AnytrustServers is the list of anytrust server addresses.
	AnytrustServers []string

	// Aggregators is the list of aggregator addresses.
	Aggregators []string

	// RoundsPerWindow defines how many rounds are in a participation window.
	RoundsPerWindow uint32

	// IBFNChunks is the number of chunks (levels) in the IBF.
	IBFNChunks int

	// IBFNBuckets is the number of buckets in the first level of the IBF.
	IBFNBuckets int

	// IBFShrinkFactor is the factor by which bucket count decreases per level.
	IBFShrinkFactor float64

	// IBFChunkSize is the size of each chunk in the IBF in bytes.
	IBFChunkSize int
}
