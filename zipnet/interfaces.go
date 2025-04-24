package zipnet

import (
	"context"
	"errors"
	"time"

	"github.com/ruteri/go-zipnet/crypto"
)

// ZIPNetConfig provides configuration parameters for ZIPNet components.
// This configuration is shared among clients, aggregators, and servers
// to ensure consistent protocol operation.
type ZIPNetConfig struct {
	// RoundDuration is the time duration of each protocol round.
	// All participants must agree on this duration for proper synchronization.
	RoundDuration time.Duration

	// MessageSlots is the number of message slots in the broadcast.
	// This determines how many clients can talk simultaneously in each round.
	MessageSlots uint32

	// MessageSize is the size of each message slot in bytes.
	// This limits the maximum size of messages that can be sent.
	MessageSize uint32

	// SchedulingSlots is the number of scheduling slots.
	// This should be larger than MessageSlots to reduce collision probability.
	// Recommended: 4x MessageSlots for ~97% non-collision rate.
	SchedulingSlots uint32

	// FootprintBits is the size of the footprint used for scheduling in bits.
	// Larger footprints reduce the probability of false collisions.
	FootprintBits uint32

	// MinClients is the minimum number of clients required for a round.
	// This ensures a minimum anonymity set size for privacy guarantees.
	MinClients uint32

	// AnytrustServers is the list of anytrust server addresses.
	// Privacy is guaranteed as long as at least one of these servers is honest.
	AnytrustServers []string

	// Aggregators is the list of aggregator addresses.
	// These are ordered by level, with the root aggregator last.
	Aggregators []string

	// RoundsPerWindow defines how many rounds are in a participation window.
	// After this many rounds, the participation counter resets for rate limiting.
	RoundsPerWindow uint32
}

// PublishedSchedule represents a schedule published by the leader server
// at the end of each round. It contains footprints indicating which slots
// are reserved for the next round.
type PublishedSchedule struct {
	// Footprints contains the raw schedule data with client footprints
	Footprints []byte

	// Signature is the leader server's signature on the schedule
	Signature crypto.Signature
}

// FootprintAt extracts a footprint at the given index in the published schedule.
// This is used by clients to check if their reservation was successful.
//
// Parameters:
// - index: The starting position of the footprint
// - length: The length of the footprint in bytes
//
// Returns the extracted footprint or an error if the index is out of bounds.
func (ps *PublishedSchedule) FootprintAt(index uint32, length int32) (crypto.Footprint, error) {
	if uint64(len(ps.Footprints)) < uint64(index)+uint64(length) {
		return crypto.Footprint{}, errors.New("out of bounds")
	}
	return crypto.NewFootprint(ps.Footprints[uint64(index) : uint64(index)+uint64(length)]), nil
}

// Client defines the interface for a ZIPNet client that participates in the
// anonymous broadcast network by sending messages or providing cover traffic.
//
// Clients operate inside Trusted Execution Environments (TEEs) to prevent
// denial-of-service attacks. The TEE ensures that clients follow the protocol
// correctly, but privacy does not depend on TEE security.
//
// The client lifecycle involves:
// 1. Setup with key generation and registration with servers
// 2. Participation in rounds by sending messages or cover traffic
// 3. Processing broadcasts to extract messages
type Client interface {
	// RegisterServerPublicKey registers a server's public key and establishes
	// a shared secret with that server using Diffie-Hellman key exchange.
	//
	// This method should be called for each anytrust server before the client
	// can participate in the protocol.
	//
	// Parameters:
	// - serverID: Unique identifier for the server
	// - publicKey: The server's public key
	//
	// Returns an error if key registration fails.
	RegisterServerPublicKey(serverID string, publicKey crypto.PublicKey) error

	// SubmitMessage prepares and submits a message for the current round.
	// If msg is nil or empty, this is treated as cover traffic.
	//
	// The message is encrypted using one-time pads derived from shared secrets
	// with all anytrust servers. If the client has a valid reservation for this
	// round, the message is placed in the reserved slot.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: Current protocol round number
	// - msg: Message content to send (nil or empty for cover traffic)
	// - requestSlot: Whether to reserve a slot for the next round
	// - publishedSchedule: The current round's published schedule
	//
	// Returns the prepared message or an error if preparation fails.
	SubmitMessage(ctx context.Context, round uint64, msg []byte,
		requestSlot bool, publishedSchedule PublishedSchedule) (*ClientMessage, error)

	// SendCoverTraffic prepares and sends cover traffic (an empty message) for
	// the current round to maintain anonymity.
	//
	// Cover traffic is essential for anonymity, as it prevents the adversary
	// from distinguishing between talking and non-talking clients.
	//
	// This is a convenience method that calls SubmitMessage with a nil message
	// and requestSlot set to false.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: Current protocol round number
	// - publishedSchedule: The current round's published schedule
	//
	// Returns the prepared message or an error if preparation fails.
	SendCoverTraffic(ctx context.Context, round uint64,
		publishedSchedule PublishedSchedule) (*ClientMessage, error)

	// ReserveSlot reserves a message slot for the next round without sending
	// an actual message in the current round.
	//
	// The reservation process uses footprint scheduling, where the client
	// computes a pseudorandom slot and footprint and includes it in the
	// current round's message.
	//
	// This is a convenience method that calls SubmitMessage with a nil message
	// and requestSlot set to true.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: Current protocol round number
	// - publishedSchedule: The current round's published schedule
	//
	// Returns the prepared message or an error if preparation fails.
	ReserveSlot(ctx context.Context, round uint64,
		publishedSchedule PublishedSchedule) (*ClientMessage, error)

	// ProcessBroadcast processes the broadcast message from the server to extract
	// relevant messages and scheduling information.
	//
	// This allows the client to verify if its message was successfully included
	// in the broadcast and to check if its slot reservation succeeded.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: Current protocol round number
	// - broadcast: The broadcast message from the server
	//
	// Returns the processed message data or an error if processing fails.
	ProcessBroadcast(ctx context.Context, round uint64, broadcast []byte) ([]byte, error)

	// GetTimesParticipated returns the number of times this client has
	// participated in the current window. This is used for rate limiting.
	GetTimesParticipated() uint32

	// GetPublicKey returns the client's public key used for authentication
	// and cryptographic operations.
	GetPublicKey() crypto.PublicKey
}

// Aggregator defines the interface for a ZIPNet aggregator that collects
// and combines client messages before forwarding to anytrust servers.
//
// Aggregators play a critical role in ZIPNet by:
// 1. Collecting messages from clients or lower-level aggregators
// 2. Validating their signatures and eligibility
// 3. Combining them using XOR operations
// 4. Forwarding the aggregated message to higher-level aggregators or servers
//
// Aggregators are untrusted for privacy, allowing them to be operated by
// infrastructure providers without compromising the security of the protocol.
type Aggregator interface {
	// ReceiveClientMessage processes a message from a client, verifying its
	// validity and preparing it for aggregation.
	//
	// This method verifies the client's signature, checks for duplicates,
	// validates the round number, and updates the internal state by XORing
	// the new message into the aggregate.
	//
	// Only leaf aggregators (level 0) should receive client messages directly.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - message: The client's submitted message
	// - clientPK: The client's public key for verification
	//
	// Returns an error if the message is invalid or processing fails.
	ReceiveClientMessage(ctx context.Context, message *ClientMessage,
		clientPK crypto.PublicKey) error

	// ReceiveAggregatorMessage processes a message from another aggregator,
	// verifying its validity and preparing it for aggregation.
	//
	// This method is used in the tree-based hierarchy where aggregators at
	// higher levels collect and combine messages from lower-level aggregators.
	//
	// Only non-leaf aggregators (level > 0) should receive aggregator messages.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - message: The aggregated message from another aggregator
	//
	// Returns an error if the message is invalid or processing fails.
	ReceiveAggregatorMessage(ctx context.Context, message *AggregatorMessage) error

	// AggregateMessages combines all received messages for the current round
	// and returns the aggregated message to be sent upstream.
	//
	// The aggregation process combines the client messages using XOR operations,
	// collects user public keys, and signs the result.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: Current protocol round number
	//
	// Returns the aggregated message or an error if aggregation fails.
	AggregateMessages(ctx context.Context, round uint64) (*AggregatorMessage, error)

	// Reset prepares the aggregator for the next round by clearing state
	// from the previous round.
	//
	// This resets the internal state including message maps, aggregated vectors,
	// and observed nonces if the round marks a new rate limiting window.
	//
	// Parameters:
	// - round: Next protocol round number
	//
	// Returns an error if reset fails.
	Reset(round uint64) error

	// GetPublicKey returns the aggregator's public key used for authentication
	// and cryptographic operations.
	GetPublicKey() crypto.PublicKey

	// GetLevel returns the level of this aggregator in the aggregation tree.
	// Level 0 indicates a leaf aggregator that receives messages directly from clients.
	// Higher levels indicate aggregators that receive from lower-level aggregators.
	GetLevel() uint32
}

// Server defines the interface for a ZIPNet anytrust server that provides
// anonymity guarantees for the broadcast network.
//
// ZIPNet servers operate in an anytrust model where privacy is guaranteed as long as
// at least one server is honest. Each server receives aggregated client messages,
// unblinds them using shared secrets, and participates in generating the final broadcast.
//
// The server lifecycle involves:
// 1. Initialization with key generation
// 2. Registration of clients, aggregators, and other servers
// 3. Processing incoming aggregated messages by unblinding them
// 4. For leader servers: combining unblinded shares to produce the final broadcast
// 5. Ratcheting keys forward after each round for forward secrecy
type Server interface {
	// RegisterClient establishes a shared secret with a client after verifying
	// their TEE attestation. The shared secret is used to derive one-time pads
	// for blinding/unblinding messages.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - clientPK: The client's public key
	// - attestation: The client's TEE attestation for verification
	//
	// Returns an error if registration fails or attestation verification fails.
	RegisterClient(ctx context.Context, clientPK crypto.PublicKey, attestation []byte) error

	// RegisterAggregator records an aggregator's public key to allow verification
	// of aggregated messages submitted by this aggregator.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - aggregatorBlob: Registration data containing the aggregator's public key and level
	//
	// Returns an error if registration fails.
	RegisterAggregator(ctx context.Context, aggregatorBlob *AggregatorRegistrationBlob) error

	// RegisterServer adds another server to the anytrust group and updates
	// the group size. This affects how many shares must be collected before
	// deriving the final broadcast.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - serverBlob: Registration data containing the server's public keys
	//
	// Returns an error if registration fails.
	RegisterServer(ctx context.Context, serverBlob *ServerRegistrationBlob) error

	// UnblindAggregate removes this server's blinding factors from an aggregated
	// message by XORing in one-time pads derived from shared secrets with clients.
	// It also ratchets the shared secrets forward for security.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - aggregate: The aggregated message containing client ciphertexts
	//
	// Returns the unblinded share and an error if unblinding fails.
	UnblindAggregate(ctx context.Context, aggregate *AggregatorMessage) (*UnblindedShareMessage, error)

	// DeriveRoundOutput combines unblinded shares from all anytrust servers
	// to produce the final broadcast message.
	//
	// This method should only be called by the leader server after collecting
	// shares from all servers in the anytrust group.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - shares: All server shares of the unblinded aggregate
	//
	// Returns the final round output or an error if derivation fails.
	DeriveRoundOutput(ctx context.Context, shares []*UnblindedShareMessage) (*RoundOutput, error)

	// ProcessAggregate handles an aggregated message from an aggregator.
	// If this server is the leader, it collects shares and produces the final broadcast.
	// If this server is a follower, it sends its share to the leader.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - message: The aggregated message from an aggregator
	//
	// Returns a server message or an error if processing fails.
	ProcessAggregate(ctx context.Context, message *AggregatorMessage) (*ServerMessage, error)

	// PublishSchedule creates and signs a schedule for the next round.
	// This is typically only performed by the leader server.
	//
	// The schedule contains footprints that indicate which slots are reserved
	// for the next round.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - round: The round number for which to publish the schedule
	// - schedVec: The scheduling vector containing footprints
	//
	// Returns the published schedule, its signature, and an error if publishing fails.
	PublishSchedule(ctx context.Context, round uint64, schedVec []byte) ([]byte, crypto.Signature, error)

	// GetPublicKey returns the server's public key used for authentication
	// and cryptographic operations.
	GetPublicKey() crypto.PublicKey
}

// TEE defines the interface for a Trusted Execution Environment that
// provides security guarantees for the ZIPNet protocol.
//
// In ZIPNet, TEEs are used for DoS prevention, not for privacy. If a TEE
// is compromised, it may affect liveness (by allowing malicious messages),
// but not privacy.
//
// The TEE provides:
// - Attestation for verifying code integrity
// - Secure key generation and storage
// - Sealed storage for persistent state
// - Secure computation environment
type TEE interface {
	// Attest produces an attestation of the code running in the TEE,
	// which can be verified by other parties to establish trust.
	//
	// The attestation proves that the client is running the expected
	// code and will follow the protocol correctly.
	//
	// Returns the attestation data and an error if attestation fails.
	Attest() ([]byte, error)

	// VerifyAttestation verifies an attestation from another party.
	//
	// This is used by servers to verify that clients are running
	// the expected code in a valid TEE.
	//
	// Parameters:
	// - attestation: The attestation data to verify
	//
	// Returns true if the attestation is valid, false otherwise, and an error if verification fails.
	VerifyAttestation(attestation []byte) (bool, error)

	// SealData encrypts data for storage outside the TEE, ensuring it can only
	// be decrypted by the same TEE instance.
	//
	// This is used to store keys and client state securely, even when
	// the client is not running.
	//
	// Parameters:
	// - data: The data to seal
	//
	// Returns the sealed data and an error if sealing fails.
	SealData(data []byte) ([]byte, error)

	// UnsealData decrypts data that was previously sealed by this TEE instance.
	//
	// This is used to recover keys and state when the client restarts.
	//
	// Parameters:
	// - sealedData: The data to unseal
	//
	// Returns the unsealed data and an error if unsealing fails.
	UnsealData(sealedData []byte) ([]byte, error)

	// GenerateKeys generates cryptographic keys for the client within the TEE.
	//
	// The keys are generated securely within the TEE and the private key
	// never leaves the TEE unencrypted.
	//
	// Returns the generated key pair and an error if key generation fails.
	GenerateKeys() (crypto.PublicKey, crypto.PrivateKey, error)

	// Sign signs data with the private key stored in the TEE.
	//
	// The private key never leaves the TEE, ensuring that only code
	// running within the TEE can sign messages.
	//
	// Parameters:
	// - data: The data to sign
	//
	// Returns the signature and an error if signing fails.
	Sign(data []byte) (crypto.Signature, error)
}

// CryptoProvider defines the interface for cryptographic operations
// required by the ZIPNet protocol.
//
// This interface abstracts the cryptographic primitives used by the protocol,
// allowing for different implementations and algorithm choices.
type CryptoProvider interface {
	// DeriveSharedSecret derives a shared secret between two parties using their
	// public and private keys, typically with Diffie-Hellman key exchange.
	//
	// In ZIPNet, this is used to establish shared secrets between clients and servers.
	//
	// Parameters:
	// - privateKey: The caller's private key
	// - otherPublicKey: The other party's public key
	//
	// Returns the derived shared secret and an error if derivation fails.
	DeriveSharedSecret(privateKey crypto.PrivateKey,
		otherPublicKey crypto.PublicKey) (crypto.SharedKey, error)

	// KDF derives keys from a master key using a key derivation function.
	//
	// In ZIPNet, this is used to derive one-time pads for the schedule vector
	// and message vector from the shared secret between a client and server.
	//
	// Parameters:
	// - masterKey: The shared key to derive from
	// - round: The current round number (for domain separation)
	// - publishedSchedule: The published schedule (as shared context)
	//
	// Returns two derived keys (for schedule vector and message vector) and an error if derivation fails.
	KDF(masterKey crypto.SharedKey, round uint64,
		publishedSchedule []byte) ([]byte, []byte, error)

	// Sign signs data with a private key.
	//
	// In ZIPNet, this is used by clients, aggregators, and servers to sign their messages.
	//
	// Parameters:
	// - privateKey: The private key to sign with
	// - data: The data to sign
	//
	// Returns the signature and an error if signing fails.
	Sign(privateKey crypto.PrivateKey, data []byte) (crypto.Signature, error)

	// Verify verifies a signature using a public key.
	//
	// In ZIPNet, this is used to verify the authenticity of messages from
	// clients, aggregators, and servers.
	//
	// Parameters:
	// - publicKey: The public key to verify with
	// - data: The data that was signed
	// - signature: The signature to verify
	//
	// Returns true if the signature is valid, false otherwise, and an error if verification fails.
	Verify(publicKey crypto.PublicKey, data []byte,
		signature crypto.Signature) (bool, error)

	// Hash computes a cryptographic hash of data.
	//
	// In ZIPNet, hashes are used for deriving identifiers, computing message
	// digests, and as part of various cryptographic operations.
	//
	// Parameters:
	// - data: The data to hash
	//
	// Returns the hash value and an error if hashing fails.
	Hash(data []byte) (crypto.Hash, error)

	// RatchetKey rotates a key for forward secrecy.
	//
	// In ZIPNet, keys are ratcheted after each round to prevent compromise
	// of past communications if a key is later compromised.
	//
	// Parameters:
	// - key: The key to ratchet
	//
	// Returns the ratcheted key and an error if ratcheting fails.
	RatchetKey(key crypto.SharedKey) (crypto.SharedKey, error)
}

// NetworkTransport defines the interface for network communication
// between ZIPNet components.
//
// This interface abstracts the network layer, allowing for different
// transport implementations (HTTP, WebSockets, direct TCP, etc.).
type NetworkTransport interface {
	// SendToAggregator sends a message to an aggregator.
	//
	// Used by clients to send their messages to their assigned aggregator.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - aggregatorID: Identifier for the target aggregator
	// - message: The message to send
	//
	// Returns an error if sending fails.
	SendToAggregator(ctx context.Context, aggregatorID string,
		message *ClientMessage) error

	// SendToServer sends a message to a server.
	//
	// Used by aggregators to send aggregated messages to anytrust servers.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - serverID: Identifier for the target server
	// - message: The message to send
	//
	// Returns an error if sending fails.
	SendToServer(ctx context.Context, serverID string,
		message *AggregatorMessage) error

	// BroadcastToClients broadcasts a message to all clients.
	//
	// Used by the leader server to publish the final output of a round.
	//
	// Parameters:
	// - ctx: Context for the operation
	// - message: The message to broadcast
	//
	// Returns an error if broadcasting fails.
	BroadcastToClients(ctx context.Context, message *ServerMessage) error

	// RegisterMessageHandler registers a handler for incoming messages.
	//
	// Used by aggregators and servers to process incoming messages.
	//
	// Parameters:
	// - handler: Function that processes incoming messages
	//
	// Returns an error if registration fails.
	RegisterMessageHandler(handler func([]byte) error) error
}

// Scheduler defines the interface for the scheduling mechanism in ZIPNet.
//
// The scheduler handles slot reservation and mapping between scheduling
// slots and message slots, implementing the footprint scheduling algorithm.
type Scheduler interface {
	// ComputeScheduleSlot computes a slot for scheduling in the next round.
	//
	// This uses a pseudorandom function to derive a slot and footprint from
	// the client's key and the round number.
	//
	// Parameters:
	// - key: The client's symmetric key
	// - round: The round for which to compute the slot
	//
	// Returns the computed slot index, footprint, and an error if computation fails.
	ComputeScheduleSlot(key []byte, round uint64) (uint32, crypto.Footprint, error)

	// VerifySchedule verifies that a schedule was properly formed and signed.
	//
	// Used by clients to verify the authenticity of published schedules.
	//
	// Parameters:
	// - schedule: The schedule to verify
	// - serverPK: The server's public key
	//
	// Returns true if the schedule is valid, false otherwise, and an error if verification fails.
	VerifySchedule(schedule PublishedSchedule, serverPK crypto.PublicKey) (bool, error)

	// MapScheduleToMessageSlot maps a scheduling slot to a message slot.
	//
	// This converts from a slot in the scheduling vector to the corresponding
	// slot in the message vector where the client should place their message.
	//
	// Parameters:
	// - scheduleSlot: The slot in the scheduling vector
	// - publishedSchedule: The published schedule
	//
	// Returns the corresponding message slot and an error if mapping fails.
	MapScheduleToMessageSlot(scheduleSlot uint32,
		publishedSchedule PublishedSchedule) (uint32, error)
}
