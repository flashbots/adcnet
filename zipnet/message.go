package zipnet

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/ruteri/go-zipnet/crypto"
)

type Signed[T any] struct {
	PublicKey crypto.PublicKey `json:"public_key"`
	Signature crypto.Signature `json:"signature"`
	Object    *T               `json:"object"`
}

func NewSigned[T any](privkey crypto.PrivateKey, obj *T) (*Signed[T], error) {
	pubkey, err := privkey.PublicKey()
	if err != nil {
		return nil, err
	}

	serializedData, err := SerializeMessage(obj)
	if err != nil {
		return nil, err
	}

	signature, err := crypto.Sign(privkey, append(serializedData, pubkey...))
	if err != nil {
		return nil, err
	}

	return &Signed[T]{
		PublicKey: pubkey,
		Signature: signature,
		Object:    obj,
	}, nil
}

func (s *Signed[T]) UnsafeObject() *T {
	return s.Object
}

func (s *Signed[T]) Recover() (*T, crypto.PublicKey, error) {
	serializedData, err := SerializeMessage(s.Object)
	if err != nil {
		return nil, nil, err
	}

	ok := s.Signature.Verify(s.PublicKey, append(serializedData, s.PublicKey...))
	if !ok {
		return nil, nil, errors.New("siganture not valid")
	}

	return s.Object, s.PublicKey, nil
}

// ScheduleMessage represents a ZIPNet protocol message containing broadcast data,
// scheduling information, and authentication metadata.
//
// This is the base message type used by clients, aggregators, and servers.
// It contains both the scheduling vector for the next round and the message
// vector for the current round.
type ScheduleMessage struct {
	// Round is the current protocol round number
	// All participants must agree on the current round for protocol synchronization
	Round uint64

	// NextSchedVec contains the scheduling vector for the next round
	// This is used for footprint scheduling to reserve message slots
	NextSchedVec []byte

	// MsgVec contains the message vector for the current round
	// This is where client messages are placed according to their reserved slots
	MsgVec []byte

	// Signature is a digital signature over the message payload
	// This is used to verify the authenticity of the message
	Signature crypto.Signature
}

// ClientMessage is an alias for ScheduleMessage sent by clients.
// Clients send these messages to aggregators, which combine them
// to produce AggregatorMessages.
type ClientMessage = ScheduleMessage

// ServerMessage is an alias for ScheduleMessage sent by servers.
// The leader server sends these messages as the final output of each round.
type ServerMessage = ScheduleMessage

// AggregatorMessage extends ScheduleMessage with additional information
// needed for aggregator-to-aggregator and aggregator-to-server communication.
//
// Aggregators create these messages by combining multiple ClientMessages
// or lower-level AggregatorMessages.
type AggregatorMessage struct {
	// Embed the base ScheduleMessage
	ScheduleMessage

	// UserPKs contains a list of all client public keys included in this aggregate
	// This is used by anytrust servers to verify the anonymity set
	UserPKs []crypto.PublicKey

	// AggregatorID is the identifier of the aggregator that created this message
	// This is used for message routing and authentication
	AggregatorID string `json:"aggregator_id,omitempty"`

	// Level indicates the level of the aggregator in the hierarchy
	// Level 0 indicates a leaf aggregator that receives messages directly from clients
	Level uint32 `json:"level,omitempty"`

	// AnytrustGroupID identifies the set of anytrust servers this message is intended for
	// This ensures the message is processed by the correct group of servers
	AnytrustGroupID string `json:"anytrust_group_id,omitempty"`
}

// UnblindedShareMessage represents a server's share of the unblinded aggregate.
// Each anytrust server creates one of these by removing its blinding factors
// from the aggregated message.
type UnblindedShareMessage struct {
	// EncryptedMsg is the original aggregated message
	// This is retained to ensure all servers are working on the same input
	EncryptedMsg *Signed[AggregatorMessage] `json:"encrypted_msg"`

	// KeyShare contains the partial decryption (the XOR of derived pads)
	// This is combined with shares from other servers to obtain the plaintext
	KeyShare *ScheduleMessage `json:"key_share"`
}

// RoundOutput represents the final output of a round after combining all
// server shares and unblinding the message.
//
// This is created by the leader server and contains the final broadcast
// message along with signatures from all participating servers.
type RoundOutput = ScheduleMessage

// OutputSignature pairs a server's public key with its signature on the round output.
// This is used to verify that the server approved the final output.
type OutputSignature struct {
	// PublicKey identifies the server that created the signature
	PublicKey crypto.PublicKey `json:"public_key"`

	// Signature is the server's signature on the round output
	Signature crypto.Signature `json:"signature"`
}

// AggregatorRegistrationBlob contains the public key and metadata for an aggregator.
// This is used during the setup phase to register aggregators with servers.
type AggregatorRegistrationBlob struct {
	// PublicKey is the aggregator's signing public key
	// This is used to verify signatures on aggregated messages
	PublicKey crypto.PublicKey `json:"public_key"`

	// Level indicates the position in the aggregation hierarchy
	// Level 0 indicates a leaf aggregator that receives directly from clients
	Level uint32 `json:"level"`
}

// ServerRegistrationBlob contains the public keys and metadata for an anytrust server.
// This is used during the setup phase to register servers with each other.
type ServerRegistrationBlob struct {
	// PublicKey is the server's signing public key
	// This is used to verify signatures on unblinded shares
	PublicKey crypto.PublicKey `json:"public_key"`

	// KemPublicKey is the server's key exchange public key
	// This is used to establish shared secrets with clients
	KemPublicKey crypto.PublicKey `json:"kem_public_key"`

	// IsLeader indicates if this server is the leader of its anytrust group
	// The leader is responsible for collecting shares and producing the final output
	IsLeader bool `json:"is_leader"`
}

// UnmarshalMessage converts bytes to a message object
// This function uses JSON deserialization, which is not optimized for performance
// but provides good compatibility and debugging capabilities.
//
// Parameters:
// - data: The serialized message bytes
//
// Returns the deserialized message and any error that occurred.
func UnmarshalMessage[T any](data []byte) (*T, error) {
	var msg T
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

func DecodeMessage[T any](reader io.Reader) (*T, error) {
	var msg T
	err := json.NewDecoder(reader).Decode(&msg)
	return &msg, err
}

// SerializeMessage converts a message object to bytes
// This function uses JSON serialization, which is not optimized for performance
// but provides good compatibility and debugging capabilities.
//
// Parameters:
// - msg: The message to serialize
//
// Returns the serialized bytes and any error that occurred.
func SerializeMessage[T any](msg *T) ([]byte, error) {
	return json.Marshal(msg)
}
