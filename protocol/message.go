package protocol

import (
	"encoding/json"
	"errors"
	"io"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

// Signed provides authentication for protocol messages.
// Security: Uses Ed25519 signatures. Assumes private keys are secure.
// Note: Signature covers serialized object + public key to prevent substitution.
type Signed[T any] struct {
	PublicKey crypto.PublicKey `json:"public_key"`
	Signature crypto.Signature `json:"signature"`
	Object    *T               `json:"object"`
}

// NewSigned creates a signed message.
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

// UnsafeObject returns the object without signature verification.
func (s *Signed[T]) UnsafeObject() *T {
	return s.Object
}

// Recover verifies the signature and returns the object and signer's public key.
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

type MessageVector []byte

// ClientRoundMessage contains a client's encrypted message and auction bid for a round.
type ClientRoundMessage struct {
	RoundNubmer   int
	AuctionVector *blind_auction.IBFVector
	MessageVector MessageVector
}

// AggregatedClientMessages contains aggregated messages from multiple clients.
type AggregatedClientMessages struct {
	RoundNubmer   int
	AuctionVector *blind_auction.IBFVector
	MessageVector MessageVector
	UserPKs       []crypto.PublicKey
}

// ServerPartialDecryptionMessage contains a server's partial decryption share.
type ServerPartialDecryptionMessage struct {
	OriginalAggregate AggregatedClientMessages
	UserPKs           []crypto.PublicKey
	BlindingVector    *blind_auction.BlindingVector
}

// ServerRoundData contains the final decrypted round output.
type ServerRoundData struct {
	RoundNubmer   int
	AuctionVector *blind_auction.IBFVector
	MessageVector MessageVector
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

// UnmarshalMessage deserializes a message from JSON bytes.
func UnmarshalMessage[T any](data []byte) (*T, error) {
	var msg T
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

// DecodeMessage deserializes a message from a JSON reader.
func DecodeMessage[T any](reader io.Reader) (*T, error) {
	var msg T
	err := json.NewDecoder(reader).Decode(&msg)
	return &msg, err
}

// SerializeMessage serializes a message to JSON bytes.
func SerializeMessage[T any](msg *T) ([]byte, error) {
	return json.Marshal(msg)
}
