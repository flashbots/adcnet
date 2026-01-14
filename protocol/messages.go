package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

type ServerID = crypto.ServerID

// Signed wraps a message with Ed25519 signature for authentication.
type Signed[T any] struct {
	PublicKey crypto.PublicKey `json:"public_key"`
	Signature crypto.Signature `json:"signature"`
	Object    *T               `json:"object"`
}

// NewSigned creates an authenticated message by signing the serialized object and public key.
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

// UnsafeObject returns the wrapped object without verifying the signature.
func (s *Signed[T]) UnsafeObject() *T {
	return s.Object
}

// Recover verifies the signature and returns the authenticated object with signer's public key.
func (s *Signed[T]) Recover() (*T, crypto.PublicKey, error) {
	serializedData, err := SerializeMessage(s.Object)
	if err != nil {
		return nil, nil, err
	}

	ok := s.Signature.Verify(s.PublicKey, append(serializedData, s.PublicKey...))
	if !ok {
		return nil, nil, errors.New("signature not valid")
	}

	return s.Object, s.PublicKey, nil
}

// ClientRoundMessage contains a client's blinded message and auction data.
type ClientRoundMessage struct {
	RoundNumber   int
	AllServerIds  []ServerID
	AuctionVector []*big.Int // Field-blinded auction IBLT elements
	MessageVector []byte     // XOR-blinded message bytes
}

// AggregatedClientMessages contains combined data from multiple clients.
type AggregatedClientMessages struct {
	RoundNumber   int
	AllServerIds  []ServerID
	AuctionVector []*big.Int         // Sum of client auction vectors in field
	MessageVector []byte             // XOR of client message vectors
	UserPKs       []crypto.PublicKey // Public keys of contributing clients
}

// UnionInplace adds another aggregate's vectors to this one in-place.
// XORs message vectors and adds auction vectors in the finite field.
func (m *AggregatedClientMessages) UnionInplace(o *AggregatedClientMessages) (*AggregatedClientMessages, error) {
	if m.RoundNumber == 0 {
		m.RoundNumber = o.RoundNumber
	} else if m.RoundNumber != o.RoundNumber {
		return nil, errors.New("mismatching rounds")
	}

	if m.AllServerIds == nil {
		m.AllServerIds = o.AllServerIds
	} else if !slices.Equal(m.AllServerIds, o.AllServerIds) {

		return nil, errors.New("mismatching share servers")
	}

	if m.AuctionVector == nil {
		m.AuctionVector = make([]*big.Int, len(o.AuctionVector))
		for i := range m.AuctionVector {
			m.AuctionVector[i] = big.NewInt(0)
		}
	}
	if m.MessageVector == nil {
		m.MessageVector = make([]byte, len(o.MessageVector))
	}
	if m.UserPKs == nil {
		m.UserPKs = []crypto.PublicKey{}
	}

	for i := range o.AuctionVector {
		crypto.FieldAddInplace(m.AuctionVector[i], o.AuctionVector[i], crypto.AuctionFieldOrder)
	}
	crypto.XorInplace(m.MessageVector, o.MessageVector)

	m.UserPKs = append(m.UserPKs, o.UserPKs...)

	return m, nil
}

// ServerPartialDecryptionMessage contains a server's blinding contribution.
type ServerPartialDecryptionMessage struct {
	ServerID          ServerID
	OriginalAggregate *AggregatedClientMessages
	UserPKs           []crypto.PublicKey
	AuctionVector     []*big.Int // Server's auction blinding vector
	MessageVector     []byte     // Server's XOR blinding vector
}

// RoundBroadcast contains the final reconstructed broadcast for a round.
type RoundBroadcast struct {
	RoundNumber   int
	AuctionVector *blind_auction.IBLTVector
	MessageVector []byte
}

// UnmarshalMessage deserializes a message from JSON.
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

// SerializeMessage serializes a message to JSON.
func SerializeMessage[T any](msg *T) ([]byte, error) {
	return json.Marshal(msg)
}
