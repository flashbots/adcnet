package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/flashbots/adcnet/crypto"
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

type AuctionData struct {
	MessageHash crypto.Hash
	Weight int
}

func (a *AuctionData) EncodeToChunk() [IBFChunkSize]byte {
	var res [IBFChunkSize]byte
	binary.BigEndian.PutUint64(res[0:8], uint64(a.Weight))
	copy(res[8:40], a.MessageHash[:])
	return res
}

func AuctionDataFromChunk(chunk [IBFChunkSize]byte) *AuctionData {
	var res AuctionData

	copy(res.MessageHash[:], chunk[8:40])
	res.Weight = int(binary.BigEndian.Uint64(chunk[0:8]))

	return &res
}

func AuctionDataFromMessage(msg []byte, weight int) *AuctionData {
	return &AuctionData{
		MessageHash: sha256.Sum256(msg),
		Weight: weight,
	}
}


type MessageVector = []byte

type ClientRoundData struct {
	RoundNubmer int
	IBFVector IBFVector
	MessageVector MessageVector
}

func (c *ClientRoundData) Encrypt(ibfVectorPad []byte, msgVectorPad []byte) *ClientRoundMessage {
	// pads are the xor of pads generated for each server
	return nil
}

func (c *ClientRoundData) Decrypt(ibfVectorPad []byte, msgVectorPad []byte) *ClientRoundMessage {
	// pads are the xor of pads generated for each server
	return nil
}


type ClientRoundMessage struct {
	RoundNubmer int
	IBFVector *IBFVector
	MessageVector MessageVector
}

// TODO: how do we aggregate secrets for ibf?
func (*IBFVector) Unblind() {
}

type AggregatedClientMessages struct {
	RoundNubmer int
	IBFVector *IBFVector
	MessageVector MessageVector
	UserPKs []crypto.PublicKey
}

func (m *AggregatedClientMessages) AggregateClientMessages(msgs []*Signed[ClientRoundMessage]) *AggregatedClientMessages {
	return nil
}

func (m *AggregatedClientMessages) AggregateAggregates(msgs []*AggregatedClientMessages) *AggregatedClientMessages {
	return nil
}

type ServerPartialDecryptionMessage struct {
	OriginalAggregate AggregatedClientMessages
	UserPKs []crypto.PublicKey
	SchedulingPad []byte
	MessagePad []byte
	CounterBlinder []uint64
}

func UnblindAggregates(msgs []*AggregatedClientMessages, ibfVectorPad []byte, msgVectorPad []byte) *ServerPartialDecryptionMessage {
	return nil
}

type ServerRoundData struct {
	RoundNubmer int
	IBFVector *IBFVector
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
