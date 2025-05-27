package blind_auction

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/flashbots/adcnet/crypto"
)

type MessagePad []byte
type AuctionPad []byte
type CountersPad []uint64

// BlindingVector contains one-time pads for message and auction data encryption.
// Assumes secure shared key establishment and unique round/key combinations.
// Provides confidentiality only, no authentication.
type BlindingVector struct {
	MessagePad  MessagePad
	AuctionPad  AuctionPad
	CountersPad CountersPad
}

// NewBlindingVector creates a new blinding vector with specified sizes.
func NewBlindingVector(msgSize uint32, auctionBuckets uint32) *BlindingVector {
	return &BlindingVector{
		MessagePad:  make([]byte, msgSize),
		AuctionPad:  make([]byte, IBFVectorSize(auctionBuckets)),
		CountersPad: make([]uint64, IBFVectorLength(auctionBuckets)),
	}
}

// UnionInplace merges another blinding vector into this one.
func (b *BlindingVector) UnionInplace(other *BlindingVector) {
	crypto.XorInplace(b.AuctionPad, other.AuctionPad)
	crypto.XorInplace(b.MessagePad, other.MessagePad)
	UnionCounterPadsInplace(b.CountersPad, other.CountersPad)
}

// DeriveInplace derives blinding pads from shared secrets, and applies them.
// Uses HKDF-SHA256. Assumes sharedKey has sufficient entropy.
// Deterministic - same inputs produce same pads.
func (b *BlindingVector) DeriveInplace(round int, sharedKey crypto.SharedKey, previousRoundAuction *IBFVector) error {
	roundSalt := binary.BigEndian.AppendUint32(sharedKey.Bytes(), uint32(round))
	if previousRoundAuction != nil {
		roundSalt = append(roundSalt, previousRoundAuction.Bytes()...)
	}

	messagePad, err := hkdf.Key(sha256.New, append(roundSalt, "message"...), nil, "", len(b.MessagePad))
	if err != nil {
		return err
	}

	crypto.XorInplace(b.MessagePad, messagePad)

	auctionPad, err := hkdf.Key(sha256.New, append(roundSalt, "auction"...), nil, "", len(b.AuctionPad))
	if err != nil {
		return err
	}

	crypto.XorInplace(b.AuctionPad, auctionPad)

	elements, err := GenCounterBlinders(roundSalt, len(b.CountersPad))
	if err != nil {
		return err
	}
	UnionCounterPadsInplace(b.CountersPad, elements)
	return nil
}

// GenCounterBlinders generates field elements for counter blinding.
func GenCounterBlinders(roundSalt []byte, length int) (CountersPad, error) {
	elements := []uint64{}
	counterPad, err := hkdf.Key(sha256.New, append(roundSalt, "counters"...), nil, "", length*8)
	if err != nil {
		return nil, err
	}

	for counterPadIndex := 0; counterPadIndex < length*8; counterPadIndex += 8 {
		fieldElement := binary.BigEndian.Uint64(counterPad[counterPadIndex:counterPadIndex+8]) % CounterFieldSize
		elements = append(elements, fieldElement)
	}

	return elements, nil
}

// Note: this is all most likely insecure. Only for illustration!
// Field size for counter blinding (using a prime field GF(p))
// Note: field is small, and a motivated adversary could brute-force it after some observation.
const CounterFieldSize uint64 = 0xFFFFFFFFFFFFFFFB // 2^64 - 5, a prime number

// BlindCounter blinds a counter value using modular addition.
// Vulnerable to statistical analysis over multiple rounds!
// TODO: Replace with Pedersen commitments or other secure scheme.
func BlindCounter(counter uint64, pad uint64) uint64 {
	// Convert counter to unsigned and compute in the field
	return (counter + pad) % CounterFieldSize
}

// UnionCounterPadsInplace merges counter pads using field addition.
func UnionCounterPadsInplace(pads1 CountersPad, pads2 CountersPad) {
	for i := range pads1 {
		pads1[i] = (pads1[i] + pads2[i]) % CounterFieldSize
	}
}

// UnblindCounter removes the blinding from a counter.
func UnblindCounter(blindedCounter uint64, pad uint64) int {
	// Compute (blinded - pad) mod p
	// Add p before subtracting to avoid underflow
	result := (blindedCounter - (pad % CounterFieldSize) + CounterFieldSize) % CounterFieldSize
	return int(result)
}

// AddBlindedCounters adds two blinded counters in the field.
func AddBlindedCounters(a, b uint64) uint64 {
	return (a + b) % CounterFieldSize
}
