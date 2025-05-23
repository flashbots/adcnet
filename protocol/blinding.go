package protocol

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/flashbots/adcnet/crypto"
)

type BlindingVector struct {
	MessagePad  []byte
	AuctionPad  []byte
	CountersPad []uint64
}

func NewBlindingVector(msgSize uint32, auctionBuckets uint32) *BlindingVector {
	return &BlindingVector{
		MessagePad:  make([]byte, msgSize),
		AuctionPad:  make([]byte, IBFVectorSize(auctionBuckets)),
		CountersPad: make([]uint64, IBFVectorLength(auctionBuckets)),
	}
}

func (b *BlindingVector) UnionInplace(other *BlindingVector) {
	crypto.XorInplace(b.AuctionPad, other.AuctionPad)
	crypto.XorInplace(b.MessagePad, other.MessagePad)
	UnionCounterPadsInplace(b.CountersPad, other.CountersPad)
}

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

func GenCounterBlinders(roundSalt []byte, length int) ([]uint64, error) {
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
