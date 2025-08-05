package crypto

import (
	"math/big"
)

// MessageFieldOrder defines the finite field order for message operations
var MessageFieldOrder *big.Int

// AuctionFieldOrder defines the finite field order for auction operations
var AuctionFieldOrder *big.Int

func init() {
	// 513 bits so that we can encode 512 bits of data in a chunk for 10k clients, deg(5) and 10 servers
	MessageFieldOrder, _ = big.NewInt(0).SetString("23551861483160902848625974283278945001376208178765538238759867299042020937974421928051251754596306387970642948144090145836318438166833376091610669188604919", 10)

	AuctionFieldOrder, _ = big.NewInt(0).SetString("63275151763513965838163916473346901052322656945674817744137239911918558788929646550175002249326583566310537778017647", 16) // 385 bits prime
}

// FieldAddInplace performs modular addition in-place: l = (l + r) mod fieldOrder.
// The result is stored in l and also returned.
func FieldAddInplace(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	l.Add(l, r)
	if l.Cmp(fieldOrder) > 0 {
		l.Sub(l, fieldOrder)
	}

	if l.Sign() < 0 {
		l.Add(l, fieldOrder)
	}

	/*
		if l.Cmp(fieldOrder) > 0 {
			panic("l + r > 2*field")
		}
		if l.Sign() < 0 {
			panic("l - r < 2*field")
		}
	*/

	return l
}

// FieldSubInplace performs modular subtraction in-place: l = (l - r) mod fieldOrder.
// The result is stored in l and also returned.
func FieldSubInplace(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	l.Sub(l, r)
	if l.Cmp(fieldOrder) > 0 {
		l.Sub(l, fieldOrder)
	}
	if l.Sign() < 0 {
		l.Add(l, fieldOrder)
	}
	return l
}
