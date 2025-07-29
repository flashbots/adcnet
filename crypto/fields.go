package crypto

import (
	"math/big"
)

var prfSeed *big.Int

// MessageFieldOrder defines the finite field order for message operations (513 bits).
var MessageFieldOrder *big.Int

// AuctionFieldOrder defines the finite field order for auction operations (384 bits).
var AuctionFieldOrder *big.Int

func init() {
	// 513 bits so that we can encode 512 bits of data in a chunk
	MessageFieldOrder, _ = big.NewInt(0).SetString("23551861483160902848625974283278945001376208178765538238759867299042020937974421928051251754596306387970642948144090145836318438166833376091610669188604919", 10)
	AuctionFieldOrder, _ = big.NewInt(0).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16) // 384 bits ring
	prfSeed, _ = big.NewInt(0).SetString("21384347777672109934322149984740494809390049493978212797410708129763158788480720729944469031881574875043683705480707297038846484696174296250022771335208983", 10)
}

// FieldAddInplace performs modular addition in-place: l = (l + r) mod fieldOrder.
// The result is stored in l and also returned.
// TODO: bench & optimize
func FieldAddInplace(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	l.Add(l, r)
	l.Mod(l, fieldOrder)
	/*
		for l.Cmp(fieldOrder) > 1 {
			l = l.Sub(l, fieldOrder)
		}
		for l.Sign() < 0 {
			l = l.Add(l, fieldOrder)
		}
	*/
	return l
}

// FieldSubInplace performs modular subtraction in-place: l = (l - r) mod fieldOrder.
// The result is stored in l and also returned.
// TODO: bench & optimize
func FieldSubInplace(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	l.Sub(l, r)
	l.Mod(l, fieldOrder)
	/*
		for l.Sign() < 0 {
			l.Add(l, fieldOrder)
		}
		for l.Cmp(fieldOrder) > 1 {
			l.Sub(l, fieldOrder)
		}*/
	return l
}
