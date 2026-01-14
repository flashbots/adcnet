package crypto

import (
	"math/big"
	"testing"
)

func FuzzFieldAddInplace(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0}, []byte{0})
	f.Add([]byte{1}, []byte{1})
	f.Add([]byte{255}, []byte{255})
	f.Add(make([]byte, 48), make([]byte, 48)) // Field element size

	f.Fuzz(func(t *testing.T, aBytes, bBytes []byte) {
		a := new(big.Int).SetBytes(aBytes)
		b := new(big.Int).SetBytes(bBytes)

		// Reduce to valid field elements
		a.Mod(a, AuctionFieldOrder)
		b.Mod(b, AuctionFieldOrder)

		// Make copies for verification
		aCopy := new(big.Int).Set(a)
		bCopy := new(big.Int).Set(b)

		// Perform addition
		result := FieldAddInplace(a, b, AuctionFieldOrder)

		// Invariant 1: Result is in range [0, fieldOrder)
		if result.Sign() < 0 {
			t.Errorf("result is negative: %v", result)
		}
		if result.Cmp(AuctionFieldOrder) >= 0 {
			t.Errorf("result >= fieldOrder: %v >= %v", result, AuctionFieldOrder)
		}

		// Invariant 2: Result equals (a + b) mod fieldOrder
		expected := new(big.Int).Add(aCopy, bCopy)
		expected.Mod(expected, AuctionFieldOrder)
		if result.Cmp(expected) != 0 {
			t.Errorf("incorrect result: got %v, want %v", result, expected)
		}

		// Invariant 3: Commutativity - (a + b) = (b + a)
		a2 := new(big.Int).Set(bCopy)
		b2 := new(big.Int).Set(aCopy)
		result2 := FieldAddInplace(a2, b2, AuctionFieldOrder)
		if result.Cmp(result2) != 0 {
			t.Errorf("commutativity failed: %v + %v = %v, but %v + %v = %v",
				aCopy, bCopy, result, bCopy, aCopy, result2)
		}
	})
}

func FuzzFieldSubInplace(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0}, []byte{0})
	f.Add([]byte{1}, []byte{1})
	f.Add([]byte{1}, []byte{2}) // Underflow case
	f.Add(make([]byte, 48), make([]byte, 48))

	f.Fuzz(func(t *testing.T, aBytes, bBytes []byte) {
		a := new(big.Int).SetBytes(aBytes)
		b := new(big.Int).SetBytes(bBytes)

		// Reduce to valid field elements
		a.Mod(a, AuctionFieldOrder)
		b.Mod(b, AuctionFieldOrder)

		// Make copies for verification
		aCopy := new(big.Int).Set(a)
		bCopy := new(big.Int).Set(b)

		// Perform subtraction
		result := FieldSubInplace(a, b, AuctionFieldOrder)

		// Invariant 1: Result is in range [0, fieldOrder)
		if result.Sign() < 0 {
			t.Errorf("result is negative: %v", result)
		}
		if result.Cmp(AuctionFieldOrder) >= 0 {
			t.Errorf("result >= fieldOrder: %v >= %v", result, AuctionFieldOrder)
		}

		// Invariant 2: Result equals (a - b) mod fieldOrder
		expected := new(big.Int).Sub(aCopy, bCopy)
		expected.Mod(expected, AuctionFieldOrder)
		if expected.Sign() < 0 {
			expected.Add(expected, AuctionFieldOrder)
		}
		if result.Cmp(expected) != 0 {
			t.Errorf("incorrect result: got %v, want %v (a=%v, b=%v)", result, expected, aCopy, bCopy)
		}

		// Invariant 3: (a - b + b) mod p = a mod p (inverse of addition)
		resultCopy := new(big.Int).Set(result)
		roundTrip := FieldAddInplace(resultCopy, bCopy, AuctionFieldOrder)
		if roundTrip.Cmp(aCopy) != 0 {
			t.Errorf("inverse property failed: (%v - %v) + %v = %v, want %v",
				aCopy, bCopy, bCopy, roundTrip, aCopy)
		}
	})
}

func FuzzFieldAddSubRoundTrip(f *testing.F) {
	f.Add([]byte{42}, []byte{17})
	f.Add(make([]byte, 48), make([]byte, 48))

	f.Fuzz(func(t *testing.T, aBytes, bBytes []byte) {
		a := new(big.Int).SetBytes(aBytes)
		b := new(big.Int).SetBytes(bBytes)

		a.Mod(a, AuctionFieldOrder)
		b.Mod(b, AuctionFieldOrder)

		original := new(big.Int).Set(a)

		// Add then subtract should give original
		FieldAddInplace(a, b, AuctionFieldOrder)
		FieldSubInplace(a, b, AuctionFieldOrder)

		if a.Cmp(original) != 0 {
			t.Errorf("round trip failed: started with %v, ended with %v (added/subtracted %v)",
				original, a, b)
		}
	})
}
