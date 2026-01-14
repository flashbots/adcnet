package crypto

import (
	"bytes"
	"testing"
)

func FuzzDeriveBlindingVector(f *testing.F) {
	// Add seed corpus with various parameters
	f.Add([]byte("shared-secret-1"), uint32(1), int32(10))
	f.Add([]byte("shared-secret-2"), uint32(0), int32(1))
	f.Add([]byte("shared-secret-3"), uint32(100), int32(50))

	f.Fuzz(func(t *testing.T, secret []byte, round uint32, nEls int32) {
		// Skip invalid inputs
		if len(secret) == 0 || nEls <= 0 || nEls > 1000 {
			t.Skip()
		}

		sharedSecrets := []SharedKey{secret}

		result := DeriveBlindingVector(sharedSecrets, round, nEls, AuctionFieldOrder)

		// Invariant 1: Output length matches nEls
		if len(result) != int(nEls) {
			t.Errorf("output length mismatch: got %d, want %d", len(result), nEls)
		}

		// Invariant 2: All elements are in valid field range
		for i, el := range result {
			if el == nil {
				t.Errorf("element %d is nil", i)
				continue
			}
			if el.Sign() < 0 {
				t.Errorf("element %d is negative: %v", i, el)
			}
			if el.Cmp(AuctionFieldOrder) >= 0 {
				t.Errorf("element %d >= fieldOrder: %v", i, el)
			}
		}

		// Invariant 3: Determinism - same inputs produce same outputs
		result2 := DeriveBlindingVector(sharedSecrets, round, nEls, AuctionFieldOrder)
		for i := range result {
			if result[i].Cmp(result2[i]) != 0 {
				t.Errorf("non-deterministic: element %d differs on second call", i)
			}
		}

		// Invariant 4: Different round produces different output (with high probability)
		if round < ^uint32(0) {
			result3 := DeriveBlindingVector(sharedSecrets, round+1, nEls, AuctionFieldOrder)
			allSame := true
			for i := range result {
				if result[i].Cmp(result3[i]) != 0 {
					allSame = false
					break
				}
			}
			if allSame && nEls > 0 {
				t.Errorf("different rounds produced identical output")
			}
		}
	})
}

func FuzzDeriveXorBlindingVector(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("shared-secret-1"), uint32(1), 100)
	f.Add([]byte("shared-secret-2"), uint32(0), 1)
	f.Add([]byte("shared-secret-3"), uint32(100), 16) // AES block size
	f.Add([]byte("shared-secret-4"), uint32(50), 17)  // Non-aligned

	f.Fuzz(func(t *testing.T, secret []byte, round uint32, nBytes int) {
		// Skip invalid inputs
		if len(secret) == 0 || nBytes < 0 || nBytes > 10000 {
			t.Skip()
		}

		sharedSecrets := []SharedKey{secret}

		result := DeriveXorBlindingVector(sharedSecrets, round, nBytes)

		// Invariant 1: Output length matches nBytes
		if len(result) != nBytes {
			t.Errorf("output length mismatch: got %d, want %d", len(result), nBytes)
		}

		// Invariant 2: Determinism
		result2 := DeriveXorBlindingVector(sharedSecrets, round, nBytes)
		if !bytes.Equal(result, result2) {
			t.Errorf("non-deterministic output")
		}

		// Invariant 3: Different round produces different output
		if nBytes > 0 && round < ^uint32(0) {
			result3 := DeriveXorBlindingVector(sharedSecrets, round+1, nBytes)
			if bytes.Equal(result, result3) {
				t.Errorf("different rounds produced identical output")
			}
		}

		// Invariant 4: Zero bytes returns empty slice
		if nBytes == 0 && len(result) != 0 {
			t.Errorf("zero nBytes should return empty slice")
		}
	})
}

func FuzzXorBlindingRoundTrip(f *testing.F) {
	f.Add([]byte("secret1"), []byte("secret2"), uint32(5), 100)

	f.Fuzz(func(t *testing.T, secret1, secret2 []byte, round uint32, nBytes int) {
		if len(secret1) == 0 || len(secret2) == 0 || nBytes <= 0 || nBytes > 1000 {
			t.Skip()
		}

		secrets := []SharedKey{secret1, secret2}

		// XOR blinding should be self-inverse when applied twice
		blinding := DeriveXorBlindingVector(secrets, round, nBytes)
		data := make([]byte, nBytes)
		for i := range data {
			data[i] = byte(i % 256)
		}
		original := make([]byte, nBytes)
		copy(original, data)

		// Apply blinding
		XorInplace(data, blinding)

		// Apply again (should restore original)
		XorInplace(data, blinding)

		if !bytes.Equal(data, original) {
			t.Errorf("XOR round trip failed")
		}
	})
}
