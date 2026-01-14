package crypto

import (
	"bytes"
	"testing"
)

func FuzzSignVerify(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})                  // Empty message
	f.Add([]byte("hello"))           // Simple message
	f.Add([]byte("test message 123")) // Longer message
	f.Add(make([]byte, 1000))        // Large message

	f.Fuzz(func(t *testing.T, data []byte) {
		// Generate a key pair
		pubKey, privKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		// Sign
		signature, err := Sign(privKey, data)
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		// Invariant 1: Signature has correct length (Ed25519 = 64 bytes)
		if len(signature) != 64 {
			t.Errorf("signature wrong length: got %d, want 64", len(signature))
		}

		// Invariant 2: Signature verifies with correct public key
		if !signature.Verify(pubKey, data) {
			t.Error("signature verification failed with correct key")
		}

		// Invariant 3: Signature fails with wrong public key
		wrongPubKey, _, _ := GenerateKeyPair()
		if signature.Verify(wrongPubKey, data) {
			t.Error("signature should not verify with wrong public key")
		}

		// Invariant 4: Modified data fails verification
		if len(data) > 0 {
			modifiedData := make([]byte, len(data))
			copy(modifiedData, data)
			modifiedData[0] ^= 0xFF
			if signature.Verify(pubKey, modifiedData) {
				t.Error("signature should not verify with modified data")
			}
		}

		// Invariant 5: Modified signature fails verification
		modifiedSig := make(Signature, len(signature))
		copy(modifiedSig, signature)
		modifiedSig[0] ^= 0xFF
		if modifiedSig.Verify(pubKey, data) {
			t.Error("modified signature should not verify")
		}

		// Invariant 6: Determinism - signing same data twice gives same signature
		signature2, _ := Sign(privKey, data)
		if !bytes.Equal(signature, signature2) {
			t.Error("signing is not deterministic")
		}
	})
}

func FuzzXorInplace(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{0}, []byte{0})
	f.Add([]byte{255}, []byte{255})
	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})
	f.Add(make([]byte, 100), make([]byte, 100))

	f.Fuzz(func(t *testing.T, a, b []byte) {
		// XorInplace requires equal lengths
		if len(a) != len(b) || len(a) == 0 {
			t.Skip()
		}

		// Keep copies of originals
		aCopy := make([]byte, len(a))
		bCopy := make([]byte, len(b))
		copy(aCopy, a)
		copy(bCopy, b)

		// Perform XOR
		result := XorInplace(a, b)

		// Invariant 1: Result is same slice as a
		if &result[0] != &a[0] {
			t.Error("XorInplace should return the same slice")
		}

		// Invariant 2: Result has correct XOR values
		for i := range result {
			expected := aCopy[i] ^ bCopy[i]
			if result[i] != expected {
				t.Errorf("incorrect XOR at index %d: got %d, want %d", i, result[i], expected)
			}
		}

		// Invariant 3: Self-inverse property: XOR(XOR(a, b), b) = a
		XorInplace(a, b)
		if !bytes.Equal(a, aCopy) {
			t.Error("XOR is not self-inverse")
		}

		// Invariant 4: XOR with zeros is identity
		zeros := make([]byte, len(a))
		copy(a, aCopy)
		XorInplace(a, zeros)
		if !bytes.Equal(a, aCopy) {
			t.Error("XOR with zeros should be identity")
		}

		// Invariant 5: XOR with self is zeros
		copy(a, aCopy)
		XorInplace(a, aCopy)
		for i, v := range a {
			if v != 0 {
				t.Errorf("XOR with self should be zero, got %d at index %d", v, i)
			}
		}
	})
}

func FuzzPublicKeyToServerID(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4})
	f.Add(make([]byte, 32)) // Typical Ed25519 pubkey size

	f.Fuzz(func(t *testing.T, pubKeyBytes []byte) {
		pubKey := PublicKey(pubKeyBytes)

		id := PublicKeyToServerID(pubKey)

		// Invariant 1: ID is never zero (reserved value handling)
		if id == 0 {
			t.Error("server ID should never be zero")
		}

		// Invariant 2: Determinism
		id2 := PublicKeyToServerID(pubKey)
		if id != id2 {
			t.Error("PublicKeyToServerID is not deterministic")
		}
	})
}

func FuzzPrivateKeyPublicKey(f *testing.F) {
	// Test that PrivateKey.PublicKey() is consistent
	f.Add(uint8(0))

	f.Fuzz(func(t *testing.T, _ uint8) {
		pubKey, privKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		// Invariant: Extracted public key matches generated public key
		extractedPubKey, err := privKey.PublicKey()
		if err != nil {
			t.Fatalf("failed to extract public key: %v", err)
		}

		if !bytes.Equal(pubKey, extractedPubKey) {
			t.Error("extracted public key doesn't match generated public key")
		}

		// Invariant: Key sizes are correct
		if len(pubKey) != 32 {
			t.Errorf("public key wrong size: got %d, want 32", len(pubKey))
		}
		if len(privKey) != 64 {
			t.Errorf("private key wrong size: got %d, want 64", len(privKey))
		}
	})
}

func FuzzNewPublicKeyFromString(f *testing.F) {
	// Add seed corpus
	f.Add("")
	f.Add("00")
	f.Add("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20") // 32 bytes hex
	f.Add("invalid")
	f.Add("0g") // Invalid hex

	f.Fuzz(func(t *testing.T, input string) {
		pubKey, err := NewPublicKeyFromString(input)

		if err != nil {
			// Error is expected for invalid hex
			return
		}

		// Invariant: String representation round-trips
		if pubKey.String() != input {
			t.Errorf("string round trip failed: got %s, want %s", pubKey.String(), input)
		}

		// Invariant: Bytes length matches hex length / 2
		expectedLen := len(input) / 2
		if len(pubKey) != expectedLen {
			t.Errorf("bytes length mismatch: got %d, want %d", len(pubKey), expectedLen)
		}
	})
}
