package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func FuzzEncryptDecrypt(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})                             // Empty plaintext
	f.Add([]byte("hello"))                      // Simple message
	f.Add([]byte("hello world, this is a test")) // Longer message
	f.Add(make([]byte, 1000))                   // Large message

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Generate a key pair for each test
		privKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pubKey := privKey.PublicKey()

		// Encrypt
		encrypted, err := Encrypt(pubKey, plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Invariant 1: Encrypted message has expected structure
		if encrypted == nil {
			t.Fatal("encrypted message is nil")
		}
		if len(encrypted.EphemeralPubKey) != 65 {
			t.Errorf("ephemeral pubkey wrong size: got %d, want 65", len(encrypted.EphemeralPubKey))
		}
		if len(encrypted.Nonce) != 12 {
			t.Errorf("nonce wrong size: got %d, want 12", len(encrypted.Nonce))
		}
		// Ciphertext should be at least plaintext length + 16 (GCM tag)
		if len(encrypted.Ciphertext) < len(plaintext)+16 {
			t.Errorf("ciphertext too short: got %d, want >= %d", len(encrypted.Ciphertext), len(plaintext)+16)
		}

		// Decrypt
		decrypted, err := Decrypt(privKey, encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		// Invariant 2: Round-trip preserves plaintext
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("round trip failed: got %v, want %v", decrypted, plaintext)
		}

		// Invariant 3: Wrong key fails decryption
		wrongKey, _ := ecdh.P256().GenerateKey(rand.Reader)
		_, err = Decrypt(wrongKey, encrypted)
		if err == nil {
			t.Error("decryption with wrong key should fail")
		}
	})
}

func FuzzParseEncryptedMessage(f *testing.F) {
	// Add seed corpus with various lengths
	f.Add(make([]byte, 0))   // Empty
	f.Add(make([]byte, 50))  // Too short
	f.Add(make([]byte, 92))  // Just under minimum
	f.Add(make([]byte, 93))  // Minimum valid length
	f.Add(make([]byte, 100)) // Valid length
	f.Add(make([]byte, 500)) // Larger message

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseEncryptedMessage(data)

		// Invariant 1: Messages < 93 bytes should fail
		minLen := 65 + 12 + 16 // ephemeralPubKey + nonce + min ciphertext (just tag)
		if len(data) < minLen {
			if err == nil {
				t.Errorf("parsing should fail for data length %d < %d", len(data), minLen)
			}
			return
		}

		// For valid-length messages, parsing should succeed
		if err != nil {
			// This is okay - the data might be malformed in other ways
			return
		}

		// Invariant 2: Parsed fields have correct lengths
		if len(msg.EphemeralPubKey) != 65 {
			t.Errorf("ephemeral pubkey wrong size: got %d, want 65", len(msg.EphemeralPubKey))
		}
		if len(msg.Nonce) != 12 {
			t.Errorf("nonce wrong size: got %d, want 12", len(msg.Nonce))
		}
		expectedCiphertextLen := len(data) - 65 - 12
		if len(msg.Ciphertext) != expectedCiphertextLen {
			t.Errorf("ciphertext wrong size: got %d, want %d", len(msg.Ciphertext), expectedCiphertextLen)
		}

		// Invariant 3: Serialization round-trip
		serialized := msg.Bytes()
		if !bytes.Equal(serialized, data) {
			t.Errorf("serialization round trip failed")
		}
	})
}

func FuzzEncryptedMessageTampering(f *testing.F) {
	f.Add([]byte("test message"), 0)
	f.Add([]byte("another test"), 50)

	f.Fuzz(func(t *testing.T, plaintext []byte, tamperIndex int) {
		if len(plaintext) == 0 {
			t.Skip()
		}

		privKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		encrypted, err := Encrypt(privKey.PublicKey(), plaintext)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		// Serialize the message
		serialized := encrypted.Bytes()
		if len(serialized) == 0 {
			t.Skip()
		}

		// Tamper with a byte
		tamperIndex = tamperIndex % len(serialized)
		if tamperIndex < 0 {
			tamperIndex = -tamperIndex
		}
		tampered := make([]byte, len(serialized))
		copy(tampered, serialized)
		tampered[tamperIndex] ^= 0xFF

		// Parse tampered message
		tamperedMsg, err := ParseEncryptedMessage(tampered)
		if err != nil {
			// Parsing might fail, which is fine
			return
		}

		// Decryption should fail due to authentication
		_, err = Decrypt(privKey, tamperedMsg)
		if err == nil {
			t.Error("decryption of tampered message should fail")
		}
	})
}
