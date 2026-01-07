package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// NOTE: this is vibecoded.

// EncryptedMessage contains ECIES-encrypted data.
// Format: ephemeral pubkey (65 bytes) || nonce (12 bytes) || ciphertext+tag
type EncryptedMessage struct {
	EphemeralPubKey []byte // P-256 uncompressed public key
	Nonce           []byte // AES-GCM nonce
	Ciphertext      []byte // Encrypted data with auth tag
}

// Encrypt encrypts plaintext to a recipient's ECDH public key using ECIES.
// Uses ephemeral ECDH key agreement and AES-256-GCM for authenticated encryption.
func Encrypt(recipientPubKey *ecdh.PublicKey, plaintext []byte) (*EncryptedMessage, error) {
	// Generate ephemeral key pair
	ephemeralPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := ephemeralPriv.ECDH(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Use shared secret as AES key (first 32 bytes of SHA-256 hash)
	aesKey := deriveAESKey(sharedSecret)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with additional data binding to ephemeral key
	ciphertext := gcm.Seal(nil, nonce, plaintext, ephemeralPriv.PublicKey().Bytes())

	return &EncryptedMessage{
		EphemeralPubKey: ephemeralPriv.PublicKey().Bytes(),
		Nonce:           nonce,
		Ciphertext:      ciphertext,
	}, nil
}

// Decrypt decrypts an ECIES-encrypted message using the recipient's private key.
func Decrypt(recipientPrivKey *ecdh.PrivateKey, msg *EncryptedMessage) ([]byte, error) {
	// Parse ephemeral public key
	ephemeralPub, err := ecdh.P256().NewPublicKey(msg.EphemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral key: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := recipientPrivKey.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive AES key
	aesKey := deriveAESKey(sharedSecret)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(msg.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	// Decrypt with additional data verification
	plaintext, err := gcm.Open(nil, msg.Nonce, msg.Ciphertext, msg.EphemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// Bytes serializes an encrypted message.
func (m *EncryptedMessage) Bytes() []byte {
	result := make([]byte, 0, len(m.EphemeralPubKey)+len(m.Nonce)+len(m.Ciphertext))
	result = append(result, m.EphemeralPubKey...)
	result = append(result, m.Nonce...)
	result = append(result, m.Ciphertext...)
	return result
}

// ParseEncryptedMessage deserializes an encrypted message.
func ParseEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	// P-256 uncompressed pubkey is 65 bytes, nonce is 12 bytes
	const pubKeyLen = 65
	const nonceLen = 12
	minLen := pubKeyLen + nonceLen + 16 // 16 is minimum ciphertext (just auth tag)

	if len(data) < minLen {
		return nil, errors.New("encrypted message too short")
	}

	return &EncryptedMessage{
		EphemeralPubKey: data[:pubKeyLen],
		Nonce:           data[pubKeyLen : pubKeyLen+nonceLen],
		Ciphertext:      data[pubKeyLen+nonceLen:],
	}, nil
}

func deriveAESKey(sharedSecret []byte) []byte {
	// Simple key derivation using SHA3-256
	hash := make([]byte, 32)
	h := sha3.New256()
	h.Write([]byte("adcnet-ecies-v1"))
	h.Write(sharedSecret)
	return h.Sum(hash[:0])
}
