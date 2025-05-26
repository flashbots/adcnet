package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/flashbots/adcnet/crypto"
)

// InMemoryTEE implements the protocol.TEE interface for testing purposes.
// This implementation simulates a TEE by keeping secrets in memory, but
// does not provide actual hardware security guarantees.
type InMemoryTEE struct {
	// A unique identifier for this TEE instance
	instanceID []byte

	// Private keys stored within the TEE
	privateKeys map[string]crypto.PrivateKey

	// A secret sealing key used to encrypt/decrypt data
	sealingKey []byte

	// Attestation verification key
	attestationKey []byte

	// Mutex for thread safety
	mu sync.Mutex
}

// NewInMemoryTEE creates a new instance of an in-memory TEE.
// Each instance has its own unique ID and sealing keys.
func NewInMemoryTEE() (*InMemoryTEE, error) {
	// Generate a random instance ID
	instanceID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, instanceID); err != nil {
		return nil, fmt.Errorf("failed to generate instance ID: %w", err)
	}

	// Generate a random sealing key
	sealingKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sealingKey); err != nil {
		return nil, fmt.Errorf("failed to generate sealing key: %w", err)
	}

	// Generate a random attestation key
	attestationKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, attestationKey); err != nil {
		return nil, fmt.Errorf("failed to generate attestation key: %w", err)
	}

	return &InMemoryTEE{
		instanceID:     instanceID,
		privateKeys:    make(map[string]crypto.PrivateKey),
		sealingKey:     sealingKey,
		attestationKey: attestationKey,
	}, nil
}

// Attest produces an attestation of the code running in the TEE.
// For this in-memory implementation, we just create a signed blob
// containing the instance ID.
func (t *InMemoryTEE) Attest() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Create a simple attestation containing the instance ID
	// In a real TEE, this would include measurements of the code
	attestationData := make([]byte, len(t.instanceID)+8)
	binary.LittleEndian.PutUint64(attestationData[:8], uint64(0x1234)) // Version
	copy(attestationData[8:], t.instanceID)

	// Sign the attestation with the attestation key
	h := hmac.New(sha256.New, t.attestationKey)
	h.Write(attestationData)
	signature := h.Sum(nil)

	// Combine data and signature
	result := make([]byte, len(attestationData)+len(signature))
	copy(result, attestationData)
	copy(result[len(attestationData):], signature)

	return result, nil
}

// VerifyAttestation verifies an attestation from another TEE.
func (t *InMemoryTEE) VerifyAttestation(attestation []byte) (bool, error) {
	if len(attestation) < 40 { // 8 bytes version + 16 bytes ID + 32 bytes signature
		return false, errors.New("attestation data too short")
	}

	// Extract the data and signature
	data := attestation[:len(attestation)-32]
	signature := attestation[len(attestation)-32:]

	// In a real implementation, we would verify that the attestation
	// contains valid measurements and is signed by a trusted authority.
	// For this in-memory implementation, we'll just check the signature.
	h := hmac.New(sha256.New, t.attestationKey)
	h.Write(data)
	expectedSignature := h.Sum(nil)

	// Compare signatures
	if hmac.Equal(signature, expectedSignature) {
		return true, nil
	}

	return false, nil
}

// SealData encrypts data for storage outside the TEE.
// This simulates sealing by encrypting with the TEE's instance-specific key.
func (t *InMemoryTEE) SealData(data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Create a simple encryption scheme using AES-GCM
	block, err := aes.NewCipher(t.sealingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal the data
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, t.instanceID)

	// Combine nonce and ciphertext
	sealed := make([]byte, len(nonce)+len(ciphertext))
	copy(sealed, nonce)
	copy(sealed[len(nonce):], ciphertext)

	return sealed, nil
}

// UnsealData decrypts data that was previously sealed by this TEE instance.
func (t *InMemoryTEE) UnsealData(sealedData []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(sealedData) < 12 {
		return nil, errors.New("sealed data too short")
	}

	// Extract nonce and ciphertext
	nonce := sealedData[:12]
	ciphertext := sealedData[12:]

	// Create cipher
	block, err := aes.NewCipher(t.sealingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Unseal the data
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, t.instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateKeys generates a key pair within the TEE.
func (t *InMemoryTEE) GenerateKeys() (crypto.PublicKey, crypto.PrivateKey, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Generate a key pair using the crypto package
	pubKey, privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Store the private key inside the TEE
	keyID := pubKey.String()
	t.privateKeys[keyID] = privKey

	return pubKey, privKey, nil
}

// Sign signs data with a private key stored in the TEE.
func (t *InMemoryTEE) Sign(data []byte) (crypto.Signature, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// For this implementation, we'll sign with the first available key.
	// In a real implementation, we would need to specify which key to use.
	if len(t.privateKeys) == 0 {
		return nil, errors.New("no private keys available for signing")
	}

	var privKey crypto.PrivateKey
	for _, key := range t.privateKeys {
		privKey = key
		break
	}

	// Sign the data using the crypto package
	return crypto.Sign(privKey, data)
}

// StorePrivateKey allows storing an existing private key in the TEE.
// This is useful for testing with predefined keys.
func (t *InMemoryTEE) StorePrivateKey(id string, privKey crypto.PrivateKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.privateKeys[id] = privKey
}

// GetInstanceID returns the unique identifier for this TEE instance.
// This is primarily for testing purposes.
func (t *InMemoryTEE) GetInstanceID() []byte {
	return t.instanceID
}
