package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"slices"
)

// Hash represents a cryptographic hash value using SHA-256 (32 bytes).
// It's used throughout ADCNet for deriving identifiers, computing message
// digests, and as part of various cryptographic operations.
type Hash [32]byte

// NewHash creates a Hash from the given data using SHA-256.
// This function is deterministic - the same input will always produce
// the same output hash.
func NewHash(data []byte) Hash {
	return sha256.Sum256(data)
}

// Bytes returns the hash as a byte slice.
// This is useful when the hash needs to be used in contexts that
// expect a slice rather than a fixed-size array.
func (h Hash) Bytes() []byte {
	return h[:]
}

// Equal compares two hashes for equality in constant time.
// The constant-time comparison helps prevent timing attacks that
// could leak information about the hash values being compared.
func (h Hash) Equal(other Hash) bool {
	return subtle.ConstantTimeCompare(h[:], other[:]) == 1
}

// String returns a hex-encoded string representation of the hash.
// This is useful for logging and debugging.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// PublicKey represents a public key used for authentication and encryption.
// In ADCNet, public keys are used to verify signatures and as client/server identifiers.
// The implementation uses Ed25519 public keys.
type PublicKey []byte

// NewPublicKeyFromBytes creates a PublicKey from a byte slice.
// This function makes a copy of the input data to ensure immutability.
func NewPublicKeyFromBytes(data []byte) PublicKey {
	pk := make([]byte, len(data))
	copy(pk, data)
	return PublicKey(pk)
}

func NewPublicKeyFromString(data string) (PublicKey, error) {
	rawBytes, err := hex.DecodeString(data)
	if err != nil {
		return PublicKey{}, err
	}

	return NewPublicKeyFromBytes(rawBytes), nil
}

// Bytes returns the public key as a byte slice.
// This is useful when the key needs to be serialized or used in cryptographic operations.
func (pk PublicKey) Bytes() []byte {
	return pk
}

// Equal compares two public keys for equality.
// Two public keys are equal if they contain exactly the same bytes.
func (pk PublicKey) Equal(other PublicKey) bool {
	return bytes.Equal(pk, other)
}

// String returns a base64-encoded string representation of the public key.
// This is useful for logging, displaying to users, and using as a map key.
func (pk PublicKey) String() string {
	return hex.EncodeToString(pk)
}

// PrivateKey represents a private key used for signing and key exchange.
// In ADCNet, private keys should be kept secure and are only used by their owners.
// The implementation uses Ed25519 private keys.
type PrivateKey []byte

// NewPrivateKeyFromBytes creates a PrivateKey from a byte slice.
// This function makes a copy of the input data to ensure immutability.
func NewPrivateKeyFromBytes(data []byte) PrivateKey {
	sk := make([]byte, len(data))
	copy(sk, data)
	return PrivateKey(sk)
}

// Bytes returns the private key as a byte slice.
// This is useful when the key needs to be sealed in a TEE or used in cryptographic operations.
// This method should be used carefully as it exposes sensitive key material.
func (sk PrivateKey) Bytes() []byte {
	return sk
}

// PublicKey derives the public key corresponding to this private key.
// For Ed25519, the public key is contained within the private key structure.
// Returns an error if the private key has an invalid format.
func (sk PrivateKey) PublicKey() (PublicKey, error) {
	if len(sk) < ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	return PublicKey(sk[32:]), nil
}

// GenerateKeyPair generates a new Ed25519 key pair for signing and verification.
// The generated keys are cryptographically secure for use in the ADCNet protocol.
// Returns the public key, private key, and any error that occurred during generation.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(publicKey), PrivateKey(privateKey), nil
}

// Signature represents a digital signature produced with a private key.
// In ADCNet, signatures are used to authenticate messages from clients,
// aggregators, and servers.
type Signature []byte

// NewSignature creates a Signature from a byte slice.
// This function makes a copy of the input data to ensure immutability.
func NewSignature(data []byte) Signature {
	sig := make([]byte, len(data))
	copy(sig, data)
	return Signature(sig)
}

// Bytes returns the signature as a byte slice.
// This is useful when the signature needs to be serialized or transmitted.
func (s Signature) Bytes() []byte {
	return []byte(s)
}

// Verify checks if this signature is valid for the given data and public key.
// Returns true if the signature is valid, false otherwise.
// This is used to verify the authenticity of messages in the ADCNet protocol.
func (s Signature) Verify(publicKey PublicKey, data []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, s)
}

// String returns a base64-encoded string representation of the signature.
// This is useful for logging and debugging.
func (s Signature) String() string {
	return hex.EncodeToString(s.Bytes())
}

// Sign signs data with the given private key using Ed25519.
// Returns the signature and any error that occurred during signing.
// In ADCNet, this is used by clients, aggregators, and servers to sign their messages.
func Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), data)
	return Signature(signature), nil
}

// SharedKey represents Diffie-Hellman shared secret.
// Security: Must have ≥128 bits entropy. Must always be derived from,
// never used as-is.
// Current implementation doesn't enforce minimum entropy.
type SharedKey []byte

// NewSharedKey creates a SharedKey from a byte slice.
// This function makes a copy of the input data to ensure immutability.
func NewSharedKey(data []byte) SharedKey {
	sk := make([]byte, len(data))
	copy(sk, data)
	return SharedKey(sk)
}

// Bytes returns the shared key as a byte slice.
// This is useful when the key needs to be used in cryptographic operations.
func (sk SharedKey) Bytes() []byte {
	return slices.Clone(sk)
}

func Xor(data []byte, key []byte) []byte {
	res := slices.Clone(data)
	if len(data) != len(key) {
		panic("xor of unequal length, refusing to continue")
	}
	for i := range data {
		res[i] ^= key[i]
	}

	return res
}

func XorInplace(data []byte, key []byte) {
	if len(data) != len(key) {
		panic("xor of unequal length, refusing to continue")
	}
	for i := range data {
		data[i] ^= key[i]
	}
}
