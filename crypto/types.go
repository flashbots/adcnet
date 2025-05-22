package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"

	"crypto/hkdf"
)

// Hash represents a cryptographic hash value using SHA-256 (32 bytes).
// It's used throughout ZIPNet for deriving identifiers, computing message
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
// In ZIPNet, public keys are used to verify signatures and as client/server identifiers.
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
// In ZIPNet, private keys should be kept secure and are only used by their owners.
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
// The generated keys are cryptographically secure for use in the ZIPNet protocol.
// Returns the public key, private key, and any error that occurred during generation.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(publicKey), PrivateKey(privateKey), nil
}

// Signature represents a digital signature produced with a private key.
// In ZIPNet, signatures are used to authenticate messages from clients,
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
// This is used to verify the authenticity of messages in the ZIPNet protocol.
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
// In ZIPNet, this is used by clients, aggregators, and servers to sign their messages.
func Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), data)
	return Signature(signature), nil
}

// SharedKey represents a shared secret between two parties, typically
// derived using Diffie-Hellman key exchange.
// In ZIPNet, shared keys are established between clients and servers
// to derive one-time pads for blinding messages.
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
	return sk
}

// Ratchet derives a new key from this shared key for forward secrecy.
// In ZIPNet, keys are ratcheted after each round to prevent compromise
// of past communications if a key is later compromised.
// Returns the ratcheted key and any error that occurred during derivation.
func (sk SharedKey) Ratchet() (SharedKey, error) {
	hash := sha256.Sum256(sk)
	return NewSharedKey(hash[:]), nil
}

// Nonce is a cryptographic nonce used for rate limiting in the ZIPNet protocol.
// Clients generate unique nonces for each message to prevent replay and DoS attacks.
// Each nonce should be used only once within a rate limiting window.
type Nonce []byte

// NewNonce creates a Nonce from a byte slice.
func NewNonce(data []byte) Nonce {
	return Nonce(data)
}

// Bytes returns the nonce as a byte slice.
func (n Nonce) Bytes() []byte {
	return []byte(n)
}

// Equal compares two nonces for equality.
// Two nonces are equal if they contain exactly the same bytes.
func (n Nonce) Equal(other Nonce) bool {
	return bytes.Equal(n, other)
}

// String returns a base64-encoded string representation of the nonce.
// This is useful for logging and debugging.
func (n Nonce) String() string {
	if len(n) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(n)
}

// GenerateNonce creates a new random nonce of 16 bytes.
// The generated nonce is cryptographically secure and suitable
// for rate limiting in the ZIPNet protocol.
func GenerateNonce() (Nonce, error) {
	nonceBytes := make([]byte, 16)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return nil, err
	}
	return NewNonce(nonceBytes), nil
}

// Footprint represents a scheduling footprint in the ZIPNet protocol.
// Footprints are used in slot reservation to detect collisions when
// multiple clients attempt to reserve the same slot.
type Footprint []byte

// NewFootprint creates a Footprint from a byte slice.
// This function makes a copy of the input data to ensure immutability.
func NewFootprint(data []byte) Footprint {
	fp := make([]byte, len(data))
	copy(fp, data)
	return Footprint(fp)
}

// Bytes returns the footprint as a byte slice.
func (fp Footprint) Bytes() []byte {
	return fp
}

// Equal compares two footprints for equality.
// Two footprints are equal if they contain exactly the same bytes.
func (fp Footprint) Equal(other Footprint) bool {
	return bytes.Equal(fp, other)
}

// String returns a base64-encoded string representation of the footprint.
// This is useful for logging and debugging.
func (fp Footprint) String() string {
	if len(fp) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(fp)
}

// StandardCryptoProvider implements the zipnet.CryptoProvider interface
// with standard cryptographic algorithms.
// It provides a concrete implementation of all cryptographic operations
// required by the ZIPNet protocol.
type StandardCryptoProvider struct{}

// NewStandardCryptoProvider creates a new standard crypto provider.
// This is the default implementation used in the ZIPNet protocol.
func NewStandardCryptoProvider() *StandardCryptoProvider {
	return &StandardCryptoProvider{}
}

// DeriveSharedSecret derives a shared secret between two parties using their
// public and private keys.
//
// Note: This is a simplified implementation for demonstration purposes.
// A production implementation should use X25519 or another secure key
// exchange algorithm.
//
// Parameters:
// - privateKey: The caller's private key
// - otherPublicKey: The other party's public key
//
// Returns the derived shared secret and any error that occurred.
func (p *StandardCryptoProvider) DeriveSharedSecret(privateKey PrivateKey, otherPublicKey PublicKey) (SharedKey, error) {
	// In a production implementation, this would use X25519
	combined := append(privateKey.Bytes(), otherPublicKey.Bytes()...)
	hash := sha256.Sum256(combined)
	return NewSharedKey(hash[:]), nil
}

// KDF derives two keys from a master key using a key derivation function.
// In ZIPNet, this is used to derive one-time pads for the scheduling vector
// and message vector.
//
// Parameters:
// - masterKey: The shared secret between client and server
// - round: The current protocol round number
// - publishedScheduleFootprints: The published schedule for this round
//
// Returns two derived keys (for schedule and message vectors) and any error.
func (p *StandardCryptoProvider) KDF(masterKey SharedKey, round uint64, publishedScheduleFootprints []byte, schedPadLength, msgVecPadLength int) ([]byte, []byte, error) {
	roundBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		roundBytes[i] = byte(round >> uint(i*8))
	}

	// Derive key for schedule vector
	schedInput := append(masterKey.Bytes(), append(roundBytes, publishedScheduleFootprints...)...)
	schedHash := sha256.Sum256(schedInput)

	// Derive key for message vector with different domain separation
	msgInput := append(masterKey.Bytes(), append([]byte("msg"), append(roundBytes, publishedScheduleFootprints...)...)...)
	msgHash := sha256.Sum256(msgInput)

	schedPad, err := hkdf.Key(sha256.New, schedHash[:], nil, "", schedPadLength)
	if err != nil {
		return nil, nil, err
	}

	msgPad, err := hkdf.Key(sha256.New, msgHash[:], nil, "", schedPadLength)
	if err != nil {
		return nil, nil, err
	}

	return schedPad, msgPad, nil
}

// Sign signs data with a private key using Ed25519.
//
// Parameters:
// - privateKey: The private key to sign with
// - data: The data to sign
//
// Returns the signature and any error that occurred.
func (p *StandardCryptoProvider) Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	return Sign(privateKey, data)
}

// Verify verifies a signature using a public key.
//
// Parameters:
// - publicKey: The public key to verify with
// - data: The data that was signed
// - signature: The signature to verify
//
// Returns error if signature is invalid.
func (p *StandardCryptoProvider) Verify(publicKey PublicKey, data []byte, signature Signature) error {
	if !signature.Verify(publicKey, data) {
		return errors.New("invalid signature")
	}
	return nil
}

// Hash computes a SHA-256 hash of the provided data.
//
// Parameters:
// - data: The data to hash
//
// Returns the hash value and any error that occurred.
func (p *StandardCryptoProvider) Hash(data []byte) (Hash, error) {
	return NewHash(data), nil
}

// RatchetKey rotates a key for forward secrecy by hashing it.
// This is used after each round to prevent compromise of past communications.
//
// Parameters:
// - key: The key to ratchet
//
// Returns the ratcheted key and any error that occurred.
func (p *StandardCryptoProvider) RatchetKey(key SharedKey) (SharedKey, error) {
	return key.Ratchet()
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

