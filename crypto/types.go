package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
)

// PublicKey represents a public key used for authentication and encryption.
// In ADCNet, public keys are used to verify signatures and as client/server identifiers.
// The implementation uses Ed25519 public keys.
type PublicKey []byte

// NewPublicKeyFromBytes creates a PublicKey from a byte slice.
func NewPublicKeyFromBytes(data []byte) PublicKey {
	pk := make([]byte, len(data))
	copy(pk, data)
	return PublicKey(pk)
}

// NewPublicKeyFromString creates a PublicKey from a hex-encoded string.
func NewPublicKeyFromString(data string) (PublicKey, error) {
	rawBytes, err := hex.DecodeString(data)
	if err != nil {
		return PublicKey{}, err
	}

	return NewPublicKeyFromBytes(rawBytes), nil
}

// Bytes returns the public key as a byte slice.
func (pk PublicKey) Bytes() []byte {
	return pk
}

// Equal compares two public keys for equality.
func (pk PublicKey) Equal(other PublicKey) bool {
	return subtle.ConstantTimeCompare(pk, other) == 0
}

// String returns a hex-encoded string representation of the public key.
func (pk PublicKey) String() string {
	return hex.EncodeToString(pk)
}

// ServerID is a unique identifier for a server derived from its public key.
type ServerID uint32

// PublicKeyToServerID derives a server ID from a public key using SHA256.
func PublicKeyToServerID(pubKey PublicKey) ServerID {
	hash := sha256.Sum256(pubKey.Bytes())
	id := binary.BigEndian.Uint32(hash[:4])
	// Ensure non-zero (ServerID 0 is reserved)
	if id == 0 {
		id = 1
	}
	return ServerID(id)
}

// ServerIDsToXEvals converts server IDs to x-coordinates for polynomial evaluation.
// Maps server IDs to sequential integers 1..n based on sorted order.
func ServerIDsToXEvals(roundSIds []ServerID, availableSIds []ServerID) []*big.Int {
	res := make([]*big.Int, len(availableSIds))
	for i := range res {
		res[i] = new(big.Int)
	}

	orderedSids := roundSIds
	slices.Sort(orderedSids)
	for j, id1 := range orderedSids {
		for k, id2 := range availableSIds {
			if id1 == id2 {
				res[k].SetUint64(uint64(j + 1))
				break
			}
		}
	}

	return res
}

// PrivateKey represents a private key used for signing and key exchange.
// The implementation uses Ed25519 private keys.
type PrivateKey []byte

// NewPrivateKeyFromBytes creates a PrivateKey from a byte slice.
func NewPrivateKeyFromBytes(data []byte) PrivateKey {
	sk := make([]byte, len(data))
	copy(sk, data)
	return PrivateKey(sk)
}

// Bytes returns the private key as a byte slice.
func (sk PrivateKey) Bytes() []byte {
	return sk
}

// PublicKey derives the public key corresponding to this private key.
func (sk PrivateKey) PublicKey() (PublicKey, error) {
	if len(sk) < ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	return PublicKey(sk[32:]), nil
}

// GenerateKeyPair generates a new Ed25519 key pair for signing and verification.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(publicKey), PrivateKey(privateKey), nil
}

// Signature represents a digital signature produced with a private key.
type Signature []byte

// NewSignature creates a Signature from a byte slice.
func NewSignature(data []byte) Signature {
	sig := make([]byte, len(data))
	copy(sig, data)
	return Signature(sig)
}

// Bytes returns the signature as a byte slice.
func (s Signature) Bytes() []byte {
	return []byte(s)
}

// Verify checks if this signature is valid for the given data and public key.
func (s Signature) Verify(publicKey PublicKey, data []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, s)
}

// String returns a hex-encoded string representation of the signature.
func (s Signature) String() string {
	return hex.EncodeToString(s.Bytes())
}

// Sign signs data with the given private key using Ed25519.
func Sign(privateKey PrivateKey, data []byte) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), data)
	return Signature(signature), nil
}

// SharedKey represents a Diffie-Hellman shared secret used for deriving blinding vectors.
type SharedKey []byte

// NewSharedKey creates a SharedKey from a byte slice.
func NewSharedKey(data []byte) SharedKey {
	sk := make([]byte, len(data))
	copy(sk, data)
	return SharedKey(sk)
}

// Bytes returns the shared key as a byte slice.
func (sk SharedKey) Bytes() []byte {
	return slices.Clone(sk)
}

// XorInplace performs byte-wise XOR: l[i] ^= r[i] for all i.
// Returns l for chaining.
func XorInplace(l, r []byte) []byte {
	for i := range l {
		l[i] ^= r[i]
	}
	return l
}
