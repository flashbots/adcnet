// crypto/kem.go
package crypto

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// KemPublicKey represents a public key for key encapsulation
type KemPublicKey [32]byte

// KemPrivateKey represents a private key for key encapsulation
type KemPrivateKey [32]byte

// GenerateKemKeyPair generates a new X25519 key pair for key exchange
func GenerateKemKeyPair() (KemPublicKey, KemPrivateKey, error) {
	var privKey KemPrivateKey
	var pubKey KemPublicKey

	if _, err := rand.Read(privKey[:]); err != nil {
		return pubKey, privKey, err
	}

	curve25519.ScalarBaseMult((*[32]byte)(&pubKey), (*[32]byte)(&privKey))
	return pubKey, privKey, nil
}

// DeriveSharedSecret performs ECDH key agreement and derives a shared secret
func DeriveSharedSecret(privateKey KemPrivateKey, publicKey KemPublicKey, info []byte) (SharedKey, error) {
	// Perform X25519 key agreement
	var sharedPoint [32]byte
	curve25519.ScalarMult(&sharedPoint, (*[32]byte)(&privateKey), (*[32]byte)(&publicKey))

	// Derive key using HKDF
	hkdf := hkdf.New(sha256.New, sharedPoint[:], nil, info)
	secret := make([]byte, 32)
	if _, err := hkdf.Read(secret); err != nil {
		return nil, err
	}

	return SharedKey(secret), nil
}
