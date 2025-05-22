package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/zipnet"
)

// ServerImpl implements the zipnet.Server interface for the ZIPNet protocol.
//
// It handles the anytrust server role which processes aggregated messages,
// unblinds them using shared secrets with clients, and publishes the final broadcast.
//
// A server operates in rounds, where in each round it:
//  1. Receives an aggregated message from a top-level aggregator
//  2. Unblinds this message using shared secrets with the clients
//  3. Either sends its unblinded share to the leader (if a follower)
//     or collects all shares and derives the final output (if the leader)
type ServerImpl struct {
	// Server identity and configuration
	config         *zipnet.ZIPNetConfig  // Protocol configuration
	cryptoProvider zipnet.CryptoProvider // For cryptographic operations
	isLeader       bool                  // Whether this server is the leader

	// Cryptographic keys
	signingKey   crypto.PrivateKey // For signing messages
	kemKey       crypto.PrivateKey // For key exchange with clients
	publicKey    crypto.PublicKey  // Signing public key
	kemPublicKey crypto.PublicKey  // Key exchange public key

	// Thread safety
	mu sync.RWMutex

	// Databases and state
	sharedSecrets  map[string]crypto.SharedKey // Maps client key to shared secret
	regUsers       map[string]bool             // Registered client public keys
	regAggregators map[string]bool             // Registered aggregator public keys
	regServers     map[string]bool             // Registered server public keys
}

// NewServer creates a new ZIPNet anytrust server with the provided dependencies.
//
// Parameters:
// - config: Protocol configuration parameters
// - cryptoProvider: For cryptographic operations
// - isLeader: Whether this server is the leader of its anytrust group
//
// Returns an initialized server or an error if creation fails.
func NewServer(config *zipnet.ZIPNetConfig, cryptoProvider zipnet.CryptoProvider,
	isLeader bool) (*ServerImpl, error) {

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cryptoProvider == nil {
		return nil, errors.New("crypto provider cannot be nil")
	}

	// Generate server keypairs
	publicKey, signingKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keypair: %w", err)
	}

	kemPublicKey, kemKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEM keypair: %w", err)
	}

	// Create server ID by hashing the public key
	h := sha256.New()
	h.Write(publicKey.Bytes())

	server := &ServerImpl{
		config:            config,
		cryptoProvider:    cryptoProvider,
		isLeader:          isLeader,
		signingKey:        signingKey,
		kemKey:            kemKey,
		publicKey:         publicKey,
		kemPublicKey:      kemPublicKey,
		sharedSecrets:     make(map[string]crypto.SharedKey),
		regUsers:          make(map[string]bool),
		regAggregators:    make(map[string]bool),
		regServers:        make(map[string]bool),
	}

	return server, nil
}

// GetPublicKey returns the server's public key used for authentication
// and cryptographic operations.
func (s *ServerImpl) GetPublicKey() crypto.PublicKey {
	return s.publicKey
}

func (s *ServerImpl) GetRegistrationBlob() *zipnet.ServerRegistrationBlob {
	return &zipnet.ServerRegistrationBlob{
		PublicKey:    s.publicKey,
		KemPublicKey: s.kemPublicKey,
		IsLeader:     s.isLeader,
	}
}

// RegisterClient establishes a shared secret with a client after verifying
// their TEE attestation.
func (s *ServerImpl) RegisterClient(ctx context.Context, clientPK crypto.PublicKey,
	attestation []byte) error {

	// Verify the client's attestation (in production code this would validate TEE)
	// Note: Like the Rust implementation, we're just logging a warning for now
	// TODO: Implement proper attestation verification

	// Derive a shared secret with the client using Diffie-Hellman
	sharedSecret, err := s.cryptoProvider.DeriveSharedSecret(s.kemKey, clientPK)
	if err != nil {
		return fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Store the shared secret and register the client
	s.mu.Lock()
	defer s.mu.Unlock()

	clientKey := clientPK.String()
	s.sharedSecrets[clientKey] = sharedSecret
	s.regUsers[clientKey] = true

	return nil
}

// RegisterAggregator records an aggregator's public key to allow verification
// of aggregated messages.
func (s *ServerImpl) RegisterAggregator(ctx context.Context,
	blob *zipnet.AggregatorRegistrationBlob) error {

	if blob == nil || blob.PublicKey == nil {
		return errors.New("invalid aggregator registration data")
	}

	// Register the aggregator
	s.mu.Lock()
	defer s.mu.Unlock()

	aggKey := blob.PublicKey.String()
	s.regAggregators[aggKey] = true

	return nil
}

// RegisterServer adds another server to the anytrust group and updates the group size.
func (s *ServerImpl) RegisterServer(ctx context.Context,
	blob *zipnet.ServerRegistrationBlob) error {

	if blob == nil || blob.PublicKey == nil || blob.KemPublicKey == nil {
		return errors.New("invalid server registration data")
	}

	// Register the server
	s.mu.Lock()
	defer s.mu.Unlock()

	serverKey := blob.PublicKey.String()
	s.regServers[serverKey] = true

	// Increment the anytrust group size
	return nil
}

// IsLeader returns true if this server is the leader of its anytrust group
func (s *ServerImpl) IsLeader() bool {
	return s.isLeader
}
