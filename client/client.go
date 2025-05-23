package client

import (
	"errors"
	"fmt"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// ClientImpl implements the ZIPNet protocol client that operates within a TEE.
// It handles message preparation, slot reservation, and participation in the
// anonymous broadcast network.
type ClientImpl struct {
	config           *protocol.ZIPNetConfig
	tee              protocol.TEE
	publicKey        crypto.PublicKey
	privateKey       crypto.PrivateKey
	key              []byte // Symmetric key for PRF operations
	serverPublicKeys map[string]crypto.PublicKey
	sharedSecrets    map[string]crypto.SharedKey

	// Client identity and state
	userID            []byte // Unique identifier derived from public key
	anythrustGroupID  []byte // Identifier for the set of anytrust servers
	timesParticipated uint32 // Counter for participation in the current window
}

// NewClient creates a new ZIPNet client with the provided dependencies.
// It generates the necessary cryptographic keys within the TEE and initializes
// the client state.
//
// The client requires:
// - config: Protocol configuration parameters
// - tee: Trusted Execution Environment for integrity protection
// - cryptoProvider: Cryptographic operations provider
// - scheduler: Slot scheduling mechanism
//
// Returns an initialized client or an error if creation fails.
func NewClient(config *protocol.ZIPNetConfig, tee zipnet.TEE,
	cryptoProvider zipnet.CryptoProvider,
	scheduler zipnet.Scheduler) (*ClientImpl, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if tee == nil {
		return nil, errors.New("TEE cannot be nil")
	}
	if cryptoProvider == nil {
		return nil, errors.New("crypto provider cannot be nil")
	}
	if scheduler == nil {
		return nil, errors.New("scheduler cannot be nil")
	}

	// Generate keys inside the TEE
	publicKey, privateKey, err := tee.GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	// Generate symmetric key for PRF operations (used in scheduling)
	keyHash, err := cryptoProvider.Hash(privateKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Generate user ID from public key
	userIDHash, err := cryptoProvider.Hash(publicKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	c := &ClientImpl{
		config:            config,
		tee:               tee,
		crypto:            cryptoProvider,
		scheduler:         scheduler,
		publicKey:         publicKey,
		privateKey:        privateKey,
		key:               keyHash.Bytes(),
		serverPublicKeys:  make(map[string]crypto.PublicKey),
		sharedSecrets:     make(map[string]crypto.SharedKey),
		userID:            userIDHash.Bytes(),
		timesParticipated: 0,
	}

	return c, nil
}

// GetPublicKey returns the client's public key used for authentication
// and cryptographic operations.
func (c *ClientImpl) GetPublicKey() crypto.PublicKey {
	return c.publicKey
}

// RegisterServerPublicKey registers a server's public key and establishes
// a shared secret with that server using Diffie-Hellman key exchange.
//
// This method should be called for each anytrust server before the client
// can participate in the protocol.
func (c *ClientImpl) RegisterServerPublicKey(serverID string, publicKey crypto.PublicKey) error {
	if publicKey == nil {
		return errors.New("server public key cannot be nil")
	}
	c.serverPublicKeys[serverID] = publicKey

	// Derive and store shared secret with this server
	sharedSecret, err := c.crypto.DeriveSharedSecret(c.privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to derive shared secret with server %s: %w", serverID, err)
	}

	// Seal the shared secret in the TEE
	sealedSecret, err := c.tee.SealData(sharedSecret.Bytes())
	if err != nil {
		return fmt.Errorf("failed to seal shared secret: %w", err)
	}

	// Unseal and store the secret
	unsealedSecret, err := c.tee.UnsealData(sealedSecret)
	if err != nil {
		return fmt.Errorf("failed to unseal shared secret: %w", err)
	}

	c.sharedSecrets[serverID] = crypto.NewSharedKey(unsealedSecret)

	// Compute anytrust group ID once all servers are registered
	if len(c.sharedSecrets) == len(c.config.AnytrustServers) {
		groupID, err := c.computeAnythrustGroupID()
		if err != nil {
			return fmt.Errorf("failed to compute anytrust group ID: %w", err)
		}
		c.anythrustGroupID = groupID
	}

	return nil
}

// GetTimesParticipated returns the number of times this client has
// participated in the current window. This is used for rate limiting.
func (c *ClientImpl) GetTimesParticipated() uint32 {
	return c.timesParticipated
}

// SaveState returns a sealed representation of the client's state.
// This can be stored externally and later restored using LoadState.
func (c *ClientImpl) SaveState() ([]byte, error) {
	// In a real implementation, this would serialize and seal
	// all necessary client state using the TEE
	return nil, errors.New("not implemented")
}

// LoadState restores the client's state from a previously saved state.
func (c *ClientImpl) LoadState(sealedState []byte) error {
	// In a real implementation, this would unseal and restore
	// the client state using the TEE
	return errors.New("not implemented")
}

// Helper function to determine if a message is cover traffic
func (c *ClientImpl) isCoverTraffic(msg []byte) bool {
	return msg == nil || len(msg) == 0
}

// Helper function to select an aggregator
func (c *ClientImpl) selectAggregator() string {
	if len(c.config.Aggregators) == 0 {
		return ""
	}
	// Simple round-robin selection; could be improved with load balancing
	return c.config.Aggregators[0]
}

// Helper function to compute the anytrust group ID
func (c *ClientImpl) computeAnythrustGroupID() ([]byte, error) {
	// Concatenate all server public keys
	var allKeys []byte
	for _, serverID := range c.config.AnytrustServers {
		pk, exists := c.serverPublicKeys[serverID]
		if !exists {
			return nil, fmt.Errorf("missing public key for server %s", serverID)
		}
		allKeys = append(allKeys, pk.Bytes()...)
	}

	// Hash the concatenated keys
	groupIDHash, err := c.crypto.Hash(allKeys)
	if err != nil {
		return nil, err
	}

	return groupIDHash.Bytes(), nil
}
