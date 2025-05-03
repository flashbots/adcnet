package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

// ClientImpl implements the ZIPNet protocol client that operates within a TEE.
// It handles message preparation, slot reservation, and participation in the
// anonymous broadcast network.
type ClientImpl struct {
	config           *zipnet.ZIPNetConfig
	tee              zipnet.TEE
	crypto           zipnet.CryptoProvider
	scheduler        zipnet.Scheduler
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
func NewClient(config *zipnet.ZIPNetConfig, tee zipnet.TEE,
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

var ErrorFootprintCollision error = errors.New("scheduling collision error")

// PrepareMessage prepares and submits a message for the current round.
// It handles both actual message transmission and cover traffic generation.
//
// Parameters:
// - ctx: Context for the operation
// - round: Current protocol round number
// - msg: Message content to send (nil for cover traffic)
// - requestSlot: Whether to reserve a slot for the next round
// - publishedSchedule: The current round's published schedule
//
// Returns the prepared message or an error if preparation fails.
func (c *ClientImpl) PrepareMessage(ctx context.Context, round uint64, msg []byte,
	requestSlot bool,
	publishedSchedule zipnet.PublishedSchedule) (*zipnet.Signed[zipnet.ClientMessage], error) {
	// Initialize empty vectors
	nextSchedVec := make([]byte, c.config.SchedulingSlots*c.config.FootprintBits/8)
	msgVec := make([]byte, c.config.MessageSlots*c.config.MessageSize)

	// Verify the published schedule's signature
	leaderServerID := c.config.AnytrustServers[0] // Assume first server is leader
	leaderPK, exists := c.serverPublicKeys[leaderServerID]
	if !exists {
		return nil, errors.New("leader server public key not registered")
	}

	valid, err := c.scheduler.VerifySchedule(publishedSchedule, leaderPK)
	if err != nil || !valid {
		return nil, errors.New("invalid schedule signature")
	}

	// Check if this round starts a new window
	if round%uint64(c.config.RoundsPerWindow) == 0 {
		c.timesParticipated = 0
	}

	// Try to reserve a slot for the next round if requested
	if requestSlot {
		nextSchedSlot, nextFootprint, err := c.scheduler.ComputeScheduleSlot(c.key, round+1)
		if err != nil {
			return nil, fmt.Errorf("failed to compute schedule slot: %w", err)
		}

		// Set the footprint in the scheduling vector
		fpBytes := nextFootprint.Bytes()
		if nextSchedSlot+uint32(len(fpBytes)) > uint32(len(nextSchedVec)) {
			return nil, errors.New("footprint exceeds scheduling vector size")
		}

		for i, b := range fpBytes {
			nextSchedVec[nextSchedSlot+uint32(i)] ^= b
		}
	}

	// Recompute the request from the last round and see if it made it
	// undisturbed into the published schedule
	curSchedSlot, curFootprint, err := c.scheduler.ComputeScheduleSlot(c.key, round)
	if err != nil {
		return nil, fmt.Errorf("failed to compute current schedule slot: %w", err)
	}

	var scheduleCollosion bool = false

	// Check if our footprint is in the published schedule
	fpBytes := curFootprint.Bytes()
	if curSchedSlot+uint32(len(fpBytes)) <= uint32(len(publishedSchedule.Footprints)) {
		// Extract footprint from published schedule
		publishedFP, err := publishedSchedule.FootprintAt(curSchedSlot, int32(len(fpBytes)))
		if err != nil {
			return nil, fmt.Errorf("failed to extract footprint: %w", err)
		}

		scheduleCollosion = !publishedFP.Equal(curFootprint)
		if !scheduleCollosion && msg != nil {
			// We have a reservation and a message to send
			msgSlot, err := c.scheduler.MapScheduleToMessageSlot(curSchedSlot, publishedSchedule)
			if err != nil {
				return nil, fmt.Errorf("failed to map schedule slot to message slot: %w", err)
			}

			// Compute falsification tag (hash of the message)
			hash, err := c.crypto.Hash(msg)
			if err != nil {
				return nil, fmt.Errorf("failed to compute message hash: %w", err)
			}

			// Write message and falsification tag to message vector
			msgStartIdx := msgSlot * c.config.MessageSize
			tagBytes := hash.Bytes()

			// Ensure message fits in the slot
			if msgStartIdx+uint32(len(msg)+len(tagBytes)) > uint32(len(msgVec)) {
				return nil, errors.New("message too large for slot")
			}

			// Copy message to vector
			copy(msgVec[msgStartIdx:], append(msg, tagBytes...))

			// Increment participation counter for talking messages
			if !c.isCoverTraffic(msg) {
				c.timesParticipated++
			}
		}
	}

	// Blind the vectors with server shared secrets
	for serverID, sharedSecret := range c.sharedSecrets {
		// Derive one-time pads for this round using KDF
		/*
			pad1, pad2, err := c.crypto.KDF(sharedSecret, round, publishedSchedule.Footprints, len(nextSchedVec), len(msgVec))
			if err != nil {
				return nil, fmt.Errorf("failed to derive pads for server %s: %w", serverID, err)
			}

				// XOR the pads with the vectors
				// TODO: the pad should be as long as vector...
				for i := 0; i < len(nextSchedVec); i++ {
					nextSchedVec[i] ^= pad1[i%len(pad1)]
				}

				for i := 0; i < len(msgVec); i++ {
					msgVec[i] ^= pad2[i%len(pad2)]
				}
		*/

		// Ratchet the shared key for forward secrecy
		newSharedKey, err := c.crypto.RatchetKey(sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to ratchet key for server %s: %w", serverID, err)
		}

		// Update the shared secret in our map
		c.sharedSecrets[serverID] = newSharedKey
	}

	// Create the message
	message, err := zipnet.NewSigned(c.privateKey, &zipnet.ClientMessage{
		Round:        round,
		NextSchedVec: nextSchedVec,
		MsgVec:       msgVec,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	if scheduleCollosion {
		return message, ErrorFootprintCollision
	} else {
		return message, nil
	}
}

// ProcessBroadcast processes the broadcast message from the server to extract
// relevant messages and scheduling information.
//
// Parameters:
// - ctx: Context for the operation
// - round: Current protocol round number
// - broadcast: The broadcast message from the server
//
// Returns the processed message data or an error if processing fails.
func (c *ClientImpl) ProcessBroadcast(ctx context.Context, round uint64, signedBroadcastMsg *zipnet.Signed[zipnet.RoundOutput]) ([]byte, error) {
	// Verify the signature
	leaderServerID := c.config.AnytrustServers[0]
	leaderPK, exists := c.serverPublicKeys[leaderServerID]
	if !exists {
		return nil, errors.New("leader server public key not registered")
	}

	broadcastMsg, recoveredPK, err := signedBroadcastMsg.Recover()
	if err != nil {
		return nil, fmt.Errorf("could not recover broadcast signature: %w", err)
	}

	if !recoveredPK.Equal(leaderPK) {
		return nil, fmt.Errorf("broadcast not signed by leader %s but rather by %s", leaderPK.String(), recoveredPK.String())
	}

	// Return the message vector for application processing
	return broadcastMsg.MsgVec, nil
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
