package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
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
//  4. Ratchets its shared secrets forward for security
type ServerImpl struct {
	// Server identity and configuration
	serverID       string                  // Unique identifier for this server
	config         *zipnet.ZIPNetConfig    // Protocol configuration
	cryptoProvider zipnet.CryptoProvider   // For cryptographic operations
	network        zipnet.NetworkTransport // For network communication
	isLeader       bool                    // Whether this server is the leader

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

	// Round management
	currentRound uint64                          // Current protocol round
	roundShares  []*zipnet.UnblindedShareMessage // Shares collected for current round
	roundOutputs map[uint64]*zipnet.RoundOutput  // Previous round outputs
	schedules    map[uint64][]byte               // Published schedules by round

	// Anytrust group properties
	anytrustGroupSize int    // Number of servers in the group
	minClients        uint32 // Minimum clients for anonymity
}

// NewServer creates a new ZIPNet anytrust server with the provided dependencies.
//
// Parameters:
// - config: Protocol configuration parameters
// - cryptoProvider: For cryptographic operations
// - network: For network communication
// - isLeader: Whether this server is the leader of its anytrust group
//
// Returns an initialized server or an error if creation fails.
func NewServer(config *zipnet.ZIPNetConfig, cryptoProvider zipnet.CryptoProvider,
	network zipnet.NetworkTransport, isLeader bool) (*ServerImpl, error) {

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cryptoProvider == nil {
		return nil, errors.New("crypto provider cannot be nil")
	}
	if network == nil {
		return nil, errors.New("network transport cannot be nil")
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
	serverID := hex.EncodeToString(h.Sum(nil))

	server := &ServerImpl{
		serverID:          serverID,
		config:            config,
		cryptoProvider:    cryptoProvider,
		network:           network,
		isLeader:          isLeader,
		signingKey:        signingKey,
		kemKey:            kemKey,
		publicKey:         publicKey,
		kemPublicKey:      kemPublicKey,
		sharedSecrets:     make(map[string]crypto.SharedKey),
		regUsers:          make(map[string]bool),
		regAggregators:    make(map[string]bool),
		regServers:        make(map[string]bool),
		currentRound:      0,
		roundShares:       make([]*zipnet.UnblindedShareMessage, 0),
		roundOutputs:      make(map[uint64]*zipnet.RoundOutput),
		schedules:         make(map[uint64][]byte),
		anytrustGroupSize: 1, // Start with just this server
		minClients:        config.MinClients,
	}

	return server, nil
}

// GetPublicKey returns the server's public key used for authentication
// and cryptographic operations.
func (s *ServerImpl) GetPublicKey() crypto.PublicKey {
	return s.publicKey
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
	s.anytrustGroupSize++

	return nil
}

// UnblindAggregate removes this server's blinding factors from an aggregated message
// by XORing in one-time pads derived from shared secrets with clients.
func (s *ServerImpl) UnblindAggregate(ctx context.Context,
	aggregate *zipnet.AggregatorMessage) (*zipnet.UnblindedShareMessage, error) {

	if aggregate == nil {
		return nil, errors.New("aggregate message cannot be nil")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Verify minimum client participation (for anonymity guarantees)
	if uint32(len(aggregate.UserPKs)) < s.minClients {
		return nil, fmt.Errorf("not enough clients: got %d, need %d",
			len(aggregate.UserPKs), s.minClients)
	}

	// Get the published schedule for this round
	publishedSchedule, ok := s.schedules[aggregate.Round]
	if !ok {
		return nil, fmt.Errorf("no published schedule for round %d", aggregate.Round)
	}

	// Create copies of the vectors to avoid modifying the original
	aSchedVec := make([]byte, len(aggregate.NextSchedVec))
	aMsgVec := make([]byte, len(aggregate.MsgVec))
	copy(aSchedVec, aggregate.NextSchedVec)
	copy(aMsgVec, aggregate.MsgVec)

	// Store ratcheted keys to update them atomically later
	ratchetedKeys := make(map[string]crypto.SharedKey)

	// Unblind with shared secrets for each participating client
	for _, userPK := range aggregate.UserPKs {
		userKey := userPK.String()

		// Get the shared secret for this user
		sharedKey, exists := s.sharedSecrets[userKey]
		if !exists {
			return nil, fmt.Errorf("no shared secret for user: %s", userKey)
		}

		// Derive pads using KDF
		pad1, pad2, err := s.cryptoProvider.KDF(sharedKey, aggregate.Round, publishedSchedule)
		if err != nil {
			return nil, fmt.Errorf("failed to derive pads: %w", err)
		}

		// XOR the pads with the vectors
		for i := 0; i < len(aSchedVec) && i < len(pad1); i++ {
			aSchedVec[i] ^= pad1[i]
		}
		for i := 0; i < len(aMsgVec) && i < len(pad2); i++ {
			aMsgVec[i] ^= pad2[i]
		}

		// Ratchet the key for forward secrecy
		ratchetedKey, err := s.cryptoProvider.RatchetKey(sharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to ratchet key: %w", err)
		}
		ratchetedKeys[userKey] = ratchetedKey
	}

	// Create the unblinded share
	keyShare := &zipnet.ScheduleMessage{
		Round:        aggregate.Round,
		NextSchedVec: aSchedVec,
		MsgVec:       aMsgVec,
	}

	unblindedShare := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    aggregate,
		KeyShare:        keyShare,
		ServerPublicKey: s.publicKey,
	}

	// Sign the unblinded share
	shareData, err := zipnet.SerializeMessage(keyShare)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key share: %w", err)
	}

	signature, err := s.cryptoProvider.Sign(s.signingKey, shareData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign unblinded share: %w", err)
	}
	unblindedShare.Signature = signature

	// Update the shared secrets with ratcheted keys
	// Need to release read lock and acquire write lock
	s.mu.RUnlock()
	s.mu.Lock()
	for userKey, ratchetedKey := range ratchetedKeys {
		s.sharedSecrets[userKey] = ratchetedKey
	}
	s.mu.Unlock()
	s.mu.RLock()

	return unblindedShare, nil
}

// DeriveRoundOutput combines unblinded shares from all anytrust servers
// to produce the final broadcast message.
func (s *ServerImpl) DeriveRoundOutput(ctx context.Context,
	shares []*zipnet.UnblindedShareMessage) (*zipnet.RoundOutput, error) {

	if !s.isLeader {
		return nil, errors.New("only leader can derive round output")
	}

	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	if len(shares) != s.anytrustGroupSize {
		return nil, fmt.Errorf("expected %d shares, got %d",
			s.anytrustGroupSize, len(shares))
	}

	// Verify all shares are for the same round
	round := shares[0].EncryptedMsg.Round
	for i, share := range shares {
		if share.EncryptedMsg.Round != round {
			return nil, fmt.Errorf("share %d has incorrect round: expected %d, got %d",
				i, round, share.EncryptedMsg.Round)
		}

		// Verify the share's signature (in production code)
		// TODO: Implement proper signature verification
	}

	// Initialize final message vectors
	finalSchedVec := make([]byte, len(shares[0].KeyShare.NextSchedVec))
	finalMsgVec := make([]byte, len(shares[0].KeyShare.MsgVec))

	// XOR all key shares together
	for _, share := range shares {
		for i := 0; i < len(finalSchedVec); i++ {
			finalSchedVec[i] ^= share.KeyShare.NextSchedVec[i]
		}
		for i := 0; i < len(finalMsgVec); i++ {
			finalMsgVec[i] ^= share.KeyShare.MsgVec[i]
		}
	}

	// XOR with the original encrypted message to get the plaintext
	for i := 0; i < len(finalSchedVec); i++ {
		finalSchedVec[i] ^= shares[0].EncryptedMsg.NextSchedVec[i]
	}
	for i := 0; i < len(finalMsgVec); i++ {
		finalMsgVec[i] ^= shares[0].EncryptedMsg.MsgVec[i]
	}

	// Create the final message
	finalMessage := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: finalSchedVec,
		MsgVec:       finalMsgVec,
	}

	// Create and sign the round output
	roundOutput := &zipnet.RoundOutput{
		Round:            round,
		Message:          finalMessage,
		ServerSignatures: []zipnet.OutputSignature{},
	}

	// Sign the output
	outputData, err := zipnet.SerializeMessage(finalMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize final message: %w", err)
	}

	signature, err := s.cryptoProvider.Sign(s.signingKey, outputData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign round output: %w", err)
	}

	// Add this server's signature
	roundOutput.ServerSignatures = append(roundOutput.ServerSignatures,
		zipnet.OutputSignature{
			PublicKey: s.publicKey,
			Signature: signature,
		})

	// Store the round output and next round's schedule
	s.mu.Lock()
	s.roundOutputs[round] = roundOutput
	s.schedules[round+1] = finalSchedVec
	s.mu.Unlock()

	return roundOutput, nil
}

// ProcessAggregate handles an aggregated message from an aggregator.
func (s *ServerImpl) ProcessAggregate(ctx context.Context,
	message *zipnet.AggregatorMessage) (*zipnet.ServerMessage, error) {

	// Verify the message (in production code)
	// TODO: Implement proper message verification

	// Unblind the aggregate
	unblindedShare, err := s.UnblindAggregate(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to unblind aggregate: %w", err)
	}

	if s.isLeader {
		// Leader collects shares (including its own)
		s.mu.Lock()

		// Store this share
		if len(s.roundShares) == 0 || s.roundShares[0].EncryptedMsg.Round != message.Round {
			// New round, reset shares collection
			s.roundShares = make([]*zipnet.UnblindedShareMessage, 0, s.anytrustGroupSize)
		}
		s.roundShares = append(s.roundShares, unblindedShare)

		// If we have all shares, derive the round output
		if len(s.roundShares) == s.anytrustGroupSize {
			roundOutput, err := s.DeriveRoundOutput(ctx, s.roundShares)
			if err != nil {
				s.mu.Unlock()
				return nil, fmt.Errorf("failed to derive round output: %w", err)
			}

			// Reset for next round
			s.roundShares = make([]*zipnet.UnblindedShareMessage, 0, s.anytrustGroupSize)
			s.mu.Unlock()

			// Create server message from round output
			return &zipnet.ServerMessage{
				Round:        roundOutput.Round,
				NextSchedVec: roundOutput.Message.NextSchedVec,
				MsgVec:       roundOutput.Message.MsgVec,
				Signature:    roundOutput.ServerSignatures[0].Signature,
			}, nil
		}

		s.mu.Unlock()
		return nil, nil // Still waiting for more shares
	} else {
		// Follower sends its share to the leader
		// TODO: Implement leader communication using network transport
		return nil, nil
	}
}

// PublishSchedule creates and signs a schedule for the next round.
func (s *ServerImpl) PublishSchedule(ctx context.Context,
	round uint64, schedVec []byte) ([]byte, crypto.Signature, error) {

	if !s.isLeader {
		return nil, nil, errors.New("only leader can publish schedule")
	}

	// Format the schedule data for signing
	buf := new(bytes.Buffer)
	buf.Write(schedVec)
	scheduleData := buf.Bytes()

	// Sign the schedule
	signature, err := s.cryptoProvider.Sign(s.signingKey, scheduleData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign schedule: %w", err)
	}

	// Store the schedule for future reference
	s.mu.Lock()
	s.schedules[round] = schedVec
	s.mu.Unlock()

	return scheduleData, signature, nil
}
