// Package aggregator implements the Aggregator interface of the ZIPNet protocol.
//
// The aggregator component forms the middle tier in ZIPNet's three-tier architecture:
// 1. Clients prepare encrypted messages in TEEs
// 2. Aggregators combine client messages to reduce bandwidth
// 3. Anytrust servers provide anonymity guarantees
//
// Aggregators are organized in a tree structure where leaf aggregators (level 0)
// collect messages directly from clients, and higher-level aggregators collect
// from lower-level aggregators. This hierarchical approach significantly reduces
// bandwidth requirements for anytrust servers.
package aggregator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

// AggregatorImpl implements the Aggregator interface for the ZIPNet protocol.
// It collects client messages, verifies their validity, and combines them
// before forwarding to anytrust servers to reduce bandwidth requirements.
type AggregatorImpl struct {
	publicKey        crypto.PublicKey
	privateKey       crypto.PrivateKey
	cryptoProvider   zipnet.CryptoProvider
	networkTransport zipnet.NetworkTransport
	config           *zipnet.ZIPNetConfig
	registeredUsers  map[string]bool // Set of registered user public keys

	// Hierarchical configuration
	level uint32 // Level in the aggregation tree (0 = leaf aggregator)

	// State for the current round
	currentRound uint64
	messages     map[string]*zipnet.ClientMessage     // Map from client public key to message
	aggrMessages map[string]*zipnet.AggregatorMessage // Map from aggregator public key to message
	aUserPKs     []crypto.PublicKey                   // List of user public keys for the round
	aSchedVec    []byte                               // Aggregate of scheduling vectors
	aMsgVec      []byte                               // Aggregate of message vectors

	// Rate limiting
	// If this is a leaf aggregator (level 0), we track nonces for rate limiting
	observedNonces map[string]bool // Map of observed rate limiting nonces for this window
	windowStart    uint64          // Round at which the current window started

	mutex sync.RWMutex // For thread safety
}

// NewAggregator creates a new ZIPNet aggregator with the provided dependencies.
// The aggregator requires a valid configuration, crypto provider, and network transport.
// It handles the collection and combination of client messages to reduce bandwidth
// requirements for anytrust servers.
//
// The level parameter specifies the aggregator's position in the hierarchy:
// - Level 0: Leaf aggregator, receives messages directly from clients
// - Level > 0: Non-leaf aggregator, receives messages from lower-level aggregators
func NewAggregator(config *zipnet.ZIPNetConfig, privateKey crypto.PrivateKey, publicKey crypto.PublicKey,
	cryptoProvider zipnet.CryptoProvider, networkTransport zipnet.NetworkTransport,
	registeredUsers []crypto.PublicKey, level uint32) (*AggregatorImpl, error) {

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cryptoProvider == nil {
		return nil, errors.New("crypto provider cannot be nil")
	}
	if networkTransport == nil {
		return nil, errors.New("network transport cannot be nil")
	}

	// Initialize the registered users map
	userMap := make(map[string]bool)
	for _, pk := range registeredUsers {
		userMap[pk.String()] = true
	}

	// Initialize observed nonces if this is a leaf aggregator
	var observedNonces map[string]bool
	if level == 0 {
		observedNonces = make(map[string]bool)
	}

	a := &AggregatorImpl{
		publicKey:        publicKey,
		privateKey:       privateKey,
		cryptoProvider:   cryptoProvider,
		networkTransport: networkTransport,
		config:           config,
		registeredUsers:  userMap,
		level:            level,
		currentRound:     0,
		messages:         make(map[string]*zipnet.ScheduleMessage),
		aggrMessages:     make(map[string]*zipnet.AggregatorMessage),
		aUserPKs:         make([]crypto.PublicKey, 0),
		aSchedVec:        make([]byte, config.SchedulingSlots*config.FootprintBits/8),
		aMsgVec:          make([]byte, config.MessageSlots*config.MessageSize),
		observedNonces:   observedNonces,
		windowStart:      0,
	}

	return a, nil
}

func (a *AggregatorImpl) WhitelistUser(clientPK crypto.PublicKey) {
	a.mutex.Lock()
	a.registeredUsers[clientPK.String()] = true
	a.mutex.Unlock()
}

// ReceiveClientMessage processes a message from a client, verifying its
// validity and preparing it for aggregation.
func (a *AggregatorImpl) ReceiveClientMessage(ctx context.Context, message *zipnet.ClientMessage, clientPK crypto.PublicKey) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Only leaf aggregators should receive client messages
	if a.level != 0 {
		return errors.New("non-leaf aggregator cannot receive client messages directly")
	}

	// Check that the client is registered
	if !a.registeredUsers[clientPK.String()] {
		return fmt.Errorf("client with public key %s is not registered", clientPK.String())
	}

	// Check that the message is for the current round
	if message.Round != a.currentRound {
		return fmt.Errorf("message round %d does not match current round %d", message.Round, a.currentRound)
	}

	// Verify the message signature
	data, err := zipnet.SerializeMessage(&zipnet.ScheduleMessage{
		Round:        message.Round,
		NextSchedVec: message.NextSchedVec,
		MsgVec:       message.MsgVec,
		// Note: Signature is excluded from the signed data
	})
	if err != nil {
		return fmt.Errorf("failed to serialize message for verification: %w", err)
	}

	valid, err := a.cryptoProvider.Verify(clientPK, data, message.Signature)
	if err != nil {
		return fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return errors.New("invalid signature")
	}

	// Check if we've already received a message from this client
	pkStr := clientPK.String()
	if _, exists := a.messages[pkStr]; exists {
		return fmt.Errorf("duplicate message from client %s", pkStr)
	}

	// Check rate limiting nonce if applicable
	// In real implementation, this would extract a nonce from the message
	// and check it against observed nonces
	// For simplicity, we're using the client's public key as a proxy for a nonce
	if a.observedNonces != nil {
		// If we've seen this "nonce" before, reject the message
		if a.observedNonces[pkStr] {
			return fmt.Errorf("duplicate rate limiting nonce from client %s", pkStr)
		}

		// Mark this "nonce" as observed
		a.observedNonces[pkStr] = true
	}

	// Store the message
	a.messages[pkStr] = message
	a.aUserPKs = append(a.aUserPKs, clientPK)

	// XOR the scheduling and message vectors
	for i := 0; i < len(a.aSchedVec) && i < len(message.NextSchedVec); i++ {
		a.aSchedVec[i] ^= message.NextSchedVec[i]
	}

	for i := 0; i < len(a.aMsgVec) && i < len(message.MsgVec); i++ {
		a.aMsgVec[i] ^= message.MsgVec[i]
	}

	return nil
}

// ReceiveAggregatorMessage processes a message from another aggregator,
// verifying its validity and preparing it for aggregation.
func (a *AggregatorImpl) ReceiveAggregatorMessage(ctx context.Context, message *zipnet.AggregatorMessage) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Only non-leaf aggregators should receive aggregator messages
	if a.level == 0 {
		return errors.New("leaf aggregator cannot receive aggregator messages")
	}

	// Check that the message is for the current round
	if message.Round != a.currentRound {
		return fmt.Errorf("message round %d does not match current round %d", message.Round, a.currentRound)
	}

	// Verify the message signature
	data, err := zipnet.SerializeMessage(&zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        message.Round,
			NextSchedVec: message.NextSchedVec,
			MsgVec:       message.MsgVec,
		},
		UserPKs: message.UserPKs,
		// Note: Signature is excluded from the signed data
	})
	if err != nil {
		return fmt.Errorf("failed to serialize message for verification: %w", err)
	}

	// We need to extract the sender's public key from the message
	// In a real implementation, this would be included in the message
	// For now, we'll use a placeholder approach
	var senderPK crypto.PublicKey
	if len(message.UserPKs) > 0 {
		// Use the first user PK as a proxy for the sender's PK
		// This is just for illustration; in a real implementation,
		// the sender's PK would be properly included and verified
		senderPK = message.UserPKs[0]
	} else {
		return errors.New("cannot identify sender of empty aggregator message")
	}

	valid, err := a.cryptoProvider.Verify(senderPK, data, message.Signature)
	if err != nil {
		return fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return errors.New("invalid signature")
	}

	// Check if we've already received a message from this aggregator
	pkStr := senderPK.String()
	if _, exists := a.aggrMessages[pkStr]; exists {
		return fmt.Errorf("duplicate message from aggregator %s", pkStr)
	}

	// Ensure no overlap of user IDs
	for _, userPK := range message.UserPKs {
		userPKStr := userPK.String()
		for _, existingUserPK := range a.aUserPKs {
			if existingUserPK.String() == userPKStr {
				return fmt.Errorf("user %s appears in multiple aggregator messages", userPKStr)
			}
		}
	}

	// Store the message
	a.aggrMessages[pkStr] = message

	// Add all user PKs from this aggregator message
	a.aUserPKs = append(a.aUserPKs, message.UserPKs...)

	// XOR the scheduling and message vectors
	for i := 0; i < len(a.aSchedVec) && i < len(message.NextSchedVec); i++ {
		a.aSchedVec[i] ^= message.NextSchedVec[i]
	}

	for i := 0; i < len(a.aMsgVec) && i < len(message.MsgVec); i++ {
		a.aMsgVec[i] ^= message.MsgVec[i]
	}

	return nil
}

// AggregateMessages combines all received messages for the current round
// and returns the aggregated message to be sent to upstream aggregator or servers.
func (a *AggregatorImpl) AggregateMessages(ctx context.Context, round uint64) (*zipnet.AggregatorMessage, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	if round != a.currentRound {
		return nil, fmt.Errorf("requested round %d does not match current round %d", round, a.currentRound)
	}

	// Check if we have enough messages to form a valid round
	if len(a.aUserPKs) < int(a.config.MinClients) {
		return nil, fmt.Errorf("not enough clients for round: got %d, need %d", len(a.aUserPKs), a.config.MinClients)
	}

	// Create the aggregated message
	aggregatedMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        a.currentRound,
			NextSchedVec: make([]byte, len(a.aSchedVec)),
			MsgVec:       make([]byte, len(a.aMsgVec)),
		},
		UserPKs: make([]crypto.PublicKey, len(a.aUserPKs)),
	}

	// Copy the data to avoid race conditions
	copy(aggregatedMsg.NextSchedVec, a.aSchedVec)
	copy(aggregatedMsg.MsgVec, a.aMsgVec)
	copy(aggregatedMsg.UserPKs, a.aUserPKs)

	// Sign the message
	data, err := zipnet.SerializeMessage(&zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        aggregatedMsg.Round,
			NextSchedVec: aggregatedMsg.NextSchedVec,
			MsgVec:       aggregatedMsg.MsgVec,
		},
		UserPKs: aggregatedMsg.UserPKs,
		// Signature will be added after
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize aggregated message: %w", err)
	}

	signature, err := a.cryptoProvider.Sign(a.privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign aggregated message: %w", err)
	}

	aggregatedMsg.Signature = signature

	return aggregatedMsg, nil
}

// Reset prepares the aggregator for the next round by clearing state from the previous round.
func (a *AggregatorImpl) Reset(round uint64) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Validate the new round
	if round <= a.currentRound {
		return fmt.Errorf("new round %d must be greater than current round %d", round, a.currentRound)
	}

	// Reset the state for the new round
	a.currentRound = round
	a.messages = make(map[string]*zipnet.ClientMessage)
	a.aggrMessages = make(map[string]*zipnet.AggregatorMessage)
	a.aUserPKs = make([]crypto.PublicKey, 0)
	a.aSchedVec = make([]byte, len(a.aSchedVec))
	a.aMsgVec = make([]byte, len(a.aMsgVec))

	// If this is a leaf aggregator and the round marks a new window, reset the nonces
	if a.observedNonces != nil && (round/uint64(a.config.RoundsPerWindow) > a.windowStart/uint64(a.config.RoundsPerWindow)) {
		a.observedNonces = make(map[string]bool)
		a.windowStart = round
	}

	return nil
}

// GetPublicKey returns the aggregator's public key used for authentication
// and cryptographic operations.
func (a *AggregatorImpl) GetPublicKey() crypto.PublicKey {
	return a.publicKey
}

// GetLevel returns the level of this aggregator in the aggregation tree.
func (a *AggregatorImpl) GetLevel() uint32 {
	return a.level
}

// ForwardAggregate sends the aggregated message to the next level in the
// aggregation tree or to anytrust servers if this is the root aggregator.
// This is a convenience method that's not part of the interface.
func (a *AggregatorImpl) ForwardAggregate(ctx context.Context) error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	// Get the aggregated message
	aggMsg, err := a.AggregateMessages(ctx, a.currentRound)
	if err != nil {
		return fmt.Errorf("failed to create aggregate: %w", err)
	}

	// If this is the root aggregator, send to all anytrust servers
	if a.level == uint32(len(a.config.Aggregators)-1) {
		for _, serverAddr := range a.config.AnytrustServers {
			err := a.networkTransport.SendToServer(ctx, serverAddr, aggMsg)
			if err != nil {
				return fmt.Errorf("failed to send to server %s: %w", serverAddr, err)
			}
		}
		return nil
	}

	// Otherwise, send to the next level aggregator
	// For simplicity, we'll just use the first one in the config that's at a higher level
	// In a real implementation, there would be a more sophisticated routing system
	nextLevel := a.level + 1
	for i, aggAddr := range a.config.Aggregators {
		if uint32(i) == nextLevel {
			// This assumes SendToAggregator can handle AggregatorMessage, which isn't
			// correct based on the interface. In a real implementation, this would need
			// proper typing or a different method.
			err := a.networkTransport.SendToAggregator(ctx, aggAddr, &aggMsg.ScheduleMessage)
			if err != nil {
				return fmt.Errorf("failed to send to aggregator %s: %w", aggAddr, err)
			}
			return nil
		}
	}

	return errors.New("no higher level aggregator found")
}

// StartRoundProcessing starts processing for a new round.
// It sets up timers to automatically collect, aggregate, and forward messages.
// This is a convenience method that's not part of the interface.
func (a *AggregatorImpl) StartRoundProcessing(ctx context.Context, round uint64) error {
	// Reset the state for the new round
	if err := a.Reset(round); err != nil {
		return err
	}

	// Set up a timer to aggregate and forward at the end of the round
	go func() {
		// Wait for the round duration minus some time for processing
		processingWindow := time.Duration(a.level) * time.Second
		timer := time.NewTimer(a.config.RoundDuration - processingWindow)

		select {
		case <-timer.C:
			// Round is over, forward the aggregate
			if err := a.ForwardAggregate(ctx); err != nil {
				// In a real implementation, this error would be logged or handled
				fmt.Printf("Failed to forward aggregate: %v\n", err)
			}
		case <-ctx.Done():
			// Context was canceled
			timer.Stop()
			return
		}
	}()

	return nil
}
