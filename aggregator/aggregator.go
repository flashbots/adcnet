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

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

// AggregatorImpl implements the Aggregator interface for the ZIPNet protocol.
// It collects client messages, verifies their validity, and combines them
// before forwarding to anytrust servers to reduce bandwidth requirements.
type AggregatorImpl struct {
	publicKey             crypto.PublicKey
	privateKey            crypto.PrivateKey
	cryptoProvider        zipnet.CryptoProvider
	config                *zipnet.ZIPNetConfig
	registeredUsers       map[string]bool // Set of registered user public keys
	registeredAggregators map[string]bool // Set of registered aggregator public keys

	// Hierarchical configuration
	level uint32 // Level in the aggregation tree (0 = leaf aggregator)

	// State for the current round
	currentRound uint64
	messages     map[string]*zipnet.ClientMessage     // Map from client public key to message
	aggrMessages map[string]*zipnet.AggregatorMessage // Map from aggregator public key to message
	aUserPKs     []crypto.PublicKey                   // List of user public keys for the round

	// Rate limiting
	// If this is a leaf aggregator (level 0), we track nonces for rate limiting
	observedNonces map[string]int // Map of observed rate limiting nonces for this window
	windowStart    uint64         // Round at which the current window started

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
	cryptoProvider zipnet.CryptoProvider,
	registeredUsers []crypto.PublicKey, registeredAggregators []crypto.PublicKey, level uint32) (*AggregatorImpl, error) {

	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cryptoProvider == nil {
		return nil, errors.New("crypto provider cannot be nil")
	}

	// Initialize the registered users map
	userMap := make(map[string]bool)
	for _, pk := range registeredUsers {
		userMap[pk.String()] = true
	}

	aggMap := make(map[string]bool)
	for _, pk := range registeredAggregators {
		aggMap[pk.String()] = true
	}

	// Initialize observed nonces if this is a leaf aggregator
	var observedNonces map[string]int
	if level == 0 {
		observedNonces = make(map[string]int)
	}

	a := &AggregatorImpl{
		publicKey:             publicKey,
		privateKey:            privateKey,
		cryptoProvider:        cryptoProvider,
		config:                config,
		registeredUsers:       userMap,
		registeredAggregators: aggMap,
		level:                 level,
		currentRound:          zipnet.CurrentRound(config.RoundDuration),
		messages:              make(map[string]*zipnet.ScheduleMessage),
		aggrMessages:          make(map[string]*zipnet.AggregatorMessage),
		aUserPKs:              make([]crypto.PublicKey, 0),
		observedNonces:        observedNonces,
		windowStart:           0,
	}

	return a, nil
}

func (a *AggregatorImpl) WhitelistUser(clientPK crypto.PublicKey) {
	a.mutex.Lock()
	a.registeredUsers[clientPK.String()] = true
	a.mutex.Unlock()
}

func (a *AggregatorImpl) WhitelistAggregator(clientPK crypto.PublicKey) {
	a.mutex.Lock()
	a.registeredAggregators[clientPK.String()] = true
	a.mutex.Unlock()
}

// ReceiveClientMessage processes a message from a client, verifying its
// validity and preparing it for aggregation.
func (a *AggregatorImpl) ReceiveClientMessage(ctx context.Context, signedMessage *zipnet.Signed[zipnet.ClientMessage]) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Only leaf aggregators should receive client messages
	if a.level != 0 {
		return errors.New("non-leaf aggregator cannot receive client messages directly")
	}

	message, clientPK, err := signedMessage.Recover()
	if err != nil {
		return fmt.Errorf("client signature not valid: %w", err)
	}

	// Check that the client is registered
	if !a.registeredUsers[clientPK.String()] {
		return fmt.Errorf("client with public key %s is not registered", clientPK.String())
	}

	// Check that the message is for the current round
	if message.Round != a.currentRound {
		return fmt.Errorf("message round %d does not match current round %d", message.Round, a.currentRound)
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
		if a.observedNonces[pkStr] > 2 { // TODO: configure max writes per epoch
			return fmt.Errorf("duplicate rate limiting nonce from client %s", pkStr)
		}

		// Mark this "nonce" as observed
		a.observedNonces[pkStr] = a.observedNonces[pkStr] + 1
	}

	// Store the message
	a.messages[pkStr] = message
	a.aUserPKs = append(a.aUserPKs, clientPK)

	return nil
}

// ReceiveAggregatorMessage processes a message from another aggregator,
// verifying its validity and preparing it for aggregation.
func (a *AggregatorImpl) ReceiveAggregatorMessage(ctx context.Context, signedMessage *zipnet.Signed[zipnet.AggregatorMessage]) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Only non-leaf aggregators should receive aggregator messages
	if a.level == 0 {
		return errors.New("leaf aggregator cannot receive aggregator messages")
	}

	message, senderPK, err := signedMessage.Recover()
	if err != nil {
		return fmt.Errorf("could not recover signer: %w", err)
	}

	pkStr := senderPK.String()
	if _, found := a.registeredAggregators[senderPK.String()]; !found {
		return fmt.Errorf("aggregator %s not whitelisted", senderPK.String())
	}

	// Check that the message is for the current round
	if message.Round != a.currentRound {
		return fmt.Errorf("message round %d does not match current round %d", message.Round, a.currentRound)
	}

	// Check if we've already received a message from this aggregator
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
	a.aUserPKs = append(a.aUserPKs, message.UserPKs...)

	return nil
}

// AggregateMessages combines all received messages for the current round
// and returns the aggregated message to be sent to upstream aggregator or servers.
func (a *AggregatorImpl) AggregateMessages(ctx context.Context, round uint64) (*zipnet.Signed[zipnet.AggregatorMessage], error) {
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
			NextSchedVec: make([]byte, a.config.SchedulingSlots*a.config.FootprintBits/8),
			MsgVec:       make([]byte, a.config.MessageSlots*a.config.MessageSize),
		},
		UserPKs: make([]crypto.PublicKey, len(a.aUserPKs)),
	}

	for _, message := range a.messages {
		// XOR the scheduling and message vectors
		for i := 0; i < len(aggregatedMsg.NextSchedVec) && i < len(message.NextSchedVec); i++ {
			aggregatedMsg.NextSchedVec[i] ^= message.NextSchedVec[i]
		}

		for i := 0; i < len(aggregatedMsg.MsgVec) && i < len(message.MsgVec); i++ {
			aggregatedMsg.MsgVec[i] ^= message.MsgVec[i]
		}
	}

	for _, message := range a.aggrMessages {
		// XOR the scheduling and message vectors
		for i := 0; i < len(aggregatedMsg.NextSchedVec) && i < len(message.NextSchedVec); i++ {
			aggregatedMsg.NextSchedVec[i] ^= message.NextSchedVec[i]
		}

		for i := 0; i < len(aggregatedMsg.MsgVec) && i < len(message.MsgVec); i++ {
			aggregatedMsg.MsgVec[i] ^= message.MsgVec[i]
		}
	}

	copy(aggregatedMsg.UserPKs, a.aUserPKs)

	// Sign the message
	return zipnet.NewSigned(a.privateKey, aggregatedMsg)
}

// Reset prepares the aggregator for the next round by clearing state from the previous round.
func (a *AggregatorImpl) Reset(round uint64) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Reset the state for the new round
	a.currentRound = round
	a.messages = make(map[string]*zipnet.ClientMessage)
	a.aggrMessages = make(map[string]*zipnet.AggregatorMessage)
	a.aUserPKs = make([]crypto.PublicKey, 0)

	// If this is a leaf aggregator and the round marks a new window, reset the nonces
	if a.observedNonces != nil && (round/uint64(a.config.RoundsPerWindow) > a.windowStart/uint64(a.config.RoundsPerWindow)) {
		a.observedNonces = make(map[string]int)
		a.windowStart = round
	}
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
