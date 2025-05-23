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
	"errors"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// AggregatorImpl implements the Aggregator interface for the ZIPNet protocol.
// It collects client messages, verifies their validity, and combines them
// before forwarding to anytrust servers to reduce bandwidth requirements.
type AggregatorImpl struct {
	publicKey             crypto.PublicKey
	privateKey            crypto.PrivateKey
	config                *protocol.ZIPNetConfig
	registeredUsers       map[string]bool // Set of registered user public keys
	registeredAggregators map[string]bool // Set of registered aggregator public keys

	// State for the current round
	level        uint64
	currentRound uint64

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
func NewAggregator(config *protocol.ZIPNetConfig, privateKey crypto.PrivateKey, publicKey crypto.PublicKey,
	registeredUsers []crypto.PublicKey, registeredAggregators []crypto.PublicKey, level uint64) (*AggregatorImpl, error) {

	if config == nil {
		return nil, errors.New("config cannot be nil")
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

	a := &AggregatorImpl{
		publicKey:             publicKey,
		privateKey:            privateKey,
		config:                config,
		registeredUsers:       userMap,
		registeredAggregators: aggMap,
		level:                 level,
		currentRound:          protocol.CurrentRound(config.RoundDuration),
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
