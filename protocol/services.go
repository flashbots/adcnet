package protocol

import (
	"crypto/ecdh"
	"errors"
	"slices"
	"sync"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

// ServerService manages server-side protocol operations.
type ServerService struct {
	config            *ADCNetConfig
	serverID          ServerID
	serverSigningKey  crypto.PrivateKey
	serverExchangeKey *ecdh.PrivateKey

	secretsMutex  sync.Mutex
	sharedSecrets map[string]crypto.SharedKey

	roundMutex   sync.Mutex
	currentRound int
	roundData    *ServerRoundData
}

// ServerRoundData holds per-round state for message reconstruction.
type ServerRoundData struct {
	Round                           int
	ServerPartialDecryptionMessages map[ServerID]*ServerPartialDecryptionMessage
	PartialDecryptionMessage        *ServerPartialDecryptionMessage
	RoundOutput                     *RoundBroadcast
}

// NewServerService creates a server service with the given configuration and keys.
func NewServerService(config *ADCNetConfig, serverId ServerID, serverSigningKey crypto.PrivateKey, serverExchangeKey *ecdh.PrivateKey) *ServerService {
	return &ServerService{
		config:            config,
		serverID:          serverId,
		serverSigningKey:  serverSigningKey,
		serverExchangeKey: serverExchangeKey,
		sharedSecrets:     make(map[string]crypto.SharedKey),
		roundData:         nil,
	}
}

// AdvanceToRound transitions the server to a new protocol round.
func (s *ServerService) AdvanceToRound(round Round) {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if s.currentRound >= round.Number {
		return
	}

	s.currentRound = round.Number
	s.roundData = &ServerRoundData{
		Round:                           s.currentRound,
		ServerPartialDecryptionMessages: make(map[ServerID]*ServerPartialDecryptionMessage),
		PartialDecryptionMessage:        nil,
		RoundOutput:                     nil,
	}
}

// RegisterClient establishes a shared secret with a client via ECDH.
func (s *ServerService) RegisterClient(clientPubkey crypto.PublicKey, clientECDHPubkey *ecdh.PublicKey) error {
	s.secretsMutex.Lock()
	defer s.secretsMutex.Unlock()

	sharedSecret, err := s.serverExchangeKey.ECDH(clientECDHPubkey)
	if err != nil {
		return err
	}

	s.sharedSecrets[clientPubkey.String()] = sharedSecret
	return nil
}

// DeregisterClient removes a client's shared secret.
func (s *ServerService) DeregisterClient(clientPubkey crypto.PublicKey) error {
	s.secretsMutex.Lock()
	defer s.secretsMutex.Unlock()

	delete(s.sharedSecrets, clientPubkey.String())
	return nil
}

// ProcessPartialDecryptionMessage collects partial decryptions from servers.
func (s *ServerService) ProcessPartialDecryptionMessage(msg *ServerPartialDecryptionMessage) (*RoundBroadcast, error) {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if msg.OriginalAggregate.RoundNumber != s.currentRound {
		return nil, errors.New("message for incorrect round")
	}

	if s.roundData.RoundOutput != nil {
		return s.roundData.RoundOutput, nil
	}

	s.roundData.ServerPartialDecryptionMessages[msg.ServerID] = msg
	if len(s.roundData.ServerPartialDecryptionMessages) < len(msg.OriginalAggregate.AllServerIds) {
		return nil, nil
	}

	msgs := make([]*ServerPartialDecryptionMessage, 0, len(s.roundData.ServerPartialDecryptionMessages))
	for _, msg := range s.roundData.ServerPartialDecryptionMessages {
		msgs = append(msgs, msg)
	}

	roundBroadcast, err := (&ServerMessager{Config: s.config, ServerID: s.serverID, SharedSecrets: s.sharedSecrets}).UnblindPartialMessages(msgs)
	if err != nil {
		return nil, err
	}

	s.roundData.RoundOutput = roundBroadcast
	return roundBroadcast, nil
}

// ProcessAggregateMessage removes this server's blinding factors from the aggregate.
func (s *ServerService) ProcessAggregateMessage(msg *AggregatedClientMessages) (*ServerPartialDecryptionMessage, error) {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if !slices.Contains(msg.AllServerIds, s.serverID) {
		return nil, errors.New("message for invalid server")
	}

	if msg.RoundNumber != s.currentRound {
		return nil, errors.New("message for incorrect round")
	}

	additionalPartialDecryption, err := (&ServerMessager{Config: s.config, ServerID: s.serverID, SharedSecrets: s.sharedSecrets}).UnblindAggregate(s.currentRound, msg)
	if err != nil {
		return nil, err
	}

	currentPartialDecryption := s.roundData.PartialDecryptionMessage
	if currentPartialDecryption == nil {
		s.roundData.PartialDecryptionMessage = additionalPartialDecryption
		currentPartialDecryption = additionalPartialDecryption
	} else {
		currentPartialDecryption.UserPKs = append(currentPartialDecryption.UserPKs, additionalPartialDecryption.UserPKs...)

		for i := range currentPartialDecryption.AuctionVector {
			crypto.FieldAddInplace(currentPartialDecryption.AuctionVector[i], additionalPartialDecryption.AuctionVector[i], crypto.AuctionFieldOrder)
		}

		crypto.XorInplace(currentPartialDecryption.MessageVector, additionalPartialDecryption.MessageVector)

		if _, err := currentPartialDecryption.OriginalAggregate.UnionInplace(msg); err != nil {
			return nil, err
		}
	}

	s.roundData.ServerPartialDecryptionMessages[s.serverID] = currentPartialDecryption
	return currentPartialDecryption, nil
}

// AggregatorService combines client messages to reduce bandwidth to servers.
type AggregatorService struct {
	config *ADCNetConfig

	clientsMutex      sync.Mutex
	authorizedClients map[string]bool

	roundMutex   sync.Mutex
	currentRound int
	roundData    *AggregatorRoundData
}

// AggregatorRoundData holds per-round aggregation state.
type AggregatorRoundData struct {
	Round     int
	Aggregate *AggregatedClientMessages
}

// NewAggregatorService creates an aggregator service.
func NewAggregatorService(config *ADCNetConfig) *AggregatorService {
	return &AggregatorService{
		config:            config,
		authorizedClients: make(map[string]bool),
		roundData:         nil,
	}
}

// AdvanceToRound transitions the aggregator to a new protocol round.
func (a *AggregatorService) AdvanceToRound(round Round) {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	if a.currentRound >= round.Number {
		return
	}

	a.currentRound = round.Number
	a.roundData = &AggregatorRoundData{
		Round:     a.currentRound,
		Aggregate: nil,
	}
}

// RegisterClient authorizes a client to submit messages.
func (a *AggregatorService) RegisterClient(pubkey crypto.PublicKey) error {
	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	a.authorizedClients[pubkey.String()] = true
	return nil
}

// DeregisterClient removes a client's authorization.
func (a *AggregatorService) DeregisterClient(pubkey crypto.PublicKey) error {
	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	delete(a.authorizedClients, pubkey.String())
	return nil
}

// ProcessClientMessages verifies and aggregates signed client messages.
func (a *AggregatorService) ProcessClientMessages(msgs []*Signed[ClientRoundMessage]) (*AggregatedClientMessages, error) {
	verified, err := VerifyClientMessages(msgs)
	if err != nil {
		return nil, err
	}
	return a.ProcessVerifiedMessages(verified)
}

// ProcessVerifiedMessages aggregates pre-verified client messages.
func (a *AggregatorService) ProcessVerifiedMessages(verified []VerifiedClientMessage) (*AggregatedClientMessages, error) {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	for _, v := range verified {
		if v.Message.RoundNumber != a.currentRound {
			return nil, errors.New("incorrect round")
		}
	}

	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	newAggregate, err := (&AggregatorMessager{Config: a.config}).AggregateVerifiedMessages(a.currentRound, a.roundData.Aggregate, verified, a.authorizedClients)
	if err != nil {
		return nil, err
	}

	a.roundData.Aggregate = newAggregate
	return a.roundData.Aggregate, nil
}

// CurrentAggregates returns the current round's aggregate.
func (a *AggregatorService) CurrentAggregates() *AggregatedClientMessages {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	if a.roundData != nil {
		return a.roundData.Aggregate
	}
	return nil
}

// ClientService manages client-side protocol operations.
type ClientService struct {
	config      *ADCNetConfig
	exchangeKey *ecdh.PrivateKey
	signingKey  crypto.PrivateKey

	secretsMutex  sync.Mutex
	sharedSecrets map[ServerID]crypto.SharedKey

	roundMutex   sync.Mutex
	currentRound int
	roundData    map[int]*ClientRoundData
}

// ClientRoundData holds per-round client state.
type ClientRoundData struct {
	roundOutput      *RoundBroadcast
	messageScheduled []byte
	auctionData      *blind_auction.AuctionData
}

// NewClientService creates a client service.
func NewClientService(config *ADCNetConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) *ClientService {
	return &ClientService{
		config:        config,
		signingKey:    signingKey,
		exchangeKey:   exchangeKey,
		sharedSecrets: make(map[ServerID]crypto.SharedKey),
		roundData:     make(map[int]*ClientRoundData),
	}
}

// AdvanceToRound transitions the client to a new protocol round.
func (c *ClientService) AdvanceToRound(round Round) {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	if round.Number <= c.currentRound {
		return
	}

	c.currentRound = round.Number

	if c.roundData[round.Number] == nil {
		c.roundData[round.Number] = &ClientRoundData{}
	}
}

// RegisterServer establishes a shared secret with a server via ECDH.
func (c *ClientService) RegisterServer(serverId ServerID, serverExchangePubkey *ecdh.PublicKey) error {
	c.secretsMutex.Lock()
	defer c.secretsMutex.Unlock()

	sharedSecret, err := c.exchangeKey.ECDH(serverExchangePubkey)
	if err != nil {
		return err
	}

	c.sharedSecrets[serverId] = sharedSecret
	return nil
}

// DeregisterServer removes a server's shared secret.
func (c *ClientService) DeregisterServer(serverId ServerID) error {
	c.secretsMutex.Lock()
	defer c.secretsMutex.Unlock()

	delete(c.sharedSecrets, serverId)
	return nil
}

// ScheduleMessageForNextRound queues a message with a bid value for the auction.
func (c *ClientService) ScheduleMessageForNextRound(msg []byte, bidValue uint32) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	// Safety check
	if msg == nil {
		return errors.New("refusing to schedule empty message")
	}

	if _, exists := c.roundData[c.currentRound]; !exists {
		return errors.New("client not yet initialized")
	}

	if c.roundData[c.currentRound].messageScheduled != nil {
		return errors.New("another message already scheduled")
	}

	c.roundData[c.currentRound].messageScheduled = msg
	c.roundData[c.currentRound].auctionData = blind_auction.AuctionDataFromMessage(msg, bidValue)

	return nil
}

// MessagesForCurrentRound generates the blinded message for the current round.
func (c *ClientService) MessagesForCurrentRound() (*Signed[ClientRoundMessage], bool, error) {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	previousRoundData := c.roundData[c.currentRound-1]
	if previousRoundData == nil {
		return nil, false, errors.New("previous round result not known")
	}

	currentRoundData := c.roundData[c.currentRound]

	msg, wonAuction, err := (&ClientMessager{Config: c.config, SharedSecrets: c.sharedSecrets}).PrepareMessage(c.currentRound, previousRoundData.roundOutput, previousRoundData.messageScheduled, currentRoundData.auctionData)
	if err != nil {
		return nil, false, err
	}

	signedMsg, err := NewSigned(c.signingKey, msg)
	if err != nil {
		return nil, false, err
	}

	return signedMsg, wonAuction, nil
}

// ProcessRoundBroadcast stores the reconstructed broadcast for auction results.
func (c *ClientService) ProcessRoundBroadcast(rb *RoundBroadcast) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	if c.roundData[rb.RoundNumber] == nil {
		c.roundData[rb.RoundNumber] = &ClientRoundData{}
	}
	c.roundData[rb.RoundNumber].roundOutput = rb
	return nil
}
