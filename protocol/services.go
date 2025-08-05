// File: protocol/services_updated.go
// This shows the updates needed to existing services.go file

package protocol

import (
	"crypto/ecdh"
	"errors"
	"sync"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

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

type ServerRoundData struct {
	Round                           int
	ServerPartialDecryptionMessages map[ServerID]*ServerPartialDecryptionMessage
	PartialDecryptionMessage        *ServerPartialDecryptionMessage
	RoundOutput                     *RoundBroadcast
}

func NewServerService(config *ADCNetConfig, serverId ServerID, serverSigningKey crypto.PrivateKey, serverExchangeKey *ecdh.PrivateKey) *ServerService {
	s := &ServerService{
		config:            config,
		serverID:          serverId,
		serverSigningKey:  serverSigningKey,
		serverExchangeKey: serverExchangeKey,
		sharedSecrets:     make(map[string]crypto.SharedKey),
		roundData:         nil,
	}

	return s
}

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

func (s *ServerService) DeregisterClient(clientPubkey crypto.PublicKey) error {
	s.secretsMutex.Lock()
	defer s.secretsMutex.Unlock()

	delete(s.sharedSecrets, clientPubkey.String())
	return nil
}

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
	if len(s.roundData.ServerPartialDecryptionMessages) < int(s.config.MinServers) {
		return nil, nil
	}

	msgs := []*ServerPartialDecryptionMessage{}
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

func (s *ServerService) ProcessAggregateMessage(msg *AggregatedClientMessages) (*ServerPartialDecryptionMessage, error) {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if msg.ServerID != s.serverID {
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

		for i := range currentPartialDecryption.MessageVector {
			crypto.FieldAddInplace(currentPartialDecryption.MessageVector[i], additionalPartialDecryption.MessageVector[i], s.config.MessageFieldOrder)
		}

		currentPartialDecryption.OriginalAggregate.UnionInplace(msg, s.config.MessageFieldOrder)
	}

	s.roundData.ServerPartialDecryptionMessages[s.serverID] = currentPartialDecryption

	return currentPartialDecryption, err
}

type AggregatorService struct {
	config *ADCNetConfig

	clientsMutex      sync.Mutex
	authorizedClients map[string]bool

	roundMutex   sync.Mutex
	currentRound int
	roundData    *AggregatorRoundData
}

type AggregatorRoundData struct {
	Round      int
	Aggregates []*AggregatedClientMessages
}

func NewAggregatorService(config *ADCNetConfig) *AggregatorService {
	a := &AggregatorService{
		config:            config,
		authorizedClients: make(map[string]bool),
		roundData:         nil,
	}

	return a
}

func (a *AggregatorService) AdvanceToRound(round Round) {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	if a.currentRound >= round.Number {
		return
	}

	a.currentRound = round.Number
	a.roundData = &AggregatorRoundData{
		Round:      a.currentRound,
		Aggregates: make([]*AggregatedClientMessages, 0),
	}
}

func (a *AggregatorService) RegisterClient(pubkey crypto.PublicKey) error {
	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	a.authorizedClients[pubkey.String()] = true

	return nil
}

func (a *AggregatorService) DeregisterClient(pubkey crypto.PublicKey) error {
	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	delete(a.authorizedClients, pubkey.String())

	return nil
}

func (a *AggregatorService) ProcessClientMessages(msgs []*Signed[ClientRoundMessage]) ([]*AggregatedClientMessages, error) {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	for _, msg := range msgs {
		if msg.UnsafeObject().RoundNumber != a.currentRound {
			return nil, errors.New("incorrect round")
		}
	}

	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	for _, msg := range msgs {
		newAggregate, err := (&AggregatorMessager{Config: a.config}).AggregateClientMessages(a.currentRound, a.roundData.Aggregates, []*Signed[ClientRoundMessage]{msg}, a.authorizedClients)
		if err != nil {
			return nil, err
		}

		a.roundData.Aggregates = newAggregate
	}

	return a.roundData.Aggregates, nil
}

func (a *AggregatorService) CurrentAggregates() []*AggregatedClientMessages {
	a.roundMutex.Lock()
	defer a.roundMutex.Unlock()

	if a.roundData != nil {
		return a.roundData.Aggregates
	}
	return nil
}

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

// ClientRoundData with exported fields
type ClientRoundData struct {
	roundOutput      *RoundBroadcast
	messageScheduled []byte
	auctionData      *blind_auction.AuctionData
}

func NewClientService(config *ADCNetConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) *ClientService {
	c := &ClientService{
		config:        config,
		signingKey:    signingKey,
		exchangeKey:   exchangeKey,
		sharedSecrets: make(map[ServerID]crypto.SharedKey),
		roundData:     make(map[int]*ClientRoundData),
	}

	return c
}

func (c *ClientService) AdvanceToRound(round Round) {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	if round.Number <= c.currentRound {
		return
	}

	c.currentRound = round.Number

	// Initialize round data if not exists
	if c.roundData[round.Number] == nil {
		c.roundData[round.Number] = &ClientRoundData{}
	}
}

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

func (c *ClientService) DeregisterServer(serverId ServerID, serverExchangePubkey *ecdh.PublicKey) error {
	c.secretsMutex.Lock()
	defer c.secretsMutex.Unlock()

	delete(c.sharedSecrets, serverId)
	return nil
}

// ScheduleMessageForNextRound schedules a message with bid value.
func (c *ClientService) ScheduleMessageForNextRound(msg []byte, bidValue uint32) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	c.roundData[c.currentRound].messageScheduled = msg
	c.roundData[c.currentRound].auctionData = blind_auction.AuctionDataFromMessage(msg, bidValue, (c.config.MessageFieldOrder.BitLen()-1)/8)

	return nil
}

func (c *ClientService) MessagesForCurrentRound() ([]*Signed[ClientRoundMessage], bool, error) {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	previousRoundData := c.roundData[c.currentRound-1]
	if previousRoundData == nil {
		previousRoundData = &ClientRoundData{}
	}

	currentRoundData := c.roundData[c.currentRound]

	msgs, wonAuction, err := (&ClientMessager{Config: c.config, SharedSecrets: c.sharedSecrets}).PrepareMessage(c.currentRound, previousRoundData.roundOutput, previousRoundData.messageScheduled, currentRoundData.auctionData)
	if err != nil {
		return nil, false, err
	}

	signedMsgs := []*Signed[ClientRoundMessage]{}
	for _, msg := range msgs {
		signedMsg, err := NewSigned(c.signingKey, msg)
		if err != nil {
			return nil, false, err
		}
		signedMsgs = append(signedMsgs, signedMsg)
	}

	return signedMsgs, wonAuction, nil
}

func (c *ClientService) ProcessRoundBroadcast(rb *RoundBroadcast) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	// Possibly overwrites
	c.roundData[rb.RoundNumber].roundOutput = rb
	return nil
}
