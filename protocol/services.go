package protocol

import (
	"crypto/ecdh"
	"errors"
	"math/big"
	"slices"
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
	roundData    map[int]*ServerRoundData
}

func NewServerService(config *ADCNetConfig, serverId ServerID, serverSigningKey crypto.PrivateKey, serverExchangeKey *ecdh.PrivateKey) *ServerService {
	s := &ServerService{
		config:            config,
		serverID:          serverId,
		serverSigningKey:  serverSigningKey,
		serverExchangeKey: serverExchangeKey,
		sharedSecrets:     make(map[string]crypto.SharedKey),
		roundData:         make(map[int]*ServerRoundData),
	}
	return s
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

func (s *ServerService) AdvanceRound(int) {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	s.currentRound += 1
	s.roundData[s.currentRound] = &ServerRoundData{
		Round:                           s.currentRound,
		ServerPartialDecryptionMessages: make(map[ServerID]*ServerPartialDecryptionMessage),
		AggregatedClientMessages: &AggregatedClientMessages{
			RoundNumber:   s.currentRound,
			ServerID:      s.serverID,
			AuctionVector: make([]*big.Int, AuctionSlotsForConfig(s.config)),
			MessageVector: make([]*big.Int, s.config.MessageSize),
		},
		RoundOutput: nil,
	}
}

func (s *ServerService) ProcessPartialDecryptionMessage(msg *ServerPartialDecryptionMessage) error {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if msg.OriginalAggregate.RoundNumber != s.currentRound {
		return errors.New("message for incorrect round")
	}

	if s.roundData[s.currentRound] == nil {
		panic("round not prepared, refusing to continue")
	}

	s.roundData[s.currentRound].ServerPartialDecryptionMessages[msg.ServerID] = msg

	return nil
}

func (s *ServerService) ProcessAggregateMessage(msg *AggregatedClientMessages) error {
	s.roundMutex.Lock()
	defer s.roundMutex.Unlock()

	if msg.ServerID != s.serverID {
		return errors.New("message for invalid server")
	}

	if msg.RoundNumber != s.currentRound {
		return errors.New("message for incorrect round")
	}

	s.roundData[s.currentRound].AggregatedClientMessages.UnionInplace(msg)

	return nil
}

type ServerRoundData struct {
	Round                           int
	ServerPartialDecryptionMessages map[ServerID]*ServerPartialDecryptionMessage
	AggregatedClientMessages        *AggregatedClientMessages
	RoundOutput                     *RoundBroadcast
}

type AggregatorService struct {
	config *ADCNetConfig

	clientsMutex      sync.Mutex
	authorizedClients map[string]bool

	roundMutex   sync.Mutex
	currentRound int
	roundData    map[int]*AggregatorRoundData
}

func NewAggregatorService(config *ADCNetConfig) *AggregatorService {
	return &AggregatorService{
		config:            config,
		authorizedClients: make(map[string]bool),
		roundData:         make(map[int]*AggregatorRoundData),
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

func (a *AggregatorService) ProcessClientMessage(msg *Signed[ClientRoundMessage]) error {
	a.roundMutex.Lock()
	defer a.roundMutex.Lock()

	if msg.UnsafeObject().RoundNumber != a.currentRound {
		return errors.New("incorrect round")
	}

	a.clientsMutex.Lock()
	defer a.clientsMutex.Unlock()

	if a.roundData[a.currentRound] == nil {
		panic("round not prepared, refusing to continue")
	}

	newAggregates, err := (&AggregatorMessager{Config: a.config}).AggregateClientMessages(a.currentRound, a.roundData[a.currentRound].Aggregates, []*Signed[ClientRoundMessage]{msg}, a.authorizedClients)
	if err != nil {
		return err
	}

	a.roundData[a.currentRound].Aggregates = newAggregates
	return nil
}

func (a *AggregatorService) ProcessAggregateMessage(msgs []*AggregatedClientMessages) error {
	a.roundMutex.Lock()
	defer a.roundMutex.Lock()

	if msgs[0].RoundNumber != a.currentRound {
		return errors.New("incorrect round")
	}

	newAggregates, err := (&AggregatorMessager{Config: a.config}).AggregateAggregates(a.currentRound, slices.Concat(a.roundData[a.currentRound].Aggregates, msgs))
	if err != nil {
		return err
	}

	a.roundData[a.currentRound].Aggregates = newAggregates
	return nil
}

type AggregatorRoundData struct {
	Round      int
	Aggregates []*AggregatedClientMessages
}

type ClientService struct {
	config      *ADCNetConfig
	exchangeKey *ecdh.PrivateKey

	secretsMutex  sync.Mutex
	sharedSecrets map[ServerID]crypto.SharedKey

	roundMutex   sync.Mutex
	currentRound int
	roundData    map[int]*ClientRoundData
}

func NewClientService(config *ADCNetConfig, exchangeKey *ecdh.PrivateKey) *ClientService {
	return &ClientService{
		config:      config,
		exchangeKey: exchangeKey,
		roundData:   make(map[int]*ClientRoundData),
	}
}

type ClientRoundData struct {
	roundOutput      *RoundBroadcast
	messageScheduled []byte
	auctionData      *blind_auction.AuctionData
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

func (c *ClientService) ScheduleMessageForNextRound(msg []byte, auctionData *blind_auction.AuctionData) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	c.roundData[c.currentRound+1] = &ClientRoundData{
		roundOutput:      nil,
		messageScheduled: msg,
		auctionData:      auctionData,
	}
	return nil
}

func (c *ClientService) ProcessRoundBroadcast(rb *RoundBroadcast) error {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	if rb.RoundNumber != c.currentRound {
		return errors.New("incorrect round")
	}

	// Possibly overwrites
	c.roundData[rb.RoundNumber].roundOutput = rb
	return nil
}

func (c *ClientService) MessageAllocated(round int) bool {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	if c.roundData[round] != nil && c.roundData[round].roundOutput != nil && c.roundData[round].auctionData != nil {
		auctionResult := (&ClientMessager{Config: c.config}).ProcessPreviousAuction(c.roundData[round].roundOutput.AuctionVector, c.roundData[round].messageScheduled)
		return auctionResult.ShouldSend
	}

	return false
}

func (c *ClientService) ParticipateInRound(round int) ([]*ClientRoundMessage, bool, error) {
	c.roundMutex.Lock()
	defer c.roundMutex.Unlock()

	c.currentRound = round
	previousRoundData := c.roundData[round-1]
	if previousRoundData == nil {
		previousRoundData = &ClientRoundData{}
	}

	currentRoundData := c.roundData[round]
	if currentRoundData == nil {
		currentRoundData = &ClientRoundData{}
		c.roundData[round] = currentRoundData
	}

	return (&ClientMessager{Config: c.config, SharedSecrets: c.sharedSecrets}).PrepareMessage(round, previousRoundData.roundOutput, previousRoundData.messageScheduled, currentRoundData.auctionData)
}
