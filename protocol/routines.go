package protocol

import (
	"crypto/sha256"
	"fmt"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

type ServerMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

// UnblindAggregates creates partial decryption of aggregated messages.
// Assumes all client shared secrets are established and fresh.
// No verification of message integrity before processing.
func (s *ServerMessager) UnblindAggregates(currentRound int, msgs []*Signed[AggregatedClientMessages], allowedAggregators map[string]bool, previousRoundAuction *blind_auction.IBFVector) (*ServerPartialDecryptionMessage, error) {
	unifiedAggregate := AggregatedClientMessages{
		RoundNumber:   currentRound,
		AuctionVector: blind_auction.NewIBFVector(s.Config.AuctionSlots),
		MessageVector: make([]byte, s.Config.MessageSize),
	}
	for _, msg := range msgs {
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !allowedAggregators[signer.String()] {
			return nil, fmt.Errorf("unauthorized aggregator %s", signer.String())
		}

		if rawMsg.RoundNumber != currentRound {
			return nil, fmt.Errorf("message for incorrect round %d, expected %d", rawMsg.RoundNumber, currentRound)
		}

		// TODO: consider recovering and checking user signatures rather than aggregator ones
		// TODO: aggregate user signatures (BLS or equivalent)
		unifiedAggregate.UserPKs = append(unifiedAggregate.UserPKs, rawMsg.UserPKs...)
		unifiedAggregate.AuctionVector.UnionInplace(rawMsg.AuctionVector)
		crypto.XorInplace(unifiedAggregate.MessageVector, rawMsg.MessageVector)
	}

	blindingVector := blind_auction.NewBlindingVector(s.Config.MessageSize, s.Config.AuctionSlots)
	for _, userPk := range unifiedAggregate.UserPKs {
		sharedKey, ok := s.SharedSecrets[userPk.String()]
		if !ok {
			return nil, fmt.Errorf("no shared key with user %x", userPk.Bytes())
		}

		err := blindingVector.DeriveInplace(currentRound, sharedKey, previousRoundAuction)
		if err != nil {
			return nil, fmt.Errorf("could not derive pads: %w", err)
		}
	}

	return &ServerPartialDecryptionMessage{
		OriginalAggregate: unifiedAggregate,
		UserPKs:           unifiedAggregate.UserPKs,
		BlindingVector:    blindingVector,
	}, nil
}

func (s *ServerMessager) UnblindPartialMessages(msgs []*Signed[ServerPartialDecryptionMessage], allowedServers map[string]bool) (*ServerRoundData, error) {
	blindingVector := blind_auction.NewBlindingVector(s.Config.MessageSize, s.Config.AuctionSlots)

	for _, msg := range msgs {
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !allowedServers[signer.String()] {
			return nil, fmt.Errorf("unauthorized server %s", signer.String())
		}
		blindingVector.UnionInplace(rawMsg.BlindingVector)
	}

	originalAggregate := msgs[0].UnsafeObject().OriginalAggregate

	unblindedMessage := ServerRoundData{
		RoundNumber:   originalAggregate.RoundNumber,
		AuctionVector: originalAggregate.AuctionVector.Clone().DecryptInplace(blindingVector.AuctionPad, blindingVector.CountersPad),
		MessageVector: crypto.Xor(originalAggregate.MessageVector, blindingVector.MessagePad),
	}

	return &unblindedMessage, nil
}

type AggregatorMessager struct {
	Config *ADCNetConfig
}

func (a *AggregatorMessager) AggregateClientMessages(round int, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNumber:   round,
		AuctionVector: blind_auction.NewIBFVector(a.Config.AuctionSlots),
		MessageVector: make([]byte, a.Config.MessageSize),
	}

	for _, msg := range msgs {
		// Note: should probably skip rather than break, or validaiton should
		// be done separately so that the handler can choose
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !authorizedClients[signer.String()] {
			return nil, fmt.Errorf("unauthorized client %s", signer.String())
		}

		if rawMsg.RoundNumber != round {
			return nil, fmt.Errorf("client message for round %d, expected %d", rawMsg.RoundNumber, round)
		}

		// TODO: aggregate user signatures (BLS or equivalent)
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, signer)
		aggregatedMsg.AuctionVector.UnionInplace(rawMsg.AuctionVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

func (a *AggregatorMessager) AggregateAggregates(round int, msgs []*Signed[AggregatedClientMessages], authorizedAggregators map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNumber: round,
	}

	for _, msg := range msgs {
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !authorizedAggregators[signer.String()] {
			return nil, fmt.Errorf("unauthorized aggregator %s", signer.String())
		}

		if rawMsg.RoundNumber != round {
			return nil, fmt.Errorf("client message for round %d, expected %d", rawMsg.RoundNumber, round)
		}

		if aggregatedMsg.AuctionVector == nil {
			aggregatedMsg.AuctionVector = blind_auction.NewIBFVector(uint32(len(rawMsg.AuctionVector.Chunks[0])))
		}

		// Alternatively recover user messages
		// TODO: aggregate user signatures (BLS or equivalent)
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, rawMsg.UserPKs...)
		aggregatedMsg.AuctionVector.UnionInplace(rawMsg.AuctionVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

type ClientMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

// PrepareMessage creates encrypted message with auction data.
func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *Signed[ServerRoundData], previousRoundMessage []byte, currentRoundAuctionData *blind_auction.AuctionData) (*ClientRoundMessage, bool, error) {

	// Note that messages must be salted (random prefix).
	shouldSendMessage, messageIndex := func() (bool, uint32) {
		if previousRoundOutput == nil || previousRoundOutput.UnsafeObject().RoundNumber+1 != currentRound {
			return false, 0
		}

		chunks := previousRoundOutput.UnsafeObject().AuctionVector.Recover()
		bids := make([]blind_auction.AuctionData, 0, len(chunks))
		for _, chunk := range chunks {
			bids = append(bids, *blind_auction.AuctionDataFromChunk(chunk))
		}

		auctionEngine := blind_auction.NewAuctionEngine(c.Config.MessageSize, blind_auction.IBFChunkSize)
		// Run auction to determine winners
		winners := auctionEngine.RunAuction(bids)

		// Check if we won
		ourHash := sha256.Sum256(previousRoundMessage)
		for _, winner := range winners {
			if winner.Bid.MessageHash == ourHash {
				return true, winner.SlotIdx
			}
		}
		return false, 0
	}()

	blindingVector := blind_auction.NewBlindingVector(c.Config.MessageSize, c.Config.AuctionSlots)

	var previousRoundAuction *blind_auction.IBFVector = nil
	if previousRoundOutput != nil {
		// TODO: we might want to verify
		previousRoundAuction = previousRoundOutput.UnsafeObject().AuctionVector
	}
	for _, serverKem := range c.SharedSecrets {
		err := blindingVector.DeriveInplace(currentRound, serverKem, previousRoundAuction)
		if err != nil {
			return nil, false, err
		}
	}

	auctionIBF := blind_auction.NewIBFVector(c.Config.AuctionSlots)
	auctionIBF.InsertChunk(currentRoundAuctionData.EncodeToChunk())
	auctionIBF.EncryptInplace(blindingVector.AuctionPad, blindingVector.CountersPad)

	messageVector := blindingVector.MessagePad
	if shouldSendMessage {
		crypto.XorInplace(messageVector[messageIndex:int(messageIndex)+len(previousRoundMessage)], previousRoundMessage)
	}

	return &ClientRoundMessage{
		RoundNumber:   currentRound,
		AuctionVector: auctionIBF,
		MessageVector: MessageVector(messageVector),
	}, shouldSendMessage, nil
}
