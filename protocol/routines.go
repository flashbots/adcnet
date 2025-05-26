package protocol

import (
	"crypto/sha256"
	"fmt"

	"github.com/flashbots/adcnet/crypto"
)

type ServerMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

// UnblindAggregates creates partial decryption of aggregated messages.
// Assumes all client shared secrets are established and fresh.
// No verification of message integrity before processing.
func (s *ServerMessager) UnblindAggregates(currentRound int, msgs []*Signed[AggregatedClientMessages], allowedAggregators map[string]bool, previousRoundAuction *IBFVector) (*ServerPartialDecryptionMessage, error) {
	unifiedAggregate := AggregatedClientMessages{
		RoundNubmer:   currentRound,
		IBFVector:     NewIBFVector(s.Config.MessageSlots),
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

		if rawMsg.RoundNubmer != currentRound {
			return nil, fmt.Errorf("message for incorrect round %d, expected %d", rawMsg.RoundNubmer, currentRound)
		}

		// TODO: consider recovering and checking user signatures rather than aggregator ones
		// TODO: aggregate user signatures (BLS or equivalent)
		unifiedAggregate.UserPKs = append(unifiedAggregate.UserPKs, rawMsg.UserPKs...)
		unifiedAggregate.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(unifiedAggregate.MessageVector, rawMsg.MessageVector)
	}

	blindingVector := NewBlindingVector(s.Config.MessageSize, s.Config.MessageSlots)
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
	blindingVector := NewBlindingVector(s.Config.MessageSize, s.Config.MessageSlots)

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
		RoundNubmer:   originalAggregate.RoundNubmer,
		IBFVector:     originalAggregate.IBFVector.Clone().DecryptInplace(blindingVector.AuctionPad, blindingVector.CountersPad),
		MessageVector: crypto.Xor(originalAggregate.MessageVector, blindingVector.MessagePad),
	}

	return &unblindedMessage, nil
}

type AggregatorMessager struct {
	Config        *ADCNetConfig
}

func (a *AggregatorMessager) AggregateClientMessages(round int, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNubmer: round,
		IBFVector:     NewIBFVector(a.Config.MessageSlots),
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

		if rawMsg.RoundNubmer != round {
			return nil, fmt.Errorf("client message for round %d, expected %d", rawMsg.RoundNubmer, round)
		}

		// TODO: aggregate user signatures (BLS or equivalent)
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, signer)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

func (a *AggregatorMessager) AggregateAggregates(round int, msgs []*Signed[AggregatedClientMessages], authorizedAggregators map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNubmer: round,
	}

	for _, msg := range msgs {
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !authorizedAggregators[signer.String()] {
			return nil, fmt.Errorf("unauthorized aggregator %s", signer.String())
		}

		if rawMsg.RoundNubmer != round {
			return nil, fmt.Errorf("client message for round %d, expected %d", rawMsg.RoundNubmer, round)
		}

		if aggregatedMsg.IBFVector == nil {
			aggregatedMsg.IBFVector = NewIBFVector(uint32(len(rawMsg.IBFVector.Chunks[0])))
		}

		// Alternatively recover user messages
		// TODO: aggregate user signatures (BLS or equivalent)
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, rawMsg.UserPKs...)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

type ClientMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

// PrepareMessage creates encrypted message with auction data.
func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *Signed[ServerRoundData], previousRoundMessage []byte, currentRoundAuctionData *AuctionData) (*ClientRoundMessage, bool, error) {

	// Note that messages must be salted (random prefix).
	shouldSendMessage, messageIndex := func() (bool, uint32) {
		if previousRoundOutput == nil || previousRoundOutput.UnsafeObject().RoundNubmer+1 != currentRound {
			return false, 0
		}

		chunks := previousRoundOutput.UnsafeObject().IBFVector.Recover()
		bids := make([]AuctionData, 0, len(chunks))
		for _, chunk := range chunks {
			bids = append(bids, *AuctionDataFromChunk(chunk))
		}

		auctionEngine := NewAuctionEngine(c.Config.MessageSize, IBFChunkSize)
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

	blindingVector := NewBlindingVector(c.Config.MessageSize, c.Config.MessageSlots)

	var previousRoundAuction *IBFVector = nil
	if previousRoundOutput != nil {
		// TODO: we might want to verify
		previousRoundAuction = previousRoundOutput.UnsafeObject().IBFVector
	}
	for _, serverKem := range c.SharedSecrets {
		err := blindingVector.DeriveInplace(currentRound, serverKem, previousRoundAuction)
		if err != nil {
			return nil, false, err
		}
	}

	auctionIBF := NewIBFVector(c.Config.MessageSlots)
	auctionIBF.InsertChunk(currentRoundAuctionData.EncodeToChunk())
	auctionIBF.EncryptInplace(blindingVector.AuctionPad, blindingVector.CountersPad)

	messageVector := blindingVector.MessagePad
	if shouldSendMessage {
		crypto.XorInplace(messageVector[messageIndex:int(messageIndex)+len(previousRoundMessage)], previousRoundMessage)
	}

	return &ClientRoundMessage{
		RoundNubmer:   currentRound,
		IBFVector:     auctionIBF,
		MessageVector: messageVector,
	}, shouldSendMessage, nil
}
