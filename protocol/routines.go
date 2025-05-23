package protocol

import (
	"crypto/sha256"
	"fmt"

	"github.com/flashbots/adcnet/crypto"
)

type ServerMessager struct {
	Config        *ZIPNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

func (s *ServerMessager) UnblindAggregates(currentRound int, msgs []*Signed[AggregatedClientMessages], allowedAggregators map[string]bool, previousRoundAuction *IBFVector) (*ServerPartialDecryptionMessage, error) {
	unifiedAggregate := AggregatedClientMessages{
		RoundNubmer:   currentRound,
		IBFVector:     NewIBFVector(s.Config.MessageSlots),
		MessageVector: make([]byte, s.Config.MessageSize*s.Config.MessageSlots),
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
		unifiedAggregate.UserPKs = append(unifiedAggregate.UserPKs, rawMsg.UserPKs...)
		unifiedAggregate.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(unifiedAggregate.MessageVector, rawMsg.MessageVector)
	}

	blindingVector := NewBlindingVector(s.Config.MessageSize*s.Config.MessageSlots, s.Config.MessageSlots)
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
	blindingVector := NewBlindingVector(s.Config.MessageSize*s.Config.MessageSlots, s.Config.MessageSlots)

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
		IBFVector:     originalAggregate.IBFVector.Decrypt(blindingVector.AuctionPad, blindingVector.CountersPad),
		MessageVector: crypto.Xor(originalAggregate.MessageVector, blindingVector.MessagePad),
	}

	return &unblindedMessage, nil
}

func AggregateClientMessages(round int, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNubmer: round,
		// TODO: initialize use Config instead
		IBFVector:     NewIBFVector(uint32(len(msgs[0].UnsafeObject().IBFVector.Chunks[0]))),
		MessageVector: make([]byte, len(msgs[0].UnsafeObject().MessageVector)),
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

		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, signer)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

func AggregateAggregates(round int, msgs []*Signed[AggregatedClientMessages], authorizedAggregators map[string]bool) (*AggregatedClientMessages, error) {
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
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, rawMsg.UserPKs...)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

type ClientMessager struct {
	Config        *ZIPNetConfig
	SharedSecrets map[string]crypto.SharedKey
}

func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *Signed[ServerRoundData], previousRoundMessage []byte, currentRoundAuctionData *AuctionData) (*ClientRoundMessage, bool, error) {
	shouldSendMessage, messageIndex := func() (bool, int) {
		if previousRoundOutput == nil || previousRoundOutput.UnsafeObject().RoundNubmer+1 != currentRound {
			return false, 0
		}

		// Check if we won the last one
		topWeight := 0
		ourWeight := 0
		previousRoundHash := sha256.Sum256(previousRoundMessage)
		for _, chunk := range previousRoundOutput.UnsafeObject().IBFVector.Recover() {
			auctionData := AuctionDataFromChunk(chunk)
			if auctionData.MessageHash == previousRoundHash {
				ourWeight = auctionData.Weight
			} else {
				if auctionData.Weight > topWeight {
					topWeight = auctionData.Weight
				}
			}
		}

		// TODO: approximage the knapsack!
		return ourWeight > topWeight, 0
	}()

	blindingVector := NewBlindingVector(c.Config.MessageSize*c.Config.MessageSlots, c.Config.MessageSlots)

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
		crypto.XorInplace(messageVector[messageIndex:messageIndex+len(previousRoundMessage)], previousRoundMessage)
	}

	return &ClientRoundMessage{
		RoundNubmer:   currentRound,
		IBFVector:     auctionIBF,
		MessageVector: messageVector,
	}, shouldSendMessage, nil
}
