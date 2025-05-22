package protocol

import (
	"crypto/sha256"
	"fmt"

	"github.com/flashbots/adcnet/crypto"
)

type ServerMessager struct {
	Config           *ZIPNetConfig
	Crypto CryptoProvider
	SharedSecrets  map[string]crypto.SharedKey
}

func (s *ServerMessager) UnblindAggregates(msgs []*Signed[AggregatedClientMessages], allowedAggregators map[string]bool) (*ServerPartialDecryptionMessage, error) {
	unifiedAggregate := AggregatedClientMessages{
		IBFVector: NewIBFVector(s.Config.MessageSlots),
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

		unifiedAggregate.UserPKs = append(unifiedAggregate.UserPKs, signer)
		unifiedAggregate.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(unifiedAggregate.MessageVector, rawMsg.MessageVector)
	}

	partialUnblindMessage := ServerPartialDecryptionMessage{
		SchedulingPad: make([]byte, IBFVectorSize(s.Config.MessageSlots)),
		MessagePad: make([]byte, s.Config.MessageSize*s.Config.MessageSlots),
	}
	for _, userPk := range unifiedAggregate.UserPKs {
		auctionPad, msgPad, err := s.Crypto.KDF(s.SharedSecrets[userPk.String()], uint64(unifiedAggregate.RoundNubmer), []byte{}, len(partialUnblindMessage.SchedulingPad), len(partialUnblindMessage.MessagePad))
		if err != nil {
			return nil, fmt.Errorf("could not derive pads: %w", err)
		}

		crypto.XorInplace(partialUnblindMessage.SchedulingPad, auctionPad)
		crypto.XorInplace(partialUnblindMessage.MessagePad, msgPad)
	}

	return &partialUnblindMessage, nil
}

func (s *ServerMessager) UnblindPartialMessages(msgs []*Signed[ServerPartialDecryptionMessage], allowedServers map[string]bool) (*ServerRoundData, error) {
	allPartialMessages := ServerPartialDecryptionMessage{
		SchedulingPad: make([]byte, IBFVectorSize(s.Config.MessageSlots)),
		MessagePad: make([]byte, s.Config.MessageSize*s.Config.MessageSlots),
	}
	for _, msg := range msgs {
		rawMsg, signer, err := msg.Recover()
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		if !allowedServers[signer.String()] {
			return nil, fmt.Errorf("unauthorized server %s", signer.String())
		}
		crypto.XorInplace(allPartialMessages.SchedulingPad, rawMsg.SchedulingPad)
		crypto.XorInplace(allPartialMessages.MessagePad, rawMsg.MessagePad)
	}

	unblindedMessage := ServerRoundData{}
	unblindedMessage.IBFVector = *msgs[0].UnsafeObject().OriginalAggregate.IBFVector.Decrypt(allPartialMessages.SchedulingPad)
	unblindedMessage.MessageVector = crypto.Xor(msgs[0].UnsafeObject().OriginalAggregate.MessageVector, allPartialMessages.MessagePad)

	return &unblindedMessage, nil
}

func AggregateClientMessages(round int, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNubmer : round,
	}

	for _, msg := range msgs {
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

		// TODO: initialize use Config instead
		if aggregatedMsg.IBFVector == nil {
			aggregatedMsg.IBFVector = NewIBFVector(uint32(len(rawMsg.IBFVector.Chunks[0])))
			aggregatedMsg.MessageVector = make([]byte, len(rawMsg.MessageVector))
		}

		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, signer)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

func AggregateAggregates(round int, msgs []*Signed[AggregatedClientMessages], authorizedAggregators map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNubmer : round,
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

		// Alternatively recover user messages
		aggregatedMsg.UserPKs = append(aggregatedMsg.UserPKs, rawMsg.UserPKs...)
		aggregatedMsg.IBFVector.UnionInplace(rawMsg.IBFVector)
		crypto.XorInplace(aggregatedMsg.MessageVector, rawMsg.MessageVector)
	}

	return &aggregatedMsg, nil
}

type ClientMessager struct {
	Config           *ZIPNetConfig
	SharedSecrets    map[string]crypto.SharedKey
	Crypto           CryptoProvider
}

func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *Signed[ServerRoundData], previousRoundMessage []byte, currentRoundAuctionData *AuctionData) (*ClientRoundMessage, bool, error) {
	shouldSendMessage, messageIndex := func() (bool, int) {
		if previousRoundOutput == nil || previousRoundOutput.UnsafeObject().RoundNubmer +1 != currentRound {
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

	// TODO: counters blinding
	auctionPad := make([]byte, IBFVectorSize(c.Config.MessageSlots))
	messagePad := make([]byte, c.Config.MessageSize*c.Config.MessageSlots) // TODO: one size for dynamic messages

	if shouldSendMessage {
		crypto.XorInplace(messagePad[messageIndex:messageIndex+len(previousRoundMessage)], previousRoundMessage)
	}

	for _, serverKem := range c.SharedSecrets {
		auctionPrf, messagePrf, err := c.Crypto.KDF(serverKem, uint64(currentRound), []byte{}, len(auctionPad), len(messagePad))
		if err != nil {
			return nil, false, err
		}
		crypto.XorInplace(auctionPad, auctionPrf)
		crypto.XorInplace(messagePad, messagePrf)
	}

	auctionIBF := NewIBFVector(c.Config.MessageSlots)
	auctionIBF.InsertChunk(currentRoundAuctionData.EncodeToChunk())
	auctionIBF.EncryptInplace(auctionPad)

	return &ClientRoundMessage{
		RoundNubmer :currentRound,
		IBFVector : auctionIBF,
		MessageVector : messagePad,
	}, shouldSendMessage, nil
}
