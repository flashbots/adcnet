package protocol

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

// ServerMessager implements server-side operations for message unblinding.
type ServerMessager struct {
	Config        *ADCNetConfig
	ServerID      ServerID
	SharedSecrets map[string]crypto.SharedKey
}

// ServerSetup creates a ServerMessager by deriving shared secrets with all clients.
func ServerSetup(config *ADCNetConfig, clientPubkeys map[string]*ecdh.PublicKey, serverId ServerID, serverPrivkey *ecdh.PrivateKey) (*ServerMessager, error) {
	sharedSecrets := make(map[string]crypto.SharedKey)
	for signingAddress, pubkey := range clientPubkeys {
		sharedSecret, err := serverPrivkey.ECDH(pubkey)
		if err != nil {
			return nil, err
		}
		sharedSecrets[signingAddress] = sharedSecret
	}
	return &ServerMessager{
		Config:        config,
		ServerID:      serverId,
		SharedSecrets: sharedSecrets,
	}, nil
}

// UnblindPartialMessages reconstructs the final broadcast by combining blinding vectors from all servers.
// Recovers messages by XORing all server blinding vectors with the aggregate.
// Recovers auction data by subtracting all server blinding vectors from the aggregate in the finite field.
func (s *ServerMessager) UnblindPartialMessages(msgs []*ServerPartialDecryptionMessage) (*RoundBroadcast, error) {
	slices.SortFunc(msgs, func(l, r *ServerPartialDecryptionMessage) int {
		return int(l.ServerID) - int(r.ServerID)
	})

	auctionVector := make([]*big.Int, len(msgs[0].AuctionVector))

	sIds := make([]ServerID, len(msgs))
	for i := range sIds {
		sIds[i] = msgs[i].ServerID
	}

	allServerIdsForRound := msgs[0].OriginalAggregate.AllServerIds
	for _, msg := range msgs {
		if !slices.Equal(allServerIdsForRound, msg.OriginalAggregate.AllServerIds) {
			return nil, fmt.Errorf("mismatching round server ids in decryption messages")
		}
	}

	for chunk := range auctionVector {
		auctionVector[chunk] = new(big.Int).Set(msgs[0].OriginalAggregate.AuctionVector[chunk])
		for i := range msgs {
			crypto.FieldSubInplace(auctionVector[chunk], msgs[i].AuctionVector[chunk], crypto.AuctionFieldOrder)
		}
	}

	messageVector := make([]byte, s.Config.MessageLength)
	copy(messageVector, msgs[0].OriginalAggregate.MessageVector)
	for i := range msgs {
		crypto.XorInplace(messageVector, msgs[i].MessageVector)
	}

	unblindedMessage := RoundBroadcast{
		RoundNumber:   msgs[0].OriginalAggregate.RoundNumber,
		AuctionVector: blind_auction.NewIBFVector(s.Config.AuctionSlots).DecodeFromElements(auctionVector),
		MessageVector: messageVector,
	}

	return &unblindedMessage, nil
}

// UnblindAggregate computes this server's blinding vector contribution.
// Derives XOR blinding for messages and field-element blinding for auction data
// from shared secrets with each client in the aggregate.
func (s *ServerMessager) UnblindAggregate(currentRound int, aggregate *AggregatedClientMessages) (*ServerPartialDecryptionMessage, error) {
	if aggregate.RoundNumber != currentRound {
		return nil, fmt.Errorf("message for incorrect round %d, expected %d", aggregate.RoundNumber, currentRound)
	}

	if !slices.Contains(aggregate.AllServerIds, s.ServerID) {
		return nil, fmt.Errorf("message for servers %v, expected %d", aggregate.AllServerIds, s.ServerID)
	}

	auctionSharedSecrets := make([]crypto.SharedKey, len(aggregate.UserPKs))
	msgSharedSecrets := make([]crypto.SharedKey, len(aggregate.UserPKs))
	for i, userPk := range aggregate.UserPKs {
		sharedKey, ok := s.SharedSecrets[userPk.String()]
		if !ok {
			return nil, fmt.Errorf("no shared key with user %x", userPk.Bytes())
		}
		auctionSharedSecrets[i] = append([]byte{0}, sharedKey...)
		msgSharedSecrets[i] = append([]byte{1}, sharedKey...)
	}

	nRoutines := min(10, len(msgSharedSecrets))
	batchSize := (len(msgSharedSecrets) + nRoutines - 1) / nRoutines

	mbvc := make(chan []byte, nRoutines)
	abvc := make(chan []*big.Int, nRoutines)
	nAuctionEls := len(aggregate.AuctionVector)
	for i := 0; i < nRoutines; i++ {
		go func(i int) {
			mbvc <- crypto.DeriveXorBlindingVector(msgSharedSecrets[i*batchSize:min(i*batchSize+batchSize, len(msgSharedSecrets))], uint32(currentRound), int32(s.Config.MessageLength))
			abvc <- crypto.DeriveBlindingVector(auctionSharedSecrets[i*batchSize:min(i*batchSize+batchSize, len(auctionSharedSecrets))], uint32(currentRound), int32(nAuctionEls), crypto.AuctionFieldOrder)
		}(i)
	}

	messageBlindingVector := <-mbvc
	for i := 1; i < nRoutines; i++ {
		crypto.XorInplace(messageBlindingVector, <-mbvc)
	}

	auctionBlindingVector := <-abvc
	for i := 1; i < nRoutines; i++ {
		for j, el := range <-abvc {
			crypto.FieldAddInplace(auctionBlindingVector[j], el, crypto.AuctionFieldOrder)
		}
	}

	userPKs := make([]crypto.PublicKey, len(aggregate.UserPKs))
	for i := range userPKs {
		copy(userPKs[i], aggregate.UserPKs[i])
	}

	return &ServerPartialDecryptionMessage{
		ServerID:          s.ServerID,
		OriginalAggregate: aggregate,
		UserPKs:           userPKs,
		AuctionVector:     auctionBlindingVector,
		MessageVector:     messageBlindingVector,
	}, nil
}

// AggregatorMessager implements message aggregation operations.
type AggregatorMessager struct {
	Config *ADCNetConfig
}

// AggregateClientMessages combines client messages into a single aggregate.
// XORs message vectors and adds auction vectors in the finite field.
func (a *AggregatorMessager) AggregateClientMessages(round int, previousAggregate *AggregatedClientMessages, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) (*AggregatedClientMessages, error) {
	aggregatedMsg := &AggregatedClientMessages{}
	if previousAggregate != nil {
		aggregatedMsg.UnionInplace(previousAggregate)
	}

	for _, msg := range msgs {
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

		_, err = aggregatedMsg.UnionInplace(&AggregatedClientMessages{
			RoundNumber:   rawMsg.RoundNumber,
			AllServerIds:  rawMsg.AllServerIds,
			AuctionVector: rawMsg.AuctionVector,
			MessageVector: rawMsg.MessageVector,
			UserPKs:       []crypto.PublicKey{signer},
		})
		if err != nil {
			return nil, fmt.Errorf("could not union client messages: %w", err)
		}
	}

	return aggregatedMsg, nil
}

// AggregateAggregates combines multiple aggregated messages into one.
func (a *AggregatorMessager) AggregateAggregates(round int, msgs []*AggregatedClientMessages) (*AggregatedClientMessages, error) {
	aggregatedMsg := &AggregatedClientMessages{}

	for _, msg := range msgs {
		if msg.RoundNumber != round {
			return nil, fmt.Errorf("aggregate message for round %d, expected %d", msg.RoundNumber, round)
		}

		_, err := aggregatedMsg.UnionInplace(msg)
		if err != nil {
			return nil, fmt.Errorf("could not union aggregates: %w", err)
		}
	}

	return aggregatedMsg, nil
}

// ClientMessager implements client-side message preparation with XOR blinding.
type ClientMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[ServerID]crypto.SharedKey
}

// ClientSetup creates a ClientMessager by deriving shared secrets with all servers.
func ClientSetup(config *ADCNetConfig, serverPubkeys map[ServerID]*ecdh.PublicKey, clientPrivkey *ecdh.PrivateKey) (*ClientMessager, error) {
	sharedSecrets := make(map[ServerID]crypto.SharedKey)
	for sId, pubkey := range serverPubkeys {
		sharedSecret, err := clientPrivkey.ECDH(pubkey)
		if err != nil {
			return nil, err
		}
		sharedSecrets[sId] = sharedSecret
	}
	return &ClientMessager{
		Config:        config,
		SharedSecrets: sharedSecrets,
	}, nil
}

// ProcessPreviousAuction determines if this client won a slot in the auction.
// Recovers auction entries from the IBF and checks for matching message hash.
func (c *ClientMessager) ProcessPreviousAuction(auctionIBF *blind_auction.IBFVector, previousRoundMessage []byte) AuctionResult {
	chunks, err := auctionIBF.Recover()
	if err != nil {
		return AuctionResult{}
	}

	bids := make([]blind_auction.AuctionData, 0, len(chunks))
	for _, chunk := range chunks {
		bids = append(bids, *blind_auction.AuctionDataFromChunk(chunk))
	}

	auctionEngine := blind_auction.NewAuctionEngine(uint32(c.Config.MessageLength), 1)
	winners := auctionEngine.RunAuction(bids)

	ourHash := sha256.Sum256(previousRoundMessage)
	for _, winner := range winners {
		if winner.Bid.MessageHash == ourHash {
			return AuctionResult{true, int(winner.SlotIdx)}
		}
	}
	return AuctionResult{false, 0}
}

// PrepareMessage creates a blinded message with auction data for the current round.
// Returns the blinded message and whether the client should send based on previous auction results.
func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *RoundBroadcast, previousRoundMessage []byte, currentRoundAuctionData *blind_auction.AuctionData) (*ClientRoundMessage, bool, error) {
	var previousAuctionResult AuctionResult
	if previousRoundOutput != nil && previousRoundOutput.RoundNumber+1 == currentRound {
		previousAuctionResult = c.ProcessPreviousAuction(previousRoundOutput.AuctionVector, previousRoundMessage)
	} else {
		previousAuctionResult = AuctionResult{false, 0}
	}

	auctionIBF := blind_auction.NewIBFVector(c.Config.AuctionSlots)
	if currentRoundAuctionData != nil {
		auctionIBF.InsertChunk(currentRoundAuctionData.EncodeToChunk())
	}
	auctionElements := auctionIBF.EncodeAsFieldElements()

	messageVector := EncodeMessageToFieldElements(previousAuctionResult, make([]byte, c.Config.MessageLength), previousRoundMessage)
	clientMessage, err := c.BlindClientMessage(currentRound, messageVector, auctionElements)

	return clientMessage, previousAuctionResult.ShouldSend, err
}

// BlindClientMessage applies XOR blinding to message and field-element blinding to auction data.
// Each server's blinding is derived deterministically from the shared secret and round number.
func (c *ClientMessager) BlindClientMessage(currentRound int, messageVector []byte, auctionElements []*big.Int) (*ClientRoundMessage, error) {
	serverIDs := make([]ServerID, 0, len(c.SharedSecrets))
	for sId := range c.SharedSecrets {
		serverIDs = append(serverIDs, sId)
	}
	slices.Sort(serverIDs)

	blindedAuctionVector := make([]*big.Int, int32(len(auctionElements)))
	for i := range blindedAuctionVector {
		blindedAuctionVector[i] = new(big.Int).Set(auctionElements[i])
	}
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		auctionBlind := crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{0}, sharedSecret...)}, uint32(currentRound), int32(len(auctionElements)), crypto.AuctionFieldOrder)
		for j := 0; j < len(blindedAuctionVector); j++ {
			crypto.FieldAddInplace(blindedAuctionVector[j], auctionBlind[j], crypto.AuctionFieldOrder)
		}
	}

	blindedMessageVector := make([]byte, int32(len(messageVector)))
	copy(blindedMessageVector, messageVector)
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		messageBlind := crypto.DeriveXorBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret...)}, uint32(currentRound), int32(c.Config.MessageLength))
		crypto.XorInplace(blindedMessageVector, messageBlind)
	}

	return &ClientRoundMessage{
		AllServerIds:  serverIDs,
		RoundNumber:   currentRound,
		AuctionVector: blindedAuctionVector,
		MessageVector: blindedMessageVector,
	}, nil
}

// EncodeMessageToFieldElements places the message at the auction-determined offset if the client won a slot.
func EncodeMessageToFieldElements(previousAuctionResult AuctionResult, messageBytes []byte, messageToEncode []byte) []byte {
	if previousAuctionResult.ShouldSend {
		copy(messageBytes[previousAuctionResult.MessageStartIndex:], messageToEncode)
	}

	return messageBytes
}

// DecodeMessageFromFieldElements converts field elements back to raw bytes.
func DecodeMessageFromFieldElements(msgEls []*big.Int, nBytesInElement int) []byte {
	msgBytes := make([]byte, len(msgEls)*nBytesInElement)
	for i, el := range msgEls {
		if el.Sign() == -1 || el.BitLen() > nBytesInElement*8 {
			for j := i * nBytesInElement; j < (i+1)*nBytesInElement; j++ {
				msgBytes[j] = 0
			}
			continue
		}
		el.FillBytes(msgBytes[i*nBytesInElement : (i+1)*nBytesInElement])
	}

	return msgBytes
}
