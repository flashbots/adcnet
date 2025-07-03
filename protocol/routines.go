package protocol

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"slices"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
)

// ServerMessager implements server-side operations for threshold decryption.
type ServerMessager struct {
	Config        *ADCNetConfig
	ServerID      int32
	SharedSecrets map[string]crypto.SharedKey
}

// UnblindPartialMessages reconstructs the final broadcast by combining partial decryptions.
// Uses polynomial interpolation at x=0 to recover the original messages and auction data.
func (s *ServerMessager) UnblindPartialMessages(msgs []*ServerPartialDecryptionMessage) (*ServerRoundData, error) {
	leaderUnblindIdx := slices.IndexFunc(msgs, func(msg *ServerPartialDecryptionMessage) bool { return msg.ServerID == s.ServerID })
	leaderUnblind := msgs[leaderUnblindIdx]

	xs := []*big.Int{}
	for i := 0; i < int(s.Config.MinServers); i++ {
		xs = append(xs, big.NewInt(int64(msgs[i].ServerID)))
	}
	evals := make([]*big.Int, int(s.Config.MinServers))
	for chunk := range leaderUnblind.AuctionVector {
		for i := 0; i < int(s.Config.MinServers); i++ {
			evals[i] = msgs[i].AuctionVector[chunk]
		}
		leaderUnblind.AuctionVector[chunk] = crypto.NevilleInterpolation(xs, evals, big.NewInt(0), crypto.AuctionFieldOrder)
	}
	for chunk := range leaderUnblind.MessageVector {
		for i := 0; i < int(s.Config.MinServers); i++ {
			evals[i] = msgs[i].MessageVector[chunk]
		}
		leaderUnblind.MessageVector[chunk] = crypto.NevilleInterpolation(xs, evals, big.NewInt(0), s.Config.MessageFieldOrder)
	}

	nBytesInFieldElement := (s.Config.MessageFieldOrder.BitLen() - 1) / 8
	msgBytes := make([]byte, int(s.Config.MessageSize)*nBytesInFieldElement)
	for i, el := range leaderUnblind.MessageVector {
		el.Mod(el, s.Config.MessageFieldOrder)
		copy(msgBytes[i*nBytesInFieldElement:(i+1)*nBytesInFieldElement], el.Bytes())
		// el.FillBytes(msgBytes[i*nBytesInFieldElement:(i+1)*nBytesInFieldElement])
	}

	unblindedMessage := ServerRoundData{
		RoundNumber:   leaderUnblind.OriginalAggregate.RoundNumber,
		AuctionVector: new(blind_auction.IBFVector).DecodeFromElements(leaderUnblind.AuctionVector),
		MessageVector: msgBytes,
	}

	return &unblindedMessage, nil
}

// UnblindAggregate creates a partial decryption by removing this server's blinding factors.
// Derives one-time pads from shared secrets with each client and subtracts them from the aggregate.
func (s *ServerMessager) UnblindAggregate(currentRound int, aggregate *AggregatedClientMessages, previousRoundAuction *blind_auction.IBFVector) (*ServerPartialDecryptionMessage, error) {
	// TODO: consider recovering and checking user signatures rather than aggregator ones
	// TODO: aggregate user signatures (BLS or equivalent)

	if aggregate.RoundNumber != currentRound {
		return nil, fmt.Errorf("message for incorrect round %d, expected %d", aggregate.RoundNumber, currentRound)
	}

	if aggregate.ServerID != s.ServerID {
		return nil, fmt.Errorf("message for incorrect server %d, expected %d", aggregate.ServerID, s.ServerID)
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

	messageBlindingVector := crypto.DeriveBlindingVector(msgSharedSecrets, uint32(currentRound), int32(s.Config.MessageSize), s.Config.MessageFieldOrder)
	nEls := 2 * blind_auction.IBFVectorSize(s.Config.AuctionSlots)
	auctionBlindingVector := crypto.DeriveBlindingVector(auctionSharedSecrets, uint32(currentRound), int32(nEls), crypto.AuctionFieldOrder)

	for i := range aggregate.MessageVector {
		crypto.FieldSubInplace(aggregate.MessageVector[i], messageBlindingVector[i], s.Config.MessageFieldOrder)
	}

	for i := range aggregate.AuctionVector {
		crypto.FieldSubInplace(aggregate.AuctionVector[i], auctionBlindingVector[i], crypto.AuctionFieldOrder)
	}

	return &ServerPartialDecryptionMessage{
		ServerID:          s.ServerID,
		OriginalAggregate: aggregate,
		UserPKs:           aggregate.UserPKs,
		AuctionVector:     aggregate.AuctionVector,
		MessageVector:     aggregate.MessageVector,
	}, nil
}

// AggregatorMessager implements message aggregation operations.
type AggregatorMessager struct {
	Config *ADCNetConfig
}

// AggregateClientMessages combines client messages by server ID.
// Verifies signatures and sums message/auction vectors in the finite field.
func (a *AggregatorMessager) AggregateClientMessages(round int, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) ([]*AggregatedClientMessages, error) {
	aggregatedMsgs := make(map[int32]*AggregatedClientMessages)

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

		if _, ok := aggregatedMsgs[rawMsg.ServerID]; !ok {
			aggregatedMsgs[rawMsg.ServerID] = &AggregatedClientMessages{
				RoundNumber: round,
				ServerID:    rawMsg.ServerID,
			}
		}

		// TODO: aggregate user signatures (BLS or equivalent)
		aggregatedMsgs[rawMsg.ServerID].UnionInplace(&AggregatedClientMessages{
			RoundNumber:   rawMsg.RoundNumber,
			ServerID:      rawMsg.ServerID,
			AuctionVector: rawMsg.AuctionVector,
			MessageVector: rawMsg.MessageVector,
			UserPKs:       []crypto.PublicKey{signer},
		})
	}

	res := []*AggregatedClientMessages{}
	for _, aggMsg := range aggregatedMsgs {
		res = append(res, aggMsg)
	}
	return res, nil
}

// AggregateAggregates combines multiple aggregated messages into one.
// Used for hierarchical aggregation to reduce bandwidth.
func (a *AggregatorMessager) AggregateAggregates(round int, msgs []*AggregatedClientMessages) (*AggregatedClientMessages, error) {
	aggregatedMsg := AggregatedClientMessages{
		RoundNumber: round,
	}

	for _, msg := range msgs {
		if msg.RoundNumber != round {
			return nil, fmt.Errorf("client message for round %d, expected %d", msg.RoundNumber, round)
		}
		aggregatedMsg.UnionInplace(msg)
	}

	return &aggregatedMsg, nil
}

// ClientMessager implements client-side message preparation with secret sharing.
type ClientMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[int32]crypto.SharedKey
}

// ProcessPreviousAuction determines if this client won a slot in the auction.
// Recovers auction entries from the IBF and checks for matching message hash.
func (c *ClientMessager) ProcessPreviousAuction(auctionIBF *blind_auction.IBFVector, previousRoundMessage []byte) AuctionResult {
	chunks, err := auctionIBF.Recover()
	if err != nil {
		// We might want to handle this — on the other hand, the only way to handle is to panic really
		return AuctionResult{}
	}

	bids := make([]blind_auction.AuctionData, 0, len(chunks))
	for _, chunk := range chunks {
		bids = append(bids, *blind_auction.AuctionDataFromChunk(chunk))
	}

	auctionEngine := blind_auction.NewAuctionEngine(c.Config.MessageSize*64, blind_auction.IBFChunkSize)
	// Run auction to determine winners
	winners := auctionEngine.RunAuction(bids)

	// Check if we won
	ourHash := sha256.Sum256(previousRoundMessage)
	for _, winner := range winners {
		if winner.Bid.MessageHash == ourHash {
			return AuctionResult{true, int(winner.SlotIdx)}
		}
	}
	return AuctionResult{false, 0}
}

// PrepareMessage creates secret-shared messages with auction data for the current round.
// Returns shares for each server and whether the client should send based on auction results.
func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *ServerRoundData, previousRoundMessage []byte, currentRoundAuctionData *blind_auction.AuctionData) ([]*ClientRoundMessage, bool, error) {
	// Note that messages must be salted (random prefix).
	var previousAuctionResult AuctionResult
	if previousRoundOutput != nil && previousRoundOutput.RoundNumber+1 == currentRound {
		previousAuctionResult = c.ProcessPreviousAuction(previousRoundOutput.AuctionVector, previousRoundMessage)
	} else {
		previousAuctionResult = AuctionResult{false, 0}
	}

	/*
		var previousRoundAuction *blind_auction.IBFVector = nil
		if previousRoundOutput != nil {
			// TODO: we might want to verify
			previousRoundAuction = previousRoundOutput.AuctionVector
		}
	*/

	auctionIBF := blind_auction.NewIBFVector(c.Config.AuctionSlots)
	if currentRoundAuctionData != nil {
		auctionIBF.InsertChunk(currentRoundAuctionData.EncodeToChunk())
	}
	auctionElements := auctionIBF.EncodeAsFieldElements()
	messageElements := EncodeMessageToFieldElements(previousAuctionResult, make([]byte, c.Config.MessageSize*64), previousRoundMessage)

	messageStreams, err := c.SecretShareMessage(currentRound, messageElements, auctionElements)
	return messageStreams, previousAuctionResult.ShouldSend, err
}

// SecretShareMessage creates polynomial shares of message and auction data.
// Uses random polynomials with the secret as the constant term, evaluates at each server ID.
func (c *ClientMessager) SecretShareMessage(currentRound int, messageElements []*big.Int, auctionElements []*big.Int) ([]*ClientRoundMessage, error) {
	// Create sorted list of server IDs for deterministic ordering
	serverIDs := make([]int32, 0, len(c.SharedSecrets))
	for sId := range c.SharedSecrets {
		serverIDs = append(serverIDs, sId)
	}
	slices.Sort(serverIDs) // Ensure deterministic order

	auctionVectors := make(map[int32][]*big.Int, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		nEls := 2 * blind_auction.IBFVectorSize(c.Config.AuctionSlots)
		auctionVectors[sId] = crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{0}, sharedSecret...)}, uint32(currentRound), int32(nEls), crypto.AuctionFieldOrder)
	}

	messageVectors := make(map[int32][]*big.Int, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		messageVectors[sId] = crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret...)}, uint32(currentRound), int32(c.Config.MessageSize), c.Config.MessageFieldOrder)
	}

	// Use sorted serverIDs to create serverXs
	serverXs := make([]*big.Int, len(serverIDs))
	for i, sId := range serverIDs {
		if sId == 0 {
			panic("server id must not be 0")
		}
		serverXs[i] = big.NewInt(int64(sId))
	}

	for i := 0; i < int(c.Config.MessageSize); i++ {
		mEvals := crypto.RandomPolynomialEvals(int(c.Config.MinServers)-1, serverXs, messageElements[i], c.Config.MessageFieldOrder)
		for j := 0; j < len(messageVectors); j++ {
			msgVector := messageVectors[int32(serverXs[j].Int64())]
			crypto.FieldAddInplace(msgVector[i], mEvals[j], c.Config.MessageFieldOrder)
		}
	}
	for i, auctionEl := range auctionElements {
		elEvals := crypto.RandomPolynomialEvals(int(c.Config.MinServers)-1, serverXs, auctionEl, crypto.AuctionFieldOrder)
		for j := 0; j < len(auctionVectors); j++ {
			auctionVector := auctionVectors[int32(serverXs[j].Int64())]
			crypto.FieldAddInplace(auctionVector[i], elEvals[j], crypto.AuctionFieldOrder)
		}
	}

	// Build response in sorted order
	resp := make([]*ClientRoundMessage, 0, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		resp = append(resp, &ClientRoundMessage{
			ServerID:      sId,
			RoundNumber:   currentRound,
			AuctionVector: auctionVectors[sId],
			MessageVector: messageVectors[sId],
		})
	}

	return resp, nil
}

// EncodeMessageToFieldElements converts a message to field elements.
// Places the message at the auction-determined offset if the client won a slot.
func EncodeMessageToFieldElements(previousAuctionResult AuctionResult, messageBytes []byte, messageToEncode []byte) []*big.Int {
	if previousAuctionResult.ShouldSend {
		for i := range messageToEncode {
			messageBytes[i+previousAuctionResult.MessageStartIndex] = messageToEncode[i]
		}
	}

	messageElements := make([]*big.Int, len(messageBytes)/64)
	for i := 0; i < len(messageBytes)/64; i++ {
		messageElements[i] = new(big.Int).SetBytes(messageBytes[i*64 : (i+1)*64])
	}

	return messageElements
}
