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

// ServerMessager implements server-side operations for threshold decryption.
type ServerMessager struct {
	Config        *ADCNetConfig
	ServerID      ServerID // Derived from the public ECDH key
	SharedSecrets map[string]crypto.SharedKey
}

// Note: clients have two keys, a signing key and a shared secret exchange key. Shared secrets are indexed by the public part of the signing key
// Maybe we can use the same key
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

// UnblindPartialMessages reconstructs the final broadcast by combining partial decryptions.
// Uses polynomial interpolation at x=0 to recover the original messages and auction data.
func (s *ServerMessager) UnblindPartialMessages(msgs []*ServerPartialDecryptionMessage) (*RoundBroadcast, error) {
	slices.SortFunc(msgs, func(l, r *ServerPartialDecryptionMessage) int {
		return int(l.ServerID) - int(r.ServerID)
	})

	auctionVector := make([]*big.Int, len(msgs[0].AuctionVector))
	msgsVector := make([]*big.Int, len(msgs[0].MessageVector))

	sIds := make([]ServerID, s.Config.MinServers)
	for i := range sIds {
		sIds[i] = msgs[i].ServerID
	}

	allServerIdsForRound := msgs[0].OriginalAggregate.AllServerIds
	for _, msg := range msgs {
		if !slices.Equal(allServerIdsForRound, msg.OriginalAggregate.AllServerIds) {
			return nil, fmt.Errorf("mismatching round server ids in decryption messages")
		}
	}

	xs := crypto.ServerIDsToXEvals(allServerIdsForRound, sIds)
	auctionCoeffs := crypto.LagrangeCoeffs(xs, crypto.AuctionFieldOrder)
	messageCoeffs := crypto.LagrangeCoeffs(xs, s.Config.MessageFieldOrder)
	evals := make([]*big.Int, int(s.Config.MinServers))
	for chunk := range auctionVector {
		for i := 0; i < int(s.Config.MinServers); i++ {
			evals[i] = msgs[i].AuctionVector[chunk]
		}
		auctionVector[chunk] = crypto.LagrangeInterpolation(xs, evals, auctionCoeffs, crypto.AuctionFieldOrder)
	}

	for chunk := range msgsVector {
		for i := 0; i < int(s.Config.MinServers); i++ {
			evals[i] = msgs[i].MessageVector[chunk]
		}
		msgsVector[chunk] = crypto.LagrangeInterpolation(xs, evals, messageCoeffs, s.Config.MessageFieldOrder)
	}

	nBytesInFieldElement := (s.Config.MessageFieldOrder.BitLen() - 1) / 8
	unblindedMessage := RoundBroadcast{
		RoundNumber:   msgs[0].OriginalAggregate.RoundNumber,
		AuctionVector: blind_auction.NewIBFVector(s.Config.AuctionSlots).DecodeFromElements(auctionVector),
		MessageVector: DecodeMessageFromFieldElements(msgsVector, nBytesInFieldElement),
	}

	return &unblindedMessage, nil
}

// UnblindAggregate creates a partial decryption by removing this server's blinding factors.
// Derives one-time pads from shared secrets with each client and subtracts them from the aggregate.
func (s *ServerMessager) UnblindAggregate(currentRound int, aggregate *AggregatedClientMessages) (*ServerPartialDecryptionMessage, error) {
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

	// Parallelization setup is somewhat finicky. Optimize for specific workload.
	nRoutines := min(10, len(msgSharedSecrets) /* for tests */)
	batchSize := (len(msgSharedSecrets) + nRoutines - 1) / nRoutines

	mbvc := make(chan []*big.Int, nRoutines)
	abvc := make(chan []*big.Int, nRoutines)
	nAuctionEls := len(aggregate.AuctionVector)
	for i := 0; i < nRoutines; i++ {
		go func(i int) {
			mbvc <- crypto.DeriveBlindingVector(msgSharedSecrets[i*batchSize:min(i*batchSize+batchSize, len(msgSharedSecrets))], uint32(currentRound), int32(s.Config.MessageSlots), s.Config.MessageFieldOrder)
			abvc <- crypto.DeriveBlindingVector(auctionSharedSecrets[i*batchSize:min(i*batchSize+batchSize, len(auctionSharedSecrets))], uint32(currentRound), int32(nAuctionEls), crypto.AuctionFieldOrder)
		}(i)
	}

	for i := 0; i < nRoutines; i++ {
		messageBlindingVector := <-mbvc
		for j, el := range messageBlindingVector {
			crypto.FieldSubInplace(aggregate.MessageVector[j], el, s.Config.MessageFieldOrder)
		}
	}

	for i := 0; i < nRoutines; i++ {
		auctionBlindingVector := <-abvc
		for j, el := range auctionBlindingVector {
			crypto.FieldSubInplace(aggregate.AuctionVector[j], el, crypto.AuctionFieldOrder)
		}
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
func (a *AggregatorMessager) AggregateClientMessages(round int, previousAggregate []*AggregatedClientMessages, msgs []*Signed[ClientRoundMessage], authorizedClients map[string]bool) ([]*AggregatedClientMessages, error) {
	aggregatedMsgs := make(map[ServerID]*AggregatedClientMessages)
	for _, agg := range previousAggregate {
		aggregatedMsgs[agg.ServerID] = agg
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

		if _, ok := aggregatedMsgs[rawMsg.ServerID]; !ok {
			aggregatedMsgs[rawMsg.ServerID] = &AggregatedClientMessages{
				RoundNumber:  round,
				ServerID:     rawMsg.ServerID,
				AllServerIds: rawMsg.AllServerIds,
			}
		}

		// TODO: aggregate user signatures (BLS or equivalent)
		_, err = aggregatedMsgs[rawMsg.ServerID].UnionInplace(&AggregatedClientMessages{
			RoundNumber:   rawMsg.RoundNumber,
			ServerID:      rawMsg.ServerID,
			AllServerIds:  rawMsg.AllServerIds,
			AuctionVector: rawMsg.AuctionVector,
			MessageVector: rawMsg.MessageVector,
			UserPKs:       []crypto.PublicKey{signer},
		}, a.Config.MessageFieldOrder)
		if err != nil {
			return nil, fmt.Errorf("could not union client messages: %w", err)
		}
	}

	res := []*AggregatedClientMessages{}
	for _, aggMsg := range aggregatedMsgs {
		res = append(res, aggMsg)
	}
	return res, nil
}

// AggregateAggregates combines multiple aggregated messages into one.
// Used for hierarchical aggregation to reduce bandwidth.
func (a *AggregatorMessager) AggregateAggregates(round int, msgs []*AggregatedClientMessages) ([]*AggregatedClientMessages, error) {
	aggregatedMsgs := make(map[ServerID]*AggregatedClientMessages)
	for _, msg := range msgs {
		if msg.RoundNumber != round {
			return nil, fmt.Errorf("aggregate message for round %d, expected %d", msg.RoundNumber, round)
		}

		currentAggregate, found := aggregatedMsgs[msg.ServerID]
		if !found {
			currentAggregate = &AggregatedClientMessages{
				RoundNumber:  round,
				ServerID:     msg.ServerID,
				AllServerIds: msg.AllServerIds,
			}
			aggregatedMsgs[msg.ServerID] = currentAggregate
		}
		_, err := currentAggregate.UnionInplace(msg, a.Config.MessageFieldOrder)
		if err != nil {
			return nil, fmt.Errorf("could not union aggregates: %w", err)
		}
	}

	res := make([]*AggregatedClientMessages, 0, len(aggregatedMsgs))
	for _, msg := range aggregatedMsgs {
		res = append(res, msg)
	}

	return res, nil
}

// ClientMessager implements client-side message preparation with secret sharing.
type ClientMessager struct {
	Config        *ADCNetConfig
	SharedSecrets map[ServerID]crypto.SharedKey
}

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

	auctionEngine := blind_auction.NewAuctionEngine(uint32(c.Config.MessageSlots), 1)
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
func (c *ClientMessager) PrepareMessage(currentRound int, previousRoundOutput *RoundBroadcast, previousRoundMessage []byte, currentRoundAuctionData *blind_auction.AuctionData) ([]*ClientRoundMessage, bool, error) {
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

	nBytesInFieldElement := (c.Config.MessageFieldOrder.BitLen() - 1) / 8
	messageElements := EncodeMessageToFieldElements(previousAuctionResult, make([]byte, c.Config.MessageSlots*nBytesInFieldElement), previousRoundMessage, nBytesInFieldElement)

	messageStreams, err := c.SecretShareMessage(currentRound, messageElements, auctionElements)
	return messageStreams, previousAuctionResult.ShouldSend, err
}

// SecretShareMessage creates polynomial shares of message and auction data.
// Uses random polynomials with the secret as the constant term, evaluates at each server ID.
func (c *ClientMessager) SecretShareMessage(currentRound int, messageElements []*big.Int, auctionElements []*big.Int) ([]*ClientRoundMessage, error) {
	// Create sorted list of server IDs for deterministic ordering
	serverIDs := make([]ServerID, 0, len(c.SharedSecrets))
	for sId := range c.SharedSecrets {
		serverIDs = append(serverIDs, sId)
	}
	slices.Sort(serverIDs) // Ensure deterministic order

	// Note: we prepare the blinding vector before secret sharing the messages. The order doesn't matter since it's just addition, but we avoid a round of allocation and initialization this way.

	auctionVectors := make(map[ServerID][]*big.Int, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		auctionVectors[sId] = crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{0}, sharedSecret...)}, uint32(currentRound), int32(len(auctionElements)), crypto.AuctionFieldOrder)
	}

	messageVectors := make(map[ServerID][]*big.Int, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		sharedSecret := c.SharedSecrets[sId]
		messageVectors[sId] = crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret...)}, uint32(currentRound), int32(len(messageElements)), c.Config.MessageFieldOrder)
	}

	serverXs := crypto.ServerIDsToXEvals(serverIDs, serverIDs)
	for i, msgEl := range messageElements {
		mEvals := crypto.RandomPolynomialEvals(int(c.Config.MinServers)-1, serverXs, msgEl, c.Config.MessageFieldOrder)
		for j := 0; j < len(messageVectors); j++ {
			msgVector := messageVectors[ServerID(serverIDs[j])]
			crypto.FieldAddInplace(msgVector[i], mEvals[j], c.Config.MessageFieldOrder)
		}
	}
	for i, auctionEl := range auctionElements {
		elEvals := crypto.RandomPolynomialEvals(int(c.Config.MinServers)-1, serverXs, auctionEl, crypto.AuctionFieldOrder)
		for j := 0; j < len(auctionVectors); j++ {
			auctionVector := auctionVectors[ServerID(serverIDs[j])]
			crypto.FieldAddInplace(auctionVector[i], elEvals[j], crypto.AuctionFieldOrder)
		}
	}

	// Build response in sorted order
	resp := make([]*ClientRoundMessage, 0, len(c.SharedSecrets))
	for _, sId := range serverIDs {
		resp = append(resp, &ClientRoundMessage{
			ServerID:      sId,
			AllServerIds:  serverIDs,
			RoundNumber:   currentRound,
			AuctionVector: auctionVectors[sId],
			MessageVector: messageVectors[sId],
		})
	}

	return resp, nil
}

// EncodeMessageToFieldElements converts a message to field elements.
// Places the message at the auction-determined offset if the client won a slot.
func EncodeMessageToFieldElements(previousAuctionResult AuctionResult, messageBytes []byte, messageToEncode []byte, nBytesInElement int) []*big.Int {
	if previousAuctionResult.ShouldSend {
		for i := range messageToEncode {
			messageBytes[i+(previousAuctionResult.MessageStartIndex*nBytesInElement)] = messageToEncode[i]
		}
	}

	messageElements := make([]*big.Int, len(messageBytes)/nBytesInElement)
	for i := 0; i < len(messageBytes)/nBytesInElement; i++ {
		messageElements[i] = new(big.Int).SetBytes(messageBytes[i*nBytesInElement : (i+1)*nBytesInElement])
	}

	return messageElements
}

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
