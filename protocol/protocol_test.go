package protocol

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"slices"
	"testing"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/require"
)

// TODO: test packing multiple messages!

func sharedSecret(path string) crypto.SharedKey {
	return crypto.NewSharedKey([]byte(path))
}

func TestSecretSharingClient(t *testing.T) {
	config := &ADCNetConfig{
		AuctionSlots:      10,
		MessageSlots:      3,
		MinServers:        2,
		MessageFieldOrder: crypto.MessageFieldOrder,
	}

	c := &ClientMessager{
		Config:        config,
		SharedSecrets: map[ServerID]crypto.SharedKey{1: sharedSecret("c1s1"), 2: sharedSecret("c1s2"), 3: sharedSecret("c1s3")},
	}

	auctionIBF := blind_auction.NewIBFVector(config.AuctionSlots)
	auctionIBF.InsertChunk((&blind_auction.AuctionData{
		MessageHash: [32]byte{},
		Weight:      10,
		Size:        1,
	}).EncodeToChunk())

	nBytesInFieldElement := (c.Config.MessageFieldOrder.BitLen() - 1) / 8
	require.Equal(t, nBytesInFieldElement, 64) // Finicky setup
	msgEls := EncodeMessageToFieldElements(AuctionResult{ShouldSend: true, MessageStartIndex: 1}, make([]byte, 64*3), []byte{10}, nBytesInFieldElement)
	require.Len(t, msgEls, 3)
	require.Zero(t, msgEls[0].Cmp(big.NewInt(0)), msgEls[0])
	expectedMsgEl := big.NewInt(0).SetBits([]big.Word{0, 0, 0, 0, 0, 0, 0, 0xa00000000000000})
	require.Zero(t, expectedMsgEl.Cmp(msgEls[1]), msgEls[1].Bits())
	require.Zero(t, msgEls[2].Cmp(big.NewInt(0)), msgEls[2])

	roundMessage, err := c.SecretShareMessage(1, msgEls, auctionIBF.EncodeAsFieldElements())
	require.NoError(t, err)
	require.Len(t, roundMessage, 3)

	s1MessageBlindingVector := crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s1")...)}, 1, int32(config.MessageSlots), config.MessageFieldOrder)
	s2MessageBlindingVector := crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s2")...)}, 1, int32(config.MessageSlots), config.MessageFieldOrder)

	s1i0Eval := crypto.FieldSubInplace(new(big.Int).Set(roundMessage[0].MessageVector[0]), s1MessageBlindingVector[0], config.MessageFieldOrder)
	s2i0Eval := crypto.FieldSubInplace(new(big.Int).Set(roundMessage[1].MessageVector[0]), s2MessageBlindingVector[0], config.MessageFieldOrder)

	i0Interpolation := crypto.LagrangeInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, []*big.Int{s1i0Eval, s2i0Eval}, nil, config.MessageFieldOrder)
	require.Zero(t, i0Interpolation.Cmp(big.NewInt(0)), i0Interpolation.String())

	s1i1Eval := crypto.FieldSubInplace(new(big.Int).Set(roundMessage[0].MessageVector[1]), s1MessageBlindingVector[1], config.MessageFieldOrder)
	s2i1Eval := crypto.FieldSubInplace(new(big.Int).Set(roundMessage[1].MessageVector[1]), s2MessageBlindingVector[1], config.MessageFieldOrder)

	require.Zero(t, crypto.LagrangeInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, []*big.Int{s1i1Eval, s2i1Eval}, nil, config.MessageFieldOrder).Cmp(expectedMsgEl))

	// TODO: add a second client!
}

func TestE2E(t *testing.T) {
	config := &ADCNetConfig{
		AuctionSlots:      10,
		MessageSlots:      3,
		MessageFieldOrder: new(big.Int).Set(crypto.MessageFieldOrder),
		MinServers:        2,
	}

	// client1PK, client1SK, _ := crypto.GenerateKeyPair()
	// client2PK, client2SK, _ := crypto.GenerateKeyPair()

	servers := make([]*ServerMessager, 3)
	for s := range servers {
		servers[s] = &ServerMessager{
			Config:        config,
			ServerID:      ServerID(s + 1),
			SharedSecrets: make(map[string]crypto.SharedKey),
		}
	}

	clientKeys := make([]crypto.PrivateKey, 3)
	clientPubkeys := make(map[string]bool)
	clients := make([]*ClientMessager, 3)
	for c := range clients {
		clients[c] = &ClientMessager{
			Config:        config,
			SharedSecrets: make(map[ServerID]crypto.SharedKey),
		}
		var pubkey crypto.PublicKey
		pubkey, clientKeys[c], _ = crypto.GenerateKeyPair()
		clientPubkeys[pubkey.String()] = true

		for s := range servers {
			sp := fmt.Sprintf("c%ds%d", c, s)
			clients[c].SharedSecrets[servers[s].ServerID] = sharedSecret(sp)
			servers[s].SharedSecrets[pubkey.String()] = sharedSecret(sp)
		}
	}

	previousRoundOutput := &RoundBroadcast{
		RoundNumber:   1,
		AuctionVector: blind_auction.NewIBFVector(config.AuctionSlots),
		MessageVector: []byte{},
	}

	msgsData := [][]byte{
		make([]byte, 64-1),
		make([]byte, 64+1),
		make([]byte, 64+2),
	}
	for i := range msgsData {
		rand.Read(msgsData[i])
		previousRoundOutput.AuctionVector.InsertChunk(blind_auction.AuctionDataFromMessage(msgsData[i], 10, (config.MessageFieldOrder.BitLen()-1)/8).EncodeToChunk())
	}

	recoveredChunks, err := previousRoundOutput.AuctionVector.Recover()
	require.NoError(t, err)
	require.Len(t, recoveredChunks, 3)

	for i := range msgsData {
		chunk := blind_auction.AuctionDataFromMessage(msgsData[i], 10, (config.MessageFieldOrder.BitLen()-1)/8).EncodeToChunk()
		require.Contains(t, recoveredChunks, chunk)
	}

	recoveredAuctionData := make([]blind_auction.AuctionData, len(recoveredChunks))
	for i := range recoveredAuctionData {
		recoveredAuctionData[i] = *blind_auction.AuctionDataFromChunk(recoveredChunks[i])
	}
	auctionWinnders := blind_auction.NewAuctionEngine(uint32(config.MessageSlots), 1).RunAuction(recoveredAuctionData)
	require.Len(t, auctionWinnders, 2, recoveredAuctionData)

	clientMsgs := []*Signed[ClientRoundMessage]{}
	talkingClients := []int{}
	for c := range clients {
		rawClientMessages, talking, err := clients[c].PrepareMessage(2, previousRoundOutput, msgsData[c], nil /* ignore the auction for now */)
		require.NoError(t, err)

		if talking {
			talkingClients = append(talkingClients, c)
		}

		require.Len(t, rawClientMessages, 3)
		for s := range rawClientMessages {
			signedClientMessage, _ := NewSigned(clientKeys[c], rawClientMessages[s])
			clientMsgs = append(clientMsgs, signedClientMessage)
		}
	}

	require.Len(t, talkingClients, 2, recoveredChunks)

	agg := &AggregatorMessager{Config: config}
	aggregatedMessages, err := agg.AggregateClientMessages(2, nil, clientMsgs, clientPubkeys)
	require.NoError(t, err)
	require.Len(t, aggregatedMessages, 3) // one message per server
	aggregatedMessagesPerServer := make(map[ServerID]*AggregatedClientMessages, 3)
	for _, msg := range aggregatedMessages {
		aggregatedMessagesPerServer[msg.ServerID] = msg
	}

	partialDecryptionMessages := make([]*ServerPartialDecryptionMessage, len(servers))
	for s := range servers {
		var err error
		partialDecryptionMessages[s], err = servers[s].UnblindAggregate(2, aggregatedMessagesPerServer[servers[s].ServerID])
		require.NoError(t, err)
	}

	roundOutput, err := servers[0].UnblindPartialMessages(partialDecryptionMessages)
	require.NoError(t, err)
	require.NotNil(t, roundOutput)

	foundMsgs := 0
	nBytesInFieldElement := (config.MessageFieldOrder.BitLen() - 1) / 8
	for startingIndex := 0; startingIndex < config.MessageSlots*nBytesInFieldElement; startingIndex += nBytesInFieldElement {
		for i := range msgsData {
			if startingIndex+len(msgsData[i]) <= len(roundOutput.MessageVector) && bytes.Equal(roundOutput.MessageVector[startingIndex:startingIndex+len(msgsData[i])], msgsData[i]) {
				foundMsgs++
			}
		}
	}

	require.Equal(t, 2, foundMsgs, "Msg: %v", roundOutput.MessageVector)

	// TODO: check auction as well
}

func BenchmarkUnblindAggregate(b *testing.B) {
	rs := mrand.New(mrand.NewSource(0))

	fieldOrders := []*big.Int{}
	for _, fBits := range []int{513} {
		fo, _ := rand.Prime(rand.Reader, fBits)
		fieldOrders = append(fieldOrders, fo)
	}
	nClientBenches := []int{100, 1000}
	msgSizeBenches := []int{10, 4000 /* 256kB */, 8 * 4000 /* 2MB */}

	sharedSecrets := make(map[string]crypto.SharedKey)
	userPKs := make([]crypto.PublicKey, slices.Max(nClientBenches))
	msgVector := make([][]*big.Int, len(fieldOrders))

	for fs := range fieldOrders {
		msgVector[fs] = make([]*big.Int, slices.Max(msgSizeBenches))
		for i := range msgVector[fs] {
			msgVector[fs][i] = new(big.Int).Rand(rs, fieldOrders[fs])
		}
	}

	for i := range userPKs {
		pubkey, _, _ := crypto.GenerateKeyPair()
		ss := make([]byte, 64)
		rand.Read(ss)
		sharedSecrets[pubkey.String()] = ss
		userPKs[i] = pubkey
	}

	for _, nClients := range nClientBenches {
		for _, msgVectorSlots := range msgSizeBenches {
			auctionVector := blind_auction.NewIBFVector(uint32(msgVectorSlots)).EncodeAsFieldElements()
			for foi, fieldOrder := range fieldOrders {
				b.Run(fmt.Sprintf("Unblind aggregate clients-%d-msg-%d-field-%d", nClients, msgVectorSlots, fieldOrder.BitLen()), func(b *testing.B) {

					server := &ServerMessager{
						Config: &ADCNetConfig{
							AuctionSlots:      10,
							MessageSlots:      msgVectorSlots,
							MessageFieldOrder: fieldOrder,
							MinServers:        2,
						},
						ServerID:      1,
						SharedSecrets: sharedSecrets,
					}

					aggregate := &AggregatedClientMessages{
						RoundNumber:   1,
						ServerID:      1,
						AllServerIds:  []ServerID{1},
						AuctionVector: auctionVector,
						MessageVector: msgVector[foi][:msgVectorSlots],
						UserPKs:       userPKs[:nClients],
					}

					for b.Loop() {
						_, err := server.UnblindAggregate(1, aggregate)
						require.NoError(b, err)
					}
				})
			}
		}
	}
}

func BenchmarkUnblindMessages(b *testing.B) {
	rs := mrand.New(mrand.NewSource(0))

	fieldOrder, _ := rand.Prime(rand.Reader, 513)
	nClientBenches := []int{100, 1000}
	msgSizeBenches := []int{10, 8 * 4000 /* 2MB */}
	nServerBenches := []int{2, 4, 10}

	sharedSecrets := make(map[string]crypto.SharedKey)
	userPKs := make([]crypto.PublicKey, slices.Max(nClientBenches))
	msgVector := make([][]*big.Int, slices.Max(nServerBenches))

	for si := range msgVector {
		msgVector[si] = make([]*big.Int, slices.Max(msgSizeBenches))
		for i := range msgVector[si] {
			msgVector[si][i] = new(big.Int).Rand(rs, fieldOrder)
		}
	}

	for i := range userPKs {
		pubkey, _, _ := crypto.GenerateKeyPair()
		ss := make([]byte, 64)
		rand.Read(ss)
		sharedSecrets[pubkey.String()] = ss
		userPKs[i] = pubkey
	}

	for _, msgVectorSlots := range msgSizeBenches {
		auctionVector := blind_auction.NewIBFVector(uint32(msgVectorSlots)).EncodeAsFieldElements()
		for _, nServers := range nServerBenches {
			for _, nClients := range nClientBenches {
				b.Run(fmt.Sprintf("Unblind partial messages servers-%d-clients-%d-msg-%d-field-%d", nServers, nClients, msgVectorSlots, fieldOrder.BitLen()), func(b *testing.B) {

					config := &ADCNetConfig{
						AuctionSlots:      10,
						MessageSlots:      msgVectorSlots,
						MessageFieldOrder: fieldOrder,
						MinServers:        uint32(nServers),
					}

					pdm := make([]*ServerPartialDecryptionMessage, nServers)
					for i := range pdm {
						pdm[i] = &ServerPartialDecryptionMessage{
							ServerID:          ServerID(i + 1),
							OriginalAggregate: &AggregatedClientMessages{RoundNumber: 1},
							UserPKs:           userPKs[:nClients],
							AuctionVector:     auctionVector,
							MessageVector:     msgVector[i][:msgVectorSlots],
						}
					}

					server := &ServerMessager{
						Config:        config,
						ServerID:      1,
						SharedSecrets: sharedSecrets,
					}

					for b.Loop() {
						_, err := server.UnblindPartialMessages(pdm)
						require.NoError(b, err)
					}
				})
			}
		}
	}
}
