package protocol

import (
	"bytes"
	"crypto/rand"
	"fmt"
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

func TestBlindingClient(t *testing.T) {
	config := &ADCNetConfig{
		AuctionSlots:  10,
		MessageLength: 20,
	}

	c := &ClientMessager{
		Config:        config,
		SharedSecrets: map[ServerID]crypto.SharedKey{1: sharedSecret("c1s1"), 2: sharedSecret("c1s2")},
	}

	auctionIBF := blind_auction.NewIBFVector(config.AuctionSlots)
	auctionIBF.InsertChunk((&blind_auction.AuctionData{
		MessageHash: [32]byte{},
		Weight:      10,
		Size:        8,
	}).EncodeToChunk())

	msgEls := make([]byte, 20)
	copy(msgEls[0:], []byte{10})
	require.Len(t, msgEls, 20)
	expectedMsg := make([]byte, 20)
	expectedMsg[0] = 0xa
	require.Equal(t, expectedMsg, msgEls)

	roundMessage, err := c.BlindClientMessage(1, msgEls, auctionIBF.EncodeAsFieldElements())
	require.NoError(t, err)
	require.NotNil(t, roundMessage)

	s1MessageBlindingVector := crypto.DeriveXorBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s1")...)}, 1, config.MessageLength)
	s2MessageBlindingVector := crypto.DeriveXorBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s2")...)}, 1, config.MessageLength)

	sEval := crypto.XorInplace(s1MessageBlindingVector, s2MessageBlindingVector)
	unblindedMessage := crypto.XorInplace(sEval, roundMessage.MessageVector)

	require.Equal(t, expectedMsg, unblindedMessage)

}

func TestE2E(t *testing.T) {
	config := &ADCNetConfig{
		AuctionSlots:  10,
		MessageLength: 192,
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
		previousRoundOutput.AuctionVector.InsertChunk(blind_auction.AuctionDataFromMessage(msgsData[i], 10).EncodeToChunk())
	}

	recoveredChunks, err := previousRoundOutput.AuctionVector.Recover()
	require.NoError(t, err)
	require.Len(t, recoveredChunks, 3)

	for i := range msgsData {
		chunk := blind_auction.AuctionDataFromMessage(msgsData[i], 10).EncodeToChunk()
		require.Contains(t, recoveredChunks, chunk)
	}

	recoveredAuctionData := make([]blind_auction.AuctionData, len(recoveredChunks))
	for i := range recoveredAuctionData {
		recoveredAuctionData[i] = *blind_auction.AuctionDataFromChunk(recoveredChunks[i])
	}
	auctionWinnders := blind_auction.NewAuctionEngine(uint32(config.MessageLength), 1).RunAuction(recoveredAuctionData)
	require.Len(t, auctionWinnders, 2, recoveredAuctionData)

	clientMsgs := []*Signed[ClientRoundMessage]{}
	talkingClients := []int{}
	for c := range clients {
		rawClientMessage, talking, err := clients[c].PrepareMessage(2, previousRoundOutput, msgsData[c], nil /* ignore the auction for now */)
		require.NoError(t, err)

		if talking {
			talkingClients = append(talkingClients, c)
		}

		require.NotNil(t, rawClientMessage)
		signedClientMessage, _ := NewSigned(clientKeys[c], rawClientMessage)
		clientMsgs = append(clientMsgs, signedClientMessage)
	}

	require.Len(t, talkingClients, 2, recoveredChunks)

	agg := &AggregatorMessager{Config: config}

	verifiedMessages, err := VerifyClientMessages(clientMsgs)
	require.NoError(t, err)
	aggregatedMessage, err := agg.AggregateVerifiedMessages(2, nil, verifiedMessages, clientPubkeys)
	require.NoError(t, err)

	partialDecryptionMessages := make([]*ServerPartialDecryptionMessage, len(servers))
	for s := range servers {
		var err error
		partialDecryptionMessages[s], err = servers[s].UnblindAggregate(2, aggregatedMessage)
		require.NoError(t, err)
	}

	roundOutput, err := servers[0].UnblindPartialMessages(partialDecryptionMessages)
	require.NoError(t, err)
	require.NotNil(t, roundOutput)

	foundMsgs := 0
	for startingIndex := 0; startingIndex < config.MessageLength; startingIndex++ {
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

	nClientBenches := []int{100, 1000}
	msgSizeBenches := []int{10, 4000 /* 256kB */, 8 * 4000 /* 2MB */}

	sharedSecrets := make(map[string]crypto.SharedKey)
	userPKs := make([]crypto.PublicKey, slices.Max(nClientBenches))

	msgVector := make([]byte, slices.Max(msgSizeBenches))
	rs.Read(msgVector)

	for i := range userPKs {
		pubkey, _, _ := crypto.GenerateKeyPair()
		ss := make([]byte, 64)
		rand.Read(ss)
		sharedSecrets[pubkey.String()] = ss
		userPKs[i] = pubkey
	}

	for _, nClients := range nClientBenches {
		for _, msgVectorLength := range msgSizeBenches {
			auctionVector := blind_auction.NewIBFVector(uint32(msgVectorLength)).EncodeAsFieldElements()
			b.Run(fmt.Sprintf("Unblind aggregate clients-%d-msg-%d", nClients, msgVectorLength), func(b *testing.B) {

				server := &ServerMessager{
					Config: &ADCNetConfig{
						AuctionSlots:  10,
						MessageLength: msgVectorLength,
					},
					ServerID:      1,
					SharedSecrets: sharedSecrets,
				}

				aggregate := &AggregatedClientMessages{
					RoundNumber:   1,
					AllServerIds:  []ServerID{1},
					AuctionVector: auctionVector,
					MessageVector: msgVector[:msgVectorLength],
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

func BenchmarkUnblindMessages(b *testing.B) {
	rs := mrand.New(mrand.NewSource(0))

	nClientBenches := []int{100, 1000}
	msgSizeBenches := []int{10 * 64, 8 * 4000 * 64}
	nServerBenches := []int{2, 4, 10}

	sharedSecrets := make(map[string]crypto.SharedKey)
	userPKs := make([]crypto.PublicKey, slices.Max(nClientBenches))
	msgVector := make([][]byte, slices.Max(nServerBenches))

	for si := range msgVector {
		msgVector[si] = make([]byte, slices.Max(msgSizeBenches))
		rs.Read(msgVector[si])
	}

	for i := range userPKs {
		pubkey, _, _ := crypto.GenerateKeyPair()
		ss := make([]byte, 64)
		rand.Read(ss)
		sharedSecrets[pubkey.String()] = ss
		userPKs[i] = pubkey
	}

	for _, msgVectorLength := range msgSizeBenches {
		auctionVector := blind_auction.NewIBFVector(uint32(msgVectorLength)).EncodeAsFieldElements()
		for _, nServers := range nServerBenches {
			for _, nClients := range nClientBenches {
				b.Run(fmt.Sprintf("Unblind partial messages servers-%d-clients-%d-msg-%d", nServers, nClients, msgVectorLength), func(b *testing.B) {

					config := &ADCNetConfig{
						AuctionSlots:  10,
						MessageLength: msgVectorLength,
					}

					pdm := make([]*ServerPartialDecryptionMessage, nServers)
					for i := range pdm {
						pdm[i] = &ServerPartialDecryptionMessage{
							ServerID:          ServerID(i + 1),
							OriginalAggregate: &AggregatedClientMessages{RoundNumber: 1},
							UserPKs:           userPKs[:nClients],
							AuctionVector:     auctionVector,
							MessageVector:     msgVector[i][:msgVectorLength],
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
