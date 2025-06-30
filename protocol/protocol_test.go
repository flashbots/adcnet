package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
		AuctionSlots:      3,
		MessageSize:       3,
		MessageFieldOrder: crypto.MessageFieldOrder,
	}

	// client1PK, client1SK, _ := crypto.GenerateKeyPair()
	// client2PK, client2SK, _ := crypto.GenerateKeyPair()

	c := &ClientMessager{
		Config:        config,
		SharedSecrets: map[int32]crypto.SharedKey{1: sharedSecret("c1s1"), 2: sharedSecret("c1s2"), 3: sharedSecret("c1s3")},
	}

	auctionIBF := blind_auction.NewIBFVector(config.AuctionSlots)
	auctionIBF.InsertChunk((&blind_auction.AuctionData{
		MessageHash: crypto.Hash{},
		Weight:      10,
		Size:        1,
	}).EncodeToChunk())

	msgEls := EncodeMessageToFieldElements(AuctionResult{ShouldSend: true, MessageStartIndex: 127}, make([]byte, 64*3), []byte{10})
	require.Len(t, msgEls, 3)
	require.Zero(t, msgEls[0].Cmp(big.NewInt(0)))
	require.Zero(t, msgEls[1].Cmp(big.NewInt(10)))
	require.Zero(t, msgEls[2].Cmp(big.NewInt(0)))

	roundMessage, err := c.SecretShareMessage(1, msgEls, auctionIBF.EncodeAsFieldElements())
	require.NoError(t, err)
	require.Len(t, roundMessage, 3)

	s1MessageBlindingVector := crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s1")...)}, 1, int32(config.MessageSize), crypto.MessageFieldOrder)
	s2MessageBlindingVector := crypto.DeriveBlindingVector([]crypto.SharedKey{append([]byte{1}, sharedSecret("c1s2")...)}, 1, int32(config.MessageSize), crypto.MessageFieldOrder)

	s1i0Eval := crypto.FieldSub(roundMessage[0].MessageVector[0], s1MessageBlindingVector[0], crypto.MessageFieldOrder)
	s2i0Eval := crypto.FieldSub(roundMessage[1].MessageVector[0], s2MessageBlindingVector[0], crypto.MessageFieldOrder)

	require.Zero(t, big.NewInt(0).Mod(crypto.NevilleInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, []*big.Int{s1i0Eval, s2i0Eval}, big.NewInt(0)), crypto.MessageFieldOrder).Cmp(big.NewInt(0)))

	s1i1Eval := crypto.FieldSub(roundMessage[0].MessageVector[1], s1MessageBlindingVector[1], crypto.MessageFieldOrder)
	s2i1Eval := crypto.FieldSub(roundMessage[1].MessageVector[1], s2MessageBlindingVector[1], crypto.MessageFieldOrder)

	require.Zero(t, big.NewInt(0).Mod(crypto.NevilleInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, []*big.Int{s1i1Eval, s2i1Eval}, big.NewInt(0)), crypto.MessageFieldOrder).Cmp(big.NewInt(10)))

	// TODO: add a second client!
}

func TestE2E(t *testing.T) {
	config := &ADCNetConfig{
		AuctionSlots:      10,
		MessageSize:       3,
		MessageFieldOrder: crypto.MessageFieldOrder,
	}

	// client1PK, client1SK, _ := crypto.GenerateKeyPair()
	// client2PK, client2SK, _ := crypto.GenerateKeyPair()

	servers := make([]*ServerMessager, 3)
	for s := range servers {
		servers[s] = &ServerMessager{
			Config:        config,
			ServerID:      int32(s + 1),
			SharedSecrets: make(map[string]crypto.SharedKey),
		}
	}

	clientKeys := make([]crypto.PrivateKey, 3)
	clientPubkeys := make(map[string]bool)
	clients := make([]*ClientMessager, 3)
	for c := range clients {
		clients[c] = &ClientMessager{
			Config:        config,
			SharedSecrets: make(map[int32]crypto.SharedKey),
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

	previousRoundOutput := &ServerRoundData{
		RoundNumber:   1,
		AuctionVector: blind_auction.NewIBFVector(config.AuctionSlots),
		MessageVector: []byte{},
	}

	msgsData := [][]byte{
		make([]byte, 30),
		make([]byte, 89),
		make([]byte, 120),
	}
	for i := range msgsData {
		rand.Read(msgsData[i])
		previousRoundOutput.AuctionVector.InsertChunk((&blind_auction.AuctionData{
			MessageHash: sha256.Sum256(msgsData[i]),
			Weight:      10,
			Size:        uint32(len(msgsData[i])),
		}).EncodeToChunk())
	}

	clientMsgs := []*Signed[ClientRoundMessage]{}
	talkingClients := []int{}
	for c := range clients {
		rawClientMessages, talking, err := clients[c].PrepareMessage(2, previousRoundOutput, msgsData[c], nil /* ignore the auction for now */)
		if talking {
			talkingClients = append(talkingClients, c)
		}

		require.NoError(t, err)
		require.Len(t, rawClientMessages, 3)
		for s := range rawClientMessages {
			signedClientMessage, _ := NewSigned(clientKeys[c], rawClientMessages[s])
			clientMsgs = append(clientMsgs, signedClientMessage)
		}
	}

	require.Len(t, talkingClients, 2)

	agg := &AggregatorMessager{Config: config}
	aggregatedMessages, err := agg.AggregateClientMessages(2, clientMsgs, clientPubkeys)
	require.NoError(t, err)
	require.Len(t, aggregatedMessages, 3) // one message per server
	aggregatedMessagesPerServer := make(map[int32]*AggregatedClientMessages, 3)
	for _, msg := range aggregatedMessages {
		aggregatedMessagesPerServer[msg.ServerID] = msg
	}

	partialDecryptionMessages := make([]*ServerPartialDecryptionMessage, len(servers))
	for s := range servers {
		var err error
		partialDecryptionMessages[s], err = servers[s].UnblindAggregate(2, aggregatedMessagesPerServer[servers[s].ServerID], previousRoundOutput.AuctionVector)
		require.NoError(t, err)
	}
	roundOutput, err := servers[0].UnblindPartialMessages(partialDecryptionMessages)
	require.NoError(t, err)
	require.NotNil(t, roundOutput)

	foundMsgs := 0
	for _, startingIndex := range []int{0, 48, 89, 120} {
		if bytes.Equal(roundOutput.MessageVector[startingIndex:startingIndex+30], msgsData[0]) {
			foundMsgs++
		}
		if startingIndex+89 <= len(roundOutput.MessageVector) && bytes.Equal(roundOutput.MessageVector[startingIndex:startingIndex+89], msgsData[1]) {
			foundMsgs++
		}
		if startingIndex+120 <= len(roundOutput.MessageVector) && bytes.Equal(roundOutput.MessageVector[startingIndex:startingIndex+120], msgsData[2]) {
			foundMsgs++
		}
	}

	require.Equal(t, 2, foundMsgs)

	// TODO: check auction as well
}

func BenchmarkUnblindAggregate(b *testing.B) {
	rs := mrand.New(mrand.NewSource(0))

	fieldOrders := []*big.Int{}
	for _, fBits := range []int{513} {
		fo, _ := rand.Prime(rand.Reader, fBits)
		fieldOrders = append(fieldOrders, fo)
	}
	nClientBenches := []int{100, 1000, 10000}
	msgSizeBenches := []int{100, 2000 /* 1MB */, 10000 /* 5MB */}

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
			for foi, fieldOrder := range fieldOrders {
				b.Run(fmt.Sprintf("Unblind aggregate clients-%d-msg-%d-field-%d", nClients, msgVectorSlots, fieldOrder.BitLen()), func(b *testing.B) {

					server := &ServerMessager{
						Config: &ADCNetConfig{
							AuctionSlots:      10,
							MessageSize:       uint32(msgVectorSlots),
							MessageFieldOrder: fieldOrder,
						},
						ServerID:      1,
						SharedSecrets: sharedSecrets,
					}

					aggregate := &AggregatedClientMessages{
						RoundNumber:   1,
						ServerID:      1,
						AuctionVector: []*big.Int{},
						MessageVector: msgVector[foi][:msgVectorSlots],
						UserPKs:       userPKs[:nClients],
					}

					for b.Loop() {
						_, err := server.UnblindAggregate(1, aggregate, nil)
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
	nClientBenches := []int{100, 10000}
	msgSizeBenches := []int{100, 10000}
	nServerBenches := []int{2, 4, 6}

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

	for _, nServers := range nServerBenches {
		for _, nClients := range nClientBenches {
			for _, msgVectorSlots := range msgSizeBenches {
				b.Run(fmt.Sprintf("Unblind partial messages servers-%d-clients-%d-msg-%d-field-%d", nServers, nClients, msgVectorSlots, fieldOrder.BitLen()), func(b *testing.B) {

					config := &ADCNetConfig{
						AuctionSlots:      10,
						MessageSize:       uint32(msgVectorSlots),
						MessageFieldOrder: fieldOrder,
					}

					pdm := make([]*ServerPartialDecryptionMessage, nServers)
					for i := range pdm {
						pdm[i] = &ServerPartialDecryptionMessage{
							ServerID:          int32(i + 1),
							OriginalAggregate: &AggregatedClientMessages{RoundNumber: 1},
							UserPKs:           userPKs[:nClients],
							AuctionVector:     []*big.Int{},
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
