package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/require"
)

func TestServices(t *testing.T) {
	// Create a test configuration
	config := &ADCNetConfig{
		AuctionSlots:    10,
		MessageLength:   640,
		MinClients:      1,
		RoundDuration:   100 * time.Millisecond,
		RoundsPerWindow: 10,
	}

	// Create server keys
	_, serverSigningKey1, _ := crypto.GenerateKeyPair()
	serverExchangeKey1, _ := ecdh.X25519().GenerateKey(rand.Reader)

	_, serverSigningKey2, _ := crypto.GenerateKeyPair()
	serverExchangeKey2, _ := ecdh.X25519().GenerateKey(rand.Reader)

	_, serverSigningKey3, _ := crypto.GenerateKeyPair()
	serverExchangeKey3, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Create client keys
	clientPubkey, clientSigningKey, _ := crypto.GenerateKeyPair()
	clientExchangeKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Create services
	server1 := NewServerService(config, 1, serverSigningKey1, serverExchangeKey1)
	server2 := NewServerService(config, 2, serverSigningKey2, serverExchangeKey2)
	server3 := NewServerService(config, 3, serverSigningKey3, serverExchangeKey3)
	aggregator := NewAggregatorService(config)
	client := NewClientService(config, clientSigningKey, clientExchangeKey)

	advanceRound := func(round Round) {
		server1.AdvanceToRound(round)
		server2.AdvanceToRound(round)
		server3.AdvanceToRound(round)
		aggregator.AdvanceToRound(round)
		client.AdvanceToRound(round)
	}

	advanceRound(Round{1, ClientRoundContext})
	advanceRound(Round{2, ClientRoundContext})

	require.NoError(t, server1.RegisterClient(clientPubkey, clientExchangeKey.PublicKey()))
	require.NoError(t, server2.RegisterClient(clientPubkey, clientExchangeKey.PublicKey()))
	require.NoError(t, server3.RegisterClient(clientPubkey, clientExchangeKey.PublicKey()))
	require.NoError(t, aggregator.RegisterClient(clientPubkey))

	// Register servers with client
	require.NoError(t, client.RegisterServer(1, serverExchangeKey1.PublicKey()))
	require.NoError(t, client.RegisterServer(2, serverExchangeKey2.PublicKey()))
	require.NoError(t, client.RegisterServer(3, serverExchangeKey3.PublicKey()))

	// Schedule a message for next round
	testMessage := []byte("Hello ADCNet!")
	bidValue := uint32(100)
	testAuctionData := blind_auction.AuctionDataFromMessage(testMessage, bidValue)

	require.NoError(t, client.ScheduleMessageForNextRound(testMessage, bidValue))

	message, shouldSend, err := client.MessagesForCurrentRound()
	require.Error(t, err)

	client.ProcessRoundBroadcast(&RoundBroadcast{
		RoundNumber:   1,
		AuctionVector: blind_auction.NewIBFVector(config.AuctionSlots),
		MessageVector: []byte{},
	})

	message, shouldSend, err = client.MessagesForCurrentRound()
	require.NoError(t, err)
	require.False(t, shouldSend)

	require.Len(t, message.Object.AuctionVector, 52)

	aggregate, err := aggregator.ProcessClientMessages([]*Signed[ClientRoundMessage]{message})
	require.NoError(t, err)
	require.Len(t, aggregate.AuctionVector, 52)

	s1pdm, err := server1.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s1pdm)

	s2pdm, err := server2.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s2pdm)

	s3pdm, err := server3.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s3pdm)

	srb, err := server1.ProcessPartialDecryptionMessage(s1pdm)
	require.NoError(t, err)
	require.Nil(t, srb)

	srb, err = server1.ProcessPartialDecryptionMessage(s2pdm)
	require.NoError(t, err)
	require.Nil(t, srb)

	srb, err = server1.ProcessPartialDecryptionMessage(s3pdm)
	require.NoError(t, err)
	require.NotNil(t, srb)

	require.Equal(t, 2, srb.RoundNumber)
	require.Equal(t, []byte{}, srb.MessageVector)

	chunks, err := srb.AuctionVector.Recover()
	require.NoError(t, err, srb.AuctionVector)
	require.Len(t, chunks, 1, srb.AuctionVector.String())
	require.Equal(t, testAuctionData.EncodeToChunk(), chunks[0], srb.AuctionVector.String())

	require.NoError(t, client.ProcessRoundBroadcast(srb))

	advanceRound(Round{3, ClientRoundContext})

	// Now verify client sends the message!

	message, shouldSend, err = client.MessagesForCurrentRound()
	require.NoError(t, err)
	require.NotNil(t, message)
	require.True(t, shouldSend) // Should send because we scheduled a message

	// Verify messages are for correct servers
	aggregate, err = aggregator.ProcessClientMessages([]*Signed[ClientRoundMessage]{message})
	require.NoError(t, err)

	s1pdm, err = server1.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s1pdm)

	s2pdm, err = server2.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s2pdm)

	s3pdm, err = server3.ProcessAggregateMessage(aggregate)
	require.NoError(t, err)
	require.NotNil(t, s3pdm)

	srb, err = server1.ProcessPartialDecryptionMessage(s2pdm)
	require.NoError(t, err)
	require.Nil(t, srb)

	srb, err = server1.ProcessPartialDecryptionMessage(s3pdm)
	require.NoError(t, err)
	require.NotNil(t, srb)

	require.True(t, bytes.Contains(srb.MessageVector, testMessage))
}
