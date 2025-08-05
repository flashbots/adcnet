package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/require"
)

func TestServices(t *testing.T) {
	// Create a test configuration
	config := &ADCNetConfig{
		AuctionSlots:      10,
		MessageSlots:      10,
		MessageFieldOrder: crypto.MessageFieldOrder,
		MinServers:        2,
		MinClients:        1,
		RoundDuration:     100 * time.Millisecond,
		RoundsPerWindow:   10,
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
	testAuctionData := blind_auction.AuctionDataFromMessage(testMessage, bidValue, (config.MessageFieldOrder.BitLen()-1)/8)

	require.NoError(t, client.ScheduleMessageForNextRound(testMessage, bidValue))

	messages, shouldSend, err := client.MessagesForCurrentRound()
	require.NoError(t, err)
	require.False(t, shouldSend)
	require.Len(t, messages, 3) // One message per server

	require.Len(t, messages[0].Object.AuctionVector, 52)

	aggregates, err := aggregator.ProcessClientMessages(messages)
	require.NoError(t, err)
	slices.SortFunc(aggregates, func(a, b *AggregatedClientMessages) int { return int(a.ServerID) - int(b.ServerID) })
	server1Aggregate, server2Aggregate, server3Aggregate := aggregates[0], aggregates[1], aggregates[2]
	require.Len(t, server3Aggregate.AuctionVector, 52)

	s1pdm, err := server1.ProcessAggregateMessage(server1Aggregate)
	require.NoError(t, err)
	require.NotNil(t, s1pdm)

	// Case 1: server 2 first processes the aggregate, and then receives s1's decryption
	s2pdm, err := server2.ProcessAggregateMessage(server2Aggregate)
	require.NoError(t, err)
	require.NotNil(t, s2pdm)

	s2rb, err := server2.ProcessPartialDecryptionMessage(s1pdm)
	require.NoError(t, err)
	require.NotNil(t, s2rb)

	require.Equal(t, make([]byte, 640), s2rb.MessageVector)

	// Case 2: server 3 first receivese s1's decryption. Note that s3 could process the original aggregate then.
	s3rb, err := server3.ProcessPartialDecryptionMessage(s1pdm)
	require.NoError(t, err)
	require.Nil(t, s3rb)

	s3pdm, err := server3.ProcessAggregateMessage(server3Aggregate)
	require.NoError(t, err)
	require.NotNil(t, s3pdm)
	require.Len(t, s3pdm.AuctionVector, 52)

	s3rb, err = server3.ProcessPartialDecryptionMessage(s3pdm)
	require.NoError(t, err)
	require.NotNil(t, s3rb)

	require.Equal(t, 1, s3rb.RoundNumber)
	require.Equal(t, make([]byte, 640), s3rb.MessageVector)

	chunks, err := s3rb.AuctionVector.Recover()
	require.NoError(t, err, s3rb.AuctionVector)
	require.Len(t, chunks, 1, s3rb.AuctionVector.String())
	require.Equal(t, testAuctionData.EncodeToChunk(), chunks[0], s3rb.AuctionVector.String())

	require.NoError(t, client.ProcessRoundBroadcast(s3rb))

	advanceRound(Round{2, ClientRoundContext})

	// Now verify client sends the message!

	messages, shouldSend, err = client.MessagesForCurrentRound()
	require.NoError(t, err)
	require.Len(t, messages, 3) // One message per server
	require.True(t, shouldSend) // Should send because we scheduled a message

	// Verify messages are for correct servers
	aggregates, err = aggregator.ProcessClientMessages(messages)
	require.NoError(t, err)
	slices.SortFunc(aggregates, func(a, b *AggregatedClientMessages) int { return int(a.ServerID) - int(b.ServerID) })
	server1Aggregate, server2Aggregate, server3Aggregate = aggregates[0], aggregates[1], aggregates[2]

	s1pdm, err = server1.ProcessAggregateMessage(server1Aggregate)
	require.NoError(t, err)
	require.NotNil(t, s1pdm)

	s2pdm, err = server2.ProcessAggregateMessage(server2Aggregate)
	require.NoError(t, err)
	require.NotNil(t, s2pdm)

	s2rb, err = server2.ProcessPartialDecryptionMessage(s1pdm)
	require.NoError(t, err)
	require.NotNil(t, s2rb)

	require.True(t, bytes.Contains(s2rb.MessageVector, testMessage))
}
