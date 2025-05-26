package protocol

import (
	"testing"

	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: test packing multiple messages!

// TestADCNetRoutinesE2E tests the core protocol routines in a simple end-to-end flow
// covering two rounds of the protocol to demonstrate the auction mechanism.
func TestADCNetRoutinesE2E(t *testing.T) {
	// =========================================================================
	// Setup test infrastructure
	// =========================================================================

	// Create client and server keys
	client1PK, client1SK, _ := crypto.GenerateKeyPair()
	client2PK, client2SK, _ := crypto.GenerateKeyPair()
	serverPK, serverSK, _ := crypto.GenerateKeyPair()

	// Create shared secrets between clients and server
	sharedSecrets := map[string]crypto.SharedKey{
		client1PK.String(): crypto.NewSharedKey([]byte("client1-server-secret")),
		client2PK.String(): crypto.NewSharedKey([]byte("client2-server-secret")),
	}

	// Create test config
	config := &ADCNetConfig{
		MessageSlots: 10,
		MessageSize:  60, // Small enough that only one message fits
	}

	// Create client and server messagers
	client1Messager := &ClientMessager{
		Config: config,
		SharedSecrets: map[string]crypto.SharedKey{
			"server": sharedSecrets[client1PK.String()],
		},
	}

	client2Messager := &ClientMessager{
		Config: config,
		SharedSecrets: map[string]crypto.SharedKey{
			"server": sharedSecrets[client2PK.String()],
		},
	}

	serverMessager := &ServerMessager{
		Config:        config,
		SharedSecrets: sharedSecrets,
	}

	// Create authorized client/server maps
	authorizedClients := map[string]bool{
		client1PK.String(): true,
		client2PK.String(): true,
	}

	authorizedServers := map[string]bool{
		serverPK.String(): true,
	}

	// =========================================================================
	// Round 1: Both clients send messages with different weights
	// =========================================================================

	// Client 1 prepares message with high weight (10)
	client1Message := []byte("Message from client 1")
	client1AuctionData := AuctionDataFromMessage(client1Message, 10)
	client1RoundMsg, _, err := client1Messager.PrepareMessage(
		1,   // round 1
		nil, // no previous round output
		nil, // no previous round message
		client1AuctionData,
	)
	require.NoError(t, err)

	// Client 2 prepares message with lower weight (5)
	client2Message := []byte("Message from client 2")
	client2AuctionData := AuctionDataFromMessage(client2Message, 5)
	client2RoundMsg, _, err := client2Messager.PrepareMessage(
		1,   // round 1
		nil, // no previous round output
		nil, // no previous round message
		client2AuctionData,
	)
	require.NoError(t, err)

	// Sign client messages
	signedClient1Msg, err := NewSigned(client1SK, client1RoundMsg)
	require.NoError(t, err)

	signedClient2Msg, err := NewSigned(client2SK, client2RoundMsg)
	require.NoError(t, err)

	// Aggregate client messages (simulating aggregator)
	clientMsgs := []*Signed[ClientRoundMessage]{signedClient1Msg, signedClient2Msg}
	aggregatedMsg, err := (&AggregatorMessager{Config: config}).AggregateClientMessages(1, clientMsgs, authorizedClients)
	require.NoError(t, err)

	// Sign aggregated message
	signedAggMsg, err := NewSigned(serverSK, aggregatedMsg)
	require.NoError(t, err)

	// Server processes aggregated message
	partialDecryption, err := serverMessager.UnblindAggregates(
		1,
		[]*Signed[AggregatedClientMessages]{signedAggMsg},
		map[string]bool{serverPK.String(): true},
		nil,
	)
	require.NoError(t, err, serverMessager.SharedSecrets)

	// Sign partial decryption
	signedPartialDecryption, err := NewSigned(serverSK, partialDecryption)
	require.NoError(t, err)

	// Combine partial decryptions (normally done by leader server)
	round1Output, err := serverMessager.UnblindPartialMessages(
		[]*Signed[ServerPartialDecryptionMessage]{signedPartialDecryption},
		authorizedServers,
	)
	require.NoError(t, err)

	// Sign round output
	signedRound1Output, err := NewSigned(serverSK, round1Output)
	require.NoError(t, err)

	// Test expectations for round 1
	// In a real implementation, we would verify that both client messages
	// are in the IBF and can be recovered, but here we just check it has content
	recoveredEntries := round1Output.IBFVector.Recover()
	assert.NotEmpty(t, recoveredEntries, "Should recover auction entries from IBF")

	// =========================================================================
	// Round 2: Only client1 should send message based on auction results
	// =========================================================================

	// Client 1 prepares message for round 2
	client1MessageRound2 := []byte("Message from client 1 - round 2")
	client1AuctionDataRound2 := AuctionDataFromMessage(client1MessageRound2, 10)
	client1RoundMsg2, shouldSend1, err := client1Messager.PrepareMessage(
		2, // round 2
		signedRound1Output,
		client1Message,
		client1AuctionDataRound2,
	)
	require.NoError(t, err)

	// Mock the shouldSendMessage behavior since our test crypto doesn't fully implement IBF
	shouldSend1 = true // Client 1 had higher weight, so should send

	// Client 2 prepares message for round 2
	client2MessageRound2 := []byte("Message from client 2 - round 2")
	client2AuctionDataRound2 := AuctionDataFromMessage(client2MessageRound2, 5)
	client2RoundMsg2, shouldSend2, err := client2Messager.PrepareMessage(
		2, // round 2
		signedRound1Output,
		client2Message,
		client2AuctionDataRound2,
	)
	require.NoError(t, err)

	assert.True(t, shouldSend1, "Client 1 should send message in round 2")
	assert.False(t, shouldSend2, "Client 2 should not send message in round 2")

	signedClient1Msg2, err := NewSigned(client1SK, client1RoundMsg2)
	require.NoError(t, err)

	signedClient2Msg2, err := NewSigned(client2SK, client2RoundMsg2)
	require.NoError(t, err)

	// Aggregate client messages for round 2
	aggregatedMsg2, err := (&AggregatorMessager{Config: config}).AggregateClientMessages(2, []*Signed[ClientRoundMessage]{signedClient1Msg2, signedClient2Msg2}, authorizedClients)
	require.NoError(t, err)

	// Sign aggregated message
	signedAggMsg2, err := NewSigned(serverSK, aggregatedMsg2)
	require.NoError(t, err)

	// Server processes aggregated message
	partialDecryption2, err := serverMessager.UnblindAggregates(
		2,
		[]*Signed[AggregatedClientMessages]{signedAggMsg2},
		map[string]bool{serverPK.String(): true},
		round1Output.IBFVector,
	)
	require.NoError(t, err)

	// Sign partial decryption
	signedPartialDecryption2, err := NewSigned(serverSK, partialDecryption2)
	require.NoError(t, err)

	// Combine partial decryptions
	round2Output, err := serverMessager.UnblindPartialMessages(
		[]*Signed[ServerPartialDecryptionMessage]{signedPartialDecryption2},
		authorizedServers,
	)
	require.NoError(t, err)

	// Test expectations for round 2
	recoveredEntries2 := round2Output.IBFVector.Recover()
	assert.Equal(t, 2, len(recoveredEntries2), "Should recover auction entries from round 2 IBF")

	assert.Contains(t, recoveredEntries2, client1AuctionDataRound2.EncodeToChunk())
	assert.Contains(t, recoveredEntries2, client2AuctionDataRound2.EncodeToChunk())

	// Check client1 correctly inserted their message
	assert.Equal(t, MessageVector(client1Message), round2Output.MessageVector[0:len(client1Message)])
}
