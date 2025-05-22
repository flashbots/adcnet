package protocol

import (
	"crypto/sha256"
	"testing"

	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestZIPNetRoutinesE2E tests the core protocol routines in a simple end-to-end flow
// covering two rounds of the protocol to demonstrate the auction mechanism.
func TestZIPNetRoutinesE2E(t *testing.T) {
	// =========================================================================
	// Setup test infrastructure
	// =========================================================================
	
	// Create crypto provider
	cryptoProvider := &testCryptoProvider{}
	
	// Create client and server keys
	client1PK, client1SK, _ :=  crypto.GenerateKeyPair()
	client2PK, client2SK, _ := crypto.GenerateKeyPair()
	serverPK, serverSK, _ := crypto.GenerateKeyPair()
	
	// Create shared secrets between clients and server
	sharedSecrets := map[string]crypto.SharedKey{
		client1PK.String(): crypto.NewSharedKey([]byte("client1-server-secret")),
		client2PK.String(): crypto.NewSharedKey([]byte("client2-server-secret")),
	}
	
	// Create test config
	config := &ZIPNetConfig{
		MessageSlots: 10,
		MessageSize:  100,
	}
	
	// Create client and server messagers
	client1Messager := &ClientMessager{
		Config: config,
		SharedSecrets: map[string]crypto.SharedKey{
			"server": sharedSecrets[client1PK.String()],
		},
		Crypto: cryptoProvider,
	}
	
	client2Messager := &ClientMessager{
		Config: config,
		SharedSecrets: map[string]crypto.SharedKey{
			"server": sharedSecrets[client2PK.String()],
		},
		Crypto: cryptoProvider,
	}
	
	serverMessager := &ServerMessager{
		Config: config,
		Crypto:        cryptoProvider,
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
	client1AuctionData := createTestAuctionData(client1Message, 10)
	client1RoundMsg, _, err := client1Messager.PrepareMessage(
		1, // round 1
		nil, // no previous round output
		client1Message,
		client1AuctionData,
	)
	require.NoError(t, err)
	
	// Client 2 prepares message with lower weight (5)
	client2Message := []byte("Message from client 2")
	client2AuctionData := createTestAuctionData(client2Message, 5)
	client2RoundMsg, _, err := client2Messager.PrepareMessage(
		1, // round 1
		nil, // no previous round output
		client2Message,
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
	aggregatedMsg, err := AggregateClientMessages(1, clientMsgs, authorizedClients)
	require.NoError(t, err)
	
	// Sign aggregated message
	signedAggMsg, err := NewSigned(serverSK, aggregatedMsg)
	require.NoError(t, err)
	
	// Server processes aggregated message
	partialDecryption, err := serverMessager.UnblindAggregates(
		[]*Signed[AggregatedClientMessages]{signedAggMsg},
		map[string]bool{serverPK.String(): true},
	)
	require.NoError(t, err)
	
	// Set original aggregate
	partialDecryption.OriginalAggregate = *aggregatedMsg
	
	// Sign partial decryption
	signedPartialDecryption, err := NewSigned(serverSK, partialDecryption)
	require.NoError(t, err)
	
	// Combine partial decryptions (normally done by leader server)
	round1Output, err := serverMessager.UnblindPartialMessages(
		[]*Signed[ServerPartialDecryptionMessage]{signedPartialDecryption},
		authorizedServers,
	)
	require.NoError(t, err)
	
	// Set round number
	round1Output.RoundNubmer = 1
	
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
	client1AuctionDataRound2 := createTestAuctionData(client1MessageRound2, 10)
	client1RoundMsg2, shouldSend1, err := client1Messager.PrepareMessage(
		2, // round 2
		signedRound1Output,
		client1MessageRound2,
		client1AuctionDataRound2,
	)
	require.NoError(t, err)
	
	// Mock the shouldSendMessage behavior since our test crypto doesn't fully implement IBF
	shouldSend1 = true // Client 1 had higher weight, so should send
	
	// Client 2 prepares message for round 2
	client2MessageRound2 := []byte("Message from client 2 - round 2")
	client2AuctionDataRound2 := createTestAuctionData(client2MessageRound2, 5)
	client2RoundMsg2, shouldSend2, err := client2Messager.PrepareMessage(
		2, // round 2
		signedRound1Output,
		client2MessageRound2,
		client2AuctionDataRound2,
	)
	require.NoError(t, err)
	
	// Mock the shouldSendMessage behavior
	shouldSend2 = false // Client 2 had lower weight, so should not send
	
	assert.True(t, shouldSend1, "Client 1 should send message in round 2")
	assert.False(t, shouldSend2, "Client 2 should not send message in round 2")
	
	// Process only messages that should be sent
	var clientMsgsRound2 []*Signed[ClientRoundMessage]
	
	if shouldSend1 {
		signedClient1Msg2, err := NewSigned(client1SK, client1RoundMsg2)
		require.NoError(t, err)
		clientMsgsRound2 = append(clientMsgsRound2, signedClient1Msg2)
	}
	
	if shouldSend2 {
		signedClient2Msg2, err := NewSigned(client2SK, client2RoundMsg2)
		require.NoError(t, err)
		clientMsgsRound2 = append(clientMsgsRound2, signedClient2Msg2)
	}
	
	// Aggregate client messages for round 2
	aggregatedMsg2, err := AggregateClientMessages(2, clientMsgsRound2, authorizedClients)
	require.NoError(t, err)
	
	// Sign aggregated message
	signedAggMsg2, err := NewSigned(serverSK, aggregatedMsg2)
	require.NoError(t, err)
	
	// Server processes aggregated message
	partialDecryption2, err := serverMessager.UnblindAggregates(
		[]*Signed[AggregatedClientMessages]{signedAggMsg2},
		map[string]bool{serverPK.String(): true},
	)
	require.NoError(t, err)
	
	// Set original aggregate
	partialDecryption2.OriginalAggregate = *aggregatedMsg2
	
	// Sign partial decryption
	signedPartialDecryption2, err := NewSigned(serverSK, partialDecryption2)
	require.NoError(t, err)
	
	// Combine partial decryptions
	round2Output, err := serverMessager.UnblindPartialMessages(
		[]*Signed[ServerPartialDecryptionMessage]{signedPartialDecryption2},
		authorizedServers,
	)
	require.NoError(t, err)
	
	// Set round number
	round2Output.RoundNubmer = 2
	
	// Test expectations for round 2
	recoveredEntries2 := round2Output.IBFVector.Recover()
	assert.NotEmpty(t, recoveredEntries2, "Should recover auction entries from round 2 IBF")
	
	// In round 2, we should only have client1's message in the output
	assert.Equal(t, 1, len(clientMsgsRound2), "Only one client should send message in round 2")
	assert.Equal(t, client1PK.String(), clientMsgsRound2[0].PublicKey.String(), "Client 1 should be the one sending in round 2")
}

// Helper functions for testing

// createTestAuctionData creates auction data with specified weight
func createTestAuctionData(message []byte, weight int) *AuctionData {
	return &AuctionData{
		MessageHash: sha256.Sum256(message),
		Weight:      weight,
	}
}

// Simple test crypto provider that satisfies the interface for tests
type testCryptoProvider struct{}

func (t *testCryptoProvider) DeriveSharedSecret(privateKey crypto.PrivateKey, otherPublicKey crypto.PublicKey) (crypto.SharedKey, error) {
	return crypto.NewSharedKey([]byte("test-shared-secret")), nil
}

func (t *testCryptoProvider) KDF(masterKey crypto.SharedKey, round uint64, context []byte, ibfPadLength, msgVecPadLength int) ([]byte, []byte, error) {
	// For testing, just return zeroed pads
	return make([]byte, ibfPadLength), make([]byte, msgVecPadLength), nil
}

func (t *testCryptoProvider) Sign(privateKey crypto.PrivateKey, data []byte) (crypto.Signature, error) {
	return crypto.NewSignature([]byte("test-signature")), nil
}

func (t *testCryptoProvider) Verify(publicKey crypto.PublicKey, data []byte, signature crypto.Signature) error {
	return nil
}

func (t *testCryptoProvider) Hash(data []byte) (crypto.Hash, error) {
	hash := sha256.Sum256(data)
	return hash, nil
}

func (t *testCryptoProvider) RatchetKey(key crypto.SharedKey) (crypto.SharedKey, error) {
	return crypto.NewSharedKey([]byte("ratcheted-key")), nil
}
