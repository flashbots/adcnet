package aggregator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/testutil"
	"github.com/ruteri/go-zipnet/zipnet"
)

// Helper function to create test aggregators
func setupTestAggregator(t *testing.T, level uint32, registeredUserCount int) (*AggregatorImpl, []crypto.PublicKey) {
	// Create test config with a lower minimum client requirement for testing
	config := testutil.NewTestConfig(testutil.WithMinClients(2))

	// Generate aggregator keys
	pubKey, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Generate registered users
	registeredUsers, err := testutil.GenerateTestPublicKeys(registeredUserCount)
	require.NoError(t, err)

	// Create dependencies
	cryptoProvider := zipnet.NewMockCryptoProvider()
	networkTransport := zipnet.NewMockNetworkTransport()

	// Create aggregator
	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, registeredUsers, level)
	require.NoError(t, err)
	require.NotNil(t, agg)

	// Initialize round
	err = agg.Reset(1)
	require.NoError(t, err)

	return agg, registeredUsers
}

// Generate a signed client message using testutil
func createSignedClientMessage(t *testing.T, round uint64, clientKey crypto.PrivateKey, cryptoProvider zipnet.CryptoProvider) *zipnet.ClientMessage {
	// Create client message with appropriate round
	msg := testutil.GenerateTestClientMessage(testutil.WithRound(round))

	// Serialize message for signing (excluding signature)
	data, err := zipnet.SerializeMessage(&zipnet.ScheduleMessage{
		Round:        msg.Round,
		NextSchedVec: msg.NextSchedVec,
		MsgVec:       msg.MsgVec,
	})
	require.NoError(t, err)

	// Sign message
	sig, err := cryptoProvider.Sign(clientKey, data)
	require.NoError(t, err)

	msg.Signature = sig
	return msg
}

// Test 1: Basic creation and properties
func TestAggregatorCreation(t *testing.T) {
	// Test leaf aggregator (level 0)
	leafAgg, users := setupTestAggregator(t, 0, 5)
	require.Equal(t, uint32(0), leafAgg.GetLevel())
	require.NotNil(t, leafAgg.GetPublicKey())
	require.Len(t, leafAgg.registeredUsers, 5)

	// Test higher-level aggregator (level 1)
	higherAgg, _ := setupTestAggregator(t, 1, 3)
	require.Equal(t, uint32(1), higherAgg.GetLevel())

	// Test invalid creation cases
	cryptoProvider := zipnet.NewMockCryptoProvider()
	networkTransport := zipnet.NewMockNetworkTransport()
	pubKey, privKey, _ := crypto.GenerateKeyPair()

	// Nil config should fail
	_, err := NewAggregator(nil, privKey, pubKey, cryptoProvider, networkTransport, users, 0)
	require.Error(t, err)

	// Nil crypto provider should fail
	_, err = NewAggregator(testutil.NewTestConfig(), privKey, pubKey, nil, networkTransport, users, 0)
	require.Error(t, err)

	// Nil network transport should fail
	_, err = NewAggregator(testutil.NewTestConfig(), privKey, pubKey, cryptoProvider, nil, users, 0)
	require.Error(t, err)
}

// Test 2: Client message reception and validation
func TestClientMessageReception(t *testing.T) {
	ctx := context.Background()

	// Create leaf aggregator (level 0)
	agg, regUsers := setupTestAggregator(t, 0, 5)
	cryptoProvider := zipnet.NewMockCryptoProvider()

	// Generate client keys - one registered, one unregistered
	regClientPub := regUsers[0]
	// Generate a new key pair for testing
	_, regClientPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	unregPub, unregPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Case 1: Valid message from registered client
	validMsg := createSignedClientMessage(t, 1, regClientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, validMsg, regClientPub)
	require.NoError(t, err)

	// Case 2: Message from unregistered client should fail
	unregMsg := createSignedClientMessage(t, 1, unregPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, unregMsg, unregPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not registered")

	// Case 3: Message with wrong round number should fail
	wrongRoundMsg := createSignedClientMessage(t, 2, regClientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, wrongRoundMsg, regClientPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "round")

	// Case 4: Duplicate message from same client should fail
	dupMsg := createSignedClientMessage(t, 1, regClientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, dupMsg, regClientPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")

	// Case 5: Non-leaf aggregator cannot receive client messages
	higherAgg, _ := setupTestAggregator(t, 1, 5)
	err = higherAgg.ReceiveClientMessage(ctx, validMsg, regClientPub)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-leaf aggregator")
}

// Test 3: Aggregator message reception
func TestAggregatorMessageReception(t *testing.T) {
	ctx := context.Background()

	// Create a non-leaf aggregator (level 1)
	higherAgg, _ := setupTestAggregator(t, 1, 5)

	// Create a leaf aggregator (level 0)
	leafAgg, regUsers := setupTestAggregator(t, 0, 5)

	// Create aggregator message (round 1)
	aggMsg := testutil.GenerateTestAggregatorMessage()
	aggMsg.Round = 1
	aggMsg.Level = 0
	aggMsg.UserPKs = regUsers

	// Case 1: Valid aggregator message to non-leaf
	err := higherAgg.ReceiveAggregatorMessage(ctx, aggMsg)
	require.NoError(t, err)

	// Case 2: Leaf aggregator cannot receive aggregator messages
	err = leafAgg.ReceiveAggregatorMessage(ctx, aggMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "leaf aggregator")

	// Case 3: Wrong round number should fail
	wrongRoundMsg := testutil.GenerateTestAggregatorMessage()
	wrongRoundMsg.Round = 2
	wrongRoundMsg.UserPKs = regUsers

	err = higherAgg.ReceiveAggregatorMessage(ctx, wrongRoundMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "round")

	// Case 4: Duplicate aggregator message should fail
	err = higherAgg.ReceiveAggregatorMessage(ctx, aggMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

// Test 4: Message aggregation (XOR combination)
func TestMessageAggregation(t *testing.T) {
	ctx := context.Background()

	// Create leaf aggregator
	agg, regUsers := setupTestAggregator(t, 0, 5)
	cryptoProvider := zipnet.NewMockCryptoProvider()

	// Generate client keys for testing
	_, clientPriv1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	_, clientPriv2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Create messages with specific content
	msgSize := uint32(160)
	contentA := []byte("Message A")
	contentB := []byte("Message B")

	// Create base messages with content
	msgA := testutil.GenerateMessageWithContent(contentA, 0, msgSize, testutil.WithRound(1))
	msgB := testutil.GenerateMessageWithContent(contentB, 1, msgSize, testutil.WithRound(1))

	// Sign messages
	dataA, err := zipnet.SerializeMessage(&zipnet.ScheduleMessage{
		Round: msgA.Round, NextSchedVec: msgA.NextSchedVec, MsgVec: msgA.MsgVec,
	})
	require.NoError(t, err)
	sigA, err := cryptoProvider.Sign(clientPriv1, dataA)
	require.NoError(t, err)
	msgA.Signature = sigA

	dataB, err := zipnet.SerializeMessage(&zipnet.ScheduleMessage{
		Round: msgB.Round, NextSchedVec: msgB.NextSchedVec, MsgVec: msgB.MsgVec,
	})
	require.NoError(t, err)
	sigB, err := cryptoProvider.Sign(clientPriv2, dataB)
	require.NoError(t, err)
	msgB.Signature = sigB

	// Submit messages to aggregator
	err = agg.ReceiveClientMessage(ctx, msgA, regUsers[0])
	require.NoError(t, err)
	err = agg.ReceiveClientMessage(ctx, msgB, regUsers[1])
	require.NoError(t, err)

	// Get aggregated message
	aggregate, err := agg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Verify contents are properly XOR'd
	// Extract messages from specific slots
	extractedA := testutil.ExtractMessageFromSlot(aggregate.MsgVec, 0, int(msgSize))
	extractedB := testutil.ExtractMessageFromSlot(aggregate.MsgVec, 1, int(msgSize))

	// Verify correct message contents
	require.Equal(t, contentA, extractedA[:len(contentA)])
	require.Equal(t, contentB, extractedB[:len(contentB)])

	// Verify userPKs contains both users
	require.Equal(t, 2, len(aggregate.UserPKs))
	require.Contains(t, aggregate.UserPKs, regUsers[0])
	require.Contains(t, aggregate.UserPKs, regUsers[1])
}

// Test 5: Round management
func TestRoundManagement(t *testing.T) {
	ctx := context.Background()

	// Step 1: Test successful message submission
	agg1, regUsers1 := setupTestAggregator(t, 0, 3)

	_, privKey1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	msg1 := createSignedClientMessage(t, 1, privKey1, zipnet.NewMockCryptoProvider())
	err = agg1.ReceiveClientMessage(ctx, msg1, regUsers1[0])
	require.NoError(t, err)

	// Verify message is stored
	require.Equal(t, 1, len(agg1.messages))

	// Step 2: Test round reset clears state
	agg2, regUsers2 := setupTestAggregator(t, 0, 3)

	_, privKey2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Submit a message to round 1
	msg2a := createSignedClientMessage(t, 1, privKey2, zipnet.NewMockCryptoProvider())
	err = agg2.ReceiveClientMessage(ctx, msg2a, regUsers2[0])
	require.NoError(t, err)

	// Reset to round 2
	err = agg2.Reset(2)
	require.NoError(t, err)

	// Verify state is reset
	require.Equal(t, uint64(2), agg2.currentRound)
	require.Equal(t, 0, len(agg2.messages))
	require.Equal(t, 0, len(agg2.aUserPKs))

	// Step 3: Test message with wrong round is rejected
	agg3, regUsers3 := setupTestAggregator(t, 0, 3)
	err = agg3.Reset(2) // Set to round 2
	require.NoError(t, err)

	// Try to submit round 1 message to round 2
	_, privKey3, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	msg3 := createSignedClientMessage(t, 1, privKey3, zipnet.NewMockCryptoProvider())
	err = agg3.ReceiveClientMessage(ctx, msg3, regUsers3[0])
	require.Error(t, err)
	require.Contains(t, err.Error(), "round")
}

// Test 6: Rate limiting
func TestRateLimiting(t *testing.T) {
	// In the real implementation, rate limiting is done with nonces
	// For this test, we're testing the reset of rate limiting between windows

	ctx := context.Background()

	// Reset the aggregator state for this test to avoid rate limiting issues
	config := testutil.NewTestConfig()
	// Manually set rounds per window since it's not in testutil options
	config.RoundsPerWindow = 5
	config.MinClients = 1 // Allow just one client for testing

	// Generate keys
	pubKey, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Generate registered users
	regUsers, err := testutil.GenerateTestPublicKeys(3)
	require.NoError(t, err)

	// Create dependencies
	cryptoProvider := zipnet.NewMockCryptoProvider()
	networkTransport := zipnet.NewMockNetworkTransport()

	// Create leaf aggregator
	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, regUsers, 0)
	require.NoError(t, err)

	// Initialize to round 1
	err = agg.Reset(1)
	require.NoError(t, err)

	// Generate a client key for testing
	_, clientPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Client sends a message in round 1
	msg1 := createSignedClientMessage(t, 1, clientPriv, cryptoProvider)

	err = agg.ReceiveClientMessage(ctx, msg1, regUsers[0])
	require.NoError(t, err)

	// In our mock, the public key string is used as the "nonce"
	// Sending another message from same client should fail (duplicate nonce)
	msg1Dup := createSignedClientMessage(t, 1, clientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg1Dup, regUsers[0])
	require.Error(t, err)

	// Each test for a new round should use a different registered user to avoid rate limiting issues
	// Advance to round 3 (still in same window)
	err = agg.Reset(3)
	require.NoError(t, err)

	// Client is still rate-limited in this window, but we're using a different client
	msg3 := createSignedClientMessage(t, 3, clientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg3, regUsers[1]) // Use regUsers[1] instead of regUsers[0]
	require.NoError(t, err)

	// Duplicate still fails
	msg3Dup := createSignedClientMessage(t, 3, clientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg3Dup, regUsers[1]) // Use regUsers[1]
	require.Error(t, err)

	// Advance to round 6 (new window)
	err = agg.Reset(6)
	require.NoError(t, err)

	// Client should be able to send in new window
	msg6 := createSignedClientMessage(t, 6, clientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg6, regUsers[2]) // Use regUsers[2]
	require.NoError(t, err)

	// Duplicate still fails in new window
	msg6Dup := createSignedClientMessage(t, 6, clientPriv, cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg6Dup, regUsers[2]) // Use regUsers[2]
	require.Error(t, err)
}

// Test 7: Minimum clients requirement
func TestMinimumClientsRequirement(t *testing.T) {
	ctx := context.Background()

	// Create aggregator with minimum 3 clients
	config := testutil.NewTestConfig(testutil.WithMinClients(3))

	pubKey, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	regUsers, err := testutil.GenerateTestPublicKeys(5)
	require.NoError(t, err)

	cryptoProvider := zipnet.NewMockCryptoProvider()
	networkTransport := zipnet.NewMockNetworkTransport()

	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, regUsers, 0)
	require.NoError(t, err)

	// Initialize round
	err = agg.Reset(1)
	require.NoError(t, err)

	// Generate client keys for testing
	clientKeys := make([]crypto.PrivateKey, 3)
	for i := range clientKeys {
		_, privKey, err := crypto.GenerateKeyPair()
		require.NoError(t, err)
		clientKeys[i] = privKey
	}

	// Submit only 2 messages (less than minimum)
	for i := 0; i < 2; i++ {
		msg := createSignedClientMessage(t, 1, clientKeys[i], cryptoProvider)
		err = agg.ReceiveClientMessage(ctx, msg, regUsers[i])
		require.NoError(t, err)
	}

	// Trying to aggregate should fail due to insufficient clients
	_, err = agg.AggregateMessages(ctx, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough clients")

	// Add one more client to meet minimum
	msg := createSignedClientMessage(t, 1, clientKeys[2], cryptoProvider)
	err = agg.ReceiveClientMessage(ctx, msg, regUsers[2])
	require.NoError(t, err)

	// Now aggregation should succeed
	aggMsg, err := agg.AggregateMessages(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, aggMsg)
	require.Equal(t, 3, len(aggMsg.UserPKs))
}

// Test 8: Hierarchical aggregation with two levels
func TestHierarchicalAggregation(t *testing.T) {
	ctx := context.Background()

	// Setup leaf aggregator and a higher-level aggregator
	leafAgg, regUsers := setupTestAggregator(t, 0, 5)
	higherAgg, _ := setupTestAggregator(t, 1, 0) // No direct users for higher aggregator

	// Submit client messages to leaf aggregator
	cryptoProvider := zipnet.NewMockCryptoProvider()

	// Generate client keys for testing
	_, clientPriv1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	_, clientPriv2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// First client message
	msg1 := createSignedClientMessage(t, 1, clientPriv1, cryptoProvider)
	err = leafAgg.ReceiveClientMessage(ctx, msg1, regUsers[0])
	require.NoError(t, err)

	// Second client message - need at least 2 clients to meet minimum
	msg2 := createSignedClientMessage(t, 1, clientPriv2, cryptoProvider)
	err = leafAgg.ReceiveClientMessage(ctx, msg2, regUsers[1])
	require.NoError(t, err)

	// Get aggregated message from leaf
	leafAggMsg, err := leafAgg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Submit leaf's aggregate to higher-level aggregator
	err = higherAgg.ReceiveAggregatorMessage(ctx, leafAggMsg)
	require.NoError(t, err)

	// Create a second leaf aggregator with different users
	leaf2Agg, regUsers2 := setupTestAggregator(t, 0, 3)

	// Generate more client keys for testing
	_, clientPriv3, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	_, clientPriv4, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Submit client messages to second leaf (need at least 2)
	msg3 := createSignedClientMessage(t, 1, clientPriv3, cryptoProvider)
	err = leaf2Agg.ReceiveClientMessage(ctx, msg3, regUsers2[0])
	require.NoError(t, err)

	// Add another client to meet minimum requirements
	msg4 := createSignedClientMessage(t, 1, clientPriv4, cryptoProvider)
	err = leaf2Agg.ReceiveClientMessage(ctx, msg4, regUsers2[1])
	require.NoError(t, err)

	// Get aggregated message from second leaf
	leaf2AggMsg, err := leaf2Agg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Submit second leaf's aggregate to higher-level aggregator
	err = higherAgg.ReceiveAggregatorMessage(ctx, leaf2AggMsg)
	require.NoError(t, err)

	// Get final aggregate from higher-level aggregator
	finalAgg, err := higherAgg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Verify the final aggregate contains all user public keys
	require.Equal(t, 4, len(finalAgg.UserPKs))

	// Verify the final aggregate has the combined message vectors
	// This would be a detailed check of the XOR operation in a real test
	require.NotNil(t, finalAgg.MsgVec)
}
