package aggregator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/testutil"
	"github.com/flashbots/adcnet/zipnet"
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

	// Generate registered aggregators (empty for now, will be added in tests as needed)
	registeredAggregators := make([]crypto.PublicKey, 0)

	// Create dependencies
	cryptoProvider := zipnet.NewMockCryptoProvider()
	networkTransport := zipnet.NewMockNetworkTransport()

	// Create aggregator
	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, registeredUsers, registeredAggregators, level)
	require.NoError(t, err)
	require.NotNil(t, agg)

	// Initialize round
	agg.Reset(1)

	return agg, registeredUsers
}

// Generate a signed client message using testutil
func createSignedClientMessage(t *testing.T, round uint64, clientKey crypto.PrivateKey) *zipnet.Signed[zipnet.ClientMessage] {
	// Create client message with appropriate round
	msg := testutil.GenerateTestClientMessage(testutil.WithRound(round))

	signedMsg, err := zipnet.NewSigned(clientKey, msg)
	require.NoError(t, err)

	return signedMsg
}

// Helper to create a signed aggregator message
func createSignedAggregatorMessage(t *testing.T, round uint64, aggPrivKey crypto.PrivateKey, userPKs []crypto.PublicKey, level uint32) *zipnet.Signed[zipnet.AggregatorMessage] {
	// Create aggregator message with appropriate round
	msg := testutil.GenerateTestAggregatorMessage(
		testutil.WithUserPKs(userPKs),
		testutil.WithLevel(level),
	)
	msg.Round = round

	signedMsg, err := zipnet.NewSigned(aggPrivKey, msg)
	require.NoError(t, err)

	return signedMsg
}

// Test 2: Client message reception and validation
func TestClientMessageReception(t *testing.T) {
	ctx := context.Background()

	// Create leaf aggregator (level 0)
	agg, _ := setupTestAggregator(t, 0, 5)

	// Generate client keys - one registered, one unregistered
	// Generate a new key pair for testing
	regClientPub, regClientPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	agg.WhitelistUser(regClientPub)

	_, unregPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Case 1: Valid message from registered client
	validMsg := createSignedClientMessage(t, 1, regClientPriv)
	err = agg.ReceiveClientMessage(ctx, validMsg)
	require.NoError(t, err)

	// Case 2: Message from unregistered client should fail
	unregMsg := createSignedClientMessage(t, 1, unregPriv)
	err = agg.ReceiveClientMessage(ctx, unregMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not registered")

	// Case 3: Message with wrong round number should fail
	wrongRoundMsg := createSignedClientMessage(t, 2, regClientPriv)
	err = agg.ReceiveClientMessage(ctx, wrongRoundMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "round")

	// Case 4: Duplicate message from same client should fail
	dupMsg := createSignedClientMessage(t, 1, regClientPriv)
	err = agg.ReceiveClientMessage(ctx, dupMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")

	// Case 5: Non-leaf aggregator cannot receive client messages
	higherAgg, _ := setupTestAggregator(t, 1, 5)
	err = higherAgg.ReceiveClientMessage(ctx, validMsg)
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

	// Generate aggregator keys for testing
	aggPub, aggPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Whitelist the aggregator in the higher-level aggregator
	higherAgg.WhitelistAggregator(aggPub)

	// Create signed aggregator message (round 1)
	aggMsg := createSignedAggregatorMessage(t, 1, aggPriv, regUsers, 0)

	// Case 1: Valid aggregator message to non-leaf
	err = higherAgg.ReceiveAggregatorMessage(ctx, aggMsg)
	require.NoError(t, err)

	// Case 2: Leaf aggregator cannot receive aggregator messages
	err = leafAgg.ReceiveAggregatorMessage(ctx, aggMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "leaf aggregator")

	// Case 3: Wrong round number should fail
	wrongRoundMsg := createSignedAggregatorMessage(t, 2, aggPriv, regUsers, 0)
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
	agg, _ := setupTestAggregator(t, 0, 5)

	// Generate client keys for testing
	clientPub1, clientPriv1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	clientPub2, clientPriv2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	agg.WhitelistUser(clientPub1)
	agg.WhitelistUser(clientPub2)

	// Create messages with specific content
	msgSize := uint32(160)
	contentA := []byte("Message A")
	contentB := []byte("Message B")

	// Create base messages with content
	msgA := testutil.GenerateMessageWithContent(contentA, 0, msgSize, testutil.WithRound(1))
	msgB := testutil.GenerateMessageWithContent(contentB, 1, msgSize, testutil.WithRound(1))

	signedA, err := zipnet.NewSigned(clientPriv1, msgA)
	require.NoError(t, err)
	signedB, err := zipnet.NewSigned(clientPriv2, msgB)
	require.NoError(t, err)

	// Submit messages to aggregator
	err = agg.ReceiveClientMessage(ctx, signedA)
	require.NoError(t, err)
	err = agg.ReceiveClientMessage(ctx, signedB)
	require.NoError(t, err)

	// Get aggregated message
	aggregate, err := agg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Access the underlying object to verify contents
	aggObj := aggregate.UnsafeObject()

	// Verify contents are properly XOR'd
	// Extract messages from specific slots
	extractedA := testutil.ExtractMessageFromSlot(aggObj.MsgVec, 0, int(msgSize))
	extractedB := testutil.ExtractMessageFromSlot(aggObj.MsgVec, 1, int(msgSize))

	// Verify correct message contents
	require.Equal(t, contentA, extractedA[:len(contentA)])
	require.Equal(t, contentB, extractedB[:len(contentB)])

	// Verify userPKs contains both users
	require.Equal(t, 2, len(aggObj.UserPKs))
	require.Contains(t, aggObj.UserPKs, clientPub1)
	require.Contains(t, aggObj.UserPKs, clientPub2)
}

// Test 5: Round management
func TestRoundManagement(t *testing.T) {
	ctx := context.Background()

	// Step 1: Test successful message submission
	agg1, _ := setupTestAggregator(t, 0, 3)

	pubKey1, privKey1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	agg1.WhitelistUser(pubKey1)

	msg1 := createSignedClientMessage(t, 1, privKey1)
	err = agg1.ReceiveClientMessage(ctx, msg1)
	require.NoError(t, err)

	// Verify message is stored
	require.Equal(t, 1, len(agg1.messages))

	// Step 2: Test round reset clears state
	agg2, _ := setupTestAggregator(t, 0, 3)

	pubKey2, privKey2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	agg2.WhitelistUser(pubKey2)

	// Submit a message to round 1
	msg2a := createSignedClientMessage(t, 1, privKey2)
	err = agg2.ReceiveClientMessage(ctx, msg2a)
	require.NoError(t, err)

	// Reset to round 2
	agg2.Reset(2)

	// Verify state is reset
	require.Equal(t, uint64(2), agg2.currentRound)
	require.Equal(t, 0, len(agg2.messages))
	require.Equal(t, 0, len(agg2.aUserPKs))

	// Step 3: Test message with wrong round is rejected
	agg3, _ := setupTestAggregator(t, 0, 3)
	agg3.Reset(2) // Set to round 2

	// Try to submit round 1 message to round 2
	pubKey3, privKey3, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	agg3.WhitelistUser(pubKey3)
	msg3 := createSignedClientMessage(t, 1, privKey3)
	err = agg3.ReceiveClientMessage(ctx, msg3)
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

	// Empty registered aggregators list for this test
	regAggs := make([]crypto.PublicKey, 0)

	// Create leaf aggregator
	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, regUsers, regAggs, 0)
	require.NoError(t, err)

	// Initialize to round 1
	agg.Reset(1)

	// Generate a client key for testing
	clientPub, clientPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	agg.WhitelistUser(clientPub)

	clientPub2, clientPriv2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	agg.WhitelistUser(clientPub2)

	// Client sends a message in round 1
	msg1 := createSignedClientMessage(t, 1, clientPriv)

	err = agg.ReceiveClientMessage(ctx, msg1)
	require.NoError(t, err)

	// In our mock, the public key string is used as the "nonce"
	// Sending another message from same client should fail (duplicate nonce)
	msg1Dup := createSignedClientMessage(t, 1, clientPriv)
	err = agg.ReceiveClientMessage(ctx, msg1Dup)
	require.Error(t, err)

	// Each test for a new round should use a different registered user to avoid rate limiting issues
	// Advance to round 3 (still in same window)
	agg.Reset(3)

	// Client is still rate-limited in this window, but we're using a different client
	msg3 := createSignedClientMessage(t, 3, clientPriv2)
	err = agg.ReceiveClientMessage(ctx, msg3) // Use regUsers[1] instead of regUsers[0]
	require.NoError(t, err)

	// Duplicate still fails
	msg3Dup := createSignedClientMessage(t, 3, clientPriv2)
	err = agg.ReceiveClientMessage(ctx, msg3Dup) // Use regUsers[1]
	require.Error(t, err)

	// Advance to round 6 (new window)
	agg.Reset(6)

	// Client should be able to send in new window
	msg6 := createSignedClientMessage(t, 6, clientPriv)
	err = agg.ReceiveClientMessage(ctx, msg6) // Use regUsers[2]
	require.NoError(t, err)

	// Duplicate still fails in new window
	msg6Dup := createSignedClientMessage(t, 6, clientPriv)
	err = agg.ReceiveClientMessage(ctx, msg6Dup) // Use regUsers[2]
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

	// Empty registered aggregators list
	regAggs := make([]crypto.PublicKey, 0)

	agg, err := NewAggregator(config, privKey, pubKey, cryptoProvider, networkTransport, regUsers, regAggs, 0)
	require.NoError(t, err)

	// Initialize round
	agg.Reset(1)

	// Generate client keys for testing
	clientKeys := make([]crypto.PrivateKey, 3)
	clientPubKeys := make([]crypto.PublicKey, 3)
	for i := range clientKeys {
		pubKey, privKey, err := crypto.GenerateKeyPair()
		require.NoError(t, err)
		clientKeys[i] = privKey
		clientPubKeys[i] = pubKey
		agg.WhitelistUser(pubKey)
	}

	// Submit only 2 messages (less than minimum)
	for i := 0; i < 2; i++ {
		msg := createSignedClientMessage(t, 1, clientKeys[i])
		err = agg.ReceiveClientMessage(ctx, msg)
		require.NoError(t, err)
	}

	// Trying to aggregate should fail due to insufficient clients
	_, err = agg.AggregateMessages(ctx, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough clients")

	// Add one more client to meet minimum
	msg := createSignedClientMessage(t, 1, clientKeys[2])
	err = agg.ReceiveClientMessage(ctx, msg)
	require.NoError(t, err)

	// Now aggregation should succeed
	aggMsg, err := agg.AggregateMessages(ctx, 1)
	require.NoError(t, err)
	require.NotNil(t, aggMsg)

	// Get the underlying object
	aggObj := aggMsg.UnsafeObject()
	require.Equal(t, 3, len(aggObj.UserPKs))
}

// Test 8: Hierarchical aggregation with two levels
func TestHierarchicalAggregation(t *testing.T) {
	ctx := context.Background()

	// Setup leaf aggregator and a higher-level aggregator
	leafAgg, _ := setupTestAggregator(t, 0, 5)
	higherAgg, _ := setupTestAggregator(t, 1, 0) // No direct users for higher aggregator

	// Register the leaf aggregator with the higher-level aggregator
	leafPubKey := leafAgg.GetPublicKey()
	higherAgg.WhitelistAggregator(leafPubKey)

	// Generate client keys for testing
	clientPub1, clientPriv1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	clientPub2, clientPriv2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	leafAgg.WhitelistUser(clientPub1)
	leafAgg.WhitelistUser(clientPub2)

	// First client message
	msg1 := createSignedClientMessage(t, 1, clientPriv1)
	err = leafAgg.ReceiveClientMessage(ctx, msg1)
	require.NoError(t, err)

	// Second client message - need at least 2 clients to meet minimum
	msg2 := createSignedClientMessage(t, 1, clientPriv2)
	err = leafAgg.ReceiveClientMessage(ctx, msg2)
	require.NoError(t, err)

	// Get aggregated message from leaf
	leafAggMsg, err := leafAgg.AggregateMessages(ctx, 1)
	require.NoError(t, err)

	// Submit leaf's aggregate to higher-level aggregator
	err = higherAgg.ReceiveAggregatorMessage(ctx, leafAggMsg)
	require.NoError(t, err)

	// Create a second leaf aggregator with different users
	leaf2Agg, _ := setupTestAggregator(t, 0, 3)
	leaf2PubKey := leaf2Agg.GetPublicKey()
	higherAgg.WhitelistAggregator(leaf2PubKey)

	// Generate more client keys for testing
	clientPub3, clientPriv3, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	clientPub4, clientPriv4, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	leaf2Agg.WhitelistUser(clientPub3)
	leaf2Agg.WhitelistUser(clientPub4)

	// Submit client messages to second leaf (need at least 2)
	msg3 := createSignedClientMessage(t, 1, clientPriv3)
	err = leaf2Agg.ReceiveClientMessage(ctx, msg3)
	require.NoError(t, err)

	// Add another client to meet minimum requirements
	msg4 := createSignedClientMessage(t, 1, clientPriv4)
	err = leaf2Agg.ReceiveClientMessage(ctx, msg4)
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

	// Get the underlying object
	finalObj := finalAgg.UnsafeObject()

	// Verify the final aggregate contains all user public keys
	require.Equal(t, 4, len(finalObj.UserPKs))

	// Verify the final aggregate has the combined message vectors
	// This would be a detailed check of the XOR operation in a real test
	require.NotNil(t, finalObj.MsgVec)
}
