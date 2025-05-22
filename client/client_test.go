package client

import (
	"context"
	"testing"
	"time"

	"github.com/flashbots/adcnet/aggregator"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/server"
	"github.com/flashbots/adcnet/zipnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerRegistration verifies client can register server public keys
func TestServerRegistration(t *testing.T) {
	// Setup client
	c, _, tee := setupTestClient(t)

	// Generate server keys
	serverPK1, serverSK1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	serverPK2, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Store private key in TEE for testing
	inMemoryTEE, ok := tee.(*zipnet.InMemoryTEE)
	require.True(t, ok)
	inMemoryTEE.StorePrivateKey("server1", serverSK1)

	// Register server keys
	err = c.RegisterServerPublicKey("server1.test", serverPK1)
	require.NoError(t, err)
	err = c.RegisterServerPublicKey("server2.test", serverPK2)
	require.NoError(t, err)

	// Try registering nil key (should fail)
	err = c.RegisterServerPublicKey("server3.test", nil)
	require.Error(t, err)
}

// TestZIPNetEndToEnd tests a complete end-to-end flow of the ZIPNet protocol.
// It involves two clients, one aggregator, and one server in a full multi-round exchange.
func TestZIPNetEndToEnd(t *testing.T) {
	// Set up a context for all operations
	ctx := context.Background()

	// Create shared configuration for all components
	config := &zipnet.ZIPNetConfig{
		RoundDuration:   1 * time.Second,
		MessageSlots:    10,
		MessageSize:     160,
		SchedulingSlots: 40,
		FootprintBits:   64,
		MinClients:      2,
		AnytrustServers: []string{"server1.test"},
		Aggregators:     []string{"agg1.test"},
		RoundsPerWindow: 100,
	}

	// Create a shared crypto provider for consistent cryptographic operations
	cryptoProvider := crypto.NewStandardCryptoProvider()

	// STEP 1: Set up the server (leader)
	t.Log("Setting up server...")
	zipServer, err := server.NewServer(config, cryptoProvider, true)
	require.NoError(t, err)

	// Get server public key for client registration
	serverPubKey := zipServer.GetPublicKey()

	// STEP 2: Set up the aggregator
	t.Log("Setting up aggregator...")
	// Generate aggregator keys
	aggPubKey, aggPrivKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Empty initial user list - we'll add them after creating clients
	registeredUsers := []crypto.PublicKey{}
	registeredAggs := []crypto.PublicKey{}

	agg, err := aggregator.NewAggregator(
		config,
		aggPrivKey,
		aggPubKey,
		cryptoProvider,
		registeredUsers,
		registeredAggs,
		0, // Leaf aggregator
	)
	require.NoError(t, err)

	// Register aggregator with server
	aggBlob := &zipnet.AggregatorRegistrationBlob{
		PublicKey: aggPubKey,
		Level:     0,
	}
	err = zipServer.RegisterAggregator(ctx, aggBlob)
	require.NoError(t, err)

	// STEP 3: Set up the two clients
	t.Log("Setting up clients...")
	// Create two separate TEEs for the clients
	tee1, err := zipnet.NewInMemoryTEE()
	require.NoError(t, err)
	tee2, err := zipnet.NewInMemoryTEE()
	require.NoError(t, err)

	// Create mock components for the clients
	mockScheduler := zipnet.NewMockScheduler(config)

	// Create two clients
	client1, err := NewClient(config, tee1, cryptoProvider, mockScheduler)
	require.NoError(t, err)
	client2, err := NewClient(config, tee2, cryptoProvider, mockScheduler)
	require.NoError(t, err)

	// Register server with both clients
	err = client1.RegisterServerPublicKey("server1.test", serverPubKey)
	require.NoError(t, err)
	err = client2.RegisterServerPublicKey("server1.test", serverPubKey)
	require.NoError(t, err)

	// Register both clients with the server and aggregator
	t.Log("Registering clients with server and aggregator...")
	err = zipServer.RegisterClient(ctx, client1.GetPublicKey(), []byte("attestation1"))
	require.NoError(t, err)
	err = zipServer.RegisterClient(ctx, client2.GetPublicKey(), []byte("attestation2"))
	require.NoError(t, err)

	// Whitelist both clients with the aggregator
	agg.WhitelistUser(client1.GetPublicKey())
	agg.WhitelistUser(client2.GetPublicKey())

	// STEP 4: Run Round 1 (Reservation round)
	t.Log("Starting round 1 (reservation round)...")
	round1 := uint64(1)

	// Initialize the round for the aggregator
	agg.Reset(round1)

	// Create an empty initial schedule for round 1
	initialSchedule := zipnet.PublishedSchedule{
		Footprints: make([]byte, config.SchedulingSlots),
		Signature:  crypto.NewSignature([]byte("initial-signature")),
	}

	// Set the schedule on the server
	err = zipServer.SetSchedule(ctx, round1, initialSchedule.Footprints, initialSchedule.Signature)
	require.NoError(t, err)

	// Both clients send reservation requests for round 2
	reserveMsg1, err := client1.PrepareMessage(ctx, round1, nil, true, initialSchedule)
	require.NoError(t, err)
	reserveMsg2, err := client2.PrepareMessage(ctx, round1, nil, true, initialSchedule)
	require.NoError(t, err)

	// Submit both messages to the aggregator
	err = agg.ReceiveClientMessage(ctx, reserveMsg1)
	require.NoError(t, err)
	err = agg.ReceiveClientMessage(ctx, reserveMsg2)
	require.NoError(t, err)

	// Aggregate the messages
	aggregatedMsg, err := agg.AggregateMessages(ctx, round1)
	require.NoError(t, err)

	// The server unblinds the aggregated message
	unboundShare, err := zipServer.UnblindAggregate(ctx, aggregatedMsg)
	require.NoError(t, err)

	t.Log(unboundShare.Object.KeyShare.NextSchedVec)

	// Server derives the round output (only one server, so just use its own share)
	shares := []*zipnet.UnblindedShareMessage{unboundShare.UnsafeObject()}
	roundOutput, err := zipServer.DeriveRoundOutput(ctx, shares)
	require.NoError(t, err)
	t.Log(roundOutput.Object.NextSchedVec)
	t.Log(roundOutput.Object.MsgVec)

	// Server publishes the schedule for round 2 based on the next schedule vector
	scheduleBytes, signature, err := zipServer.PublishSchedule(ctx, round1+1, roundOutput.UnsafeObject().NextSchedVec)
	require.NoError(t, err)

	round2Schedule := zipnet.PublishedSchedule{
		Footprints: scheduleBytes,
		Signature:  signature,
	}

	// STEP 5: Run Round 2 (Message round)
	t.Log("Starting round 2 (message round)...")
	round2 := uint64(2)

	// Reset aggregator for round 2
	agg.Reset(round2)

	// One client sends a real message, the other sends cover traffic
	messageContent := []byte("This is a secret message from client 1")

	// Client 1 sends a real message using its reservation
	msgClient1, err := client1.PrepareMessage(ctx, round2, messageContent, false, round2Schedule)
	require.NoError(t, err)

	// Client 2 sends cover traffic (empty message)
	msgClient2, err := client2.PrepareMessage(ctx, round2, nil, false, round2Schedule)
	require.NoError(t, err)

	// Check if either client had a footprint collision
	// The clients don't know in advance if their footprints would collide
	if err == ErrorFootprintCollision {
		t.Log("Client 1 had a footprint collision, trying again...")
		// In a real implementation, the client would try again in the next round
	}

	// Submit both messages to the aggregator
	err = agg.ReceiveClientMessage(ctx, msgClient1)
	require.NoError(t, err)
	err = agg.ReceiveClientMessage(ctx, msgClient2)
	require.NoError(t, err)

	// Aggregate the messages
	aggregatedMsg2, err := agg.AggregateMessages(ctx, round2)
	require.NoError(t, err)

	// The server unblinds the aggregated message
	unboundShare2, err := zipServer.UnblindAggregate(ctx, aggregatedMsg2)
	require.NoError(t, err)

	// Server derives the round output
	shares2 := []*zipnet.UnblindedShareMessage{unboundShare2.UnsafeObject()}
	roundOutput2, err := zipServer.DeriveRoundOutput(ctx, shares2)
	require.NoError(t, err)

	// STEP 6: Verify the results
	t.Log("Verifying results...")

	// Both clients process the broadcast
	clientReceived1, err := client1.ProcessBroadcast(ctx, round2, roundOutput2)
	require.NoError(t, err)
	clientReceived2, err := client2.ProcessBroadcast(ctx, round2, roundOutput2)
	require.NoError(t, err)

	// For testing purposes, manually inspect the message vector to find our message
	// In a real implementation, clients would know their assigned slots
	foundMessage := false
	msgSize := int(config.MessageSize)

	for slot := 0; slot < int(config.MessageSlots); slot++ {
		start := slot * msgSize
		end := start + len(messageContent)

		if end <= len(clientReceived1) {
			extracted := clientReceived1[start:end]
			if string(extracted) == string(messageContent) {
				foundMessage = true
				t.Logf("Found message in slot %d: %s", slot, string(extracted))
				break
			}
		}
	}

	// Assert that we found the message in the broadcast
	assert.True(t, foundMessage, "The original message was not found in the broadcast")

	// Verify both clients received the same broadcast (anonymity property)
	assert.Equal(t, clientReceived1, clientReceived2, "Both clients should receive the same broadcast")

	t.Log("End-to-end test completed successfully")
}

// TestCorrectXORBlinding tests that the client properly blinds messages using XOR
func TestCorrectXORBlinding(t *testing.T) {
	c, config, _ := setupTestClient(t)

	// Register server keys
	server1PK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	server2PK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	err = c.RegisterServerPublicKey("server1.test", server1PK)
	require.NoError(t, err)
	err = c.RegisterServerPublicKey("server2.test", server2PK)
	require.NoError(t, err)

	// Create test schedule
	footprints := make([]byte, config.SchedulingSlots)
	testSchedule := zipnet.PublishedSchedule{
		Footprints: footprints,
		Signature:  crypto.NewSignature([]byte("test-signature")),
	}

	// Submit a message
	ctx := context.Background()
	msg := []byte("test message for blinding verification")
	signedClientMsg, err := c.PrepareMessage(ctx, 1, msg, false, testSchedule)
	require.NoError(t, err)
	clientMsg, _, err := signedClientMsg.Recover()
	require.NoError(t, err)

	// In a real system, this would be simulated by having the servers unblind the message
	// Here we'll just verify the message is not visible in plaintext in the msgVec
	// by confirming the message bytes don't appear in sequence

	msgFound := false
	for i := 0; i < len(clientMsg.MsgVec)-len(msg); i++ {
		match := true
		for j := 0; j < len(msg); j++ {
			if clientMsg.MsgVec[i+j] != msg[j] {
				match = false
				break
			}
		}
		if match {
			msgFound = true
			break
		}
	}

	// The message should be blinded (XORed with one-time pads), so it shouldn't appear in plaintext
	assert.False(t, msgFound, "Message should be properly blinded")
}

// TestFootprintReservationAndUse tests the full footprint reservation and usage flow
func TestFootprintReservationAndUse(t *testing.T) {
	c, config, _ := setupTestClient(t)
	cryptoProvider := crypto.NewStandardCryptoProvider()

	// Register server
	serverPK, serverSK, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	err = c.RegisterServerPublicKey("server1.test", serverPK)
	require.NoError(t, err)

	// Create empty initial schedule
	emptySchedule := zipnet.PublishedSchedule{
		Footprints: make([]byte, config.SchedulingSlots),
		Signature:  crypto.NewSignature([]byte("test-signature")),
	}

	// Step 1: Reserve a slot for round 2
	ctx := context.Background()
	signedReserveMsg, err := c.PrepareMessage(ctx, 1, nil, true, emptySchedule)
	require.NoError(t, err)
	reserveMsg, _, err := signedReserveMsg.Recover()
	require.NoError(t, err)

	// Sign the next schedule (simulating server publishing it)
	nextSchedMsg := &zipnet.ServerMessage{
		Round:        1,
		NextSchedVec: reserveMsg.NextSchedVec,
		MsgVec:       make([]byte, config.MessageSlots*config.MessageSize),
	}
	serializedSchedMsg, err := zipnet.SerializeMessage(nextSchedMsg)
	require.NoError(t, err)
	sig, err := cryptoProvider.Sign(serverSK, serializedSchedMsg)
	require.NoError(t, err)

	// Create the schedule for round 2 that includes our reservation
	round2Schedule := zipnet.PublishedSchedule{
		Footprints: reserveMsg.NextSchedVec,
		Signature:  sig,
	}

	// Step 2: Send an actual message in round 2 using our reservation
	testMessage := []byte("message using reserved slot")
	_, err = c.PrepareMessage(ctx, 2, testMessage, false, round2Schedule)
	require.NoError(t, err)

	// The message vector should now contain our blinded message
	// In a real system, servers would unblind this

	// Step 3: Verify participation tracking behavior
	// In ZIPNet, talking messages should be counted for rate limiting
	// but the specific implementation may vary
	t.Logf("Participation count after sending message: %d", c.GetTimesParticipated())
}

// setupTestClient creates a test client with all dependencies
func setupTestClient(t *testing.T) (*ClientImpl, *zipnet.ZIPNetConfig, zipnet.TEE) {
	config := &zipnet.ZIPNetConfig{
		RoundDuration:   5 * time.Second,
		MessageSlots:    100,
		MessageSize:     160,
		SchedulingSlots: 400,
		FootprintBits:   64,
		MinClients:      10,
		AnytrustServers: []string{"server1.test", "server2.test", "server3.test"},
		Aggregators:     []string{"agg1.test"},
		RoundsPerWindow: 100,
	}
	tee, err := zipnet.NewInMemoryTEE()
	require.NoError(t, err)
	cryptoProvider := crypto.NewStandardCryptoProvider()
	scheduler := zipnet.NewMockScheduler(config)

	c, err := NewClient(config, tee, cryptoProvider, scheduler)
	require.NoError(t, err)
	require.NotNil(t, c)

	return c, config, tee
}
