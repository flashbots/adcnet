package server

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

// Helper function to create test servers
func setupTestServer(t *testing.T, isLeader bool) *ServerImpl {
	config := &zipnet.ZIPNetConfig{
		MessageSlots:    100,
		MessageSize:     160,
		SchedulingSlots: 400,
		MinClients:      2,
	}
	cryptoProvider := zipnet.NewMockCryptoProvider()
	network := zipnet.NewMockNetworkTransport()

	server, err := NewServer(config, cryptoProvider, network, isLeader)
	require.NoError(t, err)
	require.NotNil(t, server)

	return server
}

// Helper to generate test client data
func registerTestClients(t *testing.T, server *ServerImpl, count int) []crypto.PublicKey {
	ctx := context.Background()
	clientKeys := make([]crypto.PublicKey, count)

	for i := 0; i < count; i++ {
		clientPK, _, err := crypto.GenerateKeyPair()
		require.NoError(t, err)

		err = server.RegisterClient(ctx, clientPK, []byte("test-attestation"))
		require.NoError(t, err)

		clientKeys[i] = clientPK
	}

	return clientKeys
}

// Helper to register same clients with multiple servers
func registerSameClients(t *testing.T, servers []*ServerImpl, count int) []crypto.PublicKey {
	ctx := context.Background()
	clientKeys := make([]crypto.PublicKey, count)

	for i := 0; i < count; i++ {
		clientPK, _, err := crypto.GenerateKeyPair()
		require.NoError(t, err)

		for _, server := range servers {
			err = server.RegisterClient(ctx, clientPK, []byte("test-attestation"))
			require.NoError(t, err)
		}

		clientKeys[i] = clientPK
	}

	return clientKeys
}

// Helper to create a test message vector with content in a specific slot
func createMessageVector(msgSize, totalSlots uint32, slot uint32, content []byte) []byte {
	msgVec := make([]byte, msgSize*totalSlots)
	startPos := slot * msgSize

	// Copy content into the specified slot
	copy(msgVec[startPos:], content)

	return msgVec
}

// Test 1: Basic server creation and registration
func TestServerCreationAndRegistration(t *testing.T) {
	// Test server creation
	server := setupTestServer(t, false)
	require.NotNil(t, server.publicKey)
	require.NotNil(t, server.kemPublicKey)
	require.False(t, server.isLeader)

	// Test client registration
	ctx := context.Background()
	clientPK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	err = server.RegisterClient(ctx, clientPK, []byte("test-attestation"))
	require.NoError(t, err)

	// Test aggregator registration
	aggPK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	aggBlob := &zipnet.AggregatorRegistrationBlob{
		PublicKey: aggPK,
		Level:     0,
	}

	err = server.RegisterAggregator(ctx, aggBlob)
	require.NoError(t, err)

	// Test server registration
	otherServerPK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	otherServerKemPK, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	serverBlob := &zipnet.ServerRegistrationBlob{
		PublicKey:    otherServerPK,
		KemPublicKey: otherServerKemPK,
		IsLeader:     false,
	}

	initialGroupSize := server.anytrustGroupSize
	err = server.RegisterServer(ctx, serverBlob)
	require.NoError(t, err)
	require.Equal(t, initialGroupSize+1, server.anytrustGroupSize)
}

// Test 2: Anytrust model - minimum client requirements
func TestAnytrustMinClients(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t, false)

	// Create a test schedule
	round := uint64(1)
	scheduleData := make([]byte, 400)
	server.schedules[round] = scheduleData

	// Register only one client (less than minimum)
	clientKeys := registerTestClients(t, server, 1)

	// Create an aggregate message with insufficient clients
	aggregateMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, 16000),
		},
		UserPKs:      clientKeys,
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Should fail due to not enough clients
	_, err := server.UnblindAggregate(ctx, aggregateMsg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough clients")

	// Register one more client to meet minimum
	clientKeys = append(clientKeys, registerTestClients(t, server, 1)...)
	aggregateMsg.UserPKs = clientKeys

	// Should now succeed
	_, err = server.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)
}

// Test 3: Message unblinding
func TestUnblindAggregate(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t, false)

	// Create a test schedule
	round := uint64(1)
	scheduleData := make([]byte, 400)
	server.schedules[round] = scheduleData

	// Register clients
	clientKeys := registerTestClients(t, server, 3)

	// Create a message with content
	msgContent := []byte("Test message in slot 0")
	msgVec := createMessageVector(server.config.MessageSize, 100, 0, msgContent)

	// Create an aggregate message
	aggregateMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       msgVec,
		},
		UserPKs:      clientKeys,
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Get unblinded share
	share, err := server.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)
	require.NotNil(t, share)
	require.Equal(t, server.publicKey, share.ServerPublicKey)
	require.Equal(t, round, share.KeyShare.Round)

	// Check key share has expected dimensions
	require.Equal(t, len(aggregateMsg.NextSchedVec), len(share.KeyShare.NextSchedVec))
	require.Equal(t, len(aggregateMsg.MsgVec), len(share.KeyShare.MsgVec))
}

// Test 4: Key ratcheting for forward secrecy
func TestKeyRatcheting(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t, false)

	// Register 2 clients (to meet minimum client requirement)
	clientKeys := registerTestClients(t, server, 2)
	clientKey := clientKeys[0].String()

	// Get initial shared secret
	initialSecret := server.sharedSecrets[clientKey]

	// Create a test schedule
	round := uint64(1)
	scheduleData := make([]byte, 400)
	server.schedules[round] = scheduleData

	// Create a dummy aggregate to trigger ratcheting
	aggregateMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, 16000),
		},
		UserPKs:      clientKeys, // Include both clients to meet minimum
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Process the aggregate (this should ratchet the key)
	_, err := server.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)

	// Verify key was ratcheted
	ratchetedSecret := server.sharedSecrets[clientKey]

	// Keys should be different after ratcheting
	require.NotEqual(t, initialSecret, ratchetedSecret)
}

// Test 5: Leader-follower server roles
func TestLeaderFollowerRoles(t *testing.T) {
	ctx := context.Background()

	// Create leader and follower servers
	leaderServer := setupTestServer(t, true)
	followerServer := setupTestServer(t, false)

	// Register the same clients with both servers
	clientKeys := registerSameClients(t, []*ServerImpl{leaderServer, followerServer}, 2)

	// Set up schedules for both servers
	round := uint64(1)
	scheduleData := make([]byte, 400)

	leaderServer.schedules[round] = scheduleData
	followerServer.schedules[round] = scheduleData

	// Create test aggregate message
	aggregateMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, 16000),
		},
		UserPKs:      clientKeys,
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Test that only leader can derive round output
	leaderShare, err := leaderServer.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)

	followerShare, err := followerServer.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)

	// Set expected number of shares
	leaderServer.anytrustGroupSize = 2

	// Both shares must use the same encrypted message object
	followerShare.EncryptedMsg = leaderShare.EncryptedMsg

	shares := []*zipnet.UnblindedShareMessage{leaderShare, followerShare}
	output, err := leaderServer.DeriveRoundOutput(ctx, shares)
	require.NoError(t, err)
	require.NotNil(t, output)

	// Follower should not be able to derive output
	_, err = followerServer.DeriveRoundOutput(ctx, shares)
	require.Error(t, err)
	require.Contains(t, err.Error(), "only leader")
}

// Test 6: Combining unblinded shares to retrieve original message
func TestCombiningUnblindedShares(t *testing.T) {
	ctx := context.Background()

	// Create leader server
	leaderServer := setupTestServer(t, true)
	leaderServer.anytrustGroupSize = 3 // Leader + 2 followers

	// Create a test schedule
	round := uint64(1)
	scheduleData := make([]byte, 400)
	leaderServer.schedules[round] = scheduleData

	// Create test message
	originalMessage := []byte("This is the original message")
	msgSlot := uint32(0)

	// Create encrypted message - in a real system this would be XOR'd with pads from all servers
	encryptedMsg := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       createMessageVector(leaderServer.config.MessageSize, 100, msgSlot, originalMessage),
		},
		UserPKs:      []crypto.PublicKey{}, // Not relevant for this test
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Create key shares - in a real system these would be derived from shared secrets
	// For this test, all zeros (since our message is already in the clear)
	keyShare1 := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: make([]byte, 400),
		MsgVec:       make([]byte, 16000),
	}

	keyShare2 := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: make([]byte, 400),
		MsgVec:       make([]byte, 16000),
	}

	keyShare3 := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: make([]byte, 400),
		MsgVec:       make([]byte, 16000),
	}

	// Create unblinded shares from all servers
	server1PK, _, _ := crypto.GenerateKeyPair()
	server2PK, _, _ := crypto.GenerateKeyPair()
	server3PK, _, _ := crypto.GenerateKeyPair()

	share1 := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    encryptedMsg,
		KeyShare:        keyShare1,
		ServerPublicKey: server1PK,
	}

	share2 := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    encryptedMsg,
		KeyShare:        keyShare2,
		ServerPublicKey: server2PK,
	}

	share3 := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    encryptedMsg,
		KeyShare:        keyShare3,
		ServerPublicKey: server3PK,
	}

	// Combine shares
	shares := []*zipnet.UnblindedShareMessage{share1, share2, share3}
	output, err := leaderServer.DeriveRoundOutput(ctx, shares)
	require.NoError(t, err)

	// Verify the original message was recovered
	startPos := msgSlot * leaderServer.config.MessageSize
	recoveredMessage := output.Message.MsgVec[startPos : startPos+uint32(len(originalMessage))]
	require.Equal(t, originalMessage, recoveredMessage)
}

// Test 7: Anytrust model preserves anonymity with one honest server
func TestAnytrustAnonymity(t *testing.T) {
	ctx := context.Background()

	// Create honest server (leader)
	honestServer := setupTestServer(t, true)
	honestServer.anytrustGroupSize = 3 // One honest + two compromised

	// Register two clients
	client1PK, _, _ := crypto.GenerateKeyPair()
	client2PK, _, _ := crypto.GenerateKeyPair()

	err := honestServer.RegisterClient(ctx, client1PK, []byte("test-attestation"))
	require.NoError(t, err)

	err = honestServer.RegisterClient(ctx, client2PK, []byte("test-attestation"))
	require.NoError(t, err)

	// Create a test schedule
	round := uint64(1)
	scheduleData := make([]byte, 400)
	honestServer.schedules[round] = scheduleData

	// Test messages
	message1 := []byte("Message from client 1")
	message2 := []byte("Message from client 2")

	// Prepare message slots
	msgSlot1 := uint32(0)
	msgSlot2 := uint32(1)

	// Case 1: Client 1 sends message 1, Client 2 sends message 2
	// In a real scenario, the aggregate would be the result of XORing client ciphertexts
	// For testing, we'll use cleartext messages and simulate the server's unblinding

	// Create the expected final output for Case 1
	finalMsgVec1 := make([]byte, honestServer.config.MessageSize*100)
	copy(finalMsgVec1[msgSlot1*honestServer.config.MessageSize:], message1)
	copy(finalMsgVec1[msgSlot2*honestServer.config.MessageSize:], message2)

	// Create an "encrypted" aggregate message that we'll decrypt to the expected output
	// For testing purposes, we'll use random data as our encrypted message
	encryptedMsgVec1 := make([]byte, len(finalMsgVec1))
	_, err = rand.Read(encryptedMsgVec1)
	require.NoError(t, err)

	// Create the aggregate message
	aggMsg1 := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       encryptedMsgVec1,
		},
		UserPKs:      []crypto.PublicKey{client1PK, client2PK},
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Case 2: Client 1 sends message 2, Client 2 sends message 1 (swapped)
	// Create the expected final output for Case 2
	finalMsgVec2 := make([]byte, honestServer.config.MessageSize*100)
	copy(finalMsgVec2[msgSlot1*honestServer.config.MessageSize:], message2)
	copy(finalMsgVec2[msgSlot2*honestServer.config.MessageSize:], message1)

	// Create another "encrypted" aggregate message
	encryptedMsgVec2 := make([]byte, len(finalMsgVec2))
	_, err = rand.Read(encryptedMsgVec2)
	require.NoError(t, err)

	// Create the second aggregate message
	aggMsg2 := &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       encryptedMsgVec2,
		},
		UserPKs:      []crypto.PublicKey{client1PK, client2PK},
		AggregatorID: "test-agg",
		Level:        0,
	}

	// Create public keys for all three servers
	honestServerPK := honestServer.publicKey
	compromisedPK1, _, _ := crypto.GenerateKeyPair()
	compromisedPK2, _, _ := crypto.GenerateKeyPair()

	// Create KeyShare for honest server for case 1
	// We need to compute what the honest server must contribute to get the final result
	honestKeyShare1 := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: make([]byte, 400),
		MsgVec:       make([]byte, len(encryptedMsgVec1)),
	}

	// XOR with encrypted message to determine what we need to add
	for i := 0; i < len(encryptedMsgVec1); i++ {
		honestKeyShare1.MsgVec[i] = encryptedMsgVec1[i] ^ finalMsgVec1[i]
	}

	// Create unblinded share from honest server for case 1
	honestShare1 := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    aggMsg1,
		KeyShare:        honestKeyShare1,
		ServerPublicKey: honestServerPK,
		Signature:       crypto.NewSignature([]byte("honest-sig-1")),
	}

	// Create KeyShare for honest server for case 2
	honestKeyShare2 := &zipnet.ScheduleMessage{
		Round:        round,
		NextSchedVec: make([]byte, 400),
		MsgVec:       make([]byte, len(encryptedMsgVec2)),
	}

	// XOR with encrypted message to determine what we need to add for case 2
	for i := 0; i < len(encryptedMsgVec2); i++ {
		honestKeyShare2.MsgVec[i] = encryptedMsgVec2[i] ^ finalMsgVec2[i]
	}

	// Create unblinded share from honest server for case 2
	honestShare2 := &zipnet.UnblindedShareMessage{
		EncryptedMsg:    aggMsg2,
		KeyShare:        honestKeyShare2,
		ServerPublicKey: honestServerPK,
		Signature:       crypto.NewSignature([]byte("honest-sig-2")),
	}

	// Create compromised server shares (zero contribution for simplicity)
	// These could be anything - they won't affect the anonymity property
	compShare1A := &zipnet.UnblindedShareMessage{
		EncryptedMsg: aggMsg1,
		KeyShare: &zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, len(encryptedMsgVec1)),
		},
		ServerPublicKey: compromisedPK1,
		Signature:       crypto.NewSignature([]byte("comp1-sig-A")),
	}

	compShare2A := &zipnet.UnblindedShareMessage{
		EncryptedMsg: aggMsg1,
		KeyShare: &zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, len(encryptedMsgVec1)),
		},
		ServerPublicKey: compromisedPK2,
		Signature:       crypto.NewSignature([]byte("comp2-sig-A")),
	}

	compShare1B := &zipnet.UnblindedShareMessage{
		EncryptedMsg: aggMsg2,
		KeyShare: &zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, len(encryptedMsgVec2)),
		},
		ServerPublicKey: compromisedPK1,
		Signature:       crypto.NewSignature([]byte("comp1-sig-B")),
	}

	compShare2B := &zipnet.UnblindedShareMessage{
		EncryptedMsg: aggMsg2,
		KeyShare: &zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       make([]byte, len(encryptedMsgVec2)),
		},
		ServerPublicKey: compromisedPK2,
		Signature:       crypto.NewSignature([]byte("comp2-sig-B")),
	}

	// Derive outputs for both cases
	sharesA := []*zipnet.UnblindedShareMessage{honestShare1, compShare1A, compShare2A}
	sharesB := []*zipnet.UnblindedShareMessage{honestShare2, compShare1B, compShare2B}

	outputA, err := honestServer.DeriveRoundOutput(ctx, sharesA)
	require.NoError(t, err)

	outputB, err := honestServer.DeriveRoundOutput(ctx, sharesB)
	require.NoError(t, err)

	// Extract messages from both outputs
	msgSize := int(honestServer.config.MessageSize)

	// Case 1 results: client1 = message1, client2 = message2
	extractedA1 := outputA.Message.MsgVec[msgSlot1*uint32(msgSize) : msgSlot1*uint32(msgSize)+uint32(len(message1))]
	extractedA2 := outputA.Message.MsgVec[msgSlot2*uint32(msgSize) : msgSlot2*uint32(msgSize)+uint32(len(message2))]

	// Case 2 results: client1 = message2, client2 = message1
	extractedB1 := outputB.Message.MsgVec[msgSlot1*uint32(msgSize) : msgSlot1*uint32(msgSize)+uint32(len(message2))]
	extractedB2 := outputB.Message.MsgVec[msgSlot2*uint32(msgSize) : msgSlot2*uint32(msgSize)+uint32(len(message1))]

	// Verify the extracted messages match what we expect
	require.Equal(t, message1, extractedA1)
	require.Equal(t, message2, extractedA2)

	require.Equal(t, message2, extractedB1)
	require.Equal(t, message1, extractedB2)

	// Verify outputs are different (proving swapped messages)
	require.NotEqual(t, outputA.Message.MsgVec, outputB.Message.MsgVec)

	// The key point: Honest and compromised servers cannot tell which client sent which message,
	// because we can generate valid server shares for any possible assignment of messages to clients
}
