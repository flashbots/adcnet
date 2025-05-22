package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/flashbots/adcnet/aggregator"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/server"
	"github.com/flashbots/adcnet/testutil"
	"github.com/flashbots/adcnet/zipnet"
)

// TestClientHandlerEndToEnd tests the complete flow of the ZIPNet protocol
// with the improved message queueing and slot reservation approach
func TestClientHandlerEndToEnd(t *testing.T) {
	// Set up test context
	ctx := context.Background()

	// Create test configuration with small values for testing
	config := testutil.NewTestConfig(
		testutil.WithRoundDuration(2*time.Second),
		testutil.WithMinClients(2), // Minimum 2 clients required
		testutil.WithMessageSize(160),
		testutil.WithMessageSlots(10),
		testutil.WithSchedulingSlots(40),
	)

	// Create standard crypto provider for all components
	cryptoProvider := crypto.NewStandardCryptoProvider()

	// ========== 1. SET UP SERVER ==========
	// Create and setup server components
	leaderServer, err := server.NewServer(config, cryptoProvider, true)
	require.NoError(t, err)

	// Create server handler and routes
	serverRouter := chi.NewRouter()
	leaderHandler := server.NewServerHandler(leaderServer, nil)
	leaderHandler.RegisterRoutes(serverRouter)

	// Create test server for handling HTTP requests
	serverTS := httptest.NewServer(serverRouter)
	defer serverTS.Close()

	// ========== 2. SET UP AGGREGATOR ==========
	// Generate aggregator keys
	aggPK, aggSK, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Create a mock network transport for the aggregator
	aggTransport := &TestNetworkTransport{
		ServerURL: serverTS.URL,
	}

	config.AnytrustServers = []string{serverTS.URL}

	// Create the aggregator
	agg, err := aggregator.NewAggregator(
		config,
		aggSK,
		aggPK,
		cryptoProvider,
		nil, // Empty initial user list
		nil, // Empty initial aggregators list
		0,   // Level 0 (leaf aggregator)
	)
	require.NoError(t, err)

	// Create aggregator handler and routes
	aggRouter := chi.NewRouter()
	aggHandler := aggregator.NewAggregatorHandler(agg, aggTransport)
	aggHandler.RegisterRoutes(aggRouter)

	// Create test server for aggregator
	aggTS := httptest.NewServer(aggRouter)
	defer aggTS.Close()

	// ========== 3. REGISTER AGGREGATOR WITH SERVER ==========
	aggRegData := &zipnet.AggregatorRegistrationBlob{
		PublicKey: aggPK,
		Level:     0,
	}
	aggRegBytes, err := json.Marshal(aggRegData)
	require.NoError(t, err)

	regAggReq, err := http.NewRequest("POST", fmt.Sprintf("%s/server/register-aggregator", serverTS.URL), bytes.NewReader(aggRegBytes))
	require.NoError(t, err)
	regAggReq.Header.Set("Content-Type", "application/json")

	regAggResp, err := http.DefaultClient.Do(regAggReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, regAggResp.StatusCode)
	regAggResp.Body.Close()

	// ========== 4. SET UP FIRST CLIENT ==========
	// Create TEE, transport, and scheduler for the first client
	tee1, err := zipnet.NewInMemoryTEE()
	require.NoError(t, err)

	// Update config to use our test server URLs
	config.Aggregators = []string{aggTS.URL}

	clientTransport1 := &TestNetworkTransport{
		AggregatorURL: aggTS.URL,
		ServerURL:     serverTS.URL,
	}
	scheduler1 := zipnet.NewMockScheduler(config)

	// Create first client
	client1, err := NewClient(config, tee1, cryptoProvider, scheduler1)
	require.NoError(t, err)

	// ========== 5. SET UP SECOND CLIENT FOR COVER TRAFFIC ==========
	// Create a second client to meet the minimum clients requirement
	tee2, err := zipnet.NewInMemoryTEE()
	require.NoError(t, err)

	clientTransport2 := &TestNetworkTransport{
		AggregatorURL: aggTS.URL,
		ServerURL:     serverTS.URL,
	}
	scheduler2 := zipnet.NewMockScheduler(config)

	client2, err := NewClient(config, tee2, cryptoProvider, scheduler2)
	require.NoError(t, err)

	// ========== 6. REGISTER BOTH CLIENTS ==========
	// Register the first client with server
	clientPK1 := client1.GetPublicKey()
	attestation1, err := tee1.Attest()
	require.NoError(t, err)

	err = leaderServer.RegisterClient(ctx, clientPK1, attestation1)
	require.NoError(t, err)

	// Register the second client with server
	clientPK2 := client2.GetPublicKey()
	attestation2, err := tee2.Attest()
	require.NoError(t, err)

	err = leaderServer.RegisterClient(ctx, clientPK2, attestation2)
	require.NoError(t, err)

	// Register both clients with the aggregator
	regClient1Bytes, err := zipnet.SerializeMessage(&clientPK1)
	require.NoError(t, err)

	regClient1Req, err := http.NewRequest("POST", fmt.Sprintf("%s/aggregator/register-user", aggTS.URL), bytes.NewReader(regClient1Bytes))
	require.NoError(t, err)
	regClient1Req.Header.Set("Content-Type", "application/json")

	regClient1Resp, err := http.DefaultClient.Do(regClient1Req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, regClient1Resp.StatusCode)
	regClient1Resp.Body.Close()

	regClient2Bytes, err := zipnet.SerializeMessage(&clientPK2)
	require.NoError(t, err)

	regClient2Req, err := http.NewRequest("POST", fmt.Sprintf("%s/aggregator/register-user", aggTS.URL), bytes.NewReader(regClient2Bytes))
	require.NoError(t, err)
	regClient2Req.Header.Set("Content-Type", "application/json")

	regClient2Resp, err := http.DefaultClient.Do(regClient2Req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, regClient2Resp.StatusCode)
	regClient2Resp.Body.Close()

	// ========== 7. CREATE HANDLERS FOR BOTH CLIENTS ==========
	// First client handler (will send actual messages)
	clientRouter1 := chi.NewRouter()
	clientHandler1 := NewClientHandler(client1, clientTransport1)
	clientHandler1.leaderServerID = serverTS.URL
	clientHandler1.leaderPK = leaderServer.GetPublicKey()
	clientHandler1.RegisterRoutes(clientRouter1)

	// Second client handler (will only send cover traffic)
	clientRouter2 := chi.NewRouter()
	clientHandler2 := NewClientHandler(client2, clientTransport2)
	clientHandler2.leaderServerID = serverTS.URL
	clientHandler2.leaderPK = leaderServer.GetPublicKey()
	clientHandler2.RegisterRoutes(clientRouter2)

	// Create test servers for both clients
	clientTS1 := httptest.NewServer(clientRouter1)
	defer clientTS1.Close()

	clientTS2 := httptest.NewServer(clientRouter2)
	defer clientTS2.Close()

	// Register server's public key with both clients
	serverPK := leaderServer.GetPublicKey()
	err = client1.RegisterServerPublicKey(serverTS.URL, serverPK)
	require.NoError(t, err)

	err = client2.RegisterServerPublicKey(serverTS.URL, serverPK)
	require.NoError(t, err)

	// ========== 8. PUBLISH SCHEDULES FOR MULTIPLE ROUNDS ==========
	var startRound uint64 = zipnet.CurrentRound(config.RoundDuration)
	leaderHandler.PublishScheduleFor(startRound)
	require.NoError(t, err)

	// ========== 9. START BACKGROUND PROCESSES ==========
	// First start the server and aggregator background processes
	aggHandler.RunInBackground()
	leaderHandler.RunInBackground()

	// Then start client handlers after server and aggregator are ready
	// This ensures clients sync properly with the aggregator's round
	clientHandler1.RunInBackground()
	clientHandler2.RunInBackground()

	// ========== 10. QUEUE MESSAGES FOR DELIVERY ==========
	// Create and queue multiple test messages for the first client
	for i := 0; i < 3; i++ {
		msgBytes := []byte(fmt.Sprintf("Test message %d", i))

		msgSubmitReq, err := http.NewRequest("POST", fmt.Sprintf("%s/client/message", clientTS1.URL), bytes.NewReader(msgBytes))
		require.NoError(t, err)
		msgSubmitReq.Header.Set("Content-Type", "application/json")

		msgSubmitResp, err := http.DefaultClient.Do(msgSubmitReq)
		require.NoError(t, err)

		if msgSubmitResp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(msgSubmitResp.Body)
			t.Logf("Message submission failed: %s", string(body))
		}
		assert.Equal(t, http.StatusAccepted, msgSubmitResp.StatusCode)

		// Read and log the response to verify queueing is working
		var response map[string]interface{}
		err = json.NewDecoder(msgSubmitResp.Body).Decode(&response)
		require.NoError(t, err)
		msgSubmitResp.Body.Close()

		t.Logf("Message %d queued, response: %v", i, response)
	}

	// ========== 11. CHECK INITIAL CLIENT STATUS ==========
	statusReq, err := http.NewRequest("GET", fmt.Sprintf("%s/client/status", clientTS1.URL), nil)
	require.NoError(t, err)

	statusResp, err := http.DefaultClient.Do(statusReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusResp.StatusCode)

	var clientStatus map[string]interface{}
	err = json.NewDecoder(statusResp.Body).Decode(&clientStatus)
	require.NoError(t, err)
	statusResp.Body.Close()

	// Verify client status fields
	assert.Contains(t, clientStatus, "round")
	assert.Contains(t, clientStatus, "running")
	assert.Contains(t, clientStatus, "pending_messages")
	assert.True(t, clientStatus["running"].(bool))

	// We should see our queued messages
	pendingCount := clientStatus["pending_messages"].(float64)
	assert.Equal(t, 3.0, pendingCount, "Should have 3 pending messages")

	t.Logf("Initial client status: %+v", clientStatus)

	// ========== 12. WAIT FOR SLOT RESERVATION AND MESSAGE PROCESSING ==========
	// We need to wait several rounds to see slot reservation and message processing
	// First round: slot reservation
	// Second round: message sending
	// Wait for multiple rounds to ensure all messages get processed
	//
	// Increase wait time significantly to ensure message processing
	// Use a combination of waiting and active polling to ensure messages are processed
	waitDuration := config.RoundDuration * 5
	t.Logf("Waiting %v for message processing with periodic checks...", waitDuration)

	deadline := time.Now().Add(waitDuration)

	time.Sleep(time.Until(deadline))

	var endRound uint64 = zipnet.CurrentRound(config.RoundDuration)

	for round := startRound; round <= endRound; round++ {
		roundOutputReq, err := http.NewRequest("GET", fmt.Sprintf("%s/server/round-output/%d", serverTS.URL, round), nil)
		require.NoError(t, err)

		roundOutputResp, err := http.DefaultClient.Do(roundOutputReq)
		require.NoError(t, err)

		roundOutput, err := zipnet.DecodeMessage[zipnet.Signed[zipnet.RoundOutput]](roundOutputResp.Body)
		if err == nil {
			t.Log(string(roundOutput.Object.MsgVec))
		} else {
			t.Log(err)
		}

		// testMessage := []byte(fmt.Sprintf("Test message %d", i))
	}

	// ========== 13. CHECK FINAL CLIENT STATUS ==========
	statusReq2, err := http.NewRequest("GET", fmt.Sprintf("%s/client/status", clientTS1.URL), nil)
	require.NoError(t, err)

	statusResp2, err := http.DefaultClient.Do(statusReq2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusResp2.StatusCode)

	var clientStatus2 map[string]interface{}
	err = json.NewDecoder(statusResp2.Body).Decode(&clientStatus2)
	require.NoError(t, err)
	statusResp2.Body.Close()

	// The pending messages should be reduced
	pendingCount2 := clientStatus2["pending_messages"].(float64)
	t.Logf("Final client status: %+v", clientStatus2)

	// Now we expect the pending messages to be fewer than the initial count
	// If the feature works correctly
	assert.Less(t, pendingCount2, pendingCount, "Should have processed some messages")

	// Clean up
	clientHandler1.Shutdown()
	clientHandler2.Shutdown()
	aggHandler.Shutdown()
}

// TestNetworkTransport is a minimally viable implementation of the NetworkTransport interface for testing
type TestNetworkTransport struct {
	ServerURL     string
	AggregatorURL string
}

func (t *TestNetworkTransport) SendAggregateToAggregator(ctx context.Context, aggregatorID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	data, err := zipnet.SerializeMessage(message)
	if err != nil {
		return err
	}

	url := t.AggregatorURL
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/aggregator/aggregator-message", url), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aggregator returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TestNetworkTransport) SendToAggregator(ctx context.Context, aggregatorID string, message *zipnet.Signed[zipnet.ClientMessage]) error {
	data, err := zipnet.SerializeMessage(message)
	if err != nil {
		return err
	}

	url := t.AggregatorURL
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/aggregator/client-message", url), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aggregator returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TestNetworkTransport) SendAggregateToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	data, err := zipnet.SerializeMessage(message)
	if err != nil {
		return err
	}

	url := t.ServerURL
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/server/aggregate", url), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TestNetworkTransport) SendShareToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.UnblindedShareMessage]) error {
	data, err := zipnet.SerializeMessage(message)
	if err != nil {
		return err
	}

	url := t.ServerURL
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/server/share", url), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TestNetworkTransport) FetchSchedule(ctx context.Context, serverID string, round uint64) (*zipnet.PublishedSchedule, error) {
	resp, err := http.DefaultClient.Get(fmt.Sprintf("%s/server/schedule/%d", t.ServerURL, round))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return zipnet.DecodeMessage[zipnet.PublishedSchedule](resp.Body)
}

func (t *TestNetworkTransport) BroadcastToClients(ctx context.Context, message *zipnet.ServerMessage) error {
	panic("unexpected")
}

func (t *TestNetworkTransport) RegisterMessageHandler(handler func([]byte) error) error {
	panic("unexpected")
}
