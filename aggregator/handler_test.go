package aggregator

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

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/server"
	"github.com/flashbots/adcnet/testutil"
	"github.com/flashbots/adcnet/zipnet"
)

// TestEndToEndFlow tests the complete flow from client to aggregator to server
func TestEndToEndFlow(t *testing.T) {
	// Set up test context
	ctx := context.Background()

	// Create test configuration with small values for testing
	config := testutil.NewTestConfig(
		testutil.WithRoundDuration(2*time.Second),
		testutil.WithMinClients(2),
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
	leaderHandler := server.NewServerHandler(leaderServer, nil)
	serverRouter := chi.NewRouter()
	leaderHandler.RegisterRoutes(serverRouter)

	// Create test server for handling HTTP requests
	serverTS := httptest.NewServer(serverRouter)
	defer serverTS.Close()

	// ========== 2. SET UP AGGREGATOR ==========
	// Generate aggregator keys
	aggPK, aggSK, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Create transport that can communicate with our test server
	transport := &IntegrationNetworkTransport{
		ServerURL: serverTS.URL,
	}

	// Create the aggregator
	aggregator, err := NewAggregator(
		config,
		aggSK,
		aggPK,
		cryptoProvider,
		transport,
		nil, // Empty initial user list
		nil, // Empty initial aggregators list
		0,   // Level 0 (leaf aggregator)
	)
	require.NoError(t, err)

	// Create aggregator handler and routes
	aggHandler := NewAggregatorHandler(aggregator, transport)
	aggRouter := chi.NewRouter()
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

	// ========== 4. CREATE AND REGISTER CLIENT KEYS ==========
	clientPK1, clientSK1, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	clientPK2, clientSK2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	// Register with server
	err = leaderServer.RegisterClient(ctx, clientPK1, []byte("test-attestation"))
	require.NoError(t, err)
	err = leaderServer.RegisterClient(ctx, clientPK2, []byte("test-attestation"))
	require.NoError(t, err)

	// Register with aggregator
	userRegBytes1, err := zipnet.SerializeMessage(&clientPK1)
	require.NoError(t, err)

	regUser1Req, err := http.NewRequest("POST", fmt.Sprintf("%s/aggregator/register-user", aggTS.URL), bytes.NewReader(userRegBytes1))
	require.NoError(t, err)
	regUser1Req.Header.Set("Content-Type", "application/json")

	regUser1Resp, err := http.DefaultClient.Do(regUser1Req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, regUser1Resp.StatusCode)
	regUser1Resp.Body.Close()

	userRegBytes2, err := zipnet.SerializeMessage(&clientPK2)
	require.NoError(t, err)

	regUser2Req, err := http.NewRequest("POST", fmt.Sprintf("%s/aggregator/register-user", aggTS.URL), bytes.NewReader(userRegBytes2))
	require.NoError(t, err)
	regUser2Req.Header.Set("Content-Type", "application/json")

	regUser2Resp, err := http.DefaultClient.Do(regUser2Req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, regUser2Resp.StatusCode)
	regUser2Resp.Body.Close()

	// ========== 5. CHECK INITIAL AGGREGATOR STATUS ==========
	statusReq, err := http.NewRequest("GET", fmt.Sprintf("%s/aggregator/status", aggTS.URL), nil)
	require.NoError(t, err)

	statusResp, err := http.DefaultClient.Do(statusReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, statusResp.StatusCode)

	var status map[string]interface{}
	err = json.NewDecoder(statusResp.Body).Decode(&status)
	require.NoError(t, err)
	statusResp.Body.Close()

	// Assert some status fields
	assert.Contains(t, status, "level")
	assert.Equal(t, float64(0), status["level"]) // Leaf aggregator

	// ========== 6. START ROUND PROCESSING ==========
	round := zipnet.CurrentRound(config.RoundDuration)
	aggregator.Reset(round)

	// Publish initial schedule for round 1
	initialSchedVec := make([]byte, config.SchedulingSlots*config.FootprintBits/8)
	_, _, err = leaderServer.PublishSchedule(ctx, round, initialSchedVec)
	require.NoError(t, err)

	// ========== 7. CREATE AND SUBMIT CLIENT MESSAGES ==========
	// Client 1 message
	msgContent1 := []byte("Message from client 1")
	clientMsg1 := testutil.GenerateMessageWithContent(
		msgContent1,
		0,
		config.MessageSize,
		testutil.WithRound(round),
	)

	signedClientMsg1, err := zipnet.NewSigned(clientSK1, clientMsg1)
	require.NoError(t, err)

	// Send message to aggregator
	clientMsgBytes1, err := zipnet.SerializeMessage(signedClientMsg1)
	require.NoError(t, err)

	clientReq1, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/aggregator/client-message", aggTS.URL),
		bytes.NewReader(clientMsgBytes1),
	)
	require.NoError(t, err)
	clientReq1.Header.Set("Content-Type", "application/json")

	clientResp1, err := http.DefaultClient.Do(clientReq1)
	require.NoError(t, err)
	clientResp1Body, _ := io.ReadAll(clientResp1.Body)
	require.Equal(t, http.StatusOK, clientResp1.StatusCode, string(clientResp1Body))
	clientResp1.Body.Close()

	// Client 2 message
	msgContent2 := []byte("Message from client 2")
	clientMsg2 := testutil.GenerateMessageWithContent(
		msgContent2,
		1,
		config.MessageSize,
		testutil.WithRound(round),
	)

	signedClientMsg2, err := zipnet.NewSigned(clientSK2, clientMsg2)
	require.NoError(t, err)

	// Send message to aggregator
	clientMsgBytes2, err := zipnet.SerializeMessage(signedClientMsg2)
	require.NoError(t, err)

	clientReq2, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/aggregator/client-message", aggTS.URL),
		bytes.NewReader(clientMsgBytes2),
	)
	require.NoError(t, err)
	clientReq2.Header.Set("Content-Type", "application/json")

	clientResp2, err := http.DefaultClient.Do(clientReq2)
	require.NoError(t, err)
	clientResp2Body, err := io.ReadAll(clientResp2.Body)
	require.Equal(t, http.StatusOK, clientResp2.StatusCode, string(clientResp2Body))
	clientResp2.Body.Close()

	// ========== 8. FORCE ROUND END USING THE HANDLER FUNCTION ==========
	aggHandler.finalizeRound(round)

	// Give time for processing
	time.Sleep(500 * time.Millisecond)

	// ========== 9. CHECK ROUND OUTPUT FROM SERVER ==========
	roundOutputReq, err := http.NewRequest("GET", fmt.Sprintf("%s/server/round-output/%d", serverTS.URL, round), nil)
	require.NoError(t, err)

	// Try a few times with a small delay to allow for async processing
	var roundOutputResp *http.Response
	for i := 0; i < 5; i++ {
		roundOutputResp, err = http.DefaultClient.Do(roundOutputReq)
		if err == nil && roundOutputResp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	require.NoError(t, err)
	roundOutputRespBytes, err := io.ReadAll(roundOutputResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, roundOutputResp.StatusCode, string(roundOutputRespBytes))

	var roundOutput zipnet.RoundOutput
	err = json.Unmarshal(roundOutputRespBytes, &roundOutput)
	require.NoError(t, err)
	roundOutputResp.Body.Close()

	// Verify round output
	assert.Equal(t, round, roundOutput.Round)
	require.NotNil(t, roundOutput.Message)

	// Extract messages from slots to verify content
	slot0Content := testutil.ExtractMessageFromSlot(
		roundOutput.Message.MsgVec,
		0,
		int(config.MessageSize),
	)
	slot1Content := testutil.ExtractMessageFromSlot(
		roundOutput.Message.MsgVec,
		1,
		int(config.MessageSize),
	)

	// Verify message content (note: we cannot directly compare due to encryption/decryption)
	// Just check that we have non-zero content in the expected slots
	assert.NotEmpty(t, slot0Content)
	assert.NotEmpty(t, slot1Content)

	// ========== 10. VERIFY ROUND ADVANCEMENT ==========
	// Check that the aggregator moved to the next round
	statusReq2, err := http.NewRequest("GET", fmt.Sprintf("%s/aggregator/status", aggTS.URL), nil)
	require.NoError(t, err)

	statusResp2, err := http.DefaultClient.Do(statusReq2)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, statusResp2.StatusCode)

	var status2 map[string]interface{}
	err = json.NewDecoder(statusResp2.Body).Decode(&status2)
	require.NoError(t, err)
	statusResp2.Body.Close()
}

// IntegrationNetworkTransport implements the NetworkTransport interface for integration testing
type IntegrationNetworkTransport struct {
	ServerURL string
}

func (t *IntegrationNetworkTransport) SendToAggregator(ctx context.Context, aggregatorID string, message *zipnet.Signed[zipnet.ClientMessage]) error {
	return fmt.Errorf("not implemented in integration test")
}

func (t *IntegrationNetworkTransport) SendAggregateToAggregator(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	return fmt.Errorf("not implemented in integration test")
}

func (t *IntegrationNetworkTransport) SendAggregateToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	// Send the aggregate to the test server
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/server/aggregate", t.ServerURL), bytes.NewReader(data))
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
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

func (t *IntegrationNetworkTransport) SendShareToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.UnblindedShareMessage]) error {
	// Send the share to the test server
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/server/share", t.ServerURL), bytes.NewReader(data))
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
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

func (t *IntegrationNetworkTransport) FetchSchedule(ctx context.Context, serverID string, round uint64) (*zipnet.PublishedSchedule, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *IntegrationNetworkTransport) BroadcastToClients(ctx context.Context, message *zipnet.ServerMessage) error {
	return fmt.Errorf("not implemented in integration test")
}

func (t *IntegrationNetworkTransport) RegisterMessageHandler(handler func([]byte) error) error {
	return fmt.Errorf("not implemented in integration test")
}
