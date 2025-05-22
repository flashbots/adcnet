package server

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
	"github.com/flashbots/adcnet/zipnet"
)

// TestServerHandlerGreenPath tests the happy path flow through the server handler
func TestServerHandlerGreenPath(t *testing.T) {
	// Set up a test server (as leader)
	serverImpl := setupTestServer(t, true)

	// Register clients directly to meet minimum requirement
	ctx := context.Background()
	clientPK1, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	clientPK2, _, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	err = serverImpl.RegisterClient(ctx, clientPK1, []byte("test-attestation"))
	require.NoError(t, err)
	err = serverImpl.RegisterClient(ctx, clientPK2, []byte("test-attestation"))
	require.NoError(t, err)

	// Create handler and routes
	handler := NewServerHandler(serverImpl, nil)
	r := chi.NewRouter()
	handler.RegisterRoutes(r)

	leaderServer := httptest.NewServer(r)

	// Test 1: Register an aggregator
	aggPK, aggPriv, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	aggData, err := zipnet.SerializeMessage(&zipnet.AggregatorRegistrationBlob{
		PublicKey: aggPK,
		Level:     0,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	httpReq, err := http.NewRequest("POST", "/server/register-aggregator", bytes.NewReader(aggData))
	require.NoError(t, err)

	r.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test 2: Register another server
	followerServerImpl := setupTestServer(t, false)
	followerServerData, err := zipnet.SerializeMessage(followerServerImpl.GetRegistrationBlob())
	require.NoError(t, err)

	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("POST", "/server/register-server", bytes.NewReader(followerServerData))
	require.NoError(t, err)

	r.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	followerTransport := StubNetworkTransport{
		LeaderURL: leaderServer.URL,
	}

	err = followerServerImpl.RegisterClient(ctx, clientPK1, []byte("test-attestation"))
	require.NoError(t, err)
	err = followerServerImpl.RegisterClient(ctx, clientPK2, []byte("test-attestation"))
	require.NoError(t, err)

	followerHandler := NewServerHandler(followerServerImpl, &followerTransport)
	followerRouter := chi.NewRouter()
	followerHandler.RegisterRoutes(followerRouter)

	leaderServerData, err := zipnet.SerializeMessage(serverImpl.GetRegistrationBlob())
	require.NoError(t, err)

	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("POST", "/server/register-server", bytes.NewReader(leaderServerData))
	require.NoError(t, err)

	followerRouter.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	// Register aggregator with follower server
	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("POST", "/server/register-aggregator", bytes.NewReader(aggData))
	require.NoError(t, err)

	followerRouter.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test 3: Publish and retrieve a schedule
	round := zipnet.CurrentRound(serverImpl.config.RoundDuration)
	scheduleData := make([]byte, 400)
	_, signature, err := serverImpl.PublishSchedule(ctx, round, scheduleData)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("GET", fmt.Sprintf("/server/schedule/%d", round), nil)
	require.NoError(t, err)

	r.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code)

	schedule, err := zipnet.DecodeMessage[zipnet.PublishedSchedule](w.Body)
	require.NoError(t, err)
	assert.Equal(t, scheduleData, schedule.Footprints)
	assert.Equal(t, signature, schedule.Signature)

	err = followerHandler.updateSchedule(round)
	require.NoError(t, err)

	// Test 4: Process an aggregate message
	msgContent := []byte("Test message in slot 0")
	msgSize := uint32(160)
	msgSlots := uint32(100)
	msgVec := createMessageVector(msgSize, msgSlots, 0, msgContent)

	aggregateMsg, err := zipnet.NewSigned(aggPriv, &zipnet.AggregatorMessage{
		ScheduleMessage: zipnet.ScheduleMessage{
			Round:        round,
			NextSchedVec: make([]byte, 400),
			MsgVec:       msgVec,
			// In a real system this would be signed
		},
		UserPKs:         []crypto.PublicKey{clientPK1, clientPK2},
		AggregatorID:    "test-agg",
		Level:           0,
		AnytrustGroupID: "test-group",
	})
	require.NoError(t, err)

	aggregateMsgBytes, err := zipnet.SerializeMessage(aggregateMsg)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("POST", "/server/aggregate", bytes.NewReader(aggregateMsgBytes))
	require.NoError(t, err)

	followerRouter.ServeHTTP(w, httpReq)

	// For a leader with prepared shares, should return OK with the processed message
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Simulate a follower server processing the same aggregate
	// This would happen in a real system but we'll mock it here
	followerShare, err := followerServerImpl.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)

	followerShareBytes, err := zipnet.SerializeMessage(followerShare)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("POST", "/server/share", bytes.NewReader(followerShareBytes))
	require.NoError(t, err)

	r.ServeHTTP(w, httpReq)

	// For a leader with prepared shares, should return OK with the processed message
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	leaderShare, err := serverImpl.UnblindAggregate(ctx, aggregateMsg)
	require.NoError(t, err)

	// Prepare mock shares for testing server's DeriveRoundOutput
	shares := []*zipnet.UnblindedShareMessage{followerShare.UnsafeObject(), leaderShare.UnsafeObject()}
	require.Len(t, shares, 2) // TODO: try manually combining the shares

	// Test 5: Retrieve round output
	w = httptest.NewRecorder()
	httpReq, err = http.NewRequest("GET", fmt.Sprintf("/server/round-output/%d", round), nil)
	require.NoError(t, err)

	r.ServeHTTP(w, httpReq)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var retrievedOutput zipnet.RoundOutput
	err = json.Unmarshal(w.Body.Bytes(), &retrievedOutput)
	require.NoError(t, err)
	assert.Equal(t, round, retrievedOutput.Round)

	// Verify the retrieved output contains our test message
	startPos := uint32(0) * msgSize // We wrote to slot 0
	extractedMsg := retrievedOutput.Message.MsgVec[startPos : startPos+uint32(len(msgContent))]
	assert.Equal(t, msgContent, extractedMsg)

	// Test 6: Run background tasks
	handler.RunInBackground()
	time.Sleep(100 * time.Millisecond) // Give background tasks time to start
}

type StubNetworkTransport struct {
	LeaderURL string
}

func (n *StubNetworkTransport) SendToAggregator(ctx context.Context, aggregatorID string, message *zipnet.Signed[zipnet.ClientMessage]) error {
	panic("unexpected call")
}

func (n *StubNetworkTransport) SendAggregateToAggregator(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	panic("unexpected call")
}

func (n *StubNetworkTransport) SendAggregateToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.AggregatorMessage]) error {
	panic("unexpected call")
}

func (n *StubNetworkTransport) SendShareToServer(ctx context.Context, serverID string, message *zipnet.Signed[zipnet.UnblindedShareMessage]) error {
	msg, err := zipnet.SerializeMessage(message)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Post(fmt.Sprintf("%s/server/share", n.LeaderURL), "Application/JSON", bytes.NewBuffer(msg))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("could not submit share: %s", string(bodyBytes))
	}

	return nil
}

func (n *StubNetworkTransport) FetchSchedule(ctx context.Context, serverID string, round uint64) (*zipnet.PublishedSchedule, error) {
	res, err := http.DefaultClient.Get(fmt.Sprintf("%s/server/schedule/%d", n.LeaderURL, round))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return zipnet.DecodeMessage[zipnet.PublishedSchedule](res.Body)
}

func (n *StubNetworkTransport) BroadcastToClients(ctx context.Context, message *zipnet.ServerMessage) error {
	panic("unexpected call")
}

func (n *StubNetworkTransport) RegisterMessageHandler(handler func([]byte) error) error {
	panic("unexpected call")
}
