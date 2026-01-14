package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/tdx"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

// fetchServices retrieves the service list from the registry via HTTP.
func fetchServices(registryURL string) (*ServiceListResponse, error) {
	resp, err := http.Get(registryURL + "/services")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list ServiceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return &list, nil
}

// TestE2E_FullRound tests a complete message flow through the HTTP services layer.
// This is a simplified end-to-end test that deploys a minimal network and verifies
// message recovery after a full protocol round.
func TestE2E_FullRound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	const (
		numServers     = 3
		numAggregators = 1
		numClients     = 2
		roundDuration  = 1 * time.Second
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    10,
		MessageLength:   1024,
		MinClients:      uint32(numClients),
		RoundDuration:   roundDuration,
		RoundsPerWindow: 10,
	}

	attestProvider := &tdx.DummyProvider{}
	measureSource := DemoMeasurementSource()
	adminToken := "admin:test"

	// Start registry
	_, registryServer := startTestRegistry(t, adcConfig, attestProvider, measureSource, adminToken)
	defer registryServer.Close()

	// Start servers
	var servers []*testService
	var broadcastChan = make(chan *protocol.RoundBroadcast, 10)
	for i := 0; i < numServers; i++ {
		isLeader := i == 0
		svc := startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, isLeader)
		if isLeader {
			svc.httpServer.SetRoundOutputCallback(func(rb *protocol.RoundBroadcast) {
				select {
				case broadcastChan <- rb:
				default:
				}
			})
		}
		servers = append(servers, svc)
	}

	// Start aggregators
	var aggregators []*testService
	for i := 0; i < numAggregators; i++ {
		svc := startTestAggregator(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken)
		aggregators = append(aggregators, svc)
	}

	// Start clients
	var clients []*testService
	for i := 0; i < numClients; i++ {
		svc := startTestClient(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL)
		clients = append(clients, svc)
	}

	// Wait for discovery to complete
	require.Eventually(t, func() bool {
		list, err := fetchServices(registryServer.URL)
		if err != nil {
			return false
		}
		return len(list.Servers) == numServers &&
			len(list.Aggregators) == numAggregators &&
			len(list.Clients) == numClients
	}, 5*time.Second, 50*time.Millisecond, "services should register with registry")

	// Allow extra time for mutual discovery between services
	time.Sleep(500 * time.Millisecond)

	// Send test message to first client
	testMsg := "Hello E2E Test!"
	sendTestMessage(t, clients[0].ts.URL, testMsg, 100)

	// Wait for broadcasts (need 2+ rounds for message to appear due to auction scheduling)
	var foundMessage bool
	timeout := time.After(roundDuration * 8)
	for !foundMessage {
		select {
		case broadcast := <-broadcastChan:
			if bytes.Contains(broadcast.MessageVector, []byte(testMsg)) {
				foundMessage = true
			}
		case <-timeout:
			t.Fatal("timeout waiting for message in broadcast")
		}
	}

	require.True(t, foundMessage, "message should appear in broadcast")
}

type testService struct {
	ts         *httptest.Server
	httpServer *HTTPServer
	httpAgg    *HTTPAggregator
	httpClient *HTTPClient
}

func startTestRegistry(t *testing.T, adcConfig *protocol.ADCNetConfig, attestProvider TEEProvider, measureSource MeasurementSource, adminToken string) (*Registry, *httptest.Server) {
	t.Helper()

	registryConfig := &RegistryConfig{
		AttestationVerifier: attestProvider,
		MeasurementSource:   measureSource,
		AdminToken:          adminToken,
	}
	registry, err := NewRegistry(registryConfig, adcConfig)
	require.NoError(t, err)

	r := chi.NewRouter()
	registry.RegisterPublicRoutes(r)
	registry.RegisterAdminRoutes(r)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	return registry, ts
}

func startTestServer(t *testing.T, ctx context.Context, adcConfig *protocol.ADCNetConfig, attestProvider TEEProvider, measureSource MeasurementSource, registryURL, adminToken string, isLeader bool) *testService {
	t.Helper()

	pubKey, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create httptest server first to get the URL
	r := chi.NewRouter()
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	config := &ServiceConfig{
		ADCNetConfig:              adcConfig,
		AttestationProvider:       attestProvider,
		AllowedMeasurementsSource: measureSource,
		HTTPAddr:                  ts.URL[7:], // strip "http://"
		RegistryURL:               registryURL,
		AdminToken:                adminToken,
	}

	serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
	server, err := NewHTTPServer(config, serverID, privKey, exchangeKey, isLeader)
	require.NoError(t, err)

	server.RegisterRoutes(r)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	require.NoError(t, server.Start(ctx))

	return &testService{ts: ts, httpServer: server}
}

func startTestAggregator(t *testing.T, ctx context.Context, adcConfig *protocol.ADCNetConfig, attestProvider TEEProvider, measureSource MeasurementSource, registryURL, adminToken string) *testService {
	t.Helper()

	_, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	r := chi.NewRouter()
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	config := &ServiceConfig{
		ADCNetConfig:              adcConfig,
		AttestationProvider:       attestProvider,
		AllowedMeasurementsSource: measureSource,
		HTTPAddr:                  ts.URL[7:],
		RegistryURL:               registryURL,
		AdminToken:                adminToken,
	}

	agg, err := NewHTTPAggregator(config, privKey, exchangeKey)
	require.NoError(t, err)

	agg.RegisterRoutes(r)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	require.NoError(t, agg.Start(ctx))

	return &testService{ts: ts, httpAgg: agg}
}

func startTestClient(t *testing.T, ctx context.Context, adcConfig *protocol.ADCNetConfig, attestProvider TEEProvider, measureSource MeasurementSource, registryURL string) *testService {
	t.Helper()

	_, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	r := chi.NewRouter()
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)

	config := &ServiceConfig{
		ADCNetConfig:              adcConfig,
		AttestationProvider:       attestProvider,
		AllowedMeasurementsSource: measureSource,
		HTTPAddr:                  ts.URL[7:],
		RegistryURL:               registryURL,
	}

	client, err := NewHTTPClient(config, privKey, exchangeKey)
	require.NoError(t, err)

	client.RegisterRoutes(r)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	require.NoError(t, client.Start(ctx))

	return &testService{ts: ts, httpClient: client}
}

func sendTestMessage(t *testing.T, clientURL string, msg string, bid int) {
	t.Helper()

	req := HTTPClientMessage{
		Message: []byte(msg),
		Value:   bid,
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := http.Post(clientURL+"/message", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "sending message should succeed")
}

// TestE2E_ServiceDiscovery verifies that all services register and discover each other.
func TestE2E_ServiceDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    10,
		MessageLength:   1024,
		MinClients:      2,
		RoundDuration:   time.Second,
		RoundsPerWindow: 10,
	}

	attestProvider := &tdx.DummyProvider{}
	measureSource := DemoMeasurementSource()
	adminToken := "admin:test"

	_, registryServer := startTestRegistry(t, adcConfig, attestProvider, measureSource, adminToken)
	defer registryServer.Close()

	// Start services
	startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, true)
	startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, false)
	startTestAggregator(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken)
	startTestClient(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL)

	// Verify discovery
	require.Eventually(t, func() bool {
		list, err := fetchServices(registryServer.URL)
		if err != nil {
			return false
		}
		return len(list.Servers) == 2 && len(list.Aggregators) == 1 && len(list.Clients) == 1
	}, 5*time.Second, 50*time.Millisecond)

	// Verify via HTTP endpoint
	resp, err := http.Get(registryServer.URL + "/services")
	require.NoError(t, err)
	defer resp.Body.Close()

	var serviceList ServiceListResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&serviceList))
	require.Len(t, serviceList.Servers, 2)
	require.Len(t, serviceList.Aggregators, 1)
	require.Len(t, serviceList.Clients, 1)
}

// TestE2E_HealthEndpoints verifies health endpoints respond correctly.
func TestE2E_HealthEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    10,
		MessageLength:   1024,
		MinClients:      1,
		RoundDuration:   time.Second,
		RoundsPerWindow: 10,
	}

	attestProvider := &tdx.DummyProvider{}
	measureSource := DemoMeasurementSource()
	adminToken := "admin:test"

	_, registryServer := startTestRegistry(t, adcConfig, attestProvider, measureSource, adminToken)
	defer registryServer.Close()

	server := startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, true)
	client := startTestClient(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL)

	// Check registry health
	resp, err := http.Get(registryServer.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check server health
	resp, err = http.Get(server.ts.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check client health
	resp, err = http.Get(client.ts.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestE2E_EmptyRounds verifies the system handles rounds with no messages gracefully.
func TestE2E_EmptyRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    10,
		MessageLength:   512,
		MinClients:      1,
		RoundDuration:   300 * time.Millisecond,
		RoundsPerWindow: 10,
	}

	attestProvider := &tdx.DummyProvider{}
	measureSource := DemoMeasurementSource()
	adminToken := "admin:test"

	_, registryServer := startTestRegistry(t, adcConfig, attestProvider, measureSource, adminToken)
	defer registryServer.Close()

	broadcastChan := make(chan *protocol.RoundBroadcast, 10)
	leader := startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, true)
	leader.httpServer.SetRoundOutputCallback(func(rb *protocol.RoundBroadcast) {
		select {
		case broadcastChan <- rb:
		default:
		}
	})

	startTestServer(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken, false)
	startTestAggregator(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL, adminToken)
	startTestClient(t, ctx, adcConfig, attestProvider, measureSource, registryServer.URL)

	// Wait for discovery
	require.Eventually(t, func() bool {
		list, err := fetchServices(registryServer.URL)
		if err != nil {
			return false
		}
		return len(list.Servers) == 2 && len(list.Aggregators) == 1 && len(list.Clients) == 1
	}, 5*time.Second, 50*time.Millisecond)

	// Wait for at least one empty round to complete
	select {
	case broadcast := <-broadcastChan:
		require.NotNil(t, broadcast)
		t.Logf("Received empty round broadcast for round %d", broadcast.RoundNumber)
	case <-time.After(adcConfig.RoundDuration * 5):
		t.Fatal("timeout waiting for empty round broadcast")
	}
}
