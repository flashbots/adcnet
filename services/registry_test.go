package services

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func setupTestRegistry(t *testing.T, adminToken string) (*Registry, chi.Router) {
	t.Helper()

	config := &RegistryConfig{
		AdminToken: adminToken,
	}
	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:  10,
		MessageLength: 1000,
		RoundDuration: time.Second,
	}

	registry, err := NewRegistry(config, adcConfig)
	require.NoError(t, err)

	r := chi.NewRouter()
	registry.RegisterPublicRoutes(r)
	registry.RegisterAdminRoutes(r)

	return registry, r
}

func createSignedRegistration(t *testing.T, serviceType ServiceType, endpoint string) (*protocol.Signed[RegisteredService], crypto.PrivateKey) {
	t.Helper()

	pubKey, privKey, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	regService := &RegisteredService{
		ServiceType:  serviceType,
		HTTPEndpoint: endpoint,
		PublicKey:    pubKey.String(),
		ExchangeKey:  string(crypto.PublicKey(exchangeKey.PublicKey().Bytes()).String()),
	}

	signed, err := protocol.NewSigned(privKey, regService)
	require.NoError(t, err)

	return signed, privKey
}

func TestRegistry_PublicClientRegistration(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	signed, _ := createSignedRegistration(t, ClientService, "http://localhost:9000")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/register/client", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp ServiceRegistrationResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	require.True(t, resp.Success)
}

func TestRegistry_ServerRequiresAdminAuth(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	signed, _ := createSignedRegistration(t, ServerService, "http://localhost:9001")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	// Try public endpoint - should be forbidden
	req := httptest.NewRequest("POST", "/register/server", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRegistry_AdminRegistration(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	signed, _ := createSignedRegistration(t, ServerService, "http://localhost:9001")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	// Use admin endpoint with auth
	req := httptest.NewRequest("POST", "/admin/register/server", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestRegistry_AdminAuthRequired(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	signed, _ := createSignedRegistration(t, ServerService, "http://localhost:9001")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	// Admin endpoint without auth
	req := httptest.NewRequest("POST", "/admin/register/server", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegistry_WrongAdminCredentials(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	signed, _ := createSignedRegistration(t, ServerService, "http://localhost:9001")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/admin/register/server", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "wrongpassword")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRegistry_GetServices(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	// Register a client
	signed, _ := createSignedRegistration(t, ClientService, "http://localhost:9000")
	body, _ := json.Marshal(signed)
	req := httptest.NewRequest("POST", "/register/client", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Get services
	req = httptest.NewRequest("GET", "/services", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp ServiceListResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	require.Len(t, resp.Clients, 1)
	require.Len(t, resp.Servers, 0)
	require.Len(t, resp.Aggregators, 0)
}

func TestRegistry_InvalidSignature(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	// Create a signed registration but tamper with the signature
	signed, _ := createSignedRegistration(t, ClientService, "http://localhost:9000")
	signed.Signature[0] ^= 0xFF // Tamper with signature

	body, err := json.Marshal(signed)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/register/client", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRegistry_ServiceTypeMismatch(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	// Create server registration but post to client endpoint
	signed, _ := createSignedRegistration(t, ServerService, "http://localhost:9000")
	body, err := json.Marshal(signed)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/register/client", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should fail because service type in body doesn't match URL (returns 400 Bad Request)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegistry_GetConfig(t *testing.T) {
	_, router := setupTestRegistry(t, "")

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var config protocol.ADCNetConfig
	err := json.NewDecoder(w.Body).Decode(&config)
	require.NoError(t, err)
	require.Equal(t, uint32(10), config.AuctionSlots)
	require.Equal(t, 1000, config.MessageLength)
}

func TestRegistry_Health(t *testing.T) {
	_, router := setupTestRegistry(t, "")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestRegistry_Unregister(t *testing.T) {
	_, router := setupTestRegistry(t, "admin:secret")

	// Register a client
	signed, _ := createSignedRegistration(t, ClientService, "http://localhost:9000")
	body, _ := json.Marshal(signed)
	req := httptest.NewRequest("POST", "/register/client", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Unregister
	req = httptest.NewRequest("DELETE", "/admin/unregister/"+signed.Object.PublicKey, nil)
	req.SetBasicAuth("admin", "secret")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Verify it's gone
	req = httptest.NewRequest("GET", "/services", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp ServiceListResponse
	json.NewDecoder(w.Body).Decode(&resp)
	require.Len(t, resp.Clients, 0)
}
