package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// discoveryHandler processes discovered services during the discovery loop.
type discoveryHandler interface {
	onServerDiscovered(*ServiceInfo) error
	onAggregatorDiscovered(*ServiceInfo) error
	onClientDiscovered(*ServiceInfo) error
	selfPublicKey() string
}

// baseService contains common fields and methods for all HTTP services.
type baseService struct {
	config      *ServiceConfig
	roundCoord  *protocol.LocalRoundCoordinator
	registry    *ServiceRegistry
	httpClient  *http.Client
	attestation []byte
	signingKey  crypto.PrivateKey
	exchangeKey *ecdh.PrivateKey

	mu             sync.RWMutex
	currentRound   protocol.Round
	discoveryReqCh chan struct{}
}

func newBaseService(config *ServiceConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) (*baseService, error) {
	roundCoord := protocol.NewLocalRoundCoordinator(config.ADCNetConfig.RoundDuration)

	pubKey, _ := signingKey.PublicKey()
	req := &ServiceRegistrationRequest{
		ServiceType:  config.ServiceType,
		PublicKey:    pubKey.String(),
		ExchangeKey:  hex.EncodeToString(exchangeKey.PublicKey().Bytes()),
		HTTPEndpoint: fmt.Sprintf("http://%s", config.HTTPAddr),
	}

	attestation, err := AttestServiceRegistration(config.AttestationProvider, req)
	if err != nil {
		return nil, fmt.Errorf("could not attest registration: %w", err)
	}

	return &baseService{
		config:         config,
		roundCoord:     roundCoord,
		registry:       NewServiceRegistry(),
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		attestation:    attestation,
		signingKey:     signingKey,
		exchangeKey:    exchangeKey,
		discoveryReqCh: make(chan struct{}),
	}, nil
}

func (b *baseService) publicKey() crypto.PublicKey {
	pubKey, _ := b.signingKey.PublicKey()
	return pubKey
}

func (b *baseService) sendRegistrationDirectly(endpoint string, serviceType ServiceType) error {
	req := b.registrationRequest()
	signedReq, err := protocol.NewSigned(b.signingKey, req)
	if err != nil {
		return fmt.Errorf("failed to sign secret exchange: %w", err)
	}

	body, _ := json.Marshal(signedReq)
	resp, err := b.httpClient.Post(endpoint+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (b *baseService) registrationRequest() *ServiceRegistrationRequest {
	pubKey := b.publicKey()
	return &ServiceRegistrationRequest{
		ServiceType:  b.config.ServiceType,
		PublicKey:    pubKey.String(),
		ExchangeKey:  hex.EncodeToString(b.exchangeKey.PublicKey().Bytes()),
		HTTPEndpoint: fmt.Sprintf("http://%s", b.config.HTTPAddr),
		Attestation:  b.attestation,
	}
}

// registerWithRegistry registers this service with the central registry.
// Uses admin endpoint with authentication for servers and aggregators.
func (b *baseService) registerWithRegistry() error {
	if b.config.RegistryURL == "" {
		return nil
	}

	req := b.registrationRequest()

	signedReq, err := protocol.NewSigned(b.signingKey, req)
	if err != nil {
		return fmt.Errorf("failed to sign registration: %w", err)
	}

	body, _ := json.Marshal(signedReq)

	// Determine endpoint based on service type
	var url string
	if b.config.ServiceType == ClientService {
		url = fmt.Sprintf("%s/register/%s", b.config.RegistryURL, b.config.ServiceType)
	} else {
		url = fmt.Sprintf("%s/admin/register/%s", b.config.RegistryURL, b.config.ServiceType)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Add admin auth for servers and aggregators
	if b.config.ServiceType != ClientService && b.config.AdminToken != "" {
		user, pass := parseAdminToken(b.config.AdminToken)
		httpReq.SetBasicAuth(user, pass)
	}

	resp, err := b.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed (%d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func parseAdminToken(token string) (user, pass string) {
	idx := strings.Index(token, ":")
	if idx < 0 {
		return token, ""
	}
	return token[:idx], token[idx+1:]
}

// Note: this really should be async (sse/ws)
func (b *baseService) runDiscoveryLoop(ctx context.Context, handler discoveryHandler) {
	b.discoverServices(handler)

	discoveryTickerDuration := 10 * time.Minute

	ticker := time.NewTicker(discoveryTickerDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.discoverServices(handler)
		case <-b.discoveryReqCh:
			ticker.Reset(discoveryTickerDuration)
			b.discoverServices(handler)

			// drain
			select {
			case <-b.discoveryReqCh:
			default:
			}
		}
	}
}

func (b *baseService) discoverServices(handler discoveryHandler) {
	if b.config.RegistryURL == "" {
		return
	}

	resp, err := b.httpClient.Get(b.config.RegistryURL + "/services")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var list ServiceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	selfPubKey := handler.selfPublicKey()

	for _, svc := range list.Servers {
		if svc.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Servers[svc.PublicKey]; !exists {
			if err := handler.onServerDiscovered(svc); err != nil {
				continue
			}
		}
	}

	for _, svc := range list.Aggregators {
		if svc.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Aggregators[svc.PublicKey]; !exists {
			if err := handler.onAggregatorDiscovered(svc); err != nil {
				continue
			}
		}
	}

	for _, svc := range list.Clients {
		if svc.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Clients[svc.PublicKey]; !exists {
			if err := handler.onClientDiscovered(svc); err != nil {
				continue
			}
		}
	}
}

func (b *baseService) handleRegister(w http.ResponseWriter, r *http.Request, handler discoveryHandler) {
	// Rely on the remote registry for servers and aggregators. Refresh in the background.
	// Hacky, should be done with a timeout & rate limite. Likely a DoS vector.

	var signedReq protocol.Signed[ServiceRegistrationRequest]
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rr, signer, err := signedReq.Recover()
	if err != nil {
		http.Error(w, fmt.Errorf("could not recover registration signature: %w", err).Error(), http.StatusForbidden)
		return
	}

	if signer.String() != rr.PublicKey {
		http.Error(w, "signer does not match pubkey", http.StatusForbidden)
		return
	}

	if signer.String() == handler.selfPublicKey() {
		http.Error(w, "self-registration is not allowed", http.StatusForbidden)
		return
	}

	info := &ServiceInfo{
		ServiceType:  rr.ServiceType,
		HTTPEndpoint: rr.HTTPEndpoint,
		PublicKey:    rr.PublicKey,
		ExchangeKey:  rr.ExchangeKey,
		Attestation:  rr.Attestation,
		Signature:    signedReq.Signature.Bytes(),
	}

	switch info.ServiceType {
	case ClientService:
		if _, exists := b.registry.Clients[info.PublicKey]; !exists {
			err = handler.onClientDiscovered(info)
		}
	case AggregatorService:
		if _, exists := b.registry.Aggregators[info.PublicKey]; !exists {
			select {
			case b.discoveryReqCh <- struct{}{}:
			default:
			}
		}
	case ServerService:
		if _, exists := b.registry.Servers[info.PublicKey]; !exists {
			select {
			case b.discoveryReqCh <- struct{}{}:
			default:
			}
		}
	}

	if err != nil {
		http.Error(w, fmt.Errorf("could not recover registration signature: %w", err).Error(), http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(&ServiceRegistrationResponse{Success: true, PublicKey: signedReq.Object.PublicKey})
}

func (b *baseService) verifyAndStoreServer(info *ServiceInfo) (*ServiceEndpoint, error) {
	if _, err := VerifyServiceInfo(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, info); err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return nil, err
	}

	endpoint := &ServiceEndpoint{
		HTTPEndpoint: info.HTTPEndpoint,
		PublicKey:    pubKey,
		ExchangeKey:  info.ExchangeKey,
		Attestation:  info.Attestation,
	}
	b.registry.Servers[info.PublicKey] = endpoint
	return endpoint, nil
}

func (b *baseService) verifyAndStoreAggregator(info *ServiceInfo) (*ServiceEndpoint, error) {
	if _, err := VerifyServiceInfo(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, info); err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return nil, err
	}

	endpoint := &ServiceEndpoint{
		HTTPEndpoint: info.HTTPEndpoint,
		PublicKey:    pubKey,
		ExchangeKey:  info.ExchangeKey,
		Attestation:  info.Attestation,
	}
	b.registry.Aggregators[info.PublicKey] = endpoint
	return endpoint, nil
}

func (b *baseService) verifyAndStoreClient(info *ServiceInfo) (*ServiceEndpoint, error) {
	if _, err := VerifyServiceInfo(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, info); err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return nil, err
	}

	endpoint := &ServiceEndpoint{
		HTTPEndpoint: info.HTTPEndpoint,
		PublicKey:    pubKey,
		ExchangeKey:  info.ExchangeKey,
		Attestation:  info.Attestation,
	}
	b.registry.Clients[info.PublicKey] = endpoint
	return endpoint, nil
}
