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
	onServerDiscovered(*protocol.Signed[RegisteredService]) error
	onAggregatorDiscovered(*protocol.Signed[RegisteredService]) error
	onClientDiscovered(*protocol.Signed[RegisteredService]) error
	selfPublicKey() string
}

// baseService contains common fields and methods for all HTTP services.
type baseService struct {
	config      *ServiceConfig
	roundCoord  *protocol.LocalRoundCoordinator
	registry    *LocalServiceRegistry
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

	pubKey, err := signingKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	req := &RegisteredService{
		ServiceType:  config.ServiceType,
		PublicKey:    pubKey.String(),
		ExchangeKey:  hex.EncodeToString(exchangeKey.PublicKey().Bytes()),
		HTTPEndpoint: fmt.Sprintf("http://%s", config.HTTPAddr),
	}

	attestation, err := AttestServiceRegistration(config.AttestationProvider, req)
	if err != nil {
		return nil, fmt.Errorf("attesting registration: %w", err)
	}

	return &baseService{
		config:         config,
		roundCoord:     roundCoord,
		registry:       NewLocalServiceRegistry(),
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		attestation:    attestation,
		signingKey:     signingKey,
		exchangeKey:    exchangeKey,
		discoveryReqCh: make(chan struct{}, 1),
	}, nil
}

func (b *baseService) publicKey() crypto.PublicKey {
	pubKey, _ := b.signingKey.PublicKey()
	return pubKey
}

func (b *baseService) createSignedRegistration() (*protocol.Signed[RegisteredService], error) {
	pubKey := b.publicKey()
	req := &RegisteredService{
		ServiceType:  b.config.ServiceType,
		PublicKey:    pubKey.String(),
		ExchangeKey:  hex.EncodeToString(b.exchangeKey.PublicKey().Bytes()),
		HTTPEndpoint: fmt.Sprintf("http://%s", b.config.HTTPAddr),
		Attestation:  b.attestation,
	}
	return protocol.NewSigned(b.signingKey, req)
}

func (b *baseService) sendRegistrationDirectly(endpoint string) error {
	signedReq, err := b.createSignedRegistration()
	if err != nil {
		return fmt.Errorf("signing registration: %w", err)
	}

	body, err := json.Marshal(signedReq)
	if err != nil {
		return fmt.Errorf("marshaling registration: %w", err)
	}

	resp, err := b.httpClient.Post(endpoint+"/register", "application/json", bytes.NewReader(body))
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

// registerWithRegistry registers this service with the central registry.
func (b *baseService) registerWithRegistry() error {
	if b.config.RegistryURL == "" {
		return nil
	}

	signedReq, err := b.createSignedRegistration()
	if err != nil {
		return fmt.Errorf("signing registration: %w", err)
	}

	body, err := json.Marshal(signedReq)
	if err != nil {
		return fmt.Errorf("marshaling registration: %w", err)
	}

	var url string
	if b.config.ServiceType == ClientService {
		url = fmt.Sprintf("%s/register/%s", b.config.RegistryURL, b.config.ServiceType)
	} else {
		url = fmt.Sprintf("%s/admin/register/%s", b.config.RegistryURL, b.config.ServiceType)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

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
			// Drain all pending discovery requests
			for {
				select {
				case <-b.discoveryReqCh:
				default:
					goto drained
				}
			}
		drained:
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
		if svc.Object.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Servers[svc.Object.PublicKey]; !exists {
			if err := handler.onServerDiscovered(svc); err != nil {
				continue
			}
		}
	}

	for _, svc := range list.Aggregators {
		if svc.Object.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Aggregators[svc.Object.PublicKey]; !exists {
			if err := handler.onAggregatorDiscovered(svc); err != nil {
				continue
			}
		}
	}

	for _, svc := range list.Clients {
		if svc.Object.PublicKey == selfPubKey {
			continue
		}
		if _, exists := b.registry.Clients[svc.Object.PublicKey]; !exists {
			if err := handler.onClientDiscovered(svc); err != nil {
				continue
			}
		}
	}
}

func (b *baseService) handleRegister(w http.ResponseWriter, r *http.Request, handler discoveryHandler) {
	var signedReq protocol.Signed[RegisteredService]
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rr, signer, err := signedReq.Recover()
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusForbidden)
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

	switch rr.ServiceType {
	case ClientService:
		if _, exists := b.registry.Clients[rr.PublicKey]; !exists {
			if err := handler.onClientDiscovered(&signedReq); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
	case AggregatorService:
		if _, exists := b.registry.Aggregators[rr.PublicKey]; !exists {
			select {
			case b.discoveryReqCh <- struct{}{}:
			default:
			}
		}
	case ServerService:
		if _, exists := b.registry.Servers[rr.PublicKey]; !exists {
			select {
			case b.discoveryReqCh <- struct{}{}:
			default:
			}
		}
	}

	if err := json.NewEncoder(w).Encode(&ServiceRegistrationResponse{Success: true, PublicKey: rr.PublicKey}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (b *baseService) verifyAndStoreServer(signed *protocol.Signed[RegisteredService]) error {
	svc, _, err := signed.Recover()
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if _, err := VerifyRegistration(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, signed); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	b.registry.Servers[svc.PublicKey] = signed
	return nil
}

func (b *baseService) verifyAndStoreAggregator(signed *protocol.Signed[RegisteredService]) error {
	svc, _, err := signed.Recover()
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if _, err := VerifyRegistration(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, signed); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	b.registry.Aggregators[svc.PublicKey] = signed
	return nil
}

func (b *baseService) verifyAndStoreClient(signed *protocol.Signed[RegisteredService]) error {
	svc, _, err := signed.Recover()
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if _, err := VerifyRegistration(b.config.AllowedMeasurementsSource, b.config.AttestationProvider, signed); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	b.registry.Clients[svc.PublicKey] = signed
	return nil
}
