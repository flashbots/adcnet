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

	mu           sync.RWMutex
	currentRound protocol.Round
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
		config:      config,
		roundCoord:  roundCoord,
		registry:    NewServiceRegistry(),
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		attestation: attestation,
		signingKey:  signingKey,
		exchangeKey: exchangeKey,
	}, nil
}

func (b *baseService) publicKey() crypto.PublicKey {
	pubKey, _ := b.signingKey.PublicKey()
	return pubKey
}

func (b *baseService) registerWithRegistry() error {
	if b.config.RegistryURL == "" || !b.config.SelfRegister {
		return nil
	}

	pubKey := b.publicKey()
	req := &ServiceRegistrationRequest{
		ServiceType:  b.config.ServiceType,
		PublicKey:    pubKey.String(),
		ExchangeKey:  hex.EncodeToString(b.exchangeKey.PublicKey().Bytes()),
		HTTPEndpoint: fmt.Sprintf("http://%s", b.config.HTTPAddr),
		Attestation:  b.attestation,
	}

	signedReq, err := protocol.NewSigned(b.signingKey, req)
	if err != nil {
		return fmt.Errorf("failed to sign registration: %w", err)
	}

	body, _ := json.Marshal(signedReq)

	resp, err := b.httpClient.Post(
		fmt.Sprintf("%s/register/%s", b.config.RegistryURL, b.config.ServiceType),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", string(respBody))
	}
	return nil
}

func (b *baseService) runDiscoveryLoop(ctx context.Context, handler discoveryHandler) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.discoverServices(handler)
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

func (b *baseService) sendSignedSecretExchange(endpoint string, serviceType ServiceType) error {
	pubKey := b.publicKey()
	req := &SecretExchangeRequest{
		ServiceType: serviceType,
		PublicKey:   pubKey.String(),
		ExchangeKey: hex.EncodeToString(b.exchangeKey.PublicKey().Bytes()),
	}

	signedReq, err := protocol.NewSigned(b.signingKey, req)
	if err != nil {
		return fmt.Errorf("failed to sign secret exchange: %w", err)
	}

	body, _ := json.Marshal(signedReq)
	resp, err := b.httpClient.Post(endpoint+"/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
