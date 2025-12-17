package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
)

// TEEProvider abstracts attestation generation and verification.
type TEEProvider interface {
	AttestationType() string
	Attest(reportData [64]byte) ([]byte, error)
	Verify(attestationReport []byte, expectedReportData [64]byte) (map[int][]byte, error)
}

// Measurements maps PCR indices to expected measurement values for attestation verification.
type Measurements map[int][]byte

// RegistryConfig configures allowed attestation measurements.
type RegistryConfig struct {
	MeasurementSource   MeasurementSource
	AttestationProvider TEEProvider
}

// Registry manages service discovery and registration for ADCNet components.
type Registry struct {
	config    *RegistryConfig
	adcConfig *protocol.ADCNetConfig

	mu       sync.RWMutex
	services map[ServiceType]map[string]*RegisteredService
}

// NewRegistry creates a registry with the given configuration.
func NewRegistry(config *RegistryConfig, adcConfig *protocol.ADCNetConfig) *Registry {
	return &Registry{
		config:    config,
		adcConfig: adcConfig,
		services: map[ServiceType]map[string]*RegisteredService{
			ServerService:     make(map[string]*RegisteredService),
			AggregatorService: make(map[string]*RegisteredService),
			ClientService:     make(map[string]*RegisteredService),
		},
	}
}

func (r *Registry) RegisterAdminRoutes(router chi.Router) {
	router.Post("/register/{service_type}", r.handleRegister)
	router.Delete("/unregister/{public_key}", r.handleUnregister)
}

func (r *Registry) RegisterPublicRoutes(router chi.Router) {
	router.Post("/register/{service_type}", r.handleRegisterPublic)
	// router.Delete("/unregister/client", r.handleUnregisterPublic)
	router.Get("/services", r.handleGetServices)
	router.Get("/services/{type}", r.handleGetServicesByType)
	router.Get("/config", r.handleGetConfig)
}

func (r *Registry) handleRegisterPublic(w http.ResponseWriter, req *http.Request) {
	// TODO: public access should only be able to register clients, and possibly aggregators until liveness issues are addressed
	r.handleRegister(w, req)
}

func (r *Registry) handleRegister(w http.ResponseWriter, req *http.Request) {
	serviceType := ServiceType(chi.URLParam(req, "service_type"))
	if !serviceType.Valid() {
		http.Error(w, "invalid service type", http.StatusBadRequest)
		return
	}

	var signedReq protocol.Signed[ServiceRegistrationRequest]
	if err := json.NewDecoder(req.Body).Decode(&signedReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	regReq, signer, err := signedReq.Recover()
	if err != nil {
		http.Error(w, fmt.Errorf("invalid signature: %w", err).Error(), http.StatusForbidden)
		return
	}

	if regReq.ServiceType != serviceType {
		http.Error(w, fmt.Sprintf("service type mismatch: URL says %s, body says %s", serviceType, regReq.ServiceType), http.StatusBadRequest)
		return
	}

	pubKey, err := crypto.NewPublicKeyFromString(regReq.PublicKey)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	if signer.String() != pubKey.String() {
		http.Error(w, "signer does not match claimed public key", http.StatusForbidden)
		return
	}

	exchangeKey, err := hex.DecodeString(regReq.ExchangeKey)
	if err != nil {
		http.Error(w, "invalid exchange key", http.StatusBadRequest)
		return
	}

	svc := &RegisteredService{
		Type:           serviceType,
		Endpoint:       regReq.HTTPEndpoint,
		PublicKey:      pubKey,
		ExchangePubKey: exchangeKey,
		Attestation:    regReq.Attestation,
		Signature:      signedReq.Signature,
	}

	if r.config != nil && r.config.AttestationProvider != nil {
		_, err := VerifyServiceInfo(r.config.MeasurementSource, r.config.AttestationProvider, svc.ToServiceInfo())
		if err != nil {
			http.Error(w, fmt.Sprintf("attestation verification failed: %v", err), http.StatusForbidden)
			return
		}
	}

	r.mu.Lock()
	r.services[serviceType][pubKey.String()] = svc
	r.mu.Unlock()

	json.NewEncoder(w).Encode(&ServiceRegistrationResponse{
		Success:   true,
		PublicKey: pubKey.String(),
	})
}

func (r *Registry) handleUnregister(w http.ResponseWriter, req *http.Request) {
	publicKey := chi.URLParam(req, "public_key")

	r.mu.Lock()
	for _, typeMap := range r.services {
		delete(typeMap, publicKey)
	}
	r.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (r *Registry) handleGetServices(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	resp := &ServiceListResponse{
		Servers:     r.collectServices(ServerService),
		Aggregators: r.collectServices(AggregatorService),
		Clients:     r.collectServices(ClientService),
	}
	r.mu.RUnlock()

	json.NewEncoder(w).Encode(resp)
}

func (r *Registry) handleGetServicesByType(w http.ResponseWriter, req *http.Request) {
	svcType := ServiceType(chi.URLParam(req, "type"))
	if !svcType.Valid() {
		http.Error(w, "invalid service type", http.StatusBadRequest)
		return
	}

	r.mu.RLock()
	services := r.collectServices(svcType)
	r.mu.RUnlock()

	json.NewEncoder(w).Encode(services)
}

func (r *Registry) handleGetConfig(w http.ResponseWriter, req *http.Request) {
	json.NewEncoder(w).Encode(r.adcConfig)
}

func (r *Registry) collectServices(serviceType ServiceType) []*ServiceInfo {
	typeMap := r.services[serviceType]
	result := make([]*ServiceInfo, 0, len(typeMap))
	for _, svc := range typeMap {
		result = append(result, svc.ToServiceInfo())
	}
	return result
}

// Valid returns true if the service type is recognized.
func (t ServiceType) Valid() bool {
	switch t {
	case ClientService, AggregatorService, ServerService:
		return true
	}
	return false
}

// SerializeRegistrationRequest serializes a registration request for signing.
func SerializeRegistrationRequest(r *ServiceRegistrationRequest) ([]byte, error) {
	return json.Marshal(r)
}

// SerializeSecretExchangeRequest serializes a secret exchange request for signing.
func SerializeSecretExchangeRequest(r *SecretExchangeRequest) ([]byte, error) {
	return json.Marshal(r)
}

// ReportDataForService computes the attestation report data binding service identity.
func ReportDataForService(exchangeKey []byte, httpEndpoint string, pubKey crypto.PublicKey) []byte {
	hash := sha256.New()
	hash.Write(exchangeKey)
	hash.Write([]byte(httpEndpoint))
	hash.Write(pubKey.Bytes())
	return hash.Sum(nil)
}

// AttestServiceRegistration generates attestation evidence for a service.
func AttestServiceRegistration(attestationProvider TEEProvider, r *ServiceRegistrationRequest) ([]byte, error) {
	if attestationProvider == nil {
		return nil, nil
	}
	var reportData [64]byte
	copy(reportData[:], ReportDataForService([]byte(r.ExchangeKey), r.HTTPEndpoint, crypto.PublicKey(r.PublicKey)))
	return attestationProvider.Attest(reportData)
}

// VerifyServiceInfo verifies attestation for a discovered service.
func VerifyServiceInfo(source MeasurementSource, attestationProvider TEEProvider, info *ServiceInfo) (Measurements, error) {
	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	req := &ServiceRegistrationRequest{
		ServiceType:  info.ServiceType,
		PublicKey:    info.PublicKey,
		ExchangeKey:  info.ExchangeKey,
		HTTPEndpoint: info.HTTPEndpoint,
		Attestation:  info.Attestation,
	}
	_, signer, err := (&protocol.Signed[ServiceRegistrationRequest]{
		PublicKey: pubKey,
		Signature: info.Signature,
		Object:    req,
	}).Recover()
	if err != nil {
		return nil, err
	}
	if signer.String() != info.PublicKey {
		return nil, errors.New("pubkey mismatch")
	}

	if attestationProvider == nil {
		return nil, nil
	}
	if len(req.Attestation) == 0 {
		return nil, errors.New("no attestation data")
	}

	var reportData [64]byte
	copy(reportData[:], ReportDataForService([]byte(req.ExchangeKey), req.HTTPEndpoint, crypto.PublicKey(req.PublicKey)))
	measurements, err := attestationProvider.Verify(req.Attestation, reportData)
	if err != nil {
		return nil, fmt.Errorf("could not verify attestation: %w", err)
	}

	if source != nil {
		allowedMeasurements, err := source.GetAllowedMeasurements()
		if err != nil {
			return nil, fmt.Errorf("could not fetch allowed measurements: %w", err)
		}

		_, err = VerifyMeasurementsMatch(allowedMeasurements, measurements)
		if err != nil {
			return nil, fmt.Errorf("attestation is not allowed: %w", err)
		}
	}

	return measurements, nil
}
