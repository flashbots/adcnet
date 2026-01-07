package services

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
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

// Measurements maps register indices to expected measurement values.
type Measurements map[int][]byte

// RegistryStore abstracts persistence for registered services.
type RegistryStore interface {
	SaveService(signed *protocol.Signed[RegisteredService]) error
	DeleteService(publicKey string) error
	LoadAllServices() (map[ServiceType]map[string]*protocol.Signed[RegisteredService], error)
}

// RegistryConfig configures the registry.
type RegistryConfig struct {
	MeasurementSource   MeasurementSource
	AttestationProvider TEEProvider
	Store               RegistryStore
	// AdminToken requires basic auth for admin operations when set.
	AdminToken string
}

// Registry manages service discovery and registration for ADCNet components.
type Registry struct {
	config    *RegistryConfig
	adcConfig *protocol.ADCNetConfig

	mu       sync.RWMutex
	services map[ServiceType]map[string]*protocol.Signed[RegisteredService]
}

// NewRegistry creates a registry with the given configuration.
func NewRegistry(config *RegistryConfig, adcConfig *protocol.ADCNetConfig) (*Registry, error) {
	r := &Registry{
		config:    config,
		adcConfig: adcConfig,
		services: map[ServiceType]map[string]*protocol.Signed[RegisteredService]{
			ServerService:     make(map[string]*protocol.Signed[RegisteredService]),
			AggregatorService: make(map[string]*protocol.Signed[RegisteredService]),
			ClientService:     make(map[string]*protocol.Signed[RegisteredService]),
		},
	}

	// Load persisted services if store is configured
	if config.Store != nil {
		services, err := config.Store.LoadAllServices()
		if err != nil {
			return nil, fmt.Errorf("loading persisted services: %w", err)
		}
		for svcType, svcMap := range services {
			r.services[svcType] = svcMap
		}
	}

	return r, nil
}

func (r *Registry) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.config == nil || r.config.AdminToken == "" {
			next.ServeHTTP(w, req)
			return
		}

		user, pass, ok := req.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="ADCNet Registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		expectedHash := sha256.Sum256([]byte(r.config.AdminToken))
		actualHash := sha256.Sum256([]byte(user + ":" + pass))

		if subtle.ConstantTimeCompare(expectedHash[:], actualHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ADCNet Registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// RegisterAdminRoutes registers admin-only routes with authentication.
func (r *Registry) RegisterAdminRoutes(router chi.Router) {
	router.Group(func(admin chi.Router) {
		admin.Use(r.basicAuthMiddleware)
		admin.Post("/admin/register/{service_type}", r.handleAdminRegister)
		admin.Delete("/admin/unregister/{public_key}", r.handleUnregister)
	})
}

// RegisterPublicRoutes registers public routes.
func (r *Registry) RegisterPublicRoutes(router chi.Router) {
	router.Post("/register/{service_type}", r.handleRegisterPublic)
	router.Get("/services", r.handleGetServices)
	router.Get("/services/{type}", r.handleGetServicesByType)
	router.Get("/config", r.handleGetConfig)
	router.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (r *Registry) handleAdminRegister(w http.ResponseWriter, req *http.Request) {
	r.handleRegister(w, req)
}

func (r *Registry) handleRegisterPublic(w http.ResponseWriter, req *http.Request) {
	serviceType := ServiceType(chi.URLParam(req, "service_type"))

	if r.config != nil && r.config.AdminToken != "" {
		if serviceType != ClientService {
			http.Error(w, "use /admin/register for servers and aggregators", http.StatusForbidden)
			return
		}
	}

	r.handleRegister(w, req)
}

func (r *Registry) handleRegister(w http.ResponseWriter, req *http.Request) {
	serviceType := ServiceType(chi.URLParam(req, "service_type"))
	if !serviceType.Valid() {
		http.Error(w, "invalid service type", http.StatusBadRequest)
		return
	}

	var signedReq protocol.Signed[RegisteredService]
	if err := json.NewDecoder(req.Body).Decode(&signedReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	regReq, signer, err := signedReq.Recover()
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusForbidden)
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

	if _, err := hex.DecodeString(regReq.ExchangeKey); err != nil {
		http.Error(w, "invalid exchange key", http.StatusBadRequest)
		return
	}

	if r.config != nil && r.config.AttestationProvider != nil {
		_, err := VerifyRegistration(r.config.MeasurementSource, r.config.AttestationProvider, &signedReq)
		if err != nil {
			http.Error(w, fmt.Sprintf("attestation verification failed: %v", err), http.StatusForbidden)
			return
		}
	}

	r.mu.Lock()
	r.services[serviceType][pubKey.String()] = &signedReq
	r.mu.Unlock()

	// Persist to store if configured
	if r.config.Store != nil {
		if err := r.config.Store.SaveService(&signedReq); err != nil {
			// Log but don't fail the request - service is in memory
			fmt.Printf("Warning: failed to persist service registration: %v\n", err)
		}
	}

	if err := json.NewEncoder(w).Encode(&ServiceRegistrationResponse{
		Success:   true,
		PublicKey: pubKey.String(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Registry) handleUnregister(w http.ResponseWriter, req *http.Request) {
	publicKey := chi.URLParam(req, "public_key")

	r.mu.Lock()
	for _, typeMap := range r.services {
		delete(typeMap, publicKey)
	}
	r.mu.Unlock()

	if r.config.Store != nil {
		if err := r.config.Store.DeleteService(publicKey); err != nil {
			fmt.Printf("Warning: failed to delete service from store: %v\n", err)
		}
	}

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

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

	if err := json.NewEncoder(w).Encode(services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Registry) handleGetConfig(w http.ResponseWriter, req *http.Request) {
	if err := json.NewEncoder(w).Encode(r.adcConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (r *Registry) collectServices(serviceType ServiceType) []*protocol.Signed[RegisteredService] {
	typeMap := r.services[serviceType]
	result := make([]*protocol.Signed[RegisteredService], 0, len(typeMap))
	for _, svc := range typeMap {
		result = append(result, svc)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Object.PublicKey < result[j].Object.PublicKey })
	return result
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
func AttestServiceRegistration(attestationProvider TEEProvider, r *RegisteredService) ([]byte, error) {
	if attestationProvider == nil {
		return nil, nil
	}
	var reportData [64]byte
	copy(reportData[:], ReportDataForService([]byte(r.ExchangeKey), r.HTTPEndpoint, crypto.PublicKey(r.PublicKey)))
	return attestationProvider.Attest(reportData)
}

// VerifyRegistration verifies attestation for a signed registration.
func VerifyRegistration(source MeasurementSource, attestationProvider TEEProvider, signedReq *protocol.Signed[RegisteredService]) (Measurements, error) {
	rr, signer, err := signedReq.Recover()
	if err != nil {
		return nil, err
	}
	if signer.String() != rr.PublicKey {
		return nil, fmt.Errorf("pubkey mismatch")
	}

	if attestationProvider == nil {
		return nil, nil
	}
	if len(rr.Attestation) == 0 {
		return nil, fmt.Errorf("no attestation data")
	}

	var reportData [64]byte
	copy(reportData[:], ReportDataForService([]byte(rr.ExchangeKey), rr.HTTPEndpoint, crypto.PublicKey(rr.PublicKey)))
	measurements, err := attestationProvider.Verify(rr.Attestation, reportData)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}

	if source != nil {
		allowedMeasurements, err := source.GetAllowedMeasurements()
		if err != nil {
			return nil, fmt.Errorf("fetching allowed measurements: %w", err)
		}

		_, err = VerifyMeasurementsMatch(allowedMeasurements, measurements)
		if err != nil {
			return nil, fmt.Errorf("attestation not allowed: %w", err)
		}
	}

	return measurements, nil
}
