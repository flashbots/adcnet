package services

import (
	"encoding/hex"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// ServiceConfig contains configuration for HTTP services.
type ServiceConfig struct {
	ADCNetConfig              *protocol.ADCNetConfig
	AttestationProvider       TEEProvider
	AllowedMeasurementsSource MeasurementSource
	HTTPAddr                  string
	ServiceType               ServiceType
	RegistryURL               string
	// AdminToken for authenticating with registry admin endpoints (user:pass).
	// Required for servers and aggregators.
	AdminToken string
}

// ServiceType identifies the type of service.
type ServiceType string

const (
	ClientService     ServiceType = "client"
	AggregatorService ServiceType = "aggregator"
	ServerService     ServiceType = "server"
)

// ServiceRegistrationRequest registers a service with the central registry.
type ServiceRegistrationRequest struct {
	ServiceType  ServiceType `json:"service_type"`
	PublicKey    string      `json:"public_key"`
	ExchangeKey  string      `json:"exchange_key"`
	HTTPEndpoint string      `json:"http_endpoint"`
	Attestation  []byte      `json:"attestation,omitempty"`
}

// ServiceRegistrationResponse confirms registry registration.
type ServiceRegistrationResponse struct {
	Success   bool   `json:"success"`
	PublicKey string `json:"public_key,omitempty"`
	Message   string `json:"message,omitempty"`
}

// ServiceInfo describes a registered service for discovery.
type ServiceInfo struct {
	ServiceType  ServiceType `json:"service_type"`
	HTTPEndpoint string      `json:"http_endpoint"`
	PublicKey    string      `json:"public_key"`
	ExchangeKey  string      `json:"exchange_key"`
	Attestation  []byte      `json:"attestation,omitempty"`
	Signature    []byte      `json:"signature,omitempty"`
}

func (i *ServiceInfo) ToServiceRegistrationRequest() *ServiceRegistrationRequest {
	return &ServiceRegistrationRequest{
		ServiceType:  i.ServiceType,
		PublicKey:    i.PublicKey,
		ExchangeKey:  i.ExchangeKey,
		HTTPEndpoint: i.HTTPEndpoint,
		Attestation:  i.Attestation,
	}
}

// ServiceListResponse contains all registered services by type.
type ServiceListResponse struct {
	Servers     []*ServiceInfo `json:"servers"`
	Aggregators []*ServiceInfo `json:"aggregators"`
	Clients     []*ServiceInfo `json:"clients"`
}

// SecretExchangeResponse confirms shared secret establishment.
type SecretExchangeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ClientMessageRequest wraps signed client messages for HTTP transport.
type ClientMessageRequest struct {
	Messages []*protocol.Signed[protocol.ClientRoundMessage] `json:"messages"`
}

// AggregateMessageRequest wraps signed aggregated messages.
type AggregateMessageRequest struct {
	Message *protocol.Signed[protocol.AggregatedClientMessages] `json:"message"`
}

// PartialDecryptionRequest wraps signed partial decryption messages.
type PartialDecryptionRequest struct {
	Message *protocol.Signed[protocol.ServerPartialDecryptionMessage] `json:"message"`
}

// RoundBroadcastResponse wraps signed round broadcast results.
type RoundBroadcastResponse struct {
	Broadcast *protocol.Signed[protocol.RoundBroadcast] `json:"broadcast"`
}

// AggregateAggregatesRequest wraps signed aggregates for inter-aggregator communication.
type AggregateAggregatesRequest struct {
	Messages []*protocol.Signed[protocol.AggregatedClientMessages] `json:"messages"`
}

// ScheduleMessageRequest schedules a message for broadcast.
type ScheduleMessageRequest struct {
	Message  []byte `json:"message"`
	BidValue uint32 `json:"bid_value"`
}

// MessageResponse indicates if client messages were sent.
type MessageResponse struct {
	Sent     bool                                            `json:"sent"`
	Messages []*protocol.Signed[protocol.ClientRoundMessage] `json:"messages,omitempty"`
}

// ServiceRegistry caches discovered service endpoints locally.
type ServiceRegistry struct {
	Clients     map[string]*ServiceEndpoint
	Aggregators map[string]*ServiceEndpoint
	Servers     map[string]*ServiceEndpoint
}

// ServiceEndpoint contains connection information for a discovered service.
// TODO: replace with ServiceInfo
type ServiceEndpoint struct {
	HTTPEndpoint string
	PublicKey    crypto.PublicKey
	ExchangeKey  string
	Attestation  []byte
}

// NewServiceRegistry creates an empty local service cache.
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		Clients:     make(map[string]*ServiceEndpoint),
		Aggregators: make(map[string]*ServiceEndpoint),
		Servers:     make(map[string]*ServiceEndpoint),
	}
}

// RegisteredService contains registration data for a service instance.
// TODO: replace with ServiceInfo
type RegisteredService struct {
	Type           ServiceType
	Endpoint       string
	PublicKey      crypto.PublicKey
	ExchangePubKey []byte
	Attestation    []byte
	Signature      crypto.Signature
}

// ToServiceInfo converts a RegisteredService to ServiceInfo.
func (s *RegisteredService) ToServiceInfo() *ServiceInfo {
	return &ServiceInfo{
		ServiceType:  s.Type,
		HTTPEndpoint: s.Endpoint,
		PublicKey:    s.PublicKey.String(),
		ExchangeKey:  hex.EncodeToString(s.ExchangePubKey),
		Attestation:  s.Attestation,
		Signature:    s.Signature.Bytes(),
	}
}
