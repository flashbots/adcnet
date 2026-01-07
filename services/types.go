package services

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"

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
	AdminToken string
}

// ServiceType identifies the type of service.
type ServiceType string

const (
	ClientService     ServiceType = "client"
	AggregatorService ServiceType = "aggregator"
	ServerService     ServiceType = "server"
)

// Valid returns true if the service type is recognized.
func (t ServiceType) Valid() bool {
	switch t {
	case ClientService, AggregatorService, ServerService:
		return true
	}
	return false
}

// RegisteredService contains all registration data for a service instance.
// This is the canonical type used throughout the system for service identity.
type RegisteredService struct {
	ServiceType  ServiceType `json:"service_type"`
	HTTPEndpoint string      `json:"http_endpoint"`
	PublicKey    string      `json:"public_key"`
	ExchangeKey  string      `json:"exchange_key"`
	Attestation  []byte      `json:"attestation,omitempty"`
}

// ParsePublicKey returns the parsed signing public key.
func (s *RegisteredService) ParsePublicKey() (crypto.PublicKey, error) {
	return crypto.NewPublicKeyFromString(s.PublicKey)
}

// ParseExchangeKey returns the parsed ECDH public key.
func ParseExchangeKey(exchangeKey string) (*ecdh.PublicKey, error) {
	keyBytes, err := hex.DecodeString(exchangeKey)
	if err != nil {
		return nil, fmt.Errorf("invalid exchange key hex: %w", err)
	}
	return ecdh.P256().NewPublicKey(keyBytes)
}

// ServiceListResponse contains all registered services by type.
type ServiceListResponse struct {
	Servers     []*protocol.Signed[RegisteredService] `json:"servers"`
	Aggregators []*protocol.Signed[RegisteredService] `json:"aggregators"`
	Clients     []*protocol.Signed[RegisteredService] `json:"clients"`
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

// ServiceRegistrationResponse confirms registry registration.
type ServiceRegistrationResponse struct {
	Success   bool   `json:"success"`
	PublicKey string `json:"public_key,omitempty"`
	Message   string `json:"message,omitempty"`
}

// LocalServiceRegistry caches discovered and verified service endpoints locally.
type LocalServiceRegistry struct {
	Clients     map[string]*protocol.Signed[RegisteredService]
	Aggregators map[string]*protocol.Signed[RegisteredService]
	Servers     map[string]*protocol.Signed[RegisteredService]
}

// NewLocalServiceRegistry creates an empty local service cache.
func NewLocalServiceRegistry() *LocalServiceRegistry {
	return &LocalServiceRegistry{
		Clients:     make(map[string]*protocol.Signed[RegisteredService]),
		Aggregators: make(map[string]*protocol.Signed[RegisteredService]),
		Servers:     make(map[string]*protocol.Signed[RegisteredService]),
	}
}
