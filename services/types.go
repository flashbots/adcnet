package services

import (
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// ServiceConfig contains configuration for HTTP services.
type ServiceConfig struct {
	// Protocol configuration
	ADCNetConfig *protocol.ADCNetConfig

	// HTTP server configuration
	HTTPAddr string

	// Service identification
	ServiceID   string
	ServiceType ServiceType

	// Round coordination
	RoundDuration time.Duration
}

// ServiceType identifies the type of service.
type ServiceType string

const (
	ClientService     ServiceType = "client"
	AggregatorService ServiceType = "aggregator"
	ServerService     ServiceType = "server"
)

// RegistrationRequest is used for service registration.
type RegistrationRequest struct {
	ServiceID    string      `json:"service_id"`
	ServiceType  ServiceType `json:"service_type"`
	PublicKey    string      `json:"public_key"`
	ExchangeKey  string      `json:"exchange_key,omitempty"` // hex-encoded ECDH public key
	HTTPEndpoint string      `json:"http_endpoint"`
}

// RegistrationResponse confirms registration.
type RegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ClientMessageRequest wraps client messages for HTTP transport.
type ClientMessageRequest struct {
	Messages []*protocol.Signed[protocol.ClientRoundMessage] `json:"messages"`
}

// AggregateMessageRequest wraps aggregated messages.
type AggregateMessageRequest struct {
	Message *protocol.AggregatedClientMessages `json:"message"`
}

// PartialDecryptionRequest wraps partial decryption messages.
type PartialDecryptionRequest struct {
	Message *protocol.ServerPartialDecryptionMessage `json:"message"`
}

// RoundBroadcastResponse wraps round broadcast results.
type RoundBroadcastResponse struct {
	Broadcast *protocol.RoundBroadcast `json:"broadcast"`
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

// ServiceRegistry manages service endpoints.
type ServiceRegistry struct {
	Clients     map[string]*ServiceEndpoint
	Aggregators map[string]*ServiceEndpoint
	Servers     map[string]*ServiceEndpoint
}

// ServiceEndpoint contains service connection information.
type ServiceEndpoint struct {
	ServiceID    string
	HTTPEndpoint string
	PublicKey    crypto.PublicKey
	ExchangeKey  string // hex-encoded ECDH public key
}

// NewServiceRegistry creates an empty service registry.
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		Clients:     make(map[string]*ServiceEndpoint),
		Aggregators: make(map[string]*ServiceEndpoint),
		Servers:     make(map[string]*ServiceEndpoint),
	}
}
