// Package common provides shared utilities for ADCNet CLI commands.
package common

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/flashbots/adcnet/tdx"
	"gopkg.in/yaml.v3"
)

// Config contains configuration for ADCNet services.
type Config struct {
	// ServiceType specifies which service to run: client, server, or aggregator.
	ServiceType string `yaml:"service_type"`

	// HTTPAddr is the address to listen on.
	HTTPAddr string `yaml:"http_addr"`

	// RegistryURL is the central registry for service discovery.
	RegistryURL string `yaml:"registry_url"`

	// AdminToken for authenticating with registry admin endpoints (user:pass).
	AdminToken string `yaml:"admin_token"`

	// Keys configuration.
	Keys KeysConfig `yaml:"keys"`

	// Attestation configuration.
	Attestation AttestationConfig `yaml:"attestation"`

	// Server-specific configuration.
	Server ServerConfig `yaml:"server"`

	// Protocol configuration (registry only).
	Protocol ProtocolConfig `yaml:"protocol"`
}

// KeysConfig contains cryptographic key settings.
type KeysConfig struct {
	// SigningKey is hex-encoded Ed25519 private key. Generated if empty.
	SigningKey string `yaml:"signing_key"`

	// ExchangeKey is hex-encoded ECDH P-256 private key. Generated if empty.
	ExchangeKey string `yaml:"exchange_key"`
}

// AttestationConfig contains TEE attestation settings.
type AttestationConfig struct {
	// UseTDX enables real TDX attestation.
	UseTDX bool `yaml:"use_tdx"`

	// TDXRemoteURL is the remote TDX attestation service URL.
	TDXRemoteURL string `yaml:"tdx_remote_url"`

	// MeasurementsURL is the URL for allowed measurements.
	MeasurementsURL string `yaml:"measurements_url"`
}

// ServerConfig contains server-specific settings.
type ServerConfig struct {
	// IsLeader designates this server as the round leader.
	IsLeader bool `yaml:"is_leader"`
}

// ProtocolConfig contains ADCNet protocol parameters.
type ProtocolConfig struct {
	// RoundDuration is the time duration of each protocol round.
	RoundDuration time.Duration `yaml:"round_duration"`

	// MessageLength is the byte length of the message vector.
	MessageLength int `yaml:"message_length"`

	// AuctionSlots is the number of slots in the IBLT for auction data.
	AuctionSlots uint32 `yaml:"auction_slots"`

	// MinClients is the minimum number of clients for anonymity.
	MinClients uint32 `yaml:"min_clients"`

	// RoundsPerWindow defines rounds per participation window.
	RoundsPerWindow uint32 `yaml:"rounds_per_window"`
}

// DefaultConfig returns configuration with default values.
func DefaultConfig() *Config {
	return &Config{
		ServiceType: "client",
		HTTPAddr:    "", // Set by command if not in config
		Protocol: ProtocolConfig{
			RoundDuration:   10 * time.Second,
			MessageLength:   512000,
			AuctionSlots:    10,
			MinClients:      1,
			RoundsPerWindow: 10,
		},
	}
}

// LoadConfig reads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return config, nil
}

// LoadOrGenerateSigningKey loads an Ed25519 private key from hex or generates one.
func LoadOrGenerateSigningKey(hexKey string) (crypto.PrivateKey, error) {
	if hexKey != "" {
		keyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("invalid hex: %w", err)
		}
		return crypto.NewPrivateKeyFromBytes(keyBytes), nil
	}
	_, privKey, err := crypto.GenerateKeyPair()
	return privKey, err
}

// LoadOrGenerateExchangeKey loads an ECDH P-256 private key from hex or generates one.
func LoadOrGenerateExchangeKey(hexKey string) (*ecdh.PrivateKey, error) {
	if hexKey != "" {
		keyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("invalid hex: %w", err)
		}
		return ecdh.P256().NewPrivateKey(keyBytes)
	}
	return ecdh.P256().GenerateKey(rand.Reader)
}

// FetchADCConfig retrieves protocol configuration from a registry.
func FetchADCConfig(registryURL string) (*protocol.ADCNetConfig, error) {
	resp, err := http.Get(registryURL + "/config")
	if err != nil {
		return nil, fmt.Errorf("fetch config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	config, err := protocol.DecodeMessage[protocol.ADCNetConfig](resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return config, nil
}

// NewAttestationProvider creates a TEE provider based on configuration.
func NewAttestationProvider(cfg AttestationConfig) services.TEEProvider {
	if cfg.UseTDX {
		if cfg.TDXRemoteURL != "" {
			return &tdx.RemoteDCAPProvider{URL: cfg.TDXRemoteURL, Timeout: 30 * time.Second}
		}
		return &tdx.TDXProvider{}
	}
	return &tdx.DummyProvider{}
}

// NewMeasurementSource creates a measurement source from configuration.
func NewMeasurementSource(measurementsURL string) services.MeasurementSource {
	if measurementsURL != "" {
		return services.NewRemoteMeasurementSource(measurementsURL)
	}
	return nil
}

// ToADCNetConfig converts ProtocolConfig to protocol.ADCNetConfig.
func (p *ProtocolConfig) ToADCNetConfig() *protocol.ADCNetConfig {
	return &protocol.ADCNetConfig{
		AuctionSlots:    p.AuctionSlots,
		MessageLength:   p.MessageLength,
		MinClients:      p.MinClients,
		RoundDuration:   p.RoundDuration,
		RoundsPerWindow: p.RoundsPerWindow,
	}
}

// ToServicesType converts a string service type to services.ServiceType.
func ToServicesType(s string) (services.ServiceType, error) {
	switch s {
	case "client":
		return services.ClientService, nil
	case "server":
		return services.ServerService, nil
	case "aggregator":
		return services.AggregatorService, nil
	default:
		return "", fmt.Errorf("invalid service type: %s (must be client, server, or aggregator)", s)
	}
}
