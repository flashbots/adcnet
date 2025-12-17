// Package common provides shared utilities for ADCNet CLI commands.
//
// This package contains helper functions used across the standalone service
// binaries (registry, server, aggregator, client) to reduce code duplication:
//
//   - Key loading and generation for Ed25519 signing and ECDH exchange keys
//   - Configuration fetching from the registry
//   - TEE provider and measurement source factory functions
package common

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/flashbots/adcnet/tdx"
)

// LoadOrGenerateSigningKey loads an Ed25519 private key from a hex string,
// or generates a new key pair if hexKey is empty.
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

// LoadOrGenerateExchangeKey loads an ECDH P-256 private key from a hex string,
// or generates a new key if hexKey is empty.
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

// FetchADCConfig retrieves protocol configuration from a registry's /config endpoint.
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

// NewAttestationProvider creates a TEE provider based on configuration flags.
// Returns TDXProvider or RemoteDCAPProvider when useTDX is true,
// otherwise returns DummyProvider for testing.
func NewAttestationProvider(useTDX bool, remoteTDXURL string) services.TEEProvider {
	if useTDX {
		if remoteTDXURL != "" {
			return &tdx.RemoteDCAPProvider{URL: remoteTDXURL, Timeout: 30 * time.Second}
		}
		return &tdx.TDXProvider{}
	}
	return &tdx.DummyProvider{}
}

// NewMeasurementSource creates a measurement source from a URL.
// Returns nil if measurementsURL is empty, indicating no measurement
// verification should be performed.
func NewMeasurementSource(measurementsURL string) services.MeasurementSource {
	if measurementsURL != "" {
		return services.NewRemoteMeasurementSource(measurementsURL)
	}
	return nil
}
