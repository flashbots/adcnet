/*
Package services provides HTTP-based implementations of ADCNet protocol
components with centralized service discovery and attestation verification.

# Overview

This package wraps the core protocol implementations with HTTP APIs and a
central registry for service discovery:
  - RESTful communication between components
  - Centralized registry for service registration and discovery
  - Attestation verification during service discovery
  - Automatic shared secret establishment via ECDH
  - Services identified by public keys
  - All messages signed and verified for integrity

# Components

## Registry

The central Registry manages service discovery and registration. Services are
keyed by their public key. The registry supports admin authentication for
registering infrastructure services (servers, aggregators).

Public Endpoints:
  - POST /register/client - Register a client (no auth required)
  - GET /services - List all registered services
  - GET /services/{type} - List services by type
  - GET /config - Get protocol configuration
  - GET /health - Health check endpoint

Admin Endpoints (require basic auth when AdminToken is configured):
  - POST /admin/register/{service_type} - Register servers and aggregators
  - DELETE /admin/unregister/{public_key} - Remove a service

## HTTP Services

HTTPClient wraps protocol.ClientService with registry integration.
Clients self-register on startup via the public endpoint. Clients poll
servers for round broadcasts rather than receiving pushed updates, allowing
inactive clients to naturally stop participating without cleanup.

HTTPAggregator wraps protocol.AggregatorService with registry integration.
Aggregators self-register via admin endpoint with configured admin_token.
Endpoints: POST /register, POST /client-messages, POST /aggregate-messages,
GET /aggregates/{round}.

HTTPServer wraps protocol.ServerService with registry integration.
Servers self-register via admin endpoint with configured admin_token.
Endpoints: POST /register, POST /aggregate, POST /partial-decryption,
GET /round-broadcast/{round}.

## Measurement Sources

MeasurementSource provides expected TEE measurements for attestation verification:
  - StaticMeasurementSource: Predefined measurements for testing/demo
  - RemoteMeasurementSource: Fetches measurements from a URL with caching
  - DemoMeasurementSource(): Factory for dummy attestation compatibility

## Service Configuration

ServiceConfig controls service behavior:
  - ADCNetConfig: Protocol parameters (round duration, message length, etc.)
  - AttestationProvider: TEE provider for generating/verifying attestations
  - AllowedMeasurementsSource: Expected measurements for peer verification
  - RegistryURL: Central registry for service discovery
  - AdminToken: Authentication for admin registration (servers/aggregators)

Configuration can be provided via YAML files:

	http_addr: ":8081"
	registry_url: "http://localhost:8080"
	admin_token: "admin:secret"
	keys:
	  signing_key: ""
	  exchange_key: ""
	attestation:
	  use_tdx: false
	  measurements_url: ""
	server:
	  is_leader: false

## Service Lifecycle

 1. Registry starts with optional admin authentication configured
 2. Servers and aggregators start and self-register via admin endpoint
 3. Clients start and self-register via public endpoint
 4. Services begin discovery polling after registration
 5. During discovery, attestation is verified before adding peers
 6. Secret exchange uses signed requests, verified against local registry

# Message Flow

  - Client Phase: Clients discover servers and aggregators, establish shared
    secrets via signed exchange requests, XOR-blind messages with one-time pads,
    and send signed messages to aggregators. Clients poll servers for previous
    round broadcasts to determine auction results.
  - Aggregation Phase: Aggregators discover servers, XOR client message vectors
    and add auction vectors in the finite field, then forward signed aggregates
    to all servers.
  - Server Phase: Each server removes its XOR blinding factors, servers exchange
    signed partial decryptions, and the leader reconstructs messages. Round
    broadcasts are stored and made available via GET endpoint for client polling.

# Security Model

All messages are signed and verified:
  - ServiceRegistrationRequest: Signed by registrant, verified by registry
  - SecretExchangeRequest: Signed by requester, verified against attested registry
  - ClientRoundMessage: Signed by client, verified by aggregator
  - AggregatedClientMessages: Signed by aggregator, verified by servers
  - ServerPartialDecryptionMessage: Signed by server, verified by other servers
  - RoundBroadcast: Signed by leader server, verified by clients when polled

Attestation verification occurs during service discovery. All protocol messages
are verified against attested keys stored in the local registry.

# Security Notes

  - Ed25519 for all digital signatures
  - ECDH P-256 for key exchange and shared secret derivation
  - XOR-based one-time pad blinding per round
  - Attestation verification during service discovery
  - All messages signed and verified against attested registry
  - Requires ALL servers to participate for message recovery
  - Basic auth protects admin registration of servers and aggregators
  - Constant-time comparison for admin token verification

# Performance

  - Aggregators reduce server bandwidth by O(NumClients)
  - Parallel HTTP requests for efficiency
  - Configurable round duration for throughput tuning
  - Periodic discovery polling (default: 10 minute interval)
  - Measurement source caches results for 1 hour
  - Client polling for broadcasts eliminates stale client tracking
*/
package services
