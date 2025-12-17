// src_services_doc.go
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

The central Registry manages service discovery and registration. Services
register themselves with the registry and periodically poll for new peers.
Services are keyed by their public key.

Endpoints:
  - POST /register/{service_type} - Register a service with signed request and attestation
  - DELETE /unregister/{public_key} - Remove a service
  - GET /services - List all registered services
  - GET /services/{type} - List services by type
  - GET /config - Get protocol configuration

## HTTP Services

HTTPClient wraps protocol.ClientService with registry integration.
Endpoints: POST /exchange, POST /round-broadcast.

HTTPAggregator wraps protocol.AggregatorService with registry integration.
Endpoints: POST /exchange, POST /client-messages, POST /aggregate-messages,
GET /aggregates/{round}.

HTTPServer wraps protocol.ServerService with registry integration.
Endpoints: POST /exchange, POST /aggregate, POST /partial-decryption,
GET /round-broadcast/{round}.

## Service Lifecycle

 1. Registry starts and exposes discovery endpoints
 2. Services register with signed requests and attestation
 3. Services poll registry for peer discovery
 4. During discovery, attestation is verified before adding to local registry
 5. Secret exchange uses signed requests, verified against local registry

# Message Flow

  - Client Phase: Clients discover servers and aggregators, establish shared
    secrets via signed exchange requests, XOR-blind messages with one-time pads,
    and send signed messages to aggregators.
  - Aggregation Phase: Aggregators discover servers, XOR client message vectors
    and add auction vectors in the finite field, then forward signed aggregates
    to all servers.
  - Server Phase: Each server removes its XOR blinding factors, servers exchange
    signed partial decryptions, and the leader reconstructs messages and sends
    signed broadcasts to clients.

# Security Model

All messages are signed and verified:
  - ServiceRegistrationRequest: Signed by registrant, verified by registry
  - SecretExchangeRequest: Signed by requester, verified against attested registry
  - ClientRoundMessage: Signed by client, verified by aggregator
  - AggregatedClientMessages: Signed by aggregator, verified by server and
    other aggregators in hierarchical aggregation
  - ServerPartialDecryptionMessage: Signed by server, verified by other servers
  - RoundBroadcast: Signed by server, verified by clients

Attestation verification occurs during service discovery. All protocol messages
are verified against attested keys stored in the local registry.

# Security Notes

  - Uses Ed25519 for signatures
  - ECDH P-256 for key exchange
  - XOR-based one-time pad blinding per round
  - Attestation verification during service discovery
  - All messages signed and verified against attested registry
  - Registration requests signed to prove key ownership
  - Requires ALL servers to participate for message recovery

# Performance

  - Aggregators reduce server bandwidth by O(NumClients)
  - Parallel HTTP requests for efficiency
  - Configurable round duration for throughput tuning
  - Periodic discovery polling (configurable interval)
*/
package services
