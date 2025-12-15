/*
Package services provides HTTP-based implementations of ADCNet protocol
components for real-world deployment.

# Overview

This package wraps the core protocol implementations with HTTP APIs, enabling:
  - RESTful communication between components
  - Easy deployment and testing
  - Monitoring and observability
  - Flexible network topologies

# Components

## HTTP Services

HTTPClient wraps protocol.ClientService for message scheduling and auction
participation. Endpoints: POST /register, POST /round-broadcast.

HTTPAggregator wraps protocol.AggregatorService for combining client messages
to reduce server bandwidth. Endpoints: POST /register, POST /client-messages,
POST /aggregate-messages, GET /aggregates/{round}.

HTTPServer wraps protocol.ServerService for XOR unblinding with other servers.
Endpoints: POST /register, POST /aggregate, POST /partial-decryption,
GET /round-broadcast/{round}.

## Orchestrator

The Orchestrator manages deployment lifecycle including service creation,
registration, and round progression.

# Message Flow

  - Client Phase: Clients XOR-blind messages with one-time pads from all server
    shared secrets and send to aggregators.
  - Aggregation Phase: Aggregators XOR client message vectors and add auction
    vectors in the finite field, then forward to all servers.
  - Server Phase: Each server removes its XOR blinding factors, servers exchange
    partial decryptions, and the leader reconstructs messages by combining all
    server contributions.

# Security Notes

  - Uses Ed25519 for signatures
  - ECDH P-256 for key exchange
  - XOR-based one-time pad blinding per round
  - Requires ALL servers to participate for message recovery

# Performance

  - Aggregators reduce server bandwidth by O(NumClients)
  - Parallel HTTP requests for efficiency
  - Configurable round duration for throughput tuning
*/
package services
