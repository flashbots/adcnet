# ADCNet - Anonymous Distributed Communication Network

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/adcnet)](https://goreportcard.com/report/github.com/flashbots/adcnet)
[![Test status](https://github.com/flashbots/adcnet/workflows/Checks/badge.svg?branch=main)](https://github.com/flashbots/adcnet/actions?query=workflow%3A%22Checks%22)

ADCNet is a Go implementation of an anonymous distributed communication network using XOR-based message blinding and auction-based message scheduling. It provides anonymous broadcast requiring all servers to participate in message recovery.

## Overview

ADCNet enables participants to broadcast messages anonymously. Message content and sender identity remain hidden as long as not all servers collude. The protocol uses an Invertible Bloom Filter (IBF) based auction system for fair and efficient message scheduling.

## Architecture

ADCNet consists of three main components operating in a round-based protocol:

### 1. Clients

Clients prepare messages for anonymous broadcast by:
- XOR-blinding messages with one-time pads derived from shared secrets with all servers
- Participating in auctions for message slots by encoding bids into IBF chunks
- Encoding messages at auction-determined offsets if they won slots in previous rounds

### 2. Aggregators

Aggregators reduce bandwidth requirements by:
- Collecting and verifying client message signatures
- XORing client message vectors together
- Adding client auction vectors in the finite field
- Supporting hierarchical aggregation to further reduce server load

### 3. Servers

Servers collaborate to reconstruct messages:
- Each server removes its XOR blinding factors from aggregated messages
- All servers must contribute their blinding vectors
- Combined unblinding recovers the original message vector
- The reconstructed IBF is inverted to determine next round's message scheduling

## Key Features

- **XOR-Based Blinding**: Messages blinded with one-time pads from all server shared secrets
- **All-Server Participation**: Message recovery requires all servers to contribute
- **Finite Field Arithmetic**: 384-bit field for auction IBF operations
- **IBF-based Scheduling**: Distributed auction mechanism using Invertible Bloom Filters
- **Dynamic Message Sizing**: Variable-length messages allocated through auction weights
- **Anonymity Guarantees**: Unlinkability between rounds through fresh blinding
- **TEE Attestation**: Optional TDX attestation for service verification

## Protocol Flow

1. **Message Preparation** (Client):
   - Check if won slot in previous auction by comparing message hash
   - Encode message at appropriate offset if auction was won
   - XOR-blind message with one-time pads from all server shared secrets
   - Field-blind auction IBF with server-specific pads

2. **Aggregation**:
   - Aggregators XOR message vectors from multiple clients
   - Aggregators add auction vectors in the finite field
   - Support multi-level aggregation for bandwidth optimization

3. **Unblinding** (Server):
   - Each server computes its XOR blinding contribution from shared secrets
   - Creates partial decryption for message reconstruction

4. **Message Reconstruction**:
   - XOR all server blinding vectors with aggregate to recover messages
   - Subtract all server auction blindings to recover IBF
   - Decode auction IBF to determine next round's winners

## Package Structure

### `protocol`
Main protocol implementation including:
- `ClientMessager`: XOR blinding and message preparation
- `ServerMessager`: Unblinding and message reconstruction
- `AggregatorMessager`: Message aggregation operations

### `blind_auction`
Distributed auction mechanism featuring:
- `IBFVector`: Multi-level Invertible Bloom Filter implementation
- `AuctionEngine`: Knapsack-based slot allocation

### `crypto`
Cryptographic primitives providing:
- Field arithmetic in finite fields
- Key management (Ed25519 signing, P-256 key exchange)
- XOR and field-element blinding vector derivation

### `services`
HTTP service implementations with:
- Central registry for service discovery
- TEE attestation verification
- Signed message authentication
- Admin-authenticated registration for servers/aggregators

### `cmd`
Standalone CLI commands:
- `cmd/registry`: Central registry service
- `cmd/server`: ADCNet server
- `cmd/aggregator`: Message aggregator
- `cmd/client`: ADCNet client
- `cmd/common`: Shared CLI utilities

## Getting Started

### Installation

```bash
go get github.com/flashbots/adcnet
```

### Running the Demo

The demo orchestrator runs a complete local deployment with automatic service registration:

```bash
go run ./services/demo \
  --clients=10 \
  --aggregators=2 \
  --servers=5 \
  --round=10s \
  --msg-length=512000 \
  --admin-token="admin:secret"
```

### Running Standalone Services

For production deployments, run services independently:

#### 1. Start the Registry

```bash
go run ./cmd/registry \
  --addr=:8080 \
  --admin-token="admin:secret" \
  --measurements-url="https://example.com/measurements.json" \
  --round=10s \
  --msg-length=512000
```

#### 2. Start Servers

Servers must be registered by an admin before they can participate:

```bash
# Start the server (it will wait for admin registration)
go run ./cmd/server \
  --addr=:8081 \
  --registry=http://localhost:8080 \
  --leader
```

#### 3. Start Aggregators

Aggregators must also be registered by an admin:

```bash
go run ./cmd/aggregator \
  --addr=:8082 \
  --registry=http://localhost:8080
```

#### 4. Start Clients

Clients self-register via the public endpoint:

```bash
go run ./cmd/client \
  --addr=:8083 \
  --registry=http://localhost:8080
```

### Service Registration

The registry provides two registration paths:

| Endpoint | Auth Required | Service Types |
|----------|---------------|---------------|
| `POST /register/client` | No | Clients only |
| `POST /admin/register/{type}` | Yes (Basic Auth) | Servers, Aggregators |

When `--admin-token` is configured, servers and aggregators must be registered through the admin endpoint with basic authentication.

### TDX Attestation

Enable TDX attestation for production deployments:

```bash
# Local TDX device
go run ./cmd/server --tdx --registry=http://localhost:8080

# Remote TDX attestation service
go run ./cmd/server \
  --tdx \
  --tdx-url=http://attestation-service:8080 \
  --registry=http://localhost:8080
```

### Measurements Configuration

Measurements define acceptable TEE configurations:

```bash
# Remote measurements (production)
--measurements-url="https://example.com/measurements.json"

# Demo mode uses static measurements compatible with dummy attestation
# (no flag needed - this is the default in demo)
```

### Basic Usage

```go
import (
    "github.com/flashbots/adcnet/protocol"
)

config := &protocol.ADCNetConfig{
    AuctionSlots:    100,
    MessageLength:   1000,
    MinClients:      3,
    RoundDuration:   10 * time.Second,
}

client := protocol.NewClientService(config, signingKey, exchangeKey)
// Register with servers to establish shared secrets
client.RegisterServer(serverID, serverExchangePubkey)
// Schedule message for next round
client.ScheduleMessageForNextRound([]byte("hello"), 10)
```

## Security Properties

- **Privacy**: Message content hidden unless all servers collude
- **Anonymity**: Sender identity protected through XOR blinding with all servers
- **Unlinkability**: Fresh blinding prevents correlation between rounds
- **Availability**: System requires all servers to participate
- **Integrity**: Digital signatures authenticate all protocol messages
- **Attestation**: Optional TEE verification for service identity

## Implementation Details

- **Field Order**: 384-bit prime field (48-byte IBF chunks)
- **Message Blinding**: XOR with PRF-derived one-time pads unique per server/round
- **Auction Blinding**: Field addition with server-specific blinding vectors
- **IBF Structure**: 4-level filter with 0.75 shrink factor between levels
- **Signatures**: Ed25519 for all protocol messages
- **Key Exchange**: ECDH P-256 for shared secret derivation

## Testing

```bash
go test ./...
```

Performance benchmarks:

```bash
go test -bench=. ./protocol
```

## Security Considerations

- Servers must have pre-established shared secrets with all authorized clients
- All authorized clients should participate (real or dummy messages) for anonymity
- Message padding required to prevent traffic analysis
- Synchronous rounds assumed
- Not all cryptographic operations are constant-time (field arithmetic)
- **All servers must be online** for message recovery
- Admin credentials should be securely managed in production

## License

MIT License - see the LICENSE file for details.
