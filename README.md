# ADCNet - Anonymous Distributed Communication Network

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/adcnet)](https://goreportcard.com/report/github.com/flashbots/adcnet)
[![Test status](https://github.com/flashbots/adcnet/workflows/Checks/badge.svg?branch=main)](https://github.com/flashbots/adcnet/actions?query=workflow%3A%22Checks%22)

ADCNet is a Go implementation of an anonymous distributed communication network using XOR-based message blinding and auction-based message scheduling. It provides anonymous broadcast requiring all servers to participate in message recovery.

## Overview

ADCNet enables participants to broadcast messages anonymously. Message sender identity remains hidden as long as one server is honest. The protocol uses an Invertible Bloom Filter (IBF) based auction system for fair and efficient message scheduling.

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
- **Anytrust Server Group**: Anonymity preserved as long as a single server is honest
- **Finite Field Arithmetic**: 384-bit field for auction IBF operations
- **IBF-based Scheduling**: Distributed auction mechanism using Invertible Bloom Filters
- **Dynamic Message Sizing**: Variable-length messages allocated through auction weights
- **TEE Attestation**: Optional TDX attestation for service verification

## Getting Started

### Installation

```bash
go get github.com/flashbots/adcnet
```

### Configuration

Services can be configured via YAML files or command-line flags. Config files allow storing credentials securely and simplify deployment.

**Example server configuration (`server.yaml`):**

```yaml
http_addr: ":8081"
registry_url: "http://localhost:8080"
admin_token: "admin:secret"

keys:
  signing_key: ""     # Hex-encoded, generates if empty
  exchange_key: ""    # Hex-encoded, generates if empty

attestation:
  use_tdx: false
  measurements_url: ""

server:
  is_leader: true
```

**Example registry configuration (`registry.yaml`):**

```yaml
http_addr: ":8080"
admin_token: "admin:secret"

attestation:
  use_tdx: false
  measurements_url: ""

protocol:
  round_duration: 10s
  message_length: 512000
  auction_slots: 10
  min_clients: 1
```

### Running the Demo

The demo orchestrator runs a complete local deployment:

```bash
go run ./services/demo \
  --clients=10 \
  --aggregators=2 \
  --servers=5 \
  --round=10s \
  --msg-length=512000 \
  --admin-token="admin:secret"
```

## Running Standalone Services

For production deployments, run services independently using the unified service command.

### 1. Start the Registry

```bash
go run ./cmd/registry \
  --addr=:8080 \
  --admin-token="admin:secret" \
  --measurements-url="https://example.com/measurements.json" \
  --round=10s \
  --msg-length=512000
```

### 2. Start Servers

```bash
# Leader server
go run ./cmd/service \
  --service-type=server \
  --addr=:8081 \
  --registry=http://localhost:8080 \
  --admin-token="admin:secret" \
  --leader

# Additional servers
go run ./cmd/service \
  --service-type=server \
  --addr=:8082 \
  --registry=http://localhost:8080 \
  --admin-token="admin:secret"
```

### 3. Start Aggregators

```bash
go run ./cmd/service \
  --service-type=aggregator \
  --addr=:8083 \
  --registry=http://localhost:8080 \
  --admin-token="admin:secret"
```

### 4. Start Clients

```bash
go run ./cmd/service \
  --service-type=client \
  --addr=:8084 \
  --registry=http://localhost:8080
```

### Using Configuration Files

Create a YAML config for each service:

```yaml
# server.yaml
service_type: "server"
http_addr: ":8081"
registry_url: "http://localhost:8080"
admin_token: "admin:secret"
keys:
  signing_key: ""     # Generated if empty
  exchange_key: ""    # Generated if empty
attestation:
  use_tdx: true
  measurements_url: "https://example.com/measurements.json"
server:
  is_leader: true
```

```bash
go run ./cmd/service --config=server.yaml
```

### TEE Deployment

The unified service command enables building a single binary for TEE VM images:

```bash
# Build single binary
go build -o adcnet-service ./cmd/service

# Run with different configurations
./adcnet-service --config=/etc/adcnet/server.yaml
./adcnet-service --config=/etc/adcnet/client.yaml
```

Enable TDX attestation:

```bash
go run ./cmd/service \
  --service-type=server \
  --tdx \
  --tdx-url=http://attestation-service:8080 \
  --registry=http://localhost:8080
```


### Service Registration

All services self-register on startup:

| Service Type | Endpoint | Auth Required |
|--------------|----------|---------------|
| Client | `POST /register/client` | No |
| Server | `POST /admin/register/server` | Yes (Basic Auth) |
| Aggregator | `POST /admin/register/aggregator` | Yes (Basic Auth) |

Servers and aggregators include `admin_token` in their config for authentication.

### TDX Attestation

Enable TDX attestation for production deployments:

```yaml
# In config file:
attestation:
  use_tdx: true
  tdx_remote_url: "http://attestation-service:8080"  # Optional
  measurements_url: "https://example.com/measurements.json"
```

Or via flags:
```bash
go run ./cmd/server \
  --tdx \
  --tdx-url=http://attestation-service:8080 \
  --measurements-url=https://example.com/measurements.json \
  --registry=http://localhost:8080
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
client.RegisterServer(serverID, serverExchangePubkey)
client.ScheduleMessageForNextRound([]byte("hello"), 10)
```

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

### `cmd`
Standalone CLI commands:
- `cmd/registry`: Central registry service
- `cmd/server`: ADCNet server
- `cmd/aggregator`: Message aggregator
- `cmd/client`: ADCNet client

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
