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

## Security Properties

- **Privacy**: Message content hidden unless all servers collude
- **Anonymity**: Sender identity protected through XOR blinding with all servers
- **Unlinkability**: Fresh blinding prevents correlation between rounds
- **Availability**: System requires all servers to participate
- **Integrity**: Digital signatures authenticate all protocol messages

## Implementation Details

- **Field Order**: 384-bit prime field (48-byte IBF chunks)
- **Message Blinding**: XOR with PRF-derived one-time pads unique per server/round
- **Auction Blinding**: Field addition with server-specific blinding vectors
- **IBF Structure**: 4-level filter with 0.75 shrink factor between levels

## Getting Started

### Installation

```bash
go get github.com/flashbots/adcnet
```

### Running the Demo

```bash
go run ./services/demo \
  --clients=10 \
  --aggregators=2 \
  --servers=5 \
  --round=10s \
  --msg-length=512000
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

## License

MIT License - see the LICENSE file for details.
