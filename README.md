# ADCNet - Anonymous Distributed Communication Network

[![Goreport status](https://goreportcard.com/badge/github.com/flashbots/adcnet)](https://goreportcard.com/report/github.com/flashbots/adcnet)
[![Test status](https://github.com/flashbots/adcnet/workflows/Checks/badge.svg?branch=main)](https://github.com/flashbots/adcnet/actions?query=workflow%3A%22Checks%22)

ADCNet is a Go implementation of an anonymous distributed communication network using threshold cryptography and auction-based message scheduling. It provides anonymous broadcast with cryptographic privacy guarantees and efficient bandwidth allocation through a distributed auction mechanism.

## Overview

ADCNet enables participants to broadcast messages anonymously using threshold secret sharing. The protocol ensures that message content and sender identity remain hidden as long as fewer than a threshold number of servers collude. It uses an Invertible Bloom Filter (IBF) based auction system for fair and efficient message scheduling.

## Architecture

ADCNet consists of three main components operating in a round-based protocol:

### 1. Clients

Clients prepare messages for anonymous broadcast by:
- Creating polynomial secret shares of their messages using Shamir's Secret Sharing
- Blinding each share with server-specific one-time pads derived from shared secrets
- Participating in auctions for message slots by encoding bids into IBF chunks
- Encoding messages at auction-determined offsets if they won slots in previous rounds

### 2. Aggregators

Aggregators reduce bandwidth requirements by:
- Collecting and verifying client message signatures
- Combining client shares through field addition in finite fields
- Supporting hierarchical aggregation to further reduce server load
- Operating without any trust requirements for privacy

### 3. Servers

Servers collaborate to reconstruct messages through threshold decryption:
- Each server removes its blinding factors from aggregated messages
- Servers create partial decryptions by subtracting their one-time pads
- A leader server combines partial decryptions using polynomial interpolation
- The reconstructed IBF is inverted to determine next round's message scheduling

## Key Features

- **Threshold Secret Sharing**: Uses polynomial-based secret sharing with configurable threshold `t`
- **Finite Field Arithmetic**: Operates in two fields - 513-bit for messages, 384-bit for auctions
- **IBF-based Scheduling**: Distributed auction mechanism using Invertible Bloom Filters
- **One-time Pad Blinding**: Server-specific blinding using PRF-derived vectors
- **Dynamic Message Sizing**: Variable-length messages allocated through auction weights
- **Anonymity Guarantees**: Unlinkability between rounds through fresh blinding

## Protocol Flow

1. **Message Preparation** (Client):
   - Check if won slot in previous auction by comparing message hash
   - Encode message at appropriate offset if auction was won
   - Create polynomial shares where f(0) = message, degree = t-1
   - Blind shares with server-specific one-time pads

2. **Aggregation**:
   - Aggregators sum shares from multiple clients in finite field
   - Verify signatures and enforce authorization policies
   - Support multi-level aggregation for bandwidth optimization

3. **Partial Decryption** (Server):
   - Each server subtracts its blinding factors from aggregate
   - Derives blinding using PRF with shared secrets and round number
   - Creates partial decryption share for polynomial reconstruction

4. **Message Reconstruction** (Leader):
   - Collects partial decryptions from at least t servers
   - Uses Neville interpolation to evaluate polynomial at x=0
   - Recovers auction IBF to determine next round's winners
   - Outputs reconstructed message vector and auction results

## Package Structure

### `protocol`
Main protocol implementation including:
- `ClientMessager`: Secret sharing and message preparation
- `ServerMessager`: Partial decryption and message reconstruction
- `AggregatorMessager`: Message aggregation operations
- Message encoding and polynomial operations

### `blind_auction`
Distributed auction mechanism featuring:
- `IBFVector`: Multi-level Invertible Bloom Filter implementation
- `AuctionEngine`: Knapsack-based slot allocation
- Auction data encoding and recovery algorithms

### `crypto`
Cryptographic primitives providing:
- Field arithmetic in finite fields
- Polynomial interpolation (Neville's algorithm)
- Key management (Ed25519 signing, X25519 key exchange)
- Blinding vector derivation
- PRF-based random generation

## Security Properties

- **Privacy**: Message content hidden as long as fewer than `t` servers collude
- **Anonymity**: Sender identity protected through polynomial secret sharing
- **Unlinkability**: Fresh blinding prevents correlation between rounds
- **Availability**: System operates with any `t` out of `n` servers
- **Integrity**: Digital signatures authenticate all protocol messages

## Implementation Details

- **Field Orders**: 
  - Messages: 513-bit prime field (encodes 512-bit chunks)
  - Auctions: 384-bit field (48-byte IBF chunks)
- **Polynomial Degree**: t-1 where t is the threshold
- **Blinding**: PRF-based one-time pads unique per server/round/index
- **IBF Structure**: 4-level filter with 0.75 shrink factor between levels

## Getting Started

### Installation

```bash
go get github.com/flashbots/adcnet
```

### Basic Usage

```go
import (
    "github.com/flashbots/adcnet/protocol"
    "github.com/flashbots/adcnet/crypto"
)

// Configure protocol parameters
config := &protocol.ADCNetConfig{
    AuctionSlots:      100,
    MessageSize:       1000,  // Size in field elements
    MinServers:        3,     // Threshold t
    MessageFieldOrder: crypto.MessageFieldOrder,
}

// Initialize components
client := &protocol.ClientMessager{
    Config:        config,
    SharedSecrets: sharedSecrets, // Pre-established with servers
}

// Prepare and send messages
messages, shouldSend, err := client.PrepareMessage(
    roundNumber,
    previousRoundOutput,
    messageData,
    auctionBid,
)
```

## Testing

Run the test suite:

```bash
go test ./...
```

Performance benchmarks:

```bash
go test -bench=. ./protocol
```

## Security Considerations

- Servers must have pre-established shared secrets with all authorized clients
- A large share of authorized clients must participate (send real or dummy messages) for anonymity
- Message padding and salting required to prevent traffic analysis
- Synchronous rounds assumed - asynchrony breaks anonymity guarantees
- Not all cryptographic operations are constant-time (field arithmetic, polynomial math)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

This implementation is inspired by research in anonymous communication systems and threshold cryptography. The auction-based scheduling mechanism using IBFs provides an efficient solution for dynamic bandwidth allocation in anonymous broadcast protocols.

Loosely based on:
Rosenberg, M., Shih, M., Zhao, Z., Wang, R., Miers, I., & Zhang, F. (2023). ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments.
