# go-ZIPNet - Anonymous Broadcast Protocol

[![Goreport status](https://goreportcard.com/badge/github.com/ruteri/go-zipnet)](https://goreportcard.com/report/github.com/ruteri/go-zipnet)
[![Test status](https://github.com/ruteri/go-zipnet/workflows/Checks/badge.svg?branch=main)](https://github.com/ruteri/go-zipnet/actions?query=workflow%3A%22Checks%22)

go-ZIPNet is a Golang implementation of the "ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments" protocol. It provides an efficient, scalable, and robust anonymous broadcast channel with high trust diversity and low bandwidth requirements.

## Overview

ZIPNet allows participants to broadcast messages without revealing who sent which message. It improves upon existing anonymous broadcast protocols by significantly reducing server computational overhead and bandwidth requirements, making it practical to deploy with many untrusted servers for better anonymity guarantees.

## Architecture

ZIPNet consists of three main components:

### 1. Clients

Clients operate inside Trusted Execution Environments (TEEs) and prepare encrypted messages. The TEE is used for DoS prevention but not for privacy, making TEE failures a liveness issue rather than a privacy concern. Non-talking clients send all-zero messages as cover traffic.

### 2. Aggregators

Aggregators form a tree-like structure to combine client messages, significantly reducing the bandwidth requirements for anytrust servers. Aggregators are completely untrusted for privacy.

### 3. Anytrust Servers

Servers operate in an anytrust model where privacy is guaranteed as long as at least one server is honest. Servers unblind the aggregated messages and combine partial decryptions to produce the final broadcast.

## Key Features

- **Hierarchical Message Aggregation**: Uses untrusted aggregators to combine client messages, reducing bandwidth requirements
- **Falsifiable TEE Trust**: Uses TEEs for DoS prevention but not privacy
- **Efficient Cover Traffic**: Makes non-talking participants extremely cheap, encouraging large anonymity sets
- **Scalable Trust Model**: Supports hundreds of anytrust servers with minimal performance penalty
- **Forward Secrecy**: Uses key ratcheting to ensure past communications remain secure
- **Footprint Scheduling**: Efficient slot reservation mechanism for message transmission

## Implementation Details

This Go implementation provides:

- Strong typing for cryptographic primitives (Hash, Signature, PublicKey, etc.)
- Clean interfaces for Clients, Aggregators, and Servers
- Abstractions for TEEs, cryptographic operations, and network transport
- Footprint scheduling for efficient slot reservation

## Getting Started

### Prerequisites

- Go 1.18 or higher
- For client functionality: Access to a TEE (SGX, TrustZone, etc.)

### Installation

```bash
go get github.com/ruteri/go-zipnet
```

### Example Usage

#### Configuration

```go
config := &zipnet.ZIPNetConfig{
    RoundDuration:   5 * time.Second,
    MessageSlots:    1024,
    MessageSize:     160,
    SchedulingSlots: 4096,
    FootprintBits:   64,
    MinClients:      100,
    AnytrustServers: []string{"server1.example.com", "server2.example.com"},
    Aggregators:     []string{"agg1.example.com"},
    RoundsPerWindow: 100,
}
```

#### Running a Client

```go
// Initialize dependencies
tee := NewIntelSGXTEE()
crypto := zipnet.NewStandardCryptoProvider()
network := NewHTTPNetworkTransport()
scheduler := NewDefaultScheduler()

// Create a client
client, err := client.NewClient(config, tee, crypto, network, scheduler)
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}

// Register server public keys
for id, pubKey := range serverPublicKeys {
    err := client.RegisterServerPublicKey(id, pubKey)
    if err != nil {
        log.Fatalf("Failed to register server %s: %v", id, err)
    }
}

// Send a message
message := []byte("Hello, anonymous world!")
msg, err := client.SubmitMessage(ctx, currentRound, message, true, publishedSchedule)
if err != nil {
    log.Fatalf("Failed to submit message: %v", err)
}
```

#### Running an Aggregator

```go
// Initialize dependencies
crypto := zipnet.NewStandardCryptoProvider()
network := NewHTTPNetworkTransport()

// Create an aggregator
aggregator, err := aggregator.NewAggregator(config, privateKey, publicKey,
    crypto, network, registeredUsers, 0)
if err != nil {
    log.Fatalf("Failed to create aggregator: %v", err)
}

// Start processing for a new round
if err := aggregator.Reset(currentRound); err != nil {
    log.Fatalf("Failed to reset aggregator: %v", err)
}

// Receive a client message
if err := aggregator.ReceiveClientMessage(ctx, clientMessage, clientPublicKey); err != nil {
    log.Printf("Failed to process client message: %v", err)
}

// Create aggregate and forward to servers
aggregate, err := aggregator.AggregateMessages(ctx, currentRound)
if err != nil {
    log.Fatalf("Failed to create aggregate: %v", err)
}
```

#### Running a Server

```go
// Initialize dependencies
crypto := zipnet.NewStandardCryptoProvider()
network := NewHTTPNetworkTransport()

// Create a server
server, err := server.NewServer(config, crypto, network, isLeader)
if err != nil {
    log.Fatalf("Failed to create server: %v", err)
}

// Register a client
if err := server.RegisterClient(ctx, clientPublicKey, attestation); err != nil {
    log.Printf("Failed to register client: %v", err)
}

// Process an aggregate from an aggregator
serverMessage, err := server.ProcessAggregate(ctx, aggregateMessage)
if err != nil {
    log.Fatalf("Failed to process aggregate: %v", err)
}
```

## Security Considerations

- ZIPNet provides anonymity as long as at least one anytrust server is honest
- TEE security is required only for DoS prevention, not privacy
- All client messages must be processed or none; selective dropping breaks anonymity
- The protocol operates in rounds with synchrony assumptions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

ZIPNet is based on the research paper:

Rosenberg, M., Shih, M., Zhao, Z., Wang, R., Miers, I., & Zhang, F. (2023). ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments.
