# ADCNet - Anonymous Broadcast Protocol

[![Goreport status](https://goreportcard.com/badge/github.com/ruteri/auction-based-dcnet)](https://goreportcard.com/report/github.com/ruteri/auction-based-dcnet)
[![Test status](https://github.com/ruteri/auction-based-dcnet/workflows/Checks/badge.svg?branch=main)](https://github.com/ruteri/auction-based-dcnet/actions?query=workflow%3A%22Checks%22)

Auction-based DCNet is a Golang implementation of the "ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments" protocol. It provides an efficient, scalable, and robust anonymous broadcast channel with high trust diversity and low bandwidth requirements.

## Overview

ADCNet allows participants to broadcast messages without revealing who sent which message. It improves upon existing anonymous broadcast protocols by significantly reducing server computational overhead and bandwidth requirements, making it practical to deploy with many untrusted servers for better anonymity guarantees.

## Architecture

ADCNet consists of three main components:

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
- **Auction-based Scheduling**: Uses an Invertible Bloom Filter (IBF) for efficient and fair slot allocation
- **Dynamic Message Sizing**: Supports variable-length messages allocated through the auction mechanism

## Protocol Innovations

### Invertible Bloom Filter (IBF) for Message Scheduling

ADCNet uses an Invertible Bloom Filter to enable an auction-based scheduling mechanism. Instead of randomly selecting slots with static sizes (as in the original footprint scheduling), clients bid for message space by submitting weights in an auction:

1. Clients compute a hash of their message and include it with a weight in an AuctionData structure
2. These auction entries are inserted into an IBF with multiple levels and buckets
3. The IBF is encrypted using one-time pads derived from shared secrets with servers
4. After server decryption and aggregation, the IBF is "peeled" to recover all auction entries
5. Message slots are allocated based on auction weights, with higher weights receiving priority

### Dynamic Message Allocation

Unlike the original fixed-size message slots, ADCNet now supports dynamic message sizing:

1. Clients participate in the auction process to bid for message space
2. The protocol compares message weights to determine slot allocation
3. A knapsack-style optimization allocates message space based on auction results
4. This approach provides more efficient bandwidth utilization for variable-sized messages

## Implementation Details

This Go implementation provides:

- Strong typing for cryptographic primitives (Hash, Signature, PublicKey, etc.)
- Clean interfaces for Clients, Aggregators, and Servers
- Abstractions for TEEs, cryptographic operations, and network transport
- IBF-based auction mechanism for efficient slot reservation
- Support for dynamic message sizes

## Getting Started

### Prerequisites

- Go 1.18 or higher
- For client functionality: Access to a TEE (SGX, TrustZone, etc.)

### Installation

```bash
go get github.com/ruteri/auction-based-dcnet
```

## Security Considerations

- ADC provides anonymity as long as at least one anytrust server is honest
- TEE security is required only for DoS prevention and faithful auction outcomes, not privacy
- All client messages must be processed or none; selective dropping breaks anonymity
- The protocol operates in rounds with synchrony assumptions
- The IBF-based auction mechanism ensures fair slot allocation while maintaining anonymity

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

ADC is based on the research paper:

Rosenberg, M., Shih, M., Zhao, Z., Wang, R., Miers, I., & Zhang, F. (2023). ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments.
