// Package protocol implements ADCNet: an anonymous distributed communication network
// using threshold cryptography and auction-based message scheduling.
//
// # Protocol Overview
//
// ADCNet provides anonymous broadcast with the following key features:
//   - Threshold secret sharing for message privacy with liveness
//   - Auction-based scheduling using Invertible Bloom Filters (IBF)
//
// # Architecture
//
// The protocol operates through three main components:
//
//  1. Clients: Create polynomial secret shares of their messages and auction bids.
//     Each share is blinded with one-time pads derived from shared secrets with servers.
//
//  2. Aggregators: Combine client shares by adding them in the finite field.
//     This reduces bandwidth requirements for servers.
//
//  3. Servers: Collaborate to reconstruct messages using threshold decryption.
//     Each server removes its blinding factors and the leader combines partial decryptions.
//
// # Core Protocol Flow
//
// 1. Message Preparation (Client):
//    - Client determines if it won a slot in the previous round's auction
//    - Encodes message and auction data as field elements
//    - Creates polynomial shares using Shamir secret sharing (degree t-1 for t threshold)
//    - Blinds each share with server-specific one-time pads
//
// 2. Aggregation:
//    - Aggregators sum client shares in the finite field
//    - Multiple aggregation levels can reduce bandwidth hierarchically
//
// 3. Partial Decryption (Server):
//    - Each server removes its blinding factors from the aggregate
//    - Creates a partial decryption share
//
// 4. Reconstruction (Leader Server):
//    - Collects partial decryptions from at least t servers
//    - Uses polynomial interpolation to recover original messages
//    - Decodes auction IBF to determine next round's winners
//
// # Cryptographic Primitives (also see crypto package)
//
// Secret Sharing:
//   - Uses Shamir's polynomial secret sharing
//   - Message m is shared as f(0) = m where f is a random polynomial
//   - Server i receives share f(i)
//
// Blinding:
//   - One-time pads derived from shared secrets: blind = PRF(shared_secret, round, index)
//   - Separate blinding for auction and message vectors
//
// Field Arithmetic:
//   - Messages operate in MessageFieldOrder (513-bit prime)
//   - Auction data operates in AuctionFieldOrder (384-bit)
//   - All operations are modular arithmetic
//
// # Auction Mechanism
//
// The auction system uses an Invertible Bloom Filter (IBF) to enable distributed scheduling:
//
//  1. Clients encode AuctionData (message hash, weight, size) into IBF chunks
//  2. IBF vectors are secret-shared alongside message vectors
//  3. After reconstruction, the IBF is inverted to recover all auction entries
//  4. Winners are determined by solving knapsack to pack messages with tie-breaks
//  5. Message placement uses the auction results to determine byte offsets
//
// # Security Properties
//   - Privacy: Preserved as long as fewer than t servers collude
//   - Anonymity: Unlinkability between rounds via fresh blinding
//   - Availability: System operates with any t-of-n servers
//
package protocol
