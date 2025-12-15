// Package protocol implements ADCNet: an anonymous distributed communication network
// using XOR-based message blinding and auction-based message scheduling.
//
// # Protocol Overview
//
// ADCNet provides anonymous broadcast with the following key features:
//   - XOR-based blinding for message privacy requiring all servers
//   - Auction-based scheduling using Invertible Bloom Filters (IBF)
//
// # Architecture
//
// The protocol operates through three main components:
//
//  1. Clients: Blind their messages with XOR using one-time pads derived from
//     shared secrets with all servers. Auction bids use field arithmetic blinding.
//
//  2. Aggregators: Combine client messages by XORing message vectors and adding
//     auction vectors in the finite field. This reduces bandwidth to servers.
//
//  3. Servers: Each server removes its blinding factors from the aggregate.
//     Messages are recovered by XORing all server contributions.
//     Auction IBF is recovered using field subtraction.
//
// # Core Protocol Flow
//
// 1. Message Preparation (Client):
//   - Client determines if it won a slot in the previous round's auction
//   - Encodes message at the auction-determined byte offset
//   - Blinds message with XOR using one-time pads from all server shared secrets
//   - Blinds auction IBF with field addition using server-specific pads
//
// 2. Aggregation:
//   - Aggregators XOR client message vectors together
//   - Aggregators add client auction vectors in the finite field
//   - Multiple aggregation levels can reduce bandwidth hierarchically
//
// 3. Unblinding (Server):
//   - Each server derives its blinding contribution from shared secrets
//   - Server outputs its XOR blinding vector for messages
//   - Server outputs its field element blinding vector for auction
//
// 4. Reconstruction:
//   - XOR all server message blindings with aggregate to recover messages
//   - Subtract all server auction blindings from aggregate to recover IBF
//   - Decode auction IBF to determine next round's winners
//
// # Cryptographic Primitives (also see crypto package)
//
// Message Blinding:
//   - XOR-based one-time pads: blind = XOR(PRF(shared_secret_i, round)) for all servers
//   - Recovery requires all servers to contribute their blinding
//
// Auction Blinding:
//   - Field arithmetic in AuctionFieldOrder (384-bit)
//   - Each server adds its blinding, recovery subtracts all blindings
//
// # Auction Mechanism
//
// The auction system uses an Invertible Bloom Filter (IBF) to enable distributed scheduling:
//
//  1. Clients encode AuctionData (message hash, weight, size) into IBF chunks
//  2. IBF vectors are blinded and aggregated alongside message vectors
//  3. After reconstruction, the IBF is inverted to recover all auction entries
//  4. Winners are determined by solving knapsack to maximize total weight
//  5. Message placement uses the auction results to determine byte offsets
//
// # Security Properties
//   - Privacy: Requires all servers to collude to break message privacy
//   - Anonymity: Unlinkability between rounds via fresh blinding
//   - Availability: System requires all servers to participate for message recovery
package protocol
