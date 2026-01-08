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
//   - Encodes message at the auction-determined byte offset if so
//   - Blinds message with XOR using one-time pads from all server shared secrets
//   - Blinds auction IBF with field addition using server-specific pads
//
// 2. Aggregation:
//   - Aggregators XOR client message vectors together
//   - Aggregators add blinded client auction vectors
//   - Multiple aggregation levels can reduce bandwidth hierarchically
//
// 3. Unblinding (Server):
//   - Each server derives its blinding contribution from shared secrets
//   - Server sends XOR of all its XOR blinding vectors for messages
//     and its field element blinding vector for auction
//     and forwards to leader
//
// 4. Reconstruction:
//   - XOR all server message blindings with aggregate to recover messages
//   - Subtract all server auction blindings from aggregate to recover IBF
//   - Decode auction IBF to determine next round's winners
//
// # Security Properties
//
//   - Anonymity: Sender identity protected if at least one server is honest
//   - Privacy: Message content hidden unless all servers collude
//   - Unlinkability: Fresh blinding prevents correlation between rounds
package protocol
