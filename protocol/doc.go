// Package protocol implements an auction-based anonymous broadcast channel, loosely 
// based on the paper "ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted
// Execution Environments" with extensions for auction-based message scheduling
// and dynamic message sizing.
//
// # ABABC Architecture and Workflow
//
// ABABC operates through a three-tier architecture:
//
//  1. Clients: Run inside Trusted Execution Environments (TEEs) and prepare
//     encrypted messages. The TEE is used only for DoS prevention, not for
//     privacy guarantees. Clients participate in an auction-based system to
//     secure message slots.
//
//  2. Aggregators: Form a tree-like structure to combine client messages by
//     XORing them together. This significantly reduces bandwidth requirements for
//     anytrust servers. Aggregators are completely untrusted for privacy.
//
//  3. Anytrust Servers: Operate in an "anytrust" model where privacy is guaranteed
//     as long as at least one server is honest. Servers unblind the aggregated
//     messages using shared secrets with clients and combine partial decryptions
//     to produce the final broadcast.
//
// # Core Protocol Operations (protocols.go)
//
// The protocols.go file implements the core message processing operations in ABABC:
//
// ## Server Operations
//
// ServerMessager handles server-side operations for unblinding and decryption:
//
// - UnblindAggregates: Processes aggregated messages from aggregators by applying
//   server-specific decryption to create a partial decryption message. The server
//   derives one-time pads from shared secrets with each client and uses them to
//   partially decrypt the aggregated message.
//
// - UnblindPartialMessages: Combines partial decryption messages from all anytrust
//   servers to produce the final broadcast message. This is typically called by the
//   leader server after collecting shares from all anytrust servers.
//
// ## Client Operations
//
// ClientMessager handles client-side message preparation:
//
// - PrepareMessage: Creates encrypted client messages with auction data for
//   scheduling. It determines whether the client should send a message based on
//   previous round auction results, and prepares the message with proper blinding
//   using one-time pads derived from shared secrets with servers.
//
// ## Aggregation Operations
//
// - AggregateClientMessages: Combines multiple client messages into a single
//   aggregated message by XORing message vectors and merging IBF vectors.
//   It verifies client signatures and authorization before aggregation.
//
// - AggregateAggregates: Combines aggregated messages from lower-level aggregators
//   into a single aggregated message. This is used in the tree-based aggregator
//   hierarchy to reduce bandwidth requirements.
//
// # Auction-Based Scheduling with IBF
//
// The protocol uses an Invertible Bloom Filter (IBF) for message scheduling,
// which replaces the original footprint scheduling mechanism:
//
// 1. Clients create AuctionData containing a hash of their message and a weight
//    (priority) value.
//
// 2. The AuctionData is encoded into a fixed-size chunk and inserted into an IBF,
//    which is a probabilistic data structure with multiple levels and buckets.
//
// 3. The IBF is encrypted with one-time pads derived from shared secrets with
//    anytrust servers, ensuring privacy.
//
// 4. Servers unblind the IBF vectors by XORing with their portions of the one-time
//    pads.
//
// 5. The leader server combines unblinded shares and recovers all auction entries
//    from the IBF.
//
// 6. Message slots are allocated based on auction weights, with higher-weight
//    messages receiving priority.
//
// # Dynamic Message Sizing
//
// Unlike the original fixed-size message slots, ABABC supports dynamic
// message sizing through the auction mechanism:
//
// - Clients determine if they won the auction by comparing their weight to other
//   clients' weights in the previous round.
//
// - The message is placed in the appropriate slot if the client won the auction.
//
// - The system effectively implements a knapsack-style optimization for allocating
//   variable-sized messages into the broadcast vector.
//
// # Message Flow
//
// 1. Client prepares a message with auction data for the current round
// 2. Message is sent to a leaf aggregator
// 3. Aggregators combine messages and forward up the tree
// 4. Root aggregator sends the combined message to all anytrust servers
// 5. Each server creates a partial decryption by unblinding with their keys
// 6. The leader server combines all partial decryptions to get the final output
// 7. The final output, including recovered auction data, is broadcast to all clients
// 8. Clients use the auction results to determine if they can send in the next round
//
// # Security Considerations
//
// - ZIPNet provides anonymity as long as at least one anytrust server is honest
// - TEE security is required only for DoS prevention, not privacy
// - The IBF-based auction mechanism ensures fair slot allocation while maintaining anonymity
// - Forward secrecy is provided by key ratcheting after each round
// - Authentication and authorization checks verify that only legitimate participants
//   can contribute to the protocol
package protocol
