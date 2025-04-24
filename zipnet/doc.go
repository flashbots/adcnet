// Package zipnet implements the ZIPNet anonymous broadcast protocol as described
// in the paper "ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted
// Execution Environments".
//
// # ZIPNet Architecture and Workflow
//
// ZIPNet operates through a three-tier architecture:
//
//  1. Clients: Run inside Trusted Execution Environments (TEEs) and prepare encrypted
//     messages. The TEE is used only for DoS prevention, not for privacy guarantees.
//     Clients who want to talk reserve slots using a footprint scheduling mechanism.
//     Non-talking clients send cover traffic (all-zero messages) to enhance anonymity.
//
//  2. Aggregators: Form a tree-like structure to combine client messages by XORing
//     them together. This significantly reduces bandwidth requirements for anytrust
//     servers. Aggregators are completely untrusted for privacy.
//
//  3. Anytrust Servers: Operate in an "anytrust" model where privacy is guaranteed
//     as long as at least one server is honest. Servers unblind the aggregated messages
//     using shared secrets with clients and combine partial decryptions to produce
//     the final broadcast.
//
// Protocol Flow:
//
// - Clients establish shared secrets with all anytrust servers during setup
// - In each round, clients either talk, reserve a slot, or send cover traffic
// - Aggregators collect and combine messages from clients or lower-level aggregators
// - Anytrust servers unblind the aggregated message and produce the final broadcast
// - Keys are ratcheted forward after each round for forward secrecy
//
// ZIPNet's key innovations include:
// - Hierarchical message aggregation to reduce bandwidth requirements
// - Using TEEs for DoS prevention but not privacy (falsifiable TEE trust)
// - Efficient cover traffic support to enhance anonymity
// - Support for hundreds of anytrust servers with minimal overhead
//
// To use ZIPNet, you'll need to set up clients, aggregators, and servers according
// to the interfaces defined in this package.
package zipnet
