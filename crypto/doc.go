// Package crypto provides cryptographic primitives for secure anonymous communication.
//
// This package implements the core cryptographic operations required for
// anonymous broadcast protocols, including:
//
//   - Field arithmetic for finite field operations (auction data)
//   - Key encapsulation mechanisms (X25519) for shared secret derivation
//   - Digital signatures (Ed25519) for authentication
//   - XOR-based blinding vector generation for privacy-preserving message aggregation
//   - Field-based blinding for auction data aggregation
//
// The crypto package provides low-level primitives that are used by higher-level
// protocol implementations.
// Note: not all cryptographic operations are constant-time (in particular field and polynomial math)
//
// # Field Operations
//
// The package supports operations in a finite field:
//   - AuctionFieldOrder: A 384-bit field for auction-related operations
//
// # Blinding
//
// Two blinding mechanisms are provided:
//   - XOR-based blinding for message vectors (DeriveXorBlindingVector)
//   - Field arithmetic blinding for auction IBF vectors (DeriveBlindingVector)
//
// # Key Management
//
// The package provides Ed25519 for signing operations and X25519 for key exchange.
// All keys include helper methods for serialization and comparison.
package crypto
