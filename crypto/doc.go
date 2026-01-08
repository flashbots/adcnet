// Package crypto provides cryptographic primitives for secure anonymous communication.
//
// This package implements the core cryptographic operations required for
// anonymous broadcast protocols, including:
//
//   - Field arithmetic for finite field operations (auction data)
//   - Key management (Ed25519 signing, P-256 key exchange)
//   - XOR-based blinding vector generation for privacy-preserving message aggregation
//   - Field-based blinding for auction data aggregation
//
// # Field Operations
//
// The package uses a 384-bit prime field (AuctionFieldOrder) for auction-related
// operations where homomorphic addition is required.
//
// # Blinding
//
// Two blinding mechanisms are provided:
//   - XOR-based blinding for message vectors (DeriveXorBlindingVector)
//   - Field arithmetic blinding for auction IBF vectors (DeriveBlindingVector)
//
// # Security Note
//
// Not all operations are constant-time (particularly field arithmetic).
// This may leak timing information about field element values.
package crypto
