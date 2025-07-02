// Package crypto provides cryptographic primitives for secure anonymous communication.
//
// This package implements the core cryptographic operations required for
// anonymous broadcast protocols, including:
//
//   - Field arithmetic for finite field operations
//   - Polynomial interpolation for secret sharing (Shamir's Secret Sharing)
//   - Key encapsulation mechanisms (X25519) for shared secret derivation
//   - Digital signatures (Ed25519) for authentication
//   - Blinding vector generation for privacy-preserving aggregation
//
// The crypto package provides low-level primitives that are used by higher-level
// protocol implementations.
// Note: not all cryptographic operations are constant-time (in particular field and polynomial math)
//
// Field Operations
//
// The package supports operations in two finite fields:
//   - MessageFieldOrder: A 513-bit field for encoding 512-bit message chunks
//   - AuctionFieldOrder: A 384-bit field for auction-related operations
//
// Secret Sharing
//
// Polynomial-based secret sharing is implemented using Neville interpolation,
// allowing efficient reconstruction of secrets from threshold shares.
//
// Key Management
//
// The package provides Ed25519 for signing operations and X25519 for key exchange.
// All keys include helper methods for serialization and comparison.
package crypto
