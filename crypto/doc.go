// Package crypto provides cryptographic primitives used by the ZIPNet protocol.
//
// This package implements the core cryptographic operations required for the
// ZIPNet anonymous broadcast protocol, including:
//
// - Secure hashing (SHA-256)
// - Public-key cryptography (Ed25519)
// - Digital signatures and verification
// - Shared secret derivation
// - Key ratcheting for forward secrecy
// - Nonces for rate limiting
// - Footprints for slot reservation
//
// The crypto types in this package are designed to be used together with the
// ZIPNet protocol components (clients, aggregators, and servers) to provide
// anonymous communication with strong security guarantees.
//
// Most users will interact with these primitives through the CryptoProvider
// interface in the zipnet package, rather than directly.
package crypto
