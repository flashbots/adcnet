package services

import (
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// PublicKeyToServerID derives a server ID from a public key.
// Uses first 4 bytes of SHA256 hash for deterministic ID generation.

// GetServerID extracts server ID from HTTP server instance.
func GetServerID(s *HTTPServer) protocol.ServerID {
	// Access the server ID from the internal service
	// This would need proper accessor in protocol.ServerService
	pubKey, _ := s.signingKey.PublicKey()
	return protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
}
