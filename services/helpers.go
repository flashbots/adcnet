package services

import (
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
)

// GetServerID extracts server ID from HTTP server instance.
func GetServerID(s *HTTPServer) protocol.ServerID {
	pubKey, _ := s.signingKey.PublicKey()
	return protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
}
