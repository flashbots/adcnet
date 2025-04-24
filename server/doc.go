// Package server implements the anytrust server component of the ZIPNet protocol.
//
// ZIPNet's anytrust servers provide anonymity as long as at least one server is honest.
// They receive aggregated messages from aggregators, unblind them with client-shared
// keys, and combine partial decryptions to produce the final broadcast message.
package server
