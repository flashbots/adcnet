// Package main implements the ADCNet demo gateway.
//
// The demo gateway provides a unified HTTP server that:
//   - Serves the demo dashboard website
//   - Exposes REST API for network state and configuration
//   - Streams round results via Server-Sent Events
//   - Proxies message submissions through a demo client
//
// # Architecture
//
// The gateway connects to the central registry to discover services and fetch
// configuration. It polls servers for round broadcasts and decodes messages
// using the previous round's auction results.
//
// Message submission flow:
//  1. User submits message + bid to POST /api/send
//  2. Gateway encrypts payload to demo client's exchange key
//  3. Gateway forwards to client's /encrypted-message endpoint
//  4. Client includes message in next round's protocol execution
//
// # API Endpoints
//
//	GET  /api/config      Protocol configuration (round duration, capacity, etc.)
//	GET  /api/services    All registered services with health/attestation status
//	GET  /api/round       Current round number, phase, and timing
//	GET  /api/rounds/:n   Historical round data with decoded messages
//	POST /api/send        Submit message for anonymous broadcast
//
// # Streaming
//
//	GET  /events          SSE stream of round completion events
//
// Event format:
//
//	event: round
//	data: {"round":42,"timestamp":"...","messages":[...]}
//
// # Static Files
//
// If --static is provided, serves files from that directory with SPA fallback.
//
// # Security Considerations
//
// The demo client used for message submission is trusted with plaintext content.
// For production use, clients should encrypt messages end-to-end to recipients
// before submission.
//
// # Usage
//
//	go run ./cmd/demo-gateway --registry=http://localhost:7999 --static=./web/dist
//
//	# Skip attestation verification (insecure)
//	go run ./cmd/demo-gateway --registry=http://localhost:7999 --skip-verification
package main
