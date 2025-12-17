// Command demo runs a complete local ADCNet deployment for testing and development.
//
// The demo orchestrator starts all components in a single process:
//   - A central registry with configurable admin authentication
//   - Multiple servers (first server is the leader)
//   - Multiple aggregators
//   - Multiple clients that send random messages
//
// The orchestrator handles service registration automatically:
//   - Servers and aggregators expose /registration-data endpoints
//   - Orchestrator fetches signed registration data and forwards to registry
//   - Clients self-register via the public endpoint
//
// # Usage
//
//	go run ./services/demo [flags]
//
// # Flags
//
//	--clients        Number of clients (default: 10)
//	--aggregators    Number of aggregators (default: 2)
//	--servers        Number of servers (default: 5)
//	--port           Base port for services (default: 8000)
//	--round          Round duration (default: 10s)
//	--msg-length     Message vector length in bytes (default: 512000)
//	--auction-slots  Number of auction slots (default: 10)
//	--tdx            Use real TDX attestation
//	--tdx-url        Remote TDX attestation service URL
//	--measurements-url  URL for allowed measurements (uses demo static if empty)
//	--admin-token    Admin token for registry (user:pass, default: admin:admin)
//
// # Example
//
//	go run ./services/demo \
//	  --clients=10 \
//	  --servers=3 \
//	  --round=5s \
//	  --admin-token="admin:secret"
//
// Round outputs are printed as they complete, showing recovered messages.
package main
