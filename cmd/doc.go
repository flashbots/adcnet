// Package cmd provides CLI commands for ADCNet services.
//
// # Commands
//
// demo-gateway: Serves the demo website and API for visualizing ADCNet.
// Connects to the registry, streams round results, and proxies message
// submissions through a demo client.
//
//	go run ./cmd/demo-gateway --registry=http://localhost:7999
//	go run ./cmd/demo-gateway --registry=http://localhost:7999 --static=./web/dist
//
// multiservice: Unified command that runs client, server, or aggregator based
// on configuration. Suitable for building a single TEE VM image.
//
//	go run ./cmd/multiservice --service-type=server --registry=http://localhost:8080
//	go run ./cmd/multiservice --config=config.yaml
//
// registry: Central service discovery and configuration distribution.
//
//	go run ./cmd/registry --addr=:8080 --admin-token=admin:secret
//
// demo-cli: CLI for interacting with a deployed ADCNet network.
//
//	go run ./cmd/demo-cli send -r http://localhost:7999 -m "Hello" -b 100
//	go run ./cmd/demo-cli monitor -r http://localhost:7999 --follow
//
// # HTTP Configuration Mode
//
// The multiservice command supports waiting for configuration via HTTP POST,
// useful for TEE deployments where configuration is provided after boot:
//
//	# Start service in wait mode
//	go run ./cmd/multiservice --wait-config --addr=:8080
//
//	# Submit configuration to start the service
//	curl -X POST http://localhost:8080/config -d @config.yaml
//
// # Configuration
//
// All commands support YAML configuration files via the --config flag.
// Command-line flags override config file values.
//
// Example config for the unified service command:
//
//	service_type: "server"
//	http_addr: ":8081"
//	registry_url: "http://localhost:8080"
//	admin_token: "admin:secret"
//	keys:
//	  signing_key: ""
//	  exchange_key: ""
//	attestation:
//	  use_tdx: false
//	  tdx_remote_url: ""
//	  measurements_url: ""
//	server:
//	  is_leader: true
//
// # Demo Website
//
// The demo-gateway command serves a web dashboard that visualizes:
//   - Network topology (servers, aggregators, clients)
//   - Round phase progression (client → aggregation → server → broadcast)
//   - Live message stream from decoded rounds
//   - Message submission with auction bidding
//   - Protocol configuration
//
// The dashboard connects via Server-Sent Events for real-time updates.
// Static files can be served from a directory (--static) or the gateway
// serves an embedded minimal dashboard.
package cmd
