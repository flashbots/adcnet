// Package cmd provides CLI commands for ADCNet services.
//
// # Commands
//
// service: Unified command that runs client, server, or aggregator based on
// configuration. Suitable for building a single TEE VM image.
//
//	go run ./cmd/service --service-type=server --registry=http://localhost:8080
//	go run ./cmd/service --config=config.yaml
//
// registry: Central service discovery and configuration distribution.
//
//	go run ./cmd/registry --addr=:8080 --admin-token=admin:secret
//
// # HTTP Configuration Mode
//
// The service command supports waiting for configuration via HTTP POST,
// useful for TEE deployments where configuration is provided after boot:
//
//	# Start service in wait mode
//	go run ./cmd/service --wait-config --addr=:8080
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
package cmd
