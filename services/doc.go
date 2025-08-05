/*
# ADCNet Services Package

The services package provides HTTP-based implementations of ADCNet protocol components for real-world deployment.

## Overview

This package wraps the core protocol implementations with HTTP APIs, enabling:
- RESTful communication between components
- Easy deployment and testing
- Monitoring and observability
- Flexible network topologies

## Components

### HTTP Services

1. **HTTPClient** (`http_client.go`)
  - Wraps `protocol.ClientService`
  - Manages message scheduling and auction participation
  - Endpoints:
  - `POST /register` - Register with servers/aggregators
  - `POST /schedule-message` - Schedule a message for broadcast
  - `GET /round-messages` - Get messages for current round
  - `POST /round-broadcast` - Receive round results

2. **HTTPAggregator** (`http_aggregator.go`)
  - Wraps `protocol.AggregatorService`
  - Aggregates client messages to reduce server bandwidth
  - Endpoints:
  - `POST /register` - Register clients/servers
  - `POST /client-messages` - Receive client messages
  - `POST /aggregate-messages` - Hierarchical aggregation
  - `GET /aggregates/{round}` - Get round aggregates

3. **HTTPServer** (`http_server.go`)
  - Wraps `protocol.ServerService`
  - Performs threshold decryption with other servers
  - Endpoints:
  - `POST /register` - Register other servers
  - `POST /register-client` - Register clients
  - `POST /aggregate` - Receive aggregated messages
  - `POST /partial-decryption` - Exchange partial decryptions
  - `GET /round-broadcast/{round}` - Get final broadcast

### Orchestrator

The `Orchestrator` (`orchestrator.go`) manages deployment lifecycle:
- Deploys configured number of clients, aggregators, and servers
- Establishes service registrations
- Manages round progression
- Generates test messages

## Usage

### Basic Deployment

```go
import "github.com/flashbots/adcnet/services"

// Configure deployment

	config := &services.OrchestratorConfig{
	    NumClients:       10,
	    NumAggregators:   2,
	    NumServers:       3,
	    MinServers:       2,  // 2-of-3 threshold
	    BasePort:         8000,
	    RoundDuration:    10 * time.Second,
	    MessageSize:      100,
	    AuctionSlots:     20,
	}

// Create and deploy
orchestrator := services.NewOrchestrator(config)

	if err := orchestrator.Deploy(); err != nil {
	    log.Fatal(err)
	}

// Shutdown when done
defer orchestrator.Shutdown()
```

### Manual Service Creation

```go
// Create client

	config := &services.ServiceConfig{
	    ADCNetConfig:  adcnetConfig,
	    HTTPAddr:      "localhost:8001",
	    ServiceID:     "client-1",
	    ServiceType:   services.ClientService,
	}

client, err := services.NewHTTPClient(config, signingKey, exchangeKey)

// Start HTTP server
router := chi.NewRouter()
client.RegisterRoutes(router)
http.ListenAndServe(config.HTTPAddr, router)
```

## Message Flow

1. **Client Phase**:
  - Clients check previous auction results
  - Winners encode messages at allocated slots
  - Create polynomial secret shares
  - Blind shares with server-specific keys
  - Send to aggregators

2. **Aggregation Phase**:
  - Aggregators sum client shares
  - Forward aggregates to servers

3. **Server Phase**:
  - Servers remove blinding factors
  - Exchange partial decryptions
  - Leader reconstructs messages
  - Broadcast results to clients

## Testing

Run the demo application:

```bash
go run cmd/demo/main.go
```

This starts a local deployment with:
- 5 clients generating test messages
- 2 aggregators for bandwidth reduction
- 3 servers with 2-of-3 threshold
- Automatic message generation and bidding

## Configuration

Key parameters in `OrchestratorConfig`:

- `NumClients/Aggregators/Servers`: Component counts
- `MinServers`: Threshold for reconstruction
- `RoundDuration`: Time per protocol round
- `MessageSize`: Vector size in field elements
- `AuctionSlots`: IBF size for auction
- `MessagesPerRound`: Test message generation rate

## Security Notes

- Uses Ed25519 for signatures
- ECDH P-256 for key exchange
- Threshold secret sharing for privacy
- One-time pad blinding per round

## Performance

- Aggregators reduce server bandwidth by O(NumClients)
- Parallel HTTP requests for efficiency
- Configurable round duration for throughput tuning
*/
package services
