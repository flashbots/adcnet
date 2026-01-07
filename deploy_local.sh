#!/bin/bash
# deploy-local.sh - Deploy a local ADCNet network using multiservice with wait-config
#
# Deploys configurable numbers of servers, aggregators, and clients, plus
# a demo gateway for presentation.
#
# Usage:
#   ./scripts/deploy-local.sh
#   ./scripts/deploy-local.sh --servers=3 --aggregators=2 --clients=5
#   ./scripts/deploy-local.sh --round=5s --msg-length=64000

set -e

# Configuration defaults
NUM_SERVERS=2
NUM_AGGREGATORS=1
NUM_CLIENTS=2
REGISTRY_PORT=7999
GATEWAY_PORT=8000
BASE_PORT=8001
ROUND_DURATION="10s"
MESSAGE_LENGTH=512000
AUCTION_SLOTS=10
ADMIN_TOKEN="admin:secret"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --servers=*) NUM_SERVERS="${1#*=}"; shift ;;
        --aggregators=*) NUM_AGGREGATORS="${1#*=}"; shift ;;
        --clients=*) NUM_CLIENTS="${1#*=}"; shift ;;
        --round=*) ROUND_DURATION="${1#*=}"; shift ;;
        --msg-length=*) MESSAGE_LENGTH="${1#*=}"; shift ;;
        --auction-slots=*) AUCTION_SLOTS="${1#*=}"; shift ;;
        --admin-token=*) ADMIN_TOKEN="${1#*=}"; shift ;;
        --base-port=*) BASE_PORT="${1#*=}"; shift ;;
        --registry-port=*) REGISTRY_PORT="${1#*=}"; shift ;;
        --demo-gateway-port=*) GATEWAY_PORT="${1#*=}"; shift ;;
        -h|--help) 
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --servers=N        Number of servers (default: 2)"
            echo "  --aggregators=N    Number of aggregators (default: 1)"
            echo "  --clients=N        Number of clients (default: 2)"
            echo "  --round=DURATION   Round duration (default: 10s)"
            echo "  --msg-length=N     Message vector length (default: 512000)"
            echo "  --auction-slots=N  Auction slots (default: 10)"
            echo "  --admin-token=T    Admin token (default: admin:secret)"
            echo "  --base-port=N      Base port for services (default: 8001)"
            echo "  --registry-port=N  Registry port (default: 7999)"
            echo "  --demo-gateway-port=N       Demo gateway server port (default: 8000)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

REGISTRY_URL="http://localhost:${REGISTRY_PORT}"
PIDS=()
TEMP_DIR=$(mktemp -d)

cleanup() {
    echo ""
    echo "Shutting down services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$TEMP_DIR"
    echo "Cleanup complete."
}
trap cleanup EXIT INT TERM

wait_for_health() {
    local url=$1
    local name=$2
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -s "${url}/health" > /dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.2
    done
    echo "ERROR: ${name} at ${url} did not become healthy"
    return 1
}

post_config() {
    local url=$1
    local config=$2
    local name=$3

    response=$(curl -s -w "%{http_code}" -X POST "${url}/config" \
        -H "Content-Type: application/yaml" \
        -d "$config")
    
    http_code="${response: -3}"
    if [ "$http_code" != "200" ]; then
        echo "ERROR: Failed to configure ${name}: ${response}"
        return 1
    fi
    echo "    ✓ ${name} configured"
}

# Calculate port ranges
SERVER_PORTS_START=$BASE_PORT
AGG_PORTS_START=$((BASE_PORT + NUM_SERVERS))
CLIENT_PORTS_START=$((AGG_PORTS_START + NUM_AGGREGATORS))

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              ADCNet Local Deployment Script                   ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
printf "║  Registry:     http://localhost:%-6s                        ║\n" "${REGISTRY_PORT}"
printf "║  Web demo:     http://localhost:%-6s                        ║\n" "${GATEWAY_PORT}"
printf "║  Servers:      %-2d (ports %-5d-%-5d)%-25s║\n" "$NUM_SERVERS" "$SERVER_PORTS_START" "$((SERVER_PORTS_START + NUM_SERVERS - 1))" ""
printf "║  Aggregators:  %-2d (ports %-5d-%-5d)%-25s║\n" "$NUM_AGGREGATORS" "$AGG_PORTS_START" "$((AGG_PORTS_START + NUM_AGGREGATORS - 1))" ""
printf "║  Clients:      %-2d (ports %-5d-%-5d)%-25s║\n" "$NUM_CLIENTS" "$CLIENT_PORTS_START" "$((CLIENT_PORTS_START + NUM_CLIENTS - 1))" ""
printf "║  Round:        %-11s                                    ║\n" "${ROUND_DURATION}"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Start Registry
echo "[1/5] Starting registry..."
go run ./cmd/registry \
    --addr=":${REGISTRY_PORT}" \
    --admin-token="${ADMIN_TOKEN}" \
    --round="${ROUND_DURATION}" \
    --msg-length="${MESSAGE_LENGTH}" \
    --auction-slots="${AUCTION_SLOTS}" \
    --min-clients=1 \
    > "${TEMP_DIR}/registry.log" 2>&1 &
PIDS+=($!)

wait_for_health "${REGISTRY_URL}" "Registry"
echo "    ✓ Registry ready"

# Step 2: Start services in wait-config mode
echo ""
echo "[2/5] Starting ${NUM_SERVERS} servers, ${NUM_AGGREGATORS} aggregators, ${NUM_CLIENTS} clients..."

# Start servers
for i in $(seq 0 $((NUM_SERVERS - 1))); do
    port=$((SERVER_PORTS_START + i))
    go run ./cmd/multiservice --wait-config --addr=":${port}" \
        > "${TEMP_DIR}/server${i}.log" 2>&1 &
    PIDS+=($!)
done

# Start aggregators
for i in $(seq 0 $((NUM_AGGREGATORS - 1))); do
    port=$((AGG_PORTS_START + i))
    go run ./cmd/multiservice --wait-config --addr=":${port}" \
        > "${TEMP_DIR}/aggregator${i}.log" 2>&1 &
    PIDS+=($!)
done

# Start clients
for i in $(seq 0 $((NUM_CLIENTS - 1))); do
    port=$((CLIENT_PORTS_START + i))
    go run ./cmd/multiservice --wait-config --addr=":${port}" \
        > "${TEMP_DIR}/client${i}.log" 2>&1 &
    PIDS+=($!)
done

# Wait for all services to be ready
echo "    Waiting for services to accept configuration..."
for i in $(seq 0 $((NUM_SERVERS - 1))); do
    port=$((SERVER_PORTS_START + i))
    wait_for_health "http://localhost:${port}" "Server ${i}"
done
for i in $(seq 0 $((NUM_AGGREGATORS - 1))); do
    port=$((AGG_PORTS_START + i))
    wait_for_health "http://localhost:${port}" "Aggregator ${i}"
done
for i in $(seq 0 $((NUM_CLIENTS - 1))); do
    port=$((CLIENT_PORTS_START + i))
    wait_for_health "http://localhost:${port}" "Client ${i}"
done
echo "    ✓ All services ready for configuration"

# Step 3: Send configurations
echo ""
echo "[3/5] Sending configurations..."

# Configure servers (first one is leader)
for i in $(seq 0 $((NUM_SERVERS - 1))); do
    port=$((SERVER_PORTS_START + i))
    is_leader="false"
    leader_label=""
    if [ $i -eq 0 ]; then
        is_leader="true"
        leader_label=" (Leader)"
    fi
    post_config "http://localhost:${port}" "
service_type: server
http_addr: ':${port}'
registry_url: '${REGISTRY_URL}'
admin_token: '${ADMIN_TOKEN}'
server:
  is_leader: ${is_leader}
" "Server ${i}${leader_label}"
done

# Configure aggregators
for i in $(seq 0 $((NUM_AGGREGATORS - 1))); do
    port=$((AGG_PORTS_START + i))
    post_config "http://localhost:${port}" "
service_type: aggregator
http_addr: ':${port}'
registry_url: '${REGISTRY_URL}'
admin_token: '${ADMIN_TOKEN}'
" "Aggregator ${i}"
done

# Configure clients
for i in $(seq 0 $((NUM_CLIENTS - 1))); do
    port=$((CLIENT_PORTS_START + i))
    post_config "http://localhost:${port}" "
service_type: client
http_addr: ':${port}'
registry_url: '${REGISTRY_URL}'
" "Client ${i}"
done

# Step 4: Verify deployment
echo ""
echo "[4/5] Verifying deployment..."
sleep 2

services=$(curl -s "${REGISTRY_URL}/services")
n_servers=$(echo "$services" | grep -o '"service_type":"server"' | wc -l)
n_aggregators=$(echo "$services" | grep -o '"service_type":"aggregator"' | wc -l)
n_clients=$(echo "$services" | grep -o '"service_type":"client"' | wc -l)

echo "    Registered: ${n_servers} servers, ${n_aggregators} aggregators, ${n_clients} clients"

if [ "$n_servers" -ne "$NUM_SERVERS" ] || [ "$n_aggregators" -ne "$NUM_AGGREGATORS" ] || [ "$n_clients" -ne "$NUM_CLIENTS" ]; then
    echo "    ⚠ Warning: Not all services registered (expected ${NUM_SERVERS}/${NUM_AGGREGATORS}/${NUM_CLIENTS})"
fi

# Step 5: Start demo web server (after services are registered)
echo ""
echo "[5/5] Starting demo web server..."
go run ./cmd/demo-gateway \
    -addr=":${GATEWAY_PORT}" \
    -registry="${REGISTRY_URL}" \
	-static "web/dist/" \
	-skip-verification \
    > "${TEMP_DIR}/webdemo.log" 2>&1 &
PIDS+=($!)

wait_for_health "http://localhost:${GATEWAY_PORT}" "Web Demo Server"
echo "    ✓ Web demo server ready"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Deployment Complete!                       ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Stream round results:                                        ║"
printf "║    curl -N http://localhost:%s/events%-23s║\n" "${GATEWAY_PORT}" ""
echo "║                                                               ║"
echo "║  Send a message:                                              "
echo "║    go run ./cmd/demo send -r ${REGISTRY_URL} -m 'Hello ADCNet!' -b 100 --skip-verification"
echo "║                                                               "
echo "║  Monitor rounds (CLI):                                        "
echo "║    go run ./cmd/demo monitor -r ${REGISTRY_URL} --follow --skip-verification"
echo "║                                                               "
echo "║  Check status:                                                ║"
printf "║    curl %s/services | jq%-19s║\n" "${REGISTRY_URL}" ""
echo "║                                                               ║"
printf "║  View logs: tail -f %s/*.log%-17s║\n" "${TEMP_DIR}" ""
echo "║                                                               ║"
echo "║  Press Ctrl+C to shutdown                                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Wait for interrupt
wait
