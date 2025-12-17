package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		numClients      = flag.Int("clients", 10, "Number of clients")
		numAggregators  = flag.Int("aggregators", 2, "Number of aggregators")
		numServers      = flag.Int("servers", 5, "Number of servers (all required for message recovery)")
		basePort        = flag.Int("port", 8000, "Base port for services")
		roundDuration   = flag.Duration("round", 10*time.Second, "Round duration")
		messageLength   = flag.Int("msg-length", 512000, "Message vector length in bytes")
		auctionSlots    = flag.Uint("auction-slots", 10, "Number of auction slots")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX attestation service URL")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements (uses demo static if empty)")
		adminToken      = flag.String("admin-token", "admin:admin", "Admin token for registry (user:pass)")
	)
	flag.Parse()

	config := &OrchestratorConfig{
		NumClients:      *numClients,
		NumAggregators:  *numAggregators,
		NumServers:      *numServers,
		BasePort:        *basePort,
		RoundDuration:   *roundDuration,
		MessageLength:   *messageLength,
		AuctionSlots:    uint32(*auctionSlots),
		UseTDX:          *useTDX,
		RemoteTDXURL:    *remoteTDXURL,
		MeasurementsURL: *measurementsURL,
		AdminToken:      *adminToken,
	}

	orchestrator := NewOrchestrator(config)

	if err := orchestrator.Deploy(); err != nil {
		fmt.Printf("Deployment failed: %v\n", err)
		os.Exit(1)
	}

	printDeploymentInfo(config, orchestrator)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	if err := orchestrator.Shutdown(); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}

	fmt.Println("Deployment stopped.")
}

func printDeploymentInfo(config *OrchestratorConfig, o *Orchestrator) {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ADCNet Demo Deployment Running                  ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Clients:      %-4d                                          ║\n", config.NumClients)
	fmt.Printf("║  Aggregators:  %-4d                                          ║\n", config.NumAggregators)
	fmt.Printf("║  Servers:      %-4d (all required for message recovery)      ║\n", config.NumServers)
	fmt.Printf("║  Round:        %-10v                                     ║\n", config.RoundDuration)
	fmt.Printf("║  Message size: %-6d bytes                                  ║\n", config.MessageLength)

	attestMode := "Dummy"
	if config.UseTDX {
		if config.RemoteTDXURL != "" {
			attestMode = "Remote TDX"
		} else {
			attestMode = "Local TDX"
		}
	}
	fmt.Printf("║  Attestation:  %-10s                                     ║\n", attestMode)

	measureMode := "Demo Static"
	if config.MeasurementsURL != "" {
		measureMode = "Remote"
	}
	fmt.Printf("║  Measurements: %-10s                                     ║\n", measureMode)

	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Registry:     http://localhost:%d                          ║\n", config.BasePort-1)
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Round outputs will be printed as they complete.            ║")
	fmt.Println("║  Press Ctrl+C to shutdown.                                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}
