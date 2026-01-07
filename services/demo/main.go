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

	go orchestrator.SendMessages()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	if err := orchestrator.Shutdown(); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}

	fmt.Println("Deployment stopped.")
}

func printDeploymentInfo(config *OrchestratorConfig, o *Orchestrator) {
	var tout string
	tout += "\n╔══════════════════════════════════════════════════════════════╗"
	tout += "\n║              ADCNet Demo Deployment Running                  ║"
	tout += "\n╠══════════════════════════════════════════════════════════════╣"
	tout += fmt.Sprintf("\n║  Clients:      %-4d                                          ║", config.NumClients)
	tout += fmt.Sprintf("\n║  Aggregators:  %-4d                                          ║", config.NumAggregators)
	tout += fmt.Sprintf("\n║  Servers:      %-4d (all required for message recovery)      ║", config.NumServers)
	tout += fmt.Sprintf("\n║  Round:        %-10v                                    ║", config.RoundDuration)
	tout += fmt.Sprintf("\n║  Message size: %-6d bytes                                  ║", config.MessageLength)

	attestMode := "Dummy"
	if config.UseTDX {
		if config.RemoteTDXURL != "" {
			attestMode = "Remote TDX"
		} else {
			attestMode = "Local TDX"
		}
	}
	tout += fmt.Sprintf("\n║  Attestation:  %-10s                                    ║", attestMode)

	measureMode := "Demo Static"
	if config.MeasurementsURL != "" {
		measureMode = "Remote"
	}
	tout += fmt.Sprintf("\n║  Measurements: %-10s                                   ║", measureMode)

	tout += ("\n╠══════════════════════════════════════════════════════════════╣")
	tout += fmt.Sprintf("\n║  Registry:     http://localhost:%d                         ║", config.BasePort-1)
	tout += "\n╠══════════════════════════════════════════════════════════════╣"
	tout += "\n║  Round outputs will be printed as they complete.             ║"
	tout += "\n║  Press Ctrl+C to shutdown.                                   ║"
	tout += "\n╚══════════════════════════════════════════════════════════════╝"
	fmt.Println(tout)
}
