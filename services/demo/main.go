package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := &OrchestratorConfig{
		NumClients:     10,
		NumAggregators: 2,
		NumServers:     5,

		BasePort:      8000,
		RoundDuration: 10 * time.Second,
		MessageLength: 512000,
		AuctionSlots:  10,
	}

	orchestrator := NewOrchestrator(config)

	if err := orchestrator.Deploy(); err != nil {
		fmt.Printf("Deployment failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nADCNet deployment running...")
	fmt.Println("Configuration:")
	fmt.Printf("  Clients: %d\n", config.NumClients)
	fmt.Printf("  Aggregators: %d\n", config.NumAggregators)
	fmt.Printf("  Servers: %d (all required for message recovery)\n", config.NumServers)
	fmt.Printf("  Round duration: %v\n", config.RoundDuration)
	fmt.Println("\nPress Ctrl+C to shutdown...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	if err := orchestrator.Shutdown(); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}

	fmt.Println("Deployment stopped.")
}
