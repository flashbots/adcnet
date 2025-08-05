package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/adcnet/services"
)

func main() {
	// Configure deployment
	config := &services.OrchestratorConfig{
		NumClients:     10,
		NumAggregators: 2,
		NumServers:     5,
		MinServers:     2, // 2-of-3 threshold

		BasePort:      8000,
		RoundDuration: 10 * time.Second,
		MessageSlots:  1000, // 500kB
		AuctionSlots:  10,
	}

	// Create orchestrator
	orchestrator := services.NewOrchestrator(config)

	// Deploy all services
	if err := orchestrator.Deploy(); err != nil {
		fmt.Printf("Deployment failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nADCNet deployment running...")
	fmt.Println("Configuration:")
	fmt.Printf("  Clients: %d\n", config.NumClients)
	fmt.Printf("  Aggregators: %d\n", config.NumAggregators)
	fmt.Printf("  Servers: %d (threshold: %d)\n", config.NumServers, config.MinServers)
	fmt.Printf("  Round duration: %v\n", config.RoundDuration)
	fmt.Println("\nPress Ctrl+C to shutdown...")

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Shutdown
	if err := orchestrator.Shutdown(); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}

	fmt.Println("Deployment stopped.")
}
