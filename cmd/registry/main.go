// Command registry runs a standalone ADCNet registry service.
//
// The registry provides centralized service discovery for ADCNet deployments.
// It maintains a list of registered servers, aggregators, and clients, and
// distributes protocol configuration to services on startup.
//
// # Authentication
//
// When --admin-token is configured, server and aggregator registration requires
// basic authentication via the /admin/register/{type} endpoint. Client
// registration is always available via /register/client without authentication.
//
// # Endpoints
//
// Public (no auth):
//   - POST /register/client - Client self-registration
//   - GET /services - List all services
//   - GET /services/{type} - List services by type
//   - GET /config - Protocol configuration
//   - GET /health - Health check
//
// Admin (basic auth when --admin-token set):
//   - POST /admin/register/{type} - Register server or aggregator
//   - DELETE /admin/unregister/{key} - Remove a service
//
// # Usage
//
//	go run ./cmd/registry --addr=:8080 --admin-token="admin:secret"
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/adcnet/cmd/common"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	var (
		addr            = flag.String("addr", ":8080", "HTTP listen address")
		adminToken      = flag.String("admin-token", "", "Basic auth token for admin operations (user:pass)")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation verification")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX verification service URL")
		roundDuration   = flag.Duration("round", 10*time.Second, "Round duration")
		messageLength   = flag.Int("msg-length", 512000, "Message vector length in bytes")
		auctionSlots    = flag.Uint("auction-slots", 10, "Number of auction slots")
		minClients      = flag.Uint("min-clients", 1, "Minimum clients for anonymity")
	)
	flag.Parse()

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    uint32(*auctionSlots),
		MessageLength:   *messageLength,
		MinClients:      uint32(*minClients),
		RoundDuration:   *roundDuration,
		RoundsPerWindow: 10,
	}

	attestationProvider := common.NewAttestationProvider(*useTDX, *remoteTDXURL)
	measurementSource := common.NewMeasurementSource(*measurementsURL)

	registryConfig := &services.RegistryConfig{
		AttestationProvider: attestationProvider,
		MeasurementSource:   measurementSource,
		AdminToken:          *adminToken,
	}

	registry := services.NewRegistry(registryConfig, adcConfig)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	registry.RegisterPublicRoutes(r)
	registry.RegisterAdminRoutes(r)

	server := &http.Server{
		Addr:         *addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		fmt.Printf("Registry listening on %s\n", *addr)
		if *adminToken != "" {
			fmt.Println("Admin authentication enabled for /admin/* routes")
		} else {
			fmt.Println("Warning: No admin token configured, /admin/* routes are unprotected")
		}
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Shutting down registry...")
	if err := server.Shutdown(ctx); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}
}
