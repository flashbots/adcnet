// Command registry runs a standalone ADCNet registry service.
//
// The registry provides centralized service discovery for ADCNet deployments.
//
// # Configuration File
//
// Create a YAML file with registry settings:
//
//	http_addr: ":8080"
//	admin_token: "admin:secret"
//	attestation:
//	  use_tdx: false
//	  measurements_url: ""
//	protocol:
//	  round_duration: 10s
//	  message_length: 512000
//	  auction_slots: 10
//	  min_clients: 1
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
// Admin (basic auth when admin_token set):
//   - POST /admin/register/{type} - Register server or aggregator
//   - DELETE /admin/unregister/{key} - Remove a service
//
// # Usage
//
//	go run ./cmd/registry --config=registry.yaml
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
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	var (
		configPath      = flag.String("config", "", "Path to YAML config file")
		addr            = flag.String("addr", "", "HTTP listen address")
		adminToken      = flag.String("admin-token", "", "Basic auth token for admin operations (user:pass)")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation verification")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX verification service URL")
		roundDuration   = flag.Duration("round", 0, "Round duration")
		messageLength   = flag.Int("msg-length", 0, "Message vector length in bytes")
		auctionSlots    = flag.Uint("auction-slots", 0, "Number of auction slots")
		minClients      = flag.Uint("min-clients", 0, "Minimum clients for anonymity")
	)
	flag.Parse()

	// isFlagSet checks if a flag was explicitly provided on command line
	isFlagSet := func(name string) bool {
		found := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == name {
				found = true
			}
		})
		return found
	}

	cfg, err := loadConfiguration(*configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	applyFlagOverrides(cfg, *addr, *adminToken, *measurementsURL, *useTDX,
		*remoteTDXURL, *roundDuration, *messageLength, *auctionSlots, *minClients,
		isFlagSet("addr"))

	if err := run(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfiguration(configPath string) (*common.Config, error) {
	if configPath != "" {
		return common.LoadConfig(configPath)
	}
	return common.DefaultConfig(), nil
}

func applyFlagOverrides(cfg *common.Config, addr, adminToken, measurementsURL string,
	useTDX bool, remoteTDXURL string, roundDuration time.Duration,
	messageLength int, auctionSlots, minClients uint, addrExplicit bool) {

	if addrExplicit {
		cfg.HTTPAddr = addr
	} else if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = addr // Use default
	}
	if adminToken != "" {
		cfg.AdminToken = adminToken
	}
	if measurementsURL != "" {
		cfg.Attestation.MeasurementsURL = measurementsURL
	}
	if useTDX {
		cfg.Attestation.UseTDX = true
	}
	if remoteTDXURL != "" {
		cfg.Attestation.TDXRemoteURL = remoteTDXURL
	}
	if roundDuration != 0 {
		cfg.Protocol.RoundDuration = roundDuration
	}
	if messageLength != 0 {
		cfg.Protocol.MessageLength = messageLength
	}
	if auctionSlots != 0 {
		cfg.Protocol.AuctionSlots = uint32(auctionSlots)
	}
	if minClients != 0 {
		cfg.Protocol.MinClients = uint32(minClients)
	}
}

func run(cfg *common.Config) error {
	adcConfig := cfg.Protocol.ToADCNetConfig()
	attestationProvider := common.NewAttestationProvider(cfg.Attestation)
	measurementSource := common.NewMeasurementSource(cfg.Attestation.MeasurementsURL)

	registryConfig := &services.RegistryConfig{
		AttestationProvider: attestationProvider,
		MeasurementSource:   measurementSource,
		AdminToken:          cfg.AdminToken,
	}

	registry := services.NewRegistry(registryConfig, adcConfig)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	registry.RegisterPublicRoutes(r)
	registry.RegisterAdminRoutes(r)

	server := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		fmt.Printf("Registry listening on %s\n", cfg.HTTPAddr)
		if cfg.AdminToken != "" {
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
	return server.Shutdown(ctx)
}
