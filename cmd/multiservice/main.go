// Command service runs an ADCNet service (client, server, or aggregator).
//
// The service type is determined by the --service-type flag or the service_type
// field in the configuration file. This unified command enables building a single
// binary for TEE VM images.
//
// # Configuration File
//
// Create a YAML file with service settings:
//
//	service_type: "server"  # client, server, or aggregator
//	http_addr: ":8081"
//	registry_url: "http://localhost:8080"
//	admin_token: "admin:secret"
//	keys:
//	  signing_key: ""     # Hex-encoded, generates if empty
//	  exchange_key: ""    # Hex-encoded, generates if empty
//	attestation:
//	  use_tdx: false
//	  tdx_remote_url: ""
//	  measurements_url: ""
//	server:
//	  is_leader: true     # Server-specific: designates round leader
//
// # HTTP Configuration Mode
//
// Use --wait-config to start an HTTP server that waits for configuration:
//
//	go run ./cmd/service --wait-config --addr=:8080
//
// Then POST configuration to start the service:
//
//	curl -X POST http://localhost:8080/config -d @config.yaml
//
// # Service Types
//
// client: Broadcasts messages anonymously using XOR-based blinding.
// Self-registers via the registry's public endpoint.
//
// server: Participates in message reconstruction by removing XOR blinding
// factors. Requires admin authentication for registry registration.
//
// aggregator: Reduces bandwidth by combining client messages before
// forwarding to servers. Requires admin authentication for registration.
//
// # Usage
//
//	go run ./cmd/service --config=service.yaml
//	go run ./cmd/service --service-type=server --registry=http://localhost:8080
//	go run ./cmd/service --wait-config --addr=:8080
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/flashbots/adcnet/cmd/common"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		configPath      = flag.String("config", "", "Path to YAML config file")
		waitConfig      = flag.Bool("wait-config", false, "Wait for config via HTTP POST to /config")
		serviceType     = flag.String("service-type", "", "Service type: client, server, or aggregator")
		addr            = flag.String("addr", ":8080", "HTTP listen address")
		registryURL     = flag.String("registry", "", "Registry URL for service discovery")
		adminToken      = flag.String("admin-token", "", "Admin token for registry (user:pass)")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX attestation service URL")
		isLeader        = flag.Bool("leader", false, "Server only: designate as round leader")
		signingKeyHex   = flag.String("signing-key", "", "Ed25519 signing key (hex, generates if empty)")
		exchangeKeyHex  = flag.String("exchange-key", "", "ECDH P-256 exchange key (hex, generates if empty)")
	)
	flag.Parse()

	isFlagSet := func(name string) bool {
		found := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == name {
				found = true
			}
		})
		return found
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		cancel()
	}()

	var cfg *common.Config
	var err error

	if *waitConfig {
		cfg, err = waitForConfig(ctx, *addr)
		if err != nil {
			if ctx.Err() != nil {
				fmt.Println("Shutdown during config wait")
				return
			}
			fmt.Printf("Error waiting for config: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg, err = loadConfiguration(*configPath)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}
	}

	applyFlagOverrides(cfg, *serviceType, *addr, *registryURL, *adminToken,
		*measurementsURL, *useTDX, *remoteTDXURL, *isLeader, *signingKeyHex, *exchangeKeyHex,
		isFlagSet("addr"))

	if err := validateConfig(cfg); err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		os.Exit(1)
	}

	if err := run(ctx, cfg); err != nil {
		if ctx.Err() != nil {
			return
		}
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func waitForConfig(ctx context.Context, addr string) (*common.Config, error) {
	configCh := make(chan *common.Config, 1)
	errCh := make(chan error, 1)

	var configOnce sync.Once

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("waiting"))
	})

	r.Post("/config", func(w http.ResponseWriter, r *http.Request) {
		configOnce.Do(func() {
			cfg, err := parseConfigFromRequest(r)
			if err != nil {
				errCh <- err
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			configCh <- cfg
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("configuration accepted"))
		})
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		fmt.Printf("Waiting for configuration on %s (POST /config)\n", addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("config server: %w", err)
		}
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case cfg := <-configCh:
		fmt.Println("Configuration received, starting service...")
		return cfg, nil
	}
}

func parseConfigFromRequest(r *http.Request) (*common.Config, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	cfg := common.DefaultConfig()
	if err := yaml.Unmarshal(body, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

func loadConfiguration(configPath string) (*common.Config, error) {
	if configPath != "" {
		return common.LoadConfig(configPath)
	}
	return common.DefaultConfig(), nil
}

func applyFlagOverrides(cfg *common.Config, serviceType, addr, registryURL, adminToken,
	measurementsURL string, useTDX bool, remoteTDXURL string, isLeader bool,
	signingKeyHex, exchangeKeyHex string, addrExplicit bool) {

	if serviceType != "" {
		cfg.ServiceType = serviceType
	}
	if addrExplicit {
		cfg.HTTPAddr = addr
	} else if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = addr
	}
	if registryURL != "" {
		cfg.RegistryURL = registryURL
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
	if isLeader {
		cfg.Server.IsLeader = true
	}
	if signingKeyHex != "" {
		cfg.Keys.SigningKey = signingKeyHex
	}
	if exchangeKeyHex != "" {
		cfg.Keys.ExchangeKey = exchangeKeyHex
	}
}

func validateConfig(cfg *common.Config) error {
	if _, err := common.ToServicesType(cfg.ServiceType); err != nil {
		return err
	}
	if cfg.RegistryURL == "" {
		return fmt.Errorf("registry_url is required (via --registry or config file)")
	}
	return nil
}

func run(ctx context.Context, cfg *common.Config) error {
	signingKey, err := common.LoadOrGenerateSigningKey(cfg.Keys.SigningKey)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}

	exchangeKey, err := common.LoadOrGenerateExchangeKey(cfg.Keys.ExchangeKey)
	if err != nil {
		return fmt.Errorf("exchange key: %w", err)
	}

	pubKey, _ := signingKey.PublicKey()
	fmt.Printf("%s public key: %s\n", cfg.ServiceType, pubKey.String())
	fmt.Printf("Exchange public key: %s\n", hex.EncodeToString(exchangeKey.PublicKey().Bytes()))

	adcConfig, err := common.FetchADCConfig(cfg.RegistryURL)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	svcType, _ := common.ToServicesType(cfg.ServiceType)
	svcConfig := &services.ServiceConfig{
		ADCNetConfig:              adcConfig,
		AttestationProvider:       common.NewAttestationProvider(cfg.Attestation),
		AllowedMeasurementsSource: common.NewMeasurementSource(cfg.Attestation.MeasurementsURL),
		HTTPAddr:                  cfg.HTTPAddr,
		ServiceType:               svcType,
		RegistryURL:               cfg.RegistryURL,
		AdminToken:                cfg.AdminToken,
	}

	r := chi.NewRouter()

	var starter func(context.Context) error

	// Register service routes FIRST (they add middleware)
	switch cfg.ServiceType {
	case "client":
		client, err := services.NewHTTPClient(svcConfig, signingKey, exchangeKey)
		if err != nil {
			return fmt.Errorf("create client: %w", err)
		}
		client.RegisterRoutes(r)
		starter = client.Start

	case "aggregator":
		aggregator, err := services.NewHTTPAggregator(svcConfig, signingKey, exchangeKey)
		if err != nil {
			return fmt.Errorf("create aggregator: %w", err)
		}
		aggregator.RegisterRoutes(r)
		starter = aggregator.Start

	case "server":
		serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
		server, err := services.NewHTTPServer(svcConfig, serverID, signingKey, exchangeKey, cfg.Server.IsLeader)
		if err != nil {
			return fmt.Errorf("create server: %w", err)
		}
		server.RegisterRoutes(r)
		starter = server.Start
	}

	// Add health endpoint AFTER service routes (middleware already registered)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		leaderInfo := ""
		if cfg.ServiceType == "server" {
			leaderInfo = fmt.Sprintf(" (leader=%v)", cfg.Server.IsLeader)
		}
		fmt.Printf("%s listening on %s%s\n", cfg.ServiceType, cfg.HTTPAddr, leaderInfo)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := starter(ctx); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	fmt.Printf("Shutting down %s...\n", cfg.ServiceType)
	return httpServer.Shutdown(shutdownCtx)
}
