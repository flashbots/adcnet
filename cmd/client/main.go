// Command client runs a standalone ADCNet client service.
//
// Clients broadcast messages anonymously using XOR-based blinding with shared
// secrets from all servers. Message scheduling uses an auction mechanism where
// clients bid for transmission slots.
//
// # Registration
//
// Clients self-register via the registry's public endpoint on startup. No
// administrator action is required. The client discovers servers and aggregators
// through registry polling and establishes shared secrets automatically.
//
// # Usage
//
//	go run ./cmd/client --registry=http://localhost:8080
package main

import (
	"context"
	"encoding/hex"
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
		addr            = flag.String("addr", ":8083", "HTTP listen address")
		registryURL     = flag.String("registry", "", "Registry URL for service discovery")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX attestation service URL")
		signingKeyHex   = flag.String("signing-key", "", "Ed25519 signing key (hex, generates if empty)")
		exchangeKeyHex  = flag.String("exchange-key", "", "ECDH P-256 exchange key (hex, generates if empty)")
	)
	flag.Parse()

	if *registryURL == "" {
		fmt.Println("Error: --registry is required")
		os.Exit(1)
	}

	signingKey, err := common.LoadOrGenerateSigningKey(*signingKeyHex)
	if err != nil {
		fmt.Printf("Signing key error: %v\n", err)
		os.Exit(1)
	}

	exchangeKey, err := common.LoadOrGenerateExchangeKey(*exchangeKeyHex)
	if err != nil {
		fmt.Printf("Exchange key error: %v\n", err)
		os.Exit(1)
	}

	pubKey, _ := signingKey.PublicKey()
	fmt.Printf("Client public key: %s\n", pubKey.String())
	fmt.Printf("Exchange public key: %s\n", hex.EncodeToString(exchangeKey.PublicKey().Bytes()))

	adcConfig, err := common.FetchADCConfig(*registryURL)
	if err != nil {
		fmt.Printf("Error fetching config: %v\n", err)
		os.Exit(1)
	}

	attestationProvider := common.NewAttestationProvider(*useTDX, *remoteTDXURL)
	measurementSource := common.NewMeasurementSource(*measurementsURL)

	config := &services.ServiceConfig{
		ADCNetConfig:              adcConfig,
		AttestationProvider:       attestationProvider,
		AllowedMeasurementsSource: measurementSource,
		HTTPAddr:                  *addr,
		ServiceType:               services.ClientService,
		RegistryURL:               *registryURL,
		SelfRegister:              true, // Clients self-register
	}

	client, err := services.NewHTTPClient(config, signingKey, exchangeKey)
	if err != nil {
		fmt.Printf("Create client error: %v\n", err)
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	client.RegisterRoutes(r)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		fmt.Printf("Client listening on %s\n", *addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := client.Start(ctx); err != nil {
		fmt.Printf("Start error: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	fmt.Println("Shutting down client...")
	cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}
}
