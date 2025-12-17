// Command server runs a standalone ADCNet server service.
//
// Servers participate in message reconstruction by removing their XOR blinding
// factors from aggregated messages. All servers must contribute their partial
// decryptions for messages to be recovered.
//
// # Registration
//
// Servers expose a GET /registration-data endpoint that returns signed and
// attested registration data. An administrator fetches this data and forwards
// it to the registry's admin endpoint. This ensures the attestation originates
// from the server's own TEE.
//
// # Leader Election
//
// One server must be designated as the leader (--leader flag). The leader
// is responsible for broadcasting reconstructed messages to clients after
// all partial decryptions are collected.
//
// # Usage
//
//	go run ./cmd/server --registry=http://localhost:8080 --leader
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
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	var (
		addr            = flag.String("addr", ":8081", "HTTP listen address")
		registryURL     = flag.String("registry", "", "Registry URL for service discovery")
		measurementsURL = flag.String("measurements-url", "", "URL for allowed measurements")
		useTDX          = flag.Bool("tdx", false, "Use real TDX attestation")
		remoteTDXURL    = flag.String("tdx-url", "", "Remote TDX attestation service URL")
		isLeader        = flag.Bool("leader", false, "This server is the round leader")
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
	fmt.Printf("Server public key: %s\n", pubKey.String())
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
		ServiceType:               services.ServerService,
		RegistryURL:               *registryURL,
		SelfRegister:              false, // Admin registers servers
	}

	serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
	server, err := services.NewHTTPServer(config, serverID, signingKey, exchangeKey, *isLeader)
	if err != nil {
		fmt.Printf("Create server error: %v\n", err)
		os.Exit(1)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	server.RegisterRoutes(r)

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
		fmt.Printf("Server listening on %s (leader=%v)\n", *addr, *isLeader)
		fmt.Println("Registration data available at GET /registration-data")
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Server error: %v\n", err)
			os.Exit(1)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := server.Start(ctx); err != nil {
		fmt.Printf("Start error: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	fmt.Println("Shutting down server...")
	cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Shutdown error: %v\n", err)
	}
}
