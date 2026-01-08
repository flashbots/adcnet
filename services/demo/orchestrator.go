package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"sync"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/flashbots/adcnet/tdx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// OrchestratorConfig contains deployment configuration.
type OrchestratorConfig struct {
	NumClients     int
	NumAggregators int
	NumServers     int

	BasePort      int
	RoundDuration time.Duration
	MessageLength int
	AuctionSlots  uint32

	UseTDX          bool
	RemoteTDXURL    string
	MeasurementsURL string
	AdminToken      string
}

// RoundOutput captures the broadcast result for a round.
type RoundOutput struct {
	RoundNumber   int
	MessageVector []byte
	AuctionVector *blind_auction.IBFVector
	Timestamp     time.Time
}

// Orchestrator manages ADCNet deployment with a centralized registry.
type Orchestrator struct {
	config              *OrchestratorConfig
	adcConfig           *protocol.ADCNetConfig
	attestationProvider services.TEEProvider
	measurementSource   services.MeasurementSource

	registry       *services.Registry
	registryServer *http.Server
	registryURL    string
	httpClient     *http.Client

	clients     []*DeployedService
	aggregators []*DeployedService
	servers     []*DeployedService

	outputMu     sync.RWMutex
	roundOutputs []RoundOutput
	outputChan   chan RoundOutput

	ctx    context.Context
	cancel context.CancelFunc
}

// DeployedService represents a running service instance.
type DeployedService struct {
	ServiceID   string
	ServiceType services.ServiceType
	HTTPAddr    string
	HTTPServer  *http.Server

	SigningKey     crypto.PrivateKey
	PublicKey      crypto.PublicKey
	ExchangeKey    *ecdh.PrivateKey
	ExchangePubKey []byte

	Client     *services.HTTPClient
	Aggregator *services.HTTPAggregator
	Server     *services.HTTPServer
}

// NewOrchestrator creates a deployment orchestrator.
func NewOrchestrator(config *OrchestratorConfig) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	adcConfig := &protocol.ADCNetConfig{
		AuctionSlots:    config.AuctionSlots,
		MessageLength:   config.MessageLength,
		MinClients:      uint32(config.NumClients),
		RoundDuration:   config.RoundDuration,
		RoundsPerWindow: 10,
	}

	var attestationProvider services.TEEProvider
	if config.UseTDX {
		if config.RemoteTDXURL != "" {
			attestationProvider = &tdx.RemoteDCAPProvider{
				URL:     config.RemoteTDXURL,
				Timeout: 30 * time.Second,
			}
		} else {
			attestationProvider = &tdx.TDXProvider{}
		}
	} else {
		attestationProvider = &tdx.DummyProvider{}
	}

	var measurementSource services.MeasurementSource
	if config.MeasurementsURL != "" {
		measurementSource = services.NewRemoteMeasurementSource(config.MeasurementsURL)
	} else {
		measurementSource = services.DemoMeasurementSource()
	}

	return &Orchestrator{
		config:              config,
		adcConfig:           adcConfig,
		attestationProvider: attestationProvider,
		measurementSource:   measurementSource,
		httpClient:          &http.Client{Timeout: 10 * time.Second},
		roundOutputs:        make([]RoundOutput, 0),
		outputChan:          make(chan RoundOutput, 100),
		ctx:                 ctx,
		cancel:              cancel,
	}
}

// Deploy starts the registry and all services.
func (o *Orchestrator) Deploy() error {
	fmt.Println("Starting ADCNet deployment...")

	if err := o.deployRegistry(); err != nil {
		return fmt.Errorf("deploy registry: %w", err)
	}

	if err := o.deployServers(); err != nil {
		return fmt.Errorf("deploy servers: %w", err)
	}

	if err := o.deployAggregators(); err != nil {
		return fmt.Errorf("deploy aggregators: %w", err)
	}

	if err := o.deployClients(); err != nil {
		return fmt.Errorf("deploy clients: %w", err)
	}

	go o.monitorRoundOutputs()

	fmt.Printf("Deployment complete: registry + %d clients, %d aggregators, %d servers\n",
		len(o.clients), len(o.aggregators), len(o.servers))

	return nil
}

func (o *Orchestrator) deployRegistry() error {
	registryPort := o.config.BasePort - 1
	registryAddr := fmt.Sprintf("localhost:%d", registryPort)
	o.registryURL = fmt.Sprintf("http://%s", registryAddr)

	registryConfig := &services.RegistryConfig{
		AttestationVerifier: o.attestationProvider,
		MeasurementSource:   o.measurementSource,
		AdminToken:          o.config.AdminToken,
	}
	var err error
	o.registry, err = services.NewRegistry(registryConfig, o.adcConfig)
	if err != nil {
		return err
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	o.registry.RegisterPublicRoutes(r)
	o.registry.RegisterAdminRoutes(r)

	o.registryServer = &http.Server{
		Addr:    registryAddr,
		Handler: r,
	}

	go func() {
		fmt.Printf("Starting registry on %s\n", registryAddr)
		if err := o.registryServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Registry error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

func (o *Orchestrator) deployServers() error {
	for i := 0; i < o.config.NumServers; i++ {
		service, err := o.deployService(
			fmt.Sprintf("server-%d", i),
			services.ServerService,
			o.config.BasePort+i,
			i == 0,
		)
		if err != nil {
			return err
		}
		o.servers = append(o.servers, service)
	}
	return nil
}

func (o *Orchestrator) deployAggregators() error {
	for i := 0; i < o.config.NumAggregators; i++ {
		service, err := o.deployService(
			fmt.Sprintf("aggregator-%d", i),
			services.AggregatorService,
			o.config.BasePort+o.config.NumServers+i,
			false,
		)
		if err != nil {
			return err
		}
		o.aggregators = append(o.aggregators, service)
	}
	return nil
}

func (o *Orchestrator) deployClients() error {
	for i := 0; i < o.config.NumClients; i++ {
		service, err := o.deployService(
			fmt.Sprintf("client-%d", i),
			services.ClientService,
			o.config.BasePort+o.config.NumServers+o.config.NumAggregators+i,
			false,
		)
		if err != nil {
			return err
		}
		o.clients = append(o.clients, service)
	}
	return nil
}

func (o *Orchestrator) deployService(serviceID string, serviceType services.ServiceType, port int, isLeader bool) (*DeployedService, error) {
	pubKey, privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate exchange key: %w", err)
	}

	addr := fmt.Sprintf("localhost:%d", port)

	// All services include admin token for self-registration
	// (clients use public endpoint, servers/aggregators use admin endpoint)
	config := &services.ServiceConfig{
		ADCNetConfig:              o.adcConfig,
		AttestationProvider:       o.attestationProvider,
		AllowedMeasurementsSource: o.measurementSource,
		HTTPAddr:                  addr,
		ServiceType:               serviceType,
		RegistryURL:               o.registryURL,
		AdminToken:                o.config.AdminToken,
	}

	service := &DeployedService{
		ServiceID:      serviceID,
		ServiceType:    serviceType,
		HTTPAddr:       fmt.Sprintf("http://%s", addr),
		SigningKey:     privKey,
		PublicKey:      pubKey,
		ExchangeKey:    exchangeKey,
		ExchangePubKey: exchangeKey.PublicKey().Bytes(),
	}

	r := chi.NewRouter()

	switch serviceType {
	case services.ClientService:
		client, err := services.NewHTTPClient(config, privKey, exchangeKey)
		if err != nil {
			return nil, fmt.Errorf("create client: %w", err)
		}
		client.RegisterRoutes(r)
		service.Client = client

	case services.AggregatorService:
		aggregator, err := services.NewHTTPAggregator(config, privKey, exchangeKey)
		if err != nil {
			return nil, fmt.Errorf("create aggregator: %w", err)
		}
		aggregator.RegisterRoutes(r)
		service.Aggregator = aggregator

	case services.ServerService:
		serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
		server, err := services.NewHTTPServer(config, serverID, privKey, exchangeKey, isLeader)
		if err != nil {
			return nil, fmt.Errorf("create server: %w", err)
		}
		server.RegisterRoutes(r)
		service.Server = server

		if isLeader {
			server.SetRoundOutputCallback(o.handleRoundOutput)
		}
	}

	service.HTTPServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		fmt.Printf("Starting %s %s on %s\n", serviceType, serviceID, addr)
		if err := service.HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("Service %s error: %v\n", serviceID, err)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Start the service (handles self-registration internally)
	switch serviceType {
	case services.ClientService:
		service.Client.Start(o.ctx)
	case services.AggregatorService:
		service.Aggregator.Start(o.ctx)
	case services.ServerService:
		service.Server.Start(o.ctx)
	}

	return service, nil
}

func (o *Orchestrator) handleRoundOutput(broadcast *protocol.RoundBroadcast) {
	output := RoundOutput{
		RoundNumber:   broadcast.RoundNumber,
		MessageVector: broadcast.MessageVector,
		AuctionVector: broadcast.AuctionVector,
		Timestamp:     time.Now(),
	}

	select {
	case o.outputChan <- output:
	default:
		fmt.Printf("Warning: round output channel full, dropping round %d\n", broadcast.RoundNumber)
	}
}

func (o *Orchestrator) monitorRoundOutputs() {
	for {
		select {
		case <-o.ctx.Done():
			return
		case output := <-o.outputChan:
			var previousRoundAuction *blind_auction.IBFVector = nil
			o.outputMu.Lock()
			if len(o.roundOutputs) > 0 {
				previousRoundAuction = o.roundOutputs[len(o.roundOutputs)-1].AuctionVector
			}
			o.roundOutputs = append(o.roundOutputs, output)
			o.outputMu.Unlock()

			o.printRoundOutput(previousRoundAuction, output)
		}
	}
}

func (o *Orchestrator) printRoundOutput(previousRoundAuction *blind_auction.IBFVector, output RoundOutput) {
	var tout string
	tout += fmt.Sprintf("=== Round %d ===\n", output.RoundNumber)
	tout += fmt.Sprintf("Timestamp: %s\n", output.Timestamp.Format(time.RFC3339))
	if previousRoundAuction == nil {
		tout += fmt.Sprintln("unknown schedule for previous round")
		tout += fmt.Sprintln("======================")
		return
	}

	auctionChunks, err := previousRoundAuction.Recover()
	if err != nil {
		tout += fmt.Sprintf("could not recover schedule: %s\n", err.Error())
		tout += "======================\n"
		return
	}

	recoveredAuctionData := make([]blind_auction.AuctionData, len(auctionChunks))
	for i := range recoveredAuctionData {
		recoveredAuctionData[i] = *blind_auction.AuctionDataFromChunk(auctionChunks[i])
	}

	auctionWinners := blind_auction.NewAuctionEngine(uint32(o.adcConfig.MessageLength), 1).RunAuction(recoveredAuctionData)

	messages := make([][]byte, len(auctionWinners))
	for i, scheduledBid := range auctionWinners {
		messages[i] = output.MessageVector[scheduledBid.SlotIdx : scheduledBid.SlotIdx+scheduledBid.SlotSize]
	}

	if len(messages) == 0 {
		tout += "No messages in this round\n"
	} else {
		tout += fmt.Sprintf("Messages found: %d\n", len(messages))
		for i, msg := range messages {
			if len(msg) > 100 {
				tout += fmt.Sprintf("  [%d] %s... (%d bytes)\n", i, string(msg[:100]), len(msg))
			} else {
				tout += fmt.Sprintf("  [%d] %s\n", i, string(msg))
			}
		}
	}
	tout += "======================\n"
	fmt.Print(tout)
}

// GetRoundOutputs returns all captured round outputs.
func (o *Orchestrator) GetRoundOutputs() []RoundOutput {
	o.outputMu.RLock()
	defer o.outputMu.RUnlock()
	result := make([]RoundOutput, len(o.roundOutputs))
	copy(result, o.roundOutputs)
	return result
}

// GetLatestRoundOutput returns the most recent round output.
func (o *Orchestrator) GetLatestRoundOutput() *RoundOutput {
	o.outputMu.RLock()
	defer o.outputMu.RUnlock()
	if len(o.roundOutputs) == 0 {
		return nil
	}
	output := o.roundOutputs[len(o.roundOutputs)-1]
	return &output
}

// SubscribeToRoundOutputs returns a channel that receives round outputs.
func (o *Orchestrator) SubscribeToRoundOutputs() <-chan RoundOutput {
	ch := make(chan RoundOutput, 10)
	go func() {
		for {
			select {
			case <-o.ctx.Done():
				close(ch)
				return
			case output := <-o.outputChan:
				o.outputMu.Lock()
				o.roundOutputs = append(o.roundOutputs, output)
				o.outputMu.Unlock()

				select {
				case ch <- output:
				default:
				}
			}
		}
	}()
	return ch
}

func (o *Orchestrator) SendMessages() {
	roundCoord := protocol.NewLocalRoundCoordinator(o.adcConfig.RoundDuration)
	roundCoord.Start(o.ctx)
	roundChan := roundCoord.SubscribeToRounds(o.ctx)

	for {
		select {
		case <-o.ctx.Done():
			return
		case round := <-roundChan:
			// Poll for previous round's broadcast when entering client phase
			if round.Context == protocol.ServerPartialRoundContext {
				o.SendMessageToRandomClients(4)
			}
		}
	}
}

func (o *Orchestrator) SendMessageToRandomClients(nClients int) error {
	clientsPerm := mrand.Perm(len(o.clients) - 1) // Reserve the last client for demo users

	for _, ic := range clientsPerm[0:nClients] {
		client := o.clients[ic]
		req := services.HTTPClientMessage{Message: []byte(fmt.Sprintf("Hello from %s!", client.PublicKey.String()[:16])), Value: 10}
		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("could not marshal message: %w", err)
		}

		resp, err := o.httpClient.Post(client.HTTPAddr+"/message", "application/json", bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("sending message failed (%d): %s", resp.StatusCode, string(respBody))
		}
	}
	return nil
}

// Shutdown stops all services and the registry.
func (o *Orchestrator) Shutdown() error {
	fmt.Println("Shutting down deployment...")
	o.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	allServices := make([]*DeployedService, 0, len(o.clients)+len(o.aggregators)+len(o.servers))
	allServices = append(allServices, o.clients...)
	allServices = append(allServices, o.aggregators...)
	allServices = append(allServices, o.servers...)

	for _, svc := range allServices {
		svc.HTTPServer.Shutdown(ctx)
	}

	if o.registryServer != nil {
		o.registryServer.Shutdown(ctx)
	}

	return nil
}
