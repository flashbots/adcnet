package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
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
}

// Orchestrator manages ADCNet deployment.
type Orchestrator struct {
	config    *OrchestratorConfig
	adcConfig *protocol.ADCNetConfig

	clients     []*DeployedService
	aggregators []*DeployedService
	servers     []*DeployedService

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

	return &Orchestrator{
		config:    config,
		adcConfig: adcConfig,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Deploy starts all services and establishes connections.
func (o *Orchestrator) Deploy() error {
	fmt.Println("Starting ADCNet deployment...")

	if err := o.deployServers(); err != nil {
		return fmt.Errorf("deploy servers: %w", err)
	}

	if err := o.deployAggregators(); err != nil {
		return fmt.Errorf("deploy aggregators: %w", err)
	}

	if err := o.deployClients(); err != nil {
		return fmt.Errorf("deploy clients: %w", err)
	}

	if err := o.registerServices(); err != nil {
		return fmt.Errorf("register services: %w", err)
	}

	fmt.Printf("Deployment complete: %d clients, %d aggregators, %d servers\n",
		len(o.clients), len(o.aggregators), len(o.servers))

	return nil
}

// deployServers creates and starts server instances.
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

// deployAggregators creates and starts aggregator instances.
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

// deployClients creates and starts client instances.
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

// deployService creates and starts a single service instance.
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
	config := &services.ServiceConfig{
		ADCNetConfig:  o.adcConfig,
		HTTPAddr:      addr,
		ServiceID:     serviceID,
		ServiceType:   serviceType,
		RoundDuration: o.config.RoundDuration,
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
			return nil, err
		}
		client.RegisterRoutes(r)
		service.Client = client

	case services.AggregatorService:
		aggregator, err := services.NewHTTPAggregator(config)
		if err != nil {
			return nil, err
		}
		aggregator.RegisterRoutes(r)
		service.Aggregator = aggregator

	case services.ServerService:
		serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
		server, err := services.NewHTTPServer(config, serverID, privKey, exchangeKey, isLeader)
		if err != nil {
			return nil, err
		}
		server.RegisterRoutes(r)
		service.Server = server
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

	switch serviceType {
	case services.ClientService:
		service.Client.Start(o.ctx)
	case services.AggregatorService:
		service.Aggregator.Start(o.ctx)
	case services.ServerService:
		service.Server.Start(o.ctx)
	}

	time.Sleep(100 * time.Millisecond)

	return service, nil
}

// registerServices establishes connections between services.
func (o *Orchestrator) registerServices() error {
	for _, client := range o.clients {
		for _, server := range o.servers {
			if err := o.registerService(client, server); err != nil {
				return fmt.Errorf("register client %s with server %s: %w",
					client.ServiceID, server.ServiceID, err)
			}
			if err := o.registerService(server, client); err != nil {
				return fmt.Errorf("register server %s with client %s: %w",
					server.ServiceID, client.ServiceID, err)
			}
		}

		for _, agg := range o.aggregators {
			if err := o.registerService(client, agg); err != nil {
				return fmt.Errorf("register client %s with aggregator %s: %w",
					client.ServiceID, agg.ServiceID, err)
			}
			if err := o.registerService(agg, client); err != nil {
				return fmt.Errorf("register aggregator %s with client %s: %w",
					agg.ServiceID, client.ServiceID, err)
			}
		}
	}

	for _, agg := range o.aggregators {
		for _, server := range o.servers {
			if err := o.registerService(agg, server); err != nil {
				return fmt.Errorf("register aggregator %s with server %s: %w",
					agg.ServiceID, server.ServiceID, err)
			}
			if err := o.registerService(server, agg); err != nil {
				return fmt.Errorf("register server %s with aggregator %s: %w",
					server.ServiceID, agg.ServiceID, err)
			}
		}
	}

	for _, s1 := range o.servers {
		for _, s2 := range o.servers {
			if s1.ServiceID != s2.ServiceID {
				if err := o.registerService(s1, s2); err != nil {
					return fmt.Errorf("register server %s with server %s: %w",
						s1.ServiceID, s2.ServiceID, err)
				}
			}
		}
	}

	return nil
}

// registerService registers one service with another.
func (o *Orchestrator) registerService(from, to *DeployedService) error {
	req := &services.RegistrationRequest{
		ServiceID:    from.ServiceID,
		ServiceType:  from.ServiceType,
		PublicKey:    from.PublicKey.String(),
		ExchangeKey:  hex.EncodeToString(from.ExchangePubKey),
		HTTPEndpoint: from.HTTPAddr,
	}

	if from.Client != nil {
		return o.postJSON(from.Client.HttpClient, to.HTTPAddr+"/register", req)
	} else if from.Aggregator != nil {
		return o.postJSON(from.Aggregator.HttpClient, to.HTTPAddr+"/register", req)
	} else if from.Server != nil {
		return o.postJSON(from.Server.HttpClient, to.HTTPAddr+"/register", req)
	}

	return fmt.Errorf("no HTTP client available")
}

// postJSON sends a JSON POST request.
func (o *Orchestrator) postJSON(client *http.Client, url string, data interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Shutdown stops all services.
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
		if err := svc.HTTPServer.Shutdown(ctx); err != nil {
			fmt.Printf("Error shutting down %s: %v\n", svc.ServiceID, err)
		}
	}

	return nil
}
