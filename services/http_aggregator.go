package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPAggregator wraps the protocol AggregatorService with HTTP endpoints.
type HTTPAggregator struct {
	config     *ServiceConfig
	service    *protocol.AggregatorService
	roundCoord *protocol.LocalRoundCoordinator
	registry   *ServiceRegistry
	HttpClient *http.Client

	mu           sync.RWMutex
	currentRound protocol.Round
}

// NewHTTPAggregator creates a new HTTP-based aggregator service.
func NewHTTPAggregator(config *ServiceConfig) (*HTTPAggregator, error) {
	service := protocol.NewAggregatorService(config.ADCNetConfig)
	roundCoord := protocol.NewLocalRoundCoordinator(config.RoundDuration)

	return &HTTPAggregator{
		config:     config,
		service:    service,
		roundCoord: roundCoord,
		registry:   NewServiceRegistry(),
		HttpClient: &http.Client{},
	}, nil
}

// RegisterRoutes registers HTTP routes for the aggregator.
func (a *HTTPAggregator) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/register", a.handleRegister)
	r.Post("/client-messages", a.handleClientMessages)
	r.Post("/aggregate-messages", a.handleAggregateMessages)
	r.Get("/aggregates/{round}", a.handleGetAggregates)
}

// Start begins the aggregator service.
func (a *HTTPAggregator) Start(ctx context.Context) error {
	a.roundCoord.Start(ctx)
	go a.handleRoundTransitions(ctx)
	return nil
}

// handleRoundTransitions processes round changes.
func (a *HTTPAggregator) handleRoundTransitions(ctx context.Context) {
	roundChan := a.roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case round := <-roundChan:
			if round.Context == protocol.AggregatorRoundContext {
				if err := a.sendAggregates(); err != nil {
					fmt.Printf("Aggregator %s: error sending round %d aggregates: %v\n",
						a.config.ServiceID, round.Number, err)
				}
			} else if round.Context == protocol.ServerPartialRoundContext {
				a.mu.Lock()
				a.currentRound = protocol.Round{Number: round.Number + 1, Context: protocol.ClientRoundContext}
				a.service.AdvanceToRound(a.currentRound)
				a.mu.Unlock()
			}
		}
	}
}

// sendAggregates sends aggregated messages to all servers.
// All servers must receive the aggregate to remove their XOR blinding factors.
func (a *HTTPAggregator) sendAggregates() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	servers := make([]*ServiceEndpoint, 0, len(a.registry.Servers))
	for _, srv := range a.registry.Servers {
		servers = append(servers, srv)
	}

	aggregate := a.service.CurrentAggregates()
	if aggregate == nil {
		return nil
	}

	// Send aggregate to ALL servers since all must contribute their XOR blinding
	for _, srv := range servers {
		if err := a.sendToServer(srv, aggregate); err != nil {
			return fmt.Errorf("send to server %s: %w", srv.ServiceID, err)
		}
		fmt.Printf("%s: sent aggregate for round %d to %s\n",
			a.config.ServiceID, a.currentRound.Number, srv.ServiceID)
	}

	fmt.Printf("%s: sent aggregate to %d servers\n", a.config.ServiceID, len(servers))
	return nil
}

// sendToServer sends an aggregate to a specific server.
func (a *HTTPAggregator) sendToServer(srv *ServiceEndpoint, agg *protocol.AggregatedClientMessages) error {
	req := &AggregateMessageRequest{Message: agg}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := a.HttpClient.Post(
		fmt.Sprintf("%s/aggregate", srv.HTTPEndpoint),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

// handleRegister registers clients and servers with the aggregator.
func (a *HTTPAggregator) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signingPubkey, err := crypto.NewPublicKeyFromString(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid signing key", http.StatusBadRequest)
		return
	}

	endpoint := &ServiceEndpoint{
		ServiceID:    req.ServiceID,
		HTTPEndpoint: req.HTTPEndpoint,
		PublicKey:    signingPubkey,
		ExchangeKey:  req.ExchangeKey,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	switch req.ServiceType {
	case ClientService:
		if err := a.service.RegisterClient(signingPubkey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.registry.Clients[req.ServiceID] = endpoint

	case ServerService:
		a.registry.Servers[req.ServiceID] = endpoint

	default:
		http.Error(w, "invalid service type", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(&RegistrationResponse{Success: true})
}

// handleClientMessages receives messages from clients.
func (a *HTTPAggregator) handleClientMessages(w http.ResponseWriter, r *http.Request) {
	var req ClientMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("%s: processing client message\n", a.config.ServiceID)

	a.mu.Lock()
	defer a.mu.Unlock()

	aggregate, err := a.service.ProcessClientMessages(req.Messages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%s: processed %d client messages for round %d\n",
		a.config.ServiceID, len(req.Messages), a.currentRound.Number)

	json.NewEncoder(w).Encode(aggregate)
}

// handleAggregateMessages receives messages from other aggregators for hierarchical aggregation.
func (a *HTTPAggregator) handleAggregateMessages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Messages []*protocol.AggregatedClientMessages `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := (&protocol.AggregatorMessager{Config: a.config.ADCNetConfig}).
		AggregateAggregates(int(a.currentRound.Number), req.Messages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// handleGetAggregates returns aggregates for a specific round.
func (a *HTTPAggregator) handleGetAggregates(w http.ResponseWriter, r *http.Request) {
	round := chi.URLParam(r, "round")

	a.mu.Lock()
	defer a.mu.Unlock()

	currentAggregate := a.service.CurrentAggregates()
	if currentAggregate == nil {
		http.Error(w, "no aggregate available", http.StatusNotFound)
		return
	}

	if fmt.Sprintf("%d", currentAggregate.RoundNumber) != round {
		http.Error(w, "aggregate is for a different round", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(currentAggregate)
}
