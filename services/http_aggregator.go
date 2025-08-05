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
	httpClient *http.Client

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
		httpClient: &http.Client{},
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
	// Start round coordinator
	a.roundCoord.Start(ctx)

	// Subscribe to round transitions
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
				// Send aggregates to servers
				// NOTE: we can send smaler batches without ending for the context change (additive), to increase bandwidth
				if err := a.sendAggregates(); err != nil {
					fmt.Printf("Aggregator %s: error sending round %d aggregates: %v\n",
						a.config.ServiceID, round.Number, err)
				}
			} else if round.Context == protocol.ServerPartialRoundContext {
				// Start accepting messages for next round
				a.mu.Lock()
				a.currentRound = protocol.Round{Number: round.Number + 1, Context: protocol.ClientRoundContext}
				a.service.AdvanceToRound(a.currentRound)
				a.mu.Unlock()
			}
		}
	}
}

// sendAggregates sends aggregated messages to servers.
func (a *HTTPAggregator) sendAggregates() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	servers := make([]*ServiceEndpoint, 0, len(a.registry.Servers))
	for _, srv := range a.registry.Servers {
		servers = append(servers, srv)
	}

	// Send each aggregate to its target server
	aggregates := a.service.CurrentAggregates()
	for _, agg := range aggregates {
		for _, srv := range servers {
			// Find matching server by ID
			if protocol.ServerID(crypto.PublicKeyToServerID(srv.PublicKey)) == agg.ServerID {
				if err := a.sendToServer(srv, agg); err != nil {
					return fmt.Errorf("send to server %s: %w", srv.ServiceID, err)
				}
				fmt.Printf("%s: sent aggregate for round %d to %s\n", a.config.ServiceID, a.currentRound.Number, srv.ServiceID)
				break
			}
		}
	}

	fmt.Printf("%s: sent aggregates %d to %d servers\n", a.config.ServiceID, len(aggregates), len(servers))

	return nil
}

// sendToServer sends an aggregate to a specific server.
func (a *HTTPAggregator) sendToServer(srv *ServiceEndpoint, agg *protocol.AggregatedClientMessages) error {
	req := &AggregateMessageRequest{Message: agg}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := a.httpClient.Post(
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

	aggregates, err := a.service.ProcessClientMessages(req.Messages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%s: processed %d client messages for round %d and stored %d aggregates\n", a.config.ServiceID, len(req.Messages), a.currentRound.Number, len(aggregates))

	json.NewEncoder(w).Encode(aggregates)
}

// handleAggregateMessages receives messages from other aggregators.
func (a *HTTPAggregator) handleAggregateMessages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Messages []*protocol.AggregatedClientMessages `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Process hierarchical aggregation
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

	if currentAggregate != nil && fmt.Sprintf("%d", currentAggregate[0].RoundNumber) != round {
		http.Error(w, "current aggregate is for a different round than supplied", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(currentAggregate)
}
