package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPAggregator wraps the protocol AggregatorService with HTTP endpoints.
type HTTPAggregator struct {
	*baseService
	service *protocol.AggregatorService
}

// NewHTTPAggregator creates an aggregator service that registers with a central registry.
func NewHTTPAggregator(config *ServiceConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) (*HTTPAggregator, error) {
	config.ServiceType = AggregatorService
	base, err := newBaseService(config, signingKey, exchangeKey)
	if err != nil {
		return nil, err
	}

	service := protocol.NewAggregatorService(config.ADCNetConfig)

	return &HTTPAggregator{
		baseService: base,
		service:     service,
	}, nil
}

// RegisterRoutes registers HTTP routes for the aggregator.
func (a *HTTPAggregator) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/register", func(w http.ResponseWriter, r *http.Request) { a.handleRegister(w, r, a) })
	r.Post("/client-messages", a.handleClientMessages)
	r.Post("/aggregate-messages", a.handleAggregateMessages)
	r.Get("/aggregates/{round}", a.handleGetAggregates)
}

// Start registers with the central registry and begins service operations.
func (a *HTTPAggregator) Start(ctx context.Context) error {
	if err := a.registerWithRegistry(); err != nil {
		return fmt.Errorf("registry registration failed: %w", err)
	}

	a.roundCoord.Start(ctx)
	go a.handleRoundTransitions(ctx)
	go a.runDiscoveryLoop(ctx, a)

	return nil
}

func (a *HTTPAggregator) selfPublicKey() string {
	return a.publicKey().String()
}

func (a *HTTPAggregator) onServerDiscovered(signed *protocol.Signed[RegisteredService]) error {
	if err := a.verifyAndStoreServer(signed); err != nil {
		return err
	}
	return a.sendRegistrationDirectly(signed.Object.HTTPEndpoint)
}

func (a *HTTPAggregator) onAggregatorDiscovered(signed *protocol.Signed[RegisteredService]) error {
	return a.verifyAndStoreAggregator(signed)
}

func (a *HTTPAggregator) onClientDiscovered(signed *protocol.Signed[RegisteredService]) error {
	svc := signed.Object

	pubKey, err := svc.ParsePublicKey()
	if err != nil {
		return err
	}

	if err := a.service.RegisterClient(pubKey); err != nil {
		return err
	}

	return a.verifyAndStoreClient(signed)
}

func (a *HTTPAggregator) handleRoundTransitions(ctx context.Context) {
	roundChan := a.roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case round := <-roundChan:
			if round.Context == protocol.AggregatorRoundContext {
				a.sendAggregates()
			} else if round.Context == protocol.ServerPartialRoundContext {
				a.mu.Lock()
				a.currentRound = protocol.Round{Number: round.Number + 1, Context: protocol.ClientRoundContext}
				a.service.AdvanceToRound(a.currentRound)
				a.mu.Unlock()
			}
		}
	}
}

func (a *HTTPAggregator) sendAggregates() {
	a.mu.Lock()
	defer a.mu.Unlock()

	aggregate := a.service.CurrentAggregates()
	if aggregate == nil {
		return
	}

	servers := make([]*protocol.Signed[RegisteredService], 0, len(a.registry.Servers))
	for _, srv := range a.registry.Servers {
		servers = append(servers, srv)
	}

	for _, srv := range servers {
		if err := a.sendToServer(srv, aggregate); err != nil {
			// Log but continue
			fmt.Printf("Failed to send to server %s: %v\n", srv.Object.HTTPEndpoint, err)
		}
	}
}

func (a *HTTPAggregator) sendToServer(srv *protocol.Signed[RegisteredService], agg *protocol.AggregatedClientMessages) error {
	signedMsg, err := protocol.NewSigned(a.signingKey, agg)
	if err != nil {
		return err
	}

	req := &AggregateMessageRequest{Message: signedMsg}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := a.httpClient.Post(srv.Object.HTTPEndpoint+"/aggregate", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return nil
}

func (a *HTTPAggregator) handleClientMessages(w http.ResponseWriter, r *http.Request) {
	var req ClientMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify all signatures BEFORE acquiring lock (DoS prevention)
	verified, err := protocol.VerifyClientMessages(req.Messages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify all signers are registered
	for _, v := range verified {
		if _, exists := a.registry.Clients[v.Signer.String()]; !exists {
			http.Error(w, "client not registered or not attested", http.StatusForbidden)
			return
		}
	}

	aggregate, err := a.service.ProcessVerifiedMessages(verified)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(aggregate); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *HTTPAggregator) handleAggregateMessages(w http.ResponseWriter, r *http.Request) {
	var req AggregateAggregatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify signatures before lock
	msgs := make([]*protocol.AggregatedClientMessages, 0, len(req.Messages))
	signers := make([]crypto.PublicKey, 0, len(req.Messages))
	for _, signedMsg := range req.Messages {
		msg, signer, err := signedMsg.Recover()
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
			return
		}
		msgs = append(msgs, msg)
		signers = append(signers, signer)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify all signers are registered aggregators
	for _, signer := range signers {
		if _, exists := a.registry.Aggregators[signer.String()]; !exists {
			http.Error(w, "aggregator not registered or not attested", http.StatusForbidden)
			return
		}
	}

	result, err := (&protocol.AggregatorMessager{Config: a.config.ADCNetConfig}).
		AggregateAggregates(a.currentRound.Number, msgs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

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

	if err := json.NewEncoder(w).Encode(currentAggregate); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// PublicKey returns the aggregator's signing public key.
func (a *HTTPAggregator) PublicKey() crypto.PublicKey {
	return a.publicKey()
}
