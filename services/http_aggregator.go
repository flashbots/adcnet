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

// HTTPAggregator wraps the protocol AggregatorService with HTTP endpoints and registry integration.
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

	r.Get("/registration-data", a.handleRegistrationData)
	r.Post("/exchange", a.handleSecretExchange)
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

func (a *HTTPAggregator) handleRegistrationData(w http.ResponseWriter, r *http.Request) {
	data, err := a.baseService.RegistrationData()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(data)
}

func (a *HTTPAggregator) selfPublicKey() string {
	return a.publicKey().String()
}

func (a *HTTPAggregator) onServerDiscovered(info *ServiceInfo) error {
	_, err := a.verifyAndStoreServer(info)
	return err
}

func (a *HTTPAggregator) onAggregatorDiscovered(info *ServiceInfo) error {
	_, err := a.verifyAndStoreAggregator(info)
	return err
}

func (a *HTTPAggregator) onClientDiscovered(info *ServiceInfo) error {
	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return err
	}

	if err := a.service.RegisterClient(pubKey); err != nil {
		return err
	}

	_, err = a.verifyAndStoreClient(info)
	return err
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

func (a *HTTPAggregator) sendAggregates() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	aggregate := a.service.CurrentAggregates()
	if aggregate == nil {
		return nil
	}

	servers := make([]*ServiceEndpoint, 0, len(a.registry.Servers))
	for _, srv := range a.registry.Servers {
		servers = append(servers, srv)
	}

	for _, srv := range servers {
		a.sendToServer(srv, aggregate)
	}

	return nil
}

func (a *HTTPAggregator) sendToServer(srv *ServiceEndpoint, agg *protocol.AggregatedClientMessages) error {
	signedMsg, err := protocol.NewSigned(a.signingKey, agg)
	if err != nil {
		return err
	}

	req := &AggregateMessageRequest{Message: signedMsg}
	body, _ := json.Marshal(req)

	resp, err := a.httpClient.Post(srv.HTTPEndpoint+"/aggregate", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return nil
}

func (a *HTTPAggregator) handleSecretExchange(w http.ResponseWriter, r *http.Request) {
	var signedReq protocol.Signed[SecretExchangeRequest]
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req, signer, err := signedReq.Recover()
	if err != nil {
		http.Error(w, fmt.Errorf("invalid signature: %w", err).Error(), http.StatusForbidden)
		return
	}

	if signer.String() != req.PublicKey {
		http.Error(w, "signer does not match claimed public key", http.StatusForbidden)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	switch req.ServiceType {
	case ClientService:
		registered, exists := a.registry.Clients[req.PublicKey]
		if !exists {
			http.Error(w, "client not found in registry", http.StatusForbidden)
			return
		}
		if registered.ExchangeKey != req.ExchangeKey {
			http.Error(w, "exchange key mismatch with attested key", http.StatusForbidden)
			return
		}

		pubKey, _ := crypto.NewPublicKeyFromString(req.PublicKey)
		if err := a.service.RegisterClient(pubKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case ServerService:
		registered, exists := a.registry.Servers[req.PublicKey]
		if !exists {
			http.Error(w, "server not found in registry", http.StatusForbidden)
			return
		}
		if registered.ExchangeKey != req.ExchangeKey {
			http.Error(w, "exchange key mismatch with attested key", http.StatusForbidden)
			return
		}

	default:
		http.Error(w, "unsupported service type", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(&SecretExchangeResponse{Success: true})
}

func (a *HTTPAggregator) handleClientMessages(w http.ResponseWriter, r *http.Request) {
	var req ClientMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, msg := range req.Messages {
		_, signer, err := msg.Recover()
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
			return
		}
		if _, exists := a.registry.Clients[signer.String()]; !exists {
			http.Error(w, "client not registered or not attested", http.StatusForbidden)
			return
		}
	}

	aggregate, err := a.service.ProcessClientMessages(req.Messages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(aggregate)
}

func (a *HTTPAggregator) handleAggregateMessages(w http.ResponseWriter, r *http.Request) {
	var req AggregateAggregatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	msgs := make([]*protocol.AggregatedClientMessages, 0, len(req.Messages))
	for _, signedMsg := range req.Messages {
		msg, signer, err := signedMsg.Recover()
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
			return
		}
		if _, exists := a.registry.Aggregators[signer.String()]; !exists {
			http.Error(w, "aggregator not registered or not attested", http.StatusForbidden)
			return
		}
		msgs = append(msgs, msg)
	}

	result, err := (&protocol.AggregatorMessager{Config: a.config.ADCNetConfig}).
		AggregateAggregates(int(a.currentRound.Number), msgs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
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

	json.NewEncoder(w).Encode(currentAggregate)
}

// PublicKey returns the aggregator's signing public key.
func (a *HTTPAggregator) PublicKey() crypto.PublicKey {
	return a.publicKey()
}
