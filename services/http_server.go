package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// RoundOutputCallback is invoked when a round broadcast is finalized.
type RoundOutputCallback func(*protocol.RoundBroadcast)

// HTTPServer wraps the protocol ServerService with HTTP endpoints.
type HTTPServer struct {
	*baseService
	service  *protocol.ServerService
	isLeader bool

	currentPartialDecryption *protocol.Signed[protocol.ServerPartialDecryptionMessage]
	roundBroadcasts          map[int]*protocol.Signed[protocol.RoundBroadcast]
	roundOutputCallback      RoundOutputCallback
}

// NewHTTPServer creates a server service that registers with a central registry.
func NewHTTPServer(config *ServiceConfig, serverID protocol.ServerID, signingKey crypto.PrivateKey,
	exchangeKey *ecdh.PrivateKey, isLeader bool) (*HTTPServer, error) {

	config.ServiceType = ServerService
	base, err := newBaseService(config, signingKey, exchangeKey)
	if err != nil {
		return nil, err
	}

	service := protocol.NewServerService(config.ADCNetConfig, serverID, signingKey, exchangeKey)

	return &HTTPServer{
		baseService:     base,
		service:         service,
		isLeader:        isLeader,
		roundBroadcasts: make(map[int]*protocol.Signed[protocol.RoundBroadcast]),
	}, nil
}

// SetRoundOutputCallback sets a callback invoked when rounds complete.
func (s *HTTPServer) SetRoundOutputCallback(cb RoundOutputCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roundOutputCallback = cb
}

// RegisterRoutes registers HTTP routes for the server.
func (s *HTTPServer) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/register", func(w http.ResponseWriter, r *http.Request) { s.handleRegister(w, r, s) })
	r.Post("/aggregate", s.handleAggregate)
	r.Post("/partial-decryption", s.handlePartialDecryption)
	r.Get("/round-broadcast/{round}", s.handleGetRoundBroadcast)
}

// Start registers with the central registry and begins service operations.
func (s *HTTPServer) Start(ctx context.Context) error {
	if err := s.registerWithRegistry(); err != nil {
		return fmt.Errorf("registry registration failed: %w", err)
	}

	s.roundCoord.Start(ctx)
	go s.handleRoundTransitions(ctx)
	go s.runDiscoveryLoop(ctx, s)

	return nil
}

func (s *HTTPServer) selfPublicKey() string {
	return s.publicKey().String()
}

func (s *HTTPServer) onServerDiscovered(signed *protocol.Signed[RegisteredService]) error {
	if err := s.verifyAndStoreServer(signed); err != nil {
		return err
	}
	return s.sendRegistrationDirectly(signed.Object.HTTPEndpoint)
}

func (s *HTTPServer) onAggregatorDiscovered(signed *protocol.Signed[RegisteredService]) error {
	return s.verifyAndStoreAggregator(signed)
}

func (s *HTTPServer) onClientDiscovered(signed *protocol.Signed[RegisteredService]) error {
	svc := signed.Object

	pubKey, err := svc.ParsePublicKey()
	if err != nil {
		return err
	}

	ecdhKey, err := ParseExchangeKey(svc.ExchangeKey)
	if err != nil {
		return err
	}

	if err := s.verifyAndStoreClient(signed); err != nil {
		return err
	}

	return s.service.RegisterClient(pubKey, ecdhKey)
}

func (s *HTTPServer) handleRoundTransitions(ctx context.Context) {
	roundChan := s.roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case round := <-roundChan:
			s.mu.Lock()
			s.currentRound = round
			if round.Context == protocol.ClientRoundContext {
				s.service.AdvanceToRound(round)
			} else if round.Context == protocol.ServerPartialRoundContext {
				if s.currentPartialDecryption != nil &&
					s.currentPartialDecryption.UnsafeObject().OriginalAggregate.RoundNumber == round.Number {
					go s.sharePartialDecryption(s.currentPartialDecryption)
				}
				s.currentPartialDecryption = nil
			}
			s.mu.Unlock()
		}
	}
}

func (s *HTTPServer) handleAggregate(w http.ResponseWriter, r *http.Request) {
	var req AggregateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	msg, signer, err := req.Message.Recover()
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	currentRound := s.currentRound

	if currentRound.Context >= protocol.ServerPartialRoundContext {
		http.Error(w, "aggregate submitted too late", http.StatusBadRequest)
		return
	}

	if _, exists := s.registry.Aggregators[signer.String()]; !exists {
		http.Error(w, "aggregator not registered or not attested", http.StatusForbidden)
		return
	}

	partial, err := s.service.ProcessAggregateMessage(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signedPartial, err := protocol.NewSigned(s.signingKey, partial)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.currentPartialDecryption = signedPartial
	w.WriteHeader(http.StatusOK)
}

func (s *HTTPServer) handlePartialDecryption(w http.ResponseWriter, r *http.Request) {
	var req PartialDecryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	msg, signer, err := req.Message.Recover()
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	currentRound := s.currentRound

	if s.roundBroadcasts[currentRound.Number] != nil {
		if err := json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: s.roundBroadcasts[currentRound.Number]}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if _, exists := s.registry.Servers[signer.String()]; !exists {
		http.Error(w, "server not registered or not attested", http.StatusForbidden)
		return
	}

	broadcast, err := s.service.ProcessPartialDecryptionMessage(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var signedBroadcast *protocol.Signed[protocol.RoundBroadcast]
	if broadcast != nil {
		signedBroadcast, err = protocol.NewSigned(s.signingKey, broadcast)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.roundBroadcasts[broadcast.RoundNumber] = signedBroadcast

		if s.roundOutputCallback != nil {
			go s.roundOutputCallback(broadcast)
		}
	}

	if err := json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: signedBroadcast}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *HTTPServer) handleGetRoundBroadcast(w http.ResponseWriter, r *http.Request) {
	roundParam := chi.URLParam(r, "round")
	roundNumber, err := strconv.Atoi(roundParam)
	if err != nil {
		http.Error(w, "invalid round number", http.StatusBadRequest)
		return
	}

	var broadcast *protocol.Signed[protocol.RoundBroadcast]

	s.mu.RLock()
	if roundNumber == 0 {
		// Fetch latest
		var exists bool
		if broadcast, exists = s.roundBroadcasts[s.currentRound.Number]; !exists && s.currentRound.Number > 1 {
			broadcast = s.roundBroadcasts[s.currentRound.Number-1]
		}
	} else {
		broadcast = s.roundBroadcasts[roundNumber]
	}
	s.mu.RUnlock()

	if broadcast == nil {
		http.Error(w, "broadcast not available", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: broadcast}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *HTTPServer) sharePartialDecryption(partial *protocol.Signed[protocol.ServerPartialDecryptionMessage]) {
	req := &PartialDecryptionRequest{Message: partial}
	body, err := json.Marshal(req)
	if err != nil {
		return
	}

	s.mu.RLock()
	servers := make([]*protocol.Signed[RegisteredService], 0, len(s.registry.Servers))
	for _, srv := range s.registry.Servers {
		servers = append(servers, srv)
	}
	s.mu.RUnlock()

	for _, srv := range servers {
		resp, err := s.httpClient.Post(srv.Object.HTTPEndpoint+"/partial-decryption", "application/json", bytes.NewReader(body))
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}

// ServerID returns the server's unique identifier.
func (s *HTTPServer) ServerID() protocol.ServerID {
	return protocol.ServerID(crypto.PublicKeyToServerID(s.publicKey()))
}

// PublicKey returns the server's signing public key.
func (s *HTTPServer) PublicKey() crypto.PublicKey {
	return s.publicKey()
}
