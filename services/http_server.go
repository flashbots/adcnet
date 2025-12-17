package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// RoundOutputCallback is invoked when a round broadcast is finalized.
type RoundOutputCallback func(*protocol.RoundBroadcast)

// HTTPServer wraps the protocol ServerService with HTTP endpoints and registry integration.
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

	r.Get("/registration-data", s.handleRegistrationData)
	r.Post("/exchange", s.handleSecretExchange)
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

func (s *HTTPServer) handleRegistrationData(w http.ResponseWriter, r *http.Request) {
	data, err := s.baseService.RegistrationData()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(data)
}

func (s *HTTPServer) selfPublicKey() string {
	return s.publicKey().String()
}

func (s *HTTPServer) onServerDiscovered(info *ServiceInfo) error {
	_, err := s.verifyAndStoreServer(info)
	return err
}

func (s *HTTPServer) onAggregatorDiscovered(info *ServiceInfo) error {
	_, err := s.verifyAndStoreAggregator(info)
	return err
}

func (s *HTTPServer) onClientDiscovered(info *ServiceInfo) error {
	pubKey, err := crypto.NewPublicKeyFromString(info.PublicKey)
	if err != nil {
		return err
	}

	keyBytes, err := hex.DecodeString(info.ExchangeKey)
	if err != nil {
		return err
	}

	ecdhKey, err := ecdh.P256().NewPublicKey(keyBytes)
	if err != nil {
		return err
	}

	if err := s.service.RegisterClient(pubKey, ecdhKey); err != nil {
		return err
	}

	_, err = s.verifyAndStoreClient(info)
	return err
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

func (s *HTTPServer) handleSecretExchange(w http.ResponseWriter, r *http.Request) {
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

	keyBytes, err := hex.DecodeString(req.ExchangeKey)
	if err != nil {
		http.Error(w, "invalid exchange key", http.StatusBadRequest)
		return
	}

	ecdhKey, err := ecdh.P256().NewPublicKey(keyBytes)
	if err != nil {
		http.Error(w, "invalid ECDH key", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.ServiceType {
	case ClientService:
		registered, exists := s.registry.Clients[req.PublicKey]
		if !exists {
			http.Error(w, "client not found in registry", http.StatusForbidden)
			return
		}
		if registered.ExchangeKey != req.ExchangeKey {
			http.Error(w, "exchange key mismatch with attested key", http.StatusForbidden)
			return
		}

		pubKey, _ := crypto.NewPublicKeyFromString(req.PublicKey)
		if err := s.service.RegisterClient(pubKey, ecdhKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case ServerService:
		registered, exists := s.registry.Servers[req.PublicKey]
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

func (s *HTTPServer) handleAggregate(w http.ResponseWriter, r *http.Request) {
	var req AggregateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentRound.Context >= protocol.ServerPartialRoundContext {
		http.Error(w, "aggregate submitted too late", http.StatusBadRequest)
		return
	}

	msg, signer, err := req.Message.Recover()
	if err != nil {
		http.Error(w, fmt.Errorf("could not recover signature: %w", err).Error(), http.StatusBadRequest)
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

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.roundBroadcasts[s.currentRound.Number] != nil {
		json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: s.roundBroadcasts[s.currentRound.Number]})
		return
	}

	msg, signer, err := req.Message.Recover()
	if err != nil {
		http.Error(w, fmt.Errorf("could not recover signature: %w", err).Error(), http.StatusBadRequest)
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

		// Invoke callback for round output monitoring
		if s.roundOutputCallback != nil {
			go s.roundOutputCallback(broadcast)
		}

		if s.isLeader {
			go s.shareBroadcast(signedBroadcast)
		}
	}

	json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: signedBroadcast})
}

func (s *HTTPServer) handleGetRoundBroadcast(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	broadcast := s.roundBroadcasts[s.currentRound.Number]
	s.mu.RUnlock()

	if broadcast == nil {
		http.Error(w, "broadcast not available", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: broadcast})
}

func (s *HTTPServer) sharePartialDecryption(partial *protocol.Signed[protocol.ServerPartialDecryptionMessage]) {
	req := &PartialDecryptionRequest{Message: partial}
	body, _ := json.Marshal(req)

	s.mu.RLock()
	servers := make([]*ServiceEndpoint, 0, len(s.registry.Servers))
	for _, srv := range s.registry.Servers {
		servers = append(servers, srv)
	}
	s.mu.RUnlock()

	for _, srv := range servers {
		resp, err := s.httpClient.Post(srv.HTTPEndpoint+"/partial-decryption", "application/json", bytes.NewReader(body))
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}

func (s *HTTPServer) shareBroadcast(broadcast *protocol.Signed[protocol.RoundBroadcast]) {
	req := &RoundBroadcastResponse{Broadcast: broadcast}
	body, _ := json.Marshal(req)

	s.mu.RLock()
	clients := make([]*ServiceEndpoint, 0, len(s.registry.Clients))
	for _, c := range s.registry.Clients {
		clients = append(clients, c)
	}
	s.mu.RUnlock()

	for _, client := range clients {
		resp, err := s.httpClient.Post(client.HTTPEndpoint+"/round-broadcast", "application/json", bytes.NewReader(body))
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
