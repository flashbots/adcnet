package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPServer wraps the protocol ServerService with HTTP endpoints.
type HTTPServer struct {
	config     *ServiceConfig
	service    *protocol.ServerService
	roundCoord *protocol.LocalRoundCoordinator
	registry   *ServiceRegistry
	HttpClient *http.Client
	isLeader   bool

	signingKey  crypto.PrivateKey
	exchangeKey *ecdh.PrivateKey

	mu                       sync.RWMutex
	currentRound             protocol.Round
	currentPartialDecryption *protocol.ServerPartialDecryptionMessage
	roundBroadcasts          map[int]*protocol.RoundBroadcast
}

// NewHTTPServer creates a new HTTP-based server service.
func NewHTTPServer(config *ServiceConfig, serverID protocol.ServerID, signingKey crypto.PrivateKey,
	exchangeKey *ecdh.PrivateKey, isLeader bool) (*HTTPServer, error) {

	service := protocol.NewServerService(config.ADCNetConfig, serverID, signingKey, exchangeKey)
	roundCoord := protocol.NewLocalRoundCoordinator(config.RoundDuration)

	return &HTTPServer{
		config:          config,
		service:         service,
		roundCoord:      roundCoord,
		registry:        NewServiceRegistry(),
		HttpClient:      &http.Client{},
		isLeader:        isLeader,
		signingKey:      signingKey,
		exchangeKey:     exchangeKey,
		roundBroadcasts: make(map[int]*protocol.RoundBroadcast),
	}, nil
}

// RegisterRoutes registers HTTP routes for the server.
func (s *HTTPServer) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/register", s.handleRegister)
	r.Post("/aggregate", s.handleAggregate)
	r.Post("/partial-decryption", s.handlePartialDecryption)
	r.Get("/round-broadcast/{round}", s.handleGetRoundBroadcast)
}

// Start begins the server service.
func (s *HTTPServer) Start(ctx context.Context) error {
	s.roundCoord.Start(ctx)
	go s.handleRoundTransitions(ctx)
	return nil
}

// handleRoundTransitions processes round changes.
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
					s.currentPartialDecryption.OriginalAggregate.RoundNumber == round.Number {
					go s.sharePartialDecryption(s.currentPartialDecryption)
				}
				s.currentPartialDecryption = nil
			}
			s.mu.Unlock()
		}
	}
}

// handleRegister registers other servers and clients with this server.
func (s *HTTPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
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
	case ServerService:
		s.registry.Servers[req.ServiceID] = endpoint
		json.NewEncoder(w).Encode(&RegistrationResponse{Success: true})

	case ClientService:
		s.registry.Clients[req.ServiceID] = endpoint
		s.service.RegisterClient(signingPubkey, ecdhKey)
		json.NewEncoder(w).Encode(&RegistrationResponse{Success: true})

	default:
		http.Error(w, "invalid service type", http.StatusBadRequest)
	}
}

// handleAggregate receives aggregated messages from aggregators.
func (s *HTTPServer) handleAggregate(w http.ResponseWriter, r *http.Request) {
	var req AggregateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentRound.Context >= protocol.ServerPartialRoundContext {
		http.Error(w, "aggregate submitted too late in the round", http.StatusBadRequest)
		return
	}

	partial, err := s.service.ProcessAggregateMessage(req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.currentPartialDecryption = partial
	fmt.Printf("%s: processed aggregate\n", s.config.ServiceID)

	w.WriteHeader(http.StatusOK)
}

// handlePartialDecryption receives partial decryptions from other servers.
// Once all servers have contributed, the leader reconstructs the final broadcast.
func (s *HTTPServer) handlePartialDecryption(w http.ResponseWriter, r *http.Request) {
	var req PartialDecryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.roundBroadcasts[s.currentRound.Number] != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	broadcast, err := s.service.ProcessPartialDecryptionMessage(req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if broadcast != nil {
		fmt.Printf("%s (isLeader=%v): recovered broadcast\n", s.config.ServiceID, s.isLeader)
		s.roundBroadcasts[broadcast.RoundNumber] = broadcast

		if s.isLeader {
			go s.shareBroadcast(broadcast)
		}
	}

	json.NewEncoder(w).Encode(&RoundBroadcastResponse{Broadcast: broadcast})
}

// handleGetRoundBroadcast returns the broadcast for a specific round.
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

// sharePartialDecryption shares this server's XOR blinding contribution with other servers.
func (s *HTTPServer) sharePartialDecryption(partial *protocol.ServerPartialDecryptionMessage) {
	req := &PartialDecryptionRequest{Message: partial}
	body, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("Server %s: error marshaling partial decryption: %v\n",
			s.config.ServiceID, err)
		return
	}

	s.mu.RLock()
	servers := make([]*ServiceEndpoint, 0, len(s.registry.Servers))
	for _, srv := range s.registry.Servers {
		servers = append(servers, srv)
	}
	s.mu.RUnlock()

	for _, srv := range servers {
		resp, err := s.HttpClient.Post(
			fmt.Sprintf("%s/partial-decryption", srv.HTTPEndpoint),
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			fmt.Printf("Server %s: error sending partial to %s: %v\n",
				s.config.ServiceID, srv.ServiceID, err)
			continue
		}
		resp.Body.Close()
	}
}

// shareBroadcast shares the round broadcast with all registered clients.
func (s *HTTPServer) shareBroadcast(broadcast *protocol.RoundBroadcast) {
	req := &RoundBroadcastResponse{Broadcast: broadcast}
	body, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("Server %s: error marshaling broadcast: %v\n",
			s.config.ServiceID, err)
		return
	}

	s.mu.RLock()
	clients := make([]*ServiceEndpoint, 0, len(s.registry.Clients))
	for _, client := range s.registry.Clients {
		clients = append(clients, client)
	}
	s.mu.RUnlock()

	for _, client := range clients {
		resp, err := s.HttpClient.Post(
			fmt.Sprintf("%s/round-broadcast", client.HTTPEndpoint),
			"application/json",
			bytes.NewReader(body),
		)
		if err != nil {
			fmt.Printf("Server %s: error sending broadcast to client %s: %v\n",
				s.config.ServiceID, client.ServiceID, err)
			continue
		}
		resp.Body.Close()
	}
	fmt.Printf("%s: sent broadcast for round %d to %d clients\n",
		s.config.ServiceID, broadcast.RoundNumber, len(clients))
}
