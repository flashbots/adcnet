package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPClient wraps the protocol ClientService with HTTP endpoints.
type HTTPClient struct {
	config     *ServiceConfig
	service    *protocol.ClientService
	roundCoord *protocol.LocalRoundCoordinator
	registry   *ServiceRegistry
	HttpClient *http.Client

	signingKey  crypto.PrivateKey
	exchangeKey *ecdh.PrivateKey

	mu           sync.RWMutex
	currentRound protocol.Round
}

// NewHTTPClient creates a new HTTP-based client service.
func NewHTTPClient(config *ServiceConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) (*HTTPClient, error) {
	service := protocol.NewClientService(config.ADCNetConfig, signingKey, exchangeKey)
	roundCoord := protocol.NewLocalRoundCoordinator(config.RoundDuration)

	return &HTTPClient{
		config:      config,
		service:     service,
		roundCoord:  roundCoord,
		registry:    NewServiceRegistry(),
		HttpClient:  &http.Client{},
		signingKey:  signingKey,
		exchangeKey: exchangeKey,
	}, nil
}

// RegisterRoutes registers HTTP routes for the client.
func (c *HTTPClient) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/register", c.handleRegister)
	r.Post("/round-broadcast", c.handleRoundBroadcast)
}

// Start begins the client service.
func (c *HTTPClient) Start(ctx context.Context) error {
	c.roundCoord.Start(ctx)
	go c.handleRoundTransitions(ctx)
	return nil
}

// handleRoundTransitions processes round changes.
func (c *HTTPClient) handleRoundTransitions(ctx context.Context) {
	roundChan := c.roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case round := <-roundChan:
			if round.Context != protocol.ClientRoundContext {
				continue
			}

			c.mu.Lock()
			c.currentRound = round
			c.service.AdvanceToRound(round)

			// Generate test messages with some probability
			if rand.Float32() > 0.5 {
				msg := []byte(fmt.Sprintf("hello adcnet round %d from client %s!",
					round.Number, c.config.ServiceID))
				c.service.ScheduleMessageForNextRound(msg, 10)
			}

			c.mu.Unlock()

			if err := c.sendRoundMessages(); err != nil {
				fmt.Printf("Client %s: error sending round %d messages: %v\n",
					c.config.ServiceID, round.Number, err)
			}
		}
	}
}

// sendRoundMessages sends client messages to aggregators.
func (c *HTTPClient) sendRoundMessages() error {
	messages, _, err := c.service.MessagesForCurrentRound()
	if err != nil {
		return fmt.Errorf("get messages: %w", err)
	}

	req := &ClientMessageRequest{Messages: []*protocol.Signed[protocol.ClientRoundMessage]{messages}}

	c.mu.RLock()
	aggregators := make([]*ServiceEndpoint, 0, len(c.registry.Aggregators))
	for _, agg := range c.registry.Aggregators {
		aggregators = append(aggregators, agg)
	}
	c.mu.RUnlock()

	if len(aggregators) > 0 {
		agg := aggregators[rand.Int()%len(aggregators)]
		if err := c.sendToAggregator(agg, req); err != nil {
			return fmt.Errorf("send to aggregator %s: %w", agg.ServiceID, err)
		}
		fmt.Printf("%s: sent message for round %d to %s\n",
			c.config.ServiceID, c.currentRound.Number, agg.ServiceID)
	}

	return nil
}

// sendToAggregator sends messages to a specific aggregator.
func (c *HTTPClient) sendToAggregator(agg *ServiceEndpoint, req *ClientMessageRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.HttpClient.Post(
		fmt.Sprintf("%s/client-messages", agg.HTTPEndpoint),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aggregator returned status %d", resp.StatusCode)
	}

	return nil
}

// handleRegister registers the client with servers and aggregators.
func (c *HTTPClient) handleRegister(w http.ResponseWriter, r *http.Request) {
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

	c.mu.Lock()
	defer c.mu.Unlock()

	switch req.ServiceType {
	case ServerService:
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

		serverID := protocol.ServerID(crypto.PublicKeyToServerID(signingPubkey))
		if err := c.service.RegisterServer(serverID, ecdhKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("%s: registered %s\n", c.config.ServiceID, req.ServiceID)
		c.registry.Servers[req.ServiceID] = endpoint

	case AggregatorService:
		c.registry.Aggregators[req.ServiceID] = endpoint
		fmt.Printf("%s: registered %s\n", c.config.ServiceID, req.ServiceID)

	default:
		http.Error(w, "invalid service type", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(&RegistrationResponse{Success: true})
}

// handleRoundBroadcast receives round broadcast results from servers.
func (c *HTTPClient) handleRoundBroadcast(w http.ResponseWriter, r *http.Request) {
	var req RoundBroadcastResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := c.service.ProcessRoundBroadcast(req.Broadcast); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%s: processed round %d broadcast\n",
		c.config.ServiceID, req.Broadcast.RoundNumber)

	w.WriteHeader(http.StatusOK)
}
