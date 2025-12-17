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

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPClient wraps the protocol ClientService with HTTP endpoints and registry integration.
type HTTPClient struct {
	*baseService
	service *protocol.ClientService
}

// NewHTTPClient creates a client service that registers with a central registry.
func NewHTTPClient(config *ServiceConfig, signingKey crypto.PrivateKey, exchangeKey *ecdh.PrivateKey) (*HTTPClient, error) {
	config.ServiceType = ClientService
	base, err := newBaseService(config, signingKey, exchangeKey)
	if err != nil {
		return nil, err
	}

	service := protocol.NewClientService(config.ADCNetConfig, signingKey, exchangeKey)

	return &HTTPClient{
		baseService: base,
		service:     service,
	}, nil
}

// RegisterRoutes registers HTTP routes for the client.
func (c *HTTPClient) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/exchange", c.handleSecretExchange)
	r.Post("/round-broadcast", c.handleRoundBroadcast)
}

// Start registers with the central registry and begins service operations.
func (c *HTTPClient) Start(ctx context.Context) error {
	if err := c.registerWithRegistry(); err != nil {
		return fmt.Errorf("registry registration failed: %w", err)
	}

	c.roundCoord.Start(ctx)
	go c.handleRoundTransitions(ctx)
	go c.runDiscoveryLoop(ctx, c)

	return nil
}

func (c *HTTPClient) selfPublicKey() string {
	return c.publicKey().String()
}

func (c *HTTPClient) onServerDiscovered(info *ServiceInfo) error {
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

	serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
	if err := c.service.RegisterServer(serverID, ecdhKey); err != nil {
		return err
	}

	if _, err := c.verifyAndStoreServer(info); err != nil {
		return err
	}

	return c.sendSignedSecretExchange(info.HTTPEndpoint, ClientService)
}

func (c *HTTPClient) onAggregatorDiscovered(info *ServiceInfo) error {
	_, err := c.verifyAndStoreAggregator(info)
	return err
}

func (c *HTTPClient) onClientDiscovered(info *ServiceInfo) error {
	return nil
}

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

			pubKey := c.publicKey()
			if rand.Float32() > 0.5 {
				msg := []byte(fmt.Sprintf("hello adcnet round %d from %s!", round.Number, pubKey.String()[:16]))
				c.service.ScheduleMessageForNextRound(msg, 10)
			}
			c.mu.Unlock()

			c.sendRoundMessages()
		}
	}
}

func (c *HTTPClient) sendRoundMessages() error {
	messages, _, err := c.service.MessagesForCurrentRound()
	if err != nil {
		return err
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
		c.sendToAggregator(agg, req)
	}

	return nil
}

func (c *HTTPClient) sendToAggregator(agg *ServiceEndpoint, req *ClientMessageRequest) error {
	body, _ := json.Marshal(req)
	resp, err := c.httpClient.Post(agg.HTTPEndpoint+"/client-messages", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aggregator returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) handleSecretExchange(w http.ResponseWriter, r *http.Request) {
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

	c.mu.Lock()
	defer c.mu.Unlock()

	if req.ServiceType == ServerService {
		registered, exists := c.registry.Servers[req.PublicKey]
		if !exists {
			http.Error(w, "server not found in registry", http.StatusForbidden)
			return
		}
		if registered.ExchangeKey != req.ExchangeKey {
			http.Error(w, "exchange key mismatch with attested key", http.StatusForbidden)
			return
		}

		pubKey, _ := crypto.NewPublicKeyFromString(req.PublicKey)
		serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
		if err := c.service.RegisterServer(serverID, ecdhKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "unsupported service type", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(&SecretExchangeResponse{Success: true})
}

func (c *HTTPClient) handleRoundBroadcast(w http.ResponseWriter, r *http.Request) {
	var req RoundBroadcastResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Broadcast == nil {
		http.Error(w, "missing broadcast", http.StatusBadRequest)
		return
	}

	broadcast, signer, err := req.Broadcast.Recover()
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid signature: %v", err), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.registry.Servers[signer.String()]; !exists {
		http.Error(w, "server not registered or not attested", http.StatusForbidden)
		return
	}

	if err := c.service.ProcessRoundBroadcast(broadcast); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// PublicKey returns the client's signing public key.
func (c *HTTPClient) PublicKey() crypto.PublicKey {
	return c.publicKey()
}
