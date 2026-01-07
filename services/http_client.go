package services

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPClient wraps the protocol ClientService with HTTP endpoints.
type HTTPClient struct {
	*baseService
	service *protocol.ClientService

	messageToSend *HTTPClientMessage
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
		baseService:   base,
		service:       service,
		messageToSend: nil,
	}, nil
}

// RegisterRoutes registers HTTP routes for the client.
func (c *HTTPClient) RegisterRoutes(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/message", c.handleMessage)
	r.Post("/encrypted-message", c.handleEncryptedMessage)
}

type HTTPClientMessage struct {
	// Note: no integrity guarantees for the message. Should be using authenticated encryption at the protcol level.
	Message []byte
	Value   int
}

func (c *HTTPClient) handleEncryptedMessage(w http.ResponseWriter, r *http.Request) {
	var cipherReq crypto.EncryptedMessage
	if err := json.NewDecoder(r.Body).Decode(&cipherReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plaintextMsg, err := crypto.Decrypt(c.exchangeKey, &cipherReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var msg HTTPClientMessage
	if err := json.NewDecoder(bytes.NewBuffer(plaintextMsg)).Decode(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	if c.messageToSend != nil {
		c.mu.Unlock()
		http.Error(w, "message already scheduled", http.StatusBadRequest)
		return
	}
	c.messageToSend = &msg
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (c *HTTPClient) handleMessage(w http.ResponseWriter, r *http.Request) {
	var msg HTTPClientMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	if c.messageToSend != nil {
		c.mu.Unlock()
		http.Error(w, "message already scheduled", http.StatusBadRequest)
		return
	}
	c.messageToSend = &msg
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
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

func (c *HTTPClient) onServerDiscovered(signed *protocol.Signed[RegisteredService]) error {
	svc := signed.Object

	pubKey, err := svc.ParsePublicKey()
	if err != nil {
		return err
	}

	ecdhKey, err := ParseExchangeKey(svc.ExchangeKey)
	if err != nil {
		return err
	}

	serverID := protocol.ServerID(crypto.PublicKeyToServerID(pubKey))
	if err := c.service.RegisterServer(serverID, ecdhKey); err != nil {
		return err
	}

	if err := c.verifyAndStoreServer(signed); err != nil {
		return err
	}

	return c.sendRegistrationDirectly(svc.HTTPEndpoint)
}

func (c *HTTPClient) onAggregatorDiscovered(signed *protocol.Signed[RegisteredService]) error {
	if err := c.verifyAndStoreAggregator(signed); err != nil {
		return err
	}
	return c.sendRegistrationDirectly(signed.Object.HTTPEndpoint)
}

func (c *HTTPClient) onClientDiscovered(signed *protocol.Signed[RegisteredService]) error {
	return nil
}

func (c *HTTPClient) handleRoundTransitions(ctx context.Context) {
	roundChan := c.roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case round := <-roundChan:
			// Poll for previous round's broadcast when entering client phase
			if round.Context == protocol.ClientRoundContext && round.Number > 1 {
				c.pollRoundBroadcast(round.Number - 1)
			}

			if round.Context != protocol.ClientRoundContext {
				continue
			}

			c.mu.Lock()
			c.currentRound = round
			c.service.AdvanceToRound(round)
			if c.messageToSend != nil {
				err := c.service.ScheduleMessageForNextRound(c.messageToSend.Message, uint32(c.messageToSend.Value))
				c.messageToSend = nil
				if err != nil {
					c.mu.Unlock()
					fmt.Printf("could not schedule message: %v\n", err)
					return
				}
			}
			c.mu.Unlock()

			if err := c.sendRoundMessages(); err != nil {
				fmt.Printf("Failed to send round messages: %v\n", err)
			}
		}
	}
}

// pollRoundBroadcast fetches the broadcast for a completed round from any available server.
func (c *HTTPClient) pollRoundBroadcast(roundNumber int) {
	c.mu.RLock()
	servers := make([]*protocol.Signed[RegisteredService], 0, len(c.registry.Servers))
	for _, srv := range c.registry.Servers {
		servers = append(servers, srv)
	}
	c.mu.RUnlock()

	if len(servers) == 0 {
		return
	}

	for _, srv := range servers {
		// TODO: should poll the leader
		url := fmt.Sprintf("%s/round-broadcast/%d", srv.Object.HTTPEndpoint, roundNumber)
		resp, err := c.httpClient.Get(url)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var broadcastResp RoundBroadcastResponse
		if err := json.NewDecoder(resp.Body).Decode(&broadcastResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		if broadcastResp.Broadcast == nil {
			continue
		}

		broadcast, signer, err := broadcastResp.Broadcast.Recover()
		if err != nil {
			continue
		}

		c.mu.Lock()
		if _, exists := c.registry.Servers[signer.String()]; !exists {
			c.mu.Unlock()
			continue
		}

		if err := c.service.ProcessRoundBroadcast(broadcast); err != nil {
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		return
	}
}

func (c *HTTPClient) sendRoundMessages() error {
	messages, _, err := c.service.MessagesForCurrentRound()
	if err != nil {
		return err
	}

	req := &ClientMessageRequest{Messages: []*protocol.Signed[protocol.ClientRoundMessage]{messages}}

	c.mu.RLock()
	aggregators := make([]*protocol.Signed[RegisteredService], 0, len(c.registry.Aggregators))
	for _, agg := range c.registry.Aggregators {
		aggregators = append(aggregators, agg)
	}
	c.mu.RUnlock()

	if len(aggregators) > 0 {
		agg := aggregators[rand.Int()%len(aggregators)]
		if err := c.sendToAggregator(agg, req); err != nil {
			return err
		}
	}

	return nil
}

func (c *HTTPClient) sendToAggregator(agg *protocol.Signed[RegisteredService], req *ClientMessageRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(agg.Object.HTTPEndpoint+"/client-messages", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aggregator returned status %d", resp.StatusCode)
	}
	return nil
}

// PublicKey returns the client's signing public key.
func (c *HTTPClient) PublicKey() crypto.PublicKey {
	return c.publicKey()
}
