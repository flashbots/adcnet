package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/zipnet"
)

type AggregatorHandler struct {
	Aggregator *AggregatorImpl
	transport  zipnet.NetworkTransport
	config     *zipnet.ZIPNetConfig

	// For managing background tasks
	ctx        context.Context
	cancelFunc context.CancelFunc
	running    bool
	runMutex   sync.Mutex

	// Round management
	mutex        sync.RWMutex
	roundStarted time.Time
	nextRoundAt  time.Time
}

func NewAggregatorHandler(Aggregator *AggregatorImpl, transport zipnet.NetworkTransport) *AggregatorHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &AggregatorHandler{
		Aggregator: Aggregator,
		transport:  transport,
		config:     Aggregator.config,
		ctx:        ctx,
		cancelFunc: cancel,
		running:    false,
	}
}

func (h *AggregatorHandler) RunInBackground() {
	h.runMutex.Lock()
	defer h.runMutex.Unlock()

	if h.running {
		log.Println("Aggregator handler background tasks already running")
		return
	}

	log.Println("Starting aggregator background tasks")
	h.running = true

	// Start the round processing worker
	go h.roundProcessingWorker()
}

// roundProcessingWorker manages the round lifecycle
func (h *AggregatorHandler) roundProcessingWorker() {
	var currentRound uint64 = zipnet.CurrentRound(h.Aggregator.config.RoundDuration)

	// Finalize halfway through the round
	var roundOffset time.Duration = time.Duration(h.Aggregator.config.RoundDuration.Milliseconds()/2) * time.Millisecond
	h.Aggregator.Reset(currentRound + 1)

	for {
		select {
		case <-h.ctx.Done():
			log.Println("Round processing worker stopped")
			return

		case <-time.After(time.Until(zipnet.RoundOffset(currentRound+1, h.Aggregator.config.RoundDuration, roundOffset))):
			currentRound = currentRound + 1
			h.finalizeRound(currentRound)
		}
	}
}

// finalizeRound aggregates and forwards messages for the current round and prepares for the next round
func (h *AggregatorHandler) finalizeRound(round uint64) {
	log.Printf("Finalizing round %d", round)

	// Create context with timeout for the finalization
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Aggregate messages for the current round
	aggregatedMsg, err := h.Aggregator.AggregateMessages(ctx, round)
	if err != nil {
		log.Printf("Failed to aggregate messages for round %d: %v", round, err)
		// Even if aggregation fails, move to the next round
	} else {
		// Forward the aggregate to the next level or servers
		if h.Aggregator.GetLevel()+1 == uint32(len(h.config.Aggregators)) {
			// This is the root aggregator, send to all anytrust servers
			for _, serverAddr := range h.config.AnytrustServers {
				err := h.transport.SendAggregateToServer(ctx, serverAddr, aggregatedMsg)
				if err != nil {
					log.Printf("Failed to send aggregate to server %s: %v", serverAddr, err)
				}
			}
		} else {
			// Send to the next level aggregator
			nextLevel := h.Aggregator.GetLevel() + 1
			for i, aggAddr := range h.config.Aggregators {
				if uint32(i) == nextLevel {
					err = h.transport.SendAggregateToAggregator(ctx, aggAddr, aggregatedMsg)
					if err != nil {
						log.Printf("Failed to send to higher-level aggregator %s: %v", aggAddr, err)
					}
					break
				}
			}
		}
	}

	// Start the next round
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Reset the aggregator for the new round
	h.Aggregator.Reset(round + 1)

	log.Printf("Aggregator started round %d", round+1)
}

func (h *AggregatorHandler) Shutdown() {
	h.runMutex.Lock()
	defer h.runMutex.Unlock()

	if h.running {
		log.Println("Shutting down aggregator handler background tasks")
		h.cancelFunc()
		h.running = false
	}
}

func (h *AggregatorHandler) RegisterRoutes(r chi.Router) {
	r.Get("/aggregator/status", h.handleStatus)
	r.Post("/aggregator/register-user", h.handleUser)
	r.Post("/aggregator/client-message", h.handleClientMessage)
	r.Post("/aggregator/aggregator-message", h.handleAggregatorMessage)
}

// handleStatus returns the current status of the aggregator
func (h *AggregatorHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	status := map[string]interface{}{
		"level":   h.Aggregator.GetLevel(),
		"running": h.running,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleUser registers a new user with the aggregator
func (h *AggregatorHandler) handleUser(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Decode the user registration request
	publicKey, err := zipnet.DecodeMessage[crypto.PublicKey](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request: %v", err), http.StatusBadRequest)
		return
	}

	// Whitelist the user
	h.Aggregator.WhitelistUser(*publicKey)

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "User registered successfully",
	})
}

// handleClientMessage processes client messages
func (h *AggregatorHandler) handleClientMessage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Decode the client message
	clientMsg, err := zipnet.DecodeMessage[zipnet.Signed[zipnet.ClientMessage]](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode client message: %v", err), http.StatusBadRequest)
		return
	}

	// Add the message to the aggregator
	if err := h.Aggregator.ReceiveClientMessage(r.Context(), clientMsg); err != nil {
		http.Error(w, fmt.Sprintf("Failed to process client message: %v", err), http.StatusBadRequest)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"message":       "Client message received successfully",
		"next_round_in": h.nextRoundAt.Sub(time.Now()).Seconds(),
	})
}

// handleAggregatorMessage processes messages from other aggregators
func (h *AggregatorHandler) handleAggregatorMessage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Decode the aggregator message
	aggMsg, err := zipnet.DecodeMessage[zipnet.Signed[zipnet.AggregatorMessage]](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode aggregator message: %v", err), http.StatusBadRequest)
		return
	}

	// Add the message to the aggregator
	if err := h.Aggregator.ReceiveAggregatorMessage(r.Context(), aggMsg); err != nil {
		http.Error(w, fmt.Sprintf("Failed to process aggregator message: %v", err), http.StatusBadRequest)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"message":       "Aggregator message received successfully",
		"next_round_in": h.nextRoundAt.Sub(time.Now()).Seconds(),
	})
}
