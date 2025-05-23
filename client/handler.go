package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/go-chi/chi/v5"
)

// ClientHandler provides HTTP endpoints for client operations in the ZIPNet protocol
type ClientHandler struct {
	impl           *ClientImpl
	transport      protocol.NetworkTransport
	ctx            context.Context
	cancelFunc     context.CancelFunc
	leaderServerID string
	leaderPK       crypto.PublicKey

	// State management (protected by mutex)
	mutex        sync.RWMutex
	running      bool
	messageQueue []PendingMessage
}

// PendingMessage represents a message waiting to be sent
type PendingMessage struct {
	Content     []byte
	SubmittedAt time.Time
}

// NewClientHandler creates a new client handler
func NewClientHandler(client *ClientImpl, transport zipnet.NetworkTransport) *ClientHandler {
	ctx, cancel := context.WithCancel(context.Background())

	// Set leader server from the first server in the config
	var leaderServerID string
	if len(client.config.AnytrustServers) > 0 {
		leaderServerID = client.config.AnytrustServers[0]
	}

	return &ClientHandler{
		impl:           client,
		transport:      transport,
		ctx:            ctx,
		cancelFunc:     cancel,
		leaderServerID: leaderServerID,
		running:        false,
		messageQueue:   make([]PendingMessage, 0),
	}
}

// RunInBackground starts the client background task
func (h *ClientHandler) RunInBackground() {
	h.mutex.Lock()
	if h.running {
		h.mutex.Unlock()
		return
	}
	h.running = true
	h.mutex.Unlock()

	log.Println("Starting client background task")

	// Register server keys if needed
	if h.leaderPK == nil && h.leaderServerID != "" {
		if serverPK, exists := h.impl.serverPublicKeys[h.leaderServerID]; exists {
			h.leaderPK = serverPK
		}
	}

	// Start the main worker
	go h.clientWorker()
}

// Shutdown stops the background task
func (h *ClientHandler) Shutdown() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.running {
		log.Println("Shutting down client handler")
		h.cancelFunc()
		h.running = false
	}
}

// RegisterRoutes registers HTTP routes for client operations
func (h *ClientHandler) RegisterRoutes(r chi.Router) {
	r.Get("/client/status", h.handleStatus)
	r.Post("/client/message", h.handleMessage)
}

// handleStatus returns the client's current status
func (h *ClientHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	status := map[string]interface{}{
		"running":            h.running,
		"pending_messages":   len(h.messageQueue),
		"times_participated": h.impl.GetTimesParticipated(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleMessage queues a message for submission
func (h *ClientHandler) handleMessage(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	msgReq, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read message request: %v", err), http.StatusBadRequest)
		return
	}

	// Add the message to the queue
	h.mutex.Lock()
	h.messageQueue = append(h.messageQueue, PendingMessage{
		Content:     msgReq,
		SubmittedAt: time.Now(),
	})
	queuePosition := len(h.messageQueue)
	h.mutex.Unlock()

	// Response with success
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "queued",
		"message":        "Message queued for submission",
		"queue_position": queuePosition,
	})
}

// clientWorker is the main worker routine that processes rounds
func (h *ClientHandler) clientWorker() {
	var currentRound uint64 = zipnet.CurrentRound(h.impl.config.RoundDuration)
	var currentMessage []byte = nil

	for {
		select {
		case <-h.ctx.Done():
			log.Println("Client worker stopped")
			return
		case <-time.After(time.Until(zipnet.RoundStart(currentRound+1, h.impl.config.RoundDuration))):
		}

		currentRound = currentRound + 1

		schedule, err := h.fetchSchedule(currentRound)
		if err != nil {
			log.Println(fmt.Errorf("client worker could not fetch schedule for round %d: %w", currentRound, err))
			continue
		}

		// Always reserve for now
		var shouldReserve bool = true

		signedMsg, prepErr := h.impl.PrepareMessage(context.TODO(), currentRound, currentMessage, shouldReserve, *schedule)
		if prepErr != nil && !errors.Is(prepErr, ErrorFootprintCollision) {
			log.Println(fmt.Errorf("client worker could not prepare message for round %d: %w", currentRound, prepErr))
			continue
		}

		h.mutex.Lock()
		// Note: this implementation will drop messages on restarts
		if currentMessage != nil && prepErr == nil {
			log.Println("client sent message", string(currentMessage), "in round", currentRound)
			currentMessage = nil
		}
		if currentMessage == nil && len(h.messageQueue) > 0 && prepErr == nil {
			currentMessage = make([]byte, len(h.messageQueue[0].Content))
			copy(currentMessage, h.messageQueue[0].Content)
			h.messageQueue = h.messageQueue[1:]
		}
		h.mutex.Unlock()

		go func(round uint64, msg *zipnet.Signed[zipnet.ClientMessage]) {
			for _, agg := range h.impl.config.Aggregators {
				err := h.transport.SendToAggregator(context.TODO(), agg, signedMsg)
				if err != nil {
					log.Println(fmt.Errorf("could not send message in round %d to aggregator %s: %w", round, agg, err))
					continue
				} else {
					break
				}
			}
		}(currentRound, signedMsg)

		// TODO: await server broadcast!
	}
}

// fetchSchedule fetches the schedule for a round from the leader server
func (h *ClientHandler) fetchSchedule(round uint64) (*zipnet.PublishedSchedule, error) {
	// Only fetch schedule if we have a leader server ID
	if h.leaderServerID == "" || h.transport == nil {
		return nil, errors.New("cannot fetch schedule: no leader or network")
	}

	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var scheduleData *zipnet.PublishedSchedule
		scheduleData, err = h.transport.FetchSchedule(context.TODO(), h.leaderServerID, round)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return scheduleData, nil
	}

	return nil, err
}
