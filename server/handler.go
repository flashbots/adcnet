package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

type ServerHandler struct {
	impl      *ServerImpl
	transport zipnet.NetworkTransport

	// For managing background tasks
	ctx        context.Context
	cancelFunc context.CancelFunc
	running    bool
	runMutex   sync.Mutex

	// share mgmt, should be done only here or in ServerImpl
	// also this should consider anytrust group id!
	mutex        sync.Mutex
	servers      map[string]zipnet.ServerRegistrationBlob
	curRound     uint64
	roundOutputs map[uint64]*zipnet.RoundOutput
	shares       map[uint64]map[string]*zipnet.UnblindedShareMessage
}

func NewServerHandler(Server *ServerImpl, transport zipnet.NetworkTransport) *ServerHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &ServerHandler{
		impl:         Server,
		transport:    transport,
		ctx:          ctx,
		cancelFunc:   cancel,
		running:      false,
		servers:      make(map[string]zipnet.ServerRegistrationBlob),
		curRound:     0,
		roundOutputs: make(map[uint64]*zipnet.RoundOutput),
		shares:       make(map[uint64]map[string]*zipnet.UnblindedShareMessage),
	}
}

func (h *ServerHandler) RegisterRoutes(r chi.Router) {
	// Note: leader is set statically through config, should be done by consensus.
	r.Post("/server/register-client", h.registerClient)
	r.Post("/server/register-aggregator", h.registerAggregator)
	r.Post("/server/register-server", h.registerServer) // TODO: check if needed on non-leaders
	r.Post("/server/aggregate", h.aggregate)

	if h.impl.isLeader {
		r.Post("/server/share", h.share)
		r.Get("/server/round-output/{round}", h.roundOutput)
		r.Get("/server/schedule/{round}", h.schedule)
	}
}

type ClientRegistrationRequest struct {
	PublicKey   crypto.PublicKey `json:"public_key"`
	Attestation []byte           `json:"attestation"`
}

func (h *ServerHandler) registerClient(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	req, err := zipnet.DecodeMessage[ClientRegistrationRequest](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.PublicKey == nil {
		http.Error(w, "Missing client public key", http.StatusBadRequest)
		return
	}

	// Register the client with the server
	if err := h.impl.RegisterClient(r.Context(), req.PublicKey, req.Attestation); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register client: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client registered successfully",
	})
}

func (h *ServerHandler) registerAggregator(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	aggregatorBlob, err := zipnet.DecodeMessage[zipnet.AggregatorRegistrationBlob](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if aggregatorBlob.PublicKey == nil {
		http.Error(w, "Missing aggregator public key", http.StatusBadRequest)
		return
	}

	// Register the aggregator with the server
	if err := h.impl.RegisterAggregator(r.Context(), aggregatorBlob); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register aggregator: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Aggregator registered successfully",
	})
}

func (h *ServerHandler) registerServer(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	serverBlob, err := zipnet.DecodeMessage[zipnet.ServerRegistrationBlob](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if serverBlob.PublicKey == nil || serverBlob.KemPublicKey == nil {
		http.Error(w, "Missing server public keys", http.StatusBadRequest)
		return
	}

	// Register the server with this server
	if err := h.impl.RegisterServer(r.Context(), serverBlob); err != nil {
		http.Error(w, fmt.Sprintf("Failed to register server: %v", err), http.StatusInternalServerError)
		return
	}

	h.mutex.Lock()
	h.servers[serverBlob.PublicKey.String()] = *serverBlob
	h.mutex.Unlock()

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Server registered successfully",
	})
}

func (h *ServerHandler) roundOutput(w http.ResponseWriter, r *http.Request) {
	// Extract the round number from the URL path
	roundStr := chi.URLParam(r, "round")
	round, err := strconv.ParseUint(roundStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid round number: %v", err), http.StatusBadRequest)
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	roundOutput, found := h.roundOutputs[round]
	if !found {
		// TODO: consider trying to compute the output
		http.Error(w, fmt.Sprintf("No round output"), http.StatusNotFound)
		return
	}

	// Serialize the round output to JSON
	outputData, err := zipnet.SerializeMessage(roundOutput)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize round output: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the round output to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(outputData)
}

func (h *ServerHandler) schedule(w http.ResponseWriter, r *http.Request) {
	// Extract the round number from the URL path
	roundStr := chi.URLParam(r, "round")
	round, err := strconv.ParseUint(roundStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid round number: %v", err), http.StatusBadRequest)
		return
	}

	// Get the schedule from the server
	scheduleData, signature, err := h.impl.GetSchedule(round)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get schedule: %v", err), http.StatusNotFound)
		return
	}

	// Create a PublishedSchedule struct
	schedule := zipnet.PublishedSchedule{
		Footprints: scheduleData,
		Signature:  signature,
	}

	// Serialize the schedule to JSON
	responseData, err := json.Marshal(schedule)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize schedule: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the schedule to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseData)
}

func (h *ServerHandler) share(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	shareMsg, err := zipnet.DecodeMessage[zipnet.UnblindedShareMessage](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse aggregator message: %v", err), http.StatusBadRequest)
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if _, serverFound := h.servers[shareMsg.ServerPublicKey.String()]; !serverFound {
		http.Error(w, "server not whitelisted", http.StatusUnauthorized)
		return
	}

	if err = shareMsg.Verify(h.impl.cryptoProvider); err != nil {
		http.Error(w, "signature invalid", http.StatusUnauthorized)
		return
	}

	cachedRoundOutput, roundAlreadyProcessed := h.roundOutputs[shareMsg.EncryptedMsg.Round]
	if roundAlreadyProcessed {
		w.WriteHeader(http.StatusAlreadyReported)
		w.Header().Set("Content-Type", "application/json")
		responseData, err := zipnet.SerializeMessage(cachedRoundOutput)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
			return
		}

		w.Write(responseData)
		return
	}

	if h.curRound == 0 {
		// Assume valid (TODO)
		h.curRound = shareMsg.EncryptedMsg.Round
	}

	if shareMsg.EncryptedMsg.Round+1000 < h.curRound || shareMsg.EncryptedMsg.Round > h.curRound {
		http.Error(w, "round out of bounds", http.StatusBadRequest)
		return
	}

	_, roundFound := h.shares[shareMsg.EncryptedMsg.Round]
	if !roundFound {
		if len(h.shares) > 1000 {
			for round := range h.shares {
				if len(h.shares) < 1000 || round+1000 >= shareMsg.EncryptedMsg.Round {
					break
				} else {
					delete(h.shares, round)
				}
			}
		}

		h.shares[shareMsg.EncryptedMsg.Round] = make(map[string]*zipnet.UnblindedShareMessage)
		leaderShare, err := h.impl.UnblindAggregate(context.Background(), shareMsg.EncryptedMsg)
		if err != nil {
			http.Error(w, fmt.Errorf("Leader could not unblind for round: %w", err).Error(), http.StatusInternalServerError)
			return
		}
		h.shares[shareMsg.EncryptedMsg.Round][h.impl.GetPublicKey().String()] = leaderShare
	}

	h.shares[shareMsg.EncryptedMsg.Round][shareMsg.ServerPublicKey.String()] = shareMsg

	shares := []*zipnet.UnblindedShareMessage{}
	for _, share := range h.shares[shareMsg.EncryptedMsg.Round] {
		shares = append(shares, share)
	}

	// Try to wrap up the round

	roundOutput, err := h.impl.DeriveRoundOutput(r.Context(), shares)
	if err != nil && strings.Contains(err.Error(), "shares, got") { // TODO: handle the error check better
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "accepted",
			"message": "Share processed, waiting for more",
		})
		return
	} else if err != nil {
		http.Error(w, fmt.Errorf("unexpected error while processing share: %w", err).Error(), http.StatusInternalServerError)
	}

	h.roundOutputs[shareMsg.EncryptedMsg.Round] = roundOutput
	if shareMsg.EncryptedMsg.Round >= h.curRound {
		h.curRound = shareMsg.EncryptedMsg.Round + 1
		if _, _, err := h.impl.PublishSchedule(h.ctx, h.curRound, roundOutput.Message.NextSchedVec); err != nil {
			log.Panicln()
		}
	}

	// Otherwise, return the server message (final output)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Serialize and return the server message
	responseData, err := zipnet.SerializeMessage(roundOutput)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(responseData)
}

func (h *ServerHandler) aggregate(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	aggregateMsg, err := zipnet.DecodeMessage[zipnet.AggregatorMessage](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse aggregator message: %v", err), http.StatusBadRequest)
		return
	}

	unblindedMsg, err := h.impl.UnblindAggregate(r.Context(), aggregateMsg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblind aggregate: %v", err), http.StatusInternalServerError)
		return
	}

	// Serialize and return the server message
	responseData, err := zipnet.SerializeMessage(unblindedMsg)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	// TODO: should submit the unblinded message to the leader
	// TODO: if leader, should try to derive round output

	// Otherwise, return the server message (final output)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	w.Write(responseData)

	if h.transport != nil {
		go func() {
			h.mutex.Lock()
			defer h.mutex.Unlock()
			for _, rs := range h.servers {
				if rs.IsLeader {
					h.transport.SendShareToServer(context.Background(), rs.PublicKey.String(), unblindedMsg)
				}
			}
		}()
	}
}

// RunInBackground starts the background tasks for the server handler
func (h *ServerHandler) RunInBackground() {
	h.runMutex.Lock()
	defer h.runMutex.Unlock()

	if h.running {
		log.Println("Server handler background tasks already running")
		return
	}

	log.Println("Server handler background tasks started")
	h.running = true

	// Start background tasks based on server role
	if h.impl.IsLeader() {
		go h.runLeaderTasks()
	} else {
		go h.runFollowerTasks()
	}
}

// runLeaderTasks runs the background tasks specific to a leader server
func (h *ServerHandler) runLeaderTasks() {
	log.Println("Running leader-specific background tasks")
	<-h.ctx.Done()
}

// runFollowerTasks runs the background tasks specific to a follower server
func (h *ServerHandler) runFollowerTasks() {
	log.Println("Running follower-specific background tasks")

	// Create ticker for checking for updates from the leader
	syncTicker := time.NewTicker(2 * time.Second)

	defer func() {
		syncTicker.Stop()
		log.Println("Follower background tasks stopped")
	}()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-syncTicker.C:
			continue
		}
	}
}

// Shutdown stops all background tasks
func (h *ServerHandler) Shutdown() {
	h.runMutex.Lock()
	defer h.runMutex.Unlock()

	if h.running {
		log.Println("Shutting down server handler background tasks")
		h.cancelFunc()
		h.running = false
	}
}
