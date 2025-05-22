package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/zipnet"
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
	roundOutputs map[uint64]*zipnet.Signed[zipnet.RoundOutput]
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
		roundOutputs: make(map[uint64]*zipnet.Signed[zipnet.RoundOutput]),
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
	signedShareMsg, err := zipnet.DecodeMessage[zipnet.Signed[zipnet.UnblindedShareMessage]](r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse share message: %v", err), http.StatusBadRequest)
		return
	}

	_, statusCode, err := h.processShare(r.Context(), signedShareMsg)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}
	w.WriteHeader(statusCode)
}

func (h *ServerHandler) processShare(ctx context.Context, signedShareMsg *zipnet.Signed[zipnet.UnblindedShareMessage]) (*zipnet.Signed[zipnet.RoundOutput], int, error) {
	shareMsg, srvSigner, err := signedShareMsg.Recover()
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("could not recover server signature: %w", err)
	}

	aggMessage, aggSigner, err := shareMsg.EncryptedMsg.Recover()
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("could not recover aggregator signature: %w", err)
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !srvSigner.Equal(h.impl.publicKey) {
		if _, serverFound := h.servers[srvSigner.String()]; !serverFound {
			return nil, http.StatusUnauthorized, fmt.Errorf("non-whitelisted server %s", srvSigner.String())
		}
	}

	if _, found := h.impl.regAggregators[aggSigner.String()]; !found {
		return nil, http.StatusUnauthorized, fmt.Errorf("non-whitelisted aggregator %s", aggSigner.String())
	}

	cachedRoundOutput, roundAlreadyProcessed := h.roundOutputs[aggMessage.Round]
	if roundAlreadyProcessed {
		return cachedRoundOutput, http.StatusAlreadyReported, nil
	}

	var currentRound uint64 = zipnet.CurrentRound(h.impl.config.RoundDuration)
	if aggMessage.Round+1000 < currentRound || aggMessage.Round > currentRound {
		return nil, http.StatusBadRequest, fmt.Errorf("round %d out of bounds, current round %d", aggMessage.Round, currentRound)
	}

	_, roundFound := h.shares[aggMessage.Round]
	if !roundFound {
		if len(h.shares) > 1000 {
			for round := range h.shares {
				if len(h.shares) < 1000 || round+1000 >= aggMessage.Round {
					break
				} else {
					delete(h.shares, round)
				}
			}
		}

		h.shares[aggMessage.Round] = make(map[string]*zipnet.UnblindedShareMessage)
		leaderShare, err := h.impl.UnblindAggregate(context.Background(), shareMsg.EncryptedMsg)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("leader could not unblind for round: %w", err)
		}
		rawLeaderShare, _, _ := leaderShare.Recover()
		h.shares[aggMessage.Round][h.impl.GetPublicKey().String()] = rawLeaderShare
	}

	h.shares[aggMessage.Round][srvSigner.String()] = shareMsg

	shares := []*zipnet.UnblindedShareMessage{}
	for _, share := range h.shares[aggMessage.Round] {
		shares = append(shares, share)
	}

	// Try to wrap up the round

	roundOutput, err := h.impl.DeriveRoundOutput(ctx, shares)
	if err != nil && strings.Contains(err.Error(), "shares, got") { // TODO: handle the error check better
		return roundOutput, http.StatusAccepted, nil
	} else if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("unexpected error while processing share: %w", err)
	}

	h.roundOutputs[aggMessage.Round] = roundOutput

	// Otherwise, return the server message (final output)
	return roundOutput, http.StatusOK, nil
}

func (h *ServerHandler) aggregate(w http.ResponseWriter, r *http.Request) {
	// Note: there are some unexpected calls to aggregate
	defer r.Body.Close()
	aggregateMsg, err := zipnet.DecodeMessage[zipnet.Signed[zipnet.AggregatorMessage]](r.Body)
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

	if h.impl.IsLeader() {
		go func() {
			_, _, err := h.processShare(context.Background(), unblindedMsg)
			if err != nil {
				log.Println(fmt.Errorf("could not process share: %w", err))
			}
		}()
	}

	// Otherwise, return the server message (final output)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	w.Write(responseData)

	if h.transport != nil && !h.impl.IsLeader() {
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
	var currentRound uint64 = zipnet.CurrentRound(h.impl.config.RoundDuration)
	var roundOffset time.Duration = time.Duration(h.impl.config.RoundDuration.Milliseconds()*90/100) * time.Millisecond

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(time.Until(zipnet.RoundOffset(currentRound, h.impl.config.RoundDuration, roundOffset))):
			err := h.PublishScheduleFor(currentRound + 1)
			if err != nil {
				log.Println(fmt.Errorf("could not publish schedule for round %d: %w", currentRound, err))
			}
			currentRound = currentRound + 1
		}
	}
}

func (h *ServerHandler) PublishScheduleFor(round uint64) error {
	if round == 0 {
		initialSchedVec := make([]byte, h.impl.config.SchedulingSlots)
		_, _, err := h.impl.PublishSchedule(h.ctx, 0, initialSchedVec)
		return err
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()
	roundOutput, found := h.roundOutputs[round-1]
	if !found {
		initialSchedVec := make([]byte, h.impl.config.SchedulingSlots)
		_, _, err := h.impl.PublishSchedule(h.ctx, round, initialSchedVec)
		return err
	} else {
		_, _, err := h.impl.PublishSchedule(h.ctx, round, roundOutput.UnsafeObject().NextSchedVec)
		if err != nil {
			return err
		}
	}
	return nil
}

// runFollowerTasks runs the background tasks specific to a follower server
func (h *ServerHandler) runFollowerTasks() {
	log.Println("Running follower-specific background tasks")

	var currentRound uint64 = zipnet.CurrentRound(h.impl.config.RoundDuration)
	var roundOffset time.Duration = time.Duration(h.impl.config.RoundDuration.Milliseconds()*12/10) * time.Millisecond

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(time.Until(zipnet.RoundOffset(currentRound, h.impl.config.RoundDuration, roundOffset))):
			err := h.updateSchedule(currentRound + 1)
			if err != nil {
				log.Println(fmt.Errorf("could not fetch schedule for round %d", currentRound+1))
			}
			currentRound = currentRound + 1
		}
	}
}

func (h *ServerHandler) updateSchedule(round uint64) error {
	var leader string
	for _, server := range h.servers {
		if server.IsLeader {
			leader = server.PublicKey.String()
		}
	}
	if leader == "" {
		return errors.New("no leader")
	}

	schedule, err := h.transport.FetchSchedule(context.TODO(), leader, round)
	if err != nil {
		return err
	}

	err = h.impl.SetSchedule(context.TODO(), round, schedule.Footprints, schedule.Signature)
	if err != nil {
		return err
	}

	return nil
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
