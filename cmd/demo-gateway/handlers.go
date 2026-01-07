package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
)

// ServicesResponse contains all registered services with status.
type ServicesResponse struct {
	Servers     []ServiceInfo `json:"servers"`
	Aggregators []ServiceInfo `json:"aggregators"`
	Clients     []ServiceInfo `json:"clients"`
}

// ServiceInfo describes a registered service.
type ServiceInfo struct {
	PublicKey    string `json:"public_key"`
	ExchangeKey  string `json:"exchange_key"`
	HTTPEndpoint string `json:"http_endpoint"`
	Healthy      bool   `json:"healthy"`
	Attested     bool   `json:"attested"`
	IsLeader     bool   `json:"is_leader,omitempty"`
}

// RoundResponse describes the current round state.
type RoundResponse struct {
	Number      int     `json:"number"`
	Phase       string  `json:"phase"`
	PhaseIndex  int     `json:"phase_index"`
	Progress    float64 `json:"progress"`
	NextPhaseAt string  `json:"next_phase_at"`
}

// RoundDetail contains decoded round data.
type RoundDetail struct {
	Number      int             `json:"number"`
	Timestamp   string          `json:"timestamp"`
	Messages    []MessageOutput `json:"messages"`
	Bids        []BidOutput     `json:"bids"`
	AuctionBids int             `json:"auction_bids"`
	Bandwidth   BandwidthStats  `json:"bandwidth"`
}

// MessageOutput describes a decoded message.
type MessageOutput struct {
	Offset  uint32 `json:"offset"`
	Size    uint32 `json:"size"`
	Content string `json:"content"`
	Binary  bool   `json:"binary,omitempty"`
}

// BidOutput describes a decoded auction bid.
type BidOutput struct {
	MessageHash string `json:"message_hash"`
	Weight      uint32 `json:"weight"`
	Size        uint32 `json:"size"`
	Won         bool   `json:"won"`
}

// BandwidthStats describes message vector utilization.
type BandwidthStats struct {
	Total       int     `json:"total"`
	Used        int     `json:"used"`
	Utilization float64 `json:"utilization"`
}

// SendRequest contains a message submission.
type SendRequest struct {
	Message string `json:"message"`
	Bid     int    `json:"bid"`
}

// SendResponse confirms message submission.
type SendResponse struct {
	Success      bool   `json:"success"`
	ScheduledFor int    `json:"scheduled_for,omitempty"`
	Error        string `json:"error,omitempty"`
}

// RoundEvent is sent via SSE when a round completes.
type RoundEvent struct {
	Round     int             `json:"round"`
	Timestamp string          `json:"timestamp"`
	Messages  []MessageOutput `json:"messages"`
	Bids      []BidOutput     `json:"bids"`
}

// HealthResponse describes gateway health.
type HealthResponse struct {
	Status      string `json:"status"`
	Connected   bool   `json:"connected"`
	NumServers  int    `json:"num_servers"`
	LatestRound int    `json:"latest_round"`
}

func (g *Gateway) handleConfig(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	config := g.adcConfig
	g.mu.RUnlock()

	if config == nil {
		http.Error(w, "configuration not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (g *Gateway) handleServices(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	svcList := g.services
	health := g.serviceHealth
	g.mu.RUnlock()

	if svcList == nil {
		http.Error(w, "services not available", http.StatusServiceUnavailable)
		return
	}

	resp := ServicesResponse{
		Servers:     make([]ServiceInfo, 0, len(svcList.Servers)),
		Aggregators: make([]ServiceInfo, 0, len(svcList.Aggregators)),
		Clients:     make([]ServiceInfo, 0, len(svcList.Clients)),
	}

	for i, svc := range svcList.Servers {
		resp.Servers = append(resp.Servers, ServiceInfo{
			PublicKey:    svc.Object.PublicKey,
			ExchangeKey:  svc.Object.ExchangeKey,
			HTTPEndpoint: svc.Object.HTTPEndpoint,
			Healthy:      health[svc.Object.PublicKey],
			Attested:     len(svc.Object.Attestation) > 0,
			IsLeader:     i == 0,
		})
	}

	for _, svc := range svcList.Aggregators {
		resp.Aggregators = append(resp.Aggregators, ServiceInfo{
			PublicKey:    svc.Object.PublicKey,
			ExchangeKey:  svc.Object.ExchangeKey,
			HTTPEndpoint: svc.Object.HTTPEndpoint,
			Healthy:      health[svc.Object.PublicKey],
			Attested:     len(svc.Object.Attestation) > 0,
		})
	}

	for _, svc := range svcList.Clients {
		resp.Clients = append(resp.Clients, ServiceInfo{
			PublicKey:    svc.Object.PublicKey,
			ExchangeKey:  svc.Object.ExchangeKey,
			HTTPEndpoint: svc.Object.HTTPEndpoint,
			Healthy:      health[svc.Object.PublicKey],
			Attested:     len(svc.Object.Attestation) > 0,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleCurrentRound(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	config := g.adcConfig
	g.mu.RUnlock()

	if config == nil {
		http.Error(w, "configuration not available", http.StatusServiceUnavailable)
		return
	}

	round, err := protocol.RoundForTime(time.Now(), config.RoundDuration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	phaseNames := []string{"client", "aggregation", "server", "broadcast"}

	nextPhase := round.Advance()
	nextPhaseTime := protocol.TimeForRound(nextPhase, config.RoundDuration)

	phaseDuration := config.RoundDuration / 4
	phaseStart := protocol.TimeForRound(round, config.RoundDuration)
	elapsed := time.Since(phaseStart)
	progress := float64(elapsed) / float64(phaseDuration)
	if progress > 1 {
		progress = 1
	}

	resp := RoundResponse{
		Number:      round.Number,
		Phase:       phaseNames[round.Context],
		PhaseIndex:  int(round.Context),
		Progress:    progress,
		NextPhaseAt: nextPhaseTime.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleRoundDetail(w http.ResponseWriter, r *http.Request) {
	numberStr := chi.URLParam(r, "number")
	number, err := strconv.Atoi(numberStr)
	if err != nil {
		http.Error(w, "invalid round number", http.StatusBadRequest)
		return
	}

	g.mu.RLock()
	detail := g.rounds[number]
	g.mu.RUnlock()

	if detail == nil {
		http.Error(w, "round not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

func (g *Gateway) handleSend(w http.ResponseWriter, r *http.Request) {
	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, SendResponse{Error: "invalid request body"})
		return
	}

	if req.Message == "" {
		writeJSON(w, http.StatusBadRequest, SendResponse{Error: "message is required"})
		return
	}

	if req.Bid <= 0 {
		writeJSON(w, http.StatusBadRequest, SendResponse{Error: "bid must be positive"})
		return
	}

	g.mu.RLock()
	svcList := g.services
	config := g.adcConfig
	g.mu.RUnlock()

	if svcList == nil || len(svcList.Clients) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, SendResponse{Error: "no clients available"})
		return
	}

	msgData := services.HTTPClientMessage{
		Message: []byte(req.Message),
		Value:   req.Bid,
	}
	plaintext, err := json.Marshal(msgData)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, SendResponse{Error: "failed to marshal message"})
		return
	}

	// Try all clients in random order
	for _, ci := range rand.Perm(len(svcList.Clients)) {
		client := svcList.Clients[ci]
		resp, err := g.sendToClient(config, client, plaintext)
		if err != nil {
			continue
		}

		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeJSON(w, http.StatusBadGateway, SendResponse{Error: "failed to submit message"})
	return
}

func (g *Gateway) sendToClient(config *protocol.ADCNetConfig, client *protocol.Signed[services.RegisteredService], plaintext []byte) (*SendResponse, error) {
	exchangeKey, err := services.ParseExchangeKey(client.Object.ExchangeKey)
	if err != nil {
		return nil, errors.New("invalid client exchange key")
	}

	encrypted, err := crypto.Encrypt(exchangeKey, plaintext)
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	body, _ := json.Marshal(encrypted)
	resp, err := g.httpClient.Post(
		client.Object.HTTPEndpoint+"/encrypted-message",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to reach client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client returned status %d", resp.StatusCode)
	}

	var scheduledFor int
	if config != nil {
		round, _ := protocol.RoundForTime(time.Now(), config.RoundDuration)
		scheduledFor = round.Number + 2
	}

	return &SendResponse{
		Success:      true,
		ScheduledFor: scheduledFor,
	}, nil
}

func (g *Gateway) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	eventCh := make(chan *RoundEvent, 10)

	g.subscribersMu.Lock()
	g.subscribers[eventCh] = struct{}{}
	g.subscribersMu.Unlock()

	defer func() {
		g.subscribersMu.Lock()
		delete(g.subscribers, eventCh)
		g.subscribersMu.Unlock()
		close(eventCh)
	}()

	g.mu.RLock()
	if g.latestRound > 0 {
		if detail := g.rounds[g.latestRound]; detail != nil {
			event := &RoundEvent{
				Round:     detail.Number,
				Timestamp: detail.Timestamp,
				Messages:  detail.Messages,
				Bids:      detail.Bids,
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: round\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
	g.mu.RUnlock()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-eventCh:
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: round\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	connected := g.adcConfig != nil
	numServers := 0
	if g.services != nil {
		numServers = len(g.services.Servers)
	}
	latestRound := g.latestRound
	g.mu.RUnlock()

	status := "ok"
	if !connected {
		status = "connecting"
	}

	resp := HealthResponse{
		Status:      status,
		Connected:   connected,
		NumServers:  numServers,
		LatestRound: latestRound,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

func bidOutputFromAuctionData(hash [32]byte, weight, size uint32, won bool) BidOutput {
	return BidOutput{
		MessageHash: hex.EncodeToString(hash[:8]),
		Weight:      weight,
		Size:        size,
		Won:         won,
	}
}
