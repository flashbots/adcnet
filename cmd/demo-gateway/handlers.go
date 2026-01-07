package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/go-chi/chi/v5"
)

// ConfigResponse contains protocol configuration for the API.
type ConfigResponse struct {
	RoundDuration   string `json:"round_duration"`
	MessageLength   int    `json:"message_length"`
	AuctionSlots    uint32 `json:"auction_slots"`
	MinClients      uint32 `json:"min_clients"`
	RoundsPerWindow uint32 `json:"rounds_per_window"`
}

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

	resp := ConfigResponse{
		RoundDuration:   config.RoundDuration.String(),
		MessageLength:   config.MessageLength,
		AuctionSlots:    config.AuctionSlots,
		MinClients:      config.MinClients,
		RoundsPerWindow: config.RoundsPerWindow,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

	// Calculate progress within current phase
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

	// Use the last client as the demo client
	client := svcList.Clients[len(svcList.Clients)-1]

	// Parse client's exchange key
	exchangeKey, err := services.ParseExchangeKey(client.Object.ExchangeKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, SendResponse{Error: "invalid client exchange key"})
		return
	}

	// Prepare message payload
	msgData := services.HTTPClientMessage{
		Message: []byte(req.Message),
		Value:   req.Bid,
	}
	plaintext, err := json.Marshal(msgData)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, SendResponse{Error: "failed to marshal message"})
		return
	}

	// Encrypt to client's exchange key
	encrypted, err := crypto.Encrypt(exchangeKey, plaintext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, SendResponse{Error: "encryption failed"})
		return
	}

	// Send to client
	body, _ := json.Marshal(encrypted)
	resp, err := g.httpClient.Post(
		client.Object.HTTPEndpoint+"/encrypted-message",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, SendResponse{Error: fmt.Sprintf("failed to reach client: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusBadGateway, SendResponse{Error: fmt.Sprintf("client returned status %d", resp.StatusCode)})
		return
	}

	// Calculate expected round for message appearance
	var scheduledFor int
	if config != nil {
		round, _ := protocol.RoundForTime(time.Now(), config.RoundDuration)
		scheduledFor = round.Number + 2 // Current round for auction, next for message
	}

	writeJSON(w, http.StatusOK, SendResponse{
		Success:      true,
		ScheduledFor: scheduledFor,
	})
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

	// Send latest round immediately if available
	g.mu.RLock()
	if g.latestRound > 0 {
		if detail := g.rounds[g.latestRound]; detail != nil {
			event := &RoundEvent{
				Round:     detail.Number,
				Timestamp: detail.Timestamp,
				Messages:  detail.Messages,
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: round\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
	g.mu.RUnlock()

	// Stream events
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

func (g *Gateway) handleEmbeddedIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(embeddedIndexHTML))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// embeddedIndexHTML is a minimal fallback page when no static dir is provided.
const embeddedIndexHTML = `<!DOCTYPE html>
<html>
<head>
    <title>ADCNet Demo</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { color: #64748b; margin-bottom: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }
        .card h2 { font-size: 1rem; color: #94a3b8; margin-bottom: 1rem; }
        .stat { font-size: 2rem; font-weight: bold; color: #22d3ee; }
        .messages { max-height: 400px; overflow-y: auto; }
        .message { background: #0f172a; padding: 1rem; border-radius: 0.5rem; margin-bottom: 0.5rem; font-family: monospace; font-size: 0.875rem; word-break: break-all; }
        .message-meta { color: #64748b; font-size: 0.75rem; margin-top: 0.5rem; }
        .form { display: flex; flex-direction: column; gap: 1rem; }
        textarea { background: #0f172a; border: 1px solid #334155; border-radius: 0.5rem; padding: 1rem; color: #e2e8f0; resize: none; min-height: 100px; }
        button { background: linear-gradient(135deg, #06b6d4, #3b82f6); color: white; border: none; padding: 1rem; border-radius: 0.5rem; font-weight: 600; cursor: pointer; }
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .phase { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
        .phase-item { flex: 1; text-align: center; padding: 0.75rem; background: #334155; border-radius: 0.5rem; font-size: 0.875rem; }
        .phase-item.active { background: #06b6d4; color: #0f172a; }
        .services { display: flex; flex-direction: column; gap: 0.5rem; }
        .service { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: #0f172a; border-radius: 0.25rem; font-size: 0.875rem; }
        .dot { width: 8px; height: 8px; border-radius: 50%; }
        .dot.healthy { background: #22c55e; }
        .dot.unhealthy { background: #ef4444; }
        .bid-slider { display: flex; align-items: center; gap: 1rem; }
        .bid-slider input { flex: 1; }
        .bid-value { font-size: 1.5rem; font-weight: bold; color: #22d3ee; min-width: 60px; text-align: right; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 ADCNet Demo</h1>
        <p class="subtitle">Anonymous Distributed Communication Network</p>
        
        <div class="card" style="margin-bottom: 1.5rem;">
            <h2>Round <span id="round-number">-</span></h2>
            <div class="phase" id="phase-indicator">
                <div class="phase-item" data-phase="0">Client</div>
                <div class="phase-item" data-phase="1">Aggregation</div>
                <div class="phase-item" data-phase="2">Server</div>
                <div class="phase-item" data-phase="3">Broadcast</div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Network Status</h2>
                <div id="services" class="services">
                    <p style="color: #64748b;">Loading...</p>
                </div>
            </div>

            <div class="card">
                <h2>Message Stream</h2>
                <div id="messages" class="messages">
                    <p style="color: #64748b;">Waiting for messages...</p>
                </div>
            </div>

            <div class="card">
                <h2>Send Anonymous Message</h2>
                <div class="form">
                    <textarea id="message-input" placeholder="Enter your message..."></textarea>
                    <div class="bid-slider">
                        <span style="color: #64748b;">Bid:</span>
                        <input type="range" id="bid-input" min="1" max="1000" value="100">
                        <span class="bid-value" id="bid-value">100</span>
                    </div>
                    <button id="send-btn" onclick="sendMessage()">Send Anonymously</button>
                    <p style="color: #64748b; font-size: 0.75rem; text-align: center;">⚠️ Demo mode: Message routed through demo client</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API = '';
        let eventSource;

        async function fetchServices() {
            try {
                const resp = await fetch(API + '/api/services');
                const data = await resp.json();
                const container = document.getElementById('services');
                
                let html = '';
                const groups = [
                    { name: 'Servers', items: data.servers || [] },
                    { name: 'Aggregators', items: data.aggregators || [] },
                    { name: 'Clients', items: data.clients || [] }
                ];
                
                groups.forEach(group => {
                    if (group.items.length > 0) {
                        const healthy = group.items.filter(s => s.healthy).length;
                        html += '<div class="service"><span>' + group.name + '</span><span>' + healthy + '/' + group.items.length + ' online</span></div>';
                    }
                });
                
                container.innerHTML = html || '<p style="color: #64748b;">No services registered</p>';
            } catch (e) {
                console.error('Failed to fetch services:', e);
            }
        }

        async function fetchRound() {
            try {
                const resp = await fetch(API + '/api/round');
                const data = await resp.json();
                
                document.getElementById('round-number').textContent = data.number;
                
                document.querySelectorAll('.phase-item').forEach(el => {
                    el.classList.toggle('active', parseInt(el.dataset.phase) === data.phase_index);
                });
            } catch (e) {
                console.error('Failed to fetch round:', e);
            }
        }

        function connectSSE() {
            eventSource = new EventSource(API + '/events');
            
            eventSource.addEventListener('round', (e) => {
                const data = JSON.parse(e.data);
                displayRound(data);
            });
            
            eventSource.onerror = () => {
                eventSource.close();
                setTimeout(connectSSE, 3000);
            };
        }

        function displayRound(data) {
            const container = document.getElementById('messages');
            
            if (data.messages && data.messages.length > 0) {
                let html = '';
                data.messages.forEach(msg => {
                    html += '<div class="message">' + escapeHtml(msg.content) + 
                            '<div class="message-meta">Round ' + data.round + ' • Offset: ' + msg.offset + ' • Size: ' + msg.size + 'b</div></div>';
                });
                container.innerHTML = html + container.innerHTML;
                
                // Keep only last 20 messages
                while (container.children.length > 20) {
                    container.removeChild(container.lastChild);
                }
            }
        }

        async function sendMessage() {
            const input = document.getElementById('message-input');
            const bidInput = document.getElementById('bid-input');
            const btn = document.getElementById('send-btn');
            const message = input.value.trim();
            
            if (!message) return;
            
            btn.disabled = true;
            btn.textContent = 'Sending...';
            
            try {
                const resp = await fetch(API + '/api/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message, bid: parseInt(bidInput.value) })
                });
                
                const data = await resp.json();
                if (data.success) {
                    input.value = '';
                    alert('Message submitted! Expected in round ' + data.scheduled_for);
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (e) {
                alert('Failed to send: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Send Anonymously';
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Bid slider
        document.getElementById('bid-input').addEventListener('input', (e) => {
            document.getElementById('bid-value').textContent = e.target.value;
        });

        // Initialize
        fetchServices();
        fetchRound();
        connectSSE();
        setInterval(fetchServices, 30000);
        setInterval(fetchRound, 1000);
    </script>
</body>
</html>`
