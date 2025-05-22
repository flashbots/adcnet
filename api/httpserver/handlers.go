package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/flashbots/adcnet/client"
)

type ClientHandler struct {
	Client *client.ClientImpl
}

func NewClientHandler(Client *client.ClientImpl) *ClientHandler {
	return &ClientHandler{Client: Client}
}

func (h *ClientHandler) RunInBackground() {
	// 0. Register with servers
	// In the background:
	// 1. Keep track of leader server & rounds
	// 2. Send either cover traffic, or message if any
	// 3. In the future, resolve aggregators and servers
}

// See zipnet.ZIPNetConfig
type NetworkConfig struct {
	AnytrustServers []string
	Aggregators     []string
}

func (h *ClientHandler) RegisterRoutes(r chi.Router) {
	r.Post("/client/config", h.handleConfig)
	r.Post("/client/message", h.handleMessage)
}

func (h *ClientHandler) handleMessage(w http.ResponseWriter, r *http.Request) {
	// 1. reserve slot
	// 2. wait for next slot
	// 3. submit message
	// 4. continue sending cover traffic randomly
	// 5. wait for broadcast
	// 6. decrypt the broadcast message & verify
}

func (h *ClientHandler) handleConfig(w http.ResponseWriter, r *http.Request) {
	// Update config, exchange keys with servers
}
