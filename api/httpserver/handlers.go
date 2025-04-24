package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/go-zipnet/aggregator"
	"github.com/ruteri/go-zipnet/client"
	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

type ServerHandler struct {
	ZIPNetServer zipnet.Server
}

func NewServerHandler(ZIPNetServer zipnet.Server) *ServerHandler {
	return &ServerHandler{ZIPNetServer: ZIPNetServer}
}

func (h *ServerHandler) RegisterRoutes(r chi.Router) {
	// Note: leader is set statically through config, should be done by consensus.
	r.Post("/server/register-client", h.registerClient) // TODO: should check client's attestation
	r.Post("/server/register-aggregator", h.registerAggregator)
	r.Post("/server/register-server", h.registerServer)
	r.Get("/server/round-output", h.roundOutput)
	r.Get("/server/schedule", h.schedule)
	r.Post("/server/aggregate", h.aggregate) // Note: servers unblind one by one until the leader
}

func (h *ServerHandler) RunInBackground() {
	// 0. Register with servers
	// In the background:
	// 1. Unblind aggregates
	// 2. Publish schedules
}

func (h *ServerHandler) registerClient(w http.ResponseWriter, r *http.Request) {
}

func (h *ServerHandler) registerAggregator(w http.ResponseWriter, r *http.Request) {
}

func (h *ServerHandler) registerServer(w http.ResponseWriter, r *http.Request) {
}

func (h *ServerHandler) roundOutput(w http.ResponseWriter, r *http.Request) {
}

func (h *ServerHandler) schedule(w http.ResponseWriter, r *http.Request) {
}

func (h *ServerHandler) aggregate(w http.ResponseWriter, r *http.Request) {
}

type AggregatorHandler struct {
	Aggregator *aggregator.AggregatorImpl
}

func NewAggregatorHandler(aggregator *aggregator.AggregatorImpl) *AggregatorHandler {
	return &AggregatorHandler{Aggregator: aggregator}
}

func (h *AggregatorHandler) RunInBackground() {
	// 0. Register with servers
	// In the background:
	// 1. Keep track of leader server & rounds
	// 2. Aggregate and submit messages
}

func (h *AggregatorHandler) RegisterRoutes(r chi.Router) {
	r.Post("/aggregator/config", h.handleConfig)
	r.Post("/aggregator/register-user", h.handleUser)
	r.Post("/aggregator/client-message", h.handleClientMessage)
	r.Post("/aggregator/aggregator-message", h.handleAggregatorMessage)
}

func (h *AggregatorHandler) handleConfig(w http.ResponseWriter, r *http.Request) {
}

func (h *AggregatorHandler) handleUser(w http.ResponseWriter, r *http.Request) {
	h.Aggregator.WhitelistUser(crypto.PublicKey{})
}

func (h *AggregatorHandler) handleClientMessage(w http.ResponseWriter, r *http.Request) {
}

func (h *AggregatorHandler) handleAggregatorMessage(w http.ResponseWriter, r *http.Request) {
}

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
