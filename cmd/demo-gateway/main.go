package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/flashbots/adcnet/tdx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	var (
		addr             = flag.String("addr", ":8888", "HTTP listen address")
		registryURL      = flag.String("registry", "http://localhost:7999", "Registry URL")
		staticDir        = flag.String("static", "", "Directory for static files")
		skipVerification = flag.Bool("skip-verification", false, "Skip attestation verification")
		measurementsURL  = flag.String("measurements-url", "", "URL for allowed TEE measurements")
		allowedOrigins   = flag.String("allowed-origins", "http://localhost:*", "Comma-separated list of allowed CORS origins (use * for all)")
	)
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		cancel()
	}()

	// Parse allowed origins
	origins := strings.Split(*allowedOrigins, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	gateway := NewGateway(&GatewayConfig{
		RegistryURL:      *registryURL,
		SkipVerification: *skipVerification,
		MeasurementsURL:  *measurementsURL,
		StaticDir:        *staticDir,
		AllowedOrigins:   origins,
	})

	go gateway.Start(ctx)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   gateway.config.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	gateway.RegisterRoutes(r)

	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		fmt.Printf("Demo gateway listening on %s\n", *addr)
		fmt.Printf("Dashboard: http://localhost%s\n", *addr)
		fmt.Printf("SSE stream: curl -N http://localhost%s/events\n", *addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpServer.Shutdown(shutdownCtx)
	fmt.Println("Gateway shutdown complete")
}

// GatewayConfig configures the demo gateway.
type GatewayConfig struct {
	RegistryURL      string
	SkipVerification bool
	MeasurementsURL  string
	StaticDir        string
	AllowedOrigins   []string
}

// Gateway serves the demo API and website.
type Gateway struct {
	config     *GatewayConfig
	httpClient *http.Client

	mu              sync.RWMutex
	adcConfig       *protocol.ADCNetConfig
	services        *services.ServiceListResponse
	serviceHealth   map[string]bool
	rounds          map[int]*RoundDetail
	latestRound     int
	previousAuction *blind_auction.IBLTVector

	subscribersMu sync.RWMutex
	subscribers   map[chan *RoundEvent]struct{}
}

// NewGateway creates a demo gateway.
func NewGateway(config *GatewayConfig) *Gateway {
	return &Gateway{
		config:        config,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		serviceHealth: make(map[string]bool),
		rounds:        make(map[int]*RoundDetail),
		subscribers:   make(map[chan *RoundEvent]struct{}),
	}
}

// RegisterRoutes registers all HTTP routes.
func (g *Gateway) RegisterRoutes(r chi.Router) {
	r.Route("/api", func(r chi.Router) {
		r.Get("/config", g.handleConfig)
		r.Get("/services", g.handleServices)
		r.Get("/round", g.handleCurrentRound)
		r.Get("/rounds/{number}", g.handleRoundDetail)
		r.Post("/send", g.handleSend)
	})

	r.Get("/events", g.handleSSE)
	r.Get("/health", g.handleHealth)
	g.registerStaticRoutes(r)
}

func (g *Gateway) registerStaticRoutes(r chi.Router) {
	if g.config.StaticDir != "" {
		// Get absolute path of static directory for security validation
		absStaticDir, err := filepath.Abs(g.config.StaticDir)
		if err != nil {
			fmt.Printf("Warning: could not resolve static dir: %v\n", err)
			return
		}

		fileServer := http.FileServer(http.Dir(absStaticDir))
		r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Clean and validate the path to prevent directory traversal
			cleanPath := filepath.Clean(req.URL.Path)
			fullPath := filepath.Join(absStaticDir, cleanPath)

			// Ensure the resolved path is within the static directory
			if !strings.HasPrefix(fullPath, absStaticDir) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			if _, err := os.Stat(fullPath); os.IsNotExist(err) && req.URL.Path != "/" {
				http.ServeFile(w, req, filepath.Join(absStaticDir, "index.html"))
				return
			}
			fileServer.ServeHTTP(w, req)
		}))
	} else {
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "nothing to serve", http.StatusInternalServerError)
		})
		r.Get("/favicon.svg", g.handleFavicon)
	}
}

func (g *Gateway) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#06b6d4"/><stop offset="100%" style="stop-color:#3b82f6"/></linearGradient></defs><rect width="100" height="100" rx="20" fill="url(#g)"/><path d="M50 20L30 50L50 80L70 50Z" fill="white" opacity="0.9"/><circle cx="50" cy="50" r="12" fill="white"/></svg>`))
}

// Start begins background polling for registry and round data.
func (g *Gateway) Start(ctx context.Context) {
	time.Sleep(500 * time.Millisecond)

	configTicker := time.NewTicker(30 * time.Second)
	defer configTicker.Stop()

	g.refreshConfig()
	g.refreshServices()

	g.mu.RLock()
	pollInterval := 2 * time.Second
	if g.adcConfig != nil {
		pollInterval = g.adcConfig.RoundDuration / 4
	}
	g.mu.RUnlock()

	roundTicker := time.NewTicker(pollInterval)
	defer roundTicker.Stop()

	healthTicker := time.NewTicker(15 * time.Second)
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-configTicker.C:
			g.refreshConfig()
			g.refreshServices()
		case <-roundTicker.C:
			g.pollRounds()
		case <-healthTicker.C:
			g.checkServiceHealth()
		}
	}
}

func (g *Gateway) refreshConfig() {
	resp, err := g.httpClient.Get(g.config.RegistryURL + "/config")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	config, err := protocol.DecodeMessage[protocol.ADCNetConfig](resp.Body)
	if err != nil {
		return
	}

	g.mu.Lock()
	g.adcConfig = config
	g.mu.Unlock()
}

func (g *Gateway) refreshServices() {
	resp, err := g.httpClient.Get(g.config.RegistryURL + "/services")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var list services.ServiceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return
	}

	if !g.config.SkipVerification {
		list.Servers = g.verifyServices(list.Servers)
		list.Aggregators = g.verifyServices(list.Aggregators)
	}

	g.mu.Lock()
	g.services = &list
	g.mu.Unlock()

	g.checkServiceHealth()
}

func (g *Gateway) verifyServices(signed []*protocol.Signed[services.RegisteredService]) []*protocol.Signed[services.RegisteredService] {
	var measurementSource services.MeasurementSource
	if g.config.MeasurementsURL != "" {
		measurementSource = services.NewRemoteMeasurementSource(g.config.MeasurementsURL)
	} else {
		measurementSource = services.DemoMeasurementSource()
	}
	provider := &tdx.DummyProvider{}

	verified := make([]*protocol.Signed[services.RegisteredService], 0, len(signed))
	for _, svc := range signed {
		if _, err := services.VerifyRegistration(measurementSource, provider, svc); err != nil {
			continue
		}
		verified = append(verified, svc)
	}
	return verified
}

func (g *Gateway) checkServiceHealth() {
	g.mu.RLock()
	svcList := g.services
	g.mu.RUnlock()

	if svcList == nil {
		return
	}

	health := make(map[string]bool)

	checkHealth := func(endpoint string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint+"/health", nil)
		resp, err := g.httpClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	for _, svc := range svcList.Servers {
		health[svc.Object.PublicKey] = checkHealth(svc.Object.HTTPEndpoint)
	}
	for _, svc := range svcList.Aggregators {
		health[svc.Object.PublicKey] = checkHealth(svc.Object.HTTPEndpoint)
	}
	for _, svc := range svcList.Clients {
		health[svc.Object.PublicKey] = checkHealth(svc.Object.HTTPEndpoint)
	}

	g.mu.Lock()
	g.serviceHealth = health
	g.mu.Unlock()
}

func (g *Gateway) pollRounds() {
	g.mu.RLock()
	svcList := g.services
	config := g.adcConfig
	prevAuction := g.previousAuction
	latestRound := g.latestRound
	g.mu.RUnlock()

	if svcList == nil || len(svcList.Servers) == 0 || config == nil {
		return
	}

	broadcast := g.fetchLatestBroadcast(svcList.Servers)
	if broadcast == nil || broadcast.RoundNumber <= latestRound {
		return
	}

	detail := g.decodeRound(broadcast, prevAuction, config)

	g.mu.Lock()
	g.rounds[broadcast.RoundNumber] = detail
	g.latestRound = broadcast.RoundNumber
	g.previousAuction = broadcast.AuctionVector

	if len(g.rounds) > 100 {
		minRound := g.latestRound - 100
		for r := range g.rounds {
			if r < minRound {
				delete(g.rounds, r)
			}
		}
	}
	g.mu.Unlock()

	event := &RoundEvent{
		Round:     detail.Number,
		Timestamp: detail.Timestamp,
		Messages:  detail.Messages,
		Bids:      detail.Bids,
	}
	g.broadcast(event)

	fmt.Printf("Round %d: %d messages, %d bids, %.1f%% bandwidth\n",
		detail.Number, len(detail.Messages), len(detail.Bids), detail.Bandwidth.Utilization*100)
}

func (g *Gateway) fetchLatestBroadcast(servers []*protocol.Signed[services.RegisteredService]) *protocol.RoundBroadcast {
	for _, srv := range servers {
		url := fmt.Sprintf("%s/round-broadcast/0", srv.Object.HTTPEndpoint)
		resp, err := g.httpClient.Get(url)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		var broadcastResp services.RoundBroadcastResponse
		if err := json.NewDecoder(resp.Body).Decode(&broadcastResp); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		if broadcastResp.Broadcast == nil {
			continue
		}

		broadcast, signer, err := broadcastResp.Broadcast.Recover()
		if err != nil || signer.String() != srv.Object.PublicKey {
			continue
		}

		return broadcast
	}
	return nil
}

func (g *Gateway) decodeRound(broadcast *protocol.RoundBroadcast, prevAuction *blind_auction.IBLTVector, config *protocol.ADCNetConfig) *RoundDetail {
	detail := &RoundDetail{
		Number:    broadcast.RoundNumber,
		Timestamp: time.Now().Format(time.RFC3339),
		Messages:  []MessageOutput{},
		Bids:      []BidOutput{},
		Bandwidth: BandwidthStats{
			Total: config.MessageLength,
		},
	}

	// Decode current round's auction (bids for next round)
	currentChunks, err := broadcast.AuctionVector.Recover()
	if err == nil {
		winningHashes := make(map[string]bool)

		// Calculate which bids would win
		if len(currentChunks) > 0 {
			currentBids := make([]blind_auction.AuctionData, len(currentChunks))
			for i, chunk := range currentChunks {
				currentBids[i] = *blind_auction.AuctionDataFromChunk(chunk)
			}
			winners := blind_auction.NewAuctionEngine(uint32(config.MessageLength), 1).RunAuction(currentBids)
			for _, w := range winners {
				winningHashes[hex.EncodeToString(w.Bid.MessageHash[:8])] = true
			}
		}

		for _, chunk := range currentChunks {
			bid := blind_auction.AuctionDataFromChunk(chunk)
			hashStr := hex.EncodeToString(bid.MessageHash[:8])
			detail.Bids = append(detail.Bids, BidOutput{
				MessageHash: hashStr,
				Weight:      bid.Weight,
				Size:        bid.Size,
				Won:         winningHashes[hashStr],
			})
		}
	}

	detail.AuctionBids = len(detail.Bids)

	if prevAuction == nil {
		return detail
	}

	chunks, err := prevAuction.Recover()
	if err != nil {
		return detail
	}

	bids := make([]blind_auction.AuctionData, len(chunks))
	for i, chunk := range chunks {
		bids[i] = *blind_auction.AuctionDataFromChunk(chunk)
	}

	winners := blind_auction.NewAuctionEngine(uint32(config.MessageLength), 1).RunAuction(bids)

	for _, winner := range winners {
		if int(winner.SlotIdx+winner.SlotSize) > len(broadcast.MessageVector) {
			continue
		}

		msgBytes := broadcast.MessageVector[winner.SlotIdx : winner.SlotIdx+winner.SlotSize]
		msgBytes = bytes.TrimRight(msgBytes, "\x00")

		msg := MessageOutput{
			Offset: winner.SlotIdx,
			Size:   winner.SlotSize,
		}

		if isPrintable(msgBytes) {
			msg.Content = string(msgBytes)
		} else {
			msg.Content = hex.EncodeToString(msgBytes)
			msg.Binary = true
		}

		detail.Messages = append(detail.Messages, msg)
		detail.Bandwidth.Used += int(winner.SlotSize)
	}

	if detail.Bandwidth.Total > 0 {
		detail.Bandwidth.Utilization = float64(detail.Bandwidth.Used) / float64(detail.Bandwidth.Total)
	}

	return detail
}

func (g *Gateway) broadcast(event *RoundEvent) {
	g.subscribersMu.RLock()
	defer g.subscribersMu.RUnlock()

	for ch := range g.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
