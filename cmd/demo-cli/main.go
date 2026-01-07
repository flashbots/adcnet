// Command adcnet provides CLI tools for interacting with a deployed ADCNet network.
//
// # Commands
//
// send: Submit a message to the network with an auction bid.
//
//	adcnet send --registry=https://adcnet.example.com --message="Hello" --bid=100
//
// monitor: Stream round outputs as they complete.
//
//	adcnet monitor --registry=https://adcnet.example.com
//
// status: Display network topology and health.
//
//	adcnet status --registry=https://adcnet.example.com
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	blind_auction "github.com/flashbots/adcnet/blind-auction"
	"github.com/flashbots/adcnet/crypto"
	"github.com/flashbots/adcnet/protocol"
	"github.com/flashbots/adcnet/services"
	"github.com/flashbots/adcnet/tdx"
)

// verificationConfig holds attestation verification settings.
type verificationConfig struct {
	measurementsURL  string
	skipVerification bool
}

func (v *verificationConfig) measurementSource() services.MeasurementSource {
	if v.skipVerification {
		return nil
	}
	if v.measurementsURL != "" {
		return services.NewRemoteMeasurementSource(v.measurementsURL)
	}
	return services.DemoMeasurementSource()
}

func (v *verificationConfig) attestationProvider() services.TEEProvider {
	if v.skipVerification {
		return nil
	}
	return &tdx.DummyProvider{}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "send":
		err = runSend(args)
	case "monitor":
		err = runMonitor(args)
	case "status":
		err = runStatus(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`adcnet - CLI tools for ADCNet

Usage:
  adcnet <command> [options]

Commands:
  send      Send a message to the network
  monitor   Stream round outputs
  status    Display network status

Run 'adcnet <command> --help' for command-specific options.`)
}

// --- Send Command ---

func runSend(args []string) error {
	var (
		registryURL string
		message     string
		filePath    string
		bidValue    uint
		wait        bool
		timeout     time.Duration
		verifyCfg   verificationConfig
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--registry", "-r":
			i++
			if i < len(args) {
				registryURL = args[i]
			}
		case "--message", "-m":
			i++
			if i < len(args) {
				message = args[i]
			}
		case "--file", "-f":
			i++
			if i < len(args) {
				filePath = args[i]
			}
		case "--bid", "-b":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &bidValue)
			}
		case "--wait", "-w":
			wait = true
		case "--timeout":
			i++
			if i < len(args) {
				timeout, _ = time.ParseDuration(args[i])
			}
		case "--measurements-url":
			i++
			if i < len(args) {
				verifyCfg.measurementsURL = args[i]
			}
		case "--skip-verification":
			verifyCfg.skipVerification = true
		case "--help", "-h":
			printSendHelp()
			return nil
		}
	}

	if registryURL == "" {
		registryURL = "http://localhost:7999"
	}
	if message == "" && filePath == "" {
		return fmt.Errorf("--message or --file is required")
	}
	if bidValue == 0 {
		return fmt.Errorf("--bid is required and must be > 0")
	}
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	var msgBytes []byte
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}
		msgBytes = data
	} else {
		msgBytes = []byte(message)
	}

	return sendMessage(registryURL, msgBytes, uint32(bidValue), wait, timeout, &verifyCfg)
}

func printSendHelp() {
	fmt.Println(`adcnet send - Send a message to the network

Usage:
  adcnet send --registry=<url> --message=<text> --bid=<value>
  adcnet send --registry=<url> --to=<pubkey> --message=<text> --bid=<value>

Options:
  --registry, -r        Registry URL (required)
  --message, -m         Message text to send
  --file, -f            File to send as message
  --bid, -b             Auction bid value (required)
  --to, -t              Recipient's exchange public key (hex) for E2E encryption
  --wait, -w            Wait for message to appear in round output
  --timeout             Timeout for --wait (default: 2m)
  --measurements-url    URL for allowed TEE measurements
  --skip-verification   Skip attestation verification (insecure)

Examples:
  # Send message
  adcnet send -r https://adcnet.example.com -m "Hello ADCNet" -b 100`)
}

func sendMessage(registryURL string, message []byte, bidValue uint32, wait bool, timeout time.Duration, verifyCfg *verificationConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: 30 * time.Second}

	fmt.Println("Fetching network configuration...")
	adcConfig, err := fetchConfig(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	fmt.Println("Discovering services...")
	serviceList, err := fetchServices(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch services: %w", err)
	}

	if len(serviceList.Clients) == 0 {
		return fmt.Errorf("no clients available")
	}

	fmt.Println("Verifying server attestations...")
	verifiedServers, err := verifyServices(serviceList.Servers, verifyCfg)
	if err != nil {
		return fmt.Errorf("server verification failed: %w", err)
	}
	if len(verifiedServers) == 0 {
		return fmt.Errorf("no clients passed attestation verification")
	}

	fmt.Println("Verifying client attestations...")
	verifiedClients, err := verifyServices(serviceList.Clients, verifyCfg)
	if err != nil {
		return fmt.Errorf("client verification failed: %w", err)
	}
	if len(verifiedClients) == 0 {
		return fmt.Errorf("no clients passed attestation verification")
	}

	fmt.Printf("Verified %d clients and %d servers\n", len(verifiedClients), len(verifiedServers))

	clientService := verifiedClients[len(verifiedClients)-1]
	clientServiceExchangeKey, err := services.ParseExchangeKey(clientService.Object.ExchangeKey)
	if err != nil {
		return fmt.Errorf("could not parse client exchange: %w", err)
	}

	messageData := services.HTTPClientMessage{Message: message, Value: int(bidValue)}
	messagePlaintext, err := json.Marshal(messageData)
	if err != nil {
		return fmt.Errorf("could not marshal message: %w", err)
	}
	encryptedMessage, err := crypto.Encrypt(clientServiceExchangeKey, messagePlaintext)
	if err != nil {
		return fmt.Errorf("could not encrypt message: %w", err)
	}

	body, err := json.Marshal(encryptedMessage)
	if err != nil {
		return fmt.Errorf("could not marshal message: %w", err)
	}

	resp, err := http.DefaultClient.Post(clientService.Object.HTTPEndpoint+"/encrypted-message", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sending message failed (%d): %s", resp.StatusCode, string(respBody))
	}

	fmt.Println("Message submitted successfully!")

	if !wait {
		return nil
	}

	fmt.Println("\nWaiting for message confirmation...")
	return waitForMessage(ctx, httpClient, verifiedServers, message, adcConfig)
}

func verifyServices(signedServices []*protocol.Signed[services.RegisteredService], verifyCfg *verificationConfig) ([]*protocol.Signed[services.RegisteredService], error) {
	if verifyCfg.skipVerification {
		return signedServices, nil
	}

	measurementSource := verifyCfg.measurementSource()
	attestationProvider := verifyCfg.attestationProvider()

	verified := make([]*protocol.Signed[services.RegisteredService], 0, len(signedServices))

	for _, signed := range signedServices {
		_, err := services.VerifyRegistration(measurementSource, attestationProvider, signed)
		if err != nil {
			fmt.Printf("Warning: attestation verification failed for %s: %v\n", signed.Object.HTTPEndpoint, err)
			continue
		}
		verified = append(verified, signed)
	}

	return verified, nil
}

func waitForMessage(ctx context.Context, httpClient *http.Client, servers []*protocol.Signed[services.RegisteredService], message []byte, config *protocol.ADCNetConfig) error {
	roundCoord := protocol.NewLocalRoundCoordinator(config.RoundDuration)
	roundCoord.Start(ctx)
	roundChan := roundCoord.SubscribeToRounds(ctx)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for message")
		case round := <-roundChan:
			// Poll for previous round's broadcast when entering client phase
			if round.Context != protocol.ClientRoundContext {
				continue
			}
			srv := servers[0] // Leader is the first server
			broadcast, err := fetchRoundBroadcast(httpClient, srv.Object.HTTPEndpoint, 0)
			if err != nil {
				continue
			}

			if bytes.Contains(broadcast.MessageVector, message) {
				fmt.Printf("\n✓ Message confirmed in round %d!\n", broadcast.RoundNumber)
				return nil
			}

			fmt.Printf("Round %d complete, message not found (checking if bid lost auction)\n", broadcast.RoundNumber)
		}
	}
}

// --- Monitor Command ---

func runMonitor(args []string) error {
	var (
		registryURL string
		format      string
		follow      bool
		roundNumber int
		outputFile  string
		decryptKey  string
		verifyCfg   verificationConfig
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--registry", "-r":
			i++
			if i < len(args) {
				registryURL = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--follow":
			follow = true
		case "--round":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &roundNumber)
			}
		case "--output", "-o":
			i++
			if i < len(args) {
				outputFile = args[i]
			}
		case "--decrypt-key":
			i++
			if i < len(args) {
				decryptKey = args[i]
			}
		case "--measurements-url":
			i++
			if i < len(args) {
				verifyCfg.measurementsURL = args[i]
			}
		case "--skip-verification":
			verifyCfg.skipVerification = true
		case "--help", "-h":
			printMonitorHelp()
			return nil
		}
	}

	if registryURL == "" {
		return fmt.Errorf("--registry is required")
	}
	if format == "" {
		format = "text"
	}

	var decryptPrivKey *ecdh.PrivateKey
	if decryptKey != "" {
		keyBytes, err := hex.DecodeString(decryptKey)
		if err != nil {
			return fmt.Errorf("invalid decrypt key: %w", err)
		}
		decryptPrivKey, err = ecdh.P256().NewPrivateKey(keyBytes)
		if err != nil {
			return fmt.Errorf("invalid decrypt private key: %w", err)
		}
	}

	return monitorRounds(registryURL, format, follow, roundNumber, outputFile, decryptPrivKey, &verifyCfg)
}

func printMonitorHelp() {
	fmt.Println(`adcnet monitor - Stream round outputs

Usage:
  adcnet monitor --registry=<url> [options]

Options:
  --registry, -r        Registry URL (required)
  --format, -f          Output format: text, json (default: text)
  --follow              Continuously stream new rounds
  --round               Fetch a specific round number
  --output, -o          Write output to file
  --decrypt-key         Your ECDH private key (hex) to decrypt messages
  --measurements-url    URL for allowed TEE measurements
  --skip-verification   Skip attestation verification (insecure)

Examples:
  adcnet monitor -r https://adcnet.example.com
  adcnet monitor -r https://adcnet.example.com --format=json --follow
  adcnet monitor -r https://adcnet.example.com --decrypt-key=a1b2c3...`)
}

// MonitorOutput represents a decoded round for JSON output.
type MonitorOutput struct {
	RoundNumber int            `json:"round_number"`
	Timestamp   time.Time      `json:"timestamp"`
	Winners     []WinnerOutput `json:"winners"`
}

// WinnerOutput represents an auction winner's message.
type WinnerOutput struct {
	Offset    uint32 `json:"offset"`
	Size      uint32 `json:"size"`
	Content   string `json:"content"`
	Binary    bool   `json:"binary"`
	Encrypted bool   `json:"encrypted,omitempty"`
	Decrypted string `json:"decrypted,omitempty"`
}

func monitorRounds(registryURL, format string, follow bool, specificRound int, outputFile string, decryptKey *ecdh.PrivateKey, verifyCfg *verificationConfig) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		cancel()
	}()

	httpClient := &http.Client{Timeout: 30 * time.Second}

	adcConfig, err := fetchConfig(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	serviceList, err := fetchServices(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch services: %w", err)
	}

	if len(serviceList.Servers) == 0 {
		return fmt.Errorf("no servers available")
	}

	fmt.Fprintln(os.Stderr, "Verifying server attestations...")
	verifiedServers, err := verifyServices(serviceList.Servers, verifyCfg)
	if err != nil {
		return fmt.Errorf("server verification: %w", err)
	}
	if len(verifiedServers) == 0 {
		return fmt.Errorf("no servers passed attestation verification")
	}
	fmt.Fprintf(os.Stderr, "Verified %d servers\n", len(verifiedServers))

	var output io.Writer = os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	if specificRound > 0 {
		return fetchAndPrintRound(httpClient, verifiedServers, specificRound, adcConfig, format, output, decryptKey)
	}

	currentRound, _ := protocol.RoundForTime(time.Now(), adcConfig.RoundDuration)
	lastPrintedRound := currentRound.Number - 1

	if !follow {
		return fetchAndPrintRound(httpClient, verifiedServers, lastPrintedRound, adcConfig, format, output, decryptKey)
	}

	fmt.Fprintln(os.Stderr, "Monitoring round outputs (Ctrl+C to stop)...")

	ticker := time.NewTicker(adcConfig.RoundDuration / 4)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			currentRound, _ = protocol.RoundForTime(time.Now(), adcConfig.RoundDuration)

			for round := lastPrintedRound + 1; round < currentRound.Number; round++ {
				if err := fetchAndPrintRound(httpClient, verifiedServers, round, adcConfig, format, output, decryptKey); err == nil {
					lastPrintedRound = round
				}
			}
		}
	}
}

func fetchAndPrintRound(httpClient *http.Client, servers []*protocol.Signed[services.RegisteredService], roundNumber int, config *protocol.ADCNetConfig, format string, output io.Writer, decryptKey *ecdh.PrivateKey) error {
	var broadcast *protocol.RoundBroadcast
	var signer crypto.PublicKey

	for _, srv := range servers {
		b, s, err := fetchAndVerifyRoundBroadcast(httpClient, srv, roundNumber)
		if err == nil {
			broadcast = b
			signer = s
			break
		}
	}

	if broadcast == nil {
		return fmt.Errorf("round %d not available", roundNumber)
	}

	_ = signer
	return printRoundOutput(broadcast, config, format, output, decryptKey)
}

func fetchAndVerifyRoundBroadcast(httpClient *http.Client, server *protocol.Signed[services.RegisteredService], roundNumber int) (*protocol.RoundBroadcast, crypto.PublicKey, error) {
	url := fmt.Sprintf("%s/round-broadcast/%d", server.Object.HTTPEndpoint, roundNumber)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var broadcastResp services.RoundBroadcastResponse
	if err := json.NewDecoder(resp.Body).Decode(&broadcastResp); err != nil {
		return nil, nil, err
	}

	if broadcastResp.Broadcast == nil {
		return nil, nil, fmt.Errorf("no broadcast")
	}

	broadcast, signer, err := broadcastResp.Broadcast.Recover()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature: %w", err)
	}

	if signer.String() != server.Object.PublicKey {
		return nil, nil, fmt.Errorf("broadcast signed by unexpected key")
	}

	return broadcast, signer, nil
}

func fetchRoundBroadcast(httpClient *http.Client, endpoint string, roundNumber int) (*protocol.RoundBroadcast, error) {
	url := fmt.Sprintf("%s/round-broadcast/%d", endpoint, roundNumber)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var broadcastResp services.RoundBroadcastResponse
	if err := json.NewDecoder(resp.Body).Decode(&broadcastResp); err != nil {
		return nil, err
	}

	if broadcastResp.Broadcast == nil {
		return nil, fmt.Errorf("no broadcast")
	}

	broadcast, _, err := broadcastResp.Broadcast.Recover()
	return broadcast, err
}

func printRoundOutput(broadcast *protocol.RoundBroadcast, config *protocol.ADCNetConfig, format string, output io.Writer, decryptKey *ecdh.PrivateKey) error {
	chunks, err := broadcast.AuctionVector.Recover()
	if err != nil {
		chunks = nil
	}

	var winners []blind_auction.AuctionWinner
	if len(chunks) > 0 {
		bids := make([]blind_auction.AuctionData, len(chunks))
		for i, chunk := range chunks {
			bids[i] = *blind_auction.AuctionDataFromChunk(chunk)
		}
		winners = blind_auction.NewAuctionEngine(uint32(config.MessageLength), 1).RunAuction(bids)
	}

	if format == "json" {
		return printRoundJSON(broadcast, winners, output, decryptKey)
	}
	return printRoundText(broadcast, winners, output, decryptKey)
}

func printRoundText(broadcast *protocol.RoundBroadcast, winners []blind_auction.AuctionWinner, output io.Writer, decryptKey *ecdh.PrivateKey) error {
	fmt.Fprintf(output, "=== Round %d ===\n", broadcast.RoundNumber)
	fmt.Fprintf(output, "Timestamp: %s\n", time.Now().Format(time.RFC3339))

	if len(winners) == 0 {
		fmt.Fprintln(output, "No messages in this round")
	} else {
		fmt.Fprintf(output, "Messages: %d\n", len(winners))
		for i, winner := range winners {
			msgBytes := broadcast.MessageVector[winner.SlotIdx : winner.SlotIdx+winner.SlotSize]

			// Try to decrypt if key provided and message looks encrypted
			decrypted := tryDecrypt(msgBytes, decryptKey)

			if decrypted != nil {
				fmt.Fprintf(output, "  [%d] offset=%d size=%d: [ENCRYPTED → DECRYPTED] %q\n", i, winner.SlotIdx, winner.SlotSize, string(decrypted))
			} else if isPrintable(msgBytes) {
				if len(msgBytes) > 80 {
					fmt.Fprintf(output, "  [%d] offset=%d size=%d: %q...\n", i, winner.SlotIdx, winner.SlotSize, string(msgBytes[:80]))
				} else {
					fmt.Fprintf(output, "  [%d] offset=%d size=%d: %q\n", i, winner.SlotIdx, winner.SlotSize, string(msgBytes))
				}
			} else {
				fmt.Fprintf(output, "  [%d] offset=%d size=%d: <binary %d bytes>\n", i, winner.SlotIdx, winner.SlotSize, len(msgBytes))
			}
		}
	}
	fmt.Fprintln(output, "======================")
	return nil
}

func printRoundJSON(broadcast *protocol.RoundBroadcast, winners []blind_auction.AuctionWinner, output io.Writer, decryptKey *ecdh.PrivateKey) error {
	out := MonitorOutput{
		RoundNumber: broadcast.RoundNumber,
		Timestamp:   time.Now(),
		Winners:     make([]WinnerOutput, len(winners)),
	}

	for i, winner := range winners {
		msgBytes := broadcast.MessageVector[winner.SlotIdx : winner.SlotIdx+winner.SlotSize]

		wo := WinnerOutput{
			Offset:  winner.SlotIdx,
			Size:    winner.SlotSize,
			Content: string(msgBytes),
			Binary:  !isPrintable(msgBytes),
		}

		decrypted := tryDecrypt(msgBytes, decryptKey)
		if decrypted != nil {
			wo.Encrypted = true
			wo.Decrypted = string(decrypted)
		}

		out.Winners[i] = wo
	}

	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func tryDecrypt(data []byte, privKey *ecdh.PrivateKey) []byte {
	if privKey == nil {
		return nil
	}

	encrypted, err := crypto.ParseEncryptedMessage(data)
	if err != nil {
		return nil
	}

	plaintext, err := crypto.Decrypt(privKey, encrypted)
	if err != nil {
		return nil
	}

	return plaintext
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// --- Status Command ---

func runStatus(args []string) error {
	var (
		registryURL string
		verifyCfg   verificationConfig
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--registry", "-r":
			i++
			if i < len(args) {
				registryURL = args[i]
			}
		case "--measurements-url":
			i++
			if i < len(args) {
				verifyCfg.measurementsURL = args[i]
			}
		case "--skip-verification":
			verifyCfg.skipVerification = true
		case "--help", "-h":
			printStatusHelp()
			return nil
		}
	}

	if registryURL == "" {
		return fmt.Errorf("--registry is required")
	}

	return showStatus(registryURL, &verifyCfg)
}

func printStatusHelp() {
	fmt.Println(`adcnet status - Display network status

Usage:
  adcnet status --registry=<url>

Options:
  --registry, -r        Registry URL (required)
  --measurements-url    URL for allowed TEE measurements
  --skip-verification   Skip attestation verification (insecure)

Example:
  adcnet status -r https://adcnet.example.com`)
}

func showStatus(registryURL string, verifyCfg *verificationConfig) error {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	adcConfig, err := fetchConfig(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}

	serviceList, err := fetchServices(httpClient, registryURL)
	if err != nil {
		return fmt.Errorf("fetch services: %w", err)
	}

	currentRound, _ := protocol.RoundForTime(time.Now(), adcConfig.RoundDuration)
	nextRoundTime := protocol.TimeForRound(currentRound.Advance(), adcConfig.RoundDuration)
	timeUntilNext := time.Until(nextRoundTime)

	verifiedServers, _ := verifyServices(serviceList.Servers, verifyCfg)
	verifiedAggregators, _ := verifyServices(serviceList.Aggregators, verifyCfg)

	serversOnline := 0
	for _, srv := range verifiedServers {
		if checkHealth(httpClient, srv.Object.HTTPEndpoint) {
			serversOnline++
		}
	}

	aggregatorsOnline := 0
	for _, agg := range verifiedAggregators {
		if checkHealth(httpClient, agg.Object.HTTPEndpoint) {
			aggregatorsOnline++
		}
	}

	fmt.Printf("Registry: %s\n", registryURL)
	fmt.Printf("Round: %d (next in %.1fs)\n", currentRound.Number, timeUntilNext.Seconds())
	fmt.Printf("Servers: %d/%d online (%d/%d attested)\n", serversOnline, len(verifiedServers), len(verifiedServers), len(serviceList.Servers))
	fmt.Printf("Aggregators: %d/%d online (%d/%d attested)\n", aggregatorsOnline, len(verifiedAggregators), len(verifiedAggregators), len(serviceList.Aggregators))
	fmt.Printf("Clients: %d registered\n", len(serviceList.Clients))
	fmt.Println("Config:")
	fmt.Printf("  Round duration: %s\n", adcConfig.RoundDuration)
	fmt.Printf("  Message capacity: %d bytes\n", adcConfig.MessageLength)
	fmt.Printf("  Auction slots: %d\n", adcConfig.AuctionSlots)
	fmt.Printf("  Min clients: %d\n", adcConfig.MinClients)

	return nil
}

func checkHealth(httpClient *http.Client, endpoint string) bool {
	resp, err := httpClient.Get(endpoint + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// --- Shared Utilities ---

func fetchConfig(httpClient *http.Client, registryURL string) (*protocol.ADCNetConfig, error) {
	resp, err := httpClient.Get(registryURL + "/config")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}

	return protocol.DecodeMessage[protocol.ADCNetConfig](resp.Body)
}

func fetchServices(httpClient *http.Client, registryURL string) (*services.ServiceListResponse, error) {
	resp, err := httpClient.Get(registryURL + "/services")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}

	var list services.ServiceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return &list, nil
}
