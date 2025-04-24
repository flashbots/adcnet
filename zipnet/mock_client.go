package zipnet

import (
	"context"

	"github.com/ruteri/go-zipnet/crypto"
)

// MockClient implements the Client interface for testing purposes.
// It allows customization of behavior by setting function implementations.
type MockClient struct {
	publicKey        crypto.PublicKey
	prepareMessage   func(ctx context.Context, round uint64, msg []byte, requestSlot bool, publishedSchedule []byte) (*ClientMessage, error)
	processBroadcast func(ctx context.Context, round uint64, broadcast []byte) ([]byte, error)
}

// NewMockClient creates a new mock client with default implementations.
func NewMockClient(publicKey crypto.PublicKey) *MockClient {
	return &MockClient{
		publicKey: publicKey,
		prepareMessage: func(ctx context.Context, round uint64, msg []byte, requestSlot bool, publishedSchedule []byte) (*ClientMessage, error) {
			return &ClientMessage{
				Round:        round,
				NextSchedVec: make([]byte, 400),   // Default size
				MsgVec:       make([]byte, 16000), // Default size (100 slots * 160 bytes)
				Signature:    crypto.NewSignature([]byte("mock-signature")),
			}, nil
		},
		processBroadcast: func(ctx context.Context, round uint64, broadcast []byte) ([]byte, error) {
			return broadcast, nil
		},
	}
}

// GetPublicKey returns the mock client's public key.
func (m *MockClient) GetPublicKey() crypto.PublicKey {
	return m.publicKey
}

// SubmitMessage implements the Client interface for message submission.
func (m *MockClient) SubmitMessage(ctx context.Context, round uint64, msg []byte, requestSlot bool, publishedSchedule PublishedSchedule) (*ClientMessage, error) {
	return m.prepareMessage(ctx, round, msg, requestSlot, publishedSchedule.Footprints)
}

// SendCoverTraffic implements the Client interface for sending cover traffic.
func (m *MockClient) SendCoverTraffic(ctx context.Context, round uint64, publishedSchedule PublishedSchedule) (*ClientMessage, error) {
	return m.SubmitMessage(ctx, round, nil, false, publishedSchedule)
}

// ReserveSlot implements the Client interface for slot reservation.
func (m *MockClient) ReserveSlot(ctx context.Context, round uint64, publishedSchedule PublishedSchedule) (*ClientMessage, error) {
	return m.SubmitMessage(ctx, round, nil, true, publishedSchedule)
}

// ProcessBroadcast returns a mock broadcast processing result for testing.
func (m *MockClient) ProcessBroadcast(ctx context.Context, round uint64, broadcast []byte) ([]byte, error) {
	return m.processBroadcast(ctx, round, broadcast)
}

// GetTimesParticipated returns a mock count of participation.
func (m *MockClient) GetTimesParticipated() uint32 {
	return 0
}

// RegisterServerPublicKey implements the Client interface for server registration.
func (m *MockClient) RegisterServerPublicKey(serverID string, publicKey crypto.PublicKey) error {
	return nil
}

// SetPrepareMessageFunc allows customization of the PrepareMessage implementation.
func (m *MockClient) SetPrepareMessageFunc(fn func(ctx context.Context, round uint64, msg []byte, requestSlot bool, publishedSchedule []byte) (*ClientMessage, error)) {
	m.prepareMessage = fn
}

// SetProcessBroadcastFunc allows customization of the ProcessBroadcast implementation.
func (m *MockClient) SetProcessBroadcastFunc(fn func(ctx context.Context, round uint64, broadcast []byte) ([]byte, error)) {
	m.processBroadcast = fn
}

// NewMockTEE creates a mock TEE implementation for testing.
func NewMockTEE() TEE {
	return &mockTEE{}
}

type mockTEE struct{}

func (m *mockTEE) Attest() ([]byte, error) {
	return []byte("mock-attestation"), nil
}

func (m *mockTEE) VerifyAttestation(attestation []byte) (bool, error) {
	return true, nil
}

func (m *mockTEE) SealData(data []byte) ([]byte, error) {
	return data, nil
}

func (m *mockTEE) UnsealData(sealedData []byte) ([]byte, error) {
	return sealedData, nil
}

func (m *mockTEE) GenerateKeys() (crypto.PublicKey, crypto.PrivateKey, error) {
	return crypto.NewPublicKeyFromBytes([]byte("mock-public-key")),
		crypto.NewPrivateKeyFromBytes([]byte("mock-private-key")),
		nil
}

func (m *mockTEE) Sign(data []byte) (crypto.Signature, error) {
	return crypto.NewSignature([]byte("mock-signature")), nil
}

// NewMockCryptoProvider creates a mock crypto provider for testing.
func NewMockCryptoProvider() CryptoProvider {
	return &mockCryptoProvider{}
}

type mockCryptoProvider struct{}

func (m *mockCryptoProvider) DeriveSharedSecret(privateKey crypto.PrivateKey, otherPublicKey crypto.PublicKey) (crypto.SharedKey, error) {
	return crypto.NewSharedKey([]byte("mock-shared-secret")), nil
}

func (m *mockCryptoProvider) KDF(masterKey crypto.SharedKey, round uint64, publishedSchedule []byte) ([]byte, []byte, error) {
	pad1 := make([]byte, 400)     // Match SchedulingSlots
	pad2 := make([]byte, 100*160) // Match MessageSlots * MessageSize
	return pad1, pad2, nil
}

func (m *mockCryptoProvider) Sign(privateKey crypto.PrivateKey, data []byte) (crypto.Signature, error) {
	return crypto.NewSignature([]byte("mock-signature")), nil
}

func (m *mockCryptoProvider) Verify(publicKey crypto.PublicKey, data []byte, signature crypto.Signature) error {
	return nil
}

func (m *mockCryptoProvider) Hash(data []byte) (crypto.Hash, error) {
	return crypto.NewHash([]byte("mock-hash")), nil
}

func (m *mockCryptoProvider) RatchetKey(key crypto.SharedKey) (crypto.SharedKey, error) {
	return crypto.NewSharedKey([]byte("ratcheted-key")), nil
}

// NewMockNetworkTransport creates a mock network transport for testing.
func NewMockNetworkTransport() NetworkTransport {
	return &mockNetworkTransport{}
}

type mockNetworkTransport struct{}

func (m *mockNetworkTransport) SendToAggregator(ctx context.Context, aggregatorID string, message *ClientMessage) error {
	return nil
}

func (m *mockNetworkTransport) SendAggregateToServer(ctx context.Context, serverID string, message *AggregatorMessage) error {
	return nil
}

func (m *mockNetworkTransport) SendShareToServer(ctx context.Context, serverID string, message *UnblindedShareMessage) error {
	return nil
}

func (m *mockNetworkTransport) BroadcastToClients(ctx context.Context, message *ServerMessage) error {
	return nil
}

func (m *mockNetworkTransport) RegisterMessageHandler(handler func([]byte) error) error {
	return nil
}

// NewMockScheduler creates a mock scheduler for testing.
func NewMockScheduler() Scheduler {
	return &mockScheduler{}
}

type mockScheduler struct{}

func (m *mockScheduler) ComputeScheduleSlot(key []byte, round uint64) (uint32, crypto.Footprint, error) {
	return 0, crypto.NewFootprint([]byte("mock-footprint")), nil
}

func (m *mockScheduler) VerifySchedule(schedule PublishedSchedule, serverPK crypto.PublicKey) (bool, error) {
	return true, nil
}

func (m *mockScheduler) MapScheduleToMessageSlot(scheduleSlot uint32, schedule PublishedSchedule) (uint32, error) {
	return 0, nil
}
