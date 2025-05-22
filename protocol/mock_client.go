package protocol

import (
	"context"

	"github.com/ruteri/go-zipnet/crypto"
)

// MockClient implements the Client interface for testing purposes.
// It allows customization of behavior by setting function implementations.
type MockClient struct {
	nSlots uint32
	publicKey          crypto.PublicKey
	prepareMessageFunc func(ctx context.Context, round int, 
		previousRoundOutput *Signed[ServerRoundData], 
		message []byte, 
		auctionData *AuctionData) (*ClientRoundMessage, bool, error)
	processRoundDataFunc func(ctx context.Context, round int, 
		roundData *Signed[ServerRoundData]) ([]byte, error)
}

// NewMockClient creates a new mock client with default implementations.
func NewMockClient(publicKey crypto.PublicKey, nSlots uint32) *MockClient {
	return &MockClient{
		publicKey: publicKey,
		prepareMessageFunc: func(ctx context.Context, round int, 
			previousRoundOutput *Signed[ServerRoundData], 
			message []byte, 
			auctionData *AuctionData) (*ClientRoundMessage, bool, error) {
			
			// Create a default mock message
			ibfVector := NewIBFVector(nSlots)
			if auctionData != nil {
				ibfVector.InsertChunk(auctionData.EncodeToChunk())
			}
			
			return &ClientRoundMessage{
				RoundNubmer:    round,
				IBFVector:      ibfVector,
				MessageVector:  make([]byte, 16000), // Default size
			}, true, nil
		},
		processRoundDataFunc: func(ctx context.Context, round int, 
			roundData *Signed[ServerRoundData]) ([]byte, error) {
			return roundData.Object.MessageVector, nil
		},
	}
}

// GetPublicKey returns the mock client's public key.
func (m *MockClient) GetPublicKey() crypto.PublicKey {
	return m.publicKey
}

// PrepareMessage implements the Client interface for message preparation.
func (m *MockClient) PrepareMessage(ctx context.Context, round int, 
	previousRoundOutput *Signed[ServerRoundData], 
	message []byte, 
	auctionData *AuctionData) (*ClientRoundMessage, bool, error) {
	
	return m.prepareMessageFunc(ctx, round, previousRoundOutput, message, auctionData)
}

// ProcessRoundData implements the Client interface for processing broadcast data.
func (m *MockClient) ProcessRoundData(ctx context.Context, round int, 
	roundData *Signed[ServerRoundData]) ([]byte, error) {
	
	return m.processRoundDataFunc(ctx, round, roundData)
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
func (m *MockClient) SetPrepareMessageFunc(fn func(ctx context.Context, round int, 
	previousRoundOutput *Signed[ServerRoundData], 
	message []byte, 
	auctionData *AuctionData) (*ClientRoundMessage, bool, error)) {
	
	m.prepareMessageFunc = fn
}

// SetProcessRoundDataFunc allows customization of the ProcessRoundData implementation.
func (m *MockClient) SetProcessRoundDataFunc(fn func(ctx context.Context, round int, 
	roundData *Signed[ServerRoundData]) ([]byte, error)) {
	
	m.processRoundDataFunc = fn
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

func (m *mockCryptoProvider) KDF(masterKey crypto.SharedKey, round uint64, context []byte, ibfPadLength, msgVecPadLength int) ([]byte, []byte, error) {
	ibfPad := make([]byte, ibfPadLength)
	msgVecPad := make([]byte, msgVecPadLength)
	return ibfPad, msgVecPad, nil
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

func (m *mockNetworkTransport) SendToAggregator(ctx context.Context, aggregatorID string, message *Signed[ClientRoundMessage]) error {
	return nil
}

func (m *mockNetworkTransport) SendAggregateToAggregator(ctx context.Context, aggregatorID string, message *Signed[AggregatedClientMessages]) error {
	return nil
}

func (m *mockNetworkTransport) SendAggregateToServer(ctx context.Context, serverID string, message *Signed[AggregatedClientMessages]) error {
	return nil
}

func (m *mockNetworkTransport) SendShareToServer(ctx context.Context, serverID string, message *Signed[ServerPartialDecryptionMessage]) error {
	return nil
}

func (m *mockNetworkTransport) FetchRoundData(ctx context.Context, serverID string, round int) (*Signed[ServerRoundData], error) {
	return nil, nil
}

func (m *mockNetworkTransport) BroadcastToClients(ctx context.Context, message *Signed[ServerRoundData]) error {
	return nil
}

func (m *mockNetworkTransport) RegisterMessageHandler(handler func([]byte) error) error {
	return nil
}
