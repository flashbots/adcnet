package testutil

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ruteri/go-zipnet/crypto"
	"github.com/ruteri/go-zipnet/zipnet"
)

// UpdatedAggregatorMessageHelpers provides updated helpers for working with signed aggregator messages

// GenerateTestSignedAggregatorMessage creates a signed aggregator message for testing
func GenerateTestSignedAggregatorMessage(options ...AggregatorMessageOption) *zipnet.Signed[zipnet.AggregatorMessage] {
	// Generate test key pair for signing
	_, privateKey, _ := GenerateTestKeyPair()

	// Generate the aggregator message
	msg := GenerateTestAggregatorMessage(options...)

	// Sign the message
	signed, _ := zipnet.NewSigned(privateKey, msg)
	return signed
}

// GenerateTestSignedAggregatorMessageFromClients creates a signed aggregator message from client messages
func GenerateTestSignedAggregatorMessageFromClients(
	clientMessages []*zipnet.ClientMessage,
	clientPKs []crypto.PublicKey,
	privateKey crypto.PrivateKey,
	options ...AggregatorMessageOption) *zipnet.Signed[zipnet.AggregatorMessage] {

	// Generate the aggregator message
	msg := GenerateTestAggregatorMessageFromClients(clientMessages, clientPKs, options...)

	// Sign the message
	signed, _ := zipnet.NewSigned(privateKey, msg)
	return signed
}

// UpdatedTestHelpers adds additional helper functions for working with Signed messages

// ExtractMessageFromSignedAggregator extracts the message vector from a signed aggregator message
func ExtractMessageFromSignedAggregator(signedMsg *zipnet.Signed[zipnet.AggregatorMessage]) []byte {
	return signedMsg.UnsafeObject().MsgVec
}

// ExtractUserPKsFromSignedAggregator extracts the user public keys from a signed aggregator message
func ExtractUserPKsFromSignedAggregator(signedMsg *zipnet.Signed[zipnet.AggregatorMessage]) []crypto.PublicKey {
	return signedMsg.UnsafeObject().UserPKs
}

// ExtractMessageSlotFromSignedAggregator extracts a specific message slot from a signed aggregator message
func ExtractMessageSlotFromSignedAggregator(signedMsg *zipnet.Signed[zipnet.AggregatorMessage], slot int, msgSize int) []byte {
	msgVec := signedMsg.UnsafeObject().MsgVec
	return ExtractMessageFromSlot(msgVec, slot, msgSize)
}

// Existing TestUtil functions that remain unchanged below...

// =====================================
// Configuration Generators
// =====================================

// TestConfigOption is a function that modifies a ZIPNetConfig
type TestConfigOption func(*zipnet.ZIPNetConfig)

// WithMessageSlots sets the number of message slots
func WithMessageSlots(slots uint32) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.MessageSlots = slots
	}
}

// WithMessageSize sets the message size in bytes
func WithMessageSize(size uint32) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.MessageSize = size
	}
}

// WithSchedulingSlots sets the number of scheduling slots
func WithSchedulingSlots(slots uint32) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.SchedulingSlots = slots
	}
}

// WithFootprintBits sets the size of footprints in bits
func WithFootprintBits(bits uint32) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.FootprintBits = bits
	}
}

// WithMinClients sets the minimum number of clients required
func WithMinClients(clients uint32) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.MinClients = clients
	}
}

// WithRoundDuration sets the round duration
func WithRoundDuration(duration time.Duration) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.RoundDuration = duration
	}
}

// WithServerCount sets the number of anytrust servers
func WithServerCount(count int) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.AnytrustServers = make([]string, count)
		for i := 0; i < count; i++ {
			cfg.AnytrustServers[i] = fmt.Sprintf("server%d.test", i)
		}
	}
}

// WithAggregatorCount sets the number of aggregators
func WithAggregatorCount(count int) TestConfigOption {
	return func(cfg *zipnet.ZIPNetConfig) {
		cfg.Aggregators = make([]string, count)
		for i := 0; i < count; i++ {
			cfg.Aggregators[i] = fmt.Sprintf("agg%d.test", i)
		}
	}
}

// NewTestConfig creates a new ZIPNet configuration with default values
// that can be customized using options
func NewTestConfig(options ...TestConfigOption) *zipnet.ZIPNetConfig {
	// Create default test configuration
	cfg := &zipnet.ZIPNetConfig{
		RoundDuration:   5 * time.Second,
		MessageSlots:    100,
		MessageSize:     160,
		SchedulingSlots: 400,
		FootprintBits:   64,
		MinClients:      10,
		AnytrustServers: []string{"server1.test", "server2.test", "server3.test"},
		Aggregators:     []string{"agg1.test"},
		RoundsPerWindow: 5,
	}

	// Apply all provided options
	for _, option := range options {
		option(cfg)
	}

	return cfg
}

// =====================================
// Crypto Generators
// =====================================

// GenerateRandomBytes generates a slice of random bytes with the specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateTestKeyPair generates a test key pair for testing
func GenerateTestKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	return crypto.GenerateKeyPair()
}

// GenerateTestPublicKeys generates a slice of public keys for testing
func GenerateTestPublicKeys(count int) ([]crypto.PublicKey, error) {
	keys := make([]crypto.PublicKey, count)
	for i := 0; i < count; i++ {
		pubKey, _, err := GenerateTestKeyPair()
		if err != nil {
			return nil, err
		}
		keys[i] = pubKey
	}
	return keys, nil
}

// GenerateTestSignature generates a test signature for testing
func GenerateTestSignature() crypto.Signature {
	// Create a deterministic signature for testing
	return crypto.Signature([]byte("test-signature"))
}

// GenerateUniqueTestSignature generates a unique test signature
func GenerateUniqueTestSignature(id string) crypto.Signature {
	return crypto.Signature([]byte("test-signature-" + id))
}

// GenerateTestFootprint generates a test footprint for a slot
func GenerateTestFootprint(slotNumber uint32, bits uint32) crypto.Footprint {
	// Convert bits to bytes (rounding up)
	bytes := (bits + 7) / 8
	data := make([]byte, bytes)
	// Make the footprint deterministic based on the slot number
	for i := 0; i < int(bytes); i++ {
		data[i] = byte((slotNumber + uint32(i)) % 256)
	}
	return crypto.NewFootprint(data)
}

// =====================================
// Message Generators
// =====================================

// MessageOption is a function that modifies a ScheduleMessage
type MessageOption func(*zipnet.ScheduleMessage)

// WithRound sets the round number for a message
func WithRound(round uint64) MessageOption {
	return func(msg *zipnet.ScheduleMessage) {
		msg.Round = round
	}
}

// WithSchedVec sets the scheduling vector for a message
func WithSchedVec(vec []byte) MessageOption {
	return func(msg *zipnet.ScheduleMessage) {
		msg.NextSchedVec = vec
	}
}

// WithMsgVec sets the message vector for a message
func WithMsgVec(vec []byte) MessageOption {
	return func(msg *zipnet.ScheduleMessage) {
		msg.MsgVec = vec
	}
}

// WithSignature sets the signature for a message
func WithSignature(sig *crypto.Signature) MessageOption {
	return func(msg *zipnet.ScheduleMessage) {
		msg.Signature = *sig
	}
}

// GenerateTestClientMessage generates a test client message with specified options
func GenerateTestClientMessage(options ...MessageOption) *zipnet.ClientMessage {
	msg := &zipnet.ClientMessage{
		Round:        1,
		NextSchedVec: make([]byte, 400),   // Default scheduling vector size
		MsgVec:       make([]byte, 16000), // Default message vector size (100 slots * 160 bytes)
		Signature:    GenerateTestSignature(),
	}

	// Apply all provided options
	for _, option := range options {
		option(msg)
	}

	return msg
}

// GenerateTestClientMessages generates a slice of test client messages
func GenerateTestClientMessages(count int, options ...MessageOption) []*zipnet.ClientMessage {
	messages := make([]*zipnet.ClientMessage, count)
	for i := 0; i < count; i++ {
		messages[i] = GenerateTestClientMessage(options...)
	}
	return messages
}

// PlaceMessageInSlot places a message in a specific slot of a message vector
func PlaceMessageInSlot(msgVec []byte, slot uint32, msgSize uint32, msg []byte) []byte {
	start := slot * msgSize
	end := start + msgSize

	if end > uint32(len(msgVec)) {
		// Resize message vector if needed
		newVec := make([]byte, end)
		copy(newVec, msgVec)
		msgVec = newVec
	}

	// Copy message into the slot
	copy(msgVec[start:end], msg)

	return msgVec
}

// GenerateMessageWithContent creates a client message with actual content in a specific slot
func GenerateMessageWithContent(content []byte, slot uint32, msgSize uint32, options ...MessageOption) *zipnet.ClientMessage {
	// Create base message
	msg := GenerateTestClientMessage(options...)

	// Place content in the specified slot
	msg.MsgVec = PlaceMessageInSlot(msg.MsgVec, slot, msgSize, content)

	return msg
}

// AggregatorMessageOption is a function that modifies an AggregatorMessage
type AggregatorMessageOption func(*zipnet.AggregatorMessage)

// WithUserPKs sets the user public keys for an aggregator message
func WithUserPKs(keys []crypto.PublicKey) AggregatorMessageOption {
	return func(msg *zipnet.AggregatorMessage) {
		msg.UserPKs = keys
	}
}

// WithAggregatorID sets the aggregator ID for an aggregator message
func WithAggregatorID(id string) AggregatorMessageOption {
	return func(msg *zipnet.AggregatorMessage) {
		msg.AggregatorID = id
	}
}

// WithLevel sets the level for an aggregator message
func WithLevel(level uint32) AggregatorMessageOption {
	return func(msg *zipnet.AggregatorMessage) {
		msg.Level = level
	}
}

// WithAnytrustGroupID sets the anytrust group ID for an aggregator message
func WithAnytrustGroupID(id string) AggregatorMessageOption {
	return func(msg *zipnet.AggregatorMessage) {
		msg.AnytrustGroupID = id
	}
}

// GenerateTestAggregatorMessage generates a test aggregator message
func GenerateTestAggregatorMessage(options ...AggregatorMessageOption) *zipnet.AggregatorMessage {
	// Create base schedule message
	schedMsg := GenerateTestClientMessage()

	// Create aggregator message from schedule message
	msg := &zipnet.AggregatorMessage{
		ScheduleMessage: *schedMsg,
		UserPKs:         []crypto.PublicKey{},
		AggregatorID:    "test-aggregator",
		Level:           0,
		AnytrustGroupID: "test-anytrust-group",
	}

	// Apply all provided options
	for _, option := range options {
		option(msg)
	}

	return msg
}

// XORMessages combines multiple client messages using XOR
// This simulates the aggregation process
func XORMessages(messages ...*zipnet.ClientMessage) *zipnet.ScheduleMessage {
	if len(messages) == 0 {
		return nil
	}

	// Use the first message as a template
	result := &zipnet.ScheduleMessage{
		Round:        messages[0].Round,
		NextSchedVec: make([]byte, len(messages[0].NextSchedVec)),
		MsgVec:       make([]byte, len(messages[0].MsgVec)),
		Signature:    GenerateTestSignature(),
	}

	// XOR all messages together
	for _, msg := range messages {
		// XOR scheduling vectors
		for i := 0; i < len(result.NextSchedVec) && i < len(msg.NextSchedVec); i++ {
			result.NextSchedVec[i] ^= msg.NextSchedVec[i]
		}

		// XOR message vectors
		for i := 0; i < len(result.MsgVec) && i < len(msg.MsgVec); i++ {
			result.MsgVec[i] ^= msg.MsgVec[i]
		}
	}

	return result
}

// GenerateTestAggregatorMessageFromClients simulates aggregating client messages
func GenerateTestAggregatorMessageFromClients(clientMessages []*zipnet.ClientMessage, clientPKs []crypto.PublicKey, options ...AggregatorMessageOption) *zipnet.AggregatorMessage {
	// XOR all client messages
	aggregated := XORMessages(clientMessages...)

	// Create aggregator message
	msg := &zipnet.AggregatorMessage{
		ScheduleMessage: *aggregated,
		UserPKs:         clientPKs,
		AggregatorID:    "test-aggregator",
		Level:           0,
		AnytrustGroupID: "test-anytrust-group",
	}

	// Apply all provided options
	for _, option := range options {
		option(msg)
	}

	return msg
}

// UnblindedShareOption is a function that modifies an UnblindedShareMessage
type UnblindedShareOption func(*zipnet.UnblindedShareMessage)

// WithKeyShare sets the key share for an unblinded share
func WithKeyShare(share *zipnet.ScheduleMessage) UnblindedShareOption {
	return func(msg *zipnet.UnblindedShareMessage) {
		msg.KeyShare = share
	}
}

// GenerateTestUnblindedShare generates a test unblinded share message
func GenerateTestUnblindedShare(encryptedMsg *zipnet.Signed[zipnet.AggregatorMessage], options ...UnblindedShareOption) *zipnet.Signed[zipnet.UnblindedShareMessage] {
	// Generate server key pair
	_, serverPrivkey, _ := GenerateTestKeyPair()

	rawAggMsg, _, _ := encryptedMsg.Recover()
	// Create default key share (all zeros)
	keyShare := &zipnet.ScheduleMessage{
		Round:        rawAggMsg.Round,
		NextSchedVec: make([]byte, len(rawAggMsg.NextSchedVec)),
		MsgVec:       make([]byte, len(rawAggMsg.MsgVec)),
		Signature:    GenerateTestSignature(),
	}

	// Create unblinded share
	share := &zipnet.UnblindedShareMessage{
		EncryptedMsg: encryptedMsg,
		KeyShare:     keyShare,
	}

	// Apply all provided options
	for _, option := range options {
		option(share)
	}

	signed, _ := zipnet.NewSigned(serverPrivkey, share)
	return signed
}

// RoundOutputOption is a function that modifies a RoundOutput
type RoundOutputOption func(*zipnet.RoundOutput)

// GenerateTestRoundOutput generates a test round output
func GenerateTestRoundOutput(round uint64, message *zipnet.ScheduleMessage, options ...RoundOutputOption) *zipnet.RoundOutput {
	// Generate default server signatures
	signatures := make([]zipnet.OutputSignature, 3)
	for i := 0; i < 3; i++ {
		serverPK, _, _ := GenerateTestKeyPair()
		signatures[i] = zipnet.OutputSignature{
			PublicKey: serverPK,
			Signature: GenerateUniqueTestSignature(fmt.Sprintf("server%d", i)),
		}
	}

	for _, option := range options {
		option(message)
	}

	return message
}

// =====================================
// Data Extraction Utilities
// =====================================

// ExtractMessageFromSlot extracts a message from a specific slot in a message vector
func ExtractMessageFromSlot(msgVec []byte, slot int, msgSize int) []byte {
	start := slot * msgSize
	end := start + msgSize

	if start >= len(msgVec) || end > len(msgVec) {
		return nil
	}

	// Copy message from the slot
	msg := make([]byte, msgSize)
	copy(msg, msgVec[start:end])

	return msg
}

// ExtractAllMessages extracts all non-zero messages from a message vector
func ExtractAllMessages(msgVec []byte, msgSize int) [][]byte {
	if len(msgVec) == 0 || msgSize == 0 {
		return nil
	}

	slots := len(msgVec) / msgSize
	messages := make([][]byte, 0, slots)

	for i := 0; i < slots; i++ {
		msg := ExtractMessageFromSlot(msgVec, i, msgSize)

		// Check if message is non-zero
		isNonZero := false
		for _, b := range msg {
			if b != 0 {
				isNonZero = true
				break
			}
		}

		if isNonZero {
			messages = append(messages, msg)
		}
	}

	return messages
}

// =====================================
// Test Schedule Utilities
// =====================================

// GenerateTestSchedule creates a published schedule with reservations
func GenerateTestSchedule(slots []uint32, footprints []crypto.Footprint) zipnet.PublishedSchedule {
	// Calculate the total size needed for the schedule
	maxSlot := uint32(0)
	for _, slot := range slots {
		if slot > maxSlot {
			maxSlot = slot
		}
	}

	// Create schedule with some buffer
	scheduleSize := (maxSlot + 1) * 8
	if scheduleSize < 400 {
		scheduleSize = 400 // Minimum size
	}

	schedule := make([]byte, scheduleSize)

	// Place footprints in the schedule
	for i, slot := range slots {
		if i < len(footprints) {
			fpBytes := footprints[i].Bytes()
			start := slot * 8 // Assuming 8-byte footprints

			// Copy footprint into schedule
			copy(schedule[start:start+8], fpBytes)
		}
	}

	return zipnet.PublishedSchedule{
		Footprints: schedule,
		Signature:  GenerateTestSignature(),
	}
}

// AddReservationToSchedule adds a reservation to an existing schedule
func AddReservationToSchedule(schedule zipnet.PublishedSchedule, slot uint32, footprint crypto.Footprint) zipnet.PublishedSchedule {
	// Ensure schedule is big enough
	newSize := (slot + 1) * 8
	if newSize > uint32(len(schedule.Footprints)) {
		newFootprints := make([]byte, newSize)
		copy(newFootprints, schedule.Footprints)
		schedule.Footprints = newFootprints
	}

	// Add footprint
	fpBytes := footprint.Bytes()
	start := slot * 8
	copy(schedule.Footprints[start:start+8], fpBytes)

	return schedule
}
