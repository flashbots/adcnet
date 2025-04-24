/*
Package testutil provides testing utilities for the go-zipnet protocol implementation.

This package contains a comprehensive set of test data generators and utilities
designed to simplify writing tests for ZIPNet protocol components. It supports
unit testing, integration testing, and benchmarking of the entire protocol stack
by providing consistent, customizable test fixtures.

# Overview

Testing a complex protocol like ZIPNet requires generating various types of test
data, from configuration objects to cryptographic keys, messages, and schedules.
This package provides utilities for all these needs, allowing test writers to focus
on test logic rather than test data generation.

# Key Components

## Configuration Generators

Functions for creating customizable ZIPNetConfig instances:

	// Create default test config
	config := testutil.NewTestConfig()

	// Create custom config with specific options
	customConfig := testutil.NewTestConfig(
	    testutil.WithMessageSlots(200),
	    testutil.WithMessageSize(256),
	    testutil.WithServerCount(5),
	)

## Cryptographic Generators

Utilities for generating keys, signatures, and other cryptographic primitives:

	// Generate random bytes
	randomBytes, _ := testutil.GenerateRandomBytes(32)

	// Generate key pairs
	pubKey, privKey, _ := testutil.GenerateTestKeyPair()

	// Generate multiple public keys
	publicKeys, _ := testutil.GenerateTestPublicKeys(10)

## Message Generators

Functions for creating test messages for clients, aggregators, and servers:

	// Create a client message
	clientMsg := testutil.GenerateTestClientMessage()

	// Create a message with specific options
	customMsg := testutil.GenerateTestClientMessage(
	    testutil.WithRound(42),
	    testutil.WithSignature(mySignature),
	)

	// Create a message with content in a specific slot
	msgWithContent := testutil.GenerateMessageWithContent(
	    []byte("Test message"),
	    3,   // Slot number
	    160, // Message size
	)

	// Simulate message aggregation
	aggregatedMsg := testutil.GenerateTestAggregatorMessageFromClients(
	    clientMessages,
	    clientPublicKeys,
	)

## Test Schedule Utilities

Functions for creating and manipulating test schedules:

	// Create a test schedule with reservations
	schedule := testutil.GenerateTestSchedule(
	    []uint32{10, 20, 30},
	    footprints,
	)

	// Add a reservation to a schedule
	newSchedule := testutil.AddReservationToSchedule(
	    schedule,
	    45,
	    footprint,
	)

## Data Extraction Utilities

Functions for extracting and analyzing message content:

	// Extract a message from a specific slot
	message := testutil.ExtractMessageFromSlot(msgVec, 2, 160)

	// Extract all non-zero messages
	allMessages := testutil.ExtractAllMessages(msgVec, 160)

# Usage Examples

## Testing Client Message Generation

	func TestClientMessageGeneration(t *testing.T) {
	    // Setup test environment
	    client := setupTestClient()

	    // Use test utilities to generate expected message
	    expectedMsg := testutil.GenerateMessageWithContent(
	        []byte("Hello world"),
	        0,   // Slot 0
	        160, // Message size
	    )

	    // Test client's message generation
	    actualMsg, err := client.SubmitMessage(ctx, 1, []byte("Hello world"), false, testSchedule)
	    require.NoError(t, err)

	    // Compare actual message with expected
	    assert.Equal(t, expectedMsg.MsgVec, actualMsg.MsgVec)
	}

## Testing Aggregator Functionality

	func TestAggregation(t *testing.T) {
	    // Create test messages from multiple clients
	    clientMsgs := testutil.GenerateTestClientMessages(5)
	    clientPKs, _ := testutil.GenerateTestPublicKeys(5)

	    // Expected result from XORing all messages
	    expectedAggregate := testutil.XORMessages(clientMsgs...)

	    // Test actual aggregation in the aggregator
	    aggregator := setupTestAggregator()
	    for i, msg := range clientMsgs {
	        aggregator.ReceiveClientMessage(ctx, msg, clientPKs[i])
	    }

	    actualAggregate, err := aggregator.AggregateMessages(ctx, 1)
	    require.NoError(t, err)

	    // Verify correct aggregation
	    assert.Equal(t, expectedAggregate.MsgVec, actualAggregate.MsgVec)
	}

# Best Practices

1. Use the option pattern provided by this package to customize test data
2. Leverage the XOR utilities to simulate the expected behavior of aggregation
3. Use the extraction utilities to verify message placement and content
4. For large scale tests, generate the test data once and reuse it in multiple tests
5. When testing with multiple components, use a consistent configuration across all

This package is intended for testing purposes only and should not be used in
production code.
*/
package testutil
