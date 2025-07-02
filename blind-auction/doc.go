// Package blind_auction implements distributed auction scheduling for ADCNet
// using Invertible Bloom Filters (IBF).
//
// The auction mechanism enables fair bandwidth allocation without revealing
// individual bids until after aggregation. Clients encode their bids into
// IBF chunks that are secret-shared and aggregated alongside message data.
// After threshold reconstruction, the IBF is inverted to recover auction
// entries and determine message scheduling for the next round.
package blind_auction
