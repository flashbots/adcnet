package protocol

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type RoundContext int

const (
	ClientRoundContext RoundContext = iota
	AggregatorRoundContext
	ServerPartialRoundContext
	ServerLeaderRoundContext
)

type Round struct {
	Number  int
	Context RoundContext
}

func (r Round) IsAfter(r2 Round) bool {
	return r.Number > r2.Number || (r.Number == r2.Number && r.Context > r2.Context)
}

func (r Round) Advance() Round {
	if r.Context == ServerLeaderRoundContext {
		return Round{r.Number + 1, ClientRoundContext}
	}
	return Round{r.Number, r.Context + 1}
}

// RoundCoordinator manages protocol round transitions.
type RoundCoordinator interface {
	// CurrentRound returns the current protocol round number.
	CurrentRound() Round

	// SubscribeToRounds receives round transition notifications.
	SubscribeToRounds() <-chan Round

	// Start begins round progression.
	Start(ctx context.Context)

	// AdvanceToRound manually advances to a specific round (for testing).
	AdvanceToRound(round Round)
}

type Subscriber struct {
	ctx context.Context
	ch  chan Round
}

// LocalRoundCoordinator provides deterministic round advancement.
type LocalRoundCoordinator struct {
	mu            sync.RWMutex
	currentRound  Round
	roundDuration time.Duration
	subscribers   []Subscriber
	ticker        *time.Ticker
	started       *atomic.Bool
}

// NewLocalRoundCoordinator creates a time-based round coordinator.
func NewLocalRoundCoordinator(roundDuration time.Duration) *LocalRoundCoordinator {
	return &LocalRoundCoordinator{
		currentRound:  Round{0, ClientRoundContext},
		roundDuration: roundDuration,
		subscribers:   make([]Subscriber, 0),
		started:       &atomic.Bool{},
	}
}

// CurrentRound returns the current protocol round number.
func (c *LocalRoundCoordinator) CurrentRound() Round {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentRound
}

// SubscribeToRounds receives round transition notifications.
func (c *LocalRoundCoordinator) SubscribeToRounds(ctx context.Context) <-chan Round {
	c.mu.Lock()
	defer c.mu.Unlock()

	ch := make(chan Round, 10)
	c.subscribers = append(c.subscribers, Subscriber{ctx, ch})

	// Send current round immediately
	go func() {
		ch <- c.currentRound
	}()

	return ch
}

func RoundForTime(instnant time.Time, roundDuration time.Duration) Round {
	nTicks := instnant.UnixMilli() / (roundDuration.Milliseconds() / 4)
	return Round{int(nTicks / 4), RoundContext(nTicks % 4)}
}

func TimeForRound(round Round, roundDuration time.Duration) time.Time {
	startTime := time.Unix(0, 0)
	return startTime.Add(time.Duration(round.Number) * roundDuration).Add(time.Duration(round.Context) * roundDuration / 4)
}

// Start begins round progression.
func (c *LocalRoundCoordinator) Start(ctx context.Context) {
	if c.started.Swap(true) {
		return
	}

	c.currentRound = RoundForTime(time.Now(), c.roundDuration)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(TimeForRound(c.currentRound.Advance(), c.roundDuration))):
				c.advanceRound()
			}
		}
	}()
}

// AdvanceToRound manually advances to a specific round.
// Only used in tests.
func (c *LocalRoundCoordinator) AdvanceToRound(round Round) {
	for round.IsAfter(c.CurrentRound()) {
		c.advanceRound()
	}
}

// advanceRound moves to the next round and notifies subscribers.
func (c *LocalRoundCoordinator) advanceRound() {
	c.mu.Lock()
	c.currentRound = c.currentRound.Advance()
	newRound := c.currentRound

	// Notify subscribers
	toRemove := []int{}
	for i, sub := range c.subscribers {
		select {
		case <-sub.ctx.Done():
			close(sub.ch)
			toRemove = append(toRemove, i)
		case sub.ch <- newRound:
		default:
			// Skip if channel is full
		}
	}

	// Not critical to optimize this
	slices.Reverse(toRemove)
	for _, i := range toRemove {
		c.subscribers = slices.Delete(c.subscribers, i, i)
	}

	c.mu.Unlock()
}
