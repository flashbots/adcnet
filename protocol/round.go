package protocol

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// RoundContext represents the phase within a protocol round.
type RoundContext int

const (
	ClientRoundContext RoundContext = iota
	AggregatorRoundContext
	ServerPartialRoundContext
	ServerLeaderRoundContext
)

// Round represents a protocol round with its phase context.
type Round struct {
	Number  int
	Context RoundContext
}

// IsAfter returns true if this round occurs after r2.
func (r Round) IsAfter(r2 Round) bool {
	return r.Number > r2.Number || (r.Number == r2.Number && r.Context > r2.Context)
}

// Advance returns the next round phase.
func (r Round) Advance() Round {
	if r.Context == ServerLeaderRoundContext {
		return Round{r.Number + 1, ClientRoundContext}
	}
	return Round{r.Number, r.Context + 1}
}

// RoundCoordinator manages protocol round transitions.
type RoundCoordinator interface {
	CurrentRound() Round
	SubscribeToRounds(ctx context.Context) <-chan Round
	Start(ctx context.Context)
	AdvanceToRound(round Round)
}

type subscriber struct {
	ctx context.Context
	ch  chan Round
}

// LocalRoundCoordinator provides deterministic round advancement.
type LocalRoundCoordinator struct {
	mu            sync.RWMutex
	currentRound  Round
	roundDuration time.Duration
	subscribers   []subscriber
	started       *atomic.Bool
}

// NewLocalRoundCoordinator creates a time-based round coordinator.
func NewLocalRoundCoordinator(roundDuration time.Duration) *LocalRoundCoordinator {
	return &LocalRoundCoordinator{
		currentRound:  Round{0, ClientRoundContext},
		roundDuration: roundDuration,
		subscribers:   make([]subscriber, 0),
		started:       &atomic.Bool{},
	}
}

// CurrentRound returns the current protocol round number.
func (c *LocalRoundCoordinator) CurrentRound() Round {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentRound
}

// SubscribeToRounds returns a channel that receives round transition notifications.
func (c *LocalRoundCoordinator) SubscribeToRounds(ctx context.Context) <-chan Round {
	c.mu.Lock()
	defer c.mu.Unlock()

	ch := make(chan Round, 10)
	c.subscribers = append(c.subscribers, subscriber{ctx, ch})

	go func() {
		ch <- c.currentRound
	}()

	return ch
}

// RoundForTime calculates the round for a given instant.
func RoundForTime(instant time.Time, roundDuration time.Duration) (Round, error) {
	if roundDuration <= 0 {
		return Round{}, errors.New("round duration must be positive")
	}
	if instant.Before(time.Unix(0, 0)) {
		return Round{}, errors.New("time must not be negative")
	}

	tickDuration := roundDuration.Milliseconds() / 4
	if tickDuration == 0 {
		return Round{}, errors.New("round duration too small")
	}

	nTicks := instant.UnixMilli() / tickDuration
	return Round{int(nTicks / 4), RoundContext(nTicks % 4)}, nil
}

// TimeForRound returns the start time for a given round.
func TimeForRound(round Round, roundDuration time.Duration) time.Time {
	startTime := time.Unix(0, 0)
	return startTime.Add(time.Duration(round.Number) * roundDuration).Add(time.Duration(round.Context) * roundDuration / 4)
}

// Start begins round progression.
func (c *LocalRoundCoordinator) Start(ctx context.Context) {
	if c.started.Swap(true) {
		return
	}

	round, err := RoundForTime(time.Now(), c.roundDuration)
	if err != nil {
		c.currentRound = Round{0, ClientRoundContext}
	} else {
		c.currentRound = round
	}

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

// AdvanceToRound manually advances to a specific round (for testing).
func (c *LocalRoundCoordinator) AdvanceToRound(round Round) {
	for round.IsAfter(c.CurrentRound()) {
		c.advanceRound()
	}
}

func (c *LocalRoundCoordinator) advanceRound() {
	c.mu.Lock()
	c.currentRound = c.currentRound.Advance()
	newRound := c.currentRound

	toRemove := []int{}
	for i, sub := range c.subscribers {
		select {
		case <-sub.ctx.Done():
			close(sub.ch)
			toRemove = append(toRemove, i)
		case sub.ch <- newRound:
		default:
		}
	}

	slices.Reverse(toRemove)
	for _, i := range toRemove {
		c.subscribers = slices.Delete(c.subscribers, i, i)
	}

	c.mu.Unlock()
}
