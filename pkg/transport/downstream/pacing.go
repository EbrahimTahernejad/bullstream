// Package downstream provides FEC, reorder, and pacing for BullStream downstream.
package downstream

import (
	"context"
	"sync"
	"time"
)

// Pacer implements a token-bucket rate limiter for downstream packet sending.
// Tokens represent bytes; the bucket refills at RateBps bits per second.
type Pacer struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rateBps  float64 // bytes per second
	lastTick time.Time
}

// NewPacer creates a token-bucket pacer.
// rateMbps is the sustained rate in megabits per second.
// burstGroups is the burst size in FEC groups (converted to bytes via groupBytes).
func NewPacer(rateMbps float64, burstGroups int, groupBytes int) *Pacer {
	if rateMbps <= 0 {
		rateMbps = 8.0
	}
	if burstGroups <= 0 {
		burstGroups = 1
	}
	if groupBytes <= 0 {
		groupBytes = 1400 * 10 // default: 10 shards × 1400 bytes
	}
	burst := float64(burstGroups * groupBytes)
	return &Pacer{
		tokens:   burst,
		maxBurst: burst,
		rateBps:  rateMbps * 1e6 / 8, // convert Mbit/s → bytes/s
		lastTick: time.Now(),
	}
}

// Wait blocks until the pacer allows sending n bytes, or the context is cancelled.
func (p *Pacer) Wait(ctx context.Context, n int) error {
	for {
		p.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(p.lastTick).Seconds()
		p.lastTick = now
		p.tokens += elapsed * p.rateBps
		if p.tokens > p.maxBurst {
			p.tokens = p.maxBurst
		}
		if p.tokens >= float64(n) {
			p.tokens -= float64(n)
			p.mu.Unlock()
			return nil
		}
		// Calculate how long to wait for enough tokens.
		need := float64(n) - p.tokens
		wait := time.Duration(need/p.rateBps*float64(time.Second)) + time.Millisecond
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
