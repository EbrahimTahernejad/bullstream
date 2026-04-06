// Package downstream — sliding-window reorder buffer for BullStream.
package downstream

import (
	"log"
	"sync"
	"time"
)

// ReorderBuffer implements a sliding-window reorder buffer for downstream packets.
// It delivers packets in order; unrecoverable gaps trigger a RESET callback.
type ReorderBuffer struct {
	mu          sync.Mutex
	window      map[uint32][]byte // SeqNum → payload
	nextSeq     uint32
	windowSize  uint32
	gapTimeout  time.Duration
	gapTimer    *time.Timer

	// DeliverFunc is called for each packet delivered in order.
	DeliverFunc func(seqNum uint32, payload []byte)

	// ResetFunc is called when an unrecoverable gap is detected.
	ResetFunc func()
}

// NewReorderBuffer creates a reorder buffer with the given window size and gap timeout.
func NewReorderBuffer(windowSize uint32, gapTimeout time.Duration) *ReorderBuffer {
	return &ReorderBuffer{
		window:     make(map[uint32][]byte),
		windowSize: windowSize,
		gapTimeout: gapTimeout,
	}
}

// Receive buffers a packet and attempts in-order delivery.
func (r *ReorderBuffer) Receive(seqNum uint32, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Drop duplicates and out-of-window packets.
	if seqNum < r.nextSeq {
		return // already delivered
	}
	if seqNum >= r.nextSeq+r.windowSize {
		log.Printf("reorder: seq %d outside window [%d, %d), dropping", seqNum, r.nextSeq, r.nextSeq+r.windowSize)
		return
	}

	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.window[seqNum] = cp

	// Deliver as many consecutive packets as possible.
	r.deliverConsecutive()

	// If there are gaps, (re)arm the gap timer.
	if len(r.window) > 0 {
		r.resetGapTimer()
	}
}

// deliverConsecutive flushes all buffered packets starting from nextSeq.
// Must be called with r.mu held.
func (r *ReorderBuffer) deliverConsecutive() {
	for {
		pkt, ok := r.window[r.nextSeq]
		if !ok {
			break
		}
		delete(r.window, r.nextSeq)
		seq := r.nextSeq
		r.nextSeq++
		if r.DeliverFunc != nil {
			r.mu.Unlock()
			r.DeliverFunc(seq, pkt)
			r.mu.Lock()
		}
	}
}

// resetGapTimer (re)arms the gap timer. Must be called with r.mu held.
func (r *ReorderBuffer) resetGapTimer() {
	if r.gapTimer != nil {
		r.gapTimer.Stop()
	}
	r.gapTimer = time.AfterFunc(r.gapTimeout, r.onGapTimeout)
}

// onGapTimeout is called when the gap timer fires — the next expected packet has
// not arrived within the timeout window.
func (r *ReorderBuffer) onGapTimeout() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.window[r.nextSeq]; ok {
		// Packet arrived between timer fire and lock acquisition.
		r.deliverConsecutive()
		if len(r.window) > 0 {
			r.resetGapTimer()
		}
		return
	}

	// Unrecoverable gap: signal RESET.
	log.Printf("reorder: gap timeout at seq %d, triggering reset", r.nextSeq)
	if r.ResetFunc != nil {
		r.mu.Unlock()
		r.ResetFunc()
		r.mu.Lock()
	}
	// Clear the buffer.
	r.window = make(map[uint32][]byte)
}

// Reset clears the buffer and resets nextSeq to the given value.
// Used when a new session starts with a fresh epoch.
func (r *ReorderBuffer) Reset(nextSeq uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gapTimer != nil {
		r.gapTimer.Stop()
		r.gapTimer = nil
	}
	r.window = make(map[uint32][]byte)
	r.nextSeq = nextSeq
}
