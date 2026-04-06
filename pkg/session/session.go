// Package session manages per-session state for BullStream tunnels.
package session

import (
	"context"
	"sync"
	"sync/atomic"
)

// State represents the lifecycle state of a session.
type State int32

const (
	// StateOpen is the normal operating state.
	StateOpen State = iota
	// StateHalfClose means FIN has been received from one side.
	StateHalfClose
	// StateClosed means the session is fully closed.
	StateClosed
)

// Session holds per-session mutable state for one bidirectional tunnel.
type Session struct {
	// SessionID is the assigned session identifier.
	SessionID uint32
	// Epoch is the 4-byte random value generated at OPEN time.
	Epoch uint32

	// SendCredits and RecvCredits track WNDUPD backpressure.
	// sendCredits = bytes we are allowed to send.
	// recvCredits = bytes remote is allowed to send (we advertise these).
	SendCredits atomic.Int64
	RecvCredits atomic.Int64

	state atomic.Int32

	// DataCh delivers decrypted upstream data to the session reader.
	DataCh chan []byte

	// FinCh is closed when a FIN is received.
	FinCh chan struct{}

	// ResetCh is closed when a RESET is received or the session is aborted.
	ResetCh chan struct{}

	finOnce   sync.Once
	resetOnce sync.Once
	closeOnce sync.Once

	mu      sync.Mutex
	closed  bool
}

// NewSession allocates a new Session with the given ID, epoch, and initial window.
func NewSession(id, epoch uint32, windowBytes int64) *Session {
	s := &Session{
		SessionID: id,
		Epoch:     epoch,
		DataCh:    make(chan []byte, 64),
		FinCh:     make(chan struct{}),
		ResetCh:   make(chan struct{}),
	}
	s.SendCredits.Store(windowBytes)
	s.RecvCredits.Store(windowBytes)
	s.state.Store(int32(StateOpen))
	return s
}

// State returns the current session state.
func (s *Session) State() State {
	return State(s.state.Load())
}

// SetState atomically updates the session state.
func (s *Session) SetState(st State) {
	s.state.Store(int32(st))
}

// DeliverData queues data for consumption. Non-blocking; drops if full.
func (s *Session) DeliverData(ctx context.Context, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case s.DataCh <- cp:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ResetCh:
		return ErrReset
	}
}

// SignalFIN signals graceful half-close from remote.
func (s *Session) SignalFIN() {
	s.finOnce.Do(func() { close(s.FinCh) })
	s.SetState(StateHalfClose)
}

// SignalReset aborts the session immediately.
func (s *Session) SignalReset() {
	s.resetOnce.Do(func() { close(s.ResetCh) })
	s.SetState(StateClosed)
}

// Close marks the session as fully closed.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.SetState(StateClosed)
		// Drain and close DataCh to unblock any blocked readers.
		s.resetOnce.Do(func() { close(s.ResetCh) })
	})
}

// IsClosed reports whether the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ErrReset is returned when an operation is attempted on a reset session.
var ErrReset = &resetError{}

type resetError struct{}

func (e *resetError) Error() string { return "session reset" }
