// Package session — thread-safe SessionID → Session mapping.
package session

import (
	"fmt"
	"sync"
	"time"
)

// Mode controls how session IDs are allocated and encoded.
type Mode int

const (
	// ModeSingle uses 16-bit session IDs with no client ID.
	ModeSingle Mode = iota
	// ModeMulti uses 32-bit session IDs with the top 4 bits as client ID.
	ModeMulti
)

// Table is a thread-safe map from session ID to Session.
// In single mode IDs are 16-bit; in multi mode they are 32-bit with the top
// 4 bits encoding the client ID (CID).
type Table struct {
	mu            sync.RWMutex
	sessions      map[uint32]*Session
	mode          Mode
	reorderTO     time.Duration // quiet period before ID reuse
	nextSeq       uint32        // monotonically increasing sequence
	clientID      uint8         // 0 in single mode
	windowBytes   int64
}

// NewTable creates a new session table.
// reorderTimeout is the 2× reorder-timeout quiet period before ID reuse.
func NewTable(mode Mode, clientID uint8, reorderTimeout time.Duration, windowBytes int64) *Table {
	return &Table{
		sessions:    make(map[uint32]*Session),
		mode:        mode,
		reorderTO:   reorderTimeout,
		clientID:    clientID,
		windowBytes: windowBytes,
	}
}

// NewSession creates and registers a new session, assigning the next ID.
func (t *Table) NewSession(epoch uint32) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	id, err := t.allocateID()
	if err != nil {
		return nil, err
	}
	s := NewSession(id, epoch, t.windowBytes)
	t.sessions[id] = s
	return s, nil
}

// Get returns the session for the given ID, or nil if not found.
func (t *Table) Get(id uint32) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[id]
}

// Delete removes a session from the table.  It should be called after the
// quiet period has elapsed so the ID is safe to reuse.
func (t *Table) Delete(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, id)
}

// DeleteAfterQuiet removes the session after the 2× reorder-timeout quiet
// period to prevent ID reuse collisions with in-flight packets.
func (t *Table) DeleteAfterQuiet(id uint32) {
	go func() {
		time.Sleep(2 * t.reorderTO)
		t.Delete(id)
	}()
}

// Len returns the number of active sessions.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// CloseAll closes all sessions in the table.
func (t *Table) CloseAll() {
	t.mu.Lock()
	sessions := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.mu.Unlock()

	for _, s := range sessions {
		s.Close()
	}
}

// allocateID picks the next available session ID. Must be called with mu held.
func (t *Table) allocateID() (uint32, error) {
	switch t.mode {
	case ModeSingle:
		start := t.nextSeq
		for {
			id := t.nextSeq & 0xFFFF
			t.nextSeq++
			if _, exists := t.sessions[id]; !exists {
				return id, nil
			}
			if t.nextSeq&0xFFFF == start&0xFFFF {
				return 0, fmt.Errorf("session table full (single mode)")
			}
		}
	case ModeMulti:
		cidBits := uint32(t.clientID) << 28
		start := t.nextSeq
		for {
			seq := t.nextSeq & 0x0FFFFFFF
			t.nextSeq++
			id := cidBits | seq
			if _, exists := t.sessions[id]; !exists {
				return id, nil
			}
			if t.nextSeq&0x0FFFFFFF == start&0x0FFFFFFF {
				return 0, fmt.Errorf("session table full (multi mode, cid=%d)", t.clientID)
			}
		}
	default:
		return 0, fmt.Errorf("unknown session mode: %d", t.mode)
	}
}
