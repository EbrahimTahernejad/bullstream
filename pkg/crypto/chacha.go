// Package crypto — ChaCha20-Poly1305 framer for BullStream data channels.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	chachaKeySize  = 32
	chachaNonceSize = 12
	chachaTagSize  = 16
)

// ChaChaFramer encrypts and decrypts BullStream data-channel frames using
// ChaCha20-Poly1305.  It maintains separate send and receive counters so that
// both sides of a bidirectional stream never reuse a nonce.
//
// Nonce = [32-bit session epoch, BE][64-bit counter, BE] — never transmitted.
type ChaChaFramer struct {
	aead        interface{ Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	epoch       uint32
	sendCounter atomic.Uint64
	recvCounter atomic.Uint64
}

// NewChaChaFramer derives a 32-byte key from the password using HKDF-SHA256
// and constructs a ChaCha20-Poly1305 framer bound to the given session epoch.
func NewChaChaFramer(password []byte, epoch uint32) (*ChaChaFramer, error) {
	key := make([]byte, chachaKeySize)
	r := hkdf.New(sha256.New, password, nil, []byte("bullstream-data"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("chacha hkdf: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha new: %w", err)
	}
	return &ChaChaFramer{aead: aead, epoch: epoch}, nil
}

// buildNonce constructs the 12-byte nonce from epoch + counter.
func (f *ChaChaFramer) buildNonce(counter uint64) []byte {
	nonce := make([]byte, chachaNonceSize)
	binary.BigEndian.PutUint32(nonce[0:4], f.epoch)
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

// EncryptUDP encrypts a single UDP payload (no length prefix).
// The counter is incremented atomically before use.
func (f *ChaChaFramer) EncryptUDP(plaintext []byte) []byte {
	cnt := f.sendCounter.Add(1) - 1
	nonce := f.buildNonce(cnt)
	return f.aead.Seal(nil, nonce, plaintext, nil)
}

// DecryptUDP decrypts a single UDP payload (no length prefix).
func (f *ChaChaFramer) DecryptUDP(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < chachaTagSize {
		return nil, fmt.Errorf("chacha udp: ciphertext too short (%d)", len(ciphertext))
	}
	cnt := f.recvCounter.Add(1) - 1
	nonce := f.buildNonce(cnt)
	pt, err := f.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("chacha udp decrypt: %w", err)
	}
	return pt, nil
}

// WriteFrame encrypts plaintext and writes it to w with a 4-byte big-endian
// length prefix (plaintext length).
func (f *ChaChaFramer) WriteFrame(w io.Writer, plaintext []byte) error {
	cnt := f.sendCounter.Add(1) - 1
	nonce := f.buildNonce(cnt)
	ct := f.aead.Seal(nil, nonce, plaintext, nil)

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(plaintext)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("chacha write hdr: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return fmt.Errorf("chacha write ct: %w", err)
	}
	return nil
}

// ReadFrame reads a 4-byte length-prefixed encrypted frame from r, decrypts it,
// and returns the plaintext.
func (f *ChaChaFramer) ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("chacha read hdr: %w", err)
	}
	ptLen := binary.BigEndian.Uint32(hdr[:])
	ctLen := ptLen + chachaTagSize
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, fmt.Errorf("chacha read ct: %w", err)
	}
	cnt := f.recvCounter.Add(1) - 1
	nonce := f.buildNonce(cnt)
	pt, err := f.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("chacha read decrypt: %w", err)
	}
	return pt, nil
}

// SendCounter returns the current send counter value (for diagnostics).
func (f *ChaChaFramer) SendCounter() uint64 {
	return f.sendCounter.Load()
}

// RecvCounter returns the current receive counter value (for diagnostics).
func (f *ChaChaFramer) RecvCounter() uint64 {
	return f.recvCounter.Load()
}
