// Package crypto provides encryption helpers for BullStream.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	aesNonceSize = 12
	aesTagSize   = 16
	aesKeySize   = 16
)

// AESCipher wraps AES-128-GCM for the BullStream control channel.
// Each message uses a fresh random nonce.
type AESCipher struct {
	aead cipher.AEAD
}

// NewAESCipher derives a 16-byte key from the PSK using HKDF-SHA256 and
// constructs an AES-128-GCM AEAD.
func NewAESCipher(psk []byte) (*AESCipher, error) {
	key := make([]byte, aesKeySize)
	r := hkdf.New(sha256.New, psk, nil, []byte("bullstream-ctrl"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("aes hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes new gcm: %w", err)
	}
	return &AESCipher{aead: aead}, nil
}

// Encrypt seals plaintext with a fresh random nonce.
// Wire format: [12-byte nonce][ciphertext + 16-byte tag].
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("aes nonce: %w", err)
	}
	out := c.aead.Seal(nonce, nonce, plaintext, nil)
	return out, nil
}

// Decrypt verifies and decrypts a sealed message.
// Returns an error immediately on any authentication failure.
func (c *AESCipher) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < aesNonceSize+aesTagSize {
		return nil, fmt.Errorf("aes decrypt: message too short (%d)", len(msg))
	}
	nonce := msg[:aesNonceSize]
	ct := msg[aesNonceSize:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aes decrypt: %w", err)
	}
	return pt, nil
}

// WriteMsg encrypts plaintext and writes it to w with a 4-byte big-endian
// length prefix (length of the plaintext, not the ciphertext blob).
func (c *AESCipher) WriteMsg(w io.Writer, plaintext []byte) error {
	ct, err := c.Encrypt(plaintext)
	if err != nil {
		return err
	}
	// Length prefix = plaintext length.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(plaintext)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("aes write hdr: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return fmt.Errorf("aes write ct: %w", err)
	}
	return nil
}

// ReadMsg reads a 4-byte length-prefixed encrypted message from r, decrypts it,
// and returns the plaintext.
func (c *AESCipher) ReadMsg(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("aes read hdr: %w", err)
	}
	ptLen := binary.BigEndian.Uint32(hdr[:])
	// Ciphertext is nonce + ptLen + tag.
	ctLen := aesNonceSize + ptLen + aesTagSize
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, fmt.Errorf("aes read ct: %w", err)
	}
	return c.Decrypt(ct)
}
