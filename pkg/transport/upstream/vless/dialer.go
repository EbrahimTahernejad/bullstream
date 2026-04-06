// Package vless implements a minimal VLESS v0 upstream dialer for BullStream.
// It speaks the VLESS protocol directly without any external library dependency.
package vless

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Dialer dials the BullStream server data port through a VLESS proxy.
type Dialer struct {
	// ProxyAddr is the VLESS proxy address in "host:port" form.
	ProxyAddr string
	// UUID is the 16-byte VLESS client UUID.
	UUID [16]byte
	// TLS indicates whether to wrap the proxy connection in TLS.
	TLS bool
	// DstAddr is the target address the proxy should connect to.
	DstAddr string
}

// NewDialer constructs a VLESS dialer.
// uuidStr must be a standard hyphenated UUID string.
func NewDialer(proxyAddr, uuidStr, dstAddr string, useTLS bool) (*Dialer, error) {
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid uuid %q: %w", uuidStr, err)
	}
	return &Dialer{
		ProxyAddr: proxyAddr,
		UUID:      uuid,
		TLS:       useTLS,
		DstAddr:   dstAddr,
	}, nil
}

// Dial connects to the VLESS proxy and sends the VLESS v0 request header,
// then returns the connection for use as an upstream data transport.
func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("vless: dial proxy %s: %w", d.ProxyAddr, err)
	}
	_ = raw.(*net.TCPConn).SetKeepAlive(true)

	var conn net.Conn = raw
	if d.TLS {
		host, _, _ := net.SplitHostPort(d.ProxyAddr)
		tlsCfg := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("vless: tls handshake: %w", err)
		}
		conn = tlsConn
	}

	// Build VLESS v0 request.
	// [version=0][UUID 16B][addon_len=0][cmd=1 (TCP)][port 2B BE][addr_type + addr]
	host, portStr, err := net.SplitHostPort(d.DstAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: parse dst_addr %q: %w", d.DstAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: parse dst port %q: %w", portStr, err)
	}

	req, err := buildVLESSRequest(d.UUID, uint16(port), host)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: write request: %w", err)
	}

	// Read VLESS response: [version 1B][addon_len 1B][addons addon_len B]
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: read response header: %w", err)
	}
	// resp[0] = version (ignored), resp[1] = addon_len
	addonLen := int(resp[1])
	if addonLen > 0 {
		addons := make([]byte, addonLen)
		if _, err := readFull(conn, addons); err != nil {
			conn.Close()
			return nil, fmt.Errorf("vless: read response addons: %w", err)
		}
	}

	return conn, nil
}

// buildVLESSRequest constructs the VLESS v0 request bytes.
// addr can be a hostname or dotted-decimal IPv4; we always use domain (0x02) form
// unless it is a valid IPv4, in which case we use address type 0x01.
func buildVLESSRequest(uuid [16]byte, port uint16, addr string) ([]byte, error) {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00)       // version = 0
	buf = append(buf, uuid[:]...) // UUID 16 bytes
	buf = append(buf, 0x00)       // addon_len = 0
	buf = append(buf, 0x01)       // cmd = 1 (TCP)

	// Port big-endian.
	buf = append(buf, byte(port>>8), byte(port))

	// Address type + address.
	ip4 := net.ParseIP(addr)
	if ip4 != nil {
		ip4 = ip4.To4()
	}
	if ip4 != nil {
		// IPv4: addr_type=0x01, 4 bytes
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else {
		// Domain: addr_type=0x02, 1-byte length, domain bytes
		if len(addr) > 255 {
			return nil, fmt.Errorf("vless: domain too long: %d", len(addr))
		}
		buf = append(buf, 0x02)
		buf = append(buf, byte(len(addr)))
		buf = append(buf, []byte(addr)...)
	}
	return buf, nil
}

// parseUUID parses a standard 8-4-4-4-12 UUID string into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	// Strip hyphens.
	hex := make([]byte, 0, 32)
	for _, c := range s {
		if c == '-' {
			continue
		}
		hex = append(hex, byte(c))
	}
	if len(hex) != 32 {
		return uuid, fmt.Errorf("expected 32 hex chars, got %d", len(hex))
	}
	for i := 0; i < 16; i++ {
		b, err := hexByte(hex[i*2], hex[i*2+1])
		if err != nil {
			return uuid, err
		}
		uuid[i] = b
	}
	return uuid, nil
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return (h << 4) | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex char %q", c)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Ensure port field is used to avoid unused-import warning.
var _ = binary.BigEndian
