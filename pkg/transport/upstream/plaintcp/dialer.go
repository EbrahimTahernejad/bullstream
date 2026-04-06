// Package plaintcp provides a plain-TCP upstream dialer for BullStream.
package plaintcp

import (
	"context"
	"fmt"
	"net"
)

// Dialer dials the BullStream server data port directly over TCP.
type Dialer struct {
	// Addr is the server data address in "host:port" form.
	Addr string
}

// NewDialer constructs a plain-TCP dialer targeting the given address.
func NewDialer(addr string) *Dialer {
	return &Dialer{Addr: addr}
}

// Dial establishes a plain TCP connection to the server.
func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("plaintcp dial %s: %w", d.Addr, err)
	}
	// Enable TCP keepalives to prevent silent drops on idle connections.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}
	return conn, nil
}
