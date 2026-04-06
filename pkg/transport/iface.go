// Package transport defines pluggable transport interfaces for BullStream.
package transport

import (
	"context"
	"net"
)

// UpstreamDialer is implemented by client-side upstream transports.
// It dials the server's data port and returns a raw connection.
type UpstreamDialer interface {
	// Dial establishes a connection to the server data port.
	Dial(ctx context.Context) (net.Conn, error)
}

// UpstreamListener is implemented by the server to accept upstream connections.
type UpstreamListener interface {
	// Accept waits for and returns the next upstream connection.
	Accept(ctx context.Context) (net.Conn, error)
}

// DownstreamSender is implemented by the server to send packets to a client.
type DownstreamSender interface {
	// Send transmits one downstream packet to the client.
	Send(pkt []byte) error
}

// DownstreamReceiver is implemented by the client to receive downstream packets.
type DownstreamReceiver interface {
	// Recv blocks until a downstream packet is available or the context is done.
	Recv(ctx context.Context) ([]byte, error)
}
