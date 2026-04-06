// Package udpspoof — client-side UDP receiver for BullStream downstream.
package udpspoof

import (
	"context"
	"fmt"
	"net"

	"github.com/ebrahimtahernejad/bullstream/pkg/transport"
)

// Receiver implements transport.DownstreamReceiver by listening on a plain UDP
// socket and filtering packets by known spoof source addresses.
type Receiver struct {
	conn   *net.UDPConn
	filter map[string]struct{} // "ip:port" → present
	pktCh  chan []byte
	errCh  chan error
}

// NewReceiver creates a UDP receiver that listens on the given port and only
// accepts packets from the given spoof sources.
func NewReceiver(listenPort int, spoofSrcs []net.UDPAddr) (*Receiver, error) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: listenPort}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("udpspoof receiver: listen :%d: %w", listenPort, err)
	}

	filter := make(map[string]struct{}, len(spoofSrcs))
	for _, s := range spoofSrcs {
		filter[s.String()] = struct{}{}
	}

	r := &Receiver{
		conn:   conn,
		filter: filter,
		pktCh:  make(chan []byte, 256),
		errCh:  make(chan error, 1),
	}
	return r, nil
}

// Start begins receiving packets in a background goroutine.
// It stops when ctx is done or the connection is closed.
func (r *Receiver) Start(ctx context.Context) {
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := r.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case r.errCh <- fmt.Errorf("udpspoof receiver: read: %w", err):
				default:
				}
				return
			}
			// Filter by known spoof sources.
			if len(r.filter) > 0 {
				if _, ok := r.filter[src.String()]; !ok {
					continue
				}
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case r.pktCh <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Recv implements transport.DownstreamReceiver.
func (r *Receiver) Recv(ctx context.Context) ([]byte, error) {
	select {
	case pkt := <-r.pktCh:
		return pkt, nil
	case err := <-r.errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the receiver.
func (r *Receiver) Close() error {
	return r.conn.Close()
}

// UpdateFilter replaces the spoof-source filter with a new set of addresses.
func (r *Receiver) UpdateFilter(srcs []net.UDPAddr) {
	filter := make(map[string]struct{}, len(srcs))
	for _, s := range srcs {
		filter[s.String()] = struct{}{}
	}
	r.filter = filter
}

// Ensure transport.DownstreamReceiver is satisfied.
var _ transport.DownstreamReceiver = (*Receiver)(nil)
