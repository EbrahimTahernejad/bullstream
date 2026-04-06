// Package upstream provides the server-side upstream connection handler.
package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ebrahimtahernejad/bullstream/pkg/crypto"
	"github.com/ebrahimtahernejad/bullstream/pkg/proto"
	"github.com/ebrahimtahernejad/bullstream/pkg/session"
	"github.com/ebrahimtahernejad/bullstream/pkg/transport"
)

// ClientState contains server-side state for a connected client.
type ClientState struct {
	UUID        [16]byte
	ClientID    uint8
	Password    []byte
	DstAddr     string
	UDPAddr     net.UDPAddr
	Mode        session.Mode
	Sessions    *session.Table
	Sender      transport.DownstreamSender
	WindowBytes int64

	mu     sync.Mutex
	conn   net.Conn
	framer *crypto.ChaChaFramer // per upstream TCP conn, not per session
}

// Handler accepts upstream TCP connections from clients, decrypts frames, and
// routes them to the appropriate session.
type Handler struct {
	listener    net.Listener
	getClient   func(connID string) *ClientState
	dialTimeout time.Duration
	mu          sync.Mutex
}

// NewHandler creates a server upstream handler listening on the given address.
func NewHandler(listenAddr string, dialTimeout time.Duration) (*Handler, error) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("upstream handler listen %s: %w", listenAddr, err)
	}
	return &Handler{listener: l, dialTimeout: dialTimeout}, nil
}

// SetClientLookup registers the function used to find a client's state from
// the remote address string of an incoming upstream connection.
func (h *Handler) SetClientLookup(fn func(connID string) *ClientState) {
	h.mu.Lock()
	h.getClient = fn
	h.mu.Unlock()
}

// Serve accepts connections and handles them in goroutines until ctx is done.
func (h *Handler) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		h.listener.Close()
	}()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("upstream accept: %w", err)
			}
		}
		go h.handleConn(ctx, conn)
	}
}

// handleConn processes one upstream connection.
func (h *Handler) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	h.mu.Lock()
	fn := h.getClient
	h.mu.Unlock()

	if fn == nil {
		log.Printf("upstream: no client lookup registered, dropping %s", remoteAddr)
		return
	}
	cs := fn(remoteAddr)
	if cs == nil {
		log.Printf("upstream: unknown client %s, closing", remoteAddr)
		return
	}

	framer, err := crypto.NewChaChaFramer(cs.Password, 0 /* epoch per-session, set below */)
	if err != nil {
		log.Printf("upstream: failed to create framer for %s: %v", remoteAddr, err)
		return
	}

	cs.mu.Lock()
	cs.conn = conn
	cs.framer = framer
	cs.mu.Unlock()

	isMulti := cs.Mode == session.ModeMulti
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		plaintext, err := framer.ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("upstream: read frame from %s: %v", remoteAddr, err)
			}
			return
		}
		var f *proto.UpstreamFrame
		if isMulti {
			f, err = proto.UnmarshalUpstreamFrameMulti(plaintext)
		} else {
			f, err = proto.UnmarshalUpstreamFrameSingle(plaintext)
		}
		if err != nil {
			log.Printf("upstream: unmarshal frame from %s: %v", remoteAddr, err)
			return
		}
		if err := h.routeFrame(ctx, cs, f, conn, framer); err != nil {
			log.Printf("upstream: route frame sid=%d from %s: %v", f.SessionID, remoteAddr, err)
		}
	}
}

// routeFrame dispatches an upstream frame to the appropriate session handler.
func (h *Handler) routeFrame(ctx context.Context, cs *ClientState, f *proto.UpstreamFrame, conn net.Conn, framer *crypto.ChaChaFramer) error {
	switch f.MsgType {
	case proto.DataMsgOpen:
		return h.handleOpen(ctx, cs, f, conn, framer)
	case proto.DataMsgData:
		return h.handleData(cs, f)
	case proto.DataMsgFIN:
		return h.handleFIN(cs, f)
	case proto.DataMsgReset:
		return h.handleReset(cs, f)
	case proto.DataMsgWndUpd:
		return h.handleWndUpd(cs, f)
	default:
		return fmt.Errorf("unknown msg type 0x%02x", f.MsgType)
	}
}

// handleOpen processes an OPEN frame: create session, dial target, send WNDUPD.
func (h *Handler) handleOpen(ctx context.Context, cs *ClientState, f *proto.UpstreamFrame, conn net.Conn, framer *crypto.ChaChaFramer) error {
	if len(f.Payload) < 4 {
		return fmt.Errorf("OPEN payload too short: %d", len(f.Payload))
	}
	epoch := binary.BigEndian.Uint32(f.Payload[0:4])

	sess, err := cs.Sessions.NewSession(epoch)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	// Dial the destination asynchronously so we don't block the frame reader.
	go func() {
		dialCtx, cancel := context.WithTimeout(ctx, h.dialTimeout)
		defer cancel()
		target, err := net.DialTimeout("tcp", cs.DstAddr, h.dialTimeout)
		_ = dialCtx
		if err != nil {
			log.Printf("upstream: dial dst %s for sid=%d: %v", cs.DstAddr, sess.SessionID, err)
			h.sendReset(conn, framer, cs.Mode, sess.SessionID)
			sess.Close()
			return
		}
		// Send initial WNDUPD to inform client of our receive window.
		if err := h.sendWndUpd(conn, framer, cs.Mode, sess.SessionID, cs.WindowBytes); err != nil {
			log.Printf("upstream: send wndupd for sid=%d: %v", sess.SessionID, err)
		}
		// Pipe data from target back to client via downstream.
		go h.pipeTargetToDownstream(ctx, cs, sess, target)
		// Pipe data from session channel to target.
		go h.pipeSessionToTarget(ctx, cs, sess, target, conn, framer)
	}()
	return nil
}

func (h *Handler) handleData(cs *ClientState, f *proto.UpstreamFrame) error {
	sess := cs.Sessions.Get(f.SessionID)
	if sess == nil {
		return fmt.Errorf("DATA for unknown session %d", f.SessionID)
	}
	if sess.State() == session.StateClosed {
		return nil
	}
	// Deduct credits.
	sess.RecvCredits.Add(-int64(len(f.Payload)))
	return sess.DeliverData(context.Background(), f.Payload)
}

func (h *Handler) handleFIN(cs *ClientState, f *proto.UpstreamFrame) error {
	sess := cs.Sessions.Get(f.SessionID)
	if sess == nil {
		return nil
	}
	sess.SignalFIN()
	return nil
}

func (h *Handler) handleReset(cs *ClientState, f *proto.UpstreamFrame) error {
	sess := cs.Sessions.Get(f.SessionID)
	if sess == nil {
		return nil
	}
	sess.SignalReset()
	cs.Sessions.DeleteAfterQuiet(f.SessionID)
	return nil
}

func (h *Handler) handleWndUpd(cs *ClientState, f *proto.UpstreamFrame) error {
	if len(f.Payload) < 4 {
		return fmt.Errorf("WNDUPD payload too short")
	}
	credits := int64(binary.BigEndian.Uint32(f.Payload[0:4]))
	sess := cs.Sessions.Get(f.SessionID)
	if sess == nil {
		return nil
	}
	sess.SendCredits.Add(credits)
	return nil
}

// pipeTargetToDownstream reads from the target TCP conn and sends downstream UDP.
func (h *Handler) pipeTargetToDownstream(ctx context.Context, cs *ClientState, sess *session.Session, target net.Conn) {
	defer target.Close()
	buf := make([]byte, 1400)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.ResetCh:
			return
		default:
		}
		n, err := target.Read(buf)
		if n > 0 {
			// TODO: FEC encode and send via cs.Sender
			_ = cs.Sender
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("upstream: read target for sid=%d: %v", sess.SessionID, err)
			}
			return
		}
	}
}

// pipeSessionToTarget reads from the session data channel and writes to target.
func (h *Handler) pipeSessionToTarget(ctx context.Context, cs *ClientState, sess *session.Session, target net.Conn, conn net.Conn, framer *crypto.ChaChaFramer) {
	defer func() {
		target.Close()
		sess.Close()
		cs.Sessions.DeleteAfterQuiet(sess.SessionID)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.ResetCh:
			return
		case data, ok := <-sess.DataCh:
			if !ok {
				return
			}
			if _, err := target.Write(data); err != nil {
				log.Printf("upstream: write target for sid=%d: %v", sess.SessionID, err)
				h.sendReset(conn, framer, cs.Mode, sess.SessionID)
				return
			}
			// Replenish send window on the downstream side.
			credits := int64(len(data))
			sess.RecvCredits.Add(credits)
			if err := h.sendWndUpd(conn, framer, cs.Mode, sess.SessionID, credits); err != nil {
				log.Printf("upstream: send wndupd sid=%d: %v", sess.SessionID, err)
				return
			}
		case <-sess.FinCh:
			if err := target.(*net.TCPConn).CloseWrite(); err != nil {
				log.Printf("upstream: close write sid=%d: %v", sess.SessionID, err)
			}
			return
		}
	}
}

// sendWndUpd writes a WNDUPD frame on the upstream TCP connection.
func (h *Handler) sendWndUpd(conn net.Conn, framer *crypto.ChaChaFramer, mode session.Mode, sid uint32, credits int64) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(credits))
	f := &proto.UpstreamFrame{
		SessionID:  sid,
		MsgType:    proto.DataMsgWndUpd,
		PayloadLen: 4,
		Payload:    payload,
	}
	var raw []byte
	if mode == session.ModeMulti {
		raw = proto.MarshalUpstreamFrameMulti(f)
	} else {
		raw = proto.MarshalUpstreamFrameSingle(f)
	}
	return framer.WriteFrame(conn, raw)
}

// sendReset writes a RESET frame on the upstream TCP connection.
func (h *Handler) sendReset(conn net.Conn, framer *crypto.ChaChaFramer, mode session.Mode, sid uint32) {
	f := &proto.UpstreamFrame{
		SessionID: sid,
		MsgType:   proto.DataMsgReset,
	}
	var raw []byte
	if mode == session.ModeMulti {
		raw = proto.MarshalUpstreamFrameMulti(f)
	} else {
		raw = proto.MarshalUpstreamFrameSingle(f)
	}
	if err := framer.WriteFrame(conn, raw); err != nil {
		log.Printf("upstream: send reset sid=%d: %v", sid, err)
	}
}
