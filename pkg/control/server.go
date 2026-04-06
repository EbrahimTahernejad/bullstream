// Package control implements the BullStream control channel server and client.
package control

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ebrahimtahernejad/bullstream/pkg/crypto"
	"github.com/ebrahimtahernejad/bullstream/pkg/proto"
	"github.com/ebrahimtahernejad/bullstream/pkg/session"
)

// ServerConfig holds parameters for the control server.
type ServerConfig struct {
	ListenAddr          string
	PSK                 []byte
	Mode                session.Mode
	FECData             uint8
	FECParity           uint8
	FECFlushMs          int
	ReorderWindow       uint16
	ReorderTimeoutMs    uint16
	SessionWindowBytes  uint32
	MaxSessions         uint16
	IdleTimeoutS        uint16
	Users               map[string]string // username → password
	DialTimeoutS        int
}

// ClientEntry is the server's record of one registered client.
type ClientEntry struct {
	UUID       [16]byte
	ClientID   uint8
	UDPAddr    net.UDPAddr
	DstAddr    string
	Password   []byte
	Sessions   *session.Table
	conn       net.Conn
	cancelFunc context.CancelFunc
}

// Server is the BullStream control-channel server.
type Server struct {
	cfg      ServerConfig
	cipher   *crypto.AESCipher
	listener net.Listener

	mu        sync.Mutex
	// Single mode: at most one client.
	single *ClientEntry
	// Multi mode: CID → entry.
	multi     [16]*ClientEntry
	uuidToCID map[[16]byte]uint8
}

// NewServer creates a control-channel server but does not start it.
func NewServer(cfg ServerConfig) (*Server, error) {
	c, err := crypto.NewAESCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("control server: cipher: %w", err)
	}
	return &Server{
		cfg:       cfg,
		cipher:    c,
		uuidToCID: make(map[[16]byte]uint8),
	}, nil
}

// ListenAndServe binds to the configured address and processes connections until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("control server listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = l
	defer l.Close()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("control server accept: %w", err)
			}
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn processes one control connection.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Enable TCP keepalives.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}

	// Read and process the first message, which must be REGISTER.
	plaintext, err := s.cipher.ReadMsg(conn)
	if err != nil {
		log.Printf("control server: read register from %s: %v", conn.RemoteAddr(), err)
		return
	}
	env, err := proto.UnmarshalEnvelope(plaintext)
	if err != nil {
		log.Printf("control server: unmarshal envelope from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if env.Type != proto.MsgTypeRegister {
		log.Printf("control server: expected REGISTER, got 0x%02x from %s", env.Type, conn.RemoteAddr())
		s.sendNACK(conn, proto.NACKAuthFailure)
		return
	}

	reg, err := proto.UnmarshalRegister(env.Payload)
	if err != nil {
		log.Printf("control server: unmarshal register from %s: %v", conn.RemoteAddr(), err)
		s.sendNACK(conn, proto.NACKAuthFailure)
		return
	}
	if reg.Version != 1 {
		s.sendNACK(conn, proto.NACKVersionMismatch)
		return
	}

	// Validate username.
	pw, ok := s.cfg.Users[reg.Username]
	if !ok {
		log.Printf("control server: unknown user %q from %s", reg.Username, conn.RemoteAddr())
		s.sendNACK(conn, proto.NACKAuthFailure)
		return
	}

	// Validate downstream type.
	if reg.DownstreamType != proto.DownstreamUDPSpoof {
		log.Printf("control server: unsupported downstream type 0x%02x from %s", reg.DownstreamType, conn.RemoteAddr())
		s.sendNACK(conn, proto.NACKUnsupportedSpoofSelect)
		return
	}
	if reg.UDPSpoofConfig != nil {
		if reg.UDPSpoofConfig.SpoofSelect != proto.SpoofSelectRandom &&
			reg.UDPSpoofConfig.SpoofSelect != proto.SpoofSelectRoundRobin {
			s.sendNACK(conn, proto.NACKUnsupportedSpoofSelect)
			return
		}
	}

	clientCtx, cancel := context.WithCancel(ctx)
	entry := &ClientEntry{
		UUID:       reg.UUID,
		DstAddr:    reg.DstAddr,
		Password:   []byte(pw),
		conn:       conn,
		cancelFunc: cancel,
		Sessions: session.NewTable(
			s.cfg.Mode,
			0,
			time.Duration(s.cfg.ReorderTimeoutMs)*time.Millisecond*2,
			int64(s.cfg.SessionWindowBytes),
		),
	}
	if reg.UDPSpoofConfig != nil {
		entry.UDPAddr = reg.UDPSpoofConfig.UDPAddr
	}

	var clientID uint8
	switch s.cfg.Mode {
	case session.ModeSingle:
		clientID = 0
		entry.ClientID = 0
		s.mu.Lock()
		if s.single != nil && s.single.UUID != reg.UUID {
			// Different UUID — evict.
			log.Printf("control server: evicting previous single-mode client")
			s.single.cancelFunc()
			s.single.Sessions.CloseAll()
		}
		s.single = entry
		s.mu.Unlock()

	case session.ModeMulti:
		s.mu.Lock()
		// Check if this UUID already has a slot.
		if cid, exists := s.uuidToCID[reg.UUID]; exists {
			clientID = cid
			if s.multi[cid] != nil {
				s.multi[cid].cancelFunc()
				s.multi[cid].Sessions.CloseAll()
			}
			s.multi[cid] = entry
			entry.ClientID = cid
		} else {
			// Assign a new CID.
			assigned := false
			for i := uint8(0); i < 16; i++ {
				if s.multi[i] == nil {
					clientID = i
					entry.ClientID = i
					s.multi[i] = entry
					s.uuidToCID[reg.UUID] = i
					assigned = true
					break
				}
			}
			if !assigned {
				s.mu.Unlock()
				cancel()
				s.sendNACK(conn, proto.NACKSlotsFull)
				return
			}
		}
		s.mu.Unlock()
		entry.Sessions = session.NewTable(
			s.cfg.Mode,
			clientID,
			time.Duration(s.cfg.ReorderTimeoutMs)*time.Millisecond*2,
			int64(s.cfg.SessionWindowBytes),
		)
	}

	// Send ACK.
	ack := &proto.ACKMsg{
		Mode:               modeToProto(s.cfg.Mode),
		ClientID:           clientID,
		FECData:            s.cfg.FECData,
		FECParity:          s.cfg.FECParity,
		ReorderWindow:      s.cfg.ReorderWindow,
		ReorderTimeoutMs:   s.cfg.ReorderTimeoutMs,
		SessionWindowBytes: s.cfg.SessionWindowBytes,
		MaxSessions:        s.cfg.MaxSessions,
		IdleTimeoutS:       s.cfg.IdleTimeoutS,
	}
	ackBytes := proto.MarshalACK(ack)
	env2 := proto.MarshalEnvelope(proto.MsgTypeACK, ackBytes)
	if err := s.cipher.WriteMsg(conn, env2); err != nil {
		log.Printf("control server: send ACK to %s: %v", conn.RemoteAddr(), err)
		cancel()
		return
	}

	// Main loop: handle HEALTHCHECK and DEREGISTER.
	s.handleClientLoop(clientCtx, conn, entry)
}

// handleClientLoop processes ongoing control messages from an authenticated client.
func (s *Server) handleClientLoop(ctx context.Context, conn net.Conn, entry *ClientEntry) {
	defer func() {
		entry.cancelFunc()
		entry.Sessions.CloseAll()
		s.removeClient(entry)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		plaintext, err := s.cipher.ReadMsg(conn)
		if err != nil {
			log.Printf("control server: read from %s: %v", conn.RemoteAddr(), err)
			return
		}
		env, err := proto.UnmarshalEnvelope(plaintext)
		if err != nil {
			log.Printf("control server: envelope from %s: %v", conn.RemoteAddr(), err)
			return
		}

		switch env.Type {
		case proto.MsgTypeHealthcheck:
			hc, err := proto.UnmarshalHealthcheck(env.Payload)
			if err != nil {
				log.Printf("control server: healthcheck parse: %v", err)
				return
			}
			// Refresh UDPAddr.
			prevAddr := entry.UDPAddr
			entry.UDPAddr = hc.UDPAddr
			if prevAddr.String() != hc.UDPAddr.String() {
				log.Printf("control server: NAT shift for client %x: %s → %s",
					entry.UUID[:4], prevAddr.String(), hc.UDPAddr.String())
			}

			ok := &proto.OKMsg{
				Mode:     modeToProto(s.cfg.Mode),
				ClientID: entry.ClientID,
			}
			okBytes := proto.MarshalOK(ok)
			resp := proto.MarshalEnvelope(proto.MsgTypeOK, okBytes)
			if err := s.cipher.WriteMsg(conn, resp); err != nil {
				log.Printf("control server: send OK: %v", err)
				return
			}

		case proto.MsgTypeDeregister:
			dr, err := proto.UnmarshalDeregister(env.Payload)
			if err != nil {
				log.Printf("control server: deregister parse: %v", err)
				return
			}
			log.Printf("control server: DEREGISTER from client %x CID=%d", dr.UUID[:4], dr.ClientID)
			return

		default:
			log.Printf("control server: unexpected msg type 0x%02x from %s", env.Type, conn.RemoteAddr())
			return
		}
	}
}

// sendNACK sends a NACK message and closes the connection.
func (s *Server) sendNACK(conn net.Conn, reason uint8) {
	nack := proto.MarshalNACK(&proto.NACKMsg{Reason: reason})
	env := proto.MarshalEnvelope(proto.MsgTypeNACK, nack)
	_ = s.cipher.WriteMsg(conn, env)
	conn.Close()
}

// removeClient removes the client entry from the table.
func (s *Server) removeClient(entry *ClientEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.cfg.Mode {
	case session.ModeSingle:
		if s.single == entry {
			s.single = nil
		}
	case session.ModeMulti:
		cid := entry.ClientID
		if s.multi[cid] == entry {
			s.multi[cid] = nil
			delete(s.uuidToCID, entry.UUID)
		}
	}
}

// GetClient returns the ClientEntry for the given UUID, if registered.
func (s *Server) GetClient(uuid [16]byte) *ClientEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.cfg.Mode {
	case session.ModeSingle:
		if s.single != nil && s.single.UUID == uuid {
			return s.single
		}
	case session.ModeMulti:
		if cid, ok := s.uuidToCID[uuid]; ok {
			return s.multi[cid]
		}
	}
	return nil
}

func modeToProto(m session.Mode) uint8 {
	if m == session.ModeMulti {
		return proto.ModeMulti
	}
	return proto.ModeSingle
}
