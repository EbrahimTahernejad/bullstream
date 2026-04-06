// Package control — BullStream control-channel client.
package control

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ebrahimtahernejad/bullstream/pkg/crypto"
	"github.com/ebrahimtahernejad/bullstream/pkg/proto"
	"github.com/ebrahimtahernejad/bullstream/pkg/session"
)

// ClientConfig holds parameters for the control client.
type ClientClientConfig struct {
	CtrlDest            string
	PSK                 []byte
	UUID                [16]byte
	Username            string
	Password            string
	DstAddr             string
	HealthcheckInterval time.Duration
	KeepaliveInterval   time.Duration
	DialTimeout         time.Duration
	// Downstream registration parameters.
	DownstreamType    uint8
	UDPSpoofConfig    *proto.UDPSpoofRegisterConfig
}

// NegotiatedParams contains the server-authoritative parameters from ACK.
type NegotiatedParams struct {
	Mode               session.Mode
	ClientID           uint8
	FECData            uint8
	FECParity          uint8
	ReorderWindow      uint16
	ReorderTimeoutMs   uint16
	SessionWindowBytes uint32
	MaxSessions        uint16
	IdleTimeoutS       uint16
}

// Client manages the persistent control connection to the server.
type Client struct {
	cfg    ClientClientConfig
	cipher *crypto.AESCipher

	conn     net.Conn
	params   NegotiatedParams
	clientID uint8
}

// NewClient creates a control client.
func NewClient(cfg ClientClientConfig) (*Client, error) {
	c, err := crypto.NewAESCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("control client: cipher: %w", err)
	}
	return &Client{cfg: cfg, cipher: c}, nil
}

// Connect dials the control server, sends REGISTER, and receives ACK.
// Returns the negotiated parameters on success.
func (c *Client) Connect(ctx context.Context) (*NegotiatedParams, error) {
	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()

	var nd net.Dialer
	conn, err := nd.DialContext(dialCtx, "tcp", c.cfg.CtrlDest)
	if err != nil {
		return nil, fmt.Errorf("control client: dial %s: %w", c.cfg.CtrlDest, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(c.cfg.KeepaliveInterval)
	}
	c.conn = conn

	// Send REGISTER.
	reg := &proto.RegisterMsg{
		Version:        1,
		UUID:           c.cfg.UUID,
		Username:       c.cfg.Username,
		DstAddr:        c.cfg.DstAddr,
		DownstreamType: c.cfg.DownstreamType,
		UDPSpoofConfig: c.cfg.UDPSpoofConfig,
	}
	regBytes, err := proto.MarshalRegister(reg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("control client: marshal register: %w", err)
	}
	env := proto.MarshalEnvelope(proto.MsgTypeRegister, regBytes)
	if err := c.cipher.WriteMsg(conn, env); err != nil {
		conn.Close()
		return nil, fmt.Errorf("control client: send register: %w", err)
	}

	// Read ACK or NACK.
	plaintext, err := c.cipher.ReadMsg(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("control client: read ack: %w", err)
	}
	resp, err := proto.UnmarshalEnvelope(plaintext)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("control client: unmarshal ack envelope: %w", err)
	}

	switch resp.Type {
	case proto.MsgTypeNACK:
		conn.Close()
		nack, _ := proto.UnmarshalNACK(resp.Payload)
		return nil, fmt.Errorf("control client: NACK reason=0x%02x", nack.Reason)

	case proto.MsgTypeACK:
		ack, err := proto.UnmarshalACK(resp.Payload)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("control client: unmarshal ack: %w", err)
		}
		var mode session.Mode
		if ack.Mode == proto.ModeMulti {
			mode = session.ModeMulti
		} else {
			mode = session.ModeSingle
		}
		c.params = NegotiatedParams{
			Mode:               mode,
			ClientID:           ack.ClientID,
			FECData:            ack.FECData,
			FECParity:          ack.FECParity,
			ReorderWindow:      ack.ReorderWindow,
			ReorderTimeoutMs:   ack.ReorderTimeoutMs,
			SessionWindowBytes: ack.SessionWindowBytes,
			MaxSessions:        ack.MaxSessions,
			IdleTimeoutS:       ack.IdleTimeoutS,
		}
		c.clientID = ack.ClientID
		log.Printf("control client: registered, mode=%d CID=%d", ack.Mode, ack.ClientID)
		return &c.params, nil

	default:
		conn.Close()
		return nil, fmt.Errorf("control client: unexpected response type 0x%02x", resp.Type)
	}
}

// RunHealthcheck sends periodic HEALTHCHECK messages and handles server responses.
// It exits if the context is cancelled, if a mode mismatch is detected, or on error.
func (c *Client) RunHealthcheck(ctx context.Context, udpAddr func() *net.UDPAddr) error {
	ticker := time.NewTicker(c.cfg.HealthcheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		addr := udpAddr()
		if addr == nil {
			continue
		}

		hc := &proto.HealthcheckMsg{
			UUID:     c.cfg.UUID,
			UDPAddr:  *addr,
			ClientID: c.clientID,
		}
		hcBytes, err := proto.MarshalHealthcheck(hc)
		if err != nil {
			return fmt.Errorf("control client: marshal healthcheck: %w", err)
		}
		env := proto.MarshalEnvelope(proto.MsgTypeHealthcheck, hcBytes)
		if err := c.cipher.WriteMsg(c.conn, env); err != nil {
			return fmt.Errorf("control client: send healthcheck: %w", err)
		}

		// Read server response.
		plaintext, err := c.cipher.ReadMsg(c.conn)
		if err != nil {
			return fmt.Errorf("control client: read healthcheck response: %w", err)
		}
		resp, err := proto.UnmarshalEnvelope(plaintext)
		if err != nil {
			return fmt.Errorf("control client: unmarshal healthcheck response: %w", err)
		}

		switch resp.Type {
		case proto.MsgTypeOK:
			ok, err := proto.UnmarshalOK(resp.Payload)
			if err != nil {
				return fmt.Errorf("control client: unmarshal OK: %w", err)
			}
			// Check mode mismatch.
			expectedMode := uint8(proto.ModeSingle)
			if c.params.Mode == session.ModeMulti {
				expectedMode = proto.ModeMulti
			}
			if ok.Mode != expectedMode {
				return fmt.Errorf("control client: mode mismatch (expected %d, got %d) — exiting", expectedMode, ok.Mode)
			}
			// Check CID mismatch in multi mode.
			if c.params.Mode == session.ModeMulti && ok.ClientID != c.clientID {
				log.Printf("control client: CID mismatch (expected %d, got %d) — waiting for CHID", c.clientID, ok.ClientID)
			}

		case proto.MsgTypeCHID:
			chid, err := proto.UnmarshalCHID(resp.Payload)
			if err != nil {
				return fmt.Errorf("control client: unmarshal CHID: %w", err)
			}
			log.Printf("control client: CID updated %d → %d", c.clientID, chid.NewClientID)
			c.clientID = chid.NewClientID

		default:
			log.Printf("control client: unexpected healthcheck response type 0x%02x", resp.Type)
		}
	}
}

// Deregister sends a graceful DEREGISTER message and closes the control connection.
func (c *Client) Deregister() error {
	if c.conn == nil {
		return nil
	}
	dr := proto.MarshalDeregister(&proto.DeregisterMsg{
		UUID:     c.cfg.UUID,
		ClientID: c.clientID,
	})
	env := proto.MarshalEnvelope(proto.MsgTypeDeregister, dr)
	if err := c.cipher.WriteMsg(c.conn, env); err != nil {
		c.conn.Close()
		return fmt.Errorf("control client: deregister: %w", err)
	}
	return c.conn.Close()
}

// ClientID returns the currently assigned client ID.
func (c *Client) ClientID() uint8 {
	return c.clientID
}

// Params returns the negotiated server parameters.
func (c *Client) Params() NegotiatedParams {
	return c.params
}
