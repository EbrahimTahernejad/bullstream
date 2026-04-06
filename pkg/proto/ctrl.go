// Package proto defines BullStream wire-protocol message types and serialisation.
package proto

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Control message type constants.
const (
	MsgTypeRegister    = 0x01
	MsgTypeACK         = 0x02
	MsgTypeHealthcheck = 0x03
	MsgTypeOK          = 0x04
	MsgTypeCHID        = 0x05
	MsgTypeDeregister  = 0x06
	MsgTypeNACK        = 0x07
)

// Downstream type identifiers sent in REGISTER.
const (
	DownstreamUDPSpoof  = 0x01
	DownstreamICMPSpoof = 0x02
)

// SpoofSelect strategies.
const (
	SpoofSelectRandom     = 0x00
	SpoofSelectRoundRobin = 0x01
)

// Session mode constants returned in ACK.
const (
	ModeSingle = 0x00
	ModeMulti  = 0x01
)

// NACK reason codes.
const (
	NACKVersionMismatch        = 0x01
	NACKAuthFailure            = 0x02
	NACKSlotsFull              = 0x03
	NACKUnsupportedSpoofSelect = 0x04
)

// RegisterMsg is sent by the client to register itself with the server.
type RegisterMsg struct {
	Version        uint8
	UUID           [16]byte
	Username       string
	DstAddr        string
	DownstreamType uint8
	// Only valid when DownstreamType == DownstreamUDPSpoof.
	UDPSpoofConfig *UDPSpoofRegisterConfig
}

// UDPSpoofRegisterConfig carries downstream udp_spoof parameters from the client.
type UDPSpoofRegisterConfig struct {
	UDPAddr     net.UDPAddr // 4-byte IPv4 + 2-byte port
	SpoofCount  uint8
	SpoofSelect uint8
	SpoofSrcs   []net.UDPAddr
}

// MarshalRegister serialises a RegisterMsg into a byte slice.
func MarshalRegister(m *RegisterMsg) ([]byte, error) {
	buf := make([]byte, 0, 64)
	buf = append(buf, m.Version)
	buf = append(buf, m.UUID[:]...)

	// Username: 1-byte length prefix + bytes.
	if len(m.Username) > 255 {
		return nil, fmt.Errorf("username too long: %d", len(m.Username))
	}
	buf = append(buf, byte(len(m.Username)))
	buf = append(buf, []byte(m.Username)...)

	// DstAddr: 1-byte length prefix + bytes.
	if len(m.DstAddr) > 255 {
		return nil, fmt.Errorf("dst_addr too long: %d", len(m.DstAddr))
	}
	buf = append(buf, byte(len(m.DstAddr)))
	buf = append(buf, []byte(m.DstAddr)...)

	buf = append(buf, m.DownstreamType)

	switch m.DownstreamType {
	case DownstreamUDPSpoof:
		if m.UDPSpoofConfig == nil {
			return nil, fmt.Errorf("UDPSpoofConfig required for DownstreamUDPSpoof")
		}
		c := m.UDPSpoofConfig
		ip4 := c.UDPAddr.IP.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("UDPAddr must be IPv4")
		}
		buf = append(buf, ip4...)
		buf = appendUint16BE(buf, uint16(c.UDPAddr.Port))
		buf = append(buf, c.SpoofCount)
		buf = append(buf, c.SpoofSelect)
		for i := 0; i < int(c.SpoofCount); i++ {
			src4 := c.SpoofSrcs[i].IP.To4()
			if src4 == nil {
				return nil, fmt.Errorf("spoof src %d must be IPv4", i)
			}
			buf = append(buf, src4...)
			buf = appendUint16BE(buf, uint16(c.SpoofSrcs[i].Port))
		}
	}
	return buf, nil
}

// UnmarshalRegister parses a RegisterMsg from raw plaintext bytes.
func UnmarshalRegister(b []byte) (*RegisterMsg, error) {
	if len(b) < 1+16+1 {
		return nil, fmt.Errorf("register too short")
	}
	m := &RegisterMsg{}
	pos := 0
	m.Version = b[pos]
	pos++
	copy(m.UUID[:], b[pos:pos+16])
	pos += 16

	ulen := int(b[pos])
	pos++
	if pos+ulen > len(b) {
		return nil, fmt.Errorf("register truncated at username")
	}
	m.Username = string(b[pos : pos+ulen])
	pos += ulen

	if pos >= len(b) {
		return nil, fmt.Errorf("register truncated at dst_addr length")
	}
	dlen := int(b[pos])
	pos++
	if pos+dlen > len(b) {
		return nil, fmt.Errorf("register truncated at dst_addr")
	}
	m.DstAddr = string(b[pos : pos+dlen])
	pos += dlen

	if pos >= len(b) {
		return nil, fmt.Errorf("register truncated at downstream type")
	}
	m.DownstreamType = b[pos]
	pos++

	switch m.DownstreamType {
	case DownstreamUDPSpoof:
		if pos+6+2 > len(b) {
			return nil, fmt.Errorf("register truncated at udp_spoof config")
		}
		c := &UDPSpoofRegisterConfig{}
		c.UDPAddr.IP = net.IP(b[pos : pos+4]).To16()
		c.UDPAddr.Port = int(binary.BigEndian.Uint16(b[pos+4 : pos+6]))
		pos += 6
		c.SpoofCount = b[pos]
		pos++
		c.SpoofSelect = b[pos]
		pos++
		c.SpoofSrcs = make([]net.UDPAddr, c.SpoofCount)
		for i := 0; i < int(c.SpoofCount); i++ {
			if pos+6 > len(b) {
				return nil, fmt.Errorf("register truncated at spoof src %d", i)
			}
			c.SpoofSrcs[i].IP = net.IP(b[pos : pos+4]).To16()
			c.SpoofSrcs[i].Port = int(binary.BigEndian.Uint16(b[pos+4 : pos+6]))
			pos += 6
		}
		m.UDPSpoofConfig = c
	}
	return m, nil
}

// ACKMsg is sent by the server on successful REGISTER.
type ACKMsg struct {
	Mode               uint8
	ClientID           uint8
	FECData            uint8
	FECParity          uint8
	ReorderWindow      uint16
	ReorderTimeoutMs   uint16
	SessionWindowBytes uint32
	MaxSessions        uint16
	IdleTimeoutS       uint16
}

// MarshalACK serialises an ACKMsg.
func MarshalACK(m *ACKMsg) []byte {
	buf := make([]byte, 15)
	buf[0] = m.Mode
	buf[1] = m.ClientID
	buf[2] = m.FECData
	buf[3] = m.FECParity
	binary.BigEndian.PutUint16(buf[4:6], m.ReorderWindow)
	binary.BigEndian.PutUint16(buf[6:8], m.ReorderTimeoutMs)
	binary.BigEndian.PutUint32(buf[8:12], m.SessionWindowBytes)
	binary.BigEndian.PutUint16(buf[12:14], m.MaxSessions)
	binary.BigEndian.PutUint16(buf[14:16], m.IdleTimeoutS)
	return buf[:16]
}

// UnmarshalACK parses an ACKMsg from raw bytes.
func UnmarshalACK(b []byte) (*ACKMsg, error) {
	if len(b) < 16 {
		return nil, fmt.Errorf("ack too short: %d", len(b))
	}
	return &ACKMsg{
		Mode:               b[0],
		ClientID:           b[1],
		FECData:            b[2],
		FECParity:          b[3],
		ReorderWindow:      binary.BigEndian.Uint16(b[4:6]),
		ReorderTimeoutMs:   binary.BigEndian.Uint16(b[6:8]),
		SessionWindowBytes: binary.BigEndian.Uint32(b[8:12]),
		MaxSessions:        binary.BigEndian.Uint16(b[12:14]),
		IdleTimeoutS:       binary.BigEndian.Uint16(b[14:16]),
	}, nil
}

// HealthcheckMsg is sent periodically by the client to refresh NAT mappings.
type HealthcheckMsg struct {
	UUID     [16]byte
	UDPAddr  net.UDPAddr
	ClientID uint8
}

// MarshalHealthcheck serialises a HealthcheckMsg.
func MarshalHealthcheck(m *HealthcheckMsg) ([]byte, error) {
	buf := make([]byte, 23)
	copy(buf[0:16], m.UUID[:])
	ip4 := m.UDPAddr.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("UDPAddr must be IPv4")
	}
	copy(buf[16:20], ip4)
	binary.BigEndian.PutUint16(buf[20:22], uint16(m.UDPAddr.Port))
	buf[22] = m.ClientID
	return buf, nil
}

// UnmarshalHealthcheck parses a HealthcheckMsg.
func UnmarshalHealthcheck(b []byte) (*HealthcheckMsg, error) {
	if len(b) < 23 {
		return nil, fmt.Errorf("healthcheck too short: %d", len(b))
	}
	m := &HealthcheckMsg{}
	copy(m.UUID[:], b[0:16])
	m.UDPAddr.IP = net.IP(b[16:20]).To16()
	m.UDPAddr.Port = int(binary.BigEndian.Uint16(b[20:22]))
	m.ClientID = b[22]
	return m, nil
}

// OKMsg is the server's response to a HEALTHCHECK.
type OKMsg struct {
	Mode     uint8
	ClientID uint8
}

// MarshalOK serialises an OKMsg.
func MarshalOK(m *OKMsg) []byte {
	return []byte{m.Mode, m.ClientID}
}

// UnmarshalOK parses an OKMsg.
func UnmarshalOK(b []byte) (*OKMsg, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("ok too short: %d", len(b))
	}
	return &OKMsg{Mode: b[0], ClientID: b[1]}, nil
}

// CHIDMsg is sent by the server when the client's CID has changed.
type CHIDMsg struct {
	NewClientID uint8
}

// MarshalCHID serialises a CHIDMsg.
func MarshalCHID(m *CHIDMsg) []byte {
	return []byte{m.NewClientID}
}

// UnmarshalCHID parses a CHIDMsg.
func UnmarshalCHID(b []byte) (*CHIDMsg, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("chid too short")
	}
	return &CHIDMsg{NewClientID: b[0]}, nil
}

// DeregisterMsg is sent by the client on graceful shutdown.
type DeregisterMsg struct {
	UUID     [16]byte
	ClientID uint8
}

// MarshalDeregister serialises a DeregisterMsg.
func MarshalDeregister(m *DeregisterMsg) []byte {
	buf := make([]byte, 17)
	copy(buf[0:16], m.UUID[:])
	buf[16] = m.ClientID
	return buf
}

// UnmarshalDeregister parses a DeregisterMsg.
func UnmarshalDeregister(b []byte) (*DeregisterMsg, error) {
	if len(b) < 17 {
		return nil, fmt.Errorf("deregister too short: %d", len(b))
	}
	m := &DeregisterMsg{}
	copy(m.UUID[:], b[0:16])
	m.ClientID = b[16]
	return m, nil
}

// NACKMsg is sent by the server when REGISTER fails.
type NACKMsg struct {
	Reason uint8
}

// MarshalNACK serialises a NACKMsg.
func MarshalNACK(m *NACKMsg) []byte {
	return []byte{m.Reason}
}

// UnmarshalNACK parses a NACKMsg.
func UnmarshalNACK(b []byte) (*NACKMsg, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("nack too short")
	}
	return &NACKMsg{Reason: b[0]}, nil
}

// CtrlEnvelope wraps a single control message with its type byte.
// The type byte is prepended to the plaintext before encryption.
type CtrlEnvelope struct {
	Type    uint8
	Payload []byte
}

// MarshalEnvelope prepends the type byte to the payload.
func MarshalEnvelope(msgType uint8, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = msgType
	copy(out[1:], payload)
	return out
}

// UnmarshalEnvelope splits a decrypted blob into type + payload.
func UnmarshalEnvelope(b []byte) (*CtrlEnvelope, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("envelope empty")
	}
	return &CtrlEnvelope{Type: b[0], Payload: b[1:]}, nil
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// ErrHexOdd is returned when a hex string has an odd number of characters.
var ErrHexOdd = fmt.Errorf("hex string has odd length")

// ErrBadHexChar is returned when a hex string contains an invalid character.
var ErrBadHexChar = fmt.Errorf("invalid hex character")
