// Package proto — data frame and downstream packet formats.
package proto

import (
	"encoding/binary"
	"fmt"
)

// Upstream frame MsgType values.
const (
	DataMsgOpen   = 0x10 // 4-byte epoch
	DataMsgData   = 0x11 // raw bytes
	DataMsgFIN    = 0x12 // graceful half-close
	DataMsgReset  = 0x13 // hard abort
	DataMsgWndUpd = 0x14 // 4-byte credit
)

// Downstream packet flag constants.
const (
	FlagData    = 0x01
	FlagParity  = 0x02
	FlagFIN     = 0x04
	FlagReset   = 0x08
	FlagPartial = 0x10
)

// UpstreamFrame is the decoded form of one upstream multiplexed frame.
// SessionID is 16-bit in single mode or 32-bit in multi mode.
type UpstreamFrame struct {
	SessionID  uint32
	MsgType    uint8
	PayloadLen uint16
	Payload    []byte
}

// MarshalUpstreamFrameSingle encodes an UpstreamFrame with a 16-bit SessionID.
// Caller provides a pre-encrypted payload if desired; this marshals the cleartext header.
func MarshalUpstreamFrameSingle(f *UpstreamFrame) []byte {
	buf := make([]byte, 2+1+2+len(f.Payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(f.SessionID))
	buf[2] = f.MsgType
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(f.Payload)))
	copy(buf[5:], f.Payload)
	return buf
}

// MarshalUpstreamFrameMulti encodes an UpstreamFrame with a 32-bit SessionID.
func MarshalUpstreamFrameMulti(f *UpstreamFrame) []byte {
	buf := make([]byte, 4+1+2+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.SessionID)
	buf[4] = f.MsgType
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	copy(buf[7:], f.Payload)
	return buf
}

// UnmarshalUpstreamFrameSingle decodes the header from a buffer; it reads only
// the fixed header and returns offset to the payload start. The caller must
// supply enough bytes (at least 5 for header) and then read PayloadLen bytes.
func UnmarshalUpstreamFrameSingle(b []byte) (*UpstreamFrame, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("upstream frame single: too short (%d)", len(b))
	}
	f := &UpstreamFrame{}
	f.SessionID = uint32(binary.BigEndian.Uint16(b[0:2]))
	f.MsgType = b[2]
	f.PayloadLen = binary.BigEndian.Uint16(b[3:5])
	if len(b) < 5+int(f.PayloadLen) {
		return nil, fmt.Errorf("upstream frame single: payload truncated")
	}
	f.Payload = b[5 : 5+f.PayloadLen]
	return f, nil
}

// UnmarshalUpstreamFrameMulti decodes a multi-mode upstream frame.
func UnmarshalUpstreamFrameMulti(b []byte) (*UpstreamFrame, error) {
	if len(b) < 7 {
		return nil, fmt.Errorf("upstream frame multi: too short (%d)", len(b))
	}
	f := &UpstreamFrame{}
	f.SessionID = binary.BigEndian.Uint32(b[0:4])
	f.MsgType = b[4]
	f.PayloadLen = binary.BigEndian.Uint16(b[5:7])
	if len(b) < 7+int(f.PayloadLen) {
		return nil, fmt.Errorf("upstream frame multi: payload truncated")
	}
	f.Payload = b[7 : 7+f.PayloadLen]
	return f, nil
}

// DownstreamPacket is the decoded form of one UDP downstream packet.
type DownstreamPacket struct {
	SessionID  uint32
	SeqNum     uint32
	Flags      uint8
	PayloadLen uint16
	Payload    []byte // encrypted
}

// MarshalDownstreamPacketSingle encodes a DownstreamPacket with 16-bit SessionID.
func MarshalDownstreamPacketSingle(p *DownstreamPacket) []byte {
	buf := make([]byte, 2+4+1+2+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], uint16(p.SessionID))
	binary.BigEndian.PutUint32(buf[2:6], p.SeqNum)
	buf[6] = p.Flags
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(p.Payload)))
	copy(buf[9:], p.Payload)
	return buf
}

// MarshalDownstreamPacketMulti encodes a DownstreamPacket with 32-bit SessionID.
func MarshalDownstreamPacketMulti(p *DownstreamPacket) []byte {
	buf := make([]byte, 4+4+1+2+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], p.SessionID)
	binary.BigEndian.PutUint32(buf[4:8], p.SeqNum)
	buf[8] = p.Flags
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(p.Payload)))
	copy(buf[11:], p.Payload)
	return buf
}

// UnmarshalDownstreamPacketSingle decodes a single-mode downstream packet.
func UnmarshalDownstreamPacketSingle(b []byte) (*DownstreamPacket, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("downstream single: too short (%d)", len(b))
	}
	p := &DownstreamPacket{}
	p.SessionID = uint32(binary.BigEndian.Uint16(b[0:2]))
	p.SeqNum = binary.BigEndian.Uint32(b[2:6])
	p.Flags = b[6]
	p.PayloadLen = binary.BigEndian.Uint16(b[7:9])
	if len(b) < 9+int(p.PayloadLen) {
		return nil, fmt.Errorf("downstream single: payload truncated")
	}
	p.Payload = b[9 : 9+p.PayloadLen]
	return p, nil
}

// UnmarshalDownstreamPacketMulti decodes a multi-mode downstream packet.
func UnmarshalDownstreamPacketMulti(b []byte) (*DownstreamPacket, error) {
	if len(b) < 11 {
		return nil, fmt.Errorf("downstream multi: too short (%d)", len(b))
	}
	p := &DownstreamPacket{}
	p.SessionID = binary.BigEndian.Uint32(b[0:4])
	p.SeqNum = binary.BigEndian.Uint32(b[4:8])
	p.Flags = b[8]
	p.PayloadLen = binary.BigEndian.Uint16(b[9:11])
	if len(b) < 11+int(p.PayloadLen) {
		return nil, fmt.Errorf("downstream multi: payload truncated")
	}
	p.Payload = b[11 : 11+p.PayloadLen]
	return p, nil
}

// FECGroupFromSeqNum derives the FEC group and position from a SeqNum.
func FECGroupFromSeqNum(seqNum uint32, fecData, fecParity int) (group uint32, pos int) {
	stride := uint32(fecData + fecParity)
	group = seqNum / stride
	pos = int(seqNum % stride)
	return
}
