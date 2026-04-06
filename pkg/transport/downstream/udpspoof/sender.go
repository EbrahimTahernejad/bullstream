// Package udpspoof implements the server-side spoofed-UDP downstream sender.
package udpspoof

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ebrahimtahernejad/bullstream/pkg/transport"
	"github.com/ebrahimtahernejad/bullstream/pkg/transport/downstream"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SpoofSelect controls how the sender picks a spoof source for each FEC group.
type SpoofSelect int

const (
	// SpoofSelectRandom picks a random spoof source per FEC group.
	SpoofSelectRandom SpoofSelect = iota
	// SpoofSelectRoundRobin cycles through spoof sources per FEC group.
	SpoofSelectRoundRobin
)

// Sender implements transport.DownstreamSender using a raw IP socket to
// spoof the source address of outgoing UDP packets.
type Sender struct {
	dstIP    net.IP
	dstPort  uint16
	srcs     []spoofSrc
	strategy SpoofSelect
	pacer    *downstream.Pacer

	rawFd    int
	mu       sync.Mutex
	rrCursor atomic.Uint32
}

type spoofSrc struct {
	ip   net.IP
	port uint16
}

// NewSender creates a raw-socket UDP spoof sender.
// dstAddr is the client's public UDP address.
// srcs is the list of spoofed source addresses (IP:port).
// strategy selects how to pick a source per FEC group.
// pacer is the token-bucket rate limiter (may be nil for no pacing).
func NewSender(dstAddr *net.UDPAddr, srcs []net.UDPAddr, strategy SpoofSelect, pacer *downstream.Pacer) (*Sender, error) {
	if len(srcs) == 0 {
		return nil, fmt.Errorf("udpspoof sender: at least one spoof source required")
	}

	// Open raw socket IPPROTO_RAW so we write full IP headers.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("udpspoof sender: raw socket: %w", err)
	}
	// IP_HDRINCL is implicitly set for IPPROTO_RAW on Linux, but set it explicitly.
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("udpspoof sender: IP_HDRINCL: %w", err)
	}

	spoofSrcs := make([]spoofSrc, len(srcs))
	for i, s := range srcs {
		ip4 := s.IP.To4()
		if ip4 == nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("udpspoof sender: spoof src must be IPv4")
		}
		spoofSrcs[i] = spoofSrc{ip: ip4, port: uint16(s.Port)}
	}
	dstIP4 := dstAddr.IP.To4()
	if dstIP4 == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("udpspoof sender: dst must be IPv4")
	}

	return &Sender{
		dstIP:    dstIP4,
		dstPort:  uint16(dstAddr.Port),
		srcs:     spoofSrcs,
		strategy: strategy,
		pacer:    pacer,
		rawFd:    fd,
	}, nil
}

// Send implements transport.DownstreamSender.
// pkt is the complete downstream packet bytes (header + encrypted payload).
func (s *Sender) Send(pkt []byte) error {
	src := s.pickSrc()

	if s.pacer != nil {
		if err := s.pacer.Wait(context.Background(), len(pkt)); err != nil {
			return fmt.Errorf("udpspoof send: pacer: %w", err)
		}
	}

	raw, err := s.buildPacket(src, pkt)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dst := syscall.SockaddrInet4{Port: int(s.dstPort)}
	copy(dst.Addr[:], s.dstIP)
	if err := syscall.Sendto(s.rawFd, raw, 0, &dst); err != nil {
		return fmt.Errorf("udpspoof sendto: %w", err)
	}
	return nil
}

// Close releases the raw socket.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return syscall.Close(s.rawFd)
}

// UpdateDst changes the destination address (called when HEALTHCHECK reports a new UDPAddr).
func (s *Sender) UpdateDst(addr *net.UDPAddr) error {
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("udpspoof: dst must be IPv4")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dstIP = ip4
	s.dstPort = uint16(addr.Port)
	return nil
}

// pickSrc selects a spoof source for this packet/group.
func (s *Sender) pickSrc() spoofSrc {
	switch s.strategy {
	case SpoofSelectRoundRobin:
		i := s.rrCursor.Add(1) - 1
		return s.srcs[int(i)%len(s.srcs)]
	default: // Random
		return s.srcs[rand.Intn(len(s.srcs))]
	}
}

// buildPacket constructs a raw IP+UDP frame using gopacket.
func (s *Sender) buildPacket(src spoofSrc, payload []byte) ([]byte, error) {
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    src.ip,
		DstIP:    s.dstIP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(src.port),
		DstPort: layers.UDPPort(s.dstPort),
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, fmt.Errorf("udpspoof: set checksum layer: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("udpspoof serialize: %w", err)
	}
	return buf.Bytes(), nil
}

// Ensure transport.DownstreamSender is satisfied.
var _ transport.DownstreamSender = (*Sender)(nil)

// Suppress unused import warning for binary.
var _ = binary.BigEndian
