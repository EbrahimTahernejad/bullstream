// Command client runs the BullStream client: local TCP listener + tunnel.
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ebrahimtahernejad/bullstream/pkg/config"
	"github.com/ebrahimtahernejad/bullstream/pkg/control"
	"github.com/ebrahimtahernejad/bullstream/pkg/crypto"
	"github.com/ebrahimtahernejad/bullstream/pkg/proto"
	"github.com/ebrahimtahernejad/bullstream/pkg/session"
	"github.com/ebrahimtahernejad/bullstream/pkg/transport/upstream/plaintcp"
	"github.com/ebrahimtahernejad/bullstream/pkg/transport/upstream/vless"
)

const uuidFile = "~/.bullstream/uuid"

func main() {
	cfgPath := flag.String("config", "client.yaml", "path to client config file")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		log.Fatalf("client: load config: %v", err)
	}

	// Decode PSK.
	psk := decodePSK(cfg.PSK)

	// Load or generate UUID.
	uuid, err := loadOrCreateUUID()
	if err != nil {
		log.Fatalf("client: uuid: %v", err)
	}
	log.Printf("client: UUID = %s", formatUUID(uuid))

	// Build downstream registration config.
	var udpSpoofCfg *proto.UDPSpoofRegisterConfig
	var listenPort int
	if cfg.Downstream.Type == "udp_spoof" && cfg.Downstream.UDPSpoof != nil {
		ds := cfg.Downstream.UDPSpoof
		listenPort = ds.ListenPort
		pubIP := net.ParseIP(ds.PublicIP)
		if pubIP == nil {
			log.Fatalf("client: invalid public_ip %q", ds.PublicIP)
		}
		spoofSrcs := make([]net.UDPAddr, 0, len(ds.SpoofSources))
		for _, s := range ds.SpoofSources {
			addr, err := net.ResolveUDPAddr("udp4", s)
			if err != nil {
				log.Fatalf("client: invalid spoof source %q: %v", s, err)
			}
			spoofSrcs = append(spoofSrcs, *addr)
		}
		var sel uint8
		switch ds.SpoofSelect {
		case "random", "":
			sel = proto.SpoofSelectRandom
		case "round-robin":
			sel = proto.SpoofSelectRoundRobin
		default:
			log.Fatalf("client: unknown spoof_select %q", ds.SpoofSelect)
		}
		udpSpoofCfg = &proto.UDPSpoofRegisterConfig{
			UDPAddr:     net.UDPAddr{IP: pubIP.To4(), Port: listenPort},
			SpoofCount:  uint8(len(spoofSrcs)),
			SpoofSelect: sel,
			SpoofSrcs:   spoofSrcs,
		}
	}

	healthInterval := time.Duration(cfg.HealthcheckIntervalS) * time.Second
	if healthInterval <= 0 {
		healthInterval = 30 * time.Second
	}
	keepalive := time.Duration(cfg.CtrlKeepaliveS) * time.Second
	if keepalive <= 0 {
		keepalive = 15 * time.Second
	}
	dialTimeout := time.Duration(cfg.DialTimeoutS) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}

	ctrlCfg := control.ClientClientConfig{
		CtrlDest:            cfg.Upstream.CtrlDest,
		PSK:                 psk,
		UUID:                uuid,
		Username:            cfg.Username,
		Password:            cfg.Password,
		DstAddr:             cfg.DstAddr,
		HealthcheckInterval: healthInterval,
		KeepaliveInterval:   keepalive,
		DialTimeout:         dialTimeout,
		DownstreamType:      proto.DownstreamUDPSpoof,
		UDPSpoofConfig:      udpSpoofCfg,
	}

	ctrlClient, err := control.NewClient(ctrlCfg)
	if err != nil {
		log.Fatalf("client: control client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("client: shutting down")
		cancel()
	}()

	// Connect and REGISTER.
	params, err := ctrlClient.Connect(ctx)
	if err != nil {
		log.Fatalf("client: register: %v", err)
	}
	log.Printf("client: connected mode=%d fec=%d+%d window=%d",
		params.Mode, params.FECData, params.FECParity, params.SessionWindowBytes)

	// Dial upstream data connection (after receiving ACK).
	var dataConn net.Conn
	switch cfg.Upstream.Type {
	case "tcp", "":
		d := plaintcp.NewDialer(cfg.Upstream.DataDest)
		dataConn, err = d.Dial(ctx)
	case "vless":
		if cfg.Upstream.VLESS == nil {
			log.Fatalf("client: vless config required for type=vless")
		}
		d, verr := vless.NewDialer(
			cfg.Upstream.VLESS.Proxy,
			cfg.Upstream.VLESS.UUID,
			cfg.Upstream.DataDest,
			cfg.Upstream.VLESS.TLS,
		)
		if verr != nil {
			log.Fatalf("client: vless dialer: %v", verr)
		}
		dataConn, err = d.Dial(ctx)
	default:
		log.Fatalf("client: unknown upstream type %q", cfg.Upstream.Type)
	}
	if err != nil {
		log.Fatalf("client: dial data: %v", err)
	}
	log.Printf("client: data connection established to %s", cfg.Upstream.DataDest)

	// Build ChaCha framer for data connection.
	// Epoch 0 used at the connection level; each session has its own epoch in OPEN.
	framer, err := crypto.NewChaChaFramer([]byte(cfg.Password), 0)
	if err != nil {
		log.Fatalf("client: chacha framer: %v", err)
	}

	// Start local TCP listener.
	localListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("client: listen %s: %v", cfg.ListenAddr, err)
	}
	log.Printf("client: listening on %s", cfg.ListenAddr)

	// Session table.
	reorderTO := time.Duration(params.ReorderTimeoutMs) * time.Millisecond
	sessTable := session.NewTable(params.Mode, params.ClientID, reorderTO, int64(params.SessionWindowBytes))
	var writeMu sync.Mutex

	// Accept local connections.
	go func() {
		for {
			localConn, err := localListener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("client: accept: %v", err)
					continue
				}
			}
			go handleLocalConn(ctx, localConn, sessTable, dataConn, framer, params, &writeMu)
		}
	}()

	// Run healthcheck (blocking until error or ctx done).
	var currentUDPAddr *net.UDPAddr
	if udpSpoofCfg != nil {
		currentUDPAddr = &udpSpoofCfg.UDPAddr
	}

	go func() {
		if err := ctrlClient.RunHealthcheck(ctx, func() *net.UDPAddr {
			return currentUDPAddr
		}); err != nil {
			if ctx.Err() == nil {
				log.Printf("client: healthcheck error: %v", err)
				cancel()
			}
		}
	}()

	<-ctx.Done()
	log.Println("client: context done, deregistering")
	if err := ctrlClient.Deregister(); err != nil {
		log.Printf("client: deregister: %v", err)
	}
	localListener.Close()
	dataConn.Close()
}

// handleLocalConn opens a new BullStream session for a local TCP connection.
func handleLocalConn(ctx context.Context, localConn net.Conn, table *session.Table, dataConn net.Conn, framer *crypto.ChaChaFramer, params *control.NegotiatedParams, mu *sync.Mutex) {
	defer localConn.Close()

	// Generate epoch.
	var epochBytes [4]byte
	if _, err := io.ReadFull(newRandReader(), epochBytes[:]); err != nil {
		log.Printf("client: generate epoch: %v", err)
		return
	}
	epoch := uint32(epochBytes[0])<<24 | uint32(epochBytes[1])<<16 | uint32(epochBytes[2])<<8 | uint32(epochBytes[3])

	sess, err := table.NewSession(epoch)
	if err != nil {
		log.Printf("client: new session: %v", err)
		return
	}
	defer func() {
		sess.Close()
		table.DeleteAfterQuiet(sess.SessionID)
	}()

	// Send OPEN frame.
	openPayload := make([]byte, 4)
	openPayload[0] = byte(epoch >> 24)
	openPayload[1] = byte(epoch >> 16)
	openPayload[2] = byte(epoch >> 8)
	openPayload[3] = byte(epoch)

	openFrame := &proto.UpstreamFrame{
		SessionID:  sess.SessionID,
		MsgType:    proto.DataMsgOpen,
		PayloadLen: 4,
		Payload:    openPayload,
	}
	var openRaw []byte
	if params.Mode == session.ModeMulti {
		openRaw = proto.MarshalUpstreamFrameMulti(openFrame)
	} else {
		openRaw = proto.MarshalUpstreamFrameSingle(openFrame)
	}
	mu.Lock()
	err = framer.WriteFrame(dataConn, openRaw)
	mu.Unlock()
	if err != nil {
		log.Printf("client: send OPEN sid=%d: %v", sess.SessionID, err)
		return
	}

	// Proxy local → upstream.
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.ResetCh:
			return
		default:
		}

		n, err := localConn.Read(buf)
		if n > 0 {
			// Check window credits.
			for sess.SendCredits.Load() <= 0 {
				select {
				case <-ctx.Done():
					return
				case <-sess.ResetCh:
					return
				case <-time.After(time.Millisecond):
				}
			}
			dataFrame := &proto.UpstreamFrame{
				SessionID:  sess.SessionID,
				MsgType:    proto.DataMsgData,
				PayloadLen: uint16(n),
				Payload:    buf[:n],
			}
			var raw []byte
			if params.Mode == session.ModeMulti {
				raw = proto.MarshalUpstreamFrameMulti(dataFrame)
			} else {
				raw = proto.MarshalUpstreamFrameSingle(dataFrame)
			}
			mu.Lock()
			werr := framer.WriteFrame(dataConn, raw)
			mu.Unlock()
			if werr != nil {
				log.Printf("client: send DATA sid=%d: %v", sess.SessionID, werr)
				return
			}
			sess.SendCredits.Add(-int64(n))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("client: read local sid=%d: %v", sess.SessionID, err)
			}
			break
		}
	}

	// Send FIN.
	finFrame := &proto.UpstreamFrame{
		SessionID: sess.SessionID,
		MsgType:   proto.DataMsgFIN,
	}
	var finRaw []byte
	if params.Mode == session.ModeMulti {
		finRaw = proto.MarshalUpstreamFrameMulti(finFrame)
	} else {
		finRaw = proto.MarshalUpstreamFrameSingle(finFrame)
	}
	mu.Lock()
	_ = framer.WriteFrame(dataConn, finRaw)
	mu.Unlock()
}

// loadOrCreateUUID loads the persisted UUID or creates and saves a new one.
func loadOrCreateUUID() ([16]byte, error) {
	var uuid [16]byte
	path := expandHome(uuidFile)

	data, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(data))
		decoded, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
		if err == nil && len(decoded) == 16 {
			copy(uuid[:], decoded)
			return uuid, nil
		}
	}

	// Generate new UUID (random v4).
	if _, err := io.ReadFull(newRandReader(), uuid[:]); err != nil {
		return uuid, fmt.Errorf("generate uuid: %w", err)
	}
	// Set version 4 and variant bits.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	// Persist.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return uuid, fmt.Errorf("create uuid dir: %w", err)
	}
	formatted := formatUUID(uuid)
	if err := os.WriteFile(path, []byte(formatted+"\n"), 0o600); err != nil {
		return uuid, fmt.Errorf("write uuid: %w", err)
	}
	return uuid, nil
}

func formatUUID(u [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func decodePSK(s string) []byte {
	// Try hex decode first.
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil {
			return b
		}
	}
	return []byte(s)
}

func newRandReader() io.Reader {
	return crand.Reader
}
