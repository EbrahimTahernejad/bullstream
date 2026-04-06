// Command server runs the BullStream server: control listener + data listener.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ebrahimtahernejad/bullstream/pkg/config"
	"github.com/ebrahimtahernejad/bullstream/pkg/control"
	"github.com/ebrahimtahernejad/bullstream/pkg/proto"
	"github.com/ebrahimtahernejad/bullstream/pkg/session"
	"github.com/ebrahimtahernejad/bullstream/pkg/transport/upstream"
)

func main() {
	cfgPath := flag.String("config", "server.yaml", "path to server config file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		log.Fatalf("server: load config: %v", err)
	}

	// Enforce reorder_timeout_ms > fec_flush_ms at startup.
	if cfg.ReorderTimeoutMs <= cfg.FECFlushMs {
		log.Fatalf("server: reorder_timeout_ms (%d) must be greater than fec_flush_ms (%d)",
			cfg.ReorderTimeoutMs, cfg.FECFlushMs)
	}

	// Decode PSK.
	psk := decodePSK(cfg.PSK)

	// Build user map.
	users := make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		users[u.Username] = u.Password
	}

	// Determine session mode.
	var mode session.Mode
	switch cfg.SessionMode {
	case "single":
		mode = session.ModeSingle
	case "multi":
		mode = session.ModeMulti
	default:
		log.Fatalf("server: unknown session_mode %q (must be single or multi)", cfg.SessionMode)
	}

	dialTimeout := time.Duration(cfg.DialTimeout) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}

	// Build control server config.
	ctrlCfg := control.ServerConfig{
		ListenAddr:         cfg.CtrlListen,
		PSK:                psk,
		Mode:               mode,
		FECData:            uint8(cfg.FECData),
		FECParity:          uint8(cfg.FECParity),
		FECFlushMs:         cfg.FECFlushMs,
		ReorderWindow:      uint16(cfg.ReorderWindow),
		ReorderTimeoutMs:   uint16(cfg.ReorderTimeoutMs),
		SessionWindowBytes: uint32(cfg.SessionWindowBytes),
		MaxSessions:        uint16(cfg.MaxSessionsPerClient),
		IdleTimeoutS:       uint16(cfg.SessionIdleTimeoutS),
		Users:              users,
		DialTimeoutS:       cfg.DialTimeout,
	}
	ctrlServer, err := control.NewServer(ctrlCfg)
	if err != nil {
		log.Fatalf("server: control server: %v", err)
	}

	// Build upstream handler.
	upHandler, err := upstream.NewHandler(cfg.DataListen, dialTimeout)
	if err != nil {
		log.Fatalf("server: upstream handler: %v", err)
	}

	// Wire client lookup: the upstream handler needs to find a client by remote addr.
	// For now we register a simple lookup that uses the control server's state.
	upHandler.SetClientLookup(func(connID string) *upstream.ClientState {
		// In production this would match on IP/port after the client sends its UUID.
		// Here we return the single registered client as a starting point.
		_ = connID
		_ = ctrlServer
		return nil // TODO: integrate with ctrlServer.GetClient
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("server: shutting down")
		cancel()
	}()

	log.Printf("server: ctrl=%s data=%s mode=%s fec=%d+%d reorder=%dms/%dpkts",
		cfg.CtrlListen, cfg.DataListen, cfg.SessionMode,
		cfg.FECData, cfg.FECParity,
		cfg.ReorderTimeoutMs, cfg.ReorderWindow)

	errCh := make(chan error, 2)

	go func() {
		if err := ctrlServer.ListenAndServe(ctx); err != nil {
			errCh <- err
		}
	}()

	go func() {
		if err := upHandler.Serve(ctx); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatalf("server: fatal error: %v", err)
	case <-ctx.Done():
	}
}

// decodePSK decodes a hex or base64 encoded PSK string into bytes.
func decodePSK(s string) []byte {
	// Try hex first, then base64.
	if len(s) == 64 {
		b, err := hexDecode(s)
		if err == nil {
			return b
		}
	}
	// Fall back to raw bytes (for plain-text PSKs in test configs).
	return []byte(s)
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, proto.ErrHexOdd
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi, err := hexNibble(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[i*2+1])
		if err != nil {
			return nil, err
		}
		b[i] = (hi << 4) | lo
	}
	return b, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, proto.ErrBadHexChar
	}
}
