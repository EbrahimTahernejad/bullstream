# BullStream

Asymmetric TCP tunnel designed for censorship environments where upstream and downstream paths are physically different. Upstream traffic travels over plain TCP or a VLESS proxy; downstream responses return via UDP with spoofed source IPs.

## How it works

```
[ Local App ] ──TCP──► [ Client ]
                            │
                            ├── Control  (AES-128-GCM)       ──► Server :ctrl_port
                            ├── Upstream (ChaCha20-Poly1305) ──► Server :data_port
                            └── Downstream (UDP spoofed src) ◄── Server
```

- **Control channel** — persistent TCP connection carrying REGISTER / HEALTHCHECK / DEREGISTER messages, encrypted with AES-128-GCM (key derived from PSK via HKDF-SHA256).
- **Upstream data** — single persistent TCP connection multiplexing all sessions via a built-in frame protocol (no smux). Encrypted with ChaCha20-Poly1305 (key derived from user password).
- **Downstream data** — UDP packets sent from a raw socket with configurable spoofed source IP:port pairs. Hardened with Reed-Solomon FEC, a sliding-window reorder buffer, and a token-bucket pacer.

## Features

- End-to-end encryption on all channels (AES-128-GCM control, ChaCha20-Poly1305 data)
- Built-in session multiplexer — no dependency on smux or any mux library
- Reed-Solomon FEC with partial-group flush
- Sliding-window reorder buffer with configurable gap timer
- Token-bucket pacing to avoid rate-limit heuristics
- UDP source spoofing via raw sockets (server picks spoof source per FEC group)
- VLESS proxy support on the upstream path (optional TLS)
- Single and multi-client modes (up to 16 simultaneous clients in multi mode)
- All tuning parameters (FEC, reorder, window sizes) are server-authoritative — client config only needs credentials and connection targets

## Quick start

### Server (`server.yaml`)

```yaml
ctrl_listen:  "0.0.0.0:9001"
data_listen:  "0.0.0.0:9000"
psk:          "your-32-byte-hex-or-raw-psk"
session_mode: single   # single | multi

fec_data:                10
fec_parity:              3
fec_flush_ms:            5
reorder_window:          256
reorder_timeout_ms:      50
session_window_bytes:    262144
max_sessions_per_client: 1024
session_idle_timeout_s:  120

downstream:
  udp_spoof:
    rate_mbps:    8
    burst_groups: 1

users:
  - username: alice
    password:  hunter2
```

```sh
sudo bullstream-server -config server.yaml
```

> Raw socket for UDP spoofing requires root or `CAP_NET_RAW`.

### Client (`client.yaml`)

```yaml
listen_addr: "127.0.0.1:1080"
username:    alice
password:    hunter2
psk:         "your-32-byte-hex-or-raw-psk"
dst_addr:    "example.com:443"

healthcheck_interval_s: 30
ctrl_keepalive_s:       15
dial_timeout_s:         10

upstream:
  type:      tcp          # tcp | vless
  ctrl_dest: "server:9001"
  data_dest: "server:9000"
  # vless:                # uncomment for VLESS upstream
  #   proxy: "1.2.3.4:443"
  #   uuid:  "..."
  #   tls:   true

downstream:
  type: udp_spoof
  udp_spoof:
    listen_port:  4444
    public_ip:    "your-public-ip"
    spoof_sources:
      - "5.6.7.8:53"
      - "1.2.3.4:123"
    spoof_select: random   # random | round-robin
```

```sh
bullstream-client -config client.yaml
```

Point your application at `127.0.0.1:1080`.

## Authentication model

| Credential | Purpose |
|---|---|
| `psk` | Authenticates the control channel (global, both sides) |
| `username` | Client identity, sent inside encrypted REGISTER |
| `password` | Derives the data encryption key (never transmitted) |

## Building from source

```sh
go build ./cmd/client
go build ./cmd/server
```

Requires Go 1.22+. The server binary needs `CGO_ENABLED=0` and `CAP_NET_RAW` at runtime for raw socket access.

## Dependencies

| Package | Purpose |
|---|---|
| `golang.org/x/crypto` | ChaCha20-Poly1305, HKDF |
| `github.com/klauspost/reedsolomon` | FEC encode/decode |
| `github.com/google/gopacket` | Raw IP/UDP packet construction |
| `gopkg.in/yaml.v3` | Config parsing |
