# BullStream — Asymmetric Tunnel Design

## Problem Statement

Censorship environment where the upstream and downstream paths are physically
different and may change over time. The design treats both as **pluggable transports**:
the client declares which downstream transport it wants in REGISTER; the upstream
transport is determined by how the client connects. New transports (ICMP, WebSocket,
plain TCP, etc.) can be added without changing the session or crypto layers.

Current implementations:
- **Upstream**: plain TCP or TCP via VLESS proxy
- **Downstream**: UDP with spoofed source IP

Goal: TCP port-forwarder with modular transports, out-of-band control,
end-to-end encryption, and proper authentication.

---

## Data Flow

```
[ Local App ]
     │  TCP
     ▼
[ BullStream Client ]
     │
     ├──── Control   [ upstream transport → server:ctrl_port, AES-GCM ] ─────────►┐
     │                                                                              │
     ├──── Upstream  [ upstream transport → server:data_port, [smux], ChaCha20 ] ►│
     │                                                               ┌─────────────┴──────┐
     │◄─── Downstream [ downstream transport, ChaCha20 ] ───────────┤  BullStream Server  │
                                                                     └────────────────────┘
```

- **Control channel**: carried over the upstream transport to `ctrl_port`. No smux.
- **Upstream data**: carried over the upstream transport to `data_port`. Optional smux.
- **Downstream data**: carried over the client-requested downstream transport.
  FEC + sequencing + pacing. Header 9 bytes (single) / 11 bytes (multi).
- Server is **two plain TCP listeners + one downstream transport sender** — no VLESS code.

### Transport types

| Role       | Type ID | Description                        | Status      |
|------------|---------|------------------------------------|-------------|
| Upstream   | `tcp` | Direct TCP to server           | implemented |
| Upstream   | `vless`     | TCP tunnelled through VLESS proxy | implemented |
| Downstream | `udp_spoof` | UDP with spoofed source IP     | implemented |
| Downstream | `icmp_spoof`| ICMP echo-reply with spoofed src | future      |

---

## Component Map

```
bullstream/
├── cmd/
│   ├── client/main.go               # local TCP listener + glue
│   └── server/main.go               # ctrl + data listeners + downstream sender
│
├── pkg/
│   ├── config/
│   │   └── config.go                # YAML config structs (transport blocks are typed)
│   │
│   ├── proto/
│   │   ├── ctrl.go                  # control message types + serialisation
│   │   └── data.go                  # upstream frame + downstream packet format
│   │
│   ├── crypto/
│   │   ├── aes.go                   # AES-128-GCM (control channel)
│   │   └── chacha.go                # ChaCha20-Poly1305 framer (data channels)
│   │
│   ├── session/
│   │   ├── table.go                 # thread-safe SessionID → Session map
│   │   └── session.go               # per-session pipe
│   │
│   ├── control/
│   │   ├── client.go                # REGISTER, HEALTHCHECK, CHID
│   │   └── server.go                # auth, client state, session mode
│   │
│   ├── transport/
│   │   ├── iface.go                 # UpstreamDialer, UpstreamListener,
│   │   │                            # DownstreamSender, DownstreamReceiver interfaces
│   │   │
│   │   ├── upstream/
│   │   │   ├── handler.go           # server: accept conns, read frames, feed sessions
│   │   │   ├── plaintcp/
│   │   │   │   └── dialer.go        # client: dial server:data_port directly
│   │   │   └── vless/
│   │   │       └── dialer.go        # client: dial via VLESS proxy → server:data_port
│   │   │
│   │   └── downstream/
│   │       ├── fec.go               # Reed-Solomon encoder / decoder (shared)
│   │       ├── reorder.go           # sliding-window reorder buffer (shared)
│   │       ├── pacing.go            # token-bucket pacer (shared)
│   │       ├── udpspoof/
│   │       │   ├── sender.go        # server: encode→pace→raw socket sendto
│   │       │   └── receiver.go      # client: recvfrom→decrypt→FEC→reorder→deliver
│   │       └── icmpspoof/           # future
│   │           ├── sender.go
│   │           └── receiver.go
│   │
│
├── go.mod
└── go.sum
```

### Transport interfaces (`transport/iface.go`)

```go
// Client dials server for upstream data frames.
type UpstreamDialer interface {
    Dial(ctx context.Context) (net.Conn, error)
}

// Server accepts upstream connections from clients.
type UpstreamListener interface {
    Accept(ctx context.Context) (net.Conn, error)
}

// Server sends downstream packets to a specific client.
type DownstreamSender interface {
    Send(pkt []byte) error
}

// Client receives downstream packets.
type DownstreamReceiver interface {
    Recv(ctx context.Context) ([]byte, error)
}
```

FEC, reorder, and pacing are shared across all downstream implementations —
they operate on `[]byte` and are transport-agnostic.

---

## Authentication & Encryption

### Credentials

| Field      | Location     | Purpose                                          |
|------------|--------------|--------------------------------------------------|
| `psk`      | both configs | Encrypts all control messages (AES-128-GCM)      |
| `username` | client config | Identity, sent inside encrypted REGISTER        |
| `password` | both configs | Derives the data encryption key (upstream + UDP) |

Server holds a `users` map: `username → password`.
PSK is global — authenticates the channel itself.
Password is per-user — keys the data independently of the PSK.

### Control channel — AES-128-GCM

Each message on the wire:

```
[ 12-byte random nonce ][ AES-128-GCM ciphertext + 16-byte tag ]
```

- Key = HKDF-SHA256(PSK, "bullstream-ctrl", 16 bytes)
- Fresh random nonce per message
- Overhead: 28 bytes per message (fine for low-frequency control traffic)
- Any decryption failure → close connection immediately

### Data channels — ChaCha20-Poly1305

Upstream (TCP stream) and UDP downstream payload both use the same scheme:

```
Key   = HKDF-SHA256(password, "bullstream-data", 32 bytes)
Nonce = 96-bit: [ 32-bit session epoch ][ 64-bit counter, big-endian ]
Tag   = 16 bytes (Poly1305), appended to each frame/packet
```

- **Session epoch**: a 4-byte random value generated fresh at each OPEN and exchanged
  in the OPEN message. Ensures nonces are globally unique across reconnects — two
  connections starting at counter=0 have different epochs so they never reuse a nonce.
- **Counter**: two independent counters per session — `send_counter` and `recv_counter`,
  both starting at 0, never transmitted. Each side increments its own `send_counter`
  on every write and its own `recv_counter` on every read. Because the TCP data channel
  is bidirectional (DATA upstream, WNDUPD downstream), the framer must use `send_counter`
  when encrypting and `recv_counter` when decrypting — never the same counter for both
  directions, otherwise the two sides fall out of sync immediately.
- Overhead: **16 bytes per frame/packet** — epoch and counter are never on the wire.
- ChaCha20-Poly1305 chosen: no AES-NI required, constant-time everywhere, same 16-byte tag as AES-GCM.

---

## SessionID Encoding

### Single mode — 16-bit, one client

```
 bit  15 ──────────────────────────── 0
┌──────────────────────────────────────┐
│        Session sequence (16 bit)     │
└──────────────────────────────────────┘
```

- No ClientID — one client at a time
- New REGISTER with different UUID evicts current client + all sessions
- 0–65535 concurrent sessions

### Multi mode — 32-bit, multi-client

```
 bit  31 ─ 28   27 ──────────────────── 0
┌───────────┬──────────────────────────────┐
│ CID (4b)  │   Session sequence (28 bit)  │
└───────────┴──────────────────────────────┘
```

- Top 4 bits = ClientID — up to 16 simultaneous clients
- Each client assigned a CID at REGISTER
- 0–268,435,455 sessions per client

IDs wrap at max; 2× reorder-timeout quiet period before reuse.
Mode is **server-authoritative**: set in server config, sent to client in ACK.

UUID is generated on first run and **persisted to disk** (e.g. `~/.bullstream/uuid`).
This ensures a client process restart gets the same UUID — preserving its CID slot in
multi mode and avoiding a spurious eviction in single mode.

---

## Control Protocol (VLESS → ctrl_port, plain TCP, no smux)

All messages are AES-128-GCM encrypted. Connection is persistent;
HEALTHCHECK reuses it — no re-dial per ping.

### REGISTER — MsgType 0x01 (client → server)

Plaintext payload (encrypted before sending):

```
Version          = 1 byte
UUID             = 16 bytes                  (persisted to disk)
Username         = 1 byte len + N bytes
DstAddr          = 1 byte len + N bytes      (forwarding target — fixed per client)
DownstreamType   = 1 byte                    (0x01=udp_spoof, 0x02=icmp_spoof, …)
DownstreamConfig = variable, per type:

  udp_spoof (0x01):
    UDPAddr     = 4 bytes IPv4 + 2 bytes port
    SpoofCount  = 1 byte
    SpoofSelect = 1 byte  (0=random, 1=round-robin)
    SpoofSrcs   = SpoofCount × (4 bytes IPv4 + 2 bytes port)

  icmp_spoof (0x02):  [future — fields TBD]
```

Password is **not transmitted** — server looks it up by username.

`DstAddr` is fixed per client; all sessions forward to the same target.
`DownstreamType` + `DownstreamConfig` tell the server exactly how to send responses
back — the server instantiates the matching `DownstreamSender` implementation.
Server responds with NACK `0x04` if the requested downstream type is not supported.

Server behaviour — **single mode**:
- No client → accept, store state, respond ACK.
- Different UUID → evict old client + sessions, replace, respond ACK.
- Same UUID → update connection + UDPAddr (NAT may shift), respond ACK.

Server behaviour — **multi mode**:
- Assign CID 0–15; reject 17th until a slot frees.
- Same UUID reconnecting → restore previous CID, update UDPAddr.

Server response — MsgType 0x02 (ACK):

```
Mode             = 1 byte   (0=single, 1=multi)
ClientID         = 1 byte   (0x00 in single mode)
FECData          = 1 byte   (data shards)
FECParity        = 1 byte   (parity shards)
ReorderWindow    = 2 bytes  (sliding window size, packets)
ReorderTimeoutMs = 2 bytes  (gap timer, milliseconds)
SessionWindowBytes = 4 bytes (per-session receive window)
MaxSessions      = 2 bytes  (session cap enforced on both sides)
IdleTimeoutS     = 2 bytes  (session idle timeout; 0 = no timeout)
```

Everything in the ACK is **server-authoritative**. Client ignores its own values for
all of these fields and uses what the server sends. Client config only needs to carry
connection parameters and credentials — all tuning comes from the server.

### HEALTHCHECK — MsgType 0x03 (client → server, periodic)

Sent at `healthcheck_interval_s`. The persistent control connection is kept alive
between checks using TCP keepalives (`SO_KEEPALIVE`, configurable via `ctrl_keepalive_s`,
default 15s) — prevents stateful NAT/firewall from silently dropping the idle TCP
connection between 30s pings.

```
UUID     = 16 bytes
UDPAddr  = 4 bytes IPv4 + 2 bytes port   (refresh in case NAT port shifted)
ClientID = 1 byte  (0x00 in single mode)
```

Server response — MsgType 0x04 (OK):

```
Mode     = 1 byte
ClientID = 1 byte
```

Client checks:
- **Mode mismatch** → exit immediately (server was reconfigured mid-run).
- **CID mismatch** (multi mode) → server sends MsgType 0x05 CHID (1-byte NewClientID); client updates.
- **UUID unknown** (server restarted) → client re-sends full REGISTER.

### NACK — MsgType 0x07 (server → client, on any REGISTER failure)

```
Reason = 1 byte
  0x01 = version mismatch
  0x02 = auth failure (bad username / PSK decrypt failed)
  0x03 = slots full (multi mode, 16 clients already connected)
  0x04 = unsupported spoof_select value
```

Server closes the connection immediately after sending NACK.
Client logs the reason and exits — no silent broken pipe.

Server must not begin sending UDP for a client until REGISTER is fully processed
and the client's spoof sources and UDPAddr are stored. This prevents a race where
UDP is sent with a stale or zero spoof source from a previous client.

### DEREGISTER — MsgType 0x06 (client → server, graceful shutdown)

```
UUID     = 16 bytes
ClientID = 1 byte
```

Server tears down all sessions for this client and frees the slot immediately.
Without this, multi-mode slots stay occupied until idle timeout.
No response expected — client closes the control connection after sending.

---

## Upstream Protocol (VLESS → data_port, [smux], ChaCha20)

### Frame format (inside ChaCha20-Poly1305, after decryption)

```
┌──────────────────────────────────────┐
│  SessionID (16 or 32 bit, per mode)  │
├────────────┬─────────────────────────┤
│ MsgType(8b)│ PayloadLen (16b)        │
├────────────┴─────────────────────────┤
│ Payload (variable)                   │
└──────────────────────────────────────┘
Overhead: 5 bytes (single) / 7 bytes (multi)
```

MsgType values:

```
0x10 = OPEN    4-byte session epoch (random); opens session, server dials DstAddr
               Server must fully store epoch before sending any UDP for this session.
0x11 = DATA    raw TCP bytes
0x12 = FIN     graceful half-close
0x13 = RESET   hard abort
0x14 = WNDUPD  4-byte credit (backpressure, flows in both directions on this channel)
```

### Backpressure — WNDUPD (bidirectional, TCP only)

Both directions of WNDUPD travel on the **TCP data channel** — never over UDP.
A lost WNDUPD over UDP would stall the sender permanently.

Each session starts with the server-negotiated `SessionWindowBytes` on both sides:

- **Server → Client**: server writes WNDUPD when it drains bytes from DstAddr.
  Client blocks upstream writes when window hits 0.
- **Client → Server**: client writes WNDUPD as it consumes bytes from the reorder buffer.
  Server blocks UDP sends when window hits 0.

**Initial window**: on OPEN, both sides pre-load their send window with ACK
`SessionWindowBytes` without waiting for a WNDUPD — otherwise the session stalls
on the very first frame waiting for credits that can't arrive until data is sent.

### Data channel startup ordering

The client dials the data connection **after** receiving the REGISTER ACK — not before.
The ACK contains the negotiated parameters (session mode, window sizes, FEC config)
that the client needs before it can correctly format frames.

---

## UDP Downstream Protocol

### Packet wire format

FEC Group ID, FEC Index, and FEC Total are **eliminated from the header** — all
derived from the unified `SeqNum` using the negotiated `fec_data` and `fec_parity`
values from ACK. This saves 4 bytes per packet.

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
├───────────────────────────────────────────────────────────────┤
│           SessionID (16 or 32 bit, per mode)                  │
├───────────────────────────────────────────────────────────────┤
│                        SeqNum (32 bit)                        │
├───────────────────────────────────────────────────────────────┤
│  Flags (8b)           │  PayloadLen (16b)                     │
├───────────────────────────────────────────────────────────────┤
│  ChaCha20-Poly1305 encrypted payload + 16-byte tag            │
└───────────────────────────────────────────────────────────────┘

Header: 9 bytes (single) / 11 bytes (multi)
Effective payload at 1500-byte MTU: 1500 − 20 (IP) − 8 (UDP) − 9 − 16 (tag) = 1447 bytes
```

Flags:
```
0x01 = DATA
0x02 = PARITY   (FEC parity shard)
0x04 = FIN
0x08 = RESET
0x10 = PARTIAL  (group flushed before full — see below)
```

### SeqNum → FEC mapping (derived, not transmitted)

Let `stride = fec_data + fec_parity` (both known from ACK).

```
group        = SeqNum / stride
pos          = SeqNum % stride

if pos < fec_data  → data shard,   data_index  = pos
if pos >= fec_data → parity shard, parity_index = pos − fec_data
```

One unified 32-bit SeqNum space per session covers both data and parity shards.
Wraps at 2³² / stride groups — at stride=13 that is ~330M groups × fec_data shards
× 1447 bytes ≈ **3.8 TB per session** before any wrap risk.

**Wrap enforcement**: the client tracks bytes sent per session. When SeqNum reaches
`0xFFFFFFFF - stride` (one group before the end), the client sends RESET on the upstream
channel and immediately opens a new session with a fresh epoch. The application layer
sees a seamless reconnect; no data is lost since TCP retransmits any in-flight upstream
and the client re-opens the session before the last UDP packets could still be in-flight.

### FEC — Reed-Solomon

- Sender assigns SeqNums sequentially across data + parity shards of each group.
- Receiver buffers shards by `(SessionID, group)` and reconstructs as soon as any
  `fec_data` of the `stride` shards arrive.
- **Flush (PARTIAL)**: if a group isn't full after `fec_flush_ms`, it is sent
  immediately with the PARTIAL flag set. Parity shards for a partial group carry
  a 1-byte `ActualDataShards` value as the first byte of their payload — the
  receiver reads this to know how many data shards to expect for reconstruction.
  Normal (non-PARTIAL) parity shards have no such prefix.

### Reorder buffer

- Per-session sliding window, size from ACK `ReorderWindow`.
- Delivers in-order; gap timer from ACK `ReorderTimeoutMs`.
- On unrecoverable loss after FEC: RESET the session.
- **Constraint enforced by server at startup**: `reorder_timeout_ms > fec_flush_ms + expected_one_way_delay_ms`.
  If violated, the reorder gap timer fires before partial-group parity shards can arrive,
  causing unnecessary session resets. Server refuses to start if
  `reorder_timeout_ms ≤ fec_flush_ms` (the RTT component is the operator's responsibility).

### Pacing — token bucket

- Rate and burst configurable (defaults: 8 Mbit/s rate, 1 FEC group burst).
- Prevents rate-limit heuristics on the whitelisted-IP UDP path.

### Source spoofing

```
Server raw socket (SOCK_RAW + IPPROTO_RAW):
  IP src  = selected spoof IP    (chosen from SpoofSrcs per SpoofSelect strategy)
  IP dst  = UDPAddr IP           (from REGISTER / latest HEALTHCHECK)
  UDP src = selected spoof port
  UDP dst = UDPAddr port
```

The server picks a spoof source for each **FEC group** (not per-packet) to keep
packets within a group appearing to come from the same source — mixing sources
within a group would confuse stateful middleboxes.

Client filters incoming UDP by the full set of known spoof source IP:port pairs.
Packets from unknown sources are silently dropped.

If `UDPAddr` in the latest HEALTHCHECK differs from the previous value, the server
logs a warning and updates immediately. If packets stop arriving at the new address,
the server logs an error — silent misconfiguration of `public_ip` is the most likely
cause and should be loud.

Client uses plain `net.ListenUDP` — no raw socket needed on receive side.

---

## Session Lifecycle

```
Client                                       Server
  │                                             │
  │── REGISTER (UUID, user, UDPAddr, Dst) ────►│  store client state
  │◄─ ACK (mode, CID) ─────────────────────────│
  │                                             │
  │── OPEN (SessionID=1) ──────────────────────►│  dial DstAddr
  │── DATA (upstream) ─────────────────────────►│──► Target
  │◄── UDP packets (FEC, spoofed src) ──────────│◄── Target
  │── FIN ─────────────────────────────────────►│  half-close upstream
  │◄── UDP FIN ─────────────────────────────────│  half-close downstream
  │                                             │
  │  ... every 30s ...                          │
  │── HEALTHCHECK (UUID, UDPAddr) ─────────────►│  refresh NAT mapping
  │◄─ OK ──────────────────────────────────────│
```

---

## Upstream Multiplexing

The upstream frame format already contains `SessionID + MsgType + PayloadLen` — this
**is** a multiplexer. No separate mux library is needed.

One persistent upstream TCP connection is established per client after ACK is received.
All sessions share it. The server reads frames and routes by `SessionID`. Session
lifecycle (`OPEN/FIN/RESET`) and flow control (`WNDUPD`) are already handled by the
BullStream protocol itself — smux would duplicate all of that with 8 bytes of extra
header per frame.

**No smux dependency. No `mux` config knob.**

The upstream connection is established once (after REGISTER ACK) and held for the
lifetime of the client registration. If it drops, the client re-dials and re-sends
OPEN for any sessions that were in flight.

---

## Configuration

```yaml
# client.yaml  — credentials + transport config only; tuning pushed from server ACK
listen_addr:   "127.0.0.1:1080"
username:      "alice"
password:      "hunter2"
psk:           "base64-or-hex-32-bytes"
dst_addr:      "example.com:443"
healthcheck_interval_s: 30
ctrl_keepalive_s:       15
dial_timeout_s:         10

upstream:
  type: vless             # vless | tcp
  ctrl_dest: "my-server.com:9001"
  data_dest: "my-server.com:9000"
  vless:                  # only present when type=vless
    proxy:  "1.2.3.4:443"
    uuid:   "..."
    tls:    true
  # tcp:            # only present when type=tcp (no extra fields needed)

downstream:
  type: udp_spoof         # udp_spoof | icmp_spoof (future)
  udp_spoof:              # only present when type=udp_spoof
    listen_port:   4444
    public_ip:     "9.10.11.12"
    spoof_sources:
      - "5.6.7.8:53"
      - "1.2.3.4:123"
    spoof_select:  random   # random | round-robin
  # icmp_spoof:           # future

# Everything else (fec_data/parity, reorder_window/timeout, session_window_bytes,
# max_sessions, idle_timeout, mux on/off) received from server in ACK.

---

# server.yaml
ctrl_listen:  "0.0.0.0:9001"
data_listen:  "0.0.0.0:9000"
psk:          "base64-or-hex-32-bytes"
session_mode: single        # single | multi
dial_timeout_s: 10

# Session tuning — all sent to client in ACK
fec_data:                10
fec_parity:              3
fec_flush_ms:            5
reorder_window:          256
reorder_timeout_ms:      50
session_window_bytes:    262144
max_sessions_per_client: 1024
session_idle_timeout_s:  120

# Per downstream transport config (server only uses the type the client requests)
downstream:
  udp_spoof:
    rate_mbps:    8
    burst_groups: 1
  # icmp_spoof:   (future)

users:
  - username: "alice"
    password:  "hunter2"
```

---

## Key Dependencies

```
github.com/sagernet/sing            # VLESS client dialer (upstream transport)
github.com/klauspost/reedsolomon    # FEC (downstream)
github.com/google/gopacket          # raw packet crafting for UDP/ICMP spoof
golang.org/x/crypto                 # ChaCha20-Poly1305, HKDF
golang.org/x/net/ipv4               # raw socket helpers
```

---

## Implementation Phases

1. **Phase 1 — Skeleton**
   `go.mod`, config structs, proto types, session table

2. **Phase 2 — Control channel**
   AES-GCM helpers, REGISTER/HEALTHCHECK, server auth + client state

3. **Phase 3 — UDP Downstream (no FEC, no encryption, no spoof)**
   Plain UDP sender/receiver + reorder buffer, hardcoded test session

4. **Phase 4 — Upstream data channel (plaintext)**
   OPEN/DATA/FIN framing, session → DstAddr forwarding, backpressure

5. **Phase 5 — Encryption**
   ChaCha20-Poly1305 on upstream frames and UDP payloads

6. **Phase 6 — FEC**
   Reed-Solomon encode/decode + flush timer on UDP layer

7. **Phase 7 — Raw socket + spoof**
   Replace plain sendto with crafted IP/UDP packets

8. **Phase 8 — VLESS dialer**
   Client dials VLESS proxy → ctrl and data ports

9. **Phase 9 — smux**
   Wrap data connection; server toggled by `mux: true`

10. **Phase 10 — Pacing + tuning**
    Token bucket, adaptive reorder timeout, window sizing
```
