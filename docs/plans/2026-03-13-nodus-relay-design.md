# Nodus Relay — Real-Time Direct Messaging

**Date:** 2026-03-13
**Status:** APPROVED
**Component:** Nodus server + client SDK + Messenger integration

---

## Overview

Real-time TCP relay between two online users via a dedicated Nodus node. No storage — Nodus acts as a pure pipe. Messages are E2E encrypted; Nodus sees only opaque bytes. Designed to support voice/media in the future over the same connection.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Transport model | Nodus relay (not peer-to-peer) | NAT traversal not feasible without IPv6. Every client already connects to Nodus. P2P deferred to future IPv6 era. |
| Relay node selection | Kademlia distance: `SHA3(sort(fp_A, fp_B))` → nearest node | Deterministic — both parties independently compute the same node. No coordination needed. |
| Port | TCP 4004 (dedicated relay port) | Clean separation from DHT (4001), inter-node (4002), channels (4003). |
| Connection model | Lazy — connect only when active conversation starts | Avoids N open connections for N contacts. One TCP connection per active relay session. |
| Invite mechanism | DHT (existing infrastructure) | B sends a small relay invite via DHT PUT to A's listen key. No new signaling infrastructure needed. |
| Encryption | Existing Kyber1024 + AES-256-GCM E2E | Nodus sees opaque bytes only. Per-session forward secrecy deferred to future iteration. |
| Multi-session | Yes — each conversation is an independent session | A can relay with B and C simultaneously on different (or same) relay nodes. |
| Timeout | 30 seconds | If invited party doesn't connect within 30s, session cancelled, inviter falls back to DHT. |
| Voice readiness | Frame type field in wire format | `0x01` = message, `0x02` = voice (future). Same pipe, different frame types. |

## Session Flow

```
  A (sender)                    DHT                  Relay Node (TCP 4004)              B (receiver)
  ─────────                    ─────                 ────────────────────               ───────────
       │                         │                          │                               │
   1.  │── DHT PUT (message) ───>│                          │                               │
       │                         │──── push notification ──>│                               │
       │                         │                          │                          ──── │ receives msg
       │                         │                          │                               │
   2.  │                         │                          │          B checks presence: A online?
       │                         │                          │                          YES  │
       │                         │                          │                               │
   3.  │                         │                          │<── TCP 4004 connect ──────────│
       │                         │                          │    "session_init(fp_A, fp_B)" │
       │                         │                          │── "waiting_for_peer" ────────>│
       │                         │                          │                               │
   4.  │                         │<── DHT PUT (invite) ─────│───────────────────────────────│
       │<── push (invite) ───────│                          │                               │
       │                         │                          │                               │
   5.  │── TCP 4004 connect ────>│                          │                               │
       │   "session_join(fp_B)"  │                          │                               │
       │                         │                          │                               │
   6.  │<──────────── "session_ready" ─────────────────────>│                               │
       │<──────────────────────────────────────────────────>│                               │
       │              relay active: opaque frames           │                               │
       │                                                    │                               │
```

**Step-by-step:**

1. **A sends message via DHT** (existing system, unchanged). B receives it.
2. **B checks presence** — is A online? If yes, proceed. If no, done (DHT-only).
3. **B connects to relay node** (TCP 4004). B computes relay node as `nearest(SHA3(sort(fp_A, fp_B)))`. Sends `session_init` with both fingerprints.
4. **B sends relay invite to A via DHT**. Small signal message: "connect to relay node X for session". A receives via existing DHT listen.
5. **A connects to relay node** (TCP 4004). A computes relay node independently (same result). Sends `session_join`.
6. **Relay node matches the pair** — session is active. All subsequent frames are forwarded A↔B.

## Timeout & Fallback

- **30-second timeout:** If A doesn't connect within 30s of B's `session_init`, relay node cancels the session. B receives `session_timeout` and continues with DHT.
- **Mid-session disconnect:** If either party disconnects (TCP close, network failure):
  - Relay node sends `peer_disconnected` to the remaining party
  - Remaining party detects both: relay node notification + TCP state change
  - Automatic fallback to DHT for subsequent messages

## Wire Format (TCP 4004)

### Frame Header (7 bytes — consistent with existing Nodus framing)

```
┌─────────┬─────────┬──────────────┐
│ Magic   │ Version │ Payload Len  │
│ 0x4E44  │ 0x01    │ 4 bytes LE   │
│ (2B)    │ (1B)    │              │
└─────────┴─────────┴──────────────┘
```

### Relay Protocol Messages (CBOR payload)

**Client → Relay Node:**

| Message | Fields | Description |
|---------|--------|-------------|
| `session_init` | `{fp_self, fp_peer}` | Request session with peer |
| `session_join` | `{fp_self, fp_peer}` | Join existing session |
| `relay_data` | `{type: u8, data: bytes}` | Opaque E2E encrypted frame |
| `session_close` | `{}` | Graceful disconnect |

**Relay Node → Client:**

| Message | Fields | Description |
|---------|--------|-------------|
| `waiting_for_peer` | `{}` | Session created, waiting for other party |
| `session_ready` | `{}` | Both parties connected, relay active |
| `relay_data` | `{type: u8, data: bytes}` | Forwarded frame from peer |
| `peer_disconnected` | `{}` | Other party left |
| `session_timeout` | `{}` | Peer didn't join within 30s |
| `error` | `{code, msg}` | Auth failure, invalid session, etc. |

### Data Frame Types

| Type | Value | Description |
|------|-------|-------------|
| Message | `0x01` | E2E encrypted text message |
| Voice | `0x02` | Voice audio stream (future) |
| Video | `0x03` | Video stream (future) |
| Control | `0xFF` | Session control / keepalive |

## Relay Node Internals

### Session Table (in-memory only, no persistence)

```c
typedef struct {
    uint8_t  fp_a[32];           // Fingerprint A
    uint8_t  fp_b[32];           // Fingerprint B
    int      fd_a;               // TCP socket A (-1 if not connected)
    int      fd_b;               // TCP socket B (-1 if not connected)
    uint64_t created_at;         // For 30s timeout
    bool     active;             // Both connected?
} nodus_relay_session_t;
```

- **No persistence** — sessions are purely in-memory. Server restart = all sessions dropped (clients reconnect or fall back to DHT).
- **Relay logic:** When `relay_data` arrives on `fd_a`, forward to `fd_b` and vice versa. Zero inspection of payload.

### Authentication

Both parties must authenticate on TCP 4004 using the same Tier 2 auth flow (hello → challenge → auth → auth_ok). Relay node verifies:
- Fingerprint matches the one claimed in `session_init` / `session_join`
- Both fingerprints match an existing session

### Relay Node Selection Algorithm

```
relay_key = SHA3-512(min(fp_A, fp_B) || max(fp_A, fp_B))
relay_node = kademlia_nearest(relay_key, routing_table)
```

Both A and B compute this independently. Result is deterministic. If relay node is down, fall back to next nearest.

## DHT Relay Invite Format

Small ephemeral DHT value on A's listen key:

```cbor
{
    "type": "relay_invite",
    "from": <fp_B>,
    "relay_node": <node_id>,       // For verification
    "timestamp": <unix_ms>
}
```

- TTL: 60 seconds (ephemeral, just a signal)
- A validates: computes relay node independently, confirms it matches invite

## Messenger Integration

### Sending Side (dna_engine_messaging.c)

Current flow unchanged for first message. After relay session established:
- `messenger_send_message()` checks: is there an active relay session with recipient?
- If yes → encrypt message → send as `relay_data` frame (type `0x01`)
- If no → normal DHT PUT (existing path)

### Receiving Side

- New: relay data callback delivers decrypted messages via same `DNA_EVENT_MESSAGE_RECEIVED` event
- From UI perspective: no difference between DHT and relay messages

### Relay Manager (new component in messenger)

```
messenger/src/relay/
├── relay_manager.c/h      # Session lifecycle, connect/disconnect
├── relay_invite.c/h       # DHT invite send/receive
└── relay_transport.c/h    # TCP 4004 framing, send/recv
```

Manages active relay sessions, handles invite flow, automatic DHT fallback.

## What Does NOT Change

- DHT messaging (unchanged, always works as fallback)
- Message encryption format (same Kyber1024 + AES-256-GCM)
- Message storage in SQLite (relay messages also saved locally)
- Presence system (used to check if peer is online, unchanged)
- Channel system on TCP 4003 (unrelated, for group channels)

## Future Extensions

- **Per-session forward secrecy:** Ephemeral Kyber key exchange at session start
- **Voice:** Audio frames via type `0x02` over same relay connection
- **Video:** Video frames via type `0x03`
- **P2P direct:** When IPv6 is widespread, optional direct connection bypassing relay
- **Multi-device:** User on multiple devices — relay to all active devices

## Security Considerations

- Relay node sees only opaque E2E encrypted bytes — cannot read message content
- Authentication required before session join (prevents unauthorized relay usage)
- Fingerprint verification in invite prevents session hijacking
- 30s timeout prevents resource exhaustion from abandoned sessions
- No persistence — server compromise reveals no message history
