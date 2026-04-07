# P2P Architecture - Transport Layer

**Current Version:** Nodus v0.10.11, Messenger v0.9.172

## Overview

DNA Connect uses a DHT-only transport layer built on the Nodus client SDK. All messaging goes through the Nodus DHT network -- there are no direct peer-to-peer TCP connections between clients.

**Key properties:**
- DHT-only messaging via Spillway format (no direct P2P since v0.3.154)
- ICE/STUN/TURN removed for privacy (v0.4.61)
- Nodus-native presence tracking (v0.9.0+)
- Internal read thread for instant push delivery (v0.5.6 / v0.9.12)

## Transport Architecture

```
Flutter App (Dart)
    |
    v  FFI
DNA Engine (C)
    |
    v
messenger_transport.c  --  transport.c
    |
    v
nodus_ops.c / nodus_init.c
    |
    v
Nodus Client SDK (nodus_client.c)
    |
    |  Internal read thread (epoll_wait)
    |  Push notifications delivered instantly via callbacks
    |
    v  TCP 4001
Nodus Server Cluster
```

### Nodus Client SDK Internal Read Thread (v0.5.6+)

The Nodus client SDK runs an internal read thread that continuously reads the TCP connection for server-pushed notifications. This is a significant change from the previous model where a heartbeat thread polled every 60s.

**How it works:**
- The read thread starts automatically after `nodus_client_connect()` completes authentication
- It uses blocking `epoll_wait` on the TCP socket -- zero CPU usage while idle (kernel wait queue)
- When a push notification arrives (value_changed, ch_ntf, offline messages), the read thread processes it immediately and invokes the registered callback
- `nodus_client_poll()` is now a no-op when the read thread is running (returns 0 immediately)
- The read thread stops on `nodus_client_close()` or `nodus_client_force_disconnect()`

**Thread safety:**
- `poll_mutex` -- read thread locks during `epoll_wait` to serialize TCP reads
- `send_mutex` -- protects TCP writes (send operations from any thread)
- `pending_mutex` -- protects pending request slot management
- `nodus_pending_t.ready` is `_Atomic bool` for cross-thread visibility between read thread and waiting callers

**Push notification types handled by read thread:**
- `value_changed` -- DHT key updates (new messages, profile changes, group updates)
- `ch_ntf` -- Channel post notifications
- Offline message delivery

**Battery impact:** Zero. The read thread uses blocking `epoll_wait`, which puts the thread on the kernel's wait queue. No CPU spin, no periodic wakeups.

### Presence System (Nodus-native, v0.9.0+)

Presence is tracked server-side by Nodus. Connected clients are tracked automatically.

- Heartbeat sends a batch presence query via TCP every 60s (battery-optimized, v0.9.11+)
- Server responds with online/offline status for all queried fingerprints
- Status transitions fire C events (`DNA_EVENT_CONTACT_ONLINE`/`OFFLINE`) directly to Flutter
- No DHT PUT for presence -- purely server-side tracking with 45s TTL on remote entries
- Cross-node presence propagated via `p_sync` broadcast between Nodus servers (30s interval)

### DHT Offline Queue

Messages for offline recipients are stored in the DHT with 7-day TTL (Spillway format):

1. Sender encrypts message (Kyber1024 + AES-256-GCM), signs with Dilithium5
2. Message queued to recipient's DHT inbox key
3. Recipient receives message via push notification (if online) or fetches on next connect

With the internal read thread, push notifications for new offline messages arrive instantly -- no polling delay.

## Key Source Files

| File | Purpose |
|------|---------|
| `messenger/transport/transport.c` | Transport layer core (DHT bootstrap, offline queue) |
| `messenger/transport/messenger_transport.c` | Messenger-transport integration |
| `messenger/dht/shared/nodus_ops.c` | Nodus singleton convenience wrappers |
| `messenger/dht/shared/nodus_init.c` | Nodus lifecycle, known_nodes TOFU cache, bootstrap order |
| `nodus/src/client/nodus_client.c` | Client SDK with internal read thread |
| `nodus/include/nodus/nodus.h` | Client SDK public API |

## Removed Components

| Component | Removed In | Reason |
|-----------|-----------|--------|
| Direct P2P TCP messaging | v0.3.154 | DHT-only for privacy |
| ICE/STUN/TURN | v0.4.61 | Privacy (no IP disclosure) |
| OpenDHT-PQ | v0.8.0 | Replaced by Nodus |
| Manual `nodus_client_poll()` cycling | v0.5.6 | Replaced by internal read thread |

## Server Discovery & TOFU Key Cache (v0.9.172+)

Client bootstrap order: **known_nodes → config → hardcoded fallback**.

1. **`data_dir/known_nodes`** — persistent file with previously connected servers (IP, port, Dilithium fingerprint, Kyber PK hash, RTT). Populated automatically on successful connection.
2. **Config file** — `bootstrap_nodes=` in dna_config (merged, dedup)
3. **Hardcoded fallback** — 7 IPs compiled into `nodus_init.c` (last resort)

**TOFU (Trust On First Use):** On each successful auth, the connected server's Kyber PK hash is cached. If the key changes on a subsequent connection, a warning is logged (possible MITM). The server's Kyber PK is Dilithium5-signed in AUTH_OK since v0.10.10, and the client verifies this signature before establishing the encrypted channel.

## Transport Encryption (v0.10.10+)

After Dilithium5 authentication, the server sends its Kyber1024 public key signed with its Dilithium5 identity key: `sig = Dilithium5_sign(kyber_pk || challenge_nonce)`. The client verifies this signature before performing KEM encapsulation, preventing MITM key substitution. The resulting shared secret is used to establish an AES-256-GCM encrypted channel with counter-based nonces.
