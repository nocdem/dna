# Dedicated Channel Port (TCP 4003) — Design Document

**Date:** 2026-03-13
**Status:** FINAL (under review — see Review Notes at end of document)
**Component:** Nodus Server + Client SDK + Messenger

---

## Problem

Channel traffic currently shares TCP 4001 with DHT, messaging, and presence operations. This causes:

1. **Performance** — Channel message delivery (up to 256 connected users) competes with DHT GET/PUT traffic on the same socket/epoll loop
2. **Scalability** — A busy channel can degrade DHT responsiveness for all clients on that node
3. **Connection topology** — Users connect to a single nodus for everything; ideally a user connects to their DHT nodus (4001) AND directly to the channel-responsible nodus (4003) for each subscribed channel

## Solution

Dedicate TCP port 4003 to channel operations. Users open separate TCP connections to channel-responsible nodus nodes, determined by the consistent hashring. Each channel has 3 responsible nodes (multi-primary). Posts are accepted by any of the 3 and replicated to the other 2 via TCP 4002.

---

## Architecture

### Port Layout

| Port | Protocol | Purpose |
|------|----------|---------|
| UDP 4000 | Kademlia | Peer discovery (unchanged) |
| TCP 4001 | Tier 2 | DHT, messaging, presence (unchanged — channel ops removed) |
| TCP 4002 | Inter-node | Nodus-to-Nodus replication (unchanged) |
| TCP 4003 | Channel | Client-to-Nodus channel traffic (new) |

### Connection Topology

```
User
 ├─→ Nodus-A (TCP 4001) — DHT, messaging, presence
 ├─→ Nodus-C (TCP 4003) — Channel "crypto-news" (hashring selected)
 └─→ Nodus-F (TCP 4003) — Channel "tech-talk" (hashring selected)
```

- User maintains 1 DHT connection (4001) to their primary nodus
- User maintains N channel connections (4003) to channel-responsible nodus nodes
- A user subscribed to 2 channels on the same nodus uses 1 TCP connection for both
- Channel port handles ONLY: ch_create, ch_post, ch_get_posts, ch_subscribe, ch_unsubscribe

### Channel Discovery (DHT Self-Announcement)

Responsible nodus nodes announce themselves to the channel's DHT key:

```
DHT key = SHA3-512("dna:channel:nodes:" + channel_uuid)

Value (CBOR):
{
  "version": <ring_version>,
  "nodes": [
    { "ip": "164.68.105.227", "port": 4003, "node_id": <key> },
    { "ip": "164.68.116.180", "port": 4003, "node_id": <key> },
    { "ip": "161.97.85.25",   "port": 4003, "node_id": <key> }
  ]
}
```

- Written once when channel is created
- Updated only when ring changes (node joins/leaves) — new version + new 3 nodes
- Client does DHT GET on channel key → gets responsible node list → connects via TCP 4003
- Client does NOT need to know the hashring — just reads the DHT entry
- Old entries expire via DHT TTL (7 days); new entry overwrites immediately

### Ring Membership — Peer Confirmation (ring_check / ring_ack)

Ring changes use a simple 2-step confirmation between the responsible nodes over TCP 4002.
No leader election, no voting. The first node to detect a change asks the other to confirm.

**Protocol messages (TCP 4002):**

| Message | Fields | Direction |
|---------|--------|-----------|
| `ring_check` | `node_id`, `channel_uuid`, `status: "dead"\|"alive"` | Requester → Peer |
| `ring_ack` | `node_id`, `channel_uuid`, `agree: true\|false` | Peer → Requester |
| `ring_evict` | `channel_uuid`, `version` | Initiator → Evicted node |

**Node goes down:**

```
Kanal X → responsible: Nodus-1, Nodus-2, Nodus-3

Nodus-1: 60s no PONG from Nodus-3 (PBFT marks DEAD)
  → Nodus-1 sends ring_check to Nodus-2 (TCP 4002):
    { node_id: Nodus-3, channel_uuid: X, status: "dead" }

Nodus-2 checks its own PBFT state for Nodus-3:
  Case A: Nodus-3 is DEAD/SUSPECT on Nodus-2 too
    → ring_ack { agree: true }
    → Nodus-1 updates local ring: Nodus-3 out, Nodus-4 in
    → Nodus-1 writes to DHT: version+1, [Nodus-1, Nodus-2, Nodus-4]
    → Nodus-2 also updates its local ring
    → Nodus-1 sends ring_evict to Nodus-4 (TCP 4002):
      { channel_uuid: X, version: N+1 }
    → Nodus-4 receives → sends ch_ring_changed to its connected clients → drops responsibility

  Case B: Nodus-3 is ALIVE on Nodus-2
    → ring_ack { agree: false }
    → Ring unchanged. Nodus-1 retries on next PBFT tick cycle.
```

**Node comes back:**

```
Nodus-1: PONG received from Nodus-3 (PBFT marks ALIVE)
  → Nodus-1 sends ring_check to Nodus-2 (TCP 4002):
    { node_id: Nodus-3, channel_uuid: X, status: "alive" }

Nodus-2 checks:
  → Nodus-3 is ALIVE → ring_ack { agree: true }
  → Nodus-1 updates ring: Nodus-3 back in, Nodus-4 out
  → Nodus-1 writes to DHT: version+1, [Nodus-1, Nodus-2, Nodus-3]
  → Nodus-1 sends ring_evict to Nodus-4 (TCP 4002):
    { channel_uuid: X, version: N+1 }
  → Nodus-4 receives → sends ch_ring_changed to its clients → drops responsibility
```

**Key properties:**
- Single node's network issue cannot change the ring (peer must confirm)
- 2/3 confirmation: requester (1) + confirmer (1) = 2 out of 3 agree
- First to detect initiates — no leader needed
- On confirmation: initiator writes new version to DHT key
- On rejection: no change, retry on next cycle
- Clients see updated node list on next DHT GET

### Node Recovery After Extended Downtime

When a node comes back after being replaced (e.g. Nodus-3 was down for 1 day):

```
1. Nodus-1 receives PONG from Nodus-3 → PBFT marks ALIVE
   → ring_check to Nodus-2: { Nodus-3, status: "alive" }
   → Nodus-2 confirms → ring updated: [Nodus-1, Nodus-2, Nodus-3]
   → Nodus-4 exits responsible set

2. Nodus-3 has empty/stale channel data (missed 1 day of posts)
   → ch_get_posts(since=0) from Nodus-1 or Nodus-2
   → Pulls all posts (up to 7-day retention window)
   → One-time sync cost

3. Nodus-4 is no longer responsible
   → Sends ch_ring_changed to its connected clients for this channel
   → Clients do DHT GET → learn new responsible set [Nodus-1, Nodus-2, Nodus-3]
   → Clients disconnect from Nodus-4, connect to one of the new set
   → Nodus-4 can drop channel data (optional, will expire via 7-day retention anyway)

4. DHT updated: version+1, new responsible set
```

### ch_ring_changed Notification

When a node loses responsibility for a channel, it notifies connected clients:

```
ch_ring_changed {
  "ch": <channel_uuid>,
  "version": <new_ring_version>
}
```

Client receives this → does DHT GET for channel key → gets new node list → reconnects.
This is a one-way notification on the existing TCP 4003 connection.

### Client Node Selection (Lowest Latency)

DHT GET returns 3 responsible nodes. Client connects to the fastest one:

```
DHT GET → [Nodus-1 (US), Nodus-2 (EU), Nodus-3 (EU)]
→ Initiate TCP connect to all 3 in parallel
→ First to complete TCP handshake = lowest latency → use this one
→ Close the other 2 connections
```

This applies to both initial connect and reconnect after failover.

### Client Failover

1. **Node goes down** → TCP connection drops → client does DHT GET → connects to fastest of remaining responsible nodes
2. **Ring changes** → client receives `ch_ring_changed` → does DHT GET → connects to fastest responsible node
3. **Missed messages** → after reconnect, `ch_get_posts(since_timestamp)` fills the gap

---

## Post Write Flow (Multi-Primary)

```
User-A writes post
  │
  └─→ TCP 4003 → Nodus-1 (user's connected nodus)
        │
        ├─ Assign received_at timestamp (milliseconds)
        ├─ Store in SQLite
        ├─ Send to own connected subscribers (TCP 4003, same open connections)
        └─ Replicate to Nodus-2, Nodus-3 (TCP 4002, ch_rep)
              │
              ├─→ Nodus-2: Store in SQLite + send to own connected subscribers
              └─→ Nodus-3: Store in SQLite + send to own connected subscribers
```

All 3 responsible nodes are equal writers. No single primary.

### Message Delivery Mechanism

Nodus does NOT "push" — it writes to existing open TCP connections. When a subscriber
is connected via TCP 4003 and has called `ch_subscribe`, the nodus simply calls
`send(fd, cbor_buf, len)` on that client's file descriptor. This is a standard TCP
write on an already-established connection.

```c
// Post arrives (local write or via replication)
// 1. Serialize once
uint8_t buf[8192];
size_t len = encode_ch_post_notify(buf, sizeof(buf), channel_uuid, post);

// 2. Write to each subscriber's open TCP connection
for (int i = 0; i < srv->ch_session_count; i++) {
    nodus_ch_session_t *s = &srv->ch_sessions[i];
    if (!s->authenticated) continue;
    for (int j = 0; j < s->ch_sub_count; j++) {
        if (memcmp(s->ch_subs[j], channel_uuid, 16) == 0) {
            send(s->fd, buf, len, MSG_NOSIGNAL);
            break;
        }
    }
}
```

CBOR serialization happens once, then the same buffer is written to all subscriber fds.

---

## Ordering: Nodus Timestamp

No seq_id. Nodus assigns `received_at` timestamp (milliseconds) when it receives the post.

- **No seq_id**: Removed entirely. Nodus timestamp is the ordering key.
- **Storage:** `received_at INTEGER` (milliseconds since epoch, assigned by receiving nodus)
- **Dedup:** `UNIQUE(post_uuid)` per channel table
- **Client display:** `ORDER BY received_at ASC, author_fp ASC` (author_fp tie-break on same millisecond)
- **Fetch since:** `ch_get_posts(channel_uuid, since_timestamp)` — single cursor
- **Replication:** Original `received_at` preserved by receiving nodus (not reassigned)

---

## Authentication (TCP 4003)

Same auth mechanism as TCP 4001, independent session:

```
1. Client → TCP connect to nodus:4003
2. Client → hello { pubkey, fingerprint }
3. Nodus  → challenge { nonce }
4. Client → auth { signed_nonce }
5. Nodus  → auth_ok { session_token }
6. Client → ch_subscribe { channel_uuid }
7. Nodus  → ch_sub_ok
8. --- connection stays open, messages flow bidirectionally ---
```

Session token is scoped to the 4003 connection. Separate from any 4001 session.

---

## Replication Changes

### Current (Single Primary)
- Only primary accepts writes and assigns seq_id
- Primary replicates to 2 backups with pre-assigned seq_id
- Backups store with the provided seq_id

### New (Multi-Primary)
- Any of the 3 responsible nodes accepts writes
- Writer assigns `received_at` timestamp (milliseconds) when post arrives
- Writer replicates to the other 2 via TCP 4002 (ch_rep)
- Receivers store with the original `received_at` (not reassigned)
- Dedup by `post_uuid` (idempotent insert)
- Hinted handoff unchanged (queue failed replications, retry every 30s, 24h TTL)

### ch_rep Message Format

```
channel_uuid    (16 bytes)
post_uuid       (16 bytes)
author_fp       (64 bytes)
timestamp       (uint64, sender's timestamp)
received_at     (uint64, writer nodus's assigned timestamp)
body            (up to 4096 bytes)
signature       (4627 bytes, Dilithium5)
author_pk       (2592 bytes, optional, for sig verification)
```

---

## Server Implementation

### TCP 4003 Listener

- Separate `listen()` + `accept()` on port 4003
- Same epoll loop as 4001 — this is intentional and correct. epoll is non-blocking: `send()` writes to kernel TCP buffers and returns immediately. Separate ports mean separate connections, separate session pools, and separate fd sets. Channel broadcast to 256 subscribers is microsecond-level work. DHT operations on 4001 and channel operations on 4003 do NOT block each other — epoll is designed to efficiently multiplex thousands of fds in a single thread. A separate thread is unnecessary and would add mutex complexity for no benefit.
- Separate session pool: `ch_sessions[]` (dynamically sized per channel load)
- Max 256 users per channel (across all 3 responsible nodus nodes)
- Channel sessions only dispatch: ch_create, ch_post, ch_get_posts, ch_subscribe, ch_unsubscribe

### Session Structure (Channel)

```c
typedef struct {
    int fd;
    uint8_t fingerprint[64];
    uint8_t pubkey[DILITHIUM_PUBKEY_BYTES];
    uint8_t token[32];
    bool authenticated;

    // Channel subscriptions
    uint8_t ch_subs[NODUS_MAX_CH_SUBS][16];  // channel UUIDs
    int ch_sub_count;

    // Rate limiting
    uint32_t posts_this_minute;
    time_t rate_window_start;
} nodus_ch_session_t;
```

---

## Performance Analysis

### Worst Case: 1 channel, 256 clients, 10 posts/second

```
Post size:        ~9 KB (4096 body + Dilithium5 sig + CBOR overhead)
Per message:      256 × 9 KB = 2.3 MB
Per second:       10 × 2.3 MB = 23 MB/s outbound
Bandwidth:        ~18% of 1 Gbps — comfortable
Syscalls:         2560 send()/s × ~1μs = 2.5ms CPU — negligible
```

### Realistic: 1 channel, 50 clients, 1 post/second

```
Per second:       50 × 9 KB = 450 KB/s — nothing
```

### Scaling

More users → more nodus nodes → hashring distributes channels across more nodes.
A nodus responsible for 10 channels with 50 clients each = 500 connections, ~4.5 MB/s.
Self-scaling by design.

---

## Client SDK Changes

### New API

```c
// Connect to channel-responsible nodus on port 4003
nodus_ch_conn_t* nodus_channel_connect(const char *host, uint16_t port,
                                        const uint8_t *pubkey, const uint8_t *privkey,
                                        const uint8_t *fingerprint);

// Disconnect channel connection
void nodus_channel_disconnect(nodus_ch_conn_t *conn);

// Channel operations over dedicated connection
int nodus_channel_subscribe(nodus_ch_conn_t *conn, const uint8_t *channel_uuid);
int nodus_channel_unsubscribe(nodus_ch_conn_t *conn, const uint8_t *channel_uuid);
int nodus_channel_post(nodus_ch_conn_t *conn, const uint8_t *channel_uuid,
                       const uint8_t *post_uuid, const char *body, size_t body_len,
                       uint64_t timestamp, const uint8_t *signature);
int nodus_channel_get_posts(nodus_ch_conn_t *conn, const uint8_t *channel_uuid,
                            uint64_t since_timestamp, uint32_t max_count,
                            nodus_channel_post_t **posts, int *count);

// Callback for incoming messages on subscribed channels
void nodus_channel_set_notify_cb(nodus_ch_conn_t *conn,
                                  void (*cb)(const nodus_channel_post_t *post, void *user_data),
                                  void *user_data);
```

### Connection Management in Messenger

```c
// nodus_ops layer manages multiple channel connections
// Key: channel_uuid → value: nodus_ch_conn_t*
// When subscribing to a channel:
//   1. Query hashring for responsible nodes
//   2. Check if already connected to one of them on 4003
//   3. If yes, reuse connection. If no, connect to closest/first available.
```

---

## Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Max users per channel | 256 | Per channel, distributed across 3 responsible nodus nodes |
| Post body size | 4096 bytes | Text only |
| Responsible nodus per channel | 3 | Hashring-selected, multi-primary |
| Max channel subscriptions per session | 32 | Per TCP 4003 connection |
| Channel port | TCP 4003 | Dedicated, separate from DHT |
| Hinted handoff TTL | 24h | Unchanged |
| Hinted handoff max | 1000 | Per target node, unchanged |
| Post retention | 7 days | Unchanged |

---

## Migration

### Phase 1: Add TCP 4003 listener
- Server listens on 4003 alongside 4001
- Channel operations accepted on both 4001 (legacy) and 4003 (new)
- Client SDK adds `nodus_channel_connect()` API

### Phase 2: Client migration
- Messenger updated to use 4003 for channels
- Multi-nodus connection management in `nodus_ops.c`

### Phase 3: Remove channel ops from 4001
- Channel message handlers removed from 4001 dispatch
- 4001 is pure DHT/messaging/presence

---

## Files Affected

### Nodus Server
| File | Change |
|------|--------|
| `nodus/src/server/nodus_server.c` | Add TCP 4003 listener, ch_session pool, channel dispatch |
| `nodus/src/server/nodus_server.h` | Add ch_session array, 4003 socket fd |
| `nodus/src/protocol/nodus_tier2.c` | Separate channel encode/decode (or reuse existing) |
| `nodus/src/channel/nodus_channel_store.c` | Remove seq_id, use received_at + post_uuid dedup |
| `nodus/src/channel/nodus_channel_store.h` | Updated types: no seq_id, received_at based queries |
| `nodus/src/channel/nodus_replication.c` | Multi-primary: include received_at in ch_rep |
| `nodus/src/channel/nodus_replication.h` | Updated replication types |
| `nodus/include/nodus/nodus_types.h` | `NODUS_CHANNEL_PORT 4003`, `NODUS_MAX_CH_SESSIONS 256` |

### Nodus Client SDK
| File | Change |
|------|--------|
| `nodus/src/client/nodus_client.c` | `nodus_channel_connect/disconnect`, channel ops over ch_conn |
| `nodus/include/nodus/nodus.h` | Public API: channel connection functions |

### Messenger
| File | Change |
|------|--------|
| `messenger/dht/shared/nodus_ops.c` | Multi-connection management for channels |
| `messenger/dht/shared/nodus_ops.h` | Channel connection API wrappers |
| `messenger/src/api/engine/dna_engine_channels.c` | Use nodus_ops channel connections |

### Config
| File | Change |
|------|--------|
| `nodus/docs/` | Update deployment docs with port 4003 |
| Firewall rules | Open TCP 4003 on all 6 production nodes |

---

## Review Notes (2026-03-13)

### Implementation Order (APPROVED)

Phase 0 (messenger migration) removed. Implementation proceeds bottom-up:

1. **Faz 1 — TCP 4003 altyapısı**: Listener, ch_session, auth, seq_id→received_at migration
2. **Faz 2 — Ring management**: ring_check/ring_ack, DHT self-announcement, ch_ring_changed
3. **Faz 3 — Test & stabilizasyon**: Split-brain, hinted handoff, anti-entropy
4. **Faz 4 — Messenger migration**: dna_channels.c → System B, multi-conn SDK, Flutter

### Resolved: `received_at` reassignment (NOT a design flaw)

The design correctly states "Original received_at preserved by receiving nodus (not reassigned)."
Current code at `nodus_server.c:1713` reassigns it — this is a **code bug to fix during implementation**, not a design issue. The flow is:

1. Post arrives at Nodus-A → Nodus-A assigns `received_at`
2. Nodus-A replicates to B, C **with the same `received_at`**
3. B, C store with original timestamp and forward to their subscribers — no reassignment

Remaining risk: clock skew between originating nodes (~<10ms with NTP, acceptable for chat).

### Resolved: `seq_id` removal (implementation task)

Design correctly specifies seq_id removal. Current code still uses it in 6+ files.
Migration during Faz 1 implementation — not a design flaw.

### Open Issues (from 5-agent review)

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | ~~Same epoll loop defeats stated performance goal~~ | ~~CRITICAL~~ | RESOLVED — epoll is non-blocking; separate ports/sessions/connections don't block each other |
| 2 | ~~TCP 4002 unauthenticated — ring_check spoofable~~ | ~~CRITICAL~~ | RESOLVED — not a priority |
| 3 | ~~DHT key poisoning for channel discovery~~ | ~~CRITICAL~~ | RESOLVED — worst case is DoS (empty channel), not data theft. Posts are Dilithium5 signed, attacker can't forge. Low risk. |
| 4 | ~~All TCP plaintext (no TLS)~~ | ~~CRITICAL~~ | RESOLVED — channels are public content, posts are Dilithium5 signed. TLS unnecessary. |
| 5 | ~~No channel authorization (ACL)~~ | ~~CRITICAL~~ | RESOLVED — channels are public by design. Decentralized system, no moderation. Anyone can post to any channel. |
| 6 | ~~Split-brain — no reconciliation mechanism~~ | ~~HIGH~~ | RESOLVED — independent VPS servers on internet, not a local cluster. A node is either up or down. Hinted handoff (24h TTL) + ch_get_posts sync handles recovery. No realistic split-brain scenario. |
| 7 | ~~Post deletion/moderation missing~~ | ~~HIGH~~ | RESOLVED — decentralized, no moderation, no deletion by design. 7-day retention handles cleanup. |
| 8 | ~~256 client limit unenforceable across 3 nodes~~ | ~~MEDIUM~~ | RESOLVED — soft limit, not critical. Nothing breaks at 257. |
| 9 | ~~Evicted node (Nodus-4) gets no notification~~ | ~~HIGH~~ | RESOLVED — added `ring_evict` message (TCP 4002). Initiator notifies evicted node after ring_ack confirmation. |
| 10 | ~~ring_ack crash → DHT stale, no recovery~~ | ~~HIGH~~ | RESOLVED — DHT lists 3 nodes. Dead node fails TCP handshake, client connects to one of the other 2. Stale DHT is harmless. |
| 11 | ~~No SQLite busy_timeout — silent post loss~~ | ~~HIGH~~ | RESOLVED — single-threaded epoll, no concurrent SQLite writes possible. |
| 12 | ~~CBOR re-serialization per subscriber~~ | ~~HIGH~~ | RESOLVED — design pseudocode already shows correct pattern (serialize once, send to all). Fix during implementation. |
| 13 | ~~NTP clock sync requirement undocumented~~ | ~~MEDIUM~~ | RESOLVED — VPS providers run NTP by default. <10ms skew, irrelevant for chat. |
| 14 | ~~Consistency model (W=1, eventual) undocumented~~ | ~~MEDIUM~~ | RESOLVED — async replication + hinted handoff (30s retry) is fine. Not a problem. |
