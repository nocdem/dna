# Nodus — Replication Design (Target Architecture)

**Date:** 2026-03-08 (revised r2 — review fixes) | **Status:** IMPLEMENTED (2026-03-08) | **Related:** REPLICATION_ISSUES.md

> **Implementation complete.** All 6 phases implemented, 22 unit tests pass (6 new: `test_put_if_newer`, `test_routing_stale`, `test_bucket_refresh`, `test_hinted_handoff`, `test_fetch_batch`, `test_storage_cleanup`). See per-phase implementation notes below.

---

## Finalized Design Decisions

| # | Decision | Value | Rationale |
|---|----------|-------|-----------|
| Q1 | FIND_VALUE transport | **TCP only** | Values ~7.3KB (Dilithium5), UDP MTU=1400B → silent drop |
| Q2 | Republish interval | **60 min** | Kademlia standard, ~2.8 values/sec at 10K values |
| Q3 | Replication count | **R=K=8** | Standard Kademlia, `nodus_routing_find_closest()` returns min(K, node_count) |
| Q4 | Hinted handoff TTL | **7 days** | Match value TTL, max recovery window |
| Q5 | Storage cleanup interval | **1 hour** | Low overhead, sufficient for 7-day TTL values |
| Q6 | dht_find_value() model | **Async epoll state machine** | Non-blocking, no threads, matches existing TCP patterns |
| Q7 | Hinted handoff cap | **Remove** | Dead nodes removed from routing table → no accumulation. 7-day TTL cleans rest. |
| Q8 | Routing stale threshold | **1 hour** (was 90s) | 90s too aggressive at 20+ nodes — filters live non-config peers. Bucket refresh keeps entries fresh. |
| Q9 | FV recv_buf allocation | **Dynamic malloc** | Static 16×3×1.1MB = 53MB. Dynamic: malloc on query start, free on done. ~2MB peak. |
| Q10 | FV response model | **Single value** (`get()` not `get_all()`) | Matches `handle_t2_get()` behavior. Multi-value via `get_all` is separate path. |

---

## Model: Hub-Spoke + Server-Side DHT

```
T1 Clients (Hub-Spoke)              T2 Servers (DHT Network)
========================            ========================

  Client A ──TCP──► Server 1 ◄──Kademlia──► Server 2
  Client B ──TCP──► Server 2 ◄──Kademlia──► Server 3
  Client C ──TCP──► Server 1 ◄──Kademlia──► Server 4
  Client D ──TCP──► Server 3 ◄──Kademlia──► Server 1
                                    ...N servers...
```

- **T1 (Clients):** Connect to ONE server via TCP. PUT/GET/LISTEN. No routing logic. Simple hub-spoke.
- **T2 (Servers):** Form a Kademlia DHT network. Route values to K-closest nodes. Periodic republish. Standard DHT behavior like OpenDHT.

---

## T2 Server Behavior (DHT Network)

### PUT Flow (Client → Server → DHT)

**Current (broken):**
1. Client sends T2 PUT to connected server
2. Server stores locally
3. Server broadcasts to ALL PBFT peers (wrong target, wrong mechanism)

**Target:**
1. Client sends T2 PUT to connected server
2. Server stores locally via `nodus_storage_put_if_newer()` (seq check applies even on client PUT path — see FIX 0a)
3. Server computes K-closest nodes to key hash using Kademlia routing table (`nodus_routing_find_closest()`)
4. Server sends T1 STORE_VALUE to each K-closest node (skip self, skip stale entries)
5. If STORE fails, queue to hinted handoff (keyed by node_id, not IP:Port)
6. Respond PUT_OK to client (even if step 2 skipped due to newer seq — client doesn't need to know)

### GET Flow (Client → Server → DHT)

**Current (broken):**
1. Client sends T2 GET to connected server
2. Server checks local storage
3. If not found → returns empty. Done.

**Target:**
1. Client sends T2 GET to connected server
2. Server checks local storage
3. If found locally → return to client
4. If NOT found → Start async FIND_VALUE state machine (non-blocking, epoll-managed)
5. State machine does iterative Kademlia lookup via non-blocking TCP connections
6. If a node has the value → return to client + cache locally (with seq check)
7. If no node has it → return empty

### Periodic Republish

**Current:** Does not exist.

**Target:**
1. Every 60 minutes, iterate local storage via `nodus_storage_iter_all()`
2. For each stored value:
   a. Compute K-closest nodes to key hash (filter stale entries)
   b. Encode value once via `nodus_t1_store_value()` + `nodus_frame_encode()`
   c. Send encoded frame to each K-closest node via `send_frame_to_peer()`
3. Receiving nodes check seq before accepting (reject if stored seq >= incoming seq)
4. This ensures:
   - New nodes that joined after original PUT receive values they're responsible for
   - Nodes that recovered from outage get missing values
   - Values survive node churn (nodes joining/leaving)

### Node Join / Bootstrap

**Current:** Node starts empty, only receives new PUTs.

**Target:**
1. New node starts, discovers peers via Kademlia FIND_NODE(self_id)
2. Neighboring nodes detect new node in routing table
3. On next republish cycle, values that the new node is K-closest to are sent to it
4. No special "join sync" needed — periodic republish handles it naturally

---

## Critical Pre-Requisite Fixes

### FIX 0a: Seq Check Before Storage (P0 — prevents data loss)

**Bug:** `nodus_storage_put()` uses `INSERT OR REPLACE` with no seq comparison. A republish with seq=5 overwrites existing seq=10 → data loss. The code comment says *"seq comparison in application layer"* but it was never implemented.

**Affected paths (ALL 3):**
- TCP client PUT (`nodus_server.c:337`)
- TCP inter-node `sv` (`nodus_server.c:668`)
- UDP inter-node `sv` (`nodus_server.c:896`)

**Fix — single-SQL atomic `nodus_storage_put_if_newer()`:**

Preferred approach: single SQL statement avoids TOCTOU race between read and write.

```c
int nodus_storage_put_if_newer(nodus_storage_t *store, const nodus_value_t *val) {
    // Atomic: only insert/replace if no existing row has higher seq.
    // On equal seq, tiebreak by SHA3(value_data) — deterministic winner across all nodes.
    // This prevents split-brain: two servers with different data at seq=0 converge
    // to the same value (the one with the higher hash wins).
    sqlite3_stmt *stmt = store->stmt_put_if_newer;
    // Bind: key_hash, owner_fp, value_id, seq, data_hash, [all value fields]
    // SQL does: INSERT OR REPLACE WHERE NOT EXISTS (
    //   SELECT 1 FROM nodus_values
    //   WHERE key_hash=? AND owner_fp=? AND value_id=?
    //   AND (seq > ?2 OR (seq = ?2 AND data_hash >= ?3))
    // )
    // ... execute ...
    return (sqlite3_changes(store->db) > 0) ? 0 : 1;  // 0=stored, 1=skipped
}
```

**New SQL needed — `PUT_IF_NEWER_SQL`:**
```sql
INSERT OR REPLACE INTO nodus_values (key_hash, owner_fp, value_id, seq, data_hash, ...)
SELECT ?, ?, ?, ?, ?, ...
WHERE NOT EXISTS (
    SELECT 1 FROM nodus_values
    WHERE key_hash = ?1 AND owner_fp = ?2 AND value_id = ?3
    AND (seq > ?4 OR (seq = ?4 AND data_hash >= ?5))
);
```

**Tiebreaker on equal seq:** When `seq` is equal, compare `SHA3-256(value_data)`. The value with the higher hash wins deterministically. This prevents permanent divergence when two servers store different data at seq=0 (common — tests and many values use seq=0).

**`data_hash` column:** Add `data_hash BLOB` to `nodus_values` table. Computed once at insert time via `qgp_sha3_256(val->data, val->data_len)`. Small overhead, prevents split-brain. **Schema migration:** Use `ALTER TABLE nodus_values ADD COLUMN data_hash BLOB;` — existing rows get NULL, which is fine: in SQLite, `NULL >= X` evaluates to NULL (not TRUE), so the `AND (seq = ?4 AND data_hash >= ?5)` clause fails, the NOT EXISTS subquery finds no blocking row, and the INSERT proceeds. **Effect: existing NULL-hash values always lose tiebreaks** until re-PUT or republished with hash.

**New prepared statement field:** Add `sqlite3_stmt *stmt_put_if_newer` to `nodus_storage_t`.

**Usage:** Replace `nodus_storage_put()` with `nodus_storage_put_if_newer()` in **ALL 3 storage paths:**
- TCP client PUT (`nodus_server.c:337`)
- TCP inter-node `sv` (`nodus_server.c:668`)
- UDP inter-node `sv` (`nodus_server.c:896`)

**⚠ ALL paths MUST use `put_if_newer()` — no exceptions.** A client is NOT always authoritative: if a client reconnects to a different server and re-sends a stale PUT (e.g., seq=3 after seq=5 was already replicated), unconditional `nodus_storage_put()` would overwrite the newer value. Worse: the next republish cycle would then propagate the stale value to all replicas — **turning republish into a divergence amplifier**. The seq check is the system's convergence guarantee and must be applied universally.

**NULL guard on data_hash:** The `qgp_sha3_256()` call that computes `data_hash` MUST be checked for failure. If `data_hash` is NULL (hash computation failed), the SQL tiebreaker (`data_hash >= ?5`) evaluates to NULL → unconditional overwrite. Guard:
```c
uint8_t data_hash[32];
if (qgp_sha3_256(val->data, val->data_len, data_hash) != 0) {
    QGP_LOG_ERROR(LOG_TAG, "data_hash computation failed, rejecting PUT");
    return -1;
}
```

### FIX 0b: Dead Node Removal from Routing Table (P0 — prevents stale routing)

**Bug:** `nodus_pbft_tick()` marks peers DEAD after 60s but does NOT call `nodus_routing_remove()`. Dead nodes stay in routing table forever (LRU eviction never triggers with 3 nodes in 512 buckets).

**Result:** `nodus_routing_find_closest()` returns dead nodes → replication attempts timeout (2s each) → hinted handoff fills.

**Fix — add `nodus_routing_remove()` call in `nodus_pbft_tick()`:**
```c
// In nodus_pbft.c, when peer transitions to DEAD:
if (old_state != NODUS_NODE_DEAD && peer->state == NODUS_NODE_DEAD) {
    nodus_routing_remove(pbft->routing, &peer->node_id);
}
```

**Note:** `nodus_pbft_t` already has `struct nodus_server *srv` field. Access routing via `((nodus_server_t*)pbft->srv)->routing` — same pattern used by `elect_leader()` and `sync_ring()`. No new field needed.

**Also filter in `nodus_routing_find_closest()`** (safety net):
```c
// Skip entries not seen for >1 hour (bucket refresh keeps live entries fresh)
if (now - peer->last_seen > NODUS_ROUTING_STALE_SEC) continue;
```

**MANDATORY: Do BOTH.** Remove from routing table on DEAD transition + filter stale in find_closest. Phase 3 depends on this for correctness.

### FIX 0c: Dead Peer Recovery via PING Handler (P1 — pre-existing bug)

**Bug:** `nodus_pbft_tick()` skips DEAD peers for PING (line 142: `if (state == DEAD) continue`). The UDP PING handler (line 843-858) updates routing table but does NOT call any PBFT function. Result: once a peer is marked DEAD, it can never recover through normal heartbeat — **permanent deadlock**.

Recovery path is broken:
1. Node A marks node B as DEAD → stops pinging B
2. Node B (still alive) pings A → A's PING handler updates routing table only
3. A never sends PING to B → never gets PONG → `nodus_pbft_on_pong()` never called → B stays DEAD forever

**Fix — add PBFT heartbeat update in PING handler:**
```c
// In handle_udp_message(), PING handler (line 843), after routing_insert:
nodus_pbft_on_pong(&srv->pbft, &msg.node_id, from_ip, from_port);
```

This uses the existing `nodus_pbft_on_pong()` which already handles DEAD→ALIVE promotion (line 232-236 of nodus_pbft.c). A received PING proves the peer is alive, same as a received PONG.

**Alternative:** Resume pinging DEAD peers at a reduced rate (e.g., every 60s instead of 10s). This is more conservative but adds complexity.

### FIX 0d: Kademlia Bucket Refresh (P0 — routing table health for 20+ nodes)

**Bug:** PBFT only pings config peers (`seed_nodes`). Dynamically discovered peers (via FIND_NODE) have no refresh mechanism. After `NODUS_ROUTING_STALE_SEC` (1 hour), `find_closest()` filters them out → routing table effectively only contains config peers.

**Impact:** At 20+ nodes, `replicate_value()` and FIND_VALUE only target config peers. Kademlia routing is broken.

**Fix — standard Kademlia bucket refresh:**
```c
static void dht_bucket_refresh(nodus_server_t *srv) {
    static uint64_t last_refresh = 0;
    uint64_t now = nodus_time_now();
    if (now - last_refresh < NODUS_BUCKET_REFRESH_SEC) return;  // 900s (15 min)
    last_refresh = now;

    for (int b = 0; b < NODUS_BUCKETS; b++) {
        const nodus_bucket_t *bucket = &srv->routing.buckets[b];
        // Skip empty buckets
        if (bucket->count == 0) continue;
        // Skip recently active buckets (any entry seen within refresh interval)
        bool fresh = false;
        for (int e = 0; e < bucket->count && !fresh; e++) {
            if (bucket->entries[e].active &&
                now - bucket->entries[e].peer.last_seen < NODUS_BUCKET_REFRESH_SEC)
                fresh = true;
        }
        if (fresh) continue;

        // Generate random key in this bucket's range and send FIND_NODE
        nodus_key_t random_key;
        nodus_key_random_in_bucket(&random_key, &srv->identity.node_id, b);
        // Use existing UDP FIND_NODE — responses update routing table via routing_insert
        nodus_peer_t target;
        if (bucket->entries[0].active)
            target = bucket->entries[0].peer;
        else continue;
        uint8_t buf[512];
        size_t len = 0;
        nodus_t1_find_node(0, &random_key, buf, sizeof(buf), &len);
        uint8_t frame[512 + 16];
        size_t flen = nodus_frame_encode(frame, sizeof(frame), buf, (uint32_t)len);
        nodus_udp_send(&srv->udp, frame, flen, target.ip, target.udp_port);
    }
}
```

**New helper needed:** `nodus_key_random_in_bucket()` — generate random key that XOR-distances to `self_id` falls in bucket `b`. Simple: copy `self_id`, flip bit `b`, randomize remaining lower bits.

**Call from main loop:** Add `dht_bucket_refresh(srv)` alongside other tick functions.

---

## What Changes

### replicate_value() — Complete Rewrite

**Before:**
```c
for (int i = 0; i < srv->pbft.peer_count; i++) {
    nodus_cluster_peer_t *peer = &srv->pbft.peers[i];
    if (peer->state != NODUS_NODE_ALIVE) continue;
    send_frame_to_peer(peer->ip, peer->tcp_port, frame, flen);
}
```

**After:**
```c
// Find K-closest nodes to this key
nodus_peer_t closest[NODUS_K];
int count = nodus_routing_find_closest(&srv->routing, &val->key_hash, closest, NODUS_K);

for (int i = 0; i < count; i++) {
    // Skip self
    if (nodus_key_cmp(&closest[i].node_id, &srv->identity.node_id) == 0) continue;

    int rc = send_frame_to_peer(closest[i].ip, closest[i].tcp_port, frame, flen);
    if (rc != 0) {
        // Hinted handoff keyed by node_id
        nodus_storage_hinted_insert(&srv->storage, &closest[i].node_id,
                                     closest[i].ip, closest[i].tcp_port,
                                     frame, flen);
    }
}
```

**Note:** `nodus_storage_hinted_insert()` signature changes — requires schema migration (Phase 2).

### handle_t2_get() — Add FIND_VALUE Forwarding (Async State Machine)

**Before:**
```c
int rc = nodus_storage_get(&srv->storage, &msg->key, &val);
if (rc == 0 && val) {
    // send value
} else {
    nodus_t2_result_empty(...);  // DONE - returns empty
}
```

**After:**
```c
int rc = nodus_storage_get(&srv->storage, &msg->key, &val);
if (rc == 0 && val) {
    // send value
} else {
    // Start async FIND_VALUE — non-blocking, managed by epoll
    if (dht_find_value_start(srv, sess, msg->txn_id, &msg->key) != 0) {
        // Too many in-flight lookups — return empty immediately
        nodus_t2_result_empty(msg->txn_id, resp_buf, sizeof(resp_buf), &len);
        nodus_tcp_send(sess->conn, resp_buf, len);
    }
    // Response sent later by state machine when lookup completes
    return;  // Do NOT send response here
}
```

**No worker thread.** FIND_VALUE runs as an async state machine in the main event loop:
- Non-blocking TCP connections registered with the server's epoll fd
- State advanced by `dht_find_value_tick()` called from the main loop
- Zero threads, zero mutexes, zero thread-safety concerns
- Matches existing TCP transport patterns (`nodus_tcp_connect()` + `NODUS_CONN_CONNECTING` + epoll)
- **Cap: `NODUS_FV_MAX_INFLIGHT` (16) concurrent lookups.** When full, return immediate empty to client. Prevents DDoS amplification (each GET-miss → up to 9 outgoing TCP connections × 16 = 144 fds max).

### New: TCP FIND_VALUE Handler

**Add to `dispatch_t2()` pre-auth section (after `sv` handler):**

Rate-limit to `NODUS_FV_MAX_PER_SEC` (100) to prevent amplification from malicious nodes. Uses `nodus_storage_get()` (single value, highest seq) — consistent with `handle_t2_get()` behavior. Multi-value retrieval uses the separate `get_all` path.

```c
} else if (strcmp(msg.method, "fv") == 0) {
    /* Inter-nodus FIND_VALUE (no auth required, rate-limited) */
    static uint64_t fv_window_start = 0;
    static int fv_count = 0;
    uint64_t now = nodus_time_now();
    if (now != fv_window_start) { fv_window_start = now; fv_count = 0; }
    if (++fv_count > NODUS_FV_MAX_PER_SEC) {
        nodus_t2_msg_free(&msg);
        return;  /* Drop — rate limited */
    }

    nodus_tier1_msg_t t1msg;
    memset(&t1msg, 0, sizeof(t1msg));
    if (nodus_t1_decode(payload, len, &t1msg) == 0) {
        nodus_value_t *val = NULL;
        int rc = nodus_storage_get(&srv->storage, &t1msg.target, &val);

        size_t rlen = 0;
        if (rc == 0 && val) {
            /* Return single value (highest seq) — matches handle_t2_get() */
            nodus_t1_value_found(t1msg.txn_id, val,
                                  resp_buf, sizeof(resp_buf), &rlen);
            nodus_value_free(val);
        } else {
            nodus_peer_t results[NODUS_K];
            int found = nodus_routing_find_closest(&srv->routing, &t1msg.target,
                                                    results, NODUS_K);
            nodus_t1_value_not_found(t1msg.txn_id, results, found,
                                      resp_buf, sizeof(resp_buf), &rlen);
        }
        nodus_tcp_send(sess->conn, resp_buf, rlen);
    }
    nodus_t1_msg_free(&t1msg);
    nodus_t2_msg_free(&msg);
    return;
}
```

### New: dht_find_value() — Iterative Kademlia Lookup (Async Epoll State Machine)

**CRITICAL: Must use TCP, NOT UDP.** Values ~7.3KB > UDP MTU 1400B → silent drop.

**Runs in the main event loop as a non-blocking state machine. No threads.**

The server's existing TCP transport already implements non-blocking connect via epoll (`nodus_tcp_connect()` → `NODUS_CONN_CONNECTING` → `EPOLLOUT` → `handle_connect_complete()`). The FIND_VALUE state machine follows the same pattern: non-blocking connect, epoll-driven send/recv, state advancement in a tick function.

#### State Machine Struct

```c
#define NODUS_FV_MAX_INFLIGHT   16   // Max concurrent FIND_VALUE lookups
#define NODUS_FV_MAX_QUERIES     9   // Max outgoing queries per lookup (3 rounds × alpha=3)
#define NODUS_FV_TIMEOUT_MS   5000   // Per-lookup overall timeout

typedef enum {
    FV_QUERY_CONNECTING,    // Non-blocking connect in progress (EPOLLOUT)
    FV_QUERY_SENDING,       // Connected, sending request (EPOLLOUT)
    FV_QUERY_RECEIVING,     // Request sent, waiting for response (EPOLLIN)
    FV_QUERY_DONE,          // Response received or failed
} dht_fv_query_state_t;

// One outgoing TCP query to a peer
typedef struct {
    int                     fd;           // Socket fd (-1 if unused)
    dht_fv_query_state_t    state;
    nodus_key_t             node_id;      // Peer being queried
    char                    ip[64];
    uint16_t                tcp_port;
    uint64_t                started_at;   // For per-query timeout
    uint8_t                *send_buf;     // Encoded fv request frame
    size_t                  send_len;
    size_t                  send_pos;     // Bytes sent so far
    uint8_t                *recv_buf;     // Dynamic: malloc on query start, free on done
    size_t                  recv_cap;     // = NODUS_MAX_VALUE_SIZE + 65536
    size_t                  recv_len;
} dht_fv_query_t;
// Memory: ~2MB peak (2 active lookups typical) vs 53MB static (16×3×1.1MB)

// One FIND_VALUE lookup (may issue multiple queries across rounds)
typedef struct {
    bool                    active;
    nodus_key_t             key_hash;          // Key being looked up
    uint32_t                txn_id;            // Client's transaction ID
    int                     session_slot;      // Client session index
    uint64_t                started_at;        // For overall timeout

    // Kademlia iterative state
    nodus_peer_t            candidates[NODUS_K * 4];  // Peers to query (sorted by distance)
    int                     candidate_count;
    nodus_key_t             visited[NODUS_K * 4];     // Already queried node_ids
    int                     visited_count;
    int                     round;                     // Current round (0-2)

    // Active outgoing queries for this lookup
    dht_fv_query_t          queries[NODUS_ALPHA];      // Up to alpha=3 parallel queries
    int                     queries_pending;            // How many queries still in flight

    // Result
    bool                    found;
    uint8_t                *result_buf;    // Encoded response to send to client
    size_t                  result_len;
} dht_fv_lookup_t;

// All in-flight lookups (in nodus_server_t)
typedef struct {
    dht_fv_lookup_t         lookups[NODUS_FV_MAX_INFLIGHT];
} dht_fv_state_t;
```

#### Lifecycle

```
1. handle_t2_get() calls dht_find_value_start(srv, sess, txn_id, &key):
   a. Find free slot in srv->fv_state.lookups[]
   b. If none free → return -1 (caller sends empty response)
   c. Populate lookup: key_hash, txn_id, session_slot, started_at
   d. Get K-closest from routing table → candidates[]
   e. Start alpha=3 queries to closest unvisited candidates (see step 2)
   f. Return 0 (lookup started)

2. Starting a query (dht_fv_query_start):
   a. Create non-blocking socket: socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)
   b. connect() → returns EINPROGRESS
   c. Register fd with srv->tcp.epoll_fd: epoll_add(fd, EPOLLOUT | EPOLLET, tagged_ptr)
      — tagged_ptr identifies this as a FV query (not a regular client connection)
      — Use high bit of user_data pointer or separate fd→lookup mapping
   d. Set query state = FV_QUERY_CONNECTING
   e. Add node_id to visited[]

3. Main loop calls dht_find_value_tick(srv) every iteration:
   For each active lookup:
   a. Check overall timeout (NODUS_FV_TIMEOUT_MS) → if expired, complete with empty
   b. Check per-query timeouts (NODUS_FV_QUERY_TIMEOUT_MS=3000) → close timed-out fds
   c. If all queries for current round are DONE and no value found:
      - Merge closer nodes from responses into candidates[]
      - Filter visited[] nodes
      - If closer unvisited candidates exist AND round < 3 → start next round
      - Else → complete with empty
   d. If lookup complete (found or exhausted):
      - Send response to client via nodus_tcp_send(sessions[slot].conn, ...)
        (check sessions[slot].conn != NULL first — client may have disconnected)
      - If found → cache locally via nodus_storage_put_if_newer()
      - Close all open fds for this lookup
      - Mark slot inactive

4. Epoll events for FV query fds (dispatched from nodus_tcp_poll or separate handler):
   — FV query fds are distinguished from regular client connections by a lookup table
     or by storing them in a separate fd→(lookup_idx, query_idx) mapping array.

   EPOLLOUT (connecting or sending):
   a. If state == FV_QUERY_CONNECTING:
      - getsockopt(SO_ERROR) — check connect result
      - If error → state = FV_QUERY_DONE (failed), close fd
      - If success → state = FV_QUERY_SENDING, switch to EPOLLOUT
   b. If state == FV_QUERY_SENDING:
      - send() remaining bytes from send_buf
      - If complete → state = FV_QUERY_RECEIVING, switch to EPOLLIN | EPOLLET
      - If EAGAIN → wait for next EPOLLOUT

   EPOLLIN (receiving response):
   a. Read into recv_buf
   b. Try parse frame (7-byte header + payload)
   c. If complete frame:
      - Decode T1 response
      - If value_found → set lookup->found = true, encode result for client
      - If value_not_found → add returned closer nodes to candidates[]
      - state = FV_QUERY_DONE, close fd, epoll_ctl DEL
   d. If EAGAIN → wait for next EPOLLIN

   EPOLLERR / EPOLLHUP:
   a. state = FV_QUERY_DONE (failed), close fd, epoll_ctl DEL

5. Client disconnect during lookup:
   — nodus_tcp on_disconnect callback already calls session_clear()
   — dht_find_value_tick() checks sessions[slot].conn != NULL before sending
   — If NULL: discard result, close all query fds, mark inactive
   — No generation counter needed: main thread owns everything (single-threaded)
```

#### FV Query fd Mapping

FV query fds must be distinguishable from regular client/server connections in epoll events.

**Approach: fd→lookup index table.**

```c
// In nodus_server_t or dht_fv_state_t:
typedef struct {
    int lookup_idx;   // Index into lookups[]
    int query_idx;    // Index into lookup->queries[]
} dht_fv_fd_entry_t;

// Fixed-size table indexed by fd (fds are small integers on Linux)
#define NODUS_FV_FD_TABLE_SIZE  4096
dht_fv_fd_entry_t fv_fd_table[NODUS_FV_FD_TABLE_SIZE];
// Entry is valid when lookup_idx >= 0. Initialize all to -1.
```

When epoll fires for an fd, check `fv_fd_table[fd].lookup_idx >= 0`. If yes, dispatch to FV handler. If no, dispatch to regular TCP handler (existing path).

**Alternative:** Use `epoll_event.data.u64` with a tag bit to distinguish FV fds from regular connections. Both approaches work; the fd table is simpler to implement.

#### Why This Is Better Than a Worker Thread

| Concern | Worker Thread | Async State Machine |
|---------|--------------|---------------------|
| Thread safety | Separate SQLite conn, own buffers, pipe IPC, generation counter | Not needed — single-threaded |
| Session ABA | Generation counter + careful memset | Not needed — main thread owns sessions |
| Crash monitoring | Heartbeat + restart + queue drain | Not needed — no thread to crash |
| Shutdown | Atomic flag + condvar + pthread_join + drain | Close fds, mark inactive. Done. |
| Concurrent lookups | Sequential (1 worker = 1 lookup at a time) | Naturally parallel (16 concurrent) |
| Main loop blocking | None (thread is separate) | None (all non-blocking) |
| Code complexity | ~300 lines (thread + queue + pipe + crash monitor) | ~200 lines (state machine + tick) |
| Matches existing patterns | No (new threading model) | Yes (same as nodus_tcp_connect) |

#### Timeout Handling

- **Per-query timeout:** `NODUS_FV_QUERY_TIMEOUT_MS` (3000ms). Checked in `dht_find_value_tick()`. If `nodus_time_now_ms() - query->started_at > 3000`, close fd, mark DONE.
- **Per-lookup timeout:** `NODUS_FV_TIMEOUT_MS` (5000ms). If overall lookup exceeds this, send empty to client, close all fds.
- **No blocking:** All timeouts are checked by polling in the tick function. No `poll()` or `sleep()` calls.

#### Shutdown

```
1. nodus_server_stop() sets srv->running = false
2. Main loop exits
3. nodus_server_close():
   a. For each active FV lookup: close all query fds, free buffers
   b. Proceed with normal cleanup (tcp, udp, storage, etc.)
   — No threads to join, no queues to drain, no condvars to signal
```

### New: Periodic Republish Timer (Non-Blocking Epoll Sends)

**CRITICAL:** `send_frame_to_peer()` blocks up to 2s per peer on timeout. Republishing N values to K peers naively = N×K×2s worst case. At 1000 values × 7 peers = 14,000s — PBFT marks this node DEAD after 60s. **Must use non-blocking sends.**

**Design: Fetch `NODUS_REPUBLISH_BATCH` values per tick, send via non-blocking TCP managed by epoll. Zero blocking in the main loop.**

**⚠ Uses bookmark pagination (NOT persistent cursor).** A persistent `sqlite3_stmt` cursor held open across ticks blocks WAL checkpointing — the WAL file grows unboundedly for the entire republish cycle (10K values ÷ 10/batch = 1000 ticks × ~100ms = ~100s of uncheckpointed writes). Bookmark pagination avoids this: each batch is a fresh `SELECT ... WHERE key_hash > ? ORDER BY key_hash LIMIT N`, finalized immediately after reading.

```c
#define NODUS_REPUBLISH_BATCH  5   // Values per main loop iteration
#define NODUS_REPUBLISH_MAX_FDS 64  // Max concurrent outgoing republish connections

// Persistent state across ticks (in nodus_server_t)
typedef struct {
    nodus_key_t last_key;       // Bookmark: last key_hash processed (for pagination)
    bool active;                // Republish cycle in progress
    bool first_batch;           // First batch of cycle (no bookmark yet)
    uint64_t cycle_start;       // When current cycle began

    // Non-blocking send tracking
    int pending_fds;            // Number of outgoing connections in flight
} dht_republish_state_t;
```

#### Republish Send Flow (Non-Blocking)

```c
static void dht_republish(nodus_server_t *srv) {
    dht_republish_state_t *rs = &srv->republish_state;
    uint64_t now = nodus_time_now();

    if (!rs->active) {
        // Start new cycle every NODUS_REPUBLISH_SEC
        if (now - rs->cycle_start < NODUS_REPUBLISH_SEC) return;
        memset(&rs->last_key, 0, sizeof(rs->last_key));
        rs->active = true;
        rs->first_batch = true;
        rs->cycle_start = now;
    }

    // Don't fetch more if too many sends in flight
    if (rs->pending_fds >= NODUS_REPUBLISH_MAX_FDS) return;

    // Fetch BATCH values using bookmark pagination (no held cursor)
    nodus_value_t *batch[NODUS_REPUBLISH_BATCH];
    int fetched = nodus_storage_fetch_batch(&srv->storage,
                                             rs->first_batch ? NULL : &rs->last_key,
                                             batch, NODUS_REPUBLISH_BATCH);
    rs->first_batch = false;

    for (int i = 0; i < fetched; i++) {
        nodus_value_t *val = batch[i];

        // Encode frame once for all peers
        uint8_t *cbor_buf = malloc(RESP_BUF_SIZE);
        if (!cbor_buf) { nodus_value_free(val); continue; }
        size_t clen = 0;
        if (nodus_t1_store_value(0, val, cbor_buf, RESP_BUF_SIZE, &clen) != 0) {
            free(cbor_buf); nodus_value_free(val); continue;
        }
        uint8_t *frame = malloc(clen + 16);
        if (!frame) { free(cbor_buf); nodus_value_free(val); continue; }
        size_t flen = nodus_frame_encode(frame, clen + 16, cbor_buf, (uint32_t)clen);
        free(cbor_buf);

        nodus_peer_t closest[NODUS_K];
        int n = nodus_routing_find_closest(&srv->routing, &val->key_hash, closest, NODUS_K);

        for (int j = 0; j < n; j++) {
            if (nodus_key_cmp(&closest[j].node_id, &srv->identity.node_id) == 0) continue;
            if (rs->pending_fds >= NODUS_REPUBLISH_MAX_FDS) break;

            // Non-blocking fire-and-forget: connect + queue write + close on completion
            dht_republish_send_async(srv, closest[j].ip, closest[j].tcp_port,
                                      frame, flen);
            rs->pending_fds++;
            // No hinted handoff for republish — next cycle will retry
        }

        rs->last_key = val->key_hash;
        free(frame);
        nodus_value_free(val);
    }

    // Check if cycle complete (fewer rows than batch size)
    if (fetched < NODUS_REPUBLISH_BATCH) {
        rs->active = false;
        rs->cycle_start = nodus_time_now();
    }
}
```

#### `dht_republish_send_async()` — Non-Blocking Fire-and-Forget

```c
// Non-blocking TCP send: connect + send frame + close.
// All stages managed by epoll. Main loop never blocks.
void dht_republish_send_async(nodus_server_t *srv, const char *ip,
                               uint16_t port, const uint8_t *frame, size_t flen) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return;

    // Start non-blocking connect
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &addr.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    if (rc == 0) {
        // Immediate connect (rare, localhost) — queue write and close
        send(fd, frame, flen, MSG_NOSIGNAL);
        close(fd);
        srv->republish_state.pending_fds--;
        return;
    }
    if (!IS_EINPROGRESS(errno)) {
        close(fd);
        srv->republish_state.pending_fds--;
        return;
    }

    // EINPROGRESS — register with epoll for connect completion
    // Store frame data + fd in republish_conn tracking struct
    dht_republish_conn_t *rc_entry = dht_republish_conn_alloc(srv, fd, frame, flen);
    if (!rc_entry) { close(fd); srv->republish_state.pending_fds--; return; }

    epoll_add(srv->tcp.epoll_fd, fd, EPOLLOUT | EPOLLET, rc_entry);
    // epoll will fire EPOLLOUT when connected → send frame → close fd
}
```

#### Republish Connection Tracking

```c
#define NODUS_REPUBLISH_MAX_FDS  64

typedef struct {
    int      fd;
    uint8_t *frame;       // malloc'd copy of frame data
    size_t   frame_len;
    size_t   send_pos;    // Bytes sent so far
    uint64_t started_at;  // For timeout detection
    bool     active;
} dht_republish_conn_t;
```

Epoll events for republish fds are dispatched via the same fd→entry mapping pattern as FV queries. On `EPOLLOUT`: check `SO_ERROR`, if connected → `send()` non-blocking, if complete → `close(fd)` + decrement `pending_fds`. On timeout (checked in `dht_republish_tick()`, 2s) → close fd + decrement.

**Key difference from FV queries:** republish connections are fire-and-forget (no response reading). State machine is trivial: CONNECTING → SENDING → close.

#### Why Non-Blocking Republish Is Better

The old design used `send_frame_to_peer_timeout()` with 200ms connect timeout. Worst case per tick: 5 values × 7 peers × 200ms = **7s of blocking**. During a network partition (all peers unreachable), this blocks on every main loop iteration — no TCP polling, no PBFT heartbeats.

Non-blocking approach: `connect()` returns immediately (EINPROGRESS). Epoll fires when connected or timed out. **Zero blocking in the main loop.** The 100ms epoll timeout in `nodus_tcp_poll()` is the only wait, same as normal operation.

**New functions needed:**
- `nodus_storage_fetch_batch()` — `SELECT * FROM nodus_values WHERE key_hash > ? ORDER BY key_hash LIMIT ?` (returns array of `nodus_value_t*`, finalizes statement immediately)
- `dht_republish_send_async()` — non-blocking TCP fire-and-forget via epoll
- `dht_republish_tick()` — timeout expired connections, decrement pending_fds

**New SQL — `FETCH_BATCH_SQL`:**
```sql
SELECT * FROM nodus_values WHERE key_hash > ? ORDER BY key_hash LIMIT ?
```
First batch uses `key_hash > X'00..00'` (all zeros) to start from the beginning.

**New field in `nodus_server_t`:** `dht_republish_state_t republish_state`

### Hinted Handoff — Add node_id

**Schema migration (CRITICAL for deployed servers):**

Existing servers have `dht_hinted_handoff` table without `node_id` column. `CREATE TABLE IF NOT EXISTS` will NOT add the column. Hinted handoff data is transient — safe to drop and recreate.

```c
// In nodus_storage_open(), BEFORE creating the new table:
sqlite3_exec(store->db, "DROP TABLE IF EXISTS dht_hinted_handoff;", NULL, NULL, NULL);
```

**New schema:**
```sql
CREATE TABLE IF NOT EXISTS dht_hinted_handoff (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     BLOB NOT NULL,
    peer_ip     TEXT NOT NULL,
    peer_port   INTEGER NOT NULL,
    frame_data  BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    retry_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dht_hint_node ON dht_hinted_handoff(node_id);
```

**Note:** Index changes from `(peer_ip, peer_port)` to `(node_id)` since Phase 6 queries by node_id.

**Struct change:** Add `nodus_key_t node_id` field to `nodus_dht_hint_t` in `nodus_storage.h`.

**Prepared statement:** Update `HINT_INSERT_SQL` to include `node_id` bind parameter (6 params, was 5).

**TTL change:** Increase from 24 hours to **7 days** (match value TTL = `NODUS_DEFAULT_TTL`).

**Cap:** Remove `DHT_HINT_MAX_ENTRIES` (dead nodes are removed from routing table, no accumulation).

**Retry change:** Look up node_id in routing table for current IP:Port before retrying. If node migrated IP, use the routing table's current entry. New SQL needed for Phase 6:
```sql
SELECT DISTINCT node_id FROM dht_hinted_handoff WHERE expires_at > ?
```

### New: Storage Cleanup Timer

**Current:** `nodus_storage_cleanup()` exists in `nodus_storage.c:328` but is **never called**. Values never expire.

**Target:**
```c
// In server main loop, add:
static void dht_storage_cleanup(nodus_server_t *srv) {
    static uint64_t last_cleanup = 0;
    uint64_t now = nodus_time_now();
    if (now - last_cleanup < NODUS_CLEANUP_SEC) return;  // 3600s (1 hour)
    last_cleanup = now;
    nodus_storage_cleanup(&srv->storage);  // takes no `now` param — reads time(NULL) internally
}
```

---

## What Does NOT Change

- **T1 protocol (client):** No changes. Clients still connect to one server, send T2 PUT/GET/LISTEN.
- **T1 Kademlia handlers (UDP):** FIND_NODE, STORE_VALUE handlers work correctly. FIND_VALUE works but silently drops responses >1400B (acceptable — TCP path is primary).
- **Channel replication:** Already uses hashring correctly (`NODUS_R=3`). No changes needed.
- **Presence sync:** Broadcast to all PBFT peers is acceptable (everyone needs to know who's online).
- **PBFT consensus:** Stays for DNAC witness BFT. No longer used for DHT replication.

---

## PBFT vs Kademlia — Clear Separation

| Concern | Mechanism | Data Structure |
|---------|-----------|----------------|
| DNAC witness consensus | PBFT | `srv->pbft.peers[]` |
| DHT value replication | Kademlia K-closest | `srv->routing` (routing table) |
| Channel replication | Consistent hash ring | `srv->ring` (hashring) |
| Presence broadcast | All known peers | `srv->pbft.peers[]` (acceptable) |
| Peer discovery | Kademlia FIND_NODE | `srv->routing` (routing table) |

---

## Implementation Order

Dependencies resolved — each step can be implemented in order without forward references.

### Phase 1: Foundation Fixes — IMPLEMENTED
1. **FIX 0a: `nodus_storage_put_if_newer()`** — Atomic seq check with SHA3-256 hash tiebreaker (`nodus_storage.c/h`). Unit test: `test_put_if_newer`.
2. **FIX 0b: Dead node routing table removal** — Dead peer removal from routing table on PBFT DEAD transition (`nodus_pbft.c`). Stale entry filtering in `nodus_routing_find_closest()` — entries older than `NODUS_ROUTING_STALE_SEC` (3600s) excluded (`nodus_routing.c`). Unit test: `test_routing_stale`.
3. **FIX 0c: Dead peer recovery** — PING handler pong callback added (`nodus_server.c`). Received PING now calls `nodus_pbft_on_pong()` for DEAD→ALIVE recovery.
4. **FIX 0d: Kademlia bucket refresh** — `nodus_key_random_in_bucket()` (`nodus_routing.c/h`). Bucket refresh every `NODUS_BUCKET_REFRESH_SEC` (900s) in `nodus_server.c`. Unit test: `test_bucket_refresh`.

### Phase 2: Hinted Handoff Schema — IMPLEMENTED
5. **Hinted handoff migration** — Changed from IP:port keying to node_id keying. 7-day TTL (was 24h). No cap on entries. `DROP TABLE` + recreate on schema change. Unit test: `test_hinted_handoff`.

### Phase 3: K-Closest Replication — IMPLEMENTED
6. **`replicate_value()` rewrite** — Uses `nodus_routing_find_closest()` instead of PBFT peer broadcast. Failed replication creates hinted handoff entries keyed by node_id.

### Phase 4a: TCP FIND_VALUE Handler — IMPLEMENTED
7. **TCP `fv` handler** — New method in `dispatch_t2()` pre-auth section. Rate-limited: `NODUS_FV_MAX_PER_SEC` (100).
8. **`sv` rate limiting** — Added `NODUS_SV_MAX_PER_SEC` (200) to inter-node STORE_VALUE handler.

### Phase 4b: Async FIND_VALUE State Machine — IMPLEMENTED
9. **State machine structs** — `dht_fv_query_state_t`, `dht_fv_query_t`, `dht_fv_lookup_t`, `dht_fv_state_t`, `dht_fv_fd_entry_t` in `nodus_server.h`.
10. **`dht_find_value_start()`** — Starts async Kademlia lookup when GET misses locally. Up to `NODUS_FV_MAX_INFLIGHT` (16) concurrent lookups.
11. **`dht_find_value_tick()`** — Polls FV epoll fd, advances state machines, handles timeouts. 3 rounds of alpha=3 queries each.
12. **FV fd mapping** — Separate epoll fd for FV query connections. `fv_fd_table[]` for dispatch.
13. **`handle_t2_get()` forwarding** — Calls `dht_find_value_start()` on local miss, state machine sends response asynchronously.

### Phase 5: Non-Blocking Periodic Republish — IMPLEMENTED
14. **`nodus_storage_fetch_batch()`** — Bookmark-paginated batch fetch (`nodus_storage.c`). Unit test: `test_fetch_batch`.
15. **`dht_republish_send_async()`** — Non-blocking fire-and-forget TCP via separate epoll fd. `dht_republish_conn_t` tracking.
16. **`dht_republish()` + `dht_republish_state_t`** — `NODUS_REPUBLISH_SEC` (3600s) interval, `NODUS_REPUBLISH_BATCH` (5) per tick, max `NODUS_REPUBLISH_MAX_FDS` (64) concurrent fds.
17. **`dht_storage_cleanup()`** — Removes expired ephemeral values every `NODUS_CLEANUP_SEC` (3600s). Unit test: `test_storage_cleanup`.

### Phase 6: Hinted Handoff Retry Fix — IMPLEMENTED
18. **`dht_hinted_retry()`** — Queries distinct node_ids from hinted handoff table, looks up current IP:port via routing table.

### Deployment Order
- Phase 1-3: Can deploy incrementally (nodes with/without fixes coexist)
- Phase 4a: Deploy to ALL nodes before 4b (receivers must understand `fv` before senders send it)
- Phase 4b: Deploy after 4a is on all nodes (senders need receivers to have `fv` handler)
- Phase 5-6: Independent, deploy anytime after Phase 1
- All phases are single-threaded — no threading concerns during rolling deploys

---

## Constants

```c
#define NODUS_K                    8       // existing — routing bucket size = DHT replication factor
#define NODUS_R                    3       // existing — channel replication factor (hashring ONLY, separate)
#define NODUS_ALPHA                3       // existing — parallel lookup count
#define NODUS_REPUBLISH_SEC        3600    // NEW — 60 minutes
#define NODUS_REPUBLISH_BATCH      5       // NEW — values per main loop tick during republish
#define NODUS_REPUBLISH_MAX_FDS    64      // NEW — max concurrent outgoing republish connections
#define NODUS_CLEANUP_SEC          3600    // NEW — 1 hour
#define NODUS_ROUTING_STALE_SEC    3600    // NEW — filter stale entries in find_closest (1 hour, bucket refresh keeps live peers fresh)
#define NODUS_FV_MAX_INFLIGHT      16      // NEW — max concurrent FIND_VALUE lookups
#define NODUS_FV_MAX_QUERIES       9       // NEW — max outgoing queries per lookup (3 rounds × alpha=3)
#define NODUS_FV_TIMEOUT_MS        5000    // NEW — per-lookup overall timeout
#define NODUS_FV_QUERY_TIMEOUT_MS  3000    // NEW — per-query connect+recv timeout
#define NODUS_FV_FD_TABLE_SIZE     4096    // NEW — fd→lookup mapping table size
#define NODUS_TCP_CONNECT_MS       2000    // NEW — default connect timeout for send_frame_to_peer()
#define DHT_HINT_TTL_SEC           604800  // CHANGE — 7 days (was 86400 = 24h)
#define NODUS_FV_MAX_PER_SEC       100     // NEW — rate limit inter-node FIND_VALUE requests
#define NODUS_SV_MAX_PER_SEC       200     // NEW — rate limit inter-node STORE_VALUE requests (higher than FV: republish sends more)
#define NODUS_BUCKET_REFRESH_SEC   900     // NEW — 15 minutes, refresh routing buckets via FIND_NODE
// DHT_HINT_MAX_ENTRIES           REMOVED — TTL + dead node removal is sufficient
// NODUS_WORKER_*                 NOT NEEDED — no worker thread (async state machine instead)
// NODUS_REPUBLISH_CONNECT_MS     NOT NEEDED — non-blocking connects don't need timeout constant
```

**Note:** `NODUS_R=3` is for channel replication (hashring). DHT value replication uses `NODUS_K=8` (standard Kademlia). These are separate systems with separate replication factors.

---

## Verified API Surface (Agent Audit 2026-03-08)

### Available Functions (exist, ready to use)
| Function | Signature | Location |
|----------|-----------|----------|
| `nodus_routing_find_closest()` | `int (const nodus_routing_t*, const nodus_key_t*, nodus_peer_t*, int)` | `nodus_routing.c:114` |
| `nodus_routing_remove()` | `int (nodus_routing_t*, const nodus_key_t*)` | `nodus_routing.c:86` |
| `nodus_routing_lookup()` | `int (const nodus_routing_t*, const nodus_key_t*, nodus_peer_t*)` | `nodus_routing.c:172` |
| `nodus_key_cmp()` | `int (const nodus_key_t*, const nodus_key_t*)` — returns 0 if equal | `nodus_types.h:338` |
| `nodus_storage_get()` | `int (nodus_storage_t*, const nodus_key_t*, nodus_value_t**)` | `nodus_storage.c:247` |
| `nodus_storage_put()` | `int (nodus_storage_t*, const nodus_value_t*)` — INSERT OR REPLACE, NO seq check | `nodus_storage.c:225` |
| `nodus_storage_cleanup()` | `int (nodus_storage_t*)` — deletes values where `expires_at > 0 AND expires_at <= now` | `nodus_storage.c:328` |
| `nodus_t1_find_value()` | Encoder — builds `fv` request | `nodus_tier1.c:134` |
| `nodus_t1_value_found()` | Encoder — builds `fv_r` with value | `nodus_tier1.c:151` |
| `nodus_t1_value_not_found()` | Encoder — builds `fv_r` with K-closest | `nodus_tier1.c:165` |
| `nodus_t1_store_value()` | Encoder — builds `sv` request | `nodus_tier1.c:110` |
| `nodus_t1_decode()` | Decoder — parses any T1 message | `nodus_tier1.c` |
| `nodus_value_verify()` | Verify Dilithium5 signature — does NOT check seq | `nodus_value.c:140` |
| `send_frame_to_peer()` | Fire-and-forget TCP (connect, send, close, 2s timeout) | `nodus_server.c:161` |

### Functions Created (ALL IMPLEMENTED)
| Function | Purpose | Phase | Location |
|----------|---------|-------|----------|
| `nodus_storage_put_if_newer()` | Atomic seq check with SHA3-256 hash tiebreaker | Phase 1 | `nodus_storage.c/h` |
| `nodus_storage_fetch_batch()` | Bookmark-paginated batch fetch for republish | Phase 5 | `nodus_storage.c/h` |
| `nodus_key_random_in_bucket()` | Generate random key in bucket range for refresh | Phase 1 | `nodus_routing.c/h` |
| `nodus_time_now_ms()` | Millisecond timestamp for FV query timeouts | Phase 4b | `nodus_transport` |
| `dht_bucket_refresh()` | Periodic FIND_NODE on random key per stale bucket | Phase 1 | `nodus_server.c` |
| `dht_find_value_start()` | Initiate async FIND_VALUE on GET miss | Phase 4b | `nodus_server.c` |
| `dht_find_value_tick()` | Advance FV state machines, handle timeouts | Phase 4b | `nodus_server.c` |
| `dht_republish()` | Non-blocking periodic republish with batch pagination | Phase 5 | `nodus_server.c` |
| `dht_republish_send_async()` | Non-blocking fire-and-forget TCP via epoll | Phase 5 | `nodus_server.c` |
| `dht_storage_cleanup()` | Periodic expired value removal | Phase 5 | `nodus_server.c` |
| `dht_hinted_retry()` | Hinted handoff retry via routing table lookup | Phase 6 | `nodus_server.c` |
| TCP `fv` handler | Server-side TCP FIND_VALUE (rate-limited) | Phase 4a | `nodus_server.c` |
| `sv` rate limit | Rate limit inter-node STORE_VALUE | Phase 4a | `nodus_server.c` |

### Schema Changes (ALL IMPLEMENTED)
| Change | Location | Phase |
|--------|----------|-------|
| Add `data_hash BLOB` column to `nodus_values` | `nodus_storage.c` | Phase 1 |
| Add `sqlite3_stmt *stmt_put_if_newer` to `nodus_storage_t` | `nodus_storage.h` | Phase 1 |
| `DROP TABLE dht_hinted_handoff` + recreate with `node_id` | `nodus_storage.c` | Phase 2 |
| Add `nodus_key_t node_id` to `nodus_dht_hint_t` | `nodus_storage.h` | Phase 2 |
| Add `dht_fv_state_t fv_state` to `nodus_server_t` | `nodus_server.h` | Phase 4b |
| Add `dht_fv_fd_entry_t fv_fd_table[]` to `nodus_server_t` | `nodus_server.h` | Phase 4b |
| Add `dht_republish_state_t republish_state` to `nodus_server_t` (with `last_key` bookmark) | `nodus_server.h` | Phase 5 |
| Add `dht_republish_conn_t` tracking array to `nodus_server_t` | `nodus_server.h` | Phase 5 |

### Key Structs
| Struct | Fields | Location |
|--------|--------|----------|
| `nodus_peer_t` | `node_id, ip[64], udp_port, tcp_port, last_seen` | `nodus_types.h:164` |
| `nodus_value_t` | `key_hash, value_id, data, data_len, type, ttl, created_at, expires_at, seq, owner_pk, owner_fp, signature` | `nodus_types.h:136` |
| `nodus_cluster_peer_t` | `node_id, ip[64], udp_port, tcp_port, last_seen, state` | `nodus_pbft.h:30` |
| `nodus_server_t` | has `routing`, `storage`, `pbft`, `ring`, `presence`, `sessions[]` | `nodus_server.h:80` |

### Critical Architecture Notes
- **Entire server is single-threaded** — main loop + all tick functions + all async state machines run in one thread. No mutexes, no thread-safety concerns. This is a deliberate design choice, not a limitation.
- **`resp_buf` is shared global** (~1.1MB) — used for synchronous request handlers. FV query responses use per-query `recv_buf` (dynamically allocated per query). Republish uses `malloc`'d frame buffers (memcpy'd per connection).
- **`send_frame_to_peer()` is fire-and-forget** — connect, send, close. No response reading. FV queries use non-blocking epoll-managed connections with response reading.
- **FV query fds vs regular connections:** Distinguished via `fv_fd_table[fd]` mapping. When epoll fires, check if fd is in the FV table before dispatching to regular TCP handler.
- **FV lookup cap (16):** Each lookup can open up to alpha=3 concurrent TCP connections per round. Worst case: 16 × 3 = 48 extra fds. Well within `NODUS_TCP_MAX_CONNS` (1024). Prevents DDoS amplification.
- **Republish connections are fire-and-forget via epoll:** Non-blocking connect → send frame → close. Capped at `NODUS_REPUBLISH_MAX_FDS` (64). **Zero blocking** — the main loop never stalls during republish, even if all peers are unreachable. **`dht_republish_conn_alloc()` MUST memcpy frame data** — the caller frees the original frame after queueing all peers; without memcpy this is use-after-free.
- **Dedup on storage:** Atomic single-SQL `nodus_storage_put_if_newer()` checks seq + hash tiebreaker on equal seq. Prevents data loss AND split-brain divergence.
- **Routing table has no auto-expiry:** Dead nodes must be explicitly removed via `nodus_routing_remove()` from `nodus_pbft_tick()`. Additionally, `find_closest` MUST filter entries with `last_seen` older than `NODUS_ROUTING_STALE_SEC` (1 hour). Bucket refresh (every 15 min) keeps live entries fresh — this is MANDATORY for 20+ nodes where most peers are not in config.
- **Dead peer recovery:** PING handler must call `nodus_pbft_on_pong()` to allow DEAD peers to recover. Without this, once DEAD → permanent (FIX 0c).
- **Republish MUST be batched with bookmark pagination** — 5 values per tick, `SELECT ... WHERE key_hash > ? LIMIT 5` per batch (finalized immediately). Do NOT hold a persistent `sqlite3_stmt` cursor open across ticks — it blocks WAL checkpointing and causes unbounded WAL growth.
- **Client PUT MUST use `put_if_newer()`** — No exceptions. A client reconnecting to a different server can replay stale seq values. Unconditional storage on the client PUT path creates permanent divergence that republish amplifies.
- **No worker threads eliminated:** Session generation counter, pipe/eventfd IPC, separate SQLite connection, crash monitoring, shutdown drain, queue management — all removed. Async epoll state machines provide the same functionality with ~100 fewer lines of code and zero concurrency bugs.
