# Inter-Node Peer Authentication — Unfinished Feature

**Status:** INCOMPLETE — `require_peer_auth=true` breaks cluster inter-node communication. Must remain disabled in production until proper architectural fix.

**Last updated:** 2026-04-05
**Investigation:** nocdem + Claude

---

## Current State

Nodus has a `require_peer_auth` config flag intended to enforce Dilithium5
peer authentication on inter-node TCP ports (4002 and 4004).

| Port | Auth status |
|------|-------------|
| TCP 4004 (witness) | ✅ Works — witness module correctly sends hello/challenge/auth cycle |
| TCP 4002 (inter-node) | ❌ **Broken** — partial/bolt-on implementation |

When `require_peer_auth=true` is enabled cluster-wide on TCP 4002:

- Cluster p_sync (presence) fails
- DHT replication / hinted handoff fails
- VPN mesh circuit `ri_open` fails
- Cluster becomes functionally isolated per-node

## Root Cause

Inter-node TCP 4002 has **5+ independent sender code paths**, each
opening connections via `srv->inter_tcp` and writing data directly:

| Sender | File | Auth-aware? |
|--------|------|-------------|
| `presence_tick` (p_sync) | `src/server/nodus_presence.c:250` | ⚠️ Partial (fixed 2026-04-05, commit d04f5a52) |
| `dht_republish_send_async` | `src/server/nodus_server.c:588` | ❌ No — uses own socket, not inter_tcp pool |
| Hinted handoff retry | `src/server/nodus_server.c:378` | ❌ No |
| DHT STORE_VALUE forwards | `src/server/nodus_server.c:693` | ❌ No |
| VPN mesh `ri_open` (Faz 1) | `src/server/nodus_server.c:2005` | ❌ No |
| Batch forward | `src/server/nodus_server.c:1623` | ✅ Yes (own state machine) |

**The problem:** When `require_peer_auth=true`:

1. Peer receives ANY frame before hello → sends `NODUS_ERR_NOT_AUTHENTICATED` (47 bytes) → closes conn
2. Existing connections have **queued data** (hinted handoff, p_sync, replication) in `conn->wbuf` BEFORE hello is added
3. On connect, queued data flushes first → peer rejects → RST → reconnect → same cycle
4. Auth never completes, cluster inter-node becomes inert

## Why the Partial Fix Didn't Work

Commit d04f5a52 added:
- `dispatch_inter` handler for challenge/auth_ok/error (outgoing auth responses) — **correct**
- `presence_tick` sends hello before p_sync when auth required — **correct for presence alone**

But didn't touch:
- Other 4+ senders (they send data regardless of auth state)
- Existing conn write-buffer queueing order (stale data before hello)

Result: peer-side auth block DOES fire for hello, sends challenge. But by then
connection has already been reset because earlier unauth'd data caused peer
to drop it. Race between multiple senders on one shared conn.

## Proper Fix — Architecture

Auth must be **first-class connection state** with a single enforcement
point:

### 1. Connection auth state machine

Add to `nodus_tcp_conn_t` (`src/transport/nodus_tcp.h`):

```c
typedef enum {
    NODUS_CONN_AUTH_NONE = 0,        /* Freshly opened, hello not sent */
    NODUS_CONN_AUTH_HELLO_SENT,      /* Hello sent, awaiting challenge */
    NODUS_CONN_AUTH_RESPONDING,      /* Sending auth response */
    NODUS_CONN_AUTH_OK,              /* Fully authed, can send data */
    NODUS_CONN_AUTH_FAILED           /* Auth rejected, conn dead */
} nodus_conn_auth_state_t;

typedef struct nodus_tcp_conn {
    ...
    nodus_conn_auth_state_t auth_state;
    bool                    auth_required;   /* Set per-conn: true for inter_tcp */
    /* Queue of frames waiting for auth_state=OK */
    uint8_t                *pending_queue;
    size_t                  pending_queue_len;
    size_t                  pending_queue_cap;
    ...
} nodus_tcp_conn_t;
```

### 2. Gated send in `nodus_tcp_send`

```c
int nodus_tcp_send(nodus_tcp_conn_t *conn, const uint8_t *payload, size_t len) {
    if (conn->auth_required && conn->auth_state != NODUS_CONN_AUTH_OK) {
        /* Queue until auth completes */
        return pending_queue_append(conn, payload, len);
    }
    /* Normal immediate send */
    ...
}
```

### 3. Auto-hello on connect

When `nodus_tcp_connect(&srv->inter_tcp, ...)` creates a new outgoing conn:
- Mark `conn->auth_required = true`
- Set `conn->auth_state = NODUS_CONN_AUTH_NONE`
- Auto-send hello (bypassing queue gate)
- Transition to `NODUS_CONN_AUTH_HELLO_SENT`

### 4. Drain queue on auth_ok

When `auth_ok` received and `auth_state` → `NODUS_CONN_AUTH_OK`:
- Flush `pending_queue` into `conn->wbuf`
- Data was collected by senders, now released

### 5. Per-transport auth requirement

`nodus_tcp_t` gets a `bool auth_required` field set at init:
- `srv->inter_tcp`: auth_required=true when `srv->config.require_peer_auth=true`
- `srv->witness_tcp`: auth_required=true (already has own state machine — refactor to share)
- `srv->tcp` (client port 4001): uses existing session auth
- `srv->ch_server.tcp` (channel port 4003): has own auth

New conns inherit auth_required from their transport.

### 6. Timeout handling

If auth doesn't complete in N seconds (e.g. 10s), mark `auth_state = FAILED`,
disconnect, conn can be retried later.

## Scope Estimate

~300-500 lines across:
- `src/transport/nodus_tcp.{h,c}` — state machine, queue, gated send (~150 lines)
- `src/server/nodus_server.c` — auto-hello on inter_tcp connect, auth response handlers (~80 lines)
- `src/server/nodus_presence.c` — simplify, remove manual hello logic (~20 lines)
- Other senders — no changes needed (gated send transparent to callers)
- Unit tests — auth state machine, queue flush, timeout (~100 lines)
- Integration test — 2-node cluster with auth enabled (~100 lines)

## Alternative: Drop the Feature

**require_peer_auth on port 4002 may be unnecessary:**

1. **Data authenticity is already enforced**: every DHT value carries a
   Dilithium5 signature over its contents. Peer-level TCP auth is a
   belt-and-suspenders layer.
2. **Witness port (4004) already auths correctly** — that's where BFT
   integrity matters (DNAC consensus).
3. **Channel port (4003) has its own auth** (node_hello / node_auth).
4. **Practical risk**: attacker needs TCP 4002 network access. If they
   have that, signature enforcement already blocks meaningful harm.

Removing the flag:
- Delete `require_peer_auth` from config, struct, and auth blocks
- Witness port keeps its auth (hardcoded, no flag)
- Remove silent-drop fix since root cause (config-vs-code asymmetry) gone
- ~50 lines of code removal

## Recommendation

**Short term (done):** Keep `require_peer_auth=false` in production config.
Silent drop (commit ea17c86a) handles log spam. No security regression —
the feature never worked in production anyway.

**Medium term:** Decide policy:
- **Option A (proper fix):** Implement architecture above when Faz 2
  bandwidth allows. Enables transport-level peer auth on inter-node port.
  Has security value as defense-in-depth.
- **Option B (drop):** Remove the flag and its dead code paths. Simpler
  codebase. Relies on DHT value signatures for security.

Either is defensible. Status quo (code partially there, flag defaulting
false) is the worst — developer confusion, unused code, misleading comments.

## Related Commits

- `d04f5a52` nodus: inter-node outgoing auth handshake for presence_tick [BUILD]
  (partial fix, left in tree but ineffective alone)
- `ea17c86a` nodus: suppress log spam from misrouted T2 frames on witness port
  (pragmatic workaround, still needed)

## Test Plan for Proper Fix

1. Unit: auth state machine transitions
2. Unit: queue fill/flush/timeout
3. Integration: 2-node cluster with `require_peer_auth=true`, verify
   p_sync propagates and DHT replication works
4. Cluster rollout: enable on 1 node, verify peers can auth, rolling enable
5. Failure modes: test with one node having auth disabled (should reject)
6. Reconnect: kill conn during auth, verify recovery
