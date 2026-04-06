# Inter-Node Peer Authentication — FIXED

**Status:** FIXED (2026-04-06) — Deployed to production, `require_peer_auth=true` on all 7 nodes.

**Last updated:** 2026-04-06
**Implementation:** nocdem + Claude

---

## What Was Done

### Architecture: Auth State Machine + Gated Send

Added `nodus_conn_auth_state_t` to `nodus_tcp_conn_t` with states:
`NONE → HELLO_SENT → AUTH_OK / FAILED`

Single enforcement point in `nodus_tcp_send`: when `auth_required=true` and
`auth_state != AUTH_OK`, frames are queued in a pending buffer (5MB cap).
On `AUTH_OK`, pending buffer is flushed to wbuf. Auth bypass via
`nodus_tcp_send_raw` for hello/challenge/auth frames only.

### Key Design Decisions

1. **auth_required inherited at connect time** (not on_connect callback) —
   prevents race where callers write to wbuf before hello is queued.

2. **DHT replication migrated to inter_tcp pool** — removed fire-and-forget
   raw sockets (`dht_republish_send_async`, `rp_epoll_fd`, `dht_republish_conn_t`).
   All replication now goes through persistent connections with auth gate.
   Performance improvement: no per-send TCP handshake overhead.

3. **Witness port (TCP 4004) NOT covered** — witness uses T3 protocol with
   its own `w_ident` auth cycle. T2 hello would be rejected by T3 decoder.
   Witness auth is independent and already works.

4. **EPOLLOUT re-set after on_connect** — `handle_connect_complete` re-checks
   wbuf after on_connect callback to ensure EPOLLOUT is set for hello flush.

### Changes

| File | Change |
|------|--------|
| `src/transport/nodus_tcp.h` | Auth state enum, pending queue fields, `auth_required`/`auth_ctx` on transport |
| `src/transport/nodus_tcp.c` | Gated send, pending queue (append/flush/free), `send_raw`, EPOLLOUT fix, auth_required inherit at connect |
| `src/server/nodus_server.c` | Auto-hello on_inter_connect, dispatch_inter auth_state transitions, republish pool migration, auth timeout sweep, witness cleanup |
| `src/server/nodus_server.h` | Removed `dht_republish_conn_t`, `rp_epoll_fd`, `pending_fds` |
| `src/server/nodus_presence.c` | Simplified — removed manual hello/auth checks |
| `src/witness/nodus_witness.c` | Removed silent-drop T2 workaround |
| `tests/test_inter_auth.c` | 6 unit tests for auth state machine |

### Production Deployment

- All 7 nodes: `require_peer_auth=true` in `/etc/nodus.conf`
- P_SYNC: broadcasting to 6/6 routing peers
- No auth timeouts on inter-node (TCP 4002)
- Messaging verified: nocdem → punk message delivery works
- DHT name lookup works (punk, chip, nocdem all resolvable)

### Related Commits

- `9fd879c7` nodus: auth state machine + gated send with pending queue
- `572cd548` nodus: add unit tests for inter-node auth state machine
- `e6d81721` nodus: auto-hello on inter-node connect + auth state transitions
- `85bffd44` nodus: migrate DHT replication to inter_tcp pool, remove fire-and-forget
- `848ae9f7` nodus: simplify presence auth + add 10s auth timeout sweep
- `1baa2494` nodus: witness auth refactor + remove silent-drop workaround
- `1a8b6461` fix: set EPOLLOUT after on_connect callback for auth hello flush
- `e24deca2` fix: inherit auth_required at connect time, not on_connect callback
- `bcf7c604` fix: witness port uses T3 w_ident auth, not T2 hello
