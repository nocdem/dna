# Design: Separate Inter-Node TCP Port

**Date:** 2026-03-12
**Status:** APPROVED
**Audit Findings Addressed:** CRIT-1, HIGH-1, HIGH-2, HIGH-10, partial CRIT-4/5

## Problem

Nodus TCP port 4001 mixes client traffic (authenticated) with inter-node traffic (unauthenticated). This enables:
- CRIT-1: Auth bypass via T1 fallback in `dispatch_t2()`
- HIGH-1: Any TCP client can send `sv`, `fv`, `p_sync`, `ch_rep` without authentication
- HIGH-2: Global static rate limits for `sv`/`fv` allow single connection to block all replication
- HIGH-10: Unauthenticated Dilithium5 verification CPU exhaustion

## Solution

Add a second TCP port (4002) dedicated to inter-node communication. Port 4001 becomes client-only.

```
Before:
  UDP 4000 ─── Tier 1 (Kademlia)
  TCP 4001 ─── Clients + inter-node (MIXED, pre-auth messages allowed)

After:
  UDP 4000 ─── Tier 1 (Kademlia, unchanged)
  TCP 4001 ─── Client-only (hello/auth required, all pre-auth inter-node messages REJECTED)
  TCP 4002 ─── Inter-node only (sv, fv, p_sync, ch_rep, w_*)
```

## Architecture

- Second `nodus_tcp_t` instance sharing the same epoll fd — single event loop, no threading changes
- Separate connection pools (1024 each) — inter-node can't starve client slots
- Inter-node port gets its own dispatch function (`dispatch_inter`) — clean separation
- Config field: `peer_port` (default 4002)
- PBFT peer struct `tcp_port` field used for inter-node connections (already exists)

## Changes Required

### nodus_types.h
- Add `NODUS_DEFAULT_PEER_PORT 4002`

### nodus_server.h
- Add `uint16_t peer_port` to `nodus_server_config_t`
- Add `nodus_tcp_t inter_tcp` to `nodus_server_t`

### nodus_server.c
- **Init:** Initialize `srv->inter_tcp` with shared epoll, listen on `config->peer_port`
- **New function:** `dispatch_inter()` — handles sv, fv, p_sync, ch_rep, w_* with per-session rate limiting
- **Modified:** `dispatch_t2()` — delete entire pre-auth inter-node block (lines 1587-1779). Only allow hello/auth before authentication.
- **Modified:** Main loop — add `nodus_tcp_poll(&srv->inter_tcp, 0)` (shares epoll, so just processes events)
- **Modified:** `send_frame_to_peer()` — no change needed (already takes host+port as args)
- **Cleanup:** `nodus_server_close()` — close `inter_tcp`

### dispatch_inter() design
```c
static void dispatch_inter(nodus_tcp_conn_t *conn, const uint8_t *data, size_t len) {
    // Try T2 decode first for: p_sync, ch_rep, fv, w_*
    // Try T1 decode for: sv (STORE_VALUE replication)
    // Rate limit ALL message types per-session
    // NO hello/auth/put/get/listen — those are client-only
}
```

### dispatch_t2() simplified pre-auth
```c
if (!sess->authenticated) {
    if (method == "hello") { handle_hello(); return; }
    if (method == "auth")  { handle_auth();  return; }
    send_error("not_authenticated");
    return;
}
```

### nodus_presence.c
- No change needed — already connects to `peer.tcp_port` which will be the peer port

### nodus_replication.c
- No change needed — `send_to_peer()` already uses peer's configured port

### nodus.conf
- Add `peer_port = 4002`

### Config parsing (nodus-server main)
- Parse `peer_port` from config file

## Rate Limiting in dispatch_inter()

Move sv/fv from global static variables to per-session fields (matching p_sync/ch_rep pattern):

```c
// Add to nodus_session_t:
uint64_t sv_window_start;
int      sv_count;
uint64_t fv_window_start;
int      fv_count;
```

## Deployment (Rolling Upgrade)

1. Deploy new binary with `peer_port = 4002` on each node
2. Nodes connect to peers using configured peer port
3. Once all 6 nodes upgraded, firewall 4002 to cluster IPs only
4. Port 4001 is now client-only

## What This Does NOT Fix

- UDP Tier 1 remains unauthenticated (CRIT-2/CRIT-3) — separate project
- No mutual Dilithium5 auth between peers on new port — can layer on later
- Other audit findings (contact spoofing, memory safety, etc.) are separate fixes

## Findings Resolution

| Finding | Status |
|---------|--------|
| CRIT-1 (T1 fallback auth bypass) | FIXED — fallback deleted from client port |
| HIGH-1 (no inter-node TCP auth) | MITIGATED — firewallable on separate port |
| HIGH-2 (global sv/fv rate limits) | FIXED — per-session in dispatch_inter |
| HIGH-10 (unauth Dilithium5 CPU) | MITIGATED — only reachable on peer port |
| CRIT-4/5 (connection exhaustion) | MITIGATED — separate pools |
