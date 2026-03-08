# Nodus v5 — Critical Replication Issues

**Date:** 2026-03-08 | **Status:** RESOLVED (2026-03-08) | **Severity:** Was CRITICAL

> **All replication issues resolved.** Implementation completed across 6 phases. See `REPLICATION_DESIGN.md` (status: IMPLEMENTED) for details. 22 unit tests pass (6 new). Issues 9, 10, 13, 16, 19 deferred by design (see notes below).

---

## Summary

Nodus v5 DHT value replication has fundamental architectural issues. The system uses PBFT consensus peer list for replication instead of Kademlia routing. Tier 1 Kademlia infrastructure (FIND_VALUE, STORE, routing table) exists and works but is not connected to the Tier 2 client-facing operations.

---

## Issues Currently Broken (3 nodes) — ALL RESOLVED

### ISSUE 1: GET does not forward to other nodes — RESOLVED (Phase 4a/4b)
- **Location:** `nodus_server.c:361-381` (`handle_t2_get`)
- **Problem:** When a client GETs a key and the server doesn't have it locally, it returns empty. It does NOT use Tier 1 FIND_VALUE to ask other nodes.
- **Impact:** If client connects to a node that doesn't have the data, lookup fails. This caused the "bios not found" bug.
- **Fix:** When local storage returns empty, use Tier 1 FIND_VALUE (already implemented at line 906-922) to query other nodes.
- **Resolution:** `handle_t2_get()` now calls `dht_find_value_start()` on local miss. Async epoll state machine performs iterative Kademlia lookup via TCP `fv` handler. Up to 16 concurrent lookups, 3 rounds of alpha=3 queries each.

### ISSUE 2: No periodic republish — RESOLVED (Phase 5)
- **Location:** None — does not exist
- **Problem:** Values are replicated once at PUT time. If replication fails (network, pool exhaustion, node down), there is no mechanism to retry beyond hinted handoff (24h TTL). After 24h, data is permanently lost from unreachable nodes.
- **Impact:** Any transient failure lasting >24h causes permanent data loss on affected nodes.
- **Fix:** Standard Kademlia periodic republish — every N minutes, republish local values to responsible nodes.
- **Resolution:** `dht_republish()` fetches batches of values via `nodus_storage_fetch_batch()` bookmark pagination, sends via `dht_republish_send_async()` non-blocking TCP. `NODUS_REPUBLISH_SEC` = 3600s, `NODUS_REPUBLISH_BATCH` = 5 per tick, max 64 concurrent fds. Zero blocking in main loop.

### ISSUE 3: Hinted handoff expires too aggressively — RESOLVED (Phase 2)
- **Location:** `nodus_storage.c` (hinted handoff table, 24h TTL)
- **Problem:** Hinted handoff entries expire after 24 hours. If target node is unreachable for >24h, the replication is abandoned.
- **Impact:** Combined with no republish, this means any extended outage causes permanent replication gaps.
- **Resolution:** TTL increased to 7 days (was 24h), matching value TTL. Entry cap removed. Schema migrated to node_id keying with `DROP TABLE` + recreate.

### ISSUE 4: replicate_value() uses PBFT peer list instead of Kademlia routing — RESOLVED (Phase 3)
- **Location:** `nodus_server.c:239-244` (`replicate_value()`)
- **Problem:** Replication target is `srv->pbft.peers[]` (PBFT consensus members from config), not Kademlia K-closest nodes. With 3 nodes and R=3 this happens to work (all peers = all nodes). Architecturally wrong.
- **Impact:** Works for 3 nodes. Breaks when scaling.
- **Resolution:** `replicate_value()` now uses `nodus_routing_find_closest()` to find K-closest nodes instead of PBFT peer broadcast.

---

## Issues That Break on Scale (>3 nodes) — ALL RESOLVED

### ISSUE 5: PBFT peer list is static (config only) — RESOLVED (Phase 3)
- **Location:** `nodus_server.c:1043-1050`
- **Problem:** PBFT peers come from `seed_nodes` in config file. Nodes discovered dynamically via Kademlia FIND_NODE are NOT added to PBFT peer list. `replicate_value()` only sends to PBFT peers.
- **Impact:** Any node not in config never receives replicated values.
- **Resolution:** Replication no longer uses PBFT peers. Uses Kademlia routing table which includes dynamically discovered nodes.

### ISSUE 6: replicate_value() broadcasts to ALL peers instead of K-closest — RESOLVED (Phase 3)
- **Location:** `nodus_server.c:239`
- **Problem:** Sends every value to every PBFT peer. No XOR distance calculation, no K-closest selection.
- **Impact:** With 100 nodes, every PUT creates 100 copies instead of K=8 copies. Does not scale.
- **Resolution:** `replicate_value()` uses `nodus_routing_find_closest()` to select K-closest nodes. Standard Kademlia behavior.

### ISSUE 7: Hinted handoff keyed by IP:Port, not node_id — RESOLVED (Phase 2)
- **Location:** `nodus_storage.c:76-79` (HINT_GET_SQL)
- **Problem:** Hints stored with peer IP:Port as key. If node changes IP, hints are never delivered.
- **Impact:** Node migration breaks hinted handoff delivery.
- **Resolution:** Hinted handoff schema migrated to node_id keying. `DROP TABLE` + recreate with `node_id` column and index.

### ISSUE 8: Hinted retry only checks PBFT peers — RESOLVED (Phase 6)
- **Location:** `nodus_server.c:272-281` (`dht_hinted_retry()`)
- **Problem:** Retry loop iterates `srv->pbft.peers[]` only. Hints for dynamically discovered nodes are never retried.
- **Impact:** Combined with Issue 5, dynamic nodes never get failed replications.
- **Resolution:** `dht_hinted_retry()` queries distinct node_ids from hinted handoff table, looks up current IP:port via routing table.

### ISSUE 9: Client does not retry GET on other servers — MITIGATED (server-side forwarding)
- **Location:** `nodus_client.c:739-744`
- **Problem:** Client connects to one server. If GET returns empty (NODUS_ERR_NOT_FOUND), it does NOT try other known servers. Failover only triggers on connection failure, not on empty results.
- **Impact:** Client misses data that exists on other nodes.
- **Resolution:** Server-side GET forwarding via async FIND_VALUE (Phase 4b) eliminates the need for client-side retry. When a server does not have the value locally, it queries other nodes on behalf of the client.

### ISSUE 10: No data sync on node join — RESOLVED (by periodic republish)
- **Location:** None — does not exist
- **Problem:** When a new node joins the cluster, it has no mechanism to pull existing values from peers. It starts empty and only receives new PUTs going forward.
- **Impact:** Joining node has incomplete data. Clients connecting to it get wrong results.
- **Resolution:** No special join sync needed. Periodic republish (Phase 5) naturally sends values to new nodes that are K-closest. New node receives values on next republish cycle (within 60 min). In the meantime, GET forwarding (Phase 4b) serves values from other nodes.

---

## Architectural Inconsistency — RESOLVED

| System | Replication Target | Correct? |
|--------|-------------------|----------|
| Channel replication | `nodus_hashring_responsible()` — R=3 nodes via consistent hash ring | CORRECT |
| DHT value replication | `nodus_routing_find_closest()` — K-closest via Kademlia routing table | CORRECT (was: `srv->pbft.peers[]` — WRONG) |
| Presence sync | `srv->pbft.peers[]` — ALL PBFT peers | DEBATABLE |

Channel replication correctly uses the hash ring to find R=3 responsible nodes. DHT value replication should use the same pattern (or Kademlia K-closest routing) but instead broadcasts to all PBFT consensus members.

---

## Previously Unused Code — NOW ACTIVE

| Component | Location | Status |
|-----------|----------|--------|
| FIND_VALUE (fv) handler | `nodus_server.c` | **NOW ACTIVE** — TCP `fv` handler in `dispatch_t2()` pre-auth section. Used by async FIND_VALUE state machine. |
| `nodus_routing_find_closest()` | `nodus_routing.c` | **NOW ACTIVE** — Used by `replicate_value()`, `dht_republish()`, and FIND_VALUE state machine. Filters stale entries (>1h). |
| `nodus_t1_find_value()` encoder | `nodus_tier1.c` | **NOW ACTIVE** — Used by `dht_find_value_start()` to build FV query frames. |
| `nodus_hashring_responsible()` | `nodus_hashring.c` | Unchanged — still used for channel replication only (correct, separate system). |

---

## Root Cause

PBFT was designed for DNAC witness BFT consensus (transaction validation, double-spend prevention). The PBFT peer list got reused as a convenience for DHT replication targets, bypassing the Kademlia routing that was built for this purpose. This worked for 3 nodes (R=3 = total nodes) but is architecturally wrong and will break on scale.

---

## Additional Issues Found (Deep Audit 2026-03-08) — RESOLVED

### ISSUE 11: `nodus_storage_cleanup()` never called — RESOLVED (Phase 5)
- **Location:** `nodus_storage.c:328` (function exists), `nodus_server.c` main loop (no call)
- **Problem:** Values never expire from DHT storage. Function exists but nobody calls it.
- **Impact:** Unbounded storage growth over time.
- **Resolution:** `dht_storage_cleanup()` called every `NODUS_CLEANUP_SEC` (3600s) from server main loop.

### ISSUE 12: FIND_VALUE over UDP silently drops large responses — RESOLVED (Phase 4a)
- **Location:** `nodus_udp.c:92` (`nodus_udp_send()` rejects >1400 bytes), `nodus_server.c:922`
- **Problem:** Values with Dilithium5 signatures are ~7.3KB. UDP MTU is 1400 bytes. `nodus_udp_send()` returns -1 silently, callers don't check.
- **Impact:** FIND_VALUE can never return values over UDP. TCP FIND_VALUE handler must be added.
- **Resolution:** TCP `fv` handler added to `dispatch_t2()` pre-auth section. Rate-limited at `NODUS_FV_MAX_PER_SEC` (100). UDP FIND_VALUE path remains for small values.

### ISSUE 13: Client SDK GET/PUT has no retry/failover — MITIGATED (server-side forwarding)
- **Location:** `nodus_client.c:717-748`
- **Problem:** GET returns `NODUS_ERR_NOT_FOUND` immediately, no retry on other servers. Multi-server config only used for initial connect.
- **Impact:** Client misses data that exists on other nodes. (Server-side GET forwarding in design mitigates this.)
- **Resolution:** Server-side GET forwarding (Phase 4b) eliminates need for client retry. Server queries other nodes on client's behalf via async FIND_VALUE.

### ISSUE 14: `nodus_storage_put()` has no seq check — data loss on republish (CRITICAL) — RESOLVED (Phase 1)
- **Location:** `nodus_storage.c:225-244` (PUT_SQL = INSERT OR REPLACE), `nodus_server.c:337,668,896`
- **Problem:** `INSERT OR REPLACE` unconditionally overwrites existing values. No `seq` comparison. A republish with seq=5 overwrites stored seq=10. Code comment says *"seq comparison in application layer"* (line 6) but **never implemented**.
- **Impact:** Periodic republish will cause data loss — older values overwrite newer ones.
- **Fix:** Add `nodus_storage_put_if_newer()` that checks existing seq before replacing.
- **Resolution:** `nodus_storage_put_if_newer()` implemented with atomic single-SQL that checks seq + SHA3-256 hash tiebreaker on equal seq. Used on ALL storage paths (client PUT, inter-node sv, republish).

### ISSUE 15: Dead nodes stay in routing table forever (CRITICAL) — RESOLVED (Phase 1)
- **Location:** `nodus_routing.c:114-170` (no last_seen filter), `nodus_pbft.c:169` (DEAD but no routing remove)
- **Problem:** `nodus_pbft_tick()` marks peers DEAD after 60s and removes from hashring, but does NOT call `nodus_routing_remove()`. `nodus_routing_find_closest()` returns ALL active entries regardless of `last_seen` age. With 3 nodes in 512 buckets, LRU eviction never triggers.
- **Impact:** `replicate_value()` after migration to routing table will send to dead nodes, causing 2s timeouts per node and hinted handoff accumulation.
- **Fix:** Call `nodus_routing_remove()` from `nodus_pbft_tick()` on DEAD transition + filter stale entries in `find_closest`.
- **Resolution:** Dead peer removal from routing table on PBFT DEAD transition (`nodus_pbft.c`). Stale entry filtering in `nodus_routing_find_closest()` with `NODUS_ROUTING_STALE_SEC` (3600s) threshold. Bucket refresh every 15 min keeps live entries fresh.

### ISSUE 16: No thread safety for planned worker thread — N/A (async design chosen)
- **Location:** `nodus_routing.h` (no mutex), `nodus_storage.h` (no mutex), `nodus_server.h` (no pthread)
- **Problem:** Server is completely single-threaded. Routing table, storage, and prepared statements have zero mutex protection. Worker thread for `dht_find_value()` would cause race conditions.
- **Impact:** Worker thread design requires: routing table snapshot at submit time, own SQLite connection, own buffers.
- **Resolution:** Worker thread design was rejected in favor of async epoll state machine (Phase 4b). Entire server remains single-threaded. No thread safety concerns.

### ISSUE 17: Dead peer recovery deadlock (CRITICAL — pre-existing bug) — RESOLVED (Phase 1)
- **Location:** `nodus_pbft.c:142` (DEAD skip), `nodus_server.c:843-858` (PING handler)
- **Problem:** `nodus_pbft_tick()` skips DEAD peers for PING (line 142: `if (state == DEAD) continue`). The UDP PING handler updates routing table but does NOT call `nodus_pbft_on_heartbeat()` or `nodus_pbft_on_pong()`. Once a peer is marked DEAD, recovery deadlock: we don't ping them → we never get their PONG → `nodus_pbft_on_pong()` never called → DEAD forever.
- **Impact:** Any transient network issue lasting >60s permanently kills a peer. Only manual restart of the dead node's nodus service can recover. **This is a live production bug.**
- **Fix:** Add `nodus_pbft_on_pong(&srv->pbft, &msg.node_id, from_ip, from_port)` to the PING handler. A received PING proves the peer is alive, same as a received PONG.
- **Resolution:** PING handler pong callback added in `nodus_server.c`. Received PING now calls `nodus_pbft_on_pong()` which handles DEAD→ALIVE recovery.

### ISSUE 18: Republish design blocks event loop (design bug) — RESOLVED (Phase 5)
- **Location:** `REPLICATION_DESIGN.md` (original dht_republish pseudocode)
- **Problem:** Original design iterated ALL values in one call, sending to K peers each via `send_frame_to_peer()` (2s blocking timeout). At 1000 values × 7 peers, worst case = 14,000s blocking. PBFT marks node DEAD after 60s.
- **Impact:** Would crash cluster on first republish cycle.
- **Fix:** Batched republish — process 10 values per main loop tick with persistent iterator state. Fixed in REPLICATION_DESIGN.md.
- **Resolution:** Non-blocking `dht_republish_send_async()` via separate epoll fd. Fire-and-forget TCP. `NODUS_REPUBLISH_BATCH` = 5 per tick. Zero blocking in main loop.

### ISSUE 19: Session ABA problem in worker thread design (design bug) — N/A (async design chosen)
- **Location:** `nodus_server.h:53-76` (no generation counter in `nodus_session_t`)
- **Problem:** Worker thread captures session slot index. While lookup runs (up to 6s), client disconnects and new client gets same slot. Worker response sent to wrong client. **Security issue — data leak.**
- **Fix:** Add `uint64_t generation` to `nodus_session_t`, increment on `session_clear()`. Worker captures (slot, generation), main thread validates before sending. Fixed in REPLICATION_DESIGN.md.
- **Resolution:** Worker thread design was rejected. Async epoll state machine runs in the single main thread — no ABA problem possible. Session slot checked for `conn != NULL` before sending result.

### ISSUE 20: Split-brain on equal seq (design bug) — RESOLVED (Phase 1)
- **Location:** `REPLICATION_DESIGN.md` (original put_if_newer pseudocode)
- **Problem:** Original `put_if_newer()` used `>=` check. Two servers with different data at seq=0 → neither accepts the other → permanent divergence. seq=0 is common (all tests use it, many values start at 0).
- **Fix:** Atomic single-SQL with hash tiebreaker: on equal seq, compare `SHA3-256(value_data)` — deterministic winner across all nodes. Fixed in REPLICATION_DESIGN.md.
- **Resolution:** `nodus_storage_put_if_newer()` uses atomic single-SQL with SHA3-256 hash tiebreaker on equal seq. Deterministic convergence across all nodes.

---

## Pool Leak Fix (2026-03-08, COMPLETED)

**Separate from replication architecture issues.** TCP connection pool leak in `nodus_presence.c` caused nodus-01 to reject all new connections, which prevented replication delivery. Fixed by adding `nodus_tcp_disconnect()` after p_sync send. Deployed to all 3 nodes.
