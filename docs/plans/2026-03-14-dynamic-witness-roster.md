# Dynamic Witness Roster Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace static witness roster (config file + `witness_enabled` flag + `witness_address`) with automatic witness participation for all online nodus nodes, with roster dynamically built from TCP 4002 inter-node connections.

**Architecture:** Every nodus node is automatically a witness. Every 60 seconds (epoch tick), the roster is rebuilt from active TCP 4002 connections. Pending roster is swapped to active when BFT round phase is IDLE. If fewer than 5 nodes are connected, consensus is disabled.

**Tech Stack:** C, PBFT consensus, TCP 4002 inter-node transport, CBOR wire protocol

**Design doc:** `nodus/docs/DYNAMIC_WITNESS_DESIGN.md` (APPROVED)

---

## Overview of Changes

**Remove:**
- `witness_enabled` from config struct and JSON parsing
- `witness_address` from config struct and JSON parsing
- `witness_roster_file` from config struct and JSON parsing
- `nodus_witness_roster_load_file()` function
- Static roster file loading from `nodus_witness_peer_init()`

**Add:**
- `NODUS_T3_MIN_WITNESSES = 5` constant
- Pending roster fields in `nodus_witness_t`
- `nodus_witness_rebuild_roster_from_peers()` — builds roster from TCP 4002 connections
- Epoch tick logic in `nodus_witness_tick()` — 60s roster refresh cycle
- `nodus_witness_bft_consensus_active()` helper
- Witness notification on `on_inter_disconnect`

**Modify:**
- `NODUS_T3_MAX_WITNESSES` from 16 to 128
- `nodus_witness_init()` — remove roster file, build from inter_tcp
- `nodus_server_init()` — always init witness (remove `if enabled` guard)
- `on_inter_disconnect()` — notify witness module
- `nodus_witness_peer_send_ident()` — derive address from server config instead of `witness_address`
- `nodus_witness_bft_config_init()` — disable consensus if n < 5

---

### Task 1: Update constants in `nodus_types.h`

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h:102`

**Step 1: Change MAX_WITNESSES and add MIN_WITNESSES**

```c
// Change line 102:
#define NODUS_T3_MAX_WITNESSES      128
// Add after it:
#define NODUS_T3_MIN_WITNESSES      5
```

**Step 2: Build to verify no array size issues**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) 2>&1 | tail -20`
Expected: Clean build (vote arrays in round_state use MAX_WITNESSES — now 128)

Note: This increases `nodus_witness_round_state_t` size significantly because `prevotes[128]` and `precommits[128]` each contain `NODUS_SIG_BYTES` (4627 bytes). Total round_state grows to ~1.2MB. This is fine — it's a single allocation in the witness context, not per-connection.

**Step 3: Commit**

```bash
git add nodus/include/nodus/nodus_types.h
git commit -m "feat(witness): increase MAX_WITNESSES to 128, add MIN_WITNESSES=5"
```

---

### Task 2: Strip config struct — remove `enabled`, `address`, `roster_file`

**Files:**
- Modify: `nodus/src/witness/nodus_witness.h:34-38`
- Modify: `nodus/tools/nodus-server.c:93-101`
- Modify: `nodus/src/server/nodus_server.h:52` (comment update)

**Step 1: Simplify `nodus_witness_config_t`**

In `nodus/src/witness/nodus_witness.h`, replace the config struct:

```c
typedef struct {
    /* No config needed — all nodes are automatic witnesses.
     * Struct kept for future extensibility (e.g. stake threshold). */
    uint8_t  _reserved;
} nodus_witness_config_t;
```

**Step 2: Remove JSON parsing for witness config**

In `nodus/tools/nodus-server.c`, remove lines 93-101 (the entire `/* Witness module config */` block):

```c
    /* Witness module config — removed: all nodes are automatic witnesses */
```

**Step 3: Build — expect errors in nodus_witness.c and nodus_witness_peer.c**

Run: `cd /opt/dna/nodus/build && make -j$(nproc) 2>&1`
Expected: Compilation errors referencing `config.enabled`, `config.address`, `config.roster_file`. These will be fixed in subsequent tasks.

**Do not commit yet** — this task creates intentional compilation errors fixed in Tasks 3-5.

---

### Task 3: Add pending roster fields to `nodus_witness_t`

**Files:**
- Modify: `nodus/src/witness/nodus_witness.h:167-218`

**Step 1: Add epoch and pending roster fields**

In `nodus_witness_t` struct, add after the `bft_config` field (line ~194):

```c
    /* Dynamic roster — epoch-based refresh */
    uint64_t    last_epoch;                     /* Timestamp of last roster rebuild */
    nodus_witness_roster_t  pending_roster;     /* Built each epoch from inter_tcp */
    nodus_witness_bft_config_t pending_bft_config;
    bool        pending_roster_ready;           /* Pending roster waiting to swap */
```

**Step 2: No build yet** — still has errors from Task 2.

---

### Task 4: Implement `nodus_witness_rebuild_roster_from_peers()`

**Files:**
- Modify: `nodus/src/witness/nodus_witness_peer.h` — add function declaration
- Modify: `nodus/src/witness/nodus_witness_peer.c` — add implementation

**Step 1: Add declaration to header**

In `nodus_witness_peer.h`, add in the Utilities section:

```c
/** Rebuild roster from TCP 4002 connected+identified peers + self. */
int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out_roster);
```

**Step 2: Remove `nodus_witness_roster_load_file` declaration**

Remove from `nodus_witness_peer.h`:
```c
/** Load roster entries from file (one IP:port per line). */
int nodus_witness_roster_load_file(nodus_witness_t *w,
                                   const char *filename);
```

**Step 3: Implement the function**

In `nodus_witness_peer.c`, replace `nodus_witness_roster_load_file()` with:

```c
/* ── Build roster from TCP 4002 connections ──────────────────────── */

int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out) {
    if (!w || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* Add self first */
    nodus_witness_roster_entry_t *self = &out->witnesses[0];
    memcpy(self->witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(self->pubkey, w->server->identity.pk.bytes, NODUS_PK_BYTES);
    /* Address: use server's external_ip (or bind_ip) + peer_port */
    const char *ip = w->server->config.external_ip[0]
                   ? w->server->config.external_ip
                   : w->server->config.bind_ip;
    snprintf(self->address, sizeof(self->address), "%s:%u",
             ip, w->server->config.peer_port);
    self->active = true;
    out->n_witnesses = 1;

    /* Add all connected+identified inter_tcp peers */
    nodus_tcp_t *itcp = &w->server->inter_tcp;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS && out->n_witnesses < NODUS_T3_MAX_WITNESSES; i++) {
        nodus_tcp_conn_t *conn = itcp->pool[i];
        if (!conn) continue;
        if (conn->state != NODUS_CONN_CONNECTED) continue;
        if (!conn->peer_id_set) continue;

        /* Duplicate check by peer_id (first 32 bytes = witness_id) */
        bool dup = false;
        for (uint32_t j = 0; j < out->n_witnesses; j++) {
            if (memcmp(out->witnesses[j].witness_id,
                       conn->peer_id.bytes, NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        nodus_witness_roster_entry_t *entry =
            &out->witnesses[out->n_witnesses];
        memcpy(entry->witness_id, conn->peer_id.bytes, NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry->pubkey, conn->peer_pk.bytes, NODUS_PK_BYTES);
        snprintf(entry->address, sizeof(entry->address), "%s:%u",
                 conn->ip, conn->port);
        entry->active = true;
        out->n_witnesses++;
    }

    /* Sort deterministically by witness_id for consistent leader election */
    if (out->n_witnesses > 1) {
        qsort(out->witnesses, out->n_witnesses,
              sizeof(nodus_witness_roster_entry_t), roster_cmp);
    }

    out->version = w->roster.version + 1;
    return (int)out->n_witnesses;
}
```

**IMPORTANT:** The existing `roster_cmp` in `nodus_witness.c` sorts by address. For dynamic roster, sorting by `witness_id` (deterministic, derived from pubkey) is more reliable than by IP string. Update `roster_cmp` in `nodus_witness.c`:

```c
static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return memcmp(ea->witness_id, eb->witness_id, NODUS_T3_WITNESS_ID_LEN);
}
```

Also add a matching static `roster_cmp` in `nodus_witness_peer.c` (or move to a shared location — but keeping it static in both files is simpler and avoids header pollution):

```c
static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return memcmp(ea->witness_id, eb->witness_id, NODUS_T3_WITNESS_ID_LEN);
}
```

**Step 4: Remove the `nodus_witness_roster_load_file()` implementation**

Delete the entire function body (~80 lines, lines 164-247 in `nodus_witness_peer.c`).

**Step 5: Update `nodus_witness_peer_init()` — remove roster file loading**

Replace:
```c
int nodus_witness_peer_init(nodus_witness_t *w) {
    if (!w) return -1;

    /* Load roster from file if configured */
    if (w->config.roster_file[0]) {
        nodus_witness_roster_load_file(w, w->config.roster_file);
    }

    /* Connect to all roster peers (except self) */
    ...
```

With:
```c
int nodus_witness_peer_init(nodus_witness_t *w) {
    if (!w) return -1;

    /* Dynamic roster — initial build from current inter_tcp connections.
     * At init time, inter_tcp connections may not be established yet.
     * Full roster will be built on first epoch tick (60s). */
    nodus_witness_rebuild_roster_from_peers(w, &w->roster);
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

    /* Update my_index in roster */
    w->my_index = -1;
    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        if (memcmp(w->roster.witnesses[i].witness_id,
                   w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
            w->my_index = (int)i;
            break;
        }
    }

    fprintf(stderr, "%s: peer mesh init (roster=%u witnesses, my_index=%d)\n",
            LOG_TAG, w->roster.n_witnesses, w->my_index);
    return 0;
}
```

---

### Task 5: Update `nodus_witness_init()` and `nodus_witness_tick()` — epoch logic

**Files:**
- Modify: `nodus/src/witness/nodus_witness.c`

**Step 1: Simplify `witness_init_roster()`**

Replace the existing `witness_init_roster()` function:

```c
static void witness_init_roster(nodus_witness_t *witness) {
    memset(&witness->roster, 0, sizeof(witness->roster));
    witness->roster.version = 1;
    witness->my_index = -1;
    witness->last_epoch = 0;
    witness->pending_roster_ready = false;
}
```

**Step 2: Update `nodus_witness_init()` — remove config.address references**

In the init function, the log line references `config->address` — change to:

```c
    fprintf(stderr, "%s: initialized (roster=%d witnesses, my_index=%d)\n",
            LOG_TAG, witness->roster.n_witnesses, witness->my_index);
```

**Step 3: Update `nodus_witness_peer_send_ident()` — derive address from server config**

In `nodus_witness_peer.c`, the `nodus_witness_peer_send_ident()` function uses `w->config.address` for the ident message. Replace:

```c
    snprintf(msg.ident.address, sizeof(msg.ident.address),
             "%s", w->config.address);
```

With:

```c
    const char *ip = w->server->config.external_ip[0]
                   ? w->server->config.external_ip
                   : w->server->config.bind_ip;
    snprintf(msg.ident.address, sizeof(msg.ident.address),
             "%s:%u", ip, w->server->config.peer_port);
```

**Step 4: Add epoch tick to `nodus_witness_tick()`**

Replace the existing `nodus_witness_tick()`:

```c
#define WITNESS_EPOCH_SECS  60

void nodus_witness_tick(nodus_witness_t *witness) {
    if (!witness || !witness->running) return;

    /* BFT timeout checks */
    nodus_witness_bft_check_timeout(witness);

    /* Peer mesh: reconnection, IDENT exchange */
    nodus_witness_peer_tick(witness);

    /* Epoch tick: rebuild roster every 60s */
    uint64_t now = nodus_time_now();
    if (now - witness->last_epoch >= WITNESS_EPOCH_SECS) {
        witness->last_epoch = now;

        /* Build new roster from current TCP 4002 connections */
        nodus_witness_rebuild_roster_from_peers(witness, &witness->pending_roster);
        nodus_witness_bft_config_init(&witness->pending_bft_config,
                                       witness->pending_roster.n_witnesses);

        /* Check if roster actually changed */
        bool changed = (witness->pending_roster.n_witnesses != witness->roster.n_witnesses);
        if (!changed) {
            for (uint32_t i = 0; i < witness->roster.n_witnesses; i++) {
                if (memcmp(witness->roster.witnesses[i].witness_id,
                           witness->pending_roster.witnesses[i].witness_id,
                           NODUS_T3_WITNESS_ID_LEN) != 0) {
                    changed = true;
                    break;
                }
            }
        }

        if (!changed) {
            /* No change — skip swap */
            return;
        }

        /* Try to swap immediately if IDLE */
        if (witness->round_state.phase == NODUS_W_PHASE_IDLE) {
            /* Swap roster */
            memcpy(&witness->roster, &witness->pending_roster,
                   sizeof(nodus_witness_roster_t));
            memcpy(&witness->bft_config, &witness->pending_bft_config,
                   sizeof(nodus_witness_bft_config_t));
            witness->pending_roster_ready = false;

            /* Recalculate my_index */
            witness->my_index = nodus_witness_roster_find(&witness->roster,
                                                            witness->my_id);

            fprintf(stderr, "WITNESS: epoch roster swap: %u witnesses, "
                    "quorum=%u, my_index=%d\n",
                    witness->roster.n_witnesses,
                    witness->bft_config.quorum,
                    witness->my_index);
        } else {
            /* Round active — defer swap to next IDLE */
            witness->pending_roster_ready = true;
            fprintf(stderr, "WITNESS: epoch roster pending (round active, "
                    "phase=%d, pending=%u witnesses)\n",
                    witness->round_state.phase,
                    witness->pending_roster.n_witnesses);
        }
    }

    /* Check if deferred roster swap can happen now */
    if (witness->pending_roster_ready &&
        witness->round_state.phase == NODUS_W_PHASE_IDLE) {
        memcpy(&witness->roster, &witness->pending_roster,
               sizeof(nodus_witness_roster_t));
        memcpy(&witness->bft_config, &witness->pending_bft_config,
               sizeof(nodus_witness_bft_config_t));
        witness->pending_roster_ready = false;

        witness->my_index = nodus_witness_roster_find(&witness->roster,
                                                        witness->my_id);

        fprintf(stderr, "WITNESS: deferred roster swap: %u witnesses, "
                "quorum=%u, my_index=%d\n",
                witness->roster.n_witnesses,
                witness->bft_config.quorum,
                witness->my_index);
    }
}
```

**Step 5: Build**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) 2>&1`
Expected: Clean build

**Step 6: Commit**

```bash
git add nodus/src/witness/ nodus/tools/nodus-server.c nodus/src/server/nodus_server.h
git commit -m "feat(witness): dynamic roster from TCP 4002 connections (epoch 60s)"
```

---

### Task 6: Update `nodus_witness_bft_config_init()` — disable below MIN_WITNESSES

**Files:**
- Modify: `nodus/src/witness/nodus_witness_bft.c:149-165`

**Step 1: Add MIN_WITNESSES check**

Replace the existing `nodus_witness_bft_config_init()`:

```c
void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n) {
    if (!cfg) return;

    cfg->n_witnesses = n;

    /* Below minimum — consensus disabled */
    if (n < NODUS_T3_MIN_WITNESSES) {
        cfg->f_tolerance = 0;
        cfg->quorum = 0;
        cfg->round_timeout_ms = 0;
        cfg->viewchg_timeout_ms = 0;
        cfg->max_view_changes = 0;
        return;
    }

    /* n = 3f + 1 → f = (n-1)/3 */
    cfg->f_tolerance = (n - 1) / 3;
    cfg->quorum = 2 * cfg->f_tolerance + 1;

    /* Timeouts */
    cfg->round_timeout_ms = 10000;
    cfg->viewchg_timeout_ms = 30000;
    cfg->max_view_changes = 3;
}
```

**Step 2: Add `nodus_witness_bft_consensus_active()` helper**

Add declaration to `nodus_witness_bft.h`:

```c
/** Returns true if consensus is active (enough witnesses for quorum). */
bool nodus_witness_bft_consensus_active(const nodus_witness_t *w);
```

Add implementation to `nodus_witness_bft.c`:

```c
bool nodus_witness_bft_consensus_active(const nodus_witness_t *w) {
    return w && w->bft_config.quorum > 0;
}
```

**Step 3: Gate consensus operations on `consensus_active`**

In `nodus_witness_bft_start_round()`, add at the top (after null checks):

```c
    if (!nodus_witness_bft_consensus_active(w)) {
        fprintf(stderr, "%s: consensus disabled (n=%u < %d)\n",
                LOG_TAG, w->bft_config.n_witnesses, NODUS_T3_MIN_WITNESSES);
        return -1;
    }
```

**Step 4: Build and test**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure`
Expected: Clean build, all tests pass

**Step 5: Commit**

```bash
git add nodus/src/witness/nodus_witness_bft.c nodus/src/witness/nodus_witness_bft.h
git commit -m "feat(witness): disable consensus below MIN_WITNESSES(5)"
```

---

### Task 7: Always init witness in server — remove `enabled` guard

**Files:**
- Modify: `nodus/src/server/nodus_server.c:2011-2022`
- Modify: `nodus/src/server/nodus_server.c:1404-1410`

**Step 1: Remove `if (config->witness.enabled)` guard**

In `nodus_server_init()`, replace:

```c
    /* Initialize witness module if enabled */
    if (config->witness.enabled) {
        srv->witness = calloc(1, sizeof(nodus_witness_t));
        ...
    }
```

With:

```c
    /* Initialize witness module (all nodes are automatic witnesses) */
    srv->witness = calloc(1, sizeof(nodus_witness_t));
    if (!srv->witness) {
        fprintf(stderr, "Failed to allocate witness context\n");
        return -1;
    }
    if (nodus_witness_init(srv->witness, srv, &config->witness) != 0) {
        fprintf(stderr, "Witness module init failed\n");
        free(srv->witness);
        srv->witness = NULL;
        /* Non-fatal — server can run without witness */
        fprintf(stderr, "WARNING: running without witness module\n");
    }
```

**Step 2: Notify witness on inter_tcp disconnect**

In `on_inter_disconnect()`, add witness notification:

```c
static void on_inter_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_server_t *srv = (nodus_server_t *)ctx;
    nodus_inter_session_t *sess = inter_session_for_conn(srv, conn);
    if (sess) {
        inter_session_clear(sess);
    }

    /* Notify witness module so it can clear peer references */
    if (srv->witness)
        nodus_witness_peer_conn_closed(srv->witness, conn);
}
```

**Step 3: Build and test**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure`
Expected: Clean build, all tests pass

**Step 4: Commit**

```bash
git add nodus/src/server/nodus_server.c
git commit -m "feat(witness): always init witness, notify on inter_tcp disconnect"
```

---

### Task 8: Update `nodus_witness_peer_tick()` — use inter_tcp for reconnection

**Files:**
- Modify: `nodus/src/witness/nodus_witness_peer.c`

**Step 1: Simplify peer tick**

The current `nodus_witness_peer_tick()` tries to reconnect peers using addresses from the roster. With dynamic roster, peers are discovered via TCP 4002 (which the server's Kademlia bootstrap already manages). The witness peer tick still needs to:

1. Send IDENT to newly connected peers
2. Update peer records when connections change state

But it no longer needs to initiate connections — that's Kademlia's job.

Replace `nodus_witness_peer_tick()`:

```c
void nodus_witness_peer_tick(nodus_witness_t *w) {
    if (!w || !w->running) return;

    /* Scan inter_tcp for connected peers that need IDENT exchange */
    nodus_tcp_t *itcp = &w->server->inter_tcp;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *conn = itcp->pool[i];
        if (!conn) continue;
        if (conn->state != NODUS_CONN_CONNECTED) continue;

        /* Check if we already track this connection as a peer */
        int pi = find_peer_by_conn(w, conn);
        if (pi >= 0) {
            /* Already tracked — send IDENT if not yet identified */
            if (!w->peers[pi].identified) {
                nodus_witness_peer_send_ident(w, conn);
                w->peers[pi].identified = true;
            }
            continue;
        }

        /* New connection — add to peers and send IDENT */
        if (w->peer_count < NODUS_T3_MAX_WITNESSES) {
            pi = w->peer_count++;
            memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
            w->peers[pi].conn = conn;
            w->peers[pi].last_attempt = nodus_time_now();

            nodus_witness_peer_send_ident(w, conn);
            w->peers[pi].identified = true;
        }
    }

    /* Clean up peers with dead connections */
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CLOSED) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }
}
```

**Step 2: Remove `connect_to_entry()` function** — no longer needed (Kademlia manages inter-node connections).

**Step 3: Remove `parse_address()` function** — no longer needed.

**Step 4: Clean up `find_peer_by_addr()` if unused** — check if still referenced. If `handle_ident` still uses it, keep it.

**Step 5: Update `handle_ident` — remove address-based lookup and `config.address` references**

In `nodus_witness_peer_handle_ident()`, remove the "skip if this is our own address" check that referenced `w->config.address`:

The function at lines 301-375 needs updates. The `config.address` reference at line 202-203 (in the roster file loader) is already deleted. Check if `handle_ident` references it — the existing code at line 309 checks `ident->address` against roster entries which is fine.

**Step 6: Build and test**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure`
Expected: Clean build, all tests pass

**Step 7: Commit**

```bash
git add nodus/src/witness/nodus_witness_peer.c
git commit -m "feat(witness): simplify peer tick — use inter_tcp, remove static connections"
```

---

### Task 9: Update config on all 6 production servers

**Files:**
- Remote: `/etc/nodus.conf` on all 6 servers

**Step 1: Remove witness config from nodus.conf on each server**

Remove these lines from `/etc/nodus.conf` on all 6 servers:
- `"witness_enabled": true,`
- `"witness_address": "...",`
- `"witness_roster_file": "...",` (where present)

Use SSH + cat heredoc (NOT sed) to rewrite the config.

**Step 2: Verify config is valid JSON**

```bash
for ip in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
    echo "=== $ip ===" && ssh root@$ip "python3 -c \"import json; json.load(open('/etc/nodus.conf'))\" && echo OK || echo INVALID"
done
```

**Do not deploy yet** — this is a config preparation step. Deploy happens in Task 11.

---

### Task 10: Update tests

**Files:**
- Modify: `nodus/tests/test_witness_verify.c` (if it references witness config)
- Potentially add: `nodus/tests/test_witness_roster.c`

**Step 1: Check existing test for config references**

Read `nodus/tests/test_witness_verify.c` and update any `witness_config.enabled = true` or similar.

**Step 2: Build and run all tests**

Run: `cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure`
Expected: All 22 tests pass

**Step 3: Commit**

```bash
git add nodus/tests/
git commit -m "test(witness): update tests for dynamic roster"
```

---

### Task 11: Version bump + build + deploy

**Files:**
- Modify: `nodus/include/nodus/nodus_types.h` (version bump)

**Step 1: Bump nodus version**

Check current version, bump MINOR (this is a significant feature change):

```bash
grep NODUS_VERSION nodus/include/nodus/nodus_types.h
```

**Step 2: Final build**

```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 3: Commit with [BUILD]**

```bash
git add -A
git commit -m "feat: Dynamic witness roster — automatic participation via TCP 4002 (Nodus vX.Y.Z) [BUILD]"
```

**Step 4: Deploy to all 6 servers**

```bash
for ip in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
    echo "=== Deploying to $ip ===" &&
    ssh root@$ip "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus" &&
    echo "OK" || echo "FAILED"
done
```

**Step 5: Verify all 6 nodes are running and forming witness roster**

```bash
for ip in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
    echo "=== $ip ===" && ssh root@$ip "journalctl -u nodus --no-pager -n 20 | grep -i witness"
done
```

Expected: Each node should log `WITNESS: epoch roster swap: 6 witnesses, quorum=3` within 60 seconds of startup.

---

### Task 12: Documentation update

**Files:**
- Modify: `nodus/docs/DYNAMIC_WITNESS_DESIGN.md` — update status to IMPLEMENTED
- Modify: `nodus/docs/ARCHITECTURE.md` — if witness section exists
- Modify: `messenger/docs/functions/` — if witness functions changed

**Step 1: Update design doc status**

Change: `**Status:** APPROVED — Not yet implemented`
To: `**Status:** IMPLEMENTED — Deployed to production`

**Step 2: Commit**

```bash
git add nodus/docs/
git commit -m "docs: mark dynamic witness roster as implemented"
```
