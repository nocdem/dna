# Witness State Sync — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** When a witness node misses BFT rounds (restart, network issue, slow mesh), it detects the gap and replays missed blocks from a peer — restoring chain consistency, UTXO set, and nullifiers.

**Architecture:** Block-by-block sync over T3 protocol on TCP 4004. Each block is independently requested, verified (prev_hash + commit certificates), and replayed via `do_commit_db()`. Triggered at startup, epoch tick (60s), and on missed round detection.

**Tech Stack:** C, CBOR over T3 wire protocol, SQLite, SHA3-512, Dilithium5

---

## Problem Statement

Proven by EU-6 divergence (2026-04-07): node missed block 2 during cluster restart. Result:
- Chain diverged (3 blocks vs 4, different tx_hashes at same heights)
- Genesis UTXO still unspent = double-spend vulnerability
- Supply invariant broken (199.7T vs 100T genesis)
- Permanent divergence — no self-healing

## Wire Protocol

Two new T3 message types (IDs 12-13):

### w_sync_req (ID 12)

Client → Peer: "Send me block at height N"

```
method: "w_sync_req"
args: {
    "h": uint          // requested block height (0 = genesis)
}
```

### w_sync_rsp (ID 13)

Peer → Client: full block data + TX + commit certificates

```
method: "w_sync_rsp"
args: {
    "found": bool,
    "h":     uint,                    // block height
    "txh":   bstr(64),                // tx_hash
    "tty":   uint,                    // tx_type (0=genesis, 1=spend)
    "txd":   bstr,                    // full serialized TX data
    "txl":   uint,                    // tx_len
    "ts":    uint,                    // block timestamp
    "pid":   bstr(32),                // proposer_id
    "ph":    bstr(64),                // prev_hash
    "nlc":   uint,                    // nullifier_count
    "nls":   [bstr(64), ...],         // nullifier array
    "cer":   [{                       // commit certificates
        "vid": bstr(32),              // voter_id
        "sig": bstr(4627)             // Dilithium5 signature
    }, ...]
}
```

Size estimate per block: ~10KB TX + ~33KB certs (7 * 4659) = ~43KB. Well within 128KB limit.

## w_ident Extension

Add block height and UTXO checksum to w_ident args:

```
w_ident args (existing + new):
{
    "wid":  bstr(32),       // witness_id (existing)
    "pk":   bstr(2592),     // pubkey (existing)
    "addr": tstr,           // address (existing)
    "bh":   uint,           // NEW: local block height
    "uck":  bstr(64)        // NEW: UTXO set checksum (SHA3-512)
}
```

UTXO checksum: `nodus_witness_utxo_checksum()` already exists — hashes all nullifiers in sorted order. Computed after each BFT commit.

## Sync Flow

### Phase 1: Fork Detection

Before syncing blocks, check if local chain agrees with peer's chain. Compare block hashes starting from genesis:

```
Node A (height=3, diverged)          Node B (height=4, correct)
    |                                    |
    |--- w_ident (bh=3) --------------->|
    |<-- w_ident (bh=4) ----------------|
    |                                    |
    |  detect: local=3, peer=4, need sync
    |                                    |
    |--- w_sync_req {h=1} ------------->|  (verify genesis matches)
    |<-- w_sync_rsp {block 1} ---------|
    |  local block 1 tx_hash == peer block 1 tx_hash? YES ✓
    |                                    |
    |--- w_sync_req {h=2} ------------->|  (check block 2)
    |<-- w_sync_rsp {block 2} ---------|
    |  local block 2 tx_hash == peer block 2 tx_hash?
    |  LOCAL: D8CE64D4  PEER: 5A1ED7A1
    |  DIFFERENT → FORK DETECTED at height 2
    |                                    |
    |  Peer chain longer (4 > 3) + valid certs
    |  → DROP local witness DB
    |  → Full resync from genesis
```

### Phase 2: DB Rebuild on Fork

When fork is detected:

```
1. Close witness DB
2. Delete witness_<chain_id>.db file
3. Set w->db = NULL (back to pre-genesis state)
4. Start full sync from height 0 (genesis)
```

This is safe because:
- `do_commit_db()` with genesis TX + `w->db == NULL` automatically creates new DB
- All blocks replayed in order rebuild complete state
- prev_hash chain verified at each step

### Phase 3: Block-by-Block Sync (Normal Case)

When no fork detected (just missing blocks):

```
Node A (height=1)                    Node B (height=4)
    |                                    |
    |--- w_ident (bh=1) --------------->|
    |<-- w_ident (bh=4) ----------------|
    |                                    |
    |  Fork check: block 1 matches ✓
    |  No fork, just missing blocks 2,3,4
    |                                    |
    |--- w_sync_req {h=2} ------------->|
    |<-- w_sync_rsp {block 2 data} -----|
    |  verify prev_hash(2) chains from block 1 ✓
    |  verify 2f+1 commit certs ✓
    |  do_commit_db() replay ✓
    |  cert_store() ✓
    |                                    |
    |--- w_sync_req {h=3} ------------->|
    |<-- w_sync_rsp {block 3 data} -----|
    |  verify ✓, replay ✓
    |                                    |
    |--- w_sync_req {h=4} ------------->|
    |<-- w_sync_rsp {block 4 data} -----|
    |  verify ✓, replay ✓
    |                                    |
    |  SYNCED: height=4, chain consistent
```

### Full Sync Algorithm

```
sync_from_peer(peer):
    local_height = nodus_witness_block_height(w)
    peer_height  = peer->remote_height

    if peer_height <= local_height:
        return  // nothing to sync

    // Phase 1: Fork detection (compare existing blocks)
    fork_height = -1
    for h = 1 to min(local_height, peer_height):
        local_block = nodus_witness_block_get(w, h)
        peer_block  = w_sync_req(peer, h)
        verify_certs(peer_block)  // always verify even during fork check

        if local_block.tx_hash != peer_block.tx_hash:
            fork_height = h
            break

    // Phase 2: Handle fork
    if fork_height > 0:
        log("FORK DETECTED at height %d, rebuilding", fork_height)
        close_and_delete_witness_db(w)
        // Now local_height = 0, resync everything
        local_height = 0

    // Phase 3: Sync missing blocks
    for h = (local_height + 1) to peer_height:
        block = w_sync_req(peer, h)

        // Verify prev_hash
        if h == 1:
            assert block.prev_hash == all_zeros  // genesis
        else:
            expected = compute_prev_hash(local_latest_block)
            assert block.prev_hash == expected

        // Verify commit certificates (2f+1 Dilithium5 sigs)
        verified = verify_certs(block)
        if h == 1 (genesis):
            assert verified == n_witnesses  // unanimous
        else:
            assert verified >= 2f+1  // quorum

        // Replay
        do_commit_db(w, block.tx_hash, block.tx_type,
                     block.nullifiers, block.nullifier_count,
                     block.total_supply, block.timestamp,
                     block.proposer_id, block.tx_data, block.tx_len)

        // Store commit certificates
        cert_store(w, h, block.certs, block.cert_count)

    log("SYNCED: height %d → %d", original_height, peer_height)
```

### Genesis Sync (height=0)

Node with no witness DB (pre-genesis state):

```
1. Receive w_ident with bh>0 and chain_id from peer
2. Send w_sync_req {h=0} (special: request genesis)
3. Receive w_sync_rsp with genesis TX data
4. do_commit_db() handles everything:
   - Derives chain_id from genesis fingerprint + tx_hash
   - Creates witness_<chain_id>.db
   - Records genesis_state + supply
   - Creates UTXO set from genesis outputs
   - Creates block 1 with prev_hash=zeros
5. Store commit certificates
6. Continue with w_sync_req {h=1}, {h=2}, ...
```

Note: `do_commit_db()` already handles genesis DB creation (nodus_witness_bft.c:518-553). No new genesis logic needed.

## Verification (Per Block)

Each synced block goes through 3 checks before replay:

### 1. prev_hash Chain Continuity
```c
// Compute expected prev_hash from our latest block
expected = SHA3-512(local_latest.height || local_latest.tx_hash ||
                    local_latest.timestamp || local_latest.prev_hash)
// Compare with synced block's prev_hash
if (memcmp(synced_block.prev_hash, expected, 64) != 0)
    → REJECT, try another peer
// Genesis exception: prev_hash must be all zeros
```

### 2. Commit Certificate Verification
```c
for each cert in synced_block.certs:
    // Find voter's pubkey from roster
    voter_pubkey = roster_lookup(cert.voter_id)
    if (!voter_pubkey) → skip (unknown voter)

    // Verify Dilithium5 signature over (tx_hash || voter_id || timestamp)
    signed_data = tx_hash || cert.voter_id || block.timestamp
    if (dilithium5_verify(cert.sig, signed_data, voter_pubkey) != 0)
        → REJECT

// Check quorum: verified_count >= 2f+1
// Genesis: verified_count must equal n_witnesses (unanimous)
```

### 3. TX Hash Integrity
```c
// Recompute tx_hash from TX data fields
computed_hash = SHA3-512(tx_data structured fields)
if (memcmp(computed_hash, synced_block.tx_hash, 64) != 0)
    → REJECT
```

## Trigger Points

### 1. Startup (immediate)
```
nodus_witness_peer_init() or first epoch tick:
  - After w_ident exchange, compare heights
  - If local < peer → sync
```

### 2. Epoch Tick (every 60s)
```
nodus_witness_tick() → epoch handler:
  - Check all identified peers' heights
  - If local < max(peer heights) → sync from highest peer
  - If local == peer heights but checksums differ:
      - Count peers per checksum
      - If majority (>= quorum) disagrees with us → we forked
      - Drop DB + resync from majority peer
```

### 3. Missed Round Detection
```
nodus_witness_bft_handle_commit():
  - Received COMMIT for round N but local height is N-2
  - Missing block(s) between → trigger sync before processing
```

## Sync State (witness struct additions)

```c
// In nodus_witness_t:
struct {
    bool        syncing;              // sync in progress
    int         sync_peer_idx;        // which peer we're syncing from
    uint64_t    sync_target_height;   // peer's height
    uint64_t    sync_current_height;  // next block to request
    uint64_t    last_sync_attempt;    // rate limit
} sync_state;

// In nodus_witness_peer_t:
uint64_t    remote_height;            // peer's block height from w_ident
uint8_t     remote_checksum[64];      // peer's UTXO checksum from w_ident
```

## Rate Limiting & Safety

- Max 1 sync session at a time (syncing flag)
- Min 30s between sync attempts to same peer
- Sync does NOT block BFT rounds — if new COMMIT arrives during sync, process it normally (height will jump, sync fills the gap)
- If peer sends invalid data (bad prev_hash, bad certs) → abort, try next peer
- Max 1000 blocks per sync session (prevent infinite loop)

## Error Handling

| Scenario | Action |
|----------|--------|
| Peer disconnects mid-sync | Resume with another peer from last synced height |
| prev_hash mismatch (no fork) | Reject block, try another peer |
| Cert verification fails | Reject block, try another peer |
| All peers fail | Wait for next epoch tick retry |
| Sync during active BFT round | Defer sync until IDLE phase |
| Block already exists locally | Skip, move to next height |
| **Fork detected** | Drop witness DB, full resync from genesis |
| Fork at genesis (different chain) | Reject — chain_id mismatch, do not sync |
| DB delete fails | Abort sync, log error, retry next epoch |

## Fork Detection Rules

### Case 1: Peer has more blocks (peer_height > local_height)

```
Compare block hashes from genesis forward.
First mismatch = fork point.

1. Genesis (height 1) tx_hash MUST match
   → If different: chain_id mismatch, different chain, ABORT

2. Any other block tx_hash differs:
   → Fork detected
   → Peer chain is LONGER + has VALID commit certificates
   → Drop local DB, full resync from genesis
```

### Case 2: Same height, different state (peer_height == local_height)

```
Detected via UTXO checksum comparison in w_ident:

1. Collect checksums from all identified peers
2. Group by checksum → find majority (quorum)
3. If local checksum matches majority → we are correct, no action
4. If local checksum differs from majority:
   → We are on wrong fork
   → Drop local DB, full resync from a majority peer
5. If no clear majority → do nothing, wait for more peers
```

Example (EU-6 scenario with same height):
```
EU-1: uck=076e6598  ─┐
EU-2: uck=076e6598   │ majority (6 nodes)
EU-3: uck=076e6598   │
EU-4: uck=076e6598   │
EU-5: uck=076e6598   │
US-1: uck=076e6598  ─┘
EU-6: uck=a3f21b44  ← minority (1 node) → DROP DB + RESYNC
```

Quorum threshold: `2f+1` (same as BFT). If `>= quorum` peers agree on a checksum and local differs → local is wrong.

### Case 3: Pre-genesis node (no witness DB)

```
Peer has bh > 0 and valid chain_id → full sync from genesis.
No fork detection needed — just download everything.
```

### Fork rebuild procedure

```
1. Close witness DB connection (sqlite3_close)
2. Delete witness_<chain_id>.db file
3. Set w->db = NULL (back to pre-genesis state)
4. Clear local chain_id
5. Full sync from genesis (height 0)
   → do_commit_db() recreates DB automatically
6. If resync fails midway: node is in pre-genesis state
   → Next epoch tick will retry
```

## Files

### New Files
```
nodus/src/witness/nodus_witness_sync.c   — sync logic (request, verify, replay)
nodus/src/witness/nodus_witness_sync.h   — sync function declarations
```

### Modified Files
```
nodus/src/protocol/nodus_tier3.h         — w_sync_req/rsp types (ID 12,13), structs
nodus/src/protocol/nodus_tier3.c         — encode/decode for sync messages
nodus/src/witness/nodus_witness.h        — sync_state in witness struct
nodus/src/witness/nodus_witness.c        — sync trigger in epoch tick, dispatch
nodus/src/witness/nodus_witness_peer.h   — remote_height in peer struct
nodus/src/witness/nodus_witness_peer.c   — w_ident height field, sync trigger on ident
nodus/src/witness/nodus_witness_handlers.c — handle w_sync_req (server side)
nodus/CMakeLists.txt                     — add sync.c to build
```

### Untouched
```
nodus_witness_bft.c      — do_commit_db() used as-is for replay
nodus_witness_db.c       — all DB functions used as-is
nodus_server.c           — T3 dispatch already routes to witness module
```

## do_commit_db Replay Safety

Verified by code review:
- Pure DB function — no broadcasts, no client responses
- Handles genesis specially (chain_id derive + DB create)
- Calls nodus_witness_block_add (prev_hash computed automatically)
- cert_store called separately (not inside do_commit_db)
- Atomic SQLite transactions with rollback on failure
- **Safe to call for replay without any modifications**

## Test Plan

1. **Unit test:** Encode/decode w_sync_req and w_sync_rsp
2. **Integration test:** Stop one node, send TX, restart node, verify it syncs
3. **Genesis sync test:** New node joins cluster, syncs from zero
4. **Bad data test:** Peer sends block with wrong prev_hash → verify rejection
5. **Concurrent test:** Sync while BFT round in progress → no conflicts
