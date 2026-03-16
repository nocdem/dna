# DNAC BFT Dead Code Cleanup — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove all duplicate/dead BFT code from DNAC that now lives in nodus, and rewire discovery to use the nodus SDK directly.

**Architecture:** DNAC had a standalone witness system that was merged into nodus (v0.10.3). The consensus engine moved but the client-side types, serialization, roster management, and discovery code were left behind as dead weight. We delete `dnac/include/dnac/bft.h`, `dnac/src/bft/` entirely, `dnac/src/nodus/attestation.c`, rewrite `discovery.c` to use `nodus_client_dnac_roster()`, and update tests.

**Tech Stack:** C, nodus client SDK, CMake, ctest

**IMPORTANT:** This plan does NOT touch any files under `nodus/`. All changes are in `dnac/` only.

---

## What Gets Deleted

| File | Lines | Why dead |
|------|-------|----------|
| `dnac/include/dnac/bft.h` | 437 | All types duplicated in `nodus_types.h`. BFT context/callbacks unused. |
| `dnac/src/bft/serialize.c` | ~600 | Binary serialization — nodus uses CBOR. Only called by roster.c |
| `dnac/src/bft/roster.c` | ~590 | Roster management — now in `nodus/src/witness/`. Discovery rewritten. |
| `dnac/src/bft/replay.c` | ~100 | Server-side replay prevention — runs in nodus witness module. |
| `dnac/src/nodus/attestation.c` | ~800 | Binary spend request/response serialization — nodus uses CBOR. |
| `dnac/include/dnac/epoch.h` | 63 | Only included by `bft.h`. Discovery rewrite won't need it. |

**Total removed:** ~2,500+ lines of dead code

## What Gets Rewritten

| File | Change |
|------|--------|
| `dnac/src/nodus/discovery.c` | Replace `dnac_bft_client_discover_roster()` with `nodus_client_dnac_roster()` |
| `dnac/CMakeLists.txt` | Remove deleted source files |
| `dnac/tests/test_gaps.c` | Remove BFT serialize tests (they test deleted code) |

---

### Task 1: Delete `dnac/src/bft/` directory

**Files:**
- Delete: `dnac/src/bft/serialize.c`
- Delete: `dnac/src/bft/roster.c`
- Delete: `dnac/src/bft/replay.c`

**Step 1: Delete the files**

```bash
rm dnac/src/bft/serialize.c dnac/src/bft/roster.c dnac/src/bft/replay.c
rmdir dnac/src/bft
```

**Step 2: Remove from CMakeLists.txt**

In `dnac/CMakeLists.txt`, remove these three lines:
```
    src/bft/serialize.c
    src/bft/roster.c
    src/bft/replay.c
```

**Step 3: Build — expect errors**

Run: `cd /opt/dna/dnac/build && cmake .. && make -j$(nproc) 2>&1`
Expected: Errors from `discovery.c` (calls `dnac_bft_client_discover_roster`) and `test_gaps.c` (uses BFT types). These are fixed in Tasks 3-4.

**Do not commit yet.**

---

### Task 2: Delete `dnac/src/nodus/attestation.c` and `dnac/include/dnac/bft.h`

**Files:**
- Delete: `dnac/src/nodus/attestation.c`
- Delete: `dnac/include/dnac/bft.h`
- Delete: `dnac/include/dnac/epoch.h`

**Step 1: Delete**

```bash
rm dnac/src/nodus/attestation.c
rm dnac/include/dnac/bft.h
rm dnac/include/dnac/epoch.h
```

**Step 2: Remove attestation.c from CMakeLists.txt**

In `dnac/CMakeLists.txt`, remove:
```
    src/nodus/attestation.c
```

**Step 3: Check for other epoch.h users**

```bash
grep -r "dnac/epoch.h\|epoch\.h" dnac/include/ dnac/src/ --include="*.c" --include="*.h"
```

If `epoch.h` is used outside `bft.h`, keep it. If only `bft.h` includes it, it's safe to delete.

**Do not commit yet.**

---

### Task 3: Rewrite `dnac/src/nodus/discovery.c`

**Files:**
- Modify: `dnac/src/nodus/discovery.c`

**Step 1: Rewrite discovery.c to use nodus SDK directly**

Replace the entire file with:

```c
/**
 * @file discovery.c
 * @brief Witness server discovery via Nodus SDK
 *
 * Discovers witness servers by querying the roster through the
 * nodus client SDK (nodus_client_dnac_roster).
 *
 * v0.11.0: Removed file-based roster and DHT roster. Uses nodus SDK only.
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Nodus client SDK */
#include "nodus/nodus.h"

/* Nodus singleton access */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"

#define LOG_TAG "DNAC_DISCOVERY"

/* Cache configuration */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* Cached server list (shared with client.c) */
extern dnac_witness_info_t *g_witness_servers;
extern int g_witness_count;
extern uint64_t g_witness_cache_time;

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

static uint64_t get_time_sec(void) {
    return (uint64_t)time(NULL);
}

/**
 * Derive fingerprint from Dilithium5 public key
 * Fingerprint = hex(SHA3-512(pubkey))
 */
static void derive_fingerprint(const uint8_t *pubkey, size_t pk_len,
                                char *fingerprint_out) {
    uint8_t hash[64];
    qgp_sha3_512(pubkey, pk_len, hash);

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        fingerprint_out[i * 2]     = hex[(hash[i] >> 4) & 0xF];
        fingerprint_out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    fingerprint_out[128] = '\0';
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_discover(dnac_context_t *ctx,
                          dnac_witness_info_t **servers_out,
                          int *count_out) {
    if (!ctx || !servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    /* Check cache first */
    uint64_t now = get_time_sec();
    if (g_witness_servers && g_witness_count > 0 &&
        (now - g_witness_cache_time) < WITNESS_CACHE_TTL_SEC) {
        dnac_witness_info_t *cached = calloc(g_witness_count,
                                              sizeof(dnac_witness_info_t));
        if (cached) {
            memcpy(cached, g_witness_servers,
                   g_witness_count * sizeof(dnac_witness_info_t));
            *servers_out = cached;
            *count_out = g_witness_count;
            return DNAC_SUCCESS;
        }
    }

    /* Query roster via nodus SDK */
    nodus_singleton_lock();
    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        nodus_singleton_unlock();
        QGP_LOG_WARN(LOG_TAG, "No nodus connection for roster query");
        return DNAC_ERROR_NETWORK;
    }

    nodus_dnac_roster_result_t roster;
    memset(&roster, 0, sizeof(roster));
    int rc = nodus_client_dnac_roster(client, &roster);
    nodus_singleton_unlock();

    if (rc != 0 || roster.count <= 0) {
        QGP_LOG_WARN(LOG_TAG, "Roster query failed: rc=%d count=%d",
                     rc, roster.count);
        return DNAC_ERROR_NETWORK;
    }

    /* Convert roster entries to witness info array */
    dnac_witness_info_t *servers = calloc(roster.count,
                                          sizeof(dnac_witness_info_t));
    if (!servers) return DNAC_ERROR_OUT_OF_MEMORY;

    for (int i = 0; i < roster.count; i++) {
        nodus_dnac_roster_entry_t *entry = &roster.entries[i];
        dnac_witness_info_t *info = &servers[i];

        /* Convert witness_id to hex string */
        for (int j = 0; j < 32; j++) {
            snprintf(info->id + j * 2, 3, "%02x", entry->witness_id[j]);
        }

        strncpy(info->address, entry->address, sizeof(info->address) - 1);
        memcpy(info->pubkey, entry->pubkey, DNAC_PUBKEY_SIZE);
        info->is_available = entry->active;
        info->last_seen = now;

        /* Derive fingerprint from public key */
        derive_fingerprint(entry->pubkey, DNAC_PUBKEY_SIZE, info->fingerprint);
    }

    /* Update cache */
    if (g_witness_servers) free(g_witness_servers);
    g_witness_servers = calloc(roster.count, sizeof(dnac_witness_info_t));
    if (g_witness_servers) {
        memcpy(g_witness_servers, servers,
               roster.count * sizeof(dnac_witness_info_t));
        g_witness_count = roster.count;
        g_witness_cache_time = now;
    }

    *servers_out = servers;
    *count_out = roster.count;

    QGP_LOG_INFO(LOG_TAG, "Discovered %d witnesses (roster v%u)",
                 roster.count, roster.version);
    return DNAC_SUCCESS;
}

int dnac_get_witness_list(dnac_context_t *ctx,
                          dnac_witness_info_t **servers,
                          int *count) {
    return dnac_witness_discover(ctx, servers, count);
}

void dnac_free_witness_list(dnac_witness_info_t *servers, int count) {
    (void)count;
    free(servers);
}

int dnac_check_nullifier(dnac_context_t *ctx,
                         const uint8_t *nullifier,
                         bool *is_spent) {
    return dnac_witness_check_nullifier(ctx, nullifier, is_spent);
}
```

**Key changes:**
- Removed `#include "dnac/bft.h"` — no longer needed
- Removed `dnac_bft_client_discover_roster()` call — replaced with `nodus_client_dnac_roster()`
- Removed OpenSSL `EVP_*` for fingerprint — replaced with `qgp_sha3_512()` (already in shared crypto)
- Uses `nodus_dnac_roster_result_t` directly from nodus SDK

**Step 2: Check if OpenSSL dependency can be reduced**

The old `discovery.c` included `<openssl/evp.h>` just for SHA3-512 fingerprint derivation. New version uses `qgp_sha3_512()` from shared crypto. Check if anything else in DNAC still uses OpenSSL — if not, we can remove the dependency later.

---

### Task 4: Update `dnac/tests/test_gaps.c`

**Files:**
- Modify: `dnac/tests/test_gaps.c`

**Step 1: Remove `#include "dnac/bft.h"` and BFT-dependent tests**

The following tests use `dnac_bft_proposal_t`, `dnac_bft_vote_msg_t`, `dnac_bft_proposal_serialize()`, etc. — all from deleted code:

- `test_proposal_sign_verify` (line 67) — uses `dnac_bft_proposal_t`
- `test_proposal_reject_tampered` (line 120) — uses `dnac_bft_proposal_t`
- `test_proposal_reject_wrong_key` (line 155) — uses `dnac_bft_proposal_t`
- `test_vote_sign_verify` (line 182) — uses `dnac_bft_vote_msg_t`
- `test_overflow_size_calculation` (line 229) — uses `dnac_bft_proposal_t`, `dnac_bft_proposal_serialize`
- `test_bounds_check_prevents_overread` (line 261) — uses `dnac_bft_proposal_t`, `dnac_bft_proposal_deserialize`

These test **BFT serialize/sign** operations that now live in nodus. Remove them.

**Keep these tests** (they don't use `bft.h`):
- `test_zero_pubkey_rejected` (line 292) — uses `qgp_dsa87_verify`
- `test_garbage_pubkey_rejected` (line 313)
- `test_valid_pubkey_invalid_sig_rejected` (line 332)
- `test_replay_same_nonce_rejected` (line 362) — **USES `is_replay()` from replay.c — REMOVE**
- `test_replay_different_nonce_accepted` (line 381) — **REMOVE**
- `test_replay_old_timestamp_rejected` (line 401) — **REMOVE**
- `test_replay_future_timestamp_rejected` (line 418) — **REMOVE**
- `test_memo_roundtrip` (line 441) — uses `dnac_transaction_t` — **KEEP** if no bft.h deps
- `test_memo_empty_works` (line 482) — **KEEP**
- `test_memo_max_length` (line 514) — **KEEP**
- `test_memo_binary_data` (line 550) — **KEEP**

**Step 2: Remove the `#include "dnac/bft.h"` line**

**Step 3: Remove the `DNAC_BFT_SUCCESS` reference** — replace with `DNAC_SUCCESS` or `0` as appropriate.

**Step 4: Update the `main()` function** to remove deleted test registrations.

**Step 5: Build and test**

Run: `cd /opt/dna/dnac/build && cmake .. && make -j$(nproc) && ctest --output-on-failure`
Expected: Clean build, remaining tests pass.

---

### Task 5: Remove `dnac/src/nodus/nodus.h` serialization declarations

**Files:**
- Modify: `dnac/include/dnac/nodus.h`

**Step 1: Check which serialization functions in nodus.h are still used**

The following are declared in `nodus.h` and implemented in `attestation.c` (which we deleted):
- `dnac_spend_request_serialize` / `_deserialize`
- `dnac_spend_response_serialize` / `_deserialize`

Check if `tcp_client.c` or `client.c` still call these:

```bash
grep -n "spend_request_serialize\|spend_response_serialize\|spend_request_deserialize\|spend_response_deserialize" dnac/src/nodus/tcp_client.c dnac/src/nodus/client.c
```

If NOT called → remove declarations from `nodus.h`.

Also check all the other `_serialize`/`_deserialize` declarations in `nodus.h` (ledger, supply, utxo, nullifier, range, announcement). If their implementations were in `attestation.c` and nothing calls them, remove the declarations too.

**Step 2: Remove `dnac_witness_announcement_t` struct and serialization** if unused.

**Step 3: Build**

Run: `cd /opt/dna/dnac/build && cmake .. && make -j$(nproc) 2>&1`
Expected: Clean build, zero warnings.

---

### Task 6: Clean build verification + commit

**Files:**
- All modified files from Tasks 1-5

**Step 1: Full clean build**

```bash
cd /opt/dna/dnac/build && cmake .. && make -j$(nproc) 2>&1
```
Expected: Zero errors, zero warnings.

**Step 2: Run tests**

```bash
cd /opt/dna/dnac/build && ctest --output-on-failure
```
Expected: All remaining tests pass.

**Step 3: Commit**

```bash
git add -A dnac/
git commit -m "refactor(dnac): remove dead BFT code — use nodus SDK types directly (v0.11.1)

- Delete dnac/src/bft/ (serialize.c, roster.c, replay.c) — ~1300 lines
- Delete dnac/include/dnac/bft.h — ~437 lines of duplicate types
- Delete dnac/include/dnac/epoch.h — only used by bft.h
- Delete dnac/src/nodus/attestation.c — ~800 lines of dead binary serialization
- Rewrite discovery.c — use nodus_client_dnac_roster() instead of file/DHT roster
- Update test_gaps.c — remove tests for deleted serialize/replay code
- Clean up nodus.h declarations for deleted attestation functions

All witness types now come from nodus/include/nodus/nodus_types.h.
No nodus code was modified."
```

---

### Task 7: Update docs

**Files:**
- Modify: `dnac/README.md`
- Modify: `dnac/CLAUDE.md`
- Modify: `dnac/include/dnac/version.h`

**Step 1: Update README.md**

- Change "3-node witness cluster" / "2-of-3" references to "dynamic witness roster" / "PBFT quorum (2f+1)"
- Update directory structure (remove `src/bft/`)
- Update version to v0.11.1

**Step 2: Update CLAUDE.md**

- Remove references to `bft/serialize.c`, `bft/roster.c`, `bft/replay.c`
- Update directory structure
- Update version

**Step 3: Bump version**

In `dnac/include/dnac/version.h`, bump to v0.11.1.

**Step 4: Commit**

```bash
git add dnac/README.md dnac/CLAUDE.md dnac/include/dnac/version.h
git commit -m "docs(dnac): update for BFT cleanup, dynamic witness roster (v0.11.1)"
```
