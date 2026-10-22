/**
 * Nodus — Witness Database Layer Implementation
 *
 * Consolidated SQLite operations for DNAC witness state.
 * Ported from dnac/src/witness/{nullifier,ledger,utxo_set,block}.c
 *
 * Key differences from DNAC originals:
 * - All functions take nodus_witness_t* instead of void* user_data
 * - Uses witness->db instead of global sqlite3* handles
 * - Single-zone (no zone.c abstraction)
 * - Uses fprintf logging (nodus convention)
 * - Simplified ledger (no Merkle tree — proof generation deferred)
 */

#include "witness/nodus_witness_db.h"
#include "nodus/nodus_chain_config.h"  /* Hard-Fork v1 schema migration */
#include "crypto/nodus_sign.h"
#include "dnac/transaction.h"          /* DNAC_TX_HEADER_SIZE (v0.17.1) */
#include "dnac/ledger_ids.h"           /* DNA_DOMAIN_CORE (P2P-PORT F6) */
#include "dnac/res_meter.h"            /* dna_ck_add_u64 (scan-v3 balance) */
#include "witness/nodus_witness_roots_v2.h"   /* NODUS_TREASURY_POOL_* (supply view) */
#include "witness/nodus_witness_v2_produce.h" /* nodus_witness_v2_tip_height (supply view) */
#include "witness/nodus_witness_v2_claims.h"  /* nodus_witness_v2_unclaimed_total (supply view) */
#include "witness/nodus_witness_addr_index.h" /* node-local address index tables */
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/utils/qgp_bench.h"         /* perf harness — ((void)0) in production */
#include "crypto/utils/qgp_log.h"           /* QGP_LOG_* (new code; legacy lines use fprintf) */

#define LOG_TAG "WITNESS_DB"

/*
 * Pinned migration failure log literal for rollback trigger #9.
 * Phase 1.1 will introduce a real schema migration path that invokes this
 * macro from every ALTER/CREATE step. The literal MIGRATION FAILURE is the
 * exact pattern operators grep journalctl for when deciding whether to roll
 * back a deploy. Keep this macro in sync with nodus/docs/DEPLOY_RUNBOOK.md.
 */
#define WITNESS_DB_MIGRATION_FATAL(step_name, rc)                                  \
    do {                                                                           \
        fprintf(stderr, "MIGRATION FAILURE: %s failed with sqlite error %d: %s\n", \
                (step_name), (int)(rc), sqlite3_errmsg(w->db));                    \
        abort();                                                                   \
    } while (0)

/* ── Nullifier operations ────────────────────────────────────────── */

bool nodus_witness_nullifier_exists(nodus_witness_t *w, const uint8_t *nullifier) {
    /* HIGH-10: Fail-closed — DB errors assume spent to prevent double-spend */
    if (!w || !w->db || !nullifier) return true;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM nullifiers WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: nullifier query prepare failed - assuming spent (fail-closed)\n",
                LOG_TAG);
        return true;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    int rc_step = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    /* HIGH-10: fail-closed — step errors (BUSY/LOCKED/IOERR/CORRUPT) assume spent */
    if (rc_step == SQLITE_ROW) return true;
    if (rc_step == SQLITE_DONE) return false;
    fprintf(stderr, "%s: nullifier step failed rc=%d - assuming spent (fail-closed)\n",
            LOG_TAG, rc_step);
    return true;
}

/* ── UTXO set operations ─────────────────────────────────────────── */

int nodus_witness_utxo_lookup_ex(nodus_witness_t *w, const uint8_t *nullifier,
                                   uint64_t *amount_out, char *owner_out,
                                   uint8_t *token_id_out,
                                   uint64_t *unlock_block_out) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT amount, owner, token_id, unlock_block FROM utxo_set "
        "WHERE nullifier = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (amount_out)
        *amount_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    if (owner_out) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) {
            strncpy(owner_out, fp, 128);
            owner_out[128] = '\0';
        }
    }

    if (token_id_out) {
        const void *tid = sqlite3_column_blob(stmt, 2);
        int tid_len = sqlite3_column_bytes(stmt, 2);
        if (tid && tid_len >= 64) {
            memcpy(token_id_out, tid, 64);
        } else {
            memset(token_id_out, 0, 64);  /* Default: native DNAC */
        }
    }

    if (unlock_block_out)
        *unlock_block_out = (uint64_t)sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out,
                                uint8_t *token_id_out) {
    return nodus_witness_utxo_lookup_ex(w, nullifier, amount_out, owner_out,
                                         token_id_out, NULL);
}

int nodus_witness_utxo_add_locked(nodus_witness_t *w, const uint8_t *nullifier,
                                    const char *owner, uint64_t amount,
                                    const uint8_t *tx_hash, uint32_t index,
                                    uint64_t block_height,
                                    const uint8_t *token_id,
                                    uint64_t unlock_block) {
    if (!w || !w->db || !nullifier || !owner || !tx_hash) return -1;

    /* Default to native DNAC (64 zero bytes) when token_id is NULL */
    static const uint8_t zero_token[64] = {0};
    const uint8_t *tid = token_id ? token_id : zero_token;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner, amount, token_id, tx_hash, output_index, "
        " block_height, created_at, unlock_block) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: utxo add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, tid, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, (int)index);
    sqlite3_bind_int64(stmt, 7, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 8, (int64_t)time(NULL));
    sqlite3_bind_int64(stmt, 9, (int64_t)unlock_block);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: utxo add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height,
                              const uint8_t *token_id) {
    /* Legacy path: unlock_block == 0 means UTXO is already spendable. */
    return nodus_witness_utxo_add_locked(w, nullifier, owner, amount,
                                          tx_hash, index, block_height,
                                          token_id, 0);
}

int nodus_witness_utxo_sum_by_token(nodus_witness_t *w,
                                       const uint8_t *token_id,
                                       uint64_t *sum_out) {
    if (!w || !w->db || !sum_out) return -1;

    /* NULL token_id or all-zeros = native DNAC */
    uint8_t zeros[64];
    memset(zeros, 0, sizeof(zeros));
    const uint8_t *tid = token_id ? token_id : zeros;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COALESCE(SUM(amount), 0) FROM utxo_set WHERE token_id = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tid, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *sum_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

/* Phase 10 / Task 10.2 — nodus_witness_utxo_checksum DELETED. Replaced
 * by the RFC 6962 nodus_witness_merkle_compute_utxo_root in
 * nodus_witness_merkle.c. */

/* P2P-PORT F6 (K3) — 1 = utxo_set has a domain_id column, 0 = not (a
 * pre-S5 shape — all CORE by the legacy definition, the same rule the
 * CORE invariant applies, nodus_witness_v2_claims.c
 * nodus_rt_core_invariant), -1 = fault. */
static int utxo_domain_col_present(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(utxo_set)", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "domain_id") == 0) found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    return found;
}

/* The dnac_utxo listing of one owner's CORE coins, at most max_entries
 * rows (the handler caps it at DNAC_MAX_UTXO_RESULTS). Sorted by amount
 * DESCENDING, equal amounts by nullifier ASCENDING (operator 2026-10-07,
 * nodus/BUGS.md "dnac_utxo 100'den fazla…"): an owner with more coins than
 * the cap used to receive an arbitrary subset (no ORDER BY before LIMIT),
 * so a freshly received large coin could be missing and the client
 * reported "insufficient coins". The cap now always keeps the LARGEST
 * coins, and the answer is the same rows in the same order on every call.
 * Node-local RPC answer only: no apply / consensus path calls this (its
 * callers are nodus_witness_handlers.c handle_dnac_utxo and
 * handle_dnac_msig_utxo, and tests/test_v2_gate.c). The only index on utxo_set(owner) is
 * idx_utxo_owner (nodus_witness.c), so SQLite reads the owner's rows by
 * that index and sorts them before the LIMIT — linear in that owner's
 * coin count. */
static int utxo_by_owner_impl(nodus_witness_t *w, const char *owner,
                              const uint8_t *token_id,
                              nodus_witness_utxo_entry_t *out,
                              int max_entries, int *count_out);

int nodus_witness_utxo_by_owner(nodus_witness_t *w, const char *owner,
                                   nodus_witness_utxo_entry_t *out,
                                   int max_entries, int *count_out) {
    return utxo_by_owner_impl(w, owner, NULL, out, max_entries, count_out);
}

/* The same listing restricted to ONE token (operator 2026-10-22, decision
 * 2026-10-22-testnet-test-tokens-faucet-dex.md, answer 3): `token_id` is
 * exactly 64 bytes, the all-zero id = native. Order, cap, domain filter
 * and the fail-closed step/reset check are nodus_witness_utxo_by_owner's
 * (one shared body). Node-local RPC answer only; no apply path calls it. */
int nodus_witness_utxo_by_owner_token(nodus_witness_t *w, const char *owner,
                                      const uint8_t token_id[64],
                                      nodus_witness_utxo_entry_t *out,
                                      int max_entries, int *count_out) {
    if (!token_id) return -1;
    return utxo_by_owner_impl(w, owner, token_id, out, max_entries,
                              count_out);
}

static int utxo_by_owner_impl(nodus_witness_t *w, const char *owner,
                              const uint8_t *token_id,
                              nodus_witness_utxo_entry_t *out,
                              int max_entries, int *count_out) {
    if (!w || !w->db || !owner || !out || !count_out || max_entries <= 0)
        return -1;

    *count_out = 0;

    /* P2P-PORT F6 (K3, decision 2026-09-26-witness-port-session.md) — the
     * dnac_utxo answer lists CORE-domain coins only, so a networked
     * builder (`nodus-cli v2-envelope stake` / `spend`) can never select
     * a coin its CORE leg cannot spend. Filtered HERE rather than carried
     * on the wire: no reply field, no struct change, so every libdna
     * caller (dnac/src/nodus/tcp_client.c, messenger/cli) compiles and
     * behaves unchanged — on a version-3 chain the CORE invariant already
     * refuses any non-CORE row (nodus_rt_core_invariant), so what they
     * receive today is exactly this set. */
    int has_dom = utxo_domain_col_present(w->db);
    if (has_dom < 0) return -1;

    /* The statement text is assembled from fixed fragments only (never
     * from request data); the optional token filter is one more bound
     * parameter, so a token id can never alter the SQL. */
    char sql[512];
    int sn = snprintf(sql, sizeof(sql),
        /* O15B §7: unlock_block is SELECTed so the caller can tell a
         * spendable coin from one still inside its post-UNSTAKE cooldown.
         * Omitting it is what let the wallet build transactions consensus
         * was guaranteed to reject (Rule D, nodus_witness_verify.c:730). */
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index, "
        "block_height, unlock_block "
        "FROM utxo_set WHERE owner = ?%s%s "
        "ORDER BY amount DESC, nullifier ASC LIMIT ?",
        has_dom ? " AND domain_id = ?" : "",
        token_id ? " AND token_id = ?" : "");
    if (sn < 0 || (size_t)sn >= sizeof(sql)) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    int bi = 1;
    sqlite3_bind_text(stmt, bi++, owner, -1, SQLITE_STATIC);
    if (has_dom)
        sqlite3_bind_int64(stmt, bi++, (sqlite3_int64)DNA_DOMAIN_CORE);
    if (token_id)
        sqlite3_bind_blob(stmt, bi++, token_id, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, bi, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_utxo_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *blob;
        int blen;

        blob = sqlite3_column_blob(stmt, 0);
        blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == NODUS_T3_NULLIFIER_LEN)
            memcpy(e->nullifier, blob, NODUS_T3_NULLIFIER_LEN);

        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) { strncpy(e->owner, fp, sizeof(e->owner) - 1); }

        e->amount = (uint64_t)sqlite3_column_int64(stmt, 2);

        blob = sqlite3_column_blob(stmt, 3);
        blen = sqlite3_column_bytes(stmt, 3);
        if (blob && blen == 64)
            memcpy(e->token_id, blob, 64);

        blob = sqlite3_column_blob(stmt, 4);
        blen = sqlite3_column_bytes(stmt, 4);
        if (blob && blen == NODUS_T3_TX_HASH_LEN)
            memcpy(e->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

        e->output_index = (uint32_t)sqlite3_column_int(stmt, 5);
        e->block_height = (uint64_t)sqlite3_column_int64(stmt, 6);

        /* O15B §7 — a NEGATIVE stored integer must never surface as a huge
         * u64. The same fail-closed discipline the native adapter row
         * readers already apply (nodus_witness_rt_native.c, review round R4):
         * a malformed row is reported as locked-forever rather than as
         * spendable, because the failure mode of guessing wrong here is a
         * transaction every validator rejects. */
        sqlite3_int64 ub = sqlite3_column_int64(stmt, 7);
        e->unlock_block = (ub < 0) ? UINT64_MAX : (uint64_t)ub;
        count++;
    }

    /* O15B §7 — a mid-scan SQLITE_IOERR/SQLITE_CORRUPT used to truncate the
     * result set and still return success, so a wallet could sync a PARTIAL
     * UTXO list and believe it complete. Fail closed instead: an incomplete
     * answer is not an answer. (nodus/CLAUDE.md, "A DB failure is never a
     * value" — the unguarded `while (sqlite3_step(...) == SQLITE_ROW)` shape.) */
    int step_rc = sqlite3_reset(stmt);
    sqlite3_finalize(stmt);
    if (step_rc != SQLITE_OK) {
        *count_out = 0;
        return -1;
    }

    *count_out = count;
    return 0;
}

/* scan-v3 — the dnac_balance source (contract: nodus_witness_db.h). The
 * sum is taken in C, not with SQL SUM(): SQLite's SUM coerces a numeric
 * TEXT value to an integer (sqlite3_value_numeric_type) and its overflow
 * behaviour has changed across releases, so the one checked addition this
 * answer rests on is dna_ck_add_u64 over rows whose types are verified
 * one by one. */
int nodus_witness_utxo_balance_by_owner(nodus_witness_t *w,
                                        const char *owner,
                                        uint64_t spend_h,
                                        nodus_witness_balance_entry_t *out,
                                        int max_entries, int *count_out) {
    if (!w || !w->db || !owner || !out || !count_out || max_entries <= 0)
        return -1;
    *count_out = 0;

    int has_dom = utxo_domain_col_present(w->db);
    if (has_dom < 0) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        has_dom
        ? "SELECT token_id, amount, unlock_block FROM utxo_set "
          "WHERE owner = ?1 AND domain_id = ?2 "
          "ORDER BY token_id, nullifier"
        : "SELECT token_id, amount, unlock_block FROM utxo_set "
          "WHERE owner = ?1 "
          "ORDER BY token_id, nullifier", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
    if (has_dom)
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)DNA_DOMAIN_CORE);

    int count = 0;
    int result = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const void *tid = sqlite3_column_blob(stmt, 0);
        if (sqlite3_column_type(stmt, 0) != SQLITE_BLOB || !tid ||
            sqlite3_column_bytes(stmt, 0) != 64 ||
            sqlite3_column_type(stmt, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(stmt, 2) != SQLITE_INTEGER) {
            result = -1;
            break;
        }
        sqlite3_int64 amount = sqlite3_column_int64(stmt, 1);
        sqlite3_int64 unlock = sqlite3_column_int64(stmt, 2);
        if (amount < 0 || unlock < 0) {           /* never a huge u64 */
            result = -1;
            break;
        }

        /* rows arrive grouped by token (ORDER BY token_id): a new token
         * opens the next entry */
        if (count == 0 || memcmp(out[count - 1].token_id, tid, 64) != 0) {
            if (count == max_entries) {
                result = NODUS_WITNESS_BALANCE_TOO_MANY;
                break;
            }
            memset(&out[count], 0, sizeof(out[count]));
            memcpy(out[count].token_id, tid, 64);
            count++;
        }
        nodus_witness_balance_entry_t *e = &out[count - 1];
        if (dna_ck_add_u64(e->total, (uint64_t)amount, &e->total) != 0 ||
            dna_ck_add_u64(e->coins, 1, &e->coins) != 0 ||
            ((uint64_t)unlock < spend_h &&
             dna_ck_add_u64(e->spendable, (uint64_t)amount,
                            &e->spendable) != 0)) {
            result = -1;
            break;
        }
    }
    if (result == 0 && rc != SQLITE_DONE) result = -1;   /* mid-scan fault */
    sqlite3_finalize(stmt);

    if (result != 0) {
        *count_out = 0;
        return result;
    }
    *count_out = count;
    return 0;
}

/* ── Block operations ────────────────────────────────────────────── */

/* R3 W4 — nodus_witness_block_add (the legacy commit path's block-row
 * writer) is DELETED with the closed consensus lane: it has zero
 * surviving callers — the version-3 apply path writes committed blocks
 * through its own engine (nodus_witness_v2_apply.c), not through this
 * legacy INSERT. block_get below stays for the committee lookback
 * (nodus_witness_committee.c), reading whatever this build's active
 * writer populated. The client query readers that sat beside it
 * (block_get_range, block_get_genesis — the dnac_block_range /
 * dnac_genesis RPCs) are deleted: no production writer fills `blocks`
 * on a version-3 chain, so those RPCs always answered empty. */

/* SELECT column order is: height, tx_root, tx_count, timestamp,
 * proposer_id, prev_hash, state_root. Schema v12 (Phase 1 / Task 1.2)
 * dropped the legacy tx_type column from blocks; per-TX type now lives
 * on committed_transactions. */
static int block_from_row(sqlite3_stmt *stmt, nodus_witness_block_t *out) {
    memset(out, 0, sizeof(*out));
    out->height = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_root, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_count = (uint32_t)sqlite3_column_int(stmt, 2);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 3);

    blob = sqlite3_column_blob(stmt, 4);
    blen = sqlite3_column_bytes(stmt, 4);
    if (blob && blen == NODUS_T3_WITNESS_ID_LEN)
        memcpy(out->proposer_id, blob, NODUS_T3_WITNESS_ID_LEN);

    blob = sqlite3_column_blob(stmt, 5);
    blen = sqlite3_column_bytes(stmt, 5);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->prev_hash, blob, NODUS_T3_TX_HASH_LEN);

    blob = sqlite3_column_blob(stmt, 6);
    blen = sqlite3_column_bytes(stmt, 6);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->state_root, blob, NODUS_T3_TX_HASH_LEN);

    return 0;
}

int nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_root, tx_count, timestamp, proposer_id, prev_hash, state_root "
        "FROM blocks WHERE height = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)height);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

/* O15O Faz 1 — the real query, with the fault kept distinguishable from
 * the value. Full contract on the declaration in nodus_witness_db.h.
 *
 * Both branches now separate the three sqlite outcomes the old body
 * collapsed into a bare 0:
 *   prepare failure                  -> FAULT (includes "no such table")
 *   step != SQLITE_ROW/SQLITE_DONE   -> FAULT (SQLITE_BUSY, _CORRUPT, …)
 *   SQLITE_ROW with a NULL / absent aggregate, or SQLITE_DONE
 *                                    -> SUCCESS, height 0 (empty chain)
 * SQLITE_DONE cannot occur for either statement — a bare aggregate always
 * yields exactly one row — but it is admitted rather than treated as a
 * fault so a future non-aggregate rewrite of either query degrades to
 * "empty" rather than to "halt". */
int nodus_witness_block_height_checked(nodus_witness_t *w, uint64_t *out) {
    if (!out) return -1;
    if (!w) return -1;

    /* ── A MISSING HANDLE IS NOT ALWAYS A FAULT — the O15L DG-1 matrix ──
     *
     * `w->db == NULL` does NOT mean one thing, and answering it with a
     * single verdict is wrong in one direction or the other. R3 W4 — this
     * split used to have a sibling drawn with the SAME 32-byte comparison
     * in nodus_witness_bft.c's load_committee_at_height, so the two gates
     * could not disagree about which row of the matrix a node was in; that
     * function is deleted with the closed consensus lane it served, and
     * this function's own two-armed answer stands on its own:
     *
     *   chain_id == 0, db == NULL   GENUINE PRE-GENESIS. There is no
     *                               chain, so height 0 is a TRUE COMMITTED
     *                               ANSWER — the same status
     *                               load_committee_at_height gives
     *                               "count 0" there, and the same status
     *                               an empty `blocks` table gives 0 below.
     *                               Every consumer is documented to take
     *                               the gossip-roster bootstrap in this
     *                               window (F17 A5).
     *   chain_id != 0, db == NULL   DG-1 ROW 2 — this node HOLDS a chain
     *                               and cannot read it. Here 0 is the
     *                               FAIL-OPEN this function exists to
     *                               remove: it is not an answer, it is the
     *                               ABSENCE of one, and consumers of that
     *                               0 went on to resolve a committee at
     *                               height 1.
     *
     * WHY THE FIRST ARM IS LOAD-BEARING, not a courtesy. A node running
     * the genesis round is in it BY CONSTRUCTION: the chain database did
     * not exist yet, so `db` is NULL until genesis commits. R3 W4 — the
     * BFT-era callers this arm protected (nodus_witness_bft_is_leader,
     * bft_start_round_internal, handle_propose / handle_commit refusing
     * the genesis proposal on a NULL db) are deleted with that lane; a
     * version-3 chain's genesis and committee resolution run through the
     * cometbft reactor's own path instead, which this function does not
     * gate. The historical argument is kept because the DG-1 matrix
     * itself — a missing handle is not always a fault — still applies to
     * every remaining caller of this function.
     *
     * The paired gate this comment used to cross-reference
     * (nodus_witness_bft.c's load_committee_at_height) is deleted; grep
     * DG-1 before assuming any live sibling still exists. */
    if (!w->db) {
        static const uint8_t zero_chain[32] = {0};
        if (memcmp(w->chain_id, zero_chain, 32) == 0) {
            /* Deliberately NOT logged. This is a normal, expected state
             * on a fresh cluster, and the consumers reading it run at
             * tick rate — R3 W4: the sibling gate that used to decline to
             * log here for the same reason (nodus_witness_bft.c) is
             * deleted with the closed consensus lane. */
            *out = 0;
            return 0;
        }
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: this node HOLDS a chain (chain_id set) but its "
            "database is not open — refusing to answer 0 (DG-1 row 2: an "
            "absent answer is not height 0)");
        return -1;
    }

    /* O15D — on a SUCCESSOR chain the chain height IS the committed V2
     * height: the legacy `blocks` table is empty by construction and
     * stays empty forever (the legacy production lane refuses on a
     * successor), so every consumer of "this chain's height" — the
     * round anchors, IDENT advertisements, RPC status, forward routing —
     * must see the v2_blocks tip. Legacy chains take the branch below
     * byte-identically (v2_successor is false there). */
    if (w->v2_successor) {
        sqlite3_stmt *v2 = NULL;
        int vrc = sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
                -1, &v2, NULL);
        if (vrc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG,
                "block_height: v2_blocks prepare failed (rc=%d): %s",
                vrc, sqlite3_errmsg(w->db));
            return -1;
        }
        vrc = sqlite3_step(v2);
        if (vrc != SQLITE_ROW && vrc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG,
                "block_height: v2_blocks step failed (rc=%d): %s",
                vrc, sqlite3_errmsg(w->db));
            sqlite3_finalize(v2);
            return -1;
        }
        uint64_t vh = 0;
        /* COALESCE guarantees non-NULL, but the type test costs nothing
         * and keeps this branch's success rule identical to the legacy
         * one below: a NULL aggregate is an EMPTY chain, never a fault. */
        if (vrc == SQLITE_ROW &&
            sqlite3_column_type(v2, 0) != SQLITE_NULL)
            vh = (uint64_t)sqlite3_column_int64(v2, 0);
        sqlite3_finalize(v2);
        *out = vh;
        return 0;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT MAX(height) FROM blocks", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: blocks prepare failed (rc=%d): %s",
            rc, sqlite3_errmsg(w->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: blocks step failed (rc=%d): %s",
            rc, sqlite3_errmsg(w->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    uint64_t height = 0;
    /* MAX() over an empty table yields one row holding NULL — a genuinely
     * empty chain, and the one case where 0 is the honest answer. */
    if (rc == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        height = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    *out = height;
    return 0;
}

/* ── THE FAIL-OPEN FORM — for callers whose answer decides nothing ────
 *
 * O15O Faz 1. This wrapper preserves the pre-O15O behaviour EXACTLY: a
 * DB fault still yields 0, indistinguishable from an empty chain to the
 * caller. That is safe ONLY where the value labels or advises and never
 * decides, so every consensus consumer was moved to the checked form.
 *
 * What the wrapper adds is that the fault can no longer be SILENT. The
 * checked form logs the sqlite error text; this line names the FAIL-OPEN
 * itself, so an operator sees "we answered 0 because the read failed"
 * instead of inferring it from a chain that appears to be at genesis.
 * Both reach stderr in a nodus-server build: QGP_LOG_* resolves to
 * nodus/src/nodus_log_shim.c there, whose qgp_log_ring_add writes
 * straight to stderr with an [ERR/tag] prefix — the real qgp_log.c, whose
 * ring buffer nodus never enables, is only linked in the messenger tree.
 *
 * THE CALLERS DELIBERATELY LEFT ON THIS FORM (O15O Faz 1 classification;
 * a bogus 0 at each is either harmless or conservative). Named by their
 * FUNCTION as well as their line, because prose like this one is what
 * shifts line numbers: if the two disagree, the function name wins and
 * the line is stale.
 *
 *   nodus_witness_handlers.c 475, 1214, 2896 — RPC / display.
 *   nodus_witness_peer.c:435 — the height advertised in IDENT.
 *   nodus_server.c:3800      — RPC status field.
 *
 * R3 W4 — every caller this list once named in nodus_witness_bft.c
 * (supply_invariant_violated, bft_handle_vote_inner's commit tail,
 * nodus_witness_bft_handle_commit's cert store and P1 round release in
 * nodus_witness_bft_check_timeout) and in nodus_witness_sync.c is
 * DELETED with the closed consensus lane. Neither file exists any more,
 * so neither line-number citation is checkable; the classification
 * itself is moot for a caller that no longer exists. */
uint64_t nodus_witness_block_height(nodus_witness_t *w) {
    uint64_t h = 0;
    if (nodus_witness_block_height_checked(w, &h) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "block_height: READ FAULTED — answering 0 on the FAIL-OPEN "
            "accessor. If this height reaches a consensus decision, that "
            "call site belongs on nodus_witness_block_height_checked");
        return 0;
    }
    return h;
}

/* ── Supply tracking ─────────────────────────────────────────────── */

int nodus_witness_supply_init(nodus_witness_t *w, uint64_t total_supply,
                                 uint64_t reward_pool,
                                 const uint8_t *genesis_tx_hash) {
    if (!w || !w->db || !genesis_tx_hash) return -1;
    /* tokenomics-v3 P2 (P2-1): the reserve is carved OUT of the fixed
     * total supply, never added to it — a pool above the total is a
     * config the genesis Rule P.2 already refused, so reaching here with
     * one is a caller bug, never a value to store. */
    if (reward_pool > total_supply) return -1;

    /* Schema first, "already initialized" probe SECOND (2026-07-31).
     *
     * The order used to be the other way round, which made the ALTER
     * below unreachable on exactly the DB that needed it: the probe
     * returns -2 the moment it sees the id = 1 row, so a DB that already
     * held the row but predated the total_minted column could never gain
     * it — and under the D1/D2/D3 fail-close chain a missing column now
     * rejects every block (see migrate_v17_supply_total_minted, which is
     * the belt to this suspenders: it runs on every chain-DB open, while
     * this path only runs when commit_genesis calls us).
     *
     * Both statements are idempotent, so running them before the probe
     * costs nothing on an already-initialized DB: CREATE TABLE IF NOT
     * EXISTS is a no-op, and the ALTER returns "duplicate column name"
     * which is ignored via the NULL errmsg. */
    sqlite3_exec(w->db,
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  total_minted INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL,"
        /* tokenomics-v3 P2 — byte-identical to WITNESS_DB_SCHEMA
         * (nodus_witness.c) and to the S16 rung's ALTER. */
        "  reward_pool INTEGER NOT NULL DEFAULT 0"
        ");", NULL, NULL, NULL);

    /* Migration: add total_minted to pre-v0.16 DBs. The ALTER silently
     * fails when the column already exists (ignored via NULL errmsg). */
    sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking ADD COLUMN total_minted "
        "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL);
    /* tokenomics-v3 P2 — the same idempotent back-fill for reward_pool
     * (the every-open v18 leg's twin), so a legacy row this call refuses
     * to re-initialise is still readable by supply_get afterwards. */
    sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking ADD COLUMN reward_pool "
        "INTEGER NOT NULL DEFAULT 0", NULL, NULL, NULL);

    /* Check if already initialized */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  /* Already initialized */
    }
    sqlite3_finalize(stmt);

    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO supply_tracking "
        "(id, genesis_supply, total_burned, total_minted, "
        " current_supply, last_tx_hash, last_sequence, reward_pool) "
        "VALUES (1, ?, 0, 0, ?, ?, 1, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_blob(stmt, 3, genesis_tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (int64_t)reward_pool);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* D1 (2026-07-31) — three-valued so callers can tell "pre-genesis" from
 * "DB error". Conflating the two let a transient fault masquerade as a
 * legitimate empty state and reach state_root / the supply gate. Full
 * contract on the declaration in nodus_witness_db.h. */
int nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT genesis_supply, total_burned, total_minted, current_supply, "
        "       last_sequence, reward_pool "
        "FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Includes "no such table: supply_tracking" and "no such column:
         * total_minted", both of which are real errors here, NOT an absent
         * row — the caller must not read them as "pre-genesis".
         *
         * MERGE NOTE (2026-07-31): this comment used to say the table is
         * "created lazily by supply_init". That stopped being true in the
         * same round — supply_tracking is now part of WITNESS_DB_SCHEMA
         * (nodus_witness.c), so it exists from the moment the chain DB is
         * opened and only a genuinely missing/older DB can land here. The
         * total_minted column is back-filled by
         * nodus_witness_db_migrate_v17_supply_total_minted on every open. */
        QGP_LOG_ERROR(LOG_TAG, "supply_get: prepare failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        if (rc == SQLITE_DONE) return 1;   /* row genuinely absent */
        QGP_LOG_ERROR(LOG_TAG, "supply_get: step failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        return -1;
    }

    /* tokenomics-v3 P2: a stored-NEGATIVE reward_pool is a corrupt row
     * (the value is a u64 bound to INT64_MAX by every writer), never a
     * huge pool — the rtn_core_burned_fetch rule. */
    if (sqlite3_column_int64(stmt, 5) < 0) {
        sqlite3_finalize(stmt);
        QGP_LOG_ERROR(LOG_TAG, "%s", "supply_get: reward_pool is stored "
                      "negative — corrupt row");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->genesis_supply = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->total_burned   = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->total_minted   = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->current_supply = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->last_sequence  = (uint64_t)sqlite3_column_int64(stmt, 4);
    out->reward_pool    = (uint64_t)sqlite3_column_int64(stmt, 5);

    sqlite3_finalize(stmt);
    return 0;
}

/* ── Supply buckets (scan, decision 2026-09-30-scan-supply-buckets.md) ─
 * Contract on the declaration in nodus_witness_db.h. */

_Static_assert(NODUS_WITNESS_SUPPLY_TREASURY_POOLS == NODUS_TREASURY_POOL_COUNT,
               "the supply view carries exactly the treasury pool set");

/* v2_treasury, pool 1..9 into out[0..8]. The row checks are
 * treasury_scan's (nodus_witness_roots_v2.c) — the loader the treasury
 * root and the conservation invariant read through — so a row the root
 * would refuse is refused here too: a non-INTEGER column, pool_id outside
 * [MIN, MAX], a negative balance. The pool_id is the primary key, so one
 * row per pool; a pool with no row reads 0. */
static int supply_view_treasury(nodus_witness_t *w,
                                uint64_t out[NODUS_WITNESS_SUPPLY_TREASURY_POOLS]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pool_id, balance FROM v2_treasury ORDER BY pool_id ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "supply_view: treasury prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    memset(out, 0, NODUS_WITNESS_SUPPLY_TREASURY_POOLS * sizeof(uint64_t));
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_INTEGER ||
            sqlite3_column_type(stmt, 1) != SQLITE_INTEGER) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "supply_view: treasury row has a "
                          "non-INTEGER column");
            sqlite3_finalize(stmt);
            return -1;
        }
        sqlite3_int64 id = sqlite3_column_int64(stmt, 0);
        sqlite3_int64 b  = sqlite3_column_int64(stmt, 1);
        if (id < (sqlite3_int64)NODUS_TREASURY_POOL_MIN ||
            id > (sqlite3_int64)NODUS_TREASURY_POOL_MAX || b < 0) {
            QGP_LOG_ERROR(LOG_TAG, "supply_view: treasury row malformed "
                          "(pool_id %lld, balance %lld)",
                          (long long)id, (long long)b);
            sqlite3_finalize(stmt);
            return -1;
        }
        out[id - (sqlite3_int64)NODUS_TREASURY_POOL_MIN] = (uint64_t)b;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "supply_view: treasury scan aborted "
                      "(rc=%d)", rc);
        return -1;
    }
    return 0;
}

int nodus_witness_supply_view_get(nodus_witness_t *w,
                                  nodus_witness_supply_view_t *out) {
    if (!w || !w->db || !out) return -1;

    /* Committed state only: an open ledger transaction on this (single)
     * connection would let these reads see a block that is not committed
     * yet (nodus_witness_v3_block_build makes the same check). */
    if (sqlite3_get_autocommit(w->db) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "supply_view: a ledger transaction is "
                      "in progress");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    int src = nodus_witness_supply_get(w, &out->supply);
    if (src < 0) return -1;
    if (src == 1) memset(&out->supply, 0, sizeof(out->supply));
    out->has_supply = (src == 0);

    if (nodus_witness_v2_tip_height(w, &out->tip) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "supply_view: chain height unreadable");
        return -1;
    }
    if (supply_view_treasury(w, out->treasury) != 0) return -1;

    /* The CORE runtime's native asset (64 zero bytes) — the same term
     * nodus_rt_core_invariant sums, so the buckets and `current` obey
     * the one conservation equation. */
    static const uint8_t native_token[64] = {0};
    if (nodus_witness_v2_unclaimed_total(w, DNA_DOMAIN_CORE, native_token,
                                         64, &out->unclaimed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "supply_view: unclaimed distribution "
                      "total unreadable");
        return -1;
    }
    return 0;
}

/* tokenomics-v3 P2 — nodus_witness_supply_add_minted and
 * nodus_witness_supply_add_burned are DELETED (declaration comment in
 * nodus_witness_db.h): no production caller survived P2-4 / P2-6. */

/* The legacy-table query readers — tx_by_owner (committed_transactions ⋈
 * tx_outputs), tx_get, get_committed_coords (committed_transactions) and
 * cert_get (commit_certificates) — and the uncalled writer tx_output_add
 * are DELETED with the client RPCs they served (dnac_history, dnac_tx,
 * dnac_spend_replay, dnac_block): no production writer fills those tables
 * on a version-3 chain, so every answer was empty. The tables themselves
 * stay in the schema (nodus_witness.c). */

/* ── Token registry operations ──────────────────────────────────── */

int nodus_witness_token_get(nodus_witness_t *w, const uint8_t *token_id,
                               char *name_out, char *symbol_out,
                               uint8_t *decimals_out, uint64_t *supply_out,
                               char *creator_fp_out) {
    if (!w || !w->db || !token_id) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT name, symbol, decimals, supply, creator_fp "
        "FROM tokens WHERE token_id = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, token_id, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (name_out) {
        const char *n = (const char *)sqlite3_column_text(stmt, 0);
        if (n) { strncpy(name_out, n, 63); name_out[63] = '\0'; }
    }
    if (symbol_out) {
        const char *s = (const char *)sqlite3_column_text(stmt, 1);
        if (s) { strncpy(symbol_out, s, 15); symbol_out[15] = '\0'; }
    }
    if (decimals_out)
        *decimals_out = (uint8_t)sqlite3_column_int(stmt, 2);
    if (supply_out)
        *supply_out = (uint64_t)sqlite3_column_int64(stmt, 3);
    if (creator_fp_out) {
        const char *c = (const char *)sqlite3_column_text(stmt, 4);
        if (c) { strncpy(creator_fp_out, c, 128); creator_fp_out[128] = '\0'; }
    }

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_token_list(nodus_witness_t *w,
                               nodus_witness_token_entry_t *out,
                               int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT token_id, name, symbol, decimals, supply, creator_fp "
        "FROM tokens ORDER BY rowid LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_token_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *tid = sqlite3_column_blob(stmt, 0);
        int tid_len = sqlite3_column_bytes(stmt, 0);
        if (tid && tid_len == 64)
            memcpy(e->token_id, tid, 64);

        const char *n = (const char *)sqlite3_column_text(stmt, 1);
        if (n) { strncpy(e->name, n, sizeof(e->name) - 1); }

        const char *s = (const char *)sqlite3_column_text(stmt, 2);
        if (s) { strncpy(e->symbol, s, sizeof(e->symbol) - 1); }

        e->decimals = (uint8_t)sqlite3_column_int(stmt, 3);
        e->supply = (uint64_t)sqlite3_column_int64(stmt, 4);

        const char *c = (const char *)sqlite3_column_text(stmt, 5);
        if (c) { strncpy(e->creator_fp, c, sizeof(e->creator_fp) - 1); }

        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── DB transaction wrappers ─────────────────────────────────────── */

int nodus_witness_db_begin(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    /* Phase 9 / Task 47 — upgraded to BEGIN IMMEDIATE per design F-STATE-02.
     *
     * IMMEDIATE acquires the RESERVED lock synchronously: any concurrent
     * write attempt fails fast instead of waiting for the commit barrier.
     * This makes "nested begin" bugs (re-entrant block commits) surface as
     * loud SQLITE_BUSY on the second BEGIN rather than silently succeeding.
     *
     * The block commit path (commit_genesis / commit_batch / replay_block)
     * is the sole writer, so IMMEDIATE never contends in production; the
     * upgrade is a correctness guard, not a performance change. */
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: BEGIN IMMEDIATE failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    w->in_block_transaction = true;
    return 0;
}

int nodus_witness_db_commit(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    QGP_BENCH_START(QGP_BENCH_SQLITE_COMMIT);
    int rc = sqlite3_exec(w->db, "COMMIT", NULL, NULL, &err);
    QGP_BENCH_END(QGP_BENCH_SQLITE_COMMIT);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: COMMIT failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    w->in_block_transaction = false;
    return 0;
}

int nodus_witness_db_rollback(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, &err);
    /* HF-6 red-team round 1 close-out: a chain_config lookup cache warmed
     * inside the transaction may hold rows that are gone now — cold, so
     * the next lookup re-reads the database (nodus_witness_chain_config.c;
     * unconditional: a failed ROLLBACK leaves it cold too). */
    w->chain_config_cache_warm = false;
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ROLLBACK failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    w->in_block_transaction = false;
    return 0;
}

/* Reject anything but [A-Za-z0-9_] in savepoint names — they go straight
 * into SQL with no binding, and SQLite SAVEPOINT does not accept ?. */
static bool savepoint_name_safe(const char *name) {
    if (!name || !*name) return false;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    return true;
}

int nodus_witness_db_savepoint(nodus_witness_t *w, const char *name) {
    if (!w || !w->db || !savepoint_name_safe(name)) return -1;
    char sql[128];
    snprintf(sql, sizeof(sql), "SAVEPOINT %s", name);
    char *err = NULL;
    int rc = sqlite3_exec(w->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: SAVEPOINT %s failed: %s\n", LOG_TAG, name, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_rollback_to_savepoint(nodus_witness_t *w, const char *name) {
    if (!w || !w->db || !savepoint_name_safe(name)) return -1;
    char sql[128];
    snprintf(sql, sizeof(sql), "ROLLBACK TO SAVEPOINT %s", name);
    char *err = NULL;
    int rc = sqlite3_exec(w->db, sql, NULL, NULL, &err);
    /* the chain_config cache goes cold, as at nodus_witness_db_rollback */
    w->chain_config_cache_warm = false;
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ROLLBACK TO SAVEPOINT %s failed: %s\n", LOG_TAG, name, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* R3 W4 — nodus_witness_compute_block_hash / _ex (the block-hash
 * preimage shared by the legacy block_add writer and the legacy sync
 * verifier) are DELETED with the closed consensus lane: block_add above
 * and nodus_witness_sync.c's compute_prev_hash, its only two callers,
 * are both gone. */

/* Schema v12 migration (Phase 1 / Task 1.1).
 *
 * Idempotent. ALTER TABLE ADD COLUMN is silently retried on duplicate-
 * column errors so a second run on an already-migrated DB succeeds.
 * Index DROP/CREATE both use IF EXISTS / IF NOT EXISTS for the same
 * reason. Real SQLite errors (out of memory, disk full, lock contention)
 * trigger WITNESS_DB_MIGRATION_FATAL → abort().
 */
static void nodus_witness_db_migrate_v13_client_fields(nodus_witness_t *w);
static void nodus_witness_db_migrate_v14_chain_def(nodus_witness_t *w);
static void nodus_witness_db_migrate_v15_stake_delegation(nodus_witness_t *w);
/* R3 W4 — nodus_witness_db_migrate_v16_pbft_state (schema v16, the
 * singleton pbft_state table) is DELETED with the closed consensus lane:
 * nodus_witness_db_save_pbft_state / _load_pbft_state, its only writer
 * and reader, are both deleted below and the table is never read again. */
static void nodus_witness_db_migrate_v17_supply_total_minted(nodus_witness_t *w);
static void nodus_witness_db_migrate_v18_supply_reward_pool(nodus_witness_t *w);

/* Does `table` already have a column called `column`? 1 / 0 / -1 fault.
 *
 * Exists so a migration can ASK instead of inferring the answer from an
 * error message — see the block in migrate_v12 below for what that cost.
 * PRAGMA table_info is the tree's existing idiom for this
 * (nodus_witness_v2_schema.c, nodus_witness_v2_claims.c). */
static int db_column_exists(nodus_witness_t *w, const char *table,
                            const char *column) {
    if (!w || !w->db || !table || !column) return -1;
    char sql[256];
    int n = snprintf(sql, sizeof(sql), "PRAGMA table_info(\"%s\")", table);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);  /* col 1 = name */
        if (name && strcmp((const char *)name, column) == 0) { found = 1; break; }
    }
    /* A break on a match leaves rc == SQLITE_ROW, which is not a fault. */
    if (!found && rc != SQLITE_DONE) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);
    return found;
}

int nodus_witness_db_migrate_v12(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* ── tx_index column ─────────────────────────────────────────────
     *
     * ASK WHETHER THE COLUMN IS THERE; DO NOT READ SQLITE'S PROSE.
     *
     * This used to run the ALTER unconditionally and decide what the
     * failure MEANT by searching the error message for the English
     * substring "duplicate column name" — treating a hit as success and
     * anything else as fatal, with an abort(). Two things were wrong with
     * that, and the second is why it mattered:
     *
     *   1. The message is SQLite's, not ours. It is not part of any
     *      documented interface and there is no distinct result code for
     *      this case, so the check could only ever be a string match.
     *   2. This function runs on EVERY chain-database open
     *      (nodus_witness.c witness_db_open_attempt — R3 W4: the other
     *      joining path this once ran on, nodus_witness_bootstrap.c, is
     *      deleted with the closed consensus lane) — a fresh V2 chain
     *      included. If a future SQLite reworded that sentence, the substring would stop
     *      matching, the normal re-run would be classified as a real
     *      failure, and EVERY NODE WOULD abort() ON STARTUP the moment the
     *      library was upgraded. Low probability, fleet-wide blast radius,
     *      and nothing in the code said so.
     *
     * Asking removes the dependency entirely: with the column present we
     * skip the ALTER, so any ALTER failure that does happen is a genuine
     * one and the abort() below means what it says. A probe FAULT is also
     * fatal rather than assumed-absent — running an ALTER because we could
     * not tell would put the guess back. */
    {
        int have = db_column_exists(w, "committed_transactions", "tx_index");
        if (have < 0) {
            fprintf(stderr, "MIGRATION FAILURE: could not determine whether "
                            "committed_transactions.tx_index exists: %s\n",
                    sqlite3_errmsg(w->db));
            abort();
        }
        if (have == 0) {
            char *err = NULL;
            int rc = sqlite3_exec(w->db,
                "ALTER TABLE committed_transactions "
                "ADD COLUMN tx_index INTEGER NOT NULL DEFAULT 0",
                NULL, NULL, &err);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "MIGRATION FAILURE: ALTER ADD tx_index failed "
                                "with sqlite error %d: %s\n",
                        rc, err ? err : "(null)");
                if (err) sqlite3_free(err);
                abort();
            }
            if (err) sqlite3_free(err);
        }
    }

    /* Drop legacy single-column index — IF EXISTS makes it safe on fresh DBs */
    {
        char *err = NULL;
        int rc = sqlite3_exec(w->db,
            "DROP INDEX IF EXISTS idx_ctx_height",
            NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "MIGRATION FAILURE: DROP INDEX idx_ctx_height failed "
                            "with sqlite error %d: %s\n", rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
    }

    /* Create composite index — IF NOT EXISTS for idempotence */
    {
        char *err = NULL;
        int rc = sqlite3_exec(w->db,
            "CREATE INDEX IF NOT EXISTS idx_ctx_block "
            "ON committed_transactions(block_height, tx_index)",
            NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "MIGRATION FAILURE: CREATE INDEX idx_ctx_block failed "
                            "with sqlite error %d: %s\n", rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
    }

    /* Phase 11 follow-up — client_pubkey + client_sig columns. */
    nodus_witness_db_migrate_v13_client_fields(w);

    /* Phase 2 / Task 7 (anchored merkle proofs) — chain_def_blob column. */
    nodus_witness_db_migrate_v14_chain_def(w);

    /* Task 11 (stake delegation) — utxo_set.unlock_block column. */
    nodus_witness_db_migrate_v15_stake_delegation(w);

    /* Hard-Fork v1 — chain_config_history table (CREATE TABLE IF NOT EXISTS). */
    nodus_chain_config_db_migrate(w);

    /* 2026-07-31 — supply_tracking.total_minted back-fill, made reachable
     * on every open (it was unreachable inside supply_init). */
    nodus_witness_db_migrate_v17_supply_total_minted(w);

    /* tokenomics-v3 P2 — supply_tracking.reward_pool back-fill, on every
     * open, for the same reason as the v17 leg above: supply_get now
     * reads the column, so a DB that predates it would otherwise refuse
     * every supply read. The version-3 lane's own S16 rung
     * (nodus_witness_v2_schema.c) adds and VERIFIES the same column; this
     * leg is what keeps every other lane's supply read working. */
    nodus_witness_db_migrate_v18_supply_reward_pool(w);

    /* 2026-10-01 — the node-local address history index tables
     * (decision 2026-10-01-node-address-history-index.md rev 2 item 6):
     * RUNG-FREE, CREATE ... IF NOT EXISTS on every open like the
     * chain_config leg above — no schema version rung, the S16 equality
     * gates untouched. Created whatever the node flag says; only the
     * writers consult the flag. */
    nodus_witness_addr_index_migrate(w);

    return 0;
}

/* Phase 11 follow-up — additive ALTER for client_pubkey + client_sig.
 * Split out so the migration body in v12 stays focused. */
static void nodus_witness_db_migrate_v13_client_fields(nodus_witness_t *w) {
    static const char *cols[2];
    cols[0] = "ALTER TABLE committed_transactions ADD COLUMN client_pubkey BLOB";
    cols[1] = "ALTER TABLE committed_transactions ADD COLUMN client_sig BLOB";
    for (int i = 0; i < 2; i++) {
        char *err = NULL;
        int rc = sqlite3_exec(w->db, cols[i], NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            const char *msg = err ? err : "(null)";
            if (!strstr(msg, "duplicate column name")) {
                fprintf(stderr,
                        "MIGRATION FAILURE: ALTER ADD client field [%d] "
                        "sqlite error %d: %s\n", i, rc, msg);
                if (err) sqlite3_free(err);
                abort();
            }
            if (err) sqlite3_free(err);
        }
    }
}

/* Schema v14 migration (Phase 2 / Task 7 - anchored merkle proofs).
 *
 * Adds the chain_def_blob column to the blocks table. Nullable; only
 * populated for genesis blocks (height=0) and stores the serialized
 * dnac_chain_definition_t. Idempotent via duplicate-column tolerance. */
static void nodus_witness_db_migrate_v14_chain_def(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE blocks ADD COLUMN chain_def_blob BLOB",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD chain_def_blob "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* Schema v15 migration (Task 11 — stake/delegation).
 *
 * Adds the unlock_block column to the utxo_set table. Used to lock
 * stake/delegation UTXOs until a future block height (unbonding
 * cooldown). Default 0 means "already spendable"; zero value preserves
 * pre-Task-11 semantics for every existing UTXO. Idempotent via
 * duplicate-column tolerance. */
static void nodus_witness_db_migrate_v15_stake_delegation(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE utxo_set "
        "ADD COLUMN unlock_block INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD unlock_block "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* Schema v17 migration (2026-07-31) — supply_tracking.total_minted.
 *
 * The column arrived in v0.16 with an ALTER inside
 * nodus_witness_supply_init. That ALTER is UNREACHABLE on exactly the DB
 * that needs it: supply_init returns -2 ("already initialized") as soon
 * as it sees the id = 1 row, several statements BEFORE the ALTER. A DB
 * that already held the row but predated the column could never gain it.
 *
 * That was survivable while supply_get treated a failed prepare as
 * "pre-genesis". It is not any more: supply_get now returns a hard -1 on
 * prepare failure (D1), and the supply leg of the state root fails
 * closed on that (nodus_witness_supply_root_v2; the legacy epoch_state
 * leaf loader / compute_state_root that did the same were deleted by
 * the root-layout round, K2/K3) — so a missing column would make the
 * node reject every block and produce no state root at all.
 *
 * Running it here makes it reachable on EVERY chain-DB open. Inside
 * supply_init it would only be reachable on a genesis (re-)commit —
 * supply_init's current sole production caller is the version-3 genesis
 * path (nodus_witness_v2_gen.c), so a plain restart would never repair
 * the DB. R3 W4 — the legacy commit_genesis caller this comment used to
 * cite (nodus_witness_bft.c:5924) is deleted with the closed consensus
 * lane; the "sole caller, only reachable on genesis" argument itself is
 * unaffected, since it never depended on which lane called it.
 *
 * HONEST SCOPE: I could not prove such a DB still exists — the chain was
 * wiped. This is a cheap guard, not the repair of a demonstrated
 * incident.
 *
 * Two tolerated sqlite errors, neither fatal:
 *   "duplicate column name" — the normal case on every current DB.
 *   "no such table"         — supply_tracking is created by
 *                             WITNESS_DB_SCHEMA (which runs before this
 *                             in witness_db_open_path) and, on older
 *                             DBs, by supply_init; but hand-built
 *                             fixtures legitimately lack it (see
 *                             setup_pre_v12 in
 *                             tests/test_schema_migration.c:26-65).
 *                             Aborting the process over an absent table
 *                             would be a far worse failure than skipping
 *                             a back-fill that has nothing to back-fill.
 */
static void nodus_witness_db_migrate_v17_supply_total_minted(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking "
        "ADD COLUMN total_minted INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name") &&
            !strstr(msg, "no such table")) {
            fprintf(stderr,
                    "MIGRATION FAILURE: ALTER ADD supply_tracking.total_minted "
                    "sqlite error %d: %s\n", rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* tokenomics-v3 P2 — supply_tracking.reward_pool (P2-1). The v17 leg
 * above, verbatim in shape and in its two tolerated errors, for the
 * column P2 adds: "duplicate column name" is the normal case on every
 * DB this build created (WITNESS_DB_SCHEMA carries the column), "no such
 * table" a hand-built fixture that has no supply_tracking at all. The
 * DEFAULT 0 is the honest back-fill: a chain that predates the reward
 * pool never had one. */
static void nodus_witness_db_migrate_v18_supply_reward_pool(nodus_witness_t *w) {
    if (!w || !w->db) return;
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "ALTER TABLE supply_tracking "
        "ADD COLUMN reward_pool INTEGER NOT NULL DEFAULT 0",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        const char *msg = err ? err : "(null)";
        if (!strstr(msg, "duplicate column name") &&
            !strstr(msg, "no such table")) {
            QGP_LOG_ERROR(LOG_TAG, "MIGRATION FAILURE: ALTER ADD "
                          "supply_tracking.reward_pool sqlite error %d: %s",
                          rc, msg);
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
}

/* R3 W4 — nodus_witness_db_save_pbft_state and nodus_witness_db_load_
 * pbft_state (the PR 3 Yol B / H-5 persistence pair for the legacy BFT
 * view counter and PREVOTE-prepared certificate) are DELETED with the
 * closed consensus lane: `w->current_view` and `w->last_prepared`, the
 * only fields either function read or wrote, no longer exist on
 * nodus_witness_t, and their only caller (nodus_witness.c's
 * witness_db_open_attempt) no longer calls them. The pbft_state table
 * itself is left un-migrated (see the v16 migration's own deletion note
 * above) and is never read again by this build. */
