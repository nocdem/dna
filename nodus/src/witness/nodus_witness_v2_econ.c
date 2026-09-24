/**
 * Nodus — the version-3 chain's economics (tokenomics-v3 P2).
 *
 * Contract, the governing records and the touched-domain obligations are
 * in nodus_witness_v2_econ.h. Every anchor cited here is a file:line in
 * THIS tree, read rather than recalled.
 *
 * ── WHAT P2 DELETED FROM THIS FILE, AND WHY ─────────────────────────
 * O15J Faz 2 ported V1's economics verbatim: a per-block mint
 * (nodus_witness_v2_emission_apply, the 32 → 1 halving curve), an
 * `epoch_state` pool it accrued into, the epoch-start snapshot blob
 * (nodus_witness_epoch_snapshot_apply) it read delegator amounts from,
 * and an equal-per-seat settlement that BURNED its remainders and every
 * missed share. Decision §1 ("Yeni token basılmayacak"; "Hak kazanılmayan
 * ödül payları ve yuvarlama artıkları havuzda kalacak"; "Ödeme her 24
 * epoch'ta yapılacak") and design §7 P2-4/P2-6 replace every one of those
 * rules, so all of them are GONE — not disabled — per No Dead Code.
 *
 * ── P2 REVISION 2: "DELEGATOR = VALIDATOR GİBİ" (2026-09-24) ───────
 * Design docs/plans/2026-09-23-tokenomics-v3-consensus-binding-design.md
 * §7.1, decision file §3 2026-09-24 "DELEGATOR = VALIDATOR GİBİ". The
 * rev-1 patches — min(copy(H−E), live at H) per stake and a zero for a
 * delegation whose delegated_at_block was after H−E — sampled only two
 * instants and could not see a PARTIAL withdrawal taken out, used and
 * topped back up inside one epoch. The root was that an UNDELEGATE's
 * release UTXO was spendable in the next block. Revision 2 removes that
 * root instead: the release is born LOCKED until 12 epochs after the
 * stake leaves the voting power (P2-10, nodus_witness_rt_native.c
 * rtn_sysfund_exec, nodus_v2_power_exit_boundary). With every counted
 * coin locked through the epoch it earns, the distribution can simply
 * pay the set that GOVERNED the epoch, by that set's own power, and
 * split each member's share by the frozen copy that set was built from.
 * The rev-1 weigher, its live-delegation read and the delegated_at_block
 * zeroing are DELETED (design §7.1 "Silinenler"; the decision file marks
 * the 2026-09-24 entries (1)'s min() and (2) as superseded by this).
 *
 * ── DIVERGENCES FROM V1 KEPT FROM O15J (still true here) ────────────
 *  1. UTXO WRITES GO THROUGH THE TYPED EFFECT PATH (the payday), never a
 *     hand-rolled INSERT: the CORE adapter's probe → precond → mutate
 *     path, so a colliding payout identity FAILS CLOSED (PRE_ABSENT) and
 *     `created_at` is pinned to 0 (V1 wrote a wall-clock time).
 *  2. A DATABASE FAULT IS NEVER A VALUE. Every read that decides a share
 *     is three-valued, and an unreadable member / attendance / copy /
 *     supply row is -2, never "absent, keep his share".
 *  3. RETURN CONVENTION. The boundary's contract is 0/-2 with no verdict
 *     class.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_db.h"        /* supply_get               */
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT (the §A
                                              * power unit — the econ
                                              * band's build-identity
                                              * refusal)                 */
#include "witness/nodus_witness_v2_epoch.h"  /* attendance_meets_bar,
                                              * authority_for_epoch      */
#include "witness/nodus_witness_v2_gen.h"    /* stored document, reward
                                              * divisor, payout default */
#include "witness/nodus_witness_runtime.h"   /* the CORE record builder   */
#include "witness/nodus_witness_v2_adapter.h"/* effects_apply             */
#include "witness/nodus_witness_v2_claims.h" /* v2_runtime_for            */
#include "witness/nodus_witness_validator.h"

#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/res_meter.h"      /* dna_ck_add_u64                      */
#include "dnac/validator.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_u128.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2ECON"

/* The synthetic output-index ladder at one boundary (nodus_witness_
 * v2_epoch.h "THE INDEX BAND"): bond release 200 < payday base 400 <
 * graduation-delegation band 0x40000000, the band ending below 2^31. */
_Static_assert(NODUS_V2_EPGRAD_OUT_IDX < NODUS_V2_SETTLE_OUT_IDX_BASE,
               "the payday base must sit above the bond release index");
_Static_assert(NODUS_V2_SETTLE_OUT_IDX_BASE <
                   NODUS_V2_GRAD_DELEG_OUT_IDX_BASE,
               "the payday base must sit below the delegation band");

/* The stored SQLite INTEGER bound. Anything above it round-trips
 * NEGATIVE and would poison every later read — the V2EP_STORE_MAX rule
 * (nodus_witness_v2_epoch.c). */
#define V2EC_STORE_MAX  ((uint64_t)INT64_MAX)

/* ── little BE helpers ─────────────────────────────────────────────── */

static void v2ec_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* ── the two canonical payday identities (pure, no DB) ──────────────── */

int nodus_witness_v2_settlement_tx_hash(uint64_t key, uint8_t out[64]) {
    if (!out) return -2;
    /* BYTE-IDENTICAL to bft.c:2977-2986: the 10 ASCII bytes of
     * "settlement" with NO terminator, then the key big-endian.
     * sizeof("settlement") would be 11 and would silently change the
     * preimage — hence the explicit 10. */
    uint8_t pre[10 + 8];
    memcpy(pre, "settlement", 10);
    v2ec_put64(pre + 10, key);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -2;
}

int nodus_witness_v2_settlement_nullifier(const uint8_t tx_hash[64],
                                          uint8_t kind,
                                          uint32_t output_index,
                                          uint8_t out[64]) {
    if (!tx_hash || !out) return -2;
    /* bft.c:3041-3052 — SHA3-512(tx_hash ‖ kind ‖ u32be(index)). */
    uint8_t pre[64 + 1 + 4];
    memcpy(pre, tx_hash, 64);
    pre[64] = kind;
    pre[65] = (uint8_t)((output_index >> 24) & 0xff);
    pre[66] = (uint8_t)((output_index >> 16) & 0xff);
    pre[67] = (uint8_t)((output_index >>  8) & 0xff);
    pre[68] = (uint8_t)( output_index        & 0xff);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -2;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 0 — the committed economic parameters (O15J Faz 2 Block 2C)
 *
 * Contract, the defect and the binding argument: the header.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_v2_econ_params_load(nodus_witness_t *w,
                                      nodus_v2_econ_params_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!w || !w->db) return -1;

    /* ONE statement over the reserved band. The ORDER BY is explicit and
     * over a unique key (the band ids are distinct and effective_block is
     * pinned), so the walk below is identical on every node.
     *
     * NOT nodus_chain_config_get_u64: that function bounds param_id at
     * CC_PARAM_SLOTS and answers `default_value` for every band id
     * (nodus_witness_chain_config.c), which would report a committed
     * row as absent. The warm cache skips the band for the same reason,
     * so there is nothing to invalidate here either. */
    static const char *const sql =
        "SELECT param_id, new_value FROM chain_config_history "
        "WHERE param_id >= ?1 AND param_id <= ?2 AND effective_block = ?3 "
        "ORDER BY param_id ASC";

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "econ params: prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)NODUS_CC_ECON_PARAM_MIN);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)NODUS_CC_ECON_PARAM_MAX);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)NODUS_CC_ECON_EFFECTIVE_BLOCK);

    uint64_t got[NODUS_CC_ECON_PARAM_MAX - NODUS_CC_ECON_PARAM_MIN + 1];
    int      seen[NODUS_CC_ECON_PARAM_MAX - NODUS_CC_ECON_PARAM_MIN + 1];
    memset(got, 0, sizeof(got));
    memset(seen, 0, sizeof(seen));
    /* rc is seeded rather than left indeterminate: the loop below always
     * assigns it first, but a -Wmaybe-uninitialized build must not have
     * to prove that, and this tree ships warning-free. */
    int n = 0, bad = 0, rc = SQLITE_DONE;

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int          pid = sqlite3_column_int(st, 0);
        sqlite3_int64 nv = sqlite3_column_int64(st, 1);
        if (pid < (int)NODUS_CC_ECON_PARAM_MIN ||
            pid > (int)NODUS_CC_ECON_PARAM_MAX) { bad = 1; break; }
        /* A stored-negative or zero economic parameter is a corrupt row,
         * never a value: 0 blocks_per_year is not a schedule and a 0
         * epoch_length keys no epoch. The same rule the CORE row reader
         * applies (nodus_witness_rt_native.c). */
        if (nv <= 0) { bad = 1; break; }
        int idx = pid - (int)NODUS_CC_ECON_PARAM_MIN;
        if (seen[idx]) { bad = 1; break; }     /* PK makes this impossible */
        seen[idx] = 1;
        got[idx]  = (uint64_t)nv;
        n++;
    }
    sqlite3_finalize(st);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "econ params: scan aborted mid-stream "
                      "(rc=%d) — a read fault is never 'no band'", rc);
        return -1;
    }
    if (bad) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "econ params: the committed band holds "
                      "a malformed row — refusing");
        return -1;
    }

    /* ALL or NOTHING. A partial band is a chain whose economics are half
     * committed and half compiled; there is no answer to give for it. */
    if (n == 0) {
        out->present = 0;
        return 0;                  /* pre-band chain: compiled constants */
    }
    if (n != (int)(NODUS_CC_ECON_PARAM_MAX - NODUS_CC_ECON_PARAM_MIN + 1)) {
        QGP_LOG_ERROR(LOG_TAG, "econ params: the committed band is PARTIAL "
                      "(%d of %d rows) — this chain has no defined "
                      "economics", n,
                      (int)(NODUS_CC_ECON_PARAM_MAX -
                            NODUS_CC_ECON_PARAM_MIN + 1));
        return -1;
    }

    out->blocks_per_year =
        got[NODUS_CC_ECON_BLOCKS_PER_YEAR - NODUS_CC_ECON_PARAM_MIN];
    out->decimal_unit =
        got[NODUS_CC_ECON_DECIMAL_UNIT    - NODUS_CC_ECON_PARAM_MIN];
    out->epoch_length =
        got[NODUS_CC_ECON_EPOCH_LENGTH    - NODUS_CC_ECON_PARAM_MIN];

    /* THE BUILD-IDENTITY REFUSAL. Detection, not parameterisation — see
     * the header for why epoch_length cannot simply be used. Everything
     * that keys on DNAC_EPOCH_LENGTH (the boundary gate, this module's
     * distribution and payday, the snapshot builder, the UNDELEGATE
     * release lock) is covered by this one check because the apply
     * engine runs it on EVERY block (nodus_witness_v2_apply.c phase 6f —
     * relocated there by tokenomics-v3 P2 from the deleted per-block
     * mint, which used to be its per-block caller). It does NOT stop a
     * mismatched build before its first boundary work: phase 6f runs
     * AFTER phase 6e (the epoch boundary) inside the same block, so a
     * boundary block does execute its boundary on such a node — and then
     * this refusal FAULTS the block, which rolls back whole, boundary
     * included. Nothing a mismatched build computed is ever committed;
     * what the check buys is a fault on the first block, not a boundary
     * that never runs. */
    if (out->epoch_length != (uint64_t)DNAC_EPOCH_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG,
            "econ params: this chain committed epoch_length %llu at "
            "genesis, this build compiled %llu — refusing to run rather "
            "than keying epochs differently from every peer",
            (unsigned long long)out->epoch_length,
            (unsigned long long)DNAC_EPOCH_LENGTH);
        /* Zeroed again so the struct's "valid only when present" contract
         * is literally true on every -1 exit: a caller that ignores the
         * return code finds nothing usable rather than a plausible value. */
        memset(out, 0, sizeof(*out));
        return -1;
    }

    /* THE SAME REFUSAL FOR THE POWER UNIT. DNAC_DECIMAL_UNIT is read as a
     * macro wherever voting power is derived (power = total_stake /
     * DNAC_DECIMAL_UNIT: the ValidatorUpdate cometbft is told, Rule N's
     * weight floor), and the genesis builder refuses a config that
     * disagrees with it (nodus_witness_v2_gen.c gen_plan_build) — but a
     * node that arrived by SYNCING never ran the builder. A build whose
     * unit disagrees with the chain's committed one would report every
     * validator's power scaled differently from its peers; it stops here
     * instead, on the same per-block caller as epoch_length. */
    if (out->decimal_unit != (uint64_t)DNAC_DECIMAL_UNIT) {
        QGP_LOG_ERROR(LOG_TAG,
            "econ params: this chain committed decimal_unit %llu at "
            "genesis, this build compiled %llu — refusing to run rather "
            "than deriving voting power differently from every peer",
            (unsigned long long)out->decimal_unit,
            (unsigned long long)DNAC_DECIMAL_UNIT);
        memset(out, 0, sizeof(*out));
        return -1;
    }

    out->present = 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 1 — the frozen balance copy (design §7 P2-5)
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  vfp[64];
    uint8_t  ofp[64];
    uint64_t amount;
} v2ec_copy_row_t;

typedef struct {
    v2ec_copy_row_t *rows;
    size_t           n, cap;
} v2ec_copy_set_t;

static int v2ec_copy_push(v2ec_copy_set_t *s, const uint8_t vpk[],
                          const uint8_t opk[], uint64_t amount) {
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 64;
        v2ec_copy_row_t *nr = realloc(s->rows, nc * sizeof(*nr));
        if (!nr) return -2;
        s->rows = nr;
        s->cap = nc;
    }
    v2ec_copy_row_t *r = &s->rows[s->n];
    if (qgp_sha3_512(vpk, DNAC_PUBKEY_SIZE, r->vfp) != 0) return -2;
    if (opk == vpk) {
        memcpy(r->ofp, r->vfp, 64);
    } else if (qgp_sha3_512(opk, DNAC_PUBKEY_SIZE, r->ofp) != 0) {
        return -2;
    }
    r->amount = amount;
    s->n++;
    return 0;
}

int nodus_witness_v2_balance_copy_write(nodus_witness_t *w,
                                        uint64_t epoch_start) {
    if (!w || !w->db) return -2;
    if (epoch_start > V2EC_STORE_MAX) return -2;

    v2ec_copy_set_t set;
    memset(&set, 0, sizeof(set));
    int ret = -2;
    int rc;
    sqlite3_stmt *st = NULL;

    /* ── 1. validators: every row with a bond, owner = the validator ───
     * `self_stake != 0` (not `> 0`) so a stored-NEGATIVE bond is read and
     * refused below rather than silently filtered out. ORDER BY pubkey:
     * the collect order is fixed on every node (the PK decides the
     * committed set anyway — the order only fixes the INSERT sequence). */
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey, self_stake FROM validators "
            "WHERE self_stake != 0 ORDER BY pubkey ASC",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: validators prepare "
                      "failed: %s", (unsigned long long)epoch_start,
                      sqlite3_errmsg(w->db));
        goto done;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(st, 0);
        int pk_len = sqlite3_column_bytes(st, 0);
        sqlite3_int64 s = sqlite3_column_int64(st, 1);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE || s < 0) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: malformed validators "
                          "row (pubkey %d bytes, self_stake %lld)",
                          (unsigned long long)epoch_start, pk_len,
                          (long long)s);
            sqlite3_finalize(st);
            goto done;
        }
        if (v2ec_copy_push(&set, pk, pk, (uint64_t)s) != 0) {
            sqlite3_finalize(st);
            goto done;
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: validators scan failed "
                      "(rc=%d) — a scan fault is never a shorter set",
                      (unsigned long long)epoch_start, rc);
        goto done;
    }

    /* ── 2. delegations: every row ──────────────────────────────────── */
    if (sqlite3_prepare_v2(w->db,
            "SELECT validator_pubkey, delegator_pubkey, amount "
            "FROM delegations "
            "ORDER BY validator_hash ASC, delegator_hash ASC",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: delegations prepare "
                      "failed: %s", (unsigned long long)epoch_start,
                      sqlite3_errmsg(w->db));
        goto done;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *vpk = sqlite3_column_blob(st, 0);
        int vpk_len = sqlite3_column_bytes(st, 0);
        const void *dpk = sqlite3_column_blob(st, 1);
        int dpk_len = sqlite3_column_bytes(st, 1);
        sqlite3_int64 a = sqlite3_column_int64(st, 2);
        if (!vpk || vpk_len != DNAC_PUBKEY_SIZE ||
            !dpk || dpk_len != DNAC_PUBKEY_SIZE || a < 0) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: malformed "
                          "delegations row", (unsigned long long)epoch_start);
            sqlite3_finalize(st);
            goto done;
        }
        if (v2ec_copy_push(&set, vpk, dpk, (uint64_t)a) != 0) {
            sqlite3_finalize(st);
            goto done;
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: delegations scan failed "
                      "(rc=%d)", (unsigned long long)epoch_start, rc);
        goto done;
    }

    /* ── 3. write — STRICT INSERT: an existing (epoch, validator, owner)
     * row is a FAULT, never silently kept or replaced. Two ways it could
     * arise, both local defects: a boundary writing the same epoch twice,
     * or a self-delegation (delegator == validator) colliding with the
     * validator's own row — Rule S refuses that at admission
     * (nodus_witness_rt_native.c, rtn_delegate_exec). */
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_balance_copy (epoch_start, validator_fp, "
            "owner_fp, amount) VALUES (?1, ?2, ?3, ?4)",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: insert prepare failed: "
                      "%s", (unsigned long long)epoch_start,
                      sqlite3_errmsg(w->db));
        goto done;
    }
    for (size_t i = 0; i < set.n; i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start)
                != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, set.rows[i].vfp, 64, SQLITE_TRANSIENT)
                != SQLITE_OK ||
            sqlite3_bind_blob(st, 3, set.rows[i].ofp, 64, SQLITE_TRANSIENT)
                != SQLITE_OK ||
            sqlite3_bind_int64(st, 4, (sqlite3_int64)set.rows[i].amount)
                != SQLITE_OK) {
            sqlite3_finalize(st);
            goto done;
        }
        if (sqlite3_step(st) != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: row %zu insert "
                          "failed: %s", (unsigned long long)epoch_start, i,
                          sqlite3_errmsg(w->db));
            sqlite3_finalize(st);
            goto done;
        }
    }
    sqlite3_finalize(st);

    /* ── 4. prune: keep epoch_start − 2E, epoch_start − E and
     * epoch_start — THREE copies (tokenomics-v3 P3-2), nothing older.
     * Below 2E there is nothing older than epoch_start − 2E to prune.
     * Who reads what is kept (B = epoch_start):
     *   copy(B)      the commit_next of boundary B + E ranks the set it
     *                builds by it (P3-1 "okuma B",
     *                nodus_committee_compute_for_epoch);
     *   copy(B − E)  read by the commit_next of THIS boundary B, which
     *                ran before this write;
     *   copy(B − 2E) the SOURCE copy of the distribution at B + E
     *                (src(B + E) = B − 2E, v2ec_source_copy below) — that
     *                distribution runs at step 1b of boundary B + E,
     *                before that boundary's own prune deletes it.
     * Keeping two (the P2 rule, prune below B − E) would delete
     * copy(B − 2E) one boundary before its reader. */
    if (epoch_start >= 2 * (uint64_t)DNAC_EPOCH_LENGTH) {
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM v2_balance_copy WHERE epoch_start < ?1",
                -1, &st, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: prune prepare "
                          "failed: %s", (unsigned long long)epoch_start,
                          sqlite3_errmsg(w->db));
            goto done;
        }
        if (sqlite3_bind_int64(st, 1, (sqlite3_int64)
                               (epoch_start -
                                2 * (uint64_t)DNAC_EPOCH_LENGTH))
            != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: prune bind failed",
                          (unsigned long long)epoch_start);
            sqlite3_finalize(st);
            goto done;
        }
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "balance copy %llu: prune failed "
                          "(rc=%d)", (unsigned long long)epoch_start, rc);
            goto done;
        }
    }
    ret = 0;

done:
    free(set.rows);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 2 — the payout interval (design §7 P2-7)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_v2_payout_interval(nodus_witness_t *w, uint64_t *out) {
    if (!w || !w->db || !out) return -2;

    int present = nodus_witness_v2_gen_stored_doc_present(w);
    if (present < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "payout interval: the genesis document "
                      "probe faulted — a probe fault is never 'no "
                      "document'");
        return -2;
    }
    if (present == 0) {
        if (w->v2_successor) {
            /* A version-3 chain stores its document at derivation
             * (nodus_witness_v2_gen_derive_v3) and a joiner stores it at
             * adopt (nodus_witness_v2_bundle.c) — its absence here is a
             * broken database, never a chain with no interval. */
            QGP_LOG_ERROR(LOG_TAG, "%s", "payout interval: this version-3 "
                          "chain has no stored genesis document — refusing");
            return -2;
        }
        /* A database that is not a version-3 successor and has no
         * document: nothing committed the interval, so the version-3
         * default stands — the econ band's "present == 0 → compiled
         * constants" rule (nodus_witness_v2_econ_params_load above).
         * tokenomics-v3 P4 deleted the version-2 engine genesis
         * (nodus_witness_v2_genesis_ex) that used to build such chains;
         * no genesis left in the tree does. */
        *out = (uint64_t)NODUS_V2_GEN_PAYOUT_INTERVAL_EPOCHS_DEFAULT;
        return 0;
    }

    nodus_v2_gen_config_t *cfg = calloc(1, sizeof(*cfg));   /* ~240 KB */
    nodus_v2_gen_alloc_t  *allocs = NULL;
    if (!cfg) return -2;
    int rc = nodus_witness_v2_gen_stored_doc(w, cfg, &allocs);
    uint64_t v = cfg->payout_interval_epochs;
    free(allocs);
    free(cfg);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "payout interval: the stored genesis "
                      "document does not read back — refusing");
        return -2;
    }
    if (v == 0) {
        /* nodus_witness_v2_gen_v3_validate refuses a 0 interval, so a
         * document that read back cannot carry one; checked anyway
         * because the payday rule divides by it. */
        QGP_LOG_ERROR(LOG_TAG, "%s", "payout interval: the document says 0 "
                      "— refusing");
        return -2;
    }
    *out = v;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 3 — the typed-effect UTXO batch (the payday's writer)
 * ════════════════════════════════════════════════════════════════════ */

/* One typed-effect batch. DNA_EFFECT_MAX_COUNT (64) is the codec's hard
 * ceiling on a single result, so a payday with more accrual rows applies
 * SEVERAL results. Batching changes only the INSERT order, never the row
 * set: every root loader in this tree scans with an explicit total-order
 * ORDER BY on a unique key, so the committed roots are batch-boundary
 * independent. */
typedef struct {
    nodus_witness_t                 *w;
    const nodus_domain_runtime_t    *rt;
    dna_effect_in_t   in[DNA_EFFECT_MAX_COUNT];
    /* the canonical-order permutation and the sorted copy handed to the
     * encoder — in the HEAP struct, not on the apply engine's stack */
    dna_effect_in_t   sorted[DNA_EFFECT_MAX_COUNT];
    uint16_t          ord[DNA_EFFECT_MAX_COUNT];
    uint8_t           key[DNA_EFFECT_MAX_COUNT][64];
    uint8_t           val[DNA_EFFECT_MAX_COUNT][NODUS_RT_CORE_UTXO_REC_LEN];
    uint8_t           enc[DNA_EFFECT_MAX_TOTAL_LEN];
    uint16_t          n;        /* effects staged in this batch          */
    uint32_t          emitted;  /* payout rows written across all batches*/
} v2ec_batch_t;

/* Apply the staged effects, then empty the batch. @return 0 / -2. */
static int v2ec_flush(v2ec_batch_t *b) {
    if (b->n == 0) return 0;

    /* CANONICAL ORDER is a codec REQUIREMENT, not a preference: encode
     * rejects a non-ascending result outright (effect_wire.c). The
     * total order is (effect_kind, op_id, key bytes); every effect staged
     * here is a CREATE on the CORE UTXO op, so the 64-byte key alone
     * decides. Sorting a PERMUTATION keeps each dna_effect_in_t pointing
     * at its own key and value buffers. Insertion sort: n <= 64, and it
     * is deterministic on every node for the same input. */
    for (uint16_t i = 0; i < b->n; i++) b->ord[i] = i;
    for (uint16_t a = 1; a < b->n; a++) {
        uint16_t k = b->ord[a];
        int p = (int)a - 1;
        while (p >= 0 && memcmp(b->key[b->ord[p]], b->key[k], 64) > 0) {
            b->ord[p + 1] = b->ord[p];
            p--;
        }
        b->ord[p + 1] = k;
    }
    for (uint16_t i = 0; i < b->n; i++) b->sorted[i] = b->in[b->ord[i]];

    size_t wlen = 0;
    if (dna_effect_result_encode(b->sorted, b->n, b->enc, sizeof(b->enc),
                                 &wlen) != 0) {
        /* The only inputs are this module's own effects, so a reject
         * means a duplicate payout identity or a shape this build got
         * wrong — never peer data. Fail closed either way. */
        QGP_LOG_ERROR(LOG_TAG, "payday: encoding %u payout effects was "
                      "refused by the codec", (unsigned)b->n);
        return -2;
    }

    dna_effect_view_t view;
    if (dna_effect_result_decode(b->enc, wlen, &view) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "payday: this node could not decode its own encoded "
                      "effect result");
        return -2;
    }

    uint16_t fail_index = 0;
    nodus_adapter_status_t st =
        nodus_witness_v2_effects_apply(b->w, b->rt, &view, &fail_index);
    if (st != NODUS_ADAPTER_OK) {
        /* PRE_ABSENT is what makes a colliding payout identity fail here
         * instead of vanishing the way V1's INSERT OR IGNORE did
         * (bft.c:3166). Deliberately fail-closed. */
        QGP_LOG_ERROR(LOG_TAG,
                      "payday: effect %u of %u was refused by the CORE "
                      "adapter (status %d)", (unsigned)fail_index,
                      (unsigned)b->n, (int)st);
        return -2;
    }
    b->n = 0;
    return 0;
}

/* Stage one payout row to the RAW 64-byte owner fingerprint. @return 0 /
 * -2. */
static int v2ec_emit(v2ec_batch_t *b, const uint8_t owner_fp[64],
                     uint64_t amount, const uint8_t tx_hash[64],
                     uint8_t kind, uint32_t output_index,
                     uint64_t block_height) {
    if (b->n == (uint16_t)DNA_EFFECT_MAX_COUNT && v2ec_flush(b) != 0)
        return -2;

    uint16_t s = b->n;
    if (nodus_witness_v2_settlement_nullifier(tx_hash, kind, output_index,
                                              b->key[s]) != 0)
        return -2;

    /* Owner = lowercase hex of the raw fingerprint, the V1 encoding at
     * bft.c:3054-3057. `qgp_fp_raw_to_hex` NUL-terminates at 128, and
     * the record builder copies exactly 128. */
    char fp_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(owner_fp, fp_hex);

    /* Native DNAC token id = 64 zeros (bft.c:3058-3059). */
    static const uint8_t native_token[64] = {0};

    /* unlock_block 0: payday rewards are spendable immediately — V1
     * passes 0 at bft.c:3264, :3316 and :3336. */
    if (nodus_rt_core_utxo_create_eff(&b->in[s], b->val[s], b->key[s],
                                      fp_hex, amount, native_token,
                                      tx_hash, output_index, block_height,
                                      0) != 0)
        return -2;

    b->n++;
    b->emitted++;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 4 — the epoch reward distribution (design §7 P2-6 as REVISED by
 * §7.1 "P2-6 rev 2": the governing snapshot's own power between
 * members, the source copy src(H) inside a member, a consistency gate
 * between the two). Contract: the header.
 * ════════════════════════════════════════════════════════════════════ */

/* v2_reward_accrual[owner_fp] += x, READ FIRST and bound to the observed
 * value (the O11 STATS EXISTS_VERSION discipline: an absolute write bound
 * to what this transaction observed, never a blind relative UPDATE).
 * x == 0 writes nothing — a zero accrual row is never created (the
 * accrual_root loader refuses one). @return 0 / -2. */
static int v2ec_accrue(nodus_witness_t *w, const uint8_t owner_fp[64],
                       uint64_t x) {
    if (x == 0) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount FROM v2_reward_accrual WHERE owner_fp = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    if (sqlite3_bind_blob(st, 1, owner_fp, 64, SQLITE_TRANSIENT)
        != SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    int rc = sqlite3_step(st);
    int has = (rc == SQLITE_ROW);
    sqlite3_int64 cur = has ? sqlite3_column_int64(st, 0) : 0;
    sqlite3_finalize(st);
    if (!has && rc != SQLITE_DONE) return -2;
    if (has && cur <= 0) {
        QGP_LOG_ERROR(LOG_TAG, "accrual row holds %lld — corrupt",
                      (long long)cur);
        return -2;
    }

    uint64_t nv = 0;
    if (dna_ck_add_u64((uint64_t)cur, x, &nv) != 0 || nv > V2EC_STORE_MAX)
        return -2;

    if (has) {
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_reward_accrual SET amount = ?1 "
                "WHERE owner_fp = ?2 AND amount = ?3", -1, &st, NULL)
            != SQLITE_OK)
            return -2;
        if (sqlite3_bind_int64(st, 1, (sqlite3_int64)nv) != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, owner_fp, 64, SQLITE_TRANSIENT)
                != SQLITE_OK ||
            sqlite3_bind_int64(st, 3, cur) != SQLITE_OK) {
            sqlite3_finalize(st);
            return -2;
        }
    } else {
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_reward_accrual (owner_fp, amount) "
                "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            return -2;
        if (sqlite3_bind_blob(st, 1, owner_fp, 64, SQLITE_TRANSIENT)
                != SQLITE_OK ||
            sqlite3_bind_int64(st, 2, (sqlite3_int64)nv) != SQLITE_OK) {
            sqlite3_finalize(st);
            return -2;
        }
    }
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) return -2;
    return 0;
}

/* One (owner, amount) row this module reads: a copy(src) row of a
 * member, or an accrual row. */
typedef struct {
    uint8_t  fp[64];
    uint64_t amount;
} v2ec_row_t;

/* The copy(`epoch_start`) rows of ONE member, owner_fp ASC (the owner_fp
 * order the delegators are paid in). @return 0 / -2. */
static int v2ec_member_copy(nodus_witness_t *w, uint64_t epoch_start,
                            const uint8_t vfp[64], v2ec_row_t **out,
                            size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner_fp, amount FROM v2_balance_copy "
            "WHERE epoch_start = ?1 AND validator_fp = ?2 "
            "ORDER BY owner_fp ASC", -1, &st, NULL) != SQLITE_OK)
        return -2;
    if (sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start) != SQLITE_OK ||
        sqlite3_bind_blob(st, 2, vfp, 64, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    size_t cap = 0, n = 0;
    v2ec_row_t *arr = NULL;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *fp = sqlite3_column_blob(st, 0);
        int fp_len = sqlite3_column_bytes(st, 0);
        sqlite3_int64 a = sqlite3_column_int64(st, 1);
        if (!fp || fp_len != 64 || a < 0) {
            sqlite3_finalize(st);
            free(arr);
            return -2;
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            v2ec_row_t *na = realloc(arr, nc * sizeof(*na));
            if (!na) { sqlite3_finalize(st); free(arr); return -2; }
            arr = na;
            cap = nc;
        }
        memcpy(arr[n].fp, fp, 64);
        arr[n].amount = (uint64_t)a;
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) { free(arr); return -2; }
    *out = arr;
    *n_out = n;
    return 0;
}

/* tokenomics-v3 P3-1 — one validator's FROZEN totals in copy(epoch_start).
 * Contract: nodus_witness_v2_econ.h. The SAME per-member reader the
 * distribution's consistency gate uses (v2ec_member_copy), so the
 * selector that writes a snapshot entry and the gate that checks it
 * against the copy cannot read the copy two different ways. */
int nodus_witness_v2_balance_copy_frozen(nodus_witness_t *w,
                                         uint64_t epoch_start,
                                         const uint8_t *pubkey,
                                         uint64_t *self_out,
                                         uint64_t *total_out) {
    if (!w || !w->db || !pubkey || !self_out || !total_out) return -1;
    if (epoch_start > V2EC_STORE_MAX) return -1;

    uint8_t vfp[64];
    if (qgp_sha3_512(pubkey, DNAC_PUBKEY_SIZE, vfp) != 0) return -1;
    v2ec_row_t *rows = NULL;
    size_t n = 0;
    if (v2ec_member_copy(w, epoch_start, vfp, &rows, &n) != 0) return -1;

    uint64_t self = 0, total = 0;
    int ret = 0;
    for (size_t i = 0; i < n; i++) {
        if (memcmp(rows[i].fp, vfp, 64) == 0)
            self = rows[i].amount;          /* PK: at most one self row */
        if (dna_ck_add_u64(total, rows[i].amount, &total) != 0) {
            ret = -1;
            break;
        }
    }
    free(rows);
    if (ret != 0) return -1;
    *self_out = self;
    *total_out = total;
    return 0;
}

/* floor(a × b / d), 128-bit intermediate. The callers guarantee d != 0
 * and a result <= a (b <= d), so the quotient always fits 64 bits. */
static uint64_t v2ec_muldiv(uint64_t a, uint64_t b, uint64_t d) {
    uint64_t rem = 0;
    qgp_u128_t num = qgp_u128_mul_u64(qgp_u128_from_u64(a), b);
    return qgp_u128_div_u64(num, d, &rem).lo;
}

/* One member of the governing snapshot, loaded and checked (pass 1 of
 * the distribution). The copy array is owned here and freed by
 * v2ec_member_release on every path. */
typedef struct {
    int         has_row;   /* 1 a `validators` row exists at H          */
    uint8_t     vfp[64];   /* raw SHA3-512(pubkey) — the accrual key     */
    v2ec_row_t *copy;      /* its copy(src) rows, owner_fp ASC           */
    size_t      n_copy;
    uint64_t    sum_d;     /* Σ a_d: every copy(src) row but the self row */
    uint64_t    power;     /* the entry's total_stake / DNAC_DECIMAL_UNIT */
} v2ec_member_t;

static void v2ec_member_release(v2ec_member_t *m) {
    free(m->copy);
    m->copy = NULL;
}

/* The copy a governing snapshot was built FROM, for the distribution at
 * boundary H (design §8 P3-2, revising §7.1 "P2-6 rev 2"):
 *
 *   src(H) = H − 3E  when H >= 3E, else 0
 *
 * The distribution at H pays the epoch (H−E, H], governed by
 * snapshot(H−E). Under P3-1's "okuma B" the snapshot the commit_next of
 * boundary B stores for B+E ranks its set by the FROZEN totals of
 * copy(B−E) and writes exactly those totals into the entries
 * (nodus_committee_compute_for_epoch, nodus_witness_committee.c;
 * vset_build_snapshot, nodus_witness_vset.c). snapshot(H−E) was built at
 * B = H−2E, so it was built from copy(H−3E). The boundary cases:
 *
 *   H = E    governing snapshot(0)  — genesis, built by
 *            nodus_witness_vset_commit_genesis from the genesis rows; the
 *            engine genesis writes copy(0) from the SAME rows
 *            (nodus_witness_v2_apply.c, both nodus_witness_v2_balance_
 *            copy_write(w, 0) calls). src = 0.
 *   H = 2E   governing snapshot(E)  — genesis, same rows. src = 0.
 *   H = 3E   governing snapshot(2E) — built at boundary E, reading
 *            copy(E − E) = copy(0). src = 3E − 3E = 0.
 *   H = 4E   governing snapshot(3E) — built at boundary 2E, reading
 *            copy(E). src = 4E − 3E = E.
 * and in general H >= 3E reads copy(H − 3E).
 *
 * RETENTION (nodus_witness_v2_balance_copy_write step 4: boundary B keeps
 * B−2E, B−E and B). copy(H−3E) was written at boundary H−3E; the prunes
 * of boundaries H−2E (below H−4E) and H−E (below H−3E) both keep it;
 * THIS distribution runs at step 1b of boundary H
 * (nodus_witness_v2_epoch_boundary_apply), BEFORE boundary H's own step
 * 6 prunes below H−2E. copy(0) is kept by boundaries E and 2E (neither
 * prunes: B < 2E, resp. "below 0") and first deleted by boundary 3E's
 * step 6 — after boundary 3E's distribution read it. Moving the
 * distribution after step 6 would read a deleted copy. */
static uint64_t v2ec_source_copy(uint64_t boundary_height) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    return boundary_height >= 3 * E ? boundary_height - 3 * E : 0;
}

/* PASS 1 — load ONE member of the governing snapshot and CHECK it
 * against the copy it was built from (design §7.1 "Tutarlılık kapısı"):
 *
 *   copy(src) self row amount       == entry.self_bond
 *                                      (an ABSENT self row counts 0)
 *   Σ copy(src) delegator rows      == entry.total_stake − entry.self_bond
 *
 * Since tokenomics-v3 P3-1 ("okuma B") the two sides are the SAME rows
 * read twice: the entry's total_stake and self_bond were written by the
 * commit_next that built the snapshot FROM copy(src) — total = the
 * member's own copy row + Σ its delegator rows, self_bond = its own row
 * (nodus_committee_compute_for_epoch, nodus_witness_committee.c) — and
 * v2ec_source_copy names exactly that copy. For the genesis-governed
 * epochs the entry comes from the live genesis rows (bootstrap path)
 * and copy(0) from the same rows (self_stake as the self row, no
 * delegation — every genesis writes none). On an honest node the gate
 * holds by construction; a mismatch is therefore local corruption of
 * one node's copy or snapshot (or a source-copy key that drifted out of
 * step with the selector — the coupled triple, nodus_witness_v2_epoch.h
 * nodus_v2_power_exit_boundary) — it halts rather than pays silently
 * wrong (design §7.1; threat G6: the chain stops at that boundary).
 * FAULT -2.
 *
 * `power` is the entry's own voting power, total_stake / DNAC_DECIMAL_UNIT
 * — the unit the ValidatorUpdate cometbft is told uses. `has_row` is
 * whether a `validators` row exists at H (a member without one is NOT
 * paid in pass 2, its share stays in the pool). Every read is
 * three-valued: a fault is -2, never a value. @return 0 / -2. */
static int v2ec_member_load(nodus_witness_t *w, uint64_t src,
                            uint64_t boundary_height,
                            const dna_vset_entry_t *e, v2ec_member_t *m) {
    dnac_validator_record_t cur;
    memset(&cur, 0, sizeof(cur));
    int vrc = nodus_validator_get(w, e->pubkey, &cur);
    if (vrc < 0 || vrc > 1) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "distribution: a member's validators "
                      "row is unreadable — refusing rather than guessing "
                      "whether it exists");
        return -2;
    }
    m->has_row = (vrc == 0);
    if (qgp_sha3_512(e->pubkey, DNAC_PUBKEY_SIZE, m->vfp) != 0) return -2;

    if (e->self_bond > e->total_stake) {
        QGP_LOG_ERROR(LOG_TAG, "distribution at %llu: snapshot entry "
                      "carries self_bond %llu above total_stake %llu — "
                      "corrupt", (unsigned long long)boundary_height,
                      (unsigned long long)e->self_bond,
                      (unsigned long long)e->total_stake);
        return -2;
    }
    if (v2ec_member_copy(w, src, m->vfp, &m->copy, &m->n_copy) != 0)
        return -2;

    uint64_t self = 0, sum_d = 0;
    for (size_t i = 0; i < m->n_copy; i++) {
        if (memcmp(m->copy[i].fp, m->vfp, 64) == 0) {
            self = m->copy[i].amount;        /* PK: at most one self row */
            continue;
        }
        if (dna_ck_add_u64(sum_d, m->copy[i].amount, &sum_d) != 0)
            return -2;
    }
    if (self != e->self_bond || sum_d != e->total_stake - e->self_bond) {
        QGP_LOG_ERROR(LOG_TAG, "distribution at %llu: copy(%llu) disagrees "
                      "with the governing snapshot for a member (self %llu "
                      "vs self_bond %llu, delegated %llu vs %llu) — the two "
                      "were built from one state; refusing to pay",
                      (unsigned long long)boundary_height,
                      (unsigned long long)src, (unsigned long long)self,
                      (unsigned long long)e->self_bond,
                      (unsigned long long)sum_d,
                      (unsigned long long)(e->total_stake - e->self_bond));
        return -2;
    }
    m->sum_d = sum_d;
    m->power = e->total_stake / (uint64_t)DNAC_DECIMAL_UNIT;
    return 0;
}

/* PASS 2 — pay ONE loaded member its `share` into the accrual table
 * (the inner split, design §7.1 "P2-6 rev 2"):
 *
 *   base       = floor(share × self_bond / total_stake)   (the entry's
 *                own fields — pass 1 proved they match copy(src))
 *   gross      = share − base
 *   commission = floor(gross × commission_bps / 10000)    (the entry's,
 *                frozen with the set)
 *   net        = gross − commission
 *   x_d        = floor(net × a_d / Σa_d), a_d the delegator's copy(src)
 *                amount, delegators in owner_fp ASC order
 *
 * base + commission accrue to the validator's fp, each x_d to its
 * delegator's fp. Σa_d == 0 with net > 0 leaves net in the pool (pass 1
 * makes Σa_d == total_stake − self_bond, so net is 0 then anyway).
 * `*accrued_out` receives what was credited. Returns -2 on a fault; a
 * member that is not paid (no row, bar missed, zero share) returns 0
 * with *accrued_out == 0 — its whole share, delegators included, stays
 * in the pool (decision §3 "P2 tasarım soruları" (2)). */
static int v2ec_pay_member(nodus_witness_t *w, uint64_t boundary_height,
                           const dna_vset_entry_t *e,
                           const v2ec_member_t *m, uint64_t share,
                           uint64_t *accrued_out) {
    *accrued_out = 0;
    if (share == 0) return 0;
    if (!m->has_row) return 0;            /* no row: share stays in pool */

    /* ── the shared participation predicate (P1, "tek kural, iki
     * tüketici"): a miss forfeits the WHOLE share, delegators included
     * (decision §3 "P2 tasarım soruları" (2)). ─────────────────────── */
    int meets = 0;
    if (nodus_witness_v2_attendance_meets_bar(w, e->pubkey, boundary_height,
                                              &meets) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "distribution: a member's attendance "
                      "is unreadable — refusing");
        return -2;
    }
    if (!meets) return 0;

    if (e->commission_bps > (uint16_t)DNAC_COMMISSION_BPS_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "distribution: snapshot entry carries "
                      "commission %u bps — corrupt",
                      (unsigned)e->commission_bps);
        return -2;
    }

    /* share > 0 implies power > 0 (share = floor(payout × power /
     * Σpower)), hence total_stake > 0; checked anyway because it is the
     * divisor below. self_bond <= total_stake was proven in pass 1, so
     * base <= share. */
    if (e->total_stake == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "distribution: a member with a "
                      "nonzero share carries total_stake 0 — refusing");
        return -2;
    }

    const uint64_t base  = v2ec_muldiv(share, e->self_bond, e->total_stake);
    const uint64_t gross = share - base;
    const uint64_t commission =
        v2ec_muldiv(gross, (uint64_t)e->commission_bps, 10000ULL);
    const uint64_t net = gross - commission;

    uint64_t credited = 0;
    /* the validator: its own-bond base + the commission */
    {
        uint64_t vx = 0;
        if (dna_ck_add_u64(base, commission, &vx) != 0) return -2;
        if (v2ec_accrue(w, m->vfp, vx) != 0) return -2;
        credited = vx;
    }
    /* every delegator of copy(src), owner_fp ASC (the copy reader's own
     * ORDER BY) — its share of `net` by its frozen amount a_d */
    if (net > 0 && m->sum_d > 0) {
        for (size_t i = 0; i < m->n_copy; i++) {
            if (memcmp(m->copy[i].fp, m->vfp, 64) == 0) continue;
            uint64_t x = v2ec_muldiv(net, m->copy[i].amount, m->sum_d);
            if (v2ec_accrue(w, m->copy[i].fp, x) != 0) return -2;
            if (dna_ck_add_u64(credited, x, &credited) != 0) return -2;
        }
    }
    /* Σ credited <= share by construction (every factor above is <= its
     * divisor); a violation would mean this function mis-counted, so it
     * is a fault, never a pay-out beyond the share. */
    if (credited > share) return -2;
    *accrued_out = credited;
    return 0;
}

int nodus_witness_v2_settlement_apply(nodus_witness_t *w,
                                      uint64_t boundary_height,
                                      nodus_v2_epoch_fault_fn fault,
                                      void *fault_ud,
                                      uint64_t *accrued_out) {
    if (!w || !w->db || !accrued_out) return -2;
    *accrued_out = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (boundary_height < E || (boundary_height % E) != 0) return -2;
    const uint64_t epoch_start = boundary_height - E;

    /* ── the pool ─────────────────────────────────────────────────────
     * An ABSENT supply row at a boundary is a broken chain (genesis
     * writes it, nodus_witness_v2_gen.c), never "nothing to pay". */
    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int src = nodus_witness_supply_get(w, &sup);
    if (src != 0) {
        QGP_LOG_ERROR(LOG_TAG, "distribution at %llu: supply_tracking is "
                      "unreadable or absent (rc=%d) — refusing",
                      (unsigned long long)boundary_height, src);
        return -2;
    }
    const uint64_t payout = sup.reward_pool >>
                            NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    if (payout == 0) return 0;            /* an (almost) empty pool      */

    /* ── the members: the set that GOVERNED the ended epoch ─────────── */
    dna_vset_snapshot_t *snap = NULL;
    int arc = nodus_witness_v2_epoch_authority_for_epoch(w, epoch_start,
                                                         &snap, NULL, NULL);
    if (arc != 0 || !snap) {
        QGP_LOG_ERROR(LOG_TAG, "distribution at %llu: snapshot(%llu) "
                      "unreadable or absent (rc=%d) — a boundary has no "
                      "verdict class", (unsigned long long)boundary_height,
                      (unsigned long long)epoch_start, arc);
        return -2;
    }

    int ret = -2;
    const uint16_t n_mem = snap->active_count;
    const uint64_t src_epoch = v2ec_source_copy(boundary_height);
    v2ec_member_t *mem = NULL;
    uint64_t sum_power = 0, total = 0;
    if (n_mem > 0) {
        mem = calloc(n_mem, sizeof(*mem));
        if (!mem) goto done;
    }

    /* ── PASS 1: load every member, CHECK it against copy(src) (the
     * consistency gate, v2ec_member_load — a mismatch is -2), and sum
     * the governing set's power. EVERY member is counted in Σpower,
     * including one with no validators row and one that will miss the
     * attendance bar in pass 2: a forfeited share must stay in the pool,
     * never be redistributed to the members that attended (decision §3
     * "P2 tasarım soruları" (2)). The gate runs for every member BEFORE
     * anything is paid, so a divergent copy halts the boundary with the
     * pool and the accrual table untouched. ─────────────────────────── */
    for (uint16_t i = 0; i < n_mem; i++) {
        if (v2ec_member_load(w, src_epoch, boundary_height,
                             &snap->entries[i], &mem[i]) != 0)
            goto done;
        if (dna_ck_add_u64(sum_power, mem[i].power, &sum_power) != 0)
            goto done;
    }
    if (sum_power == 0) { ret = 0; goto done; }   /* no power: the payout
                                                   * stays in the pool  */

    /* ── PASS 2: share_i = floor(payout × power_i / Σpower), paid by the
     * inner split. The snapshot's committed order (hash-committed, the
     * same order cometbft is told); the per-member arithmetic is
     * independent of it — only the INSERT sequence of the accrual rows
     * follows it, and the accrual_root sorts by owner_fp. ──────────── */
    for (uint16_t i = 0; i < n_mem; i++) {
        const uint64_t share = v2ec_muldiv(payout, mem[i].power,
                                           sum_power);
        uint64_t got = 0;
        if (v2ec_pay_member(w, boundary_height, &snap->entries[i], &mem[i],
                            share, &got) != 0)
            goto done;
        if (dna_ck_add_u64(total, got, &total) != 0) goto done;
    }
    if (total > payout) goto done;        /* Σ floor(shares) <= payout   */
    if (fault && fault(fault_ud, NODUS_V2_EPST_DIST_ACCRUED, UINT32_MAX))
        goto done;

    /* ── reward_pool −= Σ credited, bound to the value this transaction
     * observed (an absolute write, never a blind relative UPDATE) ───── */
    if (total > 0) {
        if (total > sup.reward_pool) goto done;
        const uint64_t new_pool = sup.reward_pool - total;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE supply_tracking SET reward_pool = ?1 "
                "WHERE id = 1 AND reward_pool = ?2", -1, &st, NULL)
            != SQLITE_OK)
            goto done;
        if (sqlite3_bind_int64(st, 1, (sqlite3_int64)new_pool)
                != SQLITE_OK ||
            sqlite3_bind_int64(st, 2, (sqlite3_int64)sup.reward_pool)
                != SQLITE_OK) {
            sqlite3_finalize(st);
            goto done;
        }
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "distribution at %llu: the pool debit "
                          "did not land — refusing",
                          (unsigned long long)boundary_height);
            goto done;
        }
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_DIST_APPLIED, UINT32_MAX))
        goto done;

    QGP_LOG_DEBUG(LOG_TAG,
        "epoch %llu distributed at %llu: pool=%llu payout=%llu "
        "members=%u power=%llu source copy=%llu accrued=%llu",
        (unsigned long long)epoch_start,
        (unsigned long long)boundary_height,
        (unsigned long long)sup.reward_pool, (unsigned long long)payout,
        (unsigned)n_mem, (unsigned long long)sum_power,
        (unsigned long long)src_epoch, (unsigned long long)total);
    *accrued_out = total;
    ret = 0;

done:
    if (mem) {
        for (uint16_t i = 0; i < n_mem; i++) v2ec_member_release(&mem[i]);
        free(mem);
    }
    dna_vset_free(&snap);
    if (ret != 0) *accrued_out = 0;
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 5 — payday (design §7 P2-7)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_v2_payday_apply(nodus_witness_t *w,
                                  uint64_t boundary_height,
                                  uint64_t interval,
                                  nodus_v2_epoch_fault_fn fault,
                                  void *fault_ud,
                                  uint32_t *n_utxos_out) {
    if (!w || !w->db || !n_utxos_out) return -2;
    *n_utxos_out = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (interval == 0) return -2;
    if (boundary_height < E || (boundary_height % E) != 0) return -2;
    if (((boundary_height / E) % interval) != 0) return 0;   /* not a
                                                           * payday      */
    if (boundary_height > V2EC_STORE_MAX) return -2;

    /* ── every accrual row, owner_fp ASC (the payout index order) ───── */
    v2ec_row_t *rows = NULL;
    size_t n = 0, cap = 0;
    int rc;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner_fp, amount FROM v2_reward_accrual "
            "ORDER BY owner_fp ASC", -1, &st, NULL) != SQLITE_OK)
        return -2;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *fp = sqlite3_column_blob(st, 0);
        int fp_len = sqlite3_column_bytes(st, 0);
        sqlite3_int64 a = sqlite3_column_int64(st, 1);
        if (!fp || fp_len != 64 || a <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "payday: malformed accrual row — "
                          "refusing");
            sqlite3_finalize(st);
            free(rows);
            return -2;
        }
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 64;
            v2ec_row_t *nr = realloc(rows, nc * sizeof(*nr));
            if (!nr) { sqlite3_finalize(st); free(rows); return -2; }
            rows = nr;
            cap = nc;
        }
        memcpy(rows[n].fp, fp, 64);
        rows[n].amount = (uint64_t)a;
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) { free(rows); return -2; }
    if (n == 0) { free(rows); return 0; }   /* nothing accrued yet     */
    /* The payout indices 400 .. 400 + n − 1 share this boundary's
     * tx_hash with the graduation's delegation releases, whose band is
     * [NODUS_V2_GRAD_DELEG_OUT_IDX_BASE, 2^31) = [0x40000000, 0x80000000)
     * (tokenomics-v3 P3-4, moved below 2^31 by the P3 fix round —
     * nodus_witness_v2_epoch.h "THE INDEX BAND"). The kind byte already
     * separates the nullifiers; this bound keeps the (tx_hash,
     * output_index) pairs disjoint too: the last payday index
     * 400 + n − 1 stays strictly below the band's first index. It also
     * keeps every payday index below 2^31, so the signed-int readers of
     * output_index never see a narrowed value. */
    if (n > (size_t)(NODUS_V2_GRAD_DELEG_OUT_IDX_BASE -
                     NODUS_V2_SETTLE_OUT_IDX_BASE)) {
        free(rows);
        return -2;                          /* would reach the P3-4 band */
    }

    int ret = -2;
    uint8_t tx_hash[64];
    v2ec_batch_t *b = NULL;
    if (nodus_witness_v2_settlement_tx_hash(boundary_height, tx_hash) != 0)
        goto done;

    /* ~90 KB with the 64-KB encode scratch — heap, never the stack. */
    b = calloc(1, sizeof(*b));
    if (!b) goto done;
    b->w = w;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &b->rt) != 0 ||
        !b->rt) {
        /* No resolvable ACTIVE CORE runtime means this node cannot write
         * a CORE UTXO at all. Refusing is the only answer that does not
         * invent one. */
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "payday: the CORE runtime does not resolve as ACTIVE on this "
            "node — refusing to pay out");
        goto done;
    }

    for (size_t i = 0; i < n; i++) {
        if (v2ec_emit(b, rows[i].fp, rows[i].amount, tx_hash,
                      NODUS_V2_SETTLE_KIND_ACCRUAL,
                      NODUS_V2_SETTLE_OUT_IDX_BASE + (uint32_t)i,
                      boundary_height) != 0)
            goto done;
    }
    if (v2ec_flush(b) != 0) goto done;
    if (fault && fault(fault_ud, NODUS_V2_EPST_PAYDAY_EMITTED, UINT32_MAX))
        goto done;

    /* Every paid row leaves the table; exactly the rows just read. */
    if (sqlite3_prepare_v2(w->db, "DELETE FROM v2_reward_accrual",
                           -1, &st, NULL) != SQLITE_OK)
        goto done;
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || (size_t)sqlite3_changes(w->db) != n) {
        QGP_LOG_ERROR(LOG_TAG, "payday at %llu: the accrual table did not "
                      "empty as read (%zu rows) — refusing",
                      (unsigned long long)boundary_height, n);
        goto done;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_PAYDAY_APPLIED, UINT32_MAX))
        goto done;

    QGP_LOG_DEBUG(LOG_TAG, "payday at %llu: %zu accrual rows paid",
                  (unsigned long long)boundary_height, n);
    *n_utxos_out = b->emitted;
    ret = 0;

done:
    free(b);
    free(rows);
    if (ret != 0) *n_utxos_out = 0;
    return ret;
}
