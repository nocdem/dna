/**
 * Nodus — Ledger V2 O12 S2: the engine-mandatory epoch-boundary
 * transition for the (INACTIVE) V2 apply engine.
 *
 * Contract, transition order, grad_id derivation, the Rule-N
 * non-migration label and both activation obligations are documented in
 * nodus_witness_v2_epoch.h. Every source anchor cited here is a file:line
 * in THIS tree.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_econ.h"   /* O15J Faz 2 — settlement */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"

#include "dnac/dnac.h"                 /* DNAC_EPOCH_LENGTH, cooldown    */
#include "dnac/validator.h"            /* dnac_validator_record_t        */
#include "nodus/nodus_types.h"         /* NODUS_TREE_TAG_VALIDATOR       */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2EPOCH"

/* The stored SQLite INTEGER bound. Anything above it round-trips
 * NEGATIVE and would poison every later read — the rtn_token_rec_ok /
 * rtn_val_rec_ok storage-bound discipline (nodus_witness_rt_native.c
 * :3903-3905, :3918-3919). */
#define V2EP_STORE_MAX  ((uint64_t)INT64_MAX)

/* ── little BE helpers ─────────────────────────────────────────────── */

static void v2ep_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void v2ep_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* ── canonical identities (pure, no DB) ────────────────────────────── */

int nodus_witness_v2_epoch_grad_id(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                   uint64_t global_height,
                                   const uint8_t *validator_pubkey,
                                   uint8_t out_grad_id[64]) {
    if (!chain_id || !validator_pubkey || !out_grad_id) return -2;

    /* pubkey_hash = SHA3-512(NODUS_TREE_TAG_VALIDATOR ‖ pubkey) — the
     * SOURCE validators-table key derivation (nodus_types.h:189,
     * documented nodus_witness_validator.h:31-37). */
    uint8_t pk_pre[1 + DNAC_PUBKEY_SIZE];
    pk_pre[0] = (uint8_t)NODUS_TREE_TAG_VALIDATOR;
    memcpy(pk_pre + 1, validator_pubkey, DNAC_PUBKEY_SIZE);
    uint8_t pubkey_hash[64];
    if (qgp_sha3_512(pk_pre, sizeof(pk_pre), pubkey_hash) != 0) return -2;

    /* tag(16) ‖ chain_id(32) ‖ domain(4) ‖ height(8) ‖ pubkey_hash(64) */
    uint8_t pre[NODUS_V2_EPGRAD_TAG_LEN + DNA_CHAIN_ID_LEN + 4 + 8 + 64];
    memset(pre, 0, sizeof(pre));
    memcpy(pre, NODUS_V2_EPGRAD_TAG, sizeof(NODUS_V2_EPGRAD_TAG) - 1);
    size_t off = NODUS_V2_EPGRAD_TAG_LEN;
    memcpy(pre + off, chain_id, DNA_CHAIN_ID_LEN);  off += DNA_CHAIN_ID_LEN;
    v2ep_put32(pre + off, DNA_DOMAIN_CORE);         off += 4;
    v2ep_put64(pre + off, global_height);           off += 8;
    memcpy(pre + off, pubkey_hash, 64);             off += 64;

    return qgp_sha3_512(pre, off, out_grad_id) == 0 ? 0 : -2;
}

int nodus_witness_v2_epoch_grad_nullifier(const uint8_t grad_id[64],
                                          uint8_t out_nullifier[64]) {
    if (!grad_id || !out_nullifier) return -2;
    /* SOURCE synthetic-UTXO derivation, bft.c:1772-1781. */
    uint8_t pre[64 + 1 + 4];
    memcpy(pre, grad_id, 64);
    pre[64] = NODUS_V2_EPGRAD_KIND;
    v2ep_put32(pre + 65, NODUS_V2_EPGRAD_OUT_IDX);
    return qgp_sha3_512(pre, sizeof(pre), out_nullifier) == 0 ? 0 : -2;
}

/* ── committed-row shape validation ────────────────────────────────── */

/* 128 lowercase-hex characters, NUL-terminated in the record. Mirrors
 * rtn_hex_lower_ok (nodus_witness_rt_native.c:1059-1066) + the
 * NUL-termination the legacy writer guarantees (bft.c:1591). */
static int v2ep_fp_ok(const uint8_t *fp) {
    for (size_t i = 0; i < 128; i++) {
        uint8_t c = fp[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return fp[128] == 0;
}

/* The graduation's WRITABLE-SHAPE check on a committed validators row.
 * Same conditions rtn_val_rec_ok enforces on the canonical record blob
 * (nodus_witness_rt_native.c:3906-3933) — expressed against the decoded
 * struct because this module never encodes one. A failure here is a
 * FAULT, not a verdict: see the header's obligation 1. @return 1/0.
 *
 * O15J L2-F4: EXPORTED (was static). A genesis builder that seeds
 * validator rows must be able to refuse a row this predicate would later
 * reject, because a row that fails here at the FIRST graduation boundary
 * is a deterministic chain halt (-2, the stage-2 refusal below) with no
 * recovery. A mirrored copy in the builder would drift; one authority
 * cannot. */
int nodus_witness_v2_epoch_val_rec_ok(const dnac_validator_record_t *v) {
    if (!v) return 0;
    const uint64_t u64s[] = {
        v->self_stake, v->total_delegated, v->external_delegated,
        v->pending_effective_block, v->active_since_block,
        v->unstake_commit_block, v->last_validator_update_block,
        v->consecutive_missed_epochs
    };
    for (size_t i = 0; i < sizeof(u64s) / sizeof(u64s[0]); i++)
        if (u64s[i] > V2EP_STORE_MAX) return 0;
    if (v->commission_bps > DNAC_COMMISSION_BPS_MAX ||
        v->pending_commission_bps > DNAC_COMMISSION_BPS_MAX)
        return 0;
    if (v->status > (uint8_t)DNAC_VALIDATOR_ELIGIBLE) return 0;
    return v2ep_fp_ok(v->unstake_destination_fp);
}

/* ── stage 1: pending commission activation ────────────────────────── */

/* bft.c:2379-2402 shape with ONE deliberate, labeled DIVERGENCE in the
 * match predicate — `<=` instead of the legacy `=`:
 *
 * ⚠ LEGACY ARRIVAL-HEIGHT DEPENDENCE (found by the O12 R3 review;
 * RESTATED PRECISELY by O15A — the earlier wording was overstated).
 *
 * The writer stores pending_effective_block = max(next_boundary, H+E),
 * which is ALWAYS H+E: next_boundary = floor(H/E)*E + E <= H+E, with
 * equality iff H % E == 0, so the max's boundary arm is provably dead
 * (the "unreachable max arm" label at rtn_vupd_exec).
 *
 * The legacy activator (bft.c:2386, behind the :2358 boundary gate)
 * matches pending_effective_block == block_height EXACTLY, and only runs
 * at boundaries. So activation happens iff H0 + E is boundary-aligned,
 * i.e. iff **H0 % E == 0** — iff the VALIDATOR_UPDATE was applied in a
 * block whose height is itself an exact epoch boundary.
 *
 * CORRECTION: O12 recorded this as "can NEVER fire" and a commission
 * increase being "silently stranded forever". That is too strong. It
 * fires for 1 submission height in every E, and strands the other E-1.
 * The defect is real and consequential — whether a governance change
 * takes effect depends on which block happened to include it — but it is
 * arrival-height dependent, not universally dead. It is deterministic
 * across nodes (every node sees the same height), so it is an
 * economics/governance bug, NOT a chain-split risk.
 *
 * The V2 activator honors the documented INTENT instead — "defer one
 * full epoch of delegator notice, effective at a boundary"
 * (bft.c:1917-1919, design §3.9) — by activating at the FIRST boundary
 * >= the stored height. Deterministic (pure function of committed state
 * and h). The legacy lane keeps its own behaviour: changing it would
 * alter currently accepted consensus semantics on a live chain, which is
 * a hard fork and is not O15A's to make (local BUGS.md entry).
 *
 * rc checked against SQLITE_DONE, so a mid-statement I/O error can
 * never read as "nothing to activate" (v0.18.19: a DB failure is never
 * a value). */
static int v2ep_activate_commissions(nodus_witness_t *w, uint64_t h) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE validators "
            "SET commission_bps = pending_commission_bps, "
            "    pending_commission_bps = 0, "
            "    pending_effective_block = 0 "
            "WHERE pending_effective_block != 0 "
            "  AND pending_effective_block <= ?1 "
            "  AND pending_commission_bps != 0",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "commission prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "commission step failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        return -2;
    }
    return 0;
}

/* ── stage 2 helpers ───────────────────────────────────────────────── */

/* 0 = no such row, 1 = present, -2 = fault (a probe fault is never
 * "absent" — the table_exists discipline, v2_apply.c:69-70). */
static int v2ep_utxo_present(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM utxo_set WHERE nullifier = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -2;
}

/* The release UTXO. Column set, order and encodings are EXACTLY the CORE
 * adapter's RTN_CORE_OP_UTXO CREATE insert (nodus_witness_rt_native.c
 * :2368-2393) — one canonical row shape for the V2 lane, never a second
 * convention: created_at pinned 0 (deterministic lane, audit-only column
 * excluded from the UTXO merkle leaf), token_id the all-zero native id,
 * domain_id bound EXPLICITLY (no schema default,
 * nodus_witness_v2_schema.c:211). */
static int v2ep_release_utxo(nodus_witness_t *w,
                             const uint8_t nullifier[64],
                             const uint8_t grad_id[64],
                             const uint8_t *owner_fp128,
                             uint64_t amount,
                             uint64_t block_height,
                             uint64_t unlock_block) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, "
            "token_id, tx_hash, output_index, block_height, "
            "created_at, unlock_block, domain_id) "
            "VALUES (?1, ?2, ?3, zeroblob(64), ?4, ?5, ?6, 0, ?7, ?8)",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "release prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -2;
    }
    sqlite3_bind_blob(st, 1, nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, (const char *)owner_fp128, 128,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    sqlite3_bind_blob(st, 4, grad_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)NODUS_V2_EPGRAD_OUT_IDX);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)block_height);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)unlock_block);
    sqlite3_bind_int64(st, 8, (sqlite3_int64)DNA_DOMAIN_CORE);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "release insert failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        return -2;
    }
    return 0;
}

/* active_count -= 1, READ FIRST and bound to the observed value (the
 * O11 STATS EXISTS_VERSION discipline: an absolute write bound to what
 * this transaction observed, never a blind relative UPDATE). Going below
 * zero is a fault — bft.c:2538-2553 decrements unconditionally, which on
 * a corrupt counter would store a negative value and poison
 * nodus_validator_active_count for every later reader. */
static int v2ep_active_count_dec(nodus_witness_t *w) {
    int cur = 0;
    if (nodus_validator_active_count(w, &cur) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "active_count read failed");
        return -2;
    }
    if (cur <= 0) {
        QGP_LOG_ERROR(LOG_TAG,
                      "active_count %d cannot absorb a graduation", cur);
        return -2;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE validator_stats SET value = ?1 "
            "WHERE key = 'active_count' AND value = ?2", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "active_count prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -2;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)(cur - 1));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cur);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "active_count dec failed (rc=%d)", rc);
        return -2;
    }
    return 0;
}

/* ── stage 2: RETIRING → UNSTAKED graduation ───────────────────────── */

static int v2ep_graduate(nodus_witness_t *w, uint64_t h,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         nodus_v2_epoch_fault_fn fault, void *ud,
                         uint32_t *n_out) {
    /* Candidates collected FIRST — a SELECT statement cannot stay open
     * across the UPDATEs that follow on the same table (bft.c:2406-2407).
     * ORDER BY pubkey ASC is the stable total key on every node
     * (bft.c:2417-2422); the V2 grad_id no longer DEPENDS on the rank,
     * but a deterministic scan order still fixes the write order and
     * therefore the stage-fault indices. */
    uint8_t (*cand)[DNAC_PUBKEY_SIZE] =
        calloc(DNAC_MAX_VALIDATORS, DNAC_PUBKEY_SIZE);
    if (!cand) return -2;
    size_t n = 0;
    int ret = -2;
    int rc = SQLITE_OK;

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey FROM validators WHERE status = ?1 "
            "ORDER BY pubkey ASC", -1, &sel, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "RETIRING prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_RETIRING);
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        int pk_len = sqlite3_column_bytes(sel, 0);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
            QGP_LOG_ERROR(LOG_TAG, "RETIRING pubkey wrong size (%d)",
                          pk_len);
            sqlite3_finalize(sel);
            goto done;
        }
        if (n >= (size_t)DNAC_MAX_VALIDATORS) {
            /* The table itself is capped at DNAC_MAX_VALIDATORS; more
             * RETIRING rows than that means the cap was already broken
             * (bft.c:2497-2500 relies on the same bound). */
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "more RETIRING rows than DNAC_MAX_VALIDATORS");
            sqlite3_finalize(sel);
            goto done;
        }
        memcpy(cand[n++], pk, DNAC_PUBKEY_SIZE);
    }
    sqlite3_finalize(sel);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "RETIRING scan failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        goto done;
    }

    for (size_t i = 0; i < n; i++) {
        dnac_validator_record_t v;
        if (nodus_validator_get(w, cand[i], &v) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "graduate row unreadable");
            goto done;
        }
        /* ACTIVATION OBLIGATION 1 (header): a legacy-malformed row is
         * refused, never paid out to and never rewritten. */
        if (!nodus_witness_v2_epoch_val_rec_ok(&v)) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "graduate row is legacy-malformed: refusing "
                          "the boundary (activation obligation 1)");
            goto done;
        }

        uint8_t grad_id[64], nul[64];
        if (nodus_witness_v2_epoch_grad_id(chain_id, h, v.pubkey,
                                           grad_id) != 0 ||
            nodus_witness_v2_epoch_grad_nullifier(grad_id, nul) != 0)
            goto done;

        int present = v2ep_utxo_present(w, nul);
        if (present != 0) {
            /* present == 1: the SHA3 input domains of the CORE spend
             * derivation, the O11 SYSFUND release and DNA.EPGRAD.v1 are
             * disjoint, so this cannot arise from ordinary operation —
             * only local corruption. present == -2: probe fault. */
            QGP_LOG_ERROR(LOG_TAG,
                          "graduation id already present (rc=%d)",
                          present);
            goto done;
        }

        /* unlock = H + cooldown, CHECKED, and bounded by the SQLite
         * storage maximum: an unlock height that round-trips negative
         * would make the row spendable forever. */
        uint64_t unlock = h + (uint64_t)DNAC_UNSTAKE_COOLDOWN_BLOCKS;
        if (unlock < h || unlock > V2EP_STORE_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "unlock height overflows the storage bound");
            goto done;
        }
        if (h > V2EP_STORE_MAX) goto done;

        /* S3 rule (bft.c:2482-2491): the ACTUAL self_stake, never the
         * DNAC_SELF_STAKE_AMOUNT literal — paying the literal would
         * strand a surplus bond or mint from nothing, and either way the
         * supply invariant (which sums validators.self_stake) refuses
         * the block. */
        if (v2ep_release_utxo(w, nul, grad_id, v.unstake_destination_fp,
                              v.self_stake, h, unlock) != 0)
            goto done;
        if (fault && fault(ud, NODUS_V2_EPST_GRAD_RELEASE, (uint32_t)i))
            goto done;

        /* RETIRING → UNSTAKED and ZERO the bond: its value just moved
         * into the release UTXO, and leaving it on the record too would
         * double-count it in the supply invariant's Σ self_stake term
         * (bft.c:2516-2536). Nothing else on the row moves. */
        v.status = (uint8_t)DNAC_VALIDATOR_UNSTAKED;
        v.self_stake = 0;
        if (nodus_validator_update(w, &v) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "graduate row update failed");
            goto done;
        }
        if (v2ep_active_count_dec(w) != 0) goto done;
        if (fault && fault(ud, NODUS_V2_EPST_GRAD_APPLIED, (uint32_t)i))
            goto done;
    }

    *n_out = (uint32_t)n;
    ret = 0;
done:
    free(cand);
    return ret;
}

/* ── O15C: the V2 attendance writer ─────────────────────────────────
 *
 * The mirror of nodus_witness_record_attendance (nodus_witness_bft.c
 * :3356-3428) for the V2 lane: credits ONLY the committed header
 * proposer (proposer_id = SHA3-512(pubkey)[0..31], a BlockID-bound
 * field), ACTIVE/RETIRING rows only, monotonic. Runs inside the apply
 * engine's single block transaction BEFORE any root computation — the
 * O15B.1 invariant ("a field committed by a block's state_root is never
 * mutated after that root has been calculated") holds by construction,
 * and there is deliberately NO sync/replay-side compensating writer:
 * replay reaches this exact code through the one engine. */
int nodus_witness_v2_record_attendance(nodus_witness_t *w,
                                       uint64_t global_height,
                                       const uint8_t proposer_id[32],
                                       int *credited_out) {
    if (credited_out) *credited_out = 0;
    if (!w || !w->db) return -2;
    if (!proposer_id || global_height == 0) return 0;

    /* All-zero proposer = no proposer identity committed (fixtures,
     * genesis) — nothing to credit, deterministically, everywhere. */
    {
        int nz = 0;
        for (int i = 0; i < 32; i++) if (proposer_id[i]) { nz = 1; break; }
        if (!nz) return 0;
    }

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey, last_signed_block FROM validators "
            "WHERE status IN (?, ?)", -1, &sel, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(sel, 2, (int)DNAC_VALIDATOR_RETIRING);

    uint8_t match_pk[2592];
    uint64_t match_last = 0;
    int matched = 0;
    int rc;
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        if (!pk || sqlite3_column_bytes(sel, 0) != (int)sizeof(match_pk))
            continue;
        uint8_t digest[64];
        if (qgp_sha3_512(pk, sizeof(match_pk), digest) != 0) {
            sqlite3_finalize(sel);
            return -2;
        }
        if (memcmp(digest, proposer_id, 32) != 0) continue;
        memcpy(match_pk, pk, sizeof(match_pk));
        match_last = (uint64_t)sqlite3_column_int64(sel, 1);
        matched = 1;
        break;
    }
    sqlite3_finalize(sel);
    if (!matched && rc != SQLITE_ROW && rc != SQLITE_DONE) return -2;
    if (!matched) return 0;                     /* unknown proposer: skip */
    if (global_height <= match_last) return 0;  /* monotonic             */

    sqlite3_stmt *upd = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE validators SET "
            "  last_signed_block = ?,"
            "  signed_blocks_this_epoch = signed_blocks_this_epoch + 1 "
            "WHERE pubkey = ?", -1, &upd, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_int64(upd, 1, (int64_t)global_height);
    sqlite3_bind_blob(upd, 2, match_pk, sizeof(match_pk), SQLITE_STATIC);
    int urc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (urc != SQLITE_DONE) return -2;
    if (credited_out) *credited_out = 1;
    return 0;
}

/* ── O15C: Rule N settlement (legacy bft.c:2587-2723 transplant) ───── */

static int v2ep_rule_n(nodus_witness_t *w, uint64_t h) {
    uint64_t epoch_start =
        (h > (uint64_t)DNAC_EPOCH_LENGTH) ? h - (uint64_t)DNAC_EPOCH_LENGTH
                                          : 0;

    /* a. Blame the past epoch's BASE LEADER only, from the COMMITTED
     * snapshot authority (the O12 resolver). Absence = nobody had a
     * slot = nobody blamed (the legacy past_n == 0 tolerance for
     * bootstrap/fixture epochs); a FAULT stays a fault. */
    const uint8_t *leader_pk = NULL;
    dna_vset_snapshot_t *past = NULL;
    {
        uint32_t n = 0, q = 0;
        int arc = nodus_witness_v2_epoch_authority_for_epoch(w, epoch_start,
                                                             &past, &n, &q);
        if (arc < 0) { dna_vset_free(&past); return -1; }
        if (arc == 0 && past && n > 0) {
            uint64_t epoch_num = epoch_start / (uint64_t)DNAC_EPOCH_LENGTH;
            leader_pk = past->entries[(size_t)(epoch_num % n)].pubkey;
        }
    }

    int rc;
    if (leader_pk) {
        sqlite3_stmt *inc = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE validators "
                "SET consecutive_missed_epochs = "
                "    consecutive_missed_epochs + 1 "
                "WHERE status = ? AND last_signed_block < ? "
                "  AND active_since_block + ? <= ? "
                "  AND pubkey = ?", -1, &inc, NULL) != SQLITE_OK) {
            dna_vset_free(&past);
            return -1;
        }
        sqlite3_bind_int(inc, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(inc, 2, (int64_t)epoch_start);
        sqlite3_bind_int64(inc, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS);
        sqlite3_bind_int64(inc, 4, (int64_t)h);
        sqlite3_bind_blob(inc, 5, leader_pk, 2592, SQLITE_STATIC);
        rc = sqlite3_step(inc);
        sqlite3_finalize(inc);
    } else {
        rc = SQLITE_DONE;
    }
    dna_vset_free(&past);
    if (rc != SQLITE_DONE) return -1;

    /* b. Reset for attendees. */
    {
        sqlite3_stmt *rst = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE validators SET consecutive_missed_epochs = 0 "
                "WHERE status = ? AND last_signed_block >= ?",
                -1, &rst, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int(rst, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(rst, 2, (int64_t)epoch_start);
        rc = sqlite3_step(rst);
        sqlite3_finalize(rst);
        if (rc != SQLITE_DONE) return -1;
    }

    /* c. AUTO_RETIRE past the threshold, active_count kept coherent. */
    {
        sqlite3_stmt *cnt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM validators "
                "WHERE status = ? AND consecutive_missed_epochs >= ?",
                -1, &cnt, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int(cnt, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(cnt, 2, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
        int retire_count = -1;
        if (sqlite3_step(cnt) == SQLITE_ROW)
            retire_count = sqlite3_column_int(cnt, 0);
        sqlite3_finalize(cnt);
        if (retire_count < 0) return -1;

        if (retire_count > 0) {
            sqlite3_stmt *ar = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "UPDATE validators SET status = ? "
                    "WHERE status = ? AND consecutive_missed_epochs >= ?",
                    -1, &ar, NULL) != SQLITE_OK)
                return -1;
            sqlite3_bind_int(ar, 1, (int)DNAC_VALIDATOR_AUTO_RETIRED);
            sqlite3_bind_int(ar, 2, (int)DNAC_VALIDATOR_ACTIVE);
            sqlite3_bind_int64(ar, 3, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
            rc = sqlite3_step(ar);
            sqlite3_finalize(ar);
            if (rc != SQLITE_DONE) return -1;

            sqlite3_stmt *dec = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "UPDATE validator_stats SET value = value - ? "
                    "WHERE key = 'active_count'", -1, &dec, NULL)
                != SQLITE_OK)
                return -1;
            sqlite3_bind_int(dec, 1, retire_count);
            rc = sqlite3_step(dec);
            sqlite3_finalize(dec);
            if (rc != SQLITE_DONE) return -1;

            QGP_LOG_INFO(LOG_TAG, "Rule N: auto-retired %d validator(s) "
                         "at boundary %llu", retire_count,
                         (unsigned long long)h);
        }
    }

    /* d. Per-epoch counter reset — every node enters the next epoch with
     * identical counters (the legacy settlement reset). */
    {
        char *err = NULL;
        if (sqlite3_exec(w->db,
                "UPDATE validators SET signed_blocks_this_epoch = 0 "
                "WHERE signed_blocks_this_epoch > 0",
                NULL, NULL, &err) != SQLITE_OK) {
            if (err) sqlite3_free(err);
            return -1;
        }
    }
    return 0;
}

/* ── entry point ───────────────────────────────────────────────────── */

int nodus_witness_v2_epoch_boundary_apply(
        nodus_witness_t *w, uint64_t global_height,
        const uint8_t chain_id[DNA_CHAIN_ID_LEN],
        nodus_v2_epoch_fault_fn fault, void *fault_ud,
        nodus_v2_epoch_result_t *out) {
    if (!w || !w->db || !chain_id || !out) return -2;
    memset(out, 0, sizeof(*out));

    /* GATE — bft.c:2358 mirror. Height 0 is genesis (pre-boundary); the
     * first real boundary is DNAC_EPOCH_LENGTH itself. Height only: no
     * clock, no timestamp, no domain height. */
    if (global_height == 0 ||
        (global_height % (uint64_t)DNAC_EPOCH_LENGTH) != 0)
        return 0;
    out->fired = 1;

    if (v2ep_activate_commissions(w, global_height) != 0) return -2;
    if (fault && fault(fault_ud, NODUS_V2_EPST_COMMISSIONS, UINT32_MAX))
        return -2;

    if (v2ep_graduate(w, global_height, chain_id, fault, fault_ud,
                      &out->n_graduates) != 0)
        return -2;
    if (fault && fault(fault_ud, NODUS_V2_EPST_GRAD_BATCH, UINT32_MAX))
        return -2;

    /* ── EPOCH SETTLEMENT (O15J Faz 2 — V1's economics, ported) ──────
     * Drains the epoch that JUST ENDED. The key is the canonical
     * epoch_start of the previous epoch: at H = k*E that is H - E, and
     * the gate above already proved H is a positive multiple of E, so
     * the subtraction cannot underflow.
     *
     * ORDER IS LOAD-BEARING, and the reason is written out in the
     * header ("WHY SETTLEMENT SITS AT 2b"): the attendance gate reads
     * `signed_blocks_this_epoch`, and Rule N's step (d) below RESETS
     * that column. Settling after Rule N would see zeros and burn every
     * share on every node — deterministically wrong rather than flaky,
     * which is worse, not better. Settlement therefore runs BEFORE it,
     * and deliberately does NOT repeat the reset V1 performs at its own
     * tail (bft.c:3350-3360): Rule N is about to issue exactly that
     * UPDATE, inside this same transaction. */
    if (nodus_witness_v2_settlement_apply(
            w, global_height - (uint64_t)DNAC_EPOCH_LENGTH,
            fault, fault_ud,
            &out->n_settle_utxos, &out->settle_burned) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "settlement failed at boundary %llu",
                      (unsigned long long)global_height);
        return -2;
    }

    /* ── RULE N (O15C — the transplanted legacy settlement) ──────────
     * O12 deliberately skipped Rule N because the V2 lane had no
     * attendance writer. O15C supplied it
     * (nodus_witness_v2_record_attendance, called by the apply engine
     * inside the block transaction, before roots), so the settlement now
     * runs here with the EXACT legacy semantics
     * (nodus_witness_bft.c:2587-2723), authority-resolved through the
     * committed snapshot:
     *   a. blame ONLY the past epoch's BASE LEADER (snapshot entry
     *      epoch_num % n) if it never signed in that epoch, tenure-gated;
     *   b. reset consecutive_missed_epochs for attendees;
     *   c. AUTO_RETIRE at DNAC_AUTO_RETIRE_EPOCHS, decrementing
     *      active_count once per flip;
     *   d. reset every per-epoch signed-block counter for the next epoch.
     * Ordered BEFORE the flips, mirroring the legacy boundary sequence
     * (1 commissions → 2 graduation → 2b settlement → 3 Rule N →
     *  5a flips → 5b freeze).
     *
     * O15J Faz 2: step (d) is now the ONLY writer of that reset on this
     * lane, and the settlement immediately above depends on running
     * before it. Moving Rule N earlier, or moving the reset into
     * settlement, breaks one of the two — do neither without reading the
     * header's "WHY SETTLEMENT SITS AT 2b". */
    if (v2ep_rule_n(w, global_height) != 0) return -2;
    if (fault && fault(fault_ud, NODUS_V2_EPST_RULE_N, UINT32_MAX))
        return -2;

    /* Boundary flips consume the snapshot frozen one epoch earlier; an
     * ABSENT snapshot row is a documented NO-OP inside the source
     * function (nodus_witness_vset.h:183-187), never an invented set. */
    if (nodus_witness_vset_apply_boundary_flips(w, global_height) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "boundary flips failed");
        return -2;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_BOUNDARY_FLIPS, UINT32_MAX))
        return -2;

    /* Every INPUT to the next snapshot is now final (graduations
     * applied, flips applied) and nothing is built or persisted yet —
     * the honest position of the engine's F44 (header note). */
    if (fault && fault(fault_ud, NODUS_V2_EPST_SNAPSHOT_BUILD, UINT32_MAX))
        return -2;

    /* Builds over the POST-flip POST-graduation state and keys the
     * target size on the NEXT epoch's start height; insert is
     * idempotent-or-conflict, so a diverging snapshot for the same epoch
     * fails the block (nodus_witness_vset.h:203-221). */
    if (nodus_witness_vset_commit_next(w, global_height) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "next-epoch snapshot commit failed");
        return -2;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_SNAPSHOT_PERSIST, UINT32_MAX))
        return -2;

    QGP_LOG_DEBUG(LOG_TAG, "boundary at %llu applied (%u graduates, "
                  "%u settlement utxos, %llu burned)",
                  (unsigned long long)global_height,
                  (unsigned)out->n_graduates,
                  (unsigned)out->n_settle_utxos,
                  (unsigned long long)out->settle_burned);
    return 0;
}

/* ── O12 S3: the snapshot authority resolver ────────────────────────
 * Contract, the "no N parameter by construction" argument, the
 * one-canonical-key rule and the explicit contrast against the legacy
 * fallback chain (nodus_witness_sync.c:900-913) are in the header.
 * Return convention here is the QUERY lane's 0/1/-1, NOT the boundary
 * transition's 0/-2 — also documented there. */

int nodus_witness_v2_epoch_authority_for_epoch(
        nodus_witness_t *w, uint64_t epoch_start,
        dna_vset_snapshot_t **snap_out, uint32_t *n_out,
        uint32_t *quorum_out) {
    if (!w || !w->db) return -1;

    /* ONE canonical key. A non-multiple is not "an epoch we have no row
     * for" (which would be rc 1, a legitimate terminal answer) — it is a
     * malformed question, and answering it would let two spellings of
     * one epoch become two keys. */
    if ((epoch_start % (uint64_t)DNAC_EPOCH_LENGTH) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
                      "epoch_start %llu is not a multiple of the epoch "
                      "length — not a canonical epoch key",
                      (unsigned long long)epoch_start);
        return -1;
    }

    /* The ONLY source. nodus_witness_vset_get re-hashes the stored bytes,
     * strict-decodes them and cross-checks the blob's epoch and count
     * against the row BEFORE returning anything, so a corrupt row
     * arrives here as -1 and can never become a set size. Nothing in
     * this function reads the `validators` table — the CURRENT set is
     * structurally unreachable. */
    dna_vset_snapshot_t *snap = NULL;
    int rc = nodus_witness_vset_get(w, epoch_start, &snap, NULL);
    if (rc == 1) return 1;               /* TERMINAL: no authority       */
    if (rc != 0 || !snap) {
        QGP_LOG_ERROR(LOG_TAG,
                      "epoch %llu: snapshot unreadable (rc=%d) — no "
                      "authority may be inferred",
                      (unsigned long long)epoch_start, rc);
        return -1;
    }

    /* active_count is a u16 bounded by DNA_MAX_ACTIVE_VALIDATORS and
     * proven nonzero by the codec (dna_vset_alloc/decode both reject 0),
     * so the quorum is always >= 1. Belt-and-braces: a zero here would
     * mean the codec's own invariant broke, and a quorum of 1 over an
     * empty set is the one answer that must never be produced. */
    if (snap->active_count == 0 ||
        snap->active_count > DNA_MAX_ACTIVE_VALIDATORS) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: decoded active_count %u is "
                      "outside the codec's own bounds",
                      (unsigned long long)epoch_start,
                      (unsigned)snap->active_count);
        dna_vset_free(&snap);
        return -1;
    }

    /* O15F Task 1 — defence in depth. A successor snapshot larger than
     * NODUS_V2_ACTIVE_SET_MAX can never become an authority: the writer
     * guard (nodus_witness_vset_insert) already refuses to store one, so
     * a >30 blob here means a corrupt row, which fails closed rather than
     * seating an oversized committee. Legacy chains keep the 128 bound
     * enforced above. */
    if (w->v2_successor && snap->active_count > NODUS_V2_ACTIVE_SET_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: successor snapshot active_count "
                      "%u exceeds NODUS_V2_ACTIVE_SET_MAX (%d) — refusing "
                      "as authority", (unsigned long long)epoch_start,
                      (unsigned)snap->active_count, NODUS_V2_ACTIVE_SET_MAX);
        dna_vset_free(&snap);
        return -1;
    }

    uint32_t n = (uint32_t)snap->active_count;
    if (n_out)      *n_out = n;
    if (quorum_out) *quorum_out = dna_bft_quorum(n);
    if (snap_out)   *snap_out = snap;
    else            dna_vset_free(&snap);
    return 0;
}

int nodus_witness_v2_epoch_authority_for_height(
        nodus_witness_t *w, uint64_t global_height,
        dna_vset_snapshot_t **snap_out, uint32_t *n_out,
        uint32_t *quorum_out) {
    /* Division only — the key is always <= the height, so there is no
     * height (UINT64_MAX included) this can overflow. Delegating rather
     * than duplicating means a height and its epoch cannot diverge. */
    return nodus_witness_v2_epoch_authority_for_epoch(
        w, nodus_v2_epoch_start_for_height(global_height),
        snap_out, n_out, quorum_out);
}
