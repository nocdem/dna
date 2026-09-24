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
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT (Rule N
                                                weight floor, round 6)   */

#include "dnac/dnac.h"                 /* DNAC_EPOCH_LENGTH, cooldown    */
#include "dnac/validator.h"            /* dnac_validator_record_t        */
#include "dnac/cmt_pb.h"               /* CMT_PB_BLOCK_ID_FLAG_COMMIT (Q1) */
#include "dnac/ledger_roots_v2.h"      /* dna_v2_attendance_digest (S-2) */
#include "nodus/nodus_types.h"         /* NODUS_TREE_TAG_VALIDATOR       */
#include "nodus/nodus_chain_config.h"  /* nodus_chain_config_derive_witness_id */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>                     /* snprintf (Rule N savepoint)    */
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

/* ── shared: is `pubkey` an entry of `snap`? ───────────────────────────
 * Linear scan — snap->active_count is bounded by DNA_MAX_ACTIVE_
 * VALIDATORS (128), a fixed, tiny cost. Used by v2ep_graduate (R5-3, the
 * snapshot TAKING EFFECT this boundary) and v2ep_rule_n below (R5-1, the
 * snapshot that GOVERNED the ending epoch) — one comparison, two
 * different snapshots. */
static int v2ep_pubkey_in_snapshot(const dna_vset_snapshot_t *snap,
                                   const uint8_t pubkey[DNAC_PUBKEY_SIZE]) {
    for (size_t j = 0; j < (size_t)snap->active_count; j++) {
        if (memcmp(pubkey, snap->entries[j].pubkey, DNAC_PUBKEY_SIZE) == 0)
            return 1;
    }
    return 0;
}

/* ── stage 2: RETIRING → UNSTAKED graduation ───────────────────────── */

static int v2ep_graduate(nodus_witness_t *w, uint64_t h,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         nodus_v2_epoch_fault_fn fault, void *ud,
                         uint32_t *n_out) {
    /* tokenomics-v3 P1 round 5 (decision file §3 2026-09-23, "ayrılan
     * validatorun MEZUNİYETİ … ertelenir"; O6 red-team L1-1): a
     * RETIRING/AUTO_RETIRED candidate graduates at H only if it is NOT
     * an entry of the snapshot TAKING EFFECT at H — full contract in the
     * header's GRADUATION section. Absent/unreadable snapshot(H) -> -2,
     * a boundary has no verdict class. */
    dna_vset_snapshot_t *effective = NULL;
    int erc = nodus_witness_v2_epoch_authority_for_epoch(w, h, &effective,
                                                          NULL, NULL);
    if (erc != 0 || !effective) {
        QGP_LOG_ERROR(LOG_TAG,
                      "graduate: effective snapshot for epoch %llu "
                      "unreadable (rc=%d)", (unsigned long long)h, erc);
        return -2;
    }

    /* Candidates collected FIRST — a SELECT statement cannot stay open
     * across the UPDATEs that follow on the same table (bft.c:2406-2407).
     * ORDER BY pubkey ASC is the stable total key on every node
     * (bft.c:2417-2422); the V2 grad_id no longer DEPENDS on the rank,
     * but a deterministic scan order still fixes the write order and
     * therefore the stage-fault indices. */
    uint8_t (*cand)[DNAC_PUBKEY_SIZE] =
        calloc(DNAC_MAX_VALIDATORS, DNAC_PUBKEY_SIZE);
    if (!cand) { dna_vset_free(&effective); return -2; }
    size_t n = 0;
    size_t n_graduated = 0;
    int ret = -2;
    int rc = SQLITE_OK;

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(w->db,
            /* tokenomics-v3 P1 (D-11): AUTO_RETIRED graduates the same
             * way RETIRING does — its bond is RETURNED, never cut
             * (decision §3, 2026-09-23). */
            "SELECT pubkey FROM validators WHERE status IN (?1, ?2) "
            "ORDER BY pubkey ASC", -1, &sel, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "RETIRING/AUTO_RETIRED prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_RETIRING);
    sqlite3_bind_int(sel, 2, (int)DNAC_VALIDATOR_AUTO_RETIRED);
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        int pk_len = sqlite3_column_bytes(sel, 0);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
            QGP_LOG_ERROR(LOG_TAG, "RETIRING/AUTO_RETIRED pubkey wrong "
                          "size (%d)", pk_len);
            sqlite3_finalize(sel);
            goto done;
        }
        if (n >= (size_t)DNAC_MAX_VALIDATORS) {
            /* The table itself is capped at DNAC_MAX_VALIDATORS; more
             * candidate rows than that means the cap was already broken
             * (bft.c:2497-2500 relies on the same bound). */
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "more graduation candidates than "
                          "DNAC_MAX_VALIDATORS");
            sqlite3_finalize(sel);
            goto done;
        }
        memcpy(cand[n++], pk, DNAC_PUBKEY_SIZE);
    }
    sqlite3_finalize(sel);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "RETIRING/AUTO_RETIRED scan failed "
                      "(rc=%d): %s", rc, sqlite3_errmsg(w->db));
        goto done;
    }

    for (size_t i = 0; i < n; i++) {
        /* R5-3: still an entry of the snapshot taking effect this
         * boundary -> leave it UNTOUCHED for a later boundary. No row
         * read, no counter, no status change, no fault() call — nothing
         * about this candidate is decided yet. */
        if (v2ep_pubkey_in_snapshot(effective, cand[i])) {
            QGP_LOG_INFO(LOG_TAG,
                "graduation of a RETIRING/AUTO_RETIRED validator "
                "deferred at boundary %llu — still an entry of the "
                "effective snapshot", (unsigned long long)h);
            continue;
        }

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
        /* tokenomics-v3 P1 (D-11): captured BEFORE the row is overwritten
         * below — decides whether active_count is decremented for THIS
         * graduate. */
        const uint8_t orig_status = v.status;

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

        /* RETIRING/AUTO_RETIRED → UNSTAKED and ZERO the bond: its value
         * just moved into the release UTXO, and leaving it on the record
         * too would double-count it in the supply invariant's Σ
         * self_stake term (bft.c:2516-2536). Nothing else on the row
         * moves. */
        v.status = (uint8_t)DNAC_VALIDATOR_UNSTAKED;
        v.self_stake = 0;
        if (nodus_validator_update(w, &v) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "graduate row update failed");
            goto done;
        }
        /* tokenomics-v3 P1 (D-11): active_count is decremented ONLY for
         * a graduate that WAS RETIRING. Rule N already decremented it
         * for AUTO_RETIRED at the boundary that retired it
         * (v2ep_rule_n); decrementing again here would poison
         * nodus_validator_active_count for every later reader. */
        if (orig_status == (uint8_t)DNAC_VALIDATOR_RETIRING) {
            if (v2ep_active_count_dec(w) != 0) goto done;
        }
        if (fault && fault(ud, NODUS_V2_EPST_GRAD_APPLIED, (uint32_t)i))
            goto done;
        n_graduated++;
    }

    *n_out = (uint32_t)n_graduated;
    ret = 0;
done:
    free(cand);
    dna_vset_free(&effective);
    return ret;
}

/* ── tokenomics-v3 P1: the V2 attendance writer (D-2, D-4, Q1) ────────
 * Contract: nodus_witness_v2_epoch.h. REPLACES the O15C proposer-credit
 * writer (deleted with this change). */
int nodus_witness_v2_attendance_credit(nodus_witness_t *w,
                                       uint64_t global_height,
                                       const uint8_t (*addresses)[32],
                                       const int32_t *block_id_flags,
                                       size_t n_votes) {
    if (!w || !w->db) return -2;
    if (n_votes == 0) return 0;
    if (!addresses || !block_id_flags) return -2;
    /* A block at height H carries the commit FOR H-1 (BuildLastCommitInfo);
     * a non-empty vote list at the initial height would mean the host
     * handed us decided_last_commit when execution.go's own precondition
     * says it must not exist — a node-local contract violation, not a
     * value this function can honestly report as "nothing to credit". */
    if (global_height == 0) return -2;
    const uint64_t signed_height = global_height - 1;

    for (size_t i = 0; i < n_votes; i++) {
        if (block_id_flags[i] != (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT)
            continue;                     /* Q1: NIL/ABSENT do not count */

        /* R5-7: every sqlite3_bind_* return checked. A failed bind here
         * is a node-local fault, never an insert of a NULL/zeroed key or
         * an "absent" read — either would silently misattribute or lose
         * a vote's attendance credit. */
        sqlite3_stmt *sel = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT signed_count FROM v2_attendance "
                "WHERE voter_id = ?1", -1, &sel, NULL) != SQLITE_OK)
            return -2;
        if (sqlite3_bind_blob(sel, 1, addresses[i], 32, SQLITE_TRANSIENT)
            != SQLITE_OK) {
            sqlite3_finalize(sel);
            return -2;
        }
        int rc = sqlite3_step(sel);
        int has_row = (rc == SQLITE_ROW);
        uint64_t cur = has_row ? (uint64_t)sqlite3_column_int64(sel, 0) : 0;
        sqlite3_finalize(sel);
        if (!has_row && rc != SQLITE_DONE) return -2;

        if (has_row) {
            sqlite3_stmt *upd = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "UPDATE v2_attendance SET signed_count = ?1, "
                    "last_signed_height = ?2 WHERE voter_id = ?3",
                    -1, &upd, NULL) != SQLITE_OK)
                return -2;
            if (sqlite3_bind_int64(upd, 1, (sqlite3_int64)(cur + 1))
                    != SQLITE_OK ||
                sqlite3_bind_int64(upd, 2, (sqlite3_int64)signed_height)
                    != SQLITE_OK ||
                sqlite3_bind_blob(upd, 3, addresses[i], 32,
                                  SQLITE_TRANSIENT) != SQLITE_OK) {
                sqlite3_finalize(upd);
                return -2;
            }
            int urc = sqlite3_step(upd);
            sqlite3_finalize(upd);
            if (urc != SQLITE_DONE) return -2;
        } else {
            sqlite3_stmt *ins = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_attendance (voter_id, signed_count, "
                    "last_signed_height) VALUES (?1, 1, ?2)",
                    -1, &ins, NULL) != SQLITE_OK)
                return -2;
            if (sqlite3_bind_blob(ins, 1, addresses[i], 32,
                                  SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_int64(ins, 2, (sqlite3_int64)signed_height)
                    != SQLITE_OK) {
                sqlite3_finalize(ins);
                return -2;
            }
            int irc = sqlite3_step(ins);
            sqlite3_finalize(ins);
            if (irc != SQLITE_DONE) return -2;
        }
    }
    return 0;
}

/* ── tokenomics-v3 P1: the attendance reader ──────────────────────────
 * Contract: nodus_witness_v2_epoch.h. */
int nodus_witness_v2_attendance_get(nodus_witness_t *w,
                                    const uint8_t pubkey[DNAC_PUBKEY_SIZE],
                                    uint64_t *signed_count_out,
                                    uint64_t *last_signed_height_out) {
    if (!w || !w->db || !pubkey) return -2;

    uint8_t voter_id[32];
    if (nodus_chain_config_derive_witness_id(pubkey, voter_id) != 0)
        return -2;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT signed_count, last_signed_height FROM v2_attendance "
            "WHERE voter_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -2;
    /* R5-7: bind checked — a failed bind must not be read as "absent". */
    if (sqlite3_bind_blob(st, 1, voter_id, 32, SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        sqlite3_finalize(st);
        return -2;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (signed_count_out)
            *signed_count_out = (uint64_t)sqlite3_column_int64(st, 0);
        if (last_signed_height_out)
            *last_signed_height_out = (uint64_t)sqlite3_column_int64(st, 1);
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : -2;
}

/* ── tokenomics-v3 P1 round 3 (operator 2026-09-23): the SHARED
 * participation predicate ────────────────────────────────────────────
 * Contract: nodus_witness_v2_epoch.h. ONE function, TWO callers
 * (`v2ep_rule_n` below and `nodus_witness_v2_settlement_apply`,
 * nodus_witness_v2_econ.c) — both predicates, always together, per the
 * decision text's own binding (header comment, "THE SAME PREDICATE
 * BINDS THE REWARD BAR"). */
int nodus_witness_v2_attendance_meets_bar(nodus_witness_t *w,
                                          const uint8_t
                                              pubkey[DNAC_PUBKEY_SIZE],
                                          uint64_t boundary_height,
                                          int *out) {
    if (!w || !w->db || !pubkey || !out) return -2;

    uint64_t signed_count = 0, last_signed_height = 0;
    int arc = nodus_witness_v2_attendance_get(w, pubkey, &signed_count,
                                              &last_signed_height);
    if (arc == -2) return -2;
    /* arc == 1 (absent): honest zero — never signed, never credited. */
    if (arc == 1) { signed_count = 0; last_signed_height = 0; }

    const int p1 = (signed_count * 10000ULL) >=
                   ((uint64_t)DNAC_EPOCH_LENGTH *
                    (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS);

    const uint64_t window = (uint64_t)DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS;
    const uint64_t window_floor =
        (boundary_height > window) ? boundary_height - window : 0;
    const int p2 = last_signed_height > 0 &&
                   last_signed_height >= window_floor;

    *out = (p1 && p2) ? 1 : 0;
    return 0;
}

/* ── O15C: Rule N settlement (legacy bft.c:2587-2723 transplant) ───── */

/* tokenomics-v3 P1 round 6 — the savepoint Rule N's weight floor opens
 * around its AUTO_RETIRED UPDATE (v2ep_rule_n). A fixed literal: it is
 * inlined into SQL (SAVEPOINT takes no bound parameter), and no other
 * savepoint in nodus/src uses this name, so nesting inside the block's
 * own transaction / the cometbft lane's per-item savepoints
 * (nodus_witness_v2_apply.c, `cmt_item_<n>`) can never alias it. */
#define V2EP_RULE_N_SAVEPOINT "v2ep_rule_n_retire"

/* Run one savepoint statement ("SAVEPOINT", "RELEASE SAVEPOINT" or
 * "ROLLBACK TO SAVEPOINT") on V2EP_RULE_N_SAVEPOINT. Same raw-exec shape
 * as nodus_witness_v2_pools.c's s7_startup savepoint. @return 0 / -1. */
static int v2ep_rn_savepoint(nodus_witness_t *w, const char *verb) {
    char sql[64];
    snprintf(sql, sizeof(sql), "%s " V2EP_RULE_N_SAVEPOINT, verb);
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Rule N: %s failed: %s", sql,
                      err ? err : sqlite3_errmsg(w->db));
        if (err) sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* tokenomics-v3 P1 round 6 — Rule N's weight floor verdict over the NEXT
 * epoch's snapshot (decision file §3 2026-09-23 "Rule N TABANI WEIGHT
 * ÜZERİNDEN"). Power per entry is `total_stake / DNAC_DECIMAL_UNIT` —
 * the exact unit the §A ValidatorUpdate diff reports to cometbft
 * (nodus_witness_cmt_app.c:1569). P = checked sum, m = max. Allowed iff
 * P > 0 AND (P - m) > P * 2 / 3 — cometbft's own integer form
 * (shared/dnac/cmt_validation.c:298 `needed = total * 2 / 3`, a commit
 * needs tallied > needed): the set must still commit with its single
 * largest member gone.
 *
 * @param allowed_out [out] 1 allowed / 0 not allowed.
 * @return 0 computed, -1 fault (sum or doubling overflows uint64 —
 *         unreachable at real supply, refused visibly rather than
 *         wrapped). */
static int v2ep_rn_weight_verdict(const dna_vset_snapshot_t *s,
                                  uint64_t *p_out, uint64_t *m_out,
                                  int *allowed_out) {
    uint64_t P = 0, m = 0;
    for (uint16_t i = 0; i < s->active_count; i++) {
        uint64_t p = s->entries[i].total_stake / DNAC_DECIMAL_UNIT;
        if (P > UINT64_MAX - p) return -1;
        P += p;
        if (p > m) m = p;
    }
    if (P > UINT64_MAX / 2) return -1;
    *p_out = P;
    *m_out = m;
    *allowed_out = (P > 0 && (P - m) > P * 2 / 3) ? 1 : 0;
    return 0;
}

/* tokenomics-v3 P1 round 5 (O6 verifier V-1 / red-team L3-1, L3-2; decision
 * file §3 2026-09-23 — the floor was the "Rule N TABANI = 4" entry, now
 * INVALID and replaced in round 6 by the "Rule N TABANI WEIGHT
 * ÜZERİNDEN" entry, whose contract sits above the floor block below;
 * the graduation-deferral entry between them is R5-3): a member has a
 * DUTY at boundary H iff it is an entry of the
 * COMMITTED snapshot that governed the epoch just ending,
 * snapshot(H-E) — the set flipped ACTIVE at boundary H-E and the one
 * cometbft has used since H-E+2 (its own two-height lag) — AND its row's
 * status is ACTIVE right now. Evaluating every ACTIVE row regardless of
 * duty (the round-3/4 shape) charged a miss to a validator STAKEd mid-epoch
 * (seated ACTIVE, never in the duty snapshot — V-1) and let a counter
 * survive an epoch the member had no duty in (a validator that fell out of
 * ACTIVE and later came back, or was simply never evaluated because the
 * committee shrank around it), turning two NON-consecutive misses into a
 * retirement. Every bonded row (ACTIVE or ELIGIBLE) that is NOT evaluated
 * this boundary has its counter reset to 0: an epoch without a duty breaks
 * the chain of consecutive misses. RETIRING rows are excluded from the scan
 * entirely (an exiting member cannot be auto-retired a second time).
 * Candidates collected FIRST — a SELECT statement cannot stay open across
 * the UPDATEs that follow, same discipline as v2ep_graduate above. Scan
 * order is `validators` `pubkey ASC` (NOT the duty snapshot's own order,
 * which is stake DESC with a hash tiebreak inside equal-stake groups,
 * nodus_witness_committee.c:344-359 — coupling Rule N's evaluated order to
 * a value read elsewhere, current stake, would coincidentally sort the
 * update writes and their fault-stage indices by wealth, which is neither
 * needed nor exercised by any existing fault-injection test); pubkey ASC
 * is the total, stable key every other pass in this file already commits
 * to. */
static int v2ep_rule_n(nodus_witness_t *w, uint64_t h) {
    /* R5-1: absent/unreadable duty snapshot -> the boundary has no
     * verdict class (fault, not an empty-set assumption). epoch_start
     * cannot underflow: the caller's gate already proved h is a positive
     * multiple of DNAC_EPOCH_LENGTH, so h >= E. */
    const uint64_t duty_epoch_start = h - (uint64_t)DNAC_EPOCH_LENGTH;
    dna_vset_snapshot_t *duty = NULL;
    int drc = nodus_witness_v2_epoch_authority_for_epoch(
        w, duty_epoch_start, &duty, NULL, NULL);
    if (drc != 0 || !duty) {
        QGP_LOG_ERROR(LOG_TAG,
                      "Rule N: duty snapshot for epoch %llu unreadable "
                      "(rc=%d) at boundary %llu",
                      (unsigned long long)duty_epoch_start, drc,
                      (unsigned long long)h);
        return -1;
    }
    /* Round 6: the weight floor's preview of snapshot(H+E); freed at
     * `done` on every path. */
    dna_vset_snapshot_t *next = NULL;

    uint8_t (*cand)[DNAC_PUBKEY_SIZE] =
        calloc(DNAC_MAX_VALIDATORS, DNAC_PUBKEY_SIZE);
    uint8_t *cand_status = calloc(DNAC_MAX_VALIDATORS, sizeof(uint8_t));
    uint64_t *cand_missed = calloc(DNAC_MAX_VALIDATORS, sizeof(uint64_t));
    if (!cand || !cand_status || !cand_missed) {
        free(cand); free(cand_status); free(cand_missed);
        dna_vset_free(&duty);
        return -1;
    }
    size_t n = 0;
    int rc;
    int ret = -1;

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey, status, consecutive_missed_epochs FROM "
            "validators WHERE status IN (?1, ?2) ORDER BY pubkey ASC",
            -1, &sel, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Rule N: bonded prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(sel, 2, (int)DNAC_VALIDATOR_ELIGIBLE);
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        int pk_len = sqlite3_column_bytes(sel, 0);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
            QGP_LOG_ERROR(LOG_TAG, "Rule N: bonded pubkey wrong size (%d)",
                          pk_len);
            sqlite3_finalize(sel);
            goto done;
        }
        if (n >= (size_t)DNAC_MAX_VALIDATORS) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "more bonded rows than DNAC_MAX_VALIDATORS");
            sqlite3_finalize(sel);
            goto done;
        }
        memcpy(cand[n], pk, DNAC_PUBKEY_SIZE);
        cand_status[n] = (uint8_t)sqlite3_column_int(sel, 1);
        cand_missed[n] = (uint64_t)sqlite3_column_int64(sel, 2);
        n++;
    }
    sqlite3_finalize(sel);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Rule N: bonded scan failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        goto done;
    }

    /* tokenomics-v3 P1 round 3: both predicates (bar + recency window)
     * now come from ONE shared function, `nodus_witness_v2_attendance_
     * meets_bar` — the SAME one the settlement reward bar calls
     * (nodus_witness_v2_econ.c). `h` IS the boundary height the shared
     * function's `boundary_height` parameter wants: the epoch that just
     * accumulated attendance is (h - E, h], and h never underflows the
     * window arithmetic (the gate above proved h is a positive multiple
     * of DNAC_EPOCH_LENGTH, so h >= 1). */
    {
        for (size_t i = 0; i < n; i++) {
            /* R5-1: duty membership — is cand[i] an entry of duty
             * (snapshot(H-E))? Shared helper (v2ep_pubkey_in_snapshot,
             * above v2ep_graduate) — same comparison R5-3 uses against a
             * different snapshot. */
            int in_duty = v2ep_pubkey_in_snapshot(duty, cand[i]);

            int64_t new_missed;
            if (cand_status[i] == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
                in_duty) {
                int present = 0;
                int mrc = nodus_witness_v2_attendance_meets_bar(
                    w, cand[i], h, &present);
                if (mrc != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "%s",
                                  "Rule N: attendance lookup faulted");
                    goto done;
                }
                int miss = !present;
                new_missed = miss ? (int64_t)(cand_missed[i] + 1) : 0;
            } else {
                /* No duty this boundary — ELIGIBLE (never evaluated), or
                 * ACTIVE but absent from the duty snapshot (a mid-epoch
                 * STAKE, or a member the committee shrank around). Reset,
                 * never increment: an epoch without a duty breaks the
                 * chain of consecutive misses (R5-1). */
                new_missed = 0;
            }

            sqlite3_stmt *upd = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "UPDATE validators SET consecutive_missed_epochs = ?1 "
                    "WHERE status = ?2 AND pubkey = ?3", -1, &upd, NULL)
                != SQLITE_OK) {
                QGP_LOG_ERROR(LOG_TAG, "Rule N: update prepare failed: %s",
                              sqlite3_errmsg(w->db));
                goto done;
            }
            sqlite3_bind_int64(upd, 1, (sqlite3_int64)new_missed);
            sqlite3_bind_int(upd, 2, (int)cand_status[i]);
            sqlite3_bind_blob(upd, 3, cand[i], DNAC_PUBKEY_SIZE,
                              SQLITE_STATIC);
            int urc = sqlite3_step(upd);
            sqlite3_finalize(upd);
            if (urc != SQLITE_DONE) {
                QGP_LOG_ERROR(LOG_TAG, "Rule N: update failed (rc=%d): %s",
                              urc, sqlite3_errmsg(w->db));
                goto done;
            }
        }
    }

    /* AUTO_RETIRE past the threshold, behind THE WEIGHT FLOOR —
     * tokenomics-v3 P1 round 6 (decision file §3 2026-09-23, "Rule N
     * TABANI WEIGHT ÜZERİNDEN", which replaced the round-5 count floor
     * "Rule N TABANI = 4", now marked invalid there).
     *
     * WHY A FLOOR AT ALL (unchanged from round 5): the 50% bar and the
     * 120-block recency window are two DIFFERENT conditions and can fail
     * DIFFERENT members at the same boundary (red-team L3-2: 5 of a 7-
     * member committee in one worked example, every block still
     * committing), and members leaving the set still vote one more epoch
     * while Rule N only evaluates seated ones. Retiring everyone who
     * crossed the threshold can therefore leave a next set that cannot
     * survive losing a single member — or no set at all.
     *
     * WHAT IT MEASURES (round 6): VOTING POWER of the members that will
     * actually be SEATED next epoch, not a head count of bonded rows. The
     * count floor counted ELIGIBLE rows the tenure gate will not seat
     * (nodus_witness_validator.c:311 — O6 verifier: 7 members + 1 fresh
     * staker, 4 retired, count 4, next set 3 seats), and liveness is a
     * question of power: a commit needs MORE than two-thirds of it
     * (shared/dnac/cmt_validation.c:298). The rule: with every row past
     * DNAC_AUTO_RETIRE_EPOCHS provisionally retired, build the snapshot
     * this boundary's commit_next will store for H+E
     * (nodus_witness_vset_preview_next) and require that it still commits
     * with its single LARGEST member gone — see v2ep_rn_weight_verdict.
     * An EMPTY next set is never allowed. Only ACTIVE rows can reach the
     * threshold (ELIGIBLE rows were reset above, never incremented), so
     * `retire_count` is exactly the set about to lose its seat.
     * All-or-nothing, never a partial or ranked retirement: refused ->
     * ROLLBACK TO the savepoint, NOBODY is retired, the counters keep the
     * values written above (the members go at the first boundary where
     * the survivors can carry them), active_count does not move, one WARN.
     * Same precedent as `nodus_witness_domreg_exclusions_at`
     * (nodus_witness_domreg.h:239-246, "NO exclusion happens").
     *
     * WHAT IT DOES NOT DO (open operator questions, decision file §3, not
     * this rule's job): it does not cap HOW MANY may be retired at once
     * in a large set (100 equal members, 96 retired -> 4 equal left,
     * (4-1) > 4*2/3 -> allowed); and if ONE member already holds at least
     * a third of the next set's power, it allows no retirement at all
     * (stake concentration — the pre-testnet "power cap" decision). The
     * inequality forces max < P/3, so it implies at least 4 seatable
     * members: the old count bound is a consequence, not a second rule.
     *
     * WHY THE PREVIEW IS THE SNAPSHOT commit_next STORES (brief step 3,
     * every input of nodus_committee_compute_for_epoch(w, H+E) checked
     * against what runs between this point and commit_next — the
     * attendance digest, the attendance reset and the boundary flips,
     * nodus_witness_v2_epoch_boundary_apply below):
     *   - builder: the preview and commit_next share ONE static core,
     *     vset_build_snapshot (nodus_witness_vset.c:334), keyed on the
     *     same H+E and sized by the same vset_target_for_epoch
     *     (nodus_witness_vset.c:484; commit_next reaches it through
     *     vset_build_and_store :524/:530, the preview at :709).
     *   - path: H is a positive multiple of E, so H+E >= 2E > E+1 and the
     *     bootstrap branch (nodus_witness_committee.c:247) is unreachable
     *     for both.
     *   - target: committee_target_for_epoch (nodus_witness_committee.c
     *     :98, :255) reads chain_config_history only (cache hit == miss by
     *     contract, nodus_witness_chain_config.c:316-333); none of the
     *     three steps writes it.
     *   - seed: the lookback row at H+E-E-1 = H-1 (:258) — v2_blocks +
     *     the Comet BlockMeta (:271), or the legacy `blocks` row (:279);
     *     committed by an EARLIER block, written by none of the three.
     *   - candidates: nodus_validator_top_n (:320 ->
     *     nodus_witness_validator.c:303-313) — rows with status IN
     *     (ACTIVE, ELIGIBLE), filtered on active_since_block, ordered on
     *     self_stake + external_delegated then pubkey. The digest writes
     *     v2_attendance_epoch and the reset writes v2_attendance
     *     (v2ep_attendance_digest / v2ep_attendance_reset below); the
     *     flips write ONLY validators.status, and only ACTIVE/ELIGIBLE ->
     *     ELIGIBLE then ELIGIBLE -> ACTIVE (nodus_witness_vset.c:632,
     *     :657), so the candidate SET, its stakes, tenure and order are
     *     unchanged; the tiebreak (:340) hashes pubkey with the seed; the
     *     emitted fields (emit_member :230 — pubkey, total_stake,
     *     self_stake, commission_bps) are not written by any of them.
     * test_v2_epoch.c §12g checks the stored snapshot(H+E) hash equals
     * a preview built over the SAME post-boundary state — it proves the
     * builder is shared, NOT this input-by-input argument: a step later
     * inserted here that writes a committee input would stay green
     * there. Anyone adding a step between Rule N and commit_next must
     * re-walk the list above. */
    {
        sqlite3_stmt *cnt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM validators "
                "WHERE status = ? AND consecutive_missed_epochs >= ?",
                -1, &cnt, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_int(cnt, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(cnt, 2, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
        int retire_count = -1;
        if (sqlite3_step(cnt) == SQLITE_ROW)
            retire_count = sqlite3_column_int(cnt, 0);
        sqlite3_finalize(cnt);
        if (retire_count < 0) goto done;

        if (retire_count > 0) {
            /* 1. Open the savepoint. Every statement above is finalized,
             *    so none is open across it. */
            if (v2ep_rn_savepoint(w, "SAVEPOINT") != 0) goto done;

            /* 2. Retire provisionally (the same UPDATE as before round 6)
             * 3. and preview the snapshot commit_next(h) will store for
             *    h+E over exactly that state. `step_ok` stays 0 on any
             *    fault; the verdict itself is `allowed`. */
            int step_ok = 0, allowed = 0, prc = -1;
            uint64_t pw_total = 0, pw_max = 0;
            do {
                sqlite3_stmt *ar = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "UPDATE validators SET status = ? "
                        "WHERE status = ? AND consecutive_missed_epochs >= ?",
                        -1, &ar, NULL) != SQLITE_OK) {
                    QGP_LOG_ERROR(LOG_TAG, "Rule N: retire prepare "
                                  "failed: %s", sqlite3_errmsg(w->db));
                    break;
                }
                sqlite3_bind_int(ar, 1, (int)DNAC_VALIDATOR_AUTO_RETIRED);
                sqlite3_bind_int(ar, 2, (int)DNAC_VALIDATOR_ACTIVE);
                sqlite3_bind_int64(ar, 3, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
                rc = sqlite3_step(ar);
                sqlite3_finalize(ar);
                if (rc != SQLITE_DONE) {
                    QGP_LOG_ERROR(LOG_TAG, "Rule N: retire failed "
                                  "(rc=%d): %s", rc, sqlite3_errmsg(w->db));
                    break;
                }

                prc = nodus_witness_vset_preview_next(w, h, &next);
                if (prc < 0) {
                    /* FAULT, never a verdict: a node that cannot build
                     * the next set cannot judge it (and commit_next would
                     * fail on the same inputs). */
                    QGP_LOG_ERROR(LOG_TAG, "Rule N: next-set preview "
                                  "faulted at boundary %llu",
                                  (unsigned long long)h);
                    break;
                }
                if (prc == 0 &&
                    v2ep_rn_weight_verdict(next, &pw_total, &pw_max,
                                           &allowed) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Rule N: next-set power "
                                  "overflows at boundary %llu",
                                  (unsigned long long)h);
                    break;
                }
                /* prc == 1: the next set would be EMPTY — a verdict,
                 * never allowed (allowed stays 0). */
                dna_vset_free(&next);
                step_ok = 1;
            } while (0);

            if (!step_ok) {
                /* Unwind our own savepoint so the savepoint stack the
                 * caller sees is balanced, then fail the boundary; the
                 * block's own rollback discards everything regardless
                 * (return values of the unwind are logged inside and
                 * cannot change the outcome, which is already a fault). */
                (void)v2ep_rn_savepoint(w, "ROLLBACK TO SAVEPOINT");
                (void)v2ep_rn_savepoint(w, "RELEASE SAVEPOINT");
                goto done;
            }

            if (!allowed) {
                /* 5b. Refused: undo the provisional retirement (counter
                 *     writes above predate the savepoint and stay), then
                 *     drop the savepoint. active_count untouched. */
                if (v2ep_rn_savepoint(w, "ROLLBACK TO SAVEPOINT") != 0)
                    goto done;
                if (v2ep_rn_savepoint(w, "RELEASE SAVEPOINT") != 0)
                    goto done;
                QGP_LOG_WARN(LOG_TAG,
                    "Rule N: weight floor at boundary %llu — %d would "
                    "retire, next set %s P=%llu max=%llu, needs "
                    "(P-max) > P*2/3; retiring NOBODY this boundary, "
                    "counters kept",
                    (unsigned long long)h, retire_count,
                    prc == 1 ? "EMPTY" : "power",
                    (unsigned long long)pw_total,
                    (unsigned long long)pw_max);
            } else {
                /* 5a. Allowed: keep the retirement. */
                if (v2ep_rn_savepoint(w, "RELEASE SAVEPOINT") != 0)
                    goto done;

                /* active_count decrement — READ FIRST and bound to the
                 * observed value (the same CAS discipline as
                 * v2ep_active_count_dec above; the legacy blind
                 * `value = value - ?` could store a negative counter and
                 * poison nodus_validator_active_count for every later
                 * reader). active_count counts BONDED rows plus RETIRING
                 * rows not yet graduated (STAKE increments it, UNSTAKE
                 * does not decrement it — nodus_witness_rt_native.c
                 * :3380-3381 — graduation of a RETIRING row does,
                 * v2ep_graduate); retire_count is a subset of the ACTIVE
                 * rows, so cur < retire_count is unreachable — a genuine
                 * corruption, not a value. */
                int cur = 0;
                if (nodus_validator_active_count(w, &cur) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "%s",
                                  "Rule N: active_count read failed");
                    goto done;
                }
                if (cur < retire_count) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "Rule N: active_count %d cannot absorb %d "
                        "retirement(s)", cur, retire_count);
                    goto done;
                }

                sqlite3_stmt *dec = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "UPDATE validator_stats SET value = ?1 "
                        "WHERE key = 'active_count' AND value = ?2",
                        -1, &dec, NULL) != SQLITE_OK)
                    goto done;
                sqlite3_bind_int64(dec, 1,
                    (sqlite3_int64)(cur - retire_count));
                sqlite3_bind_int64(dec, 2, (sqlite3_int64)cur);
                rc = sqlite3_step(dec);
                int dec_changed = (int)sqlite3_changes(w->db);
                sqlite3_finalize(dec);
                if (rc != SQLITE_DONE || dec_changed != 1) goto done;

                QGP_LOG_INFO(LOG_TAG, "Rule N: auto-retired %d validator(s) "
                             "at boundary %llu", retire_count,
                             (unsigned long long)h);
            }
        }
    }

    ret = 0;
done:
    free(cand);
    free(cand_status);
    free(cand_missed);
    dna_vset_free(&duty);
    dna_vset_free(&next);
    return ret;
}

/* ── tokenomics-v3 P1 (S-2): the attendance digest ────────────────────
 * Hashes every `v2_attendance` row (voter_id ASC — no status join: any
 * divergence anywhere in the table is caught, not just among seated
 * validators) into ONE digest for the epoch that JUST ENDED
 * (`epoch_start = H - E`) and inserts it into `v2_attendance_epoch`.
 * This is the ONLY point at which the out-of-root attendance table's
 * contents enter `system_state_root` (the `attendance_root` leg). */
static int v2ep_attendance_digest(nodus_witness_t *w, uint64_t epoch_start) {
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT voter_id, signed_count, last_signed_height "
            "FROM v2_attendance ORDER BY voter_id ASC", -1, &sel, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "attendance digest scan prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 16, n = 0;
    dna_v2_attendance_row_t *rows = calloc(cap, sizeof(*rows));
    if (!rows) { sqlite3_finalize(sel); return -1; }

    int rc;
    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            dna_v2_attendance_row_t *nr = realloc(rows, nc * sizeof(*nr));
            if (!nr) { free(rows); sqlite3_finalize(sel); return -1; }
            rows = nr; cap = nc;
        }
        const void *vid = sqlite3_column_blob(sel, 0);
        int vid_len = sqlite3_column_bytes(sel, 0);
        if (!vid || vid_len != 32) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "attendance row voter_id wrong size — failing "
                          "the digest");
            free(rows);
            sqlite3_finalize(sel);
            return -1;
        }
        memcpy(rows[n].voter_id, vid, 32);
        rows[n].signed_count = (uint64_t)sqlite3_column_int64(sel, 1);
        rows[n].last_signed_height =
            (uint64_t)sqlite3_column_int64(sel, 2);
        n++;
    }
    sqlite3_finalize(sel);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "attendance digest scan failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        free(rows);
        return -1;
    }

    uint8_t digest[64];
    int drc = dna_v2_attendance_digest(epoch_start, rows, n, digest);
    free(rows);
    if (drc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "attendance digest computation failed for "
                      "epoch %llu", (unsigned long long)epoch_start);
        return -1;
    }

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_attendance_epoch (epoch_start, digest) "
            "VALUES (?1, ?2)", -1, &ins, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(ins, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_blob(ins, 2, digest, 64, SQLITE_TRANSIENT);
    int irc = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (irc != SQLITE_DONE) {
        /* A duplicate key (SQLITE_CONSTRAINT) means this epoch's digest
         * was already written — a FAULT, never a value: two different
         * digests for one epoch_start would be a leg-level divergence. */
        QGP_LOG_ERROR(LOG_TAG, "attendance digest insert failed for "
                      "epoch %llu (rc=%d): %s",
                      (unsigned long long)epoch_start, irc,
                      sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── tokenomics-v3 P1: the attendance reset ───────────────────────────
 * `signed_count` only — `last_signed_height` is the P2 watermark Rule N
 * needs at the NEXT boundary and is never reset. MUST run AFTER the
 * digest (v2ep_attendance_digest): resetting first would digest all
 * zeros and hide every divergence the leg exists to catch. */
static int v2ep_attendance_reset(nodus_witness_t *w) {
    char *err = NULL;
    if (sqlite3_exec(w->db,
            "UPDATE v2_attendance SET signed_count = 0 "
            "WHERE signed_count > 0",
            NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return -1;
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

    /* ── 1b. THE REWARD DISTRIBUTION (tokenomics-v3 P2, P2-6) ─────────
     * Pays the epoch (H−E, H] that JUST ENDED into the per-recipient
     * accrual. ORDER IS LOAD-BEARING — the header's "WHY THE
     * DISTRIBUTION SITS AT 1b": it reads the ended epoch's attendance
     * (zeroed by the reset at 3c) and the source balance copy
     * copy(H−2E), which this boundary's step 6 prunes. It deliberately
     * does NOT reset attendance itself: step 3c does, inside this same
     * transaction. */
    if (nodus_witness_v2_settlement_apply(w, global_height, fault, fault_ud,
                                          &out->dist_accrued) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "reward distribution failed at boundary "
                      "%llu", (unsigned long long)global_height);
        return -2;
    }

    /* ── 1c. PAYDAY (tokenomics-v3 P2, P2-7) ──────────────────────────
     * AFTER 1b, so a paying boundary pays the epoch it just credited
     * too. The interval is the chain's own (its stored genesis
     * document); a read fault is a fault, never "not a payday". */
    {
        uint64_t interval = 0;
        if (nodus_witness_v2_payout_interval(w, &interval) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "payout interval unreadable at "
                          "boundary %llu", (unsigned long long)global_height);
            return -2;
        }
        if (nodus_witness_v2_payday_apply(w, global_height, interval,
                                          fault, fault_ud,
                                          &out->n_payday_utxos) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "payday failed at boundary %llu",
                          (unsigned long long)global_height);
            return -2;
        }
    }

    if (v2ep_graduate(w, global_height, chain_id, fault, fault_ud,
                      &out->n_graduates) != 0)
        return -2;
    if (fault && fault(fault_ud, NODUS_V2_EPST_GRAD_BATCH, UINT32_MAX))
        return -2;

    /* ── RULE N (tokenomics-v3 P1, D-3 — REWRITTEN) ───────────────────
     * Every ACTIVE row with a duty evaluated against the committed
     * `v2_attendance` table; no base-leader blame, no tenure gate on the
     * evaluation; AUTO_RETIRE at DNAC_AUTO_RETIRE_EPOCHS behind the
     * round-6 WEIGHT floor, decrementing active_count once per flip.
     * RETIRING rows are not evaluated. The weight floor previews the
     * snapshot commit_next (below) stores for H+E; the three steps
     * between here and commit_next (digest, reset, flips) change none of
     * that snapshot's inputs — the argument is written above the floor in
     * v2ep_rule_n; moving any step that writes `validators` stakes,
     * tenure or bonded membership, `chain_config_history`, or the H-1
     * seed row in between would break it. Full contract: v2ep_rule_n
     * above and the header's "RULE N: REWRITTEN" section. Ordered BEFORE the
     * attendance digest/reset and the boundary flips (1 commissions →
     * 1b distribution → 1c payday → 2 graduation → 3 Rule N → 3b digest
     * → 3c reset → 4 flips → 5 snapshot → 6 balance copy). */
    if (v2ep_rule_n(w, global_height) != 0) return -2;
    if (fault && fault(fault_ud, NODUS_V2_EPST_RULE_N, UINT32_MAX))
        return -2;

    /* ── ATTENDANCE DIGEST (tokenomics-v3 P1, S-2) ────────────────────
     * MUST run BEFORE the reset immediately below: the digest is a
     * function of the epoch's ACCUMULATED counts, and resetting first
     * would digest all zeros and hide every divergence this leg exists
     * to catch. Keyed on the SAME epoch_start settlement drained above —
     * the gate already proved the subtraction cannot underflow. */
    if (v2ep_attendance_digest(
            w, global_height - (uint64_t)DNAC_EPOCH_LENGTH) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "attendance digest failed at boundary %llu",
                      (unsigned long long)global_height);
        return -2;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_ATTENDANCE_DIGEST,
                       UINT32_MAX))
        return -2;

    /* ── ATTENDANCE RESET (tokenomics-v3 P1) ──────────────────────────
     * The ONLY writer of this reset on this lane — every node enters the
     * next epoch with `v2_attendance.signed_count` at 0, per-address,
     * `last_signed_height` untouched (Rule N's own P2 watermark). Both
     * the distribution (1b) and Rule N above depend on running BEFORE
     * this step; moving it earlier, or folding it into either of them,
     * breaks one of the two — do neither without reading the header's
     * "WHY THE DISTRIBUTION SITS AT 1b". */
    if (v2ep_attendance_reset(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "attendance reset failed at boundary %llu",
                      (unsigned long long)global_height);
        return -2;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_ATTENDANCE_RESET,
                       UINT32_MAX))
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

    /* ── 6. THE FROZEN BALANCE COPY (tokenomics-v3 P2, P2-5) ──────────
     * LAST: the bonded balances the NEXT epoch starts from, after every
     * transition above (the graduation is the only one that moves a
     * stake). The distribution at H+E reads it. Out of every root. */
    if (nodus_witness_v2_balance_copy_write(w, global_height) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "balance copy failed at boundary %llu",
                      (unsigned long long)global_height);
        return -2;
    }
    if (fault && fault(fault_ud, NODUS_V2_EPST_BALANCE_COPY, UINT32_MAX))
        return -2;

    QGP_LOG_DEBUG(LOG_TAG, "boundary at %llu applied (%u graduates, "
                  "%llu accrued, %u payday utxos)",
                  (unsigned long long)global_height,
                  (unsigned)out->n_graduates,
                  (unsigned long long)out->dist_accrued,
                  (unsigned)out->n_payday_utxos);
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

/* ── tokenomics-v3 P2-10: the power exit boundary L(h) ────────────────
 * Contract and the derivation (why nb(h) + E) are in the header. Every
 * step is checked: ceil(h/E)·E and the + E can both leave 64 bits for a
 * height near UINT64_MAX, and a wrapped boundary would be a lock that
 * opens in the past. */
int nodus_v2_power_exit_boundary(uint64_t h, uint64_t *out) {
    if (!out) return -1;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;

    /* nb(h) = ceil(h / E) · E — h itself when h is a boundary. */
    uint64_t nb = h;
    if ((h % E) != 0) {
        const uint64_t q = h / E + 1;        /* h / E < UINT64_MAX: E > 1
                                              * or h % E would be 0     */
        if (q > UINT64_MAX / E) return -1;
        nb = q * E;
    }
    if (nb > UINT64_MAX - E) return -1;
    *out = nb + E;
    return 0;
}
