/**
 * Nodus — Ledger V2 Season 3: validator-set snapshot persistence, builder
 * and epoch lifecycle.
 *
 * See nodus_witness_vset.h. Every reader follows the fail-closed shape of
 * nodus_chain_config_compute_root: the step loop's final rc is checked
 * against SQLITE_DONE, a malformed row fails the computation, and no leg
 * is ever replaced by a sentinel.
 *
 * @file nodus_witness_vset.c
 */

#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_runtime.h"   /* HF-6 5d: NODUS_RT_GEN_*  */
#include "nodus/nodus_chain_config.h"
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT        */
#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/power_cap.h"                 /* HF-6 5b: the water-fill  */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_VSET"

/* The snapshot's voter_id and the chain-config witness_id are the SAME
 * 32-byte identifier derived the SAME way; reuse, never re-implement. */
_Static_assert(DNA_VSET_VOTER_ID_LEN == NODUS_CC_WITNESS_ID_SIZE,
               "snapshot voter_id width != chain-config witness_id width");
_Static_assert(DNA_VSET_PUBKEY_LEN == NODUS_CC_PUBKEY_SIZE,
               "snapshot pubkey width != chain-config pubkey width");
_Static_assert(DNA_VSET_PUBKEY_LEN == DNAC_PUBKEY_SIZE,
               "snapshot pubkey width != validator pubkey width");
_Static_assert(DNA_VSET_HASH_LEN == DNA_V2_ROOT_LEN,
               "snapshot hash width != V2 root width");
/* HF-6 5b: the compiled POWER_CAP_BPS default lies in the K5 range the
 * cap accepts (design rev 6 §5, §8) — a default outside it would make
 * every ruleset-2 power computation refuse. */
_Static_assert(DNAC_HF6_POWER_CAP_BPS_DEFAULT >= DNA_POWER_CAP_BPS_MIN &&
               DNAC_HF6_POWER_CAP_BPS_DEFAULT <= DNA_POWER_CAP_BPS_MAX,
               "DNAC_HF6_POWER_CAP_BPS_DEFAULT outside [500, 3000]");
/* HF-6 slice 8a: param 20's vote range (dnac.h, the client mirror's and
 * the scalar rule's pair) IS the water-fill's own legal range, so a legal
 * vote can never make dna_power_cap_counted refuse. */
_Static_assert(DNAC_CFG_MIN_POWER_CAP_BPS == DNA_POWER_CAP_BPS_MIN &&
               DNAC_CFG_MAX_POWER_CAP_BPS == DNA_POWER_CAP_BPS_MAX,
               "param 20's range drifted from power_cap.h");
/* HF-6 slice 8a (plan §1.7): the frozen-ratio premise. A param-20 row
 * that governs snapshot(X) has effective <= X and was committed at
 * c <= effective - grace; with grace >= DNAC_EPOCH_LENGTH that is at or
 * before boundary X - E, whose items run before that boundary builds
 * snapshot(X) — so the builder and every later consumer of snapshot(X)
 * (the Comet diffs, Rule N, the distribution, the storage settlement)
 * read ONE ratio for it. A grace below E would let a row land between the
 * build and a consumption. */
_Static_assert(DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS >= DNAC_EPOCH_LENGTH,
               "POWER_CAP_BPS's grace must cover an epoch (frozen ratio)");
/* The snapshot's validator_id is the 64-byte id the cap tie-breaks on. */
_Static_assert(DNA_VSET_VALIDATOR_ID_LEN == 64,
               "snapshot validator_id width != power-cap id width");

/* ── HF-6 slice 5c: BOTH snapshot versions, for the chain's life ────────
 *
 * Design rev 6 §6.5 ("Her okuyucu zincir ömrü boyunca iki sürümü de kabul
 * eder. v1 çıktıları bayt bayt değişmez"); plan tasks/hf6-slice5-plan.md
 * §0 fact 2, §2 "5c". Every codec call in this file is the `_ex` family
 * at max_ruleset = DNA_VSET_RULESET_TOPN_V2 with the ruleset-2 length
 * ceiling as the outer cap; the layout, the hash tag and the per-ruleset
 * length ceiling are chosen by the blob's / snapshot's OWN header
 * (shared/dnac/vset_wire.c dna_vset_hash_bytes_ex: a ruleset-1 header
 * hashes under "NDS.VSET.v1" and is refused above the ruleset-1 ceiling,
 * exactly the pre-5c bytes). A superset of the old acceptance for every
 * well-formed ruleset-1 row; the one input it now refuses on insert — a
 * blob shorter than a header or naming ruleset 0 / >= 3, which the
 * pre-5c (max_ruleset 1) bytes-level hash accepted without reading a
 * header — is a row the pre-5c decode already refused on every read.
 * No ruleset-1-only (legacy) codec entry point remains in this file.
 * Which ruleset is BUILT is the builder's (vset_build_snapshot); this
 * file stores and reads both. */
#define VSET_MAX_RULESET  DNA_VSET_RULESET_TOPN_V2
#define VSET_MAX_ENC_LEN  DNA_VSET_MAX_ENC_LEN_V2

/* ── Insert ─────────────────────────────────────────────────────────── */

int nodus_witness_vset_insert(nodus_witness_t *w,
                              uint64_t epoch_start,
                              const uint8_t *blob, size_t blob_len,
                              const uint8_t hash64[DNA_VSET_HASH_LEN],
                              uint64_t created_at_height) {
    if (!w || !w->db || !blob || !hash64) return -1;
    if (blob_len == 0 || blob_len > VSET_MAX_ENC_LEN) return -1;

    /* Never store a blob whose claimed hash is not its hash: that would
     * seed the table with a row every later read must reject. */
    uint8_t derived[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes_ex(blob, blob_len, VSET_MAX_RULESET,
                               derived) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot hash derivation failed",
                      (unsigned long long)epoch_start);
        return -1;
    }
    if (memcmp(derived, hash64, DNA_VSET_HASH_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: supplied hash does not match "
                      "the blob — refusing to store",
                      (unsigned long long)epoch_start);
        return -1;
    }

    /* ── Existing row? Idempotent only on byte-identity. ── */
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT snapshot_hash, snapshot_blob FROM validator_set_snapshots "
        "WHERE epoch_start = ?", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "snapshot select prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);

    int step = sqlite3_step(st);
    if (step == SQLITE_ROW) {
        const void *ex_hash = sqlite3_column_blob(st, 0);
        int ex_hash_len     = sqlite3_column_bytes(st, 0);
        const void *ex_blob = sqlite3_column_blob(st, 1);
        int ex_blob_len     = sqlite3_column_bytes(st, 1);

        int identical =
            ex_hash && ex_hash_len == DNA_VSET_HASH_LEN &&
            memcmp(ex_hash, hash64, DNA_VSET_HASH_LEN) == 0 &&
            ex_blob && (size_t)ex_blob_len == blob_len &&
            memcmp(ex_blob, blob, blob_len) == 0;
        sqlite3_finalize(st);

        if (identical) return 0;   /* idempotent re-apply */

        /* Two different validator sets claim the same epoch. On a live
         * chain that is a validator_set_root divergence — fatal, not a
         * value to overwrite. */
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: CONFLICTING snapshot already "
                      "stored (stored %d bytes, incoming %zu) — refusing "
                      "to overwrite",
                      (unsigned long long)epoch_start, ex_blob_len, blob_len);
        return -2;
    }
    sqlite3_finalize(st);
    if (step != SQLITE_DONE) {
        /* A probe fault is NOT "no row": failing here keeps us from
         * inserting over a row we could not read. */
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot probe failed (rc=%d)",
                      (unsigned long long)epoch_start, step);
        return -1;
    }

    /* ── No row: INSERT. ── */
    st = NULL;
    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO validator_set_snapshots "
        "(epoch_start, active_count, snapshot_hash, snapshot_blob, "
        " created_at_height) VALUES (?,?,?,?,?)", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "snapshot insert prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    /* active_count is a denormalised copy of the blob's header field; it
     * is cross-checked against the decoded value on every read. */
    uint16_t active_count = 0;
    if (blob_len >= (size_t)DNA_VSET_HDR_LEN)
        active_count = (uint16_t)(((uint16_t)blob[8] << 8) | (uint16_t)blob[9]);

    /* O15F Task 1 — THE WRITER GUARD. On a successor no snapshot larger
     * than NODUS_V2_ACTIVE_SET_MAX may ever be stored: the persisted row
     * is the sole committee authority, so refusing it here makes every
     * raw reader safe without a reader-side clamp. Fail-closed (-1);
     * legacy chains keep the 128 ceiling. */
    if (w->v2_successor && active_count > NODUS_V2_ACTIVE_SET_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: successor snapshot active_count "
                      "%u exceeds NODUS_V2_ACTIVE_SET_MAX (%d) — refusing "
                      "to store", (unsigned long long)epoch_start,
                      (unsigned)active_count, NODUS_V2_ACTIVE_SET_MAX);
        sqlite3_finalize(st);
        return -1;
    }

    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_int  (st, 2, (int)active_count);
    sqlite3_bind_blob (st, 3, hash64, DNA_VSET_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_blob (st, 4, blob, (int)blob_len, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)created_at_height);

    step = sqlite3_step(st);
    sqlite3_finalize(st);
    if (step != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot insert failed (rc=%d): "
                      "%s", (unsigned long long)epoch_start, step,
                      sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── Get ────────────────────────────────────────────────────────────── */

int nodus_witness_vset_get(nodus_witness_t *w,
                           uint64_t epoch_start,
                           dna_vset_snapshot_t **snapshot_out,
                           uint8_t hash_out64[DNA_VSET_HASH_LEN]) {
    if (!w || !w->db || !snapshot_out) return -1;

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT active_count, snapshot_hash, snapshot_blob "
        "FROM validator_set_snapshots WHERE epoch_start = ?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "snapshot get prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);

    int step = sqlite3_step(st);
    if (step == SQLITE_DONE) { sqlite3_finalize(st); return 1; } /* absent */
    if (step != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot get step failed (rc=%d)",
                      (unsigned long long)epoch_start, step);
        sqlite3_finalize(st);
        return -1;                                  /* fault ≠ absent */
    }

    int stored_count    = sqlite3_column_int(st, 0);
    const void *st_hash = sqlite3_column_blob(st, 1);
    int st_hash_len     = sqlite3_column_bytes(st, 1);
    const void *st_blob = sqlite3_column_blob(st, 2);
    int st_blob_len     = sqlite3_column_bytes(st, 2);

    if (!st_hash || st_hash_len != DNA_VSET_HASH_LEN ||
        !st_blob || st_blob_len <= 0 ||
        (size_t)st_blob_len > VSET_MAX_ENC_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: malformed snapshot row "
                      "(hash %d B, blob %d B)",
                      (unsigned long long)epoch_start, st_hash_len,
                      st_blob_len);
        sqlite3_finalize(st);
        return -1;
    }

    /* Integrity BEFORE trust: re-derive the hash over the stored bytes
     * (the tag the stored header names — a pre-5c ruleset-1 row
     * re-derives exactly the hash it was stored under). */
    uint8_t derived[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes_ex((const uint8_t *)st_blob, (size_t)st_blob_len,
                               VSET_MAX_RULESET, derived) != 0 ||
        memcmp(derived, st_hash, DNA_VSET_HASH_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: stored snapshot blob does not "
                      "match its stored hash — corruption",
                      (unsigned long long)epoch_start);
        sqlite3_finalize(st);
        return -1;
    }

    dna_vset_snapshot_t *snap = NULL;
    if (dna_vset_decode_ex((const uint8_t *)st_blob, (size_t)st_blob_len,
                           VSET_MAX_RULESET, &snap) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: stored snapshot failed to decode",
                      (unsigned long long)epoch_start);
        sqlite3_finalize(st);
        return -1;
    }

    /* The row's key and its denormalised count must agree with the blob;
     * a mismatch means the row was written by something that did not
     * respect the format. */
    if (snap->epoch != epoch_start ||
        stored_count < 0 || (int)snap->active_count != stored_count) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot row disagrees with its "
                      "blob (blob epoch %llu, blob count %u, row count %d)",
                      (unsigned long long)epoch_start,
                      (unsigned long long)snap->epoch,
                      (unsigned)snap->active_count, stored_count);
        dna_vset_free(&snap);
        sqlite3_finalize(st);
        return -1;
    }

    if (hash_out64) memcpy(hash_out64, st_hash, DNA_VSET_HASH_LEN);
    sqlite3_finalize(st);
    *snapshot_out = snap;
    return 0;
}

/* ── validator_set_root ─────────────────────────────────────────────── */

int nodus_witness_vset_root(nodus_witness_t *w,
                            uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT epoch_start, snapshot_hash FROM validator_set_snapshots "
        "ORDER BY epoch_start ASC", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        /* The table is created unconditionally in WITNESS_DB_SCHEMA
         * (nodus_witness.c), so a prepare failure here is a real fault,
         * NOT the honest empty state — fail closed. */
        QGP_LOG_ERROR(LOG_TAG, "vset scan prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 4, n = 0;
    uint64_t *epochs = malloc(cap * sizeof(uint64_t));
    uint8_t (*hashes)[DNA_V2_ROOT_LEN] = malloc(cap * sizeof(*hashes));
    if (!epochs || !hashes) {
        free(epochs); free(hashes); sqlite3_finalize(st);
        return -1;
    }
    int fail = 0;

    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            uint64_t *ne = realloc(epochs, nc * sizeof(uint64_t));
            uint8_t (*nh)[DNA_V2_ROOT_LEN] = realloc(hashes,
                                                     nc * sizeof(*nh));
            if (!ne || !nh) {
                free(ne ? ne : epochs);
                free(nh ? nh : hashes);
                sqlite3_finalize(st);
                return -1;
            }
            epochs = ne; hashes = nh; cap = nc;
        }
        const void *h  = sqlite3_column_blob(st, 1);
        int         hl = sqlite3_column_bytes(st, 1);
        if (!h || hl != DNA_V2_ROOT_LEN) {
            /* Always written full-length by _insert — a NULL or short
             * blob is corruption. FAIL, never substitute. */
            QGP_LOG_ERROR(LOG_TAG, "vset row %zu hash malformed (%d B) — "
                          "failing root", n, hl);
            fail = 1;
            break;
        }
        epochs[n] = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(hashes[n], h, DNA_V2_ROOT_LEN);
        n++;
    }
    /* Fail-close: a mid-scan error must not truncate to a "valid" root. */
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "vset scan aborted mid-stream (rc=%d) — "
                      "failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    if (!fail)
        ret = dna_v2_vset_root(epochs, hashes, n, out);   /* n==0 → empty */
    free(epochs);
    free(hashes);
    return ret;
}

/* ── Builder ────────────────────────────────────────────────────────── */

int nodus_witness_vset_entry_from_member(const nodus_committee_member_t *m,
                                         uint32_t ruleset,
                                         dna_vset_entry_t *e) {
    if (!m || !e) return -1;
    if (ruleset != DNA_VSET_RULESET_TOPN_V1 &&
        ruleset != DNA_VSET_RULESET_TOPN_V2)
        return -1;
    /* Shipped derivation, reused: SHA3-512(pubkey)[0..31]
     * (nodus_witness_chain_config.c:498) — under ruleset 2 the codec
     * recomputes and enforces the same value (vset_wire.c vset_check). */
    if (nodus_chain_config_derive_witness_id(m->pubkey, e->voter_id) != 0)
        return -1;
    memcpy(e->pubkey, m->pubkey, DNA_VSET_PUBKEY_LEN);
    e->total_stake    = m->total_stake;
    e->self_bond      = m->self_stake;
    e->commission_bps = m->commission_bps;
    if (ruleset == DNA_VSET_RULESET_TOPN_V2) {
        /* HF-6 slice 5c (design rev 6 §6.5; ORCHESTRATOR decision D6):
         * the member's ids, set by emit_member from its v2 row at key
         * generation >= NODUS_RT_GEN_STORAGE. A zero id (a member emitted
         * below generation 4) is not repaired here — the v2 encoder
         * refuses an all-zero validator_id / owner_fp. */
        memcpy(e->validator_id, m->validator_id, DNA_VSET_VALIDATOR_ID_LEN);
        memcpy(e->owner_fp, m->owner_fp, DNA_VSET_OWNER_FP_LEN);
    } else {
        /* Ruleset 1 has no slot for them (the v1 encoder refuses a
         * nonzero byte) — whatever the member carries. */
        memset(e->validator_id, 0, DNA_VSET_VALIDATOR_ID_LEN);
        memset(e->owner_fp, 0, DNA_VSET_OWNER_FP_LEN);
    }
    return 0;
}

/* (The HF-6 slice 6d rotation pass of the freeze — the khan-A3 budget
 * walk and the khan-A7 cumulative carry — was deleted with ROTATE: khan
 * decision docs/plans/decisions/2026-10-13-kurultay-18-summary.md item 1.
 * No row holds a pending key, so a snapshot's entries carry the rows'
 * own, immutable keys.) */

/* The ONE selection core behind both public builders —
 * nodus_witness_vset_build_for_epoch (every stored snapshot: genesis and
 * commit_next) and nodus_witness_vset_preview_next (tokenomics-v3 P1
 * round 6, Rule N's weight floor). Kept as one function so the snapshot
 * Rule N judges and the snapshot commit_next stores can never be built by
 * two different pieces of selection logic.
 *
 * HF-6 slice 5d: `key_gen` (the caller's resolved key generation) is
 * handed to the committee core AND decides the selection_ruleset here,
 * so the candidates, the tiebreak, the members' ids and the layout they
 * are written in are one value's consequences (ORCHESTRATOR D4 (i)).
 *
 * Unlike the public build_for_epoch, this core tells the two "no
 * snapshot" outcomes apart (FAULT vs VERDICT — a DB failure is never a
 * value):
 *   0  built, *snap_out owns a heap snapshot (dna_vset_free);
 *   1  the committee is EMPTY — a well-formed answer from committed
 *      state (no bonded, tenured validator), *snap_out untouched;
 *  -1  fault (bad args, allocation, the committee compute failed, a
 *      count above max_active, a witness_id derivation failure),
 *      *snap_out untouched.
 * (The HF-6 6d rotation pass that ran here at generation 4 was deleted
 * with ROTATE — khan decision 2026-10-13-kurultay-18-summary.md item 1;
 * every entry carries its row's own key, so the generation-4 bytes are
 * the pre-6d builder's bytes.) */
static int vset_build_snapshot(nodus_witness_t *w, uint64_t epoch_start,
                               int max_active, uint32_t key_gen,
                               dna_vset_snapshot_t **snap_out) {
    if (!w || !w->db || !snap_out) return -1;
    if (max_active < 1 || max_active > DNA_MAX_ACTIVE_VALIDATORS) return -1;

    /* 128 members are ~344 KB — heap, never the stack. */
    nodus_committee_member_t *members =
        calloc((size_t)max_active, sizeof(*members));
    if (!members) return -1;

    int count = 0;
    /* DIRECT compute (not the cached get_for_block): the cache carries no
     * self_stake, and self_bond must be the real bond. See the header. */
    if (nodus_committee_compute_for_epoch(w, epoch_start, key_gen, members,
                                          max_active, &count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: committee compute failed",
                      (unsigned long long)epoch_start);
        free(members);
        return -1;
    }
    if (count < 0 || count > max_active) {
        /* compute_for_epoch caps its output at max_entries; anything
         * outside [0, max_active] is corruption, not an empty set. */
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: committee count %d outside "
                      "[0, %d]", (unsigned long long)epoch_start, count,
                      max_active);
        free(members);
        return -1;
    }
    if (count == 0) {
        free(members);
        return 1;
    }

    dna_vset_snapshot_t *snap = dna_vset_alloc((uint16_t)count);
    if (!snap) { free(members); return -1; }

    snap->epoch             = epoch_start;
    /* HF-6 slice 5d — THE SWITCH (plan tasks/hf6-slice5-plan.md §1
     * "Rule"; design rev 6 §7.7, §8): ruleset 2 from key generation
     * NODUS_RT_GEN_STORAGE, ruleset 1 below it. The members were emitted
     * by the core at the SAME `key_gen`, so under ruleset 2 every one
     * carries its row's validator_id / owner_fp (emit_member), and the
     * entry fill below writes the layout this value names. */
    snap->selection_ruleset = key_gen >= NODUS_RT_GEN_STORAGE
                                  ? DNA_VSET_RULESET_TOPN_V2
                                  : DNA_VSET_RULESET_TOPN_V1;
    memset(snap->sortition_seed, 0, DNA_VSET_SEED_LEN);  /* reserved slot */

    for (int i = 0; i < count; i++) {
        if (nodus_witness_vset_entry_from_member(&members[i],
                                                 snap->selection_ruleset,
                                                 &snap->entries[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: entry fill failed for "
                          "member %d", (unsigned long long)epoch_start, i);
            dna_vset_free(&snap);
            free(members);
            return -1;
        }
    }
    free(members);

    *snap_out = snap;
    return 0;
}

int nodus_witness_vset_build_for_epoch(nodus_witness_t *w,
                                       uint64_t epoch_start,
                                       int max_active,
                                       uint32_t key_gen,
                                       dna_vset_snapshot_t **snapshot_out,
                                       uint8_t **blob_out,
                                       size_t *blob_len_out,
                                       uint8_t hash_out64[DNA_VSET_HASH_LEN]) {
    if (!w || !w->db) return -1;
    if (max_active < 1 || max_active > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (blob_out && !blob_len_out) return -1;

    dna_vset_snapshot_t *snap = NULL;
    int brc = vset_build_snapshot(w, epoch_start, max_active, key_gen, &snap);
    if (brc == 1) {
        /* A chain with no eligible validators has NO snapshot. An empty
         * set would encode as active_count 0, which the codec rejects —
         * and would silently claim "nobody may vote at this epoch". On
         * THIS public path an empty committee stays a failure (every
         * stored snapshot needs at least one member); only
         * nodus_witness_vset_preview_next reports it as a verdict. */
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: committee is empty (count=0) — "
                      "no snapshot", (unsigned long long)epoch_start);
        return -1;
    }
    if (brc != 0 || !snap) return -1;

    /* Encode once; every output is derived from the SAME bytes so the
     * caller can never hold a hash that disagrees with its blob. The
     * layout and the hash tag follow the snapshot's own ruleset (HF-6
     * 5c — VSET_MAX_RULESET above). */
    size_t need = dna_vset_encoded_len_ex(snap, VSET_MAX_RULESET);
    if (need == 0) { dna_vset_free(&snap); return -1; }

    uint8_t *blob = malloc(need);
    if (!blob) { dna_vset_free(&snap); return -1; }
    size_t written = 0;
    if (dna_vset_encode_ex(snap, VSET_MAX_RULESET, blob, need,
                           &written) != 0 || written != need) {
        free(blob);
        dna_vset_free(&snap);
        return -1;
    }

    uint8_t hash[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes_ex(blob, written, VSET_MAX_RULESET, hash) != 0) {
        free(blob);
        dna_vset_free(&snap);
        return -1;
    }

    /* Only now, with everything computed, publish the outputs. */
    if (hash_out64) memcpy(hash_out64, hash, DNA_VSET_HASH_LEN);
    if (blob_out) {
        *blob_out     = blob;
        *blob_len_out = written;
    } else {
        free(blob);
    }
    if (snapshot_out) *snapshot_out = snap;
    else              dna_vset_free(&snap);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * S3 epoch lifecycle — the ACTIVE surface. See nodus_witness_vset.h.
 *
 * Every function below runs inside the caller's block DB transaction
 * (finalize_block), returns -1 on any fault, and never substitutes a
 * value for a failure.
 * ════════════════════════════════════════════════════════════════════ */

/** The genesis block's height. `blocks.height` is
 *  INTEGER PRIMARY KEY AUTOINCREMENT (WITNESS_DB_SCHEMA,
 *  nodus_witness.c:80), so the first row inserted is height 1 and block 0
 *  never exists on this chain. */
#define VSET_GENESIS_BLOCK_HEIGHT  1ULL

/* The epoch's target set size, read from committed chain_config_history.
 * Mirrors committee_target_for_epoch in nodus_witness_committee.c — same
 * param, same default (DNAC_TARGET_ACTIVE_DEFAULT since tokenomics-v3
 * P3-7), same clamp, and since O15J A2 the same fail-closed
 * rule — because the snapshot builder and the committee selector MUST
 * agree on how many seats an epoch has.
 *
 * @param target_out [out] written only on success.
 * @return 0 target determined, -1 cannot determine (the caller must fail
 *         the block; a snapshot sized from a guess is a
 *         validator_set_root divergence). */
static int vset_target_for_epoch(nodus_witness_t *w, uint64_t e_start,
                                 int *target_out) {
    uint64_t target = 0;
    int crc = nodus_chain_config_get_u64(
        w, (uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT, e_start,
        (uint64_t)DNAC_TARGET_ACTIVE_DEFAULT, &target);
    if (crc < 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: TARGET_ACTIVE_COUNT is "
                      "unreadable — refusing to size a validator-set "
                      "snapshot from a guess",
                      (unsigned long long)e_start);
        return -1;
    }
    if (target < 1) target = 1;
    if (target > (uint64_t)DNA_MAX_ACTIVE_VALIDATORS)
        target = (uint64_t)DNA_MAX_ACTIVE_VALIDATORS;
    /* O15F Task 1 — a successor's active set is capped at
     * NODUS_V2_ACTIVE_SET_MAX. Mirrors committee_target_for_epoch so the
     * snapshot builder and the committee selector agree on the seat count.
     * Legacy chains keep the 128 ceiling above. */
    if (w->v2_successor && target > (uint64_t)NODUS_V2_ACTIVE_SET_MAX)
        target = (uint64_t)NODUS_V2_ACTIVE_SET_MAX;
    *target_out = (int)target;
    return 0;
}

/* Build the snapshot for `e_start` and store it. Shared by the boundary
 * and genesis paths so both produce byte-identical rows for the same
 * chain state.
 *
 * @param created_at_height provenance column only — never hashed, never
 *        read back by consensus (see WITNESS_DB_SCHEMA).
 * @param key_gen the key generation the snapshot is built at (HF-6 5d).
 * @return 0 stored or idempotent re-apply, -1 on any fault INCLUDING the
 *         -2 conflict from _insert (two different validator sets claiming
 *         one epoch is a validator_set_root divergence; the block must
 *         not commit). */
static int vset_build_and_store(nodus_witness_t *w,
                                  uint64_t e_start,
                                  uint64_t created_at_height,
                                  uint32_t key_gen) {
    int target = 0;
    if (vset_target_for_epoch(w, e_start, &target) != 0) return -1;

    uint8_t *blob = NULL;
    size_t   blob_len = 0;
    uint8_t  hash[DNA_VSET_HASH_LEN];

    if (nodus_witness_vset_build_for_epoch(w, e_start, target, key_gen,
                                            NULL, &blob, &blob_len,
                                            hash) != 0) {
        /* Includes "committee is empty". On a real chain that is a fault,
         * not an empty set — an epoch with nobody allowed to vote is not
         * a state this ledger can represent. */
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot build failed "
                      "(target=%d) — failing the block",
                      (unsigned long long)e_start, target);
        return -1;
    }

    /* O15J Faz 3 — the O15C "Stage C" one-shot exclusion of validators
     * that never signalled activation readiness is deleted with the
     * ceremony: there is no readiness signal to be missing, so an
     * ordinary snapshot build is the only build. The `built` snapshot
     * out-parameter of nodus_witness_vset_build_for_epoch existed solely
     * to feed that filter and is now passed NULL above. */

    int rc = nodus_witness_vset_insert(w, e_start, blob, blob_len, hash,
                                        created_at_height);
    free(blob);
    if (rc == 0) return 0;

    QGP_LOG_ERROR(LOG_TAG, "epoch %llu: snapshot persist failed (rc=%d) — "
                  "failing the block", (unsigned long long)e_start, rc);
    return -1;
}

/* ── Boundary flips ─────────────────────────────────────────────────── */

int nodus_witness_vset_apply_boundary_flips(nodus_witness_t *w,
                                            uint64_t boundary_height) {
    if (!w || !w->db) return -1;

    dna_vset_snapshot_t *snap = NULL;
    int grc = nodus_witness_vset_get(w, boundary_height, &snap, NULL);
    if (grc == 1) {
        /* No snapshot for this epoch. This is the legacy / first
         * post-upgrade boundary: the PREVIOUS boundary ran software that
         * had no commit_next, so no set was ever frozen for this epoch.
         * Deriving one here from the CURRENT ranking would be exactly the
         * current-set substitution the design forbids, so we do nothing
         * and let commit_next (which the caller runs next) seed the first
         * real snapshot for the epoch AFTER this one. */
        QGP_LOG_INFO(LOG_TAG, "epoch %llu: no validator-set snapshot — "
                     "boundary flips skipped (pre-S3 epoch)",
                     (unsigned long long)boundary_height);
        return 0;
    }
    if (grc != 0) return -1;   /* corruption / DB fault — never a no-op */

    /* ── THE SNAPSHOT IS THE AUTHORITY — deliberately NO recompute
     * cross-check here (ORCHESTRATOR decision, S3 wave-2 integration).
     *
     * An earlier draft recomputed the committee at flip time and failed
     * the block on any mismatch with the stored snapshot. That check was
     * a reachable deterministic HALT: nodus_committee_compute_for_epoch
     * ranks over the validators table AS IT IS NOW, while the snapshot
     * was frozen one epoch earlier — so a single mid-epoch UNSTAKE,
     * DELEGATE reorder, or (in bootstrap epochs, where the tenure gate is
     * disabled) a new STAKE would fail the boundary block on every node.
     *
     * The frozen snapshot is exactly the "committed one epoch ahead" set
     * the design demands (§7.5), so it — not a live recomputation — is
     * what membership consumes. The integrity chain that replaces the
     * recompute check:
     *   - nodus_witness_vset_get re-derives the blob hash and decodes
     *     fail-closed (corruption can never flip a status);
     *   - the flips below change validator status bytes, which feed
     *     validator_root → state_root, so a node holding a DIFFERENT
     *     snapshot for this epoch diverges at THIS block and the
     *     existing 7/7 state_root machinery refuses the commit;
     *   - nodus_witness_vset_insert (-2 on conflict) already makes two
     *     different sets for one epoch unrepresentable locally.
     * Recompute-based auditing remains available OFFLINE (tests, tools);
     * it is not a consensus gate. */

    /* ── FLIPS ──────────────────────────────────────────────────────────
     *
     * Two deterministic passes, no unordered row iteration:
     *   1. every BONDED row (ACTIVE or ELIGIBLE) → ELIGIBLE;
     *   2. every snapshot member that is now ELIGIBLE → ACTIVE.
     *
     * Pass 2 walks the SNAPSHOT (a canonical, hash-committed sequence),
     * not a query result, so the traversal order is fixed by the
     * committed bytes. The final state is order-independent anyway —
     * both passes are absolute assignments, which is also what makes the
     * whole operation idempotent under replay.
     *
     * Pass 2's `AND status = ELIGIBLE` is load-bearing: it confines the
     * write to rows pass 1 just touched, so a snapshot member that has
     * since become RETIRING / UNSTAKED / AUTO_RETIRED is NOT resurrected
     * into the active set by a stale membership record.
     *
     * Only the status byte moves. self_stake, delegation totals,
     * active_since_block, the Rule N counters and
     * validator_stats.active_count are all untouched — active_count
     * counts BONDED validators (incremented by apply_stake, decremented
     * on retirement), so a 0↔4 flip must not move it. */
    {
        sqlite3_stmt *st = NULL;
        int rc = sqlite3_prepare_v2(w->db,
            "UPDATE validators SET status = ? WHERE status IN (?, ?)",
            -1, &st, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: flip-to-eligible prepare "
                          "failed: %s", (unsigned long long)boundary_height,
                          sqlite3_errmsg(w->db));
            dna_vset_free(&snap);
            return -1;
        }
        sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_ELIGIBLE);
        sqlite3_bind_int(st, 2, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int(st, 3, (int)DNAC_VALIDATOR_ELIGIBLE);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: flip-to-eligible failed "
                          "(rc=%d)", (unsigned long long)boundary_height, rc);
            dna_vset_free(&snap);
            return -1;
        }
    }
    {
        /* HF-6 slice 6c (design 2026-10-03-hf5-validator-owner-stake rev
         * 6 §3; plan tasks/hf6-slice6-plan.md §1.5, B5): a ruleset-2
         * member is matched by its validator_id (validators.pubkey_hash,
         * the v2 row's identity). Written for ROTATE; the khan removed it
         * (decision 2026-10-13-kurultay-18-summary.md item 1), so a row's
         * key never changes and the id match flips exactly the rows the
         * pubkey match would. A ruleset-1 snapshot keeps the pubkey match,
         * byte-identical. */
        const int by_id =
            snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V2;
        sqlite3_stmt *st = NULL;
        int rc = sqlite3_prepare_v2(w->db,
            by_id ? "UPDATE validators SET status = ? "
                    "WHERE pubkey_hash = ? AND status = ?"
                  : "UPDATE validators SET status = ? "
                    "WHERE pubkey = ? AND status = ?", -1, &st, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "epoch %llu: flip-to-active prepare "
                          "failed: %s", (unsigned long long)boundary_height,
                          sqlite3_errmsg(w->db));
            dna_vset_free(&snap);
            return -1;
        }
        for (uint16_t i = 0; i < snap->active_count; i++) {
            sqlite3_reset(st);
            sqlite3_clear_bindings(st);
            sqlite3_bind_int (st, 1, (int)DNAC_VALIDATOR_ACTIVE);
            if (by_id)
                sqlite3_bind_blob(st, 2, snap->entries[i].validator_id,
                                  DNA_VSET_VALIDATOR_ID_LEN, SQLITE_STATIC);
            else
                sqlite3_bind_blob(st, 2, snap->entries[i].pubkey,
                                  DNA_VSET_PUBKEY_LEN, SQLITE_STATIC);
            sqlite3_bind_int (st, 3, (int)DNAC_VALIDATOR_ELIGIBLE);
            rc = sqlite3_step(st);
            if (rc != SQLITE_DONE) {
                QGP_LOG_ERROR(LOG_TAG, "epoch %llu: flip-to-active failed "
                              "for member %u (rc=%d)",
                              (unsigned long long)boundary_height,
                              (unsigned)i, rc);
                sqlite3_finalize(st);
                dna_vset_free(&snap);
                return -1;
            }
        }
        sqlite3_finalize(st);
    }

    QGP_LOG_INFO(LOG_TAG, "epoch %llu: validator-set flips applied "
                 "(%u seats)", (unsigned long long)boundary_height,
                 (unsigned)snap->active_count);
    dna_vset_free(&snap);
    return 0;
}

/* ── Next-epoch commitment ──────────────────────────────────────────── */

int nodus_witness_vset_commit_next(nodus_witness_t *w,
                                   uint64_t boundary_height,
                                   uint32_t key_gen) {
    if (!w || !w->db) return -1;

    /* The NEXT epoch's start height keys BOTH the target lookup and the
     * snapshot row. Rows in chain_config_history whose effective_block is
     * <= that height are already committed state at this point, so every
     * node reads the same target. `key_gen` is the boundary's one read
     * (HF-6 5d): it decides the ruleset of the row stored here. */
    uint64_t next_start = boundary_height + (uint64_t)DNAC_EPOCH_LENGTH;
    return vset_build_and_store(w, next_start, boundary_height, key_gen);
}

/* ── Next-epoch preview (tokenomics-v3 P1 round 6) ──────────────────── */

int nodus_witness_vset_preview_next(nodus_witness_t *w,
                                    uint64_t boundary_height,
                                    uint32_t key_gen,
                                    dna_vset_snapshot_t **snapshot_out) {
    if (!w || !w->db || !snapshot_out) return -1;
    if (boundary_height > UINT64_MAX - (uint64_t)DNAC_EPOCH_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG, "preview: boundary %llu + epoch length "
                      "overflows", (unsigned long long)boundary_height);
        return -1;
    }

    /* EXACTLY commit_next's key, target lookup, key generation and
     * builder core: next_start as above, vset_target_for_epoch(next_start)
     * as vset_build_and_store does, the caller's `key_gen` (the same
     * boundary read commit_next receives — HF-6 5d), and the same
     * vset_build_snapshot that nodus_witness_vset_build_for_epoch wraps.
     * Nothing is encoded, hashed or stored. */
    uint64_t next_start = boundary_height + (uint64_t)DNAC_EPOCH_LENGTH;
    int target = 0;
    if (vset_target_for_epoch(w, next_start, &target) != 0) return -1;
    return vset_build_snapshot(w, next_start, target, key_gen, snapshot_out);
}

/* ── Genesis seeding ────────────────────────────────────────────────── */

int nodus_witness_vset_commit_genesis(nodus_witness_t *w,
                                      uint64_t block_height) {
    if (!w || !w->db) return -1;
    if (block_height != VSET_GENESIS_BLOCK_HEIGHT) return 0;

    /* Seed BOTH the epoch genesis lives in (e_start 0) and the first
     * boundary's epoch (e_start EPOCH_LENGTH). Without the second row the
     * first nodus_witness_vset_apply_boundary_flips would find no
     * snapshot and silently skip, leaving the chain's first real rotation
     * unfrozen.
     *
     * The committee builder takes its bootstrap path for both (e_start <
     * EPOCH_LENGTH + 1), and that path seeds its tiebreak from
     * nodus_witness_block_get(w, 0) — which ALWAYS fails on this chain,
     * because blocks.height is AUTOINCREMENT and genesis is height 1, so
     * height 0 has no row. The ALL-ZERO seed branch therefore fires here
     * on every node and on every replay, which is exactly the property
     * this hook needs: the same branch, the same bytes, everywhere. (The
     * genesis validators are already in the validators table when this
     * runs: both callers write them first — gen_seed_state in
     * nodus_witness_v2_gen.c, or the genesis bundle's transferred
     * validators table in nodus_witness_v2_bundle.c — so they are
     * visible to the builder.)
     *
     * No chain_config_history row for DNAC_CFG_TARGET_ACTIVE_COUNT can
     * exist at genesis, so both targets resolve to the default,
     * DNAC_TARGET_ACTIVE_DEFAULT (32 since tokenomics-v3 P3-7; it was
     * DNAC_COMMITTEE_SIZE = 7). A version-3 genesis seeds exactly
     * DNAC_COMMITTEE_SIZE validators (Rule P.1, nodus_witness_v2_gen.c),
     * so both snapshots still hold all seven.
     *
     * CORRECTED (O15J Faz 2 Block 2C): this used to read "No
     * chain_config_history row can exist at genesis", which is no longer
     * true — the pure-V2 builder seeds the economic parameters at
     * effective_block 0 (nodus_witness_v2_gen.c gen_seed_state), and the
     * test fixture has long seeded an inflation-off row
     * (nodus/tests/v2_genesis_fixture.h v2x_seed_inflation_off). Neither
     * writes DNAC_CFG_TARGET_ACTIVE_COUNT, the ONLY id
     * vset_target_for_epoch reads (:438-440), so the conclusion stands —
     * but it now rests on the param, not on the table being empty.
     *
     * HF-6 slice 5d: both at NODUS_RT_GEN_1 — a chain born on this
     * binary starts at generation 1 (design rev 6 §8), so the genesis
     * snapshots are ruleset 1 (and the bootstrap path they take emits no
     * ids a ruleset-2 entry would need). */
    if (vset_build_and_store(w, 0ULL, block_height, NODUS_RT_GEN_1) != 0)
        return -1;
    if (vset_build_and_store(w, (uint64_t)DNAC_EPOCH_LENGTH,
                               block_height, NODUS_RT_GEN_1) != 0) return -1;

    QGP_LOG_INFO(LOG_TAG, "genesis: validator-set snapshots seeded for "
                 "epochs 0 and %d", (int)DNAC_EPOCH_LENGTH);
    return 0;
}

/* ── HF-6 slice 5b: the ratio seam and the ONE power helper ─────────── */

int nodus_witness_power_cap_bps_for_epoch(nodus_witness_t *w,
                                          uint64_t epoch_start,
                                          uint32_t *ratio_out) {
    if (!w || !ratio_out) return -1;
    /* HF-6 slice 8a: chain_config param 20 at the snapshot's EPOCH START
     * (the committee_target_for_epoch pattern, nodus_witness_committee.c),
     * the compiled default with no row. A read fault is -1, never the
     * default. A stored value outside [500, 3000] is this node's storage
     * disagreeing with every writer (the scalar rule admits nothing
     * else) — -1 too, checked on the u64 BEFORE the narrowing to
     * uint32_t, so no out-of-range value can wrap into the range. */
    uint64_t v = 0;
    if (nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_POWER_CAP_BPS,
                                   epoch_start,
                                   (uint64_t)DNAC_HF6_POWER_CAP_BPS_DEFAULT,
                                   &v) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: POWER_CAP_BPS is unreadable — "
                      "refusing to derive voting power from a guessed "
                      "ratio", (unsigned long long)epoch_start);
        return -1;
    }
    if (v < (uint64_t)DNAC_CFG_MIN_POWER_CAP_BPS ||
        v > (uint64_t)DNAC_CFG_MAX_POWER_CAP_BPS) {
        QGP_LOG_ERROR(LOG_TAG, "epoch %llu: POWER_CAP_BPS reads %llu, a "
                      "value no committed row can hold — this node's "
                      "chain_config storage is inconsistent",
                      (unsigned long long)epoch_start,
                      (unsigned long long)v);
        return -1;
    }
    *ratio_out = (uint32_t)v;
    return 0;
}

int nodus_witness_vset_powers(nodus_witness_t *w,
                              const dna_vset_snapshot_t *snap,
                              uint64_t out[]) {
    if (!w || !snap || !out) return -1;
    const uint16_t n = snap->active_count;
    if (n > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (n > 0 && !snap->entries) return -1;

    if (snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V1) {
        /* Uncapped, the pre-slice-5 derivation byte for byte (zero
         * allowed — each caller keeps its own zero rule). */
        for (uint16_t i = 0; i < n; i++)
            out[i] = snap->entries[i].total_stake / DNAC_DECIMAL_UNIT;
        return 0;
    }
    if (snap->selection_ruleset != DNA_VSET_RULESET_TOPN_V2) {
        QGP_LOG_ERROR(LOG_TAG, "powers: snapshot(%llu) carries ruleset %u — "
                      "no power derivation for it",
                      (unsigned long long)snap->epoch,
                      (unsigned)snap->selection_ruleset);
        return -1;
    }

    /* Ruleset 2: the water-fill cap over whole-coin powers at the ratio of
     * the snapshot's own epoch start. */
    uint32_t ratio = 0;
    if (nodus_witness_power_cap_bps_for_epoch(w, snap->epoch, &ratio) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "powers: POWER_CAP_BPS for epoch %llu is "
                      "unreadable", (unsigned long long)snap->epoch);
        return -1;
    }
    if (n == 0) return -1;                /* the cap refuses an empty set */

    /* The cap takes scalar arrays (design §5); the entries' ids are not
     * contiguous, so copy them out. Heap: 128 × 64 B ids. */
    uint64_t *p = calloc(n, sizeof(*p));
    uint8_t (*ids)[DNA_VSET_VALIDATOR_ID_LEN] = calloc(n, sizeof(*ids));
    uint64_t *counted = calloc(n, sizeof(*counted));
    int ret = -1;
    if (!p || !ids || !counted) goto done;
    for (uint16_t i = 0; i < n; i++) {
        p[i] = snap->entries[i].total_stake / DNAC_DECIMAL_UNIT;
        if (p[i] == 0) {
            QGP_LOG_ERROR(LOG_TAG, "powers: snapshot(%llu) ruleset-2 entry "
                          "%u holds total_stake %llu — below one whole coin, "
                          "a broken invariant", (unsigned long long)snap->epoch,
                          (unsigned)i,
                          (unsigned long long)snap->entries[i].total_stake);
            goto done;
        }
        memcpy(ids[i], snap->entries[i].validator_id,
               DNA_VSET_VALIDATOR_ID_LEN);
    }
    if (dna_power_cap_counted(p, (const uint8_t (*)[64])ids, n, ratio,
                              counted) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "powers: the power cap refused snapshot(%llu) "
                      "(n=%u, ratio %u bps)", (unsigned long long)snap->epoch,
                      (unsigned)n, (unsigned)ratio);
        goto done;
    }
    memcpy(out, counted, (size_t)n * sizeof(*counted));
    ret = 0;

done:
    free(p);
    free(ids);
    free(counted);
    return ret;
}
