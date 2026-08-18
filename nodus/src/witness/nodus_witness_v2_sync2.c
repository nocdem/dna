/**
 * @file nodus/src/witness/nodus_witness_v2_sync2.c
 * @brief Ledger V2 O15B — bounded catch-up, replay and restart.
 *
 * Contract and the one-engine argument are in nodus_witness_v2_sync2.h.
 * Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_ingress.h"
#include "witness/nodus_witness_v2_claims.h"

#include "dnac/block_v2.h"
#include "dnac/blockmsg_v2.h"

#include <sqlite3.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2SYNC2"

/* Committed V2 head, or 0. -1 on fault is impossible for a u64 return, so
 * `ok_out` carries the distinction — "no blocks" and "could not read" must
 * not be the same answer when the result decides whether to sync. */
static uint64_t v2_head(nodus_witness_t *w, int *ok_out) {
    *ok_out = 0;
    if (!w || !w->db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    uint64_t h = 0;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v > 0) h = (uint64_t)v;
        *ok_out = 1;
    }
    sqlite3_finalize(st);
    return h;
}

int nodus_witness_v2_sync_peer_compatible(nodus_witness_t *w,
                                          const nodus_v2_head_hint_t *hint) {
    if (!w || !hint) return 0;

    /* A protocol version this build does not implement is not "probably
     * fine" — nothing about the frames that would follow is predictable. */
    if (hint->protocol_version != (uint32_t)DNA_BLKW_VERSION) return 0;

    /* Genesis identity is the chain's root fact; chain_id is DERIVED from
     * it (chain_id = genesis_block_id[0..31], block_v2.h:81). Checking both
     * is not redundant — it also rejects a peer whose two fields disagree
     * with each other, which no honest peer produces. */
    uint8_t derived[32];
    if (dna_bh2_derive_chain_id(hint->genesis_block_id, derived) != 0)
        return 0;
    if (memcmp(derived, hint->chain_id, 32) != 0) return 0;

    uint8_t mine[32];
    /* A fault deriving OUR identity means we cannot tell. Not "yes". */
    if (nodus_witness_v2_chain_id(w, mine) != 0) return 0;
    if (memcmp(mine, hint->chain_id, 32) != 0) return 0;

    return 1;
}

int nodus_witness_v2_sync_plan_range(nodus_witness_t *w,
                                     const nodus_v2_head_hint_t *hint,
                                     uint64_t *from_out,
                                     uint32_t *count_out) {
    if (from_out)  *from_out  = 0;
    if (count_out) *count_out = 0;
    if (!w || !hint || !from_out || !count_out) return -1;

    if (!nodus_witness_v2_activation_permitted(w))
        return NODUS_V2_NOT_ACTIVE;

    if (!nodus_witness_v2_sync_peer_compatible(w, hint)) return -1;

    int ok = 0;
    uint64_t head = v2_head(w, &ok);
    if (!ok) return -1;

    /* The hint is a HINT. A peer claiming to be behind us, or level, gives
     * us nothing to ask for — and a peer claiming an absurd head does not
     * get to make us request an unbounded range, because the count is
     * clamped to NODUS_V2_SYNC_MAX_RANGE_BLOCKS regardless of what it
     * claims. */
    if (hint->head_height <= head) return 0;

    uint64_t gap = hint->head_height - head;
    uint32_t want = (gap > (uint64_t)NODUS_V2_SYNC_MAX_RANGE_BLOCKS)
                        ? NODUS_V2_SYNC_MAX_RANGE_BLOCKS
                        : (uint32_t)gap;

    *from_out  = head + 1;
    *count_out = want;
    return 0;
}

int nodus_witness_v2_sync_apply_range(nodus_witness_t *w,
                                      const uint8_t *peer_id,
                                      const uint8_t *const *frames,
                                      const size_t *lens,
                                      uint32_t n,
                                      nodus_v2_sync_range_result_t *out) {
    nodus_v2_sync_range_result_t local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    out->stop_reason = NODUS_V2_ACCEPTED;
    out->stop_index  = n;

    if (!w) return NODUS_V2_INTERNAL_FAULT;

    if (!nodus_witness_v2_activation_permitted(w)) {
        out->stop_reason = NODUS_V2_NOT_ACTIVE;
        out->stop_index  = 0;
        return NODUS_V2_NOT_ACTIVE;
    }

    if (!frames || !lens) {
        out->stop_reason = NODUS_V2_INTERNAL_FAULT;
        out->stop_index  = 0;
        return NODUS_V2_INTERNAL_FAULT;
    }

    /* An over-cap range is refused WHOLE, before the first block is
     * touched. Applying a prefix and refusing the tail would let a peer
     * choose how much work we do by how much it oversends.
     *
     * REFUSED, NOT JUDGED. These are LOCAL resource limits (sync2.h: "All
     * LOCAL resource policy; none is consensus"), so a node with a larger
     * budget accepts the same range. Reporting them as CONSENSUS_INVALID —
     * as an earlier draft did — would blame a peer for our own policy, and
     * an honest peer answering OUR 16-block request with large-but-legal
     * blocks could trip the byte budget and be marked invalid for it.
     * Review R2 found this. INTERNAL_FAULT carries the honest meaning:
     * this node did not evaluate the range. */
    if (n > NODUS_V2_SYNC_MAX_RANGE_BLOCKS) {
        QGP_LOG_WARN(LOG_TAG,
                     "range of %u blocks exceeds this node's LOCAL cap of "
                     "%u — refused without judging the peer",
                     n, (unsigned)NODUS_V2_SYNC_MAX_RANGE_BLOCKS);
        out->stop_reason = NODUS_V2_INTERNAL_FAULT;
        out->stop_index  = 0;
        out->faults++;
        return NODUS_V2_INTERNAL_FAULT;
    }

    /* Byte budget, summed BEFORE anything is applied, with a checked add. */
    uint64_t total = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (lens[i] > NODUS_V2_SYNC_MAX_RANGE_BYTES) {
            out->stop_reason = NODUS_V2_INTERNAL_FAULT;
            out->stop_index  = i;
            out->faults++;
            return NODUS_V2_INTERNAL_FAULT;
        }
        total += (uint64_t)lens[i];
        if (total > NODUS_V2_SYNC_MAX_RANGE_BYTES) {
            QGP_LOG_WARN(LOG_TAG,
                         "range bytes exceed this node's LOCAL budget at "
                         "index %u — refused without judging the peer", i);
            out->stop_reason = NODUS_V2_INTERNAL_FAULT;
            out->stop_index  = i;
            out->faults++;
            return NODUS_V2_INTERNAL_FAULT;
        }
    }

    for (uint32_t i = 0; i < n; i++) {
        nodus_v2_ingress_outcome_t oc;
        /* THE SAME ADAPTER, THE SAME ENGINE, THE SAME CHECKS as a block
         * arriving live. There is deliberately no "historical" variant:
         * a shortcut here would be a second acceptance path, and the whole
         * point of this module is that there is only one. */
        int rc = nodus_witness_v2_ingress_block(w, peer_id,
                                                frames[i], lens[i], &oc);

        if (rc == NODUS_V2_ACCEPTED || rc == NODUS_V2_ACCEPTED_PRECACHE) {
            out->applied++;
            continue;
        }
        if (rc == NODUS_V2_IDEMPOTENT_REPLAY) {
            /* Already committed. NOT a stop: re-sending is ordinary during
             * catch-up, and a duplicate has no second effect. */
            out->duplicates++;
            continue;
        }

        /* Everything else stops the range at THIS index. A range claims
         * contiguous history, so once one block does not apply, every
         * later block's parent is unverified — continuing would apply
         * blocks on top of a link we never established. */
        out->stop_index  = i;
        out->stop_reason = (nodus_v2_result_t)rc;
        if (rc == NODUS_V2_NOT_YET_LINKABLE)        out->deferred++;
        else if (nodus_v2_result_blames_peer(rc))   out->rejected++;
        else                                        out->faults++;

        QGP_LOG_WARN(LOG_TAG,
                     "range stopped at index %u: result %d (peer action %s)",
                     i, rc, nodus_v2_peer_action_name(oc.peer));
        return rc;
    }

    return 0;
}

int nodus_witness_v2_sync_restart_check(nodus_witness_t *w,
                                        uint64_t *bad_height_out) {
    if (bad_height_out) *bad_height_out = 0;
    if (!w || !w->db) return -2;

    if (!nodus_witness_v2_activation_permitted(w))
        return NODUS_V2_NOT_ACTIVE;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT global_height, block_id, header FROM v2_blocks "
            "ORDER BY global_height ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -2;

    /* Carried across rows so the CHAIN is checked, not just each row in
     * isolation. Review R2: verifying only "this header reproduces this id"
     * accepts a set of internally consistent rows that do not link to one
     * another, and accepts a valid height-7 header stored under key 5 —
     * and then reports "intact". A corruption check that cannot see a
     * broken chain is not checking the chain. */
    int      have_prev = 0;
    uint8_t  prev_id[DNA_BH2_ID_LEN];
    uint64_t prev_height = 0;

    int rc, verdict = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        uint64_t h = (uint64_t)sqlite3_column_int64(st, 0);

        const void *idb = sqlite3_column_blob(st, 1);
        int idn = sqlite3_column_bytes(st, 1);
        const void *hdb = sqlite3_column_blob(st, 2);
        int hdn = sqlite3_column_bytes(st, 2);

        /* A row whose widths are wrong is CORRUPT, not merely odd. Stop at
         * the first one — never skip it to keep going, because a skipped
         * bad record is a silent acceptance. */
        if (!idb || idn != DNA_BH2_ID_LEN ||
            !hdb || hdn != (int)DNA_BH2_ENC_SIZE) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* THE PROPERTY THE O14 `header` COLUMN EXISTS FOR: re-derive the
         * identity from the STORED canonical bytes and require it to equal
         * the STORED id. The decomposed columns cannot reconstruct a
         * header, so before that column this was uncheckable. */
        dna_block_header_v2_t hdr;
        if (dna_bh2_decode((const uint8_t *)hdb, (size_t)DNA_BH2_ENC_SIZE,
                           &hdr) != 0) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* THE ROW KEY MUST MATCH THE HEADER. A perfectly self-consistent
         * height-7 header stored under key 5 would otherwise pass — the
         * header reproduces its own id, and nothing looked at where it
         * was filed. */
        if (hdr.block_height != h) {
            QGP_LOG_ERROR(LOG_TAG,
                          "v2_blocks row keyed %llu holds a header for "
                          "height %llu",
                          (unsigned long long)h,
                          (unsigned long long)hdr.block_height);
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        if (h == 0) {
            /* Genesis identity needs the manifest bytes, which this row
             * does not carry, so it is NOT re-derived here — deriving it
             * from an input we do not have is the fabrication this tree
             * forbids. It is covered instead by the preflight's
             * GENESIS_IDENTITY_MISMATCH check, which HAS the committed
             * manifest. Width and decode were already verified above. */
            have_prev   = 1;
            prev_height = h;
            memcpy(prev_id, idb, DNA_BH2_ID_LEN);
            continue;
        }

        uint8_t id[DNA_BH2_ID_LEN];
        if (dna_bh2_block_id(&hdr, id) != 0) {
            if (bad_height_out) *bad_height_out = h;
            verdict = -2;      /* a hash failure is OURS, not corruption */
            break;
        }
        if (memcmp(id, idb, DNA_BH2_ID_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "stored header at height %llu does not reproduce "
                          "its stored BlockID",
                          (unsigned long long)h);
            if (bad_height_out) *bad_height_out = h;
            verdict = -1;
            break;
        }

        /* PARENT LINKAGE. Consecutive rows must actually form a chain:
         * this header's prev_block_id must equal the previous row's stored
         * id, and the heights must be contiguous. Without this, a set of
         * individually valid blocks that link to nothing reports "intact". */
        if (have_prev) {
            if (h != prev_height + 1) {
                QGP_LOG_ERROR(LOG_TAG,
                              "v2_blocks jumps from height %llu to %llu",
                              (unsigned long long)prev_height,
                              (unsigned long long)h);
                if (bad_height_out) *bad_height_out = h;
                verdict = -1;
                break;
            }
            if (memcmp(hdr.prev_block_id, prev_id, DNA_BH2_ID_LEN) != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "block at height %llu does not link to the "
                              "committed block at %llu",
                              (unsigned long long)h,
                              (unsigned long long)prev_height);
                if (bad_height_out) *bad_height_out = h;
                verdict = -1;
                break;
            }
        }
        have_prev   = 1;
        prev_height = h;
        memcpy(prev_id, id, DNA_BH2_ID_LEN);
    }

    /* A scan that ended for any reason other than DONE did not verify the
     * rows it never reached. Report that as "could not perform", never as
     * "intact" — the fail-closed shape nodus/CLAUDE.md requires of every
     * `while (sqlite3_step(...) == SQLITE_ROW)` loop. */
    if (verdict == 0 && rc != SQLITE_DONE) verdict = -2;

    sqlite3_finalize(st);
    return verdict;
}
