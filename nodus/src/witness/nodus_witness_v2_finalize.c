/**
 * @file nodus/src/witness/nodus_witness_v2_finalize.c
 * @brief Ledger V2 O14 — the production V2 block-acceptance seam.
 *
 * Contract, activation status and the FAULT-vs-VERDICT convention are in
 * nodus_witness_v2_finalize.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_finalize.h"

#include <sqlite3.h>
#include <string.h>

#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "witness/nodus_witness_v2_qc.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_V2_FINAL"

/* O15E Faz C — idempotent-replay QC heal.
 *
 * A node that COMMITTED a block through its own quorum but missed the
 * post-commit certificate exchange keeps `v2_blocks.qc IS NULL` — the
 * legal committed-but-uncertified window (produce.h). When that block
 * later arrives as a full BlockMessage (catch-up, or a targeted
 * QC-recovery fetch), finalize's engine returns IDEMPOTENT_REPLAY and
 * writes nothing. By that point the incoming QC has ALREADY passed
 * nodus_witness_v2_qc_verify against the COMMITTED authority (finalize
 * step 4) and its claimed BlockID EQUALS the stored id (the engine's
 * idempotent path only fires on an exact id match), so attaching it is
 * safe. The UPDATE is guarded `AND qc IS NULL` so a real QC is never
 * overwritten, and it touches ONLY the qc column — BlockID, roots,
 * state and every other field are untouched. Idempotent on replay.
 *
 * Returns nothing meaningful to the caller's verdict: a heal failure
 * leaves the row exactly as it was (still NULL) — the block stays
 * committed, and a later fetch can try again. */
static void finalize_heal_null_qc(nodus_witness_t *w, uint64_t height,
                                  const uint8_t block_id[64],
                                  const uint8_t *qc_bytes, size_t qc_len) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_blocks SET qc = ?1 "
            "WHERE global_height = ?2 AND block_id = ?3 AND qc IS NULL",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_blob(st, 1, qc_bytes, (int)qc_len, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    sqlite3_bind_blob(st, 3, block_id, 64, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) > 0)
        QGP_LOG_INFO(LOG_TAG, "healed NULL QC at height %llu via replay",
                     (unsigned long long)height);
    sqlite3_finalize(st);
}

int nodus_witness_v2_finalize_block(nodus_witness_t *w,
                                    const uint8_t *header_bytes,
                                    size_t header_len,
                                    const uint8_t *qc_bytes,
                                    size_t qc_len,
                                    nodus_v2_block_t *blk) {
    /* A NULL argument is a LOCAL programming fault, not a statement
     * about a block — there is no block here to judge. Same reasoning as
     * nodus_witness_v2_qc.c:24-30. */
    if (!w || !w->db || !header_bytes || !qc_bytes || !blk)
        return NODUS_V2_INTERNAL_FAULT;
    if (qc_len == 0) return NODUS_V2_CONSENSUS_INVALID;

    /* ── 1. EXPLICIT VERSION DISPATCH ─────────────────────────────────
     * On the ENCODED byte, before any structural interpretation. The
     * retired version and any unknown version are two distinct classes,
     * both fail-closed, and NEITHER falls back to the legacy path: a
     * legacy block does not reach this function at all. */
    if (header_len == 0) return NODUS_V2_CONSENSUS_INVALID;
    if (header_bytes[0] == DNA_BH2_VERSION_RETIRED) {
        QGP_LOG_WARN(LOG_TAG, "%s",
                     "retired header version 2 — rejected, never "
                     "reinterpreted under the v3 layout");
        return NODUS_V2_RETIRED_VERSION;
    }
    if (header_bytes[0] != DNA_BH2_VERSION) {
        QGP_LOG_WARN(LOG_TAG, "unknown header version %u — rejected",
                     (unsigned)header_bytes[0]);
        return NODUS_V2_UNSUPPORTED_VERSION;
    }

    /* ── 2. Strict decode: EXACTLY 413 bytes, no size auto-detection. */
    dna_block_header_v2_t hdr;
    if (dna_bh2_decode(header_bytes, header_len, &hdr) != 0)
        return NODUS_V2_CONSENSUS_INVALID;

    /* The header describes the block the caller handed us; a header for
     * some OTHER height is not this block's certificate. */
    if (hdr.block_height != blk->global_height)
        return NODUS_V2_CONSENSUS_INVALID;

    /* ── 3. The claimed BlockID, computed ONCE from the decoded header. */
    uint8_t claimed_id[DNA_BH2_ID_LEN];
    if (dna_bh2_block_id(&hdr, claimed_id) != 0)
        return NODUS_V2_INTERNAL_FAULT;                      /* hash fault */

    /* ── 4. Certificate verification against COMMITTED authority.
     * This is the production call the season exists to create. The
     * verifier resolves the governing snapshot itself (by height, from
     * committed state), re-hashes it, requires the header's
     * validator_set_hash to EQUAL it, recomputes the BlockID itself and
     * checks every signature over that id. Nothing about the authority
     * can be proposed from here — the function takes no snapshot, no set
     * hash, no N and no quorum parameter. */
    dna_qc_v2_t *qc = NULL;
    {
        /* O15A: the decoder distinguishes bad bytes from an allocation
         * failure, and that distinction must survive the seam. A -1 says
         * the certificate is malformed; a -2 says this node ran out of
         * memory and learned nothing. Collapsing them here would put the
         * fault back exactly where the previous contract lost it. */
        int drc = dna_qc_v2_decode(qc_bytes, qc_len, &qc);
        if (drc == NODUS_V2_INTERNAL_FAULT) return NODUS_V2_INTERNAL_FAULT;
        if (drc != 0 || !qc) return NODUS_V2_CONSENSUS_INVALID;
    }

    int vrc = nodus_witness_v2_qc_verify(w, &hdr, qc);
    dna_qc_v2_free(&qc);
    if (vrc == NODUS_V2_INTERNAL_FAULT) {
        /* FAULT, never downgraded: this node cannot decide. Returning -1
         * here would make a node that merely lacks the epoch's snapshot
         * declare a valid block invalid. */
        QGP_LOG_WARN(LOG_TAG, "%s",
                     "QC verification could not be decided on this node "
                     "(fault) — abstaining, not rejecting");
        return NODUS_V2_INTERNAL_FAULT;
    }
    if (vrc != NODUS_V2_ACCEPTED) return NODUS_V2_CONSENSUS_INVALID;

    /* ── 5. Everything above is read-only. No durable mutation has
     * happened, so a rejection here leaves the database byte-identical.
     *
     * ── 6. Execute. Every committed header field is handed to the
     * engine as an EQUALITY ASSERTION, never as a value to store: the
     * engine derives its own and rejects before COMMIT on any
     * disagreement. Set here rather than by the caller so a caller
     * cannot weaken the check by omitting one. */
    blk->epoch                  = hdr.epoch;
    blk->timestamp              = hdr.timestamp;
    memcpy(blk->proposer_id, hdr.proposer_id, sizeof(blk->proposer_id));
    blk->expect_prev_block_id   = hdr.prev_block_id;
    blk->expect_vset_hash       = hdr.validator_set_hash;
    blk->expect_block_id        = claimed_id;
    blk->expect_tx_root         = hdr.tx_root;
    blk->expect_dupd_root       = hdr.domain_updates_root;
    blk->expect_global_root     = hdr.global_state_root;
    /* domains_root is NOT a header field — global_state_root commits it
     * (dna_v2_global_root), so asserting it separately would invent a
     * commitment the header does not carry. */
    blk->expect_domains_root    = NULL;
    /* The certificate rides the block's ONE transaction, so no committed
     * block can ever exist without it. */
    blk->qc_bytes               = qc_bytes;
    blk->qc_len                 = qc_len;

    /* Every non-success class passes through UNCHANGED — including
     * NODUS_V2_NOT_YET_LINKABLE, which the engine now reports for a block
     * whose predecessors this node does not hold. Flattening it here into
     * a verdict would recreate, one layer up, the confusion the engine was
     * just taught to avoid. */
    int arc = nodus_witness_v2_apply_block(w, blk);
    if (!nodus_v2_result_is_accepted(arc)) return arc;

    /* O15E Faz C — a replay of an already-committed block whose stored
     * QC is NULL heals it with THIS verified certificate. arc == 1
     * (IDEMPOTENT_REPLAY) means the block was already committed at this
     * height with this exact id; the QC above already verified against
     * committed authority. On a fresh commit (arc 0/2) the QC rode the
     * block's transaction, so there is nothing to heal. */
    if (arc == NODUS_V2_IDEMPOTENT_REPLAY)
        finalize_heal_null_qc(w, blk->global_height, claimed_id,
                              qc_bytes, qc_len);

    /* ── 7. The id the QC certified MUST be the id that is stored.
     * On rc 0/2 the engine derived it from its own execution results; on
     * rc 1 it served the already-committed row. Either way this is the
     * final, independent equality — and on rc 1 the engine wrote
     * nothing, so a mismatch cannot have corrupted anything. */
    if (memcmp(blk->out_block_id, claimed_id, DNA_BH2_ID_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "engine-derived BlockID differs from the certified "
                      "id — rejecting");
        return NODUS_V2_CONSENSUS_INVALID;
    }

    /* ── 8. STORED-BYTES INTEGRITY (§8): the header the engine persisted
     * must itself reproduce the stored id. On rc 0/2 the engine just
     * built those bytes; on rc 1 they came back from the committed row,
     * which makes this the restart check — the bytes on disk, decoded
     * and re-hashed, must still yield the same identity. Cheap, and it
     * closes the gap between "the engine computed an id" and "the row
     * can prove that id". */
    {
        dna_block_header_v2_t stored;
        uint8_t restored_id[DNA_BH2_ID_LEN];
        if (dna_bh2_decode(blk->out_header, DNA_BH2_ENC_SIZE, &stored) != 0
            || dna_bh2_block_id(&stored, restored_id) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "stored header bytes do not decode — refusing");
            return NODUS_V2_INTERNAL_FAULT;
        }
        if (memcmp(restored_id, blk->out_block_id, DNA_BH2_ID_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "stored header bytes do not reproduce the "
                          "stored BlockID — refusing");
            return NODUS_V2_INTERNAL_FAULT;
        }
    }
    return arc;
}

int nodus_witness_v2_finalize_selfcheck(nodus_witness_t *w) {
    /* Contract and the INERT/legacy-safe argument are in the header. */
    if (!w) return -1;

    /* A zeroed block: the probes below never reach execution, but the
     * entry point rejects a NULL blk as a FAULT, so a real one is needed
     * to reach the version dispatch at all. */
    nodus_v2_block_t probe;
    memset(&probe, 0, sizeof(probe));

    static const uint8_t qc_stub[1] = { 0 };
    uint8_t hdr[DNA_BH2_ENC_SIZE];
    memset(hdr, 0, sizeof(hdr));

    /* RETIRED version 2 — a verdict, and never reinterpreted as v3.
     * O15A: asserted by its OWN class, so this probe now proves the two
     * version failures are genuinely distinguishable rather than merely
     * both non-zero. Under the old contract both returned -1 and this
     * check could not tell them apart at all. */
    hdr[0] = DNA_BH2_VERSION_RETIRED;
    if (nodus_witness_v2_finalize_block(w, hdr, sizeof(hdr), qc_stub,
                                        sizeof(qc_stub), &probe)
        != NODUS_V2_RETIRED_VERSION)
        return -1;

    /* UNKNOWN version — a separate fail-closed class. */
    hdr[0] = (uint8_t)(DNA_BH2_VERSION + 1);
    if (nodus_witness_v2_finalize_block(w, hdr, sizeof(hdr), qc_stub,
                                        sizeof(qc_stub), &probe)
        != NODUS_V2_UNSUPPORTED_VERSION)
        return -1;

    /* A NULL argument is a node FAULT, never a verdict about a block. */
    if (nodus_witness_v2_finalize_block(w, NULL, 0, qc_stub,
                                        sizeof(qc_stub), &probe)
        != NODUS_V2_INTERNAL_FAULT)
        return -1;

    return 0;
}
