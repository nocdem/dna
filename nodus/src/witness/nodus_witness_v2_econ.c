/**
 * Nodus — O15J Faz 2: V1's economics on the Ledger V2 lane.
 *
 * Contract, provenance, the user decision this implements and the
 * touched-domain obligations are in nodus_witness_v2_econ.h. Every V1
 * anchor cited here is a file:line in THIS tree, read rather than
 * recalled.
 *
 * ── WHAT COULD NOT BE LITERAL, AND WHY ──────────────────────────────
 * Four deliberate divergences from the V1 source, each named again at
 * the line where it happens:
 *
 *  1. UTXO WRITES GO THROUGH THE TYPED EFFECT PATH. V1 emits settlement
 *     rows with a hand-rolled `INSERT OR IGNORE INTO utxo_set`
 *     (bft.c:3166-3178) that does not bind `domain_id` at all. On the V2
 *     schema that column has NO default (nodus_witness_v2_schema.c:211
 *     and the note at nodus_witness_v2_epoch.c:214-217), so the V1
 *     statement would not even be well-formed here. Settlement therefore
 *     builds canonical CORE effects and applies them through
 *     nodus_witness_v2_effects_apply — the same probe → precond → mutate
 *     path every CORE spend output takes. Consequences, all improvements
 *     but all divergences: a duplicate row is now FAIL-CLOSED (the
 *     PRE_ABSENT precondition) where V1 silently ignored it, and
 *     `created_at` is pinned to 0 where V1 wrote `time(NULL)` — a WALL
 *     CLOCK value in a consensus write path (bft.c:3062). The column is
 *     excluded from the UTXO merkle leaf, so V1 never forked on it, but
 *     it is not a value this lane will reproduce.
 *
 *  2. A DATABASE FAULT IS NEVER A VALUE. V1 turns several read failures
 *     into economic outcomes: a failed epoch_state fetch means "nothing
 *     to settle" (bft.c:3089-3090), an unreadable validator row means
 *     "absent, burn his share" (bft.c:3238-3247), and three
 *     supply/delete return codes are discarded outright (bft.c:3103,
 *     :3134, :3369). Each of those is a fault here. The reason is the
 *     nodus rule this tree states everywhere else — two nodes must not
 *     be able to pay different validators because one of them had a
 *     transient I/O error.
 *
 *  3. THE PER-EPOCH COUNTER RESET IS NOT REPEATED. V1's settlement
 *     resets `signed_blocks_this_epoch` at its tail (bft.c:3350-3360).
 *     On the V2 lane the O15C Rule N transplant already performs exactly
 *     that UPDATE (nodus_witness_v2_epoch.c:611-622) one step later in
 *     the same transaction, which is precisely why settlement must run
 *     BEFORE Rule N — see the ordering note at the call site. Doing it
 *     twice would be a no-op that only widens the write set.
 *
 *  4. RETURN CONVENTION. V1's helper returns -1; the V2 boundary's
 *     contract is 0/-2 with no verdict class. Every V1 -1 becomes -2.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_db.h"        /* supply_get / add_minted /
                                              * add_burned                */
#include "witness/nodus_witness_emission.h"  /* nodus_emission_per_block  */
#include "witness/nodus_witness_epoch.h"     /* epoch_state CRUD + D.1     */
#include "witness/nodus_witness_runtime.h"   /* the CORE record builder   */
#include "witness/nodus_witness_v2_adapter.h"/* effects_apply             */
#include "witness/nodus_witness_v2_claims.h" /* v2_runtime_for            */
#include "witness/nodus_witness_validator.h"

#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_u128.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2ECON"

/* ── little BE helpers ─────────────────────────────────────────────── */

static void v2ec_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint16_t v2ec_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t v2ec_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint64_t v2ec_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* ── the two canonical settlement identities (pure, no DB) ──────────── */

int nodus_witness_v2_settlement_tx_hash(uint64_t settling_epoch_start,
                                        uint8_t out[64]) {
    if (!out) return -2;
    /* BYTE-IDENTICAL to bft.c:2977-2986: the 10 ASCII bytes of
     * "settlement" with NO terminator, then the epoch key big-endian.
     * sizeof("settlement") would be 11 and would silently change the
     * preimage — hence the explicit 10. */
    uint8_t pre[10 + 8];
    memcpy(pre, "settlement", 10);
    v2ec_put64(pre + 10, settling_epoch_start);
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
 * PART 1 — per-block emission (bft.c:3638-3720)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_v2_emission_apply(nodus_witness_t *w,
                                    uint64_t global_height,
                                    uint64_t *minted_out) {
    if (!w || !w->db || !minted_out) return -2;
    *minted_out = 0;

    /* THE GATE, verbatim (bft.c:3653-3664). The 1ULL default is the
     * source's and is load-bearing: an override this node cannot fetch
     * must not turn emission off HERE while it stays on everywhere else.
     * A pre-wipe chain that really wants emission off stores an explicit
     * 0, which this expression honours. */
    uint64_t inflation_start =
        nodus_chain_config_get_u64(w, DNAC_CFG_INFLATION_START_BLOCK,
                                   global_height, 1ULL);
    uint64_t emission = 0;
    if (inflation_start != 0 && global_height >= inflation_start)
        emission = nodus_emission_per_block(global_height);
    if (emission == 0) return 0;

    /* ── FAIL-CLOSED PRE-CHECK (divergence 2, and it has teeth) ───────
     * nodus_witness_supply_add_minted is ADVISORY: it returns 0 both
     * when the UPDATE landed and when there was no supply_tracking row
     * to update (nodus_witness_db.c:1035-1049). On the legacy lane that
     * tolerance only ever covered pre-genesis unit fixtures. Here it
     * would be a hole in the conservation equation itself: the pool
     * would grow by `emission` while total_minted did not, and the very
     * next supply gate would fail the block for a reason no message
     * names. Proving the row EXISTS first converts the advisory success
     * into a real one, because the UPDATE is keyed on that same id=1
     * row. */
    {
        nodus_witness_supply_t sup;
        memset(&sup, 0, sizeof(sup));
        int src = nodus_witness_supply_get(w, &sup);
        if (src != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "emission at %llu: supply_tracking is unreadable or absent "
                "(rc=%d) — a chain cannot mint into a row it does not have",
                (unsigned long long)global_height, src);
            return -2;
        }
    }

    if (nodus_witness_supply_add_minted(w, emission) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "emission at %llu: supply_add_minted failed",
                      (unsigned long long)global_height);
        return -2;
    }

    /* The canonical epoch key: floor(h / E) * E (bft.c:3675-3678). */
    uint64_t epoch_start = (global_height / (uint64_t)DNAC_EPOCH_LENGTH) *
                           (uint64_t)DNAC_EPOCH_LENGTH;

    int add_rc = nodus_witness_epoch_add_pool(w, epoch_start, emission);
    if (add_rc == 1) {
        /* Row missing — seed it with this mint as the starting pool, then
         * capture the epoch-start snapshot. bft.c:3680-3715, including
         * the -2 (someone else inserted it) retry. */
        nodus_epoch_state_t seed;
        memset(&seed, 0, sizeof(seed));
        seed.epoch_start_height = epoch_start;
        seed.epoch_pool_accum   = emission;
        int ins_rc = nodus_witness_epoch_insert(w, &seed);
        if (ins_rc != 0 && ins_rc != -2) {
            QGP_LOG_ERROR(LOG_TAG,
                "emission at %llu: epoch_insert seed failed rc=%d",
                (unsigned long long)global_height, ins_rc);
            return -2;
        }
        if (ins_rc == -2 &&
            nodus_witness_epoch_add_pool(w, epoch_start, emission) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "emission at %llu: epoch_add_pool retry failed",
                (unsigned long long)global_height);
            return -2;
        }

        /* HOOK 2 — THE EPOCH-START SNAPSHOT, and it is REQUIRED.
         * Settlement splits a delegator's reward by that delegator's own
         * amount, and `validator_set_snapshots` carries no per-delegation
         * figures at all — only the committee. This blob is the ONLY
         * committed source of them. The SAME writer V1 calls
         * (bft.c:3709) is called here rather than a second snapshot
         * format, because two encoders of one snapshot is two answers to
         * one question. Idempotent by its own contract
         * (nodus_witness_epoch.h:96-97). */
        if (nodus_witness_epoch_snapshot_apply(w, epoch_start) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "emission at %llu: epoch_snapshot_apply(%llu) failed",
                (unsigned long long)global_height,
                (unsigned long long)epoch_start);
            return -2;
        }
    } else if (add_rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "emission at %llu: epoch_add_pool rc=%d",
                      (unsigned long long)global_height, add_rc);
        return -2;
    }

    /* ── FAIL-CLOSED POST-CHECK (divergence 2, the pool half) ─────────
     * nodus_witness_epoch_add_pool is advisory in the SAME shape: a
     * failed prepare — the epoch_state table missing — returns 0, not an
     * error (nodus_witness_epoch.c:196-203). Minting into a pool that
     * does not exist breaks the equation exactly as the supply half
     * would. One SELECT proves the row is there; a chain that cannot
     * prove it does not mint.
     *
     * WHY THE ROW BEING PRESENT IS ENOUGH, stated because it is the
     * load-bearing step: the only way add_pool can silently answer 0
     * without having updated anything is a FAILED PREPARE, and its
     * statement and this one address the SAME table. So a successful
     * SELECT here proves the table existed, which proves that prepare
     * succeeded, which means add_pool's answer came from
     * sqlite3_changes() and was therefore handled above. */
    {
        nodus_epoch_state_t chk;
        memset(&chk, 0, sizeof(chk));
        int grc = nodus_witness_epoch_get(w, epoch_start, &chk);
        nodus_witness_epoch_free(&chk);
        if (grc != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "emission at %llu: epoch_state row %llu absent or "
                "unreadable after accrual (rc=%d) — the mint has nowhere "
                "to live", (unsigned long long)global_height,
                (unsigned long long)epoch_start, grc);
            return -2;
        }
    }

    *minted_out = emission;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * PART 2 — epoch settlement (bft.c:3085-3378)
 * ════════════════════════════════════════════════════════════════════ */

/* The snapshot_blob row widths, from the ONE writer that produces them
 * (nodus_witness_epoch.h:99-107, nodus_witness_epoch.c:301-343). */
#define V2EC_VAL_ROW (DNAC_PUBKEY_SIZE + 8 + 8 + 2 + 1)   /* 2611 */
#define V2EC_DEL_ROW (DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8) /* 5192 */

/* One typed-effect batch. DNA_EFFECT_MAX_COUNT (64) is the codec's hard
 * ceiling on a single result, and a 7-seat epoch can emit up to
 * 7 x (1 + 64) = 455 payout rows, so settlement necessarily applies
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
     * rejects a non-ascending result outright (effect_wire.c:313). The
     * total order is (effect_kind, op_id, key bytes)
     * (effect_wire.c:186-192); every effect staged here is a CREATE on
     * RTN_CORE_OP_UTXO, so the 64-byte key alone decides. Sorting a
     * PERMUTATION keeps each dna_effect_in_t pointing at its own key and
     * value buffers. Insertion sort: n <= 64, and it is deterministic on
     * every node for the same input. */
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
        QGP_LOG_ERROR(LOG_TAG, "settlement: encoding %u payout effects "
                      "was refused by the codec", (unsigned)b->n);
        return -2;
    }

    dna_effect_view_t view;
    if (dna_effect_result_decode(b->enc, wlen, &view) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "settlement: this node could not decode its own "
                      "encoded effect result");
        return -2;
    }

    uint16_t fail_index = 0;
    nodus_adapter_status_t st =
        nodus_witness_v2_effects_apply(b->w, b->rt, &view, &fail_index);
    if (st != NODUS_ADAPTER_OK) {
        /* PRE_ABSENT is what makes a colliding payout identity fail here
         * instead of vanishing the way V1's INSERT OR IGNORE did
         * (bft.c:3166). Divergence 1, deliberately fail-closed. */
        QGP_LOG_ERROR(LOG_TAG,
                      "settlement: effect %u of %u was refused by the CORE "
                      "adapter (status %d)", (unsigned)fail_index,
                      (unsigned)b->n, (int)st);
        return -2;
    }
    b->n = 0;
    return 0;
}

/* Stage one payout row. @return 0 / -2. */
static int v2ec_emit(v2ec_batch_t *b, const uint8_t *owner_pubkey,
                     uint64_t amount, const uint8_t tx_hash[64],
                     uint8_t kind, uint32_t output_index,
                     uint64_t block_height) {
    if (b->n == (uint16_t)DNA_EFFECT_MAX_COUNT && v2ec_flush(b) != 0)
        return -2;

    uint16_t s = b->n;
    if (nodus_witness_v2_settlement_nullifier(tx_hash, kind, output_index,
                                              b->key[s]) != 0)
        return -2;

    /* Owner fingerprint = hex(SHA3-512(pubkey)), the V1 encoding at
     * bft.c:3054-3057. `qgp_fp_raw_to_hex` NUL-terminates at 128, and
     * the record builder copies exactly 128. */
    uint8_t fp_raw[QGP_FP_RAW_BYTES];
    if (qgp_sha3_512(owner_pubkey, DNAC_PUBKEY_SIZE, fp_raw) != 0)
        return -2;
    char fp_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(fp_raw, fp_hex);

    /* Native DNAC token id = 64 zeros (bft.c:3058-3059). */
    static const uint8_t native_token[64] = {0};

    /* unlock_block 0: settlement rewards are spendable immediately —
     * V1 passes 0 at bft.c:3264, :3316 and :3336. */
    if (nodus_rt_core_utxo_create_eff(&b->in[s], b->val[s], b->key[s],
                                      fp_hex, amount, native_token,
                                      tx_hash, output_index, block_height,
                                      0) != 0)
        return -2;

    b->n++;
    b->emitted++;
    return 0;
}

/* The whole-pool burn shared by V1's two "nothing to distribute" exits
 * (bft.c:3102-3107 and :3132-3138). Both burn against the SNAPSHOT hash,
 * not the settlement tx_hash — kept verbatim, because that value is what
 * the audit column already records for those two cases. @return 0 / -2. */
static int v2ec_burn_whole_pool(nodus_witness_t *w, uint64_t pool,
                                const uint8_t snapshot_hash[64],
                                uint64_t settling_epoch_start,
                                uint64_t *burned_out) {
    if (pool > 0) {
        if (nodus_witness_supply_add_burned(w, pool, snapshot_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "settlement of epoch %llu: burning the undistributable "
                "pool of %llu failed",
                (unsigned long long)settling_epoch_start,
                (unsigned long long)pool);
            return -2;
        }
        *burned_out = pool;
    }
    /* Retire the row. V1 discards this return (bft.c:3106, :3137); a row
     * that vanished between the SELECT and the DELETE inside ONE
     * transaction is not an outcome this lane accepts. */
    int drc = nodus_witness_epoch_delete(w, settling_epoch_start);
    if (drc != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "settlement of epoch %llu: retiring the epoch row failed "
            "(rc=%d)", (unsigned long long)settling_epoch_start, drc);
        return -2;
    }
    return 0;
}

int nodus_witness_v2_settlement_apply(nodus_witness_t *w,
                                      uint64_t settling_epoch_start,
                                      nodus_v2_epoch_fault_fn fault,
                                      void *fault_ud,
                                      uint32_t *n_utxos_out,
                                      uint64_t *burned_out) {
    if (!w || !w->db || !n_utxos_out || !burned_out) return -2;
    *n_utxos_out = 0;
    *burned_out  = 0;

    /* ── the epoch row ───────────────────────────────────────────────
     * V1 treats ANY non-zero return as "nothing to settle"
     * (bft.c:3089-3090). Divergence 2: a MISS (rc 1) is a legitimate
     * nothing — a chain whose first epoch predates emission has no row —
     * but a read FAULT is not, and must never become one silently. */
    nodus_epoch_state_t es;
    memset(&es, 0, sizeof(es));
    int grc = nodus_witness_epoch_get(w, settling_epoch_start, &es);
    if (grc == 1) return 0;
    if (grc != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "settlement of epoch %llu: epoch_state unreadable (rc=%d) — "
            "a read fault is never 'nothing to settle'",
            (unsigned long long)settling_epoch_start, grc);
        return -2;
    }

    /* Everything the `goto done` paths below could skip is declared and
     * initialised HERE, before the first jump: no branch to the single
     * exit may cross an initialiser. */
    const uint64_t pool     = es.epoch_pool_accum;
    const uint8_t *blob     = es.snapshot_blob;
    const size_t   blob_len = es.snapshot_blob_len;

    int             ret = -2;
    v2ec_batch_t   *b   = NULL;
    size_t          off = 0;
    uint16_t        committee_count = 0;
    uint32_t        deleg_count     = 0;
    const uint8_t  *val_base        = NULL;
    const uint8_t  *deleg_base      = NULL;
    uint64_t        per_slot        = 0;
    uint64_t        total_burned_here = 0;
    uint32_t        out_idx         = NODUS_V2_SETTLE_OUT_IDX_BASE;
    uint8_t         tx_hash[64];
    memset(tx_hash, 0, sizeof(tx_hash));

    /* CANONICAL EMPTY SNAPSHOT is 6 bytes (u16 zero committee ‖ u32 zero
     * delegations). Anything shorter is not a snapshot at all — V1 burns
     * the pool and retires the row (bft.c:3102-3107). */
    if (!blob || blob_len < 6) {
        ret = v2ec_burn_whole_pool(w, pool, es.snapshot_hash,
                                   settling_epoch_start, burned_out);
        goto done;
    }

    committee_count = v2ec_be16(blob + off); off += 2;
    if (off + (size_t)committee_count * V2EC_VAL_ROW + 4 > blob_len) {
        QGP_LOG_ERROR(LOG_TAG,
            "settlement of epoch %llu: truncated snapshot_blob",
            (unsigned long long)settling_epoch_start);
        goto done;
    }
    val_base = blob + off;
    off += (size_t)committee_count * V2EC_VAL_ROW;

    deleg_count = v2ec_be32(blob + off); off += 4;
    if (off + (size_t)deleg_count * V2EC_DEL_ROW > blob_len) {
        QGP_LOG_ERROR(LOG_TAG,
            "settlement of epoch %llu: truncated snapshot delegations",
            (unsigned long long)settling_epoch_start);
        goto done;
    }
    deleg_base = blob + off;

    if (committee_count == 0) {
        ret = v2ec_burn_whole_pool(w, pool, es.snapshot_hash,
                                   settling_epoch_start, burned_out);
        goto done;
    }

    /* ── the split (bft.c:3140-3147) ─────────────────────────────────── */
    per_slot = pool / (uint64_t)committee_count;
    /* BURN LEG 1 of 3 — the remainder the committee split could not
     * divide (bft.c:3147). All three accumulate HERE and reach
     * supply_tracking through the ONE call at the end. */
    total_burned_here = pool - per_slot * (uint64_t)committee_count;

    if (nodus_witness_v2_settlement_tx_hash(settling_epoch_start,
                                            tx_hash) != 0)
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
            "settlement: the CORE runtime does not resolve as ACTIVE on "
            "this node — refusing to pay out");
        goto done;
    }

    for (uint16_t vi = 0; vi < committee_count; vi++) {
        const uint8_t *vrow = val_base + (size_t)vi * V2EC_VAL_ROW;
        const uint8_t *vpk  = vrow;
        uint64_t self_stake      = v2ec_be64(vrow + DNAC_PUBKEY_SIZE);
        uint64_t total_delegated = v2ec_be64(vrow + DNAC_PUBKEY_SIZE + 8);
        uint16_t commission_bps  = v2ec_be16(vrow + DNAC_PUBKEY_SIZE + 16);
        /* status byte at +2610: RETIRING members keep their seat for the
         * epoch (design §3.6), so it is deliberately unread — same as
         * bft.c:3186-3187. */

        /* ── ATTENDANCE (bft.c:3189-3247) ────────────────────────────
         * THE WATERMARK QUESTION, ANSWERED. The design document's §5.4
         * obligation 3 says V1 reads `validator.last_signed_block`. That
         * repeats V1's own STALE contract comment (bft.c:2955-2963); the
         * shipped code reads `signed_blocks_this_epoch` against an
         * 80%-of-expected-slots bar (bft.c:3239-3245), and the comment
         * at bft.c:3190-3210 records that the binary last-signed check
         * was REPLACED precisely because it allowed 83% planned downtime
         * per epoch. The specification of this port is the shipped
         * implementation, so the count-based gate is what is ported.
         *
         * The V2 lane HAS this counter: nodus_witness_v2_record_attendance
         * increments it for the committed header proposer inside the same
         * block transaction (nodus_witness_v2_epoch.c:485-491). It is the
         * O15C transplant, and it writes the SAME column V1's
         * record_attendance writes.
         *
         * The denominator is `committee_count` — the size THIS epoch
         * actually had, decoded from the committed snapshot being
         * iterated, not a current-set substitution (bft.c:3211-3224).
         * Rearranged to a pure multiplication so no truncation enters:
         *   signed * committee_count * 10000 >= EPOCH_LENGTH * BPS.
         *
         * GENESIS CARVE-OUT (bft.c:3230-3236): at the first settlement
         * every genesis-seeded validator has a zero counter but genuinely
         * participated. Burning the whole first pool for that would be
         * wrong, so epoch 0 treats every member as present. */
        int present = 0;
        if (settling_epoch_start == 0) {
            present = 1;
        } else {
            dnac_validator_record_t cur;
            int vrc = nodus_validator_get(w, vpk, &cur);
            if (vrc < 0) {
                /* Divergence 2: V1's `== 0` else-absent (bft.c:3240)
                 * turns an I/O error into a burn. Two nodes must not
                 * disagree about a payout because one had a bad read. */
                QGP_LOG_ERROR(LOG_TAG,
                    "settlement of epoch %llu: committee member %u is "
                    "unreadable — refusing rather than burning his share",
                    (unsigned long long)settling_epoch_start,
                    (unsigned)vi);
                goto done;
            }
            if (vrc == 0) {
                uint64_t lhs = cur.signed_blocks_this_epoch *
                               (uint64_t)committee_count * 10000ULL;
                uint64_t rhs = (uint64_t)DNAC_EPOCH_LENGTH *
                               (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS;
                if (lhs >= rhs) present = 1;
            }
            /* vrc == 1: the row is gone (graduated out of existence).
             * Not present — exactly V1's outcome for that case. */
        }

        if (!present) {
            /* BURN LEG 2 of 3 — the offline member's whole slot
             * (bft.c:3250). This is MINTED value that found no owner,
             * which is why it must be burned and not merely skipped. */
            total_burned_here += per_slot;
            continue;
        }

        if (per_slot == 0) continue;      /* pool too small (bft.c:3254) */

        if (total_delegated == 0 || deleg_count == 0) {
            if (v2ec_emit(b, vpk, per_slot, tx_hash,
                          NODUS_V2_SETTLE_KIND_VALIDATOR, out_idx++,
                          settling_epoch_start) != 0)
                goto done;
            continue;
        }

        uint64_t total_stake = self_stake + total_delegated;
        if (total_stake == 0) total_stake = 1;   /* defensive, bft.c:3277 */

        /* u128 for the products: per_slot * self_stake can exceed 64 bits
         * long before either factor does (bft.c:3280-3287). */
        uint64_t rem = 0;
        qgp_u128_t num = qgp_u128_mul_u64(qgp_u128_from_u64(per_slot),
                                          self_stake);
        uint64_t validator_base = qgp_u128_div_u64(num, total_stake,
                                                   &rem).lo;
        uint64_t delegator_gross = (per_slot > validator_base)
                                   ? (per_slot - validator_base) : 0;

        uint64_t commission = 0;
        if (commission_bps > 0 && delegator_gross > 0) {
            qgp_u128_t cn = qgp_u128_mul_u64(
                qgp_u128_from_u64(delegator_gross),
                (uint64_t)commission_bps);
            commission = qgp_u128_div_u64(cn, 10000ULL, &rem).lo;
            if (commission > delegator_gross) commission = delegator_gross;
        }
        uint64_t validator_total = validator_base + commission;
        uint64_t delegator_net   = delegator_gross - commission;

        /* Delegator shares, in the snapshot's own row order — which the
         * ONE snapshot writer fixed at validator-then-delegator pubkey
         * ASC (nodus_witness_epoch.c:327-344), so every node walks them
         * identically. V1 first copies the matching rows into a scratch
         * array (bft.c:2992-3013); scanning in place is the same walk in
         * the same order without the copy. */
        uint64_t distributed = 0;
        for (uint32_t di = 0; di < deleg_count; di++) {
            const uint8_t *drow = deleg_base + (size_t)di * V2EC_DEL_ROW;
            if (memcmp(drow + DNAC_PUBKEY_SIZE, vpk, DNAC_PUBKEY_SIZE) != 0)
                continue;
            uint64_t d_amount = v2ec_be64(drow + 2 * DNAC_PUBKEY_SIZE);

            qgp_u128_t sn = qgp_u128_mul_u64(
                qgp_u128_from_u64(delegator_net), d_amount);
            uint64_t share = qgp_u128_div_u64(sn, total_delegated, &rem).lo;
            if (share == 0) continue;     /* bft.c:3308 */

            if (v2ec_emit(b, drow, share, tx_hash,
                          NODUS_V2_SETTLE_KIND_DELEGATOR, out_idx++,
                          settling_epoch_start) != 0)
                goto done;
            distributed += share;
        }
        if (distributed > delegator_net) distributed = delegator_net;
        /* BURN LEG 3 of 3 — what integer division left behind after the
         * delegator shares (bft.c:3324-3326). */
        total_burned_here += delegator_net - distributed;

        if (validator_total > 0 &&
            v2ec_emit(b, vpk, validator_total, tx_hash,
                      NODUS_V2_SETTLE_KIND_VALIDATOR, out_idx++,
                      settling_epoch_start) != 0)
            goto done;
    }

    if (v2ec_flush(b) != 0) goto done;
    *n_utxos_out = b->emitted;
    if (fault && fault(fault_ud, NODUS_V2_EPST_SETTLE_EMITTED, UINT32_MAX))
        goto done;

    /* THE ONE BURN CALL for all three legs (bft.c:3368-3370). V1 casts
     * the return to void; divergence 2 checks it — an unrecorded burn is
     * a supply equation that no longer closes. */
    if (total_burned_here > 0) {
        if (nodus_witness_supply_add_burned(w, total_burned_here,
                                            tx_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "settlement of epoch %llu: recording the %llu burned "
                "(dust + offline shares) failed",
                (unsigned long long)settling_epoch_start,
                (unsigned long long)total_burned_here);
            goto done;
        }
        *burned_out = total_burned_here;
    }

    /* Retire the settled row (bft.c:3376). NOTE: the per-epoch
     * signed-block counter reset that V1 performs just above that line
     * (bft.c:3350-3360) is NOT repeated — divergence 3; the O15C Rule N
     * transplant issues that exact UPDATE immediately after this
     * function returns. */
    {
        int drc = nodus_witness_epoch_delete(w, settling_epoch_start);
        if (drc != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "settlement of epoch %llu: retiring the epoch row failed "
                "(rc=%d)", (unsigned long long)settling_epoch_start, drc);
            goto done;
        }
    }

    if (fault && fault(fault_ud, NODUS_V2_EPST_SETTLE_APPLIED, UINT32_MAX))
        goto done;

    QGP_LOG_DEBUG(LOG_TAG,
        "epoch %llu settled: pool=%llu committee=%u per_slot=%llu "
        "utxos=%u burned=%llu",
        (unsigned long long)settling_epoch_start,
        (unsigned long long)pool, (unsigned)committee_count,
        (unsigned long long)per_slot, (unsigned)*n_utxos_out,
        (unsigned long long)*burned_out);
    ret = 0;

done:
    free(b);
    nodus_witness_epoch_free(&es);
    if (ret != 0) { *n_utxos_out = 0; *burned_out = 0; }
    return ret;
}
