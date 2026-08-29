/**
 * Nodus — Ledger V2: the witness-side ENVELOPE PREFLIGHT SEAM (INACTIVE).
 * Contract, activation banner, the six later switch sites and the list of
 * responsibilities NOT implemented this season: nodus_witness_v2_env.h.
 *
 * This module derives; it does not decide and it does not write. The only
 * SQL it reaches is the read-only genesis lookup inside
 * nodus_witness_v2_chain_id (nodus_witness_v2_claims.c:186-203).
 *
 * @file nodus_witness_v2_env.c
 */

#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_claims.h"

#include "crypto/utils/qgp_log.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LOG_TAG "W_V2ENV"

/**
 * Resolve one leg's domain to its contextual ruleset entry.
 *
 * Linear scan: the table is one entry per REGISTERED domain, so it is a
 * handful of entries and strictly ascending (the caller's gate below
 * proves it). Ascending order is what makes "the entry for this domain"
 * unambiguous — it cannot hold two entries for one domain.
 *
 * @return the entry, or NULL if this domain has none.
 */
static const dna_env_leg_ctx_t *ctx_for_domain(
        const dna_env_leg_ctx_t *rulesets, size_t n, uint32_t domain_id) {
    for (size_t i = 0; i < n; i++)
        if (rulesets[i].domain_id == domain_id) return &rulesets[i];
    return NULL;
}

nodus_v2_env_status_t nodus_witness_v2_env_preflight_batch(
        nodus_witness_t *w,
        uint64_t proposed_global_height,
        const dna_env_leg_ctx_t *rulesets, size_t n_rulesets,
        const nodus_v2_envelope_t *envs, size_t n_envs,
        dna_env_preflight_t *out,
        size_t *fail_index_out,
        dna_env_preflight_status_t *pf_status_out) {

    if (!out) return NODUS_V2_ENV_ERR_ARG;

    /* The batch size is validated BEFORE the array is cleared. Zeroing
     * `n_envs` entries is a write through a caller-supplied length, and a
     * length that has not been checked is not a length — an out-of-range
     * n_envs would turn the fail-closed memset into an overrun. Once the
     * count is known legal the ENTIRE array is cleared, which is what
     * makes "a failed batch publishes NOTHING" true even for a caller
     * buffer that arrived dirty. */
    if (n_envs == 0 || n_envs > NODUS_V2_ENV_BATCH_MAX)
        return NODUS_V2_ENV_ERR_ARG;
    memset(out, 0, n_envs * sizeof(*out));

    if (fail_index_out) *fail_index_out = 0;
    if (pf_status_out)  *pf_status_out  = DNA_ENV_PF_OK;

    if (!w || !w->db || !rulesets || n_rulesets == 0 || !envs)
        goto fail_arg;

    /* Every envelope must actually carry bytes. Checked HERE, at the
     * argument stage, rather than being discovered by the decode below:
     * dna_env_preflight answers a NULL pointer with ERR_ARG, not
     * ERR_DECODE, so letting a NULL fall through to the decode path would
     * report the wrong reason and break the equivalence documented at
     * that call site. */
    for (size_t i = 0; i < n_envs; i++)
        if (!envs[i].env_bytes) {
            if (fail_index_out) *fail_index_out = i;
            goto fail_arg;
        }

    /* The AUTHORITATIVE chain identity: the committed genesis block_id,
     * full 32 bytes. Never w->chain_id — that is the LEGACY value whose
     * bytes 16..31 are always zero (nodus_witness.c:286-301), and binding
     * a transaction to a half-zero chain id would make two chains sharing
     * a 16-byte prefix indistinguishable. There is no parameter and no
     * fallback: a chain with no committed genesis has no identity, so
     * nothing here is derivable. */
    uint8_t chain[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(w, chain) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "no derivable V2 chain id (no committed "
                      "genesis, or a chain-DB fault — the helper does not "
                      "distinguish) — rejecting %zu envelope(s)", n_envs);
        goto fail_chain;
    }

    /* STRICTLY ascending by domain_id: duplicates and descending both
     * reject, so the table has exactly one entry per domain. */
    for (size_t i = 1; i < n_rulesets; i++)
        if (rulesets[i - 1].domain_id >= rulesets[i].domain_id) {
            QGP_LOG_ERROR(LOG_TAG, "ruleset table not strictly ascending "
                          "at index %zu", i);
            goto fail_rulesets;
        }

    for (size_t i = 0; i < n_envs; i++) {
        /* A local view, used ONLY to learn which domains this envelope's
         * legs address so the POSITIONAL context can be built. ~2.6 KB
         * automatic, no recursion. */
        dna_env_view_t local;
        if (dna_env_decode(envs[i].env_bytes, envs[i].env_len, &local) != 0) {
            /* dna_env_preflight would return exactly DNA_ENV_PF_ERR_DECODE
             * for these same bytes — it is the SAME strict decoder, called
             * deterministically on the same input — so reporting it
             * directly costs nothing and keeps one authority for framing
             * rejection. (The NULL-pointer case cannot arrive here: it was
             * gated above, precisely because that is the one input on
             * which the two answers would differ.) */
            if (fail_index_out) *fail_index_out = i;
            if (pf_status_out)  *pf_status_out  = DNA_ENV_PF_ERR_DECODE;
            goto fail_preflight;
        }

        dna_env_leg_ctx_t legs[DNA_ENV_MAX_LEGS];
        memset(legs, 0, sizeof(legs));
        for (uint16_t l = 0; l < local.leg_count; l++) {
            const dna_env_leg_ctx_t *e =
                ctx_for_domain(rulesets, n_rulesets, local.leg[l].domain_id);
            if (!e) {
                QGP_LOG_ERROR(LOG_TAG, "envelope %zu leg %u addresses "
                              "domain %u with no ruleset entry",
                              i, (unsigned)l,
                              (unsigned)local.leg[l].domain_id);
                if (fail_index_out) *fail_index_out = i;
                goto fail_ctx_missing;
            }
            legs[l] = *e;
        }

        dna_env_preflight_status_t st =
            dna_env_preflight(envs[i].env_bytes, envs[i].env_len, chain,
                              proposed_global_height, legs, local.leg_count,
                              &out[i]);
        if (st != DNA_ENV_PF_OK) {
            if (fail_index_out) *fail_index_out = i;
            if (pf_status_out)  *pf_status_out  = st;
            goto fail_preflight;
        }
    }

    /* Duplicate detection runs over the DERIVED identities only, and only
     * after every envelope has produced one. EXACTLY DNA_ENV_HASH_LEN
     * bytes are compared: a short compare would let two transactions
     * sharing a prefix pass as distinct. Wire-level first (byte-identical
     * resubmission), then INTENT-level (intent season): two envelopes
     * differing only in authorization evidence carry ONE intent under two
     * wire_ids and are ONE semantic transaction — the second is rejected. */
    for (size_t i = 0; i < n_envs; i++)
        for (size_t j = i + 1; j < n_envs; j++)
            if (memcmp(out[i].wire_id, out[j].wire_id,
                       DNA_ENV_HASH_LEN) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "duplicate derived wire_id at batch "
                              "indices %zu and %zu", i, j);
                /* the SECOND member: the first occurrence is the one that
                 * was legitimately there */
                if (fail_index_out) *fail_index_out = j;
                goto fail_dup;
            }
    for (size_t i = 0; i < n_envs; i++)
        for (size_t j = i + 1; j < n_envs; j++)
            if (memcmp(out[i].intent_id, out[j].intent_id,
                       DNA_ENV_HASH_LEN) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "duplicate derived intent_id at "
                              "batch indices %zu and %zu (same semantic "
                              "transaction under different authorization)",
                              i, j);
                if (fail_index_out) *fail_index_out = j;
                goto fail_dup_intent;
            }

    return NODUS_V2_ENV_OK;

/* Every reject clears the WHOLE array, including entries that had already
 * succeeded — a failed batch publishes NOTHING. */
fail_arg:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_ARG;
fail_chain:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_CHAIN;
fail_rulesets:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_RULESETS;
fail_ctx_missing:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_CTX_MISSING;
fail_preflight:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_PREFLIGHT;
fail_dup:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_DUP;
fail_dup_intent:
    memset(out, 0, n_envs * sizeof(*out));
    return NODUS_V2_ENV_ERR_DUP_INTENT;
}

/*
 * THE ONE seam-status -> producer-action table.
 *
 * The FAULT row is copied from the apply engine's own routing of this
 * seam's rejection (nodus_witness_v2_apply.c, the branch right after
 * preflight_reserve_batch): ERR_HASH is "this node could not compute" and
 * env_preflight.h forbids turning it into a transaction rejection;
 * DNA_METER_ERR_FAULT is an accounting invariant break in this build; an
 * underivable chain id is a chain-DB read failure. Everything else the
 * engine treats as a deterministic verdict, and so does this table — the
 * two must agree, because a propose-time answer that is kinder than the
 * commit-time answer is exactly the burnt round this classification
 * exists to prevent, and one that is harsher destroys valid work.
 *
 * The CAPACITY rows are the split that is NEW: the engine has no reason
 * to distinguish "bad entry" from "full block" (it rejects the whole
 * candidate either way), but a PRODUCER does — one means drop, the other
 * means propose less.
 */
nodus_v2_batch_fail_kind_t nodus_witness_v2_env_fail_kind(
        nodus_v2_env_status_t st,
        dna_env_preflight_status_t pf,
        dna_meter_status_t ms) {
    switch (st) {
        case NODUS_V2_ENV_OK:
            return NODUS_V2_BATCH_FAIL_NONE;

        case NODUS_V2_ENV_ERR_CHAIN:
            /* No committed genesis, or a chain-DB fault — the helper does
             * not distinguish, and neither can a verdict. */
            return NODUS_V2_BATCH_FAIL_FAULT;

        case NODUS_V2_ENV_ERR_PREFLIGHT:
            return pf == DNA_ENV_PF_ERR_HASH
                       ? NODUS_V2_BATCH_FAIL_FAULT
                       : NODUS_V2_BATCH_FAIL_ENTRY_INVALID;

        case NODUS_V2_ENV_ERR_METER:
            if (ms == DNA_METER_ERR_FAULT)
                return NODUS_V2_BATCH_FAIL_FAULT;
            /* 7 and 8 are the only two "the block is FULL" statuses: the
             * envelope's own plan was priceable and legal, the remaining
             * budget simply could not pay for it AT THIS POSITION. Every
             * other meter status (POLICY, OP_WEIGHT, DECL, OVERFLOW,
             * CEILING, DOMAIN, LIMIT, STATE) is a property of the bytes
             * and does not improve in a shorter block. */
            if (ms == DNA_METER_ERR_GLOBAL_BUDGET ||
                ms == DNA_METER_ERR_DOMAIN_BUDGET)
                return NODUS_V2_BATCH_FAIL_CAPACITY_UNITS;
            return NODUS_V2_BATCH_FAIL_ENTRY_INVALID;

        case NODUS_V2_ENV_ERR_BLOCK_BYTES:
            return NODUS_V2_BATCH_FAIL_CAPACITY_BYTES;

        case NODUS_V2_ENV_ERR_ARG:
        case NODUS_V2_ENV_ERR_RULESETS:
        case NODUS_V2_ENV_ERR_CTX_MISSING:
        case NODUS_V2_ENV_ERR_DUP:
        case NODUS_V2_ENV_ERR_DUP_INTENT:
            return NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
    }
    /* No default label above: adding a status to the enum must break the
     * build here rather than silently fall into one of the two actions.
     * An out-of-enum value still has to answer something, and the
     * conservative answer is "this node has no verdict". */
    return NODUS_V2_BATCH_FAIL_FAULT;
}

int nodus_witness_v2_block_bytes_check(const size_t *lens, size_t n,
                                       uint64_t max_block_env_bytes) {
    if (n == 0 || !lens) return -1;
    if (max_block_env_bytes == 0) return -1;   /* an unbounded block is
                                                * not a configuration    */
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        if (dna_ck_add_u64(sum, (uint64_t)lens[i], &sum) != 0)
            return -1;                          /* checked overflow       */
    }
    return sum <= max_block_env_bytes ? 0 : -1;
}

nodus_v2_env_status_t nodus_witness_v2_env_preflight_reserve_batch(
        nodus_witness_t *w,
        uint64_t proposed_global_height,
        const dna_env_leg_ctx_t *rulesets, size_t n_rulesets,
        const dna_meter_policy_t *policy,
        dna_meter_budget_t *budget,
        const nodus_v2_envelope_t *envs, size_t n_envs,
        dna_env_preflight_t *out,
        dna_meter_t *meters_out,
        size_t *fail_index_out,
        dna_env_preflight_status_t *pf_status_out,
        dna_meter_status_t *meter_status_out) {

    /* Step 1 — the unvalidated-count rule, extended to BOTH caller
     * arrays: nothing is written through an unchecked length or a NULL
     * pointer. These three rejects touch neither buffer. */
    if (!out || !meters_out) return NODUS_V2_ENV_ERR_ARG;
    if (n_envs == 0 || n_envs > NODUS_V2_ENV_BATCH_MAX)
        return NODUS_V2_ENV_ERR_ARG;
    memset(meters_out, 0, n_envs * sizeof(*meters_out));
    /* `out` is zeroed by the base entry below (or by the fail exits). */

    if (meter_status_out) *meter_status_out = DNA_METER_OK;

    /* Step 2. */
    if (!policy || !budget) {
        memset(out, 0, n_envs * sizeof(*out));
        if (fail_index_out) *fail_index_out = 0;
        if (pf_status_out)  *pf_status_out  = DNA_ENV_PF_OK;
        return NODUS_V2_ENV_ERR_ARG;
    }

    /* Step 3 — the ENTIRE base preflight, unchanged. Its rejects
     * propagate verbatim; meters_out is already zeroed. */
    nodus_v2_env_status_t st = nodus_witness_v2_env_preflight_batch(
        w, proposed_global_height, rulesets, n_rulesets, envs, n_envs,
        out, fail_index_out, pf_status_out);
    if (st != NODUS_V2_ENV_OK) return st;

    /* Step 4 — one policy check for the whole batch. */
    if (dna_meter_policy_check(policy) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "metering policy failed its self-check — "
                      "rejecting %zu envelope(s)", n_envs);
        memset(out, 0, n_envs * sizeof(*out));
        memset(meters_out, 0, n_envs * sizeof(*meters_out));
        if (fail_index_out)   *fail_index_out   = 0;
        if (meter_status_out) *meter_status_out = DNA_METER_ERR_POLICY;
        return NODUS_V2_ENV_ERR_METER;
    }

    /* Step 4b — ABSOLUTE block-byte admission (capacity season), BEFORE
     * any reservation: a byte-rejected batch never touches the unit
     * budget, and the distinct status cannot be masked by unit
     * exhaustion (header doc — the order is load-bearing). The lengths
     * summed are the DECODE-ACCEPTED exact lengths, not the caller's
     * claims: preflight proved env_len == the length the bytes imply. */
    {
        size_t lens[NODUS_V2_ENV_BATCH_MAX];
        for (size_t i = 0; i < n_envs; i++)
            lens[i] = out[i].view.env_len;
        if (nodus_witness_v2_block_bytes_check(lens, n_envs,
                policy->max_block_env_bytes) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "block byte bound rejected the batch "
                          "(%zu envelope(s), bound %llu)", n_envs,
                          (unsigned long long)policy->max_block_env_bytes);
            memset(out, 0, n_envs * sizeof(*out));
            memset(meters_out, 0, n_envs * sizeof(*meters_out));
            if (fail_index_out) *fail_index_out = 0;
            return NODUS_V2_ENV_ERR_BLOCK_BYTES;
        }
    }

    /* Step 5 — sequential reservation. The snapshot makes the batch
     * atomic: any failure restores the caller's budget byte-identically
     * (deterministic release of every earlier envelope's reservation)
     * and publishes nothing. ~1 KB automatic, no recursion. */
    dna_meter_budget_t snapshot = *budget;
    for (size_t i = 0; i < n_envs; i++) {
        dna_meter_status_t ms = dna_meter_reserve(&meters_out[i], policy,
                                                  &out[i].view, budget);
        if (ms != DNA_METER_OK) {
            QGP_LOG_ERROR(LOG_TAG, "reservation rejected at batch index "
                          "%zu (meter status %d)", i, (int)ms);
            *budget = snapshot;
            memset(out, 0, n_envs * sizeof(*out));
            memset(meters_out, 0, n_envs * sizeof(*meters_out));
            if (fail_index_out)   *fail_index_out   = i;
            if (meter_status_out) *meter_status_out = ms;
            return NODUS_V2_ENV_ERR_METER;
        }
    }

    return NODUS_V2_ENV_OK;
}
