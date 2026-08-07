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
     * bytes 16..31 are always zero (nodus_witness.c:265-280), and binding
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
     * sharing a prefix pass as distinct. */
    for (size_t i = 0; i < n_envs; i++)
        for (size_t j = i + 1; j < n_envs; j++)
            if (memcmp(out[i].tx_id, out[j].tx_id, DNA_ENV_HASH_LEN) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "duplicate derived tx_id at batch "
                              "indices %zu and %zu", i, j);
                /* the SECOND member: the first occurrence is the one that
                 * was legitimately there */
                if (fail_index_out) *fail_index_out = j;
                goto fail_dup;
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
}
