/**
 * @file shared/dnac/env_preflight.c
 * @brief Ledger V2 — generic deterministic envelope preflight.
 *
 * INACTIVE: no live consensus path calls anything here. See env_preflight.h
 * for the purity properties, the LIFETIME RULE the result inherits, the
 * FROZEN CHECK ORDER (which is the contract, not an implementation detail)
 * and the honest label on what a preflight OK does not mean.
 *
 * This file deliberately contains no hashing of its own: every digest is
 * produced by the frozen codec in env_wire.c. It has no includes beyond
 * that codec and the three freestanding headers below — no sqlite, no
 * nodus, no clock, no RNG.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "env_preflight.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

dna_env_preflight_status_t dna_env_preflight(
    const uint8_t *env_bytes, size_t env_len,
    const uint8_t chain_id[DNA_CHAIN_ID_LEN],
    uint64_t proposed_global_height,
    const dna_env_leg_ctx_t *leg_ctx, uint16_t n_leg_ctx,
    dna_env_preflight_t *out) {

    /* Step 0. Fail closed FIRST: `out` is NULL-checked ALONE and zeroed
     * before any other argument is judged, so even a NULL env_bytes reject
     * honours the header's "fully zeroed on every reject" contract
     * (env_wire.c:276-282 discipline). */
    if (!out) return DNA_ENV_PF_ERR_ARG;
    memset(out, 0, sizeof(*out));

    /* Step 1. */
    if (!env_bytes || !chain_id || !leg_ctx) goto fail_arg;

    /* Step 2. ONE authority for framing rejection: the strict codec. */
    if (dna_env_decode(env_bytes, env_len, &out->view) != 0) goto fail_decode;

    /* Step 3. EXPIRY — the locked comparison, verbatim from the header:
     *
     *   for candidate global block height H = proposed_global_height:
     *   expiry_height == 0 -> accept; expiry_height <  H -> reject;
     *   expiry_height == H -> accept; expiry_height >  H -> accept.
     *
     * Direct comparison against H AS PASSED. H is never incremented and no
     * overflow boundary is introduced: an implementation deriving H from
     * parent + 1 would wrap at UINT64_MAX and would accept an envelope
     * that expired at the parent height. 0 is the "no expiry" sentinel and
     * is accepted at every height. */
    if (out->view.expiry_height != 0 &&
        out->view.expiry_height < proposed_global_height) goto fail_expired;

    /* Step 4. The contextual table must describe THIS envelope's legs and
     * no others — a count mismatch is never repaired by truncating. */
    if ((uint32_t)n_leg_ctx != (uint32_t)out->view.leg_count)
        goto fail_ctx_count;

    /* Step 5. POSITIONAL match. Legs are strictly ascending by domain_id
     * (env_wire.c:316-317), so a reordered context table cannot align and
     * lands on ERR_CTX_DOMAIN rather than silently binding the wrong
     * ruleset hash to a leg. */
    for (uint16_t i = 0; i < out->view.leg_count; i++) {
        if (leg_ctx[i].domain_id != out->view.leg[i].domain_id)
            goto fail_ctx_domain;
        if (leg_ctx[i].ruleset_version != out->view.leg[i].ruleset_version)
            goto fail_ctx_version;
    }

    /* Step 6. */
    for (uint16_t i = 0; i < out->view.leg_count; i++)
        if (dna_env_call_commit(&out->view, i, leg_ctx[i].ruleset_hash,
                                out->call_commit[i]) != 0) goto fail_hash;

    /* Step 7. The chain id enters in FULL — all DNA_CHAIN_ID_LEN bytes are
     * handed to the codec as an opaque array; nothing here truncates it,
     * treats it as a C string, or compares it a host word at a time. */
    if (dna_env_auth_context_commit(
            &out->view, chain_id,
            (const uint8_t (*)[DNA_ENV_HASH_LEN])out->call_commit,
            out->auth_context_commit) != 0) goto fail_hash;

    /* Step 8. */
    for (uint16_t i = 0; i < out->view.leg_count; i++)
        if (dna_env_auth_digest(out->auth_context_commit, i,
                                out->view.leg[i].domain_id,
                                out->view.leg[i].runtime_op,
                                out->auth_digest[i]) != 0) goto fail_hash;

    /* Step 9. The DERIVED transaction identity — the only one this API
     * knows. It covers auth_data exactly once, via the complete bytes. */
    if (dna_env_tx_id(out->auth_context_commit, env_bytes, env_len,
                      out->tx_id) != 0) goto fail_hash;

    return DNA_ENV_PF_OK;

/* The ONE reject region. Every exit re-zeroes the WHOLE result, because a
 * partially derived commitment set is exactly the thing a caller must
 * never be able to mistake for a preflighted transaction. */
fail_arg:        memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_ARG;
fail_decode:     memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_DECODE;
fail_expired:    memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_EXPIRED;
fail_ctx_count:  memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_CTX_COUNT;
fail_ctx_domain: memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_CTX_DOMAIN;
fail_ctx_version:memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_CTX_VERSION;
fail_hash:       memset(out, 0, sizeof(*out)); return DNA_ENV_PF_ERR_HASH;
}
