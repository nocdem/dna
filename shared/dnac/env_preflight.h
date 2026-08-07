/**
 * @file shared/dnac/env_preflight.h
 * @brief Ledger V2 — generic DETERMINISTIC envelope preflight (INACTIVE).
 *
 * One function turns raw envelope bytes plus two CONTEXTUAL inputs (the
 * chain identity and the per-leg contextual ruleset identities) into the
 * complete typed commitment set of that transaction — including the
 * DERIVED transaction id, which is the ONLY transaction identity this API
 * knows. There is no caller-supplied transaction-ID parameter anywhere in
 * this header: an id that is claimed rather than derived is a forgery
 * surface, so the type system simply does not offer one.
 *
 * ACTIVATION: INACTIVE. No live consensus path calls anything here; the
 * active chain keeps the legacy V2 wire, the v3 five-input state_root and
 * the V1 block hash byte-identical. This module activates only with the
 * Ledger V2 devnet reset.
 *
 * ── What this module is ────────────────────────────────────────────────
 * It adds NO new preimage and NO new hash. Every digest it produces comes
 * out of the FROZEN codec in env_wire.{h,c}; the preflight contributes the
 * fixed ORDER those four helpers run in, plus purely structural gates that
 * hash nothing (expiry comparison, positional contextual-ruleset match).
 * That is deliberate: a second place that knows a commitment preimage is a
 * second place that can drift from consensus.
 *
 * ── PURITY (the properties every caller may rely on) ───────────────────
 *   - no database handle, no runtime, no registry, no nodus header;
 *   - no wall clock, no RNG, no environment, no global or static state;
 *   - no state mutation of ANY kind — the function only writes *out;
 *   - no allocation of its own. (The frozen codec's dna_env_call_commit
 *     and dna_env_tx_id do malloc their preimage internally and free it
 *     before returning — env_wire.c:388 / :503 — which is the documented
 *     behaviour of the codec this module consumes, not new behaviour.)
 *   - checked arithmetic only, all of it inherited from the codec's
 *     subtraction-form length guards;
 *   - BOUNDED STACK: this function's own frame is a few pointers and
 *     counters. The deepest stack it reaches is the codec's
 *     auth_context_commit preimage — 6107 bytes worst case, pinned by
 *     env_wire.c:97. Nothing here recurses.
 *
 * Two nodes handed the same bytes and the same contextual inputs therefore
 * produce byte-identical results, which is the whole point: the derived
 * tx_id is consensus material.
 *
 * ── LIFETIME RULE (inherited, and it applies to the RESULT too) ────────
 * dna_env_preflight_t embeds a dna_env_view_t, and that view BORROWS
 * `env_bytes` exactly as dna_env_decode's does (env_wire.h:240-251).
 * The result is valid ONLY while the caller's envelope buffer stays alive
 * AND unmodified. The commitment arrays (call_commit / auth_context_commit
 * / auth_digest / tx_id) are owned COPIES and stay valid regardless — it
 * is the `view` member, and only that member, that dangles.
 *
 * ── HONEST LABEL: what the preflight does NOT decide ───────────────────
 * Everything the codec declines to check (env_wire.h:125-136) it also
 * declines to check, plus: whether a domain exists / is ACTIVE, whether an
 * operation belongs to that domain, whether a runtime is resolvable,
 * whether the fee is payable, and whether any authorization is VALID.
 * A preflight OK means "this is a well-formed, unexpired, correctly
 * contextualised envelope and here are its commitments" — never
 * "this transaction may execute".
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_ENV_PREFLIGHT_H
#define SHARED_DNAC_ENV_PREFLIGHT_H

#include <stdint.h>
#include <stddef.h>

#include "env_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Why the preflight rejected. Distinct codes for distinct causes: a caller
 * that must log or route a rejection never has to guess, and a test can
 * pin WHICH gate fired rather than merely that one did.
 */
typedef enum {
    DNA_ENV_PF_OK              = 0,
    DNA_ENV_PF_ERR_ARG         = 1,  /* NULL argument                      */
    DNA_ENV_PF_ERR_DECODE      = 2,  /* strict codec rejected the bytes    */
    DNA_ENV_PF_ERR_EXPIRED     = 3,  /* expiry_height below the candidate  */
    DNA_ENV_PF_ERR_CTX_COUNT   = 4,  /* n_leg_ctx != decoded leg_count     */
    DNA_ENV_PF_ERR_CTX_DOMAIN  = 5,  /* context[i] addresses another domain*/
    DNA_ENV_PF_ERR_CTX_VERSION = 6,  /* context[i] carries another version */
    DNA_ENV_PF_ERR_HASH        = 7   /* a codec commitment helper failed —
                                      * see the FAULT note below           */
} dna_env_preflight_status_t;

/*
 * ── ERR_HASH is a NODE fault, never an envelope verdict ────────────────
 * Once the strict decode has accepted the bytes, every structural
 * precondition of the four codec helpers holds by construction (bounds
 * pinned by env_wire.c's leg_hdr_ok / env_acc_add / decode walk). The
 * only ways a helper can then fail are node-local: malloc returning NULL
 * for a preimage buffer (env_wire.c:388, :503) or the SHA3 backend
 * failing. ERR_HASH therefore says "THIS NODE could not compute", not
 * "this envelope is bad". A consensus caller MUST NOT translate it into
 * a transaction rejection — one starved witness voting reject while the
 * rest vote accept is a confident wrong answer. Fail the node's own
 * operation instead (do not vote / do not propose).
 */

/**
 * ONE authoritative contextual ruleset identity, as the caller resolved it
 * for one leg. `ruleset_hash` is the value the codec binds into
 * call_commit (env_wire.h:82-84) — it is NOT carried on the envelope wire,
 * which is exactly why it must be supplied and matched here.
 *
 * `domain_id` and `ruleset_version` are NOT redundant with the wire: they
 * are the caller's CLAIM about which (domain, version) pair this hash was
 * resolved for, and the preflight rejects if that claim disagrees with the
 * envelope. Without them a caller could silently bind leg 0's hash to
 * leg 1's leg.
 */
typedef struct {
    uint32_t domain_id;
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_ENV_RULESET_HASH_LEN];
} dna_env_leg_ctx_t;

/**
 * The typed preflight result: one decoded view plus the complete
 * commitment set, fully populated on OK and fully ZEROED on every reject.
 *
 * Slots at or beyond view.leg_count are always zero (the whole struct is
 * memset before any work), so a caller cannot read a stale digest out of
 * an unused slot.
 */
typedef struct {
    dna_env_view_t view;      /* BORROWS env_bytes — see the LIFETIME RULE */
    uint8_t call_commit[DNA_ENV_MAX_LEGS][DNA_ENV_HASH_LEN];
    uint8_t auth_context_commit[DNA_ENV_HASH_LEN];
    uint8_t auth_digest[DNA_ENV_MAX_LEGS][DNA_ENV_HASH_LEN];
    uint8_t tx_id[DNA_ENV_HASH_LEN];   /* THE authoritative transaction id */
} dna_env_preflight_t;

/* Explicit size audit. MEASURED on this build (x86-64, gcc, printed by
 * test_env_preflight): 10936 bytes — view 2616 + call_commit 4096 +
 * auth_context_commit 64 + auth_digest 4096 + tx_id 64. Multi-KB is why
 * every caller and every test HEAP-allocates this type instead of putting
 * it on the stack, and why the batch seam bounds its array. The ceiling is
 * a tripwire on a field being added carelessly, not a tuned limit. */
_Static_assert(sizeof(dna_env_preflight_t) <= 16384,
               "dna_env_preflight_t grew past its audited size ceiling");

/**
 * Deterministically preflight ONE envelope.
 *
 * ── FROZEN CHECK ORDER (the order IS the contract) ─────────────────────
 * A caller that logs or routes on the status depends on WHICH gate fires
 * first, so the sequence below is frozen. An envelope that is both expired
 * AND carries a mismatched context returns ERR_EXPIRED, never the other.
 *
 *   0. `out` NULL -> ERR_ARG. Otherwise the ENTIRE *out is zeroed BEFORE
 *      anything else is examined.
 *   1. `env_bytes` / `chain_id` / `leg_ctx` NULL -> ERR_ARG.
 *   2. strict dna_env_decode into out->view; rejected -> ERR_DECODE.
 *   3. EXPIRY, against the CANDIDATE block height H (verbatim, locked):
 *
 *        for candidate global block height H = proposed_global_height:
 *        expiry_height == 0 -> accept; expiry_height <  H -> reject;
 *        expiry_height == H -> accept; expiry_height >  H -> accept.
 *
 *      Implemented as EXACTLY one comparison against the height as passed:
 *      `expiry_height != 0 && expiry_height < proposed_global_height`.
 *      H is NEVER incremented and no overflow boundary is introduced —
 *      an implementation that computed parent_height + 1 would have a
 *      wrap case at UINT64_MAX and would accept an envelope that expired
 *      at the parent. 0 means "no expiry", so it is accepted at every H.
 *   4. n_leg_ctx != view.leg_count -> ERR_CTX_COUNT.
 *   5. POSITIONAL per-leg match, i = 0..leg_count-1:
 *        leg_ctx[i].domain_id       != view.leg[i].domain_id
 *          -> ERR_CTX_DOMAIN;
 *        leg_ctx[i].ruleset_version != view.leg[i].ruleset_version
 *          -> ERR_CTX_VERSION.
 *      Positional (not "search for the matching domain") is what makes a
 *      REORDERED context table reject: envelope legs are strictly
 *      ascending by domain_id, so any swap lands on ERR_CTX_DOMAIN.
 *   6. call_commit[i] for every leg, via dna_env_call_commit with that
 *      leg's contextual ruleset_hash; any failure -> ERR_HASH.
 *   7. auth_context_commit, via dna_env_auth_context_commit. The chain_id
 *      enters here in FULL — all 32 bytes, no truncation, no C-string
 *      handling, no host-word comparison; failure -> ERR_HASH.
 *   8. auth_digest[i] for every leg; any failure -> ERR_HASH.
 *   9. tx_id over auth_context_commit + the complete env_bytes;
 *      failure -> ERR_HASH.
 *  10. DNA_ENV_PF_OK.
 *
 * ON EVERY FAILURE after step 0 the ENTIRE *out is zeroed AGAIN before
 * returning, so no usable partial result can ever escape — the same
 * discipline the codec's own reject exit applies (env_wire.c:353-359).
 * A zeroed result is unmistakable: view.leg_count == 0, view.buf == NULL,
 * tx_id all zero.
 *
 * @param env_bytes             the exact candidate envelope bytes;
 *                              BORROWED by out->view on success.
 * @param env_len               their length; must be EXACT (the codec
 *                              rejects truncation and trailing bytes).
 * @param chain_id              CONTEXTUAL 32-byte chain identity; the
 *                              caller derives it from committed chain
 *                              state, never from the envelope.
 * @param proposed_global_height the CANDIDATE block's height (the block
 *                              this envelope would be included in), not
 *                              the parent's.
 * @param leg_ctx               n_leg_ctx entries, POSITIONALLY aligned to
 *                              the envelope's legs.
 * @param n_leg_ctx             must equal the decoded leg_count.
 * @param out                   MANDATORY; fully written on OK, fully
 *                              zeroed on every reject.
 * @return a dna_env_preflight_status_t.
 */
dna_env_preflight_status_t dna_env_preflight(
    const uint8_t *env_bytes, size_t env_len,
    const uint8_t chain_id[DNA_CHAIN_ID_LEN],
    uint64_t proposed_global_height,
    const dna_env_leg_ctx_t *leg_ctx, uint16_t n_leg_ctx,
    dna_env_preflight_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_ENV_PREFLIGHT_H */
