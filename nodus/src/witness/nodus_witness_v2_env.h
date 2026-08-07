/**
 * @file nodus_witness_v2_env.h
 * @brief Ledger V2 — the witness-side ENVELOPE PREFLIGHT SEAM: the one
 *        place the engine turns candidate envelope bytes into DERIVED
 *        transaction identities (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. The active chain keeps the
 * legacy V2 wire, the v3 five-input state_root and the V1 block hash
 * byte-identical; Type 11 stays REJECT. Tests drive this module, and the
 * V2 devnet reset is what activates it.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── Why this module exists ────────────────────────────────────────────
 * The S5 apply engine currently accepts a transaction identity from its
 * CALLER (nodus_v2_op_t.tx_id, nodus_witness_v2_apply.h:195). That is a
 * test-surface shape: a caller-asserted id cannot be checked against the
 * bytes it claims to identify, so two different transactions could be
 * presented under one id, or one transaction under two. This seam removes
 * the choice — an id here is DERIVED from the envelope bytes, the chain
 * identity and the contextual ruleset set, and from nothing else.
 *
 * Note that nodus_v2_envelope_t deliberately has NO tx_id field. The
 * absence is the mechanism: there is no way to hand this API an identity,
 * so there is no way for a caller-chosen one to reach the engine.
 *
 * ── The later switch sites (derived-ID adoption; NOT done this season) ─
 * When the engine moves off caller-supplied ids, exactly these six places
 * in nodus_witness_v2_apply.c consume nodus_v2_op_t.tx_id and must read
 * the derived dna_env_preflight_t.tx_id instead:
 *
 *   :727-730  in-block duplicate-identity check (the pairwise memcmp)
 *   :748      per-domain tx id lists (dom_ctx_t.tx_ids, feeds :1076)
 *   :1076     per-domain tx_batch_root (dna_v2_tx_batch_root over that
 *             domain's ids — a DomainUpdate field, consensus material)
 *   :1182     v2_tx_index insert (the global transaction index blob)
 *   :1194-1199 local-index MATCH: op->tx_id is memcmp'd against
 *             dom_ctx_t.tx_ids to derive local_index — and a match miss
 *             silently defaults to lidx = 0 rather than rejecting.
 *             Guaranteed-by-construction today (:748 fills the array
 *             from the same ops); a migration that switches :748 and
 *             this site on different schedules turns the miss into a
 *             SILENT wrong index. Migrate them together.
 *   :1207     v2_tx_local_index insert (per-domain local index blob)
 *   :1240     the block-level tx_root over all ids in phase order
 *
 * Every one of those is consensus material, which is why the switch is
 * its own slice with its own tests rather than a drive-by change here.
 *
 * ── NOT implemented this season (the caller's remaining obligations) ───
 * A NODUS_V2_ENV_OK from this seam means "these envelopes are well-formed,
 * unexpired against the candidate height, correctly contextualised, and
 * their derived identities are distinct". It does NOT mean any of the
 * following, all of which stay with the later caller:
 *
 *   - DOMAIN ACTIVE-STATE ENFORCEMENT — whether each leg's domain is
 *     registered and ACTIVE at block entry (today apply.c:744);
 *   - OPERATION OWNERSHIP — whether runtime_op belongs to that domain's
 *     committed ruleset at all;
 *   - RUNTIME READINESS / TABLE RESOLUTION — whether this build can
 *     resolve the domain's committed runtime tuple
 *     (nodus_witness_v2_runtime_for);
 *   - MID-BLOCK LIFECYCLE — a domain activated by this very block does
 *     not execute in it; the seam is height-agnostic about that;
 *   - HEIGHT CONTINUITY — the replay/linkage matrix stays where it is
 *     (apply.c:694); this seam only COMPARES against the candidate
 *     height it is handed, it never decides what that height should be;
 *   - BLOCK-START RULESET-SNAPSHOT CONSTRUCTION — the `rulesets` table
 *     below is an INPUT. Building it once per block from the committed
 *     registry, and proving it is the right snapshot, is the caller's;
 *   - AUTHORIZATION — auth_kind interpretation, signature verification,
 *     and every other question about whether a leg is permitted;
 *   - INTENT-LEVEL REPLAY — the batch dedup key is tx_id, which covers
 *     auth_data; the INTENT commitment (auth_context_commit)
 *     deliberately does not (env_wire.h:105-118). Two envelopes
 *     differing only in auth_data therefore carry ONE authorized intent
 *     under TWO distinct tx_ids, and BOTH pass this dedup (pinned by
 *     test_v2_env_preflight "AUTH-DATA MALLEABILITY"). Byte-level dedup
 *     is what this season locks; collapsing same-intent envelopes —
 *     via auth_context_commit equality, auth-kind canonicality, or
 *     state-level conflict — is the EXECUTION/AUTHORIZATION seasons'
 *     obligation. The intent key is already computed and exported in
 *     dna_env_preflight_t precisely so that caller need not rederive it;
 *   - FAULT vs VERDICT — a preflight ERR_HASH is a NODE-LOCAL fault
 *     (see env_preflight.h's ERR_HASH note), not a statement about the
 *     envelope. A consensus caller must fail ITS OWN operation on it
 *     (do not vote), never convert it into a transaction rejection —
 *     one witness under memory pressure voting "reject" while the rest
 *     vote "accept" is a confident wrong answer, not silence;
 *   - EXECUTION — nothing here runs, mutates or prices anything.
 *
 * ── Determinism ───────────────────────────────────────────────────────
 * The only input this module reads that is not an argument is the
 * committed genesis row, through nodus_witness_v2_chain_id — a read-only
 * point SELECT on `global_height = 0`. There is no clock, no RNG, no
 * unordered iteration, and no write of any kind. Two witnesses handed the
 * same batch, on the same chain, at the same candidate height, WITH THE
 * SAME CONTEXTUAL RULESET TABLE, produce byte-identical results. That
 * last condition is load-bearing, not decorative: ruleset_hash flows
 * call_commit → auth_context_commit → tx_id, so witnesses whose tables
 * come from registry snapshots taken at different moments derive
 * DIFFERENT identities for byte-identical envelopes. The guarantee is
 * therefore CONDITIONAL on the block-start snapshot obligation above —
 * it does not discharge it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_ENV_H
#define NODUS_WITNESS_V2_ENV_H

#include "witness/nodus_witness.h"
#include "dnac/env_preflight.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Largest batch this seam preflights in one call.
 *
 * Aligned with the apply engine's own op bound MAX_OPS
 * (nodus_witness_v2_apply.c:36), so a batch that passes here can never be
 * larger than the block the engine could accept. Both are array bounds,
 * not policy: the GLOBAL per-block transaction cap is chain-config
 * (MAX_TXS_PER_BLOCK) and is enforced by the engine, not here.
 */
#define NODUS_V2_ENV_BATCH_MAX 16

/**
 * One candidate envelope: bytes and length, nothing else.
 *
 * There is deliberately NO tx_id field — see "Why this module exists".
 * The bytes are BORROWED for the duration of the call and by the
 * resulting dna_env_preflight_t.view afterwards (env_preflight.h's
 * LIFETIME RULE); they must outlive any use of that view.
 */
typedef struct {
    const uint8_t *env_bytes;
    size_t         env_len;
} nodus_v2_envelope_t;

/** Why the batch was rejected. */
typedef enum {
    NODUS_V2_ENV_OK = 0,
    NODUS_V2_ENV_ERR_ARG,          /* NULL/one out-of-range argument       */
    NODUS_V2_ENV_ERR_CHAIN,        /* authoritative chain id underivable
                                    * (no committed V2 genesis)            */
    NODUS_V2_ENV_ERR_RULESETS,     /* context table NULL or not strictly
                                    * ascending by domain_id               */
    NODUS_V2_ENV_ERR_CTX_MISSING,  /* a decoded leg's domain has no entry
                                    * in the context table                 */
    NODUS_V2_ENV_ERR_PREFLIGHT,    /* dna_env_preflight rejected — the
                                    * exact reason is in pf_status_out     */
    NODUS_V2_ENV_ERR_DUP           /* duplicate DERIVED tx_id in the batch */
} nodus_v2_env_status_t;

/**
 * Preflight a whole batch of candidate envelopes against ONE chain
 * identity and ONE contextual ruleset table.
 *
 * ── FROZEN behaviour ──────────────────────────────────────────────────
 *   1. Argument gates (w, w->db, rulesets non-NULL with n_rulesets >= 1,
 *      envs, out, n_envs in [1, NODUS_V2_ENV_BATCH_MAX]) -> ERR_ARG. The
 *      ENTIRE out array is zeroed immediately after the out NULL check
 *      AND the n_envs range gate — an unvalidated count must never drive
 *      a write, so on `out == NULL` or an out-of-range n_envs the
 *      function returns ERR_ARG WITHOUT touching the caller's buffer.
 *      From every later reject the whole array is (re)zeroed.
 *   2. The chain id is DERIVED, via nodus_witness_v2_chain_id (the
 *      committed genesis v2_blocks row -> dna_bh2_derive_chain_id). That
 *      is the ONLY source: never w->chain_id (the LEGACY 16-byte-derived
 *      value whose bytes 16..31 are zero — nodus_witness.c:265-280), never
 *      a parameter, never a fallback. Underivable -> ERR_CHAIN.
 *   3. The context table must be STRICTLY ascending by domain_id
 *      (duplicates and descending both reject) -> ERR_RULESETS. Ascending
 *      is what makes "the entry for this domain" unambiguous.
 *   4. Per envelope, in index order: resolve each decoded leg's domain to
 *      a table entry (missing -> ERR_CTX_MISSING) and preflight through
 *      dna_env_preflight with the POSITIONAL context that produces.
 *   5. A preflight rejection -> ERR_PREFLIGHT, with the shared status in
 *      *pf_status_out and the envelope index in *fail_index_out.
 *   6. Only after ALL envelopes succeed: duplicate detection over the
 *      DERIVED ids, pairwise, EXACTLY DNA_ENV_HASH_LEN bytes. A duplicate
 *      -> ERR_DUP with *fail_index_out set to the SECOND member of the
 *      pair (the first is the one that was already legitimately there).
 *   7. NODUS_V2_ENV_OK.
 *
 * ON ANY REJECTION past the out/n_envs gates the ENTIRE out array is
 * zeroed — including entries that had already succeeded. A failed batch
 * publishes NOTHING: partial results are how a rejected block leaks a
 * usable identity. (The two gate rejects in step 1 are the deliberate
 * exception: they return before any write, so a caller buffer keeps
 * whatever it held — never treat an ERR_ARG'd buffer as cleared.)
 *
 * No table is written, no runtime is invoked, no state is mutated. The
 * only SQL executed is the read-only genesis lookup inside
 * nodus_witness_v2_chain_id.
 *
 * @param w                     witness handle; w->db must be open.
 * @param proposed_global_height the CANDIDATE block's height, passed
 *                              through to the expiry gate unchanged.
 * @param rulesets              engine-owned IMMUTABLE per-domain context
 *                              table, STRICTLY ascending by domain_id.
 * @param n_rulesets            >= 1.
 * @param envs                  n_envs candidate envelopes.
 * @param n_envs                1 .. NODUS_V2_ENV_BATCH_MAX.
 * @param out                   caller array of n_envs entries. Each is
 *                              multi-KB (see env_preflight.h's size
 *                              audit) — callers and tests HEAP-allocate.
 * @param fail_index_out        OPTIONAL. MEANINGFUL ONLY for per-envelope
 *                              failures (a NULL env_bytes ERR_ARG,
 *                              ERR_CTX_MISSING, ERR_PREFLIGHT, and the
 *                              SECOND member of an ERR_DUP pair); for
 *                              batch-level rejects (other ERR_ARG causes,
 *                              ERR_CHAIN, ERR_RULESETS) it reads 0 —
 *                              which is NOT an accusation of envelope 0.
 *                              Written only after the out/n_envs gates;
 *                              untouched on those two earliest rejects.
 * @param pf_status_out         OPTIONAL. MEANINGFUL ONLY when the return
 *                              is ERR_PREFLIGHT; on every other outcome
 *                              it reads DNA_ENV_PF_OK and must not be
 *                              consulted — route on the RETURN status
 *                              first, always. Written only after the
 *                              out/n_envs gates.
 * @return a nodus_v2_env_status_t.
 */
nodus_v2_env_status_t nodus_witness_v2_env_preflight_batch(
    nodus_witness_t *w,
    uint64_t proposed_global_height,
    const dna_env_leg_ctx_t *rulesets, size_t n_rulesets,
    const nodus_v2_envelope_t *envs, size_t n_envs,
    dna_env_preflight_t *out,
    size_t *fail_index_out,
    dna_env_preflight_status_t *pf_status_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_ENV_H */
