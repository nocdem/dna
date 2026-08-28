/**
 * @file nodus_witness_v2_claims.h
 * @brief Ledger V2 Season 6 — witness-side generic manifest persistence,
 *        real manifest_root / per-domain claims_root legs, distribution
 *        accounting, generic runtime resolution and the generic claim
 *        verify/apply pipeline (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. Tests (and later the
 * Ledger V2 devnet reset) drive it. Transaction types 12-14 remain
 * UNASSIGNED and inert: a claim is NOT a live wire transaction — the
 * codec/verify/apply entrypoints live entirely behind the inactive V2
 * boundary and the existing live wire-v2 behavior is unchanged.
 * ════════════════════════════════════════════════════════════════════════
 *
 * GENERICITY (locked): everything here is consumer-neutral AND
 * domain-neutral. A distribution names its target domain and asset
 * EXPLICITLY in committed manifest data; the generic engine routes an
 * admitted claim to the REGISTERED target runtime through the generic
 * claim hook and never creates an output, picks a domain, or applies a
 * default itself. Unknown, inactive, unregistered or incompatible
 * targets fail closed at manifest commit AND at claim time.
 *
 * ── Root ownership ────────────────────────────────────────────────────
 *   manifest_root            → SYSTEM (the generic manifest registry is
 *                              protocol state — system_state_root leg)
 *   claims_root + outputs    → the TARGET runtime/domain: each runtime
 *                              commits the claims_root over the spent
 *                              claims targeting ITS domain and owns the
 *                              outputs it created. The global layer
 *                              consumes only DomainUpdates and opaque
 *                              domain state roots.
 * Both loaders are fail-closed (v0.18.19 rule) and reproduce the frozen
 * S2 tagged-empty roots byte-identically when their table is absent
 * (pre-S6 database) or empty.
 *
 * ── Claim pipeline (called INSIDE the S5 apply transaction) ───────────
 * ADMIT (read-only, all fail-closed):
 *   1. structural claim validation (codec rule set);
 *   2. chain binding: claim.chain_id == the chain's derived chain_id;
 *   3. committed manifest lookup BY MANIFEST HASH (stored bytes re-hash
 *      verified); distribution section present; auth_mode matches;
 *   4. height window (early and late reject; post-deadline v1 RETAIN);
 *   5. leaf_index < leaf_count; leaf reconstructs + Merkle-verifies
 *      against the committed snapshot_root;
 *   6. converted amount from COMMITTED parameters (checked arithmetic);
 *   7. ML-DSA-87 signature + SHA3-512(pubkey) == dest_binding;
 *   8. TARGET RUNTIME resolution: the manifest's target_domain_id must
 *      be registered AND ACTIVE, its exact runtime tuple locally
 *      compiled, claim hooks present, and asset_check must accept the
 *      committed target_asset_ref;
 *   9. nullifier from the committed context (chain ‖ manifest_hash ‖
 *      target domain ‖ target asset ‖ leaf hash); spent rejects;
 *  10. remaining distribution value covers the amount (never mints).
 * EXECUTE (three write stages inside the ONE S5 transaction):
 *   a. the TARGET runtime's claim_apply hook creates the domain-local
 *      output and returns its output identity;
 *   b. spent-claim insert (v2_claims_spent, committed-identity keys);
 *   c. checked v2_dist_state.remaining decrement (by manifest_hash).
 * Value MOVES from unclaimed distribution to a target-runtime output —
 * never minted, never burned; supply_tracking is untouched.
 *
 * @file nodus_witness_v2_claims.h
 */

#ifndef NODUS_WITNESS_V2_CLAIMS_H
#define NODUS_WITNESS_V2_CLAIMS_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "dnac/manifest_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** manifest_root over v2_manifests (ORDER BY manifest_hash ASC — the
 *  committed identity, never the local seq). Absent table (pre-S6 DB)
 *  or empty table → the frozen tagged-empty root. Fail-closed scan. */
int nodus_witness_manifest_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** claims_root over the v2_claims_spent rows whose target_domain_id ==
 *  `domain_id` (ORDER BY nullifier ASC). The claims commitment belongs
 *  to the TARGET runtime — each domain's root covers only its own
 *  claims. Absent table or no matching rows → the frozen tagged-empty
 *  root. Fail-closed. */
int nodus_witness_claims_root_v2(nodus_witness_t *w, uint32_t domain_id,
                                 uint8_t out[64]);

/** The chain's derived 32-byte chain_id: the committed genesis
 *  v2_blocks row's block_id → dna_bh2_derive_chain_id.
 *  @return 0 / -1 (no genesis row is a fault, not a value). */
int nodus_witness_v2_chain_id(nodus_witness_t *w,
                              uint8_t out[DNA_CHAIN_ID_LEN]);

/**
 * Resolve the REGISTERED runtime for `domain_id` through the generic
 * registry path: registry row (status ACTIVE when `require_active`) →
 * current DomainManifest tuple → exact-tuple lookup in the witness's
 * runtime table (w->v2_runtime_table override or the compiled builtin
 * table). Fail-closed: unknown domain, inactive status, or a tuple this
 * build does not carry all return nonzero.
 * @return 0 with *out set / -1.
 */
int nodus_witness_v2_runtime_for(nodus_witness_t *w, uint32_t domain_id,
                                 int require_active,
                                 const nodus_domain_runtime_t **out);

/**
 * Commit one canonical GenesisManifest v1 (runs INSIDE the caller's
 * transaction — never commits on its own). Fail-closed checks:
 *   - strict decode + full validation of `bytes`;
 *   - the committed domain set must EXACTLY match the domain registry;
 *   - manifest.genesis_supply_raw must equal supply_tracking's
 *     genesis_supply (absent row = honest zero);
 *   - a distribution section's target_domain_id must be one of the
 *     manifest's domains, registered + ACTIVE, with a locally compiled
 *     runtime whose asset_check ACCEPTS the committed target_asset_ref
 *     and whose claim_apply exists (a runtime that cannot apply claims
 *     cannot be a distribution target);
 *   - the manifest_hash must not exist yet (duplicate rejects);
 *     `manifest_seq` is stored as an INTERNAL LOCATOR only.
 * When a distribution section is present, seeds v2_dist_state keyed by
 * manifest_hash with the explicit target domain/asset and
 * remaining = total_claimable. @return 0 / -1.
 */
int nodus_witness_v2_manifest_commit(nodus_witness_t *w,
                                     const uint8_t *bytes, size_t len,
                                     uint32_t manifest_seq,
                                     uint64_t committed_height);

/** Load + strict-decode a committed manifest by its INTERNAL locator;
 *  the stored bytes must re-hash to the stored manifest_hash.
 *  @return 0 found, 1 absent, -1 fault. */
int nodus_witness_v2_manifest_load(nodus_witness_t *w,
                                   uint32_t manifest_seq,
                                   dna_gman_t *out);

/** Load + strict-decode a committed manifest by its COMMITTED identity
 *  (manifest_hash); stored bytes re-hash verified.
 *  @return 0 found, 1 absent, -1 fault. */
int nodus_witness_v2_manifest_load_by_hash(nodus_witness_t *w,
                                           const uint8_t hash[64],
                                           dna_gman_t *out);

/** Σ v2_dist_state.remaining over the rows whose (target_domain_id,
 *  target_asset_ref) match — the unclaimed value a SPECIFIC runtime
 *  owns for a SPECIFIC asset. Never a cross-domain sum. Absent table
 *  (pre-S6) = honest 0; checked add; DB fault = -1 (never a value). */
int nodus_witness_v2_unclaimed_total(nodus_witness_t *w,
                                     uint32_t target_domain_id,
                                     const uint8_t *target_asset_ref,
                                     uint16_t target_asset_len,
                                     uint64_t *out);

/** Everything ADMIT establishes that EXECUTE needs: the committed
 *  target context and the resolved runtime. */
typedef struct {
    uint64_t converted;                       /* recomputed amount       */
    uint8_t  nullifier[64];                   /* committed claim id      */
    uint8_t  manifest_hash[64];               /* committed manifest id   */
    uint32_t target_domain_id;                /* committed target        */
    uint16_t target_asset_len;
    uint8_t  target_asset_ref[DNA_GMAN_ASSETREF_MAX];
    const nodus_domain_runtime_t *rt;         /* resolved TARGET runtime */
} nodus_v2_claim_admit_t;

/**
 * ADMIT one claim (read-only; pipeline steps 1-10 above).
 * @param global_height the height the claim would commit at.
 * @return 0 admissible with *out filled / -1 (fail-closed).
 */
int nodus_witness_v2_claim_admit(nodus_witness_t *w,
                                 const dna_claim_t *c,
                                 uint64_t global_height,
                                 nodus_v2_claim_admit_t *out);

/** EXECUTE stage a: route the admitted claim through the resolved
 *  TARGET runtime's claim_apply hook — the runtime creates its
 *  domain-local output and returns its output identity. INSIDE the
 *  caller's txn. */
int nodus_witness_v2_claim_output_create(nodus_witness_t *w,
                                         const dna_claim_t *c,
                                         const nodus_v2_claim_admit_t *a,
                                         uint64_t global_height,
                                         uint8_t out_output_id[64]);

/** EXECUTE stage b: spent-claim insert keyed by committed identity. */
int nodus_witness_v2_claim_spend_insert(nodus_witness_t *w,
                                        const dna_claim_t *c,
                                        const nodus_v2_claim_admit_t *a,
                                        const uint8_t output_id[64],
                                        uint64_t global_height);

/** EXECUTE stage c: checked v2_dist_state.remaining decrement (keyed by
 *  manifest_hash). */
int nodus_witness_v2_claim_state_update(nodus_witness_t *w,
                                        const uint8_t manifest_hash[64],
                                        uint64_t converted);

/**
 * O15K V-3 — the ONE spent-claim lookup: does `nullifier` have a row in
 * v2_claims_spent (the table a CLAIM's commit writes, stage b above)?
 *
 * It exists because the answer has two consumers — ADMIT step 9, and the
 * mempool reaper that decides whether a pooled class-201 entry the chain
 * has already committed may be dropped (nodus_witness_mempool_evict_
 * committed). Before O15K the reaper asked the LEGACY `nullifiers` table
 * instead, which no successor commit ever writes, so a committed claim
 * was never reaped and read as live demand forever.
 *
 * ⚠ THE RETURN IS A TRI-STATE ON PURPOSE — a bool is FORBIDDEN here.
 * The two callers' safe answers on a fault point in OPPOSITE directions:
 *
 *   | caller                | question             | maps -1 to        |
 *   |-----------------------|----------------------|-------------------|
 *   | admission (ADMIT §9)  | "may I ADMIT this?"  | SPENT → reject    |
 *   | reaper (evict)        | "may I DELETE this?" | NOT SPENT → keep  |
 *
 * Never admit a possible double-spend; never delete a client's pending
 * work. A bool would give one of them the dangerous direction, so each
 * caller maps -1 itself, at its own call site.
 *
 * Deterministic and node-local: entry bytes plus this node's committed
 * state; no clock, no message, no iteration order.
 *
 * @return 1 spent / 0 not spent / -1 FAULT ("this node does not know" —
 *         an absent or unreadable v2_claims_spent is a fault, NEVER
 *         "not spent").
 */
int nodus_witness_v2_claim_nullifier_spent(nodus_witness_t *w,
                                           const uint8_t nullifier[64]);

#ifdef NODUS_V2_TEST_SUPPLY
/**
 * O15J — TEST-ONLY. Suspend the CORE conservation invariant so an
 * engine-level test can drive synthetic envelopes that create value from
 * nothing (effect-plumbing coverage, not economics).
 *
 * Declared AND defined only under NODUS_V2_TEST_SUPPLY, which is set for
 * exactly two test targets and nowhere else. libnodus is static and
 * the TU is compiled into those binaries, so no shipped artefact
 * contains this symbol — `test_v2_supply_linked` proves that with `nm`
 * instead of asserting it here. This replaces the pre-O15J escape (an
 * absent supply_tracking row silently SKIPPING the equation), which was
 * reachable in production and is now a hard refusal.
 */
void nodus_witness_v2_supply_test_bypass(int on);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_CLAIMS_H */
