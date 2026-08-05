/**
 * @file nodus_witness_v2_claims.h
 * @brief Ledger V2 Season 6 — witness-side generic manifest persistence,
 *        real manifest_root / claims_root legs, distribution accounting
 *        and the generic claim verify/apply pipeline (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. Tests (and later the
 * Ledger V2 devnet reset) drive it. Transaction types 12-14 remain
 * UNASSIGNED and inert: a claim is NOT a live wire transaction — the
 * codec/verify/apply entrypoints live entirely behind the inactive V2
 * boundary and the existing live wire-v2 behavior is unchanged.
 * ════════════════════════════════════════════════════════════════════════
 *
 * GENERICITY (locked): everything here is consumer-neutral. The manifest
 * is validated through one generic versioned path; source-network
 * metadata is opaque committed data (no source-chain cryptography is
 * imported or verified); authorization / fee / post-deadline behavior
 * are versioned manifest parameters and unknown modes fail closed.
 *
 * ── Root ownership ────────────────────────────────────────────────────
 *   manifest_root                → SYSTEM  (system_state_root leg)
 *   claims_root + claim outputs → DNA_CORE (core_state_root leg /
 *                                  transparent UTXOs, domain_id = 1)
 * Both loaders are fail-closed (v0.18.19 rule) and reproduce the frozen
 * S2 tagged-empty roots byte-identically when their table is absent
 * (pre-S6 database) or empty — every pre-S6 chain's system/core root is
 * byte-unchanged.
 *
 * ── Claim pipeline (called INSIDE the S5 apply transaction) ───────────
 * ADMIT (read-only, all fail-closed):
 *   1. structural claim validation (codec rule set);
 *   2. chain binding: claim.chain_id == the chain's derived chain_id
 *      (genesis v2_blocks row → dna_bh2_derive_chain_id) — cross-chain
 *      replay rejects;
 *   3. committed manifest lookup by manifest_seq (stored-hash verified
 *      on load); distribution section must be present; the claim's
 *      auth_mode must equal the manifest's committed mode;
 *   4. height window: claim_start_height <= h <= claim_end_height
 *      (early and late claims reject; post-deadline v1 policy RETAIN =
 *      reject + retain state, nothing else);
 *   5. leaf_index < leaf_count; the leaf reconstructed from the claim's
 *      committed fields must verify against the manifest's
 *      snapshot_root (Merkle inclusion, shape-derived proof);
 *   6. converted amount recomputed from the COMMITTED conversion
 *      parameters with checked arithmetic (a claim carries no amount
 *      of its own — substitution is structurally impossible);
 *   7. DNA-native authorization: ML-DSA-87 signature over the tagged
 *      preimage AND SHA3-512(pubkey) == the leaf's dest_binding
 *      (destination substitution rejects);
 *   8. nullifier derived from the committed leaf context; an
 *      already-spent nullifier rejects;
 *   9. remaining distribution value must cover the converted amount
 *      (a claim can NEVER mint).
 * EXECUTE (three write stages, each a separate call so the apply engine
 * can fault-inject between them; ALL inside the ONE S5 transaction):
 *   a. spent-claim insert (v2_claims_spent);
 *   b. transparent DNA_CORE output (utxo_set; deterministic UTXO id
 *      "DNA.CLUTXO.v1", owner = the 128-hex dest_binding fingerprint,
 *      domain_id = DNA_CORE via the S5 column default);
 *   c. distribution-state decrement (v2_dist_state.remaining), checked.
 * Value MOVES from unclaimed_distribution to transparent UTXO — the S6
 * supply equation term; supply_tracking is untouched (no mint, no burn).
 *
 * @file nodus_witness_v2_claims.h
 */

#ifndef NODUS_WITNESS_V2_CLAIMS_H
#define NODUS_WITNESS_V2_CLAIMS_H

#include "witness/nodus_witness.h"
#include "dnac/manifest_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** manifest_root over v2_manifests (ORDER BY manifest_seq ASC). Absent
 *  table (pre-S6 DB) or empty table → the frozen tagged-empty root
 *  (byte-identical to the S2/S5 placeholder). Fail-closed scan. */
int nodus_witness_manifest_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** claims_root over v2_claims_spent (ORDER BY nullifier ASC). Absent
 *  table or empty table → the frozen tagged-empty root. Fail-closed. */
int nodus_witness_claims_root_v2(nodus_witness_t *w, uint8_t out[64]);

/** The chain's derived 32-byte chain_id: the committed genesis
 *  v2_blocks row's block_id → dna_bh2_derive_chain_id.
 *  @return 0 / -1 (no genesis row is a fault, not a value). */
int nodus_witness_v2_chain_id(nodus_witness_t *w,
                              uint8_t out[DNA_CHAIN_ID_LEN]);

/**
 * Commit one canonical GenesisManifest v1 (runs INSIDE the caller's
 * transaction — never commits on its own). Fail-closed checks:
 *   - strict decode + full validation of `bytes`;
 *   - the committed domain set must EXACTLY match the domain registry:
 *     same count, and every (domain_id, DomainManifest hash) pair must
 *     equal the registry's stored manifest hash;
 *   - manifest.genesis_supply_raw must equal supply_tracking's
 *     genesis_supply (absent row = honest zero);
 *   - manifest_seq must not exist yet (duplicate rejects).
 * When a distribution section is present, seeds v2_dist_state with
 * remaining = total_claimable (the ONE unclaimed-distribution owner).
 * @return 0 / -1.
 */
int nodus_witness_v2_manifest_commit(nodus_witness_t *w,
                                     const uint8_t *bytes, size_t len,
                                     uint32_t manifest_seq,
                                     uint64_t committed_height);

/** Load + strict-decode a committed manifest; the stored bytes must
 *  re-hash to the stored manifest_hash (corruption fails closed).
 *  @return 0 found, 1 absent, -1 fault. */
int nodus_witness_v2_manifest_load(nodus_witness_t *w,
                                   uint32_t manifest_seq,
                                   dna_gman_t *out);

/** Σ v2_dist_state.remaining — the generic unclaimed-distribution
 *  supply owner. Absent table (pre-S6) = honest 0; checked add;
 *  DB fault = -1 (never a value). */
int nodus_witness_v2_unclaimed_total(nodus_witness_t *w, uint64_t *out);

/**
 * ADMIT one claim (read-only; pipeline steps 1-9 above).
 * @param global_height the height the claim would commit at.
 * @param out_converted the recomputed converted amount.
 * @param out_nullifier the derived spent-claim key.
 * @return 0 admissible / -1 (every failure fail-closed).
 */
int nodus_witness_v2_claim_admit(nodus_witness_t *w,
                                 const dna_claim_t *c,
                                 uint64_t global_height,
                                 uint64_t *out_converted,
                                 uint8_t out_nullifier[64]);

/** EXECUTE stage a: spent-claim insert. INSIDE the caller's txn. */
int nodus_witness_v2_claim_spend_insert(nodus_witness_t *w,
                                        const dna_claim_t *c,
                                        const uint8_t nullifier[64],
                                        uint64_t converted,
                                        uint64_t global_height);

/** EXECUTE stage b: the transparent DNA_CORE claim output. */
int nodus_witness_v2_claim_utxo_create(nodus_witness_t *w,
                                       const dna_claim_t *c,
                                       const uint8_t nullifier[64],
                                       uint64_t converted,
                                       uint64_t global_height);

/** EXECUTE stage c: checked v2_dist_state.remaining decrement. */
int nodus_witness_v2_claim_state_update(nodus_witness_t *w,
                                        uint32_t manifest_seq,
                                        uint64_t converted);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_CLAIMS_H */
