/**
 * @file nodus_witness_vset.h
 * @brief Ledger V2 Season 3 — witness-side validator-set snapshot
 *        persistence + builder (INACTIVE).
 *
 * Persists the per-epoch validator-set snapshot defined by
 * shared/dnac/vset_wire.h into the `validator_set_snapshots` table
 * (schema: nodus/src/witness/nodus_witness.c WITNESS_DB_SCHEMA), and
 * exposes the Merkle root over those snapshots as the S3
 * validator_set_root leg of the V2 hierarchy.
 *
 * ACTIVATION (S3 wave 2): the epoch lifecycle at the bottom of this
 * header IS now called by consensus, from finalize_block:
 *   - nodus_witness_vset_commit_genesis at the genesis block,
 *   - nodus_witness_vset_apply_boundary_flips then
 *     nodus_witness_vset_commit_next as the FINAL steps of
 *     apply_epoch_boundary_transitions.
 *
 * The stored snapshots do NOT enter the live state_root: that is the v3
 * five-input formula (utxo || validator || delegation || epoch_state ||
 * chain_config — nodus_witness_merkle.c
 * nodus_witness_merkle_compute_state_root), and validator_set_root is a
 * leg of nodus_witness_system_root_v2, which no live consumer calls. What
 * DOES reach state_root is the status byte the boundary flips write, via
 * the validator subtree — and on a 7-bonded / target-7 chain every flip
 * is ACTIVE→ACTIVE, so the committed bytes are unchanged.
 *
 * Fail-closed discipline (v0.18.19 rule, nodus/CLAUDE.md): any DB
 * prepare/step error, wrong-width blob, hash mismatch or decode failure
 * fails the WHOLE call. No sentinel, no fallback, no partial result. A DB
 * failure is never a value.
 *
 * TRANSACTIONS: none of these functions issue BEGIN/COMMIT. They run
 * inside whatever transaction the caller already holds, matching the rest
 * of the witness DB layer.
 */

#ifndef NODUS_WITNESS_VSET_H
#define NODUS_WITNESS_VSET_H

#include "witness/nodus_witness.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_roots_v2.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Store the snapshot for `epoch_start`.
 *
 * Idempotent-or-fatal, never silently divergent:
 *   - no row for epoch_start          → INSERT, return 0;
 *   - row exists, SAME hash AND byte-identical blob → return 0 (idempotent
 *     re-apply, e.g. a replayed block);
 *   - row exists and ANY of hash / blob length / blob bytes differs
 *     → return -2 and log. This is a CONFLICT: two different validator
 *       sets claim the same epoch, which on a live chain means the local
 *       node and its peers would compute different validator_set_roots.
 *       The caller MUST treat -2 as fatal — it is the cross-node identity
 *       check that carries the snapshot's rank-order canonicality (see the
 *       HONEST LABEL in shared/dnac/vset_wire.h).
 *   - anything else (bad args, DB error) → -1.
 *
 * @param blob      canonical snapshot bytes (shared/dnac/vset_wire.h).
 * @param blob_len  1..DNA_VSET_MAX_ENC_LEN.
 * @param hash64    dna_vset_hash of `blob`; re-derived and checked here.
 * @return 0 stored/idempotent, -2 conflict, -1 error.
 */
int nodus_witness_vset_insert(nodus_witness_t *w,
                              uint64_t epoch_start,
                              const uint8_t *blob, size_t blob_len,
                              const uint8_t hash64[DNA_VSET_HASH_LEN],
                              uint64_t created_at_height);

/**
 * Load and DECODE the snapshot for `epoch_start`.
 *
 * Integrity is re-checked on every read before the bytes are trusted:
 * the stored blob is re-hashed (dna_vset_hash_bytes) and must equal the
 * stored hash; the decode must succeed; the decoded epoch must equal
 * `epoch_start` and the decoded active_count must equal the stored
 * active_count column. Any mismatch is corruption and returns -1.
 *
 * @param snapshot_out [out] heap snapshot on success (release with
 *        dna_vset_free); untouched otherwise.
 * @param hash_out64   [out] optional; receives the stored hash on success.
 * @return 0 found, 1 no such epoch, -1 error/corruption.
 */
int nodus_witness_vset_get(nodus_witness_t *w,
                           uint64_t epoch_start,
                           dna_vset_snapshot_t **snapshot_out,
                           uint8_t hash_out64[DNA_VSET_HASH_LEN]);

/**
 * validator_set_root over every stored snapshot, ORDER BY epoch_start ASC,
 * via dna_v2_vset_root. Each row's snapshot_hash must be exactly 64 bytes;
 * a malformed row fails the root rather than being skipped, and the scan's
 * final rc is checked against SQLITE_DONE so a mid-scan I/O error cannot
 * truncate the tree into a "valid" root.
 *
 * This function reads the stored HASHES only — it never decodes a blob, so
 * it is unaffected by whether a stored blob is a decodable snapshot.
 *
 * An empty table yields the tagged empty root (dna_v2_empty_root of
 * DNA_V2_EMPTY_VSET), identical to the S2 placeholder leg.
 *
 * @return 0 / -1.
 */
int nodus_witness_vset_root(nodus_witness_t *w,
                            uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * Build (but do NOT store) the snapshot for `epoch_start`.
 *
 * Sources the members from nodus_committee_compute_for_epoch DIRECTLY,
 * NOT from the cached nodus_committee_get_for_block. The reason is no
 * longer the cache's missing self_stake — S3 gave the cache a
 * cached_committee_self_stakes parallel array, so a hit and a miss now
 * agree. The reason is that computing directly AVOIDS CACHE-WARM
 * ORDERING DEPENDENCE: get_for_block would populate (or serve) the
 * per-witness cache keyed on the epoch containing the queried height,
 * so the snapshot's content would depend on whether some earlier
 * consumer had already warmed that slot on this node. Building from the
 * committed DB every time makes the snapshot a pure function of chain
 * state, which is what a cross-node byte-identity check requires.
 *
 * Each entry's voter_id is derived with nodus_chain_config_derive_witness_id
 * — the shipped SHA3-512(pubkey)[0..31] derivation
 * (nodus/src/witness/nodus_witness_chain_config.c:498), reused rather than
 * re-implemented so the snapshot's voter_id is the same identifier the
 * chain-config vote path already uses.
 *
 * The produced snapshot always carries selection_ruleset =
 * DNA_VSET_RULESET_TOPN_V1, an all-zero sortition_seed, epoch =
 * epoch_start, and active_count = the committee size actually returned.
 *
 * A chain with no eligible validators has NO snapshot: count == 0 returns
 * -1 rather than an empty set.
 *
 * @param max_active   target set size, must be in [1, DNA_MAX_ACTIVE_VALIDATORS].
 * @param snapshot_out [out] optional; heap snapshot (dna_vset_free).
 * @param blob_out     [out] optional; heap canonical bytes (free()).
 * @param blob_len_out [out] required iff blob_out is non-NULL.
 * @param hash_out64   [out] optional; dna_vset_hash of the snapshot.
 * @return 0 / -1. On failure NO output parameter is written.
 */
int nodus_witness_vset_build_for_epoch(nodus_witness_t *w,
                                       uint64_t epoch_start,
                                       int max_active,
                                       dna_vset_snapshot_t **snapshot_out,
                                       uint8_t **blob_out,
                                       size_t *blob_len_out,
                                       uint8_t hash_out64[DNA_VSET_HASH_LEN]);

/* ════════════════════════════════════════════════════════════════════
 * S3 epoch lifecycle — ACTIVE. Called from finalize_block.
 *
 * These three are the only functions in this file that consensus runs.
 * All of them execute INSIDE the caller's block DB transaction, in
 * finalize_block's deterministic order, so BFT-original commit, genesis
 * commit and sync replay all reach them identically (every path funnels
 * through finalize_block — nodus_witness_bft.c commit_genesis /
 * commit_batch, and replay_block which delegates to commit_batch).
 *
 * Every one of them FAILS THE BLOCK on error: a -1 propagates up through
 * apply_epoch_boundary_transitions → finalize_block → the caller's
 * rollback, so no partial membership change can ever be committed and a
 * node that cannot agree simply does not vote.
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Apply the epoch's membership flips from the snapshot committed one
 * epoch earlier.
 *
 * `boundary_height` is the epoch START height of the epoch that is
 * BEGINNING (block_height at an epoch boundary), i.e. the snapshot key.
 *
 * Steps, in this order:
 *   1. Load snapshot(boundary_height). ABSENT (rc 1) → NO-OP, return 0.
 *      That is the legacy / first-post-upgrade case: a chain whose
 *      previous boundary ran software with no commit_next has no row to
 *      apply, and inventing one would rewrite membership from the
 *      CURRENT ranking instead of the frozen one.
 *   2. FLIPS: every validator whose stored status is ACTIVE or ELIGIBLE
 *      becomes ACTIVE if its derived witness_id is in the snapshot, and
 *      ELIGIBLE otherwise. Two deterministic UPDATE statements, no
 *      row-by-row iteration order to depend on. Bond fields, delegation
 *      totals, tenure and counters are untouched — this moves ONLY the
 *      status byte.
 *
 * Idempotent: re-running on the same boundary with the same state is a
 * no-op, because the flips are absolute assignments, not toggles.
 *
 * @return 0 applied or no-op, -1 error (block MUST fail).
 */
int nodus_witness_vset_apply_boundary_flips(nodus_witness_t *w,
                                            uint64_t boundary_height);

/**
 * Build and store the snapshot for the NEXT epoch.
 *
 * Ranks over the POST-FLIP state (the caller runs the flips first), and
 * keys the target-size lookup on the NEXT epoch's start height —
 * boundary_height + DNAC_EPOCH_LENGTH — because a chain_config row whose
 * effective_block is <= that height is already committed state at this
 * point and is therefore the same on every node.
 *
 * Persisted through nodus_witness_vset_insert, so a byte-identical
 * re-apply (replay of the same block) returns 0 and a DIFFERENT snapshot
 * for the same epoch returns -2 → -1 here → the block fails. An empty
 * committee is a fault on a real chain, not an empty set: build returns
 * -1 and so does this.
 *
 * @return 0 stored/idempotent, -1 error (block MUST fail).
 */
int nodus_witness_vset_commit_next(nodus_witness_t *w,
                                   uint64_t boundary_height);

/**
 * Seed the genesis snapshots.
 *
 * Called from finalize_block, gated on the genesis condition, AFTER
 * genesis validator seeding and inside the same DB transaction. Persists
 * snapshots for BOTH e_start 0 (the epoch genesis itself lives in) and
 * e_start DNAC_EPOCH_LENGTH (the first boundary's snapshot, so the first
 * nodus_witness_vset_apply_boundary_flips has a row to apply).
 *
 * No-op returning 0 when `block_height` is not the genesis height, so
 * the caller can call it unconditionally.
 *
 * @return 0 seeded or no-op, -1 error (block MUST fail).
 */
int nodus_witness_vset_commit_genesis(nodus_witness_t *w,
                                      uint64_t block_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VSET_H */
