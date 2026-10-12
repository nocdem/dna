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
 * The stored snapshots enter the chain's state root through
 * validator_set_root, a leg of nodus_witness_system_root_v2 ("NDS.SYS.v4",
 * shared/dnac/ledger_roots_v2.h) — the SYSTEM domain root under the
 * global root the block app_hash commits. (This comment used to say the
 * snapshots did NOT enter the live state_root because that was the
 * legacy five-input formula; that formula is DELETED by the root-layout
 * round, K3.) The status byte the boundary flips write reaches the root
 * through the validator subtree as well.
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
#include "witness/nodus_witness_committee.h" /* nodus_committee_member_t */
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
 * HF-6 slice 5c: BOTH rulesets are stored (design rev 6 §6.5 — every
 * reader accepts both versions for the chain's life). The hash is
 * re-derived with dna_vset_hash_bytes_ex(…, DNA_VSET_RULESET_TOPN_V2, …):
 * the blob's own header picks the tag ("NDS.VSET.v1" / "NDS.VSET.v2") and
 * that ruleset's length ceiling, so a ruleset-1 blob hashes exactly as
 * before 5c.
 *
 * @param blob      canonical snapshot bytes (shared/dnac/vset_wire.h).
 * @param blob_len  1..DNA_VSET_MAX_ENC_LEN_V2 (and within its own
 *                  ruleset's ceiling — DNA_VSET_MAX_ENC_LEN for v1).
 * @param hash64    the snapshot hash of `blob` under the tag its header
 *                  names; re-derived and checked here.
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
 * the stored blob is re-hashed (dna_vset_hash_bytes_ex, max ruleset 2 —
 * HF-6 5c: a stored ruleset-1 row re-derives its stored v1-tag hash
 * byte for byte) and must equal the stored hash; the decode
 * (dna_vset_decode_ex, max ruleset 2 — either layout) must succeed; the
 * decoded epoch must equal
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
 * The produced snapshot carries selection_ruleset =
 * DNA_VSET_RULESET_TOPN_V2 when `key_gen >= NODUS_RT_GEN_STORAGE`, else
 * DNA_VSET_RULESET_TOPN_V1 (HF-6 slice 5d, plan tasks/hf6-slice5-plan.md
 * §1 "Rule"), an all-zero sortition_seed, epoch = epoch_start, and
 * active_count = the committee size actually returned. `key_gen` is the
 * caller's resolved key generation and is handed to
 * nodus_committee_compute_for_epoch unchanged, so the candidates, the
 * tiebreak, the entries' ids and the ruleset come from ONE value
 * (ORCHESTRATOR decision D4 (i)).
 *
 * HF-6 slice 6d (design 2026-10-03-hf5-validator-owner-stake rev 6 §3,
 * khan A1/A3): at `key_gen >= NODUS_RT_GEN_STORAGE` the builder runs the
 * ROTATION PASS of the freeze — every v2_validator_roles row with a
 * pending key and consensus_key_effective_epoch <= epoch_start − E, in
 * validator_id ASC, is accepted iff the accumulated party keeps
 * P − R > floor(2P/3) in BOTH the snapshot being built (S(U)) and the
 * stored S(epoch_start − E) (S(F)), each with its counted powers
 * (nodus_witness_vset_powers); an accepted member's entry carries its
 * pending key (voter_id re-derived), a refused one is skipped and the walk
 * continues, a member absent from S(F) adds 0 there. With no such row the
 * pass reads nothing else and the bytes are the pre-6d bytes; with one,
 * an absent / unreadable S(F) or a power that cannot be computed (or sums
 * to 0) is a FAULT (-1). Nothing is written. Contract and argument:
 * vset_rotation_pass in nodus_witness_vset.c.
 *
 * A chain with no eligible validators has NO snapshot: count == 0 returns
 * -1 rather than an empty set. (The selection itself is a static core
 * shared with nodus_witness_vset_preview_next below, which reports that
 * same empty case as a verdict, rc 1, instead.)
 *
 * @param max_active   target set size, must be in [1, DNA_MAX_ACTIVE_VALIDATORS].
 * @param snapshot_out [out] optional; heap snapshot (dna_vset_free).
 * @param blob_out     [out] optional; heap canonical bytes (free()).
 * @param blob_len_out [out] required iff blob_out is non-NULL.
 * HF-6 slice 5c: encoded and hashed through the `_ex` family at max
 * ruleset 2 (the layout and tag follow the snapshot's own ruleset);
 * each entry is filled by nodus_witness_vset_entry_from_member below.
 *
 * @param key_gen      the key generation (NODUS_RT_GEN_*) — see above.
 * @param hash_out64   [out] optional; the snapshot hash (dna_vset_hash_ex).
 * @return 0 / -1. On failure NO output parameter is written.
 */
int nodus_witness_vset_build_for_epoch(nodus_witness_t *w,
                                       uint64_t epoch_start,
                                       int max_active,
                                       uint32_t key_gen,
                                       dna_vset_snapshot_t **snapshot_out,
                                       uint8_t **blob_out,
                                       size_t *blob_len_out,
                                       uint8_t hash_out64[DNA_VSET_HASH_LEN]);

/**
 * HF-6 slice 5c — fill ONE snapshot entry from ONE committee member, in
 * the layout of `ruleset`. The builder's own fill (vset_build_snapshot
 * calls it for every member, in the ruleset its key generation selects —
 * HF-6 5d), public so a test can fill an entry from a real member.
 *
 *   voter_id       = SHA3-512(pubkey)[0..31] (nodus_chain_config_derive_
 *                    witness_id — the shipped derivation);
 *   pubkey, total_stake, self_bond (= member self_stake), commission_bps;
 *   TOPN_V2: validator_id / owner_fp copied from the member (emit_member
 *            sets them at key generation >= NODUS_RT_GEN_STORAGE; a zero
 *            id is not repaired — the v2 encoder refuses it);
 *   TOPN_V1: validator_id / owner_fp written all zero, whatever the
 *            member carries (the v1 encoder refuses a nonzero byte).
 *
 * @return 0; -1 on a NULL argument, a ruleset other than 1 / 2, or a
 *         voter_id derivation failure (`e` may be partly written).
 */
int nodus_witness_vset_entry_from_member(const nodus_committee_member_t *m,
                                         uint32_t ruleset,
                                         dna_vset_entry_t *e);

/* ════════════════════════════════════════════════════════════════════
 * S3 epoch lifecycle — ACTIVE. Called from finalize_block.
 *
 * These three are the only functions in this file through which
 * consensus WRITES state. Consensus also calls one READ-ONLY function
 * declared among them, nodus_witness_vset_preview_next (Rule N's weight
 * floor — v2ep_rule_n, nodus_witness_v2_epoch.c), which runs BEFORE
 * commit_next in the same boundary (Rule N is step 3, commit_next step 5).
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
 * HF-6 slice 5d: `key_gen` is the boundary's ONE read of the key
 * generation (nodus_witness_v2_epoch_boundary_apply), passed through
 * nodus_witness_vset_build_for_epoch — at `key_gen >=
 * NODUS_RT_GEN_STORAGE` the stored blob is ruleset 2. On a chain that
 * passes the generation-4 edge in block H − 1 the first boundary reading
 * generation 4 is B₀ = the first multiple of DNAC_EPOCH_LENGTH above H,
 * so snapshot(B₀ + E) is the first ruleset-2 row and every row <= B₀
 * stays ruleset 1 byte for byte (plan §1 "Which boundary writes the
 * first v2 snapshot") — a consequence of this rule, not a special case.
 *
 * @return 0 stored/idempotent, -1 error (block MUST fail).
 */
int nodus_witness_vset_commit_next(nodus_witness_t *w,
                                   uint64_t boundary_height,
                                   uint32_t key_gen);

/**
 * Build — WITHOUT encoding, hashing or storing — the snapshot that
 * nodus_witness_vset_commit_next(w, boundary_height) would build for the
 * epoch starting at boundary_height + DNAC_EPOCH_LENGTH if it ran over
 * the SAME committed state.
 *
 * tokenomics-v3 P1 round 6 (decision file §3 2026-09-23, "Rule N TABANI
 * WEIGHT ÜZERİNDEN"): Rule N's floor judges the voting power of the NEXT
 * epoch's seatable members, i.e. of this very snapshot. Same key
 * (boundary_height + DNAC_EPOCH_LENGTH), same target lookup
 * (vset_target_for_epoch, keyed on that height) and the same static
 * selection core that nodus_witness_vset_build_for_epoch wraps — so there
 * is exactly one piece of selection logic, not a copy.
 *
 * Pure read: runs inside the caller's transaction, writes nothing.
 *
 * Unlike nodus_witness_vset_build_for_epoch (and therefore commit_next
 * and commit_genesis, which keep "empty = fault"), this function tells a
 * VERDICT from a FAULT:
 *
 * HF-6 slice 5d: `key_gen` must be the value the same boundary passes to
 * commit_next (Rule N passes the boundary's one read) — the preview's
 * ruleset, candidates and tiebreak follow it exactly as the stored
 * snapshot's do. HF-6 slice 6d: the rotation pass of the freeze runs here
 * too (the same core), so a pending rotation the stored snapshot accepts
 * is accepted in the preview, with the same key.
 *
 * @param snapshot_out [out] heap snapshot on rc 0 (dna_vset_free);
 *        untouched otherwise.
 * @return 0 built;
 *         1 the committee is EMPTY (no bonded, tenured validator would
 *           be seated) — a well-formed answer, not an error;
 *        -1 fault (bad args, height overflow, TARGET_ACTIVE_COUNT
 *           unreadable, committee compute failed, allocation, witness_id
 *           derivation, the 6d rotation pass faulted). A DB failure is
 *           never a value.
 */
int nodus_witness_vset_preview_next(nodus_witness_t *w,
                                    uint64_t boundary_height,
                                    uint32_t key_gen,
                                    dna_vset_snapshot_t **snapshot_out);

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
 * HF-6 slice 5d: builds both at key generation NODUS_RT_GEN_1 (a chain
 * born on this binary starts at generation 1 — design rev 6 §8), so
 * snapshot(0) and snapshot(E) are always ruleset 1.
 *
 * @return 0 seeded or no-op, -1 error (block MUST fail).
 */
int nodus_witness_vset_commit_genesis(nodus_witness_t *w,
                                      uint64_t block_height);

/* ════════════════════════════════════════════════════════════════════
 * HF-6 slice 5b — THE ONE voting-power derivation of a snapshot.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §5 ("Güç tavanı — tek fonksiyon"; "Tüketiciler (hepsi bu fonksiyonu
 * çağırır)"), decision docs/plans/decisions/2026-10-08-kurultay-14-hf6-
 * summary.md K1 / K2 / K5, plan tasks/hf6-slice5-plan.md §2 "5b". Every
 * consumer of a snapshot's voting power — InitChain, the Comet boundary
 * diff (both sides), Rule N's weight floor, the reward distribution, the
 * storage report weight, the committee cache (and through it HF-2
 * governance and the CLI approval selection) — calls
 * nodus_witness_vset_powers and nothing else.
 * ════════════════════════════════════════════════════════════════════ */

/**
 * POWER_CAP_BPS in force for the snapshot whose EPOCH START is
 * `epoch_start` — the key the committee target is read at
 * (nodus_witness_committee.c committee_target_for_epoch), never the
 * queried height, so every consumer of one snapshot reads one ratio
 * (plan §1 (iii)).
 *
 * Today: the compiled DNAC_HF6_POWER_CAP_BPS_DEFAULT (param 20 does not
 * exist yet). Slice 8 replaces the body — and nothing else — with the
 * fail-closed chain-config read of param 20 at `epoch_start`
 * (nodus_chain_config_get_u64 with the default as the no-row answer; a
 * read fault is -1, never the default — the committee_target_for_epoch
 * pattern).
 *
 * @param ratio_out required; written only on 0.
 * @return 0 / -1 (bad args; from slice 8 also an unreadable param).
 */
int nodus_witness_power_cap_bps_for_epoch(nodus_witness_t *w,
                                          uint64_t epoch_start,
                                          uint32_t *ratio_out);

/**
 * The voting power of every entry of `snap`, in the snapshot's own entry
 * order, by the snapshot's OWN ruleset (design §5: "v1 snapshot →
 * tavansız; v2 → tavanlı"):
 *
 *   DNA_VSET_RULESET_TOPN_V1 → out[i] = total_stake_i / DNAC_DECIMAL_UNIT
 *     — the derivation every consumer used before slice 5, byte for byte:
 *     a zero power is allowed and returned exactly as before (each caller
 *     keeps its own zero rule, e.g. the Comet diff's power-0 fault).
 *   DNA_VSET_RULESET_TOPN_V2 → p_i = total_stake_i / DNAC_DECIMAL_UNIT;
 *     any p_i == 0 is -1 (a v2 entry below one whole coin is a broken
 *     invariant — every bond is >= STAKE_MIN); the ratio is
 *     nodus_witness_power_cap_bps_for_epoch(w, snap->epoch); out =
 *     dna_power_cap_counted(p, validator_id, n, ratio) (shared/dnac/
 *     power_cap.h — integer only, total walk order p DESC / validator_id
 *     ASC, out in the caller's order); its -1 is -1.
 *   any other ruleset → -1.
 *
 * The snapshot itself is never modified; `entry.total_stake` stays the
 * uncapped amount (design §5 "Ödül": the inner split reads it raw).
 *
 * EVERY CALLER TREATS -1 AS A NODE FAULT (the block / boundary / lookup
 * fails closed): a power that cannot be computed is never a value, and
 * substituting the raw power for a capped one would make this node vote,
 * pay and weigh on a different set than its peers.
 *
 * @param out  receives snap->active_count values (written only on 0;
 *             a caller may size it DNA_MAX_ACTIVE_VALIDATORS — larger
 *             snapshots are refused).
 * @return 0 / -1 (NULL argument, active_count > DNA_MAX_ACTIVE_VALIDATORS,
 *         unknown ruleset, a ruleset-2 zero power, the ratio unreadable,
 *         the cap refusing its input, allocation).
 */
int nodus_witness_vset_powers(nodus_witness_t *w,
                              const dna_vset_snapshot_t *snap,
                              uint64_t out[]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VSET_H */
