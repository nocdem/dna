/**
 * @file nodus_witness_domreg.h
 * @brief Ledger V2 Season 4 — witness-side domain registry: persistence,
 *        staged activation scheduler, readiness accounting and the
 *        registry state-root (INACTIVE).
 *
 * The registry is SYSTEM-owned state. The initial registry contains
 * exactly SYSTEM (0) and DNA_CORE (1); a third native domain is one more
 * row + one more compiled runtime entry — no BlockHeader change, ever.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path (PREVOTE / COMMIT / finalize_block / admission)
 * calls anything in this file. Tests and the S4 harness drive it. The
 * registry activates only with the Ledger V2 devnet reset; live V1
 * state_root, block hashes and Type-11 rejection are byte-unchanged.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── Staged activation policy (LOCKED by the S4 season charter;
 *    E = DNAC_EPOCH_LENGTH, every epoch key is an EPOCH START HEIGHT) ──
 *
 *   Stage A  A proposal (dna_domprop_digest) exists; validators submit
 *            signed readiness for the EXACT ruleset tuple. Submission is
 *            epoch-fresh: a signal is accepted only when its signal_epoch
 *            equals the authoritative snapshot's epoch at submission time.
 *   Stage B  Governance may SCHEDULE only once readiness has reached
 *            quorum = dna_bft_quorum(N) over the authoritative snapshot.
 *            Scheduling at epoch start H_k pins:
 *              readiness_deadline_epoch     = H_k + 2E   (two-epoch deadline)
 *              scheduled_activation_epoch  >= H_k + 2E   (never earlier)
 *            Quorum readiness SCHEDULES; it never ACTIVATES.
 *   Stage C  At the ordinary snapshot build for the deadline epoch,
 *            still-unready validators are EXCLUDED from the candidate set
 *            (nodus_witness_domreg_exclusions_at + _filter_snapshot) —
 *            an ordinary S3 epoch transition, decided under the old rules.
 *            NON-SLASHING: nothing touches bonds, delegations or rewards
 *            accrued state; the validator merely stops being selected and
 *            re-enters through the ordinary process once ready. A removal
 *            that would push the set below the configured floor does NOT
 *            happen (fail-safe: old rules simply continue).
 *   Stage D  A set transition and a ruleset activation NEVER share an
 *            epoch boundary: the activation precheck requires the
 *            governing snapshot's membership to be IDENTICAL to the
 *            previous epoch's. If Stage C removed anyone at H_k+2E, an
 *            activation scheduled there postpones to H_k+3E by this rule —
 *            i.e. the new set always runs >= 1 complete epoch under the
 *            old rules before any activation.
 *   Stage E  At the activation boundary the precheck re-runs against the
 *            THEN-authoritative snapshot: EVERY member must hold a stored,
 *            verified readiness signal for the live proposal (quorum is
 *            NOT enough to activate), and Stage D's membership equality
 *            must hold. Any failure postpones by EXACTLY one epoch
 *            (scheduled_activation_epoch += E, postpone_count += 1) and
 *            repeats. Governance may cancel at any point before
 *            activation; cancellation deletes the proposal AND its
 *            readiness signals, so nothing about the old proposal is
 *            reusable. No node ever partially activates.
 *
 * ── Fail-closed discipline (v0.18.19 rule) ────────────────────────────
 * Any DB error, wrong-width blob, decode failure, hash mismatch or
 * validation failure fails the WHOLE call. No sentinel, no fallback, no
 * partial registry mutation: every multi-step transition either fully
 * applies or leaves the row byte-unchanged.
 *
 * TRANSACTIONS: none of these functions issue BEGIN/COMMIT — they run
 * inside whatever transaction the caller holds (vset/db-layer pattern).
 *
 * @file nodus_witness_domreg.h
 */

#ifndef NODUS_WITNESS_DOMREG_H
#define NODUS_WITNESS_DOMREG_H

#include "witness/nodus_witness.h"
#include "dnac/domain_wire.h"
#include "dnac/vset_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Read side ──────────────────────────────────────────────────────── */

/**
 * Load one domain's registry row, fully validated:
 * record decodes + passes dna_domreg_record_validate; the stored current
 * manifest decodes and its DOMMAN hash equals the record's
 * current_manifest_hash; a stored pending manifest is present IFF the
 * record says so and hash-matches likewise.
 *
 * @param rec_out   [out] required.
 * @param cur_out   [out] optional decoded current manifest.
 * @param pend_out  [out] optional decoded pending manifest (zeroed when
 *                  the record has none).
 * @return 0 found, 1 no such domain, -1 error/corruption.
 */
int nodus_witness_domreg_get(nodus_witness_t *w, uint32_t domain_id,
                             dna_domreg_record_t *rec_out,
                             dna_domain_manifest_t *cur_out,
                             dna_domain_manifest_t *pend_out);

/**
 * domain_registry_root over every row, ORDER BY domain_id ASC, via
 * dna_domreg_root over the DECODED + validated records. A malformed row
 * fails the root; the scan rc is checked against SQLITE_DONE. An empty
 * table yields the frozen S2 tagged empty root (DNA_V2_EMPTY_DOMREG) —
 * byte-identical to the pre-S4 placeholder leg. @return 0 / -1.
 */
int nodus_witness_domreg_root(nodus_witness_t *w, uint8_t out[64]);

/* ── Genesis / registration ─────────────────────────────────────────── */

/**
 * Seed the initial registry: exactly SYSTEM and DNA_CORE, status ACTIVE,
 * manifests derived from the compiled builtin runtime table (name, tuple
 * and type ownership from each entry's checked-in descriptor; fee
 * GLOBAL_BURN; quotas 0 = global-cap-bounded; upgrade authority
 * CHAIN_CONFIG; activation_epoch 0; readiness policy STAGED_V1;
 * genesis_state_root all-zero — DOCUMENTED S5 PLACEHOLDER: the real
 * initial domain state roots are defined by the S5 atomic-apply season and
 * validated at the V2 genesis event, never by this codec).
 *
 * Idempotent-or-fatal: existing byte-identical rows are a no-op; a
 * differing existing row is a conflict (-2). @return 0 / -2 / -1.
 */
int nodus_witness_domreg_init_genesis(nodus_witness_t *w);

/**
 * Register a NEW domain (status REGISTERED, no proposal). The manifest
 * must validate; its domain_id must not exist yet; its transaction-type
 * ownership must not intersect ANY existing domain's ownership
 * (duplicate active ownership is structurally rejected at registration —
 * one type, one owner). @return 0 / -1.
 */
int nodus_witness_domreg_op_register(nodus_witness_t *w,
                                     const dna_domain_manifest_t *m);

/* ── Proposal / readiness / scheduling ops (SYSTEM-path transitions) ── */

/**
 * Open (or replace) the proposal for `domain_id`.
 *
 * REGISTERED domain: `target` must be NULL — the initial-activation
 * proposal targets the CURRENT manifest.
 * ACTIVE domain: `target` is the NEW manifest (the pending upgrade);
 * its domain_id must equal `domain_id`, its manifest hash must differ
 * from the current one, and its type ownership must not intersect any
 * OTHER domain's ownership.
 *
 * Replacing a live proposal deletes every readiness signal stored for the
 * old digest (old signals are never reusable). @return 0 / -1.
 */
int nodus_witness_domreg_op_propose(nodus_witness_t *w,
                                    const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                    uint32_t domain_id,
                                    const dna_domain_manifest_t *target,
                                    uint64_t proposal_nonce,
                                    uint64_t proposed_at_epoch);

/**
 * Submit one validator's readiness signal. ALL of the following must hold
 * or the signal is rejected without effect:
 *   - chain_id matches `expected_chain_id`;
 *   - the domain exists and carries a live proposal whose digest equals
 *     the signal's proposal_digest;
 *   - the signal's ruleset tuple (kind / abi / version / hash) equals the
 *     proposal's TARGET manifest tuple exactly;
 *   - `snap` is the authoritative snapshot whose epoch equals the
 *     signal's signal_epoch (epoch freshness);
 *   - the signal's voter_id is a member of `snap`;
 *   - the Dilithium5 signature verifies over the 233-byte preimage
 *     against that member's snapshot pubkey.
 * Duplicate handling is deterministic: a byte-identical re-submission is
 * a no-op (0); a DIFFERENT signal for the same (proposal, voter) key is a
 * conflict (-2, first-wins). A duplicate can never increase any count
 * (PRIMARY KEY). @return 0 stored/idempotent, -2 conflict, -1 rejected.
 */
int nodus_witness_domreg_op_signal(nodus_witness_t *w,
                                   const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN],
                                   const dna_readiness_signal_t *sig,
                                   const dna_vset_snapshot_t *snap);

/**
 * Count readiness for `proposal_digest` against the authoritative
 * snapshot `snap`: the number of DISTINCT snapshot members holding a
 * stored signal for that digest. One validator = one vote — stake never
 * weights this; a signal from a validator no longer in `snap` does not
 * count (membership churn recomputation). @return 0 / -1.
 */
int nodus_witness_domreg_readiness_count(nodus_witness_t *w,
                                         const uint8_t proposal_digest[DNA_DOM_HASH_LEN],
                                         const dna_vset_snapshot_t *snap,
                                         uint32_t *count_out);

/**
 * Stage B — governance schedules the live proposal.
 * Requires: digest matches; readiness_count(snap) >= dna_bft_quorum(N);
 * sched_epoch_start and activation_epoch are epoch starts (multiples of
 * DNAC_EPOCH_LENGTH) with activation_epoch >= sched_epoch_start + 2E.
 * Pins readiness_deadline_epoch = sched_epoch_start + 2E and flips
 * REGISTERED -> SCHEDULED (initial) / keeps ACTIVE (upgrade).
 * @return 0 / -1.
 */
int nodus_witness_domreg_op_schedule(nodus_witness_t *w,
                                     uint32_t domain_id,
                                     const uint8_t proposal_digest[DNA_DOM_HASH_LEN],
                                     uint64_t sched_epoch_start,
                                     uint64_t activation_epoch,
                                     const dna_vset_snapshot_t *snap);

/**
 * Governance cancellation of the live proposal (digest must match).
 * Clears proposal/pending/scheduling fields, flips SCHEDULED back to
 * REGISTERED, and DELETES every readiness signal for the digest — a
 * cancelled proposal's signals are never reusable. @return 0 / -1.
 */
int nodus_witness_domreg_op_cancel(nodus_witness_t *w, uint32_t domain_id,
                                   const uint8_t proposal_digest[DNA_DOM_HASH_LEN]);

/** Governance pause / resume / retire (minimal lifecycle edges; a domain
 *  with a live proposal cannot be paused or retired — cancel first).
 *  pause: ACTIVE->PAUSED; resume: PAUSED->ACTIVE; retire: any
 *  proposal-free non-retired state -> RETIRED. @return 0 / -1. */
int nodus_witness_domreg_op_pause(nodus_witness_t *w, uint32_t domain_id);
int nodus_witness_domreg_op_resume(nodus_witness_t *w, uint32_t domain_id);
int nodus_witness_domreg_op_retire(nodus_witness_t *w, uint32_t domain_id);

/* ── Stage C — unready exclusion (ordinary-transition inputs) ───────── */

/**
 * Compute the Stage-C exclusion list for the ordinary snapshot build of
 * `deadline_epoch_start`: the union, over every domain whose
 * readiness_deadline_epoch equals it, of candidate members WITHOUT a
 * stored signal for that domain's live proposal.
 *
 * Floor guard: if excluding them all would leave fewer than `min_count`
 * members, NO exclusion happens (*n_out = 0, return 2) — the old rules
 * simply continue and activation keeps postponing.
 *
 * @param candidate  the candidate snapshot the ordinary build produced.
 * @param excl_out   [out] voter_ids to exclude (candidate order).
 * @param cap        capacity of excl_out.
 * @return 0 list valid, 2 floor-guard (no exclusion), -1 error.
 */
int nodus_witness_domreg_exclusions_at(nodus_witness_t *w,
                                       uint64_t deadline_epoch_start,
                                       const dna_vset_snapshot_t *candidate,
                                       uint16_t min_count,
                                       uint8_t (*excl_out)[DNA_DOM_VOTER_ID_LEN],
                                       size_t cap, size_t *n_out);

/**
 * Pure helper: produce a NEW snapshot equal to `in` minus the listed
 * voters (order preserved; epoch/ruleset/seed copied). Touches NO
 * validator state — exclusion is selection-only and therefore
 * non-slashing by construction. @return heap snapshot (dna_vset_free) or
 * NULL (empty result, bad args, alloc).
 */
dna_vset_snapshot_t *
nodus_witness_domreg_filter_snapshot(const dna_vset_snapshot_t *in,
                                     const uint8_t (*excl)[DNA_DOM_VOTER_ID_LEN],
                                     size_t n_excl);

/* ── Stage D/E — boundary progression ───────────────────────────────── */

/**
 * Run the activation precheck for every domain whose
 * scheduled_activation_epoch equals `boundary_epoch_start` (ORDER BY
 * domain_id — deterministic), against the THEN-authoritative snapshot
 * `snap_now` and the previous epoch's `snap_prev`.
 *
 * AUTHORITY PIN: snap_now->epoch must equal boundary_epoch_start and
 * snap_prev->epoch must equal boundary_epoch_start − E — substituting the
 * current set for a historical one is structurally rejected (-1):
 *
 *   PASS  = every snap_now member holds a stored signal for the live
 *           proposal AND membership(snap_now) == membership(snap_prev)
 *           (Stage D separation). -> ACTIVATE: initial domains flip
 *           SCHEDULED->ACTIVE; upgrades promote pending->current.
 *           Scheduling + proposal fields clear; the digest's readiness
 *           signals are deleted.
 *   FAIL  -> POSTPONE by exactly one epoch (+= E, postpone_count += 1).
 *
 * @param activated_out / postponed_out  [out] optional counters.
 * @return 0 (all decisions applied), -1 error (nothing partially applied
 *         for the failing domain).
 */
int nodus_witness_domreg_on_boundary(nodus_witness_t *w,
                                     uint64_t boundary_epoch_start,
                                     const dna_vset_snapshot_t *snap_now,
                                     const dna_vset_snapshot_t *snap_prev,
                                     uint32_t *activated_out,
                                     uint32_t *postponed_out);

/* ── V2 semantic admission routing (INACTIVE — tests only in S4) ────── */

#include "dnac/tx_wire.h"    /* dna_exec_context_t */

/**
 * Semantic admission of one V2 ExecutionContext against the registry and
 * the locally compiled runtime table. STRUCTURAL decoding is NOT done
 * here (the shared codec already did it); this is the RUNTIME/ADMISSION
 * policy layer the S1 codec deliberately left out. Every check must pass:
 *
 *   1. ctx is structurally valid (wire_version 3);
 *   2. ctx->chain_id equals `expected_chain_id`;
 *   3. the domain exists in the registry;
 *   4. its status is ACTIVE (REGISTERED / SCHEDULED / PAUSED / RETIRED
 *      all reject);
 *   5. ctx->ruleset_version equals the ACTIVE manifest's ruleset_version;
 *   6. the EXACT runtime tuple of the active manifest is locally compiled
 *      (nodus_runtime_lookup — a validator without the runtime admits
 *      nothing from that domain);
 *   7. the manifest owns ctx->tx_type (ownership is unique by
 *      registration — one type, one owner);
 *   8. statement_version is 0 for every non-proof-bearing type;
 *   9. the runtime's own admit() accepts (pool legality + the C3 type-11
 *      REJECT live here too);
 *  10. quotas: with `used_tx_count` / `used_verify_cost` already consumed
 *      in this block, the manifest's nonzero quotas must not be exceeded
 *      (quota 0 = bounded only by the global block caps).
 *
 * @param cost_out [out] optional; the type's declared verification cost
 *                 (work units) on admit.
 * @return 0 admit, -1 reject (fail-closed on any fault).
 */
int nodus_witness_domreg_admit_v2(nodus_witness_t *w,
                                  const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN],
                                  const dna_exec_context_t *ctx,
                                  uint32_t used_tx_count,
                                  uint32_t used_verify_cost,
                                  uint32_t *cost_out);

/* ── Signal builder (the LOCAL-support gate) ────────────────────────── */

/**
 * Build and sign THIS validator's readiness signal for `domain_id`'s live
 * proposal. REFUSES (-1) unless the locally compiled runtime table
 * (nodus_runtime_lookup) contains the EXACT proposed tuple — a validator
 * without the runtime can never produce a valid signal, for any prompt.
 *
 * @param snap_epoch  the current authoritative snapshot's epoch (becomes
 *                    signal_epoch).
 * @param voter_id    this validator's 32-byte identity.
 * @param secret_key  Dilithium5 secret key (QGP_DSA87_SECRETKEYBYTES).
 * @return 0 with *out filled, -1 otherwise.
 */
int nodus_witness_domreg_build_signal(nodus_witness_t *w,
                                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                      uint32_t domain_id,
                                      uint64_t snap_epoch,
                                      const uint8_t voter_id[DNA_DOM_VOTER_ID_LEN],
                                      const uint8_t *secret_key,
                                      dna_readiness_signal_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DOMREG_H */
