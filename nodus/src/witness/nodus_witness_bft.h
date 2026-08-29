/**
 * Nodus — Witness BFT Consensus Engine
 *
 * BFT consensus for DNAC transaction witnessing.
 * Ported from dnac/src/bft/consensus.c — single-threaded, CBOR protocol.
 *
 * Key differences from DNAC:
 *   - No pthreads (runs in epoll event loop)
 *   - CBOR via Tier 3 protocol (not binary serialization)
 *   - Direct nodus_witness_db calls (not callbacks)
 *   - Signing/verification handled by T3 encode/decode layer
 *
 * @file nodus_witness_bft.h
 */

#ifndef NODUS_WITNESS_BFT_H
#define NODUS_WITNESS_BFT_H

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Config ──────────────────────────────────────────────────────── */

/** Initialize BFT config from witness count (quorum = 2f+1). */
void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n_witnesses);

/** Recompute w->bft_config from the on-chain committee at block_height.
 *
 * Authoritative quorum source. Called from leader-side round-start
 * AND from follower-side commit_batch success path (PR 1, 2026-05-03 —
 * fixes red-team C-3 from
 * docs/plans/2026-05-03-witness-auto-bootstrap-design.md). Without the
 * follower-side call, follower nodes silently drift from cluster
 * committee on CHAIN_CONFIG TX changes → divergent quorum → chain
 * split.
 *
 * Bootstrap fallback: empty committee → falls through to gossip-roster
 * size (F17 A5).
 *
 * @return 0 on success, -1 on DB error (w->bft_config left untouched). */
int  refresh_bft_config_from_committee(nodus_witness_t *w,
                                        uint64_t block_height);

/** Returns true if consensus is active (enough witnesses for quorum). */
bool nodus_witness_bft_consensus_active(const nodus_witness_t *w);

/* ── Leader election ─────────────────────────────────────────────── */

/** Get leader index for given epoch and view. */
int  nodus_witness_bft_leader_index(uint64_t epoch, uint32_t view,
                                      int n_witnesses);

/** Check if this witness is currently leader. */
bool nodus_witness_bft_is_leader(nodus_witness_t *w);

/* ── Roster ──────────────────────────────────────────────────────── */

/** Find witness in roster by ID. Returns index or -1. */
int  nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                 const uint8_t *witness_id);

/** Rank of witness_id in the roster SET ordered by witness_id (count of
 * strictly-smaller ids), independent of storage/arrival order. -1 if
 * absent. The pre-genesis leader fallback MUST use this rank, never the
 * arrival index: nodus_witness_roster_add appends in authentication
 * order and only the 60 s epoch rebuild sorts, so two nodes holding the
 * SAME set can disagree on arrival indices (BUGS.md 2026-08-04 — node7
 * rejected the genesis PROPOSE it should have voted on). */
int  nodus_witness_roster_sorted_find(const nodus_witness_roster_t *roster,
                                        const uint8_t *witness_id);

/** Inverse of nodus_witness_roster_sorted_find: ARRAY index of the entry
 * whose id has exactly `rank` strictly-smaller ids in the set, or -1.
 * Use this — never `witnesses[leader_slot]` — whenever a leader SLOT
 * produced by nodus_witness_bft_leader_index has to be resolved back to
 * a roster entry on the pre-genesis fallback. */
int  nodus_witness_roster_sorted_at(const nodus_witness_roster_t *roster,
                                      int rank);

/** O15C-D.3 — verify a prepared certificate presented on the wire.
 *
 * True iff at least quorum-many DISTINCT voters' signatures verify
 * against the 116-byte purpose-0x07 PREPARED preimage for
 * ("prepared" ‖ chain_id ‖ view ‖ height ‖ tx_hash), using the same
 * committee/roster key resolution handle_viewchg applies. chain_id is
 * read from `w`, never from the wire, so a certificate harvested before
 * a chain wipe cannot be replayed onto the successor. Duplicate voters
 * count once.
 * Anything short of quorum is false — fail-closed. */
bool nodus_witness_bft_verify_prepared_cert(nodus_witness_t *w,
                                              uint64_t height,
                                              uint32_t view,
                                              const uint8_t *tx_hash,
                                              const nodus_t3_cert_entry_t *sigs,
                                              uint32_t n_sigs);

/** O15C-D.3 — the PREPARED-VALUE LOCK.
 *
 * True iff this node must refuse `tx_hash` at `height` because it itself
 * prepared a DIFFERENT value there. Keyed on the node's own
 * `last_prepared` — its own authenticated evidence, captured at prevote
 * quorum and persisted across restart — rather than on the node-local
 * first-2f+1 `view_changes[]` subset, which is frozen at quorum and may
 * not even contain the node's own certificate.
 *
 * This is the refusal quorum intersection depends on: PRECOMMITTER ⇒
 * CARRIER, so any committed value has >= f+1 honest carriers in every
 * quorum-sized set, and each of them refuses a conflicting value at that
 * height. Height-gated so a value learned via SYNC leaves no stale lock.
 */
bool nodus_witness_bft_prepared_lock_blocks(const nodus_witness_t *w,
                                              uint64_t height,
                                              const uint8_t *tx_hash);

/** O15C-D.1 — apply the C5 reproposal selection to THIS node.
 *
 * Binds to the highest-ranked prepared certificate among the collected
 * VIEW_CHANGE records, or clears the binding when none carries one
 * (bind-or-clear: a stale binding rejects every later proposal).
 *
 * O15C-D.2 — the selection key is the CANONICAL TOTAL ORDER
 * (height, view, tx_hash), strictly descending, replacing the inherited
 * height-only rule whose equal-height ties fell back to arrival order.
 * `view` is the PBFT-canonical discriminator and is authenticated by the
 * same signatures that admit the cert; tx_hash is a total-order backstop
 * that quorum intersection should make unreachable. Identical candidate
 * SETS therefore always produce identical bindings, whatever order the
 * VIEW_CHANGE messages arrived in. See the definition for the full
 * per-level justification and the honest scope limit.
 *
 * Called on every node the moment it advances its own view on quorum.
 * Before this existed the rule was armed only in handle_newview behind
 * `new_view > current_view` — a guard that is false precisely because
 * the node just self-advanced — so the C5 gate never armed on the
 * common path and a new leader's substituted value would have been
 * accepted. The leader's NEW_VIEW payload is built from the same
 * result, so broadcast and enforcement cannot diverge. */
void nodus_witness_bft_bind_reproposal_from_view_changes(nodus_witness_t *w);

/** MED-28 — release the batch retained for a NEW_VIEW reproposal.
 * Safe to call when nothing is retained. */
void nodus_witness_retained_batch_clear(nodus_witness_t *w);

/** MED-28 — satisfy a NEW_VIEW reproposal binding from the retained
 * batch.
 *
 * The C5 rule binds the new view's first PROPOSE to a (height, tx_root)
 * DIGEST, and only a matching PROPOSE clears reproposal_required on the
 * followers — so a leader that broadcasts a binding it never acts on
 * wedges that height permanently. Called by the NEW_VIEW leader path
 * right after the broadcast.
 *
 * On a match the retained entries are handed to
 * nodus_witness_bft_start_round_from_entries, which recomputes the block
 * hash from the same tx_hashes in the same order — so the re-proposed
 * tx_root equals the bound digest by construction.
 *
 * Ownership: on a match the holder is emptied BEFORE the round starts,
 * so exactly one owner exists at every instant. If the round refuses the
 * batch, this function releases the entries itself.
 *
 * @return 0 if the reproposal round started; -1 if we do not hold the
 *         bound batch (caller stays silent and lets the view rotate) or
 *         the round refused it. */
int nodus_witness_try_repropose_retained(nodus_witness_t *w,
                                           uint64_t height,
                                           const uint8_t *tx_root);

/** Add witness to roster (no-op if already present). */
int  nodus_witness_roster_add(nodus_witness_t *w,
                                const nodus_witness_roster_entry_t *entry);

/* ── Consensus ───────────────────────────────────────────────────── */

/**
 * Phase 7 / Task 7.1 — start a BFT round from caller-owned entries.
 *
 * Thin wrapper over the shared batch round-start body. Used by callers
 * that already have mempool entries in hand (e.g. the genesis path,
 * which builds a single-entry array from raw TX args) and do not want
 * to go through the mempool pop/validate cycle.
 *
 * @return 0 success, -1 error
 */
int nodus_witness_bft_start_round_from_entries(nodus_witness_t *w,
                                                 nodus_witness_mempool_entry_t **entries,
                                                 int count);

/**
 * Phase 7 / Task 7.2 — start a BFT round from the mempool.
 *
 * Pops up to NODUS_W_MAX_BLOCK_TXS entries from the mempool, runs the
 * Phase 4 layer-2 chained-UTXO filter and DB-nullifier rechecks, and
 * forwards the survivors to the shared round-start body. On round-start
 * failure the surviving entries are returned to the mempool for retry.
 *
 * Replaces the previous static nodus_witness_propose_batch helper that
 * lived in nodus_witness.c.
 *
 * @return 0 success, -1 error or no valid entries
 */
int nodus_witness_bft_start_round_from_mempool(nodus_witness_t *w);

/* S3 — locate the optional chain_def trailer inside a serialized
 * genesis TX (pure wire walk; blob points INTO tx_data). Used by
 * commit_genesis (Rule P.2) and by sync replay to derive the genesis
 * cert quorum from the chain_def's seat count instead of the local
 * roster-derived bft_config. @return 0 (blob may be NULL) / -1. */
int nodus_witness_extract_chain_def(const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    const uint8_t **cd_blob_out,
                                    uint32_t *cd_blob_len_out);

/* Phase 6 commit wrappers — exposed for sync replay (Phase 11 Task
 * 11.4). nodus_witness_commit_block is the deprecated single-TX shim
 * that dispatches to these; sync.c calls them directly. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id);

int nodus_witness_replay_block(nodus_witness_t *w,
                                 uint64_t rsp_height,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root);

/* Phase 9 / Task 48 — per-block liveness attendance record.
 *
 * Deterministic attendance (2026-04-19 fix): record attendance based on
 * the block's proposer_id — a field in the committed block header that
 * every node agrees on. Previous design used local round_state.precommits
 * which varied per node due to TCP-delivery timing and precommit races,
 * producing divergent validator.last_signed_block and hence divergent
 * state_root at the next apply_accumulator_update (chain-halt observed
 * on d8d4d9c2 block 25). Under PROPOSER-based attendance, each
 * committee member earns attendance on blocks they proposed — with
 * round-robin leader election (epoch+view mod N), a healthy committee
 * of 7 rotates every 7 blocks, well within the 16-block liveness
 * window.
 *
 * Opens its own short-lived SQLite transaction (the block commit
 * transaction is already closed by the time the BFT / sync layer calls
 * this after nodus_witness_cert_store). Monotonic — never walks
 * last_signed_block backwards. Safe with proposer_id == NULL.
 */
int nodus_witness_record_attendance(nodus_witness_t *w,
                                      uint64_t block_height,
                                      const uint8_t *proposer_id);

/** Handle decoded PROPOSAL message. */
int nodus_witness_bft_handle_propose(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/** Handle decoded PREVOTE or PRECOMMIT message. */
int nodus_witness_bft_handle_vote(nodus_witness_t *w,
                                    const nodus_t3_msg_t *msg);

/** Handle decoded COMMIT message (from remote leader). */
int nodus_witness_bft_handle_commit(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg);

/** Handle decoded VIEW_CHANGE message. */
int nodus_witness_bft_handle_viewchg(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/** Handle decoded NEW_VIEW message. */
int nodus_witness_bft_handle_newview(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/* ── View change ─────────────────────────────────────────────────── */

/** Initiate view change (broadcasts VIEW_CHANGE to peers). */
int nodus_witness_bft_initiate_view_change(nodus_witness_t *w);

/**
 * O15H D3/D4 — the post-commit bookkeeping every SUCCESSOR commit path
 * owes: clear `last_prepared` (the block is durable, the certificate
 * protecting it is redundant) and refresh `bft_config` from the committee
 * governing the NEXT height.
 *
 * `nodus_witness_commit_batch` does both inline, but successor blocks do
 * not go through it. THREE paths commit a successor block and each must
 * call this:
 *   1. own-quorum        — nodus_witness_bft.c, PRECOMMIT quorum
 *   2. remote-COMMIT     — nodus_witness_bft.c, handle_commit
 *   3. sync / QC-recovery — nodus_witness_v2_finalize.c, which calls
 *      nodus_witness_v2_apply_block DIRECTLY
 *
 * ⚠ PATH 3 WAS MISSED, and the 20-node rehearsal showed what that costs.
 * A node that received a block by SYNC kept `last_prepared` pinned at the
 * height it had just committed, so it went on advertising a prepared
 * certificate for an ALREADY-COMMITTED height in every VIEW_CHANGE. Peers
 * selected that certificate, bound the new view to a committed height,
 * and rejected the leader's proposal for the real next one:
 * "C5 PROPOSE does not match NEW_VIEW reproposal (expected_h=37
 * got_h=37)", views climbing 8 → 18 with no block committed. Its quorum
 * also never refreshed — the original D3 symptom, on the third path.
 *
 * Idempotent, and safe to call after a REPLAY of an already-committed
 * block: clearing an already-clear slot is a no-op and the refresh reads
 * committed state. Refresh failure latches safety_halt — a witness that
 * cannot know its committee must not keep voting.
 */
void nodus_witness_bft_after_successor_commit(nodus_witness_t *w);

/* O15C-C D2 — feed buffered out-of-order PREVOTE/PRECOMMIT votes back
 * through the ordinary vote handler once the round/phase they belong to
 * is live. Called automatically at both round starts and after every
 * live vote; exported so the liveness regression can drive it. */
void nodus_witness_bft_drain_vote_buffer(nodus_witness_t *w);

/* ── Timeout ─────────────────────────────────────────────────────── */

/** Check for BFT round timeout. Called from nodus_witness_tick(). */
void nodus_witness_bft_check_timeout(nodus_witness_t *w);

/* ── Broadcast ───────────────────────────────────────────────────── */

/**
 * Encode and broadcast a T3 message to all connected witness peers.
 * Fills msg->header with sender identity (round, view, nonce, etc.).
 * Signs with server's Dilithium5 secret key.
 *
 * @return number of peers message was sent to
 */
int nodus_witness_bft_broadcast(nodus_witness_t *w, nodus_t3_msg_t *msg);

/* Phase 11 partial — nodus_witness_commit_block DELETED.
 * Was a thin dispatcher to commit_genesis / commit_batch; sync.c now
 * calls those wrappers directly. */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BFT_H */
