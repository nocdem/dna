/**
 * @file shared/dnac/cmt_light_detector.h
 * @brief cometbft @v0.38.26 `light/detector.go` ported to C — the light
 *        client's second wall of defence: after the primary's trace is
 *        verified, every witness is asked for the same block; a witness
 *        with another block is examined, and a conflict that verifies on
 *        BOTH sides is an attack, which stops the client with a LOCAL
 *        RECORD of what the reference would have sent as evidence.
 *
 * ═══ STATUS: NO PRODUCTION CALLER ══════════════════════════════════════
 * Package 3 of the light client (Kurultay #25 item 2, docs/plans/
 * decisions/2026-10-16-kurultay-25-summary.md: "The detector is required
 * in v1, including the examine step … Evidence sending is replaced by
 * 'stop + local record' (K24 D3)"). It is called from ONE place, the
 * detector hook of cmt_light_client.c (`detect_divergence`), which the
 * reference reaches after every forward and between verification
 * (client.go:691-696, :815-822). Nothing in a node opens a client yet.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── reference → port ───────────────────────────────────────────────────
 *  detectDivergence                  detector.go:28-110   cmt_light_detect_divergence
 *  compareNewLightBlockWithWitness   :121-220             compare_with_witness, after_sleep (.c)
 *  sendEvidence                      :222-228             NOT PORTED (DD4)
 *  handleConflictingHeaders          :232-289             handle_conflicting_headers (.c)
 *  examineConflictingHeaderAgainstTrace :305-389          examine_trace (.c)
 *  getTargetBlockOrLatest            :394-419             get_target_block_or_latest (.c)
 *  newLightClientAttackEvidence      :423-439             cmt_light_attack_evidence_build
 *  (none — K25-10 lock, DD9)                              cmt_light_attack_record_encode
 *  LightClientAttackEvidence.ConflictingHeaderIsInvalid
 *                                    types/evidence.go:304-310
 *                                                         cmt_light_conflicting_header_is_invalid
 *  LightClientAttackEvidence.GetByzantineValidators
 *                                    types/evidence.go:252-299
 *                                                         (inside cmt_light_attack_evidence_build)
 *  ProposerPriorityHash comparison   detector.go:211-216  cmt_light_priorities_equal (K25-3)
 *  errors: ErrFailedHeaderCrossReferencing (errors.go:45-47),
 *          ErrLightClientAttack (:68-72), ErrConflictingHeaders (:78-88),
 *          ErrProposerPrioritiesDiverge (:90-104), errBadWitness
 *          (:110-117), errNoDivergence (:119-121) — cmt_light_client.h
 *          codes and the internal result classes of the .c file.
 *
 * ── DEVIATIONS (each with its reason) ──────────────────────────────────
 *  DD1 K25-3 (operator 2026-10-16, "Evet, onaylıyorum") — the proposer
 *      priorities are compared as the FULL VECTOR, in validator order,
 *      length included (`cmt_light_priorities_equal`), instead of
 *      `ProposerPriorityHash()` (detector.go:211-216). That hash writes
 *      every varint at offset 0 of its buffer (types/validator_set.go:
 *      392-398, `binary.PutVarint(buf, …)` with no offset), so two sets
 *      whose priorities differ only in an earlier validator can hash the
 *      same. Node-local: no wire byte, block, root or consensus rule
 *      changes. The same function serves the init agreement rule (item 9
 *      R3, cmt_light_client.h) — one implementation.
 *  DD2 THE WAIT (detector.go:142-197). The reference, on ErrHeightTooHigh
 *      from a witness whose latest block is still behind the primary's and
 *      earlier in time, SLEEPS `2*maxClockDrift + maxBlockLag` (:168) and
 *      asks again. This client has no clock and runs on one event loop, so
 *      it neither sleeps nor reads a clock. The decision is split into the
 *      reference's two asks, separated by the CALLER's `now`:
 *        · first pass (no wait recorded for this target): the steps before
 *          the sleep (:142-162) run unchanged; a witness that reaches the
 *          sleep makes the whole detection return CMT_REJECT with
 *          CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND ("re-check later") AFTER
 *          every other witness was handled — nothing is saved, and the
 *          client records (target height, target hash, `now`) and a deep
 *          copy of the target light block itself;
 *        · a later call that verifies the SAME target (height and hash)
 *          with `now >= recorded now + 2*max_clock_drift + max_block_lag`
 *          is the post-sleep pass: a witness that is still too high goes
 *          straight to the post-sleep ask (:169-196), whose results are
 *          handled AFTER every other witness's, as the reference's arrive
 *          after the sleep. A call before that `now` is still the first
 *          pass and may return WITNESS_BEHIND again.
 *      What the reference decides is unchanged: the same asks in the same
 *      order with the same classification (including Q-D1 below). The
 *      wait itself is the caller's: it must call again no earlier than
 *      the wait it would have slept. Not reproduced, and why:
 *        · in the post-sleep pass every witness that answers
 *          ErrHeightTooHigh takes the post-sleep path, including one that
 *          did not reach the sleep in the first pass (it answered
 *          something else then). The reference would have given such a
 *          witness its own pre-sleep check and its own sleep. Recording a
 *          wait per witness would not make the two runs identical either:
 *          between two calls every witness may answer differently, which
 *          is network timing in the reference too.
 *        · the record is ONE target. What keeps it and what clears it, as
 *          cmt_light_detect_divergence does it:
 *            - KEPT, untouched, by the returns that come before any
 *              witness is asked: a NULL argument (CMT_FAULT), SHORT_TRACE
 *              (:29-31), a fault reading the target's height or hash, and
 *              NO_WITNESSES with an empty list (:44-46);
 *            - KEPT (or written, when none is recorded for this target —
 *              a record for another target is then replaced, `since` =
 *              this `now`) by WITNESS_BEHIND;
 *            - CLEARED by every other return: a fault while comparing,
 *              an attack, a cap, a fault or any other result of
 *              handleConflictingHeaders, PROPOSER_PRIORITIES_DIVERGE,
 *              NO_WITNESSES from removeWitnesses (:98-100), CMT_OK and
 *              FAILED_HEADER_CROSS_REFERENCING (the reference's sleep
 *              belongs to one detection).
 *          Calls that do not reach the detector (backwards verification,
 *          a trusted-height lookup, Cleanup) leave it as it is — except
 *          Update, which drops a record whose height is already in the
 *          store, and a pinned call (Update or VerifyLightBlockAtHeight,
 *          cmt_light_client.h D21), which clears the record after it
 *          judged the stored block, whatever the verdict; it only ever
 *          applies to a detection of the same height AND hash. Every
 *          clear or replacement frees the stored block
 *          (`cmt_light_detector_wait_clear`), and so does
 *          cmt_light_client_free.
 *        · the witnesses marked bad in a pass that ends WITNESS_BEHIND
 *          (a conflicting header that did not verify, :74-75; an
 *          errBadWitness, :77-82) are REMOVED before WITNESS_BEHIND is
 *          returned, as the reference removes them once its sleeping
 *          comparison has returned (:98-100). The Q-D3 refusal cannot
 *          fire there — the behind witness is never marked, so fewer
 *          than all are removed — but it is kept and is NO_WITNESSES.
 *          The record is a (height, hash) pair, so the re-indexing of
 *          removeWitnesses (Q7, cmt_light_client.h) does not touch it.
 *      THE MOVING TARGET (BUGS Z-41). Because the record is keyed to the
 *      TARGET, a caller whose target moved between the two calls — Update,
 *      which asks the primary for its LATEST block — would start a new
 *      wait on every call while a witness stays behind and the primary
 *      keeps producing, and get WITNESS_BEHIND every time. The fix is in
 *      Update (cmt_light_client.h D21), as the reference's outcome: while
 *      a wait is recorded, Update returns WITNESS_BEHIND without fetching
 *      until the wait has run, then verifies the STORED target block —
 *      the primary is not asked for it again, so what it serves at that
 *      height meanwhile changes nothing — and only the next Update moves
 *      to the latest block. Keying the wait to the
 *      WITNESS instead (one `since` per witness, whatever the target) was
 *      considered and REJECTED: the reference's sleep runs AFTER the target was fetched,
 *      so the target's time is at most `now + max_clock_drift` of the
 *      first ask (light/verifier.go:176-181; cmt_light_verifier.c:193-196)
 *      and the second ask comes `2*drift + lag` later — late enough for
 *      an honest witness to hold a block that is not before it (:184).
 *      A per-witness `since` taken at an EARLIER target gives a NEW
 *      target no such margin: a primary could serve a fresh block timed
 *      just under `now + drift` once the witness's wait has run, the
 *      honest witness's latest block is still before it (:196, benign),
 *      and an accomplice witness's match trusts it — the attack the wait
 *      exists to expose. D21 keeps that margin: the block verified after
 *      the wait is the one whose first ask started it.
 *      The liveness note at :193-195 ("If the clock drift / lag has been
 *      miscalibrated … may allow for a malicious primary to attack it")
 *      applies unchanged: a witness that stays behind after the wait is
 *      benign (:196), and another witness's match then trusts the block.
 *  DD3 THE LOCAL RECORD. This port has no LightClientAttackEvidence type
 *      (cmt_evidence.h:18, :80; the evidence decoder refuses branch 2,
 *      cmt_pb.h:379-397). `newLightClientAttackEvidence` builds a
 *      `cmt_light_attack_evidence_t` instead, holding the same fields
 *      (types/evidence.go:208-216): the conflicting block (a deep copy),
 *      the common height, the byzantine validators, the total voting power
 *      and the timestamp — the last as the reference sets it, from the
 *      common or trusted BLOCK's time (:430, :434), never a clock. The
 *      record adds, labelled PROJECT, the caller's `now` of the detection,
 *      the two providers' identities, the witness index, which evidence
 *      is missing (DD10) and whether it was written durably (DD9). It is
 *      returned to the caller (cmt_light_client_attack_record), written
 *      to the light store in the byte form of
 *      `cmt_light_attack_record_encode` (DD9), and is never put on any
 *      wire: there is no proto and no hash for it.
 *  DD4 ReportEvidence IS NOT CALLED. The reference sends the evidence
 *      against the primary to the witness and the evidence against the
 *      witness to the primary (`sendEvidence`, :222-228, :258, :286). The
 *      provider slot takes a `cmt_pb_evidence_t` (cmt_light_provider.h),
 *      which cannot carry this evidence, and K24 D3 / Kurultay #25 item 2
 *      replace sending with "stop + local record". Nothing is sent and
 *      nothing here claims delivery: the attack error says that an attack
 *      was DETECTED and recorded on this node, not that anyone was told.
 *      (The reference's error text, "Evidence has been sent to both
 *      providers", errors.go:68-72, is not reproduced.)
 *  DD5 The caps of the client (cmt_light_client.h D3) bound every loop
 *      here, and a cap reached inside the detector FAILS CLOSED: the
 *      detection returns the cap's error, nothing is saved, and the
 *      witness is NOT removed. The reference has no caps; treating a cap
 *      as an examine failure would remove a witness that might have been
 *      proving an attack. Bounds:
 *        · detectDivergence: one comparison per witness (n_witnesses);
 *        · getTargetBlockOrLatest: at most two fetches;
 *        · examine: at most `trace_len` fetches (≤ max_trace_len), and its
 *          verifySkipping calls share ONE `max_verify_steps` counter per
 *          examine; each output trace is limited to `max_trace_len`;
 *        · memory: one comparison buffer per detection, and per
 *          conflicting witness one pool (freed before the next witness)
 *          of at most 2 × (max_trace_len + 2 × max_verify_steps) light
 *          block buffers (two examines; cmt_light_client.h D3 gives the
 *          buffer size), plus the record's two deep copies on an attack.
 *  DD6 A Go nil dereference or index panic is CMT_FAULT (the client's D7):
 *      `previouslyVerifiedBlock` nil at :338, an empty witness trace at
 *      :254, and `trusted.Commit.Signatures[i]` out of range in the
 *      equivocation branch (evidence.go:283). None is reachable with two
 *      verified traces (the last needs two sets with one hash, i.e. one
 *      size and one order, and verifyBasicValsAndCommit makes each
 *      commit as long as its set); none is a verdict on a peer.
 *      ONE CASE IS REACHABLE AND IS NOT A FAULT (BUGS Z-42): a nil
 *      validator from GetByAddress in the equivocation branch
 *      (evidence.go:288-289 — Go appends the nil and the sort at :291
 *      dereferences it). The commit check stops counting once more than
 *      2/3 has signed (types/validation.go:289-291 batch, :401-403
 *      single; the port cmt_validation.c:264-266), so a COMMIT signature
 *      AFTER that point is never looked at: its address may name no
 *      validator of the set, and the block still verifies. Here such a
 *      signature is SKIPPED and counted (`n_unknown_signers`); the
 *      validators that did sign are named as before.
 *      ⚠ CLAIMED, NOT VERIFIED (F4): for the same reason, a COMMIT entry
 *      past the 2/3 stop point whose address DOES name a validator was
 *      never signature-checked either. `byzantine_validators` therefore
 *      lists the validators the two commits CLAIM signed, in both
 *      branches (the lunatic branch reads the conflicting commit's
 *      COMMIT flags the same way, evidence.go:257-268), not validators
 *      proven to have signed. The reference's evidence is the same list
 *      (it, too, reads flags only). Any later use that punishes or blames
 *      a validator — the future K25-4 evidence work — must verify each
 *      named signature against its sign bytes first.
 *  DD7 Witnesses are compared in INDEX ORDER (the client's D2) where the
 *      reference starts one goroutine per witness and handles the results
 *      in ARRIVAL order (:50-95). An early return (an attack, a priority
 *      divergence) therefore depends on index order here, on network
 *      timing there. Post-sleep results come last (DD2), as theirs do.
 *  DD8 `context.Canceled` / `DeadlineExceeded` (:90-92, :134, :171-173)
 *      have no counterpart (cmt_light_provider.h): a provider that ran out
 *      of its own deadline answers NO_RESPONSE.
 *  DD9 THE ATTACK LOCK (K25-10, operator 2026-10-19, "1"; docs/plans/
 *      decisions/2026-10-16-kurultay-25-summary.md: "after
 *      LIGHT_CLIENT_ATTACK the client refuses every further verification /
 *      save until an explicit operator clear; every attack record is kept
 *      durably in the light store … and survives a restart, which reloads
 *      the lock"). The reference has NO latch: the attack error ends that
 *      one call (detector.go:72 → client.go:820-821) and the next call
 *      verifies again. Here, when a detection returns
 *      LIGHT_CLIENT_ATTACK, the client's hook (cmt_light_client.c,
 *      `detect_divergence`) LOCKS the client and writes the record's bytes
 *      (`cmt_light_attack_record_encode`) to the store
 *      (cmt_light_store.h D9). A failed write still locks the client in
 *      memory and still returns the attack; the record's `durable` is then
 *      false and the failure is logged (a restart would not reload that
 *      lock); the write is retried at the start of every call while
 *      locked and before a clear, which refuses until it succeeded
 *      (cmt_light_client.h D20). While locked, cmt_light_client_update,
 *      cmt_light_client_verify_light_block_at_height and
 *      cmt_light_client_cleanup refuse with
 *      CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED and change nothing; so does the
 *      store write of updateTrustedLightBlock (a second guard). A client
 *      made over a store holding an uncleared record starts locked
 *      (cmt_light_client_new_from_trusted_store), and cmt_light_client_new
 *      refuses it (its next steps would change the trusted store). Only
 *      `cmt_light_client_attack_clear` (or the store's own
 *      cmt_light_store_db_clear_attack_records) unlocks; it marks the
 *      records cleared and deletes none. Node-local: no wire, block, root
 *      or consensus rule changes. Cost the operator accepted: a false
 *      alarm halts that light client until the operator looks.
 *  DD10 AN ESTABLISHED ATTACK IS NEVER DOWNGRADED (BUGS Z-42). Once the
 *      witness's conflicting header has verified (:240-250 passed), the
 *      call returns LIGHT_CLIENT_ATTACK and keeps the record whatever
 *      happens while the evidence is built: a malformed trace, an
 *      evidence build that fails, a second examine that faults. What
 *      could not be built is named in `missing`
 *      (CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY / _AGAINST_WITNESS) and
 *      logged; Q-D4 — the second examine REJECTING — stays what it is in
 *      the reference: `has_against_witness` false, nothing in `missing`.
 *      The one exception is an allocation failure of the record itself,
 *      which leaves nothing to keep or to write: the call is CMT_FAULT,
 *      and the client is still LOCKED, in memory only (DD9).
 *
 * ── REFERENCE QUIRKS REPRODUCED AS-IS ──────────────────────────────────
 *  Q-D1 Before the sleep, an error from getTargetBlockOrLatest goes to the
 *       result channel RAW (:146-149) and lands in detectDivergence's
 *       `default` case (:87-94): benign, even ErrBadLightBlock. After the
 *       sleep the same error is wrapped in errBadWitness (:170-176) and
 *       removes the witness.
 *  Q-D2 ErrProposerPrioritiesDiverge returns at once (:83-86): the witness
 *       is NOT removed, witnesses already marked bad are not removed, and
 *       the remaining witnesses are not handled.
 *  Q-D3 A witness that sends a conflicting header which cannot be verified
 *       is removed (:74-75), but when it is the last witness the removal
 *       refuses and the detection returns ErrNoWitnesses (:98-100) — the
 *       block is not trusted.
 *  Q-D4 The second examine (holding the primary as the source of truth)
 *       may fail for any reason — the primary does not have a block, its
 *       trace does not verify — and the result is STILL the attack error
 *       (:276-279); only the evidence against the witness is missing.
 *  Q-D5 The amnesia notice (:260-264) is a log line; the record keeps it
 *       as a flag.
 *  Q-D6 In the equivocation branch of GetByzantineValidators, `sigB` is
 *       the trusted commit's signature at the conflicting commit's INDEX
 *       (types/evidence.go:277-286) — positional, relying on the two sets
 *       sharing a hash (the comment at :275-276).
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock: `now` is the caller's. No randomness, no map, no floating
 * point. Witnesses in index order. Byzantine validators are sorted with
 * cmt_validators_sort_by_voting_power (types/validator_set.go:906-911, a
 * total order: power descending, address ascending). What one light
 * client trusts, and every record, is node-local and never part of any
 * consensus value.
 *
 * ── Threat model, in one line ──────────────────────────────────────────
 * The light node's honesty assumption is K25-4's: more than 2/3 of the
 * trusted set is honest, at least one provider is honest, the root is
 * right; no economic punishment. The detector turns "one provider is
 * honest" into "a lie is noticed": it does not punish anyone (BUGS Z-12).
 *
 * Reference @v0.38.26 (/home/nocdem/refs/cometbft-v0.38.26):
 *   light/detector.go   439 lines
 *   light/errors.go     121 lines
 *   types/evidence.go   :204-318 (LightClientAttackEvidence, the parts read)
 * Governing records: Kurultay #25 (items 2, K25-3, K25-4, K25-8, K25-10) —
 * docs/plans/decisions/2026-10-16-kurultay-25-summary.md; K24 D3 —
 * docs/plans/decisions/2026-10-15-kurultay-24-summary.md; B9 —
 * docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-role.md; pin —
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_DETECTOR_H
#define SHARED_DNAC_CMT_LIGHT_DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_time.h"            /* cmt_time_t                            */
#include "cmt_validator_set.h"   /* cmt_validator_t, cmt_validator_set_t  */
#include "cmt_light_block.h"     /* cmt_light_block_t, _buf_t             */
#include "cmt_light_client.h"    /* the client, its error type            */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ K25-3 — the proposer-priority comparison ═════════════════════════ */

/**
 * K25-3 — the full proposer-priority vector, in validator order, length
 * included; replaces `bytes.Equal(ProposerPriorityHash(), …)`
 * (detector.go:211-216; DD1). Two NULL sets are equal; one NULL is not.
 */
bool cmt_light_priorities_equal(const cmt_validator_set_t *a,
                                const cmt_validator_set_t *b);

/* ══ the local record (DD3) ═══════════════════════════════════════════ */

/** Which branch of GetByzantineValidators (types/evidence.go:252-299)
 *  produced `byzantine_validators`. A label of the record. PROJECT. */
#define CMT_LIGHT_ATTACK_LUNATIC      1   /* :257-271 header invalid      */
#define CMT_LIGHT_ATTACK_EQUIVOCATION 2   /* :272-292 same commit round   */
#define CMT_LIGHT_ATTACK_AMNESIA      3   /* :294-297 rounds differ       */

/**
 * The fields of `types.LightClientAttackEvidence` (types/evidence.go:
 * 208-216), held locally. Every pointer is owned; release with
 * `cmt_light_attack_evidence_release`.
 */
typedef struct {
    cmt_light_block_buf_t *conflicting_block;    /* :209 — a deep copy      */
    int64_t                common_height;        /* :210                    */
    cmt_validator_t       *byzantine_validators; /* :213 — owned, NULL if 0 */
    size_t                 n_byzantine;
    int64_t                total_voting_power;   /* :214                    */
    cmt_time_t             timestamp;            /* :215 — a BLOCK's time   */
    int                    attack;               /* CMT_LIGHT_ATTACK_*      */
    /** PROJECT (DD6, BUGS Z-42): equivocation branch only — COMMIT
     *  signatures of the conflicting commit whose address is NOT in the
     *  conflicting set, skipped (evidence.go:288-289 appends a nil there
     *  and the sort at :291 panics). Such a signature lies past the 2/3
     *  point the commit check stopped at, so nothing ever checked it. */
    size_t                 n_unknown_signers;
} cmt_light_attack_evidence_t;

/** `cmt_light_attack_record.missing` — which evidence the record does NOT
 *  hold although the attack is established (DD10). PROJECT. */
#define CMT_LIGHT_ATTACK_MISSING_AGAINST_PRIMARY 1u  /* :252-255 not built  */
#define CMT_LIGHT_ATTACK_MISSING_AGAINST_WITNESS 2u  /* :281-283 not built,
                                                        although the second
                                                        examine succeeded or
                                                        faulted (not Q-D4)  */

/**
 * What one detected attack leaves behind (DD3). `against_primary` is the
 * evidence the reference sends to the witness (detector.go:254-258);
 * `against_witness`, present when the second examine succeeded
 * (:269-286, Q-D4), the one it sends to the primary. NEITHER IS SENT
 * (DD4). Read it through `cmt_light_client_attack_record`.
 */
struct cmt_light_attack_record {
    cmt_time_t                  now;            /* PROJECT: the caller's `now` */
    size_t                      witness_index;  /* :239, at detection          */
    uint8_t                     primary_id[CMT_LIGHT_CLIENT_PEER_ID_MAX];
    size_t                      primary_id_len; /* PROJECT                     */
    uint8_t                     witness_id[CMT_LIGHT_CLIENT_PEER_ID_MAX];
    size_t                      witness_id_len; /* PROJECT                     */
    cmt_light_attack_evidence_t against_primary;     /* :255               */
    bool                        has_against_witness; /* :276-279, Q-D4     */
    cmt_light_attack_evidence_t against_witness;     /* :283               */
    bool                        commit_rounds_differ;/* :260-264, Q-D5     */
    uint32_t                    missing;        /* PROJECT: CMT_LIGHT_ATTACK_MISSING_* (DD10) */
    /** PROJECT (DD9): the store's save of this record's bytes returned
     *  CMT_OK. False = the lock holds in memory only; a restart loses it. */
    bool                        durable;
};

/**
 * DD9 — the durable form of a record: what the light client hands the
 * store (cmt_light_store.h D9). All integers big-endian; a record encodes
 * to the same bytes every time (no clock, no padding, no pointer).
 *   u8  version = 1
 *   i64 now.seconds   i32 now.nanos
 *   u64 witness_index
 *   u8  primary_id_len, primary_id   u8 witness_id_len, witness_id
 *   u8  flags: bit 0 has_against_witness, bit 1 commit_rounds_differ
 *   u8  missing (CMT_LIGHT_ATTACK_MISSING_*)
 *   EVIDENCE against_primary — present unless MISSING_AGAINST_PRIMARY
 *   EVIDENCE against_witness — present iff has_against_witness
 * EVIDENCE:
 *   u32 n, then n bytes: `cmt_light_block_encode` of the conflicting block
 *   i64 common_height   i64 total_voting_power
 *   i64 timestamp.seconds   i32 timestamp.nanos   i32 attack
 *   u32 n_unknown_signers
 *   u32 n_byzantine, then per validator: u8 address_len, address,
 *       u8 pub_key.present, the 2592 key bytes when present,
 *       i64 voting_power, i64 proposer_priority
 * `durable` is not encoded (it describes the write). `*out` is malloc'd.
 * @return CMT_OK; CMT_REJECT when the conflicting block does not encode
 *         (cmt_light_block_encode); CMT_FAULT on NULL, a present evidence
 *         without its conflicting block, a field too long for its length
 *         byte, or an allocation failure.
 */
int cmt_light_attack_record_encode(const cmt_light_attack_record_t *r,
                                   uint8_t **out, size_t *out_len);

/**
 * cometbft@v0.38.26 types/evidence.go:304-310 —
 * `ConflictingHeaderIsInvalid(trustedHeader)`: true when any of
 * ValidatorsHash, NextValidatorsHash, ConsensusHash, AppHash or
 * LastResultsHash differs (a lunatic attack). NULL is false.
 */
bool cmt_light_conflicting_header_is_invalid(const cmt_header_t *trusted,
                                             const cmt_header_t *conflicting);

/**
 * cometbft@v0.38.26 light/detector.go:423-439 —
 * `newLightClientAttackEvidence(conflicted, trusted, common)`, with
 * `GetByzantineValidators(common.ValidatorSet, trusted.SignedHeader)`
 * (types/evidence.go:252-299) — as a local record (DD3).
 *   · invalid header (:428-431): CommonHeight / Timestamp / total power of
 *     `common`; byzantine = the conflicting commit's COMMIT signers found
 *     in `common`'s set (evidence.go:257-268; absent ones skipped,
 *     :264-267);
 *   · otherwise (:432-436): of `trusted`; equal commit rounds →
 *     byzantine = the validators of the conflicting set that signed
 *     COMMIT in both commits at the same index (evidence.go:272-290,
 *     Q-D6); different rounds → none (amnesia, :294-297);
 *   · sorted by ValidatorsByVotingPower (evidence.go:270, :291).
 * In the equivocation branch a COMMIT signer whose address is not in the
 * conflicting set is SKIPPED and counted in `n_unknown_signers` (DD6).
 * `out` is zeroed first; on any failure it holds nothing.
 * @return CMT_OK; CMT_FAULT on NULL, a missing member, an allocation
 *         failure, a total-power overflow (TotalVotingPower panics,
 *         validator_set.go:344-345), an address lookup that faults, or
 *         the DD6 index case (evidence.go:283).
 */
int cmt_light_attack_evidence_build(const cmt_light_block_t *conflicted,
                                    const cmt_light_block_t *trusted,
                                    const cmt_light_block_t *common,
                                    cmt_light_attack_evidence_t *out);

/** Free what `ev` owns and zero it. NULL is a no-op. */
void cmt_light_attack_evidence_release(cmt_light_attack_evidence_t *ev);

/** Free a record (both evidences, then the record). NULL is a no-op. */
void cmt_light_attack_record_free(cmt_light_attack_record_t *r);

/* ══ INTERNAL — between cmt_light_client.c and cmt_light_detector.c ═══
 *
 * The detector is a set of `(c *Client)` methods in the reference
 * (detector.go is a file of package light); it needs the client's
 * witnesses, options, provider entry point and verifySkipping. This
 * section exposes exactly that to the two files that define
 * CMT_LIGHT_CLIENT_INTERNAL before including this header. No other file
 * may define it.
 */
#ifdef CMT_LIGHT_CLIENT_INTERNAL

/** One provider and its identity, as the client holds it. */
typedef struct {
    cmt_light_provider_t p;
    uint8_t              id[CMT_LIGHT_CLIENT_PEER_ID_MAX];
    size_t               id_len;
} cmt_light_peer_t;

/** DD2 — the one recorded wait: a witness reached the sleep (:164-168)
 *  while the client verified `height` / `hash`, at the caller's `since`.
 *  `target` is a deep copy of THAT light block (owned; NULL only while the
 *  client has taken it out to judge it, cmt_light_client.h D21): after
 *  the wait the client judges this block, never a re-fetched one, as the
 *  reference keeps the same block across its sleep. One buffer (about
 *  0.9 MiB, cmt_light_client.h D3) at most. Release with
 *  `cmt_light_detector_wait_clear`. */
typedef struct {
    bool                   pending;
    int64_t                height;
    uint8_t                hash[CMT_TMHASH_SIZE];
    size_t                 hash_len;
    cmt_time_t             since;
    cmt_light_block_buf_t *target;
} cmt_light_detector_wait_t;

/** Forget the recorded wait: free its target and zero it. NULL is a
 *  no-op. Every path that clears or replaces the record calls this. */
void cmt_light_detector_wait_clear(cmt_light_client_t *c);

/* client.go:133-162 — `type Client struct`. */
struct cmt_light_client {
    uint8_t                    chain_id[CMT_PB_CHAINID_MAX];   /* :134 */
    size_t                     chain_id_len;
    int64_t                    trusting_period;                /* :135 */
    cmt_light_client_options_t o;                              /* :136-140, :155-157 */
    cmt_light_peer_t           primary;                        /* :145 */
    cmt_light_peer_t          *witnesses;                      /* :147 */
    size_t                     n_witnesses;
    size_t                     witnesses_cap;   /* configured + 1 (:1086) */
    cmt_light_store_t          store;                          /* :150 */
    cmt_light_block_buf_t     *latest;          /* :152; NULL = nil */
    cmt_light_detector_wait_t  wait;            /* DD2 */
    cmt_light_attack_record_t *attack;          /* DD3; the last attack */
    bool                       locked;          /* DD9 (K25-10) */
};

/** The per-operation pool of light-block buffers (cmt_light_client.h D3). */
typedef struct {
    cmt_light_block_buf_t **b;
    size_t                  len;
    size_t                  cap;
} cmt_light_pool_t;

/** A bounded, non-owning array of light blocks (a trace or a cache). */
typedef struct {
    const cmt_light_block_t **v;
    size_t                    len;
    size_t                    cap;
    uint64_t                  limit;
} cmt_light_trace_t;

/* Defined in cmt_light_client.c — each is the client's own function of
 * the same role, exposed unchanged. */
cmt_light_block_buf_t *cmt_light_client_pool_new(cmt_light_pool_t *p);
void cmt_light_client_pool_free(cmt_light_pool_t *p);
void cmt_light_client_trace_free(cmt_light_trace_t *t);
int  cmt_light_client_lb_height(const cmt_light_block_t *lb, int64_t *out);
int  cmt_light_client_lb_hash(const cmt_light_block_t *lb,
                              uint8_t out[CMT_TMHASH_SIZE], size_t *len);
int  cmt_light_client_lb_hash_equal(const cmt_light_block_t *a,
                                    const cmt_light_block_t *b, bool *eq);
int  cmt_light_client_buf_copy(cmt_light_block_buf_t *dst,
                               const cmt_light_block_t *src);
/** provider.go:9-29 through the client's D15 checks. */
int  cmt_light_client_fetch(const cmt_light_client_t *c,
                            const cmt_light_peer_t *pr, int64_t height,
                            cmt_light_block_buf_t *out,
                            cmt_light_provider_error_t *perr);
/** client.go:699-773 — verifySkipping (from `source`). */
int  cmt_light_client_verify_skipping(cmt_light_client_t *c,
                                      const cmt_light_peer_t *source,
                                      const cmt_light_block_t *trusted,
                                      const cmt_light_block_t *new_lb,
                                      cmt_time_t now, cmt_light_trace_t *trace,
                                      cmt_light_pool_t *pool, uint64_t *steps,
                                      cmt_light_client_error_t *err);
/** client.go:1018-1034 — removeWitnesses. */
int  cmt_light_client_remove_witnesses(cmt_light_client_t *c, size_t *idx,
                                       size_t k);

/** DD2 — true when a wait is recorded and `now` is at or past its
 *  `since` + 2*max_clock_drift + max_block_lag. False on NULL. */
bool cmt_light_detector_wait_elapsed(const cmt_light_client_t *c,
                                     cmt_time_t now);

/**
 * cometbft@v0.38.26 light/detector.go:28-110 — detectDivergence(): see the
 * file header. `trace` is the primary's verified trace; its blocks must
 * outlive the call.
 * @return CMT_OK (a witness matched and none diverged: the caller may save
 *         the block); CMT_REJECT with `err->code` SHORT_TRACE (:29-31),
 *         NO_WITNESSES (:44-46, :98-100), PROPOSER_PRIORITIES_DIVERGE
 *         (:83-86, `witness_index`), LIGHT_CLIENT_ATTACK (:72, :278, :288;
 *         `witness_index`; the record in `c->attack`), WITNESS_BEHIND
 *         (DD2), FAILED_HEADER_CROSS_REFERENCING (:109) or a cap (DD5);
 *         CMT_FAULT.
 */
int cmt_light_detect_divergence(cmt_light_client_t *c,
                                const cmt_light_trace_t *trace,
                                cmt_time_t now,
                                cmt_light_client_error_t *err);

#endif /* CMT_LIGHT_CLIENT_INTERNAL */

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_DETECTOR_H */
