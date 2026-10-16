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
 *          client records (target height, target hash, `now`);
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
 *        · the record is ONE target; verifying another target forgets it
 *          (the reference's sleep belongs to one detection).
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
 *      the two providers' identities and the witness index. It is returned
 *      to the caller (cmt_light_client_attack_record) and is never put on
 *      any wire: there is no proto, no codec and no hash for it.
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
 *      :254, `trusted.Commit.Signatures[i]` out of range and a nil
 *      validator from GetByAddress in the equivocation branch
 *      (evidence.go:283, :288-289 — Go appends the nil and the sort at
 *      :291 dereferences it). None is reachable with two verified
 *      traces (the second needs two sets with one hash, i.e. one size and
 *      one order); none is a verdict on a peer.
 *  DD7 Witnesses are compared in INDEX ORDER (the client's D2) where the
 *      reference starts one goroutine per witness and handles the results
 *      in ARRIVAL order (:50-95). An early return (an attack, a priority
 *      divergence) therefore depends on index order here, on network
 *      timing there. Post-sleep results come last (DD2), as theirs do.
 *  DD8 `context.Canceled` / `DeadlineExceeded` (:90-92, :134, :171-173)
 *      have no counterpart (cmt_light_provider.h): a provider that ran out
 *      of its own deadline answers NO_RESPONSE.
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
 * Governing records: Kurultay #25 (items 2, K25-3, K25-4, K25-8) —
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
} cmt_light_attack_evidence_t;

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
};

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
 * `out` is zeroed first; on any failure it holds nothing.
 * @return CMT_OK; CMT_FAULT on NULL, a missing member, an allocation
 *         failure, a total-power overflow (TotalVotingPower panics,
 *         validator_set.go:344-345) or the DD6 index / nil cases.
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
 *  while the client verified `height` / `hash`, at the caller's `since`. */
typedef struct {
    bool       pending;
    int64_t    height;
    uint8_t    hash[CMT_TMHASH_SIZE];
    size_t     hash_len;
    cmt_time_t since;
} cmt_light_detector_wait_t;

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
