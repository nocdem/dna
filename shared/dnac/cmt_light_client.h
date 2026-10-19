/**
 * @file shared/dnac/cmt_light_client.h
 * @brief cometbft @v0.38.26 `light/client.go` and `light/trust_options.go`
 *        ported to C — the light client that moves its trust forwards
 *        (sequential or skipping verification), between and backwards,
 *        over a primary provider, a list of witnesses and a light store.
 *
 * ═══ STATUS: ONE CALLER — the nodus-light program ══════════════════════
 * Packages 2 and 3 of the light client (Kurultay #25 item 1, docs/plans/
 * decisions/2026-10-16-kurultay-25-summary.md: "LightBlock + ValidateBasic
 * → store → client → detector"). Nothing in a NODE opens a client yet; the
 * one caller is the stand-alone program nodus/tools/nodus-light.c (0.26.11).
 *
 * THE DETECTOR (package 3, Kurultay #25 item 2) is light/detector.go,
 * ported in cmt_light_detector.{c,h}. The reference calls
 * `detectDivergence` after every FORWARD and every BETWEEN verification
 * (client.go:691-696 in verifySequential, :815-822 in
 * verifySkippingAgainstPrimary); here that call goes to ONE named hook
 * (`detect_divergence` in cmt_light_client.c), which runs the detector. A
 * verified block is saved ONLY when the detector returns CMT_OK: at least
 * one witness holds the same block with the same proposer priorities
 * (K25-3), and no witness proved a conflict. An attack — a conflicting
 * header that verifies on both sides — STOPS the call with
 * CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK; nothing is saved, and the
 * local record of what the reference would have sent as evidence is
 * readable through `cmt_light_client_attack_record`. Nothing is sent to
 * any provider (cmt_light_detector.h DD3, DD4). The attack also LOCKS the
 * client until the operator clears it, and its record is written to the
 * light store, which reloads the lock after a restart (K25-10; D20 below,
 * cmt_light_detector.h DD9). Backwards verification
 * (:586-592 → `backwards`, :933-979) and initialisation (:360-393) do not
 * reach the detector, as in the reference.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── TRUST ROOT AND TRUSTING PERIOD ARE THE CALLER'S ────────────────────
 *  · K25-1 (operator 2026-10-16, "3"): the trust root is BOTH a release
 *    default and operator input. This library embeds NO checkpoint: the
 *    root is the `cmt_light_trust_options_t` the caller passes.
 *  · K25-2 (operator 2026-10-16, "48 saat"): the trusting period is 48 h
 *    in production. It is the caller's `period` (trust options) or
 *    `trusting_period` parameter; this library hard-codes no value.
 *
 * ── THE ≥ 2 AGREEMENT RULE AT INIT (Kurultay #25 item 9) ───────────────
 * Replaces the reference's lenient `compareFirstLightBlockWithWitnesses`
 * (:1131-1190), which ignores every "benign" error (:1172-1180), so a
 * client whose witnesses all stay silent initialises on the primary's word
 * alone. Here, after the primary's block at `options.height` has passed
 * the hash, ValidateBasic and commit checks (:364-384):
 *   R1 COHORT — the configured witnesses, in index order. Each is asked
 *      ONCE for its block at `options.height` (the SAME height; a witness
 *      that is behind is not asked for its latest).
 *   R2 IDENTITY — every provider carries the caller's identity bytes
 *      (`cmt_light_client_peer_t.id`; for a networked provider the pinned
 *      key, Kurultay #25 item 8). Agreement is counted over DISTINCT
 *      identities, and the primary's identity is one of them: a witness
 *      with the primary's identity, or one whose identity already agreed,
 *      adds nothing.
 *   R3 AGREE — a witness agrees iff it returns a block whose header hash
 *      equals the primary's (detector.go:205-208) AND whose validator set
 *      has the same proposer priorities, compared as the full vector in
 *      validator order, length included (K25-3 — instead of
 *      ProposerPriorityHash, detector.go:211-216).
 *   R4 SILENCE IS NOT AGREEMENT — NO_RESPONSE, LIGHT_BLOCK_NOT_FOUND and
 *      HEIGHT_TOO_HIGH add nothing (the reference's benign class,
 *      detector.go:134). BAD_LIGHT_BLOCK and an unnamed CMT_REJECT add
 *      nothing and the witness is removed (errBadWitness, detector.go:
 *      199-203 → client.go:1161-1166). HEIGHT_TOO_HIGH is NOT followed by
 *      the reference's request for the witness's latest block, its time
 *      comparison and its `time.Sleep(2*drift + lag)` (detector.go:
 *      142-197): item 9 compares at the same height. That lagging-witness
 *      logic belongs to the detector after init (cmt_light_detector.h
 *      DD2), which runs it.
 *   R5 DISAGREEMENT STOPS — the first witness whose block has a different
 *      hash (CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS, :1156-1160) or the
 *      same hash and different priorities
 *      (CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE, :1167-1171)
 *      ends the init with CMT_REJECT and its `witness_index`. Nothing is
 *      saved; the caller (the operator) decides.
 *   R6 THRESHOLD — the distinct agreeing identities, the primary
 *      included, must number at least `min_init_agreement` (never below
 *      CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT = 2); otherwise
 *      CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT and nothing is saved.
 *   ⚠ READING, NOT A RECORDED FACT: that the primary counts as one of the
 *     "≥ 2 peers" is this port's reading of item 9. A caller that wants
 *     two witnesses besides the primary sets `min_init_agreement` to 3.
 *   This is a CONSISTENCY check, never the root (K25-1): the root is
 *   `options.hash`, which the primary's block must match first (:376-378).
 *   DEADLINE — item 9 lists a deadline among the group rules. It is NOT in
 *   this package: bounding how long a witness may take is the PROVIDER
 *   implementation's job (cmt_light_provider.h). A witness that does not
 *   answer within it returns NO_RESPONSE, which counts as silence (R4).
 *   Every witness answer passes the client's own provider-contract checks
 *   (D15) before R3 compares it.
 *
 * ── DEVIATIONS (each with its reason) ──────────────────────────────────
 *  D1 The init agreement rule above replaces :1131-1190 (item 9).
 *  D2 Witnesses are queried in INDEX ORDER and the first valid answer is
 *     taken, where `findNewPrimary` (:1046-1127) and the init comparison
 *     query all of them concurrently and act in ARRIVAL order. Arrival
 *     order is network timing; index order makes a run reproducible. A
 *     witness after the one that answered is not asked (in Go its answer
 *     is cancelled, :1080).
 *  D3 Every loop has an explicit cap from the options (no default value —
 *     the caller chooses; a zero cap is refused at construction), and
 *     reaching it is a named CMT_REJECT:
 *       max_trace_len     — the trace either verification keeps
 *                           (:623, :688; :718, :734, :744). Sequential
 *                           verification's trace is gap + 1 blocks, so
 *                           this also caps the sequential gap; it is
 *                           checked BEFORE the first fetch.
 *       max_verify_steps  — Verify / VerifyAdjacent calls in one
 *                           verification, retries after a primary
 *                           replacement included (:626-689, :721-772,
 *                           and the re-run of :813).
 *       max_skipping_cache— the bisection cache (:714, :754, :765).
 *       max_backwards_steps — headers fetched in one backwards walk,
 *                           re-runs after a replacement (:973) included.
 *     Astra (Kurultay #25) flagged the unbounded trace. MEMORY is bounded
 *     by `max_verify_steps`, not by the trace or the cache (those hold
 *     pointers): every light block one forward / between verification
 *     fetches — an interim block or a pivot (each preceded by a Verify
 *     call) and a replacement primary's block (each after a failed
 *     Verify) — gets its own `cmt_light_block_buf_t` in a per-operation
 *     pool, so the pool holds at most about 2 × max_verify_steps buffers,
 *     all freed when the public call returns. sizeof(cmt_light_block_buf_t)
 *     = 945 856 bytes (x86_64 Linux gcc, CMT_VALSET_MAX = 128; read from
 *     a compile-time diagnostic, not a run): about 1.8 MiB per verify
 *     step. A backwards walk uses four buffers whatever its length, plus
 *     one each for the trusted block and the target.
 *  D4 The two recursions — verifySkippingAgainstPrimary calling itself
 *     after a replacement (:813) and backwards calling itself (:973) — are
 *     loops here, bounded by the caps of D3.
 *  D5 The detector hook (STATUS above) IS the detector now (package 3,
 *     cmt_light_detector.{c,h}, which list their own deviations DD1-DD10
 *     and quirks Q-D1..Q-D6). Until package 3 it failed closed with
 *     CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED; that code is gone.
 *     Reference behaviour now covered: detectDivergence (detector.go:
 *     28-110), compareNewLightBlockWithWitness (:121-220, the sleep split
 *     into two calls by the caller's `now` — DD2),
 *     handleConflictingHeaders (:232-289), examineConflictingHeader-
 *     AgainstTrace (:305-389), getTargetBlockOrLatest (:394-419) and
 *     newLightClientAttackEvidence (:423-439) as a LOCAL RECORD (DD3).
 *     Not covered: sendEvidence (:222-228) — nothing is sent (DD4). The
 *     hook is still not a caller-installable pointer.
 *  D6 CMT_FAULT is not a Go error value: a provider or store call that
 *     returns CMT_FAULT ends the operation with CMT_FAULT. It never
 *     triggers a primary replacement or a witness removal (the CMT_FAULT
 *     contract, cmt_tmhash.h:105-110: "a caller MUST NOT count -2 as …
 *     invalid input"). ONE EXCEPTION, inside the detector: once an attack
 *     is established (the witness's conflicting header verified), a
 *     provider or examine CMT_FAULT while its evidence is built does NOT
 *     end the call with CMT_FAULT — the call returns LIGHT_CLIENT_ATTACK,
 *     the record names the evidence it could not build in `missing`
 *     (cmt_light_detector.h DD10) and the client locks (D20).
 *  D7 A Go nil-pointer dereference is CMT_FAULT: a verify call while no
 *     block is trusted (`c.latestTrustedBlock` nil at :582 after Cleanup),
 *     a light block without its signed header, header or set where the
 *     reference reads through them (`.Height`, `.Hash()`).
 *  D8 `cleanupAfter` (:881-908) ignores a failed delete (:892-896, logs
 *     and goes on). Here a delete that does not return CMT_OK ends the
 *     cleanup with that code: a rollback the operator confirmed must not
 *     be reported done while the newer block is still stored.
 *  D9 ⚠ SECURITY — `backwards` (:933-979) checks that each fetched header
 *     is the parent of the one above it, down to the target height, but
 *     never that the header it reached IS the target block the primary
 *     sent first (`newLightBlock`, fetched separately at :488);
 *     `verifyLightBlock` then saves that first block (:609). A primary
 *     that answers the two requests for the same height differently gets
 *     an unverified block stored as trusted. Here, after the walk, the
 *     reached header's hash must equal the target's, else
 *     CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED (reason
 *     CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH). KEPT by the operator:
 *     K25-8 (2026-10-16, docs/plans/decisions/2026-10-16-kurultay-25-
 *     summary.md). The reference SPEC has this check: spec/light-client/
 *     verification/README.md:442-444 — `if hash(untrustedHeader) !=
 *     old.LastBlockID.Hash { return ErrInvalidAdjacentHeaders }` after
 *     the walk — and client.go applies it on its own error path
 *     (:966-971); only the success path of client.go lacks it.
 *  D10 `VerifyLightBlockAtHeight` returns the block it fetched TOGETHER
 *     with the verification error (:493). Here `out` holds the block only
 *     on CMT_OK; on any other return it is the empty light block.
 *  D11 `VerifyLightBlockAtHeight` proceeds on ANY error of
 *     `TrustedLightBlock` (:480-485). Here a CMT_FAULT from the store is
 *     returned; only a CMT_REJECT (not stored, no headers, unverified
 *     height, an unreadable row) proceeds.
 *  D12 Option widths: `PruningSize(uint16)` (:76) is 64-bit, to match the
 *     store's 64-bit count (cmt_light_store.h D1). `MaxRetryAttempts`
 *     (:100) is kept as uint16 and, as in the reference, NEVER READ —
 *     `maxRetryAttempts` has no reader in any .go file of light/.
 *     `MaxBlockLag` (:122) is read by the detector only (detector.go:168;
 *     the recorded wait of cmt_light_detector.h DD2).
 *  D13 `ConfirmationFunction(fn func(action string) bool)` (:85) becomes
 *     a callback that receives an action CODE and two heights; no text.
 *     NULL is the reference default "No confirmation is required" (:232).
 *  D14 `Logger` (:92) is the QGP_LOG macros; `quit` (:159) has no reader
 *     in client.go and is not ported; `providerMutex` (:143) is not ported
 *     — the client has ONE owner on one event loop and is NOT thread-safe.
 *  D15 PROVIDER CONTRACT MOVED INTO THE CLIENT. The reference's provider
 *     checks every answer before returning it: the header must be at the
 *     requested height when that is not 0 (light/provider/http/http.go:
 *     80-84) and `LightBlock.ValidateBasic(chainID)` must pass (:96-99),
 *     which binds the set's hash to the header's ValidatorsHash
 *     (types/light.go:21-44); either failure is ErrBadLightBlock. The C
 *     provider interface (cmt_light_provider.h) does not oblige an
 *     implementation to do this, so the client does it at its single
 *     entry point (`provider_light_block`) with its own chain id and
 *     block_protocol: a failure is BAD_LIGHT_BLOCK (reason CMT_REJECT),
 *     the buffer is reset, and every caller treats it as a provider's own
 *     ErrBadLightBlock. This restores the reference's behaviour; it is not
 *     a new rule. Without it a backwards walk (which checks only headers,
 *     :954) could store a real header with a foreign validator set — the
 *     later trusted set — and init would compare unvalidated witness
 *     blocks.
 *  D16 A CMT_OK answer with no signed header, header, commit or set is
 *     BAD_LIGHT_BLOCK (the first D15 check). In Go such a block is a nil
 *     dereference in the verifier; a peer's answer must not reach one.
 *  D17 cleanupAfter's walk (:884-899) has no option cap: each step reads a
 *     strictly LOWER stored height (LightBlockBefore), so it ends within
 *     the store's row count; it is counted against Size() + 1 and a store
 *     that breaks its own order is CMT_FAULT.
 *  D18 Constructor check order: CMT_FAULT for a NULL argument or a NULL
 *     provider / store row first; then the project's option domains
 *     (chain id length, mode, the D3 caps, min_init_agreement, the
 *     identities — CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS); then the
 *     reference's order: no witnesses (:242-244), a witness on another
 *     chain (:246-252; a CMT_FAULT from its chain_id row is CMT_FAULT),
 *     the trust level (:254-257), restore (:259-261). NewClient checks
 *     TrustOptions.ValidateBasic before all of these (:183-185).
 *  D19 The detector reads the caller's `now` where the reference does —
 *     to verify a conflicting witness's trace (detector.go:339, :370,
 *     through verifySkipping) — and ONE place more: the recorded wait of
 *     DD2 (cmt_light_detector.h) is measured against it, where the
 *     reference sleeps. It never reads a clock.
 *  D20 THE ATTACK LOCK (K25-10, operator 2026-10-19, "1"; docs/plans/
 *     decisions/2026-10-16-kurultay-25-summary.md). The reference has no
 *     latch (detector.go:72, client.go:820-821): its attack error ends
 *     one call. Here a call that returns LIGHT_CLIENT_ATTACK LOCKS the
 *     client and writes the record to the store (cmt_light_store.h D9;
 *     the byte form is cmt_light_detector.h DD9). While locked,
 *     cmt_light_client_update, cmt_light_client_verify_light_block_at_height
 *     and cmt_light_client_cleanup return CMT_REJECT with
 *     CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED and touch neither the providers
 *     nor the store; the store write of updateTrustedLightBlock refuses
 *     too. Reads (TrustedLightBlock, the heights, the identities, the
 *     record) still answer. cmt_light_client_new_from_trusted_store loads
 *     the lock from the store (an uncleared record → locked);
 *     cmt_light_client_new refuses a locked store with ATTACK_LOCKED,
 *     because its next steps (checkTrustedHeaderUsingOptions,
 *     initializeWithTrustOptions) change the trusted store. The operator
 *     unlocks with `cmt_light_client_attack_clear`, which marks every
 *     record cleared and deletes none.
 *     RULES THAT MAKE THE LOCK HOLD:
 *       · ONE client object per store prefix. The lock lives in the
 *         object and in the store; a second object on the same prefix
 *         loads it only at construction. As a second guard,
 *         updateTrustedLightBlock reads the store's uncleared records
 *         right before every save (one query on the prefix key) and
 *         refuses — and locks — when there is one, so a second object
 *         cannot save after the first one locked.
 *       · A record NOT YET DURABLE (its `durable` false: the encode or
 *         the store write failed) is written again at the start of every
 *         call while locked and before a clear; the clear REFUSES
 *         (CMT_REJECT, still locked) until the write succeeded. Encode
 *         and store failures are logged apart. A record whose encode
 *         fails every time can only be released at the store
 *         (cmt_light_store_db_clear_attack_records) with a new client.
 *  D21 UPDATE KEEPS THE TARGET OF A RECORDED WAIT (BUGS Z-41). The
 *     reference's Update fetches the latest block once and then, if a
 *     witness is behind, sleeps inside the call and trusts THAT block
 *     (client.go:447-459 → detector.go:164-197). Here the sleep is the
 *     caller's next call (cmt_light_detector.h DD2), and Update would
 *     otherwise fetch a NEW latest block on every call, so a primary that
 *     keeps producing restarted the wait forever. The record therefore
 *     holds the target LIGHT BLOCK ITSELF (a deep copy taken when the wait
 *     is recorded, cmt_light_detector.h DD2), and the primary is never
 *     asked for the target a second time — the reference keeps the same
 *     block across its sleep and does not re-ask either. A record PINS:
 *       · Update, when its height is above the trusted one;
 *       · VerifyLightBlockAtHeight, for exactly its height.
 *     Pinned, before the wait has run (`now` < since + 2*drift + lag) the
 *     call returns WITNESS_BEHIND without fetching anything; once it has
 *     run, the call verifies THE STORED BLOCK (the detector's post-sleep
 *     pass, DD2) and, on success, saves it — the client may then be
 *     behind the tip; the NEXT Update moves to the latest as usual.
 *     Whatever the verdict, the judged record is then cleared: a
 *     verification that failed before the detector ended this call as the
 *     reference's call would end, and the next call starts from a newly
 *     fetched target with a new wait. What the primary serves at that
 *     height in the meantime has no effect on the judged block.
 *     A record is STALE only when its height is already IN THE STORE
 *     (Update drops it then); a record below the tip that is not stored —
 *     VerifyLightBlockAtHeight's — is left for that call. The record is
 *     still ONE target: a later behind detection for another target
 *     replaces it (DD2).
 *
 * ── REFERENCE QUIRKS REPRODUCED AS-IS (recorded, not "fixed") ──────────
 *  Q1 verifySkipping appends a fetched pivot to the cache TWICE (:754 and
 *     :765), so the same block is verified twice against the same trusted
 *     block when the first attempt cannot trust it. Same verdict (Verify
 *     is a pure function), twice the ML-DSA work; the cache cap counts
 *     both entries. A candidate decision for the ORCHESTRATOR.
 *  Q2 On a BENIGN provider error at a pivot, verifySkipping returns the
 *     BARE ErrNewValSetCantBeTrusted (:757-758), which has no Unwrap; so
 *     verifySkippingAgainstPrimary's `errors.Unwrap(err)` is nil and takes
 *     the `case nil` branch (:814) with a nil trace, and detectDivergence
 *     refuses it ("nil or single block primary trace", detector.go:29-31).
 *     Here: CMT_LIGHT_CLIENT_ERR_SHORT_TRACE from the detector's first
 *     line (detector.go:29-31).
 *  Q3 `cleanupAfter` walks LightBlockBefore from the LATEST height down
 *     and never deletes the latest block itself (:882-899); the hash
 *     check that follows (:340-355) then removes everything.
 *  Q4 NewClientFromTrustedStore checks the WITNESSES' chain ids (:246-252)
 *     but not the primary's.
 *  Q5 After a replacement, the block saved is the ORIGINAL target the
 *     first primary sent (:609), not the replacement's (they share a
 *     hash, :667, :804, :966).
 *  Q6 findNewPrimary(remove = true) promotes the witness BEFORE
 *     `removeWitnesses` can refuse (:1091, :1098): when the promoted
 *     witness is the last one, the primary has changed, the list has not,
 *     and the call returns ErrNoWitnesses.
 *  Q7 removeWitnesses swaps each removed slot with the last witness
 *     (:1027-1031), so witness order changes; index-order queries (D2)
 *     follow the changed order.
 *  Q8 compareWithLatestHeight tests `height > latest` before `height < 0`
 *     (:421-428).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *  · detector.go's sendEvidence (:222-228) — "stop + local record"
 *    (cmt_light_detector.h DD4).
 *  · VerifyHeader (:525-556) — not in this package's dispatch.
 *  · `context.Context` — no counterpart (cmt_light_provider.h header): a
 *    provider that does not answer returns NO_RESPONSE.
 *  · Primary() / Witnesses() returning providers (:856-869) — the
 *    identity getters below answer what the reference's tests ask.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock: `now` is always the caller's parameter. No randomness, no
 * map, no floating point. Witnesses are visited in index order. What one
 * light client trusts is node-local and is never part of any consensus
 * value.
 *
 * Reference @v0.38.26 (/home/nocdem/refs/cometbft-v0.38.26):
 *   light/client.go         1190 lines
 *   light/trust_options.go    53 lines
 *   light/errors.go          121 lines (the client's error values)
 *   light/detector.go        439 lines (cmt_light_detector.{c,h})
 * Governing records: Kurultay #25 (above; K25-1, K25-2, K25-3, items 2, 7,
 * 8, 9); docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-
 * role.md (B9); pin decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_CLIENT_H
#define SHARED_DNAC_CMT_LIGHT_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_time.h"            /* cmt_time_t                            */
#include "cmt_fraction.h"        /* cmt_fraction_t                        */
#include "cmt_light_block.h"     /* cmt_light_block_t, _buf_t             */
#include "cmt_light_verifier.h"  /* cmt_light_error_t                     */
#include "cmt_light_provider.h"  /* cmt_light_provider_t                  */
#include "cmt_light_store.h"     /* cmt_light_store_t                     */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ light/trust_options.go ═══════════════════════════════════════════ */

/**
 * cometbft@v0.38.26 light/trust_options.go:11-36 — `TrustOptions`: "the
 * trust parameters needed when a new light client connects to the network
 * or when an existing light client that has been offline for longer than
 * the trusting period connects to the network". Supplied by the CALLER
 * (K25-1: the release default or the operator's own; K25-2: `period`).
 * `hash` is not owned and must outlive the call it is passed to.
 */
typedef struct {
    int64_t        period;     /* :30 `Period time.Duration`, nanoseconds */
    int64_t        height;     /* :34 */
    const uint8_t *hash;       /* :35 `Hash []byte` */
    size_t         hash_len;
} cmt_light_trust_options_t;

/**
 * cometbft@v0.38.26 light/trust_options.go:38-53 — `ValidateBasic()`:
 * `period <= 0` (:40-42), `height <= 0` (:43-45) and `len(hash) !=
 * tmhash.Size` (:46-52; 64 bytes here, cmt_tmhash.h) are CMT_REJECT.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on NULL `o`.
 */
int cmt_light_trust_options_validate_basic(const cmt_light_trust_options_t *o);

/* ══ light/client.go:20-126 — modes, defaults, options ════════════════ */

/** client.go:20-24 — `mode`. */
#define CMT_LIGHT_CLIENT_MODE_SEQUENTIAL 1
#define CMT_LIGHT_CLIENT_MODE_SKIPPING   2

/** client.go:26 — `defaultPruningSize = 1000`. */
#define CMT_LIGHT_CLIENT_DEFAULT_PRUNING_SIZE        1000u
/** client.go:27 — `defaultMaxRetryAttempts = 10` (never read, D12). */
#define CMT_LIGHT_CLIENT_DEFAULT_MAX_RETRY_ATTEMPTS  10u
/** client.go:28-32 — the bisection pivot, 9/16 of the way. */
#define CMT_LIGHT_CLIENT_VERIFY_SKIPPING_NUMERATOR   9
#define CMT_LIGHT_CLIENT_VERIFY_SKIPPING_DENOMINATOR 16
/** client.go:38 — `defaultMaxClockDrift = 10 * time.Second`, in ns. */
#define CMT_LIGHT_CLIENT_DEFAULT_MAX_CLOCK_DRIFT     ((int64_t)10 * 1000000000)
/** client.go:41 — `defaultMaxBlockLag = 10 * time.Second`, in ns. */
#define CMT_LIGHT_CLIENT_DEFAULT_MAX_BLOCK_LAG       ((int64_t)10 * 1000000000)

/** Kurultay #25 item 9 — "≥ 2 peers agree" (see the file header, R6). */
#define CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT          2u
/** The longest provider identity accepted, in bytes. A bound so the
 *  identity is finite; 64 holds an ML-DSA-87 key fingerprint (SHA3-512). */
#define CMT_LIGHT_CLIENT_PEER_ID_MAX                 64u

/** The two actions `ConfirmationFunction` is asked about (D13):
 *  :320-324 rollback to `a` = options.height, removing newer blocks up to
 *  `b` = the latest trusted height; :344-347 remove all stored blocks
 *  because the trusted hash at `a` = the latest trusted height does not
 *  match (`b` = 0). */
#define CMT_LIGHT_CLIENT_ACTION_ROLLBACK      1
#define CMT_LIGHT_CLIENT_ACTION_CLEANUP_ALL   2

/**
 * The reference's `Option`s (client.go:44-126) as one struct. Fill it with
 * `cmt_light_client_options_default` and then set the caps (D3), which
 * have NO default: a zero cap is refused by the constructors.
 */
typedef struct {
    int            verification_mode;   /* :47-70; default SKIPPING (:223) */
    cmt_fraction_t trust_level;         /* :65-69; default 1/3 (:224)     */
    uint64_t       pruning_size;        /* :72-80; 0 = never prune (D12)   */
    uint16_t       max_retry_attempts;  /* :98-104; never read (D12)       */
    int64_t        max_clock_drift;     /* :106-112, ns                    */
    int64_t        max_block_lag;       /* :114-126, ns; detector only     */
    /** The value Version.Block must equal (cmt_light_verifier.h:47-53);
     *  default CMT_BLOCK_PROTOCOL. */
    uint64_t       block_protocol;
    /** :82-89 `ConfirmationFunction` (D13). NULL = always yes (:232). */
    bool         (*confirm)(void *confirm_ctx, int action,
                            int64_t a, int64_t b);
    void          *confirm_ctx;
    /** Item 9 R6; default and minimum CMT_LIGHT_CLIENT_MIN_INIT_AGREEMENT. */
    size_t         min_init_agreement;
    /* ── caps (D3) — the caller's choice, no default ─────────────────── */
    uint64_t       max_trace_len;
    uint64_t       max_verify_steps;
    uint64_t       max_skipping_cache;
    uint64_t       max_backwards_steps;
} cmt_light_client_options_t;

/** The reference defaults (client.go:220-235): skipping with
 *  DefaultTrustLevel, pruning 1000, retry 10, drift 10 s, lag 10 s, no
 *  confirmation; plus block_protocol = CMT_BLOCK_PROTOCOL and
 *  min_init_agreement = 2. Every cap is 0 (unset). NULL is a no-op. */
void cmt_light_client_options_default(cmt_light_client_options_t *o);

/**
 * One provider and its IDENTITY (item 9 R2). `id` is the bytes the
 * caller knows the provider by — for a networked provider, its pinned key
 * (item 8). 1..CMT_LIGHT_CLIENT_PEER_ID_MAX bytes; copied by the
 * constructor. The provider table is copied too; its `ctx` must outlive
 * the client.
 */
typedef struct {
    cmt_light_provider_t provider;
    const uint8_t       *id;
    size_t               id_len;
} cmt_light_client_peer_t;

/* ══ errors — light/errors.go:43-121 and the client's unnamed errors ══ */

#define CMT_LIGHT_CLIENT_ERR_NONE                      0
/** `fmt.Errorf("invalid TrustOptions: %w")` (client.go:183-185). */
#define CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_OPTIONS     1
/** errors.go:74-76 — `ErrNoWitnesses` (client.go:242-244, :1021-1023,
 *  :1050-1052). */
#define CMT_LIGHT_CLIENT_ERR_NO_WITNESSES              2
/** "witness #%d … is on another chain" (client.go:247-252);
 *  `witness_index` is the witness. */
#define CMT_LIGHT_CLIENT_ERR_WITNESS_WRONG_CHAIN       3
/** ValidateTrustLevel (client.go:255-257, verifier.go:194-204). */
#define CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_LEVEL       4
/** An option outside its domain: an unknown mode (the reference panics at
 *  :572), a zero cap, `min_init_agreement` below 2, an empty or too long
 *  identity, a chain id above CMT_PB_CHAINID_MAX. PROJECT. */
#define CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS           5
/** errors.go:49-64 — `ErrVerificationFailed{From, To, Reason}`; `from`,
 *  `to`, and `reason` says which nested field carries the Reason. */
#define CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED       6
/** A BARE verifier error (not wrapped in ErrVerificationFailed), carried
 *  in `verify`: verifySkipping's ErrNewValSetCantBeTrusted at :758 (Q2),
 *  and backwards' VerifyBackwards error (ErrInvalidHeader) at :962 / :969. */
#define CMT_LIGHT_CLIENT_ERR_VERIFIER                  7
/** A provider error, `provider` carrying it: `lightBlockFromPrimary`'s
 *  `lastError` (:1126), returned unwrapped by checkTrustedHeaderUsingOptions
 *  (`return err`, :308-310) and initializeWithTrustOptions (:364-367); and
 *  backwards' fetch failure (:945-946), which the reference wraps with
 *  `fmt.Errorf("…: %w")` — the wrapped error is what is carried. */
#define CMT_LIGHT_CLIENT_ERR_PROVIDER                  8
/** initializeWithTrustOptions: the primary's block fails ValidateBasic
 *  (:372-374). */
#define CMT_LIGHT_CLIENT_ERR_INVALID_LIGHT_BLOCK       9
/** initializeWithTrustOptions: "expected header's hash %X, but got %X"
 *  (:376-378). */
#define CMT_LIGHT_CLIENT_ERR_HASH_MISMATCH             10
/** initializeWithTrustOptions: "invalid commit" (:380-384); `verify.reason`
 *  carries the cmt_vs_error_t. */
#define CMT_LIGHT_CLIENT_ERR_INVALID_COMMIT            11
/** errors.go:78-88 — `ErrConflictingHeaders`; `witness_index`. */
#define CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS       12
/** errors.go:90-104 — `ErrProposerPrioritiesDiverge`, by the full-vector
 *  comparison of K25-3; `witness_index`. */
#define CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE 13
/** Item 9 R6 — fewer distinct agreeing identities than
 *  `min_init_agreement`; `agreeing` is the count. PROJECT. */
#define CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT      14
/** compareWithLatestHeight "no headers exist" (:417-419). */
#define CMT_LIGHT_CLIENT_ERR_NO_HEADERS                15
/** compareWithLatestHeight "unverified header/valset requested"
 *  (:422-423). */
#define CMT_LIGHT_CLIENT_ERR_UNVERIFIED_HEIGHT         16
/** "negative height" (:426-427) and "negative or zero height"
 *  (:475-477). */
#define CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT                17
/** store.ErrLightBlockNotFound returned by the client: TrustedLightBlock
 *  (:409), restoreTrustedLightBlock (:274-277), LightBlockBefore in the
 *  between case (:597-600). */
#define CMT_LIGHT_CLIENT_ERR_NOT_FOUND                 18
/** A store call that returned CMT_REJECT (an unreadable row,
 *  cmt_light_store.h D7). */
#define CMT_LIGHT_CLIENT_ERR_STORE                     19
/** "refused to remove the stored light blocks despite hashes mismatch"
 *  (:353). */
#define CMT_LIGHT_CLIENT_ERR_REFUSED_CLEANUP           20
/** errors.go:66-72 — `ErrLightClientAttack` (detector.go:278, :288): a
 *  witness's conflicting header verified; `witness_index` is that
 *  witness and the LOCAL RECORD is `cmt_light_client_attack_record`.
 *  Nothing was sent to any provider (cmt_light_detector.h DD4). (Code 21
 *  was DETECTOR_NOT_IMPLEMENTED until package 3.) */
#define CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK       21
/** detector.go:29-31 — "nil or single block primary trace" (Q2). */
#define CMT_LIGHT_CLIENT_ERR_SHORT_TRACE               22
/** D3 caps. PROJECT. A cap reached inside the detector is returned as
 *  well (cmt_light_detector.h DD5). */
#define CMT_LIGHT_CLIENT_ERR_CAP_TRACE                 23
#define CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS          24
#define CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE        25
#define CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS       26
/** errors.go:43-47 — `ErrFailedHeaderCrossReferencing` (detector.go:
 *  108-109): no witness returned the same block. */
#define CMT_LIGHT_CLIENT_ERR_FAILED_HEADER_CROSS_REFERENCING 27
/** cmt_light_detector.h DD2 — a witness is behind where the reference
 *  sleeps (detector.go:164-168): call again, for the same target, with a
 *  `now` at least 2*max_clock_drift + max_block_lag later (Update keeps
 *  that target by itself, D21). PROJECT. */
#define CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND            28
/** D20 (K25-10) — an attack was detected and not yet cleared by the
 *  operator: the client verifies and saves nothing. PROJECT. */
#define CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED             29

/** Which nested field carries ErrVerificationFailed's Reason. */
#define CMT_LIGHT_CLIENT_REASON_NONE           0
#define CMT_LIGHT_CLIENT_REASON_VERIFIER       1  /* `verify`           */
#define CMT_LIGHT_CLIENT_REASON_PROVIDER       2  /* `provider`         */
#define CMT_LIGHT_CLIENT_REASON_NO_WITNESSES   3  /* ErrNoWitnesses     */
/** D9 — the header backwards reached is not the target. PROJECT. */
#define CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH 4

/**
 * The client's error values, as one out-parameter (the pattern of
 * `cmt_light_error_t`, cmt_light_verifier.h:189-213). On CMT_OK and on
 * CMT_FAULT `code` is CMT_LIGHT_CLIENT_ERR_NONE. Error TEXT is not
 * carried.
 */
typedef struct {
    int                        code;          /* CMT_LIGHT_CLIENT_ERR_*  */
    int64_t                    from;          /* VERIFICATION_FAILED     */
    int64_t                    to;            /* VERIFICATION_FAILED     */
    int                        reason;        /* CMT_LIGHT_CLIENT_REASON_* */
    cmt_light_error_t          verify;        /* the verifier's error    */
    cmt_light_provider_error_t provider;      /* the provider's error    */
    size_t                     witness_index; /* WRONG_CHAIN, CONFLICTING,
                                                 DIVERGE, LIGHT_CLIENT_ATTACK */
    size_t                     agreeing;      /* INIT_AGREEMENT_SHORT    */
} cmt_light_client_error_t;

/** The local record of a detected attack (cmt_light_detector.h DD3);
 *  its fields are declared there. */
typedef struct cmt_light_attack_record cmt_light_attack_record_t;

/* ══ light/client.go:128-264 — the client and its constructors ════════ */

typedef struct cmt_light_client cmt_light_client_t;

/**
 * cometbft@v0.38.26 light/client.go:164-207 — `NewClient()`.
 *
 * TrustOptions.ValidateBasic (:183-185); NewClientFromTrustedStore with
 * `trust->period` (:187-190); if the store already trusts a block,
 * checkTrustedHeaderUsingOptions (:192-197, :285-358); if it then trusts
 * none, or one below `trust->height`, initializeWithTrustOptions
 * (:199-204, :360-393) with the agreement rule of item 9 (file header).
 * No `now`: the reference checks no time at init (:369-371).
 *
 * @param witnesses at least one (:242-244); visited in index order.
 * @param store copied; its ctx must outlive the client.
 * @param out receives the client; free it with cmt_light_client_free.
 * @param err may be NULL.
 * @return CMT_OK; CMT_REJECT with `err->code` — ATTACK_LOCKED when the
 *         store holds an uncleared attack record (D20); CMT_FAULT on NULL,
 *         an allocation failure, or a provider / store CMT_FAULT (D6).
 */
int cmt_light_client_new(const uint8_t *chain_id, size_t chain_id_len,
                         const cmt_light_trust_options_t *trust,
                         const cmt_light_client_peer_t *primary,
                         const cmt_light_client_peer_t *witnesses,
                         size_t n_witnesses,
                         const cmt_light_store_t *store,
                         const cmt_light_client_options_t *opts,
                         cmt_light_client_t **out,
                         cmt_light_client_error_t *err);

/**
 * cometbft@v0.38.26 light/client.go:209-264 — `NewClientFromTrustedStore()`:
 * the options (:237-239, plus the D3 / item-9 domain checks), at least one
 * witness (:242-244), every witness on `chain_id` (:246-252, Q4),
 * ValidateTrustLevel (:254-257), and restoreTrustedLightBlock (:259-261,
 * :266-283). `trusting_period` is the caller's (K25-2); like the
 * reference, it is not range-checked here. Every store row is required,
 * the three attack-record rows included (cmt_light_store.h D9). The
 * client starts LOCKED when the store holds an uncleared attack record
 * (D20); this constructor writes nothing, so it is the one an operator
 * uses to inspect and clear.
 * @return as for cmt_light_client_new (never ATTACK_LOCKED).
 */
int cmt_light_client_new_from_trusted_store(
        const uint8_t *chain_id, size_t chain_id_len,
        int64_t trusting_period,
        const cmt_light_client_peer_t *primary,
        const cmt_light_client_peer_t *witnesses, size_t n_witnesses,
        const cmt_light_store_t *store,
        const cmt_light_client_options_t *opts,
        cmt_light_client_t **out,
        cmt_light_client_error_t *err);

/** Free the client and everything it owns. NULL is a no-op. The store
 *  and the providers are the caller's and are not closed. */
void cmt_light_client_free(cmt_light_client_t *c);

/* ══ light/client.go:395-610 — queries and verification ═══════════════ */

/**
 * cometbft@v0.38.26 light/client.go:395-410 — `TrustedLightBlock(height)`
 * ("0 - the latest"), through compareWithLatestHeight (:412-431, Q8).
 * @return CMT_OK with the block in `out`; CMT_REJECT with NO_HEADERS,
 *         UNVERIFIED_HEIGHT, BAD_HEIGHT, NOT_FOUND or STORE; CMT_FAULT.
 */
int cmt_light_client_trusted_light_block(cmt_light_client_t *c,
                                         int64_t height,
                                         cmt_light_block_buf_t *out,
                                         cmt_light_client_error_t *err);

/** client.go:830-836 — `LastTrustedHeight()`; -1 when none. */
int cmt_light_client_last_trusted_height(cmt_light_client_t *c,
                                         int64_t *out);

/** client.go:838-844 — `FirstTrustedHeight()`; -1 when none. */
int cmt_light_client_first_trusted_height(cmt_light_client_t *c,
                                          int64_t *out);

/**
 * cometbft@v0.38.26 light/client.go:433-462 — `Update(now)`: "attempts to
 * advance the state by downloading the latest light block and verifying
 * it". No trusted block (:442-445) or a latest block not above the trusted
 * one (:461): CMT_OK with `*advanced = false`. Otherwise the block is
 * verified (:453), the detector included (file header), and saved.
 * While locked (D20): CMT_REJECT with ATTACK_LOCKED, before any read.
 * While a wait is recorded (D21): WITNESS_BEHIND until it has run, then
 * the STORED target block, not the latest, is verified and saved.
 * @param out receives the new block when `*advanced` is true.
 */
int cmt_light_client_update(cmt_light_client_t *c, cmt_time_t now,
                            cmt_light_block_buf_t *out, bool *advanced,
                            cmt_light_client_error_t *err);

/**
 * cometbft@v0.38.26 light/client.go:464-494 — `VerifyLightBlockAtHeight`:
 * `height <= 0` is BAD_HEIGHT (:475-477); a block already trusted is
 * returned as is (:479-485, D11); otherwise it is fetched from the primary
 * (:487-491) and verified (:493, `verifyLightBlock` :558-610): forwards
 * from the latest trusted block, backwards from the first, or between,
 * from the closest trusted block below it. On success it is saved and the
 * store pruned (`updateTrustedLightBlock`, :910-928). `out` holds the
 * block on CMT_OK only (D10). While locked (D20): CMT_REJECT with
 * ATTACK_LOCKED, before any read. A recorded wait for this height pins
 * its stored block (D21).
 */
int cmt_light_client_verify_light_block_at_height(cmt_light_client_t *c,
                                                  int64_t height,
                                                  cmt_time_t now,
                                                  cmt_light_block_buf_t *out,
                                                  cmt_light_client_error_t *err);

/** client.go:871-877 — `Cleanup()`: forgets the trusted block and prunes
 *  the store to zero. CMT_REJECT, changing nothing, while locked (D20). */
int cmt_light_client_cleanup(cmt_light_client_t *c);

/**
 * The record of the LAST attack THIS client object found (a call that
 * returned CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK), owned by the client;
 * a later attack replaces it, cmt_light_client_free frees it. NULL when
 * none was found, or on NULL. Its fields: cmt_light_detector.h. It was
 * sent nowhere (DD4). Every record is also in the store, durably, when
 * its `durable` is true (D20; cmt_light_store_db_attack_record reads
 * them back). PROJECT (the reference returns the error only and sends
 * the evidence, detector.go:258, :286).
 */
const cmt_light_attack_record_t *
cmt_light_client_attack_record(const cmt_light_client_t *c);

/** D20 — true while an attack is not cleared (found by this client, or
 *  loaded from the store at construction). False on NULL. */
bool cmt_light_client_attack_locked(const cmt_light_client_t *c);

/**
 * D20 — the operator's clear: every attack record in the store becomes
 * cleared (none is deleted) and the client unlocks. The in-memory record
 * (cmt_light_client_attack_record) stays readable. Calling it unlocked is
 * CMT_OK. A record not yet written to the store is written first (D20).
 * @return CMT_OK; CMT_REJECT while that record still cannot be written
 *         (the client stays locked); CMT_FAULT on NULL or a store failure
 *         of the clear (the client stays locked).
 */
int cmt_light_client_attack_clear(cmt_light_client_t *c);

/* ══ the providers (client.go:853-869, by identity) ═══════════════════ */

/** The number of witnesses (`len(c.Witnesses())`). 0 on NULL. */
size_t cmt_light_client_witness_count(const cmt_light_client_t *c);

/** The primary's identity bytes (owned by the client). CMT_FAULT on
 *  NULL. */
int cmt_light_client_primary_id(const cmt_light_client_t *c,
                                const uint8_t **id, size_t *id_len);

/** Witness `i`'s identity bytes. CMT_REJECT for `i` out of range. */
int cmt_light_client_witness_id(const cmt_light_client_t *c, size_t i,
                                const uint8_t **id, size_t *id_len);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_CLIENT_H */
