/**
 * @file shared/dnac/cmt_light_client.h
 * @brief cometbft @v0.38.26 `light/client.go` and `light/trust_options.go`
 *        ported to C — the light client that moves its trust forwards
 *        (sequential or skipping verification), between and backwards,
 *        over a primary provider, a list of witnesses and a light store.
 *
 * ═══ STATUS: NO PRODUCTION CALLER — AND IT CANNOT ADVANCE YET ═══════════
 * Package 2 of the light client (Kurultay #25 item 1, docs/plans/
 * decisions/2026-10-16-kurultay-25-summary.md: "LightBlock + ValidateBasic
 * → store → client → detector"). Nothing in a node opens a client yet.
 *
 * ⚠ THE DETECTOR IS NOT PORTED (it is package 3, Kurultay #25 item 2).
 * The reference calls `detectDivergence` after every FORWARD and every
 * BETWEEN verification (client.go:691-696 in verifySequential, :815-822
 * in verifySkippingAgainstPrimary). Here that call goes to ONE named hook
 * (`detect_divergence` in cmt_light_client.c) which, until package 3
 * lands, returns CMT_REJECT with code
 * CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED. It FAILS CLOSED: the
 * block that was verified is NOT saved, `Update` does not advance, and the
 * caller sees the error. The hook is not a caller-installable pointer, so
 * no caller can make it succeed. Consequence today: only initialisation
 * (which does not reach the detector, :360-393) and BACKWARDS verification
 * (:586-592 → `backwards`, :933-979, which does not reach it either) can
 * add a block to the store.
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
 *      142-197): item 9 compares at the same height, and that lagging-
 *      witness logic is the detector's (package 3).
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
 *     Astra (Kurultay #25) flagged the unbounded trace: each entry is a
 *     full light block (`cmt_light_block_buf_t`, above one megabyte).
 *  D4 The two recursions — verifySkippingAgainstPrimary calling itself
 *     after a replacement (:813) and backwards calling itself (:973) — are
 *     loops here, bounded by the caps of D3.
 *  D5 The detector hook (STATUS above) — fails closed.
 *  D6 CMT_FAULT is not a Go error value: a provider or store call that
 *     returns CMT_FAULT ends the operation with CMT_FAULT. It never
 *     triggers a primary replacement or a witness removal (the CMT_FAULT
 *     contract, cmt_tmhash.h:105-110: "a caller MUST NOT count -2 as …
 *     invalid input").
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
 *     CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH). This TIGHTENS the
 *     reference and needs the operator's word to stay (recorded for the
 *     ORCHESTRATOR).
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
 *     `MaxBlockLag` (:122) is stored for the detector (its only reader is
 *     detector.go:168).
 *  D13 `ConfirmationFunction(fn func(action string) bool)` (:85) becomes
 *     a callback that receives an action CODE and two heights; no text.
 *     NULL is the reference default "No confirmation is required" (:232).
 *  D14 `Logger` (:92) is the QGP_LOG macros; `quit` (:159) has no reader
 *     in client.go and is not ported; `providerMutex` (:143) is not ported
 *     — the client has ONE owner on one event loop and is NOT thread-safe.
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
 *     Here: CMT_LIGHT_CLIENT_ERR_SHORT_TRACE from the hook, whose first
 *     line ports detector.go:29-31.
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
 *  · detector.go — package 3 (the hook above).
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
 *   light/detector.go:28-31  (the first line of detectDivergence, Q2)
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
/** A provider error passed through unwrapped: `lightBlockFromPrimary`'s
 *  `lastError` (:1126), and the wrapped fetch failures of backwards
 *  (:945-946) and checkTrustedHeaderUsingOptions (:307-310). `provider`
 *  carries it. */
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
/** THE DETECTOR HOOK (D5): package 3 is not ported. `trace_len`,
 *  `trace_from`, `trace_to` describe the trace it was given. */
#define CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED  21
/** detector.go:29-31 — "nil or single block primary trace" (Q2). */
#define CMT_LIGHT_CLIENT_ERR_SHORT_TRACE               22
/** D3 caps. PROJECT. */
#define CMT_LIGHT_CLIENT_ERR_CAP_TRACE                 23
#define CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS          24
#define CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE        25
#define CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS       26

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
    size_t                     witness_index; /* WRONG_CHAIN, CONFLICTING, DIVERGE */
    size_t                     agreeing;      /* INIT_AGREEMENT_SHORT    */
    size_t                     trace_len;     /* DETECTOR_NOT_IMPLEMENTED */
    int64_t                    trace_from;
    int64_t                    trace_to;
} cmt_light_client_error_t;

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
 * @return CMT_OK; CMT_REJECT with `err->code`; CMT_FAULT on NULL, an
 *         allocation failure, or a provider / store CMT_FAULT (D6).
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
 * reference, it is not range-checked here.
 * @return as for cmt_light_client_new.
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
 * verified (:453) — which, until package 3, ends at the detector hook
 * (file header): CMT_REJECT, DETECTOR_NOT_IMPLEMENTED.
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
 * block on CMT_OK only (D10).
 */
int cmt_light_client_verify_light_block_at_height(cmt_light_client_t *c,
                                                  int64_t height,
                                                  cmt_time_t now,
                                                  cmt_light_block_buf_t *out,
                                                  cmt_light_client_error_t *err);

/** client.go:871-877 — `Cleanup()`: forgets the trusted block and prunes
 *  the store to zero. */
int cmt_light_client_cleanup(cmt_light_client_t *c);

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
