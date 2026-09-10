/**
 * @file shared/dnac/cmt_state.h
 * @brief cometbft @709fd12b `state/state.go` ported to C — the committed
 *        state, the block constructor and BFT-time's median.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-D of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only. The live witness BFT,
 * QC V2 and the T3 wave-1 modules are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS ──────────────────────────────────────────────────
 * `State` is "a short description of the latest committed block" (:40-46):
 * everything needed to validate the NEXT one. Three of its functions
 * matter to consensus and are here:
 *   · `MakeBlock` (:234-263)     — the only path that builds a block;
 *   · `MedianTime` (:269-286)    — BFT-time's block time (D-20, D-19 rev 6
 *                                  item 9);
 *   · `MakeGenesisState` (:317-355) — where a chain begins.
 * `Copy` (:83-106) and `IsEmpty` (:129-131) come with them.
 *
 * ── THE ONE CLOCK, AND IT IS NOT READ HERE ─────────────────────────────
 * `MedianTime` READS NO CLOCK. It is a pure function of the previous
 * commit's timestamps and the validator set that produced them — that is
 * the whole point of BFT-time (D-20, atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19;
 * clock POLICY atlas-dec-4ac0423068085c100fdfa3e264ca16bc). `MakeBlock`
 * reads no clock either; it takes the median.
 *
 * The single clock-touching path in this file is `MakeGenesisState`, and
 * only indirectly: it calls `ValidateAndComplete` (:318), whose zero-time
 * branch (types/genesis.go:101-103) consults `cmttime.Now()`. That reaches
 * the host through the `cmt_now_fn` callback this module THREADS THROUGH
 * and never calls itself. D-18 rev 2 makes `genesis_time` mandatory on
 * this chain, so the branch is never taken here; with no callback it is a
 * FAULT, and a time is never invented.
 *
 * ⚠ A NOTE ON D-20's WORDING, because the two texts differ. D-20 rev 2
 * clause (5) describes the median as "the reference's WeightedMedian walk
 * with WEIGHT 1 over the non-ABSENT entries". The reference weights each
 * entry by its validator's VOTING POWER (state.go:280-281,
 * `NewWeightedTime(commitSig.Timestamp, validator.VotingPower)`). This
 * port follows the REFERENCE, because D-19 rev 6 — approved later, on
 * 2026-09-09 — says "everything about blocks, headers, identities and
 * commits follows the pinned reference exactly" and its item (9) names
 * `state/state.go:269` as the definition. D-20's phrasing described a
 * mapping onto the older byte layout that D-19 rev 6 withdrew. The
 * difference is reported in the wave report; it is not resolved here.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function is a pure function of its arguments, except the genesis
 * clock branch above. No randomness, no map iteration, no floating point,
 * no allocation. `MedianTime`'s ordering is `cmt_weighted_median`'s, which
 * is a STABLE sort where the reference's `sort.Slice` is unstable — see
 * cmt_time.h's note; two DNA nodes therefore always agree with each other,
 * and with Go wherever Go is itself well-defined.
 *
 * ── Storage: the caller's, and bound explicitly ────────────────────────
 * A `cmt_state_t` carries THREE validator sets, each of which needs
 * storage for up to CMT_VALSET_MAX validators — over a megabyte in total,
 * since a validator carries a 2592-byte key. Nothing here allocates. The
 * caller supplies one `cmt_state_storage_t` per state (heap, never a stack
 * object) and `cmt_state_init` records it WITHOUT binding the sets; the
 * sets are bound by `cmt_state_make_genesis` and `cmt_state_copy`. That is
 * not a detail — it is what makes `IsEmpty` exact; see there.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · :109-112 `Equals`, :116-126 `Bytes`, :134-175 `ToProto`,
 *     :178-226 `FromProto` — taşınmadı: R2 STORE. All four go through
 *     `cmtstate.State`, a message of `proto/tendermint/state/types.proto`,
 *     which cmt_pb does not implement (it is on K-1's list but outside
 *     wave R1's scope). They persist and compare a state; nothing in
 *     consensus hashes one.
 *   · :295-301 `MakeGenesisStateFromFile`, :304-314 `MakeGenesisDocFromFile`
 *     — HOST: `os.ReadFile` plus JSON. What they wrap,
 *     `MakeGenesisState`, is here.
 *   · :20-22 `stateKey` — a database key; R2 store.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   state/state.go       355 lines
 *     02dc0f209451d28202e1cc25c901af29eb48ca6e83ec5b8a69d88be10b1472fc
 *   types/test_util.go   123 lines
 *     32333c3ef6fb373706e8d7d6b87723c08d9c5b35d0b23094eb42178a8ae8caf2
 *   version/version.go    21 lines
 *     76dd0813d4e0b20117f72569c72c8f1e802d1af3266f204485fd9ace989faf79
 *     ⚠ version/version.go is NOT in the map's pin table (pin rev 5 is
 *       pending); wave R1-B opened it for the same constant and reported
 *       it as an unpinned dependency. Reported again here.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * D-20 (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19),
 * D-18 rev 2 (atlas-dec-4e84dbb5629353b78af6d04d704bd744),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_STATE_H
#define SHARED_DNAC_CMT_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_time.h"
#include "cmt_pb.h"
#include "cmt_block.h"
#include "cmt_params.h"
#include "cmt_genesis.h"
#include "cmt_validator_set.h"
#include "cmt_merkle.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cometbft@709fd12b version/version.go:6 — `TMCoreSemVer`, the string
 * `InitStateVersion.Software` is set from (state.go:35).
 *
 * ⚠ QUESTION FOR THE OPERATOR, deliberately left as the reference's value.
 * This is the only field of `State` that names a SOFTWARE build rather
 * than a protocol, and it is the reference's own version, not this
 * chain's. Should a DNA node write "0.38.19" here, or its own
 * NODUS_VERSION_* string?
 *
 * IT IS NOT CONSENSUS-CRITICAL, and that can be checked rather than
 * assumed: `Header.Version` is a `cmtversion.Consensus` carrying only
 * {Block, App} (types/block.go:331, cmt_pb.h `cmt_pb_consensus_t`), so the
 * Software string is not in the header, not in a leaf of Header.Hash
 * (block.go:445-479) and not in any other hashed structure. It reaches
 * only `cmtstate.State` (state.go:141), which is store-only and taşınmadı.
 * So the answer changes what a node writes in its own database and nothing
 * two nodes must agree on.
 */
#define CMT_SOFTWARE_VERSION "0.38.19"   /* QUESTION — see above */

/** The longest software version string a state stores, including the NUL. */
#define CMT_STATE_SOFTWARE_MAX 32

/** cometbft@709fd12b proto/tendermint/state/types.proto — `Version`, the
 *  shape `InitStateVersion` (state.go:30-36) fills. */
typedef struct {
    cmt_pb_consensus_t consensus;                 /* state.go:31-34 */
    char               software[CMT_STATE_SOFTWARE_MAX];  /* :35     */
} cmt_state_version_t;

/**
 * The validator storage one `cmt_state_t` needs.
 *
 * ⚠ NEVER A STACK OBJECT — three sets of CMT_VALSET_MAX validators, each
 * carrying a 2592-byte public key, is over a megabyte. The precedent is
 * `cmt_valset_scratch_t` (cmt_validator_set.h:238-245) and
 * `vset_wire.h:128-139`. The caller owns it and its lifetime; this module
 * never allocates and never frees.
 *
 * It is one struct rather than three parameters so that a caller cannot
 * supply two of the three and silently get a short buffer.
 */
typedef struct {
    cmt_validator_t next_validators[CMT_VALSET_MAX];   /* state.go:65 */
    cmt_validator_t validators[CMT_VALSET_MAX];        /* :66         */
    cmt_validator_t last_validators[CMT_VALSET_MAX];   /* :67         */
} cmt_state_storage_t;

/**
 * cometbft@709fd12b state/state.go:47-80 — `type State struct`.
 *
 * Field for field, in the reference's order. Two representation notes:
 *
 *  · `AppHash` and `LastResultsHash` are Go `[]byte` slices; here they are
 *    fixed 64-byte arrays with an explicit length, because a hash that
 *    arrived from somewhere may be EMPTY (the genesis AppHash usually is,
 *    and `Header.ValidateBasic` deliberately does not length-check
 *    AppHash, block.go:431) and a decoder that dropped the length could
 *    not say so.
 *
 *  · the three validator sets are held BY VALUE, and their own
 *    `validators` pointers are bound into `storage` — see `IsEmpty`.
 */
typedef struct {
    cmt_state_version_t  version;                      /* state.go:48 */

    uint8_t              chain_id[CMT_PB_CHAINID_MAX]; /* :51         */
    size_t               chain_id_len;
    int64_t              initial_height;               /* :52         */

    int64_t              last_block_height;            /* :55         */
    cmt_block_id_t       last_block_id;                /* :56         */
    cmt_time_t           last_block_time;              /* :57         */

    cmt_validator_set_t  next_validators;              /* :65         */
    cmt_validator_set_t  validators;                   /* :66         */
    cmt_validator_set_t  last_validators;              /* :67         */
    int64_t              last_height_validators_changed;        /* :68 */

    cmt_consensus_params_t consensus_params;           /* :72         */
    int64_t              last_height_consensus_params_changed;  /* :73 */

    uint8_t              last_results_hash[CMT_PB_HASH_MAX];    /* :76 */
    size_t               last_results_hash_len;
    uint8_t              app_hash[CMT_PB_HASH_MAX];             /* :79 */
    size_t               app_hash_len;

    /** The caller's storage. NOT a reference field — it is how this
     *  representation carries what Go's garbage collector carries. */
    cmt_state_storage_t *storage;
} cmt_state_t;

/**
 * The working storage `cmt_state_make_block` needs for the two validator
 * set hashes. ⚠ NEVER A STACK OBJECT: the leaf buffer alone is
 * CMT_VALSET_MAX * CMT_VALIDATOR_BYTES_MAX ≈ 334 KB.
 *
 * `MedianTime` needs NO scratch: its two arrays are at most
 * CMT_VALSET_MAX entries of 16 and 8 bytes, a few kilobytes, and they live
 * on its own stack frame.
 */
typedef struct {
    uint8_t           leaves[(size_t)CMT_VALSET_MAX *
                             (size_t)CMT_VALIDATOR_BYTES_MAX];
    cmt_merkle_item_t items[CMT_VALSET_MAX];
} cmt_state_block_scratch_t;

/**
 * Bind `storage` to `state` and zero everything else.
 *
 * It does NOT bind the three validator sets: after this call each set's
 * `validators` pointer is NULL, which is the reference's nil and which
 * `IsEmpty` reports as empty. `cmt_state_make_genesis` and
 * `cmt_state_copy` bind them.
 *
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_state_init(cmt_state_t *state, cmt_state_storage_t *storage);

/**
 * cometbft@709fd12b state/state.go:129-131 — `(state State) IsEmpty()`.
 *
 * The reference is `state.Validators == nil`, with its own comment "XXX
 * can't compare to Empty". Here it is `state->validators.validators ==
 * NULL`, and that is EXACT rather than approximate — which is the reason
 * `cmt_state_init` leaves the sets unbound.
 *
 * The distinction it preserves is real and easy to lose: a state built by
 * `MakeGenesisState` from a document with NO validators has a set that is
 * EMPTY BUT NOT NIL (state.go:325 `NewValidatorSet(nil)`), so it is NOT
 * empty by this test, while a zeroed state is. Binding the storage at init
 * would have made the two indistinguishable.
 *
 * @return true for a NULL state as well — the reference has no such case,
 *         and "nothing" is empty.
 */
bool cmt_state_is_empty(const cmt_state_t *state);

/**
 * cometbft@709fd12b state/state.go:83-106 — `(state State) Copy()`.
 *
 * A deep copy: the three sets go through `cmt_validator_set_copy` into
 * `dst`'s OWN storage, and every scalar is assigned.
 *
 * NOTE on the two hashes: `AppHash` and `LastResultsHash` are Go slices,
 * so the reference's copy SHARES their backing arrays (:102, :104) while
 * this copies the bytes. Value semantics are identical, because nothing in
 * the reference mutates a hash in place; the difference is only that a C
 * copy cannot alias.
 *
 * A set that is nil in `src` is left nil in `dst` — the reference would
 * nil-dereference on `state.Validators.Copy()` (:94-96), so an empty
 * source state is not a case the reference reaches, and this port refuses
 * it rather than inventing an answer.
 *
 * @param dst must already be `cmt_state_init`ialised with its own storage,
 *        which MUST NOT be `src`'s.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL, on missing storage, or on
 *         a source state that is empty.
 */
int cmt_state_copy(const cmt_state_t *src, cmt_state_t *dst);

/**
 * cometbft@709fd12b state/state.go:269-286 — `MedianTime()`.
 *
 * THE BLOCK TIME OF BFT-TIME (D-20; D-19 rev 6 item 9). The weighted
 * median of the previous commit's vote timestamps, weighted by each
 * signer's VOTING POWER — see the file header on D-20's differing wording.
 *
 * The walk, line by line. An array of `len(commit.Signatures)` entries is
 * built (:270) and left with HOLES: an ABSENT entry is skipped (:274-276)
 * and so is a signer the set does not contain (:277-279 — the reference's
 * own comment says the nil test is there because a test panicked without
 * it, "not needed normally"). Only the signers that were FOUND add to the
 * total (:280). `cmt_weighted_median` (cmt_time.h:191) then does the rest,
 * and it takes exactly such a NULL-holed pointer array.
 *
 * ⚠ THE LOOKUP IS BY ADDRESS (:277 `validators.GetByAddress`), not by
 * index — unlike `verifyCommitSingle`'s main path. A commit entry whose
 * address is not in the set contributes nothing at all, silently.
 *
 * ⚠ REORDERING: `cmt_weighted_median` sorts its pointer array in place,
 * exactly as the reference's `sort.Slice` (time/time.go:38) reorders the
 * fresh slice built at :270. Both arrays are local here, so no caller sees
 * it.
 *
 * If nothing is selected — an empty commit, all-absent entries, no signer
 * in the set — the result is Go's ZERO TIME, i.e. CMT_TIME_ZERO and NOT
 * the Unix epoch (time/time.go:35 never assigns `res`).
 *
 * @param vals NOT const: `GetByAddress` is declared on a const set, but
 *        the type's caches make a const state awkward; the set is not
 *        modified.
 * @return CMT_OK; CMT_REJECT if the commit carries more than
 *         CMT_VALSET_MAX signatures (a capacity rule of this port, added
 *         so the arrays need no allocation — the reference sizes them
 *         dynamically); CMT_FAULT on NULL.
 */
int cmt_state_median_time(const cmt_commit_t *commit,
                          const cmt_validator_set_t *vals,
                          cmt_time_t *out);

/**
 * cometbft@709fd12b state/state.go:234-263 — `(state State) MakeBlock()`.
 *
 * THE ONLY PATH THAT BUILDS A BLOCK. Three steps, the reference's:
 *  1. `types.MakeBlock(height, txs, lastCommit, evidence)` (:243) —
 *     `cmt_make_block` (cmt_block.h:771), which ends in fillHeader;
 *  2. the TIMESTAMP (:246-251): at `state.InitialHeight` it is
 *     `state.LastBlockTime`, which for a genesis state IS the genesis time
 *     (:343); at every other height it is `MedianTime(lastCommit,
 *     state.LastValidators)`;
 *  3. `block.Populate(...)` (:254-260) with the two set hashes, the
 *     consensus params hash, AppHash, LastResultsHash and the proposer.
 *
 * ⚠ A NULL `last_commit` at a height other than InitialHeight is CMT_FAULT:
 * the reference would nil-dereference inside MedianTime (:270
 * `commit.Signatures`). Step 1 accepts a NULL LastCommit — `MakeBlock`
 * does — so the refusal is specifically about step 2 needing one.
 *
 * @param proposer_address the round's proposer; the state does not track
 *        rounds, which is why the reference takes it as a parameter
 *        (:232-233 and its TODO).
 * @param scratch the leaf storage the two `cmt_validator_set_hash` calls
 *        need; never a stack object.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_state_make_block(const cmt_state_t *state,
                         int64_t height,
                         const cmt_data_t *data,
                         cmt_commit_t *last_commit,
                         const cmt_evidence_data_t *evidence,
                         const uint8_t *proposer_address,
                         size_t proposer_address_len,
                         cmt_state_block_scratch_t *scratch,
                         cmt_block_t *out);

/**
 * cometbft@709fd12b state/state.go:317-355 — `MakeGenesisState()`.
 *
 * Where a chain begins. `genDoc.ValidateAndComplete()` first (:318), then
 * the sets, then every field of the initial State.
 *
 * ⚠ THE ADDRESSES ARE DERIVED, NOT READ. Each validator is built with
 * `NewValidator(val.PubKey, val.Power)` (:330), which derives the address
 * from the key; the document's own `Address` field is never copied in.
 * `ValidateAndComplete` has already checked that a document that GAVE an
 * address gave the right one (genesis.go:93-95) and filled one in where it
 * did not (:96-98).
 *
 * ⚠ `Validators` and `NextValidators` DIFFER: the next set is the same
 * validators after `CopyIncrementProposerPriority(1)` (:333), so the
 * proposer for the block after genesis is already elected.
 *
 * NOTE reference behaviour at :324, `genDoc.Validators == nil`. In Go a
 * NIL slice takes the two-empty-sets branch (:325-326) while an EMPTY but
 * non-nil slice takes the other one — and that one PANICS: :333 calls
 * `CopyIncrementProposerPriority(1)` unguarded, and
 * `IncrementProposerPriority` panics on an empty set
 * (validator_set.go:132-134). This representation CAN tell the two apart,
 * and does: `gen_doc->validators == NULL` is the nil slice and takes the
 * nil branch; a non-NULL `validators` with `validators_len == 0` is the
 * empty slice, takes the other branch, and is REJECTED where the
 * reference panics (INVARIANT 7495d337) — by the port's own
 * `cmt_validator_set_increment_proposer_priority`, at the same check.
 * A NULL list with a non-zero count is CMT_FAULT (not a Go value at all).
 *
 * @param now may be NULL; consulted only for a zero genesis time, which
 *        D-18 rev 2 forbids on this chain. Never invented.
 * @param scratch the change-set storage `NewValidatorSet` needs.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_state_make_genesis(cmt_genesis_doc_t *gen_doc,
                           cmt_now_fn now, void *now_ctx,
                           cmt_valset_scratch_t *scratch,
                           cmt_state_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_STATE_H */
