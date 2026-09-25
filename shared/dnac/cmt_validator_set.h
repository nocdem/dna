/**
 * @file shared/dnac/cmt_validator_set.h
 * @brief cometbft @709fd12b `types/validator.go` + `types/validator_set.go`
 *        ported to C — the validator, the set, and proposer selection.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-C of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only. The live witness BFT,
 * QC V2 and the T3 wave-1 modules are byte-identically untouched.
 *
 * THIS MODULE SUPERSEDED the T1 proposer-priority implementation
 * (`nodus/src/bft/tendermint/tm_proposer.c`), which R2 DELETED together
 * with the rest of the T1 core — atlas-dec-a309a65984f1709149b40db9cb5b38a7.
 * The one behavioural difference between them was deliberate and is the
 * deviation register's row J4: the T1 code REFUSED any priority outside
 * ±2^40 where the reference CLIPS to the int64 ends (safeAddClip /
 * safeSubClip, validator_set.go:1011-1031) and bounds the TOTAL VOTING
 * POWER instead (MaxTotalVotingPower = MaxInt64/8, :27). The operator's
 * ruling of 2026-09-09 is "Comet'e dön: kırpma + MaxTotalVotingPower";
 * this module clips and does not repeat J4.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── What is in here ────────────────────────────────────────────────────
 * The set whose Merkle root is ValidatorsHash / NextValidatorsHash
 * (D-19 rev 6 item 5, atlas-dec-d106407a31d7d16d49d51990b75c36c6): the
 * leaves are SimpleValidator{PubKey, VotingPower} marshals
 * (validator.go:118-134) and the set order is ValidatorsByVotingPower —
 * power DESCENDING, address ASCENDING (validator_set.go:851-856,
 * :674/:964). The same set carries the proposer-priority state machine
 * that elects a proposer every round.
 *
 * ── Substitutions (umbrella rev 3, atlas-dec-d5e766defde138eb6dd02e5b81e735a8) ─
 *  · hash SHA3-512 / 64 bytes (cmt_tmhash.h);
 *  · public key ML-DSA-87, 2592 bytes, PublicKey oneof branch 9 (K-2,
 *    atlas-dec-7fde65722d68b32eca08be61fbcb47ac);
 *  · address 32 bytes, not the reference's `crypto.AddressSize` 20
 *    (validator.go:37-57 compares whatever length it is given);
 *  · `math/big` accumulation (validator_set.go:196-209) becomes an
 *    explicit two's-complement 128-bit accumulator — see
 *    cmt_validator_set_compute_avg_proposer_priority;
 *  · a panic becomes a return code — see "Return codes" below;
 *  · lists live in caller-provided storage with an explicit capacity.
 *
 * ── THE ADDRESS IS A PURE FUNCTION OF THE PUBLIC KEY ────────────────────
 * `NewValidator` sets `Address: pubKey.Address()` (validator.go:27-35) and
 * `ValidateBasic` RE-DERIVES it and compares (:49-52). In the reference
 * `Address()` is a truncated hash of the key. In THIS tree the chain
 * already derives a validator's 32-byte identity from its key by exactly
 * that shape:
 *
 *     witness_id = SHA3-512(pubkey)[0..31]
 *
 * — `nodus_chain_config_derive_witness_id`, defined at
 * `nodus/src/witness/nodus_witness_chain_config.c:637-652` and declared at
 * `nodus/include/nodus/nodus_chain_config.h:319-327`, whose body is one
 * EVP SHA3-512 over the 2592-byte key followed by a 32-byte `memcpy`. So
 * `Address()` HAS a counterpart here and is ported as
 * `cmt_pub_key_address` below, computed with this port's own SHA3-512 so
 * that `shared/` keeps no dependency on `nodus/`. Nothing is invented.
 *
 * ✔ RESOLVED IN WAVE R1-D. R1-C recorded here that `cmt_tmhash.h:29-32`
 * claimed a DNA validator identity is "never a truncation of a key hash",
 * and reported it rather than editing that file. R1-D corrected that
 * header in place and moved the truncation into it as `cmt_address_hash`
 * (= `crypto.AddressHash`, crypto/crypto.go:18-20). `cmt_pub_key_address`
 * below is now a one-line delegate that adds only the reference's nil-key
 * rule, and `cmt_pubkey_address` (cmt_vote.h) is the other wrapper: ONE
 * computation of an address in the tree, two typed entry points.
 *
 * ── Return codes (cmt_tmhash.h) ────────────────────────────────────────
 *   CMT_OK      0  accept
 *   CMT_REJECT -1  a deterministic property of the arguments — every
 *                  honest node reaches the same verdict on the same
 *                  values. Every reference panic maps here EXCEPT the one
 *                  below, and every Go index panic becomes an explicit
 *                  bounds check (INVARIANT
 *                  atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *   CMT_FAULT  -2  THIS process could not decide: a NULL argument, a hash
 *                  backend failure, or `updateTotalVotingPower`'s
 *                  MaxTotalVotingPower panic (:319-324). That last one is
 *                  a FAULT and not a verdict because the reachable case is
 *                  already refused by `verifyUpdates` with
 *                  ErrTotalVotingPowerOverflow (:483-485); arriving at the
 *                  panic means the guard in front of it did not hold, i.e.
 *                  an internal inconsistency in this process.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments and the set it
 * is given. No clock is read, no randomness is drawn, no map is iterated,
 * no floating point is used. The two sort orders are TOTAL orders whenever
 * addresses are unique (which is the set's own invariant, enforced by
 * `processChanges`), so any correct sort algorithm produces the one same
 * order; this port uses a deterministic insertion sort, and the places
 * where the reference's unstable `sort.Slice` could differ are analysed at
 * each call site (`cmt_validator_set_process_changes`,
 * `cmt_validator_set_verify_updates`). The 128-bit accumulator is built
 * from explicit 64-bit limbs rather than `__int128`, for the reason
 * `shared/crypto/utils/qgp_u128.h:12-16` gives for its own limbs: the
 * result must not depend on the compiler.
 *
 * ── Capacity ───────────────────────────────────────────────────────────
 * A set holds at most CMT_VALSET_MAX = DNA_MAX_ACTIVE_VALIDATORS = 128
 * (`ledger_ids.h:103`), this release's active-set ceiling. The reference
 * has NO count bound (validator_set.go:74-76 notes only an implied limit
 * via MaxVotesCount), so this is an added rule; it is a CAPACITY rule, it
 * adds no consensus semantics, and it is refused rather than truncated.
 * A change set may legitimately be larger than the resulting set (up to
 * 128 removals plus 128 additions), so CMT_VALSET_MAX_CHANGES is 256.
 *
 * Reference @709fd12b (SHA-256 of each file verified before use):
 *   types/validator.go      194 lines
 *     fe21832f8b1edd6e1f5adc151276efe092c5cf36c750ac2925b3332c097da7aa
 *   types/validator_set.go 1053 lines
 *     6c3a663aaf84fbee94735731eaba27d1a8e5269dd6e316e0b175595e32902221
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * K-2 (atlas-dec-7fde65722d68b32eca08be61fbcb47ac),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * pin rev 4 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_VALIDATOR_SET_H
#define SHARED_DNAC_CMT_VALIDATOR_SET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"    /* CMT_OK / CMT_REJECT / CMT_FAULT, CMT_TMHASH_SIZE */
#include "cmt_merkle.h"    /* cmt_merkle_item_t                               */
#include "cmt_pb.h"        /* cmt_pb_public_key_t, cmt_pb_validator_t, sizes  */
#include "ledger_ids.h"    /* DNA_MAX_ACTIVE_VALIDATORS                       */

#ifdef __cplusplus
extern "C" {
#endif

/* ── constants ──────────────────────────────────────────────────────── */

/** cometbft@709fd12b types/validator_set.go:27 — `MaxTotalVotingPower`,
 *  `math.MaxInt64 / 8`. The ceiling on the SUM of the voting powers; it is
 *  what keeps incrementProposerPriority from clipping and keeps
 *  `(diff + diffMax - 1)` from overflowing (:20-26). */
#define CMT_MAX_TOTAL_VOTING_POWER (INT64_MAX / 8)

/** cometbft@709fd12b types/validator_set.go:32 —
 *  `PriorityWindowSizeFactor`. Multiplied by the total voting power it
 *  gives the maximum allowed distance between two priorities. */
#define CMT_PRIORITY_WINDOW_SIZE_FACTOR 2

/** This release's active-set ceiling — `ledger_ids.h:103`. Added by this
 *  port; the reference has no count bound. See "Capacity" above. */
#define CMT_VALSET_MAX DNA_MAX_ACTIVE_VALIDATORS

/** The largest change set this port accepts: at most CMT_VALSET_MAX
 *  removals plus at most CMT_VALSET_MAX additions. */
#define CMT_VALSET_MAX_CHANGES (2 * CMT_VALSET_MAX)

/**
 * The largest `cmt_validator_bytes()` encoding, derived field by field
 * from K-1 rev 2 and K-2 — SimpleValidator{PubKey POINTER, VotingPower}:
 *
 *   PublicKey body   = tag 0x4a (1) + uvarint(2592) (2) + 2592  = 2595
 *   field 1 (PubKey) = tag 0x0a (1) + uvarint(2595) (2) + 2595  = 2598
 *   field 2 (power)  = tag 0x10 (1) + varint(int64)  (<= 10)    =   11
 *                                                       total    = 2609
 *
 * A negative voting power is the 10-byte two's-complement varint (K-1
 * rev 2 rule g), which is why field 2 is sized at 11 and not at 2.
 */
#define CMT_VALIDATOR_BYTES_MAX 2609

/* ── the validator ──────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b types/validator.go:18-24 — `type Validator struct`.
 *
 * `address_len` exists because the reference's Address is a `[]byte` whose
 * length `ValidateBasic` compares with `bytes.Equal` (:50): a validator
 * carrying a 31-byte address is INVALID, and a decoder that dropped the
 * length could not say so. A validator this module BUILDS always has
 * address_len == CMT_PB_ADDRESS_MAX; one that arrived on the wire has
 * whatever the sender wrote (`cmt_validator_from_proto` copies it, it does
 * not re-derive it — the KODEK rule for validator.go:159-175).
 *
 * ProposerPriority is deliberately NOT part of `cmt_validator_bytes` —
 * the reference's own note at :16-17 and :115-117.
 */
typedef struct {
    uint8_t             address[CMT_PB_ADDRESS_MAX];   /* validator.go:19 */
    size_t              address_len;
    cmt_pb_public_key_t pub_key;                       /* validator.go:20 */
    int64_t             voting_power;                  /* validator.go:21 */
    int64_t             proposer_priority;             /* validator.go:23 */
} cmt_validator_t;

/* ── the set ────────────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b types/validator_set.go:56-65 — `type ValidatorSet`.
 *
 * `validators` is CALLER-OWNED storage: `validators_cap` slots of which
 * `validators_len` are used. Nothing in this module allocates.
 *
 * ⚠ THE PROPOSER IS HELD BY VALUE, and that is a stated difference. The
 * reference's `Proposer` is a `*Validator` that POINTS INTO `Validators`,
 * so `Copy()` (:264-271) copies the pointer and a copy's Proposer aliases
 * the ORIGINAL's validator object — mutating the original's priorities is
 * visible through the copy, and after `applyUpdates` replaces the slice
 * (:570) the pointer may reference a validator no longer in the set. That
 * aliasing is a hazard of Go's representation rather than a designed
 * behaviour, and reproducing it in C with caller-owned storage would mean
 * a pointer that outlives what it points at. So the proposer is a SNAPSHOT
 * taken where the reference assigns the pointer (:152, :346, :931, :962).
 * Everywhere the reference reassigns it before reading it again — which is
 * every path in the production flow, `IncrementProposerPriority` at
 * `state/execution.go:617` following every set change — the two agree
 * exactly. Recorded as a deviation.
 *
 * `total_voting_power` is the reference's lazily recomputed cache
 * (:62, :332-337): a stored 0 means "not computed yet", so a set whose
 * real total is 0 recomputes on every call. Do not write it directly.
 */
typedef struct {
    cmt_validator_t *validators;              /* :58, caller-owned         */
    size_t           validators_cap;
    size_t           validators_len;
    bool             has_proposer;            /* :59, nil when false       */
    cmt_validator_t  proposer;
    int64_t          total_voting_power;      /* :62, cached (0 = unset)   */
    bool             all_keys_have_same_type; /* :64                       */
} cmt_validator_set_t;

/**
 * The working storage `cmt_validator_set_update_with_change_set` needs.
 *
 * ⚠ NEVER A STACK OBJECT — `sizeof` is above one megabyte (256 change
 * copies plus one 128-entry staging set, each validator carrying a
 * 2592-byte public key). The precedent is `vset_wire.h:128-139`, which
 * heap-allocates its 128 entries for the same reason. The caller owns it
 * and its lifetime; the module never allocates and never frees.
 *
 * It is one struct rather than seven parameters so that a caller cannot
 * supply five of the seven and silently get a short buffer.
 */
typedef struct {
    /** The deep copy `processChanges` makes (:410) so that `origChanges`
     *  is not modified and `computeNewPriorities` (:512-530) has something
     *  it may mutate. */
    cmt_validator_t  changes[CMT_VALSET_MAX_CHANGES];
    /** Pointers into `changes`, sorted by address (:411). */
    cmt_validator_t *sorted[CMT_VALSET_MAX_CHANGES];
    /** The split of `sorted` into updates (:435) and removals (:433). */
    cmt_validator_t *updates[CMT_VALSET_MAX_CHANGES];
    cmt_validator_t *removals[CMT_VALSET_MAX_CHANGES];
    /** Pointers into the SET's own storage, sorted by address (:538) —
     *  the reference's `existing`, which IS `vals.Validators`. */
    cmt_validator_t *existing[CMT_VALSET_MAX];
    /** `applyUpdates`' merge target (:540) and `applyRemovals`' (:597).
     *  Big enough for `len(existing) + len(updates)` before the removals
     *  shrink it back. */
    cmt_validator_t *merged[CMT_VALSET_MAX + CMT_VALSET_MAX_CHANGES];
    /** The staging area for `vals.Validators = merged[:i]` (:570, :617).
     *  A C write-back cannot be done in place, because `merged` is a
     *  permutation whose sources live in the destination array. */
    cmt_validator_t  final[CMT_VALSET_MAX];
} cmt_valset_scratch_t;

/* ── errors the reference carries as values ─────────────────────────── */

#define CMT_VS_ERR_NONE                            0
/** cometbft@709fd12b types/validator_set.go:800-805 —
 *  `ErrNotEnoughVotingPowerSigned`. */
#define CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED  1

/**
 * The reference's `ErrNotEnoughVotingPowerSigned` value (:802-805). The
 * 0/-1/-2 return contract cannot carry a payload, so the two numbers the
 * error carries live here.
 *
 * Its producer is the VerifyCommit family (validator_set.go:698-742).
 * R1-C ported this value while that family was still stage D and recorded
 * it as having zero consumers; since wave R1-D it HAS one —
 * `cmt_verify_commit` / `cmt_verify_commit_single` (cmt_validation.h) fill
 * it in whenever a commit is refused for want of voting power, and leave
 * `code` at CMT_VS_ERR_NONE for every other rejection.
 */
typedef struct {
    int     code;     /* CMT_VS_ERR_*   */
    int64_t got;      /* :803           */
    int64_t needed;   /* :804           */
} cmt_vs_error_t;

/** cometbft@709fd12b types/validator_set.go:796-798 —
 *  `IsErrNotEnoughVotingPowerSigned()`. The `errors.As` type test becomes
 *  a code test. */
bool cmt_is_err_not_enough_voting_power_signed(const cmt_vs_error_t *e);

/* ══ int64 arithmetic — validator_set.go:993-1053 ═════════════════════
 * Exposed so the tests can pin the clipping ends directly. Every one is
 * evaluated so that no C signed overflow occurs while the reference's
 * PREDICATE is computed unchanged. */

/** :993-1000 `safeAdd()`. On overflow the reference returns (-1, true) and
 *  this writes that same -1 sentinel, which only safeAddClip reads.
 *  @return true on overflow. `out` must not be NULL. */
bool cmt_vs_safe_add(int64_t a, int64_t b, int64_t *out);

/** :1002-1009 `safeSub()`. Same -1 sentinel on overflow. */
bool cmt_vs_safe_sub(int64_t a, int64_t b, int64_t *out);

/** :1011-1020 `safeAddClip()` — MinInt64 when b < 0, else MaxInt64. */
int64_t cmt_vs_safe_add_clip(int64_t a, int64_t b);

/** :1022-1031 `safeSubClip()` — MinInt64 when b > 0, else MaxInt64. */
int64_t cmt_vs_safe_sub_clip(int64_t a, int64_t b);

/** :1033-1053 `safeMul()`.
 *  NOTE reference quirk: for b == MinInt64 the reference's `absOfB = -b`
 *  wraps back to MinInt64 (Go wraps on overflow), so `absOfB` stays
 *  NEGATIVE and the comparison at :1048 is made against a negative
 *  divisor. Reproduced exactly, including the wrap.
 *  @return true on overflow. */
bool cmt_vs_safe_mul(int64_t a, int64_t b, int64_t *out);

/* ══ validator.go ═════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b types/validator.go:29 — `pubKey.Address()`, resolved
 * for this tree: SHA3-512(key)[0..31]. See "THE ADDRESS IS A PURE
 * FUNCTION OF THE PUBLIC KEY" in the file header for the citation this is
 * taken from and for why it is recomputed here rather than called.
 *
 * Since wave R1-D the computation itself is `cmt_address_hash`
 * (cmt_tmhash.h) = `crypto.AddressHash` (crypto/crypto.go:18-20); this
 * function is the typed wrapper that adds the nil-key rule below.
 *
 * @return CMT_OK; CMT_REJECT when the key is absent (`pk->present` false —
 *         the reference's nil PubKey has no address); CMT_FAULT on NULL or
 *         a hash backend failure.
 */
int cmt_pub_key_address(const cmt_pb_public_key_t *pk,
                        uint8_t out[CMT_PB_ADDRESS_MAX]);

/** cometbft@709fd12b types/validator.go:27-35 — `NewValidator()`. Derives
 *  the address from the key and sets ProposerPriority to 0 (:32).
 *  @return CMT_OK, CMT_REJECT if the key is absent, CMT_FAULT on NULL or a
 *          hash backend failure. */
int cmt_validator_new(const cmt_pb_public_key_t *pub_key,
                      int64_t voting_power, cmt_validator_t *out);

/**
 * cometbft@709fd12b types/validator.go:37-55 — `ValidateBasic()`.
 * NULL validator (:38-40), absent public key (:41-43), negative voting
 * power (:45-47) and an address that is not the one derived from the key
 * (:49-52) all REJECT. The last check is what makes the address
 * non-forgeable: it is re-derived, never trusted.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on a hash backend failure.
 */
int cmt_validator_validate_basic(const cmt_validator_t *v);

/** cometbft@709fd12b types/validator.go:59-62 — `Copy()`. The reference
 *  panics on a nil receiver (:58); here that is CMT_FAULT. */
int cmt_validator_copy(const cmt_validator_t *v, cmt_validator_t *out);

/**
 * cometbft@709fd12b types/validator.go:65-85 —
 * `CompareProposerPriority()`. Higher priority wins; on a tie the LOWER
 * address wins (`bytes.Compare` < 0, :75-80). A NULL `v` returns `other`,
 * exactly as the reference's nil receiver does (:66-68) — that is what
 * makes `getValWithMostPriority`'s fold work from a nil seed.
 *
 * `bytes.Compare` orders by content and then by length, so two addresses
 * of different lengths never compare equal; this port reproduces that
 * with a memcmp over the shorter length followed by a length comparison.
 *
 * @param out receives the winner (an alias of `v` or of `other`).
 * @return CMT_OK; CMT_REJECT where the reference panics on two identical
 *         validators (:82); CMT_FAULT on NULL `other` or NULL `out`.
 */
int cmt_validator_compare_proposer_priority(const cmt_validator_t *v,
                                            const cmt_validator_t *other,
                                            const cmt_validator_t **out);

/**
 * cometbft@709fd12b types/validator.go:118-134 — `Bytes()`.
 * The marshalled SimpleValidator{PubKey, VotingPower} — THE LEAF whose
 * Merkle root is ValidatorsHash (D-19 rev 6 item 5). It excludes the
 * address (redundant with the key) and the proposer priority (changes
 * every round), which is the reference's own reasoning at :114-117.
 * The reference panics when the key cannot be encoded (:121); here an
 * absent key is CMT_REJECT.
 * @param out_len receives the encoding length; `cap` should be at least
 *        CMT_VALIDATOR_BYTES_MAX.
 * @return CMT_OK, CMT_REJECT (absent key, or it does not fit), CMT_FAULT.
 */
int cmt_validator_bytes(const cmt_validator_t *v, uint8_t *out, size_t cap,
                        size_t *out_len);

/** cometbft@709fd12b types/validator.go:137-155 — `ToProto()`.
 *  @return CMT_OK, CMT_REJECT on a NULL validator (:138-140) or an absent
 *          key (:142-145), CMT_FAULT on NULL out. */
int cmt_validator_to_proto(const cmt_validator_t *v, cmt_pb_validator_t *out);

/**
 * cometbft@709fd12b types/validator.go:159-175 — `ValidatorFromProto()`.
 * ⚠ THE ADDRESS IS COPIED FROM THE WIRE, NOT RE-DERIVED (:169) — the
 * hidden KODEK rule the port map records. Whether it AGREES with the key
 * is `ValidateBasic`'s question, and every path that matters asks it
 * (`ValidatorSetFromProto` ends in `vals.ValidateBasic()`, :940).
 * @return CMT_OK, CMT_REJECT on an absent key (:164-167), CMT_FAULT.
 */
int cmt_validator_from_proto(const cmt_pb_validator_t *vp,
                             cmt_validator_t *out);

/* ── the two sort orders ────────────────────────────────────────────── */

/** cometbft@709fd12b types/validator_set.go:851-856 —
 *  `ValidatorsByVotingPower.Less()`. Power DESCENDING; equal power breaks
 *  on the ASCENDING address. */
bool cmt_validators_by_voting_power_less(const cmt_validator_t *a,
                                         const cmt_validator_t *b);

/** cometbft@709fd12b types/validator_set.go:868-870 —
 *  `ValidatorsByAddress.Less()`. Address ASCENDING. */
bool cmt_validators_by_address_less(const cmt_validator_t *a,
                                    const cmt_validator_t *b);

/** `sort.Sort(ValidatorsByVotingPower(...))` (:674, :964) over an array of
 *  POINTERS, which is what a Go `[]*Validator` is. Deterministic; see
 *  "Determinism" in the file header. */
void cmt_validators_sort_by_voting_power(cmt_validator_t **v, size_t n);

/** `sort.Sort(ValidatorsByAddress(...))` (:411, :538). Deterministic. */
void cmt_validators_sort_by_address(cmt_validator_t **v, size_t n);

/* ══ validator_set.go ═════════════════════════════════════════════════ */

/**
 * The reference's `&ValidatorSet{allKeysHaveSameType: true}` (:78-80) plus
 * the caller's storage. Call this before anything else; it does NOT add
 * validators.
 * @return CMT_OK, CMT_FAULT on NULL, CMT_REJECT if `cap` exceeds
 *         CMT_VALSET_MAX.
 */
int cmt_validator_set_init(cmt_validator_set_t *vals,
                           cmt_validator_t *storage, size_t cap);

/**
 * cometbft@709fd12b types/validator_set.go:77-89 — `NewValidatorSet()`.
 * `updateWithChangeSet(valz, false)` — so a zero-power entry is refused
 * here, unlike `UpdateWithChangeSet` — followed by
 * `IncrementProposerPriority(1)` when the list is non-empty (:85-87).
 * The reference panics on any error (:82-84).
 * @param vals must already be `cmt_validator_set_init`ialised.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_validator_set_new(cmt_validator_set_t *vals,
                          const cmt_validator_t *valz, size_t n,
                          cmt_valset_scratch_t *scratch);

/**
 * cometbft@709fd12b types/validator_set.go:91-113 — `ValidateBasic()`.
 * An empty set (:92-94), an invalid member (:96-100), an invalid proposer
 * (:102-104) and a proposer that is not a member (:106-112, the reference's
 * ErrProposerNotInVals) all REJECT.
 */
int cmt_validator_set_validate_basic(const cmt_validator_set_t *vals);

/** cometbft@709fd12b types/validator_set.go:116-118 — `IsNilOrEmpty()`. */
bool cmt_validator_set_is_nil_or_empty(const cmt_validator_set_t *vals);

/**
 * cometbft@709fd12b types/validator_set.go:122-126 —
 * `CopyIncrementProposerPriority()`. Copies into `dst` (whose storage the
 * caller supplies and which must already be initialised) and increments
 * there, leaving `src` untouched.
 */
int cmt_validator_set_copy_increment_proposer_priority(
        const cmt_validator_set_t *src, cmt_validator_set_t *dst,
        int32_t times);

/**
 * cometbft@709fd12b types/validator_set.go:131-153 —
 * `IncrementProposerPriority()`. Rescales into the window
 * `PriorityWindowSizeFactor * TotalVotingPower` (:142-143), centres
 * (:144), elects `times` times (:148-150) and stores the LAST winner as
 * the proposer (:152).
 * The reference panics on an empty set (:132-134) and on `times <= 0`
 * (:135-137); both REJECT here.
 */
int cmt_validator_set_increment_proposer_priority(cmt_validator_set_t *vals,
                                                  int32_t times);

/**
 * cometbft@709fd12b types/validator_set.go:158-179 —
 * `RescalePriorities()`.
 *
 * NOTE reference quirk, ported as-is: `diffMax <= 0` returns without doing
 * anything (:165-167, the reference calls it "merely a sanity check"), and
 * `ratio` is computed at :173 BEFORE the `diff > diffMax` test at :174 —
 * so it is computed even when it is not used. Both are kept.
 *
 * The arithmetic at :173 is Go int64 arithmetic, which WRAPS on overflow;
 * this port reproduces the wrap in unsigned arithmetic rather than
 * invoking C's undefined signed overflow. The division at :176 is Go's
 * truncating `/`, including Go's rule that `MinInt64 / -1` is MinInt64
 * rather than a trap. A `ratio` of zero is Go's divide-by-zero panic and
 * REJECTS here.
 *
 * The reference panics on an empty set (:159-161) — REJECT.
 */
int cmt_validator_set_rescale_priorities(cmt_validator_set_t *vals,
                                         int64_t diff_max);

/**
 * cometbft@709fd12b types/validator_set.go:181-193 —
 * `incrementProposerPriority()` (the unexported one). Adds each voting
 * power with safeAddClip (:184), elects the highest priority (:188) and
 * pushes the winner back by the total with safeSubClip (:190).
 * @param out_proposer receives the elected validator (an alias into
 *        `vals->validators`); may be NULL.
 */
int cmt_validator_set_increment_proposer_priority_once(
        cmt_validator_set_t *vals, const cmt_validator_t **out_proposer);

/**
 * cometbft@709fd12b types/validator_set.go:196-209 —
 * `computeAvgProposerPriority()`.
 *
 * The reference sums into a `math/big` integer and divides with
 * `(*big.Int).Div`, which is EUCLIDEAN: it returns the q for which
 * `x = y*q + m` with `0 <= m < |y|`. The divisor here is
 * `n = len(vals.Validators)`, which is strictly positive, and for a
 * positive divisor Euclidean division IS floor division. This port
 * accumulates in an explicit two's-complement 128-bit value and floors.
 *
 * 128 bits is not decoration: with n validators each holding a priority in
 * int64 range the sum reaches n * 2^63, which for n = 2 already leaves
 * int64 — the reference's own test cases 3 and 4
 * (validator_set_test.go:495-506: two validators at MaxInt64 average to
 * MaxInt64, two at MinInt64 average to MinInt64) are exactly the cases an
 * int64 accumulator gets wrong.
 *
 * The quotient always fits int64 when the divisor is the list length, so
 * the reference's "should never happen" panic at :207-208 is unreachable;
 * it is nevertheless implemented, as CMT_REJECT.
 *
 * @return CMT_OK, CMT_REJECT on an empty set (the reference divides by
 *         zero there — its own comment at :195 says it must not be
 *         called), CMT_FAULT on NULL.
 */
int cmt_validator_set_compute_avg_proposer_priority(
        const cmt_validator_set_t *vals, int64_t *out);

/**
 * cometbft@709fd12b types/validator_set.go:212-231 —
 * `computeMaxMinPriorityDiff()`. `max - min` in Go int64 arithmetic, which
 * WRAPS (reproduced in unsigned arithmetic here), then the reference's
 * `-1 * diff` when the result came out negative (:227-229) — which also
 * wraps, so a diff of MinInt64 stays MinInt64. Ported exactly.
 * The reference panics on an empty set (:213-215) — REJECT.
 */
int cmt_validator_set_compute_max_min_priority_diff(
        const cmt_validator_set_t *vals, int64_t *out);

/** cometbft@709fd12b types/validator_set.go:233-239 —
 *  `getValWithMostPriority()`. Folds CompareProposerPriority from a nil
 *  seed over the list, so the FIRST element wins by default.
 *  @return CMT_OK, CMT_REJECT on an empty set (the reference returns nil)
 *          or on two identical validators, CMT_FAULT on NULL. */
int cmt_validator_set_get_val_with_most_priority(
        const cmt_validator_set_t *vals, const cmt_validator_t **out);

/** cometbft@709fd12b types/validator_set.go:241-249 —
 *  `shiftByAvgProposerPriority()`. Subtracts the average from every
 *  priority with safeSubClip. Panics on an empty set (:242-244) → REJECT. */
int cmt_validator_set_shift_by_avg_proposer_priority(
        cmt_validator_set_t *vals);

/** cometbft@709fd12b types/validator_set.go:252-261 —
 *  `validatorListCopy()`. A nil list copies to nothing (:253-255).
 *  @return CMT_OK, CMT_REJECT if `n` exceeds `cap`, CMT_FAULT on NULL. */
int cmt_validator_list_copy(const cmt_validator_t *src, size_t n,
                            cmt_validator_t *dst, size_t cap);

/**
 * cometbft@709fd12b types/validator_set.go:264-271 — `Copy()`.
 * Copies the list, the cached total and the key-type flag, and SNAPSHOTS
 * the proposer — see the struct comment for why that last one is a value
 * here and a shared pointer in the reference.
 * @param dst must already be `cmt_validator_set_init`ialised with storage
 *        of at least `src->validators_len` slots.
 */
int cmt_validator_set_copy(const cmt_validator_set_t *src,
                           cmt_validator_set_t *dst);

/** cometbft@709fd12b types/validator_set.go:275-282 — `HasAddress()`. */
bool cmt_validator_set_has_address(const cmt_validator_set_t *vals,
                                   const uint8_t *address, size_t address_len);

/**
 * cometbft@709fd12b types/validator_set.go:286-293 — `GetByAddress()`.
 * PORT, not YOK: the port map's automatic pass marked it YOK and the
 * REV 3 override corrects it — validation.go:250/:358, evidence.go:59/:263/
 * :288, validator_set.go:468/:515/:579 and state.go:2383 all call it.
 * @param out_index receives the index, or -1 when absent (:292); may be
 *        NULL. @param out receives a COPY (:289); may be NULL.
 * @return CMT_OK whether or not it was found — "absent" is -1 in
 *         `*out_index`, not an error, exactly as the reference returns
 *         `(-1, nil)`. CMT_FAULT on NULL `vals`.
 */
int cmt_validator_set_get_by_address(const cmt_validator_set_t *vals,
                                     const uint8_t *address,
                                     size_t address_len,
                                     int32_t *out_index,
                                     cmt_validator_t *out);

/**
 * cometbft@709fd12b types/validator_set.go:299-305 — `GetByIndex()`.
 * An index below zero or at/above the length returns "nothing" (:300-302);
 * that is CMT_REJECT here, because unlike GetByAddress the reference has
 * no in-band sentinel for it.
 * @param out receives a COPY (:304); may be NULL.
 */
int cmt_validator_set_get_by_index(const cmt_validator_set_t *vals,
                                   int32_t index, cmt_validator_t *out);

/** cometbft@709fd12b types/validator_set.go:308-310 — `Size()`. */
size_t cmt_validator_set_size(const cmt_validator_set_t *vals);

/**
 * cometbft@709fd12b types/validator_set.go:314-328 —
 * `updateTotalVotingPower()`. Sums with safeAddClip and refuses above
 * MaxTotalVotingPower.
 * @return CMT_OK; CMT_FAULT where the reference panics at :319-324 — see
 *         "Return codes" in the file header for why that one is a fault
 *         and not a verdict.
 */
int cmt_validator_set_update_total_voting_power(cmt_validator_set_t *vals);

/** cometbft@709fd12b types/validator_set.go:332-337 —
 *  `TotalVotingPower()`. Recomputes when the cache reads 0. NOT const: it
 *  writes the cache, exactly as the reference does. */
int cmt_validator_set_total_voting_power(cmt_validator_set_t *vals,
                                         int64_t *out);

/**
 * cometbft@709fd12b types/validator_set.go:341-349 — `GetProposer()`.
 * Fills the proposer from `findProposer` when it is unset (:345-347) and
 * returns a COPY (:348). NOT const, for that reason.
 * @return CMT_OK, CMT_REJECT on an empty set (:342-344, the reference
 *         returns nil), CMT_FAULT on NULL.
 */
int cmt_validator_set_get_proposer(cmt_validator_set_t *vals,
                                   cmt_validator_t *out);

/**
 * cometbft@709fd12b types/validator_set.go:351-359 — `findProposer()`.
 *
 * NOTE reference quirk, ported as-is: the loop SKIPS any validator whose
 * address equals the current best's (:354). With the set's unique-address
 * invariant that can only skip the current best itself, which
 * CompareProposerPriority would have returned anyway — so the guard is a
 * no-op on any valid set. It is kept because a set that reached here with
 * duplicate addresses would behave differently without it.
 */
int cmt_validator_set_find_proposer(const cmt_validator_set_t *vals,
                                    const cmt_validator_t **out);

/**
 * cometbft@709fd12b types/validator_set.go:365-371 — `Hash()`.
 * The Merkle root over `Bytes()` leaves — ValidatorsHash and
 * NextValidatorsHash (D-19 rev 6 item 5). An EMPTY set hashes to the empty
 * tree's root H("") (crypto/merkle/tree.go:16-18 via hash.go:16-18).
 *
 * ⚠ The ORDER IS THE SET'S OWN. This function does not sort; the set is
 * kept in ValidatorsByVotingPower order by `updateWithChangeSet` (:674)
 * and by `ValidatorSetFromExistingValidators` (:964). Hashing a set that
 * was assembled by hand in another order produces another root, and that
 * is the reference's behaviour too.
 *
 * @param scratch buffer for the leaves; needs
 *        `validators_len * CMT_VALIDATOR_BYTES_MAX` bytes in the worst
 *        case. @param items array of at least `validators_len` entries.
 * @return CMT_OK, CMT_REJECT (a leaf does not fit, or a member has no
 *         key), CMT_FAULT.
 */
int cmt_validator_set_hash(const cmt_validator_set_t *vals,
                           uint8_t *scratch, size_t scratch_cap,
                           cmt_merkle_item_t *items, size_t items_cap,
                           uint8_t out[CMT_TMHASH_SIZE]);

/* ── the change-set machinery ───────────────────────────────────────── */

/**
 * cometbft@709fd12b types/validator_set.go:408-442 — `processChanges()`.
 * Deep-copies (:410), sorts by address (:411) and splits into updates and
 * removals, refusing a duplicate address (:419-422), a negative voting
 * power (:425-427) and a power above MaxTotalVotingPower (:428-431). A
 * power of exactly zero is a REMOVAL (:432-433).
 *
 * The reference's sort is unstable, and duplicates are exactly what this
 * function looks for — but it only tests ADJACENT equality, and any
 * permutation of an equal-address group leaves that group adjacent, so
 * every ordering reaches the same verdict. Deterministic.
 *
 * @param scratch supplies `changes`, `sorted`, `updates` and `removals`.
 * @param out_updates/out_removals receive pointer arrays inside `scratch`.
 */
int cmt_validator_set_process_changes(const cmt_validator_t *orig_changes,
                                      size_t n,
                                      cmt_valset_scratch_t *scratch,
                                      cmt_validator_t ***out_updates,
                                      size_t *out_updates_len,
                                      cmt_validator_t ***out_removals,
                                      size_t *out_removals_len);

/**
 * cometbft@709fd12b types/validator_set.go:462-488 — `verifyUpdates()`.
 * Sorts the updates by their DELTA against the current set and walks them
 * ascending, so the running total passes through its smallest values
 * first; a running total above MaxTotalVotingPower is
 * ErrTotalVotingPowerOverflow (:483-485).
 *
 * The reference's `sort.Slice` (:476) is unstable, and two updates can
 * share a delta. It does not matter: within a group of equal deltas every
 * permutation produces the same partial sums, because every member
 * contributes the same value. Deterministic.
 *
 * ⚠ `updates` IS NOT REORDERED, and must not be. The reference sorts
 * `updatesCopy` (:475) rather than `updates` because the caller's list has
 * to stay in the ADDRESS order `processChanges` produced: `applyUpdates`
 * documents that order as its precondition (:534-537) and merges the two
 * address-sorted lists in one pass (:543-557). A delta-ordered list fed to
 * that merge duplicates and drops entries. This port therefore takes
 * `updates` as read-only and sorts a local copy of the DELTAS, which is
 * all the overflow walk (:481-486) reads.
 *
 * @return CMT_OK, CMT_REJECT on overflow, CMT_FAULT.
 */
int cmt_validator_set_verify_updates(cmt_validator_t *const *updates,
                                     size_t updates_len,
                                     cmt_validator_set_t *vals,
                                     int64_t removed_power,
                                     int64_t *out_tvp);

/** cometbft@709fd12b types/validator_set.go:490-498 —
 *  `numNewValidators()`. How many updates are not already in the set. */
size_t cmt_validator_set_num_new_validators(cmt_validator_t *const *updates,
                                            size_t updates_len,
                                            const cmt_validator_set_t *vals);

/**
 * cometbft@709fd12b types/validator_set.go:512-530 —
 * `computeNewPriorities()`. An update that is already in the set keeps its
 * priority (:527); a NEW validator starts at
 * `-(tvp + (tvp >> 3))` — the -1.125 * P entry penalty (:518-525) that
 * stops a validator un-bonding and re-bonding to clear a negative
 * priority. Mutates the update entries.
 */
int cmt_validator_set_compute_new_priorities(cmt_validator_t **updates,
                                             size_t updates_len,
                                             const cmt_validator_set_t *vals,
                                             int64_t updated_total_voting_power);

/**
 * cometbft@709fd12b types/validator_set.go:536-571 — `applyUpdates()`.
 * Sorts the existing members by address (:538) and merges the two sorted
 * lists, the update winning on an equal address (:547-555).
 * @param existing/merged pointer arrays from `scratch`.
 */
int cmt_validator_set_apply_updates(cmt_validator_t **existing,
                                    size_t existing_len,
                                    cmt_validator_t **updates,
                                    size_t updates_len,
                                    cmt_validator_t **merged,
                                    size_t merged_cap,
                                    size_t *out_len);

/**
 * cometbft@709fd12b types/validator_set.go:575-589 — `verifyRemovals()`.
 * Every entry to remove must be in the set (:580-582); the reference also
 * panics when there are more deletes than validators (:585-587) — REJECT.
 * @param out_power receives the voting power being removed.
 */
int cmt_validator_set_verify_removals(cmt_validator_t *const *deletes,
                                      size_t deletes_len,
                                      const cmt_validator_set_t *vals,
                                      int64_t *out_power);

/**
 * cometbft@709fd12b types/validator_set.go:594-618 — `applyRemovals()`.
 * Expects both lists sorted by address, which `applyUpdates` guarantees
 * (:593). Where Go would index an exhausted `existing` (:602) this port
 * checks explicitly and REJECTS (INVARIANT 7495d337).
 */
int cmt_validator_set_apply_removals(cmt_validator_t **merged,
                                     size_t merged_len,
                                     cmt_validator_t *const *deletes,
                                     size_t deletes_len,
                                     size_t *out_len);

/**
 * cometbft@709fd12b types/validator_set.go:624-677 —
 * `updateWithChangeSet()`. The whole pipeline: process, refuse deletes
 * when they are not allowed (:635-637), refuse an empty result (:640-642),
 * verify removals then updates, compute the new priorities, apply, check
 * the key types, recompute the total, rescale, centre, and finally sort
 * into ValidatorsByVotingPower order (:674).
 *
 * An EMPTY change list returns success having done nothing (:625-627) —
 * no rescale, no centring, no sort.
 *
 * ⚠ ONE ADDED RULE, and it is a capacity rule: the resulting set may not
 * exceed CMT_VALSET_MAX. It is computed before any mutation, from
 * `len(validators) + numNewValidators - len(deletes)`, and placed AFTER
 * `verifyUpdates` so that the reference's own error precedence is
 * unchanged. On any rejection the set is left exactly as it was, which is
 * the reference's contract at :690-691.
 */
int cmt_validator_set_update_with_change_set_ex(cmt_validator_set_t *vals,
                                                const cmt_validator_t *changes,
                                                size_t changes_len,
                                                bool allow_deletes,
                                                cmt_valset_scratch_t *scratch);

/** cometbft@709fd12b types/validator_set.go:692-694 —
 *  `UpdateWithChangeSet()`. `updateWithChangeSet(changes, true)`. */
int cmt_validator_set_update_with_change_set(cmt_validator_set_t *vals,
                                             const cmt_validator_t *changes,
                                             size_t changes_len,
                                             cmt_valset_scratch_t *scratch);

/**
 * cometbft@709fd12b types/validator_set.go:748-760 —
 * `findPreviousProposer()`. The INVERSE fold of getValWithMostPriority: it
 * keeps the LOSER of every comparison (:755-757), so it finds the lowest
 * priority — the validator that would have been pushed back last.
 * @return CMT_OK, CMT_REJECT on an empty set or two identical validators.
 */
int cmt_validator_set_find_previous_proposer(const cmt_validator_set_t *vals,
                                             const cmt_validator_t **out);

/**
 * cometbft@709fd12b types/validator_set.go:762-784 —
 * `checkAllKeysHaveSameType()`. An empty set is true (:763-766); otherwise
 * every key's type must match the first one's.
 *
 * This port has exactly ONE key type — ML-DSA-87, PublicKey branch 9
 * (K-2) — so the "types differ" branch at :777-780 is unreachable and this
 * port NEVER writes false. That is stated rather than hidden.
 *
 * ⚠ NOTE reference quirk, and it is the reason this returns a code where
 * the reference returns nothing: the bootstrap at :770-776 tolerates a
 * member with NO key by CONTINUING past it, but only while `firstKeyType`
 * is still empty. Once a key HAS been seen, :777 evaluates
 * `val.PubKey.Type()` unconditionally, so a LATER keyless member
 * dereferences a nil interface and PANICS. That path is reachable — the
 * changes `updateWithChangeSet` passes here (:666) are not required to
 * carry keys — so it is reproduced as CMT_REJECT rather than quietly
 * skipped.
 *
 * @return CMT_OK, CMT_REJECT where the reference panics, CMT_FAULT on NULL.
 */
int cmt_validator_set_check_all_keys_have_same_type(cmt_validator_set_t *vals);

/** cometbft@709fd12b types/validator_set.go:788-790 —
 *  `AllKeysHaveSameType()`. Reads the cached flag. */
bool cmt_validator_set_all_keys_have_same_type(const cmt_validator_set_t *vals);

/**
 * cometbft@709fd12b types/validator_set.go:698-702 —
 * `(vals *ValidatorSet) VerifyCommit()`.
 *
 * The method form of `types.VerifyCommit`, and nothing more: the
 * reference's whole body is `return VerifyCommit(chainID, vals, blockID,
 * height, commit)` (:701). Ported in wave R1-D, once cmt_validation
 * existed; wave R1-C listed it as stage D.
 *
 * The parameters are spelled `cmt_pb_commit_t` and `cmt_pb_block_id_t`
 * rather than cmt_block.h's `cmt_commit_t` / `cmt_block_id_t` — which are
 * TYPEDEFS OF EXACTLY THESE TYPES (cmt_block.h:303, :511) — so that this
 * header need not include cmt_block.h or cmt_validation.h. cmt_validation.h
 * includes THIS header, and two headers including each other is a knot
 * worth not tying. The implementation delegates to `cmt_verify_commit`.
 *
 * @param vals NOT const: TotalVotingPower writes the set's cache.
 * @param err may be NULL; see cmt_validation.h.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_validator_set_verify_commit(cmt_validator_set_t *vals,
                                    const uint8_t *chain_id,
                                    size_t chain_id_len,
                                    const cmt_pb_block_id_t *block_id,
                                    int64_t height,
                                    const cmt_pb_commit_t *commit,
                                    cmt_vs_error_t *err);

/* ── the codec side (KODEK rows) ────────────────────────────────────── */

/**
 * cometbft@709fd12b types/validator_set.go:877-904 — `ToProto()`.
 *
 * ⚠ TWO HIDDEN RULES the port map lists, both reproduced:
 *  · an empty or nil set produces an EMPTY message, not an error
 *    (:878-880: "validator set should never be nil");
 *  · `TotalVotingPower` is ZEROED (:901) — the reference's own comment at
 *    :899-900 says the proto bytes are sometimes used as a hash, so the
 *    cached value must not leak into them.
 *
 * @param out->validators must point at caller storage of at least
 *        `vals->validators_len` slots.
 */
int cmt_validator_set_to_proto(const cmt_validator_set_t *vals,
                               cmt_pb_validator_set_t *out);

/**
 * cometbft@709fd12b types/validator_set.go:909-941 —
 * `ValidatorSetFromProto()`.
 *
 * ⚠ THREE HIDDEN RULES, all reproduced:
 *  · the key types are re-checked (:924) — this port has one key type, so
 *    the check is trivially satisfied, but it is made;
 *  · `TotalVotingPower()` is RECOMPUTED (:938) and the wire value is never
 *    trusted — the reference's comment at :933-935 is explicit that a peer
 *    could otherwise inject a wrong total;
 *  · the result ends in `ValidateBasic()` (:940), so a set whose addresses
 *    do not match their keys, or whose proposer is not a member, is
 *    refused at the decode boundary.
 *
 * A nil proto is an error (:910-912).
 */
int cmt_validator_set_from_proto(const cmt_pb_validator_set_t *vp,
                                 cmt_validator_set_t *vals);

/**
 * cometbft@709fd12b types/validator_set.go:947-966 —
 * `ValidatorSetFromExistingValidators()`. Rebuilds the exact set from an
 * array WITHOUT touching priorities or powers: every member must pass
 * ValidateBasic (:951-956), the proposer is `findPreviousProposer` (:962),
 * the total is recomputed (:963) and the list is sorted into
 * ValidatorsByVotingPower order (:964).
 * An empty list is an error (:948-950).
 */
int cmt_validator_set_from_existing_validators(cmt_validator_set_t *vals,
                                               const cmt_validator_t *valz,
                                               size_t n);

/* ── taşınmadı (not ported), with the reason ────────────────────────────
 *  validator.go
 *   · :93-102  `String`               — display only.
 *   · :105-112 `ValidatorListString`  — display only (REV 3 override:
 *                                       the automatic pass said KODEK).
 *   · :182-194 `RandValidator`        — a test helper; it also needs
 *                                       NewMockPV, which this port has no
 *                                       counterpart for.
 *  validator_set.go
 *   · :376-388 `ProposerPriorityHash` — YOK by the REV 3 override: its
 *       only caller is light/detector.go:210-211, and the light client is
 *       out of scope. The reference's own bug stays recorded and NOT
 *       ported: :384 writes every varint at offset 0 of `buf`, so :387
 *       hashes the last varint followed by zero padding.
 *   · :391-398 `Iterate`              — YOK by the REV 3 override; its
 *       only use is StringIndented.
 *   · :698-702 `VerifyCommit`         — PORTED in wave R1-D as
 *       `cmt_validator_set_verify_commit` above, once cmt_validation
 *       existed. R1-C listed it here as stage D; it is no longer a hole.
 *   · :708-720 `VerifyCommitLight`,
 *              `VerifyCommitLightAllSignatures`
 *   · :725-742 `VerifyCommitLightTrusting`,
 *              `VerifyCommitLightTrustingAllSignatures`
 *                                     — YOK by the port map's scope rule
 *       (REV 3 ~892, REV 3.1 ~950): the four wrap the light-client family
 *       of types/validation.go (:61-192), whose only callers are `light/`,
 *       the evidence pool and `blocksync/`. Our block sync takes the full
 *       `VerifyCommit` path. The Trusting pair additionally needs
 *       `cmtmath.Fraction` and a trust level, which nothing in scope
 *       supplies.
 *   · :807-809 `ErrNotEnoughVotingPowerSigned.Error` — display only; the
 *       VALUE it formats is `cmt_vs_error_t` above.
 *   · :816-841 `String` / `StringIndented` — display only.
 *   · :974-989 `RandValidatorSet`     — a test helper.
 *  Neither file's `sort.Interface` Len/Swap methods (:849, :858, :866,
 *  :872) have their own C counterpart: they are the mechanics of
 *  `sort.Sort`, and they live inside the two sort functions above.
 */

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_VALIDATOR_SET_H */
