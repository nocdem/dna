/**
 * @file shared/dnac/cmt_params.h
 * @brief cometbft @709fd12b `types/params.go` ported to C — the consensus
 *        parameters and the ConsensusHash.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-C of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── ConsensusHash is FLAT, not Merkle ──────────────────────────────────
 * `ConsensusParams.Hash()` (params.go:272-290) hashes the marshalled
 * `HashedParams{BlockMaxBytes, BlockMaxGas}` DIRECTLY — the reference's
 * own comment at :270-271 says "No need for a Merkle tree here, just a
 * small struct to hash". So the header leaf ConsensusHash commits ONLY
 * those two numbers, and every other parameter (evidence bounds, key
 * types, app version, vote-extension height) is deliberately outside it,
 * which is what lets the parameter set evolve without a header change
 * (:268-271). D-19 rev 6 item 6 records the same.
 *
 * A DIRECT CONSEQUENCE, stated because it decides a question below: the
 * public-key TYPE NAME is not consensus-critical. It is compared, it is
 * validated, and it is never hashed.
 *
 * ── QUESTION FOR THE OPERATOR — the ML-DSA-87 type name ────────────────
 * `ABCIPubKeyTypeEd25519` (params.go:24) is the string `ed25519.KeyType`.
 * ML-DSA-87 has NO counterpart in the reference, so its name cannot be
 * copied from anything, and this port does not invent one quietly:
 * CMT_PUBKEY_TYPE_MLDSA87_NAME below is a PLACEHOLDER defined in exactly
 * one place and marked. The tests pin only that the comparison compares
 * strings, never the value itself. See K-2
 * (atlas-dec-7fde65722d68b32eca08be61fbcb47ac) for the precedent: the
 * oneof FIELD NUMBER had the same shape of problem and the operator chose
 * it; unlike that number, this string enters no hash and no signature, so
 * choosing it later costs nothing.
 *
 * ── Return codes ───────────────────────────────────────────────────────
 * CMT_OK / CMT_REJECT / CMT_FAULT as cmt_tmhash.h defines them. Both
 * reference panics in this file map to CMT_REJECT: `Hash`'s marshal panic
 * (:281-283, :286-288) and `VoteExtensionsEnabled`'s `h < 1` panic
 * (:76-78). Neither is `updateTotalVotingPower`'s case — each is a
 * deterministic property of its arguments, so every honest node reaches
 * the same verdict on the same values.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure functions. No clock, no randomness, no allocation. The reference's
 * one map, `ABCIPubKeyTypesToNames` (:28-31), is used for MEMBERSHIP only
 * (`_, ok := ...` at :199) and is never iterated, so it becomes a sorted
 * static array here with no ordering consequence.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   types/params.go 370 lines
 *     1766c8ec54f5932ce43c77f48a8358237b16428f3bddd69f2998e32a0c2e7746
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PARAMS_H
#define SHARED_DNAC_CMT_PARAMS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_bits.h"   /* CMT_BITS_MAX_BLOCK_SIZE_BYTES and friends */
#include "cmt_pb.h"     /* cmt_pb_hashed_params_t                    */

#ifdef __cplusplus
extern "C" {
#endif

/* ── the three size constants ───────────────────────────────────────────
 * params.go:16, :19 and :22 are ALREADY in cmt_bits.h (:87-93), which
 * derives its BitArray bound from them. They are referenced here, never
 * redefined, so the tree keeps ONE definition of each. */

/** cometbft@709fd12b types/params.go:16 — `MaxBlockSizeBytes` (100 MB). */
#define CMT_MAX_BLOCK_SIZE_BYTES  CMT_BITS_MAX_BLOCK_SIZE_BYTES
/** cometbft@709fd12b types/params.go:19 — `BlockPartSizeBytes` (64 kB). */
#define CMT_BLOCK_PART_SIZE_BYTES CMT_BITS_BLOCK_PART_SIZE_BYTES
/** cometbft@709fd12b types/params.go:22 — `MaxBlockPartsCount`. */
#define CMT_MAX_BLOCK_PARTS_COUNT CMT_BITS_MAX_BLOCK_PARTS_COUNT

/**
 * The name of this chain's one public-key type.
 *
 * QUESTION (operator): the reference's counterpart is
 * `ABCIPubKeyTypeEd25519 = ed25519.KeyType` (params.go:24), a string.
 * ML-DSA-87 has no row in the reference, so this VALUE is a placeholder
 * and not a port of anything. It is defined here ONCE, it is not hashed
 * (ConsensusHash covers only HashedParams — see the file header), and no
 * test asserts its contents.
 */
#define CMT_PUBKEY_TYPE_MLDSA87_NAME "mldsa87"   /* QUESTION */

/** The longest type name this port stores, including the NUL. */
#define CMT_PARAMS_PUBKEY_TYPE_MAX 32
/** How many key types a ValidatorParams may list. The reference's slice
 *  is unbounded; this is a capacity bound, refused rather than truncated
 *  (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). */
#define CMT_PARAMS_MAX_PUBKEY_TYPES 8

/* ── the parameter structs (params.go:35-71) ────────────────────────── */

/** params.go:45-48 — `BlockParams`. */
typedef struct {
    int64_t max_bytes;   /* :46 */
    int64_t max_gas;     /* :47 */
} cmt_block_params_t;

/**
 * params.go:51-55 — `EvidenceParams`.
 * `MaxAgeDuration` is a Go `time.Duration`, i.e. an int64 count of
 * NANOSECONDS; the name says so here so a caller cannot read it as
 * seconds.
 */
typedef struct {
    int64_t max_age_num_blocks;  /* :52 */
    int64_t max_age_duration_ns; /* :53 */
    int64_t max_bytes;           /* :54 */
} cmt_evidence_params_t;

/**
 * params.go:59-61 — `ValidatorParams`. The reference's `[]string` becomes
 * fixed-width NUL-terminated storage: a `const char *` array would make
 * the struct own lifetimes it cannot see, and `Update` (:314) COPIES the
 * list precisely so the result does not alias its input.
 */
typedef struct {
    char   pub_key_types[CMT_PARAMS_MAX_PUBKEY_TYPES]
                        [CMT_PARAMS_PUBKEY_TYPE_MAX];   /* :60 */
    size_t pub_key_types_len;
} cmt_validator_params_t;

/** params.go:63-65 — `VersionParams`. */
typedef struct {
    uint64_t app;    /* :64 */
} cmt_version_params_t;

/** params.go:69-71 — `ABCIParams`. */
typedef struct {
    int64_t vote_extensions_enable_height;   /* :70 */
} cmt_abci_params_t;

/** params.go:35-41 — `ConsensusParams`. */
typedef struct {
    cmt_block_params_t     block;      /* :36 */
    cmt_evidence_params_t  evidence;   /* :37 */
    cmt_validator_params_t validator;  /* :38 */
    cmt_version_params_t   version;    /* :39 */
    cmt_abci_params_t      abci;       /* :40 */
} cmt_consensus_params_t;

/**
 * The POINTER-SHAPED `cmtproto.ConsensusParams` that `ValidateUpdate`
 * (:220) and `Update` (:294) take.
 *
 * Each sub-message's NIL-NESS is load-bearing in BOTH of them —
 * `updated == nil || updated.Abci == nil` returns nil immediately (:222),
 * and `Update` copies a field only when its sub-message is non-nil
 * (:302-321). So the nil-ness is carried explicitly rather than being
 * approximated by a zero value.
 *
 * There is no cmt_pb message for this type (cmt_pb carries only
 * HashedParams), so this struct never reaches a wire; it is the shape the
 * two functions above are written against. See "taşınmadı" at the end of
 * this header for ToProto / FromProto.
 */
typedef struct {
    bool                   has_block;     cmt_block_params_t     block;
    bool                   has_evidence;  cmt_evidence_params_t  evidence;
    bool                   has_validator; cmt_validator_params_t validator;
    bool                   has_version;   cmt_version_params_t   version;
    bool                   has_abci;      cmt_abci_params_t      abci;
} cmt_consensus_params_proto_t;

/* ── constructors (params.go:86-132) ────────────────────────────────── */

/** params.go:97-102 — `DefaultBlockParams()`: 22020096 bytes, MaxGas -1. */
void cmt_default_block_params(cmt_block_params_t *out);

/** params.go:105-111 — `DefaultEvidenceParams()`: 100000 blocks,
 *  48 hours expressed in nanoseconds, 1048576 bytes. */
void cmt_default_evidence_params(cmt_evidence_params_t *out);

/** params.go:115-119 — `DefaultValidatorParams()`. The reference allows
 *  only ed25519; this port allows only CMT_PUBKEY_TYPE_MLDSA87_NAME. */
void cmt_default_validator_params(cmt_validator_params_t *out);

/** params.go:121-125 — `DefaultVersionParams()`: App 0. */
void cmt_default_version_params(cmt_version_params_t *out);

/** params.go:127-132 — `DefaultABCIParams()`: enable height 0, which
 *  MEANS "vote extensions are not required" (:129-130), not "at height
 *  zero". */
void cmt_default_abci_params(cmt_abci_params_t *out);

/** params.go:86-94 — `DefaultConsensusParams()`. */
void cmt_default_consensus_params(cmt_consensus_params_t *out);

/* ── predicates and rules ───────────────────────────────────────────── */

/**
 * cometbft@709fd12b types/params.go:75-83 —
 * `ABCIParams.VoteExtensionsEnabled()`.
 * An enable height of 0 means never (:79-81); otherwise extensions are on
 * from that height upward (:82).
 * @return CMT_OK, or CMT_REJECT where the reference panics on `h < 1`
 *         (:76-78) — see "Return codes" in the file header.
 */
int cmt_abci_params_vote_extensions_enabled(cmt_abci_params_t a, int64_t h,
                                            bool *out);

/** cometbft@709fd12b types/params.go:134-141 — `IsValidPubkeyType()`.
 *  Membership of `pubkey_type` in the params' list. */
bool cmt_is_valid_pubkey_type(const cmt_validator_params_t *params,
                              const char *pubkey_type);

/**
 * cometbft@709fd12b types/params.go:145-206 — `ValidateBasic()`.
 * In the reference's own order: Block.MaxBytes must not be 0 (:146-148),
 * must be -1 or positive (:149-153) and at most MaxBlockSizeBytes
 * (:154-157); Block.MaxGas at least -1 (:159-162); Evidence.MaxAgeNumBlocks
 * positive (:164-167); Evidence.MaxAgeDuration positive (:169-172);
 * Evidence.MaxBytes at most the block bound, where a Block.MaxBytes of -1
 * counts as MaxBlockSizeBytes (:174-181) and then not negative (:183-186);
 * ABCI.VoteExtensionsEnableHeight not negative (:188-190); at least one
 * key type (:192-194); and every key type KNOWN (:196-203).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_consensus_params_validate_basic(const cmt_consensus_params_t *params);

/**
 * cometbft@709fd12b types/params.go:220-266 — `ValidateUpdate()`.
 * The ten-row table at :209-219, in the reference's order and with its
 * numbered comments carried into the code. `updated` may be NULL, which
 * is the reference's nil and returns success (:222-224).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL `params`.
 */
int cmt_consensus_params_validate_update(
        const cmt_consensus_params_t *params,
        const cmt_consensus_params_proto_t *updated, int64_t h);

/**
 * cometbft@709fd12b types/params.go:272-290 — `Hash()` — ConsensusHash.
 * H(marshal of HashedParams{Block.MaxBytes, Block.MaxGas}) — FLAT, no
 * Merkle. The reference panics on a marshal or hash failure (:281-283,
 * :286-288); both are return codes here.
 */
int cmt_consensus_params_hash(const cmt_consensus_params_t *params,
                              uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b types/params.go:294-323 — `Update()`.
 * Returns a COPY with the non-nil sub-messages of `params2` applied; the
 * original is not modified (:293, :295). A nil `params2` is a plain copy
 * (:297-299).
 *
 * ⚠ NOTE reference quirk, ported as-is: the comment at :292 says "updates
 * from the NON-ZERO fields of p2", but the code branches on each
 * sub-message being NON-NIL and then copies every field of it INCLUDING
 * zeros. A `Block{MaxBytes: 0}` therefore sets MaxBytes to 0, which
 * `ValidateBasic` would then refuse. The code is the authority; the
 * comment is wrong, and the port map records it as such.
 *
 * @return CMT_OK, CMT_REJECT if `params2->validator` lists more key types
 *         than CMT_PARAMS_MAX_PUBKEY_TYPES, CMT_FAULT on NULL.
 */
int cmt_consensus_params_update(const cmt_consensus_params_t *params,
                                const cmt_consensus_params_proto_t *params2,
                                cmt_consensus_params_t *out);

/* ── taşınmadı (not ported), with the reason ────────────────────────────
 *  · :325-346 `ToProto` and :348-370 `ConsensusParamsFromProto` —
 *    R2 STORE WORK. cmt_pb has no ConsensusParams message (only
 *    HashedParams, which is all any HASH needs), so there is nothing for
 *    them to convert to or from yet; adding one is the store's decision
 *    and this wave does not extend cmt_pb. `cmt_consensus_params_proto_t`
 *    above is the in-memory shape ValidateUpdate and Update need, and the
 *    two conversions between it and cmt_consensus_params_t are trivial —
 *    it is the WIRE they are missing, not the conversion.
 *
 *    ⚠ The quirk that lives in the unported half is recorded here so it is
 *    not lost: `ConsensusParamsFromProto` (:349-365) dereferences
 *    `pbParams.Block`, `.Evidence`, `.Validator` and `.Version` WITHOUT A
 *    NIL CHECK, while it does check `.Abci` at :366. A decoded message
 *    missing any of the first four crashes the reference. Whichever wave
 *    ports this must not reproduce the crash — Go's nil-pointer panic is
 *    exactly the fail-stop the APPROVED INVARIANT
 *    (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07) turns into an explicit
 *    refusal at the message boundary.
 *
 *  · :28-31 `ABCIPubKeyTypesToNames` — the reference maps an ABCI type
 *    name to an Amino key name. Only its KEY SET is used (:199), and only
 *    for membership, so this port carries the key set as a static array
 *    (see cmt_params.c) and no value side. The Amino names have no
 *    consumer in this port at all.
 *  · :24-25 `ABCIPubKeyTypeEd25519` / `ABCIPubKeyTypeSecp256k1` — this
 *    chain has neither key type. The ML-DSA-87 name that replaces them is
 *    the QUESTION above.
 */

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PARAMS_H */
