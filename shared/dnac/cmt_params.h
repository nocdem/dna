/**
 * @file shared/dnac/cmt_params.h
 * @brief cometbft @v0.38.26 `types/params.go` ported to C — the consensus
 *        parameters and the ConsensusHash.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-C of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── ConsensusHash is FLAT, not Merkle ──────────────────────────────────
 * `ConsensusParams.Hash()` (params.go:275-293) hashes the marshalled
 * `HashedParams{BlockMaxBytes, BlockMaxGas}` DIRECTLY — the reference's
 * own comment at :273-274 says "No need for a Merkle tree here, just a
 * small struct to hash". So the header leaf ConsensusHash commits ONLY
 * those two numbers, and every other parameter (evidence bounds, key
 * types, app version, vote-extension height) is deliberately outside it,
 * which is what lets the parameter set evolve without a header change
 * (:271-274). D-19 rev 6 item 6 records the same.
 *
 * A DIRECT CONSEQUENCE, stated because it decides a question below: the
 * public-key TYPE NAME is not consensus-critical. It is compared, it is
 * validated, and it is never hashed.
 *
 * ── QUESTION FOR THE OPERATOR — the ML-DSA-87 type name ────────────────
 * `ABCIPubKeyTypeEd25519` (params.go:25) is the string `ed25519.KeyType`.
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
 * (:284-286, :289-291) and `VoteExtensionsEnabled`'s `h < 1` panic
 * (:79-81). Neither is `updateTotalVotingPower`'s case — each is a
 * deterministic property of its arguments, so every honest node reaches
 * the same verdict on the same values.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure functions. No clock, no randomness, no allocation. The reference's
 * one map, `ABCIPubKeyTypesToNames` (:28-31; 709fd12b; at v0.38.26: :30-34, with a third row, mldsa65 — not ported), is used for MEMBERSHIP only
 * (`_, ok := ...` at :202) and is never iterated, so it becomes a sorted
 * static array here with no ordering consequence.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   types/params.go 373 lines
 *     91eb26952c7daf48d88c14de3b5e1d2a9008f67be1808512a4a121794902e0ee
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
 * params.go:17, :20 and :23 are ALREADY in cmt_bits.h (:87-93), which
 * derives its BitArray bound from them. They are referenced here, never
 * redefined, so the tree keeps ONE definition of each. */

/** cometbft@v0.38.26 types/params.go:17 — `MaxBlockSizeBytes` (100 MB). */
#define CMT_MAX_BLOCK_SIZE_BYTES  CMT_BITS_MAX_BLOCK_SIZE_BYTES
/** cometbft@v0.38.26 types/params.go:20 — `BlockPartSizeBytes` (64 kB). */
#define CMT_BLOCK_PART_SIZE_BYTES CMT_BITS_BLOCK_PART_SIZE_BYTES
/** cometbft@v0.38.26 types/params.go:23 — `MaxBlockPartsCount`. */
#define CMT_MAX_BLOCK_PARTS_COUNT CMT_BITS_MAX_BLOCK_PARTS_COUNT

/**
 * The name of this chain's one public-key type.
 *
 * QUESTION (operator): the reference's counterpart is
 * `ABCIPubKeyTypeEd25519 = ed25519.KeyType` (params.go:25), a string.
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

/* ── the parameter structs (params.go:38-74) ────────────────────────── */

/** params.go:48-51 — `BlockParams`. */
typedef struct {
    int64_t max_bytes;   /* :49 */
    int64_t max_gas;     /* :50 */
} cmt_block_params_t;

/**
 * params.go:54-58 — `EvidenceParams`.
 * `MaxAgeDuration` is a Go `time.Duration`, i.e. an int64 count of
 * NANOSECONDS; the name says so here so a caller cannot read it as
 * seconds.
 */
typedef struct {
    int64_t max_age_num_blocks;  /* :55 */
    int64_t max_age_duration_ns; /* :56 */
    int64_t max_bytes;           /* :57 */
} cmt_evidence_params_t;

/**
 * params.go:62-64 — `ValidatorParams`. The reference's `[]string` becomes
 * fixed-width NUL-terminated storage: a `const char *` array would make
 * the struct own lifetimes it cannot see, and `Update` (:317) COPIES the
 * list precisely so the result does not alias its input.
 */
typedef struct {
    char   pub_key_types[CMT_PARAMS_MAX_PUBKEY_TYPES]
                        [CMT_PARAMS_PUBKEY_TYPE_MAX];   /* :63 */
    size_t pub_key_types_len;
} cmt_validator_params_t;

/** params.go:66-68 — `VersionParams`. */
typedef struct {
    uint64_t app;    /* :67 */
} cmt_version_params_t;

/** params.go:72-74 — `ABCIParams`. */
typedef struct {
    int64_t vote_extensions_enable_height;   /* :73 */
} cmt_abci_params_t;

/** params.go:38-44 — `ConsensusParams`. */
typedef struct {
    cmt_block_params_t     block;      /* :39 */
    cmt_evidence_params_t  evidence;   /* :40 */
    cmt_validator_params_t validator;  /* :41 */
    cmt_version_params_t   version;    /* :42 */
    cmt_abci_params_t      abci;       /* :43 */
} cmt_consensus_params_t;

/**
 * The POINTER-SHAPED `cmtproto.ConsensusParams` that `ValidateUpdate`
 * (:223) and `Update` (:297) take.
 *
 * Each sub-message's NIL-NESS is load-bearing in BOTH of them —
 * `updated == nil || updated.Abci == nil` returns nil immediately (:225),
 * and `Update` copies a field only when its sub-message is non-nil
 * (:305-324). So the nil-ness is carried explicitly rather than being
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

/* ── constructors (params.go:89-135) ────────────────────────────────── */

/** params.go:100-105 — `DefaultBlockParams()`: 22020096 bytes, MaxGas -1. */
void cmt_default_block_params(cmt_block_params_t *out);

/** params.go:108-114 — `DefaultEvidenceParams()`: 100000 blocks,
 *  48 hours expressed in nanoseconds, 1048576 bytes. */
void cmt_default_evidence_params(cmt_evidence_params_t *out);

/** params.go:118-122 — `DefaultValidatorParams()`. The reference allows
 *  only ed25519; this port allows only CMT_PUBKEY_TYPE_MLDSA87_NAME. */
void cmt_default_validator_params(cmt_validator_params_t *out);

/** params.go:124-128 — `DefaultVersionParams()`: App 0. */
void cmt_default_version_params(cmt_version_params_t *out);

/** params.go:130-135 — `DefaultABCIParams()`: enable height 0, which
 *  MEANS "vote extensions are not required" (:132-133), not "at height
 *  zero". */
void cmt_default_abci_params(cmt_abci_params_t *out);

/** params.go:89-97 — `DefaultConsensusParams()`. */
void cmt_default_consensus_params(cmt_consensus_params_t *out);

/* ── predicates and rules ───────────────────────────────────────────── */

/**
 * cometbft@v0.38.26 types/params.go:78-86 —
 * `ABCIParams.VoteExtensionsEnabled()`.
 * An enable height of 0 means never (:82-84); otherwise extensions are on
 * from that height upward (:85).
 * @return CMT_OK, or CMT_REJECT where the reference panics on `h < 1`
 *         (:79-81) — see "Return codes" in the file header.
 */
int cmt_abci_params_vote_extensions_enabled(cmt_abci_params_t a, int64_t h,
                                            bool *out);

/** cometbft@v0.38.26 types/params.go:137-144 — `IsValidPubkeyType()`.
 *  Membership of `pubkey_type` in the params' list. */
bool cmt_is_valid_pubkey_type(const cmt_validator_params_t *params,
                              const char *pubkey_type);

/**
 * cometbft@v0.38.26 types/params.go:148-209 — `ValidateBasic()`.
 * In the reference's own order: Block.MaxBytes must not be 0 (:149-151),
 * must be -1 or positive (:152-156) and at most MaxBlockSizeBytes
 * (:157-160); Block.MaxGas at least -1 (:162-165); Evidence.MaxAgeNumBlocks
 * positive (:167-170); Evidence.MaxAgeDuration positive (:172-175);
 * Evidence.MaxBytes at most the block bound, where a Block.MaxBytes of -1
 * counts as MaxBlockSizeBytes (:177-184) and then not negative (:186-189);
 * ABCI.VoteExtensionsEnableHeight not negative (:191-193); at least one
 * key type (:195-197); and every key type KNOWN (:199-206).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_consensus_params_validate_basic(const cmt_consensus_params_t *params);

/**
 * cometbft@v0.38.26 types/params.go:223-269 — `ValidateUpdate()`.
 * The ten-row table at :212-222, in the reference's order and with its
 * numbered comments carried into the code. `updated` may be NULL, which
 * is the reference's nil and returns success (:225-227).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL `params`.
 */
int cmt_consensus_params_validate_update(
        const cmt_consensus_params_t *params,
        const cmt_consensus_params_proto_t *updated, int64_t h);

/**
 * cometbft@v0.38.26 types/params.go:275-293 — `Hash()` — ConsensusHash.
 * H(marshal of HashedParams{Block.MaxBytes, Block.MaxGas}) — FLAT, no
 * Merkle. The reference panics on a marshal or hash failure (:284-286,
 * :289-291); both are return codes here.
 */
int cmt_consensus_params_hash(const cmt_consensus_params_t *params,
                              uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@v0.38.26 types/params.go:297-326 — `Update()`.
 * Returns a COPY with the non-nil sub-messages of `params2` applied; the
 * original is not modified (:296, :298). A nil `params2` is a plain copy
 * (:300-302).
 *
 * ⚠ NOTE reference quirk, ported as-is: the comment at :295 says "updates
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
 *  · :328-349 `ToProto` and :351-373 `ConsensusParamsFromProto` —
 *    R2 STORE WORK. cmt_pb has no ConsensusParams message (only
 *    HashedParams, which is all any HASH needs), so there is nothing for
 *    them to convert to or from yet; adding one is the store's decision
 *    and this wave does not extend cmt_pb. `cmt_consensus_params_proto_t`
 *    above is the in-memory shape ValidateUpdate and Update need, and the
 *    two conversions between it and cmt_consensus_params_t are trivial —
 *    it is the WIRE they are missing, not the conversion.
 *
 *    ⚠ The quirk that lives in the unported half is recorded here so it is
 *    not lost: `ConsensusParamsFromProto` (:352-368) dereferences
 *    `pbParams.Block`, `.Evidence`, `.Validator` and `.Version` WITHOUT A
 *    NIL CHECK, while it does check `.Abci` at :369. A decoded message
 *    missing any of the first four crashes the reference. Whichever wave
 *    ports this must not reproduce the crash — Go's nil-pointer panic is
 *    exactly the fail-stop the APPROVED INVARIANT
 *    (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07) turns into an explicit
 *    refusal at the message boundary.
 *
 *  · :28-31 `ABCIPubKeyTypesToNames` (709fd12b; at v0.38.26: :30-34, with a third row, mldsa65 — not ported) — the reference maps an ABCI type
 *    name to an Amino key name. Only its KEY SET is used (:202), and only
 *    for membership, so this port carries the key set as a static array
 *    (see cmt_params.c) and no value side. The Amino names have no
 *    consumer in this port at all.
 *  · :25-26 `ABCIPubKeyTypeEd25519` / `ABCIPubKeyTypeSecp256k1` — this
 *    chain has neither key type. The ML-DSA-87 name that replaces them is
 *    the QUESTION above.
 */

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PARAMS_H */
