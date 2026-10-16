/**
 * @file shared/dnac/cmt_light_block.h
 * @brief cometbft @v0.38.26 `types.LightBlock` (types/light.go:11-112)
 *        ported to C — the type, `ValidateBasic`, `ToProto` /
 *        `LightBlockFromProto`, `SignedHeader.ToProto` /
 *        `SignedHeaderFromProto` (:183-226) — plus the proto3 codec of the
 *        two wire messages `tendermint.types.SignedHeader` and
 *        `tendermint.types.LightBlock` (proto/tendermint/types/
 *        types.proto:156-164).
 *
 * ═══ STATUS: NO PRODUCTION CALLER ═══════════════════════════════════════
 * Package 1 of the light client for the bandwidth and storage roles
 * (decision docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-
 * role.md, B9; Kurultay #25 item 1, docs/plans/decisions/2026-10-16-
 * kurultay-25-summary.md: "LightBlock + ValidateBasic → store → client →
 * detector"). Its consumers in this package are cmt_light_store.c and
 * the provider interface (cmt_light_provider.h); nothing in a node calls
 * it yet. It sits in nodus's COMMON source list next to
 * cmt_light_verifier.c so that it compiles on Windows.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── THE TYPE ───────────────────────────────────────────────────────────
 * `type LightBlock struct { *SignedHeader; ValidatorSet *ValidatorSet }`
 * (:13-16). Both members are POINTERS that may be nil; so they are here,
 * and neither is owned — the `cmt_signed_header_t` convention of
 * cmt_light_verifier.h:130-139. A light block that this module DECODES
 * lives in a `cmt_light_block_buf_t`, which owns the header, the commit,
 * the signature list, the validator list and the two structs the
 * pointers aim at.
 *
 * ── THE WIRE ───────────────────────────────────────────────────────────
 *   message SignedHeader { Header header = 1; Commit commit = 2; }
 *   message LightBlock   { SignedHeader signed_header = 1;
 *                          tendermint.types.ValidatorSet validator_set = 2; }
 * (types.proto:156-164). All four fields are nullable message POINTERS:
 * the generated encoder writes each one iff it is non-nil, even when its
 * body is empty (`0a 00`) — types.pb.go:1964-1994 (SignedHeader) and
 * :2011-2041 (LightBlock). So the wire carries presence, and the proto
 * structs below carry a `has_*` flag per field. The embedded Header,
 * Commit and ValidatorSet are written and read through cmt_pb's PUBLIC
 * `_marshal` / `_unmarshal` (cmt_pb.h:529-533), the pattern
 * cmt_pb_store.c established (cmt_pb_store.c:22-56).
 *
 * ── DEVIATIONS, each forced by a port type or the port's rules ─────────
 *  · `block_protocol` is a PARAMETER wherever `HeaderFromProto` or
 *    `Header.ValidateBasic` is reached (`cmt_light_block_validate_basic`,
 *    `cmt_signed_header_from_proto`, `cmt_light_block_from_proto`,
 *    `cmt_light_block_decode`) — the value Version.Block must equal, the
 *    host's, normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *    `version.BlockProtocol` is a build-time constant of the reference
 *    binary and a chain parameter here (cmt_light_verifier.h:47-53).
 *  · A SECOND occurrence of a nested message field REPLACES rather than
 *    merges, at the cmt_pb level: a duplicate `header`, `commit` or
 *    `validator_set` is decoded with cmt_pb's public `_unmarshal`, which
 *    INITS before it merges, where the generated decoder merges into the
 *    existing message (types.pb.go:4800-4803, :4836-4839, :4958-4961).
 *    The same DEVIATION cmt_pb_store.h:55-61 records, for the same
 *    reason; byte streams this port writes never carry a field twice.
 *    A duplicate `signed_header` (:4922-4925) DOES merge — its decoder is
 *    this file's own.
 *  · The capacity rule of cmt_pb.h: the decoder refuses a commit with
 *    more than CMT_VALSET_MAX signatures or a set with more than
 *    CMT_VALSET_MAX validators (cmt_validator_set.h:173, the release's
 *    active-set ceiling) — the storage a `cmt_light_block_buf_t` holds.
 *    The reference has no count bound.
 *  · Go's nil-pointer receivers: `ToProto` on a nil LightBlock returns
 *    (nil, nil) (:67-69) and `LightBlockFromProto(nil)` returns an error
 *    (:89-91). A NULL pointer here is a caller's programming error that
 *    cannot arrive from the wire, so both are CMT_FAULT — deviation
 *    register R1B-10 (cmt_evidence.h:56). A nil member INSIDE a light
 *    block (no signed header, no validator set, no header, no commit) is
 *    an optional proto field a peer can leave out and stays what the
 *    reference makes it (an error where it returns one, an absent field
 *    where it does not) — the reasoning of cmt_light_verifier.h:62-70.
 *  · Error TEXT is not carried: every `errors.New` / `fmt.Errorf` is
 *    CMT_REJECT.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function is a pure function of its arguments. No clock, no
 * randomness, no map, no floating point. Validators and signatures are
 * visited in list order. The only allocations are the leaf scratch of
 * `ValidatorSet.Hash()` in `cmt_light_block_validate_basic` (freed before
 * return, as cmt_light_verifier.c:198-225 does), the proto scratch of
 * `cmt_light_block_encode` / `cmt_light_block_decode` (freed before
 * return) and the buffer `cmt_light_block_encode` hands to its caller.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *  types/light.go
 *   · :46-63 `String` / `StringIndented`, :164-181 SignedHeader's —
 *     display only.
 *   · :123-126 `SignedHeader.IsEmpty` — no caller in the packages the
 *     light client needs from this file; it is a one-line test the
 *     caller can make on the two pointers.
 *
 * Reference @v0.38.26:
 *   types/light.go                 226 lines
 *     513cfd434dadf086a27daaa29a35a3014a356d684dbd89b0f931e6c0c5ea157d
 *     (the SHA-256 cmt_light_verifier.h:101-102 records)
 *   proto/tendermint/types/types.proto :156-164
 *   proto/tendermint/types/types.pb.go :1949-2041 (Marshal),
 *     :4742-4985 (Unmarshal)
 * Governing records: pin decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md; Kurultay #25
 * and the bandwidth role decision above.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_BLOCK_H
#define SHARED_DNAC_CMT_LIGHT_BLOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_pb.h"              /* cmt_pb_header_t, cmt_pb_commit_t, ... */
#include "cmt_block.h"           /* cmt_header_t, cmt_commit_t            */
#include "cmt_validator_set.h"   /* cmt_validator_set_t, CMT_VALSET_MAX   */
#include "cmt_light_verifier.h"  /* cmt_signed_header_t                   */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ types/light.go — LightBlock ══════════════════════════════════════ */

/**
 * cometbft@v0.38.26 types/light.go:11-16 — `type LightBlock struct`:
 * "a SignedHeader and a ValidatorSet. It is the basis of the light
 * client". Both members are POINTERS in the reference and may be nil; so
 * they are here, and neither is owned. `validator_set` is NOT const: the
 * verifier writes its TotalVotingPower cache, as in the reference
 * (cmt_light_verifier.h:250-252).
 */
typedef struct {
    const cmt_signed_header_t *signed_header;  /* light.go:14 `*SignedHeader` (embedded) */
    cmt_validator_set_t       *validator_set;  /* light.go:15 `ValidatorSet *ValidatorSet` */
} cmt_light_block_t;

/**
 * cometbft@v0.38.26 types/light.go:18-44 — `(lb LightBlock)
 * ValidateBasic(chainID)`: "checks that the data is correct and
 * consistent … This does no verification of the signatures".
 *
 * In the reference's order: a signed header is present (:22-24) and a
 * validator set is present (:25-27) — both CMT_REJECT, see the file
 * header —; the signed header passes `SignedHeader.ValidateBasic`
 * (:29-31, `cmt_signed_header_validate_basic`), the set passes
 * `ValidatorSet.ValidateBasic` (:32-34); and the header's ValidatorsHash
 * equals the set's hash (:36-41, `bytes.Equal`).
 *
 * `ValidatorSet.Hash()` needs leaf scratch in this port
 * (cmt_validator_set.h:703-724); it is heap-allocated here and freed
 * before return, as cmt_light_verifier.c:198-225 does.
 *
 * @param block_protocol the value Version.Block must equal — see the file
 *        header.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on a NULL `lb` (the reference
 *         takes it by value), a NULL `chain_id` with a non-zero length,
 *         a set above CMT_VALSET_MAX (the type's own invariant), or an
 *         allocation / hash backend failure.
 */
int cmt_light_block_validate_basic(const cmt_light_block_t *lb,
                                   const uint8_t *chain_id,
                                   size_t chain_id_len,
                                   uint64_t block_protocol);

/* ══ proto/tendermint/types/types.proto:156-164 — the wire messages ═══ */

/** types.proto:156-159 — `SignedHeader`. Both fields are POINTERS: absent
 *  when `has_*` is false. `commit.signatures` is caller-owned storage
 *  (cmt_pb_commit_t's own rule, cmt_pb.h:308-317). */
typedef struct {
    bool            has_header;     /* field 1, POINTER */
    cmt_pb_header_t header;
    bool            has_commit;     /* field 2, POINTER */
    cmt_pb_commit_t commit;
} cmt_pb_signed_header_t;

/** types.proto:161-164 — `LightBlock`. Both fields are POINTERS.
 *  `validator_set.validators` is caller-owned storage (cmt_pb.h:236-246). */
typedef struct {
    bool                   has_signed_header;  /* field 1, POINTER */
    cmt_pb_signed_header_t signed_header;
    bool                   has_validator_set;  /* field 2, POINTER */
    cmt_pb_validator_set_t validator_set;
} cmt_pb_light_block_t;

/**
 * The reference's zero value: every field absent. The caller's storage
 * pointers and capacities (`signed_header.commit.signatures`,
 * `validator_set.validators`) SURVIVE, exactly as cmt_pb_commit_init and
 * cmt_pb_validator_set_init keep them (cmt_pb.c:1210-1224, :2040-2053).
 */
void cmt_pb_signed_header_init(cmt_pb_signed_header_t *m);
void cmt_pb_light_block_init(cmt_pb_light_block_t *m);

/**
 * A buffer size that always fits the marshalled LightBlock whose commit
 * carries at most `n_signatures` entries and whose set carries at most
 * `n_validators` members. Derived field by field in cmt_light_block.c
 * (every scalar at its widest varint). Returns 0 if either count is above
 * CMT_VALSET_MAX.
 */
size_t cmt_pb_light_block_upper_bound(size_t n_validators,
                                      size_t n_signatures);

/** types.pb.go:1964-1994 — SignedHeader.MarshalToSizedBuffer: field 2
 *  (commit) iff present, then field 1 (header) iff present, written
 *  backwards — so on the wire field 1 comes first.
 *  @return CMT_OK, CMT_REJECT if it does not fit or a field is malformed,
 *          CMT_FAULT on NULL. */
int cmt_pb_signed_header_marshal(const cmt_pb_signed_header_t *m,
                                 uint8_t *out, size_t cap, size_t *out_len);

/** types.pb.go:4742-4863 — SignedHeader.Unmarshal. Unknown fields are
 *  skipped by wire type (:4843-4856). See the file header for the
 *  duplicate-field DEVIATION. Calls `cmt_pb_signed_header_init` first.
 *  @return CMT_OK, CMT_REJECT on malformed / over-capacity input,
 *          CMT_FAULT on NULL. */
int cmt_pb_signed_header_unmarshal(const uint8_t *in, size_t len,
                                   cmt_pb_signed_header_t *m);

/** types.pb.go:2011-2041 — LightBlock.MarshalToSizedBuffer: field 2
 *  (validator_set) iff present, then field 1 (signed_header) iff
 *  present, written backwards.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT as above. */
int cmt_pb_light_block_marshal(const cmt_pb_light_block_t *m,
                               uint8_t *out, size_t cap, size_t *out_len);

/** types.pb.go:4864-4985 — LightBlock.Unmarshal. Calls
 *  `cmt_pb_light_block_init` first.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT as above. */
int cmt_pb_light_block_unmarshal(const uint8_t *in, size_t len,
                                 cmt_pb_light_block_t *m);

/* ══ types/light.go — ToProto / FromProto ═════════════════════════════ */

/**
 * cometbft@v0.38.26 types/light.go:183-198 — `(sh *SignedHeader)
 * ToProto()`. `has_header` iff the header pointer is non-nil (:190-192,
 * `Header.ToProto` — the identity, cmt_block.h:432-434); `has_commit`
 * iff the commit pointer is non-nil (:193-195, `Commit.ToProto` — the
 * identity, cmt_block.h:596-597, so `out->commit.signatures` ALIASES the
 * source commit's list).
 * @return CMT_OK; CMT_FAULT on NULL (a nil receiver returns nil at
 *         :185-187 — R1B-10, see the file header).
 */
int cmt_signed_header_to_proto(const cmt_signed_header_t *sh,
                               cmt_pb_signed_header_t *out);

/**
 * cometbft@v0.38.26 types/light.go:200-226 — `SignedHeaderFromProto()`:
 * "returns an error if the header or the commit is invalid". A present
 * header goes through `HeaderFromProto` (:209-215 — BlockIDFromProto +
 * ValidateBasic, cmt_block.h:436-445) into `*h`; a present commit
 * through `CommitFromProto` (:217-223 — every entry + ValidateBasic,
 * cmt_block.h:599-603) into `*c` with `sigs` as its list. An absent field
 * leaves the matching pointer of `*out` NULL. The header / commit
 * CONSISTENCY is not checked here, by the reference either — that is
 * `SignedHeader.ValidateBasic`.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on NULL (a nil proto is an error
 *         at :203-205 — R1B-10).
 */
int cmt_signed_header_from_proto(const cmt_pb_signed_header_t *shp,
                                 uint64_t block_protocol,
                                 cmt_header_t *h,
                                 cmt_commit_sig_t *sigs, size_t sigs_cap,
                                 cmt_commit_t *c,
                                 cmt_signed_header_t *out);

/**
 * cometbft@v0.38.26 types/light.go:65-84 — `(lb *LightBlock) ToProto()`.
 * `has_signed_header` iff `lb->signed_header` is non-NULL (:73-75);
 * `has_validator_set` iff `lb->validator_set` is non-NULL (:76-81,
 * `ValidatorSet.ToProto` — an empty set is an EMPTY message, not an
 * error, and the PROTO's `total_voting_power` field is written as 0 —
 * validator_set.go:954-956; the set's own cached total is untouched;
 * cmt_validator_set.h:1023-1037).
 *
 * @param out `out->validator_set.validators` must point at caller
 *        storage of at least `lb->validator_set->validators_len` slots.
 *        `out->signed_header.commit.signatures` aliases the source.
 * @return CMT_OK, CMT_REJECT (`ValidatorSet.ToProto` errors, :77-80 —
 *         e.g. a non-empty set without a proposer); CMT_FAULT on NULL.
 */
int cmt_light_block_to_proto(const cmt_light_block_t *lb,
                             cmt_pb_light_block_t *out);

/**
 * Owned storage for ONE decoded light block: everything the two pointers
 * of `lb` aim at. ⚠ NEVER A STACK OBJECT — `sizeof` is above one
 * megabyte (CMT_VALSET_MAX signatures of 4627 bytes plus CMT_VALSET_MAX
 * validators carrying a 2592-byte key); allocate it with
 * `cmt_light_block_buf_new`. After a successful decode, `lb` is the
 * light block, and its pointers aim INTO this struct (or are NULL for an
 * absent field).
 */
typedef struct {
    cmt_header_t        header;
    cmt_commit_sig_t    sigs[CMT_VALSET_MAX];
    cmt_commit_t        commit;
    cmt_signed_header_t signed_header;
    cmt_validator_t     validators[CMT_VALSET_MAX];
    cmt_validator_set_t validator_set;
    cmt_light_block_t   lb;
} cmt_light_block_buf_t;

/** A zeroed, heap-allocated buffer whose `lb` is the empty light block
 *  (both pointers NULL). NULL on allocation failure. */
cmt_light_block_buf_t *cmt_light_block_buf_new(void);

/** Free a buffer from `cmt_light_block_buf_new`. NULL is a no-op. */
void cmt_light_block_buf_free(cmt_light_block_buf_t *b);

/** Reset `b->lb` to the empty light block (both pointers NULL) and
 *  re-bind the set to the buffer's own storage. Every decode below calls
 *  it first; a caller uses it to clear a result it will not fill.
 *  @return CMT_OK; CMT_FAULT on NULL. */
int cmt_light_block_buf_reset(cmt_light_block_buf_t *b);

/**
 * cometbft@v0.38.26 types/light.go:86-112 — `LightBlockFromProto()`:
 * "An error is returned if either the validator set or signed header are
 * invalid". A present signed header goes through `SignedHeaderFromProto`
 * (:95-101); a present set through `ValidatorSetFromProto` (:103-109 —
 * recomputed total, ValidateBasic; cmt_validator_set.h:1039-1059). An
 * absent field leaves the matching pointer of `out->lb` NULL. NOT
 * `LightBlock.ValidateBasic`: the reference does not call it here.
 *
 * `out` is fully reset first, so nothing of an earlier decode survives
 * a failed one: on CMT_REJECT / CMT_FAULT `out->lb` is the empty light
 * block.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on NULL (R1B-10).
 */
int cmt_light_block_from_proto(const cmt_pb_light_block_t *pb,
                               uint64_t block_protocol,
                               cmt_light_block_buf_t *out);

/**
 * `lb.ToProto()` followed by `lbpb.Marshal()` — the two steps the
 * reference's store takes (light/store/db/db.go:47-55). Allocates the
 * proto scratch (freed before return) and the result: on CMT_OK `*out`
 * is a malloc'd buffer of `*out_len` bytes the caller frees with free();
 * on any other return `*out` is NULL.
 * @return CMT_OK, CMT_REJECT (ToProto / Marshal errors), CMT_FAULT on
 *         NULL, a set above CMT_VALSET_MAX, or allocation failure.
 */
int cmt_light_block_encode(const cmt_light_block_t *lb,
                           uint8_t **out, size_t *out_len);

/**
 * `lbpb.Unmarshal(bz)` followed by `LightBlockFromProto(&lbpb)` — the two
 * steps the reference's store takes (db.go:120-129). Allocates the proto
 * scratch and frees it before return. Every read is bounds-checked
 * against `len` (cmt_pb_wire.h).
 * @return CMT_OK, CMT_REJECT (malformed / over-capacity bytes or an
 *         invalid member), CMT_FAULT on NULL or allocation failure.
 */
int cmt_light_block_decode(const uint8_t *in, size_t len,
                           uint64_t block_protocol,
                           cmt_light_block_buf_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_BLOCK_H */
