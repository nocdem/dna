/**
 * @file shared/dnac/cmt_part_set.h
 * @brief cometbft @709fd12b `types/part_set.go` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything in this file; it is additive only. The live witness
 * BFT, the QC V2 path and the T3 wave-1 modules (tm_commit, tm_vote,
 * tm_wal) are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A PartSet is how a block travels: the marshalled block is cut into
 * 65 536-byte parts, each carrying its Merkle inclusion proof against the
 * PartSet's root. That root and the part count ARE the PartSetHeader, and
 * the PartSetHeader is half of a BlockID (types/block.go:1463-1466) — so
 * it is inside every vote's sign bytes. Chunking is APPROVED and
 * un-parked (atlas-dec-6d35670369b69df4439cb720036fa2d7 rev 2).
 *
 * ── Domain ↔ wire ──────────────────────────────────────────────────────
 * `types.Part` and `types.PartSetHeader` are FIELD-IDENTICAL to R1-A's
 * `cmt_pb_part_t` and `cmt_pb_part_set_header_t` (same fields, same order,
 * same types), so each domain type is a typedef of the wire type and
 * `_to_proto` is the identity — exactly as R1-A did for `cmt_proof_t`
 * (cmt_pb.h:550-561). `_from_proto` is the identity FOLLOWED BY the
 * module's ValidateBasic, because the reference's are
 * (`part_set.go:111`, `:167`). The arena rule of cmt_pb.h is unchanged:
 * a decoded Part's payload lives in the caller's arena.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. SHA3-512 / 64-byte digests, via cmt_merkle (umbrella rev 3 item 4).
 * 2. NO MUTEX. The reference guards a PartSet with `cmtsync.Mutex`
 *    (part_set.go:182) and takes it in BitArray/AddPart/GetPart/…; this
 *    port is single-threaded (umbrella rev 3 item 4) and drops it.
 * 3. CALLER-PROVIDED STORAGE instead of Go slices: the caller supplies the
 *    `cmt_part_t` array and its capacity. A count above the derived bound
 *    CMT_PART_SET_MAX_PARTS is REFUSED, never truncated.
 * 4. panic → error return; every Go index panic becomes an explicit check
 *    (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 * 5. Go's five distinct error values (ErrPartTooBig, ErrPartInvalidSize,
 *    ErrPartSetUnexpectedIndex, ErrPartSetInvalidProof, ErrInvalidPart —
 *    part_set.go:18-36) all become CMT_REJECT; each C site names the
 *    reference error it stands for in a comment. The port has no error
 *    objects and no caller distinguishes them in the ported code.
 *
 * ⚠ PART PAYLOADS ARE NOT COPIED. `cmt_part_t.bytes` is a descriptor. In
 * NewPartSetFromData the parts point INTO the caller's `data` buffer,
 * exactly as the reference's `data[i*partSize : …]` slices point into
 * theirs (part_set.go:203). In AddPart the part struct is copied but its
 * payload is not, exactly as the reference stores the caller's `*Part`
 * (:326). The payload must outlive the part set.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments. No clock, no
 * randomness, no map, no unordered iteration: parts are hashed in index
 * order and the Merkle tree is cmt_merkle's, which preserves leaf order.
 * Two nodes splitting the same bytes at the same part size produce the
 * same root and the same per-part proofs.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `ErrInvalidPart.Error` (:30-32), `Unwrap` (:34-36), `Part.String`
 *     (:65-67), `Part.StringIndented` (:72-81), `PartSetHeader.String`
 *     (:125-127), `PartSet.StringShort` (:388-395) — display only.
 *   · `PartSet.MarshalJSON` (:397-412) — the port has no JSON surface for
 *     consensus objects (same reason as cmt_bits.h's).
 *
 * Reference @709fd12b (SHA-256 verified against tasks/comet-port-map.md
 * before use):
 *   types/part_set.go   412 lines 10101396b373475d18f81235a829c6d55341d2146ac2a667e851f650f5f44379
 *   types/params.go     370 lines 1766c8ec54f5932ce43c77f48a8358237b16428f3bddd69f2998e32a0c2e7746
 *   types/validation.go 427 lines 29ea9aa38bf65dcb68c27fcc0c6c4229e0a0f55814ce52c45c49cc06c7c14a7a
 *   crypto/merkle/proof.go 252 lines ddffde7a097d6a8d0ad3af25f559494065e535c8b7fa10aed66ed534ba07c907
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * chunking rev 2 (atlas-dec-6d35670369b69df4439cb720036fa2d7),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PART_SET_H
#define SHARED_DNAC_CMT_PART_SET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"       /* cmt_pb_part_t, cmt_pb_part_set_header_t, arena */
#include "cmt_merkle.h"   /* cmt_proof_t, cmt_merkle_*                      */
#include "cmt_bits.h"     /* cmt_bit_array_t, the derived part bound        */

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b types/params.go:19 — `BlockPartSizeBytes` = 65536.
 *  Restated from cmt_bits.h's copy so this module's reader sees it named
 *  as part_set.go names it; the two are the same macro value. */
#define CMT_BLOCK_PART_SIZE_BYTES CMT_BITS_BLOCK_PART_SIZE_BYTES

/** cometbft@709fd12b types/params.go:22 — `MaxBlockPartsCount` = 1601.
 *  The widest part set this port will build or accept; a `total` above it
 *  is REFUSED (INVARIANT 7495d337), never truncated. It is also exactly
 *  cmt_bits.h's CMT_BITS_MAX_BITS, so the parts bit array always fits. */
#define CMT_PART_SET_MAX_PARTS CMT_BITS_MAX_BLOCK_PARTS_COUNT

/** The reader has delivered every byte. POSITIVE, like CMT_BITS_NIL, so it
 *  is never confused with CMT_REJECT / CMT_FAULT: end of input is a normal
 *  outcome (the reference's `io.EOF`), not a failure. */
#define CMT_PART_SET_EOF 1

/**
 * cometbft@709fd12b types/validation.go:196-204 — `ValidateHash()`.
 *
 * THE ONLY validation.go ROW WAVE R1-B CARRIES. The rest of that file is
 * the VerifyCommit family, which needs a ValidatorSet and belongs to a
 * later stage. It lives in THIS header, rather than in cmt_block.h where
 * its Go file's other rows will go, because part_set.go:140 calls it and
 * cmt_block.h already includes this header for PartSetHeader — putting it
 * there would make the two headers include each other.
 *
 * "Empty is allowed; anything else must be exactly one digest wide."
 * tmhash.Size 32 → CMT_TMHASH_SIZE 64 (umbrella rev 3 item 4).
 *
 * @return CMT_OK or CMT_REJECT.
 */
int cmt_validate_hash(const uint8_t *h, size_t len);

/* ── Part (part_set.go:38-112) ──────────────────────────────────────── */

/** cometbft@709fd12b types/part_set.go:38-42 — `type Part struct`.
 *  Field-identical to cmt_pb_part_t {index, bytes, proof}; see the header. */
typedef cmt_pb_part_t cmt_part_t;

/**
 * cometbft@709fd12b types/part_set.go:45-60 — `(part *Part) ValidateBasic()`.
 *
 * Four checks, in the reference's order: the payload is at most one part
 * (:46-48, ErrPartTooBig); every part but the LAST carries exactly one
 * full part of payload (:50-52, ErrPartInvalidSize — note the comparison
 * is against `Proof.Total-1`, so the rule is driven by the proof, not by
 * the part set); the part index equals the proof index (:53-55); and the
 * proof itself validates (:56-58, cmt_proof_validate_basic).
 *
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on a NULL argument.
 */
int cmt_part_validate_basic(const cmt_part_t *part);

/**
 * cometbft@709fd12b types/part_set.go:83-95 — `(part *Part) ToProto()`.
 * The identity on this representation (the Go body copies Index, Bytes and
 * `Proof.ToProto()`, which crypto/merkle/proof.go:134-146 makes a
 * field-for-field copy). Present so the reference row has a C counterpart
 * and so call sites read alike.
 * @return CMT_OK, CMT_FAULT on NULL (the reference's "nil part" at :84-86).
 */
int cmt_part_to_proto(const cmt_part_t *part, cmt_pb_part_t *out);

/**
 * cometbft@709fd12b types/part_set.go:97-112 — `PartFromProto()`.
 * Copies the three fields and ends in ValidateBasic (:111), as every
 * FromProto in the reference does.
 * @return CMT_OK, CMT_REJECT if the proof or the part is invalid,
 *         CMT_FAULT on NULL.
 */
int cmt_part_from_proto(const cmt_pb_part_t *pb, cmt_part_t *out);

/* ── PartSetHeader (part_set.go:116-174) ────────────────────────────── */

/** cometbft@709fd12b types/part_set.go:116-119 —
 *  `type PartSetHeader struct`. Field-identical to
 *  cmt_pb_part_set_header_t {total, hash}; see the header. */
typedef cmt_pb_part_set_header_t cmt_part_set_header_t;

/** cometbft@709fd12b types/part_set.go:129-131 — `IsZero()`.
 *  A NULL header answers true: it is the zero value. */
bool cmt_psh_is_zero(const cmt_part_set_header_t *psh);

/** cometbft@709fd12b types/part_set.go:133-135 — `Equals()`. */
bool cmt_psh_equals(const cmt_part_set_header_t *psh,
                    const cmt_part_set_header_t *other);

/** cometbft@709fd12b types/part_set.go:138-144 — `ValidateBasic()`.
 *  The hash may be EMPTY (the POL BlockID of a Proposal carries none) but
 *  must otherwise be one digest wide.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_psh_validate_basic(const cmt_part_set_header_t *psh);

/** cometbft@709fd12b types/part_set.go:147-156 — `ToProto()`. The identity;
 *  a NULL receiver yields the zero header (:148-150). */
int cmt_psh_to_proto(const cmt_part_set_header_t *psh,
                     cmt_pb_part_set_header_t *out);

/** cometbft@709fd12b types/part_set.go:159-168 — `PartSetHeaderFromProto()`.
 *  Identity then ValidateBasic (:167). */
int cmt_psh_from_proto(const cmt_pb_part_set_header_t *ppsh,
                       cmt_part_set_header_t *out);

/** cometbft@709fd12b types/part_set.go:172-174 —
 *  `ProtoPartSetHeaderIsZero()`. The same predicate on the WIRE struct;
 *  block.go:1553-1555 calls it. On this representation it is the same
 *  function as cmt_psh_is_zero, kept separate so both reference rows have
 *  a C counterpart and so ported call sites read like the reference. */
bool cmt_proto_part_set_header_is_zero(const cmt_pb_part_set_header_t *ppsh);

/* ── PartSet (part_set.go:178-386) ──────────────────────────────────── */

/**
 * cometbft@709fd12b types/part_set.go:178-189 — `type PartSet struct`.
 * The `cmtsync.Mutex` of :182 is dropped (single-threaded port).
 *
 * `parts` is the caller's array of `total` slots. The reference's
 * `parts []*Part` uses a nil pointer for "not received yet"; here the
 * PRESENCE PREDICATE is `parts_bit_array` bit i, which the reference
 * keeps in lockstep with the slice anyway (it sets the bit wherever it
 * stores a part: :207 and :327). `parts_bit_array_nil` records the
 * reference's nil BitArray, which `bits.NewBitArray(0)` returns for an
 * empty part set (libs/bits/bit_array.go:26-28).
 */
typedef struct {
    uint32_t        total;                       /* part_set.go:179 */
    uint8_t         hash[CMT_TMHASH_SIZE];       /* :180 */
    size_t          hash_len;
    cmt_part_t     *parts;                       /* :183, caller-owned */
    size_t          parts_cap;
    cmt_bit_array_t parts_bit_array;             /* :184 */
    bool            parts_bit_array_nil;
    uint32_t        count;                       /* :185 */
    int64_t         byte_size;                   /* :188 */
} cmt_part_set_t;

/**
 * cometbft@709fd12b types/part_set.go:194-222 — `NewPartSetFromData()`.
 *
 * Splits `data` into ceil(len/part_size) parts, computes the Merkle root
 * over the part payloads and stores each part's inclusion proof (:210-213
 * — the transient `cmt_proof_t` array this needs is the C cost of the
 * reference's `[]*Proof`, allocated and freed inside).
 *
 * CONTRACT, as the reference's (:193): `part_size` must be greater than
 * zero — here it is CHECKED and a zero refuses, because C would divide by
 * zero where Go's caller never passes one.
 *
 * The parts point INTO `data`; see the header's payload note.
 *
 * @param parts caller storage for the parts; `parts_cap` slots.
 * @return CMT_OK; CMT_REJECT for part_size 0, a part count above
 *         CMT_PART_SET_MAX_PARTS or above `parts_cap`; CMT_FAULT on a
 *         NULL argument, an allocation failure or a hash backend failure.
 */
int cmt_new_part_set_from_data(const uint8_t *data, size_t data_len,
                               uint32_t part_size,
                               cmt_part_t *parts, size_t parts_cap,
                               cmt_part_set_t *out);

/**
 * cometbft@709fd12b types/part_set.go:225-234 — `NewPartSetFromHeader()`.
 * An empty part set ready to be filled by AddPart.
 * @return CMT_OK; CMT_REJECT if header->total exceeds
 *         CMT_PART_SET_MAX_PARTS or `parts_cap`; CMT_FAULT on NULL.
 */
int cmt_new_part_set_from_header(const cmt_part_set_header_t *header,
                                 cmt_part_t *parts, size_t parts_cap,
                                 cmt_part_set_t *out);

/** cometbft@709fd12b types/part_set.go:236-244 — `Header()`.
 *  A NULL part set yields the zero header (:237-239).
 *  @return CMT_OK, CMT_FAULT if `out` is NULL. */
int cmt_part_set_header(const cmt_part_set_t *ps, cmt_part_set_header_t *out);

/** cometbft@709fd12b types/part_set.go:246-251 — `HasHeader()`.
 *  A NULL part set answers false (:247-249). */
bool cmt_part_set_has_header(const cmt_part_set_t *ps,
                             const cmt_part_set_header_t *header);

/** cometbft@709fd12b types/part_set.go:253-257 — `BitArray()`. A COPY, as
 *  the reference returns one.
 *  @return CMT_OK, CMT_BITS_NIL when the reference's BitArray is nil (an
 *          empty part set), CMT_FAULT on NULL. */
int cmt_part_set_bit_array(const cmt_part_set_t *ps, cmt_bit_array_t *out);

/**
 * cometbft@709fd12b types/part_set.go:259-264 — `Hash()`.
 * A NULL part set answers `merkle.HashFromByteSlices(nil)` = H("")
 * (:260-262). A part set whose hash is not one digest wide is a shape a
 * wire PartSetHeader could carry; it is reported as CMT_REJECT here
 * rather than copied out short.
 * @return CMT_OK, CMT_REJECT for a short/absent hash on a non-NULL set,
 *         CMT_FAULT on a NULL `out` or a hash backend failure.
 */
int cmt_part_set_hash(const cmt_part_set_t *ps, uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@709fd12b types/part_set.go:266-271 — `HashesTo()`.
 *  A NULL part set answers false (:267-269). */
bool cmt_part_set_hashes_to(const cmt_part_set_t *ps,
                            const uint8_t *hash, size_t hash_len);

/** cometbft@709fd12b types/part_set.go:273-278 — `Count()`. NULL → 0. */
uint32_t cmt_part_set_count(const cmt_part_set_t *ps);

/** cometbft@709fd12b types/part_set.go:280-285 — `ByteSize()`. NULL → 0. */
int64_t cmt_part_set_byte_size(const cmt_part_set_t *ps);

/** cometbft@709fd12b types/part_set.go:287-292 — `Total()`. NULL → 0. */
uint32_t cmt_part_set_total(const cmt_part_set_t *ps);

/**
 * cometbft@709fd12b types/part_set.go:295-331 — `AddPart()`.
 *
 * CONTRACT, as the reference's (:294): the part has already passed
 * ValidateBasic.
 *
 * The reference's two-value return is split: `*added` is Go's bool and
 * the return code is Go's error. A NULL part set (:298-300) and a part
 * already held (:311-313) are `(false, nil)` — CMT_OK with `*added`
 * false. An index at or above `total` (:306-308) and a proof that does
 * not match the set (:316-323) are `(false, err)` — CMT_REJECT.
 *
 * INVARIANT 7495d337: the set's hash is checked to be one digest wide
 * BEFORE it is handed to cmt_proof_verify, which reads CMT_TMHASH_SIZE
 * bytes from it. Go's `bytes.Equal` would simply have failed on a shorter
 * slice; C would read past the end.
 *
 * @return CMT_OK (see `*added`), CMT_REJECT, CMT_FAULT on NULL or a hash
 *         backend failure.
 */
int cmt_part_set_add_part(cmt_part_set_t *ps, const cmt_part_t *part,
                          bool *added);

/**
 * cometbft@709fd12b types/part_set.go:333-337 — `GetPart()`.
 * @return the part, or NULL when there is none at `index` — which covers
 *         both the reference's nil slot and its out-of-range panic
 *         (`ps.parts[index]`, :336). The two are distinguishable by the
 *         caller from `index >= cmt_part_set_total(ps)`.
 */
const cmt_part_t *cmt_part_set_get_part(const cmt_part_set_t *ps,
                                        size_t index);

/** cometbft@709fd12b types/part_set.go:339-341 — `IsComplete()`.
 *  A NULL part set answers false; the reference has no nil check there
 *  and would panic on `ps.count`. */
bool cmt_part_set_is_complete(const cmt_part_set_t *ps);

/**
 * cometbft@709fd12b types/part_set.go:350-354 — `type PartSetReader struct`.
 * `off` replaces the reference's `*bytes.Reader`: the reader IS a cursor
 * over a part's payload, and a cursor is what a bytes.Reader is.
 */
typedef struct {
    const cmt_part_t *parts;   /* part_set.go:352 */
    size_t            n;
    size_t            i;       /* :351 */
    size_t            off;     /* the position inside parts[i].bytes */
} cmt_part_set_reader_t;

/** cometbft@709fd12b types/part_set.go:356-362 — `NewPartSetReader()`.
 *  @return CMT_OK; CMT_REJECT when `n` is 0 — the reference indexes
 *          `parts[0]` at :360 and panics; CMT_FAULT on NULL. */
int cmt_new_part_set_reader(const cmt_part_t *parts, size_t n,
                            cmt_part_set_reader_t *out);

/** cometbft@709fd12b types/part_set.go:343-348 — `GetReader()`.
 *  @return CMT_OK; CMT_REJECT on an incomplete part set — the reference
 *          panics there (:344-346); CMT_FAULT on NULL. */
int cmt_part_set_get_reader(const cmt_part_set_t *ps,
                            cmt_part_set_reader_t *out);

/**
 * cometbft@709fd12b types/part_set.go:364-383 — `(psr *PartSetReader) Read()`.
 *
 * Delivers the concatenation of the parts' payloads, crossing part
 * boundaries within one call exactly as the reference's recursion does
 * (:368-375).
 *
 * SHAPE, stated because it is the one thing that is not a literal
 * translation: the reference can return `(n > 0, io.EOF)` in a single
 * call, because its recursive tail propagates the EOF alongside the bytes
 * already copied. This returns CMT_OK for that short read and reports
 * CMT_PART_SET_EOF on the FOLLOWING call, which produces nothing. Both are
 * valid io.Reader behaviour and THE BYTE SEQUENCE DELIVERED IS IDENTICAL;
 * only the call at which the end is announced differs.
 *
 * A zero-length request is CMT_OK with `*n_out` 0, which is what the
 * reference's first branch returns for an empty `p` (:366-367).
 *
 * @param n_out receives the number of bytes written into `p`.
 * @return CMT_OK, CMT_PART_SET_EOF, CMT_FAULT on a NULL argument.
 */
int cmt_part_set_reader_read(cmt_part_set_reader_t *psr, uint8_t *p,
                             size_t len, size_t *n_out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PART_SET_H */
