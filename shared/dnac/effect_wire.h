/**
 * @file shared/dnac/effect_wire.h
 * @brief Ledger V2 — generic TYPED-EFFECT RESULT codec (INACTIVE).
 *
 * A typed-effect RESULT is the canonical, bounded, deterministic
 * representation of the state mutations a trusted compiled domain runtime
 * proposes for ONE transaction leg.
 *
 * The generic layer sees only generic mutation KINDS (CREATE / SET /
 * DELETE) plus opaque keys and values namespaced by a compiled adapter
 * operation id. It carries NO SQL, NO table or schema names, NO callbacks,
 * and NO domain id — the authoritative domain is engine-supplied CONTEXT,
 * exactly as `chain_id` / `ruleset_hash` are contextual to env_wire.h. A
 * result therefore says WHAT changes, never WHERE the runtime keeps it.
 *
 * ACTIVATION: nothing in the live consensus path calls anything here. This
 * codec activates only with the Ledger V2 devnet reset. The encoding exists
 * for validation, ordering, testing, metering and future versioning, and is
 * deliberately NOT added to envelope v1, tx V3, BlockHeader, BlockID,
 * DomainUpdate, or ANY commitment.
 *
 * Conventions (identical discipline to env_wire.h / vset_wire.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, BIG-ENDIAN; counts are u16;
 *   - no native struct serialization — the wire layout below IS the format;
 *   - records are STRICTLY ascending under the total order documented below
 *     (rejects duplicates AND non-canonical order), so exactly ONE encoding
 *     exists per result;
 *   - malformed/oversized input is REJECTED, never clamped or repaired;
 *   - every failure path returns -1 and produces no USABLE result: decode
 *     zeroes its view, encode leaves *written_out == 0, and the value-hash
 *     helper leaves its digest buffer untouched (see its contract for the
 *     one backend-fault caveat).
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded ASCII) ───────────────
 *   "DNA.EFFRES.v1"   wire family marker — literally the first 16 bytes of
 *                     every encoded result
 *   "DNA.EFFVAL.v1"   value hash (dna_effect_value_hash); the ONE hash this
 *                     module defines
 *
 * ── Canonical wire layout ──────────────────────────────────────────────
 * Fixed head (DNA_EFFECT_FIXED_HEAD = 23 bytes)
 *   off  0  wire_family[16]   "DNA.EFFRES.v1" zero-padded
 *   off 16  result_version u8  (= DNA_EFFECT_RESULT_VERSION; any other
 *                               value is REJECTED, never tolerated)
 *   off 17  effect_count  u16 BE  0 .. DNA_EFFECT_MAX_COUNT inclusive.
 *                               0 is a VALID EMPTY result: a leg that
 *                               mutates nothing.
 *   off 19  reserved      u32 BE  MUST be 0 (reject otherwise)
 *
 * Then effect_count records, record i at 23 + 84*i
 * (DNA_EFFECT_RECORD_LEN = 84 bytes)
 *   +0   op_id            u32 BE   compiled adapter operation identifier.
 *                                  The codec accepts ANY u32 — whether an
 *                                  op exists is the adapter layer's
 *                                  decision, not framing's.
 *   +4   effect_kind      u8       CREATE(1) | SET(2) | DELETE(3);
 *                                  0 and anything above 3 are REJECTED
 *   +5   precond_tag      u8       ABSENT(1) | EXISTS(2) |
 *                                  EXISTS_VERSION(3) | EXISTS_VHASH(4);
 *                                  0 and anything above 4 are REJECTED
 *   +6   expected_version u64 BE   MUST be 0 unless precond_tag == 3
 *   +14  expected_vhash[64]        MUST be all-zero unless precond_tag == 4
 *   +78  key_len          u16 BE   in [1, DNA_EFFECT_MAX_KEY_LEN]
 *   +80  value_len        u32 BE   in [0, DNA_EFFECT_MAX_VALUE_LEN];
 *                                  MUST be 0 when effect_kind == DELETE
 *
 * The expected_version / expected_vhash rules are RESERVED-FIELD MISUSE
 * gates, not conveniences: a field that no precondition consumes must be
 * zero on the wire, or two encodings of the same result would exist.
 *
 * Then ALL key blobs in record order, then ALL value blobs in record order
 * (the two sections are contiguous, never interleaved — same section
 * discipline as env_wire.h):
 *   KEY_BASE(n) = 23 + 84*n
 *   key_off(i)  = KEY_BASE(n) + Σ key_len[j],   j < i
 *   VAL_BASE(n) = KEY_BASE(n) + Σ key_len[j],   j < n
 *   val_off(i)  = VAL_BASE(n) + Σ value_len[j], j < i
 *   TOTAL       = VAL_BASE(n) + Σ value_len[j], j < n
 * TOTAL must be <= DNA_EFFECT_MAX_TOTAL_LEN. The bound is INCLUSIVE: a
 * result of exactly DNA_EFFECT_MAX_TOTAL_LEN bytes is valid.
 *
 * dna_effect_result_decode requires src_len to EQUAL TOTAL exactly —
 * truncation AND trailing bytes are both rejected.
 *
 * ── KIND / PRECONDITION LEGALITY ───────────────────────────────────────
 * A BICONDITIONAL, checked before anything else can consume the effect:
 *
 *     (effect_kind == CREATE)  ⇔  (precond_tag == ABSENT)
 *
 * so CREATE requires ABSENT, and SET / DELETE each require one of
 * EXISTS / EXISTS_VERSION / EXISTS_VHASH. Exactly SEVEN of the twelve
 * (kind, precond) ENUM pairs are legal; the other five enum pairs, and
 * every combination involving an out-of-range byte value, are rejected
 * by encode AND decode. (Counting the value classes {0, 1, 2, 3, >3} x
 * {0, 1, 2, 3, 4, >4} — the 30-cell sweep the tests run — that is 7
 * accepted / 23 rejected.)
 *
 * The precondition is a SINGLE tag: an expected version and an expected
 * value hash can NEVER both be active, because the type system does not
 * offer the combination. That is stronger than checking a conflict — the
 * conflicting state is unrepresentable.
 *
 * ── CANONICAL ORDER (decode AND encode both enforce) ───────────────────
 * Records must be STRICTLY ascending under this total order:
 *
 *   1. effect_kind ascending (numeric u8);
 *   2. then op_id ascending (numeric u32);
 *   3. then key bytes lexicographic: memcmp over min(key_len_a, key_len_b)
 *      bytes decides; if that prefix is equal, the SHORTER key sorts
 *      first; full equality of (kind, op_id, key bytes AND length) is a
 *      DUPLICATE.
 *
 * Equality or descent between adjacent records is REJECTED.
 *
 * ADDITIONALLY the LOGICAL key (op_id, key bytes) must be unique across
 * the WHOLE result REGARDLESS of effect_kind — the same logical key under
 * two different kinds is rejected too. Because kind is the MAJOR sort axis
 * such a pair can be non-adjacent, so the check is an explicit pairwise
 * O(n^2) scan (n <= 64, deterministic; the env batch dedup idiom).
 *
 * The ENCODER rejects non-canonical input. It never sorts, never
 * canonicalizes, and there is no last-write-wins: a caller that hands over
 * an out-of-order or duplicated list gets -1, not a repaired encoding.
 *
 * HONEST LABEL — this is a WITHIN-ONE-RESULT rule. create-then-set,
 * set-then-delete and delete-then-recreate ACROSS SEPARATE transactions
 * all remain legal; the future engine executes transactions sequentially.
 * Uniqueness here only says that one leg's result may not touch the same
 * logical key twice, because two mutations of one key in one result have
 * no deterministic order of application.
 *
 * ── HONEST LABEL: what this codec does NOT check ───────────────────────
 *   - `op_id` is not checked against any adapter. An unknown op DECODES;
 *     it does not RESOLVE.
 *   - keys and values are opaque octet strings. Their internal structure
 *     is never parsed, and a decode success says nothing about whether the
 *     mutation is meaningful or authorized.
 *   - preconditions are checked for FORM only. Whether the key really is
 *     absent / present / at that version / at that value hash is a state
 *     question, answered by the runtime that applies the result — never
 *     here.
 *   - no domain id, no fee, no metering verdict. Framing only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_EFFECT_WIRE_H
#define SHARED_DNAC_EFFECT_WIRE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_EFFECT_WIRE_FAMILY_LEN  16
#define DNA_EFFECT_TAG_LEN          16
#define DNA_EFFECT_HASH_LEN         64   /* SHA3-512                     */

/** Only result version this release encodes or accepts. */
#define DNA_EFFECT_RESULT_VERSION    1

/* ── Encoded sizes ──────────────────────────────────────────────────── */
#define DNA_EFFECT_FIXED_HEAD       23   /* 16 + 1 + 2 + 4               */
#define DNA_EFFECT_RECORD_LEN       84   /* 4+1+1+8+64+2+4               */

/**
 * ── SCAFFOLD BOUNDS (JUDGMENT, versioned behind result_version) ────────
 *
 * The four caps below are INACTIVE SCAFFOLD bounds. They are sized from
 * shipped values so that nothing in this file invents a number, but they
 * are NOT production fee policy and NOT an activation decision — those
 * belong to the Ledger V2 devnet reset, and any change to them is a
 * versioned change behind `result_version`.
 *
 *   DNA_EFFECT_MAX_COUNT      64
 *     Mirrors the two shipped per-transaction 64-caps: DNA_ENV_MAX_LEGS
 *     (shared/dnac/env_wire.h:192) and DNA_TOUCHED_MAX
 *     (shared/dnac/domain_wire.h:424). One result belongs to one leg, so a
 *     result can never need more effects than the transaction has legs
 *     touching domains.
 *
 *   DNA_EFFECT_MAX_TOTAL_LEN  65536 (INCLUSIVE)
 *     The RESULT-side byte ceiling. Historically this mirrored
 *     DNA_ENV_MAX_TOTAL_LEN while both restated the legacy 64 KiB wire
 *     ceiling; the capacity season DECOUPLED them — the ENVELOPE ceiling
 *     is now the derived 1 MiB V2 bound (env_wire.h), grown for
 *     AUTHORIZATION bytes (committee approvals, multi-signer blobs),
 *     which never re-appear in a typed-effect result. The state a legal
 *     leg mutates is unchanged by that growth, so the RESULT bound
 *     deliberately stays at the legacy 65,536 (still the
 *     NODUS_T3_MAX_TX_SIZE class of magnitude,
 *     nodus/include/nodus/nodus_types.h:157). Standalone literal so this
 *     header stays free of any nodus dependency (ledger_ids.h rule);
 *     moving it is a versioned, coordinated change behind
 *     result_version, never an automatic one.
 *
 *   DNA_EFFECT_MAX_KEY_LEN    128 (minimum 1)
 *     Covers every current domain-local key shape: the 64-byte hash
 *     identities this tree already uses as keys (nullifier / UTXO / token
 *     ids) plus composite 2x64 forms. A zero-length key is REJECTED — a
 *     mutation with no key names nothing.
 *
 *   DNA_EFFECT_MAX_VALUE_LEN  8192
 *     Exceeds the largest current domain-local row payload,
 *     DNA_VSET_ENTRY_LEN = 2642 bytes (shared/dnac/vset_wire.h:112), with
 *     headroom, while staying far under the total cap so that a single
 *     value can never be the reason a result is unencodable.
 */
#define DNA_EFFECT_MAX_COUNT        64
#define DNA_EFFECT_MAX_KEY_LEN      128
#define DNA_EFFECT_MAX_VALUE_LEN    8192
#define DNA_EFFECT_MAX_TOTAL_LEN    65536u

/* ── Mutation kinds (0 is INVALID so zeroed memory fails closed) ─────── */
typedef enum {
    DNA_EFFECT_KIND_INVALID = 0,
    DNA_EFFECT_CREATE = 1,
    DNA_EFFECT_SET    = 2,
    DNA_EFFECT_DELETE = 3
} dna_effect_kind_t;

/* ── Preconditions (0 is INVALID so zeroed memory fails closed) ──────── */
typedef enum {
    DNA_EFFECT_PRE_INVALID        = 0,
    DNA_EFFECT_PRE_ABSENT         = 1,  /* key must not exist (CREATE only) */
    DNA_EFFECT_PRE_EXISTS         = 2,  /* key must exist                   */
    DNA_EFFECT_PRE_EXISTS_VERSION = 3,  /* exists + expected_version match  */
    DNA_EFFECT_PRE_EXISTS_VHASH   = 4   /* exists + expected value-hash     */
} dna_effect_precond_t;

/* ── One effect record (the 84 wire bytes, native form) ─────────────── */
typedef struct {
    uint32_t op_id;
    uint8_t  effect_kind;      /* dna_effect_kind_t value                 */
    uint8_t  precond_tag;      /* dna_effect_precond_t value              */
    uint64_t expected_version; /* 0 unless precond_tag == EXISTS_VERSION  */
    uint8_t  expected_vhash[DNA_EFFECT_HASH_LEN];
                               /* all-zero unless precond_tag == EXISTS_VHASH */
    uint16_t key_len;
    uint32_t value_len;
} dna_effect_hdr_t;

/**
 * One effect as handed to the ENCODER. The blob lengths live in `hdr` and
 * nowhere else — there is no second copy that could disagree with it.
 * `key` is always required (key_len >= 1). `value` may be NULL ONLY when
 * value_len is 0.
 */
typedef struct {
    dna_effect_hdr_t  hdr;
    const uint8_t    *key;    /* hdr.key_len bytes, caller-owned          */
    const uint8_t    *value;  /* hdr.value_len bytes; NULL only if len 0  */
} dna_effect_in_t;

/**
 * A decoded result.
 *
 * ── LIFETIME RULE (read this before storing a view) ────────────────────
 * A view BORROWS the caller's buffer. `buf` points at the exact bytes that
 * were passed to dna_effect_result_decode, and every blob is addressed as
 * an OFFSET into that buffer — nothing is copied and nothing is heap
 * allocated by decode. A view is valid ONLY while that buffer stays alive
 * AND unmodified. Freeing, reallocating, or mutating the source buffer
 * invalidates the view immediately; using it afterwards is undefined
 * behaviour. If a view must outlive its buffer, copy the buffer and
 * re-decode.
 *
 * Effect i's key is `buf + key_off[i]`, `eff[i].key_len` bytes; its value
 * is `buf + val_off[i]`, `eff[i].value_len` bytes. Slots at or beyond
 * `effect_count` are always zero.
 *
 * DISTINGUISHING A ZEROED VIEW FROM AN EMPTY RESULT: a rejected decode
 * leaves the view fully zeroed, so `effect_count == 0 AND buf == NULL`. An
 * ACCEPTED empty result (effect_count == 0) has `buf != NULL` — `buf` is
 * the distinguisher, never the count alone.
 */
typedef struct {
    uint8_t          result_version;
    uint16_t         effect_count;
    dna_effect_hdr_t eff[DNA_EFFECT_MAX_COUNT];
    uint32_t         key_off[DNA_EFFECT_MAX_COUNT];  /* offset into buf   */
    uint32_t         val_off[DNA_EFFECT_MAX_COUNT];  /* offset into buf   */
    const uint8_t   *buf;      /* BORROWED — see LIFETIME RULE            */
    size_t           res_len;  /* == the src_len decode accepted          */
} dna_effect_view_t;

/* ── Codec ──────────────────────────────────────────────────────────── */

/**
 * Exact encoded length of the result these effects would produce.
 *
 * Rejects (-1, *out set to 0 FIRST): NULL out; NULL effects with n > 0;
 * n > DNA_EFFECT_MAX_COUNT; key_len or value_len outside their caps; any
 * accumulated length exceeding DNA_EFFECT_MAX_TOTAL_LEN. Length
 * accumulation uses the SUBTRACTION form, so no addition can wrap
 * regardless of the declared blob lengths.
 *
 * n == 0 WITH a NULL `effects` pointer is ACCEPTED and yields
 * DNA_EFFECT_FIXED_HEAD: the empty result needs no array, so demanding one
 * would make the empty case gratuitously harder to express than it is to
 * encode.
 *
 * The blob caps are judged HERE as well as in encode so that the size
 * function and the encoder can never disagree about which inputs have a
 * length. Kind / precondition legality and ordering are NOT judged here —
 * dna_effect_result_encode does that.
 *
 * @return 0 / -1.
 */
int dna_effect_result_encoded_size(const dna_effect_in_t *effects, uint16_t n,
                                   size_t *out);

/**
 * Encode canonical result bytes into dst.
 *
 * Rejects everything dna_effect_result_decode rejects — the kind /
 * precondition legality biconditional, reserved-field misuse
 * (expected_version without EXISTS_VERSION, expected_vhash without
 * EXISTS_VHASH), a non-zero value_len on a DELETE, blob-length bounds, the
 * count bound, the total-length cap, non-canonical order, and a duplicated
 * logical key — plus: NULL arguments, a NULL data pointer with a non-zero
 * length, and dst_cap < the encoding length. The encoder runs the SAME
 * rule list the decoder enforces, so encode(x) is decodable by
 * construction.
 *
 * n == 0 encodes the DNA_EFFECT_FIXED_HEAD-byte head and nothing else; as
 * in dna_effect_result_encoded_size, `effects` may be NULL in that case.
 *
 * @param written_out MANDATORY. Set to 0 before any reject, and to the
 *                    encoding length on success.
 * @return 0 / -1.
 */
int dna_effect_result_encode(const dna_effect_in_t *effects, uint16_t n,
                             uint8_t *dst, size_t dst_cap,
                             size_t *written_out);

/**
 * Decode canonical result bytes into a borrowing view.
 *
 * `src_len` must be EXACTLY the length the head and records imply —
 * truncation AND trailing bytes are both rejected. Every malformed input
 * is REJECTED; no field is ever clamped or repaired, and nothing is
 * allocated.
 *
 * On ANY rejection *out is FULLY zeroed (a leading memset plus a single
 * `fail:` re-zero exit), so a caller can never read a half-walked result.
 * See the LIFETIME RULE above for how a zeroed view is told apart from an
 * accepted EMPTY result.
 *
 * @return 0 / -1.
 */
int dna_effect_result_decode(const uint8_t *src, size_t src_len,
                             dna_effect_view_t *out);

/**
 * The value hash of one effect value — the ONE hash this module defines.
 *
 *   dna_effect_value_hash(value, value_len) =
 *       SHA3-512( "DNA.EFFVAL.v1"(16) ‖ value_len(4, BE) ‖ value(value_len) )
 *
 * The preimage is exactly 20 + value_len bytes and is built in a STACK
 * buffer; value_len is capped at DNA_EFFECT_MAX_VALUE_LEN, so the buffer
 * is at most 20 + 8192 = 8212 bytes (pinned by a _Static_assert in the .c).
 * The length prefix is what stops two different (value_len, value) pairs
 * from sharing a preimage.
 *
 * This is the value a DNA_EFFECT_PRE_EXISTS_VHASH precondition names. It
 * is NOT an effect root, NOT a result commitment and NOT part of any
 * consensus commitment — this module defines no other hash.
 *
 * Rejects: NULL out; NULL value with value_len > 0; value_len >
 * DNA_EFFECT_MAX_VALUE_LEN (which both prevents a 32-bit preimage-length
 * wrap and keeps the helper inside the codec's own bound). The digest
 * buffer is left UNTOUCHED on every reject THIS MODULE decides. HONEST
 * LABEL: on a SHA3 BACKEND fault (qgp_sha3_512 != 0) the backend may
 * have written the buffer before its own post-write check failed — the
 * return is still -1 and the digest must not be consumed.
 *
 * @return 0 / -1.
 */
int dna_effect_value_hash(const uint8_t *value, uint32_t value_len,
                          uint8_t out[DNA_EFFECT_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_EFFECT_WIRE_H */
