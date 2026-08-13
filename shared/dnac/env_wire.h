/**
 * @file shared/dnac/env_wire.h
 * @brief Ledger V2 K1 — generic transaction ENVELOPE codec + commitment
 *        helpers (INACTIVE).
 *
 * An envelope is the consumer-neutral outer container of a Ledger V2
 * transaction: fee/expiry/resource declarations plus an ordered list of
 * per-domain LEGS. Each leg says WHICH domain is being addressed, WHICH
 * runtime op is invoked, WITH what opaque call data, and carries the
 * opaque authorization bytes that satisfy that domain's auth rules.
 *
 * The envelope layer knows NOTHING about the meaning of `call_data` or
 * `auth_data` — it only frames, bounds, orders and commits to them. Every
 * domain-specific interpretation lives above this file.
 *
 * ACTIVATION: nothing in the live consensus path calls anything here. The
 * active chain keeps the legacy V2 wire (version byte 2), the v3 five-input
 * state_root and the V1 block hash byte-identical. This codec activates
 * only with the Ledger V2 devnet reset.
 *
 * Conventions (identical discipline to vset_wire.h / domain_wire.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, BIG-ENDIAN; counts are u16;
 *   - no native struct serialization — the wire layout below IS the format;
 *   - iterated legs are STRICTLY ascending by domain_id (rejects duplicates
 *     AND non-canonical order), so exactly ONE encoding exists per envelope;
 *   - malformed/oversized input is REJECTED, never clamped or repaired;
 *   - every failure path returns -1 and produces no USABLE result: decode
 *     zeroes its view, encode leaves *written_out == 0, and the commitment
 *     helpers leave their digest buffer untouched. (Encode's post-write
 *     length identity at the end of dna_env_encode is the one reject that
 *     could leave bytes in the caller's dst — it is an arithmetic identity
 *     with dna_env_encoded_size and so unreachable, and *written_out is
 *     still 0, so no caller can mistake those bytes for an envelope.)
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded ASCII) ───────────────
 *   "DNA.ENVWIRE.v1"  wire family marker — literally the first 16 bytes of
 *                     every encoded envelope, AND the first field of
 *                     AUTHCTX_BYTES (see below)
 *   "DNA.ENVCALL.v1"  per-leg call commitment
 *   "DNA.ENVCTX.v1"   authorization-context commitment
 *   "DNA.ENVAUTH.v1"  per-leg authorization digest (what a signer signs)
 *   "DNA.ENVTXID.v1"  transaction id
 *
 * ── Canonical wire layout ──────────────────────────────────────────────
 * Fixed header (DNA_ENV_FIXED_HEAD = 43 bytes)
 *   off  0  wire_family[16]        "DNA.ENVWIRE.v1" zero-padded
 *   off 16  envelope_version  u8   (= DNA_ENV_VERSION)
 *   off 17  expiry_height     u64 BE
 *   off 25  fee_amount        u64 BE
 *   off 33  res_max_total_units u64 BE
 *   off 41  leg_count         u16 BE   (1 .. DNA_ENV_MAX_LEGS)
 *
 * Then leg_count leg headers, leg i at 43 + 30*i
 * (DNA_ENV_LEG_HDR_LEN = 30 bytes)
 *   +0   domain_id            u32 BE   STRICTLY ascending across legs
 *   +4   runtime_op           u32 BE   (accepted range 0..255, see below)
 *   +8   ruleset_version      u32 BE
 *   +12  access_mode          u8       READ(1) | INVOKE(2); 0 is INVALID
 *   +13  auth_kind            u8       MUST be non-zero
 *   +14  call_len             u32 BE
 *   +18  auth_len             u32 BE
 *   +22  res_max_effects      u32 BE
 *   +26  res_max_effect_bytes u32 BE
 *
 * Then ALL call-data blobs in leg order, then ALL auth-data blobs in leg
 * order (the two sections are contiguous, never interleaved):
 *   CALL_BASE(n) = 43 + 30*n
 *   call_off(i)  = CALL_BASE(n) + Σ call_len[j], j < i
 *   AUTH_BASE(n) = CALL_BASE(n) + Σ call_len[j], j < n
 *   auth_off(i)  = AUTH_BASE(n) + Σ auth_len[j], j < i
 *   ENV_LEN      = AUTH_BASE(n) + Σ auth_len[j], j < n
 * ENV_LEN must be <= DNA_ENV_MAX_TOTAL_LEN (the bound is INCLUSIVE: an
 * envelope of exactly DNA_ENV_MAX_TOTAL_LEN bytes is valid).
 *
 * ── Commitments (all DERIVED; NEVER serialized into the envelope) ──────
 *   call_commit[i] = SHA3-512(
 *       "DNA.ENVCALL.v1"(16) ‖ domain_id(4) ‖ runtime_op(4)
 *     ‖ ruleset_version(4) ‖ ruleset_hash(64) ‖ access_mode(1)
 *     ‖ call_len(4) ‖ call_data(call_len) )
 *   `ruleset_hash` is CONTEXTUAL — supplied by the caller from the domain
 *   registry for the (domain_id, ruleset_version) pair, not carried on the
 *   envelope wire. Preimage length = 97 + call_len.
 *
 *   AUTHCTX_BYTES (an UNTAGGED byte string, 75 + 94*n bytes) =
 *       wire_family(16) ‖ envelope_version(1) ‖ chain_id(32)
 *     ‖ expiry_height(8) ‖ fee_amount(8) ‖ res_max_total_units(8)
 *     ‖ leg_count(2)
 *     then FOR EACH leg, in wire order (94 bytes each):
 *       domain_id(4) ‖ runtime_op(4) ‖ ruleset_version(4)
 *     ‖ access_mode(1) ‖ auth_kind(1) ‖ call_len(4) ‖ auth_len(4)
 *     ‖ res_max_effects(4) ‖ res_max_effect_bytes(4) ‖ call_commit[i](64)
 *   `chain_id` is CONTEXTUAL (replay separation across chains).
 *
 *   auth_context_commit = SHA3-512( "DNA.ENVCTX.v1"(16) ‖ AUTHCTX_BYTES )
 *
 *   auth_digest[i] = SHA3-512( "DNA.ENVAUTH.v1"(16)
 *     ‖ auth_context_commit(64) ‖ leg_index(2) ‖ domain_id(4)
 *     ‖ runtime_op(4) )                      — fixed 90-byte preimage
 *
 *   tx_id = SHA3-512( "DNA.ENVTXID.v1"(16) ‖ auth_context_commit(64)
 *     ‖ env_len(4) ‖ env_bytes(env_len) )
 *
 * ── NON-CIRCULARITY (the load-bearing property) ────────────────────────
 * `auth_data` bytes appear in NEITHER call_commit, NOR AUTHCTX_BYTES, NOR
 * auth_digest. Only their LENGTH (auth_len) and their KIND (auth_kind) are
 * committed there. That is what makes auth_digest[i] computable BEFORE any
 * authorization exists — a signer signs auth_digest[i], and the signature
 * it produces is then placed in that leg's auth_data. Committing the auth
 * bytes into the digest they authorize would be circular and unsignable.
 *
 * `auth_data` bytes are covered EXACTLY ONCE, inside tx_id, via the
 * complete env_bytes. tx_id is therefore a commitment to the FINAL,
 * fully-authorized transaction; auth_context_commit / auth_digest are
 * commitments to the transaction's INTENT. Mutating auth_data changes
 * tx_id ONLY, and leaves every auth_digest byte-identical (pinned by
 * test_env_wire).
 *
 * ── runtime_op: 4 wire bytes, 0..255 accepted ──────────────────────────
 * The field is 4 bytes on the wire so the op space can grow without a
 * format change. This release accepts only 0..255 (K1 charter); a larger
 * value is REJECTED by both encode and decode, never truncated.
 *
 * ── HONEST LABEL: what this codec does NOT check ───────────────────────
 *   - `auth_kind` is only checked NON-ZERO. Whether a given kind is
 *     SUPPORTED (and how its bytes parse) is out of K1 scope — that
 *     belongs to the auth-scheme layer, which does not exist yet. A
 *     non-zero unknown kind therefore DECODES; it does not VERIFY.
 *   - `call_data` and `auth_data` are opaque octet strings here. Their
 *     internal structure is never parsed, and a decode success says
 *     nothing about their validity.
 *   - `domain_id` is not checked against the domain registry, and
 *     `ruleset_version` is not checked for existence — both are admission
 *     concerns, not framing concerns.
 *   - fee/resource declarations are framed and committed, never priced.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_ENV_WIRE_H
#define SHARED_DNAC_ENV_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_ENV_WIRE_FAMILY_LEN    16
#define DNA_ENV_TAG_LEN            16
#define DNA_ENV_HASH_LEN           64   /* SHA3-512                      */
#define DNA_ENV_RULESET_HASH_LEN   64   /* SHA3-512, contextual input    */
#define DNA_ENV_CHAIN_ID_LEN       DNA_CHAIN_ID_LEN   /* 32, ledger_ids.h */

/** Only envelope version this release encodes or accepts. */
#define DNA_ENV_VERSION             1

/* ── Encoded sizes ──────────────────────────────────────────────────── */
#define DNA_ENV_FIXED_HEAD         43   /* 16 + 1 + 8 + 8 + 8 + 2        */
#define DNA_ENV_LEG_HDR_LEN        30   /* 4+4+4+1+1+4+4+4+4             */

/**
 * Largest total envelope encoding, INCLUSIVE — the VERSIONED Ledger V2
 * envelope-family capacity bound (capacity season).
 *
 * DERIVED, twice (an independent python oracle reproduces the same
 * numbers — shared/dnac/tests/env_wire_oracle.py): 2^20 is the smallest
 * power of two that contains the worst-case LEGAL envelope the two
 * production runtimes can require this release:
 *
 *   CHAIN_CONFIG carrying EVERY approval of the release validator
 *   ceiling (128, DNA_MAX_ACTIVE_VALIDATORS) under the committee-indexed
 *   auth carrier v2, single leg:            700,914 bytes
 *   the same plus a maximal 15-distinct-owner SPEND leg (the largest
 *   legal multi-leg composition under the per-runtime auth-kind
 *   allowlists):                            813,904 bytes
 *
 *   524,288 = 2^19 < 813,904 <= 2^20 = 1,048,576.
 *
 * The shape arithmetic is pinned by _Static_asserts next to the
 * constants it derives from (nodus_witness_rt_native.c — this header
 * stays free of any nodus dependency, the ledger_ids.h rule).
 *
 * This bound is a RELEASE RESOURCE CEILING of envelope version
 * DNA_ENV_VERSION — technical, version-aware, upgradeable by a
 * coordinated software release; it is NOT validator-governance policy
 * and NOT a protocol maximum.
 *
 * DELIBERATELY DECOUPLED from the legacy per-transaction wire ceiling:
 * the legacy semantic limit stays EXACTLY 65,536 bytes
 * (NODUS_T3_MAX_TX_SIZE, nodus/include/nodus/nodus_types.h:157, and its
 * libdna mirror DNAC_TXW3_MAX_TX_SIZE, shared/dnac/tx_wire.h:211) and no
 * legacy ingress, decode, mempool or verify path widens because this
 * constant grew. An envelope is classified by its leading 16-byte wire
 * family marker ("DNA.ENVWIRE.v1", byte offset 0) BEFORE any
 * length-driven allocation, so a future V2 carrier can select this bound
 * only after positive classification — a legacy frame can never
 * accidentally be sized against it.
 */
#define DNA_ENV_MAX_TOTAL_LEN      1048576u

/**
 * Largest leg count, INCLUSIVE.
 *
 * DERIVED (documented, deliberately NOT included): 64 is the shipped
 * per-transaction touched-domain cap DNA_TOUCHED_MAX
 * (shared/dnac/domain_wire.h:424). One leg addresses one domain and legs
 * are strictly ascending by domain_id, so an envelope can never touch more
 * domains than it has legs. Restated standalone for the same reason as
 * DNA_ENV_MAX_TOTAL_LEN.
 */
#define DNA_ENV_MAX_LEGS           64

/** Largest runtime_op this release accepts (see header note above). */
#define DNA_ENV_MAX_RUNTIME_OP     255u

/* ── Access modes (0 is INVALID so zeroed memory fails closed) ──────── */
typedef enum {
    DNA_ENV_ACCESS_INVALID = 0,
    DNA_ENV_ACCESS_READ    = 1,   /* leg may only read domain state       */
    DNA_ENV_ACCESS_INVOKE  = 2    /* leg may produce effects              */
} dna_env_access_mode_t;

/* ── One leg header (the 30 wire bytes, native form) ────────────────── */
typedef struct {
    uint32_t domain_id;
    uint32_t runtime_op;
    uint32_t ruleset_version;
    uint8_t  access_mode;          /* dna_env_access_mode_t value         */
    uint8_t  auth_kind;            /* non-zero; semantics out of K1 scope */
    uint32_t call_len;
    uint32_t auth_len;
    uint32_t res_max_effects;
    uint32_t res_max_effect_bytes;
} dna_env_leg_hdr_t;

/**
 * One leg as handed to the ENCODER. The blob lengths live in `hdr` and
 * nowhere else — there is no second copy that could disagree with it.
 * A NULL data pointer is permitted ONLY when its length is 0.
 */
typedef struct {
    dna_env_leg_hdr_t  hdr;
    const uint8_t     *call_data;   /* hdr.call_len bytes, caller-owned   */
    const uint8_t     *auth_data;   /* hdr.auth_len bytes, caller-owned   */
} dna_env_leg_in_t;

/** A whole envelope as handed to the ENCODER. */
typedef struct {
    uint64_t                 expiry_height;
    uint64_t                 fee_amount;
    uint64_t                 res_max_total_units;
    uint16_t                 leg_count;      /* 1 .. DNA_ENV_MAX_LEGS     */
    const dna_env_leg_in_t  *legs;           /* leg_count items           */
} dna_env_in_t;

/**
 * A decoded envelope.
 *
 * ── LIFETIME RULE (read this before storing a view) ────────────────────
 * A view BORROWS the caller's buffer. `buf` points at the exact bytes that
 * were passed to dna_env_decode, and every blob is addressed as an OFFSET
 * into that buffer — nothing is copied and nothing is heap-allocated by
 * decode. A view is valid ONLY while that buffer stays alive AND unmodified.
 * Freeing, reallocating, or mutating the source buffer invalidates the view
 * immediately; using it afterwards is undefined behaviour. If a view must
 * outlive its buffer, copy the buffer and re-decode.
 *
 * Leg i's call data is `buf + call_off[i]`, `leg[i].call_len` bytes;
 * its auth data is `buf + auth_off[i]`, `leg[i].auth_len` bytes. Slots at
 * or beyond `leg_count` are always zero.
 */
typedef struct {
    uint8_t           envelope_version;
    uint64_t          expiry_height;
    uint64_t          fee_amount;
    uint64_t          res_max_total_units;
    uint16_t          leg_count;
    dna_env_leg_hdr_t leg[DNA_ENV_MAX_LEGS];
    uint32_t          call_off[DNA_ENV_MAX_LEGS];  /* offset into buf     */
    uint32_t          auth_off[DNA_ENV_MAX_LEGS];  /* offset into buf     */
    const uint8_t    *buf;         /* BORROWED — see LIFETIME RULE        */
    size_t            env_len;     /* == the src_len decode accepted      */
} dna_env_view_t;

/* ── Codec ──────────────────────────────────────────────────────────── */

/**
 * Exact encoded length of the envelope these legs would produce.
 *
 * Rejects (-1, *out set to 0 first): NULL out; NULL legs; leg_count 0 or
 * > DNA_ENV_MAX_LEGS; any accumulated length exceeding
 * DNA_ENV_MAX_TOTAL_LEN. Length accumulation uses the SUBTRACTION form, so
 * no addition can wrap regardless of the declared blob lengths.
 *
 * This is a SIZE function only: it does not judge access_mode, auth_kind,
 * runtime_op or leg ordering — dna_env_encode does.
 *
 * @return 0 / -1.
 */
int dna_env_encoded_size(const dna_env_leg_in_t *legs, uint16_t leg_count,
                         size_t *out);

/**
 * Encode canonical envelope bytes into dst.
 *
 * Rejects everything dna_env_decode rejects (leg-count bounds, access_mode
 * not READ/INVOKE, auth_kind == 0, runtime_op > DNA_ENV_MAX_RUNTIME_OP,
 * domain_id not strictly ascending, total length over the cap), plus:
 * NULL arguments, a NULL data pointer with a non-zero length, and
 * dst_cap < the encoding length.
 *
 * @param written_out MANDATORY. Set to 0 before any reject, and to the
 *                    encoding length on success.
 * @return 0 / -1.
 */
int dna_env_encode(const dna_env_in_t *in, uint8_t *dst, size_t dst_cap,
                   size_t *written_out);

/**
 * Decode canonical envelope bytes into a borrowing view.
 *
 * `src_len` must be EXACTLY the length the header implies — truncation AND
 * trailing bytes are both rejected. Every malformed input is REJECTED; no
 * field is ever clamped or repaired, and nothing is allocated.
 *
 * On ANY rejection *out is fully zeroed (so a caller can never read a
 * half-walked envelope, and a zeroed view can never be mistaken for a
 * decoded one: leg_count == 0 and buf == NULL).
 *
 * @return 0 / -1.
 */
int dna_env_decode(const uint8_t *src, size_t src_len, dna_env_view_t *out);

/* ── Commitments ────────────────────────────────────────────────────── */

/**
 * call_commit[leg_index] — see the layout block above.
 *
 * @param ruleset_hash CONTEXTUAL: the 64-byte ruleset digest the caller
 *                     resolved for (domain_id, ruleset_version). Binding it
 *                     here is what stops a leg from being replayed against
 *                     a different ruleset carrying the same version number.
 * @return 0 / -1 (NULL args, uninitialised view, leg_index out of range).
 */
int dna_env_call_commit(const dna_env_view_t *v, uint16_t leg_index,
                        const uint8_t ruleset_hash[DNA_ENV_RULESET_HASH_LEN],
                        uint8_t out[DNA_ENV_HASH_LEN]);

/**
 * auth_context_commit — the one value every leg's auth_digest hangs from.
 *
 * @param chain_id     CONTEXTUAL: 32-byte chain identifier (replay
 *                     separation across chains).
 * @param call_commits leg_count entries, entry i being call_commit[i] as
 *                     produced by dna_env_call_commit.
 * @return 0 / -1.
 */
int dna_env_auth_context_commit(const dna_env_view_t *v,
                                const uint8_t chain_id[DNA_ENV_CHAIN_ID_LEN],
                                const uint8_t (*call_commits)[DNA_ENV_HASH_LEN],
                                uint8_t out[DNA_ENV_HASH_LEN]);

/**
 * auth_digest[leg_index] — the value a leg's authorization is produced
 * over. Computable before any auth_data exists (see NON-CIRCULARITY).
 *
 * Takes the leg's identity explicitly rather than a view, so a signer can
 * check WHAT it is signing without holding the encoded envelope.
 *
 * @return 0 / -1 (NULL args, leg_index >= DNA_ENV_MAX_LEGS,
 *         runtime_op > DNA_ENV_MAX_RUNTIME_OP).
 */
int dna_env_auth_digest(const uint8_t auth_context_commit[DNA_ENV_HASH_LEN],
                        uint16_t leg_index, uint32_t domain_id,
                        uint32_t runtime_op, uint8_t out[DNA_ENV_HASH_LEN]);

/**
 * tx_id — commitment to the FINAL, fully-authorized transaction: the
 * intent (auth_context_commit) plus the complete encoded bytes, auth data
 * included.
 *
 * @param env_bytes the exact bytes dna_env_encode produced / dna_env_decode
 *                  accepted; env_len must be in
 *                  [DNA_ENV_FIXED_HEAD, DNA_ENV_MAX_TOTAL_LEN].
 * @return 0 / -1.
 */
int dna_env_tx_id(const uint8_t auth_context_commit[DNA_ENV_HASH_LEN],
                  const uint8_t *env_bytes, size_t env_len,
                  uint8_t out[DNA_ENV_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_ENV_WIRE_H */
