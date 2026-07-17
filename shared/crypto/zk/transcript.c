/**
 * @file transcript.c
 * @brief DNAC SHA3-512 Fiat-Shamir transcript / challenger (Phase T2 impl)
 *
 * Mirrors the Plonky3 composition exactly:
 *   SerializingChallenger64<
 *       Goldilocks,
 *       HashChallenger<u8, DnacSha3_512Hasher, 64>
 *   >
 *
 * Every non-trivial block cites the Plonky3 reference and the design-doc
 * section per `feedback_no_kafadan_crypto`. Source pins:
 *
 *   Plonky3 commit 82cfad73cd734d37a0d51953094f970c531817ec
 *     challenger/src/hash_challenger.rs        (HashChallenger)
 *     challenger/src/serializing_challenger.rs (SerializingChallenger64)
 *     challenger/src/grinding_challenger.rs    (GrindingChallenger)
 *     challenger/src/lib.rs                    (CanObserve / CanSample defaults)
 *
 *   Design doc docs/plans/2026-05-26-transcript-design.md
 *
 * SHA3-512 backend: `sha3_512_oneshot` from sponge_sha3_512.c —
 * already triple-validated (C ≡ Rust `sha3` crate ≡ NIST KAT).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sponge_sha3_512.h"

/* ============================================================================
 * Public constants
 * ========================================================================== */

/* Production initial state — design doc § 16 Q1 / approved 2026-05-26.
 * Bytes of the ASCII string "DNAC|ZK|FRI|TRANSCRIPT|V1" with no NUL
 * terminator and no length prefix. 25 bytes total. */
const uint8_t DNAC_TRANSCRIPT_PROD_INIT_STATE[] = {
    'D', 'N', 'A', 'C', '|', 'Z', 'K', '|',
    'F', 'R', 'I', '|', 'T', 'R', 'A', 'N',
    'S', 'C', 'R', 'I', 'P', 'T', '|', 'V',
    '1'
};
const size_t DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN =
    sizeof(DNAC_TRANSCRIPT_PROD_INIT_STATE) / sizeof(DNAC_TRANSCRIPT_PROD_INIT_STATE[0]);

/* Compile-time sanity: the prod init must be exactly 25 bytes. */
#define DNAC_TRANSCRIPT_PROD_INIT_LEN_EXPECTED ((size_t)25)
/* Using a static_assert-equivalent via array-size trick (C99 portable). */
typedef char dnac_transcript_prod_init_len_check[
    (sizeof(DNAC_TRANSCRIPT_PROD_INIT_STATE) == DNAC_TRANSCRIPT_PROD_INIT_LEN_EXPECTED) ? 1 : -1];

/* ============================================================================
 * Struct definition
 *
 * Mirrors HashChallenger<u8, _, 64> fields
 * (Plonky3 hash_challenger.rs:10-21):
 *   input_buffer  → input_buf / input_len / input_cap (growable)
 *   output_buffer → output_buf[64] / output_len (fixed-size, LIFO via
 *                   pop-from-end on the still-valid prefix)
 *   hasher        → not stored; sha3_512_oneshot is stateless
 * ========================================================================== */

struct dnac_transcript_s {
    /** Growable byte buffer. Stores either:
     *   - the caller-supplied init state plus any subsequent observes
     *     (pre-flush),
     *   - or a 64-byte SHA3-512 digest (post-flush; flush replaces
     *     input_buffer with the digest, per hash_challenger.rs:36-43).
     *  Capacity grows by doubling; never shrinks. */
    uint8_t *input_buf;
    size_t   input_len;
    size_t   input_cap;

    /** Fixed 64-byte buffer holding the last flush's digest in STORAGE
     *  order (output_buf[0] = digest[0], ..., output_buf[63] = digest[63]).
     *  LIFO pop is `output_buf[--output_len]` — see sample_byte_priv.
     *  When output_len == 0, the next sample triggers a fresh flush. */
    uint8_t output_buf[DNAC_TRANSCRIPT_DIGEST_BYTES];
    size_t  output_len;
};

/* ============================================================================
 * Internal helpers
 * ========================================================================== */

/** Abort with a diagnostic on allocation failure / cap overflow. We deliberately
 *  do NOT propagate failure to the caller because verifier code paths cannot
 *  meaningfully recover (a malicious proof that triggers cap overflow is a DoS
 *  vector, not a normal control flow). Design doc § 10 D5, § 16 Q4. */
static void
fatal_(const char *what)
{
    fprintf(stderr, "dnac_transcript: fatal: %s\n", what);
    abort();
}

/** Grow input_buf in place to at least `needed` bytes of capacity.
 *  Strategy (deterministic given input sequence): double until >= needed
 *  or until cap. Aborts if `needed` exceeds DNAC_TRANSCRIPT_MAX_INPUT_BYTES.
 *  Aborts on realloc failure.
 *
 *  Realloc-internal address shuffling does NOT affect the byte stream
 *  (only the [0..input_len) contents matter); determinism invariant D5. */
static void
input_reserve_(dnac_transcript_t *t, size_t needed)
{
    if (needed <= t->input_cap) {
        return;
    }
    if (needed > DNAC_TRANSCRIPT_MAX_INPUT_BYTES) {
        fatal_("input_buffer cap exceeded (>16 MiB)");
    }
    size_t new_cap = (t->input_cap == 0) ? 64 : t->input_cap;
    while (new_cap < needed) {
        /* Doubling, but never exceed the hard cap. */
        if (new_cap > DNAC_TRANSCRIPT_MAX_INPUT_BYTES / 2) {
            new_cap = DNAC_TRANSCRIPT_MAX_INPUT_BYTES;
        } else {
            new_cap *= 2;
        }
    }
    uint8_t *new_buf = (uint8_t *)realloc(t->input_buf, new_cap);
    if (!new_buf) {
        fatal_("realloc failed");
    }
    t->input_buf = new_buf;
    t->input_cap = new_cap;
}

/** Replace input_buf with the supplied digest bytes.
 *  After flush, HashChallenger sets `input_buffer = digest` and
 *  `output_buffer = digest` (hash_challenger.rs:40-43). */
static void
input_replace_with_digest_(dnac_transcript_t *t, const uint8_t digest[DNAC_TRANSCRIPT_DIGEST_BYTES])
{
    input_reserve_(t, DNAC_TRANSCRIPT_DIGEST_BYTES);
    memcpy(t->input_buf, digest, DNAC_TRANSCRIPT_DIGEST_BYTES);
    t->input_len = DNAC_TRANSCRIPT_DIGEST_BYTES;
}

/** Mirrors HashChallenger::flush (Plonky3 hash_challenger.rs:36-43).
 *  Algorithm (verbatim semantics):
 *    1. digest := SHA3_512(input_buffer)        (one-shot over full buffer)
 *    2. input_buffer := digest                  (chaining: digest becomes
 *                                                the new input prefix)
 *    3. output_buffer := digest                 (LIFO pop source)
 *    4. output_len := 64                        (full digest available)
 *
 *  NO incremental sponge state: every flush is a fresh sha3_512_oneshot
 *  over the entire current input_buffer. Design doc § 5.3 + red-team R3. */
static void
flush_(dnac_transcript_t *t)
{
    uint8_t digest[DNAC_TRANSCRIPT_DIGEST_BYTES];
    sha3_512_oneshot(t->input_buf, t->input_len, digest);
    input_replace_with_digest_(t, digest);
    memcpy(t->output_buf, digest, DNAC_TRANSCRIPT_DIGEST_BYTES);
    t->output_len = DNAC_TRANSCRIPT_DIGEST_BYTES;
}

/** Mirrors HashChallenger::sample for `T=u8` (Plonky3 hash_challenger.rs:80-87):
 *    if output_buffer.is_empty() { flush(); }
 *    output_buffer.pop().expect(...)
 *
 *  LIFO pop = remove and return the LAST element of the still-valid
 *  prefix. Design doc § 5.4 + red-team R1. */
static uint8_t
sample_byte_priv_(dnac_transcript_t *t)
{
    if (t->output_len == 0) {
        flush_(t);
    }
    return t->output_buf[--t->output_len];
}

/** Composes sample_byte_priv 8 times into a little-endian u64.
 *  Mirrors the inner of `inner.sample_array::<8>()` + `u64::from_le_bytes`
 *  from serializing_challenger.rs:335. Explicit shifts; no `memcpy` of
 *  a u64 value (determinism invariant D3 / red-team R8). */
static uint64_t
sample_u64_priv_(dnac_transcript_t *t)
{
    uint8_t b0 = sample_byte_priv_(t);
    uint8_t b1 = sample_byte_priv_(t);
    uint8_t b2 = sample_byte_priv_(t);
    uint8_t b3 = sample_byte_priv_(t);
    uint8_t b4 = sample_byte_priv_(t);
    uint8_t b5 = sample_byte_priv_(t);
    uint8_t b6 = sample_byte_priv_(t);
    uint8_t b7 = sample_byte_priv_(t);
    return  ((uint64_t)b0)
         | (((uint64_t)b1) <<  8)
         | (((uint64_t)b2) << 16)
         | (((uint64_t)b3) << 24)
         | (((uint64_t)b4) << 32)
         | (((uint64_t)b5) << 40)
         | (((uint64_t)b6) << 48)
         | (((uint64_t)b7) << 56);
}

/** Emit a u64 as 8 little-endian bytes into `out`. Explicit shifts —
 *  cannot use `memcpy(out, &v, 8)` because that depends on host endian
 *  (determinism invariant D3 / red-team R8 / design doc § 6.1). */
static void
u64_to_le_bytes_(uint64_t v, uint8_t out[8])
{
    out[0] = (uint8_t)(v >>  0);
    out[1] = (uint8_t)(v >>  8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

/* ============================================================================
 * Lifecycle
 * ========================================================================== */

dnac_transcript_t *
dnac_transcript_init(const uint8_t *init_state, size_t init_state_len)
{
    if (init_state_len > DNAC_TRANSCRIPT_MAX_INPUT_BYTES) {
        fatal_("init_state_len exceeds cap");
    }
    if (init_state_len > 0 && init_state == NULL) {
        fatal_("init_state == NULL with non-zero len");
    }

    dnac_transcript_t *t = (dnac_transcript_t *)calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    t->input_buf = NULL;
    t->input_len = 0;
    t->input_cap = 0;
    t->output_len = 0;

    /* Reserve at least the init bytes plus headroom for the typical
     * first-flush digest replacement (64). Doubling rule guarantees
     * input_cap >= max(64, init_state_len). */
    size_t initial_need = init_state_len > DNAC_TRANSCRIPT_DIGEST_BYTES
                            ? init_state_len
                            : DNAC_TRANSCRIPT_DIGEST_BYTES;
    input_reserve_(t, initial_need);

    if (init_state_len > 0) {
        memcpy(t->input_buf, init_state, init_state_len);
        t->input_len = init_state_len;
    }
    return t;
}

dnac_transcript_t *
dnac_transcript_init_default(void)
{
    return dnac_transcript_init(DNAC_TRANSCRIPT_PROD_INIT_STATE,
                                DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN);
}

dnac_transcript_t *
dnac_transcript_clone(const dnac_transcript_t *src)
{
    if (!src) {
        return NULL;
    }
    dnac_transcript_t *t = (dnac_transcript_t *)calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    t->input_buf = NULL;
    t->input_len = 0;
    t->input_cap = 0;
    if (src->input_len > 0) {
        input_reserve_(t, src->input_len);
        memcpy(t->input_buf, src->input_buf, src->input_len);
        t->input_len = src->input_len;
    }
    memcpy(t->output_buf, src->output_buf, sizeof(t->output_buf));
    t->output_len = src->output_len;
    return t;
}

void
dnac_transcript_free(dnac_transcript_t *t)
{
    if (!t) {
        return;
    }
    if (t->input_buf) {
        free(t->input_buf);
    }
    /* Wipe the output buffer in case it held entropy material that the
     * caller would rather not leak in freed memory. Cheap; 64 bytes. */
    memset(t->output_buf, 0, sizeof(t->output_buf));
    free(t);
}

/* ============================================================================
 * Observe
 * ========================================================================== */

void
dnac_transcript_observe_bytes(dnac_transcript_t *t, const uint8_t *bytes, size_t len)
{
    assert(t != NULL);
    /* Empty-slice path mirrors Plonky3's `CanObserve::observe_slice`
     * default (challenger/src/lib.rs:32-39): the loop body never executes
     * for an empty slice, so NO output_buffer clear and NO input_buffer
     * append occurs. Verified against primary source 2026-05-26 audit.
     * Design doc § 5.2. */
    if (len == 0) {
        return;
    }
    assert(bytes != NULL);

    /* Cap check before reserve (more informative diagnostic). */
    if (len > DNAC_TRANSCRIPT_MAX_INPUT_BYTES - t->input_len) {
        fatal_("observe_bytes would exceed input_buffer cap");
    }

    /* Step 1: clear output_buffer.
     * Mirrors HashChallenger CanObserve<T>::observe (Plonky3
     * hash_challenger.rs:51-53): "Any buffered output is now invalid." */
    t->output_len = 0;

    /* Step 2: append to input_buffer (hash_challenger.rs:55, repeated per
     * byte by the observe_slice loop). */
    input_reserve_(t, t->input_len + len);
    memcpy(t->input_buf + t->input_len, bytes, len);
    t->input_len += len;
}

void
dnac_transcript_observe_fp(dnac_transcript_t *t, fp_t v)
{
    assert(t != NULL);
    /* SerializingChallenger64::observe(F) for Goldilocks
     * (Plonky3 serializing_challenger.rs:254-259):
     *   inner.observe_slice(&value.to_unique_u64().to_le_bytes())
     *
     * For Goldilocks `to_unique_u64()` is the default trait impl
     * (field/src/field.rs:1105-1108) which calls `as_canonical_u64()` —
     * confirmed in source 2026-05-26 audit. We use gold_fp_to_u64 which
     * applies the single conditional subtraction required to canonicalize
     * (field_goldilocks: gold_fp_to_u64). Design doc § 6.1. */
    uint64_t canonical = gold_fp_to_u64(v);
    uint8_t  le[8];
    u64_to_le_bytes_(canonical, le);
    dnac_transcript_observe_bytes(t, le, sizeof(le));
}

void
dnac_transcript_observe_fp2(dnac_transcript_t *t, fp2_t v)
{
    assert(t != NULL);
    /* Mirrors FieldChallenger::observe_algebra_element default
     * (Plonky3 challenger/src/lib.rs:106-108):
     *   self.observe_slice(alg_elem.as_basis_coefficients_slice());
     *
     * For Goldilocks² this is `c0` then `c1` in basis order. We DO NOT
     * use the FieldChallenger trait directly (the C side has no such
     * abstraction); we call the two observe_fp calls in basis order
     * which produces the same 16-byte stream. Design doc § 6.2.
     *
     * Note: fp2_t.a is c0 (constant term), .b is c1 (coefficient of X). */
    dnac_transcript_observe_fp(t, v.a);
    dnac_transcript_observe_fp(t, v.b);
}

/* ============================================================================
 * Sample
 * ========================================================================== */

fp_t
dnac_transcript_sample_fp(dnac_transcript_t *t)
{
    assert(t != NULL);
    /* SerializingChallenger64::sample for `EF = F = Goldilocks` rejection
     * loop (Plonky3 serializing_challenger.rs:333-344):
     *   loop {
     *       let value = u64::from_le_bytes(inner.sample_array());
     *       let value = value & pow_of_two_bound;
     *       if value < modulus { return F::from_canonical_unchecked(value); }
     *   }
     *
     * For Goldilocks `log2_ceil_u64(p) = 64`, so
     * `pow_of_two_bound = (1u128 << 64 - 1) as u64 = 0xFFFFFFFFFFFFFFFF`
     * which is a no-op mask. Confirmed in source 2026-05-26 audit.
     * Design doc § 7.1, invariant D9.
     *
     * Rejected 8-byte groups are CONSUMED (not re-read); the LIFO pop
     * in sample_byte_priv_ has already advanced output_len past them. */
    for (;;) {
        uint64_t u = sample_u64_priv_(t);
        if (u < GOLDILOCKS_P) {
            fp_t result;
            result.v = u;  /* value is already in [0, p) — canonical. */
            return result;
        }
        /* Reject: outer loop iterates, consuming another 8 bytes. */
    }
}

fp2_t
dnac_transcript_sample_fp2(dnac_transcript_t *t)
{
    assert(t != NULL);
    /* `CanSample<EF=fp2>::sample` on SerializingChallenger64 calls
     * `EF::from_basis_coefficients_fn(|_| sample_base(...))`
     * (Plonky3 serializing_challenger.rs:344). For Goldilocks² this is
     * exactly two sample_fp calls in basis order — design doc § 7.2. */
    fp2_t result;
    result.a = dnac_transcript_sample_fp(t);  /* c0 first */
    result.b = dnac_transcript_sample_fp(t);  /* then c1 */
    return result;
}

uint64_t
dnac_transcript_sample_bits(dnac_transcript_t *t, size_t bits)
{
    assert(t != NULL);
    /* SerializingChallenger64::sample_bits (Plonky3
     * serializing_challenger.rs:348-359):
     *   let rand_u64 = u64::from_le_bytes(self.inner.sample_array());
     *   (rand_u64 & ((1u64 << bits) - 1)) as usize
     *
     * Always consumes 8 bytes regardless of `bits`. For `bits == 0` we
     * cannot write `(1 << 0) - 1` literally without thinking about it:
     * the shift is well-defined (1ULL << 0 = 1, then 1 - 1 = 0), but a
     * cautious reader might worry about UB at `bits == 64`. We guard
     * `bits < 64` via assert (the Plonky3 assert at line 354) and
     * special-case `bits == 0` for documentation clarity. Design doc
     * § 7.3. */
    assert(bits < 64);
    uint64_t raw = sample_u64_priv_(t);
    if (bits == 0) {
        return 0;
    }
    uint64_t mask = ((uint64_t)1 << bits) - 1;
    return raw & mask;
}

/* ============================================================================
 * Grinding witness check
 * ========================================================================== */

bool
dnac_transcript_check_witness(dnac_transcript_t *t, size_t bits, fp_t witness)
{
    assert(t != NULL);
    /* GrindingChallenger::check_witness default body (Plonky3
     * grinding_challenger.rs:39-46):
     *   if bits == 0 { return true; }
     *   self.observe(witness);
     *   self.sample_bits(bits) == 0
     *
     * Critical short-circuit: `bits == 0` returns true WITHOUT observing
     * the witness and WITHOUT sampling. Transcript state is UNCHANGED.
     * Design doc § 8.1, invariant D8, red-team R6. */
    if (bits == 0) {
        return true;
    }
    dnac_transcript_observe_fp(t, witness);
    return dnac_transcript_sample_bits(t, bits) == 0;
}

fp_t
dnac_transcript_grind(dnac_transcript_t *t, size_t bits)
{
    assert(t != NULL);
    /* GrindingChallenger::grind default body (Plonky3
     * grinding_challenger.rs:29-37):
     *   let witness = (0..).map(F::from_canonical_usize)
     *                      .find(|w| self.clone().check_witness(bits, *w)).unwrap();
     *   assert!(self.check_witness(bits, witness));
     *   witness
     *
     * The search probes candidate witnesses 0,1,2,... on a CLONE of the current
     * state (self.clone()); the state under search never changes. bits==0:
     * check_witness(0,_) is always true → witness 0, and the final
     * check_witness(0,0) is a no-op — transcript UNCHANGED (identical to the
     * prior grind(0) no-op, so query_pow=0 proofs stay byte-identical). */
    if (bits == 0) {
        return gold_fp_from_u64(0);
    }
    uint64_t w = 0;
    for (;;) {
        dnac_transcript_t *probe = dnac_transcript_clone(t);
        bool ok = dnac_transcript_check_witness(probe, bits, gold_fp_from_u64(w));
        dnac_transcript_free(probe);
        if (ok) {
            break;
        }
        w++;
    }
    /* Apply to the real transcript (observe witness + sample_bits) so the state
     * advances exactly as the verifier's check_witness(bits, witness) does. */
    dnac_transcript_check_witness(t, bits, gold_fp_from_u64(w));
    return gold_fp_from_u64(w);
}

/* ============================================================================
 * Test-only state inspection (DNAC_TRANSCRIPT_TESTING)
 * ========================================================================== */

#ifdef DNAC_TRANSCRIPT_TESTING

const uint8_t *
dnac_transcript_test_input_buf_ptr(const dnac_transcript_t *t)
{
    assert(t != NULL);
    return t->input_buf;
}

size_t
dnac_transcript_test_input_buf_len(const dnac_transcript_t *t)
{
    assert(t != NULL);
    return t->input_len;
}

const uint8_t *
dnac_transcript_test_output_buf_ptr(const dnac_transcript_t *t)
{
    assert(t != NULL);
    return t->output_buf;
}

size_t
dnac_transcript_test_output_buf_remaining(const dnac_transcript_t *t)
{
    assert(t != NULL);
    return t->output_len;
}

#endif /* DNAC_TRANSCRIPT_TESTING */
