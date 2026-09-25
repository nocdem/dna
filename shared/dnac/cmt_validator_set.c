/**
 * @file shared/dnac/cmt_validator_set.c
 * @brief cometbft @709fd12b types/validator.go + types/validator_set.go in
 *        C — see cmt_validator_set.h.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS, ITERATES A MAP OR
 * ALLOCATES. Every function is a pure function of its arguments and of the
 * caller-owned storage it is given.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_validation.h"  /* cmt_verify_commit — validator_set.go:701.
                                   * Included from the .c and NOT from
                                   * cmt_validator_set.h, because
                                   * cmt_validation.h includes THAT header. */

#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * Go integer arithmetic, reproduced without C undefined behaviour.
 *
 * Go's int64 arithmetic WRAPS on overflow (Go Language Specification,
 * "Arithmetic operators": "For signed integers, the operations +, -, *, /
 * and << may legally overflow and the resulting value exists ... there is
 * no signal"). C's signed overflow is undefined, so every place the
 * reference relies on the wrap is computed in uint64_t and converted back
 * with the exact two's-complement mapping. The PREDICATES below are the
 * reference's, unchanged; only the way they are evaluated differs.
 *
 * The same discipline is already used by cmt_time.c's cmt_time_unix_nano.
 * ══════════════════════════════════════════════════════════════════════ */

/** The two's-complement reading of a uint64_t as an int64_t, without
 *  relying on the implementation-defined out-of-range conversion. */
static int64_t i64_from_u64(uint64_t u)
{
    if (u <= (uint64_t)INT64_MAX) {
        return (int64_t)u;
    }
    /* u - 2^63 lands in [0, 2^63), so the cast is in range and the
     * addition of INT64_MIN cannot overflow. */
    return (int64_t)(u - (uint64_t)INT64_MAX - 1u) + INT64_MIN;
}

static int64_t go_add(int64_t a, int64_t b)
{
    return i64_from_u64((uint64_t)a + (uint64_t)b);
}

static int64_t go_sub(int64_t a, int64_t b)
{
    return i64_from_u64((uint64_t)a - (uint64_t)b);
}

static int64_t go_mul(int64_t a, int64_t b)
{
    return i64_from_u64((uint64_t)a * (uint64_t)b);
}

/** Go's unary minus, i.e. `-1 * x`. `-MinInt64` is MinInt64. */
static int64_t go_neg(int64_t a)
{
    return i64_from_u64(0u - (uint64_t)a);
}

/**
 * Go's `>>` on a SIGNED left operand is an ARITHMETIC shift (Go Language
 * Specification, "Arithmetic operators": "The shift operators implement
 * arithmetic shifts if the left operand is a signed integer"). C's is
 * implementation-defined for a negative value, so the sign extension is
 * written out. Used only by computeNewPriorities' `tvp >> 3`.
 */
static int64_t go_shr(int64_t x, unsigned s)
{
    uint64_t ux = (uint64_t)x;

    if (s == 0) {
        return x;
    }
    if (x >= 0) {
        return (int64_t)(ux >> s);
    }
    return i64_from_u64((ux >> s) | (~(uint64_t)0 << (64 - s)));
}

/**
 * Go's integer `/`: truncation toward zero, plus the specification's one
 * special case — "if the dividend x is the most negative value for the int
 * type of x, the quotient q = x / -1 is equal to x ... due to
 * two's-complement integer overflow". C would trap or be undefined there.
 * A zero divisor is Go's runtime panic and REJECTS.
 */
static int go_div(int64_t a, int64_t b, int64_t *out)
{
    if (b == 0) {
        return CMT_REJECT;
    }
    if (a == INT64_MIN && b == -1) {
        *out = INT64_MIN;
        return CMT_OK;
    }
    *out = a / b;
    return CMT_OK;
}

/* ── the 128-bit accumulator (math/big stand-in) ─────────────────────
 * Explicit 64-bit limbs, NOT __int128, so the result cannot depend on the
 * compiler — the reason shared/crypto/utils/qgp_u128.h:12-16 gives for its
 * own limbs. qgp_u128_t itself is not used because it is UNSIGNED, its
 * subtraction ABORTS THE PROCESS on underflow (qgp_u128.h:30), and its
 * division takes an unsigned divisor; a consensus decoder may not abort
 * and this accumulator must be signed. */

typedef struct {
    uint64_t hi;   /* two's complement, most significant */
    uint64_t lo;
} cmt_i128_t;

static cmt_i128_t i128_from_i64(int64_t v)
{
    cmt_i128_t r;
    r.lo = (uint64_t)v;
    r.hi = (v < 0) ? ~(uint64_t)0 : 0u;
    return r;
}

static cmt_i128_t i128_add(cmt_i128_t a, cmt_i128_t b)
{
    cmt_i128_t r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + ((r.lo < a.lo) ? 1u : 0u);
    return r;
}

static bool i128_is_neg(cmt_i128_t a)
{
    return (a.hi >> 63) != 0u;
}

/** Two's-complement negation of a 128-bit value. */
static cmt_i128_t i128_neg(cmt_i128_t a)
{
    cmt_i128_t r;
    r.lo = ~a.lo + 1u;
    r.hi = ~a.hi + ((r.lo == 0u) ? 1u : 0u);
    return r;
}

/**
 * Unsigned 128 / 64 restoring division. The quotient is 128 bits wide; the
 * remainder is always below `d` and so fits 64 bits. `d` must be non-zero.
 *
 * A bit-at-a-time long division is used rather than a wider machine type
 * so that no compiler extension is involved. It runs 128 iterations, once
 * per IncrementProposerPriority call at most, over a list of at most 128
 * validators — nothing measurable.
 *
 * The loop invariant is `r < d`, so `2r + bit < 2d` and one conditional
 * subtraction restores it. When `2r + bit` overflows 64 bits the true
 * value is `2^64 + r_wrapped`, which exceeds `d`, so the subtraction is
 * taken; and the invariant guarantees `r_wrapped < d` there, so the
 * unsigned `r - d` wraps to exactly `(2^64 + r_wrapped) - d`.
 */
static void u128_divmod_u64(uint64_t hi, uint64_t lo, uint64_t d,
                            uint64_t *q_hi, uint64_t *q_lo, uint64_t *rem)
{
    uint64_t r = 0u, qh = 0u, ql = 0u;
    int i;

    for (i = 127; i >= 0; i--) {
        uint64_t bit = (i >= 64) ? ((hi >> (i - 64)) & 1u) : ((lo >> i) & 1u);
        int      carry = (int)(r >> 63);

        r = (r << 1) | bit;
        if (carry || r >= d) {
            r -= d;
            if (i >= 64) {
                qh |= (uint64_t)1 << (i - 64);
            } else {
                ql |= (uint64_t)1 << i;
            }
        }
    }
    *q_hi = qh;
    *q_lo = ql;
    *rem  = r;
}

/**
 * floor(a / d) for a signed 128-bit `a` and a STRICTLY POSITIVE int64 `d`,
 * which is `(*big.Int).Div` restricted to a positive divisor: Div is
 * Euclidean (`x = y*q + m` with `0 <= m < |y|`), and for `y > 0` Euclidean
 * division is floor division.
 *
 * @return true when the quotient fits an int64 — the reference's
 *         `avg.IsInt64()` at validator_set.go:203.
 */
static bool i128_floor_div_i64(cmt_i128_t a, int64_t d, int64_t *out)
{
    bool       neg = i128_is_neg(a);
    cmt_i128_t m   = neg ? i128_neg(a) : a;
    uint64_t   qh, ql, rem;

    u128_divmod_u64(m.hi, m.lo, (uint64_t)d, &qh, &ql, &rem);

    if (!neg) {
        if (qh != 0u || ql > (uint64_t)INT64_MAX) {
            return false;
        }
        *out = (int64_t)ql;
        return true;
    }
    /* floor(-m/d) = -(m/d) when the division is exact, -(m/d) - 1 when it
     * is not. The magnitude is then at most 2^63, i.e. INT64_MIN. */
    if (rem != 0u) {
        uint64_t lo2 = ql + 1u;
        qh += (lo2 == 0u) ? 1u : 0u;
        ql = lo2;
    }
    if (qh != 0u || ql > (uint64_t)INT64_MAX + 1u) {
        return false;
    }
    if (ql == (uint64_t)INT64_MAX + 1u) {
        *out = INT64_MIN;
        return true;
    }
    *out = -(int64_t)ql;
    return true;
}

/* ── bytes.Compare / bytes.Equal over an address ─────────────────────
 * Go's bytes.Compare orders by the common prefix and then by LENGTH, so
 * two addresses of different lengths never compare equal. Reproduced. */

static int addr_cmp(const uint8_t *a, size_t alen,
                    const uint8_t *b, size_t blen)
{
    size_t n = (alen < blen) ? alen : blen;
    int    c = (n == 0) ? 0 : memcmp(a, b, n);

    if (c != 0) {
        return (c < 0) ? -1 : 1;
    }
    if (alen == blen) {
        return 0;
    }
    return (alen < blen) ? -1 : 1;
}

static bool addr_eq(const uint8_t *a, size_t alen,
                    const uint8_t *b, size_t blen)
{
    return addr_cmp(a, alen, b, blen) == 0;
}

/* ══ errors ═══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/validator_set.go:796-798 */
bool cmt_is_err_not_enough_voting_power_signed(const cmt_vs_error_t *e)
{
    return e != NULL && e->code == CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED;
}

/* ══ int64 helpers — validator_set.go:993-1053 ════════════════════════ */

/* :993-1000 safeAdd() */
bool cmt_vs_safe_add(int64_t a, int64_t b, int64_t *out)
{
    if (b > 0 && a > INT64_MAX - b) {          /* :994-995 */
        *out = -1;
        return true;
    }
    if (b < 0 && a < INT64_MIN - b) {          /* :996-997 */
        *out = -1;
        return true;
    }
    *out = a + b;                              /* :999, cannot overflow now */
    return false;
}

/* :1002-1009 safeSub() */
bool cmt_vs_safe_sub(int64_t a, int64_t b, int64_t *out)
{
    if (b > 0 && a < INT64_MIN + b) {          /* :1003-1004 */
        *out = -1;
        return true;
    }
    if (b < 0 && a > INT64_MAX + b) {          /* :1005-1006 */
        *out = -1;
        return true;
    }
    *out = a - b;                              /* :1008 */
    return false;
}

/* :1011-1020 safeAddClip() */
int64_t cmt_vs_safe_add_clip(int64_t a, int64_t b)
{
    int64_t c;

    if (cmt_vs_safe_add(a, b, &c)) {           /* :1012-1013 */
        return (b < 0) ? INT64_MIN : INT64_MAX; /* :1014-1017 */
    }
    return c;                                  /* :1019 */
}

/* :1022-1031 safeSubClip() */
int64_t cmt_vs_safe_sub_clip(int64_t a, int64_t b)
{
    int64_t c;

    if (cmt_vs_safe_sub(a, b, &c)) {           /* :1023-1024 */
        return (b > 0) ? INT64_MIN : INT64_MAX; /* :1025-1028 */
    }
    return c;                                  /* :1030 */
}

/* :1033-1053 safeMul() */
bool cmt_vs_safe_mul(int64_t a, int64_t b, int64_t *out)
{
    int64_t abs_a, abs_b, limit;

    if (a == 0 || b == 0) {                    /* :1034-1036 */
        *out = 0;
        return false;
    }
    /* :1038-1041 / :1043-1046. NOTE reference quirk: for MinInt64 the Go
     * negation WRAPS back to MinInt64, so `absOf*` stays negative. go_neg
     * reproduces that exactly rather than "fixing" it. */
    abs_b = (b < 0) ? go_neg(b) : b;
    abs_a = (a < 0) ? go_neg(a) : a;

    if (go_div(INT64_MAX, abs_b, &limit) != CMT_OK) {
        /* Unreachable: abs_b is non-zero because b is non-zero and the
         * negation of a non-zero value is non-zero. Kept so the division
         * has no silent failure path. */
        return true;
    }
    if (abs_a > limit) {                       /* :1048-1050 */
        *out = 0;
        return true;
    }
    *out = go_mul(a, b);                       /* :1052 */
    return false;
}

/* ══ validator.go ═════════════════════════════════════════════════════ */

/* validator.go:29 — pubKey.Address(), i.e. crypto.AddressHash
 * (crypto/crypto.go:18-20). Wave R1-D moved the ONE truncation into
 * cmt_tmhash.h's cmt_address_hash; this stays as the typed wrapper that
 * adds the reference's nil-key rule and nothing else. */
int cmt_pub_key_address(const cmt_pb_public_key_t *pk,
                        uint8_t out[CMT_PB_ADDRESS_MAX])
{
    if (pk == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (!pk->present) {
        return CMT_REJECT;   /* the reference's nil PubKey has no address */
    }
    return cmt_address_hash(pk->key, (size_t)CMT_PB_PUBKEY_LEN, out);
}

/* validator.go:27-35 — NewValidator() */
int cmt_validator_new(const cmt_pb_public_key_t *pub_key,
                      int64_t voting_power, cmt_validator_t *out)
{
    int rc;

    if (pub_key == NULL || out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    rc = cmt_pub_key_address(pub_key, out->address);      /* :29 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->address_len       = CMT_PB_ADDRESS_MAX;
    out->pub_key           = *pub_key;                    /* :30 */
    out->voting_power      = voting_power;                /* :31 */
    out->proposer_priority = 0;                           /* :32 */
    return CMT_OK;
}

/* validator.go:37-55 — ValidateBasic() */
int cmt_validator_validate_basic(const cmt_validator_t *v)
{
    uint8_t derived[CMT_PB_ADDRESS_MAX];
    int     rc;

    if (v == NULL) {                                      /* :38-40 */
        return CMT_REJECT;
    }
    if (!v->pub_key.present) {                            /* :41-43 */
        return CMT_REJECT;
    }
    if (v->voting_power < 0) {                            /* :45-47 */
        return CMT_REJECT;
    }
    rc = cmt_pub_key_address(&v->pub_key, derived);       /* :49 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!addr_eq(v->address, v->address_len,
                 derived, CMT_PB_ADDRESS_MAX)) {          /* :50-52 */
        return CMT_REJECT;
    }
    return CMT_OK;                                        /* :54 */
}

/* validator.go:59-62 — Copy(). The reference panics on a nil receiver. */
int cmt_validator_copy(const cmt_validator_t *v, cmt_validator_t *out)
{
    if (v == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *v;                                            /* :60-61 */
    return CMT_OK;
}

/* validator.go:65-85 — CompareProposerPriority() */
int cmt_validator_compare_proposer_priority(const cmt_validator_t *v,
                                            const cmt_validator_t *other,
                                            const cmt_validator_t **out)
{
    int result;

    if (other == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (v == NULL) {                                      /* :66-68 */
        *out = other;
        return CMT_OK;
    }
    if (v->proposer_priority > other->proposer_priority) { /* :70-71 */
        *out = v;
        return CMT_OK;
    }
    if (v->proposer_priority < other->proposer_priority) { /* :72-73 */
        *out = other;
        return CMT_OK;
    }
    result = addr_cmp(v->address, v->address_len,
                      other->address, other->address_len); /* :75 */
    if (result < 0) {                                      /* :77-78 */
        *out = v;
        return CMT_OK;
    }
    if (result > 0) {                                      /* :79-80 */
        *out = other;
        return CMT_OK;
    }
    return CMT_REJECT;    /* :81-83 panic("Cannot compare identical validators") */
}

/* validator.go:118-134 — Bytes(), the ValidatorsHash leaf. */
int cmt_validator_bytes(const cmt_validator_t *v, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    cmt_pb_simple_validator_t pbv;

    if (v == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (!v->pub_key.present) {
        /* :119-122 — PubKeyToProto fails for a nil key and Bytes panics. */
        return CMT_REJECT;
    }
    cmt_pb_simple_validator_init(&pbv);
    pbv.pub_key      = v->pub_key;                        /* :125 */
    pbv.voting_power = v->voting_power;                   /* :126 */
    return cmt_pb_simple_validator_marshal(&pbv, out, cap, out_len); /* :129 */
}

/* validator.go:137-155 — ToProto() */
int cmt_validator_to_proto(const cmt_validator_t *v, cmt_pb_validator_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (v == NULL) {                                      /* :138-140 */
        return CMT_REJECT;
    }
    if (!v->pub_key.present) {                            /* :142-145 */
        return CMT_REJECT;
    }
    cmt_pb_validator_init(out);
    if (v->address_len > CMT_PB_ADDRESS_MAX) {
        return CMT_REJECT;
    }
    memcpy(out->address, v->address, v->address_len);     /* :148 */
    out->address_len       = v->address_len;
    out->pub_key           = v->pub_key;                  /* :149 */
    out->voting_power      = v->voting_power;             /* :150 */
    out->proposer_priority = v->proposer_priority;        /* :151 */
    return CMT_OK;
}

/* validator.go:159-175 — ValidatorFromProto().
 * NOTE the KODEK rule: the address is COPIED from the wire (:169), never
 * re-derived. ValidateBasic is what checks it against the key. */
int cmt_validator_from_proto(const cmt_pb_validator_t *vp,
                             cmt_validator_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (vp == NULL) {                                     /* :160-162 */
        return CMT_REJECT;
    }
    if (!vp->pub_key.present) {                           /* :164-167 */
        return CMT_REJECT;
    }
    memset(out, 0, sizeof(*out));
    if (vp->address_len > CMT_PB_ADDRESS_MAX) {
        return CMT_REJECT;
    }
    memcpy(out->address, vp->address, vp->address_len);   /* :169 */
    out->address_len       = vp->address_len;
    out->pub_key           = vp->pub_key;                 /* :170 */
    out->voting_power      = vp->voting_power;            /* :171 */
    out->proposer_priority = vp->proposer_priority;       /* :172 */
    return CMT_OK;
}

/* ── sort orders ────────────────────────────────────────────────────── */

/* validator_set.go:851-856 — ValidatorsByVotingPower.Less() */
bool cmt_validators_by_voting_power_less(const cmt_validator_t *a,
                                         const cmt_validator_t *b)
{
    if (a->voting_power == b->voting_power) {             /* :852 */
        return addr_cmp(a->address, a->address_len,
                        b->address, b->address_len) == -1; /* :853 */
    }
    return a->voting_power > b->voting_power;             /* :855 */
}

/* validator_set.go:868-870 — ValidatorsByAddress.Less() */
bool cmt_validators_by_address_less(const cmt_validator_t *a,
                                    const cmt_validator_t *b)
{
    return addr_cmp(a->address, a->address_len,
                    b->address, b->address_len) == -1;    /* :869 */
}

/* One deterministic insertion sort, shared by both orders. n is at most
 * CMT_VALSET_MAX_CHANGES = 256, so the quadratic cost is irrelevant beside
 * a single 2592-byte key comparison. */
static void sort_ptrs(cmt_validator_t **v, size_t n,
                      bool (*less)(const cmt_validator_t *,
                                   const cmt_validator_t *))
{
    size_t i, j;

    for (i = 1; i < n; i++) {
        cmt_validator_t *key = v[i];
        j = i;
        while (j > 0 && less(key, v[j - 1])) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = key;
    }
}

void cmt_validators_sort_by_voting_power(cmt_validator_t **v, size_t n)
{
    if (v != NULL) {
        sort_ptrs(v, n, cmt_validators_by_voting_power_less);
    }
}

void cmt_validators_sort_by_address(cmt_validator_t **v, size_t n)
{
    if (v != NULL) {
        sort_ptrs(v, n, cmt_validators_by_address_less);
    }
}

/**
 * `sort.Sort(ValidatorsByVotingPower(...))` applied DIRECTLY to an array
 * of validators rather than to an array of pointers, for the two call
 * sites that own their storage (:674, :964). It is the same permutation;
 * doing it in place avoids a 340 KB staging array (128 validators, each
 * carrying a 2592-byte key) that has no business on a stack.
 */
static void sort_structs_by_voting_power(cmt_validator_t *v, size_t n)
{
    size_t i, j;

    for (i = 1; i < n; i++) {
        cmt_validator_t key = v[i];
        j = i;
        while (j > 0 && cmt_validators_by_voting_power_less(&key, &v[j - 1])) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = key;
    }
}

/* ══ validator_set.go ═════════════════════════════════════════════════ */

int cmt_validator_set_init(cmt_validator_set_t *vals,
                           cmt_validator_t *storage, size_t cap)
{
    if (vals == NULL || (storage == NULL && cap != 0)) {
        return CMT_FAULT;
    }
    if (cap > CMT_VALSET_MAX) {
        return CMT_REJECT;
    }
    memset(vals, 0, sizeof(*vals));
    vals->validators     = storage;
    vals->validators_cap = cap;
    /* validators_len 0, has_proposer false, total_voting_power 0 and
     * all_keys_have_same_type false are Go's `new(ValidatorSet)` zero
     * value — the one NewValidatorSet overrides at :78-80 and the one
     * ValidatorSetFromProto and ValidatorSetFromExistingValidators start
     * from before recomputing the flag at :924 / :961. */
    return CMT_OK;
}

/* :116-118 IsNilOrEmpty() */
bool cmt_validator_set_is_nil_or_empty(const cmt_validator_set_t *vals)
{
    return vals == NULL || vals->validators_len == 0;     /* :117 */
}

/* :308-310 Size() */
size_t cmt_validator_set_size(const cmt_validator_set_t *vals)
{
    return (vals == NULL) ? 0 : vals->validators_len;
}

/* :314-328 updateTotalVotingPower() */
int cmt_validator_set_update_total_voting_power(cmt_validator_set_t *vals)
{
    int64_t sum = 0;
    size_t  i;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < vals->validators_len; i++) {
        sum = cmt_vs_safe_add_clip(sum, vals->validators[i].voting_power); /* :318 */
        if (sum > CMT_MAX_TOTAL_VOTING_POWER) {           /* :319 */
            /* :320-324 panic. FAULT, not a verdict — see the header. */
            return CMT_FAULT;
        }
    }
    vals->total_voting_power = sum;                       /* :327 */
    return CMT_OK;
}

/* :332-337 TotalVotingPower() */
int cmt_validator_set_total_voting_power(cmt_validator_set_t *vals,
                                         int64_t *out)
{
    int rc;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->total_voting_power == 0) {                  /* :333 */
        rc = cmt_validator_set_update_total_voting_power(vals);  /* :334 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    *out = vals->total_voting_power;                      /* :336 */
    return CMT_OK;
}

/* :196-209 computeAvgProposerPriority() */
int cmt_validator_set_compute_avg_proposer_priority(
        const cmt_validator_set_t *vals, int64_t *out)
{
    cmt_i128_t sum;
    size_t     i;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {
        /* :197 n == 0 makes big.Int's Div panic; :195 says the function
         * must not be called on an empty set. */
        return CMT_REJECT;
    }
    sum = i128_from_i64(0);
    for (i = 0; i < vals->validators_len; i++) {          /* :199-201 */
        sum = i128_add(sum, i128_from_i64(vals->validators[i].proposer_priority));
    }
    if (!i128_floor_div_i64(sum, (int64_t)vals->validators_len, out)) {
        /* :207-208 panic("Cannot represent avg ProposerPriority as an
         * int64"). Unreachable when the divisor is the list length — see
         * the header — but implemented rather than assumed away. */
        return CMT_REJECT;
    }
    return CMT_OK;                                        /* :203-205 */
}

/* :212-231 computeMaxMinPriorityDiff() */
int cmt_validator_set_compute_max_min_priority_diff(
        const cmt_validator_set_t *vals, int64_t *out)
{
    int64_t mx = INT64_MIN, mn = INT64_MAX, diff;
    size_t  i;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {                      /* :213-215 panic */
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :218-225 */
        int64_t p = vals->validators[i].proposer_priority;
        if (p < mn) {
            mn = p;
        }
        if (p > mx) {
            mx = p;
        }
    }
    diff = go_sub(mx, mn);                                /* :226, may wrap */
    if (diff < 0) {                                       /* :227 */
        *out = go_neg(diff);                              /* :228, also wraps */
        return CMT_OK;
    }
    *out = diff;                                          /* :230 */
    return CMT_OK;
}

/* :158-179 RescalePriorities() */
int cmt_validator_set_rescale_priorities(cmt_validator_set_t *vals,
                                         int64_t diff_max)
{
    int64_t diff, ratio;
    size_t  i;
    int     rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (cmt_validator_set_is_nil_or_empty(vals)) {        /* :159-161 panic */
        return CMT_REJECT;
    }
    if (diff_max <= 0) {                                  /* :165-167 */
        return CMT_OK;
    }
    rc = cmt_validator_set_compute_max_min_priority_diff(vals, &diff); /* :172 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :173 ratio := (diff + diffMax - 1) / diffMax. Computed BEFORE the
     * test at :174 in the reference, so it is computed here too; diff_max
     * is strictly positive, so the division cannot fail. */
    rc = go_div(go_sub(go_add(diff, diff_max), 1), diff_max, &ratio);
    if (rc != CMT_OK) {
        return rc;
    }
    if (diff > diff_max) {                                /* :174 */
        for (i = 0; i < vals->validators_len; i++) {      /* :175-177 */
            int64_t p;
            rc = go_div(vals->validators[i].proposer_priority, ratio, &p);
            if (rc != CMT_OK) {
                /* ratio == 0 is Go's divide-by-zero panic. */
                return rc;
            }
            vals->validators[i].proposer_priority = p;
        }
    }
    return CMT_OK;
}

/* :233-239 getValWithMostPriority(), by index so the caller can mutate. */
static int most_priority_index(const cmt_validator_set_t *vals, size_t *out)
{
    const cmt_validator_t *res = NULL;
    size_t                 best = 0, i;
    int                    rc;

    if (vals->validators_len == 0) {
        return CMT_REJECT;   /* the reference returns nil */
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :235-237 */
        const cmt_validator_t *w = NULL;
        rc = cmt_validator_compare_proposer_priority(res, &vals->validators[i],
                                                     &w);
        if (rc != CMT_OK) {
            return rc;
        }
        if (w != res) {
            best = i;
        }
        res = w;
    }
    *out = best;
    return CMT_OK;
}

int cmt_validator_set_get_val_with_most_priority(
        const cmt_validator_set_t *vals, const cmt_validator_t **out)
{
    size_t idx;
    int    rc;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    rc = most_priority_index(vals, &idx);
    if (rc != CMT_OK) {
        return rc;
    }
    *out = &vals->validators[idx];
    return CMT_OK;
}

/* :241-249 shiftByAvgProposerPriority() */
int cmt_validator_set_shift_by_avg_proposer_priority(cmt_validator_set_t *vals)
{
    int64_t avg;
    size_t  i;
    int     rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (cmt_validator_set_is_nil_or_empty(vals)) {        /* :242-244 panic */
        return CMT_REJECT;
    }
    rc = cmt_validator_set_compute_avg_proposer_priority(vals, &avg); /* :245 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :246-248 */
        vals->validators[i].proposer_priority =
            cmt_vs_safe_sub_clip(vals->validators[i].proposer_priority, avg);
    }
    return CMT_OK;
}

/* :181-193 incrementProposerPriority() */
int cmt_validator_set_increment_proposer_priority_once(
        cmt_validator_set_t *vals, const cmt_validator_t **out_proposer)
{
    size_t  i, best;
    int64_t tvp;
    int     rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (cmt_validator_set_is_nil_or_empty(vals)) {
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :182-186 */
        vals->validators[i].proposer_priority =
            cmt_vs_safe_add_clip(vals->validators[i].proposer_priority,
                                 vals->validators[i].voting_power);
    }
    rc = most_priority_index(vals, &best);                /* :188 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_total_voting_power(vals, &tvp); /* :190 */
    if (rc != CMT_OK) {
        return rc;
    }
    vals->validators[best].proposer_priority =
        cmt_vs_safe_sub_clip(vals->validators[best].proposer_priority, tvp);
    if (out_proposer != NULL) {
        *out_proposer = &vals->validators[best];          /* :192 */
    }
    return CMT_OK;
}

/* :131-153 IncrementProposerPriority() */
int cmt_validator_set_increment_proposer_priority(cmt_validator_set_t *vals,
                                                  int32_t times)
{
    int64_t                tvp, diff_max;
    const cmt_validator_t *proposer = NULL;
    int32_t                t;
    int                    rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (cmt_validator_set_is_nil_or_empty(vals)) {        /* :132-134 panic */
        return CMT_REJECT;
    }
    if (times <= 0) {                                     /* :135-137 panic */
        return CMT_REJECT;
    }
    rc = cmt_validator_set_total_voting_power(vals, &tvp); /* :142 */
    if (rc != CMT_OK) {
        return rc;
    }
    diff_max = go_mul(CMT_PRIORITY_WINDOW_SIZE_FACTOR, tvp);
    rc = cmt_validator_set_rescale_priorities(vals, diff_max);  /* :143 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_shift_by_avg_proposer_priority(vals); /* :144 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (t = 0; t < times; t++) {                         /* :148-150 */
        rc = cmt_validator_set_increment_proposer_priority_once(vals,
                                                               &proposer);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    /* :152 vals.Proposer = proposer — a SNAPSHOT here; see the struct
     * comment in the header for why. */
    vals->proposer     = *proposer;
    vals->has_proposer = true;
    return CMT_OK;
}

/* :252-261 validatorListCopy() */
int cmt_validator_list_copy(const cmt_validator_t *src, size_t n,
                            cmt_validator_t *dst, size_t cap)
{
    if (n == 0) {
        return CMT_OK;                                    /* :253-255 */
    }
    if (src == NULL || dst == NULL) {
        return CMT_FAULT;
    }
    if (n > cap) {
        return CMT_REJECT;
    }
    memcpy(dst, src, n * sizeof(*src));                   /* :256-259 */
    return CMT_OK;
}

/* :264-271 Copy() */
int cmt_validator_set_copy(const cmt_validator_set_t *src,
                           cmt_validator_set_t *dst)
{
    int rc;

    if (src == NULL || dst == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_validator_list_copy(src->validators, src->validators_len,
                                 dst->validators, dst->validators_cap); /* :266 */
    if (rc != CMT_OK) {
        return rc;
    }
    dst->validators_len          = src->validators_len;
    dst->has_proposer            = src->has_proposer;     /* :267 */
    dst->proposer                = src->proposer;
    dst->total_voting_power      = src->total_voting_power;      /* :268 */
    dst->all_keys_have_same_type = src->all_keys_have_same_type; /* :269 */
    return CMT_OK;
}

/* :122-126 CopyIncrementProposerPriority() */
int cmt_validator_set_copy_increment_proposer_priority(
        const cmt_validator_set_t *src, cmt_validator_set_t *dst,
        int32_t times)
{
    int rc = cmt_validator_set_copy(src, dst);            /* :123 */

    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_validator_set_increment_proposer_priority(dst, times); /* :124 */
}

/* :275-282 HasAddress() */
bool cmt_validator_set_has_address(const cmt_validator_set_t *vals,
                                   const uint8_t *address, size_t address_len)
{
    size_t i;

    if (vals == NULL) {
        return false;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :276-280 */
        if (addr_eq(vals->validators[i].address,
                    vals->validators[i].address_len, address, address_len)) {
            return true;
        }
    }
    return false;                                         /* :281 */
}

/* :286-293 GetByAddress() */
int cmt_validator_set_get_by_address(const cmt_validator_set_t *vals,
                                     const uint8_t *address,
                                     size_t address_len,
                                     int32_t *out_index,
                                     cmt_validator_t *out)
{
    size_t i;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :287-291 */
        if (addr_eq(vals->validators[i].address,
                    vals->validators[i].address_len, address, address_len)) {
            if (out_index != NULL) {
                *out_index = (int32_t)i;
            }
            if (out != NULL) {
                *out = vals->validators[i];               /* :289 a COPY */
            }
            return CMT_OK;
        }
    }
    if (out_index != NULL) {
        *out_index = -1;                                  /* :292 */
    }
    return CMT_OK;
}

/* :299-305 GetByIndex() */
int cmt_validator_set_get_by_index(const cmt_validator_set_t *vals,
                                   int32_t index, cmt_validator_t *out)
{
    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (index < 0 || (size_t)index >= vals->validators_len) { /* :300-302 */
        return CMT_REJECT;
    }
    if (out != NULL) {
        *out = vals->validators[index];                   /* :303-304 a COPY */
    }
    return CMT_OK;
}

/* :351-359 findProposer() */
int cmt_validator_set_find_proposer(const cmt_validator_set_t *vals,
                                    const cmt_validator_t **out)
{
    const cmt_validator_t *proposer = NULL;
    size_t                 i;
    int                    rc;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :353-357 */
        const cmt_validator_t *val = &vals->validators[i];
        /* :354 — NOTE reference quirk: a validator whose address equals
         * the current best's is SKIPPED. On a set with unique addresses
         * that can only be the current best itself. Kept as-is. */
        if (proposer == NULL ||
            !addr_eq(val->address, val->address_len,
                     proposer->address, proposer->address_len)) {
            rc = cmt_validator_compare_proposer_priority(proposer, val,
                                                         &proposer);
            if (rc != CMT_OK) {
                return rc;
            }
        }
    }
    *out = proposer;                                      /* :358 */
    return CMT_OK;
}

/* :341-349 GetProposer() */
int cmt_validator_set_get_proposer(cmt_validator_set_t *vals,
                                   cmt_validator_t *out)
{
    int rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {                      /* :342-344 */
        return CMT_REJECT;
    }
    if (!vals->has_proposer) {                            /* :345-347 */
        const cmt_validator_t *p = NULL;
        rc = cmt_validator_set_find_proposer(vals, &p);
        if (rc != CMT_OK) {
            return rc;
        }
        vals->proposer     = *p;
        vals->has_proposer = true;
    }
    if (out != NULL) {
        *out = vals->proposer;                            /* :348 a Copy() */
    }
    return CMT_OK;
}

/* :748-760 findPreviousProposer() */
int cmt_validator_set_find_previous_proposer(const cmt_validator_set_t *vals,
                                             const cmt_validator_t **out)
{
    const cmt_validator_t *prev = NULL;
    size_t                 i;
    int                    rc;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {
        return CMT_REJECT;   /* the reference would return nil */
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :750-758 */
        const cmt_validator_t *val = &vals->validators[i];
        const cmt_validator_t *w   = NULL;

        if (prev == NULL) {                               /* :751-754 */
            prev = val;
            continue;
        }
        rc = cmt_validator_compare_proposer_priority(prev, val, &w);
        if (rc != CMT_OK) {
            return rc;
        }
        if (w == prev) {                                  /* :755-757 keep the LOSER */
            prev = val;
        }
    }
    *out = prev;                                          /* :759 */
    return CMT_OK;
}

/* :762-784 checkAllKeysHaveSameType() */
int cmt_validator_set_check_all_keys_have_same_type(cmt_validator_set_t *vals)
{
    bool   have_first = false;   /* the reference's `firstKeyType != ""` */
    size_t i;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len == 0) {                      /* :763-766 */
        vals->all_keys_have_same_type = true;
        return CMT_OK;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :769-781 */
        const cmt_pb_public_key_t *pk = &vals->validators[i].pub_key;

        if (!have_first) {                                /* :770 */
            if (!pk->present) {
                continue;                                 /* :771-774 */
            }
            have_first = true;                            /* :775 */
        }
        /* :777 `val.PubKey.Type()`. NOTE reference quirk: with
         * firstKeyType already set, a keyless member dereferences a nil
         * interface and PANICS. Reproduced as a REJECT — see the header. */
        if (!pk->present) {
            return CMT_REJECT;
        }
        /* :777-780 "the types differ" is unreachable in this port: K-2
         * gives it exactly one key type, so all_keys_have_same_type is
         * never written false here. Stated, not hidden. */
    }
    vals->all_keys_have_same_type = true;                 /* :783 */
    return CMT_OK;
}

/* :788-790 AllKeysHaveSameType() */
bool cmt_validator_set_all_keys_have_same_type(const cmt_validator_set_t *vals)
{
    return vals != NULL && vals->all_keys_have_same_type;
}

/* :698-702 (vals *ValidatorSet) VerifyCommit() — the method form of
 * types.VerifyCommit and nothing more; the reference's whole body is the
 * one delegation at :701. */
int cmt_validator_set_verify_commit(cmt_validator_set_t *vals,
                                    const uint8_t *chain_id,
                                    size_t chain_id_len,
                                    const cmt_pb_block_id_t *block_id,
                                    int64_t height,
                                    const cmt_pb_commit_t *commit,
                                    cmt_vs_error_t *err)
{
    return cmt_verify_commit(chain_id, chain_id_len, vals, block_id,
                             height, commit, err);                /* :701 */
}

/* :91-113 ValidateBasic() */
int cmt_validator_set_validate_basic(const cmt_validator_set_t *vals)
{
    size_t i;
    int    rc;

    if (cmt_validator_set_is_nil_or_empty(vals)) {        /* :92-94 */
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :96-100 */
        rc = cmt_validator_validate_basic(&vals->validators[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    /* :102-104 — a nil Proposer reaches Validator.ValidateBasic's nil
     * branch (validator.go:38-40) and is an error. */
    if (!vals->has_proposer) {
        return CMT_REJECT;
    }
    rc = cmt_validator_validate_basic(&vals->proposer);
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :106-110 */
        if (addr_eq(vals->validators[i].address,
                    vals->validators[i].address_len,
                    vals->proposer.address, vals->proposer.address_len)) {
            return CMT_OK;                                /* :108 */
        }
    }
    return CMT_REJECT;                                    /* :112 ErrProposerNotInVals */
}

/* :365-371 Hash() */
int cmt_validator_set_hash(const cmt_validator_set_t *vals,
                           uint8_t *scratch, size_t scratch_cap,
                           cmt_merkle_item_t *items, size_t items_cap,
                           uint8_t out[CMT_TMHASH_SIZE])
{
    size_t off = 0, i;
    int    rc;

    if (vals == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len > items_cap) {
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {          /* :366-369 */
        size_t len = 0;
        if (off > scratch_cap) {
            return CMT_REJECT;
        }
        rc = cmt_validator_bytes(&vals->validators[i], scratch + off,
                                 scratch_cap - off, &len);
        if (rc != CMT_OK) {
            return rc;
        }
        items[i].data = scratch + off;
        items[i].len  = len;
        off += len;
    }
    /* :370 — an empty set hashes the empty tree, H(""). */
    return cmt_merkle_hash_from_byte_slices(items, vals->validators_len, out);
}

/* ── change-set machinery ───────────────────────────────────────────── */

/* :408-442 processChanges() */
int cmt_validator_set_process_changes(const cmt_validator_t *orig_changes,
                                      size_t n,
                                      cmt_valset_scratch_t *scratch,
                                      cmt_validator_t ***out_updates,
                                      size_t *out_updates_len,
                                      cmt_validator_t ***out_removals,
                                      size_t *out_removals_len)
{
    size_t         i, n_up = 0, n_rm = 0;
    const uint8_t *prev_addr = NULL;   /* Go's `var prevAddr Address` — nil */
    size_t         prev_len  = 0;
    int            rc;

    if (scratch == NULL || out_updates == NULL || out_updates_len == NULL ||
        out_removals == NULL || out_removals_len == NULL) {
        return CMT_FAULT;
    }
    if (n > CMT_VALSET_MAX_CHANGES) {
        return CMT_REJECT;   /* capacity — see "Capacity" in the header */
    }
    rc = cmt_validator_list_copy(orig_changes, n, scratch->changes,
                                 CMT_VALSET_MAX_CHANGES);   /* :410 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < n; i++) {
        scratch->sorted[i] = &scratch->changes[i];
    }
    cmt_validators_sort_by_address(scratch->sorted, n);      /* :411 */

    for (i = 0; i < n; i++) {                                /* :418-439 */
        cmt_validator_t *u = scratch->sorted[i];

        /* :419-422. NOTE reference quirk: `prevAddr` starts as a NIL
         * slice, and `bytes.Equal(x, nil)` is true when x is empty — so a
         * FIRST change carrying a zero-length address is reported as a
         * duplicate. Reproduced exactly. */
        if (addr_eq(u->address, u->address_len, prev_addr, prev_len)) {
            return CMT_REJECT;
        }
        if (u->voting_power < 0) {                           /* :425-427 */
            return CMT_REJECT;
        }
        if (u->voting_power > CMT_MAX_TOTAL_VOTING_POWER) {  /* :428-431 */
            return CMT_REJECT;
        }
        if (u->voting_power == 0) {                          /* :432-433 */
            scratch->removals[n_rm++] = u;
        } else {                                             /* :434-435 */
            scratch->updates[n_up++] = u;
        }
        prev_addr = u->address;                              /* :438 */
        prev_len  = u->address_len;
    }
    *out_updates      = scratch->updates;
    *out_updates_len  = n_up;
    *out_removals     = scratch->removals;
    *out_removals_len = n_rm;
    return CMT_OK;                                           /* :441 */
}

/* :467-473 — the `delta` closure verifyUpdates sorts and sums by. */
static int64_t update_delta(const cmt_validator_t *update,
                            const cmt_validator_set_t *vals)
{
    size_t i;

    for (i = 0; i < vals->validators_len; i++) {
        if (addr_eq(vals->validators[i].address,
                    vals->validators[i].address_len,
                    update->address, update->address_len)) {
            /* :470 — Go int64 subtraction, which wraps. */
            return go_sub(update->voting_power,
                          vals->validators[i].voting_power);
        }
    }
    return update->voting_power;                             /* :472 */
}

/* :462-488 verifyUpdates() */
int cmt_validator_set_verify_updates(cmt_validator_t *const *updates,
                                     size_t updates_len,
                                     cmt_validator_set_t *vals,
                                     int64_t removed_power,
                                     int64_t *out_tvp)
{
    /* :475 — `updatesCopy` exists so the CALLER's list is not reordered,
     * and that matters: the list MUST stay in the ADDRESS order
     * processChanges produced, because applyUpdates (:534-537, :543-557)
     * merges it against the address-sorted membership and depends on that
     * order. Sorting the caller's array in place would feed a
     * delta-ordered list into a two-sorted-list merge, which duplicates
     * and drops entries. Hence `updates` is read-only here.
     *
     * The copy this port sorts holds the DELTAS ALONE, not the pointers.
     * The loop below reads nothing from an update except its delta
     * (:481-486), so ordering the deltas produces exactly the reference's
     * sequence of partial sums; carrying the pointers along would be a
     * second array nothing ever reads. */
    int64_t deltas[CMT_VALSET_MAX_CHANGES];
    int64_t tvp_after_removals, tvp;
    size_t  i, j;
    int     rc;

    if (vals == NULL || out_tvp == NULL || (updates == NULL && updates_len)) {
        return CMT_FAULT;
    }
    if (updates_len > CMT_VALSET_MAX_CHANGES) {
        return CMT_REJECT;
    }
    /* The reference's closure recomputes `delta` on every comparison
     * (:467-473); it is a pure function of the update and of `vals`, and
     * `vals` does not change during the sort, so computing each one once
     * is the same function evaluated fewer times. It also turns an
     * O(n^2 * m) scan over 32-byte addresses into O(n * m). */
    for (i = 0; i < updates_len; i++) {
        deltas[i] = update_delta(updates[i], vals);
    }
    /* :476-478 — sort the deltas ascending. An insertion sort; equal
     * deltas keep their relative order where the reference's sort.Slice
     * would not, and that does not matter (see the header). */
    for (i = 1; i < updates_len; i++) {
        int64_t kd = deltas[i];
        j = i;
        while (j > 0 && kd < deltas[j - 1]) {
            deltas[j] = deltas[j - 1];
            j--;
        }
        deltas[j] = kd;
    }
    rc = cmt_validator_set_total_voting_power(vals, &tvp);   /* :480 */
    if (rc != CMT_OK) {
        return rc;
    }
    tvp_after_removals = go_sub(tvp, removed_power);
    for (i = 0; i < updates_len; i++) {                      /* :481-486 */
        tvp_after_removals = go_add(tvp_after_removals, deltas[i]);
        if (tvp_after_removals > CMT_MAX_TOTAL_VOTING_POWER) {
            return CMT_REJECT;   /* :484 ErrTotalVotingPowerOverflow */
        }
    }
    *out_tvp = go_add(tvp_after_removals, removed_power);    /* :487 */
    return CMT_OK;
}

/* :490-498 numNewValidators() */
size_t cmt_validator_set_num_new_validators(cmt_validator_t *const *updates,
                                            size_t updates_len,
                                            const cmt_validator_set_t *vals)
{
    size_t count = 0, i;

    if (updates == NULL || vals == NULL) {
        return 0;
    }
    for (i = 0; i < updates_len; i++) {                      /* :492-496 */
        if (!cmt_validator_set_has_address(vals, updates[i]->address,
                                           updates[i]->address_len)) {
            count++;
        }
    }
    return count;                                            /* :497 */
}

/* :512-530 computeNewPriorities() */
int cmt_validator_set_compute_new_priorities(cmt_validator_t **updates,
                                             size_t updates_len,
                                             const cmt_validator_set_t *vals,
                                             int64_t updated_total_voting_power)
{
    size_t i;

    if (vals == NULL || (updates == NULL && updates_len)) {
        return CMT_FAULT;
    }
    for (i = 0; i < updates_len; i++) {                      /* :513-529 */
        cmt_validator_t *u = updates[i];
        int32_t          idx = -1;
        cmt_validator_t  found;
        int              rc;

        rc = cmt_validator_set_get_by_address(vals, u->address, u->address_len,
                                              &idx, &found);   /* :515 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (idx < 0) {
            /* :525 — the entry penalty, -1.125 * P computed as
             * -(P + (P >> 3)). Go arithmetic: the shift is arithmetic and
             * both the add and the negation wrap. */
            u->proposer_priority =
                go_neg(go_add(updated_total_voting_power,
                              go_shr(updated_total_voting_power, 3)));
        } else {
            u->proposer_priority = found.proposer_priority;   /* :527 */
        }
    }
    return CMT_OK;
}

/* :536-571 applyUpdates() */
int cmt_validator_set_apply_updates(cmt_validator_t **existing,
                                    size_t existing_len,
                                    cmt_validator_t **updates,
                                    size_t updates_len,
                                    cmt_validator_t **merged,
                                    size_t merged_cap,
                                    size_t *out_len)
{
    size_t i = 0, e = 0, u = 0, j;

    if (merged == NULL || out_len == NULL ||
        (existing == NULL && existing_len) || (updates == NULL && updates_len)) {
        return CMT_FAULT;
    }
    cmt_validators_sort_by_address(existing, existing_len);   /* :538 */

    while (e < existing_len && u < updates_len) {             /* :543-557 */
        if (i >= merged_cap) {
            return CMT_REJECT;
        }
        if (addr_cmp(existing[e]->address, existing[e]->address_len,
                     updates[u]->address, updates[u]->address_len) < 0) {
            merged[i] = existing[e];                          /* :544-546 */
            e++;
        } else {
            merged[i] = updates[u];                           /* :549 */
            if (addr_eq(existing[e]->address, existing[e]->address_len,
                        updates[u]->address, updates[u]->address_len)) {
                e++;                                          /* :550-553 */
            }
            u++;                                              /* :554 */
        }
        i++;                                                  /* :556 */
    }
    for (j = e; j < existing_len; j++) {                      /* :560-563 */
        if (i >= merged_cap) {
            return CMT_REJECT;
        }
        merged[i++] = existing[j];
    }
    for (j = u; j < updates_len; j++) {                       /* :565-568 */
        if (i >= merged_cap) {
            return CMT_REJECT;
        }
        merged[i++] = updates[j];
    }
    *out_len = i;                                             /* :570 */
    return CMT_OK;
}

/* :575-589 verifyRemovals() */
int cmt_validator_set_verify_removals(cmt_validator_t *const *deletes,
                                      size_t deletes_len,
                                      const cmt_validator_set_t *vals,
                                      int64_t *out_power)
{
    int64_t removed = 0;
    size_t  i;

    if (vals == NULL || out_power == NULL ||
        (deletes == NULL && deletes_len)) {
        return CMT_FAULT;
    }
    for (i = 0; i < deletes_len; i++) {                       /* :577-584 */
        int32_t         idx = -1;
        cmt_validator_t found;
        int             rc = cmt_validator_set_get_by_address(
            vals, deletes[i]->address, deletes[i]->address_len, &idx, &found);

        if (rc != CMT_OK) {
            return rc;
        }
        if (idx < 0) {
            return CMT_REJECT;                                /* :580-582 */
        }
        removed = go_add(removed, found.voting_power);        /* :583 */
    }
    /* :585-587 panic("more deletes than validators"). Reached only AFTER
     * the loop in the reference, so the order of the two verdicts is kept. */
    if (deletes_len > vals->validators_len) {
        return CMT_REJECT;
    }
    *out_power = removed;                                     /* :588 */
    return CMT_OK;
}

/* :594-618 applyRemovals() */
int cmt_validator_set_apply_removals(cmt_validator_t **merged,
                                     size_t merged_len,
                                     cmt_validator_t *const *deletes,
                                     size_t deletes_len,
                                     size_t *out_len)
{
    size_t i = 0, e = 0, d = 0, j;

    if (out_len == NULL || (merged == NULL && merged_len) ||
        (deletes == NULL && deletes_len)) {
        return CMT_FAULT;
    }
    if (deletes_len > merged_len) {
        /* :597 `make([]*Validator, len(existing)-len(deletes))` would be a
         * negative length and panic. */
        return CMT_REJECT;
    }
    while (d < deletes_len) {                                 /* :601-609 */
        if (e >= merged_len) {
            /* :602 indexes existing[0] on an exhausted slice — a Go index
             * panic, made an explicit check (INVARIANT 7495d337). */
            return CMT_REJECT;
        }
        if (addr_eq(merged[e]->address, merged[e]->address_len,
                    deletes[d]->address, deletes[d]->address_len)) {
            d++;                                              /* :602-603 */
        } else {
            merged[i++] = merged[e];                          /* :604-607 */
        }
        e++;                                                  /* :608 */
    }
    for (j = e; j < merged_len; j++) {                        /* :612-615 */
        merged[i++] = merged[j];
    }
    *out_len = i;                                             /* :617 */
    return CMT_OK;
}

/* :624-677 updateWithChangeSet() */
int cmt_validator_set_update_with_change_set_ex(cmt_validator_set_t *vals,
                                                const cmt_validator_t *changes,
                                                size_t changes_len,
                                                bool allow_deletes,
                                                cmt_valset_scratch_t *scratch)
{
    cmt_validator_t **updates = NULL, **removals = NULL;
    size_t            updates_len = 0, removals_len = 0;
    size_t            num_new, new_size, merged_len = 0, final_len = 0, i;
    int64_t           removed_power = 0, tvp_before_removals = 0, tvp = 0;
    int               rc;

    if (vals == NULL || scratch == NULL) {
        return CMT_FAULT;
    }
    if (changes_len == 0) {                                   /* :625-627 */
        return CMT_OK;
    }
    rc = cmt_validator_set_process_changes(changes, changes_len, scratch,
                                           &updates, &updates_len,
                                           &removals, &removals_len); /* :630 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!allow_deletes && removals_len != 0) {                /* :635-637 */
        return CMT_REJECT;
    }
    num_new = cmt_validator_set_num_new_validators(updates, updates_len, vals);
    if (num_new == 0 && vals->validators_len == removals_len) { /* :640-642 */
        return CMT_REJECT;
    }
    rc = cmt_validator_set_verify_removals(removals, removals_len, vals,
                                           &removed_power);   /* :646 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_verify_updates(updates, updates_len, vals,
                                          removed_power,
                                          &tvp_before_removals); /* :653 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* ⚠ THE ONE ADDED RULE — a capacity bound, not a consensus rule. It is
     * placed after verifyUpdates so the reference's own error precedence
     * is untouched, and before any mutation so the "set is not changed on
     * error" contract (:690-691) holds. Every update either replaces a
     * member or is new, and verifyRemovals has proved every removal is a
     * member, so this is the exact resulting size. */
    new_size = vals->validators_len + num_new - removals_len;
    if (new_size > CMT_VALSET_MAX || new_size > vals->validators_cap) {
        return CMT_REJECT;
    }
    rc = cmt_validator_set_compute_new_priorities(updates, updates_len, vals,
                                                  tvp_before_removals); /* :659 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < vals->validators_len; i++) {
        scratch->existing[i] = &vals->validators[i];
    }
    rc = cmt_validator_set_apply_updates(scratch->existing,
                                         vals->validators_len,
                                         updates, updates_len,
                                         scratch->merged,
                                         CMT_VALSET_MAX + CMT_VALSET_MAX_CHANGES,
                                         &merged_len);        /* :662 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_apply_removals(scratch->merged, merged_len,
                                          removals, removals_len,
                                          &final_len);        /* :663 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (final_len != new_size || final_len > vals->validators_cap) {
        /* The predicted size and the applied size must agree; a mismatch
         * would mean the set's unique-address invariant was already
         * broken before this call. */
        return CMT_REJECT;
    }
    /* `vals.Validators = merged[:i]` (:570, :617). A C write-back cannot
     * be done in place: `merged` is a permutation whose sources live in
     * the destination array. Stage first, then copy. */
    for (i = 0; i < final_len; i++) {
        scratch->final[i] = *scratch->merged[i];
    }
    memcpy(vals->validators, scratch->final,
           final_len * sizeof(*vals->validators));
    vals->validators_len = final_len;

    rc = cmt_validator_set_check_all_keys_have_same_type(vals); /* :666 */
    if (rc != CMT_OK) {
        return rc;
    }

    /* :668 — "will panic if total voting power > MaxTotalVotingPower". The
     * cache is cleared first so the recomputation actually happens. */
    vals->total_voting_power = 0;
    rc = cmt_validator_set_update_total_voting_power(vals);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_total_voting_power(vals, &tvp);     /* :671 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_rescale_priorities(
        vals, go_mul(CMT_PRIORITY_WINDOW_SIZE_FACTOR, tvp));
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_shift_by_avg_proposer_priority(vals); /* :672 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :674 sort.Sort(ValidatorsByVotingPower(vals.Validators)) */
    sort_structs_by_voting_power(vals->validators, vals->validators_len);
    return CMT_OK;                                            /* :676 */
}

/* :692-694 UpdateWithChangeSet() */
int cmt_validator_set_update_with_change_set(cmt_validator_set_t *vals,
                                             const cmt_validator_t *changes,
                                             size_t changes_len,
                                             cmt_valset_scratch_t *scratch)
{
    return cmt_validator_set_update_with_change_set_ex(vals, changes,
                                                       changes_len, true,
                                                       scratch);
}

/* :77-89 NewValidatorSet() */
int cmt_validator_set_new(cmt_validator_set_t *vals,
                          const cmt_validator_t *valz, size_t n,
                          cmt_valset_scratch_t *scratch)
{
    int rc;

    if (vals == NULL || scratch == NULL) {
        return CMT_FAULT;
    }
    vals->all_keys_have_same_type = true;                     /* :78-80 */
    rc = cmt_validator_set_update_with_change_set_ex(vals, valz, n, false,
                                                     scratch);  /* :81 */
    if (rc != CMT_OK) {
        return rc;                                            /* :82-84 panic */
    }
    if (n > 0) {                                              /* :85-87 */
        rc = cmt_validator_set_increment_proposer_priority(vals, 1);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    return CMT_OK;                                            /* :88 */
}

/* ── codec side ─────────────────────────────────────────────────────── */

/* :877-904 ToProto() */
int cmt_validator_set_to_proto(const cmt_validator_set_t *vals,
                               cmt_pb_validator_set_t *out)
{
    size_t i;
    int    rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    /* cmt_pb_validator_set_init preserves the caller's storage pointer and
     * capacity by contract (cmt_pb.c:1498-1503) and resets everything
     * else, so it is safe to run first on both paths. */
    cmt_pb_validator_set_init(out);
    if (cmt_validator_set_is_nil_or_empty(vals)) {
        /* :878-880 — an EMPTY message, not an error. */
        return CMT_OK;
    }
    if (vals->validators_len > out->validators_cap || out->validators == NULL) {
        return CMT_REJECT;
    }
    for (i = 0; i < vals->validators_len; i++) {              /* :884-890 */
        rc = cmt_validator_to_proto(&vals->validators[i], &out->validators[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    out->validators_len = vals->validators_len;               /* :891 */

    if (!vals->has_proposer) {
        /* :893-896 — Proposer.ToProto() on a nil proposer is an error. */
        return CMT_REJECT;
    }
    rc = cmt_validator_to_proto(&vals->proposer, &out->proposer);
    if (rc != CMT_OK) {
        return rc;
    }
    out->has_proposer = true;                                 /* :897 */
    /* :899-901 — the cached total must NOT reach the bytes. */
    out->total_voting_power = 0;
    return CMT_OK;
}

/* :909-941 ValidatorSetFromProto() */
int cmt_validator_set_from_proto(const cmt_pb_validator_set_t *vp,
                                 cmt_validator_set_t *vals)
{
    size_t  i;
    int64_t tvp;
    int     rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (vp == NULL) {                                         /* :910-912 */
        return CMT_REJECT;
    }
    if (vp->validators_len > vals->validators_cap) {
        return CMT_REJECT;
    }
    /* :913 `vals := new(ValidatorSet)` — a FRESH zero value, so the cached
     * total must be cleared or :938's recomputation would not happen. */
    vals->validators_len          = 0;
    vals->has_proposer            = false;
    vals->total_voting_power      = 0;
    vals->all_keys_have_same_type = false;

    for (i = 0; i < vp->validators_len; i++) {                /* :915-922 */
        rc = cmt_validator_from_proto(&vp->validators[i], &vals->validators[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    vals->validators_len = vp->validators_len;                /* :923 */
    rc = cmt_validator_set_check_all_keys_have_same_type(vals); /* :924 */
    if (rc != CMT_OK) {
        return rc;
    }

    if (!vp->has_proposer) {
        /* :926 vp.GetProposer() is nil and ValidatorFromProto rejects it
         * (validator.go:160-162). */
        return CMT_REJECT;
    }
    rc = cmt_validator_from_proto(&vp->proposer, &vals->proposer); /* :926-929 */
    if (rc != CMT_OK) {
        return rc;
    }
    vals->has_proposer = true;                                /* :931 */

    /* :933-938 — the peer's total is NEVER trusted; it is recomputed. */
    rc = cmt_validator_set_total_voting_power(vals, &tvp);
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_validator_set_validate_basic(vals);            /* :940 */
}

/* :947-966 ValidatorSetFromExistingValidators() */
int cmt_validator_set_from_existing_validators(cmt_validator_set_t *vals,
                                               const cmt_validator_t *valz,
                                               size_t n)
{
    const cmt_validator_t *prev = NULL;
    size_t                 i;
    int                    rc;

    if (vals == NULL) {
        return CMT_FAULT;
    }
    if (n == 0) {                                             /* :948-950 */
        return CMT_REJECT;
    }
    if (valz == NULL) {
        return CMT_FAULT;
    }
    if (n > vals->validators_cap || n > CMT_VALSET_MAX) {
        return CMT_REJECT;
    }
    for (i = 0; i < n; i++) {                                 /* :951-956 */
        rc = cmt_validator_validate_basic(&valz[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    memcpy(vals->validators, valz, n * sizeof(*valz));        /* :958-960 */
    vals->validators_len          = n;
    vals->has_proposer            = false;
    vals->total_voting_power      = 0;
    vals->all_keys_have_same_type = false;

    rc = cmt_validator_set_check_all_keys_have_same_type(vals); /* :961 */
    if (rc != CMT_OK) {
        return rc;
    }

    rc = cmt_validator_set_find_previous_proposer(vals, &prev); /* :962 */
    if (rc != CMT_OK) {
        return rc;
    }
    vals->proposer     = *prev;
    vals->has_proposer = true;

    rc = cmt_validator_set_update_total_voting_power(vals);   /* :963 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :964 sort.Sort(ValidatorsByVotingPower(...)) */
    sort_structs_by_voting_power(vals->validators, n);
    return CMT_OK;                                            /* :965 */
}
