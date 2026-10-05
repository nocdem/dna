/**
 * @file evm_u256.c
 * @brief 256-bit unsigned integer arithmetic for the Nodus EVM (phase 1).
 *
 * Contract: evm_u256.h. Reference semantics (pinned): ethereum/execution-specs
 * @a87891f7, src/ethereum/forks/prague/vm/instructions/{arithmetic,bitwise,
 * comparison}.py. Each EVM operation below names the reference function whose
 * result it reproduces.
 *
 * Determinism (design §4, D2):
 *   - No undefined behaviour for any input. Every shift count used on a
 *     uint64_t is < 64; a shift that would be by 64 is a separate branch.
 *     All arithmetic is on unsigned types (no signed overflow).
 *   - The ONLY build-dependent code is the 64x64->128 multiply helper
 *     (mul64): a `unsigned __int128` fast path when the compiler offers it,
 *     otherwise (or with -DEVM_U256_PORTABLE) a 32-bit-halves path. Both
 *     return the exact 128-bit product, so results are identical. Division
 *     is a single implementation (Knuth algorithm D over 32-bit digits with
 *     uint64_t intermediates) shared by both builds.
 *   - Every function copies its operands into locals before writing r, so r
 *     may alias any operand (struct assignment, never overlapping memcpy).
 *   - No allocation, no global state, no I/O.
 */
#include "evm_u256.h"

#include <string.h>

#define M32 0xFFFFFFFFull

/* ── 64x64 -> 128 multiply ───────────────────────────────────────────── */

#if defined(__SIZEOF_INT128__) && !defined(EVM_U256_PORTABLE)
__extension__ typedef unsigned __int128 evm_u128_t;

/* lo = low 64 bits of a*b, *hi = high 64 bits. */
static inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t *hi)
{
    evm_u128_t p = (evm_u128_t)a * b;
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
}
#else
/* Portable path: schoolbook over 32-bit halves. Every partial product is
 * < 2^64 and `mid` is at most 3*(2^32-1) < 2^64, so nothing overflows. */
static inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t *hi)
{
    uint64_t a0 = a & M32, a1 = a >> 32;
    uint64_t b0 = b & M32, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & M32) + (p10 & M32);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    return (mid << 32) | (p00 & M32);
}
#endif

/* ── internal helpers ────────────────────────────────────────────────── */

static int is_neg(const evm_u256 *a)
{
    return (int)(a->w[3] >> 63);
}

/* r = -a mod 2^256 (two's complement: ~a + 1). */
static void neg(evm_u256 *r, const evm_u256 *a)
{
    evm_u256 t = *a;
    uint64_t carry = 1;
    for (int i = 0; i < 4; i++) {
        uint64_t v = ~t.w[i] + carry;
        carry = (carry && v == 0) ? 1u : 0u;
        r->w[i] = v;
    }
}

/* 1 if any of the high three limbs is non-zero, i.e. a >= 2^64. */
static int hi_limbs_nonzero(const evm_u256 *a)
{
    return (a->w[1] | a->w[2] | a->w[3]) != 0;
}

/* Full 256x256 -> 512-bit product, out[0] least significant. */
static void mul_full(uint64_t out[8], const uint64_t a[4], const uint64_t b[4])
{
    for (int i = 0; i < 8; i++)
        out[i] = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t hi;
            uint64_t lo = mul64(a[i], b[j], &hi);
            lo += out[i + j];
            hi += (lo < out[i + j]);   /* hi <= 2^64-2, cannot wrap */
            lo += carry;
            hi += (lo < carry);
            out[i + j] = lo;
            carry = hi;
        }
        out[i + 4] = carry;
    }
}

static unsigned nlz32(uint32_t x)
{
    unsigned n = 0;
    if (x == 0)
        return 32;
    while ((x & 0x80000000u) == 0) {
        x <<= 1;
        n++;
    }
    return n;
}

/**
 * Wide unsigned division: num (nlimbs = 8, 512 bits) / den (4 limbs).
 * den must be non-zero. Writes the low 256 bits of the quotient to q (may be
 * NULL) and the remainder (< den, so it fits 256 bits) to rem (may be NULL).
 *
 * Knuth, TAOCP vol. 2, 4.3.1 algorithm D, in the 32-bit-digit form of
 * Warren, Hacker's Delight 2nd ed., fig. 9-1 (divmnu), rewritten to use only
 * unsigned arithmetic (the multiply-and-subtract borrow is tracked
 * explicitly instead of via signed right shifts).
 */
static void divmod_wide(evm_u256 *q, evm_u256 *rem,
                        const uint64_t num[8], const uint64_t den[4])
{
    uint32_t u[16], v[8];
    uint32_t un[17], vn[8];
    uint32_t qd[16];
    int m, n;

    for (int i = 0; i < 8; i++) {
        u[2 * i]     = (uint32_t)(num[i] & M32);
        u[2 * i + 1] = (uint32_t)(num[i] >> 32);
    }
    for (int i = 0; i < 4; i++) {
        v[2 * i]     = (uint32_t)(den[i] & M32);
        v[2 * i + 1] = (uint32_t)(den[i] >> 32);
    }
    m = 16;
    while (m > 0 && u[m - 1] == 0)
        m--;
    n = 8;
    while (n > 0 && v[n - 1] == 0)
        n--;
    /* n >= 1 is the caller's contract (den != 0). */

    for (int i = 0; i < 16; i++)
        qd[i] = 0;

    if (m < n) {
        /* num < den: quotient 0, remainder num (fits 256 bits since m < n <= 8). */
        if (q) {
            evm_u256_zero(q);
        }
        if (rem) {
            for (int i = 0; i < 4; i++)
                rem->w[i] = num[i];
        }
        return;
    }

    if (n == 1) {
        /* Short division by a single 32-bit digit. */
        uint64_t k = 0;
        for (int j = m - 1; j >= 0; j--) {
            uint64_t t = (k << 32) | u[j];
            qd[j] = (uint32_t)(t / v[0]);
            k = t - (uint64_t)qd[j] * v[0];
        }
        if (q) {
            for (int i = 0; i < 4; i++)
                q->w[i] = (uint64_t)qd[2 * i] | ((uint64_t)qd[2 * i + 1] << 32);
        }
        if (rem) {
            evm_u256_from_u64(rem, k);
        }
        return;
    }

    /* D1: normalise so the divisor's top digit has its high bit set.
     * s in [0,31]; (x >> (32 - s)) is done on uint64_t so s == 0 gives a
     * defined shift by 32 that yields 0 for a 32-bit x. */
    unsigned s = nlz32(v[n - 1]);
    for (int i = n - 1; i > 0; i--)
        vn[i] = (uint32_t)((((uint64_t)v[i] << s) | ((uint64_t)v[i - 1] >> (32 - s))) & M32);
    vn[0] = (uint32_t)(((uint64_t)v[0] << s) & M32);

    un[m] = (uint32_t)(((uint64_t)u[m - 1] >> (32 - s)) & M32);
    for (int i = m - 1; i > 0; i--)
        un[i] = (uint32_t)((((uint64_t)u[i] << s) | ((uint64_t)u[i - 1] >> (32 - s))) & M32);
    un[0] = (uint32_t)(((uint64_t)u[0] << s) & M32);

    const uint64_t b = 1ull << 32;
    for (int j = m - n; j >= 0; j--) {
        /* D3: estimate qhat; after the correction loop qhat < b. */
        uint64_t top = ((uint64_t)un[j + n] << 32) | un[j + n - 1];
        uint64_t qhat = top / vn[n - 1];
        uint64_t rhat = top - qhat * vn[n - 1];
        while (qhat >= b ||
               qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2])) {
            qhat--;
            rhat += vn[n - 1];
            if (rhat >= b)
                break;
        }

        /* D4: multiply and subtract qhat * vn from un[j .. j+n]. */
        uint64_t borrow = 0;
        for (int i = 0; i < n; i++) {
            uint64_t p = qhat * vn[i] + borrow;      /* < 2^64: qhat,vn < 2^32 */
            uint32_t sub = (uint32_t)(p & M32);
            uint32_t cur = un[i + j];
            un[i + j] = cur - sub;                   /* mod 2^32 */
            borrow = (p >> 32) + (cur < sub ? 1u : 0u);
        }
        uint32_t cur = un[j + n];
        un[j + n] = (uint32_t)((cur - borrow) & M32);

        /* D5/D6: if the subtraction went negative, add one divisor back. */
        if ((uint64_t)cur < borrow) {
            qhat--;
            uint64_t carry = 0;
            for (int i = 0; i < n; i++) {
                uint64_t t = (uint64_t)un[i + j] + vn[i] + carry;
                un[i + j] = (uint32_t)(t & M32);
                carry = t >> 32;
            }
            un[j + n] = (uint32_t)((un[j + n] + carry) & M32);
        }
        qd[j] = (uint32_t)qhat;
    }

    if (q) {
        for (int i = 0; i < 4; i++)
            q->w[i] = (uint64_t)qd[2 * i] | ((uint64_t)qd[2 * i + 1] << 32);
    }
    if (rem) {
        /* D8: unnormalise the remainder (digits 0..n-1 of un, shifted right by s). */
        uint32_t r32[8];
        for (int i = 0; i < 8; i++)
            r32[i] = 0;
        for (int i = 0; i < n - 1; i++)
            r32[i] = (uint32_t)((((uint64_t)un[i] >> s) | ((uint64_t)un[i + 1] << (32 - s))) & M32);
        r32[n - 1] = (uint32_t)(((uint64_t)un[n - 1] >> s) & M32);
        for (int i = 0; i < 4; i++)
            rem->w[i] = (uint64_t)r32[2 * i] | ((uint64_t)r32[2 * i + 1] << 32);
    }
}

/* 256-by-256 unsigned division; den != 0. */
static void divmod256(evm_u256 *q, evm_u256 *rem,
                      const evm_u256 *a, const evm_u256 *b)
{
    uint64_t num[8];
    for (int i = 0; i < 4; i++) {
        num[i] = a->w[i];
        num[i + 4] = 0;
    }
    divmod_wide(q, rem, num, b->w);
}

/* r = v >> n (logical), n in [0, 255]. */
static void shr_small(evm_u256 *r, const evm_u256 *v, unsigned n)
{
    evm_u256 t = *v;
    unsigned ls = n / 64, bs = n % 64;
    for (unsigned i = 0; i < 4; i++) {
        uint64_t lo = (i + ls < 4) ? t.w[i + ls] : 0;
        uint64_t hi = (i + ls + 1 < 4) ? t.w[i + ls + 1] : 0;
        r->w[i] = (bs == 0) ? lo : ((lo >> bs) | (hi << (64 - bs)));
    }
}

/* r = v << n mod 2^256, n in [0, 255]. */
static void shl_small(evm_u256 *r, const evm_u256 *v, unsigned n)
{
    evm_u256 t = *v;
    unsigned ls = n / 64, bs = n % 64;
    for (unsigned i = 0; i < 4; i++) {
        uint64_t hi = (i >= ls) ? t.w[i - ls] : 0;
        uint64_t lo = (i >= ls + 1) ? t.w[i - ls - 1] : 0;
        r->w[i] = (bs == 0) ? hi : ((hi << bs) | (lo >> (64 - bs)));
    }
}

/* ── construction / conversion ───────────────────────────────────────── */

void evm_u256_zero(evm_u256 *r)
{
    r->w[0] = r->w[1] = r->w[2] = r->w[3] = 0;
}

void evm_u256_from_u64(evm_u256 *r, uint64_t v)
{
    r->w[0] = v;
    r->w[1] = r->w[2] = r->w[3] = 0;
}

void evm_u256_from_be(evm_u256 *r, const uint8_t b[32])
{
    evm_u256 t;
    for (int i = 0; i < 4; i++) {
        uint64_t x = 0;
        for (int k = 0; k < 8; k++)
            x = (x << 8) | b[(3 - i) * 8 + k];
        t.w[i] = x;
    }
    *r = t;
}

void evm_u256_to_be(uint8_t b[32], const evm_u256 *a)
{
    evm_u256 t = *a;
    for (int i = 0; i < 4; i++) {
        uint64_t x = t.w[i];
        for (int k = 7; k >= 0; k--) {
            b[(3 - i) * 8 + k] = (uint8_t)(x & 0xFF);
            x >>= 8;
        }
    }
}

int evm_u256_from_be_var(evm_u256 *r, const uint8_t *b, size_t len)
{
    uint8_t buf[32];
    if (len > 32)
        return -1;
    memset(buf, 0, sizeof(buf));
    if (len > 0)
        memcpy(buf + (32 - len), b, len);
    evm_u256_from_be(r, buf);
    return 0;
}

int evm_u256_to_u64(const evm_u256 *a, uint64_t *out)
{
    if (hi_limbs_nonzero(a))
        return 0;
    *out = a->w[0];
    return 1;
}

/* ── predicates / comparison ─────────────────────────────────────────── */

/* comparison.py:is_zero */
int evm_u256_is_zero(const evm_u256 *a)
{
    return (a->w[0] | a->w[1] | a->w[2] | a->w[3]) == 0;
}

/* comparison.py:less_than / greater_than / equal (unsigned order). */
int evm_u256_cmp(const evm_u256 *a, const evm_u256 *b)
{
    for (int i = 3; i >= 0; i--) {
        if (a->w[i] < b->w[i])
            return -1;
        if (a->w[i] > b->w[i])
            return 1;
    }
    return 0;
}

/* comparison.py:signed_less_than / signed_greater_than (to_signed order). */
int evm_u256_scmp(const evm_u256 *a, const evm_u256 *b)
{
    int na = is_neg(a), nb = is_neg(b);
    if (na != nb)
        return na ? -1 : 1;
    /* Same sign: two's-complement order equals unsigned order. */
    return evm_u256_cmp(a, b);
}

unsigned evm_u256_bitlen(const evm_u256 *a)
{
    for (int i = 3; i >= 0; i--) {
        uint64_t x = a->w[i];
        if (x != 0) {
            unsigned n = 0;
            while (x != 0) {
                x >>= 1;
                n++;
            }
            return (unsigned)i * 64u + n;
        }
    }
    return 0;
}

/* ── arithmetic ──────────────────────────────────────────────────────── */

/* arithmetic.py:add (wrapping_add). */
int evm_u256_add(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s = x.w[i] + y.w[i];
        uint64_t c1 = (s < x.w[i]);
        uint64_t s2 = s + carry;
        uint64_t c2 = (s2 < s);
        r->w[i] = s2;
        carry = c1 | c2;
    }
    return (int)carry;
}

/* arithmetic.py:sub (wrapping_sub). */
int evm_u256_sub(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t d = x.w[i] - y.w[i];
        uint64_t b1 = (x.w[i] < y.w[i]);
        uint64_t d2 = d - borrow;
        uint64_t b2 = (d < borrow);
        r->w[i] = d2;
        borrow = b1 | b2;
    }
    return (int)borrow;
}

/* arithmetic.py:mul (wrapping_mul): schoolbook, only limbs below 2^256. */
void evm_u256_mul(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    uint64_t out[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; i + j < 4; j++) {
            uint64_t hi;
            uint64_t lo = mul64(x.w[i], y.w[j], &hi);
            lo += out[i + j];
            hi += (lo < out[i + j]);
            lo += carry;
            hi += (lo < carry);
            out[i + j] = lo;
            carry = hi;
        }
    }
    for (int i = 0; i < 4; i++)
        r->w[i] = out[i];
}

/* arithmetic.py:div — divisor 0 -> 0. */
void evm_u256_div(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    if (evm_u256_is_zero(&y)) {
        evm_u256_zero(r);
        return;
    }
    divmod256(r, NULL, &x, &y);
}

/* arithmetic.py:mod — divisor 0 -> 0. */
void evm_u256_mod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    if (evm_u256_is_zero(&y)) {
        evm_u256_zero(r);
        return;
    }
    divmod256(NULL, r, &x, &y);
}

/* arithmetic.py:sdiv — divisor 0 -> 0; (-2^255) / -1 -> -2^255; otherwise
 * sign(dividend*divisor) * (|dividend| // |divisor|). The magnitude of
 * -2^255 is 2^255, which is representable unsigned; the special case falls
 * out of the general path (quotient 2^255, signs equal, no negation). */
void evm_u256_sdiv(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b, q;
    if (evm_u256_is_zero(&y)) {
        evm_u256_zero(r);
        return;
    }
    int nx = is_neg(&x), ny = is_neg(&y);
    if (nx)
        neg(&x, &x);
    if (ny)
        neg(&y, &y);
    divmod256(&q, NULL, &x, &y);
    if (nx != ny)
        neg(&q, &q);   /* q == 0 stays 0, matching sign 0 in the reference */
    *r = q;
}

/* arithmetic.py:smod — divisor 0 -> 0; get_sign(x) * (|x| % |y|). */
void evm_u256_smod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b, m;
    if (evm_u256_is_zero(&y)) {
        evm_u256_zero(r);
        return;
    }
    int nx = is_neg(&x);
    if (nx)
        neg(&x, &x);
    if (is_neg(&y))
        neg(&y, &y);
    divmod256(NULL, &m, &x, &y);
    if (nx)
        neg(&m, &m);
    *r = m;
}

/* arithmetic.py:addmod — (x + y) % z over the unbounded (257-bit) sum;
 * z == 0 -> 0. Operands are not pre-reduced: the 257-bit sum is divided. */
void evm_u256_addmod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b,
                     const evm_u256 *n)
{
    evm_u256 x = *a, y = *b, z = *n, s;
    uint64_t num[8];
    if (evm_u256_is_zero(&z)) {
        evm_u256_zero(r);
        return;
    }
    int carry = evm_u256_add(&s, &x, &y);
    for (int i = 0; i < 4; i++)
        num[i] = s.w[i];
    num[4] = (uint64_t)carry;
    num[5] = num[6] = num[7] = 0;
    divmod_wide(NULL, r, num, z.w);
}

/* arithmetic.py:mulmod — (x * y) % z over the full 512-bit product;
 * z == 0 -> 0. */
void evm_u256_mulmod(evm_u256 *r, const evm_u256 *a, const evm_u256 *b,
                     const evm_u256 *n)
{
    evm_u256 x = *a, y = *b, z = *n;
    uint64_t prod[8];
    if (evm_u256_is_zero(&z)) {
        evm_u256_zero(r);
        return;
    }
    mul_full(prod, x.w, y.w);
    divmod_wide(NULL, r, prod, z.w);
}

/* arithmetic.py:exp — pow(base, exponent, 2^256). Right-to-left binary
 * square-and-multiply; exponent 0 -> 1 for every base (pow(0, 0) == 1). */
void evm_u256_exp(evm_u256 *r, const evm_u256 *a, const evm_u256 *e)
{
    evm_u256 base = *a, ex = *e, acc;
    unsigned nbits = evm_u256_bitlen(&ex);
    evm_u256_from_u64(&acc, 1);
    for (unsigned i = 0; i < nbits; i++) {
        if ((ex.w[i / 64] >> (i % 64)) & 1u)
            evm_u256_mul(&acc, &acc, &base);
        if (i + 1 < nbits)
            evm_u256_mul(&base, &base, &base);
    }
    *r = acc;
}

/* arithmetic.py:signextend — byte_num > 31 -> value unchanged; otherwise
 * the sign bit of byte `byte_num` (counted from the least significant byte)
 * is copied into every higher bit, and those bits are cleared if it is 0. */
void evm_u256_signextend(evm_u256 *r, const evm_u256 *b, const evm_u256 *x)
{
    evm_u256 k = *b, v = *x;
    if (hi_limbs_nonzero(&k) || k.w[0] > 31) {
        *r = v;
        return;
    }
    unsigned bit = (unsigned)k.w[0] * 8u + 7u;     /* 7 .. 255 */
    unsigned limb = bit / 64, off = bit % 64;
    int sign = (int)((v.w[limb] >> off) & 1u);
    /* mask of bits [0 .. bit] within limb `limb`; off == 63 -> all ones. */
    uint64_t low_mask = (off == 63) ? ~0ull : ((1ull << (off + 1)) - 1);
    for (unsigned i = 0; i < 4; i++) {
        if (i < limb)
            continue;
        if (i == limb)
            v.w[i] = sign ? (v.w[i] | ~low_mask) : (v.w[i] & low_mask);
        else
            v.w[i] = sign ? ~0ull : 0;
    }
    *r = v;
}

/* ── bitwise ─────────────────────────────────────────────────────────── */

/* bitwise.py:bitwise_and */
void evm_u256_and(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    for (int i = 0; i < 4; i++)
        r->w[i] = x.w[i] & y.w[i];
}

/* bitwise.py:bitwise_or */
void evm_u256_or(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    for (int i = 0; i < 4; i++)
        r->w[i] = x.w[i] | y.w[i];
}

/* bitwise.py:bitwise_xor */
void evm_u256_xor(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    evm_u256 x = *a, y = *b;
    for (int i = 0; i < 4; i++)
        r->w[i] = x.w[i] ^ y.w[i];
}

/* bitwise.py:bitwise_not */
void evm_u256_not(evm_u256 *r, const evm_u256 *a)
{
    evm_u256 x = *a;
    for (int i = 0; i < 4; i++)
        r->w[i] = ~x.w[i];
}

/* bitwise.py:get_byte — index >= 32 -> 0; index 0 is the most significant
 * byte: (word >> ((31 - index) * 8)) & 0xFF. */
void evm_u256_byte(evm_u256 *r, const evm_u256 *i, const evm_u256 *x)
{
    evm_u256 idx = *i, v = *x;
    if (hi_limbs_nonzero(&idx) || idx.w[0] >= 32) {
        evm_u256_zero(r);
        return;
    }
    unsigned pos = 31u - (unsigned)idx.w[0];       /* byte from the LSB end */
    uint64_t byte = (v.w[pos / 8] >> ((pos % 8) * 8)) & 0xFFu;
    evm_u256_from_u64(r, byte);
}

/* bitwise.py:bitwise_shl — shift >= 256 -> 0. */
void evm_u256_shl(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v)
{
    evm_u256 s = *shift, x = *v;
    if (hi_limbs_nonzero(&s) || s.w[0] >= 256) {
        evm_u256_zero(r);
        return;
    }
    shl_small(r, &x, (unsigned)s.w[0]);
}

/* bitwise.py:bitwise_shr — shift >= 256 -> 0. */
void evm_u256_shr(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v)
{
    evm_u256 s = *shift, x = *v;
    if (hi_limbs_nonzero(&s) || s.w[0] >= 256) {
        evm_u256_zero(r);
        return;
    }
    shr_small(r, &x, (unsigned)s.w[0]);
}

/* bitwise.py:bitwise_sar — shift < 256: to_signed(value) >> shift (floor);
 * shift >= 256: 0 for a non-negative value, all ones for a negative one. */
void evm_u256_sar(evm_u256 *r, const evm_u256 *shift, const evm_u256 *v)
{
    evm_u256 s = *shift, x = *v;
    int negv = is_neg(&x);
    if (hi_limbs_nonzero(&s) || s.w[0] >= 256) {
        uint64_t fill = negv ? ~0ull : 0;
        r->w[0] = r->w[1] = r->w[2] = r->w[3] = fill;
        return;
    }
    unsigned n = (unsigned)s.w[0];
    evm_u256 t;
    shr_small(&t, &x, n);
    if (negv && n > 0) {
        /* Fill the top n bits: ones << (256 - n), n in [1, 255]. */
        evm_u256 ones, fillm;
        ones.w[0] = ones.w[1] = ones.w[2] = ones.w[3] = ~0ull;
        shl_small(&fillm, &ones, 256u - n);
        for (int i = 0; i < 4; i++)
            t.w[i] |= fillm.w[i];
    }
    *r = t;
}
