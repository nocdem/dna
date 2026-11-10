/**
 * @file amm_ledger.c
 * @brief nodus-amm pure integer ledger math (see amm_ledger.h).
 */
#include "amm_ledger.h"

#include <string.h>

/* ── checked primitives ───────────────────────────────────────────────── */

int amm_add(evm_u256 *r, const evm_u256 *a, const evm_u256 *b) {
    evm_u256 t;
    if (evm_u256_add(&t, a, b)) return AMM_E_OVERFLOW;
    *r = t;
    return AMM_OK;
}

int amm_mul(evm_u256 *r, const evm_u256 *a, const evm_u256 *b) {
    if (evm_u256_is_zero(a) || evm_u256_is_zero(b)) {
        evm_u256_zero(r);
        return AMM_OK;
    }
    const unsigned la = evm_u256_bitlen(a), lb = evm_u256_bitlen(b);
    /* a < 2^la and b < 2^lb: the product is < 2^(la+lb), and is at least
     * 2^(la+lb-2). */
    if (la + lb > 257u) return AMM_E_OVERFLOW;      /* product >= 2^256     */
    evm_u256 t;
    evm_u256_mul(&t, a, b);
    if (la + lb == 257u) {
        /* undecided by bit length: the product fits iff the wrapped value
         * divides back to b (if it wrapped, t < a*b so t / a < b). */
        evm_u256 q;
        evm_u256_div(&q, &t, a);                    /* a != 0 here          */
        if (evm_u256_cmp(&q, b) != 0) return AMM_E_OVERFLOW;
    }
    *r = t;
    return AMM_OK;
}

int amm_div(evm_u256 *r, const evm_u256 *a, const evm_u256 *b) {
    if (evm_u256_is_zero(b)) return AMM_E_ZERO_DIV;
    evm_u256 t;
    evm_u256_div(&t, a, b);
    *r = t;
    return AMM_OK;
}

int amm_sub(evm_u256 *r, const evm_u256 *a, const evm_u256 *b) {
    evm_u256 t;
    if (evm_u256_sub(&t, a, b)) return AMM_E_BORROW;
    *r = t;
    return AMM_OK;
}

void amm_sub_sat(evm_u256 *r, const evm_u256 *a, const evm_u256 *b) {
    evm_u256 t;
    if (evm_u256_sub(&t, a, b)) evm_u256_zero(r);
    else *r = t;
}

int amm_to_u64(uint64_t *out, const evm_u256 *a) {
    uint64_t v = 0;
    /* evm_u256_to_u64 returns 1 when the value fits, 0 when it does not */
    if (evm_u256_to_u64(a, &v) != 1) return AMM_E_OVERFLOW;
    *out = v;
    return AMM_OK;
}

/* ── swap ─────────────────────────────────────────────────────────────── */

/* Chain a failing step to the caller: every helper above leaves its result
 * untouched on refusal, so the macro only forwards the code. */
#define TRY(call)                                                            \
    do {                                                                     \
        int rc_ = (call);                                                    \
        if (rc_ != AMM_OK) return rc_;                                       \
    } while (0)

int amm_swap_emission_slip(evm_u256 *out, const evm_u256 *X,
                           const evm_u256 *x, const evm_u256 *Y) {
    evm_u256 t1, num, s, den, q;
    TRY(amm_mul(&t1, x, X));
    TRY(amm_mul(&num, &t1, Y));
    TRY(amm_add(&s, x, X));
    TRY(amm_mul(&den, &s, &s));
    TRY(amm_div(&q, &num, &den));
    if (evm_u256_cmp(&q, Y) >= 0) return AMM_E_DEPTH;
    *out = q;
    return AMM_OK;
}

int amm_swap_liquidity_fee(evm_u256 *fee, const evm_u256 *X,
                           const evm_u256 *x, const evm_u256 *Y) {
    evm_u256 t1, num, s, den, q;
    TRY(amm_mul(&t1, x, x));
    TRY(amm_mul(&num, &t1, Y));
    TRY(amm_add(&s, x, X));
    TRY(amm_mul(&den, &s, &s));
    TRY(amm_div(&q, &num, &den));
    *fee = q;
    return AMM_OK;
}

int amm_swap_output(evm_u256 *out, const evm_u256 *X, const evm_u256 *x,
                    const evm_u256 *Y) {
    /* GetSwapCalc with the commission setting 0: minSlipBps (0) is never
     * greater than slipBps, so the else branch (swap_current.go:644-648) is
     * the only one: emission (x*X*Y)/(x+X)^2. */
    return amm_swap_emission_slip(out, X, x, Y);
}

static void sides(const amm_pool_t *p, amm_dir_t dir, const evm_u256 **in_d,
                  const evm_u256 **out_d) {
    if (dir == AMM_USDT_TO_NODUS) { *in_d = &p->depth_u; *out_d = &p->depth_n; }
    else                          { *in_d = &p->depth_n; *out_d = &p->depth_u; }
}

int amm_pool_quote(const amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                   evm_u256 *out) {
    if (dir != AMM_USDT_TO_NODUS && dir != AMM_NODUS_TO_USDT) return AMM_E_RANGE;
    const evm_u256 *in_d, *out_d;
    sides(p, dir, &in_d, &out_d);
    return amm_swap_output(out, in_d, x, out_d);
}

int amm_pool_apply_swap(amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                        const evm_u256 *paid) {
    if (dir != AMM_USDT_TO_NODUS && dir != AMM_NODUS_TO_USDT) return AMM_E_RANGE;
    evm_u256 new_in, new_out;
    evm_u256 *in_d = (dir == AMM_USDT_TO_NODUS) ? &p->depth_u : &p->depth_n;
    evm_u256 *out_d = (dir == AMM_USDT_TO_NODUS) ? &p->depth_n : &p->depth_u;
    /* The output is the number the bot gave at approval, not computed again
     * (plan section 12, givens items 66, 68); it may differ from a quote of
     * today's depths. Only the depth rule and the borrow rule are checked. */
    if (evm_u256_cmp(paid, out_d) >= 0) return AMM_E_DEPTH;
    TRY(amm_add(&new_in, in_d, x));
    TRY(amm_sub(&new_out, out_d, paid));
    *in_d = new_in;
    *out_d = new_out;
    return AMM_OK;
}

/* ── payout after the network fee ─────────────────────────────────────── */

amm_payout_t amm_payout_after_fee(const evm_u256 *output, const evm_u256 *fee,
                                  const evm_u256 *minimum, evm_u256 *net) {
    evm_u256 n;
    amm_sub_sat(&n, output, fee);
    if (net) *net = n;
    if (evm_u256_is_zero(&n)) return AMM_PAYOUT_BELOW_MIN;
    if (evm_u256_cmp(&n, minimum) < 0) return AMM_PAYOUT_BELOW_MIN;
    return AMM_PAYOUT_PAY;
}

/* ── liquidity ────────────────────────────────────────────────────────── */

/* ── LegacyDec division (512-bit intermediate) ────────────────────────── */

typedef struct { uint64_t w[8]; } u512;     /* w[0] least significant        */

#define DEC_ONE18   1000000000000000000ULL  /* 10^18                         */
#define DEC_HALF18  500000000000000000ULL   /* 5 * 10^17 (fivePrecision)     */

static void u512_from_u256(u512 *r, const evm_u256 *a) {
    memset(r, 0, sizeof(*r));
    for (int i = 0; i < 4; i++) r->w[i] = a->w[i];
}

static void u512_mul_small(u512 *x, uint64_t m) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < 8; i++) {
        unsigned __int128 t = (unsigned __int128)x->w[i] * m + carry;
        x->w[i] = (uint64_t)t;
        carry = t >> 64;
    }
}

/* x /= d (truncating); returns the remainder. */
static uint64_t u512_divmod_small(u512 *x, uint64_t d) {
    unsigned __int128 rem = 0;
    for (int i = 7; i >= 0; i--) {
        unsigned __int128 cur = (rem << 64) | x->w[i];
        x->w[i] = (uint64_t)(cur / d);
        rem = cur % d;
    }
    return (uint64_t)rem;
}

static void u512_add_one(u512 *x) {
    for (int i = 0; i < 8; i++)
        if (++x->w[i] != 0) break;
}

static int u512_cmp(const u512 *a, const u512 *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->w[i] < b->w[i]) return -1;
        if (a->w[i] > b->w[i]) return 1;
    }
    return 0;
}

static void u512_sub(u512 *a, const u512 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = a->w[i] - b->w[i];
        uint64_t b1 = a->w[i] < b->w[i];
        uint64_t d2 = d - borrow;
        uint64_t b2 = d < borrow;
        a->w[i] = d2;
        borrow = b1 | b2;
    }
}

static void u512_shl1(u512 *a) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t nc = a->w[i] >> 63;
        a->w[i] = (a->w[i] << 1) | carry;
        carry = nc;
    }
}

/* q = floor(n / d), bitwise long division (n < 2^384, d < 2^256 here, so
 * the running remainder stays below 2^257 and never overflows 512 bits). */
static void u512_div(u512 *q, const u512 *n, const u512 *d) {
    u512 rem;
    memset(&rem, 0, sizeof(rem));
    memset(q, 0, sizeof(*q));
    for (int bit = 511; bit >= 0; bit--) {
        u512_shl1(&rem);
        rem.w[0] |= (n->w[bit / 64] >> (bit % 64)) & 1u;
        if (u512_cmp(&rem, d) >= 0) {
            u512_sub(&rem, d);
            q->w[bit / 64] |= (uint64_t)1 << (bit % 64);
        }
    }
}

int amm_dec_quo_trunc(evm_u256 *out, const evm_u256 *N, const evm_u256 *D) {
    if (evm_u256_is_zero(D)) return AMM_E_ZERO_DIV;
    u512 num, den, q;
    u512_from_u256(&num, N);
    u512_from_u256(&den, D);
    u512_mul_small(&num, DEC_ONE18);            /* N * 10^18 * 10^18         */
    u512_mul_small(&num, DEC_ONE18);            /* (the 10^18 scale of N and */
                                                /*  D cancels in i / d2.i)   */
    u512_div(&q, &num, &den);                   /* i = floor(N*10^36 / D)    */
    uint64_t rem = u512_divmod_small(&q, DEC_ONE18);   /* q = i / 10^18      */
    if (rem > DEC_HALF18) u512_add_one(&q);
    else if (rem == DEC_HALF18 && (q.w[0] & 1u)) u512_add_one(&q);  /* banker's */
    (void)u512_divmod_small(&q, DEC_ONE18);     /* TruncateInt               */
    for (int i = 4; i < 8; i++)
        if (q.w[i]) return AMM_E_OVERFLOW;
    for (int i = 0; i < 4; i++) out->w[i] = q.w[i];
    return AMM_OK;
}

int amm_units_for_add(evm_u256 *s, evm_u256 *new_total, const evm_u256 *P,
                      const evm_u256 *R, const evm_u256 *A,
                      const evm_u256 *r, const evm_u256 *a) {
    evm_u256 t, sum_r, sum_a, units, total;
    TRY(amm_add(&sum_r, r, R));
    if (evm_u256_is_zero(&sum_r)) return AMM_E_RANGE;   /* total NODUS zero  */
    TRY(amm_add(&sum_a, a, A));
    if (evm_u256_is_zero(&sum_a)) return AMM_E_RANGE;   /* total USDT zero   */

    if (evm_u256_is_zero(R) || evm_u256_is_zero(A) || evm_u256_is_zero(P)) {
        units = *r;
        if (evm_u256_is_zero(r)) {
            if (!evm_u256_is_zero(A)) {
                TRY(amm_mul(&t, a, R));
                TRY(amm_div(&units, &t, A));
            } else {
                units = *a;
            }
        }
    } else {
        evm_u256 ra, aR, cross, two, rA2, ra2, aR2, num, RA, den, inner;
        evm_u256_from_u64(&two, 2);
        TRY(amm_mul(&ra, r, A));                     /* r*A                 */
        TRY(amm_mul(&aR, a, R));                     /* a*R                 */
        TRY(amm_add(&cross, &ra, &aR));              /* r*A + a*R           */
        TRY(amm_mul(&rA2, r, a));
        TRY(amm_mul(&ra2, &two, &rA2));              /* 2*r*a               */
        TRY(amm_add(&inner, &cross, &ra2));
        TRY(amm_mul(&num, P, &inner));               /* P * (...)           */
        TRY(amm_mul(&RA, R, A));
        TRY(amm_mul(&aR2, &two, &RA));               /* 2*R*A               */
        TRY(amm_add(&den, &cross, &aR2));
        TRY(amm_dec_quo_trunc(&units, &num, &den));  /* LegacyDec Quo + TruncateInt */
    }
    TRY(amm_add(&total, P, &units));
    *s = units;
    if (new_total) *new_total = total;
    return AMM_OK;
}

int amm_pool_apply_add(amm_pool_t *p, const evm_u256 *r, const evm_u256 *a,
                       evm_u256 *s_out) {
    evm_u256 s, total, n, u;
    TRY(amm_units_for_add(&s, &total, &p->units, &p->depth_n, &p->depth_u,
                          r, a));
    TRY(amm_add(&n, &p->depth_n, r));
    TRY(amm_add(&u, &p->depth_u, a));
    p->depth_n = n;
    p->depth_u = u;
    p->units = total;
    if (s_out) *s_out = s;
    return AMM_OK;
}

int amm_safe_share(evm_u256 *out, const evm_u256 *part, const evm_u256 *total,
                   const evm_u256 *allocation) {
    if (evm_u256_is_zero(part) || evm_u256_is_zero(total) ||
        evm_u256_is_zero(allocation)) {
        evm_u256_zero(out);
        return AMM_OK;
    }
    const evm_u256 *p = part;
    if (evm_u256_cmp(part, total) >= 0) p = total;  /* cap at total         */
    if (evm_u256_cmp(p, total) == 0) {              /* part == total        */
        *out = *allocation;
        return AMM_OK;
    }
    evm_u256 prod, half, one, num, q;
    evm_u256_from_u64(&one, 1);
    evm_u256_shr(&half, &one, total);               /* floor(total / 2)     */
    TRY(amm_mul(&prod, allocation, p));
    TRY(amm_add(&num, &prod, &half));
    TRY(amm_div(&q, &num, total));
    *out = q;
    return AMM_OK;
}

int amm_uncapped_share(evm_u256 *out, const evm_u256 *part, const evm_u256 *total,
                       const evm_u256 *allocation) {
    if (evm_u256_is_zero(part) || evm_u256_is_zero(total) ||
        evm_u256_is_zero(allocation)) {
        evm_u256_zero(out);
        return AMM_OK;
    }
    if (evm_u256_cmp(part, total) == 0) {           /* part == total        */
        *out = *allocation;
        return AMM_OK;
    }
    evm_u256 prod, half, one, num, q;
    evm_u256_from_u64(&one, 1);
    evm_u256_shr(&half, &one, total);               /* floor(total / 2)     */
    TRY(amm_mul(&prod, allocation, part));
    TRY(amm_add(&num, &prod, &half));
    TRY(amm_div(&q, &num, total));
    *out = q;
    return AMM_OK;
}

int amm_pool_unapply_swap(amm_pool_t *p, amm_dir_t dir, const evm_u256 *x,
                          const evm_u256 *paid) {
    if (dir != AMM_USDT_TO_NODUS && dir != AMM_NODUS_TO_USDT) return AMM_E_RANGE;
    evm_u256 new_in, new_out;
    evm_u256 *in_d = (dir == AMM_USDT_TO_NODUS) ? &p->depth_u : &p->depth_n;
    evm_u256 *out_d = (dir == AMM_USDT_TO_NODUS) ? &p->depth_n : &p->depth_u;
    TRY(amm_sub(&new_in, in_d, x));
    TRY(amm_add(&new_out, out_d, paid));
    *in_d = new_in;
    *out_d = new_out;
    return AMM_OK;
}

int amm_withdraw_calc(amm_withdraw_t *w, const amm_pool_t *p,
                      const evm_u256 *lp_units, uint32_t bp) {
    if (evm_u256_is_zero(&p->units) || evm_u256_is_zero(&p->depth_n) ||
        evm_u256_is_zero(&p->depth_u) || evm_u256_is_zero(lp_units) ||
        bp > 10000u)
        return AMM_E_RANGE;
    evm_u256 bpv, ten_k, claimed, after, out_n, out_u;
    evm_u256_from_u64(&bpv, bp);
    evm_u256_from_u64(&ten_k, 10000);
    TRY(amm_safe_share(&claimed, &bpv, &ten_k, lp_units));
    amm_sub_sat(&after, lp_units, &claimed);        /* SafeSub, withdraw.go */
    TRY(amm_safe_share(&out_n, &claimed, &p->units, &p->depth_n));
    TRY(amm_safe_share(&out_u, &claimed, &p->units, &p->depth_u));
    w->units_claimed = claimed;
    w->units_after = after;
    w->out_n = out_n;
    w->out_u = out_u;
    return AMM_OK;
}

int amm_pool_apply_withdraw(amm_pool_t *p, const amm_withdraw_t *w) {
    evm_u256 n, u, units;
    TRY(amm_sub(&n, &p->depth_n, &w->out_n));
    TRY(amm_sub(&u, &p->depth_u, &w->out_u));
    TRY(amm_sub(&units, &p->units, &w->units_claimed));
    p->depth_n = n;
    p->depth_u = u;
    p->units = units;
    return AMM_OK;
}

/* ── in-flight room ───────────────────────────────────────────────────── */

int amm_inflight_admit(uint64_t v, uint64_t sum_open, uint64_t swap_max,
                       uint64_t inflight_max) {
    if (v > swap_max) return AMM_E_SWAP_LIMIT;
    if (sum_open > UINT64_MAX - v) return AMM_E_OVERFLOW;
    if (sum_open + v > inflight_max) return AMM_E_INFLIGHT;
    return AMM_OK;
}
