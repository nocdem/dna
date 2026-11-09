/**
 * test_amm_ledger.c -- the nodus-amm pure integer ledger (amm_ledger.c).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md,
 * revision 4, section 19 "test_amm_ledger"; sections 5, 12, 13, 14):
 *   L1  checked primitives: the multiply refuses exactly at 2^256 (the bit
 *       length shortcut AND the exact 257-bit case: 2^128*(2^128-1) fits,
 *       (2^129-1)*(2^128-1) does not, 2^255*2 does not), add refuses a
 *       carry, sub refuses a borrow, div refuses a zero divisor; the
 *       saturating subtraction gives 0 (never a wrapped value) when the fee
 *       is greater than the amount (givens item 52);
 *   L2  swap output x*Y/(x+X) truncated, on hand-derived vectors (the
 *       arithmetic is written next to each vector), including the plan's
 *       own rounding example x=1, X=2, Y=3 (section 12) and the section 5
 *       width example whose numerator x*X*Y = 9*10^38 passes 2^128;
 *   L3  the reference no-floor emission and liquidity fee, and that their
 *       sum equals the plain output on the vector where truncation is
 *       harmless;
 *   L4  refusals: overflow near 2^256 (inputs 2^255), zero divisor
 *       (x + X == 0), output reaching the output-side depth (X == 0);
 *   L5  the ledger update: input side += x, output side -= paid; an
 *       all-or-nothing refusal leaves the pool untouched (stale paid value,
 *       carry on the input side, depth refusal);
 *   L6  payout after the fee: net = output - fee saturating; verdict PAY
 *       when net > 0 and net >= minimum, BELOW_MIN otherwise (net == 0 also
 *       with a zero minimum, fee greater than the output also) -- givens
 *       items 51, 52, plan sections 7, 8 step 7;
 *   L7  liquidity units: same-ratio add, one-sided add, empty-pool branch,
 *       the r == 0 branch, refusal of a zero total on a side, overflow of
 *       P + units;
 *   L7b liquidity units follow THORChain's LegacyDec division (18 decimals,
 *       banker's rounding, then TruncateInt; cosmossdk.io/math v1.5.3
 *       legacy_dec.go:383-388, :624-656, :723-725; handler_add_liquidity.go:
 *       489-499): the verifier's counterexample R=A=K=3e18, P=K-1, r=a=1
 *       gives 1 unit (integer floor gave 0); exact 19-decimal ties (odd q
 *       rounds up across the integer boundary, even q stays), a value just
 *       below and just above the tie, a 512-bit intermediate (N = 2^255), the
 *       zero divisor; every vector's arithmetic is written out and was
 *       re-checked with python3 integers;
 *   L8  GetSafeShare: round half up (a=3, p=1, t=2 -> 2), cap at total,
 *       zero inputs, part == total, overflow of a*p refused;
 *   L9  withdraw: units claimed and both sides by two chained shares with
 *       round half up (bp 2505 of 1000 units -> 251, not 250), bp 10000
 *       burns everything, bp > 10000 and zero pool refused, the update
 *       refuses a borrow and changes nothing;
 *   L10 add update: depths and units move together, an overflow refusal
 *       changes nothing;
 *   L11 in-flight admission: per-swap limit, total limit, the exact
 *       boundary admitted, the sum overflow refused.
 * VECTOR PROVENANCE: every expected number was derived by hand from the cited
 * THORChain formulas (the arithmetic is in the comment of each vector) and the
 * arithmetic was cross-checked with an independent big-integer calculator
 * (python3 integers), not with the code under test.
 * WHAT IT REQUIRES: a default build; no files, no network, no clock.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: values are built from decimal strings by this test's own
 * dec() (multiply-by-10 and add through the same evm_u256 primitives); a
 * defect shared by evm_u256_mul/add would affect dec() and the code under
 * test alike, but the primitives are the EVM engine's own (covered by its
 * suite) and the vectors that exceed 2^64 are also pinned through
 * independent constructions (2^k via shifts).
 */
#include <stdio.h>
#include <string.h>

#include "amm_ledger.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static evm_u256 u64v(uint64_t v) { evm_u256 r; evm_u256_from_u64(&r, v); return r; }

/* Decimal string -> evm_u256 (digits only, value < 2^256). */
static evm_u256 dec(const char *s) {
    evm_u256 r = u64v(0), ten = u64v(10);
    for (; *s; s++) {
        evm_u256 d = u64v((uint64_t)(*s - '0')), t;
        evm_u256_mul(&t, &r, &ten);
        evm_u256_add(&r, &t, &d);
    }
    return r;
}

/* 2^k */
static evm_u256 pow2(unsigned k) {
    evm_u256 one = u64v(1), sh = u64v(k), r;
    evm_u256_shl(&r, &sh, &one);
    return r;
}

static evm_u256 max256(void) {
    evm_u256 z = u64v(0), one = u64v(1), r;
    evm_u256_sub(&r, &z, &one);                    /* 2^256 - 1             */
    return r;
}

static int eq(const evm_u256 *a, const evm_u256 *b) { return evm_u256_cmp(a, b) == 0; }
static int eq_dec(const evm_u256 *a, const char *s) {
    evm_u256 b = dec(s);
    return eq(a, &b);
}
static int eq_u64(const evm_u256 *a, uint64_t v) {
    evm_u256 b = u64v(v);
    return eq(a, &b);
}

static void l1_primitives(void) {
    printf("L1 checked primitives\n");
    evm_u256 r, a, b, one = u64v(1), zero = u64v(0), two = u64v(2);

    /* 2^128 * (2^128 - 1) = 2^256 - 2^128 < 2^256: bit lengths 129 + 128
     * = 257 (undecided by length), fits */
    a = pow2(128);
    { evm_u256 t = pow2(128); evm_u256_sub(&b, &t, &one); }
    CHECK(amm_mul(&r, &a, &b) == AMM_OK, "2^128*(2^128-1) fits");
    { evm_u256 chk, back; evm_u256_div(&back, &r, &a); chk = b;
      CHECK(eq(&back, &chk), "  and divides back"); }
    /* (2^129 - 1) * (2^128 - 1) ~ 2^257: 257 bits, does not fit */
    { evm_u256 t = pow2(129); evm_u256_sub(&a, &t, &one); }
    r = u64v(77);
    CHECK(amm_mul(&r, &a, &b) == AMM_E_OVERFLOW, "(2^129-1)*(2^128-1) overflows");
    CHECK(eq_u64(&r, 77), "  result untouched on refusal");
    /* 2^128 * 2^128 = 2^256 */
    a = pow2(128); b = pow2(128);
    CHECK(amm_mul(&r, &a, &b) == AMM_E_OVERFLOW, "2^128*2^128 overflows");
    /* 2^255 * 2 = 2^256 */
    a = pow2(255);
    CHECK(amm_mul(&r, &a, &two) == AMM_E_OVERFLOW, "2^255*2 overflows");
    /* 2^255 * 1 fits (257 bits by length, exact check passes) */
    CHECK(amm_mul(&r, &a, &one) == AMM_OK && eq(&r, &a), "2^255*1 fits");
    /* (2^128-1)^2 = 2^256 - 2^129 + 1 fits (256 bits by length) */
    { evm_u256 t = pow2(128); evm_u256_sub(&a, &t, &one); }
    CHECK(amm_mul(&r, &a, &a) == AMM_OK, "(2^128-1)^2 fits");
    /* zero factor */
    CHECK(amm_mul(&r, &zero, &a) == AMM_OK && eq_u64(&r, 0), "0*a == 0");

    /* add */
    a = max256();
    r = u64v(5);
    CHECK(amm_add(&r, &a, &one) == AMM_E_OVERFLOW && eq_u64(&r, 5),
          "(2^256-1)+1 refused, result untouched");
    CHECK(amm_add(&r, &a, &zero) == AMM_OK && eq(&r, &a), "(2^256-1)+0 fits");

    /* sub */
    a = u64v(3); b = u64v(5); r = u64v(9);
    CHECK(amm_sub(&r, &a, &b) == AMM_E_BORROW && eq_u64(&r, 9),
          "3-5 refused (borrow), result untouched");
    CHECK(amm_sub(&r, &b, &a) == AMM_OK && eq_u64(&r, 2), "5-3 == 2");

    /* saturating subtraction: never wraps */
    amm_sub_sat(&r, &a, &b);
    CHECK(eq_u64(&r, 0), "sat 3-5 == 0 (not 2^256-2)");
    amm_sub_sat(&r, &b, &a);
    CHECK(eq_u64(&r, 2), "sat 5-3 == 2");
    amm_sub_sat(&r, &a, &a);
    CHECK(eq_u64(&r, 0), "sat 3-3 == 0");

    /* div */
    r = u64v(9);
    CHECK(amm_div(&r, &a, &zero) == AMM_E_ZERO_DIV && eq_u64(&r, 9),
          "division by zero refused (EVM would give 0)");
    CHECK(amm_div(&r, &b, &two) == AMM_OK && eq_u64(&r, 2), "5/2 truncates to 2");

    uint64_t u = 0;
    CHECK(amm_to_u64(&u, &a) == AMM_OK && u == 3, "to_u64 small");
    { evm_u256 big = pow2(64);
      CHECK(amm_to_u64(&u, &big) == AMM_E_OVERFLOW, "to_u64 2^64 refused"); }
}

static void l2_l3_swap(void) {
    printf("L2/L3 swap output, no-floor emission, liquidity fee\n");
    evm_u256 out, slip, fee;
    evm_u256 x, X, Y;

    /* Plan section 12 example: x=1, X=2, Y=3.
     * plain = x*Y/(x+X) = 3/3 = 1. no-floor emission = x*X*Y/(x+X)^2
     * = 6/9 -> 0; fee = x^2*Y/(x+X)^2 = 3/9 -> 0. */
    x = u64v(1); X = u64v(2); Y = u64v(3);
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_OK && eq_u64(&out, 1),
          "x=1,X=2,Y=3: plain output 1");
    CHECK(amm_swap_emission_slip(&slip, &X, &x, &Y) == AMM_OK && eq_u64(&slip, 0),
          "x=1,X=2,Y=3: no-floor emission 0");
    CHECK(amm_swap_liquidity_fee(&fee, &X, &x, &Y) == AMM_OK && eq_u64(&fee, 0),
          "x=1,X=2,Y=3: fee 0 (output + fee != plain after truncation)");

    /* Plan section 5 width example, NODUS -> USDT, start pool:
     * x = 10^14 raw NODUS (1,000,000 NODUS), X = 3*10^15 (NODUS side),
     * Y = 3*10^9 (USDT side).
     * x+X = 3.1*10^15; x*Y = 3*10^23;
     * plain = 3*10^23 / 3.1*10^15 = 96774193.548.. -> 96774193 (96.774193 USDT)
     * x*X*Y = 9*10^38 (> 2^128 ~ 3.4*10^38): the 128-bit case of the plan;
     * (x+X)^2 = 9.61*10^30;
     * no-floor = 9*10^38 / 9.61*10^30 = 93652445.369.. -> 93652445
     * fee      = x^2*Y/(x+X)^2 = 3*10^37 / 9.61*10^30 = 3121748.17.. -> 3121748
     * 93652445 + 3121748 = 96774193 = plain. */
    x = dec("100000000000000"); X = dec("3000000000000000"); Y = dec("3000000000");
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_OK && eq_u64(&out, 96774193),
          "100 USDT worth of NODUS: plain output 96774193");
    CHECK(amm_swap_emission_slip(&slip, &X, &x, &Y) == AMM_OK &&
          eq_u64(&slip, 93652445), "no-floor emission 93652445 (numerator 9e38)");
    CHECK(amm_swap_liquidity_fee(&fee, &X, &x, &Y) == AMM_OK &&
          eq_u64(&fee, 3121748), "liquidity fee 3121748");
    { evm_u256 sum; evm_u256_add(&sum, &slip, &fee);
      CHECK(eq(&sum, &out), "emission + fee == plain on this vector"); }
    { evm_u256 w = dec("900000000000000000000000000000000000000");
      evm_u256 p; evm_u256_mul(&p, &x, &X); evm_u256_mul(&p, &p, &Y);
      CHECK(eq(&p, &w) && evm_u256_bitlen(&p) > 128,
            "numerator x*X*Y is 9e38 and wider than 128 bits"); }

    /* USDT -> NODUS, same pool: x = 10^8 (100 USDT), X = 3*10^9, Y = 3*10^15.
     * x*Y = 3*10^23; x+X = 3.1*10^9; out = 96774193548387.09 -> 96774193548387 */
    x = dec("100000000"); X = dec("3000000000"); Y = dec("3000000000000000");
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_OK &&
          eq_dec(&out, "96774193548387"), "100 USDT -> 96774193548387 raw NODUS");
}

static void l4_refusals(void) {
    printf("L4 refusals\n");
    evm_u256 out = u64v(41), x, X, Y;

    /* x*Y passes 2^256: x = Y = 2^255 */
    x = pow2(255); Y = pow2(255); X = u64v(1);
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_E_OVERFLOW, "x*Y overflow refused");
    CHECK(eq_u64(&out, 41), "  output untouched");
    /* x + X passes 2^256 */
    x = max256(); X = u64v(1); Y = u64v(1);
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_E_OVERFLOW, "x+X carry refused");
    /* x + X == 0 */
    x = u64v(0); X = u64v(0); Y = u64v(10);
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_E_ZERO_DIV,
          "x+X == 0 refused (zero divisor)");
    /* X == 0: out = x*Y/x = Y, reaches the depth: 5*7/5 = 7 >= 7 */
    x = u64v(5); X = u64v(0); Y = u64v(7);
    CHECK(amm_swap_output(&out, &X, &x, &Y) == AMM_E_DEPTH,
          "output reaching the output-side depth refused");
    /* the no-floor emission refuses the same way: x*X*Y with X=0 is 0 -> not
     * depth, so use a width case: three-factor product past 2^256 */
    x = pow2(100); X = pow2(100); Y = pow2(100);
    { evm_u256 s;
      CHECK(amm_swap_emission_slip(&s, &X, &x, &Y) == AMM_E_OVERFLOW,
            "x*X*Y = 2^300 refused"); }
}

static void l5_apply(void) {
    printf("L5 ledger update\n");
    amm_pool_t p = { dec("3000000000000000"), dec("3000000000"), u64v(1000) };
    evm_u256 x = dec("100000000"), paid;

    CHECK(amm_pool_quote(&p, AMM_USDT_TO_NODUS, &x, &paid) == AMM_OK &&
          eq_dec(&paid, "96774193548387"), "quote USDT -> NODUS");
    /* stale paid value */
    evm_u256 wrong = u64v(1);
    amm_pool_t before = p;
    CHECK(amm_pool_apply_swap(&p, AMM_USDT_TO_NODUS, &x, &wrong) == AMM_E_RANGE &&
          !memcmp(&p, &before, sizeof(p)), "a paid value that differs from the quote is refused, pool unchanged");
    /* applied: depth_u += 10^8 -> 3.1*10^9; depth_n -= 96774193548387
     * -> 3000000000000000 - 96774193548387 = 2903225806451613 */
    CHECK(amm_pool_apply_swap(&p, AMM_USDT_TO_NODUS, &x, &paid) == AMM_OK &&
          eq_dec(&p.depth_u, "3100000000") &&
          eq_dec(&p.depth_n, "2903225806451613") && eq_u64(&p.units, 1000),
          "USDT -> NODUS applied: input side += x, output side -= paid");

    /* NODUS -> USDT on a fresh pool: x = 10^14, out 96774193;
     * depth_n = 3.1*10^15, depth_u = 3*10^9 - 96774193 = 2903225807 */
    amm_pool_t q = { dec("3000000000000000"), dec("3000000000"), u64v(1) };
    evm_u256 x2 = dec("100000000000000"), o2;
    CHECK(amm_pool_quote(&q, AMM_NODUS_TO_USDT, &x2, &o2) == AMM_OK &&
          eq_u64(&o2, 96774193), "quote NODUS -> USDT");
    CHECK(amm_pool_apply_swap(&q, AMM_NODUS_TO_USDT, &x2, &o2) == AMM_OK &&
          eq_dec(&q.depth_n, "3100000000000000") &&
          eq_dec(&q.depth_u, "2903225807"),
          "NODUS -> USDT applied");

    /* carry on the input side refuses, nothing changes */
    amm_pool_t c = { u64v(10), max256(), u64v(1) };
    evm_u256 one = u64v(1), po;
    before = c;
    CHECK(amm_pool_quote(&c, AMM_USDT_TO_NODUS, &one, &po) == AMM_E_OVERFLOW,
          "input side at 2^256-1 cannot take one more");
    CHECK(amm_pool_apply_swap(&c, AMM_USDT_TO_NODUS, &one, &one) == AMM_E_OVERFLOW &&
          !memcmp(&c, &before, sizeof(c)), "refusal leaves the pool unchanged");

    /* depth refusal: empty input side */
    amm_pool_t d = { u64v(7), u64v(0), u64v(1) };      /* depth_u = 0       */
    evm_u256 five = u64v(5);
    before = d;
    CHECK(amm_pool_apply_swap(&d, AMM_USDT_TO_NODUS, &five, &five) == AMM_E_DEPTH &&
          !memcmp(&d, &before, sizeof(d)), "output reaching depth refused, pool unchanged");
    CHECK(amm_pool_quote(&d, (amm_dir_t)7, &five, &po) == AMM_E_RANGE,
          "an unknown direction is refused");
}

static void l6_payout(void) {
    printf("L6 payout after the fee\n");
    evm_u256 out = u64v(100), fee = u64v(40), min = u64v(60), net;
    CHECK(amm_payout_after_fee(&out, &fee, &min, &net) == AMM_PAYOUT_PAY &&
          eq_u64(&net, 60), "100 - 40 = 60 >= minimum 60: pay");
    min = u64v(61);
    CHECK(amm_payout_after_fee(&out, &fee, &min, &net) == AMM_PAYOUT_BELOW_MIN &&
          eq_u64(&net, 60), "minimum 61: refund path (minimum compared after the fee)");
    min = u64v(100);   /* passes only BEFORE the fee: givens item 51 */
    CHECK(amm_payout_after_fee(&out, &fee, &min, &net) == AMM_PAYOUT_BELOW_MIN,
          "an output that passes the minimum only before the fee is refunded");
    fee = u64v(100); min = u64v(0);
    CHECK(amm_payout_after_fee(&out, &fee, &min, &net) == AMM_PAYOUT_BELOW_MIN &&
          eq_u64(&net, 0), "fee == output, minimum 0: zero net, never a payout");
    fee = u64v(150);
    CHECK(amm_payout_after_fee(&out, &fee, &min, &net) == AMM_PAYOUT_BELOW_MIN &&
          eq_u64(&net, 0), "fee > output: saturates to 0, no wrap");
    fee = u64v(0);
    CHECK(amm_payout_after_fee(&out, &fee, &min, NULL) == AMM_PAYOUT_PAY,
          "fee 0, minimum 0, output 100: pay (net pointer optional)");
}

static void l7_units(void) {
    printf("L7 liquidity units\n");
    evm_u256 s, tot, P, R, A, r, a;

    /* same ratio: P=1000, R=100, A=50, r=10, a=5.
     * cross = r*A + a*R = 500 + 500 = 1000; 2*r*a = 100;
     * num = 1000 * 1100 = 1,100,000; den = 1000 + 2*100*50 = 11,000;
     * s = 100 (10% of P), total 1100 */
    P = u64v(1000); R = u64v(100); A = u64v(50); r = u64v(10); a = u64v(5);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_OK &&
          eq_u64(&s, 100) && eq_u64(&tot, 1100), "same-ratio add: 100 units");

    /* one-sided: r=10, a=0. cross = 10*50 + 0 = 500; num = 1000*500 =
     * 500,000; den = 500 + 2*100*50 = 10,500; s = 47.6 -> 47 */
    a = u64v(0);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_OK &&
          eq_u64(&s, 47) && eq_u64(&tot, 1047), "one-sided add: floor(47.6) = 47");

    /* empty pool: units = the NODUS side added */
    P = u64v(0); R = u64v(0); A = u64v(0); r = u64v(3000); a = u64v(7);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_OK &&
          eq_u64(&s, 3000) && eq_u64(&tot, 3000), "empty pool: units == added NODUS");

    /* P == 0 with depths (units reset): r=0 -> a*R/A = 5*100/50 = 10 */
    P = u64v(0); R = u64v(100); A = u64v(50); r = u64v(0); a = u64v(5);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_OK &&
          eq_u64(&s, 10), "r == 0 branch: a*R/A = 10");
    /* r == 0 and the USDT side empty -> units = a */
    P = u64v(0); R = u64v(100); A = u64v(0); r = u64v(0); a = u64v(5);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_OK &&
          eq_u64(&s, 5), "r == 0 and A == 0: units = a");

    /* zero totals refused */
    P = u64v(0); R = u64v(0); A = u64v(0); r = u64v(0); a = u64v(5);
    s = u64v(9);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_E_RANGE &&
          eq_u64(&s, 9), "r + R == 0 refused");
    r = u64v(5); a = u64v(0);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_E_RANGE,
          "a + A == 0 refused");

    /* P + s overflow: empty-pool branch, P = 2^256-1 with R = 0 */
    P = max256(); R = u64v(0); A = u64v(1); r = u64v(5); a = u64v(1);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_E_OVERFLOW,
          "P + units passing 2^256 refused");
    /* The verifier's counterexample (units rounding is THORChain's LegacyDec
     * Quo then TruncateInt, handler_add_liquidity.go:489-499):
     * R = A = K = 3*10^18, P = K - 1, r = a = 1.
     *   cross = r*A + a*R = 2K;  2*r*a = 2;  num = P*(2K + 2) = 2(K-1)(K+1)
     *   den   = cross + 2*R*A = 2K + 2K^2 = 2K(K+1)
     *   exact quotient = (K-1)/K = 1 - 1/K = 0.99999999999999999966.. (K=3e18)
     * LegacyDec keeps 18 decimals: 0.999999999999999999|666.. rounds UP to
     * 1.000000000000000000, TruncateInt = 1. Integer floor would give 0. */
    {
        evm_u256 K = dec("3000000000000000000"), one = u64v(1), Pm;
        evm_u256_sub(&Pm, &K, &one);
        CHECK(amm_units_for_add(&s, &tot, &Pm, &K, &K, &one, &one) == AMM_OK &&
              eq_u64(&s, 1), "verifier counterexample: 1 unit (LegacyDec rounds up), not 0");
    }
    /* a product passing 2^256: P = 2^255, cross ~ 2 */
    P = pow2(255); R = u64v(1); A = u64v(1); r = u64v(1); a = u64v(1);
    CHECK(amm_units_for_add(&s, &tot, &P, &R, &A, &r, &a) == AMM_E_OVERFLOW,
          "P*(...) passing 2^256 refused");
}

static void l7b_dec_quo(void) {
    printf("L7b LegacyDec division: 18-decimal banker's rounding, then truncation\n");
    evm_u256 out, N, D;
    /* Each vector is N/D with the 19th decimal written out. S = floor(N*10^36/D),
     * q = S / 10^18, rem = S mod 10^18, tie = 5*10^17. */

    /* ODD tie: N/D = (2e18 - 1)/(2e18) = 0.9999999999999999995 exactly.
     * S = (2e18-1)*1e36/2e18 = (2e18-1)*5e17 = 9.99999999999999999e35 + ... :
     *   (2e18-1)*5e17 = 1e36 - 5e17, so q = 1e18 - 1 (odd), rem = 1e18 - 5e17
     *   = 5e17 = tie. Banker's rounding goes to the EVEN neighbour of
     *   (1e18-1, 1e18): 1e18. TruncateInt(1e18 / 1e18) = 1.
     * WHAT THIS PINS: the tie branch rounds UP here. A "tie rounds down"
     * (half-down) or "tie stays" mistake gives 0 on this vector, as does the
     * old integer floor. WHAT IT CANNOT PIN: half-up versus half-to-even.
     * Proof that no vector can: TruncateInt differs between the two rules only
     * if the rounded value crosses a multiple of 10^18, i.e. q + 1 = m*10^18,
     * i.e. q = m*10^18 - 1, which is ODD (10^18 is even); on an odd q the tie
     * rule of half-to-even rounds up exactly like half-up. On an even q the two
     * rules differ in q (q vs q + 1) but never in q / 10^18 truncated. */
    N = dec("1999999999999999999"); D = dec("2000000000000000000");
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 1),
          "odd tie 0.9999999999999999995 rounds to even 1.000000000000000000 -> 1");

    /* EVEN tie: N/D = (2e18 + 1)/(2e18) = 1.0000000000000000005 exactly.
     * q = 1e18 (even), rem = 5e17 = tie: banker's keeps q = 1e18 (half-UP
     * would give 1e18 + 1); both truncate to 1, so this vector pins only that
     * a tie on an even q does not move the integer part (see the proof above:
     * the two rules cannot differ in the truncated result). */
    N = dec("2000000000000000001"); D = dec("2000000000000000000");
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 1), "even tie stays: 1");

    /* EVEN tie below a boundary: N/D = (4e18 - 3)/(2e18) = 1.9999999999999999985
     * exactly -> q = 1999999999999999998 (even), rem = 5e17: stays even ->
     * 1.999999999999999998 -> TruncateInt 1. (Half-up would give ...999 and
     * also truncate to 1: the truncated result is the same, this vector pins
     * only that the integer part 1 is unchanged by an even tie.) */
    N = dec("3999999999999999997"); D = dec("2000000000000000000");
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 1), "even tie 1.9999999999999999985 -> 1");

    /* BELOW the tie: N/D = (5e18 - 3)/(5e18) = 0.9999999999999999994
     * S = (5e18-3)*1e36/5e18 = (5e18-3)*2e17 = 1e36 - 6e17;
     * q = 1e18 - 1, rem = 1e18 - 6e17 = 4e17 < 5e17: no rounding -> 0. */
    N = dec("4999999999999999997"); D = dec("5000000000000000000");
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 0), "below the tie: 0");

    /* ABOVE the tie: N/D = (5e18 - 2)/(5e18) = 0.9999999999999999996
     * S = (5e18-2)*2e17 = 1e36 - 4e17; q = 1e18 - 1, rem = 6e17 > tie: q+1
     * = 1e18 -> 1. */
    N = dec("4999999999999999998"); D = dec("5000000000000000000");
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 1), "above the tie: 1");

    /* plain cases */
    N = u64v(500000); D = u64v(10500);                /* 47.619047619047619047.. */
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 47), "500000/10500 -> 47");
    N = u64v(7); D = u64v(7);
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 1), "7/7 -> 1");
    N = u64v(0);
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq_u64(&out, 0), "0/7 -> 0");

    /* wide numerator: N = 2^255, D = 2 -> 2^254 (N*10^36 needs 376 bits) */
    N = pow2(255); D = u64v(2);
    { evm_u256 want = pow2(254);
      CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq(&out, &want),
            "2^255/2 = 2^254 through the 512-bit intermediate"); }
    /* result passing 2^256: N = 2^255, D = 1/2 is not expressible; use
     * N = 2^255 + 2^255 - 1 over D = 1 is 2^256-1 (fits); there is no
     * whole-number D that overflows the result, so only fits are testable */
    N = max256(); D = u64v(1);
    CHECK(amm_dec_quo_trunc(&out, &N, &D) == AMM_OK && eq(&out, &N), "(2^256-1)/1 fits");
    { evm_u256 z = u64v(0);
      out = u64v(9);
      CHECK(amm_dec_quo_trunc(&out, &N, &z) == AMM_E_ZERO_DIV && eq_u64(&out, 9),
            "zero divisor refused, result untouched"); }
}

static void l8_share(void) {
    printf("L8 GetSafeShare\n");
    evm_u256 out, part, total, alloc;
    /* a=3, p=1, t=2: (3*1 + 1)/2 = 2 (1.5 rounds half up) */
    part = u64v(1); total = u64v(2); alloc = u64v(3);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 2),
          "3*1/2 = 1.5 rounds up to 2");
    /* a=10, p=1, t=3: (10 + 1)/3 = 3 (3.33 -> 3) */
    part = u64v(1); total = u64v(3); alloc = u64v(10);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 3),
          "10*1/3 = 3.33 -> 3");
    /* a=10, p=2, t=3: (20 + 1)/3 = 7 (6.67 -> 7) */
    part = u64v(2);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 7),
          "10*2/3 = 6.67 -> 7");
    /* cap: part 9 > total 3 -> allocation */
    part = u64v(9);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 10),
          "part above total is capped: allocation");
    /* part == total */
    part = u64v(3);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 10),
          "part == total: allocation");
    /* zeros */
    part = u64v(0);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 0),
          "part 0 -> 0");
    part = u64v(1); total = u64v(0);
    out = u64v(9);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_OK && eq_u64(&out, 0),
          "total 0 -> 0 (reference guard, not a division)");
    /* overflow of a*p */
    part = pow2(200); total = pow2(201); alloc = pow2(200);
    CHECK(amm_safe_share(&out, &part, &total, &alloc) == AMM_E_OVERFLOW,
          "allocation*part passing 2^256 refused");
}

static void l9_withdraw(void) {
    printf("L9 withdraw\n");
    /* pool units 10000, N 1000, U 333, provider 1000 units, bp 2505.
     * claimed = (1000*2505 + 5000)/10000 = 2,510,000/10000 = 251 (250.5 up)
     * after   = 1000 - 251 = 749
     * out_n   = (1000*251 + 5000)/10000 = 256,000/10000 = 25 (25.1)
     * out_u   = (333*251 + 5000)/10000 = 88,583/10000 = 8 (8.36) */
    amm_pool_t p = { u64v(1000), u64v(333), u64v(10000) };
    evm_u256 lp = u64v(1000);
    amm_withdraw_t w;
    CHECK(amm_withdraw_calc(&w, &p, &lp, 2505) == AMM_OK &&
          eq_u64(&w.units_claimed, 251) && eq_u64(&w.units_after, 749) &&
          eq_u64(&w.out_n, 25) && eq_u64(&w.out_u, 8),
          "bp 2505 of 1000 units: 251 claimed (half up), N 25, U 8");
    CHECK(amm_pool_apply_withdraw(&p, &w) == AMM_OK &&
          eq_u64(&p.depth_n, 975) && eq_u64(&p.depth_u, 325) &&
          eq_u64(&p.units, 9749), "update: N 975, U 325, units 9749");

    /* bp 10000: part == total -> everything */
    p = (amm_pool_t){ u64v(1000), u64v(333), u64v(1000) };
    CHECK(amm_withdraw_calc(&w, &p, &lp, 10000) == AMM_OK &&
          eq_u64(&w.units_claimed, 1000) && eq_u64(&w.units_after, 0) &&
          eq_u64(&w.out_n, 1000) && eq_u64(&w.out_u, 333),
          "bp 10000 of the whole pool: all units, both depths");
    /* refusals */
    CHECK(amm_withdraw_calc(&w, &p, &lp, 10001) == AMM_E_RANGE, "bp > 10000 refused");
    { evm_u256 z = u64v(0);
      CHECK(amm_withdraw_calc(&w, &p, &z, 100) == AMM_E_RANGE, "zero provider units refused");
      amm_pool_t e = p; e.units = z;
      CHECK(amm_withdraw_calc(&w, &e, &lp, 100) == AMM_E_RANGE, "zero pool units refused");
      e = p; e.depth_n = z;
      CHECK(amm_withdraw_calc(&w, &e, &lp, 100) == AMM_E_RANGE, "zero NODUS depth refused");
      e = p; e.depth_u = z;
      CHECK(amm_withdraw_calc(&w, &e, &lp, 100) == AMM_E_RANGE, "zero USDT depth refused"); }

    /* update that would borrow: units claimed above pool units */
    amm_pool_t b = { u64v(10), u64v(10), u64v(5) };
    amm_withdraw_t bad = { u64v(6), u64v(0), u64v(1), u64v(1) };
    amm_pool_t before = b;
    CHECK(amm_pool_apply_withdraw(&b, &bad) == AMM_E_BORROW &&
          !memcmp(&b, &before, sizeof(b)), "a borrowing update is refused, pool unchanged");
}

static void l10_add(void) {
    printf("L10 add update\n");
    amm_pool_t p = { u64v(100), u64v(50), u64v(1000) };
    evm_u256 r = u64v(10), a = u64v(5), s;
    CHECK(amm_pool_apply_add(&p, &r, &a, &s) == AMM_OK && eq_u64(&s, 100) &&
          eq_u64(&p.depth_n, 110) && eq_u64(&p.depth_u, 55) &&
          eq_u64(&p.units, 1100), "same-ratio add moves depths and units together");
    /* depth_u at 2^256-1: the unit calculation itself (r*A) passes 2^256 and
     * the whole add is refused */
    amm_pool_t q = { u64v(100), max256(), u64v(1000) };
    amm_pool_t before = q;
    evm_u256 one = u64v(1);
    CHECK(amm_pool_apply_add(&q, &r, &one, NULL) == AMM_E_OVERFLOW &&
          !memcmp(&q, &before, sizeof(q)), "overflow refusal leaves the pool unchanged");
    /* first add into an empty pool: the Foundation's start (plan section 14):
     * 30,000,000 NODUS = 3*10^15 raw, 3000 USDT = 3*10^9 raw -> units 3*10^15 */
    amm_pool_t e = { u64v(0), u64v(0), u64v(0) };
    evm_u256 rn = dec("3000000000000000"), au = dec("3000000000");
    CHECK(amm_pool_apply_add(&e, &rn, &au, &s) == AMM_OK && eq(&s, &rn) &&
          eq(&e.depth_n, &rn) && eq(&e.depth_u, &au) && eq(&e.units, &rn),
          "start pool: units = the NODUS side added");
}

static void l11_inflight(void) {
    printf("L11 in-flight admission (USDT raw: 100 USDT = 100000000)\n");
    const uint64_t SW = 100000000ULL, IF = 500000000ULL;
    CHECK(amm_inflight_admit(SW, 0, SW, IF) == AMM_OK, "100 USDT swap into an empty book");
    CHECK(amm_inflight_admit(SW + 1, 0, SW, IF) == AMM_E_SWAP_LIMIT,
          "100 USDT + 1 raw: per-swap limit");
    CHECK(amm_inflight_admit(SW, 400000000ULL, SW, IF) == AMM_OK,
          "400 open + 100: exactly 500, admitted");
    CHECK(amm_inflight_admit(SW, 400000001ULL, SW, IF) == AMM_E_INFLIGHT,
          "400.000001 open + 100: over the total");
    CHECK(amm_inflight_admit(1, UINT64_MAX, SW, IF) == AMM_E_OVERFLOW,
          "sum overflow refused, never wrapped into room");
}

int main(void) {
    printf("test_amm_ledger\n");
    l1_primitives();
    l2_l3_swap();
    l4_refusals();
    l5_apply();
    l6_payout();
    l7_units();
    l7b_dec_quo();
    l8_share();
    l9_withdraw();
    l10_add();
    l11_inflight();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
