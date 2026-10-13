/**
 * Nodus — HF-6 slice 5a: water-fill power cap (INERT pure function).
 *
 * Governing record: design 2026-10-03-hf5-validator-owner-stake rev 6 §5;
 * decisions Kurultay #14 (2026-10-08) K1, K2, K5.
 *
 * Sections:
 *   1. Every vector of the independent oracle shared/dnac/tests/
 *      power_cap_oracle.py (output: power_cap_oracle_out.txt, each vector
 *      named by its "vector <name>" line): the three §5 examples, n = 1/2/3,
 *      ratio 500 with 7 entries, a tie set with reversed ids, the 32-entry
 *      seed-1 random set at ratio 3000 and 500, and the 128-entry maxima.
 *      rand32_r500 stops at k = 19 where 10000 − r′·k = 500 = r′ — the
 *      termination edge argued in power_cap.h ("Guarantees").
 *   2. On every vector: counted ≥ 1, counted ≤ p, "no counted share exceeds
 *      r′" (counted_i·10000 ≤ r′·Σcounted, checked u64), and determinism
 *      under fixed permutations of the (p, id) pairs (reverse, rotate by 1,
 *      rotate by n/2): the same validator gets the same counted.
 *   3. Fail-closed (-1) cases, each with counted_out pre-filled by a
 *      sentinel and checked untouched: NULL args, n = 0, n = 129, a zero
 *      p_i, ratio 0 / 499 / 3001 / UINT32_MAX, and u64 overflow
 *      (p = {UINT64_MAX} → r′·S overflows; Σp overflows).
 *   4. Ratio bounds 500 and 3000 themselves are accepted.
 *
 * Fixture rules (identical to the oracle's docstring):
 *   - validator_id of the entry at INPUT position i = 64 × byte
 *     ((i·37 + 11) & 0xFF), except vector tie_rev: 64 × byte(n − i).
 *   - The 128-entry vectors are filled by loop with
 *     pmax = UINT64_MAX / 10^8 = 184467440737 (oracle: UINT64_MAX //
 *     DECIMAL_UNIT); "skew" = pmax then 127 × 1.
 *
 * @file test_power_cap.c
 */

#include "dnac/power_cap.h"
#include "dnac/ledger_ids.h"
#include "dnac/res_meter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define NMAX DNA_MAX_ACTIVE_VALIDATORS
#define PMAX 184467440737ULL     /* UINT64_MAX / 10^8 */
#define SENTINEL 0xA5A5A5A5A5A5A5A5ULL

static uint8_t g_ids[NMAX][64];

static void ids_default(uint32_t n) {
    for (uint32_t i = 0; i < n; i++)
        memset(g_ids[i], (int)((i * 37u + 11u) & 0xFFu), 64);
}

static void ids_tie_rev(uint32_t n) {
    for (uint32_t i = 0; i < n; i++)
        memset(g_ids[i], (int)((n - i) & 0xFFu), 64);
}

/* r′ recomputed here from the §5 text (the function does not return it). */
static uint64_t r_prime(uint32_t n, uint32_t ratio) {
    uint64_t avg = (10000u + n - 1u) / n;
    return avg > ratio ? avg : ratio;
}

/* Section 2 properties of one successful result. */
static int check_props(const char *name, const uint64_t *p, uint32_t n,
                       uint32_t ratio, const uint64_t *counted) {
    uint64_t sum = 0, rhs = 0, rp = r_prime(n, ratio);
    for (uint32_t i = 0; i < n; i++) {
        CHECK(counted[i] >= 1, name);
        CHECK(counted[i] <= p[i], name);
        CHECK(dna_ck_add_u64(sum, counted[i], &sum) == 0, name);
    }
    CHECK(dna_ck_mul_u64(rp, sum, &rhs) == 0, name);
    for (uint32_t i = 0; i < n; i++) {
        uint64_t lhs = 0;
        CHECK(dna_ck_mul_u64(counted[i], 10000u, &lhs) == 0, name);
        CHECK(lhs <= rhs, name);              /* share ≤ r′ */
    }
    OK();
    return 0;
}

/* Determinism: apply permutation perm (new position j holds old entry
 * perm[j]) to (p, id) pairs; the same validator must get the same value. */
static int check_perm(const char *name, const uint64_t *p, uint32_t n,
                      uint32_t ratio, const uint64_t *counted,
                      const uint32_t *perm) {
    static uint8_t pid[NMAX][64];
    uint64_t pp[NMAX], pc[NMAX];
    for (uint32_t j = 0; j < n; j++) {
        pp[j] = p[perm[j]];
        memcpy(pid[j], g_ids[perm[j]], 64);
    }
    CHECK(dna_power_cap_counted(pp, (const uint8_t (*)[64])pid, n, ratio,
                                pc) == 0, name);
    for (uint32_t j = 0; j < n; j++)
        CHECK(pc[j] == counted[perm[j]], name);
    OK();
    return 0;
}

/* Run one oracle vector (ids already in g_ids) and pin the result. */
static int run_vec(const char *name, const uint64_t *p, uint32_t n,
                   uint32_t ratio, const uint64_t *expect) {
    uint64_t out[NMAX];
    uint32_t perm[NMAX];
    uint64_t in_copy[NMAX];
    uint8_t ids_copy[NMAX][64];

    memcpy(in_copy, p, (size_t)n * sizeof(uint64_t));
    memcpy(ids_copy, g_ids, sizeof(g_ids));
    CHECK(dna_power_cap_counted(p, (const uint8_t (*)[64])g_ids, n, ratio,
                                out) == 0, name);
    /* Caller arrays are not reordered or written. */
    CHECK(memcmp(in_copy, p, (size_t)n * sizeof(uint64_t)) == 0, name);
    CHECK(memcmp(ids_copy, g_ids, sizeof(g_ids)) == 0, name);
    for (uint32_t i = 0; i < n; i++)
        CHECK(out[i] == expect[i], name);
    OK();

    if (check_props(name, p, n, ratio, out) != 0) return 1;

    for (uint32_t j = 0; j < n; j++) perm[j] = n - 1u - j;          /* reverse */
    if (check_perm(name, p, n, ratio, out, perm) != 0) return 1;
    for (uint32_t j = 0; j < n; j++) perm[j] = (j + 1u) % n;        /* rot 1 */
    if (check_perm(name, p, n, ratio, out, perm) != 0) return 1;
    for (uint32_t j = 0; j < n; j++) perm[j] = (j + n / 2u) % n;    /* rot n/2 */
    if (check_perm(name, p, n, ratio, out, perm) != 0) return 1;
    return 0;
}

#define RUN(name, ratio, P, E) \
    run_vec((name), (P), (uint32_t)(sizeof(P) / sizeof((P)[0])), (ratio), (E))

/* rand32: oracle random.Random(1), p_i = max(1, randint(1,10^12) >> randint(0,40)). */
static const uint64_t RAND32_P[32] = {
    38959209247ULL, 60ULL, 463ULL, 51197558ULL, 266489534278ULL, 54756ULL,
    667578651271ULL, 3758353ULL, 53928667ULL, 942498ULL, 10803109742ULL,
    595495266270ULL, 57840ULL, 1781ULL, 3ULL, 3123ULL, 15ULL, 23129773ULL,
    453ULL, 160958719356ULL, 26ULL, 11067740722ULL, 2640869ULL, 389367ULL,
    184ULL, 135708915ULL, 2ULL, 451ULL, 3ULL, 35ULL, 24351ULL, 357384719ULL
};
/* oracle rand32_r3000: r′=3000, stop_k=2, cap=366680653207 */
static const uint64_t RAND32_R3000[32] = {
    38959209247ULL, 60ULL, 463ULL, 51197558ULL, 266489534278ULL, 54756ULL,
    366680653207ULL, 3758353ULL, 53928667ULL, 942498ULL, 10803109742ULL,
    366680653207ULL, 57840ULL, 1781ULL, 3ULL, 3123ULL, 15ULL, 23129773ULL,
    453ULL, 160958719356ULL, 26ULL, 11067740722ULL, 2640869ULL, 389367ULL,
    184ULL, 135708915ULL, 2ULL, 451ULL, 3ULL, 35ULL, 24351ULL, 357384719ULL
};
/* oracle rand32_r500: r′=500, stop_k=19, cap=6599 */
static const uint64_t RAND32_R500[32] = {
    6599, 60, 463, 6599, 6599, 6599, 6599, 6599, 6599, 6599, 6599, 6599,
    6599, 1781, 3, 3123, 15, 6599, 453, 6599, 26, 6599, 6599, 6599, 184,
    6599, 2, 451, 3, 35, 6599, 6599
};

static int test_vectors(void) {
    /* §5 worked examples. */
    { static const uint64_t P[] = {88, 2, 2, 2, 2, 2, 2};
      static const uint64_t E[] = {5, 2, 2, 2, 2, 2, 2};
      ids_default(7); if (RUN("ex_88_2x6", 3000, P, E)) return 1; }
    { static const uint64_t P[] = {45, 45, 10};
      static const uint64_t E[] = {10, 10, 10};
      ids_default(3); if (RUN("ex_45_45_10", 3000, P, E)) return 1; }
    { static const uint64_t P[] = {10, 10, 10, 10, 10, 10, 10};
      ids_default(7); if (RUN("ex_10x7", 3000, P, P)) return 1; }

    /* Small sets: r′ = ⌈10000/n⌉. */
    { static const uint64_t P[] = {5};
      ids_default(1); if (RUN("n1", 3000, P, P)) return 1; }
    { static const uint64_t P[] = {7, 7};
      ids_default(2); if (RUN("n2_equal", 3000, P, P)) return 1; }
    { static const uint64_t P[] = {9, 1};
      static const uint64_t E[] = {1, 1};
      ids_default(2); if (RUN("n2_unequal", 3000, P, E)) return 1; }
    { static const uint64_t P[] = {4, 4, 4};
      ids_default(3); if (RUN("n3_equal", 3000, P, P)) return 1; }
    { static const uint64_t P[] = {50, 30, 20};
      static const uint64_t E[] = {20, 20, 20};
      ids_default(3); if (RUN("n3_unequal", 3000, P, E)) return 1; }
    /* Same set, caller order differs: output follows caller order. */
    { static const uint64_t P[] = {20, 50, 30};
      static const uint64_t E[] = {20, 20, 20};
      ids_default(3); if (RUN("n3_unequal_order", 3000, P, E)) return 1; }

    /* ratio 500, n = 7: r′ = 1429 > 500. */
    { static const uint64_t P[] = {100, 100, 100, 100, 100, 100, 100};
      ids_default(7); if (RUN("r500_7equal", 500, P, P)) return 1; }
    { static const uint64_t P[] = {1000, 100, 90, 80, 70, 60, 50};
      static const uint64_t E[] = {50, 50, 50, 50, 50, 50, 50};
      ids_default(7); if (RUN("r500_7skew", 500, P, E)) return 1; }

    /* Ties broken by validator_id (ids descending in input order). */
    { static const uint64_t P[] = {30, 5, 30, 5, 30, 5, 30, 5};
      ids_tie_rev(8); if (RUN("tie_rev", 3000, P, P)) return 1; }

    ids_default(32);
    if (RUN("rand32_r3000", 3000, RAND32_P, RAND32_R3000)) return 1;
    if (RUN("rand32_r500", 500, RAND32_P, RAND32_R500)) return 1;

    /* 128-entry maxima (filled by the rule in the file header). */
    {
        static uint64_t P[NMAX], E[NMAX];
        ids_default(NMAX);
        for (uint32_t i = 0; i < NMAX; i++) P[i] = PMAX;
        if (RUN("max128_equal_r3000", 3000, P, P)) return 1;
        if (RUN("max128_equal_r500", 500, P, P)) return 1;
        P[0] = PMAX;
        for (uint32_t i = 1; i < NMAX; i++) P[i] = 1;
        for (uint32_t i = 0; i < NMAX; i++) E[i] = 1;
        E[0] = 54;                 /* oracle max128_skew_r3000: cap=54 */
        if (RUN("max128_skew_r3000", 3000, P, E)) return 1;
        E[0] = 6;                  /* oracle max128_skew_r500: cap=6 */
        if (RUN("max128_skew_r500", 500, P, E)) return 1;
    }
    return 0;
}

static int sentinel_intact(const uint64_t *out, uint32_t n) {
    for (uint32_t i = 0; i < n; i++)
        if (out[i] != SENTINEL) return 0;
    return 1;
}

static int expect_fail(const char *name, const uint64_t *p,
                       const uint8_t (*ids)[64], uint32_t n, uint32_t ratio,
                       uint64_t *out, uint32_t out_n) {
    for (uint32_t i = 0; i < out_n; i++) out[i] = SENTINEL;
    CHECK(dna_power_cap_counted(p, ids, n, ratio, out) == -1, name);
    CHECK(sentinel_intact(out, out_n), name);
    OK();
    return 0;
}

static int test_rejects(void) {
    static uint64_t P[NMAX + 1];
    static uint8_t ids[NMAX + 1][64];
    uint64_t out[NMAX + 1];
    const uint8_t (*cid)[64] = (const uint8_t (*)[64])ids;

    for (uint32_t i = 0; i <= NMAX; i++) {
        P[i] = 10;
        memset(ids[i], (int)((i * 37u + 11u) & 0xFFu), 64);
    }

    /* NULL arguments. */
    if (expect_fail("NULL p", NULL, cid, 7, 3000, out, 7)) return 1;
    if (expect_fail("NULL ids", P, NULL, 7, 3000, out, 7)) return 1;
    CHECK(dna_power_cap_counted(P, cid, 7, 3000, NULL) == -1, "NULL out");
    OK();

    /* n bounds. */
    if (expect_fail("n == 0", P, cid, 0, 3000, out, 1)) return 1;
    if (expect_fail("n == 129", P, cid, NMAX + 1, 3000, out, NMAX + 1))
        return 1;

    /* ratio bounds (K5: [500, 3000]). */
    if (expect_fail("ratio 0", P, cid, 7, 0, out, 7)) return 1;
    if (expect_fail("ratio 499", P, cid, 7, 499, out, 7)) return 1;
    if (expect_fail("ratio 3001", P, cid, 7, 3001, out, 7)) return 1;
    if (expect_fail("ratio max", P, cid, 7, UINT32_MAX, out, 7)) return 1;

    /* Bounds themselves accepted. */
    CHECK(dna_power_cap_counted(P, cid, 7, 500, out) == 0, "ratio 500");
    OK();
    CHECK(dna_power_cap_counted(P, cid, 7, 3000, out) == 0, "ratio 3000");
    OK();
    CHECK(dna_power_cap_counted(P, cid, NMAX, 3000, out) == 0, "n == 128");
    OK();

    /* A zero power anywhere. */
    P[0] = 0;
    if (expect_fail("p[0] == 0", P, cid, 7, 3000, out, 7)) return 1;
    P[0] = 10; P[6] = 0;
    if (expect_fail("p[6] == 0", P, cid, 7, 3000, out, 7)) return 1;
    P[6] = 10;

    /* Overflow: r′·S with n = 1 (r′ = 10000) and p = UINT64_MAX. */
    P[0] = UINT64_MAX;
    if (expect_fail("r'*S overflow", P, cid, 1, 3000, out, 1)) return 1;
    /* Overflow: Σp. */
    P[0] = UINT64_MAX; P[1] = 1;
    if (expect_fail("sum overflow", P, cid, 2, 3000, out, 2)) return 1;
    /* Overflow: r′·S above the §5 precondition (3000 · 2^62 · 2). */
    P[0] = (uint64_t)1 << 62; P[1] = (uint64_t)1 << 62;
    if (expect_fail("r'*S overflow n2", P, cid, 2, 3000, out, 2)) return 1;
    return 0;
}

int main(void) {
    if (test_vectors() != 0) return 1;
    if (test_rejects() != 0) return 1;
    printf("test_power_cap: %d checks OK\n", g_checks);
    return 0;
}
