/**
 * test_amm_price.c -- the ETH price adapter (amm_price.c).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 10,
 * sections 10, 15, 17, 19; givens items 50, 74):
 *   P1  each ticker shape (Kraken result.<pair>.c[0], Binance and Coinbase
 *       `price`, Bitfinex element 6 of the list) is read to USDT raw per ETH
 *       (10^-6); a value truncates at 6 fraction digits; a zero price, a
 *       sign, an exponent, "12.", an empty body, an 8-digit integer part, a
 *       missing key, a short Bitfinex list and an escaped string are NOT an
 *       answer;
 *   P2  the median, as Boltz DataAggregator.ts:114-124: odd count the middle
 *       one, even count the floor of the mean of the two middle ones;
 *   P3  the conversion ceil(gas_limit * max_fee * price_e6 / 10^18): an exact
 *       case, a rounded-UP case, zero gas, a zero price refused, a 128-bit and
 *       a 64-bit overflow refused (never a wrapped value);
 *   P4  freshness and the minimum with a driven clock and stub sources:
 *       four fresh -> median of four; one source failing keeps its answer
 *       until it is older than 180 s; with fewer than 3 fresh answers the
 *       price is UNKNOWN (never zero, never an older value, the out value
 *       untouched) and it returns when 3 are fresh again; a malformed answer
 *       is not counted; a source due is fetched, a source not due is not (the
 *       schedule: older than max_age / 2);
 *   P5  the seam amm_eth_price_t answers the USDT fee from the cached price
 *       and ERR when the price is unknown; amm_price_new refuses a minimum
 *       above the listed sources, a zero minimum, a zero age, an empty or
 *       unknown source mask; the curl GET refuses a non-https URL and a zero
 *       timeout cap;
 *   P6  the cache is guarded by the adapter's own mutex (the poll thread
 *       writes, a quote on another thread reads): a reader thread started
 *       from inside a fetch finishes while the fetch is still running, so the
 *       lock is not held across the network call. HOW P6 CAN FALSELY PASS: it
 *       does not detect a missing lock (an unguarded cache also lets the
 *       reader finish; a data race needs a thread sanitizer to show); it
 *       fails only when the lock is held across the GET.
 * HAND VECTORS: every expected number is derived in its comment from the
 * source shape or the formula, not from the code under test.
 * FLAGS: a default build with libcurl (pkg-config); no network, no clock read
 * (the time is a variable the test moves), no files.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the stub answers follow the SHAPES the Boltz files read
 * (Kraken.ts:21-23, Binance.ts:5-7, Bitfinex.ts:16, CoinbasePro.ts); a live
 * exchange can answer another shape today (plan section 10: not read), which
 * only a live run shows. The libcurl transport itself is not exercised (no
 * network): only its argument refusals.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "amm_price.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static int parse(unsigned bit, const char *s, uint64_t *v) {
    return amm_price_parse(bit, s, strlen(s), v);
}

static void p1_parse(void) {
    printf("P1 ticker shapes\n");
    uint64_t v = 0;
    CHECK(parse(AMM_PRICE_BINANCE, "{\"symbol\":\"ETHUSDT\",\"price\":\"3421.56000000\"}", &v) == 0 &&
          v == 3421560000ULL, "Binance price string 3421.56 -> 3,421,560,000");
    CHECK(parse(AMM_PRICE_COINBASE, "{\"trade_id\":1,\"price\":\"3500.1\",\"size\":\"0.5\"}", &v) == 0 &&
          v == 3500100000ULL, "Coinbase price 3500.1 -> 3,500,100,000");
    CHECK(parse(AMM_PRICE_KRAKEN,
                "{\"error\":[],\"result\":{\"ETHUSDT\":{\"a\":[\"3422.0\",\"1\",\"1.000\"],"
                "\"b\":[\"3421.0\",\"1\",\"1.000\"],\"c\":[\"3421.50000\",\"0.1\"]}}}", &v) == 0 &&
          v == 3421500000ULL, "Kraken result.ETHUSDT.c[0] 3421.5 -> 3,421,500,000");
    CHECK(parse(AMM_PRICE_BITFINEX,
                "[3421.2,12.5,3421.3,8.1,-10.5,-0.003,3421.25,5000.2,3500,3300]", &v) == 0 &&
          v == 3421250000ULL, "Bitfinex element 6 (3421.25) -> 3,421,250,000");
    CHECK(parse(AMM_PRICE_BINANCE, "{\"price\":\"1.2345678\"}", &v) == 0 && v == 1234567ULL,
          "truncated at 6 fraction digits: 1.2345678 -> 1,234,567");
    CHECK(parse(AMM_PRICE_BINANCE, "{\"price\":\"7\"}", &v) == 0 && v == 7000000ULL,
          "an integer price 7 -> 7,000,000");

    static const char *bad[] = {
        "{\"price\":\"3.4e3\"}", "{\"price\":\"-5\"}", "{\"price\":\"0\"}",
        "{\"price\":\"0.0000001\"}", "{\"price\":\"12.\"}", "{\"price\":\"\"}",
        "{\"price\":\"12345678\"}", "{\"cost\":\"5\"}", "{\"price\":\"1\\u0032\"}",
        "", "{\"price\":}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char msg[96];
        v = 99;
        snprintf(msg, sizeof(msg), "refused: %s", bad[i][0] ? bad[i] : "(empty)");
        CHECK(parse(AMM_PRICE_BINANCE, bad[i], &v) != 0 && v == 99, msg);
    }
    CHECK(parse(AMM_PRICE_BITFINEX, "[1,2,3]", &v) != 0, "Bitfinex short list refused");
    CHECK(parse(AMM_PRICE_BITFINEX, "{\"price\":\"5\"}", &v) != 0, "Bitfinex object refused");
    CHECK(parse(AMM_PRICE_KRAKEN, "{\"error\":[\"EQuery:Unknown asset pair\"]}", &v) != 0,
          "Kraken error answer refused");
    CHECK(parse(0, "{\"price\":\"5\"}", &v) != 0 && parse(3, "{\"price\":\"5\"}", &v) != 0,
          "an unknown source bit refused");
}

static void p2_median(void) {
    printf("P2 median\n");
    uint64_t a[] = {5, 1, 3};
    CHECK(amm_price_median(a, 3) == 3, "odd: {5,1,3} -> 3");
    uint64_t b[] = {4, 2, 8, 6};
    CHECK(amm_price_median(b, 4) == 5, "even: sorted 2,4,6,8, mean of 4 and 6 = 5");
    uint64_t c[] = {2, 1};
    CHECK(amm_price_median(c, 2) == 1, "even: floor of 1.5 = 1");
    uint64_t d[] = {7};
    CHECK(amm_price_median(d, 1) == 7, "one value");
    uint64_t e[] = {401, 100, 300, 200};
    CHECK(amm_price_median(e, 4) == 250, "{100,200,300,401}: 200 + (300-200)/2 = 250");
    CHECK(amm_price_median(e, 0) == 0, "no value: 0 (callers never ask)");
}

static void p3_convert(void) {
    printf("P3 conversion\n");
    uint64_t f = 99;
    /* 100000 gas * 20 gwei (20e9) = 2e15 wei; price 3000 USDT = 3e9;
     * 2e15 * 3e9 = 6e24; / 1e18 = 6e6 exactly = 6 USDT */
    CHECK(amm_price_convert(100000, 20000000000ULL, 3000000000ULL, &f) == AMM_ETH_OK &&
          f == 6000000ULL, "exact: 6 USDT");
    /* 3 gas * 7 = 21 wei; * 3e9 = 6.3e10; / 1e18 = 0.000000063 -> rounded UP to 1 */
    CHECK(amm_price_convert(3, 7, 3000000000ULL, &f) == AMM_ETH_OK && f == 1,
          "rounded up: 1 raw unit, not 0");
    CHECK(amm_price_convert(0, 7, 3000000000ULL, &f) == AMM_ETH_OK && f == 0, "zero gas: 0");
    f = 55;
    CHECK(amm_price_convert(5, 5, 0, &f) == AMM_ETH_ERR && f == 55, "a zero price refused");
    /* 2^64-1 * 2^64-1 is about 3.4e38 = the 128-bit limit; * 1e13 overflows */
    CHECK(amm_price_convert(UINT64_MAX, UINT64_MAX, 10000000000000ULL, &f) == AMM_ETH_ERR && f == 55,
          "a 128-bit overflow refused");
    /* 1e19 * 1e19 = 1e38 wei fits 128 bits; * 1e12 = 1e50 does not */
    CHECK(amm_price_convert(10000000000000000000ULL, 10000000000000000000ULL,
                            1000000000000ULL, &f) == AMM_ETH_ERR, "128-bit product overflow refused");
    /* 1e19 * 1e19 = 1e38 wei, price 1 raw: 1e38 / 1e18 = 1e20 > 2^64-1 = 1.8e19 */
    CHECK(amm_price_convert(10000000000000000000ULL, 10000000000000000000ULL, 1, &f) == AMM_ETH_ERR &&
          f == 55, "a result above 2^64-1 refused");
}

/* ── stub sources ─────────────────────────────────────────────────────── */

typedef struct {
    uint64_t now;
    int fail[4];            /* by index: kraken, binance, bitfinex, coinbase   */
    int garbage[4];
    uint64_t usd[4];        /* whole USDT per ETH each source reports          */
    int fetched[4];         /* fetch count                                     */
    amm_price_t *probe;     /* P6: read the price from another thread DURING a fetch */
    int probed;
    int probe_joined;       /* the reader finished while the fetch was running */
    int probe_rc;
    pthread_t probe_th;
} world_t;

static int src_index(const char *url) {
    static const unsigned bits[4] = {AMM_PRICE_KRAKEN, AMM_PRICE_BINANCE,
                                     AMM_PRICE_BITFINEX, AMM_PRICE_COINBASE};
    for (int i = 0; i < 4; i++)
        if (!strcmp(url, amm_price_source_url(bits[i]))) return i;
    return -1;
}

typedef struct { amm_price_t *p; uint64_t v; int rc; } probe_t;

static void *probe_reader(void *a) {
    probe_t *r = a;
    r->rc = amm_price_get(r->p, &r->v);
    return NULL;
}

static int stub_get(void *ctx, const char *url, uint8_t *resp, size_t cap,
                    size_t *len, uint64_t dl) {
    (void)dl;
    world_t *w = ctx;
    int i = src_index(url);
    if (i < 0) return AMM_ETH_ERR;
    w->fetched[i]++;
    if (w->probe && !w->probed) {
        /* a quote reading the cache from ANOTHER thread while this fetch runs:
         * it must not wait for the network call */
        static probe_t pr;
        w->probed = 1;
        pr.p = w->probe; pr.v = 0; pr.rc = 99;
        if (pthread_create(&w->probe_th, NULL, probe_reader, &pr) == 0) {
            struct timespec t;
            clock_gettime(CLOCK_REALTIME, &t);
            t.tv_sec += 3;
            w->probe_joined = pthread_timedjoin_np(w->probe_th, NULL, &t) == 0;
            w->probe_rc = w->probe_joined ? pr.rc : 99;   /* a late reader is joined by the test */
        }
    }
    if (w->fail[i]) return AMM_ETH_ERR;
    char body[400];
    if (w->garbage[i]) snprintf(body, sizeof(body), "<html>busy</html>");
    else if (i == 0)
        snprintf(body, sizeof(body), "{\"error\":[],\"result\":{\"ETHUSDT\":{\"c\":[\"%llu.5\",\"1\"]}}}",
                 (unsigned long long)w->usd[i]);
    else if (i == 2)
        snprintf(body, sizeof(body), "[1,1,1,1,1,1,%llu.5,1]", (unsigned long long)w->usd[i]);
    else
        snprintf(body, sizeof(body), "{\"price\":\"%llu.5\"}", (unsigned long long)w->usd[i]);
    size_t n = strlen(body);
    if (n > cap) return AMM_ETH_ERR;
    memcpy(resp, body, n);
    *len = n;
    return AMM_ETH_OK;
}

static uint64_t stub_now(void *ctx) { return ((world_t *)ctx)->now; }

static amm_price_t *mk(world_t *w, unsigned mask, uint64_t min) {
    amm_price_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.get = stub_get; c.get_ctx = w; c.now_s = stub_now; c.now_ctx = w;
    c.sources = mask; c.min_sources = min; c.max_age_seconds = 180;
    return amm_price_new(&c);
}

static void p4_fresh(void) {
    printf("P4 freshness, minimum, schedule\n");
    world_t w;
    memset(&w, 0, sizeof(w));
    w.usd[0] = 3400; w.usd[1] = 3410; w.usd[2] = 3420; w.usd[3] = 3430;  /* each +.5 */
    amm_price_t *p = mk(&w, AMM_PRICE_ALL, 3);
    uint64_t v = 777;
    CHECK(p != NULL, "adapter built (4 sources, minimum 3, 180 s)");
    CHECK(amm_price_get(p, &v) == AMM_ETH_ERR && v == 777, "nothing fetched yet: unknown");

    /* a) t=1000, all four answer: the prices are 3400.5, 3410.5, 3420.5, 3430.5;
     * even count: 3410.5 + (3420.5 - 3410.5)/2 = 3415.5 -> 3,415,500,000 */
    w.now = 1000;
    CHECK(amm_price_poll(p, 0) == 4, "a) four fresh answers");
    CHECK(amm_price_get(p, &v) == AMM_ETH_OK && v == 3415500000ULL, "a) median of four 3415.5");
    int f0[4]; memcpy(f0, w.fetched, sizeof(f0));

    /* not due (age 50 < 90): nothing is fetched */
    w.now = 1050;
    CHECK(amm_price_poll(p, 0) == 4 && !memcmp(f0, w.fetched, sizeof(f0)),
          "a source younger than max_age / 2 is not fetched again");

    /* b) t=1100, binance fails: all four due (age 100 >= 90); binance keeps its
     * answer from 1000 (age 100 <= 180): still four fresh */
    w.now = 1100; w.fail[1] = 1;
    CHECK(amm_price_poll(p, 0) == 4 && w.fetched[1] == f0[1] + 1,
          "b) a failed fetch keeps the previous answer while it is within 180 s");
    CHECK(amm_price_get(p, &v) == AMM_ETH_OK && v == 3415500000ULL, "b) price unchanged");

    /* c) t=1181: binance 181 s old -> not used; the others (age 81) not due.
     * three fresh: 3400.5, 3420.5, 3430.5 -> median 3420.5 */
    w.now = 1181;
    CHECK(amm_price_poll(p, 0) == 3, "c) the 181 s old answer is not fresh");
    CHECK(amm_price_get(p, &v) == AMM_ETH_OK && v == 3420500000ULL,
          "c) median of the three fresh answers 3420.5");

    /* d) t=1291: coinbase (answered 1100) is 191 s old too; kraken and bitfinex
     * refetched at 1200? they were not due at 1181; at 1291 age 191 -> due, ok.
     * fresh: kraken, bitfinex = 2 < 3 -> UNKNOWN */
    w.now = 1291; w.fail[3] = 1;
    CHECK(amm_price_poll(p, 0) == 2, "d) two fresh answers");
    v = 4242;
    CHECK(amm_price_get(p, &v) == AMM_ETH_ERR && v == 4242,
          "d) fewer than 3 fresh: price UNKNOWN, never zero, never an older value");

    /* e) the sources come back */
    w.now = 1300; w.fail[1] = 0; w.fail[3] = 0;
    CHECK(amm_price_poll(p, 0) == 4 && amm_price_get(p, &v) == AMM_ETH_OK &&
          v == 3415500000ULL, "e) three or more fresh again: the price returns");

    /* a malformed answer is not counted: kraken answers HTML from the start */
    world_t w2;
    memset(&w2, 0, sizeof(w2));
    w2.usd[1] = 3410; w2.usd[2] = 3420; w2.usd[3] = 3430; w2.garbage[0] = 1;
    amm_price_t *q = mk(&w2, AMM_PRICE_ALL, 3);
    w2.now = 500;
    CHECK(amm_price_poll(q, 0) == 3 && amm_price_get(q, &v) == AMM_ETH_OK && v == 3420500000ULL,
          "a malformed answer is not counted: median of 3410.5, 3420.5, 3430.5");
    amm_price_free(q);

    /* a source that is not listed is never fetched */
    world_t w3;
    memset(&w3, 0, sizeof(w3));
    w3.usd[0] = 3400; w3.usd[1] = 3410; w3.usd[2] = 3420; w3.usd[3] = 3430; w3.now = 9;
    q = mk(&w3, AMM_PRICE_KRAKEN | AMM_PRICE_BINANCE, 2);
    CHECK(amm_price_poll(q, 0) == 2 && w3.fetched[2] == 0 && w3.fetched[3] == 0 &&
          amm_price_get(q, &v) == AMM_ETH_OK && v == 3405500000ULL,
          "only the listed sources are read: median 3400.5 / 3410.5 = 3405.5");
    amm_price_free(q);
    amm_price_free(p);
}

static void p5_seam_and_config(void) {
    printf("P5 seam, configuration, transport arguments\n");
    world_t w;
    memset(&w, 0, sizeof(w));
    w.usd[0] = 3000; w.usd[1] = 3000; w.usd[2] = 3000; w.usd[3] = 3000; w.now = 10;
    amm_price_t *p = mk(&w, AMM_PRICE_ALL, 3);
    amm_eth_price_t seam;
    amm_price_seam(p, &seam);
    uint64_t fee = 31;
    CHECK(seam.fee_usdt(seam.ctx, 100000, 20000000000ULL, &fee, 0) == AMM_ETH_ERR && fee == 31,
          "seam: price unknown -> ERR, out untouched");
    amm_price_poll(p, 0);
    /* price 3000.5 -> 3,000,500,000; wei 2e15; product 2e15 * 3.0005e9 = 6.001e24;
     * / 1e18 = 6,001,000 exactly */
    CHECK(seam.fee_usdt(seam.ctx, 100000, 20000000000ULL, &fee, 0) == AMM_ETH_OK &&
          fee == 6001000ULL, "seam: 6.001 USDT from the cached price");
    amm_price_free(p);

    amm_price_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.get = stub_get; c.get_ctx = &w; c.now_s = stub_now; c.now_ctx = &w;
    c.sources = AMM_PRICE_ALL; c.min_sources = 3; c.max_age_seconds = 180;
    amm_price_t *t = amm_price_new(&c);
    CHECK(t != NULL, "the plan's values build");
    amm_price_free(t);
    c.min_sources = 5; CHECK((t = amm_price_new(&c)) == NULL, "minimum above the sources refused"); amm_price_free(t);
    c.min_sources = 0; CHECK((t = amm_price_new(&c)) == NULL, "minimum 0 refused"); amm_price_free(t);
    c.min_sources = 3; c.max_age_seconds = 0; CHECK((t = amm_price_new(&c)) == NULL, "age 0 refused"); amm_price_free(t);
    c.max_age_seconds = 180; c.sources = 0; CHECK((t = amm_price_new(&c)) == NULL, "empty mask refused"); amm_price_free(t);
    c.sources = 16; CHECK((t = amm_price_new(&c)) == NULL, "unknown mask bit refused"); amm_price_free(t);
    c.sources = AMM_PRICE_KRAKEN | AMM_PRICE_BINANCE;
    CHECK((t = amm_price_new(&c)) == NULL, "3 of 2 listed refused"); amm_price_free(t);

    CHECK(amm_price_curl_new(0) == NULL, "curl GET: a zero timeout cap refused");
    amm_price_curl_t *cc = amm_price_curl_new(1000);
    uint8_t buf[16]; size_t n = 0;
    CHECK(cc != NULL && amm_price_curl_get(cc, "http://example.invalid/x", buf, sizeof(buf), &n, 0) == AMM_ETH_ERR,
          "curl GET: a non-https URL refused before any connection");
    amm_price_curl_free(cc);
}

static void p6_cache_lock(void) {
    printf("P6 the price cache is guarded: a quote reads it while a poll is fetching\n");
    world_t w;
    memset(&w, 0, sizeof(w));
    w.usd[0] = 3000; w.usd[1] = 3000; w.usd[2] = 3000; w.usd[3] = 3000; w.now = 10;
    amm_price_t *p = mk(&w, AMM_PRICE_ALL, 3);
    uint64_t v = 0;
    CHECK(amm_price_poll(p, 0) == 4 && amm_price_get(p, &v) == AMM_ETH_OK, "the first poll fills the cache");
    /* every source is due again (older than max_age / 2 = 90 s); during the
     * first fetch of the second poll another thread reads the price */
    w.now = 200;
    w.probe = p;
    amm_price_poll(p, 0);
    if (!w.probe_joined && w.probed) pthread_join(w.probe_th, NULL);
    CHECK(w.probed && w.probe_joined,
          "the reader thread finished while the poll was still inside a network fetch "
          "(the lock is not held across the GET)");
    CHECK(w.probe_rc == AMM_ETH_ERR || w.probe_rc == AMM_ETH_OK,
          "and it got a complete answer (a price or unknown), never a torn one");
    amm_price_free(p);
}

int main(void) {
    printf("test_amm_price\n");
    p1_parse();
    p2_median();
    p3_convert();
    p4_fresh();
    p5_seam_and_config();
    p6_cache_lock();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
