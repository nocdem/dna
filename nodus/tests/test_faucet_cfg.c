/**
 * test_faucet_cfg.c — the nodus-faucet configuration parser.
 *
 * WHAT IT PROVES: the operator's defaults (decision 2026-10-22-testnet-test-
 * tokens-faucet-dex.md: 100 000 NODUS = 10^13, 100 tUSDT = 10^8, 10 NODUS =
 * 10^9, fee ceiling 0.1 NODUS = 10^7) are what an unset key means; the file
 * is STRICT — an unknown key, a duplicate key, a malformed value, a missing
 * required key or an out-of-range value refuses the whole file.
 * WHAT IT REQUIRES: a default build; no environment, no network, no files.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: it parses strings; it does not prove the service reads the
 * values it parsed (test_faucet_state covers the use of amounts and ceiling).
 */
#include <stdio.h>
#include <string.h>

#include "faucet_cfg.h"

static int g_failures = 0;
#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (cond) printf("  ok    %s\n", what);                              \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

#define FP64  "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa"
#define CH32  "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" \
              "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" \
              "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb"

#define MINIMAL                                   \
    "node_host = 127.0.0.1\n"                     \
    "node_port = 4001\n"                          \
    "node_fp = " FP64 "\n"                        \
    "chain_id = " CH32 "\n"                       \
    "key_dir = /var/lib/nodus-faucet/keys\n"      \
    "journal_path = /var/lib/nodus-faucet/j.db\n" \
    "token_id = " FP64 "\n"                       \
    "listen_port = 4010\n"

static int parse(const char *text, faucet_cfg_t *c) {
    char err[160];
    return faucet_cfg_parse(text, c, err, sizeof(err));
}

int main(void) {
    printf("test_faucet_cfg\n");
    faucet_cfg_t c;

    CHECK(parse(MINIMAL, &c) == 0, "C1 the minimal required file parses");
    CHECK(c.full_native == 10000000000000ULL, "C1 default full_native = 10^13 (100 000 NODUS)");
    CHECK(c.full_token == 100000000ULL, "C1 default full_token = 10^8 (100 tUSDT, 6 decimals)");
    CHECK(c.start_native == 1000000000ULL, "C1 default start_native = 10^9 (10 NODUS)");
    CHECK(c.fee_ceiling == 10000000ULL, "C1 default fee ceiling = 10^7 (0.1 NODUS)");
    CHECK(c.expiry_ahead == 90, "C1 default expiry margin = tip + 90");
    CHECK(c.listen_port == 4010 && c.node_port == 4001, "C1 ports parsed");
    CHECK(c.chain_id[0] == 0xbb && c.node_fp[63] == 0xaa, "C1 hex keys decoded");

    CHECK(parse(MINIMAL "fee_ceiling = 5000000\nqueue_cap = 8\n", &c) == 0 &&
          c.fee_ceiling == 5000000 && c.queue_cap == 8, "C2 optional keys override defaults");
    CHECK(parse(MINIMAL "# comment\n\n  poll_ms = 2000  \n", &c) == 0 && c.poll_ms == 2000,
          "C2 comments, blank lines and padding are fine");

    CHECK(parse(MINIMAL "bogus = 1\n", &c) != 0, "C3 an unknown key refuses the file");
    CHECK(parse(MINIMAL "listen_port = 4011\n", &c) != 0, "C3 a duplicate required key refuses");
    CHECK(parse(MINIMAL "queue_cap = 4\nqueue_cap = 5\n", &c) != 0, "C3 a duplicate optional key refuses");
    CHECK(parse("node_host = x\n", &c) != 0, "C4 a missing required key refuses");
    CHECK(parse(MINIMAL "fee_ceiling = 12abc\n", &c) != 0, "C5 a malformed number refuses");
    CHECK(parse(MINIMAL "fee_ceiling = -1\n", &c) != 0, "C5 a negative number refuses");
    CHECK(parse(MINIMAL "fee_ceiling = 0\n", &c) != 0, "C5 a zero fee ceiling refuses");
    CHECK(parse(MINIMAL "full_native = 18446744073709551615\n", &c) != 0,
          "C5 an amount that could overflow capacity arithmetic refuses");
    CHECK(parse(MINIMAL "expiry_ahead = 95\n", &c) != 0, "C6 expiry margin above 90 refuses (mempool admits tip + 100)");
    CHECK(parse(MINIMAL "expiry_ahead = 5\n", &c) != 0, "C6 expiry margin below 10 refuses");
    CHECK(parse(MINIMAL "storage_ceiling = 1000\n", &c) != 0, "C6 a storage ceiling below 1 MiB refuses");
    CHECK(parse(MINIMAL "queue_cap = 0\n", &c) != 0, "C6 queue_cap 0 refuses");
    CHECK(parse(MINIMAL "conn_cap = 1000\n", &c) != 0, "C6 conn_cap above 256 refuses");

    {
        char bad[2048];
        snprintf(bad, sizeof(bad), "%s", MINIMAL);
        char *p = strstr(bad, "chain_id = ") + 11;
        p[0] = 'B';                           /* uppercase hex */
        CHECK(parse(bad, &c) != 0, "C7 uppercase hex refuses");
        snprintf(bad, sizeof(bad), "%s", MINIMAL);
        p = strstr(bad, "chain_id = ") + 11;
        p[63] = '\n';                         /* short chain id */
        CHECK(parse(bad, &c) != 0, "C7 a short chain id refuses");
    }

    printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
    return g_failures ? 1 : 0;
}
