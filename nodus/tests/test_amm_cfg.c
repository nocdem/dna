/**
 * test_amm_cfg.c -- the nodus-amm settings file (amm_cfg.c).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 15 "Settings", section 19; amm_cfg.h for the key table):
 *   C1  a minimal file (only the required keys) parses and every optional
 *       setting takes the plan's value: confirmation bounds 100 / 1,000
 *       USDT and counts 3 / 5 / 33 (givens item 60), swap_max 100
 *       USDT, inflight_max 500 USDT, pool start 3000 USDT / 30,000,000 NODUS,
 *       liquidity waits 300 Ethereum blocks / 3 Nodus blocks, all pauses off,
 *       the USDT mainnet contract;
 *   C2  every value of a file overrides its default (and the parsed
 *       addresses, providers and flags land in the right fields);
 *   C3  each DEFERRED setting is required: removing any one of them refuses
 *       the file (eth_providers, eth_quorum, eth_reorg_window_blocks,
 *       payout_final_depth_eth, http_max_body,
 *       http_max_response, eth_price_source, eip712_name, expected_origin,
 *       held_keeps_room (0 | 1, no default: the plan defers whether a held
 *       swap keeps its in-flight room, plan lines 312, 407; 0, 1, 2, text and
 *       a duplicate are tested),
 *       as does removing a deployment key (foundation_eth, foundation_nodus,
 *       node_*, journal_path);
 *   C4  strictness: unknown key, duplicate key, a line without '=', a sign or a space or
 *       a hex digit inside a number, out-of-bounds values at both edges
 *       (each eth_conf_count_* 0 / 1 / 100 / 101), a swap limit above the
 *       in-flight total, a quorum above the number of providers or zero, a
 *       provider that is not https or is listed twice or empty element, more
 *       providers than the table holds, a window below the largest
 *       confirmation count (33 by default; 32 refused, 33 accepted),
 *       confirmation bounds equal or descending, counts decreasing from
 *       row to row (givens item 60, plan section 15 load check),
 *       the retired key eth_confirmations (an unknown key),
 *       pause flags other than 0 / 1, uppercase hex addresses, a short
 *       address, a control byte in a name;
 *   C5  the loader: a missing file, a NUL byte, a file above 16 KiB are
 *       refused; a good file loads; a refusal reports a reason;
 *   C6  the three settings of the operator's answers of 2026-11-10: the file
 *       without approval_valid_seconds loads with 300 s (givens 72), without
 *       eth_chain_id with 1 and with 11155111 as written (givens 77), without
 *       commission with 0, 0 written accepted, 1 / 25 / -1 and a repeated
 *       key refused (givens 73; shape DEFERRED, plan sections 12 and 15);
 *       0 for approval_valid_seconds and eth_chain_id refused.
 *   C7  (revision 10) swap_min_usdt default 1,000,000 raw (givens 89), 0 and a
 *       value above swap_max_usdt refused; the three ETH price keys
 *       (eth_price_sources names, eth_price_min_sources 3, eth_price_max_age_
 *       seconds 180; givens 74, plan s.10, s.15) with their defaults, a
 *       minimum above the listed sources refused, duplicates, empty
 *       elements, unknown names and URLs refused, the retired single key
 *       eth_price_source refused; the service keys (http_*, scan bounds, key
 *       paths, lock path) are required without a default (C3) and their
 *       bounds refuse 0 / 65 / 101 at the edges.
 *   NOTE C3 no longer lists eth_price_source: the key was replaced by the
 *   optional eth_price_sources (a plan value exists), so the file without
 *   them loads.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp for the
 *   loader cases, removed at the end; no network.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: bounds the plan leaves open (the quorum lower bound, the
 *   window relation, equal confirmation bounds refused as "not ascending",
 *   the key names eth_conf_*) are pinned here as THIS implementation's reading
 *   (amm_cfg.h); a later plan decision changes them. The test proves the
 *   parser matches its header, not that the values are operationally wise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "amm_cfg.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static char HEX128[129], HEX64[65], HEX40[41];

static void init_hex(void) {
    memset(HEX128, 'a', 128); HEX128[128] = '\0';
    memset(HEX64, 'b', 64);   HEX64[64] = '\0';
    memset(HEX40, 'c', 40);   HEX40[40] = '\0';
}

/* The required keys; `skip` (may be NULL) names one key to leave out,
 * `extra` (may be NULL) is appended verbatim. */
static void build(char *out, size_t cap, const char *skip, const char *extra) {
    struct { const char *k; const char *v; } kv[] = {
        {"node_host", "127.0.0.1"}, {"node_port", "4001"},
        {"node_fp", HEX128}, {"chain_id", HEX64},
        {"journal_path", "/var/lib/nodus-amm/journal.db"},
        {"eth_providers", "https://rpc-a.example/v1/k1, https://rpc-b.example/v1/k2,https://rpc-c.example/k3"},
        {"eth_quorum", "2"},
        {"foundation_eth", HEX40}, {"foundation_nodus", HEX128},
        {"eip712_name", "Nodus Swap"}, {"expected_origin", "https://swap.example"},
        {"eth_reorg_window_blocks", "96"}, {"approval_valid_seconds", "1800"},
        {"payout_final_depth_eth", "12"}, {"http_max_body", "65536"},
        {"http_max_response", "65536"}, {"held_keeps_room", "0"},
        {"http_port", "8480"}, {"http_conn_cap", "16"}, {"http_timeout_ms", "5000"},
        {"worker_interval_ms", "1000"}, {"rpc_timeout_ms", "8000"},
        {"eth_start_height", "100"}, {"nodus_start_height", "50"},
        {"eth_max_scan_blocks", "20"}, {"nodus_page_limit", "50"},
        {"nodus_max_pages", "4"}, {"nodus_expiry_ahead", "50"},
        {"nodus_resubmit_blocks", "3"}, {"nodus_scan_blocks", "64"},
        {"eth_key_path", "/var/lib/nodus-amm/eth.key"},
        {"nodus_key_dir", "/var/lib/nodus-amm/id"},
        {"lock_path", "/var/lib/nodus-amm/lock"},
    };
    size_t n = 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(kv) / sizeof(kv[0]); i++) {
        if (skip && !strcmp(skip, kv[i].k)) continue;
        n += (size_t)snprintf(out + n, cap - n, "%s = %s\n", kv[i].k, kv[i].v);
    }
    if (extra) snprintf(out + n, cap - n, "%s", extra);
}

static int parses(const char *skip, const char *extra, amm_cfg_t *cfg) {
    char text[4096], err[160];
    build(text, sizeof(text), skip, extra);
    return amm_cfg_parse(text, cfg, err, sizeof(err));
}

static void c1_defaults(void) {
    printf("C1 minimal file: the plan's values\n");
    amm_cfg_t c;
    CHECK(parses(NULL, NULL, &c) == 0, "minimal file parses");
    CHECK(c.eth_conf_bound_1_usdt == 100000000ULL &&
          c.eth_conf_bound_2_usdt == 1000000000ULL,
          "bounds 100 / 1,000 USDT raw (givens item 60)");
    CHECK(c.eth_conf_count_1 == 3 && c.eth_conf_count_2 == 5 &&
          c.eth_conf_count_3 == 33, "counts 3 / 5 / 33 (givens item 60)");
    CHECK(c.swap_max_usdt == 100000000ULL, "swap_max 100 USDT raw");
    CHECK(c.inflight_max_usdt == 500000000ULL, "inflight_max 500 USDT raw");
    CHECK(c.pool_start_usdt == 3000000000ULL, "start pool 3000 USDT raw");
    CHECK(c.pool_start_nodus == 3000000000000000ULL, "start pool 30,000,000 NODUS raw");
    CHECK(c.liquidity_wait_eth_blocks == 300, "liquidity wait 300 Ethereum blocks");
    CHECK(c.liquidity_wait_nodus_blocks == 3, "liquidity wait 3 Nodus blocks");
    CHECK(!c.swaps_paused && !c.liquidity_paused && !c.payouts_paused, "pauses off");
    static const uint8_t usdt[20] = {0xda,0xc1,0x7f,0x95,0x8d,0x2e,0xe5,0x23,0xa2,
        0x20,0x62,0x06,0x99,0x45,0x97,0xc1,0x3d,0x83,0x1e,0xc7};
    CHECK(!memcmp(c.usdt_contract, usdt, 20), "USDT mainnet contract");
    CHECK(c.n_providers == 3 && c.eth_quorum == 2, "three providers, quorum 2");
    CHECK(!strcmp(c.eth_providers[1], "https://rpc-b.example/v1/k2"),
          "provider list is trimmed and ordered as written");
    CHECK(c.node_port == 4001 && !strcmp(c.node_host, "127.0.0.1"), "node address");
    CHECK(c.foundation_eth[0] == 0xcc && c.foundation_eth[19] == 0xcc, "foundation_eth bytes");
    CHECK(!strcmp(c.foundation_nodus, HEX128), "foundation_nodus kept as text");
    CHECK(c.held_keeps_room == 0, "held_keeps_room 0 as written");
    CHECK(c.eth_reorg_window_blocks == 96 && c.approval_valid_seconds == 1800 &&
          c.payout_final_depth_eth == 12 && c.http_max_body == 65536 &&
          c.http_max_response == 65536, "deferred values as written");
}

static void c2_overrides(void) {
    printf("C2 overrides\n");
    amm_cfg_t c;
    CHECK(parses(NULL,
        "eth_conf_bound_1_usdt = 21\neth_conf_bound_2_usdt = 22\n"
        "eth_conf_count_1 = 2\neth_conf_count_2 = 4\neth_conf_count_3 = 6\n"
        "swap_min_usdt = 5\nswap_max_usdt = 7\ninflight_max_usdt = 9\n"
        "pool_start_usdt = 11\npool_start_nodus = 13\n"
        "liquidity_wait_eth_blocks = 17\nliquidity_wait_nodus_blocks = 19\n"
        "swaps_paused = 1\nliquidity_paused = 1\npayouts_paused = 1\n"
        "usdt_contract = 00112233445566778899aabbccddeeff00112233\n"
        "# a comment\n\n   \n", &c) == 0, "file with every optional key parses");
    CHECK(c.eth_conf_bound_1_usdt == 21 && c.eth_conf_bound_2_usdt == 22 &&
          c.eth_conf_count_1 == 2 && c.eth_conf_count_2 == 4 &&
          c.eth_conf_count_3 == 6, "confirmation bounds and counts override");
    CHECK(c.swap_max_usdt == 7 &&
          c.inflight_max_usdt == 9 && c.pool_start_usdt == 11 &&
          c.pool_start_nodus == 13 && c.liquidity_wait_eth_blocks == 17 &&
          c.liquidity_wait_nodus_blocks == 19, "numbers override");
    CHECK(c.swaps_paused && c.liquidity_paused && c.payouts_paused, "pauses on");
    CHECK(c.usdt_contract[0] == 0x00 && c.usdt_contract[19] == 0x33, "contract override");
}

static void c3_required(void) {
    printf("C3 every deferred / deployment key is required\n");
    static const char *keys[] = {
        "eth_providers", "eth_quorum", "eth_reorg_window_blocks",
        "payout_final_depth_eth", "http_max_body",
        "http_max_response", "eip712_name",
        "expected_origin", "held_keeps_room", "foundation_eth", "foundation_nodus", "node_host",
        "node_port", "node_fp", "chain_id", "journal_path",
        "http_port", "http_conn_cap", "http_timeout_ms", "worker_interval_ms",
        "rpc_timeout_ms", "eth_start_height", "nodus_start_height",
        "eth_max_scan_blocks", "nodus_page_limit", "nodus_max_pages",
        "nodus_expiry_ahead", "nodus_resubmit_blocks", "nodus_scan_blocks",
        "eth_key_path", "nodus_key_dir", "lock_path" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        amm_cfg_t c;
        char msg[96];
        snprintf(msg, sizeof(msg), "missing %s refuses the file", keys[i]);
        CHECK(parses(keys[i], NULL, &c) != 0, msg);
    }
}

static void expect_refused(const char *extra, const char *skip, const char *what) {
    amm_cfg_t c;
    char text[4096], err[160] = "";
    build(text, sizeof(text), skip, extra);
    int rc = amm_cfg_parse(text, &c, err, sizeof(err));
    char msg[200];
    snprintf(msg, sizeof(msg), "%s refused", what);
    CHECK(rc != 0 && err[0] != '\0', msg);
}

static void c4_strict(void) {
    printf("C4 strictness and bounds\n");
    expect_refused("commision = 0\n", NULL, "unknown key");
    expect_refused("eth_conf_count_1 = 3\neth_conf_count_1 = 4\n", NULL, "duplicate optional key");
    expect_refused("eth_confirmations = 3\n", NULL, "retired key eth_confirmations (unknown key)");
    expect_refused("eth_quorum = 1\n", NULL, "duplicate required key");
    expect_refused("garbage line\n", NULL, "line without '='");
    expect_refused("swap_max_usdt = -5\n", NULL, "negative number");
    expect_refused("swap_max_usdt = +5\n", NULL, "plus sign");
    expect_refused("swap_max_usdt = 5 5\n", NULL, "space inside a number");
    expect_refused("swap_max_usdt = 0x10\n", NULL, "hex number");
    expect_refused("swap_max_usdt = 99999999999999999999\n", NULL, "u64 overflow");
    expect_refused("swap_max_usdt = 4611686018427387904\n", NULL, "implausibly large (> UINT64_MAX/4)");
    expect_refused("swap_max_usdt = 0\n", NULL, "zero swap limit");

    amm_cfg_t c;
    /* confirmation counts (givens item 60): each count 1..100 */
    CHECK(parses(NULL, "eth_conf_count_1 = 1\n", &c) == 0 && c.eth_conf_count_1 == 1,
          "eth_conf_count_1 1 (lower edge) accepted");
    expect_refused("eth_conf_count_1 = 0\n", NULL, "eth_conf_count_1 0");
    expect_refused("eth_conf_count_2 = 0\n", NULL, "eth_conf_count_2 0");
    expect_refused("eth_conf_count_3 = 0\n", NULL, "eth_conf_count_3 0");
    expect_refused("eth_conf_count_1 = 101\n", NULL, "eth_conf_count_1 101");
    expect_refused("eth_conf_count_2 = 101\n", NULL, "eth_conf_count_2 101");
    expect_refused("eth_conf_count_3 = 101\n", NULL, "eth_conf_count_3 101");
    {   /* 100 passes the key bound; the window must then be at least 100 */
        char text[4096];
        build(text, sizeof(text), "eth_reorg_window_blocks",
              "eth_conf_count_3 = 100\neth_reorg_window_blocks = 100\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && c.eth_conf_count_3 == 100,
              "eth_conf_count_3 100 (upper edge) accepted with window 100");
        build(text, sizeof(text), "eth_reorg_window_blocks",
              "eth_conf_count_3 = 100\neth_reorg_window_blocks = 99\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0,
              "eth_conf_count_3 100 with window 99 refused");
        build(text, sizeof(text), "eth_reorg_window_blocks",
              "eth_conf_count_1 = 100\neth_conf_count_2 = 100\n"
              "eth_conf_count_3 = 100\neth_reorg_window_blocks = 100\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0,
              "equal counts 100 / 100 / 100 accepted (counts may stay level)");
    }
    /* counts must not decrease from row to row (plan section 15) */
    expect_refused("eth_conf_count_1 = 6\n", NULL, "count 1 (6) above count 2 (5)");
    expect_refused("eth_conf_count_2 = 2\n", NULL, "count 2 (2) below count 1 (3)");
    expect_refused("eth_conf_count_3 = 4\n", NULL, "count 3 (4) below count 2 (5)");
    expect_refused("eth_conf_count_2 = 34\n", NULL, "count 2 (34) above count 3 (33)");
    CHECK(parses(NULL, "eth_conf_count_2 = 3\n", &c) == 0 && c.eth_conf_count_2 == 3,
          "count 2 == count 1 accepted");
    CHECK(parses(NULL, "eth_conf_count_2 = 33\n", &c) == 0 && c.eth_conf_count_2 == 33,
          "count 2 == count 3 accepted");
    /* bounds must be ascending (plan section 15); this reading is strict */
    expect_refused("eth_conf_bound_1_usdt = 1000000000\n", NULL,
                   "bounds equal (1,000 / 1,000)");
    expect_refused("eth_conf_bound_1_usdt = 2000000000\n", NULL,
                   "bounds descending (bound 1 above bound 2)");
    expect_refused("eth_conf_bound_2_usdt = 100000000\n", NULL,
                   "bounds equal (100 / 100)");
    expect_refused("eth_conf_bound_2_usdt = 50000000\n", NULL,
                   "bounds descending (bound 2 below bound 1)");
    expect_refused("eth_conf_bound_1_usdt = 0\n", NULL, "bound 1 zero");
    CHECK(parses(NULL, "eth_conf_bound_2_usdt = 100000001\n", &c) == 0 &&
          c.eth_conf_bound_2_usdt == 100000001ULL,
          "bound 2 one raw unit above bound 1 accepted");
    expect_refused("swap_max_usdt = 600000000\n", NULL, "swap limit above in-flight total");
    /* the reorg window must hold against the LARGEST count (count 3, 33) */
    {   char text[4096];
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 2\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "window 2 below the largest count 33 refused");
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 5\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0,
              "window 5 (above count 2, below count 3) refused: the largest count rules");
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 32\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "window 32 below the largest count 33 refused");
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 33\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0, "window == largest count 33 accepted"); }

    /* quorum */
    {   char text[4096];
        build(text, sizeof(text), "eth_quorum", "eth_quorum = 0\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "quorum 0 refused");
        build(text, sizeof(text), "eth_quorum", "eth_quorum = 4\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "quorum 4 above 3 providers refused");
        build(text, sizeof(text), "eth_quorum", "eth_quorum = 3\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && c.eth_quorum == 3,
              "quorum 3 of 3 accepted");
        build(text, sizeof(text), "eth_quorum", "eth_quorum = 1\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && c.eth_quorum == 1,
              "quorum 1 accepted (the plan sets no other lower bound)"); }

    /* providers */
    {   char text[4096];
        const char *bad[] = {
            "http://rpc.example/x", "https://rpc.example/a,,https://rpc.example/b",
            ",https://rpc.example/a", "https://rpc.example/a,",
            "https://rpc.example/a,https://rpc.example/a", "https://", "",
            "https://rpc.example/a b" };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char line[300], msg[120];
            snprintf(line, sizeof(line), "eth_providers = %s\n", bad[i]);
            build(text, sizeof(text), "eth_providers", line);
            snprintf(msg, sizeof(msg), "provider list case %zu refused", i);
            CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, msg);
        }
        /* AMM_MAX_PROVIDERS accepted, one more refused */
        char list[2048] = "eth_providers = ";
        size_t n = strlen(list);
        for (int i = 0; i < AMM_MAX_PROVIDERS; i++)
            n += (size_t)snprintf(list + n, sizeof(list) - n, "%shttps://p%d.example/x",
                                  i ? "," : "", i);
        snprintf(list + n, sizeof(list) - n, "\n");
        build(text, sizeof(text), "eth_providers", list);
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && c.n_providers == AMM_MAX_PROVIDERS,
              "AMM_MAX_PROVIDERS providers accepted");
        n = strlen(list) - 1;
        snprintf(list + n, sizeof(list) - n, ",https://extra.example/x\n");
        build(text, sizeof(text), "eth_providers", list);
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "one provider more refused"); }

    /* flags, hex, names */
    expect_refused("held_keeps_room = 2\n", "held_keeps_room", "held_keeps_room 2");
    expect_refused("held_keeps_room = yes\n", "held_keeps_room", "held_keeps_room text");
    expect_refused("held_keeps_room = 1\n", NULL, "duplicate held_keeps_room");
    CHECK(parses("held_keeps_room", "held_keeps_room = 1\n", &c) == 0 && c.held_keeps_room == 1,
          "held_keeps_room 1 as written");
    expect_refused("swaps_paused = 2\n", NULL, "pause flag 2");
    expect_refused("swaps_paused = on\n", NULL, "pause flag text");
    expect_refused("usdt_contract = DAC17F958D2EE523A2206206994597C13D831EC7\n", NULL,
                   "uppercase hex address");
    expect_refused("usdt_contract = dac17f958d2ee523\n", NULL, "short address");
    expect_refused("eip712_name = a\tb\n", "eip712_name", "control byte in a name");
    {
        char text[4096];
        build(text, sizeof(text), "eip712_name", "eip712_name = Nodus\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && !strcmp(c.eip712_name, "Nodus"),
              "plain name accepted (control for the refusals above)");
    }
}

static void c5_loader(void) {
    printf("C5 loader\n");
    char dir[] = "/tmp/amm_cfg_testXXXXXX";
    if (!mkdtemp(dir)) { printf("  FAIL  mkdtemp\n"); g_failures++; g_checks++; return; }
    char path[300], text[4096], err[160];
    amm_cfg_t c;

    snprintf(path, sizeof(path), "%s/none.cfg", dir);
    CHECK(amm_cfg_load(path, &c, err, sizeof(err)) != 0 && err[0], "missing file refused with a reason");

    build(text, sizeof(text), NULL, NULL);
    snprintf(path, sizeof(path), "%s/ok.cfg", dir);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(text, 1, strlen(text), f); fclose(f); }
    CHECK(amm_cfg_load(path, &c, err, sizeof(err)) == 0 && c.eth_quorum == 2, "good file loads");

    snprintf(path, sizeof(path), "%s/nul.cfg", dir);
    f = fopen(path, "wb");
    if (f) { fwrite(text, 1, strlen(text), f); fputc('\0', f); fputc('\n', f); fclose(f); }
    CHECK(amm_cfg_load(path, &c, err, sizeof(err)) != 0, "NUL byte refused");

    snprintf(path, sizeof(path), "%s/big.cfg", dir);
    f = fopen(path, "wb");
    if (f) {
        fwrite(text, 1, strlen(text), f);
        for (int i = 0; i < 1100; i++) fputs("# padding padding padding\n", f);
        fclose(f);
    }
    CHECK(amm_cfg_load(path, &c, err, sizeof(err)) != 0, "file above 16 KiB refused");

    /* clean up */
    const char *names[] = {"none.cfg", "ok.cfg", "nul.cfg", "big.cfg"};
    for (size_t i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);
}

static void c6_operator_settings(void) {
    printf("C6 approval_valid_seconds, eth_chain_id, commission\n");
    amm_cfg_t c;
    /* approval_valid_seconds: the base file writes 1800; leaving it out gives
     * the default of givens item 72 */
    CHECK(parses("approval_valid_seconds", NULL, &c) == 0 &&
          c.approval_valid_seconds == 300,
          "approval_valid_seconds absent: 300 seconds (givens item 72)");
    CHECK(parses(NULL, NULL, &c) == 0 && c.approval_valid_seconds == 1800,
          "approval_valid_seconds written: the written value");
    expect_refused("approval_valid_seconds = 0\n", "approval_valid_seconds",
                   "approval_valid_seconds 0");
    expect_refused("approval_valid_seconds = 60\n", NULL,
                   "approval_valid_seconds repeated");
    CHECK(parses("approval_valid_seconds", "approval_valid_seconds = 1\n", &c) == 0 &&
          c.approval_valid_seconds == 1, "approval_valid_seconds 1 (lower edge) accepted");

    /* eth_chain_id */
    CHECK(parses(NULL, NULL, &c) == 0 && c.eth_chain_id == 1,
          "eth_chain_id absent: 1 (Ethereum mainnet)");
    CHECK(parses(NULL, "eth_chain_id = 11155111\n", &c) == 0 &&
          c.eth_chain_id == 11155111ULL,
          "eth_chain_id 11155111 (Sepolia, givens item 77) as written");
    expect_refused("eth_chain_id = 0\n", NULL, "eth_chain_id 0");
    expect_refused("eth_chain_id = 1\neth_chain_id = 2\n", NULL, "eth_chain_id repeated");
    expect_refused("eth_chain_id = 0x1\n", NULL, "eth_chain_id hex");
    expect_refused("eth_chain_id = 4611686018427387904\n", NULL,
                   "eth_chain_id implausibly large (> UINT64_MAX/4)");

    /* commission: the plan's key (section 15), 0 only while its shape is
     * DEFERRED (section 12) */
    CHECK(parses(NULL, NULL, &c) == 0 && c.commission == 0,
          "commission absent: 0 (givens item 73)");
    CHECK(parses(NULL, "commission = 0\n", &c) == 0 && c.commission == 0,
          "commission 0 written, accepted");
    expect_refused("commission = 1\n", NULL, "commission 1 (no commission shape is built)");
    expect_refused("commission = 25\n", NULL, "commission 25");
    expect_refused("commission = -1\n", NULL, "commission negative");
    expect_refused("commission = 0\ncommission = 0\n", NULL, "commission repeated");
}

static void c7_price_and_min(void) {
    printf("C7 swap_min_usdt and the ETH price settings (givens 74, 89)\n");
    amm_cfg_t c;
    CHECK(parses(NULL, NULL, &c) == 0 && c.swap_min_usdt == 1000000ULL &&
          c.eth_price_min_sources == 3 && c.eth_price_max_age_seconds == 180 &&
          c.eth_price_sources == AMM_PRICE_ALL,
          "defaults: 1 USDT, 3 sources, 180 s, all four names");
    CHECK(parses(NULL, "swap_min_usdt = 5\n", &c) == 0 && c.swap_min_usdt == 5,
          "swap_min_usdt written");
    expect_refused("swap_min_usdt = 0\n", NULL, "swap_min_usdt 0");
    expect_refused("swap_min_usdt = 100000001\n", NULL, "swap_min_usdt above swap_max_usdt");
    CHECK(parses(NULL, "eth_price_sources = kraken, binance,bitfinex\n", &c) == 0 &&
          c.eth_price_sources == (AMM_PRICE_KRAKEN | AMM_PRICE_BINANCE | AMM_PRICE_BITFINEX),
          "three names listed");
    expect_refused("eth_price_sources = kraken,binance\n", NULL,
                   "min sources 3 above the two listed (plan s.15 load check)");
    CHECK(parses(NULL, "eth_price_sources = kraken,binance\neth_price_min_sources = 2\n", &c) == 0,
          "two listed with minimum 2 accepted");
    expect_refused("eth_price_sources = kraken,kraken,binance,coinbase\n", NULL, "a name listed twice");
    expect_refused("eth_price_sources = kraken,,binance,coinbase\n", NULL, "an empty element");
    expect_refused("eth_price_sources = kraken,gemini,binance,coinbase\n", NULL, "an unknown name");
    expect_refused("eth_price_sources = https://api.kraken.com/0/public\n", NULL, "a URL instead of a name");
    expect_refused("eth_price_source = https://price.example/eth\n", NULL, "the retired key eth_price_source");
    expect_refused("eth_price_min_sources = 0\n", NULL, "min sources 0");
    expect_refused("eth_price_min_sources = 5\n", NULL, "min sources above the four known sources");
    expect_refused("eth_price_max_age_seconds = 0\n", NULL, "max age 0");
    CHECK(parses(NULL, "eth_price_max_age_seconds = 60\n", &c) == 0 &&
          c.eth_price_max_age_seconds == 60, "max age written");
    expect_refused("http_port = 0\n", "http_port", "http_port 0");
    expect_refused("http_conn_cap = 65\n", "http_conn_cap", "http_conn_cap 65");
    expect_refused("nodus_expiry_ahead = 101\n", "nodus_expiry_ahead", "nodus_expiry_ahead 101");
    expect_refused("nodus_page_limit = 101\n", "nodus_page_limit", "nodus_page_limit 101");
}

/* C8 (revision 12, givens item 96, plan section 15): liquidity_min_nodus.
 * PROVES: default 100,000 NODUS = 10^13 raw; a written value overrides it;
 * 0 and a repeated key are refused (load check: greater than 0).
 * FALSE PASS: the default is compared with the same literal the loader holds;
 * 10^13 = 100,000 x 10^8 is checked by hand in the comment, not derived. */
static void c8_liquidity_min(void) {
    printf("C8 liquidity_min_nodus\n");
    amm_cfg_t c;
    CHECK(parses(NULL, NULL, &c) == 0 && c.liquidity_min_nodus == 10000000000000ULL,
          "default 100,000 NODUS = 10^13 raw (givens item 96)");
    CHECK(parses(NULL, "liquidity_min_nodus = 777\n", &c) == 0 &&
          c.liquidity_min_nodus == 777, "a written value overrides the default");
    expect_refused("liquidity_min_nodus = 0\n", NULL, "liquidity_min_nodus 0");
    expect_refused("liquidity_min_nodus = 5\nliquidity_min_nodus = 6\n", NULL,
                   "liquidity_min_nodus repeated");
}

int main(void) {
    printf("test_amm_cfg\n");
    init_hex();
    c1_defaults();
    c2_overrides();
    c3_required();
    c4_strict();
    c5_loader();
    c6_operator_settings();
    c7_price_and_min();
    c8_liquidity_min();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
