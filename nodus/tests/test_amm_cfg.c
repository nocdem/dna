/**
 * test_amm_cfg.c -- the nodus-amm settings file (amm_cfg.c).
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 15 "Settings", section 19; amm_cfg.h for the key table):
 *   C1  a minimal file (only the required keys) parses and every optional
 *       setting takes the plan's value: eth_confirmations 3, swap_max 100
 *       USDT, inflight_max 500 USDT, pool start 3000 USDT / 30,000,000 NODUS,
 *       liquidity waits 300 Ethereum blocks / 3 Nodus blocks, all pauses off,
 *       the USDT mainnet contract;
 *   C2  every value of a file overrides its default (and the parsed
 *       addresses, providers and flags land in the right fields);
 *   C3  each DEFERRED setting is required: removing any one of them refuses
 *       the file (eth_providers, eth_quorum, eth_reorg_window_blocks,
 *       approval_valid_seconds, payout_final_depth_eth, http_max_body,
 *       http_max_response, eth_price_source, eip712_name, expected_origin,
 *       held_keeps_room (0 | 1, no default: the plan defers whether a held
 *       swap keeps its in-flight room, plan lines 312, 407; 0, 1, 2, text and
 *       a duplicate are tested),
 *       as does removing a deployment key (foundation_eth, foundation_nodus,
 *       node_*, journal_path);
 *   C4  strictness: unknown key (including "commission", which the plan does
 *       not build), duplicate key, a line without '=', a sign or a space or
 *       a hex digit inside a number, out-of-bounds values at both edges
 *       (eth_confirmations 0 / 1 / 100 / 101), a swap limit above the
 *       in-flight total, a quorum above the number of providers or zero, a
 *       provider that is not https or is listed twice or empty element, more
 *       providers than the table holds, a window below the confirmations,
 *       pause flags other than 0 / 1, uppercase hex addresses, a short
 *       address, a control byte in a name;
 *   C5  the loader: a missing file, a NUL byte, a file above 16 KiB are
 *       refused; a good file loads; a refusal reports a reason.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp for the
 *   loader cases, removed at the end; no network.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: bounds the plan leaves open (the quorum lower bound, the
 *   window relation) are pinned here as THIS implementation's reading
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
        {"eth_price_source", "https://price.example/eth"},
        {"eip712_name", "Nodus Swap"}, {"expected_origin", "https://swap.example"},
        {"eth_reorg_window_blocks", "96"}, {"approval_valid_seconds", "1800"},
        {"payout_final_depth_eth", "12"}, {"http_max_body", "65536"},
        {"http_max_response", "65536"}, {"held_keeps_room", "0"},
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
    CHECK(c.eth_confirmations == 3, "eth_confirmations 3 (givens item 22)");
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
        "eth_confirmations = 5\nswap_max_usdt = 7\ninflight_max_usdt = 9\n"
        "pool_start_usdt = 11\npool_start_nodus = 13\n"
        "liquidity_wait_eth_blocks = 17\nliquidity_wait_nodus_blocks = 19\n"
        "swaps_paused = 1\nliquidity_paused = 1\npayouts_paused = 1\n"
        "usdt_contract = 00112233445566778899aabbccddeeff00112233\n"
        "# a comment\n\n   \n", &c) == 0, "file with every optional key parses");
    CHECK(c.eth_confirmations == 5 && c.swap_max_usdt == 7 &&
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
        "approval_valid_seconds", "payout_final_depth_eth", "http_max_body",
        "http_max_response", "eth_price_source", "eip712_name",
        "expected_origin", "held_keeps_room", "foundation_eth", "foundation_nodus", "node_host",
        "node_port", "node_fp", "chain_id", "journal_path" };
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
    expect_refused("commission = 5\n", NULL, "unknown key (commission is not built)");
    expect_refused("eth_confirmations = 3\neth_confirmations = 4\n", NULL, "duplicate optional key");
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
    CHECK(parses(NULL, "eth_confirmations = 1\n", &c) == 0 && c.eth_confirmations == 1,
          "eth_confirmations 1 (lower edge) accepted");
    CHECK(parses(NULL, "eth_confirmations = 100\neth_reorg_window_blocks = 100\n", &c) != 0,
          "duplicate eth_reorg_window_blocks refused (control)");
    expect_refused("eth_confirmations = 0\n", NULL, "eth_confirmations 0");
    expect_refused("eth_confirmations = 101\n", NULL, "eth_confirmations 101");
    {   /* 100 passes the key bound; needs a window of at least 100 */
        char text[4096];
        build(text, sizeof(text), "eth_reorg_window_blocks",
              "eth_confirmations = 100\neth_reorg_window_blocks = 100\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0 && c.eth_confirmations == 100,
              "eth_confirmations 100 (upper edge) accepted with window 100");
    }
    expect_refused("swap_max_usdt = 600000000\n", NULL, "swap limit above in-flight total");
    {   char text[4096];
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 2\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) != 0, "window 2 below confirmations 3 refused");
        build(text, sizeof(text), "eth_reorg_window_blocks", "eth_reorg_window_blocks = 3\n");
        CHECK(amm_cfg_parse(text, &c, NULL, 0) == 0, "window == confirmations accepted"); }

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

int main(void) {
    printf("test_amm_cfg\n");
    init_hex();
    c1_defaults();
    c2_overrides();
    c3_required();
    c4_strict();
    c5_loader();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
