/**
 * Nodus — tool network file and --pin / --chain resolver tests
 *
 * Subject: src/client/nodus_tool_network.c (DHT v2 package 3c; decision
 * docs/plans/decisions/2026-10-24-dht-v2-tool-network-identity.md).
 *
 * PROVES
 *   - a good file loads (chain id, every node's ip / port / fp), also from a
 *     real file on disk and through NODUS_NETWORK;
 *   - the whole file is refused, with a reason, for: not JSON, trailing
 *     garbage, a non-object root, an unknown top-level key, an unknown node
 *     key, a missing chain_id / nodes / node field, an all-zero or
 *     wrong-length or upper-case chain id / fp, a non-IPv4 ip, a port of 0 /
 *     65536 / a string, a duplicate ip:port, an empty node list, more than
 *     NODUS_TOOL_NET_MAX_NODES nodes;
 *   - resolve: the file gives pin and chain for exactly its ip:port; --pin
 *     overrides the pin, --chain overrides the chain; an ip:port that is not
 *     in the file with no --pin is refused; neither file nor flags is
 *     refused for the pin and, with only --pin, for the chain;
 *     flags alone (no file) are enough;
 *   - fill: a client config comes out with a pin list and chain id that
 *     nodus_client_init would accept (non-empty, non-zero), a refused fill
 *     leaves the config untouched, fill_all uses the file's node list;
 *   - a named but bad network file refuses even when both flags are given.
 *
 * REQUIRES
 *   - Compile flags: a build with json-c (NODUS_HAS_JSONC). Without it the
 *     file cases FAIL (they do not skip). Nothing else.
 *   - Environment: none; the test sets and unsets NODUS_NETWORK itself and
 *     writes one temp file under /tmp.
 *
 * LEAVES
 *   Nothing: the temp file is removed; NODUS_NETWORK is unset on exit.
 *
 * HOW IT CAN LIE
 *   - Strings are built with fixed sample digits, not real fingerprints: it
 *     proves parsing and resolution, not that a pin matches a live node
 *     (that is nodus_tcp_sc / the harness).
 *   - Duplicate JSON KEYS inside one object are not detected by json-c (it
 *     keeps the last value); the test does not claim they are.
 *   - fill() is checked on the config fields it sets; nodus_client_init
 *     itself is not called here.
 */

#include "client/nodus_tool_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-62s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(cond, msg) do { if (cond) { PASS(); } else { FAIL(msg); } } while(0)

static int passed = 0;
static int failed = 0;

#define CHAIN_A "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
#define CHAIN_B "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
/* 128 lowercase hex digits, distinguishable by repeating one digit pair */
#define FP1 "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
#define FP2 "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
#define FP3 "33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"

#define NODE(ip, port, fp) "{\"ip\":\"" ip "\",\"port\":" port ",\"fp\":\"" fp "\"}"
#define GOOD_FILE \
    "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" \
    NODE("10.0.0.1", "4001", FP1) "," NODE("10.0.0.2", "4001", FP2) "]}"

static int parse(nodus_tool_net_t *t, const char *text, char *err) {
    nodus_tool_net_init(t);
    return nodus_tool_net_parse(t, text, strlen(text), err,
                                NODUS_TOOL_NET_ERR_SIZE);
}

static void expect_refused(const char *name, const char *text,
                           const char *reason_part) {
    static nodus_tool_net_t t;
    char err[NODUS_TOOL_NET_ERR_SIZE];
    TEST(name);
    int rc = parse(&t, text, err);
    CHECK(rc == -1 && !t.has_file && t.node_count == 0 &&
              strstr(err, reason_part) != NULL,
          err[0] ? err : "accepted, or no reason given");
}

static bool key_is(const nodus_key_t *k, char c) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        if (k->bytes[i] != (uint8_t)(((c >= 'a' ? c - 'a' + 10 : c - '0') << 4)
                                     | (c >= 'a' ? c - 'a' + 10 : c - '0')))
            return false;
    return true;
}

static void cfg_one(nodus_client_config_t *cfg, const char *ip, uint16_t port) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->servers[0].ip, sizeof(cfg->servers[0].ip), "%s", ip);
    cfg->servers[0].port = port;
    cfg->server_count = 1;
}

int main(void) {
    static nodus_tool_net_t t;
    char err[NODUS_TOOL_NET_ERR_SIZE];
    printf("test_tool_network\n");
    unsetenv(NODUS_TOOL_NET_ENV);

#ifndef NODUS_HAS_JSONC
    TEST("built with json-c");
    FAIL("NODUS_HAS_JSONC is not defined: the file cases cannot run");
    printf("\n%d passed, %d failed\n", passed, failed);
    return 1;
#else
    /* ── a good file ─────────────────────────────────────────────── */
    TEST("good file: chain id and both nodes");
    CHECK(parse(&t, GOOD_FILE, err) == 0 && t.has_file && t.node_count == 2 &&
              t.chain[0] == 0xaa && t.chain[1] == 0x11 &&
              strcmp(t.nodes[1].ip, "10.0.0.2") == 0 &&
              t.nodes[1].port == 4001 && key_is(&t.nodes[0].fp, '1') &&
              key_is(&t.nodes[1].fp, '2'),
          err);

    TEST("good file with surrounding whitespace");
    CHECK(parse(&t, "\n  " GOOD_FILE "  \n", err) == 0, err);

    /* ── every refusal, whole file ───────────────────────────────── */
    expect_refused("refused: not JSON", "chain_id", "not valid JSON");
    /* json-c's strict tokener reports trailing characters itself; either that
     * or the module's own trailing-characters check refuses it — both texts
     * say "JSON". */
    expect_refused("refused: trailing garbage", GOOD_FILE " x", "JSON");
    expect_refused("refused: root is an array", "[]", "not a JSON object");
    expect_refused("refused: unknown top-level key",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "4001", FP1)
                   "],\"extra\":1}", "unknown key \"extra\"");
    expect_refused("refused: unknown node key",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[{\"ip\":\"10.0.0.1\","
                   "\"port\":4001,\"fp\":\"" FP1 "\",\"name\":\"x\"}]}",
                   "unknown key \"name\"");
    expect_refused("refused: chain_id missing",
                   "{\"nodes\":[" NODE("10.0.0.1", "4001", FP1) "]}",
                   "\"chain_id\" is missing");
    expect_refused("refused: nodes missing",
                   "{\"chain_id\":\"" CHAIN_A "\"}", "\"nodes\" is missing");
    expect_refused("refused: node without fp",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[{\"ip\":\"10.0.0.1\","
                   "\"port\":4001}]}", "needs \"ip\", \"port\" and \"fp\"");
    expect_refused("refused: chain id too short",
                   "{\"chain_id\":\"aa\",\"nodes\":[" NODE("10.0.0.1", "4001", FP1) "]}",
                   "\"chain_id\" must be 64");
    expect_refused("refused: chain id all zero",
                   "{\"chain_id\":\"0000000000000000000000000000000000000000000000000000000000000000\","
                   "\"nodes\":[" NODE("10.0.0.1", "4001", FP1) "]}",
                   "\"chain_id\" must be 64");
    expect_refused("refused: chain id upper case",
                   "{\"chain_id\":\"AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11AA11\","
                   "\"nodes\":[" NODE("10.0.0.1", "4001", FP1) "]}",
                   "\"chain_id\" must be 64");
    expect_refused("refused: fp wrong length",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "4001", "1111")
                   "]}", "\"fp\" must be 128");
    expect_refused("refused: fp not hex",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "4001",
                   "zz11111111111111111111111111111111111111111111111111111111111111"
                   "1111111111111111111111111111111111111111111111111111111111111111")
                   "]}", "\"fp\" must be 128");
    expect_refused("refused: ip is a host name",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("node1.example", "4001", FP1)
                   "]}", "IPv4 literal");
    expect_refused("refused: ip with a leading zero octet",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("010.0.0.1", "4001", FP1)
                   "]}", "IPv4 literal");
    expect_refused("refused: port 0",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "0", FP1) "]}",
                   "1..65535");
    expect_refused("refused: port 65536",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "65536", FP1)
                   "]}", "1..65535");
    expect_refused("refused: port as a string",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "\"4001\"", FP1)
                   "]}", "\"port\" must be an integer");
    expect_refused("refused: duplicate ip:port",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[" NODE("10.0.0.1", "4001", FP1) ","
                   NODE("10.0.0.1", "4001", FP2) "]}", "listed twice");
    expect_refused("refused: empty node list",
                   "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[]}", "is empty");

    TEST("refused: more than the node cap");
    {
        /* NODUS_TOOL_NET_MAX_NODES + 1 distinct ip:port nodes */
        size_t cap = 64 + (size_t)(NODUS_TOOL_NET_MAX_NODES + 1) * 160;
        char *big = malloc(cap);
        size_t n = (size_t)snprintf(big, cap, "{\"chain_id\":\"" CHAIN_A "\",\"nodes\":[");
        for (int i = 0; i < NODUS_TOOL_NET_MAX_NODES + 1; i++)
            n += (size_t)snprintf(big + n, cap - n,
                                  "%s{\"ip\":\"10.0.%d.%d\",\"port\":4001,\"fp\":\"" FP1 "\"}",
                                  i ? "," : "", i / 250, i % 250 + 1);
        snprintf(big + n, cap - n, "]}");
        int rc = parse(&t, big, err);
        free(big);
        CHECK(rc == -1 && strstr(err, "more than") != NULL, err);
    }

    /* ── resolve ─────────────────────────────────────────────────── */
    nodus_key_t pin;
    uint8_t chain[NODUS_CLIENT_CHAIN_ID_SIZE];

    TEST("resolve: file gives pin and chain for exactly that ip:port");
    parse(&t, GOOD_FILE, err);
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.2", 4001, &pin, chain, err,
                                 sizeof(err)) == 0 &&
              key_is(&pin, '2') && chain[0] == 0xaa,
          err);

    TEST("resolve: ip:port not in the file, no flag -> refused");
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.3", 4001, &pin, chain, err,
                                 sizeof(err)) == -1 &&
              strstr(err, "not in the network file") != NULL,
          err);
    TEST("resolve: same ip, other port -> refused");
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.1", 4002, &pin, chain, err,
                                 sizeof(err)) == -1,
          "accepted a different port");

    TEST("resolve: --pin overrides the file's pin, even for a foreign node");
    CHECK(nodus_tool_net_set_pin_hex(&t, FP3, err, sizeof(err)) == 0 &&
              nodus_tool_net_resolve(&t, "10.0.0.3", 4001, &pin, chain, err,
                                     sizeof(err)) == 0 &&
              key_is(&pin, '3') && chain[0] == 0xaa,
          err);
    TEST("resolve: --pin overrides a node the file does list");
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.1", 4001, &pin, chain, err,
                                 sizeof(err)) == 0 && key_is(&pin, '3'),
          err);

    TEST("resolve: --chain overrides the file's chain id");
    parse(&t, GOOD_FILE, err);
    CHECK(nodus_tool_net_set_chain_hex(&t, CHAIN_B, err, sizeof(err)) == 0 &&
              nodus_tool_net_resolve(&t, "10.0.0.1", 4001, &pin, chain, err,
                                     sizeof(err)) == 0 &&
              chain[0] == 0xbb && key_is(&pin, '1'),
          err);

    TEST("chain only: flag over file; none -> refused");
    {
        uint8_t c2[NODUS_CLIENT_CHAIN_ID_SIZE];
        static nodus_tool_net_t t2;
        nodus_tool_net_init(&t2);
        int none = nodus_tool_net_chain(&t2, c2, err, sizeof(err));
        parse(&t2, GOOD_FILE, err);
        int file = nodus_tool_net_chain(&t2, c2, err, sizeof(err));
        int fa = c2[0];
        nodus_tool_net_set_chain_hex(&t2, CHAIN_B, err, sizeof(err));
        int flag = nodus_tool_net_chain(&t2, c2, err, sizeof(err));
        CHECK(none == -1 && file == 0 && fa == 0xaa && flag == 0 &&
                  c2[0] == 0xbb,
              "chain-only resolution wrong");
    }

    TEST("resolve: flags alone, no file");
    nodus_tool_net_init(&t);
    nodus_tool_net_set_pin_hex(&t, FP1, err, sizeof(err));
    nodus_tool_net_set_chain_hex(&t, CHAIN_B, err, sizeof(err));
    CHECK(nodus_tool_net_resolve(&t, "192.0.2.9", 9, &pin, chain, err,
                                 sizeof(err)) == 0 &&
              key_is(&pin, '1') && chain[0] == 0xbb,
          err);

    TEST("resolve: neither file nor flags -> refused (pin)");
    nodus_tool_net_init(&t);
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.1", 4001, &pin, chain, err,
                                 sizeof(err)) == -1 &&
              strstr(err, "no server pin") != NULL,
          err);

    TEST("resolve: --pin only, no chain anywhere -> refused (chain)");
    nodus_tool_net_set_pin_hex(&t, FP1, err, sizeof(err));
    CHECK(nodus_tool_net_resolve(&t, "10.0.0.1", 4001, &pin, chain, err,
                                 sizeof(err)) == -1 &&
              strstr(err, "no chain id") != NULL,
          err);

    TEST("flags: malformed --pin / --chain refused");
    nodus_tool_net_init(&t);
    CHECK(nodus_tool_net_set_pin_hex(&t, "abcd", err, sizeof(err)) == -1 &&
              nodus_tool_net_set_chain_hex(&t, FP1, err, sizeof(err)) == -1 &&
              !t.has_pin_flag && !t.has_chain_flag,
          "accepted a malformed flag");

    /* ── fill ────────────────────────────────────────────────────── */
    nodus_client_config_t cfg;

    TEST("fill: one server -> one pin and the chain id");
    parse(&t, GOOD_FILE, err);
    cfg_one(&cfg, "10.0.0.2", 4001);
    CHECK(nodus_tool_net_fill(&t, &cfg, err, sizeof(err)) == 0 &&
              cfg.pinned_server_fp_count == 1 && cfg.pinned_server_fps &&
              key_is(&cfg.pinned_server_fps[0], '2') &&
              cfg.has_expected_chain_id && cfg.expected_chain_id[0] == 0xaa,
          err);

    TEST("fill: a second client with another server keeps the first valid");
    {
        nodus_client_config_t cfg2;
        cfg_one(&cfg2, "10.0.0.1", 4001);
        CHECK(nodus_tool_net_fill(&t, &cfg2, err, sizeof(err)) == 0 &&
                  key_is(&cfg2.pinned_server_fps[0], '1') &&
                  key_is(&cfg.pinned_server_fps[0], '2'),
              err);
    }

    TEST("fill: refused fill leaves the config untouched");
    cfg_one(&cfg, "10.0.0.9", 4001);
    CHECK(nodus_tool_net_fill(&t, &cfg, err, sizeof(err)) == -1 &&
              cfg.pinned_server_fps == NULL && cfg.pinned_server_fp_count == 0 &&
              !cfg.has_expected_chain_id,
          "config changed on refusal");

    TEST("fill_all: servers and pins come from the file's node list");
    memset(&cfg, 0, sizeof(cfg));
    CHECK(nodus_tool_net_fill_all(&t, &cfg, err, sizeof(err)) == 0 &&
              cfg.server_count == 2 && cfg.servers[1].port == 4001 &&
              strcmp(cfg.servers[1].ip, "10.0.0.2") == 0 &&
              cfg.pinned_server_fp_count == 2 &&
              key_is(&cfg.pinned_server_fps[0], '1') &&
              key_is(&cfg.pinned_server_fps[1], '2') &&
              cfg.has_expected_chain_id,
          err);

    TEST("fill_all: no file -> refused");
    nodus_tool_net_init(&t);
    memset(&cfg, 0, sizeof(cfg));
    CHECK(nodus_tool_net_fill_all(&t, &cfg, err, sizeof(err)) == -1 &&
              cfg.server_count == 0,
          err);

    /* ── open: --network, NODUS_NETWORK, bad file wins over flags ── */
    char path[] = "/tmp/test_tool_network_XXXXXX";
    int fd = mkstemp(path);
    TEST("open: --network <file> reads a real file");
    if (fd < 0) { FAIL("mkstemp"); }
    else {
        ssize_t w = write(fd, GOOD_FILE, strlen(GOOD_FILE));
        close(fd);
        nodus_tool_net_init(&t);
        CHECK(w == (ssize_t)strlen(GOOD_FILE) &&
                  nodus_tool_net_open(&t, path, NULL, NULL, err, sizeof(err)) == 0 &&
                  t.has_file && t.node_count == 2,
              err);

        TEST("open: NODUS_NETWORK names the file when no flag does");
        setenv(NODUS_TOOL_NET_ENV, path, 1);
        nodus_tool_net_init(&t);
        CHECK(nodus_tool_net_open(&t, NULL, NULL, NULL, err, sizeof(err)) == 0 &&
                  t.has_file,
              err);
        unsetenv(NODUS_TOOL_NET_ENV);

        TEST("open: --network wins over NODUS_NETWORK");
        setenv(NODUS_TOOL_NET_ENV, "/nonexistent/none.json", 1);
        nodus_tool_net_init(&t);
        CHECK(nodus_tool_net_open(&t, path, NULL, NULL, err, sizeof(err)) == 0,
              err);
        unsetenv(NODUS_TOOL_NET_ENV);
        unlink(path);
    }

    TEST("open: a named file that is missing refuses even with both flags");
    nodus_tool_net_init(&t);
    CHECK(nodus_tool_net_open(&t, "/nonexistent/none.json", FP1, CHAIN_A, err,
                              sizeof(err)) == -1 &&
              strstr(err, "cannot open") != NULL,
          err);

    TEST("open: neither file nor flags is not an error yet (resolve refuses)");
    nodus_tool_net_init(&t);
    CHECK(nodus_tool_net_open(&t, NULL, NULL, NULL, err, sizeof(err)) == 0 &&
              !t.has_file && !t.has_pin_flag && !t.has_chain_flag,
          err);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
#endif
}
