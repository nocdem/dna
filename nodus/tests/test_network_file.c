/**
 * test_network_file — P2P-PORT F6: the published network file.
 *
 * Decision docs/plans/decisions/2026-09-26-witness-port-session.md
 * ("Ağ config dosyası (pin + seed'ler)", "Pin'i tören yazar"); design
 * docs/plans/2026-09-26-p2p-port-design.md §4. Subject: nodus_server.c
 * nodus_network_file_load / _apply / _write_pin and
 * nodus_server_check_chain_pin (nodus_server.h).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *  1. load: a valid file yields its pin and its peers in file order; an
 *     empty or absent pin is "no pin"; every malformed shape (not JSON,
 *     not an object, an unknown key, a pin that is not 0/64 hex digits,
 *     peers not an array of "id@ip:port" with a valid ID and an IP
 *     literal, a duplicate peer, a missing file) is REFUSED as a whole.
 *  2. apply: the peers are merged into the p2p persistent peers without
 *     duplicating one already there; a pin arms the joiner AND the start
 *     check; a pin that disagrees with --v2-genesis-pin is refused; no
 *     pin leaves a given --v2-genesis-pin exactly as it was.
 *  3. write_pin (pin-auto): an EMPTY pin is filled, every other key kept
 *     in its order; the SAME pin → no write (file bytes unchanged); a
 *     DIFFERENT pin → refused, file bytes unchanged; a malformed or
 *     missing file → refused; no temp file is left behind.
 *  4. check_chain_pin: no chain database (or no directory) passes; a
 *     real derived version-3 chain passes against its own id and is
 *     refused against any other; only the file the witness scan would
 *     open (the smallest canonical witness_<32 hex>.db) is judged — a
 *     non-canonical name is ignored, an unreadable canonical one that
 *     sorts first is refused.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: a build with json-c (NODUS_HAS_JSONC — CMakeLists.txt
 * adds this test only then). Environment: a writable /tmp.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success (its /tmp directories are removed); a failed CHECK
 * returns at once and leaves its /tmp/test_network_file_* directory.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The IDs used are syntactically valid hex, not keys of running
 *     nodes: this proves the file's validation, not that a peer dials.
 *  2. Case 4's chain is the shared test fixture's (v2_genesis_fixture.h),
 *     derived by the production builder and opened by the production
 *     gate — but the start check is exercised directly, not through a
 *     nodus_server_init.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "server/nodus_server.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;
static char g_dir[128];

#define ID_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define ID_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define PEER_A ID_A "@127.0.0.1:14004"
#define PEER_B ID_B "@10.0.0.2:4004"
#define PIN1 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define PIN2 "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

static void rm_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(text);
    int rc = (fwrite(text, 1, n, f) == n) ? 0 : -1;
    if (fclose(f) != 0) rc = -1;
    return rc;
}

/* Whole file into a heap buffer (NUL-terminated). NULL on failure. */
static char *read_text(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = calloc(1, 65536);
    if (buf) {
        size_t n = fread(buf, 1, 65535, f);
        buf[n] = '\0';
    }
    fclose(f);
    return buf;
}

static void hex_to32(const char *hex, uint8_t out[32]) {
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* Count directory entries whose name contains ".tmp." (leftover temps). */
static int count_tmp(const char *dir) {
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL)
        if (strstr(e->d_name, ".tmp.")) n++;
    closedir(d);
    return n;
}

/* ══ 1. load ══════════════════════════════════════════════════════════ */

static int t_load(void) {
    char p[256];
    nodus_network_file_t nf;
    uint8_t pin1[32];

    hex_to32(PIN1, pin1);
    snprintf(p, sizeof(p), "%s/net.json", g_dir);

    CHECK(write_text(p, "{ \"v2_genesis_pin\": \"" PIN1 "\", "
                        "\"persistent_peers\": [\"" PEER_A "\", \""
                        PEER_B "\"] }") == 0, "write valid");
    CHECK(nodus_network_file_load(p, &nf) == 0, "a valid file loads");
    CHECK(nf.has_pin && memcmp(nf.pin, pin1, 32) == 0, "its pin");
    CHECK(nf.n_peers == 2 && strcmp(nf.peers[0], PEER_A) == 0 &&
          strcmp(nf.peers[1], PEER_B) == 0, "its peers, in file order");

    /* upper-case hex is the same pin */
    {
        char up[65];
        for (int i = 0; i < 64; i++) {
            char c = PIN1[i];
            up[i] = (c >= 'a' && c <= 'f') ? (char)(c - 32) : c;
        }
        up[64] = '\0';
        char text[256];
        snprintf(text, sizeof(text), "{ \"v2_genesis_pin\": \"%s\" }", up);
        CHECK(write_text(p, text) == 0, "write upper");
        CHECK(nodus_network_file_load(p, &nf) == 0 && nf.has_pin &&
              memcmp(nf.pin, pin1, 32) == 0, "upper-case hex pin");
    }

    CHECK(write_text(p, "{ \"v2_genesis_pin\": \"\", "
                        "\"persistent_peers\": [\"" PEER_A "\"] }") == 0,
          "write empty pin");
    CHECK(nodus_network_file_load(p, &nf) == 0 && !nf.has_pin &&
          nf.n_peers == 1, "an EMPTY pin is no pin");

    CHECK(write_text(p, "{ }") == 0, "write empty object");
    CHECK(nodus_network_file_load(p, &nf) == 0 && !nf.has_pin &&
          nf.n_peers == 0, "absent keys: no pin, no peers");

    static const char *bad[] = {
        "{",                                                   /* not JSON  */
        "[ \"" PEER_A "\" ]",                                  /* not object*/
        "{ \"v2_genesis_pinn\": \"" PIN1 "\" }",               /* typo key  */
        "{ \"seed_nodes\": [] }",                              /* other key */
        "{ \"v2_genesis_pin\": \"0123\" }",                    /* short pin */
        "{ \"v2_genesis_pin\": \"" PIN1 "00\" }",              /* long pin  */
        "{ \"v2_genesis_pin\": \"g123456789abcdef0123456789abcdef"
          "0123456789abcdef0123456789abcdef\" }",              /* non-hex   */
        "{ \"v2_genesis_pin\": 5 }",                           /* not string*/
        "{ \"v2_genesis_pin\": null }",                        /* null      */
        "{ \"persistent_peers\": \"" PEER_A "\" }",            /* not array */
        "{ \"persistent_peers\": [ 5 ] }",                     /* not string*/
        "{ \"persistent_peers\": [ \"127.0.0.1:4004\" ] }",    /* no ID     */
        "{ \"persistent_peers\": [ \"" ID_A "@localhost:4004\" ] }", /* DNS */
        "{ \"persistent_peers\": [ \"abcd@127.0.0.1:4004\" ] }", /* bad ID  */
        "{ \"persistent_peers\": [ \"" ID_A "@127.0.0.1\" ] }",  /* no port */
        "{ \"persistent_peers\": [ \"\" ] }",                  /* empty     */
        "{ \"persistent_peers\": [ \"" PEER_A "\", \"" PEER_A "\" ] }",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(write_text(p, bad[i]) == 0, "write malformed");
        memset(&nf, 0x5A, sizeof(nf));
        if (nodus_network_file_load(p, &nf) != -1) {
            fprintf(stderr, "  accepted: %s\n", bad[i]);
            CHECK(0, "a malformed file is refused");
        }
        CHECK(!nf.has_pin && nf.n_peers == 0,
              "a refused file leaves nothing behind in the result");
    }

    /* more peers than the list holds */
    {
        size_t cap = 256 + (size_t)(NODUS_P2P_MAX_PEER_LIST + 1) * 96;
        char *text = calloc(1, cap);
        CHECK(text != NULL, "alloc");
        size_t off = (size_t)snprintf(text, cap, "{ \"persistent_peers\": [");
        for (int i = 0; i <= NODUS_P2P_MAX_PEER_LIST; i++)
            off += (size_t)snprintf(text + off, cap - off, "%s\"" ID_A
                                    "@127.0.0.1:%d\"", i ? ", " : " ",
                                    20000 + i);
        snprintf(text + off, cap - off, " ] }");
        int wr = write_text(p, text);
        free(text);
        CHECK(wr == 0, "write oversized");
        CHECK(nodus_network_file_load(p, &nf) == -1,
              "more than NODUS_P2P_MAX_PEER_LIST peers is refused");
    }

    char missing[256];
    snprintf(missing, sizeof(missing), "%s/nope.json", g_dir);
    CHECK(nodus_network_file_load(missing, &nf) == -1,
          "a named but missing file is refused");
    return 0;
}

/* ══ 2. apply ═════════════════════════════════════════════════════════ */

static int t_apply(void) {
    nodus_network_file_t nf;
    nodus_server_config_t *cfg = calloc(1, sizeof(*cfg));
    uint8_t pin1[32], pin2[32];

    CHECK(cfg != NULL, "alloc");
    hex_to32(PIN1, pin1);
    hex_to32(PIN2, pin2);

    /* peers merged, the one already present (from -s id@) not doubled */
    memset(&nf, 0, sizeof(nf));
    nf.n_peers = 2;
    snprintf(nf.peers[0], sizeof(nf.peers[0]), "%s", PEER_A);
    snprintf(nf.peers[1], sizeof(nf.peers[1]), "%s", PEER_B);
    nodus_p2p_config_default(&cfg->p2p);
    CHECK(nodus_p2p_config_add_persistent(&cfg->p2p, PEER_A) == 0, "seed");
    CHECK(nodus_network_file_apply(&nf, cfg) == 0, "apply, no pin");
    CHECK(cfg->p2p.n_persistent_peers == 2 &&
          strcmp(cfg->p2p.persistent_peers[0], PEER_A) == 0 &&
          strcmp(cfg->p2p.persistent_peers[1], PEER_B) == 0,
          "merged: the present entry kept once, the new one appended");
    CHECK(!cfg->has_v2_genesis_pin && !cfg->has_network_pin,
          "no file pin: neither the joiner nor the start check is armed");

    /* a CLI pin alone is left as it was when the file has none */
    memset(cfg, 0, sizeof(*cfg));
    nodus_p2p_config_default(&cfg->p2p);
    cfg->has_v2_genesis_pin = true;
    memcpy(cfg->v2_genesis_pin, pin2, 32);
    CHECK(nodus_network_file_apply(&nf, cfg) == 0, "apply over a CLI pin");
    CHECK(cfg->has_v2_genesis_pin &&
          memcmp(cfg->v2_genesis_pin, pin2, 32) == 0 &&
          !cfg->has_network_pin,
          "--v2-genesis-pin alone keeps its old meaning");

    /* a file pin arms both */
    memset(cfg, 0, sizeof(*cfg));
    nodus_p2p_config_default(&cfg->p2p);
    nf.has_pin = true;
    memcpy(nf.pin, pin1, 32);
    CHECK(nodus_network_file_apply(&nf, cfg) == 0, "apply with a pin");
    CHECK(cfg->has_v2_genesis_pin && cfg->has_network_pin &&
          memcmp(cfg->v2_genesis_pin, pin1, 32) == 0 &&
          memcmp(cfg->network_pin, pin1, 32) == 0,
          "the file pin arms the joiner and the start check");

    /* agreeing CLI pin: accepted; disagreeing: refused */
    memset(cfg, 0, sizeof(*cfg));
    nodus_p2p_config_default(&cfg->p2p);
    cfg->has_v2_genesis_pin = true;
    memcpy(cfg->v2_genesis_pin, pin1, 32);
    CHECK(nodus_network_file_apply(&nf, cfg) == 0 && cfg->has_network_pin,
          "the same pin on both sides is accepted");
    memset(cfg, 0, sizeof(*cfg));
    nodus_p2p_config_default(&cfg->p2p);
    cfg->has_v2_genesis_pin = true;
    memcpy(cfg->v2_genesis_pin, pin2, 32);
    CHECK(nodus_network_file_apply(&nf, cfg) == -1,
          "--v2-genesis-pin and the file's pin must agree");

    /* a full list refuses rather than drops */
    memset(cfg, 0, sizeof(*cfg));
    nodus_p2p_config_default(&cfg->p2p);
    for (int i = 0; i < NODUS_P2P_MAX_PEER_LIST; i++) {
        char s[CMT_P2P_NETADDR_STR_MAX];
        snprintf(s, sizeof(s), ID_A "@127.0.0.1:%d", 30000 + i);
        CHECK(nodus_p2p_config_add_persistent(&cfg->p2p, s) == 0, "fill");
    }
    nf.has_pin = false;
    CHECK(nodus_network_file_apply(&nf, cfg) == -1,
          "a merge that does not fit is refused, not silently dropped");

    free(cfg);
    return 0;
}

/* ══ 3. write_pin (pin-auto) ══════════════════════════════════════════ */

static int t_write_pin(void) {
    char p[256];
    nodus_network_file_t nf;
    uint8_t pin1[32], pin2[32];
    char *before, *after;

    hex_to32(PIN1, pin1);
    hex_to32(PIN2, pin2);
    snprintf(p, sizeof(p), "%s/pinauto.json", g_dir);

    /* empty pin, seeds first: filled in place, seeds kept, key order kept */
    CHECK(write_text(p, "{ \"persistent_peers\": [\"" PEER_A "\", \""
                        PEER_B "\"], \"v2_genesis_pin\": \"\" }") == 0,
          "write");
    CHECK(nodus_network_file_write_pin(p, pin1) == 0, "an empty pin is "
          "written");
    CHECK(nodus_network_file_load(p, &nf) == 0 && nf.has_pin &&
          memcmp(nf.pin, pin1, 32) == 0, "the written pin reads back");
    CHECK(nf.n_peers == 2 && strcmp(nf.peers[0], PEER_A) == 0 &&
          strcmp(nf.peers[1], PEER_B) == 0, "the seeds are kept, in order");
    before = read_text(p);
    CHECK(before != NULL, "read");
    {
        const char *kp = strstr(before, "\"persistent_peers\"");
        const char *kn = strstr(before, "\"v2_genesis_pin\"");
        int order_ok = kp && kn && kp < kn;
        int lower_ok = strstr(before, PIN1) != NULL;
        if (!order_ok || !lower_ok) free(before);
        CHECK(order_ok, "the keys keep their order");
        CHECK(lower_ok, "the pin is written as lower-case hex");
    }
    CHECK(count_tmp(g_dir) == 0, "no temp file left behind");

    /* the SAME pin: nothing written */
    CHECK(nodus_network_file_write_pin(p, pin1) == 1,
          "the same pin again is a no-op (1)");
    after = read_text(p);
    {
        int same = after && strcmp(before, after) == 0;
        free(after);
        if (!same) free(before);
        CHECK(same, "the no-op leaves the file byte-identical");
    }

    /* a DIFFERENT pin: refused, never overwritten */
    CHECK(nodus_network_file_write_pin(p, pin2) == -1,
          "a different pin is refused");
    after = read_text(p);
    {
        int same = after && strcmp(before, after) == 0;
        free(after);
        free(before);
        CHECK(same, "the refusal leaves the file byte-identical");
    }

    /* no pin key at all: appended */
    CHECK(write_text(p, "{ \"persistent_peers\": [\"" PEER_A "\"] }") == 0,
          "write");
    CHECK(nodus_network_file_write_pin(p, pin2) == 0, "an absent pin is "
          "written");
    CHECK(nodus_network_file_load(p, &nf) == 0 && nf.has_pin &&
          memcmp(nf.pin, pin2, 32) == 0 && nf.n_peers == 1,
          "the appended pin reads back with the seed");

    /* malformed: refused, unchanged */
    CHECK(write_text(p, "{ \"v2_genesis_pinn\": \"\" }") == 0, "write");
    before = read_text(p);
    CHECK(before != NULL, "read");
    {
        int wr = nodus_network_file_write_pin(p, pin1);
        if (wr != -1) free(before);
        CHECK(wr == -1, "a malformed file is never written into");
    }
    after = read_text(p);
    {
        int same = after && strcmp(before, after) == 0;
        free(after);
        free(before);
        CHECK(same, "the malformed file is left byte-identical");
    }

    {
        char missing[256];
        snprintf(missing, sizeof(missing), "%s/nope.json", g_dir);
        CHECK(nodus_network_file_write_pin(missing, pin1) == -1,
              "a missing file is refused (the ceremony does not invent one)");
        struct stat st;
        CHECK(stat(missing, &st) != 0, "and none is created");
    }
    CHECK(count_tmp(g_dir) == 0, "no temp file left behind");
    return 0;
}

/* ══ 4. check_chain_pin ═══════════════════════════════════════════════ */

static int t_check_chain_pin(void) {
    uint8_t pin2[32];
    char sub[256], junk[300];
    v2x_chain_t c;

    hex_to32(PIN2, pin2);

    snprintf(sub, sizeof(sub), "%s/empty", g_dir);
    CHECK(mkdir(sub, 0700) == 0, "mkdir");
    CHECK(nodus_server_check_chain_pin(sub, pin2) == 0,
          "no chain database: the pin is a joiner's, nothing to compare");
    snprintf(sub, sizeof(sub), "%s/absent", g_dir);
    CHECK(nodus_server_check_chain_pin(sub, pin2) == 0,
          "no data directory: no chain");

    CHECK(v2x_chain_open(&c, "netfile", 0x21) == 0,
          "a real version-3 chain (production builder + open gate)");
    /* release the fixture's handle; the check opens its own */
    sqlite3_close(c.w->db);
    c.w->db = NULL;
    {
        int eq  = nodus_server_check_chain_pin(c.dir, c.chain32);
        int neq = nodus_server_check_chain_pin(c.dir, pin2);
        uint8_t id[32];
        int rd = -1;
        DIR *d = opendir(c.dir);
        struct dirent *e;
        while (d && (e = readdir(d)) != NULL) {
            size_t l = strlen(e->d_name);
            if (strncmp(e->d_name, "witness_", 8) == 0 && l > 11 &&
                strcmp(e->d_name + l - 3, ".db") == 0) {
                char dp[400];
                snprintf(dp, sizeof(dp), "%s/%s", c.dir, e->d_name);
                rd = nodus_server_read_chain_id(dp, id);
                break;
            }
        }
        if (d) closedir(d);
        int rd_ok = (rd == 0 && memcmp(id, c.chain32, 32) == 0);
        /* a NON-canonical name is never opened by the witness scan —
         * and is not judged by the start check either */
        snprintf(junk, sizeof(junk), "%s/witness_00ff.db", c.dir);
        int wj1 = write_text(junk, "not a database");
        int ign = nodus_server_check_chain_pin(c.dir, c.chain32);
        /* a CANONICAL name that sorts first IS the file the scan opens
         * (lexicographically smallest) — unreadable, so refused */
        snprintf(junk, sizeof(junk),
                 "%s/witness_00000000000000000000000000000000.db", c.dir);
        int wj2 = write_text(junk, "not a database");
        int bad = nodus_server_check_chain_pin(c.dir, c.chain32);
        v2x_chain_close(&c);
        CHECK(rd_ok, "nodus_server_read_chain_id reads the derived id");
        CHECK(eq == 0, "the chain's own id passes");
        CHECK(neq == -1, "a different pin refuses the start");
        CHECK(wj1 == 0 && wj2 == 0, "write junk");
        CHECK(ign == 0, "a non-canonical witness_*.db (not the scan's) is "
              "ignored, as the witness scan ignores it");
        CHECK(bad == -1, "the file the scan WOULD open (smallest canonical "
              "name) is unreadable: the start is refused");
    }
    return 0;
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_network_file_XXXXXX");
    if (!mkdtemp(g_dir)) {
        fprintf(stderr, "test_network_file: mkdtemp failed\n");
        return 1;
    }
    struct { const char *name; int (*fn)(void); } cases[] = {
        { "load",            t_load },
        { "apply",           t_apply },
        { "write_pin",       t_write_pin },
        { "check_chain_pin", t_check_chain_pin },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-18s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_network_file: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    if (failed == 0) rm_dir(g_dir);
    return failed ? 1 : 0;
}
