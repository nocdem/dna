/**
 * "Update required" — the node operator's warning (design
 * docs/plans/2026-10-20-update-required-warning-design.md §1 C, package U4).
 *
 * A node on an old binary meets a chain_config param id its build does not
 * know (a newer release's hard-fork vote). nodus_chain_config_scalar_rules
 * refuses it (unchanged), and the node diverges at the block that commits
 * the vote. This file pins the plain log line that now says so, and that
 * nothing else changed:
 *
 *   1. nodus_chain_config_param_unknown — "unknown" is exactly the ids
 *      above this build's id space (CC_PARAM_MAX_ID == DNAC_CFG_PARAM_MAX_ID)
 *      that are not the genesis economic band 200-202. Ids 1..MAX are all
 *      named by this build: each is either read by the running consensus
 *      or one this build names and refuses (1, 2, 3, 16).
 *   2. nodus_chain_config_scan_unknown_params — the startup scan of
 *      chain_config_history: silent and 0 for known rows (a governed id, a
 *      retired id, the economic band), the count of DISTINCT unknown ids
 *      otherwise, the UPDATE REQUIRED text on stderr once per id, and 0 for
 *      a database without the table.
 *   3. nodus_chain_config_scalar_rules — the verdict is unchanged (-1 for
 *      an unknown id, 0 for a legal known proposal); the warning is printed
 *      for an unknown id only, and only once per id per process.
 *
 * The log is captured by swapping fd 2 onto a temp file (the nodus log
 * shim writes every QGP_LOG_* line to stderr — nodus_log_shim.c), the
 * pattern of test_witness_block_height_checked.c.
 *
 * FIXTURE: nodus_witness_t is multi-MB — calloc, never the stack.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include "dnac/dnac.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

static nodus_witness_t *setup_witness(char data_path[64]) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);
    snprintf(data_path, 64, "/tmp/test_cc_unknown_XXXXXX");
    CHECK(mkdtemp(data_path) != NULL);
    snprintf(w->data_path, sizeof(w->data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xC7, sizeof(chain_id));
    CHECK(nodus_witness_create_chain_db(w, chain_id) == 0);
    CHECK(w->db != NULL);
    return w;
}

static void teardown_witness(nodus_witness_t *w, const char *data_path) {
    if (w && w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", data_path);
    int rc = system(cmd);
    (void)rc;
}

static void insert_row(nodus_witness_t *w, int param_id, uint64_t value,
                       uint64_t effective_block) {
    uint8_t tx_hash[64];
    memset(tx_hash, (int)(param_id & 0xff), sizeof(tx_hash));
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 1, ?4, 1, 0)",
            -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_int  (st, 1, param_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective_block);
    sqlite3_bind_blob (st, 4, tx_hash, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    CHECK(rc == SQLITE_DONE);
}

/* ── stderr capture ─────────────────────────────────────────────────────
 * cap_begin swaps fd 2 onto a fresh temp file; cap_end restores it and
 * reads what was written into `buf`. Every assertion runs AFTER cap_end,
 * so a failing CHECK still reaches the real stderr. */
typedef struct { int saved; int tmpfd; int redirected; } cap_t;

static void cap_begin(cap_t *c) {
    char tmpl[] = "/tmp/test_cc_unknown_log_XXXXXX";
    c->tmpfd = mkstemp(tmpl);
    CHECK(c->tmpfd >= 0);
    CHECK(unlink(tmpl) == 0);
    fflush(stderr);
    c->saved = dup(2);
    c->redirected = (c->saved >= 0) ? dup2(c->tmpfd, 2) : -1;
}

static void cap_end(cap_t *c, char *buf, size_t cap) {
    fflush(stderr);
    int restored = (c->saved >= 0) ? dup2(c->saved, 2) : -1;
    if (c->saved >= 0) close(c->saved);
    CHECK(c->redirected >= 0);
    CHECK(restored >= 0);
    CHECK(lseek(c->tmpfd, 0, SEEK_SET) == 0);
    ssize_t n = read(c->tmpfd, buf, cap - 1);
    CHECK(n >= 0);
    buf[n] = '\0';
    close(c->tmpfd);
}

static int count_occurrences(const char *hay, const char *needle) {
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = strstr(hay, needle); p; p = strstr(p + len, needle))
        n++;
    return n;
}

int main(void) {
    char buf[16384];
    char needle[160];

    /* Test 1: the predicate over the whole uint8 id space. */
    {
        for (int id = 0; id <= 255; id++) {
            bool want = id > (int)DNAC_CFG_PARAM_MAX_ID &&
                        !(id >= (int)NODUS_CC_ECON_PARAM_MIN &&
                          id <= (int)NODUS_CC_ECON_PARAM_MAX);
            CHECK(nodus_chain_config_param_unknown(id) == want);
        }
        /* Every id in 1..MAX is named by this build: read by the running
         * consensus, or one of the ids it names and refuses (1, 2, 3 and
         * 16). A new id that is neither must be decided here, not left to
         * fall into "known" silently. */
        for (int id = 1; id <= (int)DNAC_CFG_PARAM_MAX_ID; id++) {
            bool named_refused = id == DNAC_CFG_MAX_TXS_PER_BLOCK ||
                                 id == DNAC_CFG_BLOCK_INTERVAL_SEC ||
                                 id == DNAC_CFG_INFLATION_START_BLOCK ||
                                 id == DNAC_CFG_RULESET_GEN_STORAGE;
            CHECK(dnac_cfg_param_read_by_consensus((uint8_t)id) ||
                  named_refused);
        }
        /* Out of the uint8 range (a corrupt row only): unknown. */
        CHECK(nodus_chain_config_param_unknown(-1));
        CHECK(nodus_chain_config_param_unknown(256));
        CHECK(!nodus_chain_config_param_unknown(0));
        printf("  1. param_unknown over 0..255 + edges            OK\n");
    }

    /* Test 2: startup scan — known rows are silent, unknown rows are
     * counted and printed once per id. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);

        /* an empty table */
        cap_t c;
        cap_begin(&c);
        int rc0 = nodus_chain_config_scan_unknown_params(w);
        cap_end(&c, buf, sizeof(buf));
        CHECK(rc0 == 0);
        CHECK(strstr(buf, "UPDATE REQUIRED") == NULL);

        /* known rows: a governed id (5), a retired id this build names
         * (16), the genesis economic band (200, 202) */
        insert_row(w, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 121, 0);
        insert_row(w, DNAC_CFG_RULESET_GEN_STORAGE, 1, 100);
        insert_row(w, (int)NODUS_CC_ECON_BLOCKS_PER_YEAR, 6307200, 0);
        insert_row(w, (int)NODUS_CC_ECON_EPOCH_LENGTH, 720, 0);
        cap_begin(&c);
        int rc1 = nodus_chain_config_scan_unknown_params(w);
        cap_end(&c, buf, sizeof(buf));
        CHECK(rc1 == 0);
        CHECK(strstr(buf, "UPDATE REQUIRED") == NULL);

        /* unknown rows: 24 twice (two effective heights — ONE distinct id)
         * and 40 (23 is the ML-DSA-87 precompile vote, a known id) */
        insert_row(w, 24, 7, 500);
        insert_row(w, 24, 8, 900);
        insert_row(w, 40, 1, 600);
        cap_begin(&c);
        int rc2 = nodus_chain_config_scan_unknown_params(w);
        cap_end(&c, buf, sizeof(buf));
        CHECK(rc2 == 2);
        snprintf(needle, sizeof(needle),
                 "UPDATE REQUIRED: a chain_config proposal names param 24, "
                 "which this build (nodus %s) does not know",
                 NODUS_VERSION_STRING);
        CHECK(count_occurrences(buf, needle) == 1);
        snprintf(needle, sizeof(needle),
                 "UPDATE REQUIRED: a chain_config proposal names param 40, "
                 "which this build (nodus %s) does not know",
                 NODUS_VERSION_STRING);
        CHECK(count_occurrences(buf, needle) == 1);
        CHECK(strstr(buf, "install-node.sh update") != NULL);
        CHECK(strstr(buf, "cannot follow the chain past this block") != NULL);
        CHECK(count_occurrences(buf, "UPDATE REQUIRED") == 2);

        /* a second scan still COUNTS both, but prints nothing: the
         * once-per-id-per-process limit */
        cap_begin(&c);
        int rc3 = nodus_chain_config_scan_unknown_params(w);
        cap_end(&c, buf, sizeof(buf));
        CHECK(rc3 == 2);
        CHECK(strstr(buf, "UPDATE REQUIRED") == NULL);

        /* the scan is read-only: the rows are all still there */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(w->db,
                    "SELECT COUNT(*) FROM chain_config_history", -1, &st,
                    NULL) == SQLITE_OK);
            CHECK(sqlite3_step(st) == SQLITE_ROW);
            CHECK(sqlite3_column_int(st, 0) == 7);
            sqlite3_finalize(st);
        }

        /* a database without the table (a pre-migration fixture) is
         * "nothing to report", never a fault */
        CHECK(sqlite3_exec(w->db, "DROP TABLE chain_config_history", NULL,
                           NULL, NULL) == SQLITE_OK);
        CHECK(nodus_chain_config_scan_unknown_params(w) == 0);

        teardown_witness(w, data_path);

        /* no database at all: cannot read */
        nodus_witness_t *nodb = calloc(1, sizeof(*nodb));
        CHECK(nodb != NULL);
        CHECK(nodus_chain_config_scan_unknown_params(nodb) == -1);
        CHECK(nodus_chain_config_scan_unknown_params(NULL) == -1);
        free(nodb);
        printf("  2. startup scan: silent / counted / once / no table OK\n");
    }

    /* Test 3: the refusal point — verdict unchanged, warning once. */
    {
        cap_t c;

        /* id 25: never warned in this process yet */
        cap_begin(&c);
        int r1 = nodus_chain_config_scalar_rules(25, 1, 10, 2000, 1500, 1);
        int r2 = nodus_chain_config_scalar_rules(25, 1, 10, 2000, 1500, 1);
        cap_end(&c, buf, sizeof(buf));
        CHECK(r1 == -1);
        CHECK(r2 == -1);
        snprintf(needle, sizeof(needle),
                 "UPDATE REQUIRED: a chain_config proposal names param 25, "
                 "which this build (nodus %s) does not know",
                 NODUS_VERSION_STRING);
        CHECK(count_occurrences(buf, needle) == 1);

        /* id 24: already printed by the scan above — same process, so
         * silent here; the verdict is still -1 */
        cap_begin(&c);
        int r3 = nodus_chain_config_scalar_rules(24, 1, 10, 2000, 1500, 1);
        cap_end(&c, buf, sizeof(buf));
        CHECK(r3 == -1);
        CHECK(strstr(buf, "UPDATE REQUIRED") == NULL);

        /* refused ids this build KNOWS: id 0, retired 1 / 16, not-read 2,
         * the economic band 201 — refused, and silent */
        cap_begin(&c);
        int k0 = nodus_chain_config_scalar_rules(0, 1, 10, 2000, 1500, 1);
        int k1 = nodus_chain_config_scalar_rules(1, 1, 10, 2000, 1500, 1);
        int k2 = nodus_chain_config_scalar_rules(2, 5, 10, 2000, 1500, 1);
        int k16 = nodus_chain_config_scalar_rules(16, 1, 10, 2000, 1500, 1);
        int k201 = nodus_chain_config_scalar_rules(
                       (uint8_t)NODUS_CC_ECON_DECIMAL_UNIT, 1, 10, 2000,
                       1500, 1);
        /* a legal known proposal: gas price 121 */
        int ok5 = nodus_chain_config_scalar_rules(
                      (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 121, 10,
                      2000, 1500, 1);
        cap_end(&c, buf, sizeof(buf));
        CHECK(k0 == -1);
        CHECK(k1 == -1);
        CHECK(k2 == -1);
        CHECK(k16 == -1);
        CHECK(k201 == -1);
        CHECK(ok5 == 0);
        CHECK(strstr(buf, "UPDATE REQUIRED") == NULL);
        printf("  3. scalar_rules: verdict unchanged, warned once   OK\n");
    }

    printf("test_cc_unknown_param: all OK\n");
    return 0;
}
