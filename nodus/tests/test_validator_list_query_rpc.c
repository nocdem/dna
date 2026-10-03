/**
 * Nodus — Task 63 dnac_validator_list_query RPC helper test
 *
 * Exercises nodus_validator_list_paged() — the backing query for
 * dnac_validator_list_query. The RPC handler itself is thin CBOR glue
 * around this helper.
 *
 * Scenarios:
 *   1. Empty DB -> count=0, total=0.
 *   2. filter_status = -1 (all) lists every row regardless of status.
 *   3. filter_status = ACTIVE lists only ACTIVE rows; total excludes
 *      non-ACTIVE rows.
 *   4. Pagination: limit=2 offset=0 and offset=2 return disjoint rows
 *      that together cover the full filter set.
 *   5. Ordering: (self_stake + external_delegated) DESC, pubkey ASC.
 *   6. The reply's per-entry "dlg" (delegator count) source:
 *      nodus_delegation_count_by_validator — the call the handler makes
 *      for every listed validator — answers the number of seeded
 *      delegation rows (N for one validator, 0 for one without any, a
 *      known 0 rather than an error), drops by one on a delete, and
 *      equals the chain's own cap read: the same
 *      `SELECT COUNT(*) FROM delegations WHERE validator_hash = ?` keyed
 *      by SHA3-512(NODUS_TREE_TAG_DELEGATION || validator_pubkey), the
 *      key rtn_delegate_read_plan builds for rtn_sys_delegcnt_fetch
 *      (nodus_witness_rt_native.c), computed here independently. No DB
 *      connection is a failure (-1), never a 0.
 *
 * Requires: a default build, no environment. Leaves behind: nothing (the
 * /tmp directory is removed; an aborting CHECK leaves it).
 * How it can lie: scenario 6 pins the count SOURCE and its key
 * derivation, not the handler's CBOR encoder (handle_dnac_validator_list
 * _query is static and only sends) — the reply's decode side is pinned
 * by tests/test_client_validator_list.c. The delegation rows are
 * inserted by nodus_delegation_insert, not by an applied DELEGATE.
 * Nothing here was RUN by the author of scenario 6 (BUILDER: compile
 * only).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "nodus/nodus_types.h"   /* NODUS_TREE_TAG_DELEGATION */

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

static void seed_val(nodus_witness_t *w, uint8_t pub_fill,
                      uint64_t self_stake, uint64_t external_delegated,
                      uint8_t status) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memset(v.pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v.self_stake         = self_stake;
    v.total_delegated    = external_delegated;
    v.external_delegated = external_delegated;
    v.commission_bps     = 500;
    v.status             = status;
    v.active_since_block = 1;
    uint8_t fp_raw[64];
    qgp_sha3_512(v.pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v.unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v.unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v.unstake_destination_fp[128] = '\0';
    memset(v.unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_validator_insert(w, &v), 0);
}

static void seed_deleg(nodus_witness_t *w, uint8_t delegator_fill,
                        uint8_t validator_fill) {
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    memset(d.delegator_pubkey, delegator_fill, DNAC_PUBKEY_SIZE);
    memset(d.validator_pubkey, validator_fill, DNAC_PUBKEY_SIZE);
    d.amount             = 100;
    d.delegated_at_block = 1;
    CHECK_EQ(nodus_delegation_insert(w, &d), 0);
}

/* The chain's cap read, computed independently of delegation.c: the key
 * rtn_delegate_read_plan builds (rtn_tag_key = SHA3-512(tag || pubkey))
 * and the statement rtn_sys_delegcnt_fetch runs. */
static int chain_side_count(nodus_witness_t *w, uint8_t validator_fill) {
    uint8_t pre[1 + DNAC_PUBKEY_SIZE];
    pre[0] = (uint8_t)NODUS_TREE_TAG_DELEGATION;
    memset(pre + 1, validator_fill, DNAC_PUBKEY_SIZE);
    uint8_t key[64];
    CHECK_EQ(qgp_sha3_512(pre, sizeof(pre), key), 0);
    sqlite3_stmt *st = NULL;
    CHECK_EQ(sqlite3_prepare_v2(w->db,
                 "SELECT COUNT(*) FROM delegations WHERE validator_hash = ?1",
                 -1, &st, NULL), SQLITE_OK);
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    CHECK_EQ(sqlite3_step(st), SQLITE_ROW);
    int n = (int)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int main(void) {
    char data_path[] = "/tmp/test_validator_list_rpc_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xC6, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* Scratch list — cap well above any seeded count. */
    const int cap = 16;
    dnac_validator_record_t *out = calloc((size_t)cap, sizeof(*out));
    CHECK(out != NULL);

    /* ── (1) Empty DB ──────────────────────────────────────────────── */
    int count = -1, total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, /*filter=*/-1,
                                          /*offset=*/0, cap,
                                          out, &count, &total), 0);
    CHECK_EQ(count, 0);
    CHECK_EQ(total, 0);
    fprintf(stderr, "[1/6] empty DB OK\n");

    /* Seed 4 rows — 3 ACTIVE, 1 RETIRING. Stakes designed so the DESC
     * ordering is deterministic: 0x44 > 0x33 > 0x22 > 0x11 by stake. */
    seed_val(&w, 0x11, 1000, 0, DNAC_VALIDATOR_ACTIVE);
    seed_val(&w, 0x22, 2000, 0, DNAC_VALIDATOR_ACTIVE);
    seed_val(&w, 0x33, 3000, 0, DNAC_VALIDATOR_RETIRING);
    seed_val(&w, 0x44, 4000, 0, DNAC_VALIDATOR_ACTIVE);

    /* ── (2) filter=-1 returns all 4 ──────────────────────────────── */
    count = -1; total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, -1, 0, cap, out, &count, &total), 0);
    CHECK_EQ(count, 4);
    CHECK_EQ(total, 4);
    /* Highest stake first: 0x44 (4000) then 0x33 (3000). */
    CHECK_EQ(out[0].self_stake, 4000);
    CHECK_EQ(out[0].pubkey[0], 0x44);
    CHECK_EQ(out[1].self_stake, 3000);
    CHECK_EQ(out[1].pubkey[0], 0x33);
    CHECK_EQ(out[2].self_stake, 2000);
    CHECK_EQ(out[3].self_stake, 1000);
    fprintf(stderr, "[2/6] filter=-1 returns all 4 OK\n");

    /* ── (3) filter=ACTIVE returns 3 rows ─────────────────────────── */
    count = -1; total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, DNAC_VALIDATOR_ACTIVE, 0, cap,
                                          out, &count, &total), 0);
    CHECK_EQ(count, 3);
    CHECK_EQ(total, 3);
    /* ACTIVE ordering: 0x44, 0x22, 0x11 (0x33 is RETIRING, excluded). */
    CHECK_EQ(out[0].pubkey[0], 0x44);
    CHECK_EQ(out[1].pubkey[0], 0x22);
    CHECK_EQ(out[2].pubkey[0], 0x11);
    fprintf(stderr, "[3/6] filter=ACTIVE filters correctly OK\n");

    /* ── (4) Pagination: limit=2 offset=0 then offset=2 ──────────── */
    count = -1; total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, -1, 0, 2, out, &count, &total), 0);
    CHECK_EQ(count, 2);
    CHECK_EQ(total, 4);
    CHECK_EQ(out[0].pubkey[0], 0x44);
    CHECK_EQ(out[1].pubkey[0], 0x33);

    count = -1; total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, -1, 2, 2, out, &count, &total), 0);
    CHECK_EQ(count, 2);
    CHECK_EQ(total, 4);
    CHECK_EQ(out[0].pubkey[0], 0x22);
    CHECK_EQ(out[1].pubkey[0], 0x11);
    fprintf(stderr, "[4/6] pagination (limit+offset) OK\n");

    /* ── (5) pubkey-tiebreak: same stake -> ASC by pubkey ─────────── */
    seed_val(&w, 0x55, 4000, 0, DNAC_VALIDATOR_ACTIVE);  /* ties 0x44 */
    count = -1; total = -1;
    CHECK_EQ(nodus_validator_list_paged(&w, DNAC_VALIDATOR_ACTIVE,
                                          0, cap, out, &count, &total), 0);
    CHECK_EQ(count, 4);
    CHECK_EQ(total, 4);
    /* 0x44 < 0x55 byte-wise -> 0x44 first in the tied pair. */
    CHECK_EQ(out[0].pubkey[0], 0x44);
    CHECK_EQ(out[1].pubkey[0], 0x55);
    fprintf(stderr, "[5/6] pubkey tiebreak ASC OK\n");

    /* ── (6) the "dlg" source: delegator count per listed validator ── */
    {
        /* 0x44 gets 37 delegators (delegator keys 0x80..0xA4), 0x55
         * gets 1, the others none. */
        for (int i = 0; i < 37; i++) seed_deleg(&w, (uint8_t)(0x80 + i), 0x44);
        seed_deleg(&w, 0x80, 0x55);   /* same delegator, other validator */

        count = -1; total = -1;
        CHECK_EQ(nodus_validator_list_paged(&w, -1, 0, cap, out,
                                              &count, &total), 0);
        CHECK_EQ(count, 5);
        int seen = 0;
        for (int i = 0; i < count; i++) {
            int n = -1;
            CHECK_EQ(nodus_delegation_count_by_validator(&w, out[i].pubkey,
                                                         &n), 0);
            int want = out[i].pubkey[0] == 0x44 ? 37
                     : out[i].pubkey[0] == 0x55 ? 1 : 0;
            CHECK_EQ(n, want);
            CHECK_EQ(n, chain_side_count(&w, out[i].pubkey[0]));
            seen++;
        }
        CHECK_EQ(seen, 5);

        /* a delete moves the count by exactly one */
        uint8_t dpk[DNAC_PUBKEY_SIZE], vpk[DNAC_PUBKEY_SIZE];
        memset(dpk, 0x80, sizeof(dpk));
        memset(vpk, 0x44, sizeof(vpk));
        CHECK_EQ(nodus_delegation_delete(&w, dpk, vpk), 0);
        int n = -1;
        CHECK_EQ(nodus_delegation_count_by_validator(&w, vpk, &n), 0);
        CHECK_EQ(n, 36);
        CHECK_EQ(n, chain_side_count(&w, 0x44));

        /* the 2048 cap is the constant the client shows N against */
        CHECK_EQ(NODUS_MAX_DELEGATORS_PER_VALIDATOR, 2048);
    }
    fprintf(stderr, "[6/6] delegator count per validator OK\n");

    /* No DB connection (w->db NULL — the helper's own guard, not a failed
     * SQL step) is a failure, never a 0, and leaves *count_out untouched
     * (the handler turns -1 into an error reply). */
    sqlite3_close(w.db);
    w.db = NULL;
    {
        uint8_t vpk[DNAC_PUBKEY_SIZE];
        memset(vpk, 0x44, sizeof(vpk));
        int n = 12345;
        CHECK_EQ(nodus_delegation_count_by_validator(&w, vpk, &n), -1);
        CHECK_EQ(n, 12345);
    }

    free(out);
    rmrf(data_path);
    fprintf(stderr, "test_validator_list_query_rpc: all 6 scenarios passed\n");
    return 0;
}
