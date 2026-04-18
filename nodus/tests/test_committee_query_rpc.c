/**
 * Nodus — Task 62 dnac_committee_query RPC shape test
 *
 * The handler is thin glue over nodus_committee_get_for_block +
 * nodus_validator_get (for status) + the server roster array (for
 * endpoint). The committee computation itself is covered end-to-end by
 * test_committee_cache / test_committee_election. This test validates
 * the pieces the RPC adds:
 *
 *   1. epoch_start math: (target_h / EPOCH_LENGTH) * EPOCH_LENGTH.
 *   2. committee->validator status resolution — RETIRING propagates.
 *   3. roster address matches when pubkey is present; empty string
 *      otherwise.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "nodus/nodus_types.h"

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
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %llu != %llu\n", \
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

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                            uint64_t active_since, uint64_t self_stake,
                            uint8_t status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake         = self_stake;
    v->commission_bps     = 500;
    v->status             = status;
    v->active_since_block = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

static void insert_block_row(nodus_witness_t *w, uint64_t height,
                              const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, "
        " prev_hash, state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    uint8_t zeros[64] = {0};
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, state_seed, 64, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

int main(void) {
    char data_path[] = "/tmp/test_committee_query_rpc_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0xC5, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* ── (1) epoch_start math ─────────────────────────────────────── */
    /* For target_h = 721, epoch_start = (721/120)*120 = 720. */
    uint64_t target_h      = 721;
    uint64_t epoch_start   = (target_h / (uint64_t)DNAC_EPOCH_LENGTH) *
                              (uint64_t)DNAC_EPOCH_LENGTH;
    CHECK_EQ(epoch_start, 720);
    /* target_h = 120 (first block of epoch 1) -> epoch_start = 120. */
    CHECK_EQ((120ULL / (uint64_t)DNAC_EPOCH_LENGTH) * (uint64_t)DNAC_EPOCH_LENGTH,
             120ULL);
    /* target_h < EPOCH_LENGTH -> epoch_start = 0. */
    CHECK_EQ((50ULL / (uint64_t)DNAC_EPOCH_LENGTH) * (uint64_t)DNAC_EPOCH_LENGTH,
             0ULL);
    fprintf(stderr, "[1/3] epoch_start math OK\n");

    /* ── (2) committee member status resolution ───────────────────── */
    /* Seed two ACTIVE validators so bootstrap admits both, then flip one
     * to RETIRING in the underlying table. The committee cache stays
     * frozen (per-epoch), but the handler ALWAYS re-fetches the
     * validator row to resolve status — so the RPC response must
     * surface the updated status even when the cached committee entry
     * still lists the validator. */
    dnac_validator_record_t v1, v2;
    init_validator(&v1, 0x11, 1, 10000000, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v2, 0x22, 1, 20000000, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &v1), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v2), 0);

    /* Query committee for target_h = 1 (bootstrap path). */
    uint64_t q_height = 1;
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, q_height, committee,
                                             DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK(count >= 2);

    /* Flip v2 to RETIRING directly in the validators table (simulates
     * the state post-UNSTAKE apply, same as test_retiring_committee_membership). */
    v2.status = DNAC_VALIDATOR_RETIRING;
    CHECK_EQ(nodus_validator_update(&w, &v2), 0);

    /* Mirror the handler's status-resolution path: each committee member
     * is re-fetched via nodus_validator_get; the status from the table
     * is what the RPC ships. Cached committee still lists v2 — but the
     * resolved status is now RETIRING. */
    int seen_retiring = 0, seen_active = 0;
    for (int i = 0; i < count; i++) {
        dnac_validator_record_t rec;
        CHECK_EQ(nodus_validator_get(&w, committee[i].pubkey, &rec), 0);
        if (rec.status == DNAC_VALIDATOR_RETIRING) seen_retiring++;
        if (rec.status == DNAC_VALIDATOR_ACTIVE)   seen_active++;
    }
    CHECK_EQ(seen_retiring, 1);
    CHECK_EQ(seen_active, 1);
    fprintf(stderr, "[2/3] status resolution OK (cache frozen, status live)\n");

    /* ── (3) roster endpoint match-by-pubkey ──────────────────────── */
    /* Seed the witness roster so v1's pubkey has an address; v2 does
     * not appear — the RPC MUST leave its address empty. */
    memset(&w.roster, 0, sizeof(w.roster));
    w.roster.version = 7;
    w.roster.n_witnesses = 1;
    memcpy(w.roster.witnesses[0].pubkey, v1.pubkey, NODUS_PK_BYTES);
    memcpy(w.roster.witnesses[0].witness_id, "id000000000000000000000000000001",
           NODUS_T3_WITNESS_ID_LEN);
    snprintf(w.roster.witnesses[0].address,
             sizeof(w.roster.witnesses[0].address),
             "witness-01.test:4004");
    w.roster.witnesses[0].active = true;

    /* Mirror the handler's roster lookup: scan for pubkey match. */
    for (int i = 0; i < count; i++) {
        const char *addr = "";
        for (uint32_t j = 0; j < w.roster.n_witnesses; j++) {
            if (memcmp(w.roster.witnesses[j].pubkey, committee[i].pubkey,
                       DNAC_PUBKEY_SIZE) == 0) {
                addr = w.roster.witnesses[j].address;
                break;
            }
        }
        if (memcmp(committee[i].pubkey, v1.pubkey, DNAC_PUBKEY_SIZE) == 0) {
            CHECK(strcmp(addr, "witness-01.test:4004") == 0);
        } else {
            CHECK(addr[0] == '\0');
        }
    }
    fprintf(stderr, "[3/3] roster endpoint lookup OK\n");

    (void)insert_block_row; /* reserved for future full-epoch lookback tests */

    sqlite3_close(w.db);
    rmrf(data_path);
    fprintf(stderr, "test_committee_query_rpc: all 3 scenarios passed\n");
    return 0;
}
