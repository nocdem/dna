/**
 * Nodus — UTXO state_root determinism tests
 *
 * Verifies the Phase 2 / Task 2.5 rewrite of compute_utxo_root that
 * applies the RFC 6962 leaf domain tag and reduces through the new
 * merkle_root_rfc6962 §2.1 recursion.
 *
 * Root-layout round K1 (2026-09-25, docs/plans/decisions/
 * 2026-09-25-root-layout-round.md): the leaf preimage gained
 * unlock_block u64 LE, appended last (340 bytes, no tag). Added here:
 *   - a byte-exact KAT of the 340-byte leaf, rebuilt by an INDEPENDENT
 *     path (every byte written out by hand below, hashed directly with
 *     OpenSSL SHA3-512 — not through nodus_witness_merkle_leaf_hash),
 *     and pinned to literals from
 *     shared/dnac/tests/ledger_roots_v2_accrual_oracle.py
 *     (KAT_UTXO_LEAF_UB / _UB0 / KAT_UTXO_ROOT_UB — same author, same
 *     day: SELF-CONSISTENT, not an external audit);
 *   - unlock_block moves both the leaf and the utxo_root;
 *   - a NEGATIVE stored unlock_block fails the root closed (-1, the
 *     caller's buffer untouched), never hashes a huge u64.
 * The same fixture row is pinned on the client side in
 * dnac/tests/test_merkle_verify.c (dnac_utxo_compute_leaf_hash).
 */

#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL DEFAULT x'"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "',"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT 0,"
        /* root-layout round K1: read by the leaf loader (production's
         * column, nodus_witness_db.c migration) */
        "  unlock_block INTEGER NOT NULL DEFAULT 0"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

static int insert_utxo(nodus_witness_t *w, uint8_t marker) {
    uint8_t nullifier[64];
    uint8_t token_id[64];
    uint8_t tx_hash[64];
    memset(nullifier, marker, 64);
    memset(token_id, 0, 64);
    memset(tx_hash, marker ^ 0x55, 64);

    char owner[129];
    for (int i = 0; i < 128; i++) owner[i] = "0123456789abcdef"[(marker + i) & 0xf];
    owner[128] = '\0';

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, output_index) "
        "VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)((uint64_t)marker * 1000));
    sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, marker);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_root_independent_of_insertion_order(void) {
    TEST("UTXO root independent of insertion order");

    static nodus_witness_t w1, w2;   /* S3: multi-MB — static, never stack;
                                      * setup_witness memsets both. */
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    for (uint8_t m = 0x10; m <= 0x18; m++) {
        if (insert_utxo(&w1, m) != 0) { FAIL("insert w1"); goto done; }
    }
    for (int m = 0x18; m >= 0x10; m--) {
        if (insert_utxo(&w2, (uint8_t)m) != 0) { FAIL("insert w2"); goto done; }
    }

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) != 0) { FAIL("roots differ"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

static void test_root_changes_on_amount_flip(void) {
    TEST("UTXO root changes when an amount flips by 1");

    static nodus_witness_t w1, w2;   /* S3: multi-MB — static, never stack;
                                      * setup_witness memsets both. */
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    for (uint8_t m = 0x20; m <= 0x25; m++) {
        if (insert_utxo(&w1, m) != 0) { FAIL("insert w1"); goto done; }
        if (insert_utxo(&w2, m) != 0) { FAIL("insert w2"); goto done; }
    }

    sqlite3_exec(w2.db,
        "UPDATE utxo_set SET amount = amount + 1 WHERE rowid = 3",
        NULL, NULL, NULL);

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) == 0) { FAIL("amount flip not detected"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

static void test_empty_utxo_set_root_deterministic(void) {
    TEST("empty UTXO set has deterministic non-zero root");

    static nodus_witness_t w1, w2;   /* S3: multi-MB — static, never stack;
                                      * setup_witness memsets both. */
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) != 0) { FAIL("empty roots differ"); goto done; }

    uint8_t zero[64] = {0};
    if (memcmp(r1, zero, 64) == 0) { FAIL("empty root is all zeros"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

/* ── Root-layout round K1 — the 340-byte leaf ───────────────────────── */

/* The oracle's fixture row (ledger_roots_v2_accrual_oracle.py UTXO_*):
 *   nullifier    fill(0x11)       fill(s)[i] = s + 7*i  (mod 256)
 *   owner        "ab" x 64        128 ASCII bytes
 *   amount       0x0102030405060708
 *   token_id     fill(0x22)
 *   tx_hash      fill(0x33)
 *   output_index 0x0A0B0C0D
 *   unlock_block 0x1122334455667788 (and 0 for the second vector) */
static const char *KAT_UTXO_LEAF_UB =
    "ea456d4a87981fd399ebdf635ff7707b9c8e7a3e502afb46f5880421fb1b17c6"
    "dd28a87da24519a9e396686fd92db2a06d1ed6efa83be20c01e8701f2da2c86c";
static const char *KAT_UTXO_LEAF_UB0 =
    "f8f07fe0e0ddcfc238f52d3815ab4988a07033e9e6e6bedd9824d31b7a7edddb"
    "544da24c962549fd8e6f6b99d6c7f67235f04cbde794663dd699d6f07b7448a0";
static const char *KAT_UTXO_ROOT_UB =
    "44ada91934ebac950284405f65b76dea8f080214a0cf0666b3facd2290b7111e"
    "9340958b910f1d9ffb2de2623264e25ecfc37357c39975e92b614ecfd0253e24";

#define KAT_AMOUNT        0x0102030405060708ULL
#define KAT_OUTPUT_INDEX  0x0A0B0C0Du
#define KAT_UNLOCK_BLOCK  0x1122334455667788ULL

static void kat_fill(uint8_t *dst, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static int kat_hex_eq(const uint8_t h[64], const char *hex) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4];
        got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        printf("\n    pinned: %s\n    got:    %s\n    ", hex, got);
        return 0;
    }
    return 1;
}

static void kat_row(uint8_t nullifier[64], char owner[129],
                    uint8_t token_id[64], uint8_t tx_hash[64]) {
    kat_fill(nullifier, 64, 0x11);
    for (int i = 0; i < 128; i += 2) { owner[i] = 'a'; owner[i + 1] = 'b'; }
    owner[128] = '\0';
    kat_fill(token_id, 64, 0x22);
    kat_fill(tx_hash, 64, 0x33);
}

/* SHA3-512 over a caller-built buffer — no production helper involved. */
static int sha3_512_raw(const uint8_t *p, size_t n, uint8_t out[64]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int len = 0;
    int ok = md &&
             EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1 &&
             EVP_DigestUpdate(md, p, n) == 1 &&
             EVP_DigestFinal_ex(md, out, &len) == 1 && len == 64;
    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

/* The 340-byte preimage written out BY HAND, field by field, every
 * scalar byte spelled explicitly (little-endian): this is the
 * independent path the production leaf is compared against. */
static size_t kat_preimage(uint8_t pre[340], int with_unlock) {
    uint8_t nullifier[64], token_id[64], tx_hash[64];
    char owner[129];
    kat_row(nullifier, owner, token_id, tx_hash);
    size_t off = 0;
    memcpy(pre + off, nullifier, 64);                  off += 64;   /*   0 */
    memcpy(pre + off, owner, 128);                     off += 128;  /*  64 */
    static const uint8_t amount_le[8] =
        { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
    memcpy(pre + off, amount_le, 8);                   off += 8;    /* 192 */
    memcpy(pre + off, token_id, 64);                   off += 64;   /* 200 */
    memcpy(pre + off, tx_hash, 64);                    off += 64;   /* 264 */
    static const uint8_t oi_le[4] = { 0x0D, 0x0C, 0x0B, 0x0A };
    memcpy(pre + off, oi_le, 4);                       off += 4;    /* 328 */
    static const uint8_t ub_le[8] =
        { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
    static const uint8_t ub0_le[8] = { 0 };
    memcpy(pre + off, with_unlock ? ub_le : ub0_le, 8); off += 8;   /* 332 */
    return off;                                                     /* 340 */
}

static void test_leaf_kat_340(void) {
    TEST("K1: 340-byte leaf == hand-built preimage == pin");

    uint8_t pre[340], manual[64], manual0[64];
    if (kat_preimage(pre, 1) != 340) { FAIL("preimage length"); return; }
    if (sha3_512_raw(pre, 340, manual) != 0) { FAIL("sha3 manual"); return; }
    if (kat_preimage(pre, 0) != 340) { FAIL("preimage length 0"); return; }
    if (sha3_512_raw(pre, 340, manual0) != 0) { FAIL("sha3 manual0"); return; }

    uint8_t nullifier[64], token_id[64], tx_hash[64];
    char owner[129];
    kat_row(nullifier, owner, token_id, tx_hash);
    uint8_t leaf[64], leaf0[64];
    if (nodus_witness_merkle_leaf_hash(nullifier, owner, KAT_AMOUNT,
                                       token_id, tx_hash, KAT_OUTPUT_INDEX,
                                       leaf, KAT_UNLOCK_BLOCK) != 0 ||
        nodus_witness_merkle_leaf_hash(nullifier, owner, KAT_AMOUNT,
                                       token_id, tx_hash, KAT_OUTPUT_INDEX,
                                       leaf0, 0) != 0) {
        FAIL("leaf_hash"); return;
    }
    if (memcmp(leaf, manual, 64) != 0) { FAIL("leaf != hand-built"); return; }
    if (memcmp(leaf0, manual0, 64) != 0) { FAIL("leaf0 != hand-built"); return; }
    if (!kat_hex_eq(leaf, KAT_UTXO_LEAF_UB)) { FAIL("leaf pin"); return; }
    if (!kat_hex_eq(leaf0, KAT_UTXO_LEAF_UB0)) { FAIL("leaf0 pin"); return; }
    if (memcmp(leaf, leaf0, 64) == 0) {
        FAIL("unlock_block does not reach the leaf"); return;
    }
    /* The pre-K1 332-byte digest (no unlock_block) is a DIFFERENT value
     * from both — the old and new formats never collide by length. */
    uint8_t old332[64];
    if (sha3_512_raw(pre, 332, old332) != 0) { FAIL("sha3 332"); return; }
    if (memcmp(old332, leaf0, 64) == 0) {
        FAIL("340-byte leaf with unlock 0 equals the 332-byte leaf"); return;
    }
    PASS();
}

static int insert_kat_row(nodus_witness_t *w, sqlite3_int64 unlock_block) {
    uint8_t nullifier[64], token_id[64], tx_hash[64];
    char owner[129];
    kat_row(nullifier, owner, token_id, tx_hash);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, "
        "output_index, unlock_block) VALUES (?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)KAT_AMOUNT);
    sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)KAT_OUTPUT_INDEX);
    sqlite3_bind_int64(stmt, 7, unlock_block);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_root_kat_and_unlock_moves_root(void) {
    TEST("K1: DB root pin; unlock_block moves the utxo_root");

    static nodus_witness_t w;   /* multi-MB — static, never stack */
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }
    if (insert_kat_row(&w, (sqlite3_int64)KAT_UNLOCK_BLOCK) != 0) {
        FAIL("insert"); goto done;
    }
    uint8_t r1[64], r0[64];
    if (nodus_witness_merkle_compute_utxo_root(&w, r1) != 0) {
        FAIL("root"); goto done;
    }
    if (!kat_hex_eq(r1, KAT_UTXO_ROOT_UB)) { FAIL("root pin"); goto done; }

    /* The ONLY change is the lock height: the root must move. */
    if (sqlite3_exec(w.db, "UPDATE utxo_set SET unlock_block = 0",
                     NULL, NULL, NULL) != SQLITE_OK) {
        FAIL("update"); goto done;
    }
    if (nodus_witness_merkle_compute_utxo_root(&w, r0) != 0) {
        FAIL("root0"); goto done;
    }
    if (memcmp(r1, r0, 64) == 0) {
        FAIL("unlock_block change not detected by the root"); goto done;
    }
    /* …and it moves to exactly SHA3-512(0x00 || KAT_UTXO_LEAF_UB0). */
    {
        uint8_t pre[340], leaf0[64], tagged[65], expect[64];
        kat_preimage(pre, 0);
        if (sha3_512_raw(pre, 340, leaf0) != 0) { FAIL("sha3"); goto done; }
        tagged[0] = 0x00;
        memcpy(tagged + 1, leaf0, 64);
        if (sha3_512_raw(tagged, 65, expect) != 0) { FAIL("sha3 t"); goto done; }
        if (memcmp(r0, expect, 64) != 0) { FAIL("root0 != H(0x00||leaf0)"); goto done; }
    }
    PASS();
done:
    sqlite3_close(w.db);
}

static void test_negative_unlock_fails_closed(void) {
    TEST("K1: negative unlock_block fails the root closed");

    static nodus_witness_t w;   /* multi-MB — static, never stack */
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }
    /* A healthy row first, so the bad row is not the only one: the
     * loader must refuse the WHOLE set, never skip the bad row. */
    if (insert_utxo(&w, 0x10) != 0) { FAIL("insert ok row"); goto done; }
    if (insert_kat_row(&w, -1) != 0) { FAIL("insert bad row"); goto done; }

    uint8_t root[64];
    memset(root, 0xA5, sizeof(root));
    if (nodus_witness_merkle_compute_utxo_root(&w, root) == 0) {
        FAIL("negative unlock_block produced a root"); goto done;
    }
    for (int i = 0; i < 64; i++) {
        if (root[i] != 0xA5) { FAIL("root_out written on failure"); goto done; }
    }
    /* INT64_MIN too — the most negative value must not wrap either. */
    if (sqlite3_exec(w.db,
            "UPDATE utxo_set SET unlock_block = -9223372036854775808 "
            "WHERE unlock_block = -1", NULL, NULL, NULL) != SQLITE_OK) {
        FAIL("update"); goto done;
    }
    if (nodus_witness_merkle_compute_utxo_root(&w, root) == 0) {
        FAIL("INT64_MIN unlock_block produced a root"); goto done;
    }
    /* Repairing the row restores a root — the refusal was the row's. */
    if (sqlite3_exec(w.db, "UPDATE utxo_set SET unlock_block = 5 "
                     "WHERE unlock_block < 0", NULL, NULL, NULL) != SQLITE_OK) {
        FAIL("repair"); goto done;
    }
    if (nodus_witness_merkle_compute_utxo_root(&w, root) != 0) {
        FAIL("repaired set still fails"); goto done;
    }
    PASS();
done:
    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus UTXO state_root Tests\n");
    printf("==========================================\n\n");

    test_empty_utxo_set_root_deterministic();
    test_root_independent_of_insertion_order();
    test_root_changes_on_amount_flip();
    test_leaf_kat_340();
    test_root_kat_and_unlock_moves_root();
    test_negative_unlock_fails_closed();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
