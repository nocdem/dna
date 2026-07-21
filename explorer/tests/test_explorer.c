/**
 * DNA Explorer — exp_db unit tests
 *
 * Macro style follows nodus/tests/test_storage.c (TEST/PASS/FAIL + counters).
 * Every test opens exp_db on ":memory:".
 */

#include "exp_db.h"
#include "exp_extract.h"
#include "exp_chain.h"
#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "crypto/hash/qgp_sha3.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/* Cursor sentinel for "start from the most recent row" — see exp_db.h:
 * genesis is height 0, so 0 cannot mean "unbounded", and cursors are bound
 * to sqlite as signed 64-bit, so INT64_MAX (not UINT64_MAX) is the usable
 * ceiling. */
#define EXP_CURSOR_TOP INT64_MAX

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void fill(uint8_t *buf, size_t n, uint8_t v) {
    memset(buf, v, n);
}

/* fix round 1: exp_extract_tx now rejects owner_fingerprint blobs that
 * aren't exactly 128 lowercase-hex chars + NUL (see exp_extract.c). Build
 * valid-format test fingerprints (128 repeats of one hex char + NUL) rather
 * than hand-typing a 128-char literal, which is easy to miscount. `fp_out`
 * must have room for 129 bytes. */
static void set_test_fp(char *fp_out, char hexchar) {
    memset(fp_out, hexchar, 128);
    fp_out[128] = '\0';
}

/* ── t1: open creates schema; meta roundtrip u64 + blob ────────────── */

static void test_meta_roundtrip(void) {
    TEST("meta u64 + blob roundtrip");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0 || !db) {
        FAIL("exp_db_open failed");
        return;
    }

    uint64_t val = 0;
    if (exp_db_get_meta_u64(db, "last_indexed_seq", &val) != -1) {
        FAIL("expected -1 for missing key");
        exp_db_close(db);
        return;
    }

    if (exp_db_set_meta_u64(db, "last_indexed_seq", 123456789ULL) != 0) {
        FAIL("set_meta_u64 failed");
        exp_db_close(db);
        return;
    }
    if (exp_db_get_meta_u64(db, "last_indexed_seq", &val) != 0 || val != 123456789ULL) {
        FAIL("u64 roundtrip mismatch");
        exp_db_close(db);
        return;
    }

    /* overwrite same key */
    if (exp_db_set_meta_u64(db, "last_indexed_seq", 42ULL) != 0 ||
        exp_db_get_meta_u64(db, "last_indexed_seq", &val) != 0 || val != 42ULL) {
        FAIL("u64 overwrite mismatch");
        exp_db_close(db);
        return;
    }

    uint8_t chain_id[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    if (exp_db_set_meta_blob(db, "chain_id", chain_id, sizeof(chain_id)) != 0) {
        FAIL("set_meta_blob failed");
        exp_db_close(db);
        return;
    }

    uint8_t out[16];
    size_t out_len = 0;
    if (exp_db_get_meta_blob(db, "chain_id", out, sizeof(out), &out_len) != 0 ||
        out_len != sizeof(chain_id) || memcmp(out, chain_id, sizeof(chain_id)) != 0) {
        FAIL("blob roundtrip mismatch");
        exp_db_close(db);
        return;
    }

    /* buffer-too-small must fail cleanly, not overrun */
    uint8_t tiny[2];
    size_t tiny_len = 0;
    if (exp_db_get_meta_blob(db, "chain_id", tiny, sizeof(tiny), &tiny_len) == 0) {
        FAIL("expected failure for undersized buffer");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ── t2: insert_block + query_blocks ordering + set_block_hash backfill ── */

static void test_blocks_ordering(void) {
    TEST("insert_block ordering + set_block_hash backfill");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    exp_block_row_t b1 = {0}, b2 = {0}, b3 = {0};

    b1.height = 1; fill(b1.tx_root, 64, 0x01); b1.timestamp = 1000; fill(b1.proposer, 32, 0xA1); b1.tx_count = 2; b1.has_block_hash = 0;
    b2.height = 2; fill(b2.tx_root, 64, 0x02); b2.timestamp = 2000; fill(b2.proposer, 32, 0xA2); b2.tx_count = 3; b2.has_block_hash = 0;
    b3.height = 3; fill(b3.tx_root, 64, 0x03); b3.timestamp = 3000; fill(b3.proposer, 32, 0xA3); b3.tx_count = 1; b3.has_block_hash = 0;

    if (exp_db_insert_block(db, &b1) != 0 || exp_db_insert_block(db, &b2) != 0 || exp_db_insert_block(db, &b3) != 0) {
        FAIL("insert_block failed");
        exp_db_close(db);
        return;
    }

    exp_block_row_t rows[8];
    int count = -1;
    if (exp_db_query_blocks(db, EXP_CURSOR_TOP, 10, rows, &count) != 0 || count != 3) {
        FAIL("query_blocks count mismatch");
        exp_db_close(db);
        return;
    }
    if (rows[0].height != 3 || rows[1].height != 2 || rows[2].height != 1) {
        FAIL("query_blocks not DESC by height");
        exp_db_close(db);
        return;
    }

    /* cursor: before_height=3 excludes height 3 */
    int count2 = -1;
    if (exp_db_query_blocks(db, 3, 10, rows, &count2) != 0 || count2 != 2 ||
        rows[0].height != 2 || rows[1].height != 1) {
        FAIL("query_blocks before_height cursor wrong");
        exp_db_close(db);
        return;
    }

    /* genesis-boundary: walking below the lowest indexed height (1) must
     * terminate with zero rows, never wrap back to the top (0 is NOT an
     * "unbounded" sentinel — genesis itself is height 0). */
    int count_boundary = -1;
    if (exp_db_query_blocks(db, 1, 10, rows, &count_boundary) != 0 || count_boundary != 0) {
        FAIL("query_blocks should return 0 rows below the lowest height");
        exp_db_close(db);
        return;
    }

    uint8_t hash1[64], hash2[64];
    fill(hash1, 64, 0xB1);
    fill(hash2, 64, 0xB2);

    if (exp_db_set_block_hash(db, 1, hash1) != 0 || exp_db_set_block_hash(db, 2, hash2) != 0) {
        FAIL("set_block_hash failed");
        exp_db_close(db);
        return;
    }

    exp_block_row_t row;
    if (exp_db_query_block_by_height(db, 1, &row) != 0 || !row.has_block_hash ||
        memcmp(row.block_hash, hash1, 64) != 0 || row.timestamp != 1000 || row.tx_count != 2 ||
        memcmp(row.proposer, b1.proposer, 32) != 0 || memcmp(row.tx_root, b1.tx_root, 64) != 0) {
        FAIL("query_block_by_height(1) mismatch");
        exp_db_close(db);
        return;
    }

    if (exp_db_query_block_by_height(db, 3, &row) != 0 || row.has_block_hash) {
        FAIL("tip block_hash should still be unset");
        exp_db_close(db);
        return;
    }

    if (exp_db_query_block_by_hash(db, hash2, &row) != 0 || row.height != 2) {
        FAIL("query_block_by_hash(hash2) mismatch");
        exp_db_close(db);
        return;
    }

    uint8_t bogus[64];
    fill(bogus, 64, 0xFF);
    if (exp_db_query_block_by_hash(db, bogus, &row) == 0) {
        FAIL("query_block_by_hash should miss on unknown hash");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ── t3: insert_tx (2 outputs, different token_ids, 1 input) ───────── */

static void test_tx_insert_and_balance(void) {
    TEST("insert_tx + query_tx + query_balance + verify_addr_stats");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    uint8_t token_a[64], token_b[64];
    fill(token_a, 64, 0x00);   /* native token */
    fill(token_b, 64, 0xAA);

    exp_tx_row_t tx = {0};
    fill(tx.hash, 64, 0x10);
    tx.seq = 1;
    tx.height = 1;
    tx.tx_type = 5;
    tx.fee = 1000;
    tx.timestamp = 1700000000ULL;
    tx.multi_signer = 0;

    static const char raw_bytes[] = "test-raw-tx-bytes-for-hash-10";
    tx.size = (uint32_t)strlen(raw_bytes);

    exp_io_row_t ios[3];
    memset(ios, 0, sizeof(ios));

    memcpy(ios[0].tx_hash, tx.hash, 64);
    ios[0].io_index = 0; ios[0].direction = 1; /* out */
    strcpy(ios[0].address, "addr_recipient_1");
    memcpy(ios[0].token_id, token_a, 64);
    ios[0].amount = 100;

    memcpy(ios[1].tx_hash, tx.hash, 64);
    ios[1].io_index = 1; ios[1].direction = 1; /* out */
    strcpy(ios[1].address, "addr_recipient_2");
    memcpy(ios[1].token_id, token_b, 64);
    ios[1].amount = 250;

    memcpy(ios[2].tx_hash, tx.hash, 64);
    ios[2].io_index = 0; ios[2].direction = 0; /* in */
    strcpy(ios[2].address, "addr_signer_1");
    memcpy(ios[2].token_id, token_a, 64);
    ios[2].amount = 100;

    if (exp_db_insert_tx(db, &tx, (const uint8_t *)raw_bytes, strlen(raw_bytes), ios, 3) != 0) {
        FAIL("insert_tx failed");
        exp_db_close(db);
        return;
    }

    /* query_tx: row + ios + raw bytes */
    exp_tx_row_t tx_out = {0};
    exp_io_row_t ios_out[8];
    int io_count = -1;
    uint8_t *raw_out = NULL;
    size_t raw_len_out = 0;

    if (exp_db_query_tx(db, tx.hash, &tx_out, ios_out, 8, &io_count, &raw_out, &raw_len_out) != 0) {
        FAIL("query_tx failed");
        exp_db_close(db);
        return;
    }
    if (tx_out.seq != 1 || tx_out.height != 1 || tx_out.tx_type != 5 || tx_out.fee != 1000 ||
        tx_out.size != tx.size || tx_out.timestamp != 1700000000ULL || tx_out.multi_signer != 0) {
        FAIL("query_tx row field mismatch");
        free(raw_out);
        exp_db_close(db);
        return;
    }
    if (io_count != 3) {
        FAIL("query_tx io_count mismatch");
        free(raw_out);
        exp_db_close(db);
        return;
    }
    if (!raw_out || raw_len_out != strlen(raw_bytes) || memcmp(raw_out, raw_bytes, raw_len_out) != 0) {
        FAIL("query_tx raw bytes mismatch");
        free(raw_out);
        exp_db_close(db);
        return;
    }
    free(raw_out);

    /* query_balance: credit-only recipient addrs, debit on signer addr */
    uint64_t bal = 0, txc = 0;
    if (exp_db_query_balance(db, "addr_recipient_1", token_a, &bal, &txc) != 0 || bal != 100 || txc != 1) {
        FAIL("balance mismatch for addr_recipient_1/token_a");
        exp_db_close(db);
        return;
    }
    if (exp_db_query_balance(db, "addr_recipient_2", token_b, &bal, &txc) != 0 || bal != 250 || txc != 1) {
        FAIL("balance mismatch for addr_recipient_2/token_b");
        exp_db_close(db);
        return;
    }
    if (exp_db_query_balance(db, "addr_signer_1", token_a, &bal, &txc) != 0 || (int64_t)bal != -100 || txc != 1) {
        FAIL("balance mismatch for addr_signer_1/token_a (expected -100)");
        exp_db_close(db);
        return;
    }

    if (exp_db_verify_addr_stats(db) != 0) {
        FAIL("verify_addr_stats reported divergence");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ── t4: duplicate tx insert is a no-op ─────────────────────────────── */

static void test_duplicate_insert_noop(void) {
    TEST("duplicate insert_tx is a no-op");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    uint8_t token_a[64];
    fill(token_a, 64, 0x00);

    exp_tx_row_t tx = {0};
    fill(tx.hash, 64, 0x20);
    tx.seq = 1; tx.height = 1; tx.tx_type = 1; tx.fee = 10; tx.timestamp = 5000; tx.multi_signer = 0;

    static const char raw_bytes[] = "dup-raw";
    tx.size = (uint32_t)strlen(raw_bytes);

    exp_io_row_t io = {0};
    memcpy(io.tx_hash, tx.hash, 64);
    io.io_index = 0; io.direction = 1;
    strcpy(io.address, "addr_dup_target");
    memcpy(io.token_id, token_a, 64);
    io.amount = 50;

    if (exp_db_insert_tx(db, &tx, (const uint8_t *)raw_bytes, strlen(raw_bytes), &io, 1) != 0) {
        FAIL("first insert failed");
        exp_db_close(db);
        return;
    }

    /* second insert: same hash, different (bogus) io payload — must be ignored entirely */
    exp_io_row_t io2 = io;
    io2.amount = 999999;
    if (exp_db_insert_tx(db, &tx, (const uint8_t *)raw_bytes, strlen(raw_bytes), &io2, 1) != 0) {
        FAIL("second insert (duplicate) should return 0, not error");
        exp_db_close(db);
        return;
    }

    exp_tx_row_t tx_out = {0};
    exp_io_row_t ios_out[8];
    int io_count = -1;
    uint8_t *raw_out = NULL;
    size_t raw_len_out = 0;
    if (exp_db_query_tx(db, tx.hash, &tx_out, ios_out, 8, &io_count, &raw_out, &raw_len_out) != 0 ||
        io_count != 1) {
        FAIL("duplicate insert changed io row count");
        free(raw_out);
        exp_db_close(db);
        return;
    }
    free(raw_out);

    uint64_t bal = 0, txc = 0;
    if (exp_db_query_balance(db, "addr_dup_target", token_a, &bal, &txc) != 0 || bal != 50 || txc != 1) {
        FAIL("duplicate insert double-counted addr_stats");
        exp_db_close(db);
        return;
    }

    if (exp_db_verify_addr_stats(db) != 0) {
        FAIL("verify_addr_stats reported divergence after duplicate insert");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ── t5: query_address pagination, seq DESC, exactly-once coverage ─── */

static void test_address_pagination(void) {
    TEST("query_address pagination (limit 2, before_seq walk)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    uint8_t token_a[64];
    fill(token_a, 64, 0x00);

    uint64_t seqs[3] = {1, 2, 3};
    uint64_t heights[3] = {1, 1, 2};
    uint64_t amounts[3] = {10, 20, 30};

    for (int i = 0; i < 3; i++) {
        exp_tx_row_t tx = {0};
        fill(tx.hash, 64, (uint8_t)(0x30 + i));
        tx.seq = seqs[i];
        tx.height = heights[i];
        tx.tx_type = 1;
        tx.fee = 1;
        tx.timestamp = 6000 + i;
        tx.multi_signer = 0;

        char raw_buf[16];
        snprintf(raw_buf, sizeof(raw_buf), "raw_%d", i);
        tx.size = (uint32_t)strlen(raw_buf);

        exp_io_row_t io = {0};
        memcpy(io.tx_hash, tx.hash, 64);
        io.io_index = 0; io.direction = 1;
        strcpy(io.address, "addr_walker");
        memcpy(io.token_id, token_a, 64);
        io.amount = amounts[i];

        if (exp_db_insert_tx(db, &tx, (const uint8_t *)raw_buf, strlen(raw_buf), &io, 1) != 0) {
            FAIL("insert_tx failed while seeding pagination test");
            exp_db_close(db);
            return;
        }
    }

    exp_tx_row_t rows[8];
    int count = -1;

    if (exp_db_query_address(db, "addr_walker", EXP_CURSOR_TOP, 2, rows, &count) != 0 || count != 2 ||
        rows[0].seq != 3 || rows[1].seq != 2) {
        FAIL("first page wrong (expected seq 3,2 DESC)");
        exp_db_close(db);
        return;
    }

    uint64_t cursor = rows[count - 1].seq; /* = 2 */
    int count2 = -1;
    if (exp_db_query_address(db, "addr_walker", cursor, 2, rows, &count2) != 0 || count2 != 1 ||
        rows[0].seq != 1) {
        FAIL("second page wrong (expected seq 1 only)");
        exp_db_close(db);
        return;
    }

    /* one more page should be empty */
    uint64_t cursor2 = rows[count2 - 1].seq; /* = 1 */
    int count3 = -1;
    if (exp_db_query_address(db, "addr_walker", cursor2, 2, rows, &count3) != 0 || count3 != 0) {
        FAIL("third page should be empty");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ── t6-t9: exp_extract_tx (Task 3) ─────────────────────────────────── */

#define EXP_TEST_TX_BUF_SIZE 32768

static void test_extract_basic_mapping(void) {
    TEST("exp_extract_tx basic mapping (1 in, 2 out, 1 signer)");

    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = DNAC_PROTOCOL_VERSION;
    tx.type = DNAC_TX_SPEND;
    tx.timestamp = 999999999ULL;   /* fixed, deliberately not "now" (D4/F6) */
    fill(tx.tx_hash, DNAC_TX_HASH_SIZE, 0xCC);
    tx.committed_fee = 555555ULL;

    tx.input_count = 1;
    fill(tx.inputs[0].nullifier, DNAC_NULLIFIER_SIZE, 0xAA);
    tx.inputs[0].amount = 700;
    /* token_id left zero == native DNAC */

    /* fix round 1: owner_fingerprint is now validated as exactly 128
     * lowercase-hex chars + NUL (see exp_extract.c) — use valid-format
     * fixtures rather than arbitrary strings. */
    char fp_one[129], fp_two[129];
    set_test_fp(fp_one, '1');
    set_test_fp(fp_two, '2');

    tx.output_count = 2;
    tx.outputs[0].version = 1;
    strcpy(tx.outputs[0].owner_fingerprint, fp_one);
    tx.outputs[0].amount = 300;
    /* token_id left zero == native DNAC */

    tx.outputs[1].version = 1;
    strcpy(tx.outputs[1].owner_fingerprint, fp_two);
    tx.outputs[1].amount = 400;
    fill(tx.outputs[1].token_id, DNAC_TOKEN_ID_SIZE, 0xBB);

    tx.witness_count = 0;

    tx.signer_count = 1;
    fill(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, 0x11);
    fill(tx.signers[0].signature, DNAC_SIGNATURE_SIZE, 0x00);

    char expected_fp0[129];
    if (qgp_sha3_512_hex(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, expected_fp0, sizeof(expected_fp0)) != 0) {
        FAIL("qgp_sha3_512_hex for expected fp0 failed");
        return;
    }

    uint8_t buf[EXP_TEST_TX_BUF_SIZE];
    size_t written = 0;
    if (dnac_tx_serialize(&tx, buf, sizeof(buf), &written) != DNAC_SUCCESS) {
        FAIL("dnac_tx_serialize failed");
        return;
    }

    exp_tx_row_t tx_row;
    exp_io_row_t ios[8];
    int io_count = -1;
    if (exp_extract_tx(buf, written, 42, 7, &tx_row, ios, 8, &io_count) != 0) {
        FAIL("exp_extract_tx failed");
        return;
    }

    if (io_count != 3) { FAIL("io_count mismatch"); return; }
    if (memcmp(tx_row.hash, tx.tx_hash, 64) != 0) { FAIL("hash mismatch"); return; }
    if (tx_row.seq != 42 || tx_row.height != 7) { FAIL("seq/height mismatch"); return; }
    if (tx_row.tx_type != (int)DNAC_TX_SPEND) { FAIL("tx_type mismatch"); return; }
    if (tx_row.fee != 555555ULL) { FAIL("fee mismatch"); return; }
    if (tx_row.size != written) { FAIL("size mismatch"); return; }
    if (tx_row.timestamp != 999999999ULL) { FAIL("timestamp not from deserialized tx (D4/F6)"); return; }
    if (tx_row.multi_signer != 0) { FAIL("multi_signer should be 0 for 1 signer"); return; }

    /* io[0]: input 0, direction=in, attributed to signer[0] fp */
    if (ios[0].direction != 0 || ios[0].io_index != 0 || ios[0].amount != 700) {
        FAIL("ios[0] input fields mismatch");
        return;
    }
    if (strcmp(ios[0].address, expected_fp0) != 0) { FAIL("ios[0] address != signer[0] fp"); return; }
    if (memcmp(ios[0].tx_hash, tx.tx_hash, 64) != 0) { FAIL("ios[0] tx_hash mismatch"); return; }

    /* io[1]: output 0 */
    if (ios[1].direction != 1 || ios[1].io_index != 0 || ios[1].amount != 300) {
        FAIL("ios[1] output0 fields mismatch");
        return;
    }
    if (strcmp(ios[1].address, fp_one) != 0) { FAIL("ios[1] address mismatch"); return; }

    /* io[2]: output 1 */
    if (ios[2].direction != 1 || ios[2].io_index != 1 || ios[2].amount != 400) {
        FAIL("ios[2] output1 fields mismatch");
        return;
    }
    if (strcmp(ios[2].address, fp_two) != 0) { FAIL("ios[2] address mismatch"); return; }
    if (memcmp(ios[2].token_id, tx.outputs[1].token_id, 64) != 0) { FAIL("ios[2] token_id mismatch"); return; }

    PASS();
}

static void test_extract_multi_signer(void) {
    TEST("exp_extract_tx multi_signer flag + both inputs -> signer[0] fp");

    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = DNAC_PROTOCOL_VERSION;
    tx.type = DNAC_TX_SPEND;
    tx.timestamp = 888888888ULL;
    fill(tx.tx_hash, DNAC_TX_HASH_SIZE, 0xDD);
    tx.committed_fee = 20000ULL;

    tx.input_count = 2;
    fill(tx.inputs[0].nullifier, DNAC_NULLIFIER_SIZE, 0x01);
    tx.inputs[0].amount = 111;
    fill(tx.inputs[1].nullifier, DNAC_NULLIFIER_SIZE, 0x02);
    tx.inputs[1].amount = 222;

    /* fix round 1: owner_fingerprint is now validated as exactly 128
     * lowercase-hex chars + NUL (see exp_extract.c). */
    char fp_multi[129];
    set_test_fp(fp_multi, '3');

    tx.output_count = 1;
    tx.outputs[0].version = 1;
    strcpy(tx.outputs[0].owner_fingerprint, fp_multi);
    tx.outputs[0].amount = 300;

    tx.signer_count = 2;
    fill(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, 0x11);
    fill(tx.signers[0].signature, DNAC_SIGNATURE_SIZE, 0x00);
    fill(tx.signers[1].pubkey, DNAC_PUBKEY_SIZE, 0x22);
    fill(tx.signers[1].signature, DNAC_SIGNATURE_SIZE, 0x00);

    char expected_fp0[129];
    if (qgp_sha3_512_hex(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, expected_fp0, sizeof(expected_fp0)) != 0) {
        FAIL("qgp_sha3_512_hex for expected fp0 failed");
        return;
    }

    uint8_t buf[EXP_TEST_TX_BUF_SIZE];
    size_t written = 0;
    if (dnac_tx_serialize(&tx, buf, sizeof(buf), &written) != DNAC_SUCCESS) {
        FAIL("dnac_tx_serialize failed");
        return;
    }

    exp_tx_row_t tx_row;
    exp_io_row_t ios[8];
    int io_count = -1;
    if (exp_extract_tx(buf, written, 99, 12, &tx_row, ios, 8, &io_count) != 0) {
        FAIL("exp_extract_tx failed");
        return;
    }

    if (io_count != 3) { FAIL("io_count mismatch"); return; }
    if (tx_row.multi_signer != 1) { FAIL("multi_signer should be 1 for 2 signers"); return; }

    if (ios[0].direction != 0 || ios[0].amount != 111 || strcmp(ios[0].address, expected_fp0) != 0) {
        FAIL("ios[0] not attributed to signer[0]");
        return;
    }
    if (ios[1].direction != 0 || ios[1].amount != 222 || strcmp(ios[1].address, expected_fp0) != 0) {
        FAIL("ios[1] not attributed to signer[0]");
        return;
    }
    if (ios[2].direction != 1 || ios[2].amount != 300) { FAIL("ios[2] output mismatch"); return; }

    PASS();
}

static void test_signer_fingerprint_kat(void) {
    TEST("exp_signer_fingerprint == SHA3-512 hex, lowercase, 128 chars");

    uint8_t buf[64];
    for (int i = 0; i < 64; i++) buf[i] = (uint8_t)i;

    uint8_t digest[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512(buf, sizeof(buf), digest) != 0) {
        FAIL("qgp_sha3_512 failed");
        return;
    }
    char expected[129];
    for (int i = 0; i < QGP_SHA3_512_DIGEST_LENGTH; i++) {
        snprintf(expected + i * 2, 3, "%02x", digest[i]);
    }
    expected[128] = '\0';

    char fp_out[129];
    if (exp_signer_fingerprint(buf, sizeof(buf), fp_out) != 0) {
        FAIL("exp_signer_fingerprint failed");
        return;
    }

    if (strlen(fp_out) != 128) { FAIL("fingerprint length != 128"); return; }
    if (strcmp(fp_out, expected) != 0) { FAIL("fingerprint != independently-computed SHA3-512 hex"); return; }
    for (size_t i = 0; i < strlen(fp_out); i++) {
        char c = fp_out[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            FAIL("fingerprint not lowercase hex");
            return;
        }
    }

    PASS();
}

static void test_extract_signer_count_zero(void) {
    TEST("exp_extract_tx rejects signer_count == 0 (defensive)");

    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = DNAC_PROTOCOL_VERSION;
    tx.type = DNAC_TX_SPEND;
    tx.timestamp = 123456789ULL;
    fill(tx.tx_hash, DNAC_TX_HASH_SIZE, 0xEE);
    tx.committed_fee = 1000ULL;

    tx.input_count = 1;
    fill(tx.inputs[0].nullifier, DNAC_NULLIFIER_SIZE, 0x03);
    tx.inputs[0].amount = 50;

    tx.output_count = 1;
    tx.outputs[0].version = 1;
    strcpy(tx.outputs[0].owner_fingerprint, "recipient_fp_zero_signer");
    tx.outputs[0].amount = 50;

    tx.signer_count = 0;  /* malformed but structurally deserializable —
                            * dnac_tx_deserialize only rejects
                            * signer_count > DNAC_TX_MAX_SIGNERS. */

    uint8_t buf[EXP_TEST_TX_BUF_SIZE];
    size_t written = 0;
    if (dnac_tx_serialize(&tx, buf, sizeof(buf), &written) != DNAC_SUCCESS) {
        FAIL("dnac_tx_serialize failed");
        return;
    }

    exp_tx_row_t tx_row;
    exp_io_row_t ios[8];
    int io_count = -1;
    if (exp_extract_tx(buf, written, 1, 1, &tx_row, ios, 8, &io_count) == 0) {
        FAIL("exp_extract_tx should reject signer_count == 0");
        return;
    }

    PASS();
}

/* ── Fix round 1 regression: hostile owner_fingerprint rejected ────── */
static void test_extract_rejects_malformed_output_fingerprint(void) {
    TEST("exp_extract_tx rejects non-hex/unterminated owner_fingerprint");

    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = DNAC_PROTOCOL_VERSION;
    tx.type = DNAC_TX_SPEND;
    tx.timestamp = 135791113ULL;
    fill(tx.tx_hash, DNAC_TX_HASH_SIZE, 0xFF);
    tx.committed_fee = 12345ULL;

    tx.input_count = 1;
    fill(tx.inputs[0].nullifier, DNAC_NULLIFIER_SIZE, 0x04);
    tx.inputs[0].amount = 900;

    /* Hostile output: 129 raw bytes, all 'A' — valid length (129) but no
     * NUL within the field and not lowercase hex. This is the exact shape
     * dnac_tx_deserialize accepts as an unvalidated blob (see finding:
     * exp_extract.c pre-fix memcpy'd this straight into row->address,
     * which exp_db.c then binds with strlen-based sqlite3_bind_text —
     * OOB read on a hostile TX). */
    tx.output_count = 1;
    tx.outputs[0].version = 1;
    memset(tx.outputs[0].owner_fingerprint, 'A', 129);
    tx.outputs[0].amount = 50;

    tx.signer_count = 1;
    fill(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, 0x11);
    fill(tx.signers[0].signature, DNAC_SIGNATURE_SIZE, 0x00);

    uint8_t buf[EXP_TEST_TX_BUF_SIZE];
    size_t written = 0;
    if (dnac_tx_serialize(&tx, buf, sizeof(buf), &written) != DNAC_SUCCESS) {
        FAIL("dnac_tx_serialize failed");
        return;
    }

    exp_tx_row_t tx_row;
    exp_io_row_t ios[8];
    int io_count = -1;
    if (exp_extract_tx(buf, written, 1, 1, &tx_row, ios, 8, &io_count) == 0) {
        FAIL("exp_extract_tx should reject malformed owner_fingerprint");
        return;
    }

    PASS();
}

/* ── Fix round 2 regression: charset branch specifically ────────────── */
static void test_extract_rejects_non_hex_charset_output_fingerprint(void) {
    TEST("exp_extract_tx rejects output fingerprint failing charset check");

    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));

    tx.version = DNAC_PROTOCOL_VERSION;
    tx.type = DNAC_TX_SPEND;
    tx.timestamp = 246813579ULL;
    fill(tx.tx_hash, DNAC_TX_HASH_SIZE, 0x77);
    tx.committed_fee = 6789ULL;

    tx.input_count = 1;
    fill(tx.inputs[0].nullifier, DNAC_NULLIFIER_SIZE, 0x05);
    tx.inputs[0].amount = 400;

    /* Output fingerprint: 128 x 'A' + NUL at [128] — passes the NUL@128
     * and strlen==128 checks but fails the lowercase-hex charset loop
     * ('A' is uppercase, not in [0-9a-f]). This exercises the charset
     * rejection branch specifically, distinct from the round-1 test's
     * unterminated/wrong-length 129-byte blob. */
    tx.output_count = 1;
    tx.outputs[0].version = 1;
    set_test_fp(tx.outputs[0].owner_fingerprint, 'A');
    tx.outputs[0].amount = 25;

    tx.signer_count = 1;
    fill(tx.signers[0].pubkey, DNAC_PUBKEY_SIZE, 0x22);
    fill(tx.signers[0].signature, DNAC_SIGNATURE_SIZE, 0x00);

    uint8_t buf[EXP_TEST_TX_BUF_SIZE];
    size_t written = 0;
    if (dnac_tx_serialize(&tx, buf, sizeof(buf), &written) != DNAC_SUCCESS) {
        FAIL("dnac_tx_serialize failed");
        return;
    }

    exp_tx_row_t tx_row;
    exp_io_row_t ios[8];
    int io_count = -1;
    if (exp_extract_tx(buf, written, 1, 1, &tx_row, ios, 8, &io_count) == 0) {
        FAIL("exp_extract_tx should reject non-hex-charset owner_fingerprint");
        return;
    }

    PASS();
}

/* ── t12-t13: exp_chain_config_load (Task 4) ────────────────────────
 * Uses mkstemp — a fixed filename would race under CI parallelism
 * (forbidden: "tests that pass under low load but fail under CI
 * parallelism"). Network paths (exp_chain_open/rotate/supply/...) are
 * NOT unit-tested here per plan Task 4 — no network calls in tests;
 * they get the live smoke in Task 9. */

static void test_chain_config_load(void) {
    TEST("exp_chain_config_load (2 servers + comment + blank line)");

    char path[] = "/tmp/exp_chain_test_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "# comment line, should be skipped\n");
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "   \n");                 /* whitespace-only line */
    fprintf(f, "203.0.113.5 4002\n");
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc != 0 || count != 2) { FAIL("config_load count mismatch"); return; }
    if (strcmp(servers[0].host, "127.0.0.1") != 0 || servers[0].port != 4001) {
        FAIL("config_load servers[0] mismatch");
        return;
    }
    if (strcmp(servers[1].host, "203.0.113.5") != 0 || servers[1].port != 4002) {
        FAIL("config_load servers[1] mismatch");
        return;
    }

    PASS();
}

static void test_chain_config_load_rejects_malformed(void) {
    TEST("exp_chain_config_load rejects a malformed line");

    char path[] = "/tmp/exp_chain_test_bad_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "this-line-has-no-port\n");
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc == 0) { FAIL("expected failure for malformed line"); return; }

    PASS();
}

/* ── t14-t19: exp_reset_fsm_feed (Task 4, F4) — pure logic ──────────── */

static void test_reset_fsm_match_is_no(void) {
    TEST("reset FSM: matching chain_id -> NO");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));

    uint8_t ref[32];
    fill(ref, 32, 0x42);

    /* first feed (fsm zero-initialized) adopts ref as the reference */
    if (exp_reset_fsm_feed(&fsm, ref, 0) != EXP_RESET_NO) { FAIL("first feed should be NO"); return; }
    /* subsequent matching feeds from any server stay NO */
    if (exp_reset_fsm_feed(&fsm, ref, 1) != EXP_RESET_NO) { FAIL("matching feed should be NO"); return; }

    PASS();
}

static void test_reset_fsm_one_mismatch_pending(void) {
    TEST("reset FSM: one mismatch -> PENDING");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);  /* establish reference */
    if (exp_reset_fsm_feed(&fsm, cand, 0) != EXP_RESET_PENDING) {
        FAIL("first mismatch should be PENDING");
        return;
    }

    PASS();
}

static void test_reset_fsm_same_server_twice_still_pending(void) {
    TEST("reset FSM: same server reporting mismatch twice -> still PENDING");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    exp_reset_fsm_feed(&fsm, cand, 3);
    if (exp_reset_fsm_feed(&fsm, cand, 3) != EXP_RESET_PENDING) {
        FAIL("same-server repeat should still be PENDING (only 1 distinct server)");
        return;
    }

    PASS();
}

static void test_reset_fsm_two_servers_two_polls_confirmed(void) {
    TEST("reset FSM: 2 distinct servers x 2 polls -> CONFIRMED");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    if (exp_reset_fsm_feed(&fsm, cand, 0) != EXP_RESET_PENDING) { FAIL("poll1 should be PENDING"); return; }
    if (exp_reset_fsm_feed(&fsm, cand, 1) != EXP_RESET_CONFIRMED) {
        FAIL("poll2 from a distinct server should be CONFIRMED");
        return;
    }

    PASS();
}

static void test_reset_fsm_mismatch_then_match_back_to_no(void) {
    TEST("reset FSM: mismatch then match -> back to NO");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    exp_reset_fsm_feed(&fsm, cand, 0);   /* PENDING */
    if (exp_reset_fsm_feed(&fsm, ref, 1) != EXP_RESET_NO) {
        FAIL("matching feed after a mismatch should return to NO");
        return;
    }
    /* verify tracking state was actually cleared, not just the return
     * code: a fresh single-server mismatch must restart at PENDING, not
     * jump straight to CONFIRMED off stale servers_seen/polls_seen. */
    if (exp_reset_fsm_feed(&fsm, cand, 2) != EXP_RESET_PENDING) {
        FAIL("post-reset mismatch should restart at PENDING");
        return;
    }

    PASS();
}

static void test_reset_fsm_candidate_switch_restarts(void) {
    TEST("reset FSM: switching mismatching candidate restarts tracking");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];    fill(ref, 32, 0x42);
    uint8_t cand_x[32]; fill(cand_x, 32, 0x11);
    uint8_t cand_y[32]; fill(cand_y, 32, 0x22);

    exp_reset_fsm_feed(&fsm, ref, 0);
    if (exp_reset_fsm_feed(&fsm, cand_x, 0) != EXP_RESET_PENDING) { FAIL("cand_x poll1 should be PENDING"); return; }
    /* a DIFFERENT mismatching candidate from a different server must
     * restart tracking, not carry cand_x's poll count toward cand_y */
    if (exp_reset_fsm_feed(&fsm, cand_y, 1) != EXP_RESET_PENDING) {
        FAIL("candidate switch should restart at PENDING, not CONFIRMED");
        return;
    }
    /* one more distinct-server poll of cand_y should now confirm */
    if (exp_reset_fsm_feed(&fsm, cand_y, 2) != EXP_RESET_CONFIRMED) {
        FAIL("cand_y poll2 (distinct server) should be CONFIRMED");
        return;
    }

    PASS();
}

int main(void) {
    printf("=== DNA Explorer exp_db Tests ===\n");

    test_meta_roundtrip();
    test_blocks_ordering();
    test_tx_insert_and_balance();
    test_duplicate_insert_noop();
    test_address_pagination();
    test_extract_basic_mapping();
    test_extract_multi_signer();
    test_signer_fingerprint_kat();
    test_extract_signer_count_zero();
    test_extract_rejects_malformed_output_fingerprint();
    test_extract_rejects_non_hex_charset_output_fingerprint();
    test_chain_config_load();
    test_chain_config_load_rejects_malformed();
    test_reset_fsm_match_is_no();
    test_reset_fsm_one_mismatch_pending();
    test_reset_fsm_same_server_twice_still_pending();
    test_reset_fsm_two_servers_two_polls_confirmed();
    test_reset_fsm_mismatch_then_match_back_to_no();
    test_reset_fsm_candidate_switch_restarts();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
