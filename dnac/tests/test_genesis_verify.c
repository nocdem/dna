/**
 * @file test_genesis_verify.c
 * @brief Tests for dnac_genesis_verify — bootstrap trust from bytes.
 *
 * Covers:
 *   - test_positive       : encoded genesis decodes + verifies against correct chain_id
 *   - test_wrong_chain_id : verification fails when chain_id does not match
 *   - test_tampered_bytes : bit-flip in encoded bytes fails re-hash check
 *   - test_non_genesis    : height-1 block rejected (must be genesis)
 */

#include "dnac/ledger.h"
#include "dnac/block.h"
#include "dnac/chain_def_codec.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static dnac_block_t *build_sample_genesis(void) {
    static dnac_block_t b;
    memset(&b, 0, sizeof(b));
    b.block_height = 0;
    b.is_genesis = true;
    strcpy(b.chain_def.chain_name, "genesis-test");
    b.chain_def.protocol_version = 1;
    b.chain_def.witness_count = 0;  /* no pubkeys — keeps test minimal */
    b.chain_def.max_active_witnesses = 21;
    b.chain_def.block_interval_sec = 5;
    b.chain_def.max_txs_per_block = 10;
    b.chain_def.view_change_timeout_ms = 5000;
    strcpy(b.chain_def.token_symbol, "DNAC");
    b.chain_def.token_decimals = 8;
    b.chain_def.initial_supply_raw = 100;
    b.tx_count = 1;
    b.timestamp = 1700000000ULL;
    assert(dnac_block_compute_hash(&b) == 0);
    return &b;
}

static void test_positive(void) {
    dnac_block_t *g = build_sample_genesis();

    static uint8_t buf[32768];
    size_t len = 0;
    assert(dnac_block_encode(g, buf, sizeof(buf), &len) == 0);

    dnac_trusted_state_t trust;
    assert(dnac_genesis_verify(buf, len, g->block_hash, &trust));

    assert(memcmp(trust.chain_id, g->block_hash, DNAC_BLOCK_HASH_SIZE) == 0);
    assert(trust.chain_def.protocol_version == 1);
    assert(trust.chain_def.token_decimals == 8);
    assert(strcmp(trust.chain_def.chain_name, "genesis-test") == 0);
    assert(trust.chain_def.witness_count == 0);
    printf("PASS test_positive\n");
}

static void test_wrong_chain_id(void) {
    dnac_block_t *g = build_sample_genesis();
    static uint8_t buf[32768];
    size_t len = 0;
    assert(dnac_block_encode(g, buf, sizeof(buf), &len) == 0);

    uint8_t wrong_id[DNAC_BLOCK_HASH_SIZE];
    memcpy(wrong_id, g->block_hash, DNAC_BLOCK_HASH_SIZE);
    wrong_id[0] ^= 0x01;

    dnac_trusted_state_t trust;
    if (dnac_genesis_verify(buf, len, wrong_id, &trust)) {
        fprintf(stderr, "FAIL test_wrong_chain_id — accepted wrong chain_id\n");
        assert(0);
    }
    printf("PASS test_wrong_chain_id\n");
}

static void test_tampered_bytes(void) {
    dnac_block_t *g = build_sample_genesis();
    static uint8_t buf[32768];
    size_t len = 0;
    assert(dnac_block_encode(g, buf, sizeof(buf), &len) == 0);

    /* Flip a byte inside state_root (offset 8 + 64 + 0 = 72). */
    buf[72] ^= 0x01;

    dnac_trusted_state_t trust;
    if (dnac_genesis_verify(buf, len, g->block_hash, &trust)) {
        fprintf(stderr, "FAIL test_tampered_bytes — accepted tampered bytes\n");
        assert(0);
    }
    printf("PASS test_tampered_bytes\n");
}

static void test_non_genesis(void) {
    /* Build a height-1 non-genesis block and try to decode it as genesis. */
    static dnac_block_t b;
    memset(&b, 0, sizeof(b));
    b.block_height = 1;
    b.is_genesis = false;
    b.tx_count = 1;
    b.timestamp = 1700000000ULL;
    /* Non-zero prev_block_hash so we don't collide with zero_hash guard. */
    memset(b.prev_block_hash, 0xAA, DNAC_BLOCK_HASH_SIZE);
    assert(dnac_block_compute_hash(&b) == 0);

    static uint8_t buf[32768];
    size_t len = 0;
    assert(dnac_block_encode(&b, buf, sizeof(buf), &len) == 0);

    dnac_trusted_state_t trust;
    if (dnac_genesis_verify(buf, len, b.block_hash, &trust)) {
        fprintf(stderr, "FAIL test_non_genesis — accepted height=1 block\n");
        assert(0);
    }
    printf("PASS test_non_genesis\n");
}

int main(void) {
    test_positive();
    test_wrong_chain_id();
    test_tampered_bytes();
    test_non_genesis();
    printf("ALL PASS\n");
    return 0;
}
