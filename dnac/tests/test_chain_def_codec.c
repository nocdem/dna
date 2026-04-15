/**
 * @file test_chain_def_codec.c
 * @brief Roundtrip + determinism test for chain_def encode/decode.
 *
 * Guards against serialization drift in dnac_chain_def_encode /
 * dnac_chain_def_decode. If any field order, width, or padding convention
 * changes, these tests must be updated in lockstep with the codec — and
 * that's the whole point: the test is the canary.
 */

#include "dnac/chain_def_codec.h"
#include "dnac/block.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void fill_sample(dnac_chain_definition_t *cd) {
    memset(cd, 0, sizeof(*cd));

    strcpy(cd->chain_name, "test-chain");
    cd->protocol_version = 1;
    /* parent_chain_id zeros (root chain) */
    strcpy(cd->genesis_message, "DNAC test chain - roundtrip fixture");

    cd->witness_count = 2;
    cd->max_active_witnesses = 21;
    /* Fake pubkeys: patterned bytes */
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        cd->witness_pubkeys[0][i] = (uint8_t)(i & 0xff);
        cd->witness_pubkeys[1][i] = (uint8_t)((i + 0x80) & 0xff);
    }

    cd->block_interval_sec = 5;
    cd->max_txs_per_block = 10;
    cd->view_change_timeout_ms = 5000;

    strcpy(cd->token_symbol, "DNAC");
    cd->token_decimals = 8;
    cd->initial_supply_raw = 100000000000000000ULL;
    /* native_token_id zeros */

    /* fee_recipient zeros (burn) */
}

static void test_size_matches(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);
    size_t expected = dnac_chain_def_encoded_size(&cd);
    printf("encoded_size (witness_count=2): %zu bytes\n", expected);
    assert(expected > 0);
    assert(expected <= dnac_chain_def_max_size());
    printf("PASS test_size_matches\n");
}

static void test_roundtrip_identical(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);

    uint8_t buf1[65536];
    size_t len1 = 0;
    int rc = dnac_chain_def_encode(&cd, buf1, sizeof(buf1), &len1);
    assert(rc == 0);
    printf("encoded %zu bytes\n", len1);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    rc = dnac_chain_def_decode(buf1, len1, &decoded);
    assert(rc == 0);

    /* Re-encode the decoded struct, must produce byte-identical buffer */
    uint8_t buf2[65536];
    size_t len2 = 0;
    rc = dnac_chain_def_encode(&decoded, buf2, sizeof(buf2), &len2);
    assert(rc == 0);
    assert(len1 == len2);
    assert(memcmp(buf1, buf2, len1) == 0);
    printf("PASS test_roundtrip_identical\n");
}

static void test_reject_too_small_buffer(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);
    uint8_t tiny[10];
    size_t len = 0;
    int rc = dnac_chain_def_encode(&cd, tiny, sizeof(tiny), &len);
    assert(rc == -1);
    printf("PASS test_reject_too_small_buffer\n");
}

static void test_reject_oversized_witness_count(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);
    cd.witness_count = 999;  /* > DNAC_MAX_WITNESSES_COMPILE_CAP */
    uint8_t buf[65536];
    size_t len = 0;
    int rc = dnac_chain_def_encode(&cd, buf, sizeof(buf), &len);
    assert(rc == -1);
    printf("PASS test_reject_oversized_witness_count\n");
}

static void test_reject_trailing_bytes(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);
    uint8_t buf[65536];
    size_t len = 0;
    int rc = dnac_chain_def_encode(&cd, buf, sizeof(buf), &len);
    assert(rc == 0);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    /* Pass an extra byte at the end */
    rc = dnac_chain_def_decode(buf, len + 1, &decoded);
    assert(rc == -1);
    printf("PASS test_reject_trailing_bytes\n");
}

static void test_reject_short_buffer(void) {
    dnac_chain_definition_t cd;
    fill_sample(&cd);
    uint8_t buf[65536];
    size_t len = 0;
    int rc = dnac_chain_def_encode(&cd, buf, sizeof(buf), &len);
    assert(rc == 0);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    rc = dnac_chain_def_decode(buf, len - 1, &decoded);
    assert(rc == -1);
    printf("PASS test_reject_short_buffer\n");
}

int main(void) {
    test_size_matches();
    test_roundtrip_identical();
    test_reject_too_small_buffer();
    test_reject_oversized_witness_count();
    test_reject_trailing_bytes();
    test_reject_short_buffer();
    printf("ALL PASS\n");
    return 0;
}
