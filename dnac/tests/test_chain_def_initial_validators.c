/**
 * @file test_chain_def_initial_validators.c
 * @brief Phase 12 Task 56 — initial_validators[] codec + canonical-hash guards.
 *
 * Coverage:
 *   1. Round-trip: populate 7 initial_validators, encode → decode, exact match.
 *   2. Canonical hash: encoded size includes ALL 129 fp bytes and ALL 128
 *      endpoint bytes. Mutating a post-NUL byte changes the encoded blob
 *      and therefore any downstream hash.
 *   3. Exact size: CD_FIXED + 7 × PUBKEY + 1 + 7 × (2592+129+2+128).
 *   4. Count-cap rejection: initial_validator_count > DNAC_COMMITTEE_SIZE
 *      is rejected by the encoder.
 *   5. Count == 0 still round-trips (legacy chain_defs).
 */

#include "dnac/chain_def_codec.h"
#include "dnac/block.h"
#include "dnac/dnac.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

/* Patterned pubkey generator — distinct per index. */
static void fill_patterned_pubkey(uint8_t out[DNAC_PUBKEY_SIZE], int seed) {
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        out[i] = (uint8_t)((i + 37 * seed) & 0xff);
    }
}

static void fill_sample_with_validators(dnac_chain_definition_t *cd) {
    memset(cd, 0, sizeof(*cd));

    strcpy(cd->chain_name, "test-chain");
    cd->protocol_version = 1;
    strcpy(cd->genesis_message, "DNAC Phase 12 initial_validators test");

    cd->witness_count = 2;
    cd->max_active_witnesses = 21;
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        cd->witness_pubkeys[0][i] = (uint8_t)(i & 0xff);
        cd->witness_pubkeys[1][i] = (uint8_t)((i + 0x80) & 0xff);
    }

    cd->block_interval_sec = 5;
    cd->max_txs_per_block = 10;
    cd->view_change_timeout_ms = 5000;

    strcpy(cd->token_symbol, "DNAC");
    cd->token_decimals = 8;
    cd->initial_supply_raw = DNAC_DEFAULT_TOTAL_SUPPLY;

    /* Populate 7 initial validators with distinct patterned pubkeys. */
    cd->initial_validator_count = DNAC_COMMITTEE_SIZE;
    for (int i = 0; i < DNAC_COMMITTEE_SIZE; i++) {
        dnac_chain_initial_validator_t *iv = &cd->initial_validators[i];
        fill_patterned_pubkey(iv->pubkey, i + 1);
        snprintf(iv->unstake_destination_fp, DNAC_FINGERPRINT_SIZE,
                 "fp-validator-%d", i);
        iv->commission_bps = (uint16_t)(100 * i);  /* 0, 100, 200, ... */
        snprintf(iv->endpoint, DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN,
                 "node%d.dnac.test:4004", i);
    }
}

static void test_roundtrip_seven(void) {
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);

    uint8_t buf[131072];
    size_t len = 0;
    CHECK(dnac_chain_def_encode(&cd, buf, sizeof(buf), &len) == 0);
    printf("encoded %zu bytes (with 7 initial_validators)\n", len);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    CHECK(dnac_chain_def_decode(buf, len, &decoded) == 0);

    /* Every field must byte-match. */
    CHECK(memcmp(&cd, &decoded, sizeof(cd)) == 0);

    /* Re-encode the decoded struct — must produce byte-identical blob. */
    uint8_t buf2[131072];
    size_t len2 = 0;
    CHECK(dnac_chain_def_encode(&decoded, buf2, sizeof(buf2), &len2) == 0);
    CHECK(len == len2);
    CHECK(memcmp(buf, buf2, len) == 0);
    printf("PASS test_roundtrip_seven\n");
}

static void test_expected_encoded_size(void) {
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);

    /* Pre-Task-56 baseline (without trailer) = 297 + 2 × 2592 = 5481 bytes.
     * Trailer = 1 + 7 × (2592 + 129 + 2 + 128) = 1 + 7 × 2851 = 19958 bytes.
     * Total expected = 5481 + 19958 = 25439 bytes. */
    size_t expected = 297 + (size_t)cd.witness_count * DNAC_PUBKEY_SIZE
                    + 1 + (size_t)DNAC_COMMITTEE_SIZE *
                        (DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE + 2 +
                         DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN);

    size_t actual = dnac_chain_def_encoded_size(&cd);
    printf("expected=%zu actual=%zu\n", expected, actual);
    CHECK(expected == actual);

    printf("PASS test_expected_encoded_size\n");
}

static void test_canonical_hash_postnul_malleability(void) {
    /* Proves: mutating a post-NUL byte of endpoint[128] changes the encoded
     * blob (so any downstream hash, e.g. chain_id, would differ).
     *
     * Scenario: set endpoint to "a:1" + zero padding, encode → blob1.
     *           Flip endpoint[127] = 0xFF (post-NUL mutation), encode → blob2.
     *           blob1 != blob2 (proves full-buffer participation). */
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);

    /* Use a short endpoint so we have real post-NUL bytes to mutate. */
    memset(cd.initial_validators[0].endpoint, 0,
           DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN);
    strcpy(cd.initial_validators[0].endpoint, "a:1");

    uint8_t buf1[131072];
    size_t len1 = 0;
    CHECK(dnac_chain_def_encode(&cd, buf1, sizeof(buf1), &len1) == 0);

    /* Mutate a post-NUL byte. */
    cd.initial_validators[0].endpoint[DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN - 1] =
        (char)0xFF;

    uint8_t buf2[131072];
    size_t len2 = 0;
    CHECK(dnac_chain_def_encode(&cd, buf2, sizeof(buf2), &len2) == 0);

    CHECK(len1 == len2);
    CHECK(memcmp(buf1, buf2, len1) != 0);  /* post-NUL byte participates */
    printf("PASS test_canonical_hash_postnul_malleability\n");
}

static void test_canonical_hash_fp_postnul(void) {
    /* Same as above but for unstake_destination_fp. */
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);

    memset(cd.initial_validators[0].unstake_destination_fp, 0,
           DNAC_FINGERPRINT_SIZE);
    strcpy(cd.initial_validators[0].unstake_destination_fp, "short-fp");

    uint8_t buf1[131072];
    size_t len1 = 0;
    CHECK(dnac_chain_def_encode(&cd, buf1, sizeof(buf1), &len1) == 0);

    cd.initial_validators[0].unstake_destination_fp[DNAC_FINGERPRINT_SIZE - 1] =
        (char)0x7F;

    uint8_t buf2[131072];
    size_t len2 = 0;
    CHECK(dnac_chain_def_encode(&cd, buf2, sizeof(buf2), &len2) == 0);
    CHECK(len1 == len2);
    CHECK(memcmp(buf1, buf2, len1) != 0);
    printf("PASS test_canonical_hash_fp_postnul\n");
}

static void test_reject_count_over_cap(void) {
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);
    cd.initial_validator_count = DNAC_COMMITTEE_SIZE + 1;  /* = 8, over cap */

    uint8_t buf[131072];
    size_t len = 0;
    CHECK(dnac_chain_def_encode(&cd, buf, sizeof(buf), &len) == -1);
    printf("PASS test_reject_count_over_cap\n");
}

static void test_zero_count_roundtrip(void) {
    /* Legacy chain_defs without initial_validators — count=0 is accepted
     * by the codec. Genesis verify Rule P rejects count!=7 separately. */
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);
    cd.initial_validator_count = 0;
    memset(cd.initial_validators, 0, sizeof(cd.initial_validators));

    uint8_t buf[131072];
    size_t len = 0;
    CHECK(dnac_chain_def_encode(&cd, buf, sizeof(buf), &len) == 0);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    CHECK(dnac_chain_def_decode(buf, len, &decoded) == 0);
    CHECK(decoded.initial_validator_count == 0);
    printf("PASS test_zero_count_roundtrip\n");
}

static void test_commission_bps_be_encoding(void) {
    /* Verify u16 big-endian on the wire for commission_bps. */
    dnac_chain_definition_t cd;
    fill_sample_with_validators(&cd);
    cd.initial_validators[0].commission_bps = 0x1234;

    uint8_t buf[131072];
    size_t len = 0;
    CHECK(dnac_chain_def_encode(&cd, buf, sizeof(buf), &len) == 0);

    /* Compute where iv[0].commission_bps lives in the blob. */
    size_t fixed = 297 + (size_t)cd.witness_count * DNAC_PUBKEY_SIZE + 1;
    size_t cbps_off = fixed + DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE;
    CHECK(buf[cbps_off]     == 0x12);
    CHECK(buf[cbps_off + 1] == 0x34);

    dnac_chain_definition_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    CHECK(dnac_chain_def_decode(buf, len, &decoded) == 0);
    CHECK(decoded.initial_validators[0].commission_bps == 0x1234);
    printf("PASS test_commission_bps_be_encoding\n");
}

int main(void) {
    test_roundtrip_seven();
    test_expected_encoded_size();
    test_canonical_hash_postnul_malleability();
    test_canonical_hash_fp_postnul();
    test_reject_count_over_cap();
    test_zero_count_roundtrip();
    test_commission_bps_be_encoding();
    printf("ALL PASS\n");
    return 0;
}
