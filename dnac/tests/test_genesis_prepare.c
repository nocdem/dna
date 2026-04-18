/**
 * @file test_genesis_prepare.c
 * @brief Phase 12 Task 58 — dnac_cli_genesis_prepare_blob round-trip.
 *
 * Writes a mock config file with 7 initial_validators, calls
 * dnac_cli_genesis_prepare_blob, then decodes the output blob via
 * dnac_chain_def_decode and verifies the validators round-trip with
 * byte-identical fields (pubkey, fp, commission_bps, endpoint).
 *
 * Also covers:
 *   - Missing validator entry → error
 *   - Duplicate pubkey → error (Rule P.3 canary)
 *   - Unknown key → error
 */

#include "dnac/genesis_prepare.h"
#include "dnac/chain_def_codec.h"
#include "dnac/block.h"
#include "dnac/dnac.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

/* Write a patterned 2592-byte pubkey hex (5184 chars) for index `i`. */
static void write_pubkey_hex(FILE *f, int key_idx, int seed) {
    fprintf(f, "validator_%d_pubkey=", key_idx);
    for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
        uint8_t v = (uint8_t)((b + 31 * (seed + 1)) & 0xff);
        fprintf(f, "%02x", v);
    }
    fprintf(f, "\n");
}

/* Return the patterned pubkey bytes. */
static void patterned_pubkey(uint8_t out[DNAC_PUBKEY_SIZE], int seed) {
    for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
        out[b] = (uint8_t)((b + 31 * (seed + 1)) & 0xff);
    }
}

static const char *make_tmp_path(char buf[64]) {
    strcpy(buf, "/tmp/test_genesis_prepare_XXXXXX");
    int fd = mkstemp(buf);
    CHECK(fd >= 0);
    close(fd);
    return buf;
}

static void test_full_roundtrip(void) {
    char path[64];
    make_tmp_path(path);

    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fprintf(f, "# Phase 12 Task 58 — mock operator config\n");
    fprintf(f, "chain_name=mainnet-test\n");
    fprintf(f, "protocol_version=1\n");
    fprintf(f, "witness_count=0\n");
    fprintf(f, "max_active_witnesses=21\n");
    fprintf(f, "block_interval_sec=5\n");
    fprintf(f, "genesis_message=mock genesis\n");
    fprintf(f, "initial_supply_raw=100000000000000000\n");
    for (int i = 0; i < 7; i++) {
        write_pubkey_hex(f, i, i);
        fprintf(f, "validator_%d_fp=fp-%d\n", i, i);
        fprintf(f, "validator_%d_commission_bps=%d\n", i, 100 * i);
        fprintf(f, "validator_%d_endpoint=node%d.dnac.test:4004\n", i, i);
    }
    fclose(f);

    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256] = {0};

    int rc = dnac_cli_genesis_prepare_blob(path, blob, sizeof(blob),
                                             &blob_len, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "prepare failed: %s\n", err);
    }
    CHECK(rc == 0);
    CHECK(blob_len > 0);

    /* Decode and verify. */
    dnac_chain_definition_t cd;
    memset(&cd, 0, sizeof(cd));
    CHECK(dnac_chain_def_decode(blob, blob_len, &cd) == 0);
    CHECK(cd.initial_validator_count == DNAC_COMMITTEE_SIZE);
    CHECK(strcmp(cd.chain_name, "mainnet-test") == 0);
    CHECK(cd.protocol_version == 1);
    CHECK(cd.block_interval_sec == 5);

    for (int i = 0; i < 7; i++) {
        uint8_t expected[DNAC_PUBKEY_SIZE];
        patterned_pubkey(expected, i);
        CHECK(memcmp(cd.initial_validators[i].pubkey, expected,
                     DNAC_PUBKEY_SIZE) == 0);

        char expected_fp[8];
        snprintf(expected_fp, sizeof(expected_fp), "fp-%d", i);
        CHECK(strcmp(cd.initial_validators[i].unstake_destination_fp,
                     expected_fp) == 0);

        CHECK(cd.initial_validators[i].commission_bps == 100 * i);

        char expected_ep[32];
        snprintf(expected_ep, sizeof(expected_ep), "node%d.dnac.test:4004", i);
        CHECK(strcmp(cd.initial_validators[i].endpoint, expected_ep) == 0);
    }

    unlink(path);
    printf("PASS test_full_roundtrip\n");
}

static void test_missing_validator(void) {
    /* Only populate 6 of 7 validators — prepare must fail. */
    char path[64];
    make_tmp_path(path);

    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fprintf(f, "chain_name=partial-test\n");
    for (int i = 0; i < 6; i++) {
        write_pubkey_hex(f, i, i);
        fprintf(f, "validator_%d_fp=fp-%d\n", i, i);
        fprintf(f, "validator_%d_commission_bps=0\n", i);
        fprintf(f, "validator_%d_endpoint=n%d\n", i, i);
    }
    fclose(f);

    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256] = {0};

    CHECK(dnac_cli_genesis_prepare_blob(path, blob, sizeof(blob),
                                          &blob_len, err, sizeof(err)) == -1);
    CHECK(strstr(err, "missing") != NULL);  /* hint: "validator_6_... missing" */

    unlink(path);
    printf("PASS test_missing_validator\n");
}

static void test_duplicate_pubkey(void) {
    char path[64];
    make_tmp_path(path);

    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fprintf(f, "chain_name=dup-test\n");
    for (int i = 0; i < 7; i++) {
        /* All 7 use seed=0 → identical pubkeys. */
        write_pubkey_hex(f, i, 0);
        fprintf(f, "validator_%d_fp=fp-%d\n", i, i);
        fprintf(f, "validator_%d_commission_bps=0\n", i);
        fprintf(f, "validator_%d_endpoint=n%d\n", i, i);
    }
    fclose(f);

    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256] = {0};

    CHECK(dnac_cli_genesis_prepare_blob(path, blob, sizeof(blob),
                                          &blob_len, err, sizeof(err)) == -1);
    CHECK(strstr(err, "duplicate") != NULL);

    unlink(path);
    printf("PASS test_duplicate_pubkey\n");
}

static void test_unknown_key(void) {
    char path[64];
    make_tmp_path(path);

    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fprintf(f, "chain_name=unknown-key-test\n");
    fprintf(f, "bogus_field=42\n");   /* should trigger unknown-key error */
    fclose(f);

    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256] = {0};

    CHECK(dnac_cli_genesis_prepare_blob(path, blob, sizeof(blob),
                                          &blob_len, err, sizeof(err)) == -1);
    CHECK(strstr(err, "unknown key") != NULL);

    unlink(path);
    printf("PASS test_unknown_key\n");
}

static void test_commission_range(void) {
    char path[64];
    make_tmp_path(path);

    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    fprintf(f, "chain_name=comm-test\n");
    for (int i = 0; i < 7; i++) {
        write_pubkey_hex(f, i, i);
        fprintf(f, "validator_%d_fp=fp-%d\n", i, i);
        fprintf(f, "validator_%d_commission_bps=%s\n",
                i, (i == 3) ? "10001" : "500");  /* one out-of-range */
        fprintf(f, "validator_%d_endpoint=n%d\n", i, i);
    }
    fclose(f);

    uint8_t blob[65536];
    size_t  blob_len = 0;
    char    err[256] = {0};

    CHECK(dnac_cli_genesis_prepare_blob(path, blob, sizeof(blob),
                                          &blob_len, err, sizeof(err)) == -1);
    CHECK(strstr(err, "commission_bps") != NULL);

    unlink(path);
    printf("PASS test_commission_range\n");
}

int main(void) {
    test_full_roundtrip();
    test_missing_validator();
    test_duplicate_pubkey();
    test_unknown_key();
    test_commission_range();
    printf("ALL PASS\n");
    return 0;
}
