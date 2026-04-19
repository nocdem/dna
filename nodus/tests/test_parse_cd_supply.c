/**
 * Nodus — test for nodus_witness_parse_cd_supply (genesis ghost stake fix).
 *
 * Builds a minimal chain_def blob matching Task 56's pinned layout and
 * verifies parse_cd_supply returns the correct initial_supply_raw and
 * initial_validator_count. Pure function, no DB, no witness state.
 */

#include "witness/nodus_witness_genesis_seed.h"
#include "dnac/dnac.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define CHECK_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK_TRUE fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

/* Layout (from nodus_witness_genesis_seed.c comment): */
#define CD_FIXED_BYTES  (32 + 4 + 64 + 64 + 4 + 4 + 4 + 4 + 4 + 8 + 1 + 8 + 64 + 32)
#define IV_ENTRY_BYTES  (DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE + 2 + 128)

static size_t build_cd(uint8_t *blob, uint32_t witness_count,
                       uint64_t initial_supply_raw,
                       uint8_t initial_validator_count) {
    size_t off = 0;
    /* chain_name(32) */          memset(blob + off, 'A', 32);               off += 32;
    /* protocol_version(4 LE) */  blob[off]=1; blob[off+1]=0; blob[off+2]=0; blob[off+3]=0; off += 4;
    /* parent_chain_id(64) */     memset(blob + off, 0, 64);                 off += 64;
    /* genesis_message(64) */     memset(blob + off, 0, 64);                 off += 64;
    /* witness_count(4 LE) */
    blob[off+0] = (uint8_t)(witness_count & 0xff);
    blob[off+1] = (uint8_t)((witness_count >> 8) & 0xff);
    blob[off+2] = (uint8_t)((witness_count >> 16) & 0xff);
    blob[off+3] = (uint8_t)((witness_count >> 24) & 0xff);
    off += 4;
    /* max_active_witnesses(4) */ blob[off]=21; blob[off+1]=0; blob[off+2]=0; blob[off+3]=0; off += 4;
    /* witness_pubkeys */         memset(blob + off, 0xA5, (size_t)witness_count * DNAC_PUBKEY_SIZE);
                                  off += (size_t)witness_count * DNAC_PUBKEY_SIZE;
    /* block_interval_sec(4) */   blob[off]=5; blob[off+1]=0; blob[off+2]=0; blob[off+3]=0; off += 4;
    /* max_txs_per_block(4) */    blob[off]=10; blob[off+1]=0; blob[off+2]=0; blob[off+3]=0; off += 4;
    /* view_change_timeout(4) */  blob[off]=0x88; blob[off+1]=0x13; blob[off+2]=0; blob[off+3]=0; off += 4; /* 5000ms */
    /* token_symbol(8) */         memset(blob + off, 0, 8); memcpy(blob + off, "DNAC", 4); off += 8;
    /* token_decimals(1) */       blob[off++] = 8;
    /* initial_supply_raw(8 LE) */
    for (int i = 0; i < 8; i++) blob[off + i] = (uint8_t)((initial_supply_raw >> (i * 8)) & 0xff);
    off += 8;
    /* native_token_id(64) */     memset(blob + off, 0, 64);                 off += 64;
    /* fee_recipient(32) */       memset(blob + off, 0, 32);                 off += 32;
    /* initial_validator_count(1) */
    blob[off++] = initial_validator_count;
    /* iv entries — dummy bytes, parse_cd_supply doesn't read them */
    for (int i = 0; i < initial_validator_count; i++) {
        memset(blob + off, (uint8_t)(i + 1), IV_ENTRY_BYTES);
        off += IV_ENTRY_BYTES;
    }
    return off;
}

int main(void) {
    static uint8_t blob[65536];
    size_t len;
    uint64_t supply_out = 0;
    uint8_t  count_out  = 0;

    /* 1. Standard 1B supply, 7 validators, witness_count=7. */
    len = build_cd(blob, /*wc*/7, DNAC_DEFAULT_TOTAL_SUPPLY, /*iv*/7);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, &supply_out, &count_out), 0);
    CHECK_EQ(supply_out, DNAC_DEFAULT_TOTAL_SUPPLY);
    CHECK_EQ(count_out, 7);
    fprintf(stderr, "test 1: 1B/7v OK (supply=%llu count=%u)\n",
            (unsigned long long)supply_out, (unsigned)count_out);

    /* 2. Different supply value, 5 validators. */
    len = build_cd(blob, /*wc*/5, 500000000ULL, /*iv*/5);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, &supply_out, &count_out), 0);
    CHECK_EQ(supply_out, 500000000ULL);
    CHECK_EQ(count_out, 5);
    fprintf(stderr, "test 2: 500M/5v OK\n");

    /* 3. Zero-validator (legacy chain_def sans trailer) — supply parsed,
     *    count=0. */
    /* Build with iv=0 (skip trailer byte): just reserve the count byte = 0. */
    len = build_cd(blob, /*wc*/3, 999000000000ULL, /*iv*/0);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, &supply_out, &count_out), 0);
    CHECK_EQ(supply_out, 999000000000ULL);
    CHECK_EQ(count_out, 0);
    fprintf(stderr, "test 3: legacy blob OK\n");

    /* 4. NULL / zero-len rejected. */
    CHECK_EQ(nodus_witness_parse_cd_supply(NULL, 0, &supply_out, &count_out), -1);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, 0, &supply_out, &count_out), -1);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, 10, &supply_out, &count_out), -1);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, NULL, &count_out), -1);
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, &supply_out, NULL), -1);
    fprintf(stderr, "test 4: arg validation OK\n");

    /* 5. witness_count > 21 → reject. */
    uint8_t *p_wc = blob + 32 + 4 + 64 + 64;
    p_wc[0] = 99;  /* 99 < 256, so fits in one byte; witness_count = 99 LE */
    CHECK_EQ(nodus_witness_parse_cd_supply(blob, len, &supply_out, &count_out), -1);
    fprintf(stderr, "test 5: witness_count>21 rejected\n");

    fprintf(stderr, "PASS test_parse_cd_supply\n");
    return 0;
}
