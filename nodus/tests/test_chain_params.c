/**
 * Nodus — Ledger V2 S1: per-chain parameter boundary tests.
 *
 * Addendum #2 B1: genesis supply is a MANIFEST value, not a universal code
 * constant. This test pins the S1 state of that boundary:
 *   1. The official DNA fixture values: 1B supply (10^17 raw), 10M self-bond
 *      (10^15 raw) = exactly 1% of the DNA genesis supply.
 *   2. A synthetic third-party chain_def with a DIFFERENT committed supply
 *      flows through the SAME generic paths: the consensus-side supply
 *      parser (nodus_witness_parse_cd_supply — the value Rule P.2 and
 *      supply_tracking seeding actually consume) returns the committed
 *      per-chain value, not the DNA constant.
 *   3. Manifest-bound identity: changing initial_supply_raw changes the
 *      genesis block hash (= chain_id), because the chain_def is part of
 *      the genesis BlockID preimage.
 *
 * The self-bond term deliberately has NO per-chain test: chain_def carries
 * no min_self_bond field until the Season-6 manifest — the macro is the
 * single authoritative source on every path until then (explicit deferral,
 * S1 report §9).
 *
 * @file test_chain_params.c
 */

#include "dnac/dnac.h"
#include "dnac/block.h"
#include "dnac/chain_def_codec.h"
#include "witness/nodus_witness_genesis_seed.h"   /* nodus_witness_parse_cd_supply */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void fill(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static void make_cd(dnac_chain_definition_t *cd, const char *name,
                    uint64_t supply_raw) {
    memset(cd, 0, sizeof(*cd));
    snprintf(cd->chain_name, sizeof(cd->chain_name), "%s", name);
    cd->protocol_version = 2;
    snprintf(cd->genesis_message, sizeof(cd->genesis_message), "s1-param-test");
    cd->witness_count = 1;
    fill(cd->witness_pubkeys[0], DNAC_PUBKEY_SIZE, 0x77);
    cd->block_interval_sec = 5;
    cd->max_txs_per_block = 10;
    cd->view_change_timeout_ms = 5000;
    snprintf(cd->token_symbol, sizeof(cd->token_symbol), "TST");
    cd->token_decimals = 8;
    cd->initial_supply_raw = supply_raw;
}

int main(void) {
    /* 1. Official DNA fixture values (the DNA-mainnet manifest pins). */
    CHECK(DNAC_DEFAULT_TOTAL_SUPPLY == 100000000000000000ULL,
          "DNA genesis supply != 10^17 raw"); OK();
    CHECK(DNAC_SELF_STAKE_AMOUNT == 1000000000000000ULL,
          "DNA min self-bond != 10^15 raw"); OK();
    CHECK(DNAC_SELF_STAKE_AMOUNT == DNAC_DEFAULT_TOTAL_SUPPLY / 100,
          "self-bond != 1%% of DNA genesis supply"); OK();

    /* 2. Generic per-chain supply boundary (consensus-side parser). */
    dnac_chain_definition_t *cd_dna = malloc(sizeof(*cd_dna));
    dnac_chain_definition_t *cd_3p  = malloc(sizeof(*cd_3p));
    CHECK(cd_dna && cd_3p, "alloc");
    make_cd(cd_dna, "dna-fixture", DNAC_DEFAULT_TOTAL_SUPPLY);
    make_cd(cd_3p,  "third-party", 42ULL * 100000000ULL);   /* 42 tokens */

    uint8_t blob[8192];
    size_t blob_len = 0;
    uint64_t supply = 0;
    uint8_t vcount = 0;

    CHECK(dnac_chain_def_encode(cd_dna, blob, sizeof(blob), &blob_len) == 0,
          "encode dna cd");
    CHECK(nodus_witness_parse_cd_supply(blob, blob_len, &supply, &vcount) == 0,
          "parse dna cd");
    CHECK(supply == DNAC_DEFAULT_TOTAL_SUPPLY,
          "dna fixture supply not resolved through the generic path"); OK();

    CHECK(dnac_chain_def_encode(cd_3p, blob, sizeof(blob), &blob_len) == 0,
          "encode 3p cd");
    CHECK(nodus_witness_parse_cd_supply(blob, blob_len, &supply, &vcount) == 0,
          "parse 3p cd");
    CHECK(supply == 42ULL * 100000000ULL,
          "third-party supply not resolved through the generic path"); OK();

    /* 3. Manifest-bound identity: supply is committed into the genesis
     *    BlockID (= chain_id) — two chains differing only in supply are
     *    different chains. */
    dnac_block_t *b1 = calloc(1, sizeof(*b1));
    dnac_block_t *b2 = calloc(1, sizeof(*b2));
    dnac_block_t *b3 = calloc(1, sizeof(*b3));
    CHECK(b1 && b2 && b3, "alloc blocks");
    b1->block_height = 0;
    fill(b1->tx_root, DNAC_BLOCK_HASH_SIZE, 0x11);
    fill(b1->state_root, DNAC_BLOCK_HASH_SIZE, 0x22);
    fill(b1->proposer_id, DNAC_BLOCK_PROPOSER_SIZE, 0x33);
    b1->tx_count = 1;
    *b2 = *b1;
    *b3 = *b1;
    CHECK(dnac_block_set_genesis_def(b1, cd_dna) == 0, "set cd1");
    CHECK(dnac_block_set_genesis_def(b2, cd_3p) == 0, "set cd2");
    CHECK(dnac_block_set_genesis_def(b3, cd_dna) == 0, "set cd3");
    CHECK(dnac_block_compute_hash(b1) == 0, "hash1");
    CHECK(dnac_block_compute_hash(b2) == 0, "hash2");
    CHECK(dnac_block_compute_hash(b3) == 0, "hash3");
    CHECK(memcmp(b1->block_hash, b2->block_hash, DNAC_BLOCK_HASH_SIZE) != 0,
          "supply change did not change the chain identity"); OK();
    CHECK(memcmp(b1->block_hash, b3->block_hash, DNAC_BLOCK_HASH_SIZE) == 0,
          "genesis hash not deterministic"); OK();

    free(b1); free(b2); free(b3);
    free(cd_dna); free(cd_3p);
    printf("test_chain_params: %d checks OK\n", g_checks);
    return 0;
}
