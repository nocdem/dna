/**
 * Test: batch get vs individual get with REAL data.
 * Compares results to prove batch forward actually returns data.
 */
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static nodus_identity_t test_id;

static void hash_key(const char *str, nodus_key_t *out) {
    /* SHA3-512 — same as nodus_ops hash_str */
    extern void qgp_sha3_512(const uint8_t *data, size_t len, uint8_t *out);
    qgp_sha3_512((const uint8_t *)str, strlen(str), out->bytes);
}

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "164.68.105.227";
    uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 4001;

    printf("=== Batch vs Individual — Real Data Test ===\n");
    printf("Server: %s:%d\n\n", ip, port);

    uint8_t seed[32]; memset(seed, 0xBB, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.servers[0].ip, ip, 63);
    cfg.servers[0].port = port;
    cfg.server_count = 1;
    cfg.request_timeout_ms = 15000;

    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    if (nodus_client_init(&client, &cfg, &test_id) != 0 ||
        nodus_client_connect(&client) != 0) {
        fprintf(stderr, "FAIL: connect\n");
        return 1;
    }
    printf("Connected.\n\n");

    /* Real channel metadata keys */
    const char *str_keys[] = {
        "dna:channels:meta:94e8ed2b-92fe-46f5-bf44-65af1483e55e",  /* General */
        "dna:channels:meta:5b17b54a-43ed-475e-ad3b-d5fa46907210",
        "dna:channels:meta:11191eee-4173-4f30-a35d-de8fefbef7d8",
    };
    int nkeys = 3;

    nodus_key_t keys[3];
    for (int i = 0; i < nkeys; i++)
        hash_key(str_keys[i], &keys[i]);

    /* Test 1: Individual get for each key */
    printf("=== Test 1: Individual GET (Kademlia FIND_VALUE) ===\n");
    for (int i = 0; i < nkeys; i++) {
        nodus_value_t *val = NULL;
        int rc = nodus_client_get(&client, &keys[i], &val);
        printf("  key[%d]: rc=%d data=%s (%zu bytes)\n", i, rc,
               val ? "YES" : "NO", val ? val->data_len : 0);
        if (val) nodus_value_free(val);
    }

    /* Test 2: Batch get for same keys */
    printf("\n=== Test 2: BATCH GET (forward to closest peer) ===\n");
    nodus_batch_result_t *results = NULL;
    int count = 0;
    int rc = nodus_client_get_batch(&client, keys, nkeys, &results, &count);
    printf("  rc=%d result_count=%d\n", rc, count);
    if (results) {
        for (int i = 0; i < count; i++) {
            size_t total_bytes = 0;
            for (size_t j = 0; j < results[i].count; j++)
                if (results[i].vals[j]) total_bytes += results[i].vals[j]->data_len;
            printf("  key[%d]: values=%zu total_bytes=%zu\n",
                   i, results[i].count, total_bytes);
        }
        nodus_client_free_batch_result(results, count);
    }

    /* Test 3: Compare — batch should return same data as individual */
    printf("\n=== Test 3: Comparison ===\n");
    int batch_has_data = 0;
    int individual_has_data = 0;

    results = NULL; count = 0;
    rc = nodus_client_get_batch(&client, keys, nkeys, &results, &count);
    for (int i = 0; i < nkeys; i++) {
        nodus_value_t *val = NULL;
        int irc = nodus_client_get(&client, &keys[i], &val);
        int i_has = (irc == 0 && val && val->data_len > 0);
        int b_has = (i < count && results && results[i].count > 0);
        printf("  key[%d]: individual=%s batch=%s %s\n", i,
               i_has ? "YES" : "NO", b_has ? "YES" : "NO",
               (i_has == b_has) ? "MATCH" : "*** MISMATCH ***");
        if (i_has) individual_has_data++;
        if (b_has) batch_has_data++;
        if (val) nodus_value_free(val);
    }
    if (results) nodus_client_free_batch_result(results, count);

    printf("\nIndividual: %d/%d  Batch: %d/%d\n", individual_has_data, nkeys, batch_has_data, nkeys);
    printf("Result: %s\n", (individual_has_data == batch_has_data) ? "PASS" : "FAIL — batch missing data!");

    nodus_client_close(&client);
    return (individual_has_data == batch_has_data) ? 0 : 1;
}
