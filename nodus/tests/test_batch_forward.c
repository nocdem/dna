/**
 * Test: batch forward crash reproduction
 * Sends get_batch with keys that are NOT on the connected node's local storage
 * to trigger the forward code path on the server.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

/* SHA3-512 hash of a string key */
static void hash_str(const char *str, nodus_key_t *out) {
    /* Use the same hash as nodus_ops */
    extern void nodus_sha3_512(const uint8_t *data, size_t len, uint8_t *out);
    nodus_sha3_512((const uint8_t *)str, strlen(str), out->bytes);
}

int main(int argc, char **argv) {
    const char *server_ip = argc > 1 ? argv[1] : "161.97.85.25";
    uint16_t port = 4001;

    printf("=== Batch Forward Crash Test ===\n");
    printf("Connecting to %s:%d...\n", server_ip, port);

    /* Generate identity */
    nodus_identity_t id;
    if (nodus_identity_generate(&id) != 0) {
        fprintf(stderr, "Failed to generate identity\n");
        return 1;
    }

    /* Connect */
    nodus_client_config_t config;
    memset(&config, 0, sizeof(config));
    config.servers[0] = (nodus_server_endpoint_t){ .port = port };
    strncpy(config.servers[0].ip, server_ip, sizeof(config.servers[0].ip) - 1);
    config.server_count = 1;
    config.request_timeout_ms = 15000;

    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    if (nodus_client_init(&client, &config, &id) != 0) {
        fprintf(stderr, "Client init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "Connect failed\n");
        return 1;
    }

    printf("Connected and authenticated.\n");

    /* Build keys that are unlikely to be on local storage */
    const char *test_keys[] = {
        "dna:channels:meta:00000000-0000-0000-0000-000000000001",
        "dna:channels:meta:00000000-0000-0000-0000-000000000002",
        "dna:channels:meta:00000000-0000-0000-0000-000000000003",
        "dna:channels:meta:00000000-0000-0000-0000-000000000004",
        "dna:channels:meta:00000000-0000-0000-0000-000000000005",
    };
    int key_count = 5;

    nodus_key_t keys[5];
    for (int i = 0; i < key_count; i++) {
        hash_str(test_keys[i], &keys[i]);
    }

    printf("Sending get_batch with %d keys (all should miss locally)...\n", key_count);

    nodus_batch_result_t *results = NULL;
    int result_count = 0;
    int rc = nodus_client_get_batch(&client, keys, key_count, &results, &result_count);

    printf("get_batch returned: rc=%d, result_count=%d\n", rc, result_count);

    if (rc == 0 && results) {
        for (int i = 0; i < result_count; i++) {
            printf("  key[%d]: %zu values\n", i, results[i].count);
        }
        nodus_client_free_batch_result(results, result_count);
    }

    /* Try again with real channel keys */
    printf("\nSending get_batch with real channel keys...\n");
    const char *real_keys[] = {
        "dna:channels:meta:94e8ed2b-92fe-46f5-bf44-65af1483e55e",
        "dna:channels:meta:5b17b54a-43ed-475e-ad3b-d5fa46907210",
        "dna:channels:meta:11191eee-4173-4f30-a35d-de8fefbef7d8",
    };
    int real_count = 3;
    nodus_key_t real_hashed[3];
    for (int i = 0; i < real_count; i++) {
        hash_str(real_keys[i], &real_hashed[i]);
    }

    results = NULL;
    result_count = 0;
    rc = nodus_client_get_batch(&client, real_hashed, real_count, &results, &result_count);

    printf("get_batch returned: rc=%d, result_count=%d\n", rc, result_count);
    if (rc == 0 && results) {
        for (int i = 0; i < result_count; i++) {
            printf("  key[%d]: %zu values\n", i, results[i].count);
        }
        nodus_client_free_batch_result(results, result_count);
    }

    /* Repeat 10 times to stress test */
    printf("\nStress test: 10 rapid get_batch calls...\n");
    for (int t = 0; t < 10; t++) {
        results = NULL;
        result_count = 0;
        rc = nodus_client_get_batch(&client, keys, key_count, &results, &result_count);
        printf("  [%d] rc=%d results=%d\n", t, rc, result_count);
        if (results) nodus_client_free_batch_result(results, result_count);
    }

    printf("\nDone. Server should still be alive.\n");

    nodus_client_close(&client);
    return 0;
}
