/**
 * Live test: get_batch with keys NOT in local storage → triggers server forward.
 * Run against a real nodus server to reproduce forward-related SEGV.
 *
 * Usage: ./test_batch_forward_live [server_ip] [port]
 */
#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include "crypto/nodus_identity.h"
#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static nodus_identity_t test_id;

static void init_id(void) {
    uint8_t seed[32];
    memset(seed, 0xAA, sizeof(seed));
    nodus_identity_from_seed(seed, &test_id);
}

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "161.97.85.25";
    uint16_t port = argc > 2 ? (uint16_t)atoi(argv[2]) : 4001;

    printf("=== Batch Forward Live Test ===\n");
    init_id();

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.servers[0].ip, ip, 63);
    cfg.servers[0].port = port;
    cfg.server_count = 1;
    cfg.request_timeout_ms = 15000;

    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    if (nodus_client_init(&client, &cfg, &test_id) != 0) {
        fprintf(stderr, "FAIL: client init\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "FAIL: connect to %s:%d\n", ip, port);
        nodus_client_close(&client);
        return 1;
    }
    printf("Connected to %s:%d\n\n", ip, port);

    /* Test 1: Fake keys (guaranteed local miss → forward) */
    printf("Test 1: 5 fake keys (all miss → forward)...\n");
    nodus_key_t fake_keys[5];
    for (int i = 0; i < 5; i++) {
        memset(&fake_keys[i], 0x10 + i, sizeof(nodus_key_t));
    }

    nodus_batch_result_t *results = NULL;
    int count = 0;
    int rc = nodus_client_get_batch(&client, fake_keys, 5, &results, &count);
    printf("  rc=%d count=%d\n", rc, count);
    if (results) nodus_client_free_batch_result(results, count);

    /* Check server alive */
    nodus_value_t *ping_val = NULL;
    rc = nodus_client_get(&client, &fake_keys[0], &ping_val);
    printf("  Server alive after test 1: %s\n\n", (rc == 0 || rc == 2) ? "YES" : "NO");
    if (ping_val) nodus_value_free(ping_val);

    /* Test 2: Rapid fire 20 batch calls */
    printf("Test 2: 20 rapid fake batch calls...\n");
    for (int t = 0; t < 20; t++) {
        results = NULL; count = 0;
        rc = nodus_client_get_batch(&client, fake_keys, 5, &results, &count);
        printf("  [%02d] rc=%d count=%d\n", t, rc, count);
        if (results) nodus_client_free_batch_result(results, count);
        if (rc != 0 && rc != 2) {
            printf("  ERROR: batch failed, server may have crashed\n");
            break;
        }
    }

    /* Test 3: Mix of hits and misses */
    printf("\nTest 3: mixed keys (some real, some fake)...\n");
    nodus_key_t mixed[4];
    memset(&mixed[0], 0x30, sizeof(nodus_key_t));  /* fake */
    memset(&mixed[1], 0x31, sizeof(nodus_key_t));  /* fake */
    memset(&mixed[2], 0x32, sizeof(nodus_key_t));  /* fake */
    memset(&mixed[3], 0x33, sizeof(nodus_key_t));  /* fake */
    results = NULL; count = 0;
    rc = nodus_client_get_batch(&client, mixed, 4, &results, &count);
    printf("  rc=%d count=%d\n", rc, count);
    if (results) nodus_client_free_batch_result(results, count);

    printf("\n=== All tests complete. Server status: ");
    ping_val = NULL;
    rc = nodus_client_get(&client, &fake_keys[0], &ping_val);
    printf("%s ===\n", (rc == 0 || rc == 2) ? "ALIVE" : "DEAD/DISCONNECTED");
    if (ping_val) nodus_value_free(ping_val);

    nodus_client_close(&client);
    return 0;
}
