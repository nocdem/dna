/**
 * Test OpenDHT Signed Put Behavior
 *
 * Critical question: Does putSigned() with same value_id REPLACE old values
 * or ACCUMULATE them like unsigned put()?
 *
 * Test scenario:
 * 1. PUT value1 with id=1, seq=0
 * 2. Wait for propagation
 * 3. GET and count values
 * 4. PUT value2 with id=1, seq=1
 * 5. Wait for propagation
 * 6. GET and count values
 *
 * Expected (replacement): Step 6 returns 1 value (only latest)
 * Actual (accumulation): Step 6 returns 2+ values (all versions)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core/dht_context.h"

#define TEST_KEY_STRING "test_signed_put_key_12345"

void print_separator() {
    printf("\n========================================\n\n");
}

int main() {
    printf("OpenDHT Signed Put Replacement Test\n");
    print_separator();

    // 1. Initialize DHT context
    printf("Step 1: Initializing DHT context...\n");

    dht_config_t config = {0};
    config.port = 4007;  // Use different port to avoid conflicts
    config.is_bootstrap = false;
    snprintf(config.identity, sizeof(config.identity), "test_signed_put");

    // Add bootstrap nodes
    snprintf(config.bootstrap_nodes[0], 256, "154.38.182.161:4000");
    snprintf(config.bootstrap_nodes[1], 256, "164.68.105.227:4000");
    snprintf(config.bootstrap_nodes[2], 256, "164.68.116.180:4000");
    config.bootstrap_count = 3;

    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        fprintf(stderr, "Failed to create DHT context\n");
        return 1;
    }

    if (dht_context_start(ctx) != 0) {
        fprintf(stderr, "Failed to start DHT\n");
        dht_context_free(ctx);
        return 1;
    }

    printf("✓ DHT started on port %d\n", config.port);

    // Wait for DHT to connect
    printf("Waiting for DHT to connect to network (10 seconds)...\n");
    sleep(10);

    if (!dht_context_is_ready(ctx)) {
        printf("⚠ Warning: DHT may not be fully connected\n");
    } else {
        printf("✓ DHT is ready\n");
    }

    print_separator();

    // 2. Generate test key
    printf("Step 2: Generating test key...\n");
    uint8_t test_key[64];
    memset(test_key, 0, sizeof(test_key));

    // Use SHA3-512 for consistent key
    const char *key_str = TEST_KEY_STRING;
    extern void qgp_sha3_512(const uint8_t *data, size_t len, uint8_t *hash);
    qgp_sha3_512((const uint8_t*)key_str, strlen(key_str), test_key);

    printf("Test key: %s\n", key_str);
    printf("SHA3-512 hash (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           test_key[0], test_key[1], test_key[2], test_key[3],
           test_key[4], test_key[5], test_key[6], test_key[7]);

    print_separator();

    // 3. First signed put
    printf("Step 3: First signed PUT (value_id=1, data='version1')...\n");

    const char *data1 = "version1";
    int result1 = dht_put_signed(ctx, test_key, 64,
                                 (const uint8_t*)data1, strlen(data1),
                                 1,  // value_id = 1
                                 0); // ttl = default (7 days)

    if (result1 != 0) {
        fprintf(stderr, "✗ First PUT failed\n");
        dht_context_free(ctx);
        return 1;
    }

    printf("✓ First PUT successful\n");
    printf("Waiting 15 seconds for DHT propagation...\n");
    sleep(15);

    print_separator();

    // 4. Check how many values after first put
    printf("Step 4: GET after first PUT...\n");

    uint8_t **values1 = NULL;
    size_t *lengths1 = NULL;
    size_t count1 = 0;

    int get_result1 = dht_get_all(ctx, test_key, 64, &values1, &lengths1, &count1);

    if (get_result1 == 0 && count1 > 0) {
        printf("✓ Found %zu value(s) in DHT\n", count1);
        for (size_t i = 0; i < count1; i++) {
            printf("  Value %zu: %zu bytes = '%.*s'\n",
                   i+1, lengths1[i], (int)lengths1[i], values1[i]);
        }

        // Free values
        for (size_t i = 0; i < count1; i++) {
            free(values1[i]);
        }
        free(values1);
        free(lengths1);
    } else {
        printf("✗ No values found (DHT not propagated yet?)\n");
    }

    print_separator();

    // 5. Second signed put (same value_id, new data)
    printf("Step 5: Second signed PUT (value_id=1, data='version2_updated')...\n");

    const char *data2 = "version2_updated";
    int result2 = dht_put_signed(ctx, test_key, 64,
                                 (const uint8_t*)data2, strlen(data2),
                                 1,  // SAME value_id = 1
                                 0);

    if (result2 != 0) {
        fprintf(stderr, "✗ Second PUT failed\n");
        dht_context_free(ctx);
        return 1;
    }

    printf("✓ Second PUT successful\n");
    printf("Waiting 15 seconds for DHT propagation...\n");
    sleep(15);

    print_separator();

    // 6. Check how many values after second put (CRITICAL TEST)
    printf("Step 6: GET after second PUT (CRITICAL TEST)...\n");

    uint8_t **values2 = NULL;
    size_t *lengths2 = NULL;
    size_t count2 = 0;

    int get_result2 = dht_get_all(ctx, test_key, 64, &values2, &lengths2, &count2);

    if (get_result2 == 0 && count2 > 0) {
        printf("Found %zu value(s) in DHT\n", count2);
        for (size_t i = 0; i < count2; i++) {
            printf("  Value %zu: %zu bytes = '%.*s'\n",
                   i+1, lengths2[i], (int)lengths2[i], values2[i]);
        }

        print_separator();

        // Analysis
        printf("RESULT ANALYSIS:\n\n");

        if (count2 == 1) {
            printf("✓✓✓ REPLACEMENT WORKS! ✓✓✓\n");
            printf("Only 1 value found (the latest one)\n");
            printf("Old value was REPLACED by new value\n");
            printf("\n");
            printf("This means Model E (sender outbox) is VIABLE!\n");
            printf("Signed puts with same value_id will prevent accumulation.\n");
        } else if (count2 == 2) {
            printf("✗✗✗ ACCUMULATION STILL HAPPENS ✗✗✗\n");
            printf("Found 2 values (both versions kept)\n");
            printf("Old value was NOT replaced\n");
            printf("\n");
            printf("This means Model E will NOT solve accumulation problem.\n");
            printf("Need to find alternative approach.\n");
        } else {
            printf("⚠⚠⚠ UNEXPECTED RESULT ⚠⚠⚠\n");
            printf("Found %zu values (unexpected count)\n", count2);
            printf("Need to investigate further.\n");
        }

        // Free values
        for (size_t i = 0; i < count2; i++) {
            free(values2[i]);
        }
        free(values2);
        free(lengths2);
    } else {
        printf("✗ No values found (DHT retrieval failed)\n");
    }

    print_separator();

    // 7. Third put to confirm pattern
    printf("Step 7: Third signed PUT (value_id=1, data='version3_final')...\n");

    const char *data3 = "version3_final";
    int result3 = dht_put_signed(ctx, test_key, 64,
                                 (const uint8_t*)data3, strlen(data3),
                                 1,  // SAME value_id = 1
                                 0);

    if (result3 != 0) {
        fprintf(stderr, "✗ Third PUT failed\n");
        dht_context_free(ctx);
        return 1;
    }

    printf("✓ Third PUT successful\n");
    printf("Waiting 15 seconds for DHT propagation...\n");
    sleep(15);

    print_separator();

    // 8. Final check
    printf("Step 8: Final GET (confirm pattern)...\n");

    uint8_t **values3 = NULL;
    size_t *lengths3 = NULL;
    size_t count3 = 0;

    int get_result3 = dht_get_all(ctx, test_key, 64, &values3, &lengths3, &count3);

    if (get_result3 == 0 && count3 > 0) {
        printf("Found %zu value(s) in DHT\n", count3);
        for (size_t i = 0; i < count3; i++) {
            printf("  Value %zu: %zu bytes = '%.*s'\n",
                   i+1, lengths3[i], (int)lengths3[i], values3[i]);
        }

        print_separator();

        printf("FINAL CONCLUSION:\n\n");

        if (count3 == 1) {
            printf("✓ Pattern confirmed: Only 1 value (replacement works)\n");
            printf("Model E (sender outbox) is HIGHLY RECOMMENDED\n");
        } else if (count3 == 3) {
            printf("✗ Pattern confirmed: 3 values (accumulation happens)\n");
            printf("Model E will NOT solve the problem\n");
        } else {
            printf("Count: %zu values\n", count3);
            printf("Need further investigation\n");
        }

        // Free values
        for (size_t i = 0; i < count3; i++) {
            free(values3[i]);
        }
        free(values3);
        free(lengths3);
    } else {
        printf("✗ No values found\n");
    }

    print_separator();

    // Cleanup
    printf("Cleanup: Stopping DHT...\n");
    dht_context_free(ctx);

    printf("✓ Test complete\n");

    return 0;
}
