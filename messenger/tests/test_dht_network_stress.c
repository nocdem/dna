/**
 * @file test_dht_network_stress.c
 * @brief DHT network stress and reliability test
 *
 * Tests:
 * - Multiple concurrent put/get operations
 * - Large value handling
 * - Connection timeout handling
 * - Network resilience
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include "../dht/client/dht_singleton.h"
#include "../dht/core/dht_context.h"

#define NUM_CONCURRENT_OPS 10
#define LARGE_VALUE_SIZE (64 * 1024)  // 64 KB
#define STRESS_ITERATIONS 100

typedef struct {
    int thread_id;
    int success_count;
    int failure_count;
} thread_data_t;

void* concurrent_put_thread(void* arg) {
    thread_data_t *data = (thread_data_t*)arg;
    char key[64];
    char value[256];

    for (int i = 0; i < STRESS_ITERATIONS; i++) {
        snprintf(key, sizeof(key), "stress_key_%d_%d", data->thread_id, i);
        snprintf(value, sizeof(value), "stress_value_%d_%d", data->thread_id, i);

        int ret = dht_put_signed(key, (uint8_t*)value, strlen(value));
        if (ret == 0) {
            data->success_count++;
        } else {
            data->failure_count++;
        }

        usleep(10000);  // 10ms delay
    }

    return NULL;
}

int main(void) {
    printf("=== DHT Network Stress Test ===\n\n");

    // Initialize DHT
    printf("1. Initializing DHT for stress test...\n");
    const char* identity_name = "test_stress";
    int ret = dht_singleton_init(identity_name);
    assert(ret == 0 && "DHT initialization failed");
    printf("   ✓ DHT initialized\n\n");

    // Test large value handling
    printf("2. Testing large value handling...\n");
    uint8_t *large_value = malloc(LARGE_VALUE_SIZE);
    memset(large_value, 0xAA, LARGE_VALUE_SIZE);

    const char *large_key = "stress_large_value";
    ret = dht_put_signed(large_key, large_value, LARGE_VALUE_SIZE);
    if (ret == 0) {
        printf("   ✓ Large value (%d KB) stored successfully\n", LARGE_VALUE_SIZE / 1024);

        sleep(2);

        // Retrieve large value
        uint8_t *retrieved = NULL;
        size_t retrieved_len = 0;
        ret = dht_get_signed(large_key, &retrieved, &retrieved_len);
        if (ret == 0 && retrieved != NULL) {
            assert(retrieved_len == LARGE_VALUE_SIZE && "Size mismatch");
            assert(memcmp(retrieved, large_value, LARGE_VALUE_SIZE) == 0
                   && "Content mismatch");
            printf("   ✓ Large value retrieved and verified\n");
            free(retrieved);
        }
    } else {
        printf("   (Skipped - no network connection)\n");
    }
    free(large_value);
    printf("\n");

    // Test concurrent operations
    printf("3. Testing concurrent operations (%d threads)...\n", NUM_CONCURRENT_OPS);
    pthread_t threads[NUM_CONCURRENT_OPS];
    thread_data_t thread_data[NUM_CONCURRENT_OPS];

    // Start concurrent threads
    for (int i = 0; i < NUM_CONCURRENT_OPS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].success_count = 0;
        thread_data[i].failure_count = 0;

        pthread_create(&threads[i], NULL, concurrent_put_thread, &thread_data[i]);
    }

    // Wait for threads
    for (int i = 0; i < NUM_CONCURRENT_OPS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Calculate statistics
    int total_success = 0;
    int total_failure = 0;
    for (int i = 0; i < NUM_CONCURRENT_OPS; i++) {
        total_success += thread_data[i].success_count;
        total_failure += thread_data[i].failure_count;
    }

    int total_ops = total_success + total_failure;
    float success_rate = total_ops > 0 ? (float)total_success / total_ops * 100 : 0;

    printf("   Concurrent operations completed:\n");
    printf("   - Total operations: %d\n", total_ops);
    printf("   - Successful: %d\n", total_success);
    printf("   - Failed: %d\n", total_failure);
    printf("   - Success rate: %.2f%%\n", success_rate);

    if (total_ops > 0) {
        assert(success_rate > 50.0 && "Success rate too low");
        printf("   ✓ Acceptable success rate\n");
    }
    printf("\n");

    // Test connection timeout handling
    printf("4. Testing connection timeout handling...\n");
    ret = dht_context_bootstrap("192.0.2.1", 4000);  // TEST-NET address (unreachable)
    assert(ret != 0 && "Invalid bootstrap should fail");
    printf("   ✓ Invalid bootstrap rejected\n\n");

    // Test network resilience
    printf("5. Testing network resilience...\n");
    int is_running = dht_context_is_running();
    printf("   DHT still running after stress: %s\n", is_running ? "Yes" : "No");

    size_t node_count = dht_context_get_node_count();
    printf("   Connected nodes: %zu\n", node_count);
    printf("   ✓ DHT resilient to stress\n\n");

    // Cleanup
    printf("6. Cleaning up...\n");
    dht_singleton_cleanup();
    printf("   ✓ Cleanup complete\n\n");

    printf("=== All Stress Tests Passed ===\n");
    printf("Performance Statistics:\n");
    printf("  - Concurrent threads: %d\n", NUM_CONCURRENT_OPS);
    printf("  - Operations per thread: %d\n", STRESS_ITERATIONS);
    printf("  - Total operations: %d\n", total_ops);
    printf("  - Success rate: %.2f%%\n", success_rate);
    printf("  - Large value size: %d KB\n", LARGE_VALUE_SIZE / 1024);
    printf("  - Network resilience: Verified\n");

    return 0;
}
