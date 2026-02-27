/**
 * Test suite for DHT listen() API (Phase 1 - Push Notifications)
 *
 * Tests real-time DHT value notifications using the listen() wrapper.
 */

#include "../dht/core/dht_listen.h"
#include "../dht/core/dht_context.h"
#include "../dht/client/dht_singleton.h"
#include "../dht/shared/dht_offline_queue.h"
#include "../crypto/utils/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

// Test configuration
#define TEST_TIMEOUT_SECONDS 30

// Callback tracking structure
typedef struct {
    int callback_count;
    int messages_received;
    bool expired_received;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool test_complete;
} test_callback_context_t;

/**
 * Generate test fingerprint (128 hex chars)
 */
static void generate_test_fingerprint(char *fp, int seed) {
    unsigned char hash[64];
    char seed_str[32];
    snprintf(seed_str, sizeof(seed_str), "test_fp_%d", seed);

    qgp_sha3_512((const unsigned char*)seed_str, strlen(seed_str), hash);

    for (int i = 0; i < 64; i++) {
        snprintf(&fp[i * 2], 3, "%02x", hash[i]);
    }
    fp[128] = '\0';
}

/**
 * Test callback for listen() API
 */
static bool test_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    test_callback_context_t *ctx = (test_callback_context_t*)user_data;

    pthread_mutex_lock(&ctx->mutex);

    ctx->callback_count++;

    if (expired) {
        printf("    [Callback] Received expiration notification\n");
        ctx->expired_received = true;
    } else if (value && value_len > 0) {
        printf("    [Callback] Received value (%zu bytes)\n", value_len);

        // Try to deserialize as offline messages
        dht_offline_message_t *messages = NULL;
        size_t count = 0;
        if (dht_deserialize_messages(value, value_len, &messages, &count) == 0) {
            printf("    [Callback] Deserialized %zu message(s)\n", count);
            ctx->messages_received += count;
            dht_offline_messages_free(messages, count);
        }

        ctx->test_complete = true;
        pthread_cond_signal(&ctx->cond);
    }

    pthread_mutex_unlock(&ctx->mutex);

    return true;  // Continue listening
}

/**
 * Test 1: Basic listen() and callback invocation
 */
static int test_basic_listen(dht_context_t *ctx) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("TEST 1: Basic listen() and Callback Invocation\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    // Generate test identities
    char sender_fp[129];
    char recipient_fp[129];
    generate_test_fingerprint(sender_fp, 1001);
    generate_test_fingerprint(recipient_fp, 2001);

    printf("Sender:    %.20s...\n", sender_fp);
    printf("Recipient: %.20s...\n\n", recipient_fp);

    // Initialize callback context
    test_callback_context_t callback_ctx = {0};
    pthread_mutex_init(&callback_ctx.mutex, NULL);
    pthread_cond_init(&callback_ctx.cond, NULL);

    // Generate outbox key
    uint8_t outbox_key[64];
    dht_generate_outbox_key(sender_fp, recipient_fp, outbox_key);

    printf("Step 1: Start listening on outbox key...\n");
    size_t listen_token = dht_listen(
        ctx,
        outbox_key,
        64,
        test_listen_callback,
        &callback_ctx
    );

    if (listen_token == 0) {
        fprintf(stderr, "✗ Failed to start listening\n\n");
        return -1;
    }

    printf("✓ Started listening (token: %zu)\n\n", listen_token);

    // Give DHT a moment to set up subscription
    sleep(2);

    printf("Step 2: Queue a message (should trigger callback)...\n");
    uint8_t test_message[1024];
    memset(test_message, 0xAB, sizeof(test_message));

    int queue_result = dht_queue_message(
        ctx,
        sender_fp,
        recipient_fp,
        test_message,
        sizeof(test_message),
        1,    // seq_num for watermark
        3600  // 1 hour TTL
    );

    if (queue_result != 0) {
        fprintf(stderr, "✗ Failed to queue message\n\n");
        dht_cancel_listen(ctx, listen_token);
        return -1;
    }

    printf("✓ Message queued\n\n");

    printf("Step 3: Wait for callback (max %d seconds)...\n", TEST_TIMEOUT_SECONDS);

    pthread_mutex_lock(&callback_ctx.mutex);
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += TEST_TIMEOUT_SECONDS;

    while (!callback_ctx.test_complete) {
        int wait_result = pthread_cond_timedwait(
            &callback_ctx.cond,
            &callback_ctx.mutex,
            &timeout
        );

        if (wait_result == ETIMEDOUT) {
            pthread_mutex_unlock(&callback_ctx.mutex);
            fprintf(stderr, "✗ Timeout waiting for callback\n\n");
            dht_cancel_listen(ctx, listen_token);
            return -1;
        }
    }
    pthread_mutex_unlock(&callback_ctx.mutex);

    printf("✓ Callback received!\n\n");

    printf("Step 4: Cancel subscription...\n");
    dht_cancel_listen(ctx, listen_token);
    printf("✓ Subscription cancelled\n\n");

    printf("Results:\n");
    printf("  Callbacks invoked: %d\n", callback_ctx.callback_count);
    printf("  Messages received: %d\n", callback_ctx.messages_received);
    printf("  Expiration events: %s\n\n", callback_ctx.expired_received ? "Yes" : "No");

    if (callback_ctx.callback_count > 0 && callback_ctx.messages_received > 0) {
        printf("✓ TEST PASSED\n\n");
        return 0;
    } else {
        fprintf(stderr, "✗ TEST FAILED: No messages received via callback\n\n");
        return -1;
    }
}

/**
 * Test 2: Multiple simultaneous subscriptions
 */
static int test_multiple_subscriptions(dht_context_t *ctx) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("TEST 2: Multiple Simultaneous Subscriptions\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    const int NUM_CONTACTS = 5;
    char sender_fps[NUM_CONTACTS][129];
    char recipient_fp[129];
    size_t listen_tokens[NUM_CONTACTS];
    test_callback_context_t callback_ctxs[NUM_CONTACTS];

    generate_test_fingerprint(recipient_fp, 3000);

    printf("Step 1: Subscribe to %d contacts' outboxes...\n", NUM_CONTACTS);

    for (int i = 0; i < NUM_CONTACTS; i++) {
        generate_test_fingerprint(sender_fps[i], 4000 + i);

        // Initialize callback context
        memset(&callback_ctxs[i], 0, sizeof(test_callback_context_t));
        pthread_mutex_init(&callback_ctxs[i].mutex, NULL);
        pthread_cond_init(&callback_ctxs[i].cond, NULL);

        // Generate outbox key
        uint8_t outbox_key[64];
        dht_generate_outbox_key(sender_fps[i], recipient_fp, outbox_key);

        // Start listening
        listen_tokens[i] = dht_listen(
            ctx,
            outbox_key,
            64,
            test_listen_callback,
            &callback_ctxs[i]
        );

        if (listen_tokens[i] == 0) {
            fprintf(stderr, "✗ Failed to start listening for contact %d\n", i + 1);
            // Cancel previous subscriptions
            for (int j = 0; j < i; j++) {
                dht_cancel_listen(ctx, listen_tokens[j]);
            }
            return -1;
        }

        printf("  [%d/%d] ✓ Listening (token: %zu)\n",
               i + 1, NUM_CONTACTS, listen_tokens[i]);
    }

    printf("\n");

    // Check active subscription count
    size_t active_count = dht_get_active_listen_count(ctx);
    printf("Active subscriptions: %zu (expected: %d)\n\n", active_count, NUM_CONTACTS);

    if (active_count != NUM_CONTACTS) {
        fprintf(stderr, "✗ Subscription count mismatch!\n\n");
        for (int i = 0; i < NUM_CONTACTS; i++) {
            dht_cancel_listen(ctx, listen_tokens[i]);
        }
        return -1;
    }

    sleep(2);  // Let subscriptions settle

    printf("Step 2: Queue messages from each contact...\n");

    uint8_t test_message[512];
    memset(test_message, 0xCD, sizeof(test_message));

    for (int i = 0; i < NUM_CONTACTS; i++) {
        int queue_result = dht_queue_message(
            ctx,
            sender_fps[i],
            recipient_fp,
            test_message,
            sizeof(test_message),
            (uint64_t)(i + 1),  // seq_num for watermark
            3600
        );

        if (queue_result == 0) {
            printf("  [%d/%d] ✓ Queued\n", i + 1, NUM_CONTACTS);
        } else {
            fprintf(stderr, "  [%d/%d] ✗ Failed\n", i + 1, NUM_CONTACTS);
        }

        usleep(100000);  // 100ms between messages
    }

    printf("\n");

    printf("Step 3: Cancel all subscriptions...\n");
    for (int i = 0; i < NUM_CONTACTS; i++) {
        dht_cancel_listen(ctx, listen_tokens[i]);
    }
    printf("✓ All subscriptions cancelled\n\n");

    // Check active count after cancellation
    active_count = dht_get_active_listen_count(ctx);
    printf("Active subscriptions after cancellation: %zu (expected: 0)\n\n", active_count);

    if (active_count == 0) {
        printf("✓ TEST PASSED\n\n");
        return 0;
    } else {
        fprintf(stderr, "✗ TEST FAILED: Subscriptions not properly cancelled\n\n");
        return -1;
    }
}

/**
 * Test 3: Invalid parameters
 */
static int test_invalid_parameters(dht_context_t *ctx) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("TEST 3: Invalid Parameters Handling\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    uint8_t test_key[64] = {0};
    test_callback_context_t callback_ctx = {0};

    printf("Testing invalid parameters...\n");

    // Test 1: NULL context
    size_t token1 = dht_listen(NULL, test_key, 64, test_listen_callback, &callback_ctx);
    printf("  NULL context: %s\n", token1 == 0 ? "✓ Rejected" : "✗ Accepted");

    // Test 2: NULL key
    size_t token2 = dht_listen(ctx, NULL, 64, test_listen_callback, &callback_ctx);
    printf("  NULL key: %s\n", token2 == 0 ? "✓ Rejected" : "✗ Accepted");

    // Test 3: Zero key length
    size_t token3 = dht_listen(ctx, test_key, 0, test_listen_callback, &callback_ctx);
    printf("  Zero key length: %s\n", token3 == 0 ? "✓ Rejected" : "✗ Accepted");

    // Test 4: NULL callback
    size_t token4 = dht_listen(ctx, test_key, 64, NULL, &callback_ctx);
    printf("  NULL callback: %s\n\n", token4 == 0 ? "✓ Rejected" : "✗ Accepted");

    if (token1 == 0 && token2 == 0 && token3 == 0 && token4 == 0) {
        printf("✓ TEST PASSED\n\n");
        return 0;
    } else {
        fprintf(stderr, "✗ TEST FAILED: Invalid parameters not properly rejected\n\n");
        return -1;
    }
}

/**
 * Main test runner
 */
int main(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║   DHT listen() API Test Suite (Phase 1)              ║\n");
    printf("║   Testing push notification infrastructure            ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");

    // Initialize DHT
    printf("Initializing DHT singleton...\n");
    int ret = dht_singleton_init();
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize DHT singleton\n");
        fprintf(stderr, "Make sure you have an identity created\n");
        return 1;
    }

    dht_context_t *ctx = dht_singleton_get();
    assert(ctx != NULL && "Failed to get DHT context");

    // Wait for DHT to be ready
    printf("Waiting for DHT to connect to network...\n");
    int max_wait = 15;
    int waited = 0;
    while (!dht_context_is_ready(ctx) && waited < max_wait) {
        printf("  Waiting... (%d/%d seconds)\n", waited + 1, max_wait);
        sleep(1);
        waited++;
    }

    if (!dht_context_is_ready(ctx)) {
        printf("⚠ DHT not ready after %d seconds\n", max_wait);
        printf("This test requires network connectivity to bootstrap nodes\n");
        dht_singleton_cleanup();
        return 1;
    }

    printf("✓ DHT initialized and connected\n\n");

    sleep(2);  // Let DHT fully stabilize

    // Run tests
    int test1_result = test_basic_listen(ctx);
    sleep(1);

    int test2_result = test_multiple_subscriptions(ctx);
    sleep(1);

    int test3_result = test_invalid_parameters(ctx);

    // Cleanup
    printf("Cleaning up...\n");
    dht_singleton_cleanup();
    printf("✓ Cleanup complete\n\n");

    // Final summary
    printf("═══════════════════════════════════════════════════════\n");
    printf("TEST SUMMARY\n");
    printf("═══════════════════════════════════════════════════════\n\n");

    printf("Test 1 (Basic listen):         %s\n",
           test1_result == 0 ? "✓ PASSED" : "✗ FAILED");
    printf("Test 2 (Multiple subscriptions): %s\n",
           test2_result == 0 ? "✓ PASSED" : "✗ FAILED");
    printf("Test 3 (Invalid parameters):   %s\n\n",
           test3_result == 0 ? "✓ PASSED" : "✗ FAILED");

    int total_passed = (test1_result == 0 ? 1 : 0) +
                       (test2_result == 0 ? 1 : 0) +
                       (test3_result == 0 ? 1 : 0);

    printf("Total: %d/3 tests passed\n\n", total_passed);

    if (total_passed == 3) {
        printf("🎉 ALL TESTS PASSED!\n");
        printf("✓ DHT listen() API is working correctly\n");
        printf("✓ Ready for Phase 2 integration\n\n");
        return 0;
    } else {
        fprintf(stderr, "⚠ SOME TESTS FAILED\n");
        fprintf(stderr, "Please review the output above\n\n");
        return 1;
    }
}
