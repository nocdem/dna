/**
 * Test offline message queue key consistency
 *
 * This test verifies that messages sent to a recipient can be retrieved
 * by that recipient, checking for the fingerprint vs display name bug.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../dht/dht_context.h"
#include "../dht/dht_offline_queue.h"
#include "../qgp_sha3.h"

// Compute queue key like dht_offline_queue.c does
void compute_queue_key(const char *recipient, uint8_t *key_out) {
    char key_input[1024];
    snprintf(key_input, sizeof(key_input), "%s:offline_queue", recipient);
    qgp_sha3_512((const uint8_t*)key_input, strlen(key_input), key_out);
}

int main() {
    printf("[TEST] Testing offline queue key consistency\n\n");

    // Simulate two identities
    const char *alice_fingerprint = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890";
    const char *alice_name = "alice";

    const char *bob_fingerprint = "9f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c5b4a3210";
    const char *bob_name = "bob";

    printf("Alice fingerprint: %s\n", alice_fingerprint);
    printf("Alice name: %s\n\n", alice_name);

    printf("Bob fingerprint: %s\n", bob_fingerprint);
    printf("Bob name: %s\n\n", bob_name);

    // Compute queue keys
    uint8_t queue_key_fingerprint[64];
    uint8_t queue_key_name[64];

    compute_queue_key(bob_fingerprint, queue_key_fingerprint);
    compute_queue_key(bob_name, queue_key_name);

    printf("Queue key (using fingerprint):\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", queue_key_fingerprint[i]);
    }
    printf("\n\n");

    printf("Queue key (using name):\n");
    for (int i = 0; i < 64; i++) {
        printf("%02x", queue_key_name[i]);
    }
    printf("\n\n");

    // Check if they match
    if (memcmp(queue_key_fingerprint, queue_key_name, 64) == 0) {
        printf("✓ KEYS MATCH - offline messages will work\n");
        return 0;
    } else {
        printf("✗ KEYS DON'T MATCH - THIS IS THE BUG!\n");
        printf("\nScenario:\n");
        printf("1. Alice sends message to 'bob' (using display name)\n");
        printf("   → Message queued at: SHA3-512('bob:offline_queue')\n");
        printf("2. Bob retrieves messages using his fingerprint\n");
        printf("   → Checks: SHA3-512('<fingerprint>:offline_queue')\n");
        printf("3. Keys don't match → Bob never receives the message!\n");
        return 1;
    }
}
