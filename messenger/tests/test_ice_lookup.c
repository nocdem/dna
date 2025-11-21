/**
 * Test ICE Candidate DHT Lookup
 *
 * Usage: ./test_ice_lookup <peer_fingerprint>
 * Example: ./test_ice_lookup 88a2f89d6999eda9...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../dht/client/dht_singleton.h"
#include "../crypto/utils/qgp_sha3.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <peer_fingerprint>\n", argv[0]);
        fprintf(stderr, "Example: %s 88a2f89d6999eda9...\n", argv[0]);
        return 1;
    }

    const char *peer_fingerprint = argv[1];

    printf("=== ICE Candidate DHT Lookup Test ===\n");
    printf("Peer fingerprint: %s\n", peer_fingerprint);
    printf("\n");

    // Initialize DHT singleton
    printf("[1] Initializing DHT singleton...\n");
    if (dht_singleton_init() != 0) {
        fprintf(stderr, "ERROR: Failed to initialize DHT singleton\n");
        return 1;
    }

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        fprintf(stderr, "ERROR: DHT context is NULL\n");
        return 1;
    }
    printf("    ✓ DHT initialized\n\n");

    // Create DHT key: SHA3-512(peer_fingerprint + ":ice_candidates")
    printf("[2] Creating DHT key...\n");
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:ice_candidates", peer_fingerprint);
    printf("    Key input: %s\n", key_input);

    // Hash key with SHA3-512 (128 hex chars)
    char hex_key[129];
    if (qgp_sha3_512_hex((uint8_t*)key_input, strlen(key_input),
                         hex_key, sizeof(hex_key)) != 0) {
        fprintf(stderr, "ERROR: Failed to hash DHT key\n");
        return 1;
    }
    printf("    SHA3-512 hash: %s\n", hex_key);
    printf("    (OpenDHT will hash this again to 160-bit InfoHash)\n\n");

    // Fetch from DHT
    printf("[3] Querying DHT...\n");
    uint8_t *value_data = NULL;
    size_t value_len = 0;

    int ret = dht_get(dht, (uint8_t*)hex_key, strlen(hex_key), &value_data, &value_len);

    if (ret == 0 && value_data) {
        printf("    ✓✓ SUCCESS - Found ICE candidates in DHT!\n");
        printf("    Candidate data (%zu bytes):\n", value_len);
        printf("----------------------------------------\n");
        printf("%.*s\n", (int)value_len, value_data);
        printf("----------------------------------------\n");

        // Count candidates
        int candidate_count = 0;
        for (size_t i = 0; i < value_len; i++) {
            if (value_data[i] == '\n') candidate_count++;
        }
        printf("    Total candidates: %d\n", candidate_count);

        free(value_data);
    } else {
        printf("    ✗ FAILED - No ICE candidates found in DHT\n\n");
        printf("Possible reasons:\n");
        printf("  1. Peer hasn't started messenger yet\n");
        printf("  2. Peer's ICE initialization failed\n");
        printf("  3. Peer hasn't published candidates (check peer logs)\n");
        printf("  4. Wrong fingerprint (verify it matches peer's identity)\n");
        printf("  5. DHT propagation delay (wait 10-30 seconds)\n\n");
        printf("Peer should see this in their logs:\n");
        printf("  [ICE] Candidates published to DHT\n");
        printf("  [P2P] ✓ Presence and ICE candidates both registered\n");
    }

    printf("\n[4] Cleanup...\n");
    dht_singleton_cleanup();
    printf("    ✓ Done\n");

    return (ret == 0) ? 0 : 1;
}
