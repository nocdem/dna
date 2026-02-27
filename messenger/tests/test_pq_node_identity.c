/**
 * @file test_pq_node_identity.c
 * @brief Test PQ DHT node identity generation and validation
 *
 * Tests:
 * - Generate Dilithium5 node identity
 * - Save/load identity from disk
 * - Certificate validation
 * - Identity fingerprint generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../dht/client/dht_identity.h"
#include "../crypto/dsa/api.h"
#include "../crypto/utils/qgp_sha3.h"

#define TEST_IDENTITY_NAME "test_node"
#define TEST_IDENTITY_PATH "/tmp/test_identity.pqkey"

int main(void) {
    printf("=== PQ Node Identity Test ===\n\n");

    // Generate new Dilithium5 identity
    printf("1. Generating Dilithium5 identity...\n");
    dht_identity_t *identity = dht_identity_generate(TEST_IDENTITY_NAME);
    assert(identity != NULL && "Identity generation failed");
    printf("   ✓ Identity generated: %s\n", TEST_IDENTITY_NAME);

    // Get identity fingerprint
    char fingerprint[128];
    dht_identity_get_fingerprint(identity, fingerprint, sizeof(fingerprint));
    printf("   Fingerprint: %s\n", fingerprint);
    assert(strlen(fingerprint) > 0 && "Fingerprint generation failed");
    printf("   ✓ Fingerprint generated\n\n");

    // Save identity to disk
    printf("2. Saving identity to disk...\n");
    int ret = dht_identity_save(identity, TEST_IDENTITY_PATH);
    assert(ret == 0 && "Identity save failed");
    printf("   ✓ Identity saved to: %s\n", TEST_IDENTITY_PATH);

    // Check file exists
    assert(access(TEST_IDENTITY_PATH, F_OK) == 0 && "Identity file not found");
    printf("   ✓ Identity file exists\n\n");

    // Free original identity
    dht_identity_free(identity);

    // Load identity from disk
    printf("3. Loading identity from disk...\n");
    dht_identity_t *loaded_identity = dht_identity_load(TEST_IDENTITY_PATH);
    assert(loaded_identity != NULL && "Identity load failed");
    printf("   ✓ Identity loaded from disk\n");

    // Verify loaded fingerprint matches
    char loaded_fingerprint[128];
    dht_identity_get_fingerprint(loaded_identity, loaded_fingerprint,
                                 sizeof(loaded_fingerprint));
    assert(strcmp(fingerprint, loaded_fingerprint) == 0 && "Fingerprint mismatch");
    printf("   ✓ Loaded fingerprint matches: %s\n\n", loaded_fingerprint);

    // Test certificate validation
    printf("4. Validating certificate...\n");
    int is_valid = dht_identity_validate(loaded_identity);
    assert(is_valid && "Certificate validation failed");
    printf("   ✓ Certificate is valid\n");

    // Get public key
    const uint8_t *pubkey = dht_identity_get_public_key(loaded_identity);
    assert(pubkey != NULL && "Public key extraction failed");
    printf("   ✓ Public key extracted\n");
    printf("   Public key size: %d bytes\n\n", pqcrystals_dilithium5_PUBLICKEYBYTES);

    // Test sign/verify with identity
    printf("5. Testing sign/verify with identity...\n");
    const char *test_msg = "Test message for identity";
    uint8_t *signature = NULL;
    size_t sig_len = 0;

    ret = dht_identity_sign(loaded_identity, (uint8_t*)test_msg,
                           strlen(test_msg), &signature, &sig_len);
    assert(ret == 0 && "Signing failed");
    assert(sig_len == pqcrystals_dilithium5_BYTES && "Signature size mismatch");
    printf("   ✓ Message signed\n");
    printf("   Signature size: %zu bytes\n", sig_len);

    ret = dht_identity_verify(loaded_identity, (uint8_t*)test_msg,
                             strlen(test_msg), signature, sig_len);
    assert(ret == 0 && "Verification failed");
    printf("   ✓ Signature verified\n\n");

    free(signature);

    // Test identity comparison
    printf("6. Testing identity comparison...\n");
    dht_identity_t *identity2 = dht_identity_generate("test_node2");
    assert(identity2 != NULL);

    int are_equal = dht_identity_compare(loaded_identity, identity2);
    assert(are_equal == 0 && "Different identities should not be equal");
    printf("   ✓ Different identities correctly identified\n");

    are_equal = dht_identity_compare(loaded_identity, loaded_identity);
    assert(are_equal == 1 && "Same identity should be equal");
    printf("   ✓ Same identity correctly identified\n\n");

    // Cleanup
    printf("7. Cleaning up...\n");
    dht_identity_free(loaded_identity);
    dht_identity_free(identity2);
    unlink(TEST_IDENTITY_PATH);
    printf("   ✓ Cleanup complete\n\n");

    printf("=== All Node Identity Tests Passed ===\n");
    printf("Identity Properties:\n");
    printf("  - Algorithm: Dilithium5 (ML-DSA-87)\n");
    printf("  - Public Key: %d bytes\n", pqcrystals_dilithium5_PUBLICKEYBYTES);
    printf("  - Secret Key: %d bytes\n", pqcrystals_dilithium5_SECRETKEYBYTES);
    printf("  - Signature: %d bytes\n", pqcrystals_dilithium5_BYTES);
    printf("  - Security: NIST Category 5 (256-bit quantum)\n");

    return 0;
}
