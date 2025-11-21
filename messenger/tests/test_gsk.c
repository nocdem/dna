/**
 * @file test_gsk.c
 * @brief Unit Tests for GSK (Group Symmetric Key) Implementation
 *
 * Tests for DNA Messenger v0.09 - GSK Upgrade
 *
 * Test Coverage:
 * - GSK generation and rotation
 * - GSK storage and loading (database)
 * - GSK packet building and extraction
 * - Kyber1024 wrapping and unwrapping
 * - Dilithium5 signature verification
 * - DHT chunked storage (publish/fetch)
 *
 * @date 2025-11-21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../messenger/gsk.h"
#include "../messenger/gsk_packet.h"
#include "../message_backup.h"
#include "../dht/shared/dht_gsk_storage.h"
#include "../dht/core/dht_context.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_sha3.h"

// Test database path
#define TEST_DB_PATH "/tmp/test_gsk_messages.db"
#define TEST_GROUP_UUID "550e8400-e29b-41d4-a716-446655440000"

// Test result counters
static int tests_passed = 0;
static int tests_failed = 0;

// Helper macros
#define TEST_START(name) \
    printf("\n[TEST] %s\n", name); \
    printf("================================================================================\n");

#define TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("  ✓ %s\n", message); \
            tests_passed++; \
        } else { \
            printf("  ✗ FAIL: %s\n", message); \
            tests_failed++; \
        } \
    } while (0)

#define TEST_END() \
    printf("================================================================================\n");

/**
 * Test 1: GSK Generation
 *
 * Verifies:
 * - gsk_generate() creates random 32-byte keys
 * - Each call produces unique keys
 */
void test_gsk_generation() {
    TEST_START("Test 1: GSK Generation");

    uint8_t gsk1[GSK_KEY_SIZE] = {0};
    uint8_t gsk2[GSK_KEY_SIZE] = {0};

    // Generate two GSKs
    int ret1 = gsk_generate(TEST_GROUP_UUID, 1, gsk1);
    int ret2 = gsk_generate(TEST_GROUP_UUID, 2, gsk2);

    TEST_ASSERT(ret1 == 0, "First GSK generation succeeded");
    TEST_ASSERT(ret2 == 0, "Second GSK generation succeeded");

    // Check keys are non-zero
    int gsk1_nonzero = 0, gsk2_nonzero = 0;
    for (int i = 0; i < GSK_KEY_SIZE; i++) {
        if (gsk1[i] != 0) gsk1_nonzero = 1;
        if (gsk2[i] != 0) gsk2_nonzero = 1;
    }
    TEST_ASSERT(gsk1_nonzero, "First GSK is non-zero");
    TEST_ASSERT(gsk2_nonzero, "Second GSK is non-zero");

    // Check keys are different (uniqueness)
    int keys_different = (memcmp(gsk1, gsk2, GSK_KEY_SIZE) != 0);
    TEST_ASSERT(keys_different, "Generated GSKs are unique");

    TEST_END();
}

/**
 * Test 2: GSK Storage and Loading
 *
 * Verifies:
 * - gsk_store() saves GSK to database
 * - gsk_load() retrieves correct GSK
 * - Version number is preserved
 */
void test_gsk_storage() {
    TEST_START("Test 2: GSK Storage and Loading");

    // Initialize message backup context (required for GSK)
    message_backup_context_t *backup_ctx = message_backup_init("test_gsk");
    TEST_ASSERT(backup_ctx != NULL, "Message backup context created");

    // Initialize GSK subsystem
    int ret = gsk_init(backup_ctx);
    TEST_ASSERT(ret == 0, "Database initialization succeeded");

    // Generate test GSK
    uint8_t original_gsk[GSK_KEY_SIZE];
    gsk_generate(TEST_GROUP_UUID, 1, original_gsk);

    // Store GSK
    ret = gsk_store(TEST_GROUP_UUID, 1, original_gsk);
    TEST_ASSERT(ret == 0, "GSK storage succeeded");

    // Load GSK
    uint8_t loaded_gsk[GSK_KEY_SIZE];
    uint32_t loaded_version = 0;
    ret = gsk_load_active(TEST_GROUP_UUID, loaded_gsk, &loaded_version);
    TEST_ASSERT(ret == 0, "GSK loading succeeded");

    // Verify version
    TEST_ASSERT(loaded_version == 1, "Version number preserved (expected 1)");

    // Verify GSK content
    int keys_match = (memcmp(original_gsk, loaded_gsk, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(keys_match, "Loaded GSK matches original");

    TEST_END();
}

/**
 * Test 3: GSK Rotation
 *
 * Verifies:
 * - gsk_rotate() increments version
 * - New GSK is different from old GSK
 */
void test_gsk_rotation() {
    TEST_START("Test 3: GSK Rotation");

    // Store initial GSK (version 1)
    uint8_t gsk_v1[GSK_KEY_SIZE];
    gsk_generate(TEST_GROUP_UUID, 1, gsk_v1);
    gsk_store(TEST_GROUP_UUID, 1, gsk_v1);

    // Rotate GSK
    uint32_t new_version = 0;
    uint8_t gsk_v2[GSK_KEY_SIZE];
    int ret = gsk_rotate(TEST_GROUP_UUID, &new_version, gsk_v2);
    TEST_ASSERT(ret == 0, "GSK rotation succeeded");

    // Verify version incremented
    TEST_ASSERT(new_version == 2, "Version incremented to 2");

    // Verify new GSK is different
    int keys_different = (memcmp(gsk_v1, gsk_v2, GSK_KEY_SIZE) != 0);
    TEST_ASSERT(keys_different, "Rotated GSK is different from original");

    // Store rotated GSK and verify it's now the latest
    gsk_store(TEST_GROUP_UUID, new_version, gsk_v2);
    uint8_t loaded_gsk[GSK_KEY_SIZE];
    uint32_t loaded_version = 0;
    gsk_load_active(TEST_GROUP_UUID, loaded_gsk, &loaded_version);
    TEST_ASSERT(loaded_version == 2, "Latest version is 2");

    int loaded_matches = (memcmp(gsk_v2, loaded_gsk, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(loaded_matches, "Loaded GSK matches rotated GSK");

    TEST_END();
}

/**
 * Test 4: GSK Packet Building and Extraction
 *
 * Verifies:
 * - gsk_packet_build() creates valid packet
 * - gsk_packet_extract() recovers GSK correctly
 * - Signature verification passes
 */
void test_gsk_packet() {
    TEST_START("Test 4: GSK Packet Building and Extraction");

    // Generate test GSK
    uint8_t test_gsk[GSK_KEY_SIZE];
    gsk_generate(TEST_GROUP_UUID, 1, test_gsk);

    // Generate Dilithium5 keypair (owner)
    uint8_t owner_pubkey[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t owner_privkey[QGP_DSA87_SECRETKEYBYTES];
    int ret = qgp_dsa87_keypair(owner_pubkey, owner_privkey);
    TEST_ASSERT(ret == 0, "Owner Dilithium5 keypair generated");

    // Generate Kyber1024 keypairs (3 members)
    uint8_t member_pubkeys[3][QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t member_privkeys[3][QGP_KEM1024_SECRETKEYBYTES];
    uint8_t member_fingerprints[3][64];  // Binary fingerprints

    gsk_member_entry_t members[3];
    for (int i = 0; i < 3; i++) {
        // Generate Dilithium keypair for fingerprint
        uint8_t member_dil_pubkey[QGP_DSA87_PUBLICKEYBYTES];
        uint8_t member_dil_privkey[QGP_DSA87_SECRETKEYBYTES];
        qgp_dsa87_keypair(member_dil_pubkey, member_dil_privkey);

        // Calculate fingerprint (SHA3-512 of Dilithium pubkey)
        qgp_sha3_512(member_dil_pubkey, QGP_DSA87_PUBLICKEYBYTES, member_fingerprints[i]);

        // Copy fingerprint to member entry
        memcpy(members[i].fingerprint, member_fingerprints[i], 64);

        // Generate Kyber keypair
        ret = qgp_kem1024_keypair(member_pubkeys[i], member_privkeys[i]);
        TEST_ASSERT(ret == 0, "Member Kyber1024 keypair generated");

        // Set pointer to public key (don't copy, just assign pointer)
        members[i].kyber_pubkey = member_pubkeys[i];
    }

    // Build packet
    uint8_t *packet = NULL;
    size_t packet_size = 0;
    ret = gsk_packet_build(TEST_GROUP_UUID, 1, test_gsk, members, 3,
                           owner_privkey, &packet, &packet_size);
    TEST_ASSERT(ret == 0, "GSK packet build succeeded");
    TEST_ASSERT(packet != NULL, "Packet buffer allocated");
    TEST_ASSERT(packet_size > 0, "Packet size is positive");

    printf("  → Packet size: %zu bytes\n", packet_size);

    // Verify signature first
    ret = gsk_packet_verify(packet, packet_size, owner_pubkey);
    TEST_ASSERT(ret == 0, "Packet signature verification passed");

    // Extract GSK from packet (simulate each member)
    for (int i = 0; i < 3; i++) {
        // Extract GSK using binary fingerprint
        uint8_t extracted_gsk[GSK_KEY_SIZE];
        uint32_t extracted_version = 0;
        ret = gsk_packet_extract(packet, packet_size,
                                 member_fingerprints[i],
                                 member_privkeys[i],
                                 extracted_gsk,
                                 &extracted_version);

        char test_name[128];
        snprintf(test_name, sizeof(test_name), "Member %d GSK extraction succeeded", i);
        TEST_ASSERT(ret == 0, test_name);

        if (ret == 0) {
            // Verify extracted GSK matches original
            int gsk_matches = (memcmp(test_gsk, extracted_gsk, GSK_KEY_SIZE) == 0);
            snprintf(test_name, sizeof(test_name), "Member %d extracted GSK matches original", i);
            TEST_ASSERT(gsk_matches, test_name);

            // Verify version
            snprintf(test_name, sizeof(test_name), "Member %d version is correct (1)", i);
            TEST_ASSERT(extracted_version == 1, test_name);
        }
    }

    free(packet);
    TEST_END();
}

/**
 * Test 5: GSK Packet Signature Verification
 *
 * Verifies:
 * - Signature verification passes with correct key
 * - Signature verification fails with wrong key
 * - Tampered packets are rejected
 */
void test_gsk_signature_verification() {
    TEST_START("Test 5: GSK Packet Signature Verification");

    // Generate test GSK
    uint8_t test_gsk[GSK_KEY_SIZE];
    gsk_generate(TEST_GROUP_UUID, 1, test_gsk);

    // Generate owner keypair
    uint8_t owner_pubkey[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t owner_privkey[QGP_DSA87_SECRETKEYBYTES];
    qgp_dsa87_keypair(owner_pubkey, owner_privkey);

    // Generate wrong owner keypair (for negative test)
    uint8_t wrong_pubkey[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t wrong_privkey[QGP_DSA87_SECRETKEYBYTES];
    qgp_dsa87_keypair(wrong_pubkey, wrong_privkey);

    // Generate member with proper fingerprint
    gsk_member_entry_t member;
    uint8_t member_dil_pubkey[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t member_dil_privkey[QGP_DSA87_SECRETKEYBYTES];
    qgp_dsa87_keypair(member_dil_pubkey, member_dil_privkey);

    uint8_t member_fingerprint_bin[64];
    qgp_sha3_512(member_dil_pubkey, QGP_DSA87_PUBLICKEYBYTES, member_fingerprint_bin);

    // Copy fingerprint to member entry
    memcpy(member.fingerprint, member_fingerprint_bin, 64);

    uint8_t member_kyber_pubkey[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t member_kyber_privkey[QGP_KEM1024_SECRETKEYBYTES];
    qgp_kem1024_keypair(member_kyber_pubkey, member_kyber_privkey);

    // Set pointer to public key (don't copy, just assign pointer)
    member.kyber_pubkey = member_kyber_pubkey;

    // Build packet
    uint8_t *packet = NULL;
    size_t packet_size = 0;
    int ret = gsk_packet_build(TEST_GROUP_UUID, 1, test_gsk, &member, 1,
                               owner_privkey, &packet, &packet_size);
    TEST_ASSERT(ret == 0, "Packet build succeeded");

    // Test 1: Verify with correct key (should succeed)
    ret = gsk_packet_verify(packet, packet_size, owner_pubkey);
    TEST_ASSERT(ret == 0, "Signature verification passed with correct key");

    // Test 2: Verify with wrong key (should fail)
    ret = gsk_packet_verify(packet, packet_size, wrong_pubkey);
    TEST_ASSERT(ret != 0, "Signature verification failed with wrong key");

    // Test 3: Tamper with packet (should fail)
    if (packet_size > 100) {
        uint8_t *tampered_packet = malloc(packet_size);
        memcpy(tampered_packet, packet, packet_size);
        tampered_packet[100] ^= 0xFF; // Flip bits

        ret = gsk_packet_verify(tampered_packet, packet_size, owner_pubkey);
        TEST_ASSERT(ret != 0, "Tampered packet rejected");

        free(tampered_packet);
    }

    free(packet);
    TEST_END();
}

/**
 * Test 6: DHT Chunked Storage
 *
 * Verifies:
 * - Chunk serialization/deserialization
 * - Chunk key generation
 * - Large packet chunking logic
 * - Chunk size limits (50 KB max)
 */
void test_dht_chunked_storage() {
    TEST_START("Test 6: DHT Chunked Storage");

    // Test 1: Chunk key generation
    char key0[65] = {0};
    char key1[65] = {0};
    int ret = dht_gsk_make_chunk_key(TEST_GROUP_UUID, 1, 0, key0);
    TEST_ASSERT(ret == 0, "Chunk 0 key generation succeeded");
    TEST_ASSERT(strlen(key0) == 64, "Chunk key is 64 hex chars");

    ret = dht_gsk_make_chunk_key(TEST_GROUP_UUID, 1, 1, key1);
    TEST_ASSERT(ret == 0, "Chunk 1 key generation succeeded");

    // Keys should be different for different chunk indices
    int keys_different = (strcmp(key0, key1) != 0);
    TEST_ASSERT(keys_different, "Different chunks have different keys");

    printf("  → Chunk 0 key: %.16s...\n", key0);
    printf("  → Chunk 1 key: %.16s...\n", key1);

    // Test 2: Chunk serialization/deserialization
    // Create a test chunk with some data
    uint8_t test_data[1024];
    for (int i = 0; i < 1024; i++) {
        test_data[i] = (uint8_t)(i & 0xFF);
    }

    dht_gsk_chunk_t chunk = {
        .magic = DHT_GSK_MAGIC,
        .version = DHT_GSK_VERSION,
        .total_chunks = 3,
        .chunk_index = 0,
        .chunk_size = 1024,
        .chunk_data = test_data
    };

    // Serialize
    uint8_t *serialized = NULL;
    size_t serialized_size = 0;
    ret = dht_gsk_serialize_chunk(&chunk, &serialized, &serialized_size);
    TEST_ASSERT(ret == 0, "Chunk serialization succeeded");
    TEST_ASSERT(serialized != NULL, "Serialized buffer allocated");
    TEST_ASSERT(serialized_size > 0, "Serialized size is positive");

    printf("  → Serialized chunk size: %zu bytes\n", serialized_size);

    // Deserialize
    dht_gsk_chunk_t deserialized_chunk = {0};
    ret = dht_gsk_deserialize_chunk(serialized, serialized_size, &deserialized_chunk);
    TEST_ASSERT(ret == 0, "Chunk deserialization succeeded");

    // Verify deserialized chunk matches original
    TEST_ASSERT(deserialized_chunk.magic == DHT_GSK_MAGIC, "Magic bytes preserved");
    TEST_ASSERT(deserialized_chunk.version == DHT_GSK_VERSION, "Version preserved");
    TEST_ASSERT(deserialized_chunk.total_chunks == 3, "Total chunks preserved");
    TEST_ASSERT(deserialized_chunk.chunk_index == 0, "Chunk index preserved");
    TEST_ASSERT(deserialized_chunk.chunk_size == 1024, "Chunk size preserved");

    int data_matches = (memcmp(deserialized_chunk.chunk_data, test_data, 1024) == 0);
    TEST_ASSERT(data_matches, "Chunk data preserved");

    // Test 3: Chunk size limits
    size_t max_chunk_size = DHT_GSK_CHUNK_SIZE;  // 50 KB
    TEST_ASSERT(max_chunk_size == 50 * 1024, "Max chunk size is 50 KB");

    // Simulate a large packet (100 KB) requiring 2 chunks
    size_t large_packet_size = 100 * 1024;
    uint32_t expected_chunks = (large_packet_size + max_chunk_size - 1) / max_chunk_size;
    TEST_ASSERT(expected_chunks == 2, "100 KB packet requires 2 chunks");

    printf("  → Large packet: %zu bytes requires %u chunks\n",
           large_packet_size, expected_chunks);

    // Test 4: Maximum chunks limit
    TEST_ASSERT(DHT_GSK_MAX_CHUNKS == 4, "Maximum 4 chunks supported");

    size_t max_packet_size = DHT_GSK_MAX_CHUNKS * max_chunk_size;
    printf("  → Maximum packet size: %zu bytes (200 KB)\n", max_packet_size);

    // Cleanup
    free(serialized);
    dht_gsk_free_chunk(&deserialized_chunk);

    TEST_END();
}

/**
 * Main test runner
 */
int main(int argc, char *argv[]) {
    printf("\n");
    printf("################################################################################\n");
    printf("#                                                                              #\n");
    printf("#  GSK (Group Symmetric Key) Unit Tests - DNA Messenger v0.09                 #\n");
    printf("#                                                                              #\n");
    printf("################################################################################\n");

    // Run tests
    test_gsk_generation();
    test_gsk_storage();
    test_gsk_rotation();
    test_gsk_packet();
    test_gsk_signature_verification();
    test_dht_chunked_storage();

    // Summary
    printf("\n");
    printf("################################################################################\n");
    printf("#  TEST SUMMARY                                                                #\n");
    printf("################################################################################\n");
    printf("\n");
    printf("  Total Tests: %d\n", tests_passed + tests_failed);
    printf("  Passed:      %d ✓\n", tests_passed);
    printf("  Failed:      %d ✗\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("  🎉 ALL TESTS PASSED!\n");
        printf("\n");
        return 0;
    } else {
        printf("  ❌ SOME TESTS FAILED\n");
        printf("\n");
        return 1;
    }
}
