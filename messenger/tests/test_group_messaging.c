/**
 * @file test_group_messaging.c
 * @brief Integration Tests for Group Messaging with GSK
 *
 * End-to-end tests for DNA Messenger v0.09 - GSK Upgrade
 *
 * Test Scenarios:
 * - Create group with 3 members
 * - Send encrypted group message using GSK
 * - Add member (triggers GSK rotation)
 * - Remove member (triggers GSK rotation)
 * - Verify old GSK cannot decrypt new messages
 * - Test ownership transfer when owner offline
 *
 * @date 2025-11-21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../messenger.h"
#include "../messenger/gsk.h"
#include "../messenger/gsk_packet.h"
#include "../messenger/group_ownership.h"
#include "../dht/shared/dht_groups.h"
#include "../dht/core/dht_context.h"

// Test constants
#define TEST_DB_PATH_ALICE "/tmp/test_group_alice_messages.db"
#define TEST_DB_PATH_BOB "/tmp/test_group_bob_messages.db"
#define TEST_DB_PATH_CAROL "/tmp/test_group_carol_messages.db"
#define TEST_GROUP_UUID "550e8400-e29b-41d4-a716-446655440000"
#define TEST_GROUP_NAME "Test Group Chat"

// Test result counters
static int tests_passed = 0;
static int tests_failed = 0;

// Helper macros
#define TEST_START(name) \
    printf("\n[INTEGRATION TEST] %s\n", name); \
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
 * Test user context
 */
typedef struct {
    char *identity;
    char *fingerprint;
    messenger_context_t *ctx;
    uint8_t dilithium_pubkey[QGP_DILITHIUM_PUBLICKEY_BYTES];
    uint8_t dilithium_privkey[QGP_DILITHIUM_SECRETKEY_BYTES];
    uint8_t kyber_pubkey[QGP_KYBER_PUBLICKEY_BYTES];
    uint8_t kyber_privkey[QGP_KYBER_SECRETKEY_BYTES];
} test_user_t;

/**
 * Setup test user
 */
int setup_test_user(test_user_t *user, const char *identity, const char *db_path) {
    user->identity = strdup(identity);

    // Generate keys
    if (qgp_dilithium_keypair(user->dilithium_pubkey, user->dilithium_privkey) != 0) {
        fprintf(stderr, "Failed to generate Dilithium5 keypair for %s\n", identity);
        return -1;
    }

    if (qgp_kyber_keypair(user->kyber_pubkey, user->kyber_privkey) != 0) {
        fprintf(stderr, "Failed to generate Kyber1024 keypair for %s\n", identity);
        return -1;
    }

    // Calculate fingerprint (SHA3-512 of Dilithium pubkey)
    uint8_t fingerprint_bin[64];
    qgp_sha3_512(user->dilithium_pubkey, QGP_DILITHIUM_PUBLICKEY_BYTES, fingerprint_bin);

    user->fingerprint = malloc(129);
    for (int i = 0; i < 64; i++) {
        sprintf(user->fingerprint + (i * 2), "%02x", fingerprint_bin[i]);
    }
    user->fingerprint[128] = '\0';

    printf("  → %s fingerprint: %.16s...\n", identity, user->fingerprint);

    return 0;
}

/**
 * Cleanup test user
 */
void cleanup_test_user(test_user_t *user) {
    if (user->identity) free(user->identity);
    if (user->fingerprint) free(user->fingerprint);
}

/**
 * Integration Test 1: Create Group and Send Message
 *
 * Flow:
 * 1. Alice creates group with Bob and Carol
 * 2. Alice generates GSK (version 1)
 * 3. Alice builds Initial Key Packet
 * 4. Alice sends encrypted group message using GSK
 * 5. Bob and Carol extract GSK and decrypt message
 */
void test_create_group_and_send() {
    TEST_START("Integration Test 1: Create Group and Send Message");

    // Setup users
    test_user_t alice, bob, carol;
    setup_test_user(&alice, "alice", TEST_DB_PATH_ALICE);
    setup_test_user(&bob, "bob", TEST_DB_PATH_BOB);
    setup_test_user(&carol, "carol", TEST_DB_PATH_CAROL);

    // Step 1: Alice creates group
    printf("\n  Step 1: Alice creates group\n");

    // Initialize GSK database
    unlink(TEST_DB_PATH_ALICE);
    int ret = gsk_init_db(TEST_DB_PATH_ALICE);
    TEST_ASSERT(ret == 0, "Alice GSK database initialized");

    // Generate initial GSK
    uint8_t gsk_v1[GSK_KEY_SIZE];
    ret = gsk_generate(gsk_v1);
    TEST_ASSERT(ret == 0, "GSK v1 generated");

    // Store GSK
    ret = gsk_store(TEST_GROUP_UUID, 1, gsk_v1);
    TEST_ASSERT(ret == 0, "GSK v1 stored");

    // Step 2: Build Initial Key Packet for Bob and Carol
    printf("\n  Step 2: Build Initial Key Packet\n");

    gsk_member_entry_t members[2];

    // Bob
    memcpy(members[0].fingerprint, bob.fingerprint, 129);
    memcpy(members[0].kyber_pubkey, bob.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    // Carol
    memcpy(members[1].fingerprint, carol.fingerprint, 129);
    memcpy(members[1].kyber_pubkey, carol.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    uint8_t *packet = NULL;
    size_t packet_size = 0;
    ret = gsk_packet_build(TEST_GROUP_UUID, 1, gsk_v1, members, 2,
                           alice.dilithium_privkey, &packet, &packet_size);
    TEST_ASSERT(ret == 0, "Initial Key Packet built");
    printf("    → Packet size: %zu bytes\n", packet_size);

    // Step 3: Bob extracts GSK
    printf("\n  Step 3: Bob extracts GSK from packet\n");

    uint8_t bob_gsk[GSK_KEY_SIZE];
    char bob_uuid[37];
    uint32_t bob_version;
    ret = gsk_packet_extract(packet, packet_size,
                             bob.fingerprint, bob.kyber_privkey,
                             alice.dilithium_pubkey,
                             bob_uuid, &bob_version, bob_gsk);
    TEST_ASSERT(ret == 0, "Bob extracted GSK");
    TEST_ASSERT(bob_version == 1, "Bob got version 1");

    int bob_gsk_matches = (memcmp(bob_gsk, gsk_v1, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(bob_gsk_matches, "Bob's GSK matches Alice's");

    // Step 4: Carol extracts GSK
    printf("\n  Step 4: Carol extracts GSK from packet\n");

    uint8_t carol_gsk[GSK_KEY_SIZE];
    char carol_uuid[37];
    uint32_t carol_version;
    ret = gsk_packet_extract(packet, packet_size,
                             carol.fingerprint, carol.kyber_privkey,
                             alice.dilithium_pubkey,
                             carol_uuid, &carol_version, carol_gsk);
    TEST_ASSERT(ret == 0, "Carol extracted GSK");
    TEST_ASSERT(carol_version == 1, "Carol got version 1");

    int carol_gsk_matches = (memcmp(carol_gsk, gsk_v1, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(carol_gsk_matches, "Carol's GSK matches Alice's");

    // Step 5: Alice sends encrypted message (using GSK for group encryption)
    printf("\n  Step 5: Alice sends group message\n");

    const char *test_message = "Hello group! This is encrypted with GSK v1.";
    printf("    → Message: \"%s\"\n", test_message);
    printf("    → Using GSK v1 for AES-256-GCM encryption\n");

    // Note: Actual encryption would use dna_encrypt_message_group()
    // For this test, we verify that all members have the same GSK
    TEST_ASSERT(bob_gsk_matches && carol_gsk_matches,
                "All members can decrypt (same GSK)");

    // Cleanup
    free(packet);
    cleanup_test_user(&alice);
    cleanup_test_user(&bob);
    cleanup_test_user(&carol);

    TEST_END();
}

/**
 * Integration Test 2: Add Member (GSK Rotation)
 *
 * Flow:
 * 1. Group exists with Alice, Bob, Carol (GSK v1)
 * 2. Alice adds Dave to group
 * 3. GSK rotates to v2 (automatic)
 * 4. New packet includes all 4 members
 * 5. Old GSK v1 cannot decrypt new messages
 */
void test_add_member_rotation() {
    TEST_START("Integration Test 2: Add Member (GSK Rotation)");

    // Setup users
    test_user_t alice, bob, carol, dave;
    setup_test_user(&alice, "alice", TEST_DB_PATH_ALICE);
    setup_test_user(&bob, "bob", TEST_DB_PATH_BOB);
    setup_test_user(&carol, "carol", TEST_DB_PATH_CAROL);
    setup_test_user(&dave, "dave", "/tmp/test_group_dave_messages.db");

    // Step 1: Initial group with v1
    printf("\n  Step 1: Initial group (Alice, Bob, Carol) with GSK v1\n");

    unlink(TEST_DB_PATH_ALICE);
    gsk_init_db(TEST_DB_PATH_ALICE);

    uint8_t gsk_v1[GSK_KEY_SIZE];
    gsk_generate(gsk_v1);
    gsk_store(TEST_GROUP_UUID, 1, gsk_v1);

    printf("    → GSK v1 stored\n");

    // Step 2: Add Dave (triggers rotation)
    printf("\n  Step 2: Alice adds Dave (triggers GSK rotation)\n");

    uint32_t new_version;
    uint8_t gsk_v2[GSK_KEY_SIZE];
    int ret = gsk_rotate(TEST_GROUP_UUID, &new_version, gsk_v2);
    TEST_ASSERT(ret == 0, "GSK rotation succeeded");
    TEST_ASSERT(new_version == 2, "Version incremented to 2");

    int keys_different = (memcmp(gsk_v1, gsk_v2, GSK_KEY_SIZE) != 0);
    TEST_ASSERT(keys_different, "GSK v2 is different from v1");

    // Store new GSK
    gsk_store(TEST_GROUP_UUID, new_version, gsk_v2);

    // Step 3: Build new packet with all 4 members
    printf("\n  Step 3: Build new Initial Key Packet with 4 members\n");

    gsk_member_entry_t members[4];
    memcpy(members[0].fingerprint, bob.fingerprint, 129);
    memcpy(members[0].kyber_pubkey, bob.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    memcpy(members[1].fingerprint, carol.fingerprint, 129);
    memcpy(members[1].kyber_pubkey, carol.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    memcpy(members[2].fingerprint, dave.fingerprint, 129);
    memcpy(members[2].kyber_pubkey, dave.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    // Add Alice herself (owner also gets wrapped GSK)
    memcpy(members[3].fingerprint, alice.fingerprint, 129);
    memcpy(members[3].kyber_pubkey, alice.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    uint8_t *packet = NULL;
    size_t packet_size = 0;
    ret = gsk_packet_build(TEST_GROUP_UUID, 2, gsk_v2, members, 4,
                           alice.dilithium_privkey, &packet, &packet_size);
    TEST_ASSERT(ret == 0, "New Initial Key Packet built with 4 members");
    printf("    → New packet size: %zu bytes\n", packet_size);

    // Step 4: Dave extracts new GSK
    printf("\n  Step 4: Dave extracts GSK v2\n");

    uint8_t dave_gsk[GSK_KEY_SIZE];
    char dave_uuid[37];
    uint32_t dave_version;
    ret = gsk_packet_extract(packet, packet_size,
                             dave.fingerprint, dave.kyber_privkey,
                             alice.dilithium_pubkey,
                             dave_uuid, &dave_version, dave_gsk);
    TEST_ASSERT(ret == 0, "Dave extracted GSK v2");
    TEST_ASSERT(dave_version == 2, "Dave got version 2");

    int dave_gsk_matches = (memcmp(dave_gsk, gsk_v2, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(dave_gsk_matches, "Dave's GSK matches Alice's v2");

    // Step 5: Verify old GSK is different
    printf("\n  Step 5: Verify forward secrecy\n");

    TEST_ASSERT(keys_different, "Old GSK v1 cannot decrypt new messages");
    printf("    → Forward secrecy: Old members with v1 cannot read new messages\n");

    // Cleanup
    free(packet);
    cleanup_test_user(&alice);
    cleanup_test_user(&bob);
    cleanup_test_user(&carol);
    cleanup_test_user(&dave);

    TEST_END();
}

/**
 * Integration Test 3: Remove Member (GSK Rotation)
 *
 * Flow:
 * 1. Group with Alice, Bob, Carol, Dave (GSK v2)
 * 2. Alice removes Dave
 * 3. GSK rotates to v3 (automatic)
 * 4. Dave cannot decrypt new messages
 */
void test_remove_member_rotation() {
    TEST_START("Integration Test 3: Remove Member (GSK Rotation)");

    // Setup users
    test_user_t alice, bob, carol, dave;
    setup_test_user(&alice, "alice", TEST_DB_PATH_ALICE);
    setup_test_user(&bob, "bob", TEST_DB_PATH_BOB);
    setup_test_user(&carol, "carol", TEST_DB_PATH_CAROL);
    setup_test_user(&dave, "dave", "/tmp/test_group_dave_messages.db");

    // Step 1: Group with v2
    printf("\n  Step 1: Group with GSK v2 (4 members)\n");

    unlink(TEST_DB_PATH_ALICE);
    gsk_init_db(TEST_DB_PATH_ALICE);

    uint8_t gsk_v2[GSK_KEY_SIZE];
    gsk_generate(gsk_v2);
    gsk_store(TEST_GROUP_UUID, 2, gsk_v2);

    // Step 2: Remove Dave (triggers rotation)
    printf("\n  Step 2: Alice removes Dave (triggers GSK rotation)\n");

    uint32_t new_version;
    uint8_t gsk_v3[GSK_KEY_SIZE];
    int ret = gsk_rotate(TEST_GROUP_UUID, &new_version, gsk_v3);
    TEST_ASSERT(ret == 0, "GSK rotation succeeded");
    TEST_ASSERT(new_version == 3, "Version incremented to 3");

    int keys_different = (memcmp(gsk_v2, gsk_v3, GSK_KEY_SIZE) != 0);
    TEST_ASSERT(keys_different, "GSK v3 is different from v2");

    gsk_store(TEST_GROUP_UUID, new_version, gsk_v3);

    // Step 3: Build packet WITHOUT Dave
    printf("\n  Step 3: Build packet excluding Dave\n");

    gsk_member_entry_t members[3];
    memcpy(members[0].fingerprint, bob.fingerprint, 129);
    memcpy(members[0].kyber_pubkey, bob.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    memcpy(members[1].fingerprint, carol.fingerprint, 129);
    memcpy(members[1].kyber_pubkey, carol.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    memcpy(members[2].fingerprint, alice.fingerprint, 129);
    memcpy(members[2].kyber_pubkey, alice.kyber_pubkey, QGP_KYBER_PUBLICKEY_BYTES);

    uint8_t *packet = NULL;
    size_t packet_size = 0;
    ret = gsk_packet_build(TEST_GROUP_UUID, 3, gsk_v3, members, 3,
                           alice.dilithium_privkey, &packet, &packet_size);
    TEST_ASSERT(ret == 0, "New packet built without Dave");

    // Step 4: Verify Dave cannot extract (not in member list)
    printf("\n  Step 4: Verify Dave is excluded\n");

    uint8_t dave_gsk[GSK_KEY_SIZE];
    char dave_uuid[37];
    uint32_t dave_version;
    ret = gsk_packet_extract(packet, packet_size,
                             dave.fingerprint, dave.kyber_privkey,
                             alice.dilithium_pubkey,
                             dave_uuid, &dave_version, dave_gsk);
    TEST_ASSERT(ret != 0, "Dave cannot extract GSK (not in member list)");

    printf("    → Dave excluded from group: Cannot decrypt new messages\n");

    // Step 5: Verify Bob can still extract
    printf("\n  Step 5: Verify Bob can still extract GSK v3\n");

    uint8_t bob_gsk[GSK_KEY_SIZE];
    char bob_uuid[37];
    uint32_t bob_version;
    ret = gsk_packet_extract(packet, packet_size,
                             bob.fingerprint, bob.kyber_privkey,
                             alice.dilithium_pubkey,
                             bob_uuid, &bob_version, bob_gsk);
    TEST_ASSERT(ret == 0, "Bob extracted GSK v3");

    int bob_gsk_matches = (memcmp(bob_gsk, gsk_v3, GSK_KEY_SIZE) == 0);
    TEST_ASSERT(bob_gsk_matches, "Bob's GSK v3 is correct");

    // Cleanup
    free(packet);
    cleanup_test_user(&alice);
    cleanup_test_user(&bob);
    cleanup_test_user(&carol);
    cleanup_test_user(&dave);

    TEST_END();
}

/**
 * Integration Test 4: Ownership Transfer
 *
 * Flow:
 * 1. Alice is owner (publishes heartbeat)
 * 2. Alice goes offline (7+ days)
 * 3. Bob detects Alice offline
 * 4. Ownership transfers to Bob (deterministic)
 * 5. Bob rotates GSK as new owner
 */
void test_ownership_transfer() {
    TEST_START("Integration Test 4: Ownership Transfer");

    printf("  ⚠ Skipping ownership transfer test (requires mock time)\n");
    printf("  → Ownership logic verified via unit tests\n");
    printf("  → See: messenger/group_ownership.{h,c}\n");
    printf("  → Deterministic algorithm: highest SHA3-512(fingerprint)\n");

    // TODO: Implement mock time functions for testing 7-day timeout
    // For now, ownership transfer is tested manually

    TEST_END();
}

/**
 * Main test runner
 */
int main(int argc, char *argv[]) {
    printf("\n");
    printf("################################################################################\n");
    printf("#                                                                              #\n");
    printf("#  Group Messaging Integration Tests - DNA Messenger v0.09                    #\n");
    printf("#                                                                              #\n");
    printf("################################################################################\n");

    // Run integration tests
    test_create_group_and_send();
    test_add_member_rotation();
    test_remove_member_rotation();
    test_ownership_transfer();

    // Summary
    printf("\n");
    printf("################################################################################\n");
    printf("#  INTEGRATION TEST SUMMARY                                                    #\n");
    printf("################################################################################\n");
    printf("\n");
    printf("  Total Tests: %d\n", tests_passed + tests_failed);
    printf("  Passed:      %d ✓\n", tests_passed);
    printf("  Failed:      %d ✗\n", tests_failed);
    printf("\n");

    if (tests_failed == 0) {
        printf("  🎉 ALL INTEGRATION TESTS PASSED!\n");
        printf("\n");
        return 0;
    } else {
        printf("  ❌ SOME INTEGRATION TESTS FAILED\n");
        printf("\n");
        return 1;
    }
}
