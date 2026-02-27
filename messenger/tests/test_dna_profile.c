/**
 * @file test_dna_profile.c
 * @brief Unit tests for DNA profile management
 *
 * Tests profile data structures, validation, and serialization functions.
 *
 * @author DNA Messenger Team
 * @date 2025-11-05
 */

#include "../dht/client/dna_profile.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

// ANSI color codes for test output
#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET "\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) printf("\n[TEST] %s\n", name)
#define TEST_PASS(msg) do { \
    printf("  " COLOR_GREEN "✓" COLOR_RESET " %s\n", msg); \
    tests_passed++; \
} while(0)
#define TEST_FAIL(msg) do { \
    printf("  " COLOR_RED "✗" COLOR_RESET " %s\n", msg); \
    tests_failed++; \
} while(0)
#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        TEST_PASS(msg); \
    } else { \
        TEST_FAIL(msg); \
    } \
} while(0)

// ===== Test: Identity Creation and Destruction =====
void test_identity_creation(void) {
    TEST_START("Identity Creation and Destruction");

    dna_unified_identity_t *identity = dna_identity_create();
    TEST_ASSERT(identity != NULL, "Identity created successfully");

    if (identity) {
        TEST_ASSERT(identity->fingerprint[0] == '\0', "Fingerprint initialized to empty");
        TEST_ASSERT(identity->has_registered_name == false, "Name registration flag initialized to false");
        TEST_ASSERT(identity->version == 0, "Version initialized to 0");
        dna_identity_free(identity);
        TEST_PASS("Identity freed successfully");
    }
}

// ===== Test: Wallet Address Validation =====
void test_wallet_validation(void) {
    TEST_START("Wallet Address Validation");

    // Valid Cellframe address (base58)
    const char *valid_cf = "mHBXVe5rSeAyVmZb3GLLrr56zHkD3b3BzUdqhLYjcgzHZ5e";
    TEST_ASSERT(dna_validate_wallet_address(valid_cf, "backbone"), "Valid Cellframe address accepted");

    // Valid Ethereum address (0x + 40 hex chars = 42 total)
    const char *valid_eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";
    TEST_ASSERT(dna_validate_wallet_address(valid_eth, "eth"), "Valid Ethereum address accepted");

    // Invalid addresses
    TEST_ASSERT(!dna_validate_wallet_address("", "backbone"), "Empty address rejected");
    TEST_ASSERT(!dna_validate_wallet_address("invalid", "eth"), "Invalid Ethereum address rejected");
    TEST_ASSERT(!dna_validate_wallet_address("0x123", "eth"), "Short Ethereum address rejected");

    // Unknown network
    TEST_ASSERT(!dna_validate_wallet_address(valid_cf, "unknown"), "Unknown network rejected");
}

// ===== Test: DNA Name Validation =====
// NOTE: test_ipfs_validation() removed in v0.3.150 - IPFS support removed in commit eb88052
void test_name_validation(void) {
    TEST_START("DNA Name Validation");

    // Valid names
    TEST_ASSERT(dna_validate_name("nocdem"), "Valid name 'nocdem' accepted");
    TEST_ASSERT(dna_validate_name("alice.crypto"), "Valid name with dot accepted");
    TEST_ASSERT(dna_validate_name("bob_test"), "Valid name with underscore accepted");
    TEST_ASSERT(dna_validate_name("charlie-123"), "Valid name with dash and numbers accepted");

    // Invalid names
    TEST_ASSERT(!dna_validate_name("ab"), "Too short name (2 chars) rejected");
    TEST_ASSERT(!dna_validate_name(""), "Empty name rejected");
    TEST_ASSERT(!dna_validate_name("this_name_is_way_too_long_and_exceeds_limit"), "Too long name (>36 chars) rejected");
    TEST_ASSERT(!dna_validate_name("admin"), "Disallowed name 'admin' rejected");
    TEST_ASSERT(!dna_validate_name("root"), "Disallowed name 'root' rejected");
    TEST_ASSERT(!dna_validate_name("name with spaces"), "Name with spaces rejected");
    TEST_ASSERT(!dna_validate_name("name@special"), "Name with @ symbol rejected");
}

// ===== Test: Network Type Checking =====
void test_network_checking(void) {
    TEST_START("Network Type Checking");

    // Cellframe networks
    TEST_ASSERT(dna_network_is_cellframe("backbone"), "Backbone is Cellframe");
    TEST_ASSERT(dna_network_is_cellframe("kelvpn"), "KelVPN is Cellframe");
    TEST_ASSERT(dna_network_is_cellframe("removed"), "Riemann is Cellframe");
    TEST_ASSERT(!dna_network_is_cellframe("eth"), "ETH is not Cellframe");

    // External blockchains
    TEST_ASSERT(dna_network_is_external("eth"), "ETH is external");
    TEST_ASSERT(dna_network_is_external("sol"), "SOL is external");
    TEST_ASSERT(!dna_network_is_external("backbone"), "Backbone is not external");

    // Unknown network
    TEST_ASSERT(!dna_network_is_cellframe("unknown"), "Unknown network not Cellframe");
    TEST_ASSERT(!dna_network_is_external("unknown"), "Unknown network not external");
}

// ===== Test: Wallet Getters and Setters =====
void test_wallet_getters_setters(void) {
    TEST_START("Wallet Getters and Setters");

    dna_unified_identity_t *identity = dna_identity_create();
    if (!identity) {
        TEST_FAIL("Failed to create identity");
        return;
    }

    // Set backbone address
    const char *backbone_addr = "mHBXVe5rSeAyVmZb3GLLrr56zHkD3b3BzUdqhLYjcgzHZ5e";
    int ret = dna_identity_set_wallet(identity, "backbone", backbone_addr);
    TEST_ASSERT(ret == 0, "Set backbone wallet address");

    // Get backbone address
    const char *retrieved = dna_identity_get_wallet(identity, "backbone");
    TEST_ASSERT(retrieved != NULL, "Retrieved backbone address not NULL");
    TEST_ASSERT(strcmp(retrieved, backbone_addr) == 0, "Retrieved address matches set address");

    // Set Ethereum address (0x + 40 hex chars = 42 total)
    const char *eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";
    ret = dna_identity_set_wallet(identity, "eth", eth_addr);
    TEST_ASSERT(ret == 0, "Set Ethereum wallet address");

    // Get Ethereum address
    retrieved = dna_identity_get_wallet(identity, "eth");
    TEST_ASSERT(retrieved != NULL, "Retrieved Ethereum address not NULL");
    TEST_ASSERT(strcmp(retrieved, eth_addr) == 0, "Retrieved ETH address matches");

    // Get unset wallet
    retrieved = dna_identity_get_wallet(identity, "sol");
    TEST_ASSERT(retrieved != NULL && strlen(retrieved) == 0, "Unset wallet returns empty string");

    // Invalid network (returns -2 because address validation fails first for unknown networks)
    ret = dna_identity_set_wallet(identity, "invalid_network", backbone_addr);
    TEST_ASSERT(ret < 0, "Setting invalid network fails (returns error code)");

    dna_identity_free(identity);
}

// ===== Test: Identity JSON Serialization =====
void test_identity_serialization(void) {
    TEST_START("Identity JSON Serialization");

    dna_unified_identity_t *identity = dna_identity_create();
    if (!identity) {
        TEST_FAIL("Failed to create identity");
        return;
    }

    // Set test data
    strncpy(identity->fingerprint, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", sizeof(identity->fingerprint) - 1);
    identity->has_registered_name = true;
    strncpy(identity->registered_name, "testuser", sizeof(identity->registered_name) - 1);
    identity->timestamp = 1699000000;
    identity->version = 1;

    // Serialize
    char *json = dna_identity_to_json(identity);
    TEST_ASSERT(json != NULL, "Identity serialized to JSON");

    if (json) {
        // Check JSON contains expected fields
        TEST_ASSERT(strstr(json, "fingerprint") != NULL, "JSON contains 'fingerprint' field");
        TEST_ASSERT(strstr(json, "has_registered_name") != NULL, "JSON contains name flag");
        TEST_ASSERT(strstr(json, "testuser") != NULL, "JSON contains registered name");

        // Deserialize
        dna_unified_identity_t *parsed = NULL;
        int ret = dna_identity_from_json(json, &parsed);
        TEST_ASSERT(ret == 0, "Identity deserialized from JSON");
        TEST_ASSERT(parsed != NULL, "Parsed identity not NULL");

        if (parsed) {
            TEST_ASSERT(strcmp(parsed->fingerprint, identity->fingerprint) == 0, "Fingerprint matches");
            TEST_ASSERT(parsed->has_registered_name == identity->has_registered_name, "Name flag matches");
            TEST_ASSERT(strcmp(parsed->registered_name, identity->registered_name) == 0, "Registered name matches");
            TEST_ASSERT(parsed->timestamp == identity->timestamp, "Timestamp matches");
            TEST_ASSERT(parsed->version == identity->version, "Version matches");
            dna_identity_free(parsed);
        }

        free(json);
    }

    dna_identity_free(identity);
}

// ===== Main Test Runner =====
int main(void) {
    printf("\n" COLOR_YELLOW "========================================\n");
    printf("DNA Profile Unit Tests\n");
    printf("========================================" COLOR_RESET "\n");

    test_identity_creation();
    test_wallet_validation();
    test_name_validation();
    test_network_checking();
    test_wallet_getters_setters();
    test_identity_serialization();

    printf("\n" COLOR_YELLOW "========================================\n");
    printf("Test Results\n");
    printf("========================================" COLOR_RESET "\n");
    printf(COLOR_GREEN "Passed: %d\n" COLOR_RESET, tests_passed);
    if (tests_failed > 0) {
        printf(COLOR_RED "Failed: %d\n" COLOR_RESET, tests_failed);
    } else {
        printf("Failed: %d\n", tests_failed);
    }
    printf("Total:  %d\n", tests_passed + tests_failed);

    if (tests_failed == 0) {
        printf("\n" COLOR_GREEN "✓ All tests passed!" COLOR_RESET "\n\n");
        return 0;
    } else {
        printf("\n" COLOR_RED "✗ Some tests failed!" COLOR_RESET "\n\n");
        return 1;
    }
}
