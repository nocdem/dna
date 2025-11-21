/**
 * @file test_gsk_simple.c
 * @brief Simple GSK Unit Tests
 *
 * Basic tests for GSK v0.09 implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../messenger/gsk.h"
#include "../message_backup.h"

#define TEST_GROUP_UUID "550e8400-e29b-41d4-a716-446655440000"
#define TEST_IDENTITY "test_gsk_simple"

int main() {
    printf("\n=== GSK Simple Tests ===\n\n");
    
    // Test 1: Generate GSK
    printf("Test 1: GSK Generation\n");
    uint8_t gsk1[GSK_KEY_SIZE];
    uint8_t gsk2[GSK_KEY_SIZE];
    
    if (gsk_generate(TEST_GROUP_UUID, 1, gsk1) != 0) {
        printf("  FAIL: gsk_generate\n");
        return 1;
    }
    printf("  PASS: GSK generated\n");
    
    if (gsk_generate(TEST_GROUP_UUID, 2, gsk2) != 0) {
        printf("  FAIL: second gsk_generate\n");
        return 1;
    }
    
    if (memcmp(gsk1, gsk2, GSK_KEY_SIZE) == 0) {
        printf("  FAIL: GSKs not unique\n");
        return 1;
    }
    printf("  PASS: GSKs are unique\n");
    
    // Test 2: Storage and Loading
    printf("\nTest 2: Storage and Loading\n");

    // Initialize message backup context (required for GSK)
    message_backup_context_t *backup_ctx = message_backup_init(TEST_IDENTITY);
    if (!backup_ctx) {
        printf("  FAIL: message_backup_init\n");
        return 1;
    }

    if (gsk_init(backup_ctx) != 0) {
        printf("  FAIL: gsk_init\n");
        return 1;
    }
    printf("  PASS: Database initialized\n");
    
    if (gsk_store(TEST_GROUP_UUID, 1, gsk1) != 0) {
        printf("  FAIL: gsk_store\n");
        return 1;
    }
    printf("  PASS: GSK stored\n");
    
    uint8_t loaded_gsk[GSK_KEY_SIZE];
    uint32_t loaded_version = 0;
    if (gsk_load_active(TEST_GROUP_UUID, loaded_gsk, &loaded_version) != 0) {
        printf("  FAIL: gsk_load_active\n");
        return 1;
    }

    if (loaded_version != 1) {
        printf("  FAIL: version mismatch (expected 1, got %u)\n", loaded_version);
        return 1;
    }
    printf("  PASS: Version correct\n");

    if (memcmp(gsk1, loaded_gsk, GSK_KEY_SIZE) != 0) {
        printf("  FAIL: GSK mismatch\n");
        return 1;
    }
    printf("  PASS: GSK matches\n");
    
    // Test 3: Rotation
    printf("\nTest 3: Rotation\n");
    uint32_t new_version;
    uint8_t gsk_rotated[GSK_KEY_SIZE];
    
    if (gsk_rotate(TEST_GROUP_UUID, &new_version, gsk_rotated) != 0) {
        printf("  FAIL: gsk_rotate\n");
        return 1;
    }
    
    if (new_version != 2) {
        printf("  FAIL: version not incremented (expected 2, got %u)\n", new_version);
        return 1;
    }
    printf("  PASS: Version incremented to %u\n", new_version);
    
    if (memcmp(gsk1, gsk_rotated, GSK_KEY_SIZE) == 0) {
        printf("  FAIL: Rotated GSK same as original\n");
        return 1;
    }
    printf("  PASS: Rotated GSK is different\n");
    
    printf("\n=== ALL TESTS PASSED ===\n\n");
    return 0;
}
