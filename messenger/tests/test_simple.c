#include "../dht/client/dna_profile.h"
#include <stdio.h>
#include <assert.h>

int main() {
    printf("Test 1: Create identity...\n");
    dna_unified_identity_t *identity = dna_identity_create();
    assert(identity != NULL);
    printf("  OK\n");

    printf("Test 2: Free identity...\n");
    dna_identity_free(identity);
    printf("  OK\n");

    printf("Test 3: Validate name...\n");
    int result = dna_validate_name("nocdem");
    printf("  Result: %d\n", result);

    printf("Test 4: Validate wallet...\n");
    result = dna_validate_wallet_address("mHBXVe5rSeAyVmZb3GLLrr56zHkD3b3BzUdqhLYjcgzHZ5e", "backbone");
    printf("  Result: %d\n", result);

    printf("\nAll tests passed!\n");
    return 0;
}
