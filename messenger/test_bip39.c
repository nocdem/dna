#include <stdio.h>
#include <string.h>
#include "bip39.h"

int main(void) {
    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];

    // Generate a mnemonic
    printf("Generating 24-word BIP39 mnemonic...\n");
    if (bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic)) != 0) {
        fprintf(stderr, "Error: Failed to generate mnemonic\n");
        return 1;
    }

    printf("Generated mnemonic:\n%s\n\n", mnemonic);
    printf("Mnemonic length: %zu bytes\n\n", strlen(mnemonic));

    // Validate the mnemonic
    printf("Validating mnemonic...\n");
    if (!bip39_validate_mnemonic(mnemonic)) {
        fprintf(stderr, "Error: Mnemonic validation failed!\n");
        fprintf(stderr, "This should never happen - the generated mnemonic should be valid!\n");
        return 1;
    }

    printf("✓ Mnemonic is valid\n\n");

    // Try deriving seeds
    printf("Deriving seeds from mnemonic...\n");
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonic, "", signing_seed, encryption_seed) != 0) {
        fprintf(stderr, "Error: Seed derivation failed!\n");
        return 1;
    }

    printf("✓ Seed derivation successful\n");
    printf("✓ All tests passed!\n");

    return 0;
}
