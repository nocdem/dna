/**
 * @file seed_derivation.c
 * @brief QGP seed derivation from BIP39 master seed
 *
 * Derives deterministic signing and encryption seeds from a BIP39 master seed
 * using SHAKE256 (extensible output function).
 *
 * Derivation scheme:
 * - BIP39 mnemonic → PBKDF2-HMAC-SHA512 → 64-byte master seed
 * - Master seed + context → SHAKE256 → 32-byte signing seed
 * - Master seed + context → SHAKE256 → 32-byte encryption seed
 *
 * @author QGP Development Team
 * @date 2025-10-12
 */

#include "bip39.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "crypto/kyber512/fips202_kyber.h"

/**
 * Derive QGP signing and encryption seeds from BIP39 mnemonic
 *
 * Uses BIP39 to generate a 64-byte master seed, then derives:
 * - signing_seed = SHAKE256(master_seed || "qgp-signing-v1", 32)
 * - encryption_seed = SHAKE256(master_seed || "qgp-encryption-v1", 32)
 *
 * @param mnemonic BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
 * @param passphrase Optional passphrase (empty string if none)
 * @param signing_seed Output buffer for signing seed (32 bytes)
 * @param encryption_seed Output buffer for encryption seed (32 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_derive_seeds_from_mnemonic(
    const char *mnemonic,
    const char *passphrase,
    uint8_t signing_seed[32],
    uint8_t encryption_seed[32]
) {
    if (!mnemonic || !signing_seed || !encryption_seed) {
        return -1;
    }

    // Validate mnemonic
    if (!bip39_validate_mnemonic(mnemonic)) {
        fprintf(stderr, "Error: Invalid BIP39 mnemonic\n");
        return -1;
    }

    // Derive 64-byte master seed from mnemonic
    uint8_t master_seed[BIP39_SEED_SIZE];
    if (bip39_mnemonic_to_seed(mnemonic, passphrase, master_seed) != 0) {
        fprintf(stderr, "Error: Failed to derive master seed from mnemonic\n");
        return -1;
    }

    // Derive signing seed: SHAKE256(master_seed || "qgp-signing-v1", 32)
    {
        const char *signing_context = "qgp-signing-v1";
        size_t context_len = strlen(signing_context);
        size_t input_len = BIP39_SEED_SIZE + context_len;

        uint8_t *input = malloc(input_len);
        if (!input) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return -1;
        }

        memcpy(input, master_seed, BIP39_SEED_SIZE);
        memcpy(input + BIP39_SEED_SIZE, signing_context, context_len);

        shake256(signing_seed, 32, input, input_len);
        free(input);
    }

    // Derive encryption seed: SHAKE256(master_seed || "qgp-encryption-v1", 32)
    {
        const char *encryption_context = "qgp-encryption-v1";
        size_t context_len = strlen(encryption_context);
        size_t input_len = BIP39_SEED_SIZE + context_len;

        uint8_t *input = malloc(input_len);
        if (!input) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return -1;
        }

        memcpy(input, master_seed, BIP39_SEED_SIZE);
        memcpy(input + BIP39_SEED_SIZE, encryption_context, context_len);

        shake256(encryption_seed, 32, input, input_len);
        free(input);
    }

    // Clear master seed from memory (security)
    memset(master_seed, 0, BIP39_SEED_SIZE);

    return 0;
}

/**
 * Display BIP39 mnemonic in a user-friendly format
 *
 * Prints mnemonic with word numbers for easy verification and backup.
 *
 * @param mnemonic BIP39 mnemonic phrase
 */
void qgp_display_mnemonic(const char *mnemonic) {
    if (!mnemonic) {
        return;
    }

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║                         BIP39 RECOVERY PHRASE                         ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                       ║\n");

    // Split mnemonic into words
    char *mnemonic_copy = strdup(mnemonic);
    if (!mnemonic_copy) {
        return;
    }

    char *token = strtok(mnemonic_copy, " ");
    int word_num = 1;

    while (token != NULL) {
        printf("║  %2d. %-15s", word_num, token);

        // Print in two columns
        token = strtok(NULL, " ");
        if (token != NULL) {
            printf("  %2d. %-15s  ║\n", word_num + 1, token);
            word_num += 2;
            token = strtok(NULL, " ");
        } else {
            printf("                     ║\n");
            break;
        }
    }

    printf("║                                                                       ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    printf("║ ⚠️  IMPORTANT: Write down these words in order and store securely    ║\n");
    printf("║     This phrase can recover your keys. Keep it safe!                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    free(mnemonic_copy);
}
