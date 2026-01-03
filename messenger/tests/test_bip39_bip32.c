/**
 * @file test_bip39_bip32.c
 * @brief Test BIP39 mnemonic and BIP32 HD key derivation
 *
 * Tests:
 * - BIP39 mnemonic generation (12, 24 words)
 * - BIP39 mnemonic validation
 * - BIP39 seed derivation (with/without passphrase)
 * - BIP32 master key derivation
 * - BIP32 hardened/normal child derivation
 * - BIP32 path derivation (Ethereum BIP-44)
 * - Known test vectors
 *
 * Part of DNA Messenger beta readiness testing (P1-2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../crypto/bip39/bip39.h"
#include "../crypto/bip32/bip32.h"
#include "../crypto/utils/qgp_random.h"

#define TEST_PASSED(name) printf("   ✓ %s\n", name)
#define TEST_FAILED(name) do { printf("   ✗ %s\n", name); return 1; } while(0)

/* Helper to print hex */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("   %s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/**
 * Test BIP39 mnemonic generation (12 words)
 */
static int test_mnemonic_generation_12(void) {
    printf("\n1. Testing 12-word mnemonic generation...\n");

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];

    int ret = bip39_generate_mnemonic(12, mnemonic, sizeof(mnemonic));
    if (ret != 0) TEST_FAILED("Mnemonic generation failed");
    TEST_PASSED("Mnemonic generated");

    /* Count words */
    int word_count = 1;
    for (size_t i = 0; mnemonic[i]; i++) {
        if (mnemonic[i] == ' ') word_count++;
    }

    if (word_count != 12) {
        printf("   Expected 12 words, got %d\n", word_count);
        TEST_FAILED("Wrong word count");
    }
    TEST_PASSED("Word count verified (12)");

    /* Validate the generated mnemonic */
    if (!bip39_validate_mnemonic(mnemonic)) {
        TEST_FAILED("Generated mnemonic failed validation");
    }
    TEST_PASSED("Mnemonic passes validation");

    printf("   Mnemonic: %.40s...\n", mnemonic);
    return 0;
}

/**
 * Test BIP39 mnemonic generation (24 words)
 */
static int test_mnemonic_generation_24(void) {
    printf("\n2. Testing 24-word mnemonic generation...\n");

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];

    int ret = bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic));
    if (ret != 0) TEST_FAILED("Mnemonic generation failed");
    TEST_PASSED("Mnemonic generated");

    /* Count words */
    int word_count = 1;
    for (size_t i = 0; mnemonic[i]; i++) {
        if (mnemonic[i] == ' ') word_count++;
    }

    if (word_count != 24) {
        printf("   Expected 24 words, got %d\n", word_count);
        TEST_FAILED("Wrong word count");
    }
    TEST_PASSED("Word count verified (24)");

    /* Validate the generated mnemonic */
    if (!bip39_validate_mnemonic(mnemonic)) {
        TEST_FAILED("Generated mnemonic failed validation");
    }
    TEST_PASSED("Mnemonic passes validation");

    return 0;
}

/**
 * Test BIP39 mnemonic validation
 */
static int test_mnemonic_validation(void) {
    printf("\n3. Testing mnemonic validation...\n");

    /* Valid 12-word mnemonic (BIP39 test vector) */
    const char *valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    if (!bip39_validate_mnemonic(valid_mnemonic)) {
        TEST_FAILED("Valid mnemonic rejected");
    }
    TEST_PASSED("Valid mnemonic accepted");

    /* Invalid: wrong checksum */
    const char *invalid_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    if (bip39_validate_mnemonic(invalid_checksum)) {
        TEST_FAILED("Invalid checksum accepted");
    }
    TEST_PASSED("Invalid checksum rejected");

    /* Invalid: non-BIP39 word */
    const char *invalid_word = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword";
    if (bip39_validate_mnemonic(invalid_word)) {
        TEST_FAILED("Invalid word accepted");
    }
    TEST_PASSED("Invalid word rejected");

    /* Invalid: wrong word count */
    const char *wrong_count = "abandon abandon abandon";
    if (bip39_validate_mnemonic(wrong_count)) {
        TEST_FAILED("Wrong word count accepted");
    }
    TEST_PASSED("Wrong word count rejected");

    return 0;
}

/**
 * Test BIP39 seed derivation
 */
static int test_seed_derivation(void) {
    printf("\n4. Testing BIP39 seed derivation...\n");

    /* BIP39 test vector */
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    uint8_t seed[BIP39_SEED_SIZE];

    /* Derive seed without passphrase */
    int ret = bip39_mnemonic_to_seed(mnemonic, "", seed);
    if (ret != 0) TEST_FAILED("Seed derivation failed");
    TEST_PASSED("Seed derived (no passphrase)");

    /* Verify seed is non-zero */
    int non_zero = 0;
    for (size_t i = 0; i < BIP39_SEED_SIZE; i++) {
        if (seed[i] != 0) non_zero = 1;
    }
    if (!non_zero) TEST_FAILED("Seed is all zeros");
    TEST_PASSED("Seed contains non-zero data");

    print_hex("Seed (first 32 bytes)", seed, 32);

    /* Derive seed with passphrase */
    uint8_t seed_with_pass[BIP39_SEED_SIZE];
    ret = bip39_mnemonic_to_seed(mnemonic, "TREZOR", seed_with_pass);
    if (ret != 0) TEST_FAILED("Seed derivation with passphrase failed");
    TEST_PASSED("Seed derived (with passphrase)");

    /* Seeds should be different */
    if (memcmp(seed, seed_with_pass, BIP39_SEED_SIZE) == 0) {
        TEST_FAILED("Passphrase didn't change seed");
    }
    TEST_PASSED("Passphrase produces different seed");

    return 0;
}

/**
 * Test QGP seed derivation (signing + encryption seeds)
 */
static int test_qgp_seed_derivation(void) {
    printf("\n5. Testing QGP seed derivation...\n");

    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    int ret = qgp_derive_seeds_from_mnemonic(mnemonic, "", signing_seed, encryption_seed);
    if (ret != 0) TEST_FAILED("QGP seed derivation failed");
    TEST_PASSED("QGP seeds derived");

    /* Seeds should be different from each other */
    if (memcmp(signing_seed, encryption_seed, 32) == 0) {
        TEST_FAILED("Signing and encryption seeds are identical");
    }
    TEST_PASSED("Signing and encryption seeds are different");

    print_hex("Signing seed", signing_seed, 32);
    print_hex("Encryption seed", encryption_seed, 32);

    /* Test with master seed output */
    uint8_t master_seed[64];
    ret = qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed, master_seed);
    if (ret != 0) TEST_FAILED("QGP seed derivation with master failed");
    TEST_PASSED("QGP seeds with master derived");

    return 0;
}

/**
 * Test BIP32 master key derivation
 */
static int test_bip32_master_key(void) {
    printf("\n6. Testing BIP32 master key derivation...\n");

    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /* Get BIP39 seed first */
    uint8_t seed[BIP39_SEED_SIZE];
    int ret = bip39_mnemonic_to_seed(mnemonic, "", seed);
    if (ret != 0) TEST_FAILED("BIP39 seed derivation failed");

    /* Derive master key */
    bip32_extended_key_t master;
    ret = bip32_master_key_from_seed(seed, BIP39_SEED_SIZE, &master);
    if (ret != 0) TEST_FAILED("Master key derivation failed");
    TEST_PASSED("Master key derived");

    /* Verify master key properties */
    if (master.depth != 0) TEST_FAILED("Master key depth should be 0");
    TEST_PASSED("Master key depth is 0");

    /* Key should be non-zero */
    int non_zero = 0;
    for (size_t i = 0; i < BIP32_KEY_SIZE; i++) {
        if (master.private_key[i] != 0) non_zero = 1;
    }
    if (!non_zero) TEST_FAILED("Master private key is all zeros");
    TEST_PASSED("Master private key is non-zero");

    print_hex("Master private key", master.private_key, 32);

    /* Clean up */
    bip32_clear_key(&master);
    return 0;
}

/**
 * Test BIP32 child derivation
 */
static int test_bip32_child_derivation(void) {
    printf("\n7. Testing BIP32 child derivation...\n");

    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    uint8_t seed[BIP39_SEED_SIZE];
    bip39_mnemonic_to_seed(mnemonic, "", seed);

    bip32_extended_key_t master;
    bip32_master_key_from_seed(seed, BIP39_SEED_SIZE, &master);

    /* Derive hardened child (m/44') */
    bip32_extended_key_t child44;
    int ret = bip32_derive_hardened(&master, 44, &child44);
    if (ret != 0) TEST_FAILED("Hardened child derivation failed");
    TEST_PASSED("Hardened child derived (m/44')");

    if (child44.depth != 1) TEST_FAILED("Child depth should be 1");
    TEST_PASSED("Child depth is 1");

    /* Child key should be different from master */
    if (memcmp(master.private_key, child44.private_key, BIP32_KEY_SIZE) == 0) {
        TEST_FAILED("Child key same as master");
    }
    TEST_PASSED("Child key differs from master");

    /* Derive another level (m/44'/60') */
    bip32_extended_key_t child60;
    ret = bip32_derive_hardened(&child44, 60, &child60);
    if (ret != 0) TEST_FAILED("Second level derivation failed");
    TEST_PASSED("Second level derived (m/44'/60')");

    if (child60.depth != 2) TEST_FAILED("Grandchild depth should be 2");
    TEST_PASSED("Grandchild depth is 2");

    /* Clean up */
    bip32_clear_key(&master);
    bip32_clear_key(&child44);
    bip32_clear_key(&child60);
    return 0;
}

/**
 * Test BIP32 path derivation (Ethereum)
 */
static int test_bip32_path_derivation(void) {
    printf("\n8. Testing BIP32 path derivation (Ethereum)...\n");

    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    uint8_t seed[BIP39_SEED_SIZE];
    bip39_mnemonic_to_seed(mnemonic, "", seed);

    /* Derive Ethereum key using convenience function */
    bip32_extended_key_t eth_key;
    int ret = bip32_derive_ethereum(seed, BIP39_SEED_SIZE, &eth_key);
    if (ret != 0) TEST_FAILED("Ethereum key derivation failed");
    TEST_PASSED("Ethereum key derived (m/44'/60'/0'/0/0)");

    /* Verify depth (should be 5 for full path) */
    if (eth_key.depth != 5) {
        printf("   Expected depth 5, got %u\n", eth_key.depth);
        TEST_FAILED("Wrong derivation depth");
    }
    TEST_PASSED("Derivation depth is 5");

    print_hex("Ethereum private key", eth_key.private_key, 32);

    /* Get public key */
    uint8_t pubkey[65];
    ret = bip32_get_public_key(&eth_key, pubkey);
    if (ret != 0) TEST_FAILED("Public key derivation failed");
    TEST_PASSED("Public key derived");

    if (pubkey[0] != 0x04) TEST_FAILED("Public key should start with 0x04");
    TEST_PASSED("Public key format correct (uncompressed)");

    /* Also test path string derivation */
    bip32_extended_key_t path_key;
    ret = bip32_derive_path(seed, BIP39_SEED_SIZE, "m/44'/60'/0'/0/0", &path_key);
    if (ret != 0) TEST_FAILED("Path string derivation failed");
    TEST_PASSED("Path string derivation succeeded");

    /* Both methods should produce same key */
    if (memcmp(eth_key.private_key, path_key.private_key, BIP32_KEY_SIZE) != 0) {
        TEST_FAILED("Path methods produce different keys");
    }
    TEST_PASSED("Both derivation methods match");

    /* Clean up */
    bip32_clear_key(&eth_key);
    bip32_clear_key(&path_key);
    return 0;
}

/**
 * Test deterministic derivation
 */
static int test_deterministic(void) {
    printf("\n9. Testing deterministic derivation...\n");

    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /* Derive twice */
    uint8_t seed1[BIP39_SEED_SIZE], seed2[BIP39_SEED_SIZE];
    bip39_mnemonic_to_seed(mnemonic, "", seed1);
    bip39_mnemonic_to_seed(mnemonic, "", seed2);

    if (memcmp(seed1, seed2, BIP39_SEED_SIZE) != 0) {
        TEST_FAILED("Same mnemonic produces different seeds");
    }
    TEST_PASSED("Seed derivation is deterministic");

    /* Derive master keys */
    bip32_extended_key_t master1, master2;
    bip32_master_key_from_seed(seed1, BIP39_SEED_SIZE, &master1);
    bip32_master_key_from_seed(seed2, BIP39_SEED_SIZE, &master2);

    if (memcmp(master1.private_key, master2.private_key, BIP32_KEY_SIZE) != 0) {
        TEST_FAILED("Same seed produces different master keys");
    }
    TEST_PASSED("Master key derivation is deterministic");

    /* Derive Ethereum keys */
    bip32_extended_key_t eth1, eth2;
    bip32_derive_ethereum(seed1, BIP39_SEED_SIZE, &eth1);
    bip32_derive_ethereum(seed2, BIP39_SEED_SIZE, &eth2);

    if (memcmp(eth1.private_key, eth2.private_key, BIP32_KEY_SIZE) != 0) {
        TEST_FAILED("Same seed produces different Ethereum keys");
    }
    TEST_PASSED("Ethereum key derivation is deterministic");

    /* Clean up */
    bip32_clear_key(&master1);
    bip32_clear_key(&master2);
    bip32_clear_key(&eth1);
    bip32_clear_key(&eth2);
    return 0;
}

/**
 * Test multiple mnemonics produce different keys
 */
static int test_uniqueness(void) {
    printf("\n10. Testing uniqueness across mnemonics...\n");

    char mnemonic1[BIP39_MAX_MNEMONIC_LENGTH];
    char mnemonic2[BIP39_MAX_MNEMONIC_LENGTH];

    bip39_generate_mnemonic(24, mnemonic1, sizeof(mnemonic1));
    bip39_generate_mnemonic(24, mnemonic2, sizeof(mnemonic2));

    /* Mnemonics should be different */
    if (strcmp(mnemonic1, mnemonic2) == 0) {
        TEST_FAILED("Two generated mnemonics are identical");
    }
    TEST_PASSED("Generated mnemonics are unique");

    /* Derive seeds */
    uint8_t seed1[BIP39_SEED_SIZE], seed2[BIP39_SEED_SIZE];
    bip39_mnemonic_to_seed(mnemonic1, "", seed1);
    bip39_mnemonic_to_seed(mnemonic2, "", seed2);

    if (memcmp(seed1, seed2, BIP39_SEED_SIZE) == 0) {
        TEST_FAILED("Different mnemonics produce same seed");
    }
    TEST_PASSED("Different mnemonics produce different seeds");

    /* Derive Ethereum keys */
    bip32_extended_key_t eth1, eth2;
    bip32_derive_ethereum(seed1, BIP39_SEED_SIZE, &eth1);
    bip32_derive_ethereum(seed2, BIP39_SEED_SIZE, &eth2);

    if (memcmp(eth1.private_key, eth2.private_key, BIP32_KEY_SIZE) == 0) {
        TEST_FAILED("Different seeds produce same Ethereum key");
    }
    TEST_PASSED("Different seeds produce different Ethereum keys");

    /* Clean up */
    bip32_clear_key(&eth1);
    bip32_clear_key(&eth2);
    return 0;
}

/**
 * Security information
 */
static void print_security_info(void) {
    printf("\n11. Security Parameters\n");
    printf("   BIP39 Standard: PBKDF2-HMAC-SHA512, %d iterations\n", BIP39_PBKDF2_ROUNDS);
    printf("   BIP39 Seed Size: %d bytes (512 bits)\n", BIP39_SEED_SIZE);
    printf("   BIP39 Wordlist: %d words (English)\n", BIP39_WORDLIST_SIZE);
    printf("   BIP32 Key Size: %d bytes (256 bits)\n", BIP32_KEY_SIZE);
    printf("   BIP32 Curve: secp256k1\n");
    printf("   BIP44 Coin Types: BTC(0), ETH(60), TRX(195), SOL(501)\n");
    printf("   Properties: Deterministic, hierarchical, standard-compliant\n");
}

int main(void) {
    printf("=== BIP39/BIP32 Unit Tests (P1-2) ===\n");

    int failed = 0;

    failed += test_mnemonic_generation_12();
    failed += test_mnemonic_generation_24();
    failed += test_mnemonic_validation();
    failed += test_seed_derivation();
    failed += test_qgp_seed_derivation();
    failed += test_bip32_master_key();
    failed += test_bip32_child_derivation();
    failed += test_bip32_path_derivation();
    failed += test_deterministic();
    failed += test_uniqueness();

    print_security_info();

    printf("\n");
    if (failed == 0) {
        printf("=== All BIP39/BIP32 Tests Passed ===\n");
        return 0;
    } else {
        printf("=== %d Test(s) Failed ===\n", failed);
        return 1;
    }
}
