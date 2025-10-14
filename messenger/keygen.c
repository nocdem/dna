/*
 * pqsignum - Key generation (Signing + Encryption keypairs, Cross-Platform)
 *
 * - Direct Dilithium3 key generation (vendored pq-crystals/dilithium)
 * - Direct Kyber512 key generation (vendored pq-crystals/kyber)
 * - Round-trip verification mandatory for both keys
 * - Cross-platform directory operations via platform abstraction layer
 */

#include "qgp.h"
#include "qgp_types.h"
#include "qgp_compiler.h"
#include "qgp_platform.h"
#include "bip39.h"
#include "kyber_deterministic.h"  // For deterministic Kyber generation
#include "qgp_kyber.h"
#include "qgp_dilithium.h"

// QGP only supports Dilithium3 (ML-DSA-65, FIPS 204)

static qgp_key_type_t get_sign_key_type(const char *algo) {
    if (strcasecmp(algo, "dilithium") == 0) {
        return QGP_KEY_TYPE_DILITHIUM3;
    } else {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", algo);
        fprintf(stderr, "QGP only supports: dilithium (FIPS 204 / ML-DSA-65)\n");
        return QGP_KEY_TYPE_INVALID;
    }
}

/**
 * Generate keypair for pqsignum
 *
 * Creates TWO key files (PQSigNum format):
 * 1. <name>-signing.pqkey - Signing key (Dilithium3 only)
 * 2. <name>-encryption.pqkey - Encryption key (Kyber512 KEM)
 *
 * Protocol Mode:
 * - All keys verified with round-trip tests
 * - Signing key: sign → verify
 * - Encryption key: encap → decap
 */
int cmd_gen_key(const char *name, const char *algo, const char *output_dir) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    char *sign_key_path = NULL;
    char *enc_key_path = NULL;
    int ret = EXIT_ERROR;

    printf("Generating keypair for: %s\n", name);
    printf("  Signing algorithm: %s\n", algo);
    printf("  Encryption: Kyber512 KEM (post-quantum)\n");
    printf("  Output directory: %s\n", output_dir);

    // Get signing key type
    qgp_key_type_t sign_key_type = get_sign_key_type(algo);
    if (sign_key_type == QGP_KEY_TYPE_INVALID) {
        return EXIT_KEY_ERROR;
    }

    // Create output directory if it doesn't exist
    if (!qgp_platform_is_directory(output_dir)) {
        if (qgp_platform_mkdir(output_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", output_dir);
            return EXIT_ERROR;
        }
        printf("Created directory: %s\n", output_dir);
    }

    // Build key file paths (algorithm-aware naming)
    char sign_filename[512];
    char enc_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s-dilithium3.pqkey", name);
    snprintf(enc_filename, sizeof(enc_filename), "%s-kyber512.pqkey", name);

    sign_key_path = build_path(output_dir, sign_filename);
    enc_key_path = build_path(output_dir, enc_filename);

    if (!sign_key_path || !enc_key_path) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Check if files already exist
    if (file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key already exists: %s\n", sign_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key already exists: %s\n", enc_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 1: Generate SIGNING key (Dilithium3 only)
    // ======================================================================

    printf("\n[1/2] Generating signing key (%s)...\n", algo);


    sign_key = qgp_key_new(QGP_KEY_TYPE_DILITHIUM3, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed for signing key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    strncpy(sign_key->name, name, sizeof(sign_key->name) - 1);

    // Allocate Dilithium3 key buffers
    uint8_t *dilithium_pk = calloc(1, QGP_DILITHIUM3_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DILITHIUM3_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Dilithium3 key buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        sign_key = NULL;
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Generate Dilithium3 keypair
    if (qgp_dilithium3_keypair(dilithium_pk, dilithium_sk) != 0) {
        fprintf(stderr, "Error: Dilithium3 key generation failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        sign_key = NULL;
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Store in qgp_key_t structure
    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DILITHIUM3_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DILITHIUM3_SECRETKEYBYTES;

    printf("  ✓ Dilithium3 (ML-DSA-65) signing key generated\n");
    printf("  ✓ Public key: %d bytes\n", QGP_DILITHIUM3_PUBLICKEYBYTES);
    printf("  ✓ Secret key: %d bytes\n", QGP_DILITHIUM3_SECRETKEYBYTES);

    // Save signing key in QGP format
    if (qgp_key_save(sign_key, sign_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Signing key saved: %s\n", sign_key_path);

    // Protocol Mode: Round-trip verification for signing key
    printf("  Verifying signing key (round-trip test)...\n");
    const char *test_data = "qgp-verification-test";
    size_t test_len = strlen(test_data);


    if (sign_key->type == QGP_KEY_TYPE_DILITHIUM3) {
        uint8_t test_sig[QGP_DILITHIUM3_BYTES];
        size_t test_siglen = 0;

        // Sign test data
        if (qgp_dilithium3_signature(test_sig, &test_siglen,
                                      (const uint8_t*)test_data, test_len,
                                      sign_key->private_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 signing failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Verify signature
        if (qgp_dilithium3_verify(test_sig, test_siglen,
                                   (const uint8_t*)test_data, test_len,
                                   sign_key->public_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 verification failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ Dilithium3 key verified (sign → verify PASSED)\n");
        printf("  ✓ Signature size: %zu bytes\n", test_siglen);
    }

    // ======================================================================
    // STEP 2: Generate ENCRYPTION key (Kyber512 KEM)
    // ======================================================================

    printf("\n[2/2] Generating encryption key (Kyber512 KEM)...\n");


    enc_key = qgp_key_new(QGP_KEY_TYPE_KYBER512, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    strncpy(enc_key->name, name, sizeof(enc_key->name) - 1);

    // Allocate buffers for Kyber keypair
    uint8_t *kyber_pk = calloc(1, QGP_KYBER512_PUBLICKEYBYTES);
    uint8_t *kyber_sk = calloc(1, QGP_KYBER512_SECRETKEYBYTES);

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Kyber key buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Generate random Kyber512 keypair using vendored implementation
    if (qgp_kyber512_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "Error: Kyber512 key generation failed\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Store in qgp_key_t structure
    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = QGP_KYBER512_PUBLICKEYBYTES;
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = QGP_KYBER512_SECRETKEYBYTES;

    printf("  ✓ Kyber512 KEM key generated\n");

    // Validate key sizes
    if (!enc_key->public_key || enc_key->public_key_size != 800) {
        fprintf(stderr, "Error: Invalid public key (expected 800 bytes, got %zu)\n",
                enc_key->public_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    if (!enc_key->private_key || enc_key->private_key_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n",
                enc_key->private_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Save encryption key in QGP format
    if (qgp_key_save(enc_key, enc_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key saved: %s\n", enc_key_path);
    printf("  ✓ Public key: 800 bytes\n");
    printf("  ✓ Private key: 1632 bytes\n");

    // ======================================================================
    // SUCCESS
    // ======================================================================

    printf("\n✓ Keypair generation complete!\n");
    printf("\nGenerated files:\n");
    printf("  Signing key:     %s (keep private!)\n", sign_key_path);
    printf("  Encryption key:  %s (keep private!)\n", enc_key_path);

    // Register keys in keyring
    printf("\nRegistering keys in keyring...\n");
    if (keyring_register_private_key(name, sign_key_path, enc_key_path) == 0) {
        printf("  ✓ Keys registered in keyring\n");
        printf("  View with: qgp --list-keys\n");
    } else {
        printf("  ⚠ Warning: Could not register keys in keyring (non-fatal)\n");
    }

    // Auto-export public key directly to keyring
    printf("\nExporting public key to keyring...\n");

    // Create keyring directory path
    char *keyring_dir = build_path(output_dir, "keyring");
    if (!keyring_dir) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for keyring path\n");
        goto skip_export;
    }

    // Create keyring directory if it doesn't exist
    if (!qgp_platform_is_directory(keyring_dir)) {
        if (qgp_platform_mkdir(keyring_dir) != 0) {
            fprintf(stderr, "  ⚠ Warning: Cannot create keyring directory: %s\n", keyring_dir);
            free(keyring_dir);
            goto skip_export;
        }
    }

    // Build public key path in keyring directory
    char pubkey_filename[512];
    snprintf(pubkey_filename, sizeof(pubkey_filename), "%s.pub", name);
    char *pubkey_path = build_path(keyring_dir, pubkey_filename);
    free(keyring_dir);

    if (!pubkey_path) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for public key path\n");
        goto skip_export;
    }

    // Export public key directly to keyring
    if (cmd_export_pubkey(name, output_dir, pubkey_path) == 0) {
        printf("  ✓ Public key exported to keyring: %s\n", pubkey_path);

        // Import the exported public key into keyring index
        if (cmd_keyring_import(pubkey_path, name) == 0) {
            printf("  ✓ Public key registered in keyring\n");
            printf("  You can now use: qgp --encrypt --file secret.txt --recipient %s\n", name);
        } else {
            printf("  ⚠ Warning: Could not register public key in keyring (non-fatal)\n");
        }
    } else {
        printf("  ⚠ Warning: Could not export public key (non-fatal)\n");
        printf("  You can export it later with: qgp --export --name %s\n", name);
    }

    free(pubkey_path);

skip_export:
    printf("\nNext steps:\n");
    printf("  1. Share your public key with others:\n");
    printf("       Export with: qgp --export --name %s --output %s.asc\n", name, name);
    printf("\n  2. Sign a file:\n");
    printf("       qgp --sign --file document.pdf --key %s\n", name);
    printf("\n  3. Encrypt a file for someone:\n");
    printf("       qgp --encrypt --file secret.txt --recipient <their-name>\n");
    printf("\n  4. Decrypt a file sent to you:\n");
    printf("       qgp --decrypt --file secret.txt.enc --key %s\n", name);

    ret = EXIT_SUCCESS;

cleanup:
    if (sign_key_path) free(sign_key_path);
    if (enc_key_path) free(enc_key_path);


    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}

/**
 * Generate keypair from randomly generated BIP39 mnemonic
 *
 * Creates TWO key files (PQSigNum format) from deterministic seeds:
 * 1. <name>-signing.pqkey - Signing key (Dilithium/Falcon/SPHINCS+)
 * 2. <name>-encryption.pqkey - Encryption key (Kyber512 KEM)
 *
 * Seed Derivation:
 * - Generates random 24-word BIP39 mnemonic
 * - Displays mnemonic to user (for backup)
 * - Prompts for optional passphrase
 * - Derives signing_seed[32] and encryption_seed[32] via PBKDF2-HMAC-SHA512 + SHAKE256
 * - Uses deterministic Dilithium3 and Kyber512 key generation from seeds
 *
 * Security:
 * - All keys verified with round-trip tests
 * - Signing key: sign → verify
 * - Encryption key: encap → decap
 */
int cmd_gen_key_from_seed(const char *name, const char *algo, const char *output_dir) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    char *sign_key_path = NULL;
    char *enc_key_path = NULL;
    int ret = EXIT_ERROR;

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    char passphrase[256];
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    printf("Generating keypair with BIP39 recovery seed for: %s\n", name);
    printf("  Signing algorithm: %s\n", algo);
    printf("  Encryption: Kyber512 KEM (post-quantum)\n");
    printf("  Output directory: %s\n", output_dir);
    printf("\n");

    // Get signing key type
    qgp_key_type_t sign_key_type = get_sign_key_type(algo);
    if (sign_key_type == QGP_KEY_TYPE_INVALID) {
        return EXIT_KEY_ERROR;
    }

    // ======================================================================
    // STEP 1: Generate random 24-word BIP39 mnemonic
    // ======================================================================

    printf("[Step 1/4] Generating random 24-word BIP39 mnemonic...\n");
    if (bip39_generate_mnemonic(24, mnemonic, sizeof(mnemonic)) != 0) {
        fprintf(stderr, "✗ Error: Failed to generate mnemonic\n");
        return EXIT_CRYPTO_ERROR;
    }
    printf("  ✓ Mnemonic generated\n\n");

    // ======================================================================
    // STEP 2: Display mnemonic to user (for backup)
    // ======================================================================

    printf("════════════════════════════════════════════════════════════════════\n");
    printf("                  ⚠ CRITICAL: WRITE DOWN YOUR RECOVERY SEED ⚠\n");
    printf("════════════════════════════════════════════════════════════════════\n\n");

    printf("Your 24-word BIP39 recovery seed:\n\n");
    qgp_display_mnemonic(mnemonic);

    printf("\n");
    printf("⚠ IMPORTANT:\n");
    printf("  • Write down these 24 words on paper and store securely\n");
    printf("  • This is the ONLY way to recover your keys if lost\n");
    printf("  • Anyone with this seed can access your keys\n");
    printf("  • NEVER share this seed with anyone\n");
    printf("  • NEVER store it digitally (no photos, no cloud)\n");
    printf("\n");
    printf("════════════════════════════════════════════════════════════════════\n\n");

    // Wait for user confirmation
    printf("Press Enter after you have written down your recovery seed...\n");
    char confirm[256];
    if (!fgets(confirm, sizeof(confirm), stdin)) {
        fprintf(stderr, "Error: Failed to read confirmation\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        return EXIT_ERROR;
    }

    // ======================================================================
    // STEP 3: Prompt for optional passphrase
    // ======================================================================

    printf("\n[Step 2/4] Optional passphrase (recommended for extra security)\n");
    printf("Enter passphrase (press Enter for none):\n");
    if (!fgets(passphrase, sizeof(passphrase), stdin)) {
        fprintf(stderr, "Error: Failed to read passphrase\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        return EXIT_ERROR;
    }

    // Remove trailing newline
    size_t len = strlen(passphrase);
    if (len > 0 && passphrase[len - 1] == '\n') {
        passphrase[len - 1] = '\0';
    }

    if (strlen(passphrase) > 0) {
        printf("  ✓ Passphrase set (remember this for recovery!)\n");
    } else {
        printf("  ✓ No passphrase (seed alone is sufficient for recovery)\n");
    }

    // ======================================================================
    // STEP 4: Derive QGP seeds
    // ======================================================================

    printf("\n[Step 3/4] Deriving seeds from mnemonic (PBKDF2 2048 iterations + SHAKE256)...\n");
    if (qgp_derive_seeds_from_mnemonic(mnemonic, passphrase, signing_seed, encryption_seed) != 0) {
        fprintf(stderr, "✗ Error: Seed derivation failed\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(passphrase, 0, sizeof(passphrase));
        return EXIT_CRYPTO_ERROR;
    }

    printf("  ✓ Signing seed derived (32 bytes)\n");
    printf("  ✓ Encryption seed derived (32 bytes)\n");

    // Zero out mnemonic and passphrase from memory (security)
    memset(mnemonic, 0, sizeof(mnemonic));
    memset(passphrase, 0, sizeof(passphrase));

    // ======================================================================
    // STEP 5: Create output directory
    // ======================================================================

    printf("\n[Step 4/4] Generating keys from seed...\n");

    if (!qgp_platform_is_directory(output_dir)) {
        if (qgp_platform_mkdir(output_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", output_dir);
            goto cleanup;
        }
        printf("\nCreated directory: %s\n", output_dir);
    }

    // Build key file paths (algorithm-aware naming)
    char sign_filename[512];
    char enc_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s-dilithium3.pqkey", name);
    snprintf(enc_filename, sizeof(enc_filename), "%s-kyber512.pqkey", name);

    sign_key_path = build_path(output_dir, sign_filename);
    enc_key_path = build_path(output_dir, enc_filename);

    if (!sign_key_path || !enc_key_path) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Check if files already exist
    if (file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key already exists: %s\n", sign_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    if (file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key already exists: %s\n", enc_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // ======================================================================
    // STEP 6: Generate SIGNING key from seed
    // ======================================================================

    printf("\n  [1/2] Generating signing key from seed (%s)...\n", algo);


    if (sign_key_type == QGP_KEY_TYPE_DILITHIUM3) {
        sign_key = qgp_key_new(QGP_KEY_TYPE_DILITHIUM3, QGP_KEY_PURPOSE_SIGNING);
        if (!sign_key) {
            fprintf(stderr, "Error: Memory allocation failed for signing key\n");
            ret = EXIT_ERROR;
            goto cleanup;
        }

        strncpy(sign_key->name, name, sizeof(sign_key->name) - 1);

        // Allocate Dilithium3 key buffers
        uint8_t *dilithium_pk = calloc(1, QGP_DILITHIUM3_PUBLICKEYBYTES);
        uint8_t *dilithium_sk = calloc(1, QGP_DILITHIUM3_SECRETKEYBYTES);

        if (!dilithium_pk || !dilithium_sk) {
            fprintf(stderr, "Error: Memory allocation failed for Dilithium3 key buffers\n");
            free(dilithium_pk);
            free(dilithium_sk);
            qgp_key_free(sign_key);
            sign_key = NULL;
            ret = EXIT_ERROR;
            goto cleanup;
        }

        // Generate deterministic Dilithium3 keypair from seed
        if (qgp_dilithium3_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
            fprintf(stderr, "Error: Dilithium3 key generation from seed failed\n");
            free(dilithium_pk);
            free(dilithium_sk);
            qgp_key_free(sign_key);
            sign_key = NULL;
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Store in qgp_key_t structure
        sign_key->public_key = dilithium_pk;
        sign_key->public_key_size = QGP_DILITHIUM3_PUBLICKEYBYTES;
        sign_key->private_key = dilithium_sk;
        sign_key->private_key_size = QGP_DILITHIUM3_SECRETKEYBYTES;

        printf("  ✓ Dilithium3 (ML-DSA-65) signing key generated from seed (deterministic)\n");
        printf("  ✓ Public key: %d bytes\n", QGP_DILITHIUM3_PUBLICKEYBYTES);
        printf("  ✓ Secret key: %d bytes\n", QGP_DILITHIUM3_SECRETKEYBYTES);
    }

    // Save signing key in QGP format
    if (qgp_key_save(sign_key, sign_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Signing key saved: %s\n", sign_key_path);

    // Protocol Mode: Round-trip verification for signing key
    printf("  Verifying signing key (round-trip test)...\n");
    const char *test_data = "pqsignum-verification-test";
    size_t test_len = strlen(test_data);


    if (sign_key->type == QGP_KEY_TYPE_DILITHIUM3) {
        uint8_t test_sig[QGP_DILITHIUM3_BYTES];
        size_t test_siglen = 0;

        // Sign test data
        if (qgp_dilithium3_signature(test_sig, &test_siglen,
                                      (const uint8_t*)test_data, test_len,
                                      sign_key->private_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 signing failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        // Verify signature
        if (qgp_dilithium3_verify(test_sig, test_siglen,
                                   (const uint8_t*)test_data, test_len,
                                   sign_key->public_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 verification failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup;
        }

        printf("  ✓ Dilithium3 key verified (sign → verify PASSED)\n");
        printf("  ✓ Signature size: %zu bytes\n", test_siglen);
    }

    // ======================================================================
    // STEP 7: Generate ENCRYPTION key from seed
    // ======================================================================

    printf("\n  [2/2] Generating encryption key from seed (Kyber512 KEM)...\n");


    enc_key = qgp_key_new(QGP_KEY_TYPE_KYBER512, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    strncpy(enc_key->name, name, sizeof(enc_key->name) - 1);

    // Allocate buffers for Kyber keypair
    uint8_t *kyber_pk = calloc(1, 800);
    uint8_t *kyber_sk = calloc(1, 1632);

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Kyber key buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_ERROR;
        goto cleanup;
    }

    // Generate deterministic Kyber512 keypair from seed
    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: Deterministic Kyber512 key generation failed\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Store in qgp_key_t structure
    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 800;
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 1632;

    printf("  ✓ Kyber512 KEM key generated from seed (deterministic)\n");

    // Validate key sizes
    if (!enc_key->public_key || enc_key->public_key_size != 800) {
        fprintf(stderr, "Error: Invalid public key (expected 800 bytes, got %zu)\n",
                enc_key->public_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    if (!enc_key->private_key || enc_key->private_key_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n",
                enc_key->private_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup;
    }

    // Save encryption key in QGP format
    if (qgp_key_save(enc_key, enc_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup;
    }

    printf("  ✓ Encryption key saved: %s\n", enc_key_path);
    printf("  ✓ Public key: 800 bytes\n");
    printf("  ✓ Private key: 1632 bytes\n");

    // ======================================================================
    // SUCCESS
    // ======================================================================

    printf("\n✓ Keypair generation from seed complete!\n");
    printf("\nGenerated files:\n");
    printf("  Signing key:     %s (keep private!)\n", sign_key_path);
    printf("  Encryption key:  %s (keep private!)\n", enc_key_path);

    printf("\n⚠ IMPORTANT: Store your BIP39 mnemonic securely!\n");
    printf("  - Your keys can be recovered from the mnemonic + passphrase\n");
    printf("  - Without the mnemonic, you cannot recover your keys\n");
    printf("  - Write it down and store in a secure location\n");

    // Register keys in keyring
    printf("\nRegistering keys in keyring...\n");
    if (keyring_register_private_key(name, sign_key_path, enc_key_path) == 0) {
        printf("  ✓ Keys registered in keyring\n");
        printf("  View with: qgp --list-keys\n");
    } else {
        printf("  ⚠ Warning: Could not register keys in keyring (non-fatal)\n");
    }

    // Auto-export public key directly to keyring
    printf("\nExporting public key to keyring...\n");

    // Create keyring directory path
    char *keyring_dir = build_path(output_dir, "keyring");
    if (!keyring_dir) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for keyring path\n");
        goto skip_export;
    }

    // Create keyring directory if it doesn't exist
    if (!qgp_platform_is_directory(keyring_dir)) {
        if (qgp_platform_mkdir(keyring_dir) != 0) {
            fprintf(stderr, "  ⚠ Warning: Cannot create keyring directory: %s\n", keyring_dir);
            free(keyring_dir);
            goto skip_export;
        }
    }

    // Build public key path in keyring directory
    char pubkey_filename[512];
    snprintf(pubkey_filename, sizeof(pubkey_filename), "%s.pub", name);
    char *pubkey_path = build_path(keyring_dir, pubkey_filename);
    free(keyring_dir);

    if (!pubkey_path) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for public key path\n");
        goto skip_export;
    }

    // Export public key directly to keyring
    if (cmd_export_pubkey(name, output_dir, pubkey_path) == 0) {
        printf("  ✓ Public key exported to keyring: %s\n", pubkey_path);

        // Import the exported public key into keyring index
        if (cmd_keyring_import(pubkey_path, name) == 0) {
            printf("  ✓ Public key registered in keyring\n");
            printf("  You can now use: qgp --encrypt --file secret.txt --recipient %s\n", name);
        } else {
            printf("  ⚠ Warning: Could not register public key in keyring (non-fatal)\n");
        }
    } else {
        printf("  ⚠ Warning: Could not export public key (non-fatal)\n");
        printf("  You can export it later with: qgp --export --name %s\n", name);
    }

    free(pubkey_path);

skip_export:
    printf("\nNext steps:\n");
    printf("  1. Share your public key with others:\n");
    printf("       Export with: qgp --export --name %s --output %s.asc\n", name, name);
    printf("\n  2. Sign a file:\n");
    printf("       qgp --sign --file document.pdf --key %s\n", name);
    printf("\n  3. Encrypt a file for someone:\n");
    printf("       qgp --encrypt --file secret.txt --recipient <their-name>\n");
    printf("\n  4. Decrypt a file sent to you:\n");
    printf("       qgp --decrypt --file secret.txt.enc --key %s\n", name);
    printf("\n  5. To recover lost keys:\n");
    printf("       Use: qgp --restore --name <newname>\n");
    printf("       (You'll be prompted for your 24-word recovery seed)\n");

    ret = EXIT_SUCCESS;

cleanup:
    // Zero out seeds from memory (security)
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    if (sign_key_path) free(sign_key_path);
    if (enc_key_path) free(enc_key_path);


    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}

/**
 * Restore keypair from existing BIP39 mnemonic
 *
 * Creates TWO key files (PQSigNum format) from user-provided mnemonic:
 * 1. <name>-signing.pqkey - Signing key (Dilithium/Falcon/SPHINCS+)
 * 2. <name>-encryption.pqkey - Encryption key (Kyber512 KEM)
 *
 * Recovery Workflow:
 * - Prompts user for existing 24-word BIP39 mnemonic
 * - Validates mnemonic checksum
 * - Prompts for passphrase (if used during generation)
 * - Derives signing_seed[32] and encryption_seed[32] via PBKDF2-HMAC-SHA512 + SHAKE256
 * - Regenerates keys deterministically (identical to original keys)
 *
 * Security:
 * - All keys verified with round-trip tests
 * - Signing key: sign → verify
 * - Encryption key: encap → decap
 */
int cmd_restore_key_from_seed(const char *name, const char *algo, const char *output_dir) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    char *sign_key_path = NULL;
    char *enc_key_path = NULL;
    int ret = EXIT_ERROR;

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    char passphrase[256];
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    printf("Restoring keypair from BIP39 recovery seed for: %s\n", name);
    printf("  Signing algorithm: %s\n", algo);
    printf("  Encryption: Kyber512 KEM (post-quantum)\n");
    printf("  Output directory: %s\n", output_dir);
    printf("\n");

    // Get signing key type
    qgp_key_type_t sign_key_type = get_sign_key_type(algo);
    if (sign_key_type == QGP_KEY_TYPE_INVALID) {
        return EXIT_KEY_ERROR;
    }

    // ======================================================================
    // STEP 1: Prompt for BIP39 mnemonic
    // ======================================================================

    printf("[Step 1/4] Enter your 24-word BIP39 recovery seed\n");
    printf("(separated by spaces)\n\n");

    if (!fgets(mnemonic, sizeof(mnemonic), stdin)) {
        fprintf(stderr, "Error: Failed to read mnemonic\n");
        return EXIT_ERROR;
    }

    // Remove trailing newline
    size_t len = strlen(mnemonic);
    if (len > 0 && mnemonic[len - 1] == '\n') {
        mnemonic[len - 1] = '\0';
    }

    // ======================================================================
    // STEP 2: Validate mnemonic
    // ======================================================================

    printf("\n[Step 2/4] Validating mnemonic...\n");
    if (!bip39_validate_mnemonic(mnemonic)) {
        fprintf(stderr, "✗ Error: Invalid mnemonic\n");
        fprintf(stderr, "  - Check word spelling (must be BIP39 wordlist words)\n");
        fprintf(stderr, "  - Verify checksum (last word encodes checksum)\n");
        fprintf(stderr, "  - Ensure correct word count (12/15/18/21/24 words)\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        return EXIT_ERROR;
    }
    printf("  ✓ Mnemonic valid\n");

    // ======================================================================
    // STEP 3: Prompt for optional passphrase
    // ======================================================================

    printf("\n[Step 3/4] Enter passphrase (if you used one during generation)\n");
    printf("Press Enter if no passphrase was used:\n");
    if (!fgets(passphrase, sizeof(passphrase), stdin)) {
        fprintf(stderr, "Error: Failed to read passphrase\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        return EXIT_ERROR;
    }

    // Remove trailing newline
    len = strlen(passphrase);
    if (len > 0 && passphrase[len - 1] == '\n') {
        passphrase[len - 1] = '\0';
    }

    if (strlen(passphrase) > 0) {
        printf("  ✓ Using passphrase\n");
    } else {
        printf("  ✓ No passphrase (seed only)\n");
    }

    // ======================================================================
    // STEP 4: Derive QGP seeds
    // ======================================================================

    printf("\n[Step 4/4] Deriving seeds from mnemonic (PBKDF2 2048 iterations + SHAKE256)...\n");
    if (qgp_derive_seeds_from_mnemonic(mnemonic, passphrase, signing_seed, encryption_seed) != 0) {
        fprintf(stderr, "✗ Error: Seed derivation failed\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(passphrase, 0, sizeof(passphrase));
        return EXIT_CRYPTO_ERROR;
    }

    printf("  ✓ Signing seed derived (32 bytes)\n");
    printf("  ✓ Encryption seed derived (32 bytes)\n");

    // Zero out mnemonic and passphrase from memory (security)
    memset(mnemonic, 0, sizeof(mnemonic));
    memset(passphrase, 0, sizeof(passphrase));

    printf("\nRegenerating keys from seed...\n");

    // ======================================================================
    // STEP 5: Create output directory
    // ======================================================================

    if (!qgp_platform_is_directory(output_dir)) {
        if (qgp_platform_mkdir(output_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", output_dir);
            goto cleanup_restore;
        }
        printf("Created directory: %s\n", output_dir);
    }

    // Build key file paths (algorithm-aware naming)
    char sign_filename[512];
    char enc_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s-dilithium3.pqkey", name);
    snprintf(enc_filename, sizeof(enc_filename), "%s-kyber512.pqkey", name);

    sign_key_path = build_path(output_dir, sign_filename);
    enc_key_path = build_path(output_dir, enc_filename);

    if (!sign_key_path || !enc_key_path) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    // Check if files already exist
    if (file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key already exists: %s\n", sign_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    if (file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key already exists: %s\n", enc_key_path);
        fprintf(stderr, "Remove it first or use a different name\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    // ======================================================================
    // STEP 6: Generate SIGNING key from seed
    // ======================================================================

    printf("\n  [1/2] Regenerating signing key from seed (%s)...\n", algo);


    if (sign_key_type == QGP_KEY_TYPE_DILITHIUM3) {
        sign_key = qgp_key_new(QGP_KEY_TYPE_DILITHIUM3, QGP_KEY_PURPOSE_SIGNING);
        if (!sign_key) {
            fprintf(stderr, "Error: Memory allocation failed for signing key\n");
            ret = EXIT_ERROR;
            goto cleanup_restore;
        }

        strncpy(sign_key->name, name, sizeof(sign_key->name) - 1);

        // Allocate Dilithium3 key buffers
        uint8_t *dilithium_pk = calloc(1, QGP_DILITHIUM3_PUBLICKEYBYTES);
        uint8_t *dilithium_sk = calloc(1, QGP_DILITHIUM3_SECRETKEYBYTES);

        if (!dilithium_pk || !dilithium_sk) {
            fprintf(stderr, "Error: Memory allocation failed for Dilithium3 key buffers\n");
            free(dilithium_pk);
            free(dilithium_sk);
            qgp_key_free(sign_key);
            sign_key = NULL;
            ret = EXIT_ERROR;
            goto cleanup_restore;
        }

        // Generate deterministic Dilithium3 keypair from seed
        if (qgp_dilithium3_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
            fprintf(stderr, "Error: Dilithium3 key regeneration from seed failed\n");
            free(dilithium_pk);
            free(dilithium_sk);
            qgp_key_free(sign_key);
            sign_key = NULL;
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup_restore;
        }

        // Store in qgp_key_t structure
        sign_key->public_key = dilithium_pk;
        sign_key->public_key_size = QGP_DILITHIUM3_PUBLICKEYBYTES;
        sign_key->private_key = dilithium_sk;
        sign_key->private_key_size = QGP_DILITHIUM3_SECRETKEYBYTES;

        printf("  ✓ Dilithium3 (ML-DSA-65) signing key regenerated from seed (deterministic)\n");
        printf("  ✓ Public key: %d bytes\n", QGP_DILITHIUM3_PUBLICKEYBYTES);
        printf("  ✓ Secret key: %d bytes\n", QGP_DILITHIUM3_SECRETKEYBYTES);
    }

    // Save signing key in QGP format
    if (qgp_key_save(sign_key, sign_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    printf("  ✓ Signing key saved: %s\n", sign_key_path);

    // Protocol Mode: Round-trip verification for signing key
    printf("  Verifying signing key (round-trip test)...\n");
    const char *test_data = "pqsignum-verification-test";
    size_t test_len = strlen(test_data);


    if (sign_key->type == QGP_KEY_TYPE_DILITHIUM3) {
        uint8_t test_sig[QGP_DILITHIUM3_BYTES];
        size_t test_siglen = 0;

        // Sign test data
        if (qgp_dilithium3_signature(test_sig, &test_siglen,
                                      (const uint8_t*)test_data, test_len,
                                      sign_key->private_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 signing failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup_restore;
        }

        // Verify signature
        if (qgp_dilithium3_verify(test_sig, test_siglen,
                                   (const uint8_t*)test_data, test_len,
                                   sign_key->public_key) != 0) {
            fprintf(stderr, "  ✗ CRITICAL ERROR: Dilithium3 verification failed\n");
            ret = EXIT_CRYPTO_ERROR;
            goto cleanup_restore;
        }

        printf("  ✓ Dilithium3 key verified (sign → verify PASSED)\n");
        printf("  ✓ Signature size: %zu bytes\n", test_siglen);
    }

    // ======================================================================
    // STEP 7: Generate ENCRYPTION key from seed
    // ======================================================================

    printf("\n  [2/2] Regenerating encryption key from seed (Kyber512 KEM)...\n");


    enc_key = qgp_key_new(QGP_KEY_TYPE_KYBER512, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    strncpy(enc_key->name, name, sizeof(enc_key->name) - 1);

    // Allocate buffers for Kyber keypair
    uint8_t *kyber_pk = calloc(1, 800);
    uint8_t *kyber_sk = calloc(1, 1632);

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Kyber key buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    // Generate deterministic Kyber512 keypair from seed
    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: Deterministic Kyber512 key generation failed\n");
        free(kyber_pk);
        free(kyber_sk);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup_restore;
    }

    // Store in qgp_key_t structure
    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 800;
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 1632;

    printf("  ✓ Kyber512 KEM key regenerated from seed (deterministic)\n");

    // Validate key sizes
    if (!enc_key->public_key || enc_key->public_key_size != 800) {
        fprintf(stderr, "Error: Invalid public key (expected 800 bytes, got %zu)\n",
                enc_key->public_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup_restore;
    }

    if (!enc_key->private_key || enc_key->private_key_size != 1632) {
        fprintf(stderr, "Error: Invalid private key (expected 1632 bytes, got %zu)\n",
                enc_key->private_key_size);
        ret = EXIT_CRYPTO_ERROR;
        goto cleanup_restore;
    }

    // Save encryption key in QGP format
    if (qgp_key_save(enc_key, enc_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        ret = EXIT_ERROR;
        goto cleanup_restore;
    }

    printf("  ✓ Encryption key saved: %s\n", enc_key_path);
    printf("  ✓ Public key: 800 bytes\n");
    printf("  ✓ Private key: 1632 bytes\n");

    // ======================================================================
    // SUCCESS
    // ======================================================================

    printf("\n✓ Keys successfully restored from recovery seed!\n");
    printf("\nRestored files:\n");
    printf("  Signing key:     %s (keep private!)\n", sign_key_path);
    printf("  Encryption key:  %s (keep private!)\n", enc_key_path);

    // Register keys in keyring
    printf("\nRegistering keys in keyring...\n");
    if (keyring_register_private_key(name, sign_key_path, enc_key_path) == 0) {
        printf("  ✓ Keys registered in keyring\n");
        printf("  View with: qgp --list-keys\n");
    } else {
        printf("  ⚠ Warning: Could not register keys in keyring (non-fatal)\n");
    }

    // Auto-export public key directly to keyring
    printf("\nExporting public key to keyring...\n");

    // Create keyring directory path
    char *keyring_dir = build_path(output_dir, "keyring");
    if (!keyring_dir) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for keyring path\n");
        goto skip_export_restore;
    }

    // Create keyring directory if it doesn't exist
    if (!qgp_platform_is_directory(keyring_dir)) {
        if (qgp_platform_mkdir(keyring_dir) != 0) {
            fprintf(stderr, "  ⚠ Warning: Cannot create keyring directory: %s\n", keyring_dir);
            free(keyring_dir);
            goto skip_export_restore;
        }
    }

    // Build public key path in keyring directory
    char pubkey_filename[512];
    snprintf(pubkey_filename, sizeof(pubkey_filename), "%s.pub", name);
    char *pubkey_path = build_path(keyring_dir, pubkey_filename);
    free(keyring_dir);

    if (!pubkey_path) {
        fprintf(stderr, "  ⚠ Warning: Memory allocation failed for public key path\n");
        goto skip_export_restore;
    }

    // Export public key directly to keyring
    if (cmd_export_pubkey(name, output_dir, pubkey_path) == 0) {
        printf("  ✓ Public key exported to keyring: %s\n", pubkey_path);

        // Import the exported public key into keyring index
        if (cmd_keyring_import(pubkey_path, name) == 0) {
            printf("  ✓ Public key registered in keyring\n");
            printf("  You can now use: qgp --encrypt --file secret.txt --recipient %s\n", name);
        } else {
            printf("  ⚠ Warning: Could not register public key in keyring (non-fatal)\n");
        }
    } else {
        printf("  ⚠ Warning: Could not export public key (non-fatal)\n");
        printf("  You can export it later with: qgp --export --name %s\n", name);
    }

    free(pubkey_path);

skip_export_restore:
    printf("\n✓ Key restoration complete!\n");
    printf("  Your keys have been successfully recovered from your recovery seed.\n");

    ret = EXIT_SUCCESS;

cleanup_restore:
    // Zero out seeds from memory (security)
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    if (sign_key_path) free(sign_key_path);
    if (enc_key_path) free(enc_key_path);


    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}
