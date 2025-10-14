/*
 * DNA Messenger - PostgreSQL Implementation
 *
 * Phase 3: Local PostgreSQL (localhost)
 * Phase 4: Network PostgreSQL (remote server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "messenger.h"
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"
#include "qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "kyber_deterministic.h"  // For crypto_kem_keypair_derand

// Global configuration
static dna_config_t g_config;

// ============================================================================
// INITIALIZATION
// ============================================================================

messenger_context_t* messenger_init(const char *identity) {
    if (!identity) {
        fprintf(stderr, "Error: Identity required\n");
        return NULL;
    }

    // Load configuration
    if (dna_config_load(&g_config) != 0) {
        fprintf(stderr, "Error: Failed to load configuration\n");
        return NULL;
    }

    messenger_context_t *ctx = calloc(1, sizeof(messenger_context_t));
    if (!ctx) {
        return NULL;
    }

    // Set identity
    ctx->identity = strdup(identity);
    if (!ctx->identity) {
        free(ctx);
        return NULL;
    }

    // Build connection string from config
    char connstring[512];
    dna_config_build_connstring(&g_config, connstring, sizeof(connstring));

    // Connect to PostgreSQL
    ctx->pg_conn = PQconnectdb(connstring);
    if (PQstatus(ctx->pg_conn) != CONNECTION_OK) {
        fprintf(stderr, "PostgreSQL connection failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQfinish(ctx->pg_conn);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize DNA context
    ctx->dna_ctx = dna_context_new();
    if (!ctx->dna_ctx) {
        fprintf(stderr, "Error: Failed to create DNA context\n");
        PQfinish(ctx->pg_conn);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    printf("✓ Messenger initialized for '%s'\n", identity);
    printf("✓ Connected to PostgreSQL: dna_messenger\n");

    return ctx;
}

void messenger_free(messenger_context_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->dna_ctx) {
        dna_context_free(ctx->dna_ctx);
    }

    if (ctx->pg_conn) {
        PQfinish(ctx->pg_conn);
    }

    free(ctx->identity);
    free(ctx);
}

// ============================================================================
// KEY GENERATION
// ============================================================================

int messenger_generate_keys(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    // Check if identity already exists in keyserver
    uint8_t *existing_sign = NULL, *existing_enc = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, identity, &existing_sign, &sign_len, &existing_enc, &enc_len) == 0) {
        free(existing_sign);
        free(existing_enc);
        fprintf(stderr, "\nError: Identity '%s' already exists in keyserver!\n", identity);
        fprintf(stderr, "Please choose a different name.\n\n");
        return -1;
    }

    // Create ~/.dna directory
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot get home directory\n");
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Use the QGP function to generate keys with BIP39 seed phrase
    // This will show the user their recovery seed and generate keys deterministically
    if (cmd_gen_key_from_seed(identity, "dilithium", dna_dir) != 0) {
        fprintf(stderr, "Error: Key generation failed\n");
        return -1;
    }

    // cmd_gen_key_from_seed creates keys in QGP format which includes public keys
    // Now we need to export the public keys and upload to keyserver

    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", dna_dir, identity);

    // Export public key bundle
    if (cmd_export_pubkey(identity, dna_dir, pubkey_path) != 0) {
        fprintf(stderr, "Error: Failed to export public key\n");
        return -1;
    }

    // Read the ASCII-armored public key bundle
    char *type = NULL;
    uint8_t *pubkey_data = NULL;
    size_t pubkey_data_size = 0;
    char **headers = NULL;
    size_t header_count = 0;

    if (read_armored_file(pubkey_path, &type, &pubkey_data, &pubkey_data_size,
                          &headers, &header_count) != 0) {
        fprintf(stderr, "Error: Failed to read ASCII-armored public key\n");
        return -1;
    }

    // Parse header (20 bytes): magic[8] + version + sign_key_type + enc_key_type + reserved + sign_size(4) + enc_size(4)
    if (pubkey_data_size < 20) {
        fprintf(stderr, "Error: Public key data too small\n");
        free(type);
        free(pubkey_data);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);
        return -1;
    }

    uint32_t sign_pubkey_size, enc_pubkey_size;
    memcpy(&sign_pubkey_size, pubkey_data + 12, 4);  // offset 12: after magic+version+types+reserved
    memcpy(&enc_pubkey_size, pubkey_data + 16, 4);   // offset 16

    // Extract keys (after 20-byte header)
    uint8_t dilithium_pk[1952];
    uint8_t kyber_pk[800];
    memcpy(dilithium_pk, pubkey_data + 20, sizeof(dilithium_pk));
    memcpy(kyber_pk, pubkey_data + 20 + sign_pubkey_size, sizeof(kyber_pk));

    // Cleanup
    free(type);
    free(pubkey_data);
    for (size_t i = 0; i < header_count; i++) free(headers[i]);
    free(headers);

    // Upload public keys to keyserver
    if (messenger_store_pubkey(ctx, identity, dilithium_pk, sizeof(dilithium_pk),
                                kyber_pk, sizeof(kyber_pk)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    // Rename key files for messenger compatibility
    // Messenger expects: <identity>-dilithium.pqkey and <identity>-kyber512.pqkey
    // QGP creates: <identity>-dilithium3.pqkey and <identity>-kyber512.pqkey
    char dilithium3_path[512], dilithium_path[512];
    snprintf(dilithium3_path, sizeof(dilithium3_path), "%s/%s-dilithium3.pqkey", dna_dir, identity);
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s-dilithium.pqkey", dna_dir, identity);

    if (rename(dilithium3_path, dilithium_path) != 0) {
        fprintf(stderr, "Warning: Could not rename signing key file\n");
    }

    printf("\n✓ Keys uploaded to keyserver\n");
    printf("✓ Identity '%s' is now ready to use!\n\n", identity);
    return 0;
}

int messenger_restore_keys(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    // Check if identity already exists in keyserver
    uint8_t *existing_sign = NULL, *existing_enc = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, identity, &existing_sign, &sign_len, &existing_enc, &enc_len) == 0) {
        free(existing_sign);
        free(existing_enc);
        fprintf(stderr, "\nError: Identity '%s' already exists in keyserver!\n", identity);
        fprintf(stderr, "Please choose a different name or delete the existing identity first.\n\n");
        return -1;
    }

    // Create ~/.dna directory
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot get home directory\n");
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Use QGP's restore function which prompts for mnemonic and passphrase
    if (cmd_restore_key_from_seed(identity, "dilithium", dna_dir) != 0) {
        fprintf(stderr, "Error: Key restoration failed\n");
        return -1;
    }

    // Export public key bundle
    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", dna_dir, identity);

    if (cmd_export_pubkey(identity, dna_dir, pubkey_path) != 0) {
        fprintf(stderr, "Error: Failed to export public key\n");
        return -1;
    }

    // Read the ASCII-armored public key bundle
    char *type = NULL;
    uint8_t *pubkey_data = NULL;
    size_t pubkey_data_size = 0;
    char **headers = NULL;
    size_t header_count = 0;

    if (read_armored_file(pubkey_path, &type, &pubkey_data, &pubkey_data_size,
                          &headers, &header_count) != 0) {
        fprintf(stderr, "Error: Failed to read ASCII-armored public key\n");
        return -1;
    }

    // Parse header (20 bytes): magic[8] + version + sign_key_type + enc_key_type + reserved + sign_size(4) + enc_size(4)
    if (pubkey_data_size < 20) {
        fprintf(stderr, "Error: Public key data too small\n");
        free(type);
        free(pubkey_data);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);
        return -1;
    }

    uint32_t sign_pubkey_size, enc_pubkey_size;
    memcpy(&sign_pubkey_size, pubkey_data + 12, 4);  // offset 12: after magic+version+types+reserved
    memcpy(&enc_pubkey_size, pubkey_data + 16, 4);   // offset 16

    // Extract keys (after 20-byte header)
    uint8_t dilithium_pk[1952];
    uint8_t kyber_pk[800];
    memcpy(dilithium_pk, pubkey_data + 20, sizeof(dilithium_pk));
    memcpy(kyber_pk, pubkey_data + 20 + sign_pubkey_size, sizeof(kyber_pk));

    // Cleanup
    free(type);
    free(pubkey_data);
    for (size_t i = 0; i < header_count; i++) free(headers[i]);
    free(headers);

    // Upload public keys to keyserver
    if (messenger_store_pubkey(ctx, identity, dilithium_pk, sizeof(dilithium_pk),
                                kyber_pk, sizeof(kyber_pk)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    // Rename key files for messenger compatibility
    // Messenger expects: <identity>-dilithium.pqkey and <identity>-kyber512.pqkey
    // QGP creates: <identity>-dilithium3.pqkey and <identity>-kyber512.pqkey
    char dilithium3_path[512], dilithium_path[512];
    snprintf(dilithium3_path, sizeof(dilithium3_path), "%s/%s-dilithium3.pqkey", dna_dir, identity);
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s-dilithium.pqkey", dna_dir, identity);

    if (rename(dilithium3_path, dilithium_path) != 0) {
        fprintf(stderr, "Warning: Could not rename signing key file\n");
    }

    printf("\n✓ Keys restored and uploaded to keyserver\n");
    printf("✓ Identity '%s' is now ready to use!\n\n", identity);
    return 0;
}

int messenger_restore_keys_from_file(messenger_context_t *ctx, const char *identity, const char *seed_file) {
    if (!ctx || !identity || !seed_file) {
        return -1;
    }

    // For restore, identity MUST exist in keyserver
    // We're verifying the restored keys match what's already there
    uint8_t *keyserver_sign = NULL, *keyserver_enc = NULL;
    size_t keyserver_sign_len = 0, keyserver_enc_len = 0;

    if (messenger_load_pubkey(ctx, identity, &keyserver_sign, &keyserver_sign_len, &keyserver_enc, &keyserver_enc_len) != 0) {
        fprintf(stderr, "\nError: Identity '%s' not found in keyserver!\n", identity);
        fprintf(stderr, "Cannot restore - no keys to verify against.\n");
        fprintf(stderr, "Use 'Generate new identity' if this is a new identity.\n\n");
        return -1;
    }

    // Read seed phrase from file
    FILE *f = fopen(seed_file, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open seed file: %s\n", seed_file);
        return -1;
    }

    char line[2048];
    if (!fgets(line, sizeof(line), f)) {
        fprintf(stderr, "Error: Failed to read seed file\n");
        fclose(f);
        return -1;
    }
    fclose(f);

    // Remove trailing newline
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
    }

    // Parse line: "word1 word2 ... word24 [passphrase]"
    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    char passphrase[256] = {0};

    // Split into words
    char *words[25];  // 24 words + optional passphrase
    int word_count = 0;

    char *token = strtok(line, " ");
    while (token != NULL && word_count < 25) {
        words[word_count++] = token;
        token = strtok(NULL, " ");
    }

    if (word_count < 24) {
        fprintf(stderr, "Error: Seed file must contain at least 24 words\n");
        fprintf(stderr, "Found only %d words\n", word_count);
        return -1;
    }

    // Build mnemonic from first 24 words
    mnemonic[0] = '\0';
    for (int i = 0; i < 24; i++) {
        if (i > 0) strcat(mnemonic, " ");
        strcat(mnemonic, words[i]);
    }

    // If 25th word exists, it's the passphrase
    if (word_count >= 25) {
        strncpy(passphrase, words[24], sizeof(passphrase) - 1);
        passphrase[sizeof(passphrase) - 1] = '\0';
    }

    printf("Restoring identity '%s' from seed file\n", identity);
    printf("  Mnemonic: %d words\n", 24);
    printf("  Passphrase: %s\n\n", word_count >= 25 ? "yes" : "no");

    // Validate mnemonic
    if (!bip39_validate_mnemonic(mnemonic)) {
        fprintf(stderr, "Error: Invalid BIP39 mnemonic in seed file\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(passphrase, 0, sizeof(passphrase));
        return -1;
    }

    // Derive seeds from mnemonic
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonic, passphrase, signing_seed, encryption_seed) != 0) {
        fprintf(stderr, "Error: Seed derivation failed\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        memset(passphrase, 0, sizeof(passphrase));
        return -1;
    }

    // Zero out mnemonic and passphrase
    memset(mnemonic, 0, sizeof(mnemonic));
    memset(passphrase, 0, sizeof(passphrase));

    // Create ~/.dna directory
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot get home directory\n");
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Create directory if needed
    if (!qgp_platform_is_directory(dna_dir)) {
        if (qgp_platform_mkdir(dna_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", dna_dir);
            memset(signing_seed, 0, sizeof(signing_seed));
            memset(encryption_seed, 0, sizeof(encryption_seed));
            return -1;
        }
    }

    // Generate Dilithium3 signing key from seed
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s-dilithium3.pqkey", dna_dir, identity);

    qgp_key_t *sign_key = qgp_key_new(QGP_KEY_TYPE_DILITHIUM3, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed for signing key\n");
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    strncpy(sign_key->name, identity, sizeof(sign_key->name) - 1);

    uint8_t *dilithium_pk = calloc(1, QGP_DILITHIUM3_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DILITHIUM3_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Dilithium3 buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    if (qgp_dilithium3_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: Dilithium3 key generation from seed failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DILITHIUM3_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DILITHIUM3_SECRETKEYBYTES;

    if (qgp_key_save(sign_key, dilithium_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    printf("✓ Dilithium3 signing key generated from seed\n");

    // Copy dilithium public key for verification before freeing
    uint8_t dilithium_pk_verify[1952];
    memcpy(dilithium_pk_verify, dilithium_pk, sizeof(dilithium_pk_verify));

    qgp_key_free(sign_key);

    // Generate Kyber512 encryption key from seed
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s-kyber512.pqkey", dna_dir, identity);

    qgp_key_t *enc_key = qgp_key_new(QGP_KEY_TYPE_KYBER512, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    strncpy(enc_key->name, identity, sizeof(enc_key->name) - 1);

    uint8_t *kyber_pk = calloc(1, 800);
    uint8_t *kyber_sk = calloc(1, 1632);

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Kyber512 buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: Kyber512 key generation from seed failed\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 800;
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 1632;

    if (qgp_key_save(enc_key, kyber_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        qgp_key_free(enc_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    printf("✓ Kyber512 encryption key generated from seed\n");

    // Copy kyber public key for verification before freeing
    uint8_t kyber_pk_verify[800];
    memcpy(kyber_pk_verify, kyber_pk, sizeof(kyber_pk_verify));

    qgp_key_free(enc_key);

    // Secure wipe seeds
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));

    // Export public key bundle
    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", dna_dir, identity);

    if (cmd_export_pubkey(identity, dna_dir, pubkey_path) != 0) {
        fprintf(stderr, "Error: Failed to export public key\n");
        return -1;
    }

    // Read the restored .pub file to get ASCII-armored public key
    char *restored_type = NULL;
    uint8_t *restored_pubkey_data = NULL;
    size_t restored_pubkey_size = 0;
    char **restored_headers = NULL;
    size_t restored_header_count = 0;

    if (read_armored_file(pubkey_path, &restored_type, &restored_pubkey_data, &restored_pubkey_size,
                          &restored_headers, &restored_header_count) != 0) {
        fprintf(stderr, "Error: Failed to read restored ASCII-armored public key\n");
        free(keyserver_sign);
        free(keyserver_enc);
        return -1;
    }

    // Parse keyserver data (also ASCII-armored)
    char *keyserver_type = NULL;
    uint8_t *keyserver_pubkey_data = NULL;
    size_t keyserver_pubkey_size = 0;
    char **keyserver_headers = NULL;
    size_t keyserver_header_count = 0;

    // keyserver_sign contains ASCII-armored data, parse it
    // Write to temp file, then read it back
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "/tmp/.dna_verify_%s.pub", identity);
    FILE *temp_f = fopen(temp_path, "w");
    if (!temp_f) {
        fprintf(stderr, "Error: Cannot create temp file for verification\n");
        free(restored_type);
        free(restored_pubkey_data);
        for (size_t i = 0; i < restored_header_count; i++) free(restored_headers[i]);
        free(restored_headers);
        free(keyserver_sign);
        free(keyserver_enc);
        return -1;
    }
    fwrite(keyserver_sign, 1, keyserver_sign_len, temp_f);
    fclose(temp_f);

    if (read_armored_file(temp_path, &keyserver_type, &keyserver_pubkey_data, &keyserver_pubkey_size,
                          &keyserver_headers, &keyserver_header_count) != 0) {
        fprintf(stderr, "Error: Failed to parse keyserver ASCII-armored public key\n");
        remove(temp_path);
        free(restored_type);
        free(restored_pubkey_data);
        for (size_t i = 0; i < restored_header_count; i++) free(restored_headers[i]);
        free(restored_headers);
        free(keyserver_sign);
        free(keyserver_enc);
        return -1;
    }
    remove(temp_path);

    // Verify restored keys match keyserver
    printf("\nVerifying restored keys against keyserver...\n");

    if (restored_pubkey_size != keyserver_pubkey_size) {
        fprintf(stderr, "\nError: Public key size mismatch!\n");
        fprintf(stderr, "  Keyserver: %zu bytes\n", keyserver_pubkey_size);
        fprintf(stderr, "  Restored:  %zu bytes\n", restored_pubkey_size);
        fprintf(stderr, "  The restored identity is WRONG - incorrect seed or identity!\n\n");
        free(restored_type);
        free(restored_pubkey_data);
        for (size_t i = 0; i < restored_header_count; i++) free(restored_headers[i]);
        free(restored_headers);
        free(keyserver_type);
        free(keyserver_pubkey_data);
        for (size_t i = 0; i < keyserver_header_count; i++) free(keyserver_headers[i]);
        free(keyserver_headers);
        free(keyserver_sign);
        free(keyserver_enc);
        return -1;
    }

    if (memcmp(keyserver_pubkey_data, restored_pubkey_data, restored_pubkey_size) != 0) {
        fprintf(stderr, "\nError: Public keys DOES NOT MATCH keyserver!\n");
        fprintf(stderr, "  The restored identity is WRONG - incorrect seed or identity!\n\n");
        free(restored_type);
        free(restored_pubkey_data);
        for (size_t i = 0; i < restored_header_count; i++) free(restored_headers[i]);
        free(restored_headers);
        free(keyserver_type);
        free(keyserver_pubkey_data);
        for (size_t i = 0; i < keyserver_header_count; i++) free(keyserver_headers[i]);
        free(keyserver_headers);
        free(keyserver_sign);
        free(keyserver_enc);
        return -1;
    }

    // Keys match! Clean up
    free(restored_type);
    free(restored_pubkey_data);
    for (size_t i = 0; i < restored_header_count; i++) free(restored_headers[i]);
    free(restored_headers);
    free(keyserver_type);
    free(keyserver_pubkey_data);
    for (size_t i = 0; i < keyserver_header_count; i++) free(keyserver_headers[i]);
    free(keyserver_headers);
    free(keyserver_sign);
    free(keyserver_enc);

    printf("✓ Signing public key verified against keyserver\n");
    printf("✓ Encryption public key verified against keyserver\n");

    // Rename signing key file for messenger compatibility
    char dilithium3_path[512], dilithium_renamed[512];
    snprintf(dilithium3_path, sizeof(dilithium3_path), "%s/%s-dilithium3.pqkey", dna_dir, identity);
    snprintf(dilithium_renamed, sizeof(dilithium_renamed), "%s/%s-dilithium.pqkey", dna_dir, identity);

    if (rename(dilithium3_path, dilithium_renamed) != 0) {
        fprintf(stderr, "Warning: Could not rename signing key file\n");
    }

    printf("\n✓ Keys restored from file and verified against keyserver\n");
    printf("✓ Identity '%s' is now ready to use!\n\n", identity);
    return 0;
}

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================

int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
) {
    if (!ctx || !identity || !signing_pubkey || !encryption_pubkey) {
        return -1;
    }

    const char *paramValues[4];
    int paramLengths[4];
    int paramFormats[4] = {0, 1, 0, 1}; // text, binary, text, binary

    char len_str1[32], len_str2[32];
    snprintf(len_str1, sizeof(len_str1), "%zu", signing_pubkey_len);
    snprintf(len_str2, sizeof(len_str2), "%zu", encryption_pubkey_len);

    paramValues[0] = identity;
    paramValues[1] = (const char*)signing_pubkey;
    paramLengths[1] = (int)signing_pubkey_len;
    paramValues[2] = len_str1;
    paramValues[3] = (const char*)encryption_pubkey;
    paramLengths[3] = (int)encryption_pubkey_len;

    const char *query =
        "INSERT INTO keyserver (identity, signing_pubkey, signing_pubkey_len, encryption_pubkey, encryption_pubkey_len) "
        "VALUES ($1, $2, $3::integer, $4, $5::integer) "
        "ON CONFLICT (identity) DO UPDATE SET "
        "signing_pubkey = $2, signing_pubkey_len = $3::integer, "
        "encryption_pubkey = $4, encryption_pubkey_len = $5::integer";

    // Need 5 parameters
    const char *all_params[5] = {identity, (const char*)signing_pubkey, len_str1, (const char*)encryption_pubkey, len_str2};
    int all_lengths[5] = {0, (int)signing_pubkey_len, 0, (int)encryption_pubkey_len, 0};
    int all_formats[5] = {0, 1, 0, 1, 0};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 5, NULL, all_params, all_lengths, all_formats, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Store pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Public key stored for '%s'\n", identity);
    return 0;
}

int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out
) {
    if (!ctx || !identity) {
        return -1;
    }

    const char *paramValues[1] = {identity};
    const char *query =
        "SELECT signing_pubkey, signing_pubkey_len, encryption_pubkey, encryption_pubkey_len "
        "FROM keyserver WHERE identity = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 1); // Binary result

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Load pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Public key not found for '%s'\n", identity);
        PQclear(res);
        return -1;
    }

    // Extract binary data
    int sign_len = PQgetlength(res, 0, 0);
    int enc_len = PQgetlength(res, 0, 2);

    *signing_pubkey_out = malloc(sign_len);
    *encryption_pubkey_out = malloc(enc_len);

    if (!*signing_pubkey_out || !*encryption_pubkey_out) {
        free(*signing_pubkey_out);
        free(*encryption_pubkey_out);
        PQclear(res);
        return -1;
    }

    memcpy(*signing_pubkey_out, PQgetvalue(res, 0, 0), sign_len);
    memcpy(*encryption_pubkey_out, PQgetvalue(res, 0, 2), enc_len);

    *signing_pubkey_len_out = sign_len;
    *encryption_pubkey_len_out = enc_len;

    PQclear(res);
    return 0;
}

int messenger_list_pubkeys(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *query = "SELECT identity, created_at FROM keyserver ORDER BY identity";
    PGresult *res = PQexec(ctx->pg_conn, query);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List pubkeys failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Keyserver (%d identities) ===\n\n", rows);

    for (int i = 0; i < rows; i++) {
        const char *identity = PQgetvalue(res, i, 0);
        const char *created_at = PQgetvalue(res, i, 1);
        printf("  %s (added: %s)\n", identity, created_at);
    }

    printf("\n");
    PQclear(res);
    return 0;
}

/**
 * Get contact list (identities from keyserver)
 */
int messenger_get_contact_list(messenger_context_t *ctx, char ***identities_out, int *count_out) {
    if (!ctx || !identities_out || !count_out) {
        return -1;
    }

    const char *query = "SELECT identity FROM keyserver ORDER BY identity";
    PGresult *res = PQexec(ctx->pg_conn, query);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get contact list failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *identities_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array of string pointers
    char **identities = (char**)malloc(sizeof(char*) * rows);
    if (!identities) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy each identity string
    for (int i = 0; i < rows; i++) {
        const char *identity = PQgetvalue(res, i, 0);
        identities[i] = strdup(identity);
        if (!identities[i]) {
            // Clean up on failure
            for (int j = 0; j < i; j++) {
                free(identities[j]);
            }
            free(identities);
            PQclear(res);
            return -1;
        }
    }

    *identities_out = identities;
    PQclear(res);
    return 0;
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

int messenger_send_message(
    messenger_context_t *ctx,
    const char *recipient,
    const char *message
) {
    if (!ctx || !recipient || !message) {
        return -1;
    }

    printf("\n[Sending message to %s]\n", recipient);

    // Load recipient's public key from PostgreSQL
    uint8_t *sign_pubkey = NULL, *enc_pubkey = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, recipient, &sign_pubkey, &sign_len, &enc_pubkey, &enc_len) != 0) {
        fprintf(stderr, "Error: Could not load public key for '%s'\n", recipient);
        return -1;
    }

    // Load sender's private signing key from filesystem using qgp_key_load
    const char *home = qgp_platform_home_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/.dna/%s-dilithium.pqkey", home, ctx->identity);

    qgp_key_t *sender_sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sender_sign_key) != 0) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", dilithium_path);
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    if (sender_sign_key->private_key_size != 4032) {
        fprintf(stderr, "Error: Invalid Dilithium3 private key size: %zu (expected 4032)\n",
                sender_sign_key->private_key_size);
        qgp_key_free(sender_sign_key);
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    // Load sender's public signing key from PostgreSQL
    uint8_t *sender_sign_pubkey_pg = NULL;
    uint8_t *sender_enc_pubkey_pg = NULL;
    size_t sender_sign_len = 0, sender_enc_len = 0;

    if (messenger_load_pubkey(ctx, ctx->identity, &sender_sign_pubkey_pg, &sender_sign_len,
                               &sender_enc_pubkey_pg, &sender_enc_len) != 0) {
        fprintf(stderr, "Error: Could not load sender's public key from keyserver\n");
        qgp_key_free(sender_sign_key);
        free(sign_pubkey);
        free(enc_pubkey);
        return -1;
    }

    // Encrypt message using raw keys
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    dna_error_t err = dna_encrypt_message_raw(
        ctx->dna_ctx,
        (const uint8_t*)message,
        strlen(message),
        enc_pubkey,  // Recipient's Kyber512 public key (800 bytes)
        sender_sign_pubkey_pg,  // Sender's Dilithium3 public key (1952 bytes)
        sender_sign_key->private_key,  // Sender's Dilithium3 private key (4032 bytes)
        &ciphertext,
        &ciphertext_len
    );

    // Free sender signing key (secure wipes private key internally)
    qgp_key_free(sender_sign_key);

    free(sign_pubkey);
    free(enc_pubkey);
    free(sender_sign_pubkey_pg);
    free(sender_enc_pubkey_pg);

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Encryption failed: %s\n", dna_error_string(err));
        return -1;
    }

    printf("✓ Message encrypted (%zu bytes)\n", ciphertext_len);

    // Store in database
    const char *paramValues[5];
    int paramLengths[5];
    int paramFormats[5] = {0, 0, 1, 0, 0}; // text, text, binary, text, text

    char len_str[32];
    snprintf(len_str, sizeof(len_str), "%zu", ciphertext_len);

    paramValues[0] = ctx->identity;
    paramValues[1] = recipient;
    paramValues[2] = (const char*)ciphertext;
    paramLengths[2] = (int)ciphertext_len;
    paramValues[3] = len_str;

    const char *query =
        "INSERT INTO messages (sender, recipient, ciphertext, ciphertext_len) "
        "VALUES ($1, $2, $3, $4::integer)";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 4, NULL, paramValues, paramLengths, paramFormats, 0);

    free(ciphertext);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Store message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Message sent to '%s'\n", recipient);

    return 0;
}

int messenger_list_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *paramValues[1] = {ctx->identity};
    const char *query =
        "SELECT id, sender, created_at FROM messages "
        "WHERE recipient = $1 ORDER BY created_at DESC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List messages failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Inbox for %s (%d messages) ===\n\n", ctx->identity, rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *sender = PQgetvalue(res, i, 1);
        const char *timestamp = PQgetvalue(res, i, 2);
        printf("  [%s] From: %s (%s)\n", id, sender, timestamp);
    }

    if (rows == 0) {
        printf("  (no messages)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}

int messenger_list_sent_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    const char *paramValues[1] = {ctx->identity};
    const char *query =
        "SELECT id, recipient, created_at FROM messages "
        "WHERE sender = $1 ORDER BY created_at DESC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "List sent messages failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Sent by %s (%d messages) ===\n\n", ctx->identity, rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *recipient = PQgetvalue(res, i, 1);
        const char *timestamp = PQgetvalue(res, i, 2);
        printf("  [%s] To: %s (%s)\n", id, recipient, timestamp);
    }

    if (rows == 0) {
        printf("  (no sent messages)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}

int messenger_read_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Fetch message from database
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);
    const char *paramValues[1] = {id_str};
    const char *query = "SELECT sender, ciphertext FROM messages WHERE id = $1 AND recipient = $2";

    const char *params[2] = {id_str, ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 1); // Binary result

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Fetch message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Message %d not found or not for you\n", message_id);
        PQclear(res);
        return -1;
    }

    const char *sender = PQgetvalue(res, 0, 0);
    const uint8_t *ciphertext = (const uint8_t*)PQgetvalue(res, 0, 1);
    size_t ciphertext_len = PQgetlength(res, 0, 1);

    printf("\n========================================\n");
    printf(" Message #%d from %s\n", message_id, sender);
    printf("========================================\n\n");

    // Load recipient's private Kyber512 key from filesystem using qgp_key_load
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s-kyber512.pqkey", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", kyber_path);
        PQclear(res);
        return -1;
    }

    if (kyber_key->private_key_size != 1632) {
        fprintf(stderr, "Error: Invalid Kyber512 private key size: %zu (expected 1632)\n",
                kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        PQclear(res);
        return -1;
    }

    // Decrypt message using raw key
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *sender_sign_pubkey_from_msg = NULL;
    size_t sender_sign_pubkey_len = 0;

    dna_error_t err = dna_decrypt_message_raw(
        ctx->dna_ctx,
        ciphertext,
        ciphertext_len,
        kyber_key->private_key,
        &plaintext,
        &plaintext_len,
        &sender_sign_pubkey_from_msg,
        &sender_sign_pubkey_len
    );

    // Free Kyber key (secure wipes private key internally)
    qgp_key_free(kyber_key);

    if (err != DNA_OK) {
        fprintf(stderr, "Error: Decryption failed: %s\n", dna_error_string(err));
        PQclear(res);
        return -1;
    }

    // Verify sender's public key against keyserver
    uint8_t *sender_sign_pubkey_keyserver = NULL;
    uint8_t *sender_enc_pubkey_keyserver = NULL;
    size_t sender_sign_len_keyserver = 0, sender_enc_len_keyserver = 0;

    if (messenger_load_pubkey(ctx, sender, &sender_sign_pubkey_keyserver, &sender_sign_len_keyserver,
                               &sender_enc_pubkey_keyserver, &sender_enc_len_keyserver) != 0) {
        fprintf(stderr, "Warning: Could not verify sender '%s' against keyserver\n", sender);
        fprintf(stderr, "Message decrypted but sender identity NOT verified!\n");
    } else {
        // Compare public keys
        if (sender_sign_len_keyserver != sender_sign_pubkey_len ||
            memcmp(sender_sign_pubkey_keyserver, sender_sign_pubkey_from_msg, sender_sign_pubkey_len) != 0) {
            fprintf(stderr, "ERROR: Sender public key mismatch!\n");
            fprintf(stderr, "The message claims to be from '%s' but the signature doesn't match keyserver.\n", sender);
            fprintf(stderr, "Possible spoofing attempt!\n");
            free(plaintext);
            free(sender_sign_pubkey_from_msg);
            free(sender_sign_pubkey_keyserver);
            free(sender_enc_pubkey_keyserver);
            PQclear(res);
            return -1;
        }
        free(sender_sign_pubkey_keyserver);
        free(sender_enc_pubkey_keyserver);
    }

    // Display message
    printf("Message:\n");
    printf("----------------------------------------\n");
    printf("%.*s\n", (int)plaintext_len, plaintext);
    printf("----------------------------------------\n");
    printf("✓ Signature verified from %s\n", sender);
    printf("✓ Sender identity verified against keyserver\n");

    // Cleanup
    free(plaintext);
    free(sender_sign_pubkey_from_msg);
    PQclear(res);
    printf("\n");
    return 0;
}

int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    const char *paramValues[1] = {identity};
    const char *query = "DELETE FROM keyserver WHERE identity = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete pubkey failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    printf("✓ Public key deleted for '%s'\n", identity);
    PQclear(res);
    return 0;
}

int messenger_delete_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);

    const char *paramValues[1] = {id_str};
    const char *query = "DELETE FROM messages WHERE id = $1";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete message failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    printf("✓ Message %d deleted\n", message_id);
    PQclear(res);
    return 0;
}

// ============================================================================
// MESSAGE SEARCH/FILTERING
// ============================================================================

int messenger_search_by_sender(messenger_context_t *ctx, const char *sender) {
    if (!ctx || !sender) {
        return -1;
    }

    const char *paramValues[2] = {ctx->identity, sender};
    const char *query =
        "SELECT id, sender, created_at FROM messages "
        "WHERE recipient = $1 AND sender = $2 "
        "ORDER BY created_at DESC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Search by sender failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n=== Messages from %s to %s (%d messages) ===\n\n", sender, ctx->identity, rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *timestamp = PQgetvalue(res, i, 2);
        printf("  [%s] %s\n", id, timestamp);
    }

    if (rows == 0) {
        printf("  (no messages from %s)\n", sender);
    }

    printf("\n");
    PQclear(res);
    return 0;
}

int messenger_show_conversation(messenger_context_t *ctx, const char *other_identity) {
    if (!ctx || !other_identity) {
        return -1;
    }

    const char *paramValues[4] = {ctx->identity, other_identity, other_identity, ctx->identity};
    const char *query =
        "SELECT id, sender, recipient, created_at FROM messages "
        "WHERE (sender = $1 AND recipient = $2) OR (sender = $3 AND recipient = $4) "
        "ORDER BY created_at ASC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 4, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Show conversation failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    printf("\n");
    printf("========================================\n");
    printf(" Conversation: %s <-> %s\n", ctx->identity, other_identity);
    printf(" (%d messages)\n", rows);
    printf("========================================\n\n");

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *sender = PQgetvalue(res, i, 1);
        const char *recipient = PQgetvalue(res, i, 2);
        const char *timestamp = PQgetvalue(res, i, 3);

        // Format: [ID] timestamp sender -> recipient
        if (strcmp(sender, ctx->identity) == 0) {
            // Message sent by current user
            printf("  [%s] %s  You -> %s\n", id, timestamp, recipient);
        } else {
            // Message received by current user
            printf("  [%s] %s  %s -> You\n", id, timestamp, sender);
        }
    }

    if (rows == 0) {
        printf("  (no messages exchanged)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}

/**
 * Get conversation with another user (returns message array for GUI)
 */
int messenger_get_conversation(messenger_context_t *ctx, const char *other_identity,
                                 message_info_t **messages_out, int *count_out) {
    if (!ctx || !other_identity || !messages_out || !count_out) {
        return -1;
    }

    const char *paramValues[4] = {ctx->identity, other_identity, other_identity, ctx->identity};
    const char *query =
        "SELECT id, sender, recipient, created_at FROM messages "
        "WHERE (sender = $1 AND recipient = $2) OR (sender = $3 AND recipient = $4) "
        "ORDER BY created_at ASC";

    PGresult *res = PQexecParams(ctx->pg_conn, query, 4, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get conversation failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *messages_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array of message_info_t
    message_info_t *messages = (message_info_t*)calloc(rows, sizeof(message_info_t));
    if (!messages) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy message data
    for (int i = 0; i < rows; i++) {
        const char *id_str = PQgetvalue(res, i, 0);
        const char *sender = PQgetvalue(res, i, 1);
        const char *recipient = PQgetvalue(res, i, 2);
        const char *timestamp = PQgetvalue(res, i, 3);

        messages[i].id = atoi(id_str);
        messages[i].sender = strdup(sender);
        messages[i].recipient = strdup(recipient);
        messages[i].timestamp = strdup(timestamp);
        messages[i].plaintext = NULL;  // Not decrypted

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp) {
            // Clean up on failure
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].plaintext);
            }
            free(messages);
            PQclear(res);
            return -1;
        }
    }

    *messages_out = messages;
    PQclear(res);
    return 0;
}

/**
 * Free message array
 */
void messenger_free_messages(message_info_t *messages, int count) {
    if (!messages) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(messages[i].sender);
        free(messages[i].recipient);
        free(messages[i].timestamp);
        free(messages[i].plaintext);
    }
    free(messages);
}

int messenger_search_by_date(messenger_context_t *ctx, const char *start_date,
                              const char *end_date, bool include_sent, bool include_received) {
    if (!ctx) {
        return -1;
    }

    if (!include_sent && !include_received) {
        fprintf(stderr, "Error: Must include either sent or received messages\n");
        return -1;
    }

    // Build dynamic query based on parameters
    char query[1024];
    int param_count = 1;  // Start with identity
    const char *paramValues[5];
    paramValues[0] = ctx->identity;

    // Base query
    strcpy(query, "SELECT id, sender, recipient, created_at FROM messages WHERE ");

    // Sender/recipient conditions
    if (include_sent && include_received) {
        strcat(query, "(sender = $1 OR recipient = $1)");
    } else if (include_sent) {
        strcat(query, "sender = $1");
    } else {
        strcat(query, "recipient = $1");
    }

    // Date range conditions
    if (start_date) {
        param_count++;
        char condition[64];
        snprintf(condition, sizeof(condition), " AND created_at >= $%d", param_count);
        strcat(query, condition);
        paramValues[param_count - 1] = start_date;
    }

    if (end_date) {
        param_count++;
        char condition[64];
        snprintf(condition, sizeof(condition), " AND created_at < $%d", param_count);
        strcat(query, condition);
        paramValues[param_count - 1] = end_date;
    }

    strcat(query, " ORDER BY created_at DESC");

    PGresult *res = PQexecParams(ctx->pg_conn, query, param_count, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Search by date failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);

    printf("\n=== Messages");
    if (start_date || end_date) {
        printf(" (");
        if (start_date) printf("from %s", start_date);
        if (start_date && end_date) printf(" ");
        if (end_date) printf("to %s", end_date);
        printf(")");
    }
    if (include_sent && include_received) {
        printf(" - Sent & Received");
    } else if (include_sent) {
        printf(" - Sent Only");
    } else {
        printf(" - Received Only");
    }
    printf(" ===\n\n");

    printf("Found %d messages:\n\n", rows);

    for (int i = 0; i < rows; i++) {
        const char *id = PQgetvalue(res, i, 0);
        const char *sender = PQgetvalue(res, i, 1);
        const char *recipient = PQgetvalue(res, i, 2);
        const char *timestamp = PQgetvalue(res, i, 3);

        if (strcmp(sender, ctx->identity) == 0) {
            printf("  [%s] %s  To: %s\n", id, timestamp, recipient);
        } else {
            printf("  [%s] %s  From: %s\n", id, timestamp, sender);
        }
    }

    if (rows == 0) {
        printf("  (no messages found)\n");
    }

    printf("\n");
    PQclear(res);
    return 0;
}
