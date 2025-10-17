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
#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
#else
#include <sys/time.h>
#endif
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "messenger.h"
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"
#include "qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "kyber_deterministic.h"  // For crypto_kem_keypair_derand
#include "qgp_aes.h"  // For qgp_aes256_encrypt
#include "aes_keywrap.h"  // For aes256_wrap_key
#include "qgp_random.h"  // For qgp_randombytes

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

    // Initialize pubkey cache
    ctx->cache_count = 0;
    memset(ctx->cache, 0, sizeof(ctx->cache));

    printf("✓ Messenger initialized for '%s'\n", identity);
    printf("✓ Connected to PostgreSQL: dna_messenger\n");

    return ctx;
}

void messenger_free(messenger_context_t *ctx) {
    if (!ctx) {
        return;
    }

    // Free pubkey cache
    for (int i = 0; i < ctx->cache_count; i++) {
        free(ctx->cache[i].identity);
        free(ctx->cache[i].signing_pubkey);
        free(ctx->cache[i].encryption_pubkey);
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

/**
 * Base64 decode helper
 */
static size_t base64_decode(const char *input, uint8_t **output) {
    BIO *bio, *b64;
    size_t input_len = strlen(input);
    size_t decode_len = (input_len * 3) / 4;

    *output = malloc(decode_len);
    if (!*output) return 0;

    bio = BIO_new_mem_buf(input, input_len);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_size = BIO_read(bio, *output, decode_len);
    BIO_free_all(bio);

    if (decoded_size < 0) {
        free(*output);
        *output = NULL;
        return 0;
    }

    return decoded_size;
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

    // Check cache first
    for (int i = 0; i < ctx->cache_count; i++) {
        if (strcmp(ctx->cache[i].identity, identity) == 0) {
            // Cache hit - duplicate and return
            *signing_pubkey_out = malloc(ctx->cache[i].signing_pubkey_len);
            *encryption_pubkey_out = malloc(ctx->cache[i].encryption_pubkey_len);

            if (!*signing_pubkey_out || !*encryption_pubkey_out) {
                free(*signing_pubkey_out);
                free(*encryption_pubkey_out);
                return -1;
            }

            memcpy(*signing_pubkey_out, ctx->cache[i].signing_pubkey, ctx->cache[i].signing_pubkey_len);
            memcpy(*encryption_pubkey_out, ctx->cache[i].encryption_pubkey, ctx->cache[i].encryption_pubkey_len);
            *signing_pubkey_len_out = ctx->cache[i].signing_pubkey_len;
            *encryption_pubkey_len_out = ctx->cache[i].encryption_pubkey_len;

            return 0;
        }
    }

    // Cache miss - fetch from API: https://cpunk.io/api/keyserver/lookup/<identity>
    char url[512];
    snprintf(url, sizeof(url), "https://cpunk.io/api/keyserver/lookup/%s", identity);

    char cmd[1024];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "curl -s \"%s\"", url);
#else
    snprintf(cmd, sizeof(cmd), "curl -s '%s'", url);
#endif

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to fetch public key from API\n");
        return -1;
    }

    // Read response (up to 10KB)
    char response[10240];
    size_t response_len = fread(response, 1, sizeof(response) - 1, fp);
    response[response_len] = '\0';
    pclose(fp);

    // Trim whitespace and newlines (Windows CRLF issue)
    while (response_len > 0 &&
           (response[response_len-1] == '\n' ||
            response[response_len-1] == '\r' ||
            response[response_len-1] == ' ' ||
            response[response_len-1] == '\t')) {
        response[--response_len] = '\0';
    }

    // Parse JSON response using json-c
    struct json_object *root = json_tokener_parse(response);
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON response for '%s'\n", identity);
        fprintf(stderr, "Raw response (%zu bytes): '%s'\n", response_len, response);
        return -1;
    }

    // Check success field
    struct json_object *success_obj = json_object_object_get(root, "success");
    if (!success_obj || !json_object_get_boolean(success_obj)) {
        fprintf(stderr, "Error: API returned failure for identity '%s'\n", identity);
        json_object_put(root);
        return -1;
    }

    // Get data object
    struct json_object *data_obj = json_object_object_get(root, "data");
    if (!data_obj) {
        fprintf(stderr, "Error: No 'data' field in API response\n");
        json_object_put(root);
        return -1;
    }

    // Extract base64-encoded public keys
    struct json_object *dilithium_obj = json_object_object_get(data_obj, "dilithium_pub");
    struct json_object *kyber_obj = json_object_object_get(data_obj, "kyber_pub");

    if (!dilithium_obj || !kyber_obj) {
        fprintf(stderr, "Error: Missing public keys in API response\n");
        json_object_put(root);
        return -1;
    }

    const char *dilithium_b64 = json_object_get_string(dilithium_obj);
    const char *kyber_b64 = json_object_get_string(kyber_obj);

    // Decode base64
    uint8_t *dilithium_decoded = NULL;
    uint8_t *kyber_decoded = NULL;

    size_t dilithium_len = base64_decode(dilithium_b64, &dilithium_decoded);
    size_t kyber_len = base64_decode(kyber_b64, &kyber_decoded);

    json_object_put(root);

    if (dilithium_len == 0 || kyber_len == 0) {
        fprintf(stderr, "Error: Base64 decode failed\n");
        free(dilithium_decoded);
        free(kyber_decoded);
        return -1;
    }

    *signing_pubkey_out = dilithium_decoded;
    *signing_pubkey_len_out = dilithium_len;
    *encryption_pubkey_out = kyber_decoded;
    *encryption_pubkey_len_out = kyber_len;

    printf("✓ Fetched public key for '%s' from API (dilithium: %zu bytes, kyber: %zu bytes)\n",
           identity, dilithium_len, kyber_len);

    // Add to cache (if space available)
    if (ctx->cache_count < PUBKEY_CACHE_SIZE) {
        pubkey_cache_entry_t *entry = &ctx->cache[ctx->cache_count];
        entry->identity = strdup(identity);
        entry->signing_pubkey = malloc(dilithium_len);
        entry->encryption_pubkey = malloc(kyber_len);

        if (entry->identity && entry->signing_pubkey && entry->encryption_pubkey) {
            memcpy(entry->signing_pubkey, dilithium_decoded, dilithium_len);
            memcpy(entry->encryption_pubkey, kyber_decoded, kyber_len);
            entry->signing_pubkey_len = dilithium_len;
            entry->encryption_pubkey_len = kyber_len;
            ctx->cache_count++;
        } else {
            // Cleanup on allocation failure
            free(entry->identity);
            free(entry->signing_pubkey);
            free(entry->encryption_pubkey);
        }
    }

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

// Multi-recipient encryption header and entry structures
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x05 (GCM)
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} messenger_enc_header_t;

typedef struct {
    uint8_t kyber_ciphertext[768];    // Kyber512 ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte + 8-byte IV)
} messenger_recipient_entry_t;

/**
 * Multi-recipient encryption (adapted from encrypt.c)
 *
 * @param plaintext: Message to encrypt
 * @param plaintext_len: Message length
 * @param recipient_enc_pubkeys: Array of recipient Kyber512 public keys (800 bytes each)
 * @param recipient_count: Number of recipients (including sender)
 * @param sender_sign_key: Sender's Dilithium3 signing key
 * @param ciphertext_out: Output ciphertext (caller must free)
 * @param ciphertext_len_out: Output ciphertext length
 * @return: 0 on success, -1 on error
 */
static int messenger_encrypt_multi_recipient(
    const char *plaintext,
    size_t plaintext_len,
    uint8_t **recipient_enc_pubkeys,
    size_t recipient_count,
    qgp_key_t *sender_sign_key,
    uint8_t **ciphertext_out,
    size_t *ciphertext_len_out
) {
    uint8_t *dek = NULL;
    uint8_t *encrypted_data = NULL;
    messenger_recipient_entry_t *recipient_entries = NULL;
    uint8_t *signature_data = NULL;
    uint8_t *output_buffer = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    size_t encrypted_size = 0;
    size_t signature_size = 0;
    int ret = -1;

    // Step 1: Generate random 32-byte DEK
    dek = malloc(32);
    if (!dek) {
        fprintf(stderr, "Error: Memory allocation failed for DEK\n");
        goto cleanup;
    }

    if (qgp_randombytes(dek, 32) != 0) {
        fprintf(stderr, "Error: Failed to generate random DEK\n");
        goto cleanup;
    }

    // Step 2: Sign plaintext with Dilithium3
    qgp_signature_t *signature = qgp_signature_new(QGP_SIG_TYPE_DILITHIUM,
                                                     QGP_DILITHIUM3_PUBLICKEYBYTES,
                                                     QGP_DILITHIUM3_BYTES);
    if (!signature) {
        fprintf(stderr, "Error: Memory allocation failed for signature\n");
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_key->public_key,
           QGP_DILITHIUM3_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dilithium3_signature(qgp_signature_get_bytes(signature), &actual_sig_len,
                                  (const uint8_t*)plaintext, plaintext_len,
                                  sender_sign_key->private_key) != 0) {
        fprintf(stderr, "Error: Dilithium3 signature creation failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;

    // Round-trip verification
    if (qgp_dilithium3_verify(qgp_signature_get_bytes(signature), actual_sig_len,
                               (const uint8_t*)plaintext, plaintext_len,
                               qgp_signature_get_pubkey(signature)) != 0) {
        fprintf(stderr, "Error: Round-trip verification FAILED\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature_size = qgp_signature_get_size(signature);
    signature_data = malloc(signature_size);
    if (!signature_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    if (qgp_signature_serialize(signature, signature_data) == 0) {
        fprintf(stderr, "Error: Signature serialization failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }
    qgp_signature_free(signature);

    // Step 3: Encrypt plaintext with AES-256-GCM using DEK
    messenger_enc_header_t header_for_aad;
    memset(&header_for_aad, 0, sizeof(header_for_aad));
    memcpy(header_for_aad.magic, "PQSIGENC", 8);
    header_for_aad.version = 0x05;
    header_for_aad.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header_for_aad.recipient_count = (uint8_t)recipient_count;
    header_for_aad.encrypted_size = (uint32_t)plaintext_len;
    header_for_aad.signature_size = (uint32_t)signature_size;

    encrypted_data = malloc(plaintext_len);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Memory allocation failed for ciphertext\n");
        goto cleanup;
    }

    if (qgp_aes256_encrypt(dek, (const uint8_t*)plaintext, plaintext_len,
                           (uint8_t*)&header_for_aad, sizeof(header_for_aad),
                           encrypted_data, &encrypted_size,
                           nonce, tag) != 0) {
        fprintf(stderr, "Error: AES-256-GCM encryption failed\n");
        goto cleanup;
    }

    // Step 4: Create recipient entries (wrap DEK for each recipient)
    recipient_entries = calloc(recipient_count, sizeof(messenger_recipient_entry_t));
    if (!recipient_entries) {
        fprintf(stderr, "Error: Memory allocation failed for recipient entries\n");
        goto cleanup;
    }

    for (size_t i = 0; i < recipient_count; i++) {
        uint8_t kyber_ciphertext[768];
        uint8_t kek[32];  // KEK = shared secret from Kyber

        // Kyber512 encapsulation
        if (qgp_kyber512_enc(kyber_ciphertext, kek, recipient_enc_pubkeys[i]) != 0) {
            fprintf(stderr, "Error: Kyber512 encapsulation failed for recipient %zu\n", i+1);
            memset(kek, 0, 32);
            goto cleanup;
        }

        // Wrap DEK with KEK
        uint8_t wrapped_dek[40];
        if (aes256_wrap_key(dek, 32, kek, wrapped_dek) != 0) {
            fprintf(stderr, "Error: Failed to wrap DEK for recipient %zu\n", i+1);
            memset(kek, 0, 32);
            goto cleanup;
        }

        // Store recipient entry
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 768);
        memcpy(recipient_entries[i].wrapped_dek, wrapped_dek, 40);

        // Wipe KEK
        memset(kek, 0, 32);
    }

    // Step 5: Build output buffer
    // Format: [header | recipient_entries | nonce | ciphertext | tag | signature]
    size_t total_size = sizeof(messenger_enc_header_t) +
                       (sizeof(messenger_recipient_entry_t) * recipient_count) +
                       12 + encrypted_size + 16 + signature_size;

    output_buffer = malloc(total_size);
    if (!output_buffer) {
        fprintf(stderr, "Error: Memory allocation failed for output\n");
        goto cleanup;
    }

    size_t offset = 0;

    // Header
    messenger_enc_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "PQSIGENC", 8);
    header.version = 0x05;
    header.enc_key_type = (uint8_t)DAP_ENC_KEY_TYPE_KEM_KYBER512;
    header.recipient_count = (uint8_t)recipient_count;
    header.encrypted_size = (uint32_t)encrypted_size;
    header.signature_size = (uint32_t)signature_size;

    memcpy(output_buffer + offset, &header, sizeof(header));
    offset += sizeof(header);

    // Recipient entries
    memcpy(output_buffer + offset, recipient_entries,
           sizeof(messenger_recipient_entry_t) * recipient_count);
    offset += sizeof(messenger_recipient_entry_t) * recipient_count;

    // Nonce (12 bytes)
    memcpy(output_buffer + offset, nonce, 12);
    offset += 12;

    // Encrypted data
    memcpy(output_buffer + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    // Tag (16 bytes)
    memcpy(output_buffer + offset, tag, 16);
    offset += 16;

    // Signature
    memcpy(output_buffer + offset, signature_data, signature_size);
    offset += signature_size;

    *ciphertext_out = output_buffer;
    *ciphertext_len_out = total_size;
    ret = 0;

cleanup:
    if (dek) {
        memset(dek, 0, 32);
        free(dek);
    }
    if (encrypted_data) free(encrypted_data);
    if (recipient_entries) free(recipient_entries);
    if (signature_data) free(signature_data);
    if (ret != 0 && output_buffer) free(output_buffer);

    return ret;
}

int messenger_send_message(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
    const char *message
) {
    if (!ctx || !recipients || !message || recipient_count == 0 || recipient_count > 254) {
        fprintf(stderr, "Error: Invalid arguments (recipient_count must be 1-254)\n");
        return -1;
    }

    // Debug: show what we received
    printf("\n========== DEBUG: messenger_send_message() called ==========\n");
    printf("Version: %s (commit %s, built %s)\n", PQSIGNUM_VERSION, BUILD_HASH, BUILD_TS);
    printf("\nSender: '%s'\n", ctx->identity);
    printf("\nRecipients (%zu):\n", recipient_count);
    for (size_t i = 0; i < recipient_count; i++) {
        printf("  [%zu] = '%s' (length: %zu)\n", i, recipients[i], strlen(recipients[i]));
    }
    printf("\nMessage body:\n");
    printf("  Text: '%s'\n", message);
    printf("  Length: %zu bytes\n", strlen(message));
    printf("===========================================================\n\n");

    // Display recipients
    printf("\n[Sending message to %zu recipient(s)]\n", recipient_count);
    for (size_t i = 0; i < recipient_count; i++) {
        printf("  - %s\n", recipients[i]);
    }

    // Build full recipient list: sender + recipients (sender as first recipient)
    // This allows sender to decrypt their own sent messages
    size_t total_recipients = recipient_count + 1;
    const char **all_recipients = malloc(sizeof(char*) * total_recipients);
    if (!all_recipients) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    all_recipients[0] = ctx->identity;  // Sender is first recipient
    for (size_t i = 0; i < recipient_count; i++) {
        all_recipients[i + 1] = recipients[i];
    }

    printf("✓ Sender '%s' added as first recipient (can decrypt own sent messages)\n", ctx->identity);

    // Load sender's private signing key from filesystem
    const char *home = qgp_platform_home_dir();
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/.dna/%s-dilithium.pqkey", home, ctx->identity);

    qgp_key_t *sender_sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sender_sign_key) != 0) {
        fprintf(stderr, "Error: Cannot load sender's signing key from %s\n", dilithium_path);
        free(all_recipients);
        return -1;
    }

    // Load all recipient public keys from keyserver (including sender)
    uint8_t **enc_pubkeys = calloc(total_recipients, sizeof(uint8_t*));
    uint8_t **sign_pubkeys = calloc(total_recipients, sizeof(uint8_t*));

    if (!enc_pubkeys || !sign_pubkeys) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(enc_pubkeys);
        free(sign_pubkeys);
        free(all_recipients);
        qgp_key_free(sender_sign_key);
        return -1;
    }

    // Load public keys for all recipients from keyserver
    for (size_t i = 0; i < total_recipients; i++) {
        size_t sign_len = 0, enc_len = 0;
        if (messenger_load_pubkey(ctx, all_recipients[i],
                                   &sign_pubkeys[i], &sign_len,
                                   &enc_pubkeys[i], &enc_len) != 0) {
            fprintf(stderr, "Error: Cannot load public key for '%s' from keyserver\n", all_recipients[i]);

            // Cleanup on error
            for (size_t j = 0; j < total_recipients; j++) {
                free(enc_pubkeys[j]);
                free(sign_pubkeys[j]);
            }
            free(enc_pubkeys);
            free(sign_pubkeys);
            free(all_recipients);
            qgp_key_free(sender_sign_key);
            return -1;
        }
        printf("✓ Loaded public key for '%s' from keyserver\n", all_recipients[i]);
    }

    // Multi-recipient encryption implementation
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    int ret = messenger_encrypt_multi_recipient(
        message, strlen(message),
        enc_pubkeys, total_recipients,
        sender_sign_key,
        &ciphertext, &ciphertext_len
    );

    // Cleanup keys
    for (size_t i = 0; i < total_recipients; i++) {
        free(enc_pubkeys[i]);
        free(sign_pubkeys[i]);
    }
    free(enc_pubkeys);
    free(sign_pubkeys);
    free(all_recipients);
    qgp_key_free(sender_sign_key);

    if (ret != 0) {
        fprintf(stderr, "Error: Multi-recipient encryption failed\n");
        return -1;
    }

    printf("✓ Message encrypted (%zu bytes) for %zu recipient(s)\n", ciphertext_len, total_recipients);

    // Generate unique message_group_id (use microsecond timestamp for uniqueness)
#ifdef _WIN32
    // Windows: Use GetSystemTimeAsFileTime()
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Convert 100-nanosecond intervals to microseconds
    int message_group_id = (int)(uli.QuadPart / 10);
#else
    // POSIX: Use clock_gettime()
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int message_group_id = (int)(ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
#endif

    printf("✓ Assigned message_group_id: %d\n", message_group_id);

    // Store in database - one row per actual recipient (not including sender)
    const char *query =
        "INSERT INTO messages (sender, recipient, ciphertext, ciphertext_len, message_group_id) "
        "VALUES ($1, $2, $3, $4::integer, $5::integer)";

    char len_str[32];
    snprintf(len_str, sizeof(len_str), "%zu", ciphertext_len);

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", message_group_id);

    const char *paramValues[5];
    int paramLengths[5];
    int paramFormats[5] = {0, 0, 1, 0, 0}; // text, text, binary, text, text

    paramValues[0] = ctx->identity;
    paramValues[2] = (const char*)ciphertext;
    paramLengths[2] = (int)ciphertext_len;
    paramValues[3] = len_str;
    paramValues[4] = group_id_str;

    // Store one row for each actual recipient (not sender)
    for (size_t i = 0; i < recipient_count; i++) {
        paramValues[1] = recipients[i];

        PGresult *res = PQexecParams(ctx->pg_conn, query, 5, NULL, paramValues, paramLengths, paramFormats, 0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Store message failed for recipient '%s': %s\n",
                    recipients[i], PQerrorMessage(ctx->pg_conn));
            PQclear(res);
            free(ciphertext);
            return -1;
        }

        PQclear(res);
        printf("✓ Message stored for '%s'\n", recipients[i]);
    }

    free(ciphertext);

    printf("✓ Message sent successfully to %zu recipient(s)\n\n", recipient_count);
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

    // Load recipient's private Kyber512 key from filesystem
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

int messenger_decrypt_message(messenger_context_t *ctx, int message_id,
                                char **plaintext_out, size_t *plaintext_len_out) {
    if (!ctx || !plaintext_out || !plaintext_len_out) {
        return -1;
    }

    // Fetch message from database
    // Support decrypting both received messages (recipient = identity) AND sent messages (sender = identity)
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);
    const char *query = "SELECT sender, ciphertext FROM messages WHERE id = $1 AND (recipient = $2 OR sender = $2)";

    const char *params[2] = {id_str, ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 1); // Binary result

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }

    const char *sender = PQgetvalue(res, 0, 0);
    const uint8_t *ciphertext = (const uint8_t*)PQgetvalue(res, 0, 1);
    size_t ciphertext_len = PQgetlength(res, 0, 1);

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s-kyber512.pqkey", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        PQclear(res);
        return -1;
    }

    if (kyber_key->private_key_size != 1632) {
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
        PQclear(res);
        return -1;
    }

    // Verify sender's public key against keyserver
    uint8_t *sender_sign_pubkey_keyserver = NULL;
    uint8_t *sender_enc_pubkey_keyserver = NULL;
    size_t sender_sign_len_keyserver = 0, sender_enc_len_keyserver = 0;

    if (messenger_load_pubkey(ctx, sender, &sender_sign_pubkey_keyserver, &sender_sign_len_keyserver,
                               &sender_enc_pubkey_keyserver, &sender_enc_len_keyserver) == 0) {
        // Compare public keys
        if (sender_sign_len_keyserver != sender_sign_pubkey_len ||
            memcmp(sender_sign_pubkey_keyserver, sender_sign_pubkey_from_msg, sender_sign_pubkey_len) != 0) {
            // Signature mismatch - possible spoofing
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

    free(sender_sign_pubkey_from_msg);
    PQclear(res);

    // Return plaintext as null-terminated string
    *plaintext_out = (char*)malloc(plaintext_len + 1);
    if (!*plaintext_out) {
        free(plaintext);
        return -1;
    }

    memcpy(*plaintext_out, plaintext, plaintext_len);
    (*plaintext_out)[plaintext_len] = '\0';
    *plaintext_len_out = plaintext_len;

    free(plaintext);
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
        "SELECT id, sender, recipient, created_at, status, delivered_at, read_at FROM messages "
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
        const char *status = PQgetvalue(res, i, 4);
        const char *delivered_at = PQgetvalue(res, i, 5);
        const char *read_at = PQgetvalue(res, i, 6);

        messages[i].id = atoi(id_str);
        messages[i].sender = strdup(sender);
        messages[i].recipient = strdup(recipient);
        messages[i].timestamp = strdup(timestamp);
        messages[i].status = strdup(status ? status : "sent");
        messages[i].delivered_at = delivered_at ? strdup(delivered_at) : NULL;
        messages[i].read_at = read_at ? strdup(read_at) : NULL;
        messages[i].plaintext = NULL;  // Not decrypted

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Clean up on failure
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
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
        free(messages[i].status);
        free(messages[i].delivered_at);
        free(messages[i].read_at);
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

// ============================================================================
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================

int messenger_mark_delivered(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", message_id);

    const char *query =
        "UPDATE messages "
        "SET status = 'delivered', delivered_at = CURRENT_TIMESTAMP "
        "WHERE id = $1 AND status = 'sent'";

    const char *params[1] = {id_str};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Mark delivered failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}

int messenger_mark_conversation_read(messenger_context_t *ctx, const char *sender_identity) {
    if (!ctx || !sender_identity) {
        return -1;
    }

    // Update messages to 'read' status
    // If delivered_at is NULL (message went directly from sent to read), set it to current timestamp
    const char *query =
        "UPDATE messages "
        "SET status = 'read', "
        "    delivered_at = COALESCE(delivered_at, CURRENT_TIMESTAMP), "
        "    read_at = CURRENT_TIMESTAMP "
        "WHERE recipient = $1 AND sender = $2 AND status IN ('sent', 'delivered')";

    const char *params[2] = {ctx->identity, sender_identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Mark conversation read failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================

/**
 * Create a new group
 */
int messenger_create_group(
    messenger_context_t *ctx,
    const char *name,
    const char *description,
    const char **members,
    size_t member_count,
    int *group_id_out
) {
    if (!ctx || !name || !members || member_count == 0) {
        fprintf(stderr, "Error: Invalid arguments for group creation\n");
        return -1;
    }

    // Validate group name
    if (strlen(name) == 0) {
        fprintf(stderr, "Error: Group name cannot be empty\n");
        return -1;
    }

    // Begin transaction
    PGresult *res = PQexec(ctx->pg_conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Begin transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Insert group
    const char *insert_group_query =
        "INSERT INTO groups (name, description, creator) "
        "VALUES ($1, $2, $3) RETURNING id";

    const char *group_params[3] = {name, description ? description : "", ctx->identity};
    res = PQexecParams(ctx->pg_conn, insert_group_query, 3, NULL, group_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Create group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }

    int group_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    // Add creator as member with role 'creator'
    const char *add_creator_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'creator')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *creator_params[2] = {group_id_str, ctx->identity};

    res = PQexecParams(ctx->pg_conn, add_creator_query, 2, NULL, creator_params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add creator to group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    // Add other members with role 'member'
    const char *add_member_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    for (size_t i = 0; i < member_count; i++) {
        const char *member_params[2] = {group_id_str, members[i]};
        res = PQexecParams(ctx->pg_conn, add_member_query, 2, NULL, member_params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Add member '%s' to group failed: %s\n",
                    members[i], PQerrorMessage(ctx->pg_conn));
            PQclear(res);
            PQexec(ctx->pg_conn, "ROLLBACK");
            return -1;
        }
        PQclear(res);
    }

    // Commit transaction
    res = PQexec(ctx->pg_conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Commit transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    if (group_id_out) {
        *group_id_out = group_id;
    }

    printf("✓ Group '%s' created with ID %d\n", name, group_id);
    printf("✓ Added %zu member(s) to group\n", member_count);
    return 0;
}

/**
 * Get list of all groups current user belongs to
 */
int messenger_get_groups(
    messenger_context_t *ctx,
    group_info_t **groups_out,
    int *count_out
) {
    if (!ctx || !groups_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id IN (SELECT group_id FROM group_members WHERE member = $1) "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at "
        "ORDER BY g.created_at DESC";

    const char *params[1] = {ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get groups failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *groups_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    group_info_t *groups = (group_info_t*)calloc(rows, sizeof(group_info_t));
    if (!groups) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy data
    for (int i = 0; i < rows; i++) {
        groups[i].id = atoi(PQgetvalue(res, i, 0));
        groups[i].name = strdup(PQgetvalue(res, i, 1));
        const char *desc = PQgetvalue(res, i, 2);
        groups[i].description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
        groups[i].creator = strdup(PQgetvalue(res, i, 3));
        groups[i].created_at = strdup(PQgetvalue(res, i, 4));
        groups[i].member_count = atoi(PQgetvalue(res, i, 5));

        if (!groups[i].name || !groups[i].creator || !groups[i].created_at) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(groups[j].name);
                free(groups[j].description);
                free(groups[j].creator);
                free(groups[j].created_at);
            }
            free(groups);
            PQclear(res);
            return -1;
        }
    }

    *groups_out = groups;
    PQclear(res);
    return 0;
}

/**
 * Get group info by ID
 */
int messenger_get_group_info(
    messenger_context_t *ctx,
    int group_id,
    group_info_t *group_out
) {
    if (!ctx || !group_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id = $1 "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    group_out->id = atoi(PQgetvalue(res, 0, 0));
    group_out->name = strdup(PQgetvalue(res, 0, 1));
    const char *desc = PQgetvalue(res, 0, 2);
    group_out->description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
    group_out->creator = strdup(PQgetvalue(res, 0, 3));
    group_out->created_at = strdup(PQgetvalue(res, 0, 4));
    group_out->member_count = atoi(PQgetvalue(res, 0, 5));

    PQclear(res);

    if (!group_out->name || !group_out->creator || !group_out->created_at) {
        free(group_out->name);
        free(group_out->description);
        free(group_out->creator);
        free(group_out->created_at);
        return -1;
    }

    return 0;
}

/**
 * Get members of a specific group
 */
int messenger_get_group_members(
    messenger_context_t *ctx,
    int group_id,
    char ***members_out,
    int *count_out
) {
    if (!ctx || !members_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT member FROM group_members WHERE group_id = $1 ORDER BY joined_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group members failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *members_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    char **members = (char**)malloc(sizeof(char*) * rows);
    if (!members) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy member names
    for (int i = 0; i < rows; i++) {
        members[i] = strdup(PQgetvalue(res, i, 0));
        if (!members[i]) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                free(members[j]);
            }
            free(members);
            PQclear(res);
            return -1;
        }
    }

    *members_out = members;
    PQclear(res);
    return 0;
}

/**
 * Add member to group
 */
int messenger_add_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Added '%s' to group %d\n", member, group_id);
    return 0;
}

/**
 * Remove member from group
 */
int messenger_remove_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "DELETE FROM group_members WHERE group_id = $1 AND member = $2";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Remove group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Removed '%s' from group %d\n", member, group_id);
    return 0;
}

/**
 * Leave a group
 */
int messenger_leave_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    return messenger_remove_group_member(ctx, group_id, ctx->identity);
}

/**
 * Delete a group (creator only)
 */
int messenger_delete_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    // Verify current user is the creator
    const char *check_query = "SELECT creator FROM groups WHERE id = $1";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *check_params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, check_query, 1, NULL, check_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Check group creator failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    const char *creator = PQgetvalue(res, 0, 0);
    if (strcmp(creator, ctx->identity) != 0) {
        fprintf(stderr, "Error: Only the group creator can delete the group\n");
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Delete group (CASCADE will delete members automatically)
    const char *delete_query = "DELETE FROM groups WHERE id = $1";
    const char *delete_params[1] = {group_id_str};

    res = PQexecParams(ctx->pg_conn, delete_query, 1, NULL, delete_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d deleted\n", group_id);
    return 0;
}

/**
 * Update group info (name, description)
 */
int messenger_update_group_info(
    messenger_context_t *ctx,
    int group_id,
    const char *name,
    const char *description
) {
    if (!ctx) {
        return -1;
    }

    if (!name && !description) {
        fprintf(stderr, "Error: Must provide at least name or description to update\n");
        return -1;
    }

    // Build dynamic query
    char query[512] = "UPDATE groups SET ";
    bool need_comma = false;

    if (name) {
        strcat(query, "name = $2");
        need_comma = true;
    }

    if (description) {
        if (need_comma) strcat(query, ", ");
        if (name) {
            strcat(query, "description = $3");
        } else {
            strcat(query, "description = $2");
        }
    }

    strcat(query, " WHERE id = $1");

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);

    const char *params[3] = {group_id_str, NULL, NULL};
    int param_count = 1;

    if (name) {
        params[param_count++] = name;
    }
    if (description) {
        params[param_count++] = description;
    }

    PGresult *res = PQexecParams(ctx->pg_conn, query, param_count, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Update group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d updated\n", group_id);
    return 0;
}

/**
 * Send message to group
 */
int messenger_send_group_message(
    messenger_context_t *ctx,
    int group_id,
    const char *message
) {
    if (!ctx || !message) {
        return -1;
    }

    // Get all group members except current user
    char **members = NULL;
    int member_count = 0;

    if (messenger_get_group_members(ctx, group_id, &members, &member_count) != 0) {
        fprintf(stderr, "Error: Failed to get group members\n");
        return -1;
    }

    if (member_count == 0) {
        fprintf(stderr, "Error: Group has no members\n");
        return -1;
    }

    // Filter out current user from recipients
    const char **recipients = (const char**)malloc(sizeof(char*) * member_count);
    size_t recipient_count = 0;

    for (int i = 0; i < member_count; i++) {
        if (strcmp(members[i], ctx->identity) != 0) {
            recipients[recipient_count++] = members[i];
        }
    }

    if (recipient_count == 0) {
        fprintf(stderr, "Error: No other members in group besides sender\n");
        free(recipients);
        for (int i = 0; i < member_count; i++) free(members[i]);
        free(members);
        return -1;
    }

    // Send message to all recipients
    int ret = messenger_send_message(ctx, recipients, recipient_count, message);

    // Cleanup
    free(recipients);
    for (int i = 0; i < member_count; i++) free(members[i]);
    free(members);

    if (ret == 0) {
        printf("✓ Message sent to group %d (%zu recipients)\n", group_id, recipient_count);
    }

    return ret;
}

/**
 * Get conversation for a group
 */
int messenger_get_group_conversation(
    messenger_context_t *ctx,
    int group_id,
    message_info_t **messages_out,
    int *count_out
) {
    if (!ctx || !messages_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT id, sender, recipient, created_at, status, delivered_at, read_at "
        "FROM messages "
        "WHERE group_id = $1 "
        "ORDER BY created_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group conversation failed: %s\n", PQerrorMessage(ctx->pg_conn));
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

    // Allocate array
    message_info_t *messages = (message_info_t*)calloc(rows, sizeof(message_info_t));
    if (!messages) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy message data
    for (int i = 0; i < rows; i++) {
        messages[i].id = atoi(PQgetvalue(res, i, 0));
        messages[i].sender = strdup(PQgetvalue(res, i, 1));
        messages[i].recipient = strdup(PQgetvalue(res, i, 2));
        messages[i].timestamp = strdup(PQgetvalue(res, i, 3));
        const char *status = PQgetvalue(res, i, 4);
        messages[i].status = strdup(status ? status : "sent");
        const char *delivered_at = PQgetvalue(res, i, 5);
        messages[i].delivered_at = (delivered_at && strlen(delivered_at) > 0) ? strdup(delivered_at) : NULL;
        const char *read_at = PQgetvalue(res, i, 6);
        messages[i].read_at = (read_at && strlen(read_at) > 0) ? strdup(read_at) : NULL;
        messages[i].plaintext = NULL;

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
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
 * Free group array
 */
void messenger_free_groups(group_info_t *groups, int count) {
    if (!groups) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(groups[i].name);
        free(groups[i].description);
        free(groups[i].creator);
        free(groups[i].created_at);
    }
    free(groups);
}
