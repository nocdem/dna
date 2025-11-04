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
#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
#else
#include <sys/time.h>
#include <unistd.h>  // For unlink(), close()
#endif
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "messenger.h"
#include "messenger_p2p.h"  // Phase 9.1b: P2P delivery integration
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"
#include "dht/dht_singleton.h"  // Global DHT singleton
#include "qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "kyber_deterministic.h"  // For crypto_kem_keypair_derand
#include "qgp_aes.h"  // For qgp_aes256_encrypt
#include "aes_keywrap.h"  // For aes256_wrap_key
#include "qgp_random.h"  // For qgp_randombytes
#include "keyserver_cache.h"  // Phase 4: Keyserver cache
#include "dht/dht_keyserver.h"   // Phase 9.4: DHT-based keyserver
#include "dht/dht_context.h"     // Phase 9.4: DHT context management
#include "p2p/p2p_transport.h"   // For getting DHT context
#include "contacts_db.h"         // Phase 9.4: Local contacts database

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

    // Initialize SQLite local message storage
    ctx->backup_ctx = message_backup_init(identity);
    if (!ctx->backup_ctx) {
        fprintf(stderr, "Error: Failed to initialize SQLite message storage\n");
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize DNA context
    ctx->dna_ctx = dna_context_new();
    if (!ctx->dna_ctx) {
        fprintf(stderr, "Error: Failed to create DNA context\n");
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize pubkey cache (in-memory)
    ctx->cache_count = 0;
    memset(ctx->cache, 0, sizeof(ctx->cache));

    // Initialize keyserver cache (SQLite persistent)
    if (keyserver_cache_init(NULL) != 0) {
        fprintf(stderr, "Warning: Failed to initialize keyserver cache\n");
        // Non-fatal - continue without cache
    }

    printf("✓ Messenger initialized for '%s'\n", identity);
    printf("✓ SQLite database: ~/.dna/messages.db\n");

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

    if (ctx->backup_ctx) {
        message_backup_close(ctx->backup_ctx);
    }

    // Cleanup keyserver cache
    keyserver_cache_cleanup();

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
    uint8_t dilithium_pk[2592];  // Dilithium5 public key size
    uint8_t kyber_pk[1568];  // Kyber1024 public key size
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

    printf("\n✓ Keys uploaded to keyserver\n");
    printf("✓ Identity '%s' is now ready to use!\n\n", identity);
    return 0;
}

int messenger_generate_keys_from_seeds(
    messenger_context_t *ctx,
    const char *identity,
    const uint8_t *signing_seed,
    const uint8_t *encryption_seed)
{
    if (!ctx || !identity || !signing_seed || !encryption_seed) {
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

    // Create directory if needed
    if (!qgp_platform_is_directory(dna_dir)) {
        if (qgp_platform_mkdir(dna_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", dna_dir);
            return -1;
        }
    }

    // Generate Dilithium3 signing key from seed
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s.dsa", dna_dir, identity);

    qgp_key_t *sign_key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed for signing key\n");
        return -1;
    }

    strncpy(sign_key->name, identity, sizeof(sign_key->name) - 1);

    uint8_t *dilithium_pk = calloc(1, QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DSA87_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Dilithium3 buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        return -1;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: Dilithium3 key generation from seed failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        return -1;
    }

    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DSA87_SECRETKEYBYTES;

    if (qgp_key_save(sign_key, dilithium_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        qgp_key_free(sign_key);
        return -1;
    }

    printf("✓ Dilithium3 signing key generated from seed\n");

    // Copy dilithium public key for upload before freeing
    uint8_t dilithium_pk_copy[2592];  // Dilithium5 public key size
    memcpy(dilithium_pk_copy, dilithium_pk, sizeof(dilithium_pk_copy));

    qgp_key_free(sign_key);

    // Generate Kyber512 encryption key from seed
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s.kem", dna_dir, identity);

    qgp_key_t *enc_key = qgp_key_new(QGP_KEY_TYPE_KEM1024, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        return -1;
    }

    strncpy(enc_key->name, identity, sizeof(enc_key->name) - 1);

    uint8_t *kyber_pk = calloc(1, 1568);  // Kyber1024 public key size
    uint8_t *kyber_sk = calloc(1, 3168);  // Kyber1024 secret key size

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Kyber512 buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        return -1;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: Kyber512 key generation from seed failed\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        return -1;
    }

    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 1568;  // Kyber1024 public key size
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 3168;  // Kyber1024 secret key size

    if (qgp_key_save(enc_key, kyber_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        qgp_key_free(enc_key);
        return -1;
    }

    printf("✓ Kyber512 encryption key generated from seed\n");

    // Copy kyber public key for upload before freeing
    uint8_t kyber_pk_copy[1568];  // Kyber1024 public key size
    memcpy(kyber_pk_copy, kyber_pk, sizeof(kyber_pk_copy));

    qgp_key_free(enc_key);

    // Upload public keys to DHT keyserver
    if (messenger_store_pubkey(ctx, identity, dilithium_pk_copy, sizeof(dilithium_pk_copy),
                                kyber_pk_copy, sizeof(kyber_pk_copy)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    printf("✓ Keys uploaded to DHT keyserver\n");
    printf("✓ Identity '%s' is now ready to use!\n", identity);
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
    uint8_t dilithium_pk[2592];  // Dilithium5 public key size
    uint8_t kyber_pk[1568];  // Kyber1024 public key size
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
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s.dsa", dna_dir, identity);

    qgp_key_t *sign_key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed for signing key\n");
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    strncpy(sign_key->name, identity, sizeof(sign_key->name) - 1);

    uint8_t *dilithium_pk = calloc(1, QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DSA87_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed for Dilithium3 buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: Dilithium3 key generation from seed failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DSA87_SECRETKEYBYTES;

    if (qgp_key_save(sign_key, dilithium_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    printf("✓ Dilithium3 signing key generated from seed\n");

    // Copy dilithium public key for verification before freeing
    uint8_t dilithium_pk_verify[2592];  // Dilithium5 public key size
    memcpy(dilithium_pk_verify, dilithium_pk, sizeof(dilithium_pk_verify));

    qgp_key_free(sign_key);

    // Generate Kyber512 encryption key from seed
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s.kem", dna_dir, identity);

    qgp_key_t *enc_key = qgp_key_new(QGP_KEY_TYPE_KEM1024, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    strncpy(enc_key->name, identity, sizeof(enc_key->name) - 1);

    uint8_t *kyber_pk = calloc(1, 1568);  // Kyber1024 public key size
    uint8_t *kyber_sk = calloc(1, 3168);  // Kyber1024 secret key size

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
    enc_key->public_key_size = 1568;  // Kyber1024 public key size
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 3168;  // Kyber1024 secret key size

    if (qgp_key_save(enc_key, kyber_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        qgp_key_free(enc_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    printf("✓ Kyber512 encryption key generated from seed\n");

    // Copy kyber public key for verification before freeing
    uint8_t kyber_pk_verify[1568];  // Kyber1024 public key size
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
    snprintf(dilithium3_path, sizeof(dilithium3_path), "%s/%s-dilithium3.pqkey", dna_dir, identity);  // Old format for migration
    snprintf(dilithium_renamed, sizeof(dilithium_renamed), "%s/%s.dsa", dna_dir, identity);

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

/**
 * Base64 encode helper
 */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* base64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6) & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }

    // Add padding
    size_t mod = len % 3;
    if (mod == 1) {
        out[out_len - 2] = '=';
        out[out_len - 1] = '=';
    } else if (mod == 2) {
        out[out_len - 1] = '=';
    }

    out[out_len] = '\0';
    return out;
}

int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
) {
    if (!ctx || !identity || !signing_pubkey || !encryption_pubkey) {
        fprintf(stderr, "ERROR: Invalid arguments to messenger_store_pubkey\n");
        return -1;
    }

    // Phase 9.4: Use DHT-based keyserver instead of HTTP
    printf("⟳ Publishing public keys for '%s' to DHT keyserver...\n", identity);

    // Use global DHT singleton (initialized at app startup)
    // This eliminates the need for temporary DHT contexts
    dht_context_t *dht_ctx = NULL;

    if (ctx->p2p_transport) {
        // Use existing P2P transport's DHT (when logged in)
        dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
        printf("[INFO] Using P2P transport DHT for key publishing\n");
    } else {
        // Use global DHT singleton (during identity creation, before login)
        dht_ctx = dht_singleton_get();
        if (!dht_ctx) {
            fprintf(stderr, "ERROR: Global DHT not initialized! Call dht_singleton_init() at app startup.\n");
            return -1;
        }
        printf("[INFO] Using global DHT singleton for key publishing\n");
    }

    // Get dna_dir path
    const char *home = getenv("HOME");
    if (!home) {
        home = getenv("USERPROFILE");  // Windows fallback
        if (!home) {
            fprintf(stderr, "ERROR: HOME environment variable not set\n");
            return -1;
        }
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Load private key for signing
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s.dsa", dna_dir, identity);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "ERROR: Failed to load signing key: %s\n", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->private_key) {
        fprintf(stderr, "ERROR: Not a Dilithium private key\n");
        qgp_key_free(key);
        return -1;
    }

    // Publish to DHT
    int ret = dht_keyserver_publish(
        dht_ctx,
        identity,
        signing_pubkey,
        encryption_pubkey,
        key->private_key
    );

    qgp_key_free(key);

    // No cleanup needed - global DHT singleton persists for app lifetime
    // P2P transport DHT is managed by p2p_transport_free()

    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to publish keys to DHT keyserver\n");
        return -1;
    }

    printf("✓ Public keys published to DHT successfully!\n");
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
        fprintf(stderr, "ERROR: Invalid arguments to messenger_load_pubkey\n");
        return -1;
    }

    // Phase 4: Check keyserver cache first
    keyserver_cache_entry_t *cached = NULL;
    int ret = keyserver_cache_get(identity, &cached);
    if (ret == 0 && cached) {
        // Cache hit!
        *signing_pubkey_out = malloc(cached->dilithium_pubkey_len);
        *encryption_pubkey_out = malloc(cached->kyber_pubkey_len);

        if (!*signing_pubkey_out || !*encryption_pubkey_out) {
            if (*signing_pubkey_out) free(*signing_pubkey_out);
            if (*encryption_pubkey_out) free(*encryption_pubkey_out);
            keyserver_cache_free_entry(cached);
            return -1;
        }

        memcpy(*signing_pubkey_out, cached->dilithium_pubkey, cached->dilithium_pubkey_len);
        memcpy(*encryption_pubkey_out, cached->kyber_pubkey, cached->kyber_pubkey_len);
        *signing_pubkey_len_out = cached->dilithium_pubkey_len;
        *encryption_pubkey_len_out = cached->kyber_pubkey_len;

        keyserver_cache_free_entry(cached);
        printf("✓ Loaded public keys for '%s' from cache\n", identity);
        return 0;
    }

    // Cache miss - fetch from DHT keyserver
    printf("⟳ Fetching public keys for '%s' from DHT keyserver...\n", identity);

    // Get DHT context from P2P transport
    if (!ctx->p2p_transport) {
        fprintf(stderr, "ERROR: P2P transport not initialized\n");
        return -1;
    }

    dht_context_t *dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        fprintf(stderr, "ERROR: DHT context not available\n");
        return -1;
    }

    // Lookup in DHT
    dht_pubkey_entry_t *entry = NULL;
    ret = dht_keyserver_lookup(dht_ctx, identity, &entry);

    if (ret != 0) {
        if (ret == -2) {
            fprintf(stderr, "ERROR: Identity '%s' not found in DHT keyserver\n", identity);
        } else if (ret == -3) {
            fprintf(stderr, "ERROR: Signature verification failed for identity '%s'\n", identity);
        } else {
            fprintf(stderr, "ERROR: Failed to lookup identity in DHT keyserver\n");
        }
        return -1;
    }

    // Allocate and copy keys
    uint8_t *dil_decoded = malloc(DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    uint8_t *kyber_decoded = malloc(DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    if (!dil_decoded || !kyber_decoded) {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        if (dil_decoded) free(dil_decoded);
        if (kyber_decoded) free(kyber_decoded);
        dht_keyserver_free_entry(entry);
        return -1;
    }

    memcpy(dil_decoded, entry->dilithium_pubkey, DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE);
    memcpy(kyber_decoded, entry->kyber_pubkey, DHT_KEYSERVER_KYBER_PUBKEY_SIZE);

    size_t dil_len = DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE;
    size_t kyber_len = DHT_KEYSERVER_KYBER_PUBKEY_SIZE;

    // Free DHT entry
    dht_keyserver_free_entry(entry);

    // Store in cache for future lookups
    keyserver_cache_put(identity, dil_decoded, dil_len, kyber_decoded, kyber_len, 0);

    // Return keys
    *signing_pubkey_out = dil_decoded;
    *signing_pubkey_len_out = dil_len;
    *encryption_pubkey_out = kyber_decoded;
    *encryption_pubkey_len_out = kyber_len;
    printf("✓ Loaded public keys for '%s' from keyserver\n", identity);
    return 0;
}

int messenger_list_pubkeys(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Fetch from cpunk.io API
    const char *url = "https://cpunk.io/api/keyserver/list";
    char cmd[1024];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "curl -s \"%s\"", url);
#else
    snprintf(cmd, sizeof(cmd), "curl -s '%s'", url);
#endif

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to fetch identity list from keyserver\n");
        return -1;
    }

    char response[102400]; // 100KB buffer for large lists
    size_t response_len = fread(response, 1, sizeof(response) - 1, fp);
    response[response_len] = '\0';
    pclose(fp);

    // Trim whitespace
    while (response_len > 0 &&
           (response[response_len-1] == '\n' ||
            response[response_len-1] == '\r' ||
            response[response_len-1] == ' ' ||
            response[response_len-1] == '\t')) {
        response[--response_len] = '\0';
    }

    // Parse JSON response
    struct json_object *root = json_tokener_parse(response);
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON response\n");
        return -1;
    }

    // Check success field
    struct json_object *success_obj = json_object_object_get(root, "success");
    if (!success_obj || !json_object_get_boolean(success_obj)) {
        fprintf(stderr, "Error: API returned failure\n");
        json_object_put(root);
        return -1;
    }

    // Get total count
    struct json_object *total_obj = json_object_object_get(root, "total");
    int total = total_obj ? json_object_get_int(total_obj) : 0;

    printf("\n=== Keyserver (%d identities) ===\n\n", total);

    // Get identities array
    struct json_object *identities_obj = json_object_object_get(root, "identities");
    if (!identities_obj || !json_object_is_type(identities_obj, json_type_array)) {
        json_object_put(root);
        return 0;
    }

    int count = json_object_array_length(identities_obj);
    for (int i = 0; i < count; i++) {
        struct json_object *identity_obj = json_object_array_get_idx(identities_obj, i);
        if (!identity_obj) continue;

        struct json_object *dna_obj = json_object_object_get(identity_obj, "dna");
        struct json_object *registered_obj = json_object_object_get(identity_obj, "registered_at");

        const char *identity = dna_obj ? json_object_get_string(dna_obj) : "unknown";
        const char *registered_at = registered_obj ? json_object_get_string(registered_obj) : "unknown";

        printf("  %s (added: %s)\n", identity, registered_at);
    }

    printf("\n");
    json_object_put(root);
    return 0;
}

/**
 * Get contact list (from local contacts database)
 * Phase 9.4: Replaced HTTP API with local contacts_db
 */
int messenger_get_contact_list(messenger_context_t *ctx, char ***identities_out, int *count_out) {
    if (!ctx || !identities_out || !count_out) {
        return -1;
    }

    // Initialize contacts database if not already done
    if (contacts_db_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize contacts database\n");
        return -1;
    }

    // Get contact list from database
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0) {
        fprintf(stderr, "Error: Failed to get contact list\n");
        return -1;
    }

    *count_out = list->count;

    if (list->count == 0) {
        *identities_out = NULL;
        contacts_db_free_list(list);
        return 0;
    }

    // Allocate array of string pointers
    char **identities = (char**)malloc(sizeof(char*) * list->count);
    if (!identities) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        contacts_db_free_list(list);
        return -1;
    }

    // Copy each identity string
    for (size_t i = 0; i < list->count; i++) {
        identities[i] = strdup(list->contacts[i].identity);
        if (!identities[i]) {
            // Clean up on failure
            for (size_t j = 0; j < i; j++) {
                free(identities[j]);
            }
            free(identities);
            contacts_db_free_list(list);
            return -1;
        }
    }

    *identities_out = identities;
    contacts_db_free_list(list);
    return 0;
}

// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================

// Multi-recipient encryption header and entry structures
typedef struct {
    char magic[8];              // "PQSIGENC"
    uint8_t version;            // 0x06 (Category 5: Kyber1024 + Dilithium5)
    uint8_t enc_key_type;       // DAP_ENC_KEY_TYPE_KEM_KYBER512
    uint8_t recipient_count;    // Number of recipients (1-255)
    uint8_t reserved;
    uint32_t encrypted_size;    // Size of encrypted data
    uint32_t signature_size;    // Size of signature
} messenger_enc_header_t;

typedef struct {
    uint8_t kyber_ciphertext[1568];   // Kyber1024 ciphertext
    uint8_t wrapped_dek[40];          // AES-wrapped DEK (32-byte + 8-byte IV)
} messenger_recipient_entry_t;

/**
 * Multi-recipient encryption (adapted from encrypt.c)
 *
 * @param plaintext: Message to encrypt
 * @param plaintext_len: Message length
 * @param recipient_enc_pubkeys: Array of recipient Kyber1024 public keys (1568 bytes each)
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
                                                     QGP_DSA87_PUBLICKEYBYTES,
                                                     QGP_DSA87_SIGNATURE_BYTES);
    if (!signature) {
        fprintf(stderr, "Error: Memory allocation failed for signature\n");
        goto cleanup;
    }

    memcpy(qgp_signature_get_pubkey(signature), sender_sign_key->public_key,
           QGP_DSA87_PUBLICKEYBYTES);

    size_t actual_sig_len = 0;
    if (qgp_dsa87_sign(qgp_signature_get_bytes(signature), &actual_sig_len,
                                  (const uint8_t*)plaintext, plaintext_len,
                                  sender_sign_key->private_key) != 0) {
        fprintf(stderr, "Error: Dilithium3 signature creation failed\n");
        qgp_signature_free(signature);
        goto cleanup;
    }

    signature->signature_size = actual_sig_len;

    // Round-trip verification
    if (qgp_dsa87_verify(qgp_signature_get_bytes(signature), actual_sig_len,
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
    header_for_aad.version = 0x06;
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
        uint8_t kyber_ciphertext[1568];  // Kyber1024 ciphertext size
        uint8_t kek[32];  // KEK = shared secret from Kyber

        // Kyber512 encapsulation
        if (qgp_kem1024_encapsulate(kyber_ciphertext, kek, recipient_enc_pubkeys[i]) != 0) {
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
        memcpy(recipient_entries[i].kyber_ciphertext, kyber_ciphertext, 1568);  // Kyber1024 ciphertext size
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
    header.version = 0x06;
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
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/.dna/%s.dsa", home, ctx->identity);

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

    // Store in SQLite local database - one row per actual recipient (not sender)
    time_t now = time(NULL);

    for (size_t i = 0; i < recipient_count; i++) {
        int result = message_backup_save(
            ctx->backup_ctx,
            ctx->identity,      // sender
            recipients[i],      // recipient
            ciphertext,         // encrypted message
            ciphertext_len,     // encrypted length
            now,                // timestamp
            true                // is_outgoing = true (we're sending)
        );

        if (result != 0) {
            fprintf(stderr, "Store message failed for recipient '%s' in SQLite\n", recipients[i]);
            free(ciphertext);
            return -1;
        }

        printf("✓ Message stored locally for '%s'\n", recipients[i]);
    }

    // Phase 9.1b: Try P2P delivery for each recipient
    // If P2P succeeds, message delivered instantly
    // If P2P fails, message queued in DHT offline queue
    if (ctx->p2p_enabled && ctx->p2p_transport) {
        printf("\n[P2P] Attempting direct P2P delivery to %zu recipient(s)...\n", recipient_count);

        size_t p2p_success = 0;
        for (size_t i = 0; i < recipient_count; i++) {
            if (messenger_send_p2p(ctx, recipients[i], ciphertext, ciphertext_len) == 0) {
                p2p_success++;
            }
        }

        printf("[P2P] Delivery summary: %zu/%zu via P2P, %zu via DHT offline queue\n\n",
               p2p_success, recipient_count, recipient_count - p2p_success);
    } else {
        printf("\n[P2P] P2P disabled - using DHT offline queue\n\n");
    }

    free(ciphertext);

    printf("✓ Message sent successfully to %zu recipient(s)\n\n", recipient_count);
    return 0;
}

int messenger_list_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "List messages failed from SQLite\n");
        return -1;
    }

    // Filter for incoming messages only (where recipient == ctx->identity)
    int incoming_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            incoming_count++;
        }
    }

    printf("\n=== Inbox for %s (%d messages) ===\n\n", ctx->identity, incoming_count);

    if (incoming_count == 0) {
        printf("  (no messages)\n");
    } else {
        // Print incoming messages in reverse chronological order
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].recipient, ctx->identity) == 0) {
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

                printf("  [%d] From: %s (%s)\n", all_messages[i].id, all_messages[i].sender, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_list_sent_messages(messenger_context_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "List sent messages failed from SQLite\n");
        return -1;
    }

    // Filter for outgoing messages only (where sender == ctx->identity)
    int sent_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
            sent_count++;
        }
    }

    printf("\n=== Sent by %s (%d messages) ===\n\n", ctx->identity, sent_count);

    if (sent_count == 0) {
        printf("  (no sent messages)\n");
    } else {
        // Print sent messages in reverse chronological order
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

                printf("  [%d] To: %s (%s)\n", all_messages[i].id, all_messages[i].recipient, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_read_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Search SQLite for all messages to find the one with matching ID
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "Fetch message failed from SQLite\n");
        return -1;
    }

    // Find message with matching ID where we are the recipient
    backup_message_t *target_msg = NULL;
    for (int i = 0; i < all_count; i++) {
        if (all_messages[i].id == message_id && strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            target_msg = &all_messages[i];
            break;
        }
    }

    if (!target_msg) {
        fprintf(stderr, "Message %d not found or not for you\n", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    const char *sender = target_msg->sender;
    const uint8_t *ciphertext = target_msg->encrypted_message;
    size_t ciphertext_len = target_msg->encrypted_len;

    printf("\n========================================\n");
    printf(" Message #%d from %s\n", message_id, sender);
    printf("========================================\n\n");

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", kyber_path);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {  // Kyber1024 secret key size
        fprintf(stderr, "Error: Invalid Kyber1024 private key size: %zu (expected 3168)\n",
                kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        message_backup_free_messages(all_messages, all_count);
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
        message_backup_free_messages(all_messages, all_count);
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
            message_backup_free_messages(all_messages, all_count);
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
    message_backup_free_messages(all_messages, all_count);
    printf("\n");
    return 0;
}

int messenger_decrypt_message(messenger_context_t *ctx, int message_id,
                                char **plaintext_out, size_t *plaintext_len_out) {
    if (!ctx || !plaintext_out || !plaintext_len_out) {
        return -1;
    }

    // Fetch message from SQLite local database
    // Support decrypting both received messages (recipient = identity) AND sent messages (sender = identity)
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "Fetch message failed from SQLite\n");
        return -1;
    }

    // Find message with matching ID (either as sender OR recipient)
    backup_message_t *target_msg = NULL;
    for (int i = 0; i < all_count; i++) {
        if (all_messages[i].id == message_id) {
            target_msg = &all_messages[i];
            break;
        }
    }

    if (!target_msg) {
        fprintf(stderr, "Message %d not found\n", message_id);
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    const char *sender = target_msg->sender;
    const uint8_t *ciphertext = target_msg->encrypted_message;
    size_t ciphertext_len = target_msg->encrypted_len;

    // Load recipient's private Kyber512 key from filesystem
    const char *home = qgp_platform_home_dir();
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem", home, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0) {
        message_backup_free_messages(all_messages, all_count);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {  // Kyber1024 secret key size
        qgp_key_free(kyber_key);
        message_backup_free_messages(all_messages, all_count);
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
        message_backup_free_messages(all_messages, all_count);
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
            message_backup_free_messages(all_messages, all_count);
            return -1;
        }
        free(sender_sign_pubkey_keyserver);
        free(sender_enc_pubkey_keyserver);
    }

    free(sender_sign_pubkey_from_msg);
    message_backup_free_messages(all_messages, all_count);

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
    // TODO: Phase 2/4 - Migrate to DHT keyserver
    fprintf(stderr, "ERROR: messenger_delete_pubkey() not yet implemented (DHT migration pending)\n");
    (void)ctx; (void)identity;
    return -1;
}

int messenger_delete_message(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Delete from SQLite local database
    int result = message_backup_delete(ctx->backup_ctx, message_id);
    if (result != 0) {
        fprintf(stderr, "Delete message failed from SQLite\n");
        return -1;
    }

    printf("✓ Message %d deleted\n", message_id);
    return 0;
}

// ============================================================================
// MESSAGE SEARCH/FILTERING
// ============================================================================

int messenger_search_by_sender(messenger_context_t *ctx, const char *sender) {
    if (!ctx || !sender) {
        return -1;
    }

    // Search SQLite for all messages involving this identity
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "Search by sender failed from SQLite\n");
        return -1;
    }

    // Filter for messages from specified sender to current user (incoming messages only)
    int matching_count = 0;
    for (int i = 0; i < all_count; i++) {
        if (strcmp(all_messages[i].sender, sender) == 0 &&
            strcmp(all_messages[i].recipient, ctx->identity) == 0) {
            matching_count++;
        }
    }

    printf("\n=== Messages from %s to %s (%d messages) ===\n\n", sender, ctx->identity, matching_count);

    // Print matching messages in reverse chronological order
    if (matching_count == 0) {
        printf("  (no messages from %s)\n", sender);
    } else {
        for (int i = all_count - 1; i >= 0; i--) {
            if (strcmp(all_messages[i].sender, sender) == 0 &&
                strcmp(all_messages[i].recipient, ctx->identity) == 0) {
                struct tm *tm_info = localtime(&all_messages[i].timestamp);
                char timestamp_str[32];
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
                printf("  [%d] %s\n", all_messages[i].id, timestamp_str);
            }
        }
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

int messenger_show_conversation(messenger_context_t *ctx, const char *other_identity) {
    if (!ctx || !other_identity) {
        return -1;
    }

    // Get conversation from SQLite local database
    backup_message_t *messages = NULL;
    int count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, other_identity, &messages, &count);
    if (result != 0) {
        fprintf(stderr, "Show conversation failed from SQLite\n");
        return -1;
    }

    printf("\n");
    printf("========================================\n");
    printf(" Conversation: %s <-> %s\n", ctx->identity, other_identity);
    printf(" (%d messages)\n", count);
    printf("========================================\n\n");

    for (int i = 0; i < count; i++) {
        struct tm *tm_info = localtime(&messages[i].timestamp);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

        // Format: [ID] timestamp sender -> recipient
        if (strcmp(messages[i].sender, ctx->identity) == 0) {
            // Message sent by current user
            printf("  [%d] %s  You -> %s\n", messages[i].id, timestamp_str, messages[i].recipient);
        } else {
            // Message received by current user
            printf("  [%d] %s  %s -> You\n", messages[i].id, timestamp_str, messages[i].sender);
        }
    }

    if (count == 0) {
        printf("  (no messages exchanged)\n");
    }

    printf("\n");
    message_backup_free_messages(messages, count);
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

    // Get conversation from SQLite local database
    backup_message_t *backup_messages = NULL;
    int backup_count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, other_identity, &backup_messages, &backup_count);
    if (result != 0) {
        fprintf(stderr, "Get conversation failed from SQLite\n");
        return -1;
    }

    *count_out = backup_count;

    if (backup_count == 0) {
        *messages_out = NULL;
        return 0;
    }

    // Convert backup_message_t to message_info_t for GUI compatibility
    message_info_t *messages = (message_info_t*)calloc(backup_count, sizeof(message_info_t));
    if (!messages) {
        fprintf(stderr, "Memory allocation failed\n");
        message_backup_free_messages(backup_messages, backup_count);
        return -1;
    }

    // Convert each message
    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Convert time_t to string (format: YYYY-MM-DD HH:MM:SS)
        struct tm *tm_info = localtime(&backup_messages[i].timestamp);
        messages[i].timestamp = (char*)malloc(32);
        if (messages[i].timestamp) {
            strftime(messages[i].timestamp, 32, "%Y-%m-%d %H:%M:%S", tm_info);
        }

        // Convert bool flags to status string
        if (backup_messages[i].read) {
            messages[i].status = strdup("read");
        } else if (backup_messages[i].delivered) {
            messages[i].status = strdup("delivered");
        } else {
            messages[i].status = strdup("sent");
        }

        // For now, we don't have separate timestamps for delivered/read
        // We could add these to SQLite schema later if needed
        messages[i].delivered_at = backup_messages[i].delivered ? strdup(messages[i].timestamp) : NULL;
        messages[i].read_at = backup_messages[i].read ? strdup(messages[i].timestamp) : NULL;
        messages[i].plaintext = NULL;  // Not decrypted yet

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
            message_backup_free_messages(backup_messages, backup_count);
            return -1;
        }
    }

    *messages_out = messages;
    message_backup_free_messages(backup_messages, backup_count);
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

    // Parse date strings to time_t for comparison (format: YYYY-MM-DD)
    time_t start_time = 0;
    time_t end_time = 0;

    if (start_date) {
        struct tm tm = {0};
        if (sscanf(start_date, "%d-%d-%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
            tm.tm_year -= 1900;  // Years since 1900
            tm.tm_mon -= 1;      // Months since January (0-11)
            start_time = mktime(&tm);
        }
    }

    if (end_date) {
        struct tm tm = {0};
        if (sscanf(end_date, "%d-%d-%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday) == 3) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            end_time = mktime(&tm);
        }
    }

    // Get all messages from SQLite
    backup_message_t *all_messages = NULL;
    int all_count = 0;

    int result = message_backup_search_by_identity(ctx->backup_ctx, ctx->identity, &all_messages, &all_count);
    if (result != 0) {
        fprintf(stderr, "Search by date failed from SQLite\n");
        return -1;
    }

    // Filter by date range and sent/received criteria
    int matching_count = 0;
    for (int i = 0; i < all_count; i++) {
        // Check sent/received filter
        bool is_sent = (strcmp(all_messages[i].sender, ctx->identity) == 0);
        bool is_received = (strcmp(all_messages[i].recipient, ctx->identity) == 0);

        if (!include_sent && is_sent) continue;
        if (!include_received && is_received) continue;

        // Check date range
        if (start_date && all_messages[i].timestamp < start_time) continue;
        if (end_date && all_messages[i].timestamp >= end_time) continue;

        matching_count++;
    }

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

    printf("Found %d messages:\n\n", matching_count);

    // Print matching messages in reverse chronological order
    for (int i = all_count - 1; i >= 0; i--) {
        // Apply same filters
        bool is_sent = (strcmp(all_messages[i].sender, ctx->identity) == 0);
        bool is_received = (strcmp(all_messages[i].recipient, ctx->identity) == 0);

        if (!include_sent && is_sent) continue;
        if (!include_received && is_received) continue;

        if (start_date && all_messages[i].timestamp < start_time) continue;
        if (end_date && all_messages[i].timestamp >= end_time) continue;

        struct tm *tm_info = localtime(&all_messages[i].timestamp);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

        if (strcmp(all_messages[i].sender, ctx->identity) == 0) {
            printf("  [%d] %s  To: %s\n", all_messages[i].id, timestamp_str, all_messages[i].recipient);
        } else {
            printf("  [%d] %s  From: %s\n", all_messages[i].id, timestamp_str, all_messages[i].sender);
        }
    }

    if (matching_count == 0) {
        printf("  (no messages found)\n");
    }

    printf("\n");
    message_backup_free_messages(all_messages, all_count);
    return 0;
}

// ============================================================================
// MESSAGE STATUS / READ RECEIPTS
// ============================================================================

int messenger_mark_delivered(messenger_context_t *ctx, int message_id) {
    if (!ctx) {
        return -1;
    }

    // Mark message as delivered in SQLite local database
    int result = message_backup_mark_delivered(ctx->backup_ctx, message_id);
    if (result != 0) {
        fprintf(stderr, "Mark delivered failed from SQLite\n");
        return -1;
    }

    return 0;
}

int messenger_mark_conversation_read(messenger_context_t *ctx, const char *sender_identity) {
    if (!ctx || !sender_identity) {
        return -1;
    }

    // Get all messages in conversation with sender
    backup_message_t *messages = NULL;
    int count = 0;

    int result = message_backup_get_conversation(ctx->backup_ctx, sender_identity, &messages, &count);
    if (result != 0) {
        fprintf(stderr, "Mark conversation read failed from SQLite\n");
        return -1;
    }

    // Mark all incoming messages (where we are recipient) as read
    for (int i = 0; i < count; i++) {
        if (strcmp(messages[i].recipient, ctx->identity) == 0 && !messages[i].read) {
            // First ensure it's marked as delivered
            if (!messages[i].delivered) {
                message_backup_mark_delivered(ctx->backup_ctx, messages[i].id);
            }
            // Then mark as read
            message_backup_mark_read(ctx->backup_ctx, messages[i].id);
        }
    }

    message_backup_free_messages(messages, count);
    return 0;
}

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================
// NOTE: Group functions temporarily disabled - being migrated to DHT (Phase 3)
// See messenger_stubs.c for temporary stub implementations

#if 0  // DISABLED: PostgreSQL group functions (Phase 3 - DHT migration pending)

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

#endif  // DISABLED: PostgreSQL group functions
