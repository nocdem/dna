/*
 * DNA Messenger - Key Generation Module Implementation
 */

#include "keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../qgp.h"
#include "../crypto/bip39/bip39.h"
#include "../crypto/utils/kyber_deterministic.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/core/dht_context.h"
#include "../dht/client/dht_singleton.h"
#include "../dht/client/dht_identity_backup.h"
#include "../database/keyserver_cache.h"
#include "../p2p/p2p_transport.h"
#include "../dna_config.h"
#include "keys.h"
#include "../blockchain/cellframe/cellframe_wallet_create.h"
#include "../blockchain/cellframe/cellframe_wallet.h"

// Network byte order conversion
#ifdef _WIN32
#include <winsock2.h>
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#else
#include <arpa/inet.h>
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#endif
#endif

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

    if (messenger_load_pubkey(ctx, identity, &existing_sign, &sign_len, &existing_enc, &enc_len, NULL) == 0) {
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

    // Compute fingerprint from Dilithium5 public key
    char fingerprint[129];
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512(dilithium_pk, sizeof(dilithium_pk), hash) != 0) {
        fprintf(stderr, "Error: Failed to compute fingerprint\n");
        free(type);
        free(pubkey_data);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);
        return -1;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';

    // Cleanup
    free(type);
    free(pubkey_data);
    for (size_t i = 0; i < header_count; i++) free(headers[i]);
    free(headers);

    // Upload public keys to keyserver (FINGERPRINT-FIRST)
    if (messenger_store_pubkey(ctx, fingerprint, identity, dilithium_pk, sizeof(dilithium_pk),
                                kyber_pk, sizeof(kyber_pk)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    printf("\n✓ Keys uploaded to keyserver\n");
    printf("✓ Identity '%s' (fingerprint: %s) is now ready to use!\n\n", identity, fingerprint);
    return 0;
}

int messenger_generate_keys_from_seeds(
    const char *name,
    const uint8_t *signing_seed,
    const uint8_t *encryption_seed,
    const uint8_t *wallet_seed,
    const char *data_dir,
    char *fingerprint_out)
{
    if (!signing_seed || !encryption_seed || !data_dir || !fingerprint_out) {
        fprintf(stderr, "Error: Invalid arguments to messenger_generate_keys_from_seeds\n");
        return -1;
    }

    // Generate Dilithium5 (ML-DSA-87) signing key from seed FIRST (need fingerprint for directory)
    qgp_key_t *sign_key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed for signing key\n");
        return -1;
    }

    uint8_t *dilithium_pk = calloc(1, QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DSA87_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed for DSA-87 buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        return -1;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: DSA-87 key generation from seed failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        return -1;
    }

    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DSA87_SECRETKEYBYTES;

    // Compute fingerprint from public key (SHA3-512 hash)
    char fingerprint[129];
    dna_compute_fingerprint(dilithium_pk, fingerprint);

    // Directory is always fingerprint-based (deterministic, never changes)
    const char *dir_name = fingerprint;

    // Create directory structure: ~/.dna/<fingerprint>/keys/ and ~/.dna/<fingerprint>/wallets/
    char identity_dir[512];
    char keys_dir[512];
    char wallets_dir[512];

    snprintf(identity_dir, sizeof(identity_dir), "%s/%s", data_dir, dir_name);
    snprintf(keys_dir, sizeof(keys_dir), "%s/%s/keys", data_dir, dir_name);
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/%s/wallets", data_dir, dir_name);

    // Create base data dir if needed
    if (!qgp_platform_is_directory(data_dir)) {
        if (qgp_platform_mkdir(data_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", data_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create identity directory
    if (!qgp_platform_is_directory(identity_dir)) {
        if (qgp_platform_mkdir(identity_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", identity_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create keys directory
    if (!qgp_platform_is_directory(keys_dir)) {
        if (qgp_platform_mkdir(keys_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", keys_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create wallets directory
    if (!qgp_platform_is_directory(wallets_dir)) {
        if (qgp_platform_mkdir(wallets_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", wallets_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    printf("[KEYGEN] Creating identity '%s' in %s\n", dir_name, identity_dir);

    printf("✓ ML-DSA-87 signing key generated from seed\n");
    printf("  Fingerprint: %s\n", fingerprint);

    // Save to keys directory
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s.dsa", keys_dir, fingerprint);

    if (qgp_key_save(sign_key, dilithium_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        qgp_key_free(sign_key);
        return -1;
    }

    // Keep copies of keys for DHT publishing (before freeing)
    uint8_t *dilithium_pubkey_copy = malloc(sign_key->public_key_size);
    uint8_t *dilithium_privkey_copy = malloc(sign_key->private_key_size);
    if (!dilithium_pubkey_copy || !dilithium_privkey_copy) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(dilithium_pubkey_copy);
        free(dilithium_privkey_copy);
        qgp_key_free(sign_key);
        return -1;
    }
    memcpy(dilithium_pubkey_copy, sign_key->public_key, sign_key->public_key_size);
    memcpy(dilithium_privkey_copy, sign_key->private_key, sign_key->private_key_size);
    size_t dilithium_pubkey_size = sign_key->public_key_size;
    size_t dilithium_privkey_size = sign_key->private_key_size;

    qgp_key_free(sign_key);

    // Generate Kyber1024 (ML-KEM-1024) encryption key from seed
    qgp_key_t *enc_key = qgp_key_new(QGP_KEY_TYPE_KEM1024, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed for encryption key\n");
        return -1;
    }

    uint8_t *kyber_pk = calloc(1, 1568);  // Kyber1024 public key size
    uint8_t *kyber_sk = calloc(1, 3168);  // Kyber1024 secret key size

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed for KEM-1024 buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        return -1;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: KEM-1024 key generation from seed failed\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        return -1;
    }

    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 1568;  // Kyber1024 public key size
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 3168;  // Kyber1024 secret key size

    // Save to keys directory
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s.kem", keys_dir, fingerprint);

    if (qgp_key_save(enc_key, kyber_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        qgp_key_free(enc_key);
        free(dilithium_pubkey_copy);
        free(dilithium_privkey_copy);
        return -1;
    }

    printf("✓ ML-KEM-1024 encryption key generated from seed\n");

    // Keep copies of public keys for DHT publishing (before freeing)
    uint8_t *kyber_pubkey_copy = malloc(enc_key->public_key_size);
    if (!kyber_pubkey_copy) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        qgp_key_free(enc_key);
        free(dilithium_pubkey_copy);
        free(dilithium_privkey_copy);
        return -1;
    }
    memcpy(kyber_pubkey_copy, enc_key->public_key, enc_key->public_key_size);
    size_t kyber_pubkey_size = enc_key->public_key_size;

    // Create DHT identity backup (for BIP39 recovery)
    printf("[DHT Identity] Creating random DHT identity for signing...\n");

    // Get DHT context (global singleton)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        fprintf(stderr, "Warning: DHT not initialized, skipping DHT identity backup\n");
        fprintf(stderr, "         You can retry DHT identity creation after connecting to DHT\n");
    } else {
        // Create random DHT identity + encrypted backup (local + DHT)
        dht_identity_t *dht_identity = NULL;
        if (dht_identity_create_and_backup(fingerprint, kyber_pk, dht_ctx, &dht_identity) != 0) {
            fprintf(stderr, "Warning: Failed to create DHT identity backup\n");
            fprintf(stderr, "         Your messenger will still work, but DHT operations may accumulate values\n");
        } else {
            printf("[DHT Identity] ✓ Random DHT identity created and backed up\n");
            printf("[DHT Identity] ✓ Encrypted backup saved locally and published to DHT\n");

            // Free the identity (will be loaded later on login)
            dht_identity_free(dht_identity);
        }

        // NOTE: DHT publishing is now done via dht_keyserver_publish() with a name
        // Name-first architecture: identities are only published when a DNA name is registered
        // Keys are saved locally here, but not published to DHT until name registration
        printf("[DHT_KEYSERVER] Keys saved locally. DHT publish requires DNA name registration.\n");
    }

    qgp_key_free(enc_key);

    // Securely wipe and free key copies
    if (dilithium_privkey_copy) {
        memset(dilithium_privkey_copy, 0, dilithium_privkey_size);
        free(dilithium_privkey_copy);
    }
    free(dilithium_pubkey_copy);
    free(kyber_pubkey_copy);

    // Create Cellframe wallet if wallet_seed provided
    if (wallet_seed) {
        printf("[WALLET] Creating Cellframe wallet...\n");

        char wallet_address[CF_WALLET_ADDRESS_MAX];

        // Create wallet as <dir_name>.dwallet in ~/.dna/<dir_name>/wallets/
        if (cellframe_wallet_create_from_seed(wallet_seed, dir_name, wallets_dir, wallet_address) == 0) {
            printf("[WALLET] ✓ Cellframe wallet created: %s.dwallet\n", dir_name);
            printf("[WALLET] ✓ Address: %s\n", wallet_address);
        } else {
            fprintf(stderr, "[WALLET] Warning: Failed to create Cellframe wallet (non-fatal)\n");
        }
    }

    // Copy fingerprint to output parameter
    strncpy(fingerprint_out, fingerprint, 128);
    fingerprint_out[128] = '\0';

    printf("✓ Identity created successfully!\n");
    printf("✓ Fingerprint: %s\n", fingerprint);
    printf("\nNote: Register a name via Settings menu to allow others to find you.\n");
    return 0;
}

/**
 * Find the path to a key file (.dsa or .kem) for a given fingerprint
 * Searches through all ~/.dna/<name>/keys/ directories
 */
static int keygen_find_key_path(const char *dna_dir, const char *fingerprint,
                                const char *extension, char *path_out) {
    DIR *base_dir = opendir(dna_dir);
    if (!base_dir) {
        return -1;
    }

    struct dirent *identity_entry;
    while ((identity_entry = readdir(base_dir)) != NULL) {
        if (strcmp(identity_entry->d_name, ".") == 0 ||
            strcmp(identity_entry->d_name, "..") == 0) {
            continue;
        }

        char test_path[512];
        snprintf(test_path, sizeof(test_path), "%s/%s/keys/%s%s",
                 dna_dir, identity_entry->d_name, fingerprint, extension);

        FILE *f = fopen(test_path, "r");
        if (f) {
            fclose(f);
            strncpy(path_out, test_path, 511);
            path_out[511] = '\0';
            closedir(base_dir);
            return 0;
        }
    }

    closedir(base_dir);
    return -1;
}

int messenger_register_name(
    messenger_context_t *ctx,
    const char *fingerprint,
    const char *desired_name)
{
    if (!ctx || !fingerprint || !desired_name) {
        fprintf(stderr, "Error: Invalid parameters\n");
        return -1;
    }

    // Validate fingerprint length
    if (strlen(fingerprint) != 128) {
        fprintf(stderr, "Error: Invalid fingerprint length (must be 128 hex chars)\n");
        return -1;
    }

    // Validate name format (3-20 chars, alphanumeric + underscore)
    size_t name_len = strlen(desired_name);
    if (name_len < 3 || name_len > 20) {
        fprintf(stderr, "Error: Name must be 3-20 characters\n");
        return -1;
    }

    for (size_t i = 0; i < name_len; i++) {
        char c = desired_name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            fprintf(stderr, "Error: Name can only contain letters, numbers, and underscore\n");
            return -1;
        }
    }

    // Check if name already exists in keyserver
    uint8_t *existing_sign = NULL, *existing_enc = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, desired_name, &existing_sign, &sign_len, &existing_enc, &enc_len, NULL) == 0) {
        free(existing_sign);
        free(existing_enc);
        fprintf(stderr, "\nError: Name '%s' is already registered!\n", desired_name);
        fprintf(stderr, "Please choose a different name.\n\n");
        return -1;
    }

    // Load keys from fingerprint-based files
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot get home directory\n");
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Find key files in ~/.dna/*/keys/ structure
    char dilithium_path[512];
    char kyber_path[512];
    if (keygen_find_key_path(dna_dir, fingerprint, ".dsa", dilithium_path) != 0) {
        fprintf(stderr, "Error: Signing key not found for fingerprint: %s\n", fingerprint);
        return -1;
    }
    if (keygen_find_key_path(dna_dir, fingerprint, ".kem", kyber_path) != 0) {
        fprintf(stderr, "Error: Encryption key not found for fingerprint: %s\n", fingerprint);
        return -1;
    }

    // Load Dilithium key
    qgp_key_t *sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sign_key) != 0 || !sign_key) {
        fprintf(stderr, "Error: Failed to load signing key from %s\n", dilithium_path);
        return -1;
    }

    // Load Kyber key
    qgp_key_t *enc_key = NULL;
    if (qgp_key_load(kyber_path, &enc_key) != 0 || !enc_key) {
        fprintf(stderr, "Error: Failed to load encryption key from %s\n", kyber_path);
        qgp_key_free(sign_key);
        return -1;
    }

    // Get DHT context
    dht_context_t *dht_ctx = NULL;
    if (ctx->p2p_transport) {
        dht_ctx = (dht_context_t*)p2p_transport_get_dht_context(ctx->p2p_transport);
    } else {
        dht_ctx = dht_singleton_get();
    }

    if (!dht_ctx) {
        fprintf(stderr, "Error: DHT not available, cannot register name\n");
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    }

    // Find wallet address for this identity
    char wallet_address[128] = {0};
    char wallets_path[512];
    snprintf(wallets_path, sizeof(wallets_path), "%s/%s/wallets", dna_dir, fingerprint);

    DIR *wdir = opendir(wallets_path);
    if (wdir) {
        struct dirent *wentry;
        while ((wentry = readdir(wdir)) != NULL) {
            if (strstr(wentry->d_name, ".dwallet")) {
                char wpath[768];
                snprintf(wpath, sizeof(wpath), "%s/%s", wallets_path, wentry->d_name);
                cellframe_wallet_t *wallet = NULL;
                if (wallet_read_cellframe_path(wpath, &wallet) == 0 && wallet) {
                    if (wallet->address[0]) {
                        strncpy(wallet_address, wallet->address, sizeof(wallet_address) - 1);
                    }
                    wallet_free(wallet);
                    break;
                }
            }
        }
        closedir(wdir);
    }

    // Publish identity to DHT (unified: creates fingerprint:profile and name:lookup)
    int publish_result = dht_keyserver_publish(
        dht_ctx,
        fingerprint,
        desired_name,
        sign_key->public_key,
        enc_key->public_key,
        sign_key->private_key,
        wallet_address[0] ? wallet_address : NULL
    );

    if (publish_result == -2) {
        fprintf(stderr, "Error: Name '%s' is already taken\n", desired_name);
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    } else if (publish_result != 0) {
        fprintf(stderr, "Error: Failed to publish identity to DHT\n");
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    }

    printf("[DNA] ✓ Identity published to DHT (fingerprint:profile + name:lookup)\n");

    // Cache public keys locally
    if (keyserver_cache_put(fingerprint, sign_key->public_key, sign_key->public_key_size,
                            enc_key->public_key, enc_key->public_key_size, 365*24*60*60) == 0) {
        printf("[DNA] ✓ Public keys cached locally\n");
    }

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    printf("✓ Name '%s' registered successfully!\n", desired_name);
    printf("✓ Others can now find you by searching for '%s' or by fingerprint\n", desired_name);
    return 0;
}

int messenger_restore_keys(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    // Check if identity already exists in keyserver
    uint8_t *existing_sign = NULL, *existing_enc = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, identity, &existing_sign, &sign_len, &existing_enc, &enc_len, NULL) == 0) {
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

    // Compute fingerprint from Dilithium5 public key
    char fingerprint[129];
    unsigned char hash[64];  // SHA3-512 = 64 bytes
    if (qgp_sha3_512(dilithium_pk, sizeof(dilithium_pk), hash) != 0) {
        fprintf(stderr, "Error: Failed to compute fingerprint\n");
        free(type);
        free(pubkey_data);
        for (size_t i = 0; i < header_count; i++) free(headers[i]);
        free(headers);
        return -1;
    }

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        sprintf(fingerprint + (i * 2), "%02x", hash[i]);
    }
    fingerprint[128] = '\0';

    // Cleanup
    free(type);
    free(pubkey_data);
    for (size_t i = 0; i < header_count; i++) free(headers[i]);
    free(headers);

    // Upload public keys to keyserver (FINGERPRINT-FIRST)
    if (messenger_store_pubkey(ctx, fingerprint, identity, dilithium_pk, sizeof(dilithium_pk),
                                kyber_pk, sizeof(kyber_pk)) != 0) {
        fprintf(stderr, "Error: Failed to upload public keys to keyserver\n");
        return -1;
    }

    printf("\n✓ Keys restored and uploaded to keyserver\n");
    printf("✓ Identity '%s' (fingerprint: %s) is now ready to use!\n\n", identity, fingerprint);
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

    if (messenger_load_pubkey(ctx, identity, &keyserver_sign, &keyserver_sign_len, &keyserver_enc, &keyserver_enc_len, NULL) != 0) {
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

    // Build mnemonic from first 24 words with bounds checking
    size_t pos = 0;
    for (int i = 0; i < 24; i++) {
        // Add space separator
        if (i > 0 && pos < sizeof(mnemonic) - 1) {
            mnemonic[pos++] = ' ';
        }

        // Add word with overflow check
        size_t word_len = strlen(words[i]);
        if (pos + word_len >= sizeof(mnemonic)) {
            fprintf(stderr, "Error: Mnemonic buffer overflow (word %d too long)\n", i);
            return -1;
        }
        memcpy(mnemonic + pos, words[i], word_len);
        pos += word_len;
    }
    mnemonic[pos] = '\0';

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

    // Derive seeds from mnemonic (wallet_seed not used for restore - wallet already exists)
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    if (qgp_derive_seeds_from_mnemonic(mnemonic, passphrase, signing_seed, encryption_seed, NULL) != 0) {
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

    // Generate Dilithium5 signing key (ML-DSA-87) from seed
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
        fprintf(stderr, "Error: Memory allocation failed for DSA-87 buffers\n");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: DSA-87 key generation from seed failed\n");
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

    printf("✓ ML-DSA-87 signing key generated from seed\n");

    // Copy dilithium public key for verification before freeing
    uint8_t dilithium_pk_verify[2592];  // Dilithium5 public key size
    memcpy(dilithium_pk_verify, dilithium_pk, sizeof(dilithium_pk_verify));

    qgp_key_free(sign_key);

    // Generate Kyber1024 encryption key (ML-KEM-1024) from seed
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
        fprintf(stderr, "Error: Memory allocation failed for KEM-1024 buffers\n");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        memset(signing_seed, 0, sizeof(signing_seed));
        memset(encryption_seed, 0, sizeof(encryption_seed));
        return -1;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: KEM-1024 key generation from seed failed\n");
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

    printf("✓ ML-KEM-1024 encryption key generated from seed\n");

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
