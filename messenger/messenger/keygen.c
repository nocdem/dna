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
#include "../crypto/utils/qgp_log.h"

#define LOG_TAG "KEYGEN"
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
#include "../blockchain/ethereum/eth_wallet.h"
#include "../blockchain/solana/sol_wallet.h"
#include "../blockchain/cellframe/cellframe_wallet.h"
#include "../blockchain/blockchain_wallet.h"
#include "../crypto/utils/seed_storage.h"

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
        QGP_LOG_ERROR(LOG_TAG, "Identity '%s' already exists in keyserver! Please choose a different name.", identity);
        return -1;
    }

    // Get data directory
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get data directory");
        return -1;
    }

    // Use the QGP function to generate keys with BIP39 seed phrase
    // This will show the user their recovery seed and generate keys deterministically
    if (cmd_gen_key_from_seed(identity, "dilithium", data_dir) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Key generation failed");
        return -1;
    }

    // cmd_gen_key_from_seed creates keys in QGP format which includes public keys
    // Now we need to export the public keys and upload to keyserver

    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", data_dir, identity);

    // Export public key bundle
    if (cmd_export_pubkey(identity, data_dir, pubkey_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to export public key");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to read ASCII-armored public key");
        return -1;
    }

    // Parse header (20 bytes): magic[8] + version + sign_key_type + enc_key_type + reserved + sign_size(4) + enc_size(4)
    if (pubkey_data_size < 20) {
        QGP_LOG_ERROR(LOG_TAG, "Public key data too small");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to upload public keys to keyserver");
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
    const uint8_t *master_seed,
    const char *mnemonic,
    const char *data_dir,
    char *fingerprint_out)
{
    if (!signing_seed || !encryption_seed || !data_dir || !fingerprint_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to messenger_generate_keys_from_seeds");
        return -1;
    }

    // Generate Dilithium5 (ML-DSA-87) signing key from seed FIRST (need fingerprint for directory)
    qgp_key_t *sign_key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for signing key");
        return -1;
    }

    uint8_t *dilithium_pk = calloc(1, QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DSA87_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for DSA-87 buffers");
        free(dilithium_pk);
        free(dilithium_sk);
        qgp_key_free(sign_key);
        return -1;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DSA-87 key generation from seed failed");
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

    // Create directory structure: <data_dir>/<fingerprint>/keys/ and <data_dir>/<fingerprint>/wallets/
    char identity_dir[512];
    char keys_dir[512];
    char wallets_dir[512];

    snprintf(identity_dir, sizeof(identity_dir), "%s/%s", data_dir, dir_name);
    snprintf(keys_dir, sizeof(keys_dir), "%s/%s/keys", data_dir, dir_name);
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/%s/wallets", data_dir, dir_name);

    // Create base data dir if needed
    if (!qgp_platform_is_directory(data_dir)) {
        if (qgp_platform_mkdir(data_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", data_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create identity directory
    if (!qgp_platform_is_directory(identity_dir)) {
        if (qgp_platform_mkdir(identity_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", identity_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create keys directory
    if (!qgp_platform_is_directory(keys_dir)) {
        if (qgp_platform_mkdir(keys_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", keys_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    // Create wallets directory
    if (!qgp_platform_is_directory(wallets_dir)) {
        if (qgp_platform_mkdir(wallets_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", wallets_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Creating identity '%s' in %s\n", dir_name, identity_dir);

    printf("✓ ML-DSA-87 signing key generated from seed\n");
    printf("  Fingerprint: %s\n", fingerprint);

    // Save to keys directory
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s.dsa", keys_dir, fingerprint);

    if (qgp_key_save(sign_key, dilithium_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save signing key");
        qgp_key_free(sign_key);
        return -1;
    }

    // Keep copies of keys for DHT publishing (before freeing)
    uint8_t *dilithium_pubkey_copy = malloc(sign_key->public_key_size);
    uint8_t *dilithium_privkey_copy = malloc(sign_key->private_key_size);
    if (!dilithium_pubkey_copy || !dilithium_privkey_copy) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
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
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for encryption key");
        return -1;
    }

    uint8_t *kyber_pk = calloc(1, 1568);  // Kyber1024 public key size
    uint8_t *kyber_sk = calloc(1, 3168);  // Kyber1024 secret key size

    if (!kyber_pk || !kyber_sk) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for KEM-1024 buffers");
        free(kyber_pk);
        free(kyber_sk);
        qgp_key_free(enc_key);
        return -1;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM-1024 key generation from seed failed");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to save encryption key");
        qgp_key_free(enc_key);
        free(dilithium_pubkey_copy);
        free(dilithium_privkey_copy);
        return -1;
    }

    printf("✓ ML-KEM-1024 encryption key generated from seed\n");

    // Keep copies of public keys for DHT publishing (before freeing)
    uint8_t *kyber_pubkey_copy = malloc(enc_key->public_key_size);
    if (!kyber_pubkey_copy) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
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
        QGP_LOG_WARN(LOG_TAG, "DHT not initialized, skipping DHT identity backup");
        
    } else {
        // Create random DHT identity + encrypted backup (local + DHT)
        dht_identity_t *dht_identity = NULL;
        if (dht_identity_create_and_backup(fingerprint, kyber_pk, dht_ctx, &dht_identity) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to create DHT identity backup");
            
        } else {
            printf("[DHT Identity] ✓ Random DHT identity created and backed up\n");
            printf("[DHT Identity] ✓ Encrypted backup saved locally and published to DHT\n");

            // Free the identity (will be loaded later on login)
            dht_identity_free(dht_identity);
        }

        // NOTE: DHT publishing is now done via dht_keyserver_publish() with a name
        // Name-first architecture: identities are only published when a DNA name is registered
        // Keys are saved locally here, but not published to DHT until name registration
        QGP_LOG_INFO(LOG_TAG, "Keys saved locally. DHT publish requires DNA name registration.\n");
    }

    // Create blockchain wallets from master_seed and mnemonic
    // - Cellframe uses SHA3-256(mnemonic) to match Cellframe wallet app
    // - ETH/SOL use BIP-44/SLIP-10 from 64-byte master_seed
    if (master_seed) {
        QGP_LOG_INFO(LOG_TAG, "Creating blockchain wallets...\n");

        if (blockchain_create_all_wallets(master_seed, mnemonic, dir_name, wallets_dir) == 0) {
            QGP_LOG_INFO(LOG_TAG, "✓ Blockchain wallets created in %s\n", wallets_dir);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Some wallets may have failed to create (non-fatal)\n");
        }

        // Save encrypted master seed for future chain wallet creation
        // Uses Kyber1024 KEM + AES-256-GCM encryption
        if (seed_storage_save(master_seed, kyber_pk, identity_dir) == 0) {
            QGP_LOG_INFO(LOG_TAG, "✓ Encrypted master seed saved for future wallet creation\n");
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to save encrypted seed (non-fatal)\n");
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "No master_seed provided - skipping wallet creation\n");
    }

    qgp_key_free(enc_key);

    // Securely wipe and free key copies
    if (dilithium_privkey_copy) {
        memset(dilithium_privkey_copy, 0, dilithium_privkey_size);
        free(dilithium_privkey_copy);
    }
    free(dilithium_pubkey_copy);
    free(kyber_pubkey_copy);

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
 * Searches through all <data_dir>/<name>/keys/ directories
 */
static int keygen_find_key_path(const char *data_dir, const char *fingerprint,
                                const char *extension, char *path_out) {
    DIR *base_dir = opendir(data_dir);
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
                 data_dir, identity_entry->d_name, fingerprint, extension);

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
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters");
        return -1;
    }

    // Validate fingerprint length
    if (strlen(fingerprint) != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length (must be 128 hex chars)");
        return -1;
    }

    // Validate name format (3-20 chars, alphanumeric + underscore)
    size_t name_len = strlen(desired_name);
    if (name_len < 3 || name_len > 20) {
        QGP_LOG_ERROR(LOG_TAG, "Name must be 3-20 characters");
        return -1;
    }

    for (size_t i = 0; i < name_len; i++) {
        char c = desired_name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            QGP_LOG_ERROR(LOG_TAG, "Name can only contain letters, numbers, and underscore");
            return -1;
        }
    }

    // Check if name already exists in keyserver
    uint8_t *existing_sign = NULL, *existing_enc = NULL;
    size_t sign_len = 0, enc_len = 0;

    if (messenger_load_pubkey(ctx, desired_name, &existing_sign, &sign_len, &existing_enc, &enc_len, NULL) == 0) {
        free(existing_sign);
        free(existing_enc);
        QGP_LOG_ERROR(LOG_TAG, "Name '%s' is already registered! Please choose a different name.", desired_name);
        return -1;
    }

    // Load keys from fingerprint-based files
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get data directory");
        return -1;
    }

    // Find key files in <data_dir>/*/keys/ structure
    char dilithium_path[512];
    char kyber_path[512];
    if (keygen_find_key_path(data_dir, fingerprint, ".dsa", dilithium_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signing key not found for fingerprint: %.16s...", fingerprint);
        return -1;
    }
    if (keygen_find_key_path(data_dir, fingerprint, ".kem", kyber_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Encryption key not found for fingerprint: %.16s...", fingerprint);
        return -1;
    }

    // Load Dilithium key
    qgp_key_t *sign_key = NULL;
    if (qgp_key_load(dilithium_path, &sign_key) != 0 || !sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key from %s", dilithium_path);
        return -1;
    }

    // Load Kyber key
    qgp_key_t *enc_key = NULL;
    if (qgp_key_load(kyber_path, &enc_key) != 0 || !enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load encryption key from %s", kyber_path);
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
        QGP_LOG_ERROR(LOG_TAG, "DHT not available, cannot register name");
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    }

    // Find wallet addresses for this identity
    char wallet_address[128] = {0};
    char eth_address[48] = {0};
    char sol_address[48] = {0};
    char wallets_path[512];
    snprintf(wallets_path, sizeof(wallets_path), "%s/%s/wallets", data_dir, fingerprint);

    QGP_LOG_DEBUG(LOG_TAG, "Scanning wallets directory: %s", wallets_path);

    DIR *wdir = opendir(wallets_path);
    if (wdir) {
        QGP_LOG_DEBUG(LOG_TAG, "Wallets directory opened successfully");
        struct dirent *wentry;
        while ((wentry = readdir(wdir)) != NULL) {
            QGP_LOG_DEBUG(LOG_TAG, "Found file: %s", wentry->d_name);

            // Cellframe wallet
            if (strstr(wentry->d_name, ".dwallet") && wallet_address[0] == '\0') {
                char wpath[768];
                snprintf(wpath, sizeof(wpath), "%s/%s", wallets_path, wentry->d_name);
                QGP_LOG_DEBUG(LOG_TAG, "Loading Cellframe wallet: %s", wpath);
                cellframe_wallet_t *wallet = NULL;
                if (wallet_read_cellframe_path(wpath, &wallet) == 0 && wallet) {
                    if (wallet->address[0]) {
                        strncpy(wallet_address, wallet->address, sizeof(wallet_address) - 1);
                        QGP_LOG_DEBUG(LOG_TAG, "Cellframe wallet loaded: %s", wallet_address);
                    } else {
                        QGP_LOG_WARN(LOG_TAG, "Cellframe wallet has empty address");
                    }
                    wallet_free(wallet);
                } else {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to load Cellframe wallet: %s", wpath);
                }
            }
            // ETH wallet
            if (strstr(wentry->d_name, ".eth.json") && eth_address[0] == '\0') {
                char wpath[768];
                snprintf(wpath, sizeof(wpath), "%s/%s", wallets_path, wentry->d_name);
                QGP_LOG_DEBUG(LOG_TAG, "Loading ETH wallet: %s", wpath);
                eth_wallet_t eth_wallet;
                if (eth_wallet_load(wpath, &eth_wallet) == 0) {
                    strncpy(eth_address, eth_wallet.address_hex, sizeof(eth_address) - 1);
                    QGP_LOG_DEBUG(LOG_TAG, "ETH wallet loaded: %s", eth_address);
                } else {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to load ETH wallet: %s", wpath);
                }
            }
            // SOL wallet
            if (strstr(wentry->d_name, ".sol.json") && sol_address[0] == '\0') {
                char wpath[768];
                snprintf(wpath, sizeof(wpath), "%s/%s", wallets_path, wentry->d_name);
                QGP_LOG_DEBUG(LOG_TAG, "Loading SOL wallet: %s", wpath);
                sol_wallet_t sol_wallet;
                if (sol_wallet_load(wpath, &sol_wallet) == 0) {
                    strncpy(sol_address, sol_wallet.address, sizeof(sol_address) - 1);
                    QGP_LOG_DEBUG(LOG_TAG, "SOL wallet loaded: %s", sol_address);
                    sol_wallet_clear(&sol_wallet);
                } else {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to load SOL wallet: %s", wpath);
                }
            }
        }
        closedir(wdir);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open wallets directory: %s", wallets_path);
    }

    // Log final wallet addresses before publishing
    QGP_LOG_INFO(LOG_TAG, "Wallet addresses for profile publish:");
    QGP_LOG_INFO(LOG_TAG, "  Cellframe: %s", wallet_address[0] ? wallet_address : "(none)");
    QGP_LOG_INFO(LOG_TAG, "  ETH: %s", eth_address[0] ? eth_address : "(none)");
    QGP_LOG_INFO(LOG_TAG, "  SOL: %s", sol_address[0] ? sol_address : "(none)");

    // Publish identity to DHT (unified: creates fingerprint:profile and name:lookup)
    int publish_result = dht_keyserver_publish(
        dht_ctx,
        fingerprint,
        desired_name,
        sign_key->public_key,
        enc_key->public_key,
        sign_key->private_key,
        wallet_address[0] ? wallet_address : NULL,
        eth_address[0] ? eth_address : NULL,
        sol_address[0] ? sol_address : NULL
    );

    if (publish_result == -2) {
        QGP_LOG_ERROR(LOG_TAG, "Name '%s' is already taken", desired_name);
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    } else if (publish_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish identity to DHT");
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Identity published to DHT (fingerprint:profile + name:lookup)\n");

    // Cache public keys locally
    if (keyserver_cache_put(fingerprint, sign_key->public_key, sign_key->public_key_size,
                            enc_key->public_key, enc_key->public_key_size, 365*24*60*60) == 0) {
        QGP_LOG_INFO(LOG_TAG, "✓ Public keys cached locally\n");
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
        QGP_LOG_ERROR(LOG_TAG, "Identity '%s' already exists in keyserver! Please choose a different name.", identity);
        return -1;
    }

    // Get data directory
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot get data directory");
        return -1;
    }

    // Use QGP's restore function which prompts for mnemonic and passphrase
    if (cmd_restore_key_from_seed(identity, "dilithium", data_dir) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Key restoration failed");
        return -1;
    }

    // Export public key bundle
    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", data_dir, identity);

    if (cmd_export_pubkey(identity, data_dir, pubkey_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to export public key");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to read ASCII-armored public key");
        return -1;
    }

    // Parse header (20 bytes): magic[8] + version + sign_key_type + enc_key_type + reserved + sign_size(4) + enc_size(4)
    if (pubkey_data_size < 20) {
        QGP_LOG_ERROR(LOG_TAG, "Public key data too small");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint");
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
        QGP_LOG_ERROR(LOG_TAG, "Failed to upload public keys to keyserver");
        return -1;
    }

    printf("\n✓ Keys restored and uploaded to keyserver\n");
    printf("✓ Identity '%s' (fingerprint: %s) is now ready to use!\n\n", identity, fingerprint);
    return 0;
}

// NOTE: messenger_restore_keys_from_file() was removed - dead code using old path structure
