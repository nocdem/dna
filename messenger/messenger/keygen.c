/*
 * DNA Messenger - Key Generation Module Implementation
 */

// Windows: winsock2.h must be included before windows.h (pulled in by other headers)
#ifdef _WIN32
#include <winsock2.h>
#endif

#include "keygen.h"
#include "messenger_core.h"
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
#include "../dht/client/dht_identity.h"
#include "../database/keyserver_cache.h"
// p2p_transport.h no longer needed - Phase 14 uses dht_singleton_get() directly
#include "../dna_config.h"
#include "keys.h"
#include "../blockchain/cellframe/cellframe_wallet_create.h"
#include "../blockchain/ethereum/eth_wallet.h"
#include "../blockchain/solana/sol_wallet.h"
#include "../blockchain/cellframe/cellframe_wallet.h"
#include "../blockchain/blockchain_wallet.h"
#include "../blockchain/tron/trx_wallet.h"
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

/* v0.3.0: messenger_generate_keys() removed - use messenger_generate_keys_from_seeds() */

int messenger_generate_keys_from_seeds(
    const char *name,
    const uint8_t *signing_seed,
    const uint8_t *encryption_seed,
    const uint8_t *master_seed,
    const char *mnemonic,
    const char *data_dir,
    const char *password,
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

    // v0.3.0: Single-user flat storage (no fingerprint in path)
    // Create directory structure: <data_dir>/keys/, <data_dir>/wallets/, <data_dir>/db/
    char keys_dir[512];
    char wallets_dir[512];
    char db_dir[512];

    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/wallets", data_dir);
    snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);

    // Create base data dir if needed
    if (!qgp_platform_is_directory(data_dir)) {
        if (qgp_platform_mkdir(data_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", data_dir);
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

    // Create db directory
    if (!qgp_platform_is_directory(db_dir)) {
        if (qgp_platform_mkdir(db_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot create directory: %s", db_dir);
            qgp_key_free(sign_key);
            return -1;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Creating identity (fingerprint: %.16s...) in %s\n", fingerprint, data_dir);

    printf("✓ ML-DSA-87 signing key generated from seed\n");
    printf("  Fingerprint: %s\n", fingerprint);

    // Save to keys directory (optionally encrypted with password)
    // v0.3.0: Flat structure - keys/identity.dsa instead of keys/<fingerprint>.dsa
    char dilithium_path[512];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/identity.dsa", keys_dir);

    if (qgp_key_save_encrypted(sign_key, dilithium_path, password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save signing key");
        qgp_key_free(sign_key);
        return -1;
    }

    if (password && strlen(password) > 0) {
        QGP_LOG_INFO(LOG_TAG, "✓ Signing key encrypted with password");
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

    // Save to keys directory (optionally encrypted with password)
    // v0.3.0: Flat structure - keys/identity.kem instead of keys/<fingerprint>.kem
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/identity.kem", keys_dir);

    if (qgp_key_save_encrypted(enc_key, kyber_path, password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save encryption key");
        qgp_key_free(enc_key);
        free(dilithium_pubkey_copy);
        free(dilithium_privkey_copy);
        return -1;
    }

    printf("✓ ML-KEM-1024 encryption key generated from seed\n");

    if (password && strlen(password) > 0) {
        QGP_LOG_INFO(LOG_TAG, "✓ Encryption key encrypted with password");
    }

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

    // Create DHT identity from master seed (deterministic - same seed = same DHT identity)
    // This eliminates the need for DHT identity backup - just derive from BIP39 seed
    if (master_seed) {
        printf("[DHT Identity] Deriving deterministic DHT identity from master seed...\n");

        // Derive dht_seed = SHA3-512(master_seed + "dht_identity")[0:32]
        // Use SHA3-512 truncated to 32 bytes (cryptographically sound)
        uint8_t dht_seed[32];
        uint8_t full_hash[64];
        uint8_t seed_input[64 + 12];  // 64-byte master_seed + "dht_identity" (12 bytes)
        memcpy(seed_input, master_seed, 64);
        memcpy(seed_input + 64, "dht_identity", 12);

        if (qgp_sha3_512(seed_input, sizeof(seed_input), full_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to derive DHT seed from master seed");
        } else {
            // Truncate to 32 bytes for DHT seed
            memcpy(dht_seed, full_hash, 32);
            qgp_secure_memzero(full_hash, sizeof(full_hash));

            // Generate DHT identity deterministically from derived seed
            dht_identity_t *dht_identity = NULL;
            if (dht_identity_generate_from_seed(dht_seed, &dht_identity) != 0) {
                QGP_LOG_WARN(LOG_TAG, "Failed to create deterministic DHT identity");
            } else {
                printf("[DHT Identity] ✓ Deterministic DHT identity derived from master seed\n");
                printf("[DHT Identity] ✓ Same seed will always produce same DHT identity\n");

                // Export and save DHT identity locally for faster loading
                // v0.3.0: Flat structure - dht_identity.bin in root data dir
                uint8_t *dht_id_buffer = NULL;
                size_t dht_id_size = 0;
                if (dht_identity_export_to_buffer(dht_identity, &dht_id_buffer, &dht_id_size) == 0) {
                    char dht_id_path[512];
                    snprintf(dht_id_path, sizeof(dht_id_path), "%s/dht_identity.bin", data_dir);
                    FILE *f = fopen(dht_id_path, "wb");
                    if (f) {
                        fwrite(dht_id_buffer, 1, dht_id_size, f);
                        fclose(f);
                        QGP_LOG_INFO(LOG_TAG, "DHT identity saved to %s", dht_id_path);
                    }
                    free(dht_id_buffer);
                }

                // Free the identity (will be derived again on login)
                dht_identity_free(dht_identity);
            }

            // Securely wipe seed data
            qgp_secure_memzero(dht_seed, sizeof(dht_seed));
            qgp_secure_memzero(seed_input, sizeof(seed_input));
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "No master_seed provided - DHT identity not created");
        QGP_LOG_WARN(LOG_TAG, "DHT operations will use random identity (not recoverable)");
    }

    // NOTE: DHT publishing is now done via dht_keyserver_publish() with a name
    // Name-first architecture: identities are only published when a DNA name is registered
    // Keys are saved locally here, but not published to DHT until name registration
    QGP_LOG_INFO(LOG_TAG, "Keys saved locally. DHT publish requires DNA name registration.\n");

    // Save encrypted mnemonic for recovery and on-demand wallet derivation
    // Wallet private keys are NOT stored - they are derived when needed for transactions
    // This reduces attack surface: only mnemonic.enc needs to be protected
    // v0.3.0: Flat structure - mnemonic.enc in root data dir
    if (mnemonic && strlen(mnemonic) > 0) {
        if (mnemonic_storage_save(mnemonic, kyber_pk, data_dir) == 0) {
            QGP_LOG_INFO(LOG_TAG, "✓ Encrypted mnemonic saved (wallet keys derived on-demand)\n");
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to save encrypted mnemonic\n");
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "No mnemonic provided - wallet recovery will not be possible\n");
    }

    qgp_key_free(enc_key);

    // Securely wipe and free key copies
    if (dilithium_privkey_copy) {
        qgp_secure_memzero(dilithium_privkey_copy, dilithium_privkey_size);
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
    if (messenger_find_key_path(data_dir, fingerprint, ".dsa", dilithium_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signing key not found for fingerprint: %.16s...", fingerprint);
        return -1;
    }
    if (messenger_find_key_path(data_dir, fingerprint, ".kem", kyber_path) != 0) {
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

    // Phase 14: Use global DHT singleton directly (no P2P transport dependency)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available, cannot register name");
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    }

    // Derive wallet addresses from mnemonic (on-demand derivation)
    // Wallet files are no longer stored - addresses are derived when needed
    char wallet_address[128] = {0};
    char eth_address[48] = {0};
    char sol_address[48] = {0};
    char trx_address[48] = {0};

    // v0.3.0: Flat structure - mnemonic.enc in root data_dir
    // Check if mnemonic exists and derive wallet addresses
    if (mnemonic_storage_exists(data_dir)) {
        char mnemonic[512] = {0};

        // Decrypt mnemonic using Kyber private key
        if (mnemonic_storage_load(mnemonic, sizeof(mnemonic),
                                   enc_key->private_key, data_dir) == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "Mnemonic loaded for wallet derivation");

            // Convert mnemonic to 64-byte master seed for ETH/SOL
            uint8_t master_seed[64];
            if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) == 0) {

                // Derive ETH address
                eth_wallet_t eth_wallet;
                if (eth_wallet_generate(master_seed, 64, &eth_wallet) == 0) {
                    strncpy(eth_address, eth_wallet.address_hex, sizeof(eth_address) - 1);
                    eth_wallet_clear(&eth_wallet);
                    QGP_LOG_DEBUG(LOG_TAG, "Derived ETH address: %s", eth_address);
                }

                // Derive SOL address
                sol_wallet_t sol_wallet;
                if (sol_wallet_generate(master_seed, 64, &sol_wallet) == 0) {
                    strncpy(sol_address, sol_wallet.address, sizeof(sol_address) - 1);
                    sol_wallet_clear(&sol_wallet);
                    QGP_LOG_DEBUG(LOG_TAG, "Derived SOL address: %s", sol_address);
                }

                // Derive TRX address
                trx_wallet_t trx_wallet;
                if (trx_wallet_generate(master_seed, 64, &trx_wallet) == 0) {
                    strncpy(trx_address, trx_wallet.address, sizeof(trx_address) - 1);
                    trx_wallet_clear(&trx_wallet);
                    QGP_LOG_DEBUG(LOG_TAG, "Derived TRX address: %s", trx_address);
                }

                // Clear master seed
                qgp_secure_memzero(master_seed, sizeof(master_seed));
            }

            // Derive Cellframe address (uses SHA3-256 of mnemonic, not BIP39 seed)
            uint8_t cf_seed[CF_WALLET_SEED_SIZE];
            if (cellframe_derive_seed_from_mnemonic(mnemonic, cf_seed) == 0) {
                if (cellframe_wallet_derive_address(cf_seed, wallet_address) == 0) {
                    QGP_LOG_DEBUG(LOG_TAG, "Derived Cellframe address: %s", wallet_address);
                }
                qgp_secure_memzero(cf_seed, sizeof(cf_seed));
            }

            // Clear mnemonic from memory
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to decrypt mnemonic for wallet derivation");
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "No mnemonic found - wallet addresses will be empty");
    }

    // Log final wallet addresses before publishing
    QGP_LOG_INFO(LOG_TAG, "Wallet addresses for profile publish:");
    QGP_LOG_INFO(LOG_TAG, "  Cellframe: %s", wallet_address[0] ? wallet_address : "(none)");
    QGP_LOG_INFO(LOG_TAG, "  ETH: %s", eth_address[0] ? eth_address : "(none)");
    QGP_LOG_INFO(LOG_TAG, "  SOL: %s", sol_address[0] ? sol_address : "(none)");
    QGP_LOG_INFO(LOG_TAG, "  TRX: %s", trx_address[0] ? trx_address : "(none)");

    // Publish identity to DHT (unified: creates fingerprint:profile and name:lookup)
    QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] keygen calling dht_keyserver_publish for new identity");
    int publish_result = dht_keyserver_publish(
        dht_ctx,
        fingerprint,
        desired_name,
        sign_key->public_key,
        enc_key->public_key,
        sign_key->private_key,
        wallet_address[0] ? wallet_address : NULL,
        eth_address[0] ? eth_address : NULL,
        sol_address[0] ? sol_address : NULL,
        trx_address[0] ? trx_address : NULL
    );

    if (publish_result == -2) {
        QGP_LOG_ERROR(LOG_TAG, "Name '%s' is already taken", desired_name);
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        return -1;
    } else if (publish_result == -3) {
        QGP_LOG_ERROR(LOG_TAG, "DHT network not ready - cannot register name '%s'", desired_name);
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

    // Read-back verification: confirm data actually stored in DHT
    // Wait briefly for DHT propagation before verifying
    qgp_platform_sleep_ms(1500);  // 1.5 seconds

    dna_unified_identity_t *verify_identity = NULL;
    int verify_result = dht_keyserver_lookup(dht_ctx, fingerprint, &verify_identity);
    if (verify_result == 0 && verify_identity) {
        QGP_LOG_INFO(LOG_TAG, "✓ Read-back verification: profile confirmed in DHT");
        dna_identity_free(verify_identity);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Read-back verification failed (profile may still propagate)");
        // Don't fail registration - PUT succeeded, verification is extra assurance
    }

    // Verify name lookup alias
    char *lookup_fp = NULL;
    int alias_verify = dna_lookup_by_name(dht_ctx, desired_name, &lookup_fp);
    if (alias_verify == 0 && lookup_fp) {
        if (strncmp(lookup_fp, fingerprint, 128) == 0) {
            QGP_LOG_INFO(LOG_TAG, "✓ Read-back verification: name '%s' -> fingerprint confirmed", desired_name);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Name lookup returned different fingerprint!");
        }
        free(lookup_fp);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Read-back verification failed for name lookup (may still propagate)");
    }

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

// ============================================================================
// KEY RESTORATION FROM BIP39 SEED
// ============================================================================

static qgp_key_type_t get_sign_key_type(const char *algo) {
    if (strcasecmp(algo, "dilithium") == 0) {
        return QGP_KEY_TYPE_DSA87;
    } else {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", algo);
        return QGP_KEY_TYPE_INVALID;
    }
}

/**
 * Restore keys from BIP39 recovery seed
 *
 * Prompts user for mnemonic and passphrase via stdin, then regenerates
 * the signing and encryption keys deterministically.
 *
 * @param name: Identity name
 * @param algo: Signing algorithm ("dilithium")
 * @param output_dir: Directory to save keys
 * @return: 0 on success, non-zero on error
 */
int cmd_restore_key_from_seed(const char *name, const char *algo, const char *output_dir) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    char *sign_key_path = NULL;
    char *enc_key_path = NULL;
    int ret = -1;

    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    char passphrase[256];
    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];

    printf("Restoring keypair from BIP39 recovery seed for: %s\n", name);
    printf("  Signing algorithm: %s\n", algo);
    printf("  Encryption: ML-KEM-1024 (post-quantum)\n");
    printf("  Output directory: %s\n", output_dir);
    printf("\n");

    qgp_key_type_t sign_key_type = get_sign_key_type(algo);
    if (sign_key_type == QGP_KEY_TYPE_INVALID) {
        return -1;
    }

    /* Step 1: Prompt for BIP39 mnemonic */
    printf("[Step 1/4] Enter your 24-word BIP39 recovery seed\n");
    printf("(separated by spaces)\n\n");

    if (!fgets(mnemonic, sizeof(mnemonic), stdin)) {
        fprintf(stderr, "Error: Failed to read mnemonic\n");
        return -1;
    }

    size_t len = strlen(mnemonic);
    if (len > 0 && mnemonic[len - 1] == '\n') {
        mnemonic[len - 1] = '\0';
    }

    /* Step 2: Validate mnemonic */
    printf("\n[Step 2/4] Validating mnemonic...\n");
    if (!bip39_validate_mnemonic(mnemonic)) {
        fprintf(stderr, "Error: Invalid mnemonic\n");
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        return -1;
    }
    printf("  Mnemonic valid\n");

    /* Step 3: Prompt for passphrase */
    printf("\n[Step 3/4] Enter passphrase (if you used one during generation)\n");
    printf("Press Enter if no passphrase was used:\n");
    if (!fgets(passphrase, sizeof(passphrase), stdin)) {
        fprintf(stderr, "Error: Failed to read passphrase\n");
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        return -1;
    }

    len = strlen(passphrase);
    if (len > 0 && passphrase[len - 1] == '\n') {
        passphrase[len - 1] = '\0';
    }

    /* Step 4: Derive seeds */
    printf("\n[Step 4/4] Deriving seeds from mnemonic...\n");
    if (qgp_derive_seeds_from_mnemonic(mnemonic, passphrase, signing_seed, encryption_seed) != 0) {
        fprintf(stderr, "Error: Seed derivation failed\n");
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));
        qgp_secure_memzero(passphrase, sizeof(passphrase));
        return -1;
    }

    qgp_secure_memzero(mnemonic, sizeof(mnemonic));
    qgp_secure_memzero(passphrase, sizeof(passphrase));

    printf("  Seeds derived\n");
    printf("\nRegenerating keys from seed...\n");

    /* Create output directory */
    if (!qgp_platform_is_directory(output_dir)) {
        if (qgp_platform_mkdir(output_dir) != 0) {
            fprintf(stderr, "Error: Cannot create directory: %s\n", output_dir);
            goto cleanup;
        }
    }

    /* Build key paths */
    char sign_filename[512];
    char enc_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s.dsa", name);
    snprintf(enc_filename, sizeof(enc_filename), "%s.kem", name);

    sign_key_path = qgp_platform_join_path(output_dir, sign_filename);
    enc_key_path = qgp_platform_join_path(output_dir, enc_filename);

    if (!sign_key_path || !enc_key_path) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    if (qgp_platform_file_exists(sign_key_path)) {
        fprintf(stderr, "Error: Signing key already exists: %s\n", sign_key_path);
        goto cleanup;
    }

    if (qgp_platform_file_exists(enc_key_path)) {
        fprintf(stderr, "Error: Encryption key already exists: %s\n", enc_key_path);
        goto cleanup;
    }

    /* Generate signing key */
    printf("\n  [1/2] Regenerating signing key from seed...\n");

    sign_key = qgp_key_new(QGP_KEY_TYPE_DSA87, QGP_KEY_PURPOSE_SIGNING);
    if (!sign_key) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    strncpy(sign_key->name, name, sizeof(sign_key->name) - 1);

    uint8_t *dilithium_pk = calloc(1, QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dilithium_sk = calloc(1, QGP_DSA87_SECRETKEYBYTES);

    if (!dilithium_pk || !dilithium_sk) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        goto cleanup;
    }

    if (qgp_dsa87_keypair_derand(dilithium_pk, dilithium_sk, signing_seed) != 0) {
        fprintf(stderr, "Error: DSA-87 key regeneration failed\n");
        free(dilithium_pk);
        free(dilithium_sk);
        goto cleanup;
    }

    sign_key->public_key = dilithium_pk;
    sign_key->public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    sign_key->private_key = dilithium_sk;
    sign_key->private_key_size = QGP_DSA87_SECRETKEYBYTES;

    if (qgp_key_save(sign_key, sign_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save signing key\n");
        goto cleanup;
    }
    printf("  Signing key saved: %s\n", sign_key_path);

    /* Verify signing key */
    const char *test_data = "verification-test";
    size_t test_len = strlen(test_data);
    uint8_t test_sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t test_siglen = 0;

    if (qgp_dsa87_sign(test_sig, &test_siglen, (const uint8_t*)test_data, test_len, sign_key->private_key) != 0 ||
        qgp_dsa87_verify(test_sig, test_siglen, (const uint8_t*)test_data, test_len, sign_key->public_key) != 0) {
        fprintf(stderr, "Error: Signing key verification failed\n");
        goto cleanup;
    }
    printf("  Signing key verified\n");

    /* Generate encryption key */
    printf("\n  [2/2] Regenerating encryption key from seed...\n");

    enc_key = qgp_key_new(QGP_KEY_TYPE_KEM1024, QGP_KEY_PURPOSE_ENCRYPTION);
    if (!enc_key) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    strncpy(enc_key->name, name, sizeof(enc_key->name) - 1);

    uint8_t *kyber_pk = calloc(1, 1568);
    uint8_t *kyber_sk = calloc(1, 3168);

    if (!kyber_pk || !kyber_sk) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(kyber_pk);
        free(kyber_sk);
        goto cleanup;
    }

    if (crypto_kem_keypair_derand(kyber_pk, kyber_sk, encryption_seed) != 0) {
        fprintf(stderr, "Error: KEM-1024 key regeneration failed\n");
        free(kyber_pk);
        free(kyber_sk);
        goto cleanup;
    }

    enc_key->public_key = kyber_pk;
    enc_key->public_key_size = 1568;
    enc_key->private_key = kyber_sk;
    enc_key->private_key_size = 3168;

    if (qgp_key_save(enc_key, enc_key_path) != 0) {
        fprintf(stderr, "Error: Failed to save encryption key\n");
        goto cleanup;
    }
    printf("  Encryption key saved: %s\n", enc_key_path);

    printf("\nKeys successfully restored from recovery seed!\n");
    ret = 0;

cleanup:
    qgp_secure_memzero(signing_seed, sizeof(signing_seed));
    qgp_secure_memzero(encryption_seed, sizeof(encryption_seed));

    if (sign_key_path) free(sign_key_path);
    if (enc_key_path) free(enc_key_path);
    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}
