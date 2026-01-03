/**
 * @file trx_wallet_create.c
 * @brief TRON Wallet Creation Implementation
 *
 * Creates TRON wallets using BIP-44 derivation from BIP39 seeds.
 * Path: m/44'/195'/0'/0/0
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#include "trx_wallet.h"
#include "trx_base58.h"
#include "../../crypto/bip32/bip32.h"
#include "../../crypto/utils/keccak256.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <json-c/json.h>

#define LOG_TAG "TRX_WALLET"

/* Global secp256k1 context */
static secp256k1_context *g_trx_secp256k1_ctx = NULL;

/* Current RPC endpoint */
static char g_trx_rpc_endpoint[256] = TRX_RPC_ENDPOINT_DEFAULT;

/**
 * Get/create secp256k1 context
 */
static secp256k1_context* get_secp256k1_ctx(void) {
    if (g_trx_secp256k1_ctx == NULL) {
        g_trx_secp256k1_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
        );
    }
    return g_trx_secp256k1_ctx;
}

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

int trx_address_from_pubkey(
    const uint8_t pubkey_uncompressed[TRX_PUBLIC_KEY_SIZE],
    uint8_t address_raw_out[TRX_ADDRESS_RAW_SIZE]
) {
    if (!pubkey_uncompressed || !address_raw_out) {
        return -1;
    }

    /* Verify public key starts with 0x04 (uncompressed) */
    if (pubkey_uncompressed[0] != 0x04) {
        QGP_LOG_ERROR(LOG_TAG, "Public key must be uncompressed (start with 0x04)");
        return -1;
    }

    /* Hash pubkey[1:65] with Keccak-256 (skip 0x04 prefix) */
    uint8_t hash[32];
    if (keccak256(pubkey_uncompressed + 1, 64, hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Keccak256 hash failed");
        return -1;
    }

    /* Address = 0x41 || hash[-20:] */
    address_raw_out[0] = TRX_ADDRESS_PREFIX;
    memcpy(address_raw_out + 1, hash + 12, 20);

    return 0;
}

int trx_address_to_base58(
    const uint8_t address_raw[TRX_ADDRESS_RAW_SIZE],
    char *address_out,
    size_t address_size
) {
    if (!address_raw || !address_out || address_size < TRX_ADDRESS_SIZE) {
        return -1;
    }

    /* Verify prefix */
    if (address_raw[0] != TRX_ADDRESS_PREFIX) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid TRON address prefix: 0x%02x", address_raw[0]);
        return -1;
    }

    /* Encode as Base58Check */
    int len = trx_base58check_encode(address_raw, TRX_ADDRESS_RAW_SIZE, address_out, address_size);
    if (len < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Base58Check encoding failed");
        return -1;
    }

    return 0;
}

int trx_address_from_base58(
    const char *address,
    uint8_t address_raw_out[TRX_ADDRESS_RAW_SIZE]
) {
    if (!address || !address_raw_out) {
        return -1;
    }

    /* Decode Base58Check */
    int len = trx_base58check_decode(address, address_raw_out, TRX_ADDRESS_RAW_SIZE);
    if (len != TRX_ADDRESS_RAW_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Base58Check decoding failed or wrong length: %d", len);
        return -1;
    }

    /* Verify prefix */
    if (address_raw_out[0] != TRX_ADDRESS_PREFIX) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid TRON address prefix: 0x%02x", address_raw_out[0]);
        return -1;
    }

    return 0;
}

bool trx_validate_address(const char *address) {
    if (!address) {
        return false;
    }

    /* Check length (TRON addresses are 34 characters) */
    size_t len = strlen(address);
    if (len != 34) {
        return false;
    }

    /* Check prefix (must start with 'T') */
    if (address[0] != 'T') {
        return false;
    }

    /* Verify Base58Check encoding and checksum */
    uint8_t address_raw[TRX_ADDRESS_RAW_SIZE];
    if (trx_address_from_base58(address, address_raw) != 0) {
        return false;
    }

    return true;
}

/* ============================================================================
 * WALLET GENERATION
 * ============================================================================ */

int trx_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    trx_wallet_t *wallet_out
) {
    if (!seed || seed_len < 64 || !wallet_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to trx_wallet_generate");
        return -1;
    }

    memset(wallet_out, 0, sizeof(*wallet_out));

    /* Derive key using BIP-44 path: m/44'/195'/0'/0/0 */
    bip32_extended_key_t derived_key;
    if (bip32_derive_path(seed, seed_len, "m/44'/195'/0'/0/0", &derived_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "BIP-44 derivation failed for TRON path");
        return -1;
    }

    /* Copy private key */
    memcpy(wallet_out->private_key, derived_key.private_key, TRX_PRIVATE_KEY_SIZE);

    /* Get uncompressed public key */
    if (bip32_get_public_key(&derived_key, wallet_out->public_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get public key");
        bip32_clear_key(&derived_key);
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Clear derived key */
    bip32_clear_key(&derived_key);

    /* Derive TRON address from public key */
    if (trx_address_from_pubkey(wallet_out->public_key, wallet_out->address_raw) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive address from public key");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Encode address as Base58Check */
    if (trx_address_to_base58(wallet_out->address_raw, wallet_out->address, TRX_ADDRESS_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode address as Base58Check");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Generated TRON wallet: %s", wallet_out->address);
    return 0;
}

int trx_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
) {
    if (!seed || seed_len < 64 || !name || !wallet_dir || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to trx_wallet_create_from_seed");
        return -1;
    }

    /* Generate wallet */
    trx_wallet_t wallet;
    if (trx_wallet_generate(seed, seed_len, &wallet) != 0) {
        return -1;
    }

    /* Save wallet to file */
    if (trx_wallet_save(&wallet, name, wallet_dir) != 0) {
        trx_wallet_clear(&wallet);
        return -1;
    }

    /* Copy address to output */
    strncpy(address_out, wallet.address, TRX_ADDRESS_SIZE - 1);
    address_out[TRX_ADDRESS_SIZE - 1] = '\0';

    /* Clear sensitive data */
    trx_wallet_clear(&wallet);

    QGP_LOG_INFO(LOG_TAG, "Created TRON wallet: %s", address_out);
    return 0;
}

void trx_wallet_clear(trx_wallet_t *wallet) {
    if (wallet) {
        memset(wallet, 0, sizeof(*wallet));
    }
}

/* ============================================================================
 * WALLET STORAGE
 * ============================================================================ */

int trx_wallet_save(
    const trx_wallet_t *wallet,
    const char *name,
    const char *wallet_dir
) {
    if (!wallet || !name || !wallet_dir) {
        return -1;
    }

    /* M9: Validate wallet name to prevent path traversal attacks */
    if (!qgp_platform_sanitize_filename(name)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid wallet name (contains unsafe characters): %s", name);
        return -1;
    }

    /* Create wallet directory if needed */
    if (!qgp_platform_is_directory(wallet_dir)) {
        if (qgp_platform_mkdir(wallet_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create directory: %s", wallet_dir);
            return -1;
        }
    }

    /* Build file path */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s%s", wallet_dir, name, TRX_WALLET_EXTENSION);

    /* Convert private key to hex */
    char privkey_hex[65];
    for (int i = 0; i < TRX_PRIVATE_KEY_SIZE; i++) {
        snprintf(privkey_hex + i * 2, 3, "%02x", wallet->private_key[i]);
    }
    privkey_hex[64] = '\0';

    /* Create JSON object */
    json_object *root = json_object_new_object();
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create JSON object");
        return -1;
    }

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "address", json_object_new_string(wallet->address));
    json_object_object_add(root, "private_key", json_object_new_string(privkey_hex));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(root, "blockchain", json_object_new_string("tron"));
    json_object_object_add(root, "network", json_object_new_string("mainnet"));

    /* Write to file */
    FILE *fp = fopen(file_path, "w");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open file for writing: %s", file_path);
        json_object_put(root);
        qgp_secure_memzero(privkey_hex, sizeof(privkey_hex));
        return -1;
    }

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    fprintf(fp, "%s\n", json_str);
    fclose(fp);

    /* Set file permissions to owner-only */
#ifndef _WIN32
    chmod(file_path, 0600);
#endif

    /* Cleanup */
    json_object_put(root);
    qgp_secure_memzero(privkey_hex, sizeof(privkey_hex));

    QGP_LOG_DEBUG(LOG_TAG, "Saved TRON wallet to: %s", file_path);
    return 0;
}

int trx_wallet_load(
    const char *file_path,
    trx_wallet_t *wallet_out
) {
    if (!file_path || !wallet_out) {
        return -1;
    }

    memset(wallet_out, 0, sizeof(*wallet_out));

    /* Read file */
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open wallet file: %s", file_path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10000) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid wallet file size: %ld", file_size);
        fclose(fp);
        return -1;
    }

    char *json_str = malloc(file_size + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }

    size_t read_len = fread(json_str, 1, file_size, fp);
    fclose(fp);
    json_str[read_len] = '\0';

    /* Parse JSON */
    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse wallet JSON");
        return -1;
    }

    /* Extract fields */
    json_object *address_obj, *privkey_obj;

    if (!json_object_object_get_ex(root, "address", &address_obj) ||
        !json_object_object_get_ex(root, "private_key", &privkey_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "Missing required fields in wallet JSON");
        json_object_put(root);
        return -1;
    }

    const char *address_str = json_object_get_string(address_obj);
    const char *privkey_str = json_object_get_string(privkey_obj);

    /* Copy address */
    strncpy(wallet_out->address, address_str, TRX_ADDRESS_SIZE - 1);

    /* Parse private key from hex */
    if (strlen(privkey_str) != 64) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid private key length in wallet");
        json_object_put(root);
        return -1;
    }

    for (int i = 0; i < TRX_PRIVATE_KEY_SIZE; i++) {
        unsigned int byte;
        if (sscanf(privkey_str + i * 2, "%2x", &byte) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid hex in private key");
            json_object_put(root);
            memset(wallet_out, 0, sizeof(*wallet_out));
            return -1;
        }
        wallet_out->private_key[i] = (uint8_t)byte;
    }

    json_object_put(root);

    /* Regenerate public key from private key */
    secp256k1_context *ctx = get_secp256k1_ctx();
    if (!ctx) {
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, wallet_out->private_key) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to regenerate public key");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    size_t len = TRX_PUBLIC_KEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(ctx, wallet_out->public_key, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize public key");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Regenerate raw address */
    if (trx_address_from_pubkey(wallet_out->public_key, wallet_out->address_raw) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive address");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    return 0;
}

int trx_wallet_get_address(
    const char *file_path,
    char *address_out,
    size_t address_size
) {
    if (!file_path || !address_out || address_size < TRX_ADDRESS_SIZE) {
        return -1;
    }

    /* Read just the address field from JSON */
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10000) {
        fclose(fp);
        return -1;
    }

    char *json_str = malloc(file_size + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }

    size_t read_len = fread(json_str, 1, file_size, fp);
    fclose(fp);
    json_str[read_len] = '\0';

    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        return -1;
    }

    json_object *address_obj;
    if (!json_object_object_get_ex(root, "address", &address_obj)) {
        json_object_put(root);
        return -1;
    }

    const char *address_str = json_object_get_string(address_obj);
    strncpy(address_out, address_str, address_size - 1);
    address_out[address_size - 1] = '\0';

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * RPC ENDPOINT MANAGEMENT
 * ============================================================================ */

int trx_rpc_set_endpoint(const char *endpoint) {
    if (!endpoint || strlen(endpoint) >= sizeof(g_trx_rpc_endpoint)) {
        return -1;
    }

    strncpy(g_trx_rpc_endpoint, endpoint, sizeof(g_trx_rpc_endpoint) - 1);
    g_trx_rpc_endpoint[sizeof(g_trx_rpc_endpoint) - 1] = '\0';

    QGP_LOG_INFO(LOG_TAG, "TRON RPC endpoint set to: %s", g_trx_rpc_endpoint);
    return 0;
}

const char* trx_rpc_get_endpoint(void) {
    return g_trx_rpc_endpoint;
}
