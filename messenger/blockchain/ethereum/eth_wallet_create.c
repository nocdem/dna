/**
 * @file eth_wallet_create.c
 * @brief Ethereum Wallet Creation Implementation
 *
 * Creates Ethereum wallets using BIP-44 derivation from BIP39 seeds.
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "eth_wallet.h"
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

#define LOG_TAG "ETH_WALLET"

/* Global secp256k1 context */
static secp256k1_context *g_eth_secp256k1_ctx = NULL;

/**
 * Get/create secp256k1 context
 */
static secp256k1_context* get_secp256k1_ctx(void) {
    if (g_eth_secp256k1_ctx == NULL) {
        g_eth_secp256k1_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
        );
    }
    return g_eth_secp256k1_ctx;
}

/* ============================================================================
 * WALLET GENERATION
 * ============================================================================ */

int eth_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    eth_wallet_t *wallet_out
) {
    if (!seed || seed_len < 64 || !wallet_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to eth_wallet_generate");
        return -1;
    }

    memset(wallet_out, 0, sizeof(*wallet_out));

    /* Derive key using BIP-44 path: m/44'/60'/0'/0/0 */
    bip32_extended_key_t derived_key;
    if (bip32_derive_ethereum(seed, seed_len, &derived_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "BIP-44 derivation failed");
        return -1;
    }

    /* Copy private key */
    memcpy(wallet_out->private_key, derived_key.private_key, 32);

    /* Get uncompressed public key */
    if (bip32_get_public_key(&derived_key, wallet_out->public_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get public key");
        bip32_clear_key(&derived_key);
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Clear derived key */
    bip32_clear_key(&derived_key);

    /* Derive Ethereum address from public key */
    if (eth_address_from_pubkey(wallet_out->public_key, wallet_out->address) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive address from public key");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Format address as checksummed hex */
    if (eth_address_to_hex(wallet_out->address, wallet_out->address_hex) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to format address as hex");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Generated Ethereum wallet: %s", wallet_out->address_hex);
    return 0;
}

int eth_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
) {
    if (!seed || seed_len < 64 || !name || !wallet_dir || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to eth_wallet_create_from_seed");
        return -1;
    }

    /* Generate wallet */
    eth_wallet_t wallet;
    if (eth_wallet_generate(seed, seed_len, &wallet) != 0) {
        return -1;
    }

    /* Save wallet to file */
    if (eth_wallet_save(&wallet, name, wallet_dir) != 0) {
        eth_wallet_clear(&wallet);
        return -1;
    }

    /* Copy address to output */
    strncpy(address_out, wallet.address_hex, ETH_ADDRESS_HEX_SIZE - 1);
    address_out[ETH_ADDRESS_HEX_SIZE - 1] = '\0';

    /* Clear sensitive data */
    eth_wallet_clear(&wallet);

    QGP_LOG_INFO(LOG_TAG, "Created Ethereum wallet: %s", address_out);
    return 0;
}

void eth_wallet_clear(eth_wallet_t *wallet) {
    if (wallet) {
        memset(wallet, 0, sizeof(*wallet));
    }
}

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

int eth_address_from_private_key(
    const uint8_t private_key[32],
    uint8_t address_out[20]
) {
    if (!private_key || !address_out) {
        return -1;
    }

    secp256k1_context *ctx = get_secp256k1_ctx();
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get secp256k1 context");
        return -1;
    }

    /* Verify private key is valid */
    if (secp256k1_ec_seckey_verify(ctx, private_key) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid private key");
        return -1;
    }

    /* Generate public key */
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, private_key) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create public key");
        return -1;
    }

    /* Serialize as uncompressed */
    uint8_t pubkey_uncompressed[65];
    size_t len = 65;
    if (secp256k1_ec_pubkey_serialize(ctx, pubkey_uncompressed, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize public key");
        return -1;
    }

    /* Derive address */
    return eth_address_from_pubkey(pubkey_uncompressed, address_out);
}

int eth_address_to_hex(
    const uint8_t address[20],
    char hex_out[43]
) {
    if (!address || !hex_out) {
        return -1;
    }

    /* Convert to lowercase hex first */
    char lowercase[41];
    for (int i = 0; i < 20; i++) {
        snprintf(lowercase + i * 2, 3, "%02x", address[i]);
    }
    lowercase[40] = '\0';

    /* Apply EIP-55 checksum */
    char checksummed[41];
    if (eth_address_checksum(lowercase, checksummed) != 0) {
        return -1;
    }

    /* Format with 0x prefix */
    snprintf(hex_out, 43, "0x%s", checksummed);
    return 0;
}

bool eth_validate_address(const char *address) {
    if (!address) {
        return false;
    }

    const char *hex = address;

    /* Skip 0x prefix */
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    /* Must be 40 hex characters */
    if (strlen(hex) != 40) {
        return false;
    }

    /* Validate all characters are hex */
    for (int i = 0; i < 40; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }

    return true;
}

/* ============================================================================
 * WALLET STORAGE
 * ============================================================================ */

int eth_wallet_save(
    const eth_wallet_t *wallet,
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
    snprintf(file_path, sizeof(file_path), "%s/%s%s", wallet_dir, name, ETH_WALLET_EXTENSION);

    /* Convert private key to hex */
    char privkey_hex[65];
    for (int i = 0; i < 32; i++) {
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
    json_object_object_add(root, "address", json_object_new_string(wallet->address_hex));
    json_object_object_add(root, "private_key", json_object_new_string(privkey_hex));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(root, "blockchain", json_object_new_string("ethereum"));
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

    QGP_LOG_DEBUG(LOG_TAG, "Saved wallet to: %s", file_path);
    return 0;
}

int eth_wallet_load(
    const char *file_path,
    eth_wallet_t *wallet_out
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
    strncpy(wallet_out->address_hex, address_str, ETH_ADDRESS_HEX_SIZE - 1);

    /* Parse private key from hex */
    if (strlen(privkey_str) != 64) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid private key length in wallet");
        json_object_put(root);
        return -1;
    }

    for (int i = 0; i < 32; i++) {
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

    /* Regenerate public key and address from private key */
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

    size_t len = 65;
    if (secp256k1_ec_pubkey_serialize(ctx, wallet_out->public_key, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize public key");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    if (eth_address_from_pubkey(wallet_out->public_key, wallet_out->address) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive address");
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    return 0;
}

int eth_wallet_get_address(
    const char *file_path,
    char *address_out,
    size_t address_size
) {
    if (!file_path || !address_out || address_size < ETH_ADDRESS_HEX_SIZE) {
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
