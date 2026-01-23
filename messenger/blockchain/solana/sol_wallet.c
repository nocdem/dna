/**
 * @file sol_wallet.c
 * @brief Solana Wallet Implementation
 *
 * Creates Solana wallets using SLIP-10 Ed25519 derivation from BIP39 seeds.
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#include "sol_wallet.h"
#include "../../crypto/utils/base58.h"
#include "../../crypto/utils/qgp_log.h"
#include "../../crypto/utils/qgp_platform.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <json-c/json.h>

#define LOG_TAG "SOL_WALLET"

/* SLIP-10 Ed25519 derivation constant */
#define SLIP10_ED25519_SEED "ed25519 seed"

/* RPC endpoints with fallbacks (accessed from sol_rpc.c) */
const char *g_sol_rpc_endpoints[] = {
    SOL_RPC_MAINNET,
    SOL_RPC_MAINNET_FALLBACK1,
    SOL_RPC_MAINNET_FALLBACK2
};

/* RPC endpoint (configurable) - can be overridden or auto-selected */
static char g_sol_rpc_endpoint[256] = SOL_RPC_MAINNET;

/* Index of current/last working endpoint (accessed from sol_rpc.c) */
int g_sol_rpc_current_idx = 0;

/* ============================================================================
 * SLIP-10 ED25519 DERIVATION
 * ============================================================================ */

/**
 * SLIP-10 master key derivation for Ed25519
 *
 * key = HMAC-SHA512("ed25519 seed", seed)
 * IL (left 32 bytes) = private key
 * IR (right 32 bytes) = chain code
 */
static int slip10_master_key(
    const uint8_t *seed,
    size_t seed_len,
    uint8_t key_out[32],
    uint8_t chain_code_out[32]
) {
    uint8_t hmac_out[64];
    unsigned int hmac_len = 64;

    if (!HMAC(EVP_sha512(), SLIP10_ED25519_SEED, strlen(SLIP10_ED25519_SEED),
              seed, seed_len, hmac_out, &hmac_len)) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA512 failed for master key");
        return -1;
    }

    memcpy(key_out, hmac_out, 32);
    memcpy(chain_code_out, hmac_out + 32, 32);

    return 0;
}

/**
 * SLIP-10 child key derivation for Ed25519
 *
 * For Ed25519, only hardened derivation is supported.
 * data = 0x00 || key || index (with hardened bit set)
 */
static int slip10_derive_child(
    const uint8_t key[32],
    const uint8_t chain_code[32],
    uint32_t index,
    uint8_t key_out[32],
    uint8_t chain_code_out[32]
) {
    /* Ed25519 only supports hardened derivation */
    uint32_t hardened_index = index | 0x80000000;

    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, key, 32);
    data[33] = (hardened_index >> 24) & 0xFF;
    data[34] = (hardened_index >> 16) & 0xFF;
    data[35] = (hardened_index >> 8) & 0xFF;
    data[36] = hardened_index & 0xFF;

    uint8_t hmac_out[64];
    unsigned int hmac_len = 64;

    if (!HMAC(EVP_sha512(), chain_code, 32, data, 37, hmac_out, &hmac_len)) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA512 failed for child derivation");
        return -1;
    }

    memcpy(key_out, hmac_out, 32);
    memcpy(chain_code_out, hmac_out + 32, 32);

    return 0;
}

/**
 * Derive Solana key using SLIP-10 path m/44'/501'/0'/0'
 */
static int slip10_derive_solana(
    const uint8_t *seed,
    size_t seed_len,
    uint8_t private_key_out[32]
) {
    uint8_t key[32], chain_code[32];

    /* Master key */
    if (slip10_master_key(seed, seed_len, key, chain_code) != 0) {
        return -1;
    }

    /* Derive path: m/44'/501'/0'/0' */
    uint32_t path[] = { 44, 501, 0, 0 };

    for (int i = 0; i < 4; i++) {
        uint8_t new_key[32], new_chain[32];
        if (slip10_derive_child(key, chain_code, path[i], new_key, new_chain) != 0) {
            qgp_secure_memzero(key, 32);
            qgp_secure_memzero(chain_code, 32);
            return -1;
        }
        memcpy(key, new_key, 32);
        memcpy(chain_code, new_chain, 32);
    }

    memcpy(private_key_out, key, 32);

    /* Clear intermediate values */
    qgp_secure_memzero(key, 32);
    qgp_secure_memzero(chain_code, 32);

    return 0;
}

/* ============================================================================
 * ED25519 KEY OPERATIONS
 * ============================================================================ */

/**
 * Generate Ed25519 public key from private key using OpenSSL
 */
static int ed25519_pubkey_from_private(
    const uint8_t private_key[32],
    uint8_t public_key_out[32]
) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, private_key, 32
    );
    if (!pkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create Ed25519 key: %s",
                     ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    size_t pubkey_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pubkey_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get Ed25519 public key");
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_free(pkey);
    return 0;
}

/* ============================================================================
 * WALLET GENERATION
 * ============================================================================ */

int sol_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    sol_wallet_t *wallet_out
) {
    if (!seed || seed_len < 64 || !wallet_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sol_wallet_generate");
        return -1;
    }

    memset(wallet_out, 0, sizeof(*wallet_out));

    /* Derive private key using SLIP-10 */
    if (slip10_derive_solana(seed, seed_len, wallet_out->private_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SLIP-10 derivation failed");
        return -1;
    }

    /* Generate public key */
    if (ed25519_pubkey_from_private(wallet_out->private_key,
                                     wallet_out->public_key) != 0) {
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    /* Convert to base58 address */
    if (sol_pubkey_to_address(wallet_out->public_key, wallet_out->address) != 0) {
        memset(wallet_out, 0, sizeof(*wallet_out));
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Generated Solana wallet: %s", wallet_out->address);
    return 0;
}

int sol_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
) {
    if (!seed || seed_len < 64 || !name || !wallet_dir || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to sol_wallet_create_from_seed");
        return -1;
    }

    /* Generate wallet */
    sol_wallet_t wallet;
    if (sol_wallet_generate(seed, seed_len, &wallet) != 0) {
        return -1;
    }

    /* Save wallet to file */
    if (sol_wallet_save(&wallet, name, wallet_dir) != 0) {
        sol_wallet_clear(&wallet);
        return -1;
    }

    /* Copy address to output */
    strncpy(address_out, wallet.address, SOL_ADDRESS_SIZE);
    address_out[SOL_ADDRESS_SIZE] = '\0';

    /* Clear sensitive data */
    sol_wallet_clear(&wallet);

    QGP_LOG_INFO(LOG_TAG, "Created Solana wallet: %s", address_out);
    return 0;
}

/* ============================================================================
 * WALLET FILE I/O
 * ============================================================================ */

int sol_wallet_save(
    const sol_wallet_t *wallet,
    const char *name,
    const char *wallet_dir
) {
    if (!wallet || !name || !wallet_dir) {
        return -1;
    }

    /* Create wallet JSON */
    json_object *root = json_object_new_object();
    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "blockchain", json_object_new_string("solana"));
    json_object_object_add(root, "network", json_object_new_string("mainnet-beta"));
    json_object_object_add(root, "address", json_object_new_string(wallet->address));

    /* Encode private key as hex */
    char priv_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(priv_hex + i * 2, 3, "%02x", wallet->private_key[i]);
    }
    json_object_object_add(root, "private_key", json_object_new_string(priv_hex));

    /* Encode public key as hex */
    char pub_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(pub_hex + i * 2, 3, "%02x", wallet->public_key[i]);
    }
    json_object_object_add(root, "public_key", json_object_new_string(pub_hex));

    json_object_object_add(root, "created_at", json_object_new_int64(time(NULL)));

    /* v0.3.0: Build file path - flat structure */
    (void)name;  // Unused in v0.3.0 flat structure
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/wallet.sol.json", wallet_dir);

    /* Write to file */
    FILE *f = fopen(filepath, "w");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open wallet file for writing: %s", filepath);
        json_object_put(root);
        return -1;
    }

    fprintf(f, "%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    fclose(f);
    json_object_put(root);

    /* Set file permissions (owner read/write only) */
#ifndef _WIN32
    chmod(filepath, 0600);
#endif

    QGP_LOG_DEBUG(LOG_TAG, "Saved Solana wallet to: %s", filepath);
    return 0;
}

int sol_wallet_load(
    const char *wallet_path,
    sol_wallet_t *wallet_out
) {
    if (!wallet_path || !wallet_out) {
        return -1;
    }

    memset(wallet_out, 0, sizeof(*wallet_out));

    /* Read file */
    FILE *f = fopen(wallet_path, "r");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open wallet file: %s", wallet_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json_str = malloc(fsize + 1);
    if (!json_str) {
        fclose(f);
        return -1;
    }

    size_t read_bytes = fread(json_str, 1, fsize, f);
    fclose(f);
    if (read_bytes != (size_t)fsize) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read wallet file: expected %ld, got %zu", fsize, read_bytes);
        free(json_str);
        return -1;
    }
    json_str[fsize] = '\0';

    /* Parse JSON */
    json_object *root = json_tokener_parse(json_str);
    free(json_str);

    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse wallet JSON");
        return -1;
    }

    /* Extract fields */
    json_object *addr_obj, *priv_obj, *pub_obj;

    if (!json_object_object_get_ex(root, "address", &addr_obj) ||
        !json_object_object_get_ex(root, "private_key", &priv_obj) ||
        !json_object_object_get_ex(root, "public_key", &pub_obj)) {
        QGP_LOG_ERROR(LOG_TAG, "Missing required fields in wallet file");
        json_object_put(root);
        return -1;
    }

    /* Copy address */
    strncpy(wallet_out->address, json_object_get_string(addr_obj), SOL_ADDRESS_SIZE);

    /* Decode private key from hex */
    const char *priv_hex = json_object_get_string(priv_obj);
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(priv_hex + i * 2, "%02x", &byte);
        wallet_out->private_key[i] = (uint8_t)byte;
    }

    /* Decode public key from hex */
    const char *pub_hex = json_object_get_string(pub_obj);
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        sscanf(pub_hex + i * 2, "%02x", &byte);
        wallet_out->public_key[i] = (uint8_t)byte;
    }

    json_object_put(root);
    return 0;
}

void sol_wallet_clear(sol_wallet_t *wallet) {
    if (wallet) {
        memset(wallet, 0, sizeof(*wallet));
    }
}

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

int sol_pubkey_to_address(
    const uint8_t pubkey[SOL_PUBLIC_KEY_SIZE],
    char *address_out
) {
    if (!pubkey || !address_out) {
        return -1;
    }

    /* Solana address is just base58-encoded public key */
    size_t encoded_len = base58_encode(pubkey, SOL_PUBLIC_KEY_SIZE, address_out);
    if (encoded_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Base58 encoding failed");
        return -1;
    }

    return 0;
}

int sol_address_to_pubkey(
    const char *address,
    uint8_t pubkey_out[SOL_PUBLIC_KEY_SIZE]
) {
    if (!address || !pubkey_out) {
        return -1;
    }

    uint8_t decoded[64];
    size_t decoded_len = base58_decode(address, decoded);

    if (decoded_len != SOL_PUBLIC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Solana address length: %zu (expected %d)",
                     decoded_len, SOL_PUBLIC_KEY_SIZE);
        return -1;
    }

    memcpy(pubkey_out, decoded, SOL_PUBLIC_KEY_SIZE);
    return 0;
}

bool sol_validate_address(const char *address) {
    if (!address) {
        return false;
    }

    size_t len = strlen(address);

    /* Solana addresses are typically 32-44 characters */
    if (len < 32 || len > 44) {
        return false;
    }

    /* Must be valid base58 characters */
    const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (size_t i = 0; i < len; i++) {
        if (!strchr(base58_chars, address[i])) {
            return false;
        }
    }

    /* Try to decode - must be exactly 32 bytes */
    uint8_t decoded[64];
    size_t decoded_len = base58_decode(address, decoded);

    return decoded_len == SOL_PUBLIC_KEY_SIZE;
}

/* ============================================================================
 * SIGNING
 * ============================================================================ */

int sol_sign_message(
    const uint8_t *message,
    size_t message_len,
    const uint8_t private_key[SOL_PRIVATE_KEY_SIZE],
    const uint8_t public_key[SOL_PUBLIC_KEY_SIZE],
    uint8_t signature_out[SOL_SIGNATURE_SIZE]
) {
    (void)public_key; /* Not needed for OpenSSL Ed25519 signing */

    if (!message || !private_key || !signature_out) {
        return -1;
    }

    /* Create Ed25519 key from private key */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL, private_key, 32
    );
    if (!pkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create Ed25519 key for signing");
        return -1;
    }

    /* Create signing context */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    size_t sig_len = SOL_SIGNATURE_SIZE;
    int ret = -1;

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(md_ctx, signature_out, &sig_len, message, message_len) == 1) {
        ret = 0;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Ed25519 signing failed: %s",
                     ERR_error_string(ERR_get_error(), NULL));
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return ret;
}

/* ============================================================================
 * RPC ENDPOINT
 * ============================================================================ */

void sol_rpc_set_endpoint(const char *endpoint) {
    if (endpoint) {
        strncpy(g_sol_rpc_endpoint, endpoint, sizeof(g_sol_rpc_endpoint) - 1);
        g_sol_rpc_endpoint[sizeof(g_sol_rpc_endpoint) - 1] = '\0';
    }
}

const char* sol_rpc_get_endpoint(void) {
    return g_sol_rpc_endpoint;
}
