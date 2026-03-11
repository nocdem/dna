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
#include "crypto/key/bip32/bip32.h"
#include "crypto/hash/keccak256.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
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

/* RPC endpoints with fallbacks */
const char *g_trx_rpc_endpoints[] = {
    TRX_RPC_ENDPOINT_DEFAULT,
    TRX_RPC_ENDPOINT_FALLBACK1,
    TRX_RPC_ENDPOINT_FALLBACK2
};

/* Current RPC endpoint (can be overridden) */
static char g_trx_rpc_endpoint[256] = TRX_RPC_ENDPOINT_DEFAULT;

/* Index of current/last working endpoint */
int g_trx_rpc_current_idx = 0;

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

void trx_wallet_clear(trx_wallet_t *wallet) {
    if (wallet) {
        qgp_secure_memzero(wallet, sizeof(*wallet));
    }
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
