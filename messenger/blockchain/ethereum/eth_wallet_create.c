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

void eth_wallet_clear(eth_wallet_t *wallet) {
    if (wallet) {
        qgp_secure_memzero(wallet, sizeof(*wallet));
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

/* v0.9.17: Wallet file save/load/get_address removed — seed-based derivation only */
