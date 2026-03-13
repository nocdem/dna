/**
 * @file sol_wallet.c
 * @brief Solana Wallet Implementation
 *
 * Creates Solana wallets using SLIP-10 Ed25519 derivation from BIP39 seeds.
 *
 * @author DNA Connect Team
 * @date 2025-12-09
 */

#include "sol_wallet.h"
#include "crypto/utils/base58.h"
#include "crypto/sign/ed25519_sign.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
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
    SOL_RPC_MAINNET_FALLBACK1
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

/* ed25519_pubkey_from_private() is now in crypto/sign/ed25519_sign.c */

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

void sol_wallet_clear(sol_wallet_t *wallet) {
    if (wallet) {
        qgp_secure_memzero(wallet, sizeof(*wallet));
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
    (void)public_key; /* Not needed for Ed25519 signing */

    return ed25519_sign(private_key, message, message_len, signature_out);
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
