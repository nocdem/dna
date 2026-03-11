/*
 * cellframe_wallet_create.c - Cellframe Wallet Derivation
 *
 * Derives Cellframe wallet keys and addresses from deterministic seeds.
 * No wallet files are created — all operations are in-memory.
 */

#include "cellframe_wallet_create.h"
#include "cellframe_addr.h"
#include "cellframe_minimal.h"
#include "crypto/sign/cellframe_dilithium/dilithium_params.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "WALLET"

/* Serialize Dilithium key with length+kind header (Cellframe format) */
static void serialize_dilithium_key(
    const uint8_t *key_data,
    size_t key_size,
    uint32_t kind,
    uint8_t *out,
    size_t *out_size
) {
    /* Total serialized length = 8 (length field) + 4 (kind) + key_size */
    uint64_t total_len = 8 + 4 + key_size;

    /* Write length (little-endian) */
    memcpy(out, &total_len, 8);

    /* Write kind (little-endian) */
    memcpy(out + 8, &kind, 4);

    /* Write key data */
    memcpy(out + 12, key_data, key_size);

    *out_size = (size_t)total_len;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int cellframe_derive_seed_from_mnemonic(
    const char *mnemonic,
    uint8_t seed_out[CF_WALLET_SEED_SIZE]
) {
    if (!mnemonic || !seed_out) {
        return -1;
    }

    /*
     * Cellframe wallet app derivation (NOT BIP39!):
     * 1. Take mnemonic words as space-separated string
     * 2. Apply SHA3-256 (Keccak-256) to the string
     * 3. Use resulting 32 bytes as seed
     *
     * Source: cellframe-wallet/cpp-cellframe/SDKInterface/DapCommonInterface.cpp
     * Uses dap_hash_fast() which is SHA3-256/Keccak-256
     */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create SHA3-256 context\n");
        return -1;
    }

    int ret = -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init SHA3-256\n");
        goto cleanup;
    }

    if (EVP_DigestUpdate(mdctx, mnemonic, strlen(mnemonic)) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update SHA3-256\n");
        goto cleanup;
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, seed_out, &hash_len) != 1 || hash_len != 32) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to finalize SHA3-256\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int cellframe_wallet_derive_address(
    const uint8_t seed[CF_WALLET_SEED_SIZE],
    char *address_out
) {
    if (!seed || !address_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to cellframe_wallet_derive_address\n");
        return -1;
    }

    int result = -1;
    dilithium_public_key_t pubkey = {0};
    dilithium_private_key_t privkey = {0};
    uint8_t *serialized_pubkey = NULL;

    /* Generate Dilithium MODE_1 keypair from 32-byte seed */
    if (dilithium_crypto_sign_keypair(&pubkey, &privkey, MODE_1, seed, CF_WALLET_SEED_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate Dilithium keypair\n");
        goto cleanup;
    }

    /* Verify key sizes match expectations */
    if (pubkey.kind != MODE_1) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected key kind\n");
        goto cleanup;
    }

    /* Allocate buffer for serialized public key */
    size_t serialized_pubkey_size = 8 + 4 + CF_DILITHIUM_PUBLICKEYBYTES;
    serialized_pubkey = malloc(serialized_pubkey_size);
    if (!serialized_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Serialize public key */
    size_t actual_pubkey_size;
    serialize_dilithium_key(pubkey.data, CF_DILITHIUM_PUBLICKEYBYTES,
                           CF_DILITHIUM_KIND_MODE_1,
                           serialized_pubkey, &actual_pubkey_size);

    /* Generate address from serialized public key */
    if (cellframe_addr_from_pubkey(serialized_pubkey, actual_pubkey_size,
                                   CELLFRAME_NET_BACKBONE, address_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate address\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    /* Securely clear sensitive data */
    if (serialized_pubkey) {
        memset(serialized_pubkey, 0, serialized_pubkey_size);
        free(serialized_pubkey);
    }

    /* Clean up Dilithium keys (private key was generated but not needed) */
    if (privkey.data) {
        dilithium_private_key_delete(&privkey);
    }
    if (pubkey.data) {
        dilithium_public_key_delete(&pubkey);
    }

    return result;
}

int cellframe_wallet_derive_keys(
    const uint8_t seed[CF_WALLET_SEED_SIZE],
    cellframe_wallet_t **wallet_out
) {
    if (!seed || !wallet_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to cellframe_wallet_derive_keys\n");
        return -1;
    }

    int result = -1;
    dilithium_public_key_t pubkey = {0};
    dilithium_private_key_t privkey = {0};
    cellframe_wallet_t *wallet = NULL;
    uint8_t *serialized_pubkey = NULL;
    uint8_t *serialized_privkey = NULL;

    /* Allocate wallet structure */
    wallet = calloc(1, sizeof(cellframe_wallet_t));
    if (!wallet) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate wallet\n");
        return -1;
    }

    /* Generate Dilithium MODE_1 keypair from 32-byte seed */
    if (dilithium_crypto_sign_keypair(&pubkey, &privkey, MODE_1, seed, CF_WALLET_SEED_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate Dilithium keypair\n");
        goto cleanup;
    }

    /* Verify key sizes match expectations */
    if (pubkey.kind != MODE_1 || privkey.kind != MODE_1) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected key kind\n");
        goto cleanup;
    }

    /* Allocate buffers for serialized keys */
    /* Serialized size = 8 (length) + 4 (kind) + key_size */
    size_t serialized_pubkey_size = 8 + 4 + CF_DILITHIUM_PUBLICKEYBYTES;
    size_t serialized_privkey_size = 8 + 4 + CF_DILITHIUM_SECRETKEYBYTES;

    serialized_pubkey = malloc(serialized_pubkey_size);
    serialized_privkey = malloc(serialized_privkey_size);

    if (!serialized_pubkey || !serialized_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Serialize keys */
    size_t actual_pubkey_size, actual_privkey_size;
    serialize_dilithium_key(pubkey.data, CF_DILITHIUM_PUBLICKEYBYTES,
                           CF_DILITHIUM_KIND_MODE_1,
                           serialized_pubkey, &actual_pubkey_size);

    serialize_dilithium_key(privkey.data, CF_DILITHIUM_SECRETKEYBYTES,
                           CF_DILITHIUM_KIND_MODE_1,
                           serialized_privkey, &actual_privkey_size);

    /* Generate address from serialized public key */
    if (cellframe_addr_from_pubkey(serialized_pubkey, actual_pubkey_size,
                                   CELLFRAME_NET_BACKBONE, wallet->address) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate address\n");
        goto cleanup;
    }

    /* Populate wallet structure */
    strncpy(wallet->name, "derived", WALLET_NAME_MAX - 1);
    wallet->status = WALLET_STATUS_UNPROTECTED;
    wallet->sig_type = WALLET_SIG_DILITHIUM;
    wallet->deprecated = false;

    /* Transfer serialized keys to wallet (ownership transferred) */
    wallet->public_key = serialized_pubkey;
    wallet->public_key_size = actual_pubkey_size;
    wallet->private_key = serialized_privkey;
    wallet->private_key_size = actual_privkey_size;

    /* Prevent double-free */
    serialized_pubkey = NULL;
    serialized_privkey = NULL;

    *wallet_out = wallet;
    wallet = NULL; /* Prevent cleanup from freeing */
    result = 0;

    QGP_LOG_DEBUG(LOG_TAG, "Derived wallet keys, address: %s", (*wallet_out)->address);

cleanup:
    /* Securely clear any remaining buffers */
    if (serialized_privkey) {
        qgp_secure_memzero(serialized_privkey, serialized_privkey_size);
        free(serialized_privkey);
    }
    if (serialized_pubkey) {
        qgp_secure_memzero(serialized_pubkey, serialized_pubkey_size);
        free(serialized_pubkey);
    }

    /* Clean up Dilithium keys */
    if (privkey.data) {
        dilithium_private_key_delete(&privkey);
    }
    if (pubkey.data) {
        dilithium_public_key_delete(&pubkey);
    }

    /* Free wallet on error */
    if (wallet) {
        free(wallet);
    }

    return result;
}

/* ============================================================================
 * WALLET CLEANUP
 * ============================================================================ */

void wallet_free(cellframe_wallet_t *wallet) {
    if (!wallet) {
        return;
    }

    if (wallet->public_key) {
        qgp_secure_memzero(wallet->public_key, wallet->public_key_size);
        free(wallet->public_key);
    }

    if (wallet->private_key) {
        qgp_secure_memzero(wallet->private_key, wallet->private_key_size);
        free(wallet->private_key);
    }

    free(wallet);
}
