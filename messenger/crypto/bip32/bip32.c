/**
 * @file bip32.c
 * @brief BIP-32 Hierarchical Deterministic Key Derivation Implementation
 *
 * Implements BIP-32 HD wallet key derivation for secp256k1 curve.
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#include "bip32.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <secp256k1.h>
#include "../utils/qgp_log.h"
#include "../utils/qgp_platform.h"

#define LOG_TAG "BIP32"

/* BIP-32 master key derivation uses this as HMAC key */
static const char *BIP32_SEED_KEY = "Bitcoin seed";

/* Global secp256k1 context - created once */
static secp256k1_context *g_secp256k1_ctx = NULL;

/**
 * Initialize secp256k1 context (lazy initialization)
 */
static secp256k1_context* get_secp256k1_context(void) {
    if (g_secp256k1_ctx == NULL) {
        g_secp256k1_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
        );
        if (g_secp256k1_ctx == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create secp256k1 context");
        }
    }
    return g_secp256k1_ctx;
}

/**
 * Compute HMAC-SHA512
 */
static int hmac_sha512(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t output[64]
) {
    unsigned int out_len = 64;

    if (HMAC(EVP_sha512(), key, (int)key_len, data, data_len, output, &out_len) == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA512 failed");
        return -1;
    }

    if (out_len != 64) {
        QGP_LOG_ERROR(LOG_TAG, "HMAC-SHA512 output length mismatch: %u", out_len);
        return -1;
    }

    return 0;
}

/**
 * Compute SHA256 hash
 */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t output[32]) {
    SHA256(data, len, output);
}

/**
 * Compute RIPEMD160(SHA256(data)) - used for fingerprint
 */
static void hash160(const uint8_t *data, size_t len, uint8_t output[20]) {
    uint8_t sha256_out[32];
    unsigned int ripemd_len = 20;
    SHA256(data, len, sha256_out);
    EVP_Digest(sha256_out, 32, output, &ripemd_len, EVP_ripemd160(), NULL);
}

/**
 * Check if private key is valid for secp256k1
 * Must be > 0 and < curve order
 */
static int is_valid_private_key(const uint8_t key[32]) {
    secp256k1_context *ctx = get_secp256k1_context();
    if (ctx == NULL) return 0;

    return secp256k1_ec_seckey_verify(ctx, key);
}

/**
 * Add two 256-bit numbers modulo curve order
 * result = (a + b) mod n
 */
static int add_private_keys(
    const uint8_t a[32],
    const uint8_t b[32],
    uint8_t result[32]
) {
    secp256k1_context *ctx = get_secp256k1_context();
    if (ctx == NULL) return -1;

    /* Copy a to result */
    memcpy(result, a, 32);

    /* Add b to result (modulo curve order) */
    if (secp256k1_ec_seckey_tweak_add(ctx, result, b) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1_ec_seckey_tweak_add failed");
        return -1;
    }

    return 0;
}

/**
 * Get compressed public key from private key
 */
static int get_compressed_pubkey(const uint8_t privkey[32], uint8_t pubkey[33]) {
    secp256k1_context *ctx = get_secp256k1_context();
    if (ctx == NULL) return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, privkey) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1_ec_pubkey_create failed");
        return -1;
    }

    size_t len = 33;
    if (secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &pk, SECP256K1_EC_COMPRESSED) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1_ec_pubkey_serialize failed");
        return -1;
    }

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int bip32_master_key_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    bip32_extended_key_t *master_out
) {
    if (!seed || seed_len == 0 || !master_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to bip32_master_key_from_seed");
        return -1;
    }

    /* HMAC-SHA512(key="Bitcoin seed", data=seed) */
    uint8_t hmac_output[64];
    if (hmac_sha512(
            (const uint8_t *)BIP32_SEED_KEY,
            strlen(BIP32_SEED_KEY),
            seed,
            seed_len,
            hmac_output) != 0) {
        return -1;
    }

    /* First 32 bytes = private key (IL) */
    memcpy(master_out->private_key, hmac_output, 32);

    /* Last 32 bytes = chain code (IR) */
    memcpy(master_out->chain_code, hmac_output + 32, 32);

    /* Verify private key is valid */
    if (!is_valid_private_key(master_out->private_key)) {
        QGP_LOG_ERROR(LOG_TAG, "Derived master key is invalid - extremely rare, try different seed");
        qgp_secure_memzero(master_out, sizeof(*master_out));
        qgp_secure_memzero(hmac_output, sizeof(hmac_output));
        return -1;
    }

    /* Master key metadata */
    master_out->depth = 0;
    master_out->child_index = 0;
    memset(master_out->parent_fingerprint, 0, 4);

    /* Clear intermediate data */
    qgp_secure_memzero(hmac_output, sizeof(hmac_output));

    QGP_LOG_DEBUG(LOG_TAG, "Master key derived from seed");
    return 0;
}

int bip32_derive_hardened(
    const bip32_extended_key_t *parent,
    uint32_t index,
    bip32_extended_key_t *child_out
) {
    if (!parent || !child_out) {
        return -1;
    }

    /* Add hardened flag to index */
    uint32_t hardened_index = index | BIP32_HARDENED_OFFSET;

    /* Data = 0x00 || parent_private_key || index (big-endian) */
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent->private_key, 32);
    data[33] = (hardened_index >> 24) & 0xFF;
    data[34] = (hardened_index >> 16) & 0xFF;
    data[35] = (hardened_index >> 8) & 0xFF;
    data[36] = hardened_index & 0xFF;

    /* HMAC-SHA512(key=chain_code, data=data) */
    uint8_t hmac_output[64];
    if (hmac_sha512(parent->chain_code, 32, data, 37, hmac_output) != 0) {
        qgp_secure_memzero(data, sizeof(data));
        return -1;
    }

    /* Clear sensitive data */
    qgp_secure_memzero(data, sizeof(data));

    /* Child private key = (IL + parent_key) mod n */
    if (add_private_keys(parent->private_key, hmac_output, child_out->private_key) != 0) {
        qgp_secure_memzero(hmac_output, sizeof(hmac_output));
        return -1;
    }

    /* Verify child key is valid */
    if (!is_valid_private_key(child_out->private_key)) {
        QGP_LOG_ERROR(LOG_TAG, "Derived child key is invalid - try next index");
        qgp_secure_memzero(hmac_output, sizeof(hmac_output));
        qgp_secure_memzero(child_out, sizeof(*child_out));
        return -1;
    }

    /* Child chain code = IR */
    memcpy(child_out->chain_code, hmac_output + 32, 32);

    /* Metadata */
    child_out->depth = parent->depth + 1;
    child_out->child_index = hardened_index;

    /* Parent fingerprint = first 4 bytes of HASH160(parent_pubkey) */
    uint8_t parent_pubkey[33];
    if (get_compressed_pubkey(parent->private_key, parent_pubkey) == 0) {
        uint8_t hash160_out[20];
        hash160(parent_pubkey, 33, hash160_out);
        memcpy(child_out->parent_fingerprint, hash160_out, 4);
        qgp_secure_memzero(hash160_out, sizeof(hash160_out));
    } else {
        memset(child_out->parent_fingerprint, 0, 4);
    }

    qgp_secure_memzero(hmac_output, sizeof(hmac_output));
    qgp_secure_memzero(parent_pubkey, sizeof(parent_pubkey));

    return 0;
}

int bip32_derive_normal(
    const bip32_extended_key_t *parent,
    uint32_t index,
    bip32_extended_key_t *child_out
) {
    if (!parent || !child_out) {
        return -1;
    }

    /* Index must not have hardened flag */
    if (index >= BIP32_HARDENED_OFFSET) {
        QGP_LOG_ERROR(LOG_TAG, "Index has hardened flag - use bip32_derive_hardened");
        return -1;
    }

    /* Get parent public key (compressed) */
    uint8_t parent_pubkey[33];
    if (get_compressed_pubkey(parent->private_key, parent_pubkey) != 0) {
        return -1;
    }

    /* Data = parent_pubkey || index (big-endian) */
    uint8_t data[37];
    memcpy(data, parent_pubkey, 33);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    /* HMAC-SHA512(key=chain_code, data=data) */
    uint8_t hmac_output[64];
    if (hmac_sha512(parent->chain_code, 32, data, 37, hmac_output) != 0) {
        qgp_secure_memzero(data, sizeof(data));
        qgp_secure_memzero(parent_pubkey, sizeof(parent_pubkey));
        return -1;
    }

    /* Child private key = (IL + parent_key) mod n */
    if (add_private_keys(parent->private_key, hmac_output, child_out->private_key) != 0) {
        qgp_secure_memzero(hmac_output, sizeof(hmac_output));
        qgp_secure_memzero(data, sizeof(data));
        qgp_secure_memzero(parent_pubkey, sizeof(parent_pubkey));
        return -1;
    }

    /* Verify child key is valid */
    if (!is_valid_private_key(child_out->private_key)) {
        QGP_LOG_ERROR(LOG_TAG, "Derived child key is invalid - try next index");
        qgp_secure_memzero(hmac_output, sizeof(hmac_output));
        qgp_secure_memzero(data, sizeof(data));
        qgp_secure_memzero(parent_pubkey, sizeof(parent_pubkey));
        qgp_secure_memzero(child_out, sizeof(*child_out));
        return -1;
    }

    /* Child chain code = IR */
    memcpy(child_out->chain_code, hmac_output + 32, 32);

    /* Metadata */
    child_out->depth = parent->depth + 1;
    child_out->child_index = index;

    /* Parent fingerprint = first 4 bytes of HASH160(parent_pubkey) */
    uint8_t hash160_out[20];
    hash160(parent_pubkey, 33, hash160_out);
    memcpy(child_out->parent_fingerprint, hash160_out, 4);

    /* Clear sensitive data */
    qgp_secure_memzero(hmac_output, sizeof(hmac_output));
    qgp_secure_memzero(data, sizeof(data));
    qgp_secure_memzero(parent_pubkey, sizeof(parent_pubkey));
    qgp_secure_memzero(hash160_out, sizeof(hash160_out));

    return 0;
}

int bip32_derive_path(
    const uint8_t *seed,
    size_t seed_len,
    const char *path,
    bip32_extended_key_t *key_out
) {
    if (!seed || seed_len == 0 || !path || !key_out) {
        return -1;
    }

    /* Path must start with 'm' or 'M' */
    if (path[0] != 'm' && path[0] != 'M') {
        QGP_LOG_ERROR(LOG_TAG, "Path must start with 'm': %s", path);
        return -1;
    }

    /* Derive master key */
    bip32_extended_key_t current;
    if (bip32_master_key_from_seed(seed, seed_len, &current) != 0) {
        return -1;
    }

    /* Parse and derive path components */
    const char *p = path + 1;  /* Skip 'm' */

    while (*p != '\0') {
        /* Skip separator */
        if (*p == '/') {
            p++;
            continue;
        }

        /* Parse index */
        char *endptr;
        unsigned long index = strtoul(p, &endptr, 10);

        if (endptr == p) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid path component at: %s", p);
            bip32_clear_key(&current);
            return -1;
        }

        if (index > 0x7FFFFFFF) {
            QGP_LOG_ERROR(LOG_TAG, "Index too large: %lu", index);
            bip32_clear_key(&current);
            return -1;
        }

        /* Check for hardened indicator */
        int hardened = 0;
        if (*endptr == '\'' || *endptr == 'h' || *endptr == 'H') {
            hardened = 1;
            endptr++;
        }

        /* Derive child */
        bip32_extended_key_t child;
        int result;

        if (hardened) {
            result = bip32_derive_hardened(&current, (uint32_t)index, &child);
        } else {
            result = bip32_derive_normal(&current, (uint32_t)index, &child);
        }

        if (result != 0) {
            bip32_clear_key(&current);
            return -1;
        }

        /* Move to child */
        bip32_clear_key(&current);
        memcpy(&current, &child, sizeof(current));
        qgp_secure_memzero(&child, sizeof(child));

        p = endptr;
    }

    /* Copy result */
    memcpy(key_out, &current, sizeof(*key_out));
    bip32_clear_key(&current);

    return 0;
}

int bip32_derive_ethereum(
    const uint8_t *seed,
    size_t seed_len,
    bip32_extended_key_t *key_out
) {
    /* BIP-44 Ethereum path: m/44'/60'/0'/0/0 */
    return bip32_derive_path(seed, seed_len, "m/44'/60'/0'/0/0", key_out);
}

int bip32_get_public_key(
    const bip32_extended_key_t *key,
    uint8_t pubkey_out[65]
) {
    if (!key || !pubkey_out) {
        return -1;
    }

    secp256k1_context *ctx = get_secp256k1_context();
    if (ctx == NULL) return -1;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, key->private_key) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1_ec_pubkey_create failed");
        return -1;
    }

    size_t len = 65;
    if (secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &len, &pk, SECP256K1_EC_UNCOMPRESSED) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1_ec_pubkey_serialize failed");
        return -1;
    }

    return 0;
}

int bip32_get_public_key_compressed(
    const bip32_extended_key_t *key,
    uint8_t pubkey_out[33]
) {
    if (!key || !pubkey_out) {
        return -1;
    }

    return get_compressed_pubkey(key->private_key, pubkey_out);
}

void bip32_clear_key(bip32_extended_key_t *key) {
    if (key) {
        qgp_secure_memzero(key, sizeof(*key));
    }
}
