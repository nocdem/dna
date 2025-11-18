/*
 * cellframe_sign_minimal.c - Minimal Dilithium Signing Implementation
 *
 * Signs transactions with Dilithium MODE_1 matching Cellframe SDK exactly.
 */

#include "blockchain_sign_minimal.h"
#include "../crypto/cellframe_dilithium/cellframe_dilithium_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

// ============================================================================
// SHA3-256 IMPLEMENTATION (Using OpenSSL)
// ============================================================================

void cellframe_sha3_256(const uint8_t *data, size_t data_len, uint8_t hash[32]) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        memset(hash, 0, 32);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        memset(hash, 0, 32);
    }

    EVP_MD_CTX_free(mdctx);
}

// ============================================================================
// DAP_SIGN_T BUILDER
// ============================================================================

int cellframe_build_dap_sign_t(const uint8_t *pub_key, size_t pub_key_size,
                                 const uint8_t *signature, size_t sig_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out) {
    if (!pub_key || !signature || !dap_sign_out || !dap_sign_size_out) {
//         fprintf(stderr, "[SIGN] Invalid parameters\n");
        return -1;
    }

    // Validate public key size
    if (pub_key_size != 1184 && pub_key_size != 1196) {
//         fprintf(stderr, "[SIGN] Invalid public key size: %zu (expected 1184 or 1196)\n", pub_key_size);
        return -1;
    }

    // Validate signature size
    if (sig_size != 2044 && sig_size != 2076 && sig_size != 2096) {
//         fprintf(stderr, "[SIGN] Invalid signature size: %zu (expected 2044, 2076, or 2096)\n", sig_size);
        return -1;
    }

    // Prepare serialized public key (1196 bytes)
    uint8_t *serialized_pubkey = NULL;
    size_t serialized_pubkey_size = 1196;

    if (pub_key_size == 1196) {
        // Already serialized
        serialized_pubkey = malloc(1196);
        if (!serialized_pubkey) return -1;
        memcpy(serialized_pubkey, pub_key, 1196);
    } else {
        // Add 12-byte serialization header
        serialized_pubkey = malloc(1196);
        if (!serialized_pubkey) return -1;

        // Serialization header: [8-byte length][4-byte type]
        uint64_t len = 1196;
        uint32_t type = 1;  // Type 1 for serialized key

        memcpy(serialized_pubkey, &len, 8);
        memcpy(serialized_pubkey + 8, &type, 4);
        memcpy(serialized_pubkey + 12, pub_key, 1184);
    }

    // Prepare serialized signature (2096 bytes)
    uint8_t *serialized_sig = NULL;
    size_t serialized_sig_size = 2096;

    if (sig_size == 2096) {
        // Already serialized
        serialized_sig = malloc(2096);
        if (!serialized_sig) {
            free(serialized_pubkey);
            return -1;
        }
        memcpy(serialized_sig, signature, 2096);
    } else {
        // Add 20-byte serialization wrapper
        serialized_sig = malloc(2096);
        if (!serialized_sig) {
            free(serialized_pubkey);
            return -1;
        }

        // Wrapper: [8-byte total_len][4-byte type][8-byte sig_len][payload]
        uint64_t total_len = 2096;
        uint32_t wrapper_type = 1;  // Type 1 for serialized signature
        uint64_t payload_len = (sig_size == 2076) ? 2076 : 2076;  // ATTACHED signature length

        memcpy(serialized_sig, &total_len, 8);
        memcpy(serialized_sig + 8, &wrapper_type, 4);
        memcpy(serialized_sig + 12, &payload_len, 8);

        if (sig_size == 2076) {
            // Already ATTACHED, just copy
            memcpy(serialized_sig + 20, signature, 2076);
        } else {
            // Detached signature (2044 bytes)
            // Need to convert to ATTACHED by appending 32-byte message
            // For transaction signing, the "message" is the hash (32 bytes)
            memcpy(serialized_sig + 20, signature, 2044);
            memset(serialized_sig + 20 + 2044, 0, 32);  // Zero-filled message placeholder
        }
    }

    // Build dap_sign_t structure
    // Total: 14 (header) + 1196 (pubkey) + 2096 (sig) = 3306 bytes
    size_t total_size = 14 + 1196 + 2096;
    uint8_t *dap_sign = malloc(total_size);
    if (!dap_sign) {
        free(serialized_pubkey);
        free(serialized_sig);
        return -1;
    }

    // Build header (14 bytes)
    uint32_t sig_type = CELLFRAME_SIG_DILITHIUM;  // 0x0102
    uint8_t hash_type = 0x01;  // SHA3-256
    uint8_t padding = 0x00;
    uint32_t sign_size = 2096;
    uint32_t sign_pkey_size = 1196;

    size_t offset = 0;
    memcpy(dap_sign + offset, &sig_type, 4); offset += 4;
    memcpy(dap_sign + offset, &hash_type, 1); offset += 1;
    memcpy(dap_sign + offset, &padding, 1); offset += 1;
    memcpy(dap_sign + offset, &sign_size, 4); offset += 4;
    memcpy(dap_sign + offset, &sign_pkey_size, 4); offset += 4;

    // Append public key (1196 bytes)
    memcpy(dap_sign + offset, serialized_pubkey, 1196); offset += 1196;

    // Append signature (2096 bytes)
    memcpy(dap_sign + offset, serialized_sig, 2096); offset += 2096;

    free(serialized_pubkey);
    free(serialized_sig);

    *dap_sign_out = dap_sign;
    *dap_sign_size_out = total_size;

//     fprintf(stderr, "[SIGN] Built dap_sign_t: %zu bytes (14 + 1196 + 2096)\n", total_size);
    return 0;
}

// ============================================================================
// TRANSACTION SIGNING
// ============================================================================

int cellframe_sign_transaction(const uint8_t *tx_data, size_t tx_size,
                                 const uint8_t *priv_key, size_t priv_key_size,
                                 const uint8_t *pub_key, size_t pub_key_size,
                                 uint8_t **dap_sign_out, size_t *dap_sign_size_out) {
    if (!tx_data || !priv_key || !pub_key || !dap_sign_out || !dap_sign_size_out) {
//         fprintf(stderr, "[SIGN] Invalid parameters\n");
        return -1;
    }

//     fprintf(stderr, "[SIGN] Signing transaction: %zu bytes\n", tx_size);
//     fprintf(stderr, "[SIGN] Private key size: %zu bytes\n", priv_key_size);
//     fprintf(stderr, "[SIGN] Public key size: %zu bytes\n", pub_key_size);

    // DEBUG: Check tx_items_size field
    if (tx_size >= 12) {
        uint32_t tx_items_size;
        memcpy(&tx_items_size, tx_data + 8, 4);
//         fprintf(stderr, "[SIGN] DEBUG: tx_items_size in signing data = %u (0x%08x)\n", tx_items_size, tx_items_size);
        if (tx_items_size != 0) {
//             fprintf(stderr, "[SIGN] ❌ ERROR: tx_items_size should be 0 when signing, but is %u!\n", tx_items_size);
        } else {
//             fprintf(stderr, "[SIGN] ✅ CORRECT: tx_items_size is 0\n");
        }

#ifdef DEBUG_BLOCKCHAIN_SIGNING
        // Debug: Save signing data to file for analysis
        FILE *f_sign = fopen("/tmp/signing_data_our.bin", "wb");
        if (f_sign) {
            fwrite(tx_data, 1, tx_size, f_sign);
            fclose(f_sign);
            fprintf(stderr, "[SIGN] DEBUG: Saved signing data to /tmp/signing_data_our.bin\n");
        }
#endif
    }

    // Step 1: Hash transaction
    uint8_t tx_hash[32];
    cellframe_sha3_256(tx_data, tx_size, tx_hash);

//     fprintf(stderr, "[SIGN] Transaction hash (SHA3-256): ");
    for (int i = 0; i < 32; i++) {
        fprintf(stderr, "%02x", tx_hash[i]);
    }
    fprintf(stderr, "\n");

    // Step 2: Extract raw private key (skip serialization header if present)
    const uint8_t *raw_priv_key = priv_key;
    size_t raw_priv_key_size = priv_key_size;

    if (priv_key_size >= 12) {
        // Check for serialization header [8-byte length][4-byte type]
        uint64_t serialized_len;
        memcpy(&serialized_len, priv_key, 8);

        if (serialized_len == priv_key_size) {
            // Has serialization header, skip it
            raw_priv_key = priv_key + 12;
            raw_priv_key_size = priv_key_size - 12;
            // fprintf(stderr, "[SIGN] Detected serialization header, using raw key: %zu bytes\n",
            //         raw_priv_key_size);
        }
    }

    // Step 3: Sign hash with Dilithium
    size_t sig_len = 4096;  // Max size
    uint8_t *signature = malloc(sig_len);
    if (!signature) {
//         fprintf(stderr, "[SIGN] Memory allocation failed\n");
        return -1;
    }

    int ret = pqcrystals_cellframe_dilithium_signature(
        signature, &sig_len,
        tx_hash, sizeof(tx_hash),
        NULL, 0,  // No context
        raw_priv_key
    );

    if (ret != 0) {
//         fprintf(stderr, "[SIGN] Dilithium signing failed: %d\n", ret);
        free(signature);
        return -1;
    }

//     fprintf(stderr, "[SIGN] Dilithium signature created: %zu bytes\n", sig_len);

    // Step 4: Extract raw public key (skip serialization header if present)
    const uint8_t *raw_pub_key = pub_key;
    size_t raw_pub_key_size = pub_key_size;

    if (pub_key_size >= 12) {
        uint64_t serialized_len;
        memcpy(&serialized_len, pub_key, 8);

        if (serialized_len == pub_key_size) {
            raw_pub_key = pub_key + 12;
            raw_pub_key_size = pub_key_size - 12;
//             fprintf(stderr, "[SIGN] Using raw public key: %zu bytes\n", raw_pub_key_size);
        }
    }

    // Step 5: Build dap_sign_t structure
    // Note: We pass the RAW keys, and cellframe_build_dap_sign_t will add headers
    ret = cellframe_build_dap_sign_t(
        raw_pub_key, raw_pub_key_size,
        signature, sig_len,
        dap_sign_out, dap_sign_size_out
    );

    free(signature);

    if (ret != 0) {
//         fprintf(stderr, "[SIGN] Failed to build dap_sign_t\n");
        return -1;
    }

    // fprintf(stderr, "[SIGN] Transaction signed successfully: dap_sign_t = %zu bytes\n",
    //         *dap_sign_size_out);

    return 0;
}
