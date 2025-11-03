/*
 * cellframe_addr.c - Cellframe Address Generation
 *
 * Generates Cellframe blockchain addresses from Dilithium keys
 */

#include "cellframe_addr.h"
#include "cellframe_minimal.h"  // For cellframe_addr_t (77 bytes)
#include "base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/**
 * Calculate SHA3-256 hash using OpenSSL
 */
static int sha3_256(const uint8_t *data, size_t data_len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int hash_len = 32;
    if (EVP_DigestFinal_ex(ctx, hash_out, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Generate Cellframe address from serialized public key
 *
 * NOTE: pubkey should point to ALREADY SERIALIZED public key data
 * Cellframe serialization format:
 * [8 bytes: total length] + [4 bytes: kind] + [N bytes: public key data]
 *
 * The wallet file stores this serialized format starting at offset 0x86.
 * We hash this data AS-IS, using the length specified in the first 8 bytes.
 */
int cellframe_addr_from_pubkey(const uint8_t *pubkey, size_t pubkey_size,
                                 uint64_t net_id, char *address_out) {
    if (!pubkey || pubkey_size < 12 || !address_out) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Invalid arguments\n");
        return -1;
    }

    // Build address structure (77 bytes total - wire format with padding)
    cellframe_addr_t addr;
    memset(&addr, 0, sizeof(addr));

    addr.addr_ver = 1;  // 1 for current version

    // Network ID (little-endian uint64_t)
    addr.net_id.uint64 = net_id;

    // Signature type (0x0102 for Dilithium)
    addr.sig_type.type = CELLFRAME_SIG_DILITHIUM;

    // Hash the serialized public key with SHA3-256
    if (sha3_256(pubkey, pubkey_size, addr.data.hash) != 0) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Failed to hash public key\n");
        return -1;
    }

    // Calculate checksum (SHA3-256 of everything except checksum field)
    size_t data_size = sizeof(addr) - sizeof(addr.checksum);  // 45 bytes (77 - 32)
    if (sha3_256((uint8_t*)&addr, data_size, addr.checksum.raw) != 0) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Failed to calculate checksum\n");
        return -1;
    }

    // Base58 encode the entire structure
    size_t encoded_len = base58_encode(&addr, sizeof(addr), address_out);
    if (encoded_len == 0) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Base58 encoding failed\n");
        return -1;
    }

    return 0;
}

/**
 * Get Cellframe address for current DNA identity
 */
int cellframe_addr_for_identity(const char *identity, uint64_t net_id, char *address_out) {
    if (!identity || !address_out) {
        fprintf(stderr, "cellframe_addr_for_identity: Invalid arguments\n");
        return -1;
    }

    // Build path to public key file
    const char *home = getenv("HOME");
    if (!home) {
        home = "/root";
    }

    char pubkey_path[512];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/.dna/%s-dilithium3.pqkey.pub",
             home, identity);

    // Read public key file
    FILE *fp = fopen(pubkey_path, "rb");
    if (!fp) {
        fprintf(stderr, "cellframe_addr_for_identity: Cannot open public key file: %s\n",
                pubkey_path);
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 100000) {
        fprintf(stderr, "cellframe_addr_for_identity: Invalid file size: %ld\n", file_size);
        fclose(fp);
        return -1;
    }

    // Read public key data
    uint8_t *pubkey = malloc(file_size);
    if (!pubkey) {
        fprintf(stderr, "cellframe_addr_for_identity: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    if (fread(pubkey, 1, file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "cellframe_addr_for_identity: Failed to read public key\n");
        free(pubkey);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    // Generate address
    int ret = cellframe_addr_from_pubkey(pubkey, file_size, net_id, address_out);

    // Clean up
    memset(pubkey, 0, file_size);
    free(pubkey);

    return ret;
}

/**
 * Convert binary Cellframe address to base58 string
 */
int cellframe_addr_to_str(const void *addr, char *str_out, size_t str_max) {
    if (!addr || !str_out || str_max < CELLFRAME_ADDR_STR_MAX) {
        return -1;
    }

    // Base58 encode the binary address (49 bytes - matches Cellframe SDK)
    size_t encoded_len = base58_encode(addr, sizeof(cellframe_addr_t), str_out);
    if (encoded_len == 0 || encoded_len >= str_max) {
        return -1;
    }

    return 0;
}

/**
 * Parse base58 string to binary Cellframe address
 */
int cellframe_addr_from_str(const char *str, void *addr_out) {
    if (!str || !addr_out) {
        return -1;
    }

    // Decode base58 string to binary (should be 49 bytes - matches Cellframe SDK)
    size_t decoded_len = base58_decode(str, (uint8_t *)addr_out);
    if (decoded_len != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "cellframe_addr_from_str: Invalid address length: %zu (expected %zu)\n",
                decoded_len, sizeof(cellframe_addr_t));
        return -1;
    }

    return 0;
}
