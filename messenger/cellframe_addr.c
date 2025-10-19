/*
 * cellframe_addr.c - Cellframe Address Generation
 *
 * Generates Cellframe blockchain addresses from Dilithium keys
 */

#include "cellframe_addr.h"
#include "base58.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Cellframe address structure (before base58 encoding)
typedef struct {
    uint8_t addr_ver;        // Address version (always 1)
    uint64_t net_id;         // Network ID
    uint16_t sig_type;       // Signature type
    uint8_t pkey_hash[32];   // SHA3-256 hash of public key
    uint8_t checksum[32];    // SHA3-256 checksum
} __attribute__((packed)) cellframe_addr_t;

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
 * Generate Cellframe address from public key
 */
int cellframe_addr_from_pubkey(const uint8_t *pubkey, size_t pubkey_size,
                                 uint64_t net_id, char *address_out) {
    if (!pubkey || pubkey_size == 0 || !address_out) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Invalid arguments\n");
        return -1;
    }

    // Build address structure
    cellframe_addr_t addr;
    memset(&addr, 0, sizeof(addr));

    addr.addr_ver = 1;  // Current version
    addr.net_id = net_id;
    addr.sig_type = CELLFRAME_SIG_DILITHIUM;

    // Hash public key with SHA3-256
    if (sha3_256(pubkey, pubkey_size, addr.pkey_hash) != 0) {
        fprintf(stderr, "cellframe_addr_from_pubkey: Failed to hash public key\n");
        return -1;
    }

    // Calculate checksum (SHA3-256 of everything except checksum field)
    size_t data_size = sizeof(addr) - sizeof(addr.checksum);
    if (sha3_256((uint8_t*)&addr, data_size, addr.checksum) != 0) {
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
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/.dna/%s-dilithium.pqkey.pub",
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
