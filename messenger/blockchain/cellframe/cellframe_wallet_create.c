/*
 * cellframe_wallet_create.c - Cellframe Wallet Creation
 *
 * Creates CF20 .dwallet files from deterministic seeds.
 */

#include "cellframe_wallet_create.h"
#include "cellframe_addr.h"
#include "cellframe_minimal.h"
#include "../../crypto/cellframe_dilithium/dilithium_params.h"
#include "../../crypto/kem/fips202_kyber.h"  /* For shake256 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir_portable(path) _mkdir(path)
#else
#define mkdir_portable(path) mkdir(path, 0700)
#endif

/* BIP39 master seed size */
#define BIP39_SEED_SIZE 64

/* Cert header for unprotected wallets */
static const uint8_t CERT_HEADER[8] = {
    0x00, 0x00, 0x00, 0x00,  /* cert magic/version */
    0x01, 0x00, 0x00, 0x00   /* cert type */
};

/* Padding before serialized keys in cert data (0x59 = 89 bytes) */
#define CERT_KEY_OFFSET 0x59

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

/**
 * Serialize a Dilithium key with length and kind header
 *
 * Format: [8-byte length][4-byte kind][N-byte key data]
 *
 * @param key_data      Raw key bytes
 * @param key_size      Size of raw key (1184 for pubkey, 2800 for privkey)
 * @param kind          Dilithium kind (MODE_1 = 1)
 * @param out           Output buffer (must be key_size + 12 bytes)
 * @param out_size      Output: total serialized size
 */
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

/**
 * Write .dwallet file
 *
 * @param path              Full path to output file
 * @param wallet_name       Wallet name (stored in file)
 * @param serialized_pubkey Serialized public key (with header)
 * @param pubkey_size       Size of serialized public key
 * @param serialized_privkey Serialized private key (with header)
 * @param privkey_size      Size of serialized private key
 * @return 0 on success, -1 on error
 */
static int write_dwallet_file(
    const char *path,
    const char *wallet_name,
    const uint8_t *serialized_pubkey,
    size_t pubkey_size,
    const uint8_t *serialized_privkey,
    size_t privkey_size
) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "[WALLET] Failed to create wallet file: %s\n", path);
        return -1;
    }

    size_t wallet_name_len = strlen(wallet_name);
    if (wallet_name_len > 64) {
        wallet_name_len = 64;  /* Truncate if too long */
    }

    /* Write fixed header (23 bytes) */
    uint8_t header[23] = {0};

    /* Magic: "DWALLET\0" */
    memcpy(header, "DWALLET", 8);

    /* Version: 1 (unprotected) - uint32 at offset 0x08 */
    uint32_t version = DWALLET_VERSION_UNPROTECTED;
    memcpy(header + 0x08, &version, 4);

    /* Type: 0 at offset 0x0C */
    header[0x0C] = 0;

    /* Padding: 8 bytes of zeros at offset 0x0D */
    /* Already zero from initialization */

    /* Wallet name length: uint16 at offset 0x15 */
    uint16_t name_len = (uint16_t)wallet_name_len;
    memcpy(header + 0x15, &name_len, 2);

    if (fwrite(header, 1, 23, fp) != 23) {
        fclose(fp);
        return -1;
    }

    /* Write wallet name */
    if (fwrite(wallet_name, 1, wallet_name_len, fp) != wallet_name_len) {
        fclose(fp);
        return -1;
    }

    /* Write cert header (8 bytes) */
    if (fwrite(CERT_HEADER, 1, 8, fp) != 8) {
        fclose(fp);
        return -1;
    }

    /* Write padding before keys (0x59 = 89 bytes of zeros) */
    uint8_t cert_padding[CERT_KEY_OFFSET] = {0};
    if (fwrite(cert_padding, 1, CERT_KEY_OFFSET, fp) != CERT_KEY_OFFSET) {
        fclose(fp);
        return -1;
    }

    /* Write serialized public key */
    if (fwrite(serialized_pubkey, 1, pubkey_size, fp) != pubkey_size) {
        fclose(fp);
        return -1;
    }

    /* Write serialized private key */
    if (fwrite(serialized_privkey, 1, privkey_size, fp) != privkey_size) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    /* Set file permissions to owner-only on Unix */
#ifndef _WIN32
    chmod(path, 0600);
#endif

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int cellframe_derive_wallet_seed(
    const uint8_t master_seed[64],
    uint8_t wallet_seed_out[32]
) {
    if (!master_seed || !wallet_seed_out) {
        return -1;
    }

    /* Derive wallet seed: SHAKE256(master_seed || "cellframe-wallet-v1", 32) */
    const char *context = "cellframe-wallet-v1";
    size_t context_len = strlen(context);
    size_t input_len = BIP39_SEED_SIZE + context_len;

    uint8_t *input = malloc(input_len);
    if (!input) {
        return -1;
    }

    memcpy(input, master_seed, BIP39_SEED_SIZE);
    memcpy(input + BIP39_SEED_SIZE, context, context_len);

    shake256(wallet_seed_out, 32, input, input_len);

    /* Clear input from memory */
    memset(input, 0, input_len);
    free(input);

    return 0;
}

int cellframe_wallet_create_from_seed(
    const uint8_t seed[32],
    const char *wallet_name,
    const char *wallet_dir,
    char *address_out
) {
    if (!seed || !wallet_name || !wallet_dir || !address_out) {
        fprintf(stderr, "[WALLET] Invalid arguments\n");
        return -1;
    }

    int result = -1;
    dilithium_public_key_t pubkey = {0};
    dilithium_private_key_t privkey = {0};
    uint8_t *serialized_pubkey = NULL;
    uint8_t *serialized_privkey = NULL;

    /* Generate Dilithium MODE_1 keypair from seed */
    if (dilithium_crypto_sign_keypair(&pubkey, &privkey, MODE_1, seed, 32) != 0) {
        fprintf(stderr, "[WALLET] Failed to generate Dilithium keypair\n");
        goto cleanup;
    }

    /* Verify key sizes match expectations */
    if (pubkey.kind != MODE_1 || privkey.kind != MODE_1) {
        fprintf(stderr, "[WALLET] Unexpected key kind\n");
        goto cleanup;
    }

    /* Allocate buffers for serialized keys */
    /* Serialized size = 8 (length) + 4 (kind) + key_size */
    size_t serialized_pubkey_size = 8 + 4 + CF_DILITHIUM_PUBLICKEYBYTES;
    size_t serialized_privkey_size = 8 + 4 + CF_DILITHIUM_SECRETKEYBYTES;

    serialized_pubkey = malloc(serialized_pubkey_size);
    serialized_privkey = malloc(serialized_privkey_size);

    if (!serialized_pubkey || !serialized_privkey) {
        fprintf(stderr, "[WALLET] Memory allocation failed\n");
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

    /* Create wallet directory if it doesn't exist */
    mkdir_portable(wallet_dir);

    /* Build wallet file path */
    char wallet_path[512];
    snprintf(wallet_path, sizeof(wallet_path), "%s/%s.dwallet", wallet_dir, wallet_name);

    /* Write wallet file */
    if (write_dwallet_file(wallet_path, wallet_name,
                          serialized_pubkey, actual_pubkey_size,
                          serialized_privkey, actual_privkey_size) != 0) {
        fprintf(stderr, "[WALLET] Failed to write wallet file\n");
        goto cleanup;
    }

    /* Generate address from serialized public key */
    if (cellframe_addr_from_pubkey(serialized_pubkey, actual_pubkey_size,
                                   CELLFRAME_NET_BACKBONE, address_out) != 0) {
        fprintf(stderr, "[WALLET] Failed to generate address\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    /* Securely clear sensitive data */
    if (serialized_privkey) {
        memset(serialized_privkey, 0, serialized_privkey_size);
        free(serialized_privkey);
    }
    if (serialized_pubkey) {
        memset(serialized_pubkey, 0, serialized_pubkey_size);
        free(serialized_pubkey);
    }

    /* Clean up Dilithium keys */
    if (privkey.data) {
        dilithium_private_key_delete(&privkey);
    }
    if (pubkey.data) {
        dilithium_public_key_delete(&pubkey);
    }

    return result;
}
