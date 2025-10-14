/*
 * qgp_key.c - QGP Key Management 
 *
 * Memory management and serialization for QGP keys.
 * Uses QGP's own file format with no external dependencies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qgp_types.h"

// ============================================================================
// KEY MEMORY MANAGEMENT
// ============================================================================

/**
 * Create a new QGP key structure
 *
 * @param type: Key algorithm type
 * @param purpose: Key purpose (signing or encryption)
 * @return: Allocated key structure (caller must free with qgp_key_free())
 */
qgp_key_t* qgp_key_new(qgp_key_type_t type, qgp_key_purpose_t purpose) {
    qgp_key_t *key = QGP_CALLOC(1, sizeof(qgp_key_t));
    if (!key) {
        return NULL;
    }

    key->type = type;
    key->purpose = purpose;
    key->public_key = NULL;
    key->public_key_size = 0;
    key->private_key = NULL;
    key->private_key_size = 0;
    memset(key->name, 0, sizeof(key->name));

    return key;
}

/**
 * Free a QGP key structure
 *
 * @param key: Key to free (can be NULL)
 */
void qgp_key_free(qgp_key_t *key) {
    if (!key) {
        return;
    }

    // Securely wipe private key before freeing
    if (key->private_key) {
        memset(key->private_key, 0, key->private_key_size);
        QGP_FREE(key->private_key);
    }

    // Free public key
    if (key->public_key) {
        QGP_FREE(key->public_key);
    }

    // Wipe and free key structure
    memset(key, 0, sizeof(qgp_key_t));
    QGP_FREE(key);
}

// ============================================================================
// KEY SERIALIZATION
// ============================================================================

/**
 * Save private key to file
 *
 * File format: [header | public_key | private_key]
 *
 * @param key: Key to save
 * @param path: Output file path
 * @return: 0 on success, -1 on error
 */
int qgp_key_save(const qgp_key_t *key, const char *path) {
    if (!key || !path) {
        fprintf(stderr, "qgp_key_save: Invalid arguments\n");
        return -1;
    }

    if (!key->public_key || !key->private_key) {
        fprintf(stderr, "qgp_key_save: Key has no public or private key data\n");
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "qgp_key_save: Cannot open file: %s\n", path);
        return -1;
    }

    // Prepare header
    qgp_privkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PRIVKEY_MAGIC, 8);
    header.version = QGP_PRIVKEY_VERSION;
    header.key_type = key->type;
    header.purpose = key->purpose;
    header.public_key_size = key->public_key_size;
    header.private_key_size = key->private_key_size;
    strncpy(header.name, key->name, sizeof(header.name) - 1);

    // Write header
    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "qgp_key_save: Failed to write header\n");
        fclose(fp);
        return -1;
    }

    // Write public key
    if (fwrite(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        fprintf(stderr, "qgp_key_save: Failed to write public key\n");
        fclose(fp);
        return -1;
    }

    // Write private key
    if (fwrite(key->private_key, 1, key->private_key_size, fp) != key->private_key_size) {
        fprintf(stderr, "qgp_key_save: Failed to write private key\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * Load private key from file
 *
 * @param path: Input file path
 * @param key_out: Output key (caller must free with qgp_key_free())
 * @return: 0 on success, -1 on error
 */
int qgp_key_load(const char *path, qgp_key_t **key_out) {
    if (!path || !key_out) {
        fprintf(stderr, "qgp_key_load: Invalid arguments\n");
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "qgp_key_load: Cannot open file: %s\n", path);
        return -1;
    }

    // Read header
    qgp_privkey_file_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "qgp_key_load: Failed to read header\n");
        fclose(fp);
        return -1;
    }

    // Validate header
    if (memcmp(header.magic, QGP_PRIVKEY_MAGIC, 8) != 0) {
        fprintf(stderr, "qgp_key_load: Invalid magic (not a QGP private key file)\n");
        fclose(fp);
        return -1;
    }

    if (header.version != QGP_PRIVKEY_VERSION) {
        fprintf(stderr, "qgp_key_load: Unsupported version: %d\n", header.version);
        fclose(fp);
        return -1;
    }

    // Create key structure
    qgp_key_t *key = qgp_key_new((qgp_key_type_t)header.key_type, (qgp_key_purpose_t)header.purpose);
    if (!key) {
        fprintf(stderr, "qgp_key_load: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    strncpy(key->name, header.name, sizeof(key->name) - 1);

    // Allocate and read public key
    key->public_key_size = header.public_key_size;
    key->public_key = QGP_MALLOC(key->public_key_size);
    if (!key->public_key) {
        fprintf(stderr, "qgp_key_load: Memory allocation failed for public key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        fprintf(stderr, "qgp_key_load: Failed to read public key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    // Allocate and read private key
    key->private_key_size = header.private_key_size;
    key->private_key = QGP_MALLOC(key->private_key_size);
    if (!key->private_key) {
        fprintf(stderr, "qgp_key_load: Memory allocation failed for private key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->private_key, 1, key->private_key_size, fp) != key->private_key_size) {
        fprintf(stderr, "qgp_key_load: Failed to read private key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *key_out = key;
    return 0;
}

/**
 * Save public key to file
 *
 * @param key: Key containing public key
 * @param path: Output file path
 * @return: 0 on success, -1 on error
 */
int qgp_pubkey_save(const qgp_key_t *key, const char *path) {
    if (!key || !path) {
        fprintf(stderr, "qgp_pubkey_save: Invalid arguments\n");
        return -1;
    }

    if (!key->public_key) {
        fprintf(stderr, "qgp_pubkey_save: Key has no public key data\n");
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "qgp_pubkey_save: Cannot open file: %s\n", path);
        return -1;
    }

    // Prepare header
    qgp_pubkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PUBKEY_MAGIC, 8);
    header.version = QGP_PUBKEY_VERSION;
    header.key_type = key->type;
    header.purpose = key->purpose;
    header.public_key_size = key->public_key_size;
    strncpy(header.name, key->name, sizeof(header.name) - 1);

    // Write header
    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "qgp_pubkey_save: Failed to write header\n");
        fclose(fp);
        return -1;
    }

    // Write public key
    if (fwrite(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        fprintf(stderr, "qgp_pubkey_save: Failed to write public key\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * Load public key from file
 *
 * @param path: Input file path
 * @param key_out: Output key (caller must free with qgp_key_free())
 * @return: 0 on success, -1 on error
 */
int qgp_pubkey_load(const char *path, qgp_key_t **key_out) {
    if (!path || !key_out) {
        fprintf(stderr, "qgp_pubkey_load: Invalid arguments\n");
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "qgp_pubkey_load: Cannot open file: %s\n", path);
        return -1;
    }

    // Read header
    qgp_pubkey_file_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "qgp_pubkey_load: Failed to read header\n");
        fclose(fp);
        return -1;
    }

    // Validate header
    if (memcmp(header.magic, QGP_PUBKEY_MAGIC, 8) != 0) {
        fprintf(stderr, "qgp_pubkey_load: Invalid magic (not a QGP public key file)\n");
        fclose(fp);
        return -1;
    }

    if (header.version != QGP_PUBKEY_VERSION) {
        fprintf(stderr, "qgp_pubkey_load: Unsupported version: %d\n", header.version);
        fclose(fp);
        return -1;
    }

    // Create key structure
    qgp_key_t *key = qgp_key_new((qgp_key_type_t)header.key_type, (qgp_key_purpose_t)header.purpose);
    if (!key) {
        fprintf(stderr, "qgp_pubkey_load: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    strncpy(key->name, header.name, sizeof(key->name) - 1);

    // Allocate and read public key
    key->public_key_size = header.public_key_size;
    key->public_key = QGP_MALLOC(key->public_key_size);
    if (!key->public_key) {
        fprintf(stderr, "qgp_pubkey_load: Memory allocation failed for public key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        fprintf(stderr, "qgp_pubkey_load: Failed to read public key\n");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *key_out = key;
    return 0;
}
