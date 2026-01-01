/*
 * QGP - Quantum Good Privacy
 * Copyright (c) 2025 QGP contributors
 *
 * Post-quantum file signing and encryption tool with vendored
 * pq-crystals implementations (Dilithium5/ML-DSA-87, Kyber1024/ML-KEM-1024)
 */

#ifndef QGP_H
#define QGP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>


#include "crypto/utils/qgp_types.h"

// Version info
#ifndef PQSIGNUM_VERSION
#define PQSIGNUM_VERSION "1.0.0"
#endif

#ifndef BUILD_TS
#define BUILD_TS "unknown"
#endif

#ifndef BUILD_HASH
#define BUILD_HASH "unknown"
#endif

// Default paths
#define DEFAULT_KEYRING_DIR ".qgp"
#define DEFAULT_CERT_EXT ".dcert"
#define DEFAULT_SIG_EXT ".sig"
#define DEFAULT_ASC_EXT ".asc"

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_ERROR 2
#define EXIT_CRYPTO_ERROR 4
#define EXIT_KEY_ERROR 5

// Configuration structure
typedef struct {
    char *default_key_name;      // Default identity for signing/decryption
    const char *default_algorithm; // Default signature algorithm (currently only dilithium)
    char *keyring_dir;           // Custom keyring directory (NULL = use default)
} qgp_config_t;

// Function prototypes

// Key restoration (messenger/keygen.c)
int cmd_restore_key_from_seed(const char *name, const char *algo, const char *output_dir);

// Public key export (crypto/utils/qgp_key.c)
int cmd_export_pubkey(const char *name, const char *key_dir, const char *output_file);

// Legacy keyring stubs (return NULL - keyring not used in DNA Messenger)
// These exist only for API compatibility with old dna_api.c code
char* keyring_find_key(const char *name);
char* keyring_find_private_key(const char *name, const char *key_type);

// ASCII Armor (armor.c)
bool is_armored_file(const char *path);
int write_armored_file(const char *output_path, const char *type,
                       const uint8_t *data, size_t data_size,
                       const char **headers, size_t header_count);
int read_armored_file(const char *input_path, char **type_out,
                      uint8_t **data_out, size_t *data_size_out,
                      char ***headers_out, size_t *header_count_out);
const char* get_signature_algorithm_name(const qgp_signature_t *signature);
size_t build_signature_headers(const qgp_signature_t *signature, const char **headers, size_t max_headers);

// Configuration (config.c)
int qgp_config_load(void);
const qgp_config_t* qgp_config_get(void);
void qgp_config_free(void);
int qgp_config_create_default(void);
int qgp_config_set_default_key(const char *key_name);

#endif // QGP_H
