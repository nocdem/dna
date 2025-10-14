/*
 * DNA Messenger - Configuration Management
 */

#ifndef DNA_CONFIG_H
#define DNA_CONFIG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DNA Configuration
 */
typedef struct {
    char server_host[256];     // e.g., "192.168.0.1" or "dna.example.com"
    int server_port;           // e.g., 5432
    char database[64];         // e.g., "dna_messenger"
    char username[64];         // e.g., "dna"
    char password[128];        // e.g., "dna_password"
} dna_config_t;

/**
 * Load configuration from ~/.dna/config
 * Returns 0 on success, -1 on error
 */
int dna_config_load(dna_config_t *config);

/**
 * Save configuration to ~/.dna/config
 * Returns 0 on success, -1 on error
 */
int dna_config_save(const dna_config_t *config);

/**
 * Build PostgreSQL connection string from config
 * Buffer must be at least 512 bytes
 */
void dna_config_build_connstring(const dna_config_t *config, char *connstring, size_t size);

/**
 * Interactive configuration setup
 */
int dna_config_setup(dna_config_t *config);

#ifdef __cplusplus
}
#endif

#endif // DNA_CONFIG_H
