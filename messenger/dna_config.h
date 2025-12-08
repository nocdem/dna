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
 * DNA Configuration (Log settings only)
 */
typedef struct {
    char log_level[16];        // DEBUG, INFO, WARN, ERROR, NONE
    char log_tags[512];        // Comma-separated tags to show (empty = all)
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
 * Apply log settings from config
 * Call this after dna_config_load() to enable log filtering
 */
void dna_config_apply_log_settings(const dna_config_t *config);

#ifdef __cplusplus
}
#endif

#endif // DNA_CONFIG_H
