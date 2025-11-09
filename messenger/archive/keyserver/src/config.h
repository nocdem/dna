/*
 * Configuration Parser
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "keyserver.h"

/**
 * Load configuration from file
 *
 * @param filename: Path to config file
 * @param config: Configuration structure to populate
 * @return 0 on success, -1 on error
 */
int config_load(const char *filename, config_t *config);

/**
 * Initialize configuration with defaults
 *
 * @param config: Configuration structure to initialize
 */
void config_init_defaults(config_t *config);

/**
 * Print configuration (for debugging)
 *
 * @param config: Configuration to print
 */
void config_print(const config_t *config);

#endif // CONFIG_H
