/*
 * DNA Messenger - Configuration Management
 */

#include "dna_config.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CONFIG_FILE_NAME "config"

// Forward declaration
int dna_config_save(const dna_config_t *config);

static void get_config_path(char *path, size_t size) {
    const char *home = qgp_platform_home_dir();
    snprintf(path, size, "%s/.dna/%s", home, CONFIG_FILE_NAME);
}

int dna_config_load(dna_config_t *config) {
    if (!config) {
        return -1;
    }

    memset(config, 0, sizeof(dna_config_t));

    char config_path[512];
    get_config_path(config_path, sizeof(config_path));

    FILE *f = fopen(config_path, "r");
    if (!f) {
        // Default config if file doesn't exist
        strcpy(config->log_level, "WARN");
        config->log_tags[0] = '\0';  // Empty = show all

        // Default bootstrap nodes
        strcpy(config->bootstrap_nodes[0], "154.38.182.161:4000");
        strcpy(config->bootstrap_nodes[1], "164.68.105.227:4000");
        strcpy(config->bootstrap_nodes[2], "164.68.116.180:4000");
        config->bootstrap_count = 3;

        // Create default config file
        dna_config_save(config);
        return 0;
    }

    // Read config file (simple key=value format)
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Parse key=value
        char *equals = strchr(line, '=');
        if (!equals) {
            continue;
        }

        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        if (strcmp(key, "log_level") == 0) {
            strncpy(config->log_level, value, sizeof(config->log_level) - 1);
        } else if (strcmp(key, "log_tags") == 0) {
            strncpy(config->log_tags, value, sizeof(config->log_tags) - 1);
        } else if (strcmp(key, "bootstrap_nodes") == 0) {
            // Parse comma-separated bootstrap nodes
            config->bootstrap_count = 0;
            char nodes_copy[512];
            strncpy(nodes_copy, value, sizeof(nodes_copy) - 1);
            nodes_copy[sizeof(nodes_copy) - 1] = '\0';

            char *token = strtok(nodes_copy, ",");
            while (token != NULL && config->bootstrap_count < DNA_MAX_BOOTSTRAP_NODES) {
                // Trim whitespace
                while (*token == ' ') token++;
                char *end = token + strlen(token) - 1;
                while (end > token && *end == ' ') *end-- = '\0';

                if (*token != '\0') {
                    strncpy(config->bootstrap_nodes[config->bootstrap_count], token, 63);
                    config->bootstrap_nodes[config->bootstrap_count][63] = '\0';
                    config->bootstrap_count++;
                }
                token = strtok(NULL, ",");
            }
        }
    }

    // Set defaults if not in config
    if (config->log_level[0] == '\0') {
        strcpy(config->log_level, "WARN");
    }

    // Default bootstrap nodes if none specified
    if (config->bootstrap_count == 0) {
        strcpy(config->bootstrap_nodes[0], "154.38.182.161:4000");
        strcpy(config->bootstrap_nodes[1], "164.68.105.227:4000");
        strcpy(config->bootstrap_nodes[2], "164.68.116.180:4000");
        config->bootstrap_count = 3;
    }

    fclose(f);
    return 0;
}

int dna_config_save(const dna_config_t *config) {
    if (!config) {
        return -1;
    }

    // Ensure ~/.dna directory exists
    const char *home = qgp_platform_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    if (qgp_platform_mkdir(dna_dir) != 0 && errno != EEXIST) {
        return -1;
    }

    char config_path[512];
    get_config_path(config_path, sizeof(config_path));

    FILE *f = fopen(config_path, "w");
    if (!f) {
        return -1;
    }

    fprintf(f, "# DNA Messenger Configuration\n\n");

    fprintf(f, "# Log level: DEBUG, INFO, WARN, ERROR, NONE\n");
    fprintf(f, "log_level=%s\n\n", config->log_level);

    fprintf(f, "# Log tags: comma-separated list (empty = show all)\n");
    fprintf(f, "log_tags=%s\n\n", config->log_tags);

    fprintf(f, "# Bootstrap nodes: comma-separated list (ip:port)\n");
    fprintf(f, "bootstrap_nodes=");
    for (int i = 0; i < config->bootstrap_count; i++) {
        if (i > 0) fprintf(f, ",");
        fprintf(f, "%s", config->bootstrap_nodes[i]);
    }
    fprintf(f, "\n");

    fclose(f);
    return 0;
}

void dna_config_apply_log_settings(const dna_config_t *config) {
    if (!config) {
        return;
    }

    // Set log level
    qgp_log_level_t level = QGP_LOG_LEVEL_WARN;  // default
    if (strcmp(config->log_level, "DEBUG") == 0) {
        level = QGP_LOG_LEVEL_DEBUG;
    } else if (strcmp(config->log_level, "INFO") == 0) {
        level = QGP_LOG_LEVEL_INFO;
    } else if (strcmp(config->log_level, "WARN") == 0) {
        level = QGP_LOG_LEVEL_WARN;
    } else if (strcmp(config->log_level, "ERROR") == 0) {
        level = QGP_LOG_LEVEL_ERROR;
    } else if (strcmp(config->log_level, "NONE") == 0) {
        level = QGP_LOG_LEVEL_NONE;
    }
    fprintf(stderr, "[CONFIG] log_level='%s' -> level=%d\n", config->log_level, level);
    qgp_log_set_level(level);

    // Set tag filter if specified
    if (config->log_tags[0] != '\0') {
        // Use whitelist mode - only show specified tags
        qgp_log_set_filter_mode(QGP_LOG_FILTER_WHITELIST);
        qgp_log_clear_filters();

        // Parse comma-separated tags
        char tags_copy[512];
        strncpy(tags_copy, config->log_tags, sizeof(tags_copy) - 1);
        tags_copy[sizeof(tags_copy) - 1] = '\0';

        char *token = strtok(tags_copy, ",");
        while (token != NULL) {
            // Trim whitespace
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (*token != '\0') {
                qgp_log_enable_tag(token);
            }
            token = strtok(NULL, ",");
        }
    }
    // If log_tags is empty, default blacklist mode shows all
}
