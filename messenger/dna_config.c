/*
 * DNA Messenger - Configuration Management
 */

#include "dna_config.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CONFIG_FILE_NAME "config"

static void get_config_path(char *path, size_t size) {
    const char *home = qgp_platform_home_dir();
    snprintf(path, size, "%s/.dna/%s", home, CONFIG_FILE_NAME);
}

int dna_config_load(dna_config_t *config) {
    if (!config) {
        return -1;
    }

    char config_path[512];
    get_config_path(config_path, sizeof(config_path));

    FILE *f = fopen(config_path, "r");
    if (!f) {
        // Default config if file doesn't exist
        strcpy(config->server_host, "ai.cpunk.io");
        config->server_port = 5432;
        strcpy(config->database, "dna_messenger");
        strcpy(config->username, "dna");
        strcpy(config->password, "dna_password");
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

        if (strcmp(key, "server_host") == 0) {
            strncpy(config->server_host, value, sizeof(config->server_host) - 1);
        } else if (strcmp(key, "server_port") == 0) {
            config->server_port = atoi(value);
        } else if (strcmp(key, "database") == 0) {
            strncpy(config->database, value, sizeof(config->database) - 1);
        } else if (strcmp(key, "username") == 0) {
            strncpy(config->username, value, sizeof(config->username) - 1);
        } else if (strcmp(key, "password") == 0) {
            strncpy(config->password, value, sizeof(config->password) - 1);
        }
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

    fprintf(f, "# DNA Messenger Configuration\n");
    fprintf(f, "# Auto-generated - edit with caution\n\n");
    fprintf(f, "server_host=%s\n", config->server_host);
    fprintf(f, "server_port=%d\n", config->server_port);
    fprintf(f, "database=%s\n", config->database);
    fprintf(f, "username=%s\n", config->username);
    fprintf(f, "password=%s\n", config->password);

    fclose(f);
    printf("✓ Configuration saved to %s\n", config_path);
    return 0;
}

void dna_config_build_connstring(const dna_config_t *config, char *connstring, size_t size) {
    snprintf(connstring, size,
             "postgresql://%s:%s@%s:%d/%s",
             config->username,
             config->password,
             config->server_host,
             config->server_port,
             config->database);
}

int dna_config_setup(dna_config_t *config) {
    if (!config) {
        return -1;
    }

    printf("\n=== DNA Messenger - Server Configuration ===\n\n");

    // Only ask for server IP/hostname
    printf("DNA Server (IP or hostname): ");
    if (!fgets(config->server_host, sizeof(config->server_host), stdin)) {
        return -1;
    }
    config->server_host[strcspn(config->server_host, "\n")] = 0;

    if (strlen(config->server_host) == 0) {
        fprintf(stderr, "Error: Server address required\n");
        return -1;
    }

    // Set defaults (standard DNA Messenger values)
    config->server_port = 5432;
    strcpy(config->database, "dna_messenger");
    strcpy(config->username, "dna");
    strcpy(config->password, "dna_password");

    printf("\n✓ Server configured: %s:%d\n", config->server_host, config->server_port);
    printf("\n");
    return 0;
}
