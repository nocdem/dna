/*
 * QGP - Configuration File Support
 * Simple INI-style configuration parser for default settings
 *
 * Configuration file location: ~/.qgp/config
 * Format:
 *   # Comments start with #
 *   key = value
 *
 * Supported keys:
 *   default_key_name = <name>        # Default identity for signing/decryption
 *   default_algorithm = dilithium    # Default signature algorithm
 *   keyring_dir = <path>             # Custom keyring directory (default: ~/.qgp)
 */

#include "qgp.h"
#include "qgp_compiler.h"
#include <ctype.h>

#define MAX_LINE_LENGTH 1024
#define MAX_CONFIG_KEY 64
#define MAX_CONFIG_VALUE 512

// Global configuration structure
static qgp_config_t g_config = {
    .default_key_name = NULL,
    .default_algorithm = "dilithium",  // Default
    .keyring_dir = NULL
};

// Trim whitespace from both ends of a string
static char* trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;  // All spaces

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Null terminate
    *(end + 1) = 0;

    return str;
}

// Parse a boolean value (yes/no, true/false, 1/0)
static bool parse_bool(const char *value) {
    if (strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcmp(value, "1") == 0) {
        return true;
    }
    return false;
}

// Parse a single configuration line
static void parse_config_line(char *line) {
    // Skip comments and empty lines
    char *trimmed = trim_whitespace(line);
    if (trimmed[0] == '#' || trimmed[0] == '\0') {
        return;
    }

    // Find the '=' separator
    char *equals = strchr(trimmed, '=');
    if (!equals) {
        return;  // Invalid line, skip silently
    }

    // Split into key and value
    *equals = '\0';
    char *key = trim_whitespace(trimmed);
    char *value = trim_whitespace(equals + 1);

    // Parse configuration keys
    if (strcmp(key, "default_key_name") == 0) {
        if (g_config.default_key_name) {
            free(g_config.default_key_name);
        }
        g_config.default_key_name = strdup(value);
    }
    else if (strcmp(key, "default_algorithm") == 0) {
        if (strcmp(value, "dilithium") == 0) {
            g_config.default_algorithm = strdup(value);
        } else {
            fprintf(stderr, "Warning: Unknown algorithm '%s' in config (only 'dilithium' supported)\n", value);
        }
    }
    else if (strcmp(key, "keyring_dir") == 0) {
        if (g_config.keyring_dir) {
            free(g_config.keyring_dir);
        }
        g_config.keyring_dir = strdup(value);
    }
}

// Load configuration from ~/.qgp/config
int qgp_config_load(void) {
    char *home = get_home_dir();
    if (!home) {
        return -1;  // Can't find home directory
    }

    char *config_dir = build_path(home, DEFAULT_KEYRING_DIR);
    char *config_path = build_path(config_dir, "config");
    free(config_dir);

    // If config file doesn't exist, use defaults (not an error)
    if (!file_exists(config_path)) {
        free(config_path);
        return 0;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        free(config_path);
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), fp)) {
        parse_config_line(line);
    }

    fclose(fp);
    free(config_path);
    return 0;
}

// Get the global configuration
const qgp_config_t* qgp_config_get(void) {
    return &g_config;
}

// Free configuration resources
void qgp_config_free(void) {
    if (g_config.default_key_name) {
        free(g_config.default_key_name);
        g_config.default_key_name = NULL;
    }
    if (g_config.keyring_dir) {
        free(g_config.keyring_dir);
        g_config.keyring_dir = NULL;
    }
}

// Create a default configuration file with comments
int qgp_config_create_default(void) {
    char *home = get_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot determine home directory\n");
        return -1;
    }

    char *config_dir = build_path(home, DEFAULT_KEYRING_DIR);
    char *config_path = build_path(config_dir, "config");
    free(config_dir);

    // Check if config already exists
    if (file_exists(config_path)) {
        fprintf(stderr, "Configuration file already exists: %s\n", config_path);
        free(config_path);
        return -1;
    }

    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create configuration file: %s\n", config_path);
        free(config_path);
        return -1;
    }

    // Write default configuration with helpful comments
    fprintf(fp, "# QGP Configuration File\n");
    fprintf(fp, "# This file contains default settings for QGP operations\n");
    fprintf(fp, "# Lines starting with # are comments\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Default identity for signing and decryption operations\n");
    fprintf(fp, "# If specified, you don't need to use --key flag\n");
    fprintf(fp, "# Use: qgp --set-default <keyname> to set this\n");
    fprintf(fp, "# default_key_name = alice\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Default signature algorithm (only dilithium is currently supported)\n");
    fprintf(fp, "default_algorithm = dilithium\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Custom keyring directory (default: ~/.qgp)\n");
    fprintf(fp, "# keyring_dir = /custom/path\n");
    fprintf(fp, "#\n");

    fclose(fp);
    printf("Created default configuration file: %s\n", config_path);
    printf("Edit this file to customize default settings.\n");
    free(config_path);
    return 0;
}

// Set default key in configuration file
int qgp_config_set_default_key(const char *key_name) {
    char *home = get_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot determine home directory\n");
        return -1;
    }

    char *config_dir = build_path(home, DEFAULT_KEYRING_DIR);
    char *config_path = build_path(config_dir, "config");
    free(config_dir);

    // Read existing config or create if doesn't exist
    FILE *fp_read = fopen(config_path, "r");
    char **lines = NULL;
    size_t line_count = 0;
    bool found_default_key = false;

    if (fp_read) {
        char line[MAX_LINE_LENGTH];
        while (fgets(line, sizeof(line), fp_read)) {
            // Check if this is the default_key_name line (without modifying the original)
            char line_copy[MAX_LINE_LENGTH];
            strncpy(line_copy, line, sizeof(line_copy) - 1);
            line_copy[sizeof(line_copy) - 1] = '\0';
            char *trimmed = trim_whitespace(line_copy);

            if (strncmp(trimmed, "default_key_name", 16) == 0 ||
                strncmp(trimmed, "# default_key_name", 18) == 0) {
                // Replace with new value
                char new_line[MAX_LINE_LENGTH];
                snprintf(new_line, sizeof(new_line), "default_key_name = %s\n", key_name);
                lines = realloc(lines, (line_count + 1) * sizeof(char*));
                lines[line_count++] = strdup(new_line);
                found_default_key = true;
            } else {
                // Keep existing line (preserve newlines)
                lines = realloc(lines, (line_count + 1) * sizeof(char*));
                lines[line_count++] = strdup(line);
            }
        }
        fclose(fp_read);
    }

    // If config doesn't exist or doesn't have default_key_name, create it
    if (!found_default_key) {
        if (line_count == 0) {
            // Create new config from scratch
            qgp_config_create_default();
            fp_read = fopen(config_path, "r");
            if (fp_read) {
                char line[MAX_LINE_LENGTH];
                while (fgets(line, sizeof(line), fp_read)) {
                    lines = realloc(lines, (line_count + 1) * sizeof(char*));
                    lines[line_count++] = strdup(line);
                }
                fclose(fp_read);
            }
        }
        // Add default_key_name line
        char new_line[MAX_LINE_LENGTH];
        snprintf(new_line, sizeof(new_line), "default_key_name = %s\n", key_name);
        lines = realloc(lines, (line_count + 1) * sizeof(char*));
        lines[line_count++] = strdup(new_line);
    }

    // Write updated config
    FILE *fp_write = fopen(config_path, "w");
    if (!fp_write) {
        fprintf(stderr, "Error: Cannot write configuration file: %s\n", config_path);
        for (size_t i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        free(config_path);
        return -1;
    }

    for (size_t i = 0; i < line_count; i++) {
        fputs(lines[i], fp_write);
        free(lines[i]);
    }
    free(lines);
    fclose(fp_write);

    printf("✓ Default key set to: %s\n", key_name);
    printf("Configuration saved to: %s\n", config_path);
    free(config_path);
    return 0;
}
