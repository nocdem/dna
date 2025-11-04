/*
 * Configuration Parser
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

config_t g_config;

void config_init_defaults(config_t *config) {
    // Server
    strcpy(config->bind_address, "0.0.0.0");
    config->port = DEFAULT_PORT;
    config->max_connections = DEFAULT_MAX_CONNECTIONS;

    // Database
    strcpy(config->db_host, DEFAULT_DB_HOST);
    config->db_port = DEFAULT_DB_PORT;
    strcpy(config->db_name, DEFAULT_DB_NAME);
    strcpy(config->db_user, "keyserver_user");
    strcpy(config->db_password, "");
    config->db_pool_size = 10;
    config->db_pool_timeout = 5;

    // Security
    strcpy(config->verify_json_path, "../utils/verify_json");
    config->verify_timeout = 5;
    config->max_timestamp_skew = MAX_TIMESTAMP_SKEW;

    // Rate limits
    config->rate_limit_register_count = 10;
    config->rate_limit_register_period = 3600;
    config->rate_limit_lookup_count = 100;
    config->rate_limit_lookup_period = 60;
    config->rate_limit_list_count = 10;
    config->rate_limit_list_period = 60;

    // Validation
    config->handle_min_length = MIN_DNA_LENGTH;
    config->handle_max_length = MAX_DNA_LENGTH;
    config->device_min_length = MIN_DNA_LENGTH;
    config->device_max_length = MAX_DNA_LENGTH;
    config->dilithium_pub_size = 2592;
    config->kyber_pub_size = 1568;  // Kyber1024 public key size

    // Logging
    strcpy(config->log_level, "info");
    strcpy(config->log_file, "");
    strcpy(config->log_format, "text");
}

static void parse_line(const char *line, config_t *config) {
    char key[256], value[512];

    // Skip comments and empty lines
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
        return;
    }

    // Skip section headers [section]
    if (line[0] == '[') {
        return;
    }

    // Parse key = value
    if (sscanf(line, " %255[^=] = %511[^\n\r]", key, value) != 2) {
        return;
    }

    // Trim whitespace from key
    char *k = key;
    while (*k == ' ' || *k == '\t') k++;
    size_t klen = strlen(k);
    while (klen > 0 && (k[klen-1] == ' ' || k[klen-1] == '\t')) {
        k[--klen] = '\0';
    }

    // Trim whitespace from value
    char *v = value;
    while (*v == ' ' || *v == '\t') v++;
    size_t len = strlen(v);
    while (len > 0 && (v[len-1] == ' ' || v[len-1] == '\t')) {
        v[--len] = '\0';
    }

    // Server settings
    if (strcmp(k, "bind_address") == 0) {
        strncpy(config->bind_address, v, sizeof(config->bind_address) - 1);
    } else if (strcmp(k, "port") == 0) {
        config->port = atoi(v);
    } else if (strcmp(k, "max_connections") == 0) {
        config->max_connections = atoi(v);
    }
    // Database settings
    else if (strcmp(k, "host") == 0) {
        strncpy(config->db_host, v, sizeof(config->db_host) - 1);
    } else if (strcmp(k, "dbname") == 0) {
        strncpy(config->db_name, v, sizeof(config->db_name) - 1);
    } else if (strcmp(k, "user") == 0) {
        strncpy(config->db_user, v, sizeof(config->db_user) - 1);
    } else if (strcmp(k, "password") == 0) {
        strncpy(config->db_password, v, sizeof(config->db_password) - 1);
    }
    // Security
    else if (strcmp(k, "verify_json_path") == 0) {
        strncpy(config->verify_json_path, v, sizeof(config->verify_json_path) - 1);
    }
    // Logging
    else if (strcmp(k, "level") == 0) {
        strncpy(config->log_level, v, sizeof(config->log_level) - 1);
    }
}

int config_load(const char *filename, config_t *config) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file: %s\n", filename);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        parse_line(line, config);
    }

    fclose(fp);
    return 0;
}

void config_print(const config_t *config) {
    printf("Configuration:\n");
    printf("  Server: %s:%d\n", config->bind_address, config->port);
    printf("  Database: %s@%s:%d/%s\n",
           config->db_user, config->db_host, config->db_port, config->db_name);
    printf("  Verify binary: %s\n", config->verify_json_path);
    printf("  Log level: %s\n", config->log_level);
}
