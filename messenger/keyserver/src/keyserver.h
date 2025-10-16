/*
 * DNA Keyserver - Main Header
 *
 * HTTP REST API keyserver for DNA Messenger
 */

#ifndef KEYSERVER_H
#define KEYSERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Version
#define KEYSERVER_VERSION "0.1.0"

// Configuration defaults
#define DEFAULT_PORT 8080
#define DEFAULT_MAX_CONNECTIONS 1000
#define DEFAULT_DB_HOST "localhost"
#define DEFAULT_DB_PORT 5432
#define DEFAULT_DB_NAME "dna_keyserver"

// Validation limits
#define MIN_HANDLE_LENGTH 3
#define MAX_HANDLE_LENGTH 32
#define MAX_IDENTITY_LENGTH 65  // "handle/device"
#define MAX_PUBKEY_B64 4096
#define INBOX_KEY_HEX_LENGTH 64
#define MAX_TIMESTAMP_SKEW 3600  // 1 hour

// Rate limits
#define RATE_LIMIT_REGISTER 10    // per hour
#define RATE_LIMIT_LOOKUP 100     // per minute
#define RATE_LIMIT_LIST 10        // per minute

// HTTP status codes
#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_NOT_FOUND 404
#define HTTP_CONFLICT 409
#define HTTP_TOO_MANY_REQUESTS 429
#define HTTP_INTERNAL_ERROR 500

// Identity structure
typedef struct {
    int id;
    char handle[MAX_HANDLE_LENGTH + 1];
    char device[MAX_HANDLE_LENGTH + 1];
    char identity[MAX_IDENTITY_LENGTH + 1];
    char *dilithium_pub;
    char *kyber_pub;
    char inbox_key[INBOX_KEY_HEX_LENGTH + 1];
    int version;
    int updated_at;
    char *sig;
    int schema_version;
    char registered_at[32];
    char last_updated[32];
} identity_t;

// Configuration structure
typedef struct {
    // Server
    char bind_address[256];
    int port;
    int max_connections;

    // Database
    char db_host[256];
    int db_port;
    char db_name[256];
    char db_user[256];
    char db_password[256];
    int db_pool_size;
    int db_pool_timeout;

    // Security
    char verify_json_path[512];
    int verify_timeout;
    int max_timestamp_skew;

    // Rate limits
    int rate_limit_register_count;
    int rate_limit_register_period;
    int rate_limit_lookup_count;
    int rate_limit_lookup_period;
    int rate_limit_list_count;
    int rate_limit_list_period;

    // Validation
    int handle_min_length;
    int handle_max_length;
    int device_min_length;
    int device_max_length;
    int dilithium_pub_size;
    int kyber_pub_size;

    // Logging
    char log_level[16];
    char log_file[512];
    char log_format[16];
} config_t;

// Global configuration
extern config_t g_config;

// Logging macros
#define LOG_DEBUG(fmt, ...) log_message("DEBUG", fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_message("INFO",  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_message("WARN",  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message("ERROR", fmt, ##__VA_ARGS__)

void log_message(const char *level, const char *fmt, ...);

#endif // KEYSERVER_H
