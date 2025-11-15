/**
 * DHT Layer - Standardized Error Codes
 *
 * Unified error code definitions for all DHT modules to ensure consistency.
 * All DHT functions should use these error codes for return values.
 *
 * @file dht_errors.h
 * @author DNA Messenger Team
 * @date 2025-11-16
 */

#ifndef DHT_ERRORS_H
#define DHT_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DHT Error Codes
 *
 * All DHT functions return 0 on success, negative values on error.
 * This enum provides standardized error codes across all DHT modules.
 */
typedef enum {
    DHT_SUCCESS           =  0,   /**< Operation completed successfully */
    DHT_ERROR_GENERAL     = -1,   /**< General/unspecified error */
    DHT_ERROR_NOT_FOUND   = -2,   /**< Requested key/value not found in DHT */
    DHT_ERROR_AUTH_FAILED = -3,   /**< Signature verification or authentication failed */
    DHT_ERROR_TIMEOUT     = -4,   /**< Operation timed out */
    DHT_ERROR_INVALID_PARAM = -5, /**< Invalid function parameter (NULL or malformed) */
    DHT_ERROR_MEMORY      = -6,   /**< Memory allocation failed */
    DHT_ERROR_NETWORK     = -7,   /**< Network/DHT communication error */
    DHT_ERROR_SERIALIZE   = -8,   /**< Serialization/deserialization failed */
    DHT_ERROR_CRYPTO      = -9,   /**< Cryptographic operation failed */
    DHT_ERROR_NOT_INIT    = -10,  /**< DHT context not initialized */
    DHT_ERROR_ALREADY_EXISTS = -11, /**< Item already exists (duplicate) */
    DHT_ERROR_STORAGE     = -12,  /**< Storage/persistence error */
} dht_error_t;

/**
 * Get human-readable error message for error code
 *
 * @param error_code DHT error code (from dht_error_t enum)
 * @return Constant string describing the error (never NULL)
 */
static inline const char* dht_strerror(int error_code) {
    switch (error_code) {
        case DHT_SUCCESS:           return "Success";
        case DHT_ERROR_GENERAL:     return "General error";
        case DHT_ERROR_NOT_FOUND:   return "Not found in DHT";
        case DHT_ERROR_AUTH_FAILED: return "Authentication/signature verification failed";
        case DHT_ERROR_TIMEOUT:     return "Operation timed out";
        case DHT_ERROR_INVALID_PARAM: return "Invalid parameter";
        case DHT_ERROR_MEMORY:      return "Memory allocation failed";
        case DHT_ERROR_NETWORK:     return "Network/DHT communication error";
        case DHT_ERROR_SERIALIZE:   return "Serialization/deserialization failed";
        case DHT_ERROR_CRYPTO:      return "Cryptographic operation failed";
        case DHT_ERROR_NOT_INIT:    return "DHT context not initialized";
        case DHT_ERROR_ALREADY_EXISTS: return "Item already exists";
        case DHT_ERROR_STORAGE:     return "Storage/persistence error";
        default:                    return "Unknown error";
    }
}

/**
 * Migration Note for Existing Code:
 *
 * Old pattern (inconsistent):
 *   return -1;  // Could mean any error
 *   return -2;  // Sometimes "not found", sometimes other errors
 *   return -3;  // Sometimes "auth failed", sometimes other errors
 *
 * New pattern (standardized):
 *   return DHT_ERROR_INVALID_PARAM;  // Clear meaning
 *   return DHT_ERROR_NOT_FOUND;      // Unambiguous
 *   return DHT_ERROR_AUTH_FAILED;    // Self-documenting
 *
 * Migration can be gradual - existing -1/-2/-3 return values will continue
 * to work, but new code should use these enums for clarity.
 */

#ifdef __cplusplus
}
#endif

#endif // DHT_ERRORS_H
