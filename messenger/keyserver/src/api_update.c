/*
 * API Handler: POST /update
 */

#include "keyserver.h"
#include "http_utils.h"
#include "rate_limit.h"
#include "validation.h"
#include "signature.h"
#include "db.h"
#include <string.h>

enum MHD_Result api_update_handler(struct MHD_Connection *connection, PGconn *db_conn,
                                     const char *upload_data, size_t upload_data_size) {
    char client_ip[46];
    char error_msg[512];

    // Get client IP
    if (http_get_client_ip(connection, client_ip, sizeof(client_ip)) != 0) {
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Failed to get client IP");
    }

    // Rate limiting (use same limit as register)
    if (!rate_limit_check(client_ip, RATE_LIMIT_TYPE_REGISTER)) {
        LOG_WARN("Rate limit exceeded for update: %s", client_ip);
        return http_send_error(connection, HTTP_TOO_MANY_REQUESTS, "Rate limit exceeded");
    }

    // Parse JSON payload
    json_object *payload = http_parse_json_post(upload_data, upload_data_size);
    if (!payload) {
        return http_send_error(connection, HTTP_BAD_REQUEST, "Invalid JSON");
    }

    // Validate payload structure
    if (validate_register_payload(payload, error_msg, sizeof(error_msg)) != 0) {
        LOG_WARN("Validation failed: %s", error_msg);
        json_object_put(payload);
        return http_send_error(connection, HTTP_BAD_REQUEST, error_msg);
    }

    // Extract fields
    json_object *field;
    json_object_object_get_ex(payload, "dna", &field);
    const char *dna = json_object_get_string(field);

    json_object_object_get_ex(payload, "dilithium_pub", &field);
    const char *dilithium_pub = json_object_get_string(field);

    json_object_object_get_ex(payload, "kyber_pub", &field);
    const char *kyber_pub = json_object_get_string(field);

    json_object_object_get_ex(payload, "cf20pub", &field);
    const char *cf20pub = json_object_get_string(field);

    json_object_object_get_ex(payload, "version", &field);
    int version = json_object_get_int(field);

    // For update, version must be > 1
    if (version <= 1) {
        LOG_WARN("Invalid update version: %d (must be > 1)", version);
        json_object_put(payload);
        return http_send_error(connection, HTTP_BAD_REQUEST, "Update version must be > 1");
    }

    json_object_object_get_ex(payload, "updated_at", &field);
    int updated_at = json_object_get_int(field);

    json_object_object_get_ex(payload, "sig", &field);
    const char *signature = json_object_get_string(field);

    // Verify signature
    LOG_INFO("Verifying signature for %s (update)", dna);
    int sig_result = signature_verify(payload, signature, dilithium_pub,
                                      g_config.verify_json_path,
                                      g_config.verify_timeout);

    if (sig_result == -1) {
        LOG_WARN("Invalid signature from %s", client_ip);
        json_object_put(payload);
        return http_send_error(connection, HTTP_BAD_REQUEST, "Invalid signature");
    }

    if (sig_result == -2) {
        LOG_ERROR("Signature verification error");
        json_object_put(payload);
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Signature verification error");
    }

    // Build identity structure
    identity_t identity;
    memset(&identity, 0, sizeof(identity));

    strncpy(identity.dna, dna, MAX_DNA_LENGTH);
    identity.dilithium_pub = (char*)dilithium_pub;
    identity.kyber_pub = (char*)kyber_pub;
    strncpy(identity.cf20pub, cf20pub, CF20_ADDRESS_LENGTH);
    identity.version = version;
    identity.updated_at = updated_at;
    identity.sig = (char*)signature;
    identity.schema_version = 1;

    // Update in database
    int db_result = db_update_identity(db_conn, &identity);

    if (db_result == -4) {
        // Not found
        snprintf(error_msg, sizeof(error_msg), "Identity not found. Use /api/keyserver/register to register first.");
        json_object_put(payload);
        return http_send_error(connection, HTTP_NOT_FOUND, error_msg);
    }

    if (db_result == -2) {
        // Version conflict
        snprintf(error_msg, sizeof(error_msg), "Version must be greater than current version");
        json_object_put(payload);
        return http_send_error(connection, HTTP_CONFLICT, error_msg);
    }

    if (db_result != 0) {
        LOG_ERROR("Database update failed");
        json_object_put(payload);
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Database error");
    }

    // Success response
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(true));
    json_object_object_add(response, "dna", json_object_new_string(dna));
    json_object_object_add(response, "version", json_object_new_int(version));
    json_object_object_add(response, "message", json_object_new_string("Identity updated successfully"));

    json_object_put(payload);

    LOG_INFO("Updated: %s (version %d)", dna, version);
    return http_send_json_response(connection, HTTP_OK, response);
}
