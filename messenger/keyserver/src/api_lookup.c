/*
 * API Handler: GET /lookup/<identity>
 */

#include "keyserver.h"
#include "http_utils.h"
#include "rate_limit.h"
#include "db.h"
#include <string.h>

enum MHD_Result api_lookup_handler(struct MHD_Connection *connection, PGconn *db_conn,
                                    const char *dna) {
    char client_ip[46];

    // Get client IP
    if (http_get_client_ip(connection, client_ip, sizeof(client_ip)) != 0) {
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Failed to get client IP");
    }

    // Rate limiting
    if (!rate_limit_check(client_ip, RATE_LIMIT_TYPE_LOOKUP)) {
        LOG_WARN("Rate limit exceeded for lookup: %s", client_ip);
        return http_send_error(connection, HTTP_TOO_MANY_REQUESTS, "Rate limit exceeded");
    }

    // Query database
    identity_t identity;
    memset(&identity, 0, sizeof(identity));

    int result = db_lookup_identity(db_conn, dna, &identity);

    if (result == -2) {
        // Not found
        json_object *response = json_object_new_object();
        json_object_object_add(response, "success", json_object_new_boolean(false));
        json_object_object_add(response, "error", json_object_new_string("Identity not found"));
        json_object_object_add(response, "dna", json_object_new_string(dna));

        return http_send_json_response(connection, HTTP_NOT_FOUND, response);
    }

    if (result != 0) {
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Database query failed");
    }

    // Build JSON response
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(true));
    json_object_object_add(response, "dna", json_object_new_string(identity.dna));

    // Data object with full identity info
    json_object *data = json_object_new_object();
    json_object_object_add(data, "v", json_object_new_int(identity.schema_version));
    json_object_object_add(data, "dna", json_object_new_string(identity.dna));
    json_object_object_add(data, "dilithium_pub", json_object_new_string(identity.dilithium_pub));
    json_object_object_add(data, "kyber_pub", json_object_new_string(identity.kyber_pub));
    json_object_object_add(data, "cf20pub", json_object_new_string(identity.cf20pub));
    json_object_object_add(data, "version", json_object_new_int(identity.version));
    json_object_object_add(data, "updated_at", json_object_new_int(identity.updated_at));
    json_object_object_add(data, "sig", json_object_new_string(identity.sig));

    json_object_object_add(response, "data", data);
    json_object_object_add(response, "registered_at", json_object_new_string(identity.registered_at));
    json_object_object_add(response, "last_updated", json_object_new_string(identity.last_updated));

    db_free_identity(&identity);

    LOG_INFO("Lookup: %s found", dna);
    return http_send_json_response(connection, HTTP_OK, response);
}
