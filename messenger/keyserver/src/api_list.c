/*
 * API Handler: GET /list
 */

#include "keyserver.h"
#include "http_utils.h"
#include "rate_limit.h"
#include "db.h"
#include <string.h>

enum MHD_Result api_list_handler(struct MHD_Connection *connection, sqlite3 *db_conn,
                                  const char *url) {
    char client_ip[46];

    // Get client IP
    if (http_get_client_ip(connection, client_ip, sizeof(client_ip)) != 0) {
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Failed to get client IP");
    }

    // Rate limiting
    if (!rate_limit_check(client_ip, RATE_LIMIT_TYPE_LIST)) {
        LOG_WARN("Rate limit exceeded for list: %s", client_ip);
        return http_send_error(connection, HTTP_TOO_MANY_REQUESTS, "Rate limit exceeded");
    }

    // Parse query parameters (limit, offset, search)
    int limit = 100;  // default
    int offset = 0;   // default
    const char *search = NULL;

    const char *limit_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
    const char *offset_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "offset");
    search = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "search");

    if (limit_str) {
        limit = atoi(limit_str);
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
    }

    if (offset_str) {
        offset = atoi(offset_str);
        if (offset < 0) offset = 0;
    }

    // Query database
    identity_t *identities = NULL;
    int count = 0;

    if (db_list_identities(db_conn, limit, offset, search, &identities, &count) != 0) {
        return http_send_error(connection, HTTP_INTERNAL_ERROR, "Database query failed");
    }

    // Get total count
    int total = db_count_identities(db_conn);

    // Build JSON response
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(true));
    json_object_object_add(response, "total", json_object_new_int(total));

    // Identities array
    json_object *identities_array = json_object_new_array();
    for (int i = 0; i < count; i++) {
        json_object *id_obj = json_object_new_object();
        json_object_object_add(id_obj, "dna", json_object_new_string(identities[i].dna));
        json_object_object_add(id_obj, "version", json_object_new_int(identities[i].version));
        json_object_object_add(id_obj, "registered_at", json_object_new_string(identities[i].registered_at));
        json_object_object_add(id_obj, "last_updated", json_object_new_string(identities[i].last_updated));

        json_object_array_add(identities_array, id_obj);
    }
    json_object_object_add(response, "identities", identities_array);

    // Pagination info
    json_object *pagination = json_object_new_object();
    json_object_object_add(pagination, "limit", json_object_new_int(limit));
    json_object_object_add(pagination, "offset", json_object_new_int(offset));
    json_object_object_add(pagination, "has_more", json_object_new_boolean(offset + count < total));
    json_object_object_add(response, "pagination", pagination);

    db_free_identities(identities, count);

    LOG_INFO("List: returned %d identities", count);
    return http_send_json_response(connection, HTTP_OK, response);
}
