/*
 * HTTP Response Utilities
 */

#include "http_utils.h"
#include "keyserver.h"
#include <string.h>
#include <arpa/inet.h>

int http_send_json_response(struct MHD_Connection *connection,
                            int status_code, json_object *json_obj) {
    const char *json_str = json_object_to_json_string_ext(json_obj,
                                                          JSON_C_TO_STRING_PLAIN);

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json_str),
        (void*)json_str,
        MHD_RESPMEM_MUST_COPY
    );

    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");

    int ret = MHD_queue_response(connection, status_code, response);

    MHD_destroy_response(response);
    json_object_put(json_obj);

    return ret;
}

int http_send_error(struct MHD_Connection *connection,
                   int status_code, const char *error_msg) {
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(false));
    json_object_object_add(response, "error", json_object_new_string(error_msg));

    return http_send_json_response(connection, status_code, response);
}

int http_send_success(struct MHD_Connection *connection, const char *message) {
    json_object *response = json_object_new_object();
    json_object_object_add(response, "success", json_object_new_boolean(true));
    json_object_object_add(response, "message", json_object_new_string(message));

    return http_send_json_response(connection, HTTP_OK, response);
}

int http_get_client_ip(struct MHD_Connection *connection,
                      char *ip_buf, size_t ip_len) {
    const union MHD_ConnectionInfo *info;

    info = MHD_get_connection_info(connection,
                                   MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (!info) {
        return -1;
    }

    struct sockaddr *addr = (struct sockaddr*)info->client_addr;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_buf, ip_len);
        return 0;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_buf, ip_len);
        return 0;
    }

    return -1;
}

json_object* http_parse_json_post(const char *upload_data,
                                  size_t upload_data_size) {
    if (!upload_data || upload_data_size == 0) {
        return NULL;
    }

    // Ensure null termination
    char *json_str = malloc(upload_data_size + 1);
    if (!json_str) {
        return NULL;
    }

    memcpy(json_str, upload_data, upload_data_size);
    json_str[upload_data_size] = '\0';

    json_object *obj = json_tokener_parse(json_str);
    free(json_str);

    return obj;
}
