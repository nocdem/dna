/*
 * HTTP Response Utilities
 */

#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <microhttpd.h>
#include <json-c/json.h>

/**
 * Send JSON response
 *
 * @param connection: MHD connection
 * @param status_code: HTTP status code
 * @param json_obj: JSON object to send (will be freed)
 * @return MHD result code
 */
int http_send_json_response(struct MHD_Connection *connection,
                            int status_code, json_object *json_obj);

/**
 * Send error response
 *
 * @param connection: MHD connection
 * @param status_code: HTTP status code
 * @param error_msg: Error message
 * @return MHD result code
 */
int http_send_error(struct MHD_Connection *connection,
                   int status_code, const char *error_msg);

/**
 * Send success response with message
 *
 * @param connection: MHD connection
 * @param message: Success message
 * @return MHD result code
 */
int http_send_success(struct MHD_Connection *connection, const char *message);

/**
 * Get client IP address from connection
 *
 * @param connection: MHD connection
 * @param ip_buf: Buffer to store IP address
 * @param ip_len: Size of buffer
 * @return 0 on success, -1 on error
 */
int http_get_client_ip(struct MHD_Connection *connection,
                      char *ip_buf, size_t ip_len);

/**
 * Parse JSON from POST data
 *
 * @param upload_data: Raw POST data
 * @param upload_data_size: Size of POST data
 * @return Parsed JSON object or NULL on error
 */
json_object* http_parse_json_post(const char *upload_data,
                                  size_t upload_data_size);

#endif // HTTP_UTILS_H
