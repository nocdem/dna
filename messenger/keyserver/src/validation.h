/*
 * Request Validation
 */

#ifndef VALIDATION_H
#define VALIDATION_H

#include "keyserver.h"
#include <json-c/json.h>

/**
 * Validate registration payload
 *
 * @param payload: JSON payload from POST /register
 * @param error_msg: Buffer for error message (if validation fails)
 * @param error_len: Size of error message buffer
 * @return 0 if valid, -1 if invalid
 */
int validate_register_payload(json_object *payload, char *error_msg, size_t error_len);

/**
 * Validate DNA handle format
 *
 * @param dna: DNA handle string to validate
 * @return true if valid, false otherwise
 */
bool validate_dna(const char *dna);

/**
 * Validate timestamp (within allowed skew)
 *
 * @param timestamp: Unix timestamp from client
 * @param max_skew: Maximum allowed skew in seconds
 * @return true if valid, false otherwise
 */
bool validate_timestamp(int timestamp, int max_skew);

/**
 * Validate base64 string
 *
 * @param b64_str: Base64 string to validate
 * @return true if valid base64, false otherwise
 */
bool validate_base64(const char *b64_str);

#endif // VALIDATION_H
