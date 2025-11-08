/*
 * Signature Verification - Dilithium3
 */

#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "keyserver.h"
#include <json-c/json.h>

/**
 * Verify Dilithium3 signature on JSON payload
 *
 * Calls the verify_json utility as a subprocess
 *
 * @param payload: JSON object (without "sig" field)
 * @param signature: Base64-encoded Dilithium3 signature
 * @param public_key: Base64-encoded Dilithium3 public key
 * @param verify_path: Path to verify_json binary
 * @param timeout: Timeout in seconds
 * @return 0 if valid, -1 if invalid, -2 on error
 */
int signature_verify(json_object *payload, const char *signature,
                    const char *public_key, const char *verify_path,
                    int timeout);

/**
 * Build canonical JSON string (without "sig" field)
 *
 * @param payload: JSON object with all fields including "sig"
 * @return Allocated JSON string without "sig" field (caller must free)
 */
char* signature_build_canonical_json(json_object *payload);

#endif // SIGNATURE_H
