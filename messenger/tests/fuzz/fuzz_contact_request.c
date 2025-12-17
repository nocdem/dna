/**
 * @file fuzz_contact_request.c
 * @brief libFuzzer harness for DHT contact request deserialization
 *
 * Fuzzes dht_deserialize_contact_request() which parses binary-formatted
 * contact requests from the DHT.
 *
 * Request Format:
 * [4-byte magic "DNAR"][1-byte version][8-byte timestamp][8-byte expiry]
 * [129-byte sender_fingerprint][64-byte sender_name][2592-byte dilithium_pubkey]
 * [256-byte message][2-byte sig_len][signature bytes]
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dht/shared/dht_contact_request.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    dht_contact_request_t request;
    memset(&request, 0, sizeof(request));

    /* This function should handle malformed input gracefully */
    /* No dynamic allocations in dht_contact_request_t, so no cleanup needed */
    dht_deserialize_contact_request(data, size, &request);

    return 0;
}
