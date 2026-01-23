/**
 * @file attestation.c
 * @brief Witness attestation serialization
 */

#include "dnac/nodus.h"
#include "dnac/witness.h"
#include <string.h>

int dnac_spend_request_serialize(const dnac_spend_request_t *request,
                                 uint8_t *buffer,
                                 size_t buffer_len,
                                 size_t *written_out) {
    if (!request || !buffer || !written_out) return -1;

    /* v0.4.0 format: tx_hash + tx_len + tx_data + sender_pubkey + signature + timestamp + fee
     * tx_len is variable, so we calculate size based on actual tx_len */
    size_t required = DNAC_TX_HASH_SIZE +      /* tx_hash */
                      4 +                       /* tx_len (uint32) */
                      request->tx_len +         /* tx_data (variable) */
                      DNAC_PUBKEY_SIZE +        /* sender_pubkey */
                      DNAC_SIGNATURE_SIZE +     /* signature */
                      8 +                       /* timestamp */
                      8;                        /* fee_amount */

    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    memcpy(p, request->tx_hash, DNAC_TX_HASH_SIZE); p += DNAC_TX_HASH_SIZE;

    /* tx_len as 4-byte little-endian */
    p[0] = (request->tx_len >> 0) & 0xFF;
    p[1] = (request->tx_len >> 8) & 0xFF;
    p[2] = (request->tx_len >> 16) & 0xFF;
    p[3] = (request->tx_len >> 24) & 0xFF;
    p += 4;

    /* tx_data (variable length) */
    memcpy(p, request->tx_data, request->tx_len); p += request->tx_len;

    memcpy(p, request->sender_pubkey, DNAC_PUBKEY_SIZE); p += DNAC_PUBKEY_SIZE;
    memcpy(p, request->signature, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    /* Little-endian timestamp */
    for (int i = 0; i < 8; i++) {
        p[i] = (request->timestamp >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* Little-endian fee */
    for (int i = 0; i < 8; i++) {
        p[i] = (request->fee_amount >> (i * 8)) & 0xFF;
    }
    p += 8;

    *written_out = required;
    return 0;
}

int dnac_spend_request_deserialize(const uint8_t *buffer,
                                   size_t buffer_len,
                                   dnac_spend_request_t *request_out) {
    if (!buffer || !request_out) return -1;

    /* v0.4.0: Minimum header size before tx_data */
    size_t min_header = DNAC_TX_HASH_SIZE + 4;  /* tx_hash + tx_len */
    if (buffer_len < min_header) return -1;

    const uint8_t *p = buffer;
    memcpy(request_out->tx_hash, p, DNAC_TX_HASH_SIZE); p += DNAC_TX_HASH_SIZE;

    /* tx_len as 4-byte little-endian */
    request_out->tx_len = (uint32_t)p[0] |
                          ((uint32_t)p[1] << 8) |
                          ((uint32_t)p[2] << 16) |
                          ((uint32_t)p[3] << 24);
    p += 4;

    /* Validate tx_len doesn't exceed max */
    if (request_out->tx_len > DNAC_MAX_TX_SIZE) return -1;

    /* Calculate total required size */
    size_t required = DNAC_TX_HASH_SIZE + 4 + request_out->tx_len +
                      DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE + 16;
    if (buffer_len < required) return -1;

    /* tx_data (variable length) */
    memcpy(request_out->tx_data, p, request_out->tx_len); p += request_out->tx_len;

    memcpy(request_out->sender_pubkey, p, DNAC_PUBKEY_SIZE); p += DNAC_PUBKEY_SIZE;
    memcpy(request_out->signature, p, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    request_out->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        request_out->timestamp |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    request_out->fee_amount = 0;
    for (int i = 0; i < 8; i++) {
        request_out->fee_amount |= ((uint64_t)p[i]) << (i * 8);
    }

    return 0;
}

int dnac_spend_response_serialize(const dnac_spend_response_t *response,
                                  uint8_t *buffer,
                                  size_t buffer_len,
                                  size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* v3 format: status + witness_id + signature + timestamp + server_pubkey + version + error_message */
    size_t required = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE + 3 + 256;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    *p++ = (uint8_t)response->status;
    memcpy(p, response->witness_id, 32); p += 32;
    memcpy(p, response->signature, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    for (int i = 0; i < 8; i++) {
        p[i] = (response->timestamp >> (i * 8)) & 0xFF;
    }
    p += 8;

    memcpy(p, response->server_pubkey, DNAC_PUBKEY_SIZE); p += DNAC_PUBKEY_SIZE;
    memcpy(p, response->software_version, 3); p += 3;

    memcpy(p, response->error_message, 256);

    *written_out = required;
    return 0;
}

int dnac_spend_response_deserialize(const uint8_t *buffer,
                                    size_t buffer_len,
                                    dnac_spend_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    /* v3 format: status + witness_id + signature + timestamp + server_pubkey + version + error_message */
    size_t required_v3 = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE + 3 + 256;
    size_t required_v2 = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE + 256;
    size_t required_v1 = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + 256;  /* old format without pubkey */

    bool has_version = (buffer_len >= required_v3);
    bool has_pubkey = (buffer_len >= required_v2);
    if (buffer_len < required_v1) return -1;

    const uint8_t *p = buffer;
    response_out->status = (dnac_nodus_status_t)*p++;
    memcpy(response_out->witness_id, p, 32); p += 32;
    memcpy(response_out->signature, p, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    response_out->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        response_out->timestamp |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    if (has_pubkey) {
        memcpy(response_out->server_pubkey, p, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
    } else {
        memset(response_out->server_pubkey, 0, DNAC_PUBKEY_SIZE);
    }

    if (has_version) {
        memcpy(response_out->software_version, p, 3);
        p += 3;
    } else {
        memset(response_out->software_version, 0, 3);
    }

    memcpy(response_out->error_message, p, 256);
    response_out->error_message[255] = '\0';

    return 0;
}

/* ============================================================================
 * Witness Announcement Serialization
 * ========================================================================== */

int witness_announcement_serialize(const dnac_witness_announcement_t *announcement,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out) {
    if (!announcement || !buffer || !written_out) return -1;

    size_t required = DNAC_ANNOUNCEMENT_SERIALIZED_SIZE;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    /* Version (1 byte) */
    *p++ = announcement->version;

    /* Witness ID (32 bytes) */
    memcpy(p, announcement->witness_id, 32);
    p += 32;

    /* Current epoch (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (announcement->current_epoch >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* Epoch duration (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (announcement->epoch_duration >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* Timestamp (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (announcement->timestamp >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* Software version (3 bytes) */
    memcpy(p, announcement->software_version, 3);
    p += 3;

    /* Witness public key (2592 bytes) */
    memcpy(p, announcement->witness_pubkey, DNAC_PUBKEY_SIZE);
    p += DNAC_PUBKEY_SIZE;

    /* Signature (4627 bytes) */
    memcpy(p, announcement->signature, DNAC_SIGNATURE_SIZE);

    *written_out = required;
    return 0;
}

int witness_announcement_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_witness_announcement_t *announcement_out) {
    if (!buffer || !announcement_out) return -1;

    size_t required = DNAC_ANNOUNCEMENT_SERIALIZED_SIZE;
    if (buffer_len < required) return -1;

    const uint8_t *p = buffer;

    /* Version (1 byte) */
    announcement_out->version = *p++;

    /* Witness ID (32 bytes) */
    memcpy(announcement_out->witness_id, p, 32);
    p += 32;

    /* Current epoch (8 bytes, little-endian) */
    announcement_out->current_epoch = 0;
    for (int i = 0; i < 8; i++) {
        announcement_out->current_epoch |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    /* Epoch duration (8 bytes, little-endian) */
    announcement_out->epoch_duration = 0;
    for (int i = 0; i < 8; i++) {
        announcement_out->epoch_duration |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    /* Timestamp (8 bytes, little-endian) */
    announcement_out->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        announcement_out->timestamp |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    /* Software version (3 bytes) - optional for backward compat */
    if (buffer_len >= DNAC_ANNOUNCEMENT_SERIALIZED_SIZE) {
        memcpy(announcement_out->software_version, p, 3);
        p += 3;
    } else {
        memset(announcement_out->software_version, 0, 3);
    }

    /* Witness public key (2592 bytes) */
    memcpy(announcement_out->witness_pubkey, p, DNAC_PUBKEY_SIZE);
    p += DNAC_PUBKEY_SIZE;

    /* Signature (4627 bytes) */
    memcpy(announcement_out->signature, p, DNAC_SIGNATURE_SIZE);

    return 0;
}
