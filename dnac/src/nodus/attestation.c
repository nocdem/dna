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

    /* Calculate required size */
    size_t required = DNAC_TX_HASH_SIZE +      /* tx_hash */
                      DNAC_NULLIFIER_SIZE +     /* nullifier */
                      DNAC_PUBKEY_SIZE +        /* sender_pubkey */
                      DNAC_SIGNATURE_SIZE +     /* signature */
                      8 +                       /* timestamp */
                      8;                        /* fee_amount */

    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    memcpy(p, request->tx_hash, DNAC_TX_HASH_SIZE); p += DNAC_TX_HASH_SIZE;
    memcpy(p, request->nullifier, DNAC_NULLIFIER_SIZE); p += DNAC_NULLIFIER_SIZE;
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

    size_t required = DNAC_TX_HASH_SIZE + DNAC_NULLIFIER_SIZE +
                      DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE + 16;

    if (buffer_len < required) return -1;

    const uint8_t *p = buffer;
    memcpy(request_out->tx_hash, p, DNAC_TX_HASH_SIZE); p += DNAC_TX_HASH_SIZE;
    memcpy(request_out->nullifier, p, DNAC_NULLIFIER_SIZE); p += DNAC_NULLIFIER_SIZE;
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

    size_t required = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + 256;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    *p++ = (uint8_t)response->status;
    memcpy(p, response->witness_id, 32); p += 32;
    memcpy(p, response->signature, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    for (int i = 0; i < 8; i++) {
        p[i] = (response->timestamp >> (i * 8)) & 0xFF;
    }
    p += 8;

    memcpy(p, response->error_message, 256);

    *written_out = required;
    return 0;
}

int dnac_spend_response_deserialize(const uint8_t *buffer,
                                    size_t buffer_len,
                                    dnac_spend_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t required = 1 + 32 + DNAC_SIGNATURE_SIZE + 8 + 256;
    if (buffer_len < required) return -1;

    const uint8_t *p = buffer;
    response_out->status = (dnac_nodus_status_t)*p++;
    memcpy(response_out->witness_id, p, 32); p += 32;
    memcpy(response_out->signature, p, DNAC_SIGNATURE_SIZE); p += DNAC_SIGNATURE_SIZE;

    response_out->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        response_out->timestamp |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

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

    /* Witness public key (2592 bytes) */
    memcpy(announcement_out->witness_pubkey, p, DNAC_PUBKEY_SIZE);
    p += DNAC_PUBKEY_SIZE;

    /* Signature (4627 bytes) */
    memcpy(announcement_out->signature, p, DNAC_SIGNATURE_SIZE);

    return 0;
}
