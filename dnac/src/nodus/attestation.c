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

    /* Safe size calculation (Gap 9: v0.6.0) */
    const size_t fixed_size = DNAC_TX_HASH_SIZE + 4 + DNAC_PUBKEY_SIZE +
                              DNAC_SIGNATURE_SIZE + 8 + 8;

    /* Check for overflow: tx_len + fixed_size */
    if (request->tx_len > SIZE_MAX - fixed_size) {
        return -1;  /* Integer overflow */
    }

    size_t required = fixed_size + request->tx_len;

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

/* ============================================================================
 * v0.5.0: Ledger Query Serialization
 * ========================================================================== */

int dnac_ledger_query_serialize(const dnac_ledger_query_t *query,
                                uint8_t *buffer,
                                size_t buffer_len,
                                size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: tx_hash (64) + include_proof (1) = 65 bytes */
    size_t required = DNAC_TX_HASH_SIZE + 1;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    memcpy(p, query->tx_hash, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;
    *p = query->include_proof ? 1 : 0;

    *written_out = required;
    return 0;
}

int dnac_ledger_query_deserialize(const uint8_t *buffer,
                                  size_t buffer_len,
                                  dnac_ledger_query_t *query_out) {
    if (!buffer || !query_out) return -1;

    size_t required = DNAC_TX_HASH_SIZE + 1;
    if (buffer_len < required) return -1;

    const uint8_t *p = buffer;
    memcpy(query_out->tx_hash, p, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;
    query_out->include_proof = (*p != 0);

    return 0;
}

int dnac_ledger_response_serialize(const dnac_ledger_response_t *response,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status (1) + seq (8) + tx_hash (64) + tx_type (1) + merkle_root (64) +
     *         timestamp (8) + epoch (8) + has_proof (1) + leaf_hash (64) +
     *         proof_length (4) + proof_root (64) = 287 bytes */
    size_t required = 1 + 8 + 64 + 1 + 64 + 8 + 8 + 1 + 64 + 4 + 64;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;

    /* sequence_number (little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (response->sequence_number >> (i * 8)) & 0xFF;
    }
    p += 8;

    memcpy(p, response->tx_hash, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;

    *p++ = response->tx_type;

    memcpy(p, response->merkle_root, 64);
    p += 64;

    /* timestamp (little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (response->timestamp >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* epoch (little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (response->epoch >> (i * 8)) & 0xFF;
    }
    p += 8;

    *p++ = response->has_proof ? 1 : 0;

    memcpy(p, response->leaf_hash, 64);
    p += 64;

    /* proof_length (little-endian) */
    for (int i = 0; i < 4; i++) {
        p[i] = (response->proof_length >> (i * 8)) & 0xFF;
    }
    p += 4;

    memcpy(p, response->proof_root, 64);

    *written_out = required;
    return 0;
}

int dnac_ledger_response_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_ledger_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t required = 1 + 8 + 64 + 1 + 64 + 8 + 8 + 1 + 64 + 4 + 64;
    if (buffer_len < required) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;

    response_out->sequence_number = 0;
    for (int i = 0; i < 8; i++) {
        response_out->sequence_number |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    memcpy(response_out->tx_hash, p, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;

    response_out->tx_type = *p++;

    memcpy(response_out->merkle_root, p, 64);
    p += 64;

    response_out->timestamp = 0;
    for (int i = 0; i < 8; i++) {
        response_out->timestamp |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    response_out->epoch = 0;
    for (int i = 0; i < 8; i++) {
        response_out->epoch |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    response_out->has_proof = (*p++ != 0);

    memcpy(response_out->leaf_hash, p, 64);
    p += 64;

    response_out->proof_length = 0;
    for (int i = 0; i < 4; i++) {
        response_out->proof_length |= ((int)p[i]) << (i * 8);
    }
    p += 4;

    memcpy(response_out->proof_root, p, 64);

    return 0;
}

/* ============================================================================
 * v0.5.0: Supply Query Serialization
 * ========================================================================== */

int dnac_supply_query_serialize(const dnac_supply_query_t *query,
                                uint8_t *buffer,
                                size_t buffer_len,
                                size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: padding (1) = 1 byte */
    if (buffer_len < 1) return -1;

    buffer[0] = query->padding;
    *written_out = 1;
    return 0;
}

int dnac_supply_query_deserialize(const uint8_t *buffer,
                                  size_t buffer_len,
                                  dnac_supply_query_t *query_out) {
    if (!buffer || !query_out) return -1;
    if (buffer_len < 1) return -1;

    query_out->padding = buffer[0];
    return 0;
}

int dnac_supply_response_serialize(const dnac_supply_response_t *response,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status (1) + genesis_supply (8) + total_burned (8) +
     *         current_supply (8) + last_tx_hash (64) + last_sequence (8) = 97 bytes */
    size_t required = 1 + 8 + 8 + 8 + 64 + 8;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;

    for (int i = 0; i < 8; i++) p[i] = (response->genesis_supply >> (i * 8)) & 0xFF;
    p += 8;

    for (int i = 0; i < 8; i++) p[i] = (response->total_burned >> (i * 8)) & 0xFF;
    p += 8;

    for (int i = 0; i < 8; i++) p[i] = (response->current_supply >> (i * 8)) & 0xFF;
    p += 8;

    memcpy(p, response->last_tx_hash, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;

    for (int i = 0; i < 8; i++) p[i] = (response->last_sequence >> (i * 8)) & 0xFF;

    *written_out = required;
    return 0;
}

int dnac_supply_response_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_supply_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t required = 1 + 8 + 8 + 8 + 64 + 8;
    if (buffer_len < required) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;

    for (int i = 0; i < 8; i++) response_out->genesis_supply |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    for (int i = 0; i < 8; i++) response_out->total_burned |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    for (int i = 0; i < 8; i++) response_out->current_supply |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    memcpy(response_out->last_tx_hash, p, DNAC_TX_HASH_SIZE);
    p += DNAC_TX_HASH_SIZE;

    for (int i = 0; i < 8; i++) response_out->last_sequence |= ((uint64_t)p[i]) << (i * 8);

    return 0;
}

/* ============================================================================
 * v0.5.0: UTXO Query Serialization
 * ========================================================================== */

int dnac_utxo_query_serialize(const dnac_utxo_query_t *query,
                              uint8_t *buffer,
                              size_t buffer_len,
                              size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: owner_commitment (64) + max_results (4) = 68 bytes */
    size_t required = 64 + 4;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;
    memcpy(p, query->owner_commitment, 64);
    p += 64;

    for (int i = 0; i < 4; i++) p[i] = (query->max_results >> (i * 8)) & 0xFF;

    *written_out = required;
    return 0;
}

int dnac_utxo_query_deserialize(const uint8_t *buffer,
                                size_t buffer_len,
                                dnac_utxo_query_t *query_out) {
    if (!buffer || !query_out) return -1;

    size_t required = 64 + 4;
    if (buffer_len < required) return -1;

    const uint8_t *p = buffer;
    memcpy(query_out->owner_commitment, p, 64);
    p += 64;

    query_out->max_results = 0;
    for (int i = 0; i < 4; i++) query_out->max_results |= ((int)p[i]) << (i * 8);

    return 0;
}

int dnac_utxo_response_serialize(const dnac_utxo_response_t *response,
                                 uint8_t *buffer,
                                 size_t buffer_len,
                                 size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status (1) + count (4) + entries (count * (64 + 64 + 4 + 8 + 8)) */
    size_t entry_size = 64 + 64 + 4 + 8 + 8;  /* 148 bytes per entry */
    size_t required = 1 + 4 + (response->count * entry_size);
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;

    for (int i = 0; i < 4; i++) p[i] = (response->count >> (i * 8)) & 0xFF;
    p += 4;

    for (int i = 0; i < response->count && i < DNAC_MAX_UTXO_QUERY_RESULTS; i++) {
        const dnac_utxo_entry_t *e = &response->utxos[i];

        memcpy(p, e->commitment, 64);
        p += 64;

        memcpy(p, e->tx_hash, DNAC_TX_HASH_SIZE);
        p += DNAC_TX_HASH_SIZE;

        for (int j = 0; j < 4; j++) p[j] = (e->output_index >> (j * 8)) & 0xFF;
        p += 4;

        for (int j = 0; j < 8; j++) p[j] = (e->amount >> (j * 8)) & 0xFF;
        p += 8;

        for (int j = 0; j < 8; j++) p[j] = (e->created_epoch >> (j * 8)) & 0xFF;
        p += 8;
    }

    *written_out = required;
    return 0;
}

int dnac_utxo_response_deserialize(const uint8_t *buffer,
                                   size_t buffer_len,
                                   dnac_utxo_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    if (buffer_len < 5) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;

    response_out->count = 0;
    for (int i = 0; i < 4; i++) response_out->count |= ((int)p[i]) << (i * 8);
    p += 4;

    if (response_out->count > DNAC_MAX_UTXO_QUERY_RESULTS) {
        response_out->count = DNAC_MAX_UTXO_QUERY_RESULTS;
    }

    size_t entry_size = 64 + 64 + 4 + 8 + 8;
    size_t required = 5 + (response_out->count * entry_size);
    if (buffer_len < required) return -1;

    for (int i = 0; i < response_out->count; i++) {
        dnac_utxo_entry_t *e = &response_out->utxos[i];

        memcpy(e->commitment, p, 64);
        p += 64;

        memcpy(e->tx_hash, p, DNAC_TX_HASH_SIZE);
        p += DNAC_TX_HASH_SIZE;

        e->output_index = 0;
        for (int j = 0; j < 4; j++) e->output_index |= ((uint32_t)p[j]) << (j * 8);
        p += 4;

        e->amount = 0;
        for (int j = 0; j < 8; j++) e->amount |= ((uint64_t)p[j]) << (j * 8);
        p += 8;

        e->created_epoch = 0;
        for (int j = 0; j < 8; j++) e->created_epoch |= ((uint64_t)p[j]) << (j * 8);
        p += 8;
    }

    return 0;
}

/* ============================================================================
 * v0.5.0: UTXO Proof Query Serialization
 * ========================================================================== */

int dnac_utxo_proof_query_serialize(const dnac_utxo_proof_query_t *query,
                                    uint8_t *buffer,
                                    size_t buffer_len,
                                    size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: commitment (64) = 64 bytes */
    if (buffer_len < 64) return -1;

    memcpy(buffer, query->commitment, 64);
    *written_out = 64;
    return 0;
}

int dnac_utxo_proof_query_deserialize(const uint8_t *buffer,
                                      size_t buffer_len,
                                      dnac_utxo_proof_query_t *query_out) {
    if (!buffer || !query_out) return -1;
    if (buffer_len < 64) return -1;

    memcpy(query_out->commitment, buffer, 64);
    return 0;
}

int dnac_utxo_proof_response_serialize(const dnac_utxo_proof_response_t *response,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status (1) + exists (1) + commitment (64) + root (64) + epoch (8) = 138 bytes */
    size_t required = 1 + 1 + 64 + 64 + 8;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;
    *p++ = response->exists ? 1 : 0;

    memcpy(p, response->commitment, 64);
    p += 64;

    memcpy(p, response->root, 64);
    p += 64;

    for (int i = 0; i < 8; i++) p[i] = (response->epoch >> (i * 8)) & 0xFF;

    *written_out = required;
    return 0;
}

int dnac_utxo_proof_response_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_utxo_proof_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t required = 1 + 1 + 64 + 64 + 8;
    if (buffer_len < required) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;
    response_out->exists = (*p++ != 0);

    memcpy(response_out->commitment, p, 64);
    p += 64;

    memcpy(response_out->root, p, 64);
    p += 64;

    for (int i = 0; i < 8; i++) response_out->epoch |= ((uint64_t)p[i]) << (i * 8);

    return 0;
}

/* ============================================================================
 * v0.5.0: Nullifier Check Serialization
 * ========================================================================== */

int dnac_nullifier_query_serialize(const dnac_nullifier_query_t *query,
                                    uint8_t *buffer,
                                    size_t buffer_len,
                                    size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: nullifier (64 bytes) */
    size_t required = DNAC_NULLIFIER_SIZE;
    if (buffer_len < required) return -1;

    memcpy(buffer, query->nullifier, DNAC_NULLIFIER_SIZE);

    *written_out = required;
    return 0;
}

int dnac_nullifier_query_deserialize(const uint8_t *buffer,
                                      size_t buffer_len,
                                      dnac_nullifier_query_t *query_out) {
    if (!buffer || !query_out) return -1;

    if (buffer_len < DNAC_NULLIFIER_SIZE) return -1;

    memset(query_out, 0, sizeof(*query_out));
    memcpy(query_out->nullifier, buffer, DNAC_NULLIFIER_SIZE);

    return 0;
}

int dnac_nullifier_response_serialize(const dnac_nullifier_response_t *response,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status (1) + is_spent (1) + nullifier (64) + spent_epoch (8) = 74 bytes */
    size_t required = 1 + 1 + DNAC_NULLIFIER_SIZE + 8;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;
    *p++ = response->is_spent ? 1 : 0;

    memcpy(p, response->nullifier, DNAC_NULLIFIER_SIZE);
    p += DNAC_NULLIFIER_SIZE;

    for (int i = 0; i < 8; i++) p[i] = (response->spent_epoch >> (i * 8)) & 0xFF;

    *written_out = required;
    return 0;
}

int dnac_nullifier_response_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_nullifier_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t required = 1 + 1 + DNAC_NULLIFIER_SIZE + 8;
    if (buffer_len < required) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;
    response_out->is_spent = (*p++ != 0);

    memcpy(response_out->nullifier, p, DNAC_NULLIFIER_SIZE);
    p += DNAC_NULLIFIER_SIZE;

    for (int i = 0; i < 8; i++) response_out->spent_epoch |= ((uint64_t)p[i]) << (i * 8);

    return 0;
}

/* ============================================================================
 * P0-2 (v0.7.0): Ledger Range Query Serialization
 * ========================================================================== */

int dnac_ledger_range_query_serialize(const dnac_ledger_range_query_t *query,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out) {
    if (!query || !buffer || !written_out) return -1;

    /* Format: from_sequence (8) + to_sequence (8) + include_proofs (1) = 17 bytes */
    size_t required = 8 + 8 + 1;
    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    /* from_sequence (little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (query->from_sequence >> (i * 8)) & 0xFF;
    }
    p += 8;

    /* to_sequence (little-endian) */
    for (int i = 0; i < 8; i++) {
        p[i] = (query->to_sequence >> (i * 8)) & 0xFF;
    }
    p += 8;

    *p = query->include_proofs ? 1 : 0;

    *written_out = required;
    return 0;
}

int dnac_ledger_range_query_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_ledger_range_query_t *query_out) {
    if (!buffer || !query_out) return -1;

    size_t required = 8 + 8 + 1;
    if (buffer_len < required) return -1;

    memset(query_out, 0, sizeof(*query_out));
    const uint8_t *p = buffer;

    /* from_sequence (little-endian) */
    for (int i = 0; i < 8; i++) {
        query_out->from_sequence |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    /* to_sequence (little-endian) */
    for (int i = 0; i < 8; i++) {
        query_out->to_sequence |= ((uint64_t)p[i]) << (i * 8);
    }
    p += 8;

    query_out->include_proofs = (*p != 0);

    return 0;
}

/* Range entry size: seq(8) + tx_hash(64) + tx_type(1) + merkle_root(64) + timestamp(8) + epoch(8) = 153 bytes */
#define RANGE_ENTRY_SIZE (8 + 64 + 1 + 64 + 8 + 8)

int dnac_ledger_range_response_serialize(const dnac_ledger_range_response_t *response,
                                          uint8_t *buffer,
                                          size_t buffer_len,
                                          size_t *written_out) {
    if (!response || !buffer || !written_out) return -1;

    /* Format: status(1) + first_seq(8) + last_seq(8) + total_entries(8) + count(4) + entries */
    size_t header_size = 1 + 8 + 8 + 8 + 4;
    size_t entries_size = response->count * RANGE_ENTRY_SIZE;
    size_t required = header_size + entries_size;

    if (buffer_len < required) return -1;

    uint8_t *p = buffer;

    *p++ = (uint8_t)response->status;

    for (int i = 0; i < 8; i++) p[i] = (response->first_sequence >> (i * 8)) & 0xFF;
    p += 8;

    for (int i = 0; i < 8; i++) p[i] = (response->last_sequence >> (i * 8)) & 0xFF;
    p += 8;

    for (int i = 0; i < 8; i++) p[i] = (response->total_entries >> (i * 8)) & 0xFF;
    p += 8;

    for (int i = 0; i < 4; i++) p[i] = (response->count >> (i * 8)) & 0xFF;
    p += 4;

    /* Serialize each entry */
    for (int i = 0; i < response->count && i < DNAC_MAX_RANGE_RESULTS; i++) {
        const dnac_ledger_range_entry_t *e = &response->entries[i];

        for (int j = 0; j < 8; j++) p[j] = (e->sequence_number >> (j * 8)) & 0xFF;
        p += 8;

        memcpy(p, e->tx_hash, DNAC_TX_HASH_SIZE);
        p += DNAC_TX_HASH_SIZE;

        *p++ = e->tx_type;

        memcpy(p, e->merkle_root, 64);
        p += 64;

        for (int j = 0; j < 8; j++) p[j] = (e->timestamp >> (j * 8)) & 0xFF;
        p += 8;

        for (int j = 0; j < 8; j++) p[j] = (e->epoch >> (j * 8)) & 0xFF;
        p += 8;
    }

    *written_out = required;
    return 0;
}

int dnac_ledger_range_response_deserialize(const uint8_t *buffer,
                                            size_t buffer_len,
                                            dnac_ledger_range_response_t *response_out) {
    if (!buffer || !response_out) return -1;

    size_t header_size = 1 + 8 + 8 + 8 + 4;
    if (buffer_len < header_size) return -1;

    memset(response_out, 0, sizeof(*response_out));
    const uint8_t *p = buffer;

    response_out->status = (dnac_nodus_status_t)*p++;

    for (int i = 0; i < 8; i++) response_out->first_sequence |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    for (int i = 0; i < 8; i++) response_out->last_sequence |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    for (int i = 0; i < 8; i++) response_out->total_entries |= ((uint64_t)p[i]) << (i * 8);
    p += 8;

    for (int i = 0; i < 4; i++) response_out->count |= ((int)p[i]) << (i * 8);
    p += 4;

    /* Clamp count to max */
    if (response_out->count > DNAC_MAX_RANGE_RESULTS) {
        response_out->count = DNAC_MAX_RANGE_RESULTS;
    }

    /* Verify buffer has enough data for entries */
    size_t required = header_size + (response_out->count * RANGE_ENTRY_SIZE);
    if (buffer_len < required) return -1;

    /* Deserialize each entry */
    for (int i = 0; i < response_out->count; i++) {
        dnac_ledger_range_entry_t *e = &response_out->entries[i];

        e->sequence_number = 0;
        for (int j = 0; j < 8; j++) e->sequence_number |= ((uint64_t)p[j]) << (j * 8);
        p += 8;

        memcpy(e->tx_hash, p, DNAC_TX_HASH_SIZE);
        p += DNAC_TX_HASH_SIZE;

        e->tx_type = *p++;

        memcpy(e->merkle_root, p, 64);
        p += 64;

        e->timestamp = 0;
        for (int j = 0; j < 8; j++) e->timestamp |= ((uint64_t)p[j]) << (j * 8);
        p += 8;

        e->epoch = 0;
        for (int j = 0; j < 8; j++) e->epoch |= ((uint64_t)p[j]) << (j * 8);
        p += 8;
    }

    return 0;
}
