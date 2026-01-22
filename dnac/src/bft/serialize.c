/**
 * @file serialize.c
 * @brief BFT Message Serialization
 *
 * Binary serialization for BFT consensus messages.
 * All multi-byte integers are stored in network byte order (big-endian).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <arpa/inet.h>

#include "dnac/bft.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "BFT_SERIALIZE"

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

static void write_u8(uint8_t **buf, uint8_t val) {
    **buf = val;
    (*buf)++;
}

static void write_u32(uint8_t **buf, uint32_t val) {
    uint32_t n = htonl(val);
    memcpy(*buf, &n, 4);
    *buf += 4;
}

static void write_u64(uint8_t **buf, uint64_t val) {
    uint32_t hi = htonl((uint32_t)(val >> 32));
    uint32_t lo = htonl((uint32_t)(val & 0xFFFFFFFF));
    memcpy(*buf, &hi, 4);
    memcpy(*buf + 4, &lo, 4);
    *buf += 8;
}

static void write_bytes(uint8_t **buf, const uint8_t *data, size_t len) {
    memcpy(*buf, data, len);
    *buf += len;
}

static void write_string(uint8_t **buf, const char *str, size_t max_len) {
    size_t len = strlen(str);
    if (len > max_len - 1) len = max_len - 1;
    memcpy(*buf, str, len);
    memset(*buf + len, 0, max_len - len);
    *buf += max_len;
}

static uint8_t read_u8(const uint8_t **buf) {
    uint8_t val = **buf;
    (*buf)++;
    return val;
}

static uint32_t read_u32(const uint8_t **buf) {
    uint32_t n;
    memcpy(&n, *buf, 4);
    *buf += 4;
    return ntohl(n);
}

static uint64_t read_u64(const uint8_t **buf) {
    uint32_t hi, lo;
    memcpy(&hi, *buf, 4);
    memcpy(&lo, *buf + 4, 4);
    *buf += 8;
    return ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
}

static void read_bytes(const uint8_t **buf, uint8_t *out, size_t len) {
    memcpy(out, *buf, len);
    *buf += len;
}

static void read_string(const uint8_t **buf, char *out, size_t max_len) {
    memcpy(out, *buf, max_len);
    out[max_len - 1] = '\0';
    *buf += max_len;
}

/* ============================================================================
 * Header Serialization
 * ========================================================================== */

/* Header size: 1 + 1 + 8 + 4 + 32 + 8 = 54 bytes */
#define BFT_HEADER_SIZE 54

int dnac_bft_header_serialize(const dnac_bft_msg_header_t *header,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written) {
    if (!header || !buffer || buffer_len < BFT_HEADER_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    write_u8(&p, header->version);
    write_u8(&p, (uint8_t)header->type);
    write_u64(&p, header->round);
    write_u32(&p, header->view);
    write_bytes(&p, header->sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    write_u64(&p, header->timestamp);

    if (written) *written = BFT_HEADER_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_header_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_msg_header_t *header) {
    if (!buffer || !header || buffer_len < BFT_HEADER_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;
    header->version = read_u8(&p);
    header->type = (dnac_bft_msg_type_t)read_u8(&p);
    header->round = read_u64(&p);
    header->view = read_u32(&p);
    read_bytes(&p, header->sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    header->timestamp = read_u64(&p);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Proposal Serialization
 * ========================================================================== */

/* Proposal size: header(54) + tx_hash(64) + nullifier(64) + pubkey(2592) +
 *                client_sig(4627) + fee(8) + sig(4627) = 12036 bytes */
#define BFT_PROPOSAL_SIZE (BFT_HEADER_SIZE + 64 + 64 + DNAC_PUBKEY_SIZE + \
                           DNAC_SIGNATURE_SIZE + 8 + DNAC_SIGNATURE_SIZE)

int dnac_bft_proposal_serialize(const dnac_bft_proposal_t *proposal,
                                uint8_t *buffer, size_t buffer_len,
                                size_t *written) {
    if (!proposal || !buffer || buffer_len < BFT_PROPOSAL_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    /* Serialize header */
    int rc = dnac_bft_header_serialize(&proposal->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    /* Serialize payload */
    write_bytes(&p, proposal->tx_hash, DNAC_TX_HASH_SIZE);
    write_bytes(&p, proposal->nullifier, DNAC_NULLIFIER_SIZE);
    write_bytes(&p, proposal->sender_pubkey, DNAC_PUBKEY_SIZE);
    write_bytes(&p, proposal->client_signature, DNAC_SIGNATURE_SIZE);
    write_u64(&p, proposal->fee_amount);
    write_bytes(&p, proposal->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = BFT_PROPOSAL_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_proposal_deserialize(const uint8_t *buffer, size_t buffer_len,
                                  dnac_bft_proposal_t *proposal) {
    if (!buffer || !proposal || buffer_len < BFT_PROPOSAL_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    /* Deserialize header */
    int rc = dnac_bft_header_deserialize(p, buffer_len, &proposal->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    /* Deserialize payload */
    read_bytes(&p, proposal->tx_hash, DNAC_TX_HASH_SIZE);
    read_bytes(&p, proposal->nullifier, DNAC_NULLIFIER_SIZE);
    read_bytes(&p, proposal->sender_pubkey, DNAC_PUBKEY_SIZE);
    read_bytes(&p, proposal->client_signature, DNAC_SIGNATURE_SIZE);
    proposal->fee_amount = read_u64(&p);
    read_bytes(&p, proposal->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Vote Serialization
 * ========================================================================== */

/* Vote size: header(54) + tx_hash(64) + vote(4) + reason(256) + sig(4627) = 5005 bytes */
#define BFT_VOTE_SIZE (BFT_HEADER_SIZE + 64 + 4 + 256 + DNAC_SIGNATURE_SIZE)

int dnac_bft_vote_serialize(const dnac_bft_vote_msg_t *vote,
                            uint8_t *buffer, size_t buffer_len,
                            size_t *written) {
    if (!vote || !buffer || buffer_len < BFT_VOTE_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    int rc = dnac_bft_header_serialize(&vote->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    write_bytes(&p, vote->tx_hash, DNAC_TX_HASH_SIZE);
    write_u32(&p, (uint32_t)vote->vote);
    write_string(&p, vote->reason, 256);
    write_bytes(&p, vote->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = BFT_VOTE_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_vote_deserialize(const uint8_t *buffer, size_t buffer_len,
                              dnac_bft_vote_msg_t *vote) {
    if (!buffer || !vote || buffer_len < BFT_VOTE_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    int rc = dnac_bft_header_deserialize(p, buffer_len, &vote->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    read_bytes(&p, vote->tx_hash, DNAC_TX_HASH_SIZE);
    vote->vote = (dnac_bft_vote_t)read_u32(&p);
    read_string(&p, vote->reason, 256);
    read_bytes(&p, vote->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Commit Serialization
 * ========================================================================== */

/* Commit size: header(54) + tx_hash(64) + nullifier(64) + n_precommits(4) + sig(4627) = 4813 bytes */
#define BFT_COMMIT_SIZE (BFT_HEADER_SIZE + 64 + 64 + 4 + DNAC_SIGNATURE_SIZE)

int dnac_bft_commit_serialize(const dnac_bft_commit_t *commit,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written) {
    if (!commit || !buffer || buffer_len < BFT_COMMIT_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    int rc = dnac_bft_header_serialize(&commit->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    write_bytes(&p, commit->tx_hash, DNAC_TX_HASH_SIZE);
    write_bytes(&p, commit->nullifier, DNAC_NULLIFIER_SIZE);
    write_u32(&p, commit->n_precommits);
    write_bytes(&p, commit->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = BFT_COMMIT_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_commit_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_commit_t *commit) {
    if (!buffer || !commit || buffer_len < BFT_COMMIT_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    int rc = dnac_bft_header_deserialize(p, buffer_len, &commit->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    read_bytes(&p, commit->tx_hash, DNAC_TX_HASH_SIZE);
    read_bytes(&p, commit->nullifier, DNAC_NULLIFIER_SIZE);
    commit->n_precommits = read_u32(&p);
    read_bytes(&p, commit->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * View Change Serialization
 * ========================================================================== */

/* View change size: header(54) + new_view(4) + last_committed(8) + sig(4627) = 4693 bytes */
#define BFT_VIEW_CHANGE_SIZE (BFT_HEADER_SIZE + 4 + 8 + DNAC_SIGNATURE_SIZE)

int dnac_bft_view_change_serialize(const dnac_bft_view_change_t *vc,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written) {
    if (!vc || !buffer || buffer_len < BFT_VIEW_CHANGE_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    int rc = dnac_bft_header_serialize(&vc->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    write_u32(&p, vc->new_view);
    write_u64(&p, vc->last_committed_round);
    write_bytes(&p, vc->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = BFT_VIEW_CHANGE_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_view_change_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_view_change_t *vc) {
    if (!buffer || !vc || buffer_len < BFT_VIEW_CHANGE_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    int rc = dnac_bft_header_deserialize(p, buffer_len, &vc->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    vc->new_view = read_u32(&p);
    vc->last_committed_round = read_u64(&p);
    read_bytes(&p, vc->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Roster Serialization
 * ========================================================================== */

/* Roster entry size: id(32) + pubkey(2592) + address(256) + joined_epoch(8) + active(1) = 2889 bytes */
#define BFT_ROSTER_ENTRY_SIZE (32 + DNAC_PUBKEY_SIZE + 256 + 8 + 1)

/* Roster header: version(4) + n_witnesses(4) = 8 bytes */
#define BFT_ROSTER_HEADER_SIZE 8

int dnac_bft_roster_serialize(const dnac_roster_t *roster,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written) {
    if (!roster || !buffer) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    size_t required = BFT_ROSTER_HEADER_SIZE +
                      (roster->n_witnesses * BFT_ROSTER_ENTRY_SIZE) +
                      DNAC_SIGNATURE_SIZE;

    if (buffer_len < required) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;

    /* Header */
    write_u32(&p, roster->version);
    write_u32(&p, roster->n_witnesses);

    /* Entries */
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        const dnac_roster_entry_t *e = &roster->witnesses[i];
        write_bytes(&p, e->witness_id, DNAC_BFT_WITNESS_ID_SIZE);
        write_bytes(&p, e->pubkey, DNAC_PUBKEY_SIZE);
        write_string(&p, e->address, DNAC_BFT_MAX_ADDRESS_LEN);
        write_u64(&p, e->joined_epoch);
        write_u8(&p, e->active ? 1 : 0);
    }

    /* Signature */
    write_bytes(&p, roster->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = required;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_roster_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_roster_t *roster) {
    if (!buffer || !roster || buffer_len < BFT_ROSTER_HEADER_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    roster->version = read_u32(&p);
    roster->n_witnesses = read_u32(&p);

    if (roster->n_witnesses > DNAC_BFT_MAX_WITNESSES) {
        QGP_LOG_ERROR(LOG_TAG, "Roster has too many witnesses: %u", roster->n_witnesses);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    size_t required = BFT_ROSTER_HEADER_SIZE +
                      (roster->n_witnesses * BFT_ROSTER_ENTRY_SIZE) +
                      DNAC_SIGNATURE_SIZE;

    if (buffer_len < required) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Entries */
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        dnac_roster_entry_t *e = &roster->witnesses[i];
        read_bytes(&p, e->witness_id, DNAC_BFT_WITNESS_ID_SIZE);
        read_bytes(&p, e->pubkey, DNAC_PUBKEY_SIZE);
        read_string(&p, e->address, DNAC_BFT_MAX_ADDRESS_LEN);
        e->joined_epoch = read_u64(&p);
        e->active = read_u8(&p) != 0;
    }

    /* Signature */
    read_bytes(&p, roster->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Forward Request Serialization
 * ========================================================================== */

/* Forward req: header(54) + tx_hash(64) + nullifier(64) + pubkey(2592) +
 *              client_sig(4627) + fee(8) + forwarder_id(32) + sig(4627) = 12068 bytes */
#define BFT_FORWARD_REQ_SIZE (BFT_HEADER_SIZE + 64 + 64 + DNAC_PUBKEY_SIZE + \
                              DNAC_SIGNATURE_SIZE + 8 + 32 + DNAC_SIGNATURE_SIZE)

int dnac_bft_forward_req_serialize(const dnac_bft_forward_req_t *req,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written) {
    if (!req || !buffer || buffer_len < BFT_FORWARD_REQ_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    int rc = dnac_bft_header_serialize(&req->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    write_bytes(&p, req->tx_hash, DNAC_TX_HASH_SIZE);
    write_bytes(&p, req->nullifier, DNAC_NULLIFIER_SIZE);
    write_bytes(&p, req->sender_pubkey, DNAC_PUBKEY_SIZE);
    write_bytes(&p, req->client_signature, DNAC_SIGNATURE_SIZE);
    write_u64(&p, req->fee_amount);
    write_bytes(&p, req->forwarder_id, DNAC_BFT_WITNESS_ID_SIZE);
    write_bytes(&p, req->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = BFT_FORWARD_REQ_SIZE;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_forward_req_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_req_t *req) {
    if (!buffer || !req || buffer_len < BFT_FORWARD_REQ_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    int rc = dnac_bft_header_deserialize(p, buffer_len, &req->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    read_bytes(&p, req->tx_hash, DNAC_TX_HASH_SIZE);
    read_bytes(&p, req->nullifier, DNAC_NULLIFIER_SIZE);
    read_bytes(&p, req->sender_pubkey, DNAC_PUBKEY_SIZE);
    read_bytes(&p, req->client_signature, DNAC_SIGNATURE_SIZE);
    req->fee_amount = read_u64(&p);
    read_bytes(&p, req->forwarder_id, DNAC_BFT_WITNESS_ID_SIZE);
    read_bytes(&p, req->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Forward Response Serialization
 * ========================================================================== */

/* Witness sig size: id(32) + sig(4627) + pubkey(2592) + ts(8) = 7259 bytes */
#define WITNESS_SIG_SIZE (32 + DNAC_SIGNATURE_SIZE + DNAC_PUBKEY_SIZE + 8)

/* Forward rsp base: header(54) + status(4) + tx_hash(64) + count(4) + sig(4627) = 4753 bytes */
#define BFT_FORWARD_RSP_BASE_SIZE (BFT_HEADER_SIZE + 4 + 64 + 4 + DNAC_SIGNATURE_SIZE)

int dnac_bft_forward_rsp_serialize(const dnac_bft_forward_rsp_t *rsp,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written) {
    if (!rsp || !buffer) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    size_t required = BFT_FORWARD_RSP_BASE_SIZE +
                      (rsp->witness_count * WITNESS_SIG_SIZE);

    if (buffer_len < required) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    uint8_t *p = buffer;
    size_t header_written;

    int rc = dnac_bft_header_serialize(&rsp->header, p, buffer_len, &header_written);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += header_written;

    write_u32(&p, (uint32_t)rsp->status);
    write_bytes(&p, rsp->tx_hash, DNAC_TX_HASH_SIZE);
    write_u32(&p, (uint32_t)rsp->witness_count);

    /* Witness signatures */
    for (int i = 0; i < rsp->witness_count; i++) {
        const dnac_witness_sig_t *w = &rsp->witnesses[i];
        write_bytes(&p, w->witness_id, 32);
        write_bytes(&p, w->signature, DNAC_SIGNATURE_SIZE);
        write_bytes(&p, w->server_pubkey, DNAC_PUBKEY_SIZE);
        write_u64(&p, w->timestamp);
    }

    write_bytes(&p, rsp->signature, DNAC_SIGNATURE_SIZE);

    if (written) *written = required;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_forward_rsp_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_rsp_t *rsp) {
    if (!buffer || !rsp || buffer_len < BFT_FORWARD_RSP_BASE_SIZE) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    const uint8_t *p = buffer;

    int rc = dnac_bft_header_deserialize(p, buffer_len, &rsp->header);
    if (rc != DNAC_BFT_SUCCESS) return rc;
    p += BFT_HEADER_SIZE;

    rsp->status = (int)read_u32(&p);
    read_bytes(&p, rsp->tx_hash, DNAC_TX_HASH_SIZE);
    rsp->witness_count = (int)read_u32(&p);

    if (rsp->witness_count > DNAC_TX_MAX_WITNESSES) {
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    size_t required = BFT_FORWARD_RSP_BASE_SIZE +
                      (rsp->witness_count * WITNESS_SIG_SIZE);

    if (buffer_len < required) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Witness signatures */
    for (int i = 0; i < rsp->witness_count; i++) {
        dnac_witness_sig_t *w = &rsp->witnesses[i];
        read_bytes(&p, w->witness_id, 32);
        read_bytes(&p, w->signature, DNAC_SIGNATURE_SIZE);
        read_bytes(&p, w->server_pubkey, DNAC_PUBKEY_SIZE);
        w->timestamp = read_u64(&p);
    }

    read_bytes(&p, rsp->signature, DNAC_SIGNATURE_SIZE);

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

dnac_bft_msg_type_t dnac_bft_get_msg_type(const uint8_t *buffer, size_t buffer_len) {
    if (!buffer || buffer_len < 2) {
        return 0;
    }
    /* Type is at offset 1 (after version byte) */
    return (dnac_bft_msg_type_t)buffer[1];
}

size_t dnac_bft_msg_size(dnac_bft_msg_type_t type) {
    switch (type) {
        case BFT_MSG_PROPOSAL:
            return BFT_PROPOSAL_SIZE;
        case BFT_MSG_PREVOTE:
        case BFT_MSG_PRECOMMIT:
            return BFT_VOTE_SIZE;
        case BFT_MSG_COMMIT:
            return BFT_COMMIT_SIZE;
        case BFT_MSG_VIEW_CHANGE:
            return BFT_VIEW_CHANGE_SIZE;
        case BFT_MSG_FORWARD_REQ:
            return BFT_FORWARD_REQ_SIZE;
        case BFT_MSG_FORWARD_RSP:
            /* Variable size - return base */
            return BFT_FORWARD_RSP_BASE_SIZE;
        default:
            return 0;
    }
}
