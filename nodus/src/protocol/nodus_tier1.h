/**
 * Nodus — Tier 1 Protocol (Nodus-Nodus)
 *
 * Encode/decode inter-node messages:
 *   UDP: ping, pong, find_node, nodes_found
 *   TCP: store_value, store_ack, find_value, value_found,
 *        subscribe, unsubscribe, notify
 *
 * @file nodus_tier1.h
 */

#ifndef NODUS_TIER1_H
#define NODUS_TIER1_H

#include "nodus/nodus_types.h"
#include "core/nodus_value.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Encode (message → CBOR buffer) ─────────────────────────────── */

int nodus_t1_ping(uint32_t txn, const nodus_key_t *node_id,
                   uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_pong(uint32_t txn, const nodus_key_t *node_id,
                   uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_find_node(uint32_t txn, const nodus_key_t *target,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_nodes_found(uint32_t txn, const nodus_peer_t *peers, int count,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_store_value(uint32_t txn, const nodus_value_t *val,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_store_ack(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_find_value(uint32_t txn, const nodus_key_t *key,
                         uint8_t *buf, size_t cap, size_t *out_len);

/** value_found response (value present) */
int nodus_t1_value_found(uint32_t txn, const nodus_value_t *val,
                          uint8_t *buf, size_t cap, size_t *out_len);

/** value_found response (no value, return closest nodes) */
int nodus_t1_value_not_found(uint32_t txn, const nodus_peer_t *peers, int count,
                              uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_subscribe(uint32_t txn, const nodus_key_t *key,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_unsubscribe(uint32_t txn, const nodus_key_t *key,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t1_notify(uint32_t txn, const nodus_key_t *key,
                     const nodus_value_t *val,
                     uint8_t *buf, size_t cap, size_t *out_len);

/* ── Decoded message ─────────────────────────────────────────────── */

#define NODUS_T1_MAX_PEERS (NODUS_K * 3)

typedef struct {
    uint32_t        txn_id;
    char            type;           /* 'q', 'r', 'e' */
    char            method[16];     /* "ping", "fn", "sv", etc. */

    /* Parsed fields (method-dependent) */
    nodus_key_t     node_id;        /* ping/pong sender */
    nodus_key_t     target;         /* find_node target / find_value key */
    nodus_peer_t    peers[NODUS_T1_MAX_PEERS];
    int             peer_count;
    nodus_value_t  *value;          /* Heap-allocated if present */
    bool            has_value;      /* true = value_found, false = nodes */

    /* Error */
    int             error_code;
    char            error_msg[128];
} nodus_tier1_msg_t;

/**
 * Decode a Tier 1 CBOR payload into structured message.
 * Caller must call nodus_t1_msg_free() when done.
 */
int nodus_t1_decode(const uint8_t *buf, size_t len, nodus_tier1_msg_t *msg);

/** Free resources in decoded message. */
void nodus_t1_msg_free(nodus_tier1_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TIER1_H */
