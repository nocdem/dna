/**
 * Nodus v5 — Consistent Hash Ring for Channel Sharding
 *
 * Each Nodus has a position: nodus_id (SHA3-512 of pubkey).
 * Each channel has a position: SHA3-512(channel_uuid).
 * Responsible set: first 3 distinct Nodus clockwise from channel position.
 *
 * @file nodus_hashring.h
 */

#ifndef NODUS_HASHRING_H
#define NODUS_HASHRING_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum Nodus nodes in the ring */
#define NODUS_RING_MAX_NODES 256

/** Ring member */
typedef struct {
    nodus_key_t   node_id;
    char          ip[64];
    uint16_t      tcp_port;
} nodus_ring_member_t;

/** Responsible set for a channel (Primary + 2 Backups) */
typedef struct {
    nodus_ring_member_t nodes[NODUS_R];
    int count;  /* Actual count (may be < R if fewer Nodus exist) */
} nodus_responsible_set_t;

/** Hash ring */
typedef struct {
    nodus_ring_member_t members[NODUS_RING_MAX_NODES];
    int                 count;
    uint32_t            version;   /* Ring version (incremented on membership change) */
    bool                sorted;    /* Internal: whether members are sorted */
} nodus_hashring_t;

/**
 * Initialize an empty hash ring.
 */
void nodus_hashring_init(nodus_hashring_t *ring);

/**
 * Add a Nodus to the ring.
 *
 * @param ring     Ring
 * @param node_id  Nodus ID (SHA3-512 of pubkey)
 * @param ip       Nodus IP address
 * @param tcp_port Nodus TCP port
 * @return 0 on success, -1 on error (full or duplicate)
 */
int nodus_hashring_add(nodus_hashring_t *ring,
                       const nodus_key_t *node_id,
                       const char *ip, uint16_t tcp_port);

/**
 * Remove a Nodus from the ring.
 *
 * @param ring     Ring
 * @param node_id  Nodus ID to remove
 * @return 0 if removed, -1 if not found
 */
int nodus_hashring_remove(nodus_hashring_t *ring, const nodus_key_t *node_id);

/**
 * Compute the responsible set for a channel UUID.
 *
 * @param ring          Ring
 * @param channel_uuid  16-byte channel UUID
 * @param result        Output responsible set
 * @return 0 on success, -1 on error (empty ring)
 */
int nodus_hashring_responsible(const nodus_hashring_t *ring,
                                const uint8_t *channel_uuid,
                                nodus_responsible_set_t *result);

/**
 * Compute the responsible set for an arbitrary key hash.
 *
 * @param ring     Ring
 * @param key      Key (already hashed)
 * @param result   Output responsible set
 * @return 0 on success, -1 on error
 */
int nodus_hashring_responsible_for_key(const nodus_hashring_t *ring,
                                        const nodus_key_t *key,
                                        nodus_responsible_set_t *result);

/**
 * Check if a node_id is in the ring.
 */
bool nodus_hashring_contains(const nodus_hashring_t *ring, const nodus_key_t *node_id);

/**
 * Get ring member count.
 */
int nodus_hashring_count(const nodus_hashring_t *ring);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_HASHRING_H */
