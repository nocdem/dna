/**
 * Nodus — Kademlia Routing Table
 *
 * 512 k-buckets (one per bit of the SHA3-512 key space).
 * Each bucket holds up to k=8 peers, ordered by last_seen (LRU).
 *
 * @file nodus_routing.h
 */

#ifndef NODUS_ROUTING_H
#define NODUS_ROUTING_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Single k-bucket entry */
typedef struct {
    nodus_peer_t  peer;
    bool          active;
} nodus_bucket_entry_t;

/** K-bucket */
typedef struct {
    nodus_bucket_entry_t entries[NODUS_K];
    int count;
} nodus_bucket_t;

/** Routing table */
typedef struct {
    nodus_key_t    self_id;         /* This node's ID */
    nodus_bucket_t buckets[NODUS_BUCKETS];
} nodus_routing_t;

/**
 * Initialize routing table.
 *
 * @param rt       Routing table to initialize
 * @param self_id  This node's ID
 */
void nodus_routing_init(nodus_routing_t *rt, const nodus_key_t *self_id);

/**
 * Compute bucket index for a peer ID.
 * index = leading_zero_bits(XOR(self_id, peer_id))
 * Range: 0..511, or -1 if peer_id == self_id.
 */
int nodus_routing_bucket_index(const nodus_routing_t *rt, const nodus_key_t *peer_id);

/**
 * Insert or update a peer in the routing table.
 * If bucket is full, evicts least-recently-seen entry.
 *
 * @param rt    Routing table
 * @param peer  Peer to insert
 * @return 0 on success, 1 if already existed (updated), -1 on error
 */
int nodus_routing_insert(nodus_routing_t *rt, const nodus_peer_t *peer);

/**
 * Try to insert a peer. If bucket is full, returns the LRU candidate
 * for ping-before-evict instead of immediately evicting.
 *
 * @param rt              Routing table
 * @param peer            Peer to insert
 * @param evict_candidate Output: filled with LRU peer info when return is 2
 * @return 0 = inserted, 1 = already existed (updated), 2 = bucket full (ping candidate), -1 = error
 */
int nodus_routing_try_insert(nodus_routing_t *rt, const nodus_peer_t *peer,
                              nodus_peer_t *evict_candidate);

/**
 * Remove a peer from the routing table.
 *
 * @param rt       Routing table
 * @param peer_id  ID of peer to remove
 * @return 0 if removed, -1 if not found
 */
int nodus_routing_remove(nodus_routing_t *rt, const nodus_key_t *peer_id);

/**
 * Find the k closest peers to a target key.
 *
 * @param rt         Routing table
 * @param target     Target key
 * @param results    Output array (must hold at least max_results entries)
 * @param max_results Maximum results to return
 * @return Number of peers found
 */
int nodus_routing_find_closest(const nodus_routing_t *rt,
                                const nodus_key_t *target,
                                nodus_peer_t *results,
                                int max_results);

/**
 * Look up a specific peer by ID.
 *
 * @param rt       Routing table
 * @param peer_id  Peer ID to look up
 * @param peer_out Output peer info (if found)
 * @return 0 if found, -1 if not found
 */
int nodus_routing_lookup(const nodus_routing_t *rt,
                          const nodus_key_t *peer_id,
                          nodus_peer_t *peer_out);

/**
 * Get total number of peers in routing table.
 */
int nodus_routing_count(const nodus_routing_t *rt);

/**
 * Touch a peer (update last_seen to current time).
 *
 * @param rt       Routing table
 * @param peer_id  Peer to touch
 * @return 0 on success, -1 if not found
 */
int nodus_routing_touch(nodus_routing_t *rt, const nodus_key_t *peer_id);

/**
 * Generate a random key whose XOR distance to self_id falls in bucket b.
 * Used for Kademlia bucket refresh (FIND_NODE on random key per stale bucket).
 *
 * @param result   Output key
 * @param self_id  This node's ID
 * @param bucket   Bucket index (0..511)
 */
void nodus_key_random_in_bucket(nodus_key_t *result,
                                 const nodus_key_t *self_id,
                                 int bucket);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_ROUTING_H */
