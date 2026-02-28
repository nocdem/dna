/**
 * Nodus v5 — Kademlia Routing Table
 *
 * 512 k-buckets, k=8. XOR-distance based.
 * LRU eviction: least-recently-seen entry is replaced when bucket is full.
 */

#include "core/nodus_routing.h"
#include <string.h>
#include <time.h>

void nodus_routing_init(nodus_routing_t *rt, const nodus_key_t *self_id) {
    if (!rt || !self_id) return;
    memset(rt, 0, sizeof(*rt));
    rt->self_id = *self_id;
}

int nodus_routing_bucket_index(const nodus_routing_t *rt, const nodus_key_t *peer_id) {
    if (!rt || !peer_id) return -1;

    nodus_key_t distance;
    nodus_key_xor(&distance, &rt->self_id, peer_id);

    /* If distance is zero, peer_id == self_id */
    if (nodus_key_is_zero(&distance))
        return -1;

    int clz = nodus_key_clz(&distance);
    /* clz ranges from 0 to 511 for non-zero distances */
    if (clz >= NODUS_BUCKETS)
        return NODUS_BUCKETS - 1;

    return clz;
}

int nodus_routing_insert(nodus_routing_t *rt, const nodus_peer_t *peer) {
    if (!rt || !peer) return -1;

    int idx = nodus_routing_bucket_index(rt, &peer->node_id);
    if (idx < 0) return -1;  /* Can't insert self */

    nodus_bucket_t *bucket = &rt->buckets[idx];

    /* Check if peer already exists */
    for (int i = 0; i < bucket->count; i++) {
        if (bucket->entries[i].active &&
            nodus_key_cmp(&bucket->entries[i].peer.node_id, &peer->node_id) == 0) {
            /* Update existing entry */
            bucket->entries[i].peer = *peer;
            if (bucket->entries[i].peer.last_seen == 0)
                bucket->entries[i].peer.last_seen = (uint64_t)time(NULL);
            return 1;  /* Already existed, updated */
        }
    }

    /* Find empty slot */
    for (int i = 0; i < NODUS_K; i++) {
        if (!bucket->entries[i].active) {
            bucket->entries[i].peer = *peer;
            if (bucket->entries[i].peer.last_seen == 0)
                bucket->entries[i].peer.last_seen = (uint64_t)time(NULL);
            bucket->entries[i].active = true;
            if (i >= bucket->count)
                bucket->count = i + 1;
            return 0;
        }
    }

    /* Bucket full — evict least-recently-seen */
    int lru_idx = 0;
    uint64_t oldest = bucket->entries[0].peer.last_seen;
    for (int i = 1; i < NODUS_K; i++) {
        if (bucket->entries[i].peer.last_seen < oldest) {
            oldest = bucket->entries[i].peer.last_seen;
            lru_idx = i;
        }
    }

    bucket->entries[lru_idx].peer = *peer;
    if (bucket->entries[lru_idx].peer.last_seen == 0)
        bucket->entries[lru_idx].peer.last_seen = (uint64_t)time(NULL);
    bucket->entries[lru_idx].active = true;
    return 0;
}

int nodus_routing_remove(nodus_routing_t *rt, const nodus_key_t *peer_id) {
    if (!rt || !peer_id) return -1;

    int idx = nodus_routing_bucket_index(rt, peer_id);
    if (idx < 0) return -1;

    nodus_bucket_t *bucket = &rt->buckets[idx];
    for (int i = 0; i < bucket->count; i++) {
        if (bucket->entries[i].active &&
            nodus_key_cmp(&bucket->entries[i].peer.node_id, peer_id) == 0) {
            bucket->entries[i].active = false;
            memset(&bucket->entries[i].peer, 0, sizeof(nodus_peer_t));
            return 0;
        }
    }
    return -1;
}

/** XOR distance comparison for sorting: is a closer to target than b? */
static int distance_cmp(const nodus_key_t *target,
                        const nodus_key_t *a,
                        const nodus_key_t *b) {
    nodus_key_t da, db;
    nodus_key_xor(&da, target, a);
    nodus_key_xor(&db, target, b);
    return nodus_key_cmp(&da, &db);
}

int nodus_routing_find_closest(const nodus_routing_t *rt,
                                const nodus_key_t *target,
                                nodus_peer_t *results,
                                int max_results) {
    if (!rt || !target || !results || max_results <= 0)
        return 0;

    /* Collect all active peers */
    int total = 0;

    /* Temporary array — stack allocated. Max theoretical entries = 512 * 8 = 4096 */
    /* For practical purposes, iterate buckets and use insertion sort into results */
    int found = 0;

    for (int b = 0; b < NODUS_BUCKETS; b++) {
        const nodus_bucket_t *bucket = &rt->buckets[b];
        for (int e = 0; e < bucket->count; e++) {
            if (!bucket->entries[e].active)
                continue;

            const nodus_peer_t *peer = &bucket->entries[e].peer;

            if (found < max_results) {
                /* Insertion sort into results */
                int pos = found;
                for (int j = 0; j < found; j++) {
                    if (distance_cmp(target, &peer->node_id, &results[j].node_id) < 0) {
                        pos = j;
                        break;
                    }
                }
                /* Shift right */
                if (pos < found) {
                    for (int j = found; j > pos; j--)
                        results[j] = results[j - 1];
                }
                results[pos] = *peer;
                found++;
            } else {
                /* Check if closer than the farthest current result */
                if (distance_cmp(target, &peer->node_id, &results[found - 1].node_id) < 0) {
                    /* Find insertion position */
                    int pos = found - 1;
                    for (int j = 0; j < found; j++) {
                        if (distance_cmp(target, &peer->node_id, &results[j].node_id) < 0) {
                            pos = j;
                            break;
                        }
                    }
                    /* Shift right, dropping last */
                    for (int j = found - 1; j > pos; j--)
                        results[j] = results[j - 1];
                    results[pos] = *peer;
                }
            }

            total++;
        }
    }

    return found;
}

int nodus_routing_lookup(const nodus_routing_t *rt,
                          const nodus_key_t *peer_id,
                          nodus_peer_t *peer_out) {
    if (!rt || !peer_id) return -1;

    int idx = nodus_routing_bucket_index(rt, peer_id);
    if (idx < 0) return -1;

    const nodus_bucket_t *bucket = &rt->buckets[idx];
    for (int i = 0; i < bucket->count; i++) {
        if (bucket->entries[i].active &&
            nodus_key_cmp(&bucket->entries[i].peer.node_id, peer_id) == 0) {
            if (peer_out)
                *peer_out = bucket->entries[i].peer;
            return 0;
        }
    }
    return -1;
}

int nodus_routing_count(const nodus_routing_t *rt) {
    if (!rt) return 0;

    int total = 0;
    for (int b = 0; b < NODUS_BUCKETS; b++) {
        const nodus_bucket_t *bucket = &rt->buckets[b];
        for (int e = 0; e < bucket->count; e++) {
            if (bucket->entries[e].active)
                total++;
        }
    }
    return total;
}

int nodus_routing_touch(nodus_routing_t *rt, const nodus_key_t *peer_id) {
    if (!rt || !peer_id) return -1;

    int idx = nodus_routing_bucket_index(rt, peer_id);
    if (idx < 0) return -1;

    nodus_bucket_t *bucket = &rt->buckets[idx];
    for (int i = 0; i < bucket->count; i++) {
        if (bucket->entries[i].active &&
            nodus_key_cmp(&bucket->entries[i].peer.node_id, peer_id) == 0) {
            bucket->entries[i].peer.last_seen = (uint64_t)time(NULL);
            return 0;
        }
    }
    return -1;
}
