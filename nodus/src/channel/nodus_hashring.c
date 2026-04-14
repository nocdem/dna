/**
 * Nodus — Consistent Hash Ring
 *
 * Sorted ring of Nodus IDs. Channel assignment by clockwise walk.
 * Deterministic: same members + same channel UUID = same responsible set.
 */

#include "channel/nodus_hashring.h"
#include "crypto/nodus_sign.h"
#include <string.h>
#include <stdlib.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Sort members by node_id for deterministic ring ordering */
static int member_cmp(const void *a, const void *b) {
    const nodus_ring_member_t *ma = (const nodus_ring_member_t *)a;
    const nodus_ring_member_t *mb = (const nodus_ring_member_t *)b;
    return nodus_key_cmp(&ma->node_id, &mb->node_id);
}

static void ensure_sorted(nodus_hashring_t *ring) {
    if (!ring->sorted && ring->count > 1) {
        qsort(ring->members, (size_t)ring->count, sizeof(nodus_ring_member_t), member_cmp);
        ring->sorted = true;
    }
}

void nodus_hashring_init(nodus_hashring_t *ring) {
    if (!ring) return;
    memset(ring, 0, sizeof(*ring));
    ring->version = 1;
    ring->sorted = true;
}

int nodus_hashring_add(nodus_hashring_t *ring,
                       const nodus_key_t *node_id,
                       const char *ip, uint16_t tcp_port) {
    if (!ring || !node_id || !ip) return -1;
    if (ring->count >= NODUS_RING_MAX_NODES) return -1;

    /* Check for duplicate */
    for (int i = 0; i < ring->count; i++) {
        if (nodus_key_cmp(&ring->members[i].node_id, node_id) == 0)
            return -1;
    }

    nodus_ring_member_t *m = &ring->members[ring->count];
    m->node_id = *node_id;
    strncpy(m->ip, ip, sizeof(m->ip) - 1);
    m->ip[sizeof(m->ip) - 1] = '\0';
    m->tcp_port = tcp_port;

    ring->count++;
    ring->sorted = false;
    ring->version++;
    return 0;
}

int nodus_hashring_remove(nodus_hashring_t *ring, const nodus_key_t *node_id) {
    if (!ring || !node_id) return -1;

    for (int i = 0; i < ring->count; i++) {
        if (nodus_key_cmp(&ring->members[i].node_id, node_id) == 0) {
            /* Shift remaining members */
            for (int j = i; j < ring->count - 1; j++)
                ring->members[j] = ring->members[j + 1];
            ring->count--;
            ring->version++;
            /* sorted order is preserved since we just removed one element */
            return 0;
        }
    }
    return -1;
}

int nodus_hashring_responsible_for_key(const nodus_hashring_t *ring,
                                        const nodus_key_t *key,
                                        nodus_responsible_set_t *result) {
    if (!ring || !key || !result) return -1;
    if (ring->count == 0) return -1;

    memset(result, 0, sizeof(*result));

    /* Cast away const for sorting — we need sorted order */
    nodus_hashring_t *mutable_ring = (nodus_hashring_t *)ring;
    ensure_sorted(mutable_ring);

    /*
     * Walk clockwise from channel position.
     * Find the first member whose node_id >= key (binary search),
     * then collect up to R distinct members wrapping around.
     */

    /* Binary search: find first member with node_id >= key */
    int start = 0;
    int lo = 0, hi = ring->count - 1;
    bool found = false;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = nodus_key_cmp(&ring->members[mid].node_id, key);
        if (cmp >= 0) {
            start = mid;
            found = true;
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }

    /* If no member >= key, wrap to first member (clockwise wrap) */
    if (!found)
        start = 0;

    /* Collect R members starting from 'start', wrapping around */
    int want = (ring->count < NODUS_R) ? ring->count : NODUS_R;
    result->count = 0;

    for (int i = 0; i < ring->count && result->count < want; i++) {
        int idx = (start + i) % ring->count;
        result->nodes[result->count] = ring->members[idx];
        result->count++;
    }

    return 0;
}

int nodus_hashring_responsible(const nodus_hashring_t *ring,
                                const uint8_t *channel_uuid,
                                nodus_responsible_set_t *result) {
    if (!ring || !channel_uuid || !result) return -1;

    /* Hash the UUID to get ring position */
    nodus_key_t ch_key;
    if (nodus_hash(channel_uuid, NODUS_UUID_BYTES, &ch_key) != 0)
        return -1;

    return nodus_hashring_responsible_for_key(ring, &ch_key, result);
}

bool nodus_hashring_contains(const nodus_hashring_t *ring, const nodus_key_t *node_id) {
    if (!ring || !node_id) return false;

    for (int i = 0; i < ring->count; i++) {
        if (nodus_key_cmp(&ring->members[i].node_id, node_id) == 0)
            return true;
    }
    return false;
}

int nodus_hashring_count(const nodus_hashring_t *ring) {
    return ring ? ring->count : 0;
}
