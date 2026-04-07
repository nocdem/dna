/**
 * Nodus — Witness Mempool Implementation
 *
 * Fee-ordered queue of pending DNAC transactions.
 * Single-threaded (epoll event loop) — no locking needed.
 *
 * @file nodus_witness_mempool.c
 */

#include "witness/nodus_witness_mempool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS-MEMPOOL"

/* ── Init ───────────────────────────────────────────────────────── */

void nodus_witness_mempool_init(nodus_witness_mempool_t *mp) {
    if (!mp) return;
    memset(mp, 0, sizeof(*mp));
}

/* ── Free entry ─────────────────────────────────────────────────── */

void nodus_witness_mempool_entry_free(nodus_witness_mempool_entry_t *entry) {
    if (!entry) return;
    free(entry->tx_data);
    entry->tx_data = NULL;
    free(entry);
}

/* ── Add (fee-sorted, highest fee first) ────────────────────────── */

int nodus_witness_mempool_add(nodus_witness_mempool_t *mp,
                               nodus_witness_mempool_entry_t *entry) {
    if (!mp || !entry) return -1;

    if (mp->count >= NODUS_W_MAX_MEMPOOL) {
        fprintf(stderr, "%s: mempool full (%d/%d)\n",
                LOG_TAG, mp->count, NODUS_W_MAX_MEMPOOL);
        return -1;
    }

    /* Duplicate check (same tx_hash) */
    for (int i = 0; i < mp->count; i++) {
        if (memcmp(mp->entries[i]->tx_hash, entry->tx_hash,
                   NODUS_T3_TX_HASH_LEN) == 0) {
            fprintf(stderr, "%s: duplicate tx_hash rejected\n", LOG_TAG);
            return -2;
        }
    }

    /* Find insertion point: first entry with fee < new entry's fee */
    int pos = mp->count;  /* default: append at end (lowest fee) */
    for (int i = 0; i < mp->count; i++) {
        if (mp->entries[i]->fee < entry->fee) {
            pos = i;
            break;
        }
    }

    /* Shift entries down to make room */
    for (int i = mp->count; i > pos; i--)
        mp->entries[i] = mp->entries[i - 1];

    mp->entries[pos] = entry;
    mp->count++;

    fprintf(stderr, "%s: added TX (fee=%llu, pos=%d, count=%d)\n",
            LOG_TAG, (unsigned long long)entry->fee, pos, mp->count);
    return 0;
}

/* ── Pop batch (highest fee first, from head) ───────────────────── */

int nodus_witness_mempool_pop_batch(nodus_witness_mempool_t *mp,
                                     nodus_witness_mempool_entry_t **out,
                                     int max) {
    if (!mp || !out || max <= 0) return 0;

    int count = mp->count < max ? mp->count : max;

    /* Copy top entries to output */
    for (int i = 0; i < count; i++)
        out[i] = mp->entries[i];

    /* Shift remaining entries up */
    int remaining = mp->count - count;
    for (int i = 0; i < remaining; i++)
        mp->entries[i] = mp->entries[count + i];

    /* Clear vacated slots */
    for (int i = remaining; i < mp->count; i++)
        mp->entries[i] = NULL;

    mp->count = remaining;

    if (count > 0) {
        fprintf(stderr, "%s: popped %d TXs (remaining=%d)\n",
                LOG_TAG, count, mp->count);
    }

    return count;
}

/* ── Remove by client connection ────────────────────────────────── */

void nodus_witness_mempool_remove_by_conn(nodus_witness_mempool_t *mp,
                                            struct nodus_tcp_conn *conn) {
    if (!mp || !conn) return;

    int removed = 0;
    int write_idx = 0;

    for (int i = 0; i < mp->count; i++) {
        if (mp->entries[i]->client_conn == conn) {
            nodus_witness_mempool_entry_free(mp->entries[i]);
            mp->entries[i] = NULL;
            removed++;
        } else {
            mp->entries[write_idx++] = mp->entries[i];
        }
    }

    /* Clear trailing slots */
    for (int i = write_idx; i < mp->count; i++)
        mp->entries[i] = NULL;

    mp->count = write_idx;

    if (removed > 0) {
        fprintf(stderr, "%s: removed %d entries for closed conn (remaining=%d)\n",
                LOG_TAG, removed, mp->count);
    }
}

/* ── Clear all ──────────────────────────────────────────────────── */

void nodus_witness_mempool_clear(nodus_witness_mempool_t *mp) {
    if (!mp) return;

    for (int i = 0; i < mp->count; i++) {
        nodus_witness_mempool_entry_free(mp->entries[i]);
        mp->entries[i] = NULL;
    }

    int old_count = mp->count;
    mp->count = 0;

    if (old_count > 0) {
        fprintf(stderr, "%s: cleared %d entries\n", LOG_TAG, old_count);
    }
}
