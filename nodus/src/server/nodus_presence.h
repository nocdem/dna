/**
 * Nodus — Server-Side Presence Table
 *
 * Tracks which clients are connected to this node and across the cluster.
 * Local entries (peer_index=0) are set on auth, cleared on disconnect.
 * Remote entries come from inter-node p_sync messages and expire after TTL.
 *
 * @file nodus_presence.h
 */

#ifndef NODUS_PRESENCE_H
#define NODUS_PRESENCE_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_PRESENCE_MAX_ENTRIES  2048
#define NODUS_PRESENCE_REMOTE_TTL   45   /* seconds — remote entry expiry */
#define NODUS_PRESENCE_SYNC_SEC     30   /* inter-node sync interval */

typedef struct {
    nodus_key_t  client_fp;       /* 64-byte fingerprint */
    uint8_t      peer_index;      /* 0 = local, 1..N = cluster peer index + 1 */
    uint64_t     last_seen;       /* Unix timestamp */
    bool         active;
} nodus_presence_entry_t;

/* p_sync dial pacing (S5a review F5). The tick dials every routing peer it
 * has no usable 4002 conn to; without pacing an unreachable or refusing
 * peer is redialed every NODUS_PRESENCE_SYNC_SEC, and a routing table of
 * up to NODUS_BUCKETS * NODUS_K peers can outrun NODUS_TCP_MAX_CONNS.
 *
 * Backoff: each fresh dial is recorded per (ip, port, node_id) and that
 * key is not dialed again before now + delay(fail_count), delay =
 * BASE << (fail_count - 1) capped at MAX: 30, 60, 120, 240, 480, 900 s.
 * The entry is cleared the first tick that finds the conn established, so
 * a dial that succeeds never waits: BASE equals the sync interval, so the
 * entry recorded at the dial has always expired by the next tick.
 *
 * Cap: at most DIAL_CAP fresh dials per tick (a dial that returns NULL
 * counts). 16 ≥ today's 7-node cluster, so a healthy cluster still
 * connects fully on the first tick; at 16 per 30 s a refusing or silent
 * routing table opens at most 16 handshakes (a Dilithium5 sign and a KEM
 * each) and 16 pool slots per tick, against a pool of 1024. Peers beyond
 * the cap are skipped without penalty and tried on a later tick.
 *
 * Table size: entries are created only by dials, at most DIAL_CAP per
 * tick, and an entry holds a key back for at most MAX seconds = MAX / SYNC
 * ticks; so at most 16 * (900 / 30) = 480 keys are ever in backoff at
 * once — 512 slots hold them all. When the table is full (keys of peers
 * that left the routing table stay until evicted) the entry with the
 * smallest next_try (lowest slot on a tie) is replaced. */
#define NODUS_PRESENCE_DIAL_CAP          16
#define NODUS_PRESENCE_BACKOFF_BASE_SEC  30
#define NODUS_PRESENCE_BACKOFF_MAX_SEC   900
#define NODUS_PRESENCE_BACKOFF_SLOTS     512

typedef struct {
    nodus_key_t  node_id;         /* the pinned identity the dial carried */
    char         ip[64];
    uint16_t     port;
    uint32_t     fail_count;      /* dials since the last established conn */
    uint64_t     next_try;        /* no dial to this key before (unix s) */
    bool         used;
} nodus_presence_backoff_t;

typedef struct {
    nodus_presence_backoff_t slots[NODUS_PRESENCE_BACKOFF_SLOTS];
} nodus_presence_backoff_table_t;

typedef struct {
    nodus_presence_entry_t entries[NODUS_PRESENCE_MAX_ENTRIES];
    int      count;
    uint64_t last_sync;           /* Last time we broadcast to peers */
    nodus_presence_backoff_table_t dial_backoff;   /* p_sync dial pacing */
} nodus_presence_table_t;

struct nodus_server;
struct nodus_tcp_conn;

/** Add a locally-connected client to the presence table. */
void nodus_presence_add_local(struct nodus_server *srv, const nodus_key_t *fp);

/** Remove a locally-connected client from the presence table. */
void nodus_presence_remove_local(struct nodus_server *srv, const nodus_key_t *fp);

/** Merge remote fingerprints received from a peer node. */
void nodus_presence_merge_remote(struct nodus_server *srv, const nodus_key_t *fps,
                                   int count, uint8_t peer_index);

/** Check if a fingerprint is online anywhere in the cluster. */
bool nodus_presence_is_online(struct nodus_server *srv, const nodus_key_t *fp,
                                uint8_t *peer_index_out);

/** Batch query: check online status + last_seen for N fingerprints. */
int nodus_presence_query_batch(struct nodus_server *srv, const nodus_key_t *fps,
                                 int fp_count, bool *online_out, uint8_t *peers_out,
                                 uint64_t *last_seen_out);

/** Expire stale remote entries. */
void nodus_presence_expire(struct nodus_server *srv, uint64_t now);

/** Get all locally-connected fingerprints. */
int nodus_presence_get_local(struct nodus_server *srv, nodus_key_t *fps_out,
                               int max_count);

/** Periodic tick: expire + broadcast local list to peers (dials paced by
 *  the backoff table and NODUS_PRESENCE_DIAL_CAP, see above). */
void nodus_presence_tick(struct nodus_server *srv);

/* ── Dial backoff (pure: the caller passes `now`; no clock read) ──── */

/** Delay after `fail_count` recorded dials (≥ 1): BASE << (n - 1), capped
 *  at MAX. 0 for fail_count 0. */
uint64_t nodus_presence_backoff_delay(uint32_t fail_count);

/** True when (ip, port, node_id) may be dialed at `now`: no entry, or its
 *  next_try has been reached. */
bool nodus_presence_backoff_allows(const nodus_presence_backoff_table_t *t,
                                   const char *ip, uint16_t port,
                                   const nodus_key_t *node_id, uint64_t now);

/** Record a fresh dial to (ip, port, node_id) at `now`: fail_count + 1,
 *  next_try = now + delay(fail_count). A new key takes a free slot, or the
 *  slot with the smallest next_try (lowest index on a tie). */
void nodus_presence_backoff_record(nodus_presence_backoff_table_t *t,
                                   const char *ip, uint16_t port,
                                   const nodus_key_t *node_id, uint64_t now);

/** The conn to (ip, port, node_id) is established: forget the key. */
void nodus_presence_backoff_clear(nodus_presence_backoff_table_t *t,
                                  const char *ip, uint16_t port,
                                  const nodus_key_t *node_id);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_PRESENCE_H */
