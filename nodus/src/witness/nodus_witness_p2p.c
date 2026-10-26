/**
 * @file nodus/src/witness/nodus_witness_p2p.c
 * @brief The nodus host of the ported cometbft @v0.38.26 p2p layer on the
 *        witness port 4004. Contract, governing records and the
 *        deviations: nodus_witness_p2p.h. The witness-free part (sockets,
 *        worker, NodeInfo, transport, switch, address book, PEX, own ADDR
 *        record) is the embedded host net/nodus_p2p_host.{h,c} (net-layer
 *        design 2026-10-19 §11, package N3).
 *
 * Reference call sites each block mirrors are named per block
 * (node/node.go and node/setup.go: how a node builds and starts its p2p
 * half; p2p/transport.go / switch.go: what a host must do for them).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_p2p.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_join.h"
#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_storage_reporter.h"  /* channel 0x72 */
#include "witness/nodus_witness_storage_holder.h"    /* channel 0x73 */
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_p2p_pex.h"
#include "dnac/cmt_p2p_addrbook.h"
#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_block.h"         /* CMT_BLOCK_PROTOCOL            */
#include "dnac/cmt_part_set.h"      /* CMT_BLOCK_PART_SIZE_BYTES     */
#include "dnac/cmt_mem.h"           /* CMT_MEM_CHANNEL, mempool cfg  */
#include "dnac/validator.h"         /* DNAC_VALIDATOR_ACTIVE / ELIGIBLE */
#include "witness/nodus_witness_v2_storage.h"  /* frozen storage sets    */
#include "witness/nodus_witness_v2_produce.h"  /* v2 tip height          */
#include "witness/nodus_witness_storage_probe.h" /* epoch_for_tip        */

/* Sockets, threads, files and clocks are the embedded host's
 * (net/nodus_p2p_host.c, net-layer package N3). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_P2P"

/* The consensus seam's index space IS the reactors' peer tables. */
_Static_assert((int)CMT_CONR_MAX_PEERS == (int)CMT_MEM_MAX_PEERS,
               "cmt_conr and cmt_memr must share one peer index space");

/* ══ the witness host ═════════════════════════════════════════════════ */

typedef struct {
    char    id[CMT_P2P_ID_CAP];
    uint8_t pk[NODUS_PK_BYTES];
    /* true: added from the `validators` query or a tip ± 1 committee;
     * false: ONLY a member of the frozen storage set S(H) or S(H − E)
     * (cap-exempt, nothing else — nodus_witness_p2p_is_validator_bonded). */
    bool    validator;
} p2p_bonded_t;

/** The largest StatusResponse `bs_receive` keeps before the lane is live:
 *  its canonical form is at most tag + len + two (tag + 10-byte varint)
 *  fields = 24 bytes (cmt_bsync_msgs.c, types.pb.go:565-581, :704-718). */
#define NODUS_P2P_BS_STATUS_MAX 32

/** One index of the consensus seam (file header). */
typedef struct {
    cmt_p2p_peer_t *peer;          /* NULL = free                          */
    bool conr_init, memr_init;     /* the reactor's InitPeer ran           */
    bool conr_added, memr_added;   /* the reactor's AddPeer ran            */
    bool cons_removed, mem_removed;/* the shim's RemovePeer ran            */
    int  pending_stop;             /* deferred StopPeerForError reason     */
    /* DEVIATION (bs_receive): the latest 0x40 StatusResponse this peer
     * sent before the lane was live, re-marshalled; replayed into the
     * block sync reactor at nodus_witness_p2p_lane_live. */
    bool    bs_status_held;
    char    bs_status_id[CMT_P2P_ID_CAP];
    uint8_t bs_status[NODUS_P2P_BS_STATUS_MAX];
    size_t  bs_status_len;
} p2p_lane_slot_t;

/* The 0x70 serving side's per-requester gate (red-team H2 / R6 F5): one
 * entry per requesting peer ID, the last time it was served. Sized by
 * the host's peer index space (CMT_CONR_MAX_PEERS, the consensus seam's
 * slot count): no more peers than that can be connected and indexed at
 * once. ⚠ NOT GROUNDED — channel 0x70 has no reference counterpart
 * (R-P2P-5). */
#define NODUS_P2P_GB_SERVE_SLOTS  CMT_CONR_MAX_PEERS
/** The minimum gap between two chunks served to ONE requester — the
 *  former node-wide V2SYNC_SERVE_MIN_GAP_MS (nodus_witness_v2_sync2.c),
 *  now per requester. ⚠ NOT GROUNDED (local policy, as it was). */
#define NODUS_P2P_GB_SERVE_GAP_MS 100u

typedef struct {
    char     id[CMT_P2P_ID_CAP];   /* "" = free                          */
    uint64_t last_ms;              /* monotonic                          */
} p2p_gb_serve_t;

/* StopPeerForError reasons this host passes (logged by the switch). */
#define NODUS_P2P_STOP_CONR_BASE    400   /* + cmt_conr_stop_reason_t      */
#define NODUS_P2P_STOP_MEMR         410   /* mempool/reactor.go:182        */
#define NODUS_P2P_STOP_DECODE_0X70  420   /* peer.go:418-429               */
#define NODUS_P2P_STOP_DECODE_0X71  421
#define NODUS_P2P_STOP_DECODE_0X72  422
#define NODUS_P2P_STOP_DECODE_0X73  423
#define NODUS_P2P_STOP_BSYNC_BASE   430   /* + cmt_bsync_stop_reason_t     */
/* Validator priority on a full index table (lane_slot_evict_for; operator
 * decision 2026-10-14, docs/plans/2026-10-14-dht-v2-design.md §2 "4004
 * admission"). No reference counterpart: the reference has no index
 * table (a peer is a map key, consensus/reactor.go). */
#define NODUS_P2P_STOP_LANE_EVICT   440

struct nodus_witness_p2p {
    nodus_witness_t            *w;
    /* The witness-free host (net/nodus_p2p_host.h): identity, config,
     * sockets, worker, NodeInfo, transport, switch, book, PEX, our own
     * ADDR record (its `self_bonded` written by the bonded-set refresh). */
    nodus_p2p_host_t            host;

    cmt_p2p_ch_desc_t           cons_desc[CMT_CONR_NUM_CHANNELS];
    cmt_p2p_ch_desc_t           mem_desc[1];
    cmt_p2p_ch_desc_t           bs_desc[1];
    cmt_p2p_ch_desc_t           gb_desc[1];
    cmt_p2p_ch_desc_t           cc_desc[1];
    cmt_p2p_ch_desc_t           sp_desc[1];      /* 0x72 archive probe */
    cmt_p2p_ch_desc_t           sf_desc[1];      /* 0x73 segment fetch */

    /* the bonded set (K2 / N5), sorted by ID (whether our own ID is in
     * it: host.self_bonded) */
    p2p_bonded_t               *bonded;
    int                         n_bonded, cap_bonded;
    bool                        bonded_valid;
    uint64_t                    bonded_tip;
    /* Whether the LAST derivation of the set ran to the end (the tip read
     * and the validators read both succeeded). 4004 keeps its last good set
     * when a refresh fails (admission must not flap); the ROLE EXPORT must
     * not: an old set exported as fresh would keep exempting an identity
     * whose role ended (nodus_witness_p2p_roles_fill refuses while false). */
    bool                        bonded_derive_ok;
    /* IDs that JOINED the set, summed over every refresh (the purge's
     * input, bonded_purge_new) — nodus_witness_p2p_bonded_joined_total */
    uint64_t                    bonded_joined_total;
    /* a frozen storage-set member without a registry row was skipped and
     * logged once (bonded_add_storage_set) */
    bool                        storage_orphan_warned;

    /* 0x70 — the joiner's ONE outstanding genesis-bundle request
     * (nodus_witness_p2p_gb_request / _gb_take) and the serving side's
     * per-requester gate (nodus_witness_p2p_gb_serve_allow). Kept here,
     * with the channel, not in nodus_witness_t (red-team H2). */
    bool                        gb_out_valid;
    char                        gb_out_peer[CMT_P2P_ID_CAP];
    uint64_t                    gb_out_offset;
    p2p_gb_serve_t              gb_serve[NODUS_P2P_GB_SERVE_SLOTS];
    /* The serving side's in-memory copy of the chain's genesis bundle
     * (RT2 B-F2; nodus_witness_p2p_gb_bundle), and the chain id it
     * belongs to. NULL = not loaded yet. */
    uint8_t                    *gb_bundle;
    size_t                      gb_bundle_len;
    uint8_t                     gb_bundle_chain[32];

    /* M4 — the last "no persistent peers" ERROR (monotonic ms; 0 = none) */
    int64_t                     no_peer_logged_ms;

    /* the consensus lane */
    cmt_conr_host_t             conr_host;
    cmt_memr_host_t             memr_host;
    bool                        lane_prepared;
    nodus_cmt_store_t          *store;
    cmt_now_fn                  lane_now;       /* the wall clock       */
    void                       *lane_now_ctx;
    cmt_mono_fn                 lane_mono;      /* the wait clock       */
    void                       *lane_mono_ctx;
    cmt_pb_arena_t              recv_arena;
    cmt_commit_sig_t           *commit_sigs;
    cmt_extended_commit_sig_t  *ext_sigs;
    cmt_pb_arena_t              ext_load_arena;
    cmt_pb_arena_t              part_arena;
    cmt_conr_t                 *conr;
    cmt_memr_t                 *memr;
    cmt_bsync_reactor_t        *bsync;       /* 0x40, borrowed (header)  */
    bool                        lane_live;
    p2p_lane_slot_t             slots[CMT_CONR_MAX_PEERS];
    bool                        any_pending_stop;
    /* A reactor call made from a p2p callback (receive, InitPeer,
     * AddPeer, RemovePeer) returned CMT_FAULT — node-local (W1.7). The
     * callback has no caller to hand it to, so it is kept here and
     * nodus_witness_p2p_lane_tick / _lane_live return CMT_FAULT from then
     * on; the witness stops consensus participation on that
     * (nodus_witness.c witness_cmt_tick). Never cleared: a node that
     * faulted does not resume (lane_fault_note). */
    bool                        lane_fault;
};

/* ── the bonded set (K2 / N5) ───────────────────────────────────────── */

static int bonded_cmp(const void *a, const void *b)
{
    return strcmp(((const p2p_bonded_t *)a)->id, ((const p2p_bonded_t *)b)->id);
}

/* bsearch's comparator with the KEY first (C11 7.22.5.1): the key is the
 * ID string itself, so a lookup builds no 2.6 KB p2p_bonded_t key (RT2
 * D-F1 — the former memset of the whole entry, pubkey included, on every
 * is_bonded / bonded_pubkey). */
static int bonded_id_cmp(const void *key, const void *elem)
{
    return strcmp((const char *)key, ((const p2p_bonded_t *)elem)->id);
}

static const p2p_bonded_t *bonded_find_in(const p2p_bonded_t *set, int n,
                                          const char *id)
{
    if (id == NULL || n <= 0 || strlen(id) >= CMT_P2P_ID_CAP) {
        return NULL;
    }
    return (const p2p_bonded_t *)bsearch(id, set, (size_t)n, sizeof(*set),
                                         bonded_id_cmp);
}

static const p2p_bonded_t *bonded_find(const nodus_witness_p2p_t *p,
                                       const char *id)
{
    return bonded_find_in(p->bonded, p->n_bonded, id);
}

/* One pubkey into the scratch set being built (unsorted while filling;
 * duplicates skipped). `validator` is ORed into a duplicate: a key that is
 * both a storage-set member and a validator / committee member is a validator
 * whatever the add order. */
static void bonded_add(p2p_bonded_t **set, int *n, int *cap,
                       const uint8_t pk[NODUS_PK_BYTES], bool validator)
{
    char id[CMT_P2P_ID_CAP];
    int i;

    if (cmt_p2p_pubkey_to_id(pk, id) != CMT_OK) {
        return;
    }
    for (i = 0; i < *n; i++) {
        if (strcmp((*set)[i].id, id) == 0) {
            (*set)[i].validator = (*set)[i].validator || validator;
            return;
        }
    }
    if (*n == *cap) {
        int ncap = *cap > 0 ? *cap * 2 : 64;
        p2p_bonded_t *nb = (p2p_bonded_t *)realloc(*set, (size_t)ncap * sizeof(*nb));

        if (nb == NULL) {
            return;
        }
        *set = nb;
        *cap = ncap;
    }
    memcpy((*set)[*n].id, id, sizeof(id));
    memcpy((*set)[*n].pk, pk, NODUS_PK_BYTES);
    (*set)[*n].validator = validator;
    (*n)++;
}

/* N5: the committee a height resolves to (the deleted B1 gate's reads,
 * nodus_witness_peer.c:696-720 before F5). */
static void bonded_add_committee(nodus_witness_p2p_t *p, p2p_bonded_t **set,
                                 int *n, int *cap, uint64_t height)
{
    nodus_committee_member_t *cm = NULL;
    int k = 0, i;

    if (nodus_committee_get_for_block_alloc(p->w, height, &cm, &k) == 0) {
        for (i = 0; i < k; i++) {
            bonded_add(set, n, cap, cm[i].pubkey, true);
        }
    }
    free(cm);
}

/* The members of the frozen storage set S(epoch_start), added with
 * validator = false. The set is read with nodus_witness_storage_set_get —
 * the archive's own reader (nodus_witness_storage_holder.c
 * nodus_witness_sthold_must_hold), which re-checks the stored S(H)
 * against its member rows and returns them node_fp ascending. Each
 * member's node_pk comes from the registry by node_fp WHATEVER the row's
 * status: membership decides, not status (an EXITING member still holds
 * its segments until the boundary that drops it). rc 1 (no such set) adds
 * nothing; a fault (-1, already logged by the reader) adds nothing from
 * that set. A member with no registry row (a committed set never has
 * one) is skipped and logged once per process. */
static void bonded_add_storage_set(nodus_witness_p2p_t *p, p2p_bonded_t **set,
                                   int *n, int *cap, uint64_t epoch_start)
{
    nodus_storage_set_t *ss;
    sqlite3_stmt *st = NULL;
    uint32_t i;

    ss = (nodus_storage_set_t *)calloc(1, sizeof(*ss));
    if (ss == NULL) {
        return;
    }
    if (nodus_witness_storage_set_get(p->w, epoch_start, ss) != 0 ||
        ss->count == 0) {
        free(ss);
        return;
    }
    if (sqlite3_prepare_v2(p->w->db,
                           "SELECT node_pk FROM v2_storage_nodes WHERE node_fp = ?1",
                           -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_WARN(LOG_TAG, "v2_storage_nodes table unreadable: %s",
                     sqlite3_errmsg(p->w->db));
        free(ss);
        return;
    }
    for (i = 0; i < ss->count; i++) {
        int rc;

        sqlite3_reset(st);
        if (sqlite3_bind_blob(st, 1, ss->fps[i], 64, SQLITE_STATIC) != SQLITE_OK) {
            break;
        }
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (sqlite3_column_bytes(st, 0) == NODUS_PK_BYTES) {
                bonded_add(set, n, cap,
                           (const uint8_t *)sqlite3_column_blob(st, 0), false);
            }
        } else if (rc == SQLITE_DONE) {
            if (!p->storage_orphan_warned) {
                p->storage_orphan_warned = true;
                QGP_LOG_WARN(LOG_TAG, "storage set %llu: a member has no "
                             "v2_storage_nodes row — skipped (logged once)",
                             (unsigned long long)epoch_start);
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "v2_storage_nodes read failed: %s",
                         sqlite3_errmsg(p->w->db));
            break;
        }
    }
    sqlite3_finalize(st);
    free(ss);
}

/*
 * Z2-F11 — the IDs that are in the new bonded set `nb` and were not in
 * the old one keep only a signed record and no ban from their unbonded
 * days (cmt_p2p_addrbook_purge_bonded_ids); otherwise a stale unsigned
 * entry → failed dials → MarkBad would refuse its signed record for 24 h
 * (design K2/K3: a new candidate is never held back). Only a NEWLY bonded
 * ID can need it (RT2 D-F1 — the purge used to walk the whole book and
 * every ban on every tip change): mark_bad never bans a bonded ID and the
 * book refuses an unsigned address for one (cmt_p2p_addrbook.c
 * add_address, and the file load's §2R4 P4 check), so an ID that stays
 * bonded acquires nothing to purge. Both sets are sorted by ID: one
 * merge walk. An old set that was never valid counts as empty — every
 * member is new.
 */
static void bonded_purge_new(nodus_witness_p2p_t *p, const p2p_bonded_t *nb,
                             int n_new)
{
    const char (*ids)[CMT_P2P_ID_CAP];
    char (*fresh)[CMT_P2P_ID_CAP];
    int i, j = 0, n_fresh = 0, n_old = p->bonded_valid ? p->n_bonded : 0;

    if (n_new == 0) {
        return;
    }
    fresh = (char (*)[CMT_P2P_ID_CAP])malloc((size_t)n_new * sizeof(*fresh));
    if (fresh == NULL) {
        return;
    }
    for (i = 0; i < n_new; i++) {
        int c = 1;

        while (j < n_old && (c = strcmp(p->bonded[j].id, nb[i].id)) < 0) {
            j++;
        }
        if (j < n_old && c == 0) {
            continue;                           /* bonded before: nothing */
        }
        memcpy(fresh[n_fresh++], nb[i].id, CMT_P2P_ID_CAP);
    }
    ids = (const char (*)[CMT_P2P_ID_CAP])fresh;
    p->bonded_joined_total += (uint64_t)n_fresh;
    if (n_fresh > 0 && p->host.book != NULL) {
        (void)cmt_p2p_addrbook_purge_bonded_ids(p->host.book, ids, n_fresh);
    }
    free(fresh);
}

uint64_t nodus_witness_p2p_bonded_joined_total(const nodus_witness_p2p_t *p)
{
    return p != NULL ? p->bonded_joined_total : 0;
}

void nodus_witness_p2p_refresh_bonded(nodus_witness_p2p_t *p)
{
    uint64_t tip = 0;
    sqlite3_stmt *st = NULL;
    bool was_self;
    p2p_bonded_t *nb = NULL;
    int n_new = 0, cap_new = 0;
    bool derive_ok = true;

    if (p == NULL) {
        return;
    }
    was_self = p->host.self_bonded;
    if (p->w == NULL || p->w->db == NULL) {
        p->n_bonded = 0;
        p->bonded_valid = true;
        p->bonded_derive_ok = true;
        p->bonded_tip = 0;
        p->host.self_bonded = false;
        return;
    }
    if (nodus_witness_block_height_checked(p->w, &tip) != 0) {
        p->bonded_derive_ok = false;           /* the role export stops ... */
        return;                                /* ... 4004 keeps the last good set */
    }
    /* The new set is built beside the old one, so the two can be
     * compared (bonded_purge_new) before the old one is replaced. */
    if (sqlite3_prepare_v2(p->w->db,
                           "SELECT pubkey FROM validators WHERE status IN (?, ?) "
                           "ORDER BY pubkey_hash", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int(st, 2, (int)DNAC_VALIDATOR_ELIGIBLE);
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_bytes(st, 0) == NODUS_PK_BYTES) {
                bonded_add(&nb, &n_new, &cap_new,
                           (const uint8_t *)sqlite3_column_blob(st, 0), true);
            }
        }
        sqlite3_finalize(st);
    } else {
        derive_ok = false;
        QGP_LOG_WARN(LOG_TAG, "validators table unreadable: %s",
                     sqlite3_errmsg(p->w->db));
    }
    /* The members of the frozen storage sets S(H) and S(H − E) are
     * cap-exempt too (khan decision docs/plans/decisions/2026-10-14-
     * kurultay-22-summary.md item 3(a) — node-local admission, no chain
     * change — with the membership rule of docs/plans/2026-10-14-dht-v2-
     * design.md §2 "4004 admission" and "One eligibility function",
     * operator decision 2026-10-14 "Evet"). H is the boundary of the
     * epoch the committed tip is in, derived exactly as the archive
     * derives it: nodus_witness_v2_tip_height + nodus_stprobe_epoch_for_tip
     * (H = floor(tip / E) · E, none below E; nodus_witness_storage_holder.c
     * worker tick, nodus_witness_storage_fetch.c serve), and S(H − E)
     * only when H > E (nodus_witness_sthold_must_hold). Consequences:
     * before the storage activation there is no set and no storage
     * exemption; a node registered ACTIVE but not yet in S(H) is NOT
     * exempt until the boundary that freezes it in; a node that left
     * S(H) stays exempt while it is in S(H − E). node_pk is the storage
     * node's 4004 identity key. Added with validator = false: a storage
     * member gets the connection admission treatment ONLY — it is not
     * listed in the 4001 dnac_roster and does not pass the 0x71 approval
     * gate (nodus_witness_p2p_is_validator_bonded). */
    {
        const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
        uint64_t v2_tip = 0, H = 0;

        if (nodus_witness_v2_tip_height(p->w, &v2_tip) == 0 &&
            nodus_stprobe_epoch_for_tip(v2_tip, E, &H) == 0) {
            bonded_add_storage_set(p, &nb, &n_new, &cap_new, H);
            if (H > E) {
                bonded_add_storage_set(p, &nb, &n_new, &cap_new, H - E);
            }
        }
    }
    bonded_add_committee(p, &nb, &n_new, &cap_new, tip + 1);
    if (tip >= 1) {
        bonded_add_committee(p, &nb, &n_new, &cap_new, tip - 1);
    }
    if (n_new > 1) {
        qsort(nb, (size_t)n_new, sizeof(*nb), bonded_cmp);
    }
    bonded_purge_new(p, nb, n_new);
    free(p->bonded);
    p->bonded = nb;
    p->n_bonded = n_new;
    p->cap_bonded = cap_new;
    p->bonded_valid = true;
    p->bonded_derive_ok = derive_ok;
    p->bonded_tip = tip;
    p->host.self_bonded = bonded_find(p, p->host.self_id) != NULL;
    if (p->host.self_bonded && !was_self && p->host.pex != NULL) {
        cmt_p2p_pex_own_record_changed(p->host.pex);     /* R-P2P-41 */
    }
}

static void bonded_maybe_refresh(nodus_witness_p2p_t *p)
{
    uint64_t tip = 0;

    if (p->w == NULL || p->w->db == NULL) {
        if (p->n_bonded != 0 || !p->bonded_valid) {
            nodus_witness_p2p_refresh_bonded(p);
        }
        return;
    }
    if (!p->bonded_valid ||
        (nodus_witness_block_height_checked(p->w, &tip) == 0 && tip != p->bonded_tip)) {
        nodus_witness_p2p_refresh_bonded(p);
    }
}

bool nodus_witness_p2p_is_bonded(nodus_witness_p2p_t *p, const char *id)
{
    return p != NULL && bonded_find(p, id) != NULL;
}

bool nodus_witness_p2p_is_validator_bonded(nodus_witness_p2p_t *p, const char *id)
{
    const p2p_bonded_t *b = p != NULL ? bonded_find(p, id) : NULL;

    return b != NULL && b->validator;
}

int nodus_witness_p2p_bonded_count(nodus_witness_p2p_t *p)
{
    return p != NULL ? p->n_bonded : 0;
}

bool nodus_witness_p2p_bonded_at(nodus_witness_p2p_t *p, int i,
                                 char id[CMT_P2P_ID_CAP],
                                 uint8_t pk[NODUS_PK_BYTES])
{
    if (p == NULL || i < 0 || i >= p->n_bonded) {
        return false;
    }
    if (id != NULL) {
        memcpy(id, p->bonded[i].id, CMT_P2P_ID_CAP);
    }
    if (pk != NULL) {
        memcpy(pk, p->bonded[i].pk, NODUS_PK_BYTES);
    }
    return true;
}

/*
 * ACTIVE-ROLE set (operator decisions 2026-10-24 addendum 2026-10-26: "a node
 * active in ANY role is exempt from ALL of the per-IP limits" of the 4001 /
 * WS / 4002 accept). It is the bonded set above (validators ACTIVE or
 * ELIGIBLE, tip ± 1 committees, the frozen S(H) / S(H − E) members — reused
 * as it is, not re-derived) UNION the storage registry rows ACTIVE or
 * EXITING (v2_storage_nodes.status 1 / 2), by node_fp. The registry rows are
 * added HERE and not to the bonded set because the bonded set is the 4004
 * admission rule, decided by membership and not by status (a newly ACTIVE
 * row is not a member until the next boundary — header, BONDED SET), and
 * 4004 must not change. Output: SHA3-512 fingerprints of the public keys
 * (node ids), the key a proven session is looked up by. -1 when the set
 * does not fit `max` or the registry cannot be read (the caller treats the
 * set as UNKNOWN — nothing is exempted).
 */
int nodus_witness_p2p_roles_fill(nodus_witness_p2p_t *p, uint8_t (*fps)[64],
                                 uint32_t max, uint32_t *n_out)
{
    uint32_t n = 0;
    int i;

    if (p == NULL || fps == NULL || n_out == NULL) {
        return -1;
    }
    /* The bonded part must come from a derivation that ran to the end at
     * the current tip: never an old set kept by 4004 after a failed read
     * (the caches would stamp it fresh). */
    if (p->bonded_valid && !p->bonded_derive_ok) {
        nodus_witness_p2p_refresh_bonded(p);   /* retry the failed derivation */
    } else {
        bonded_maybe_refresh(p);      /* bring it to the current tip first */
    }
    if (!p->bonded_valid || !p->bonded_derive_ok) {
        return -1;
    }
    for (i = 0; i < p->n_bonded; i++) {
        nodus_pubkey_t pub;
        nodus_key_t fp;

        if (n >= max) {
            return -1;
        }
        memcpy(pub.bytes, p->bonded[i].pk, NODUS_PK_BYTES);
        if (nodus_fingerprint(&pub, &fp) != 0) {
            return -1;
        }
        memcpy(fps[n++], fp.bytes, 64);
    }
    if (p->w != NULL && p->w->db != NULL) {
        sqlite3_stmt *st = NULL;
        int rc;

        if (sqlite3_prepare_v2(p->w->db,
                               "SELECT node_fp FROM v2_storage_nodes "
                               "WHERE status IN (?1, ?2)",
                               -1, &st, NULL) != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_int(st, 1, (int)DNA_V2_STORAGE_ACTIVE);
        sqlite3_bind_int(st, 2, (int)DNA_V2_STORAGE_EXITING);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            uint32_t j;
            const uint8_t *f = (const uint8_t *)sqlite3_column_blob(st, 0);
            bool dup = false;

            if (sqlite3_column_bytes(st, 0) != 64 || f == NULL) {
                /* a malformed registry row is an export error, not a row
                 * to skip: the set would silently lose a member */
                sqlite3_finalize(st);
                return -1;
            }
            for (j = 0; j < n && !dup; j++) {
                dup = memcmp(fps[j], f, 64) == 0;
            }
            if (dup) {
                continue;
            }
            if (n >= max) {
                sqlite3_finalize(st);
                return -1;
            }
            memcpy(fps[n++], f, 64);
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            return -1;
        }
    }
    *n_out = n;
    return 0;
}

static bool h_is_bonded(void *ctx, const char *id)
{
    return nodus_witness_p2p_is_bonded((nodus_witness_p2p_t *)ctx, id);
}

static int h_bonded_count(void *ctx)
{
    return nodus_witness_p2p_bonded_count((nodus_witness_p2p_t *)ctx);
}

/* Free entries of the state machine's peer queue (cmt_cs_t.peer_q,
 * CMT_CS_MSG_QUEUE_SIZE = 1000 = consensus/state.go:168's msgQueueSize).
 * No lane bound, or no state machine behind it: unbounded — PEX, the
 * 0x70 / 0x71 channels and a pre-genesis joiner never wait (and a reactor
 * that is not running enqueues nothing, cmt_conr.c:739-741). */
static size_t peer_q_room(const nodus_witness_p2p_t *p)
{
    size_t len;

    if (p->conr == NULL || p->conr->cs == NULL) {
        return SIZE_MAX;
    }
    len = p->conr->cs->peer_q_len;
    return len < (size_t)CMT_CS_MSG_QUEUE_SIZE
               ? (size_t)CMT_CS_MSG_QUEUE_SIZE - len : 0;
}

/*
 * The transport's `may_receive` row — the consensus reactor's blocking
 * `peerMsgQueue <-` (consensus/reactor.go:333, :339, :359) in the
 * single-loop form: ROOM FOR ONE MESSAGE. The reference blocks each
 * message on its own slot; here the question is asked before EVERY
 * message a peer connection delivers (cmt_p2p_peer_pump →
 * cmt_p2p_mconn_recv_n with max 1) and before every socket read
 * (io_read). The lane tick (nodus_witness.c witness_cmt_tick) drains the
 * queue between two polls.
 *
 * WHY NOTHING READ IS EVER DROPPED (the invariant the deleted 483-message
 * step margin, register R-P2P-57, used to protect): a message reaches
 * cons_receive only if this row answered true right before the packets
 * that completed it were consumed, i.e. with >= 1 free entry; one
 * delivered message enqueues at most ONE entry (Proposal
 * cmt_conr.c:950-953, BlockPart :975-978, Vote :1014-1016 — the only
 * three enqueue sites, each a single cs_q_push, cmt_cs.c:761), and the
 * push happens synchronously inside that delivery, so the next question
 * sees it. No step size and no byte arithmetic remain. The bytes of a
 * message that may not be delivered stay in the connection's buffers
 * (pbuf / rbuf / the socket) until the queue has room — TCP
 * backpressure, as in the reference.
 */
static bool h_may_receive(void *ctx)
{
    return peer_q_room((const nodus_witness_p2p_t *)ctx) >= 1;
}

/*
 * The per-peer share of the state machine's peer queue behind the
 * contended threshold (h_recv_near_full): the queue divided evenly over
 * every index the consensus seam has — CMT_CS_MSG_QUEUE_SIZE (1000,
 * consensus/state.go:168) / CMT_CONR_MAX_PEERS (128) = 7 entries. So the
 * threshold, connected peers × share, never exceeds the queue itself
 * (128 × 7 = 896 < 1000), and with every index in use the queue is
 * contended below nearly its whole size.
 * ⚠ NOT GROUNDED — the reference has no share (its blocked goroutines
 * need no decision; decision 2026-09-27-p2p-fix-2.md (4) names "a
 * per-pass share" and leaves the number to the port).
 */
#define NODUS_P2P_RECV_SHARE ((size_t)CMT_CS_MSG_QUEUE_SIZE / (size_t)CMT_CONR_MAX_PEERS)
_Static_assert((size_t)CMT_CS_MSG_QUEUE_SIZE / (size_t)CMT_CONR_MAX_PEERS >= 1,
               "every consensus index must have a share of at least one entry");

/*
 * The transport's `recv_near_full` row — the queue is CONTENDED: fewer
 * free entries than connected peers × NODUS_P2P_RECV_SHARE, i.e. it can
 * no longer give every peer its share (decision 2026-09-27-p2p-fix-2.md
 * (4); RT2 A-F1 — the former "room < peers" rule let one peer take all
 * but n − 1 entries first). From here on each peer delivers ONE
 * queue-entering message per pump and the walks move on, sweep after
 * sweep while room remains (cmt_p2p_peer.h "THE RECEIVE GATE",
 * cmt_p2p_transport_tick), which is the order the Go runtime gives
 * blocked senders on a full channel (FIFO sendq): every waiting
 * recvRoutine gets one freed slot in turn. Above the threshold a peer
 * delivers until the queue becomes contended — every other peer's share
 * is still there.
 * ⚠ NOT GROUNDED as a threshold — the reference has none (register
 * R-P2P-58, replaced by this rule).
 */
static bool h_recv_near_full(void *ctx)
{
    const nodus_witness_p2p_t *p = (const nodus_witness_p2p_t *)ctx;
    size_t room = peer_q_room(p);
    int n = p->host.sw_init ? cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&p->host.sw)) : 0;

    if (room == SIZE_MAX) {
        return false;
    }
    return room < (size_t)(n > 1 ? n : 1) * NODUS_P2P_RECV_SHARE;
}

/*
 * The transport's `queue_mark` row: the peer queue's LENGTH. A delivered
 * message entered the queue exactly when the length moved across its
 * delivery — the pump compares the value right before and right after
 * the one recv_n call that delivered it (cmt_p2p_peer_pump). Exact
 * because nothing POPS the queue inside a delivery: the only pop is
 * cmt_cs_step's (cmt_cs.c:1623), which runs from the lane tick
 * (nodus_witness.c), never from a reactor Receive; and a delivery pushes
 * at most one entry (Proposal cmt_conr.c:950-953, BlockPart :975-978,
 * Vote :1014-1016 — each one cs_q_push, cmt_cs.c:761). Chosen over "the
 * channel id decides" because channel 0x21 also carries ProposalPOL and
 * 0x23 VoteSetBits, which enter no queue. No lane (a joiner, before
 * genesis): 0 — nothing enters a queue, and the queue is never contended.
 */
static uint64_t h_queue_mark(void *ctx)
{
    const nodus_witness_p2p_t *p = (const nodus_witness_p2p_t *)ctx;

    if (p->conr == NULL || p->conr->cs == NULL) {
        return 0;
    }
    return (uint64_t)p->conr->cs->peer_q_len;
}

static bool h_bonded_pubkey(void *ctx, const char *id,
                            uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    const p2p_bonded_t *b = bonded_find((const nodus_witness_p2p_t *)ctx, id);

    if (b == NULL) {
        return false;
    }
    memcpy(pk, b->pk, QGP_DSA87_PUBLICKEYBYTES);
    return true;
}

/* The signed-address lookup is the host's (nodus_p2p_host_signed_addr). */
bool nodus_witness_p2p_signed_addr(nodus_witness_p2p_t *p,
                                   const uint8_t pk[NODUS_PK_BYTES],
                                   char *out, size_t cap)
{
    return p != NULL && nodus_p2p_host_signed_addr(&p->host, pk, out, cap);
}

/* ── the consensus seam (file header) ───────────────────────────────── */

/* A reactor call made from inside a p2p callback returned `rc`. CMT_FAULT
 * is node-local (W1.7: a store, allocation or wiring failure of THIS
 * node, never a peer's input) and must stop consensus participation; the
 * callback returns void, so the fault is logged and made sticky here and
 * nodus_witness_p2p_lane_tick returns it (the reference panics at the
 * same places, e.g. mempool/clist_mempool.go:272-274). CMT_REJECT and
 * CMT_OK are not faults and are left to the caller. */
static void lane_fault_note(nodus_witness_p2p_t *p, int rc, const char *what,
                            const char *peer_id, int index)
{
    if (rc != CMT_FAULT) {
        return;
    }
    QGP_LOG_ERROR(LOG_TAG, "%s: CMT_FAULT (peer %s, index %d) — consensus "
                  "participation stops at the next lane tick", what,
                  peer_id != NULL ? peer_id : "-", index);
    p->lane_fault = true;
}

static int lane_find(const nodus_witness_p2p_t *p, const cmt_p2p_peer_t *peer)
{
    int i;

    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer == peer) {
            return i;
        }
    }
    return -1;
}

static int lane_slot_evict_for(nodus_witness_p2p_t *p, cmt_p2p_peer_t *peer);

static int lane_slot_for(nodus_witness_p2p_t *p, cmt_p2p_peer_t *peer)
{
    int i = lane_find(p, peer);

    if (i >= 0 || peer == NULL) {
        return i;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {         /* the lowest free index */
        if (p->slots[i].peer == NULL) {
            memset(&p->slots[i], 0, sizeof(p->slots[i]));
            p->slots[i].peer = peer;
            return i;
        }
    }
    i = lane_slot_evict_for(p, peer);                  /* validator priority */
    if (i >= 0) {
        return i;
    }
    QGP_LOG_WARN(LOG_TAG, "peer %s gets no consensus index (all %d in use)",
                 cmt_p2p_peer_id(peer), (int)CMT_CONR_MAX_PEERS);
    return -1;
}

static void lane_slot_release(nodus_witness_p2p_t *p, int i)
{
    if (p->slots[i].cons_removed && p->slots[i].mem_removed) {
        memset(&p->slots[i], 0, sizeof(p->slots[i]));
    }
}

/* Take index `i` out of both reactors and free it — a peer the switch
 * dropped without a RemovePeer (switch.go:812-866: an addPeer that fails
 * after InitPeer calls no RemovePeer, in the reference too). */
static void lane_slot_clear(nodus_witness_p2p_t *p, int i)
{
    if (p->slots[i].conr_init && p->conr != NULL) {
        lane_fault_note(p, cmt_conr_remove_peer(p->conr, i),
                        "conr RemovePeer", NULL, i);
    }
    if (p->slots[i].memr_init && p->memr != NULL) {
        lane_fault_note(p, cmt_memr_remove_peer(p->memr, i),
                        "memr RemovePeer", NULL, i);
    }
    memset(&p->slots[i], 0, sizeof(p->slots[i]));
}

/* Whether `id` is in this node's CONFIGURED unconditional_peer_ids. Not
 * cmt_p2p_switch_is_peer_unconditional: that one also answers true for
 * every bonded ID, storage-set members included (cmt_p2p_switch.c,
 * R-P2P-7). */
static bool cfg_unconditional(const nodus_witness_p2p_t *p, const char *id)
{
    int k;

    for (k = 0; k < p->host.cfg.n_unconditional_peer_ids; k++) {
        if (strcmp(p->host.cfg.unconditional_peer_ids[k], id) == 0) {
            return true;
        }
    }
    return false;
}

/* The index table is full and `peer` (not indexed yet) arrives. VALIDATOR
 * PRIORITY (operator decision 2026-10-14 "Tamam, muaf olsun. Dediğin gibi
 * olsun", docs/plans/2026-10-14-dht-v2-design.md §2 "4004 admission"):
 * when `peer` is validator-bonded (nodus_witness_p2p_is_validator_bonded),
 * a peer that is NOT is disconnected and its index goes to `peer`.
 * @return the index now holding `peer`, or -1 (nothing changed).
 *
 * Runs inside the switch's addPeer, in CONSENSUS's InitPeer — the first
 * registered reactor, so no reactor has seen `peer` yet, and `peer` is
 * not in the peer set yet (cmt_p2p_switch.c add_peer: InitPeer before
 * peer_set_add). StopPeerForError is synchronous there: transport
 * cleanup, every reactor's RemovePeer (cons_remove_peer / mem_remove_peer
 * release the index), removal from the peer set; the memory is freed at
 * the end of the tick (bury). The switch does the same inside addPeer for
 * a cross-dial (filter_peer stops the older connection).
 *
 * The choice, in index order (deterministic for this node's table; node-
 * local — an index never enters a block, a vote or state):
 *   1. an index whose peer is no longer in the switch's peer set (a failed
 *      addPeer dropped it; lane_gc would clear it after the tick) is
 *      cleared and taken — nobody is disconnected. Its pointer is
 *      compared, never dereferenced.
 *   2. else the LOWEST index whose peer is not validator-bonded, not a
 *      configured persistent peer (cmt_p2p_peer_is_persistent — the switch
 *      would redial it at once) and not a configured unconditional ID (the
 *      operator named it). That peer is stopped. */
static int lane_slot_evict_for(nodus_witness_p2p_t *p, cmt_p2p_peer_t *peer)
{
    const cmt_p2p_peer_set_t *ps;
    const char *vid = cmt_p2p_peer_id(peer);
    char        eid[CMT_P2P_ID_CAP];
    int         i, k, victim = -1;

    if (!nodus_witness_p2p_is_validator_bonded(p, vid)) {
        return -1;
    }
    ps = cmt_p2p_switch_peers(&p->host.sw);
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        const cmt_p2p_peer_t *q = p->slots[i].peer;
        bool in_set = false;

        if (q == NULL || q == peer) {
            continue;
        }
        for (k = 0; k < ps->n; k++) {
            if (ps->list[k] == q) {
                in_set = true;
                break;
            }
        }
        if (!in_set) {                                   /* rule 1 */
            lane_slot_clear(p, i);
            p->slots[i].peer = peer;
            return i;
        }
        if (victim < 0 &&
            !nodus_witness_p2p_is_validator_bonded(p, cmt_p2p_peer_id(q)) &&
            !cmt_p2p_peer_is_persistent(q) &&
            !cfg_unconditional(p, cmt_p2p_peer_id(q))) {
            victim = i;                                  /* rule 2 */
        }
    }
    if (victim < 0) {
        return -1;
    }
    snprintf(eid, sizeof(eid), "%s", cmt_p2p_peer_id(p->slots[victim].peer));
    cmt_p2p_switch_stop_peer_for_error(&p->host.sw, p->slots[victim].peer,
                                       NODUS_P2P_STOP_LANE_EVICT);
    if (p->slots[victim].peer != NULL) {
        QGP_LOG_ERROR(LOG_TAG, "index %d still held after stopping %s — "
                      "validator %s gets no consensus index", victim, eid, vid);
        return -1;
    }
    p->slots[victim].peer = peer;                        /* released: zeroed */
    QGP_LOG_INFO(LOG_TAG, "all %d consensus indices in use: non-validator %s "
                 "disconnected, its index %d given to validator %s",
                 (int)CMT_CONR_MAX_PEERS, eid, victim, vid);
    return victim;
}

/* After the switch's tick every indexed peer must be in the peer set;
 * one that is not was dropped by a failed addPeer (above). Pointers are
 * compared, never dereferenced — the switch may already have freed it. */
static void lane_gc(nodus_witness_p2p_t *p)
{
    const cmt_p2p_peer_set_t *ps = cmt_p2p_switch_peers(&p->host.sw);
    int i, k;

    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        bool in_set = false;

        if (p->slots[i].peer == NULL) {
            continue;
        }
        for (k = 0; k < ps->n; k++) {
            if (ps->list[k] == p->slots[i].peer) {
                in_set = true;
                break;
            }
        }
        if (!in_set) {
            lane_slot_clear(p, i);
        }
    }
}

/* SHA3-512(the authenticated ML-DSA-87 key), all 64 bytes — the node
 * fingerprint a registry row is keyed by (the archive probe's pin). */
static bool peer_fp(const cmt_p2p_peer_t *peer,
                    uint8_t out[QGP_SHA3_512_DIGEST_LENGTH])
{
    const uint8_t *pk;

    if (peer == NULL || peer->conn == NULL || peer->conn->sc == NULL ||
        !cmt_p2p_sc_is_authenticated(peer->conn->sc) ||
        (pk = cmt_p2p_sc_remote_pubkey(peer->conn->sc)) == NULL ||
        qgp_sha3_512(pk, CMT_P2P_SC_DSA_PK_SIZE, out) != 0) {
        return false;
    }
    return true;
}

/* SHA3-512(the authenticated ML-DSA-87 key)[0..31] (file header). */
static bool peer_wid(const cmt_p2p_peer_t *peer, uint8_t out[32])
{
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];

    if (!peer_fp(peer, fp)) {
        return false;
    }
    memcpy(out, fp, 32);
    return true;
}

static void lane_conr_init(nodus_witness_p2p_t *p, int i)
{
    uint8_t id[32];
    int     rc;

    if (p->conr == NULL || p->slots[i].conr_init || !peer_wid(p->slots[i].peer, id)) {
        return;
    }
    rc = cmt_conr_init_peer(p->conr, i, id);              /* switch.go:830-832 */
    if (rc == CMT_OK) {
        p->slots[i].conr_init = true;
    }
    lane_fault_note(p, rc, "conr InitPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_memr_init(nodus_witness_p2p_t *p, int i)
{
    int rc;

    if (p->memr == NULL || p->slots[i].memr_init) {
        return;
    }
    rc = cmt_memr_init_peer(p->memr, i);
    if (rc == CMT_OK) {
        p->slots[i].memr_init = true;
    }
    lane_fault_note(p, rc, "memr InitPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_conr_add(nodus_witness_p2p_t *p, int i)
{
    int rc;

    if (p->conr == NULL || !p->slots[i].conr_init || p->slots[i].conr_added) {
        return;
    }
    rc = cmt_conr_add_peer(p->conr, i);                   /* switch.go:859-861 */
    if (rc == CMT_OK) {
        p->slots[i].conr_added = true;
    }
    lane_fault_note(p, rc, "conr AddPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_memr_add(nodus_witness_p2p_t *p, int i)
{
    const cmt_p2p_peer_t *peer = p->slots[i].peer;
    int                   rc;

    if (p->memr == NULL || !p->slots[i].memr_init || p->slots[i].memr_added) {
        return;
    }
    rc = cmt_memr_add_peer(p->memr, i, cmt_p2p_peer_is_persistent(peer),
                           cmt_p2p_switch_is_peer_unconditional(
                               &p->host.sw, cmt_p2p_peer_id(peer)));
    if (rc == CMT_OK) {
        p->slots[i].memr_added = true;
    }
    lane_fault_note(p, rc, "memr AddPeer", cmt_p2p_peer_id(peer), i);
}

static void process_pending_stops(nodus_witness_p2p_t *p)
{
    int i;

    if (!p->any_pending_stop) {
        return;
    }
    p->any_pending_stop = false;
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        int reason = p->slots[i].pending_stop;
        cmt_p2p_peer_t *peer = p->slots[i].peer;

        if (reason == 0) {
            continue;
        }
        p->slots[i].pending_stop = 0;
        if (peer != NULL) {
            cmt_p2p_switch_stop_peer_for_error(&p->host.sw, peer, reason);
        }
    }
}

/* CONSENSUS shim reactor (channels 0x20-0x23, cmt_conr_get_channels). */
static const cmt_p2p_ch_desc_t *cons_channels(void *ctx, int *n)
{
    *n = CMT_CONR_NUM_CHANNELS;
    return ((nodus_witness_p2p_t *)ctx)->cons_desc;
}

static void cons_init_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    /* InitPeer runs once per peer object, and CONSENSUS is registered
     * before MEMPOOL: an index already naming this pointer belongs to a
     * freed peer whose memory was reused — clear it. */
    if (i >= 0) {
        lane_slot_clear(p, i);
    }
    i = lane_slot_for(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_conr_init(p, i);
    }
}

static void cons_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_conr_add(p, i);
    }
}

static void cons_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i < 0) {
        return;
    }
    if (p->slots[i].conr_init && p->conr != NULL) {
        lane_fault_note(p, cmt_conr_remove_peer(p->conr, i),   /* reactor.go:213-223 */
                        "conr RemovePeer", cmt_p2p_peer_id(peer), i);
    }
    p->slots[i].conr_init = false;
    p->slots[i].conr_added = false;
    p->slots[i].cons_removed = true;
    p->slots[i].pending_stop = 0;
    lane_slot_release(p, i);
}

static void cons_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                         const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, src), rc;

    if (i < 0 || p->conr == NULL || !p->slots[i].conr_added) {
        QGP_LOG_DEBUG(LOG_TAG, "consensus message from %s before the reactor "
                      "knows it — dropped (R-P2P-47)", cmt_p2p_peer_id(src));
        return;
    }
    rc = cmt_conr_receive(p->conr, i, ch_id, msg, len);
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "conr receive: CMT_FAULT (index %d channel "
                      "0x%02x)", i, ch_id);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    } else if (rc == CMT_REJECT) {
        /* The state machine's peer queue was full (R3-A-2) and the
         * message is DROPPED after its PeerState effects — the reference
         * blocks instead (consensus/reactor.go:333, :339, :359). Should be
         * unreachable: every message is delivered only after h_may_receive
         * found room for ONE, and one message enqueues at most one entry
         * (h_may_receive's invariant). A line here means that invariant
         * is broken. recv_msg is the message this call decoded
         * (cmt_conr.h, valid until the next receive). */
        int kind = p->conr->recv_msg != NULL ? (int)p->conr->recv_msg->kind : -1;

        QGP_LOG_WARN(LOG_TAG, "conr receive: REJECT (peer queue full) — "
                     "%s DROPPED from index %d channel 0x%02x",
                     kind == (int)CMT_PB_CONS_MSG_PROPOSAL   ? "Proposal" :
                     kind == (int)CMT_PB_CONS_MSG_BLOCK_PART ? "BlockPart" :
                     kind == (int)CMT_PB_CONS_MSG_VOTE       ? "Vote" :
                                                               "message",
                     i, ch_id);
    }
    process_pending_stops(p);
}

/* MEMPOOL shim reactor (channel 0x30, cmt_memr_get_channels). */
static const cmt_p2p_ch_desc_t *mem_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->mem_desc;
}

static void mem_init_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);                 /* CONSENSUS's InitPeer assigned it */

    if (i >= 0 && p->lane_live) {
        lane_memr_init(p, i);
    }
}

static void mem_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_memr_add(p, i);
    }
}

static void mem_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i < 0) {
        return;
    }
    if (p->slots[i].memr_init && p->memr != NULL) {
        lane_fault_note(p, cmt_memr_remove_peer(p->memr, i),   /* mempool/reactor.go:135-138 */
                        "memr RemovePeer", cmt_p2p_peer_id(peer), i);
    }
    p->slots[i].memr_init = false;
    p->slots[i].memr_added = false;
    p->slots[i].mem_removed = true;
    lane_slot_release(p, i);
}

static void mem_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                        const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, src), rc;
    uint8_t id[32];

    (void)ch_id;
    if (i < 0 || p->memr == NULL || !p->slots[i].memr_added) {
        QGP_LOG_DEBUG(LOG_TAG, "mempool message from %s before the reactor "
                      "knows it — dropped (R-P2P-47)", cmt_p2p_peer_id(src));
        return;
    }
    if (!peer_wid(src, id)) {
        return;
    }
    rc = cmt_memr_receive(p->memr, i, msg, len, id, sizeof(id));
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "memr receive: CMT_FAULT (index %d)", i);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    } else if (rc == CMT_REJECT) {
        QGP_LOG_WARN(LOG_TAG, "memr receive: REJECT from index %d", i);
    }
    process_pending_stops(p);
}

/* BLOCKSYNC shim reactor (channel 0x40, cmt_bsync_reactor_get_channels;
 * header "THE BLOCK SYNC SEAM"). No InitPeer: blocksync/reactor.go
 * embeds BaseReactor's no-op InitPeer. */
static const cmt_p2p_ch_desc_t *bs_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->bs_desc;
}

/* reactor.go:195-208 AddPeer — only once the lane is live (R-P2P-47);
 * lane_live runs it for the peers connected before. */
static void bs_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_live && p->bsync != NULL) {
        /* cmt_bsync_reactor_add_peer answers CMT_OK or CMT_FAULT only. */
        lane_fault_note(p, cmt_bsync_reactor_add_peer(p->bsync,
                                                      cmt_p2p_peer_id(peer)),
                        "blocksync AddPeer", cmt_p2p_peer_id(peer), -1);
    }
}

/* reactor.go:210-213 RemovePeer — the pool forgets the ID. */
static void bs_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i >= 0) {
        p->slots[i].bs_status_held = false;     /* a held status dies here */
    }
    if (p->bsync != NULL) {
        cmt_bsync_reactor_remove_peer(p->bsync, cmt_p2p_peer_id(peer));
    }
}

/* ⚠ DEVIATION (no reference counterpart — the reference has no pre-live
 * window: p2p/switch.go:235-247 starts every reactor BEFORE it accepts a
 * peer, so a peer's AddPeer StatusResponse, reactor.go:195-208, always
 * reaches a running reactor). Here R-P2P-47 keeps the reactors away
 * from peers until nodus_witness_p2p_lane_live, and dropping that one
 * message made the pool learn the peer's height only at its 10 s status
 * broadcast (reactor.go:401, :447-449) — every node's switch to
 * consensus late by up to one interval. So while the lane is not live a
 * 0x40 StatusResponse is KEPT — only the LATEST one per peer (its lane
 * slot, keyed by the peer's p2p ID), canonical re-marshal, at most
 * NODUS_P2P_BS_STATUS_MAX bytes — and replayed into the reactor right
 * after it runs (lane_live). It is discarded when the peer is removed or
 * the lane unbound. Every other 0x40 message is still DROPPED before the
 * lane is live, undecodable bytes included, and the sender is never
 * stopped for anything received then (a pre-genesis joiner has no chain
 * to answer from). A peer holding no lane index keeps nothing. */
static void bs_hold_status(nodus_witness_p2p_t *p, cmt_p2p_peer_t *src,
                           const uint8_t *msg, size_t len)
{
    cmt_bsync_msg_t m;
    int i = lane_find(p, src);
    size_t n = 0;

    if (i < 0) {
        return;
    }
    cmt_bsync_msg_init(&m);
    if (cmt_bsync_msg_unmarshal(msg, len, &m) != CMT_OK ||
        m.kind != CMT_BSYNC_MSG_STATUS_RESPONSE) {
        cmt_bsync_msg_release(&m);
        return;
    }
    if (cmt_bsync_msg_marshal(&m, p->slots[i].bs_status,
                              sizeof(p->slots[i].bs_status), &n) == CMT_OK) {
        p->slots[i].bs_status_len = n;
        snprintf(p->slots[i].bs_status_id, CMT_P2P_ID_CAP, "%s",
                 cmt_p2p_peer_id(src));
        p->slots[i].bs_status_held = true;       /* the latest replaces */
    }
    cmt_bsync_msg_release(&m);
}

/* Replay the held StatusResponse of index `i` into the running block sync
 * reactor (the DEVIATION above), once; the entry is discarded either way. */
static void bs_replay_status(nodus_witness_p2p_t *p, int i)
{
    const char *id;

    if (!p->slots[i].bs_status_held) {
        return;
    }
    p->slots[i].bs_status_held = false;
    id = cmt_p2p_peer_id(p->slots[i].peer);
    if (p->bsync == NULL || strcmp(id, p->slots[i].bs_status_id) != 0) {
        return;
    }
    if (cmt_bsync_reactor_receive(p->bsync, id, p->slots[i].bs_status,
                                  p->slots[i].bs_status_len) == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "blocksync receive (held status): CMT_FAULT "
                      "(peer %s)", id);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    }
}

bool nodus_witness_p2p_bsync_status_held(const nodus_witness_p2p_t *p,
                                         const char *peer_id,
                                         int64_t *out_height)
{
    int i;

    if (p == NULL || peer_id == NULL) {
        return false;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer != NULL && p->slots[i].bs_status_held &&
            strcmp(p->slots[i].bs_status_id, peer_id) == 0) {
            if (out_height != NULL) {
                cmt_bsync_msg_t m;

                cmt_bsync_msg_init(&m);
                *out_height = cmt_bsync_msg_unmarshal(p->slots[i].bs_status,
                                                      p->slots[i].bs_status_len,
                                                      &m) == CMT_OK ? m.height : -1;
                cmt_bsync_msg_release(&m);
            }
            return true;
        }
    }
    return false;
}

/* reactor.go:348-381 Receive. Before the lane is live — a pinned-genesis
 * joiner has no chain, a node before genesis time has no running
 * reactors — the message is DROPPED and the sender is NOT stopped
 * (R-P2P-47): an honest peer asks every node it meets. The one exception
 * is a StatusResponse, held for the replay (DEVIATION, bs_hold_status). */
static void bs_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int rc;

    (void)ch_id;
    if (!p->lane_live) {
        bs_hold_status(p, src, msg, len);
        QGP_LOG_DEBUG(LOG_TAG, "blocksync message from %s before the reactor "
                      "runs — dropped, a StatusResponse held (R-P2P-47)",
                      cmt_p2p_peer_id(src));
        return;
    }
    if (p->bsync == NULL) {
        QGP_LOG_DEBUG(LOG_TAG, "blocksync message from %s with no block sync "
                      "reactor — dropped", cmt_p2p_peer_id(src));
        return;
    }
    rc = cmt_bsync_reactor_receive(p->bsync, cmt_p2p_peer_id(src), msg, len);
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "blocksync receive: CMT_FAULT (peer %s)",
                      cmt_p2p_peer_id(src));
        p->lane_fault = true;          /* sticky — lane_fault_note */
    }
    process_pending_stops(p);
}

/* 0x70 — the genesis bundle (the former verbs 24/25). */
static const cmt_p2p_ch_desc_t *gb_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->gb_desc;
}

static void noop_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    (void)ctx;
    (void)peer;
}

static void noop_remove(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    (void)ctx;
    (void)peer;
    (void)reason;
}

static void gb_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_t3_msg_t m;

    (void)ch_id;
    if (nodus_t3_gbundle_decode(msg, len, &m) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x70 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->host.sw, src, NODUS_P2P_STOP_DECODE_0X70);
        return;
    }
    if (p->w == NULL) {
        return;
    }
    if (m.type == NODUS_T3_V2_GBUNDLE_REQ) {
        nodus_witness_v2_sync_handle_gbundle_q(p->w, cmt_p2p_peer_id(src),
                                               &m.w_v2_gbundle_q);
    } else {
        /* The sender travels with the response: the joiner takes a chunk
         * only from the peer it asked (red-team H2). */
        nodus_witness_v2_join_handle_gbundle_r(p->w, cmt_p2p_peer_id(src),
                                               &m.w_v2_gbundle_r);
    }
}

bool nodus_witness_p2p_gb_request(nodus_witness_p2p_t *p, const char *peer_id,
                                  uint64_t offset, const uint8_t *msg,
                                  size_t len)
{
    if (p == NULL || peer_id == NULL || strlen(peer_id) >= sizeof(p->gb_out_peer)) {
        return false;
    }
    /* A new request replaces the outstanding one: a late answer to the
     * old one is dropped by gb_take (the joiner asks again from its
     * accumulated offset anyway). */
    p->gb_out_valid = false;
    if (!nodus_witness_p2p_send(p, peer_id, NODUS_P2P_CH_GBUNDLE, msg, len)) {
        return false;
    }
    snprintf(p->gb_out_peer, sizeof(p->gb_out_peer), "%s", peer_id);
    p->gb_out_offset = offset;
    p->gb_out_valid = true;
    return true;
}

bool nodus_witness_p2p_gb_take(nodus_witness_p2p_t *p, const char *peer_id,
                               uint64_t offset)
{
    if (p == NULL || peer_id == NULL || !p->gb_out_valid ||
        strcmp(p->gb_out_peer, peer_id) != 0 || p->gb_out_offset != offset) {
        return false;
    }
    p->gb_out_valid = false;                 /* one answer per request */
    return true;
}

bool nodus_witness_p2p_gb_serve_allow(nodus_witness_p2p_t *p, const char *peer_id,
                                      uint64_t now_ms)
{
    int i, free_i = -1, stale_i = -1, target;

    if (p == NULL || peer_id == NULL || peer_id[0] == '\0' ||
        strlen(peer_id) >= sizeof(p->gb_serve[0].id)) {
        return false;
    }
    for (i = 0; i < NODUS_P2P_GB_SERVE_SLOTS; i++) {
        p2p_gb_serve_t *e = &p->gb_serve[i];
        /* A clock that went back reads as "just served" (the
         * rate-limit table's skew rule, nodus_cc_rate_limit_check). */
        uint64_t elapsed = now_ms >= e->last_ms ? now_ms - e->last_ms : 0;

        if (e->id[0] == '\0') {
            if (free_i < 0) {
                free_i = i;
            }
            continue;
        }
        if (strcmp(e->id, peer_id) == 0) {
            if (elapsed < NODUS_P2P_GB_SERVE_GAP_MS) {
                return false;
            }
            e->last_ms = now_ms;
            return true;
        }
        if (elapsed >= NODUS_P2P_GB_SERVE_GAP_MS && stale_i < 0) {
            stale_i = i;       /* past its gap: holds nobody back any more */
        }
    }
    target = free_i >= 0 ? free_i : stale_i;
    if (target < 0) {
        /* Every entry was served inside the gap: more requesters than
         * the host can index, all at once — refuse this one. */
        QGP_LOG_DEBUG(LOG_TAG, "0x70 request from %s not served: every "
                      "serve slot busy", peer_id);
        return false;
    }
    snprintf(p->gb_serve[target].id, sizeof(p->gb_serve[target].id), "%s", peer_id);
    p->gb_serve[target].last_ms = now_ms;
    return true;
}

/*
 * The serving side's bundle copy (RT2 B-F2): the bytes are read from the
 * chain database ONCE and served from memory after that — the former
 * SELECT + malloc + free per chunk request made every requester's 100 ms
 * gap a full bundle read. The bundle is immutable once the genesis
 * committed (nodus_witness_v2_bundle_persist refuses a row that differs,
 * nodus_witness_v2_bundle.h "WHY IT IS PERSISTED AT DERIVATION TIME"), so
 * the copy can never go stale for its chain; it is keyed by the chain id
 * anyway, so a host that finds itself on another chain reloads. No
 * reference counterpart (R-P2P-5).
 */
bool nodus_witness_p2p_gb_bundle(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                 const uint8_t **out, size_t *len)
{
    if (p == NULL || chain == NULL || out == NULL || len == NULL ||
        p->gb_bundle == NULL || memcmp(p->gb_bundle_chain, chain, 32) != 0) {
        return false;
    }
    *out = p->gb_bundle;
    *len = p->gb_bundle_len;
    return true;
}

bool nodus_witness_p2p_gb_bundle_keep(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                      uint8_t *bytes, size_t len)
{
    if (p == NULL || chain == NULL || bytes == NULL || len == 0) {
        free(bytes);
        return false;
    }
    free(p->gb_bundle);
    p->gb_bundle = bytes;
    p->gb_bundle_len = len;
    memcpy(p->gb_bundle_chain, chain, 32);
    return true;
}

/* 0x71 — the governance approval (the former verbs 40/41). */
static const cmt_p2p_ch_desc_t *cc_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->cc_desc;
}

static void cc_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_t3_msg_t m;
    uint8_t wid[32];

    (void)ch_id;
    if (nodus_t3_cc_appr_decode(msg, len, &m) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x71 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->host.sw, src, NODUS_P2P_STOP_DECODE_0X71);
        return;
    }
    if (m.type != NODUS_T3_CC_APPR_REQ) {
        /* A response is taken only by this node's own pending approval
         * collection, only when it names that collection's request (its
         * `rq`, decision 2026-09-27-p2p-fix-2.md (2)) and only from a seat
         * it asked and has not heard from (decision
         * 2026-09-26-cc-approval-via-own-node.md (3)); every other
         * response is dropped, as verb 41 was at the tier-3 dispatcher's
         * `default:`. DEBUG, not WARN (RT2 B-F3 / Codex 11): a late honest
         * answer after the collection's deadline looks exactly like an
         * unsolicited one, and any connected peer could otherwise write
         * WARN lines at will. The sender is not stopped, for the same
         * reason. */
        if (p->w == NULL ||
            !nodus_witness_cc_collect_on_rsp(p->w, cmt_p2p_peer_id(src),
                                             &m.cc_appr_rsp)) {
            QGP_LOG_DEBUG(LOG_TAG, "unsolicited 0x71 response from %s dropped",
                          cmt_p2p_peer_id(src));
        }
        return;
    }
    if (p->w == NULL || !peer_wid(src, wid)) {
        return;
    }
    (void)nodus_witness_handle_cc_appr_req(p->w, cmt_p2p_peer_id(src), wid,
                                           &m.cc_appr_req);
}

/* 0x72 — the archive probe (package B2b-1; nodus_witness_storage_
 * reporter.h). No reference counterpart (R-P2P-5). The sender's identity
 * handed on is the FULL SHA3-512 of its authenticated key — the probe
 * pins the registry's 64-byte node_fp, not the 32-byte p2p ID. A message
 * that does not decode stops the peer, as on 0x70 / 0x71. */
static const cmt_p2p_ch_desc_t *sp_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->sp_desc;
}

static void sp_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];

    (void)ch_id;
    if (p->w == NULL || !peer_fp(src, fp)) {
        return;
    }
    if (nodus_witness_stprobe_on_msg(p->w, cmt_p2p_peer_id(src), fp, msg,
                                     len) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x72 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->host.sw, src, NODUS_P2P_STOP_DECODE_0X72);
    }
}

/* 0x73 — the segment fetch (package B2b-2; nodus_witness_storage_
 * holder.h). No reference counterpart (R-P2P-5). As 0x72: the sender's
 * identity handed on is the FULL SHA3-512 of its authenticated key — the
 * serving side admits only a registered ACTIVE storage member, keyed by
 * that 64-byte node_fp. A message that does not decode stops the peer. */
static const cmt_p2p_ch_desc_t *sf_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->sf_desc;
}

static void sf_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];

    (void)ch_id;
    if (p->w == NULL || !peer_fp(src, fp)) {
        return;
    }
    if (nodus_witness_sthold_on_msg(p->w, cmt_p2p_peer_id(src), fp, msg,
                                    len) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x73 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->host.sw, src, NODUS_P2P_STOP_DECODE_0X73);
    }
}

/* ── the lane's host rows (cmt_conr_host_t, cmt_memr_host_t) ────────── */

/* peer.go:258-268 Send / TrySend (R-P2P-19: Send ≡ TrySend). */
static bool lane_send(void *ctx, int idx, uint8_t ch, const uint8_t *bytes,
                      size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return false;
    }
    return cmt_p2p_peer_send(p->slots[idx].peer, ch, bytes, len);
}

/* switch.go:336-359 StopPeerForError — DEFERRED until the reactor call
 * that raised it returns (file header). */
static void lane_conr_stop(void *ctx, int idx, int reason_code)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return;
    }
    p->slots[idx].pending_stop = NODUS_P2P_STOP_CONR_BASE + reason_code;
    p->any_pending_stop = true;
}

static void lane_memr_stop(void *ctx, int idx)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return;
    }
    p->slots[idx].pending_stop = NODUS_P2P_STOP_MEMR;
    p->any_pending_stop = true;
}

static int lane_now(void *ctx, cmt_time_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_now == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return p->lane_now(p->lane_now_ctx, out);
}

/* The reactors' `mono` row (ctx = this host): the lane's WAIT clock,
 * CLOCK_MONOTONIC (decision 2026-09-30-monotonic-waits.md). */
static int lane_mono(void *ctx, int64_t *out_ns)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_mono == NULL || out_ns == NULL) {
        return CMT_FAULT;
    }
    return p->lane_mono(p->lane_mono_ctx, out_ns);
}

static int lane_bs_base(void *ctx, int64_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || p->store == NULL) return CMT_FAULT;
    *out = nodus_cmt_bs_base(p->store);
    return CMT_OK;
}

static int lane_bs_height(void *ctx, int64_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || p->store == NULL) return CMT_FAULT;
    *out = nodus_cmt_bs_height(p->store);
    return CMT_OK;
}

/* reactor.go:590-596 / :660-672 — the BlockID projection of LoadBlockMeta. */
static int lane_bs_meta_block_id(void *ctx, int64_t height, cmt_block_id_t *out,
                                 bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_cmt_block_meta_t *meta;
    int rc;

    if (out == NULL || out_found == NULL || p->store == NULL) return CMT_FAULT;
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (meta == NULL) return CMT_FAULT;
    rc = nodus_cmt_bs_load_block_meta(p->store, height, meta, out_found);
    if (rc == CMT_OK && *out_found) {
        *out = meta->block_id;
    }
    free(meta);
    return rc;
}

/* reactor.go:673 LoadBlockPart — `bytes` points into part_arena, valid
 * until the next call of this row (cmt_conr.h:462-469). */
static int lane_bs_part(void *ctx, int64_t height, int index, cmt_part_t *out,
                        bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || out_found == NULL || p->store == NULL) return CMT_FAULT;
    p->part_arena.used = 0;
    return nodus_cmt_bs_load_block_part(p->store, height, index, &p->part_arena,
                                        out, out_found);
}

/* reactor.go:765 LoadBlockCommit. */
static int lane_bs_commit(void *ctx, int64_t height, cmt_commit_t *out,
                          bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->store == NULL) return CMT_FAULT;
    return nodus_cmt_bs_load_block_commit(p->store, height, p->commit_sigs,
                                          (size_t)CMT_VALSET_MAX, out, out_found);
}

/* reactor.go:763 LoadBlockExtendedCommit. */
static int lane_bs_ext_commit(void *ctx, int64_t height, cmt_extended_commit_t *out,
                              bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->store == NULL) return CMT_FAULT;
    p->ext_load_arena.used = 0;
    return nodus_cmt_bs_load_block_extended_commit(p->store, height, p->ext_sigs,
                                                   (size_t)CMT_VALSET_MAX,
                                                   &p->ext_load_arena, out,
                                                   out_found);
}

/* ── the block sync reactor's p2p rows (cmt_bsync_host_t, `ctx`) ───── */

/* reactor.go:221, :247, :365, :434 — `Switch.Peers().Get(id)` then
 * `TrySend` on 0x40; a peer not connected is `false`. */
static bool bs_try_send(void *ctx, const char *peer_id, const uint8_t *msg,
                        size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->host.sw),
                                                peer_id);

    return peer != NULL &&
           cmt_p2p_peer_try_send(peer, CMT_BSYNC_CHANNEL, msg, len);
}

/* reactor.go:197-203 — `peer.Send` (≡ TrySend, R-P2P-19). */
static bool bs_send(void *ctx, const char *peer_id, const uint8_t *msg,
                    size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->host.sw),
                                                peer_id);

    return peer != NULL && cmt_p2p_peer_send(peer, CMT_BSYNC_CHANNEL, msg, len);
}

/* reactor.go:681-684 — `Switch.Broadcast` on 0x40. */
static void bs_broadcast(void *ctx, const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    (void)cmt_p2p_switch_broadcast(&p->host.sw, CMT_BSYNC_CHANNEL, msg, len);
}

/* switch.go:336-359 StopPeerForError, DEFERRED like the other lane rows:
 * the peer by ID (a peer no longer connected is skipped — reactor.go:
 * 442-443, :661, :672), then its index. A connected peer with no
 * index cannot be deferred — logged (header). */
static void bs_stop_peer(void *ctx, const char *peer_id, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->host.sw),
                                                peer_id);
    int i;

    if (peer == NULL) {
        return;
    }
    i = lane_find(p, peer);
    if (i < 0) {
        QGP_LOG_WARN(LOG_TAG, "blocksync asked to stop %s (reason %d) but the "
                     "peer holds no index — not stopped", peer_id, reason);
        return;
    }
    p->slots[i].pending_stop = NODUS_P2P_STOP_BSYNC_BASE + reason;
    p->any_pending_stop = true;
}

int nodus_witness_p2p_bsync_host_fill(nodus_witness_p2p_t *p,
                                      cmt_bsync_host_t *out)
{
    if (p == NULL || out == NULL || !p->lane_prepared) {
        return CMT_FAULT;
    }
    out->ctx                 = p;
    out->try_send            = bs_try_send;
    out->send                = bs_send;
    out->broadcast           = bs_broadcast;
    out->stop_peer_for_error = bs_stop_peer;
    out->now                 = p->lane_now;       /* wall: bans, rate    */
    out->now_ctx             = p->lane_now_ctx;
    out->mono                = p->lane_mono;      /* every wait          */
    out->mono_ctx            = p->lane_mono_ctx;
    return CMT_OK;
}

void nodus_witness_p2p_bsync_bind(nodus_witness_p2p_t *p,
                                  cmt_bsync_reactor_t *bsync)
{
    if (p != NULL) {
        p->bsync = bsync;
    }
}

cmt_bsync_reactor_t *nodus_witness_p2p_bsync(const nodus_witness_p2p_t *p)
{
    return p != NULL ? p->bsync : NULL;
}

/* mempool/reactor.go:190-192, :222-235 — the consensus reactor's
 * PeerState is the peer's one PeerStateKey value. */
static int64_t lane_peer_height(void *ctx, int idx, bool *out_known)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->conr == NULL || idx < 0 || idx >= CMT_CONR_MAX_PEERS ||
        !p->conr->peers[idx].in_set) {
        if (out_known != NULL) *out_known = false;
        return 0;
    }
    if (out_known != NULL) *out_known = true;
    return cmt_ps_get_height(&p->conr->peers[idx].ps);
}

int nodus_witness_p2p_lane_prepare(nodus_witness_p2p_t *p,
                                   nodus_cmt_store_t *store,
                                   cmt_now_fn now, void *now_ctx,
                                   cmt_mono_fn mono, void *mono_ctx)
{
    if (p == NULL || store == NULL || now == NULL || mono == NULL ||
        p->lane_prepared) {
        return CMT_FAULT;
    }
    p->store = store;
    p->lane_now = now;
    p->lane_now_ctx = now_ctx;
    p->lane_mono = mono;
    p->lane_mono_ctx = mono_ctx;

    memset(&p->conr_host, 0, sizeof(p->conr_host));
    p->conr_host.send = lane_send;
    p->conr_host.try_send = lane_send;                     /* R-P2P-19 */
    p->conr_host.stop_peer_for_error = lane_conr_stop;
    p->conr_host.bs_base = lane_bs_base;
    p->conr_host.bs_height = lane_bs_height;
    p->conr_host.bs_load_block_meta_block_id = lane_bs_meta_block_id;
    p->conr_host.bs_load_block_part = lane_bs_part;
    p->conr_host.bs_load_block_commit = lane_bs_commit;
    p->conr_host.bs_load_block_extended_commit = lane_bs_ext_commit;
    p->conr_host.now = lane_now;
    p->conr_host.mono = lane_mono;

    memset(&p->memr_host, 0, sizeof(p->memr_host));
    p->memr_host.ctx = p;
    p->memr_host.send = lane_send;
    p->memr_host.stop_peer_for_error = lane_memr_stop;
    p->memr_host.peer_height = lane_peer_height;
    p->memr_host.mono = lane_mono;

    /* cmt_conr.h "THE RECEIVE ARENA": exactly one message's bound,
     * reset by cmt_conr_receive at the top of every call. */
    p->recv_arena.cap = (size_t)CMT_CONR_MAX_MSG_SIZE;
    p->recv_arena.buf = (uint8_t *)malloc(p->recv_arena.cap);
    p->recv_arena.used = 0;
    p->commit_sigs = (cmt_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                sizeof(*p->commit_sigs));
    p->ext_sigs = (cmt_extended_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                      sizeof(*p->ext_sigs));
    p->ext_load_arena.cap = (size_t)CMT_VALSET_MAX * 4096u;
    p->ext_load_arena.buf = (uint8_t *)malloc(p->ext_load_arena.cap);
    p->ext_load_arena.used = 0;
    p->part_arena.cap = (size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u;
    p->part_arena.buf = (uint8_t *)malloc(p->part_arena.cap);
    p->part_arena.used = 0;
    if (p->recv_arena.buf == NULL || p->commit_sigs == NULL ||
        p->ext_sigs == NULL || p->ext_load_arena.buf == NULL ||
        p->part_arena.buf == NULL) {
        free(p->recv_arena.buf);
        free(p->commit_sigs);
        free(p->ext_sigs);
        free(p->ext_load_arena.buf);
        free(p->part_arena.buf);
        memset(&p->recv_arena, 0, sizeof(p->recv_arena));
        memset(&p->ext_load_arena, 0, sizeof(p->ext_load_arena));
        memset(&p->part_arena, 0, sizeof(p->part_arena));
        p->commit_sigs = NULL;
        p->ext_sigs = NULL;
        p->store = NULL;
        return CMT_FAULT;
    }
    p->lane_prepared = true;
    return CMT_OK;
}

const cmt_conr_host_t *nodus_witness_p2p_conr_host(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->conr_host : NULL;
}

const cmt_memr_host_t *nodus_witness_p2p_memr_host(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->memr_host : NULL;
}

cmt_pb_arena_t *nodus_witness_p2p_recv_arena(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->recv_arena : NULL;
}

void nodus_witness_p2p_lane_bind(nodus_witness_p2p_t *p, cmt_conr_t *conr,
                                 cmt_memr_t *memr)
{
    if (p != NULL) {
        p->conr = conr;
        p->memr = memr;
    }
}

int nodus_witness_p2p_lane_live(nodus_witness_p2p_t *p)
{
    int i;

    if (p == NULL || p->conr == NULL || p->memr == NULL) {
        return CMT_FAULT;
    }
    p->lane_live = true;
    /* R-P2P-47: every connected peer, index order, the reference's
     * addPeer order (switch.go:830-832 then :859-861). The block sync
     * reactor has no InitPeer; its AddPeer (our StatusResponse,
     * reactor.go:195-208) comes after the other two's. */
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer == NULL) {
            continue;
        }
        lane_conr_init(p, i);
        lane_memr_init(p, i);
        lane_conr_add(p, i);
        lane_memr_add(p, i);
        if (p->bsync != NULL) {
            /* CMT_OK or CMT_FAULT only (cmt_bsync_reactor_add_peer). */
            lane_fault_note(p, cmt_bsync_reactor_add_peer(
                                   p->bsync, cmt_p2p_peer_id(p->slots[i].peer)),
                            "blocksync AddPeer",
                            cmt_p2p_peer_id(p->slots[i].peer), i);
        }
        /* The StatusResponse this peer sent before the lane was live
         * (DEVIATION, bs_hold_status) — after AddPeer, as the reference's
         * running reactor would have received it. The caller has STARTED
         * the block sync reactor before this call (nodus_witness.c). */
        bs_replay_status(p, i);
    }
    process_pending_stops(p);   /* a replayed status may be invalid (:350-354) */
    /* A reactor fault during the admission above (lane_fault_note). */
    return p->lane_fault ? CMT_FAULT : CMT_OK;
}

int nodus_witness_p2p_lane_tick(nodus_witness_p2p_t *p, int64_t *next_deadline_ns)
{
    int64_t d_conr = INT64_MAX, d_memr = INT64_MAX, d_bsync = INT64_MAX;
    bool memr_has = false;

    if (next_deadline_ns != NULL) {
        *next_deadline_ns = INT64_MAX;
    }
    if (p == NULL || p->conr == NULL || p->memr == NULL) {
        return CMT_FAULT;
    }
    /* A reactor call made from a p2p callback since the last tick (or
     * any earlier one) returned CMT_FAULT — sticky, lane_fault_note. */
    if (p->lane_fault) {
        return CMT_FAULT;
    }
    if (cmt_conr_tick(p->conr, &d_conr) == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (cmt_memr_tick(p->memr, &d_memr, &memr_has) == CMT_FAULT) {
        return CMT_FAULT;
    }
    /* The block sync reactor's poolRoutine (cmt_bsync_reactor.h); after
     * the switch to consensus it returns at once with no deadline. */
    if (p->bsync != NULL &&
        cmt_bsync_reactor_tick(p->bsync, &d_bsync) == CMT_FAULT) {
        return CMT_FAULT;
    }
    process_pending_stops(p);
    if (next_deadline_ns != NULL) {
        int64_t d = (memr_has && d_memr < d_conr) ? d_memr : d_conr;

        *next_deadline_ns = d_bsync < d ? d_bsync : d;
    }
    return CMT_OK;
}

bool nodus_witness_p2p_lane_faulted(const nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_fault;
}

void nodus_witness_p2p_lane_unbind(nodus_witness_p2p_t *p)
{
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].conr_init && p->conr != NULL) {
            (void)cmt_conr_remove_peer(p->conr, i);
        }
        if (p->slots[i].memr_init && p->memr != NULL) {
            (void)cmt_memr_remove_peer(p->memr, i);
        }
        p->slots[i].conr_init = p->slots[i].conr_added = false;
        p->slots[i].memr_init = p->slots[i].memr_added = false;
        p->slots[i].pending_stop = 0;
        p->slots[i].bs_status_held = false;      /* bs_hold_status */
    }
    p->any_pending_stop = false;
    p->lane_live = false;
    p->conr = NULL;
    p->memr = NULL;
    p->bsync = NULL;      /* its owner frees it (nodus_witness_close) */
}

/* ── construction (node.go:283-421 / setup.go:349-491, the p2p half) ── */

static void fill_descs(nodus_witness_p2p_t *p)
{
    size_t n = 0, i;
    const cmt_conr_channel_desc_t *cd = cmt_conr_get_channels(&n);
    cmt_mempool_config_t mc;
    cmt_memr_t *probe;
    cmt_memr_channel_descriptor_t md;

    for (i = 0; i < n && i < CMT_CONR_NUM_CHANNELS; i++) {
        p->cons_desc[i].id = cd[i].id;
        p->cons_desc[i].priority = cd[i].priority;
        p->cons_desc[i].send_queue_capacity = cd[i].send_queue_capacity;
        p->cons_desc[i].recv_buffer_capacity = cd[i].recv_buffer_capacity;
        p->cons_desc[i].recv_message_capacity = cd[i].recv_message_capacity;
    }
    /* mempool/reactor.go:73-91 GetChannels over the node's mempool config
     * — cometbft's defaults, the one nodus_cmt_node_init builds the
     * mempool with (nodus_witness_cmt_node.c, cmt_mempool_config_default).
     * Only `config` is read (cmt_memr.c GetChannels). */
    memset(&md, 0, sizeof(md));
    md.id = CMT_MEM_CHANNEL;
    md.priority = 5;
    md.recv_message_capacity = (size_t)CMT_CONR_MAX_MSG_SIZE;
    probe = (cmt_memr_t *)calloc(1, sizeof(*probe));
    if (probe != NULL && cmt_mempool_config_default(&mc) == CMT_OK) {
        probe->config = &mc;
        (void)cmt_memr_get_channels(probe, &md);
    }
    free(probe);
    p->mem_desc[0].id = md.id;
    p->mem_desc[0].priority = md.priority;
    p->mem_desc[0].send_queue_capacity = 0;       /* FillDefaults (:762-774) */
    p->mem_desc[0].recv_buffer_capacity = 0;
    p->mem_desc[0].recv_message_capacity = (int)md.recv_message_capacity;
    /* blocksync/reactor.go:182-193 GetChannels — 0x40, priority 5, send
     * queue 1000, receive buffer 50 × 4096, MaxMsgSize (msgs.go:16-18,
     * the operator's "follow the reference" answer). */
    {
        cmt_bsync_channel_desc_t bd;

        cmt_bsync_reactor_get_channels(&bd);
        p->bs_desc[0].id = bd.id;
        p->bs_desc[0].priority = bd.priority;
        p->bs_desc[0].send_queue_capacity = bd.send_queue_capacity;
        p->bs_desc[0].recv_buffer_capacity = bd.recv_buffer_capacity;
        p->bs_desc[0].recv_message_capacity = (int)bd.recv_message_capacity;
    }
    /* R-P2P-5: the two nodus channels (constants and their rationale:
     * nodus_witness_p2p.h). ⚠ NOT GROUNDED — no reference channel. */
    p->gb_desc[0].id = NODUS_P2P_CH_GBUNDLE;
    p->gb_desc[0].priority = NODUS_P2P_GBUNDLE_PRIORITY;
    p->gb_desc[0].send_queue_capacity = NODUS_P2P_GBUNDLE_SEND_QUEUE;
    p->gb_desc[0].recv_buffer_capacity = 0;
    p->gb_desc[0].recv_message_capacity = (int)NODUS_T3_GBUNDLE_MSG_MAX;
    p->cc_desc[0].id = NODUS_P2P_CH_CC_APPR;
    p->cc_desc[0].priority = NODUS_P2P_CCAPPR_PRIORITY;
    p->cc_desc[0].send_queue_capacity = NODUS_P2P_CCAPPR_SEND_QUEUE;
    p->cc_desc[0].recv_buffer_capacity = 0;
    p->cc_desc[0].recv_message_capacity = (int)NODUS_T3_CC_APPR_MSG_MAX;
    /* 0x72 — the archive probe (nodus_witness_p2p.h; ⚠ NOT GROUNDED, the
     * byte awaits the operator's approval). Its largest message is an
     * answer of three samples (NODUS_STPROBE_MSG_MAX). */
    p->sp_desc[0].id = NODUS_P2P_CH_STPROBE;
    p->sp_desc[0].priority = NODUS_P2P_STPROBE_PRIORITY;
    p->sp_desc[0].send_queue_capacity = NODUS_P2P_STPROBE_SEND_QUEUE;
    p->sp_desc[0].recv_buffer_capacity = 0;
    p->sp_desc[0].recv_message_capacity = (int)NODUS_STPROBE_MSG_MAX;
    /* 0x73 — the segment fetch (nodus_witness_p2p.h; ⚠ NOT GROUNDED, the
     * byte awaits the operator's approval). Its largest message is an
     * answer carrying a terminal commit (NODUS_STFETCH_MSG_MAX). */
    p->sf_desc[0].id = NODUS_P2P_CH_STFETCH;
    p->sf_desc[0].priority = NODUS_P2P_STFETCH_PRIORITY;
    p->sf_desc[0].send_queue_capacity = NODUS_P2P_STFETCH_SEND_QUEUE;
    p->sf_desc[0].recv_buffer_capacity = 0;
    p->sf_desc[0].recv_message_capacity = (int)NODUS_STFETCH_MSG_MAX;
}

/* One reactor of this host, registered by the embedded host's _init in
 * array order (the former add_reactor's fields; the switch copies it). */
static void make_reactor(nodus_witness_p2p_t *p, cmt_p2p_reactor_t *r,
                         const char *name,
                         const cmt_p2p_ch_desc_t *(*chans)(void *, int *),
                         void (*init_peer)(void *, cmt_p2p_peer_t *),
                         void (*add_peer)(void *, cmt_p2p_peer_t *),
                         void (*remove_peer)(void *, cmt_p2p_peer_t *, int),
                         void (*receive)(void *, cmt_p2p_peer_t *, uint8_t,
                                         const uint8_t *, size_t))
{
    memset(r, 0, sizeof(*r));
    r->name = name;
    r->ctx = p;
    r->get_channels = chans;
    r->init_peer = init_peer;
    r->add_peer = add_peer;
    r->remove_peer = remove_peer;
    r->receive = receive;
}

static void no_peer_check(nodus_witness_p2p_t *p, bool at_start);   /* M4 */

/* The seven reactors this host registers (CONSENSUS first — its InitPeer
 * assigns the index; header "the REACTORS"). */
#define NODUS_W_P2P_N_REACTORS 7

nodus_witness_p2p_t *nodus_witness_p2p_new(struct nodus_witness *w,
                                           const nodus_witness_p2p_params_t *prm)
{
    nodus_witness_p2p_t *p;
    nodus_p2p_host_params_t hp;
    cmt_p2p_reactor_t rs[NODUS_W_P2P_N_REACTORS];
    uint8_t chans[CMT_P2P_MAX_NUM_CHANNELS];
    size_t n_chans = 0;
    int i;

    if (prm == NULL) {
        return NULL;
    }
    p = (nodus_witness_p2p_t *)calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->w = w;

    /* node.go:927-974 makeNodeInfo. Channels in the reference's list order
     * (blocksync, consensus, mempool, :948-954; PEX last — the host appends
     * it) with the nodus channels before PEX. */
    fill_descs(p);
    chans[n_chans++] = p->bs_desc[0].id;
    for (i = 0; i < CMT_CONR_NUM_CHANNELS; i++) {
        chans[n_chans++] = p->cons_desc[i].id;
    }
    chans[n_chans++] = p->mem_desc[0].id;
    chans[n_chans++] = NODUS_P2P_CH_GBUNDLE;
    chans[n_chans++] = NODUS_P2P_CH_CC_APPR;
    chans[n_chans++] = NODUS_P2P_CH_STPROBE;
    chans[n_chans++] = NODUS_P2P_CH_STFETCH;

    make_reactor(p, &rs[0], "CONSENSUS", cons_channels, cons_init_peer,
                 cons_add_peer, cons_remove_peer, cons_receive);
    make_reactor(p, &rs[1], "MEMPOOL", mem_channels, mem_init_peer, mem_add_peer,
                 mem_remove_peer, mem_receive);
    make_reactor(p, &rs[2], "BLOCKSYNC", bs_channels, noop_peer, bs_add_peer,
                 bs_remove_peer, bs_receive);
    make_reactor(p, &rs[3], "GBUNDLE", gb_channels, noop_peer, noop_peer,
                 noop_remove, gb_receive);
    make_reactor(p, &rs[4], "CCAPPR", cc_channels, noop_peer, noop_peer,
                 noop_remove, cc_receive);
    make_reactor(p, &rs[5], "STPROBE", sp_channels, noop_peer, noop_peer,
                 noop_remove, sp_receive);
    make_reactor(p, &rs[6], "STFETCH", sf_channels, noop_peer, noop_peer,
                 noop_remove, sf_receive);

    memset(&hp, 0, sizeof(hp));
    hp.identity = prm->identity;
    hp.chain_id = prm->chain_id;
    hp.cfg = prm->cfg;
    hp.listen_ip = prm->listen_ip;
    hp.listen_port = prm->listen_port;
    hp.external_ip = prm->external_ip;
    hp.data_path = prm->data_path;
    hp.seq_dir = prm->seq_dir;
    hp.open_listener = prm->open_listener;
    hp.n_workers = prm->n_workers;
    hp.channels = chans;
    hp.n_channels = n_chans;
    hp.reactors = rs;
    hp.n_reactors = NODUS_W_P2P_N_REACTORS;
    hp.policy.ctx = p;
    hp.policy.is_bonded = h_is_bonded;
    hp.policy.bonded_count = h_bonded_count;
    hp.policy.bonded_pubkey = h_bonded_pubkey;
    hp.policy.may_receive = h_may_receive;
    hp.policy.recv_near_full = h_recv_near_full;
    hp.policy.queue_mark = h_queue_mark;
    /* Listener, own address, NodeInfo, transport, switch, the reactors
     * above, address book + PEX, the configured peer lists. */
    if (nodus_p2p_host_init(&p->host, &hp) != 0) {
        goto fail;
    }

    /* The bonded set before the first connection is admitted. */
    nodus_witness_p2p_refresh_bonded(p);

    /* The worker threads, OnStart (switch, own record, persistent peers)
     * and the "p2p on …" line (nodus_p2p_host_start). */
    if (nodus_p2p_host_start(&p->host) != 0) {
        goto fail;
    }
    no_peer_check(p, true);
    return p;

fail:
    nodus_witness_p2p_free(p);
    return NULL;
}

void nodus_witness_p2p_free(nodus_witness_p2p_t *p)
{
    if (p == NULL) {
        return;
    }
    nodus_witness_p2p_lane_unbind(p);
    /* A pending approval collection waits on THIS host's peers: it ends
     * here, with no reply (the CLI's own request times out). */
    if (p->w != NULL && p->w->p2p == p) {
        nodus_witness_cc_collect_abort(p->w);
    }
    /* switch stop (book saved), worker stop, PEX, switch, transport,
     * book, sockets, mutex, NodeInfo — and our record wiped. */
    nodus_p2p_host_free(&p->host);
    free(p->bonded);
    free(p->gb_bundle);
    free(p->recv_arena.buf);
    free(p->commit_sigs);
    free(p->ext_sigs);
    free(p->ext_load_arena.buf);
    free(p->part_arena.buf);
    free(p);
}

/* How often the M4 ERROR repeats while it holds. Operator choice
 * (fix proposals 2026-09-27 "REVISED" M4: "every 60 s"). */
#define NODUS_P2P_NO_PEER_LOG_MS 60000

/*
 * M4 — a node that HOLDS A CHAIN but was given no persistent peers (no
 * network file, or one without peers) has nobody to dial: it learns
 * peers only if one dials in, and a validator cut off like that stalls
 * silently. ERROR at start when none is configured, and every
 * NODUS_P2P_NO_PEER_LOG_MS while NO peer is connected — configured or not
 * (a listed but unreachable set is the same stall); the node is never
 * refused (operator: log,
 * do not refuse). A joiner (no chain yet) has its own diagnosis
 * (nodus_witness_v2_join.c join_diag). The reference dials whatever
 * persistent_peers holds (node.go:562-566) and says nothing when it is
 * empty; no counterpart for this warning — an operator aid, not
 * consensus (monotonic clock, D3).
 */
static void no_peer_check(nodus_witness_p2p_t *p, bool at_start)
{
    int64_t now_ms;

    if (p->w == NULL || p->w->db == NULL) {
        return;
    }
    now_ms = nodus_p2p_mono_ns(NULL) / 1000000;
    if (at_start && p->host.cfg.n_persistent_peers > 0) {
        /* peers are configured: nothing to say yet, but arm the 60 s
         * clock so an unreachable set is reported one period in
         * (ORCHESTRATOR repair — verifier: the periodic ERROR must cover
         * "0 CONNECTED", not only "0 configured") */
        p->no_peer_logged_ms = now_ms != 0 ? now_ms : 1;
        return;
    }
    if (!at_start && nodus_witness_p2p_peer_count(p) > 0) {
        return;
    }
    if (!at_start && p->no_peer_logged_ms != 0 &&
        now_ms - p->no_peer_logged_ms < NODUS_P2P_NO_PEER_LOG_MS) {
        return;
    }
    p->no_peer_logged_ms = now_ms != 0 ? now_ms : 1;
    QGP_LOG_ERROR(LOG_TAG, "this node holds a chain but has %d persistent "
                  "peer(s) configured and %d connected — it cannot reach "
                  "the validators; check the network file and the peers' "
                  "reachability", p->host.cfg.n_persistent_peers,
                  nodus_witness_p2p_peer_count(p));
}

void nodus_witness_p2p_poll(nodus_witness_p2p_t *p, int timeout_ms)
{
    if (p == NULL) {
        return;
    }
    /* worker results, the socket wait, worker results, I/O, switch tick */
    nodus_p2p_host_poll_io(&p->host, timeout_ms);
    lane_gc(p);
    nodus_p2p_host_pex_tick(&p->host);
    process_pending_stops(p);
    bonded_maybe_refresh(p);
    nodus_p2p_host_own_record_check(&p->host);
    no_peer_check(p, false);
    /* The node-side approval collection's deadline (tooling, not
     * consensus — the monotonic clock, nodus_witness.h
     * NODUS_CC_COLLECT_DEADLINE_MS). */
    if (p->w != NULL && p->w->p2p == p) {
        nodus_witness_cc_collect_tick(p->w, nodus_p2p_mono_ns(NULL) / 1000000);
    }
    nodus_p2p_host_flush(&p->host);
}

/* The accessors below answer from the embedded host (nodus_p2p_host.h). */

uint16_t nodus_witness_p2p_listen_port(const nodus_witness_p2p_t *p)
{
    return p != NULL ? nodus_p2p_host_listen_port(&p->host) : 0;
}

const char *nodus_witness_p2p_id(const nodus_witness_p2p_t *p)
{
    return p != NULL ? nodus_p2p_host_id(&p->host) : "";
}

cmt_p2p_switch_t *nodus_witness_p2p_switch(nodus_witness_p2p_t *p)
{
    return p != NULL ? nodus_p2p_host_switch(&p->host) : NULL;
}

int nodus_witness_p2p_peer_count(const nodus_witness_p2p_t *p)
{
    return p != NULL ? nodus_p2p_host_peer_count(&p->host) : 0;
}

bool nodus_witness_p2p_peer_id_at(const nodus_witness_p2p_t *p, int i,
                                  char out[CMT_P2P_ID_CAP])
{
    return p != NULL && nodus_p2p_host_peer_id_at(&p->host, i, out);
}

bool nodus_witness_p2p_has_peer(const nodus_witness_p2p_t *p, const char *peer_id)
{
    return p != NULL && nodus_p2p_host_has_peer(&p->host, peer_id);
}

int nodus_witness_p2p_lane_index(const nodus_witness_p2p_t *p, const char *peer_id)
{
    const cmt_p2p_peer_t *peer;

    if (p == NULL || peer_id == NULL ||
        (peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->host.sw), peer_id)) == NULL) {
        return -1;
    }
    return lane_find(p, peer);
}

bool nodus_witness_p2p_send(nodus_witness_p2p_t *p, const char *peer_id,
                            uint8_t ch, const uint8_t *msg, size_t len)
{
    return p != NULL && nodus_p2p_host_send(&p->host, peer_id, ch, msg, len);
}
