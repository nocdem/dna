/**
 * @file nodus_witness_role_prune.h
 * @brief Role-based block retention: the retain height this node's
 *        Commit hands the block executor, decided from this node's
 *        setting, its roles on the chain and — for a storage member —
 *        which of its assigned segment files are complete.
 *
 * Decisions: docs/plans/decisions/2026-10-14-role-based-pruning.md (THIS
 * rule: pruning follows the role; storage pruning is GUARDED by the
 * segment files; an explicit setting wins), 2026-10-03-block-pruning-7-
 * paydays.md (the numbers: 7 paydays = 120 960 blocks, the evidence-
 * window floor, the archive nodes EU-6 / US-1).
 *
 * ── THE SETTING (nodus.json "retain_blocks"; nodus_witness_config_t) ───
 *   absent        AUTO     — the role decides (below)
 *   0             ARCHIVE  — never prune, whatever the roles
 *   N > 0         EXPLICIT — keep the last N blocks; the storage guard
 *                            still applies (the start-time floor of
 *                            nodus_cmt_node_check_retain_blocks applies to
 *                            N exactly as before)
 *
 * ── THE DECISION (nodus_role_prune_retain_height — pure) ──────────────
 *   ARCHIVE or a fault (a role or guard read failed) → 0 (nothing pruned)
 *   base = N                    EXPLICIT
 *        = auto_blocks          AUTO and this node is a bonded validator
 *                               (status ACTIVE or ELIGIBLE) or a storage
 *                               member (registry status ACTIVE or EXITING)
 *        = 0                    AUTO, no role: keeps everything
 *   R = nodus_cmt_app_retain_height(height, base)   (0 when height <= base)
 *   storage member: R = min(R, keep_from_segment, keep_from_unpublished)
 *     keep_from_segment     = (k−1)·P + 1 for the LOWEST segment k this
 *                             node must hold (nodus_witness_sthold_must_
 *                             hold) whose file is not complete (no valid
 *                             seg-<k>.ok, nodus_seg_held); none when every
 *                             one is complete
 *     keep_from_unpublished = max_published_k · P + 1 — the first height
 *                             of the period not yet published as a
 *                             segment: those blocks exist only in the
 *                             block store
 *   R <= 1 → 0 (R = 1 keeps every block anyway).
 *   `auto_blocks` is NODUS_PRUNE_AUTO_RETAIN when that exceeds the chain's
 *   evidence window, else 0 (AUTO then keeps everything — decided and
 *   logged once by nodus_cmt_node_init; a fail-closed choice for data,
 *   reached only by a short-epoch build).
 *
 * ── THE INPUTS (nodus_role_prune_commit — after each Commit's COMMIT) ──
 * Read from COMMITTED state only, on the witness thread, every Commit:
 * this node's key = w->host->identity->pk; validator = a `validators` row
 * with that pubkey (the column, not pubkey_hash: under HF-6 pubkey_hash is
 * the validator_id) and status ACTIVE / ELIGIBLE; storage member =
 * `v2_storage_nodes` row node_fp = SHA3-512(pk) with status ACTIVE /
 * EXITING; the highest published k (`v2_storage_segments`). For a storage
 * member: the epoch H = ⌊height/E⌋·E, the must-hold list at H and the
 * completeness of each listed file.
 *   CACHE: the must-hold list is cached keyed by (H, max published k) —
 *   every row it is derived from (the frozen storage sets, the published
 *   segment list) is written only at an epoch boundary, so a miss
 *   computes what a hit returns. Inside the cached list, the files before
 *   `first_open` were found complete and are not re-read; the first not
 *   complete one is re-checked at every Commit, and the cursor moves past
 *   it once its marker is valid. (A file found complete that later goes
 *   bad — a disk fault, an operator deleting it — is seen at the next H;
 *   its blocks may already be pruned: the holder re-fetches it.)
 *   FAIL CLOSED: any read error (no identity, an SQL error, must-hold
 *   faulted, a marker unreadable, no segment directory) answers 0 for
 *   this Commit, logged at most once per epoch. A storage member with no
 *   frozen storage_set(H) yet, or at a height below the first epoch, keeps
 *   everything (no assignment is known: K9a — a member at the first
 *   storage boundary must still hold the whole archive).
 *
 * ── DETERMINISM ───────────────────────────────────────────────────────
 * Node-local: the retain height reaches only this node's block / state
 * store pruning (nodus_cmt_blockexec_prune_blocks). No consensus byte,
 * app_hash input, vote or replication path reads it; no clock is read.
 * Two nodes with different settings or files prune differently and agree
 * on every block.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_ROLE_PRUNE_H
#define NODUS_WITNESS_ROLE_PRUNE_H

#include "witness/nodus_witness.h"
#include "dnac/ledger_roots_v2.h"     /* DNA_V2_SEGMENT_BLOCKS */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** AUTO's retention for a validator or storage member: 7 paydays
 *  (decision 2026-10-03-block-pruning-7-paydays.md item 1; 2026-10-14-
 *  role-based-pruning.md items 1-2) = 7 segments of DNA_V2_SEGMENT_BLOCKS
 *  (one payday period each) = 120 960 blocks at the shipped epoch length. */
#define NODUS_PRUNE_AUTO_RETAIN  ((int64_t)(7u * DNA_V2_SEGMENT_BLOCKS))

_Static_assert(DNAC_EPOCH_LENGTH != 720 || NODUS_PRUNE_AUTO_RETAIN == 120960,
               "7 paydays at the shipped epoch length is 120960 blocks");

/** The setting's three meanings (header "THE SETTING"). */
typedef enum {
    NODUS_PRUNE_CFG_AUTO     = 0,
    NODUS_PRUNE_CFG_ARCHIVE  = 1,
    NODUS_PRUNE_CFG_EXPLICIT = 2
} nodus_prune_cfg_t;

/** The decision's inputs (header "THE DECISION"). */
typedef struct {
    int64_t           height;        /* the height being committed       */
    nodus_prune_cfg_t cfg;
    int64_t           cfg_blocks;    /* EXPLICIT: N > 0                  */
    int64_t           auto_blocks;   /* AUTO's base for a role; 0 = keep  */
    bool              fault;         /* a role / guard read failed       */
    bool              is_validator;
    bool              is_storage;
    /* storage member only: */
    int64_t           keep_from_segment;     /* 0 = none incomplete       */
    int64_t           keep_from_unpublished; /* >= 1                       */
} nodus_prune_in_t;

/** The base the setting and the roles give (0 = keep everything): ARCHIVE
 *  0, EXPLICIT cfg_blocks, AUTO auto_blocks for a validator or storage
 *  member and 0 otherwise. Pure. */
int64_t nodus_role_prune_base(const nodus_prune_in_t *in);

/** The retain height (header "THE DECISION"). Pure: no clock, no state,
 *  no I/O. NULL → 0. */
int64_t nodus_role_prune_retain_height(const nodus_prune_in_t *in);

/** The runtime: the must-hold cache and the log memory. Lives inside the
 *  application context (nodus_cmt_app_ledger_t.prune_rt); zero = empty
 *  cache, AUTO disabled until nodus_cmt_node_init sets auto_blocks. */
typedef struct {
    int64_t   auto_blocks;
    /* must-hold cache, keyed by (cache_H, cache_maxk) */
    bool      have_cache;
    uint64_t  cache_H;
    uint64_t  cache_maxk;
    uint64_t *ks;                      /* k ascending, heap              */
    size_t    n_ks;
    size_t    first_open;              /* ks[0..first_open) complete     */
    bool      cache_no_set;            /* no storage_set(H): keep all    */
    /* the last mode logged */
    bool      logged;
    int       last_cfg;
    bool      last_val, last_sto, last_fault;
    int64_t   last_base;
    uint64_t  last_open_k;             /* 0 = none                       */
    int64_t   last_unpub;
    /* fault log: at most once per epoch */
    bool      fault_logged;
    uint64_t  fault_epoch;
} nodus_role_prune_rt_t;

/** The retain height for the Commit of `height` on this node: reads the
 *  setting (w->config), the roles and the guard (header "THE INPUTS"),
 *  logs a mode change (tag W_PRUNE), and returns
 *  nodus_role_prune_retain_height. Never fails: a fault answers 0. */
int64_t nodus_role_prune_commit(nodus_witness_t *w, nodus_role_prune_rt_t *rt,
                                int64_t height);

/** Free the cache (the application context's release). NULL-safe. */
void nodus_role_prune_rt_free(nodus_role_prune_rt_t *rt);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_ROLE_PRUNE_H */
