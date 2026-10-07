/**
 * @file nodus/src/witness/nodus_witness_cmt_app.c
 * @brief The application table of nodus_witness_cmt_app.h.
 *
 * Every function carries the cometbft @v0.38.26 site it implements and,
 * where it reads the ledger, the ledger function it reuses. Nothing here
 * re-implements a ledger rule: the admission check, the contextual
 * ruleset table, the batch preflight and the capacity seam are the
 * engine's own entry points, called as the live lane calls them.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_cmt_app.h"

#include <stdarg.h>                    /* app_refuse_log                 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>                  /* PRId64 in the apply log line   */

/* `sqlite3.h` arrives with witness/nodus_witness.h:27 (the tree's own
 * convention — nodus_witness_cmt_store.c takes it the same way). */

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_tmhash.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_ids.h"

#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_domreg.h"    /* the committed per-domain
                                              * quota (PrepareProposal)  */
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_apply.h"  /* Nodus EVM: the EVM block gas
                                              * limit (CheckTx max-gas)  */
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"    /* the STORED chain id
                                              * (nodus_witness_v2_gen.h:786) */
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT
                                              * (nodus_witness_emission.h:42) */
#include "witness/nodus_witness_v2_epoch.h"  /* round 2 §A:
                                              * nodus_witness_v2_epoch_
                                              * authority_for_epoch */

#define LOG_TAG "CMT-APP"

/* ═══════════════════════════════════════════════════════════════════════
 * Construction
 * ═══════════════════════════════════════════════════════════════════════ */

/* ORCHESTRATOR delta 1, item B: the smallest canonical item either wire
 * codec accepts. An envelope's own framing minimum (env_wire.h:198-199,
 * 43-byte fixed head + one 30-byte leg header, call_len/auth_len both
 * legally 0 at this layer's framing rules — env_wire.h's own "HONEST
 * LABEL" says this layer parses neither) is smaller by two orders of
 * magnitude than a claim's fixed minimum (manifest_wire.h:452-454,
 * 7 404 bytes: a 2 592-byte pubkey plus a 4 627-byte signature alone
 * dominate it), so an all-envelope block is always the worst case for
 * TOTAL item count. */
#define CMT_APP_MIN_ENV_BYTES ((size_t)(DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN))

/* ORCHESTRATOR delta 1, item B: the WORST-CASE committee size for
 * sizing an array once, at init, for the node's whole lifetime — the
 * SMALLEST possible validator count, because cmt_max_data_bytes's
 * commit-size term SHRINKS the byte budget as the committee GROWS
 * (shared/dnac/cmt_block.c:1700-1745), so the smallest committee gives
 * the LARGEST possible budget and therefore the safe upper bound on
 * item count regardless of how large the committee grows later (up to
 * DNAC_MAX_ACTIVE_VALIDATORS, dnac.h:201). */
#define CMT_APP_MIN_VALS_FOR_BOUND ((int64_t)1)

/* ═══════════════════════════════════════════════════════════════════════
 * CHECKTX-P1 — node-local mempool admission state (the header's context
 * fields say what each set is FOR; this section is only their mechanics).
 * The pending conflict set is an OPEN-ADDRESSING HASH SET (linear
 * probing, load ≤ 1/2, power-of-two table, O(1) average per key — round 2
 * replaced the sorted array whose memmove insert made a recheck refill
 * O(K²)). The slot hash is the first 8 bytes of SHA3-512 of the key
 * bytes, so no submitter can steer keys into one probe chain; it is
 * deterministic, and nothing iterates the table to decide anything. The
 * auth cache stays a SORTED POINTER ARRAY with binary search (it is
 * inserted into only on a NEW admission or a recheck miss).
 * ═══════════════════════════════════════════════════════════════════════ */

/* Conflict-key tags: the first byte of every key, so the three key
 * spaces can never collide with one another. */
#define CMT_APP_PKEY_TAG_INTENT     ((uint8_t)1)   /* envelope intent_id   */
#define CMT_APP_PKEY_TAG_NULLIFIER  ((uint8_t)2)   /* claim nullifier      */
#define CMT_APP_PKEY_TAG_ROW        ((uint8_t)3)   /* a row-identity row   */

/* tag ‖ domain u32 BE ‖ op u32 BE ‖ key_len u16 BE ‖ key — the longest
 * key form (a 64-byte id key is 65). */
#define CMT_APP_PKEY_MAX_LEN (1u + 4u + 4u + 2u + DNA_EFFECT_MAX_KEY_LEN)

/** PrepareProposal refill passes (red-team F2/F3): after a seam refusal
 *  names one offender, at most this many passes REFILL the freed room
 *  from the remaining fee-ordered candidates; every pass after it drops
 *  the offender AND halves what is left. See the drop loop's own bound
 *  statement. */
#define NODUS_CMT_APP_PREP_REFILL_MAX ((size_t)8)

struct nodus_cmt_app_pkey {
    uint64_t h;                /* the slot hash (see app_key_hash)        */
    uint8_t  owner[64];        /* the entry identity that claimed the key */
    uint16_t len;
    uint8_t  key[];            /* `len` bytes                             */
};

struct nodus_cmt_app_acache {
    uint8_t                  wire_id[64];
    uint64_t                 gen;       /* last commit generation used    */
    uint16_t                 leg_count;
    uint8_t                 *present;   /* [leg_count] 1 = kind-1/3
                                         * verdict cached               */
    uint8_t                (*digest)[64];            /* [leg_count]       */
    nodus_rt_auth_verdict_t *verdict;                /* [leg_count]       */
};

/** One candidate conflict key, built before the set is consulted. */
typedef struct {
    uint16_t len;
    uint8_t  b[CMT_APP_PKEY_MAX_LEN];
} app_key_t;

/** The slot hash: the first 8 bytes (big-endian) of SHA3-512(key).
 *  @return 0 / -1 hash backend (node-local). */
static int app_key_hash(const uint8_t *key, uint16_t len, uint64_t *h)
{
    uint8_t d[64];
    int     i;

    if (qgp_sha3_512(key, len, d) != 0) {
        return -1;
    }
    *h = 0;
    for (i = 0; i < 8; i++) {
        *h = (*h << 8) | d[i];
    }
    return 0;
}

/** The slot holding `key`, or the empty slot where it would go.
 *  `ctx->pend_cap` must be a nonzero power of two with a free slot. */
static size_t pend_slot(const nodus_cmt_app_ledger_t *ctx, uint64_t h,
                        const uint8_t *key, uint16_t len, int *found)
{
    size_t mask = ctx->pend_cap - 1;
    size_t at   = (size_t)h & mask;

    *found = 0;
    while (ctx->pend[at]) {
        const struct nodus_cmt_app_pkey *k = ctx->pend[at];

        if (k->h == h && k->len == len && memcmp(k->key, key, len) == 0) {
            *found = 1;
            return at;
        }
        at = (at + 1) & mask;
    }
    return at;
}

/** Grow the table to `want` slots (a power of two) and rehash.
 *  @return 0 / -2 allocation failure (the table is untouched). */
static int pend_grow(nodus_cmt_app_ledger_t *ctx, size_t want)
{
    struct nodus_cmt_app_pkey **old = ctx->pend;
    size_t                      old_cap = ctx->pend_cap, i;
    struct nodus_cmt_app_pkey **t = calloc(want, sizeof(*t));

    if (!t) {
        return -2;
    }
    ctx->pend     = t;
    ctx->pend_cap = want;
    for (i = 0; i < old_cap; i++) {
        if (old[i]) {
            int    found;
            size_t at = pend_slot(ctx, old[i]->h, old[i]->key, old[i]->len,
                                  &found);

            t[at] = old[i];
        }
    }
    free(old);
    return 0;
}

/**
 * Admit one entry's `n` keys, ALL OR NOTHING — every allocation happens
 * before the first insert, so a failure leaves the set exactly as it was.
 * @return 0 admitted (every key now owned by `owner`); 1 a key is owned
 *         by ANOTHER entry (conflict — nothing inserted); 2 the set is at
 *         its `pend_max` bound (nothing inserted); -2 allocation or hash
 *         backend failure (nothing inserted).
 */
static int pend_admit(nodus_cmt_app_ledger_t *ctx, const uint8_t owner[64],
                      const app_key_t *keys, size_t n)
{
    struct nodus_cmt_app_pkey **recs = NULL;
    uint64_t *hs = NULL;
    size_t    i, fresh = 0, used = 0;
    int       rc = -2;

    if (n == 0) {
        return 0;
    }
    hs = (uint64_t *)calloc(n, sizeof(*hs));
    if (!hs) {
        return -2;
    }
    for (i = 0; i < n; i++) {
        if (app_key_hash(keys[i].b, keys[i].len, &hs[i]) != 0) {
            goto out;
        }
    }
    /* 1. the verdict: any key another entry owns is a conflict */
    for (i = 0; i < n && ctx->pend_cap; i++) {
        int    found;
        size_t at = pend_slot(ctx, hs[i], keys[i].b, keys[i].len, &found);

        if (found && memcmp(ctx->pend[at]->owner, owner, 64) != 0) {
            rc = 1;
            goto out;
        }
    }
    for (i = 0; i < n; i++) {
        int found = 0;

        if (ctx->pend_cap) {
            (void)pend_slot(ctx, hs[i], keys[i].b, keys[i].len, &found);
        }
        if (!found) {
            fresh++;
        }
    }
    if (fresh == 0) {
        rc = 0;                       /* this owner already holds all   */
        goto out;
    }
    if (fresh > ctx->pend_max - ctx->pend_n) {
        rc = 2;
        goto out;
    }
    /* 2. every allocation BEFORE the first insert */
    if ((ctx->pend_n + fresh) * 2 > ctx->pend_cap) {
        size_t want = ctx->pend_cap ? ctx->pend_cap : 1024;

        while ((ctx->pend_n + fresh) * 2 > want) {
            want *= 2;
        }
        if (pend_grow(ctx, want) != 0) {
            goto out;
        }
    }
    recs = calloc(fresh, sizeof(*recs));
    if (!recs) {
        goto out;
    }
    for (i = 0; i < fresh; i++) {
        recs[i] = (struct nodus_cmt_app_pkey *)
            calloc(1, sizeof(struct nodus_cmt_app_pkey) + CMT_APP_PKEY_MAX_LEN);
        if (!recs[i]) {
            goto out;
        }
    }
    /* 3. the inserts — nothing below can fail */
    for (i = 0; i < n; i++) {
        int    found;
        size_t at = pend_slot(ctx, hs[i], keys[i].b, keys[i].len, &found);
        struct nodus_cmt_app_pkey *k;

        if (found) {
            continue;                 /* this owner already holds it    */
        }
        k = recs[used];
        recs[used++] = NULL;
        k->h   = hs[i];
        memcpy(k->owner, owner, 64);
        k->len = keys[i].len;
        memcpy(k->key, keys[i].b, keys[i].len);
        ctx->pend[at] = k;
        ctx->pend_n++;
    }
    rc = 0;
out:
    if (recs) {
        for (i = 0; i < fresh; i++) {
            free(recs[i]);            /* NULL for every record inserted */
        }
    }
    free(recs);
    free(hs);
    return rc;
}

/** Commit: every pending key goes (the recheck repopulates). */
static void pend_clear(nodus_cmt_app_ledger_t *ctx)
{
    size_t i;

    for (i = 0; i < ctx->pend_cap; i++) {
        free(ctx->pend[i]);
        ctx->pend[i] = NULL;
    }
    ctx->pend_n = 0;
}

static void acache_entry_free(struct nodus_cmt_app_acache *e)
{
    if (e) {
        free(e->present);
        free(e->digest);
        free(e->verdict);
        free(e);
    }
}

static size_t acache_find(const nodus_cmt_app_ledger_t *ctx,
                          const uint8_t wire_id[64], int *found)
{
    size_t lo = 0, hi = ctx->acache_n;

    *found = 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (memcmp(ctx->acache[mid]->wire_id, wire_id, 64) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo < ctx->acache_n &&
        memcmp(ctx->acache[lo]->wire_id, wire_id, 64) == 0) {
        *found = 1;
    }
    return lo;
}

/**
 * Cache the auth_kind-1 and auth_kind-3 verdicts of an envelope the dry
 * run just ADMITTED (kind 3 — general multisig, design F1.3: its verdict,
 * descriptor facts included, is a pure function of the auth bytes and
 * the leg digest exactly like kind 1's, and the cache key is the
 * wire_id, which commits the auth bytes). Nothing is cached when no leg
 * is kind 1 or 3, when the cache is at its cap, or when an allocation
 * fails — a miss only means the next recheck verifies in full, so none
 * of these is an error. Kind 2 is never cached (its verdict depends on
 * the governing committee snapshot).
 */
static int acache_kind_ok(uint8_t kind)
{
    return kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
           kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
}

static void acache_store(nodus_cmt_app_ledger_t *ctx,
                         const nodus_v2_env_dry_run_t *dry)
{
    struct nodus_cmt_app_acache *e;
    size_t   at;
    int      found;
    uint16_t l, n_cacheable = 0;

    for (l = 0; l < dry->leg_count; l++) {
        if (acache_kind_ok(dry->auth_kind[l])) {
            n_cacheable++;
        }
    }
    if (n_cacheable == 0 || ctx->acache_n >= ctx->acache_max) {
        return;
    }
    at = acache_find(ctx, dry->wire_id, &found);
    if (found) {
        ctx->acache[at]->gen = ctx->acache_gen;
        return;
    }
    if (ctx->acache_n == ctx->acache_cap) {
        size_t want = ctx->acache_cap ? ctx->acache_cap * 2 : 256;
        struct nodus_cmt_app_acache **grown;

        if (want > ctx->acache_max) {
            want = ctx->acache_max;
        }
        grown = realloc(ctx->acache, want * sizeof(*grown));
        if (!grown) {
            return;
        }
        ctx->acache     = grown;
        ctx->acache_cap = want;
    }
    e = (struct nodus_cmt_app_acache *)calloc(1, sizeof(*e));
    if (!e) {
        return;
    }
    e->present = (uint8_t *)calloc(dry->leg_count, sizeof(*e->present));
    e->digest  = calloc(dry->leg_count, sizeof(*e->digest));
    e->verdict = (nodus_rt_auth_verdict_t *)
        calloc(dry->leg_count, sizeof(*e->verdict));
    if (!e->present || !e->digest || !e->verdict) {
        acache_entry_free(e);
        return;
    }
    memcpy(e->wire_id, dry->wire_id, 64);
    e->gen       = ctx->acache_gen;
    e->leg_count = dry->leg_count;
    for (l = 0; l < dry->leg_count; l++) {
        if (!acache_kind_ok(dry->auth_kind[l])) {
            continue;              /* kind 2: never cached               */
        }
        e->present[l] = 1;
        memcpy(e->digest[l], dry->leg_digest[l], 64);
        e->verdict[l] = dry->verdict[l];
    }
    memmove(&ctx->acache[at + 1], &ctx->acache[at],
            (ctx->acache_n - at) * sizeof(*ctx->acache));
    ctx->acache[at] = e;
    ctx->acache_n++;
}

/** Commit: drop every entry not used since the previous commit, then
 *  open the next generation. Order-preserving compaction. */
static void acache_sweep(nodus_cmt_app_ledger_t *ctx)
{
    size_t i, kept = 0;

    for (i = 0; i < ctx->acache_n; i++) {
        if (ctx->acache[i]->gen < ctx->acache_gen) {
            acache_entry_free(ctx->acache[i]);
        } else {
            ctx->acache[kept++] = ctx->acache[i];
        }
    }
    ctx->acache_n = kept;
    ctx->acache_gen++;
}

/* ORCHESTRATOR delta 2, item A — only THREE arrays remain context-owned
 * across calls (the ABCI response-ownership rule; see the header's
 * struct comment) since round 2 added `val_updates` (§A); every other
 * scratch array delta 1 kept here is now local to the row that uses it.
 * NULL-safe throughout. */
void nodus_cmt_app_ledger_release(nodus_cmt_app_ledger_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->prep_txs);
    free(ctx->fb_pb);
    free(ctx->val_updates);
    ctx->prep_txs      = NULL;
    ctx->prep_txs_len  = 0;
    ctx->prep_txs_cap  = 0;
    ctx->fb_pb         = NULL;
    ctx->fb_pb_cap     = 0;
    ctx->val_updates     = NULL;
    ctx->val_updates_cap = 0;
    /* CHECKTX-P1 — the node-local mempool admission state. */
    pend_clear(ctx);
    free(ctx->pend);
    ctx->pend     = NULL;
    ctx->pend_cap = 0;
    {
        size_t i;

        for (i = 0; i < ctx->acache_n; i++) {
            acache_entry_free(ctx->acache[i]);
        }
    }
    free(ctx->acache);
    ctx->acache     = NULL;
    ctx->acache_n   = 0;
    ctx->acache_cap = 0;
}

int nodus_cmt_app_ledger_init(nodus_cmt_app_ledger_t *ctx, nodus_witness_t *w,
                              const cmt_genesis_doc_t *gendoc)
{
    if (!ctx || !w || !w->db || !gendoc) {
        return CMT_FAULT;
    }
    /* Every ledger seam this module calls refuses a non-successor chain
     * (nodus_witness_v2_produce.c:358-360 and the divert at
     * nodus_witness_verify.c:808-813), so a table bound to a legacy chain
     * would have rows that all fault. Refuse at bind time instead. */
    if (!w->v2_successor) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "the Comet application binds a Ledger V2 successor "
                      "chain only");
        return CMT_FAULT;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->w = w;
    ctx->gendoc = gendoc;

    /* ── ORCHESTRATOR delta 1, item B — THE THREE BOUNDS, DERIVED ────── */

    /* PREP_BOUND: the mempool's own configured `size`. The real mempool
     * config is built later, in nodus_cmt_node_init's step 7a — this
     * calls the SAME pure default constructor early, only to read
     * `.size`; both calls yield the identical value (D-4 rev 3), so
     * there is no second source of truth, only a second read of one. */
    {
        cmt_mempool_config_t mem_cfg_for_bound;
        if (cmt_mempool_config_default(&mem_cfg_for_bound) != CMT_OK ||
            mem_cfg_for_bound.size <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the mempool default config could not be read for "
                          "sizing the prepare-side arrays");
            return CMT_FAULT;
        }
        ctx->prep_bound = (size_t)mem_cfg_for_bound.size;
    }

    /* CHECKTX-P1 — the two node-local admission sets' CEILINGS, from the
     * same mempool size (nothing is allocated here; both grow on use).
     * An envelope's legs address DISTINCT domains (env_wire.c's strictly
     * ascending leg order) and a leg's domain must have a compiled
     * runtime (the per-leg admission), so no admitted entry claims more
     * conflict keys than one intent plus DNA_EFFECT_MAX_COUNT rows per
     * COMPILED runtime; the auth cache holds at most two inter-commit
     * windows of entries (the header's lifecycle note). */
    {
        size_t n_rt = 0;

        if (!nodus_runtime_builtin_table(&n_rt) || n_rt == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the compiled runtime table is "
                          "empty — the conflict-set bound cannot be sized");
            return CMT_FAULT;
        }
        ctx->pend_max = ctx->prep_bound *
                        (1u + n_rt * (size_t)DNA_EFFECT_MAX_COUNT);
    }
    ctx->acache_max = 2u * ctx->prep_bound;

    /* ENV_BOUND / CLAIM_BOUND: MaxDataBytes (types/block.go:281-300,
     * ported as cmt_max_data_bytes_no_evidence — evidence is never
     * ported, D-23's own "sm.EmptyEvidencePool{}" binding) divided by
     * the smallest canonical item of each class. `block.max_bytes`
     * comes from the genesis document, not a hardcoded 22 020 096 — the
     * ARITHMETIC is D-4 rev 3's, the VALUE read is whatever this chain's
     * committed genesis actually says. */
    {
        int64_t max_bytes = gendoc->has_consensus_params
                                ? gendoc->consensus_params.block.max_bytes
                                : 0;
        int64_t max_data_bytes = 0;
        int64_t min_env_proto  = 0;
        int64_t min_claim_proto = 0;

        if (max_bytes <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the genesis document carries no usable "
                          "Block.MaxBytes — the byte-bound seam cannot be "
                          "sized");
            return CMT_FAULT;
        }
        if (cmt_max_data_bytes_no_evidence(max_bytes,
                                           CMT_APP_MIN_VALS_FOR_BOUND,
                                           &max_data_bytes) != CMT_OK ||
            max_data_bytes <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "MaxDataBytes could not be computed from this "
                          "chain's Block.MaxBytes");
            return CMT_FAULT;
        }
        min_env_proto =
            nodus_cmt_compute_proto_size_for_tx(CMT_APP_MIN_ENV_BYTES);
        min_claim_proto =
            nodus_cmt_compute_proto_size_for_tx((size_t)DNA_CLAIM_FIXED_LEN);
        if (min_env_proto <= 0 || min_claim_proto <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the minimum item proto-size computed as zero or "
                          "negative — refusing to size the byte-bound seam "
                          "on a nonsensical figure");
            return CMT_FAULT;
        }
        ctx->env_bound   = (size_t)(max_data_bytes / min_env_proto);
        ctx->claim_bound = (size_t)(max_data_bytes / min_claim_proto);
        if (ctx->env_bound == 0 || ctx->claim_bound == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the derived byte-bound seam has zero capacity — "
                          "Block.MaxBytes is too small for even one minimal "
                          "item");
            return CMT_FAULT;
        }
        QGP_LOG_INFO(LOG_TAG, "byte-bound capacity seam (per-request, R3 "
                     "W4-C delta 2): max_bytes=%" PRId64 " max_data_bytes="
                     "%" PRId64 " prep_bound=%zu env_bound=%zu "
                     "claim_bound=%zu env_batch_max(engine)=%zu "
                     "env_cap(effective)=%zu claim_cap(effective)=%zu "
                     "mixed_item_cap=%zu",
                     max_bytes, max_data_bytes, ctx->prep_bound,
                     ctx->env_bound, ctx->claim_bound,
                     (size_t)NODUS_V2_ENV_BATCH_MAX,
                     (ctx->env_bound < (size_t)NODUS_V2_ENV_BATCH_MAX
                          ? ctx->env_bound
                          : (size_t)NODUS_V2_ENV_BATCH_MAX),
                     (ctx->claim_bound < NODUS_V2_APPLY_MAX_CLAIMS
                          ? ctx->claim_bound
                          : NODUS_V2_APPLY_MAX_CLAIMS),
                     (size_t)NODUS_V2_APPLY_MAX_OPS);
    }

    /* ── delta 2: NOTHING IS ALLOCATED HERE. prep_txs/fb_pb start NULL
     * (the memset above) and are built by their own rows, per request,
     * on first use — see nodus_cmt_app_prepare_proposal /
     * _finalize_block. Every other scratch array is now local to the
     * row that needs it. */
    return CMT_OK;
}

int nodus_cmt_app_ledger_build(nodus_cmt_app_t *out, nodus_cmt_app_ledger_t *ctx)
{
    if (!out || !ctx || !ctx->w) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->ctx                   = ctx;
    out->init_chain            = nodus_cmt_app_init_chain;            /* :20 */
    out->prepare_proposal      = nodus_cmt_app_prepare_proposal;      /* :21 */
    out->process_proposal      = nodus_cmt_app_process_proposal;      /* :22 */
    out->extend_vote           = nodus_cmt_app_extend_vote;           /* :23 */
    out->verify_vote_extension = nodus_cmt_app_verify_vote_extension; /* :24 */
    out->finalize_block        = nodus_cmt_app_finalize_block;        /* :25 */
    out->commit                = nodus_cmt_app_commit;                /* :26 */
    return CMT_OK;
}

/* proxy/app_conn.go:31 — `Error()`. The in-process connection has no
 * sticky error: there is no socket to break. */
static int app_mempool_error(void *vctx)
{
    return vctx ? CMT_OK : CMT_FAULT;
}

/* proxy/app_conn.go:35 — `Flush()`. Nothing is buffered between the
 * mempool and this application: `check_tx` answers in line. */
static int app_mempool_flush(void *vctx)
{
    return vctx ? CMT_OK : CMT_FAULT;
}

int nodus_cmt_app_ledger_build_mempool(cmt_mem_app_t *out,
                                       nodus_cmt_app_ledger_t *ctx)
{
    if (!out || !ctx || !ctx->w) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->ctx      = ctx;
    out->error    = app_mempool_error;
    out->check_tx = nodus_cmt_app_check_tx;
    out->flush    = app_mempool_flush;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The identity `nodus_witness_verify_transaction` demands
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_entry_identity(nodus_cmt_app_ledger_t *ctx,
                                 const uint8_t *bytes, size_t len,
                                 uint8_t out_id[64], uint8_t *out_class)
{
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    dna_env_preflight_t          *pf   = NULL;
    nodus_v2_envelope_t           env;
    uint64_t                      tip = 0;
    uint8_t                       cls;
    int                           rc = CMT_FAULT;

    if (!ctx || !ctx->w || !bytes || len == 0 || !out_id || !out_class) {
        return CMT_FAULT;
    }
    /* The ONE byte-driven classification authority — admission, ingress
     * and round entry share it (nodus_witness_v2_produce.h's contract). */
    cls = nodus_witness_v2_classify_entry(bytes, (uint32_t)len);
    *out_class = cls;

    if (cls == NODUS_W_TX_V2_CLAIM) {
        /* nodus_witness_verify.c:564-572 — the claim lane demands
         * SHA3-512 of the exact claim bytes. */
        if (qgp_sha3_512(bytes, len, out_id) != 0) {
            return CMT_FAULT;                   /* hash backend: node-local */
        }
        return CMT_OK;
    }

    /* nodus_witness_verify.c:750 — the envelope lane demands the DERIVED
     * wire_id. Deriving it needs the committed contextual ruleset table
     * and the candidate height, exactly as the seam builds them. */
    bctx = (nodus_witness_v2_block_ctx_t *)calloc(1, sizeof(*bctx));
    pf   = (dna_env_preflight_t *)calloc(1, sizeof(*pf));
    if (!bctx || !pf) {
        goto done;
    }
    if (nodus_witness_v2_tip_height(ctx->w, &tip) != 0) {
        goto done;                              /* node-local read fault   */
    }
    /* HF-3: the context is built at the candidate height (tip + 1), the
     * same height the preflight below uses; only its ruleset table is
     * read here. */
    switch (nodus_witness_v2_block_ctx_build(ctx->w, tip + 1u, bctx)) {
    case 0:
        break;
    case -1:
        /* A CHAIN-STATE verdict: SYSTEM is not ACTIVE, so no block on
         * this chain is appliable. Deterministic and identical on every
         * node — a refusal of the candidate, not this node's failure. */
        rc = CMT_REJECT;
        goto done;
    default:
        goto done;                              /* -2 node-local fault     */
    }
    env.env_bytes = bytes;
    env.env_len   = len;
    if (nodus_witness_v2_env_preflight_batch(ctx->w, tip + 1u, bctx->rulesets,
                                             bctx->n_rulesets, &env, 1, pf,
                                             NULL, NULL) != NODUS_V2_ENV_OK) {
        rc = CMT_REJECT;                        /* the bytes yield no id   */
        goto done;
    }
    memcpy(out_id, pf->wire_id, 64);
    rc = CMT_OK;
done:
    free(pf);
    free(bctx);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════
 * CheckTx — proxy/app_conn.go:33-34, D-23 rev 5 (9)
 * ═══════════════════════════════════════════════════════════════════════ */

/** The nonzero `ResponseCheckTx.Code` this application answers a refused
 *  transaction with. The reference reserves 0 for OK
 *  (abci/types/types.go:11) and leaves every other value to the
 *  application; one value is enough because the mempool only tests
 *  `code == CodeTypeOK` (clist_mempool.go:412, :492). */
#define NODUS_CMT_APP_CODE_REJECTED  ((uint32_t)1)
/** HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6
 *  "A distinct CheckTx code for 'generation not in force'"): the refused
 *  envelope names, for some domain, a ruleset_version that IS a compiled
 *  generation of that domain but not the one the committed registry runs
 *  — a client built for the other side of the RULESET_GEN2 height. Its
 *  only reader is the client that submitted (reload, rebuild). OUTSIDE
 *  every hash by construction: a CheckTx response code is mempool-only
 *  (the mempool tests `code == OK` and nothing else, shared/dnac/
 *  cmt_mem.c :1250/:1336) and LastResultsHash is built from FinalizeBlock
 *  results (shared/dnac/cmt_results.c), which never carry this value.
 *
 *  THE CHECKTX CODE SPACE (ResponseCheckTx.Code, this file only):
 *    0    OK (the reference's CodeTypeOK)
 *    1    NODUS_CMT_APP_CODE_REJECTED   — every other refusal
 *    100  NODUS_CMT_APP_CODE_GENERATION — this one
 *  The FinalizeBlock per-item codes are a DIFFERENT space,
 *  nodus_v2_tx_code_t (nodus_witness_v2_apply.h: 0 OK, 1..9 DECODE …
 *  FEE). 100 is deliberately outside it so a reader holding a bare
 *  number never confuses "generation not in force" with a FinalizeBlock
 *  class (2 would read as NODUS_V2_TX_ERR_CONTEXT). (REJECTED = 1 equals
 *  NODUS_V2_TX_ERR_DECODE numerically — pre-HF-4, unchanged here.) A new
 *  CheckTx code takes a value unused by both spaces. */
#define NODUS_CMT_APP_CODE_GENERATION ((uint32_t)100)
_Static_assert(NODUS_CMT_APP_CODE_GENERATION != NODUS_CMT_APP_CODE_REJECTED &&
               NODUS_CMT_APP_CODE_GENERATION >
                   (uint32_t)NODUS_V2_TX_ERR_FEE,
               "the CheckTx generation code collides with another code");
/* Nodus EVM: no time-windowed CheckTx EVM budget — the reference has no such
 * clock read (docs/plans/decisions/2026-09-25-consensus-clock-scope-correction.md). */

/** HF-4 — is a REFUSED envelope a "generation not in force" case (the
 *  code above)? Pure classification of an already-refused entry: decode
 *  the envelope; for each leg, the committed manifest of its domain runs
 *  ruleset_version R, and the leg names V != R where V is the
 *  ruleset_version of SOME compiled generation of that domain.
 *  @return 1 yes / 0 no (any decode or read problem is "no" — the entry
 *  is refused either way, only the code differs). */
static int app_generation_not_in_force(nodus_witness_t *w,
                                       const uint8_t *tx, size_t tx_len)
{
    dna_env_view_t v;
    memset(&v, 0, sizeof(v));
    if (dna_env_decode(tx, tx_len, &v) != 0) return 0;
    for (uint16_t l = 0; l < v.leg_count; l++) {
        dna_domain_manifest_t man;
        if (nodus_witness_domreg_get(w, v.leg[l].domain_id, NULL, &man,
                                     NULL) != 0)
            return 0;
        if (v.leg[l].ruleset_version == man.ruleset_version) continue;
        for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
            const nodus_domain_runtime_t *rt =
                nodus_runtime_for_generation(g, v.leg[l].domain_id);
            if (rt && rt->ruleset_version == v.leg[l].ruleset_version)
                return 1;
        }
    }
    return 0;
}

/** Encode one 64-byte identity key (intent_id / claim nullifier). */
static void app_key_id(app_key_t *k, uint8_t tag, const uint8_t id[64])
{
    k->b[0] = tag;
    memcpy(k->b + 1, id, 64);
    k->len = 65;
}

/** Encode one row-identity key: tag ‖ domain ‖ op ‖ key_len ‖ key. */
static void app_key_row(app_key_t *k, const nodus_v2_dry_run_row_t *r)
{
    uint8_t *p = k->b;

    p[0] = CMT_APP_PKEY_TAG_ROW;
    p[1] = (uint8_t)(r->domain_id >> 24);
    p[2] = (uint8_t)(r->domain_id >> 16);
    p[3] = (uint8_t)(r->domain_id >> 8);
    p[4] = (uint8_t)r->domain_id;
    p[5] = (uint8_t)(r->op_id >> 24);
    p[6] = (uint8_t)(r->op_id >> 16);
    p[7] = (uint8_t)(r->op_id >> 8);
    p[8] = (uint8_t)r->op_id;
    p[9] = (uint8_t)(r->key_len >> 8);
    p[10] = (uint8_t)r->key_len;
    memcpy(p + 11, r->key, r->key_len);
    k->len = (uint16_t)(11u + r->key_len);
}

/** CheckTx's refusal reason — abci types.proto:265 `ResponseCheckTx.log`
 *  ("nondeterministic"): human-readable text for the submitting client
 *  only (the reference's BroadcastTxSync returns it, rpc/core/
 *  mempool.go:52). The mempool never reads it and no hash covers it, so
 *  it decides nothing. Truncation to CMT_MEM_CHECK_TX_LOG_MAX is silent;
 *  the verdict is `code`, never this text. */
__attribute__((format(printf, 2, 3)))
static void app_refuse_log(cmt_mem_response_check_tx_t *res,
                           const char *fmt, ...)
{
    va_list ap;

    if (!res) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(res->log, sizeof(res->log), fmt, ap);
    va_end(ap);
}

/** Red-team 1 F1 — the NON-MUTATING probe the dry run calls for an ABI-2
 *  leg's synthetic keys after authorization, before anything executes
 *  (nodus_v2_conflict_probe_fn). Exactly pend_admit's verdict step 1: a
 *  key held by ANOTHER entry is a conflict; one held by this same entry
 *  (`owner`) is not, so a recheck of an admitted entry still passes.
 *  Nothing is inserted — app_pend_admit inserts every key of the entry
 *  after the whole dry run succeeded. */
typedef struct {
    const nodus_cmt_app_ledger_t *ctx;
    const uint8_t                *owner;      /* the entry identity [64]  */
} app_probe_ctx_t;

static int app_pend_probe(void *pctx, const nodus_v2_dry_run_row_t *rows,
                          size_t n)
{
    const app_probe_ctx_t *p = (const app_probe_ctx_t *)pctx;
    size_t                 i;

    if (!p || !p->ctx || !p->owner || (n && !rows)) {
        return -2;
    }
    for (i = 0; i < n && p->ctx->pend_cap; i++) {
        app_key_t k;
        uint64_t  h;
        int       found;
        size_t    at;

        app_key_row(&k, &rows[i]);
        if (app_key_hash(k.b, k.len, &h) != 0) {
            return -2;
        }
        at = pend_slot(p->ctx, h, k.b, k.len, &found);
        if (found && memcmp(p->ctx->pend[at]->owner, p->owner, 64) != 0) {
            return 1;
        }
    }
    return 0;
}

/** Admit `keys` for the entry `owner` into the pending conflict set and
 *  turn the answer into CheckTx's: CMT_OK with `*refused` set on a
 *  conflict or a full set, CMT_FAULT on an allocation failure. */
static int app_pend_admit(nodus_cmt_app_ledger_t *ctx,
                          const uint8_t owner[64], const app_key_t *keys,
                          size_t n, bool *refused,
                          cmt_mem_response_check_tx_t *res)
{
    int prc = pend_admit(ctx, owner, keys, n);

    if (prc == -2) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "check_tx: the pending conflict set "
                      "could not grow on this node");
        return CMT_FAULT;
    }
    if (prc == 1) {
        QGP_LOG_DEBUG(LOG_TAG, "%s", "check_tx refused: a pending mempool "
                      "entry already claims this intent / nullifier / row");
        app_refuse_log(res, "%s", "a pending mempool entry already claims "
                       "this intent / nullifier / row");
        *refused = true;
    } else if (prc == 2) {
        QGP_LOG_WARN(LOG_TAG, "check_tx refused: the pending conflict set "
                     "is at its bound (%zu keys)", ctx->pend_max);
        app_refuse_log(res, "the pending conflict set is at its bound "
                       "(%zu keys)", ctx->pend_max);
        *refused = true;
    }
    return CMT_OK;
}

/**
 * CHECKTX-P1 — the ENVELOPE half after the admission lane: the per-item
 * lifetime rule, the dry run (VM-less for an EVM leg, NEW and RECHECK —
 * red-team 1 F1 — with the non-mutating pending-conflict probe of its
 * synthetic keys after authorization), then the conflict keys (intent +
 * every row-identity row) inserted, then the auth cache. On RECHECK the
 * cached kind-1
 * and kind-3 (general multisig) verdicts of this wire_id are
 * offered to the dry run, which takes one only where the leg digest it
 * derives again matches — and re-runs every state-dependent stage.
 * @return CMT_OK (verdict in `*refused`) / CMT_FAULT node-local.
 */
static int app_check_envelope(nodus_cmt_app_ledger_t *ctx,
                              const uint8_t *tx, size_t tx_len,
                              const uint8_t id[64], bool is_recheck,
                              bool *refused,
                              cmt_mem_response_check_tx_t *res)
{
    nodus_v2_env_dry_run_t *dry  = NULL;
    app_key_t              *keys = NULL;
    nodus_v2_auth_reuse_t   reuse;
    const nodus_v2_auth_reuse_t *reuse_p = NULL;
    char   reason[256];
    size_t i, nkeys;
    int    drc;
    int    rc = CMT_FAULT;

    /* ── the mempool LIFETIME rule (docs/plans/decisions/2026-09-25-
     * mempool-policy.md, decision 1), new AND recheck: an envelope must
     * name an expiry, and no further than NODUS_CMT_APP_MAX_EXPIRY_AHEAD
     * blocks past the committed tip. The lower side — an expiry already
     * passed at tip + 1 — is the preflight's own refusal inside the dry
     * run (env_preflight.c step 3), so every admitted envelope leaves
     * the mempool at the first recheck after its expiry, at most that
     * many blocks from admission. A mempool rule only: block validity
     * (expiry 0 = "never") is unchanged. */
    {
        dna_env_view_t view;
        uint64_t       tip = 0;

        memset(&view, 0, sizeof(view));
        if (dna_env_decode(tx, tx_len, &view) != 0) {
            app_refuse_log(res, "%s", "the envelope does not decode");
            *refused = true;                 /* entry_identity decoded it;
                                              * unreachable, fail closed  */
            return CMT_OK;
        }
        if (nodus_witness_v2_tip_height(ctx->w, &tip) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "check_tx: the committed tip is "
                          "unreadable on this node");
            return CMT_FAULT;
        }
        if (view.expiry_height == 0 ||
            view.expiry_height >
                tip + (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD) {
            QGP_LOG_DEBUG(LOG_TAG, "check_tx refused: expiry_height %" PRIu64
                          " is 0 or beyond tip %" PRIu64 " + %u",
                          view.expiry_height, tip,
                          (unsigned)NODUS_CMT_APP_MAX_EXPIRY_AHEAD);
            app_refuse_log(res, "expiry_height %" PRIu64 " is 0 or beyond "
                           "tip %" PRIu64 " + %u", view.expiry_height, tip,
                           (unsigned)NODUS_CMT_APP_MAX_EXPIRY_AHEAD);
            *refused = true;
            return CMT_OK;
        }

        /* ── Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-
         * design.md rev 3 §8) — the MAX-GAS rule, new AND recheck: an
         * envelope whose EVM block-gas share (a CALL / CREATE leg's
         * DECLARED gas_limit, a bridge op's 21 000 —
         * nodus_rt_evm_env_block_gas, the ONE function the proposal seam
         * and FinalizeBlock sum) exceeds the EVM_BLOCK_GAS_LIMIT in force
         * for the next block (chain_config param 15 at tip + 1) can never
         * fit any block, so it is refused here instead of waiting in the
         * mempool until it expires. The reference's behaviour: cometbft
         * v0.38.26 mempool/mempool.go PostCheckMaxGas refuses a tx whose
         * gas_wanted > the consensus MaxGas. Placement differs (ours is
         * the application's CheckTx verdict, the reference's the
         * mempool's post-check on gas_wanted, which stays 0 here — see
         * nodus_cmt_app_check_tx); the effect is the same refusal. Pure
         * bytes + one committed chain_config read — no clock. */
        {
            uint64_t share = nodus_rt_evm_env_block_gas(&view,
                                                        DNA_DOMAIN_EVM);
            if (share > 0) {
                uint64_t lim = 0;
                char     greason[160];

                greason[0] = '\0';
                if (nodus_witness_v2_evm_block_gas_limit(
                        ctx->w, tip + 1, &lim, greason,
                        sizeof(greason)) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "check_tx: %s", greason);
                    return CMT_FAULT;
                }
                if (share > lim) {
                    QGP_LOG_DEBUG(LOG_TAG, "check_tx refused: EVM gas %"
                                  PRIu64 " exceeds the block gas limit %"
                                  PRIu64, share, lim);
                    app_refuse_log(res, "EVM gas %" PRIu64 " exceeds the "
                                   "block gas limit %" PRIu64, share, lim);
                    *refused = true;
                    return CMT_OK;
                }
            }
        }
    }

    dry = (nodus_v2_env_dry_run_t *)calloc(1, sizeof(*dry));   /* ~100 KB:
                                     * 64 verdicts × 1 440 B since HF-2
                                     * (1 424 B general multisig, ~70 KB
                                     * before) */
    if (!dry) {
        return CMT_FAULT;
    }
    if (is_recheck) {
        int    found = 0;
        size_t at = acache_find(ctx, id, &found);

        if (found) {
            struct nodus_cmt_app_acache *e = ctx->acache[at];

            e->gen = ctx->acache_gen;        /* used in this window     */
            memset(&reuse, 0, sizeof(reuse));
            reuse.leg_count = e->leg_count;
            reuse.present   = e->present;
            reuse.digest    = (const uint8_t (*)[64])e->digest;
            reuse.verdict   = e->verdict;
            reuse_p = &reuse;
        }
    }
    reason[0] = '\0';
    /* Nodus EVM, red-team 1 F1: a NEW entry and its RECHECK both run the
     * VM-less mode — an EVM leg's shared pre-validation only (auth shape,
     * pairing, decode, nonce, balance, intrinsic gas, the gas declaration
     * and read caps), never the VM: an EVM execution outcome never
     * changes admission (a failed execution is applied and paid), so
     * executing at admission bought nothing but unpaid, unbudgeted work
     * (the reference's mempool validates, it does not execute). The
     * pending-conflict PROBE runs inside the dry run right after
     * authorization, before any leg executes; it only looks — the keys
     * are inserted below, after the whole run succeeded. */
    {
        app_probe_ctx_t pc;

        pc.ctx   = ctx;
        pc.owner = id;
        drc = nodus_witness_v2_env_dry_run_ex(ctx->w, tx, tx_len, reuse_p,
                                              1, app_pend_probe, &pc, dry,
                                              reason, sizeof(reason));
    }
    if (drc == -2) {
        QGP_LOG_ERROR(LOG_TAG, "check_tx: the dry run could not be computed "
                      "on this node: %s", reason);
        goto done;                       /* never a verdict about the tx */
    }
    if (drc != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "check_tx refused by the dry run (item code "
                      "%u): %s", (unsigned)dry->code, reason);
        app_refuse_log(res, "dry run item code %u: %s",
                       (unsigned)dry->code, reason);
        *refused = true;
        rc = CMT_OK;
        goto done;
    }
    /* the conflict keys: the intent, then every row-identity row the
     * effects claim (every DELETE, every PRE_ABSENT CREATE — apply.h
     * `nodus_v2_dry_run_row_t`, which says why SETs are not keys) */
    nkeys = 1 + dry->n_rows;
    keys  = (app_key_t *)calloc(nkeys, sizeof(*keys));
    if (!keys) {
        goto done;
    }
    app_key_id(&keys[0], CMT_APP_PKEY_TAG_INTENT, dry->intent_id);
    for (i = 0; i < dry->n_rows; i++) {
        app_key_row(&keys[1 + i], &dry->rows[i]);
    }
    rc = app_pend_admit(ctx, id, keys, nkeys, refused, res);
    if (rc == CMT_OK && !*refused) {
        acache_store(ctx, dry);          /* NEW, or a RECHECK miss      */
    }

done:
    free(keys);
    nodus_witness_v2_env_dry_run_free(dry);
    free(dry);
    return rc;
}

/**
 * CHECKTX-P1 — the CLAIM half after the admission lane: the claim's
 * canonical nullifier (the apply lane's own derivation) is its conflict
 * key, so K signature-variants of ONE claim — K distinct entry ids, one
 * nullifier — admit only the first (red-team F5).
 * @return CMT_OK (verdict in `*refused`) / CMT_FAULT node-local.
 */
static int app_check_claim(nodus_cmt_app_ledger_t *ctx,
                           const uint8_t *tx, size_t tx_len,
                           const uint8_t id[64], bool *refused,
                           cmt_mem_response_check_tx_t *res)
{
    app_key_t key;
    uint8_t   nul[64];
    int       nrc;

    nrc = nodus_witness_v2_claim_nullifier(ctx->w, tx, tx_len, nul);
    if (nrc == -2) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "check_tx: the claim nullifier could "
                      "not be derived on this node");
        return CMT_FAULT;
    }
    if (nrc != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "%s", "check_tx refused: the claim's "
                      "nullifier derivation refused it");
        app_refuse_log(res, "%s", "the claim's nullifier derivation "
                       "refused it");
        *refused = true;
        return CMT_OK;
    }
    app_key_id(&key, CMT_APP_PKEY_TAG_NULLIFIER, nul);
    return app_pend_admit(ctx, id, &key, 1, refused, res);
}

int nodus_cmt_app_check_tx(void *vctx, const cmt_mem_request_check_tx_t *req,
                           cmt_mem_response_check_tx_t *res)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    uint8_t  id[64];
    uint8_t  cls = 0;
    char     reason[256];
    bool     refused = false;
    int      rc;

    if (!ctx || !ctx->w || !req || !res) {
        return CMT_FAULT;
    }
    memset(res, 0, sizeof(*res));
    if (!req->tx || req->tx_len == 0) {
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        app_refuse_log(res, "%s", "empty transaction");
        return CMT_OK;                          /* the request was served  */
    }
    /* `gas_wanted` stays 0: `PostCheckMaxGas` is nil while MaxGas is −1
     * (mempool.go:132-134), which is the value D-4 rev 3 (2) writes into
     * the genesis document, so the mempool never reads it. Nodus EVM: the EVM
     * gas bound that post-check would enforce is the application's own
     * refusal instead (app_check_envelope, "the MAX-GAS rule"). */
    rc = nodus_cmt_app_entry_identity(ctx, req->tx, req->tx_len, id, &cls);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;                       /* node-local: the panic
                                                 * class of :273/:669     */
    }
    if (rc != CMT_OK) {
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        app_refuse_log(res, "%s", "no entry identity: the envelope fails "
                       "preflight, or SYSTEM is not active");
        return CMT_OK;
    }
    reason[0] = '\0';
    /* D-23 rev 5 (9): the ledger's admission check, in ADMISSION mode
     * (nodus_witness_verify.h:50). On a successor chain the function
     * diverts to the V2 lane (nodus_witness_verify.c:808-813) and the
     * legacy parameters are unread — passed as the divert reads them. */
    rc = nodus_witness_verify_transaction(ctx->w, req->tx,
                                          (uint32_t)req->tx_len, id, cls,
                                          NULL, 0, NULL, NULL, 0,
                                          NODUS_WITNESS_VERIFY_ADMISSION,
                                          reason, sizeof(reason));
    if (rc != 0) {
        /* −1 invalid and −2 double-spend are both deterministic verdicts
         * about the bytes; neither is this node failing. */
        QGP_LOG_DEBUG(LOG_TAG, "check_tx refused (rc %d): %s", rc, reason);
        res->code = (cls == NODUS_W_TX_V2_ENVELOPE &&
                     app_generation_not_in_force(ctx->w, req->tx,
                                                 req->tx_len))
                        ? NODUS_CMT_APP_CODE_GENERATION
                        : NODUS_CMT_APP_CODE_REJECTED;
        app_refuse_log(res, "%s%s", res->code ==
                                      NODUS_CMT_APP_CODE_GENERATION
                                  ? "generation not in force: " : "",
                       reason[0] ? reason
                                 : (rc == -2 ? "double spend" : "invalid"));
        return CMT_OK;
    }
    /* ── AND THE SIGNATURES, AND EVERYTHING ELSE THE ITEM WOULD MEET ──
     * The admission lane above verifies NONE of the signatures. It runs
     * the wire-family marker, the contextual ruleset table, the
     * preflight, a `wire_id` comparison and the committed-intent guard
     * (nodus_witness_verify.c:674-784), and the preflight's own honest
     * label says it decides nothing about "whether any authorization is
     * VALID" (env_preflight.h:57-63). The `wire_id` comparison cannot
     * substitute: this row DERIVES the id from the very bytes it is
     * checking, so the comparison is a tautology (reported round 1) —
     * flipping a byte inside an approval signature changes both sides
     * and is accepted.
     *
     * CHECKTX-P1: nor does it run per-leg admission, the meter
     * reservation or the execution — so entries the proposal seam (or
     * the apply lane) then refuses sat in the mempool forever and were
     * re-admitted by every recheck (red-team F1/F3, nodus/BUGS.md). The
     * envelope now runs the apply engine's own per-item stages as a
     * DRY RUN (nodus_witness_v2_env_dry_run), the authorization stage
     * among them — the SAME helper the item loop uses, so D-4 rev 3 (1)'s
     * "including the signature" is still met by one source. Then every
     * entry's conflict keys meet the pending conflict set. Nodus EVM (red-team
     * 1 F1): an EVM leg is NOT executed here — the dry run's no-VM mode
     * runs its shared pre-validation only, and its synthetic (sender,
     * nonce) / ticket key is probed against the pending set right after
     * authorization, before that pre-validation. */
    if (cls == NODUS_W_TX_V2_ENVELOPE) {
        rc = app_check_envelope(ctx, req->tx, req->tx_len, id,
                                req->type == CMT_MEM_CHECK_TX_TYPE_RECHECK,
                                &refused, res);
    } else {
        rc = app_check_claim(ctx, req->tx, req->tx_len, id, &refused, res);
    }
    if (rc != CMT_OK) {
        res->log[0] = '\0';              /* a fault answers no text     */
        return CMT_FAULT;                /* node-local: never a verdict  */
    }
    if (refused) {
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        if (res->log[0] == '\0') {       /* every refusal site above
                                          * writes one; fail closed on
                                          * text, never on the verdict  */
            app_refuse_log(res, "%s", "refused");
        }
    } else {
        res->log[0] = '\0';              /* OK carries no text          */
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * InitChain — consensus/replay.go:318-373, D-23 rev 5 (7)
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_init_chain(void *vctx,
                             const nodus_abci_request_init_chain_t *req,
                             nodus_abci_response_init_chain_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    dna_vset_snapshot_t    *snap = NULL;
    uint8_t                 chain_id[DNA_CHAIN_ID_LEN];
    uint8_t                 root[64];
    size_t                  i, j;
    int                     rc = CMT_FAULT;

    if (!ctx || !ctx->w || !ctx->gendoc || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));

    /* ── (1) the committed chain id == the request's ───────────────────
     * ONE derivation, the ledger's own: `nodus_witness_v2_chain_id`
     * answers from the stored genesis document
     * (nodus_witness_v2_claims.c, nodus_witness_v2_chain_id). The
     * height-0 block-row branch it used to have is deleted with the
     * version-2 genesis that wrote that row (tokenomics-v3 P4). */
    if (nodus_witness_v2_chain_id(ctx->w, chain_id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the committed chain id is underivable");
        return CMT_FAULT;
    }
    if (req->chain_id_len != DNA_CHAIN_ID_LEN ||
        memcmp(req->chain_id, chain_id, DNA_CHAIN_ID_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the request's chain id is not the "
                      "committed one");
        return CMT_FAULT;
    }

    /* ── (2) the ledger's COMMITTED global root == the document's
     * app_hash ────────────────────────────────────────────────────────
     * The request carries no app_hash (abci/types.proto:76-83; the
     * reference sends six fields, replay.go:327-334), so the comparison
     * uses the genesis document this application was bound to
     * (DEVIATION R3-C1a-1).
     *
     * The ledger side is `nodus_witness_v2_committed_global_root` — the
     * tip block row's stored `global_root`, or the genesis composition
     * where no row exists — NOT `nodus_witness_global_root_v2`, which
     * recomputes from the live tables and is therefore an answer about
     * NOW rather than about the last committed block. One quantity, one
     * reader: the same helper serves anywhere this application needs
     * "the root after the last block". */
    if (nodus_witness_v2_committed_global_root(ctx->w, root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the ledger's committed global root is "
                      "unreadable");
        return CMT_FAULT;
    }
    if (ctx->gendoc->app_hash_len != 64 ||
        memcmp(ctx->gendoc->app_hash, root, 64) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the genesis document's app_hash is not "
                      "the ledger's committed global root");
        return CMT_FAULT;
    }

    /* ── (3) the committed validator set == the request's validators ──
     * The committed set is the genesis snapshot (epoch start 0). The
     * comparison is a MULTISET comparison on (public key, power), so it
     * does not depend on either side's ordering — the snapshot's rank
     * order and the document's order are different by construction
     * (nodus_witness_vset.h's build contract, D-19 rev 6 (5)). */
    if (nodus_witness_vset_get(ctx->w, 0, &snap, NULL) != 0 || !snap) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: no committed genesis validator snapshot");
        return CMT_FAULT;
    }
    if (req->validators_len != (size_t)snap->active_count) {
        QGP_LOG_ERROR(LOG_TAG, "InitChain: the request carries %zu validators, "
                      "the committed snapshot %u", req->validators_len,
                      (unsigned)snap->active_count);
        goto done;
    }
    /* A TRUE MULTISET EQUALITY, not a per-entry lookup.
     *
     * Each committed entry may be consumed AT MOST ONCE, so a request
     * carrying the same key twice cannot satisfy two positions with one
     * committed row: [A, A] against a committed [A, B] leaves B
     * unmatched and A already used, and is refused. Counting matches
     * per request entry — what this did before — accepted exactly that,
     * because each of the two A's found its one match independently.
     *
     * Unreachable through `derive_v3`, which refuses a duplicate
     * validator pubkey before anything is written
     * (nodus_witness_v2_gen.c:703-710, Rule P.3) — but InitChain's whole
     * job is to distrust the document it is handed, so it must not
     * depend on the producer's rule. With the counts equal and every
     * committed entry consumed at most once, "every request entry
     * matched" is multiset equality. */
    {
        /* tokenomics-v3 P3-7 (design D-10): the match table is sized by
         * the version-3 active-set ceiling NODUS_V2_ACTIVE_SET_MAX (32),
         * the same bound the snapshot writer, the resolver and the genesis
         * config array (NODUS_V2_GEN_MAX_VALIDATORS) enforce — no longer
         * by DNAC_COMMITTEE_SIZE (7), which is the genesis COUNT rule
         * (P.1), not a set-size ceiling. */
        bool used[NODUS_V2_ACTIVE_SET_MAX];

        if ((size_t)snap->active_count > NODUS_V2_ACTIVE_SET_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "InitChain: the committed snapshot holds "
                          "%u validators, above the version-3 active-set "
                          "ceiling %u", (unsigned)snap->active_count,
                          (unsigned)NODUS_V2_ACTIVE_SET_MAX);
            goto done;
        }
        memset(used, 0, sizeof(used));
        for (i = 0; i < req->validators_len; i++) {
            const cmt_pb_validator_update_t *v = &req->validators[i];
            bool matched = false;

            if (!v->pub_key.present) {
                QGP_LOG_ERROR(LOG_TAG, "InitChain: request validator %zu "
                              "carries no public key", i);
                goto done;
            }
            for (j = 0; j < (size_t)snap->active_count; j++) {
                uint64_t whole;

                if (used[j] ||
                    memcmp(v->pub_key.key, snap->entries[j].pubkey,
                           DNA_VSET_PUBKEY_LEN) != 0) {
                    continue;
                }
                /* THE POWER IS IN WHOLE UNITS, NOT RAW ONES.
                 * `gen_v3_row_derive` (nodus_witness_v2_gen.c:2302-2321)
                 * computes `power = self_stake / decimal_unit` — the
                 * SELF stake alone, because delegated is zero at genesis
                 * by construction (the config has no delegation input;
                 * gen.c:2315-2317 states it as a read fact, gen.h:613-621
                 * records why) — and the config's `decimal_unit` must
                 * equal the compiled DNAC_DECIMAL_UNIT (gen.c:529-533,
                 * nodus_witness_emission.h:42 = 100 000 000). Comparing
                 * against the RAW `total_stake` would refuse every real
                 * version-3 document by a factor of 10^8; `total_stake`
                 * IS the self stake at genesis for the same reason. */
                whole = snap->entries[j].total_stake / DNAC_DECIMAL_UNIT;
                if (v->power < 0 || (uint64_t)v->power != whole) {
                    QGP_LOG_ERROR(LOG_TAG, "InitChain: validator %zu's power "
                                  "%lld is not the committed stake %llu raw "
                                  "(= %llu whole units)", i,
                                  (long long)v->power,
                                  (unsigned long long)
                                      snap->entries[j].total_stake,
                                  (unsigned long long)whole);
                    goto done;
                }
                used[j] = true;
                matched = true;
                break;
            }
            if (!matched) {
                QGP_LOG_ERROR(LOG_TAG, "InitChain: request validator %zu "
                              "matches no UNUSED committed entry", i);
                goto done;
            }
        }
    }

    /* ── the response: app_hash, NO validator update, NO param update ──
     * replay.go:346-360 applies an update only when the application
     * returns one; returning none leaves the genesis document's set and
     * parameters in place, which is what D-23 rev 5 (7) requires. */
    memcpy(resp->app_hash, root, 64);
    resp->app_hash_len = 64;
    resp->validators = NULL;
    resp->validators_len = 0;
    resp->has_consensus_params = false;
    rc = CMT_OK;
done:
    dna_vset_free(&snap);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════
 * PrepareProposal — state/execution.go:141-165, D-4 rev 3 (3)
 * ═══════════════════════════════════════════════════════════════════════ */

/** Is this envelope a chain_config transaction?
 *
 * The legacy lane (deleted in R3 W4-D with nodus_witness_bft.c) keyed
 * the rule on the entry class `NODUS_W_TX_CHAIN_CONFIG` (bft.c:5434-5465
 * leader side, :6264-6280 follower side, in the tree before W4-D). The V2 lane has no such class — every entry
 * is an ENVELOPE or a CLAIM — so the same transaction is identified by
 * what it DOES: a leg on the SYSTEM domain (DNA_DOMAIN_SYSTEM,
 * shared/dnac/ledger_ids.h:52) whose `runtime_op` is
 * DNA_SYSRULE_CHAIN_CONFIG (nodus_witness_runtime.h:82 — "runtime_op 6,
 * legacy tx 10", nodus_witness_rt_native.c:17). DEVIATION R3-C1a-3: the
 * mapping is derived from the two sites above, not written anywhere as a
 * rule.
 */
static bool env_is_chain_config(const dna_env_view_t *v)
{
    uint16_t l;

    for (l = 0; l < v->leg_count; l++) {
        if (v->leg[l].domain_id == DNA_DOMAIN_SYSTEM &&
            v->leg[l].runtime_op == DNA_SYSRULE_CHAIN_CONFIG) {
            return true;
        }
    }
    return false;
}

/**
 * ORCHESTRATOR delta 2, item A — run the ledger's whole-batch capacity
 * seam over the `n` request indices in `order` (`order[k]` is an index
 * into `txs`). Builds a LIGHTWEIGHT `nodus_witness_batch_item_t` view,
 * heap, sized to `n` (per-request, never to a caller's worst-case
 * bound), freed before every return. `cap` is the CALLER's own already-
 * established admission ceiling (`ctx->prep_bound` for PrepareProposal,
 * `ctx->env_bound` for ProcessProposal) — `n` is always <= `cap` here,
 * both call sites refuse a larger request before this function is ever
 * reached, so this is a second, cheap belt-and-braces check inside
 * `nodus_witness_v2_produce_batch_check_capped`, not a live guard.
 *
 * `kind` (may be NULL) receives the seam's CLASSIFIED refusal
 * (`nodus_v2_batch_check_result_t.kind`, nodus_witness_v2_env.h): on a
 * -1 it says whether `*fail_slot` names an offender (ENTRY_INVALID), a
 * fit boundary (CAPACITY_UNITS) or nothing at all (CAPACITY_BYTES,
 * whose index is 0 by design — nodus_witness_v2_produce.c, the
 * "accuses nobody" note). PrepareProposal must read it; a caller that
 * does not is exactly the 2026-09-25 devnet halt.
 * @return 0 clean, -1 with `*fail_slot` naming the SLOT of `order` the
 *         seam reported (read it through `*kind`), -2 node-local fault
 *         (including an allocation failure for the view array itself).
 */
static int app_seam_check(nodus_cmt_app_ledger_t *ctx,
                          const cmt_pb_bytes_t *txs,
                          const size_t *order, size_t n, size_t cap,
                          int *fail_slot, nodus_v2_batch_fail_kind_t *kind)
{
    nodus_witness_batch_item_t   *view = NULL;
    nodus_v2_batch_check_result_t result;
    int fi = 0;
    int rc;
    size_t k;

    if (fail_slot) {
        *fail_slot = 0;
    }
    if (kind) {
        *kind = NODUS_V2_BATCH_FAIL_NONE;
    }
    if (n == 0) {
        return 0;                            /* an empty block is legal   */
    }
    view = (nodus_witness_batch_item_t *)calloc(n, sizeof(*view));
    if (!view) {
        return -2;
    }
    for (k = 0; k < n; k++) {
        const cmt_pb_bytes_t *t = &txs[order[k]];

        /* The seam reads tx_type, tx_data and tx_len only
         * (nodus_witness_v2_produce.c:369-386); the bytes are BORROWED
         * from the request and outlive this call. Classified fresh here
         * rather than threaded through a shared ctx array — delta 2
         * removed that array, and re-classifying (a leading-bytes check)
         * is cheap. */
        view[k].tx_type = nodus_witness_v2_classify_entry(t->data,
                                                           (uint32_t)t->len);
        view[k].tx_data = t->data;
        view[k].tx_len  = t->len;
    }
    memset(&result, 0, sizeof(result));
    rc = nodus_witness_v2_produce_batch_check_capped(
        ctx->w, view, (int)n, (int)cap, &fi, &result);
    if (rc == -1 && fail_slot) {
        *fail_slot = (fi >= 0 && (size_t)fi < n) ? fi : 0;
    }
    if (rc != 0 && kind) {
        *kind = result.kind;
    }
    free(view);
    return rc;
}

/** The unit/quota inputs of one PrepareProposal (CHECKTX-P1 round 2):
 *  the block-start budget and the committed per-domain quotas, read once
 *  per call from the block context the seam itself builds. `policy` is
 *  NULL when no envelope is a candidate. */
typedef struct {
    const dna_meter_policy_t *policy;
    dna_meter_budget_t        budget;               /* fresh, per call   */
    size_t                    n_quota;
    uint32_t                  quota_dom[DNA_METER_MAX_DOMAINS];
    uint16_t                  quota[DNA_METER_MAX_DOMAINS]; /* 0 = none  */
    dna_env_view_t           *view;                 /* heap scratch      */
    dna_meter_t              *meter;                /* heap scratch      */
    /* Nodus EVM: the block context's EVM facts (evm_active / evm_domain_id /
     * evm_block_gas_limit) — the streamed leg of each reservation and the
     * block gas sum, the seam's own rules (nodus_witness_v2_produce.c) */
    nodus_witness_v2_block_ctx_t evm_ctx;           /* EVM fields only   */
} app_prep_units_t;

/** Index of `domain_id` in the quota table, or -1. */
static int app_prep_quota_ix(const app_prep_units_t *u, uint32_t domain_id)
{
    size_t d;

    for (d = 0; d < u->n_quota; d++) {
        if (u->quota_dom[d] == domain_id) {
            return (int)d;
        }
    }
    return -1;
}

/**
 * CHECKTX-P1 — PACK one proposal: ONE forward pass over the
 * sorted (fee per unit, descending) `order[0..n)`, skipping every
 * `excluded[]` request index, that keeps an entry only if ALL of these
 * still hold with it
 * added, and otherwise SKIPS it and goes on (red-team F2/F6: the 0.19.77
 * pass STOPPED at the first envelope over the byte window, which cut
 * every lower-fee entry behind it — claims included, although claims
 * never count against the envelope window):
 *
 *  - `max_tx_bytes` bounds `ComputeProtoSizeForTxs` of the answer
 *    (types/tx.go:188-192; the host validates it again at
 *    nodus_witness_cmt_host.c:802 through `nodus_cmt_txs_validate`), so
 *    the accumulation uses the same measure;
 *  - `max_env_bytes` bounds the summed wire length of the ENVELOPE
 *    entries, exactly `nodus_witness_v2_block_bytes_check`'s measure
 *    (nodus_witness_v2_env.c): the seam sums `view.env_len` of the
 *    envelope subset only (claims never enter it,
 *    nodus_witness_v2_produce.c's class split), and `env_len` IS the
 *    entry's length for every envelope that decodes (shared/dnac/
 *    env_wire.c, "EXACT length" — every ENVELOPE in `order[]` decoded).
 *    The bound is INCLUSIVE, as there. An envelope that ALONE exceeds
 *    it fits no block (the legacy leader's own "genuinely poison" case)
 *    and is skipped like any other that does not fit;
 *  - R3 W4 package C — the PER-CLASS caps, now that the engine's own
 *    scratch is heap and sized per-block (nodus_witness_v2_apply.c):
 *    envelopes ≤ min(`env_bound`, `NODUS_V2_ENV_BATCH_MAX`) (delta 2
 *    on: a MEMORY ceiling, 3 075 since general multisig grew the auth
 *    verdict (64 MiB / 21 824 B; 20 908 B / 3 209 before); FROZEN at 3 075
 *    by HF-2 because consensus reads it — the budget grew to 65 MiB for
 *    the 21 856 B cost instead) — NOT the chain-config hard cap of 10 delta 1
 *    briefly tied it to; MAX_TXS_PER_BLOCK is RETIRED, apply.h; the
 *    min() because this chain's own byte-derived env_bound can only be
 *    SMALLER on a genesis document with an unusually small block) and
 *    claims ≤ min(`claim_bound`, `NODUS_V2_APPLY_MAX_CLAIMS`) (the
 *    smaller of this chain's own byte-derived claim capacity and the
 *    most claims any cometbft block can carry, 14 162 —
 *    nodus_witness_v2_apply.h). A class that reached its cap skips its
 *    own lowest-fee remainder only. ⚠ CORRECTED CLAIM (was wrong here
 *    through W3, R3-W3-C2a-19): a domain_id CANNOT repeat across one
 *    envelope's legs — `dna_env_decode` (shared/dnac/env_wire.c:364-365)
 *    and `dna_env_encode` (:276) both refuse a leg list that is not
 *    STRICTLY ascending by domain_id — so the engine's per-domain
 *    `d->n_tx` bound is a proven-unreachable FAULT, not a live risk;
 *  - ORCHESTRATOR delta 11 — the engine's own per-block MIXED item
 *    bound `NODUS_V2_APPLY_MAX_OPS` (R3-W3-C2a-19; package C made it
 *    the DERIVED sum of the two class caps), the pass STOPS there: kept
 *    as defense-in-depth behind the per-class caps, a no-op in practice.
 *
 * Shaping the proposal this way is squarely inside the Application's own
 * contract — abci++_methods.md's PrepareProposal section: "The
 * Application _can_ modify the raw proposal: it can reorder, remove or
 * add transactions... If the Application considers that `tx` should not
 * be proposed in this block ... then it should not include it in
 * `PrepareProposalResponse.txs`" (spec/abci/abci++_methods.md:347-351,
 * cometbft @v0.38.26). Every kept entry keeps its sort order.
 *
 * CHECKTX-P1 round 2 (red-team HIGH "the hog", decision 2026-09-25-
 * mempool-policy.md 2: "sığmayan işlem atlanır, arkasındaki sığanlar
 * bloğa girer") — two more bounds, the ones the seam and the item loop
 * enforce, so the seam no longer has a unit budget to refuse on:
 *  - the UNIT budget: each envelope is reserved with the seam's OWN call,
 *    `dna_meter_reserve` (res_meter.c:278-340 — the plan's declared
 *    ceiling against the GLOBAL remainder, every leg's static units
 *    against its DOMAIN remainder), against a scratch copy of the SAME
 *    block-start budget the seam builds, in the SAME order the seam
 *    reserves (the packed order). A GLOBAL/DOMAIN budget refusal SKIPS
 *    the envelope and the pass goes on, so smaller later ones still fit;
 *    any other reservation refusal (an unpriceable plan) is a property
 *    of the bytes — the envelope is EXCLUDED for the call;
 *  - the per-domain `quota_tx_per_block` of the committed manifest (the
 *    item loop's CAPACITY rule, `env_admit_legs` in
 *    nodus_witness_v2_apply.c; the seam has no such check): an envelope
 *    one of whose leg domains already has its quota of packed envelopes
 *    is SKIPPED.
 * Claims are unmetered and quota-free (the seam and the item loop
 * reserve and count ENVELOPES only), so a claim is packed whenever its
 * class cap and `max_tx_bytes` allow, whatever the envelopes did.
 *
 * @return the packed count (written to `sel`, request indices);
 *         `*env_total_out` receives the packed envelope bytes.
 */
static size_t app_prep_pack(const nodus_cmt_app_ledger_t *ctx,
                            const nodus_abci_request_prepare_proposal_t *req,
                            const size_t *order, size_t n,
                            const uint8_t *class_arr, bool *excluded,
                            uint64_t max_env_bytes,
                            const app_prep_units_t *u, size_t *sel,
                            uint64_t *env_total_out)
{
    size_t   env_cap = ctx->env_bound < NODUS_V2_ENV_BATCH_MAX
                           ? ctx->env_bound
                           : NODUS_V2_ENV_BATCH_MAX;
    size_t   claim_cap = ctx->claim_bound < NODUS_V2_APPLY_MAX_CLAIMS
                             ? ctx->claim_bound
                             : NODUS_V2_APPLY_MAX_CLAIMS;
    size_t   k, out = 0, env_kept = 0, claim_kept = 0;
    int64_t  total = 0;
    uint64_t env_total = 0;
    dna_meter_budget_t budget;                   /* the scratch remainder */
    uint32_t n_tx[DNA_METER_MAX_DOMAINS];        /* packed per quota dom  */
    uint64_t gas_sum = 0;                        /* Nodus EVM: packed EVM gas */

    memset(&budget, 0, sizeof(budget));
    memset(n_tx, 0, sizeof(n_tx));
    if (u->policy) {
        budget = u->budget;
    }
    for (k = 0; k < n && out < NODUS_V2_APPLY_MAX_OPS; k++) {
        size_t  idx    = order[k];
        size_t  len    = req->txs[idx].len;
        int64_t cost   = nodus_cmt_compute_proto_size_for_tx(len);
        bool    is_env = class_arr[idx] == NODUS_W_TX_V2_ENVELOPE;

        if (excluded[idx]) {
            continue;
        }
        if (is_env ? env_kept >= env_cap : claim_kept >= claim_cap) {
            continue;                        /* this class's own overflow */
        }
        if (cost < 0 || total > req->max_tx_bytes - cost) {
            continue;                        /* does not fit the budget   */
        }
        if (is_env && ((uint64_t)len > max_env_bytes ||
                       env_total > max_env_bytes - (uint64_t)len)) {
            continue;                        /* the ledger's byte bound   */
        }
        if (is_env) {
            const dna_env_view_t *v = u->view;
            dna_meter_status_t    ms;
            uint16_t              l;
            bool                  quota_full = false, unknown = false;

            if (!u->policy || !u->view || !u->meter ||
                dna_env_decode(req->txs[idx].data, len, u->view) != 0) {
                excluded[idx] = true;        /* nothing to reserve with   */
                continue;
            }
            for (l = 0; l < v->leg_count; l++) {
                int qi = app_prep_quota_ix(u, v->leg[l].domain_id);

                if (qi < 0) {
                    unknown = true;          /* no ACTIVE runtime domain  */
                    break;
                }
                if (u->quota[qi] != 0 &&
                    n_tx[qi] + 1u > (uint32_t)u->quota[qi]) {
                    quota_full = true;
                }
            }
            if (unknown) {
                excluded[idx] = true;
                continue;
            }
            if (quota_full) {
                continue;                    /* the domain's block quota  */
            }
            /* Nodus EVM (design §8): the block gas sum — an envelope whose EVM
             * share does not fit what is left is SKIPPED (a smaller later
             * one may still fit), the seam's own rule; a share that alone
             * exceeds the limit fits no block. A no-op before the EVM
             * edge (evm_active 0). */
            uint64_t gas_try = gas_sum;
            if (nodus_witness_v2_ctx_block_gas_add(&u->evm_ctx, v,
                                                   &gas_try) != 0) {
                continue;
            }
            memset(u->meter, 0, sizeof(*u->meter));
            /* Nodus EVM: an EVM leg is the plan's streamed leg (the seam's and
             * the item loop's rule; 0 before the EVM edge = the
             * dna_meter_reserve of before) — F3-C1's noted gap */
            ms = dna_meter_reserve_ex(
                u->meter, u->policy, v, &budget,
                nodus_witness_v2_ctx_stream_leg(&u->evm_ctx, v));
            if (ms == DNA_METER_ERR_GLOBAL_BUDGET ||
                ms == DNA_METER_ERR_DOMAIN_BUDGET) {
                continue;                    /* the unit budget: skip     */
            }
            if (ms != DNA_METER_OK) {
                excluded[idx] = true;        /* the plan itself refused   */
                continue;
            }
            gas_sum = gas_try;
            for (l = 0; l < v->leg_count; l++) {
                n_tx[app_prep_quota_ix(u, v->leg[l].domain_id)]++;
            }
            env_total += (uint64_t)len;
            env_kept++;
        } else {
            claim_kept++;
        }
        total += cost;
        sel[out++] = idx;
    }
    *env_total_out = env_total;
    return out;
}

/* ── FEE PER UNIT, exactly (CHECKTX-P1 round 2, decision 2026-09-25-
 * mempool-policy.md 2 — "gas çarpanı": fee / declared gas limit, no new
 * wire field). Two ratios fee_a/units_a and fee_b/units_b compare as the
 * 128-bit products fee_a·units_b and fee_b·units_a — integer only, no
 * floating point, no rounding. A claim (no fee field) and an envelope
 * declaring 0 units both rank as the ratio 0/1. */
static void app_mul_u64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t a0 = a & 0xFFFFFFFFu, a1 = a >> 32;
    uint64_t b0 = b & 0xFFFFFFFFu, b1 = b >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);

    *lo = (p00 & 0xFFFFFFFFu) | (mid << 32);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

/** 1 when fee_a/units_a is STRICTLY greater than fee_b/units_b. */
static bool app_ratio_gt(uint64_t fee_a, uint64_t units_a,
                         uint64_t fee_b, uint64_t units_b)
{
    uint64_t lh, ll, rh, rl;

    if (units_a == 0) { fee_a = 0; units_a = 1; }
    if (units_b == 0) { fee_b = 0; units_b = 1; }
    app_mul_u64(fee_a, units_b, &lh, &ll);
    app_mul_u64(fee_b, units_a, &rh, &rl);
    return lh > rh || (lh == rh && ll > rl);
}

int nodus_cmt_app_prepare_proposal(
        void *vctx, const nodus_abci_request_prepare_proposal_t *req,
        nodus_abci_response_prepare_proposal_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    size_t   n = 0, i, k;
    size_t   n_sel = 0;             /* the packed proposal, in `sel`     */
    uint64_t env_total = 0;         /* summed ENVELOPE bytes, the seam's
                                     * own block-byte measure           */
    uint64_t max_env_bytes = 0;     /* the policy's max_block_env_bytes  */
    bool     bytes_logged = false;  /* the unreachable-BYTES line, once  */
    bool     cc_alone = false;      /* a chain_config rides alone        */
    bool     refill_ok = true;      /* no tail drop happened yet         */
    size_t   passes = 0;            /* seam refusals acted on            */
    size_t   guard;
    int      rc_out = CMT_FAULT;

    /* ORCHESTRATOR delta 2, item A — every array below is LOCAL and
     * PER-REQUEST, sized to req->txs_len (never to prep_bound's worst
     * case), freed via goto-cleanup before every return. Only
     * `new_prep_txs` survives past this function — it becomes
     * `ctx->prep_txs`, the RESPONSE buffer the ABCI ownership rule keeps
     * valid until the NEXT call to this same method. CHECKTX-P1 adds
     * `excluded` (per request index: out of this proposal for good) and
     * `sel` (the packed proposal, request indices in sort order), both
     * the same size and lifetime; round 2 adds `units` (each envelope's
     * declared res_max_total_units, the sort's denominator) and `pu`
     * (the unit/quota inputs of the pack, freed with its scratch). */
    uint64_t       *fee       = NULL;
    uint64_t       *units     = NULL;
    app_prep_units_t *pu      = NULL;
    uint8_t        *class_arr = NULL;
    bool           *is_cc     = NULL;
    bool           *excluded  = NULL;
    size_t         *order     = NULL;
    size_t         *sel       = NULL;
    cmt_pb_bytes_t *new_prep_txs = NULL;

    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));

    /* delta 2 — THIS call is "the next call" the ABCI ownership rule
     * means: the PREVIOUS response buffer may now be freed. A FAULT
     * return below stops the node anyway (umbrella panic rule), so
     * there is no "next call" to have left it valid for. */
    free(ctx->prep_txs);
    ctx->prep_txs     = NULL;
    ctx->prep_txs_len = 0;
    ctx->prep_txs_cap = 0;

    if (req->txs_len > ctx->prep_bound) {
        /* An explicit bound, INVARIANT
         * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07 — the mempool's own
         * configured size. The host reaps at most what it was
         * configured for; more than this module can hold is a
         * node-local configuration mismatch, not a peer's doing. */
        QGP_LOG_ERROR(LOG_TAG, "PrepareProposal carries %zu transactions, the "
                      "bound is %zu", req->txs_len, ctx->prep_bound);
        return CMT_FAULT;
    }
    if (req->txs_len == 0) {
        resp->txs     = NULL;
        resp->txs_len = 0;
        return CMT_OK;                       /* nothing to allocate        */
    }

    fee       = (uint64_t *)calloc(req->txs_len, sizeof(*fee));
    class_arr = (uint8_t *)calloc(req->txs_len, sizeof(*class_arr));
    is_cc     = (bool *)calloc(req->txs_len, sizeof(*is_cc));
    order     = (size_t *)calloc(req->txs_len, sizeof(*order));
    excluded  = (bool *)calloc(req->txs_len, sizeof(*excluded));
    sel       = (size_t *)calloc(req->txs_len, sizeof(*sel));
    units     = (uint64_t *)calloc(req->txs_len, sizeof(*units));
    pu        = (app_prep_units_t *)calloc(1, sizeof(*pu));
    if (!fee || !class_arr || !is_cc || !order || !excluded || !sel ||
        !units || !pu) {
        rc_out = CMT_FAULT;
        goto done;
    }

    /* ── classify and price every candidate ─────────────────────────── */
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];
        dna_env_view_t view;
        uint8_t cls;

        if (!t->data || t->len == 0) {
            continue;                        /* nothing to propose        */
        }
        cls = nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len);
        class_arr[i] = cls;
        is_cc[i]     = false;
        fee[i]       = 0;
        if (cls == NODUS_W_TX_V2_ENVELOPE) {
            memset(&view, 0, sizeof(view));
            if (dna_env_decode(t->data, t->len, &view) != 0) {
                continue;                    /* the engine would refuse it */
            }
            /* env_wire.h:53-54 — `fee_amount` u64 BE at offset 25,
             * `res_max_total_units` u64 BE at offset 33. */
            fee[i]   = view.fee_amount;
            units[i] = view.res_max_total_units;
            is_cc[i] = env_is_chain_config(&view);
        }
        /* A CLAIM carries no fee field (dna_claim_t has none), so its
         * ordering key is 0 and it sorts after every paying envelope.
         * DEVIATION R3-C1a-2: D-4 rev 3 (3) says "fee-descending" and
         * does not define a claim's fee. */
        order[n++] = i;
    }

    /* ── fee PER UNIT descending, STABLE (ties keep arrival order) ────
     * CHECKTX-P1 round 2, decision 2026-09-25-mempool-policy.md 2: the
     * key is fee / declared res_max_total_units (the wallet's "gas
     * multiplier" — no new wire field), compared EXACTLY by
     * `app_ratio_gt` (128-bit cross products). A full-budget "hog" paying
     * the minimum fee therefore sorts LAST, not second. Insertion sort
     * with a strict `>` test: an element moves past an earlier one only
     * when its ratio is strictly greater, so equal ratios stay in request
     * order. This was the legacy mempool's own ordering discipline over
     * the flat fee (its insert went before the FIRST entry with a
     * strictly smaller fee; that module was deleted in R3 W4 — the rule
     * lives here now). */
    for (k = 1; k < n; k++) {
        size_t cur = order[k];
        size_t j   = k;

        while (j > 0 && app_ratio_gt(fee[cur], units[cur],
                                     fee[order[j - 1]], units[order[j - 1]])) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = cur;
    }

    /* ── the ledger's own envelope-byte bound, from the SAME authority
     * the seam reads ─────────────────────────────────────────────────
     * INVARIANT: PrepareProposal applies every byte bound the engine
     * enforces BEFORE the seam runs. The engine's absolute per-block
     * envelope-byte bound is the SYSTEM runtime's sealed meter policy's
     * `max_block_env_bytes` (nodus_witness_runtime.c `sys_policy_build`,
     * 2 x DNA_ENV_MAX_TOTAL_LEN), enforced as a whole-batch SUM in the
     * reserve seam (nodus_witness_v2_env.c, step 4b). It is read here
     * through the ONE block-start context builder the seam itself uses
     * (nodus_witness_v2_produce.c, the envelope subset), never
     * hard-coded, so a repinned policy moves both sides together. From
     * the HF-3 height (the context's hf3_active) the seam skips that sum
     * and this bound becomes UINT64_MAX with it — still the same
     * authority on both sides (design 2026-10-01-hf3-comet-block-bounds-
     * design.md §0 rule 1).
     *
     * 2026-09-25 devnet halt at height 135: this bound was NOT applied
     * here, ~827 envelopes (~6 MB) reached the seam, the seam answered
     * CAPACITY_BYTES with its by-design index 0, and the drop loop below
     * read that 0 as an offender — it dropped the HIGHEST-fee envelope
     * and re-ran the full seam, one envelope per pass: O(n^2), minutes
     * per PrepareProposal on the single event loop, every round late,
     * the chain halted with the mempool full.
     *
     * Built only when an ENVELOPE is a candidate: the seam builds the
     * context only for a non-empty envelope subset too, so a claims-only
     * proposal behaves exactly as before. A build failure is the same
     * condition the seam reports as a node-local fault (-1 and -2 both,
     * nodus_witness_v2_produce.c's block-context branch), which the drop
     * loop below already turns into CMT_FAULT — answered the same way
     * here, just earlier. */
    for (k = 0; k < n; k++) {
        if (class_arr[order[k]] == NODUS_W_TX_V2_ENVELOPE) {
            break;
        }
    }
    if (k < n) {
        nodus_witness_v2_block_ctx_t *bctx =
            (nodus_witness_v2_block_ctx_t *)calloc(1, sizeof(*bctx));
        uint64_t prep_tip = 0;
        int bcrc;

        if (!bctx) {
            rc_out = CMT_FAULT;
            goto done;
        }
        /* HF-3 D1 (b): this proposal's OWN height source — the committed
         * tip + 1 from the database, the height the seam's `candidate`
         * (nodus_witness_v2_produce.c) resolves too, so the pack and the
         * drop loop's seam runs judge under one switch. An unreadable
         * tip is this node's fault (the same -2 the builder answers). */
        bcrc = (nodus_witness_v2_tip_height(ctx->w, &prep_tip) != 0)
                   ? -2
                   : nodus_witness_v2_block_ctx_build(ctx->w, prep_tip + 1u,
                                                      bctx);
        if (bcrc == 0 && bctx->policy) {
            /* HF-3 §0 rule 1: from the HF-3 height the envelope-byte
             * bound is NOT a bound — the seam skips its byte step
             * (skip_byte_bound = hf3_active) and the pack must not trim
             * on it either, or Prepare and Process would disagree about
             * the same batch. UINT64_MAX, never 0 (0 is the FAULT gate
             * below and a -1 in nodus_witness_v2_block_bytes_check): the
             * pack's `len > max_env_bytes` / `env_total > max_env_bytes -
             * len` tests then never fire (env_total <= max_tx_bytes, so
             * the subtraction cannot wrap), and neither does the
             * chain_config candidate's `len > max_env_bytes`. */
            max_env_bytes = bctx->hf3_active
                                ? UINT64_MAX
                                : bctx->policy->max_block_env_bytes;
            /* CHECKTX-P1 round 2 — the pack's unit/quota inputs from the
             * SAME context: the sealed policy (BORROWED from the runtime
             * registry, outlives this call), the fresh budget, and every
             * budgeted domain's committed quota_tx_per_block (the manifest
             * the item loop's admission reads — doms_load →
             * nodus_witness_domreg_get). */
            pu->policy  = bctx->policy;
            pu->budget  = bctx->budget;
            pu->n_quota = bctx->budget.n_domains;
            /* Nodus EVM: the EVM facts of the same context */
            pu->evm_ctx.evm_active          = bctx->evm_active;
            pu->evm_ctx.evm_domain_id       = bctx->evm_domain_id;
            pu->evm_ctx.evm_block_gas_limit = bctx->evm_block_gas_limit;
            for (i = 0; i < pu->n_quota && bcrc == 0; i++) {
                dna_domain_manifest_t man;

                pu->quota_dom[i] = bctx->budget.dom[i].domain_id;
                if (nodus_witness_domreg_get(ctx->w, pu->quota_dom[i], NULL,
                                             &man, NULL) != 0) {
                    bcrc = -2;               /* registry unreadable here  */
                } else {
                    pu->quota[i] = man.quota_tx_per_block;
                }
            }
        }
        free(bctx);                          /* only scalars + the borrowed
                                              * policy pointer are kept    */
        pu->view  = (dna_env_view_t *)calloc(1, sizeof(*pu->view));
        pu->meter = (dna_meter_t *)calloc(1, sizeof(*pu->meter));
        if (bcrc != 0 || max_env_bytes == 0 || !pu->view || !pu->meter) {
            QGP_LOG_ERROR(LOG_TAG, "PrepareProposal: the block-start "
                          "context (the envelope-byte bound, the unit "
                          "budget, the domain quotas) could not be built on "
                          "this node (rc=%d)", bcrc);
            rc_out = CMT_FAULT;
            goto done;
        }
    }

    /* ── a chain_config transaction rides alone — IF IT CAN RIDE ──────
     * The legacy leader keeps the chain_config entry and requeues the
     * rest (nodus_witness_bft.c:5434-5465); here the rest simply stay in
     * the mempool, because PrepareProposal only chooses.
     *
     * CHECKTX-P1 (red-team F1): the fee-first chain_config candidate
     * used to ride alone UNCONDITIONALLY — so one the seam refuses (a
     * SYSTEM CHAIN_CONFIG leg declaring res_max_total_units 0) emptied
     * every block while it sat in the mempool. Now each chain_config
     * candidate, in fee order, rides alone only if it fits the byte
     * budgets and the seam accepts it ALONE; a refused one is left out
     * (it stays in the mempool, where the CheckTx dry run keeps a new one
     * from arriving) and the next is tried. Every chain_config candidate
     * is excluded from the ordinary packing below either way — they
     * never share a block. Bound: one one-item seam run per chain_config
     * candidate. */
    for (k = 0; k < n; k++) {
        size_t  idx = order[k];
        size_t  len;
        int64_t cost;
        int     crc;

        if (!is_cc[idx]) {
            continue;
        }
        excluded[idx] = true;
        len  = req->txs[idx].len;
        cost = nodus_cmt_compute_proto_size_for_tx(len);
        if (cost < 0 || cost > req->max_tx_bytes ||
            (uint64_t)len > max_env_bytes) {
            continue;                        /* fits no block this round  */
        }
        crc = app_seam_check(ctx, req->txs, &order[k], 1, ctx->prep_bound,
                             NULL, NULL);
        if (crc == -2) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "PrepareProposal: the capacity seam faulted on "
                          "this node (chain_config candidate)");
            rc_out = CMT_FAULT;
            goto done;
        }
        if (crc == 0) {
            sel[0]  = idx;
            n_sel   = 1;
            cc_alone = true;
            break;
        }
        QGP_LOG_INFO(LOG_TAG, "%s", "PrepareProposal: a chain_config "
                     "candidate the seam refuses alone is left out; the "
                     "rest are packed");
    }

    /* ── pack: the byte budgets, the unit budget, the domain quotas, the
     * per-class caps and the mixed item bound, in ONE sorted pass
     * (app_prep_pack — see its comment for why an entry that does not
     * fit is SKIPPED, not a stop). ──────────────────────────────────── */
    if (!cc_alone) {
        n_sel = app_prep_pack(ctx, req, order, n, class_arr, excluded,
                              max_env_bytes, pu, sel, &env_total);
    }

    /* ── the engine's own seam: never propose what apply would refuse ──
     * O15I capacity seam, with the O15I leader's KIND discrimination
     * (defa07c6 — the legacy leader in nodus_witness_bft.c, deleted in
     * R3 W4; nodus_witness_v2_env.h's nodus_v2_batch_fail_kind_t):
     *  - ENTRY_INVALID at slot i: that entry never becomes valid — it
     *    is EXCLUDED and the proposal is REPACKED from the remaining
     *    sorted candidates (CHECKTX-P1, red-team F2: the freed room is
     *    refilled, not left empty), re-run.
     *  - CAPACITY_UNITS at ANY slot: unreachable in practice — the pack
     *    reserved every envelope with the seam's own `dna_meter_reserve`,
     *    in the seam's order, against the same block-start budget, and
     *    skipped the ones that did not fit. Should it happen anyway, the
     *    named entry is EXCLUDED and the proposal repacked, exactly like
     *    ENTRY_INVALID. CHECKTX-P1 round 2 DELETED the 0.19.77
     *    "truncate to the prefix [0, i)" answer: it discarded every
     *    fitting entry behind a full-budget hog — claims included — and
     *    the hog was re-admitted by every recheck (red-team HIGH).
     *  - CAPACITY_BYTES: its index is 0 BY DESIGN and accuses nobody
     *    (nodus_witness_v2_produce.c). Unreachable after the pack's
     *    envelope-byte bound (same bound, same measure); should it ever
     *    happen, the tail is dropped — never slot 0 — no refill follows,
     *    and it is logged once per call.
     *  - anything else is this node's fault: the proposal stops.
     *
     * BOUND (red-team F2/F3). Let W = the packed count (at most
     * NODUS_V2_APPLY_MAX_OPS) and R = NODUS_CMT_APP_PREP_REFILL_MAX.
     * Passes 1..R that name an offender repack (each pass excludes one
     * candidate for good, so a repack never re-proposes it); every later
     * pass removes one entry AND halves what is left. So at most
     * R + ceil(log2 W) + 1 seam runs follow the first, each over at most
     * W entries: O((R + log W) · W) seam work, never the O(W^2) of one
     * run per dropped entry. The CheckTx dry run (and its conflict set)
     * is what makes an offender rare in the first place — every mempool
     * entry already passed the seam's own per-item checks at this
     * height, and the pack already applied the seam's byte and unit
     * bounds. The guard below is only a belt. */
    for (guard = 0; !cc_alone &&
                    guard <= ctx->prep_bound + NODUS_CMT_APP_PREP_REFILL_MAX;
         guard++) {
        int fail_slot = 0;
        nodus_v2_batch_fail_kind_t fkind = NODUS_V2_BATCH_FAIL_NONE;
        int rc = app_seam_check(ctx, req->txs, sel, n_sel, ctx->prep_bound,
                                &fail_slot, &fkind);

        if (rc == 0) {
            break;
        }
        if (rc != -1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "PrepareProposal: the capacity seam faulted on "
                          "this node");
            rc_out = CMT_FAULT;
            goto done;
        }
        if (n_sel == 0) {
            break;                           /* nothing left to drop: an
                                              * EMPTY block is legal       */
        }
        passes++;
        if (fkind == NODUS_V2_BATCH_FAIL_CAPACITY_BYTES) {
            if (!bytes_logged) {
                QGP_LOG_ERROR(LOG_TAG, "PrepareProposal: the seam refused "
                              "%zu candidates on the envelope-byte bound "
                              "AFTER the byte trim (bound %llu, trimmed to "
                              "%llu) — dropping from the tail", n_sel,
                              (unsigned long long)max_env_bytes,
                              (unsigned long long)env_total);
                bytes_logged = true;
            }
            n_sel--;
            refill_ok = false;
            if (passes > NODUS_CMT_APP_PREP_REFILL_MAX && n_sel > 1) {
                n_sel = (n_sel + 1) / 2;     /* the geometric tail bound  */
            }
        } else if (fkind != NODUS_V2_BATCH_FAIL_ENTRY_INVALID &&
                   fkind != NODUS_V2_BATCH_FAIL_CAPACITY_UNITS) {
            /* rc -1 always carries one of the three verdict kinds
             * (nodus_witness_v2_produce.c); any other kind here is this
             * node failing to classify, never a verdict to act on. */
            QGP_LOG_ERROR(LOG_TAG, "PrepareProposal: the capacity seam "
                          "refused with an unclassified kind %d",
                          (int)fkind);
            rc_out = CMT_FAULT;
            goto done;
        } else {
            /* ENTRY_INVALID, or CAPACITY_UNITS (any slot — the pack
             * should have made it unreachable), at fail_slot: that entry
             * is out of this proposal for good. */
            if (fkind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS) {
                QGP_LOG_WARN(LOG_TAG, "PrepareProposal: the seam refused "
                             "slot %d of %zu on the unit budget AFTER the "
                             "pack reserved it — excluding it", fail_slot,
                             n_sel);
            }
            excluded[sel[fail_slot]] = true;
            if (refill_ok && passes <= NODUS_CMT_APP_PREP_REFILL_MAX) {
                n_sel = app_prep_pack(ctx, req, order, n, class_arr,
                                      excluded, max_env_bytes, pu, sel,
                                      &env_total);
                continue;                    /* the freed room, refilled  */
            }
            for (k = (size_t)fail_slot; k + 1 < n_sel; k++) {
                sel[k] = sel[k + 1];
            }
            n_sel--;
            if (passes > NODUS_CMT_APP_PREP_REFILL_MAX && n_sel > 1) {
                n_sel = (n_sel + 1) / 2;     /* the geometric tail bound  */
            }
        }
    }

    /* ── the RESPONSE buffer: ctx-owned past this return, sized to the
     * KEPT count `n_sel`, never to prep_bound. ──────────────────────── */
    if (n_sel > 0) {
        new_prep_txs = (cmt_pb_bytes_t *)calloc(n_sel,
                                                sizeof(*new_prep_txs));
        if (!new_prep_txs) {
            rc_out = CMT_FAULT;
            goto done;
        }
        for (k = 0; k < n_sel; k++) {
            new_prep_txs[k] = req->txs[sel[k]];
        }
    }
    ctx->prep_txs     = new_prep_txs;   /* NULL when n_sel == 0, and that
                                         * is a valid empty response      */
    ctx->prep_txs_len = n_sel;
    ctx->prep_txs_cap = n_sel;
    resp->txs     = ctx->prep_txs;
    resp->txs_len = n_sel;
    rc_out = CMT_OK;

done:
    free(fee);
    free(class_arr);
    free(is_cc);
    free(order);
    free(excluded);
    free(sel);
    free(units);
    if (pu) {
        free(pu->view);
        free(pu->meter);
        free(pu);
    }
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ProcessProposal — state/execution.go:174-200
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_process_proposal(
        void *vctx, const nodus_abci_request_process_proposal_t *req,
        nodus_abci_response_process_proposal_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    size_t   i, n = 0;
    size_t  *order = NULL;
    int      rc;
    int      rc_out = CMT_FAULT;

    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    resp->status = NODUS_ABCI_PROPOSAL_STATUS_REJECT;

    /* A proposal is a PEER'S input: every refusal of it is a verdict
     * carried in `status`, never a return code — the host turns a
     * non-CMT_OK return into CMT_FAULT and stops the node
     * (nodus_witness_cmt_host.c:882-884). Umbrella rev 6's panic rule.
     *
     * ORCHESTRATOR delta 11 (R3-W3-C2a-19) — the engine's own per-block
     * ARRAY bound, checked FIRST and alone: the cheapest possible check
     * (one comparison against `req->txs_len`, nothing allocated, nothing
     * read from `req->txs`) and it must run before every other check so
     * a request a LATER check would otherwise spend work rejecting for
     * a different reason is still caught here. An honest proposer never
     * trips this: PrepareProposal (above) never returns more than
     * `NODUS_V2_APPLY_MAX_OPS` items, so this is coherent with it in the
     * sense abci++_methods.md requires ("PrepareProposal-ProcessProposal
     * coherence", consensus/state.go:1367-1376) — the liveness warning
     * at spec/abci/abci++_methods.md:463-464 ("applications SHOULD
     * always ACCEPT unless they really know the liveness implications
     * of REJECT") does not apply to a REJECT an honest round never
     * reaches. `ProcessProposalResponse.status == REJECT` is exactly
     * what turns into a nil prevote (abci++_methods.md:456-457, 488-490;
     * `defaultDoPrevote`, consensus/state.go:1377-1391 — `!isAppValid`
     * signs a nil vote instead of the proposal's block). */
    if (req->txs_len > NODUS_V2_APPLY_MAX_OPS) {
        QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu transactions exceed "
                     "the engine's per-block item bound %u — refused "
                     "before any per-item work", req->txs_len,
                     (unsigned)NODUS_V2_APPLY_MAX_OPS);
        return CMT_OK;                       /* status stays REJECT        */
    }

    /* ORCHESTRATOR delta 2, item A: env_bound, NOT prep_bound. delta 1
     * narrowed this to prep_bound because prep_class/prep_order/
     * seam_entry/seam_ptr were SHARED, fixed-size, ctx-owned arrays
     * sized to prep_bound for memory reasons. delta 2 makes every array
     * here per-request and local, so there is no fixed array left for a
     * 5 000-item narrowing to protect, and the reference imposes no such
     * rule on ProcessProposal — its only ceiling is the byte-derived
     * physical limit, the SAME one FinalizeBlock already uses. A count
     * above env_bound is therefore MALFORMED under this chain's own
     * consensus params (D-4 rev 3) and refused as a proposal verdict
     * (REJECT), before anything is allocated for it. */
    if (req->txs_len > ctx->env_bound) {
        QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu transactions exceed "
                     "env_bound %zu — malformed under this chain's own "
                     "consensus params", req->txs_len, ctx->env_bound);
        return CMT_OK;                       /* status stays REJECT        */
    }

    /* ── R3 W4 package C — PER-CLASS refusal, the same caps
     * PrepareProposal enforces above (an honest proposer never trips
     * this either, for the same coherence reason as the mixed cap). A
     * classify pass over `req->txs` — cheap (byte-prefix inspection,
     * one call per item), no allocation — run BEFORE the per-item
     * seam loop below so an over-count-by-class proposal is refused
     * without ever building `order[]` or touching committed state. */
    {
        size_t env_n = 0, claim_n = 0;
        size_t env_cap = ctx->env_bound < NODUS_V2_ENV_BATCH_MAX
                             ? ctx->env_bound
                             : NODUS_V2_ENV_BATCH_MAX;
        size_t claim_cap = ctx->claim_bound < NODUS_V2_APPLY_MAX_CLAIMS
                                ? ctx->claim_bound
                                : NODUS_V2_APPLY_MAX_CLAIMS;

        for (i = 0; i < req->txs_len; i++) {
            const cmt_pb_bytes_t *t = &req->txs[i];
            uint8_t cls;

            if (!t->data || t->len == 0) {
                continue;      /* the empty-item REJECT below catches it */
            }
            cls = nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len);
            if (cls == NODUS_W_TX_V2_ENVELOPE) {
                env_n++;
            } else if (cls == NODUS_W_TX_V2_CLAIM) {
                claim_n++;
            }
        }
        if (env_n > env_cap) {
            QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu envelopes exceed "
                         "the envelope batch cap %zu — refused before "
                         "any per-item work", env_n, env_cap);
            return CMT_OK;                   /* status stays REJECT       */
        }
        if (claim_n > claim_cap) {
            QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu claims exceed "
                         "this chain's claim capacity %zu — refused "
                         "before any per-item work", claim_n, claim_cap);
            return CMT_OK;                   /* status stays REJECT       */
        }
    }

    if (req->txs_len > 0) {
        order = (size_t *)calloc(req->txs_len, sizeof(*order));
        if (!order) {
            return CMT_FAULT;
        }
    }
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];

        if (!t->data || t->len == 0) {
            rc_out = CMT_OK;                 /* an empty item: REJECT      */
            goto done;
        }
        order[n++] = i;
    }
    rc = app_seam_check(ctx, req->txs, order, n, ctx->env_bound, NULL, NULL);
    if (rc == -2) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "ProcessProposal: the capacity seam faulted on this "
                      "node — no verdict about the proposal");
        rc_out = CMT_FAULT;
        goto done;
    }
    if (rc == 0) {
        resp->status = NODUS_ABCI_PROPOSAL_STATUS_ACCEPT;
    }
    rc_out = CMT_OK;

done:
    free(order);
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The vote-extension pair — abci/types/application.go:100-108
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_extend_vote(void *vctx,
                              const nodus_abci_request_extend_vote_t *req,
                              nodus_abci_response_extend_vote_t *resp)
{
    (void)req;
    if (!vctx || !resp) {
        return CMT_FAULT;
    }
    /* :100-102 — `&ResponseExtendVote{}`: an EMPTY extension. Vote
     * extensions are off (VoteExtensionsEnableHeight 0, D-4 rev 3 (2)),
     * so no committed block reaches this row. */
    memset(resp, 0, sizeof(*resp));
    return CMT_OK;
}

int nodus_cmt_app_verify_vote_extension(
        void *vctx, const nodus_abci_request_verify_vote_extension_t *req,
        nodus_abci_response_verify_vote_extension_t *resp)
{
    (void)req;
    if (!vctx || !resp) {
        return CMT_FAULT;
    }
    /* :104-108 — Status ACCEPT. */
    memset(resp, 0, sizeof(*resp));
    resp->status = NODUS_ABCI_VERIFY_STATUS_ACCEPT;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * FinalizeBlock — state/execution.go:255-289's callee: the ledger's
 * cometbft apply lane (D-23 rev 5 (6))
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_finalize_block(void *vctx,
                                 const nodus_abci_request_finalize_block_t *req,
                                 nodus_abci_response_finalize_block_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    nodus_v2_block_t       *blk = NULL;
    size_t i, n_env = 0, n_claim = 0;
    size_t claim_alloc;
    int    rc;
    int    rc_out = CMT_FAULT;

    /* ORCHESTRATOR delta 2, item A — every array below is LOCAL and
     * PER-REQUEST, sized to req->txs_len (fb_claim capped additionally
     * at claim_bound — see claim_alloc below), freed via goto-cleanup
     * before every return. Only `new_fb_pb` survives past this
     * function — it becomes `ctx->fb_pb`, the RESPONSE buffer the ABCI
     * ownership rule keeps valid until the NEXT call to this method. */
    uint8_t                        *class_arr = NULL;
    size_t                         *of_arr    = NULL;
    /* Nodus EVM red-team 1 F12 — of_arr's inverse for envelopes: the block
     * position of envelope slot k (blk->env_block_pos; node-local receipt
     * index data only) */
    size_t                         *env_pos_arr = NULL;
    nodus_v2_envelope_t            *env_arr   = NULL;
    dna_claim_t                    *claim_arr = NULL;
    nodus_v2_tx_result_t           *results_arr = NULL;
    cmt_pb_stored_exec_tx_result_t *new_fb_pb   = NULL;
    /* tokenomics-v3 P1 (D-2) — the decided_last_commit copy, LOCAL to
     * this call: `blk` (and therefore these arrays) is consumed
     * synchronously inside nodus_witness_v2_apply_block below, never
     * retained past this function's return — unlike fb_pb/prep_txs,
     * these need no ctx-owned lifetime. */
    uint8_t                       (*votes_addr_arr)[32] = NULL;
    int32_t                        *votes_flag_arr      = NULL;
    /* round 2 §A (D-1, G1) — the epoch-boundary ValidatorUpdates diff.
     * `vu_snap_new`/`vu_snap_old` are the two committed snapshots being
     * compared; `vu_scratch` is LOCAL per-request scratch (freed at
     * `done:` like class_arr/of_arr/etc above), sized to the tight
     * worst-case bound for THIS boundary (snap_new's count + snap_old's
     * count — never the compile-time CMT_VALSET_MAX_CHANGES), filled
     * in place and then handed straight to `ctx->val_updates` on
     * success — the same "no separate scratch+final copy" shape
     * `new_fb_pb`/`ctx->fb_pb` already use above, because here too the
     * final size is known before the array is filled. */
    dna_vset_snapshot_t             *vu_snap_new = NULL;
    dna_vset_snapshot_t             *vu_snap_old = NULL;
    cmt_pb_validator_update_t       *vu_scratch   = NULL;

    if (resp) {
        memset(resp, 0, sizeof(*resp));
    }
    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }

    /* delta 2 — THIS call is "the next call" the ABCI ownership rule
     * means for FinalizeBlock's own response: the PREVIOUS tx_results
     * buffer may now be freed. A FAULT return below stops the node
     * anyway (umbrella panic rule). */
    free(ctx->fb_pb);
    ctx->fb_pb     = NULL;
    ctx->fb_pb_cap = 0;
    /* round 2 §A — `val_updates` follows the identical rule: THIS call
     * is "the next call" for FinalizeBlock's SECOND response buffer too. */
    free(ctx->val_updates);
    ctx->val_updates     = NULL;
    ctx->val_updates_cap = 0;

    /* env_bound, not the retired NODUS_CMT_APP_MAX_TXS — the byte-derived
     * count no honestly-decided block (Block.MaxBytes, D-4 rev 3) can
     * physically exceed. A decided block is never refused with a
     * verdict, but this can only be reached by a physically-impossible
     * request given the chain's own consensus params — a node-local
     * configuration mismatch, not anyone's transaction's fault. */
    if (req->txs_len > ctx->env_bound) {
        QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock carries %zu transactions, "
                      "the byte-derived bound is %zu", req->txs_len,
                      ctx->env_bound);
        return CMT_FAULT;
    }
    /* ORCHESTRATOR delta 4, item A — `results_arr` is allocated on BOTH
     * branches, unconditionally, even when `req->txs_len == 0`: the
     * engine's own precondition (nodus_witness_v2_apply.c:2185-2191, NOT
     * this file's whitelist) refuses `blk->cmt.results == NULL`
     * BEFORE it ever looks at the count, so a NULL array stops the node
     * on the very first EMPTY decided block — and under D-4 rev 3 a
     * quiet chain produces one every `create_empty_blocks_interval`
     * (60 s), so this is not a corner case, it is the FIRST block a
     * quiet chain ever applies. `calloc(0, …)` is never relied on here —
     * its result is implementation-defined and this tree builds for
     * Windows/Android too — so the count passed to calloc is
     * `req->txs_len ? req->txs_len : 1` while `results_cap` (read at
     * :1169 below) stays the true `req->txs_len` (0 for an empty block):
     * the engine only ever reads `results[0..n_envs+n_claims)`, which is
     * the empty range when both are 0, so the one extra slot calloc'd
     * for the NULL-avoidance is never touched. */
    results_arr = (nodus_v2_tx_result_t *)
        calloc(req->txs_len ? req->txs_len : 1, sizeof(*results_arr));
    if (!results_arr) {
        rc_out = CMT_FAULT;
        goto done;
    }
    if (req->txs_len == 0) {
        /* An empty decided block: still applied (n_envs=n_claims=0 is
         * legal); `class_arr`/`of_arr`/`env_arr`/`claim_arr` stay NULL —
         * every loop below is bounded by `req->txs_len` (0), so none of
         * them is ever indexed. Only `results_arr` above needs the
         * NULL-avoidance, because the engine reads `blk->cmt.results`
         * itself before consulting the counts. */
    } else {
        /* delta 2: fb_claim capped at claim_bound (~2 972), NEVER at
         * req->txs_len (up to env_bound, ~293 525) — a claim's own
         * minimum wire size is two orders of magnitude larger than an
         * envelope's, so allocating dna_claim_t VALUES (~11.6 KB each)
         * at env_bound scale would be the multi-gigabyte mistake this
         * whole delta exists to avoid. The `n_claim >= claim_alloc`
         * guard below (unchanged logic from delta 1) still protects
         * against the physically-impossible case of MORE claims than
         * that within one request. */
        claim_alloc = (req->txs_len < ctx->claim_bound)
                          ? req->txs_len : ctx->claim_bound;

        class_arr   = (uint8_t *)calloc(req->txs_len, sizeof(*class_arr));
        of_arr      = (size_t *)calloc(req->txs_len, sizeof(*of_arr));
        env_pos_arr = (size_t *)calloc(req->txs_len, sizeof(*env_pos_arr));
        env_arr     = (nodus_v2_envelope_t *)calloc(req->txs_len,
                                                    sizeof(*env_arr));
        /* results_arr is already allocated above, unconditionally
         * (delta 4, item A) — not repeated here. */
        claim_arr   = claim_alloc
            ? (dna_claim_t *)calloc(claim_alloc, sizeof(*claim_arr))
            : NULL;
        if (!class_arr || !of_arr || !env_pos_arr || !env_arr ||
            (claim_alloc && !claim_arr)) {
            rc_out = CMT_FAULT;
            goto done;
        }
    }

    /* ── classify, and split the two item kinds out ──────────────────
     * D-23 rev 5 (6): "an item that does not even decode is a per-item
     * failure, not a block failure". The classification boundary is
     * here: bytes the ONE byte-driven authority
     * (`nodus_witness_v2_classify_entry`) calls an ENVELOPE go to the
     * engine's envelope list, bytes it calls a CLAIM are decoded and go
     * to its claim list, and a claim whose bytes do not decode is coded
     * here — the engine never sees it.
     *
     * The engine applies both kinds per item; the block never fails
     * because one of them did. */
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];

        class_arr[i] = (t->data && t->len)
            ? nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len)
            : (uint8_t)0;
        of_arr[i] = (size_t)-1;
        if (class_arr[i] == NODUS_W_TX_V2_ENVELOPE) {
            env_arr[n_env].env_bytes = t->data;
            env_arr[n_env].env_len   = t->len;
            env_pos_arr[n_env] = i;          /* its block position     */
            of_arr[i] = n_env;
            n_env++;
        } else if (class_arr[i] == NODUS_W_TX_V2_CLAIM) {
            /* claim_alloc (== MIN(req->txs_len, claim_bound)) is the
             * true physical ceiling for THIS request; reaching it is the
             * same class of node-local impossibility as the txs_len
             * guard above, NOT a peer's malformed bytes — treated
             * identically to a claim that does not decode (D-23 rev 5
             * (6): a per-item failure, not a block failure) so a decided
             * block is never refused a verdict here, and logged loudly
             * because it should never actually happen. */
            if (n_claim >= claim_alloc) {
                QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: claim count would "
                              "exceed this request's claim bound %zu at "
                              "block position %zu — coding this item as a "
                              "decode failure rather than overflowing "
                              "the claim array", claim_alloc, i);
            } else if (dna_claim_decode(t->data, t->len,
                                        &claim_arr[n_claim]) == 0) {
                of_arr[i] = n_claim;
                n_claim++;
            }
            /* a claim that does not decode (or would overflow the
             * derived bound above) keeps of_arr[i] == -1 and is coded
             * below; its bytes never reach the engine */
        }
    }

    /* ── the engine, ONCE, inside the host's transaction ─────────── */
    blk = (nodus_v2_block_t *)calloc(1, sizeof(*blk));
    if (!blk) {
        rc_out = CMT_FAULT;
        goto done;
    }
    blk->global_height = (uint64_t)req->height;
    blk->epoch = nodus_v2_epoch_for_height(blk->global_height);
    memcpy(blk->proposer_id, req->proposer_address,
           req->proposer_address_len > 32 ? 32 : req->proposer_address_len);
    /* `timestamp` is informational in the engine and enters no identity
     * (nodus_v2_block_t's contract); the block's real time is the Comet
     * header's, which consensus owns. */
    blk->timestamp = (uint64_t)req->time.seconds;
    blk->envs = n_env ? env_arr : NULL;
    blk->n_envs = n_env;
    blk->env_block_pos = n_env ? env_pos_arr : NULL;
    blk->claims = n_claim ? claim_arr : NULL;
    blk->n_claims = n_claim;
    blk->cmt.on = true;
    memcpy(blk->cmt.block_hash, req->hash,
           req->hash_len > 64 ? 64 : req->hash_len);
    /* `v2_blocks.vset_hash` receives the request's NEXT-validators hash
     * — the only validator hash `RequestFinalizeBlock` carries
     * (execution.go:257). D-17 rev 7 (6) calls the column "the block's
     * ValidatorsHash"; the two coincide only while validator updates are
     * empty. REGISTER ROW R3-C1a-10, stated in full at
     * nodus_v2_block_cmt_t.validators_hash. */
    memcpy(blk->cmt.validators_hash, req->next_validators_hash,
           req->next_validators_hash_len > 64
               ? 64 : req->next_validators_hash_len);
    blk->cmt.results = results_arr;
    /* delta 2: results_arr is sized to req->txs_len itself (this
     * request's own true worst case for n_env + n_claim), not to
     * env_bound — the per-request array already IS the tight bound. */
    blk->cmt.results_cap = req->txs_len;

    /* tokenomics-v3 P1 (D-2) — decided_last_commit, copied VERBATIM into
     * two per-request LOCAL arrays (freed at `done:` below, never
     * ctx-owned: nodus_witness_v2_apply_block consumes them
     * synchronously, before this function returns). `votes_len == 0`
     * (the initial height, execution.go:482-486) leaves both NULL/0 —
     * the legal empty case nodus_witness_v2_attendance_credit already
     * documents. */
    if (req->decided_last_commit.votes_len > 0) {
        size_t nv = req->decided_last_commit.votes_len;
        votes_addr_arr = (uint8_t (*)[32])calloc(nv, sizeof(*votes_addr_arr));
        votes_flag_arr = (int32_t *)calloc(nv, sizeof(*votes_flag_arr));
        if (!votes_addr_arr || !votes_flag_arr) {
            rc_out = CMT_FAULT;
            goto done;
        }
        for (size_t vi = 0; vi < nv; vi++) {
            const nodus_abci_vote_info_t *v =
                &req->decided_last_commit.votes[vi];
            /* address_len is a REQUEST field, not a compile-time
             * guarantee — tm2pb_validator always writes exactly 32
             * (nodus_witness_cmt_host.c:173), but this function must not
             * trust a comment about a caller it does not control. Any
             * other length is a node-local contract break: CMT_FAULT,
             * never a skip (the same class as the n_votes>0/height==0
             * guard in the attendance writer). */
            if (v->validator.address_len != 32) {
                QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: decided_last_commit "
                              "vote %zu carries address_len %zu, not 32",
                              vi, v->validator.address_len);
                rc_out = CMT_FAULT;
                goto done;
            }
            memcpy(votes_addr_arr[vi], v->validator.address, 32);
            votes_flag_arr[vi] = v->block_id_flag;
        }
    }
    blk->cmt.votes_address        = votes_addr_arr;
    blk->cmt.votes_block_id_flag  = votes_flag_arr;
    blk->cmt.votes_len            = req->decided_last_commit.votes_len;

    blk->fail_at = ctx->test_fail_at;    /* TEST-ONLY; 0 = no injection */
    blk->fail_env_index    = ctx->test_fail_env_index;
    blk->fail_effect_index = ctx->test_fail_effect_index;

    rc = nodus_witness_v2_apply_block(ctx->w, blk);
    if (rc != 0) {
        /* The lane's rule: a decided block is never refused, so the only
         * negative the engine can return here is a node-local fault and
         * the host must roll back and stop. The engine's own reason is
         * logged because it names the check that failed.
         *
         * ORCHESTRATOR delta 11 (R3-W3-C2a-19; R3-W4 package C moved the
         * per-block scratch this bound protects to the heap, sized by
         * the block's own counts, and added the per-CLASS caps below it):
         * the engine's own per-block ARRAY bound (`nodus_witness_v2_
         * apply.c`'s FAULT naming `MAX_OPS`) is the LAST line of defence,
         * never the first — an honest proposer/validator pair never
         * reaches it, because `nodus_cmt_app_prepare_proposal` (above)
         * never packs more than `NODUS_V2_ENV_BATCH_MAX` envelopes or
         * `min(ctx->claim_bound, NODUS_V2_APPLY_MAX_CLAIMS)` claims (and,
         * defense-in-depth, never more than `NODUS_V2_APPLY_MAX_OPS`
         * items total) and `nodus_cmt_app_process_proposal` (above)
         * REJECTs any proposal that carries more of either class before
         * doing any per-item work. A decided
         * block reaching this FAULT with more than that bound means
         * both of those gates were bypassed — +2/3 of the validators
         * decided a block no honest node running this application could
         * have proposed or accepted, the reference's "byzantine +2/3
         * committed an invalid block" class (umbrella panic rule,
         * atlas-dec-d5e766defde138eb6dd02e5b81e735a8, rev 6 in this
         * tree — the dispatch that named this delta cited "umbrella rev
         * 4"; this tree's own governing record is rev 6, cited as read,
         * not the dispatch's number) — this node stopping is correct. */
        QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: the ledger could not apply "
                      "the decided block at height %" PRId64 " (rc %d): %s",
                      req->height, rc, blk->out_reason);
        rc_out = CMT_FAULT;
        goto done;
    }

    /* ── the RESPONSE buffer: ctx-owned past this return, sized to
     * req->txs_len (one result per block position), never to env_bound. */
    /* Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
     * rev 3 §7): the same allocation carries, after the txs_len results,
     * txs_len × 64 bytes of RESPONSE-OWNED storage for ExecTxResult.Data
     * — an applied EVM leg's receipt digest is copied there, never
     * pointed at in the engine's results array (which is engine scratch).
     * calloc(n, S + 64) = n·S + n·64 bytes, overflow-checked by calloc;
     * it is freed with fb_pb, so no new ownership exists. Items without
     * Data never touch it. */
    if (req->txs_len > 0) {
        new_fb_pb = (cmt_pb_stored_exec_tx_result_t *)
            calloc(req->txs_len, sizeof(*new_fb_pb) + 64u);
        if (!new_fb_pb) {
            rc_out = CMT_FAULT;
            goto done;
        }
    }

    /* ── one ExecTxResult per item, in BLOCK ORDER ─────────────────
     * The engine's results are envelopes first then claims, each in its
     * own order; `of_arr` maps a block position back to its slot in
     * whichever list it went to. */
    for (i = 0; i < req->txs_len; i++) {
        cmt_pb_stored_exec_tx_result_t *r = &new_fb_pb[i];
        const nodus_v2_tx_result_t     *e = NULL;

        memset(r, 0, sizeof(*r));
        if (of_arr[i] != (size_t)-1) {
            if (class_arr[i] == NODUS_W_TX_V2_ENVELOPE) {
                e = &blk->cmt.results[of_arr[i]];
            } else {
                e = &blk->cmt.results[n_env + of_arr[i]];
            }
        }
        if (e) {
            r->det.code       = e->code;
            r->det.gas_wanted = (int64_t)e->gas_wanted;
            r->det.gas_used   = (int64_t)e->gas_used;
            /* Nodus EVM §7: an applied EVM leg's receipt digest, COPIED into
             * the response-owned tail (block position i). data_len 0 —
             * every non-EVM and every refused item — leaves `data`
             * empty, which is not marshalled: those results, and the
             * LastResultsHash of a block without an EVM leg, are
             * byte-identical to before. */
            if (e->data_len == 64) {
                uint8_t *tail = (uint8_t *)(new_fb_pb + req->txs_len) +
                                (size_t)i * 64u;
                memcpy(tail, e->data, 64);
                r->det.data.data = tail;
                r->det.data.len  = 64;
            } else if (e->data_len != 0) {
                free(new_fb_pb);         /* not yet handed to ctx      */
                rc_out = CMT_FAULT;      /* engine contract: 0 or 64 */
                goto done;
            }
        } else {
            /* bytes the engine never saw: a claim that does not decode,
             * or an empty item. The classification boundary's own code
             * (D-23 rev 5 (6)). */
            r->det.code = NODUS_V2_TX_ERR_DECODE;
        }
        /* `data` stays EMPTY — one of the two values D-23 rev 4 allows.
         * The engine retains no per-item effect bytes (apply.h's
         * nodus_v2_tx_result_t says why), so producing them would mean
         * changing exec_one_env's contract. Reported as a gap. */
    }
    ctx->fb_pb     = new_fb_pb;
    ctx->fb_pb_cap = req->txs_len;
    resp->tx_results = ctx->fb_pb;
    resp->tx_results_cap = req->txs_len;   /* delta 2: per-request */
    resp->tx_results_len = req->txs_len;

    /* app_hash = the ledger's global state root AFTER this block
     * (D-23 rev 4 (3)); consensus binds it as the NEXT header's AppHash
     * (D-19 rev 6 (1)). */
    memcpy(resp->app_hash, blk->out_global_root, 64);
    resp->app_hash_len = 64;

    /* ── tokenomics-v3 P1 §A (D-1, G1), round 2 — the epoch-boundary
     * ValidatorUpdates diff, now UNBLOCKED (ctx->val_updates,
     * nodus_witness_cmt_app.h). Non-boundary height: NULL/0, the legal
     * "leave the set" response (replay.go:346-360). At a boundary height
     * H (H % DNAC_EPOCH_LENGTH == 0, H > 0), diff the committed authority
     * for epoch H (the set that TAKES EFFECT at H, frozen at H-E by
     * nodus_witness_vset_commit_next) against the committed authority
     * for epoch H-E (what cometbft holds NOW, by induction — InitChain
     * above checked snapshot(0); every earlier boundary announced its
     * own snap_new, which became the next boundary's snap_old). Either
     * snapshot ABSENT (resolver rc 1) or UNREADABLE (rc -1) is
     * CMT_FAULT, never an empty list — an empty list here would tell
     * cometbft "nothing changed" when the true answer is "unknown". */
    resp->validator_updates = NULL;
    resp->validator_updates_len = 0;
    {
        uint64_t H = blk->global_height;

        if (H > 0 && (H % (uint64_t)DNAC_EPOCH_LENGTH) == 0) {
            int    arc_new, arc_old;
            size_t vu_bound = 0, n_updates = 0;
            size_t n_added = 0, n_power_changed = 0, n_removed = 0;
            size_t jn, jo;
            int    fault = 0;

            arc_new = nodus_witness_v2_epoch_authority_for_epoch(
                ctx->w, H, &vu_snap_new, NULL, NULL);
            arc_old = nodus_witness_v2_epoch_authority_for_epoch(
                ctx->w, H - (uint64_t)DNAC_EPOCH_LENGTH, &vu_snap_old,
                NULL, NULL);
            if (arc_new != 0 || arc_old != 0) {
                QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: epoch boundary "
                              "height %" PRIu64 " — validator-set "
                              "snapshot absent or unreadable (new rc=%d, "
                              "old rc=%d)", H, arc_new, arc_old);
                dna_vset_free(&vu_snap_new);
                dna_vset_free(&vu_snap_old);
                rc_out = CMT_FAULT;
                goto done;
            }

            /* Tight worst-case bound for THIS boundary: every new-side
             * entry could be an addition/power-change, every old-side
             * entry could be a removal. Both counts are individually
             * bounded by DNA_MAX_ACTIVE_VALIDATORS == CMT_VALSET_MAX
             * (vset_wire.h / cmt_validator_set.h), so the sum can never
             * itself exceed CMT_VALSET_MAX_CHANGES — sized to THIS
             * boundary, never to the compile-time ceiling. */
            vu_bound = (size_t)vu_snap_new->active_count +
                       (size_t)vu_snap_old->active_count;
            if (vu_bound > 0) {
                vu_scratch = (cmt_pb_validator_update_t *)
                    calloc(vu_bound, sizeof(*vu_scratch));
                if (!vu_scratch) {
                    dna_vset_free(&vu_snap_new);
                    dna_vset_free(&vu_snap_old);
                    rc_out = CMT_FAULT;
                    goto done;
                }
            }

            /* additions / power changes, in snap_new's OWN order */
            for (jn = 0; jn < (size_t)vu_snap_new->active_count && !fault;
                 jn++) {
                const dna_vset_entry_t *en = &vu_snap_new->entries[jn];
                uint64_t power = en->total_stake / DNAC_DECIMAL_UNIT;
                uint64_t old_power = 0;
                int      found = 0;

                for (jo = 0; jo < (size_t)vu_snap_old->active_count;
                     jo++) {
                    if (memcmp(en->pubkey, vu_snap_old->entries[jo].pubkey,
                               DNA_VSET_PUBKEY_LEN) == 0) {
                        found = 1;
                        old_power = vu_snap_old->entries[jo].total_stake /
                                    DNAC_DECIMAL_UNIT;
                        break;
                    }
                }
                if (power == 0) {
                    /* Invariant, unreachable at self-stake >= 10M — a
                     * genesis/join gate already refuses this. Checked
                     * here anyway because this row must never emit a
                     * ValidatorUpdate the reference itself would refuse
                     * (crypto/encoding/codec.go: power <= 0 is invalid). */
                    QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: boundary %"
                                  PRIu64 " — new-snapshot entry %zu "
                                  "computes power 0", H, jn);
                    fault = 1;
                    break;
                }
                if (!found || old_power != power) {
                    if (n_updates >= vu_bound) { fault = 1; break; }
                    vu_scratch[n_updates].pub_key.present = true;
                    memcpy(vu_scratch[n_updates].pub_key.key, en->pubkey,
                           DNA_VSET_PUBKEY_LEN);
                    vu_scratch[n_updates].power = (int64_t)power;
                    n_updates++;
                    if (found) n_power_changed++; else n_added++;
                }
            }
            /* removals, in snap_old's OWN order */
            for (jo = 0; jo < (size_t)vu_snap_old->active_count && !fault;
                 jo++) {
                const dna_vset_entry_t *eo = &vu_snap_old->entries[jo];
                int found = 0;

                for (jn = 0; jn < (size_t)vu_snap_new->active_count;
                     jn++) {
                    if (memcmp(eo->pubkey, vu_snap_new->entries[jn].pubkey,
                               DNA_VSET_PUBKEY_LEN) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    if (n_updates >= vu_bound) { fault = 1; break; }
                    vu_scratch[n_updates].pub_key.present = true;
                    memcpy(vu_scratch[n_updates].pub_key.key, eo->pubkey,
                           DNA_VSET_PUBKEY_LEN);
                    vu_scratch[n_updates].power = 0;
                    n_updates++;
                    n_removed++;
                }
            }
            /* Defense-in-depth: n_updates cannot exceed
             * CMT_VALSET_MAX_CHANGES given the per-snapshot bound above,
             * but this row refuses rather than emit an over-sized
             * ValidatorUpdates list if that invariant is ever broken
             * elsewhere. */
            if (!fault && n_updates > (size_t)CMT_VALSET_MAX_CHANGES) {
                fault = 1;
            }

            if (fault) {
                QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: boundary %"
                              PRIu64 " — validator update computation "
                              "refused (bound %zu, CMT_VALSET_MAX_CHANGES "
                              "%d)", H, vu_bound, CMT_VALSET_MAX_CHANGES);
                free(vu_scratch);
                vu_scratch = NULL;
                dna_vset_free(&vu_snap_new);
                dna_vset_free(&vu_snap_old);
                rc_out = CMT_FAULT;
                goto done;
            }

            /* ONE INFO line per boundary, also when all three are 0 —
             * a quiet boundary is still a boundary the operator should
             * be able to see happened. */
            QGP_LOG_INFO(LOG_TAG, "FinalizeBlock: epoch boundary height "
                         "%" PRIu64 " — validator_updates n_added=%zu "
                         "n_power_changed=%zu n_removed=%zu", H, n_added,
                         n_power_changed, n_removed);

            if (n_updates > 0) {
                ctx->val_updates     = vu_scratch;
                ctx->val_updates_cap = vu_bound;
                vu_scratch = NULL;    /* ownership transferred to ctx */
                resp->validator_updates = ctx->val_updates;
                resp->validator_updates_len = n_updates;
            } else {
                /* quiet boundary: unchanged members are not re-announced
                 * (`resp->validator_updates` stays NULL/0, set above). */
                free(vu_scratch);
                vu_scratch = NULL;
            }
            dna_vset_free(&vu_snap_new);
            dna_vset_free(&vu_snap_old);
        }
    }
    resp->has_consensus_param_updates = false;   /* none, D-23 rev 4 (3) */
    resp->events_len = 0;                        /* no events (YOK)      */

    /* The height the NEXT Commit commits — its retain_height input
     * (nodus_cmt_app_commit). Node-local; no response byte. */
    ctx->fb_height = req->height;
    rc_out = CMT_OK;

done:
    free(blk);
    free(class_arr);
    free(of_arr);
    free(env_pos_arr);
    free(env_arr);
    free(claim_arr);
    free(results_arr);
    free(votes_addr_arr);
    free(votes_flag_arr);
    /* round 2 §A — every path above that reaches `done:` has already
     * either freed these explicitly or (on success) NULLed `vu_scratch`
     * after transferring it to `ctx->val_updates`; unconditionally safe
     * here too (dna_vset_free/free are both NULL-safe), matching this
     * function's existing exhaustive style. */
    free(vu_scratch);
    dna_vset_free(&vu_snap_new);
    dna_vset_free(&vu_snap_old);
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Commit — the COMMIT of the host's ONE transaction, D-23 rev 5 (5)
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_commit(void *vctx, nodus_abci_response_commit_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    char *err = NULL;

    if (!ctx || !ctx->w || !ctx->w->db || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    /* The host opened the transaction before FinalizeBlock. Being outside
     * one here means the bracket was never opened or was already closed —
     * a node-local invariant broken, never a peer's doing: CMT_FAULT. */
    if (sqlite3_get_autocommit(ctx->w->db)) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "Commit called outside the host's transaction");
        return CMT_FAULT;
    }
    if (sqlite3_exec(ctx->w->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "COMMIT failed: %s", err ? err : "?");
        sqlite3_free(err);
        return CMT_FAULT;
    }
    /* CHECKTX-P1 — the committed state just moved, so every pending
     * conflict key is stale: clear the set here, AFTER the COMMIT, and
     * let the mempool's recheck repopulate it in FIFO order — the host
     * calls this row and only then `mempool->update`, whose recheck
     * re-runs CheckTx over every remaining entry
     * (nodus_witness_cmt_host.c `blockexec_commit`; cmt_mem.c
     * `mem_recheck_txs`). The auth cache advances one generation. */
    pend_clear(ctx);
    acache_sweep(ctx);
    /* Node-local block retention (decision 2026-10-03-block-pruning-7-
     * paydays.md): with `retain_blocks` N > 0 the block executor's
     * `pruneBlocks` (execution.go:340-347; nodus_witness_cmt_host.c
     * `nodus_cmt_blockexec_prune_blocks`) keeps the last N blocks; with 0
     * (archive) it is not entered. A pure function of the committed
     * height and this node's setting — no clock, no consensus byte. */
    resp->retain_height = nodus_cmt_app_retain_height(
        ctx->fb_height, ctx->w->config.retain_blocks);
    return CMT_OK;
}

int64_t nodus_cmt_app_retain_height(int64_t height, int64_t retain_blocks)
{
    /* `PruneBlocks(R)` deletes [base, R) and sets base = R
     * (nodus_witness_cmt_store.c `nodus_cmt_bs_prune_blocks`, store.go
     * :377, :435), so [R, height] = height − R + 1 blocks remain. For
     * exactly `retain_blocks` of them R = height − retain_blocks + 1.
     * At height ≤ retain_blocks there is nothing to drop: 0. */
    if (retain_blocks <= 0 || height <= retain_blocks) {
        return 0;
    }
    return height - retain_blocks + 1;
}
