/**
 * @file nodus_witness_v2_migrate.c
 * @brief HF-6 sub-slice 3b — the one-shot generation-4 validator
 *        migration. Contract: nodus_witness_v2_migrate.h.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §7 steps 1-4, 6, 10 (+ §4: the consensus-key reservations, slice 4);
 * plan tasks/hf6-slice3-plan.md §2 "3b" steps 1-3;
 * decisions docs/plans/decisions/2026-10-08-kurultay-14-hf6-summary.md
 * (K4 accrual merge, K8 Foundation address) and
 * docs/plans/decisions/2026-10-09-kurultay-16-hf6-storage-summary.md (D2:
 * the Foundation rows are exactly active_since_block <= 1).
 *
 * Every failure is -2, a NODE fault: the edge is a phase of a decided
 * block, never a verdict about it (the 6b'' precedent).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_migrate.h"
#include "witness/nodus_witness_validator.h" /* slice 4: key reservation */

#include "nodus/nodus_types.h"         /* NODUS_TREE_TAG_VALIDATOR / _DELEGATION */
#include "dnac/dnac.h"                 /* DNAC_SELF_STAKE_AMOUNT,
                                        * DNAC_HF6_STAKE_MIN_DEFAULT        */
#include "dnac/validator.h"            /* dnac_validator_status_t           */
#include "dnac/valbind_wire.h"         /* dna_validator_id_migrated         */
#include "dnac/res_meter.h"            /* dna_ck_add_u64                    */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2MIGRATE"

#define MG_KEY   64u
#define MG_PK    DNAC_PUBKEY_SIZE
#define MG_I64   ((uint64_t)INT64_MAX)

_Static_assert(DNA_VALBIND_ID_LEN == MG_KEY, "validator_id is 64 bytes");
_Static_assert(DNA_VALBIND_PUBKEY_LEN == DNAC_PUBKEY_SIZE,
               "the consent / validator_id pubkey is the stored pubkey");
_Static_assert(DNAC_HF6_STAKE_MIN_DEFAULT < DNAC_SELF_STAKE_AMOUNT,
               "the split leaves a non-zero self-delegation");

/* (10M − 2M): the self-delegation every bonded row receives */
#define MG_SELF_DELEG  (DNAC_SELF_STAKE_AMOUNT - DNAC_HF6_STAKE_MIN_DEFAULT)

/* ── in-memory rows ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t  old_key[MG_KEY];  /* SHA3-512(0x02 ‖ pk), the stored key   */
    uint8_t  fp[MG_KEY];       /* SHA3-512(pk), untagged                */
    uint8_t  vid[MG_KEY];      /* dna_validator_id_migrated(chain32, pk) */
    uint8_t  owner[MG_KEY];
    uint8_t *pk;               /* MG_PK bytes, owned                    */
    int      foundation;       /* active_since_block <= 1 (D2 (a))      */
    int      bonded;           /* ACTIVE or ELIGIBLE                    */
    int      unstaked;         /* UNSTAKED: graduated, no reservation   */
    uint64_t self_stake, total_delegated, external_delegated;  /* to write */
    uint64_t read_self_stake, read_total_delegated;            /* as read  */
} mg_val_t;

typedef struct {
    uint8_t  dfp[MG_KEY];      /* new delegator_hash                    */
    uint8_t  vid[MG_KEY];      /* new validator_hash                    */
    uint8_t *dpk;              /* MG_PK bytes, owned                    */
    uint8_t *vpk;              /* MG_PK bytes, owned                    */
    uint64_t amount, at;
} mg_del_t;

typedef struct {
    uint64_t epoch;
    uint8_t  vfp[MG_KEY];
    uint8_t  ofp[MG_KEY];
    uint8_t  kind;
    uint64_t amount;
} mg_copy_t;

typedef struct {
    uint8_t fp[MG_KEY];
    size_t  idx;               /* into mg_t.v                           */
} mg_fpidx_t;

typedef struct {
    mg_val_t   *v;   size_t nv;
    mg_del_t   *d;   size_t nd, cd, nd_old;
    mg_copy_t  *c;   size_t nc, cc;
    mg_fpidx_t *by_fp;         /* nv entries, sorted by fp              */
} mg_t;

static void mg_free(mg_t *m) {
    for (size_t i = 0; i < m->nv; i++) free(m->v[i].pk);
    for (size_t i = 0; i < m->nd; i++) {
        free(m->d[i].dpk);
        free(m->d[i].vpk);
    }
    free(m->v);
    free(m->d);
    free(m->c);
    free(m->by_fp);
    memset(m, 0, sizeof(*m));
}

static int mg_tag_key(uint8_t tag, const uint8_t *pk, uint8_t out[MG_KEY]) {
    uint8_t *pre = malloc(1u + MG_PK);
    if (!pre) return -1;
    pre[0] = tag;
    memcpy(pre + 1, pk, MG_PK);
    int rc = qgp_sha3_512(pre, 1u + MG_PK, out) == 0 ? 0 : -1;
    free(pre);
    return rc;
}

static int mg_is_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* a stored INTEGER as a uint64 in [0, INT64_MAX]; else -1 */
static int mg_col_u64(sqlite3_stmt *st, int col, uint64_t *out) {
    if (sqlite3_column_type(st, col) != SQLITE_INTEGER) return -1;
    sqlite3_int64 v = sqlite3_column_int64(st, col);
    if (v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* a stored BLOB of exactly `len` bytes; NULL otherwise */
static const uint8_t *mg_col_blob(sqlite3_stmt *st, int col, size_t len) {
    if (sqlite3_column_type(st, col) != SQLITE_BLOB) return NULL;
    if ((size_t)sqlite3_column_bytes(st, col) != len) return NULL;
    return (const uint8_t *)sqlite3_column_blob(st, col);
}

static int mg_add(uint64_t a, uint64_t b, uint64_t *out) {
    uint64_t s = 0;
    if (dna_ck_add_u64(a, b, &s) != 0 || s > MG_I64) return -1;
    *out = s;
    return 0;
}

/* ── lookups (both arrays sorted, keys unique — a total order) ─────── */

/* the validators row whose pubkey is `pk` (v is pubkey ASC) */
static const mg_val_t *mg_val_by_pk(const mg_t *m, const uint8_t *pk) {
    size_t lo = 0, hi = m->nv;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(m->v[mid].pk, pk, MG_PK);
        if (c == 0) return &m->v[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static int mg_cmp_fpidx(const void *a, const void *b) {
    return memcmp(((const mg_fpidx_t *)a)->fp, ((const mg_fpidx_t *)b)->fp,
                  MG_KEY);
}

/* the validators row whose SHA3-512(pk) is `fp` */
static const mg_val_t *mg_val_by_fp(const mg_t *m, const uint8_t *fp) {
    size_t lo = 0, hi = m->nv;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(m->by_fp[mid].fp, fp, MG_KEY);
        if (c == 0) return &m->v[m->by_fp[mid].idx];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* new delegation PK order: (validator_hash, delegator_hash) ASC — the
 * order the gen-4 readers walk (design §6.4) */
static int mg_cmp_del(const void *a, const void *b) {
    const mg_del_t *x = a, *y = b;
    int c = memcmp(x->vid, y->vid, MG_KEY);
    return c ? c : memcmp(x->dfp, y->dfp, MG_KEY);
}

/* new copy PK order: (epoch_start, validator_fp, owner_fp, kind) ASC */
static int mg_cmp_copy(const void *a, const void *b) {
    const mg_copy_t *x = a, *y = b;
    if (x->epoch != y->epoch) return x->epoch < y->epoch ? -1 : 1;
    int c = memcmp(x->vfp, y->vfp, MG_KEY);
    if (c) return c;
    c = memcmp(x->ofp, y->ofp, MG_KEY);
    if (c) return c;
    return (x->kind > y->kind) - (x->kind < y->kind);
}

static int mg_del_push(mg_t *m) {
    if (m->nd == m->cd) {
        size_t nc = m->cd ? m->cd * 2 : 32;
        mg_del_t *nr = realloc(m->d, nc * sizeof(*nr));
        if (!nr) return -1;
        m->d = nr;
        m->cd = nc;
    }
    memset(&m->d[m->nd], 0, sizeof(m->d[0]));
    m->d[m->nd].dpk = malloc(MG_PK);
    m->d[m->nd].vpk = malloc(MG_PK);
    if (!m->d[m->nd].dpk || !m->d[m->nd].vpk) {
        free(m->d[m->nd].dpk);
        free(m->d[m->nd].vpk);
        return -1;
    }
    m->nd++;
    return 0;
}

/* ── READ 1: validators, pubkey ASC ─────────────────────────────────── */

static int mg_read_validators(nodus_witness_t *w, mg_t *m,
                              const uint8_t chain32[32],
                              const uint8_t foundation_fp[MG_KEY]) {
    sqlite3_stmt *st = NULL;
    size_t cap = 0;
    int rc;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey_hash, pubkey, self_stake, total_delegated, "
            "external_delegated, status, active_since_block "
            "FROM validators ORDER BY pubkey ASC", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "validators prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *key = mg_col_blob(st, 0, MG_KEY);
        const uint8_t *pk = mg_col_blob(st, 1, MG_PK);
        uint64_t status = 0, since = 0;
        mg_val_t v;
        memset(&v, 0, sizeof(v));
        if (!key || !pk ||
            mg_col_u64(st, 2, &v.self_stake) != 0 ||
            mg_col_u64(st, 3, &v.total_delegated) != 0 ||
            mg_col_u64(st, 4, &v.external_delegated) != 0 ||
            mg_col_u64(st, 5, &status) != 0 ||
            mg_col_u64(st, 6, &since) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a malformed validators row "
                          "(key / pubkey length or an amount outside "
                          "[0, INT64_MAX])");
            goto fail;
        }
        if (status != DNAC_VALIDATOR_ACTIVE &&
            status != DNAC_VALIDATOR_RETIRING &&
            status != DNAC_VALIDATOR_UNSTAKED &&
            status != DNAC_VALIDATOR_AUTO_RETIRED &&
            status != DNAC_VALIDATOR_ELIGIBLE) {
            QGP_LOG_ERROR(LOG_TAG, "a validators row with status %llu",
                          (unsigned long long)status);
            goto fail;
        }
        if (mg_tag_key(NODUS_TREE_TAG_VALIDATOR, pk, v.old_key) != 0 ||
            qgp_sha3_512(pk, MG_PK, v.fp) != 0 ||
            dna_validator_id_migrated(v.vid, chain32, pk) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "hash backend failure while "
                          "deriving a validator's keys");
            goto fail;
        }
        if (memcmp(v.old_key, key, MG_KEY) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a validators row whose key is not "
                          "SHA3-512(0x02 || pubkey) — already migrated or "
                          "corrupt; refusing to migrate it twice");
            goto fail;
        }
        v.read_self_stake = v.self_stake;
        v.read_total_delegated = v.total_delegated;
        v.foundation = (since <= 1u);
        memcpy(v.owner, v.foundation ? foundation_fp : v.fp, MG_KEY);
        v.bonded = (status == DNAC_VALIDATOR_ACTIVE ||
                    status == DNAC_VALIDATOR_ELIGIBLE);
        v.unstaked = (status == DNAC_VALIDATOR_UNSTAKED);
        if (v.bonded) {
            /* design §7.2: 10M → 2M bond + 8M self-delegation; the exact
             * 10M is what every STAKE and the genesis wrote
             * (rt_native.c rtn_stake_exec, v2_gen.c Rule P.1) */
            if (v.self_stake != DNAC_SELF_STAKE_AMOUNT) {
                QGP_LOG_ERROR(LOG_TAG, "a bonded validators row holds "
                              "self_stake %llu, not DNAC_SELF_STAKE_AMOUNT "
                              "%llu", (unsigned long long)v.self_stake,
                              (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
                goto fail;
            }
            v.self_stake = DNAC_HF6_STAKE_MIN_DEFAULT;
            if (mg_add(v.total_delegated, MG_SELF_DELEG,
                       &v.total_delegated) != 0 ||
                mg_add(v.external_delegated, MG_SELF_DELEG,
                       &v.external_delegated) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a bonded row's delegated "
                              "totals overflow INT64 with the "
                              "self-delegation");
                goto fail;
            }
        }
        if (m->nv == cap) {
            size_t nc = cap ? cap * 2 : 16;
            mg_val_t *nr = realloc(m->v, nc * sizeof(*nr));
            if (!nr) goto oom;
            m->v = nr;
            cap = nc;
        }
        v.pk = malloc(MG_PK);
        if (!v.pk) goto oom;
        memcpy(v.pk, pk, MG_PK);
        m->v[m->nv++] = v;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "validators scan failed (rc=%d)", rc);
        return -1;
    }
    /* pubkey ASC with unique keys: equal pubkeys would share a tagged
     * key (the PRIMARY KEY), so this holds on every committed table;
     * checked, because the lookups below depend on it */
    for (size_t i = 1; i < m->nv; i++)
        if (memcmp(m->v[i - 1].pk, m->v[i].pk, MG_PK) >= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "validators pubkeys are not "
                          "strictly ascending");
            return -1;
        }
    if (m->nv) {
        m->by_fp = malloc(m->nv * sizeof(*m->by_fp));
        if (!m->by_fp) return -1;
        for (size_t i = 0; i < m->nv; i++) {
            memcpy(m->by_fp[i].fp, m->v[i].fp, MG_KEY);
            m->by_fp[i].idx = i;
        }
        qsort(m->by_fp, m->nv, sizeof(*m->by_fp), mg_cmp_fpidx);
        for (size_t i = 1; i < m->nv; i++)
            if (memcmp(m->by_fp[i - 1].fp, m->by_fp[i].fp, MG_KEY) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "two validators share "
                              "SHA3-512(pubkey)");
                return -1;
            }
    }
    return 0;
oom:
    QGP_LOG_ERROR(LOG_TAG, "%s", "allocation failed reading validators");
fail:
    sqlite3_finalize(st);
    return -1;
}

/* ── READ 2: delegations, primary-key order; re-keyed on the way in ── */

static int mg_read_delegations(nodus_witness_t *w, mg_t *m) {
    sqlite3_stmt *st = NULL;
    int rc;
    if (sqlite3_prepare_v2(w->db,
            "SELECT delegator_hash, validator_hash, delegator_pubkey, "
            "validator_pubkey, amount, delegated_at_block "
            "FROM delegations ORDER BY delegator_hash ASC, "
            "validator_hash ASC", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delegations prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *dh = mg_col_blob(st, 0, MG_KEY);
        const uint8_t *vh = mg_col_blob(st, 1, MG_KEY);
        const uint8_t *dpk = mg_col_blob(st, 2, MG_PK);
        const uint8_t *vpk = mg_col_blob(st, 3, MG_PK);
        uint64_t amount = 0, at = 0;
        uint8_t kd[MG_KEY], kv[MG_KEY];
        if (!dh || !vh || !dpk || !vpk ||
            mg_col_u64(st, 4, &amount) != 0 || amount == 0 ||
            mg_col_u64(st, 5, &at) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a malformed delegations row");
            goto fail;
        }
        if (mg_tag_key(NODUS_TREE_TAG_DELEGATION, dpk, kd) != 0 ||
            mg_tag_key(NODUS_TREE_TAG_DELEGATION, vpk, kv) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "hash backend failure on a "
                          "delegation key");
            goto fail;
        }
        if (memcmp(kd, dh, MG_KEY) != 0 || memcmp(kv, vh, MG_KEY) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a delegations row whose key is "
                          "not the tagged hash of its pubkeys — already "
                          "migrated or corrupt");
            goto fail;
        }
        const mg_val_t *v = mg_val_by_pk(m, vpk);
        if (!v) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a delegation names a validator "
                          "pubkey with no validators row");
            goto fail;
        }
        if (mg_del_push(m) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "allocation failed reading "
                          "delegations");
            goto fail;
        }
        mg_del_t *d = &m->d[m->nd - 1];
        if (qgp_sha3_512(dpk, MG_PK, d->dfp) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "hash backend failure on a "
                          "delegator fingerprint");
            goto fail;
        }
        memcpy(d->vid, v->vid, MG_KEY);
        memcpy(d->dpk, dpk, MG_PK);
        memcpy(d->vpk, vpk, MG_PK);
        d->amount = amount;
        d->at = at;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delegations scan failed (rc=%d)", rc);
        return -1;
    }
    m->nd_old = m->nd;
    return 0;
fail:
    sqlite3_finalize(st);
    return -1;
}

/* ── READ 3: v2_balance_copy, every epoch, primary-key order ───────── */

static int mg_read_copy(nodus_witness_t *w, mg_t *m) {
    sqlite3_stmt *st = NULL;
    int rc;
    if (sqlite3_prepare_v2(w->db,
            "SELECT epoch_start, validator_fp, owner_fp, kind, amount "
            "FROM v2_balance_copy ORDER BY epoch_start ASC, "
            "validator_fp ASC, owner_fp ASC, kind ASC", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_balance_copy prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *vfp = mg_col_blob(st, 1, MG_KEY);
        const uint8_t *ofp = mg_col_blob(st, 2, MG_KEY);
        uint64_t epoch = 0, kind = 0, amount = 0;
        if (!vfp || !ofp || mg_col_u64(st, 0, &epoch) != 0 ||
            mg_col_u64(st, 3, &kind) != 0 || kind > 1u ||
            mg_col_u64(st, 4, &amount) != 0 ||
            (kind == 0u && memcmp(vfp, ofp, MG_KEY) != 0)) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "a malformed v2_balance_copy row");
            goto fail;
        }
        /* K14 item 7 / design §7.4: every retained epoch is re-keyed and
         * NEVER skipped — an unmapped row would leave a copy the first
         * post-H distribution cannot find (v2_econ.c member copy gate,
         * −2 on every node) */
        const mg_val_t *v = mg_val_by_fp(m, vfp);
        if (!v) {
            QGP_LOG_ERROR(LOG_TAG, "a v2_balance_copy row of epoch %llu "
                          "names a validator_fp with no validators row",
                          (unsigned long long)epoch);
            goto fail;
        }
        if (m->nc == m->cc) {
            size_t nc = m->cc ? m->cc * 2 : 64;
            mg_copy_t *nr = realloc(m->c, nc * sizeof(*nr));
            if (!nr) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "allocation failed reading "
                              "v2_balance_copy");
                goto fail;
            }
            m->c = nr;
            m->cc = nc;
        }
        mg_copy_t *c = &m->c[m->nc++];
        c->epoch = epoch;
        memcpy(c->vfp, v->vid, MG_KEY);
        /* kind 0: owner = the validator (the v2_econ.c invariant) → its
         * validator_id; kind 1: the delegator's untagged fp, unchanged */
        memcpy(c->ofp, kind == 0u ? v->vid : ofp, MG_KEY);
        c->kind = (uint8_t)kind;
        c->amount = amount;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2_balance_copy scan failed (rc=%d)", rc);
        return -1;
    }
    return 0;
fail:
    sqlite3_finalize(st);
    return -1;
}

/* one v2_reward_accrual row: 0 present (*amount set) / 1 absent / -1 */
static int mg_accrual_get(nodus_witness_t *w, const uint8_t fp[MG_KEY],
                          uint64_t *amount) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    if (sqlite3_bind_blob(st, 1, fp, MG_KEY, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW && mg_col_u64(st, 0, amount) == 0) {
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* ── SQL helpers for the WRITE phase ───────────────────────────────── */

/* run a parameterless statement; *changes set on success */
static int mg_exec(nodus_witness_t *w, const char *sql, int *changes) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed (%s): %s", sql,
                      sqlite3_errmsg(w->db));
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "step failed (%s): rc=%d", sql, rc);
        return -1;
    }
    *changes = sqlite3_changes(w->db);
    return 0;
}

static int mg_step_one(nodus_witness_t *w, sqlite3_stmt *st,
                       const char *what) {
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "%s: rc=%d, %d rows changed (want 1): %s",
                      what, rc, sqlite3_changes(w->db),
                      sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── the migration ──────────────────────────────────────────────────── */

int nodus_witness_v2_roles_migrate(nodus_witness_t *w, uint64_t h_next,
                                   const uint8_t chain32[32],
                                   const uint8_t foundation_fp[64]) {
    if (!w || !w->db || !chain32 || !foundation_fp) return -2;
    if (h_next == 0 || h_next > MG_I64) {
        QGP_LOG_ERROR(LOG_TAG, "activation height %llu outside [1, "
                      "INT64_MAX]", (unsigned long long)h_next);
        return -2;
    }
    if (mg_is_zero(foundation_fp, MG_KEY)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "an all-zero Foundation owner (no "
                      "owner_fp is ever all-zero, design §6.5)");
        return -2;
    }
    if (sqlite3_get_autocommit(w->db) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "called outside a transaction — the "
                      "migration is one step of a block's transaction");
        return -2;
    }

    mg_t m;
    sqlite3_stmt *st = NULL;
    int ret = -2, ch = 0, target_present = 0;
    uint64_t acc_target = 0, acc_sum = 0;
    uint64_t sup_before = 0, sup_after = 0;
    size_t n_src = 0, n_found = 0, n_keys = 0;
    memset(&m, 0, sizeof(m));

    /* ══ READ ════════════════════════════════════════════════════════ */
    {
        sqlite3_int64 n = -1;
        if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM "
                               "v2_validator_roles", -1, &st, NULL)
            != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "v2_validator_roles unreadable: %s",
                          sqlite3_errmsg(w->db));
            goto done;
        }
        n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (n != 0) {
            QGP_LOG_ERROR(LOG_TAG, "v2_validator_roles already holds %lld "
                          "rows — the migration runs once, on an empty "
                          "table", (long long)n);
            goto done;
        }
        /* HF-6 slice 4: the consensus-key reservation table too */
        if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM "
                               "v2_consensus_keys", -1, &st, NULL)
            != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "v2_consensus_keys unreadable: %s",
                          sqlite3_errmsg(w->db));
            goto done;
        }
        n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (n != 0) {
            QGP_LOG_ERROR(LOG_TAG, "v2_consensus_keys already holds %lld "
                          "rows — the migration runs once, on an empty "
                          "table", (long long)n);
            goto done;
        }
    }
    if (mg_read_validators(w, &m, chain32, foundation_fp) != 0) goto done;
    if (mg_read_delegations(w, &m) != 0) goto done;
    if (mg_read_copy(w, &m) != 0) goto done;

    /* K4: the Foundation rows' accruals and the Foundation's own row,
     * read before anything is written. Sources visited in owner_fp ASC
     * (m.by_fp order) — the sum is order-free, the fixed walk is the
     * determinism rule. The written value is the target plus every
     * deleted source, so Σaccrual is conserved by construction. */
    {
        int r = mg_accrual_get(w, foundation_fp, &acc_target);
        if (r < 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the Foundation accrual row is "
                          "unreadable or malformed");
            goto done;
        }
        target_present = (r == 0);
        acc_sum = target_present ? acc_target : 0;
        for (size_t k = 0; k < m.nv; k++) {
            const mg_val_t *v = &m.v[m.by_fp[k].idx];
            uint64_t a = 0;
            if (!v->foundation) continue;
            if (memcmp(v->fp, foundation_fp, MG_KEY) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a Foundation validator's own "
                              "address IS the Foundation owner — a merge "
                              "into itself is refused");
                goto done;
            }
            r = mg_accrual_get(w, v->fp, &a);
            if (r < 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a Foundation node's accrual "
                              "row is unreadable or malformed");
                goto done;
            }
            if (r == 1) continue;
            n_src++;
            if (mg_add(acc_sum, a, &acc_sum) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the Foundation accrual merge "
                              "leaves [0, INT64_MAX] (K4: checked add)");
                goto done;
            }
        }
    }

    /* ══ COMPUTE ═════════════════════════════════════════════════════ */
    /* Σself + Σtotal_delegated (the staked part of the phase-7 supply
     * equation), from the values AS READ vs the values to be written */
    for (size_t i = 0; i < m.nv; i++) {
        const mg_val_t *v = &m.v[i];
        n_found += (size_t)v->foundation;
        if (mg_add(sup_before, v->read_self_stake, &sup_before) != 0 ||
            mg_add(sup_before, v->read_total_delegated, &sup_before) != 0 ||
            mg_add(sup_after, v->self_stake, &sup_after) != 0 ||
            mg_add(sup_after, v->total_delegated, &sup_after) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the staked supply leaves INT64");
            goto done;
        }
    }
    if (sup_before != sup_after) {
        QGP_LOG_ERROR(LOG_TAG, "staked supply %llu -> %llu: the split must "
                      "conserve it", (unsigned long long)sup_before,
                      (unsigned long long)sup_after);
        goto done;
    }

    /* the self-delegation (owner_fp, validator_id) of every bonded row,
     * in pubkey ASC: a top-up of the re-keyed row when that key exists
     * (delegated_at_block unchanged, design §7.2), else a new row at H.
     * Only re-keyed rows (index < nd_old) can match — one bonded row adds
     * one key, and validator_ids are distinct. */
    for (size_t i = 0; i < m.nv; i++) {
        const mg_val_t *v = &m.v[i];
        size_t j;
        if (!v->bonded) continue;
        for (j = 0; j < m.nd_old; j++)
            if (memcmp(m.d[j].dfp, v->owner, MG_KEY) == 0 &&
                memcmp(m.d[j].vid, v->vid, MG_KEY) == 0)
                break;
        if (j < m.nd_old) {
            if (mg_add(m.d[j].amount, MG_SELF_DELEG, &m.d[j].amount) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a self-delegation top-up "
                              "leaves INT64");
                goto done;
            }
            continue;
        }
        if (mg_del_push(&m) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "allocation failed adding a "
                          "self-delegation");
            goto done;
        }
        mg_del_t *d = &m.d[m.nd - 1];
        memcpy(d->dfp, v->owner, MG_KEY);
        memcpy(d->vid, v->vid, MG_KEY);
        /* The *_pubkey columns are never read by a generation-4 reader
         * (plan §1; the §6.4 leaf, nodus_witness_merkle.c
         * nodus_witness_merkle_compute_delegation_root_v2, leaves them
         * out). They are still written FULL-LENGTH (sub-slice 3d kept
         * this deliberately). After the edge the production SYSTEM root
         * is the v5 composition over the §6.3 / §6.4 leaves
         * (nodus_rt_system_state_root, nodus_witness_v2_claims.c);
         * nodus_witness_global_root_v2 has NO production caller in
         * nodus/src (its callers are tests — test_v2_claims.c,
         * test_hf4_names_engine.c). The v1 delegation loader, which
         * refuses any other length (load_delegation_leaves), is still
         * composed by the helpers that take no generation input —
         * nodus_witness_system_root_v2 (the v4 composition; the tests'
         * nodus_witness_global_root_v2 reads it) and
         * nodus_witness_system_payload_root_v2 (the SYSTEM activation
         * payload, nodus_witness_roots_v2.c); a zero-length column would
         * turn those helpers into a fault on every migrated chain.
         * validator_pubkey = the consensus key (true). delegator_pubkey =
         * that same key when the owner IS SHA3-512(key) (true: the node
         * key is the owner); for a Foundation-owned row there is no
         * single delegator key (a 2-of-3 address), so 2592 × 0x00 — never
         * a real key, so it cannot tie with the pre-H node-key row in the
         * v1 loader's (validator_pubkey, delegator_pubkey) order. */
        memcpy(d->vpk, v->pk, MG_PK);
        if (v->foundation) memset(d->dpk, 0, MG_PK);
        else memcpy(d->dpk, v->pk, MG_PK);
        d->amount = MG_SELF_DELEG;
        d->at = h_next;
    }
    if (m.nd > 1) qsort(m.d, m.nd, sizeof(*m.d), mg_cmp_del);
    for (size_t i = 1; i < m.nd; i++)
        if (mg_cmp_del(&m.d[i - 1], &m.d[i]) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "two re-keyed delegations share "
                          "(delegator_fp, validator_id)");
            goto done;
        }
    if (m.nc > 1) qsort(m.c, m.nc, sizeof(*m.c), mg_cmp_copy);
    for (size_t i = 1; i < m.nc; i++)
        if (mg_cmp_copy(&m.c[i - 1], &m.c[i]) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "two re-keyed v2_balance_copy rows "
                          "share a primary key");
            goto done;
        }
    /* ══ WRITE ═══════════════════════════════════════════════════════ */
    /* validators: re-key in place. The old key is SHA3-512(0x02‖pk) and
     * the new one a "NDS.VALMIG.v1" SHA3-512 — distinct hash domains, so
     * no row can transiently collide with another's new key; a collision
     * would be a UNIQUE fault anyway, never a silent overwrite. */
    if (sqlite3_prepare_v2(w->db,
            "UPDATE validators SET pubkey_hash = ?1, self_stake = ?2, "
            "total_delegated = ?3, external_delegated = ?4 "
            "WHERE pubkey_hash = ?5 AND pubkey = ?6", -1, &st, NULL)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "validators update prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    for (size_t i = 0; i < m.nv; i++) {
        const mg_val_t *v = &m.v[i];
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (sqlite3_bind_blob(st, 1, v->vid, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int64(st, 2, (sqlite3_int64)v->self_stake) != SQLITE_OK ||
            sqlite3_bind_int64(st, 3, (sqlite3_int64)v->total_delegated) != SQLITE_OK ||
            sqlite3_bind_int64(st, 4, (sqlite3_int64)v->external_delegated) != SQLITE_OK ||
            sqlite3_bind_blob(st, 5, v->old_key, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 6, v->pk, MG_PK, SQLITE_STATIC) != SQLITE_OK ||
            mg_step_one(w, st, "validators re-key") != 0)
            goto done;
    }
    sqlite3_finalize(st);
    st = NULL;

    /* v2_validator_roles: (validator_id, owner_fp, 2592 × 0x00, 0) — the
     * one "no pending key" encoding (design §6.3) */
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_validator_roles (validator_id, owner_fp, "
            "pending_consensus_pubkey, consensus_key_effective_epoch) "
            "VALUES (?1, ?2, ?3, 0)", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "roles insert prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    for (size_t i = 0; i < m.nv; i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (sqlite3_bind_blob(st, 1, m.v[i].vid, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, m.v[i].owner, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_zeroblob(st, 3, (int)MG_PK) != SQLITE_OK ||
            mg_step_one(w, st, "v2_validator_roles insert") != 0)
            goto done;
    }
    sqlite3_finalize(st);
    st = NULL;

    /* HF-6 slice 4 (design rev 6 §4) — v2_consensus_keys: one role-1
     * reservation (SHA3-512(pk), validator_id) per migrated row that has
     * NOT graduated. An UNSTAKED row already left the bonded/exiting
     * lifecycle (its graduation would have released the key, §4 last
     * sentence), so it holds none: the table stays the pure function
     * "role 1 = every validators row whose status is not UNSTAKED" that
     * the generation-4 STAKE and graduation maintain afterwards. Visited
     * in SHA3-512(pk) ASC (m.by_fp — the table's own key order); the keys
     * are distinct (checked in mg_read_validators). */
    for (size_t k = 0; k < m.nv; k++) {
        const mg_val_t *v = &m.v[m.by_fp[k].idx];
        if (v->unstaked) continue;
        if (nodus_validator_v2_key_insert(w, v->fp, v->vid,
                                          (uint8_t)NODUS_V2_KEY_ROLE_ACTIVE)
            != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "v2_consensus_keys insert failed");
            goto done;
        }
        n_keys++;
    }

    /* delegations: delete every row, re-insert the computed set in its
     * new primary-key order (no lookup against a half-re-keyed table) */
    if (mg_exec(w, "DELETE FROM delegations", &ch) != 0) goto done;
    if ((size_t)ch != m.nd_old) {
        QGP_LOG_ERROR(LOG_TAG, "delegations delete removed %d rows, %zu "
                      "were read", ch, m.nd_old);
        goto done;
    }
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO delegations (delegator_hash, validator_hash, "
            "delegator_pubkey, validator_pubkey, amount, "
            "delegated_at_block) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "delegations insert prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    for (size_t i = 0; i < m.nd; i++) {
        const mg_del_t *d = &m.d[i];
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (d->amount == 0 || d->amount > MG_I64 || d->at > MG_I64 ||
            sqlite3_bind_blob(st, 1, d->dfp, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, d->vid, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 3, d->dpk, MG_PK, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 4, d->vpk, MG_PK, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int64(st, 5, (sqlite3_int64)d->amount) != SQLITE_OK ||
            sqlite3_bind_int64(st, 6, (sqlite3_int64)d->at) != SQLITE_OK ||
            mg_step_one(w, st, "delegations insert") != 0)
            goto done;
    }
    sqlite3_finalize(st);
    st = NULL;

    /* v2_balance_copy: the same delete + ordered re-insert; amounts are
     * the stored ones, byte for byte (K14 item 7) */
    if (mg_exec(w, "DELETE FROM v2_balance_copy", &ch) != 0) goto done;
    if ((size_t)ch != m.nc) {
        QGP_LOG_ERROR(LOG_TAG, "v2_balance_copy delete removed %d rows, %zu "
                      "were read", ch, m.nc);
        goto done;
    }
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_balance_copy (epoch_start, validator_fp, "
            "owner_fp, kind, amount) VALUES (?1, ?2, ?3, ?4, ?5)",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_balance_copy insert prepare failed: %s",
                      sqlite3_errmsg(w->db));
        goto done;
    }
    for (size_t i = 0; i < m.nc; i++) {
        const mg_copy_t *c = &m.c[i];
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        if (sqlite3_bind_int64(st, 1, (sqlite3_int64)c->epoch) != SQLITE_OK ||
            sqlite3_bind_blob(st, 2, c->vfp, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_blob(st, 3, c->ofp, MG_KEY, SQLITE_STATIC) != SQLITE_OK ||
            sqlite3_bind_int64(st, 4, (sqlite3_int64)c->kind) != SQLITE_OK ||
            sqlite3_bind_int64(st, 5, (sqlite3_int64)c->amount) != SQLITE_OK ||
            mg_step_one(w, st, "v2_balance_copy insert") != 0)
            goto done;
    }
    sqlite3_finalize(st);
    st = NULL;

    /* K4: delete the Foundation nodes' accrual rows (owner_fp ASC), then
     * write the merged Foundation row — only when a source existed */
    if (n_src > 0) {
        if (sqlite3_prepare_v2(w->db, "DELETE FROM v2_reward_accrual "
                               "WHERE owner_fp = ?1", -1, &st, NULL)
            != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "accrual delete prepare failed: %s",
                          sqlite3_errmsg(w->db));
            goto done;
        }
        size_t deleted = 0;
        for (size_t k = 0; k < m.nv; k++) {
            const mg_val_t *v = &m.v[m.by_fp[k].idx];
            if (!v->foundation) continue;
            sqlite3_reset(st);
            sqlite3_clear_bindings(st);
            if (sqlite3_bind_blob(st, 1, v->fp, MG_KEY, SQLITE_STATIC)
                    != SQLITE_OK ||
                sqlite3_step(st) != SQLITE_DONE) {
                QGP_LOG_ERROR(LOG_TAG, "accrual delete failed: %s",
                              sqlite3_errmsg(w->db));
                goto done;
            }
            deleted += (size_t)sqlite3_changes(w->db);
        }
        sqlite3_finalize(st);
        st = NULL;
        if (deleted != n_src) {
            QGP_LOG_ERROR(LOG_TAG, "accrual merge deleted %zu source rows, "
                          "%zu were read", deleted, n_src);
            goto done;
        }
        if (sqlite3_prepare_v2(w->db, target_present
                ? "UPDATE v2_reward_accrual SET amount = ?2 "
                  "WHERE owner_fp = ?1"
                : "INSERT INTO v2_reward_accrual (owner_fp, amount) "
                  "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "accrual write prepare failed: %s",
                          sqlite3_errmsg(w->db));
            goto done;
        }
        if (sqlite3_bind_blob(st, 1, foundation_fp, MG_KEY, SQLITE_STATIC)
                != SQLITE_OK ||
            sqlite3_bind_int64(st, 2, (sqlite3_int64)acc_sum) != SQLITE_OK ||
            mg_step_one(w, st, "Foundation accrual write") != 0)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "HF-6 migration: %zu validators re-keyed (%zu "
                 "Foundation-owned), %zu consensus keys reserved, %zu "
                 "delegations (%zu before), %zu balance-copy rows, %zu "
                 "accrual rows merged into the Foundation owner", m.nv,
                 n_found, n_keys, m.nd, m.nd_old, m.nc, n_src);
    ret = 0;
done:
    sqlite3_finalize(st);
    mg_free(&m);
    return ret;
}
