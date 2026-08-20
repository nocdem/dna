/**
 * @file nodus_witness_v2_pools.c
 * @brief Ledger V2 Season 7 — persistent shielded pool state
 *        implementation. Contract: nodus_witness_v2_pools.h.
 *
 * INACTIVE: no live consensus path calls anything here.
 *
 * @file nodus_witness_v2_pools.c
 */

#include "witness/nodus_witness_v2_pools.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/zk/shielded_tree.h"
#include "crypto/zk/field_goldilocks.h"

#define LOG_TAG "W_V2POOLS"

/* The zk-free pool_wire mirrors of the zk constants must be IDENTICAL —
 * a drift here would let the outer commitment accept lanes the tree
 * rejects (or vice versa). */
_Static_assert(DNA_POOL_FE_P == GOLDILOCKS_P,
               "pool_wire Goldilocks mirror drifted");
_Static_assert(DNA_POOL_TREE_DEPTH_V1 == SHIELDED_TREE_DEPTH,
               "pool_wire depth mirror drifted");
_Static_assert(DNA_POOL_NOTE_LEN == SHIELDED_TREE_LANES * 8,
               "note byte width mirror drifted");

#define DEPTH   SHIELDED_TREE_DEPTH
#define LANES   SHIELDED_TREE_LANES
#define FRONTIER_BLOB_LEN (DEPTH * DNA_POOL_NOTE_LEN)   /* 24 × 32 = 768 */

/* ── canonical 4×u64 BE ↔ lane conversion ───────────────────────────── */

static void lanes_to_be(const uint64_t lanes[LANES],
                        uint8_t out[DNA_POOL_NOTE_LEN]) {
    for (int l = 0; l < LANES; l++) {
        uint64_t v = lanes[l];
        for (int i = 7; i >= 0; i--) {
            out[l * 8 + i] = (uint8_t)(v & 0xff);
            v >>= 8;
        }
    }
}

/* @return 0 ok (canonical), -1 non-canonical. */
static int be_to_lanes(const uint8_t in[DNA_POOL_NOTE_LEN],
                       uint64_t lanes[LANES]) {
    for (int l = 0; l < LANES; l++) {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | in[l * 8 + i];
        if (v >= GOLDILOCKS_P) return -1;
        lanes[l] = v;
    }
    return 0;
}

/* ── frontier helpers ───────────────────────────────────────────────────
 * The persisted blob holds level i's filled-subtree digest iff bit i of
 * note_count is 1, ZERO otherwise (canonical storage). Restoring fills
 * the non-meaningful levels with the cached empty roots E_i, exactly
 * the state shielded_tree_init + the append history would hold. */

static int frontier_restore(shielded_tree_t *t, uint64_t note_count,
                            const uint8_t blob[FRONTIER_BLOB_LEN]) {
    if (shielded_tree_init(t) != SHIELDED_TREE_OK) return -1;
    for (unsigned i = 0; i < DEPTH; i++) {
        const uint8_t *lv = blob + (size_t)i * DNA_POOL_NOTE_LEN;
        if ((note_count >> i) & 1u) {
            if (be_to_lanes(lv, t->filled[i]) != 0) return -1;
        } else {
            /* canonical storage: a non-meaningful level MUST be zero */
            for (int b = 0; b < DNA_POOL_NOTE_LEN; b++)
                if (lv[b] != 0) return -1;
            /* t->filled[i] stays E_i from init */
        }
    }
    t->next_index = note_count;
    return 0;
}

static void frontier_persist(const shielded_tree_t *t,
                             uint8_t blob[FRONTIER_BLOB_LEN]) {
    memset(blob, 0, FRONTIER_BLOB_LEN);
    for (unsigned i = 0; i < DEPTH; i++)
        if ((t->next_index >> i) & 1u)
            lanes_to_be(t->filled[i], blob + (size_t)i * DNA_POOL_NOTE_LEN);
}

/* Root of the n-leaf tree recomputed from the frontier — the walk
 * mirrors the shipped incremental update (shielded_tree.c:80-100) with
 * the current node starting as the EMPTY leaf at position n: at level i
 * a set count bit pairs filled[i] on the left, a clear bit pairs the
 * empty subtree E_i on the right. Used ONLY as the restart/mutual
 * verification oracle; appends always go through shielded_tree_append. */
static void frontier_root(const shielded_tree_t *t,
                          uint64_t lanes_out[LANES]) {
    uint64_t cur[LANES];
    memcpy(cur, t->empty[0], sizeof(cur));
    uint64_t ci = t->next_index;
    for (unsigned i = 0; i < DEPTH; i++) {
        uint64_t left[LANES], right[LANES];
        if (ci & 1u) {
            memcpy(left, t->filled[i], sizeof(left));
            memcpy(right, cur, sizeof(right));
        } else {
            memcpy(left, cur, sizeof(left));
            memcpy(right, t->empty[i], sizeof(right));
        }
        note_merkle_compress(left, right, cur);
        ci >>= 1;
    }
    memcpy(lanes_out, cur, sizeof(cur));
}

/* ── small DB helpers (fail-closed) ─────────────────────────────────── */

static int table_exists(nodus_witness_t *w, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* One-row u64 aggregate for a (domain, pool) scope. @return 0/-1. */
static int pool_q1(nodus_witness_t *w, const char *sql, uint32_t dom,
                   uint32_t pool, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    sqlite3_int64 v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* ── pool create ────────────────────────────────────────────────────── */

int nodus_witness_v2_pool_create(nodus_witness_t *w,
                                 const dna_pool_config_t *cfg,
                                 uint64_t global_height) {
    if (!w || !w->db || !cfg) return -1;
    if (cfg->tree_depth != DNA_POOL_TREE_DEPTH_V1) return -1;
    if (cfg->history_limit == 0) return -1;
    if (cfg->asset_ref_len == 0 ||
        cfg->asset_ref_len > DNA_POOL_ASSETREF_MAX)
        return -1;
    /* configuration must hash (validates the remaining shape) */
    uint8_t cfg_hash[64];
    if (dna_pool_config_hash(cfg, cfg_hash) != 0) return -1;

    /* Idempotent-or-conflict on the CONFIGURATION columns. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT config_version, tree_depth, history_limit, asset_ref "
            "FROM v2_pools WHERE domain_id=?1 AND pool_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cfg->domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cfg->pool_id);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        int same =
            (uint64_t)sqlite3_column_int64(st, 0) == cfg->config_version &&
            (uint64_t)sqlite3_column_int64(st, 1) == cfg->tree_depth &&
            (uint64_t)sqlite3_column_int64(st, 2) == cfg->history_limit &&
            sqlite3_column_bytes(st, 3) == (int)cfg->asset_ref_len &&
            memcmp(sqlite3_column_blob(st, 3), cfg->asset_ref,
                   cfg->asset_ref_len) == 0;
        sqlite3_finalize(st);
        return same ? 0 : -1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;

    /* Canonical initial state. */
    uint64_t empty_lanes[LANES];
    uint8_t empty_root[DNA_POOL_NOTE_LEN];
    if (shielded_tree_empty_root(DEPTH, empty_lanes) != SHIELDED_TREE_OK)
        return -1;
    lanes_to_be(empty_lanes, empty_root);
    uint8_t nul_root[64];
    if (dna_pool_nul_empty_root(nul_root) != 0) return -1;
    uint8_t frontier[FRONTIER_BLOB_LEN];
    memset(frontier, 0, sizeof(frontier));

    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_pools (domain_id, pool_id, config_version, "
            "tree_depth, history_limit, asset_ref, note_count, note_root, "
            "frontier, nul_count, nul_root, balance, hist_count, "
            "hist_next_seq) VALUES (?1,?2,?3,?4,?5,?6,0,?7,?8,0,?9,0,1,1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cfg->domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cfg->pool_id);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)cfg->config_version);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)cfg->tree_depth);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)cfg->history_limit);
    sqlite3_bind_blob(st, 6, cfg->asset_ref, cfg->asset_ref_len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 7, empty_root, DNA_POOL_NOTE_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8, frontier, FRONTIER_BLOB_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 9, nul_root, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;

    /* History seq 0 = the canonical empty root. */
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_pool_roots (domain_id, pool_id, seq, "
            "note_root, global_height) VALUES (?1,?2,0,?3,?4)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cfg->domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cfg->pool_id);
    sqlite3_bind_blob(st, 3, empty_root, DNA_POOL_NOTE_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)global_height);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ── pool load + mutual verification ────────────────────────────────── */

int nodus_witness_v2_pool_load(nodus_witness_t *w, uint32_t domain_id,
                               uint32_t pool_id,
                               nodus_v2_pool_state_t *out) {
    if (!w || !w->db || !out) return -1;
    memset(out, 0, sizeof(*out));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT config_version, tree_depth, history_limit, asset_ref, "
            "note_count, note_root, frontier, nul_count, nul_root, "
            "balance, hist_count, hist_next_seq FROM v2_pools "
            "WHERE domain_id=?1 AND pool_id=?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool_id);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }

    int bad = 0;
    out->cfg.domain_id = domain_id;
    out->cfg.pool_id = pool_id;
    sqlite3_int64 v;
    v = sqlite3_column_int64(st, 0);
    if (v <= 0 || v > (sqlite3_int64)UINT32_MAX) bad = 1;
    out->cfg.config_version = (uint32_t)v;
    v = sqlite3_column_int64(st, 1);
    if (v != DNA_POOL_TREE_DEPTH_V1) bad = 1;
    out->cfg.tree_depth = (uint8_t)v;
    v = sqlite3_column_int64(st, 2);
    if (v <= 0 || v > (sqlite3_int64)UINT32_MAX) bad = 1;
    out->cfg.history_limit = (uint32_t)v;
    int aref_len = sqlite3_column_bytes(st, 3);
    if (aref_len <= 0 || aref_len > DNA_POOL_ASSETREF_MAX) {
        bad = 1;
    } else {
        out->cfg.asset_ref_len = (uint16_t)aref_len;
        memcpy(out->cfg.asset_ref, sqlite3_column_blob(st, 3),
               (size_t)aref_len);
    }
    v = sqlite3_column_int64(st, 4);
    if (v < 0 || (uint64_t)v > SHIELDED_TREE_CAPACITY) bad = 1;
    out->note_count = (uint64_t)v;
    if (sqlite3_column_bytes(st, 5) != DNA_POOL_NOTE_LEN) bad = 1;
    else memcpy(out->note_root, sqlite3_column_blob(st, 5),
                DNA_POOL_NOTE_LEN);
    if (sqlite3_column_bytes(st, 6) != FRONTIER_BLOB_LEN) bad = 1;
    else memcpy(out->frontier, sqlite3_column_blob(st, 6),
                FRONTIER_BLOB_LEN);
    v = sqlite3_column_int64(st, 7);
    if (v < 0) bad = 1;
    out->nul_count = (uint64_t)v;
    if (sqlite3_column_bytes(st, 8) != DNA_POOL_ROOT_LEN) bad = 1;
    else memcpy(out->nul_root, sqlite3_column_blob(st, 8),
                DNA_POOL_ROOT_LEN);
    v = sqlite3_column_int64(st, 9);
    if (v < 0) bad = 1;
    out->balance = (uint64_t)v;
    v = sqlite3_column_int64(st, 10);
    if (v < 1) bad = 1;
    out->hist_count = (uint64_t)v;
    v = sqlite3_column_int64(st, 11);
    if (v < 1) bad = 1;
    out->hist_next_seq = (uint64_t)v;
    sqlite3_finalize(st);
    if (bad) {
        QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) row malformed — fail closed",
                      domain_id, pool_id);
        return -1;
    }
    if (!dna_pool_lanes_canonical(out->note_root)) return -1;
    if (out->hist_count > out->cfg.history_limit) return -1;
    if (out->hist_count > out->hist_next_seq) return -1;

    /* Mutual verification 1: frontier + count reproduce the root.
     * FULL tree (count == 2^24): every count bit is 0, so the frontier
     * carries no meaningful level — its canonical form is all-zero and
     * the final root is bound by the retained history (verified below)
     * and the committed pools_root instead. A full pool is terminal:
     * the capacity pre-check refuses every further append. */
    if (out->note_count == SHIELDED_TREE_CAPACITY) {
        const uint8_t *fb = (const uint8_t *)out->frontier;
        for (size_t i = 0; i < FRONTIER_BLOB_LEN; i++)
            if (fb[i] != 0) {
                QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) full-tree frontier "
                              "non-canonical — fail closed", domain_id,
                              pool_id);
                return -1;
            }
    } else {
        shielded_tree_t *t = calloc(1, sizeof(*t));
        if (!t) return -1;
        if (frontier_restore(t, out->note_count,
                             (const uint8_t *)out->frontier) != 0) {
            shielded_tree_free(t); free(t);
            QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) frontier non-canonical",
                          domain_id, pool_id);
            return -1;
        }
        uint64_t root_lanes[LANES];
        uint8_t root_be[DNA_POOL_NOTE_LEN];
        frontier_root(t, root_lanes);
        lanes_to_be(root_lanes, root_be);
        shielded_tree_free(t); free(t);
        if (memcmp(root_be, out->note_root, DNA_POOL_NOTE_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) frontier/root/count "
                          "disagree — fail closed", domain_id, pool_id);
            return -1;
        }
    }

    /* Mutual verification 2: the derived append-only tables' TIPS
     * agree with the committed counters (MAX(position) + 1 == count;
     * a zero counter tolerates no row). The tables are DERIVED/
     * rebuildable — their full-body audit is recovery-tooling scope,
     * never an ordinary-startup rebuild/repair. */
    uint64_t n = 0;
    if (out->note_count == 0) {
        if (pool_q1(w, "SELECT EXISTS(SELECT 1 FROM v2_pool_notes WHERE "
                    "domain_id=?1 AND pool_id=?2)", domain_id, pool_id,
                    &n) != 0 || n != 0)
            return -1;
    } else {
        if (pool_q1(w, "SELECT COALESCE(MAX(position),0) FROM "
                    "v2_pool_notes WHERE domain_id=?1 AND pool_id=?2",
                    domain_id, pool_id, &n) != 0 ||
            n != out->note_count - 1)
            return -1;
    }
    if (out->nul_count == 0) {
        if (pool_q1(w, "SELECT EXISTS(SELECT 1 FROM v2_pool_nullifiers "
                    "WHERE domain_id=?1 AND pool_id=?2)", domain_id,
                    pool_id, &n) != 0 || n != 0)
            return -1;
    } else {
        if (pool_q1(w, "SELECT COALESCE(MAX(position),0) FROM "
                    "v2_pool_nullifiers WHERE domain_id=?1 AND "
                    "pool_id=?2", domain_id, pool_id, &n) != 0 ||
            n != out->nul_count - 1)
            return -1;
    }

    /* Mutual verification 3: the retained history window. */
    if (pool_q1(w, "SELECT COUNT(*) FROM v2_pool_roots WHERE "
                "domain_id=?1 AND pool_id=?2", domain_id, pool_id, &n)
        != 0 || n != out->hist_count)
        return -1;
    uint64_t mx = 0, mn = 0;
    if (pool_q1(w, "SELECT COALESCE(MAX(seq),0) FROM v2_pool_roots WHERE "
                "domain_id=?1 AND pool_id=?2", domain_id, pool_id, &mx)
        != 0 || mx != out->hist_next_seq - 1)
        return -1;
    if (pool_q1(w, "SELECT COALESCE(MIN(seq),0) FROM v2_pool_roots WHERE "
                "domain_id=?1 AND pool_id=?2", domain_id, pool_id, &mn)
        != 0 || mn != out->hist_next_seq - out->hist_count)
        return -1;
    /* The newest retained entry must BE the current root. */
    if (sqlite3_prepare_v2(w->db,
            "SELECT note_root FROM v2_pool_roots WHERE domain_id=?1 AND "
            "pool_id=?2 AND seq=?3", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool_id);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)mx);
    rc = sqlite3_step(st);
    int cur_ok = (rc == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == DNA_POOL_NOTE_LEN &&
                  memcmp(sqlite3_column_blob(st, 0), out->note_root,
                         DNA_POOL_NOTE_LEN) == 0);
    sqlite3_finalize(st);
    if (!cur_ok) {
        QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) current root absent from "
                      "retained history — fail closed", domain_id,
                      pool_id);
        return -1;
    }
    return 0;
}

/* ── batch shape validation ─────────────────────────────────────────── */

int nodus_witness_v2_pool_mut_validate(const nodus_v2_pool_mut_t *m) {
    if (!m) return -1;
    if (m->n_outs > 0 && !m->outs) return -1;
    if (m->n_ins > 0 && !m->ins) return -1;
    if (m->n_outs == 0 && m->n_ins == 0 &&
        m->balance_add == 0 && m->balance_sub == 0)
        return -1;                       /* declared no-op batch rejects  */

    for (size_t i = 0; i < m->n_outs; i++) {
        const nodus_v2_pool_out_t *o = &m->outs[i];
        if (!dna_pool_lanes_canonical(o->commitment)) return -1;
        if (i == 0) {
            if (o->output_slot != 0) return -1;   /* slots start at 0    */
        } else {
            const nodus_v2_pool_out_t *p = &m->outs[i - 1];
            if (o->tx_index == p->tx_index) {
                if (o->output_slot != p->output_slot + 1)
                    return -1;           /* duplicate / gap / reorder     */
            } else if (o->tx_index > p->tx_index) {
                if (o->output_slot != 0) return -1;
            } else {
                return -1;               /* descending tx order           */
            }
        }
    }
    for (size_t i = 0; i < m->n_ins; i++) {
        const nodus_v2_pool_in_t *in = &m->ins[i];
        if (!dna_pool_lanes_canonical(in->nullifier)) return -1;
        if (i == 0) {
            if (in->input_slot != 0) return -1;
        } else {
            const nodus_v2_pool_in_t *p = &m->ins[i - 1];
            if (in->tx_index == p->tx_index) {
                if (in->input_slot != p->input_slot + 1) return -1;
            } else if (in->tx_index > p->tx_index) {
                if (in->input_slot != 0) return -1;
            } else {
                return -1;
            }
        }
        for (size_t j = 0; j < i; j++)   /* in-batch duplicate nullifier */
            if (memcmp(in->nullifier, m->ins[j].nullifier,
                       DNA_POOL_NULLIFIER_LEN) == 0)
                return -1;
    }
    return 0;
}

/* ── batch apply ────────────────────────────────────────────────────── */

#define STAGE(s)                                                          \
    do {                                                                  \
        if (cb && cb(ud, (s)) != 0) goto fail;                            \
    } while (0)

int nodus_witness_v2_pool_apply(nodus_witness_t *w,
                                const nodus_v2_pool_mut_t *m,
                                uint64_t global_height,
                                nodus_v2_pool_stage_cb cb, void *ud) {
    if (!w || !w->db || !m) return -1;
    if (nodus_witness_v2_pool_mut_validate(m) != 0) return -1;

    nodus_v2_pool_state_t ps;
    int rc = nodus_witness_v2_pool_load(w, m->domain_id, m->pool_id, &ps);
    if (rc != 0) return -1;              /* absent pool is a reject too   */

    /* Fail-closed pre-checks BEFORE any mutation. */
    if (m->n_outs > SHIELDED_TREE_CAPACITY ||
        ps.note_count > SHIELDED_TREE_CAPACITY - m->n_outs)
        return -1;                       /* batch crossing capacity       */
    if (ps.balance > UINT64_MAX - m->balance_add) return -1;
    {
        uint64_t nb = ps.balance + m->balance_add;
        if (m->balance_sub > nb) return -1;      /* below zero            */
        nb -= m->balance_sub;
        /* SQLite INTEGER is SIGNED 64-bit: a balance above INT64_MAX
         * cannot round-trip through storage — checked here so the
         * add can never wrap into the sign bit (protocol supply is
         * far below this bound). */
        if (nb > (uint64_t)0x7FFFFFFFFFFFFFFFULL) return -1;
    }
    if (ps.nul_count > UINT64_MAX - m->n_ins) return -1;
    if (ps.hist_next_seq == UINT64_MAX) return -1;
    for (size_t i = 0; i < m->n_ins; i++) {      /* committed duplicates  */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_pool_nullifiers WHERE domain_id=?1 AND "
                "pool_id=?2 AND nullifier=?3", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_blob(st, 3, m->ins[i].nullifier,
                          DNA_POOL_NULLIFIER_LEN, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) nullifier already spent "
                          "— rejected", m->domain_id, m->pool_id);
            return -1;
        }
        if (rc != SQLITE_DONE) return -1;
    }

    shielded_tree_t *t = calloc(1, sizeof(*t));
    if (!t) return -1;
    if (frontier_restore(t, ps.note_count,
                         (const uint8_t *)ps.frontier) != 0) {
        free(t);
        return -1;
    }
    /* the restored tree's root is the VERIFIED stored root (load
     * recomputed it from the frontier; a full tree binds it through
     * the history instead) — needed for the no-append stages below */
    if (be_to_lanes(ps.note_root, t->root) != 0) {
        shielded_tree_free(t); free(t);
        return -1;
    }

    /* s1: commitment inserts (canonical positions note_count..+n-1). */
    for (size_t i = 0; i < m->n_outs; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_pool_notes (domain_id, pool_id, position, "
                "commitment, global_height, tx_index, output_slot) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &st, NULL)
            != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(ps.note_count + i));
        sqlite3_bind_blob(st, 4, m->outs[i].commitment, DNA_POOL_NOTE_LEN,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)global_height);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)m->outs[i].tx_index);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)m->outs[i].output_slot);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
    }
    STAGE(NODUS_V2_POOL_STAGE_COMMITS);

    /* s2: append through the SHIPPED tree primitive; persist the
     * canonical frontier + root + count. */
    for (size_t i = 0; i < m->n_outs; i++) {
        uint64_t leaf[LANES];
        if (be_to_lanes(m->outs[i].commitment, leaf) != 0) goto fail;
        if (shielded_tree_append(t, leaf, NULL) != SHIELDED_TREE_OK)
            goto fail;
    }
    if (m->n_outs > 0) {
        uint8_t frontier[FRONTIER_BLOB_LEN], root_be[DNA_POOL_NOTE_LEN];
        uint64_t root_lanes[LANES];
        frontier_persist(t, frontier);
        if (shielded_tree_root(t, root_lanes) != SHIELDED_TREE_OK)
            goto fail;
        lanes_to_be(root_lanes, root_be);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_pools SET note_count=?3, note_root=?4, "
                "frontier=?5 WHERE domain_id=?1 AND pool_id=?2",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)t->next_index);
        sqlite3_bind_blob(st, 4, root_be, DNA_POOL_NOTE_LEN,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, frontier, FRONTIER_BLOB_LEN,
                          SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
        memcpy(ps.note_root, root_be, DNA_POOL_NOTE_LEN);
        ps.note_count = t->next_index;
    }
    STAGE(NODUS_V2_POOL_STAGE_FRONTIER);

    /* s3: strict nullifier inserts (canonical positions). */
    for (size_t i = 0; i < m->n_ins; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_pool_nullifiers (domain_id, pool_id, "
                "nullifier, position, global_height, tx_index, input_slot) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &st, NULL)
            != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_blob(st, 3, m->ins[i].nullifier,
                          DNA_POOL_NULLIFIER_LEN, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)(ps.nul_count + i));
        sqlite3_bind_int64(st, 5, (sqlite3_int64)global_height);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)m->ins[i].tx_index);
        sqlite3_bind_int64(st, 7, (sqlite3_int64)m->ins[i].input_slot);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;   /* incl. UNIQUE violation    */
    }
    STAGE(NODUS_V2_POOL_STAGE_NULLS);

    /* s4: incremental nullifier-root chain + counter. */
    if (m->n_ins > 0) {
        uint8_t acc[DNA_POOL_ROOT_LEN];
        memcpy(acc, ps.nul_root, DNA_POOL_ROOT_LEN);
        for (size_t i = 0; i < m->n_ins; i++)
            if (dna_pool_nul_step(acc, ps.nul_count + i,
                                  m->ins[i].nullifier, acc) != 0)
                goto fail;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_pools SET nul_count=?3, nul_root=?4 "
                "WHERE domain_id=?1 AND pool_id=?2", -1, &st, NULL)
            != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_int64(st, 3,
                           (sqlite3_int64)(ps.nul_count + m->n_ins));
        sqlite3_bind_blob(st, 4, acc, DNA_POOL_ROOT_LEN, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
        ps.nul_count += m->n_ins;
        memcpy(ps.nul_root, acc, DNA_POOL_ROOT_LEN);
    }
    STAGE(NODUS_V2_POOL_STAGE_NULROOT);

    /* s5: checked balance update. */
    if (m->balance_add != 0 || m->balance_sub != 0) {
        uint64_t nb = ps.balance + m->balance_add - m->balance_sub;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_pools SET balance=?3 WHERE domain_id=?1 AND "
                "pool_id=?2", -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)nb);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
        ps.balance = nb;
    }
    STAGE(NODUS_V2_POOL_STAGE_BALANCE);

    /* s6: history — ONE entry iff the FINAL root changed. */
    {
        int changed = 0;
        uint64_t cur_lanes[LANES];
        uint8_t cur_be[DNA_POOL_NOTE_LEN];
        if (shielded_tree_root(t, cur_lanes) != SHIELDED_TREE_OK)
            goto fail;
        lanes_to_be(cur_lanes, cur_be);
        if (m->n_outs > 0) {
            /* the pre-batch root is the newest retained entry; compare
             * against the post-batch root */
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT note_root FROM v2_pool_roots WHERE "
                    "domain_id=?1 AND pool_id=?2 AND seq=?3",
                    -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            sqlite3_bind_int64(st, 3,
                               (sqlite3_int64)(ps.hist_next_seq - 1));
            rc = sqlite3_step(st);
            if (rc != SQLITE_ROW ||
                sqlite3_column_bytes(st, 0) != DNA_POOL_NOTE_LEN) {
                sqlite3_finalize(st);
                goto fail;
            }
            changed = memcmp(sqlite3_column_blob(st, 0), cur_be,
                             DNA_POOL_NOTE_LEN) != 0;
            sqlite3_finalize(st);
        }
        if (changed) {
            /* A RETAINED root reappearing as a NEW root is corruption/
             * collision — fail closed (the UNIQUE constraint backs
             * this, but the explicit check names the failure). */
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT 1 FROM v2_pool_roots WHERE domain_id=?1 AND "
                    "pool_id=?2 AND note_root=?3", -1, &st, NULL)
                != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            sqlite3_bind_blob(st, 3, cur_be, DNA_POOL_NOTE_LEN,
                              SQLITE_TRANSIENT);
            rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc == SQLITE_ROW) {
                QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) retained root "
                              "reappeared as a new root — fail closed",
                              m->domain_id, m->pool_id);
                goto fail;
            }
            if (rc != SQLITE_DONE) goto fail;

            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_pool_roots (domain_id, pool_id, seq, "
                    "note_root, global_height) VALUES (?1,?2,?3,?4,?5)",
                    -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)ps.hist_next_seq);
            sqlite3_bind_blob(st, 4, cur_be, DNA_POOL_NOTE_LEN,
                              SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 5, (sqlite3_int64)global_height);
            rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) goto fail;

            if (sqlite3_prepare_v2(w->db,
                    "UPDATE v2_pools SET hist_count=hist_count+1, "
                    "hist_next_seq=hist_next_seq+1 WHERE domain_id=?1 "
                    "AND pool_id=?2", -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) goto fail;
            ps.hist_count++;
            ps.hist_next_seq++;
        }
        STAGE(NODUS_V2_POOL_STAGE_HISTORY);

        /* s7: deterministic eviction of exactly the single oldest
         * entry once the consensus-committed limit is exceeded. */
        if (changed && ps.hist_count > ps.cfg.history_limit) {
            uint64_t oldest = ps.hist_next_seq - ps.hist_count;
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "DELETE FROM v2_pool_roots WHERE domain_id=?1 AND "
                    "pool_id=?2 AND seq=?3", -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)oldest);
            rc = sqlite3_step(st);
            int nchg = sqlite3_changes(w->db);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE || nchg != 1) goto fail;
            if (sqlite3_prepare_v2(w->db,
                    "UPDATE v2_pools SET hist_count=hist_count-1 WHERE "
                    "domain_id=?1 AND pool_id=?2", -1, &st, NULL)
                != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)m->domain_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)m->pool_id);
            rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) goto fail;
        }
        STAGE(NODUS_V2_POOL_STAGE_EVICT);
    }

    shielded_tree_free(t);
    free(t);
    return 0;

fail:
    shielded_tree_free(t);
    free(t);
    return -1;
}

/* ── startup verification (S7 correction — full nullifier-log replay
 *    + derived note-table structural shape; contract in the header) ── */

/* Replay ONE pool's ordered nullifier log + check its derived note
 * table. Read-only; @return 0 / -1 (fail closed, nothing mutated). */
static int pool_startup_verify_one(nodus_witness_t *w, uint32_t dom,
                                   uint32_t pool, uint64_t nul_count,
                                   const uint8_t nul_root[64],
                                   uint64_t note_count) {
    /* ── nullifier log: full ordered DNA.PNUL.v1 chain replay ──────── */
    uint8_t acc[DNA_POOL_ROOT_LEN];
    if (dna_pool_nul_empty_root(acc) != 0) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT position, nullifier FROM v2_pool_nullifiers WHERE "
            "domain_id=?1 AND pool_id=?2 ORDER BY position ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool);
    uint64_t expect = 0;
    int rc, fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 pos = sqlite3_column_int64(st, 0);
        const void *nul = sqlite3_column_blob(st, 1);
        if (pos < 0 || (uint64_t)pos != expect ||          /* gap /
                                              first-row!=0 / reorder   */
            !nul ||
            sqlite3_column_bytes(st, 1) != DNA_POOL_NULLIFIER_LEN ||
            !dna_pool_lanes_canonical(nul)) {
            fail = 1;
            break;
        }
        if (dna_pool_nul_step(acc, expect, nul, acc) != 0) {
            fail = 1;
            break;
        }
        expect++;
    }
    if (!fail && rc != SQLITE_DONE) fail = 1;  /* mid-scan fault        */
    sqlite3_finalize(st);
    if (fail) {
        QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) nullifier log corrupt — "
                      "fail closed", dom, pool);
        return -1;
    }
    /* processed rows == committed count; replayed root == committed
     * root (zero rows ⇒ count 0 AND the canonical empty root — both
     * covered by these two checks) */
    if (expect != nul_count ||
        memcmp(acc, nul_root, DNA_POOL_ROOT_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) nullifier log disagrees "
                      "with committed root/count — fail closed", dom,
                      pool);
        return -1;
    }

    /* ── derived note table: structural shape only ─────────────────── */
    uint64_t n = 0;
    if (pool_q1(w, "SELECT COUNT(*) FROM v2_pool_notes WHERE "
                "domain_id=?1 AND pool_id=?2", dom, pool, &n) != 0 ||
        n != note_count)
        return -1;
    if (note_count > 0) {
        if (pool_q1(w, "SELECT COALESCE(MIN(position),1) FROM "
                    "v2_pool_notes WHERE domain_id=?1 AND pool_id=?2",
                    dom, pool, &n) != 0 || n != 0)
            return -1;
        if (pool_q1(w, "SELECT COALESCE(MAX(position),0) FROM "
                    "v2_pool_notes WHERE domain_id=?1 AND pool_id=?2",
                    dom, pool, &n) != 0 || n != note_count - 1)
            return -1;
    }
    if (sqlite3_prepare_v2(w->db,
            "SELECT commitment FROM v2_pool_notes WHERE domain_id=?1 "
            "AND pool_id=?2 ORDER BY position ASC", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool);
    fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *c = sqlite3_column_blob(st, 0);
        if (!c || sqlite3_column_bytes(st, 0) != DNA_POOL_NOTE_LEN ||
            !dna_pool_lanes_canonical(c)) {
            fail = 1;
            break;
        }
    }
    if (!fail && rc != SQLITE_DONE) fail = 1;
    sqlite3_finalize(st);
    if (fail) {
        QGP_LOG_ERROR(LOG_TAG, "pool (%u,%u) derived note table "
                      "malformed — fail closed", dom, pool);
        return -1;
    }
    return 0;
}

int nodus_witness_v2_pools_startup_check(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) return -1;
    if (ver != NODUS_V2_SCHEMA_VERSION_S7 &&
        ver != NODUS_V2_SCHEMA_VERSION_S8 &&
        ver != NODUS_V2_SCHEMA_VERSION_S9 &&
        ver != NODUS_V2_SCHEMA_VERSION_S10 &&
        ver != NODUS_V2_SCHEMA_VERSION_S11 &&
        ver != NODUS_V2_SCHEMA_VERSION_S12)
        return 0;                        /* pre-v7: no pool state (the
                                          * S8 intent schema CONTAINS the
                                          * S7 pool tables — the check
                                          * must keep running there)     */

    /* One consistent read snapshot for the whole pass. SAVEPOINT (not
     * BEGIN) so the pass also composes under a caller-held
     * transaction; standalone it starts an implicit transaction. */
    if (sqlite3_exec(w->db, "SAVEPOINT s7_startup", NULL, NULL, NULL)
        != SQLITE_OK)
        return -1;

    int ret = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT domain_id, pool_id, nul_count, nul_root, note_count "
            "FROM v2_pools ORDER BY domain_id ASC, pool_id ASC",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    int rc;
    ret = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 dom = sqlite3_column_int64(st, 0);
        sqlite3_int64 pool = sqlite3_column_int64(st, 1);
        sqlite3_int64 nc = sqlite3_column_int64(st, 2);
        const void *nr = sqlite3_column_blob(st, 3);
        sqlite3_int64 notes = sqlite3_column_int64(st, 4);
        if (dom < 0 || dom > (sqlite3_int64)UINT32_MAX || pool < 0 ||
            pool > (sqlite3_int64)UINT32_MAX || nc < 0 || notes < 0 ||
            !nr || sqlite3_column_bytes(st, 3) != DNA_POOL_ROOT_LEN) {
            ret = -1;
            break;
        }
        if (pool_startup_verify_one(w, (uint32_t)dom, (uint32_t)pool,
                                    (uint64_t)nc, nr,
                                    (uint64_t)notes) != 0) {
            ret = -1;
            break;
        }
    }
    if (ret == 0 && rc != SQLITE_DONE) ret = -1;
    sqlite3_finalize(st);
done:
    (void)sqlite3_exec(w->db,
                       "ROLLBACK TO s7_startup; RELEASE s7_startup",
                       NULL, NULL, NULL);
    return ret;
}

/* ── pools_root loader ──────────────────────────────────────────────── */

/* Recompute one pool's retained-window history commitment (bounded by
 * the consensus-committed history_limit). */
static int pool_hist_commit(nodus_witness_t *w,
                            const nodus_v2_pool_state_t *ps,
                            uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT seq, note_root FROM v2_pool_roots WHERE domain_id=?1 "
            "AND pool_id=?2 ORDER BY seq ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)ps->cfg.domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)ps->cfg.pool_id);

    size_t cap = (size_t)ps->hist_count ? (size_t)ps->hist_count : 1;
    uint64_t *seqs = malloc(cap * sizeof(*seqs));
    uint8_t (*roots)[DNA_POOL_NOTE_LEN] = malloc(cap * DNA_POOL_NOTE_LEN);
    if (!seqs || !roots) {
        free(seqs); free(roots); sqlite3_finalize(st);
        return -1;
    }
    size_t n = 0;
    int rc, fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) { fail = 1; break; }   /* more rows than committed */
        sqlite3_int64 s = sqlite3_column_int64(st, 0);
        if (s < 0 || sqlite3_column_bytes(st, 1) != DNA_POOL_NOTE_LEN) {
            fail = 1;
            break;
        }
        seqs[n] = (uint64_t)s;
        memcpy(roots[n], sqlite3_column_blob(st, 1), DNA_POOL_NOTE_LEN);
        n++;
    }
    if (!fail && rc != SQLITE_DONE) fail = 1;
    sqlite3_finalize(st);
    int ret = -1;
    if (!fail && n == ps->hist_count)
        ret = dna_pool_hist_commit(
            seqs, (const uint8_t (*)[DNA_POOL_NOTE_LEN])roots, n, out);
    free(seqs);
    free(roots);
    return ret;
}

int nodus_witness_pools_root_v2(nodus_witness_t *w, uint32_t domain_id,
                                uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_pools");
    if (has < 0) return -1;
    if (has == 0)                        /* pre-S7 DB: honest empty leg  */
        return dna_pools_root(domain_id, NULL, 0, out);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pool_id FROM v2_pools WHERE domain_id=?1 "
            "ORDER BY pool_id ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);

    size_t cap = 4, n = 0;
    uint32_t *ids = malloc(cap * sizeof(*ids));
    if (!ids) { sqlite3_finalize(st); return -1; }
    int rc, fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            uint32_t *ni = realloc(ids, nc * sizeof(*ni));
            if (!ni) { fail = 1; break; }
            ids = ni; cap = nc;
        }
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v < 0 || v > (sqlite3_int64)UINT32_MAX) { fail = 1; break; }
        ids[n++] = (uint32_t)v;
    }
    if (!fail && rc != SQLITE_DONE) fail = 1;
    sqlite3_finalize(st);
    if (fail) { free(ids); return -1; }

    int ret = -1;
    dna_pool_leaf_t *leaves = NULL;
    if (n > 0) {
        leaves = calloc(n, sizeof(*leaves));
        if (!leaves) { free(ids); return -1; }
        for (size_t i = 0; i < n; i++) {
            nodus_v2_pool_state_t ps;
            if (nodus_witness_v2_pool_load(w, domain_id, ids[i], &ps)
                != 0)
                goto done;               /* absent mid-scan = fault too  */
            dna_pool_leaf_t *L = &leaves[i];
            L->domain_id = domain_id;
            L->pool_id = ids[i];
            if (dna_pool_config_hash(&ps.cfg, L->config_hash) != 0)
                goto done;
            memcpy(L->note_root, ps.note_root, DNA_POOL_NOTE_LEN);
            L->note_count = ps.note_count;
            memcpy(L->nul_root, ps.nul_root, DNA_POOL_ROOT_LEN);
            L->nul_count = ps.nul_count;
            L->balance = ps.balance;
            if (pool_hist_commit(w, &ps, L->hist_commit) != 0) goto done;
            L->hist_count = ps.hist_count;
            L->hist_next_seq = ps.hist_next_seq;
        }
    }
    ret = dna_pools_root(domain_id, leaves, n, out);
done:
    free(leaves);
    free(ids);
    return ret;
}

/* ── anchor lookup ──────────────────────────────────────────────────── */

int nodus_witness_v2_pool_anchor_check(nodus_witness_t *w,
                                       const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                       uint32_t domain_id,
                                       uint32_t pool_id,
                                       const uint8_t note_root[DNA_POOL_NOTE_LEN]) {
    if (!w || !w->db || !chain_id || !note_root) return -1;
    if (!dna_pool_lanes_canonical(note_root)) return -1;

    /* chain binding: the anchor is only meaningful on THIS chain */
    uint8_t want[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(w, want) != 0) return -1;
    if (memcmp(want, chain_id, DNA_CHAIN_ID_LEN) != 0) return -1;

    /* the pool must exist (verifies domain/pool namespacing) */
    nodus_v2_pool_state_t ps;
    if (nodus_witness_v2_pool_load(w, domain_id, pool_id, &ps) != 0)
        return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_pool_roots WHERE domain_id=?1 AND "
            "pool_id=?2 AND note_root=?3", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pool_id);
    sqlite3_bind_blob(st, 3, note_root, DNA_POOL_NOTE_LEN,
                      SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 0;
    return -1;                           /* absent OR fault: reject      */
}

/* ── per-(domain, asset) balance total ──────────────────────────────── */

int nodus_witness_v2_pool_balance_total(nodus_witness_t *w,
                                        uint32_t domain_id,
                                        const uint8_t *asset_ref,
                                        uint16_t asset_ref_len,
                                        uint64_t *out) {
    if (!w || !w->db || !asset_ref || !out) return -1;
    if (asset_ref_len == 0 || asset_ref_len > DNA_POOL_ASSETREF_MAX)
        return -1;
    *out = 0;

    int has = table_exists(w, "v2_pools");
    if (has < 0) return -1;
    if (has == 0) return 0;              /* pre-S7 DB: honest zero       */

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT balance FROM v2_pools WHERE domain_id=?1 AND "
            "asset_ref=?2 ORDER BY pool_id ASC", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_blob(st, 2, asset_ref, asset_ref_len, SQLITE_TRANSIENT);
    uint64_t total = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 b = sqlite3_column_int64(st, 0);
        if (b < 0) { sqlite3_finalize(st); return -1; }
        if ((uint64_t)b > UINT64_MAX - total) {
            sqlite3_finalize(st);
            return -1;                   /* checked add                  */
        }
        total += (uint64_t)b;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;    /* mid-scan fault ≠ a value     */
    *out = total;
    return 0;
}

/* ── DNA_CORE runtime pool policy ───────────────────────────────────── */

/* The CORE runtime's configured pools (v1: exactly the native D=24
 * shielded pool). The asset_ref is the existing 64-byte token_id
 * namespace; the native DNAC id is 64 zero bytes
 * (nodus_rt_core_asset_check, nodus_witness_v2_claims.c). This table
 * is the ONLY place that knows the native pool's concrete
 * configuration — the generic engine dispatches through state_init. */
static const dna_pool_config_t CORE_POOLS_V1[] = {
    {
        .domain_id      = DNA_DOMAIN_CORE,
        .pool_id        = DNAC_SHIELDED_POOL_V1,
        .config_version = 1,
        .tree_depth     = DNA_POOL_TREE_DEPTH_V1,
        .history_limit  = DNA_POOL_HISTORY_DEVNET_V1,
        .asset_ref_len  = 64,
        .asset_ref      = { 0 },        /* native DNAC token_id          */
    },
};

int nodus_rt_core_state_init(const nodus_domain_runtime_t *rt,
                             struct nodus_witness *wv,
                             uint64_t activation_global_height) {
    nodus_witness_t *w = (nodus_witness_t *)wv;
    if (!rt || !w || !w->db) return -1;

    /* Pool state requires the S7 pool tables (present in S7, S8 and S9 —
     * each later schema CONTAINS the earlier ones) — an activation on an
     * older schema fails closed, never a partial init. */
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        (ver != NODUS_V2_SCHEMA_VERSION_S7 &&
         ver != NODUS_V2_SCHEMA_VERSION_S8 &&
         ver != NODUS_V2_SCHEMA_VERSION_S9 &&
         ver != NODUS_V2_SCHEMA_VERSION_S10 &&
         ver != NODUS_V2_SCHEMA_VERSION_S11 &&
         ver != NODUS_V2_SCHEMA_VERSION_S12))
        return -1;

    for (size_t i = 0;
         i < sizeof(CORE_POOLS_V1) / sizeof(CORE_POOLS_V1[0]); i++) {
        dna_pool_config_t cfg = CORE_POOLS_V1[i];
        cfg.domain_id = rt->domain_id;   /* the runtime's OWN domain     */
        if (nodus_witness_v2_pool_create(w, &cfg,
                                         activation_global_height) != 0)
            return -1;
    }
    return 0;
}
