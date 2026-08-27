/**
 * @file test_v2_pools.c
 * @brief Ledger V2 Season 7 — adversarial suite for the persistent
 *        shielded pool state (INACTIVE).
 *
 * Groups:
 *   1. KATs — outer SHA3-512 tag/preimage literals INDEPENDENTLY
 *      reproduced (python3 hashlib.sha3_512 over the documented
 *      preimages; generation commands recorded inline), codec shape
 *      rejects, frozen S2 empty-pools identity.
 *   2. Genesis + CORE pool + anchors — the configured native pool
 *      (devnet R = 720 pinned through the config KAT), empty-root
 *      bridge identity with the shipped shielded_tree, authoritative
 *      anchor lookup, restart + corruption fail-closed.
 *   3. Append order + determinism — canonical (tx, slot) ordering,
 *      reject matrix, intermediate roots absent, twin-fixture root
 *      identity, reordered outputs diverge.
 *   4. Capacity — synthetic near-capacity frontier: exact last
 *      position succeeds, beyond-capacity and batch-crossing reject
 *      BEFORE any mutation (digest-proven).
 *   5. Nullifiers — strict insert, committed/restart duplicates,
 *      cross-pool + cross-domain non-collision, deterministic
 *      accumulator, order divergence.
 *   6. Root history — one entry per changed final root, quiet batches
 *      add nothing, eviction of exactly the oldest, expired anchors,
 *      rollback restores the evicted root, retained-root reappearance
 *      fails closed.
 *   7. Balance — checked add/sub, overflow/underflow, root ownership
 *      (CORE + global move, SYSTEM does not).
 *   8. Engine — supply-preserving transparent↔pool fixtures, follower
 *      order-divergence reject, twin-DB byte identity, duplicate-batch
 *      reject, S7 fault points F19-F25 with full-DB digest rollback
 *      proof, SYSTEM-only quiet block leaves the pool untouched.
 *   9. Migration — 0→7 / 5→7 / 6→7, idempotency, version 8+ reject,
 *      per-stage fault rollback (digest-proven), column-drift reject.
 *  10. Inactivity — type 11 admission still rejects, types 12-14
 *      unassigned.
 *
 * @file test_v2_pools.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_pools.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"

#include "v2_exec_fixture.h"
#include "v2_genesis_fixture.h"

#include "dnac/pool_wire.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/zk/shielded_tree.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── independently generated KAT literals ──────────────────────────────
 * python3: hashlib.sha3_512 over the EXACT documented preimages
 * (pool_wire.h). Tags are 16-byte zero-padded ASCII; integers BE.
 *   E_POOLS  = sha3_512(tag("DNA.E.POOLS.v1"))          (frozen S2)
 *   E_PNUL   = sha3_512(tag("DNA.E.PNUL.v1"))
 *   E_PHIST  = sha3_512(tag("DNA.E.PHIST.v1"))
 *   CFG_CORE = sha3_512(tag("DNA.POOLCFG.v1") ‖ be32(1) ‖ be32(1) ‖
 *              be32(1) ‖ be8(24) ‖ be32(720) ‖ be16(64) ‖ 64×00)
 *   NULSTEP  = sha3_512(tag("DNA.PNUL.v1") ‖ E_PNUL ‖ be64(0) ‖ 32×01)
 *   HISTSTEP = sha3_512(tag("DNA.PHIST.v1") ‖ E_PHIST ‖ be64(0) ‖ 32×00)
 *   LEAF     = sha3_512(tag("DNA.POOLLEAF.v1") ‖ be32(1) ‖ be32(1) ‖
 *              CFG_CORE ‖ 32×00 ‖ be64(0) ‖ E_PNUL ‖ be64(0) ‖ be64(0) ‖
 *              E_PHIST ‖ be64(1) ‖ be64(1))                            */
static const uint8_t KAT_E_POOLS[64] = {
    0xfb, 0xba, 0x0c, 0x37, 0x85, 0x30, 0xaa, 0x12, 0x14, 0xdb, 0xe5, 0xd8, 0x81, 0x0c, 0x28, 0xb7,
    0x48, 0x7a, 0xba, 0x1b, 0x7c, 0xc6, 0xa4, 0x4c, 0x29, 0x1c, 0x62, 0x36, 0x9d, 0xc1, 0xae, 0x22,
    0x27, 0x27, 0xe0, 0x95, 0x49, 0xef, 0x48, 0xcc, 0x63, 0x8c, 0x7f, 0xac, 0xe4, 0x87, 0x58, 0x96,
    0x4b, 0x43, 0x61, 0x07, 0xb6, 0x61, 0xb9, 0x1d, 0xb8, 0x2f, 0xcb, 0x30, 0x8f, 0x3d, 0x80, 0x42,
};
static const uint8_t KAT_E_PNUL[64] = {
    0xdc, 0x4f, 0xca, 0xe4, 0x33, 0x9f, 0x1f, 0x03, 0xe2, 0x73, 0x15, 0x7e, 0xa9, 0x56, 0x50, 0xf6,
    0xdc, 0x65, 0x2f, 0x8b, 0x64, 0x92, 0xd0, 0x31, 0x9e, 0xc6, 0x17, 0x6e, 0x63, 0xaa, 0x90, 0xf9,
    0x6e, 0x4d, 0x9a, 0x63, 0xd3, 0x5b, 0x02, 0x8e, 0xbb, 0x39, 0xf1, 0x4d, 0x90, 0x9f, 0xa4, 0x5d,
    0xa5, 0xec, 0x9d, 0xfa, 0x4d, 0x83, 0x5c, 0xe3, 0x02, 0xb8, 0x8c, 0xd9, 0x3d, 0x4d, 0x0d, 0x0c,
};
static const uint8_t KAT_E_PHIST[64] = {
    0xf8, 0xa3, 0xed, 0x1d, 0xec, 0x0e, 0xe5, 0xdc, 0x04, 0x2a, 0x07, 0x23, 0x9f, 0xa1, 0x90, 0x38,
    0x5a, 0x29, 0xe7, 0xed, 0x2e, 0xa6, 0x20, 0xf9, 0xd6, 0x03, 0xb8, 0xd1, 0xef, 0x78, 0xf1, 0xab,
    0x03, 0x59, 0xa8, 0xdb, 0xbf, 0x49, 0x94, 0x44, 0xff, 0xd1, 0xdb, 0x84, 0xfe, 0x82, 0xa2, 0x86,
    0x64, 0xab, 0xcd, 0x2b, 0x97, 0xd0, 0x61, 0x02, 0x7b, 0x6e, 0xc8, 0xa1, 0xf1, 0xff, 0xed, 0xbe,
};
static const uint8_t KAT_CFG_CORE[64] = {
    0xdc, 0x7e, 0x92, 0xca, 0xc5, 0x66, 0xea, 0xa1, 0x1c, 0x5b, 0xf2, 0x39, 0x61, 0x87, 0xc3, 0x92,
    0x09, 0xaa, 0xfd, 0xf3, 0x59, 0x28, 0x9f, 0x28, 0x85, 0xe6, 0x08, 0xbd, 0x15, 0x46, 0xc2, 0x4f,
    0xa5, 0xe9, 0xff, 0xed, 0x4f, 0x80, 0x4a, 0x53, 0x1d, 0x46, 0x10, 0x09, 0x29, 0xee, 0xfa, 0x3d,
    0xba, 0x4e, 0x0c, 0x3c, 0xe6, 0xff, 0x86, 0x1c, 0x06, 0x1f, 0x05, 0x96, 0x9e, 0xb9, 0x8c, 0xec,
};
static const uint8_t KAT_NULSTEP[64] = {
    0xe9, 0x13, 0xb7, 0x03, 0xeb, 0x3d, 0x8e, 0xf0, 0x12, 0xb6, 0x8b, 0x52, 0x7e, 0xea, 0x14, 0x12,
    0x63, 0x5c, 0x25, 0x66, 0x3e, 0x19, 0x45, 0xad, 0x30, 0x61, 0x5d, 0x20, 0xef, 0x30, 0x35, 0xd7,
    0xe4, 0x14, 0x80, 0x9b, 0x87, 0x51, 0xe1, 0x82, 0x73, 0x22, 0xd8, 0x36, 0xaa, 0x56, 0x0a, 0x3a,
    0x50, 0x86, 0x00, 0x8e, 0x63, 0x38, 0x95, 0xb8, 0x0f, 0xc3, 0x87, 0xd1, 0xb0, 0x60, 0x94, 0xe9,
};
static const uint8_t KAT_HISTSTEP[64] = {
    0x28, 0x19, 0xba, 0xd3, 0x6c, 0xaf, 0xca, 0x03, 0xa0, 0x17, 0x7e, 0xb5, 0xca, 0x61, 0xd9, 0x94,
    0x60, 0xe5, 0x44, 0x77, 0xcc, 0x46, 0xbd, 0xcb, 0x5d, 0xbd, 0x62, 0x0f, 0x44, 0x5d, 0x0d, 0xf5,
    0x17, 0x7e, 0x31, 0x88, 0xab, 0xee, 0xaa, 0x56, 0x75, 0x2e, 0x9e, 0xe5, 0x13, 0xb1, 0x30, 0xc8,
    0x8d, 0xc1, 0x53, 0xa2, 0x54, 0x60, 0xbc, 0x32, 0x23, 0xca, 0x79, 0x90, 0x72, 0xfd, 0x78, 0x61,
};
static const uint8_t KAT_LEAF[64] = {
    0x94, 0xa8, 0xcc, 0xbb, 0x68, 0x77, 0xf1, 0x44, 0x54, 0xe5, 0xc8, 0xba, 0x59, 0x40, 0xef, 0x1d,
    0x27, 0xb6, 0x2d, 0xcc, 0x3d, 0x03, 0x1f, 0x4b, 0x0b, 0xd9, 0x13, 0x04, 0x2f, 0x5b, 0x58, 0x6d,
    0x66, 0x52, 0x0d, 0x9d, 0x2d, 0x92, 0x51, 0x24, 0x97, 0x26, 0x4e, 0x8c, 0x7d, 0x2b, 0x90, 0x1f,
    0xaa, 0x9d, 0x75, 0x64, 0xd0, 0x75, 0xb1, 0x64, 0xd0, 0xb4, 0xda, 0x79, 0x16, 0xb7, 0x87, 0xc9,
};

/* ── fs + fixture (test_v2_apply.c pattern) ─────────────────────────── */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_pools_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x55, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}
/* silent variant for statements EXPECTED to fail */
static int run_sql_q(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

/* ── full-DB digest (rollback oracle, test_v2_apply.c pattern) ──────── */
typedef struct { uint8_t *buf; size_t len, cap; } dyn_t;

static int dyn_put(dyn_t *d, const void *p, size_t n) {
    if (d->len + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 65536;
        while (nc < d->len + n) nc *= 2;
        uint8_t *nb = realloc(d->buf, nc);
        if (!nb) return -1;
        d->buf = nb; d->cap = nc;
    }
    memcpy(d->buf + d->len, p, n);
    d->len += n;
    return 0;
}

static int db_state_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name NOT LIKE 'sqlite_%' ORDER BY name", -1, &ts, NULL)
        != SQLITE_OK)
        return -1;
    dyn_t d = { 0 };
    int rc, out_rc = -1;
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (dyn_put(&d, name, strlen(name) + 1) != 0) goto done;
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t t = (uint8_t)sqlite3_column_type(rs, c);
                if (dyn_put(&d, &t, 1) != 0) { sqlite3_finalize(rs); goto done; }
                if (t == SQLITE_NULL) continue;
                const void *b = sqlite3_column_blob(rs, c);
                int bl = sqlite3_column_bytes(rs, c);
                uint32_t bl32 = (uint32_t)bl;
                if (dyn_put(&d, &bl32, 4) != 0 ||
                    (bl > 0 && dyn_put(&d, b, (size_t)bl) != 0)) {
                    sqlite3_finalize(rs);
                    goto done;
                }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    out_rc = qgp_sha3_512(d.buf ? d.buf : (const uint8_t *)"", d.len, out)
                 == 0 ? 0 : -1;
done:
    sqlite3_finalize(ts);
    free(d.buf);
    return out_rc;
}

/* ── helpers ────────────────────────────────────────────────────────── */
static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

/* canonical 32-byte value from a small seed (lanes < 2^40 < p) */
static void mk_c(uint64_t seed, uint8_t out[32]) {
    memset(out, 0, 32);
    for (int l = 0; l < 4; l++) {
        uint64_t v = seed * 4 + (uint64_t)l + 1;
        for (int i = 7; i >= 0; i--) {
            out[l * 8 + i] = (uint8_t)(v & 0xff);
            v >>= 8;
        }
    }
}

static void lanes_be(const uint64_t lanes[4], uint8_t out[32]) {
    for (int l = 0; l < 4; l++) {
        uint64_t v = lanes[l];
        for (int i = 7; i >= 0; i--) {
            out[l * 8 + i] = (uint8_t)(v & 0xff);
            v >>= 8;
        }
    }
}

static int genesis(fixture_t *fx) {
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    uint8_t vset[64];
    mk_id(vset, 0x77);
    /* O14: the genesis BlockID is DERIVED by the engine, not chosen. */
    return v2x_genesis_min(fx->w, vset, NULL, NULL);
}

/* one pool batch inside an explicit transaction (module-level tests) */
static int apply_txn(fixture_t *fx, const nodus_v2_pool_mut_t *m,
                     uint64_t h) {
    if (run_sql(fx->w->db, "BEGIN IMMEDIATE") != 0) return -1;
    if (nodus_witness_v2_pool_apply(fx->w, m, h, NULL, NULL) != 0) {
        (void)run_sql(fx->w->db, "ROLLBACK");
        return -1;
    }
    return run_sql(fx->w->db, "COMMIT");
}

static void mk_out(nodus_v2_pool_out_t *o, uint64_t seed, uint32_t tx,
                   uint16_t slot) {
    memset(o, 0, sizeof(*o));
    mk_c(seed, o->commitment);
    o->tx_index = tx;
    o->output_slot = slot;
}

static void mk_in(nodus_v2_pool_in_t *in, uint64_t seed, uint32_t tx,
                  uint16_t slot) {
    memset(in, 0, sizeof(*in));
    mk_c(seed + 0x900000, in->nullifier);
    in->tx_index = tx;
    in->input_slot = slot;
}

static void mut_init(nodus_v2_pool_mut_t *m, uint32_t dom, uint32_t pool) {
    memset(m, 0, sizeof(*m));
    m->domain_id = dom;
    m->pool_id = pool;
}

/* ── 1. KATs + codec shape ──────────────────────────────────────────── */
static int t_kats(void) {
    printf("1: outer-commitment KATs (python-reproduced) + codec shape\n");
    uint8_t got[64];

    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_POOLS, got) == 0 &&
          memcmp(got, KAT_E_POOLS, 64) == 0, "frozen E_POOLS"); OK();
    CHECK(dna_pools_root(1, NULL, 0, got) == 0 &&
          memcmp(got, KAT_E_POOLS, 64) == 0,
          "zero-pool pools_root != frozen S2 empty"); OK();
    CHECK(dna_pool_nul_empty_root(got) == 0 &&
          memcmp(got, KAT_E_PNUL, 64) == 0, "E_PNUL"); OK();
    CHECK(dna_pool_hist_empty(got) == 0 &&
          memcmp(got, KAT_E_PHIST, 64) == 0, "E_PHIST"); OK();

    dna_pool_config_t cfg = {
        .domain_id = 1, .pool_id = 1, .config_version = 1,
        .tree_depth = 24, .history_limit = 720,
        .asset_ref_len = 64, .asset_ref = { 0 },
    };
    CHECK(dna_pool_config_hash(&cfg, got) == 0 &&
          memcmp(got, KAT_CFG_CORE, 64) == 0,
          "CORE native pool config hash (pins devnet R=720)"); OK();

    uint8_t nul[32], root32[32], acc[64];
    memset(nul, 0x01, 32);
    CHECK(dna_pool_nul_step(KAT_E_PNUL, 0, nul, acc) == 0 &&
          memcmp(acc, KAT_NULSTEP, 64) == 0, "nul step"); OK();
    memset(root32, 0, 32);
    CHECK(dna_pool_hist_step(KAT_E_PHIST, 0, root32, acc) == 0 &&
          memcmp(acc, KAT_HISTSTEP, 64) == 0, "hist step"); OK();

    dna_pool_leaf_t L;
    memset(&L, 0, sizeof(L));
    L.domain_id = 1; L.pool_id = 1;
    memcpy(L.config_hash, KAT_CFG_CORE, 64);
    memcpy(L.nul_root, KAT_E_PNUL, 64);
    memcpy(L.hist_commit, KAT_E_PHIST, 64);
    L.hist_count = 1; L.hist_next_seq = 1;
    CHECK(dna_pool_leaf_hash(&L, got) == 0 &&
          memcmp(got, KAT_LEAF, 64) == 0, "pool leaf"); OK();

    /* canonicality: p-1 accepted, p rejected */
    uint8_t b[32];
    memset(b, 0, 32);
    CHECK(dna_pool_lanes_canonical(b) == 1, "zeros canonical"); OK();
    static const uint8_t pm1[8] = {0xFF,0xFF,0xFF,0xFF,0,0,0,0};
    memcpy(b, pm1, 8);
    CHECK(dna_pool_lanes_canonical(b) == 1, "p-1 canonical"); OK();
    static const uint8_t pex[8] = {0xFF,0xFF,0xFF,0xFF,0,0,0,1};
    memcpy(b, pex, 8);
    CHECK(dna_pool_lanes_canonical(b) == 0, "p rejected"); OK();
    CHECK(dna_pool_nul_step(KAT_E_PNUL, 0, b, acc) == -1,
          "non-canonical nullifier step accepted"); OK();
    CHECK(dna_pool_hist_step(KAT_E_PHIST, 0, b, acc) == -1,
          "non-canonical hist root accepted"); OK();

    /* history window contiguity */
    uint64_t seqs2[2] = { 3, 5 };
    uint8_t roots2[2][32];
    memset(roots2, 0, sizeof(roots2));
    CHECK(dna_pool_hist_commit(seqs2, (const uint8_t (*)[32])roots2, 2,
                               acc) == -1,
          "gapped history window accepted"); OK();
    uint64_t seqs3[2] = { 3, 4 };
    CHECK(dna_pool_hist_commit(seqs3, (const uint8_t (*)[32])roots2, 2,
                               acc) == 0,
          "contiguous window rejected"); OK();
    CHECK(dna_pool_hist_commit(NULL, NULL, 0, acc) == 0 &&
          memcmp(acc, KAT_E_PHIST, 64) == 0, "empty window"); OK();

    /* pools_root ordering + ownership */
    dna_pool_leaf_t two[2];
    memcpy(&two[0], &L, sizeof(L));
    memcpy(&two[1], &L, sizeof(L));
    two[0].pool_id = 2; two[1].pool_id = 1;
    CHECK(dna_pools_root(1, two, 2, got) == -1,
          "descending pool order accepted"); OK();
    two[0].pool_id = 1;
    CHECK(dna_pools_root(1, two, 2, got) == -1,
          "duplicate pool id accepted"); OK();
    two[1].pool_id = 2; two[1].domain_id = 9;
    CHECK(dna_pools_root(1, two, 2, got) == -1,
          "foreign-domain pool leaf accepted"); OK();
    two[1].domain_id = 1;
    CHECK(dna_pools_root(1, two, 2, got) == 0, "2-leaf root"); OK();
    return 0;
}

/* ── 2. genesis + CORE pool + anchors + fail-closed load ────────────── */
static int t_core_pool(void) {
    printf("2: genesis CORE pool, bridge identity, anchors, corruption\n");
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    CHECK(genesis(&fx) == 0, "genesis"); OK();

    nodus_v2_pool_state_t ps;
    CHECK(nodus_witness_v2_pool_load(fx.w, DNA_DOMAIN_CORE,
                                     DNAC_SHIELDED_POOL_V1, &ps) == 0,
          "CORE pool absent after genesis"); OK();
    CHECK(ps.cfg.config_version == 1 && ps.cfg.tree_depth == 24 &&
          ps.cfg.history_limit == DNA_POOL_HISTORY_DEVNET_V1 &&
          ps.cfg.history_limit == 720 && ps.cfg.asset_ref_len == 64,
          "CORE pool config"); OK();
    for (int i = 0; i < 64; i++)
        CHECK(ps.cfg.asset_ref[i] == 0, "native asset ref");
    OK();
    uint8_t cfgh[64];
    CHECK(dna_pool_config_hash(&ps.cfg, cfgh) == 0 &&
          memcmp(cfgh, KAT_CFG_CORE, 64) == 0,
          "committed CORE config != python KAT"); OK();
    CHECK(ps.note_count == 0 && ps.nul_count == 0 && ps.balance == 0 &&
          ps.hist_count == 1 && ps.hist_next_seq == 1, "initial state");
    OK();

    /* bridge identity: initial root IS the shipped tree's E_24 */
    uint64_t e24[4];
    uint8_t e24_be[32];
    CHECK(shielded_tree_empty_root(24, e24) == SHIELDED_TREE_OK, "E24");
    lanes_be(e24, e24_be);
    CHECK(memcmp(ps.note_root, e24_be, 32) == 0,
          "initial root != shielded_tree E_24"); OK();
    CHECK(memcmp(ps.nul_root, KAT_E_PNUL, 64) == 0, "initial nul root");
    OK();

    /* anchors */
    uint8_t chain[32];
    CHECK(nodus_witness_v2_chain_id(fx.w, chain) == 0, "chain id");
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 1, e24_be)
          == 0, "initial empty root not accepted"); OK();
    uint8_t bad[32];
    memcpy(bad, e24_be, 32);
    uint8_t chain2[32];
    memcpy(chain2, chain, 32);
    chain2[0] ^= 1;
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain2, 1, 1, e24_be)
          == -1, "wrong chain accepted"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 0, 1, e24_be)
          == -1, "wrong domain accepted"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 9, e24_be)
          == -1, "wrong pool accepted"); OK();
    mk_c(0xF00F, bad);
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 1, bad)
          == -1, "forged root accepted"); OK();
    memcpy(bad, e24_be, 32);
    memset(bad, 0xFF, 8);              /* lane >= p: non-canonical      */
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 1, bad)
          == -1, "non-canonical anchor accepted"); OK();

    /* state_init idempotent-or-conflict */
    size_t nrt = 0;
    const nodus_domain_runtime_t *tab = nodus_runtime_builtin_table(&nrt);
    CHECK(tab && nrt == 2 && tab[1].state_init, "state_init hook");
    CHECK(tab[1].state_init(&tab[1], (struct nodus_witness *)fx.w, 0)
          == 0, "re-init not idempotent"); OK();
    CHECK(run_sql(fx.w->db,
        "UPDATE v2_pools SET config_version=2 WHERE domain_id=1 AND "
        "pool_id=1") == 0, "bump ver");
    CHECK(tab[1].state_init(&tab[1], (struct nodus_witness *)fx.w, 0)
          == -1, "conflicting config tolerated"); OK();
    CHECK(run_sql(fx.w->db,
        "UPDATE v2_pools SET config_version=1 WHERE domain_id=1 AND "
        "pool_id=1") == 0, "restore ver");

    /* restart reproduces */
    CHECK(fx_reopen(&fx) == 0, "reopen");
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0 &&
          memcmp(ps.note_root, e24_be, 32) == 0 && ps.note_count == 0,
          "restart state"); OK();

    /* corruption fails closed (each inside a rolled-back txn) */
    struct { const char *sql; const char *what; } corr[] = {
        { "UPDATE v2_pools SET frontier = x'01' || substr(frontier, 2) "
          "WHERE domain_id=1 AND pool_id=1",
          "non-zero unfilled frontier level tolerated" },
        { "UPDATE v2_pools SET note_count = 3 "
          "WHERE domain_id=1 AND pool_id=1",
          "count drift tolerated" },
        { "UPDATE v2_pools SET note_root = zeroblob(32) "
          "WHERE domain_id=1 AND pool_id=1",
          "root drift tolerated" },
        { "UPDATE v2_pool_roots SET note_root = zeroblob(32) "
          "WHERE domain_id=1 AND pool_id=1 AND seq=0",
          "history/current disagreement tolerated" },
        { "DELETE FROM v2_pool_roots "
          "WHERE domain_id=1 AND pool_id=1 AND seq=0",
          "empty history tolerated" },
        { "UPDATE v2_pools SET hist_count = 900 "
          "WHERE domain_id=1 AND pool_id=1",
          "hist_count > limit tolerated" },
        { "UPDATE v2_pools SET tree_depth = 23 "
          "WHERE domain_id=1 AND pool_id=1",
          "wrong depth tolerated" },
    };
    for (size_t i = 0; i < sizeof(corr) / sizeof(corr[0]); i++) {
        CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(run_sql(fx.w->db, corr[i].sql) == 0, "corrupt");
        CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == -1,
              corr[i].what);
        OK();
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
    }
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0, "intact");
    OK();
    /* absent pool is 1, never silently created */
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 42, &ps) == 1, "absent");
    OK();
    fx_close(&fx);
    return 0;
}

/* ── 3. append order + determinism ──────────────────────────────────── */
static int t_append(void) {
    printf("3: canonical append order, reject matrix, twin identity\n");
    fixture_t fa, fb, fc;
    CHECK(fx_open(&fa) == 0 && genesis(&fa) == 0, "fx a");
    CHECK(fx_open(&fb) == 0 && genesis(&fb) == 0, "fx b");
    CHECK(fx_open(&fc) == 0 && genesis(&fc) == 0, "fx c");

    /* reject matrix (pure shape) */
    nodus_v2_pool_mut_t m;
    nodus_v2_pool_out_t o2[3];
    nodus_v2_pool_in_t i2[2];
    mut_init(&m, 1, 1);
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "no-op batch");
    OK();
    mut_init(&m, 1, 1);
    mk_out(&o2[0], 1, 0, 1);            /* slot must start at 0          */
    m.outs = o2; m.n_outs = 1;
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "slot start 1");
    OK();
    mk_out(&o2[0], 1, 0, 0);
    mk_out(&o2[1], 2, 0, 2);            /* gap                           */
    m.n_outs = 2;
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "slot gap"); OK();
    mk_out(&o2[1], 2, 0, 0);            /* duplicate (tx, slot)          */
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "dup slot"); OK();
    mk_out(&o2[0], 1, 1, 0);
    mk_out(&o2[1], 2, 0, 0);            /* descending tx                 */
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "tx desc"); OK();
    mk_out(&o2[0], 1, 0, 0);
    mk_out(&o2[1], 2, 1, 1);            /* new tx must restart at 0      */
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "tx slot"); OK();
    mk_out(&o2[1], 2, 1, 0);
    memset(o2[1].commitment, 0xFF, 8);  /* non-canonical lane            */
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "non-canonical");
    OK();
    mut_init(&m, 1, 1);
    mk_in(&i2[0], 7, 0, 0);
    mk_in(&i2[1], 7, 0, 1);             /* duplicate nullifier bytes     */
    m.ins = i2; m.n_ins = 2;
    CHECK(nodus_witness_v2_pool_mut_validate(&m) == -1, "in-batch dup");
    OK();

    /* twin batches on a and b: identical canonical mutations */
    nodus_v2_pool_out_t oo[2];
    mk_out(&oo[0], 100, 0, 0);
    mk_out(&oo[1], 101, 0, 1);
    mut_init(&m, 1, 1);
    m.outs = oo; m.n_outs = 2;
    CHECK(apply_txn(&fa, &m, 1) == 0, "apply a"); OK();
    CHECK(apply_txn(&fb, &m, 1) == 0, "apply b"); OK();
    nodus_v2_pool_state_t pa, pb;
    CHECK(nodus_witness_v2_pool_load(fa.w, 1, 1, &pa) == 0, "load a");
    CHECK(nodus_witness_v2_pool_load(fb.w, 1, 1, &pb) == 0, "load b");
    CHECK(memcmp(pa.note_root, pb.note_root, 32) == 0 &&
          pa.note_count == 2 && pb.note_count == 2,
          "twin fixtures diverge"); OK();
    uint8_t ra[64], rb[64];
    CHECK(nodus_witness_pools_root_v2(fa.w, 1, ra) == 0 &&
          nodus_witness_pools_root_v2(fb.w, 1, rb) == 0 &&
          memcmp(ra, rb, 64) == 0, "twin pools_root diverge"); OK();

    /* the intermediate 1-leaf root never enters history */
    {
        shielded_tree_t *t = calloc(1, sizeof(*t));
        CHECK(t && shielded_tree_init(t) == SHIELDED_TREE_OK, "tree");
        uint64_t leaf[4];
        for (int l = 0; l < 4; l++) {
            uint64_t v = 0;
            for (int i = 0; i < 8; i++)
                v = (v << 8) | oo[0].commitment[l * 8 + i];
            leaf[l] = v;
        }
        CHECK(shielded_tree_append(t, leaf, NULL) == SHIELDED_TREE_OK,
              "append");
        uint64_t r1[4];
        uint8_t r1_be[32];
        CHECK(shielded_tree_root(t, r1) == SHIELDED_TREE_OK, "root");
        lanes_be(r1, r1_be);
        shielded_tree_free(t);
        free(t);
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fa.w->db,
              "SELECT COUNT(*) FROM v2_pool_roots WHERE domain_id=1 AND "
              "pool_id=1 AND note_root=?1", -1, &st, NULL) == SQLITE_OK,
              "prep");
        sqlite3_bind_blob(st, 1, r1_be, 32, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int64(st, 0) == 0,
              "intermediate root entered history");
        sqlite3_finalize(st);
        OK();
    }
    CHECK(pa.hist_count == 2 && pa.hist_next_seq == 2,
          "exactly one entry per changed block root"); OK();

    /* different canonical assignment of the SAME commitments diverges */
    nodus_v2_pool_out_t swapped[2];
    memcpy(swapped[0].commitment, oo[1].commitment, 32);
    swapped[0].tx_index = 0; swapped[0].output_slot = 0;
    memcpy(swapped[1].commitment, oo[0].commitment, 32);
    swapped[1].tx_index = 0; swapped[1].output_slot = 1;
    mut_init(&m, 1, 1);
    m.outs = swapped; m.n_outs = 2;
    CHECK(apply_txn(&fc, &m, 1) == 0, "apply c"); OK();
    nodus_v2_pool_state_t pc;
    CHECK(nodus_witness_v2_pool_load(fc.w, 1, 1, &pc) == 0, "load c");
    CHECK(memcmp(pc.note_root, pa.note_root, 32) != 0,
          "reordered outputs produced the same root"); OK();

    /* restart reproduces the appended state */
    CHECK(fx_reopen(&fa) == 0, "reopen");
    nodus_v2_pool_state_t pr;
    CHECK(nodus_witness_v2_pool_load(fa.w, 1, 1, &pr) == 0 &&
          memcmp(pr.note_root, pa.note_root, 32) == 0 &&
          pr.note_count == 2, "restart lost appends"); OK();

    fx_close(&fa); fx_close(&fb); fx_close(&fc);
    return 0;
}

/* ── 4. capacity (synthetic near-cap frontier) ──────────────────────── */
static int t_capacity(void) {
    printf("4: capacity — last position succeeds, beyond rejects\n");
    fixture_t fx;
    CHECK(fx_open(&fx) == 0 && genesis(&fx) == 0, "fixture");

    /* synthetic VALID state at note_count = 2^24 - 1 (all frontier
     * levels meaningful): arbitrary canonical filled values, root
     * recomputed by the mirror walk (leaf-empty at position n; a set
     * bit pairs filled[i] left — shielded_tree.c:80-100). */
    uint64_t count = SHIELDED_TREE_CAPACITY - 1;
    uint8_t frontier[24][32];
    uint64_t filled[24][4];
    for (int i = 0; i < 24; i++) {
        for (int l = 0; l < 4; l++)
            filled[i][l] = (uint64_t)(i * 4 + l + 1);
        lanes_be(filled[i], frontier[i]);
    }
    uint64_t cur[4] = { 0, 0, 0, 0 };   /* E_0 (empty leaf)             */
    for (int i = 0; i < 24; i++)        /* all count bits are 1         */
        note_merkle_compress(filled[i], cur, cur);
    uint8_t root_be[32];
    lanes_be(cur, root_be);

    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(fx.w->db,
          "UPDATE v2_pools SET note_count=?1, note_root=?2, frontier=?3 "
          "WHERE domain_id=1 AND pool_id=1", -1, &st, NULL) == SQLITE_OK,
          "prep");
    sqlite3_bind_int64(st, 1, (sqlite3_int64)count);
    sqlite3_bind_blob(st, 2, root_be, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, frontier, sizeof(frontier),
                      SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "update pool");
    sqlite3_finalize(st);
    CHECK(sqlite3_prepare_v2(fx.w->db,
          "UPDATE v2_pool_roots SET note_root=?1 WHERE domain_id=1 AND "
          "pool_id=1 AND seq=0", -1, &st, NULL) == SQLITE_OK, "prep2");
    sqlite3_bind_blob(st, 1, root_be, 32, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "update hist");
    sqlite3_finalize(st);
    /* one derived tip row so MAX(position) agrees */
    CHECK(sqlite3_prepare_v2(fx.w->db,
          "INSERT INTO v2_pool_notes (domain_id, pool_id, position, "
          "commitment, global_height, tx_index, output_slot) "
          "VALUES (1, 1, ?1, zeroblob(32), 0, 0, 0)", -1, &st, NULL)
          == SQLITE_OK, "prep3");
    sqlite3_bind_int64(st, 1, (sqlite3_int64)(count - 1));
    CHECK(sqlite3_step(st) == SQLITE_DONE, "tip row");
    sqlite3_finalize(st);

    nodus_v2_pool_state_t ps;
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0 &&
          ps.note_count == count, "synthetic near-cap state invalid");
    OK();

    uint8_t dg[64], dg2[64];
    /* a batch CROSSING capacity rejects atomically, before mutation */
    nodus_v2_pool_mut_t m;
    nodus_v2_pool_out_t oo[2];
    mk_out(&oo[0], 500, 0, 0);
    mk_out(&oo[1], 501, 0, 1);
    mut_init(&m, 1, 1);
    m.outs = oo; m.n_outs = 2;
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    CHECK(apply_txn(&fx, &m, 1) == -1, "capacity-crossing batch passed");
    OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "crossing batch mutated state"); OK();

    /* the EXACT last available position succeeds */
    m.n_outs = 1;
    CHECK(apply_txn(&fx, &m, 1) == 0, "last position refused"); OK();
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0 &&
          ps.note_count == SHIELDED_TREE_CAPACITY &&
          memcmp(ps.note_root, root_be, 32) != 0, "full state"); OK();

    /* appending beyond 2^24 rejects BEFORE mutation */
    nodus_v2_pool_out_t o1;
    mk_out(&o1, 502, 0, 0);
    mut_init(&m, 1, 1);
    m.outs = &o1; m.n_outs = 1;
    CHECK(db_state_digest(fx.w, dg) == 0, "digest2");
    CHECK(apply_txn(&fx, &m, 2) == -1, "append past capacity passed");
    OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "over-capacity append mutated state"); OK();
    fx_close(&fx);
    return 0;
}

/* ── 5. nullifiers ──────────────────────────────────────────────────── */
static int t_nullifiers(void) {
    printf("5: nullifier set — strict insert, namespacing, chain\n");
    fixture_t fa, fb;
    CHECK(fx_open(&fa) == 0 && genesis(&fa) == 0, "fx a");
    CHECK(fx_open(&fb) == 0 && genesis(&fb) == 0, "fx b");

    /* second pool in the SAME domain + a pool in ANOTHER domain (the
     * module is generic; registration authority is engine scope) */
    dna_pool_config_t p5 = {
        .domain_id = 1, .pool_id = 5, .config_version = 1,
        .tree_depth = 24, .history_limit = 720,
        .asset_ref_len = 64, .asset_ref = { 0xAB },
    };
    dna_pool_config_t d9 = {
        .domain_id = 9, .pool_id = 1, .config_version = 1,
        .tree_depth = 24, .history_limit = 720,
        .asset_ref_len = 64, .asset_ref = { 0xAB },
    };
    CHECK(run_sql(fa.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_pool_create(fa.w, &p5, 0) == 0, "p5");
    CHECK(nodus_witness_v2_pool_create(fa.w, &d9, 0) == 0, "d9");
    CHECK(run_sql(fa.w->db, "COMMIT") == 0, "commit");

    nodus_v2_pool_mut_t m;
    nodus_v2_pool_in_t ii[2];
    mk_in(&ii[0], 1, 0, 0);
    mk_in(&ii[1], 2, 0, 1);
    mut_init(&m, 1, 1);
    m.ins = ii; m.n_ins = 2;
    CHECK(apply_txn(&fa, &m, 1) == 0, "insert a"); OK();
    CHECK(apply_txn(&fb, &m, 1) == 0, "insert b"); OK();

    nodus_v2_pool_state_t pa, pb;
    CHECK(nodus_witness_v2_pool_load(fa.w, 1, 1, &pa) == 0, "load a");
    CHECK(nodus_witness_v2_pool_load(fb.w, 1, 1, &pb) == 0, "load b");
    CHECK(pa.nul_count == 2 &&
          memcmp(pa.nul_root, pb.nul_root, 64) == 0,
          "nullifier root diverges across nodes"); OK();

    /* test-side chain reproduction */
    uint8_t acc[64];
    CHECK(dna_pool_nul_empty_root(acc) == 0, "empty");
    CHECK(dna_pool_nul_step(acc, 0, ii[0].nullifier, acc) == 0, "s0");
    CHECK(dna_pool_nul_step(acc, 1, ii[1].nullifier, acc) == 0, "s1");
    CHECK(memcmp(acc, pa.nul_root, 64) == 0,
          "committed root != recomputed chain"); OK();

    /* nullifier root changed history? no — root unchanged, no entry */
    CHECK(pa.hist_count == 1 && pa.hist_next_seq == 1,
          "nullifier-only batch consumed the history window"); OK();

    /* committed duplicate rejects; also after restart */
    nodus_v2_pool_in_t one;
    memcpy(&one, &ii[0], sizeof(one));
    mut_init(&m, 1, 1);
    m.ins = &one; m.n_ins = 1;
    CHECK(apply_txn(&fa, &m, 2) == -1, "committed dup accepted"); OK();
    CHECK(fx_reopen(&fa) == 0, "reopen");
    CHECK(apply_txn(&fa, &m, 2) == -1, "dup accepted after restart");
    OK();

    /* the same bytes in another pool / another domain do NOT collide */
    mut_init(&m, 1, 5);
    m.ins = &one; m.n_ins = 1;
    CHECK(apply_txn(&fa, &m, 2) == 0, "cross-pool collision"); OK();
    mut_init(&m, 9, 1);
    m.ins = &one; m.n_ins = 1;
    CHECK(apply_txn(&fa, &m, 2) == 0, "cross-domain collision"); OK();

    /* SQLite uniqueness backstop (strict insert, no OR IGNORE) */
    CHECK(run_sql_q(fa.w->db,
        "INSERT INTO v2_pool_nullifiers (domain_id, pool_id, nullifier, "
        "position, global_height, tx_index, input_slot) "
        "SELECT domain_id, pool_id, nullifier, 99, 9, 9, 9 "
        "FROM v2_pool_nullifiers WHERE domain_id=1 AND pool_id=1 "
        "LIMIT 1") == -1, "PK backstop"); OK();

    /* ANOTHER domain's pool never enters CORE's pools_root */
    uint8_t core_root[64];
    CHECK(nodus_witness_pools_root_v2(fa.w, 1, core_root) == 0, "root");
    uint8_t d9_root[64];
    CHECK(nodus_witness_pools_root_v2(fa.w, 9, d9_root) == 0, "root9");
    CHECK(memcmp(core_root, d9_root, 64) != 0, "domain roots equal");
    OK();

    /* order divergence: swapped input slots → different root */
    fixture_t fcx;
    CHECK(fx_open(&fcx) == 0 && genesis(&fcx) == 0, "fx c");
    nodus_v2_pool_in_t sw[2];
    memcpy(sw[0].nullifier, ii[1].nullifier, 32);
    sw[0].tx_index = 0; sw[0].input_slot = 0;
    memcpy(sw[1].nullifier, ii[0].nullifier, 32);
    sw[1].tx_index = 0; sw[1].input_slot = 1;
    mut_init(&m, 1, 1);
    m.ins = sw; m.n_ins = 2;
    CHECK(apply_txn(&fcx, &m, 1) == 0, "swapped insert"); OK();
    nodus_v2_pool_state_t pcx;
    CHECK(nodus_witness_v2_pool_load(fcx.w, 1, 1, &pcx) == 0, "load c");
    CHECK(memcmp(pcx.nul_root, pa.nul_root, 64) != 0,
          "insertion-order divergence undetectable"); OK();

    fx_close(&fa); fx_close(&fb); fx_close(&fcx);
    return 0;
}

/* ── 6. root history + eviction (limit-3 pool) ──────────────────────── */
static int t_history(void) {
    printf("6: root history — window, eviction, expiry, rollback\n");
    fixture_t fx;
    CHECK(fx_open(&fx) == 0 && genesis(&fx) == 0, "fixture");

    dna_pool_config_t p7 = {
        .domain_id = 1, .pool_id = 7, .config_version = 1,
        .tree_depth = 24, .history_limit = 3,
        .asset_ref_len = 64, .asset_ref = { 0xAB },
    };
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_pool_create(fx.w, &p7, 0) == 0, "create p7");
    CHECK(run_sql(fx.w->db, "COMMIT") == 0, "commit");

    uint8_t chain[32];
    CHECK(nodus_witness_v2_chain_id(fx.w, chain) == 0, "chain");
    nodus_v2_pool_state_t ps;
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 7, &ps) == 0, "load");
    uint8_t r0[32];
    memcpy(r0, ps.note_root, 32);       /* seq 0: canonical empty root  */

    /* four root changes: r1..r4 (each batch = one block's final root) */
    uint8_t roots[5][32];
    memcpy(roots[0], r0, 32);
    for (uint64_t k = 1; k <= 4; k++) {
        nodus_v2_pool_mut_t m;
        nodus_v2_pool_out_t o;
        mk_out(&o, 0x600 + k, 0, 0);
        mut_init(&m, 1, 7);
        m.outs = &o; m.n_outs = 1;
        CHECK(apply_txn(&fx, &m, k) == 0, "change");
        CHECK(nodus_witness_v2_pool_load(fx.w, 1, 7, &ps) == 0, "load");
        memcpy(roots[k], ps.note_root, 32);
    }
    OK();
    /* window after 4 changes with limit 3: retained {r2, r3, r4} */
    CHECK(ps.hist_count == 3 && ps.hist_next_seq == 5, "window shape");
    OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[0])
          == -1, "evicted empty root accepted (expired)"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[1])
          == -1, "evicted r1 accepted (expired)"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[2])
          == 0, "retained r2 rejected"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[4])
          == 0, "current rejected"); OK();

    /* quiet batches consume nothing: balance-only + nullifier-only */
    nodus_v2_pool_mut_t m;
    mut_init(&m, 1, 7);
    m.balance_add = 5;
    CHECK(apply_txn(&fx, &m, 5) == 0, "balance batch"); OK();
    nodus_v2_pool_in_t in1;
    mk_in(&in1, 0x7777, 0, 0);
    mut_init(&m, 1, 7);
    m.ins = &in1; m.n_ins = 1;
    CHECK(apply_txn(&fx, &m, 6) == 0, "nul batch"); OK();
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 7, &ps) == 0 &&
          ps.hist_count == 3 && ps.hist_next_seq == 5,
          "quiet batches consumed the window"); OK();

    /* rollback restores the evicted root and removes the new one */
    uint8_t dg[64], dg2[64];
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    nodus_v2_pool_out_t o5;
    mk_out(&o5, 0x605, 0, 0);
    mut_init(&m, 1, 7);
    m.outs = &o5; m.n_outs = 1;
    CHECK(nodus_witness_v2_pool_apply(fx.w, &m, 7, NULL, NULL) == 0,
          "b5");
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 7, &ps) == 0, "load5");
    uint8_t r5[32];
    memcpy(r5, ps.note_root, 32);
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[2])
          == -1, "r2 still retained inside txn"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, r5)
          == 0, "r5 not retained inside txn"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rollback incomplete"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, roots[2])
          == 0, "rollback lost r2"); OK();
    CHECK(nodus_witness_v2_pool_anchor_check(fx.w, chain, 1, 7, r5)
          == -1, "rolled-back r5 still authoritative"); OK();

    /* a RETAINED root reappearing as the new root fails closed:
     * corrupt the oldest retained entry to the root b5 will produce */
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(fx.w->db,
          "UPDATE v2_pool_roots SET note_root=?1 WHERE domain_id=1 AND "
          "pool_id=7 AND seq=2", -1, &st, NULL) == SQLITE_OK, "prep");
    sqlite3_bind_blob(st, 1, r5, 32, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "corrupt seq2");
    sqlite3_finalize(st);
    CHECK(apply_txn(&fx, &m, 7) == -1,
          "retained-root reappearance tolerated"); OK();
    /* (the corruption also fails the load path — restore it) */
    CHECK(sqlite3_prepare_v2(fx.w->db,
          "UPDATE v2_pool_roots SET note_root=?1 WHERE domain_id=1 AND "
          "pool_id=7 AND seq=2", -1, &st, NULL) == SQLITE_OK, "prep2");
    sqlite3_bind_blob(st, 1, roots[2], 32, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE, "restore seq2");
    sqlite3_finalize(st);
    CHECK(apply_txn(&fx, &m, 7) == 0, "clean b5"); OK();
    fx_close(&fx);
    return 0;
}

/* ── 7. balance + root ownership ────────────────────────────────────── */
static int t_balance(void) {
    printf("7: checked balance, root ownership (CORE moves, SYSTEM not)\n");
    fixture_t fx;
    CHECK(fx_open(&fx) == 0 && genesis(&fx) == 0, "fixture");

    uint8_t sys0[64], core0[64], glob0[64], dom0[64];
    CHECK(nodus_witness_system_root_v2(fx.w, sys0) == 0, "sys0");
    CHECK(nodus_witness_core_root_v2(fx.w, core0) == 0, "core0");
    CHECK(nodus_witness_global_root_v2(fx.w, glob0, dom0, NULL, NULL)
          == 0, "glob0");

    nodus_v2_pool_mut_t m;
    mut_init(&m, 1, 1);
    m.balance_add = 5;
    CHECK(apply_txn(&fx, &m, 1) == 0, "add 5"); OK();
    nodus_v2_pool_state_t ps;
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0 &&
          ps.balance == 5, "balance 5"); OK();

    uint8_t sys1[64], core1[64];
    CHECK(nodus_witness_system_root_v2(fx.w, sys1) == 0, "sys1");
    CHECK(nodus_witness_core_root_v2(fx.w, core1) == 0, "core1");
    CHECK(memcmp(core0, core1, 64) != 0,
          "pool balance did not move the CORE root"); OK();
    CHECK(memcmp(sys0, sys1, 64) == 0,
          "pool balance moved the SYSTEM root"); OK();
    /* (global_root_v2 recomputes from COMMITTED heads — an unapplied
     * module-level mutation must NOT move it; the engine test proves
     * the transitive DomainHead → global movement) */
    uint8_t glob1[64];
    CHECK(nodus_witness_global_root_v2(fx.w, glob1, NULL, NULL, NULL)
          == 0 && memcmp(glob0, glob1, 64) == 0,
          "uncommitted-head global root moved"); OK();

    /* below zero rejects; exact drain succeeds */
    mut_init(&m, 1, 1);
    m.balance_sub = 6;
    CHECK(apply_txn(&fx, &m, 2) == -1, "underflow tolerated"); OK();
    mut_init(&m, 1, 1);
    m.balance_sub = 5;
    CHECK(apply_txn(&fx, &m, 2) == 0, "drain"); OK();
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &ps) == 0 &&
          ps.balance == 0, "drained"); OK();

    /* addition overflow rejects (checked arithmetic; the storage
     * bound is INT64_MAX — SQLite INTEGER is signed 64-bit) */
    CHECK(run_sql(fx.w->db,
        "UPDATE v2_pools SET balance = 9223372036854775806 "
        "WHERE domain_id=1 AND pool_id=1") == 0, "near-max");
    mut_init(&m, 1, 1);
    m.balance_add = 2;
    CHECK(apply_txn(&fx, &m, 3) == -1, "overflow tolerated"); OK();
    CHECK(run_sql(fx.w->db,
        "UPDATE v2_pools SET balance = 0 "
        "WHERE domain_id=1 AND pool_id=1") == 0, "restore");

    /* per-(domain, asset) totals: foreign asset never summed */
    dna_pool_config_t pf = {
        .domain_id = 1, .pool_id = 8, .config_version = 1,
        .tree_depth = 24, .history_limit = 720,
        .asset_ref_len = 64, .asset_ref = { 0xCD },
    };
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_pool_create(fx.w, &pf, 0) == 0, "pf");
    CHECK(run_sql(fx.w->db, "COMMIT") == 0, "commit");
    mut_init(&m, 1, 8);
    m.balance_add = 7;
    CHECK(apply_txn(&fx, &m, 4) == 0, "foreign add"); OK();
    static const uint8_t native[64] = { 0 };
    uint64_t tot = 0;
    CHECK(nodus_witness_v2_pool_balance_total(fx.w, 1, native, 64, &tot)
          == 0 && tot == 0,
          "foreign-asset balance entered the native total"); OK();
    uint8_t foreign[64];
    memset(foreign, 0, 64);
    foreign[0] = 0xCD;
    CHECK(nodus_witness_v2_pool_balance_total(fx.w, 1, foreign, 64, &tot)
          == 0 && tot == 7, "foreign total"); OK();
    /* the supply invariant ignores the foreign-asset pool balance */
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "foreign-asset pool balance broke the DNAC equation"); OK();
    fx_close(&fx);
    return 0;
}

/* ── 8. engine — supply moves, follower reject, faults ──────────────── */
static int seed_small_supply(fixture_t *fx) {
    /* genesis_supply 1000, all of it one CORE utxo → invariant holds */
    if (run_sql(fx->w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, 1000, 0, 0, 1000, x'00', 0)") != 0)
        return -1;
    return run_sql(fx->w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) VALUES (CAST(zeroblob(63)||x'01' AS BLOB), 'fp', "
        "1000, zeroblob(64), zeroblob(63)||x'aa', 0, 0, 0, 0, 1)");
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = 0;
    /* O14 leader mode: identity is DERIVED, never carried. */
    b->envs = envs;
    b->n_envs = n;
}

/* CORE envelope: SET the fixture UTXO (key 63×00 + 0x01) to an ABSOLUTE
 * amount through the typed adapter — the old raw-SQL "UPDATE utxo_set
 * SET amount = N" op, typed. */
static int env_utxo_abs(v2x_env_t *e, uint64_t amount) {
    uint8_t key[64] = { 0 };
    key[63] = 0x01;
    uint8_t val[8];
    for (int i = 0; i < 8; i++)
        val[i] = (uint8_t)(amount >> (56 - 8 * i));
    return v2x_env1(e, 1, 1, V2X_OP_UTXO, DNA_EFFECT_SET,
                    DNA_EFFECT_PRE_EXISTS, key, 64, val, 8);
}

static int t_engine(void) {
    printf("8: engine — supply moves, follower reject, fault points\n");
    fixture_t fe, fe2;
    CHECK(fx_open(&fe) == 0, "fx e");
    CHECK(nodus_witness_db_migrate_v2s9(fe.w) == 0, "migrate");
    CHECK(seed_small_supply(&fe) == 0, "seed");
    uint8_t gid[64], vset[64];
    mk_id(gid, 0xEE);
    mk_id(vset, 0x77);
    CHECK(v2x_genesis_min(fe.w, vset, gid, NULL) == 0, "genesis");
    OK();
    CHECK(fx_open(&fe2) == 0, "fx e2");
    CHECK(nodus_witness_db_migrate_v2s9(fe2.w) == 0, "migrate2");
    CHECK(seed_small_supply(&fe2) == 0, "seed2");
    CHECK(v2x_genesis_min(fe2.w, vset, NULL, NULL) == 0, "genesis2");

    uint8_t sys_pre[64];
    CHECK(nodus_witness_system_root_v2(fe.w, sys_pre) == 0, "sys pre");

    CHECK(v2x_table_init(fe.w) == 0, "scripted table fe");
    CHECK(v2x_table_init(fe2.w) == 0, "scripted table fe2");

    /* block 1: transparent → pool (5 units), one commitment + one
     * nullifier ride along */
    static v2x_env_t eop1;
    CHECK(env_utxo_abs(&eop1, 995) == 0, "eop1");
    nodus_v2_envelope_t vop1 = { eop1.bytes, eop1.len };
    nodus_v2_pool_out_t o1;
    nodus_v2_pool_in_t in1;
    mk_out(&o1, 0x800, 0, 0);
    mk_in(&in1, 0x801, 0, 0);
    nodus_v2_pool_mut_t pm1;
    mut_init(&pm1, 1, 1);
    pm1.outs = &o1; pm1.n_outs = 1;
    pm1.ins = &in1; pm1.n_ins = 1;
    pm1.balance_add = 5;

    nodus_v2_block_t b1;
    mk_block(&b1, 1, &vop1, 1);
    b1.pool_muts = &pm1;
    b1.n_pool_muts = 1;
    CHECK(nodus_witness_v2_apply_block(fe.w, &b1) == 0,
          "transparent→pool block rejected"); OK();
    nodus_v2_pool_state_t ps;
    CHECK(nodus_witness_v2_pool_load(fe.w, 1, 1, &ps) == 0 &&
          ps.balance == 5 && ps.note_count == 1 && ps.nul_count == 1,
          "pool state after block"); OK();
    uint8_t sys_post[64];
    CHECK(nodus_witness_system_root_v2(fe.w, sys_post) == 0, "sys post");
    CHECK(memcmp(sys_pre, sys_post, 64) == 0,
          "pool block moved the SYSTEM root"); OK();

    /* identical canonical mutations on an independent DB → identical
     * committed roots (byte-for-byte) */
    nodus_v2_block_t b1b;
    memcpy(&b1b, &b1, sizeof(b1));
    CHECK(nodus_witness_v2_apply_block(fe2.w, &b1b) == 0, "twin block");
    CHECK(memcmp(b1.out_global_root, b1b.out_global_root, 64) == 0 &&
          memcmp(b1.out_domains_root, b1b.out_domains_root, 64) == 0,
          "independent DBs diverged"); OK();

    /* block 2: pool → transparent (exact reverse) */
    static v2x_env_t eop2;
    CHECK(env_utxo_abs(&eop2, 1000) == 0, "eop2");
    nodus_v2_envelope_t vop2 = { eop2.bytes, eop2.len };
    nodus_v2_pool_mut_t pm2;
    mut_init(&pm2, 1, 1);
    pm2.balance_sub = 5;
    nodus_v2_block_t b2;
    mk_block(&b2, 2, &vop2, 1);
    b2.pool_muts = &pm2;
    b2.n_pool_muts = 1;
    CHECK(nodus_witness_v2_apply_block(fe.w, &b2) == 0,
          "pool→transparent block rejected"); OK();
    CHECK(nodus_witness_v2_pool_load(fe.w, 1, 1, &ps) == 0 &&
          ps.balance == 0, "drained"); OK();

    /* a pool credit WITHOUT the matching transparent debit violates
     * conservation → whole block rolls back (digest-proven) */
    uint8_t dg[64], dg2[64];
    CHECK(db_state_digest(fe.w, dg) == 0, "digest");
    nodus_v2_pool_mut_t pm3;
    mut_init(&pm3, 1, 1);
    pm3.balance_add = 5;
    nodus_v2_block_t b3;
    mk_block(&b3, 3, NULL, 0);
    b3.pool_muts = &pm3;
    b3.n_pool_muts = 1;
    CHECK(nodus_witness_v2_apply_block(fe.w, &b3) == -1,
          "unbacked pool credit committed"); OK();
    CHECK(db_state_digest(fe.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "supply reject leaked state"); OK();

    /* duplicate (domain, pool) batches in ONE block reject */
    nodus_v2_pool_mut_t twins[2];
    mut_init(&twins[0], 1, 1);
    twins[0].balance_add = 1;
    mut_init(&twins[1], 1, 1);
    twins[1].balance_sub = 1;
    nodus_v2_block_t b4;
    mk_block(&b4, 3, NULL, 0);
    b4.pool_muts = twins;
    b4.n_pool_muts = 2;
    CHECK(nodus_witness_v2_apply_block(fe.w, &b4) == -1,
          "duplicate pool batches accepted"); OK();
    /* unregistered owning domain rejects */
    nodus_v2_pool_mut_t pm9;
    mut_init(&pm9, 9, 1);
    pm9.balance_add = 1;
    nodus_v2_block_t b5;
    mk_block(&b5, 3, NULL, 0);
    b5.pool_muts = &pm9;
    b5.n_pool_muts = 1;
    CHECK(nodus_witness_v2_apply_block(fe.w, &b5) == -1,
          "unregistered pool domain accepted"); OK();

    /* follower order-divergence reject: same mutations, different
     * canonical assignment, expected root from the OTHER node */
    {
        static v2x_env_t eop3;
        CHECK(env_utxo_abs(&eop3, 990) == 0, "eop3");
        nodus_v2_envelope_t vop3 = { eop3.bytes, eop3.len };
        nodus_v2_pool_out_t two_a[2], two_b[2];
        mk_out(&two_a[0], 0x810, 0, 0);
        mk_out(&two_a[1], 0x811, 0, 1);
        memcpy(two_b[0].commitment, two_a[1].commitment, 32);
        two_b[0].tx_index = 0; two_b[0].output_slot = 0;
        memcpy(two_b[1].commitment, two_a[0].commitment, 32);
        two_b[1].tx_index = 0; two_b[1].output_slot = 1;
        nodus_v2_pool_mut_t pma, pmb;
        mut_init(&pma, 1, 1);
        pma.outs = two_a; pma.n_outs = 2;
        pma.balance_add = 10;
        mut_init(&pmb, 1, 1);
        pmb.outs = two_b; pmb.n_outs = 2;
        pmb.balance_add = 10;

        nodus_v2_block_t ba;
        mk_block(&ba, 3, &vop3, 1);
        ba.pool_muts = &pma;
        ba.n_pool_muts = 1;
        CHECK(nodus_witness_v2_apply_block(fe.w, &ba) == 0, "leader");
        OK();
        nodus_v2_block_t bb;
        mk_block(&bb, 2, &vop3, 1);     /* fe2 is at height 1            */
        /* O14: prev and id are both derived from committed state. */
        bb.pool_muts = &pmb;
        bb.n_pool_muts = 1;
        bb.expect_global_root = ba.out_global_root;
        CHECK(nodus_witness_v2_apply_block(fe2.w, &bb) == -1,
              "order divergence not caught by root expectation"); OK();
    }

    /* SYSTEM-only quiet block: pool row, history and CORE head height
     * are untouched */
    {
        uint64_t core_h_pre = 0, core_h_post = 0;
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fe.w->db,
              "SELECT domain_height FROM v2_domain_heads WHERE "
              "domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "row");
        core_h_pre = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        nodus_v2_pool_state_t pre_ps, post_ps;
        CHECK(nodus_witness_v2_pool_load(fe.w, 1, 1, &pre_ps) == 0,
              "pre");
        static v2x_env_t esop;
        {
            uint8_t skey[12];
            v2x_put32(skey, 2);
            v2x_put64(skey + 4, 999991);
            uint8_t sval[8];
            v2x_put64(sval, 5);
            CHECK(v2x_env1(&esop, 0, 1, V2X_OP_CC, DNA_EFFECT_CREATE,
                           DNA_EFFECT_PRE_ABSENT, skey, 12, sval, 8)
                      == 0, "esop");
        }
        nodus_v2_envelope_t vsop = { esop.bytes, esop.len };
        nodus_v2_block_t bs;
        mk_block(&bs, 4, &vsop, 1);
        /* O14: prev derived from the committed parent. */
        CHECK(nodus_witness_v2_apply_block(fe.w, &bs) == 0, "sys block");
        OK();
        CHECK(sqlite3_prepare_v2(fe.w->db,
              "SELECT domain_height FROM v2_domain_heads WHERE "
              "domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep2");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "row2");
        core_h_post = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        CHECK(core_h_pre == core_h_post,
              "quiet block advanced the CORE domain"); OK();
        CHECK(nodus_witness_v2_pool_load(fe.w, 1, 1, &post_ps) == 0 &&
              memcmp(pre_ps.note_root, post_ps.note_root, 32) == 0 &&
              pre_ps.hist_next_seq == post_ps.hist_next_seq &&
              pre_ps.balance == post_ps.balance,
              "quiet block touched the pool"); OK();
    }

    /* S7 fault points F19-F25: full-DB digest restored on every one.
     * The batch exercises every stage: commits + frontier + nulls +
     * nul root + balance + history + eviction (drive the CORE pool's
     * history? limit is 720 — use the foreign-asset limit-3 pool
     * created pre-genesis in module tests? Here: create a limit-3
     * pool INSIDE committed state first (its own block is not needed
     * — direct create + the pool joins CORE's pools_root; the next
     * block's untouched-domain guard would flag CORE... so commit the
     * creation THROUGH a block-visible path: create pre-genesis is
     * impossible now — instead run THREE root-changing blocks on the
     * CORE pool after temporarily shrinking its history_limit is a
     * config mutation — NOT allowed. Simplest sound route: a fresh
     * fixture whose genesis pool table gains a limit-3 foreign-asset
     * pool BEFORE genesis, exactly like the module tests). */
    fixture_t ff;
    CHECK(fx_open(&ff) == 0, "fx f");
    CHECK(nodus_witness_db_migrate_v2s9(ff.w) == 0, "migrate f");
    CHECK(seed_small_supply(&ff) == 0, "seed f");
    {
        /* pre-genesis: create the limit-3 pool so the genesis CORE
         * payload commits it (generic: any runtime could have done
         * this in its own state_init) */
        dna_pool_config_t p7 = {
            .domain_id = 1, .pool_id = 7, .config_version = 1,
            .tree_depth = 24, .history_limit = 3,
            .asset_ref_len = 64, .asset_ref = { 0xAB },
        };
        CHECK(run_sql(ff.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_v2_pool_create(ff.w, &p7, 0) == 0, "p7");
        CHECK(run_sql(ff.w->db, "COMMIT") == 0, "commit");
    }
    CHECK(v2x_genesis_min(ff.w, vset, gid, NULL) == 0,
          "genesis f");
    /* drive the pool to its history limit with three blocks */
    for (uint64_t k = 1; k <= 3; k++) {
        nodus_v2_pool_out_t o;
        mk_out(&o, 0x900 + k, 0, 0);
        nodus_v2_pool_mut_t pm;
        mut_init(&pm, 1, 7);
        pm.outs = &o; pm.n_outs = 1;
        nodus_v2_block_t bk;
        mk_block(&bk, k, NULL, 0);
        bk.pool_muts = &pm;
        bk.n_pool_muts = 1;
        CHECK(nodus_witness_v2_apply_block(ff.w, &bk) == 0, "warm");
    }
    CHECK(nodus_witness_v2_pool_load(ff.w, 1, 7, &ps) == 0 &&
          ps.hist_count == 3, "warmed to limit"); OK();

    nodus_v2_pool_out_t fo[2];
    nodus_v2_pool_in_t fi;
    mk_out(&fo[0], 0x910, 0, 0);
    mk_out(&fo[1], 0x911, 0, 1);
    mk_in(&fi, 0x912, 0, 0);
    nodus_v2_pool_mut_t fpm;
    mut_init(&fpm, 1, 7);
    fpm.outs = fo; fpm.n_outs = 2;
    fpm.ins = &fi; fpm.n_ins = 1;
    /* balance stays 0-sum against supply: foreign asset — free */
    fpm.balance_add = 1;

    static const nodus_v2_apply_fail_t points[] = {
        V2AP_FAIL_AFTER_POOL_COMMITS, V2AP_FAIL_AFTER_POOL_FRONTIER,
        V2AP_FAIL_AFTER_POOL_NULLS, V2AP_FAIL_AFTER_POOL_NULROOT,
        V2AP_FAIL_AFTER_POOL_BALANCE, V2AP_FAIL_AFTER_POOL_HISTORY,
        V2AP_FAIL_AFTER_POOL_EVICT,
    };
    CHECK(db_state_digest(ff.w, dg) == 0, "digest f");
    for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
        nodus_v2_block_t bf;
        mk_block(&bf, 4, NULL, 0);
        /* O14: prev derived from the committed parent. */
        bf.pool_muts = &fpm;
        bf.n_pool_muts = 1;
        bf.fail_at = points[i];
        bf.fail_pool_index = 0;
        CHECK(nodus_witness_v2_apply_block(ff.w, &bf) == -1,
              "fault point did not abort"); OK();
        CHECK(db_state_digest(ff.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0,
              "fault point leaked state (digest)"); OK();
    }
    /* the clean run commits — the eviction really happened */
    nodus_v2_block_t bf;
    mk_block(&bf, 4, NULL, 0);
    /* O14: prev derived from the committed parent. */
    bf.pool_muts = &fpm;
    bf.n_pool_muts = 1;
    CHECK(nodus_witness_v2_apply_block(ff.w, &bf) == 0, "clean"); OK();
    CHECK(nodus_witness_v2_pool_load(ff.w, 1, 7, &ps) == 0 &&
          ps.hist_count == 3 && ps.hist_next_seq == 5 &&
          ps.balance == 1, "post-fault state"); OK();

    fx_close(&fe); fx_close(&fe2); fx_close(&ff);
    return 0;
}

/* ── 9. migration matrix ────────────────────────────────────────────── */
static int t_migration(void) {
    printf("9: v6→v7 migration — matrix, faults, drift\n");
    uint32_t ver = 0;

    /* fresh 0 → 7, idempotent, 8+ rejects */
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fx");
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 0,
          "fresh version"); OK();
    CHECK(nodus_witness_db_migrate_v2s7(fx.w) == 0, "0→7"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 7,
          "version 7"); OK();
    uint8_t dg[64], dg2[64];
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    CHECK(nodus_witness_db_migrate_v2s7(fx.w) == 0, "re-run"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "idempotent re-run mutated state"); OK();
    CHECK(run_sql(fx.w->db, "PRAGMA user_version = 8") == 0, "v8");
    CHECK(nodus_witness_db_migrate_v2s7(fx.w) == -1,
          "version 8 migrated"); OK();
    CHECK(nodus_witness_db_migrate_v2s5(fx.w) == -1,
          "S5 touched a v8 database"); OK();
    CHECK(nodus_witness_db_migrate_v2s6(fx.w) == -1,
          "S6 touched a v8 database"); OK();
    fx_close(&fx);

    /* 5 → 7 and 6 → 7 */
    fixture_t f5;
    CHECK(fx_open(&f5) == 0, "f5");
    CHECK(nodus_witness_db_migrate_v2s5(f5.w) == 0, "0→5");
    CHECK(nodus_witness_db_migrate_v2s7(f5.w) == 0, "5→7"); OK();
    CHECK(nodus_witness_db_schema_version(f5.w, &ver) == 0 && ver == 7,
          "5→7 version"); OK();
    fx_close(&f5);
    fixture_t f6;
    CHECK(fx_open(&f6) == 0, "f6");
    CHECK(nodus_witness_db_migrate_v2s6(f6.w) == 0, "0→6");

    /* per-stage fault rollback at v6 (digest-proven) */
    CHECK(db_state_digest(f6.w, dg) == 0, "digest6");
    static const nodus_v2s7_mig_fail_t stages[] = {
        V2S7MIG_FAIL_AFTER_BEGIN, V2S7MIG_FAIL_AFTER_TABLES,
        V2S7MIG_FAIL_AFTER_VERIFY, V2S7MIG_FAIL_BEFORE_COMMIT,
    };
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        CHECK(nodus_witness_db_migrate_v2s7_ex(f6.w, stages[i]) == -1,
              "stage fault survived"); OK();
        CHECK(nodus_witness_db_schema_version(f6.w, &ver) == 0 &&
              ver == 6, "fault left a non-v6 version"); OK();
        CHECK(db_state_digest(f6.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0, "fault leaked state"); OK();
    }
    CHECK(nodus_witness_db_migrate_v2s7(f6.w) == 0, "6→7"); OK();
    fx_close(&f6);

    /* column drift: a wrong-shape v2_pools at v6 rejects the migration
     * and the database stays a valid v6 */
    fixture_t fd;
    CHECK(fx_open(&fd) == 0, "fd");
    CHECK(nodus_witness_db_migrate_v2s6(fd.w) == 0, "0→6 d");
    CHECK(run_sql(fd.w->db,
        "CREATE TABLE v2_pools (wrong INTEGER)") == 0, "drift");
    CHECK(nodus_witness_db_migrate_v2s7(fd.w) == -1,
          "column drift migrated"); OK();
    CHECK(nodus_witness_db_schema_version(fd.w, &ver) == 0 && ver == 6,
          "drift left a non-v6 version"); OK();
    CHECK(run_sql(fd.w->db, "DROP TABLE v2_pools") == 0, "drop");
    CHECK(nodus_witness_db_migrate_v2s7(fd.w) == 0, "post-drift 6→7");
    OK();
    fx_close(&fd);
    return 0;
}

/* ── 10. inactivity boundary ────────────────────────────────────────── */
static int t_inactivity(void) {
    printf("10: inactivity — type 11 REJECT, 12-14 unassigned\n");
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    CHECK(t && n == 2, "table");
    const nodus_domain_runtime_t *core = &t[1];
    CHECK(core->domain_id == DNA_DOMAIN_CORE, "core slot");
    CHECK(core->admit(core, 11, DNAC_SHIELDED_POOL_V1) == -1,
          "type 11 admitted (C3 stop broken)"); OK();
    CHECK(core->admit(core, 11, DNA_POOL_NONE) == -1,
          "type 11 admitted without pool"); OK();
    /* S9: 12/13 are assigned (SHIELD/UNSHIELD, DNA_CORE, V3-only, REJECT until
     * activation). Since W4 the CORE descriptor OWNS them, so admission no
     * longer fails on non-ownership — it fails on the explicit hard stop in
     * rt_admit_common, which covers 11/12/13 and runs BEFORE the pool rule. */
    CHECK(dna_tx_type_owner(12) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(13) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(14) == DNA_TX_OWNER_NONE,
          "types 12-14 ownership (S9)"); OK();
    CHECK(core->admit(core, 12, DNAC_SHIELDED_POOL_V1) == -1 &&
          core->admit(core, 13, DNAC_SHIELDED_POOL_V1) == -1,
          "types 12/13 admitted (S9 REJECT posture broken)"); OK();
    CHECK(nodus_witness_runtime_selfcheck() == 0, "selfcheck"); OK();
    return 0;
}

/* ── 11. S7 correction pass — preimage lengths + startup verification ─ */

/* Manual field-by-field reconstruction of the two preimages, proving
 * the declared lengths (config: 35 fixed + asset_len, tag INCLUDED;
 * leaf: 272-byte field payload, 288-byte complete preimage). */
static int t_corr_preimage(void) {
    printf("11a: exact preimage lengths (config 99 / leaf 288)\n");
    static const uint8_t TAG_CFG[16] = "DNA.POOLCFG.v1\0";
    static const uint8_t TAG_LEAF[16] = "DNA.POOLLEAF.v1";

    /* config: the CORE-native pool (dom 1, pool 1, ver 1, depth 24,
     * limit 720, 64-zero-byte asset) — 99 bytes INCLUDING the tag */
    uint8_t cpre[99];
    size_t off = 0;
    memcpy(cpre + off, TAG_CFG, 16);                     off += 16;
    static const uint8_t be1[4] = { 0, 0, 0, 1 };
    memcpy(cpre + off, be1, 4);                          off += 4; /*dom*/
    memcpy(cpre + off, be1, 4);                          off += 4; /*pool*/
    memcpy(cpre + off, be1, 4);                          off += 4; /*ver*/
    cpre[off++] = 24;                                    /* depth      */
    static const uint8_t be720[4] = { 0, 0, 0x02, 0xD0 };
    memcpy(cpre + off, be720, 4);                        off += 4;
    cpre[off++] = 0; cpre[off++] = 64;                   /* asset_len  */
    CHECK(off == DNA_POOL_CFG_PREIMAGE_FIXED_LEN && off == 35,
          "config fixed-part length != 35"); OK();
    memset(cpre + off, 0, 64);                           off += 64;
    CHECK(off == sizeof(cpre) && off == 99,
          "config total preimage != 99"); OK();
    uint8_t got[64];
    CHECK(qgp_sha3_512(cpre, off, got) == 0 &&
          memcmp(got, KAT_CFG_CORE, 64) == 0,
          "manual 99-byte config preimage != dna_pool_config_hash KAT");
    OK();

    /* leaf: the synthetic KAT leaf — 288 bytes INCLUDING the tag */
    uint8_t lpre[DNA_POOL_LEAF_PREIMAGE_LEN];
    CHECK(sizeof(lpre) == 288 && DNA_POOL_LEAF_PAYLOAD_LEN == 272,
          "declared leaf lengths wrong"); OK();
    off = 0;
    memcpy(lpre + off, TAG_LEAF, 16);                    off += 16;
    memcpy(lpre + off, be1, 4);                          off += 4;
    memcpy(lpre + off, be1, 4);                          off += 4;
    memcpy(lpre + off, KAT_CFG_CORE, 64);                off += 64;
    memset(lpre + off, 0, 32);                           off += 32;
    memset(lpre + off, 0, 8);                            off += 8;
    memcpy(lpre + off, KAT_E_PNUL, 64);                  off += 64;
    memset(lpre + off, 0, 8);                            off += 8;
    memset(lpre + off, 0, 8);                            off += 8;
    memcpy(lpre + off, KAT_E_PHIST, 64);                 off += 64;
    memset(lpre + off, 0, 8); lpre[off + 7] = 1;         off += 8;
    memset(lpre + off, 0, 8); lpre[off + 7] = 1;         off += 8;
    CHECK(off == DNA_POOL_LEAF_PREIMAGE_LEN,
          "final leaf write offset != declared 288"); OK();
    CHECK(qgp_sha3_512(lpre, off, got) == 0 &&
          memcmp(got, KAT_LEAF, 64) == 0,
          "manual 288-byte leaf preimage != dna_pool_leaf_hash KAT");
    OK();
    return 0;
}

/* startup verification: full nullifier-log replay + derived note-table
 * shape; corruption scenarios each prove fail-close WITHOUT mutation. */
static int t_corr_startup(void) {
    printf("11b: startup verification — corruption matrix\n");
    fixture_t fx;
    CHECK(fx_open(&fx) == 0 && genesis(&fx) == 0, "fixture");

    /* second pool (foreign asset, zero nullifiers) for the empty-table
     * and pool-isolation scenarios */
    dna_pool_config_t p5 = {
        .domain_id = 1, .pool_id = 5, .config_version = 1,
        .tree_depth = 24, .history_limit = 720,
        .asset_ref_len = 64, .asset_ref = { 0xAB },
    };
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_pool_create(fx.w, &p5, 0) == 0, "p5");
    CHECK(run_sql(fx.w->db, "COMMIT") == 0, "commit");

    /* CORE pool: 2 commitments + 3 nullifiers */
    nodus_v2_pool_out_t oo[2];
    nodus_v2_pool_in_t ii[3];
    mk_out(&oo[0], 0xA10, 0, 0);
    mk_out(&oo[1], 0xA11, 0, 1);
    mk_in(&ii[0], 0xA20, 1, 0);
    mk_in(&ii[1], 0xA21, 1, 1);
    mk_in(&ii[2], 0xA22, 1, 2);
    nodus_v2_pool_mut_t m;
    mut_init(&m, 1, 1);
    m.outs = oo; m.n_outs = 2;
    m.ins = ii; m.n_ins = 3;
    CHECK(apply_txn(&fx, &m, 1) == 0, "seed batch"); OK();

    /* valid database: the check passes and the PRODUCTION path
     * (create_chain_db on reopen) accepts it */
    CHECK(nodus_witness_v2_pools_startup_check(fx.w) == 0,
          "valid state rejected"); OK();
    CHECK(fx_reopen(&fx) == 0, "valid restart refused"); OK();
    CHECK(nodus_witness_v2_pools_startup_check(fx.w) == 0,
          "valid state rejected post-restart"); OK();

    /* corruption matrix — each inside a rolled-back txn: corrupt,
     * digest, check MUST fail, digest unchanged (no mutation/repair),
     * rollback, check green again */
    static const struct { const char *sql; const char *what; } corr[] = {
        { "DELETE FROM v2_pool_nullifiers WHERE domain_id=1 AND "
          "pool_id=1 AND position=1",
          "interior nullifier deletion tolerated" },
        { "DELETE FROM v2_pool_nullifiers WHERE domain_id=1 AND "
          "pool_id=1 AND position=0",
          "first-row deletion tolerated" },
        { "DELETE FROM v2_pool_nullifiers WHERE domain_id=1 AND "
          "pool_id=1 AND position=2",
          "final-row deletion tolerated" },
        { "UPDATE v2_pool_nullifiers SET position=7 WHERE domain_id=1 "
          "AND pool_id=1 AND position=2",
          "position gap tolerated" },
        { "UPDATE v2_pool_nullifiers SET nullifier=zeroblob(31)||x'02' "
          "WHERE domain_id=1 AND pool_id=1 AND position=1",
          "modified nullifier bytes tolerated" },
        { "UPDATE v2_pool_nullifiers SET "
          "nullifier=x'FFFFFFFFFFFFFFFF'||zeroblob(24) "
          "WHERE domain_id=1 AND pool_id=1 AND position=1",
          "non-canonical nullifier tolerated" },
        { "UPDATE v2_pools SET nul_count=2 WHERE domain_id=1 AND "
          "pool_id=1",
          "nul_count too small tolerated" },
        { "UPDATE v2_pools SET nul_count=4 WHERE domain_id=1 AND "
          "pool_id=1",
          "nul_count too large tolerated" },
        { "UPDATE v2_pools SET nul_root=zeroblob(64) WHERE domain_id=1 "
          "AND pool_id=1",
          "modified nul_root tolerated" },
        /* empty table + non-empty root (pool 5 has zero rows) */
        { "UPDATE v2_pools SET nul_root=zeroblob(64) WHERE domain_id=1 "
          "AND pool_id=5",
          "empty table with non-empty root tolerated" },
        /* non-empty table + empty root/count (rows remain) */
        { "UPDATE v2_pools SET nul_count=0, nul_root="
          "x'dc4fcae4339f1f03e273157ea95650f6dc652f8b6492d0319ec6176e63aa90f9"
          "6e4d9a63d35b028ebb39f14d909fa45da5ec9dfa4d835ce302b88cd93d4d0d0c'"
          " WHERE domain_id=1 AND pool_id=1",
          "non-empty table with empty root tolerated" },
        /* derived note table: interior deletion / shifted position /
         * short commitment / non-canonical commitment */
        { "DELETE FROM v2_pool_notes WHERE domain_id=1 AND pool_id=1 "
          "AND position=0",
          "note interior deletion tolerated" },
        { "UPDATE v2_pool_notes SET position=5 WHERE domain_id=1 AND "
          "pool_id=1 AND position=1",
          "note position shift tolerated" },
        { "UPDATE v2_pool_notes SET commitment=zeroblob(31) WHERE "
          "domain_id=1 AND pool_id=1 AND position=0",
          "short note commitment tolerated" },
        { "UPDATE v2_pool_notes SET "
          "commitment=x'FFFFFFFFFFFFFFFF'||zeroblob(24) WHERE "
          "domain_id=1 AND pool_id=1 AND position=0",
          "non-canonical note commitment tolerated" },
    };
    uint8_t d1[64], d2[64];
    for (size_t i = 0; i < sizeof(corr) / sizeof(corr[0]); i++) {
        CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(run_sql(fx.w->db, corr[i].sql) == 0, "corrupt");
        CHECK(db_state_digest(fx.w, d1) == 0, "digest");
        CHECK(nodus_witness_v2_pools_startup_check(fx.w) == -1,
              corr[i].what);
        OK();
        CHECK(db_state_digest(fx.w, d2) == 0 &&
              memcmp(d1, d2, 64) == 0,
              "startup check mutated/repaired state"); OK();
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
        CHECK(nodus_witness_v2_pools_startup_check(fx.w) == 0,
              "state not restored");
    }

    /* pool isolation: while pool 5 is corrupted the whole-DB check
     * fails; restoring pool 5 (CORE untouched throughout) passes —
     * one pool's corruption never repairs or masks another's state */
    nodus_v2_pool_state_t core_before;
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &core_before) == 0,
          "core load");
    CHECK(run_sql(fx.w->db,
        "UPDATE v2_pools SET nul_root=zeroblob(64) WHERE domain_id=1 "
        "AND pool_id=5") == 0, "corrupt p5");
    CHECK(nodus_witness_v2_pools_startup_check(fx.w) == -1,
          "corrupt sibling pool tolerated"); OK();
    /* PRODUCTION path: the committed corruption makes the DB open
     * itself refuse (create_chain_db → startup check → fail closed) */
    CHECK(fx_reopen(&fx) != 0,
          "production open accepted a corrupt pool DB"); OK();
    /* reopen a RAW handle (bypassing the witness gate) purely to
     * restore the fixture, then prove the production path recovers */
    {
        char dbp[512];
        snprintf(dbp, sizeof(dbp),
                 "%s/witness_55555555555555555555555555555555.db",
                 fx.dir);
        sqlite3 *raw = NULL;
        CHECK(sqlite3_open(dbp, &raw) == SQLITE_OK, "raw open");
        uint8_t nr[64];
        CHECK(dna_pool_nul_empty_root(nr) == 0, "empty root");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(raw,
              "UPDATE v2_pools SET nul_root=?1 WHERE domain_id=1 AND "
              "pool_id=5", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, nr, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore p5");
        sqlite3_finalize(st);
        sqlite3_close(raw);
    }
    CHECK(fx_reopen(&fx) == 0, "restored DB refused"); OK();
    CHECK(nodus_witness_v2_pools_startup_check(fx.w) == 0, "green");
    OK();
    nodus_v2_pool_state_t core_after;
    CHECK(nodus_witness_v2_pool_load(fx.w, 1, 1, &core_after) == 0 &&
          memcmp(&core_before, &core_after, sizeof(core_after)) == 0,
          "CORE pool state changed across the corruption cycle"); OK();

    fx_close(&fx);
    return 0;
}

int main(void) {
    /* O15J Faz 2 — this file pins POOL-ROOT ISOLATION ("a pool block must
     * not move the SYSTEM root"). A mint moves epoch_state, a SYSTEM leg,
     * on every block, so that property is inexpressible with inflation on.
     * Quiet chain; emission is covered by test_v2_econ. */
    v2x_inflation_off = 1;

    if (t_kats()) return 1;
    if (t_core_pool()) return 1;
    if (t_append()) return 1;
    if (t_capacity()) return 1;
    if (t_nullifiers()) return 1;
    if (t_history()) return 1;
    if (t_balance()) return 1;
    if (t_engine()) return 1;
    if (t_migration()) return 1;
    if (t_inactivity()) return 1;
    if (t_corr_preimage()) return 1;
    if (t_corr_startup()) return 1;
    printf("test_v2_pools: ALL OK (%d checks)\n", g_checks);
    return 0;
}
