/**
 * Nodus — Ledger V2 O12 S2: the ENGINE-MANDATORY epoch-boundary
 * transition (nodus_witness_v2_epoch.{h,c}) driven through the real
 * (INACTIVE) V2 apply engine.
 *
 * Sections:
 *   §1  DERIVATION MATRIX — the boundary fires exactly at H % E == 0 for
 *       H > 0; genesis does not fire; E−1 / E+1 do not fire; the module
 *       is a no-op on every non-boundary height (DB digest byte-identical);
 *       and the H + DNAC_UNSTAKE_COOLDOWN_BLOCKS storage-bound guard is
 *       fail-closed at a representable near-INT64_MAX multiple of E.
 *   §2  GRADUATION — a RETIRING row graduates at the boundary and NOT
 *       one block before; the release UTXO carries the record's ACTUAL
 *       bond (seeded ABOVE DNAC_SELF_STAKE_AMOUNT so the macro cannot
 *       pass by accident), the independently recomputed grad_id as
 *       tx_hash, the recomputed nullifier as the row key, the
 *       destination fp as owner, unlock H + cooldown, index 200,
 *       domain CORE, created_at 0; the bond zeroes, the status becomes
 *       UNSTAKED, everything else on the row is byte-unchanged,
 *       active_count drops by exactly one, and the supply gate is GREEN.
 *   §3  NO DOUBLE GRADUATION — byte-identical replay of the boundary
 *       block is rc 1 with a byte-identical digest, and the NEXT
 *       boundary does not re-graduate an UNSTAKED row.
 *   §4  PENDING COMMISSION — activates at ITS OWN pending_effective_block
 *       boundary, never one epoch early.
 *   §5  FLIPS — a bonded validator absent from the frozen snapshot is
 *       demoted to ELIGIBLE while snapshot members stay ACTIVE, and the
 *       pass-2 `AND status = ELIGIBLE` predicate refuses to resurrect a
 *       snapshot member that has since left the bonded states.
 *   §6  MULTIPLE GRADUATES — two RETIRING rows in one boundary get
 *       distinct per-record grad_ids, both release, active_count drops
 *       by two, and seeding the validators in the OPPOSITE order across
 *       two independent fixtures yields byte-identical consensus roots.
 *   §7  COMMIT_NEXT — the snapshot for the next-next epoch exists,
 *       decodes and hash-verifies; an independent twin fixture rebuilds
 *       it byte-identically; a pre-planted DIFFERENT snapshot for that
 *       epoch makes the block FAIL with a byte-identical digest.
 *   §8  FAULT POINTS F39-F45 — each injected boundary block leaves the
 *       whole-DB digest byte-identical, and the clean retry afterwards
 *       commits the SAME snapshot bytes and the SAME roots as an
 *       uninjected twin fixture.
 *   §9  RESTART — reopening after a committed boundary preserves the
 *       snapshot and the graduated state; reopening after a rolled-back
 *       injection reproduces the pre-block digest.
 *   §10 MALFORMED ROW — a legacy-malformed RETIRING row (bad destination
 *       fingerprint) makes the boundary block FAIL, digest unchanged.
 *
 * Every boundary block driven here carries ZERO envelopes: the boundary
 * is ENGINE-MANDATORY, not caller-declared, so an empty batch must still
 * run it.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/ledger_ids.h"
#include "dnac/vset_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdint.h>       /* uintptr_t sentinels, INT64_MAX, UINT64_MAX */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
                __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E   ((uint64_t)DNAC_EPOCH_LENGTH)
#define CD  ((uint64_t)DNAC_UNSTAKE_COOLDOWN_BLOCKS)

/* ── deterministic pseudo-keys ──────────────────────────────────────────
 * NO real Dilithium keypair is needed anywhere in this file: every block
 * driven here carries ZERO envelopes, so no signature is ever verified.
 * The validators table only needs DISTINCT 2592-byte pubkeys (the vset
 * builder derives each voter_id by hashing the pubkey), and a
 * deterministic filler keeps the whole run reproducible byte-for-byte.  */
#define N_KEYS 10
static uint8_t g_pk[N_KEYS][DNAC_PUBKEY_SIZE];
static char    g_fp[N_KEYS][129];       /* lowercase hex, NUL-terminated */

static void keys_init(void) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        /* distinct, deterministic, and NOT all-equal bytes: the vset
         * ranking tiebreaks on pubkey ASC, so distinctness must survive
         * the very first byte AND the whole buffer. */
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
            g_pk[i][b] = (uint8_t)((b * 31u + i * 7u + 11u) & 0xFF);
        g_pk[i][0] = (uint8_t)(0x10 + i);
        uint8_t full[64];
        qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, full);
        for (int b = 0; b < 64; b++) {
            g_fp[i][2 * b]     = hexd[full[b] >> 4];
            g_fp[i][2 * b + 1] = hexd[full[b] & 0xF];
        }
        g_fp[i][128] = '\0';
    }
}

/* ── fixture (the test_v2_native shape) ─────────────────────────────── */

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
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint64_t         height;            /* last committed V2 height       */
} fixture_t;

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static uint64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* Same, with the height/epoch operands FORMATTED from the E macro
 * rather than spelled as literals: DNAC_EPOCH_LENGTH is #ifndef-guarded
 * for the short-epoch harness, and a hard-coded 720/1440 would silently
 * desynchronize from the chain the fixture actually drives. */
static uint64_t q1f(nodus_witness_t *w, const char *fmt, uint64_t a) {
    char sql[320];
    snprintf(sql, sizeof(sql), fmt, (unsigned long long)a);
    return q1(w, sql);
}

typedef struct { uint8_t *buf; size_t len, cap; } dyn_t;
static int dyn_put(dyn_t *d, const void *p, size_t n) {
    if (d->len + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 4096;
        while (nc < d->len + n) nc *= 2;
        uint8_t *nb = realloc(d->buf, nc);
        if (!nb) return -1;
        d->buf = nb;
        d->cap = nc;
    }
    memcpy(d->buf + d->len, p, n);
    d->len += n;
    return 0;
}

/* WHOLE-database digest: every non-internal table, every row, every
 * column, ORDER BY rowid. The rollback proof is byte-compare of THIS —
 * never a return code. (test_v2_native's db_state_digest shape.) */
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
                if (dyn_put(&d, &t, 1) != 0) {
                    sqlite3_finalize(rs); goto done;
                }
                if (t == SQLITE_NULL) continue;
                const void *b = sqlite3_column_blob(rs, c);
                int bl = sqlite3_column_bytes(rs, c);
                uint32_t bl32 = (uint32_t)bl;
                if (dyn_put(&d, &bl32, 4) != 0 ||
                    (bl > 0 && dyn_put(&d, b, (size_t)bl) != 0)) {
                    sqlite3_finalize(rs); goto done;
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

static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

/* Deterministic per-height block ids: a boundary block driven twice in
 * two fixtures must carry the SAME id, or the twin comparison would be
 * comparing different blocks. */
/* Synthetic block id for height h. The FULL height is embedded in the
 * first 8 bytes (BE): the original byte pattern `(h*7 + 3i + 1) & 0xFF`
 * alone repeats with period 256, so block_id(257) == block_id(1) and the
 * engine's replay/linkage guard correctly rejected the drive at height
 * 257 (found live by the E-1 drive). */
static void mk_block_id(uint8_t out[64], uint64_t h) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(h >> (56 - 8 * i));
    for (int i = 8; i < 64; i++)
        out[i] = (uint8_t)((h * 7u + (uint64_t)i * 3u + 1u) & 0xFF);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    /* O14 leader mode: identity is DERIVED, never carried. */
    b->envs = NULL;
    b->n_envs = 0;                       /* ZERO-ENVELOPE by design      */
}

/* ── seeding helpers ────────────────────────────────────────────────── */

/* One validator row. `bond` is the ACTUAL self_stake — the graduation
 * pays THIS back, never the DNAC_SELF_STAKE_AMOUNT macro. */
static int seed_validator(fixture_t *fx, int k, uint64_t bond,
                          uint8_t status, uint16_t comm,
                          uint16_t pend_comm, uint64_t pend_eff) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_pk[k], DNAC_PUBKEY_SIZE);
    v.self_stake = bond;
    v.status = status;
    v.active_since_block = 1;
    v.commission_bps = comm;
    v.pending_commission_bps = pend_comm;
    v.pending_effective_block = pend_eff;
    memcpy(v.unstake_destination_fp, g_fp[k], 129);
    return nodus_validator_insert(fx->w, &v);
}

static int seed_utxo(fixture_t *fx, int k, uint64_t amount,
                     uint8_t seed_byte, uint8_t nul_out[64]) {
    uint8_t seed[32];
    memset(seed, seed_byte, sizeof(seed));
    uint8_t pre[160];
    memcpy(pre, g_fp[k], 128);
    memcpy(pre + 128, seed, 32);
    if (qgp_sha3_512(pre, sizeof(pre), nul_out) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul_out, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp[k], 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/*
 * ACTIVATION OBLIGATION 2 (nodus_witness_v2_epoch.h), handled HONESTLY
 * in the fixture rather than by inventing engine behaviour:
 * nodus_witness_vset_commit_next(H) builds the snapshot for
 * e_start = H + E, and nodus_committee_compute_for_epoch reads the
 * LEGACY `blocks` row at e_start − E − 1 == H − 1 for its state_seed
 * tiebreak (nodus_witness_committee.c:116-125). A pure-V2 chain produces
 * no legacy block rows, so the test plants the one row the source path
 * needs, with a FIXED deterministic state_root so two twin fixtures see
 * an identical seed. `blocks.height` is an explicit column
 * (nodus_witness.c:80-90), so the row is planted at the exact height —
 * nodus_witness_block_add only ever APPENDS.
 */
static int seed_legacy_block(fixture_t *fx, uint64_t height) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "INSERT OR IGNORE INTO blocks (height, tx_root, tx_count, "
            "timestamp, proposer_id, prev_hash, state_root, created_at) "
            "VALUES (?1, zeroblob(64), 0, 0, zeroblob(32), zeroblob(64), "
            "?2, 0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    uint8_t sr[64];
    memset(sr, 0x5A, sizeof(sr));        /* FIXED across every fixture   */
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob(st, 2, sr, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* One validator's seed spec (so a fixture can be replayed in a
 * DIFFERENT insertion order without changing anything else). */
typedef struct {
    int      key;
    uint64_t bond;
    uint8_t  status;
    uint16_t comm;
    uint16_t pend_comm;
    uint64_t pend_eff;
} vspec_t;

#define BOND_BASE  DNAC_SELF_STAKE_AMOUNT
/* A bond ABOVE the macro, so the "release the ACTUAL self_stake, never
 * the DNAC_SELF_STAKE_AMOUNT literal" rule (bft.c:2482-2491) cannot pass
 * by coincidence. */
#define BOND_BIG   (DNAC_SELF_STAKE_AMOUNT + 424242ULL)
#define UTXO_A     5000000ULL

/*
 * THE TWO-STAGE FIXTURE, and why it is two stages.
 *
 * `validators`, `delegations`, `supply_tracking`, `utxo_set` and
 * `validator_set_snapshots` are all LEGS of the V2 domain state roots
 * (system: roots_v2.c:279-311; core: utxo/supply legs). The V2 genesis
 * commits a DomainHead whose root is computed over whatever those
 * tables hold AT THAT MOMENT. Any direct SQL write afterwards moves the
 * root out of band, and the very next driven block recomputes a root
 * that no longer matches the committed head — the engine's
 * untouched-domain guard (v2_apply.c:1583-1589) then rejects it with
 * "domain N mutated without being declared touched". That guard is
 * CORRECT: an out-of-band consensus-state write is exactly the thing it
 * exists to catch, and a fixture is not exempt from it.
 *
 *   fx_genesis     — stage 1: DB + schema + validator/supply/UTXO seed +
 *                    the SOURCE genesis vset snapshots. Stops BEFORE the
 *                    V2 genesis so a test can still shape its pre-chain
 *                    state (a late joiner, a status flip, a malformed
 *                    legacy row) with the snapshots ALREADY FROZEN.
 *   fx_v2_genesis  — stage 2: the V2 genesis itself. After this call the
 *                    fixture is a live chain and NOTHING may write a
 *                    consensus table except through a block.
 *
 * The one deliberate exception is a test that plants CORRUPTION to prove
 * a fail-closed path (the conflicting snapshot in §7, which must be
 * planted immediately before the boundary block that trips on it).
 */
static int fx_genesis(fixture_t *fx, const char *tag,
                      const vspec_t *specs, size_t n_spec,
                      int n_active_count) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    /* the live constructor's cache sentinel (nodus_witness.c:649) — a
     * zeroed struct reads as a CACHED EMPTY committee for epoch 0 */
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_epoch_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    uint64_t bonds = 0;
    for (size_t i = 0; i < n_spec; i++) {
        if (seed_validator(fx, specs[i].key, specs[i].bond,
                           specs[i].status, specs[i].comm,
                           specs[i].pend_comm, specs[i].pend_eff) != 0)
            return -1;
        bonds += specs[i].bond;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", n_active_count);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    /* CORE supply invariant: genesis == Σ CORE utxo + Σ self_stake. */
    {
        uint64_t supply = UTXO_A + bonds;
        char sql[320];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence) VALUES (1, %llu, 0, 0, "
                 "%llu, zeroblob(64), 0)",
                 (unsigned long long)supply, (unsigned long long)supply);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    uint8_t nul[64];
    if (seed_utxo(fx, 0, UTXO_A, 0xA1, nul) != 0) return -1;

    /* The SOURCE genesis hook: seeds the snapshots for epoch 0 AND
     * epoch E, so the first boundary's flips have a frozen row to apply
     * (nodus_witness_vset.h:223-238). MUST run BEFORE the V2 genesis:
     * validator_set_snapshots feeds the vset leg of system_state_root
     * (roots_v2.c:291), so the genesis DomainHead root has to commit
     * the seeded rows — seeding after genesis is an out-of-band SYSTEM
     * mutation and the engine's untouched-domain guard rejects the very
     * first driven block (found live: "domain 0 mutated without being
     * declared touched" at the E-1 drive). */
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;
    return 0;
}

/* Stage 2 — see the two-stage note above. Every direct write to a
 * consensus table must ALREADY have happened when this returns. */
static int fx_v2_genesis(fixture_t *fx) {
    uint8_t vset[64];
    mk_id(vset, 0x77);
    /* O14: the genesis BlockID is DERIVED by the engine, not chosen. */
    if (v2x_genesis_min(fx->w, vset, NULL, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;
    fx->height = 0;
    return 0;
}

/* The common shape: no pre-chain shaping needed between the stages. */
static int fx_genesis_full(fixture_t *fx, const char *tag,
                           const vspec_t *specs, size_t n_spec,
                           int n_active_count) {
    if (fx_genesis(fx, tag, specs, n_spec, n_active_count) != 0) return -1;
    return fx_v2_genesis(fx);
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    rmrf(fx->dir);
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

/* Apply one zero-envelope block at the next height. Plants the legacy
 * lookback row a boundary needs BEFORE applying. */
static int fx_block(fixture_t *fx, nodus_v2_block_t *out_blk, int *rc_out) {
    uint64_t h = fx->height + 1;
    if (h % E == 0 && seed_legacy_block(fx, h - 1) != 0) return -1;
    nodus_v2_block_t b;
    mk_block(&b, h);
    int rc = nodus_witness_v2_apply_block(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc == 0 || rc == 1 || rc == 2) fx->height = h;
    if (out_blk) *out_blk = b;
    return rc == 0 ? 0 : -1;
}

/* Drive empty blocks up to and including `target`. */
static int fx_drive_to(fixture_t *fx, uint64_t target) {
    while (fx->height < target) {
        int rc = 0;
        if (fx_block(fx, NULL, &rc) != 0) {
            fprintf(stderr, "fx_drive_to: block at height %llu failed "
                    "(rc=%d)\n",
                    (unsigned long long)(fx->height + 1), rc);
            return -1;
        }
    }
    return 0;
}

/* Apply the next block with an injected fault; PROVE the whole-DB digest
 * is byte-identical afterwards. @return 0 iff rc was a rollback class
 * AND the digest did not move. */
static int fx_block_inject(fixture_t *fx, nodus_v2_apply_fail_t pt,
                           int *rc_out) {
    uint64_t h = fx->height + 1;
    if (h % E == 0 && seed_legacy_block(fx, h - 1) != 0) return -1;
    uint8_t d0[64], d1[64];
    if (db_state_digest(fx->w, d0) != 0) return -1;
    nodus_v2_block_t b;
    mk_block(&b, h);
    b.fail_at = pt;
    int rc = nodus_witness_v2_apply_block(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc != -1 && rc != -2) return -1;
    if (db_state_digest(fx->w, d1) != 0) return -1;
    return memcmp(d0, d1, 64) == 0 ? 0 : -1;
}

/* ── row readers ────────────────────────────────────────────────────── */

typedef struct {
    int      found;
    char     owner[129];
    uint64_t amount, block_height, created_at, unlock_block;
    int64_t  output_index, domain_id;
    uint8_t  tx_hash[64], token_id[64];
    int      txh_len, tok_len;
} utxo_row_t;

static int utxo_get(nodus_witness_t *w, const uint8_t nul[64],
                    utxo_row_t *r) {
    memset(r, 0, sizeof(*r));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, amount, token_id, tx_hash, output_index, "
            "block_height, created_at, unlock_block, domain_id "
            "FROM utxo_set WHERE nullifier = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *o = (const char *)sqlite3_column_text(st, 0);
        int ol = sqlite3_column_bytes(st, 0);
        if (o && ol == 128) memcpy(r->owner, o, 128);
        r->amount = (uint64_t)sqlite3_column_int64(st, 1);
        r->tok_len = sqlite3_column_bytes(st, 2);
        if (r->tok_len == 64)
            memcpy(r->token_id, sqlite3_column_blob(st, 2), 64);
        r->txh_len = sqlite3_column_bytes(st, 3);
        if (r->txh_len == 64)
            memcpy(r->tx_hash, sqlite3_column_blob(st, 3), 64);
        r->output_index = sqlite3_column_int64(st, 4);
        r->block_height = (uint64_t)sqlite3_column_int64(st, 5);
        r->created_at   = (uint64_t)sqlite3_column_int64(st, 6);
        r->unlock_block = (uint64_t)sqlite3_column_int64(st, 7);
        r->domain_id    = sqlite3_column_int64(st, 8);
        r->found = 1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int val_get(fixture_t *fx, int k, dnac_validator_record_t *out) {
    return nodus_validator_get(fx->w, g_pk[k], out);
}

/* The two V2 domain state roots — order-independent commitments, which
 * is what a twin-fixture identity check must compare (a raw table digest
 * would compare rowid ORDER, not content). */
static int roots_pair(nodus_witness_t *w, uint8_t sys[64],
                      uint8_t core[64]) {
    if (nodus_witness_system_root_v2(w, sys) != 0) return -1;
    return nodus_witness_core_root_v2(w, core);
}

/* The stored snapshot's canonical bytes + hash for one epoch. */
static int snap_blob(nodus_witness_t *w, uint64_t e_start,
                     uint8_t **blob_out, size_t *len_out,
                     uint8_t hash_out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT snapshot_blob, snapshot_hash FROM "
            "validator_set_snapshots WHERE epoch_start = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)e_start);
    int ret = 1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        int bl = sqlite3_column_bytes(st, 0);
        int hl = sqlite3_column_bytes(st, 1);
        if (bl > 0 && hl == 64) {
            uint8_t *b = malloc((size_t)bl);
            if (b) {
                memcpy(b, sqlite3_column_blob(st, 0), (size_t)bl);
                memcpy(hash_out, sqlite3_column_blob(st, 1), 64);
                *blob_out = b;
                *len_out = (size_t)bl;
                ret = 0;
            } else {
                ret = -1;
            }
        } else {
            ret = -1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════
 * §1  DERIVATION MATRIX + the storage-bound guard
 * ════════════════════════════════════════════════════════════════════ */

static int test_derivation(void) {
    printf("\n§1 derivation matrix + storage-bound guard\n");
    fixture_t fx;
    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
        { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0, 0, 0 },
    };
    CHECK(fx_genesis_full(&fx, "deriv", specs, 7, 7) == 0, "genesis");

    /* The heights that must NOT fire — proven both by `fired` and by a
     * byte-identical whole-DB digest. Genesis (0) is the load-bearing
     * one: bft.c:2358 excludes it explicitly. */
    static const uint64_t noop_h[] = { 0, 1, 2, 719, 721, 1439, 1441 };
    for (size_t i = 0; i < sizeof(noop_h) / sizeof(noop_h[0]); i++) {
        uint64_t h = noop_h[i];
        CHECK(h == 0 || (h % E) != 0, "noop height must not be a boundary");
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(fx.w, d0) == 0, "digest");
        nodus_v2_epoch_result_t ep;
        memset(&ep, 0xFF, sizeof(ep));
        CHECK(nodus_witness_v2_epoch_boundary_apply(
                  fx.w, h, fx.chain_id, NULL, NULL, &ep) == 0,
              "non-boundary height must be a clean no-op");
        CHECK(ep.fired == 0 && ep.n_graduates == 0,
              "non-boundary height must not fire");
        CHECK(db_state_digest(fx.w, d1) == 0, "digest");
        CHECK(memcmp(d0, d1, 64) == 0,
              "a non-boundary call must not touch one byte");
    }
    OK();
    printf("  ok: 0 / 1 / 2 / E-1 / E+1 / 2E-1 / 2E+1 are all no-ops\n");

    /* E, 2E, 3E ... ARE boundaries — asserted on the pure predicate so
     * the claim is about the gate, not about a particular DB state. */
    for (uint64_t k = 1; k <= 5; k++) {
        uint64_t h = k * E;
        CHECK(h > 0 && (h % E) == 0, "k*E is a boundary");
        CHECK(nodus_v2_epoch_for_height(h) == k,
              "the epoch of k*E is k");
        CHECK(nodus_v2_epoch_for_height(h - 1) == k - 1 &&
              nodus_v2_epoch_for_height(h + 1) == k,
              "E-1 closes the previous epoch, E+1 opens the new one");
    }
    OK();

    /* THE STORAGE-BOUND GUARD. A representable multiple of E so close to
     * INT64_MAX that H + DNAC_UNSTAKE_COOLDOWN_BLOCKS leaves the SQLite
     * INTEGER range: the release must be REFUSED, not stored as a value
     * that round-trips negative (which would make the output spendable
     * forever). Driven DIRECTLY at the module — reaching this height
     * through the engine would need 2^63 committed blocks — inside a
     * transaction the test owns and rolls back, exactly as the engine
     * would. */
    {
        uint64_t hbig = ((uint64_t)INT64_MAX / E) * E;
        CHECK(hbig > 0 && (hbig % E) == 0, "hbig is a boundary");
        CHECK(hbig + CD > (uint64_t)INT64_MAX,
              "the fixture height must actually overflow the bound");

        /* EXEMPT from the two-stage rule (fx_genesis note): this whole
         * probe lives inside a transaction the test itself rolls back,
         * and NO block is ever driven on this fixture afterwards — so
         * the post-genesis write is never observed by the engine's
         * untouched-domain guard. */
        CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        /* one RETIRING row, or the graduation loop never runs */
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get val 6");
        v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "make RETIRING");

        nodus_v2_epoch_result_t ep;
        CHECK(nodus_witness_v2_epoch_boundary_apply(
                  fx.w, hbig, fx.chain_id, NULL, NULL, &ep) == -2,
              "an unrepresentable unlock height must FAIL CLOSED");
        uint8_t gid[64], nul[64];
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, hbig, g_pk[6],
                                             gid) == 0, "grad_id");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(gid, nul) == 0, "nul");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul, &r) == 0, "utxo probe");
        CHECK(!r.found,
              "the guard must fire BEFORE the release row is written");
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
        OK();
        printf("  ok: unlock overflow at H=%llu fails closed, no row\n",
               (unsigned long long)hbig);
    }

    /* grad_id is a pure function of (chain, domain, height, validator):
     * every axis moves it, and nothing else does. */
    {
        uint8_t a[64], b[64], c[64], d[64];
        uint8_t other_chain[DNA_CHAIN_ID_LEN];
        memcpy(other_chain, fx.chain_id, DNA_CHAIN_ID_LEN);
        other_chain[0] ^= 0x01;
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[0], a)
              == 0, "grad a");
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[1], b)
              == 0, "grad b");
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, 2 * E, g_pk[0], c)
              == 0, "grad c");
        CHECK(nodus_witness_v2_epoch_grad_id(other_chain, E, g_pk[0], d)
              == 0, "grad d");
        CHECK(memcmp(a, b, 64) != 0, "a different validator, a different id");
        CHECK(memcmp(a, c, 64) != 0, "a different height, a different id");
        CHECK(memcmp(a, d, 64) != 0, "a different chain, a different id");
        uint8_t a2[64];
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[0], a2)
              == 0, "grad a2");
        CHECK(memcmp(a, a2, 64) == 0, "the derivation is deterministic");
        /* and the row key is a pure function of the id */
        uint8_t n1[64], n2[64];
        CHECK(nodus_witness_v2_epoch_grad_nullifier(a, n1) == 0, "n1");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(b, n2) == 0, "n2");
        CHECK(memcmp(n1, n2, 64) != 0, "distinct ids, distinct row keys");
        CHECK(memcmp(n1, a, 64) != 0, "the row key is not the id itself");
        OK();
        printf("  ok: grad_id binds chain / height / validator, "
               "nullifier derives from it\n");
    }

    /* ── INDEPENDENT KAT (R3 review fold) ─────────────────────────────
     * Every check above calls the production function on BOTH sides, so
     * a preimage-layout defect (tag padding, endianness, field order,
     * domain constant) would be invisible. These literals were derived
     * by an INDEPENDENT python3 transcription of the documented preimage
     * ("DNA.EPGRAD.v1" zero-padded to 16 ‖ chain[32] ‖ u32be(DOMAIN_CORE
     * = 1) ‖ u64be(720) ‖ SHA3-512(0x02 ‖ pubkey)) and of the nullifier
     * (SHA3-512(grad_id ‖ 0x10 ‖ u32be(200))) — hashlib.sha3_512, no C
     * code involved. Inputs: chain = 32×0xAB, pubkey = 2592×0x11. */
    {
        static const uint8_t KAT_GRAD_ID[64] = {
            0x5f, 0xf1, 0x44, 0x3b, 0x2b, 0x04, 0x40, 0x50,
            0x4b, 0x51, 0x30, 0x4f, 0x97, 0xc4, 0x05, 0x70,
            0xb3, 0x0e, 0x90, 0x65, 0x2a, 0xc9, 0x11, 0x1d,
            0x4b, 0xed, 0xeb, 0xd0, 0x5b, 0x76, 0x2a, 0x50,
            0xf3, 0x01, 0x7a, 0xa2, 0xbe, 0x1a, 0xd0, 0xf1,
            0x67, 0x2d, 0x62, 0x6a, 0x25, 0x9c, 0xb9, 0xa1,
            0x2e, 0x78, 0x82, 0x39, 0x7f, 0x49, 0xb1, 0x38,
            0x57, 0x60, 0x74, 0xa7, 0x8c, 0x73, 0x30, 0x87,
        };
        static const uint8_t KAT_GRAD_NUL[64] = {
            0x1a, 0x5c, 0xc3, 0x32, 0xfc, 0x95, 0x55, 0xc3,
            0x42, 0x81, 0x0b, 0xe0, 0x4c, 0x47, 0xcd, 0xdb,
            0x6e, 0x00, 0xad, 0xa3, 0x45, 0x9b, 0x8b, 0x31,
            0x82, 0x7c, 0x90, 0x14, 0xda, 0xf4, 0xce, 0xcb,
            0x08, 0xae, 0x78, 0x5e, 0xc4, 0xdb, 0x31, 0x06,
            0xa3, 0x0a, 0xef, 0x2c, 0x5a, 0x3c, 0x26, 0xa1,
            0x84, 0x50, 0xa1, 0xaa, 0x89, 0x85, 0x65, 0x8d,
            0xac, 0xa3, 0xf3, 0x01, 0xad, 0x63, 0x5f, 0xce,
        };
        uint8_t kchain[DNA_CHAIN_ID_LEN];
        static uint8_t kpk[DNAC_PUBKEY_SIZE];
        uint8_t gid[64], nul[64];
        memset(kchain, 0xAB, sizeof(kchain));
        memset(kpk, 0x11, sizeof(kpk));
        CHECK(nodus_witness_v2_epoch_grad_id(kchain, 720, kpk, gid) == 0,
              "KAT grad_id derives");
        CHECK(memcmp(gid, KAT_GRAD_ID, 64) == 0,
              "grad_id matches the independent python-derived KAT");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(gid, nul) == 0,
              "KAT nullifier derives");
        CHECK(memcmp(nul, KAT_GRAD_NUL, 64) == 0,
              "nullifier matches the independent python-derived KAT");
        OK();
        printf("  ok: DNA.EPGRAD.v1 preimage pinned by an independent "
               "KAT\n");
    }

    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §2-§5  GRADUATION / REPLAY / COMMISSION / FLIPS — one chain, driven
 *        across TWO real boundaries.
 *
 * Seed layout (7 bonded rows + 1 late joiner):
 *   key 0..5  ACTIVE, BOND_BASE          — the frozen snapshot's members
 *   key 6     ACTIVE, BOND_BIG           — becomes RETIRING pre-boundary
 *   key 5     also carries a pending commission effective at 2E
 *   key 4     also carries a pending commission effective at E
 *   key 7     ACTIVE, added between the two fixture stages, so it is
 *             bonded but NOT in the frozen snapshot(E)
 *
 * Every mutation below sits BETWEEN fx_genesis and fx_v2_genesis: the
 * snapshots are already frozen (so the flip and resurrection scenarios
 * are unchanged) while the genesis DomainHead root still commits the
 * final pre-chain state. See the two-stage note on fx_genesis.
 * ════════════════════════════════════════════════════════════════════ */

static int test_boundary_chain(void) {
    printf("\n§2-§5 graduation / replay / commission / flips\n");
    fixture_t fx;
    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,    0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,    0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,    0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,    0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 777,  E },
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 888,  2 * E },
        { 6, BOND_BIG,  DNAC_VALIDATOR_ACTIVE, 250, 0,    0 },
    };
    CHECK(fx_genesis(&fx, "chain", specs, 7, 7) == 0, "genesis");

    /* key 7 joins AFTER the genesis snapshots were frozen but BEFORE the
     * V2 genesis, so it is bonded, absent from snapshot(E) — the flip
     * fixture — and still inside the pre-chain window. Its bond must
     * enter the supply equation too. */
    /* key 7 also carries the REAL-WORLD pending-commission shape the R3
     * review found untested: an increase submitted OFF-boundary writes
     * pending_effective_block = H + E, which is never boundary-aligned
     * (here: a submission at H=3 → peff = E+3). Under the legacy
     * equality match this NEVER activates (the dead path, bft.c:2386);
     * the V2 `<=` activator must hold it through the E boundary (notice
     * period not yet complete) and land it at 2E. */
    CHECK(seed_validator(&fx, 7, BOND_BASE, DNAC_VALIDATOR_ACTIVE,
                         100, 555, E + 3) == 0, "late joiner");
    {
        char sql[192];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = current_supply "
                 "+ %llu WHERE id = 1",
                 (unsigned long long)BOND_BASE,
                 (unsigned long long)BOND_BASE);
        CHECK(run_sql(fx.w->db, sql) == 0, "supply top-up");
    }
    CHECK(run_sql(fx.w->db,
                  "UPDATE validator_stats SET value = 8 "
                  "WHERE key = 'active_count'") == 0, "count 8");

    /* UNSTAKE-shaped pre-state: key 6 RETIRING with its bond intact —
     * exactly what the O11 UNSTAKE apply leaves behind (the principal
     * release is DEFERRED to this boundary). */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6");
        v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
        v.unstake_commit_block = 3;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "RETIRING");
    }
    /* A snapshot member that has LEFT the bonded states: pass 2's
     * `AND status = ELIGIBLE` predicate must refuse to resurrect it. */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 3, &v) == 0, "get 3");
        v.status = (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "AUTO_RETIRED");
    }

    /* Stage 2 — the pre-chain state is now FINAL, so the genesis
     * DomainHead roots commit exactly what the first driven block will
     * recompute. Everything above had to happen on this side of the
     * line (two-stage note on fx_genesis). */
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "the supply gate is GREEN on the committed genesis state");
    OK();

    /* ── §2a: the boundary does NOT fire early ─────────────────────── */
    CHECK(fx_drive_to(&fx, E - 1) == 0, "drive to E-1");
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6 at E-1");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_RETIRING,
              "still RETIRING one block before the boundary");
        CHECK(v.self_stake == BOND_BIG, "bond still on the record");
        CHECK(val_get(&fx, 4, &v) == 0, "get 4 at E-1");
        CHECK(v.commission_bps == 100 && v.pending_commission_bps == 777,
              "the pending commission has NOT activated mid-epoch");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 8,
              "active_count untouched mid-epoch");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots") == 2,
              "only the two genesis-seeded snapshots exist");
    }
    OK();
    printf("  ok: no graduation, no commission activation before H=E\n");

    uint8_t gid6[64], nul6[64];
    CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[6], gid6)
          == 0, "grad_id 6");
    CHECK(nodus_witness_v2_epoch_grad_nullifier(gid6, nul6) == 0, "nul 6");

    /* ── §2b: the boundary block itself (ZERO envelopes) ───────────── */
    nodus_v2_block_t bE;
    {
        int rc = 0;
        CHECK(fx_block(&fx, &bE, &rc) == 0 && rc == 0,
              "the zero-envelope boundary block must COMMIT");
        CHECK(bE.n_envs == 0, "the block really carried no envelopes");
        CHECK(fx.height == E, "height advanced to E");
    }
    OK();

    /* the release UTXO, checked field by field against the CORE adapter's
     * canonical row shape (rt_native.c:2368-2393) */
    {
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul6, &r) == 0, "utxo probe");
        CHECK(r.found, "the graduation released a UTXO");
        CHECK(r.amount == BOND_BIG,
              "the release pays the record's ACTUAL bond, not the macro");
        CHECK(BOND_BIG != DNAC_SELF_STAKE_AMOUNT,
              "the fixture bond really differs from the macro");
        CHECK(memcmp(r.owner, g_fp[6], 128) == 0,
              "owner is the record's unstake_destination_fp");
        CHECK(r.txh_len == 64 && memcmp(r.tx_hash, gid6, 64) == 0,
              "tx_hash is the INDEPENDENTLY recomputed grad_id");
        CHECK(r.output_index == (int64_t)NODUS_V2_EPGRAD_OUT_IDX,
              "output_index 200");
        CHECK(r.unlock_block == E + CD,
              "unlock = H + DNAC_UNSTAKE_COOLDOWN_BLOCKS");
        CHECK(r.block_height == E, "block_height = the boundary height");
        CHECK(r.created_at == 0,
              "created_at is the pinned deterministic lane");
        CHECK(r.domain_id == (int64_t)DNA_DOMAIN_CORE,
              "the row is owned by DNA_CORE explicitly");
        CHECK(r.tok_len == 64, "token blob width");
        uint8_t zero[64];
        memset(zero, 0, sizeof(zero));
        CHECK(memcmp(r.token_id, zero, 64) == 0, "native token id");
        OK();
        printf("  ok: release UTXO exact (amount %llu, unlock %llu)\n",
               (unsigned long long)r.amount,
               (unsigned long long)r.unlock_block);
    }

    /* the validators row: exactly two fields moved */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6 at E");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED, "UNSTAKED");
        CHECK(v.self_stake == 0,
              "the bond is zeroed — its value lives in the UTXO now");
        CHECK(v.commission_bps == 250, "commission untouched");
        CHECK(v.active_since_block == 1, "tenure untouched");
        CHECK(v.unstake_commit_block == 3, "commit block untouched");
        CHECK(memcmp(v.unstake_destination_fp, g_fp[6], 129) == 0,
              "destination untouched");
        CHECK(v.total_delegated == 0 && v.external_delegated == 0,
              "delegation totals untouched");
        OK();
    }

    /* the counter, and the invariant the whole transition exists to keep */
    CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                   "key='active_count'") == 7,
          "active_count decremented by exactly one");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "the supply gate is GREEN after the bond moved into a UTXO");
    OK();

    /* ── §4: pending commission timing ─────────────────────────────── */
    {
        dnac_validator_record_t v4, v5;
        CHECK(val_get(&fx, 4, &v4) == 0, "get 4");
        CHECK(v4.commission_bps == 777 &&
              v4.pending_commission_bps == 0 &&
              v4.pending_effective_block == 0,
              "the pending commission effective at E activated at E");
        CHECK(val_get(&fx, 5, &v5) == 0, "get 5");
        CHECK(v5.commission_bps == 100 &&
              v5.pending_commission_bps == 888 &&
              v5.pending_effective_block == 2 * E,
              "a pending commission for 2E must NOT activate one epoch "
              "early");
        /* the OFF-boundary increase (peff = E+3 > E): its notice period
         * is not complete at E, so the `<=` activator must NOT fire */
        dnac_validator_record_t v7;
        CHECK(val_get(&fx, 7, &v7) == 0, "get 7");
        CHECK(v7.commission_bps == 100 &&
              v7.pending_commission_bps == 555 &&
              v7.pending_effective_block == E + 3,
              "an off-boundary pending (peff = E+3) must ride PAST the "
              "E boundary untouched");
        OK();
        printf("  ok: commission activates at ITS boundary, not before\n");
    }

    /* ── §5: the flips ─────────────────────────────────────────────── */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 7, &v) == 0, "get 7");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
              "a bonded validator absent from the frozen snapshot is "
              "demoted to ELIGIBLE, never dropped");
        CHECK(v.self_stake == BOND_BASE,
              "only the status byte moved — the bond stays locked");
        CHECK(val_get(&fx, 0, &v) == 0, "get 0");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "a snapshot member is (re)seated ACTIVE");
        CHECK(val_get(&fx, 3, &v) == 0, "get 3");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED,
              "pass 2's ELIGIBLE predicate refuses to resurrect a "
              "snapshot member that left the bonded states");
        CHECK(val_get(&fx, 6, &v) == 0, "get 6");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED,
              "the freshly graduated row is not resurrected either");
        OK();
        printf("  ok: flips demote/seat/never resurrect\n");
    }

    /* the next snapshot exists and the boundary's roots/metadata landed */
    CHECK(q1f(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots "
                    "WHERE epoch_start = %llu", 2 * E) == 1,
          "commit_next froze the snapshot for epoch start 2E");
    CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_blocks WHERE global_height "
                    "= %llu", E) == 1,
          "the boundary block's metadata row committed");
    CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_domain_updates WHERE "
                    "global_height = %llu", E) == 2,
          "both SYSTEM and CORE were declared touched and produced a "
          "DomainUpdate");
    OK();

    /* ── §3a: byte-identical replay of the committed boundary block ── */
    {
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(fx.w, d0) == 0, "digest");
        /* O14 D6: the rc-1 idempotent path is FOLLOWER-mode only — it
         * needs an asserted id to probe with. Read the committed id of
         * the boundary block and assert it. (The leader-mode arm, which
         * has no id and therefore dies on height continuity, is covered
         * separately in test_v2_apply.) */
        uint8_t committed_id[64];
        CHECK(v2x_block_id_at(fx.w, E, committed_id) == 0,
              "read committed boundary id");
        nodus_v2_block_t rb;
        mk_block(&rb, E);
        rb.expect_block_id = committed_id;
        int rc = nodus_witness_v2_apply_block(fx.w, &rb);
        CHECK(rc == 1, "byte-identical replay is the no-write idempotent "
                       "path");
        CHECK(db_state_digest(fx.w, d1) == 0, "digest");
        CHECK(memcmp(d0, d1, 64) == 0, "replay wrote nothing");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "output_index = 200") == 1,
              "exactly ONE graduation UTXO exists after the replay");
        OK();
        printf("  ok: replay is a no-op, no second release\n");
    }

    /* ── §3b: the NEXT boundary does not re-graduate ───────────────── */
    {
        /* O15J Faz 2: SCOPED to the graduation output index.
         *
         * ⚠ The stated cause was CORRECTED by review R2-F10. This
         * comment used to say the narrowing was needed because "the
         * boundary now also SETTLES ... into payout UTXOs, so a
         * whole-table count would grow". That CANNOT HAPPEN IN THIS
         * FILE: main sets v2x_inflation_off = 1, so no pool ever
         * accrues and settlement is a permanent no-op here. The
         * narrowing is still right — it says what the assertion always
         * meant — but it is a PRECISION fix, not a repair of a break.
         *
         * The claim being made here is about the RETIRING scan, and
         * index 200 is exactly the graduation's own slot
         * (nodus_witness_v2_epoch.h) — narrowing the query
         * makes the assertion say what it always meant. */
        uint64_t grads_before = q1(fx.w, "SELECT COUNT(*) FROM utxo_set "
                                         "WHERE output_index = 200");
        CHECK(fx_drive_to(&fx, 2 * E) == 0, "drive to 2E");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set "
                       "WHERE output_index = 200") == grads_before,
              "an UNSTAKED row is not selected by the RETIRING scan — "
              "no second release");
        uint8_t gid2[64], nul2[64];
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, 2 * E, g_pk[6],
                                             gid2) == 0, "grad_id 2E");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(gid2, nul2) == 0,
              "nul 2E");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul2, &r) == 0, "probe");
        CHECK(!r.found, "no 2E-height release for the same validator");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 7,
              "active_count did not drop a second time");
        /* and the 2E pending commission DID activate now */
        dnac_validator_record_t v5;
        CHECK(val_get(&fx, 5, &v5) == 0, "get 5 at 2E");
        CHECK(v5.commission_bps == 888 &&
              v5.pending_commission_bps == 0 &&
              v5.pending_effective_block == 0,
              "the 2E pending commission activated at 2E");
        /* the off-boundary increase lands at the FIRST boundary >= its
         * stored height: 2E >= E+3. Under the legacy equality match
         * this raise would be stranded forever (the R3 dead path). */
        dnac_validator_record_t v7b;
        CHECK(val_get(&fx, 7, &v7b) == 0, "get 7 at 2E");
        CHECK(v7b.commission_bps == 555 &&
              v7b.pending_commission_bps == 0 &&
              v7b.pending_effective_block == 0,
              "an off-boundary pending (peff = E+3) activates at the "
              "first boundary past it (2E)");
        CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply still ok");
        /* A GRADUATE-FREE boundary still fires (a snapshot was frozen,
         * so SYSTEM moved) but must NOT declare CORE touched — an
         * unconditional CORE declaration would trip the engine's
         * "declared but changed nothing" reject instead. */
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots "
                        "WHERE epoch_start = %llu", 3 * E) == 1,
              "the 2E boundary froze the snapshot for epoch start 3E");
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_domain_updates WHERE "
                        "global_height = %llu", 2 * E) == 1,
              "a graduate-free boundary declares SYSTEM only");
        CHECK(q1f(fx.w, "SELECT domain_id FROM v2_domain_updates WHERE "
                        "global_height = %llu", 2 * E) == DNA_DOMAIN_SYSTEM,
              "and that one DomainUpdate is SYSTEM's");
        OK();
        printf("  ok: no double graduation across the next boundary\n");
    }

    /* ── §9a: restart after a COMMITTED boundary ───────────────────── */
    {
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(fx.w, d0) == 0, "digest");
        CHECK(fx_reopen(&fx) == 0, "reopen");
        CHECK(db_state_digest(fx.w, d1) == 0, "digest");
        CHECK(memcmp(d0, d1, 64) == 0, "reopen changed nothing");
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6 post-reopen");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
              v.self_stake == 0, "graduated state persisted");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul6, &r) == 0 && r.found &&
              r.amount == BOND_BIG, "the release UTXO persisted");
        dna_vset_snapshot_t *snap = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 2 * E, &snap, NULL) == 0 &&
              snap != NULL,
              "the frozen snapshot persisted, decoded and hash-verified");
        dna_vset_free(&snap);
        OK();
        printf("  ok: restart preserves graduation + snapshot\n");
    }

    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §6  MULTIPLE GRADUATES + insertion-order independence
 * ════════════════════════════════════════════════════════════════════ */

/* Build a chain with TWO RETIRING rows, seeding the validators in the
 * caller's order, and drive it exactly to the first boundary. */
static int multi_build(fixture_t *fx, const char *tag,
                       const vspec_t *specs, size_t n) {
    if (fx_genesis(fx, tag, specs, n, (int)n) != 0) return -1;
    /* Between the stages: the snapshots are frozen with both rows still
     * ACTIVE (so the boundary must refuse to resurrect them once they
     * graduate), and the genesis root commits them as RETIRING. */
    for (int k = 5; k <= 6; k++) {
        dnac_validator_record_t v;
        if (nodus_validator_get(fx->w, g_pk[k], &v) != 0) return -1;
        v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
        if (nodus_validator_update(fx->w, &v) != 0) return -1;
    }
    if (fx_v2_genesis(fx) != 0) return -1;
    return fx_drive_to(fx, E);
}

static int test_multi_graduate(void) {
    printf("\n§6 multiple graduates + insertion-order independence\n");

    /* Same seven rows, seeded in two DIFFERENT orders. */
    static const vspec_t asc[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 5, BOND_BIG,  DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    static const vspec_t desc[7] = {
        { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 5, BOND_BIG,  DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };

    fixture_t a, b;
    CHECK(multi_build(&a, "multiA", asc, 7) == 0, "fixture A");
    CHECK(multi_build(&b, "multiB", desc, 7) == 0, "fixture B");

    /* both graduates released, with DISTINCT per-record identities */
    uint8_t g5[64], g6[64], n5[64], n6[64];
    CHECK(nodus_witness_v2_epoch_grad_id(a.chain_id, E, g_pk[5], g5) == 0,
          "gid5");
    CHECK(nodus_witness_v2_epoch_grad_id(a.chain_id, E, g_pk[6], g6) == 0,
          "gid6");
    CHECK(memcmp(g5, g6, 64) != 0,
          "two graduates in ONE boundary get distinct ids — no rank, no "
          "collision");
    CHECK(nodus_witness_v2_epoch_grad_nullifier(g5, n5) == 0, "n5");
    CHECK(nodus_witness_v2_epoch_grad_nullifier(g6, n6) == 0, "n6");
    OK();

    for (int pass = 0; pass < 2; pass++) {
        fixture_t *f = pass ? &b : &a;
        utxo_row_t r5, r6;
        CHECK(utxo_get(f->w, n5, &r5) == 0 && r5.found, "release 5");
        CHECK(utxo_get(f->w, n6, &r6) == 0 && r6.found, "release 6");
        CHECK(r5.amount == BOND_BIG && r6.amount == BOND_BASE,
              "each graduate is paid ITS OWN bond");
        CHECK(memcmp(r5.owner, g_fp[5], 128) == 0 &&
              memcmp(r6.owner, g_fp[6], 128) == 0, "owners");
        CHECK(r5.output_index == 200 && r6.output_index == 200,
              "BOTH carry index 200 — the identity is the grad_id, not "
              "the rank (the legacy 200+i allocation is superseded)");
        CHECK(r5.unlock_block == E + CD && r6.unlock_block == E + CD,
              "unlocks");
        CHECK(q1(f->w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 5,
              "active_count dropped by exactly two");
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(f->w, g_pk[5], &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
              v.self_stake == 0, "row 5 graduated");
        CHECK(nodus_validator_get(f->w, g_pk[6], &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
              v.self_stake == 0, "row 6 graduated");
        CHECK(nodus_witness_v2_supply_check(f->w) == 0, "supply gate");
    }
    OK();
    printf("  ok: two graduates, distinct ids, both at index 200\n");

    /* INSERTION-ORDER INDEPENDENCE. Compared on the CONTENT commitments
     * (the two domain state roots) rather than a raw table digest: the
     * two fixtures inserted the same rows in opposite orders, so their
     * rowid layouts differ by construction while every consensus
     * commitment must be byte-identical. */
    {
        uint8_t sa[64], ca[64], sb[64], cb[64];
        CHECK(roots_pair(a.w, sa, ca) == 0, "roots A");
        CHECK(roots_pair(b.w, sb, cb) == 0, "roots B");
        CHECK(memcmp(sa, sb, 64) == 0,
              "system_state_root is insertion-order independent");
        CHECK(memcmp(ca, cb, 64) == 0,
              "core_state_root is insertion-order independent");
        uint8_t *ba = NULL, *bb = NULL;
        size_t la = 0, lb = 0;
        uint8_t ha[64], hb[64];
        CHECK(snap_blob(a.w, 2 * E, &ba, &la, ha) == 0, "snap A");
        CHECK(snap_blob(b.w, 2 * E, &bb, &lb, hb) == 0, "snap B");
        CHECK(la == lb && memcmp(ba, bb, la) == 0,
              "the frozen snapshot bytes are byte-identical");
        CHECK(memcmp(ha, hb, 64) == 0, "and so is its hash");
        free(ba);
        free(bb);
        OK();
        printf("  ok: opposite seeding orders → identical roots + "
               "snapshot bytes\n");
    }

    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §7  COMMIT_NEXT — rebuild identity and the conflict path
 * ════════════════════════════════════════════════════════════════════ */

static const vspec_t g_plain7[7] = {
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
};

static int test_commit_next(void) {
    printf("\n§7 commit_next: rebuild identity + conflict\n");

    fixture_t a;
    CHECK(fx_genesis_full(&a, "cnA", g_plain7, 7, 7) == 0, "genesis A");
    CHECK(fx_drive_to(&a, E) == 0, "drive A to E");

    /* the row exists, decodes, and hash-verifies (nodus_witness_vset_get
     * re-hashes the blob and cross-checks the decoded epoch + count
     * before it returns anything) */
    {
        dna_vset_snapshot_t *s = NULL;
        uint8_t h[64];
        CHECK(nodus_witness_vset_get(a.w, 2 * E, &s, h) == 0 && s,
              "snapshot(2E) exists, decodes and hash-verifies");
        CHECK(s->epoch == 2 * E, "the decoded epoch is the key");
        CHECK(s->active_count > 0, "a real chain never freezes an empty "
                                   "set");
        dna_vset_free(&s);
        OK();
    }

    /* an INDEPENDENT twin fixture rebuilds the same bytes from the same
     * committed state */
    {
        fixture_t b;
        CHECK(fx_genesis_full(&b, "cnB", g_plain7, 7, 7) == 0,
              "genesis B");
        CHECK(fx_drive_to(&b, E) == 0, "drive B to E");
        uint8_t *ba = NULL, *bb = NULL;
        size_t la = 0, lb = 0;
        uint8_t ha[64], hb[64];
        CHECK(snap_blob(a.w, 2 * E, &ba, &la, ha) == 0, "blob A");
        CHECK(snap_blob(b.w, 2 * E, &bb, &lb, hb) == 0, "blob B");
        CHECK(la == lb && memcmp(ba, bb, la) == 0 &&
              memcmp(ha, hb, 64) == 0,
              "two independent fixtures freeze byte-identical snapshots");
        free(ba);
        free(bb);
        uint8_t sa[64], ca[64], sb[64], cb[64];
        CHECK(roots_pair(a.w, sa, ca) == 0 && roots_pair(b.w, sb, cb) == 0,
              "roots");
        CHECK(memcmp(sa, sb, 64) == 0 && memcmp(ca, cb, 64) == 0,
              "and identical domain roots");
        fx_close(&b);
        OK();
        printf("  ok: twin fixtures agree byte-for-byte\n");
    }
    fx_close(&a);

    /* CONFLICT: a DIFFERENT snapshot already sitting on the epoch the
     * boundary is about to freeze must FAIL the block, byte-identically
     * rolled back (nodus_witness_vset.h:55-66 — the cross-node identity
     * check). */
    {
        fixture_t c;
        CHECK(fx_genesis_full(&c, "cnC", g_plain7, 7, 7) == 0,
              "genesis C");
        /* The drive MUST succeed first: it proves the failure below is
         * the snapshot CONFLICT at the boundary and not an out-of-band
         * write tripping the untouched-domain guard on an earlier
         * block. This is the one deliberate post-genesis corruption in
         * the file, and it is planted immediately before the block that
         * must trip on it (two-stage note on fx_genesis). */
        CHECK(fx_drive_to(&c, E - 1) == 0, "drive C to E-1");
        /* plant a decoy snapshot for epoch 2E: a blob that is NOT what
         * the boundary will build */
        {
            uint8_t decoy[128], dh[64];
            memset(decoy, 0xD1, sizeof(decoy));
            CHECK(qgp_sha3_512(decoy, sizeof(decoy), dh) == 0, "hash");
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(c.w->db,
                    "INSERT INTO validator_set_snapshots (epoch_start, "
                    "snapshot_hash, snapshot_blob, active_count, "
                    "created_at_height) VALUES (?1, ?2, ?3, 7, 0)",
                    -1, &st, NULL) == SQLITE_OK, "prepare decoy");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)(2 * E));
            sqlite3_bind_blob(st, 2, dh, 64, SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 3, decoy, sizeof(decoy),
                              SQLITE_TRANSIENT);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            CHECK(rc == SQLITE_DONE, "decoy planted");
        }
        CHECK(seed_legacy_block(&c, E - 1) == 0, "legacy lookback");
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(c.w, d0) == 0, "digest");
        nodus_v2_block_t b;
        mk_block(&b, E);
        int rc = nodus_witness_v2_apply_block(c.w, &b);
        CHECK(rc == -2,
              "a diverging snapshot for the same epoch is a NODE FAULT — "
              "two validator sets claiming one epoch");
        CHECK(db_state_digest(c.w, d1) == 0, "digest");
        CHECK(memcmp(d0, d1, 64) == 0,
              "the failed boundary block rolled back byte-identically");
        CHECK(q1f(c.w, "SELECT COUNT(*) FROM v2_blocks WHERE "
                       "global_height = %llu", E) == 0, "no block row");
        fx_close(&c);
        OK();
        printf("  ok: snapshot conflict fails the block, digest intact\n");
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §8  FAULT POINTS F39-F45 (+ §9b restart after a rolled-back inject)
 *
 * ONE fixture is driven to E−1 and every fault point is injected against
 * the SAME pre-block state — which is only sound because each injection
 * is PROVEN to leave the whole-DB digest byte-identical, so the fixture
 * is genuinely unchanged between injections. The clean retry afterwards
 * is then compared against a twin fixture that was never injected.
 * ════════════════════════════════════════════════════════════════════ */

static int test_faults(void) {
    printf("\n§8 fault points F39-F45 + clean-retry twin identity\n");

    /* two graduates so the per-graduate points (F40/F41, which fire on
     * candidate index 0) have a SECOND graduate behind them — a partial
     * batch is exactly the state that must not survive */
    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 555, E },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
        { 5, BOND_BIG,  DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
        { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0,   0 },
    };
    static const nodus_v2_apply_fail_t pts[7] = {
        V2AP_FAIL_AFTER_EPOCH_COMMISSIONS,
        V2AP_FAIL_AFTER_FIRST_GRAD_RELEASE,
        V2AP_FAIL_AFTER_FIRST_GRAD_APPLIED,
        V2AP_FAIL_AFTER_GRAD_BATCH,
        V2AP_FAIL_AFTER_BOUNDARY_FLIPS,
        V2AP_FAIL_AFTER_SNAPSHOT_BUILD,
        V2AP_FAIL_AFTER_SNAPSHOT_PERSIST
    };
    static const char *names[7] = {
        "F39 commissions", "F40 grad[0] release", "F41 grad[0] applied",
        "F42 grad batch", "F43 flips", "F44 snapshot build",
        "F45 snapshot persist"
    };

    fixture_t f, t;
    CHECK(fx_genesis(&f, "fault", specs, 7, 7) == 0, "genesis F");
    CHECK(fx_genesis(&t, "twin", specs, 7, 7) == 0, "genesis T");
    for (int pass = 0; pass < 2; pass++) {
        fixture_t *x = pass ? &t : &f;
        /* between the stages — see the two-stage note on fx_genesis */
        for (int k = 5; k <= 6; k++) {
            dnac_validator_record_t v;
            CHECK(nodus_validator_get(x->w, g_pk[k], &v) == 0, "get");
            v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
            CHECK(nodus_validator_update(x->w, &v) == 0, "RETIRING");
        }
        CHECK(fx_v2_genesis(x) == 0, "v2 genesis");
        CHECK(fx_drive_to(x, E - 1) == 0, "drive to E-1");
    }

    /* the ids the boundary WOULD create — every injection must leave
     * both absent */
    uint8_t n5[64], n6[64];
    {
        uint8_t g5[64], g6[64];
        CHECK(nodus_witness_v2_epoch_grad_id(f.chain_id, E, g_pk[5], g5)
              == 0 &&
              nodus_witness_v2_epoch_grad_id(f.chain_id, E, g_pk[6], g6)
              == 0, "gids");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(g5, n5) == 0 &&
              nodus_witness_v2_epoch_grad_nullifier(g6, n6) == 0, "nuls");
    }

    /* Plant the legacy lookback row BEFORE the entry digest is taken.
     * fx_block_inject seeds it lazily, and that INSERT autocommits
     * OUTSIDE the block transaction (it is fixture setup, not engine
     * work), so digesting first would compare a pre-row snapshot against
     * a post-row one and report a rollback failure that never happened.
     * Every later call hits the OR IGNORE no-op path. */
    CHECK(seed_legacy_block(&f, E - 1) == 0, "legacy lookback for F");
    CHECK(seed_legacy_block(&t, E - 1) == 0, "legacy lookback for T");

    uint8_t entry[64];
    CHECK(db_state_digest(f.w, entry) == 0, "entry digest");

    for (size_t i = 0; i < 7; i++) {
        int rc = 0;
        CHECK(fx_block_inject(&f, pts[i], &rc) == 0,
              "an injected boundary block must roll back with a "
              "byte-identical whole-DB digest");
        CHECK(rc == -2,
              "boundary failure is a NODE FAULT, never a verdict");
        uint8_t now[64];
        CHECK(db_state_digest(f.w, now) == 0, "digest");
        CHECK(memcmp(entry, now, 64) == 0,
              "the fixture is still at its pre-block state");
        /* the observable no-survivor set, spelled out */
        utxo_row_t r;
        CHECK(utxo_get(f.w, n5, &r) == 0 && !r.found, "no release 5");
        CHECK(utxo_get(f.w, n6, &r) == 0 && !r.found, "no release 6");
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(f.w, g_pk[5], &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_RETIRING &&
              v.self_stake == BOND_BIG, "row 5 untouched");
        CHECK(nodus_validator_get(f.w, g_pk[3], &v) == 0 &&
              v.commission_bps == 100 && v.pending_commission_bps == 555,
              "the pending commission did not survive");
        CHECK(q1(f.w, "SELECT value FROM validator_stats WHERE "
                      "key='active_count'") == 7, "counter untouched");
        CHECK(q1f(f.w, "SELECT COUNT(*) FROM validator_set_snapshots "
                       "WHERE epoch_start = %llu", 2 * E) == 0,
              "no snapshot survived");
        CHECK(q1f(f.w, "SELECT COUNT(*) FROM v2_blocks WHERE "
                       "global_height = %llu", E) == 0, "no block row");
        printf("  ok: %s -> rc %d, digest identical\n", names[i], rc);
    }
    OK();

    /* §9b: restart after a rolled-back injection reproduces the
     * pre-block digest — the rollback survived the process, it was not
     * an in-memory illusion. */
    {
        CHECK(fx_reopen(&f) == 0, "reopen after rollback");
        uint8_t now[64];
        CHECK(db_state_digest(f.w, now) == 0, "digest");
        CHECK(memcmp(entry, now, 64) == 0,
              "reopening after a rolled-back injection reproduces the "
              "pre-block digest");
        OK();
        printf("  ok: rollback survives a restart\n");
    }

    /* the CLEAN RETRY: same block, no injection — must produce exactly
     * what the never-injected twin produces */
    {
        int rc = 0;
        CHECK(fx_block(&f, NULL, &rc) == 0 && rc == 0,
              "the clean retry commits");
        CHECK(fx_block(&t, NULL, &rc) == 0 && rc == 0,
              "the twin commits");
        uint8_t *bf = NULL, *bt = NULL;
        size_t lf = 0, lt = 0;
        uint8_t hf[64], ht[64];
        CHECK(snap_blob(f.w, 2 * E, &bf, &lf, hf) == 0, "snap F");
        CHECK(snap_blob(t.w, 2 * E, &bt, &lt, ht) == 0, "snap T");
        CHECK(lf == lt && memcmp(bf, bt, lf) == 0 &&
              memcmp(hf, ht, 64) == 0,
              "the retried boundary freezes the SAME snapshot bytes as a "
              "fixture that was never injected");
        free(bf);
        free(bt);
        uint8_t sf[64], cf[64], st2[64], ct[64];
        CHECK(roots_pair(f.w, sf, cf) == 0 &&
              roots_pair(t.w, st2, ct) == 0, "roots");
        CHECK(memcmp(sf, st2, 64) == 0 && memcmp(cf, ct, 64) == 0,
              "and the SAME domain roots — seven interrupted attempts "
              "left no residue");
        CHECK(q1(f.w, "SELECT value FROM validator_stats WHERE "
                      "key='active_count'") == 5, "two graduates");
        CHECK(nodus_witness_v2_supply_check(f.w) == 0, "supply gate");
        OK();
        printf("  ok: clean retry == never-injected twin\n");
    }

    fx_close(&f);
    fx_close(&t);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §10  MALFORMED RETIRING ROW (activation obligation 1)
 * ════════════════════════════════════════════════════════════════════ */

static int test_malformed_row(void) {
    printf("\n§10 legacy-malformed RETIRING row\n");
    fixture_t fx;
    CHECK(fx_genesis(&fx, "malf", g_plain7, 7, 7) == 0, "genesis");

    /* BOTH mutations sit between the fixture stages. The malformed
     * fingerprint is NOT planted mid-chain: `validators` feeds the
     * SYSTEM root, so a post-genesis write would be caught by the
     * untouched-domain guard on the very next block and this test would
     * pass for the WRONG reason — a generic out-of-band-write reject
     * instead of the graduation's writable-shape refusal. Seeding it
     * pre-genesis is also the honest model of the case: a legacy chain
     * carrying a malformed row from before the V2 lane existed. */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6");
        v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "RETIRING");
    }
    /* Break the destination fingerprint DIRECTLY in the row — the shape
     * a legacy lane could have written and the V2 lane must refuse to
     * pay out to. Uppercase hex is the narrowest possible break: the
     * value is still 128 characters and still hex. */
    {
        char bad[129];
        memcpy(bad, g_fp[6], 129);
        bad[7] = 'A';
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
                "UPDATE validators SET unstake_destination_fp = ?1 "
                "WHERE pubkey = ?2", -1, &st, NULL) == SQLITE_OK,
              "prepare");
        sqlite3_bind_text(st, 1, bad, 128, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, g_pk[6], DNAC_PUBKEY_SIZE,
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        CHECK(rc == SQLITE_DONE && sqlite3_changes(fx.w->db) == 1,
              "malformed fp planted");
    }
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* The malformed row is committed state and every ordinary block
     * rides straight past it — only the GRADUATION reads that column. */
    CHECK(fx_drive_to(&fx, E - 1) == 0,
          "a malformed row does not disturb ordinary blocks");
    CHECK(seed_legacy_block(&fx, E - 1) == 0, "legacy lookback");

    uint8_t d0[64], d1[64];
    CHECK(db_state_digest(fx.w, d0) == 0, "digest");
    nodus_v2_block_t b;
    mk_block(&b, E);
    int rc = nodus_witness_v2_apply_block(fx.w, &b);
    CHECK(rc == -2,
          "a legacy-malformed graduate refuses the boundary as a NODE "
          "FAULT (activation obligation 1)");
    CHECK(db_state_digest(fx.w, d1) == 0, "digest");
    CHECK(memcmp(d0, d1, 64) == 0,
          "nothing was paid out and nothing was rewritten");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE output_index = "
                   "200") == 0, "no release row");
    OK();
    printf("  ok: malformed destination fp → -2, digest intact\n");

    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §11-§18  O12 S3 — THE SNAPSHOT AUTHORITY RESOLVER
 *
 * These groups deliberately use a BARE fixture: schema only, no V2
 * genesis, no driven blocks. That is sound precisely because no
 * DomainHead exists to desynchronize — the untouched-domain guard has
 * nothing to guard — so §13 can mutate the `validators` table freely to
 * prove the CURRENT set cannot leak into a HISTORICAL answer. It also
 * keeps the whole section free of 720-block drives.
 *
 * Every snapshot is stored through the SOURCE path
 * (nodus_witness_vset_insert over real dna_vset_alloc/encode/hash
 * bytes), so the rows are canonical and the resolver is exercised
 * against exactly what the boundary would have written.
 * ════════════════════════════════════════════════════════════════════ */

/* Schema only — no validators, no supply, no genesis, no snapshots. */
static int fx_bare(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_epoch_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    return 0;
}

/* Canonical synthetic snapshot bytes for `n` members.
 * Mirrors the SOURCE builder's shape exactly, or vset_get's integrity
 * work would reject the fixture and every test below would pass for the
 * wrong reason: voter_id IS SHA3-512(pubkey)[0..31] (the shipped
 * derivation), sortition_seed stays all-zero (nonzero rejects under
 * TOPN_V1), and `epoch` equals the key it is stored under (vset_get
 * cross-checks it). `variant` shifts every pubkey so two epochs with the
 * SAME member count still produce different bytes.
 * @return heap blob (caller frees) or NULL. */
static uint8_t *snap_build(uint64_t epoch_start, uint16_t n, uint8_t variant,
                           size_t *len_out, uint8_t hash_out[64]) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    if (!s) return NULL;
    s->epoch = epoch_start;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        for (size_t b = 0; b < DNA_VSET_PUBKEY_LEN; b++)
            e->pubkey[b] = (uint8_t)((b * 7u + (size_t)i * 13u +
                                      (size_t)variant * 101u + 3u) & 0xFF);
        e->pubkey[0] = (uint8_t)i;          /* distinct within the set   */
        e->pubkey[1] = variant;             /* distinct across epochs    */
        uint8_t full[64];
        if (qgp_sha3_512(e->pubkey, DNA_VSET_PUBKEY_LEN, full) != 0) {
            dna_vset_free(&s);
            return NULL;
        }
        memcpy(e->voter_id, full, DNA_VSET_VOTER_ID_LEN);
        e->total_stake    = 1000u + i;
        e->self_bond      = 1000u;
        e->commission_bps = 100;
    }
    uint8_t *buf = malloc(DNA_VSET_MAX_ENC_LEN);
    if (!buf) { dna_vset_free(&s); return NULL; }
    size_t len = 0;
    if (dna_vset_encode(s, buf, DNA_VSET_MAX_ENC_LEN, &len) != 0 ||
        dna_vset_hash(s, hash_out) != 0) {
        free(buf);
        dna_vset_free(&s);
        return NULL;
    }
    dna_vset_free(&s);
    *len_out = len;
    return buf;
}

/* Build + store through the SOURCE persistence path. */
static int snap_store(fixture_t *fx, uint64_t epoch_start, uint16_t n,
                      uint8_t variant, uint8_t hash_out[64]) {
    size_t len = 0;
    uint8_t hash[64];
    uint8_t *blob = snap_build(epoch_start, n, variant, &len, hash);
    if (!blob) return -1;
    int rc = nodus_witness_vset_insert(fx->w, epoch_start, blob, len, hash,
                                       /*created_at_height=*/0);
    free(blob);
    if (rc != 0) return -1;
    if (hash_out) memcpy(hash_out, hash, 64);
    return 0;
}

/* Flip exactly ONE byte of a stored snapshot blob, in C — SQL string
 * surgery on a BLOB column is not a single-byte edit and would prove
 * something vaguer than intended. */
static int corrupt_blob_byte(fixture_t *fx, uint64_t epoch_start,
                             size_t offset) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "SELECT snapshot_blob FROM validator_set_snapshots "
            "WHERE epoch_start = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    int len = sqlite3_column_bytes(st, 0);
    if (len <= 0 || offset >= (size_t)len) {
        sqlite3_finalize(st);
        return -1;
    }
    uint8_t *buf = malloc((size_t)len);
    if (!buf) { sqlite3_finalize(st); return -1; }
    memcpy(buf, sqlite3_column_blob(st, 0), (size_t)len);
    sqlite3_finalize(st);
    buf[offset] ^= 0x01;                 /* ONE bit of ONE byte         */

    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validator_set_snapshots SET snapshot_blob = ?1 "
            "WHERE epoch_start = ?2", -1, &st, NULL) != SQLITE_OK) {
        free(buf);
        return -1;
    }
    sqlite3_bind_blob(st, 1, buf, len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)epoch_start);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    free(buf);
    return (rc == SQLITE_DONE && sqlite3_changes(fx->w->db) == 1) ? 0 : -1;
}

/* Replace the stored hash with `width` zero bytes (64 = a valid-width
 * WRONG hash, 32 = a malformed column). */
static int corrupt_hash(fixture_t *fx, uint64_t epoch_start, int width) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validator_set_snapshots SET snapshot_hash = ?1 "
            "WHERE epoch_start = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_zeroblob(st, 1, width);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)epoch_start);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(fx->w->db) == 1) ? 0 : -1;
}

/* ── §11 quorum arithmetic THROUGH the resolver ─────────────────────── */

static int test_authority_quorum(void) {
    printf("\n§11 dynamic quorum through the resolver\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "quorum") == 0, "bare fixture");

    /* N and the HAND-COMPUTED quorum literal. floor(2N/3)+1:
     *   1→1  2→2  3→3  4→3  6→5  7→5  12→9  86→58  128→86
     * The last is the release ceiling DNA_MAX_ACTIVE_VALIDATORS, and 7→5
     * is the legacy committee's shipped quorum. */
    static const uint16_t Ns[]   = { 1, 2, 3, 4, 6, 7, 12, 86, 128 };
    static const uint32_t QLIT[] = { 1, 2, 3, 3, 5, 5,  9, 58,  86 };
    const size_t NN = sizeof(Ns) / sizeof(Ns[0]);

    CHECK(Ns[NN - 1] == DNA_MAX_ACTIVE_VALIDATORS,
          "the matrix really reaches the release ceiling");

    for (size_t i = 0; i < NN; i++) {
        uint64_t e_start = (uint64_t)(i + 1) * E;
        CHECK(snap_store(&fx, e_start, Ns[i], (uint8_t)(i + 1), NULL) == 0,
              "store synthetic snapshot");

        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, e_start, NULL, &n, &q) == 0, "resolve by epoch");
        CHECK(n == Ns[i], "N comes from the snapshot's own active_count");
        CHECK(q == QLIT[i], "quorum equals the hand-computed literal");
        CHECK(q == dna_bft_quorum(n),
              "and equals the shared formula over the resolved N");

        /* the SAME answer keyed by a height inside that epoch — the
         * historical-certification form */
        uint32_t hn = 0, hq = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, e_start + E / 2, NULL, &hn, &hq) == 0,
              "resolve by height");
        CHECK(hn == n && hq == q,
              "height and epoch forms cannot disagree");
        printf("  ok: N=%3u -> quorum %3u\n", (unsigned)Ns[i],
               (unsigned)q);
    }
    OK();

    /* The snapshot itself is available and self-consistent. */
    {
        dna_vset_snapshot_t *s = NULL;
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, 7 * E, &s, &n, &q) == 0, "resolve with snapshot");
        CHECK(s != NULL, "snapshot handed out");
        CHECK(s->active_count == n, "the reported N IS the snapshot's");
        CHECK(s->epoch == 7 * E, "and it carries its own epoch key");
        CHECK(q == dna_bft_quorum((uint32_t)s->active_count), "quorum");
        dna_vset_free(&s);
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ── §12 the ceiling + 1 dies before the resolver ───────────────────── */

static int test_authority_ceiling(void) {
    printf("\n§12 active_count = ceiling + 1 is unstorable\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "ceil") == 0, "bare fixture");

    const uint16_t OVER = (uint16_t)(DNA_MAX_ACTIVE_VALIDATORS + 1);

    /* (a) the allocator is the FIRST gate — a snapshot that large cannot
     * even be constructed in memory. */
    CHECK(dna_vset_alloc(OVER) == NULL,
          "dna_vset_alloc refuses the ceiling + 1");
    CHECK(dna_vset_alloc(0) == NULL, "and refuses an empty set");
    OK();

    /* (b) a HAND-CRAFTED blob claiming 129 — bypassing the allocator
     * entirely — dies in decode, and dies on the header BEFORE any
     * allocation is attempted. */
    size_t need = (size_t)DNA_VSET_HDR_LEN +
                  (size_t)OVER * (size_t)DNA_VSET_ENTRY_LEN;
    CHECK(need > DNA_VSET_MAX_ENC_LEN,
          "the implied length already exceeds the release maximum");
    uint8_t *big = calloc(1, need);
    CHECK(big != NULL, "alloc");
    big[8]  = (uint8_t)(OVER >> 8);          /* active_count u16 BE      */
    big[9]  = (uint8_t)OVER;
    big[13] = (uint8_t)DNA_VSET_RULESET_TOPN_V1;  /* ruleset u32 BE      */
    {
        dna_vset_snapshot_t *s = NULL;
        CHECK(dna_vset_decode(big, need, &s) == -1,
              "decode refuses a header claiming more than the ceiling");
        CHECK(s == NULL, "and produces no partial result");
    }
    OK();

    /* (c) the storage path refuses it too — blob_len > the maximum. */
    {
        uint8_t h[64];
        CHECK(qgp_sha3_512(big, need, h) == 0, "hash");
        CHECK(nodus_witness_vset_insert(fx.w, E, big, need, h, 0) == -1,
              "vset_insert refuses an over-length blob");
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots "
                        "WHERE epoch_start = %llu", E) == 0,
              "nothing was stored");
    }
    free(big);
    OK();

    /* (d) and so the resolver never sees it: the epoch simply has no
     * committed authority. */
    {
        uint32_t n = 0xDEAD, q = 0xBEEF;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == 1,
              "no authority for an epoch whose oversized snapshot was "
              "refused");
        CHECK(n == 0xDEAD && q == 0xBEEF, "outputs untouched on rc 1");
    }
    OK();
    printf("  ok: dies at alloc, at decode, and at insert\n");

    /* The largest LEGAL set does store and resolve — proving the reject
     * above is the ceiling and not a blanket size failure. */
    CHECK(snap_store(&fx, 2 * E, DNA_MAX_ACTIVE_VALIDATORS, 9, NULL) == 0,
          "the ceiling itself stores");
    {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, 2 * E, NULL, &n, &q) == 0, "resolve");
        CHECK(n == DNA_MAX_ACTIVE_VALIDATORS && q == 86,
              "the ceiling resolves to quorum 86");
    }
    OK();
    fx_close(&fx);
    return 0;
}

/* ── §13 historical authority; the current set is unreachable ───────── */

static int test_authority_historical(void) {
    printf("\n§13 historical authority vs the current set\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "hist") == 0, "bare fixture");

    /* three epochs, three DIFFERENT member counts */
    uint8_t h0[64], h1[64], h2[64];
    CHECK(snap_store(&fx, 0,     3, 1, h0) == 0, "snapshot(0) N=3");
    CHECK(snap_store(&fx, E,     5, 2, h1) == 0, "snapshot(E) N=5");
    CHECK(snap_store(&fx, 2 * E, 7, 3, h2) == 0, "snapshot(2E) N=7");
    OK();

    struct { uint64_t h; uint32_t n, q; } cases[] = {
        { 0,         3, 3 }, { 1,         3, 3 }, { E - 1,     3, 3 },
        { E,         5, 4 }, { E + 1,     5, 4 }, { 2 * E - 1, 5, 4 },
        { 2 * E,     7, 5 }, { 2 * E + 1, 7, 5 }, { 3 * E - 1, 7, 5 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, cases[i].h, NULL, &n, &q) == 0, "resolve height");
        CHECK(n == cases[i].n,
              "each height is served by ITS OWN epoch's snapshot");
        CHECK(q == cases[i].q && q == dna_bft_quorum(n), "its own quorum");
        CHECK(nodus_v2_epoch_start_for_height(cases[i].h) ==
              (cases[i].h / E) * E, "the key is floor(h/E)*E");
    }
    OK();
    printf("  ok: 3 windows, 3 distinct N/quorum pairs (3/3, 5/4, 7/5)\n");

    /* Now MUTATE THE CURRENT SET as violently as the schema allows —
     * add validators, change stakes, flip statuses — and re-resolve a
     * HISTORICAL height. If any part of the answer moved, the current
     * set had leaked into it. (Legal here only because this fixture has
     * no committed chain: see the section note.) */
    for (int k = 0; k < 8; k++)
        CHECK(seed_validator(&fx, k, BOND_BIG,
                             k % 2 ? DNAC_VALIDATOR_ELIGIBLE
                                   : DNAC_VALIDATOR_ACTIVE,
                             (uint16_t)(100 + k), 0, 0) == 0, "seed");
    CHECK(run_sql(fx.w->db,
                  "UPDATE validator_stats SET value = 8 "
                  "WHERE key = 'active_count'") == 0, "count");
    CHECK(run_sql(fx.w->db,
                  "UPDATE validators SET self_stake = self_stake * 2")
          == 0, "restake");
    OK();

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, cases[i].h, NULL, &n, &q) == 0, "re-resolve");
        CHECK(n == cases[i].n && q == cases[i].q,
              "an 8-validator CURRENT set cannot change what governed a "
              "historical height");
    }
    /* byte-identical, not merely equal in N */
    {
        dna_vset_snapshot_t *s = NULL;
        uint8_t hh[64];
        CHECK(nodus_witness_vset_get(fx.w, E, &s, hh) == 0 && s, "get");
        CHECK(memcmp(hh, h1, 64) == 0,
              "the historical snapshot's hash is byte-identical after "
              "the current set churned");
        CHECK(s->active_count == 5, "and still 5 members");
        dna_vset_free(&s);
    }
    OK();
    printf("  ok: current set churn leaves historical answers identical\n");

    /* ABSENCE stays terminal WITH A LIVE CURRENT SET. §14's absence
     * probes run on a bare fixture whose validator_stats.active_count is
     * zero, so a mutant that falls back to the current set on rc 1 is
     * INVISIBLE there (found live: campaign mutant M10 survived §14).
     * This fixture now has 8 seeded validators and active_count = 8 —
     * the tempting fallback value — so the probe below dies iff the
     * resolver ever serves anything but the committed row. */
    {
        uint32_t n = 0xDEAD, q = 0xDEAD;
        dna_vset_snapshot_t *s = (dna_vset_snapshot_t *)0x1;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, 5 * E, &s, &n, &q) == 1,
              "absence with a live current set stays terminal rc 1");
        CHECK(n == 0xDEAD && q == 0xDEAD &&
              s == (dna_vset_snapshot_t *)0x1,
              "and no output moves — the 8-validator current set is not "
              "an authority for an uncommitted epoch");
    }
    OK();
    printf("  ok: absence is terminal even with a live current set\n");

    /* ── §17 restart ───────────────────────────────────────────────── */
    CHECK(fx_reopen(&fx) == 0, "reopen");
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, cases[i].h, NULL, &n, &q) == 0, "resolve");
        CHECK(n == cases[i].n && q == cases[i].q,
              "authority survives a restart unchanged");
    }
    OK();
    printf("  ok: §17 restart reproduces every answer\n");
    fx_close(&fx);
    return 0;
}

/* ── §14 absent, §16 non-canonical key ──────────────────────────────── */

static int test_authority_absent(void) {
    printf("\n§14/§16 absent authority + non-canonical keys\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "absent") == 0, "bare fixture");
    CHECK(snap_store(&fx, E, 7, 1, NULL) == 0, "one snapshot at E");

    /* §14 — no row for that epoch: TERMINAL rc 1, outputs untouched.
     * The caller must fail closed; it must NOT fall back to the current
     * set (nodus_witness_sync.c:900-913 is precisely what this is not). */
    static const uint64_t gaps[] = { 0, 2, 5 };  /* epoch multipliers    */
    for (size_t i = 0; i < sizeof(gaps) / sizeof(gaps[0]); i++) {
        uint32_t n = 0x11111111, q = 0x22222222;
        dna_vset_snapshot_t *s = (dna_vset_snapshot_t *)(uintptr_t)0x1;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, gaps[i] * E, &s, &n, &q) == 1, "absent epoch");
        CHECK(n == 0x11111111 && q == 0x22222222,
              "rc 1 writes no output");
        CHECK(s == (dna_vset_snapshot_t *)(uintptr_t)0x1,
              "and hands out no snapshot");
    }
    /* the far-future case, and the pre-genesis gap (epoch 0 has no row
     * in this fixture even though heights 0..E-1 are perfectly legal) */
    {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, 1000000ULL * E + 5, NULL, &n, &q) == 1,
              "far-future height has no committed authority");
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, 3, NULL, &n, &q) == 1,
              "a pre-genesis-gap height has none either — never the "
              "current set");
    }
    OK();
    printf("  ok: absence is rc 1 and terminal\n");

    /* §16 — one canonical key. E+1 and E-1 name no epoch; they are
     * malformed questions (-1), NOT absent epochs (1), so a caller can
     * never confuse "I asked wrong" with "history has no answer". */
    static const uint64_t bad[] = { 1, E - 1, E + 1, 2 * E + 7, 3 * E - 1 };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint32_t n = 0x33333333, q = 0x44444444;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, bad[i], NULL, &n, &q) == -1,
              "a non-multiple-of-E epoch key is rejected");
        CHECK(n == 0x33333333 && q == 0x44444444, "outputs untouched");
    }
    /* ...and the canonical spelling of the SAME epoch resolves fine */
    {
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == 0 && n == 7 && q == 5,
              "the canonical key for that epoch resolves");
    }
    CHECK(nodus_witness_v2_epoch_authority_for_epoch(NULL, E, NULL, NULL,
                                                     NULL) == -1,
          "a NULL witness is a fault, never an absence");
    OK();
    printf("  ok: non-canonical key -> -1, distinct from absence\n");
    fx_close(&fx);
    return 0;
}

/* ── §15 corrupt rows are faults, never values ──────────────────────── */

static int test_authority_corrupt(void) {
    printf("\n§15 corrupt authority rows fail closed\n");

    /* (a) flip ONE byte of the stored blob → the re-hash disagrees. */
    {
        fixture_t fx;
        CHECK(fx_bare(&fx, "corrblob") == 0, "fixture");
        CHECK(snap_store(&fx, E, 7, 1, NULL) == 0, "store");
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == 0 && n == 7,
              "resolves before the corruption");
        /* offset 40 lands inside the header's sortition_seed — a byte
         * the codec cares about and the hash covers */
        CHECK(corrupt_blob_byte(&fx, E, 40) == 0, "flip one blob byte");
        n = 0x55555555; q = 0x66666666;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == -1,
              "a blob that does not match its hash is a FAULT");
        CHECK(n == 0x55555555 && q == 0x66666666, "outputs untouched");
        fx_close(&fx);
        OK();
    }

    /* (b) corrupt the stored HASH instead — same verdict, other side of
     * the same equality. */
    {
        fixture_t fx;
        CHECK(fx_bare(&fx, "corrhash") == 0, "fixture");
        CHECK(snap_store(&fx, E, 7, 1, NULL) == 0, "store");
        CHECK(corrupt_hash(&fx, E, 64) == 0, "zero the hash, right width");
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == -1,
              "a hash that does not match its blob is a FAULT");
        /* a WRONG-WIDTH hash is equally fatal — never truncated-trusted */
        CHECK(corrupt_hash(&fx, E, 32) == 0, "shrink the hash column");
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == -1,
              "a short hash column is a FAULT");
        fx_close(&fx);
        OK();
    }

    /* (c) a blob that is hash-CONSISTENT but carries an unknown
     * selection_ruleset. It passes the integrity check and dies in
     * DECODE — the deeper gate. Ruleset 0 is INVALID by design (zeroed
     * memory must not decode) and >= 2 is RESERVED for sortition. */
    {
        fixture_t fx;
        CHECK(fx_bare(&fx, "corrver") == 0, "fixture");
        static const uint32_t bad_rs[] = { 0u, 2u, 0xFFFFFFFFu };
        for (size_t i = 0; i < sizeof(bad_rs) / sizeof(bad_rs[0]); i++) {
            uint64_t key = (uint64_t)(i + 1) * E;
            size_t len = 0;
            uint8_t hash[64];
            uint8_t *blob = snap_build(key, 7, (uint8_t)(i + 1), &len,
                                       hash);
            CHECK(blob != NULL, "build");
            blob[10] = (uint8_t)(bad_rs[i] >> 24);
            blob[11] = (uint8_t)(bad_rs[i] >> 16);
            blob[12] = (uint8_t)(bad_rs[i] >> 8);
            blob[13] = (uint8_t)bad_rs[i];
            /* re-hash so the row is INTERNALLY consistent — the point is
             * to reach decode, not to re-test the hash check */
            uint8_t rehash[64];
            CHECK(dna_vset_hash_bytes(blob, len, rehash) == 0, "rehash");
            CHECK(nodus_witness_vset_insert(fx.w, key, blob, len, rehash,
                                            0) == 0,
                  "the storage layer stores it — it only checks the hash");
            free(blob);
            uint32_t n = 0x77777777, q = 0x88888888;
            CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                      fx.w, key, NULL, &n, &q) == -1,
                  "an unknown selection_ruleset dies in decode");
            CHECK(n == 0x77777777 && q == 0x88888888, "outputs untouched");
        }
        fx_close(&fx);
        OK();
    }

    /* (d) a blob whose own epoch field disagrees with the row key — the
     * cross-check. A snapshot filed under the wrong epoch must never
     * govern that epoch. */
    {
        fixture_t fx;
        CHECK(fx_bare(&fx, "corrkey") == 0, "fixture");
        size_t len = 0;
        uint8_t hash[64];
        uint8_t *blob = snap_build(/*blob says*/ 2 * E, 7, 1, &len, hash);
        CHECK(blob != NULL, "build");
        CHECK(nodus_witness_vset_insert(fx.w, /*stored under*/ E, blob,
                                        len, hash, 0) == 0, "insert");
        free(blob);
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(
                  fx.w, E, NULL, &n, &q) == -1,
              "a snapshot whose blob names another epoch is a FAULT");
        fx_close(&fx);
        OK();
    }
    printf("  ok: blob / hash / ruleset / epoch-key corruption all -1\n");
    return 0;
}

/* ── §18 large heights reduce without overflow ──────────────────────── */

static int test_authority_large_height(void) {
    printf("\n§18 large-height reduction\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "huge") == 0, "bare fixture");

    /* The key derivation is division + multiplication, so the result is
     * always <= h and no height can overflow it. Proven at the extreme. */
    CHECK(nodus_v2_epoch_start_for_height(UINT64_MAX) ==
          (UINT64_MAX / E) * E, "UINT64_MAX reduces by division");
    CHECK(nodus_v2_epoch_start_for_height(UINT64_MAX) <= UINT64_MAX,
          "the key never exceeds its height");
    CHECK(nodus_v2_epoch_start_for_height(0) == 0, "genesis reduces to 0");
    CHECK(nodus_v2_epoch_start_for_height(E - 1) == 0 &&
          nodus_v2_epoch_start_for_height(E) == E &&
          nodus_v2_epoch_start_for_height(E + 1) == E,
          "window edges");
    OK();

    /* UINT64_MAX itself: no authority was ever stored there, so the
     * correct answer is the TERMINAL absence — not a fault, not a
     * wrapped key, and certainly not the current set. */
    {
        uint32_t n = 0x99999999, q = 0xAAAAAAAA;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, UINT64_MAX, NULL, &n, &q) == 1,
              "the maximum height resolves to a clean absence");
        CHECK(n == 0x99999999 && q == 0xAAAAAAAA, "outputs untouched");
    }
    OK();

    /* A REPRESENTABLE near-INT64_MAX epoch key does carry authority: the
     * key must survive sqlite3_bind_int64, so the stored epoch_start has
     * to be <= INT64_MAX (the same storage bound the boundary's unlock
     * guard respects). */
    {
        uint64_t hbig = ((uint64_t)INT64_MAX / E) * E;
        CHECK(hbig <= (uint64_t)INT64_MAX && (hbig % E) == 0,
              "hbig is a representable epoch key");
        CHECK(snap_store(&fx, hbig, 12, 7, NULL) == 0, "store at hbig");

        uint64_t probes[] = { hbig, hbig + 1, hbig + E / 2, hbig + E - 1 };
        for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            CHECK(nodus_v2_epoch_start_for_height(probes[i]) == hbig,
                  "every height in the huge window reduces to hbig");
            uint32_t n = 0, q = 0;
            CHECK(nodus_witness_v2_epoch_authority_for_height(
                      fx.w, probes[i], NULL, &n, &q) == 0,
                  "resolve at a huge height");
            CHECK(n == 12 && q == 9,
                  "and it serves that epoch's own authority");
        }
        /* one height past the window belongs to the NEXT epoch, which
         * has no row — the window is exact, not approximate */
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_height(
                  fx.w, hbig + E, NULL, &n, &q) == 1,
              "the next epoch has no authority of its own");
    }
    OK();
    printf("  ok: no h+E on this path; the window is exact at scale\n");
    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== Ledger V2 O12 S2/S3 — epoch boundary + snapshot "
           "authority ===\n");
    printf("(INACTIVE: no live consensus path calls this module)\n");
    /* O15J Faz 2 — this file pins per-block DomainUpdate counts and
     * whole-table row counts across boundaries. Emission makes every
     * block produce a SYSTEM and a CORE update, so those counts change
     * for a reason unrelated to what the file tests. Quiet chain;
     * emission and settlement are covered by test_v2_econ. */
    v2x_inflation_off = 1;
    keys_init();

    /* S2 — the engine-mandatory boundary transition */
    if (test_derivation() != 0) return 1;
    if (test_boundary_chain() != 0) return 1;
    if (test_multi_graduate() != 0) return 1;
    if (test_commit_next() != 0) return 1;
    if (test_faults() != 0) return 1;
    if (test_malformed_row() != 0) return 1;

    /* S3 — the snapshot authority resolver + dynamic quorum */
    if (test_authority_quorum() != 0) return 1;
    if (test_authority_ceiling() != 0) return 1;
    if (test_authority_historical() != 0) return 1;
    if (test_authority_absent() != 0) return 1;
    if (test_authority_corrupt() != 0) return 1;
    if (test_authority_large_height() != 0) return 1;

    printf("\n=== ALL %d CHECK GROUPS PASSED ===\n", g_checks);
    return 0;
}
