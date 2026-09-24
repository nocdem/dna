/**
 * Nodus — Ledger V2 O12 S2: the ENGINE-MANDATORY epoch-boundary
 * transition (nodus_witness_v2_epoch.{h,c}) driven through the real V2
 * apply engine in its cometbft lane (tokenomics-v3 P4: every genesis
 * here is a seeded version-3 genesis and every block goes through
 * v2x_cmt_apply, the test acting as the host — v2_genesis_fixture.h).
 *
 * Sections:
 *   §1  DERIVATION MATRIX — the boundary fires exactly at H % E == 0 for
 *       H > 0; genesis does not fire; E−1 / E+1 do not fire; the module
 *       is a no-op on every non-boundary height (DB digest byte-identical);
 *       and the H + 84·E (DNAC_VALIDATOR_UNBOND_EPOCHS, P3-3) storage-bound
 *       guard is
 *       fail-closed at a representable near-INT64_MAX multiple of E.
 *   §2  GRADUATION — a RETIRING row graduates at the boundary and NOT
 *       one block before; the release UTXO carries the record's ACTUAL
 *       bond (seeded ABOVE DNAC_SELF_STAKE_AMOUNT so the macro cannot
 *       pass by accident), the independently recomputed grad_id as
 *       tx_hash, the recomputed nullifier as the row key, the
 *       destination fp as owner, unlock H + 84·E (P3-3), index 200,
 *       domain CORE, created_at 0; the bond zeroes, the status becomes
 *       UNSTAKED, everything else on the row is byte-unchanged,
 *       active_count drops by exactly one, and the supply gate is GREEN.
 *   §3  NO DOUBLE GRADUATION — the boundary height applied again is a
 *       node FAULT with a byte-identical digest (the cometbft lane has
 *       no idempotent replay), and the NEXT boundary does not re-graduate
 *       an UNSTAKED row.
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
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT (§12e-i) */
#include "witness/nodus_witness_v2_econ.h"   /* P3: the balance copy (§12i)
                                              * + the settlement identity
                                              * (§2e)                     */
#include "witness/nodus_witness_delegation.h"/* P3-4: seeded delegations  */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"        /* CMT_PB_BLOCK_ID_FLAG_COMMIT (Q1)      */
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
/* The graduation lock, tokenomics-v3 P3-3 (decision §1 "Validator bekleme
 * süresi 84 epoch"): 84 epochs past the graduation boundary. Spelled with
 * the LITERAL 84 rather than DNAC_VALIDATOR_UNBOND_EPOCHS, so a drift of
 * the constant turns every `unlock == H + CD` below red (RED ON THE
 * PRE-P3 TREE: the lock was DNAC_UNSTAKE_COOLDOWN_BLOCKS = 17280 = 24
 * epochs at E = 720). */
#define CD  (84ULL * E)
/* the delegator lock the graduation's delegation release uses (P3-4):
 * decision §1 "Delegator bekleme süresi 12 epoch", literal likewise */
#define CD_DELEG  (12ULL * E)

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

/* A zero-envelope block as nodus_cmt_app_finalize_block hands it to the
 * engine. Its identity (the Comet block hash) comes from the host's
 * block-store record v2x_cmt_apply writes (v2_genesis_fixture.h) — the
 * same record the boundary's committee seed later reads back at the
 * lookback height — so a boundary block driven twice in two twin
 * fixtures carries the SAME id. */
static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
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
 * The LEGACY seed row — used ONLY by the §14 preview case, which runs on
 * a bare, NON-successor database (fx_bare: no genesis, v2_successor
 * false). There nodus_committee_compute_for_epoch reads the legacy
 * `blocks` row at e_start − E − 1 for its state_seed tiebreak (the
 * `v2_successor == false` branch of nodus_witness_committee.c), so the
 * test plants that one row with a FIXED deterministic state_root.
 * `blocks.height` is an explicit column, so the row is planted at the
 * exact height — nodus_witness_block_add only ever APPENDS.
 *
 * tokenomics-v3 P4: every GENESIS-based case in this file is a
 * version-3 chain (v2_successor true), whose seed source is the host's
 * block-store record at that height (nodus_witness_committee.c
 * v2_seed_block_id); v2x_cmt_apply writes that record for every block
 * it applies, so those cases plant nothing.
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
 *                    engine genesis so a test can still shape its
 *                    pre-chain state (a late joiner, a status flip, a
 *                    malformed legacy row) with the snapshots ALREADY
 *                    FROZEN.
 *   fx_v2_genesis  — stage 2: the engine genesis itself. After this call
 *                    the fixture is a live chain and NOTHING may write a
 *                    consensus table except through a block.
 *
 * tokenomics-v3 P4: the two stages ARE the seeded version-3 genesis
 * (v2_genesis_fixture.h): stage 1 opens with v2x_seed_prepare (the
 * derivation's step 4: live rung S16, v2_successor before any validator
 * row, the economic band), stage 2 is v2x_seed_genesis (the committed
 * authority, the registry, the engine genesis
 * nodus_witness_v2_genesis_cmt, the stored document, the reopen through
 * the production open path). These chains carry validator sets, bonds
 * and genesis UTXOs a version-3 config cannot express, which is why they
 * are seeded rather than derived.
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
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_epoch_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (v2x_seed_prepare(fx->w, fx->chain_id16, 0) != 0) return -1;

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
    /* not a real genesis: stage 1 always seeds a spendable UTXO_A row
     * (the fee funding every driven block spends). */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    {
        /* not a real genesis: these chains model PRE-CHAIN lifecycle
         * states — RETIRING graduates, AUTO_RETIRED and ELIGIBLE rows —
         * that a version-3 genesis (every row ACTIVE) cannot write; the
         * subjects of §2-§10 are exactly those rows. Only named when
         * such a row is present, so an all-ACTIVE chain keeps the real
         * genesis's active_count (every row). */
        uint64_t nonact = q1(fx->w, "SELECT COUNT(*) FROM validators "
                                    "WHERE status != 0");
        if (nonact == UINT64_MAX) return -1;
        if (nonact != 0) v2x_seed_not_real(V2X_SEED_NOT_REAL_STATUSES);
    }
    if (v2x_seed_genesis(fx->w, fx->chain_id16, 0, NULL, 0, NULL) != 0)
        return -1;
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

/* A restart.
 *
 * A VERSION-3 chain (every genesis-based case — tokenomics-v3 P4)
 * reopens through the PRODUCTION open path,
 * nodus_witness_create_chain_db, whose post-open gate recognises it from
 * its stored document and sets v2_successor / v2_chain32 again.
 *
 * The BARE, non-successor fixture (fx_bare, §11-§14) is no chain at all
 * — it has no stored document, and the §14 case plants a legacy
 * `blocks` row — so the gate would refuse it (outcome (c), exactly as
 * test_v2_restart_gate.c pins); its subject is persistence of the
 * snapshot rows, not the chain-role gate. It reopens the SAME file
 * directly with the PRAGMAs witness_db_open_attempt (nodus_witness.c)
 * sets and nothing else: journal_mode=WAL, synchronous=NORMAL and a busy
 * timeout; there is no foreign_keys pragma in the witness sources to
 * replicate. */
static int fx_reopen(fixture_t *fx) {
    if (fx->w->v2_successor) {
        sqlite3_close(fx->w->db);
        fx->w->db = NULL;
        fx->w->cached_committee_epoch_start = UINT64_MAX;
        fx->w->chain_config_cache_warm = false;
        return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
    }
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;

    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", fx->chain_id16[i]);
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/witness_%s.db", fx->dir, hex);

    int rc = sqlite3_open_v2(db_path, &fx->w->db, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_busy_timeout(fx->w->db, NODUS_W_DB_BUSY_TIMEOUT_MS);
    sqlite3_exec(fx->w->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(fx->w->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    fx->w->cached_committee_epoch_start = UINT64_MAX;
    return 0;
}

/* round 2 (R2-2) — every CURRENTLY ACTIVE validator's voter_id (SHA3-512
 * of its pubkey, truncated to 32 bytes — vset_wire.h's own key, the
 * SAME derivation `rn_block` below already uses), queried LIVE from the
 * `validators` table rather than any fixture-side key list: different
 * cases in this file seed different subsets of `g_pk[]` via `vspec_t`,
 * so a hardcoded index list would silently stop matching whichever case
 * changed its own seeding. `addrs` is capped at N_KEYS (10) — this
 * file's whole validator pool — so the query itself refuses to overrun
 * it rather than truncate silently. */
static int fx_active_voters(fixture_t *fx, uint8_t addrs[N_KEYS][32],
                            size_t *n_out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "SELECT pubkey FROM validators WHERE status = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_ACTIVE);
    size_t n = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= N_KEYS) { sqlite3_finalize(st); return -1; }
        const void *pk = sqlite3_column_blob(st, 0);
        int pklen = sqlite3_column_bytes(st, 0);
        uint8_t digest[64];
        if (pklen != (int)DNAC_PUBKEY_SIZE || !pk ||
            qgp_sha3_512((const uint8_t *)pk, DNAC_PUBKEY_SIZE, digest)
                != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        memcpy(addrs[n], digest, 32);
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    *n_out = n;
    return 0;
}

/* Apply one zero-envelope block at the next height. Plants the legacy
 * lookback row a boundary needs BEFORE applying.
 *
 * round 2 (R2-2, MEASURED): once R2-1 lands the attendance tables in the
 * base schema, Rule N evaluates every ACTIVE row against REAL
 * attendance — a fixture driving blocks WITHOUT `blk->cmt.votes_*`
 * credits nobody, so every ACTIVE validator misses every boundary and
 * two consecutive misses AUTO_RETIRE the whole set (Rule N working
 * correctly, not a defect) — but a case whose SUBJECT is something else
 * entirely (graduation, restart, a staking envelope, determinism) must
 * not have its validator set dissolve underneath it. `fx_block` now
 * feeds a FULL-COMMITTEE COMMIT vote on every block above the initial
 * height, keeping Rule N a no-op for every case that drives through it.
 * `test_rule_n_liveness`'s own `rn_block`/`rn_drive` (below) are
 * UNTOUCHED — that case deliberately drives PARTIAL attendance and must
 * keep doing so; it does not call this function.
 *
 * LIFETIME NOTE: `addrs`/`flags` are this function's own stack arrays;
 * `*out_blk = b` copies the `nodus_v2_block_t` (including the pointers
 * into them) but NOT their storage. Safe only because
 * `nodus_witness_v2_apply_block` runs (and this function returns) before
 * any caller could dereference `out_blk->cmt.votes_address` — the one
 * caller that reads `out_blk` at all (test_v2_epoch.c's own §2 boundary
 * case) reads only `.n_envs`. A future caller must not read
 * `out_blk->cmt.*` after this function returns. */
static int fx_block(fixture_t *fx, nodus_v2_block_t *out_blk, int *rc_out) {
    uint64_t h = fx->height + 1;
    nodus_v2_block_t b;
    mk_block(&b, h);
    uint8_t addrs[N_KEYS][32];
    int32_t flags[N_KEYS];
    if (h > 1) {
        size_t n = 0;
        if (fx_active_voters(fx, addrs, &n) != 0) return -1;
        if (n > 0) {
            for (size_t i = 0; i < n; i++)
                flags[i] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
            b.cmt.votes_address = (const uint8_t (*)[32])addrs;
            b.cmt.votes_block_id_flag = flags;
            b.cmt.votes_len = n;
        }
    }
    /* the cometbft lane, the test as the host (v2x_cmt_apply): 0
     * committed, NODUS_V2_INTERNAL_FAULT rolled back */
    int rc = v2x_cmt_apply(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc == 0) fx->height = h;
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
 * is byte-identical afterwards. In the cometbft lane every boundary
 * stage fault is a node FAULT (a boundary has no verdict class, and a
 * decided block is never refused), which the host rolls back.
 * @return 0 iff rc was NODUS_V2_INTERNAL_FAULT AND the digest did not
 * move. */
static int fx_block_inject(fixture_t *fx, nodus_v2_apply_fail_t pt,
                           int *rc_out) {
    uint64_t h = fx->height + 1;
    uint8_t d0[64], d1[64];
    if (db_state_digest(fx->w, d0) != 0) return -1;
    nodus_v2_block_t b;
    mk_block(&b, h);
    b.fail_at = pt;
    int rc = v2x_cmt_apply(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc != NODUS_V2_INTERNAL_FAULT) return -1;
    /* A boundary failure is a NODE FAULT, never a verdict — and the body
     * says so itself (phase 6e's V2AP_FAULT), before the wrapper's fold
     * could have made anything look like one. */
    if (v2x_reason_is(&b, V2X_FAULT, "phase 6e") != 0) return -1;
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
     * INT64_MAX that H + 84·E (P3-3) leaves the SQLite
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

        /* round 5 (R5-3): `v2ep_graduate` now resolves the EFFECTIVE
         * snapshot at `hbig` first and defers any candidate still an
         * entry of it — with NO snapshot committed for `hbig` at all,
         * that resolution would itself fail (-2, "unreadable"), which is
         * ALSO an honest fail-closed answer but not the SPECIFIC guard
         * (the unlock-height overflow check, deeper in the candidate
         * loop) this case is named for and exists to reach. Seed a
         * minimal synthetic one-member snapshot at `hbig` whose member
         * is NOT g_pk[6] (a synthetic pubkey), so the resolver succeeds,
         * key 6 is correctly found absent from it (never deferred), and
         * the candidate loop actually reaches the overflow guard. */
        {
            dna_vset_snapshot_t *hs = dna_vset_alloc(1);
            CHECK(hs != NULL, "alloc synthetic snapshot");
            hs->epoch = hbig;
            memset(hs->entries[0].pubkey, 0xAB, DNA_VSET_PUBKEY_LEN);
            uint8_t full[64];
            CHECK(qgp_sha3_512(hs->entries[0].pubkey, DNA_VSET_PUBKEY_LEN,
                               full) == 0, "hash synthetic pubkey");
            memcpy(hs->entries[0].voter_id, full, DNA_VSET_VOTER_ID_LEN);
            hs->entries[0].total_stake    = 1000;
            hs->entries[0].self_bond      = 1000;
            hs->entries[0].commission_bps = 100;
            uint8_t *hbuf = malloc(DNA_VSET_MAX_ENC_LEN);
            CHECK(hbuf != NULL, "alloc encode buffer");
            size_t hlen = 0;
            uint8_t hhash[64];
            CHECK(dna_vset_encode(hs, hbuf, DNA_VSET_MAX_ENC_LEN, &hlen)
                      == 0 && dna_vset_hash(hs, hhash) == 0,
                  "encode+hash synthetic snapshot");
            dna_vset_free(&hs);
            CHECK(nodus_witness_vset_insert(fx.w, hbig, hbuf, hlen, hhash,
                                            0) == 0,
                  "seed synthetic snapshot at hbig");
            free(hbuf);
        }

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
    /* round 5 (R5-3) note: keys 3 and 6 are seeded RETIRING/AUTO_RETIRED
     * directly IN THE SPECS, before `fx_genesis`'s own
     * `nodus_witness_vset_commit_genesis` call runs — exactly the
     * `test_rule_n_retiring_excluded` pattern, and for the SAME reason:
     * `nodus_validator_top_n` (status IN (ACTIVE, ELIGIBLE) only) never
     * selects a RETIRING/AUTO_RETIRED row, so both are ALREADY absent
     * from snapshot(0) and snapshot(E) the moment they are built. Before
     * round 5 both were seeded ACTIVE and flipped by direct SQL AFTER
     * the freeze (modeling "already RETIRING/AUTO_RETIRED before this
     * boundary" the same way `test_rule_n_retiring_excluded` always
     * has) — that ordering put both keys INSIDE the frozen snapshot(E),
     * which R5-3 now DEFERS graduation for (a candidate still an entry
     * of the snapshot taking effect this boundary is left untouched).
     * Seeding pre-freeze instead keeps this test's actual SUBJECT
     * (graduation payout, flips, replay, next-boundary non-regraduation)
     * unaffected: everything below this point still graduates exactly
     * at boundary E, because neither key was ever a snapshot member. */
    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0,    0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0,    0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0,    0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_AUTO_RETIRED, 100, 0,    0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 777,  E },
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 888,  2 * E },
        { 6, BOND_BIG,  DNAC_VALIDATOR_RETIRING,     250, 0,    0 },
    };
    /* n_active_count = 6, not 7: the D-11 active_count invariant counts
     * every row NOT YET GRADUATED (ACTIVE stays counted; RETIRING stays
     * counted until it actually graduates — rt_native.c:3381,
     * "self_stake stays untouched and active_count is NOT [decremented]"
     * at UNSTAKE-request time) MINUS AUTO_RETIRED (decremented the SAME
     * step Rule N sets it — v2ep_rule_n). So the honest baseline here is
     * 5 ACTIVE (0,1,2,4,5) + 1 RETIRING-but-not-yet-graduated (6) = 6;
     * key 3 (AUTO_RETIRED) is NOT counted, modeling that Rule N already
     * decremented it in a prior, unmodeled cycle — the SAME fact the
     * pre-round-5 fixture modeled explicitly with a later SQL UPDATE
     * (removed below, now baked into this baseline instead). */
    CHECK(fx_genesis(&fx, "chain", specs, 7, 6) == 0, "genesis");

    /* key 7 joins AFTER the genesis snapshots were frozen but BEFORE the
     * V2 genesis, so it is bonded, absent from snapshot(E) — the flip
     * fixture — and still inside the pre-chain window. Its bond must
     * enter the supply equation too. */
    /* key 7 also carries the REAL-WORLD pending-commission shape the R3
     * review found untested: an increase submitted OFF-boundary wrote
     * pending_effective_block = H + E, which is never boundary-aligned
     * (here: a submission at H=3 → peff = E+3). (The V2 writer stores
     * H + 2E since the P3 fix round — decision file §3 2026-09-24; this
     * case pins the ACTIVATOR's `<=` on a hand-set peff, whose subject
     * does not depend on which writer produced it.) Under the legacy
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
                  "UPDATE validator_stats SET value = 7 "
                  "WHERE key = 'active_count'") == 0, "count 7 (6 + key 7)");

    /* UNSTAKE-shaped pre-state: key 6 RETIRING with its bond intact —
     * exactly what the O11 UNSTAKE apply leaves behind (the principal
     * release is DEFERRED to this boundary). `unstake_commit_block`
     * cannot be set through `vspec_t`/`seed_validator`, so it is still
     * set here by direct mutation — AFTER the freeze, which is fine:
     * it does not change key 6's STATUS (already RETIRING since specs),
     * so it cannot change snapshot(E)'s membership either. */
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get 6");
        v.unstake_commit_block = 3;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "unstake_commit_block");
    }
    /* Neither key 6 (RETIRING) nor key 3 (AUTO_RETIRED) is a member of
     * ANY committed snapshot (both were non-ACTIVE/non-ELIGIBLE before
     * `fx_genesis`'s own commit ran) — the pre-round-5 comment here
     * explaining a SEPARATE active_count correction for key 3 is GONE
     * because that correction is now baked into the genesis baseline
     * (n_active_count = 6, above). What remains true and IS still
     * discriminating below: only key 6's RETIRING-origin graduation may
     * move active_count at the boundary (7 -> 6) — key 3's AUTO_RETIRED-
     * origin graduation must NOT move it a second time (D-11); a build
     * that (wrongly) decremented for both would land on 5, not 6. */

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
                       "key='active_count'") == 7,
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
              "unlock = H + 84·E (P3-3; was H + 17280 = H + 24E)");
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

    /* the counter, and the invariant the whole transition exists to keep.
     * tokenomics-v3 P1 (D-11): TWO graduates fire at this boundary now
     * (key 6 RETIRING, key 3 AUTO_RETIRED), but only ONE of them may
     * decrement active_count here — the RETIRING-origin one (key 6). A
     * real Rule N AUTO_RETIRE flip decrements active_count in the SAME
     * step it sets the status, so by the time key 3 reaches this
     * boundary as AUTO_RETIRED, the count must already reflect that
     * decrement. The fixture flips key 3 via raw SQL (no Rule N pass
     * runs in this test), so it models that prior decrement explicitly:
     * count is set to 8 at line ~906 (7 genesis + late-joiner key 7),
     * then dropped to 7 right after key 3 is flipped to AUTO_RETIRED,
     * with a comment there explaining why. Starting from that honest
     * baseline of 7, THIS boundary's graduation sweep must decrement
     * exactly once more — for key 6 only, per D-11 — landing on 6. A
     * regression that double-decrements for the AUTO_RETIRED-origin
     * graduate too would land on 5, not 6; this assertion is what
     * catches that. */
    CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                   "key='active_count'") == 6,
          "active_count decremented by exactly one at this boundary "
          "(D-11: only for the RETIRING-origin graduate, key 6 — key 3's "
          "AUTO_RETIRED-origin graduation does not decrement again, "
          "since Rule N already did when it set that status — see the "
          "comment above)");
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
        /* tokenomics-v3 P1 (D-11, round 5 note): AUTO_RETIRED graduates
         * the SAME boundary it is found at (v2ep_graduate runs at step 2,
         * BEFORE the flips at step 4), so by the time the flips run
         * validator 3 is already UNSTAKED, not AUTO_RETIRED. Since round
         * 5 (R5-3), validator 3 was ALSO never a member of snapshot(E) in
         * the first place (seeded AUTO_RETIRED before the genesis freeze,
         * above) — pass 2 walks ONLY the snapshot's own entries, so it
         * never visits validator 3's row at all; there is nothing here
         * for "AND status = ELIGIBLE" to refuse. The PROPERTY this case
         * pins ("a graduated row is never resurrected by the flips") is
         * unchanged; the MECHANISM is "pass 2 never reaches it" rather
         * than "pass 2 reaches it and declines" (that second mechanism —
         * a candidate still IN the effective snapshot, deferred, RETIRING
         * at flip time — is pinned separately, see the graduation
         * deferral test). */
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED,
              "validator 3 graduated to UNSTAKED at this boundary and "
              "the flips do not touch it (never a snapshot member)");
        CHECK(v.self_stake == 0,
              "D-11: the AUTO_RETIRED graduate's bond moved into its "
              "release UTXO too");
        CHECK(val_get(&fx, 6, &v) == 0, "get 6");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED,
              "validator 6 graduated the same way, same reason — not a "
              "snapshot member, so the flips do not touch it either");
        OK();
        printf("  ok: flips demote/seat/never resurrect\n");
    }

    /* D-11: validator 3's release UTXO exists too — the SAME boundary
     * graduated TWO candidates (RETIRING key 6 AND AUTO_RETIRED key 3),
     * ORDER BY pubkey ASC over their union. */
    {
        uint8_t gid3[64], nul3[64];
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[3], gid3)
              == 0, "grad_id 3");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(gid3, nul3) == 0,
              "nul 3");
        utxo_row_t r3;
        CHECK(utxo_get(fx.w, nul3, &r3) == 0, "utxo probe 3");
        CHECK(r3.found, "D-11: the AUTO_RETIRED graduate released a UTXO "
                        "too, no cut to principal");
        CHECK(r3.amount == BOND_BASE,
              "the release pays validator 3's ACTUAL bond");
        CHECK(memcmp(r3.owner, g_fp[3], 128) == 0,
              "owner is validator 3's unstake_destination_fp");
        CHECK(r3.unlock_block == E + CD,
              "unlock = H + 84·E (P3-3), same as any "
              "other graduate");
        OK();
        printf("  ok: D-11 AUTO_RETIRED graduates alongside RETIRING, "
               "same boundary, bond returned\n");
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
        /* tokenomics-v3 P4: the legacy lane's rc-1 idempotent replay (an
         * asserted expect_block_id) has NO cometbft-lane counterpart —
         * the lane refuses identity assertions and consensus never
         * re-delivers a finalized height. The boundary height again is a
         * node FAULT the host rolls back; what this section pins — the
         * replay writes nothing and releases no second bond — is
         * asserted on that. */
        nodus_v2_block_t rb;
        mk_block(&rb, E);
        int rc = v2x_cmt_apply(fx.w, &rb);
        CHECK(rc == NODUS_V2_INTERNAL_FAULT &&
              v2x_reason_is(&rb, V2X_VERDICT, "at or below") == 0,
              "byte-identical replay is the no-write idempotent path");
        CHECK(db_state_digest(fx.w, d1) == 0, "digest");
        CHECK(memcmp(d0, d1, 64) == 0, "replay wrote nothing");
        /* tokenomics-v3 P1 (D-11): TWO graduates at this boundary now
         * (RETIRING key 6 AND AUTO_RETIRED key 3), so TWO graduation
         * UTXOs — the replay must not create a THIRD. */
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "output_index = 200") == 2,
              "exactly TWO graduation UTXOs exist after the replay "
              "(D-11: key 6 RETIRING + key 3 AUTO_RETIRED)");
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
         * whole-table count would grow". Since tokenomics-v3 P2 no
         * boundary writes a payout UTXO except a PAYDAY (every
         * payout_interval_epochs-th epoch — the stored document's
         * default here, P2-7), which this
         * section never reaches, and every fixture here seeds an empty
         * reward pool. The narrowing is still right — it says what the
         * assertion always meant — but it is a PRECISION fix, not a
         * repair of a break.
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
              "an UNSTAKED row is not selected by the RETIRING/"
              "AUTO_RETIRED scan (D-11) — no second release");
        uint8_t gid2[64], nul2[64];
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, 2 * E, g_pk[6],
                                             gid2) == 0, "grad_id 2E");
        CHECK(nodus_witness_v2_epoch_grad_nullifier(gid2, nul2) == 0,
              "nul 2E");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul2, &r) == 0, "probe");
        CHECK(!r.found, "no 2E-height release for the same validator");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 6,
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
 * §2e THE GRADUATION RELEASES THE GRADUATE'S DELEGATIONS
 *     (tokenomics-v3 P3-4; decision file §3 2026-09-24 "P3 soruları" (3)
 *     "validator mezun olduğunda kalan delegasyonlar otomatik olarak
 *     UNDELEGATE gibi, delegator kilidiyle (12 epoch) sahiplerine döner";
 *     design §8 P3-4)
 *
 * Seed (every row pre-freeze or pre-genesis — the two-stage rule):
 *   keys 0,1,2,4,5 ACTIVE; key 3 AUTO_RETIRED and key 6 RETIRING, both
 *   seeded BEFORE the genesis snapshots so neither is an entry of
 *   snapshot(E) — both graduate at E (the test_boundary_chain pattern).
 *   Delegations: key 7 → key 3 (5·MIN), key 8 → key 6 (3·MIN),
 *   key 9 → key 6 (2·MIN), and key 9 → key 0 (1·MIN, a NON-graduate —
 *   must survive untouched). MIN = DNAC_MIN_DELEGATION.
 *
 * Expected at E, by hand:
 *   tx_hash   = SHA3-512("settlement" ‖ u64be(E)) — recomputed here from
 *               the bytes, not through the production helper;
 *   ranks     = graduates in pubkey ASC (key 3's first byte 0x13 < key 6's
 *               0x16), each graduate's delegations in delegator_hash ASC
 *               (SHA3-512(0x03 ‖ pubkey), computed and ordered here):
 *               key 3's one delegation rank 0, key 6's two ranks 1 and 2;
 *   index     = 0x40000000 + rank (the band below 2^31 — P3 fix round;
 *               the first cut's 0x80000000 needed signed narrowing);
 *   nullifier = SHA3-512(tx_hash ‖ 0x23 ‖ u32be(index));
 *   row       = owner hex(SHA3-512(delegator pk)), the delegation amount,
 *               unlock E + 12E, block_height E, domain CORE, created_at 0;
 *   the three delegation rows are DELETED, the two graduates' total/
 *   external_delegated are 0, key 9 → key 0 is untouched, copy(E) holds no
 *   row of either graduate, and the supply equation closes.
 * F60 (V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE, first graduate = key 3)
 * rolls the boundary back byte-identically — asserted here on the rows the
 * release touched: no release UTXO at any of the three nullifiers, all
 * four delegation rows back, and both graduates' status / bond / BOTH
 * delegated totals exactly as seeded — and the clean retry commits.
 *
 * RED ON THE PRE-P3 TREE: the graduation released only the bond and left
 * total_delegated on an UNSTAKED row — the delegations stayed bonded to
 * a validator that no longer exists, no release UTXO appeared, and F60
 * did not exist (an unknown stage id fails closed).
 * KILLED BY: releasing to the validator's destination instead of the
 * delegator; unlock at the 84-epoch validator lock or unlocked; a rank
 * that restarts per graduate (key 6's first release would reuse index
 * 0x40000000 — the same (tx_hash, index) pair as key 3's); a kind byte or
 * index band shared with the payday; leaving the rows or the totals
 * behind; running after the balance copy (copy(E) would hold them). */
static int test_grad_deleg_release(void) {
    printf("\n§2e graduation releases the graduate's delegations "
           "(tokenomics-v3 P3-4)\n");
    const uint64_t MIN = (uint64_t)DNAC_MIN_DELEGATION;
    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_AUTO_RETIRED, 100, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0, 0 },
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE,       100, 0, 0 },
        { 6, BOND_BIG,  DNAC_VALIDATOR_RETIRING,     250, 0, 0 },
    };
    /* (delegator, validator, amount) */
    const int      dl_d[4] = { 7, 8, 9, 9 };
    const int      dl_v[4] = { 3, 6, 6, 0 };
    const uint64_t dl_a[4] = { 5 * MIN, 3 * MIN, 2 * MIN, 1 * MIN };

    fixture_t fx;
    /* active_count 6: 5 ACTIVE + key 6 RETIRING (not yet graduated);
     * key 3 AUTO_RETIRED already left it (test_boundary_chain's note) */
    CHECK(fx_genesis(&fx, "gdel", specs, 7, 6) == 0, "genesis stage 1");
    uint64_t dsum = 0;
    for (int i = 0; i < 4; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, g_pk[dl_d[i]], DNAC_PUBKEY_SIZE);
        memcpy(d.validator_pubkey, g_pk[dl_v[i]], DNAC_PUBKEY_SIZE);
        d.amount = dl_a[i];
        CHECK(nodus_delegation_insert(fx.w, &d) == 0, "seed delegation");
        dnac_validator_record_t v;
        CHECK(val_get(&fx, dl_v[i], &v) == 0, "get target");
        v.total_delegated    += dl_a[i];
        v.external_delegated += dl_a[i];
        CHECK(nodus_validator_update(fx.w, &v) == 0, "target totals");
        dsum += dl_a[i];
    }
    {
        char sql[224];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = current_supply "
                 "+ %llu WHERE id = 1",
                 (unsigned long long)dsum, (unsigned long long)dsum);
        CHECK(run_sql(fx.w->db, sql) == 0, "supply += delegated");
    }
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply green at genesis");
    OK();

    /* ── the hand-derived identities ────────────────────────────────── */
    uint8_t txh[64];
    {
        uint8_t pre[18];
        memcpy(pre, "settlement", 10);
        for (int i = 0; i < 8; i++)
            pre[10 + i] = (uint8_t)(E >> (56 - 8 * i));
        CHECK(qgp_sha3_512(pre, sizeof(pre), txh) == 0, "tx_hash");
        uint8_t prod[64];
        CHECK(nodus_witness_v2_settlement_tx_hash(E, prod) == 0 &&
              memcmp(prod, txh, 64) == 0,
              "FIXTURE GUARD: the hand tx_hash equals the payday's");
    }
    /* key 6's two delegators in delegator_hash ASC */
    int k6_first = 8, k6_second = 9;
    {
        uint8_t pre[1 + DNAC_PUBKEY_SIZE], h8[64], h9[64];
        pre[0] = (uint8_t)NODUS_TREE_TAG_DELEGATION;
        memcpy(pre + 1, g_pk[8], DNAC_PUBKEY_SIZE);
        CHECK(qgp_sha3_512(pre, sizeof(pre), h8) == 0, "h8");
        memcpy(pre + 1, g_pk[9], DNAC_PUBKEY_SIZE);
        CHECK(qgp_sha3_512(pre, sizeof(pre), h9) == 0, "h9");
        if (memcmp(h9, h8, 64) < 0) { k6_first = 9; k6_second = 8; }
    }
    CHECK(g_pk[3][0] < g_pk[6][0], "FIXTURE GUARD: key 3 sorts first");
    /* rank r → (delegator, amount) */
    const int      r_del[3] = { 7, k6_first, k6_second };
    const uint64_t r_amt[3] = { 5 * MIN,
                                k6_first == 8 ? 3 * MIN : 2 * MIN,
                                k6_first == 8 ? 2 * MIN : 3 * MIN };
    uint8_t nul[3][64];
    for (int r = 0; r < 3; r++) {
        uint8_t pre[64 + 1 + 4];
        const uint32_t idx = 0x40000000u + (uint32_t)r;
        memcpy(pre, txh, 64);
        pre[64] = 0x23;
        pre[65] = (uint8_t)(idx >> 24); pre[66] = (uint8_t)(idx >> 16);
        pre[67] = (uint8_t)(idx >> 8);  pre[68] = (uint8_t)idx;
        CHECK(qgp_sha3_512(pre, sizeof(pre), nul[r]) == 0, "nul");
    }
    CHECK(NODUS_V2_GRAD_DELEG_KIND == 0x23 &&
          NODUS_V2_GRAD_DELEG_OUT_IDX_BASE == 0x40000000u,
          "FIXTURE GUARD: the P3-4 kind and band"); OK();

    /* ── F60: interrupt after the first graduate's delegation release ─ */
    CHECK(fx_drive_to(&fx, E - 1) == 0, "drive to E-1");
    /* the pre-boundary image of every row the release touches */
    dnac_validator_record_t pre3, pre6;
    CHECK(val_get(&fx, 3, &pre3) == 0 && val_get(&fx, 6, &pre6) == 0,
          "pre-boundary graduate rows");
    CHECK(pre3.total_delegated == 5 * MIN &&
          pre3.external_delegated == 5 * MIN &&
          pre6.total_delegated == 5 * MIN &&
          pre6.external_delegated == 5 * MIN,
          "FIXTURE GUARD: both graduates hold their seeded delegations");
    {
        int rc = 0;
        CHECK(fx_block_inject(&fx, V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE,
                              &rc) == 0 && rc == -2,
              "F60 rolls the boundary back byte-identically");
        for (int r = 0; r < 3; r++) {
            utxo_row_t u;
            CHECK(utxo_get(fx.w, nul[r], &u) == 0 && !u.found,
                  "F60 left no release UTXO");
        }
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 4,
              "F60 restored all four delegation rows (key 3's included — "
              "its release ran before the fault)");
        for (int i = 0; i < 3; i++) {
            dnac_delegation_record_t d;
            CHECK(nodus_delegation_get(fx.w, g_pk[dl_d[i]], g_pk[dl_v[i]],
                                       &d) == 0 && d.amount == dl_a[i],
                  "F60 restored the graduates' delegation rows and amounts");
        }
        dnac_validator_record_t v3, v6;
        CHECK(val_get(&fx, 3, &v3) == 0 && val_get(&fx, 6, &v6) == 0,
              "post-F60 graduate rows");
        CHECK(v3.status == pre3.status && v3.self_stake == pre3.self_stake &&
              v3.total_delegated == pre3.total_delegated &&
              v3.external_delegated == pre3.external_delegated,
              "F60 restored key 3's status, bond and BOTH delegated totals");
        CHECK(v6.status == pre6.status && v6.self_stake == pre6.self_stake &&
              v6.total_delegated == pre6.total_delegated &&
              v6.external_delegated == pre6.external_delegated,
              "F60 restored key 6's status, bond and BOTH delegated totals");
        OK();
    }

    /* ── the clean boundary ─────────────────────────────────────────── */
    {
        int rc = 0;
        CHECK(fx_block(&fx, NULL, &rc) == 0 && rc == 0 && fx.height == E,
              "the boundary block commits");
    }
    for (int r = 0; r < 3; r++) {
        utxo_row_t u;
        CHECK(utxo_get(fx.w, nul[r], &u) == 0 && u.found,
              "release UTXO present at its hand-derived nullifier");
        CHECK(memcmp(u.owner, g_fp[r_del[r]], 128) == 0,
              "owner = the DELEGATOR's fingerprint (hex)");
        CHECK(u.amount == r_amt[r], "amount = the delegation amount");
        CHECK(u.unlock_block == E + CD_DELEG,
              "unlock = H_grad + 12E — the delegator lock, not 84E");
        CHECK(u.block_height == E && u.created_at == 0 &&
              u.domain_id == (int64_t)DNA_DOMAIN_CORE,
              "block_height E, created_at 0, CORE");
        CHECK(u.output_index == (int64_t)(0x40000000u + (uint32_t)r),
              "output_index = the band base + the boundary-wide rank");
        CHECK(u.txh_len == 64 && memcmp(u.tx_hash, txh, 64) == 0,
              "tx_hash = the settlement tx_hash of H_grad");
    }
    OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 1,
          "the graduates' three delegation rows are deleted, key 9 → "
          "key 0 survives"); OK();
    {
        dnac_validator_record_t v;
        for (int k = 3; k <= 6; k += 3) {
            CHECK(val_get(&fx, k, &v) == 0 &&
                  v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
                  v.self_stake == 0 && v.total_delegated == 0 &&
                  v.external_delegated == 0,
                  "graduate UNSTAKED with bond and delegated totals 0");
        }
        CHECK(val_get(&fx, 0, &v) == 0 && v.total_delegated == MIN &&
              v.external_delegated == MIN,
              "a non-graduate's delegation totals are untouched");
        uint8_t gid6[64], gnul6[64];
        utxo_row_t u;
        CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[6], gid6)
                  == 0 &&
              nodus_witness_v2_epoch_grad_nullifier(gid6, gnul6) == 0 &&
              utxo_get(fx.w, gnul6, &u) == 0 && u.found &&
              u.amount == BOND_BIG && u.unlock_block == E + CD,
              "the graduate's own bond still releases at H + 84E (P3-3)");
    }
    OK();
    {
        uint8_t f3[64], f6[64];
        CHECK(qgp_sha3_512(g_pk[3], DNAC_PUBKEY_SIZE, f3) == 0 &&
              qgp_sha3_512(g_pk[6], DNAC_PUBKEY_SIZE, f6) == 0, "fps");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT COUNT(*) FROM v2_balance_copy WHERE epoch_start "
                  "= ?1 AND (validator_fp = ?2 OR validator_fp = ?3)",
                  -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)E);
        sqlite3_bind_blob(st, 2, f3, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, f6, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int64(st, 0) == 0,
              "copy(E) holds no row of either graduate — the release ran "
              "BEFORE the balance copy");
        sqlite3_finalize(st);
    }
    CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                   "key='active_count'") == 5,
          "active_count drops once, for the RETIRING graduate only");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "the supply equation closes — delegated bucket moved to utxo");
    OK();
    printf("  ok: 3 delegations released (ranks 0..2, kind 0x23, unlock "
           "E + 12E), rows gone, totals 0, F60 atomic\n");
    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §6  MULTIPLE GRADUATES + insertion-order independence
 * ════════════════════════════════════════════════════════════════════ */

/* Build a chain with TWO RETIRING rows, seeding the validators in the
 * caller's order, and drive it exactly to the first boundary.
 *
 * round 5 (R5-3) note: keys 5 and 6 are now RETIRING in a LOCAL, mutable
 * copy of the caller's spec array BEFORE `fx_genesis`'s own
 * `nodus_witness_vset_commit_genesis` call — the SAME
 * `test_rule_n_retiring_excluded` / `test_boundary_chain` pattern, for
 * the SAME reason: `nodus_validator_top_n` never selects a RETIRING row,
 * so both are absent from snapshot(0)/snapshot(E) the moment they are
 * built, and R5-3's deferral (which only holds back a candidate still an
 * entry of the snapshot taking effect this boundary) does not apply —
 * both still graduate exactly at E, which is this test's actual subject.
 * Before round 5 both were seeded ACTIVE and flipped by direct SQL
 * AFTER the freeze, which put both INSIDE the frozen snapshot(E) and is
 * now deferred by R5-3. active_count's baseline is UNCHANGED by this
 * reordering (still `(int)n`): RETIRING does not decrement active_count
 * at UNSTAKE-request time regardless of when the status was set
 * (rt_native.c:3381) — only AUTO_RETIRED does, and neither row is ever
 * AUTO_RETIRED here. */
static int multi_build(fixture_t *fx, const char *tag,
                       const vspec_t *specs, size_t n) {
    if (n > 7) return -1;
    vspec_t local[7];
    memcpy(local, specs, n * sizeof(vspec_t));
    for (size_t i = 0; i < n; i++) {
        if (local[i].key == 5 || local[i].key == 6)
            local[i].status = (uint8_t)DNAC_VALIDATOR_RETIRING;
    }
    if (fx_genesis(fx, tag, local, n, (int)n) != 0) return -1;
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
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(c.w, d0) == 0, "digest");
        nodus_v2_block_t b;
        mk_block(&b, E);
        int rc = v2x_cmt_apply(c.w, &b);
        CHECK(rc == NODUS_V2_INTERNAL_FAULT &&
              v2x_reason_is(&b, V2X_FAULT, "phase 6e") == 0,
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

    /* round 5 (R5-3) note: keys 5 and 6 must be RETIRING BEFORE
     * `fx_genesis`'s own snapshot freeze — the `multi_build` /
     * `test_boundary_chain` pattern, same reason: a candidate still an
     * entry of the snapshot taking effect this boundary is now DEFERRED
     * (not evaluated at all — the per-candidate loop `continue`s before
     * ever reaching `v2ep_release_utxo` or a fault point), which would
     * leave F40-F42 with no candidate to inject against. A local mutable
     * copy of `specs` carries the pre-freeze status; `nodus_validator_
     * top_n` then never selects either row into snapshot(0)/snapshot(E). */
    vspec_t local_specs[7];
    memcpy(local_specs, specs, sizeof(specs));
    for (size_t i = 0; i < 7; i++) {
        if (local_specs[i].key == 5 || local_specs[i].key == 6)
            local_specs[i].status = (uint8_t)DNAC_VALIDATOR_RETIRING;
    }

    fixture_t f, t;
    CHECK(fx_genesis(&f, "fault", local_specs, 7, 7) == 0, "genesis F");
    CHECK(fx_genesis(&t, "twin", local_specs, 7, 7) == 0, "genesis T");
    for (int pass = 0; pass < 2; pass++) {
        fixture_t *x = pass ? &t : &f;
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

    /* (The committee seed's lookback record at E-1 is the host's
     * block-store row v2x_cmt_apply wrote when block E-1 committed —
     * already in both fixtures; the injected block's own record is
     * written inside the host transaction and rolled back with it.) */
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
    /* round 5 (R5-3) note: key 6 is RETIRING in a LOCAL copy of
     * `g_plain7` (the shared array itself is `const` and used by other
     * tests) BEFORE `fx_genesis`'s own snapshot freeze — the
     * `multi_build` / `test_boundary_chain` pattern, same reason: a
     * candidate still an entry of the effective snapshot is now DEFERRED
     * before `v2ep_graduate` ever calls `nodus_validator_get` /
     * `nodus_witness_v2_epoch_val_rec_ok` on it, which would make this
     * case's actual subject — activation obligation 1, the
     * legacy-malformed-row refusal — unreachable. */
    vspec_t local7[7];
    memcpy(local7, g_plain7, sizeof(g_plain7));
    for (size_t i = 0; i < 7; i++) {
        if (local7[i].key == 6)
            local7[i].status = (uint8_t)DNAC_VALIDATOR_RETIRING;
    }
    CHECK(fx_genesis(&fx, "malf", local7, 7, 7) == 0, "genesis");

    /* the malformed fingerprint is NOT planted mid-chain: `validators`
     * feeds the SYSTEM root, so a post-genesis write would be caught by
     * the untouched-domain guard on the very next block and this test
     * would pass for the WRONG reason — a generic out-of-band-write
     * reject instead of the graduation's writable-shape refusal. Seeding
     * it pre-genesis is also the honest model of the case: a legacy
     * chain carrying a malformed row from before the V2 lane existed. */
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
    /* not a real genesis: a legacy-malformed row IS this case's subject,
     * and derive_v3 refuses to commit one (L2-F4) */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_MALFORMED);
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* The malformed row is committed state and every ordinary block
     * rides straight past it — only the GRADUATION reads that column. */
    CHECK(fx_drive_to(&fx, E - 1) == 0,
          "a malformed row does not disturb ordinary blocks");

    uint8_t d0[64], d1[64];
    CHECK(db_state_digest(fx.w, d0) == 0, "digest");
    nodus_v2_block_t b;
    mk_block(&b, E);
    int rc = v2x_cmt_apply(fx.w, &b);
    CHECK(rc == NODUS_V2_INTERNAL_FAULT &&
          v2x_reason_is(&b, V2X_FAULT, "phase 6e") == 0,
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

/* ════════════════════════════════════════════════════════════════════
 * §10  RULE N — tokenomics-v3 P1 (D-3): the liveness/AUTO_RETIRE matrix
 *
 * Real signature attendance ONLY — no field is hand-written into
 * `v2_attendance` or `validators.consecutive_missed_epochs`; every
 * credit comes from a real decided_last_commit vote (`rn_block` below,
 * mirroring test_v2_econ.c's fx_block_by/fx_drive), exactly as
 * nodus_cmt_app_finalize_block populates blk->cmt from a real ABCI
 * request.
 * ════════════════════════════════════════════════════════════════════ */

/* Apply the next block, crediting a COMMIT vote for every key in
 * `attend[]` (n_attend entries, 0 legal). `h == 1` never carries votes
 * (execution.go's own precondition: no previous commit to report). */
static int rn_block(fixture_t *fx, const int *attend, size_t n_attend,
                    int *rc_out) {
    uint64_t h = fx->height + 1;
    if (n_attend > 8) return -1;
    nodus_v2_block_t b;
    mk_block(&b, h);
    uint8_t addrs[8][32];
    int32_t flags[8];
    if (h > 1 && n_attend > 0) {
        for (size_t i = 0; i < n_attend; i++) {
            uint8_t digest[64];
            if (qgp_sha3_512(g_pk[attend[i]], DNAC_PUBKEY_SIZE, digest) != 0)
                return -1;
            memcpy(addrs[i], digest, 32);
            flags[i] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
        }
        b.cmt.votes_address = (const uint8_t (*)[32])addrs;
        b.cmt.votes_block_id_flag = flags;
        b.cmt.votes_len = n_attend;
    }
    int rc = v2x_cmt_apply(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc == 0) fx->height = h;
    if (rc != 0)
        fprintf(stderr, "rn_block: height %llu failed (rc=%d): %s\n",
                (unsigned long long)h, rc, b.out_reason);
    return rc == 0 ? 0 : -1;
}

/* Drive to `target`; every block in [from, to] credits `attend[]`. */
static int rn_drive(fixture_t *fx, uint64_t target, const int *attend,
                    size_t n_attend, uint64_t from, uint64_t to) {
    while (fx->height < target) {
        uint64_t h = fx->height + 1;
        int rc = 0;
        int in_range = (h >= from && h <= to);
        if (rn_block(fx, in_range ? attend : NULL, in_range ? n_attend : 0,
                    &rc) != 0)
            return -1;
    }
    return 0;
}

static int test_rule_n_liveness(void) {
    printf("\n\xc2\xa7" "10 Rule N liveness matrix (tokenomics-v3 P1, D-3)\n");

    /* round 5 (R5-2) note, re-derived for round 6's WEIGHT floor: TWO
     * extra always-passing members (3, 4) were added — with only 3
     * members, retiring validator 1 would leave 2 equal seatable members
     * for the next epoch, and the floor refuses that: power P = 2p,
     * max = p, (P - max) = p is NOT > P*2/3 = floor(4p/3), so this
     * case's whole epoch-2 section would assert something false. With 5
     * equal members (all genesis-seeded, active_since_block 1, so all
     * tenured), retiring the ONE (validator 1) leaves 4 equal seatable
     * members: P = 4p, (P - max) = 3p > floor(8p/3) — allowed, the
     * smallest equal set the weight floor lets through, so the ordinary
     * AUTO_RETIRE path this case actually tests still runs
     * (p = BOND_BASE / DNAC_DECIMAL_UNIT = 10^7). Keys 3 and 4 attend the IDENTICAL
     * blocks validator 0 already does in both epochs (added to the
     * `only0`/`both`/`who0`/`both02` attend arrays below), so they never
     * miss and never affect the counts this case asserts. */
    static const vspec_t specs[5] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "rulen", specs, 5, 5) == 0, "genesis");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* `required` is the EXACT P1 threshold: the smallest signed_count for
     * which signed_count*10000 >= E*DNAC_LIVENESS_THRESHOLD_BPS holds
     * (round 3: 5000, not the retired 8000). `required` itself must
     * PASS and `required - 1` must FAIL — both proven as a fixture guard
     * before anything is asserted about the engine. */
    const uint64_t required =
        (E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS + 10000ULL - 1) /
        10000ULL;
    CHECK(required > 1 && required < E,
          "FIXTURE GUARD: required must be reachable inside one epoch");
    CHECK(required * 10000ULL >= E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS,
          "FIXTURE GUARD: required clears the bar");
    CHECK((required - 1) * 10000ULL <
          E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS,
          "FIXTURE GUARD: required-1 does NOT clear the bar — the exact "
          "boundary");

    /* Epoch 1 (heights 1..E): validator 0 attends the last `required`
     * blocks (P1 exact pass, P2 trivially satisfied — its last vote is
     * in the LAST block of the epoch); validator 1 attends the last
     * `required-1` blocks (P1 exact MISS, one short); validator 2 never
     * attends (misses both predicates). Both 0 and 1 share their last
     * `required-1` blocks so P2 cannot be what distinguishes them — ONLY
     * P1 differs. */
    {
        int both[4]  = { 0, 1, 3, 4 };
        int only0[3] = { 0, 3, 4 };
        CHECK(rn_drive(&fx, E - required, NULL, 0, 0, 0) == 0,
              "quiet run-up to E-required");
        CHECK(rn_drive(&fx, E - required + 1, only0, 3,
                       E - required + 1, E - required + 1) == 0,
              "validators 0, 3, 4's extra block");
        CHECK(rn_drive(&fx, E, both, 4, E - required + 2, E) == 0,
              "validators 0, 1, 3, 4 share the remaining required-1 "
              "blocks");
        CHECK(fx.height == E, "drove exactly to the first boundary");
    }

    {
        dnac_validator_record_t v0, v1, v2;
        CHECK(val_get(&fx, 0, &v0) == 0 && val_get(&fx, 1, &v1) == 0 &&
              val_get(&fx, 2, &v2) == 0, "get all three at E");
        CHECK(v0.consecutive_missed_epochs == 0,
              "P1 exact pass (required) + P2 pass -> no miss");
        CHECK(v1.consecutive_missed_epochs == 1,
              "P1 exact miss (required-1) -> miss, despite P2 passing");
        CHECK(v2.consecutive_missed_epochs == 1,
              "never attended -> miss (both predicates fail)");
        CHECK(v0.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v1.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v2.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "one miss is not enough to AUTO_RETIRE");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 5,
              "active_count untouched by a single miss");
    }
    OK();
    printf("  ok: epoch 1 — P1 exact boundary, miss vs pass\n");

    /* Epoch 2 (heights E+1..2E): validator 0 (+3, +4) attend fully again
     * (stay at 0 misses); validator 1 attends NOTHING this time (second
     * consecutive miss -> AUTO_RETIRED, active_count -1, exactly once);
     * validator 2 attends FULLY this time (a pass resets its counter to
     * 0, proving the reset is not itself a decrement toward AUTO_RETIRE). */
    {
        int who0[3] = { 0, 3, 4 };
        int both02[4] = { 0, 2, 3, 4 };
        CHECK(rn_drive(&fx, 2 * E - required, who0, 3, E + 1,
                       2 * E - required) == 0,
              "validators 0, 3, 4's run-up in epoch 2");
        CHECK(rn_drive(&fx, 2 * E, both02, 4, 2 * E - required + 1, 2 * E)
                  == 0,
              "validators 0, 2, 3, 4 share the last `required` blocks");
        CHECK(fx.height == 2 * E, "drove exactly to the second boundary");
    }

    {
        dnac_validator_record_t v0, v1, v2, v3, v4;
        CHECK(val_get(&fx, 0, &v0) == 0 && val_get(&fx, 1, &v1) == 0 &&
              val_get(&fx, 2, &v2) == 0 && val_get(&fx, 3, &v3) == 0 &&
              val_get(&fx, 4, &v4) == 0, "get all five at 2E");
        CHECK(v0.consecutive_missed_epochs == 0,
              "validator 0: second consecutive pass, still 0");
        CHECK(v1.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED,
              "validator 1: TWO consecutive misses -> AUTO_RETIRED "
              "(DNAC_AUTO_RETIRE_EPOCHS == 2); the next set is 4 equal "
              "members, (P - max) = 3p > P*2/3, so the round-6 weight "
              "floor does not block this retirement");
        CHECK(v2.consecutive_missed_epochs == 0 &&
              v2.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "validator 2: a PASS resets the counter to 0, not merely "
              "decrements it");
        CHECK(v3.consecutive_missed_epochs == 0 &&
              v3.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v4.consecutive_missed_epochs == 0 &&
              v4.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "FIXTURE GUARD: validators 3 and 4 never missed either "
              "epoch");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 4,
              "active_count dropped by EXACTLY one for the ONE "
              "AUTO_RETIRE, not per-miss and not twice");
    }
    OK();
    printf("  ok: epoch 2 — two consecutive misses AUTO_RETIREs, a pass "
           "resets to 0, active_count drops exactly once, the weight "
           "floor does not block a retirement that leaves 4 equal "
           "members\n");

    fx_close(&fx);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * round 2 — Rule N edge cases owed from round 1's own "NOT DONE" list:
 * the P2 window's exact edges, RETIRING exclusion, twin determinism
 * across a real attendance-bearing boundary, and fault injection at the
 * two NEW attendance stages.
 * ════════════════════════════════════════════════════════════════════ */

static int test_rule_n_p2_window(void) {
    printf("\n\xc2\xa7" "11a Rule N P2 window — exact edges (H-W passes, "
           "H-W-1 fails, 0 fails)\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "p2win", specs, 3, 3) == 0, "genesis");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    const uint64_t W = (uint64_t)DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS;
    const uint64_t required =
        (E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS + 10000ULL - 1) /
        10000ULL;
    CHECK(required > 0 && required <= E - W,
          "FIXTURE GUARD: `required` consecutive-enough blocks fit "
          "before the window edge, with room for a quiet run-up");

    /* A vote FED at block h credits `last_signed_height = h-1` (D-2: the
     * commit a block carries is FOR the previous height — `rn_block`'s
     * own comment above states the same rule). So to make a validator's
     * STORED last_signed_height land exactly on H-W, its LAST FED block
     * must be H-W+1, not H-W (test_rule_n_liveness escapes this because
     * ITS last vote is fed at block E, storing E-1 >= H-W trivially).
     *
     * validator 0 (key 0): LAST FED block H-W+1 -> stored last_signed_
     * height == H-W — P1 passes at the exact bar (the same `required`
     * test_rule_n_liveness already proves is exact); P2 passes at the
     * exact window edge (>=). validator 1 (key 1): the SAME `required`
     * count, but its LAST FED block is H-W -> stored last_signed_height
     * == H-W-1, one short of the window — P1 still passes (same count),
     * P2 fails (< H-W). validator 2 (key 2): never attends at all —
     * last_signed_height stays 0, the OTHER named P2 failure ("0
     * fails"). The two windows OVERLAP everywhere except each one's own
     * unique edge block, so both are driven in THREE stages: validator
     * 1's unique first block, the shared overlap, then validator 0's
     * unique last block. */
    int v0[1] = { 0 };
    int v1[1] = { 1 };
    int both01[2] = { 0, 1 };

    CHECK(rn_drive(&fx, E - W - required, NULL, 0, 0, 0) == 0,
          "quiet run-up");
    CHECK(rn_drive(&fx, E - W - required + 1, v1, 1,
                   E - W - required + 1, E - W - required + 1) == 0,
          "validator 1's unique (first) attended block");
    CHECK(rn_drive(&fx, E - W, both01, 2,
                   E - W - required + 2, E - W) == 0,
          "validators 0 and 1 share the overlap");
    CHECK(rn_drive(&fx, E - W + 1, v0, 1, E - W + 1, E - W + 1) == 0,
          "validator 0's unique (last) attended block");
    CHECK(rn_drive(&fx, E, NULL, 0, 0, 0) == 0, "quiet run to the boundary");
    CHECK(fx.height == E, "drove exactly to the boundary");

    {
        dnac_validator_record_t r0, r1, r2;
        CHECK(val_get(&fx, 0, &r0) == 0 && val_get(&fx, 1, &r1) == 0 &&
              val_get(&fx, 2, &r2) == 0, "get all three");
        CHECK(r0.consecutive_missed_epochs == 0,
              "P2 EXACT PASS: last_signed_height == H-W");
        CHECK(r1.consecutive_missed_epochs == 1,
              "P2 EXACT FAIL: last_signed_height == H-W-1, one short");
        CHECK(r2.consecutive_missed_epochs == 1,
              "P2 FAIL: never signed, last_signed_height == 0");
    }
    OK();
    printf("  ok: P2 window — H-W passes, H-W-1 fails, 0 fails\n");
    fx_close(&fx);
    return 0;
}

static int test_rule_n_retiring_excluded(void) {
    printf("\n\xc2\xa7" "11b Rule N — RETIRING rows are not evaluated\n");

    static const vspec_t specs[2] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE,   100, 0, 0 },
        { 1, BOND_BIG,  DNAC_VALIDATOR_RETIRING, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "retexcl", specs, 2, 2) == 0, "genesis");

    /* round 5 (R5-3) note: validator 1 is seeded RETIRING BEFORE
     * `fx_genesis`'s own `nodus_witness_vset_commit_genesis` call runs,
     * so `nodus_validator_top_n` (status IN (ACTIVE, ELIGIBLE) only)
     * never selects it into snapshot(0) or snapshot(E) — it graduates
     * normally at E, R5-3's deferral (which only holds back a candidate
     * still an entry of the EFFECTIVE snapshot) does not apply. This
     * test's outcome is therefore unchanged by round 5.
     *
     * validator 1 already carries ONE Rule N miss from a PRIOR epoch —
     * seeded directly, BETWEEN the two genesis stages, the SAME
     * placement test_faults() uses for its own hand-set RETIRING rows
     * (its own comment: mutating validators state AFTER fx_v2_genesis
     * would drift against what that stage already committed). If Rule N
     * evaluated this RETIRING row, a second miss here would push it to
     * 2 (AUTO_RETIRE); proving it stays at 1 is proof Rule N's own
     * UPDATE never touched this row — only graduation's did. */
    {
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(fx.w, g_pk[1], &v) == 0, "get key 1");
        v.consecutive_missed_epochs = 1;
        CHECK(nodus_validator_update(fx.w, &v) == 0,
              "seed one prior miss");
    }
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    int v0[1] = { 0 };
    CHECK(rn_drive(&fx, E, v0, 1, 2, E) == 0,
          "validator 0 fully attended; validator 1 (RETIRING) gets none");
    CHECK(fx.height == E, "drove exactly to the boundary");

    {
        dnac_validator_record_t r0, r1;
        CHECK(val_get(&fx, 0, &r0) == 0 && val_get(&fx, 1, &r1) == 0,
              "get both");
        CHECK(r0.consecutive_missed_epochs == 0,
              "validator 0: fully attended, no miss");
        CHECK(r1.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED,
              "validator 1: graduated normally (the RETIRING path, not "
              "AUTO_RETIRE)");
        CHECK(r1.consecutive_missed_epochs == 1,
              "Rule N: RETIRING rows are not evaluated — the counter "
              "this validator carried BEFORE the boundary is UNCHANGED, "
              "even though it received ZERO attendance and graduated in "
              "the SAME block");
    }
    OK();
    printf("  ok: a RETIRING row's Rule N counter survives its own "
           "graduation untouched\n");
    fx_close(&fx);
    return 0;
}

static int test_rule_n_twin_determinism(void) {
    printf("\n\xc2\xa7" "11c Rule N — twin determinism across a real "
           "attendance-driven boundary\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t a, b;
    CHECK(fx_genesis(&a, "twindet_a", specs, 3, 3) == 0, "genesis a");
    CHECK(fx_genesis(&b, "twindet_b", specs, 3, 3) == 0, "genesis b");
    CHECK(fx_v2_genesis(&a) == 0, "v2 genesis a");
    CHECK(fx_v2_genesis(&b) == 0, "v2 genesis b");

    /* IDENTICAL attendance history on both: validators 0 and 2 attend
     * fully, validator 1 never does — a genuine miss-bearing boundary
     * (not a quiet one), so the digest comparison actually exercises the
     * attendance digest/reset legs, not just an empty pass-through. */
    int who02[2] = { 0, 2 };
    CHECK(rn_drive(&a, E, who02, 2, 2, E) == 0, "drive a");
    CHECK(rn_drive(&b, E, who02, 2, 2, E) == 0, "drive b");
    CHECK(a.height == E && b.height == E, "both at the boundary");

    uint8_t da[64], db[64];
    CHECK(db_state_digest(a.w, da) == 0, "digest a");
    CHECK(db_state_digest(b.w, db) == 0, "digest b");
    CHECK(memcmp(da, db, 64) == 0,
          "two independently-driven fixtures, IDENTICAL attendance "
          "history, produce a byte-identical whole-DB digest");

    {
        dnac_validator_record_t v1a, v1b;
        CHECK(val_get(&a, 1, &v1a) == 0 && val_get(&b, 1, &v1b) == 0,
              "get validator 1 on both");
        CHECK(v1a.consecutive_missed_epochs == 1 &&
              v1b.consecutive_missed_epochs == 1,
              "FIXTURE GUARD: the miss actually happened on both");
    }
    OK();
    printf("  ok: twin fixtures agree byte-for-byte through a real "
           "attendance-bearing boundary\n");
    fx_close(&a);
    fx_close(&b);
    return 0;
}

static int test_rule_n_attendance_fault_stages(void) {
    printf("\n\xc2\xa7" "11d Rule N fault points at the two NEW attendance "
           "stages\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    static const nodus_v2_apply_fail_t pts[2] = {
        V2AP_FAIL_AFTER_ATTENDANCE_DIGEST,
        V2AP_FAIL_AFTER_ATTENDANCE_RESET
    };
    static const char *names[2] = {
        "attendance digest written", "signed_count reset"
    };

    for (size_t i = 0; i < 2; i++) {
        fixture_t fx;
        char tag[32];

        snprintf(tag, sizeof(tag), "attfault%zu", i);
        CHECK(fx_genesis(&fx, tag, specs, 3, 3) == 0, "genesis");
        CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");
        /* `fx_drive_to`/`fx_block` (round 2, R2-2) feed a FULL-COMMITTEE
         * COMMIT vote per block, so by E-1 there is REAL, non-trivial
         * attendance behind the digest/reset stages this case injects
         * at. */
        CHECK(fx_drive_to(&fx, E - 1) == 0,
              "drive to E-1 with real attendance behind it");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_attendance WHERE "
                       "signed_count > 0") == 3,
              "FIXTURE GUARD: real attendance accumulated for all three");

        uint8_t entry[64];
        CHECK(db_state_digest(fx.w, entry) == 0, "entry digest");

        int rc = 0;
        CHECK(fx_block_inject(&fx, pts[i], &rc) == 0,
              "an injected fault AT this stage rolls back with a "
              "byte-identical whole-DB digest");
        CHECK(rc == -2, "boundary failure is a NODE FAULT, never a verdict");

        uint8_t now[64];
        CHECK(db_state_digest(fx.w, now) == 0, "digest");
        CHECK(memcmp(entry, now, 64) == 0,
              "the fixture is still at its pre-block state");
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_attendance_epoch WHERE "
                        "epoch_start = %llu", 0ULL) == 0,
              "no attendance digest row survived the rollback");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_attendance WHERE "
                       "signed_count = 0") == 0,
              "signed_count was NOT reset — the reset step never "
              "committed");

        /* clean retry: the SAME boundary, uninjected, lands both stages */
        CHECK(fx_block(&fx, NULL, &rc) == 0 && rc == 0,
              "the clean retry commits");
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_attendance_epoch WHERE "
                        "epoch_start = %llu", 0ULL) == 1,
              "the clean retry wrote exactly one digest row for epoch 0");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_attendance WHERE "
                       "signed_count > 0") == 0,
              "the clean retry reset every signed_count to 0");

        printf("  ok: %s fault point rolls back cleanly; the clean "
               "retry lands both stages\n", names[i]);
        fx_close(&fx);
    }
    OK();
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * round 3 (R3-1, operator 2026-09-23): the property the 50% bar BUYS —
 * a jittery-but-healthy cluster clears it where the retired 80% bar
 * could not have. All three members are genesis-seeded and therefore
 * entries of snapshot(0) — the round-5 (R5-1) duty check
 * (`nodus_witness_v2_epoch_authority_for_epoch(w, H-E)`) resolves to
 * that snapshot at this fixture's boundary (H=E, H-E=0,
 * `nodus_witness_vset_commit_genesis` seeds it — fx_genesis, above), and
 * all three are entries of it, so all three still have a duty here; this
 * test's outcome is unchanged by round 5.
 * ════════════════════════════════════════════════════════════════════ */

/* A block commits on MORE than two-thirds of the committee's signatures
 * (decision file §3's round-5 correction entry): with THREE members that
 * is exactly TWO per block, and this case rotates WHICH one is left out
 * round-robin (height h excludes member h % 3) — network jitter, not a
 * chronically slow node, since no member is EVER excluded twice in a
 * row. Every member therefore signs exactly 2 of every 3 blocks: ~66.7%
 * average attendance, comfortably ABOVE the 50% bar (5000 bps) and BELOW
 * the RETIRED 80% bar (8000 bps) — the exact arithmetic the operator's
 * decision cites, corrected round 5: this is the WORST-case floor a
 * healthy cluster sits at (q/n for n=3, q=2), not a ceiling nothing can
 * cross — a healthier cluster (no rotation, every member almost always
 * present) would clear well above two-thirds. Height 1 never carries a
 * vote regardless of which set is passed (rn_block's own h>1 gate), so
 * it does not disturb the rotation's shape. */
static int test_rule_n_jittery_cluster(void) {
    printf("\n\xc2\xa7" "11e Rule N — jittery-but-healthy cluster: "
           "quorum-only rotating attendance clears the 50%% bar for "
           "EVERY member (would have failed every member at the "
           "retired 80%% bar)\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "jitter", specs, 3, 3) == 0, "genesis");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* R4-1: the boundary block (step 6 of nodus_witness_v2_epoch_boundary_
     * apply, round 2's S-2 ordering) resets EVERY row's signed_count to 0
     * AFTER settlement (step 3) and Rule N (step 4) have already read it —
     * the engine is correct to do this (round 4 brief). Drive only to
     * E − 1 here, so the raw counters are still live, and read the
     * FIXTURE GUARDs at that height; the boundary block (E) is driven
     * separately below, and only the OUTCOME (consecutive_missed_epochs,
     * status) is asserted after it. */
    for (uint64_t h = fx.height + 1; h <= E - 1; h++) {
        int excluded = (int)(h % 3);
        int attend[2];
        size_t k = 0;
        for (int m = 0; m < 3; m++) {
            if (m != excluded) attend[k++] = m;
        }
        int rc = 0;
        CHECK(rn_block(&fx, attend, k, &rc) == 0 && rc == 0,
              "quorum-only rotating block");
    }
    CHECK(fx.height == E - 1, "drove to the block before the boundary");

    {
        /* FIXTURE GUARD: the rotation really did produce ~2/3 attendance
         * for everyone, not some other shape — 2/3 clears 5000 bps
         * (required today, E * 5000 / 10000) but would NOT have cleared
         * 8000 bps (E * 8000 / 10000) at the SAME count. This is the
         * exact arithmetic named in the constant's own comment
         * (dnac.h, DNAC_LIVENESS_THRESHOLD_BPS) and in the decision
         * file's §3 last entry — proven here, not merely asserted. Read
         * BEFORE the boundary block: the boundary's step 6 zeroes
         * signed_count for every row, so a read after it would see 0. */
        uint64_t sc0 = 0, sc1 = 0, sc2 = 0;
        CHECK(nodus_witness_v2_attendance_get(fx.w, g_pk[0], &sc0, NULL)
                  == 0, "sc0");
        CHECK(nodus_witness_v2_attendance_get(fx.w, g_pk[1], &sc1, NULL)
                  == 0, "sc1");
        CHECK(nodus_witness_v2_attendance_get(fx.w, g_pk[2], &sc2, NULL)
                  == 0, "sc2");
        CHECK(sc0 * 10000ULL >= E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS &&
              sc1 * 10000ULL >= E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS &&
              sc2 * 10000ULL >= E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS,
              "FIXTURE GUARD: every member's real count clears 5000 bps");
        CHECK(sc0 * 10000ULL < E * 8000ULL &&
              sc1 * 10000ULL < E * 8000ULL &&
              sc2 * 10000ULL < E * 8000ULL,
              "FIXTURE GUARD: the SAME count would have missed the "
              "RETIRED 8000 bps bar for every member — this is what "
              "changed, not the rotation");
    }

    {
        /* the boundary block itself (h == E); same round-robin exclusion
         * as the loop above. */
        int excluded = (int)(E % 3);
        int attend[2];
        size_t k = 0;
        for (int m = 0; m < 3; m++) {
            if (m != excluded) attend[k++] = m;
        }
        int rc = 0;
        CHECK(rn_block(&fx, attend, k, &rc) == 0 && rc == 0,
              "quorum-only rotating boundary block");
    }
    CHECK(fx.height == E, "drove exactly to the boundary");

    {
        dnac_validator_record_t v0, v1, v2;
        CHECK(val_get(&fx, 0, &v0) == 0 && val_get(&fx, 1, &v1) == 0 &&
              val_get(&fx, 2, &v2) == 0, "get all three at E");
        CHECK(v0.consecutive_missed_epochs == 0 &&
              v1.consecutive_missed_epochs == 0 &&
              v2.consecutive_missed_epochs == 0,
              "jittery-but-healthy rotation: NO member falls below the "
              "50% bar");
        CHECK(v0.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v1.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v2.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "the whole set stays ACTIVE — no collapse");
    }
    OK();
    printf("  ok: jittery cluster — quorum-only rotating attendance "
           "clears the 50%% bar for every member\n");
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * round 5 — R5-1 duty-set evaluation, R5-2 the floor (a head count in
 * round 5, voting power since round 6 — §12c re-derived, §12e-§12i
 * added below), R5-3 graduation deferral. Every round-5 case below is
 * RED on round <= 4's code and the reason is stated inline.
 * ════════════════════════════════════════════════════════════════════ */

/* R5-8(a) — verifier V-1: a validator STAKEd MID-EPOCH is not charged a
 * miss at the next boundary; its counter is 0. */
static int test_rule_n_midepoch_stake_no_miss(void) {
    printf("\n\xc2\xa7" "12a Rule N — a mid-epoch STAKE gets no miss "
           "(R5-1, verifier V-1)\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "midstake", specs, 3, 3) == 0, "genesis");

    /* R5-1: STAKE writes a NEW row with status = ACTIVE
     * (nodus_witness_rt_native.c:3108) while the duty snapshot is already
     * frozen. Modeled with the late-joiner pattern above (key 7): seeded
     * AFTER fx_genesis froze snapshot(0) and snapshot(E), BEFORE the V2
     * genesis. It cannot be seeded between blocks after the V2 genesis —
     * a direct SQL write there moves a committed root outside any block
     * and the block's untouched-domain guard (phase 8) rightly refuses it;
     * real STAKEs arrive inside a block, which these fixtures do not
     * drive. The property under test is unchanged: key 3 is ACTIVE and
     * is NOT an entry of snapshot(0), the duty snapshot for boundary E,
     * so it can never be a cometbft voter for epoch 1 and never attends.
     * Before round 5, `v2ep_rule_n` evaluated every ACTIVE row regardless
     * of duty and charged it a miss it had no chance to avoid — the exact
     * bug verifier V-1 found. */
    CHECK(seed_validator(&fx, 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE,
                         100, 0, 0) == 0, "STAKE after snapshot freeze (key 3)");
    /* A real STAKE funds the bond from its sibling SYSFUND leg and
     * bumps active_count by one (nodus_witness_rt_native.c:3083-3131);
     * this fixture has no UTXO large enough to debit, so the bond enters
     * the supply equation the way the late-joiner fixture does it
     * ("supply top-up") — otherwise the PRE-APPLY supply gate
     * (nodus_witness_v2_claims.c:1114-1160) correctly refuses a bond
     * that came from nowhere. */
    {
        char sql[192];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = current_supply "
                 "+ %llu WHERE id = 1",
                 (unsigned long long)BOND_BASE,
                 (unsigned long long)BOND_BASE);
        CHECK(run_sql(fx.w->db, sql) == 0, "supply top-up (key 3 bond)");
    }
    CHECK(run_sql(fx.w->db,
                  "UPDATE validator_stats SET value = 4 "
                  "WHERE key = 'active_count'") == 0,
          "active_count 4 (3 + key 3)");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* validators 0, 1, 2 (the ONLY entries of snapshot(0)) attend fully
     * for the whole epoch; key 3 never attends. */
    int all012[3] = { 0, 1, 2 };
    CHECK(rn_drive(&fx, E, all012, 3, 2, E) == 0,
          "epoch 1, validator 3 never attends");
    CHECK(fx.height == E, "drove exactly to the boundary");

    {
        dnac_validator_record_t v3;
        CHECK(val_get(&fx, 3, &v3) == 0, "get 3");
        CHECK(v3.consecutive_missed_epochs == 0,
              "R5-1: no duty this boundary (absent from snapshot(0)) -> "
              "reset to 0, never charged a miss — RED before round 5");
        /* Not ACTIVE after boundary E: the flips run after Rule N and
         * seat ONLY entries of snapshot(E) (nodus_witness_vset.c:562-625,
         * pass 1 every bonded row -> ELIGIBLE, pass 2 snapshot members
         * -> ACTIVE); snapshot(E) was frozen at genesis without key 3. */
        CHECK(v3.status == (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
              "ELIGIBLE (not in snapshot(E)), never AUTO_RETIRED");
        dnac_validator_record_t v0;
        CHECK(val_get(&fx, 0, &v0) == 0, "get 0");
        CHECK(v0.consecutive_missed_epochs == 0,
              "FIXTURE GUARD: the genesis members, who DID have a real "
              "duty and met it, are unaffected");
    }
    OK();
    printf("  ok: a mid-epoch STAKE gets no miss at the next boundary\n");
    fx_close(&fx);
    return 0;
}

/* Replace the stored snapshot(epoch_start) with the SAME snapshot minus
 * the entry for `pk` — entry order, stakes, ruleset and seed untouched,
 * so the result is what the source builder would have frozen had `pk`
 * not been selected. PRE-V2-GENESIS ONLY: the snapshot table feeds the
 * vset leg of system_state_root (fx_genesis' own note above), so a
 * rewrite after the V2 genesis would trip the untouched-domain guard.
 * vset_insert CONFLICTs on an existing row by design, hence the DELETE
 * first — test-only, the same move test_cmt_app.c's boundary-diff
 * fixture makes. */
static int snap_drop_member(fixture_t *fx, uint64_t epoch_start,
                            const uint8_t pk[DNAC_PUBKEY_SIZE]) {
    dna_vset_snapshot_t *cur = NULL;
    if (nodus_witness_vset_get(fx->w, epoch_start, &cur, NULL) != 0 || !cur)
        return -1;
    int ret = -1;
    dna_vset_snapshot_t *next = NULL;
    uint8_t *buf = NULL;
    uint16_t keep = 0;
    for (uint16_t i = 0; i < cur->active_count; i++)
        if (memcmp(cur->entries[i].pubkey, pk, DNAC_PUBKEY_SIZE) != 0) keep++;
    if (keep == cur->active_count || keep == 0) goto out;   /* absent/only */
    next = dna_vset_alloc(keep);
    if (!next) goto out;
    next->epoch = cur->epoch;
    next->selection_ruleset = cur->selection_ruleset;
    memcpy(next->sortition_seed, cur->sortition_seed,
           sizeof(next->sortition_seed));
    for (uint16_t i = 0, j = 0; i < cur->active_count; i++)
        if (memcmp(cur->entries[i].pubkey, pk, DNAC_PUBKEY_SIZE) != 0)
            next->entries[j++] = cur->entries[i];
    buf = malloc(DNA_VSET_MAX_ENC_LEN);
    if (!buf) goto out;
    size_t len = 0;
    uint8_t hash[64];
    if (dna_vset_encode(next, buf, DNA_VSET_MAX_ENC_LEN, &len) != 0 ||
        dna_vset_hash(next, hash) != 0)
        goto out;
    char sql[128];
    snprintf(sql, sizeof(sql),
             "DELETE FROM validator_set_snapshots WHERE epoch_start = %llu",
             (unsigned long long)epoch_start);
    if (run_sql(fx->w->db, sql) != 0) goto out;
    if (nodus_witness_vset_insert(fx->w, epoch_start, buf, len, hash, 0) != 0)
        goto out;
    ret = 0;
out:
    free(buf);
    dna_vset_free(&next);
    dna_vset_free(&cur);
    return ret;
}

/* R5-8(b) — verifier V-1's other half: a member that misses once, then
 * has no duty for a whole epoch, has its counter reset to 0 rather than
 * carrying the stale miss into a LATER, unrelated duty epoch. */
static int test_rule_n_no_duty_resets_counter(void) {
    printf("\n\xc2\xa7" "12b Rule N — a no-duty epoch resets the counter "
           "(R5-1, verifier V-1)\n");

    static const vspec_t specs[3] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "noduty", specs, 3, 3) == 0, "genesis");
    /* Validator 1 loses its seat at boundary E (an ordinary rotation):
     * snapshot(E) is frozen WITHOUT it while snapshot(0) keeps it. Done
     * before the V2 genesis — see snap_drop_member. Boundary E's own
     * flips then demote it to ELIGIBLE (nodus_witness_vset.c:562-625),
     * and commit_next(E) re-selects it for snapshot(2E) (top_n reads
     * ACTIVE + ELIGIBLE, nodus_witness_validator.c:303). */
    CHECK(snap_drop_member(&fx, E, g_pk[1]) == 0,
          "snapshot(E) frozen without validator 1");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    /* Epoch 1 (1..E): validators 0 and 2 attend fully; validator 1 never
     * attends — a GENUINE miss against a REAL duty (it is an entry of
     * snapshot(0)). */
    int both02[2] = { 0, 2 };
    CHECK(rn_drive(&fx, E, both02, 2, 2, E) == 0, "epoch 1 drive");
    CHECK(fx.height == E, "drove to E");

    {
        dnac_validator_record_t v1;
        CHECK(val_get(&fx, 1, &v1) == 0, "get 1 at E");
        CHECK(v1.consecutive_missed_epochs == 1,
              "FIXTURE GUARD: validator 1 genuinely missed epoch 1 (it "
              "had a real duty)");
        CHECK(v1.status == (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
              "FIXTURE GUARD: one miss does not retire it; boundary E's "
              "flips left it ELIGIBLE (not a snapshot(E) member) — it "
              "carries its ONE miss into a no-duty epoch");
    }

    /* Epoch 2 (E+1..2E): validators 0 and 2 attend fully; validator 1 is
     * ELIGIBLE throughout and absent from the duty snapshot(E) — it has
     * NO duty at boundary 2E. */
    CHECK(rn_drive(&fx, 2 * E, both02, 2, E + 1, 2 * E) == 0,
          "epoch 2 drive, validator 1 stays ELIGIBLE throughout");
    CHECK(fx.height == 2 * E, "drove to 2E");

    {
        dnac_validator_record_t v1;
        CHECK(val_get(&fx, 1, &v1) == 0, "get 1 at 2E");
        CHECK(v1.consecutive_missed_epochs == 0,
              "R5-1: an epoch without a duty (ELIGIBLE throughout, never "
              "evaluated) RESETS the counter to 0 — RED before round 5 "
              "(the old ACTIVE-only scan never touched an ELIGIBLE row "
              "at all, so the stale miss from epoch 1 would have "
              "survived unreset)");
        /* boundary 2E's OWN flip step re-seats validator 1 to ACTIVE
         * (commit_next(E) put it back into snapshot(2E)) AFTER
         * Rule N already reset its counter — the same "rejoin" moment
         * verifier V-1 described: a member that lost its seat, sat out a
         * whole duty epoch, then regains its seat, must start its next
         * miss count from a clean 0, not from a carried-over 1. */
        CHECK(v1.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "validator 1 rejoins ACTIVE at this same boundary (a "
              "snapshot(2E) member) — Rule N's reset already committed "
              "before this flip runs");
    }
    OK();
    printf("  ok: a no-duty epoch resets the counter, breaking the "
           "non-consecutive-miss chain\n");
    fx_close(&fx);
    return 0;
}

/* R5-8(c) — THE FLOOR, re-derived in round 6 for the WEIGHT rule
 * (decision file §3 2026-09-23 "Rule N TABANI WEIGHT ÜZERİNDEN", which
 * replaced "Rule N TABANI = 4"; red-team L3-2's worked example,
 * orchestration.md FLEET TV3-P1 O6 red-team L3): a 7-member committee
 * where the liveness bar and the 120-block recency window fail
 * DIFFERENT members in the SAME boundary, so 5 of 7 reach
 * AUTO_RETIRE_EPOCHS at the SAME boundary. Retiring all 5 would seat 2
 * equal members next epoch: power P = 2p, max = p (p = BOND_BASE /
 * DNAC_DECIMAL_UNIT = 10^7), and (P - max) = p is NOT > P*2/3 =
 * floor(4p/3) — so the floor must retire NOBODY, keep every incremented
 * counter, and log a WARN. The control epoch then retires 2 of 7,
 * leaving 5 equal: (P - max) = 4p > floor(10p/3) — allowed.
 *
 * HONEST LABEL: every member here is genesis-seeded and equal-staked, so
 * this case gives the SAME outcome under the retired count floor
 * (bonded_after 2 < 4 refused; 5 >= 4 allowed) — it pins that the weight
 * rule still covers red-team L3-2, it does NOT discriminate weight from
 * count. §12e (stake concentration) and §12h (untenured staker) do.
 *
 * Numbers re-derived for THIS fixture's compiled constants — E = 720
 * (DNAC_EPOCH_LENGTH), W = 120 (DNAC_SETTLEMENT_ATTENDANCE_WINDOW_
 * BLOCKS), required = ceil(E * 5000 / 10000) = 360, quorum(7) =
 * floor(2*7/3) + 1 = 5 (dna_bft_quorum, ledger_ids.h:140-142):
 *   F, G (keys 5, 6):    sign EVERY block (720) -> P1 pass, P2 pass.
 *   D, E' (keys 3, 4):   sign ONLY the first E-W = 600 blocks -> P1
 *                        pass (600 >= 360) but last_signed_height caps
 *                        at 599 < E-W = 600 -> P2 FAIL.
 *   A, B, C (keys 0-2):  sign the LAST W = 120 blocks (clears P2) PLUS
 *                        200 EARLY blocks each (a fixed literal, NOT
 *                        derived from `required` — the red-team's own
 *                        number), rotating one at a time across the
 *                        first E-W = 600 blocks (3 * 200 = 600, exact
 *                        tiling, one signer per early block) -> total
 *                        120 + 200 = 320 < 360 -> P1 FAIL. (Epoch 1
 *                        only: block 1 carries no commit, so A gets
 *                        199 early credits there, 319 total — same
 *                        outcome.)
 * Every block from h=2 on carries exactly quorum(7) = 5 signers: [1, E-W] = F,G (2
 * fixed) + D,E' (2 fixed) + ONE of {A,B,C} (rotating) = 5; [E-W+1, E] =
 * F,G (2) + A,B,C (3) = 5. Miss set this epoch: {D, E', A, B, C} = 5 of
 * 7; F, G pass. */
static int test_rule_n_floor(void) {
    printf("\n\xc2\xa7" "12c Rule N — THE FLOOR: nobody is retired when "
           "the next set (2 equal members) could not commit without its "
           "largest member (round 6 weight rule, red-team L3-2)\n");

    static const vspec_t specs[7] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* A */
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* B */
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* C */
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* D */
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* E' */
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* F */
        { 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* G */
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "floor", specs, 7, 7) == 0, "genesis");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    const uint64_t W = (uint64_t)DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS;
    const uint64_t required =
        (E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS + 10000ULL - 1) /
        10000ULL;
    CHECK(W == 120, "FIXTURE GUARD: this fixture's numbers assume "
                    "W = 120 exactly");
    CHECK(required == 360, "FIXTURE GUARD: this fixture's numbers "
                           "assume required = 360 exactly (E = 720)");
    const uint64_t early_each = 200;                    /* literal, L3-2 */
    CHECK(early_each * 3 == E - W,
          "FIXTURE GUARD: three members' early rotation exactly tiles "
          "the first E-W blocks, one signer per block, zero overlap");
    CHECK(W + early_each < required,
          "FIXTURE GUARD: A/B/C's total (window + early) misses the "
          "bar");

    /* Epochs 1 and 2 (heights 1..2E): the SAME miss pattern both times,
     * so D, E', A, B, C each accumulate TWO consecutive misses. */
    for (int epoch = 0; epoch < 2; epoch++) {
        const uint64_t base = (uint64_t)epoch * E;
        for (uint64_t h = fx.height + 1; h <= base + E; h++) {
            uint64_t rel = h - base;                    /* 1..E in-epoch */
            int attend[5];
            size_t k = 0;
            attend[k++] = 5;                             /* F: always    */
            attend[k++] = 6;                             /* G: always    */
            if (rel <= E - W) {
                attend[k++] = 3;                          /* D: first 600 */
                attend[k++] = 4;                          /* E': first600 */
                attend[k++] = (int)((rel - 1) % 3);       /* rotate A/B/C */
            } else {
                attend[k++] = 0;                          /* A: last W    */
                attend[k++] = 1;                          /* B: last W    */
                attend[k++] = 2;                          /* C: last W    */
            }
            CHECK(k == 5, "exactly quorum(7) = 5 signers this block");
            int rc = 0;
            CHECK(rn_block(&fx, attend, k, &rc) == 0 && rc == 0,
                  "the L3-2 pattern's block");
        }
    }
    CHECK(fx.height == 2 * E, "drove exactly to the second boundary");

    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 5, &v) == 0 && v.consecutive_missed_epochs == 0
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "F: 0");
        CHECK(val_get(&fx, 6, &v) == 0 && v.consecutive_missed_epochs == 0
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "G: 0");
        CHECK(val_get(&fx, 3, &v) == 0 && v.consecutive_missed_epochs == 2
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "D: TWO consecutive misses reached the threshold, but the "
              "floor left it ACTIVE — counters are 2, not AUTO_RETIRED");
        CHECK(val_get(&fx, 4, &v) == 0 && v.consecutive_missed_epochs == 2
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "E': 2");
        CHECK(val_get(&fx, 0, &v) == 0 && v.consecutive_missed_epochs == 2
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "A: 2");
        CHECK(val_get(&fx, 1, &v) == 0 && v.consecutive_missed_epochs == 2
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "B: 2");
        CHECK(val_get(&fx, 2, &v) == 0 && v.consecutive_missed_epochs == 2
                  && v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE, "C: 2");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 7,
              "the weight floor fired — retiring all 5 would seat 2 "
              "equal members, (P - max) = p is not > P*2/3, so NOBODY "
              "was retired and active_count did not move — RED before "
              "round 5 (no floor: all five AUTO_RETIRED, active_count "
              "7 -> 2); same outcome under round 5's count floor");
    }
    OK();
    printf("  ok: the floor blocks a 5-of-7 simultaneous retirement, "
           "counters stay at 2\n");

    /* ── CONTROL: a SMALLER retirement (5 equal members left) still fires
     * normally. Epoch 3: D, E', C fully recover (counters reset 2 -> 0);
     * A, B repeat the SAME failing pattern (counter 2 -> 3, still over
     * threshold); F, G continue perfect. Only A and B reach the
     * threshold this boundary. */
    {
        for (uint64_t h = fx.height + 1; h <= 3 * E; h++) {
            uint64_t rel = h - 2 * E;                   /* 1..E in-epoch */
            int attend[7];
            size_t k = 0;
            attend[k++] = 2;                             /* C: always    */
            attend[k++] = 3;                              /* D: always   */
            attend[k++] = 4;                              /* E': always  */
            attend[k++] = 5;                              /* F: always   */
            attend[k++] = 6;                              /* G: always   */
            /* A signs blocks [1,200] and the last W; B signs [201,400]
             * and the last W — 200 + 120 = 320 each, the SAME failing
             * total as before. Overlap with the 5 always-signers is
             * fine: this control does not need an exact quorum count,
             * only real progress and the SAME miss shape for A, B. */
            if (rel <= 200) attend[k++] = 0;
            if (rel > 200 && rel <= 400) attend[k++] = 1;
            if (rel > E - W) { attend[k++] = 0; attend[k++] = 1; }
            int rc = 0;
            CHECK(rn_block(&fx, attend, k, &rc) == 0 && rc == 0,
                  "the control epoch's block");
        }
    }
    CHECK(fx.height == 3 * E, "drove exactly to the third boundary");

    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 2, &v) == 0 && v.consecutive_missed_epochs == 0,
              "C recovered: full attendance resets its counter to 0");
        CHECK(val_get(&fx, 3, &v) == 0 && v.consecutive_missed_epochs == 0,
              "D recovered");
        CHECK(val_get(&fx, 4, &v) == 0 && v.consecutive_missed_epochs == 0,
              "E' recovered");
        CHECK(val_get(&fx, 0, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED,
              "A: THREE consecutive misses now (2 kept by the floor + "
              "this one) — the next set is 5 equal members, (P - max) "
              "= 4p > P*2/3, so the retirement proceeds normally this "
              "time");
        CHECK(val_get(&fx, 1, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED, "B: same");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 5,
              "active_count dropped by exactly two — the control "
              "retirement was NOT blocked");
    }
    OK();
    printf("  ok: control — a 2-of-7 retirement (5 equal members left, "
           "4p > 10p/3) proceeds normally\n");

    fx_close(&fx);
    return 0;
}

/* R5-8(d) — graduation deferral (decision file §3 2026-09-23, "ayrılan
 * validatorun MEZUNİYETİ … ertelenir"; O6 red-team L1-1): a validator
 * that UNSTAKEs while it is still a member of the snapshot TAKING EFFECT
 * at the next boundary is NOT graduated there — it stays RETIRING, its
 * bond stays locked, and it graduates only at the FOLLOWING boundary,
 * once it is genuinely absent from the effective snapshot. */
static int test_rule_n_graduation_deferral(void) {
    printf("\n\xc2\xa7" "12d Rule N — graduation deferral: a mid-epoch "
           "UNSTAKE stays seated one extra epoch (R5-3, red-team "
           "L1-1)\n");

    static const vspec_t specs[4] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BIG,  DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    fixture_t fx;
    CHECK(fx_genesis(&fx, "graddefer", specs, 4, 4) == 0, "genesis");

    /* UNSTAKE inside the epoch that just started (H-E, H) with H = E:
     * validator 1 is already ACTIVE in the genesis-frozen snapshot(0)
     * AND snapshot(E) (both built while it was still ACTIVE, above) —
     * modeled directly, as O11's UNSTAKE apply leaves it: RETIRING, bond
     * intact. Timed BETWEEN the fixture stages, same discipline as
     * `test_boundary_chain`'s key 6 / `test_rule_n_retiring_excluded`'s
     * key 1 — the ONE difference here is deliberate: this candidate MUST
     * still be a snapshot(E) member, so it is flipped AFTER the freeze,
     * not before. */
    {
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(fx.w, g_pk[1], &v) == 0, "get 1");
        v.status = (uint8_t)DNAC_VALIDATOR_RETIRING;
        v.unstake_commit_block = 3;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "RETIRING mid-epoch");
    }
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    uint8_t gid[64], nul[64];
    CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, E, g_pk[1], gid)
          == 0, "grad_id at E");
    CHECK(nodus_witness_v2_epoch_grad_nullifier(gid, nul) == 0, "nul at E");

    CHECK(fx_drive_to(&fx, E) == 0, "drive to the first boundary");
    CHECK(fx.height == E, "at E");

    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 1, &v) == 0, "get 1 at E");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_RETIRING,
              "R5-3: still RETIRING at E — still a member of the "
              "snapshot taking effect at E, so graduation is DEFERRED — "
              "RED before round 5 (the old code graduated it here "
              "unconditionally)");
        CHECK(v.self_stake == BOND_BIG,
              "the bond is still locked, not released");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul, &r) == 0, "utxo probe at E");
        CHECK(!r.found, "no release UTXO at E");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 4,
              "active_count untouched at E — no graduation happened");
    }
    OK();
    printf("  ok: still RETIRING at E, not released, still in "
           "snapshot(E)\n");

    /* commit_next(E) (run inside the E boundary above) builds snapshot
     * for epoch_start = 2E from the POST-flip, POST-graduation state —
     * validator 1 is RETIRING, `nodus_validator_top_n` never selects a
     * RETIRING row, so it is genuinely absent from snapshot(2E). At the
     * NEXT boundary (2E), graduation is no longer deferred. */
    uint8_t gid2[64], nul2[64];
    CHECK(nodus_witness_v2_epoch_grad_id(fx.chain_id, 2 * E, g_pk[1], gid2)
          == 0, "grad_id at 2E");
    CHECK(nodus_witness_v2_epoch_grad_nullifier(gid2, nul2) == 0,
          "nul at 2E");

    CHECK(fx_drive_to(&fx, 2 * E) == 0, "drive to the second boundary");
    CHECK(fx.height == 2 * E, "at 2E");

    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 1, &v) == 0, "get 1 at 2E");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED,
              "graduated at 2E — genuinely absent from the effective "
              "snapshot now");
        CHECK(v.self_stake == 0, "the bond moved into the release UTXO");
        utxo_row_t r;
        CHECK(utxo_get(fx.w, nul2, &r) == 0, "utxo probe at 2E");
        CHECK(r.found, "released at H+E, not at H");
        CHECK(r.amount == BOND_BIG, "pays the record's actual bond");
        CHECK(r.unlock_block == 2 * E + CD,
              "unlock = (H+E) + 84·E (P3-3) — H+E is "
              "the height it ACTUALLY graduates at, not the height "
              "UNSTAKE was requested");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 3,
              "active_count dropped by EXACTLY one, and only NOW — one "
              "single move across the whole two-boundary sequence");
        utxo_row_t r_early;
        CHECK(utxo_get(fx.w, nul, &r_early) == 0, "re-probe the E-keyed "
                                                   "grad_id");
        CHECK(!r_early.found,
              "the E-keyed grad_id (deferred, never used) still has no "
              "row — the deferred candidate did not silently graduate "
              "under the WRONG height either");
    }
    OK();
    printf("  ok: graduated at 2E, unlock = 2E + 84E, active_count "
           "moved exactly once\n");

    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * round 6 — THE WEIGHT FLOOR (decision file §3 2026-09-23, "Rule N
 * TABANI WEIGHT ÜZERİNDEN"). A boundary's retirement stands iff the
 * snapshot commit_next will store for H+E still commits with its single
 * largest member gone: power per entry = total_stake / DNAC_DECIMAL_UNIT
 * (the §A unit, nodus_witness_cmt_app.c:1569), P = sum, max = largest,
 * allowed iff P > 0 AND (P - max) > P * 2 / 3 (cometbft's integer form,
 * shared/dnac/cmt_validation.c:298). Empty next set -> never allowed.
 *
 * Every drive below is "survivors attend every block from height 2,
 * victims never attend": each victim has a real duty in snapshot(0) and
 * snapshot(E) (both frozen at genesis with every seeded member), misses
 * twice, and reaches DNAC_AUTO_RETIRE_EPOCHS at boundary 2E — the one
 * boundary every case below judges. Every validator is genesis-seeded
 * (active_since_block 1, always tenured) unless a case says otherwise.
 * ════════════════════════════════════════════════════════════════════ */

/* The rule, re-derived here INDEPENDENTLY of the engine's static
 * v2ep_rn_weight_verdict, so a fixture guard can state what the engine
 * must decide before the engine is asked. */
static int rn_weight_allows(const uint64_t *power, size_t n) {
    uint64_t P = 0, m = 0;
    for (size_t i = 0; i < n; i++) {
        P += power[i];
        if (power[i] > m) m = power[i];
    }
    return P > 0 && (P - m) > P * 2 / 3;
}

static int snap_has(const dna_vset_snapshot_t *s,
                    const uint8_t pk[DNAC_PUBKEY_SIZE]) {
    for (uint16_t i = 0; i < s->active_count; i++)
        if (memcmp(s->entries[i].pubkey, pk, DNAC_PUBKEY_SIZE) == 0)
            return 1;
    return 0;
}

/* Drive heights 1..2E with `surv` attending every block from 2 on. */
static int rn_two_epochs(fixture_t *fx, const int *surv, size_t n_surv) {
    if (rn_drive(fx, 2 * E, surv, n_surv, 2, 2 * E) != 0) return -1;
    return fx->height == 2 * E ? 0 : -1;
}

/* §12e — STAKE CONCENTRATION: 4 survivors, but one of them holds 40 % of
 * their power, so the next set cannot commit without it — nobody is
 * retired. RED on round 5's count floor: bonded_after = 7 - 3 = 4 was
 * NOT below 4, so the count floor retired all three. */
static int test_rule_n_weight_concentration(void) {
    printf("\n\xc2\xa7" "12e Rule N weight floor — 4 survivors, one holds "
           "40%% of their power: nobody retired (round 6)\n");

    static const vspec_t specs[7] = {
        { 0, 2 * BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* 40 */
        { 1, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* 20 */
        { 2, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* 20 */
        { 3, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* 20 */
        { 4, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* victim */
        { 5, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* victim */
        { 6, BOND_BASE,     DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },  /* victim */
    };
    {
        /* FIXTURE GUARD: powers are exact integers and the arithmetic is
         * what the case name claims, BEFORE the engine is consulted. */
        CHECK(BOND_BASE % DNAC_DECIMAL_UNIT == 0,
              "FIXTURE GUARD: BOND_BASE is a whole number of power units");
        const uint64_t p = BOND_BASE / DNAC_DECIMAL_UNIT;
        const uint64_t surv[4] = { 2 * p, p, p, p };
        CHECK(!rn_weight_allows(surv, 4),
              "FIXTURE GUARD: 40/20/20/20 -> (P - max) = 3p is NOT > "
              "floor(10p/3)");
        CHECK(2 * p * 3 >= 5 * p,
              "FIXTURE GUARD: the largest survivor holds >= 1/3 of the "
              "survivors' power");
        CHECK(7 - 3 >= 4,
              "FIXTURE GUARD: round 5's count floor (bonded_after >= 4) "
              "WOULD have allowed this retirement — the case is RED there");
    }
    fixture_t fx;
    CHECK(fx_genesis_full(&fx, "wconc", specs, 7, 7) == 0, "genesis");

    int surv[4] = { 0, 1, 2, 3 };
    CHECK(rn_two_epochs(&fx, surv, 4) == 0, "two epochs, 4-6 never sign");

    {
        dnac_validator_record_t v;
        for (int k = 4; k <= 6; k++) {
            CHECK(val_get(&fx, k, &v) == 0, "get victim");
            CHECK(v.consecutive_missed_epochs == 2,
                  "victim reached the threshold (counter kept at 2)");
            CHECK(v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
                  "victim NOT retired — the survivors' largest member "
                  "holds 40% of their power — RED on round 5's count "
                  "floor, which retired it");
        }
        for (int k = 0; k <= 3; k++) {
            CHECK(val_get(&fx, k, &v) == 0 &&
                  v.consecutive_missed_epochs == 0 &&
                  v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE,
                  "FIXTURE GUARD: survivors never missed");
        }
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 7,
              "active_count did not move");
    }
    {
        /* The ROLLBACK TO undid the provisional retirement BEFORE
         * commit_next ran: the stored next set still seats the victims. */
        dna_vset_snapshot_t *st = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 3 * E, &st, NULL) == 0 && st,
              "snapshot(3E) stored");
        int ok = st->active_count == 7 && snap_has(st, g_pk[4]) &&
                 snap_has(st, g_pk[5]) && snap_has(st, g_pk[6]);
        dna_vset_free(&st);
        CHECK(ok, "snapshot(3E) still seats all 7 — the refused "
                  "retirement left no trace in the next set");
    }
    OK();
    printf("  ok: 40/20/20/20 survivors — nobody retired, counters kept, "
           "next set unchanged\n");
    fx_close(&fx);
    return 0;
}

/* §12f — EQUAL SURVIVORS: 4 equal -> retired; 3 equal -> nobody retired.
 * §12g — in the allowed case, the snapshot commit_next STORED for H+E is
 * byte-for-byte what preview_next builds: same members, same order, same
 * hash. HONEST SCOPE (round-6 O6 verifier): the preview here runs AFTER
 * block 2E committed, i.e. over the same post-flip state commit_next
 * saw, so this proves "same builder, same state -> same snapshot". It
 * CANNOT catch a future step inserted between Rule N and commit_next
 * that writes a committee input; that half rests on the input-by-input
 * argument in the comment above v2ep_rule_n's floor block.
 * §12f is GREEN on round 5 too (6-2 = 4 >= 4 allowed; 5-2 = 3 < 4
 * refused) — it pins the weight rule's small-set edge, not the change.
 * §12g is RED on round 5 by construction: nodus_witness_vset_preview_next
 * does not exist there. */
static int test_rule_n_weight_equal_survivors(void) {
    printf("\n\xc2\xa7" "12f Rule N weight floor — 4 equal survivors "
           "retire, 3 equal survivors do not (round 6)\n");

    const uint64_t p = BOND_BASE / DNAC_DECIMAL_UNIT;
    {
        const uint64_t four[4] = { p, p, p, p };
        const uint64_t three[3] = { p, p, p };
        CHECK(rn_weight_allows(four, 4),
              "FIXTURE GUARD: 4 equal -> 3p > floor(8p/3)");
        CHECK(!rn_weight_allows(three, 3),
              "FIXTURE GUARD: 3 equal -> 2p is NOT > 2p");
    }

    /* (a) 6 equal, keys 4 and 5 fail -> 4 equal survivors -> retired. */
    {
        static const vspec_t specs[6] = {
            { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        };
        fixture_t fx;
        CHECK(fx_genesis_full(&fx, "weq4", specs, 6, 6) == 0, "genesis");
        int surv[4] = { 0, 1, 2, 3 };
        CHECK(rn_two_epochs(&fx, surv, 4) == 0, "two epochs, 4-5 silent");

        dnac_validator_record_t v;
        CHECK(val_get(&fx, 4, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED,
              "key 4 AUTO_RETIRED — 4 equal survivors carry it");
        CHECK(val_get(&fx, 5, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED,
              "key 5 AUTO_RETIRED");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 4,
              "active_count 6 -> 4, exactly once per retirement");
        OK();
        printf("  ok: 4 equal survivors — both victims retired\n");

        /* §12g — after block 2E committed, the only writes since Rule N
         * ran are the digest (v2_attendance_epoch), the reset
         * (v2_attendance.signed_count) and the flips (validators.status
         * among bonded rows) plus the block's own bookkeeping at height
         * 2E; none is an input of the preview (the argument above the
         * floor in v2ep_rule_n). So the preview taken NOW must equal the
         * one Rule N judged, and must equal what commit_next(2E) stored. */
        printf("\n\xc2\xa7" "12g the stored snapshot(H+E) IS the preview "
               "Rule N judged\n");
        dna_vset_snapshot_t *pv = NULL, *st = NULL;
        uint8_t st_hash[64], pv_hash[64];
        CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, &pv) == 0 && pv,
              "preview_next(2E) builds");
        CHECK(nodus_witness_vset_get(fx.w, 3 * E, &st, st_hash) == 0 && st,
              "snapshot(3E) stored by commit_next(2E)");
        int same = pv->active_count == 4 &&
                   pv->active_count == st->active_count &&
                   pv->epoch == st->epoch && pv->epoch == 3 * E;
        for (uint16_t i = 0; same && i < pv->active_count; i++) {
            const dna_vset_entry_t *a = &pv->entries[i];
            const dna_vset_entry_t *b = &st->entries[i];
            same = memcmp(a->pubkey, b->pubkey, DNA_VSET_PUBKEY_LEN) == 0 &&
                   memcmp(a->voter_id, b->voter_id,
                          sizeof(a->voter_id)) == 0 &&
                   a->total_stake == b->total_stake &&
                   a->self_bond == b->self_bond &&
                   a->commission_bps == b->commission_bps;
        }
        int hashed = dna_vset_hash(pv, pv_hash) == 0 &&
                     memcmp(pv_hash, st_hash, 64) == 0;
        int victims_out = !snap_has(pv, g_pk[4]) && !snap_has(pv, g_pk[5]);
        dna_vset_free(&pv);
        dna_vset_free(&st);
        CHECK(same, "preview and stored snapshot: same members, same "
                    "order, same stakes");
        CHECK(hashed, "preview hash == stored snapshot_hash");
        CHECK(victims_out, "neither retired member is in the next set");
        OK();
        printf("  ok: stored snapshot(3E) is the preview, member for "
               "member and byte for byte\n");
        fx_close(&fx);
    }

    /* (b) 5 equal, keys 3 and 4 fail -> 3 equal survivors -> nobody. */
    {
        static const vspec_t specs[5] = {
            { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
            { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        };
        fixture_t fx;
        CHECK(fx_genesis_full(&fx, "weq3", specs, 5, 5) == 0, "genesis");
        int surv[3] = { 0, 1, 2 };
        CHECK(rn_two_epochs(&fx, surv, 3) == 0, "two epochs, 3-4 silent");

        dnac_validator_record_t v;
        CHECK(val_get(&fx, 3, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v.consecutive_missed_epochs == 2,
              "key 3 NOT retired, counter kept at 2 — 3 equal survivors "
              "cannot commit without their largest member");
        CHECK(val_get(&fx, 4, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
              v.consecutive_missed_epochs == 2, "key 4 same");
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 5,
              "active_count did not move");
        OK();
        printf("  ok: 3 equal survivors — nobody retired\n");
        fx_close(&fx);
    }
    return 0;
}

/* §12h — the O6 verifier's scenario: an UNTENURED staker is not counted.
 * 6 genesis members + 1 staker whose bond is younger than
 * DNAC_MIN_TENURE_BLOCKS at the next epoch's start, so
 * nodus_validator_top_n (nodus_witness_validator.c:311) will not seat it
 * at 3E. Keys 3, 4, 5 fail twice. Survivors that can be SEATED: 0, 1, 2
 * (3 equal) -> refused. Had the staker been counted they would be 4
 * equal -> allowed. RED on round 5: its count floor saw bonded = 7
 * (6 ACTIVE + the ELIGIBLE staker), 7 - 3 = 4, and retired all three,
 * leaving a 3-seat next set. */
static int test_rule_n_weight_untenured_not_counted(void) {
    printf("\n\xc2\xa7" "12h Rule N weight floor — an untenured staker "
           "is not counted (O6 verifier, round 6)\n");

    static const vspec_t specs[6] = {
        { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 3, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 4, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
        { 5, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 100, 0, 0 },
    };
    /* The staker's bond is dated E + 1 — a STAKE landing in epoch 2.
     * Tenure (Rule R) needs active_since + DNAC_MIN_TENURE_BLOCKS <=
     * e_start: E+1 + 2E > 3E, so it is NOT seatable at 3E (nor at 2E). */
    const uint64_t staker_since = E + 1;
    {
        const uint64_t p = BOND_BASE / DNAC_DECIMAL_UNIT;
        const uint64_t three[3] = { p, p, p };
        const uint64_t four[4] = { p, p, p, p };
        CHECK(staker_since + (uint64_t)DNAC_MIN_TENURE_BLOCKS > 3 * E,
              "FIXTURE GUARD: the staker is untenured at e_start = 3E");
        CHECK(!rn_weight_allows(three, 3),
              "FIXTURE GUARD: the 3 seatable survivors fail the rule");
        CHECK(rn_weight_allows(four, 4),
              "FIXTURE GUARD: counting the staker would PASS — the case "
              "discriminates exactly the defect");
        CHECK(7 - 3 >= 4,
              "FIXTURE GUARD: round 5's count floor (bonded_after >= 4) "
              "would have allowed this retirement — RED there");
    }

    fixture_t fx;
    CHECK(fx_genesis(&fx, "wtenure", specs, 6, 6) == 0, "genesis");
    /* Shaped BETWEEN the fixture stages (fixture rule: no consensus-table
     * SQL after the V2 genesis) — the §12a pattern: a STAKE creates an
     * ACTIVE row (nodus_witness_rt_native.c:3108) with active_since = its
     * executing height; the row exists from genesis here only because the
     * fixture cannot write between blocks. It is absent from snapshot(0)
     * and snapshot(E) (both frozen above), so it never has a duty; the
     * boundary-E flips leave it ELIGIBLE and it stays bonded. */
    CHECK(seed_validator(&fx, 6, BOND_BASE, DNAC_VALIDATOR_ACTIVE,
                         100, 0, 0) == 0, "staker row (key 6)");
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0, "get staker");
        v.active_since_block = staker_since;
        CHECK(nodus_validator_update(fx.w, &v) == 0, "date the bond E+1");
        char sql[192];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = current_supply "
                 "+ %llu WHERE id = 1",
                 (unsigned long long)BOND_BASE,
                 (unsigned long long)BOND_BASE);
        CHECK(run_sql(fx.w->db, sql) == 0, "supply top-up (staker bond)");
    }
    CHECK(run_sql(fx.w->db,
                  "UPDATE validator_stats SET value = 7 "
                  "WHERE key = 'active_count'") == 0,
          "active_count 7 (6 + the staker)");
    CHECK(fx_v2_genesis(&fx) == 0, "v2 genesis");

    int surv[3] = { 0, 1, 2 };
    CHECK(rn_two_epochs(&fx, surv, 3) == 0, "two epochs, 3-5 silent");

    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 6, &v) == 0 &&
              v.status == (uint8_t)DNAC_VALIDATOR_ELIGIBLE &&
              v.consecutive_missed_epochs == 0,
              "FIXTURE GUARD: the staker is bonded (ELIGIBLE), never "
              "charged — it IS in round 5's bonded count");
        for (int k = 3; k <= 5; k++) {
            CHECK(val_get(&fx, k, &v) == 0 &&
                  v.status == (uint8_t)DNAC_VALIDATOR_ACTIVE &&
                  v.consecutive_missed_epochs == 2,
                  "victim NOT retired — only 3 equal members could be "
                  "seated at 3E — RED on round 5's count floor");
        }
        CHECK(q1(fx.w, "SELECT value FROM validator_stats WHERE "
                       "key='active_count'") == 7,
              "active_count did not move");
    }
    {
        dna_vset_snapshot_t *st = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 3 * E, &st, NULL) == 0 && st,
              "snapshot(3E) stored");
        int ok = !snap_has(st, g_pk[6]) && st->active_count == 6;
        dna_vset_free(&st);
        CHECK(ok, "the tenure gate kept the staker out of snapshot(3E) — "
                  "the set the floor judged never contained it");
    }
    OK();
    printf("  ok: an untenured staker does not prop up a retirement\n");
    fx_close(&fx);
    return 0;
}

/* §12i — nodus_witness_vset_preview_next tells a VERDICT from a FAULT
 * (brief step 2), and the public build_for_epoch keeps "empty = fault".
 * Bare fixture (no V2 genesis, no DomainHead to guard), legacy seed path
 * (w->v2_successor = 0): the lookback seed for e_start = 3E is the
 * legacy `blocks` row at 2E - 1 (nodus_witness_committee.c:258, :279).
 * RED on round 5: the function does not exist there. The in-boundary
 * fault path (Rule N returning -1 because the preview faulted) is NOT
 * isolated here: with the hooks this file has, a missing seed row also
 * fails commit_next later in the same boundary, so a failed block cannot
 * say which of the two failed. */
static int test_vset_preview_verdicts(void) {
    printf("\n\xc2\xa7" "12i preview_next — 0 built / 1 empty (verdict) "
           "/ -1 fault\n");
    fixture_t fx;
    CHECK(fx_bare(&fx, "preview") == 0, "bare fixture");

    dna_vset_snapshot_t *s = NULL;
    CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, &s) == -1 && !s,
          "no seed row at 2E-1: FAULT (-1), never an empty verdict");
    CHECK(nodus_witness_vset_preview_next(fx.w, UINT64_MAX - 1, &s) == -1
              && !s, "H + E overflow: FAULT");
    CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, NULL) == -1,
          "NULL out: FAULT");

    CHECK(seed_legacy_block(&fx, 2 * E - 1) == 0, "seed row at 2E-1");
    CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, &s) == 1 && !s,
          "seed present, no validator: EMPTY verdict (1), out untouched");
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, 3 * E,
                                             DNAC_COMMITTEE_SIZE, NULL,
                                             NULL, NULL, NULL) == -1,
          "the public build_for_epoch still treats EMPTY as a failure "
          "(commit_next / commit_genesis semantics unchanged)");

    CHECK(seed_validator(&fx, 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE,
                         100, 0, 0) == 0, "one tenured validator");
    CHECK(seed_validator(&fx, 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE,
                         100, 0, 0) == 0, "one more, re-dated below");
    {
        dnac_validator_record_t v;
        CHECK(val_get(&fx, 1, &v) == 0, "get 1");
        v.active_since_block = 2 * E;      /* 2E + 2E > 3E: untenured */
        CHECK(nodus_validator_update(fx.w, &v) == 0, "untenured bond");
    }
    /* tokenomics-v3 P3-1 ("okuma B"): the set previewed at boundary 2E
     * (for 3E) ranks by the frozen copy(E); this bare fixture never ran a
     * boundary, so the copy is written here from the two live rows. Before
     * it exists the tenured validator holds no frozen stake — not seated,
     * so the preview is the EMPTY verdict. RED ON THE PRE-P3 TREE: the
     * live read seated it (0) with no copy. */
    CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, &s) == 1 && !s,
          "P3-1: no frozen copy(E) -> nobody seatable -> EMPTY verdict");
    CHECK(nodus_witness_v2_balance_copy_write(fx.w, E) == 0,
          "write copy(E) from the live rows");
    CHECK(nodus_witness_vset_preview_next(fx.w, 2 * E, &s) == 0 && s,
          "one tenured validator: built (0)");
    int ok = s->active_count == 1 && s->epoch == 3 * E &&
             memcmp(s->entries[0].pubkey, g_pk[0], DNAC_PUBKEY_SIZE) == 0 &&
             s->entries[0].total_stake == BOND_BASE;
    dna_vset_free(&s);
    CHECK(ok, "the preview is keyed on H+E and passes through the same "
              "tenure gate as commit_next — key 1 is not seated");
    OK();
    printf("  ok: preview_next separates FAULT from EMPTY; build_for_epoch "
           "unchanged\n");
    fx_close(&fx);
    return 0;
}

int main(void) {
    printf("=== Ledger V2 O12 S2/S3 — epoch boundary + snapshot "
           "authority ===\n");
    printf("(INACTIVE: no live consensus path calls this module)\n");
    /* This file pins per-block DomainUpdate counts and whole-table row
     * counts across boundaries. tokenomics-v3 P2 deleted the per-block
     * mint, so every chain is quiet (the O15J `v2x_inflation_off` switch
     * is gone); the reward distribution pays nothing here because these
     * fixtures reserve no reward pool (their seeded supply rows carry
     * reward_pool 0).
     * The distribution and the payday are covered by test_v2_econ. */
    keys_init();

    /* S2 — the engine-mandatory boundary transition */
    if (test_derivation() != 0) return 1;
    if (test_boundary_chain() != 0) return 1;
    if (test_grad_deleg_release() != 0) return 1;   /* tokenomics-v3 P3-4 */
    if (test_multi_graduate() != 0) return 1;
    if (test_commit_next() != 0) return 1;
    if (test_faults() != 0) return 1;
    if (test_malformed_row() != 0) return 1;
    if (test_rule_n_liveness() != 0) return 1;
    if (test_rule_n_p2_window() != 0) return 1;
    if (test_rule_n_retiring_excluded() != 0) return 1;
    if (test_rule_n_twin_determinism() != 0) return 1;
    if (test_rule_n_attendance_fault_stages() != 0) return 1;
    if (test_rule_n_jittery_cluster() != 0) return 1;
    if (test_rule_n_midepoch_stake_no_miss() != 0) return 1;
    if (test_rule_n_no_duty_resets_counter() != 0) return 1;
    if (test_rule_n_floor() != 0) return 1;
    if (test_rule_n_graduation_deferral() != 0) return 1;
    if (test_rule_n_weight_concentration() != 0) return 1;
    if (test_rule_n_weight_equal_survivors() != 0) return 1;
    if (test_rule_n_weight_untenured_not_counted() != 0) return 1;
    if (test_vset_preview_verdicts() != 0) return 1;

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
