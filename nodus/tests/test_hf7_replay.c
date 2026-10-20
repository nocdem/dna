/**
 * @file nodus/tests/test_hf7_replay.c
 * @brief HF-7 P1c-2 — the rooted replay relation (v2_replay) and the D2
 *        whole-block expiry rule, at the roots generation and below it.
 *
 * Design docs/plans/2026-09-11-nodus-ledger-snapshot-design.md §10.2
 * items 5-7, §10.3 (rows "replay guard tables", "v2_replay rows", "expiry
 * block rule", "CheckTx expiry"), §10.9 (rev 1), §10.11 (khan decisions:
 * no per-block cap, the mempool window stays 100 node-local, the expiry
 * column an INTEGER); decision docs/plans/decisions/2026-10-20-kurultay-
 * 27-hf7-p1-summary.md items 3, 4, 5; docs/plans/decisions/2026-09-25-
 * mempool-policy.md decision 1.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. predicate: nodus_witness_v2_expiry_in_window at every endpoint —
 *     e = 0, H − 1, H, H + 720, H + 721, UINT64_MAX, and around 2^63 (no
 *     wrap: e − H is formed only once e >= H). False would mean a block
 *     rule that admits an expired / unbounded envelope or wraps.
 *  2. rows_gen5 (roots generation, HF-3 on):
 *     - block 1 [A e=6, F failing e=6, B e=1]: one v2_replay row per
 *       APPLIED item with tx_id = A's wire id, intent_id = A's intent id,
 *       expiry 6; the failing item F left no row (its savepoint rolled
 *       back); B (e == H) was inserted and PRUNED by phase 12d in its own
 *       block; the two index tables still carry A and B (node-local RPC
 *       indexes, written as before, never copied into v2_replay);
 *     - block 2 [A again, A' (same intent, other auth bytes → other wire
 *       id), C, C again]: A and A' REPLAY, the in-block duplicate of C
 *       REPLAY, C applied;
 *     - the other three callers refuse A and A' at the roots generation:
 *       the CheckTx dry run (code REPLAY), the proposal seam
 *       (ENTRY_INVALID at its index), CheckTx's admission lane
 *       (verify_v2_successor_tx → "intent or wire id already committed");
 *     - the guard swap is exact (direct calls, rolled-back edits): with
 *       v2_replay emptied the roots-generation guard sees NO hit while the
 *       generation-4 guard still hits through the index tables; with the
 *       index tables emptied the roots guard hits and the generation-4 one
 *       does not; the tx_id half alone and the intent half alone each hit;
 *     - blocks 3..5 keep A's row (6 > H), block 6 prunes it (6 <= 6).
 *  3. prune_direct: nodus_witness_v2_replay_prune deletes EXACTLY the rows
 *     with expiry <= H (rows 5, 6, 7 → prune at 6 deletes two, leaves 7),
 *     is idempotent, and is a no-op below the roots generation.
 *  4. expiry_gen5 (roots generation, HF-3 on), at candidate H = tip + 1:
 *     for e in {0, H − 1, H + 721, UINT64_MAX, 2^63}: the seam refuses
 *     ENTRY_INVALID at the violator's index, ProcessProposal REJECTs a
 *     proposal [good, violator], PrepareProposal never selects the violator
 *     (it returns the good envelopes only), FinalizeBlock FAULTs a block
 *     [good, violator] with "phase 0d" in the reason and the whole database
 *     byte-identical; e = H and e = H + 720 pass all three and apply.
 *  5. expiry_gen5_nohf3: the seam's D2 refusal runs at the roots
 *     generation with HF-3 OFF too (one violator, one good envelope).
 *  6. checktx_gen5: CheckTx (nodus_cmt_app_check_tx) at tip T refuses
 *     e = 0, e = T and e = T + 101, admits e = T + 1 and e = T + 100.
 *  7. gen4_unchanged (generation 4, HF-3 on): no v2_replay row is ever
 *     written; A and A' are REPLAY through the index tables in the item
 *     loop, the dry run, the seam and the admission lane (the old reason
 *     text); an envelope with e = 0 and one with e = H + 721 APPLY; one
 *     with e = H − 1 is a FAILED ITEM (DECODE) in a committed block, not a
 *     fault; the seam accepts e = 0 and e = H + 721.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 *  Compile flags: none beyond the default nodus build (NODUS_EVM_ENABLED
 *  not needed). Environment: none. The seeded database is climbed to
 *  schema S19 (nodus_witness_db_migrate_v2s19) before the genesis — the
 *  seeding helper stops at S16. The roots generation is reached
 *  WITHOUT its edge: the scripted runtime table (v2_exec_fixture.h,
 *  builtin-copied SYSTEM/CORE entries) is copied per fixture with its
 *  `generation` field set to NODUS_RT_GEN_ROOTS (or NODUS_RT_GEN_STORAGE)
 *  BEFORE the seeded version-3 genesis, so the registry tuples resolve
 *  onto entries that report that generation from genesis on (lookup is
 *  by the five-axis tuple, never by generation). The two entries'
 *  `state_root` hooks are pinned to the generation-1 compositions
 *  (h7_sys_root / h7_core_root): at >= 4 the native hooks would compose
 *  SYSTEM v5 over v2_validator_roles rows only the HF-6 edge writes, and a
 *  CORE root the genesis registry row does not carry. Every block stays in
 *  epoch 0 (default DNAC_EPOCH_LENGTH 720), so no boundary runs.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 *  One /tmp/test_hf7_replay_<tag>_XXXXXX directory per fixture, removed
 *  at its end (left behind only on a CHECK failure).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A real chain reaches generation 5 through the HF-7 edge (P1d) at the
 *    end of block A − 1; this file never crosses an edge, so the A − 1
 *    cell of the transition matrix (index-table guard, no rows, today's
 *    expiry rule, edge at the end) is NOT exercised here — the engine
 *    edge is test_hf7_edge.c's (HF-7 P1d), 7/7 is P1e's harness
 *    scenario. The block-start reading is pinned only indirectly:
 *    every gate reads the context's generation, built before phase 6b.
 *  - The SYSTEM / CORE root compositions are pinned to generation 1's
 *    (above), so no domain-root rule of generation >= 4 is exercised here.
 *    The patched generation still reaches every engine-body gate on it:
 *    after HF-7 P1c-1 merges, phase 13's GLOBAL v2 / replay_root and the
 *    DomainHead v2 head-authoritative read run too, on a chain that never
 *    crossed the edge that seeds `last_upd_hash`. A failure there is not
 *    a replay/expiry defect — read the reason.
 *  - The scripted runtime ignores the fee and hashes any auth bytes, so
 *    "A' is the same intent under another authorization" is the intent /
 *    wire derivation's statement, not a second real signer.
 *  - CheckTx's lower bound: the admission lane's preflight (at tip + 1)
 *    already refuses e < tip + 1 BEFORE the window check, so case 6 shows
 *    the refusal, not which of the two checks produced it.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_cmt_app.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_exec_fixture.h"
#include "v2_genesis_fixture.h"

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

/* ── fs ─────────────────────────────────────────────────────────────── */
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

/* ── fixture: a seeded version-3 chain at a CHOSEN generation ─────────
 * The scripted table (v2_exec_fixture.h v2x_table_init) is copied into
 * the fixture and its two entries' `generation` set to `gen` BEFORE the
 * genesis, so the genesis composes its roots under that generation and
 * every block after it is judged by it (header "WHAT IT REQUIRES"). */
typedef struct {
    nodus_witness_t        *w;
    char                    dir[256];
    uint8_t                 chain_id16[16];
    nodus_domain_runtime_t  tab[2];
} h7_fx_t;

/* The genesis generation's root compositions, pinned on the patched
 * entries: nodus_rt_system_state_root / nodus_rt_core_state_root
 * (nodus_witness_v2_claims.c) choose the composition by rt->generation,
 * and at >= 4 the SYSTEM root's validator leaf joins v2_validator_roles —
 * rows only the HF-6 edge writes (nodus_witness_v2_roles_migrate), which a
 * seeded genesis never runs — while the CORE root gains the EVM reserve
 * leaf the registry's genesis_state_root (composed by the builtin
 * generation-1 entry, nodus_witness_domreg_init_genesis) does not carry.
 * Pinning the generation-1 compositions keeps the root legs out of what
 * this file tests; the replay leg and the GLOBAL composition are phase
 * 13's, not these hooks'. */
static int h7_sys_root(const nodus_domain_runtime_t *rt,
                       struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return nodus_witness_system_root_v2((nodus_witness_t *)w, out);
}

static int h7_core_root(const nodus_domain_runtime_t *rt,
                        struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return nodus_witness_core_root_v2((nodus_witness_t *)w, out);
}

static int h7_open(h7_fx_t *fx, const char *tag, uint32_t gen, int hf3) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf7_replay_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x37, sizeof(fx->chain_id16));
    if (v2x_seed_prepare(fx->w, fx->chain_id16, 0) != 0) return -1;
    /* v2x_seed_prepare leaves the chain at S16; v2_replay is an S19 table
     * (HF-7 P1b), so climb the rungs before the genesis, as a node's
     * at-open rung does (nodus_witness.c witness_open_migrate_s19) */
    {
        uint32_t ver = 0;
        if (nodus_witness_db_migrate_v2s19(fx->w) != 0 ||
            nodus_witness_db_schema_version(fx->w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S19)
            return -1;
    }
    if (v2x_table_init(fx->w) != 0) return -1;
    memcpy(fx->tab, g_v2x_table, sizeof(fx->tab));
    if (fx->tab[0].domain_id != DNA_DOMAIN_SYSTEM ||
        fx->tab[1].domain_id != DNA_DOMAIN_CORE)
        return -1;                           /* PREMISE: SYSTEM, CORE    */
    fx->tab[0].generation = gen;
    fx->tab[1].generation = gen;
    fx->tab[0].state_root = h7_sys_root;     /* SYSTEM (domain 0)        */
    fx->tab[1].state_root = h7_core_root;    /* CORE   (domain 1)        */
    fx->w->v2_runtime_table   = fx->tab;
    fx->w->v2_runtime_table_n = 2;
    if (hf3) {
        /* HF-3 in force from block 1 (pre-genesis row: a post-genesis
         * chain_config write would move the SYSTEM root outside a block —
         * test_v2_apply.c hf3_fx_open) */
        char sql[320];
        char *err = NULL;
        snprintf(sql, sizeof(sql),
                 "INSERT INTO chain_config_history (param_id, new_value, "
                 "effective_block, commit_block, tx_hash, proposal_nonce, "
                 "created_at_unix) VALUES (%u, %llu, 1, 0, zeroblob(64), 1, "
                 "0)", (unsigned)DNAC_CFG_HF3_ACTIVE,
                 (unsigned long long)DNAC_CFG_HF3_ACTIVE_ON);
        if (sqlite3_exec(fx->w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
            fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
            sqlite3_free(err);
            return -1;
        }
        fx->w->chain_config_cache_warm = false;
    }
    if (v2x_seed_genesis(fx->w, fx->chain_id16, 0, NULL, 0, NULL) != 0)
        return -1;
    /* the admission lane's gate (nodus_witness_v2_ingress_is_armed): the
     * fixture is a committed version-3 chain, armed as a started node is */
    fx->w->v2_ingress_armed = true;
    return 0;
}

static void h7_close(h7_fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/** PREMISE: the committed registry AND the block-start context at the
 *  next height both report `gen`. 0 / -1. */
static int h7_gen_is(nodus_witness_t *w, uint32_t gen) {
    uint32_t kg = 0;
    uint64_t tip = 0;
    nodus_witness_v2_block_ctx_t *b = calloc(1, sizeof(*b));
    int ok = -1;
    if (!b) return -1;
    if (nodus_witness_v2_key_generation(w, &kg) == 0 && kg == gen &&
        nodus_witness_v2_tip_height(w, &tip) == 0 &&
        nodus_witness_v2_block_ctx_build(w, tip + 1, b) == 0 &&
        b->generation == gen)
        ok = 0;
    free(b);
    return ok;
}

/* ── envelopes ──────────────────────────────────────────────────────── */
#define H7_KIND_CREATE  0      /* CORE UTXO CREATE (amount 0) — applies   */
#define H7_KIND_FAIL    1      /* CORE UTXO SET on an absent row — refused
                                * at execution (PRE_EXISTS)               */

/** One CORE envelope: `kind` on key (0x77, kind, tag), amount 0 (the CORE
 *  supply equation is untouched), expiry `expiry`, ONE auth byte `auth`
 *  (another auth byte = another wire id, the same intent id). 0 / -1. */
static int h7_env(v2x_env_t *e, uint8_t tag, int kind, uint64_t expiry,
                  uint8_t auth) {
    uint8_t key[64] = { 0 };
    uint8_t val[8]  = { 0 };
    uint8_t res[512];
    uint8_t call[600];
    size_t  rl = 0;
    uint32_t cl;
    dna_env_leg_in_t leg;
    dna_env_in_t env;

    key[61] = 0x77;
    key[62] = (uint8_t)kind;
    key[63] = tag;
    if (v2x_eff1(res, sizeof(res), V2X_OP_UTXO,
                 kind == H7_KIND_FAIL ? DNA_EFFECT_SET : DNA_EFFECT_CREATE,
                 kind == H7_KIND_FAIL ? DNA_EFFECT_PRE_EXISTS
                                      : DNA_EFFECT_PRE_ABSENT,
                 key, 64, val, 8, &rl) != 0)
        return -1;
    cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = 1;
    leg.hdr.runtime_op           = 1;
    leg.hdr.ruleset_version      = v2x_ruleset_version_for(1);
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = 1;
    leg.hdr.call_len             = cl;
    leg.hdr.auth_len             = 1;
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 2048;
    leg.call_data                = call;
    leg.auth_data                = &auth;
    memset(&env, 0, sizeof(env));
    env.expiry_height       = expiry;
    env.fee_amount          = 0;
    env.res_max_total_units = 200000;
    env.leg_count           = 1;
    env.legs                = &leg;
    return dna_env_encode(&env, e->bytes, sizeof(e->bytes), &e->len);
}

/** The envelope's wire and intent ids as the engine derives them at the
 *  next height (the CheckTx dry run's preflight — the item loop's own).
 *  0 / -1 (the preflight did not run: e.g. already expired). */
static int h7_ids(nodus_witness_t *w, const v2x_env_t *e, uint8_t wire[64],
                  uint8_t intent[64]) {
    static const uint8_t zero[64];
    nodus_v2_env_dry_run_t *dr = calloc(1, sizeof(*dr));
    char why[256];
    int ok = -1;
    if (!dr) return -1;
    if (nodus_witness_v2_env_dry_run(w, e->bytes, e->len, NULL, dr, why,
                                     sizeof(why)) != -2 &&
        memcmp(dr->wire_id, zero, 64) != 0) {
        memcpy(wire, dr->wire_id, 64);
        memcpy(intent, dr->intent_id, 64);
        ok = 0;
    }
    nodus_witness_v2_env_dry_run_free(dr);
    free(dr);
    return ok;
}

/** The CheckTx dry run's verdict: 0 passed / 1 refused with *code / -1
 *  fault. */
static int h7_dry(nodus_witness_t *w, const v2x_env_t *e, uint32_t *code) {
    nodus_v2_env_dry_run_t *dr = calloc(1, sizeof(*dr));
    char why[256];
    int rc;
    if (!dr) return -1;
    rc = nodus_witness_v2_env_dry_run(w, e->bytes, e->len, NULL, dr, why,
                                      sizeof(why));
    *code = dr->code;
    nodus_witness_v2_env_dry_run_free(dr);
    free(dr);
    return rc == 0 ? 0 : (rc == -1 ? 1 : -1);
}

/** The seam over `n` envelopes at tip + 1 — the call ProcessProposal makes
 *  (nodus_witness_cmt_app.c app_seam_check). rc 0 / -1 / -2. */
static int h7_seam(nodus_witness_t *w, v2x_env_t *const *es, size_t n,
                   nodus_v2_batch_fail_kind_t *kind, int *fi) {
    nodus_witness_batch_item_t it[8];
    nodus_v2_batch_check_result_t r;
    int rc;
    if (n == 0 || n > 8) return -3;
    for (size_t i = 0; i < n; i++) {
        it[i].tx_type = NODUS_W_TX_V2_ENVELOPE;
        it[i].tx_data = es[i]->bytes;
        it[i].tx_len  = (uint32_t)es[i]->len;
    }
    memset(&r, 0, sizeof(r));
    *fi = -1;
    rc = nodus_witness_v2_produce_batch_check_capped(w, it, (int)n, (int)n,
                                                     fi, &r);
    *kind = r.kind;
    return rc;
}

/** CheckTx's admission lane (verify_v2_successor_tx) in ADMISSION mode:
 *  0 admitted / -1 refused (reason in why). */
static int h7_admit(nodus_witness_t *w, const v2x_env_t *e,
                    const uint8_t wire[64], char *why, size_t why_len) {
    why[0] = '\0';
    return nodus_witness_verify_transaction(
        w, e->bytes, (uint32_t)e->len, wire, NODUS_W_TX_V2_ENVELOPE, NULL, 0,
        NULL, NULL, 0, NODUS_WITNESS_VERIFY_ADMISSION, why, why_len);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/** Apply a block of `n` fixture envelopes at height h; the item codes are
 *  copied into codes[]. 0 committed / -1 otherwise. */
static int h7_apply(nodus_witness_t *w, uint64_t h, v2x_env_t *const *es,
                    size_t n, uint32_t *codes) {
    nodus_v2_envelope_t v[8];
    nodus_v2_block_t blk;
    if (n > 8) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = es[i]->bytes;
        v[i].env_len   = es[i]->len;
    }
    mk_block(&blk, h, n ? v : NULL, n);
    if (v2x_cmt_apply(w, &blk) != 0) return -1;
    for (size_t i = 0; i < n && codes; i++)
        codes[i] = blk.cmt.results[i].code;
    return 0;
}

/** FinalizeBlock's phase 0d: the block is a node FAULT whose reason names
 *  phase 0d, and the whole database is byte-identical. 0 / -1. */
static int h7_fault_0d(nodus_witness_t *w, uint64_t h, v2x_env_t *const *es,
                       size_t n) {
    nodus_v2_envelope_t v[8];
    nodus_v2_block_t blk;
    if (n == 0 || n > 8) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = es[i]->bytes;
        v[i].env_len   = es[i]->len;
    }
    mk_block(&blk, h, v, n);
    return v2x_cmt_fault_why(w, &blk, V2X_FAULT, "phase 0d");
}

static uint64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    uint64_t v = UINT64_MAX;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
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

/** The v2_replay row keyed by `wire`: 1 found (intent / expiry out, the
 *  storage classes checked BLOB / BLOB / INTEGER), 0 absent, -1 fault. */
static int h7_row(nodus_witness_t *w, const uint8_t wire[64],
                  uint8_t intent[64], uint64_t *expiry) {
    sqlite3_stmt *st = NULL;
    int rc, ret = -1;
    if (sqlite3_prepare_v2(w->db,
            "SELECT intent_id, expiry_height, typeof(tx_id), "
            "typeof(intent_id), typeof(expiry_height) FROM v2_replay "
            "WHERE tx_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, wire, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW &&
               sqlite3_column_bytes(st, 0) == 64 &&
               strcmp((const char *)sqlite3_column_text(st, 2), "blob") == 0 &&
               strcmp((const char *)sqlite3_column_text(st, 3), "blob") == 0 &&
               strcmp((const char *)sqlite3_column_text(st, 4),
                      "integer") == 0) {
        memcpy(intent, sqlite3_column_blob(st, 0), 64);
        *expiry = (uint64_t)sqlite3_column_int64(st, 1);
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

/** The ONE guard, asked directly at `gen` for (intent, wire). hit / -1. */
static int h7_guard(nodus_witness_t *w, uint32_t gen, const uint8_t intent[64],
                    const uint8_t wire[64]) {
    dna_env_preflight_t *p = calloc(1, sizeof(*p));
    char why[192];
    int hit = 0, rc;
    if (!p) return -1;
    memcpy(p->intent_id, intent, 64);
    memcpy(p->wire_id, wire, 64);
    rc = nodus_witness_v2_replay_guard(w, p, gen, 0, &hit, why, sizeof(why));
    free(p);
    return rc == 0 ? hit : -1;
}

/* ══ 1. the predicate ═══════════════════════════════════════════════ */
static int t_predicate(void) {
    const uint64_t H = 1000;
    const uint64_t W = NODUS_V2_EXPIRY_WINDOW_BLOCKS;
    const uint64_t T63 = (uint64_t)1 << 63;

    CHECK(W == 720, "PREMISE: the window is 720 blocks (§10.11 C)"); OK();
    CHECK(!nodus_witness_v2_expiry_in_window(0, H), "e = 0 is outside"); OK();
    CHECK(!nodus_witness_v2_expiry_in_window(H - 1, H), "e = H - 1 outside");
    OK();
    CHECK(nodus_witness_v2_expiry_in_window(H, H), "e = H inside"); OK();
    CHECK(nodus_witness_v2_expiry_in_window(H + W, H), "e = H + 720 inside");
    OK();
    CHECK(!nodus_witness_v2_expiry_in_window(H + W + 1, H),
          "e = H + 721 outside"); OK();
    CHECK(!nodus_witness_v2_expiry_in_window(UINT64_MAX, H),
          "e = UINT64_MAX outside (no wrap)"); OK();
    CHECK(!nodus_witness_v2_expiry_in_window(T63, H),
          "e = 2^63 outside at a small H"); OK();
    CHECK(nodus_witness_v2_expiry_in_window(T63 + W, T63) &&
          !nodus_witness_v2_expiry_in_window(T63 + W + 1, T63) &&
          !nodus_witness_v2_expiry_in_window(T63 - 1, T63),
          "around 2^63: [H, H + 720] exactly"); OK();
    CHECK(nodus_witness_v2_expiry_in_window(UINT64_MAX, UINT64_MAX - W) &&
          !nodus_witness_v2_expiry_in_window(UINT64_MAX - W - 1,
                                              UINT64_MAX - W),
          "at the top of u64: H + 720 = UINT64_MAX inside, no h + 720 "
          "formed"); OK();
    CHECK(!nodus_witness_v2_expiry_in_window(1, 2) &&
          nodus_witness_v2_expiry_in_window(1, 1),
          "the smallest heights"); OK();
    return 0;
}

/* ══ 2. rows, replays and the guard swap at the roots generation ═══ */
static int t_rows_gen5(void) {
    h7_fx_t fx;
    static v2x_env_t A, Ap, F, B, C;
    uint8_t wa[64], ia[64], wap[64], iap[64], wb[64], ib[64], wf[64], iff[64];
    uint8_t got_i[64];
    uint64_t got_e = 0;
    uint32_t codes[8];
    uint32_t code = 0;
    nodus_v2_batch_fail_kind_t kind;
    int fi;
    char why[256];

    CHECK(h7_open(&fx, "rows5", NODUS_RT_GEN_ROOTS, 1) == 0, "gen-5 chain");
    OK();
    CHECK(h7_gen_is(fx.w, NODUS_RT_GEN_ROOTS) == 0,
          "PREMISE: registry and block-start context report the roots "
          "generation"); OK();

    CHECK(h7_env(&A, 1, H7_KIND_CREATE, 6, 0xAA) == 0 &&
          h7_env(&Ap, 1, H7_KIND_CREATE, 6, 0xBB) == 0 &&
          h7_env(&F, 2, H7_KIND_FAIL, 6, 0xAA) == 0 &&
          h7_env(&B, 3, H7_KIND_CREATE, 1, 0xAA) == 0 &&
          h7_env(&C, 4, H7_KIND_CREATE, 10, 0xAA) == 0, "envelopes");
    CHECK(h7_ids(fx.w, &A, wa, ia) == 0 && h7_ids(fx.w, &Ap, wap, iap) == 0 &&
          h7_ids(fx.w, &B, wb, ib) == 0 && h7_ids(fx.w, &F, wf, iff) == 0,
          "ids at candidate 1");
    CHECK(memcmp(ia, iap, 64) == 0 && memcmp(wa, wap, 64) != 0,
          "PREMISE: A' is A's intent under another wire realization"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 0,
          "PREMISE: the relation starts empty"); OK();

    /* ── block 1: A applies, F fails, B (e == H) applies ─────────────── */
    {
        v2x_env_t *b1[3] = { &A, &F, &B };
        CHECK(h7_apply(fx.w, 1, b1, 3, codes) == 0, "block 1 committed"); OK();
        CHECK(codes[0] == NODUS_V2_TX_OK && codes[1] != NODUS_V2_TX_OK &&
              codes[2] == NODUS_V2_TX_OK, "A applied, F refused, B applied");
        OK();
    }
    CHECK(h7_row(fx.w, wa, got_i, &got_e) == 1 &&
          memcmp(got_i, ia, 64) == 0 && got_e == 6,
          "A's row: tx_id = its wire id, intent_id, expiry 6, BLOB/BLOB/"
          "INTEGER"); OK();
    CHECK(h7_row(fx.w, wf, got_i, &got_e) == 0,
          "the failed item F left NO row (its savepoint rolled back)"); OK();
    CHECK(h7_row(fx.w, wb, got_i, &got_e) == 0,
          "B (e == H) was inserted and pruned by phase 12d in its own "
          "block"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 1,
          "exactly one row: A's"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_intent_index WHERE "
                   "global_height = 1") == 2 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index WHERE "
                   "global_height = 1") == 2,
          "the two index tables still carry A and B (node-local, written "
          "as before, not pruned)"); OK();

    /* ── the other three callers refuse A and A' (candidate 2) ───────── */
    CHECK(h7_dry(fx.w, &A, &code) == 1 && code == NODUS_V2_TX_ERR_REPLAY,
          "dry run: A is REPLAY"); OK();
    CHECK(h7_dry(fx.w, &Ap, &code) == 1 && code == NODUS_V2_TX_ERR_REPLAY,
          "dry run: A' (same intent) is REPLAY"); OK();
    {
        v2x_env_t *s[2] = { &C, &Ap };
        CHECK(h7_seam(fx.w, s, 2, &kind, &fi) == -1 &&
              kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID && fi == 1,
              "seam: A' is ENTRY_INVALID at its index"); OK();
        CHECK(h7_seam(fx.w, s, 1, &kind, &fi) == 0,
              "seam: the batch without it is accepted"); OK();
    }
    CHECK(h7_admit(fx.w, &A, wa, why, sizeof(why)) == -1 &&
          strstr(why, "intent or wire id already committed") != NULL,
          "admission lane: A refused by the replay relation"); OK();
    CHECK(h7_admit(fx.w, &Ap, wap, why, sizeof(why)) == -1 &&
          strstr(why, "intent or wire id already committed") != NULL,
          "admission lane: A' refused by the replay relation"); OK();

    /* ── the guard swap, exactly (direct calls, rolled-back edits) ───── */
    CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, ia, wa) == 1 &&
          h7_guard(fx.w, NODUS_RT_GEN_STORAGE, ia, wa) == 1,
          "both tables hold A"); OK();
    CHECK(run_sql(fx.w->db, "BEGIN") == 0 &&
          run_sql(fx.w->db, "DELETE FROM v2_replay") == 0, "edit 1");
    CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, ia, wa) == 0,
          "roots generation: the index tables are NOT a guard"); OK();
    CHECK(h7_guard(fx.w, NODUS_RT_GEN_STORAGE, ia, wa) == 1,
          "generation 4: the index tables are the guard"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "undo 1");
    CHECK(run_sql(fx.w->db, "BEGIN") == 0 &&
          run_sql(fx.w->db, "DELETE FROM v2_intent_index") == 0 &&
          run_sql(fx.w->db, "DELETE FROM v2_tx_index") == 0, "edit 2");
    CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, ia, wa) == 1,
          "roots generation: v2_replay alone refuses A"); OK();
    CHECK(h7_guard(fx.w, NODUS_RT_GEN_STORAGE, ia, wa) == 0,
          "generation 4 never reads v2_replay"); OK();
    {
        uint8_t other[64];
        memset(other, 0x5A, sizeof(other));
        CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, other, wa) == 1,
              "the tx_id half alone is a hit"); OK();
        CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, ia, other) == 1,
              "the intent_id half alone is a hit"); OK();
        CHECK(h7_guard(fx.w, NODUS_RT_GEN_ROOTS, other, other) == 0,
              "neither half: no hit"); OK();
    }
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "undo 2");

    /* ── block 2: A and A' REPLAY; the in-block duplicate of C REPLAY ── */
    {
        v2x_env_t *b2[4] = { &A, &Ap, &C, &C };
        CHECK(h7_apply(fx.w, 2, b2, 4, codes) == 0, "block 2 committed"); OK();
        CHECK(codes[0] == NODUS_V2_TX_ERR_REPLAY &&
              codes[1] == NODUS_V2_TX_ERR_REPLAY,
              "item loop: A and A' are REPLAY"); OK();
        CHECK(codes[2] == NODUS_V2_TX_OK &&
              codes[3] == NODUS_V2_TX_ERR_REPLAY,
              "item loop: C applies, its in-block duplicate is REPLAY"); OK();
    }
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 2,
          "rows: A (6) and C (10)"); OK();

    /* ── the prune through the engine: A's row lives through 5, dies at 6 */
    for (uint64_t h = 3; h <= 5; h++)
        CHECK(h7_apply(fx.w, h, NULL, 0, NULL) == 0, "empty block");
    CHECK(h7_row(fx.w, wa, got_i, &got_e) == 1,
          "after block 5 A's row (expiry 6) is still there"); OK();
    CHECK(h7_apply(fx.w, 6, NULL, 0, NULL) == 0, "block 6");
    CHECK(h7_row(fx.w, wa, got_i, &got_e) == 0 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 1,
          "block 6 pruned A's row (6 <= 6), C's (10) stays"); OK();

    h7_close(&fx);
    return 0;
}

/* 63 zero bytes as hex (126 '0'), the prefix of the 64-byte ids below */
#define H7_Z16 "0000000000000000"
#define H7_Z63 H7_Z16 H7_Z16 H7_Z16 H7_Z16 H7_Z16 H7_Z16 H7_Z16 \
               "00000000000000"

/* ══ 3. the prune, directly ═════════════════════════════════════════ */
static int t_prune_direct(void) {
    h7_fx_t fx;
    uint64_t n = 99;
    char why[192];

    CHECK(h7_open(&fx, "prune", NODUS_RT_GEN_ROOTS, 0) == 0, "gen-5 chain");
    CHECK(run_sql(fx.w->db, "BEGIN") == 0 &&
          run_sql(fx.w->db,
                  "INSERT INTO v2_replay (tx_id, intent_id, expiry_height) "
                  /* 64-byte BLOB literals: `zeroblob(63) || x'05'` is
                   * TEXT in SQLite (|| always yields text), which the S19
                   * typeof CHECK refuses */
                  "VALUES (x'" H7_Z63 "05', x'" H7_Z63 "15', 5),"
                  " (x'" H7_Z63 "06', x'" H7_Z63 "16', 6),"
                  " (x'" H7_Z63 "07', x'" H7_Z63 "17', 7)") == 0,
          "three rows, expiry 5, 6, 7");
    CHECK(nodus_witness_v2_replay_prune(fx.w, NODUS_RT_GEN_STORAGE, 7, &n,
                                        why, sizeof(why)) == 0 && n == 0 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 3,
          "below the roots generation the prune deletes nothing"); OK();
    CHECK(nodus_witness_v2_replay_prune(fx.w, NODUS_RT_GEN_ROOTS, 6, &n,
                                        why, sizeof(why)) == 0 && n == 2,
          "the prune at 6 deletes two rows"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 1 &&
          q1(fx.w, "SELECT expiry_height FROM v2_replay") == 7,
          "exactly expiry <= 6 went; 7 stays"); OK();
    CHECK(nodus_witness_v2_replay_prune(fx.w, NODUS_RT_GEN_ROOTS, 6, &n,
                                        why, sizeof(why)) == 0 && n == 0,
          "idempotent"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "undo");
    h7_close(&fx);
    return 0;
}

/* ══ 4. the D2 window at Prepare / Process / Finalize (gen 5) ═══════ */
static int t_expiry_gen5(void) {
    h7_fx_t fx;
    nodus_cmt_app_ledger_t *app = NULL;
    const v2x_cmt_gen_t *gs;
    static v2x_env_t good_h, good_w, bad[5];
    uint64_t tip = 0, H;
    uint32_t codes[8];
    nodus_v2_batch_fail_kind_t kind;
    int fi;
    static const char *const bad_name[5] = {
        "e = 0", "e = H - 1", "e = H + 721", "e = UINT64_MAX", "e = 2^63"
    };

    CHECK(h7_open(&fx, "exp5", NODUS_RT_GEN_ROOTS, 1) == 0, "gen-5 chain");
    CHECK(h7_gen_is(fx.w, NODUS_RT_GEN_ROOTS) == 0, "PREMISE: generation 5");
    /* move the tip off 0 so e = H - 1 is a real height */
    for (uint64_t h = 1; h <= 3; h++)
        CHECK(h7_apply(fx.w, h, NULL, 0, NULL) == 0, "empty block");
    CHECK(nodus_witness_v2_tip_height(fx.w, &tip) == 0 && tip == 3, "tip 3");
    H = tip + 1;

    CHECK(h7_env(&good_h, 0x10, H7_KIND_CREATE, H, 0xAA) == 0 &&
          h7_env(&good_w, 0x11, H7_KIND_CREATE,
                 H + NODUS_V2_EXPIRY_WINDOW_BLOCKS, 0xAA) == 0 &&
          h7_env(&bad[0], 0x20, H7_KIND_CREATE, 0, 0xAA) == 0 &&
          h7_env(&bad[1], 0x21, H7_KIND_CREATE, H - 1, 0xAA) == 0 &&
          h7_env(&bad[2], 0x22, H7_KIND_CREATE,
                 H + NODUS_V2_EXPIRY_WINDOW_BLOCKS + 1, 0xAA) == 0 &&
          h7_env(&bad[3], 0x23, H7_KIND_CREATE, UINT64_MAX, 0xAA) == 0 &&
          h7_env(&bad[4], 0x24, H7_KIND_CREATE, (uint64_t)1 << 63, 0xAA)
              == 0, "envelopes");

    gs = v2x_cmt_genesis_state(fx.w);
    app = calloc(1, sizeof(*app));
    CHECK(gs && app, "genesis document + alloc");
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &gs->doc) == CMT_OK, "bind");

    for (int k = 0; k < 5; k++) {
        v2x_env_t *s1[2] = { &good_h, &bad[k] };
        cmt_pb_bytes_t txs[3];
        nodus_abci_request_process_proposal_t  preq;
        nodus_abci_response_process_proposal_t presp;
        nodus_abci_request_prepare_proposal_t  qreq;
        nodus_abci_response_prepare_proposal_t qresp;

        /* the seam names the violator */
        CHECK(h7_seam(fx.w, s1, 2, &kind, &fi) == -1 &&
              kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID && fi == 1,
              bad_name[k]); OK();

        /* ProcessProposal: REJECT the whole proposal */
        txs[0].data = good_h.bytes; txs[0].len = good_h.len;
        txs[1].data = bad[k].bytes; txs[1].len = bad[k].len;
        memset(&preq, 0, sizeof(preq));
        memset(&presp, 0, sizeof(presp));
        preq.txs = txs;
        preq.txs_len = 2;
        CHECK(nodus_cmt_app_process_proposal(app, &preq, &presp) == CMT_OK &&
              presp.status == NODUS_ABCI_PROPOSAL_STATUS_REJECT,
              bad_name[k]); OK();

        /* PrepareProposal: never selects it */
        txs[2].data = good_w.bytes; txs[2].len = good_w.len;
        memset(&qreq, 0, sizeof(qreq));
        memset(&qresp, 0, sizeof(qresp));
        qreq.txs = txs;
        qreq.txs_len = 3;
        qreq.max_tx_bytes = 22020096;
        CHECK(nodus_cmt_app_prepare_proposal(app, &qreq, &qresp) == CMT_OK,
              "prepare answers");
        CHECK(qresp.txs_len == 2, bad_name[k]); OK();
        for (size_t j = 0; j < qresp.txs_len; j++)
            CHECK(!(qresp.txs[j].len == bad[k].len &&
                    memcmp(qresp.txs[j].data, bad[k].bytes, bad[k].len)
                        == 0), bad_name[k]);
        OK();

        /* FinalizeBlock: a node FAULT, nothing written */
        CHECK(h7_fault_0d(fx.w, H, s1, 2) == 0, bad_name[k]); OK();
    }

    /* the two window endpoints pass all three and apply */
    {
        v2x_env_t *ok2[2] = { &good_h, &good_w };
        cmt_pb_bytes_t txs[2];
        nodus_abci_request_process_proposal_t  preq;
        nodus_abci_response_process_proposal_t presp;
        uint8_t wh[64], ih[64], ww[64], iw[64], gi[64];
        uint64_t ge = 0;

        CHECK(h7_seam(fx.w, ok2, 2, &kind, &fi) == 0,
              "seam accepts e = H and e = H + 720"); OK();
        txs[0].data = good_h.bytes; txs[0].len = good_h.len;
        txs[1].data = good_w.bytes; txs[1].len = good_w.len;
        memset(&preq, 0, sizeof(preq));
        memset(&presp, 0, sizeof(presp));
        preq.txs = txs;
        preq.txs_len = 2;
        CHECK(nodus_cmt_app_process_proposal(app, &preq, &presp) == CMT_OK &&
              presp.status == NODUS_ABCI_PROPOSAL_STATUS_ACCEPT,
              "ProcessProposal ACCEPTs them"); OK();
        CHECK(h7_ids(fx.w, &good_h, wh, ih) == 0 &&
              h7_ids(fx.w, &good_w, ww, iw) == 0, "ids");
        CHECK(h7_apply(fx.w, H, ok2, 2, codes) == 0 &&
              codes[0] == NODUS_V2_TX_OK && codes[1] == NODUS_V2_TX_OK,
              "FinalizeBlock applies both"); OK();
        CHECK(h7_row(fx.w, wh, gi, &ge) == 0,
              "e = H: inserted, pruned in the same block"); OK();
        CHECK(h7_row(fx.w, ww, gi, &ge) == 1 &&
              ge == H + NODUS_V2_EXPIRY_WINDOW_BLOCKS &&
              memcmp(gi, iw, 64) == 0, "e = H + 720: its row stays"); OK();
    }

    nodus_cmt_app_ledger_release(app);
    free(app);
    h7_close(&fx);
    return 0;
}

/* ══ 5. the seam's D2 refusal with HF-3 OFF (gen 5) ══════════════════ */
static int t_expiry_gen5_nohf3(void) {
    h7_fx_t fx;
    static v2x_env_t good, over;
    nodus_v2_batch_fail_kind_t kind;
    int fi;

    CHECK(h7_open(&fx, "exp5n", NODUS_RT_GEN_ROOTS, 0) == 0, "gen-5 chain");
    CHECK(h7_env(&good, 0x30, H7_KIND_CREATE, 1, 0xAA) == 0 &&
          h7_env(&over, 0x31, H7_KIND_CREATE,
                 1 + NODUS_V2_EXPIRY_WINDOW_BLOCKS + 1, 0xAA) == 0,
          "envelopes at candidate 1");
    {
        v2x_env_t *s[2] = { &good, &over };
        CHECK(h7_seam(fx.w, s, 2, &kind, &fi) == -1 &&
              kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID && fi == 1,
              "HF-3 off: the seam still refuses e = H + 721"); OK();
        CHECK(h7_seam(fx.w, s, 1, &kind, &fi) == 0,
              "HF-3 off: e = H passes"); OK();
        CHECK(h7_fault_0d(fx.w, 1, s, 2) == 0,
              "HF-3 off: FinalizeBlock FAULTs it"); OK();
    }
    h7_close(&fx);
    return 0;
}

/* ══ 6. CheckTx's window at the roots generation ═════════════════════ */
static int t_checktx_gen5(void) {
    h7_fx_t fx;
    nodus_cmt_app_ledger_t *app = NULL;
    const v2x_cmt_gen_t *gs;
    static v2x_env_t e[5];
    const uint64_t T = 2;
    static const char *const name[5] = {
        "e = 0 refused", "e = T refused", "e = T + 101 refused",
        "e = T + 1 admitted", "e = T + 100 admitted"
    };
    const int admit[5] = { 0, 0, 0, 1, 1 };

    CHECK(h7_open(&fx, "ckt5", NODUS_RT_GEN_ROOTS, 1) == 0, "gen-5 chain");
    for (uint64_t h = 1; h <= T; h++)
        CHECK(h7_apply(fx.w, h, NULL, 0, NULL) == 0, "empty block");
    CHECK(h7_env(&e[0], 0x40, H7_KIND_CREATE, 0, 0xAA) == 0 &&
          h7_env(&e[1], 0x41, H7_KIND_CREATE, T, 0xAA) == 0 &&
          h7_env(&e[2], 0x42, H7_KIND_CREATE,
                 T + NODUS_CMT_APP_MAX_EXPIRY_AHEAD + 1, 0xAA) == 0 &&
          h7_env(&e[3], 0x43, H7_KIND_CREATE, T + 1, 0xAA) == 0 &&
          h7_env(&e[4], 0x44, H7_KIND_CREATE,
                 T + NODUS_CMT_APP_MAX_EXPIRY_AHEAD, 0xAA) == 0,
          "envelopes");
    gs = v2x_cmt_genesis_state(fx.w);
    app = calloc(1, sizeof(*app));
    CHECK(gs && app, "genesis document + alloc");
    CHECK(nodus_cmt_app_ledger_init(app, fx.w, &gs->doc) == CMT_OK, "bind");
    for (int k = 0; k < 5; k++) {
        cmt_mem_request_check_tx_t  req;
        cmt_mem_response_check_tx_t res;
        memset(&req, 0, sizeof(req));
        memset(&res, 0, sizeof(res));
        req.tx = e[k].bytes;
        req.tx_len = e[k].len;
        req.type = CMT_MEM_CHECK_TX_TYPE_NEW;
        CHECK(nodus_cmt_app_check_tx(app, &req, &res) == CMT_OK, "served");
        CHECK((res.code == CMT_MEM_CODE_TYPE_OK) == (admit[k] != 0),
              name[k]); OK();
    }
    nodus_cmt_app_ledger_release(app);
    free(app);
    h7_close(&fx);
    return 0;
}

/* ══ 7. generation 4: every verdict and table as before ═════════════ */
static int t_gen4_unchanged(void) {
    h7_fx_t fx;
    static v2x_env_t A, Ap, Z, X, E, Y, W;
    uint8_t wa[64], ia[64], wap[64], iap[64];
    uint32_t codes[8];
    uint32_t code = 0;
    nodus_v2_batch_fail_kind_t kind;
    int fi;
    char why[256];

    CHECK(h7_open(&fx, "gen4", NODUS_RT_GEN_STORAGE, 1) == 0, "gen-4 chain");
    CHECK(h7_gen_is(fx.w, NODUS_RT_GEN_STORAGE) == 0,
          "PREMISE: generation 4"); OK();
    CHECK(h7_env(&A, 1, H7_KIND_CREATE, 6, 0xAA) == 0 &&
          h7_env(&Ap, 1, H7_KIND_CREATE, 6, 0xBB) == 0 &&
          h7_env(&Z, 2, H7_KIND_CREATE, 0, 0xAA) == 0 &&
          h7_env(&X, 3, H7_KIND_CREATE, 1 + NODUS_V2_EXPIRY_WINDOW_BLOCKS + 1,
                 0xAA) == 0 &&
          h7_env(&E, 4, H7_KIND_CREATE, 1, 0xAA) == 0 &&
          h7_env(&Y, 5, H7_KIND_CREATE, 0, 0xAA) == 0 &&
          h7_env(&W, 6, H7_KIND_CREATE, 3 + NODUS_V2_EXPIRY_WINDOW_BLOCKS + 1,
                 0xAA) == 0, "envelopes");
    CHECK(h7_ids(fx.w, &A, wa, ia) == 0 && h7_ids(fx.w, &Ap, wap, iap) == 0,
          "ids");

    /* block 1: A, e = 0 and e = H + 721 all APPLY (no D2 below ROOTS) */
    {
        v2x_env_t *b1[3] = { &A, &Z, &X };
        CHECK(h7_apply(fx.w, 1, b1, 3, codes) == 0 &&
              codes[0] == NODUS_V2_TX_OK && codes[1] == NODUS_V2_TX_OK &&
              codes[2] == NODUS_V2_TX_OK,
              "gen 4: e = 0 and e = H + 721 apply"); OK();
    }
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 0,
          "gen 4: no v2_replay row is written"); OK();

    /* the four callers refuse A / A' through the index tables */
    CHECK(h7_dry(fx.w, &A, &code) == 1 && code == NODUS_V2_TX_ERR_REPLAY &&
          h7_dry(fx.w, &Ap, &code) == 1 && code == NODUS_V2_TX_ERR_REPLAY,
          "gen 4 dry run: REPLAY through the index tables"); OK();
    {
        v2x_env_t *s[2] = { &Y, &Ap };
        CHECK(h7_seam(fx.w, s, 2, &kind, &fi) == -1 &&
              kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID && fi == 1,
              "gen 4 seam: A' ENTRY_INVALID through the index tables"); OK();
    }
    CHECK(h7_admit(fx.w, &A, wa, why, sizeof(why)) == -1 &&
          strstr(why, "intent already committed on this chain") != NULL,
          "gen 4 admission lane: today's intent-index refusal"); OK();

    /* block 2: A, A' REPLAY; e = H - 1 is a FAILED item, not a fault */
    {
        v2x_env_t *b2[3] = { &A, &Ap, &E };
        CHECK(h7_apply(fx.w, 2, b2, 3, codes) == 0,
              "gen 4: block 2 commits"); OK();
        CHECK(codes[0] == NODUS_V2_TX_ERR_REPLAY &&
              codes[1] == NODUS_V2_TX_ERR_REPLAY,
              "gen 4 item loop: REPLAY through the index tables"); OK();
        CHECK(codes[2] == NODUS_V2_TX_ERR_DECODE,
              "gen 4: an expired item is a failed item (DECODE)"); OK();
    }
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_replay") == 0,
          "gen 4: still no v2_replay row"); OK();

    /* the seam at candidate 3: e = 0 and e = H + 721 are accepted */
    {
        v2x_env_t *s[2] = { &Y, &W };
        CHECK(h7_seam(fx.w, s, 2, &kind, &fi) == 0,
              "gen 4 seam: no D2"); OK();
    }
    h7_close(&fx);
    return 0;
}

int main(void) {
    if (t_predicate() != 0) return 1;
    if (t_rows_gen5() != 0) return 1;
    if (t_prune_direct() != 0) return 1;
    if (t_expiry_gen5() != 0) return 1;
    if (t_expiry_gen5_nohf3() != 0) return 1;
    if (t_checktx_gen5() != 0) return 1;
    if (t_gen4_unchanged() != 0) return 1;
    printf("test_hf7_replay: %d checks passed\n", g_checks);
    return 0;
}
