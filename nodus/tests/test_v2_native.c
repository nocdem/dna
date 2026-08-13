/**
 * Nodus — Ledger V2 native-auth season: the PRODUCTION SYSTEM/DNA_CORE
 * runtime vertical slices, driven through the REAL builtin table (no
 * scripted override anywhere in this file).
 *
 * What lives here (the scripted-engine matrix stays in test_v2_exec):
 *
 *   1. AUTH — the verified authorization boundary: valid multi-signer
 *      acceptance; wrong key / malformed key / malformed signature /
 *      unsupported scheme / zero pubkey / disordered signers; binding
 *      of the signed digest to chain, domain, ruleset hash, runtime_op,
 *      call bytes and expiry (each substitution rejects); an
 *      authorization COMMITMENT without verification rejects; no
 *      caller-forged verdict is expressible; the auth-data-malleability
 *      twin (one intent, two tx_ids) cannot double-spend.
 *   2. RUNTIME AUTHORITY — five-axis exact lookup misses per axis;
 *      missing auth/exec hooks fail closed; un-migrated runtime_ops
 *      (CORE 2..6, SYSTEM 1..5) deterministically reject.
 *   3. SYSTEM slice — CHAIN_CONFIG under the capacity-season carrier
 *      v2 (proposal-only call, auth_kind-2 committee approvals):
 *      positive quorum commit + activation semantics + SYSTEM-root
 *      movement + untouched CORE; the committee-approval matrix
 *      (quorum-1 IS reachable now — the old wire floor is retired with
 *      the vote wire — plus duplicate/unsorted/out-of-range seats,
 *      count/framing/truncation/trailing, wrong member, wrong epoch,
 *      wrong set hash, kind-1-no-approvals, allowlist), snapshot
 *      ROTATION, validity-window shape, FRESHNESS, grace, duplicate
 *      (param, effective), INFLATION_START monotonicity, nonzero
 *      fee_amount — rejects digest-proven; CC fault matrix F26/F28/
 *      F34/F13/F14.
 *   4. CORE slice — SPEND: valid transfer + change; multi-input/multi-
 *      owner; exact-value; fee burned exactly once; per-token
 *      conservation; duplicate/missing/spent inputs; wrong owner;
 *      locked input; value mismatch; overflow; duplicate output id;
 *      cross-domain UTXO substitution; supply invariant equality.
 *   5. ENGINE — new fault points 28-33 (digest rollback), exact meter
 *      accounting of the consumed units, restart/replay idempotency,
 *      twin-fixture root determinism.
 *
 * @file test_v2_native.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"   /* carrier v2: learn the
                                        * resolved governing committee  */
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

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

/* ── keys (generated once; both twin fixtures share them) ──────────── */
#define N_KEYS 17                 /* 0..6 committee, 7..15 users (15
                                   * distinct owners = keys 0..14 for
                                   * the max-cardinality SPEND), 16 stray*/
static uint8_t g_pk[N_KEYS][2592];
static uint8_t g_sk[N_KEYS][4896];
static char    g_fp[N_KEYS][129]; /* lowercase hex, NUL-terminated       */
#define K_STRAY (N_KEYS - 1)      /* never seated, never funded          */

static int keys_init(void) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        if (qgp_dsa87_keypair(g_pk[i], g_sk[i]) != 0) return -1;
        uint8_t full[64];
        if (qgp_sha3_512(g_pk[i], 2592, full) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            g_fp[i][2 * b]     = hexd[full[b] >> 4];
            g_fp[i][2 * b + 1] = hexd[full[b] & 0xF];
        }
        g_fp[i][128] = '\0';
    }
    return 0;
}

/* ── fixture (the test_v2_exec shape) ──────────────────────────────── */
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
    uint8_t          chain_id[32];      /* the DERIVED V2 chain id       */
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

static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    mk_id(b->block_id, (uint8_t)(0xB0 + h));
    mk_id(b->prev_block_id, h == 1 ? 0xEE : (uint8_t)(0xB0 + h - 1));
    mk_id(b->vset_hash, 0x77);
    b->envs = envs;
    b->n_envs = n;
}

/* reject with digest-identical rollback proof; reports the rc class */
static int apply_reject(nodus_witness_t *w, nodus_v2_block_t *b,
                        int *rc_out) {
    uint8_t d0[64], d1[64];
    if (db_state_digest(w, d0) != 0) return 1;
    int rc = nodus_witness_v2_apply_block(w, b);
    if (rc_out) *rc_out = rc;
    if (rc != -1 && rc != -2) return 1;
    if (db_state_digest(w, d1) != 0) return 1;
    return memcmp(d0, d1, 64) != 0;
}

/* seed one CORE utxo owned by key k; nullifier = SHA3(fp128 ‖ seed32)
 * — the SOURCE output-identity derivation, so the row is spendable. */
static int seed_utxo(fixture_t *fx, int k, uint64_t amount,
                     uint8_t seed_byte, uint64_t unlock,
                     uint8_t nul_out[64]) {
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
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, ?4, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul_out, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp[k], 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)unlock);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

#define VAL_BOND 1000ULL
#define UTXO_A   5000000ULL
#define UTXO_B   3000000ULL
#define UTXO_C   2000000ULL
#define FEE_MIN  1000000ULL       /* == DNAC_MIN_FEE_RAW == BASE_TX_FEE  */

static uint8_t g_nul_a[64], g_nul_b[64], g_nul_c[64], g_nul_lock[64];

/* full fixture, GENERALIZED over the validator set (capacity season):
 * schema v7 + nval-validator committee from a caller key table +
 * funded CORE state + V2 genesis over the PRODUCTION builtin table.
 * For nval != 7 a TARGET_ACTIVE_COUNT chain-config row (param 4,
 * effective 0) is committed BEFORE genesis, so the committee target
 * derivation (committee_target_for_epoch) resolves nval — the SOURCE
 * path, not a test shortcut. */
static uint8_t g_gid_fill = 0xEE;   /* genesis id fill — the cross-chain
                                     * intent test overrides it to build
                                     * a fixture on a DIFFERENT chain    */

static int fx_genesis_n(fixture_t *fx, const char *tag,
                        const uint8_t (*vkeys)[2592], int nval) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    /* the live constructor's cache sentinel (nodus_witness.c:649) — a
     * zeroed struct would otherwise read as a CACHED EMPTY committee
     * for epoch 0 */
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_native_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0)
        return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s8(fx->w) != 0) return -1;

    if (nval != 7) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO chain_config_history (param_id, new_value, "
                 "effective_block, commit_block, tx_hash, proposal_nonce, "
                 "created_at_unix) VALUES (4, %d, 0, 0, zeroblob(64), "
                 "1, 0)", nval);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }

    /* nval ACTIVE validators = the bootstrap committee */
    for (int i = 0; i < nval; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, vkeys[i], 2592);
        v.self_stake = VAL_BOND;
        v.status = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    /* funded supply: genesis == Σutxo + Σbonds (CORE invariant) */
    {
        uint64_t supply = UTXO_A + UTXO_B + UTXO_C +
                          (uint64_t)nval * VAL_BOND;
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence) VALUES (1, %llu, 0, 0, "
                 "%llu, zeroblob(64), 0)",
                 (unsigned long long)supply,
                 (unsigned long long)supply);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    if (seed_utxo(fx, 7, UTXO_A, 0xA1, 0, g_nul_a) != 0) return -1;
    if (seed_utxo(fx, 7, UTXO_B, 0xA2, 0, g_nul_b) != 0) return -1;
    if (seed_utxo(fx, 8, UTXO_C, 0xC1, 0, g_nul_c) != 0) return -1;

    uint8_t gid[64], vset[64];
    mk_id(gid, g_gid_fill);
    mk_id(vset, 0x77);
    if (nodus_witness_v2_genesis(fx->w, gid, vset, 0) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;
    return 0;
}

static int fx_genesis(fixture_t *fx, const char *tag) {
    return fx_genesis_n(fx, tag, (const uint8_t (*)[2592])g_pk, 7);
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
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

/* ── envelope builders with REAL signatures ─────────────────────────── */

/* Standard-shape envelope buffer — NOT the 1 MiB V2 ceiling (capacity
 * season): sizing every test envelope to DNA_ENV_MAX_TOTAL_LEN would
 * put megabyte objects on test stacks. The ceiling-shape tests
 * heap-allocate their own buffers. 128 KiB covers every standard shape
 * here (largest: 7-committee all-N CC ≈ 40 KiB; 15-owner SPEND ≈
 * 113 KiB). */
#define NATIVE_ENV_BUF 131072u

typedef struct {
    uint8_t bytes[NATIVE_ENV_BUF];
    size_t  len;
} env_t;

/* what-was-signed overrides (binding-substitution matrix). Every field
 * 0/NULL = sign the envelope's real derived digest. */
typedef struct {
    const uint8_t *chain_id;      /* sign against another chain          */
    uint32_t domain_id;           /* nonzero = sign for another domain   */
    uint32_t runtime_op;          /* nonzero = sign for another op       */
    const uint8_t *ruleset_hash;  /* sign against another ruleset hash   */
    uint64_t expiry_delta;        /* nonzero = sign a shifted expiry     */
    int call_flip;                /* nonzero = sign over flipped call    */
    int garbage_auth;             /* auth_data = garbage, skip signing   */
    int break_sig;                /* flip one signature byte post-sign   */
    int break_key;                /* flip one pubkey byte post-sign      */
    int zero_key;                 /* zero the first pubkey               */
    int swap_order;               /* emit signers in DESCENDING order    */
    uint8_t auth_kind;            /* nonzero = override auth_kind        */
    uint8_t sig_extra;            /* XOR into first sig byte of signer 0
                                   * AFTER signing (malleability twin:
                                   * invalidates nothing if 0)           */
    int sign_with;                /* >0: sign with THIS key index instead
                                   * of the declared pubkeys' keys
                                   * (0 = no override)                   */
} sign_opt_t;

/* Build + sign a one-leg envelope. `signers` are key indices; pubkeys
 * are emitted in ascending pubkey order (the canonical form) unless
 * opts->swap_order. */
static int env_build_signed(fixture_t *fx, env_t *e,
                            uint32_t domain_id, uint32_t runtime_op,
                            const uint8_t *call, uint32_t call_len,
                            uint64_t fee, uint64_t expiry,
                            uint32_t max_effects, uint32_t max_effect_bytes,
                            const int *signers, int n_signers,
                            const sign_opt_t *opt_in) {
    sign_opt_t o;
    memset(&o, 0, sizeof(o));
    if (opt_in) o = *opt_in;

    if (n_signers < 1 || n_signers > 15) return -1;   /* scheme cap 15 */
    uint32_t auth_len = 1 + (uint32_t)n_signers * 7219u;
    uint8_t *auth = calloc(1, auth_len);
    if (!auth) return -1;

    /* ascending-pubkey signer order (canonical) */
    int ord[15];
    for (int i = 0; i < n_signers; i++) ord[i] = signers[i];
    for (int a = 1; a < n_signers; a++)
        for (int b = a; b > 0 &&
             memcmp(g_pk[ord[b - 1]], g_pk[ord[b]], 2592) > 0; b--) {
            int t = ord[b];
            ord[b] = ord[b - 1];
            ord[b - 1] = t;
        }
    if (o.swap_order && n_signers >= 2) {   /* descending = non-canonical */
        for (int i = 0; i < n_signers / 2; i++) {
            int t = ord[i];
            ord[i] = ord[n_signers - 1 - i];
            ord[n_signers - 1 - i] = t;
        }
    }

    /* the envelope (auth zeroed for now; lengths already final) */
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = domain_id;
    leg.hdr.runtime_op = runtime_op;
    /* the committed ruleset version, DERIVED from the compiled table
     * (burn season: SYSTEM v2 AND CORE v2) */
    {
        size_t rn = 0;
        const nodus_domain_runtime_t *rt = nodus_runtime_builtin_table(&rn);
        leg.hdr.ruleset_version = domain_id == DNA_DOMAIN_SYSTEM
                                      ? rt[0].ruleset_version
                                      : rt[1].ruleset_version;
    }
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = o.auth_kind ? o.auth_kind : 1;
    leg.hdr.call_len = call_len;
    leg.hdr.auth_len = auth_len;
    leg.hdr.res_max_effects = max_effects;
    leg.hdr.res_max_effect_bytes = max_effect_bytes;
    leg.call_data = call;
    leg.auth_data = auth;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height = expiry;
    in.fee_amount = fee;
    in.res_max_total_units = 200000;
    in.leg_count = 1;
    in.legs = &leg;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0) {
        free(auth);
        return -1;
    }

    /* derive WHAT IS SIGNED — from the envelope, or from the mutated
     * parameters (binding-substitution tests sign a digest for a
     * DIFFERENT context; the engine then derives the real one and every
     * signature must fail) */
    dna_env_view_t v;
    if (dna_env_decode(e->bytes, e->len, &v) != 0) { free(auth); return -1; }
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    const uint8_t *rs_hash =
        domain_id == DNA_DOMAIN_SYSTEM ? t[0].ruleset_hash
                                       : t[1].ruleset_hash;
    if (o.ruleset_hash) rs_hash = o.ruleset_hash;
    const uint8_t *chain = o.chain_id ? o.chain_id : fx->chain_id;

    uint8_t call_commit[64], acc[64], digest[64];
    if (o.call_flip || o.expiry_delta) {
        /* rebuild a TWIN view over mutated bytes and commit over那 —
         * only the signed digest moves, the emitted envelope stays */
        static uint8_t twin[NATIVE_ENV_BUF];
        memcpy(twin, e->bytes, e->len);
        if (o.call_flip) twin[v.call_off[0]] ^= 0x01;
        if (o.expiry_delta) {
            uint64_t ex = expiry + o.expiry_delta;
            for (int i = 0; i < 8; i++)
                twin[17 + i] = (uint8_t)(ex >> (56 - 8 * i));
        }
        dna_env_view_t tv;
        if (dna_env_decode(twin, e->len, &tv) != 0) { free(auth); return -1; }
        if (dna_env_call_commit(&tv, 0, rs_hash, call_commit) != 0 ||
            dna_env_auth_context_commit(&tv, chain,
                (const uint8_t (*)[64])call_commit, acc) != 0) {
            free(auth);
            return -1;
        }
    } else {
        if (dna_env_call_commit(&v, 0, rs_hash, call_commit) != 0 ||
            dna_env_auth_context_commit(&v, chain,
                (const uint8_t (*)[64])call_commit, acc) != 0) {
            free(auth);
            return -1;
        }
    }
    uint32_t dig_domain = o.domain_id ? o.domain_id : domain_id;
    uint32_t dig_op = o.runtime_op ? o.runtime_op : runtime_op;
    if (dna_env_auth_digest(acc, 0, dig_domain, dig_op, digest) != 0) {
        free(auth);
        return -1;
    }

    /* fill auth_data */
    auth[0] = (uint8_t)n_signers;
    for (int i = 0; i < n_signers; i++) {
        uint8_t *slot = auth + 1 + (size_t)i * 7219;
        memcpy(slot, g_pk[ord[i]], 2592);
        if (!o.garbage_auth) {
            size_t siglen = 4627;
            int sk = o.sign_with > 0 ? o.sign_with : ord[i];
            if (qgp_dsa87_sign(slot + 2592, &siglen, digest, 64,
                               g_sk[sk]) != 0 || siglen != 4627) {
                free(auth);
                return -1;
            }
        } else {
            memset(slot + 2592, 0xDD, 4627);
        }
    }
    if (o.break_sig) auth[1 + 2592] ^= 0x01;
    if (o.break_key) auth[1] ^= 0x01;
    if (o.zero_key) memset(auth + 1, 0, 2592);
    if (o.sig_extra) auth[1 + 2592] ^= o.sig_extra;

    /* re-encode with the real auth bytes (same lengths → same commits) */
    leg.auth_data = auth;
    int rc = dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len);
    free(auth);
    return rc;
}

/* SPEND call v1 builder */
typedef struct {
    int      owner;               /* key index for the fp                */
    uint64_t amount;
    uint8_t  seed_byte;
    const uint8_t *token;         /* NULL = native                        */
} out_spec_t;

/* `ins_v` is really `const uint8_t (*)[64]` — taken as const void* so
 * every call site can hand a non-const array without the pre-C2X
 * pedantic qualifier diagnostic (strict-C11 gate). */
static uint32_t spend_call_build(uint8_t *dst, size_t cap,
                                 const void *ins_v, int n_in,
                                 const out_spec_t *outs, int n_out) {
    const uint8_t (*ins)[64] = (const uint8_t (*)[64])ins_v;
    size_t need = 2 + (size_t)n_in * 64 + (size_t)n_out * 232;
    if (need > cap) return 0;
    dst[0] = (uint8_t)n_in;
    /* ascending input order (canonical) */
    const uint8_t *ptr[16];
    for (int i = 0; i < n_in; i++) ptr[i] = ins[i];
    for (int a = 1; a < n_in; a++)
        for (int b = a; b > 0 && memcmp(ptr[b - 1], ptr[b], 64) > 0; b--) {
            const uint8_t *t = ptr[b];
            ptr[b] = ptr[b - 1];
            ptr[b - 1] = t;
        }
    size_t off = 1;
    for (int i = 0; i < n_in; i++, off += 64)
        memcpy(dst + off, ptr[i], 64);
    dst[off++] = (uint8_t)n_out;
    for (int o = 0; o < n_out; o++) {
        memcpy(dst + off, g_fp[outs[o].owner], 128);
        for (int i = 0; i < 8; i++)
            dst[off + 128 + i] = (uint8_t)(outs[o].amount >> (56 - 8 * i));
        if (outs[o].token) memcpy(dst + off + 136, outs[o].token, 64);
        else memset(dst + off + 136, 0, 64);
        memset(dst + off + 200, outs[o].seed_byte, 32);
        off += 232;
    }
    return (uint32_t)off;
}

/* derived output nullifier for later spends */
static int out_nul(int owner, uint8_t seed_byte, uint8_t nul[64]) {
    uint8_t pre[160];
    memcpy(pre, g_fp[owner], 128);
    memset(pre + 128, seed_byte, 32);
    return qgp_sha3_512(pre, sizeof(pre), nul);
}

/* ── CHAIN_CONFIG carrier v2 machinery (capacity season) ──────────────
 * call v2 = the 41-byte PROPOSAL; committee approvals ride auth_kind 2:
 *   submitter_count u8 ‖ submitters × (pk ‖ sig)
 *   ‖ approval_count u16 BE ‖ approvals × (seat u16 BE ‖ sig)
 * The test LEARNS the resolved committee from the same authority the
 * engine consults (nodus_committee_get_for_block at H-1), then signs
 * every approval digest INDEPENDENTLY (its own preimage constants would
 * defeat the purpose — it calls the exported helpers, which the oracle
 * side of the season pins). */

/* proposal-only call v2 */
static uint32_t cc_call_build(uint8_t *dst, size_t cap, uint8_t param,
                              uint64_t new_value, uint64_t effective,
                              uint64_t nonce, uint64_t signed_at,
                              uint64_t valid_before) {
    if (cap < 41) return 0;
    dst[0] = param;
    uint64_t vals[5] = { new_value, effective, nonce, signed_at,
                         valid_before };
    for (int f = 0; f < 5; f++)
        for (int i = 0; i < 8; i++)
            dst[1 + f * 8 + i] = (uint8_t)(vals[f] >> (56 - 8 * i));
    return 41;
}

/* the learned governing committee (engine authority, test-side view) */
typedef struct {
    uint32_t count;
    uint64_t epoch;
    uint8_t  set_hash[64];
    /* seat index of each of a caller-supplied key table (-1 unseated) */
    int      seat_of[256];
    nodus_committee_member_t *mem;      /* calloc'd, caller frees        */
} cc_view_t;

static int cc_learn(fixture_t *fx, uint64_t exec_h,
                    const uint8_t (*keys)[2592], int n_keys,
                    cc_view_t *v) {
    memset(v, 0, sizeof(*v));
    for (int i = 0; i < 256; i++) v->seat_of[i] = -1;
    int count = 0;
    if (exec_h == 0) return -1;
    if (nodus_committee_get_for_block_alloc(fx->w, exec_h - 1, &v->mem,
                                            &count) != 0 || count <= 0)
        return -1;
    v->count = (uint32_t)count;
    v->epoch = nodus_v2_epoch_for_height(exec_h - 1);
    uint8_t (*fps)[64] = calloc((size_t)count, 64);
    if (!fps) return -1;
    for (int i = 0; i < count; i++) {
        if (qgp_sha3_512(v->mem[i].pubkey, 2592, fps[i]) != 0) {
            free(fps);
            return -1;
        }
        for (int k = 0; k < n_keys && k < 256; k++)
            if (memcmp(v->mem[i].pubkey, keys[k], 2592) == 0)
                v->seat_of[k] = i;
    }
    int rc = nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                         v->count, v->set_hash);
    free(fps);
    return rc;
}

/* corruption knobs for the approval section */
typedef struct {
    int      bad_sig_at;      /* approval slot to bit-flip, -1 = none    */
    int      dup_seat;        /* slot1 gets slot0's seat (duplicate)     */
    int      unsorted;        /* emit approvals in DESCENDING seat order */
    int      seat_override;   /* >=0: force slot0's WIRE seat to this    */
    int64_t  epoch_delta;     /* sign for epoch + delta                  */
    int      set_hash_flip;   /* sign against a bit-flipped set hash     */
    int      trailing_byte;   /* append one byte after the last approval */
    int      truncate;        /* drop the last byte                      */
    int      count_delta;     /* add to the DECLARED approval count      */
    int      sign_with;       /* >0: sign every approval with THIS key   */
} cc_opt_t;

/* Build a SYSTEM CHAIN_CONFIG envelope under carrier v2 into an
 * arbitrary buffer (heap for the ceiling shapes). voters = KEY indices
 * into `keys`/`sks`; the submitter is always keys[submitter_key].
 * `so` mutates what the leg digest is derived over (the kind-1 test
 * machinery, reused verbatim so the whole substitution matrix applies
 * to approvals too). */
static int cc_build(fixture_t *fx, uint8_t *buf, size_t cap, size_t *len,
                    uint64_t exec_h,
                    const uint8_t (*keys)[2592],
                    const uint8_t (*sks)[4896], int n_keys,
                    int submitter_key,
                    uint8_t param, uint64_t new_value, uint64_t effective,
                    uint64_t nonce, uint64_t signed_at,
                    uint64_t valid_before, uint64_t fee,
                    uint64_t res_ceiling,
                    const int *voters, int n_votes,
                    const cc_opt_t *cc_in, const sign_opt_t *so_in) {
    cc_opt_t co;
    sign_opt_t so;
    memset(&co, 0, sizeof(co));
    co.bad_sig_at = -1;
    co.seat_override = -1;
    if (cc_in) co = *cc_in;
    memset(&so, 0, sizeof(so));
    if (so_in) so = *so_in;

    cc_view_t cv;
    if (cc_learn(fx, exec_h, keys, n_keys, &cv) != 0) return -1;

    uint8_t call[41];
    if (cc_call_build(call, sizeof(call), param, new_value, effective,
                      nonce, signed_at, valid_before) != 41) {
        free(cv.mem);
        return -1;
    }

    /* seats of the voters, ascending (canonical), then options */
    int seats[256];
    if (n_votes < 1 || n_votes > 200) { free(cv.mem); return -1; }
    for (int i = 0; i < n_votes; i++) {
        seats[i] = cv.seat_of[voters[i]];
        if (seats[i] < 0) { free(cv.mem); return -1; }  /* unseated key */
    }
    for (int a = 1; a < n_votes; a++)
        for (int b2 = a; b2 > 0 && seats[b2 - 1] > seats[b2]; b2--) {
            int t = seats[b2];
            seats[b2] = seats[b2 - 1];
            seats[b2 - 1] = t;
        }
    if (co.dup_seat && n_votes >= 2) seats[1] = seats[0];
    if (co.unsorted && n_votes >= 2) {
        int t = seats[0];
        seats[0] = seats[n_votes - 1];
        seats[n_votes - 1] = t;
    }
    /* override lands on the LAST slot so ascending order stays intact —
     * the range violation is then not entangled with the ordering rule
     * (review finding 1b). The zero-signature residue on an unmapped
     * seat is STRUCTURAL: no key owns a seat outside the snapshot, so a
     * "valid signature for an out-of-range seat" cannot exist — range
     * gate and signature verify are deliberately co-sufficient
     * (defense in depth), and the range gate fires first. */
    if (co.seat_override >= 0) seats[n_votes - 1] = co.seat_override;

    uint32_t declared = (uint32_t)((int)n_votes + co.count_delta);
    /* the FULL canonical layout is always materialised; truncate /
     * trailing mutate only the DECLARED length (the encoder copies
     * auth_len bytes of the oversized buffer, so no writer can overrun
     * a shortened allocation) */
    uint32_t full_len = 1 + 7219u              /* one submitter          */
                        + 2 + (uint32_t)n_votes * 4629u;
    uint32_t auth_len = full_len;
    if (co.trailing_byte) auth_len += 1;
    if (co.truncate) auth_len -= 1;

    uint8_t *auth = calloc(1, (size_t)full_len + 1);
    if (!auth) { free(cv.mem); return -1; }

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version = 2;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = so.auth_kind ? so.auth_kind : 2;
    leg.hdr.call_len = 41;
    leg.hdr.auth_len = auth_len;
    leg.hdr.res_max_effects = 4;
    leg.hdr.res_max_effect_bytes = 2048;
    leg.call_data = call;
    leg.auth_data = auth;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = fee;
    in.res_max_total_units = res_ceiling;
    in.leg_count = 1;
    in.legs = &leg;
    if (dna_env_encode(&in, buf, cap, len) != 0) {
        free(auth);
        free(cv.mem);
        return -1;
    }

    /* the LEG digest (what the submitter signs and what every approval
     * hangs from) — with the sign_opt substitutions applied, exactly
     * like env_build_signed */
    dna_env_view_t v;
    if (dna_env_decode(buf, *len, &v) != 0) { free(auth); free(cv.mem);
                                              return -1; }
    size_t bn = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&bn);
    const uint8_t *rs_hash = so.ruleset_hash ? so.ruleset_hash
                                             : bt[0].ruleset_hash;
    const uint8_t *chain = so.chain_id ? so.chain_id : fx->chain_id;
    uint8_t call_commit[64], acc[64], digest[64];
    if (so.call_flip) {
        static uint8_t twin[NATIVE_ENV_BUF];
        if (*len > sizeof(twin)) { free(auth); free(cv.mem); return -1; }
        memcpy(twin, buf, *len);
        twin[v.call_off[0]] ^= 0x01;
        dna_env_view_t tv;
        if (dna_env_decode(twin, *len, &tv) != 0 ||
            dna_env_call_commit(&tv, 0, rs_hash, call_commit) != 0 ||
            dna_env_auth_context_commit(&tv, chain,
                (const uint8_t (*)[64])call_commit, acc) != 0) {
            free(auth); free(cv.mem);
            return -1;
        }
    } else if (dna_env_call_commit(&v, 0, rs_hash, call_commit) != 0 ||
               dna_env_auth_context_commit(&v, chain,
                   (const uint8_t (*)[64])call_commit, acc) != 0) {
        free(auth); free(cv.mem);
        return -1;
    }
    if (dna_env_auth_digest(acc, 0, DNA_DOMAIN_SYSTEM,
                            DNA_SYSRULE_CHAIN_CONFIG, digest) != 0) {
        free(auth); free(cv.mem);
        return -1;
    }

    /* submitter section */
    auth[0] = 1;
    memcpy(auth + 1, keys[submitter_key], 2592);
    {
        size_t siglen = 4627;
        if (qgp_dsa87_sign(auth + 1 + 2592, &siglen, digest, 64,
                           sks[submitter_key]) != 0 || siglen != 4627) {
            free(auth); free(cv.mem);
            return -1;
        }
    }
    /* approval section */
    {
        uint8_t *ap = auth + 1 + 7219;
        ap[0] = (uint8_t)(declared >> 8);
        ap[1] = (uint8_t)declared;
        uint8_t sh[64];
        memcpy(sh, cv.set_hash, 64);
        if (co.set_hash_flip) sh[0] ^= 0x01;
        uint64_t ep = (uint64_t)((int64_t)cv.epoch + co.epoch_delta);
        for (int i = 0; i < n_votes; i++) {
            uint8_t *slot = ap + 2 + (size_t)i * 4629;
            /* the WIRE seat (post-options); the SIGNING seat is the
             * same value — a wrong wire seat therefore also signs for
             * that wrong seat, and dies on membership/verify */
            uint16_t seat = (uint16_t)seats[i];
            slot[0] = (uint8_t)(seat >> 8);
            slot[1] = (uint8_t)seat;
            uint8_t adig[64];
            if (nodus_rt_cc_approval_digest(digest, sh, ep, seat,
                                            adig) != 0) {
                free(auth); free(cv.mem);
                return -1;
            }
            /* sign with the key that OWNS the seat (learned), unless
             * overridden */
            int signer_key = co.sign_with > 0 ? co.sign_with : -1;
            if (signer_key < 0) {
                for (int k = 0; k < n_keys; k++)
                    if (cv.seat_of[k] == (int)seat) { signer_key = k;
                                                      break; }
            }
            if (signer_key < 0) {
                /* a seat no test key owns (override outside the map):
                 * leave the zero signature — it cannot verify anyway */
                continue;
            }
            size_t siglen = 4627;
            if (qgp_dsa87_sign(slot + 2, &siglen, adig, 64,
                               sks[signer_key]) != 0 || siglen != 4627) {
                free(auth); free(cv.mem);
                return -1;
            }
            if (co.bad_sig_at == i) slot[2] ^= 0x01;
        }
    }

    /* re-encode with the real auth bytes (same lengths, same commits) */
    leg.auth_data = auth;
    int rc = dna_env_encode(&in, buf, cap, len);
    free(auth);
    free(cv.mem);
    return rc;
}

static int spend_env(fixture_t *fx, env_t *e,
                     const void *ins, int n_in,
                     const out_spec_t *outs, int n_out, uint64_t fee,
                     const int *signers, int n_signers,
                     const sign_opt_t *opt) {
    static uint8_t call[8192];
    uint32_t cl = spend_call_build(call, sizeof(call), ins, n_in, outs,
                                   n_out);
    if (!cl) return -1;
    return env_build_signed(fx, e, DNA_DOMAIN_CORE, DNA_CORERULE_SPEND,
                            call, cl, fee, 0, 40, 16384, signers,
                            n_signers, opt);
}

/* standard-fixture convenience wrapper (7-committee, submitter key 0) */
static int cc_env(fixture_t *fx, env_t *e, uint64_t exec_h,
                  uint8_t param, uint64_t value, uint64_t effective,
                  uint64_t nonce, uint64_t signed_at,
                  uint64_t valid_before, const int *voters, int n_votes,
                  uint64_t fee, const cc_opt_t *co,
                  const sign_opt_t *so) {
    return cc_build(fx, e->bytes, sizeof(e->bytes), &e->len, exec_h,
                    (const uint8_t (*)[2592])g_pk,
                    (const uint8_t (*)[4896])g_sk, N_KEYS, 0,
                    param, value, effective, nonce, signed_at,
                    valid_before, fee, 200000, voters, n_votes, co, so);
}

/* current head root of a domain */
static int head_root(nodus_witness_t *w, uint32_t dom, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT head FROM v2_domain_heads WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    int rc = sqlite3_step(st);
    int ok = -1;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 89) {
        memcpy(out, (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

/* the CORE-side conservation identity, read straight from the tables */
static int supply_identity_holds(nodus_witness_t *w) {
    uint64_t g = q1(w, "SELECT genesis_supply FROM supply_tracking");
    uint64_t m = q1(w, "SELECT total_minted FROM supply_tracking");
    uint64_t bu = q1(w, "SELECT total_burned FROM supply_tracking");
    uint64_t ux = q1(w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set "
                        "WHERE token_id = zeroblob(64)");
    uint64_t bo = q1(w, "SELECT COALESCE(SUM(self_stake),0) FROM validators");
    if (g == UINT64_MAX || m == UINT64_MAX || bu == UINT64_MAX ||
        ux == UINT64_MAX || bo == UINT64_MAX)
        return 0;
    return g + m - bu == ux + bo;
}

/* ══ 1. AUTH — the verified boundary ═══════════════════════════════ */

static int test_auth(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "auth") == 0, "genesis");
    int s7[1] = { 7 };
    out_spec_t outs[2] = {
        { 8, 2000000, 0x01, NULL },      /* to user 8                    */
        { 7, 2000000, 0x02, NULL }       /* change to user 7             */
    };
    uint8_t ins[1][64];
    memcpy(ins[0], g_nul_a, 64);
    env_t e;
    nodus_v2_block_t b;
    nodus_v2_envelope_t ve;

    /* the substitution matrix: everything the digest binds, mutated at
     * SIGNING time, must invalidate the engine-verified signature */
    struct { const char *name; sign_opt_t o; } neg[12];
    memset(neg, 0, sizeof(neg));
    neg[0].name = "wrong key (signature by another keypair)";
    neg[0].o.sign_with = 9;
    neg[1].name = "malformed signature (bit flip)";
    neg[1].o.break_sig = 1;
    neg[2].name = "malformed key (bit flip after signing)";
    neg[2].o.break_key = 1;
    neg[3].name = "auth kind outside CORE's allowlist (kind 2)";
    neg[3].o.auth_kind = 2;       /* capacity season: kind 2 EXISTS but
                                   * only SYSTEM declares it — a CORE
                                   * leg carrying it dies at admission  */
    neg[4].name = "zero pubkey";
    neg[4].o.zero_key = 1;
    neg[5].name = "commitment without verification (garbage auth)";
    neg[5].o.garbage_auth = 1;
    static uint8_t other_chain[32];
    memset(other_chain, 0x99, 32);
    neg[6].name = "cross-chain replay (signed for another chain)";
    neg[6].o.chain_id = other_chain;
    neg[7].name = "cross-domain replay (signed for another domain)";
    neg[7].o.domain_id = 99;      /* any domain but the leg's own —
                                   * 0 (SYSTEM) is the no-override
                                   * sentinel of this test helper, and
                                   * the digest binds the numeric id,
                                   * so 99 proves the same binding      */
    neg[8].name = "runtime-op substitution (signed for BURN)";
    neg[8].o.runtime_op = DNA_CORERULE_BURN;
    static uint8_t other_rs[64];
    memset(other_rs, 0x55, 64);
    neg[9].name = "cross-ruleset replay (signed for another hash)";
    neg[9].o.ruleset_hash = other_rs;
    neg[10].name = "call-byte substitution (signed over flipped call)";
    neg[10].o.call_flip = 1;
    neg[11].name = "expiry substitution (signed over shifted expiry)";
    neg[11].o.expiry_delta = 7;

    for (int i = 0; i < 12; i++) {
        CHECK(spend_env(&fx, &e, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        &neg[i].o) == 0, "build");
        ve.env_bytes = e.bytes;
        ve.env_len = e.len;
        mk_block(&b, 1, &ve, 1);
        int rc = 0;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1, neg[i].name);
        OK();
    }

    /* disordered multi-signer rejects; canonical order verifies */
    {
        int s78[2] = { 7, 8 };
        uint8_t ins2[2][64];
        memcpy(ins2[0], g_nul_b, 64);
        memcpy(ins2[1], g_nul_c, 64);
        out_spec_t o1[1] = { { 7, 4000000, 0x03, NULL } };
        sign_opt_t so;
        memset(&so, 0, sizeof(so));
        so.sign_with = -1;
        so.swap_order = 1;
        CHECK(spend_env(&fx, &e, ins2, 2, o1, 1, FEE_MIN, s78, 2, &so)
                  == 0, "build");
        ve.env_bytes = e.bytes;
        ve.env_len = e.len;
        mk_block(&b, 1, &ve, 1);
        int rc = 0;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "disordered signers must reject");
        OK();
    }

    /* the POSITIVE control: canonical single-signer spend commits */
    CHECK(spend_env(&fx, &e, ins, 1, outs, 2, FEE_MIN, s7, 1, NULL) == 0,
          "build");
    ve.env_bytes = e.bytes;
    ve.env_len = e.len;
    mk_block(&b, 1, &ve, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
          "valid authorization must commit");
    OK();

    /* AUTH-DATA MALLEABILITY TWIN (CLOSED by the intent season):
     * Dilithium signing is randomized, so re-signing the SAME intent
     * yields a second envelope with a DIFFERENT wire_id. It must not
     * double-spend — and BOTH guards would now kill it: the committed-
     * intent replay guard (fires first, pre-BEGIN) and the spent-input
     * guard (the first commit consumed the inputs). This is the season's
     * "SPEND replay where both guards would reject" case. */
    {
        env_t twin;
        CHECK(spend_env(&fx, &twin, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "twin build");
        CHECK(twin.len == e.len, "twin shape");
        CHECK(memcmp(twin.bytes, e.bytes, e.len) != 0,
              "randomized signing must produce a distinct envelope");
        nodus_v2_envelope_t vt = { twin.bytes, twin.len };
        nodus_v2_block_t b2;
        mk_block(&b2, 2, &vt, 1);       /* prev links to block 1        */
        int rc = 0;
        CHECK(apply_reject(fx.w, &b2, &rc) == 0 && rc == -1,
              "malleability twin must not double-spend");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ══ 2. RUNTIME AUTHORITY ══════════════════════════════════════════ */

static int test_authority(void) {
    /* five-axis exact lookup: each axis mismatch misses */
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    CHECK(t && n == 2, "table");
    const nodus_domain_runtime_t *core = &t[1];
    CHECK(nodus_runtime_lookup_in(t, n, core->domain_id,
              core->runtime_kind, core->runtime_abi,
              core->ruleset_version, core->ruleset_hash) == core,
          "exact tuple resolves");
    OK();
    uint8_t bad[64];
    memcpy(bad, core->ruleset_hash, 64);
    bad[0] ^= 1;
    CHECK(nodus_runtime_lookup_in(t, n, 99, core->runtime_kind,
              core->runtime_abi, 1, core->ruleset_hash) == NULL,
          "wrong domain");
    CHECK(nodus_runtime_lookup_in(t, n, core->domain_id, 9,
              core->runtime_abi, 1, core->ruleset_hash) == NULL,
          "wrong kind");
    CHECK(nodus_runtime_lookup_in(t, n, core->domain_id,
              core->runtime_kind, 9, 1, core->ruleset_hash) == NULL,
          "wrong abi");
    CHECK(nodus_runtime_lookup_in(t, n, core->domain_id,
              core->runtime_kind, core->runtime_abi, 9,
              core->ruleset_hash) == NULL,
          "wrong version");
    CHECK(nodus_runtime_lookup_in(t, n, core->domain_id,
              core->runtime_kind, core->runtime_abi, 1, bad) == NULL,
          "wrong hash (no fallback, no closest match)");
    OK();

    /* missing hooks fail closed at admission (table copy, same tuple) */
    fixture_t fx;
    CHECK(fx_genesis(&fx, "authy") == 0, "genesis");
    static nodus_domain_runtime_t noexec[2], noauth[2];
    memcpy(noexec, t, sizeof(noexec));
    memcpy(noauth, t, sizeof(noauth));
    noexec[1].exec = NULL;
    noauth[1].auth = NULL;
    int s7[1] = { 7 };
    uint8_t ins[1][64];
    memcpy(ins[0], g_nul_a, 64);
    out_spec_t outs[1] = { { 8, 4000000, 0x01, NULL } };
    env_t e;
    CHECK(spend_env(&fx, &e, ins, 1, outs, 1, FEE_MIN, s7, 1, NULL) == 0,
          "build");
    nodus_v2_envelope_t ve = { e.bytes, e.len };
    nodus_v2_block_t b;
    fx.w->v2_runtime_table = noexec;
    fx.w->v2_runtime_table_n = 2;
    mk_block(&b, 1, &ve, 1);
    int rc = 0;
    CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
          "missing exec hook fails closed");
    OK();
    fx.w->v2_runtime_table = noauth;
    mk_block(&b, 1, &ve, 1);
    CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
          "missing auth hook fails closed");
    OK();
    fx.w->v2_runtime_table = NULL;      /* back to the builtin table    */
    fx.w->v2_runtime_table_n = 0;

    /* un-migrated runtime_ops deterministically reject (owned but not
     * yet implemented — incl. the SHIELDED/SHIELD/UNSHIELD rule ids, so
     * types 11/12/13 stay dead through this lane too) */
    for (uint32_t op = 2; op <= 6; op++) {
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE, op,
                               (const uint8_t *)"x", 1, FEE_MIN, 0, 4,
                               1024, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vo = { e.bytes, e.len };
        mk_block(&b, 1, &vo, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "un-migrated CORE op must reject");
    }
    OK();
    for (uint32_t op = 1; op <= 5; op++) {
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_SYSTEM, op,
                               (const uint8_t *)"x", 1, 0, 0, 4,
                               1024, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vo = { e.bytes, e.len };
        mk_block(&b, 1, &vo, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "un-migrated SYSTEM op must reject");
    }
    OK();
    fx_close(&fx);
    return 0;
}

/* ══ 3. SYSTEM slice — CHAIN_CONFIG ════════════════════════════════ */

static int test_system_cc(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "cc") == 0, "genesis");
    int voters5[5] = { 0, 1, 2, 3, 4 };
    int voters4[4] = { 0, 1, 2, 3 };
    int voters7[7] = { 0, 1, 2, 3, 4, 5, 6 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;

    uint8_t sys_r0[64], core_r0[64];
    CHECK(head_root(fx.w, 0, sys_r0) == 0 &&
          head_root(fx.w, 1, core_r0) == 0, "roots");

    /* ── scalar/economic negatives (call rules, unchanged authority) ── */
    {
        struct {
            const char *name;
            uint64_t eff, vb, fee;
        } sneg[3] = {
            { "validity-window shape (valid_before <= effective)",
              1000, 0, 0 },              /* vb=0 dies at the SCALAR
                                          * window rule; the real
                                          * freshness gate runs at H=3  */
            { "grace violation (effective too soon)", 100, 2000, 0 },
            { "nonzero fee on a SYSTEM leg", 1000, 2000, FEE_MIN },
        };
        for (int i = 0; i < 3; i++) {
            CHECK(cc_env(&fx, &e, 1, 1, 5, sneg[i].eff, 0x42, 1,
                         sneg[i].vb, voters5, 5, sneg[i].fee, NULL,
                         NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  sneg[i].name);
            OK();
        }
    }

    /* ── the COMMITTEE-APPROVAL matrix (carrier v2) ─────────────────── */
    {
        struct {
            const char *name;
            const int *voters; int nv;
            cc_opt_t co;
            sign_opt_t so;
        } cneg[14];
        memset(cneg, 0, sizeof(cneg));
        for (int i = 0; i < 14; i++) {
            cneg[i].voters = voters5;
            cneg[i].nv = 5;
            cneg[i].co.bad_sig_at = -1;
            cneg[i].co.seat_override = -1;
        }
        cneg[0].name = "quorum minus one (4 of 7)";
        cneg[0].voters = voters4; cneg[0].nv = 4;
        cneg[1].name = "bad approval signature (bit flip)";
        cneg[1].co.bad_sig_at = 2;
        cneg[2].name = "duplicate snapshot index";
        cneg[2].co.dup_seat = 1;
        cneg[3].name = "unsorted snapshot indices";
        cneg[3].co.unsorted = 1;
        /* the two range entries carry FIVE approvals (quorum met) with
         * only the LAST seat out of range — sub-quorum can no longer be
         * the reason (review finding 1b); the zero-sig residue is the
         * structural defense-in-depth documented at cc_build */
        cneg[4].name = "index == committee size";
        cneg[4].co.seat_override = 7;
        cneg[5].name = "index beyond committee size";
        cneg[5].co.seat_override = 200;
        /* count > N is STRUCTURALLY co-sufficient with framing: 8 slots
         * cannot be carried as 7 — the count gate is simply the first
         * to fire */
        cneg[6].name = "approval count greater than committee";
        cneg[6].voters = voters7; cneg[6].nv = 7;
        cneg[6].co.count_delta = 1;
        cneg[7].name = "count/framing mismatch (declared < carried)";
        cneg[7].co.count_delta = -1;
        cneg[8].name = "truncated approval bytes";
        cneg[8].co.truncate = 1;
        cneg[9].name = "trailing bytes after the approvals";
        cneg[9].co.trailing_byte = 1;
        cneg[10].name = "wrong committee member (unseated key signs)";
        cneg[10].co.sign_with = K_STRAY;
        cneg[11].name = "wrong governing epoch (signed for epoch+1)";
        cneg[11].co.epoch_delta = 1;
        cneg[12].name = "wrong snapshot identity (set-hash flip)";
        cneg[12].co.set_hash_flip = 1;
        static uint8_t other_chain2[32];
        memset(other_chain2, 0x99, 32);
        cneg[13].name = "cross-chain envelope (decided at the SUBMITTER "
                        "signature; approvals inherit the same chain "
                        "binding transitively via leg_auth_digest)";
        cneg[13].so.chain_id = other_chain2;
        for (int i = 0; i < 14; i++) {
            CHECK(cc_env(&fx, &e, 1, 1, 5, 1000, 0x42, 1, 2000,
                         cneg[i].voters, cneg[i].nv, 0, &cneg[i].co,
                         &cneg[i].so) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  cneg[i].name);
            OK();
        }
        /* proposal substitution: approvals bind the CALL BYTES through
         * the leg digest — signing over a flipped call invalidates
         * every signature (submitter AND approvals) */
        {
            sign_opt_t so;
            memset(&so, 0, sizeof(so));
            so.call_flip = 1;
            CHECK(cc_env(&fx, &e, 1, 1, 5, 1000, 0x42, 1, 2000, voters5,
                         5, 0, NULL, &so) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "proposal substitution invalidates the approvals");
            OK();
        }
        /* a KIND-1 CHAIN_CONFIG leg carries NO approvals: the verdict
         * has n_approvals == 0 / committee_n == 0 and exec rejects at
         * the quorum gate — approvals cannot be implied */
        {
            uint8_t call41[41];
            CHECK(cc_call_build(call41, sizeof(call41), 1, 5, 1000, 0x42,
                                1, 2000) == 41, "call");
            int sub[1] = { 0 };
            CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_SYSTEM,
                                   DNA_SYSRULE_CHAIN_CONFIG, call41, 41,
                                   0, 0, 4, 2048, sub, 1, NULL) == 0,
                  "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "kind-1 CC leg (no approvals) fails the quorum gate");
            OK();
        }
        /* an auth kind outside the runtime's allowlist dies at
         * admission (unknown kind 3 on a SYSTEM leg) */
        {
            sign_opt_t so;
            memset(&so, 0, sizeof(so));
            so.auth_kind = 3;
            CHECK(cc_env(&fx, &e, 1, 1, 5, 1000, 0x42, 1, 2000, voters5,
                         5, 0, NULL, &so) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "auth kind outside the allowlist must reject");
            OK();
        }
    }

    /* INFLATION_START monotonicity: a prior nonzero row is seeded, so
     * a proposal disabling it (0) or moving it past now must reject */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO chain_config_history (param_id, new_value, "
        "effective_block, commit_block, tx_hash, proposal_nonce, "
        "created_at_unix) VALUES (3, 900000, 500000, 0, zeroblob(64), "
        "7, 0)") == 0, "seed inflation row");
    CHECK(cc_env(&fx, &e, 1, 3, 0, 20000, 0x43, 1, 30000, voters5, 5, 0,
                 NULL, NULL) == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "monotonicity: cannot disable once enabled");
        OK();
        CHECK(cc_env(&fx, &e, 1, 3, 999, 20000, 0x44, 1, 30000, voters5,
                     5, 0, NULL, NULL) == 0, "build");
        nodus_v2_envelope_t v2e = { e.bytes, e.len };
        mk_block(&b, 1, &v2e, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "monotonicity: cannot move start past current block");
        OK();
    }

    /* POSITIVE: quorum (5 of 7) commits; scheduled activation holds */
    CHECK(cc_env(&fx, &e, 1, 1, 5, 1000, 0x42, 1, 2000, voters5, 5, 0,
                 NULL, NULL) == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        int prc = nodus_witness_v2_apply_block(fx.w, &b);
        if (prc != 0) fprintf(stderr, "cc positive rc=%d\n", prc);
        CHECK(prc == 0, "quorum proposal must commit");
        OK();
    }
    CHECK(q1(fx.w, "SELECT new_value FROM chain_config_history WHERE "
                   "param_id=1 AND effective_block=1000") == 5,
          "row committed");
    CHECK(q1(fx.w, "SELECT commit_block FROM chain_config_history WHERE "
                   "param_id=1 AND effective_block=1000") == 1,
          "commit height recorded");
    CHECK(q1(fx.w, "SELECT created_at_unix FROM chain_config_history "
                   "WHERE param_id=1 AND effective_block=1000") == 0,
          "no wall clock in the deterministic lane");
    OK();
    /* scheduled-transition semantics: value governs only from its
     * effective height (the shipped lookup is the authority) */
    CHECK(nodus_chain_config_get_u64(fx.w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                     999, 10) == 10,
          "not active before effective height");
    CHECK(nodus_chain_config_get_u64(fx.w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                     1000, 10) == 5,
          "active from effective height");
    OK();
    /* SYSTEM root moved; CORE untouched (root AND height) */
    {
        uint8_t sys_r1[64], core_r1[64];
        CHECK(head_root(fx.w, 0, sys_r1) == 0 &&
              head_root(fx.w, 1, core_r1) == 0, "roots");
        CHECK(memcmp(sys_r0, sys_r1, 64) != 0,
              "SYSTEM state root must move");
        CHECK(memcmp(core_r0, core_r1, 64) == 0,
              "CORE state root must not move");
        CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=1") == 0,
              "CORE domain height must not move");
        CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=0") == 1,
              "SYSTEM domain height advanced");
        OK();
    }
    /* a second scheduled transition commits at H=2 so the chain reaches
     * a height where the FRESHNESS gate becomes reachable */
    CHECK(cc_env(&fx, &e, 2, 1, 6, 1001, 0x77, 1, 2000, voters5, 5, 0,
                 NULL, NULL) == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "second scheduled transition must commit");
        OK();
    }
    /* FRESHNESS (CC-G): a proposal whose valid_before lies BELOW the
     * commit height rejects at the freshness mirror, with the scalar
     * window intact (vb 2 > effective 1 > 0, signed_at 1 < vb) —
     * reachable only at H > vb, hence the H=3 placement */
    CHECK(cc_env(&fx, &e, 3, 1, 5, 1, 0x88, 1, 2, voters5, 5, 0,
                 NULL, NULL) == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "stale proposal (freshness) must reject");
        OK();
    }
    /* duplicate (param, effective) is a replayed transition — rejects */
    CHECK(cc_env(&fx, &e, 3, 1, 5, 1000, 0x99, 2, 2000, voters5, 5, 0,
                 NULL, NULL) == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate (param, effective) must reject");
        OK();
    }

    /* ── SNAPSHOT ROTATION (wrong historical snapshot) ──────────────────
     * Approvals signed against the OLD resolved committee must die once
     * the governing set changes: key 6 rotates OUT, key 15 rotates IN
     * (a validator-table swap + committee-cache invalidation — the
     * bootstrap resolution recomputes from the table). The signed set
     * hash and every seat mapping then disagree with the engine's
     * resolution. The voters (keys 0..4) are all STILL seated — only
     * the SNAPSHOT identity moved, so this isolates the snapshot
     * binding, not membership. */
    {
        env_t *stale = malloc(sizeof(*stale));
        CHECK(stale != NULL, "alloc");
        CHECK(cc_env(&fx, stale, 3, 1, 7, 3000, 0xAB, 3, 4000, voters5,
                     5, 0, NULL, NULL) == 0, "build stale");
        /* rotate: 6 out, 15 in */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET pubkey=?1 WHERE pubkey=?2",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, g_pk[15], 2592, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, g_pk[6], 2592, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "rotate");
        sqlite3_finalize(st);
        fx.w->cached_committee_epoch_start = UINT64_MAX;   /* cold cache */
        nodus_v2_envelope_t ve = { stale->bytes, stale->len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "stale-snapshot approvals must reject after rotation");
        OK();
        /* the ROTATED-IN validator signs under the NEW snapshot: fresh
         * approvals with key 15 in the set commit */
        int votersr[5] = { 0, 1, 2, 3, 15 };
        CHECK(cc_env(&fx, stale, 3, 1, 7, 3000, 0xAB, 3, 4000, votersr,
                     5, 0, NULL, NULL) == 0, "build fresh");
        nodus_v2_envelope_t vf = { stale->bytes, stale->len };
        mk_block(&b, 3, &vf, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "rotated-in committee signs under the new snapshot");
        OK();
        free(stale);
    }

    /* ── CC fault-injection matrix (capacity-season stages) ──────────── */
    {
        static const nodus_v2_apply_fail_t cpts[5] = {
            V2AP_FAIL_AFTER_ENV_RESERVE, V2AP_FAIL_AFTER_AUTH,
            V2AP_FAIL_AFTER_CC_SNAPSHOT, V2AP_FAIL_BEFORE_COMMIT,
            V2AP_FAIL_COMMIT
        };
        int votersr[5] = { 0, 1, 2, 3, 15 };
        for (int p = 0; p < 5; p++) {
            CHECK(cc_env(&fx, &e, 4, 1, 8, 4000, 0xC0 + (uint64_t)p, 4,
                         5000, votersr, 5, 0, NULL, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 4, &ve, 1);
            b.fail_at = cpts[p];
            b.fail_env_index = 0;
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "CC fault point must roll back byte-identically");
            OK();
        }
        /* clean re-apply commits (budgets and snapshot state intact) */
        CHECK(cc_env(&fx, &e, 4, 1, 8, 4000, 0xC9, 4, 5000, votersr, 5,
                     0, NULL, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "clean re-apply after CC faults must commit");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ══ 3b. COMMITTEE CAPACITY — source-derived boundaries ═════════════ */

/* Committee sizes derived from the SOURCE constants, not prose:
 *   - genesis floor: DNAC_COMMITTEE_SIZE = 7, quorum dna_bft_quorum(7)
 *   - the FIRST committee whose quorum exceeds the RETIRED cap (8):
 *     smallest N with dna_bft_quorum(N) > 8  →  N = 12 (quorum 9)
 *   - the release technical ceiling: DNA_MAX_ACTIVE_VALIDATORS = 128,
 *     quorum dna_bft_quorum(128) = 86
 * The 128-seat leg runs REAL ML-DSA-87 end-to-end (128 keypairs, 128
 * approval signatures verified through the whole engine path). */
static uint8_t g_bpk[DNA_MAX_ACTIVE_VALIDATORS][2592];
static uint8_t g_bsk[DNA_MAX_ACTIVE_VALIDATORS][4896];

static int test_committee_capacity(void) {
    /* derive the boundary sizes from source and re-verify the formula
     * independently (floor(2N/3)+1 in integer arithmetic) */
    uint32_t n_first = 0;
    for (uint32_t n = 8; n <= 32; n++)
        if (dna_bft_quorum(n) > 8) { n_first = n; break; }
    CHECK(n_first == 12, "first quorum > 8 committee derives to 12");
    CHECK(dna_bft_quorum(12) == 9, "quorum(12)");
    CHECK(dna_bft_quorum(7) == (2u * 7u) / 3u + 1u &&
          dna_bft_quorum(7) == 5, "independent quorum recheck (7)");
    CHECK(dna_bft_quorum(DNA_MAX_ACTIVE_VALIDATORS) ==
              (2u * DNA_MAX_ACTIVE_VALIDATORS) / 3u + 1u &&
          dna_bft_quorum(DNA_MAX_ACTIVE_VALIDATORS) == 86,
          "independent quorum recheck (release ceiling)");
    OK();

    /* ── N = 12: the OLD cap 8 is provably gone ─────────────────────── */
    {
        fixture_t fx;
        int q9[9], q8[8];
        for (int i = 0; i < 9; i++) q9[i] = i;
        for (int i = 0; i < 8; i++) q8[i] = i;
        /* first 12 test keys as validators */
        CHECK(fx_genesis_n(&fx, "cap12", (const uint8_t (*)[2592])g_pk,
                           12) == 0, "genesis 12");
        env_t e;
        nodus_v2_block_t b;
        int rc = 0;
        /* quorum(12) = 9 > the retired cap 8: NINE approvals commit */
        CHECK(cc_env(&fx, &e, 1, 1, 5, 1000, 0x42, 1, 2000, q9, 9, 0,
                     NULL, NULL) == 0, "build 9");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "quorum 9 of 12 commits — the old 8-vote cap is gone");
        OK();
        /* quorum-1 = 8 (the exact retired cap) fails */
        CHECK(cc_env(&fx, &e, 2, 1, 6, 3000, 0x43, 1, 4000, q8, 8, 0,
                     NULL, NULL) == 0, "build 8");
        nodus_v2_envelope_t v8 = { e.bytes, e.len };
        mk_block(&b, 2, &v8, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "8 of 12 (quorum-1) must reject");
        OK();
        fx_close(&fx);
    }

    /* ── N = 128 (the release ceiling), REAL ML-DSA-87 end-to-end ───── */
    {
        for (int i = 0; i < DNA_MAX_ACTIVE_VALIDATORS; i++)
            if (qgp_dsa87_keypair(g_bpk[i], g_bsk[i]) != 0) {
                fprintf(stderr, "big keygen failed\n");
                return 1;
            }
        fixture_t fx;
        CHECK(fx_genesis_n(&fx, "cap128", (const uint8_t (*)[2592])g_bpk,
                           DNA_MAX_ACTIVE_VALIDATORS) == 0,
              "genesis 128");
        /* the ceiling-shape envelopes exceed the standard buffer — heap
         * (never the stack; capacity-season discipline) */
        size_t cap = DNA_ENV_MAX_TOTAL_LEN;
        uint8_t *buf = malloc(cap);
        CHECK(buf != NULL, "alloc");
        size_t elen = 0;
        int voters[DNA_MAX_ACTIVE_VALIDATORS];
        nodus_v2_block_t b;
        int rc = 0;
        const uint32_t Q = dna_bft_quorum(DNA_MAX_ACTIVE_VALIDATORS);

        /* ALL 128 distinct approvals — the worst-case legal envelope
         * shape of the DNA_ENV_MAX_TOTAL_LEN derivation — commits */
        for (int i = 0; i < 128; i++) voters[i] = i;
        CHECK(cc_build(&fx, buf, cap, &elen, 1,
                       (const uint8_t (*)[2592])g_bpk,
                       (const uint8_t (*)[4896])g_bsk, 128, 0,
                       1, 5, 1000, 0x42, 1, 2000, 0, 750000,
                       voters, 128, NULL, NULL) == 0, "build 128");
        CHECK(elen > 590000 && elen <= DNA_ENV_MAX_TOTAL_LEN,
              "all-N envelope is a ceiling-class shape");
        {
            nodus_v2_envelope_t ve = { buf, elen };
            mk_block(&b, 1, &ve, 1);
            CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
                  "ALL 128 release-ceiling approvals commit");
            OK();
        }
        /* EXACT quorum (86) commits */
        CHECK(cc_build(&fx, buf, cap, &elen, 2,
                       (const uint8_t (*)[2592])g_bpk,
                       (const uint8_t (*)[4896])g_bsk, 128, 0,
                       1, 6, 3000, 0x43, 2, 4000, 0, 750000,
                       voters, (int)Q, NULL, NULL) == 0, "build 86");
        {
            nodus_v2_envelope_t ve = { buf, elen };
            mk_block(&b, 2, &ve, 1);
            CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
                  "exact release-ceiling quorum (86 of 128) commits");
            OK();
        }
        /* quorum-1 (85) rejects */
        CHECK(cc_build(&fx, buf, cap, &elen, 3,
                       (const uint8_t (*)[2592])g_bpk,
                       (const uint8_t (*)[4896])g_bsk, 128, 0,
                       1, 7, 5000, 0x44, 3, 6000, 0, 750000,
                       voters, (int)Q - 1, NULL, NULL) == 0, "build 85");
        {
            nodus_v2_envelope_t ve = { buf, elen };
            mk_block(&b, 3, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "quorum-1 (85 of 128) must reject");
            OK();
        }
        free(buf);
        fx_close(&fx);
    }
    return 0;
}

/* ══ 4. CORE slice — SPEND ═════════════════════════════════════════ */

static int test_core_spend(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "spend") == 0, "genesis");
    int s7[1] = { 7 };
    int s78[2] = { 7, 8 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    uint8_t ins1[1][64];
    memcpy(ins1[0], g_nul_a, 64);

    /* seed one LOCKED utxo (unlock far in the future) for the lock gate */
    CHECK(seed_utxo(&fx, 7, 1500000 + FEE_MIN, 0xE1, 100000,
                    g_nul_lock) == 0, "seed locked");
    /* the invariant seed must still hold: add the locked value */
    {
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = "
                 "current_supply + %llu WHERE id = 1",
                 (unsigned long long)(1500000 + FEE_MIN),
                 (unsigned long long)(1500000 + FEE_MIN));
        CHECK(run_sql(fx.w->db, sql) == 0, "supply seed");
    }

    /* ── negatives (each digest-proven no-op) ───────────────────────── */
    out_spec_t o_ok[2] = { { 8, 2000000, 0x01, NULL },
                           { 7, 2000000, 0x02, NULL } };
    struct {
        const char *name;
        const void *ins; int n_in;      /* really (*)[64] — see the
                                         * spend_call_build shim         */
        out_spec_t outs[3]; int n_out;
        uint64_t fee; const int *signers; int n_signers;
    } neg[6];
    memset(neg, 0, sizeof(neg));
    static uint8_t missing[1][64];
    memset(missing, 0x77, sizeof(missing));
    static uint8_t tok1[64];
    memset(tok1, 0x71, 64);
    neg[0].name = "missing input";
    neg[0].ins = missing; neg[0].n_in = 1;
    neg[0].outs[0] = o_ok[0]; neg[0].n_out = 1;
    neg[0].fee = FEE_MIN; neg[0].signers = s7; neg[0].n_signers = 1;
    neg[1].name = "wrong owner (signer does not own the input)";
    neg[1].ins = g_nul_c; neg[1].n_in = 1;
    /* BALANCED on purpose (in 2M = out 1M + fee 1M): ownership is the
     * ONLY violated rule, so this cannot pass vacuously through the
     * conservation check */
    neg[1].outs[0].owner = 8; neg[1].outs[0].amount = UTXO_C - FEE_MIN;
    neg[1].outs[0].seed_byte = 0x04; neg[1].n_out = 1;
    neg[1].fee = FEE_MIN; neg[1].signers = s7; neg[1].n_signers = 1;
    neg[2].name = "value mismatch (fee != committed declaration)";
    neg[2].ins = ins1; neg[2].n_in = 1;
    neg[2].outs[0] = o_ok[0]; neg[2].outs[1] = o_ok[1]; neg[2].n_out = 2;
    neg[2].fee = FEE_MIN + 1; neg[2].signers = s7; neg[2].n_signers = 1;
    neg[3].name = "checked-subtract underflow (outputs exceed inputs)";
    neg[3].ins = ins1; neg[3].n_in = 1;
    neg[3].outs[0].owner = 8; neg[3].outs[0].amount = UTXO_A;
    neg[3].outs[0].seed_byte = 0x05; neg[3].n_out = 1;
    neg[3].fee = FEE_MIN; neg[3].signers = s7; neg[3].n_signers = 1;
    neg[4].name = "duplicate output identifier";
    neg[4].ins = ins1; neg[4].n_in = 1;
    neg[4].outs[0].owner = 8; neg[4].outs[0].amount = 2000000;
    neg[4].outs[0].seed_byte = 0x06;
    neg[4].outs[1].owner = 8; neg[4].outs[1].amount = 2000000;
    neg[4].outs[1].seed_byte = 0x06;    /* same fp + seed = same id     */
    neg[4].n_out = 2;
    neg[4].fee = FEE_MIN; neg[4].signers = s7; neg[4].n_signers = 1;
    neg[5].name = "token conservation (token minted from nothing)";
    neg[5].ins = ins1; neg[5].n_in = 1;
    neg[5].outs[0].owner = 8; neg[5].outs[0].amount = 4000000;
    neg[5].outs[0].seed_byte = 0x07;
    neg[5].outs[1].owner = 8; neg[5].outs[1].amount = 5;
    neg[5].outs[1].seed_byte = 0x08; neg[5].outs[1].token = tok1;
    neg[5].n_out = 2;
    neg[5].fee = FEE_MIN; neg[5].signers = s7; neg[5].n_signers = 1;
    for (int i = 0; i < 6; i++) {
        CHECK(spend_env(&fx, &e, neg[i].ins, neg[i].n_in, neg[i].outs,
                        neg[i].n_out, neg[i].fee, neg[i].signers,
                        neg[i].n_signers, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1, neg[i].name);
        OK();
    }

    /* zero-amount output rejects (transparent-leg §6: amount >= 1 —
     * the R2/R4 review convergence; balanced on purpose so the amount
     * floor is the only violated rule) */
    {
        out_spec_t oz[2] = { { 8, UTXO_A - FEE_MIN, 0x0C, NULL },
                             { 8, 0, 0x0D, NULL } };
        CHECK(spend_env(&fx, &e, ins1, 1, oz, 2, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "zero-amount output must reject");
        OK();
    }

    /* fee below the shipped floors rejects (balanced: in = out + fee) */
    {
        out_spec_t of[1] = { { 8, UTXO_A - (FEE_MIN - 1), 0x0E, NULL } };
        CHECK(spend_env(&fx, &e, ins1, 1, of, 1, FEE_MIN - 1, s7, 1,
                        NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "sub-floor fee must reject");
        OK();
    }

    /* malformed owner fingerprint (non-hex byte) rejects */
    {
        static uint8_t call[8192];
        uint32_t cl = spend_call_build(call, sizeof(call), ins1, 1,
                                       o_ok, 2);
        CHECK(cl > 0, "call");
        call[1 + 64 + 1] = 'Z';          /* first output's fp[0] slot   */
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SPEND, call, cl, FEE_MIN, 0,
                               40, 16384, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "non-hex owner fingerprint must reject");
        OK();
    }

    /* auth-data layout mismatch: declared kind 1 but auth_len does not
     * equal 1 + n*7219 — the scheme parser fails closed */
    {
        static uint8_t call[8192];
        uint32_t cl = spend_call_build(call, sizeof(call), ins1, 1,
                                       o_ok, 2);
        CHECK(cl > 0, "call");
        static const uint8_t tiny_auth[3] = { 2, 0xAA, 0xBB };
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op = DNA_CORERULE_SPEND;
        leg.hdr.ruleset_version = 2;     /* burn season: CORE v2         */
        leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind = 1;
        leg.hdr.call_len = cl;
        leg.hdr.auth_len = sizeof(tiny_auth);
        leg.hdr.res_max_effects = 40;
        leg.hdr.res_max_effect_bytes = 16384;
        leg.call_data = call;
        leg.auth_data = tiny_auth;
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.fee_amount = FEE_MIN;
        in.res_max_total_units = 200000;
        in.leg_count = 1;
        in.legs = &leg;
        CHECK(dna_env_encode(&in, e.bytes, sizeof(e.bytes), &e.len) == 0,
              "encode");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "auth layout mismatch must reject");
        OK();
    }

    /* duplicate input inside one call (non-canonical order) */
    {
        static uint8_t call[8192];
        uint32_t cl = spend_call_build(call, sizeof(call), ins1, 1,
                                       o_ok, 2);
        CHECK(cl > 0, "call");
        /* hand-corrupt: 2 identical inputs */
        static uint8_t call2[8192];
        call2[0] = 2;
        memcpy(call2 + 1, g_nul_a, 64);
        memcpy(call2 + 65, g_nul_a, 64);
        memcpy(call2 + 129, call + 65, cl - 65);
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SPEND, call2, cl + 64,
                               FEE_MIN, 0, 40, 16384, s7, 1, NULL) == 0,
              "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate input in one transaction must reject");
        OK();
    }

    /* locked input rejects */
    {
        uint8_t insl[1][64];
        memcpy(insl[0], g_nul_lock, 64);
        out_spec_t ol[1] = { { 8, 1500000, 0x09, NULL } };
        CHECK(spend_env(&fx, &e, insl, 1, ol, 1, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "locked input must reject");
        OK();
    }

    /* cross-domain UTXO substitution: a row owned by another domain is
     * invisible to the CORE adapter (missing input) AND poisons the
     * supply gate — the block cannot commit either way */
    {
        fixture_t fx2;
        CHECK(fx_genesis(&fx2, "xdom") == 0, "genesis");
        CHECK(run_sql(fx2.w->db,
            "UPDATE utxo_set SET domain_id = 0 WHERE nullifier = "
            "(SELECT nullifier FROM utxo_set LIMIT 1)") == 0, "foreign");
        env_t e2;
        uint8_t insx[1][64];
        memcpy(insx[0], g_nul_a, 64);
        CHECK(spend_env(&fx2, &e2, insx, 1, o_ok, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e2.bytes, e2.len };
        nodus_v2_block_t b2;
        mk_block(&b2, 1, &ve, 1);
        CHECK(apply_reject(fx2.w, &b2, &rc) == 0 && rc == -1,
              "cross-domain substitution cannot commit");
        OK();
        fx_close(&fx2);
    }

    /* ── POSITIVE: transfer with change ─────────────────────────────── */
    uint64_t burned0 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint8_t core_r0[64], sys_r0[64];
    CHECK(head_root(fx.w, 1, core_r0) == 0 &&
          head_root(fx.w, 0, sys_r0) == 0, "roots");
    CHECK(spend_env(&fx, &e, ins1, 1, o_ok, 2, FEE_MIN, s7, 1, NULL)
              == 0, "build");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "valid transfer must commit");
        OK();
    }
    /* input gone, outputs exist with exact amounts and owners */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT COUNT(*) FROM utxo_set WHERE nullifier=?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, g_nul_a, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int64(st, 0) == 0, "input consumed");
        sqlite3_finalize(st);
        OK();
        uint8_t n1[64], n2[64];
        CHECK(out_nul(8, 0x01, n1) == 0 && out_nul(7, 0x02, n2) == 0,
              "nuls");
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT amount, owner, block_height FROM utxo_set WHERE "
              "nullifier=?1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, n1, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              (uint64_t)sqlite3_column_int64(st, 0) == 2000000 &&
              strcmp((const char *)sqlite3_column_text(st, 1),
                     g_fp[8]) == 0 &&
              sqlite3_column_int64(st, 2) == 1,
              "recipient output canonical");
        sqlite3_finalize(st);
        OK();
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT amount FROM utxo_set WHERE nullifier=?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, n2, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              (uint64_t)sqlite3_column_int64(st, 0) == 2000000,
              "change output canonical");
        sqlite3_finalize(st);
        OK();
        /* transaction identity comes ONLY from the canonical envelope
         * bytes + engine context: the created rows' tx_hash must equal
         * the independently re-derived preflight tx_id */
        {
            size_t bn = 0;
            const nodus_domain_runtime_t *bt =
                nodus_runtime_builtin_table(&bn);
            dna_env_leg_ctx_t lctx;
            memset(&lctx, 0, sizeof(lctx));
            lctx.domain_id = DNA_DOMAIN_CORE;
            lctx.ruleset_version = bt[1].ruleset_version;
            memcpy(lctx.ruleset_hash, bt[1].ruleset_hash, 64);
            dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
            CHECK(pf != NULL, "alloc");
            CHECK(dna_env_preflight(e.bytes, e.len, fx.chain_id, 1,
                                    &lctx, 1, pf) == DNA_ENV_PF_OK,
                  "re-preflight");
            st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT tx_hash FROM utxo_set WHERE nullifier=?1",
                  -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, n1, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == 64 &&
                  memcmp(sqlite3_column_blob(st, 0), pf->intent_id,
                         64) == 0,
                  "output provenance is the DERIVED INTENT identity");
            /* and it is NOT the full-wire identity (intent season) */
            CHECK(memcmp(pf->intent_id, pf->wire_id, 64) != 0,
                  "intent and wire identities are distinct values");
            sqlite3_finalize(st);
            free(pf);
            OK();
        }
    }
    /* fee burned exactly once; conservation identity holds */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
              == burned0 + FEE_MIN, "fee burned exactly once");
    CHECK(supply_identity_holds(fx.w), "pre/post total DNAC identity");
    OK();
    /* CORE root moved + height advanced; SYSTEM untouched */
    {
        uint8_t core_r1[64], sys_r1[64];
        CHECK(head_root(fx.w, 1, core_r1) == 0 &&
              head_root(fx.w, 0, sys_r1) == 0, "roots");
        CHECK(memcmp(core_r0, core_r1, 64) != 0, "CORE root moved");
        CHECK(memcmp(sys_r0, sys_r1, 64) == 0, "SYSTEM root untouched");
        CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=0") == 0,
              "SYSTEM height untouched");
        OK();
    }
    /* meter accounting: consumed units are the exact placeholder-weight
     * formula — base(1) + op(1) + call bytes + auth bytes + actual
     * effects + actual canonical result bytes + reads. Recomputed here
     * from first principles; the DomainUpdate carries the engine's
     * number. */
    {
        dna_env_view_t v;
        CHECK(dna_env_decode(e.bytes, e.len, &v) == 0, "view");
        /* actual result: 2 CREATE (64+284 each) + 1 SET (1+8) + 1 DEL
         * (64+0) records */
        uint64_t res_bytes = 23 + 84 * 4 + (64 + 64 + 1 + 64)
                             + (284 + 284 + 8);
        /* w_base is charged GLOBALLY (no authoring domain) — the
         * DomainUpdate carries the LEG-domain consumption only */
        uint64_t expect = 1 /*op*/ + v.leg[0].call_len
                          + v.leg[0].auth_len + 4 /*effects*/
                          + res_bytes + 2 /*reads: 1 input + supply*/;
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates WHERE "
                       "global_height=1") == 1, "one update");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT upd FROM v2_domain_updates WHERE global_height=1",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW, "upd row");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u)
                  == 0, "decode");
        sqlite3_finalize(st);
        CHECK(u.res_verify_cost == expect,
              "consumed units are exactly the priced work");
        OK();
    }

    /* multi-input, multi-owner, exact value (no change) */
    {
        uint8_t ins2[2][64];
        memcpy(ins2[0], g_nul_b, 64);
        memcpy(ins2[1], g_nul_c, 64);
        out_spec_t o2[1] = { { 7, UTXO_B + UTXO_C - FEE_MIN, 0x0A,
                               NULL } };
        CHECK(spend_env(&fx, &e, ins2, 2, o2, 1, FEE_MIN, s78, 2, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "multi-input exact-value transfer must commit");
        CHECK(supply_identity_holds(fx.w), "identity");
        OK();
    }

    /* already-spent input (replaying a consumed transaction's input) */
    {
        CHECK(spend_env(&fx, &e, ins1, 1, o_ok, 2, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "already-spent input must reject");
        OK();
    }

    /* ── SIGNER CARDINALITY (capacity season: the derived cap 15) ───── */
    {
        /* 15 inputs, EVERY input owned by a DISTINCT signer — the
         * structural maximum the NODUS_RT_AUTH_MAX_SIGNERS derivation
         * names. 15 keys, 15 real signatures, engine-verified. */
        fixture_t fs;
        CHECK(fx_genesis(&fs, "sig15") == 0, "genesis");
        uint8_t nul15[15][64];
        uint64_t extra = 0;
        for (int i = 0; i < 15; i++) {
            CHECK(seed_utxo(&fs, i, 1000000, (uint8_t)(0xD0 + i), 0,
                            nul15[i]) == 0, "seed");
            extra += 1000000;
        }
        {
            char sql[192];
            snprintf(sql, sizeof(sql),
                     "UPDATE supply_tracking SET genesis_supply = "
                     "genesis_supply + %llu, current_supply = "
                     "current_supply + %llu WHERE id = 1",
                     (unsigned long long)extra, (unsigned long long)extra);
            CHECK(run_sql(fs.w->db, sql) == 0, "supply seed");
        }
        int s15[15];
        for (int i = 0; i < 15; i++) s15[i] = i;
        out_spec_t o15[1] = { { 7, 15 * 1000000ULL - FEE_MIN, 0x31,
                                NULL } };
        env_t *e15 = malloc(sizeof(*e15));
        CHECK(e15 != NULL, "alloc");
        CHECK(spend_env(&fs, e15, (const uint8_t (*)[64])nul15, 15, o15,
                        1, FEE_MIN, s15, 15, NULL) == 0, "build 15x15");
        {
            nodus_v2_envelope_t ve = { e15->bytes, e15->len };
            nodus_v2_block_t bs;
            mk_block(&bs, 1, &ve, 1);
            CHECK(nodus_witness_v2_apply_block(fs.w, &bs) == 0,
                  "15 inputs / 15 distinct owners must commit");
            CHECK(supply_identity_holds(fs.w), "identity");
            OK();
        }
        /* ONE signer covering 15 owned inputs — no duplicate signatures
         * required (signer cardinality derives from unique owners, not
         * input count) */
        uint8_t nul1[15][64];
        extra = 0;
        for (int i = 0; i < 15; i++) {
            CHECK(seed_utxo(&fs, 7, 500000, (uint8_t)(0x50 + i), 0,
                            nul1[i]) == 0, "seed");
            extra += 500000;
        }
        {
            char sql[192];
            snprintf(sql, sizeof(sql),
                     "UPDATE supply_tracking SET genesis_supply = "
                     "genesis_supply + %llu, current_supply = "
                     "current_supply + %llu WHERE id = 1",
                     (unsigned long long)extra, (unsigned long long)extra);
            CHECK(run_sql(fs.w->db, sql) == 0, "supply seed");
        }
        out_spec_t o1x[1] = { { 8, 15 * 500000ULL - FEE_MIN, 0x32,
                                NULL } };
        CHECK(spend_env(&fs, e15, (const uint8_t (*)[64])nul1, 15, o1x,
                        1, FEE_MIN, s7, 1, NULL) == 0, "build 15x1");
        {
            nodus_v2_envelope_t ve = { e15->bytes, e15->len };
            nodus_v2_block_t bs;
            mk_block(&bs, 2, &ve, 1);
            CHECK(nodus_witness_v2_apply_block(fs.w, &bs) == 0,
                  "one signer authorizing 15 owned inputs must commit");
            OK();
        }
        /* an EXTRA unrelated signer is legal under kind 1 (every
         * signature verifies; ownership needs only that each input's
         * owner is AMONG the verified signers) — pinned as ACCEPT so a
         * future minimality rule is a visible change, not drift */
        {
            uint8_t nx[1][64];
            CHECK(seed_utxo(&fs, 7, 2 * FEE_MIN, 0x66, 0, nx[0]) == 0,
                  "seed");
            char sql[192];
            snprintf(sql, sizeof(sql),
                     "UPDATE supply_tracking SET genesis_supply = "
                     "genesis_supply + %llu, current_supply = "
                     "current_supply + %llu WHERE id = 1",
                     (unsigned long long)(2 * FEE_MIN),
                     (unsigned long long)(2 * FEE_MIN));
            CHECK(run_sql(fs.w->db, sql) == 0, "supply seed");
            int s79[2] = { 7, 9 };       /* 9 owns nothing here          */
            out_spec_t ox[1] = { { 8, FEE_MIN, 0x67, NULL } };
            CHECK(spend_env(&fs, e15, nx, 1, ox, 1, FEE_MIN, s79, 2,
                            NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e15->bytes, e15->len };
            nodus_v2_block_t bs;
            mk_block(&bs, 3, &ve, 1);
            CHECK(nodus_witness_v2_apply_block(fs.w, &bs) == 0,
                  "extra unrelated signer is pinned ACCEPT");
            OK();
        }
        /* ONE ABOVE the derived bound: a raw 16-signer kind-1 blob is a
         * parse-level reject (count > NODUS_RT_AUTH_MAX_SIGNERS) */
        {
            uint32_t alen = 1 + 16u * 7219u;
            uint8_t *auth = calloc(1, alen);
            CHECK(auth != NULL, "alloc");
            auth[0] = 16;
            for (int i = 0; i < 16; i++)   /* distinct non-zero prefixes */
                memset(auth + 1 + (size_t)i * 7219, (uint8_t)(i + 1), 64);
            uint8_t call[8192];
            uint32_t cl = spend_call_build(call, sizeof(call),
                                           (const uint8_t (*)[64])nul15,
                                           1, o_ok, 2);
            CHECK(cl > 0, "call");
            dna_env_leg_in_t leg;
            memset(&leg, 0, sizeof(leg));
            leg.hdr.domain_id = DNA_DOMAIN_CORE;
            leg.hdr.runtime_op = DNA_CORERULE_SPEND;
            leg.hdr.ruleset_version = 2; /* burn season: CORE v2         */
            leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
            leg.hdr.auth_kind = 1;
            leg.hdr.call_len = cl;
            leg.hdr.auth_len = alen;
            leg.hdr.res_max_effects = 40;
            leg.hdr.res_max_effect_bytes = 16384;
            leg.call_data = call;
            leg.auth_data = auth;
            dna_env_in_t in;
            memset(&in, 0, sizeof(in));
            in.fee_amount = FEE_MIN;
            in.res_max_total_units = 200000;
            in.leg_count = 1;
            in.legs = &leg;
            CHECK(dna_env_encode(&in, e15->bytes, sizeof(e15->bytes),
                                 &e15->len) == 0, "encode");
            free(auth);
            nodus_v2_envelope_t ve = { e15->bytes, e15->len };
            nodus_v2_block_t bs;
            mk_block(&bs, 4, &ve, 1);
            CHECK(apply_reject(fs.w, &bs, &rc) == 0 && rc == -1,
                  "16 signers (one above the derived bound) must reject");
            OK();
        }
        /* NARROW ZERO-PREFIX key: first 32 bytes zero, remainder alive.
         * The scheme's null-key discipline keys on the 32-byte prefix
         * (no honest ML-DSA-87 key has a zero rho), so this dies at the
         * PARSE level — before any signature math. Pinned so the guard
         * cannot silently narrow. */
        {
            uint32_t alen = 1 + 7219u;
            uint8_t *auth = calloc(1, alen);
            CHECK(auth != NULL, "alloc");
            auth[0] = 1;
            memset(auth + 1, 0, 32);                 /* zero prefix      */
            memset(auth + 1 + 32, 0xA7, 2592 - 32);  /* alive remainder  */
            memset(auth + 1 + 2592, 0xB1, 4627);     /* garbage sig      */
            uint8_t call[8192];
            uint32_t cl = spend_call_build(call, sizeof(call),
                                           (const uint8_t (*)[64])nul15,
                                           1, o_ok, 2);
            CHECK(cl > 0, "call");
            dna_env_leg_in_t leg;
            memset(&leg, 0, sizeof(leg));
            leg.hdr.domain_id = DNA_DOMAIN_CORE;
            leg.hdr.runtime_op = DNA_CORERULE_SPEND;
            leg.hdr.ruleset_version = 2; /* burn season: CORE v2         */
            leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
            leg.hdr.auth_kind = 1;
            leg.hdr.call_len = cl;
            leg.hdr.auth_len = alen;
            leg.hdr.res_max_effects = 40;
            leg.hdr.res_max_effect_bytes = 16384;
            leg.call_data = call;
            leg.auth_data = auth;
            dna_env_in_t in;
            memset(&in, 0, sizeof(in));
            in.fee_amount = FEE_MIN;
            in.res_max_total_units = 200000;
            in.leg_count = 1;
            in.legs = &leg;
            CHECK(dna_env_encode(&in, e15->bytes, sizeof(e15->bytes),
                                 &e15->len) == 0, "encode");
            free(auth);
            nodus_v2_envelope_t ve = { e15->bytes, e15->len };
            nodus_v2_block_t bs;
            mk_block(&bs, 4, &ve, 1);
            CHECK(apply_reject(fs.w, &bs, &rc) == 0 && rc == -1,
                  "zero-prefix pubkey must reject at the parse level");
            OK();
        }
        free(e15);
        fx_close(&fs);
    }

    /* checked-add overflow across inputs: THREE INT64_MAX utxos (each
     * individually representable and non-negative, so the malformed-row
     * guard passes) whose sum crosses UINT64_MAX at the third input —
     * the dna_ck_add_u64 path in exec is what fires. The supply row
     * cannot represent the total, so the invariant is made vacuous
     * (honest pre-genesis shape) and only the overflow verdict is
     * asserted. */
    {
        fixture_t fo;
        CHECK(fx_genesis(&fo, "ovf") == 0, "genesis");
        CHECK(run_sql(fo.w->db, "DELETE FROM supply_tracking") == 0,
              "vacuous supply");
        uint8_t na[64], nb[64], nc[64];
        CHECK(seed_utxo(&fo, 7, (uint64_t)INT64_MAX, 0xF1, 0, na) == 0 &&
              seed_utxo(&fo, 7, (uint64_t)INT64_MAX, 0xF2, 0, nb) == 0 &&
              seed_utxo(&fo, 7, (uint64_t)INT64_MAX, 0xF3, 0, nc) == 0,
              "seed");
        uint8_t insb[3][64];
        memcpy(insb[0], na, 64);
        memcpy(insb[1], nb, 64);
        memcpy(insb[2], nc, 64);
        out_spec_t oo[1] = { { 8, 5, 0x0B, NULL } };
        env_t eo;
        CHECK(spend_env(&fo, &eo, insb, 3, oo, 1, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { eo.bytes, eo.len };
        nodus_v2_block_t bo;
        mk_block(&bo, 1, &ve, 1);
        CHECK(apply_reject(fo.w, &bo, &rc) == 0 && rc == -1,
              "checked-add overflow must reject");
        OK();
        fx_close(&fo);
    }
    fx_close(&fx);
    return 0;
}

/* ══ 5. ENGINE — faults, restart, determinism ══════════════════════ */

static int test_engine(void) {
    /* fault injection at the new stages: digest-identical rollback */
    static const nodus_v2_apply_fail_t pts[7] = {
        V2AP_FAIL_AFTER_AUTH, V2AP_FAIL_AFTER_READ_PLAN,
        V2AP_FAIL_AFTER_READS, V2AP_FAIL_AFTER_EXEC_HOOK,
        V2AP_FAIL_AFTER_EFFECT_DECODE, V2AP_FAIL_AFTER_EFFECT_CHARGE,
        V2AP_FAIL_AFTER_ENV_EXEC   /* POST-mutation: the envelope's
                                    * adapter writes already landed —
                                    * the rollback must erase them      */
    };
    int s7[1] = { 7 };
    out_spec_t outs[2] = { { 8, 2000000, 0x01, NULL },
                           { 7, 2000000, 0x02, NULL } };
    for (int p = 0; p < 7; p++) {
        fixture_t fx;
        CHECK(fx_genesis(&fx, "fault") == 0, "genesis");
        uint8_t ins[1][64];
        memcpy(ins[0], g_nul_a, 64);
        env_t e;
        CHECK(spend_env(&fx, &e, ins, 1, outs, 2, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        nodus_v2_block_t b;
        mk_block(&b, 1, &ve, 1);
        b.fail_at = pts[p];
        b.fail_env_index = 0;
        int rc = 0;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "fault point must roll back byte-identically");
        OK();
        /* and the SAME block, un-faulted, commits (budgets restored) */
        b.fail_at = V2AP_FAIL_NONE;
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "clean re-apply after the fault must commit");
        OK();
        fx_close(&fx);
    }

    /* twin determinism + restart/replay idempotency */
    {
        fixture_t a, c;
        CHECK(fx_genesis(&a, "twinA") == 0, "genesis A");
        CHECK(fx_genesis(&c, "twinB") == 0, "genesis B");
        env_t e;
        uint8_t ins[1][64];
        memcpy(ins[0], g_nul_a, 64);
        CHECK(spend_env(&a, &e, ins, 1, outs, 2, FEE_MIN, s7, 1, NULL)
                  == 0, "build");
        /* the SAME bytes to both fixtures (chain ids are equal by
         * construction — same chain_id16, same genesis id) */
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        nodus_v2_block_t ba, bb;
        mk_block(&ba, 1, &ve, 1);
        mk_block(&bb, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "A commits");
        /* B applies in FOLLOWER mode: A's roots are the expectation, so
         * a divergent recomputation would reject (the mismatch legs of
         * the expectation matrix live in test_v2_apply) */
        bb.expect_tx_root = ba.out_tx_root;
        bb.expect_dupd_root = ba.out_dupd_root;
        bb.expect_domains_root = ba.out_domains_root;
        bb.expect_global_root = ba.out_global_root;
        CHECK(nodus_witness_v2_apply_block(c.w, &bb) == 0, "B commits");
        CHECK(memcmp(ba.out_global_root, bb.out_global_root, 64) == 0 &&
              memcmp(ba.out_tx_root, bb.out_tx_root, 64) == 0 &&
              memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0,
              "twin fixtures must land on byte-identical roots");
        OK();
        /* identical replay short-circuits BEFORE any expectation is
         * consulted (same height + same block id ⇒ rc 1, no writes) */
        nodus_v2_block_t bf;
        mk_block(&bf, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(c.w, &bf) == 1,
              "identical replay is idempotent (rc 1)");
        OK();
        /* restart: reopen the DB and replay the committed block */
        CHECK(fx_reopen(&a) == 0, "reopen");
        nodus_v2_block_t br;
        mk_block(&br, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(a.w, &br) == 1,
              "post-restart replay is idempotent (rc 1)");
        OK();
        fx_close(&a);
        fx_close(&c);
    }
    return 0;
}

/* ══ 7. CANONICAL INTENT IDENTITY (intent season) ══════════════════ */

/* Digest ONLY the consensus-owned state tables (rowid order — both twin
 * fixtures execute identical operation sequences, so rowids align). The
 * wire/audit surfaces (v2_blocks, v2_tx_index, v2_domain_updates,
 * v2_root_history, and v2_intent_index's tx_id column) are EXPECTED to
 * differ between authorization twins and are deliberately excluded. */
static int consensus_state_digest(nodus_witness_t *w, uint8_t out[64]) {
    static const char *const tables[] = {
        "utxo_set", "supply_tracking", "chain_config_history",
        "v2_domain_heads", "v2_dist_state", "v2_claims_spent",
        "v2_pools", "v2_pool_nullifiers"
    };
    dyn_t d = { 0 };
    int out_rc = -1;
    for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 tables[t]);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        if (dyn_put(&d, tables[t], strlen(tables[t]) + 1) != 0) {
            sqlite3_finalize(rs);
            goto done;
        }
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t ty = (uint8_t)sqlite3_column_type(rs, c);
                if (dyn_put(&d, &ty, 1) != 0) { sqlite3_finalize(rs);
                                                goto done; }
                if (ty == SQLITE_NULL) continue;
                const void *bp = sqlite3_column_blob(rs, c);
                uint32_t bl = (uint32_t)sqlite3_column_bytes(rs, c);
                if (dyn_put(&d, &bl, 4) != 0 ||
                    (bl > 0 && dyn_put(&d, bp, bl) != 0)) {
                    sqlite3_finalize(rs);
                    goto done;
                }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    out_rc = qgp_sha3_512(d.buf ? d.buf : (const uint8_t *)"", d.len, out)
                 == 0 ? 0 : -1;
done:
    free(d.buf);
    return out_rc;
}

/* Derive both identities of an envelope's bytes exactly as the engine
 * does (single-leg CORE or SYSTEM fixture shapes). */
static int derive_ids(fixture_t *fx, const env_t *e, uint32_t domain,
                      uint8_t wire_out[64], uint8_t intent_out[64]) {
    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    if (!bt || n != 2) return -1;
    const nodus_domain_runtime_t *rt =
        domain == DNA_DOMAIN_SYSTEM ? &bt[0] : &bt[1];
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = domain;
    lctx.ruleset_version = rt->ruleset_version;
    memcpy(lctx.ruleset_hash, rt->ruleset_hash, 64);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    int rc = -1;
    if (dna_env_preflight(e->bytes, e->len, fx->chain_id, 1, &lctx, 1,
                          pf) == DNA_ENV_PF_OK) {
        memcpy(wire_out, pf->wire_id, 64);
        memcpy(intent_out, pf->intent_id, 64);
        rc = 0;
    }
    free(pf);
    return rc;
}

static int test_intent_engine(void) {
    int s7[1] = { 7 };
    out_spec_t outs[2] = {
        { 8, 2000000, 0x01, NULL },
        { 7, 2000000, 0x02, NULL }
    };
    uint8_t ins[1][64];
    int rc = 0;

    /* ── SPEND TWIN EXECUTION across independent identical fixtures:
     * realization A on fixture A, a DIFFERENT valid signature
     * realization of the SAME intent on fixture B. Consensus state and
     * roots must match byte-for-byte; the wire surfaces must not. ──── */
    {
        fixture_t a, b2;
        CHECK(fx_genesis(&a, "intA") == 0, "genesis A");
        CHECK(fx_genesis(&b2, "intB") == 0, "genesis B");
        memcpy(ins[0], g_nul_a, 64);
        env_t ea, eb;
        CHECK(spend_env(&a, &ea, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "build A");
        CHECK(spend_env(&b2, &eb, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "build B");
        CHECK(ea.len == eb.len && memcmp(ea.bytes, eb.bytes, ea.len) != 0,
              "randomized signing must give distinct realizations");
        OK();

        uint8_t wa[64], ia[64], wb[64], ib[64];
        CHECK(derive_ids(&a, &ea, DNA_DOMAIN_CORE, wa, ia) == 0 &&
              derive_ids(&b2, &eb, DNA_DOMAIN_CORE, wb, ib) == 0,
              "derive");
        CHECK(memcmp(ia, ib, 64) == 0, "twins must share ONE intent_id");
        CHECK(memcmp(wa, wb, 64) != 0, "twins must have DISTINCT wire_ids");
        OK();

        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vb = { eb.bytes, eb.len };
        nodus_v2_block_t ba, bb;
        mk_block(&ba, 1, &va, 1);
        mk_block(&bb, 1, &vb, 1);
        mk_id(bb.block_id, 0xC1);       /* different wire ⇒ a different
                                         * block — ids must not collide  */
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "A commits");
        CHECK(nodus_witness_v2_apply_block(b2.w, &bb) == 0, "B commits");
        OK();

        /* consensus partition: state + state-bearing roots IDENTICAL */
        uint8_t da[64], db[64];
        CHECK(consensus_state_digest(a.w, da) == 0 &&
              consensus_state_digest(b2.w, db) == 0, "digest");
        CHECK(memcmp(da, db, 64) == 0,
              "consensus state tables must be byte-identical across "
              "authorization twins");
        CHECK(memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0 &&
              memcmp(ba.out_global_root, bb.out_global_root, 64) == 0,
              "domain/global roots must be twin-identical");
        /* wire partition: full-wire tx roots DIFFER (correct, §11) */
        CHECK(memcmp(ba.out_tx_root, bb.out_tx_root, 64) != 0,
              "wire tx roots must differ between twins");
        OK();

        /* the semantic index carries the SAME intent under each fixture's
         * OWN wire realization */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(a.w->db,
                  "SELECT intent_id, tx_id FROM v2_intent_index",
                  -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), ia, 64) == 0 &&
                  memcmp(sqlite3_column_blob(st, 1), wa, 64) == 0,
                  "A's intent row");
            sqlite3_finalize(st);
            st = NULL;
            CHECK(sqlite3_prepare_v2(b2.w->db,
                  "SELECT intent_id, tx_id FROM v2_intent_index",
                  -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), ib, 64) == 0 &&
                  memcmp(sqlite3_column_blob(st, 1), wb, 64) == 0,
                  "B's intent row");
            sqlite3_finalize(st);
            OK();
        }

        /* UTXO provenance is the intent — byte-identical rows, and NOT
         * either wire id */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(a.w->db,
                  "SELECT tx_hash FROM utxo_set WHERE block_height=1 "
                  "LIMIT 1", -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), ia, 64) == 0,
                  "UTXO provenance == intent_id");
            sqlite3_finalize(st);
            OK();
        }

        /* ── COMMITTED-INTENT REPLAY, later block, THIRD realization —
         * rejected by the intent guard with digest-identical rollback
         * (both the intent guard and the spent-input guard would kill
         * it; the intent guard fires first, pre-BEGIN). ────────────── */
        {
            env_t ec;
            CHECK(spend_env(&a, &ec, ins, 1, outs, 2, FEE_MIN, s7, 1,
                            NULL) == 0, "build C");
            CHECK(memcmp(ec.bytes, ea.bytes, ea.len) != 0, "distinct");
            nodus_v2_envelope_t vc = { ec.bytes, ec.len };
            nodus_v2_block_t bc;
            mk_block(&bc, 2, &vc, 1);
            CHECK(apply_reject(a.w, &bc, &rc) == 0 && rc == -1,
                  "committed intent under a new witness must reject");
            OK();

            /* REOPEN: the guard reads COMMITTED state — protection
             * survives a database restart */
            CHECK(fx_reopen(&a) == 0, "reopen");
            nodus_v2_block_t bd;
            mk_block(&bd, 2, &vc, 1);
            CHECK(apply_reject(a.w, &bd, &rc) == 0 && rc == -1,
                  "intent replay protection must survive reopen");
            OK();

            /* byte-identical committed-block replay is STILL idempotent
             * (whole-block matrix runs before the intent guard) */
            nodus_v2_block_t be;
            mk_block(&be, 1, &va, 1);
            CHECK(nodus_witness_v2_apply_block(a.w, &be) == 1,
                  "committed-block replay stays idempotent");
            OK();

            /* RESURRECTED-INPUT REPLAY — the case where the intent guard
             * is the ONLY thing standing: fixture surgery re-creates the
             * spent input (and keeps the supply identity consistent), so
             * a same-intent/different-witness realization would EXECUTE
             * CLEANLY if the guard keyed on the wrong identity. It must
             * still reject as a VERDICT (-1) with a digest-identical
             * rollback — a guard that missed would instead die on the
             * v2_intent_index UNIQUE backstop as a node fault (-2), or
             * worse, double-apply. */
            {
                CHECK(seed_utxo(&a, 7, UTXO_A, 0xA1, 0, ins[0]) == 0,
                      "resurrect spent input");
                /* also remove block 1's created outputs, so the replay's
                 * CREATEs face ABSENT keys — under a mutant guard the
                 * whole execution would go clean and the UNIQUE backstop
                 * (a -2 fault, not a -1 verdict) would be the only thing
                 * left. Net utxo delta = +UTXO_A − (2×2,000,000) =
                 * +FEE_MIN; genesis is rebalanced by exactly that so the
                 * CORE conservation identity keeps holding. */
                CHECK(run_sql(a.w->db,
                      "DELETE FROM utxo_set WHERE block_height = 1") == 0,
                      "clear block-1 outputs");
                char sql[256];
                snprintf(sql, sizeof(sql),
                         "UPDATE supply_tracking SET "
                         "genesis_supply = genesis_supply + %llu, "
                         "current_supply = current_supply + %llu",
                         (unsigned long long)FEE_MIN,
                         (unsigned long long)FEE_MIN);
                CHECK(run_sql(a.w->db, sql) == 0, "rebalance supply");
                env_t ef;
                CHECK(spend_env(&a, &ef, ins, 1, outs, 2, FEE_MIN, s7, 1,
                                NULL) == 0, "build F");
                nodus_v2_envelope_t vf = { ef.bytes, ef.len };
                nodus_v2_block_t bf2;
                mk_block(&bf2, 2, &vf, 1);
                CHECK(apply_reject(a.w, &bf2, &rc) == 0 && rc == -1,
                      "resurrected-input intent replay must reject as a "
                      "verdict — the intent guard, not the backstop");
                OK();
            }
        }
        fx_close(&a);
        fx_close(&b2);
    }

    /* ── CHAIN_CONFIG TWINS: same proposal, two different valid
     * committee subsets (exact quorum {0..4} vs {1..5}, and the
     * all-validator set) — one intent; SYSTEM state twin-identical. ── */
    {
        fixture_t a, b2, c;
        CHECK(fx_genesis(&a, "ccA") == 0, "genesis ccA");
        CHECK(fx_genesis(&b2, "ccB") == 0, "genesis ccB");
        CHECK(fx_genesis(&c, "ccC") == 0, "genesis ccC");
        int q1v[5] = { 0, 1, 2, 3, 4 };
        int q2v[5] = { 1, 2, 3, 4, 5 };
        int q7v[7] = { 0, 1, 2, 3, 4, 5, 6 };
        env_t ea, eb, ec;
        CHECK(cc_env(&a, &ea, 1, 1, 5, 1000, 0x42, 1, 2000, q1v, 5, 0,
                     NULL, NULL) == 0, "build ccA");
        CHECK(cc_env(&b2, &eb, 1, 1, 5, 1000, 0x42, 1, 2000, q2v, 5, 0,
                     NULL, NULL) == 0, "build ccB");
        CHECK(cc_env(&c, &ec, 1, 1, 5, 1000, 0x42, 1, 2000, q7v, 7, 0,
                     NULL, NULL) == 0, "build ccC (all validators)");

        uint8_t wa[64], ia[64], wb[64], ib[64], wc[64], ic[64];
        CHECK(derive_ids(&a, &ea, DNA_DOMAIN_SYSTEM, wa, ia) == 0 &&
              derive_ids(&b2, &eb, DNA_DOMAIN_SYSTEM, wb, ib) == 0,
              "derive cc");
        CHECK(memcmp(ia, ib, 64) == 0,
              "different committee subsets: ONE intent");
        CHECK(memcmp(wa, wb, 64) != 0,
              "different committee subsets: DISTINCT wire ids");
        /* all-N approval set: DIFFERENT auth_len — intent still equal */
        CHECK(derive_ids(&c, &ec, DNA_DOMAIN_SYSTEM, wc, ic) == 0,
              "derive ccC");
        CHECK(memcmp(ia, ic, 64) == 0,
              "exact quorum vs all-validator set: ONE intent");
        CHECK(memcmp(wa, wc, 64) != 0, "distinct wire id (all-N)");
        OK();

        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vb = { eb.bytes, eb.len };
        nodus_v2_envelope_t vc = { ec.bytes, ec.len };
        nodus_v2_block_t ba, bb, bc;
        mk_block(&ba, 1, &va, 1);
        mk_block(&bb, 1, &vb, 1);
        mk_block(&bc, 1, &vc, 1);
        mk_id(bb.block_id, 0xC2);
        mk_id(bc.block_id, 0xC3);
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "ccA commits");
        CHECK(nodus_witness_v2_apply_block(b2.w, &bb) == 0, "ccB commits");
        CHECK(nodus_witness_v2_apply_block(c.w, &bc) == 0, "ccC commits");
        OK();

        uint8_t da[64], db[64], dc[64];
        CHECK(consensus_state_digest(a.w, da) == 0 &&
              consensus_state_digest(b2.w, db) == 0 &&
              consensus_state_digest(c.w, dc) == 0, "digest cc");
        CHECK(memcmp(da, db, 64) == 0 && memcmp(da, dc, 64) == 0,
              "SYSTEM consensus state must be identical across committee "
              "subsets (incl. the cc history row's intent provenance)");
        CHECK(memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0 &&
              memcmp(ba.out_domains_root, bc.out_domains_root, 64) == 0,
              "SYSTEM roots twin-identical");
        CHECK(memcmp(ba.out_tx_root, bb.out_tx_root, 64) != 0,
              "cc wire tx roots differ");
        OK();

        /* the committed history row's provenance IS the intent */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(a.w->db,
                  "SELECT tx_hash FROM chain_config_history WHERE "
                  "param_id=1 AND effective_block=1000",
                  -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), ia, 64) == 0,
                  "cc history provenance == intent_id");
            sqlite3_finalize(st);
            OK();
        }

        /* NO-INPUT SYSTEM REPLAY: the same proposal under yet another
         * valid subset in a LATER block — an inputless transaction has
         * no spent-row guard, so the intent guard is the ONLY semantic
         * protection. It must reject with rollback. */
        {
            env_t er;
            int q3v[5] = { 2, 3, 4, 5, 6 };
            CHECK(cc_env(&a, &er, 2, 1, 5, 1000, 0x42, 1, 2000, q3v, 5,
                         0, NULL, NULL) == 0, "build replay");
            nodus_v2_envelope_t vr = { er.bytes, er.len };
            nodus_v2_block_t br;
            mk_block(&br, 2, &vr, 1);
            CHECK(apply_reject(a.w, &br, &rc) == 0 && rc == -1,
                  "no-input SYSTEM intent replay must reject");
            OK();
        }

        /* MATCHING INTENT IS NEVER EVIDENCE OF AUTHORIZATION: a
         * realization of the already-committed intent carrying an
         * INVALID signature must reject as a VERDICT (-1) — never
         * commit, never soften to a fault. */
        {
            env_t ebad;
            int q4v[5] = { 0, 1, 2, 3, 4 };
            sign_opt_t so;
            memset(&so, 0, sizeof(so));
            so.break_sig = 1;
            CHECK(cc_env(&a, &ebad, 2, 1, 5, 1000, 0x42, 1, 2000, q4v,
                         5, 0, NULL, &so) == 0, "build bad-sig replay");
            nodus_v2_envelope_t vb2 = { ebad.bytes, ebad.len };
            nodus_v2_block_t bb2;
            mk_block(&bb2, 2, &vb2, 1);
            CHECK(apply_reject(a.w, &bb2, &rc) == 0 && rc == -1,
                  "matching intent is never evidence of authorization");
            OK();
        }
        fx_close(&a);
        fx_close(&b2);
        fx_close(&c);
    }

    /* ── CROSS-CHAIN: the same semantic content on another chain is a
     * DIFFERENT intent (chain_id is in the preimage) — and the foreign
     * envelope still dies on the chain binding (signature over the
     * foreign chain's digest). ─────────────────────────────────────── */
    {
        fixture_t a, o;
        CHECK(fx_genesis(&a, "xcA") == 0, "genesis xcA");
        /* a SECOND CHAIN: same keys, same funded state, different
         * committed genesis id ⇒ different derived chain id */
        g_gid_fill = 0xEF;
        int orc = fx_genesis(&o, "xcO");
        g_gid_fill = 0xEE;
        CHECK(orc == 0, "genesis xcO (other chain)");
        memcpy(ins[0], g_nul_a, 64);
        env_t ea;
        CHECK(spend_env(&a, &ea, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "build xc");
        uint8_t wa[64], ia[64], wo[64], io[64];
        CHECK(derive_ids(&a, &ea, DNA_DOMAIN_CORE, wa, ia) == 0, "ids A");
        CHECK(memcmp(a.chain_id, o.chain_id, 32) != 0,
              "fixtures must be different chains");
        CHECK(derive_ids(&o, &ea, DNA_DOMAIN_CORE, wo, io) == 0, "ids O");
        CHECK(memcmp(ia, io, 64) != 0,
              "cross-chain: intents must differ");
        OK();
        /* the foreign chain still REJECTS the envelope: its auth digest
         * differs, so every signature fails verification. prev links to
         * chain O's OWN genesis id so the block reaches the auth stage
         * rather than dying at height linkage. */
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_block_t bo;
        mk_block(&bo, 1, &va, 1);
        mk_id(bo.prev_block_id, 0xEF);
        CHECK(apply_reject(o.w, &bo, &rc) == 0 && rc == -1,
              "cross-chain replay must fail the chain binding");
        OK();
        fx_close(&a);
        fx_close(&o);
    }

    /* ── FAULT POINTS F35 (post-guard, pre-BEGIN) and F36 (after the
     * intent-index insert, inside the transaction): full digest
     * rollback, no identity index rows, clean retry commits. ───────── */
    {
        fixture_t fx;
        CHECK(fx_genesis(&fx, "f3536") == 0, "genesis f");
        memcpy(ins[0], g_nul_a, 64);
        env_t e;
        CHECK(spend_env(&fx, &e, ins, 1, outs, 2, FEE_MIN, s7, 1,
                        NULL) == 0, "build f");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        nodus_v2_block_t b;

        mk_block(&b, 1, &ve, 1);
        b.fail_at = V2AP_FAIL_AFTER_INTENT_GUARD;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "F35 must reject with digest-identical rollback");
        OK();
        mk_block(&b, 1, &ve, 1);
        b.fail_at = V2AP_FAIL_AFTER_INTENT_INDEX;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "F36 must reject with digest-identical rollback");
        /* the interrupted block committed NEITHER identity index */
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_intent_index") == 0,
              "F36 left an intent row");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index") == 0,
              "F36 left a wire row");
        OK();
        /* clean retry commits, and BOTH indices land atomically */
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "clean retry after faults must commit");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_intent_index") == 1 &&
              q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index") == 1,
              "both identity indices committed");
        OK();
        fx_close(&fx);
    }

    return 0;
}

/* ══ 8. CORE slice — BURN (burn season) ════════════════════════════ */

/* BURN call v1 builder: SPEND transfer section ‖ burn_amount u64 BE. */
static uint32_t burn_call_build(uint8_t *dst, size_t cap,
                                const void *ins_v, int n_in,
                                const out_spec_t *outs, int n_out,
                                uint64_t burn) {
    uint32_t cl = spend_call_build(dst, cap, ins_v, n_in, outs, n_out);
    if (!cl || (size_t)cl + 8 > cap) return 0;
    for (int i = 0; i < 8; i++)
        dst[cl + i] = (uint8_t)(burn >> (56 - 8 * i));
    return cl + 8;
}

static int burn_env(fixture_t *fx, env_t *e,
                    const void *ins, int n_in,
                    const out_spec_t *outs, int n_out,
                    uint64_t fee, uint64_t burn,
                    const int *signers, int n_signers,
                    const sign_opt_t *opt) {
    static uint8_t call[8192];
    uint32_t cl = burn_call_build(call, sizeof(call), ins, n_in, outs,
                                  n_out, burn);
    if (!cl) return -1;
    return env_build_signed(fx, e, DNA_DOMAIN_CORE, DNA_CORERULE_BURN,
                            call, cl, fee, 0, 40, 16384, signers,
                            n_signers, opt);
}

/* seed one CORE utxo carrying a CUSTOM token (the token wrong-asset
 * legs). Token value is outside the native conservation identity, so no
 * supply rebalance is needed. */
static int seed_token_utxo(fixture_t *fx, int k, uint64_t amount,
                           uint8_t seed_byte, const uint8_t token[64],
                           uint8_t nul_out[64]) {
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
            "(?1, ?2, ?3, ?4, zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul_out, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp[k], 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    sqlite3_bind_blob(st, 4, token, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* the full persisted DomainHead blob — byte-identity across a block
 * proves the domain was NOT touched (root, height, last_updated all
 * inside). */
static int head_blob(nodus_witness_t *w, uint32_t dom, uint8_t out[89]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT head FROM v2_domain_heads WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    int rc = sqlite3_step(st);
    int ok = -1;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 89) {
        memcpy(out, sqlite3_column_blob(st, 0), 89);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

static int test_core_burn(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "burn") == 0, "genesis");
    int s7[1] = { 7 };
    int s8[1] = { 8 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    uint8_t ins1[1][64];
    memcpy(ins1[0], g_nul_a, 64);

    /* extra fixture rows: one LOCKED native utxo, one CUSTOM-token utxo */
    CHECK(seed_utxo(&fx, 7, 1500000 + FEE_MIN, 0xE2, 100000,
                    g_nul_lock) == 0, "seed locked");
    {
        char sql[192];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = "
                 "genesis_supply + %llu, current_supply = "
                 "current_supply + %llu WHERE id = 1",
                 (unsigned long long)(1500000 + FEE_MIN),
                 (unsigned long long)(1500000 + FEE_MIN));
        CHECK(run_sql(fx.w->db, sql) == 0, "supply seed");
    }
    static uint8_t tokT[64];
    memset(tokT, 0x71, sizeof(tokT));
    uint8_t nul_tok[64];
    CHECK(seed_token_utxo(&fx, 7, 500, 0xD1, tokT, nul_tok) == 0,
          "seed token utxo");

    /* ── negatives (each a digest-proven no-op) ─────────────────────── */
    /* zero burn amount — a zero burn IS a SPEND (canonical form) */
    {
        out_spec_t o[1] = { { 8, UTXO_A - FEE_MIN, 0x11, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN, 0, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "zero burn amount must reject");
        OK();
    }
    /* insufficient input: outputs + fee already consume everything, the
     * burn has no funding */
    {
        out_spec_t o[1] = { { 8, UTXO_A - FEE_MIN, 0x12, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN, 1000000, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unfunded burn must reject");
        OK();
    }
    /* checked-add overflow: fee + burn_amount wraps. BALANCED FOR THE
     * WRAPPED VALUE on purpose (review round): fee(10^6) + UINT64_MAX
     * wraps to 999,999, and out 4,000,001 + 999,999 == in 5,000,000 —
     * so if the checked add were removed, conservation would PASS and
     * the leg would commit. The ck_add is the only violated rule. */
    {
        out_spec_t o[1] = { { 8, 4000001, 0x13, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN, UINT64_MAX,
                       s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "fee+burn overflow must reject");
        OK();
    }
    /* duplicate input (hand-corrupted call, two identical nullifiers).
     * BALANCED FOR THE DOUBLED SUM on purpose (review round): out
     * 8,999,999 + fee 10^6 + burn 1 == 2×UTXO_A, so conservation is NOT
     * the rejecting rule — the duplicate itself is (parse dedup, with
     * the engine's read-order dedup and the effect codec's logical-key
     * uniqueness as the deeper layers). */
    {
        static uint8_t call[8192];
        out_spec_t o[1] = { { 8, 8999999, 0x14, NULL } };
        uint32_t cl = burn_call_build(call, sizeof(call), ins1, 1, o, 1,
                                      1);
        CHECK(cl > 0, "call");
        static uint8_t call2[8192];
        call2[0] = 2;
        memcpy(call2 + 1, g_nul_a, 64);
        memcpy(call2 + 65, g_nul_a, 64);
        memcpy(call2 + 129, call + 65, cl - 65);
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_BURN, call2, cl + 64,
                               FEE_MIN, 0, 40, 16384, s7, 1, NULL) == 0,
              "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate burn input must reject");
        OK();
    }
    /* wrong owner (key8's utxo, key7 signs; balanced on purpose) */
    {
        uint8_t insc[1][64];
        memcpy(insc[0], g_nul_c, 64);
        out_spec_t o[1] = { { 8, UTXO_C - FEE_MIN - 1, 0x15, NULL } };
        CHECK(burn_env(&fx, &e, insc, 1, o, 1, FEE_MIN, 1, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unowned burn input must reject");
        OK();
    }
    /* invalid signature (valid shape otherwise) */
    {
        out_spec_t o[1] = { { 7, 2000000, 0x16, NULL } };
        sign_opt_t so;
        memset(&so, 0, sizeof(so));
        so.break_sig = 1;
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN,
                       UTXO_A - 2000000 - FEE_MIN, s7, 1, &so) == 0,
              "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "invalid burn signature must reject");
        OK();
    }
    /* wrong asset: a TOKEN deficit is not an expressible burn — the
     * legacy lane cannot represent one either (nothing decrements
     * tokens.supply) */
    {
        uint8_t ins2[2][64];
        memcpy(ins2[0], g_nul_a, 64);
        memcpy(ins2[1], nul_tok, 64);
        /* native balanced exactly (in A = change + fee + burn); the
         * token's 500 units simply vanish — MUST reject */
        out_spec_t o[1] = { { 7, UTXO_A - FEE_MIN - 1, 0x17, NULL } };
        CHECK(burn_env(&fx, &e, ins2, 2, o, 1, FEE_MIN, 1, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "token burn (deficit) must reject");
        OK();
        /* partial token deficit rejects too */
        out_spec_t o2[2] = { { 7, UTXO_A - FEE_MIN - 1, 0x18, NULL },
                             { 7, 400, 0x19, tokT } };
        CHECK(burn_env(&fx, &e, ins2, 2, o2, 2, FEE_MIN, 1, s7, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve2 = { e.bytes, e.len };
        mk_block(&b, 1, &ve2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "partial token burn must reject");
        OK();
    }
    /* fee mismatch: equation balanced for FEE_MIN, envelope declares
     * FEE_MIN + 1 */
    {
        out_spec_t o[1] = { { 8, UTXO_A - FEE_MIN - 1000, 0x1A, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN + 1, 1000, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "burn fee mismatch must reject");
        OK();
    }
    /* fee below the shipped floors (balanced on purpose) */
    {
        out_spec_t o[1] = { { 8, UTXO_A - FEE_MIN, 0x1B, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN - 1, 1, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "sub-floor burn fee must reject");
        OK();
    }
    /* locked input */
    {
        uint8_t insl[1][64];
        memcpy(insl[0], g_nul_lock, 64);
        out_spec_t o[1] = { { 7, 1000000, 0x1C, NULL } };
        CHECK(burn_env(&fx, &e, insl, 1, o, 1, FEE_MIN, 500000, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "locked burn input must reject");
        OK();
    }
    /* CROSS-OP replay negatives: the byte shapes are mutually
     * unparseable — a BURN call under SPEND has 8 trailing bytes, a
     * SPEND call under BURN is 8 short */
    {
        static uint8_t call[8192];
        out_spec_t o[1] = { { 8, 2000000, 0x1D, NULL } };
        uint32_t cl = burn_call_build(call, sizeof(call), ins1, 1, o, 1,
                                      UTXO_A - 2000000 - FEE_MIN);
        CHECK(cl > 0, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SPEND, call, cl, FEE_MIN, 0,
                               40, 16384, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "BURN call bytes under runtime_op SPEND must reject");
        OK();
        uint32_t cl2 = spend_call_build(call, sizeof(call), ins1, 1, o,
                                        1);
        CHECK(cl2 > 0, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_BURN, call, cl2, FEE_MIN, 0,
                               40, 16384, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve2 = { e.bytes, e.len };
        mk_block(&b, 1, &ve2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "SPEND call bytes under runtime_op BURN must reject");
        OK();
    }

    /* ── POSITIVE 1: burn with change ───────────────────────────────── */
    uint8_t sys_head0[89];
    CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_head0) == 0, "sys head");
    uint8_t core_root0[64];
    CHECK(head_root(fx.w, DNA_DOMAIN_CORE, core_root0) == 0, "core root");
    uint64_t burned0 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint64_t supply0 = q1(fx.w,
                          "SELECT current_supply FROM supply_tracking");
    env_t e_p1;
    uint8_t p1_wire[64], p1_intent[64];
    {
        out_spec_t o[1] = { { 7, 2000000, 0x20, NULL } };
        CHECK(burn_env(&fx, &e_p1, ins1, 1, o, 1, FEE_MIN, 2000000, s7,
                       1, NULL) == 0, "build");
        CHECK(derive_ids(&fx, &e_p1, DNA_DOMAIN_CORE, p1_wire,
                         p1_intent) == 0, "ids");
        nodus_v2_envelope_t ve = { e_p1.bytes, e_p1.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "burn with change must commit");
        OK();
        /* the exact before/after invariant, named buckets (the season's
         * §6 proof): total_burned += fee + burn, current_supply -= the
         * same, input row GONE, exactly one change row created */
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned0 + FEE_MIN + 2000000,
              "total_burned == before + fee + burn_amount");
        CHECK(q1(fx.w, "SELECT current_supply FROM supply_tracking")
                  == supply0 - (FEE_MIN + 2000000),
              "current_supply fell by exactly fee + burn_amount");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT COUNT(*) FROM utxo_set WHERE nullifier=?1",
                  -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, g_nul_a, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 0,
              "burned input must be consumed");
            sqlite3_finalize(st);
        }
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "block_height=1") == 1, "exactly one change row");
        /* provenance: the change row binds the INTENT identity */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT tx_hash, created_at FROM utxo_set WHERE "
                  "block_height=1", -1, &st, NULL) == SQLITE_OK &&
                  sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), p1_intent, 64) == 0 &&
                  sqlite3_column_int64(st, 1) == 0,
                  "change provenance == intent_id, created_at == 0");
            sqlite3_finalize(st);
        }
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        /* CORE root moved; SYSTEM head byte-unchanged (untouched domain
         * does not advance) */
        uint8_t core_root1[64], sys_head1[89];
        CHECK(head_root(fx.w, DNA_DOMAIN_CORE, core_root1) == 0 &&
              memcmp(core_root0, core_root1, 64) != 0,
              "CORE root must move");
        CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_head1) == 0 &&
              memcmp(sys_head0, sys_head1, 89) == 0,
              "SYSTEM head must not move on a CORE burn");
        OK();
    }

    /* already-spent input (the consumed A) in a later block */
    {
        out_spec_t o[1] = { { 7, 2000000, 0x21, NULL } };
        CHECK(burn_env(&fx, &e, ins1, 1, o, 1, FEE_MIN, 2000000, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "already-spent burn input must reject");
        OK();
    }
    /* semantic replay under a DIFFERENT auth witness (same intent) */
    {
        env_t e2;
        out_spec_t o[1] = { { 7, 2000000, 0x20, NULL } };
        CHECK(burn_env(&fx, &e2, ins1, 1, o, 1, FEE_MIN, 2000000, s7, 1,
                       NULL) == 0, "build twin");
        CHECK(memcmp(e2.bytes, e_p1.bytes, e_p1.len) != 0, "distinct");
        uint8_t w2[64], i2[64];
        CHECK(derive_ids(&fx, &e2, DNA_DOMAIN_CORE, w2, i2) == 0, "ids");
        CHECK(memcmp(i2, p1_intent, 64) == 0 &&
              memcmp(w2, p1_wire, 64) != 0,
              "twin: same intent, different wire");
        nodus_v2_envelope_t ve = { e2.bytes, e2.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "burn replay under a new witness must reject");
        OK();
    }

    /* ── POSITIVE 2: full-value burn (no outputs) ───────────────────── */
    {
        uint64_t burned_pre = q1(fx.w,
                                 "SELECT total_burned FROM supply_tracking");
        uint8_t insb[1][64];
        memcpy(insb[0], g_nul_b, 64);
        CHECK(burn_env(&fx, &e, insb, 1, NULL, 0, FEE_MIN,
                       UTXO_B - FEE_MIN, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "full-value burn must commit");
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned_pre + UTXO_B,
              "full value entered total_burned");
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        OK();
    }

    /* ── POSITIVE 3: smallest burn (1 raw unit), second owner ───────── */
    {
        uint64_t burned_pre = q1(fx.w,
                                 "SELECT total_burned FROM supply_tracking");
        uint8_t insc[1][64];
        memcpy(insc[0], g_nul_c, 64);
        out_spec_t o[1] = { { 8, UTXO_C - FEE_MIN - 1, 0x22, NULL } };
        CHECK(burn_env(&fx, &e, insc, 1, o, 1, FEE_MIN, 1, s8, 1, NULL)
                  == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "smallest burn must commit");
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned_pre + FEE_MIN + 1, "burn of exactly 1 unit");
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        OK();
    }

    /* ── POSITIVE 4: balanced token PASS-THROUGH rides a native burn ── */
    {
        uint64_t burned_pre = q1(fx.w,
                                 "SELECT total_burned FROM supply_tracking");
        /* inputs: the token row plus P1's change output (key 7, seed
         * 0x20, 2M) */
        uint8_t chg[64];
        CHECK(out_nul(7, 0x20, chg) == 0, "chg id");
        uint8_t ins2[2][64];
        memcpy(ins2[0], chg, 64);
        memcpy(ins2[1], nul_tok, 64);
        out_spec_t o[2] = { { 7, 500000, 0x23, NULL },
                            { 7, 500, 0x24, tokT } };
        CHECK(burn_env(&fx, &e, ins2, 2, o, 2, FEE_MIN,
                       2000000 - 500000 - FEE_MIN, s7, 1, NULL) == 0,
              "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "token pass-through burn must commit");
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned_pre + 2000000 - 500000,
              "only native value burned");
        /* the token moved intact */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT COALESCE(SUM(amount),0) FROM utxo_set WHERE "
                  "token_id=?1", -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, tokT, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 500,
                  "token value conserved across the burn");
            sqlite3_finalize(st);
        }
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        OK();
    }
    fx_close(&fx);

    /* ── AUTH-WITNESS TWINS across independent fixtures ─────────────── */
    {
        fixture_t a, b2;
        CHECK(fx_genesis(&a, "bwtA") == 0, "genesis A");
        CHECK(fx_genesis(&b2, "bwtB") == 0, "genesis B");
        uint8_t insa[1][64];
        memcpy(insa[0], g_nul_a, 64);
        out_spec_t o[1] = { { 7, 2000000, 0x25, NULL } };
        env_t ea, eb;
        CHECK(burn_env(&a, &ea, insa, 1, o, 1, FEE_MIN, 2000000, s7, 1,
                       NULL) == 0, "build A");
        CHECK(burn_env(&b2, &eb, insa, 1, o, 1, FEE_MIN, 2000000, s7, 1,
                       NULL) == 0, "build B");
        uint8_t wa[64], ia[64], wb[64], ib[64];
        CHECK(derive_ids(&a, &ea, DNA_DOMAIN_CORE, wa, ia) == 0 &&
              derive_ids(&b2, &eb, DNA_DOMAIN_CORE, wb, ib) == 0, "ids");
        CHECK(memcmp(ia, ib, 64) == 0 && memcmp(wa, wb, 64) != 0,
              "burn twins: one intent, two wires");
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vb = { eb.bytes, eb.len };
        nodus_v2_block_t ba, bb;
        mk_block(&ba, 1, &va, 1);
        mk_block(&bb, 1, &vb, 1);
        mk_id(bb.block_id, 0xC4);
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "A commits");
        CHECK(nodus_witness_v2_apply_block(b2.w, &bb) == 0, "B commits");
        uint8_t da[64], db[64];
        CHECK(consensus_state_digest(a.w, da) == 0 &&
              consensus_state_digest(b2.w, db) == 0, "digest");
        CHECK(memcmp(da, db, 64) == 0 &&
              memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0 &&
              memcmp(ba.out_global_root, bb.out_global_root, 64) == 0,
              "burn twins: consensus state + roots identical");
        CHECK(memcmp(ba.out_tx_root, bb.out_tx_root, 64) != 0,
              "burn twins: wire tx roots differ");
        OK();
        fx_close(&a);
        fx_close(&b2);
    }

    /* ── CROSS-CHAIN + CROSS-DOMAIN replay negatives ────────────────── */
    {
        fixture_t a, o2;
        CHECK(fx_genesis(&a, "bxcA") == 0, "genesis A");
        g_gid_fill = 0xF0;
        int orc = fx_genesis(&o2, "bxcO");
        g_gid_fill = 0xEE;
        CHECK(orc == 0, "genesis O");
        uint8_t insa[1][64];
        memcpy(insa[0], g_nul_a, 64);
        out_spec_t o[1] = { { 7, 2000000, 0x26, NULL } };
        env_t ea;
        CHECK(burn_env(&a, &ea, insa, 1, o, 1, FEE_MIN, 2000000, s7, 1,
                       NULL) == 0, "build");
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_block_t bo;
        mk_block(&bo, 1, &va, 1);
        mk_id(bo.prev_block_id, 0xF0);
        CHECK(apply_reject(o2.w, &bo, &rc) == 0 && rc == -1,
              "cross-chain burn replay must fail the chain binding");
        OK();
        /* cross-domain: the same call bytes as a SYSTEM leg — SYSTEM
         * owns no runtime_op 2 semantics for them (admission owns the
         * rule ids; op 2 IS a SYSTEM rule id (DELEGATE), so this dies
         * on the auth binding/exec rules — either way a VERDICT) */
        {
            static uint8_t call[8192];
            uint32_t cl = burn_call_build(call, sizeof(call), insa, 1,
                                          o, 1, 2000000);
            CHECK(cl > 0, "call");
            CHECK(env_build_signed(&a, &e, DNA_DOMAIN_SYSTEM,
                                   DNA_CORERULE_BURN, call, cl, 0, 0,
                                   40, 16384, s7, 1, NULL) == 0,
                  "build");
            nodus_v2_envelope_t vs = { e.bytes, e.len };
            nodus_v2_block_t bs;
            mk_block(&bs, 1, &vs, 1);
            CHECK(apply_reject(a.w, &bs, &rc) == 0 && rc == -1,
                  "burn call routed to SYSTEM must reject");
            OK();
        }
        fx_close(&a);
        fx_close(&o2);
    }

    /* ── F37 mid-effect-list faults + the per-leg points, then a clean
     * retry (a burn-with-change leg applies effects
     * [CREATE change, SET burned, DELETE input]) ────────────────────── */
    {
        for (uint32_t idx = 0; idx < 3; idx++) {
            fixture_t fxf;
            CHECK(fx_genesis(&fxf, "bf37") == 0, "genesis");
            uint8_t insa[1][64];
            memcpy(insa[0], g_nul_a, 64);
            out_spec_t o[1] = { { 7, 2000000, 0x27, NULL } };
            env_t ef;
            CHECK(burn_env(&fxf, &ef, insa, 1, o, 1, FEE_MIN, 2000000,
                           s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { ef.bytes, ef.len };
            nodus_v2_block_t bf;
            mk_block(&bf, 1, &ve, 1);
            bf.fail_at = V2AP_FAIL_AFTER_EFFECT_APPLY;
            bf.fail_env_index = 0;
            bf.fail_effect_index = idx;
            CHECK(apply_reject(fxf.w, &bf, &rc) == 0 && rc == -1,
                  "F37 mid-effect fault must roll back byte-identically");
            /* clean retry commits deterministically */
            bf.fail_at = V2AP_FAIL_NONE;
            CHECK(nodus_witness_v2_apply_block(fxf.w, &bf) == 0,
                  "clean retry after F37 must commit");
            CHECK(supply_identity_holds(fxf.w), "identity after retry");
            OK();
            fx_close(&fxf);
        }
        /* the reads/decode/commit-failure points with a BURN envelope */
        static const nodus_v2_apply_fail_t pts[4] = {
            V2AP_FAIL_AFTER_READS, V2AP_FAIL_AFTER_EFFECT_DECODE,
            V2AP_FAIL_BEFORE_COMMIT, V2AP_FAIL_COMMIT
        };
        for (int p = 0; p < 4; p++) {
            fixture_t fxf;
            CHECK(fx_genesis(&fxf, "bflt") == 0, "genesis");
            uint8_t insa[1][64];
            memcpy(insa[0], g_nul_a, 64);
            out_spec_t o[1] = { { 7, 2000000, 0x28, NULL } };
            env_t ef;
            CHECK(burn_env(&fxf, &ef, insa, 1, o, 1, FEE_MIN, 2000000,
                           s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { ef.bytes, ef.len };
            nodus_v2_block_t bf;
            mk_block(&bf, 1, &ve, 1);
            bf.fail_at = pts[p];
            bf.fail_env_index = 0;
            CHECK(apply_reject(fxf.w, &bf, &rc) == 0 && rc == -1,
                  "burn fault point must roll back byte-identically");
            bf.fail_at = V2AP_FAIL_NONE;
            CHECK(nodus_witness_v2_apply_block(fxf.w, &bf) == 0,
                  "clean retry after the burn fault must commit");
            OK();
            fx_close(&fxf);
        }
    }
    return 0;
}

/* ══ 9. CORE slice — TOKEN_CREATE (burn season) ════════════════════ */

#define TC_FEE NODUS_W_TOKEN_CREATE_FEE   /* 10^15 raw = 10M DNAC       */

/* TOKEN_CREATE call v1 builder. outs[0] must carry the token (the
 * caller sets outs[0].token = token_id). */
static uint32_t tc_call_build(uint8_t *dst, size_t cap,
                              const uint8_t token_id[64],
                              const char *name, const char *sym,
                              uint8_t decimals,
                              const void *ins_v, int n_in,
                              const out_spec_t *outs, int n_out) {
    size_t nl = strlen(name), sl = strlen(sym);
    size_t off = 0;
    if (cap < 64 + 1 + nl + 1 + sl + 1) return 0;
    memcpy(dst, token_id, 64);
    off = 64;
    dst[off++] = (uint8_t)nl;
    memcpy(dst + off, name, nl);
    off += nl;
    dst[off++] = (uint8_t)sl;
    memcpy(dst + off, sym, sl);
    off += sl;
    dst[off++] = decimals;
    uint32_t cl = spend_call_build(dst + off, cap - off, ins_v, n_in,
                                   outs, n_out);
    if (!cl) return 0;
    return (uint32_t)(off + cl);
}

static int tc_env(fixture_t *fx, env_t *e, const uint8_t token_id[64],
                  const char *name, const char *sym, uint8_t decimals,
                  const void *ins, int n_in, const out_spec_t *outs,
                  int n_out, uint64_t fee, const int *signers,
                  int n_signers, const sign_opt_t *opt) {
    static uint8_t call[8192];
    uint32_t cl = tc_call_build(call, sizeof(call), token_id, name, sym,
                                decimals, ins, n_in, outs, n_out);
    if (!cl) return -1;
    return env_build_signed(fx, e, DNA_DOMAIN_CORE,
                            DNA_CORERULE_TOKEN_CREATE, call, cl, fee, 0,
                            40, 16384, signers, n_signers, opt);
}

/* count the tokens-table rows under one id */
static uint64_t tok_rows(nodus_witness_t *w, const uint8_t token_id[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM tokens WHERE token_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_blob(st, 1, token_id, 64, SQLITE_TRANSIENT);
    uint64_t n = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* seed one big native funding utxo (>= the creation fee) + rebalance
 * the fixture's conservation identity */
static int seed_funding(fixture_t *fx, int k, uint64_t amount,
                        uint8_t seed_byte, uint8_t nul_out[64]) {
    if (seed_utxo(fx, k, amount, seed_byte, 0, nul_out) != 0) return -1;
    char sql[224];
    snprintf(sql, sizeof(sql),
             "UPDATE supply_tracking SET genesis_supply = "
             "genesis_supply + %llu, current_supply = "
             "current_supply + %llu WHERE id = 1",
             (unsigned long long)amount, (unsigned long long)amount);
    return run_sql(fx->w->db, sql);
}

static int test_core_token_create(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "tc") == 0, "genesis");
    int s7[1] = { 7 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;

    static uint8_t tokA[64], tokB[64], tokC[64];
    memset(tokA, 0xA7, 64);
    memset(tokB, 0xB8, 64);
    memset(tokC, 0xC9, 64);

    uint8_t nul_f1[64], nul_f2[64], nul_f3[64];
    CHECK(seed_funding(&fx, 7, TC_FEE + 3000000, 0x31, nul_f1) == 0,
          "funding 1");
    CHECK(seed_funding(&fx, 7, TC_FEE, 0x32, nul_f2) == 0, "funding 2");
    CHECK(seed_funding(&fx, 7, TC_FEE + FEE_MIN, 0x33, nul_f3) == 0,
          "funding 3");
    uint8_t insf1[1][64], insf2[1][64], insf3[1][64];
    memcpy(insf1[0], nul_f1, 64);
    memcpy(insf2[0], nul_f2, 64);
    memcpy(insf3[0], nul_f3, 64);

    /* ── negatives (each a digest-proven no-op) ─────────────────────── */
    /* insufficient funding: the fixture's ordinary 5M utxo cannot fund
     * the 10M-DNAC creation fee */
    {
        uint8_t insa[1][64];
        memcpy(insa[0], g_nul_a, 64);
        out_spec_t o[1] = { { 7, 777, 0x41, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insa, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "underfunded token creation must reject");
        OK();
    }
    /* exact fee boundary MINUS ONE (balanced on purpose: change absorbs
     * the difference, so the floor is the only violated rule) */
    {
        out_spec_t o[2] = { { 7, 777, 0x42, tokA },
                            { 7, 3000001, 0x43, NULL } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1, o, 2,
                     TC_FEE - 1, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "creation fee below the shipped floor must reject");
        OK();
    }
    /* invalid authorization */
    {
        out_spec_t o[2] = { { 7, 777, 0x44, tokA },
                            { 7, 3000000, 0x45, NULL } };
        sign_opt_t so;
        memset(&so, 0, sizeof(so));
        so.break_sig = 1;
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1, o, 2,
                     TC_FEE, s7, 1, &so) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "invalid creation signature must reject");
        OK();
    }
    /* the malformed-call matrix (every leg parse-rejected) */
    {
        struct {
            const char *what;
            const char *name, *sym;
            uint8_t decimals;
            const uint8_t *tid;
            uint64_t supply;
        } m[7];
        memset(m, 0, sizeof(m));
        static uint8_t zeros[64];
        memset(zeros, 0, 64);
        static const char n33[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        m[0].what = "empty name";
        m[0].name = ""; m[0].sym = "TT"; m[0].decimals = 8;
        m[0].tid = tokA; m[0].supply = 777;
        m[1].what = "33-byte name";
        m[1].name = n33; m[1].sym = "TT"; m[1].decimals = 8;
        m[1].tid = tokA; m[1].supply = 777;
        m[2].what = "9-byte symbol";
        m[2].name = "TestToken"; m[2].sym = "SSSSSSSSS";
        m[2].decimals = 8; m[2].tid = tokA; m[2].supply = 777;
        m[3].what = "decimals 19";
        m[3].name = "TestToken"; m[3].sym = "TT"; m[3].decimals = 19;
        m[3].tid = tokA; m[3].supply = 777;
        m[4].what = "colon in name (legacy-memo-unrepresentable)";
        m[4].name = "Test:Token"; m[4].sym = "TT"; m[4].decimals = 8;
        m[4].tid = tokA; m[4].supply = 777;
        m[5].what = "all-zero token id (the native id)";
        m[5].name = "TestToken"; m[5].sym = "TT"; m[5].decimals = 8;
        m[5].tid = zeros; m[5].supply = 777;
        m[6].what = "supply above the INT64 storage bound";
        m[6].name = "TestToken"; m[6].sym = "TT"; m[6].decimals = 8;
        m[6].tid = tokA;
        m[6].supply = 9223372036854775808ULL;   /* INT64_MAX + 1 */
        for (int i = 0; i < 7; i++) {
            out_spec_t o[2] = { { 7, m[i].supply, 0x46, m[i].tid },
                                { 7, 3000000, 0x47, NULL } };
            CHECK(tc_env(&fx, &e, m[i].tid, m[i].name, m[i].sym,
                         m[i].decimals, insf1, 1, o, 2, TC_FEE, s7, 1,
                         NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1, m[i].what);
            OK();
        }
        /* non-printable byte in the name (0x1f) — hand-patched call */
        {
            static uint8_t call[8192];
            out_spec_t o[2] = { { 7, 777, 0x48, tokA },
                                { 7, 3000000, 0x49, NULL } };
            uint32_t cl = tc_call_build(call, sizeof(call), tokA,
                                        "TestToken", "TT", 8, insf1, 1,
                                        o, 2);
            CHECK(cl > 0, "call");
            call[65] = 0x1f;             /* first name byte              */
            CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                                   DNA_CORERULE_TOKEN_CREATE, call, cl,
                                   TC_FEE, 0, 40, 16384, s7, 1, NULL)
                      == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "non-printable name byte must reject");
            OK();
        }
        /* truncated call (one byte short — exact-length rule) */
        {
            static uint8_t call[8192];
            out_spec_t o[2] = { { 7, 777, 0x4A, tokA },
                                { 7, 3000000, 0x4B, NULL } };
            uint32_t cl = tc_call_build(call, sizeof(call), tokA,
                                        "TestToken", "TT", 8, insf1, 1,
                                        o, 2);
            CHECK(cl > 0, "call");
            CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                                   DNA_CORERULE_TOKEN_CREATE, call,
                                   cl - 1, TC_FEE, 0, 40, 16384, s7, 1,
                                   NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "truncated creation call must reject");
            OK();
        }
        /* output[0] carries a DIFFERENT token than the declared id */
        {
            out_spec_t o[2] = { { 7, 777, 0x4C, tokB },
                                { 7, 3000000, 0x4D, NULL } };
            CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1,
                         o, 2, TC_FEE, s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "genesis-output token substitution must reject");
            OK();
        }
        /* a SECOND output carrying the new token (supply inflation) */
        {
            out_spec_t o[2] = { { 7, 777, 0x4E, tokA },
                                { 7, 1, 0x4F, tokA } };
            CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1,
                         o, 2, TC_FEE, s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "second output of the new token must reject");
            OK();
        }
        /* zero initial supply (output amount floor) */
        {
            out_spec_t o[2] = { { 7, 0, 0x50, tokA },
                                { 7, 3000000, 0x51, NULL } };
            CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1,
                         o, 2, TC_FEE, s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "zero initial supply must reject");
            OK();
        }
    }
    /* deliberate collision fixture: a pre-existing registry row under
     * the target id (INSERTED DIRECTLY — the legacy INSERT OR IGNORE
     * would have silently dropped the new registration; V2 rejects) */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "INSERT INTO tokens (token_id, name, symbol, decimals, "
              "supply, creator_fp, flags, block_height, timestamp) "
              "VALUES (?1, 'Squat', 'SQ', 8, 1, ?2, 0, 0, 0)",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, tokC, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, g_fp[8], 128, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "squat row");
        sqlite3_finalize(st);
        out_spec_t o[2] = { { 7, 777, 0x52, tokC },
                            { 7, 3000000, 0x53, NULL } };
        CHECK(tc_env(&fx, &e, tokC, "TestToken", "TT", 8, insf1, 1, o, 2,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "colliding token id must reject");
        OK();
    }
    /* funding-input matrix (review round: these were BURN-only) */
    {
        /* NON-NATIVE funding input: seed a token utxo for key 7 and try
         * to fund the creation fee with it (native leg balanced so the
         * native-only rule is the one violated: token in TC_FEE covers
         * nothing, native in == 0 != out+fee) — actually the non-native
         * check fires FIRST, before any sum */
        static uint8_t tokFund[64];
        memset(tokFund, 0x77, 64);
        uint8_t ntok[64];
        CHECK(seed_token_utxo(&fx, 7, 5, 0x63, tokFund, ntok) == 0,
              "seed token fund");
        uint8_t insn[2][64];
        memcpy(insn[0], nul_f1, 64);
        memcpy(insn[1], ntok, 64);
        out_spec_t o[2] = { { 7, 777, 0x64, tokA },
                            { 7, 3000000, 0x65, NULL } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insn, 2, o, 2,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "non-native creation funding must reject");
        OK();
        /* LOCKED funding input */
        uint8_t nlock[64];
        CHECK(seed_utxo(&fx, 7, TC_FEE, 0x66, 100000, nlock) == 0,
              "seed locked fund");
        {
            char sql[224];
            snprintf(sql, sizeof(sql),
                     "UPDATE supply_tracking SET genesis_supply = "
                     "genesis_supply + %llu, current_supply = "
                     "current_supply + %llu WHERE id = 1",
                     (unsigned long long)TC_FEE,
                     (unsigned long long)TC_FEE);
            CHECK(run_sql(fx.w->db, sql) == 0, "supply seed");
        }
        uint8_t insl[1][64];
        memcpy(insl[0], nlock, 64);
        out_spec_t ol[1] = { { 7, 777, 0x67, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insl, 1, ol, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vl = { e.bytes, e.len };
        mk_block(&b, 1, &vl, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "locked creation funding must reject");
        OK();
        /* WRONG-OWNER funding (key 8 signs over key 7's utxo) */
        int s8w[1] = { 8 };
        uint8_t insw[1][64];
        memcpy(insw[0], nul_f2, 64);     /* key 7's TC_FEE row           */
        out_spec_t ow[1] = { { 8, 777, 0x68, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insw, 1, ow, 1,
                     TC_FEE, s8w, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vw = { e.bytes, e.len };
        mk_block(&b, 1, &vw, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unowned creation funding must reject");
        OK();
        /* MISSING funding input */
        static uint8_t insm[1][64];
        memset(insm, 0x5E, sizeof(insm));
        out_spec_t om[1] = { { 7, 777, 0x69, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insm, 1, om, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vm = { e.bytes, e.len };
        mk_block(&b, 1, &vm, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "missing creation funding must reject");
        OK();
    }
    /* checked-add overflow in the change accumulation (the one §14 item
     * that had no TOKEN_CREATE coverage — review round): two change
     * outputs of (2^64−1) + 1 wrap the native_out sum */
    {
        out_spec_t o[3] = { { 7, 777, 0x6A, tokA },
                            { 7, UINT64_MAX, 0x6B, NULL },
                            { 7, 1, 0x6C, NULL } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1, o, 3,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "change-sum overflow must reject");
        OK();
    }
    /* shape boundaries + cross-op (review round) */
    {
        /* in_count 15 exceeds the TOKEN_CREATE read budget (max 14) */
        static uint8_t ins15[15][64];
        for (int i = 0; i < 15; i++)
            memset(ins15[i], (uint8_t)(0x80 + i), 64);
        out_spec_t o[1] = { { 7, 777, 0x6D, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, ins15, 15, o,
                     1, TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "15-input creation must reject (read budget)");
        OK();
        /* out_count 0 (a creation must create its genesis output) */
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "TT", 8, insf1, 1, o, 0,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t v0 = { e.bytes, e.len };
        mk_block(&b, 1, &v0, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "zero-output creation must reject");
        OK();
        /* ':' in the SYMBOL (the name variant lives in the matrix) */
        CHECK(tc_env(&fx, &e, tokA, "TestToken", "T:", 8, insf1, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vs = { e.bytes, e.len };
        mk_block(&b, 1, &vs, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "colon in symbol must reject");
        OK();
        /* CROSS-OP: TOKEN_CREATE bytes under runtime_op BURN and under
         * SPEND — both unparseable under the foreign op */
        static uint8_t call[8192];
        out_spec_t o2[2] = { { 7, 777, 0x6E, tokA },
                             { 7, 3000000, 0x6F, NULL } };
        uint32_t cl = tc_call_build(call, sizeof(call), tokA,
                                    "TestToken", "TT", 8, insf1, 1, o2,
                                    2);
        CHECK(cl > 0, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_BURN, call, cl, TC_FEE, 0,
                               40, 16384, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vb2 = { e.bytes, e.len };
        mk_block(&b, 1, &vb2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "TOKEN_CREATE bytes under runtime_op BURN must reject");
        OK();
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SPEND, call, cl, TC_FEE, 0,
                               40, 16384, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vsp = { e.bytes, e.len };
        mk_block(&b, 1, &vsp, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "TOKEN_CREATE bytes under runtime_op SPEND must reject");
        OK();
    }

    /* ── POSITIVE 1: valid creation with change ─────────────────────── */
    uint64_t burned0 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint8_t core_root0[64], sys_head0[89];
    CHECK(head_root(fx.w, DNA_DOMAIN_CORE, core_root0) == 0, "core root");
    CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_head0) == 0, "sys head");
    env_t e_p1;
    uint8_t p1_wire[64], p1_intent[64];
    {
        out_spec_t o[2] = { { 7, 123456789, 0x54, tokA },
                            { 7, 2000000, 0x55, NULL } };
        CHECK(tc_env(&fx, &e_p1, tokA, "TestToken", "TT", 8, insf1, 1,
                     o, 2, TC_FEE + 1000000, s7, 1, NULL) == 0, "build");
        CHECK(derive_ids(&fx, &e_p1, DNA_DOMAIN_CORE, p1_wire,
                         p1_intent) == 0, "ids");
        nodus_v2_envelope_t ve = { e_p1.bytes, e_p1.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "valid token creation must commit");
        OK();
        /* the registry row: every committed column, wall clock EXCLUDED */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT name, symbol, decimals, supply, creator_fp, "
                  "flags, block_height, timestamp FROM tokens WHERE "
                  "token_id=?1", -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, tokA, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW, "registry row exists");
            CHECK(strcmp((const char *)sqlite3_column_text(st, 0),
                         "TestToken") == 0 &&
                  strcmp((const char *)sqlite3_column_text(st, 1),
                         "TT") == 0 &&
                  sqlite3_column_int64(st, 2) == 8 &&
                  sqlite3_column_int64(st, 3) == 123456789 &&
                  strncmp((const char *)sqlite3_column_text(st, 4),
                          g_fp[7], 128) == 0 &&
                  sqlite3_column_int64(st, 5) == 0 &&
                  sqlite3_column_int64(st, 6) == 1,
                  "registry row columns");
            CHECK(sqlite3_column_int64(st, 7) == 0,
                  "registry timestamp must be 0 (no wall clock)");
            sqlite3_finalize(st);
            OK();
        }
        /* the token genesis utxo: full supply, intent provenance */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT amount, owner, tx_hash, created_at FROM "
                  "utxo_set WHERE token_id=?1", -1, &st, NULL)
                      == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, tokA, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 123456789 &&
                  strncmp((const char *)sqlite3_column_text(st, 1),
                          g_fp[7], 128) == 0 &&
                  memcmp(sqlite3_column_blob(st, 2), p1_intent, 64) == 0 &&
                  sqlite3_column_int64(st, 3) == 0,
                  "token genesis utxo (supply, owner, intent, no clock)");
            CHECK(sqlite3_step(st) == SQLITE_DONE,
                  "exactly ONE token utxo");
            sqlite3_finalize(st);
            OK();
        }
        /* fee burned exactly once; native conservation holds; the
         * current_supply COLUMN itself stays coherent (review round:
         * pin the derivation, not just the recomputed identity) */
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned0 + TC_FEE + 1000000,
              "creation fee burned exactly once");
        CHECK(q1(fx.w, "SELECT current_supply FROM supply_tracking")
                  == q1(fx.w, "SELECT genesis_supply + total_minted - "
                              "total_burned FROM supply_tracking"),
              "current_supply column == genesis + minted - burned");
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        /* token_root moved the CORE root; SYSTEM untouched */
        uint8_t core_root1[64], sys_head1[89];
        CHECK(head_root(fx.w, DNA_DOMAIN_CORE, core_root1) == 0 &&
              memcmp(core_root0, core_root1, 64) != 0,
              "CORE root must move");
        CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_head1) == 0 &&
              memcmp(sys_head0, sys_head1, 89) == 0,
              "SYSTEM head must not move on a token creation");
        OK();
    }

    /* duplicate token ID in a LATER block (registry-read reject) */
    {
        out_spec_t o2[1] = { { 7, 42, 0x56, tokA } };
        CHECK(tc_env(&fx, &e, tokA, "Other", "OT", 8, insf2, 1, o2, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate token id must reject");
        CHECK(tok_rows(fx.w, tokA) == 1, "exactly one registry row");
        OK();
    }
    /* semantic replay of the COMMITTED creation under a fresh witness */
    {
        env_t e2;
        out_spec_t o[2] = { { 7, 123456789, 0x54, tokA },
                            { 7, 2000000, 0x55, NULL } };
        CHECK(tc_env(&fx, &e2, tokA, "TestToken", "TT", 8, insf1, 1, o,
                     2, TC_FEE + 1000000, s7, 1, NULL) == 0, "build");
        uint8_t w2[64], i2[64];
        CHECK(derive_ids(&fx, &e2, DNA_DOMAIN_CORE, w2, i2) == 0 &&
              memcmp(i2, p1_intent, 64) == 0 &&
              memcmp(w2, p1_wire, 64) != 0,
              "replay twin: same intent, new wire");
        nodus_v2_envelope_t ve = { e2.bytes, e2.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "creation replay under a new witness must reject");
        OK();
    }

    /* ── POSITIVE 2: exact-fee boundary + maximal metadata + supply at
     * the INT64 storage bound + no change output ───────────────────── */
    {
        uint64_t burned_pre = q1(fx.w,
                                 "SELECT total_burned FROM supply_tracking");
        static const char n32[] = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";
        out_spec_t o[1] = { { 7, 9223372036854775807ULL, 0x58, tokB } };
        CHECK(tc_env(&fx, &e, tokB, n32, "SSSSSSSS", 18, insf2, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "boundary creation must commit");
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
                  == burned_pre + TC_FEE, "exact-fee boundary burned");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "SELECT name, symbol, decimals, supply FROM tokens "
                  "WHERE token_id=?1", -1, &st, NULL) == SQLITE_OK,
                  "prep");
            sqlite3_bind_blob(st, 1, tokB, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  strcmp((const char *)sqlite3_column_text(st, 0), n32)
                      == 0 &&
                  strcmp((const char *)sqlite3_column_text(st, 1),
                         "SSSSSSSS") == 0 &&
                  sqlite3_column_int64(st, 2) == 18 &&
                  sqlite3_column_int64(st, 3) == 9223372036854775807LL,
                  "maximal metadata + INT64_MAX supply round-trip");
            sqlite3_finalize(st);
        }
        CHECK(supply_identity_holds(fx.w), "conservation identity");
        OK();
    }
    fx_close(&fx);

    /* ── SAME-BLOCK duplicate: two creations of ONE id in one block —
     * the second leg's registry read runs INSIDE the transaction and
     * sees the first row: the whole block rejects, nothing survives ── */
    {
        fixture_t fx2;
        CHECK(fx_genesis(&fx2, "tcdup") == 0, "genesis");
        uint8_t f1[64], f2[64];
        CHECK(seed_funding(&fx2, 7, TC_FEE, 0x34, f1) == 0, "fund");
        CHECK(seed_funding(&fx2, 8, TC_FEE, 0x35, f2) == 0, "fund");
        uint8_t i1[1][64], i2v[1][64];
        memcpy(i1[0], f1, 64);
        memcpy(i2v[0], f2, 64);
        int s8[1] = { 8 };
        out_spec_t oa[1] = { { 7, 100, 0x59, tokA } };
        out_spec_t ob[1] = { { 8, 200, 0x5A, tokA } };
        env_t ea, eb;
        CHECK(tc_env(&fx2, &ea, tokA, "First", "F1", 8, i1, 1, oa, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build A");
        CHECK(tc_env(&fx2, &eb, tokA, "Second", "F2", 8, i2v, 1, ob, 1,
                     TC_FEE, s8, 1, NULL) == 0, "build B");
        nodus_v2_envelope_t vs[2] = { { ea.bytes, ea.len },
                                      { eb.bytes, eb.len } };
        nodus_v2_block_t bd;
        mk_block(&bd, 1, vs, 2);
        CHECK(apply_reject(fx2.w, &bd, &rc) == 0 && rc == -1,
              "same-block duplicate token id must reject the block");
        CHECK(tok_rows(fx2.w, tokA) == 0, "no registry row survived");
        OK();
        fx_close(&fx2);
    }

    /* ── INSERTION-ORDER INDEPENDENCE: [A,B] vs [B,A] in one block —
     * identical domain/global roots (token_root sorts by token_id),
     * different wire tx roots ───────────────────────────────────────── */
    {
        fixture_t xa, xb;
        CHECK(fx_genesis(&xa, "tcordA") == 0, "genesis A");
        CHECK(fx_genesis(&xb, "tcordB") == 0, "genesis B");
        env_t ea, eb;
        uint8_t fa[64], fb[64];
        int s8[1] = { 8 };
        /* fixture A */
        CHECK(seed_funding(&xa, 7, TC_FEE, 0x36, fa) == 0, "fund");
        CHECK(seed_funding(&xa, 8, TC_FEE, 0x37, fb) == 0, "fund");
        uint8_t ia[1][64], ib[1][64];
        memcpy(ia[0], fa, 64);
        memcpy(ib[0], fb, 64);
        out_spec_t oa[1] = { { 7, 111, 0x5B, tokA } };
        out_spec_t ob[1] = { { 8, 222, 0x5C, tokB } };
        CHECK(tc_env(&xa, &ea, tokA, "Alpha", "AA", 8, ia, 1, oa, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build A1");
        CHECK(tc_env(&xa, &eb, tokB, "Beta", "BB", 8, ib, 1, ob, 1,
                     TC_FEE, s8, 1, NULL) == 0, "build A2");
        nodus_v2_envelope_t va[2] = { { ea.bytes, ea.len },
                                      { eb.bytes, eb.len } };
        nodus_v2_block_t b1;
        mk_block(&b1, 1, va, 2);
        CHECK(nodus_witness_v2_apply_block(xa.w, &b1) == 0, "A commits");
        /* fixture B — the SAME two creations, opposite order */
        env_t ea2, eb2;
        CHECK(seed_funding(&xb, 7, TC_FEE, 0x36, fa) == 0, "fund");
        CHECK(seed_funding(&xb, 8, TC_FEE, 0x37, fb) == 0, "fund");
        CHECK(tc_env(&xb, &ea2, tokA, "Alpha", "AA", 8, ia, 1, oa, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build B1");
        CHECK(tc_env(&xb, &eb2, tokB, "Beta", "BB", 8, ib, 1, ob, 1,
                     TC_FEE, s8, 1, NULL) == 0, "build B2");
        nodus_v2_envelope_t vb[2] = { { eb2.bytes, eb2.len },
                                      { ea2.bytes, ea2.len } };
        nodus_v2_block_t b2;
        mk_block(&b2, 1, vb, 2);
        mk_id(b2.block_id, 0xC5);
        CHECK(nodus_witness_v2_apply_block(xb.w, &b2) == 0, "B commits");
        CHECK(memcmp(b1.out_domains_root, b2.out_domains_root, 64) == 0 &&
              memcmp(b1.out_global_root, b2.out_global_root, 64) == 0,
              "creation order must not move the state roots");
        CHECK(memcmp(b1.out_tx_root, b2.out_tx_root, 64) != 0,
              "wire tx roots differ across orders (correct)");
        OK();
        fx_close(&xa);
        fx_close(&xb);
    }

    /* ── CROSS-CHAIN replay negative ────────────────────────────────── */
    {
        fixture_t a, o2;
        CHECK(fx_genesis(&a, "tcxcA") == 0, "genesis A");
        g_gid_fill = 0xF1;
        int orc = fx_genesis(&o2, "tcxcO");
        g_gid_fill = 0xEE;
        CHECK(orc == 0, "genesis O");
        uint8_t f1[64];
        CHECK(seed_funding(&a, 7, TC_FEE, 0x38, f1) == 0, "fund");
        /* fund the OTHER chain identically (same seed ⇒ same nullifier)
         * so the chain binding is the ONLY rejecting rule — review
         * round: without this, a missing-input reject stood behind it */
        CHECK(seed_funding(&o2, 7, TC_FEE, 0x38, f1) == 0, "fund O");
        uint8_t i1[1][64];
        memcpy(i1[0], f1, 64);
        out_spec_t o[1] = { { 7, 333, 0x5D, tokC } };
        env_t ea;
        CHECK(tc_env(&a, &ea, tokC, "Gamma", "GG", 8, i1, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build");
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_block_t bo;
        mk_block(&bo, 1, &va, 1);
        mk_id(bo.prev_block_id, 0xF1);
        CHECK(apply_reject(o2.w, &bo, &rc) == 0 && rc == -1,
              "cross-chain creation replay must fail the chain binding");
        OK();
        fx_close(&a);
        fx_close(&o2);
    }

    /* ── AUTH-WITNESS TWINS: deterministic id + root across fixtures ── */
    {
        fixture_t a, b2;
        CHECK(fx_genesis(&a, "tctwA") == 0, "genesis A");
        CHECK(fx_genesis(&b2, "tctwB") == 0, "genesis B");
        uint8_t f1[64];
        CHECK(seed_funding(&a, 7, TC_FEE, 0x39, f1) == 0, "fund A");
        CHECK(seed_funding(&b2, 7, TC_FEE, 0x39, f1) == 0, "fund B");
        uint8_t i1[1][64];
        memcpy(i1[0], f1, 64);
        out_spec_t o[1] = { { 7, 444, 0x5E, tokC } };
        env_t ea, eb;
        CHECK(tc_env(&a, &ea, tokC, "Delta", "DD", 8, i1, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build A");
        CHECK(tc_env(&b2, &eb, tokC, "Delta", "DD", 8, i1, 1, o, 1,
                     TC_FEE, s7, 1, NULL) == 0, "build B");
        uint8_t wa[64], iaa[64], wb[64], ibb[64];
        CHECK(derive_ids(&a, &ea, DNA_DOMAIN_CORE, wa, iaa) == 0 &&
              derive_ids(&b2, &eb, DNA_DOMAIN_CORE, wb, ibb) == 0,
              "ids");
        CHECK(memcmp(iaa, ibb, 64) == 0 && memcmp(wa, wb, 64) != 0,
              "creation twins: one intent, two wires");
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vb = { eb.bytes, eb.len };
        nodus_v2_block_t ba, bb;
        mk_block(&ba, 1, &va, 1);
        mk_block(&bb, 1, &vb, 1);
        mk_id(bb.block_id, 0xC6);
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "A commits");
        CHECK(nodus_witness_v2_apply_block(b2.w, &bb) == 0, "B commits");
        uint8_t da[64], db[64];
        CHECK(consensus_state_digest(a.w, da) == 0 &&
              consensus_state_digest(b2.w, db) == 0, "digest");
        /* the tokens table is not in consensus_state_digest's list —
         * compare it directly, then the roots */
        CHECK(memcmp(da, db, 64) == 0,
              "creation twins: consensus state identical");
        CHECK(memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0 &&
              memcmp(ba.out_global_root, bb.out_global_root, 64) == 0,
              "creation twins: roots identical");
        CHECK(memcmp(ba.out_tx_root, bb.out_tx_root, 64) != 0,
              "creation twins: wire tx roots differ");
        OK();
        fx_close(&a);
        fx_close(&b2);
    }

    /* ── F37 mid-effect faults over a creation leg: effects are
     * [CREATE utxo0, CREATE utxo1, CREATE registry, SET burned,
     *  DELETE input] — prove rollback after the registry insert (2),
     * after the fee mutation (3) and after the consumption (4), plus a
     * clean retry; the registry row must never survive a fault ─────── */
    {
        for (uint32_t idx = 2; idx <= 4; idx++) {
            fixture_t fxf;
            CHECK(fx_genesis(&fxf, "tcf37") == 0, "genesis");
            uint8_t f1[64];
            CHECK(seed_funding(&fxf, 7, TC_FEE + 1000000, 0x3A, f1) == 0,
                  "fund");
            uint8_t i1[1][64];
            memcpy(i1[0], f1, 64);
            out_spec_t o[2] = { { 7, 555, 0x5F, tokC },
                                { 7, 1000000, 0x60, NULL } };
            env_t ef;
            CHECK(tc_env(&fxf, &ef, tokC, "Fault", "FF", 8, i1, 1, o, 2,
                         TC_FEE, s7, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { ef.bytes, ef.len };
            nodus_v2_block_t bf;
            mk_block(&bf, 1, &ve, 1);
            bf.fail_at = V2AP_FAIL_AFTER_EFFECT_APPLY;
            bf.fail_env_index = 0;
            bf.fail_effect_index = idx;
            CHECK(apply_reject(fxf.w, &bf, &rc) == 0 && rc == -1,
                  "creation F37 fault must roll back byte-identically");
            CHECK(tok_rows(fxf.w, tokC) == 0,
                  "no registry row survives a fault");
            bf.fail_at = V2AP_FAIL_NONE;
            CHECK(nodus_witness_v2_apply_block(fxf.w, &bf) == 0,
                  "clean retry after the creation fault must commit");
            CHECK(tok_rows(fxf.w, tokC) == 1 &&
                  supply_identity_holds(fxf.w),
                  "retry landed the registry row + identity");
            OK();
            fx_close(&fxf);
        }
    }
    return 0;
}

/* ══ 10. HOOK-LEVEL fail-closed pins (burn season) ═════════════════
 * Two rejects are DEFENSE-IN-DEPTH seams a block-level test cannot
 * observe (a mutant removing them is masked by the next layer, which
 * produces the same block verdict). Pin them at the layer that owns
 * them, so the mutation campaign has a killing assertion:
 *   - the TOKEN_CREATE exec hook itself rejects a PRESENT registry
 *     read (before the CREATE/ABSENT adapter precondition ever runs);
 *   - the CORE adapter's mediated read scopes by the RESOLVED
 *     runtime's domain — a foreign-domain utxo row is invisible. */
static int test_hook_level_pins(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "hook") == 0, "genesis");
    int s7[1] = { 7 };
    static uint8_t tokH[64];
    memset(tokH, 0x99, 64);
    uint8_t f1[64];
    CHECK(seed_funding(&fx, 7, TC_FEE, 0x3B, f1) == 0, "fund");
    uint8_t i1[1][64];
    memcpy(i1[0], f1, 64);
    out_spec_t o[1] = { { 7, 777, 0x61, tokH } };
    env_t e;
    CHECK(tc_env(&fx, &e, tokH, "Hook", "HH", 8, i1, 1, o, 1, TC_FEE,
                 s7, 1, NULL) == 0, "build");

    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    const nodus_domain_runtime_t *rt = &bt[1];

    dna_env_view_t v;
    CHECK(dna_env_decode(e.bytes, e.len, &v) == 0, "decode");

    nodus_rt_auth_verdict_t av;
    memset(&av, 0, sizeof(av));
    av.n_signers = 1;
    CHECK(qgp_sha3_512(g_pk[7], 2592, av.signer_fp[0]) == 0, "fp");
    static uint8_t iid[64];
    memset(iid, 0x33, 64);
    nodus_rt_exec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = fx.chain_id;
    ctx.global_height = 1;
    ctx.intent_id = iid;
    ctx.wire_id = iid;
    ctx.auth = &av;

    nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
    uint16_t nr = 0;
    CHECK(nodus_rt_core_read_plan(rt, &v, 0, &ctx, reqs,
                                  NODUS_RT_MAX_READS, &nr) == 0 &&
          nr == 3, "read plan (1 input + supply + registry)");
    nodus_rt_read_res_t reads[NODUS_RT_MAX_READS];
    memset(reads, 0, sizeof(reads));
    for (uint16_t r = 0; r < nr; r++)
        CHECK(nodus_witness_v2_read_one(fx.w, rt, &reqs[r], &reads[r])
                  == NODUS_ADAPTER_OK, "mediated read");
    static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
    size_t rl = 0;
    CHECK(nodus_rt_core_exec(rt, &v, 0, &ctx, reads, nr, res,
                             sizeof(res), &rl) == 0,
          "honest hook-level exec accepts");
    OK();
    /* the MUTANT-6 killer: a PRESENT registry read must be rejected by
     * the HOOK itself — never left for the adapter precondition */
    reads[nr - 1].present = 1;
    reads[nr - 1].value_len = 188;
    CHECK(nodus_rt_core_exec(rt, &v, 0, &ctx, reads, nr, res,
                             sizeof(res), &rl) == -1,
          "duplicate registry read must reject at the hook");
    OK();

    /* the MUTANT-8 killer: a FOREIGN-DOMAIN utxo row is invisible to
     * the CORE adapter's mediated read (scoped by rt->domain_id) */
    {
        uint8_t fnul[64];
        CHECK(seed_utxo(&fx, 7, 12345, 0x62, 0, fnul) == 0, "seed");
        CHECK(run_sql(fx.w->db,
              "UPDATE utxo_set SET domain_id = 0 WHERE block_height = 0 "
              "AND amount = 12345") == 0, "foreignize");
        nodus_rt_read_req_t rq;
        memset(&rq, 0, sizeof(rq));
        rq.op_id = 1;                    /* RTN_CORE_OP_UTXO             */
        rq.key_len = 64;
        memcpy(rq.key, fnul, 64);
        nodus_rt_read_res_t rr;
        CHECK(nodus_witness_v2_read_one(fx.w, rt, &rq, &rr)
                  == NODUS_ADAPTER_OK && rr.present == 0,
              "foreign-domain utxo must be invisible to the CORE "
              "adapter");
        OK();
    }

    /* a MALFORMED legacy tokens row (the live lane never bounded
     * name/symbol) must surface as a STORAGE FAULT — never as absence
     * (which would let a colliding creation commit) and never as a
     * value (which would hash bytes the row does not canonically hold).
     * Pins the fetch-side fail-close the review round examined. */
    {
        static uint8_t badId[64];
        memset(badId, 0xBD, 64);
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "INSERT INTO tokens (token_id, name, symbol, decimals, "
              "supply, creator_fp, flags, block_height, timestamp) "
              "VALUES (?1, 'AVeryLongLegacyTokenNameThatExceedsBounds', "
              "'LONGSYMB0L', 8, 1, ?2, 0, 0, 0)",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, badId, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, g_fp[7], 128, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "legacy row");
        sqlite3_finalize(st);
        nodus_rt_read_req_t rq;
        memset(&rq, 0, sizeof(rq));
        rq.op_id = 4;                    /* RTN_CORE_OP_TOKEN            */
        rq.key_len = 64;
        memcpy(rq.key, badId, 64);
        nodus_rt_read_res_t rr;
        CHECK(nodus_witness_v2_read_one(fx.w, rt, &rq, &rr)
                  == NODUS_ADAPTER_ERR_STORAGE_FAULT,
              "malformed legacy token row must be a storage fault");
        OK();
    }
    fx_close(&fx);
    return 0;
}

int main(void) {
    if (keys_init() != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    if (test_auth() != 0) return 1;
    if (test_authority() != 0) return 1;
    if (test_system_cc() != 0) return 1;
    if (test_committee_capacity() != 0) return 1;
    if (test_core_spend() != 0) return 1;
    if (test_engine() != 0) return 1;
    if (test_intent_engine() != 0) return 1;
    if (test_core_burn() != 0) return 1;
    if (test_core_token_create() != 0) return 1;
    if (test_hook_level_pins() != 0) return 1;
    printf("test_v2_native: ALL OK (%d checks)\n", g_checks);
    return 0;
}
