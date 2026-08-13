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
    if (nodus_witness_db_migrate_v2s7(fx->w) != 0) return -1;

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
    mk_id(gid, 0xEE);
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
    /* capacity season: SYSTEM is ruleset v2, CORE stays v1 */
    leg.hdr.ruleset_version = domain_id == DNA_DOMAIN_SYSTEM ? 2 : 1;
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

    /* AUTH-DATA MALLEABILITY TWIN (the residual intent-dedup seam,
     * labeled): Dilithium signing is randomized, so re-signing the SAME
     * intent yields a second envelope with a DIFFERENT tx_id. It must
     * not double-spend: the first commit consumed the inputs, so the
     * twin dies as missing-input. */
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
        leg.hdr.ruleset_version = 1;
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
            lctx.ruleset_version = 1;
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
                  memcmp(sqlite3_column_blob(st, 0), pf->tx_id, 64) == 0,
                  "output provenance is the DERIVED transaction id");
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
            leg.hdr.ruleset_version = 1;
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
            leg.hdr.ruleset_version = 1;
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
    printf("test_v2_native: ALL OK (%d checks)\n", g_checks);
    return 0;
}
