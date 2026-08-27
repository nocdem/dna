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
 *   6. (§11, O11) SYSTEM slice — STAKE + the CORE funding leg: the
 *      first CROSS-DOMAIN operation. Two positives (destination
 *      fingerprint derived from the staker's own key and not), a
 *      17-case adversarial matrix (funding, ownership, token purity,
 *      dust, the self-bond floor, the commission narrowing, duplicate
 *      inputs, both fee rules, both missing-leg forms, sibling-op
 *      mismatch, extra signer, identity mismatch, both broken
 *      signatures), Rule I, and the two-leg identity/replay behaviour
 *      (byte-identical replay + the authorization twin).
 *   7. (§12, O11) hook-level fail-closed pins the block layer masks:
 *      the 2-leg shape gate on both sides, the kind-2 refusal at exec,
 *      and the SYSTEM adapter's negative-integer row readers.
 *   8. (§14-§16, O11 S5) fault injection + ATOMICITY across the
 *      cross-domain shape (the F26/F28/F30/F31/F37/F38/F35/F36/F13/F14
 *      matrix over a DELEGATE and an UNDELEGATE envelope, F38 being the
 *      half-envelope point that fires BETWEEN the two legs), the
 *      VALIDATOR-SET FIREWALL (snapshots / epoch_state /
 *      chain_config_history / resolved committee / resolved-set hash
 *      byte-identical across all four ops; op 5 and types 11/12/13 still
 *      dead), and the global leftovers (same-block duplicate intent,
 *      cross-chain independence + binding, reversed leg order at BOTH
 *      the encoder and the decoder, the wall-clock structural pin, and
 *      one operation at each of epoch LEN-1 / LEN / LEN+1).
 *   9. (§17-§18, O12 S1) SYSTEM slice — VALIDATOR_UPDATE (runtime_op 5,
 *      legacy tx 9): the first record op whose funding leg moves NO
 *      value (lock = release = 0). Positives for all three commission
 *      transitions (decrease / equal / increase), ELIGIBLE and RETIRING
 *      updaters, sequential updates and fee-only conservation; a
 *      12-case negative matrix (unknown validator, UNSTAKED,
 *      AUTO_RETIRED, bps > 10000, call length ±1, all-zero identity,
 *      valid-signature-wrong-identity, kind-2 carriage, both single-leg
 *      forms, foreign sibling); ACTIVE-SET immutability,
 *      committed-intent replay, cross-chain separation and the
 *      twin-execution determinism check. §18 adds the hook-level pins
 *      the block layer cannot separate — above all the one-epoch
 *      deferral arithmetic at epoch LEN-1 / LEN / LEN+1, where the next
 *      boundary and H + epoch coincide.
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
#include "witness/nodus_witness_vset.h"        /* O11 S5: seed the frozen
                                        * validator-set snapshots through
                                        * the SOURCE genesis hook       */
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

#include "v2_genesis_fixture.h"

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
    /* O14 leader mode: identity is DERIVED, never carried. */
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
/* O14: the genesis BlockID is DERIVED, so a fixture can no longer be put
 * on a different chain by naming a different id. It is differentiated by
 * genesis CONTENT instead — this fill seeds the genesis validator-set
 * hash, which is a bound header field, so changing it changes the
 * derived genesis BlockID and therefore the derived chain id. Same
 * cross-chain intent, now earned rather than asserted. */
static uint8_t g_gid_fill = 0xEE;

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
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    if (nval != 7) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO chain_config_history (param_id, new_value, "
                 "effective_block, commit_block, tx_hash, proposal_nonce, "
                 "created_at_unix) VALUES (4, %d, 0, 0, zeroblob(64), "
                 "1, 0)", nval);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }

    /* nval ACTIVE validators = the bootstrap committee.
     * O11: each row carries a REAL 128-hex unstake_destination_fp (its
     * own key's fingerprint) — that is what the legacy lane writes on
     * every STAKE (bft.c:1591, qgp_fp_raw_to_hex) and what live genesis
     * chain_defs carry. The earlier memset-empty fp was an unrealistic
     * fixture shape: the V2 writable-shape verdict rightly WRITE-FREEZES
     * such rows (legacy-malformed), which would make every delegation
     * onto a fixture validator reject for a reason no live row has. */
    for (int i = 0; i < nval; i++) {
        dnac_validator_record_t v;
        uint8_t fpr[64];
        static const char hexd[] = "0123456789abcdef";
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, vkeys[i], 2592);
        v.self_stake = VAL_BOND;
        v.status = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        /* O14: genesis binds the COMMITTED validator-set hash, so a
         * fixture on "another chain" must commit a DIFFERENT set. Vary
         * commission_bps — it is carried into the snapshot entry
         * (nodus_witness_vset.c:363) so it moves the set hash, the
         * genesis BlockID and the chain id — while leaving the signing
         * pubkeys untouched, which the real-key QC/approval matrices
         * depend on. Only the NON-default chains differ, so the ordinary
         * fixture's commission stays exactly 0 and the
         * commission-semantics tests are untouched. */
        v.commission_bps = (g_gid_fill == 0xEE) ? 0
                                                : (uint16_t)g_gid_fill;
        if (qgp_sha3_512(vkeys[i], 2592, fpr) != 0) return -1;
        for (int b2 = 0; b2 < 64; b2++) {
            v.unstake_destination_fp[2 * b2]     = hexd[fpr[b2] >> 4];
            v.unstake_destination_fp[2 * b2 + 1] = hexd[fpr[b2] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
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

    /* O14: the chain is differentiated by the committed VALIDATOR SET,
     * since genesis must bind the committed authority. This fixture
     * seeds its own real-key validators above, so vary the set by also
     * seeding a filler keyed on g_gid_fill BEFORE genesis. */
    uint8_t vset[64];
    mk_id(vset, g_gid_fill);
    if (v2x_seed_authority_fill(fx->w, g_gid_fill) != 0) return -1;
    if (v2x_genesis_min(fx->w, vset, NULL, NULL) != 0) return -1;
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

/* The COMPILED ruleset version of a domain — never a literal. Every leg
 * this file builds derives its ruleset_version from the production
 * table, so a season that advances a ruleset (O11: both 2 → 3) does not
 * silently turn every envelope here into a five-axis lookup miss. */
static uint32_t rsv_of(uint32_t domain_id) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    return domain_id == DNA_DOMAIN_SYSTEM ? t[0].ruleset_version
                                          : t[1].ruleset_version;
}

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
    /* the committed ruleset version, DERIVED from the compiled table */
    leg.hdr.ruleset_version = rsv_of(domain_id);
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
    leg.hdr.ruleset_version = rsv_of(DNA_DOMAIN_SYSTEM);
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

/* The CORE-side conservation identity, read straight from the tables —
 * the same buckets nodus_rt_core_invariant sums (v2_claims.c:787).
 * O11: `total_delegated` was MISSING here and had to be added — every
 * fixture before the stake lifecycle had an all-zero delegated bucket,
 * so the omission was invisible; a DELEGATE moves value INTO it and the
 * helper would have reported a false violation (the engine's own gate
 * always counted it).
 *
 * O15J Faz 2: `epoch_pool` was added here because the V2 lane grew a
 * per-block mint that credits total_minted AND epoch_state.epoch_pool_accum
 * together (nodus_witness_v2_econ.c, engine phase 6f), so a helper that
 * counts `m` but not the pool reports a false violation on any minting
 * chain — the engine's own gate always counted it
 * (nodus_witness_v2_claims.c).
 *
 * ⚠ HONEST LABEL, added by review R2-F7: in THIS file the term is
 * currently DEAD. main sets v2x_inflation_off = 1 and every fixture
 * reaches genesis through v2x_genesis_min, so no epoch_state row is ever
 * created: `ep` is 0 at all 20+ call sites and the identity is
 * byte-equivalent to its pre-Faz-2 form. A mutant deleting `+ ep` below
 * survives every assertion in this file.
 *
 * It is kept, not reverted, for two reasons: the helper is correct for
 * the general case and would silently start lying if this file ever
 * un-quiets, and deleting it would leave the next author to rediscover
 * the same thing. But it must not be COUNTED as coverage — emission's
 * effect on the supply identity is proven in test_v2_econ, where the
 * chain actually mints. Unclaimed distribution and shielded remain zero
 * in this file. */
static int supply_identity_holds(nodus_witness_t *w) {
    uint64_t g = q1(w, "SELECT genesis_supply FROM supply_tracking");
    uint64_t m = q1(w, "SELECT total_minted FROM supply_tracking");
    uint64_t bu = q1(w, "SELECT total_burned FROM supply_tracking");
    uint64_t ux = q1(w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set "
                        "WHERE token_id = zeroblob(64)");
    uint64_t bo = q1(w, "SELECT COALESCE(SUM(self_stake),0) FROM validators");
    uint64_t dl = q1(w, "SELECT COALESCE(SUM(total_delegated),0) "
                        "FROM validators");
    uint64_t ep = q1(w, "SELECT COALESCE(SUM(epoch_pool_accum),0) "
                        "FROM epoch_state");
    if (g == UINT64_MAX || m == UINT64_MAX || bu == UINT64_MAX ||
        ux == UINT64_MAX || bo == UINT64_MAX || dl == UINT64_MAX ||
        ep == UINT64_MAX)
        return 0;
    return g + m - bu == ux + bo + dl + ep;
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
     * types 11/12/13 stay dead through this lane too).
     * O11/O12 note: SYSTEM ops 1..5 (the stake lifecycle plus
     * VALIDATOR_UPDATE) and CORE op 7 (SYSFUND) ARE implemented now, and
     * both loops still hold for the right reason — every one of these
     * legs carries a 1-byte call, which no compiled parser accepts, and
     * each validator-record op additionally requires the 2-leg envelope
     * shape a single-leg envelope cannot have. The loops therefore pin
     * "unimplemented op rejects" for CORE 2..6, and "malformed call /
     * wrong envelope shape rejects" for SYSTEM 1..5. */
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
     * the governing set changes: key 6 rotates OUT, key 15 rotates IN.
     * The voters (keys 0..4) are all STILL seated — only the SNAPSHOT
     * identity moved, so this isolates the snapshot binding, not
     * membership.
     *
     * O14: the rotation is now applied to the COMMITTED SNAPSHOT, not
     * just the validators table. Before O14 these fixtures carried no
     * snapshot at all, so committee resolution fell back to recomputing
     * from the live table and a bare table swap was enough. Now the
     * frozen snapshot IS the authority — and correctly SURVIVES a live
     * table edit — so the set has to be re-frozen for the governing
     * identity to actually move. That makes this test exercise the real
     * authority mechanism instead of a recompute fallback. */
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
        /* Re-freeze the governing set over the rotated table, so the
         * RESOLVED authority genuinely changes (see the note above). */
        CHECK(run_sql(fx.w->db, "DELETE FROM validator_set_snapshots") == 0,
              "clear snapshots");
        CHECK(nodus_witness_vset_commit_genesis(fx.w, 1) == 0,
              "re-freeze rotated set");
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

/* ══ 3a. O15F — V2-lane TARGET_ACTIVE_COUNT range narrowing [7..30] ═══
 *
 * D2: a runtime-op-6 CHAIN_CONFIG envelope raising TARGET_ACTIVE_COUNT
 * (param 4) above NODUS_V2_ACTIVE_SET_MAX (30) is a deterministic VERDICT
 * reject — checked in rtn_cc_exec AFTER the shared scalar rules, and the
 * exec hook is PURE (no witness handle), so the bound is V2-lane-GLOBAL.
 * The legacy scalar range [7..128] still ADMITS 31 (that is what makes
 * this the NEW rule); 30 (== max, accept side of the off-by-one) and 20
 * commit. */
static int test_system_cc_target_active_max(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "ccmax") == 0, "genesis");
    int voters5[5] = { 0, 1, 2, 3, 4 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;

    /* TARGET_ACTIVE_COUNT carries the SAFETY grace class, so `effective`
     * must clear H + DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS (17280 in the
     * default build) — 20000/20001 do, at H=1/H=2. valid_before exceeds
     * both (scalar window + freshness). */
    const uint64_t EFF0 = 20000, EFF1 = 20001, VB = 30000;

    /* 31 > 30: rejects as a deterministic verdict, DB byte-identical.
     * The scalar rule [7..128] ACCEPTS 31, so before the D2 narrowing
     * lands this envelope COMMITS and apply_reject FAILS here — the
     * failing-test proof. */
    CHECK(cc_env(&fx, &e, 1, DNAC_CFG_TARGET_ACTIVE_COUNT, 31, EFF0, 0x31,
                 1, VB, voters5, 5, 0, NULL, NULL) == 0, "build 31");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "TARGET_ACTIVE_COUNT=31 must reject (V2-lane max 30)");
        OK();
    }

    /* 30 == NODUS_V2_ACTIVE_SET_MAX: commits (accept side; the 31 reject
     * left no row, so EFF0 is free). */
    CHECK(cc_env(&fx, &e, 1, DNAC_CFG_TARGET_ACTIVE_COUNT, 30, EFF0, 0x30,
                 1, VB, voters5, 5, 0, NULL, NULL) == 0, "build 30");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "TARGET_ACTIVE_COUNT=30 must commit");
        OK();
    }
    CHECK((uint64_t)q1(fx.w, "SELECT new_value FROM chain_config_history "
                   "WHERE param_id=4 AND effective_block=20000") == 30,
          "target=30 row committed"); OK();

    /* 20 < max: commits at H=2 (distinct effective ⇒ distinct PK). */
    CHECK(cc_env(&fx, &e, 2, DNAC_CFG_TARGET_ACTIVE_COUNT, 20, EFF1, 0x20,
                 1, VB, voters5, 5, 0, NULL, NULL) == 0, "build 20");
    {
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "TARGET_ACTIVE_COUNT=20 must commit");
        OK();
    }
    CHECK((uint64_t)q1(fx.w, "SELECT new_value FROM chain_config_history "
                   "WHERE param_id=4 AND effective_block=20001") == 20,
          "target=20 row committed"); OK();

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
        leg.hdr.ruleset_version = rsv_of(DNA_DOMAIN_CORE);
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
            leg.hdr.ruleset_version = rsv_of(DNA_DOMAIN_CORE);
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
            leg.hdr.ruleset_version = rsv_of(DNA_DOMAIN_CORE);
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
         * consulted (same height + asserted committed id ⇒ rc 1, no
         * writes). O14 D6: the id is ENGINE-derived, so the replay
         * asserts the one the engine actually committed. */
        uint8_t idc[64];
        CHECK(v2x_block_id_at(c.w, 1, idc) == 0, "read committed id (c)");
        nodus_v2_block_t bf;
        mk_block(&bf, 1, &ve, 1);
        bf.expect_block_id = idc;
        CHECK(nodus_witness_v2_apply_block(c.w, &bf) == 1,
              "identical replay is idempotent (rc 1)");
        OK();
        /* restart: reopen the DB and replay the committed block */
        CHECK(fx_reopen(&a) == 0, "reopen");
        uint8_t ida[64];
        CHECK(v2x_block_id_at(a.w, 1, ida) == 0, "read committed id (a)");
        nodus_v2_block_t br;
        mk_block(&br, 1, &ve, 1);
        br.expect_block_id = ida;
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
        /* O14: no id is assigned. Different wire ⇒ different tx_root ⇒
         * the engine DERIVES different BlockIDs. What the test used to
         * assert by construction is now a property of the engine, and
         * the digest comparison below is what proves it. */
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
            uint8_t id1[64];
            CHECK(v2x_block_id_at(a.w, 1, id1) == 0, "read committed id1");
            nodus_v2_block_t be;
            mk_block(&be, 1, &va, 1);
            be.expect_block_id = id1;
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
        /* O14: ids are engine-derived — see the twin note above. */
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
        /* O14: prev is DERIVED from chain O's own committed genesis, so
         * the block reaches the auth stage without being told to. */
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
        /* O14: ids are engine-derived — see the twin note above. */
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
        /* O14: prev is DERIVED from chain O2's own committed genesis. */
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
        /* O14: id derived by the engine. */
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
        /* O14: prev derived from this chain's own committed genesis. */
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
        /* O14: id derived by the engine. */
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

/* ══ 11. SYSTEM slice — STAKE + the CORE funding leg (O11) ═════════
 *
 * The first CROSS-DOMAIN operation of the V2 lane: one envelope, two
 * legs (SYSTEM record + CORE funding), one intent, one fee. The section
 * covers the two positive shapes (destination fingerprint derived from
 * the staker's own key, and NOT derived), the adversarial matrix, and
 * the identity/replay behaviour of a two-leg envelope. */

#define STAKE_BOND    DNAC_SELF_STAKE_AMOUNT      /* 10M × 10^8 raw     */
#define STAKE_CHANGE  250000ULL
#define STAKE_FUND    (STAKE_BOND + FEE_MIN + STAKE_CHANGE)
#define STAKE_BPS     500u

/* STAKE call v1 (exact 2666 B): staker_pubkey ‖ commission_bps u16
 * ‖ bond u64 ‖ unstake_destination_fp[64 RAW]. */
static uint32_t stake_call_build(uint8_t *dst, size_t cap, int staker,
                                 uint32_t bps, uint64_t bond,
                                 const uint8_t dest_fp[64]) {
    if (cap < 2666) return 0;
    memcpy(dst, g_pk[staker], 2592);
    dst[2592] = (uint8_t)(bps >> 8);
    dst[2593] = (uint8_t)bps;
    for (int i = 0; i < 8; i++)
        dst[2594 + i] = (uint8_t)(bond >> (56 - 8 * i));
    memcpy(dst + 2602, dest_fp, 64);
    return 2666;
}

/* the RAW 64-byte fingerprint of a test key (the call carries raw
 * bytes; the validator row stores the 128-char hex form) */
static int key_fp_raw(int k, uint8_t out[64]) {
    return qgp_sha3_512(g_pk[k], 2592, out) == 0 ? 0 : -1;
}

/* two-leg build knobs */
typedef struct {
    uint8_t sys_auth_kind;   /* 0 = kind 1                              */
    int     break_sys_sig;   /* flip one byte of leg0's first signature */
    int     break_core_sig;
    int     sys_sign_with;   /* >0: sign leg0 with THIS key's secret    */
} two_opt_t;

/* Build + sign the canonical 2-leg envelope: leg0 SYSTEM(sys_op),
 * leg1 CORE(core_op), each independently kind-1 signed by its own
 * signer set over ITS OWN leg auth_digest (which hangs from the ONE
 * auth_context_commit covering BOTH legs' call commitments — so no leg
 * can be spliced onto another envelope). */
static int two_leg_build(fixture_t *fx, env_t *e,
                         uint32_t sys_op, const uint8_t *sys_call,
                         uint32_t sys_len,
                         uint32_t core_op, const uint8_t *core_call,
                         uint32_t core_len, uint64_t fee,
                         const int *sys_signers, int n_sys,
                         const int *core_signers, int n_core,
                         const two_opt_t *opt_in) {
    two_opt_t o;
    memset(&o, 0, sizeof(o));
    if (opt_in) o = *opt_in;
    if (n_sys < 1 || n_sys > 15 || n_core < 1 || n_core > 15) return -1;

    uint32_t alen[2] = { 1 + (uint32_t)n_sys * 7219u,
                         1 + (uint32_t)n_core * 7219u };
    uint8_t *auth[2];
    auth[0] = calloc(1, alen[0]);
    auth[1] = calloc(1, alen[1]);
    dna_env_leg_in_t legs[2];
    dna_env_in_t in;
    dna_env_view_t v;
    const nodus_domain_runtime_t *t;
    size_t rn = 0;
    uint8_t cc[2][64], acc[64];
    int ord[2][15];
    int nsg[2];
    const int *src[2];
    int rc = -1;

    if (!auth[0] || !auth[1]) goto done;
    nsg[0] = n_sys;  nsg[1] = n_core;
    src[0] = sys_signers; src[1] = core_signers;
    for (int L = 0; L < 2; L++) {
        for (int i = 0; i < nsg[L]; i++) ord[L][i] = src[L][i];
        for (int a = 1; a < nsg[L]; a++)          /* ascending pubkeys  */
            for (int b = a; b > 0 &&
                 memcmp(g_pk[ord[L][b - 1]], g_pk[ord[L][b]], 2592) > 0;
                 b--) {
                int tmp = ord[L][b];
                ord[L][b] = ord[L][b - 1];
                ord[L][b - 1] = tmp;
            }
    }

    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = sys_op;
    legs[0].hdr.ruleset_version = rsv_of(DNA_DOMAIN_SYSTEM);
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = o.sys_auth_kind ? o.sys_auth_kind : 1;
    legs[0].hdr.call_len = sys_len;
    legs[0].hdr.auth_len = alen[0];
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = sys_call;
    legs[0].auth_data = auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = core_op;
    legs[1].hdr.ruleset_version = rsv_of(DNA_DOMAIN_CORE);
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = 1;
    legs[1].hdr.call_len = core_len;
    legs[1].hdr.auth_len = alen[1];
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = core_call;
    legs[1].auth_data = auth[1];

    memset(&in, 0, sizeof(in));
    in.fee_amount = fee;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        goto done;
    if (dna_env_decode(e->bytes, e->len, &v) != 0) goto done;
    t = nodus_runtime_builtin_table(&rn);
    if (!t || rn != 2) goto done;
    if (dna_env_call_commit(&v, 0, t[0].ruleset_hash, cc[0]) != 0 ||
        dna_env_call_commit(&v, 1, t[1].ruleset_hash, cc[1]) != 0 ||
        dna_env_auth_context_commit(&v, fx->chain_id,
            (const uint8_t (*)[64])cc, acc) != 0)
        goto done;

    for (uint16_t L = 0; L < 2; L++) {
        uint8_t digest[64];
        if (dna_env_auth_digest(acc, L, legs[L].hdr.domain_id,
                                legs[L].hdr.runtime_op, digest) != 0)
            goto done;
        auth[L][0] = (uint8_t)nsg[L];
        for (int i = 0; i < nsg[L]; i++) {
            uint8_t *slot = auth[L] + 1 + (size_t)i * 7219;
            size_t siglen = 4627;
            int sk = ord[L][i];
            memcpy(slot, g_pk[ord[L][i]], 2592);
            if (L == 0 && o.sys_sign_with > 0) sk = o.sys_sign_with;
            if (qgp_dsa87_sign(slot + 2592, &siglen, digest, 64,
                               g_sk[sk]) != 0 || siglen != 4627)
                goto done;
        }
    }
    if (o.break_sys_sig)  auth[0][1 + 2592] ^= 0x01;
    if (o.break_core_sig) auth[1][1 + 2592] ^= 0x01;

    legs[0].auth_data = auth[0];
    legs[1].auth_data = auth[1];
    rc = dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len);
done:
    free(auth[0]);
    free(auth[1]);
    return rc;
}

/* Both identities of a TWO-leg envelope, derived exactly as the engine
 * does (derive_ids is the single-leg form). */
static int derive_ids2(fixture_t *fx, const env_t *e,
                       uint8_t wire_out[64], uint8_t intent_out[64]) {
    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    dna_env_leg_ctx_t lctx[2];
    if (!bt || n != 2) return -1;
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = bt[0].ruleset_version;
    memcpy(lctx[0].ruleset_hash, bt[0].ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = bt[1].ruleset_version;
    memcpy(lctx[1].ruleset_hash, bt[1].ruleset_hash, 64);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    int rc = -1;
    if (dna_env_preflight(e->bytes, e->len, fx->chain_id, 1, lctx, 2, pf)
        == DNA_ENV_PF_OK) {
        memcpy(wire_out, pf->wire_id, 64);
        memcpy(intent_out, pf->intent_id, 64);
        rc = 0;
    }
    free(pf);
    return rc;
}

/* one validator column, by pubkey_hash (integer columns only) */
static uint64_t val_col(nodus_witness_t *w, const uint8_t pkh[64],
                        const char *col) {
    char sql[192];
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM validators WHERE pubkey_hash = ?1", col);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_blob(st, 1, pkh, 64, SQLITE_TRANSIENT);
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* the validator-tree leaf key the adapter and the merkle loader share */
static int val_key(int k, uint8_t out[64]) {
    uint8_t pre[1 + 2592];
    pre[0] = NODUS_TREE_TAG_VALIDATOR;
    memcpy(pre + 1, g_pk[k], 2592);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* full-row assertion helper: every column of one validator row, blobs
 * and text included. @return 0 = all match. */
static int val_row_matches(nodus_witness_t *w, const uint8_t pkh[64],
                           int staker, uint64_t bond, uint32_t bps,
                           uint64_t since, const char *dest_fp_hex,
                           int dest_pk_key /* -1 = all-zero */) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey, self_stake, total_delegated, "
            "external_delegated, commission_bps, pending_commission_bps, "
            "pending_effective_block, status, active_since_block, "
            "unstake_commit_block, unstake_destination_fp, "
            "unstake_destination_pubkey, last_validator_update_block, "
            "consecutive_missed_epochs, last_signed_block, "
            "signed_blocks_this_epoch FROM validators "
            "WHERE pubkey_hash = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, pkh, 64, SQLITE_TRANSIENT);
    int ok = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const uint8_t *pk = sqlite3_column_blob(st, 0);
        const char *fp = (const char *)sqlite3_column_text(st, 10);
        const uint8_t *dpk = sqlite3_column_blob(st, 11);
        uint8_t zero[2592];
        memset(zero, 0, sizeof(zero));
        ok = (pk && sqlite3_column_bytes(st, 0) == 2592 &&
              memcmp(pk, g_pk[staker], 2592) == 0 &&
              (uint64_t)sqlite3_column_int64(st, 1) == bond &&
              sqlite3_column_int64(st, 2) == 0 &&
              sqlite3_column_int64(st, 3) == 0 &&
              (uint32_t)sqlite3_column_int64(st, 4) == bps &&
              sqlite3_column_int64(st, 5) == 0 &&
              sqlite3_column_int64(st, 6) == 0 &&
              sqlite3_column_int64(st, 7) == 0 &&
              (uint64_t)sqlite3_column_int64(st, 8) == since &&
              sqlite3_column_int64(st, 9) == 0 &&
              fp && strlen(fp) == 128 &&
              memcmp(fp, dest_fp_hex, 128) == 0 &&
              dpk && sqlite3_column_bytes(st, 11) == 2592 &&
              memcmp(dpk, dest_pk_key >= 0 ? g_pk[dest_pk_key] : zero,
                     2592) == 0 &&
              sqlite3_column_int64(st, 12) == 0 &&
              sqlite3_column_int64(st, 13) == 0 &&
              sqlite3_column_int64(st, 14) == 0 &&
              sqlite3_column_int64(st, 15) == 0) ? 0 : -1;
    }
    sqlite3_finalize(st);
    return ok;
}

static uint64_t active_count(nodus_witness_t *w) {
    return q1(w, "SELECT value FROM validator_stats WHERE "
                 "key = 'active_count'");
}

static uint64_t utxo_rows(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    uint64_t n = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static uint64_t dom_height(nodus_witness_t *w, uint32_t dom) {
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT domain_height FROM v2_domain_heads WHERE "
             "domain_id = %u", dom);
    return q1(w, sql);
}

static int test_system_stake(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "stake") == 0, "genesis");
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    int s9[1]  = { 9 };
    int s10[1] = { 10 };
    int s11[1] = { 11 };
    int s9x[2] = { 9, 11 };
    static uint8_t scall[4096], fcall[8192];
    uint8_t fp9[64], fp_other[64];
    CHECK(key_fp_raw(9, fp9) == 0 && key_fp_raw(K_STRAY, fp_other) == 0,
          "fps");

    /* funding: one UTXO per staker + one owned by an unrelated key */
    uint8_t f9[64], f10[64], f11[64], ftok[64];
    CHECK(seed_funding(&fx, 9, STAKE_FUND, 0xF1, f9) == 0, "fund 9");
    CHECK(seed_funding(&fx, 10, STAKE_FUND, 0xF2, f10) == 0, "fund 10");
    CHECK(seed_funding(&fx, 11, STAKE_FUND, 0xF3, f11) == 0, "fund 11");
    {
        static uint8_t tokS[64];
        memset(tokS, 0x5A, sizeof(tokS));
        CHECK(seed_token_utxo(&fx, 9, 900, 0xF4, tokS, ftok) == 0,
              "fund token");
    }
    uint8_t in9[1][64], in11[1][64], in2[2][64];
    memcpy(in9[0], f9, 64);
    memcpy(in11[0], f11, 64);
    memcpy(in2[0], f9, 64);
    memcpy(in2[1], ftok, 64);

    /* ── §C negative matrix (each a digest-proven no-op at height 1) ── */

    /* C1 insufficient funding: the change swallows the bond */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE + 1, 0x51, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C1 underfunded stake must reject");
        OK();
    }
    /* C2 wrong owner: key 11's UTXO funds key 9's stake (balanced) */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x52, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in11, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C2 unowned funding input must reject");
        OK();
    }
    /* C3 non-native INPUT: the native side balances exactly, the token
     * input's 900 units are simply outside the equation — the
     * native-only narrowing is the only violated rule */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x53, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in2, 2, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C3 non-native funding input must reject");
        OK();
    }
    /* C4 non-native CHANGE output: the two outputs sum to exactly the
     * native change, so conservation would PASS if the parse-side
     * native-only rule were removed */
    {
        static uint8_t tokC[64];
        memset(tokC, 0x5B, sizeof(tokC));
        out_spec_t o[2] = { { 9, STAKE_CHANGE - 1, 0x54, NULL },
                            { 9, 1, 0x55, tokC } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 2);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C4 non-native change output must reject");
        OK();
    }
    /* C5 zero-amount change output (balanced: the pair sums right) */
    {
        out_spec_t o[2] = { { 9, STAKE_CHANGE, 0x56, NULL },
                            { 9, 0, 0x57, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 2);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C5 zero-amount change output must reject");
        OK();
    }
    /* C6 bond below the self-bond floor (conservation still balances —
     * the floor is the only violated rule) */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE + 1, 0x58, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND - 1, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C6 bond below DNAC_SELF_STAKE_AMOUNT must reject");
        OK();
    }
    /* C7 commission above the client bound (the LABELED NARROWING) */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x59, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9,
                                       DNAC_COMMISSION_BPS_MAX + 1,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C7 commission_bps > 10000 must reject");
        OK();
    }
    /* C8 duplicate input nullifier, BALANCED for the doubled sum: if the
     * ascending-order dedup were removed, conservation would pass */
    {
        out_spec_t o[1] = { { 9, STAKE_FUND + STAKE_CHANGE, 0x5A, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        static uint8_t dup[8192];
        dup[0] = 2;
        memcpy(dup + 1, f9, 64);
        memcpy(dup + 65, f9, 64);
        memcpy(dup + 129, fcall + 65, fl - 65);
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, dup, fl + 64, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C8 duplicate funding input must reject");
        OK();
    }
    /* C9 fee below the shipped floors (balanced for that fee) */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE + 1, 0x5B, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN - 1,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C9 sub-floor fee must reject");
        OK();
    }
    /* C10 fee MISMATCH: the equation balances for FEE_MIN, the envelope
     * declares FEE_MIN + 1 — the fee is not a free parameter */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x5C, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN + 1,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C10 declared fee != what the inputs release must reject");
        OK();
    }
    /* C11 MISSING CORE LEG: a single-leg SYSTEM STAKE envelope */
    {
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        CHECK(sl, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_SYSTEM,
                               DNA_SYSRULE_STAKE, scall, sl, 0, 0, 8,
                               16384, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C11 single-leg STAKE (no funding) must reject");
        OK();
    }
    /* C12 MISSING SYSTEM LEG: a single-leg CORE SYSFUND envelope */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x5D, NULL } };
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(fl, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                               0, 40, 16384, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C12 single-leg SYSFUND (no record) must reject");
        OK();
    }
    /* C13 SIBLING-OP MISMATCH: leg0 is a CHAIN_CONFIG leg, so the
     * funding leg has no stake-lifecycle partner.
     * HONEST LABEL: this pins that the COMPOSITION rejects, not WHICH
     * rule rejects it. Legs execute in order and leg0 runs first, so the
     * CHAIN_CONFIG exec dies on its own rules (fee_amount != 0, then
     * quorum) before leg1's sibling gate is ever consulted — and a
     * variant where leg0 survives is structurally inexpressible, because
     * CC requires fee 0 while SYSFUND requires fee >= the floor. The
     * sibling gate itself is pinned in isolation at the hook layer
     * (§12 P5, over BOTH foreign SYSTEM ops incl. this one). */
    {
        uint8_t cc41[41];
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x5E, NULL } };
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(cc_call_build(cc41, sizeof(cc41), 1, 7, 100, 1, 0,
                            UINT64_MAX) == 41 && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_CHAIN_CONFIG, cc41, 41,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C13 SYSFUND with a non-staking sibling must reject");
        OK();
    }
    /* C14 SYSTEM-leg EXTRA SIGNER: two valid kind-1 signers on the
     * record leg. The verdict is legitimate; STAKE's own authority rule
     * (exactly one signer) rejects it at exec — a twin can never write a
     * divergent row because it can never write at all. */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x5F, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9x, 2, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C14 extra SYSTEM signer must reject (n_signers != 1)");
        OK();
    }
    /* C15 IDENTITY MISMATCH: the record leg is validly signed — by the
     * WRONG key. The call names staker 9; the verified fingerprint is
     * key 11's, so the call-carried identity and the verdict disagree. */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x60, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C15 signer fp != SHA3(call.staker_pubkey) must reject");
        OK();
    }
    /* C16 broken record-leg signature (the auth boundary itself) */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x61, NULL } };
        two_opt_t to;
        memset(&to, 0, sizeof(to));
        to.break_sys_sig = 1;
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, &to) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C16 invalid record-leg signature must reject");
        OK();
    }
    /* C17 broken funding-leg signature */
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x62, NULL } };
        two_opt_t to;
        memset(&to, 0, sizeof(to));
        to.break_core_sig = 1;
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, &to) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C17 invalid funding-leg signature must reject");
        OK();
    }

    /* ── §A the canonical positive (destination fp = the staker's own) ─ */
    uint64_t burned0 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint8_t sys_head0[89], core_head0[89];
    CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_head0) == 0, "sys head");
    CHECK(head_blob(fx.w, DNA_DOMAIN_CORE, core_head0) == 0, "core head");
    CHECK(active_count(fx.w) == 0, "fixture starts with active_count 0");
    OK();
    uint8_t pkh9[64], pkh10[64];
    CHECK(val_key(9, pkh9) == 0 && val_key(10, pkh10) == 0, "keys");
    env_t e_a;
    uint8_t a_wire[64], a_intent[64], chg9[64];
    {
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x71, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e_a, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &e_a, a_wire, a_intent) == 0, "ids");
        CHECK(out_nul(9, 0x71, chg9) == 0, "change id");
        nodus_v2_envelope_t ve = { e_a.bytes, e_a.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "A: the canonical STAKE must commit");
        OK();
    }
    /* every validator column, exactly */
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM validators") == 7 + 1,
          "A: exactly one new validator row"); OK();
    CHECK(val_row_matches(fx.w, pkh9, 9, STAKE_BOND, STAKE_BPS, 1,
                          g_fp[9], /*dest_pk=*/9) == 0,
          "A: validator row columns"); OK();
    CHECK(active_count(fx.w) == 1, "A: active_count == 1"); OK();
    /* the funding leg's own effects */
    CHECK(utxo_rows(fx.w, f9) == 0, "A: funding input deleted"); OK();
    CHECK(utxo_rows(fx.w, chg9) == 1, "A: change UTXO created"); OK();
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT amount, owner, tx_hash, output_index, block_height, "
              "unlock_block, token_id FROM utxo_set WHERE nullifier = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, chg9, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW, "row");
        uint8_t zt[64];
        memset(zt, 0, sizeof(zt));
        CHECK((uint64_t)sqlite3_column_int64(st, 0) == STAKE_CHANGE &&
              memcmp(sqlite3_column_text(st, 1), g_fp[9], 128) == 0 &&
              sqlite3_column_bytes(st, 2) == 64 &&
              memcmp(sqlite3_column_blob(st, 2), a_intent, 64) == 0 &&
              sqlite3_column_int64(st, 3) == 0 &&
              sqlite3_column_int64(st, 4) == 1 &&
              sqlite3_column_int64(st, 5) == 0 &&
              memcmp(sqlite3_column_blob(st, 6), zt, 64) == 0,
              "A: change row binds the INTENT identity + the right shape");
        sqlite3_finalize(st);
        OK();
    }
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
              == burned0 + FEE_MIN,
          "A: burned += the fee and ONLY the fee"); OK();
    CHECK(supply_identity_holds(fx.w),
          "A: the CORE conservation identity still holds"); OK();
    /* both domains moved, each exactly once */
    {
        uint8_t sh[89], ch[89];
        CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sh) == 0 &&
              head_blob(fx.w, DNA_DOMAIN_CORE, ch) == 0, "heads");
        CHECK(memcmp(sh, sys_head0, 89) != 0 &&
              memcmp(ch, core_head0, 89) != 0,
              "A: BOTH domain heads must move"); OK();
        CHECK(dom_height(fx.w, DNA_DOMAIN_SYSTEM) == 1 &&
              dom_height(fx.w, DNA_DOMAIN_CORE) == 1,
              "A: each domain advanced exactly once"); OK();
    }

    /* ── §B second positive: a destination fingerprint that is NOT
     *    derived from the staker's key leaves the destination PUBKEY
     *    all-zero (bft.c:1596-1600) ─────────────────────────────────── */
    {
        uint8_t in10[1][64], chg10[64];
        out_spec_t o[1] = { { 10, STAKE_CHANGE, 0x72, NULL } };
        memcpy(in10[0], f10, 64);
        uint32_t sl = stake_call_build(scall, sizeof(scall), 10,
                                       STAKE_BPS, STAKE_BOND, fp_other);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in10, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s10, 1, s10, 1, NULL) == 0, "build");
        CHECK(out_nul(10, 0x72, chg10) == 0, "change id");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "B: foreign-destination STAKE must commit"); OK();
        CHECK(val_row_matches(fx.w, pkh10, 10, STAKE_BOND, STAKE_BPS, 2,
                              g_fp[K_STRAY], /*dest_pk=*/-1) == 0,
              "B: destination pubkey stays all-zero"); OK();
        CHECK(active_count(fx.w) == 2, "B: active_count == 2"); OK();
        CHECK(utxo_rows(fx.w, chg10) == 1, "B: change UTXO"); OK();
        CHECK(supply_identity_holds(fx.w), "B: supply identity"); OK();
    }

    /* ── §C (stateful tail) ─────────────────────────────────────────── */
    /* C18 RULE I: a SECOND stake for the same pubkey. The call bytes
     * DIFFER (another commission), so the intent guard cannot be what
     * rejects it — the ABSENT validator read is. */
    {
        uint8_t f9b[64], in9b[1][64];
        CHECK(seed_funding(&fx, 9, STAKE_FUND, 0xF5, f9b) == 0, "fund");
        memcpy(in9b[0], f9b, 64);
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x73, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9,
                                       STAKE_BPS + 1, STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9b, 1, o, 1);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C18 Rule I: a second stake for one pubkey must reject");
        OK();
        CHECK(active_count(fx.w) == 2 &&
              val_col(fx.w, pkh9, "commission_bps") == STAKE_BPS,
              "C18 the existing row is untouched"); OK();
    }
    /* C19 byte-identical WIRE replay in a later block.
     * HONEST LABEL: two rules are CO-SUFFICIENT here and the test does
     * not separate them — the committed-identity guard fires pre-BEGIN,
     * and the funding input this envelope names was consumed by §A, so
     * a mutant removing the guard would still see the leg reject on a
     * missing input. That is structural: an intent twin of a COMMITTED
     * staking intent necessarily re-spends the same UTXO. The guard
     * itself is pinned in isolation by §7 (test_intent_engine), on a
     * SPEND whose inputs can be reconstructed. */
    {
        nodus_v2_envelope_t ve = { e_a.bytes, e_a.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C19 byte-identical replay must reject"); OK();
    }
    /* C20 AUTH TWIN: the same intent authorized by a DIFFERENT valid
     * witness (an extra funding-leg signer). The load-bearing assertions
     * here are the two IDENTITY ones — an extra witness must not move
     * intent_id and must move wire_id, which is what makes a two-leg
     * staking envelope twin-stable. The block-level rejection carries
     * the same C19 co-sufficiency caveat. */
    {
        int core2[2] = { 9, 11 };
        out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x71, NULL } };
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
        env_t e_t;
        uint8_t t_wire[64], t_intent[64];
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e_t, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, core2, 2, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &e_t, t_wire, t_intent) == 0, "ids");
        CHECK(memcmp(t_intent, a_intent, 64) == 0,
              "C20 an extra witness must NOT move the intent id"); OK();
        CHECK(memcmp(t_wire, a_wire, 64) != 0,
              "C20 it MUST move the wire id"); OK();
        nodus_v2_envelope_t ve = { e_t.bytes, e_t.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "C20 the auth twin must reject on the committed intent");
        OK();
    }
    CHECK(supply_identity_holds(fx.w), "tail: supply identity"); OK();
    fx_close(&fx);
    return 0;
}

/* ══ 12. O11 HOOK-LEVEL fail-closed pins ═══════════════════════════
 * Seams a block-level test cannot observe, because the next layer
 * produces the same block verdict:
 *   - the SYSTEM hooks refuse a leg that is not the canonical 2-leg
 *     staking shape (leg_count 1, wrong sibling op);
 *   - the STAKE exec refuses a kind-2 record leg — SYSTEM's ALLOWLIST
 *     permits the carriage, the OP decides its own authority;
 *   - the SYSTEM adapter's row readers fail CLOSED on malformed
 *     (negative-integer) validator_stats / validators rows. */
static int test_o11_hook_pins(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "o11hk") == 0, "genesis");
    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    const nodus_domain_runtime_t *sys = &bt[0];
    const nodus_domain_runtime_t *core = &bt[1];
    int s9[1] = { 9 };
    static uint8_t scall[4096], fcall[8192];
    uint8_t fp9[64], f9[64], in9[1][64];
    CHECK(key_fp_raw(9, fp9) == 0, "fp");
    CHECK(seed_funding(&fx, 9, STAKE_FUND, 0xE1, f9) == 0, "fund");
    memcpy(in9[0], f9, 64);
    out_spec_t o[1] = { { 9, STAKE_CHANGE, 0x81, NULL } };
    uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                   STAKE_BOND, fp9);
    uint32_t fl = spend_call_build(fcall, sizeof(fcall), in9, 1, o, 1);
    CHECK(sl && fl, "call");

    env_t e;
    CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                        DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                        s9, 1, s9, 1, NULL) == 0, "build");
    dna_env_view_t v;
    CHECK(dna_env_decode(e.bytes, e.len, &v) == 0, "decode");

    nodus_rt_auth_verdict_t av;
    memset(&av, 0, sizeof(av));
    av.n_signers = 1;
    CHECK(qgp_sha3_512(g_pk[9], 2592, av.signer_fp[0]) == 0, "fp");
    static uint8_t iid[64];
    memset(iid, 0x44, 64);
    nodus_rt_exec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = fx.chain_id;
    ctx.global_height = 1;
    ctx.intent_id = iid;
    ctx.wire_id = iid;
    ctx.auth = &av;

    /* the honest hook-level round-trip first (so every negative below is
     * a real difference, not a broken harness) */
    nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
    uint16_t nr = 0;
    CHECK(nodus_rt_system_read_plan(sys, &v, 0, &ctx, reqs,
                                    NODUS_RT_MAX_READS, &nr) == 0 &&
          nr == 2, "STAKE plans the validator + counter reads"); OK();
    nodus_rt_read_res_t reads[NODUS_RT_MAX_READS];
    memset(reads, 0, sizeof(reads));
    for (uint16_t r = 0; r < nr; r++)
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &reqs[r], &reads[r])
                  == NODUS_ADAPTER_OK, "mediated read");
    CHECK(reads[0].present == 0 && reads[1].present == 1 &&
          reads[1].value_len == 8,
          "validator ABSENT, counter PRESENT"); OK();
    static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
    size_t rl = 0;
    CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, reads, nr, res,
                               sizeof(res), &rl) == 0,
          "honest hook-level STAKE exec accepts"); OK();

    /* P1: a PRESENT validator read rejects at the HOOK — never left for
     * the CREATE/ABSENT adapter precondition (Rule I, defence in depth) */
    {
        nodus_rt_read_res_t r2[NODUS_RT_MAX_READS];
        memcpy(r2, reads, sizeof(r2));
        r2[0].present = 1;
        r2[0].value_len = 5397;
        CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, r2, nr, res,
                                   sizeof(res), &rl) == -1,
              "P1 present validator row must reject at the hook"); OK();
    }
    /* P2: an ABSENT counter row rejects (a chain that cannot count its
     * validators must not pretend the counter was 0) */
    {
        nodus_rt_read_res_t r2[NODUS_RT_MAX_READS];
        memcpy(r2, reads, sizeof(r2));
        r2[1].present = 0;
        r2[1].value_len = 0;
        CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, r2, nr, res,
                                   sizeof(res), &rl) == -1,
              "P2 missing active_count row must reject"); OK();
    }
    /* P3: KIND-2 CARRIAGE on the record leg. SYSTEM's allowlist permits
     * auth_kind 2, but STAKE decides its own authority and refuses a
     * committee-approval carrier — the runtime.h SCOPING NOTE, enforced. */
    {
        dna_env_view_t v2 = v;
        v2.leg[0].auth_kind = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        CHECK(nodus_rt_system_exec(sys, &v2, 0, &ctx, reads, nr, res,
                                   sizeof(res), &rl) == -1,
              "P3 kind-2 carriage on a STAKE leg must reject at exec");
        OK();
    }
    /* P4: leg_count 1 — a record leg with no funding partner. Both SYSTEM
     * hooks refuse it, before any read or write. */
    {
        dna_env_view_t v2 = v;
        v2.leg_count = 1;
        uint16_t nr2 = 0;
        CHECK(nodus_rt_system_read_plan(sys, &v2, 0, &ctx, reqs,
                                        NODUS_RT_MAX_READS, &nr2) == -1,
              "P4 single-leg STAKE must fail to plan"); OK();
        CHECK(nodus_rt_system_exec(sys, &v2, 0, &ctx, reads, nr, res,
                                   sizeof(res), &rl) == -1,
              "P4 single-leg STAKE must fail to exec"); OK();
    }
    /* P5: the CORE funding hook refuses a sibling that is not a
     * stake-lifecycle op. THIS is the pin for the sibling gate — the
     * block-level C13 cannot be it, because leg0 executes FIRST and a
     * CHAIN_CONFIG leg dies on its own rules (fee != 0, quorum) before
     * leg1 is ever reached; and a C13 whose leg0 survives is
     * structurally inexpressible (CC requires fee 0, SYSFUND requires
     * fee >= the floor). Two foreign SYSTEM ops are exercised: 6
     * (CHAIN_CONFIG — the live one, so the gate must discriminate the
     * validator-record family from EXECUTABLE ops, not merely from dead
     * ones) and 7 (an id no compiled SYSTEM ruleset owns at all).
     * O12 S1 NOTE: op 5 (VALIDATOR_UPDATE) used to sit in this list as
     * the "owned but un-migrated" case. It has JOINED the family this
     * season — its funding sibling is legal (fee-only, lock = 0) — so it
     * is no longer a foreign sibling and was replaced by op 7. */
    {
        static const uint32_t foreign[2] = { DNA_SYSRULE_CHAIN_CONFIG,
                                             7u };
        for (int i = 0; i < 2; i++) {
            dna_env_view_t v2 = v;
            nodus_rt_read_res_t r2[NODUS_RT_MAX_READS];
            uint16_t nr2 = 0;
            v2.leg[0].runtime_op = foreign[i];
            CHECK(nodus_rt_core_read_plan(core, &v2, 1, &ctx, reqs,
                                          NODUS_RT_MAX_READS, &nr2) == -1,
                  "P5 SYSFUND must not plan under a foreign sibling");
            memset(r2, 0, sizeof(r2));
            CHECK(nodus_rt_core_exec(core, &v2, 1, &ctx, r2, 2, res,
                                     sizeof(res), &rl) == -1,
                  "P5 SYSFUND must not exec under a foreign sibling");
        }
        OK();
    }
    /* P6: the CORE funding hook's own honest plan (1 input + supply) */
    {
        uint16_t nr2 = 0;
        CHECK(nodus_rt_core_read_plan(core, &v, 1, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr2) == 0 &&
              nr2 == 2, "P6 SYSFUND plans input + supply reads"); OK();
    }

    /* P7: a NEGATIVE validator_stats counter is a STORAGE FAULT, never a
     * value and never absence — a corrupt row must not become a count */
    {
        CHECK(run_sql(fx.w->db,
              "UPDATE validator_stats SET value = -5 WHERE "
              "key = 'active_count'") == 0, "corrupt counter");
        nodus_rt_read_req_t rq;
        nodus_rt_read_res_t rr;
        memset(&rq, 0, sizeof(rq));
        rq.op_id = 7;                    /* RTN_SYS_OP_STATS             */
        rq.key_len = 1;
        rq.key[0] = 1;
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &rq, &rr)
                  == NODUS_ADAPTER_ERR_STORAGE_FAULT,
              "P7 negative active_count must be a storage fault"); OK();
        CHECK(run_sql(fx.w->db,
              "UPDATE validator_stats SET value = 0 WHERE "
              "key = 'active_count'") == 0, "restore");
    }
    /* P8: a NEGATIVE validator integer column is a STORAGE FAULT too —
     * the merkle leaf loader refuses such a row, so the mediated read
     * must refuse it as well rather than surfacing a huge u64 */
    {
        uint8_t pkh0[64];
        nodus_rt_read_req_t rq;
        nodus_rt_read_res_t rr;
        CHECK(val_key(0, pkh0) == 0, "key");
        memset(&rq, 0, sizeof(rq));
        rq.op_id = 4;                    /* RTN_SYS_OP_VAL               */
        rq.key_len = 64;
        memcpy(rq.key, pkh0, 64);
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &rq, &rr)
                  == NODUS_ADAPTER_OK && rr.present == 1 &&
              rr.value_len == 5397,
              "P8 an honest validator row reads as the 5397-byte record");
        OK();
        CHECK(run_sql(fx.w->db,
              "UPDATE validators SET self_stake = -1 WHERE "
              "active_since_block = 1") == 0, "corrupt row");
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &rq, &rr)
                  == NODUS_ADAPTER_ERR_STORAGE_FAULT,
              "P8 negative self_stake must be a storage fault"); OK();
    }
    /* P9: the read-only ops have NO probe surface, and an unknown op
     * resolves nowhere (fail-closed op table) */
    {
        nodus_rt_read_req_t rq;
        nodus_rt_read_res_t rr;
        memset(&rq, 0, sizeof(rq));
        rq.op_id = 6;                    /* RTN_SYS_OP_DELEGCNT          */
        rq.key_len = 64;
        memset(rq.key, 0x11, 64);
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &rq, &rr)
                  == NODUS_ADAPTER_OK && rr.present == 1 &&
              rr.value_len == 8,
              "P9 the delegation counter answers 0 as a VALUE"); OK();
        for (int i = 0; i < 8; i++)
            CHECK(rr.value[i] == 0, "P9 count == 0");
        OK();
        rq.op_id = 8;                    /* not in the compiled table    */
        CHECK(nodus_witness_v2_read_one(fx.w, sys, &rq, &rr)
                  == NODUS_ADAPTER_ERR_UNKNOWN_OP,
              "P9 an unknown SYSTEM op must not resolve"); OK();
    }
    fx_close(&fx);
    return 0;
}

/* ══ 13. SYSTEM slice — DELEGATE / UNSTAKE / UNDELEGATE (O11 S2+S3) ═
 *
 * The rest of the stake lifecycle. These three ops share S1's envelope
 * shape, authority rule and funding leg, so this section concentrates on
 * what is NEW: which rows they read, which columns they move, and which
 * columns they must NOT move. Every positive compares the FULL canonical
 * validator record before and after with only the expected fields
 * patched — a transition that quietly touches a third column fails.
 *
 * The fixture's seven genesis validators (keys 0..6, self_stake
 * VAL_BOND, ACTIVE) are the delegation targets; no STAKE is needed
 * first, which keeps these tests independent of §11. */

/* Record offsets, RESTATED here rather than imported: the production
 * macros live in nodus_witness_rt_native.c and are not exported, and an
 * independent restatement is what catches a silent layout move. */
#define TVAL_REC_LEN     5397u
#define TVAL_SELF_OFF    2592u
#define TVAL_TOT_OFF     2600u
#define TVAL_EXT_OFF     2608u
/* the commission window (O12 S1 — restated independently, same rule as
 * the offsets above: the production macros are not exported and an
 * independent restatement is what catches a silent layout move) */
#define TVAL_COMM_OFF    2616u
#define TVAL_PCOMM_OFF   2618u
#define TVAL_PEFF_OFF    2620u
#define TVAL_STATUS_OFF  2628u
#define TVAL_SINCE_OFF   2629u
#define TVAL_UCOMMIT_OFF 2637u
#define TVAL_DFP_OFF     2645u
#define TVAL_DPK_OFF     2773u
#define TVAL_LASTUPD_OFF 5365u
#define TDEL_REC_LEN     5200u
#define TDEL_AMT_OFF     5184u
#define TDEL_AT_OFF      5192u

#define DLG_AMOUNT   400000ULL
#define DLG_CHANGE   50000ULL
/* funds a DELEGATE: the locked amount + the fee + one change output */
#define DLG_FUND     (DLG_AMOUNT + FEE_MIN + DLG_CHANGE)
/* funds an op that locks NOTHING (UNSTAKE / UNDELEGATE): the fee plus a
 * change output. NOT "fee only" — the fee-only shape is a single input
 * of exactly FEE_MIN with out_count 0, exercised separately (UP2). */
#define NOLOCK_FUND  (FEE_MIN + DLG_CHANGE)

static uint64_t tbe64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* DELEGATE / UNDELEGATE call v1 (exact 5192 B). */
static uint32_t deleg_call_build(uint8_t *dst, size_t cap, int delegator,
                                 int validator, uint64_t amount) {
    if (cap < 5192) return 0;
    memcpy(dst, g_pk[delegator], 2592);
    memcpy(dst + 2592, g_pk[validator], 2592);
    for (int i = 0; i < 8; i++)
        dst[5184 + i] = (uint8_t)(amount >> (56 - 8 * i));
    return 5192;
}

/* UNSTAKE call v1 (exact 2592 B). */
static uint32_t unstake_call_build(uint8_t *dst, size_t cap,
                                   int validator) {
    if (cap < 2592) return 0;
    memcpy(dst, g_pk[validator], 2592);
    return 2592;
}

/* VALIDATOR_UPDATE call v1 (exact 2594 B — O12 S1): identity_pubkey
 * ‖ new_commission_bps u16 BE. The legacy wire's trailing
 * signed_at_block[8] is DELIBERATELY ABSENT (bft.c:1913 carried it;
 * bft.c:1932/1951 never read it — the V2 envelope owns freshness), which
 * is exactly why 2602 must NOT decode: the ±1 length matrix in §17 pins
 * that this decoder accepts one length and one length only. */
#define TVUPD_CALL_LEN   2594u
static uint32_t vupd_call_build(uint8_t *dst, size_t cap, int validator,
                                uint32_t bps) {
    if (cap < 2594) return 0;
    memcpy(dst, g_pk[validator], 2592);
    dst[2592] = (uint8_t)(bps >> 8);
    dst[2593] = (uint8_t)bps;
    return 2594;
}

/* the delegations composite key: BOTH halves use the DELEGATION tag
 * (nodus_witness_delegation.c delegation_row_hash) */
static int deleg_key_of(int delegator, int validator, uint8_t out[128]) {
    uint8_t pre[1 + 2592];
    pre[0] = NODUS_TREE_TAG_DELEGATION;
    memcpy(pre + 1, g_pk[delegator], 2592);
    if (qgp_sha3_512(pre, sizeof(pre), out) != 0) return -1;
    memcpy(pre + 1, g_pk[validator], 2592);
    return qgp_sha3_512(pre, sizeof(pre), out + 64) == 0 ? 0 : -1;
}

/* One row, straight through the compiled adapter's mediated read — the
 * SAME bytes exec observes, so a full-record comparison is a comparison
 * of what consensus actually saw. @return 1 present / 0 absent / -1. */
static int sysrow_read(nodus_witness_t *w, uint32_t op_id,
                       const uint8_t *key, uint16_t key_len,
                       uint8_t *out, uint32_t expect_len) {
    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    nodus_rt_read_req_t rq;
    nodus_rt_read_res_t rr;
    if (!bt || n != 2) return -1;
    memset(&rq, 0, sizeof(rq));
    rq.op_id = op_id;
    rq.key_len = key_len;
    memcpy(rq.key, key, key_len);
    if (nodus_witness_v2_read_one(w, &bt[0], &rq, &rr) != NODUS_ADAPTER_OK)
        return -1;
    if (!rr.present) return 0;
    if (rr.value_len != expect_len) return -1;
    if (out) memcpy(out, rr.value, expect_len);
    return 1;
}

/* a fee-funding SYSFUND leg: one input, one change output */
static uint32_t fund_call(uint8_t *dst, size_t cap, const uint8_t in[64],
                          int owner, uint64_t change, uint8_t seed) {
    uint8_t ins[1][64];
    out_spec_t o[1];
    memcpy(ins[0], in, 64);
    o[0].owner = owner;
    o[0].amount = change;
    o[0].seed_byte = seed;
    o[0].token = NULL;
    return spend_call_build(dst, cap, ins, 1, o, 1);
}

static int test_system_delegate(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "dlg") == 0, "genesis");
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    int s9[1] = { 9 }, s10[1] = { 10 }, s11[1] = { 11 };
    static uint8_t scall[8192], fcall[8192];
    uint8_t f9[64], f10[64], f11[64];
    CHECK(seed_funding(&fx, 9, DLG_FUND, 0xD1, f9) == 0, "fund 9");
    CHECK(seed_funding(&fx, 10, DLG_FUND, 0xD2, f10) == 0, "fund 10");
    CHECK(seed_funding(&fx, 11, DLG_FUND, 0xD3, f11) == 0, "fund 11");

    uint8_t vk0[64], vk2[64], vk3[64], vk4[64];
    CHECK(val_key(0, vk0) == 0 && val_key(2, vk2) == 0 &&
          val_key(3, vk3) == 0 && val_key(4, vk4) == 0, "val keys");
    uint8_t dk90[128], dk10_0[128];
    CHECK(deleg_key_of(9, 0, dk90) == 0 &&
          deleg_key_of(10, 0, dk10_0) == 0, "deleg keys");

    /* validator 2 becomes ELIGIBLE, validator 3 RETIRING — the two
     * status classes the BONDED gate must separate (bft.c:1429-1434) */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET status = 4 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk2, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "eligible");
        sqlite3_finalize(st);
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET status = 1 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk3, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "retiring");
        sqlite3_finalize(st);
    }

    /* ── negatives (digest-proven no-ops at height 1) ───────────────── */
    /* D1 self-delegation (Rule S) — key 0 delegating to itself. It is
     * also funded, so only Rule S rejects. */
    {
        uint8_t f0[64];
        CHECK(seed_funding(&fx, 0, DLG_FUND, 0xD4, f0) == 0, "fund 0");
        int s0[1] = { 0 };
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 0, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f0, 0, DLG_CHANGE,
                                0x11);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s0, 1, s0, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D1 self-delegation must reject (Rule S)"); OK();
    }
    /* D2 unknown validator (the stray key has no row) */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, K_STRAY,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x12);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D2 unknown validator must reject"); OK();
    }
    /* D3 RETIRING target: an exit state is not a delegation target */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 3,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x13);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D3 RETIRING target must reject"); OK();
    }
    /* D4 amount 0 and D5 amount > total supply */
    {
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9,
                                DLG_AMOUNT + DLG_CHANGE, 0x14);
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0, 0);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D4 zero delegation amount must reject"); OK();
    }
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DNAC_DEFAULT_TOTAL_SUPPLY + 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x15);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        /* HONEST LABEL: unlike D4 this envelope is NOT balanced for the
         * declared amount (no funding leg could be — the amount exceeds
         * total supply), so conservation is violated too. The supply
         * bound is nevertheless the rejecting site: leg0 executes to
         * completion before leg1 is touched, and the bound fires inside
         * leg0's exec, so the funding leg is never consulted. */
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D5 amount above total supply must reject"); OK();
    }
    /* D6 CONSERVATION: the funding leg does not lock the call's amount.
     * The SYSTEM leg is perfectly valid; the CORE leg's change is one
     * too large, so Σin != change + fee + amount. This is the pin that
     * "fund a different amount than you declare" is INEXPRESSIBLE. */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9,
                                DLG_CHANGE + 1, 0x16);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D6 funding that does not lock the declared amount must "
              "reject"); OK();
    }
    /* D7 wrong-owner funding input (key 11's UTXO, key 9 delegating) */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f11, 9, DLG_CHANGE,
                                0x17);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D7 unowned funding input must reject"); OK();
    }
    /* D8 identity mismatch: the call names delegator 9, key 11 signs */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x18);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D8 signer fp != SHA3(call.delegator) must reject"); OK();
    }

    /* ── POSITIVE 1: a new delegation ───────────────────────────────── */
    uint8_t v0_before[TVAL_REC_LEN], v0_after[TVAL_REC_LEN];
    CHECK(sysrow_read(fx.w, 4, vk0, 64, v0_before, TVAL_REC_LEN) == 1,
          "validator 0 row"); OK();
    uint64_t burned0 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint8_t sys_h0[89], core_h0[89];
    CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sys_h0) == 0 &&
          head_blob(fx.w, DNA_DOMAIN_CORE, core_h0) == 0, "heads");
    env_t e_p1;
    uint8_t p1_wire[64], p1_intent[64], chg9[64];
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x21);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e_p1, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &e_p1, p1_wire, p1_intent) == 0, "ids");
        CHECK(out_nul(9, 0x21, chg9) == 0, "change id");
        nodus_v2_envelope_t ve = { e_p1.bytes, e_p1.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P1 a new delegation must commit"); OK();
    }
    /* the validator record: EXACTLY the two totals moved */
    CHECK(sysrow_read(fx.w, 4, vk0, 64, v0_after, TVAL_REC_LEN) == 1,
          "row"); OK();
    {
        uint8_t expect[TVAL_REC_LEN];
        memcpy(expect, v0_before, TVAL_REC_LEN);
        for (int i = 0; i < 8; i++) {
            expect[TVAL_TOT_OFF + i] =
                (uint8_t)(DLG_AMOUNT >> (56 - 8 * i));
            expect[TVAL_EXT_OFF + i] =
                (uint8_t)(DLG_AMOUNT >> (56 - 8 * i));
        }
        CHECK(memcmp(expect, v0_after, TVAL_REC_LEN) == 0,
              "P1 ONLY total_delegated and external_delegated moved");
        OK();
        CHECK(tbe64(v0_after + TVAL_SELF_OFF) == VAL_BOND,
              "P1 self_stake is NOT a delegation bucket"); OK();
    }
    /* the delegation row, exact */
    {
        uint8_t d[TDEL_REC_LEN];
        CHECK(sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1,
              "delegation row"); OK();
        CHECK(memcmp(d, g_pk[9], 2592) == 0 &&
              memcmp(d + 2592, g_pk[0], 2592) == 0 &&
              tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT &&
              tbe64(d + TDEL_AT_OFF) == 1,
              "P1 delegation row columns"); OK();
    }
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
              == burned0 + FEE_MIN, "P1 burned += fee only"); OK();
    CHECK(utxo_rows(fx.w, f9) == 0 && utxo_rows(fx.w, chg9) == 1,
          "P1 input spent, change created"); OK();
    CHECK(supply_identity_holds(fx.w),
          "P1 supply identity (delegated bucket included)"); OK();
    {
        uint8_t sh[89], ch[89];
        CHECK(head_blob(fx.w, DNA_DOMAIN_SYSTEM, sh) == 0 &&
              head_blob(fx.w, DNA_DOMAIN_CORE, ch) == 0, "heads");
        CHECK(memcmp(sh, sys_h0, 89) != 0 && memcmp(ch, core_h0, 89) != 0,
              "P1 both heads moved"); OK();
        CHECK(dom_height(fx.w, DNA_DOMAIN_SYSTEM) == 1 &&
              dom_height(fx.w, DNA_DOMAIN_CORE) == 1,
              "P1 each domain advanced once"); OK();
    }

    /* ── POSITIVE 2: TOP-UP at a later height — amount SUMS and
     *    delegated_at_block is REFRESHED (bft.c:1468) ───────────────── */
    {
        uint8_t f9b[64];
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0xD5, f9b) == 0, "fund");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x22);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P2 top-up must commit"); OK();
        uint8_t d[TDEL_REC_LEN];
        CHECK(sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1,
              "row"); OK();
        CHECK(tbe64(d + TDEL_AMT_OFF) == 2 * DLG_AMOUNT,
              "P2 the top-up SUMS into the existing position"); OK();
        CHECK(tbe64(d + TDEL_AT_OFF) == 2,
              "P2 delegated_at_block is REFRESHED to the new height");
        OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 1,
              "P2 a top-up creates NO second row"); OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(tbe64(v + TVAL_TOT_OFF) == 2 * DLG_AMOUNT &&
              tbe64(v + TVAL_EXT_OFF) == 2 * DLG_AMOUNT,
              "P2 validator totals summed"); OK();
        CHECK(supply_identity_holds(fx.w), "P2 supply identity"); OK();
    }

    /* ── POSITIVE 3: a SECOND delegator onto the same validator ─────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 10, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f10, 10, DLG_CHANGE,
                                0x23);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s10, 1, s10, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P3 a second delegator must commit"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 2,
              "P3 two distinct delegation rows"); OK();
        uint8_t d[TDEL_REC_LEN];
        CHECK(sysrow_read(fx.w, 5, dk10_0, 128, d, TDEL_REC_LEN) == 1,
              "row"); OK();
        CHECK(tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT,
              "P3 the second position is independent"); OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(tbe64(v + TVAL_TOT_OFF) == 3 * DLG_AMOUNT,
              "P3 validator totals aggregate both delegators"); OK();
        CHECK(supply_identity_holds(fx.w), "P3 supply identity"); OK();
    }

    /* ── POSITIVE 4: an ELIGIBLE validator IS a legal target ────────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 11, 2,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f11, 11, DLG_CHANGE,
                                0x24);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s11, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P4 an ELIGIBLE validator must accept delegation"); OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk2, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(v[TVAL_STATUS_OFF] == 4,
              "P4 the target's status is UNCHANGED by a delegation");
        OK();
        CHECK(supply_identity_holds(fx.w), "P4 supply identity"); OK();
    }

    /* ── D10b LOCKED FUNDING INPUT (O11 R3 finding): the SYSFUND lock
     *    gate (rtn_sysfund_exec `unlock >= H` — a SEPARATE function
     *    from rtn_xfer_exec's tested gate) had NO coverage because
     *    every fixture funds unlock=0. The post-UNSTAKE graduation
     *    principal is emitted LOCKED, so a locked UTXO funding a
     *    staking envelope is exactly the shape that must die here. The
     *    envelope is otherwise perfectly balanced — the lock gate is
     *    the only violated rule. ─────────────────────────────────────── */
    {
        uint8_t flk[64];
        /* seed_funding keeps the supply identity (row + counters), THEN
         * the row is locked in place — so the ONLY violated rule is the
         * lock gate, never the pre-apply supply gate */
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0x27, flk) == 0,
              "locked fund");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "UPDATE utxo_set SET unlock_block = 1000 "
                  "WHERE nullifier = ?1", -1, &st, NULL) == SQLITE_OK,
                  "prep");
            sqlite3_bind_blob(st, 1, flk, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "lock");
            sqlite3_finalize(st);
        }
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), flk, 9, DLG_CHANGE,
                                0x28);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D10b a LOCKED funding input must reject at the SYSFUND "
              "lock gate"); OK();
        /* restore the fixture exactly: remove the locked row AND its
         * seed_funding supply bump (seed-and-restore discipline) */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "DELETE FROM utxo_set WHERE nullifier = ?1",
                  -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, flk, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "cleanup row");
            sqlite3_finalize(st);
        }
        {
            char sql[224];
            snprintf(sql, sizeof(sql),
                     "UPDATE supply_tracking SET genesis_supply = "
                     "genesis_supply - %llu, current_supply = "
                     "current_supply - %llu WHERE id = 1",
                     (unsigned long long)DLG_FUND,
                     (unsigned long long)DLG_FUND);
            CHECK(run_sql(fx.w->db, sql) == 0, "cleanup supply");
        }
        CHECK(supply_identity_holds(fx.w), "D10b restore identity"); OK();
    }

    /* ── N4b OVER-WITHDRAWAL UNDER AGGREGATION (O11 mutation-campaign
     *    addition, ORCHESTRATOR): delegator 9's position is 2×DLG_AMOUNT
     *    (P1+P2) but validator 0's totals are 3× (P3 added delegator
     *    10). A request for 2×+1 clears the validator-totals underflow
     *    check, so the PER-POSITION bound `amount <= have` is the ONLY
     *    verdict-class defence — mutant M5 (bound dropped) survived the
     *    single-delegator N4 exactly because the totals check masked it
     *    there, and under M5 this shape degrades to a mutate-side node
     *    fault (the wrapped row amount trips the INT64 storage bound as
     *    -2). rc == -1 is therefore the load-bearing half of this
     *    assertion, not a formality. ─────────────────────────────────── */
    {
        uint8_t f9x[64];
        CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xD7, f9x) == 0, "fund");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       2 * DLG_AMOUNT + 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9x, 9, DLG_CHANGE,
                                0x26);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N4b over-withdrawal must be a VERDICT even when the "
              "validator totals cover it"); OK();
    }

    /* ── D9 TOP-UP OVERFLOW: a validator whose totals already sit at
     *    the storage bound cannot absorb more. Seeded and RESTORED
     *    around the check so the fixture's supply identity survives. ── */
    {
        uint8_t f9c[64];
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0xD6, f9c) == 0, "fund");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET total_delegated = ?2, "
              "external_delegated = ?2 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk4, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, INT64_MAX);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "seed");
        sqlite3_finalize(st);
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 4,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9c, 9, DLG_CHANGE,
                                0x25);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D9 totals at the storage bound must reject the top-up");
        OK();
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET total_delegated = 0, "
              "external_delegated = 0 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk4, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore");
        sqlite3_finalize(st);
    }

    /* ── D10 AUTH TWIN + D11 semantic replay ────────────────────────── */
    {
        int core2[2] = { 9, 11 };
        env_t e_t;
        uint8_t t_wire[64], t_intent[64];
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x21);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e_t, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, core2, 2, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &e_t, t_wire, t_intent) == 0, "ids");
        CHECK(memcmp(t_intent, p1_intent, 64) == 0,
              "D10 an extra funding witness must NOT move intent_id");
        OK();
        CHECK(memcmp(t_wire, p1_wire, 64) != 0,
              "D10 it MUST move wire_id"); OK();
        nodus_v2_envelope_t ve = { e_t.bytes, e_t.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D10 the auth twin of a committed intent must reject");
        OK();
        nodus_v2_envelope_t vr2 = { e_p1.bytes, e_p1.len };
        mk_block(&b, 5, &vr2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "D11 byte-identical replay must reject"); OK();
    }

    /* ── D12 KIND-2 CARRIAGE on a DELEGATE leg (hook level: the block
     *    layer would reject at the auth boundary and pin nothing) ───── */
    {
        size_t n = 0;
        const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x26);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        dna_env_view_t v;
        CHECK(dna_env_decode(e.bytes, e.len, &v) == 0, "decode");
        nodus_rt_auth_verdict_t av;
        memset(&av, 0, sizeof(av));
        av.n_signers = 1;
        CHECK(qgp_sha3_512(g_pk[9], 2592, av.signer_fp[0]) == 0, "fp");
        static uint8_t iid[64];
        memset(iid, 0x55, 64);
        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.chain_id = fx.chain_id;
        ctx.global_height = 5;
        ctx.intent_id = iid;
        ctx.wire_id = iid;
        ctx.auth = &av;
        nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
        nodus_rt_read_res_t reads[NODUS_RT_MAX_READS];
        uint16_t nr = 0;
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        size_t rl = 0;
        CHECK(nodus_rt_system_read_plan(&bt[0], &v, 0, &ctx, reqs,
                                        NODUS_RT_MAX_READS, &nr) == 0 &&
              nr == 2, "D12 DELEGATE plans validator + delegation reads");
        OK();
        CHECK(reqs[0].op_id == 4 && reqs[0].key_len == 64 &&
              reqs[1].op_id == 5 && reqs[1].key_len == 128 &&
              memcmp(reqs[0].key, vk0, 64) == 0 &&
              memcmp(reqs[1].key, dk90, 128) == 0,
              "D12 the planned keys are the tag-derived row keys"); OK();
        memset(reads, 0, sizeof(reads));
        for (uint16_t r = 0; r < nr; r++)
            CHECK(nodus_witness_v2_read_one(fx.w, &bt[0], &reqs[r],
                                            &reads[r])
                      == NODUS_ADAPTER_OK, "read");
        CHECK(nodus_rt_system_exec(&bt[0], &v, 0, &ctx, reads, nr, res,
                                   sizeof(res), &rl) == 0,
              "D12 honest hook-level DELEGATE accepts"); OK();
        dna_env_view_t v2 = v;
        v2.leg[0].auth_kind = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        CHECK(nodus_rt_system_exec(&bt[0], &v2, 0, &ctx, reads, nr, res,
                                   sizeof(res), &rl) == -1,
              "D12 kind-2 carriage on a DELEGATE leg must reject"); OK();
        /* and a two-signer verdict, the other half of the authority rule */
        av.n_signers = 2;
        CHECK(nodus_rt_system_exec(&bt[0], &v, 0, &ctx, reads, nr, res,
                                   sizeof(res), &rl) == -1,
              "D12 n_signers != 1 must reject"); OK();
    }
    fx_close(&fx);
    return 0;
}

static int test_system_unstake(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "unstk") == 0, "genesis");
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    int s1[1] = { 1 }, s5[1] = { 5 }, s6[1] = { 6 };
    int s9[1] = { 9 }, s11[1] = { 11 };
    static uint8_t scall[8192], fcall[8192];
    uint8_t f9[64], f9b[64], f9d[64], f10[64];
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xC1, f9) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xC2, f9b) == 0, "fund");
    CHECK(seed_funding(&fx, 9, FEE_MIN, 0xC4, f9d) == 0, "fund exact");
    CHECK(seed_funding(&fx, 10, DLG_FUND, 0xC5, f10) == 0, "fund 10");

    uint8_t vk1[64], vk6[64];
    CHECK(val_key(1, vk1) == 0 && val_key(6, vk6) == 0, "keys");

    /* ── U1 unknown validator ───────────────────────────────────────── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), K_STRAY);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x31);
        int sk[1] = { K_STRAY };
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            sk, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "U1 unknown validator must reject"); OK();
    }
    /* ── U2 wrong signer: the call names validator 1, key 11 signs ──── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x32);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "U2 a non-owner cannot retire a validator"); OK();
    }
    /* ── U3 sub-floor fee (balanced for that fee) ───────────────────── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9,
                                DLG_CHANGE + 1, 0x33);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN - 1,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "U3 sub-floor fee must reject"); OK();
    }
    /* ── U4 RULE A: a delegation still references validator 5 ───────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 10, 5,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f10, 10, DLG_CHANGE,
                                0x34);
        int s10[1] = { 10 };
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s10, 1, s10, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "U4 setup delegation commits"); OK();

        uint32_t sl2 = unstake_call_build(scall, sizeof(scall), 5);
        uint32_t fl2 = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                 0x35);
        CHECK(sl2 && fl2, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl2,
                            DNA_CORERULE_SYSFUND, fcall, fl2, FEE_MIN,
                            s5, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve2 = { e.bytes, e.len };
        mk_block(&b, 2, &ve2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "U4 Rule A: a delegated validator cannot unstake"); OK();
    }

    /* ── POSITIVE: validator 1 retires, funded by key 9's leg ────────
     *    The two legs are signed by DIFFERENT keys — the record leg by
     *    the validator, the funding leg by whoever owns the inputs. */
    uint8_t v1_before[TVAL_REC_LEN], v1_after[TVAL_REC_LEN];
    CHECK(sysrow_read(fx.w, 4, vk1, 64, v1_before, TVAL_REC_LEN) == 1,
          "row"); OK();
    uint64_t burned1 = q1(fx.w, "SELECT total_burned FROM supply_tracking");
    uint64_t ac_before = active_count(fx.w);
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x36);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "UP1 UNSTAKE must commit"); OK();
    }
    CHECK(sysrow_read(fx.w, 4, vk1, 64, v1_after, TVAL_REC_LEN) == 1,
          "row"); OK();
    {
        uint8_t expect[TVAL_REC_LEN];
        memcpy(expect, v1_before, TVAL_REC_LEN);
        expect[TVAL_STATUS_OFF] = 1;                 /* RETIRING        */
        for (int i = 0; i < 8; i++)
            expect[TVAL_UCOMMIT_OFF + i] = (uint8_t)(2ULL >> (56 - 8 * i));
        CHECK(memcmp(expect, v1_after, TVAL_REC_LEN) == 0,
              "UP1 ONLY status and unstake_commit_block moved"); OK();
        CHECK(tbe64(v1_after + TVAL_SELF_OFF) == VAL_BOND,
              "UP1 the principal is NOT released here (graduation is a "
              "deferred season)"); OK();
        CHECK(tbe64(v1_after + TVAL_SINCE_OFF) ==
              tbe64(v1_before + TVAL_SINCE_OFF),
              "UP1 active_since_block untouched"); OK();
    }
    CHECK(active_count(fx.w) == ac_before,
          "UP1 active_count does NOT drop at the request"); OK();
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking")
              == burned1 + FEE_MIN, "UP1 burned += fee"); OK();
    CHECK(supply_identity_holds(fx.w), "UP1 supply identity"); OK();

    /* ── U5 REPEATED unstake: the row is RETIRING, no longer BONDED ── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x37);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "U5 a RETIRING validator cannot unstake again"); OK();
    }
    /* ── POSITIVE 2: a ZERO-CHANGE funding leg (out_count 0, the input
     *    is exactly the fee) — the BURN precedent, on the staking lane.
     *    Validator 6 is used because it carries no delegation, so Rule A
     *    is satisfied without any state surgery (U4 above owns the
     *    Rule A pin; this case is only about the zero-change leg). */
    {
        uint8_t ins[1][64];
        memcpy(ins[0], f9d, 64);
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 6);
        uint32_t fl = spend_call_build(fcall, sizeof(fcall), ins, 1,
                                       NULL, 0);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s6, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "UP2 a zero-change fee-only funding leg must commit"); OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk6, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(v[TVAL_STATUS_OFF] == 1 &&
              tbe64(v + TVAL_UCOMMIT_OFF) == 3, "UP2 row"); OK();
        CHECK(utxo_rows(fx.w, f9d) == 0,
              "UP2 the whole input went to the fee"); OK();
        CHECK(supply_identity_holds(fx.w), "UP2 supply identity"); OK();
    }
    fx_close(&fx);
    return 0;
}

static int test_system_undelegate(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "undlg") == 0, "genesis");
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    int s9[1] = { 9 }, s11[1] = { 11 };
    static uint8_t scall[8192], fcall[8192];
    uint8_t f9[64], f9b[64], f9c[64], f9d[64], f9e[64], f9f[64];
    CHECK(seed_funding(&fx, 9, DLG_FUND, 0xB1, f9) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xB2, f9b) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xB3, f9c) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xB4, f9d) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xB5, f9e) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xB6, f9f) == 0, "fund");

    uint8_t vk0[64], dk90[128];
    CHECK(val_key(0, vk0) == 0 && deleg_key_of(9, 0, dk90) == 0, "keys");

    /* setup: a 2×DLG_AMOUNT position so a PARTIAL and a FULL withdrawal
     * both fit */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x41);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "setup"); OK();
    }

    /* ── negatives at height 2 ──────────────────────────────────────── */
    /* N1 unknown delegation (key 11 never delegated) */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 11, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x42);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N1 unknown delegation must reject"); OK();
    }
    /* N2 wrong owner: the call names delegator 9, key 11 signs */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x43);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s11, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N2 only the delegator may withdraw"); OK();
    }
    /* N3 amount 0 and N4 amount above the position */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0, 0);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x44);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N3 zero withdrawal must reject"); OK();
    }
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT + 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x45);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N4 withdrawing more than the position must reject"); OK();
    }
    /* N5 TOTALS UNDERFLOW: validator totals below the delegation row —
     * malformed legacy state fails CLOSED, it is never repaired.
     * Seeded and restored around the check. */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET total_delegated = ?2, "
              "external_delegated = ?2 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk0, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)(DLG_AMOUNT - 1));
        CHECK(sqlite3_step(st) == SQLITE_DONE, "seed");
        sqlite3_finalize(st);
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x46);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N5 totals below the position must fail closed"); OK();
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE validators SET total_delegated = ?2, "
              "external_delegated = ?2 WHERE pubkey_hash = ?1",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, vk0, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)DLG_AMOUNT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore");
        sqlite3_finalize(st);
    }

    /* ── POSITIVE 1: PARTIAL withdrawal ─────────────────────────────── */
    uint8_t d_before[TDEL_REC_LEN];
    CHECK(sysrow_read(fx.w, 5, dk90, 128, d_before, TDEL_REC_LEN) == 1,
          "row"); OK();
    uint64_t at_before = tbe64(d_before + TDEL_AT_OFF);
    uint64_t half = DLG_AMOUNT / 2;
    uint8_t rel1[64], intent1[64];
    {
        env_t ep;
        uint8_t w1[64];
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0, half);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x47);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &ep, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &ep, w1, intent1) == 0, "ids");
        /* the release nullifier: SHA3-512(intent ‖ 0x01 ‖ u32be(100)) */
        {
            uint8_t pre[69];
            memcpy(pre, intent1, 64);
            pre[64] = 0x01;
            pre[65] = 0; pre[66] = 0; pre[67] = 0; pre[68] = 100;
            CHECK(qgp_sha3_512(pre, sizeof(pre), rel1) == 0, "rel id");
        }
        nodus_v2_envelope_t ve = { ep.bytes, ep.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "R1 a partial withdrawal must commit"); OK();
    }
    {
        uint8_t d[TDEL_REC_LEN];
        CHECK(sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1,
              "row"); OK();
        uint8_t expect[TDEL_REC_LEN];
        memcpy(expect, d_before, TDEL_REC_LEN);
        for (int i = 0; i < 8; i++)
            expect[TDEL_AMT_OFF + i] =
                (uint8_t)((DLG_AMOUNT - half) >> (56 - 8 * i));
        CHECK(memcmp(expect, d, TDEL_REC_LEN) == 0,
              "R1 ONLY the amount moved — delegated_at_block is NOT "
              "refreshed by a withdrawal"); OK();
        CHECK(tbe64(d + TDEL_AT_OFF) == at_before, "R1 clock untouched");
        OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(tbe64(v + TVAL_TOT_OFF) == DLG_AMOUNT - half &&
              tbe64(v + TVAL_EXT_OFF) == DLG_AMOUNT - half,
              "R1 both validator totals fell by the amount"); OK();
    }
    /* the RELEASE UTXO, exactly */
    {
        sqlite3_stmt *st = NULL;
        CHECK(utxo_rows(fx.w, rel1) == 1, "R1 release UTXO exists"); OK();
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT amount, owner, tx_hash, output_index, "
              "block_height, unlock_block, token_id FROM utxo_set "
              "WHERE nullifier = ?1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, rel1, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_ROW, "row");
        uint8_t zt[64];
        memset(zt, 0, sizeof(zt));
        CHECK((uint64_t)sqlite3_column_int64(st, 0) == half &&
              memcmp(sqlite3_column_text(st, 1), g_fp[9], 128) == 0 &&
              sqlite3_column_bytes(st, 2) == 64 &&
              memcmp(sqlite3_column_blob(st, 2), intent1, 64) == 0 &&
              sqlite3_column_int64(st, 3) == 100 &&
              sqlite3_column_int64(st, 4) == 2 &&
              sqlite3_column_int64(st, 5) == 0 &&
              memcmp(sqlite3_column_blob(st, 6), zt, 64) == 0,
              "R1 the release UTXO's every column");
        sqlite3_finalize(st);
        OK();
    }
    CHECK(supply_identity_holds(fx.w),
          "R1 supply identity across a release"); OK();

    /* ── POSITIVE 2: FULL drain — the row is DELETED, and the second
     *    release has a DIFFERENT nullifier because it is a different
     *    intent (the release id can never collide across withdrawals) ─ */
    uint8_t rel2[64], intent2[64];
    {
        env_t ep;
        uint8_t w2[64];
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT - half);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9c, 9, DLG_CHANGE,
                                0x48);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &ep, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &ep, w2, intent2) == 0, "ids");
        {
            uint8_t pre[69];
            memcpy(pre, intent2, 64);
            pre[64] = 0x01;
            pre[65] = 0; pre[66] = 0; pre[67] = 0; pre[68] = 100;
            CHECK(qgp_sha3_512(pre, sizeof(pre), rel2) == 0, "rel id");
        }
        CHECK(memcmp(intent1, intent2, 64) != 0 &&
              memcmp(rel1, rel2, 64) != 0,
              "R2 a second withdrawal is a different intent, hence a "
              "different release identity"); OK();
        nodus_v2_envelope_t ve = { ep.bytes, ep.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "R2 the full drain must commit"); OK();
    }
    CHECK(sysrow_read(fx.w, 5, dk90, 128, NULL, TDEL_REC_LEN) == 0,
          "R2 a drained delegation row is DELETED"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 0,
          "R2 no delegation rows remain"); OK();
    {
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(tbe64(v + TVAL_TOT_OFF) == 0 &&
              tbe64(v + TVAL_EXT_OFF) == 0,
              "R2 the validator's delegated totals are back to zero");
        OK();
        CHECK(tbe64(v + TVAL_SELF_OFF) == VAL_BOND,
              "R2 self_stake was never involved"); OK();
    }
    CHECK(utxo_rows(fx.w, rel2) == 1 && utxo_rows(fx.w, rel1) == 1,
          "R2 both release UTXOs coexist"); OK();
    CHECK(supply_identity_holds(fx.w), "R2 supply identity"); OK();

    /* ── N6 repeated FULL drain: the row is gone ────────────────────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT - half);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9d, 9, DLG_CHANGE,
                                0x49);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N6 withdrawing from a drained position must reject"); OK();
    }

    /* ── POSITIVE 3: ANY validator status — delegators of an UNSTAKED
     *    validator can still exit (bft.c:1818-1821) ─────────────────── */
    {
        uint8_t vk6[64], dk96[128];
        CHECK(val_key(6, vk6) == 0 && deleg_key_of(9, 6, dk96) == 0,
              "keys");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 6,
                                       DLG_AMOUNT);
        uint8_t f9g[64];
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0xB7, f9g) == 0, "fund");
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9g, 9, DLG_CHANGE,
                                0x4A);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "setup"); OK();
        /* The validator is retired out from under the delegator.
         * HONEST LABEL: this row is SYNTHETIC pre-graduation state — an
         * UNSTAKED status with a non-zero self_stake is what a chain
         * looks like between the retirement request and the epoch
         * boundary that actually releases the bond (a deferred season).
         * It is exactly the state the any-status rule exists for, and
         * the supply identity holds because both this test's helper and
         * the engine's own gate (v2_claims.c:847) sum self_stake over
         * ALL validators regardless of status. */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                  "UPDATE validators SET status = 2 WHERE "
                  "pubkey_hash = ?1", -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_blob(st, 1, vk6, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "unstaked");
            sqlite3_finalize(st);
        }
        uint32_t sl2 = deleg_call_build(scall, sizeof(scall), 9, 6,
                                        DLG_AMOUNT);
        uint32_t fl2 = fund_call(fcall, sizeof(fcall), f9e, 9, DLG_CHANGE,
                                 0x4B);
        CHECK(sl2 && fl2, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl2,
                            DNA_CORERULE_SYSFUND, fcall, fl2, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve2 = { e.bytes, e.len };
        mk_block(&b, 5, &ve2, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "R3 an UNSTAKED validator's delegator can still exit"); OK();
        CHECK(sysrow_read(fx.w, 5, dk96, 128, NULL, TDEL_REC_LEN) == 0,
              "R3 the position is gone"); OK();
        uint8_t v[TVAL_REC_LEN];
        CHECK(sysrow_read(fx.w, 4, vk6, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(v[TVAL_STATUS_OFF] == 2,
              "R3 the withdrawal does not change the validator's status");
        OK();
        CHECK(supply_identity_holds(fx.w), "R3 supply identity"); OK();
    }

    /* ── N7 CROSS-OP: a DELEGATE-shaped intent submitted under the
     *    UNDELEGATE op byte. The op is intent-committed, so this is a
     *    DIFFERENT intent, never a replay of the delegate — and it
     *    rejects on its own rules (no position that size exists). ───── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9f, 9, DLG_CHANGE,
                                0x4C);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 6, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N7 the same call bytes under another op must reject");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ══ 14. O11 S5 — fault injection + cross-domain ATOMICITY ═════════
 *
 * A staking envelope is the engine's first CROSS-DOMAIN transaction: two
 * legs, two domains, one intent. The obligation this section discharges
 * is that NO fault point can leave a HALF envelope — a validator or
 * delegation row without the funding that paid for it, or consumed
 * funding without the record it bought. F38 is the point that only
 * exists for this shape: it fires BETWEEN the two legs. */

/* the release UTXO identity the CORE funding leg derives for an
 * UNDELEGATE (SHA3-512(intent ‖ 0x01 ‖ u32be(100))) */
static int release_nul(const uint8_t intent[64], uint8_t out[64]) {
    uint8_t pre[69];
    memcpy(pre, intent, 64);
    pre[64] = 0x01;
    pre[65] = 0; pre[66] = 0; pre[67] = 0; pre[68] = 100;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* digest of ONE table (rowid order) — the firewall/atomicity proof unit
 * when a whole-DB digest would be too coarse to name what stayed put */
static int table_digest(nodus_witness_t *w, const char *name,
                        uint8_t out[64]) {
    char sql[192];
    snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid", name);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    dyn_t d = { 0 };
    int rc, ok = -1;
    if (dyn_put(&d, name, strlen(name) + 1) != 0) goto done;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int nc = sqlite3_column_count(st);
        for (int c = 0; c < nc; c++) {
            uint8_t t = (uint8_t)sqlite3_column_type(st, c);
            if (dyn_put(&d, &t, 1) != 0) goto done;
            if (t == SQLITE_NULL) continue;
            const void *bp = sqlite3_column_blob(st, c);
            uint32_t bl = (uint32_t)sqlite3_column_bytes(st, c);
            if (dyn_put(&d, &bl, 4) != 0 ||
                (bl > 0 && dyn_put(&d, bp, bl) != 0))
                goto done;
        }
    }
    if (rc != SQLITE_DONE) goto done;
    ok = qgp_sha3_512(d.buf ? d.buf : (const uint8_t *)"", d.len, out)
             == 0 ? 0 : -1;
done:
    sqlite3_finalize(st);
    free(d.buf);
    return ok;
}

/* Height-UNIQUE block ids. mk_block derives its id from (0xB0 + h),
 * which wraps at h = 80 and collides at h and h+256 — the engine
 * rejects a repeated BlockID at another height, so the long epoch drive
 * below needs ids that stay distinct for hundreds of blocks. */
static void mk_id_h(uint8_t out[64], uint64_t h) {
    memset(out, 0xA5, 64);
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(h >> (56 - 8 * i));
}
static void mk_block_h(nodus_v2_block_t *b, uint64_t h,
                       const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    /* O14 leader mode: identity is DERIVED — no id, parent or set hash
     * is carried. The parent chain follows the committed rows. */
    b->envs = envs;
    b->n_envs = n;
}

/* the fault points this section drives; F37/F38 carry their own index */
typedef struct {
    nodus_v2_apply_fail_t pt;
    uint32_t              effect_index;   /* F37 only                    */
    uint32_t              leg_index;      /* F38 only                    */
    const char           *name;
} fpt_t;

static const fpt_t O11_FAULTS[] = {
    { V2AP_FAIL_AFTER_ENV_RESERVE,   0, 0, "F26 post-reserve" },
    { V2AP_FAIL_AFTER_AUTH,          0, 0, "F28 post-auth" },
    { V2AP_FAIL_AFTER_READS,         0, 0, "F30 post-reads" },
    { V2AP_FAIL_AFTER_EXEC_HOOK,     0, 0, "F31 post-exec-hook" },
    /* F37 fires on the FIRST leg whose effect_count exceeds the index.
     * Leg 0 has exactly TWO effects in both shapes driven here, so
     * index 0 lands inside leg 0, and index 2 skips leg 0 entirely and
     * lands in leg 1 — but WHERE in leg 1 depends on the shape:
     *   DELEGATE  leg 1 has 3 effects → index 2 is its LAST, so the
     *             injection is at the TAIL of leg 1 (all of the leg's
     *             mutations applied, envelope not yet finalized);
     *   UNDELEGATE leg 1 has 4 effects (change CREATE, RELEASE CREATE,
     *             supply SET, input DELETE) → index 2 is genuinely
     *             MID-leg: the release UTXO EXISTS in the transaction
     *             and the funding input is not yet deleted. That is the
     *             one point in this matrix where the released value is
     *             live and then erased.
     * The shipped F37 carries no leg selector — "F37 on leg 1" is
     * reachable only through this effect-count arithmetic, which is
     * precisely the gap F38 was added to close. */
    { V2AP_FAIL_AFTER_EFFECT_APPLY,  0, 0, "F37 inside leg 0" },
    { V2AP_FAIL_AFTER_EFFECT_APPLY,  2, 0, "F37 in leg 1" },
    { V2AP_FAIL_AFTER_LEG_APPLY,     0, 0, "F38 BETWEEN legs" },
    { V2AP_FAIL_AFTER_INTENT_GUARD,  0, 0, "F35 post-replay-guard" },
    { V2AP_FAIL_AFTER_INTENT_INDEX,  0, 0, "F36 post-intent-index" },
    { V2AP_FAIL_BEFORE_COMMIT,       0, 0, "F13 pre-commit" },
    { V2AP_FAIL_COMMIT,              0, 0, "F14 commit failure" }
};
#define O11_FAULT_N (sizeof(O11_FAULTS) / sizeof(O11_FAULTS[0]))

static int test_o11_fault_matrix(void) {
    static uint8_t scall[8192], fcall[8192];
    int s9[1] = { 9 };

    /* ── A. the DELEGATE shape ──────────────────────────────────────── */
    for (size_t p = 0; p < O11_FAULT_N; p++) {
        fixture_t fx;
        env_t e;
        nodus_v2_block_t b;
        int rc = 0;
        uint8_t f9[64], vk0[64], dk90[128], chg[64];
        CHECK(fx_genesis(&fx, "f38d") == 0, "genesis");
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0xA1, f9) == 0, "fund");
        CHECK(val_key(0, vk0) == 0 && deleg_key_of(9, 0, dk90) == 0,
              "keys");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x91);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(out_nul(9, 0x91, chg) == 0, "change id");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        b.fail_at = O11_FAULTS[p].pt;
        b.fail_env_index = 0;
        b.fail_effect_index = O11_FAULTS[p].effect_index;
        b.fail_leg_index = O11_FAULTS[p].leg_index;
        /* the whole-DB digest is byte-identical across the injection */
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              O11_FAULTS[p].name);
        /* and the named half-envelope residues, individually: no
         * delegation row, no totals movement, the funding input still
         * unspent, no change output */
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 0,
              "no orphan delegation row survives the fault");
        CHECK(sysrow_read(fx.w, 5, dk90, 128, NULL, TDEL_REC_LEN) == 0,
              "the delegation row is absent through the adapter too");
        {
            uint8_t v[TVAL_REC_LEN];
            CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1,
                  "validator row");
            CHECK(tbe64(v + TVAL_TOT_OFF) == 0 &&
                  tbe64(v + TVAL_EXT_OFF) == 0,
                  "no delegated total survives the fault");
        }
        CHECK(utxo_rows(fx.w, f9) == 1,
              "the funding input was NOT consumed");
        CHECK(utxo_rows(fx.w, chg) == 0, "no change output survives");
        OK();
        /* CLEAN RETRY: the same block, un-faulted, commits to the exact
         * expected end state */
        b.fail_at = V2AP_FAIL_NONE;
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "clean retry after the fault must commit"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 1 &&
              utxo_rows(fx.w, f9) == 0 && utxo_rows(fx.w, chg) == 1,
              "retry end-state exact");
        {
            uint8_t v[TVAL_REC_LEN], d[TDEL_REC_LEN];
            CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1 &&
                  sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1,
                  "rows");
            CHECK(tbe64(v + TVAL_TOT_OFF) == DLG_AMOUNT &&
                  tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT,
                  "retry wrote exactly one position");
        }
        CHECK(supply_identity_holds(fx.w), "retry supply identity");
        OK();
        fx_close(&fx);
    }

    /* ── B. the UNDELEGATE shape (the RELEASE UTXO must never appear) ─ */
    for (size_t p = 0; p < O11_FAULT_N; p++) {
        fixture_t fx;
        env_t e, ed;
        nodus_v2_block_t b;
        int rc = 0;
        uint8_t f9[64], f9b[64], vk0[64], dk90[128], relid[64];
        uint8_t wid[64], iid[64];
        CHECK(fx_genesis(&fx, "f38u") == 0, "genesis");
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0xA2, f9) == 0, "fund");
        CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xA3, f9b) == 0, "fund");
        CHECK(val_key(0, vk0) == 0 && deleg_key_of(9, 0, dk90) == 0,
              "keys");
        /* setup: a committed position to withdraw from */
        {
            uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                           DLG_AMOUNT);
            uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9,
                                    DLG_CHANGE, 0x92);
            CHECK(sl && fl, "call");
            CHECK(two_leg_build(&fx, &ed, DNA_SYSRULE_DELEGATE, scall, sl,
                                DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                                s9, 1, s9, 1, NULL) == 0, "build");
            nodus_v2_envelope_t vd = { ed.bytes, ed.len };
            mk_block(&b, 1, &vd, 1);
            CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "setup");
        }
        /* the partial withdrawal under injection */
        uint64_t half = DLG_AMOUNT / 2;
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0, half);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x93);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &e, wid, iid) == 0, "ids");
        CHECK(release_nul(iid, relid) == 0, "release id");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        b.fail_at = O11_FAULTS[p].pt;
        b.fail_env_index = 0;
        b.fail_effect_index = O11_FAULTS[p].effect_index;
        b.fail_leg_index = O11_FAULTS[p].leg_index;
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              O11_FAULTS[p].name);
        /* the release UTXO is the value this fault could have minted */
        CHECK(utxo_rows(fx.w, relid) == 0,
              "NO release UTXO survives the fault");
        CHECK(utxo_rows(fx.w, f9b) == 1,
              "the fee funding was NOT consumed");
        {
            uint8_t d[TDEL_REC_LEN], v[TVAL_REC_LEN];
            CHECK(sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1 &&
                  sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1,
                  "rows");
            CHECK(tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT,
                  "the position is untouched by the fault");
            CHECK(tbe64(v + TVAL_TOT_OFF) == DLG_AMOUNT,
                  "the validator totals are untouched");
        }
        OK();
        b.fail_at = V2AP_FAIL_NONE;
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "clean retry after the fault must commit"); OK();
        CHECK(utxo_rows(fx.w, relid) == 1,
              "retry creates EXACTLY the release UTXO");
        {
            uint8_t d[TDEL_REC_LEN];
            CHECK(sysrow_read(fx.w, 5, dk90, 128, d, TDEL_REC_LEN) == 1,
                  "row");
            CHECK(tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT - half,
                  "retry decremented the position exactly once");
        }
        CHECK(supply_identity_holds(fx.w), "retry supply identity");
        OK();
        fx_close(&fx);
    }
    return 0;
}

/* ══ 15. O11 S5 — the VALIDATOR-SET FIREWALL ═══════════════════════
 *
 * Season §11 (+ O12 S1): none of the five SYSTEM validator-record
 * operations — the four stake-lifecycle ops and VALIDATOR_UPDATE — may
 * touch the validator-SET machinery. They write ROWS; the
 * SET (who is seated, for which epoch) is frozen in
 * validator_set_snapshots and consumed by committee resolution. The
 * distinction is the whole reason a mid-epoch STAKE cannot change who
 * signs the next block.
 *
 * SEEDING CHOICE: the snapshots are seeded through the SOURCE path
 * nodus_witness_vset_commit_genesis(w, 1) — the genesis hook itself,
 * which writes the rows for epoch 0 and epoch DNAC_EPOCH_LENGTH from
 * the already-seeded validators table. That is the cheapest HONEST
 * method: no hand-built snapshot bytes, no test-only writer, and it is
 * exactly what a real chain has. With the epoch-0 row present,
 * nodus_committee_get_for_block serves the FROZEN row instead of the
 * live recompute — without it, a STAKE that adds a 10M-bond validator
 * would legitimately change the recomputed committee and the test would
 * be proving the wrong thing. */
static int test_o11_vset_firewall(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx, "vsfw") == 0, "genesis");
    CHECK(nodus_witness_vset_commit_genesis(fx.w, 1) == 0,
          "seed the genesis validator-set snapshots"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots") == 2,
          "epochs 0 and DNAC_EPOCH_LENGTH are frozen"); OK();

    static uint8_t scall[8192], fcall[8192];
    int s9[1] = { 9 }, s10[1] = { 10 }, s1[1] = { 1 };
    env_t e;
    nodus_v2_block_t b;
    int rc = 0;
    uint8_t f9[64], f10[64], f10b[64], f9b[64], f9c[64];
    CHECK(seed_funding(&fx, 9, STAKE_FUND, 0x51, f9) == 0, "fund");
    CHECK(seed_funding(&fx, 10, DLG_FUND, 0x52, f10) == 0, "fund");
    CHECK(seed_funding(&fx, 10, NOLOCK_FUND, 0x53, f10b) == 0, "fund");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0x54, f9b) == 0, "fund");
    /* a SEPARATE unspent input for the op-5 rejects below: reusing the
     * UNSTAKE leg's (by then spent) input would give those envelopes a
     * second reason to die and make the op-5 pin vacuous */
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0x5A, f9c) == 0, "fund");
    uint8_t fp9[64];
    CHECK(key_fp_raw(9, fp9) == 0, "fp");

    /* the four frozen surfaces, captured ONCE */
    uint8_t vset0[64], epoch0[64], cc0[64], sethash0[64];
    CHECK(table_digest(fx.w, "validator_set_snapshots", vset0) == 0 &&
          table_digest(fx.w, "epoch_state", epoch0) == 0 &&
          table_digest(fx.w, "chain_config_history", cc0) == 0,
          "capture"); OK();
    /* the RESOLVED committee at a fixed governing height (epoch 0, so
     * the frozen row serves it) */
    nodus_committee_member_t *m0 = NULL;
    int n0 = 0;
    /* COLD every time: nodus_committee_get_for_block memoises by epoch
     * start, and a warm cache would answer from memory no matter what
     * the tables said — which would make the whole firewall assertion
     * vacuous. UINT64_MAX is the live constructor's cold sentinel
     * (nodus_witness.c:649, the same one fx_genesis_n sets). */
    fx.w->cached_committee_epoch_start = UINT64_MAX;
    CHECK(nodus_committee_get_for_block_alloc(fx.w, 3, &m0, &n0) == 0 &&
          n0 == DNAC_COMMITTEE_SIZE,
          "the frozen set is the genesis seven"); OK();
    {
        uint8_t (*fps)[64] = calloc((size_t)n0, 64);
        CHECK(fps != NULL, "alloc");
        for (int i = 0; i < n0; i++)
            CHECK(qgp_sha3_512(m0[i].pubkey, 2592, fps[i]) == 0, "fp");
        CHECK(nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                          (uint32_t)n0, sethash0) == 0,
              "set hash");
        free(fps);
        OK();
    }

    /* helper: every frozen surface is byte-identical, and committee
     * resolution returns the same members in the same order */
    #define FIREWALL_HOLDS(label) do {                                   \
        uint8_t d1[64];                                                  \
        CHECK(table_digest(fx.w, "validator_set_snapshots", d1) == 0 &&  \
              memcmp(d1, vset0, 64) == 0,                                \
              label ": validator_set_snapshots moved");                  \
        CHECK(table_digest(fx.w, "epoch_state", d1) == 0 &&              \
              memcmp(d1, epoch0, 64) == 0, label ": epoch_state moved"); \
        CHECK(table_digest(fx.w, "chain_config_history", d1) == 0 &&     \
              memcmp(d1, cc0, 64) == 0,                                  \
              label ": chain_config_history moved");                     \
        nodus_committee_member_t *mn = NULL;                             \
        int nn = 0;                                                      \
        fx.w->cached_committee_epoch_start = UINT64_MAX;  /* COLD */     \
        CHECK(nodus_committee_get_for_block_alloc(fx.w, 3, &mn, &nn)     \
                  == 0 && nn == n0, label ": committee size moved");     \
        for (int i = 0; i < nn; i++)                                     \
            CHECK(memcmp(mn[i].pubkey, m0[i].pubkey, 2592) == 0,         \
                  label ": committee MEMBER or ORDER moved");            \
        uint8_t (*fps2)[64] = calloc((size_t)nn, 64);                    \
        CHECK(fps2 != NULL, "alloc");                                    \
        for (int i = 0; i < nn; i++)                                     \
            CHECK(qgp_sha3_512(mn[i].pubkey, 2592, fps2[i]) == 0, "fp"); \
        uint8_t sh[64];                                                  \
        CHECK(nodus_rt_committee_set_hash((const uint8_t (*)[64])fps2,   \
                                          (uint32_t)nn, sh) == 0 &&      \
              memcmp(sh, sethash0, 64) == 0,                             \
              label ": resolved-set hash moved");                        \
        free(fps2);                                                      \
        free(mn);                                                        \
        OK();                                                            \
    } while (0)

    /* ── 1. STAKE — a BRAND NEW 10M-bond validator ─────────────────── */
    {
        uint32_t sl = stake_call_build(scall, sizeof(scall), 9, STAKE_BPS,
                                       STAKE_BOND, fp9);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, STAKE_CHANGE,
                                0x55);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_STAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "STAKE commits"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM validators") == 8,
              "the validators TABLE grew"); OK();
    }
    /* the table grew and the SET did not — the load-bearing separation:
     * a 10^15-bond newcomer would top any live recompute */
    FIREWALL_HOLDS("after STAKE");

    /* ── 2. DELEGATE ────────────────────────────────────────────────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 10, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f10, 10, DLG_CHANGE,
                                0x56);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s10, 1, s10, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "DELEGATE commits"); OK();
    }
    FIREWALL_HOLDS("after DELEGATE");

    /* ── 3. UNDELEGATE (full drain, so op 4's release path runs) ────── */
    {
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 10, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f10b, 10,
                                DLG_CHANGE, 0x57);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNDELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s10, 1, s10, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "UNDELEGATE commits"); OK();
    }
    FIREWALL_HOLDS("after UNDELEGATE");

    /* ── 4. UNSTAKE — a SEATED validator requests retirement ────────── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9b, 9, DLG_CHANGE,
                                0x58);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_UNSTAKE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "UNSTAKE commits"); OK();
        uint8_t vk1[64], v[TVAL_REC_LEN];
        CHECK(val_key(1, vk1) == 0 &&
              sysrow_read(fx.w, 4, vk1, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(v[TVAL_STATUS_OFF] == 1, "the row IS retiring"); OK();
    }
    /* a RETIRING committee member is still seated for this epoch — the
     * snapshot is the authority, and the row status is not */
    FIREWALL_HOLDS("after UNSTAKE");
    CHECK(supply_identity_holds(fx.w), "firewall run supply identity");
    OK();

    /* ── 5. VALIDATOR_UPDATE (SYSTEM op 5) — O12 S1 makes it LIVE, and
     *    the firewall must survive it too.
     *
     * The two rejects first (they leave f9c unspent, so the live update
     * below is not funded by a rolled-back input): an UNSTAKE-shaped
     * 2592-byte call in the op-5 record slot decodes as NOTHING (the op
     * accepts 2594 and only 2594), and the single-leg form has no
     * funding sibling. Then the real thing: validator 1 is RETIRING
     * after step 4 — a bonded exit state that keeps paying delegators
     * through its cooldown, so it is still allowed to tune commission
     * (bft.c:1966-1976). Its row moves; the SET must not. ─────────── */
    {
        uint32_t sl = unstake_call_build(scall, sizeof(scall), 1);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9c, 9, DLG_CHANGE,
                                0x59);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE, scall,
                            sl, DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "a 2592-byte call in the op-5 slot must reject");
        OK();
        /* and single-leg */
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_SYSTEM,
                               DNA_SYSRULE_VALIDATOR_UPDATE, scall, sl,
                               0, 0, 8, 16384, s1, 1, NULL) == 0,
              "build");
        nodus_v2_envelope_t v2 = { e.bytes, e.len };
        mk_block(&b, 5, &v2, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "single-leg VALIDATOR_UPDATE must reject"); OK();
        /* the LIVE update */
        uint32_t vl = vupd_call_build(scall, sizeof(scall), 1, 750);
        fl = fund_call(fcall, sizeof(fcall), f9c, 9, DLG_CHANGE, 0x5B);
        CHECK(vl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE, scall,
                            vl, DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s1, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t vv = { e.bytes, e.len };
        mk_block(&b, 5, &vv, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "a RETIRING validator's commission update commits"); OK();
        uint8_t vk1[64], v[TVAL_REC_LEN];
        CHECK(val_key(1, vk1) == 0 &&
              sysrow_read(fx.w, 4, vk1, 64, v, TVAL_REC_LEN) == 1, "row");
        CHECK(v[TVAL_STATUS_OFF] == 1 &&
              tbe64(v + TVAL_PEFF_OFF) == 5 + (uint64_t)DNAC_EPOCH_LENGTH,
              "the deferral landed and the exit state did not move"); OK();
    }
    FIREWALL_HOLDS("after VALIDATOR_UPDATE");
    /* ── 6. types 11/12/13 still REJECT at admission (cheap re-pin) ─── */
    {
        size_t n = 0;
        const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
        const nodus_domain_runtime_t *core = &bt[1];
        CHECK(core->admit(core, 11, DNAC_SHIELDED_POOL_V1) == -1 &&
              core->admit(core, 11, DNA_POOL_NONE) == -1 &&
              core->admit(core, 12, DNAC_SHIELDED_POOL_V1) == -1 &&
              core->admit(core, 12, DNA_POOL_NONE) == -1 &&
              core->admit(core, 13, DNAC_SHIELDED_POOL_V1) == -1 &&
              core->admit(core, 13, DNA_POOL_NONE) == -1,
              "the C3 hard stop must survive the staking season"); OK();
    }
    #undef FIREWALL_HOLDS
    free(m0);
    fx_close(&fx);
    return 0;
}

/* ══ 16. O11 S5 — cross-domain / global leftovers ══════════════════ */
static int test_o11_global(void) {
    static uint8_t scall[8192], fcall[8192];
    int s9[1] = { 9 };
    int rc = 0;

    /* ── 1. SAME-BLOCK duplicate intent: the batch dedup, not the
     *    committed guard (nothing is committed yet) ─────────────────── */
    {
        fixture_t fx;
        env_t e;
        nodus_v2_block_t b;
        uint8_t f9[64];
        CHECK(fx_genesis(&fx, "dupint") == 0, "genesis");
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0x61, f9) == 0, "fund");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x62);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t two[2] = { { e.bytes, e.len },
                                       { e.bytes, e.len } };
        mk_block(&b, 1, two, 2);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "the same staking intent twice in ONE block must reject");
        OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 0 &&
              utxo_rows(fx.w, f9) == 1,
              "the rejected batch left nothing"); OK();
        /* ONE copy commits — the rejection was the duplicate, not the
         * envelope */
        nodus_v2_envelope_t one = { e.bytes, e.len };
        mk_block(&b, 1, &one, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "a single copy of the same envelope commits"); OK();
        fx_close(&fx);
    }

    /* ── 2. CROSS-CHAIN: the same semantic delegate commits on two
     *    DIFFERENT chains independently, and neither chain accepts the
     *    other's bytes (the §7 cross-chain pattern, staking shape) ──── */
    {
        fixture_t a, o;
        env_t ea, eo;
        nodus_v2_block_t b;
        uint8_t fa[64], fo[64], ia[64], wa[64], io[64], wo[64];
        CHECK(fx_genesis(&a, "xcdA") == 0, "genesis A");
        g_gid_fill = 0xF2;
        int orc = fx_genesis(&o, "xcdO");
        g_gid_fill = 0xEE;
        CHECK(orc == 0, "genesis O");
        CHECK(memcmp(a.chain_id, o.chain_id, 32) != 0,
              "the fixtures must be different chains"); OK();
        CHECK(seed_funding(&a, 9, DLG_FUND, 0x63, fa) == 0, "fund A");
        CHECK(seed_funding(&o, 9, DLG_FUND, 0x63, fo) == 0, "fund O");
        /* the two chains' funding nullifiers are IDENTICAL by
         * construction — an output id is SHA3-512(owner_fp ‖ seed) and
         * commits no chain identity, so ONE call payload addresses both.
         * Pinned rather than left as a coincidence, because it is what
         * makes the replay leg below a pure CHAIN-BINDING test: the
         * foreign envelope names a row that really does exist here. */
        CHECK(memcmp(fa, fo, 64) == 0,
              "the funding ids must coincide across chains"); OK();
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), fa, 9, DLG_CHANGE,
                                0x64);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&a, &ea, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build A");
        CHECK(two_leg_build(&o, &eo, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build O");
        CHECK(derive_ids2(&a, &ea, wa, ia) == 0 &&
              derive_ids2(&o, &eo, wo, io) == 0, "ids");
        CHECK(memcmp(ia, io, 64) != 0,
              "the SAME semantic delegate has DIFFERENT intents on "
              "different chains"); OK();
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vo = { eo.bytes, eo.len };
        mk_block(&b, 1, &va, 1);
        CHECK(nodus_witness_v2_apply_block(a.w, &b) == 0, "A commits");
        mk_block(&b, 1, &vo, 1);
        /* O14: prev derived from this chain's own committed genesis. */
        CHECK(nodus_witness_v2_apply_block(o.w, &b) == 0, "O commits");
        OK();
        /* chain A's exact bytes on chain O: every signature was made
         * over A's chain-bound digest */
        {
            fixture_t o2;
            g_gid_fill = 0xF3;
            int o2rc = fx_genesis(&o2, "xcdO2");
            g_gid_fill = 0xEE;
            CHECK(o2rc == 0, "genesis O2");
            uint8_t f2[64];
            CHECK(seed_funding(&o2, 9, DLG_FUND, 0x63, f2) == 0, "fund");
            mk_block(&b, 1, &va, 1);
            /* O14: prev derived from the committed parent. */
            CHECK(apply_reject(o2.w, &b, &rc) == 0 && rc == -1,
                  "chain A's bytes must fail chain O2's binding"); OK();
            fx_close(&o2);
        }
        fx_close(&a);
        fx_close(&o);
    }

    /* ── 3. REVERSED LEG ORDER ──────────────────────────────────────
     * Two layers, and the FIRST one is the honest headline: the
     * ENCODER itself refuses to build a descending-domain envelope
     * (env_wire.c:274-277), so a non-canonical leg order is not
     * producible through the canonical API at all. The DECODER's own
     * refusal is then pinned by hand-swapping the two 30-byte leg
     * headers of an already-encoded envelope — the total length and
     * every blob stay put, so the ONLY thing wrong with those bytes is
     * the order. ──────────────────────────────────────────────────── */
    {
        fixture_t fx;
        env_t e;
        nodus_v2_block_t b;
        uint8_t f9[64];
        CHECK(fx_genesis(&fx, "legord") == 0, "genesis");
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0x65, f9) == 0, "fund");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x66);
        CHECK(sl && fl, "call");
        /* layer 1: the encoder refuses descending legs outright */
        {
            dna_env_leg_in_t legs[2];
            dna_env_in_t in;
            static uint8_t dummy_auth[1 + 7219];
            /* generously sized ON PURPOSE: if the buffer were too small
             * the encoder could reject for CAPACITY instead of ORDER and
             * the pin would be vacuous */
            static uint8_t buf[32768];
            size_t wlen = 0;
            memset(legs, 0, sizeof(legs));
            legs[0].hdr.domain_id = DNA_DOMAIN_CORE;      /* 1 FIRST     */
            legs[0].hdr.runtime_op = DNA_CORERULE_SYSFUND;
            legs[0].hdr.ruleset_version = rsv_of(DNA_DOMAIN_CORE);
            legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
            legs[0].hdr.auth_kind = 1;
            legs[0].hdr.call_len = fl;
            legs[0].hdr.auth_len = sizeof(dummy_auth);
            legs[0].call_data = fcall;
            legs[0].auth_data = dummy_auth;
            legs[1].hdr.domain_id = DNA_DOMAIN_SYSTEM;    /* 0 SECOND    */
            legs[1].hdr.runtime_op = DNA_SYSRULE_DELEGATE;
            legs[1].hdr.ruleset_version = rsv_of(DNA_DOMAIN_SYSTEM);
            legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
            legs[1].hdr.auth_kind = 1;
            legs[1].hdr.call_len = sl;
            legs[1].hdr.auth_len = sizeof(dummy_auth);
            legs[1].call_data = scall;
            legs[1].auth_data = dummy_auth;
            memset(&in, 0, sizeof(in));
            in.fee_amount = FEE_MIN;
            in.res_max_total_units = 400000;
            in.leg_count = 2;
            in.legs = legs;
            CHECK(dna_env_encode(&in, buf, sizeof(buf), &wlen) != 0 &&
                  wlen == 0,
                  "the ENCODER must refuse descending leg order"); OK();
        }
        /* layer 2: hand-swap the leg headers of a canonical envelope */
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        {
            static uint8_t bad[NATIVE_ENV_BUF];
            uint8_t tmp[DNA_ENV_LEG_HDR_LEN];
            dna_env_view_t v;
            memcpy(bad, e.bytes, e.len);
            memcpy(tmp, bad + DNA_ENV_FIXED_HEAD, DNA_ENV_LEG_HDR_LEN);
            memcpy(bad + DNA_ENV_FIXED_HEAD,
                   bad + DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN,
                   DNA_ENV_LEG_HDR_LEN);
            memcpy(bad + DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN, tmp,
                   DNA_ENV_LEG_HDR_LEN);
            CHECK(dna_env_decode(bad, e.len, &v) != 0 &&
                  v.leg_count == 0 && v.buf == NULL,
                  "the DECODER must refuse descending leg order"); OK();
            nodus_v2_envelope_t ve = { bad, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "a reversed-leg envelope must never reach execution");
            OK();
        }
        fx_close(&fx);
    }

    /* ── 4. WALL-CLOCK INDEPENDENCE (structural pin) ────────────────
     * Deliberately NOT a timing test — faking one would prove nothing.
     * The property is structural and has two halves, both cheap:
     *   (a) the execution context has no clock: nodus_rt_exec_ctx_t
     *       carries chain_id / global_height / epoch / the derived
     *       identities / the auth verdict / the committee view, and the
     *       ONLY time-like inputs are global_height and epoch;
     *   (b) epoch is a PURE FUNCTION of the block count — never a
     *       timestamp — and the engine VERIFIES blk->epoch against it
     *       rather than trusting the caller (v2_apply.c).
     * The behavioural half (identical bytes ⇒ identical state and
     * roots, whenever they run) is already proven by the twin-fixture
     * sections §7 and §11-§13, which execute the same envelopes on
     * independently created fixtures and byte-compare consensus state;
     * duplicating that here would add no information. ─────────────── */
    {
        for (uint64_t h = 0; h < 3; h++)
            CHECK(nodus_v2_epoch_for_height(h) == h / DNAC_EPOCH_LENGTH,
                  "epoch must be the pure block-count derivation");
        CHECK(nodus_v2_epoch_for_height(DNAC_EPOCH_LENGTH - 1) == 0 &&
              nodus_v2_epoch_for_height(DNAC_EPOCH_LENGTH) == 1 &&
              nodus_v2_epoch_for_height(DNAC_EPOCH_LENGTH + 1) == 1,
              "the boundary is exactly h / DNAC_EPOCH_LENGTH"); OK();
        /* the engine REJECTS a lying epoch rather than trusting it */
        fixture_t fx;
        env_t e;
        nodus_v2_block_t b;
        uint8_t f9[64];
        CHECK(fx_genesis(&fx, "epochlie") == 0, "genesis");
        CHECK(seed_funding(&fx, 9, DLG_FUND, 0x67, f9) == 0, "fund");
        uint32_t sl = deleg_call_build(scall, sizeof(scall), 9, 0,
                                       DLG_AMOUNT);
        uint32_t fl = fund_call(fcall, sizeof(fcall), f9, 9, DLG_CHANGE,
                                0x68);
        CHECK(sl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                            DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            s9, 1, s9, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        b.epoch = 7;                     /* a lie about its own epoch    */
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "a block that lies about its epoch must reject"); OK();
        fx_close(&fx);
    }

    /* ── 5. EPOCH BOUNDARY: the same operation at LEN-1, LEN, LEN+1 ──
     * O12 S2 gave the V2 engine an epoch-boundary phase of its own
     * (nodus_witness_v2_epoch.c: commissions → graduation → flips →
     * commit_next), so the boundary block at LEN now ALSO freezes the
     * snapshot for epoch 2·LEN — which needs the legacy `blocks` row at
     * the lookback height LEN−1 (committee.c:116-125; the V2-native
     * seed source is an ACTIVATION-SEASON obligation, see the module
     * header). The fixture plants that row below, exactly as
     * test_v2_epoch does. The property under test is unchanged: a
     * staking envelope behaves IDENTICALLY across the boundary and
     * blk->epoch is the derived value at each height. Driving there
     * needs DNAC_EPOCH_LENGTH-2 empty blocks; that empty blocks commit
     * at all is asserted explicitly below, so if this engine ever
     * refuses them the failure names itself rather than silently
     * skipping the boundary. ──────────────────────────────────────── */
    {
        fixture_t fx;
        env_t e;
        nodus_v2_block_t b;
        uint8_t f[3][64], vk0[64];
        const int delegators[3] = { 9, 10, 11 };
        CHECK(fx_genesis(&fx, "epochb") == 0, "genesis");
        CHECK(val_key(0, vk0) == 0, "key");
        /* NOTE (ORCHESTRATOR integration): funding is seeded AFTER the
         * empty drive, not here. seed_funding writes utxo_set OUT OF
         * BAND (no block), so the CORE head root and the recomputed
         * root diverge until the next block that DECLARES CORE touched
         * absorbs the drift — and an EMPTY block declares nothing, so
         * the untouched-domain guard would (correctly) reject it. The
         * guard firing on out-of-band state drift is the engine working
         * as designed; the fixture must not create the drift before the
         * empties. */
        /* The first empty block is an ASSUMPTION, asserted by name.
         * A block with no envelopes, no claims and no pool batches has
         * no precedent anywhere in this test tree — every existing
         * `mk_block(..., NULL, 0)` carries pool_muts — so this is the
         * first time fully-empty legality is exercised. If the engine
         * refuses one, THIS assertion names the reason the boundary
         * drive stopped rather than the drive silently not happening. */
        mk_block_h(&b, 1, NULL, 0);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "an EMPTY V2 block must commit (epoch-boundary drive)");
        OK();
        for (uint64_t h = 2; h < (uint64_t)DNAC_EPOCH_LENGTH - 1; h++) {
            mk_block_h(&b, h, NULL, 0);
            if (nodus_witness_v2_apply_block(fx.w, &b) != 0) {
                fprintf(stderr, "empty drive failed at height %llu\n",
                        (unsigned long long)h);
                return 1;
            }
        }
        OK();
        /* funding lands here — the very next block (LEN-1) declares
         * CORE touched, so the out-of-band drift is absorbed by its
         * ordinary head update (see the ORCHESTRATOR note above) */
        for (int i = 0; i < 3; i++)
            CHECK(seed_funding(&fx, delegators[i], DLG_FUND,
                               (uint8_t)(0x70 + i), f[i]) == 0, "fund");
        /* O12 S2: the boundary block at LEN freezes snapshot(2·LEN),
         * whose committee compute reads the LEGACY blocks row at the
         * lookback height (state_seed tiebreak, committee.c:116-125).
         * Plant it — `blocks` is legacy block storage, not a V2 root
         * leg, so the out-of-band insert cannot trip the guard. */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                "INSERT OR IGNORE INTO blocks (height, tx_root, "
                "tx_count, timestamp, proposer_id, prev_hash, "
                "state_root, created_at) VALUES (?1, zeroblob(64), 0, "
                "0, zeroblob(32), zeroblob(64), ?2, 0)",
                -1, &st, NULL) == SQLITE_OK, "lookback prep");
            uint8_t sr[64];
            memset(sr, 0x5A, sizeof(sr));
            sqlite3_bind_int64(st, 1,
                (sqlite3_int64)((uint64_t)DNAC_EPOCH_LENGTH - 1));
            sqlite3_bind_blob(st, 2, sr, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "lookback row");
            sqlite3_finalize(st);
        }
        /* three identical-shaped delegations at LEN-1, LEN, LEN+1 */
        for (int i = 0; i < 3; i++) {
            uint64_t h = (uint64_t)DNAC_EPOCH_LENGTH - 1 + (uint64_t)i;
            int sd[1] = { delegators[i] };
            uint32_t sl = deleg_call_build(scall, sizeof(scall),
                                           delegators[i], 0, DLG_AMOUNT);
            uint32_t fl = fund_call(fcall, sizeof(fcall), f[i],
                                    delegators[i], DLG_CHANGE,
                                    (uint8_t)(0x78 + i));
            CHECK(sl && fl, "call");
            CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_DELEGATE, scall, sl,
                                DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                                sd, 1, sd, 1, NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block_h(&b, h, &ve, 1);
            CHECK(b.epoch == h / (uint64_t)DNAC_EPOCH_LENGTH,
                  "the block's epoch is the derived value");
            CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
                  "a staking envelope commits identically across the "
                  "epoch boundary");
            uint8_t d[TDEL_REC_LEN], dk[128];
            CHECK(deleg_key_of(delegators[i], 0, dk) == 0 &&
                  sysrow_read(fx.w, 5, dk, 128, d, TDEL_REC_LEN) == 1,
                  "row");
            CHECK(tbe64(d + TDEL_AMT_OFF) == DLG_AMOUNT &&
                  tbe64(d + TDEL_AT_OFF) == h,
                  "the position records the executing height");
            OK();
        }
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM delegations") == 3,
              "three independent positions across the boundary"); OK();
        {
            uint8_t v[TVAL_REC_LEN];
            CHECK(sysrow_read(fx.w, 4, vk0, 64, v, TVAL_REC_LEN) == 1,
                  "row");
            CHECK(tbe64(v + TVAL_TOT_OFF) == 3 * DLG_AMOUNT,
                  "the totals aggregate across the boundary"); OK();
        }
        CHECK(supply_identity_holds(fx.w), "boundary supply identity");
        OK();
        fx_close(&fx);
    }
    return 0;
}

/* ══ 17. SYSTEM slice — VALIDATOR_UPDATE (O12 S1) ══════════════════
 *
 * The validator's own commission change, migrated from
 * apply_validator_update (nodus_witness_bft.c:1934-2003) onto the 2-leg
 * validator-record envelope. It is the first record op whose funding leg
 * moves NO value at all: lock = release = 0, so the CORE sibling is a
 * pure fee payment.
 *
 * What this section pins that no earlier one can:
 *   - the three-way commission transition (decrease / equal / increase)
 *     and the ONE-EPOCH deferral arithmetic, including its behaviour ON
 *     an epoch boundary;
 *   - that a transition touches the commission window and
 *     last_validator_update_block and NOTHING else — asserted by a
 *     FULL-RECORD byte comparison against the record the mediated read
 *     observed, with only the named columns patched;
 *   - that the ACTIVE SET is untouched (snapshots + epoch_state).
 *
 * ⚠ ARITHMETIC LABEL, stated once here and once at rtn_vupd_exec: the
 * source deferral is max(next_epoch_boundary, H + E) and the BOUNDARY
 * ARM IS UNREACHABLE. next_epoch_boundary = floor(H/E)*E + E and
 * floor(H/E)*E <= H, so the boundary can never EXCEED H + E; it EQUALS
 * it exactly when H is a multiple of E. The tests below therefore pin
 * the two reachable cases — off-boundary (H + E strictly greater) and
 * on-boundary (the two expressions coincide) — rather than pretending a
 * third exists. The ternary is nevertheless preserved verbatim in the
 * runtime, so if E ever becomes per-epoch state the pin still applies to
 * the code the source wrote. */

/* Insert one extra validator row in a given status with ZERO self_stake.
 * Zero is load-bearing twice: the CORE supply identity sums self_stake
 * (a nonzero bond would need a matching genesis bump), and the committee
 * recompute orders by (self_stake + external_delegated) DESC with
 * LIMIT target, so a 0-stake row can never displace one of the seven
 * genesis validators. The destination fingerprint is a REAL 128-char
 * lowercase hex window — the writable-shape verdict rightly freezes
 * anything else (fx_genesis_n carries the same note). */
static int seed_validator(fixture_t *fx, int k, int status, uint32_t bps) {
    static const char hexd[] = "0123456789abcdef";
    dnac_validator_record_t v;
    uint8_t fpr[64];
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_pk[k], 2592);
    v.self_stake = 0;
    v.status = (uint8_t)status;
    v.commission_bps = (uint16_t)bps;
    v.active_since_block = 1;
    if (qgp_sha3_512(g_pk[k], 2592, fpr) != 0) return -1;
    for (int b = 0; b < 64; b++) {
        v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
        v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
    }
    v.unstake_destination_fp[128] = '\0';
    return nodus_validator_insert(fx->w, &v);
}

/* Force one validator row's commission window out of band (pre-block, the
 * §13 status-seeding precedent). */
static int set_commission(fixture_t *fx, const uint8_t pkh[64],
                          uint32_t cur, uint32_t pending, uint64_t peff) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validators SET commission_bps = ?1, "
            "pending_commission_bps = ?2, pending_effective_block = ?3 "
            "WHERE pubkey_hash = ?4", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)cur);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pending);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)peff);
    sqlite3_bind_blob(st, 4, pkh, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Every column of a validator record EXCEPT the four this op may write.
 * A transition that quietly moves a fifth column fails here — this is
 * the "NOTHING ELSE MOVES" assertion, done positively (compare the whole
 * 5397-byte record) rather than by listing what to check. @return 0 =
 * every untouched column is byte-identical. */
static int vupd_only_commission_moved(const uint8_t *before,
                                      const uint8_t *after) {
    uint8_t a[TVAL_REC_LEN], b[TVAL_REC_LEN];
    memcpy(a, before, TVAL_REC_LEN);
    memcpy(b, after, TVAL_REC_LEN);
    /* blank the four writable columns in BOTH copies, then demand the
     * remaining 5387 bytes are identical */
    memset(a + TVAL_COMM_OFF, 0, 2);
    memset(b + TVAL_COMM_OFF, 0, 2);
    memset(a + TVAL_PCOMM_OFF, 0, 2);
    memset(b + TVAL_PCOMM_OFF, 0, 2);
    memset(a + TVAL_PEFF_OFF, 0, 8);
    memset(b + TVAL_PEFF_OFF, 0, 8);
    memset(a + TVAL_LASTUPD_OFF, 0, 8);
    memset(b + TVAL_LASTUPD_OFF, 0, 8);
    return memcmp(a, b, TVAL_REC_LEN) == 0 ? 0 : -1;
}

/* The commission window as three numbers, straight off a stored row. */
typedef struct { uint32_t cur, pending; uint64_t peff, last_upd; } vwin_t;
static void vupd_window(const uint8_t *rec, vwin_t *w) {
    w->cur      = ((uint32_t)rec[TVAL_COMM_OFF] << 8) |
                  rec[TVAL_COMM_OFF + 1];
    w->pending  = ((uint32_t)rec[TVAL_PCOMM_OFF] << 8) |
                  rec[TVAL_PCOMM_OFF + 1];
    w->peff     = tbe64(rec + TVAL_PEFF_OFF);
    w->last_upd = tbe64(rec + TVAL_LASTUPD_OFF);
}

/* Build the canonical VALIDATOR_UPDATE envelope: leg0 = op 5 signed by
 * the validator itself, leg1 = the FEE-ONLY funding leg signed by whoever
 * owns the input. */
static int vupd_env(fixture_t *fx, env_t *e, int validator, uint32_t bps,
                    const uint8_t in[64], int funder, uint8_t seed,
                    uint64_t fee, const two_opt_t *opt) {
    static uint8_t vcall[4096], fcall[8192];
    int sv[1], sf[1];
    uint32_t vl = vupd_call_build(vcall, sizeof(vcall), validator, bps);
    uint32_t fl = fund_call(fcall, sizeof(fcall), in, funder, DLG_CHANGE,
                            seed);
    if (!vl || !fl) return -1;
    sv[0] = validator;
    sf[0] = funder;
    return two_leg_build(fx, e, DNA_SYSRULE_VALIDATOR_UPDATE, vcall, vl,
                         DNA_CORERULE_SYSFUND, fcall, fl, fee, sv, 1,
                         sf, 1, opt);
}

/* the stored amount of one UTXO, by its nullifier (UINT64_MAX = absent) */
static uint64_t utxo_amount_of(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount FROM utxo_set WHERE nullifier = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* the four seeded non-committee rows */
#define VU_ELIGIBLE  12
#define VU_RETIRING  13
#define VU_UNSTAKED  14
#define VU_AUTORET   15

static int vupd_fixture(fixture_t *fx, const char *tag) {
    uint8_t pkh[7][64];
    if (fx_genesis(fx, tag) != 0) return -1;
    /* freeze the SET through the SOURCE genesis hook FIRST, so committee
     * resolution serves the frozen row and the extra rows below cannot
     * be mistaken for a set change (the §15 seeding note) */
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;
    for (int k = 0; k < 7; k++)
        if (val_key(k, pkh[k]) != 0) return -1;
    /* key 0: a real current rate PLUS a stale pending entry — a decrease
     * must clear it. key 1: the same, for the EQUAL path. */
    if (set_commission(fx, pkh[0], 3000, 9999, 12345) != 0) return -1;
    if (set_commission(fx, pkh[1], 3000, 4444, 777) != 0) return -1;
    /* key 6 keeps commission 0 — the increase path */
    if (seed_validator(fx, VU_ELIGIBLE, DNAC_VALIDATOR_ELIGIBLE, 500) != 0)
        return -1;
    if (seed_validator(fx, VU_RETIRING, DNAC_VALIDATOR_RETIRING, 500) != 0)
        return -1;
    if (seed_validator(fx, VU_UNSTAKED, DNAC_VALIDATOR_UNSTAKED, 500) != 0)
        return -1;
    if (seed_validator(fx, VU_AUTORET, DNAC_VALIDATOR_AUTO_RETIRED, 500)
        != 0)
        return -1;
    return 0;
}

static int test_system_validator_update(void) {
    fixture_t fx;
    env_t e;
    static env_t e_p6;                /* P6's exact bytes, for the
                                       * byte-identical replay leg      */
    nodus_v2_block_t b;
    int rc = 0;
    static uint8_t vcall[4096], fcall[8192];
    uint8_t fneg[64], fpos[8][64];
    uint8_t pkh0[64], pkh1[64], pkh6[64], pkhE[64], pkhR[64], pkhU[64],
            pkhA[64];
    uint8_t before[TVAL_REC_LEN], after[TVAL_REC_LEN];
    vwin_t w;

    CHECK(vupd_fixture(&fx, "vupd") == 0, "genesis");
    CHECK(val_key(0, pkh0) == 0 && val_key(1, pkh1) == 0 &&
          val_key(6, pkh6) == 0 && val_key(VU_ELIGIBLE, pkhE) == 0 &&
          val_key(VU_RETIRING, pkhR) == 0 &&
          val_key(VU_UNSTAKED, pkhU) == 0 &&
          val_key(VU_AUTORET, pkhA) == 0, "keys");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0x90, fneg) == 0, "fund neg");
    for (int i = 0; i < 8; i++)
        CHECK(seed_funding(&fx, 9, NOLOCK_FUND, (uint8_t)(0x91 + i),
                           fpos[i]) == 0, "fund pos");

    /* the frozen SET surfaces, captured before anything executes */
    uint8_t vset0[64], epoch0[64];
    CHECK(table_digest(fx.w, "validator_set_snapshots", vset0) == 0 &&
          table_digest(fx.w, "epoch_state", epoch0) == 0, "capture");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM validator_set_snapshots") == 2,
          "the set really is frozen (2 seeded epochs)"); OK();

    /* ══ NEGATIVES — every one a digest-proven no-op at height 1 ══════
     * They all name the SAME unspent funding input, which stays unspent
     * precisely because they all reject. */

    /* N1 UNKNOWN validator: the stray key has no validator row at all */
    {
        CHECK(vupd_env(&fx, &e, K_STRAY, 500, fneg, 9, 0xA0, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N1 unknown validator must reject"); OK();
    }
    /* N2 UNSTAKED and N3 AUTO_RETIRED: frozen stake, frozen commission
     * (bft.c:1970-1976). Both rows EXIST and are otherwise well-formed,
     * so status is the only violated rule. */
    {
        CHECK(vupd_env(&fx, &e, VU_UNSTAKED, 100, fneg, 9, 0xA1, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N2 an UNSTAKED validator must not update"); OK();
    }
    {
        CHECK(vupd_env(&fx, &e, VU_AUTORET, 100, fneg, 9, 0xA2, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N3 an AUTO_RETIRED validator must not update"); OK();
    }
    /* N4 bps above the source bound (bft.c:1953-1957) */
    {
        CHECK(vupd_env(&fx, &e, 0, DNAC_COMMISSION_BPS_MAX + 1, fneg, 9,
                       0xA3, FEE_MIN, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N4 commission_bps > 10000 must reject"); OK();
    }
    /* N5/N6 call length ±1: EXACT 2594, never a prefix and never a
     * suffix. 2595 is also the shape a caller would produce by starting
     * to re-append the retired signed_at_block field. */
    {
        static const uint32_t lens[2] = { 2593u, 2595u };
        int sv[1] = { 0 }, sf[1] = { 9 };
        for (int i = 0; i < 2; i++) {
            uint32_t fl;
            CHECK(vupd_call_build(vcall, sizeof(vcall), 0, 500) == 2594,
                  "call");
            vcall[2594] = 0x00;          /* the +1 byte, if used         */
            fl = fund_call(fcall, sizeof(fcall), fneg, 9, DLG_CHANGE,
                           (uint8_t)(0xA4 + i));
            CHECK(fl, "fund call");
            CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE,
                                vcall, lens[i], DNA_CORERULE_SYSFUND,
                                fcall, fl, FEE_MIN, sv, 1, sf, 1,
                                NULL) == 0, "build");
            nodus_v2_envelope_t ve = { e.bytes, e.len };
            mk_block(&b, 1, &ve, 1);
            CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
                  "N5/N6 a call length other than 2594 must reject");
        }
        OK();
    }
    /* N7 ALL-ZERO identity pubkey (a well-formed 2594-byte call whose
     * identity no key can own) */
    {
        int sv[1] = { 0 }, sf[1] = { 9 };
        uint32_t fl;
        memset(vcall, 0, 2594);
        vcall[2592] = 0;
        vcall[2593] = 100;
        fl = fund_call(fcall, sizeof(fcall), fneg, 9, DLG_CHANGE, 0xA6);
        CHECK(fl, "fund call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE, vcall,
                            2594, DNA_CORERULE_SYSFUND, fcall, fl,
                            FEE_MIN, sv, 1, sf, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N7 an all-zero identity pubkey must reject"); OK();
    }
    /* N8 WRONG SIGNER: the call names validator 0, the record leg is
     * signed by key 1 — a fully VALID kind-1 signature over the right
     * digest by the wrong identity. The authorization boundary accepts
     * it (key 1 really signed); the CALL-IDENTITY binding at exec is
     * what kills it. Pinned in isolation at the hook layer below. */
    {
        int sv[1] = { 1 }, sf[1] = { 9 };
        uint32_t vl = vupd_call_build(vcall, sizeof(vcall), 0, 100);
        uint32_t fl = fund_call(fcall, sizeof(fcall), fneg, 9, DLG_CHANGE,
                                0xA7);
        CHECK(vl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE, vcall,
                            vl, DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                            sv, 1, sf, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N8 a valid signature by the wrong identity must reject");
        OK();
    }
    /* N9 KIND-2 CARRIAGE on the record leg: SYSTEM's allowlist permits
     * it, the OP refuses it. (The hook-level pin below separates the
     * exec refusal from the authorization layer's own kind-2 parse.) */
    {
        two_opt_t o;
        memset(&o, 0, sizeof(o));
        o.sys_auth_kind = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        CHECK(vupd_env(&fx, &e, 0, 100, fneg, 9, 0xA8, FEE_MIN, &o) == 0,
              "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N9 kind-2 carriage on an op-5 leg must reject"); OK();
    }
    /* N10 SINGLE-LEG SYSTEM: a record with no funding partner */
    {
        int sv[1] = { 0 };
        uint32_t vl = vupd_call_build(vcall, sizeof(vcall), 0, 100);
        CHECK(vl, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_SYSTEM,
                               DNA_SYSRULE_VALIDATOR_UPDATE, vcall, vl,
                               0, 0, 8, 16384, sv, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N10 single-leg VALIDATOR_UPDATE must reject"); OK();
    }
    /* N11 SINGLE-LEG SYSFUND: funding with no record partner */
    {
        int sf[1] = { 9 };
        uint32_t fl = fund_call(fcall, sizeof(fcall), fneg, 9, DLG_CHANGE,
                                0xA9);
        CHECK(fl, "call");
        CHECK(env_build_signed(&fx, &e, DNA_DOMAIN_CORE,
                               DNA_CORERULE_SYSFUND, fcall, fl, FEE_MIN,
                               0, 40, 16384, sf, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N11 single-leg SYSFUND must reject"); OK();
    }
    /* N12 SIBLING MISMATCH: a well-formed op-5 record leg paired with a
     * CORE SPEND instead of the funding op. Unlike §11's C13 this one is
     * NOT ambiguous about where it dies — leg0 executes first, and leg0's
     * own shape gate requires leg1 to be DNA_CORERULE_SYSFUND. */
    {
        int sv[1] = { 0 }, sf[1] = { 9 };
        uint32_t vl = vupd_call_build(vcall, sizeof(vcall), 0, 100);
        uint32_t fl = fund_call(fcall, sizeof(fcall), fneg, 9, DLG_CHANGE,
                                0xAA);
        CHECK(vl && fl, "call");
        CHECK(two_leg_build(&fx, &e, DNA_SYSRULE_VALIDATOR_UPDATE, vcall,
                            vl, DNA_CORERULE_SPEND, fcall, fl, FEE_MIN,
                            sv, 1, sf, 1, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "N12 a non-SYSFUND sibling must reject"); OK();
    }
    /* the whole negative matrix left the chain untouched */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0 &&
          utxo_rows(fx.w, fneg) == 1,
          "the negative matrix burned nothing and spent nothing"); OK();

    /* ══ POSITIVES ═══════════════════════════════════════════════════ */

    /* P1 DECREASE — immediate, and the stale pending entry is CLEARED */
    {
        CHECK(sysrow_read(fx.w, 4, pkh0, 64, before, TVAL_REC_LEN) == 1,
              "before");
        CHECK(vupd_env(&fx, &e, 0, 1000, fpos[0], 9, 0xB0, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 1, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P1 a decrease commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkh0, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 1000 && w.pending == 0 && w.peff == 0 &&
              w.last_upd == 1,
              "P1 immediate rate, pending cleared, Rule K stamped"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P1 no other column moved"); OK();
        /* fee-only conservation: the change output exists, the input is
         * gone, and EXACTLY the fee was burned */
        uint8_t chg[64];
        CHECK(out_nul(9, 0xB0, chg) == 0, "change id");
        CHECK(utxo_rows(fx.w, chg) == 1 && utxo_rows(fx.w, fpos[0]) == 0,
              "P1 change created, funding input consumed"); OK();
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") ==
                  FEE_MIN &&
              utxo_amount_of(fx.w, chg) == DLG_CHANGE,
              "P1 exactly the fee burned, exactly the change created");
        OK();
        CHECK(supply_identity_holds(fx.w), "P1 supply identity"); OK();
    }
    /* P2 EQUAL — falls through the decrease branch: the current rate does
     * not move and the stale pending entry is dropped (bft.c:1922-1924) */
    {
        CHECK(sysrow_read(fx.w, 4, pkh1, 64, before, TVAL_REC_LEN) == 1,
              "before");
        vupd_window(before, &w);
        CHECK(w.cur == 3000 && w.pending == 4444 && w.peff == 777,
              "P2 precondition: a stale pending entry exists"); OK();
        CHECK(vupd_env(&fx, &e, 1, 3000, fpos[1], 9, 0xB1, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P2 an equal update commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkh1, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 3000 && w.pending == 0 && w.peff == 0 &&
              w.last_upd == 2,
              "P2 rate unchanged, pending cleared"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P2 no other column moved"); OK();
    }
    /* P3 INCREASE off a boundary — DEFERRED exactly one epoch, current
     * rate untouched. H = 3, so H + E strictly exceeds the next epoch
     * boundary and the max selects H + E. */
    {
        CHECK(sysrow_read(fx.w, 4, pkh6, 64, before, TVAL_REC_LEN) == 1,
              "before");
        CHECK(vupd_env(&fx, &e, 6, 2500, fpos[2], 9, 0xB2, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 3, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P3 an increase commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkh6, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 0 && w.pending == 2500 &&
              w.peff == 3 + (uint64_t)DNAC_EPOCH_LENGTH && w.last_upd == 3,
              "P3 deferred one full epoch, current rate untouched"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P3 no other column moved"); OK();
    }
    /* P4 an ELIGIBLE validator may update (a seat-less bonded validator
     * tunes commission trying to win a seat back — bft.c:1966-1969) */
    {
        CHECK(sysrow_read(fx.w, 4, pkhE, 64, before, TVAL_REC_LEN) == 1,
              "before");
        CHECK(vupd_env(&fx, &e, VU_ELIGIBLE, 200, fpos[3], 9, 0xB3,
                       FEE_MIN, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 4, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P4 an ELIGIBLE validator's update commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkhE, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 200 && w.pending == 0 && w.last_upd == 4 &&
              after[TVAL_STATUS_OFF] == (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
              "P4 rate moved, status did NOT"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P4 no other column moved"); OK();
    }
    /* P5 a RETIRING validator may update (it keeps paying delegators
     * through its cooldown) — and this one INCREASES, so the deferral
     * lands on an exit-state row without disturbing the exit */
    {
        CHECK(sysrow_read(fx.w, 4, pkhR, 64, before, TVAL_REC_LEN) == 1,
              "before");
        CHECK(vupd_env(&fx, &e, VU_RETIRING, 900, fpos[4], 9, 0xB4,
                       FEE_MIN, NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e.bytes, e.len };
        mk_block(&b, 5, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P5 a RETIRING validator's update commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkhR, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 500 && w.pending == 900 &&
              w.peff == 5 + (uint64_t)DNAC_EPOCH_LENGTH && w.last_upd == 5 &&
              after[TVAL_STATUS_OFF] == (uint8_t)DNAC_VALIDATOR_RETIRING,
              "P5 deferral set, exit state untouched"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P5 no other column moved"); OK();
    }
    /* P6 SEQUENTIAL updates: validator 0 again, in a later block. Rule K's
     * stamp must ADVANCE, and the second transition must read the row the
     * FIRST one wrote (1000, not the seeded 3000) — an increase relative
     * to the current committed value. */
    {
        CHECK(sysrow_read(fx.w, 4, pkh0, 64, before, TVAL_REC_LEN) == 1,
              "before");
        vupd_window(before, &w);
        CHECK(w.cur == 1000 && w.last_upd == 1,
              "P6 precondition: P1's row is what P6 reads"); OK();
        CHECK(vupd_env(&fx, &e_p6, 0, 1200, fpos[5], 9, 0xB5, FEE_MIN,
                       NULL) == 0, "build");
        nodus_v2_envelope_t ve = { e_p6.bytes, e_p6.len };
        mk_block(&b, 6, &ve, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "P6 a second update commits"); OK();
        CHECK(sysrow_read(fx.w, 4, pkh0, 64, after, TVAL_REC_LEN) == 1,
              "after");
        vupd_window(after, &w);
        CHECK(w.cur == 1000 && w.pending == 1200 &&
              w.peff == 6 + (uint64_t)DNAC_EPOCH_LENGTH && w.last_upd == 6,
              "P6 last_validator_update_block advanced"); OK();
        CHECK(vupd_only_commission_moved(before, after) == 0,
              "P6 no other column moved"); OK();
    }
    /* six committed envelopes, six fees, nothing else destroyed */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") ==
              6 * FEE_MIN,
          "fee-only: exactly one fee burned per committed update"); OK();
    CHECK(supply_identity_holds(fx.w), "supply identity"); OK();

    /* ══ ACTIVE-SET IMMUTABILITY ══════════════════════════════════════
     * Six commission changes later, the SET machinery is byte-identical:
     * a commission change is not a set change. */
    {
        uint8_t d1[64];
        CHECK(table_digest(fx.w, "validator_set_snapshots", d1) == 0 &&
              memcmp(d1, vset0, 64) == 0,
              "validator_set_snapshots must be byte-identical"); OK();
        CHECK(table_digest(fx.w, "epoch_state", d1) == 0 &&
              memcmp(d1, epoch0, 64) == 0,
              "epoch_state must be byte-identical"); OK();
        CHECK(val_col(fx.w, pkh0, "self_stake") == VAL_BOND &&
              val_col(fx.w, pkh0, "status") ==
                  (uint64_t)DNAC_VALIDATOR_ACTIVE &&
              val_col(fx.w, pkh0, "total_delegated") == 0 &&
              val_col(fx.w, pkh0, "external_delegated") == 0,
              "stake and status did not move"); OK();
        CHECK(active_count(fx.w) == 0,
              "validator_stats.active_count did not move"); OK();
    }

    /* ══ REPLAY ═══════════════════════════════════════════════════════
     * HONEST LABEL (the §11 C19 caveat, verbatim in force here): the
     * committed-identity guard fires pre-BEGIN, AND the funding input
     * this envelope names was consumed by P6, so a mutant that removed
     * the guard would still see the leg reject on a missing input. The
     * two rules are CO-SUFFICIENT and this test does not separate them —
     * an intent twin of a committed record envelope necessarily re-spends
     * the same UTXO. The guard is pinned in isolation by §7. What IS
     * separated here is the IDENTITY behaviour: an extra funding witness
     * must not move intent_id and must move wire_id. */
    {
        static env_t twin;               /* 128 KiB — off the stack     */
        uint8_t w0[64], i0[64], wt[64], it[64];
        int sv[1] = { 0 }, sf2[2] = { 9, 11 };
        uint32_t vl = vupd_call_build(vcall, sizeof(vcall), 0, 1200);
        uint32_t fl = fund_call(fcall, sizeof(fcall), fpos[5], 9,
                                DLG_CHANGE, 0xB5);
        CHECK(vl && fl, "call");
        /* BYTE-IDENTICAL replay of P6 in a LATER block: the very bytes
         * that committed at height 6 */
        nodus_v2_envelope_t ve = { e_p6.bytes, e_p6.len };
        mk_block(&b, 7, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "a committed update intent must not replay"); OK();
        CHECK(derive_ids2(&fx, &e_p6, w0, i0) == 0, "ids");
        /* the AUTH TWIN: one more valid funding signer, same intent */
        CHECK(two_leg_build(&fx, &twin, DNA_SYSRULE_VALIDATOR_UPDATE,
                            vcall, vl, DNA_CORERULE_SYSFUND, fcall, fl,
                            FEE_MIN, sv, 1, sf2, 2, NULL) == 0, "build");
        CHECK(derive_ids2(&fx, &twin, wt, it) == 0, "ids");
        CHECK(memcmp(it, i0, 64) == 0,
              "an extra witness must NOT move the intent id"); OK();
        CHECK(memcmp(wt, w0, 64) != 0, "it MUST move the wire id"); OK();
        nodus_v2_envelope_t vt = { twin.bytes, twin.len };
        mk_block(&b, 7, &vt, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "the auth twin must reject on the committed intent"); OK();
    }
    fx_close(&fx);

    /* ══ CROSS-CHAIN ══════════════════════════════════════════════════
     * The same semantic update is a DIFFERENT intent on a different
     * chain, and one chain's bytes never authorize on another. */
    {
        fixture_t a, o;
        static env_t ea, eo;             /* 128 KiB each — off the stack */
        uint8_t fa[64], fo[64], ia[64], wa[64], io[64], wo[64];
        CHECK(vupd_fixture(&a, "vuxcA") == 0, "genesis A");
        g_gid_fill = 0xF6;
        int orc = vupd_fixture(&o, "vuxcO");
        g_gid_fill = 0xEE;
        CHECK(orc == 0, "genesis O");
        CHECK(memcmp(a.chain_id, o.chain_id, 32) != 0,
              "the fixtures must be different chains"); OK();
        CHECK(seed_funding(&a, 9, NOLOCK_FUND, 0xC0, fa) == 0, "fund A");
        CHECK(seed_funding(&o, 9, NOLOCK_FUND, 0xC0, fo) == 0, "fund O");
        CHECK(memcmp(fa, fo, 64) == 0,
              "the funding ids coincide, so the replay is a pure "
              "chain-binding test"); OK();
        CHECK(vupd_env(&a, &ea, 0, 1000, fa, 9, 0xC1, FEE_MIN, NULL) == 0 &&
              vupd_env(&o, &eo, 0, 1000, fo, 9, 0xC1, FEE_MIN, NULL) == 0,
              "build");
        CHECK(derive_ids2(&a, &ea, wa, ia) == 0 &&
              derive_ids2(&o, &eo, wo, io) == 0, "ids");
        CHECK(memcmp(ia, io, 64) != 0,
              "the same update has DIFFERENT intents on different chains");
        OK();
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vo = { eo.bytes, eo.len };
        mk_block(&b, 1, &va, 1);
        CHECK(nodus_witness_v2_apply_block(a.w, &b) == 0, "A commits");
        mk_block(&b, 1, &vo, 1);
        /* O14: prev derived from this chain's own committed genesis. */
        CHECK(nodus_witness_v2_apply_block(o.w, &b) == 0, "O commits");
        OK();
        {
            fixture_t o2;
            g_gid_fill = 0xF7;
            int o2rc = vupd_fixture(&o2, "vuxcO2");
            g_gid_fill = 0xEE;
            CHECK(o2rc == 0, "genesis O2");
            uint8_t f2[64];
            CHECK(seed_funding(&o2, 9, NOLOCK_FUND, 0xC0, f2) == 0, "fund");
            mk_block(&b, 1, &va, 1);
            /* O14: prev derived from the committed parent. */
            CHECK(apply_reject(o2.w, &b, &rc) == 0 && rc == -1,
                  "chain A's bytes must fail chain O2's binding"); OK();
            fx_close(&o2);
        }
        fx_close(&a);
        fx_close(&o);
    }

    /* ══ TWIN EXECUTION (the §7 convention) ═══════════════════════════
     * Two independent fixtures, two DIFFERENT valid signature
     * realizations of ONE intent. Consensus state, the validator record
     * itself and the domain/global roots must be byte-identical; the
     * wire tx roots must not be. */
    {
        fixture_t a, b2;
        static env_t ea, eb;             /* 128 KiB each — off the stack */
        uint8_t fa[64], fb[64], wa[64], ia[64], wb[64], ib[64];
        nodus_v2_block_t ba, bb;
        CHECK(vupd_fixture(&a, "vutwA") == 0, "genesis A");
        CHECK(vupd_fixture(&b2, "vutwB") == 0, "genesis B");
        CHECK(seed_funding(&a, 9, NOLOCK_FUND, 0xD0, fa) == 0, "fund A");
        CHECK(seed_funding(&b2, 9, NOLOCK_FUND, 0xD0, fb) == 0, "fund B");
        CHECK(vupd_env(&a, &ea, 6, 2500, fa, 9, 0xD1, FEE_MIN, NULL) == 0 &&
              vupd_env(&b2, &eb, 6, 2500, fb, 9, 0xD1, FEE_MIN, NULL) == 0,
              "build");
        CHECK(ea.len == eb.len && memcmp(ea.bytes, eb.bytes, ea.len) != 0,
              "randomized signing must give distinct realizations"); OK();
        CHECK(derive_ids2(&a, &ea, wa, ia) == 0 &&
              derive_ids2(&b2, &eb, wb, ib) == 0, "ids");
        CHECK(memcmp(ia, ib, 64) == 0 && memcmp(wa, wb, 64) != 0,
              "update twins: one intent, two wires"); OK();
        nodus_v2_envelope_t va = { ea.bytes, ea.len };
        nodus_v2_envelope_t vb = { eb.bytes, eb.len };
        mk_block(&ba, 1, &va, 1);
        mk_block(&bb, 1, &vb, 1);
        /* O14: id derived by the engine. */
        CHECK(nodus_witness_v2_apply_block(a.w, &ba) == 0, "A commits");
        CHECK(nodus_witness_v2_apply_block(b2.w, &bb) == 0, "B commits");
        OK();
        uint8_t da[64], db[64];
        CHECK(consensus_state_digest(a.w, da) == 0 &&
              consensus_state_digest(b2.w, db) == 0, "digest");
        CHECK(memcmp(da, db, 64) == 0,
              "update twins: consensus state identical"); OK();
        /* `validators` is not in consensus_state_digest's list — compare
         * the record this op actually wrote, byte for byte */
        {
            uint8_t ra[TVAL_REC_LEN], rb[TVAL_REC_LEN], k6[64];
            CHECK(val_key(6, k6) == 0, "key");
            CHECK(sysrow_read(a.w, 4, k6, 64, ra, TVAL_REC_LEN) == 1 &&
                  sysrow_read(b2.w, 4, k6, 64, rb, TVAL_REC_LEN) == 1,
                  "rows");
            CHECK(memcmp(ra, rb, TVAL_REC_LEN) == 0,
                  "update twins: the validator record is byte-identical");
            OK();
        }
        CHECK(memcmp(ba.out_domains_root, bb.out_domains_root, 64) == 0 &&
              memcmp(ba.out_global_root, bb.out_global_root, 64) == 0,
              "update twins: roots identical"); OK();
        CHECK(memcmp(ba.out_tx_root, bb.out_tx_root, 64) != 0,
              "update twins: wire tx roots differ"); OK();
        fx_close(&a);
        fx_close(&b2);
    }
    return 0;
}

/* ══ 18. O12 S1 HOOK-LEVEL pins for VALIDATOR_UPDATE ═══════════════
 *
 * Seams the block layer cannot separate, because the next layer produces
 * the same block verdict:
 *   - the ONE-EPOCH deferral arithmetic at heights the block layer would
 *     need a 720-block drive to reach (H = E-1 / E / E+1), including the
 *     ON-BOUNDARY case where next_epoch_boundary and H + E coincide;
 *   - the call-identity binding: a LEGITIMATE one-signer verdict naming
 *     the wrong identity dies at exec, not at the authorization boundary;
 *   - the read plan's exact shape (one mediated read, no counter, no
 *     delegation count);
 *   - kind-2 refusal at exec, with a verdict the auth layer would have
 *     accepted. */
static int test_vupd_hook_pins(void) {
    fixture_t fx;
    env_t e;
    static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
    size_t rl = 0;
    size_t n = 0;
    const nodus_domain_runtime_t *bt = nodus_runtime_builtin_table(&n);
    const nodus_domain_runtime_t *sys, *core;
    uint8_t f9[64], iid[64];
    nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
    nodus_rt_read_res_t reads[NODUS_RT_MAX_READS];
    uint16_t nr = 0;
    nodus_rt_auth_verdict_t av;
    nodus_rt_exec_ctx_t ctx;
    dna_env_view_t v;

    CHECK(bt && n == 2, "table");
    sys = &bt[0];
    core = &bt[1];
    CHECK(vupd_fixture(&fx, "vuhk") == 0, "genesis");
    CHECK(seed_funding(&fx, 9, NOLOCK_FUND, 0xE0, f9) == 0, "fund");
    /* validator 6 starts at commission 0, so every bps > 0 below is an
     * INCREASE and exercises the deferral arm */
    CHECK(vupd_env(&fx, &e, 6, 2500, f9, 9, 0xE1, FEE_MIN, NULL) == 0,
          "build");
    CHECK(dna_env_decode(e.bytes, e.len, &v) == 0, "decode");

    memset(&av, 0, sizeof(av));
    av.n_signers = 1;
    CHECK(qgp_sha3_512(g_pk[6], 2592, av.signer_fp[0]) == 0, "fp");
    memset(iid, 0x51, sizeof(iid));
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = fx.chain_id;
    ctx.global_height = 1;
    ctx.intent_id = iid;
    ctx.wire_id = iid;
    ctx.auth = &av;

    /* the honest round-trip first, so every negative below is a real
     * difference rather than a broken harness */
    CHECK(nodus_rt_system_read_plan(sys, &v, 0, &ctx, reqs,
                                    NODUS_RT_MAX_READS, &nr) == 0 &&
          nr == 1 && reqs[0].op_id == 4 && reqs[0].key_len == 64,
          "H1 op 5 plans EXACTLY one validator read"); OK();
    memset(reads, 0, sizeof(reads));
    CHECK(nodus_witness_v2_read_one(fx.w, sys, &reqs[0], &reads[0])
              == NODUS_ADAPTER_OK && reads[0].present == 1 &&
          reads[0].value_len == TVAL_REC_LEN, "mediated read"); OK();
    CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, reads, nr, res,
                              sizeof(res), &rl) == 0,
          "H2 the honest hook-level update accepts"); OK();

    /* the effect this op emits: ONE vhash-bound SET of the validator row,
     * and nothing else */
    {
        dna_effect_view_t ev;
        CHECK(dna_effect_result_decode(res, rl, &ev) == 0 &&
              ev.effect_count == 1, "decode result"); OK();
        CHECK(ev.eff[0].op_id == 4 &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              ev.eff[0].key_len == 64 &&
              ev.eff[0].value_len == TVAL_REC_LEN,
              "H3 exactly one EXISTS_VHASH-bound validator SET"); OK();
        CHECK(vupd_only_commission_moved(reads[0].value,
                                         ev.buf + ev.val_off[0]) == 0,
              "H3 the emitted record differs ONLY in the commission "
              "window"); OK();
    }

    /* H4 the deferral arithmetic across the epoch boundary. The block
     * layer would need a 720-block drive to reach these heights; the
     * arithmetic is a pure function of ctx->global_height, so it is
     * pinned here directly.
     *   H = E-1  → boundary E,    H+E = 2E-1  → max = 2E-1  (off)
     *   H = E    → boundary 2E,   H+E = 2E    → max = 2E    (COINCIDE)
     *   H = E+1  → boundary 2E,   H+E = 2E+1  → max = 2E+1  (off)
     * The middle row is the on-boundary case; note it is the ONLY height
     * class where the two expressions agree, and the boundary never
     * EXCEEDS H+E — see the section header's arithmetic label. */
    {
        const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
        const uint64_t hs[4]   = { 1, E - 1, E, E + 1 };
        for (int i = 0; i < 4; i++) {
            dna_effect_view_t ev;
            uint64_t H = hs[i];
            uint64_t boundary = ((H / E) + 1) * E;
            uint64_t want = boundary > H + E ? boundary : H + E;
            ctx.global_height = H;
            CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, reads, nr, res,
                                      sizeof(res), &rl) == 0, "exec");
            CHECK(dna_effect_result_decode(res, rl, &ev) == 0 &&
                  ev.effect_count == 1, "decode");
            const uint8_t *nv = ev.buf + ev.val_off[0];
            vwin_t w;
            vupd_window(nv, &w);
            CHECK(w.cur == 0 && w.pending == 2500 && w.peff == want &&
                  w.last_upd == H,
                  "H4 the deferral is max(next boundary, H + epoch)");
            CHECK(w.peff == H + E,
                  "H4 the boundary arm never exceeds H + epoch");
        }
        OK();
        ctx.global_height = 1;
    }

    /* H5 CALL-IDENTITY BINDING: a perfectly legitimate one-signer verdict
     * that names ANOTHER validator. The authorization boundary would have
     * accepted this (key 0 could really have signed); exec refuses it
     * because the row a record op writes derives from CALL bytes only. */
    {
        nodus_rt_auth_verdict_t bad;
        memcpy(&bad, &av, sizeof(bad));
        CHECK(qgp_sha3_512(g_pk[0], 2592, bad.signer_fp[0]) == 0, "fp");
        ctx.auth = &bad;
        CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, reads, nr, res,
                                  sizeof(res), &rl) == -1,
              "H5 a valid verdict for the wrong identity must reject");
        OK();
        ctx.auth = &av;
    }
    /* H6 EXTRA SIGNER: two verified signers, one of them the right
     * identity. The op requires EXACTLY one, so a twin cannot write a
     * divergent row — it cannot write at all. */
    {
        nodus_rt_auth_verdict_t two;
        memcpy(&two, &av, sizeof(two));
        two.n_signers = 2;
        CHECK(qgp_sha3_512(g_pk[9], 2592, two.signer_fp[1]) == 0, "fp");
        ctx.auth = &two;
        CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, reads, nr, res,
                                  sizeof(res), &rl) == -1,
              "H6 a second verified signer must reject"); OK();
        ctx.auth = &av;
    }
    /* H7 KIND-2 CARRIAGE at exec, with an otherwise perfect verdict */
    {
        dna_env_view_t v2 = v;
        v2.leg[0].auth_kind = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        CHECK(nodus_rt_system_exec(sys, &v2, 0, &ctx, reads, nr, res,
                                  sizeof(res), &rl) == -1,
              "H7 kind-2 carriage on an op-5 leg must reject at exec");
        OK();
    }
    /* H8 SINGLE-LEG: both hooks refuse a record leg with no partner */
    {
        dna_env_view_t v2 = v;
        uint16_t nr2 = 0;
        v2.leg_count = 1;
        CHECK(nodus_rt_system_read_plan(sys, &v2, 0, &ctx, reqs,
                                        NODUS_RT_MAX_READS, &nr2) == -1,
              "H8 single-leg op 5 must fail to plan"); OK();
        CHECK(nodus_rt_system_exec(sys, &v2, 0, &ctx, reads, nr, res,
                                  sizeof(res), &rl) == -1,
              "H8 single-leg op 5 must fail to exec"); OK();
    }
    /* H9 ABSENT row: a missing validator is a deterministic VERDICT, not
     * a create and not a node fault */
    {
        nodus_rt_read_res_t r2[NODUS_RT_MAX_READS];
        memcpy(r2, reads, sizeof(r2));
        r2[0].present = 0;
        r2[0].value_len = 0;
        CHECK(nodus_rt_system_exec(sys, &v, 0, &ctx, r2, nr, res,
                                  sizeof(res), &rl) == -1,
              "H9 a missing validator row must reject as a verdict"); OK();
    }
    /* H10 the CORE funding hook ACCEPTS op 5 as a sibling — it joined
     * the validator-record family this season — and plans the ordinary
     * input + burned-counter pair. This is the positive counterpart of
     * the §12 P5 foreign-sibling loop, which op 5 left when it became
     * legal. */
    {
        uint16_t nr2 = 0;
        CHECK(nodus_rt_core_read_plan(core, &v, 1, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr2) == 0 &&
              nr2 == 2,
              "H10 SYSFUND plans under an op-5 sibling"); OK();
    }
    /* H11 a MALFORMED op-5 record leg poisons its sibling too: the CORE
     * hook decodes the flow through the SAME parser, so a bad record call
     * can never be paired with a good funding leg */
    {
        dna_env_view_t v2 = v;
        uint16_t nr2 = 0;
        v2.leg[0].call_len = TVUPD_CALL_LEN - 1;
        CHECK(nodus_rt_core_read_plan(core, &v2, 1, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr2) == 0,
              "H11 the CORE plan does not decode the sibling call");
        memset(reads, 0, sizeof(reads));
        for (uint16_t r = 0; r < nr2; r++)
            CHECK(nodus_witness_v2_read_one(fx.w, core, &reqs[r],
                                            &reads[r]) == NODUS_ADAPTER_OK,
                  "read");
        CHECK(nodus_rt_core_exec(core, &v2, 1, &ctx, reads, nr2, res,
                                 sizeof(res), &rl) == -1,
              "H11 a truncated op-5 sibling must reject the funding leg");
        OK();
    }
    fx_close(&fx);
    return 0;
}

int main(void) {
    /* O15J Faz 2 — this file pins which domain roots a given runtime op
     * moves: "op X moves SYSTEM", "op X must NOT move CORE".
     *
     * A mint moves BOTH roots on every block, so with inflation on the
     * "must move" half becomes VACUOUS (true for a reason unrelated to
     * the op) and the "must not move" half FAILS OUTRIGHT. An earlier
     * version of this comment said both became "vacuously true" — review
     * R2-F12 corrected that; only one half is vacuity, the other is a
     * hard failure.
     *
     * Either way the properties are inexpressible on a minting chain, so
     * this file runs quiet. Emission and settlement have their own
     * coverage in test_v2_econ. */
    v2x_inflation_off = 1;

    if (keys_init() != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    if (test_auth() != 0) return 1;
    if (test_authority() != 0) return 1;
    if (test_system_cc() != 0) return 1;
    if (test_system_cc_target_active_max() != 0) return 1;
    if (test_committee_capacity() != 0) return 1;
    if (test_core_spend() != 0) return 1;
    if (test_engine() != 0) return 1;
    if (test_intent_engine() != 0) return 1;
    if (test_core_burn() != 0) return 1;
    if (test_core_token_create() != 0) return 1;
    if (test_hook_level_pins() != 0) return 1;
    if (test_system_stake() != 0) return 1;
    if (test_o11_hook_pins() != 0) return 1;
    if (test_system_delegate() != 0) return 1;
    if (test_system_unstake() != 0) return 1;
    if (test_system_undelegate() != 0) return 1;
    if (test_o11_fault_matrix() != 0) return 1;
    if (test_o11_vset_firewall() != 0) return 1;
    if (test_o11_global() != 0) return 1;
    if (test_system_validator_update() != 0) return 1;
    if (test_vupd_hook_pins() != 0) return 1;
    printf("test_v2_native: ALL OK (%d checks)\n", g_checks);
    return 0;
}
