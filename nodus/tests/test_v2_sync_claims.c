/**
 * @file nodus/tests/test_v2_sync_claims.c
 * @brief Ledger V2 O15F Task 5 — sync/joiner CLAIM carriage (blkframe v2).
 *
 * `shared/dnac/blockmsg_v2.*` is PROTECTED and stays byte-identical
 * (claim_count still 0). Claims ride a NODUS-side per-frame container that
 * WRAPS the canonical BlockMessage v1:
 *
 *   blkframe := 0x02 ‖ u32be blkmsg_len ‖ blkmsg(v1) ‖ u32be n_claims ‖
 *              ( u32be claim_len ‖ claim_bytes ) × n_claims
 *
 * Two independent successor fixtures, A (producer) and B (empty at
 * genesis, SAME pinned genesis). A commits a claim block + a claim-free
 * block, each certified with a real QC. Then:
 *
 *  - serve on A: the claim block yields a 0x02 container, the claim-free
 *    block yields a BARE v1 blockmsg (byte 0 == 0x01), genesis (h=0) is
 *    handled as today (rc 1, no QC by construction);
 *  - adversarial containers fed to B at genesis reject PRE-COMMIT with the
 *    DB digest byte-unchanged: a claim omitted, an extra valid claim,
 *    a truncated container, a trailing-byte container;
 *  - the honest frames feed to B via nodus_witness_v2_sync_apply_range →
 *    B reaches A's head with byte-identical BlockID/roots and its own
 *    v2_claim_bytes rows equal A's;
 *  - a REORDERED-claim container is ACCEPTED on a fresh twin B2 with the
 *    IDENTICAL BlockID (claim carriage order is not consensus-bound —
 *    claims_root sorts by nullifier) while storing a different availability
 *    index order — the sharp true statement, not a reject (source:
 *    apply.c claim phase enforces no order; claims.c reads ORDER BY
 *    nullifier ASC; finalize compares out_block_id == claimed_id only);
 *  - a pre-S12 height (count row absent) serves rc 1 UNAVAILABLE.
 *
 * Fixture: the test_v2_produce/test_v2_claim_ingress shape (7 REAL
 * ML-DSA-87 validators + a server identity to sign the own DNA.CERT.v2 +
 * the present-distribution genesis) migrated to schema S12 and ARMED via
 * the test-authority gate fixture (compiled into this binary only —
 * mirrors test_v2_gate).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_ingress.h"
#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_mempool.h"
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/qc_v2.h"
#include "dnac/block_v2.h"
#include "dnac/blockmsg_v2.h"
#include "dnac/vset_wire.h"
#include "dnac/manifest_wire.h"
#include "dnac/domain_wire.h"

#include "v2_genesis_fixture.h"    /* v2x_db_digest */

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ── deterministic committee keys (test_v2_produce shape) ───────────── */

#define N_KEYS 7

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];

static int make_keys(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        uint8_t full[64];
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

/* ── deterministic distribution leaves (test_v2_claims shape) ───────── */

#define N_LEAVES 3
static uint8_t g_pk[N_LEAVES][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[N_LEAVES][QGP_DSA87_SECRETKEYBYTES];
static dna_dist_leaf_t g_leaf[N_LEAVES];
static uint8_t g_leaf_hash[N_LEAVES][64];
static uint8_t g_snapshot_root[64];

static const uint8_t g_native_asset[64] = {0};   /* CORE: native token  */

/* conv 3/2 FLOOR: 10->15, 5->7, 7->10; Sum = 32 */
static const uint64_t g_src_amount[N_LEAVES] = { 10, 5, 7 };
static const uint64_t g_conv_amount[N_LEAVES] = { 15, 7, 10 };
static const char *g_src_id[N_LEAVES] = { "src-alpha", "src-beta", "src-gamma" };

static int keys_init(void) {
    for (int i = 0; i < N_LEAVES; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x90 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0)
            return -1;
        memset(&g_leaf[i], 0, sizeof(g_leaf[i]));
        g_leaf[i].leaf_version = DNA_DIST_VERSION;
        g_leaf[i].source_id_len = (uint16_t)strlen(g_src_id[i]);
        memcpy(g_leaf[i].source_id, g_src_id[i], g_leaf[i].source_id_len);
        g_leaf[i].source_amount = g_src_amount[i];
        if (qgp_sha3_512(g_pk[i], QGP_DSA87_PUBLICKEYBYTES,
                         g_leaf[i].dest_binding) != 0)
            return -1;
        if (dna_dist_leaf_hash(&g_leaf[i], g_leaf_hash[i]) != 0)
            return -1;
    }
    if (dna_dist_snapshot_root(g_leaf, N_LEAVES, g_snapshot_root) != 0)
        return -1;
    if (dna_dist_check_totals(g_leaf, N_LEAVES, 3, 2,
                              DNA_DISTROUND_FLOOR, 32) != 0)
        return -1;
    return 0;
}

/* ── fixture ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    char             dir[128];
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint8_t          genesis_id[64];
    uint8_t          manifest_hash[64];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
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

static int seed_validators(fixture_t *fx) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_ks[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        uint8_t fpr[64];
        if (qgp_sha3_512(g_ks[i].pk, DNAC_PUBKEY_SIZE, fpr) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return 0;
}

/* genesis(1000) = CORE utxo(968) + unclaimed distribution(32) */
static int seed_supply_dist(nodus_witness_t *w) {
    if (run_sql(w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
            "total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 1000, 0, 0, 968, x'00', 0)") != 0)
        return -1;
    return run_sql(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'01', 'genesis', 968, zeroblob(64), "
        "zeroblob(63)||x'aa', 0, 0, 0, 0, 1)");
}

static int build_dist_manifest(nodus_witness_t *w, uint8_t *out, size_t cap,
                               size_t *out_len, uint8_t out_mh[64]) {
    dna_domain_manifest_t dm;
    uint8_t sys_h[64], core_h[64];
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, sys_h) != 0) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, core_h) != 0) return -1;

    dna_gman_t m;
    memset(&m, 0, sizeof(m));
    m.manifest_version   = DNA_GMAN_VERSION;
    m.genesis_supply_raw = 1000;
    m.domain_count       = 2;
    m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m.domains[0].manifest_hash, sys_h, 64);
    m.domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m.domains[1].manifest_hash, core_h, 64);

    m.dist_present       = 1;
    m.dist_version       = DNA_DIST_VERSION;
    m.target_domain_id   = DNA_DOMAIN_CORE;
    m.target_asset_len   = 64;
    memcpy(m.target_asset_ref, g_native_asset, 64);
    m.source_tag_len     = (uint16_t)strlen("testnet-generic");
    memcpy(m.source_tag, "testnet-generic", m.source_tag_len);
    m.source_commit_len  = 16;
    memset(m.source_commit, 0x77, 16);
    memcpy(m.snapshot_root, g_snapshot_root, 64);
    m.leaf_count         = N_LEAVES;
    m.conv_numerator     = 3;
    m.conv_denominator   = 2;
    m.rounding_mode      = DNA_DISTROUND_FLOOR;
    m.excluded_amount    = 4;
    m.total_claimable    = 32;
    m.claim_start_height = 1;
    m.claim_end_height   = 1000000;
    m.auth_mode          = DNA_CLAIMAUTH_DNA_NATIVE;
    m.fee_mode           = DNA_CLAIMFEE_NONE;
    m.post_deadline_mode = DNA_POSTDL_RETAIN;

    if (dna_gman_hash(&m, out_mh) != 0) return -1;
    return dna_gman_encode(&m, out, cap, out_len);
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w   = calloc(1, sizeof(*fx->w));
    fx->srv = calloc(1, sizeof(*fx->srv));
    if (!fx->w || !fx->srv) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_syncc_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) return -1;
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x5D, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    /* migrate the whole way to S12 — the count/bytes tables the serve path
     * reads land at S12 (stepwise: S9 requires the base, S12 requires S11). */
    if (nodus_witness_db_migrate_v2s9(fx->w)  != 0) return -1;
    if (nodus_witness_db_migrate_v2s10(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s11(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s12(fx->w) != 0) return -1;

    if (seed_supply_dist(fx->w) != 0) return -1;
    if (seed_validators(fx) != 0) return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;
    if (nodus_witness_domreg_init_genesis(fx->w) != 0) return -1;

    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (build_dist_manifest(fx->w, mbytes, sizeof(mbytes), &mlen,
                            fx->manifest_hash) != 0)
        return -1;

    uint8_t vsh[DNA_VSET_HASH_LEN];
    memset(vsh, 0x77, sizeof(vsh));
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(fx->w, 0, &s0, &sn,
                                                        &sq) == 0 && s0) {
            int hrc = dna_vset_hash(s0, vsh);
            dna_vset_free(&s0);
            if (hrc != 0) return -1;
        } else {
            dna_vset_free(&s0);
            return -1;
        }
    }
    if (nodus_witness_v2_genesis_ex(fx->w, NULL, vsh, 0, mbytes, mlen) != 0)
        return -1;

    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(fx->w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        int ok = 0;
        if (sqlite3_step(st) == SQLITE_ROW &&
            sqlite3_column_bytes(st, 0) == 64) {
            memcpy(fx->genesis_id, sqlite3_column_blob(st, 0), 64);
            memcpy(fx->chain_id, fx->genesis_id, 32);
            ok = 1;
        }
        sqlite3_finalize(st);
        if (!ok) return -1;
    }

    memcpy(fx->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(fx->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(fx->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    fx->w->server = fx->srv;
    memcpy(fx->w->my_id, g_ks[0].voter, 32);
    fx->w->v2_successor = true;
    memcpy(fx->w->v2_chain32, fx->chain_id, 32);
    /* Open the production gate for THIS handle — the only way serve/ingress/
     * apply_range answer at all. The authority + readiness fixture is
     * compiled into this binary and nowhere else (mirrors test_v2_gate). */
    nodus_witness_v2_gate_test_arm(fx->w, 1);
    fx->w->v2_ingress_armed = true;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        nodus_witness_mempool_clear(&fx->w->mempool);
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    free(fx->srv);
    fx->srv = NULL;
    if (fx->dir[0]) rmrf(fx->dir);
}

/* ── claim + envelope builders ──────────────────────────────────────── */

static int make_claim(dna_claim_t *c, int leaf, const uint8_t chain[32],
                      const uint8_t manifest_hash[64]) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain, 32);
    memcpy(c->manifest_hash, manifest_hash, 64);
    c->leaf_index = (uint64_t)leaf;
    c->source_id_len = g_leaf[leaf].source_id_len;
    memcpy(c->source_id, g_leaf[leaf].source_id, c->source_id_len);
    c->source_amount = g_leaf[leaf].source_amount;
    memcpy(c->dest_binding, g_leaf[leaf].dest_binding, 64);
    uint16_t ns = 0;
    if (dna_dist_proof_build((const uint8_t (*)[64])g_leaf_hash, N_LEAVES,
                             (uint64_t)leaf, c->siblings, &ns) != 0)
        return -1;
    c->n_siblings = ns;
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, g_pk[leaf], QGP_DSA87_PUBLICKEYBYTES);
    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len,
                       g_sk[leaf]) != 0 || siglen != DNA_CLAIM_SIG_LEN)
        return -1;
    return 0;
}

static int claim_ids(const dna_claim_t *c, uint8_t nul[64], uint8_t oid[64]) {
    dna_dist_leaf_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    uint8_t lh[64];
    if (dna_dist_leaf_hash(&leaf, lh) != 0) return -1;
    if (dna_claim_nullifier(c->chain_id, c->manifest_hash, DNA_DOMAIN_CORE,
                            g_native_asset, 64, lh, nul) != 0)
        return -1;
    return dna_claim_utxo_id(nul, oid);
}

static int encode_claim(const dna_claim_t *c, uint8_t **out, size_t *out_len,
                        uint8_t hash[64]) {
    size_t need = dna_claim_encoded_len(c);
    if (need == 0) return -1;
    uint8_t *b = malloc(need);
    if (!b) return -1;
    size_t wr = 0;
    if (dna_claim_encode(c, b, need, &wr) != 0 || wr != need) {
        free(b);
        return -1;
    }
    if (qgp_sha3_512(b, wr, hash) != 0) { free(b); return -1; }
    *out = b;
    *out_len = wr;
    return 0;
}

static nodus_witness_mempool_entry_t *
mkclaimentry(const uint8_t *bytes, size_t len, const uint8_t hash[64],
             const uint8_t nullifier[64]) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    memcpy(e->tx_hash, hash, 64);
    e->tx_type = NODUS_W_TX_V2_CLAIM;
    e->tx_data = malloc(len);
    if (!e->tx_data) { free(e); return NULL; }
    memcpy(e->tx_data, bytes, len);
    e->tx_len = (uint32_t)len;
    memcpy(e->nullifiers[0], nullifier, 64);
    e->nullifier_count = 1;
    return e;
}

/* ── the smallest successor-valid SYSTEM CHAIN_CONFIG envelope ───────── */

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
} test_env_t;

static int build_cc_env(fixture_t *fx, uint64_t nonce, test_env_t *out) {
    memset(out, 0, sizeof(*out));
    const uint8_t *chain32 = fx->chain_id;

    dna_domain_manifest_t sys_man;
    if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0)
        return -1;

    uint64_t tip = 0;
    if (nodus_witness_v2_tip_height(fx->w, &tip) != 0) return -1;

    nodus_committee_member_t *cm = NULL;
    int cmn = 0;
    if (nodus_committee_get_for_block_alloc(fx->w, tip, &cm, &cmn) != 0 ||
        cmn < 1)
        return -1;

    int rc = -1;
    uint8_t *fps = malloc((size_t)cmn * 64);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    uint8_t *auth = NULL;
    uint8_t *env_bytes = NULL;
    do {
        if (!fps || !pf) break;
        uint8_t set_hash[64];
        int bad = 0;
        for (int i = 0; i < cmn; i++)
            if (qgp_sha3_512(cm[i].pubkey, DNAC_PUBKEY_SIZE,
                             fps + (size_t)i * 64) != 0) { bad = 1; break; }
        if (bad) break;
        if (nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                        (uint32_t)cmn, set_hash) != 0)
            break;
        uint64_t appr_epoch = nodus_v2_epoch_for_height(tip);
        uint32_t quorum = dna_bft_quorum((uint32_t)cmn);

        uint8_t call[41];
        uint64_t nv = 7, eff = tip + 100000, vb = eff + 100000, sa = 1;
        call[0] = 4;                    /* DNAC_CFG_TARGET_ACTIVE_COUNT */
        for (int i = 0; i < 8; i++) call[1 + i]  = (uint8_t)(nv  >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) call[9 + i]  = (uint8_t)(eff >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) call[17 + i] = (uint8_t)(nonce >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) call[25 + i] = (uint8_t)(sa  >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) call[33 + i] = (uint8_t)(vb  >> (56 - 8 * i));

        size_t auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                          (size_t)quorum * NODUS_RT_AUTH_APPROVAL_LEN;
        auth = calloc(1, auth_len);
        if (!auth) break;

        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
        leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
        leg.hdr.ruleset_version      = sys_man.ruleset_version;
        leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
        leg.hdr.call_len             = sizeof(call);
        leg.hdr.auth_len             = (uint32_t)auth_len;
        leg.hdr.res_max_effects      = 4;
        leg.hdr.res_max_effect_bytes = 4096;
        leg.call_data = call;
        leg.auth_data = auth;

        dna_env_in_t env_in;
        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height       = 0;
        env_in.fee_amount          = 0;
        env_in.res_max_total_units = 200000;
        env_in.leg_count           = 1;
        env_in.legs                = &leg;

        size_t env_len = 0;
        if (dna_env_encoded_size(&leg, 1, &env_len) != 0) break;
        env_bytes = malloc(env_len);
        if (!env_bytes) break;

        dna_env_leg_ctx_t lctx;
        lctx.domain_id       = DNA_DOMAIN_SYSTEM;
        lctx.ruleset_version = sys_man.ruleset_version;
        memcpy(lctx.ruleset_hash, sys_man.ruleset_hash, 64);

        size_t used = 0;
        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len) break;
        if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK) break;

        uint8_t *p = auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl,
                           pf->auth_digest[0], 64, g_ks[0].sk) != 0)
            break;
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(quorum >> 8);
        p[1] = (uint8_t)quorum;
        p += 2;

        uint32_t emitted = 0;
        for (int s = 0; s < cmn && emitted < quorum; s++) {
            int ki = -1;
            for (int k = 0; k < N_KEYS; k++)
                if (memcmp(cm[s].pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE) == 0) {
                    ki = k;
                    break;
                }
            if (ki < 0) { bad = 1; break; }
            uint8_t adg[64];
            if (nodus_rt_cc_approval_digest(pf->auth_digest[0], set_hash,
                                            appr_epoch, (uint16_t)s,
                                            adg) != 0) { bad = 1; break; }
            p[0] = (uint8_t)((uint16_t)s >> 8);
            p[1] = (uint8_t)s;
            sl = 0;
            if (qgp_dsa87_sign(p + 2, &sl, adg, 64, g_ks[ki].sk) != 0) {
                bad = 1;
                break;
            }
            p += NODUS_RT_AUTH_APPROVAL_LEN;
            emitted++;
        }
        if (bad || emitted != quorum) break;

        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len) break;
        if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, &lctx,
                              1, pf) != DNA_ENV_PF_OK) break;

        out->bytes = env_bytes;
        out->len   = env_len;
        memcpy(out->wire_id, pf->wire_id, 64);
        memcpy(out->intent_id, pf->intent_id, 64);
        env_bytes = NULL;
        rc = 0;
    } while (0);

    free(env_bytes);
    free(auth);
    free(pf);
    free(fps);
    free(cm);
    return rc;
}

static void mkenventry(nodus_witness_mempool_entry_t *e, const test_env_t *env) {
    memset(e, 0, sizeof(*e));
    memcpy(e->tx_hash, env->wire_id, 64);
    e->tx_type = NODUS_W_TX_V2_ENVELOPE;
    e->tx_data = env->bytes;
    e->tx_len  = (uint32_t)env->len;
}

/* one valid DNA.CERT.v2 signature by keyset `k` over `block_id` */
static int sign_cert(const keyset_t *k, const uint8_t block_id[64],
                     uint64_t height, const uint8_t chain[32],
                     const uint8_t vset_hash[64],
                     uint8_t out_sig[NODUS_SIG_BYTES]) {
    uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
    if (dna_cert_v2_preimage(block_id, k->voter, height, chain, vset_hash,
                             pre) != 0)
        return -1;
    size_t sl = 0;
    memset(out_sig, 0, NODUS_SIG_BYTES);
    return qgp_dsa87_sign(out_sig, &sl, pre, sizeof(pre), k->sk);
}

/* commit ONE block on A and attach its QC (own cert + peer certs to quorum) */
static int produce_and_certify(fixture_t *fx,
                               nodus_witness_mempool_entry_t **batch,
                               int n, uint64_t height,
                               uint8_t out_id[64], uint8_t out_root[64]) {
    nodus_v2_produce_out_t o;
    if (nodus_witness_v2_produce_commit(fx->w, batch, n, height, 42,
                                        fx->w->my_id, NULL, &o) != 0)
        return -1;
    if (!o.have_cert) return -1;
    memcpy(out_id, o.block_id, 64);
    memcpy(out_root, o.global_root, 64);

    uint8_t vsh[64];
    memcpy(vsh, fx->w->v2_certpool.vset_hash, 64);
    uint8_t sig[NODUS_SIG_BYTES];
    for (int k = 1; k <= 6 && !fx->w->v2_certpool.qc_attached; k++) {
        if (sign_cert(&g_ks[k], o.block_id, height, fx->chain_id, vsh,
                      sig) != 0)
            return -1;
        nodus_witness_v2_cert_note(fx->w, height, g_ks[k].voter, o.block_id,
                                   sig);
    }
    return fx->w->v2_certpool.qc_attached ? 0 : -1;
}

/* apply ONE frame through the ONE engine adapter (sync range of length 1) */
static nodus_v2_result_t feed_one(nodus_witness_t *w, const uint8_t *frame,
                                  size_t len) {
    const uint8_t *frames[1] = { frame };
    const size_t   lens[1]   = { len };
    nodus_v2_sync_range_result_t rr;
    (void)nodus_witness_v2_sync_apply_range(w, NULL, frames, lens, 1, &rr);
    return rr.stop_reason;
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    CHECK(make_keys() == 0, "committee keygen");
    CHECK(keys_init() == 0, "distribution leaves");

    fixture_t A, B, B2;
    CHECK(fx_open(&A, "a") == 0, "fixture A open"); OK();
    CHECK(fx_open(&B, "b") == 0, "fixture B open"); OK();
    CHECK(fx_open(&B2, "c") == 0, "fixture B2 open"); OK();
    CHECK(memcmp(A.genesis_id, B.genesis_id, 64) == 0 &&
          memcmp(A.genesis_id, B2.genesis_id, 64) == 0,
          "twin fixtures derive the SAME pinned genesis"); OK();

    /* the three claims, encoded once, byte-identical for every fixture */
    dna_claim_t c0, c1, c2;
    CHECK(make_claim(&c0, 0, A.chain_id, A.manifest_hash) == 0, "claim0");
    CHECK(make_claim(&c1, 1, A.chain_id, A.manifest_hash) == 0, "claim1");
    CHECK(make_claim(&c2, 2, A.chain_id, A.manifest_hash) == 0, "claim2");
    uint8_t *c0b = NULL, *c1b = NULL, *c2b = NULL;
    size_t c0n = 0, c1n = 0, c2n = 0;
    uint8_t c0h[64], c1h[64], c2h[64];
    CHECK(encode_claim(&c0, &c0b, &c0n, c0h) == 0, "encode c0");
    CHECK(encode_claim(&c1, &c1b, &c1n, c1h) == 0, "encode c1");
    CHECK(encode_claim(&c2, &c2b, &c2n, c2h) == 0, "encode c2");
    uint8_t c0nul[64], c0oid[64], c1nul[64], c1oid[64], c2nul[64], c2oid[64];
    CHECK(claim_ids(&c0, c0nul, c0oid) == 0, "c0 ids");
    CHECK(claim_ids(&c1, c1nul, c1oid) == 0, "c1 ids");
    CHECK(claim_ids(&c2, c2nul, c2oid) == 0, "c2 ids");
    OK();

    /* ── A produces: h1 = [env, c0, c1] (claim block), h2 = [env] ─────── */
    uint8_t blk1_id[64], blk1_root[64], blk2_id[64], blk2_root[64];
    {
        test_env_t e1;
        CHECK(build_cc_env(&A, 101, &e1) == 0, "env for h1");
        nodus_witness_mempool_entry_t ev, cl0, cl1, *tmp;
        mkenventry(&ev, &e1);
        tmp = mkclaimentry(c0b, c0n, c0h, c0nul);
        CHECK(tmp, "cl0"); cl0 = *tmp; free(tmp);
        tmp = mkclaimentry(c1b, c1n, c1h, c1nul);
        CHECK(tmp, "cl1"); cl1 = *tmp; free(tmp);
        nodus_witness_mempool_entry_t *batch[3] = { &ev, &cl0, &cl1 };
        CHECK(produce_and_certify(&A, batch, 3, 1, blk1_id, blk1_root) == 0,
              "A commits + certifies the claim block h1"); OK();
        free(ev.tx_data); free(cl0.tx_data); free(cl1.tx_data);
    }
    {
        test_env_t e2;
        CHECK(build_cc_env(&A, 202, &e2) == 0, "env for h2");
        nodus_witness_mempool_entry_t ev;
        mkenventry(&ev, &e2);
        nodus_witness_mempool_entry_t *batch[1] = { &ev };
        CHECK(produce_and_certify(&A, batch, 1, 2, blk2_id, blk2_root) == 0,
              "A commits + certifies the claim-free block h2"); OK();
        free(ev.tx_data);
    }
    CHECK(q1(A.w, "SELECT n_claims FROM v2_claim_counts WHERE global_height=1")
              == 2, "A h1 count row = 2"); OK();
    CHECK(q1(A.w, "SELECT n_claims FROM v2_claim_counts WHERE global_height=2")
              == 0, "A h2 count row = 0"); OK();

    /* ── serve: 0x02 container for h1, bare v1 for h2, rc 1 for genesis ─ */
    uint8_t *f1 = NULL, *f2 = NULL, *fg = NULL;
    size_t l1 = 0, l2 = 0, lg = 0;
    CHECK(nodus_witness_v2_sync_serve_block(A.w, 1, &f1, &l1) == 0 && f1 && l1,
          "serve h1"); OK();
    CHECK(f1[0] == NODUS_V2_BLKFRAME_TAG,
          "h1 served as a 0x02 blkframe container"); OK();
    CHECK(nodus_witness_v2_sync_serve_block(A.w, 2, &f2, &l2) == 0 && f2 && l2,
          "serve h2"); OK();
    CHECK(f2[0] == (uint8_t)DNA_BLKW_VERSION,
          "h2 served as a BARE v1 blockmsg (byte 0 == 0x01)"); OK();
    CHECK(nodus_witness_v2_sync_serve_block(A.w, 0, &fg, &lg) == 1 && !fg,
          "genesis (h=0) serves rc 1 as today"); OK();

    /* the container's inner blkmsg (for building adversarial variants) */
    uint32_t bml = rd32(f1 + 1);
    const uint8_t *bm = f1 + 5;
    CHECK((size_t)bml + 5u <= l1, "inner blkmsg length in range"); OK();

    /* ── adversarial: B at genesis rejects tampered h1, DB byte-unchanged ── */
    uint8_t dg0[64], dg1[64];
    CHECK(v2x_db_digest(B.w, dg0) == 0, "B digest baseline");

    {   /* a claim omitted: {c0} only */
        const uint8_t *cl[1] = { c0b };
        const size_t   ln[1] = { c0n };
        uint8_t *bad = NULL; size_t bl = 0;
        CHECK(nodus_witness_v2_blkframe_encode(bm, bml, cl, ln, 1, &bad,
                                               &bl) == 0, "encode omitted");
        CHECK(feed_one(B.w, bad, bl) != NODUS_V2_ACCEPTED,
              "B rejects a claim-omitted container"); OK();
        CHECK(nodus_witness_v2_tip_height(B.w, &(uint64_t){0}) == 0, "tip ok");
        free(bad);
    }
    {   /* an extra valid claim: {c0, c1, c2} */
        const uint8_t *cl[3] = { c0b, c1b, c2b };
        const size_t   ln[3] = { c0n, c1n, c2n };
        uint8_t *bad = NULL; size_t bl = 0;
        CHECK(nodus_witness_v2_blkframe_encode(bm, bml, cl, ln, 3, &bad,
                                               &bl) == 0, "encode extra");
        CHECK(feed_one(B.w, bad, bl) != NODUS_V2_ACCEPTED,
              "B rejects an extra-valid-claim container"); OK();
        free(bad);
    }
    {   /* truncated: drop the last byte */
        uint8_t *trunc = malloc(l1 - 1);
        CHECK(trunc, "alloc trunc");
        memcpy(trunc, f1, l1 - 1);
        CHECK(feed_one(B.w, trunc, l1 - 1) != NODUS_V2_ACCEPTED,
              "B rejects a truncated container"); OK();
        free(trunc);
    }
    {   /* trailing byte */
        uint8_t *tr = malloc(l1 + 1);
        CHECK(tr, "alloc trailing");
        memcpy(tr, f1, l1);
        tr[l1] = 0x00;
        CHECK(feed_one(B.w, tr, l1 + 1) != NODUS_V2_ACCEPTED,
              "B rejects a trailing-byte container"); OK();
        free(tr);
    }
    CHECK(v2x_db_digest(B.w, dg1) == 0, "B digest after rejects");
    CHECK(memcmp(dg0, dg1, 64) == 0,
          "every rejected container left B's DB byte-unchanged"); OK();
    CHECK(nodus_witness_v2_tip_height(B.w, &(uint64_t){0}) == 0 &&
          q1(B.w, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks") == 0,
          "B still at genesis after all rejects"); OK();

    /* ── happy path: feed h1 + h2 as a range, B reaches A's head ──────── */
    {
        const uint8_t *frames[2] = { f1, f2 };
        const size_t   lens[2]   = { l1, l2 };
        nodus_v2_sync_range_result_t rr;
        CHECK(nodus_witness_v2_sync_apply_range(B.w, NULL, frames, lens, 2,
                                                &rr) == 0,
              "B applies the honest 2-block range"); OK();
        CHECK(rr.applied == 2, "both blocks applied"); OK();
    }
    /* B is at A's head with byte-identical identity */
    {
        uint64_t tb = 0;
        CHECK(nodus_witness_v2_tip_height(B.w, &tb) == 0 && tb == 2,
              "B reached head h2"); OK();
        for (uint64_t h = 1; h <= 2; h++) {
            sqlite3_stmt *sa = NULL, *sb = NULL;
            const char *sql = "SELECT block_id, global_root, header "
                              "FROM v2_blocks WHERE global_height = ?1";
            CHECK(sqlite3_prepare_v2(A.w->db, sql, -1, &sa, NULL) == SQLITE_OK &&
                  sqlite3_prepare_v2(B.w->db, sql, -1, &sb, NULL) == SQLITE_OK,
                  "id q");
            sqlite3_bind_int64(sa, 1, (sqlite3_int64)h);
            sqlite3_bind_int64(sb, 1, (sqlite3_int64)h);
            CHECK(sqlite3_step(sa) == SQLITE_ROW &&
                  sqlite3_step(sb) == SQLITE_ROW, "rows exist");
            CHECK(sqlite3_column_bytes(sa, 0) == 64 &&
                  sqlite3_column_bytes(sb, 0) == 64 &&
                  memcmp(sqlite3_column_blob(sa, 0),
                         sqlite3_column_blob(sb, 0), 64) == 0,
                  "A/B BlockID identical"); OK();
            CHECK(memcmp(sqlite3_column_blob(sa, 1),
                         sqlite3_column_blob(sb, 1), 64) == 0,
                  "A/B global root identical"); OK();
            CHECK(sqlite3_column_bytes(sa, 2) == DNA_BH2_ENC_SIZE &&
                  sqlite3_column_bytes(sb, 2) == DNA_BH2_ENC_SIZE &&
                  memcmp(sqlite3_column_blob(sa, 2),
                         sqlite3_column_blob(sb, 2), DNA_BH2_ENC_SIZE) == 0,
                  "A/B header bytes identical"); OK();
            sqlite3_finalize(sa);
            sqlite3_finalize(sb);
        }
    }
    /* B's claim availability rows equal A's, index for index */
    {
        CHECK(q1(B.w, "SELECT n_claims FROM v2_claim_counts "
                      "WHERE global_height=1") == 2, "B h1 count = 2"); OK();
        CHECK(q1(B.w, "SELECT n_claims FROM v2_claim_counts "
                      "WHERE global_height=2") == 0, "B h2 count = 0"); OK();
        for (int idx = 0; idx <= 1; idx++) {
            sqlite3_stmt *sa = NULL, *sb = NULL;
            const char *sql = "SELECT claim_hash, claim FROM v2_claim_bytes "
                              "WHERE global_height=1 AND claim_index=?1";
            CHECK(sqlite3_prepare_v2(A.w->db, sql, -1, &sa, NULL) == SQLITE_OK &&
                  sqlite3_prepare_v2(B.w->db, sql, -1, &sb, NULL) == SQLITE_OK,
                  "claim q");
            sqlite3_bind_int64(sa, 1, idx);
            sqlite3_bind_int64(sb, 1, idx);
            CHECK(sqlite3_step(sa) == SQLITE_ROW &&
                  sqlite3_step(sb) == SQLITE_ROW, "claim rows exist");
            int la = sqlite3_column_bytes(sa, 1);
            int lb = sqlite3_column_bytes(sb, 1);
            CHECK(la == lb && la > 0 &&
                  memcmp(sqlite3_column_blob(sa, 1),
                         sqlite3_column_blob(sb, 1), (size_t)la) == 0,
                  "A/B claim bytes identical at index"); OK();
            CHECK(memcmp(sqlite3_column_blob(sa, 0),
                         sqlite3_column_blob(sb, 0), 64) == 0,
                  "A/B claim hash identical at index"); OK();
            sqlite3_finalize(sa);
            sqlite3_finalize(sb);
        }
        /* index 0 IS c0, index 1 IS c1 — the produced (batch) order */
        CHECK(q1(B.w, "SELECT COUNT(*) FROM v2_claim_bytes "
                      "WHERE global_height=1") == 2, "B stored 2 claims"); OK();
    }

    /* ── reorder is NOT a divergence: B2 accepts {c1,c0} with the SAME
     * BlockID, storing a DIFFERENT availability index order. ──────────── */
    {
        const uint8_t *cl[2] = { c1b, c0b };   /* swapped */
        const size_t   ln[2] = { c1n, c0n };
        uint8_t *swap = NULL; size_t sl = 0;
        CHECK(nodus_witness_v2_blkframe_encode(bm, bml, cl, ln, 2, &swap,
                                               &sl) == 0, "encode reorder");
        nodus_v2_ingress_outcome_t oc;
        int rc = nodus_witness_v2_ingress_block(B2.w, NULL, swap, sl, &oc);
        CHECK(nodus_v2_result_is_accepted(rc),
              "B2 ACCEPTS a reordered-claim container (order not bound)"); OK();
        uint64_t t2 = 0;
        CHECK(nodus_witness_v2_tip_height(B2.w, &t2) == 0 && t2 == 1,
              "B2 committed h1"); OK();
        /* identical consensus identity */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(B2.w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height=1",
                -1, &st, NULL) == SQLITE_OK, "b2 id q");
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == 64 &&
                  memcmp(sqlite3_column_blob(st, 0), blk1_id, 64) == 0,
                  "B2 BlockID EQUALS A's despite reorder"); OK();
            sqlite3_finalize(st);
        }
        /* but the availability index order differs: index 0 is c1 here */
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(B2.w->db,
                "SELECT claim_hash FROM v2_claim_bytes "
                "WHERE global_height=1 AND claim_index=0",
                -1, &st, NULL) == SQLITE_OK, "b2 claim q");
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  memcmp(sqlite3_column_blob(st, 0), c1h, 64) == 0,
                  "B2 stored c1 at index 0 (received order, != A's)"); OK();
            sqlite3_finalize(st);
        }
        free(swap);
    }

    /* ── pre-S12 height: count row absent ⇒ serve rc 1 UNAVAILABLE ────── */
    {
        CHECK(run_sql(A.w->db,
              "DELETE FROM v2_claim_counts WHERE global_height=2") == 0,
              "drop A's h2 count row");
        uint8_t *fx2 = NULL; size_t lx = 0;
        CHECK(nodus_witness_v2_sync_serve_block(A.w, 2, &fx2, &lx) == 1 && !fx2,
              "h2 with no count row serves rc 1 (pre-S12, fail-closed)"); OK();
    }

    free(f1); free(f2); free(c0b); free(c1b); free(c2b);
    fx_close(&A); fx_close(&B); fx_close(&B2);

    printf("test_v2_sync_claims: %d checks passed\n", g_checks);
    return 0;
}
