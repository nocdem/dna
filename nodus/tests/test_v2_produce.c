/**
 * @file nodus/tests/test_v2_produce.c
 * @brief Ledger V2 O15D — successor block production through the REAL
 *        production functions (nodus_witness_v2_produce_* + the verify
 *        divert), never a parallel test-only builder.
 *
 * Fixture: the test_v2_finalize shape — 7 REAL ML-DSA-87 validators
 * seeded as the committed authority snapshot, a committed V2 genesis,
 * plus (new here) a minimal server identity so the produce seam can sign
 * its own DNA.CERT.v2 certificate, and the successor role flags the
 * post-open gate would derive on a real successor. The seam-derivation
 * and role-probe wiring themselves are covered by the O15C seam tests
 * and the seven-validator rehearsal; THIS suite proves the production
 * handoff semantics.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"     /* is_leader — §18's precondition */
#include "witness/nodus_witness_v2_env.h"  /* the seam + refusal KIND        */
#include "transport/nodus_tcp.h"           /* nodus_time_now — the reaper gate */
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_qc.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
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
#include "dnac/vset_wire.h"

#include "../tests/v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── deterministic keys (the test_v2_finalize shape) ────────────────── */

#define N_KEYS 7

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];
static keyset_t g_outsider;            /* NOT a committee member */

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
    uint8_t oseed[32];
    memset(oseed, 0xA7, sizeof(oseed));
    if (qgp_dsa87_keypair_derand(g_outsider.pk, g_outsider.sk, oseed) != 0)
        return -1;
    uint8_t ofull[64];
    if (qgp_sha3_512(g_outsider.pk, QGP_DSA87_PUBLICKEYBYTES, ofull) != 0)
        return -1;
    memcpy(g_outsider.voter, ofull, 32);
    return 0;
}

/* ── fixture ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;              /* identity carrier for produce */
    char             dir[128];
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint8_t          genesis_id[64];
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

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w   = calloc(1, sizeof(*fx->w));   /* multi-MB: never on the stack */
    fx->srv = calloc(1, sizeof(*fx->srv));
    if (!fx->w || !fx->srv) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_prod_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) return -1;
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x5D, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    if (run_sql(fx->w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
            " total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0)
        return -1;

    if (seed_validators(fx) != 0) return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;

    uint8_t vset[64];
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, fx->genesis_id, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;

    /* The successor role + identity the post-open gate derives on a real
     * successor (rehearsal-covered wiring), and the server identity the
     * produce seam signs its certificate with: validator g_ks[0]. */
    memcpy(fx->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(fx->srv->identity.sk.bytes, g_ks[0].sk,
           QGP_DSA87_SECRETKEYBYTES);
    memcpy(fx->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    fx->w->server = fx->srv;
    memcpy(fx->w->my_id, g_ks[0].voter, 32);
    fx->w->v2_successor = true;
    memcpy(fx->w->v2_chain32, fx->chain_id, 32);
    fx->w->v2_ingress_armed = true;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    free(fx->srv);
    fx->srv = NULL;
    if (fx->dir[0]) rmrf(fx->dir);
}

/* ── the smallest successor-valid envelope (single-leg CC, kind 2) ──── */

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
} test_env_t;

/* The shape §1-§11 use: the fixture's default declared unit ceiling and
 * the exact 41-byte CHAIN_CONFIG call payload. NODUS_V2_GLOBAL_UNIT_BUDGET
 * / CC_UNITS is how many of these fit ONE block — see §13. */
#define CC_UNITS     200000u
#define CC_CALL_LEN  41u

/*
 * How many fixture envelopes fit ONE block's unit budget — DERIVED, not
 * guessed, from two values read in this tree:
 *   - NODUS_V2_GLOBAL_UNIT_BUDGET (nodus_witness_v2_apply.h) seeds
 *     budget.global_remaining for every block;
 *   - dna_meter_plan_build sets total_ceiling = res_max_total_units
 *     verbatim, and dna_meter_reserve debits exactly total_ceiling from
 *     the global budget (shared/dnac/res_meter.c) — so each of these
 *     envelopes costs the block exactly CC_UNITS.
 * => CC_FIT = 5, and envelope index 5 is the first refused, with
 *    DNA_METER_ERR_GLOBAL_BUDGET. That is precisely the signature the
 *    20-node rehearsal reported: "reservation rejected at batch index 5
 *    (meter status 7)".
 *
 * The per-domain budget does NOT bind first: SYSTEM's committed manifest
 * carries quota_verify_cost = 0 (nodus_witness_domreg.c), which the
 * engine maps to the same 1,000,000, while one envelope's static_units is
 * a few tens of thousands of weight-1 units. §14 ASSERTS the meter status
 * rather than trusting that reasoning.
 */
#define CC_FIT ((int)(NODUS_V2_GLOBAL_UNIT_BUDGET / CC_UNITS))

/* Build a valid single-leg SYSTEM CHAIN_CONFIG envelope over the
 * fixture's committed state, signed by quorum committee approvals.
 * `nonce` varies the intent; `chain` overrides the bound chain id
 * (NULL = the fixture chain).
 *
 * `units` is the envelope's DECLARED res_max_total_units, which
 * dna_meter_plan_build takes verbatim as the plan's total_ceiling
 * (res_meter.c) and dna_meter_reserve then debits from the block's global
 * budget — so it is the single knob that decides how many of these fit
 * one block. `call_len` (>= CC_CALL_LEN) zero-pads the call payload,
 * which grows the envelope's WIRE SIZE without changing what the seam
 * derives; the preflight seam never interprets call bytes. Both exist so
 * the capacity sections can drive the two independent bounds — the unit
 * budget and the absolute block-byte bound — on purpose. */
static int build_cc_env_ex(fixture_t *fx, uint64_t nonce,
                           const uint8_t *chain, uint64_t units,
                           size_t call_len, test_env_t *out) {
    memset(out, 0, sizeof(*out));
    if (call_len < CC_CALL_LEN) return -1;
    const uint8_t *chain32 = chain ? chain : fx->chain_id;

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
    uint8_t *call = calloc(1, call_len);      /* zero-padded past byte 41 */
    do {
        if (!fps || !pf || !call) break;
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
        leg.hdr.call_len             = (uint32_t)call_len;
        leg.hdr.auth_len             = (uint32_t)auth_len;
        leg.hdr.res_max_effects      = 4;
        leg.hdr.res_max_effect_bytes = 4096;
        leg.call_data = call;
        leg.auth_data = auth;

        dna_env_in_t env_in;
        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height       = 0;
        env_in.fee_amount          = 0;
        env_in.res_max_total_units = units;
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

        /* submitter = g_ks[0] over the leg auth digest */
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

        /* first `quorum` seats, ascending; sign each with its seat key */
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
    free(call);
    free(auth);
    free(pf);
    free(fps);
    free(cm);
    return rc;
}

static int build_cc_env(fixture_t *fx, uint64_t nonce,
                        const uint8_t *chain, test_env_t *out) {
    return build_cc_env_ex(fx, nonce, chain, CC_UNITS, CC_CALL_LEN, out);
}

static void mkentry(nodus_witness_mempool_entry_t *e, const test_env_t *env) {
    memset(e, 0, sizeof(*e));
    memcpy(e->tx_hash, env->wire_id, 64);
    e->tx_type = NODUS_W_TX_V2_ENVELOPE;
    e->tx_data = env->bytes;
    e->tx_len  = (uint32_t)env->len;
}

/* A HEAP entry owning a COPY of the envelope bytes — mandatory for every
 * section that lets the shaping path dispose of entries:
 * nodus_witness_mempool_entry_free() frees both entry->tx_data and the
 * entry itself, so a stack entry or a borrowed tx_data pointer is a crash
 * or a double free the moment an entry is dropped or requeued. */
static nodus_witness_mempool_entry_t *mkentry_heap(const test_env_t *env) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->tx_data = malloc(env->len);
    if (!e->tx_data) { free(e); return NULL; }
    memcpy(e->tx_data, env->bytes, env->len);
    memcpy(e->tx_hash, env->wire_id, 64);
    e->tx_type = NODUS_W_TX_V2_ENVELOPE;
    e->tx_len  = (uint32_t)env->len;
    return e;
}

/* Is `wire_id` sitting in the mempool right now? */
static int pool_holds(nodus_witness_t *w, const uint8_t wire_id[64]) {
    for (int i = 0; i < w->mempool.count; i++)
        if (w->mempool.entries[i] &&
            memcmp(w->mempool.entries[i]->tx_hash, wire_id, 64) == 0)
            return 1;
    return 0;
}

/* ── production internals under test (the apply_tx_to_state precedent:
 *    non-static, no public header, driven directly by the suite) ─────── */

int nodus_witness_bft_shape_successor_batch(
        nodus_witness_t *w, nodus_witness_mempool_entry_t **batch, int count);
int nodus_witness_mempool_reap_epoch(nodus_witness_t *w);

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

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    /* O15J Faz 2 — this file pins that an UNTOUCHED domain stays at
     * height 0 across a produced block. A mint touches CORE and SYSTEM on
     * every block, so that property needs a quiet chain. Emission is
     * covered by test_v2_econ. */
    v2x_inflation_off = 1;

    CHECK(make_keys() == 0, "keygen");

    fixture_t A, B;
    CHECK(fx_open(&A, "a") == 0, "fixture A open"); OK();
    CHECK(fx_open(&B, "b") == 0, "fixture B open"); OK();
    CHECK(memcmp(A.genesis_id, B.genesis_id, 64) == 0,
          "fixtures derive the SAME genesis identity"); OK();

    /* §0 — height accessor: a successor handle reports the V2 tip. */
    CHECK(nodus_witness_block_height(A.w) == 0,
          "successor height accessor reads v2_blocks (genesis only)"); OK();

    test_env_t e1, e_other_chain;
    CHECK(build_cc_env(&A, 1, NULL, &e1) == 0, "build envelope"); OK();
    {
        uint8_t other[32];
        memset(other, 0xEE, sizeof(other));
        CHECK(build_cc_env(&A, 2, other, &e_other_chain) == 0,
              "build cross-chain envelope"); OK();
    }

    /* §1 — the verify divert: the ONE successor admission lane. */
    {
        char rr[256];
        /* legacy wire bytes: version byte 2, no family marker */
        uint8_t legacy[128];
        memset(legacy, 0, sizeof(legacy));
        legacy[0] = 2; legacy[1] = 1;
        uint8_t fakehash[64];
        memset(fakehash, 0x11, sizeof(fakehash));
        CHECK(nodus_witness_verify_transaction(A.w, legacy, sizeof(legacy),
                  fakehash, 1, NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) != 0,
              "legacy wire refused on successor"); OK();
        /* valid envelope, wrong submitted hash */
        CHECK(nodus_witness_verify_transaction(A.w, e1.bytes,
                  (uint32_t)e1.len, fakehash, NODUS_W_TX_V2_ENVELOPE,
                  NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) != 0,
              "hash != wire_id refused"); OK();
        /* valid envelope, correct hash */
        CHECK(nodus_witness_verify_transaction(A.w, e1.bytes,
                  (uint32_t)e1.len, e1.wire_id, NODUS_W_TX_V2_ENVELOPE,
                  NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) == 0,
              "valid envelope admitted"); OK();
        /* cross-chain envelope refused (chain binding) */
        CHECK(nodus_witness_verify_transaction(A.w, e_other_chain.bytes,
                  (uint32_t)e_other_chain.len, e_other_chain.wire_id,
                  NODUS_W_TX_V2_ENVELOPE, NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) != 0,
              "cross-chain envelope refused"); OK();
        /* unarmed node refuses everything */
        A.w->v2_ingress_armed = false;
        CHECK(nodus_witness_verify_transaction(A.w, e1.bytes,
                  (uint32_t)e1.len, e1.wire_id, NODUS_W_TX_V2_ENVELOPE,
                  NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) != 0,
              "unarmed successor refuses"); OK();
        A.w->v2_ingress_armed = true;
    }

    /* §2 — batch check: duplicate intent in one batch rejects. */
    {
        nodus_witness_mempool_entry_t x, y;
        nodus_witness_mempool_entry_t *b2[2] = { &x, &y };
        mkentry(&x, &e1);
        mkentry(&y, &e1);            /* same wire bytes = same intent */
        int fi = -1;
        CHECK(nodus_witness_v2_produce_batch_check(A.w, b2, 2, &fi) == -1,
              "duplicate intent rejected in batch"); OK();
        CHECK(fi == 1, "offender is the second entry"); OK();
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        CHECK(nodus_witness_v2_produce_batch_check(A.w, b1, 1, &fi) == 0,
              "single valid entry passes the seam"); OK();
    }

    /* §3 — produce refuses on a non-successor handle. */
    {
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        A.w->v2_successor = false;
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 1, 42,
                  A.w->my_id, NULL, &o) == -2,
              "non-successor handle refused"); OK();
        A.w->v2_successor = true;
    }

    /* §4 — FIRST successor block: leader mode, engine-owned identity. */
    uint8_t blk1_id[64], blk1_root[64], blk1_vsh[64];
    {
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 1, 42,
                  A.w->my_id, NULL, &o) == 0,
              "first successor block commits"); OK();
        CHECK(o.have_cert == 1, "own certificate signed"); OK();
        memcpy(blk1_id, o.block_id, 64);
        memcpy(blk1_root, o.global_root, 64);
        memcpy(blk1_vsh, A.w->v2_certpool.vset_hash, 64);

        uint64_t tip = 0;
        CHECK(nodus_witness_v2_tip_height(A.w, &tip) == 0 && tip == 1,
              "tip advanced to 1"); OK();
        CHECK(nodus_witness_block_height(A.w) == 1,
              "height accessor tracks the successor tip"); OK();
        CHECK(x.committed_block_height == 1 && x.committed_tx_index == 0,
              "entry receipt fields stamped"); OK();

        /* §4a — genesis is the ONLY permitted parent of block 1. */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT prev_block_id, header FROM v2_blocks "
                  "WHERE global_height = 1", -1, &st, NULL) == SQLITE_OK,
              "block row query");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "block 1 row exists");
        CHECK(sqlite3_column_bytes(st, 0) == 64 &&
              memcmp(sqlite3_column_blob(st, 0), A.genesis_id, 64) == 0,
              "block 1 parent IS the successor genesis"); OK();
        dna_block_header_v2_t hdr;
        CHECK(sqlite3_column_bytes(st, 1) == DNA_BH2_ENC_SIZE &&
              dna_bh2_decode(sqlite3_column_blob(st, 1), DNA_BH2_ENC_SIZE,
                             &hdr) == 0,
              "stored header decodes");
        CHECK(memcmp(hdr.prev_block_id, A.genesis_id, 64) == 0 &&
              hdr.block_height == 1 && hdr.epoch == 0,
              "header parent/height/epoch"); OK();
        sqlite3_finalize(st);

        /* §4b — committed transaction result: the chain_config row. */
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT COUNT(*) FROM chain_config_history "
                  "WHERE param_id = 4", -1, &st, NULL) == SQLITE_OK, "cc q");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int64(st, 0) == 1,
              "CHAIN_CONFIG history row committed"); OK();
        sqlite3_finalize(st);

        /* §4c — untouched domain: CORE's head did not advance. */
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT domain_height FROM v2_domain_heads "
                  "WHERE domain_id = ?1", -1, &st, NULL) == SQLITE_OK,
              "head q");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_CORE);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int64(st, 0) == 0,
              "untouched CORE domain_height stays 0"); OK();
        sqlite3_finalize(st);
    }

    /* §5 — replay through the production path: the engine's leader mode
     * deliberately has NO idempotent fast path (apply.c:1167-1173 — it
     * is unlocked only by an expect_block_id assertion, which produce
     * never supplies; the round machinery's already-committed guards sit
     * in front). A re-produce of the committed height is a VERDICT and
     * leaves the database byte-identical — no second effect, ever. */
    {
        uint8_t d_before[64], d_after[64];
        CHECK(v2x_db_digest(A.w, d_before) == 0, "digest before");
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 1, 42,
                  A.w->my_id, NULL, &o) == -1,
              "re-produce of a committed height is a verdict"); OK();
        CHECK(v2x_db_digest(A.w, d_after) == 0 &&
              memcmp(d_before, d_after, 64) == 0,
              "replay attempt left the database byte-identical"); OK();
    }

    /* §6 — height rules through the ordinary path. */
    {
        test_env_t e2;
        CHECK(build_cc_env(&A, 3, NULL, &e2) == 0, "build env 2");
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e2);
        nodus_v2_produce_out_t o;
        uint8_t d_before[64], d_after[64];
        CHECK(v2x_db_digest(A.w, d_before) == 0, "digest");
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 3, 42,
                  A.w->my_id, NULL, &o) == -2,
              "height gap is node-local (not-yet-linkable), no verdict");
        OK();
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 1, 42,
                  A.w->my_id, NULL, &o) == -1,
              "at-or-below tip with different content is a verdict"); OK();
        CHECK(v2x_db_digest(A.w, d_after) == 0 &&
              memcmp(d_before, d_after, 64) == 0,
              "failed attempts left no partial state"); OK();
        free(e2.bytes);
    }

    /* §7 — follower identity: fixture B re-executes block 1 with A's
     * claimed global root as the C3-analog assertion. */
    {
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        CHECK(nodus_witness_v2_produce_commit(B.w, b1, 1, 1, 42,
                  A.w->my_id, blk1_root, &o) == 0,
              "follower commit with expected root"); OK();
        CHECK(memcmp(o.block_id, blk1_id, 64) == 0,
              "leader and follower derive the SAME BlockID"); OK();
        CHECK(memcmp(o.global_root, blk1_root, 64) == 0,
              "leader and follower derive the SAME global root"); OK();
    }

    /* §7b — a WRONG claimed root rejects BEFORE any commit (fresh
     * fixture C at height 1 — same chain, divergent assertion). */
    {
        fixture_t C;
        CHECK(fx_open(&C, "c") == 0, "fixture C open");
        uint8_t d_before[64], d_after[64];
        CHECK(v2x_db_digest(C.w, d_before) == 0, "digest");
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        uint8_t wrong[64];
        memset(wrong, 0xAB, sizeof(wrong));
        CHECK(nodus_witness_v2_produce_commit(C.w, b1, 1, 1, 42,
                  A.w->my_id, wrong, &o) == -1,
              "divergent claimed root is a verdict"); OK();
        CHECK(v2x_db_digest(C.w, d_after) == 0 &&
              memcmp(d_before, d_after, 64) == 0,
              "rejected block left C byte-identical (atomicity)"); OK();
        fx_close(&C);
    }

    /* §8 — committed-intent replay refused at admission. */
    {
        char rr[256];
        CHECK(nodus_witness_verify_transaction(A.w, e1.bytes,
                  (uint32_t)e1.len, e1.wire_id, NODUS_W_TX_V2_ENVELOPE,
                  NULL, 0, NULL, NULL, 0,
                  NODUS_WITNESS_VERIFY_VALIDATION, rr, sizeof(rr)) != 0,
              "committed intent refused at admission"); OK();
    }

    /* §9 — QC formation: peer certs -> quorum -> verified QC attached. */
    {
        CHECK(A.w->v2_certpool.height == 1 && A.w->v2_certpool.committed,
              "pool holds the committed height"); OK();
        CHECK(A.w->v2_certpool.n >= 1, "own cert pooled"); OK();
        CHECK(!A.w->v2_certpool.qc_attached,
              "no QC below quorum"); OK();

        /* outsider cert: never counted */
        uint8_t sig[NODUS_SIG_BYTES];
        CHECK(sign_cert(&g_outsider, blk1_id, 1, A.chain_id, blk1_vsh,
                        sig) == 0, "outsider sign");
        nodus_witness_v2_cert_note(A.w, 1, g_outsider.voter, blk1_id, sig);
        /* diverged cert (wrong block id): never counted */
        uint8_t wrong_id[64];
        memset(wrong_id, 0xCD, sizeof(wrong_id));
        CHECK(sign_cert(&g_ks[1], wrong_id, 1, A.chain_id, blk1_vsh,
                        sig) == 0, "diverged sign");
        nodus_witness_v2_cert_note(A.w, 1, g_ks[1].voter, wrong_id, sig);
        CHECK(!A.w->v2_certpool.qc_attached,
              "outsider/diverged certs buy nothing"); OK();

        /* real peer certs up to quorum (5 of 7): ks[1..4] */
        for (int k = 1; k <= 4; k++) {
            CHECK(sign_cert(&g_ks[k], blk1_id, 1, A.chain_id, blk1_vsh,
                            sig) == 0, "peer sign");
            /* duplicate delivery of each cert: dedup keeps first */
            nodus_witness_v2_cert_note(A.w, 1, g_ks[k].voter, blk1_id, sig);
            nodus_witness_v2_cert_note(A.w, 1, g_ks[k].voter, blk1_id, sig);
        }
        /* ks[1] first delivered a DIVERGED cert (keep-first) — one more
         * honest voter closes the quorum. */
        CHECK(sign_cert(&g_ks[5], blk1_id, 1, A.chain_id, blk1_vsh,
                        sig) == 0, "peer sign 5");
        nodus_witness_v2_cert_note(A.w, 1, g_ks[5].voter, blk1_id, sig);
        CHECK(A.w->v2_certpool.qc_attached, "QC attached at quorum"); OK();

        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT qc FROM v2_blocks WHERE global_height = 1",
                  -1, &st, NULL) == SQLITE_OK, "qc q");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_type(st, 0) != SQLITE_NULL,
              "QC persisted on the block row"); OK();
        const void *qcb = sqlite3_column_blob(st, 0);
        int qcl = sqlite3_column_bytes(st, 0);
        dna_qc_v2_t *qc = NULL;
        CHECK(qcb && qcl > 0 &&
              dna_qc_v2_decode((const uint8_t *)qcb, (size_t)qcl,
                               &qc) == 0,
              "stored QC decodes"); OK();
        /* the ONE verifier accepts the stored bytes */
        sqlite3_stmt *hs = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT header FROM v2_blocks WHERE global_height = 1",
                  -1, &hs, NULL) == SQLITE_OK, "hdr q");
        CHECK(sqlite3_step(hs) == SQLITE_ROW, "hdr row");
        dna_block_header_v2_t hdr;
        CHECK(dna_bh2_decode(sqlite3_column_blob(hs, 0), DNA_BH2_ENC_SIZE,
                             &hdr) == 0, "hdr decode");
        CHECK(nodus_witness_v2_qc_verify(A.w, &hdr, qc) == 0,
              "stored QC verifies against committed authority"); OK();
        dna_qc_v2_free(&qc);
        sqlite3_finalize(hs);
        sqlite3_finalize(st);
    }

    /* §10 — tip survives close/reopen; production resumes on top. */
    {
        char dbfile[512];
        snprintf(dbfile, sizeof(dbfile), "%s", sqlite3_db_filename(
                     A.w->db, "main"));
        sqlite3_close(A.w->db);
        A.w->db = NULL;
        CHECK(sqlite3_open(dbfile, &A.w->db) == SQLITE_OK, "reopen"); OK();
        A.w->cached_committee_epoch_start = UINT64_MAX;
        uint64_t tip = 0;
        CHECK(nodus_witness_v2_tip_height(A.w, &tip) == 0 && tip == 1,
              "tip survives reopen"); OK();
        memset(&A.w->v2_certpool, 0, sizeof(A.w->v2_certpool));

        test_env_t e3;
        CHECK(build_cc_env(&A, 4, NULL, &e3) == 0, "build env 3");
        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e3);
        nodus_v2_produce_out_t o;
        CHECK(nodus_witness_v2_produce_commit(A.w, b1, 1, 2, 43,
                  A.w->my_id, NULL, &o) == 0,
              "production resumes from the reopened tip"); OK();
        CHECK(nodus_witness_block_height(A.w) == 2, "tip now 2"); OK();
        /* parent linkage: block 2's parent is block 1 */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db,
                  "SELECT prev_block_id FROM v2_blocks "
                  "WHERE global_height = 2", -1, &st, NULL) == SQLITE_OK,
              "b2 q");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              memcmp(sqlite3_column_blob(st, 0), blk1_id, 64) == 0,
              "block 2 parent IS block 1"); OK();
        sqlite3_finalize(st);
        free(e3.bytes);
    }

    /* §11 — remote-COMMIT race path precondition + effect (O15G).
     *
     * nodus_witness_bft_handle_commit's successor remote path calls
     * produce_commit with a NON-NULL expected_global_root (the leader's
     * claimed root, the C3-analog assertion) — the same shape §7 drives.
     * The O15G bft.c fix broadcasts the resulting rv2out cert; the
     * pre-fix code DISCARDED it (bft.c copied only global_root). This
     * section pins the two facts that fix relies on:
     *   (a) the remote-shape invocation STILL signs + SELF-NOTES a
     *       broadcastable cert over the node's OWN derived BlockID
     *       (produce.c:564 — the value handle_commit must put on the
     *       wire), and
     *   (b) once such race-path certs circulate, the committing node's
     *       QC forms — a node that reached its block via the race is not
     *       stuck at qc NULL, provided the cert reaches quorum.
     * Without the broadcast, a boundary where every joiner commits via
     * this race circulates fewer than quorum certs and the QC never
     * forms on any node (the reported N=7->20 boundary symptom). The
     * broadcast WIRING itself is exercised only by the multi-node
     * rehearsal; this proves the precondition it depends on. */
    {
        fixture_t R;
        CHECK(fx_open(&R, "r") == 0, "fixture R open"); OK();

        nodus_witness_mempool_entry_t x;
        nodus_witness_mempool_entry_t *b1[1] = { &x };
        mkentry(&x, &e1);
        nodus_v2_produce_out_t o;
        /* REMOTE shape: expected_global_root != NULL (the leader's root). */
        CHECK(nodus_witness_v2_produce_commit(R.w, b1, 1, 1, 42,
                  A.w->my_id, blk1_root, &o) == 0,
              "remote-path produce commits with the expected root"); OK();
        CHECK(o.have_cert == 1,
              "remote-path produce yields a BROADCASTABLE cert "
              "(handle_commit must not discard rv2out.have_cert)"); OK();
        CHECK(memcmp(o.block_id, blk1_id, 64) == 0,
              "the cert is over the node's OWN derived BlockID"); OK();
        uint8_t zero_sig[NODUS_SIG_BYTES];
        memset(zero_sig, 0, sizeof(zero_sig));
        CHECK(memcmp(o.cert_sig, zero_sig, NODUS_SIG_BYTES) != 0,
              "the broadcastable cert_sig is populated"); OK();

        /* (a) self-note: the node's OWN cert is already in its pool over
         * the derived id — so its OWN QC can include itself even though a
         * node never receives its own broadcast. */
        CHECK(R.w->v2_certpool.committed && R.w->v2_certpool.height == 1,
              "pool adopted the committed height"); OK();
        int self_slot = -1;
        for (uint32_t i = 0; i < R.w->v2_certpool.n; i++) {
            if (memcmp(R.w->v2_certpool.slots[i].voter_id,
                       g_ks[0].voter, 32) == 0) {
                self_slot = (int)i;
                break;
            }
        }
        CHECK(self_slot >= 0, "the node SELF-NOTED its own cert"); OK();
        CHECK(memcmp(R.w->v2_certpool.slots[self_slot].block_id,
                     blk1_id, 64) == 0,
              "the self-noted cert is over the derived BlockID"); OK();
        CHECK(memcmp(R.w->v2_certpool.slots[self_slot].sig,
                     o.cert_sig, NODUS_SIG_BYTES) == 0,
              "the self-noted sig IS the broadcast cert_sig"); OK();
        CHECK(!R.w->v2_certpool.qc_attached,
              "no QC from the self-note alone (below quorum)"); OK();

        /* (b) circulate quorum-completing peer race-path certs -> QC
         * forms (self g_ks[0] + g_ks[1..4] = 5 of 7). The committing node
         * reached its block via the REMOTE path, yet once peer certs
         * arrive it assembles + attaches the QC. */
        uint8_t sig[NODUS_SIG_BYTES];
        for (int k = 1; k <= 4; k++) {
            CHECK(sign_cert(&g_ks[k], o.block_id, 1, R.chain_id,
                            R.w->v2_certpool.vset_hash, sig) == 0,
                  "peer cert sign");
            nodus_witness_v2_cert_note(R.w, 1, g_ks[k].voter, o.block_id,
                                       sig);
        }
        CHECK(R.w->v2_certpool.qc_attached,
              "QC forms for a race-path committer once certs circulate");
        OK();
        sqlite3_stmt *qst = NULL;
        CHECK(sqlite3_prepare_v2(R.w->db,
                  "SELECT qc FROM v2_blocks WHERE global_height = 1",
                  -1, &qst, NULL) == SQLITE_OK, "qc q");
        CHECK(sqlite3_step(qst) == SQLITE_ROW &&
              sqlite3_column_type(qst, 0) != SQLITE_NULL,
              "QC persisted on the race-path committer's block row"); OK();
        sqlite3_finalize(qst);

        fx_close(&R);
    }

    /* ══ CAPACITY SEASON — §12-§18 ══════════════════════════════════════
     * These sections close the coverage hole that let the propose-time
     * check ship blind to the meter: before them, NO test in this tree
     * drove a MULTI-ENTRY successor batch. "One envelope fits" was the
     * only fact ever proven, so a full NODUS_W_MAX_BLOCK_TXS batch the
     * global unit budget cannot pay for reached the commit engine
     * unchallenged and killed the round there.
     *
     * VACUITY CHECK (done explicitly, not asserted about): §13 is the
     * anti-vacuity control — a batch that FITS must come back untouched.
     * Without it, an implementation that truncated every batch to one
     * entry would satisfy §14-§17. §14 additionally pins the truncation
     * BOUNDARY (exactly CC_FIT, not "some prefix") and the identity of
     * every entry on both sides of it, so "truncate to 1 and requeue the
     * rest" fails it too. §16 pins that the offender was FREED, not
     * requeued — the one assertion that separates entry-invalid handling
     * from truncation, and the reason a blanket "requeue everything"
     * cannot pass this suite either.
     */

    /* §12 — the refusal CLASSIFIER: one pure table, driven directly.
     *
     * FAILS IF: any row of nodus_witness_v2_env_fail_kind
     * (nodus_witness_v2_env.c) is changed. In particular, routing
     * DNA_METER_ERR_GLOBAL_BUDGET to ENTRY_INVALID — the pre-fix
     * behaviour, where a full block destroyed a valid transaction — is
     * caught by the third check here before any batch is even built. */
    {
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_OK, DNA_ENV_PF_OK,
                                             DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_NONE, "OK classifies as NONE"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_DUP_INTENT,
                                             DNA_ENV_PF_OK, DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_ENTRY_INVALID,
              "duplicate intent is an ENTRY verdict"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_METER,
                  DNA_ENV_PF_OK, DNA_METER_ERR_GLOBAL_BUDGET) ==
              NODUS_V2_BATCH_FAIL_CAPACITY_UNITS,
              "global budget exhaustion is CAPACITY, never an entry verdict");
        OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_METER,
                  DNA_ENV_PF_OK, DNA_METER_ERR_DOMAIN_BUDGET) ==
              NODUS_V2_BATCH_FAIL_CAPACITY_UNITS,
              "domain budget exhaustion is CAPACITY too"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_METER,
                  DNA_ENV_PF_OK, DNA_METER_ERR_CEILING) ==
              NODUS_V2_BATCH_FAIL_ENTRY_INVALID,
              "an over-ceiling declaration is the ENTRY's own fault"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_BLOCK_BYTES,
                  DNA_ENV_PF_OK, DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_CAPACITY_BYTES,
              "the block-byte bound is its OWN capacity kind (its "
              "fail_index names nobody)"); OK();
        /* The three FAULT rows, copied from the engine's own routing. */
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_PREFLIGHT,
                  DNA_ENV_PF_ERR_HASH, DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_FAULT,
              "ERR_HASH is a node fault, never a transaction verdict"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_PREFLIGHT,
                  DNA_ENV_PF_ERR_EXPIRED, DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_ENTRY_INVALID,
              "expiry IS a transaction verdict"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_METER,
                  DNA_ENV_PF_OK, DNA_METER_ERR_FAULT) ==
              NODUS_V2_BATCH_FAIL_FAULT,
              "a meter accounting fault is a node fault"); OK();
        CHECK(nodus_witness_v2_env_fail_kind(NODUS_V2_ENV_ERR_CHAIN,
                  DNA_ENV_PF_OK, DNA_METER_OK) ==
              NODUS_V2_BATCH_FAIL_FAULT,
              "an underivable chain id is a node fault"); OK();
    }

    /* Fixture D: a fresh successor at tip 0 for the shaping sections. */
    fixture_t D;
    CHECK(fx_open(&D, "d") == 0, "fixture D open"); OK();
    CHECK(CC_FIT >= 2 && CC_FIT < NODUS_W_MAX_BLOCK_TXS,
          "fixture arithmetic: a full batch neither fits nor is poison"); OK();

    /* NODUS_W_MAX_BLOCK_TXS distinct, individually-valid envelopes — the
     * exact shape a leader pops from a busy mempool. */
    test_env_t big[NODUS_W_MAX_BLOCK_TXS];
    for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++)
        CHECK(build_cc_env(&D, 100 + (uint64_t)i, NULL, &big[i]) == 0,
              "build capacity envelope");
    OK();

    /* §13 — ANTI-VACUITY CONTROL: a batch that FITS is proposed WHOLE.
     *
     * FAILS IF: the shaping loop truncates unconditionally, or the
     * metered seam rejects a legal in-budget batch. Without this section
     * every other capacity check below is satisfiable by "always propose
     * one entry", which is why it runs first. */
    {
        nodus_witness_mempool_entry_t *b[NODUS_W_MAX_BLOCK_TXS];
        for (int i = 0; i < CC_FIT; i++) {
            b[i] = mkentry_heap(&big[i]);
            CHECK(b[i] != NULL, "heap entry");
        }
        int fi = -1;
        nodus_v2_batch_check_result_t r;
        CHECK(nodus_witness_v2_produce_batch_check_ex(D.w, b, CC_FIT, &fi,
                                                      &r) == 0,
              "a batch that fits the unit budget passes the metered seam");
        OK();
        CHECK(r.kind == NODUS_V2_BATCH_FAIL_NONE, "no refusal kind"); OK();

        int k = nodus_witness_bft_shape_successor_batch(D.w, b, CC_FIT);
        CHECK(k == CC_FIT, "a fitting batch is shaped to ITSELF"); OK();
        CHECK(D.w->mempool.count == 0,
              "nothing was requeued: the whole batch is proposable"); OK();
        for (int i = 0; i < CC_FIT; i++) {
            CHECK(b[i] && memcmp(b[i]->tx_hash, big[i].wire_id, 64) == 0,
                  "the proposal keeps every entry, in order");
            nodus_witness_mempool_entry_free(b[i]);
        }
        OK();
    }

    /* §14 — OVER-BUDGET batch is TRUNCATED, and the tail is REQUEUED.
     *
     * The defect this whole change exists for: a full batch reserves
     * fine up to CC_FIT and then cannot pay for entry CC_FIT, which the
     * commit engine turns into a WHOLE-BLOCK rejection (BATCH COMMIT
     * FAILED + DNAC_STATUS_ERROR to every client in it).
     *
     * FAILS IF: the CAPACITY_UNITS branch in
     * nodus_witness_bft_shape_successor_batch is deleted — the batch then
     * falls into the entry-invalid path and entry CC_FIT is DESTROYED,
     * so the tail is one shorter and pool_holds(big[CC_FIT]) is false.
     * FAILS IF: `bfail > 0` is inverted — the prefix is dropped instead.
     * FAILS IF: the propose-time check is reverted to the BASE preflight
     * (nodus_witness_v2_env_preflight_batch) — no meter runs, the check
     * returns 0 for all ten, and k is NODUS_W_MAX_BLOCK_TXS. */
    {
        nodus_witness_mempool_entry_t *b[NODUS_W_MAX_BLOCK_TXS];
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) {
            b[i] = mkentry_heap(&big[i]);
            CHECK(b[i] != NULL, "heap entry");
        }

        /* The raw seam verdict first: WHICH entry, and for WHICH reason. */
        int fi = -1;
        nodus_v2_batch_check_result_t r;
        CHECK(nodus_witness_v2_produce_batch_check_ex(
                  D.w, b, NODUS_W_MAX_BLOCK_TXS, &fi, &r) == -1,
              "a full batch does NOT fit one block's unit budget"); OK();
        CHECK(r.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS,
              "and it is refused as CAPACITY, not as a bad entry"); OK();
        CHECK(r.meter_status == DNA_METER_ERR_GLOBAL_BUDGET,
              "the GLOBAL unit budget is what binds (status 7 — the "
              "rehearsal's signature), not the per-domain quota"); OK();
        CHECK(fi == CC_FIT,
              "the fit boundary is exactly CC_FIT entries"); OK();

        int k = nodus_witness_bft_shape_successor_batch(
                    D.w, b, NODUS_W_MAX_BLOCK_TXS);
        CHECK(k == CC_FIT, "the leader proposes the prefix that fits"); OK();
        CHECK(D.w->mempool.count == NODUS_W_MAX_BLOCK_TXS - CC_FIT,
              "and the tail went BACK to the mempool — nothing destroyed");
        OK();
        for (int i = 0; i < CC_FIT; i++)
            CHECK(b[i] && memcmp(b[i]->tx_hash, big[i].wire_id, 64) == 0,
                  "the proposal is the ORIGINAL prefix, in order");
        OK();
        for (int i = CC_FIT; i < NODUS_W_MAX_BLOCK_TXS; i++) {
            CHECK(b[i] == NULL, "truncated slots are cleared");
            CHECK(pool_holds(D.w, big[i].wire_id),
                  "every truncated entry is pending again, not freed");
        }
        OK();

        /* The shaped prefix is proposable as-is. */
        CHECK(nodus_witness_v2_produce_batch_check(D.w, b, k, &fi) == 0,
              "the truncated proposal passes the seam whole"); OK();
        for (int i = 0; i < k; i++)
            nodus_witness_mempool_entry_free(b[i]);
        nodus_witness_mempool_clear(&D.w->mempool);
        CHECK(D.w->mempool.count == 0, "pool drained for the next section");
    }

    /* §15 — a POISON entry (fail_index == 0) is DROPPED, and a good entry
     * behind it is still proposed.
     *
     * The envelope declares more units than a whole EMPTY block has, so
     * it can never fit any block, at any position. Requeueing it would
     * re-poison every future round; the fix is that it self-evicts in one.
     *
     * FAILS IF: the `bfail > 0` guard on the truncate branch is dropped —
     * truncating at 0 yields valid == 0, so k is 0 and the good entry
     * never gets proposed. FAILS IF the poison is requeued instead of
     * freed — mempool.count is 1, not 0. */
    {
        test_env_t poison;
        CHECK(build_cc_env_ex(&D, 200,  NULL,
                              (uint64_t)NODUS_V2_GLOBAL_UNIT_BUDGET + 1u,
                              CC_CALL_LEN, &poison) == 0,
              "build an envelope that cannot fit an EMPTY block"); OK();

        nodus_witness_mempool_entry_t *b[2];
        b[0] = mkentry_heap(&poison);
        b[1] = mkentry_heap(&big[0]);
        CHECK(b[0] && b[1], "heap entries");

        int fi = -1;
        nodus_v2_batch_check_result_t r;
        CHECK(nodus_witness_v2_produce_batch_check_ex(D.w, b, 2, &fi, &r)
                  == -1, "the poison batch is refused"); OK();
        CHECK(r.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS &&
              r.meter_status == DNA_METER_ERR_GLOBAL_BUDGET,
              "refused for CAPACITY at the very first entry"); OK();
        CHECK(fi == 0, "the offender is entry 0"); OK();

        int k = nodus_witness_bft_shape_successor_batch(D.w, b, 2);
        CHECK(k == 1, "the good entry behind the poison is still proposed");
        OK();
        CHECK(memcmp(b[0]->tx_hash, big[0].wire_id, 64) == 0,
              "and it is the GOOD one that survived"); OK();
        CHECK(D.w->mempool.count == 0,
              "the poison was FREED, not requeued — it self-evicts"); OK();

        nodus_witness_mempool_entry_free(b[0]);
        free(poison.bytes);
    }

    /* §16 — ENTRY-INVALID keeps today's behaviour: dropped, NOT requeued.
     *
     * Two copies of one envelope are one semantic transaction under two
     * wire realizations; the seam refuses the SECOND (ERR_DUP). That is a
     * verdict about bytes, not about room, so the offender is destroyed
     * exactly as before this change.
     *
     * FAILS IF: the discrimination is made blanket in either direction —
     * a "requeue everything" shaping leaves mempool.count == 1 here, and
     * a "truncate on every refusal" shaping proposes 1 entry and requeues
     * the duplicate instead of freeing it. This section is the reason the
     * change is a DISCRIMINATION and not a behaviour swap. */
    {
        nodus_witness_mempool_entry_t *b[2];
        b[0] = mkentry_heap(&big[1]);
        b[1] = mkentry_heap(&big[1]);          /* same bytes = same intent */
        CHECK(b[0] && b[1], "heap entries");

        int fi = -1;
        nodus_v2_batch_check_result_t r;
        CHECK(nodus_witness_v2_produce_batch_check_ex(D.w, b, 2, &fi, &r)
                  == -1, "duplicate intent refused"); OK();
        CHECK(r.kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID,
              "and classified as an ENTRY verdict, not capacity"); OK();
        CHECK(fi == 1, "the offender is the second copy"); OK();

        int k = nodus_witness_bft_shape_successor_batch(D.w, b, 2);
        CHECK(k == 1, "the survivor is proposed"); OK();
        CHECK(D.w->mempool.count == 0,
              "the invalid entry was FREED — an entry verdict never "
              "requeues (this is what separates it from truncation)");
        OK();
        nodus_witness_mempool_entry_free(b[0]);
    }

    /* §17 — the BLOCK-BYTE bound: drop from the TAIL, never at
     * fail_index.
     *
     * Step 4b of the reserve seam sums every accepted envelope's bytes
     * BEFORE any reservation and, on refusal, reports fail_index 0
     * regardless of which envelope crossed the bound
     * (nodus_witness_v2_env.c). Reading that 0 as "entry 0 is poison"
     * would destroy an innocent entry, so this path shrinks from the tail
     * instead — and once the batch fits by BYTES, the unit budget still
     * has to be satisfied, which truncates it further.
     *
     * FAILS IF: CAPACITY_BYTES is routed through the truncate-at-index
     * branch (fail_index 0 => valid 0 => k == 0) or through the drop
     * branch (entry 0 destroyed => the pool is short by one).
     * The precondition CHECK below is the vacuity guard: if these
     * envelopes ever stop summing past the policy's bound, the section
     * fails loudly instead of silently degenerating into §14. */
    {
        /* Each ~290 KB: a 260 KB zero-padded call plus the quorum auth
         * blob. Ten of them sum past the SYSTEM policy's
         * max_block_env_bytes = 2 * DNA_ENV_MAX_TOTAL_LEN
         * (nodus_witness_runtime.c, sys_policy_build). units is raised so
         * the declaration still covers its own static_units — an
         * over-ceiling declaration would be an ENTRY verdict (§12) and
         * would test the wrong branch. */
        const uint64_t fat_units = 400000u;
        const size_t   fat_call  = 260000u;
        test_env_t fat[NODUS_W_MAX_BLOCK_TXS];
        size_t sum = 0;
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) {
            CHECK(build_cc_env_ex(&D, 300 + (uint64_t)i, NULL, fat_units,
                                  fat_call, &fat[i]) == 0,
                  "build oversized envelope");
            sum += fat[i].len;
        }
        OK();
        CHECK(sum > (size_t)2u * (size_t)DNA_ENV_MAX_TOTAL_LEN,
              "PRECONDITION: the batch really does exceed the policy's "
              "block-byte bound (else this section proves nothing)"); OK();

        nodus_witness_mempool_entry_t *b[NODUS_W_MAX_BLOCK_TXS];
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) {
            b[i] = mkentry_heap(&fat[i]);
            CHECK(b[i] != NULL, "heap entry");
        }

        int fi = -1;
        nodus_v2_batch_check_result_t r;
        CHECK(nodus_witness_v2_produce_batch_check_ex(
                  D.w, b, NODUS_W_MAX_BLOCK_TXS, &fi, &r) == -1,
              "the oversized batch is refused"); OK();
        CHECK(r.kind == NODUS_V2_BATCH_FAIL_CAPACITY_BYTES,
              "by the BYTE bound, before any unit reservation — the "
              "order step 4b calls load-bearing"); OK();
        CHECK(fi == 0, "and it accuses entry 0, which is not an accusation");
        OK();

        int k = nodus_witness_bft_shape_successor_batch(
                    D.w, b, NODUS_W_MAX_BLOCK_TXS);
        /* Bytes force a shrink; the unit budget then decides the final
         * size, exactly as in §14 — 1,000,000 / 400,000 = 2. */
        const int fat_fit = (int)(NODUS_V2_GLOBAL_UNIT_BUDGET / fat_units);
        CHECK(k == fat_fit, "the proposal is the unit-budget prefix"); OK();
        CHECK(memcmp(b[0]->tx_hash, fat[0].wire_id, 64) == 0,
              "entry 0 was NOT treated as the offender"); OK();
        CHECK(D.w->mempool.count == NODUS_W_MAX_BLOCK_TXS - fat_fit,
              "every non-proposed entry is pending again — the byte path "
              "requeues, it does not destroy"); OK();
        for (int i = fat_fit; i < NODUS_W_MAX_BLOCK_TXS; i++)
            CHECK(pool_holds(D.w, fat[i].wire_id), "tail entry preserved");
        OK();

        for (int i = 0; i < k; i++)
            nodus_witness_mempool_entry_free(b[i]);
        nodus_witness_mempool_clear(&D.w->mempool);
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) free(fat[i].bytes);
    }

    for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) free(big[i].bytes);
    fx_close(&D);

    /* §18 — the REAPER runs WHILE LEADING (the removed role gate).
     *
     * A leader used to be excluded from nodus_witness_mempool_reap_epoch,
     * so the only remover of its stale entries was batch selection: an
     * entry had to be POPPED into a candidate batch and BURNED through
     * the seam before it could be freed. In the 164744Z rehearsal node1
     * pooled 26 entries, proposed exactly ONCE, and that single proposal
     * had to drop 13 stale claims through the seam first.
     *
     * FAILS IF: `!nodus_witness_bft_is_leader(w) &&` is restored to the
     * gate — reap_epoch then declines (-1) and the decided entry survives.
     * The is_leader precondition CHECK is what makes that true; without
     * it the section would pass against the old code. */
    {
        fixture_t E;
        CHECK(fx_open(&E, "e") == 0, "fixture E open"); OK();

        test_env_t decided, live;
        CHECK(build_cc_env(&E, 400, NULL, &decided) == 0, "build decided");
        CHECK(build_cc_env(&E, 401, NULL, &live) == 0, "build live");

        /* Commit `decided` so its intent is in v2_intent_index — the
         * exact fact nodus_witness_v2_entry_verdict reads. */
        {
            nodus_witness_mempool_entry_t x;
            nodus_witness_mempool_entry_t *b1[1] = { &x };
            mkentry(&x, &decided);
            nodus_v2_produce_out_t o;
            CHECK(nodus_witness_v2_produce_commit(E.w, b1, 1, 1, 42,
                      E.w->my_id, NULL, &o) == 0,
                  "the decided envelope is committed"); OK();
        }

        /* Make this node the leader. The committee is the 7 seeded
         * validators, and leader = (epoch + view) % 7, so some view in
         * [0, 7) elects us — deterministic, no timing involved. */
        int elected = 0;
        for (uint32_t v = 0; v < DNAC_COMMITTEE_SIZE + 8u && !elected; v++) {
            E.w->current_view = v;
            if (nodus_witness_bft_is_leader(E.w)) elected = 1;
        }
        CHECK(elected && nodus_witness_bft_is_leader(E.w),
              "PRECONDITION: this node IS the leader (without this the "
              "section cannot see the removed role gate at all)"); OK();

        nodus_witness_mempool_entry_t *ed = mkentry_heap(&decided);
        nodus_witness_mempool_entry_t *el = mkentry_heap(&live);
        CHECK(ed && el, "heap entries");
        CHECK(nodus_witness_mempool_add(&E.w->mempool, ed) == 0, "pool +1");
        CHECK(nodus_witness_mempool_add(&E.w->mempool, el) == 0, "pool +2");
        CHECK(E.w->mempool.count == 2, "two pooled entries"); OK();

        /* Open the epoch window and clear the latch — the other gates are
         * untouched by this change and must still be satisfied. */
        E.w->last_epoch = nodus_time_now();
        E.w->last_evict_epoch = E.w->last_epoch - 1;

        int reaped = nodus_witness_mempool_reap_epoch(E.w);
        CHECK(reaped == 1,
              "a LEADING node reaps its own pool (role gate removed)"); OK();
        CHECK(E.w->mempool.count == 1, "exactly one entry left"); OK();
        CHECK(E.w->mempool.entries[0] &&
              memcmp(E.w->mempool.entries[0]->tx_hash, live.wire_id, 64) == 0,
              "the LIVE entry survived; the committed one was reaped"); OK();

        /* The latch still holds: one scan per epoch, leader or not. */
        CHECK(nodus_witness_mempool_reap_epoch(E.w) == -1,
              "the last_evict_epoch latch is unchanged"); OK();

        nodus_witness_mempool_clear(&E.w->mempool);
        free(decided.bytes);
        free(live.bytes);
        fx_close(&E);
    }

    free(e1.bytes);
    free(e_other_chain.bytes);
    fx_close(&A);
    fx_close(&B);
    printf("test_v2_produce: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
