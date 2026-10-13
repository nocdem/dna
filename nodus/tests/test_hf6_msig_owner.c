/**
 * @file nodus/tests/test_hf6_msig_owner.c
 * @brief HF-6 — a multisig (auth_kind 3) OWNER for the generation-4 owner
 *        operations: the shared builder's unsigned two-leg envelope, the v2
 *        multi-leg co-sign files, the combine, and the chain's OWN auth
 *        hook + exec hooks judging the result.
 *
 * Governing records: docs/plans/decisions/2026-09-29-general-multisig.md,
 * addendum "çok bacaklı ortak imza dosyası v2" (operator 2026-10-13: v1
 * files unchanged; v2 files only for envelopes with >= 2 kind-3 legs; the
 * co-signer sees every leg decoded and re-derives every digest; one
 * signature file signs all legs or none; combine re-derives every digest
 * and runs the chain's auth check per kind-3 leg); design docs/plans/
 * 2026-10-03-hf5-validator-owner-stake-design.md rev 6 §1.3 (owner kind 1
 * / kind 3, the address equality). The chain rule under test is
 * nodus_witness_rt_native.c rtn_sys_owner_auth (kind 3: one descriptor,
 * satisfied, no foreign signer, address == owner) and rtn_input_owned (a
 * coin of the address is owned only when its descriptor is satisfied).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A 2-of-3 descriptor (members K1 K2 K3; KX a foreign key), its address
 *  ADDR = SHA3-512(descriptor) (nodus_v2_msig_desc_from_keys).
 *  O1 STAKE v2 owned by ADDR (the node KC consents to ADDR): the builder
 *     returns an UNSIGNED envelope — both legs auth_kind 3, K = 2 zero
 *     slots, the descriptor — whose call's owner_fp is ADDR, whose change
 *     goes to ADDR, with leg_digest[0..1] == a fresh preflight's
 *     auth_digest[0..1]; the v2 export text round-trips; review2 by K1
 *     shows op 1, ADDR, the consensus key, the bond and the funding, and
 *     refuses KX (not a member) and a flipped exported digest; K1 and K2
 *     each sign BOTH digests into a v2 signature file (round trip);
 *     combine2 assembles them; the chain's auth hook on EACH leg returns
 *     one satisfied descriptor whose address is ADDR with every signer in
 *     it; the GEN_STORAGE SYSTEM exec, fed that REAL leg-0 verdict,
 *     APPLIES (op-13 row owner = ADDR); the CORE exec, fed the REAL leg-1
 *     verdict and coins owned by ADDR, balances (Σin == change + fee +
 *     bond).
 *  O2 ROTATE of that validator by ADDR (the new key KN consents to ADDR):
 *     the same CLIENT path builds, signs and combines (the client builder
 *     is removed by the next package), but the chain REFUSES it: HF-6 has
 *     no key rotation (khan decision 2026-10-13-kurultay-18-summary.md
 *     item 1) — the generation-4 SYSTEM exec returns -1 for op 10 even
 *     with the owner's real authorization and the committed row from O1,
 *     and the CORE funding leg refuses to pair with it (-1).
 *  O3 STORAGE_REGISTER owned by ADDR (KS consents with op 3): the same
 *     path; the exec CREATEs the storage row with ADDR in its owner
 *     column; the funding balances with lock = bond.
 *  N1 BELOW M — the O1 STAKE rebuilt by hand with ONE slot (K = 1 < M = 2;
 *     the builder refuses K < M, ERR_ARG — checked), signed by K1 alone
 *     and assembled with assemble2: the auth hook verifies the signature
 *     but records the descriptor NOT satisfied; the SYSTEM exec refuses
 *     (owner rule) and the CORE exec refuses (an input of ADDR is not
 *     owned).
 *  N2 A FOREIGN SIGNER — STAKE built with K = 3 and signed by K1, K2, KX:
 *     combine2 refuses (NOT_MEMBER); assembled by hand (assemble2 does not
 *     judge membership), the auth hook records the descriptor satisfied
 *     but the signers-in-descriptor bit CLEAR; the SYSTEM exec refuses
 *     (decision D6 — no foreign signer rides along).
 *  N3 All or nothing: a signature file carrying the leg-0 signature twice
 *     (no leg-1 signature) is refused by sig2_check (SIG_DIGEST); a file
 *     with only one digest/sig pair does not parse; a sig line whose leg
 *     index differs from its digest line does not parse; a duplicated
 *     signer is refused (DUP_SIGNER); one signature for K = 2 is
 *     COUNT.
 *  K1 The kind-1 path: the same STAKE v2 with the new request fields left
 *     zero still builds signed, auth_kind 1 on both legs, decodes with
 *     auth_kind 1 and the owner key as identity; a legacy (generation 0)
 *     STAKE with a descriptor is ERR_GEN; a v1 export text is not a v2
 *     export and a v2 export text is not a v1 export.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 is compiled only with the
 * EVM runtime; the CMake target is registered only then). Environment:
 * none. No database, no network, no files.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Hook level: the auth VERDICTS are real (nodus_rt_auth_dsa87_v1 over
 *    the assembled bytes and the preflight digests), but the reads (the
 *    active count, the committed rows, the funding UTXO rows with ADDR as
 *    owner) are FABRICATED engine facts; no block is applied, the meter
 *    and the mempool are not exercised.
 *  - N1 and N2 are assembled by HAND (the library's combine refuses them
 *    before the chain could): they prove the chain's refusal of such
 *    bytes, not that any client can produce them.
 *  - nodus-cli's `--msig` paths, `msig sign` / `msig combine` v2 and
 *    `consent --msig` are I/O around the library calls driven here; their
 *    argument handling, file handling and printing are not driven.
 *  - The CORE leg's foreign-signer case (N2) is not checked at the CORE
 *    exec: the chain does not apply the owner rule there (a satisfied
 *    descriptor owns its coins whatever else signed).
 *  - The v1 SPEND flow's byte vectors are test_v2_msig.c's (unchanged);
 *    this file only checks that the two formats do not read each other.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_stake.h"
#include "client/nodus_v2_msig.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
#include "dnac/valbind_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define SMIN     ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define SBOND    ((uint64_t)DNAC_HF6_STORAGE_BOND_DEFAULT)
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN  ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define TIP      8u
#define H_EXEC   9u               /* the executing height == tip + 1     */
#define EXP      (H_EXEC + 100u)  /* the consent expiry (within 720)     */
#define BPS      500u

/* restated from nodus_witness_rt_native.c (static there) — the same
 * values test_v2_stake_client.c restates */
#define OP_VAL2       13u
#define OP_STOR       8u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_SELF_OFF   (128u + 2u * 2592u + 8u)
#define V2_PPK_OFF    (128u + 2592u)
#define UTXO_REC_LEN  284u
#define UTXO_AMT_OFF  128u
#define UTXO_UNL_OFF  276u
#define STOR_REC_LEN  2693u
#define STOR_OWNER_OFF 2592u
#define STOR_BOND_OFF 2656u

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

/* ══ keys, descriptor, ruleset ═══════════════════════════════════════ */

/* K1..K3 the members, KX foreign, KC the STAKE node key, KN the rotation
 * target, KS a storage node */
enum { K1, K2, K3, KX, KC, KN, KS, N_KEYS };
static uint8_t g_pk[N_KEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[N_KEYS][QGP_DSA87_SECRETKEYBYTES];

static uint8_t g_desc[DNA_MSIG_MAX_DESC_LEN];
static size_t  g_desc_len;
static uint8_t g_addr[64];
static char    g_addr_hex[129];

static nodus_v2_stake_ruleset_t g_rs4;
static const nodus_domain_runtime_t *g_s4, *g_c4;
static uint8_t g_chain32[DNA_CHAIN_ID_LEN];
static nodus_v2_stake_coin_t g_coin;

static int setup(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x91 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) return -1;
    }
    uint8_t keys[3 * QGP_DSA87_PUBLICKEYBYTES];
    for (int i = 0; i < 3; i++)
        memcpy(keys + (size_t)i * PK_LEN, g_pk[K1 + i], PK_LEN);
    if (nodus_v2_msig_desc_from_keys(2, 3, keys, g_desc, sizeof(g_desc),
                                     &g_desc_len, g_addr) != NODUS_V2_SPEND_OK)
        return -1;
    hex_of(g_addr, g_addr_hex);
    g_s4 = nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                        DNA_DOMAIN_SYSTEM);
    g_c4 = nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    if (!g_s4 || !g_c4) return -1;
    memset(&g_rs4, 0, sizeof(g_rs4));
    g_rs4.sys_ruleset_version  = g_s4->ruleset_version;
    memcpy(g_rs4.sys_ruleset_hash, g_s4->ruleset_hash, 64);
    g_rs4.core_ruleset_version = g_c4->ruleset_version;
    memcpy(g_rs4.core_ruleset_hash, g_c4->ruleset_hash, 64);
    memset(g_chain32, 0x5D, sizeof(g_chain32));
    return 0;
}

static void coin_set(uint64_t amount) {
    memset(&g_coin, 0, sizeof(g_coin));
    memset(g_coin.nul, 0x48, 64);
    g_coin.amount = amount;
}

/* the two positional leg contexts of an owner envelope */
static void lctx_set(dna_env_leg_ctx_t lctx[2]) {
    memset(lctx, 0, 2 * sizeof(lctx[0]));
    lctx[0].domain_id       = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = g_rs4.sys_ruleset_version;
    memcpy(lctx[0].ruleset_hash, g_rs4.sys_ruleset_hash, 64);
    lctx[1].domain_id       = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = g_rs4.core_ruleset_version;
    memcpy(lctx[1].ruleset_hash, g_rs4.core_ruleset_hash, 64);
}

/* the node consent nodus-cli `validator consent --msig` makes: the two
 * codec calls, owner = ADDR */
static int consent_make(nodus_v2_consent_t *c, uint8_t op,
                        const uint8_t subject[64], int key) {
    memset(c, 0, sizeof(*c));
    c->op = op;
    memcpy(c->chain32, g_chain32, 32);
    memcpy(c->subject, subject, 64);
    memcpy(c->owner_fp, g_addr, 64);
    memcpy(c->consensus_pk, g_pk[key], PK_LEN);
    c->expiry = EXP;
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    size_t sl = 0;
    if (dna_valbind_consent_msg(msg, c->chain32, op, c->subject, c->owner_fp,
                                c->consensus_pk, c->expiry) != 0)
        return -1;
    if (dna_valbind_consent_sign(c->sig, &sl, msg, g_sk[key]) != 0 ||
        sl != SIG_LEN)
        return -1;
    return 0;
}

/* a generation-4 owner request for ADDR with K signers */
static void req_msig(nodus_v2_stake_req_t *r, nodus_v2_stake_op_t op,
                     const nodus_v2_consent_t *c, uint32_t k) {
    memset(r, 0, sizeof(*r));
    r->rs = &g_rs4;
    r->op = op;
    r->chain32 = g_chain32;
    r->tip = TIP;
    r->expiry_height = TIP + 50u;
    r->amount = op == NODUS_V2_STAKE_OP_STAKE ? SMIN
              : op == NODUS_V2_STAKE_OP_STORAGE_REGISTER ? SBOND : 0;
    r->commission_bps = op == NODUS_V2_STAKE_OP_STAKE ? BPS : 0;
    r->coins = &g_coin;
    r->n_coins = 1;
    r->generation = NODUS_RT_GEN_STORAGE;
    if (c) {
        r->consensus_pk = c->consensus_pk;
        r->consent_sig = c->sig;
        r->consent_expiry = c->expiry;
        r->validator_id = op == NODUS_V2_STAKE_OP_ROTATE ? c->subject : NULL;
    }
    r->msig_desc = g_desc;
    r->msig_desc_len = g_desc_len;
    r->msig_signers = k;
}

/* one member's v2 signature over every digest of `x`, through its text */
static int sig2_make(int who, const nodus_v2_msig_export2_t *x,
                     nodus_v2_msig_sig2_t *out) {
    nodus_v2_msig_sig2_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    memcpy(s->pk, g_pk[who], PK_LEN);
    s->n = x->n_digests;
    for (uint32_t j = 0; j < x->n_digests; j++) {
        size_t sl = 0;
        s->leg_index[j] = x->leg_index[j];
        memcpy(s->digest[j], x->digest[j], 64);
        if (qgp_dsa87_sign(s->sig[j], &sl, x->digest[j], 64, g_sk[who]) != 0 ||
            sl != SIG_LEN) {
            free(s);
            return -1;
        }
    }
    char *t = NULL;
    size_t tl = 0;
    int rc = nodus_v2_msig_sig2_encode(s, &t, &tl) == NODUS_V2_SPEND_OK &&
             nodus_v2_msig_sig2_parse(t, tl, out) == NODUS_V2_SPEND_OK &&
             memcmp(out, s, sizeof(*s)) == 0 ? 0 : -1;
    free(t);
    free(s);
    return rc;
}

/* the export of a built unsigned envelope, through its v2 text */
static int export_of(const nodus_v2_stake_built_t *b, uint32_t k,
                     nodus_v2_msig_export2_t *x) {
    nodus_v2_msig_export2_t src;
    memset(&src, 0, sizeof(src));
    memcpy(src.chain32, g_chain32, DNA_CHAIN_ID_LEN);
    src.tip = TIP;
    src.signers = k;
    src.n_digests = 2;
    src.leg_index[0] = 0;
    src.leg_index[1] = 1;
    memcpy(src.digest[0], b->leg_digest[0], 64);
    memcpy(src.digest[1], b->leg_digest[1], 64);
    src.env = b->env;
    src.env_len = b->env_len;
    char *t = NULL;
    size_t tl = 0;
    int rc = -1;
    if (nodus_v2_msig_export2_encode(&src, &t, &tl) == NODUS_V2_SPEND_OK &&
        nodus_v2_msig_export2_parse(t, tl, x) == NODUS_V2_SPEND_OK &&
        x->env_len == b->env_len && memcmp(x->env, b->env, b->env_len) == 0 &&
        x->signers == k && x->n_digests == 2 &&
        memcmp(x->digest, src.digest, 2 * 64) == 0 && x->tip == TIP)
        rc = 0;
    free(t);
    return rc;
}

/* ══ the chain's view: real verdicts, fabricated reads ════════════════ */

static nodus_rt_auth_verdict_t g_av[2];
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_dig[2][64];
static nodus_rt_read_res_t g_reads[NODUS_RT_MAX_READS];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* the chain's own auth hook on leg L of the (signed) view, over the
 * preflight digest; leaves g_av[L] / g_dig[L]. @return the hook's rc. */
static int verdict(const dna_env_view_t *v, uint16_t L, const uint8_t dg[64]) {
    nodus_rt_exec_ctx_t c;
    memset(&c, 0, sizeof(c));
    memcpy(g_dig[L], dg, 64);
    c.chain_id = g_chain32;
    c.global_height = H_EXEC;
    c.leg_auth_digest = g_dig[L];
    memset(&g_av[L], 0, sizeof(g_av[L]));
    return nodus_rt_auth_dsa87_v1(L == 0 ? g_s4 : g_c4, v, L, &c, &g_av[L]);
}

/* the exec ctx for leg L with its REAL verdict */
static void ctx_for(uint16_t L, const uint8_t intent[64]) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.chain_id = g_chain32;
    g_ctx.global_height = H_EXEC;
    g_ctx.epoch = H_EXEC / E_LEN;
    g_ctx.wire_id = intent;
    g_ctx.intent_id = intent;
    g_ctx.auth_context_commit = g_dig[L];
    g_ctx.leg_auth_digest = g_dig[L];
    g_ctx.auth = &g_av[L];
    g_ctx.stake_min = SMIN;
    g_ctx.storage_bond = SBOND;
}

/* the funding reads: every input a UTXO row owned by ADDR holding
 * `amount`, then the pool */
static uint16_t fund_reads(const dna_env_view_t *v, uint64_t amount) {
    const uint8_t *c = v->buf + v->call_off[1];
    const uint8_t n_in = c[0];
    memset(g_reads, 0, sizeof(g_reads));
    for (uint8_t i = 0; i < n_in; i++) {
        g_reads[i].present = 1;
        g_reads[i].value_len = UTXO_REC_LEN;
        memcpy(g_reads[i].value, g_addr_hex, 128);
        put64(g_reads[i].value + UTXO_AMT_OFF, amount);
        put64(g_reads[i].value + UTXO_UNL_OFF, 0);
    }
    g_reads[n_in].present = 1;
    g_reads[n_in].value_len = 8;
    put64(g_reads[n_in].value, 1000u);
    return (uint16_t)(n_in + 1u);
}

static int sys_exec(const dna_env_view_t *v, uint16_t n_reads,
                    dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(g_s4, v, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int core_exec(const dna_env_view_t *v, uint16_t n_reads) {
    size_t rl = 0;
    return nodus_rt_core_exec(g_c4, v, 1, &g_ctx, g_reads, n_reads,
                              g_res, sizeof(g_res), &rl);
}

/* ══ the happy path, shared by O1-O3 ══════════════════════════════════
 * build (K = 2) → export text → review2 (K1; KX refused; a flipped digest
 * refused) → K1 and K2 sign both legs → combine2 → the auth hook on both
 * legs: one satisfied descriptor == ADDR, every signer in it. Leaves the
 * signed envelope in *x, its view in *v and the intent in intent[]. */
static int owner_path(const nodus_v2_stake_req_t *r, nodus_v2_msig_export2_t *x,
                      dna_env_view_t *v, uint8_t intent[64],
                      nodus_v2_stake_built_t *b) {
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(r, b, &e) == NODUS_V2_SPEND_OK,
          "kind-3 owner envelope builds");
    CHECK(b->auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1 &&
          b->dec.auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1 &&
          b->dec.gen4 == 1 && b->dec.msig_signers == 2 &&
          b->dec.msig_m == 2 && b->dec.msig_n == 3 &&
          memcmp(b->dec.msig_addr, g_addr, 64) == 0 &&
          memcmp(b->dec.owner_fp, g_addr, 64) == 0,
          "read-back: kind 3, K 2, 2-of-3, owner = ADDR");
    {
        static const uint8_t zero64[64] = { 0 };
        uint8_t zpk[2592];
        memset(zpk, 0, sizeof(zpk));
        CHECK(memcmp(b->wire_id, zero64, 64) == 0 &&
              memcmp(b->dec.identity_pk, zpk, sizeof(zpk)) == 0,
              "unsigned: no wire_id, no single-signer identity");
        CHECK(b->dec.n_out == 0 ||
              memcmp(b->dec.change_owner, g_addr_hex, 128) == 0,
              "the change goes back to ADDR");
    }
    /* both legs: kind 3, K zero slots ‖ 1 ‖ dlen ‖ the descriptor */
    CHECK(dna_env_decode(b->env, b->env_len, v) == 0 && v->leg_count == 2,
          "two legs");
    for (uint16_t L = 0; L < 2; L++) {
        const uint8_t *a = v->buf + v->auth_off[L];
        const size_t off = 1u + 2u * NODUS_RT_AUTH_SIGNER_LEN;
        uint8_t zslot[NODUS_RT_AUTH_SIGNER_LEN];
        memset(zslot, 0, sizeof(zslot));
        CHECK(v->leg[L].auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1 &&
              v->leg[L].auth_len == off + 3u + g_desc_len && a[0] == 2 &&
              memcmp(a + 1, zslot, sizeof(zslot)) == 0 &&
              memcmp(a + 1 + NODUS_RT_AUTH_SIGNER_LEN, zslot,
                     sizeof(zslot)) == 0 &&
              a[off] == 1 && a[off + 1] == (uint8_t)(g_desc_len >> 8) &&
              a[off + 2] == (uint8_t)g_desc_len &&
              memcmp(a + off + 3, g_desc, g_desc_len) == 0,
              "auth blob = 2 zero slots ‖ dcount 1 ‖ dlen ‖ descriptor");
    }
    /* the digests are a fresh preflight's */
    dna_env_leg_ctx_t lctx[2];
    lctx_set(lctx);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf != NULL, "alloc");
    CHECK(dna_env_preflight(b->env, b->env_len, g_chain32, TIP + 1, lctx, 2,
                            pf) == DNA_ENV_PF_OK &&
          memcmp(pf->auth_digest[0], b->leg_digest[0], 64) == 0 &&
          memcmp(pf->auth_digest[1], b->leg_digest[1], 64) == 0 &&
          memcmp(b->leg_digest[0], b->leg_digest[1], 64) != 0 &&
          memcmp(pf->intent_id, b->intent_id, 64) == 0,
          "leg_digest[0..1] == the preflight's (and the two differ)");

    /* the export and the co-signers' read-back */
    CHECK(export_of(b, 2, x) == 0, "v2 export round-trips");
    nodus_v2_msig_review2_t *rv = calloc(1, sizeof(*rv));
    CHECK(rv != NULL, "alloc");
    CHECK(nodus_v2_msig_review2(x, lctx, 2, g_pk[K1], pf, rv) ==
              NODUS_V2_SPEND_OK &&
          memcmp(rv->addr, g_addr, 64) == 0 && rv->m == 2 && rv->n == 3 &&
          rv->signers == 2 && rv->n_digests == 2 &&
          rv->op.op == (uint32_t)r->op &&
          memcmp(rv->op.owner_fp, g_addr, 64) == 0 &&
          rv->op.n_in == b->dec.n_in && rv->fee == b->fee &&
          memcmp(rv->intent_id, b->intent_id, 64) == 0,
          "review2: the operation, ADDR, the funding, both digests");
    CHECK(nodus_v2_msig_review2(x, lctx, 2, g_pk[KX], pf, rv) ==
              NODUS_V2_MSIG_ERR_NOT_MEMBER,
          "review2 refuses a key outside the descriptor");
    x->digest[1][7] ^= 0x01;
    CHECK(nodus_v2_msig_review2(x, lctx, 2, g_pk[K1], pf, rv) ==
              NODUS_V2_MSIG_ERR_DIGEST,
          "review2 refuses an exported leg-1 digest that does not re-derive");
    x->digest[1][7] ^= 0x01;
    free(rv);

    /* two members sign BOTH legs; the combine */
    nodus_v2_msig_sig2_t *s[2] = { calloc(1, sizeof(nodus_v2_msig_sig2_t)),
                                   calloc(1, sizeof(nodus_v2_msig_sig2_t)) };
    CHECK(s[0] && s[1], "alloc");
    CHECK(sig2_make(K2, x, s[0]) == 0 && sig2_make(K1, x, s[1]) == 0,
          "K2 and K1 sign both digests (v2 signature text round-trips)");
    int bad = 7;
    CHECK(nodus_v2_msig_combine2(x, lctx, 2,
                                 (const nodus_v2_msig_sig2_t *const *)s, 2,
                                 pf, &bad) == NODUS_V2_SPEND_OK && bad == -1,
          "combine2 assembles both legs");
    free(s[0]);
    free(s[1]);
    CHECK(memcmp(pf->intent_id, b->intent_id, 64) == 0 &&
          memcmp(pf->auth_digest[0], b->leg_digest[0], 64) == 0 &&
          memcmp(pf->auth_digest[1], b->leg_digest[1], 64) == 0,
          "the signed envelope keeps the intent and both digests");
    memcpy(intent, pf->intent_id, 64);

    /* the chain's auth hook on each leg */
    CHECK(dna_env_decode(x->env, x->env_len, v) == 0, "signed decodes");
    for (uint16_t L = 0; L < 2; L++) {
        CHECK(verdict(v, L, pf->auth_digest[L]) == 0 &&
              g_av[L].n_signers == 2 && g_av[L].n_msig == 1 &&
              g_av[L].msig_satisfied[0] == 1 &&
              (g_av[L].msig_signers_in_desc & 1u) == 1u &&
              memcmp(g_av[L].msig_addr[0], g_addr, 64) == 0,
              "auth hook: one satisfied descriptor == ADDR, no foreign "
              "signer");
    }
    {   /* the signed envelope still reads back as the owner operation */
        nodus_v2_stake_decoded_t *d = calloc(1, sizeof(*d));
        CHECK(d && nodus_v2_stake_decode(x->env, x->env_len, d) ==
                       NODUS_V2_SPEND_OK &&
              d->auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1 &&
              memcmp(d->msig_addr, g_addr, 64) == 0,
              "signed envelope decodes (kind 3)");
        free(d);
    }
    free(pf);
    return 0;
}

/* ══ O1-O3 and N1-N3 ══════════════════════════════════════════════════ */

static uint8_t g_vid[64];
static uint8_t g_row[V2_REC_LEN];

static int t_stake2(void) {
    static const uint8_t zero64[64] = { 0 };
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, KC) == 0,
          "KC consents to ADDR's STAKE");
    const uint64_t coin = SMIN + 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 2);
    nodus_v2_stake_built_t b;
    nodus_v2_msig_export2_t x;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    uint8_t intent[64];
    CHECK(v != NULL, "alloc");
    if (owner_path(&r, &x, v, intent, &b) != 0) return 1;
    CHECK(memcmp(v->buf + v->call_off[0], g_addr, 64) == 0 &&
          v->leg[0].call_len == NODUS_V2_STAKE2_CALL_LEN,
          "STAKE v2 call: owner_fp = ADDR (7301 bytes)");

    /* SYSTEM exec with the REAL leg-0 verdict */
    CHECK(dna_validator_id_new(g_vid, g_chain32, intent) == 0, "vid");
    ctx_for(0, intent);
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;                     /* active_count 7     */
        g_reads[0].value_len = 8;
        put64(g_reads[0].value, 7);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(v, 3, &ev) == 0 && ev.effect_count == 3,
              "STAKE exec APPLIES under the kind-3 owner");
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        CHECK(ev.eff[0].op_id == OP_VAL2 &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].value_len == V2_REC_LEN &&
              memcmp(v0, g_vid, 64) == 0 &&
              memcmp(v0 + V2_OWNER_OFF, g_addr, 64) == 0 &&
              get64(v0 + V2_SELF_OFF) == SMIN,
              "the op-13 row: the printed validator_id, owner ADDR, bond");
        memcpy(g_row, v0, V2_REC_LEN);
    }
    /* CORE exec with the REAL leg-1 verdict */
    ctx_for(1, intent);
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(v, nr) == 0,
              "funding by ADDR's coins balances (lock = bond)");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(v, nr) == -1, "+1 on the input refused");
    }
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    free(v);
    return 0;
}

static int t_rotate(void) {
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_ROTATE, g_vid, KN) == 0,
          "KN consents to ADDR rotating the validator onto it");
    const uint64_t coin = 5000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_ROTATE, &c, 2);
    nodus_v2_stake_built_t b;
    nodus_v2_msig_export2_t x;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    uint8_t intent[64];
    CHECK(v != NULL, "alloc");
    if (owner_path(&r, &x, v, intent, &b) != 0) return 1;
    CHECK(v->leg[0].call_len == NODUS_V2_ROTATE_CALL_LEN &&
          memcmp(v->buf + v->call_off[0], g_vid, 64) == 0,
          "ROTATE call names the validator (7291 bytes)");
    ctx_for(0, intent);
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;                     /* the committed row */
        g_reads[0].value_len = V2_REC_LEN;
        memcpy(g_reads[0].value, g_row, V2_REC_LEN);
        memset(&ev, 0, sizeof(ev));
        /* HF-6 D1 (khan decision 2026-10-13-kurultay-18-summary.md item
         * 1): the chain has no ROTATE — the client builder still produces
         * the envelope (its removal is the next package's), the chain's
         * generation-4 SYSTEM exec refuses op 10 as an unowned op (-1, a
         * VERDICT, never -2) even with the owner's real authorization */
        CHECK(sys_exec(v, 2, &ev) == -1,
              "ROTATE exec REFUSED (-1): op 10 is no chain operation");
    }
    ctx_for(1, intent);
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(v, nr) == -1,
              "the CORE funding leg does not pair with an op-10 sibling (-1)");
    }
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    free(v);
    return 0;
}

static int t_storage(void) {
    static const uint8_t zero64[64] = { 0 };
    uint8_t ks_fp[64];
    CHECK(qgp_sha3_512(g_pk[KS], PK_LEN, ks_fp) == 0, "node fp");
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STORAGE_REGISTER, zero64, KS) == 0,
          "KS consents (op 3) to ADDR owning it");
    const uint64_t coin = SBOND + 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER, &c, 2);
    nodus_v2_stake_built_t b;
    nodus_v2_msig_export2_t x;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    uint8_t intent[64];
    CHECK(v != NULL, "alloc");
    if (owner_path(&r, &x, v, intent, &b) != 0) return 1;
    CHECK(v->leg[0].call_len == NODUS_V2_STREG_CALL_LEN &&
          memcmp(v->buf + v->call_off[0], g_addr, 64) == 0 &&
          memcmp(b.dec.node_fp, ks_fp, 64) == 0,
          "STORAGE_REGISTER call: owner_fp = ADDR, node KS (7299 bytes)");
    ctx_for(0, intent);
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[1].present = 1;                     /* live count 0      */
        g_reads[1].value_len = 8;
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(v, 2, &ev) == 0 && ev.effect_count == 1,
              "REGISTER exec APPLIES under the kind-3 owner");
        const uint8_t *rec = ev.buf + ev.val_off[0];
        CHECK(ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].value_len == STOR_REC_LEN &&
              memcmp(rec + STOR_OWNER_OFF, g_addr, 64) == 0 &&
              get64(rec + STOR_BOND_OFF) == SBOND,
              "CREATE op 8: ADDR in the owner column, the bond");
    }
    ctx_for(1, intent);
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(v, nr) == 0,
              "funding by ADDR's coins balances (lock = bond)");
    }
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    free(v);
    return 0;
}

/* N1 — the STAKE with ONE slot (K = 1 < M = 2), by hand: the built K = 2
 * envelope's legs re-encoded with a one-slot blob, preflighted, signed by
 * K1 alone (assemble2). */
static int t_below_m(void) {
    static const uint8_t zero64[64] = { 0 };
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, KC) == 0, "consent");
    const uint64_t coin = SMIN + 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 1);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "the builder refuses K = 1 < M = 2");
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 2);
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK, "K = 2");

    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v && dna_env_decode(b.env, b.env_len, v) == 0, "decode");
    const size_t alen1 = 1u + NODUS_RT_AUTH_SIGNER_LEN + 3u + g_desc_len;
    uint8_t *auth = calloc(1, alen1);
    CHECK(auth != NULL, "alloc");
    auth[0] = 1;
    auth[1 + NODUS_RT_AUTH_SIGNER_LEN] = 1;
    auth[2 + NODUS_RT_AUTH_SIGNER_LEN] = (uint8_t)(g_desc_len >> 8);
    auth[3 + NODUS_RT_AUTH_SIGNER_LEN] = (uint8_t)g_desc_len;
    memcpy(auth + 4 + NODUS_RT_AUTH_SIGNER_LEN, g_desc, g_desc_len);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    for (int L = 0; L < 2; L++) {
        legs[L].hdr = v->leg[L];
        legs[L].hdr.auth_len = (uint32_t)alen1;
        legs[L].call_data = v->buf + v->call_off[L];
        legs[L].auth_data = auth;
    }
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height = v->expiry_height;
    in.fee_amount = v->fee_amount;
    in.res_max_total_units = v->res_max_total_units;
    in.leg_count = 2;
    in.legs = legs;
    size_t len = 0, used = 0;
    CHECK(dna_env_encoded_size(legs, 2, &len) == 0, "size");
    nodus_v2_msig_export2_t x;
    memset(&x, 0, sizeof(x));
    x.env = malloc(len);
    CHECK(x.env && dna_env_encode(&in, x.env, len, &used) == 0 && used == len,
          "one-slot envelope encodes");
    x.env_len = len;
    dna_env_leg_ctx_t lctx[2];
    lctx_set(lctx);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf && dna_env_preflight(x.env, x.env_len, g_chain32, TIP + 1, lctx,
                                  2, pf) == DNA_ENV_PF_OK, "preflight");
    memcpy(x.chain32, g_chain32, DNA_CHAIN_ID_LEN);
    x.tip = TIP;
    x.signers = 1;
    x.n_digests = 2;
    x.leg_index[1] = 1;
    memcpy(x.digest[0], pf->auth_digest[0], 64);
    memcpy(x.digest[1], pf->auth_digest[1], 64);
    nodus_v2_msig_sig2_t *s = calloc(1, sizeof(*s));
    CHECK(s && sig2_make(K1, &x, s) == 0, "K1 signs both");
    dna_env_view_t *xv = calloc(1, sizeof(*xv));
    CHECK(xv && dna_env_decode(x.env, x.env_len, xv) == 0, "decode");
    const nodus_v2_msig_sig2_t *one[1] = { s };
    CHECK(nodus_v2_msig_assemble2(&x, xv, one, 1) == NODUS_V2_SPEND_OK,
          "assembled by hand");
    CHECK(dna_env_decode(x.env, x.env_len, xv) == 0, "re-decode");
    for (uint16_t L = 0; L < 2; L++)
        CHECK(verdict(xv, L, pf->auth_digest[L]) == 0 &&
              g_av[L].n_signers == 1 && g_av[L].n_msig == 1 &&
              g_av[L].msig_satisfied[0] == 0,
              "auth hook: the signature verifies, the descriptor is NOT "
              "satisfied (1 < M)");
    ctx_for(0, pf->intent_id);
    memset(g_reads, 0, sizeof(g_reads));
    g_reads[0].present = 1;
    g_reads[0].value_len = 8;
    put64(g_reads[0].value, 7);
    CHECK(sys_exec(xv, 3, NULL) == -1,
          "SYSTEM exec refuses: the owner rule needs >= M signers");
    ctx_for(1, pf->intent_id);
    {
        uint16_t nr = fund_reads(xv, coin);
        CHECK(core_exec(xv, nr) == -1,
              "CORE exec refuses: ADDR's coin is not owned below M");
    }
    free(s);
    free(xv);
    free(pf);
    free(auth);
    free(v);
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* N2 — K = 3 signed by K1, K2 and the foreign KX */
static int t_foreign(void) {
    static const uint8_t zero64[64] = { 0 };
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, KC) == 0, "consent");
    coin_set(SMIN + 9000000000ULL);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 3);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK &&
          b.dec.msig_signers == 3, "K = 3 (= N) builds");
    nodus_v2_msig_export2_t x;
    CHECK(export_of(&b, 3, &x) == 0, "export");
    nodus_v2_msig_sig2_t *s[3];
    for (int i = 0; i < 3; i++) {
        s[i] = calloc(1, sizeof(*s[i]));
        CHECK(s[i] != NULL, "alloc");
    }
    CHECK(sig2_make(K1, &x, s[0]) == 0 && sig2_make(K2, &x, s[1]) == 0 &&
          sig2_make(KX, &x, s[2]) == 0, "K1, K2, KX sign");
    dna_env_leg_ctx_t lctx[2];
    lctx_set(lctx);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf != NULL, "alloc");
    int bad = 0;
    CHECK(nodus_v2_msig_combine2(&x, lctx, 2,
                                 (const nodus_v2_msig_sig2_t *const *)s, 3,
                                 pf, &bad) == NODUS_V2_MSIG_ERR_NOT_MEMBER &&
          bad == 2, "combine2 refuses the foreign signer");
    /* by hand: assemble2 does not judge membership */
    nodus_v2_msig_export2_free(&x);
    CHECK(export_of(&b, 3, &x) == 0, "export again");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v && dna_env_decode(x.env, x.env_len, v) == 0, "decode");
    CHECK(nodus_v2_msig_assemble2(&x, v,
                                  (const nodus_v2_msig_sig2_t *const *)s, 3)
              == NODUS_V2_SPEND_OK, "assembled by hand");
    CHECK(dna_env_decode(x.env, x.env_len, v) == 0, "re-decode");
    CHECK(verdict(v, 0, b.leg_digest[0]) == 0 && g_av[0].n_signers == 3 &&
          g_av[0].n_msig == 1 && g_av[0].msig_satisfied[0] == 1 &&
          (g_av[0].msig_signers_in_desc & 1u) == 0,
          "auth hook: satisfied (2 members), but a signer is NOT in the "
          "descriptor");
    ctx_for(0, b.intent_id);
    memset(g_reads, 0, sizeof(g_reads));
    g_reads[0].present = 1;
    g_reads[0].value_len = 8;
    put64(g_reads[0].value, 7);
    CHECK(sys_exec(v, 3, NULL) == -1,
          "SYSTEM exec refuses a foreign signer riding along (D6)");
    for (int i = 0; i < 3; i++) free(s[i]);
    free(v);
    free(pf);
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* N3 — all or nothing, the count, the duplicate, the text rules */
static int t_all_or_nothing(void) {
    static const uint8_t zero64[64] = { 0 };
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, KC) == 0, "consent");
    coin_set(SMIN + 9000000000ULL);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 2);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK, "build");
    nodus_v2_msig_export2_t x;
    CHECK(export_of(&b, 2, &x) == 0, "export");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_msig_leg_t leg;
    CHECK(v && nodus_v2_msig_legs_open2(&x, v, &leg) == NODUS_V2_SPEND_OK &&
          leg.m == 2 && leg.n == 3 && leg.desc_len == g_desc_len,
          "legs_open2: both legs, one descriptor");
    nodus_v2_msig_sig2_t *s = calloc(1, sizeof(*s));
    nodus_v2_msig_sig2_t *t2 = calloc(1, sizeof(*t2));
    CHECK(s && t2 && sig2_make(K1, &x, s) == 0, "K1 signs");
    CHECK(nodus_v2_msig_sig2_check(&x, &leg, s) == NODUS_V2_SPEND_OK,
          "a complete signature checks");
    /* the leg-0 signature in place of leg 1's: leg 1 unsigned */
    *t2 = *s;
    memcpy(t2->digest[1], t2->digest[0], 64);
    memcpy(t2->sig[1], t2->sig[0], SIG_LEN);
    CHECK(nodus_v2_msig_sig2_check(&x, &leg, t2) ==
              NODUS_V2_MSIG_ERR_SIG_DIGEST,
          "a file that does not sign leg 1's digest is refused");
    *t2 = *s;
    t2->sig[1][100] ^= 0x01;
    CHECK(nodus_v2_msig_sig2_check(&x, &leg, t2) == NODUS_V2_MSIG_ERR_SIG,
          "a bad leg-1 signature is refused");
    {   /* the texts */
        char *t = NULL;
        size_t tl = 0;
        CHECK(nodus_v2_msig_sig2_encode(s, &t, &tl) == NODUS_V2_SPEND_OK,
              "sig2 encodes");
        /* drop the last digest/sig pair: one leg only */
        char *p = strstr(t, "\ndigest 1 ");
        CHECK(p != NULL, "leg-1 digest line");
        CHECK(nodus_v2_msig_sig2_parse(t, (size_t)(p - t) + 1, t2) ==
                  NODUS_V2_MSIG_ERR_FORMAT,
              "a signature of one leg only does not parse");
        /* the sig line of leg 1 renamed to leg 0 */
        char *q = strstr(t, "\nsig 1 ");
        CHECK(q != NULL, "leg-1 sig line");
        q[5] = '0';
        CHECK(nodus_v2_msig_sig2_parse(t, tl, t2) == NODUS_V2_MSIG_ERR_FORMAT,
              "a sig line whose leg differs from its digest line");
        q[5] = '1';
        CHECK(nodus_v2_msig_sig2_parse(t, tl, t2) == NODUS_V2_SPEND_OK,
              "restored text parses");
        free(t);
    }
    {
        dna_env_leg_ctx_t lctx[2];
        lctx_set(lctx);
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        CHECK(pf != NULL, "alloc");
        const nodus_v2_msig_sig2_t *twice[2] = { s, s };
        int bad = 0;
        CHECK(nodus_v2_msig_combine2(&x, lctx, 2, twice, 2, pf, &bad) ==
                  NODUS_V2_MSIG_ERR_DUP_SIGNER,
              "the same key twice");
        CHECK(nodus_v2_msig_combine2(&x, lctx, 2, twice, 1, pf, &bad) ==
                  NODUS_V2_MSIG_ERR_COUNT,
              "one signature for K = 2");
        free(pf);
    }
    free(s);
    free(t2);
    free(v);
    nodus_v2_msig_export2_free(&x);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* K1 — the kind-1 path and the format separation */
static int t_kind1(void) {
    static const uint8_t zero64[64] = { 0 };
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, KC) == 0, "consent");
    /* a kind-1 owner K1: the consent names K1's fingerprint */
    uint8_t k1_fp[64];
    CHECK(qgp_sha3_512(g_pk[K1], PK_LEN, k1_fp) == 0, "fp");
    memcpy(c.owner_fp, k1_fp, 64);
    coin_set(SMIN + 9000000000ULL);
    nodus_v2_stake_req_t r;
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 0);
    r.msig_desc = NULL;                       /* the new fields zero      */
    r.msig_desc_len = 0;
    r.pk = g_pk[K1];
    r.sk = g_sk[K1];
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK &&
          b.auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
          b.dec.auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
          memcmp(b.dec.identity_pk, g_pk[K1], PK_LEN) == 0 &&
          memcmp(b.dec.owner_fp, k1_fp, 64) == 0,
          "kind 1 unchanged: signed, the owner key is the identity");
    {
        dna_env_view_t *v = calloc(1, sizeof(*v));
        CHECK(v && dna_env_decode(b.env, b.env_len, v) == 0 &&
              v->leg[0].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
              v->leg[1].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
              v->leg[0].auth_len == 1u + NODUS_RT_AUTH_SIGNER_LEN &&
              v->leg[1].auth_len == 1u + NODUS_RT_AUTH_SIGNER_LEN,
              "kind 1: one signer slot per leg");
        free(v);
    }
    {   /* a v2 export text is not v1, a v1 is not v2 */
        nodus_v2_msig_export2_t src, x2;
        memset(&src, 0, sizeof(src));
        memcpy(src.chain32, g_chain32, DNA_CHAIN_ID_LEN);
        src.tip = TIP;
        src.signers = 2;
        src.n_digests = 2;
        src.leg_index[1] = 1;
        src.env = b.env;
        src.env_len = b.env_len;
        char *t = NULL, *t1 = NULL;
        size_t tl = 0, tl1 = 0;
        nodus_v2_msig_export_t x1;
        CHECK(nodus_v2_msig_export2_encode(&src, &t, &tl) ==
                  NODUS_V2_SPEND_OK &&
              nodus_v2_msig_export_parse(t, tl, &x1) ==
                  NODUS_V2_MSIG_ERR_FORMAT,
              "the v1 reader refuses a v2 export");
        uint8_t dg[64];
        memset(dg, 0x33, sizeof(dg));
        CHECK(nodus_v2_msig_export_encode(g_chain32, TIP, 2, dg, b.env,
                                          b.env_len, &t1, &tl1) ==
                  NODUS_V2_SPEND_OK &&
              nodus_v2_msig_export2_parse(t1, tl1, &x2) ==
                  NODUS_V2_MSIG_ERR_FORMAT,
              "the v2 reader refuses a v1 export");
        /* a kind-1 envelope is not a v2 export's shape */
        CHECK(nodus_v2_msig_export2_parse(t, tl, &x2) == NODUS_V2_SPEND_OK,
              "parse");
        dna_env_view_t *v = calloc(1, sizeof(*v));
        nodus_v2_msig_leg_t leg;
        CHECK(v && nodus_v2_msig_legs_open2(&x2, v, &leg) ==
                       NODUS_V2_MSIG_ERR_SHAPE,
              "legs_open2 refuses legs that are not kind 3");
        free(v);
        nodus_v2_msig_export2_free(&x2);
        free(t);
        free(t1);
    }
    nodus_v2_stake_built_free(&b);
    /* a legacy layout has no kind-3 owner */
    req_msig(&r, NODUS_V2_STAKE_OP_STAKE, &c, 2);
    r.generation = 0;
    r.amount = DNAC_SELF_STAKE_AMOUNT;
    r.dest_fp = zero64;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
          "a legacy STAKE with a descriptor is ERR_GEN");
    return 0;
}

int main(void) {
    if (setup() != 0) {
        fprintf(stderr, "setup failed (keys, descriptor, generation 4)\n");
        return 1;
    }
    if (t_stake2() != 0) return 1;
    if (t_rotate() != 0) return 1;           /* after O1: its row */
    if (t_storage() != 0) return 1;
    if (t_below_m() != 0) return 1;
    if (t_foreign() != 0) return 1;
    if (t_all_or_nothing() != 0) return 1;
    if (t_kind1() != 0) return 1;
    printf("test_hf6_msig_owner: %d checks passed\n", g_checks);
    return 0;
}
