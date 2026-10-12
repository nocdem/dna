/**
 * @file nodus/tests/test_hf6_stake.c
 * @brief HF-6 slice 4 — STAKE under generation 4: owner authority, node
 *        consent, the STAKE_MIN bond window and the consensus-key
 *        reservation.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.3 (owner rule), §1.5 (bond: STAKE_MIN <= bond <= INT64_MAX, both
 * verdicts), §2 (STAKE call owner_fp[64] ‖ consensus_pk[2592] ‖
 * consent_sig[4627] ‖ consent_expiry u64 ‖ commission u16 ‖ bond u64 =
 * 7301 B; the consent re-construction contract), §4 (one reservation per
 * consensus key; graduation releases it), §6.1 (consent bytes, ctx
 * "nodus.valbind.v1", expiry rule), §6.2 (validator_id from intent_id),
 * §6.3 (the row); decisions 2026-10-08-kurultay-14-hf6-summary.md (K7 call
 * sizes, K9 STAKE_MIN domain) and 2026-10-09-kurultay-16-hf6-storage-
 * summary.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. HOOK LEVEL — the GEN_STORAGE (= HF-6 generation 4) SYSTEM / CORE
 *     runtimes over fabricated engine facts (a decoded 2-leg envelope, a
 *     verdict, mediated-read results) and REAL ML-DSA-87 consent
 *     signatures:
 *   A1 the plan is [op 7 active_count] [op 13 validator_id] [op 17
 *      SHA3-512(consensus_pk)], in that order; the validator_id it names
 *      equals an INDEPENDENT recomputation SHA3-512("NDS.VALID.v1"+4×0x00 ‖
 *      chain32 ‖ intent_id) (written here from the §6.2 bytes, not through
 *      dna_validator_id_new); length 7300 / 7302 refused by plan and exec;
 *      the legacy (generation-3) runtime refuses the 7301-B call.
 *   A2 kind-1 positive: three effects in canonical order — CREATE op 13
 *      (key validator_id; owner_fp, consensus key, no pending key, self =
 *      bond, ACTIVE since h, commission), CREATE op 17 (key SHA3-512(pk);
 *      validator_id ‖ role 1), SET op 7 (active_count + 1, bound to the
 *      observed version). Kind-3 positive (2-of-3 address as owner).
 *   A3 authority refusals (-1): a kind-1 signer that is not the owner, a
 *      kind-3 descriptor of another address, kind 2.
 *   A4 consent refusals (-1): another ctx, an empty ctx, a ROTATE (op 2)
 *      and a STORAGE_REGISTER (op 3) consent, another chain, another
 *      owner, another key's signature, expiry h - 1 and h + 721; expiry h
 *      and h + 720 accepted.
 *   A5 bond / scalar: STAKE_MIN - 1 refused, STAKE_MIN and INT64_MAX
 *      accepted, INT64_MAX + 1 refused, a commission above the bound
 *      refused. HF-6 slice 8a: the floor is the engine fact
 *      ctx.stake_min — at 10^13 a bond of 10^13 (and one below the
 *      compiled 2M) applies and 10^13 - 1 is refused; a ctx carrying 0
 *      (never engine-filled) is a node fault (-2).
 *   A6 reads: the validator_id present (-1); the key reserved (-1; a
 *      malformed reservation answer -2); no active_count row (-1);
 *      active_count at DNAC_MAX_VALIDATORS (Rule M, -1); a read count
 *      that is not 3 (-2).
 *   A7 the CORE SYSFUND leg pairs with a generation-4 STAKE sibling (plan
 *      = inputs + pool); the read-only describer names the STAKE by its
 *      owner address (rec_v2 0, rec_validator_fp = owner_fp, amount =
 *      bond).
 *  B. ENGINE (twin seeded chains, EVM-enabled build: V0..V6 ACTIVE 10M
 *     since 1, VR RETIRING 10M since 1, every block from 2 carrying the
 *     seven COMMIT votes; param 9 at 2, param 14 at 3, param 18 — the
 *     generation-4 vote (D4) — at 4, so the edge runs in block 3):
 *   B1 after the edge: eight role-1 reservations (seven + VR).
 *   B2 block 4: a kind-1 STAKE (owner KO, key KC1, bond STAKE_MIN)
 *      applies: validators + v2_validator_roles + v2_consensus_keys rows
 *      under validator_id = the recomputation from the engine's intent_id;
 *      active_count + 1; the owner's coin consumed; Σutxo + Σself_stake +
 *      Σtotal_delegated + reward_pool conserved; the CORE invariant holds.
 *   B3 block 5: a kind-3 STAKE (owner = the 2-of-3 address M, funded by
 *      KD) applies with owner_fp = M.
 *   B4 block 6: a STAKE re-using KC1 (reserved by B2's validator) and
 *      block 7: a STAKE using VR's key (reserved by the migrated RETIRING
 *      VR) are REFUSED with the ledger tables byte-identical.
 *   B5 at boundary E VR graduates: UNSTAKED and its reservation released.
 *   B6 block E + 1: a STAKE re-using VR's key APPLIES under a NEW
 *      validator_id (≠ VR's migrated id) and re-reserves the key; the two
 *      twins' databases are byte-identical.
 *   B7 (HF-6 slice 8a) a committed chain_config param-19 (STAKE_MIN) row
 *      of 10^13 effective at E (written into both twins just before the
 *      boundary block E): block E + 2's STAKE with bond 10^13 - 1 is
 *      REFUSED with the ledger byte-identical, block E + 3's with bond
 *      10^13 — below the compiled 2M default — APPLIES (self_stake
 *      10^13); the engine reads the row, not the constant.
 *   B8 (HF-6 slice 8a) an out-of-range param-19 row (10^13 - 1, which no
 *      vote can commit) effective at E + 4 makes block E + 4 FAIL WHOLE
 *      on twin A — a node fault whose reason is env_stake_min's range
 *      check ("STAKE_MIN … no committed row can hold"), never a verdict
 *      and never the default; the tip stays at E + 3.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). B assumes
 * DNAC_EPOCH_LENGTH >= 8 (checked; true for the production 720 and the
 * harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_hf6_stake_* directories, removed at the end (left behind
 * when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Section A fabricates the verdicts and the read results: it proves the
 *    hooks' rule decisions, not the engine's reads (B does those). Its
 *    consent signatures are real.
 *  - B's genesis UTXOs and the RETIRING row are SEEDED
 *    (V2X_SEED_NOT_REAL_UTXOS / _STATUSES); the reward pool is non-zero
 *    by hand (the test_v2_econ device).
 *  - B stops at E + 1: the first boundary after a generation-4 STAKE is
 *    not crossed with a new validator inside a governing snapshot (that
 *    needs the vset v2 of slice 5 — the v1-snapshot bridge resolves an
 *    entry by its MIGRATED id). Boundary E itself is crossed with the two
 *    block-4/5 validators present; they are not seated there by
 *    construction, not by luck: Rule R tenure (active_since + 2E <=
 *    e_start, nodus_witness_committee.c nodus_committee_compute_for_epoch)
 *    excludes them, and a candidate absent from the frozen copy ranks 0
 *    and is skipped, never a fault (same function).
 *  - B7 / B8's param-19 rows are written straight into
 *    chain_config_history (cc_row), not voted: the vote's own rules
 *    (range, grace, generation 4) are test_hf4_params.c's. B7's row is
 *    planted right before a block that touches SYSTEM (the boundary E) so
 *    the committed root absorbs it; B8's fault aborts its block before
 *    phase 8, so the untouched-domain guard is never reached there. A B8
 *    that faulted for another reason would fail its reason check.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_v2_produce.h"   /* 8a: the tip after B8 */
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/cmt_pb.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
#include "dnac/valbind_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define FEE       ((uint64_t)DNAC_MIN_FEE_RAW)
#define TEN_M     ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define SMIN      ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define MIL       (1000000ULL * 100000000ULL)        /* 1M NODUS raw     */
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN   ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN   ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define AUTH1     (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define CALL_LEN  7301u           /* design §2 (K7): 64+2592+4627+8+2+8 */

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STATS      7u
#define OP_VAL2       13u
#define OP_KEYRES     17u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_PPK_OFF    (128u + 2592u)
#define V2_KEFF_OFF   (128u + 2u * 2592u)             /* 5312 */
#define V2_SELF_OFF   (V2_KEFF_OFF + 8u)
#define V2_TOT_OFF    (V2_SELF_OFF + 8u)
#define V2_EXT_OFF    (V2_TOT_OFF + 8u)
#define V2_COMM_OFF   (V2_EXT_OFF + 8u)
#define V2_PCOMM_OFF  (V2_COMM_OFF + 2u)
#define V2_PEFF_OFF   (V2_PCOMM_OFF + 2u)
#define V2_STAT_OFF   (V2_PEFF_OFF + 8u)
#define V2_SINCE_OFF  (V2_STAT_OFF + 1u)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static uint16_t get16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the genesis committee, VR the RETIRING row; KO a single-key
 * owner, KD a funder, KX a foreign key, K1..K3 the multisig keys, KC1 /
 * KC2 consensus keys; KC3 the HF-6 slice 8a consensus key (B7) */
enum { V0, V1, V2, V3, V4, V5, V6, VR, KO, KD, KX, K1, K2, K3, KC1, KC2,
       KC3, N_KEYS };
#define N_VAL 7
static sk_key_t g_k[N_KEYS];
static uint8_t  g_vaddr[N_VAL][32];
static int32_t  g_vflag[N_VAL];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x91 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    for (int i = 0; i < N_VAL; i++) {
        if (nodus_chain_config_derive_witness_id(g_k[i].pk, g_vaddr[i]) != 0)
            return -1;
        g_vflag[i] = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    return 0;
}

/* ══ the multisig descriptor M = 2-of-3 {K1, K2, K3} ══════════════════ */

static uint8_t g_dm[DNA_MSIG_MAX_DESC_LEN];
static size_t  g_dm_len;
static uint8_t g_am[64];                       /* address of M            */
static uint8_t g_an[64];                       /* a second (foreign) one  */

static void sort_keys(const int *ks, int n, int *ord) {
    for (int i = 0; i < n; i++) ord[i] = ks[i];
    for (int a = 1; a < n; a++)
        for (int b = a; b > 0 &&
             memcmp(g_k[ord[b - 1]].pk, g_k[ord[b]].pk, PK_LEN) > 0; b--) {
            int t = ord[b];
            ord[b] = ord[b - 1];
            ord[b - 1] = t;
        }
}

static int desc_make(void) {
    static uint8_t keys[3 * 2592];
    const int km[3] = { K1, K2, K3 };
    int ord[3];
    sort_keys(km, 3, ord);
    for (int i = 0; i < 3; i++)
        memcpy(keys + (size_t)i * PK_LEN, g_k[ord[i]].pk, PK_LEN);
    if (dna_msig_desc_encode(2, 3, keys, g_dm, DNA_MSIG_MAX_DESC_LEN,
                             &g_dm_len) != 0)
        return -1;
    if (dna_msig_address(g_dm, g_dm_len, g_am) != 0) return -1;
    memset(g_an, 0xA7, sizeof(g_an));
    return 0;
}

/* the kind-3 auth blob: K1 + K2 sign `digest` (zeros when NULL — the
 * first pass), one descriptor M. @return length / 0. */
static size_t k3_blob(uint8_t *dst, size_t cap, const uint8_t *digest) {
    const int two[2] = { K1, K2 };
    int ord[2];
    sort_keys(two, 2, ord);
    size_t need = 1 + 2 * SGN_LEN + 1 + 2 + g_dm_len;
    if (need > cap) return 0;
    size_t off = 0;
    dst[off++] = 2;
    for (int i = 0; i < 2; i++) {
        memcpy(dst + off, g_k[ord[i]].pk, PK_LEN);
        memset(dst + off + PK_LEN, 0, SIG_LEN);
        if (digest) {
            size_t sl = 0;
            if (qgp_dsa87_sign(dst + off + PK_LEN, &sl, digest, 64,
                               g_k[ord[i]].sk) != 0)
                return 0;
        }
        off += SGN_LEN;
    }
    dst[off++] = 1;
    dst[off++] = (uint8_t)(g_dm_len >> 8);
    dst[off++] = (uint8_t)g_dm_len;
    memcpy(dst + off, g_dm, g_dm_len);
    off += g_dm_len;
    return off == need ? off : 0;
}

/* ══ the generation-4 STAKE call ══════════════════════════════════════ */

/* How the consent is formed (A4 variants). */
enum {
    CS_OK = 0,        /* the §6.1 message, ctx "nodus.valbind.v1"        */
    CS_CTX_OTHER,     /* ctx "nodus.valbind.v2"                          */
    CS_CTX_EMPTY,     /* qgp_dsa87_sign: empty ctx                       */
    CS_OP_ROTATE,     /* op 2 with a non-zero subject                    */
    CS_OP_STORAGE,    /* op 3 (STORAGE_REGISTER)                         */
    CS_CHAIN_OTHER,   /* another chain id                                */
    CS_OWNER_OTHER,   /* another owner_fp in the signed message          */
    CS_KEY_OTHER      /* signed by another key's sk                      */
};

/* owner_fp ‖ consensus_pk ‖ consent_sig ‖ expiry ‖ commission ‖ bond.
 * @return CALL_LEN / 0 on a setup failure. */
static uint32_t stake2_call(uint8_t *dst, const uint8_t chain32[32],
                            const uint8_t owner[64], int ckey,
                            uint64_t expiry, uint16_t bps, uint64_t bond,
                            int variant) {
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    uint8_t chain[32], own[64], subj[64];
    uint8_t op = DNA_VALBIND_OP_STAKE;
    memcpy(chain, chain32, 32);
    memcpy(own, owner, 64);
    memset(subj, 0, sizeof(subj));
    if (variant == CS_CHAIN_OTHER) chain[0] ^= 0x01;
    if (variant == CS_OWNER_OTHER) own[0] ^= 0x01;
    if (variant == CS_OP_ROTATE) {
        op = DNA_VALBIND_OP_ROTATE;
        memset(subj, 0x5E, sizeof(subj));
    }
    if (variant == CS_OP_STORAGE) op = DNA_VALBIND_OP_STORAGE_REGISTER;
    if (dna_valbind_consent_msg(msg, chain, op, subj, own, g_k[ckey].pk,
                                expiry) != 0)
        return 0;
    uint8_t *sig = dst + 64 + PK_LEN;
    size_t sl = 0;
    int rc;
    if (variant == CS_CTX_OTHER)
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg),
                                (const uint8_t *)"nodus.valbind.v2", 16,
                                g_k[ckey].sk);
    else if (variant == CS_CTX_EMPTY)
        rc = qgp_dsa87_sign(sig, &sl, msg, sizeof(msg), g_k[ckey].sk);
    else
        rc = dna_valbind_consent_sign(sig, &sl, msg,
                                      g_k[variant == CS_KEY_OTHER ? KX
                                                                  : ckey].sk);
    if (rc != 0 || sl != SIG_LEN) return 0;
    memcpy(dst, owner, 64);
    memcpy(dst + 64, g_k[ckey].pk, PK_LEN);
    size_t off = 64 + PK_LEN + SIG_LEN;
    put64(dst + off, expiry);         off += 8;
    dst[off++] = (uint8_t)(bps >> 8);
    dst[off++] = (uint8_t)bps;
    put64(dst + off, bond);           off += 8;
    return off == CALL_LEN ? CALL_LEN : 0;
}

/* the INDEPENDENT §6.2 recomputation: SHA3-512("NDS.VALID.v1" + 4 × 0x00
 * ‖ chain32 ‖ intent_id) — written from the design bytes */
static int vid_expect(const uint8_t chain32[32], const uint8_t intent[64],
                      uint8_t out[64]) {
    uint8_t pre[16 + 32 + 64];
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALID.v1", 12);
    memcpy(pre + 16, chain32, 32);
    memcpy(pre + 48, intent, 64);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66u;
}

/* ══ A. hook level ═══════════════════════════════════════════════════ */

typedef struct {
    uint8_t  fund[66];
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

static int hk_build(hk_env_t *e, const uint8_t *call, uint32_t call_len,
                    uint8_t sys_kind) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_STAKE;
    legs[0].hdr.ruleset_version = 9;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = sys_kind;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = e->auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = 7;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = e->fund;
    legs[1].auth_data = e->auth[1];
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view);
}

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void ctx_reset(uint64_t height) {
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_chain, 0x4C, sizeof(g_chain));
    memset(g_intent, 0x5D, sizeof(g_intent));
    memset(g_dig, 0x3C, sizeof(g_dig));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = height;
    g_ctx.epoch = height / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
    /* HF-6 slice 8a: the engine facts every ctx carries — the param-19 /
     * param-21 values with no row (the engine's env_stake_min /
     * env_storage_bond answer these defaults) */
    g_ctx.stake_min = SMIN;
    g_ctx.storage_bond = (uint64_t)DNAC_HF6_STORAGE_BOND_DEFAULT;
}

static void av_k1(int key) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[key].fp, 64);
}

static void av_k3(const uint8_t addr[64]) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 2;
    memcpy(g_av.signer_fp[0], g_k[K1].fp, 64);
    memcpy(g_av.signer_fp[1], g_k[K2].fp, 64);
    g_av.n_msig = 1;
    memcpy(g_av.msig_addr[0], addr, 64);
    g_av.msig_satisfied[0] = 1;
    g_av.msig_signers_in_desc = 1u;
}

static nodus_rt_read_res_t g_reads[4];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* the three reads of a STAKE that may apply: active_count `n`, the id
 * absent, the key absent */
static void rd_ok(uint64_t n) {
    memset(g_reads, 0, sizeof(g_reads));
    g_reads[0].present = 1;
    g_reads[0].value_len = 8;
    put64(g_reads[0].value, n);
}

static int sys_exec(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                    uint16_t n_reads, dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, &e->view, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int sys_plan(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                    nodus_rt_read_req_t *rq, uint16_t *n) {
    return nodus_rt_system_read_plan(rt, &e->view, 0, &g_ctx, rq,
                                     NODUS_RT_MAX_READS, n);
}

/* build + exec one variant with the "may apply" reads; @return exec rc */
static int try_stake(const nodus_domain_runtime_t *s4, hk_env_t *e,
                     uint8_t *call, const uint8_t owner[64], int ckey,
                     uint64_t expiry, uint16_t bps, uint64_t bond,
                     int variant, uint8_t kind) {
    if (stake2_call(call, g_chain, owner, ckey, expiry, bps, bond,
                    variant) != CALL_LEN)
        return -100;
    if (hk_build(e, call, CALL_LEN, kind) != 0) return -101;
    rd_ok(7);
    return sys_exec(s4, e, 3, NULL);
}

static int t_hooks(void) {
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s4 && s3 && c4, "generations 3 and 4 compiled");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (op 13 CREATE and op 17 "
          "pass the adapter's dead-op rule)");

    static hk_env_t e;
    static uint8_t call[CALL_LEN + 8];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    dna_effect_view_t ev;
    const uint64_t H = 9;
    const uint64_t EXP = H + 100;
    ctx_reset(H);

    uint8_t vid[64], kh[64];
    CHECK(vid_expect(g_chain, g_intent, vid) == 0, "vid recomputation");
    CHECK(qgp_sha3_512(g_k[KC1].pk, PK_LEN, kh) == 0, "key hash");

    /* ── A1. the plan and the length ───────────────────────────────── */
    CHECK(stake2_call(call, g_chain, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK)
          == CALL_LEN, "a 7301-byte call");
    CHECK(hk_build(&e, call, CALL_LEN, 1) == 0, "env");
    CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 3, "STAKE: 3 reads");
    CHECK(rq[0].op_id == OP_STATS && rq[0].key_len == 1 &&
          rq[0].key[0] == 1u, "read 0: op 7 active_count");
    CHECK(rq[1].op_id == OP_VAL2 && rq[1].key_len == 64 &&
          memcmp(rq[1].key, vid, 64) == 0,
          "read 1: op 13 keyed by the independently recomputed "
          "validator_id (§6.2)");
    CHECK(rq[2].op_id == OP_KEYRES && rq[2].key_len == 64 &&
          memcmp(rq[2].key, kh, 64) == 0,
          "read 2: op 17 keyed by SHA3-512(consensus_pk)");
    {
        uint8_t id2[64];
        CHECK(dna_validator_id_new(id2, g_chain, g_intent) == 0 &&
              memcmp(id2, vid, 64) == 0,
              "the slice-1 codec agrees with the recomputation");
    }
    for (int d = -1; d <= 1; d += 2) {
        CHECK(hk_build(&e, call, (uint32_t)((int)CALL_LEN + d), 1) == 0,
              "env ± 1");
        av_k1(KO);
        rd_ok(7);
        CHECK(sys_plan(s4, &e, rq, &n) == -1, "7301 ± 1 refused (plan)");
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "7301 ± 1 refused (exec)");
    }
    CHECK(hk_build(&e, call, CALL_LEN, 1) == 0, "env");
    CHECK(sys_plan(s3, &e, rq, &n) == -1,
          "the generation-3 runtime refuses the 7301-B STAKE");

    /* ── A2. positives ─────────────────────────────────────────────── */
    av_k1(KO);
    rd_ok(7);
    CHECK(sys_exec(s4, &e, 3, &ev) == 0 && ev.effect_count == 3,
          "kind-1 owner: applies, three effects");
    {
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        const uint8_t *v1 = ev.buf + ev.val_off[1];
        const uint8_t *v2 = ev.buf + ev.val_off[2];
        CHECK(ev.eff[0].op_id == OP_VAL2 &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[0], vid, 64) == 0 &&
              ev.eff[0].value_len == V2_REC_LEN,
              "effect 0: CREATE op 13 under validator_id");
        CHECK(memcmp(v0, vid, 64) == 0 &&
              memcmp(v0 + V2_OWNER_OFF, g_k[KO].fp, 64) == 0 &&
              memcmp(v0 + V2_CPK_OFF, g_k[KC1].pk, PK_LEN) == 0 &&
              all_zero(v0 + V2_PPK_OFF, PK_LEN) &&
              get64(v0 + V2_KEFF_OFF) == 0 &&
              get64(v0 + V2_SELF_OFF) == SMIN &&
              get64(v0 + V2_TOT_OFF) == 0 && get64(v0 + V2_EXT_OFF) == 0 &&
              get16(v0 + V2_COMM_OFF) == 500 &&
              get16(v0 + V2_PCOMM_OFF) == 0 && get64(v0 + V2_PEFF_OFF) == 0 &&
              v0[V2_STAT_OFF] == DNAC_VALIDATOR_ACTIVE &&
              get64(v0 + V2_SINCE_OFF) == H,
              "the §6.3 row: owner, consensus key, no pending key, self = "
              "bond, ACTIVE since h, commission");
        CHECK(ev.eff[1].op_id == OP_KEYRES &&
              ev.eff[1].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[1].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              memcmp(ev.buf + ev.key_off[1], kh, 64) == 0 &&
              ev.eff[1].value_len == 65 && memcmp(v1, vid, 64) == 0 &&
              v1[64] == 1u,
              "effect 1: CREATE op 17 — SHA3-512(pk) -> validator_id, "
              "role 1");
        CHECK(ev.eff[2].op_id == OP_STATS &&
              ev.eff[2].effect_kind == DNA_EFFECT_SET &&
              ev.eff[2].precond_tag == DNA_EFFECT_PRE_EXISTS_VERSION &&
              ev.eff[2].expected_version == 7 && get64(v2) == 8,
              "effect 2: active_count 7 -> 8, bound to the observed value");
    }
    CHECK(try_stake(s4, &e, call, g_am, KC2, EXP, 0, SMIN, CS_OK, 3) == -1,
          "kind-3 leg with a kind-1 verdict is refused");
    CHECK(stake2_call(call, g_chain, g_am, KC2, EXP, 0, SMIN, CS_OK)
          == CALL_LEN && hk_build(&e, call, CALL_LEN, 3) == 0, "kind-3 env");
    av_k3(g_am);
    rd_ok(7);
    CHECK(sys_exec(s4, &e, 3, &ev) == 0 &&
          memcmp(ev.buf + ev.val_off[0] + V2_OWNER_OFF, g_am, 64) == 0,
          "kind-3 owner (2-of-3 address): applies, owner_fp = the address");

    /* ── A3. authority ─────────────────────────────────────────────── */
    av_k1(KX);
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK, 1)
          == -1, "kind 1 by a non-owner refused");
    av_k3(g_an);
    CHECK(try_stake(s4, &e, call, g_am, KC1, EXP, 500, SMIN, CS_OK, 3)
          == -1, "kind 3 with another address refused");
    av_k1(KO);
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK, 2)
          == -1, "kind 2 refused");

    /* ── A4. consent ───────────────────────────────────────────────── */
    {
        static const struct { int v; const char *what; } bad[] = {
            { CS_CTX_OTHER,   "another FIPS 204 ctx" },
            { CS_CTX_EMPTY,   "an empty ctx" },
            { CS_OP_ROTATE,   "a ROTATE (op 2) consent" },
            { CS_OP_STORAGE,  "a STORAGE_REGISTER (op 3) consent" },
            { CS_CHAIN_OTHER, "a consent for another chain" },
            { CS_OWNER_OTHER, "a consent for another owner" },
            { CS_KEY_OTHER,   "another key's signature" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            av_k1(KO);
            int rc = try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500,
                               SMIN, bad[i].v, 1);
            if (rc != -1) {
                fprintf(stderr, "consent variant: %s -> %d\n", bad[i].what,
                        rc);
            }
            CHECK(rc == -1, "a bad consent is a verdict (-1)");
        }
        av_k1(KO);
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, H - 1, 500, SMIN,
                        CS_OK, 1) == -1, "expiry h - 1 refused");
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, H + 721, 500, SMIN,
                        CS_OK, 1) == -1, "expiry h + 721 refused");
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, H, 500, SMIN,
                        CS_OK, 1) == 0, "expiry h accepted");
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, H + 720, 500, SMIN,
                        CS_OK, 1) == 0, "expiry h + 720 accepted");
    }

    /* ── A5. bond and commission ───────────────────────────────────── */
    av_k1(KO);
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN - 1,
                    CS_OK, 1) == -1, "bond STAKE_MIN - 1 refused");
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK, 1)
          == 0, "bond STAKE_MIN accepted");
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, TEN_M, CS_OK, 1)
          == 0, "bond above STAKE_MIN accepted (the old exact 10M rule is "
          "gone)");
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500,
                    (uint64_t)INT64_MAX, CS_OK, 1) == 0,
          "bond INT64_MAX accepted");
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500,
                    (uint64_t)INT64_MAX + 1u, CS_OK, 1) == -1,
          "bond INT64_MAX + 1 refused (a verdict, never a fault)");
    CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP,
                    (uint16_t)(DNAC_COMMISSION_BPS_MAX + 1), SMIN, CS_OK, 1)
          == -1, "commission above the bound refused");
    /* HF-6 slice 8a: the floor is the ENGINE FACT ctx.stake_min (param 19
     * at the item's height), not a compiled constant: at the K9 lower end
     * a bond of 100k NODUS applies and one raw unit less is refused; a
     * ctx carrying 0 (never engine-filled) is a NODE fault, not "no
     * floor" */
    {
        const uint64_t MN = (uint64_t)DNAC_HF6_STAKE_MIN_MIN;
        g_ctx.stake_min = MN;
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, MN, CS_OK,
                        1) == 0, "stake_min fact 10^13: bond 10^13 accepted");
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, MN - 1u,
                      CS_OK, 1) == -1,
              "stake_min fact 10^13: bond 10^13 - 1 refused");
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN - 1u,
                        CS_OK, 1) == 0,
              "a bond below the compiled default applies under a lower "
              "voted floor");
        g_ctx.stake_min = 0;
        CHECK(try_stake(s4, &e, call, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK,
                        1) == -2, "stake_min 0 (not engine-filled): -2");
        g_ctx.stake_min = SMIN;
    }

    /* ── A6. reads ─────────────────────────────────────────────────── */
    CHECK(stake2_call(call, g_chain, g_k[KO].fp, KC1, EXP, 500, SMIN, CS_OK)
          == CALL_LEN && hk_build(&e, call, CALL_LEN, 1) == 0, "env");
    av_k1(KO);
    rd_ok(7);
    g_reads[1].present = 1;
    g_reads[1].value_len = V2_REC_LEN;
    CHECK(sys_exec(s4, &e, 3, NULL) == -1, "the validator_id exists: -1");
    rd_ok(7);
    g_reads[2].present = 1;
    g_reads[2].value_len = 65;
    memset(g_reads[2].value, 0x77, 64);
    g_reads[2].value[64] = 1;
    CHECK(sys_exec(s4, &e, 3, NULL) == -1,
          "the consensus key is reserved by another validator: -1 (§4)");
    g_reads[2].value_len = 64;
    CHECK(sys_exec(s4, &e, 3, NULL) == -2,
          "a reservation answer outside the adapter contract: -2");
    rd_ok(7);
    g_reads[0].present = 0;
    CHECK(sys_exec(s4, &e, 3, NULL) == -1, "no active_count row: -1");
    rd_ok((uint64_t)DNAC_MAX_VALIDATORS);
    CHECK(sys_exec(s4, &e, 3, NULL) == -1, "Rule M: the 129th refused");
    rd_ok((uint64_t)DNAC_MAX_VALIDATORS - 1u);
    CHECK(sys_exec(s4, &e, 3, NULL) == 0, "the 128th applies");
    rd_ok(7);
    CHECK(sys_exec(s4, &e, 2, NULL) == -2, "two reads: a node fault");

    /* ── A7. CORE pairing and the describer ────────────────────────── */
    {
        nodus_rt_read_req_t cr[NODUS_RT_MAX_READS];
        uint16_t cn = 0;
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-4 CORE: the STAKE sibling plans inputs + pool");
        nodus_rt_leg_desc_t d;
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_STAKE && d.rec_v2 == 0 &&
              memcmp(d.rec_validator_fp, g_k[KO].fp, 64) == 0 &&
              memcmp(d.rec_dest_fp, g_k[KO].fp, 64) == 0 &&
              d.rec_amount == SMIN && d.rec_commission_bps == 500,
              "describer: the STAKE by its owner address and its bond");
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

typedef struct { int key; uint8_t seed; uint64_t amount; } coin_def_t;
enum { C1, C2, C3, C4, C5, C6, C7, C8, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [C1] = { KO, 0x71, 0 },   /* kind-1 STAKE KC1, block 4              */
    [C2] = { KD, 0x72, 0 },   /* kind-3 STAKE KC2 (3M), block 5         */
    [C3] = { KO, 0x73, 0 },   /* KC1 again, block 6 — refused           */
    [C4] = { KO, 0x74, 0 },   /* VR's key before graduation — refused   */
    [C5] = { KO, 0x75, 0 },   /* VR's key after graduation, E + 1       */
    [C6] = { KO, 0x76, 0 },   /* 8a: bond 10^13 - 1 at E + 2 — refused  */
    [C7] = { KO, 0x77, 0 },   /* 8a: bond 10^13 at E + 3 — applies      */
    [C8] = { KO, 0x78, 0 },   /* 8a: the fault probe at E + 4           */
};
static uint64_t g_amt[N_COINS];
static uint8_t  g_nul[N_COINS][64];

#define H9   2u
#define HE   3u
#define H14  4u       /* param 18: the gen-4 edge runs in block H14 − 1 */

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[COINS[c].key].hex, 128);
    memset(pre + 128, COINS[c].seed, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_bind_text(st, 2, g_k[COINS[c].key].hex, 128,
                          SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)g_amt[c]) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (sqlite3_bind_int64(st, 1, (sqlite3_int64)param) == SQLITE_OK &&
        sqlite3_bind_int64(st, 2, (sqlite3_int64)value) == SQLITE_OK &&
        sqlite3_bind_int64(st, 3, (sqlite3_int64)effective) == SQLITE_OK &&
        sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce) == SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seed_val(nodus_witness_t *w, int k, uint8_t status) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PK_LEN);
    v.self_stake = TEN_M;
    v.commission_bps = 500;
    v.status = status;
    v.active_since_block = 1;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    return nodus_validator_insert(w, &v);
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_stake_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x6F, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
               H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, H14, 13) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i, (uint8_t)DNAC_VALIDATOR_ACTIVE) != 0) return -1;
        total += TEN_M;
    }
    if (seed_val(w, VR, (uint8_t)DNAC_VALIDATOR_RETIRING) != 0) return -1;
    total += TEN_M;
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c) != 0) return -1;
        total += g_amt[c];
    }
    {
        /* not a real genesis: a non-zero reward pool (the test_v2_econ
         * device) and spendable coins; supply = bonds + coins + pool */
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)(total + RPOOL),
                 (unsigned long long)RPOOL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS | V2X_SEED_NOT_REAL_STATUSES);
    return v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, NULL);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = N_VAL;
    }
}

/* one block on both twins (0 or 1 envelope); the item codes agree and the
 * committed global roots agree. *code = the item's code. 0 / -1. */
static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const uint8_t *env, size_t len, uint32_t *code) {
    nodus_v2_envelope_t v[1] = { { env, len } };
    nodus_v2_tx_result_t ra[1], rb[1];
    nodus_v2_block_t ba, bb;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, env ? v : NULL, env ? 1 : 0);
    mk_block(&bb, h, env ? v : NULL, env ? 1 : 0);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 1;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 1;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    if (env && ra[0].code != rb[0].code) return -1;
    if (code) *code = env ? ra[0].code : 0;
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0) {
        fprintf(stderr, "block %llu: twin global roots differ\n",
                (unsigned long long)h);
        return -1;
    }
    return 0;
}

static int run_to(fixture_t *a, fixture_t *b, uint64_t *h, uint64_t last) {
    while (*h < last) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

/* A generation-4 STAKE envelope against the registry's CURRENT manifests,
 * REALLY signed (two passes): the SYSTEM leg kind 1 by `sys_signer` (>= 0)
 * or kind 3 over M by K1 + K2 (`sys_signer` < 0); the CORE SYSFUND leg
 * kind 1 by the coin's owner, spending coin `c` entirely (bond + FEE).
 * The consent is formed BEFORE the envelope (it does not commit to the
 * intent). *intent_out = the engine-derived intent_id. @return 0 / -1. */
static int st_env(nodus_witness_t *w, uint64_t height, const uint8_t *call,
                  int c, int sys_signer, uint8_t **out, size_t *out_len,
                  uint8_t intent_out[64]) {
    static uint8_t fund[66];
    static uint8_t sys_auth[32 * 1024];
    static uint8_t core_auth[AUTH1];
    dna_domain_manifest_t sys, core;
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0
        || nodus_witness_v2_chain_id(w, chain32) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul[c]);
    size_t sys_alen = 0;
    if (sys_signer >= 0) {
        sys_alen = AUTH1;
        memset(sys_auth, 0, AUTH1);
    } else {
        sys_alen = k3_blob(sys_auth, sizeof(sys_auth), NULL);
        if (sys_alen == 0) return -1;
    }
    memset(core_auth, 0, sizeof(core_auth));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_STAKE;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = sys_signer >= 0
                                ? NODUS_RT_AUTHKIND_DSA87_MULTI_V1
                                : NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    legs[0].hdr.call_len = CALL_LEN;
    legs[0].hdr.auth_len = (uint32_t)sys_alen;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = sys_auth;
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH1;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = core_auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        if (sys_signer >= 0) {
            sys_auth[0] = 1;
            memcpy(sys_auth + 1, g_k[sys_signer].pk, PK_LEN);
            if (qgp_dsa87_sign(sys_auth + 1 + PK_LEN, &sl, pf->auth_digest[0],
                               64, g_k[sys_signer].sk) != 0)
                break;
        } else if (k3_blob(sys_auth, sizeof(sys_auth), pf->auth_digest[0])
                   != sys_alen) {
            break;
        }
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[COINS[c].key].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[COINS[c].key].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        memcpy(intent_out, pf->intent_id, 64);
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused STAKE must leave untouched */
static int ledger_digest(nodus_witness_t *w, uint8_t out[64]) {
    static const char *const q[] = {
        "SELECT * FROM validators ORDER BY pubkey_hash",
        "SELECT * FROM v2_validator_roles ORDER BY validator_id",
        "SELECT * FROM v2_consensus_keys ORDER BY consensus_pk_hash",
        "SELECT * FROM delegations ORDER BY delegator_hash, validator_hash",
        "SELECT * FROM utxo_set ORDER BY nullifier",
        "SELECT * FROM supply_tracking ORDER BY id",
        "SELECT * FROM validator_stats ORDER BY key",
    };
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    int ok = 0;
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]) && ok == 0; i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, q[i], -1, &st, NULL) != SQLITE_OK) {
            ok = -1;
            break;
        }
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && ok == 0) {
            int nc = sqlite3_column_count(st);
            for (int c = 0; c < nc && ok == 0; c++) {
                int t = sqlite3_column_type(st, c);
                const void *p = NULL;
                int n = 0;
                sqlite3_int64 iv = 0;
                if (t == SQLITE_INTEGER) {
                    iv = sqlite3_column_int64(st, c);
                    p = &iv;
                    n = (int)sizeof(iv);
                } else if (t != SQLITE_NULL) {
                    p = sqlite3_column_blob(st, c);
                    n = sqlite3_column_bytes(st, c);
                }
                size_t need = len + 1 + 4 + (size_t)n;
                if (need > cap) {
                    size_t nc2 = cap;
                    while (nc2 < need) nc2 *= 2;
                    uint8_t *g = realloc(buf, nc2);
                    if (!g) { ok = -1; break; }
                    buf = g;
                    cap = nc2;
                }
                buf[len++] = (uint8_t)t;
                buf[len++] = (uint8_t)(n >> 24);
                buf[len++] = (uint8_t)(n >> 16);
                buf[len++] = (uint8_t)(n >> 8);
                buf[len++] = (uint8_t)n;
                if (n > 0 && p) memcpy(buf + len, p, (size_t)n);
                len += (size_t)n;
            }
        }
        if (rc != SQLITE_DONE && rc != SQLITE_ROW) ok = -1;
        sqlite3_finalize(st);
    }
    if (ok == 0 && qgp_sha3_512(buf, len, out) != 0) ok = -1;
    free(buf);
    return ok;
}

static int q_u64(nodus_witness_t *w, const char *sql, const uint8_t *b1,
                 int l1, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if (!b1 || sqlite3_bind_blob(st, 1, b1, l1, SQLITE_TRANSIENT) ==
                   SQLITE_OK)
        rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* Σutxo + Σself_stake + Σtotal_delegated + reward_pool — the value a
 * STAKE only MOVES (utxo → self_stake, fee → pool) */
static int value_sum(nodus_witness_t *w, uint64_t *out) {
    uint64_t u = 0, s = 0, p = 0;
    if (q_u64(w, "SELECT COALESCE(SUM(amount), 0) FROM utxo_set", NULL, 0,
              &u) != 0 ||
        q_u64(w, "SELECT COALESCE(SUM(self_stake), 0) + "
              "COALESCE(SUM(total_delegated), 0) FROM validators", NULL, 0,
              &s) != 0 ||
        q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              NULL, 0, &p) != 0)
        return -1;
    *out = u + s + p;
    return 0;
}

static int core_invariant(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rt) != 0 || !rt
        || !rt->invariant)
        return -1;
    return rt->invariant(rt, w);
}

/* the reservation of `pk`: 0 found (vid, role) / 1 absent / -1 */
static int key_of(nodus_witness_t *w, const uint8_t *pk, uint8_t vid[64],
                  uint8_t *role) {
    uint8_t kh[64];
    if (qgp_sha3_512(pk, PK_LEN, kh) != 0) return -1;
    return nodus_validator_v2_key_get(w, kh, vid, role);
}

static int t_engine(void) {
    fixture_t A, B;
    static uint8_t call[CALL_LEN];
    uint8_t *e = NULL, intent[64], chain32[DNA_CHAIN_ID_LEN];
    uint8_t vid1[64], vid2[64], vidr[64], vidr2[64], got[64], role = 0;
    uint8_t d0[64], d1[64];
    size_t l = 0;
    uint64_t h = 0, x = 0, cnt0 = 0, sum0 = 0, sum1 = 0;
    uint32_t code = 0;

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    g_amt[C1] = SMIN + FEE;
    g_amt[C2] = 3 * MIL + FEE;
    g_amt[C3] = SMIN + FEE;
    g_amt[C4] = SMIN + FEE;
    g_amt[C5] = SMIN + FEE;
    g_amt[C6] = (uint64_t)DNAC_HF6_STAKE_MIN_MIN - 1u + FEE;
    g_amt[C7] = (uint64_t)DNAC_HF6_STAKE_MIN_MIN + FEE;
    g_amt[C8] = SMIN + FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── B1. the edge reserves every not-UNSTAKED key ──────────────── */
    CHECK(run_to(&A, &B, &h, H14 - 1) == 0, "blocks 1..H14-1 (the edge)");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_consensus_keys", NULL, 0, &x)
          == 0 && x == N_VAL + 1, "eight reservations (seven + VR)");
    CHECK(dna_validator_id_migrated(vidr, chain32, g_k[VR].pk) == 0 &&
          key_of(A.w, g_k[VR].pk, got, &role) == 0 &&
          memcmp(got, vidr, 64) == 0 && role == 1,
          "VR's key reserved to its migrated validator_id");

    /* ── B2. block 4: a kind-1 STAKE applies ───────────────────────── */
    CHECK(q_u64(A.w, "SELECT value FROM validator_stats WHERE key = "
                "'active_count'", NULL, 0, &cnt0) == 0, "active_count");
    CHECK(value_sum(A.w, &sum0) == 0, "value before");
    CHECK(stake2_call(call, chain32, g_k[KO].fp, KC1, H14 + 100, 300, SMIN,
                      CS_OK) == CALL_LEN, "call");
    CHECK(st_env(A.w, H14, call, C1, KO, &e, &l, intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, H14, e, l, &code) == 0 &&
          code == NODUS_V2_TX_OK, "block 4: the kind-1 STAKE applies");
    free(e); e = NULL;
    h = H14;
    CHECK(vid_expect(chain32, intent, vid1) == 0, "vid recomputation");
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        CHECK(r != NULL, "alloc");
        int ok = nodus_validator_v2_get(A.w, vid1, r) == 0 &&
                 memcmp(r->owner_fp, g_k[KO].fp, 64) == 0 &&
                 memcmp(r->rec.pubkey, g_k[KC1].pk, PK_LEN) == 0 &&
                 all_zero(r->pending_consensus_pubkey, PK_LEN) &&
                 r->consensus_key_effective_epoch == 0 &&
                 r->rec.self_stake == SMIN && r->rec.total_delegated == 0 &&
                 r->rec.status == DNAC_VALIDATOR_ACTIVE &&
                 r->rec.active_since_block == H14 &&
                 r->rec.commission_bps == 300;
        free(r);
        CHECK(ok, "validators + v2_validator_roles rows under the "
              "recomputed validator_id (§6.2, §6.3)");
    }
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, vid1, 64) == 0 && role == 1,
          "KC1 reserved to it, role 1");
    CHECK(q_u64(A.w, "SELECT value FROM validator_stats WHERE key = "
                "'active_count'", NULL, 0, &x) == 0 && x == cnt0 + 1,
          "active_count + 1");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1",
                g_nul[C1], 64, &x) == 0 && x == 0,
          "the owner's coin is consumed (bond locked by the CORE leg)");
    CHECK(value_sum(A.w, &sum1) == 0 && sum1 == sum0,
          "Σutxo + Σstake + pool conserved (bond utxo -> self_stake, fee "
          "-> pool)");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "the CORE supply invariant holds on both twins");

    /* ── B3. block 5: a kind-3 STAKE (owner = M) applies ───────────── */
    CHECK(stake2_call(call, chain32, g_am, KC2, H14 + 100, 0, 3 * MIL,
                      CS_OK) == CALL_LEN, "call");
    CHECK(st_env(A.w, 5, call, C2, -1, &e, &l, intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, 5, e, l, &code) == 0 && code == NODUS_V2_TX_OK,
          "block 5: the kind-3 STAKE applies");
    free(e); e = NULL;
    h = 5;
    CHECK(vid_expect(chain32, intent, vid2) == 0 &&
          q_u64(A.w, "SELECT self_stake FROM validators WHERE pubkey_hash "
                "= ?1", vid2, 64, &x) == 0 && x == 3 * MIL,
          "a 3M bond (above STAKE_MIN)");
    {
        uint8_t own[64];
        CHECK(nodus_rt_native_validator_owner(A.w, vid2, own) == 0 &&
              memcmp(own, g_am, 64) == 0, "owner_fp = the 2-of-3 address");
    }

    /* ── B4. reserved keys are refused, the ledger untouched ───────── */
    CHECK(stake2_call(call, chain32, g_k[KO].fp, KC1, H14 + 100, 300, SMIN,
                      CS_OK) == CALL_LEN, "call");
    CHECK(st_env(A.w, 6, call, C3, KO, &e, &l, intent) == 0, "envelope");
    CHECK(ledger_digest(A.w, d0) == 0, "ledger before");
    CHECK(apply_both(&A, &B, 6, e, l, &code) == 0 && code != NODUS_V2_TX_OK,
          "block 6: KC1 again (reserved by the block-4 validator) refused");
    free(e); e = NULL;
    h = 6;
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "the ledger tables are byte-identical across the block");
    CHECK(stake2_call(call, chain32, g_k[KO].fp, VR, H14 + 100, 300, SMIN,
                      CS_OK) == CALL_LEN, "call");
    CHECK(st_env(A.w, 7, call, C4, KO, &e, &l, intent) == 0, "envelope");
    CHECK(ledger_digest(A.w, d0) == 0, "ledger before");
    CHECK(apply_both(&A, &B, 7, e, l, &code) == 0 && code != NODUS_V2_TX_OK,
          "block 7: VR's key (reserved by the RETIRING VR) refused");
    free(e); e = NULL;
    h = 7;
    CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "the ledger tables are byte-identical across the block");

    /* ── B5. boundary E: VR graduates, its key is released ─────────── */
    /* HF-6 slice 8a: a committed param-19 (STAKE_MIN) row of 10^13
     * (100k NODUS, the K9 lower end) effective at E, written into BOTH
     * twins immediately before the boundary block E — a block that
     * touches SYSTEM (VR graduates), so the row enters the committed
     * SYSTEM root there and no later untouched-SYSTEM block sees a root
     * it did not commit (phase 8's untouched-domain guard). Read from E
     * on; B7 shows it moving the floor. */
    CHECK(run_to(&A, &B, &h, E_LEN - 1) == 0, "to the block before E");
    CHECK(cc_row(A.w, DNAC_CFG_STAKE_MIN, (uint64_t)DNAC_HF6_STAKE_MIN_MIN,
                 E_LEN, 19) == 0 &&
          cc_row(B.w, DNAC_CFG_STAKE_MIN, (uint64_t)DNAC_HF6_STAKE_MIN_MIN,
                 E_LEN, 19) == 0, "param-19 row 10^13 @ E on both twins");
    CHECK(run_to(&A, &B, &h, E_LEN) == 0, "to the boundary E");
    CHECK(q_u64(A.w, "SELECT status FROM validators WHERE pubkey_hash = ?1",
                vidr, 64, &x) == 0 && x == DNAC_VALIDATOR_UNSTAKED,
          "VR graduated at E (UNSTAKED)");
    CHECK(key_of(A.w, g_k[VR].pk, got, &role) == 1,
          "VR's reservation released (§4, last sentence)");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, vid1, 64) == 0, "KC1's reservation kept");

    /* ── B6. E + 1: VR's key STAKEd again under a NEW validator_id ─── */
    CHECK(stake2_call(call, chain32, g_k[KO].fp, VR, E_LEN + 50, 300, SMIN,
                      CS_OK) == CALL_LEN, "call");
    CHECK(st_env(A.w, E_LEN + 1, call, C5, KO, &e, &l, intent) == 0,
          "envelope");
    CHECK(apply_both(&A, &B, E_LEN + 1, e, l, &code) == 0 &&
          code == NODUS_V2_TX_OK,
          "E + 1: the released key is STAKEd again");
    free(e); e = NULL;
    h = E_LEN + 1;
    CHECK(vid_expect(chain32, intent, vidr2) == 0 &&
          memcmp(vidr2, vidr, 64) != 0, "a NEW validator_id");
    CHECK(key_of(A.w, g_k[VR].pk, got, &role) == 0 &&
          memcmp(got, vidr2, 64) == 0 && role == 1,
          "the key re-reserved to the new validator_id");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM validators WHERE pubkey = ?1",
                g_k[VR].pk, (int)PK_LEN, &x) == 0 && x == 2,
          "two rows hold VR's key: the UNSTAKED one and the new one");
    CHECK(core_invariant(A.w) == 0, "the CORE invariant holds");
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }

    /* ── B7. HF-6 slice 8a: the committed param-19 row IS the floor ── */
    {
        const uint64_t MN = (uint64_t)DNAC_HF6_STAKE_MIN_MIN;
        CHECK(MN < SMIN, "the voted floor is below the compiled default");
        CHECK(stake2_call(call, chain32, g_k[KO].fp, KC3, E_LEN + 50, 300,
                          MN - 1u, CS_OK) == CALL_LEN, "call");
        CHECK(st_env(A.w, E_LEN + 2, call, C6, KO, &e, &l, intent) == 0,
              "envelope");
        CHECK(ledger_digest(A.w, d0) == 0, "ledger before");
        CHECK(apply_both(&A, &B, E_LEN + 2, e, l, &code) == 0 &&
              code != NODUS_V2_TX_OK,
              "E + 2: bond 10^13 - 1 refused under the voted floor 10^13");
        free(e); e = NULL;
        h = E_LEN + 2;
        CHECK(ledger_digest(A.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "the ledger tables are byte-identical across the block");
        CHECK(stake2_call(call, chain32, g_k[KO].fp, KC3, E_LEN + 50, 300,
                          MN, CS_OK) == CALL_LEN, "call");
        CHECK(st_env(A.w, E_LEN + 3, call, C7, KO, &e, &l, intent) == 0,
              "envelope");
        CHECK(apply_both(&A, &B, E_LEN + 3, e, l, &code) == 0 &&
              code == NODUS_V2_TX_OK,
              "E + 3: bond 10^13 (below the compiled 2M) applies under the "
              "voted floor");
        free(e); e = NULL;
        h = E_LEN + 3;
        uint8_t vid3[64];
        CHECK(vid_expect(chain32, intent, vid3) == 0 &&
              q_u64(A.w, "SELECT self_stake FROM validators WHERE "
                    "pubkey_hash = ?1", vid3, 64, &x) == 0 && x == MN,
              "the new validator's bond is 10^13");
        CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
              "the CORE invariant holds on both twins");
    }

    /* ── B8. HF-6 slice 8a: a stored param-19 value no vote can produce
     *       FAULTs the item's ctx fill on this node — never a default,
     *       never a verdict. The row (10^13 - 1, below the K9 floor) is
     *       written straight into twin A only; the block aborts whole at
     *       the authorization stage's fill, before phase 8 runs, and its
     *       reason names the param. ─────────────────────────────────── */
    {
        CHECK(cc_row(A.w, DNAC_CFG_STAKE_MIN,
                     (uint64_t)DNAC_HF6_STAKE_MIN_MIN - 1u, E_LEN + 4, 20)
              == 0, "an out-of-range param-19 row @ E + 4 on twin A");
        CHECK(stake2_call(call, chain32, g_k[KO].fp, KX, E_LEN + 50, 300,
                          SMIN, CS_OK) == CALL_LEN, "call");
        CHECK(st_env(A.w, E_LEN + 4, call, C8, KO, &e, &l, intent) == 0,
              "envelope");
        nodus_v2_envelope_t v[1] = { { e, l } };
        nodus_v2_tx_result_t ra[1];
        nodus_v2_block_t ba;
        memset(ra, 0, sizeof(ra));
        mk_block(&ba, E_LEN + 4, v, 1);
        ba.cmt.results = ra;
        ba.cmt.results_cap = 1;
        CHECK(v2x_cmt_apply(A.w, &ba) != 0,
              "E + 4: the block does not apply (a node FAULT)");
        CHECK(strstr(ba.out_reason, "FAULT") != NULL &&
              strstr(ba.out_reason, "STAKE_MIN") != NULL &&
              strstr(ba.out_reason, "no committed row can hold") != NULL,
              "the fault reason is the param-19 range check");
        free(e); e = NULL;
        CHECK(nodus_witness_v2_tip_height(A.w, &x) == 0 && x == E_LEN + 3,
              "twin A's tip did not move");
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "hooks_gen4_stake",      t_hooks },
        { "engine_gen4_stake",     t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0 || desc_make() != 0) {
        fprintf(stderr, "test_hf6_stake: key / descriptor setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_stake: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
