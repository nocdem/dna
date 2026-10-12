/**
 * @file nodus/tests/test_hf6_rotate.c
 * @brief HF-6 slice 6 — ROTATE_CONSENSUS_KEY (runtime_op 10): owned and
 *        priced by generation 4 only (sub-slice 6a) and its exec (6b).
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §2 (ROTATE = runtime_op 10, call validator_id[64] ‖ new_pk[2592] ‖
 * consent_sig[4627] ‖ consent_expiry u64 = 7291 B; the generation-4
 * SYSTEM descriptor {1..10}; the consent re-construction contract), §3
 * (rotation; khan decisions of 2026-10-12: A1 exec writes the first
 * boundary >= the commit height, A4 the funding leg is fee-only, A5 only
 * ACTIVE / ELIGIBLE rows, A6 versions stay SYSTEM 9 / CORE 7), §4 (key
 * uniqueness), §6.1 (consent bytes, ctx "nodus.valbind.v1", expiry rule),
 * §6.3 (row); decision 2026-10-08-kurultay-14-hf6-summary.md K7; plan
 * tasks/hf6-slice6-plan.md §1.1, §2 "6a" / "6b".
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. TABLE (no database):
 *   A1 DNA_SYSRULE_ROTATE_CONSENSUS_KEY == 10; the generation-4 SYSTEM
 *      descriptor (still v9) owns op 10 and no earlier generation's
 *      SYSTEM or CORE descriptor does — the list rt_owns_runtime_op
 *      (nodus_witness_v2_apply.c, static) walks, restated here as the
 *      same ascending scan.
 *   A2 the generation-4 SYSTEM policy prices op 10 at weight 1; no
 *      earlier one does; the compiled table passes its selfcheck (every
 *      pin and DNAC_CFG_RULESET_GEN_STORAGE_D re-derive — the oracle
 *      literals of shared/dnac/tests/storage_oracle.py).
 *   A3 the SYSTEM read plan and exec of generations 1..3 and of a NULL
 *      runtime refuse op 10 (-1, never -2).
 *  H. HOOKS — the generation-4 SYSTEM / CORE runtimes over fabricated
 *     engine facts (a decoded 2-leg envelope, a verdict, mediated-read
 *     results) and REAL ML-DSA-87 consent signatures:
 *   H1 the plan is [op 13 validator_id] [op 17 SHA3-512(new_pk)], in
 *      that order; length 7290 / 7292 refused by plan and exec; the
 *      generation-3 runtime refuses the 7291-B call.
 *   H2 kind-1 owner (ACTIVE and ELIGIBLE rows) and kind-3 owner (2-of-3
 *      address) positives: exactly two effects — CREATE op 17 behind
 *      ABSENT (key SHA3-512(new_pk), value validator_id ‖ role 2), then
 *      SET op 13 behind EXISTS_VHASH bound to the observed row's hash,
 *      whose value is the observed row with ONLY pending_consensus_pubkey
 *      := new_pk and consensus_key_effective_epoch := F changed; F = the
 *      first epoch boundary >= h (h itself at a boundary, else the next).
 *   H3 refusals (-1): unknown validator_id; a kind-1 signer that is not
 *      the row's owner; a kind-3 descriptor of another address; kind 2;
 *      status RETIRING / UNSTAKED / AUTO_RETIRED; a pending key already
 *      set; new_pk equal to the row's current key; new_pk reserved by
 *      another validator as role 1 and as role 2 (a malformed reservation
 *      answer -2); expiry h - 1 and h + 721 (h and h + 720 accepted);
 *      consents with op 1 (STAKE), an all-zero subject, another
 *      validator's id, another owner, another chain, signed by the OLD
 *      key, signed under ctx "nodus.valbind.v2"; a malformed SYSFUND
 *      sibling and a non-SYSFUND sibling; a read count that is not 2
 *      (-2).
 *   H4 the CORE SYSFUND leg pairs with a ROTATE sibling under generation
 *      4 (plan = inputs + pool) and NOT under generation 3; the
 *      read-only describer describes both legs (SYSTEM: no record kind).
 *  B. ENGINE (twin seeded chains, EVM-enabled build — the test_hf6_stake
 *     fixture: V0..V6 ACTIVE 10M since 1; param 9 at 2, param 14 at 3,
 *     param 16 — the generation-4 dev trigger — at 4, so the edge runs in
 *     block 3):
 *   B1 block 3 (generation 3): a 2-leg {SYSTEM op 10, CORE SYSFUND}
 *      envelope is refused at ADMISSION (the live gate is
 *      rt_owns_runtime_op in env_admit_legs; rt_admit_common judges
 *      (tx_type, pool) only and is reached solely through
 *      nodus_witness_domreg_admit_v2, which has no production caller — so
 *      no SYS_TYPES change is involved); its funding coin stays unspent.
 *   B2 block 4: a generation-4 STAKE (owner KO, key KC1) opens V_A.
 *   B3 block 5: a kind-1 ROTATE of V_A to KN APPLIES: the roles row
 *      carries pending = KN and epoch F = E (the first boundary >= 5), the
 *      consensus key stays KC1, KN is reserved to V_A as role 2 and KC1
 *      stays role 1; the funding coin is consumed; Σutxo + Σself_stake +
 *      Σtotal_delegated + reward_pool is conserved (fee -> pool).
 *   B4 block 6: a second ROTATE of V_A (to KN2) is REFUSED with the ledger
 *      tables byte-identical (a rotation is pending).
 *   B5 block 7: a STAKE opens V_B (key KC2); block 8: a ROTATE of V_B to
 *      KN (pending for V_A, role 2) and block 9: to V1's key (role 1,
 *      reserved by the migration) are REFUSED, ledger byte-identical; the
 *      twins' databases agree at the end.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). B assumes
 * DNAC_EPOCH_LENGTH >= 12 (checked; true for the production 720 and the
 * harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_hf6_rotate_* directories, removed at the end (left behind
 * when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A1 restates rt_owns_runtime_op's scan (the engine's is static); B1
 *    is what drives the real gate.
 *  - The pinned hashes are oracle literals: selfcheck proves this build's
 *    encoder agrees with them, not that the oracle's inputs are the
 *    design's (the oracle names its sources in its docstring).
 *  - Section H fabricates the verdicts and the read results: it proves
 *    the hook's rule decisions, not the engine's reads (B does those).
 *    Its consent signatures are real. Kind 3 is exercised only there (the
 *    engine's kind-3 SYSTEM authorization is test_hf6_stake's B3).
 *  - B stops before the first boundary: the freeze that decides whether
 *    the rotation is accepted, the row switch and the reservation
 *    promotion are slices 6c / 6d — nothing here proves a pending key
 *    ever becomes the consensus key.
 *  - B's genesis UTXOs are SEEDED (V2X_SEED_NOT_REAL_UTXOS); the reward
 *    pool is non-zero by hand (the test_v2_econ device).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/cmt_pb.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
#include "dnac/res_meter.h"
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
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define PK_LEN    ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN   ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN   ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define AUTH1     (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define ROT_LEN   7291u           /* design §2 (K7): 64+2592+4627+8      */
#define STK_LEN   7301u           /* design §2 (K7): 64+2592+4627+8+2+8  */

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_VAL2       13u
#define OP_KEYRES     17u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_PPK_OFF    (128u + 2592u)
#define V2_KEFF_OFF   (128u + 2u * 2592u)             /* 5312 */
#define V2_SELF_OFF   (V2_KEFF_OFF + 8u)
#define V2_COMM_OFF   (V2_SELF_OFF + 24u)
#define V2_STAT_OFF   (V2_COMM_OFF + 12u)
#define V2_SINCE_OFF  (V2_STAT_OFF + 1u)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
/* the first epoch boundary >= h, written independently (khan A1) */
static uint64_t first_boundary(uint64_t h) {
    return ((h + E_LEN - 1) / E_LEN) * E_LEN;
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the genesis committee; KO a single-key owner / funder, KX a
 * foreign key, K1..K3 the multisig keys; KC1 / KC2 consensus keys of
 * STAKEd validators, KN / KN2 rotation targets */
enum { V0, V1, V2, V3, V4, V5, V6, KO, KX, K1, K2, K3, KC1, KC2, KN, KN2,
       N_KEYS };
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
        memset(seed, 0x31 + i, sizeof(seed));
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

/* ══ the ROTATE call and its consent ══════════════════════════════════ */

/* How the consent is formed (H3 variants). */
enum {
    CS_OK = 0,        /* the §6.1 ROTATE message, ctx "nodus.valbind.v1" */
    CS_OP_STAKE,      /* op 1 (STAKE) with the zero subject              */
    CS_SUBJ_ZERO,     /* op 2 with an all-zero subject (hand-built: the
                       * codec refuses to build it)                      */
    CS_SUBJ_OTHER,    /* op 2 naming another validator_id                */
    CS_OWNER_OTHER,   /* another owner_fp in the signed message          */
    CS_CHAIN_OTHER,   /* another chain id                                */
    CS_KEY_OLD,       /* signed by the row's CURRENT key's sk            */
    CS_CTX_OTHER      /* ctx "nodus.valbind.v2"                          */
};

/* validator_id ‖ new_pk ‖ consent_sig ‖ expiry. `owner` is the owner the
 * consent names (the committed row's, for a valid one); `old_key` the
 * row's current key (CS_KEY_OLD). @return ROT_LEN / 0 on setup failure. */
static uint32_t rot_call(uint8_t *dst, const uint8_t chain32[32],
                         const uint8_t vid[64], const uint8_t owner[64],
                         int new_key, int old_key, uint64_t expiry,
                         int variant) {
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    uint8_t chain[32], own[64], subj[64];
    uint8_t op = DNA_VALBIND_OP_ROTATE;
    memcpy(chain, chain32, 32);
    memcpy(own, owner, 64);
    memcpy(subj, vid, 64);
    if (variant == CS_CHAIN_OTHER) chain[0] ^= 0x01;
    if (variant == CS_OWNER_OTHER) own[0] ^= 0x01;
    if (variant == CS_SUBJ_OTHER) subj[0] ^= 0x01;
    if (variant == CS_OP_STAKE) {
        op = DNA_VALBIND_OP_STAKE;
        memset(subj, 0, sizeof(subj));
    }
    if (dna_valbind_consent_msg(msg, chain, op, subj, own, g_k[new_key].pk,
                                expiry) != 0)
        return 0;
    uint8_t *sig = dst + 64 + PK_LEN;
    size_t sl = 0;
    int rc;
    static const uint8_t ctx1[] = "nodus.valbind.v1";
    static const uint8_t ctx2[] = "nodus.valbind.v2";
    if (variant == CS_SUBJ_ZERO) {
        /* the codec refuses op 2 with a zero subject on build AND sign, so
         * the 2765 bytes are zeroed by hand and signed with the right ctx */
        memset(msg + DNA_VALBIND_OFF_SUBJECT, 0, DNA_VALBIND_SUBJECT_LEN);
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg), ctx1, 16,
                                g_k[new_key].sk);
    } else if (variant == CS_CTX_OTHER) {
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg), ctx2, 16,
                                g_k[new_key].sk);
    } else {
        rc = dna_valbind_consent_sign(sig, &sl, msg,
                                      g_k[variant == CS_KEY_OLD ? old_key
                                                                : new_key].sk);
    }
    if (rc != 0 || sl != SIG_LEN) return 0;
    memcpy(dst, vid, 64);
    memcpy(dst + 64, g_k[new_key].pk, PK_LEN);
    put64(dst + 64 + PK_LEN + SIG_LEN, expiry);
    return ROT_LEN;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66u;
}

/* ══ A. the table ════════════════════════════════════════════════════ */

/* the rt_owns_runtime_op scan (nodus_witness_v2_apply.c — static there) */
static int owns(const nodus_domain_runtime_t *rt, uint32_t op) {
    const dna_ruleset_desc_t *d = &rt->descriptor;
    for (size_t i = 0; i < d->rule_count; i++) {
        if (d->rule_ids[i] == op) return 1;
        if (d->rule_ids[i] > op) break;
    }
    return 0;
}

/* ══ H. hook level ═══════════════════════════════════════════════════ */

/* sibling shapes for hk_build */
enum { SIB_OK = 0, SIB_BAD_CALL, SIB_SPEND };

typedef struct {
    uint8_t  fund[66];
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

static int hk_build(hk_env_t *e, const uint8_t *call, uint32_t call_len,
                    uint8_t sys_kind, int sib) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul);
    if (sib == SIB_BAD_CALL) fl = 65u;          /* truncated: no out_count */
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
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
    legs[1].hdr.runtime_op = sib == SIB_SPEND ? DNA_CORERULE_SPEND
                                              : DNA_CORERULE_SYSFUND;
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

/* the observed §6.3 record (op 13 value) of validator `vid`: owner, the
 * current key `cpk`, `status`, pending key `ppk` (-1 = none) with epoch
 * `keff`; self 2M, commission 500, active since 1 */
static void row_make(uint8_t rec[V2_REC_LEN], const uint8_t vid[64],
                     const uint8_t owner[64], int cpk, uint8_t status,
                     int ppk, uint64_t keff) {
    memset(rec, 0, V2_REC_LEN);
    memcpy(rec, vid, 64);
    memcpy(rec + V2_OWNER_OFF, owner, 64);
    memcpy(rec + V2_CPK_OFF, g_k[cpk].pk, PK_LEN);
    if (ppk >= 0) {
        memcpy(rec + V2_PPK_OFF, g_k[ppk].pk, PK_LEN);
        put64(rec + V2_KEFF_OFF, keff);
    }
    put64(rec + V2_SELF_OFF, SMIN);
    rec[V2_COMM_OFF] = 0x01;
    rec[V2_COMM_OFF + 1] = 0xF4;                       /* 500 bps         */
    rec[V2_STAT_OFF] = status;
    put64(rec + V2_SINCE_OFF, 1);
}

/* the two reads of a ROTATE that may apply: the row present, the key
 * absent */
static void rd_row(const uint8_t rec[V2_REC_LEN]) {
    memset(g_reads, 0, sizeof(g_reads));
    g_reads[0].present = 1;
    g_reads[0].value_len = V2_REC_LEN;
    memcpy(g_reads[0].value, rec, V2_REC_LEN);
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

/* hook fixture: validator VA (owner KO, current key V0); VB another id */
static uint8_t g_va[64], g_vb[64];

/* build + exec one variant against row `rec` with the "may apply" reads;
 * @return exec rc */
static int try_rot(const nodus_domain_runtime_t *s4, hk_env_t *e,
                   uint8_t *call, const uint8_t rec[V2_REC_LEN],
                   const uint8_t owner[64], int new_key, uint64_t expiry,
                   int variant, uint8_t kind) {
    if (rot_call(call, g_chain, g_va, owner, new_key, V0, expiry, variant)
        != ROT_LEN)
        return -100;
    if (hk_build(e, call, ROT_LEN, kind, SIB_OK) != 0) return -101;
    rd_row(rec);
    return sys_exec(s4, e, 2, NULL);
}

static int t_table(void) {
    const uint32_t OP = DNA_SYSRULE_ROTATE_CONSENSUS_KEY;
    CHECK(OP == 10u, "ROTATE_CONSENSUS_KEY is runtime_op 10 (design §2)");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (the oracle pins and "
          "the generation-4 vote literal re-derive)");

    for (uint32_t g = 1; g <= NODUS_RT_GEN_STORAGE; g++) {
        const nodus_domain_runtime_t *s =
            nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c =
            nodus_runtime_for_generation(g, DNA_DOMAIN_CORE);
        CHECK(s && c, "generations 1..4 compiled");
        CHECK(owns(c, OP) == 0, "no CORE descriptor owns op 10");
        CHECK(owns(s, OP) == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM descriptor owns op 10");
        uint64_t w = 0;
        int priced = s->meter_policy &&
                     dna_meter_op_weight(s->meter_policy, OP, &w) == 0;
        CHECK(priced == (g == NODUS_RT_GEN_STORAGE),
              "only the generation-4 SYSTEM policy prices op 10");
        if (priced) CHECK(w == 1u, "at weight 1");
    }
    {
        const nodus_domain_runtime_t *s4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c4 =
            nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                         DNA_DOMAIN_CORE);
        CHECK(s4->ruleset_version == 9 && c4->ruleset_version == 7,
              "the generation-4 versions stay SYSTEM 9 / CORE 7 (A6)");
        CHECK(s4->descriptor.rule_count == 10 &&
              s4->descriptor.rule_ids[9] == OP,
              "SYSTEM v9 rules {1..10}");
        uint64_t d = 0;
        CHECK(dna_ruleset_gen_digest(NODUS_RT_GEN_STORAGE,
                                     s4->ruleset_hash, c4->ruleset_hash,
                                     DNAC_RULESET_SWITCH_SPEC_VERSION,
                                     &d) == 0 &&
              d == (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D,
              "the dev vote literal re-derives from the re-pinned hashes");
    }

    /* A3: below generation 4 every SYSTEM hook refuses op 10 */
    {
        static hk_env_t e;
        static uint8_t call[ROT_LEN];
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        memset(call, 0x5A, sizeof(call));
        CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                       SIB_OK) == 0, "an op-10 envelope");
        ctx_reset(10);
        av_k1(KO);
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        for (uint32_t g = 0; g < NODUS_RT_GEN_STORAGE; g++) {
            const nodus_domain_runtime_t *s =
                g ? nodus_runtime_for_generation(g, DNA_DOMAIN_SYSTEM)
                  : NULL;
            uint16_t n = 0;
            size_t rl = 0;
            CHECK(nodus_rt_system_read_plan(s, &e.view, 0, &g_ctx, rq,
                                            NODUS_RT_MAX_READS, &n) == -1,
                  "op 10's read plan refuses (-1) below generation 4");
            CHECK(nodus_rt_system_exec(s, &e.view, 0, &g_ctx, NULL, 0, res,
                                       sizeof(res), &rl) == -1,
                  "op 10's exec refuses (-1) below generation 4");
        }
    }
    return 0;
}

static int t_hooks(void) {
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_CORE);
    CHECK(s4 && s3 && c4 && c3, "generations 3 and 4 compiled");

    static hk_env_t e;
    static uint8_t call[ROT_LEN + 8];
    static uint8_t row[V2_REC_LEN], row2[V2_REC_LEN];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    dna_effect_view_t ev;
    const uint64_t H = 9;
    const uint64_t EXP = H + 100;
    ctx_reset(H);
    memset(g_va, 0x2A, sizeof(g_va));
    memset(g_vb, 0x2B, sizeof(g_vb));

    uint8_t khn[64];
    CHECK(qgp_sha3_512(g_k[KN].pk, PK_LEN, khn) == 0, "key hash");
    row_make(row, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, -1,
             0);

    /* ── H1. the plan and the length ───────────────────────────────── */
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN, "a 7291-byte call");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 2, "ROTATE: 2 reads");
    CHECK(rq[0].op_id == OP_VAL2 && rq[0].key_len == 64 &&
          memcmp(rq[0].key, g_va, 64) == 0,
          "read 0: op 13 keyed by the call's validator_id");
    CHECK(rq[1].op_id == OP_KEYRES && rq[1].key_len == 64 &&
          memcmp(rq[1].key, khn, 64) == 0,
          "read 1: op 17 keyed by SHA3-512(new_pk)");
    for (int d = -1; d <= 1; d += 2) {
        CHECK(hk_build(&e, call, (uint32_t)((int)ROT_LEN + d),
                       NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK) == 0,
              "env ± 1");
        av_k1(KO);
        rd_row(row);
        CHECK(sys_plan(s4, &e, rq, &n) == -1, "7291 ± 1 refused (plan)");
        CHECK(sys_exec(s4, &e, 2, NULL) == -1, "7291 ± 1 refused (exec)");
    }
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    CHECK(sys_plan(s3, &e, rq, &n) == -1,
          "the generation-3 runtime refuses the ROTATE");

    /* ── H2. positives ─────────────────────────────────────────────── */
    av_k1(KO);
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 2,
          "kind-1 owner, ACTIVE row: applies, exactly two effects");
    {
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        const uint8_t *v1 = ev.buf + ev.val_off[1];
        uint8_t vh[DNA_EFFECT_HASH_LEN];
        CHECK(ev.eff[0].op_id == OP_KEYRES &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[0], khn, 64) == 0 &&
              ev.eff[0].value_len == 65 && memcmp(v0, g_va, 64) == 0 &&
              v0[64] == (uint8_t)NODUS_V2_KEY_ROLE_PENDING && v0[64] == 2u,
              "effect 0: CREATE op 17 — SHA3-512(new_pk) -> validator_id, "
              "role 2 (pending)");
        CHECK(dna_effect_value_hash(row, V2_REC_LEN, vh) == 0 &&
              ev.eff[1].op_id == OP_VAL2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              ev.eff[1].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              memcmp(ev.eff[1].expected_vhash, vh, sizeof(vh)) == 0 &&
              ev.eff[1].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[1], g_va, 64) == 0 &&
              ev.eff[1].value_len == V2_REC_LEN,
              "effect 1: SET op 13 under validator_id, bound to the "
              "observed row's hash");
        CHECK(memcmp(v1 + V2_PPK_OFF, g_k[KN].pk, PK_LEN) == 0 &&
              get64(v1 + V2_KEFF_OFF) == first_boundary(H) &&
              first_boundary(H) == E_LEN,
              "the row carries pending = new_pk and epoch F = the first "
              "boundary >= h (A1)");
        CHECK(memcmp(v1, row, V2_PPK_OFF) == 0 &&
              memcmp(v1 + V2_KEFF_OFF + 8, row + V2_KEFF_OFF + 8,
                     V2_REC_LEN - (V2_KEFF_OFF + 8)) == 0,
              "nothing else in the row moves (consensus key, owner, stake, "
              "status, Rule K stamp unchanged)");
    }
    {
        /* F at and just past a boundary */
        const uint64_t hs[2] = { E_LEN, E_LEN + 1 };
        const uint64_t fs[2] = { E_LEN, 2 * E_LEN };
        for (int i = 0; i < 2; i++) {
            ctx_reset(hs[i]);
            av_k1(KO);
            CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0,
                           hs[i] + 1, CS_OK) == ROT_LEN &&
                  hk_build(&e, call, ROT_LEN,
                           NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK) == 0,
                  "env");
            rd_row(row);
            CHECK(sys_exec(s4, &e, 2, &ev) == 0 &&
                  get64(ev.buf + ev.val_off[1] + V2_KEFF_OFF) == fs[i],
                  "F = h at a boundary (a ROTATE committed AT F is "
                  "included), the next boundary one block later");
        }
        ctx_reset(H);
    }
    av_k1(KO);
    row_make(row2, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ELIGIBLE,
             -1, 0);
    CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "kind-1 owner, ELIGIBLE row: applies");
    row_make(row2, g_va, g_am, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, -1, 0);
    av_k3(g_am);
    CHECK(try_rot(s4, &e, call, row2, g_am, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0,
          "kind-3 owner (2-of-3 address): applies");

    /* ── H3. refusals ──────────────────────────────────────────────── */
    av_k1(KO);
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN && hk_build(&e, call, ROT_LEN,
                                 NODUS_RT_AUTHKIND_DSA87_MULTI_V1, SIB_OK)
          == 0, "env");
    memset(g_reads, 0, sizeof(g_reads));
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "unknown validator_id: -1");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 1, NULL) == -2, "one read: a node fault");

    av_k1(KX);
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "kind 1 by a non-owner refused");
    av_k3(g_an);
    CHECK(try_rot(s4, &e, call, row2, g_am, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == -1,
          "kind 3 with another address refused");
    av_k1(KO);
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_CC_V1) == -1, "kind 2 refused");
    {
        static const uint8_t bad_st[3] = {
            (uint8_t)DNAC_VALIDATOR_RETIRING,
            (uint8_t)DNAC_VALIDATOR_UNSTAKED,
            (uint8_t)DNAC_VALIDATOR_AUTO_RETIRED
        };
        for (int i = 0; i < 3; i++) {
            row_make(row2, g_va, g_k[KO].fp, V0, bad_st[i], -1, 0);
            CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                          NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
                  "RETIRING / UNSTAKED / AUTO_RETIRED refused (A5)");
        }
    }
    row_make(row2, g_va, g_k[KO].fp, V0, (uint8_t)DNAC_VALIDATOR_ACTIVE, KN2,
             E_LEN);
    CHECK(try_rot(s4, &e, call, row2, g_k[KO].fp, KN, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "a pending key already set: the second ROTATE refused (§3)");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, V0, EXP, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "new_pk == the row's current key refused (with the reservation "
          "read fabricated absent: the explicit check decides)");
    for (uint8_t role = 1; role <= 2; role++) {
        CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
              == ROT_LEN && hk_build(&e, call, ROT_LEN,
                                     NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                                     SIB_OK) == 0, "env");
        rd_row(row);
        g_reads[1].present = 1;
        g_reads[1].value_len = 65;
        memcpy(g_reads[1].value, g_vb, 64);
        g_reads[1].value[64] = role;
        CHECK(sys_exec(s4, &e, 2, NULL) == -1,
              "new_pk reserved by another validator (role 1, then role 2) "
              "refused (§4)");
    }
    g_reads[1].value_len = 64;
    CHECK(sys_exec(s4, &e, 2, NULL) == -2,
          "a reservation answer outside the adapter contract: -2");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H - 1, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h - 1 refused");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H + 721, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h + 721 refused");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h accepted");
    CHECK(try_rot(s4, &e, call, row, g_k[KO].fp, KN, H + 720, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h + 720 accepted");
    {
        static const struct { int v; const char *what; } bad[] = {
            { CS_OP_STAKE,    "a STAKE (op 1) consent" },
            { CS_SUBJ_ZERO,   "an all-zero subject" },
            { CS_SUBJ_OTHER,  "another validator's id as subject" },
            { CS_OWNER_OTHER, "a consent for another owner" },
            { CS_CHAIN_OTHER, "a consent for another chain" },
            { CS_KEY_OLD,     "the OLD key's signature" },
            { CS_CTX_OTHER,   "ctx nodus.valbind.v2" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            int rc = try_rot(s4, &e, call, row, g_k[KO].fp, KN, EXP,
                             bad[i].v, NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
            if (rc != -1)
                fprintf(stderr, "consent variant: %s -> %d\n", bad[i].what,
                        rc);
            CHECK(rc == -1, "a bad consent is a verdict (-1)");
        }
    }
    CHECK(rot_call(call, g_chain, g_va, g_k[KO].fp, KN, V0, EXP, CS_OK)
          == ROT_LEN, "call");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_BAD_CALL) == 0, "env with a truncated SYSFUND call");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "a malformed SYSFUND sibling: -1");
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_SPEND) == 0, "env with a SPEND sibling");
    rd_row(row);
    CHECK(sys_exec(s4, &e, 2, NULL) == -1, "a non-SYSFUND sibling: -1");
    CHECK(sys_plan(s4, &e, rq, &n) == -1, "and its plan: -1");

    /* ── H4. CORE pairing and the describer ────────────────────────── */
    CHECK(hk_build(&e, call, ROT_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                   SIB_OK) == 0, "env");
    {
        nodus_rt_read_req_t cr[NODUS_RT_MAX_READS];
        uint16_t cn = 0;
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-4 CORE: the ROTATE sibling plans inputs + pool");
        CHECK(nodus_rt_core_read_plan(c3, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == -1,
              "gen-3 CORE: SYSFUND does not pair with op 10");
        nodus_rt_leg_desc_t d;
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_NONE &&
              d.runtime_op == DNA_SYSRULE_ROTATE_CONSENSUS_KEY,
              "describer: an applied ROTATE is described, no record kind");
        CHECK(nodus_rt_native_describe_leg(&e.view, 1, H, g_intent, &d) == 0
              && d.n_consumed == 1 && d.n_created == 0,
              "describer: the SYSFUND sibling consumes its input, creates "
              "nothing (fee-only, A4)");
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

/* every coin is KO's: S* fund a STAKE (bond STAKE_MIN + FEE), R* a
 * ROTATE or an admission probe (exactly FEE — a ROTATE locks nothing) */
enum { S1, S2, R1, R2, R3, R4, R5, R6, N_COINS };
static uint8_t  g_nul[N_COINS][64];
static uint64_t g_amt[N_COINS];

#define H9   2u
#define HE   3u
#define H14  4u       /* param 16: the gen-4 edge runs in block H14 − 1 */

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[KO].hex, 128);
    memset(pre + 128, 0x61 + c, 32);
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
        sqlite3_bind_text(st, 2, g_k[KO].hex, 128, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
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

static int seed_val(nodus_witness_t *w, int k) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PK_LEN);
    v.self_stake = TEN_M;
    v.commission_bps = 500;
    v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    v.active_since_block = 1;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    return nodus_validator_insert(w, &v);
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_rotate_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x6E, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
               H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_STORAGE,
               (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, H14, 13) != 0)
        return -1;
    uint64_t total = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i) != 0) return -1;
        total += TEN_M;
    }
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
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
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

/* A 2-leg {SYSTEM `op`, CORE SYSFUND} envelope against the registry's
 * CURRENT manifests, REALLY signed (two passes): the SYSTEM leg kind 1 by
 * KO, the CORE SYSFUND leg kind 1 by KO spending coin `c` entirely.
 * *intent_out (may be NULL) = the engine-derived intent_id.
 * @return 0 / -1. */
static int rec_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                   const uint8_t *call, uint32_t call_len, int c,
                   uint8_t **out, size_t *out_len, uint8_t *intent_out) {
    static uint8_t fund[66];
    static uint8_t sys_auth[AUTH1];
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
    memset(sys_auth, 0, sizeof(sys_auth));
    memset(core_auth, 0, sizeof(core_auth));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH1;
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
        sys_auth[0] = 1;
        memcpy(sys_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(sys_auth + 1 + PK_LEN, &sl, pf->auth_digest[0],
                           64, g_k[KO].sk) != 0)
            break;
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[KO].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[KO].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (intent_out) memcpy(intent_out, pf->intent_id, 64);
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* the generation-4 STAKE call (owner KO, key `ckey`, bond STAKE_MIN,
 * commission 300) with its op-1 consent — test_hf6_stake's layout.
 * @return STK_LEN / 0. */
static uint32_t stake2_call(uint8_t *dst, const uint8_t chain32[32],
                            int ckey, uint64_t expiry) {
    static const uint8_t zero_subj[64] = { 0 };
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    if (dna_valbind_consent_msg(msg, chain32, DNA_VALBIND_OP_STAKE,
                                zero_subj, g_k[KO].fp, g_k[ckey].pk,
                                expiry) != 0)
        return 0;
    size_t sl = 0;
    if (dna_valbind_consent_sign(dst + 64 + PK_LEN, &sl, msg,
                                 g_k[ckey].sk) != 0 || sl != SIG_LEN)
        return 0;
    memcpy(dst, g_k[KO].fp, 64);
    memcpy(dst + 64, g_k[ckey].pk, PK_LEN);
    size_t off = 64 + PK_LEN + SIG_LEN;
    put64(dst + off, expiry);         off += 8;
    dst[off++] = 0x01;
    dst[off++] = 0x2C;                                 /* 300 bps         */
    put64(dst + off, SMIN);           off += 8;
    return off == STK_LEN ? STK_LEN : 0;
}

/* the independent §6.2 recomputation: SHA3-512("NDS.VALID.v1" + 4 × 0x00
 * ‖ chain32 ‖ intent_id) */
static int vid_expect(const uint8_t chain32[32], const uint8_t intent[64],
                      uint8_t out[64]) {
    uint8_t pre[16 + 32 + 64];
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALID.v1", 12);
    memcpy(pre + 16, chain32, 32);
    memcpy(pre + 48, intent, 64);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused leg must leave untouched */
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

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* Σutxo + Σself_stake + Σtotal_delegated + reward_pool — the value a
 * ROTATE only MOVES (its fee -> pool) */
static int value_sum(nodus_witness_t *w, uint64_t *out) {
    uint64_t u = 0, s = 0, p = 0;
    if (q_u64(w, "SELECT COALESCE(SUM(amount), 0) FROM utxo_set", &u) != 0 ||
        q_u64(w, "SELECT COALESCE(SUM(self_stake), 0) + "
              "COALESCE(SUM(total_delegated), 0) FROM validators", &s) != 0 ||
        q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              &p) != 0)
        return -1;
    *out = u + s + p;
    return 0;
}

/* rows of utxo_set holding coin `c`: 1 unspent / 0 spent / -1 error */
static int coin_count(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    int out = -1;
    if (sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* the reservation of `pk`: 0 found (vid, role) / 1 absent / -1 */
static int key_of(nodus_witness_t *w, const uint8_t *pk, uint8_t vid[64],
                  uint8_t *role) {
    uint8_t kh[64];
    if (qgp_sha3_512(pk, PK_LEN, kh) != 0) return -1;
    return nodus_validator_v2_key_get(w, kh, vid, role);
}

/* one ROTATE block expected REFUSED with the ledger tables untouched */
static int rot_refused(fixture_t *A, fixture_t *B, uint64_t h,
                       const uint8_t *call, int coin) {
    uint8_t *e = NULL, d0[64], d1[64];
    size_t l = 0;
    uint32_t code = 0;
    if (rec_env(A->w, h, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                coin, &e, &l, NULL) != 0)
        return -1;
    int ok = ledger_digest(A->w, d0) == 0 &&
             apply_both(A, B, h, e, l, &code) == 0 &&
             code == NODUS_V2_TX_ERR_EXEC &&
             ledger_digest(A->w, d1) == 0 && memcmp(d0, d1, 64) == 0 &&
             coin_count(A->w, coin) == 1;
    free(e);
    return ok ? 0 : -1;
}

static int t_engine(void) {
    fixture_t A, B;
    static uint8_t call[STK_LEN];
    uint8_t *e = NULL, intent[64], chain32[DNA_CHAIN_ID_LEN];
    uint8_t vid_a[64], vid_b[64], got[64], role = 0;
    size_t l = 0;
    uint64_t h = 0, sum0 = 0, sum1 = 0;
    uint32_t code = 0;

    CHECK(E_LEN >= 12, "no epoch boundary among heights 1..11");
    g_amt[S1] = SMIN + FEE;
    g_amt[S2] = SMIN + FEE;
    for (int c = R1; c < N_COINS; c++) g_amt[c] = FEE;
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (edge in block H14 - 1)");
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── B1. block 3 (generation 3): refused at ADMISSION ──────────── */
    {
        uint8_t vid0[64];
        CHECK(dna_validator_id_migrated(vid0, chain32, g_k[V0].pk) == 0,
              "V0's migrated validator_id");
        CHECK(rot_call(call, chain32, vid0, g_k[V0].fp, KN, V0, HE + 100,
                       CS_OK) == ROT_LEN, "a 7291-byte call");
    }
    CHECK(run_to(&A, &B, &h, HE - 1) == 0, "blocks 1..2");
    CHECK(rec_env(A.w, HE, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R1, &e, &l, NULL) == 0, "an op-10 envelope at block 3");
    CHECK(apply_both(&A, &B, HE, e, l, &code) == 0 &&
          code == NODUS_V2_TX_ERR_ADMISSION,
          "generation 3: op 10 is refused at admission (unowned)");
    free(e); e = NULL;
    h = HE;
    /* block 3 also runs the generation-4 edge (the migration rewrites
     * the validator tables), so no whole-ledger comparison here: the
     * refused envelope's funding coin is what must survive */
    CHECK(coin_count(A.w, R1) == 1,
          "the refused envelope's funding coin is unspent");

    /* ── B2. block 4: STAKE opens V_A (owner KO, key KC1) ──────────── */
    CHECK(stake2_call(call, chain32, KC1, H14 + 100) == STK_LEN, "call");
    CHECK(rec_env(A.w, H14, DNA_SYSRULE_STAKE, call, STK_LEN, S1, &e, &l,
                  intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, H14, e, l, &code) == 0 &&
          code == NODUS_V2_TX_OK, "block 4: the STAKE applies");
    free(e); e = NULL;
    h = H14;
    CHECK(vid_expect(chain32, intent, vid_a) == 0, "V_A's validator_id");

    /* ── B3. block 5: ROTATE V_A -> KN applies ─────────────────────── */
    CHECK(value_sum(A.w, &sum0) == 0, "value before");
    CHECK(rot_call(call, chain32, vid_a, g_k[KO].fp, KN, KC1, 5 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rec_env(A.w, 5, DNA_SYSRULE_ROTATE_CONSENSUS_KEY, call, ROT_LEN,
                  R2, &e, &l, NULL) == 0, "envelope");
    CHECK(apply_both(&A, &B, 5, e, l, &code) == 0 && code == NODUS_V2_TX_OK,
          "block 5: the kind-1 ROTATE applies");
    free(e); e = NULL;
    h = 5;
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        CHECK(r != NULL, "alloc");
        int ok = nodus_validator_v2_get(A.w, vid_a, r) == 0 &&
                 memcmp(r->pending_consensus_pubkey, g_k[KN].pk, PK_LEN)
                     == 0 &&
                 r->consensus_key_effective_epoch == first_boundary(5) &&
                 r->consensus_key_effective_epoch == E_LEN &&
                 memcmp(r->rec.pubkey, g_k[KC1].pk, PK_LEN) == 0 &&
                 memcmp(r->owner_fp, g_k[KO].fp, 64) == 0 &&
                 r->rec.status == DNAC_VALIDATOR_ACTIVE &&
                 r->rec.self_stake == SMIN &&
                 r->rec.last_validator_update_block == 0;
        free(r);
        CHECK(ok, "the §6.3 row: pending = KN, epoch F = E (A1), the "
              "consensus key still KC1, nothing else moved");
    }
    CHECK(key_of(A.w, g_k[KN].pk, got, &role) == 0 &&
          memcmp(got, vid_a, 64) == 0 && role == NODUS_V2_KEY_ROLE_PENDING,
          "KN reserved to V_A, role 2 (pending)");
    CHECK(key_of(A.w, g_k[KC1].pk, got, &role) == 0 &&
          memcmp(got, vid_a, 64) == 0 && role == NODUS_V2_KEY_ROLE_ACTIVE,
          "KC1 still reserved to V_A, role 1");
    CHECK(coin_count(A.w, R2) == 0, "the funding coin is consumed");
    CHECK(value_sum(A.w, &sum1) == 0 && sum1 == sum0,
          "Σutxo + Σstake + pool conserved (the fee -> pool; no lock, A4)");

    /* ── B4. block 6: a second ROTATE of V_A is refused ────────────── */
    CHECK(rot_call(call, chain32, vid_a, g_k[KO].fp, KN2, KC1, 6 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 6, call, R3) == 0,
          "block 6: a second ROTATE while one is pending is refused, the "
          "ledger tables byte-identical");
    h = 6;

    /* ── B5. V_B: the pending and the migrated keys are reserved ───── */
    CHECK(stake2_call(call, chain32, KC2, 7 + 100) == STK_LEN, "call");
    CHECK(rec_env(A.w, 7, DNA_SYSRULE_STAKE, call, STK_LEN, S2, &e, &l,
                  intent) == 0, "envelope");
    CHECK(apply_both(&A, &B, 7, e, l, &code) == 0 && code == NODUS_V2_TX_OK,
          "block 7: the STAKE of V_B applies");
    free(e); e = NULL;
    h = 7;
    CHECK(vid_expect(chain32, intent, vid_b) == 0, "V_B's validator_id");
    CHECK(rot_call(call, chain32, vid_b, g_k[KO].fp, KN, KC2, 8 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 8, call, R4) == 0,
          "block 8: V_B -> KN (pending for V_A, role 2) refused");
    CHECK(rot_call(call, chain32, vid_b, g_k[KO].fp, V1, KC2, 9 + 100,
                   CS_OK) == ROT_LEN, "call");
    CHECK(rot_refused(&A, &B, 9, call, R5) == 0,
          "block 9: V_B -> V1's key (role 1, the migration's) refused");
    h = 9;
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
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
        { "table_op10_owned",      t_table },
        { "hooks_gen4_rotate",     t_hooks },
        { "engine_gen4_rotate",    t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0 || desc_make() != 0) {
        fprintf(stderr, "test_hf6_rotate: key / descriptor setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_rotate: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
