/**
 * @file nodus/tests/test_hf6_calls.c
 * @brief HF-6 sub-slice 3c — owner authority and the generation-4 call
 *        layouts of the SYSTEM validator-record ops 2..5 (the legacy
 *        2666-B STAKE refused under generation 4; the generation-4 STAKE
 *        of slice 4 is test_hf6_stake's); sub-slice 3e — the HF-8 name
 *        rule and its self-delegation exemption on the SYSTEM DELEGATE.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.3 (owner rule, kind-3 address equality), §2 (call layouts: DELEGATE /
 * UNDELEGATE delegator_fp[64] ‖ validator_id[64] ‖ amount u64 = 136,
 * UNSTAKE validator_id[64] ‖ owner_fp[64] = 128, VALIDATOR_UPDATE
 * validator_id[64] ‖ owner_fp[64] ‖ commission u16 = 130 — the owner_fp
 * since the khan decision of 2026-10-13, docs/plans/decisions/2026-10-13-
 * kurultay-18-summary.md item 2 "C2"), §6.3/§6.4 (the row values); plan
 * tasks/hf6-slice3-plan.md §2 "3c" / "3e" + §3; decisions D3 (Kurultay #16
 * summary — the HF-8 self-delegation exemption under generation 4 is
 * delegator_fp == owner_fp(validator_id), judged on the SYSTEM side, sub-
 * slice 3e) and D6 (the kind-3 "every
 * verified signer is a key of the descriptor" verdict fact); K3 (Kurultay
 * #14: no TRANSFER_OWNER).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. HOOK LEVEL — the GEN_STORAGE (= HF-6 generation 4) and the EVM
 *     generation (3) SYSTEM / CORE runtimes over fabricated engine facts
 *     (a decoded 2-leg envelope, a verdict, mediated-read results):
 *   A1 read plans under generation 4: DELEGATE = [op 13 key validator_id,
 *      op 14 key delegator_fp ‖ validator_id, op 15 key validator_id];
 *      UNDELEGATE = the first two; UNSTAKE / VALIDATOR_UPDATE = [op 13];
 *      every exact length ± 1 refused (plan AND exec); the legacy 2666-B
 *      STAKE, 5192-B DELEGATE / UNDELEGATE, 2592-B UNSTAKE and 2594-B
 *      VALIDATOR_UPDATE refused by the generation-4 plan and exec, and the
 *      same calls planned by the generation-3 runtime exactly as before
 *      (ops 4 / 5 / 6 / 7).
 *   A2 each op × kind 1 / kind 3 positive, with the effect bytes naming
 *      ops 13 / 14 ONLY (never 4 / 5 / 6), and the record values the rule
 *      writes (DELEGATE create + top-up, UNDELEGATE partial + drain,
 *      UNSTAKE → RETIRING, VALIDATOR_UPDATE decrease immediate / increase
 *      deferred).
 *   A3 refusals, each -1 (a verdict, never -2): DELEGATE / UNDELEGATE by a
 *      non-delegator (kind 1); UNSTAKE / VALIDATOR_UPDATE by a non-owner
 *      (kind 1); kind 3 with a satisfied descriptor of the WRONG address,
 *      an UNSATISFIED one, an extra foreign signer (D6 bit clear), TWO
 *      descriptors; a kind-2 leg; a missing verdict. C2: UNSTAKE /
 *      VALIDATOR_UPDATE whose call owner_fp is not the committed row's —
 *      kind 1 signed by the call's owner AND by the row's owner, and kind
 *      3 with the row's vault descriptor swapped in for the call's vault
 *      (the "descriptor swap": the signatures of co-members of two vaults
 *      cannot be redirected) and with the call's vault signing; the 128 /
 *      130-byte calls ± 1, the pre-C2 64 / 66-byte calls, and the C2
 *      lengths under generation 3 (the length sets stay disjoint from the
 *      legacy 2592 / 2594).
 *   A4 the CORE SYSFUND leg: a STAKE sibling planned by the generation-4
 *      CORE read plan since slice 4 (refused by it in 3c) and by
 *      generation 3; a generation-4
 *      DELEGATE sibling planned (inputs + pool); with the HF-8 gate on
 *      (param 17) the generation-4 CORE leg STILL plans inputs + pool only
 *      — no CORE NAMEOWN, and its input ceiling stays 15 (sub-slice 3e,
 *      decision D3: the name rule lives on the SYSTEM leg) — while the
 *      generation-3 legacy gate still plans its NAMEOWN read.
 *   A7 D3 (sub-slice 3e) — the HF-8 name rule on the generation-4 SYSTEM
 *      DELEGATE: gate off → the 3c plan (3 reads); gate on → + ONE read,
 *      op 16 (SYSTEM NAMEOWN2) keyed by the call's delegator_fp, last;
 *      UNDELEGATE never reads a name. Exec with the gate on: a non-owner
 *      delegator without a name refused (-1), with a name applied; the
 *      validator's OWNER (delegator_fp == the observed row's owner_fp)
 *      applied without a name, kind 1 AND kind 3; a kind-3 non-owner
 *      refused / applied by name; a present name outside 3..36 bytes and
 *      a read count that disagrees with the gate are node faults (-2);
 *      gate off → a nameless non-owner applies (unchanged). The
 *      generation-3 SYSTEM plan is unchanged with the gate on.
 *   A5 the read-only describer: an applied generation-4 DELEGATE /
 *      UNSTAKE / VALIDATOR_UPDATE is described from its call (the
 *      delegator_fp and the validator_id), and the UNDELEGATE release coin
 *      of a generation-4 call is owned by hex(delegator_fp) directly (the
 *      legacy call's by hex(SHA3-512(delegator pubkey))).
 *   A6 D6 through the REAL auth hook (nodus_rt_auth_dsa87_v1, real ML-DSA-87
 *      signatures): 2 of a 2-of-3 descriptor's keys sign → satisfied AND
 *      the "every signer is a key" bit set; the same plus a foreign signer
 *      → still satisfied (CORE's fact unchanged) but the bit CLEAR; two
 *      descriptors each get their own bit.
 *  B. ENGINE (one seeded chain, EVM-enabled build, HF-2 on from 1, param 9
 *     at 2, param 14 at 3, param 18 — the generation-4 vote (D4) — at
 *     6, every block through the cometbft host):
 *   B1 block 3 (generation 3): a legacy 2666-B STAKE and a legacy 5192-B
 *      DELEGATE APPLY.
 *   B2 block 5 = H-1: the edge (generation 4) migrates both rows.
 *   B3 block 6 (generation 4): a legacy STAKE and a legacy DELEGATE —
 *      built the same way, against the current registry — are REFUSED and
 *      the ledger tables (validators, roles, delegations, utxo_set,
 *      supply_tracking, validator_stats) are byte-identical across the
 *      block.
 *   B4 generation-4 calls APPLY end to end: a kind-1 DELEGATE top-up of
 *      the migrated delegation (block 7); a kind-3 DELEGATE whose
 *      delegator is a 2-of-3 multisig address, funded by another key
 *      (block 8) — a new row with full-length pubkey columns (the 3b
 *      precedent); a VALIDATOR_UPDATE by the staker's own key (its owner)
 *      and the same by a non-owner refused (block 9); a kind-3 UNDELEGATE
 *      draining the multisig row with the release coin owned by the
 *      multisig address and locked (block 10); an UNSTAKE by the owner
 *      (block 11).
 *   B5 the SYSTEM adapter's read-only op 16 serves the committed v2_names
 *      row by owner (present with the name bytes / absent / a 63-byte key
 *      refused as ERR_SHAPE) through the engine's mediated-read entry.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). B assumes
 * DNAC_EPOCH_LENGTH > 12 (no boundary among heights 1..11 — checked; true
 * for the production 720 and the harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf6_calls_* directory, removed at the end (left behind
 * when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Section A fabricates the verdicts and the read results: it proves the
 *    hooks' rule decisions, not the engine's read execution or signature
 *    verification (A6 and B do those, on real signatures).
 *  - B's genesis UTXOs are SEEDED (V2X_SEED_NOT_REAL_UTXOS). The genesis
 *    validators are Foundation-owned after the edge (D2), so B exercises
 *    the owner rule on the staker's own row and the kind-3 rule on a
 *    multisig DELEGATOR — never a Foundation-owned UNSTAKE.
 *  - Until sub-slice 3d the generation-4 SYSTEM root is composed by the
 *    v1 leaf loaders; B proves the blocks commit, not the v2 leaves.
 *  - Refusals in B are asserted by item code and the ledger-table digest,
 *    not by a whole-database digest (a refused item still writes its
 *    block's receipts).
 *  - HF-8 (param 17) stays off in B; its generation-4 rule (D3) is proven
 *    at hook level (A4, A7) over fabricated reads, and op 16's storage
 *    read in B5 — no block in B applies a DELEGATE with the gate on, so
 *    the engine's plan → read → exec wiring of the gated 4-read DELEGATE
 *    is not exercised end to end here.
 *  - B5 writes its v2_names row by direct SQL after the last block; it
 *    proves the adapter read, not a NAME_REGISTER.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_v2_adapter.h"  /* B5: read_one (op 16) */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/msig_wire.h"
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

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define DLG      ((uint64_t)DNAC_MIN_DELEGATION)
#define TEN_M    ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define OUT_LEN  232u
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN  ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN  ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define AUTH1    (1u + NODUS_RT_AUTH_SIGNER_LEN)

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_VAL        4u
#define OP_DELEG      5u
#define OP_DELEGCNT   6u
#define OP_STATS      7u
#define OP_VAL2       13u
#define OP_DELEG2     14u
#define OP_DELEGCNT2  15u
#define OP_NAMEOWN2   16u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_SELF_OFF   (128u + 2u * 2592u + 8u)       /* 5320 */
#define V2_TOT_OFF    (V2_SELF_OFF + 8u)
#define V2_EXT_OFF    (V2_TOT_OFF + 8u)
#define V2_COMM_OFF   (V2_EXT_OFF + 8u)
#define V2_PCOMM_OFF  (V2_COMM_OFF + 2u)
#define V2_PEFF_OFF   (V2_PCOMM_OFF + 2u)
#define V2_STAT_OFF   (V2_PEFF_OFF + 8u)
#define V2_SINCE_OFF  (V2_STAT_OFF + 1u)
#define V2_UCOM_OFF   (V2_SINCE_OFF + 8u)
#define V2_LUPD_OFF   (V2_UCOM_OFF + 8u)
#define D2_REC_LEN    144u
#define D2_AMT_OFF    128u
#define D2_AT_OFF     136u

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

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* KD delegator, KO a single-key owner, KX a foreign key, K1..K3 the
 * multisig keys, KS / KS2 stakers (B) */
enum { KD, KO, KX, K1, K2, K3, KS, KS2, N_KEYS };
static sk_key_t g_k[N_KEYS];

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
        memset(seed, 0x2B + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* ══ the multisig descriptors ═════════════════════════════════════════ */

static uint8_t g_dm[DNA_MSIG_MAX_DESC_LEN];   /* M  = 2-of-3 {K1,K2,K3}  */
static size_t  g_dm_len;
static uint8_t g_am[64];                      /* address of M             */
static char    g_am_hex[129];
static uint8_t g_dn[DNA_MSIG_MAX_DESC_LEN];   /* N  = 2-of-2 {K1,K2}      */
static size_t  g_dn_len;
static uint8_t g_an[64];

/* keys `ks` (n of them) sorted ascending by pubkey into `ord` */
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

static int desc_make(uint8_t m, const int *ks, int n, uint8_t *out,
                     size_t *len, uint8_t addr[64]) {
    static uint8_t keys[7 * 2592];
    int ord[7];
    sort_keys(ks, n, ord);
    for (int i = 0; i < n; i++)
        memcpy(keys + (size_t)i * PK_LEN, g_k[ord[i]].pk, PK_LEN);
    if (dna_msig_desc_encode(m, (uint8_t)n, keys, out, DNA_MSIG_MAX_DESC_LEN,
                             len) != 0)
        return -1;
    return dna_msig_address(out, *len, addr) == 0 ? 0 : -1;
}

static int descs_make(void) {
    const int km[3] = { K1, K2, K3 };
    const int kn[2] = { K1, K2 };
    if (desc_make(2, km, 3, g_dm, &g_dm_len, g_am) != 0) return -1;
    if (desc_make(2, kn, 2, g_dn, &g_dn_len, g_an) != 0) return -1;
    hex_of(g_am, g_am_hex);
    return 0;
}

/* A kind-3 auth blob: the signer section (signers sorted ascending by
 * pubkey, each signing `digest`) ‖ dcount ‖ (dlen ‖ descriptor)… with
 * `nd` descriptors from {M, N} emitted ascending by address. When
 * `digest` is NULL the signatures are left zero (the first pass of the
 * two-pass build). @return blob length / 0 on error. */
static size_t k3_blob(uint8_t *dst, size_t cap, const int *signers, int ns,
                      int nd, const uint8_t *digest) {
    int ord[7];
    if (ns < 1 || ns > 7 || nd < 1 || nd > 2) return 0;
    sort_keys(signers, ns, ord);
    size_t need = 1 + (size_t)ns * SGN_LEN + 1 + 2 + g_dm_len +
                  (nd == 2 ? 2 + g_dn_len : 0);
    if (need > cap) return 0;
    size_t off = 0;
    dst[off++] = (uint8_t)ns;
    for (int i = 0; i < ns; i++) {
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
    dst[off++] = (uint8_t)nd;
    const uint8_t *d[2] = { g_dm, g_dn };
    size_t dl[2] = { g_dm_len, g_dn_len };
    int first = 0;
    if (nd == 2 && memcmp(g_an, g_am, 64) < 0) first = 1;
    for (int j = 0; j < nd; j++) {
        int k = (nd == 2) ? (j == 0 ? first : 1 - first) : 0;
        dst[off++] = (uint8_t)(dl[k] >> 8);
        dst[off++] = (uint8_t)dl[k];
        memcpy(dst + off, d[k], dl[k]);
        off += dl[k];
    }
    return off == need ? off : 0;
}

/* ══ call builders ════════════════════════════════════════════════════ */

static uint32_t deleg2_call(uint8_t *dst, const uint8_t dfp[64],
                            const uint8_t vid[64], uint64_t amount) {
    memcpy(dst, dfp, 64);
    memcpy(dst + 64, vid, 64);
    put64(dst + 128, amount);
    return 136u;
}
/* C2 (khan decision 2026-10-13, Kurultay #18 item 2): UNSTAKE =
 * validator_id ‖ owner_fp (128 B), VALIDATOR_UPDATE = validator_id ‖
 * owner_fp ‖ commission u16 (130 B) */
static uint32_t unstake2_call(uint8_t *dst, const uint8_t vid[64],
                              const uint8_t owner[64]) {
    memcpy(dst, vid, 64);
    memcpy(dst + 64, owner, 64);
    return 128u;
}
static uint32_t vupd2_call(uint8_t *dst, const uint8_t vid[64],
                           const uint8_t owner[64], uint16_t bps) {
    memcpy(dst, vid, 64);
    memcpy(dst + 64, owner, 64);
    dst[128] = (uint8_t)(bps >> 8);
    dst[129] = (uint8_t)bps;
    return 130u;
}
static uint32_t stake1_call(uint8_t *dst, int key, uint16_t bps,
                            uint64_t bond) {
    memcpy(dst, g_k[key].pk, PK_LEN);
    dst[PK_LEN] = (uint8_t)(bps >> 8);
    dst[PK_LEN + 1] = (uint8_t)bps;
    put64(dst + PK_LEN + 2, bond);
    memcpy(dst + PK_LEN + 10, g_k[key].fp, 64);
    return (uint32_t)(PK_LEN + 2 + 8 + 64);
}
static uint32_t deleg1_call(uint8_t *dst, const uint8_t *dpk,
                            const uint8_t *vpk, uint64_t amount) {
    memcpy(dst, dpk, PK_LEN);
    memcpy(dst + PK_LEN, vpk, PK_LEN);
    put64(dst + 2 * PK_LEN, amount);
    return (uint32_t)(2 * PK_LEN + 8);
}

/* SYSFUND call: in_count ‖ nullifiers ‖ out_count ‖ outputs */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64], int chg_key,
                          uint64_t change, uint8_t seed_byte) {
    size_t off = 0;
    dst[off++] = 1;
    memcpy(dst + off, nul, 64);         off += 64;
    if (change > 0) {
        uint8_t seed[32];
        memset(seed, seed_byte, sizeof(seed));
        dst[off++] = 1;
        nodus_v2_xfer_out_put(dst + off, g_k[chg_key].hex, change, NULL,
                              seed);
        off += OUT_LEN;
    } else {
        dst[off++] = 0;
    }
    return (uint32_t)off;
}

/* ══ A. hook level ═══════════════════════════════════════════════════ */

typedef struct {
    uint8_t  fund[2 + 64 + OUT_LEN];
    uint8_t  auth[2][AUTH1];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

/* a decoded envelope: leg 0 SYSTEM `op` (call, auth kind `sys_kind`),
 * leg 1 CORE SYSFUND (a 1-input, 0-output funding call); auth bytes zero
 * (the exec hooks read the verdict, never the auth bytes) */
static int hk_build(hk_env_t *e, uint32_t op, const uint8_t *call,
                    uint32_t call_len, uint8_t sys_kind) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul, KD, 0, 0);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = 10;   /* the generation-4 SYSTEM (D2) */
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
    legs[1].hdr.ruleset_version = 8;    /* the generation-4 CORE (D2)   */
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

/* a kind-1 verdict: one signer `key` */
static void av_k1(int key) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[key].fp, 64);
}

/* a kind-3 verdict: two signers (K1, K2), `nd` descriptors, the first
 * with address `addr`, satisfied flag `sat`, D6 bit `allin` */
static void av_k3(const uint8_t addr[64], int sat, int allin, int nd) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 2;
    memcpy(g_av.signer_fp[0], g_k[K1].fp, 64);
    memcpy(g_av.signer_fp[1], g_k[K2].fp, 64);
    g_av.n_msig = (uint16_t)nd;
    memcpy(g_av.msig_addr[0], addr, 64);
    g_av.msig_satisfied[0] = (uint8_t)(sat ? 1 : 0);
    if (allin) g_av.msig_signers_in_desc = 1u;
    if (nd == 2) {
        memcpy(g_av.msig_addr[1], g_an, 64);
        g_av.msig_satisfied[1] = 1;
        g_av.msig_signers_in_desc |= 2u;
    }
}

static nodus_rt_read_res_t g_reads[4];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* a fabricated generation-4 validator record */
static void val2_make(uint8_t *r, const uint8_t vid[64],
                      const uint8_t owner[64], uint8_t status,
                      uint64_t tot, uint16_t comm) {
    memset(r, 0, V2_REC_LEN);
    memcpy(r, vid, 64);
    memcpy(r + V2_OWNER_OFF, owner, 64);
    memcpy(r + V2_CPK_OFF, g_k[KX].pk, PK_LEN);
    put64(r + V2_SELF_OFF, 2u * 100000000000000ULL);
    put64(r + V2_TOT_OFF, tot);
    put64(r + V2_EXT_OFF, tot);
    r[V2_COMM_OFF] = (uint8_t)(comm >> 8);
    r[V2_COMM_OFF + 1] = (uint8_t)comm;
    r[V2_STAT_OFF] = status;
    put64(r + V2_SINCE_OFF, 1);
}

static void del2_make(uint8_t *r, const uint8_t dfp[64],
                      const uint8_t vid[64], uint64_t amount) {
    memset(r, 0, D2_REC_LEN);
    memcpy(r, dfp, 64);
    memcpy(r + 64, vid, 64);
    put64(r + D2_AMT_OFF, amount);
    put64(r + D2_AT_OFF, 3);
}

static void rd_val2(int slot, const uint8_t vid[64], const uint8_t owner[64],
                    uint8_t status, uint64_t tot, uint16_t comm) {
    memset(&g_reads[slot], 0, sizeof(g_reads[slot]));
    g_reads[slot].present = 1;
    g_reads[slot].value_len = V2_REC_LEN;
    val2_make(g_reads[slot].value, vid, owner, status, tot, comm);
}
static void rd_del2(int slot, const uint8_t dfp[64], const uint8_t vid[64],
                    uint64_t amount) {
    memset(&g_reads[slot], 0, sizeof(g_reads[slot]));
    if (amount == 0) return;              /* absent                      */
    g_reads[slot].present = 1;
    g_reads[slot].value_len = D2_REC_LEN;
    del2_make(g_reads[slot].value, dfp, vid, amount);
}
static void rd_cnt(int slot, uint64_t n) {
    memset(&g_reads[slot], 0, sizeof(g_reads[slot]));
    g_reads[slot].present = 1;
    g_reads[slot].value_len = 8;
    put64(g_reads[slot].value, n);
}
/* the SYSTEM NAMEOWN2 answer (op 16): `name` NULL = absent, else the
 * name bytes (len may be out of contract on purpose) */
static void rd_name(int slot, const char *name, uint32_t len) {
    memset(&g_reads[slot], 0, sizeof(g_reads[slot]));
    if (!name) return;                    /* absent                      */
    g_reads[slot].present = 1;
    g_reads[slot].value_len = len;
    memcpy(g_reads[slot].value, name, len);
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

/* every effect names a generation-4 op (13 / 14) — never 4 / 5 / 6 */
static int only_new_ops(const dna_effect_view_t *ev) {
    for (uint16_t i = 0; i < ev->effect_count; i++)
        if (ev->eff[i].op_id != OP_VAL2 && ev->eff[i].op_id != OP_DELEG2)
            return 0;
    return 1;
}

static const uint8_t *ev_val(const dna_effect_view_t *ev, int i) {
    return ev->buf + ev->val_off[i];
}
static const uint8_t *ev_key(const dna_effect_view_t *ev, int i) {
    return ev->buf + ev->key_off[i];
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
    CHECK(s4->allowed_auth_kinds ==
              (NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
               NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1) |
               NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1)) &&
          s3->allowed_auth_kinds ==
              (NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
               NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1)),
          "SYSTEM allowlist: {1,2,3} in generation 4, {1,2} before");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "the compiled table passes its selfcheck (descriptor hashes "
          "unchanged, generation-conditional auth-kind pin)");

    static hk_env_t e;
    static uint8_t call[6000];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    dna_effect_view_t ev;
    const uint64_t H = 9;
    uint8_t vid[64], vid_m[64];
    memset(vid, 0xC1, sizeof(vid));
    memset(vid_m, 0xC2, sizeof(vid_m));
    ctx_reset(H);

    /* ── A1. read plans and lengths ───────────────────────────────── */
    {
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 3, "DELEGATE: 3 reads");
        uint8_t dk[128];
        memcpy(dk, g_k[KD].fp, 64);
        memcpy(dk + 64, vid, 64);
        CHECK(rq[0].op_id == OP_VAL2 && rq[0].key_len == 64 &&
              memcmp(rq[0].key, vid, 64) == 0 &&
              rq[1].op_id == OP_DELEG2 && rq[1].key_len == 128 &&
              memcmp(rq[1].key, dk, 128) == 0 &&
              rq[2].op_id == OP_DELEGCNT2 && rq[2].key_len == 64 &&
              memcmp(rq[2].key, vid, 64) == 0,
              "DELEGATE reads ops 13 / 14 / 15, keys from the call");
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 2 &&
              rq[0].op_id == OP_VAL2 && rq[1].op_id == OP_DELEG2 &&
              memcmp(rq[1].key, dk, 128) == 0, "UNDELEGATE: ops 13 / 14");
        for (int d = -1; d <= 1; d += 2) {
            CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call,
                           (uint32_t)((int)cl + d), 1) == 0, "env");
            CHECK(sys_plan(s4, &e, rq, &n) == -1, "DELEGATE 136 ± 1 plan");
            av_k1(KD);
            CHECK(sys_exec(s4, &e, 3, NULL) == -1, "DELEGATE 136 ± 1 exec");
            CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call,
                           (uint32_t)((int)cl + d), 1) == 0, "env");
            CHECK(sys_plan(s4, &e, rq, &n) == -1, "UNDELEGATE 136 ± 1");
        }
        cl = unstake2_call(call, vid, g_k[KO].fp);
        CHECK(cl == 128u, "gen-4 UNSTAKE is 128 bytes (C2)");
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 1 &&
              rq[0].op_id == OP_VAL2 && memcmp(rq[0].key, vid, 64) == 0,
              "UNSTAKE: op 13 by validator_id");
        /* ±1 and the pre-C2 64-byte layout: every one refused */
        {
            const int bad_len[3] = { 127, 129, 64 };
            for (int d = 0; d < 3; d++) {
                CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call,
                               (uint32_t)bad_len[d], 1) == 0, "env");
                CHECK(sys_plan(s4, &e, rq, &n) == -1,
                      "UNSTAKE 128 ± 1 / pre-C2 64 plan");
                CHECK(sys_exec(s4, &e, 1, NULL) == -1,
                      "UNSTAKE 128 ± 1 / pre-C2 64 exec");
            }
        }
        cl = vupd2_call(call, vid, g_k[KO].fp, 300);
        CHECK(cl == 130u, "gen-4 VALIDATOR_UPDATE is 130 bytes (C2)");
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 1 &&
              rq[0].op_id == OP_VAL2 && memcmp(rq[0].key, vid, 64) == 0,
              "VALIDATOR_UPDATE: op 13 by validator_id");
        {
            const int bad_len[3] = { 129, 131, 66 };
            for (int d = 0; d < 3; d++) {
                CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call,
                               (uint32_t)bad_len[d], 1) == 0, "env");
                CHECK(sys_plan(s4, &e, rq, &n) == -1,
                      "VUPD 130 ± 1 / pre-C2 66 plan");
                CHECK(sys_exec(s4, &e, 1, NULL) == -1,
                      "VUPD 130 ± 1 / pre-C2 66 exec");
            }
        }
        cl = vupd2_call(call, vid, g_k[KO].fp,
                        (uint16_t)(DNAC_COMMISSION_BPS_MAX + 1));
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1,
              "VUPD above the bps bound refused by the decoder");

        /* the legacy layouts: refused by generation 4, planned by 3 */
        cl = stake1_call(call, KD, 500, TEN_M);
        CHECK(cl == 2666u, "legacy STAKE is 2666 bytes");
        CHECK(hk_build(&e, DNA_SYSRULE_STAKE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1,
              "gen 4: the legacy 2666-B STAKE refused (plan — slice 4's "
              "STAKE is 7301 B, test_hf6_stake)");
        av_k1(KD);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1,
              "gen 4: the legacy 2666-B STAKE refused (exec)");
        CHECK(sys_plan(s3, &e, rq, &n) == 0 && n == 2 &&
              rq[0].op_id == OP_VAL && rq[1].op_id == OP_STATS,
              "gen 3: the same STAKE plans ops 4 / 7");
        cl = deleg1_call(call, g_k[KD].pk, g_k[KX].pk, DLG);
        CHECK(cl == 5192u, "legacy DELEGATE is 5192 bytes");
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1,
              "gen 4: legacy DELEGATE refused (plan)");
        CHECK(sys_exec(s4, &e, 3, NULL) == -1,
              "gen 4: legacy DELEGATE refused (exec)");
        CHECK(sys_plan(s3, &e, rq, &n) == 0 && n == 3 &&
              rq[0].op_id == OP_VAL && rq[1].op_id == OP_DELEG &&
              rq[2].op_id == OP_DELEGCNT,
              "gen 3: the same DELEGATE plans ops 4 / 5 / 6");
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1 &&
              sys_exec(s4, &e, 2, NULL) == -1,
              "gen 4: legacy UNDELEGATE refused");
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, g_k[KD].pk,
                       (uint32_t)PK_LEN, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1 &&
              sys_exec(s4, &e, 1, NULL) == -1,
              "gen 4: legacy 2592-B UNSTAKE refused");
        CHECK(sys_plan(s3, &e, rq, &n) == 0 && n == 1 &&
              rq[0].op_id == OP_VAL, "gen 3: the same UNSTAKE plans op 4");
        memcpy(call, g_k[KD].pk, PK_LEN);
        call[PK_LEN] = 0;
        call[PK_LEN + 1] = 100;
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call,
                       (uint32_t)PK_LEN + 2u, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == -1 &&
              sys_exec(s4, &e, 1, NULL) == -1,
              "gen 4: legacy 2594-B VALIDATOR_UPDATE refused");
        /* the reverse: the C2 lengths are no legacy layout (the length
         * sets stay disjoint — 128 / 130 vs 2592 / 2594) */
        cl = unstake2_call(call, vid, g_k[KO].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl, 1) == 0, "env");
        av_k1(KO);
        CHECK(sys_plan(s3, &e, rq, &n) == -1 &&
              sys_exec(s3, &e, 1, NULL) == -1,
              "gen 3: the 128-B UNSTAKE is refused");
        cl = vupd2_call(call, vid, g_k[KO].fp, 300);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(sys_plan(s3, &e, rq, &n) == -1 &&
              sys_exec(s3, &e, 1, NULL) == -1,
              "gen 3: the 130-B VALIDATOR_UPDATE is refused");
    }

    /* ── A2/A3. DELEGATE ─────────────────────────────────────────── */
    {
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        av_k1(KD);
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        rd_del2(1, g_k[KD].fp, vid, 0);
        rd_cnt(2, 0);
        CHECK(sys_exec(s4, &e, 3, &ev) == 0, "kind 1 delegator: applies");
        CHECK(ev.effect_count == 2 && only_new_ops(&ev) &&
              ev.eff[0].op_id == OP_DELEG2 &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 128 && ev.eff[0].value_len == D2_REC_LEN &&
              ev.eff[1].op_id == OP_VAL2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              ev.eff[1].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              ev.eff[1].value_len == V2_REC_LEN,
              "CREATE op 14 + SET op 13 — the new ops only");
        CHECK(memcmp(ev_key(&ev, 0), g_k[KD].fp, 64) == 0 &&
              memcmp(ev_key(&ev, 0) + 64, vid, 64) == 0 &&
              memcmp(ev_val(&ev, 0), ev_key(&ev, 0), 128) == 0 &&
              get64(ev_val(&ev, 0) + D2_AMT_OFF) == DLG &&
              get64(ev_val(&ev, 0) + D2_AT_OFF) == H,
              "the delegation row = delegator_fp ‖ validator_id ‖ amt ‖ h");
        CHECK(get64(ev_val(&ev, 1) + V2_TOT_OFF) == 9 * DLG &&
              get64(ev_val(&ev, 1) + V2_EXT_OFF) == 9 * DLG &&
              memcmp(ev_val(&ev, 1) + V2_OWNER_OFF, g_k[KO].fp, 64) == 0,
              "both totals + amount, owner carried through");
        /* top-up */
        rd_del2(1, g_k[KD].fp, vid, 2 * DLG);
        CHECK(sys_exec(s4, &e, 3, &ev) == 0 && ev.effect_count == 2 &&
              only_new_ops(&ev) && ev.eff[0].op_id == OP_VAL2 &&
              ev.eff[1].op_id == OP_DELEG2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              get64(ev_val(&ev, 1) + D2_AMT_OFF) == 3 * DLG,
              "kind 1 top-up: SET 13, SET 14");
        rd_del2(1, g_k[KD].fp, vid, 0);
        /* refusals */
        av_k1(KX);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "a non-delegator (kind 1)");
        g_ctx.auth = NULL;
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "no verdict");
        g_ctx.auth = &g_av;
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_CC_V1) == 0, "env");
        av_k1(KD);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "kind 2 carriage refused");
        /* kind 3: the delegator IS the multisig address */
        cl = deleg2_call(call, g_am, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        av_k3(g_am, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 3, &ev) == 0 && only_new_ops(&ev) &&
              memcmp(ev_key(&ev, 0), g_am, 64) == 0,
              "kind 3 delegator: applies, row keyed by the address");
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1,
              "kind 3, satisfied but the WRONG address");
        av_k3(g_am, 0, 1, 1);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "kind 3, unsatisfied");
        av_k3(g_am, 1, 0, 1);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1,
              "kind 3, an extra foreign signer (D6 bit clear)");
        av_k3(g_am, 1, 1, 2);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "kind 3, two descriptors");
        /* the delegation rules still hold */
        av_k3(g_am, 1, 1, 1);
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_RETIRING, 8 * DLG, 500);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "not BONDED");
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        g_reads[0].present = 0;
        g_reads[0].value_len = 0;
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "unknown validator");
        rd_val2(0, vid_m, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        CHECK(sys_exec(s4, &e, 3, NULL) == -2,
              "a row that is not the key it was read by: node fault");
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        rd_cnt(2, NODUS_MAX_DELEGATORS_PER_VALIDATOR);
        CHECK(sys_exec(s4, &e, 3, NULL) == -1, "validator full");
        rd_cnt(2, 0);
        cl = deleg2_call(call, g_am, vid, DLG - 1);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        CHECK(sys_exec(s4, &e, 3, NULL) == -1,
              "a new row below the minimum delegation");
    }

    /* ── A2/A3. UNDELEGATE ───────────────────────────────────────── */
    {
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        av_k1(KD);
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_RETIRING, 8 * DLG, 500);
        rd_del2(1, g_k[KD].fp, vid, 3 * DLG);
        CHECK(sys_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 2 &&
              only_new_ops(&ev) && ev.eff[0].op_id == OP_VAL2 &&
              ev.eff[1].op_id == OP_DELEG2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              get64(ev_val(&ev, 1) + D2_AMT_OFF) == 2 * DLG &&
              get64(ev_val(&ev, 1) + D2_AT_OFF) == 3 &&
              get64(ev_val(&ev, 0) + V2_TOT_OFF) == 7 * DLG,
              "partial: SET 13, SET 14 (no status gate, height kept)");
        rd_del2(1, g_k[KD].fp, vid, DLG);
        CHECK(sys_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 2 &&
              only_new_ops(&ev) &&
              ev.eff[1].effect_kind == DNA_EFFECT_DELETE &&
              ev.eff[1].op_id == OP_DELEG2,
              "drain: SET 13, DELETE 14");
        av_k1(KO);
        CHECK(sys_exec(s4, &e, 2, NULL) == -1,
              "the validator's owner is not the delegator");
        av_k1(KD);
        rd_del2(1, g_k[KD].fp, vid, 0);
        CHECK(sys_exec(s4, &e, 2, NULL) == -1, "unknown delegation");
        cl = deleg2_call(call, g_am, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        rd_del2(1, g_am, vid, DLG);
        av_k3(g_am, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 2, &ev) == 0 && only_new_ops(&ev),
              "kind 3 delegator drains");
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 2, NULL) == -1, "kind 3 wrong address");
        av_k3(g_am, 1, 0, 1);
        CHECK(sys_exec(s4, &e, 2, NULL) == -1, "kind 3 foreign signer");
    }

    /* ── A2/A3. UNSTAKE (owner in the call == the row's — C2) ─────── */
    {
        uint32_t cl = unstake2_call(call, vid, g_k[KO].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl, 1) == 0, "env");
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        av_k1(KO);
        CHECK(sys_exec(s4, &e, 1, &ev) == 0 && ev.effect_count == 1 &&
              only_new_ops(&ev) && ev.eff[0].op_id == OP_VAL2 &&
              ev_val(&ev, 0)[V2_STAT_OFF] == DNAC_VALIDATOR_RETIRING &&
              get64(ev_val(&ev, 0) + V2_UCOM_OFF) == H,
              "kind 1 owner: RETIRING at h, op 13 only");
        av_k1(KD);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "a non-owner (kind 1)");
        av_k1(KX);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "the consensus key is not the owner");
        /* C2 owner mismatch, kind 1: the call names KD, KD signs, the row
         * is KO's — refused although the signer matches the call */
        cl = unstake2_call(call, vid, g_k[KD].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl, 1) == 0, "env");
        av_k1(KD);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 1: call owner != row owner (signer == call owner)");
        av_k1(KO);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 1: call owner != row owner (signer == row owner)");
        cl = unstake2_call(call, vid, g_am);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        rd_val2(0, vid, g_am, DNAC_VALIDATOR_ELIGIBLE, 8 * DLG, 500);
        av_k3(g_am, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, &ev) == 0 && only_new_ops(&ev),
              "kind 3 owner (multisig-owned row)");
        /* C2 descriptor swap (SYSTEM): the signatures were given for the
         * vault named in the call (g_an); the row is g_am's and g_am's
         * satisfied descriptor rides along — refused by the owner
         * equality, whichever descriptor is presented */
        cl = unstake2_call(call, vid, g_an);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        av_k3(g_am, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 3: descriptor swapped to the row's vault, call names "
              "another vault");
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 3: the call's vault signs, the row is another's");
        cl = unstake2_call(call, vid, g_am);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 wrong address");
        av_k3(g_am, 0, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 unsatisfied");
        av_k3(g_am, 1, 0, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 foreign signer");
        av_k3(g_am, 1, 1, 2);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 two descriptors");
        av_k3(g_am, 1, 1, 1);
        rd_val2(0, vid, g_am, DNAC_VALIDATOR_RETIRING, 8 * DLG, 500);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "repeat (not BONDED)");
    }

    /* ── A2/A3. VALIDATOR_UPDATE (owner in the call == the row's) ─── */
    {
        uint32_t cl = vupd2_call(call, vid, g_k[KO].fp, 300);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        av_k1(KO);
        CHECK(sys_exec(s4, &e, 1, &ev) == 0 && ev.effect_count == 1 &&
              only_new_ops(&ev) &&
              get16(ev_val(&ev, 0) + V2_COMM_OFF) == 300 &&
              get16(ev_val(&ev, 0) + V2_PCOMM_OFF) == 0 &&
              get64(ev_val(&ev, 0) + V2_PEFF_OFF) == 0 &&
              get64(ev_val(&ev, 0) + V2_LUPD_OFF) == H,
              "decrease: immediate, Rule K stamp");
        cl = vupd2_call(call, vid, g_k[KO].fp, 700);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(sys_exec(s4, &e, 1, &ev) == 0 &&
              get16(ev_val(&ev, 0) + V2_COMM_OFF) == 500 &&
              get16(ev_val(&ev, 0) + V2_PCOMM_OFF) == 700 &&
              get64(ev_val(&ev, 0) + V2_PEFF_OFF) == H + 2 * E_LEN,
              "increase: deferred to h + 2E");
        av_k1(KD);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "a non-owner (kind 1)");
        /* C2 owner mismatch, kind 1 */
        cl = vupd2_call(call, vid, g_k[KD].fp, 700);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 1: call owner != row owner (signer == call owner)");
        av_k1(KO);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 1: call owner != row owner (signer == row owner)");
        cl = vupd2_call(call, vid, g_am, 700);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        rd_val2(0, vid, g_am, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        av_k3(g_am, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, &ev) == 0 && only_new_ops(&ev),
              "kind 3 owner");
        /* C2 descriptor swap (SYSTEM) */
        cl = vupd2_call(call, vid, g_an, 700);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 3: descriptor swapped to the row's vault, call names "
              "another vault");
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1,
              "C2 kind 3: the call's vault signs, the row is another's");
        cl = vupd2_call(call, vid, g_am, 700);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        av_k3(g_am, 1, 1, 1);
        av_k3(g_an, 1, 1, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 wrong address");
        av_k3(g_am, 1, 0, 1);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "kind 3 foreign signer");
        av_k3(g_am, 1, 1, 1);
        rd_val2(0, vid, g_am, DNAC_VALIDATOR_UNSTAKED, 8 * DLG, 500);
        CHECK(sys_exec(s4, &e, 1, NULL) == -1, "frozen stake");
    }

    /* ── A4. the CORE SYSFUND leg ────────────────────────────────── */
    {
        nodus_rt_read_req_t cr[NODUS_RT_MAX_READS];
        uint16_t cn = 0;
        uint32_t cl = stake1_call(call, KD, 500, TEN_M);
        CHECK(hk_build(&e, DNA_SYSRULE_STAKE, call, cl, 1) == 0, "env");
        av_k1(KD);
        /* slice 4: the generation-4 CORE leg pairs with a STAKE sibling
         * like ops 2..5 — the shape is the op id; a legacy-length STAKE
         * call is refused where the value moves (rtn_sys_call_flow at
         * exec), the legacy-UNSTAKE-sibling precedent */
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-4 CORE: a STAKE sibling plans (slice 4)");
        CHECK(nodus_rt_core_read_plan(c3, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-3 CORE: the same STAKE sibling plans");
        cl = deleg2_call(call, g_k[KD].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2, "gen-4 CORE: a gen-4 DELEGATE sibling plans");
        g_ctx.delegate_name_required = 1;
        CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 2 && cr[1].op_id != 6u,
              "D3 (3e): HF-8 on, the gen-4 CORE leg plans inputs + pool "
              "only — no CORE NAMEOWN (the SYSTEM leg judges the name)");
        {
            /* the gen-4 CORE leg under the gate keeps the 15-input
             * ceiling (the gated 14 is the generation-3 CORE budget) */
            static hk_env_t e15;
            static uint8_t f15[2 + 15 * 64 + 1];
            uint8_t nul[64];
            size_t off = 0;
            f15[off++] = 15;
            for (int i = 0; i < 15; i++) {
                memset(nul, 0x10 + i, sizeof(nul));
                memcpy(f15 + off, nul, 64);
                off += 64;
            }
            f15[off++] = 0;
            CHECK(hk_build(&e15, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0,
                  "env");
            /* swap the funding call for the 15-input one: rebuild by
             * hand (hk_build's funding call has one input) */
            dna_env_leg_in_t legs[2];
            memset(legs, 0, sizeof(legs));
            legs[0].hdr = e15.view.leg[0];
            legs[0].call_data = call;
            legs[0].auth_data = e15.auth[0];
            legs[1].hdr = e15.view.leg[1];
            legs[1].hdr.call_len = (uint32_t)off;
            legs[1].call_data = f15;
            legs[1].auth_data = e15.auth[1];
            dna_env_in_t in;
            memset(&in, 0, sizeof(in));
            in.fee_amount = FEE;
            in.res_max_total_units = 400000;
            in.leg_count = 2;
            in.legs = legs;
            CHECK(dna_env_encode(&in, e15.bytes, sizeof(e15.bytes),
                                 &e15.len) == 0 &&
                  dna_env_decode(e15.bytes, e15.len, &e15.view) == 0,
                  "env (15 inputs)");
            CHECK(nodus_rt_core_read_plan(c4, &e15.view, 1, &g_ctx, cr,
                                          NODUS_RT_MAX_READS, &cn) == 0 &&
                  cn == 16,
                  "D3 (3e): a gen-4 DELEGATE's CORE leg with 15 inputs "
                  "plans under the gate (15 + pool)");
        }
        cl = deleg1_call(call, g_k[KD].pk, g_k[KX].pk, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_core_read_plan(c3, &e.view, 1, &g_ctx, cr,
                                      NODUS_RT_MAX_READS, &cn) == 0 &&
              cn == 3, "gen 3: the legacy gate still plans NAMEOWN");
        g_ctx.delegate_name_required = 0;
    }

    /* ── A7. D3 (3e): the HF-8 name rule on the SYSTEM DELEGATE ──── */
    {
        uint8_t dk[128];
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        /* gate OFF: the 3c plan, byte for byte */
        g_ctx.delegate_name_required = 0;
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 3,
              "gate off: 3 reads, no NAMEOWN2");
        /* gate ON: + ONE read, op 16 keyed by the call's delegator_fp,
         * LAST (16 > 15: ascending (op, key) by construction) */
        g_ctx.delegate_name_required = 1;
        memcpy(dk, g_k[KD].fp, 64);
        memcpy(dk + 64, vid, 64);
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 4 &&
              rq[0].op_id == OP_VAL2 && rq[1].op_id == OP_DELEG2 &&
              memcmp(rq[1].key, dk, 128) == 0 &&
              rq[2].op_id == OP_DELEGCNT2 &&
              rq[3].op_id == OP_NAMEOWN2 && rq[3].key_len == 64 &&
              memcmp(rq[3].key, g_k[KD].fp, 64) == 0,
              "gate on: [13, 14, 15, 16(delegator_fp)]");
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s4, &e, rq, &n) == 0 && n == 2,
              "gate on: UNDELEGATE plans no name read");
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");

        /* a NON-owner delegator (owner KO, delegator KD) */
        av_k1(KD);
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        rd_del2(1, g_k[KD].fp, vid, 0);
        rd_cnt(2, 0);
        rd_name(3, NULL, 0);
        CHECK(sys_exec(s4, &e, 4, NULL) == -1,
              "gate on: a nameless non-owner delegator refused (-1)");
        rd_name(3, "alice", 5);
        CHECK(sys_exec(s4, &e, 4, &ev) == 0 && ev.effect_count == 2 &&
              only_new_ops(&ev),
              "gate on: a non-owner WITH a name applies (ops 13/14 only)");
        rd_name(3, "al", 2);
        CHECK(sys_exec(s4, &e, 4, NULL) == -2,
              "a present name below DNAC_NAME_MIN_LEN: adapter fault");
        rd_name(3, "abcdefghijklmnopqrstuvwxyz0123456789x", 37);
        CHECK(sys_exec(s4, &e, 4, NULL) == -2,
              "a present name above DNAC_NAME_MAX_LEN: adapter fault");
        rd_name(3, NULL, 0);
        CHECK(sys_exec(s4, &e, 3, NULL) == -2,
              "gate on, 3 reads: the n_reads contract (fault)");
        g_ctx.delegate_name_required = 0;
        CHECK(sys_exec(s4, &e, 4, NULL) == -2,
              "gate off, 4 reads: the n_reads contract (fault)");
        CHECK(sys_exec(s4, &e, 3, &ev) == 0,
              "gate off: a nameless non-owner applies (unchanged)");
        g_ctx.delegate_name_required = 1;

        /* the OWNER self-delegates, kind 1: exempt (no name) */
        cl = deleg2_call(call, g_k[KO].fp, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        av_k1(KO);
        rd_del2(1, g_k[KO].fp, vid, 0);
        rd_name(3, NULL, 0);
        CHECK(sys_exec(s4, &e, 4, &ev) == 0 && only_new_ops(&ev),
              "gate on: the owner (kind 1) without a name applies");
        /* the OWNER is a multisig address, kind 3: exempt (no name) */
        cl = deleg2_call(call, g_am, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_MSIG_V1) == 0, "env");
        av_k3(g_am, 1, 1, 1);
        rd_val2(0, vid, g_am, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        rd_del2(1, g_am, vid, 0);
        CHECK(sys_exec(s4, &e, 4, &ev) == 0 && only_new_ops(&ev),
              "gate on: the owner (kind 3) without a name applies");
        /* the same multisig delegator to a validator it does NOT own */
        rd_val2(0, vid, g_k[KO].fp, DNAC_VALIDATOR_ACTIVE, 8 * DLG, 500);
        CHECK(sys_exec(s4, &e, 4, NULL) == -1,
              "gate on: a nameless kind-3 non-owner refused");
        rd_name(3, "vault", 5);
        CHECK(sys_exec(s4, &e, 4, &ev) == 0,
              "gate on: a named kind-3 non-owner applies");
        /* the exemption is decided by the OBSERVED owner, never before
         * the validator row is judged: an unknown validator stays -1 */
        g_reads[0].present = 0;
        g_reads[0].value_len = 0;
        CHECK(sys_exec(s4, &e, 4, NULL) == -1,
              "gate on: unknown validator (-1)");

        /* generation 3 is untouched by the gate on the SYSTEM side */
        cl = deleg1_call(call, g_k[KD].pk, g_k[KX].pk, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(sys_plan(s3, &e, rq, &n) == 0 && n == 3 &&
              rq[2].op_id == OP_DELEGCNT,
              "gen 3 SYSTEM: gate on, the same 3 reads (ops 4 / 5 / 6)");
        g_ctx.delegate_name_required = 0;
    }

    /* ── A5. the read-only describer ─────────────────────────────── */
    {
        nodus_rt_leg_desc_t d;
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid, 2 * DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_DELEGATE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_DELEGATE &&
              memcmp(d.rec_delegator_fp, g_k[KD].fp, 64) == 0 &&
              memcmp(d.rec_validator_fp, vid, 64) == 0 &&
              d.rec_amount == 2 * DLG, "gen-4 DELEGATE described");
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 1, H, g_intent, &d) == 0
              && d.n_created == 1 &&
              memcmp(d.created[0].owner_hex, g_k[KD].hex, 128) == 0 &&
              d.created[0].amount == 2 * DLG &&
              d.created[0].unlock_block > H,
              "gen-4 UNDELEGATE release: owner hex(delegator_fp), locked");
        cl = deleg2_call(call, g_am, vid, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 3) == 0, "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 1, H, g_intent, &d) == 0
              && d.n_created == 1 &&
              memcmp(d.created[0].owner_hex, g_am_hex, 128) == 0,
              "a multisig delegator's release is owned by its address");
        cl = deleg1_call(call, g_k[KD].pk, g_k[KX].pk, DLG);
        CHECK(hk_build(&e, DNA_SYSRULE_UNDELEGATE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 1, H, g_intent, &d) == 0
              && d.n_created == 1 &&
              memcmp(d.created[0].owner_hex, g_k[KD].hex, 128) == 0,
              "legacy UNDELEGATE release: hex(SHA3-512(delegator pk))");
        cl = unstake2_call(call, vid, g_k[KO].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_UNSTAKE, call, cl, 1) == 0, "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_UNSTAKE &&
              memcmp(d.rec_validator_fp, vid, 64) == 0,
              "gen-4 UNSTAKE described");
        cl = vupd2_call(call, vid, g_k[KO].fp, 250);
        CHECK(hk_build(&e, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, 1) == 0,
              "env");
        CHECK(nodus_rt_native_describe_leg(&e.view, 0, H, g_intent, &d) == 0
              && d.rec == NODUS_RT_DESC_REC_VALIDATOR_UPDATE &&
              d.rec_commission_bps == 250 &&
              memcmp(d.rec_validator_fp, vid, 64) == 0,
              "gen-4 VALIDATOR_UPDATE described");
    }
    return 0;
}

/* ── A6. D6 through the REAL auth hook ────────────────────────────── */

/* a single-leg SYSTEM envelope carrying `blob` as its kind-3 auth */
static int k3_view(uint8_t *bytes, size_t cap, const uint8_t *blob,
                   size_t blen, dna_env_view_t *v, size_t *len) {
    static uint8_t call[130];
    uint8_t vid[64];
    memset(vid, 0xC1, sizeof(vid));
    uint32_t cl = vupd2_call(call, vid, g_am, 100);
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_VALIDATOR_UPDATE;
    leg.hdr.ruleset_version = 10;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    leg.hdr.call_len = cl;
    leg.hdr.auth_len = (uint32_t)blen;
    leg.hdr.res_max_effects = 8;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data = call;
    leg.auth_data = blob;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 1;
    in.legs = &leg;
    if (dna_env_encode(&in, bytes, cap, len) != 0) return -1;
    return dna_env_decode(bytes, *len, v);
}

static int t_auth_d6(void) {
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    CHECK(s4 != NULL, "generation 4 compiled");
    static uint8_t blob[64 * 1024], bytes[96 * 1024];
    dna_env_view_t v;
    size_t len = 0, bl = 0;
    nodus_rt_auth_verdict_t av;
    ctx_reset(9);

    const int two[2] = { K1, K2 };
    bl = k3_blob(blob, sizeof(blob), two, 2, 1, g_dig);
    CHECK(bl > 0 && k3_view(bytes, sizeof(bytes), blob, bl, &v, &len) == 0,
          "2 of M's keys sign");
    CHECK(nodus_rt_auth_dsa87_v1(s4, &v, 0, &g_ctx, &av) == 0 &&
          av.n_signers == 2 && av.n_msig == 1 && av.msig_satisfied[0] == 1 &&
          memcmp(av.msig_addr[0], g_am, 64) == 0 &&
          (av.msig_signers_in_desc & 1u) == 1u,
          "satisfied, address M, every signer is one of M's keys");

    const int three[3] = { K1, K2, KX };
    bl = k3_blob(blob, sizeof(blob), three, 3, 1, g_dig);
    CHECK(bl > 0 && k3_view(bytes, sizeof(bytes), blob, bl, &v, &len) == 0,
          "M's two keys + a foreign signer");
    CHECK(nodus_rt_auth_dsa87_v1(s4, &v, 0, &g_ctx, &av) == 0 &&
          av.n_signers == 3 && av.n_msig == 1 && av.msig_satisfied[0] == 1 &&
          av.msig_signers_in_desc == 0,
          "still satisfied (CORE's fact unchanged) — the D6 bit CLEAR");

    bl = k3_blob(blob, sizeof(blob), two, 2, 2, g_dig);
    CHECK(bl > 0 && k3_view(bytes, sizeof(bytes), blob, bl, &v, &len) == 0,
          "two descriptors M and N, signed by K1 + K2");
    CHECK(nodus_rt_auth_dsa87_v1(s4, &v, 0, &g_ctx, &av) == 0 &&
          av.n_msig == 2 && av.msig_satisfied[0] == 1 &&
          av.msig_satisfied[1] == 1 && av.msig_signers_in_desc == 3u,
          "each descriptor records its own bit");

    /* kind 1 and a bad signature leave the field 0 / reject */
    bl = k3_blob(blob, sizeof(blob), two, 2, 1, g_dig);
    blob[1 + PK_LEN + 5] ^= 0x01;
    CHECK(k3_view(bytes, sizeof(bytes), blob, bl, &v, &len) == 0 &&
          nodus_rt_auth_dsa87_v1(s4, &v, 0, &g_ctx, &av) == -1 &&
          av.msig_signers_in_desc == 0, "a bad signature: rejected, zeroed");
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

typedef struct { int key; uint8_t seed; uint64_t amount; } coin_def_t;
enum { CS1, CD1, CS2, CD2, CD3, CM1, CV1, CV2, CU1, CX1, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [CS1] = { KS,  0x61, 0 },            /* legacy STAKE at 3 (gen 3)    */
    [CD1] = { KD,  0x62, 0 },            /* legacy DELEGATE at 3         */
    [CS2] = { KS2, 0x63, 0 },            /* legacy STAKE at 6 (gen 4)    */
    [CD2] = { KD,  0x64, 0 },            /* legacy DELEGATE at 6         */
    [CD3] = { KD,  0x65, 0 },            /* gen-4 DELEGATE top-up at 7   */
    [CM1] = { KD,  0x66, 0 },            /* gen-4 kind-3 DELEGATE at 8   */
    [CV1] = { KS,  0x67, 0 },            /* gen-4 VUPD by the owner, 9   */
    [CV2] = { KD,  0x68, 0 },            /* gen-4 VUPD by a non-owner, 9 */
    [CU1] = { KD,  0x69, 0 },            /* gen-4 kind-3 UNDELEGATE, 10  */
    [CX1] = { KS,  0x6A, 0 },            /* gen-4 UNSTAKE at 11          */
};
static uint64_t g_amt[N_COINS];
static uint8_t  g_nul[N_COINS][64];

static void coin_amounts(void) {
    g_amt[CS1] = TEN_M + FEE;
    g_amt[CD1] = DLG + FEE;
    g_amt[CS2] = TEN_M + FEE;
    g_amt[CD2] = DLG + FEE;
    g_amt[CD3] = DLG + FEE;
    g_amt[CM1] = DLG + FEE;
    g_amt[CV1] = FEE;
    g_amt[CV2] = FEE;
    g_amt[CU1] = FEE;
    g_amt[CX1] = FEE;
}

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

#define H9   2u
#define HE   3u
#define HS   6u       /* param 18 (the generation-4 vote): H-1 = 5 */

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_calls_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x37, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
               (uint64_t)DNAC_CFG_RULESET_GEN2_D2, H9, 12) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D,
               HE, 14) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, HS, 13) != 0)
        return -1;
    for (int c = 0; c < N_COINS; c++)
        if (seed_coin(fx->w, c) != 0) return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
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

/* A 2-leg staking envelope against the registry's CURRENT manifests,
 * REALLY signed (two passes: framing, then the engine-derived leg
 * digests). The SYSTEM leg is kind 1 by `sys_signer` (>= 0) or — when
 * `sys_signer` < 0 — kind 3 over descriptor M signed by K1 + K2; the CORE
 * SYSFUND leg is kind 1 by the coin's owner, spending coin `c` entirely
 * (lock + FEE == its amount — no change). @return 0 / -1. */
static int st_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                  const uint8_t *sys_call, uint32_t sys_len, int c,
                  int sys_signer, uint8_t **out, size_t *out_len) {
    static uint8_t fund[2 + 64 + OUT_LEN];
    static uint8_t sys_auth[32 * 1024];
    static uint8_t core_auth[AUTH1];
    const int two[2] = { K1, K2 };
    dna_domain_manifest_t sys, core;
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0
        || nodus_witness_v2_chain_id(w, chain32) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul[c], COINS[c].key, 0, 0);
    size_t sys_alen = 0;
    if (sys_signer >= 0) {
        sys_alen = AUTH1;
        memset(sys_auth, 0, AUTH1);
    } else {
        sys_alen = k3_blob(sys_auth, sizeof(sys_auth), two, 2, 1, NULL);
        if (sys_alen == 0) return -1;
    }
    memset(core_auth, 0, sizeof(core_auth));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = sys_signer >= 0
                                ? NODUS_RT_AUTHKIND_DSA87_MULTI_V1
                                : NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    legs[0].hdr.call_len = sys_len;
    legs[0].hdr.auth_len = (uint32_t)sys_alen;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = sys_call;
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
        } else if (k3_blob(sys_auth, sizeof(sys_auth), two, 2, 1,
                           pf->auth_digest[0]) != sys_alen) {
            break;
        }
        core_auth[0] = 1;
        memcpy(core_auth + 1, g_k[COINS[c].key].pk, PK_LEN);
        if (qgp_dsa87_sign(core_auth + 1 + PK_LEN, &sl, pf->auth_digest[1],
                           64, g_k[COINS[c].key].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* apply one block of `n` (<= 4) envelopes; the per-item codes out */
static int apply(fixture_t *fx, uint64_t h, const nodus_v2_envelope_t *envs,
                 size_t n, uint32_t *codes) {
    nodus_v2_tx_result_t r[4];
    nodus_v2_block_t b;
    if (n > 4) return -1;
    memset(r, 0, sizeof(r));
    mk_block(&b, h, envs, n);
    b.cmt.results = r;
    b.cmt.results_cap = 4;
    if (v2x_cmt_apply(fx->w, &b) != 0) return -1;
    for (size_t i = 0; i < n; i++)
        if (codes) codes[i] = r[i].code;
    return 0;
}

/* one envelope, one block: 0 applied / 1 refused / -1 error */
static int apply1(fixture_t *fx, uint64_t h, uint8_t *bytes, size_t len) {
    nodus_v2_envelope_t v[1] = { { bytes, len } };
    uint32_t code = 0;
    int rc = apply(fx, h, v, 1, &code);
    free(bytes);
    if (rc != 0) return -1;
    return code == NODUS_V2_TX_OK ? 0 : 1;
}

/* SHA3-512 over the ledger tables' rows in key order — the state a
 * refused validator-record item must leave untouched */
static int ledger_digest(nodus_witness_t *w, uint8_t out[64]) {
    static const char *const q[] = {
        "SELECT * FROM validators ORDER BY pubkey_hash",
        "SELECT * FROM v2_validator_roles ORDER BY validator_id",
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
                 int l1, const uint8_t *b2, int l2, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = -1;
    if ((!b1 || sqlite3_bind_blob(st, 1, b1, l1, SQLITE_TRANSIENT) ==
                    SQLITE_OK) &&
        (!b2 || sqlite3_bind_blob(st, 2, b2, l2, SQLITE_TRANSIENT) ==
                    SQLITE_OK))
        rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* the validator_id (validators.pubkey_hash) of the row holding `pk` */
static int vid_of(nodus_witness_t *w, const uint8_t *pk, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT pubkey_hash FROM validators WHERE "
                           "pubkey = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ret = -1;
    if (sqlite3_bind_blob(st, 1, pk, (int)PK_LEN, SQLITE_TRANSIENT) ==
            SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

static int t_engine(void) {
    fixture_t F;
    static uint8_t call[6000];
    uint8_t *e = NULL;
    size_t l = 0;
    uint8_t v0pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t vid0[64], vids[64], dg_before[64], dg_after[64];
    uint64_t x = 0, y = 0;

    CHECK(E_LEN > 12, "no epoch boundary among heights 1..11");
    coin_amounts();
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&F, "eng") == 0,
          "seeded chain (param 9 at 2, param 14 at 3, param 18 at 6)");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(F.w->db, "SELECT pubkey FROM validators "
                                 "ORDER BY pubkey ASC LIMIT 1", -1, &st,
                                 NULL) == SQLITE_OK, "prepare");
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_bytes(st, 0) == (int)PK_LEN;
        if (ok) memcpy(v0pk, sqlite3_column_blob(st, 0), PK_LEN);
        sqlite3_finalize(st);
        CHECK(ok, "a genesis validator V0");
    }

    CHECK(apply(&F, 1, NULL, 0, NULL) == 0 && apply(&F, 2, NULL, 0, NULL)
          == 0, "blocks 1, 2 (the generation 2 and 3 edges)");

    /* ── B1. block 3, generation 3: the legacy calls apply ─────────── */
    {
        uint8_t *e2 = NULL;
        size_t l2 = 0;
        uint32_t codes[2];
        uint32_t cl = stake1_call(call, KS, 500, TEN_M);
        CHECK(st_env(F.w, 3, DNA_SYSRULE_STAKE, call, cl, CS1, KS, &e, &l)
              == 0, "legacy STAKE (gen 3)");
        static uint8_t call2[6000];
        uint32_t cl2 = deleg1_call(call2, g_k[KD].pk, v0pk, DLG);
        CHECK(st_env(F.w, 3, DNA_SYSRULE_DELEGATE, call2, cl2, CD1, KD, &e2,
                     &l2) == 0, "legacy DELEGATE (gen 3)");
        nodus_v2_envelope_t v[2] = { { e, l }, { e2, l2 } };
        int rc = apply(&F, 3, v, 2, codes);
        free(e); free(e2); e = NULL;
        CHECK(rc == 0 && codes[0] == NODUS_V2_TX_OK &&
              codes[1] == NODUS_V2_TX_OK,
              "generation 3: the 2666-B STAKE and 5192-B DELEGATE apply");
    }
    CHECK(apply(&F, 4, NULL, 0, NULL) == 0 && apply(&F, 5, NULL, 0, NULL)
          == 0, "blocks 4, 5 (= H-1: the generation-4 edge + migration)");
    {
        const nodus_domain_runtime_t *rt = NULL;
        CHECK(nodus_witness_v2_runtime_for(F.w, DNA_DOMAIN_SYSTEM, 1, &rt)
              == 0 && rt && rt->generation == NODUS_RT_GEN_STORAGE,
              "the registry judges generation 4");
    }
    CHECK(vid_of(F.w, v0pk, vid0) == 0 && vid_of(F.w, g_k[KS].pk, vids) == 0,
          "migrated validator_ids");
    CHECK(q_u64(F.w, "SELECT amount FROM delegations WHERE delegator_hash = "
                "?1 AND validator_hash = ?2", g_k[KD].fp, 64, vid0, 64, &x)
          == 0 && x == DLG, "the delegation re-keyed (SHA3(dpk), vid)");

    /* ── B3. block 6, generation 4: the legacy calls are refused ────── */
    {
        uint8_t *e2 = NULL;
        size_t l2 = 0;
        uint32_t codes[2];
        uint32_t cl = stake1_call(call, KS2, 500, TEN_M);
        CHECK(st_env(F.w, 6, DNA_SYSRULE_STAKE, call, cl, CS2, KS2, &e, &l)
              == 0, "legacy STAKE (gen 4)");
        static uint8_t call2[6000];
        uint32_t cl2 = deleg1_call(call2, g_k[KD].pk, v0pk, DLG);
        CHECK(st_env(F.w, 6, DNA_SYSRULE_DELEGATE, call2, cl2, CD2, KD, &e2,
                     &l2) == 0, "legacy DELEGATE (gen 4)");
        CHECK(ledger_digest(F.w, dg_before) == 0, "ledger before");
        nodus_v2_envelope_t v[2] = { { e, l }, { e2, l2 } };
        int rc = apply(&F, 6, v, 2, codes);
        free(e); free(e2); e = NULL;
        CHECK(rc == 0 && codes[0] != NODUS_V2_TX_OK &&
              codes[1] != NODUS_V2_TX_OK,
              "generation 4: the legacy STAKE and DELEGATE are refused");
        CHECK(ledger_digest(F.w, dg_after) == 0 &&
              memcmp(dg_before, dg_after, 64) == 0,
              "the ledger tables are byte-identical across the block");
    }

    /* ── B4. generation-4 calls apply end to end ─────────────────────── */
    {
        uint32_t cl = deleg2_call(call, g_k[KD].fp, vid0, DLG);
        CHECK(q_u64(F.w, "SELECT total_delegated FROM validators WHERE "
                    "pubkey_hash = ?1", vid0, 64, NULL, 0, &y) == 0,
              "V0 total before");
        CHECK(st_env(F.w, 7, DNA_SYSRULE_DELEGATE, call, cl, CD3, KD, &e, &l)
              == 0 && apply1(&F, 7, e, l) == 0,
              "block 7: kind-1 gen-4 DELEGATE top-up applies");
        CHECK(q_u64(F.w, "SELECT amount FROM delegations WHERE "
                    "delegator_hash = ?1 AND validator_hash = ?2",
                    g_k[KD].fp, 64, vid0, 64, &x) == 0 && x == 2 * DLG,
              "the re-keyed row topped up");
        CHECK(q_u64(F.w, "SELECT total_delegated FROM validators WHERE "
                    "pubkey_hash = ?1", vid0, 64, NULL, 0, &x) == 0 &&
              x == y + DLG, "V0 total_delegated + amount");

        cl = deleg2_call(call, g_am, vid0, DLG);
        CHECK(st_env(F.w, 8, DNA_SYSRULE_DELEGATE, call, cl, CM1, -1, &e, &l)
              == 0 && apply1(&F, 8, e, l) == 0,
              "block 8: kind-3 DELEGATE by the 2-of-3 address applies "
              "(funded by another key)");
        CHECK(q_u64(F.w, "SELECT amount FROM delegations WHERE "
                    "delegator_hash = ?1 AND validator_hash = ?2",
                    g_am, 64, vid0, 64, &x) == 0 && x == DLG,
              "a new (multisig address, validator_id) row");
        CHECK(q_u64(F.w, "SELECT length(delegator_pubkey) + "
                    "length(validator_pubkey) FROM delegations WHERE "
                    "delegator_hash = ?1 AND validator_hash = ?2",
                    g_am, 64, vid0, 64, &x) == 0 && x == 2 * PK_LEN,
              "its pubkey columns are full-length (the 3b precedent)");

        uint8_t *e2 = NULL;
        size_t l2 = 0;
        uint32_t codes[2];
        cl = vupd2_call(call, vids, g_k[KS].fp, 300);
        CHECK(st_env(F.w, 9, DNA_SYSRULE_VALIDATOR_UPDATE, call, cl, CV1, KS,
                     &e, &l) == 0, "VUPD by the owner");
        static uint8_t call2[130];
        uint32_t cl2 = vupd2_call(call2, vids, g_k[KD].fp, 200);
        CHECK(st_env(F.w, 9, DNA_SYSRULE_VALIDATOR_UPDATE, call2, cl2, CV2,
                     KD, &e2, &l2) == 0, "VUPD by a non-owner");
        nodus_v2_envelope_t v[2] = { { e, l }, { e2, l2 } };
        int rc = apply(&F, 9, v, 2, codes);
        free(e); free(e2); e = NULL;
        CHECK(rc == 0 && codes[0] == NODUS_V2_TX_OK &&
              codes[1] != NODUS_V2_TX_OK,
              "block 9: the owner's VALIDATOR_UPDATE applies, the "
              "non-owner's is refused");
        CHECK(q_u64(F.w, "SELECT commission_bps FROM validators WHERE "
                    "pubkey_hash = ?1", vids, 64, NULL, 0, &x) == 0 &&
              x == 300, "the decrease took effect immediately");

        cl = deleg2_call(call, g_am, vid0, DLG);
        CHECK(st_env(F.w, 10, DNA_SYSRULE_UNDELEGATE, call, cl, CU1, -1, &e,
                     &l) == 0 && apply1(&F, 10, e, l) == 0,
              "block 10: kind-3 UNDELEGATE drains the multisig row");
        CHECK(q_u64(F.w, "SELECT COUNT(*) FROM delegations WHERE "
                    "delegator_hash = ?1 AND validator_hash = ?2",
                    g_am, 64, vid0, 64, &x) == 0 && x == 0, "row deleted");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(F.w->db, "SELECT amount, unlock_block "
                                     "FROM utxo_set WHERE owner = ?1", -1,
                                     &st, NULL) == SQLITE_OK, "prepare");
            int ok = sqlite3_bind_text(st, 1, g_am_hex, 128,
                                       SQLITE_TRANSIENT) == SQLITE_OK &&
                     sqlite3_step(st) == SQLITE_ROW &&
                     (uint64_t)sqlite3_column_int64(st, 0) == DLG &&
                     (uint64_t)sqlite3_column_int64(st, 1) > 10u &&
                     sqlite3_step(st) == SQLITE_DONE;
            sqlite3_finalize(st);
            CHECK(ok, "the release coin is owned by the multisig address "
                      "(the call's delegator_fp) and locked");
        }

        cl = unstake2_call(call, vids, g_k[KS].fp);
        CHECK(st_env(F.w, 11, DNA_SYSRULE_UNSTAKE, call, cl, CX1, KS, &e, &l)
              == 0 && apply1(&F, 11, e, l) == 0,
              "block 11: UNSTAKE by the owner applies");
        CHECK(q_u64(F.w, "SELECT status FROM validators WHERE pubkey_hash = "
                    "?1", vids, 64, NULL, 0, &x) == 0 &&
              x == DNAC_VALIDATOR_RETIRING &&
              q_u64(F.w, "SELECT unstake_commit_block FROM validators WHERE "
                    "pubkey_hash = ?1", vids, 64, NULL, 0, &y) == 0 &&
              y == 11, "RETIRING at 11");
    }

    /* ── B5. D3 (3e): the SYSTEM adapter's READ-ONLY NAMEOWN2 (op 16)
     * serves the committed v2_names row by owner — the same row the
     * CORE NAMEOWN (op 6) serves. The row is written by direct SQL AFTER
     * the last applied block (no block follows, so no root is judged
     * against it). */
    {
        const nodus_domain_runtime_t *sys = NULL;
        nodus_rt_read_req_t rq;
        nodus_rt_read_res_t rr;
        sqlite3_stmt *st = NULL;
        CHECK(nodus_witness_v2_runtime_for(F.w, DNA_DOMAIN_SYSTEM, 1, &sys)
              == 0 && sys, "the generation-4 SYSTEM runtime");
        CHECK(sqlite3_prepare_v2(F.w->db, "INSERT INTO v2_names (name, "
                                 "owner, registered_height) VALUES "
                                 "(?1, ?2, 11)", -1, &st, NULL) ==
              SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, "alice", 5, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, g_k[KD].fp, 64, SQLITE_STATIC);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        CHECK(rc == SQLITE_DONE, "a v2_names row for KD");
        memset(&rq, 0, sizeof(rq));
        rq.op_id = OP_NAMEOWN2;
        rq.key_len = 64;
        memcpy(rq.key, g_k[KD].fp, 64);
        CHECK(nodus_witness_v2_read_one(F.w, sys, &rq, &rr) ==
                  NODUS_ADAPTER_OK && rr.present == 1 &&
              rr.value_len == 5 && memcmp(rr.value, "alice", 5) == 0,
              "op 16: KD's name, served by the SYSTEM adapter");
        memcpy(rq.key, g_k[KX].fp, 64);
        CHECK(nodus_witness_v2_read_one(F.w, sys, &rq, &rr) ==
                  NODUS_ADAPTER_OK && rr.present == 0 && rr.value_len == 0,
              "op 16: a nameless owner reads ABSENT (never a fault)");
        rq.key_len = 63;
        CHECK(nodus_witness_v2_read_one(F.w, sys, &rq, &rr) ==
                  NODUS_ADAPTER_ERR_SHAPE,
              "op 16: a 63-byte key is out of the op's shape");
    }
    fx_close(&F);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "hooks_gen4_calls_owner_auth", t_hooks },
        { "auth_hook_d6_bit",            t_auth_d6 },
        { "engine_gen3_to_gen4_calls",   t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0 || descs_make() != 0) {
        fprintf(stderr, "test_hf6_calls: key / descriptor setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_calls: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
