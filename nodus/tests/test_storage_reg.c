/**
 * @file nodus/tests/test_storage_reg.c
 * @brief HF-6 slice 6b-1 — STORAGE_REGISTER v2 / STORAGE_EXIT v2 under the
 *        owner/node split: the hook-level rule matrix, and registrations
 *        applied end to end on twin generation-4 chains through exit,
 *        release, the old life's last settlement and a re-registration
 *        under a different owner.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §11 items 1-5 (identity = the node key; REGISTER v2 7299 B; the exact
 * STORAGE_BOND with 0 < bond <= INT64_MAX; the re-registration rule
 * ⌊(h−1)/E⌋ − ⌊(x−1)/E⌋ >= 2; EXIT v2 by the row's owner — 128 B =
 * node_fp ‖ owner_fp since the khan decision of 2026-10-13, docs/plans/
 * decisions/2026-10-13-kurultay-18-summary.md item 2 "C2"), §2 (call
 * table), §6.1 (consent bytes: op 3, subject 64 × 0, ctx
 * "nodus.valbind.v1"), G11-G13, and the khan decisions under §11.7 of
 * 2026-10-12 (A2: a released node may register again under a DIFFERENT
 * owner). Decisions docs/plans/decisions/2026-10-09-kurultay-16-hf6-
 * storage-summary.md (khan 1 and 3: layouts, consent op 3, the rule;
 * STORAGE_BOND exact, [100k, 1M] NODUS, default 1M) and the storage-reward
 * records it keeps (2026-10-04-storage-reward-approved.md, 2026-10-05-
 * storage-reward-is-for-archive.md). Plan tasks/hf6-slice6b-plan.md §1.1-
 * §1.3, §2 "6b-1".
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. HOOK LEVEL — nodus_rt_system_read_plan / _exec (and the CORE SYSFUND
 *     leg) of the GEN_STORAGE (= HF-6 generation 4) runtimes over
 *     fabricated engine facts (a decoded 2-leg envelope, a verdict,
 *     mediated-read results) and REAL ML-DSA-87 node consents:
 *   A1 plans: REGISTER = [row op 8 keyed SHA3-512(call.node_pk), live
 *      count op 9 selector 1]; EXIT = [row op 8 keyed by the call's first
 *      64 bytes, node_fp]; generation 2 plans nothing; a malformed REPORT
 *      refused (its rule: test_storage_b2).
 *   A2 REGISTER positives: kind 1 (owner KO signs) — ONE CREATE / ABSENT
 *      on op 8 keyed node_fp whose 2693-byte record is node_pk ‖ owner_fp
 *      (the call's, in the payee_fp column) ‖ bond ‖ ACTIVE ‖ h ‖ 0 ‖ 0 ‖
 *      0; kind 3 (owner = a 2-of-3 address, the Foundation shape) — the
 *      record names the address; expiry h and h + 720 accepted; 255 live
 *      rows admit one more.
 *   A3 REGISTER refusals, each -1 (a verdict, never -2): call length 7298
 *      / 7300 (plan and exec); the storage-reward-v1 2664-byte layout;
 *      the v1 2592-byte EXIT layout; signer != owner_fp; the node key as
 *      the signer; two signers; kind 2; kind 3 whose descriptor address !=
 *      owner_fp, with a foreign signer, below M; bond 0, STORAGE_BOND − 1,
 *      STORAGE_BOND + 1, INT64_MAX + 1; expiry h − 1 and h + 721; a
 *      consent with op 1, op 2, op 3 over a NON-ZERO subject, another
 *      owner, another chain, another signing key, the empty ctx, ctx
 *      "nodus.valbind.v2"; the node's row ACTIVE, EXITING, RELEASED with
 *      exit_height 0; 256 live rows; a single-leg envelope; a CORE sibling
 *      that is not SYSFUND; generation 3 (GEN_EVM), generation 2 and a NULL
 *      runtime. A row whose node_pk is not the call's is -2 (the adapter
 *      out of contract).
 *   A4 re-registration from RELEASED (design §11.4), for x on a boundary
 *      (x = 2E) and x = 2E − 1 (B_rel = 2E for both): h = B_rel + E (3E)
 *      refused, h = B_rel + E + 1 accepted — ONE SET / EXISTS_VHASH bound
 *      to the observed record's value hash, the record reset (registered
 *      h, exit 0, fail_streak 0, grace_until 0); h = x + 1 refused. A2: a
 *      revive at B_rel + E + 1 naming a DIFFERENT owner (KP) than the
 *      released row's (KO) applies with owner_fp = KP when KP signs, and
 *      is refused when the OLD owner signs it.
 *   A5 EXIT: by the row's owner kind 1 and kind 3 — ONE SET / EXISTS_VHASH
 *      on op 8 (the only op named), EXITING, exit_height h, every other
 *      column copied (fail_streak and grace_until included); refused (-1):
 *      the node key as the signer, a non-owner, call length 127 / 129 and
 *      the pre-C2 64 (plan and exec), no row, EXITING, RELEASED, a
 *      non-SYSFUND sibling, a single leg; C2: the call's owner_fp not the
 *      row's — kind 1 signed by the call's owner AND by the row's owner,
 *      kind 3 with the row's vault descriptor swapped in for the call's
 *      vault (the descriptor swap) and with the call's vault signing; a
 *      row whose key does not hash from its node_pk is -2.
 *   A6 the CORE SYSFUND leg pairs with a storage op only under GEN_STORAGE
 *      (the generation-2 CORE refuses the plan; GEN_STORAGE plans inputs +
 *      pool), and a THIRD-PARTY-funded REGISTER balances: leg 1 signed by
 *      a key that is neither the owner nor the node, its coin, Σin == fee
 *      + bond (design §11.3 "kim öderse ödesin").
 *  B. ENGINE, twin fixtures (same seed, same genesis, every block applied
 *     to both; after EVERY block the committed global roots are equal; at
 *     every boundary and every block with an envelope each committed
 *     SYSTEM head equals its runtime's recomputation): seven seeded
 *     validators with REAL keys (every block carries their COMMIT votes),
 *     treasury pool 1 = 10^16, param 9 at 2, param 14 at 3, param 18 at 4
 *     (the generation-4 edge runs in block 3), eight segments PRE-SEEDED
 *     (published at 1). KN is the storage node key, KO its first owner, KP
 *     the second; KN never signs a leg, it only consents.
 *       block 2 (generation 2): a registration is NOT applied; no row.
 *       block 4: KO registers KN (kind 1, KN's op-3 consent): code OK; the
 *         row (node_pk = KN, owner = KO, bond STORAGE_BOND, ACTIVE, 4, 0)
 *         with typed columns; the coin spent, the change created; reward
 *         pool += fee; utxo + pool + storage bonds unchanged (supply
 *         conserved); the CORE invariant holds; the committed SYSTEM root
 *         is the v5 composition and moved.
 *       block 5: four refusals with real signatures — KO again (ACTIVE),
 *         the SYSTEM leg signed by the NODE key, bond − 1, a consent signed
 *         by a foreign key: registry root unchanged.
 *       block 6: an EXIT signed by the node key (not the owner) and an
 *         EXIT of an unregistered node: both refused; KN still ACTIVE.
 *       boundary E: KN in set(E) (the first storage boundary: no grace).
 *       block 2E (a boundary block): KO's EXIT applies before the boundary
 *         step; the boundary releases the bond as ONE locked UTXO owned by
 *         KO's hex fingerprint (the row's owner — not the node), amount
 *         STORAGE_BOND, unlock 2E + 12E, identity dna_v2_storage_exit_id;
 *         the row RELEASED with exit_height 2E; bonds − BOND, utxo + BOND;
 *         set(2E) excludes KN.
 *       2E + 1: all seven seats report for H = E with KN's bit 1.
 *       block 3E (= B_rel + E): KO and KP each try to register KN again:
 *         both REFUSED (the rule, same owner and different owner alike);
 *         the boundary in that same block settles H = E and credits the
 *         OLD owner KO exactly the pool-1 debit (> 0); KP has nothing; the
 *         row still names KO.
 *       block 3E + 1: KP registers KN (A2): code OK; the row ACTIVE, owner
 *         KP, registered 3E + 1, exit 0, fail_streak 0, grace_until 0;
 *         KO's accrual unchanged; one bond in the supply term; the CORE
 *         invariant holds on both twins.
 *       HF-6 slice 8a — block 3E + 2, with a committed param-21
 *         (STORAGE_BOND) row of 10^13 effective there: KN2 registered
 *         with the compiled 1M is REFUSED, KN3 with exactly 10^13
 *         APPLIES (its row records 10^13 on both twins) — the engine
 *         reads the row, not the constant.
 *       HF-6 slice 8a — block 3E + 3 on twin A, with an out-of-range
 *         param-21 row (10^14 + 1, which no vote can commit) effective
 *         there: the block FAILS WHOLE — a node fault whose reason is
 *         env_storage_bond's range check, never a verdict and never the
 *         default; the last block stays 3E + 2.
 *  A3 also (HF-6 slice 8a): the exact bond is the engine fact
 *     ctx.storage_bond — at 10^13 the bond 10^13 applies and the compiled
 *     1M is refused; a ctx carrying 0 (never engine-filled) is -2.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: an EVM-enabled (standalone, non-Windows) build —
 * generation 4 exists only there; the CMake target is registered only
 * then. DNAC_EPOCH_LENGTH >= 8 (checked: no boundary among heights 1..7);
 * every height is derived from it, so the production 720 and the harness
 * 15 both work. Environment: none. Cost: section B applies 3E + 2 blocks
 * to each of two fixtures (≈ 4 300 block applications at E = 720), each
 * followed by a global-root compare, plus one aborted block on one.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_storage_reg_* directories, removed at the end (left
 * behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Section A fabricates the verdict and the read results: it proves the
 *    hooks' rule decisions, not the engine's read execution or leg
 *    signature verification (section B does those). Its node consents
 *    are REAL signatures, verified by the exec.
 *  - The cap (256 live rows) is proven at hook level only (a fabricated
 *    count of 255 / 256); no 256-node chain is built.
 *  - The param-21 rows of the HF-6 slice 8a steps are written straight
 *    into chain_config_history (cc_row), not voted: the vote's rules
 *    (range, grace, generation 4) are test_hf4_params.c's. The legal row
 *    is planted right before a block whose applied item touches SYSTEM;
 *    the out-of-range row's fault aborts its block before phase 8. A
 *    fault for another reason would fail the reason check.
 *  - B's genesis UTXOs, validator rows and segments are SEEDED
 *    (V2X_SEED_NOT_REAL_UTXOS; segments published at 1, a state the chain
 *    never writes — the test_storage_b2 device). The validators are
 *    seated by construction, not by a ceremony.
 *  - B's settlement verdict is today's (slice 6b-2 changes F2 to the
 *    owner-or-key rule): KO and KP own no validator, so the result is the
 *    same under both rules.
 *  - Refusals are asserted by item code and by the registry / bond /
 *    accrual observations, not by a whole-database digest. A refused item
 *    leaves its coin today (decision 2026-09-25-failed-tx-pays-fee.md
 *    approved, not implemented); every case uses its own coin.
 *  - "Twin" is two fixtures in one process, not a 7-machine run.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/msig_wire.h"
#include "dnac/validator.h"
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

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define D2       ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define D4       ((uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define BOND     ((uint64_t)DNAC_HF6_STORAGE_BOND_DEFAULT)
#define CHG      700000000ULL
#define POOL1    10000000000000000ULL          /* 10^16 raw (pool 1)     */
#define OUT_LEN  232u
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN  ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define SGN_LEN  ((size_t)NODUS_RT_AUTH_SIGNER_LEN)
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define N_SEGS   8u
#define REP_FIXED 78u

/* design §2 / §11.3 / §11.5 (Kurultay #16 khan decision 1) */
#define STREG_LEN  7299u          /* 64 + 2592 + 4627 + 8 + 8            */
#define STEXIT_LEN 128u           /* node_fp ‖ owner_fp (C2, 2026-10-13) */
#define V1_STREG_LEN 2664u        /* storage reward v1 (refused)         */

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STOR        8u
#define OP_STORCNT     9u
#define OP_UTXO        1u
#define OP_SUPPLY      3u
#define SEL_POOL       3u
#define STOR_REC_LEN   2693u
#define STOR_OWNER_OFF 2592u      /* the payee_fp column = the owner     */
#define STOR_BOND_OFF  2656u
#define STOR_STAT_OFF  2664u
#define STOR_REGH_OFF  2665u
#define STOR_EXITH_OFF 2673u
#define STOR_FAIL_OFF  2681u
#define STOR_GRACE_OFF 2685u
#define UTXO_REC_LEN   284u
#define UTXO_AMT_OFF   128u
#define UTXO_UNL_OFF   276u

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk)                        */
    char    hex[129];
} sk_key_t;

/* V0..V6 the validators (section B); KN the storage node key; KO its
 * first owner, KP its second (A2); KX a foreign key; K1..K3 the multisig
 * keys of the 2-of-3 owner M; KN2 / KN3 / KN4 the HF-6 slice 8a storage
 * node keys (section B, the param-21 steps). */
enum { V0, V1, V2, V3, V4, V5, V6, KN, KO, KP, KX, K1, K2, K3, KN2, KN3,
       KN4, N_KEYS };
#define N_VAL 7
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
        memset(seed, 0x51 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* ══ the 2-of-3 owner M = {K1, K2, K3} (the Foundation's shape) ══════ */

static uint8_t g_dm[DNA_MSIG_MAX_DESC_LEN];
static size_t  g_dm_len;
static uint8_t g_am[64];                       /* address of M            */
static uint8_t g_an[64];                       /* a foreign address        */

/* The generation-4 STORAGE_EXIT call node_fp ‖ owner_fp (128 B — khan
 * decision 2026-10-13, Kurultay #18 item 2 "C2"). One static buffer: every
 * caller encodes it into an envelope before the next call. */
static uint8_t g_xc[STEXIT_LEN];
static const uint8_t *exit_call(const uint8_t node_fp[64],
                                const uint8_t owner[64]) {
    memcpy(g_xc, node_fp, 64);
    memcpy(g_xc + 64, owner, 64);
    return g_xc;
}

static int desc_make(void) {
    static uint8_t keys[3 * 2592];
    int ord[3] = { K1, K2, K3 };
    for (int a = 1; a < 3; a++)                /* ascending by pubkey     */
        for (int b = a; b > 0 &&
             memcmp(g_k[ord[b - 1]].pk, g_k[ord[b]].pk, PK_LEN) > 0; b--) {
            int t = ord[b];
            ord[b] = ord[b - 1];
            ord[b - 1] = t;
        }
    for (int i = 0; i < 3; i++)
        memcpy(keys + (size_t)i * PK_LEN, g_k[ord[i]].pk, PK_LEN);
    if (dna_msig_desc_encode(2, 3, keys, g_dm, DNA_MSIG_MAX_DESC_LEN,
                             &g_dm_len) != 0)
        return -1;
    if (dna_msig_address(g_dm, g_dm_len, g_am) != 0) return -1;
    memset(g_an, 0xA7, sizeof(g_an));
    return 0;
}

/* ══ the generation-4 STORAGE_REGISTER call ══════════════════════════ */

/* How the node consent is formed (A3 consent variants). */
enum {
    CS_OK = 0,        /* §6.1, op 3, zero subject, ctx "nodus.valbind.v1" */
    CS_OP_STAKE,      /* op 1 (STAKE), zero subject                       */
    CS_OP_ROTATE,     /* op 2 (ROTATE), non-zero subject                  */
    CS_OP3_SUBJECT,   /* op 3 over a NON-ZERO subject (restated message —
                       * the codec refuses to build it)                   */
    CS_OWNER_OTHER,   /* another owner_fp in the signed message           */
    CS_CHAIN_OTHER,   /* another chain id                                 */
    CS_KEY_OTHER,     /* signed by another key's sk                       */
    CS_CTX_EMPTY,     /* qgp_dsa87_sign: empty ctx                        */
    CS_CTX_OTHER      /* ctx "nodus.valbind.v2"                           */
};

static const uint8_t VB_CTX[16] = {
    'n','o','d','u','s','.','v','a','l','b','i','n','d','.','v','1'
};

/* owner_fp ‖ node_pk ‖ consent_sig ‖ expiry ‖ bond, with the node `node`
 * consenting on `chain32`. @return STREG_LEN / 0 on a setup failure. */
static uint32_t streg_call(uint8_t *dst, const uint8_t chain32[32],
                           const uint8_t owner[64], int node,
                           uint64_t expiry, uint64_t bond, int variant) {
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    uint8_t chain[32], own[64], subj[64];
    uint8_t op = DNA_VALBIND_OP_STORAGE_REGISTER;
    memcpy(chain, chain32, 32);
    memcpy(own, owner, 64);
    memset(subj, 0, sizeof(subj));
    if (variant == CS_CHAIN_OTHER) chain[0] ^= 0x01;
    if (variant == CS_OWNER_OTHER) own[0] ^= 0x01;
    if (variant == CS_OP_STAKE) op = DNA_VALBIND_OP_STAKE;
    if (variant == CS_OP_ROTATE) {
        op = DNA_VALBIND_OP_ROTATE;
        memset(subj, 0x5E, sizeof(subj));
    }
    uint8_t *sig = dst + 64 + PK_LEN;
    size_t sl = 0;
    int rc;
    if (variant == CS_OP3_SUBJECT) {
        /* §6.1 restated by hand: version 1 ‖ chain ‖ op 3 ‖ subject ≠ 0 ‖
         * owner ‖ pk ‖ expiry, signed with the right ctx */
        memset(msg, 0, sizeof(msg));
        msg[3] = 1;
        memcpy(msg + 4, chain, 32);
        msg[36] = DNA_VALBIND_OP_STORAGE_REGISTER;
        memset(msg + 37, 0x5E, 64);
        memcpy(msg + 101, own, 64);
        memcpy(msg + 165, g_k[node].pk, PK_LEN);
        put64(msg + 2757, expiry);
        rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg), VB_CTX,
                                sizeof(VB_CTX), g_k[node].sk);
    } else {
        if (dna_valbind_consent_msg(msg, chain, op, subj, own, g_k[node].pk,
                                    expiry) != 0)
            return 0;
        if (variant == CS_CTX_OTHER)
            rc = qgp_dsa87_sign_ctx(sig, &sl, msg, sizeof(msg),
                                    (const uint8_t *)"nodus.valbind.v2", 16,
                                    g_k[node].sk);
        else if (variant == CS_CTX_EMPTY)
            rc = qgp_dsa87_sign(sig, &sl, msg, sizeof(msg), g_k[node].sk);
        else
            rc = dna_valbind_consent_sign(sig, &sl, msg,
                                          g_k[variant == CS_KEY_OTHER
                                                  ? KX : node].sk);
    }
    if (rc != 0 || sl != SIG_LEN) return 0;
    memcpy(dst, owner, 64);
    memcpy(dst + 64, g_k[node].pk, PK_LEN);
    size_t off = 64 + PK_LEN + SIG_LEN;
    put64(dst + off, expiry);         off += 8;
    put64(dst + off, bond);           off += 8;
    return off == STREG_LEN ? STREG_LEN : 0;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count ‖ outputs (change back to
 * `chg_key` when `change` > 0) */
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
    uint8_t  auth[2][AUTH_LEN];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

/* a decoded envelope: leg 0 SYSTEM `op` (call), leg 1 CORE `core_op` (a
 * 1-input, 0-output funding call, nullifier 0xA5…) unless `single`; auth
 * bytes zero (the hooks read the verdict, never the auth bytes) */
static int hk_build(hk_env_t *e, uint32_t op, const uint8_t *call,
                    uint32_t call_len, uint8_t sys_kind, uint32_t core_op,
                    int single) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul, KO, 0, 0);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = 10;   /* the generation-4 SYSTEM (D2) */
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = sys_kind;
    legs[0].hdr.call_len = call_len;
    legs[0].hdr.auth_len = AUTH_LEN;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = e->auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = core_op;
    legs[1].hdr.ruleset_version = 8;    /* the generation-4 CORE (D2)   */
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH_LEN;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = e->fund;
    legs[1].auth_data = e->auth[1];
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = single ? 1 : 2;
    in.legs = legs;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view);
}

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void ctx_at(uint64_t height) {
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
    /* HF-6 slice 8a: the engine facts every ctx carries — params 19 / 21
     * with no row (env_stake_min / env_storage_bond's defaults) */
    g_ctx.stake_min = (uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT;
    g_ctx.storage_bond = BOND;
}

/* kind-1 verdict: `key` alone, or `key` + KX when `two` */
static void av_k1(int key, int two) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = two ? 2 : 1;
    memcpy(g_av.signer_fp[0], g_k[key].fp, 64);
    if (two) memcpy(g_av.signer_fp[1], g_k[KX].fp, 64);
}

/* kind-3 verdict: K1 + K2 signed one descriptor of address `addr` */
static void av_k3(const uint8_t addr[64], int satisfied, int in_desc) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 2;
    memcpy(g_av.signer_fp[0], g_k[K1].fp, 64);
    memcpy(g_av.signer_fp[1], g_k[K2].fp, 64);
    g_av.n_msig = 1;
    memcpy(g_av.msig_addr[0], addr, 64);
    g_av.msig_satisfied[0] = (uint8_t)(satisfied ? 1 : 0);
    g_av.msig_signers_in_desc = in_desc ? 1u : 0u;
}

static nodus_rt_read_res_t g_reads[NODUS_RT_MAX_READS];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* a fabricated registry record of KN */
static void rec_make(uint8_t *r, const uint8_t owner[64], uint8_t status,
                     uint64_t regh, uint64_t exith) {
    memset(r, 0, STOR_REC_LEN);
    memcpy(r, g_k[KN].pk, PK_LEN);
    memcpy(r + STOR_OWNER_OFF, owner, 64);
    put64(r + STOR_BOND_OFF, BOND);
    r[STOR_STAT_OFF] = status;
    put64(r + STOR_REGH_OFF, regh);
    put64(r + STOR_EXITH_OFF, exith);
}

/* reads: [0] KN's row (absent when status == 0) owned by `owner`, a
 * lived-in row (fail_streak 2, grace_until set — EXIT copies both, a
 * re-registration starts from 0); [1] the live count */
static void reads_set(uint8_t status, const uint8_t owner[64],
                      uint64_t exith, uint64_t count) {
    memset(g_reads, 0, sizeof(g_reads));
    if (status != 0) {
        g_reads[0].present = 1;
        g_reads[0].value_len = STOR_REC_LEN;
        rec_make(g_reads[0].value, owner, status, 2, exith);
        g_reads[0].value[STOR_FAIL_OFF + 3] = 2;
        put64(g_reads[0].value + STOR_GRACE_OFF, 0x0000000000ABCDEFULL);
    }
    g_reads[1].present = 1;
    g_reads[1].value_len = 8;
    put64(g_reads[1].value, count);
}

static int hk_exec(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                   uint16_t n_reads, dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, &e->view, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int hk_plan(const nodus_domain_runtime_t *rt, const hk_env_t *e,
                   nodus_rt_read_req_t *rq, uint16_t *n) {
    return nodus_rt_system_read_plan(rt, &e->view, 0, &g_ctx, rq,
                                     NODUS_RT_MAX_READS, n);
}

/* build a REGISTER for KN owned by `owner` (consent `variant`, kind
 * `kind`) at height `h`, then exec it with the reads already set.
 * @return the exec rc, or -100 / -101 on a setup failure. */
static int try_reg(const nodus_domain_runtime_t *rt, hk_env_t *e,
                   uint8_t *call, const uint8_t owner[64], uint64_t h,
                   uint64_t expiry, uint64_t bond, int variant,
                   uint8_t kind) {
    if (streg_call(call, g_chain, owner, KN, expiry, bond, variant)
        != STREG_LEN)
        return -100;
    if (hk_build(e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN, kind,
                 DNA_CORERULE_SYSFUND, 0) != 0)
        return -101;
    g_ctx.global_height = h;
    return hk_exec(rt, e, 2, NULL);
}

static int t_hooks(void) {
    const nodus_domain_runtime_t *s2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s2 && s3 && s4 && c2 && c4, "compiled generations 2, 3 and 4");
    static hk_env_t e;
    static uint8_t call[STREG_LEN + 8];
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t n = 0;
    dna_effect_view_t ev;
    const uint64_t H = 9;
    const uint64_t EXP = H + 100;
    ctx_at(H);

    /* ── A1. read plans ───────────────────────────────────────────── */
    CHECK(streg_call(call, g_chain, g_k[KO].fp, KN, EXP, BOND, CS_OK)
          == STREG_LEN, "a 7299-byte REGISTER call");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "register envelope");
    av_k1(KO, 0);
    CHECK(hk_plan(s4, &e, rq, &n) == 0 && n == 2, "REGISTER plans 2 reads");
    CHECK(rq[0].op_id == OP_STOR && rq[0].key_len == 64 &&
          memcmp(rq[0].key, g_k[KN].fp, 64) == 0,
          "read 0 = the row, key SHA3-512(call.node_pk), untagged");
    CHECK(rq[1].op_id == OP_STORCNT && rq[1].key_len == 1 &&
          rq[1].key[0] == 1, "read 1 = the live count, selector 1");
    CHECK(hk_plan(s2, &e, rq, &n) == -1, "generation 2 plans nothing");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "exit envelope");
    CHECK(hk_plan(s4, &e, rq, &n) == 0 && n == 1 && rq[0].op_id == OP_STOR
          && rq[0].key_len == 64 && memcmp(rq[0].key, g_k[KN].fp, 64) == 0,
          "EXIT plans the row keyed by the call's first 64 bytes (node_fp)");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REPORT, call, 8,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 1)
          == 0, "report envelope");
    CHECK(hk_plan(s4, &e, rq, &n) == -1, "a malformed REPORT plans nothing");
    CHECK(hk_exec(s4, &e, 0, NULL) == -1, "a malformed REPORT refused");

    /* ── A2. REGISTER positives ───────────────────────────────────── */
    CHECK(streg_call(call, g_chain, g_k[KO].fp, KN, EXP, BOND, CS_OK)
          == STREG_LEN &&
          hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "register envelope");
    av_k1(KO, 0);
    reads_set(0, NULL, 0, 0);
    memset(&ev, 0, sizeof(ev));
    CHECK(hk_exec(s4, &e, 2, &ev) == 0, "kind-1 owner: applies");
    {
        uint8_t want[STOR_REC_LEN];
        rec_make(want, g_k[KO].fp, DNA_V2_STORAGE_ACTIVE, H, 0);
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 64 &&
              memcmp(ev.buf + ev.key_off[0], g_k[KN].fp, 64) == 0 &&
              ev.eff[0].value_len == STOR_REC_LEN &&
              memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
              "ONE CREATE / ABSENT on op 8 keyed node_fp: node_pk ‖ owner "
              "(the call's) ‖ bond ‖ ACTIVE ‖ h ‖ 0 ‖ 0 ‖ 0");
    }
    reads_set(0, NULL, 0, (uint64_t)NODUS_STORAGE_SET_MAX - 1u);
    CHECK(hk_exec(s4, &e, 2, NULL) == 0, "255 live rows: admitted");
    reads_set(0, NULL, 0, 0);
    CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, H, BOND, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h accepted");
    CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, H + 720, BOND, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
          "expiry h + 720 accepted");
    CHECK(streg_call(call, g_chain, g_am, KN, EXP, BOND, CS_OK) == STREG_LEN
          && hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                      NODUS_RT_AUTHKIND_DSA87_MSIG_V1, DNA_CORERULE_SYSFUND,
                      0) == 0, "kind-3 envelope");
    av_k3(g_am, 1, 1);
    memset(&ev, 0, sizeof(ev));
    CHECK(hk_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 1 &&
          memcmp(ev.buf + ev.val_off[0] + STOR_OWNER_OFF, g_am, 64) == 0,
          "kind-3 owner (a 2-of-3 address, the Foundation shape): applies, "
          "owner = the address");

    /* ── A3. REGISTER refusals ────────────────────────────────────── */
    CHECK(streg_call(call, g_chain, g_k[KO].fp, KN, EXP, BOND, CS_OK)
          == STREG_LEN, "call");
    for (int d = -1; d <= 1; d += 2) {
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call,
                       (uint32_t)((int)STREG_LEN + d),
                       NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "env ± 1");
        av_k1(KO, 0);
        reads_set(0, NULL, 0, 0);
        CHECK(hk_plan(s4, &e, rq, &n) == -1, "7299 ± 1 refused (plan)");
        CHECK(hk_exec(s4, &e, 2, NULL) == -1, "7299 ± 1 refused (exec)");
    }
    {
        /* the storage-reward-v1 layouts, now no layout at all */
        static uint8_t v1[V1_STREG_LEN];
        memcpy(v1, g_k[KN].pk, PK_LEN);
        put64(v1 + PK_LEN, BOND);
        memcpy(v1 + PK_LEN + 8, g_k[KN].fp, 64);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, v1, V1_STREG_LEN,
                       NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "v1 REGISTER env");
        av_k1(KN, 0);
        CHECK(hk_plan(s4, &e, rq, &n) == -1 &&
              hk_exec(s4, &e, 2, NULL) == -1,
              "the 2664-byte v1 REGISTER (node key signing) refused");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT, g_k[KN].pk,
                       (uint32_t)PK_LEN, NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "v1 EXIT env");
        reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KN].fp, 0, 1);
        CHECK(hk_plan(s4, &e, rq, &n) == -1 &&
              hk_exec(s4, &e, 1, NULL) == -1,
              "the 2592-byte v1 EXIT (the node key) refused");
    }
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "register envelope");
    reads_set(0, NULL, 0, 0);
    av_k1(KX, 0);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "signer != owner_fp refused");
    av_k1(KN, 0);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1,
          "the NODE key as the signer is not the owner: refused (G1)");
    av_k1(KO, 1);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "two signers refused");
    av_k1(KO, 0);
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_CC_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "kind-2 env");
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "kind 2 refused");
    CHECK(streg_call(call, g_chain, g_am, KN, EXP, BOND, CS_OK) == STREG_LEN
          && hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                      NODUS_RT_AUTHKIND_DSA87_MSIG_V1, DNA_CORERULE_SYSFUND,
                      0) == 0, "kind-3 env");
    av_k3(g_an, 1, 1);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1,
          "kind 3 whose descriptor address != owner_fp refused");
    av_k3(g_am, 1, 0);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1,
          "kind 3 with a foreign signer riding along refused (D6)");
    av_k3(g_am, 0, 1);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "kind 3 below M refused");

    av_k1(KO, 0);
    reads_set(0, NULL, 0, 0);
    {
        static const struct { uint64_t bond; const char *what; } bad[] = {
            { 0,                          "bond 0" },
            { BOND - 1u,                  "bond STORAGE_BOND - 1" },
            { BOND + 1u,                  "bond STORAGE_BOND + 1" },
            { (uint64_t)INT64_MAX + 1u,   "bond INT64_MAX + 1" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            int rc = try_reg(s4, &e, call, g_k[KO].fp, H, EXP, bad[i].bond,
                             CS_OK, NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
            if (rc != -1) fprintf(stderr, "%s -> %d\n", bad[i].what, rc);
            CHECK(rc == -1, "a bond other than STORAGE_BOND is a verdict");
        }
    }
    /* HF-6 slice 8a: STORAGE_BOND is the ENGINE FACT ctx.storage_bond
     * (param 21 at the item's height): at the vote range's lower end
     * (10^13) exactly that bond applies and the compiled 1M default is
     * refused; a ctx carrying 0 (never engine-filled) is a NODE fault */
    {
        const uint64_t BMIN = (uint64_t)DNAC_HF6_STORAGE_BOND_MIN;
        g_ctx.storage_bond = BMIN;
        CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, EXP, BMIN, CS_OK,
                      NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
              "storage_bond fact 10^13: bond 10^13 applies");
        CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, EXP, BOND, CS_OK,
                      NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
              "storage_bond fact 10^13: the compiled 1M bond refused");
        g_ctx.storage_bond = 0;
        CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, EXP, BOND, CS_OK,
                      NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -2,
              "storage_bond 0 (not engine-filled): -2");
        CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, EXP, 0, CS_OK,
                      NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -2,
              "storage_bond 0 and bond 0: still the fault, never a match");
        g_ctx.storage_bond = BOND;
    }
    CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, H - 1, BOND, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h - 1 refused");
    CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, H + 721, BOND, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
          "expiry h + 721 refused");
    {
        static const struct { int v; const char *what; } bad[] = {
            { CS_OP_STAKE,    "a STAKE (op 1) consent" },
            { CS_OP_ROTATE,   "a ROTATE (op 2) consent" },
            { CS_OP3_SUBJECT, "op 3 over a non-zero subject" },
            { CS_OWNER_OTHER, "a consent for another owner" },
            { CS_CHAIN_OTHER, "a consent for another chain" },
            { CS_KEY_OTHER,   "another key's signature" },
            { CS_CTX_EMPTY,   "an empty FIPS 204 ctx" },
            { CS_CTX_OTHER,   "ctx nodus.valbind.v2" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            int rc = try_reg(s4, &e, call, g_k[KO].fp, H, EXP, BOND,
                             bad[i].v, NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
            if (rc != -1)
                fprintf(stderr, "consent variant: %s -> %d\n", bad[i].what,
                        rc);
            CHECK(rc == -1, "a bad consent is a verdict (-1, G11)");
        }
    }
    CHECK(try_reg(s4, &e, call, g_k[KO].fp, H, EXP, BOND, CS_OK,
                  NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0, "the good call");
    reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 1);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "the node's row ACTIVE refused");
    reads_set(DNA_V2_STORAGE_EXITING, g_k[KO].fp, 5, 1);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "the node's row EXITING refused");
    reads_set(DNA_V2_STORAGE_RELEASED, g_k[KO].fp, 0, 0);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1,
          "a RELEASED row with exit_height 0 refused");
    reads_set(0, NULL, 0, (uint64_t)NODUS_STORAGE_SET_MAX);
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "cap: 256 live rows refused");
    reads_set(DNA_V2_STORAGE_RELEASED, g_k[KO].fp, 3, 0);
    memcpy(g_reads[0].value, g_k[KX].pk, PK_LEN);   /* another node's row */
    CHECK(hk_exec(s4, &e, 2, NULL) == -2,
          "a row whose node_pk is not the call's: the adapter out of "
          "contract (-2)");
    reads_set(0, NULL, 0, 0);
    CHECK(hk_exec(s3, &e, 2, NULL) == -1 && hk_exec(s2, &e, 2, NULL) == -1 &&
          hk_exec(NULL, &e, 2, NULL) == -1,
          "generation 3 / generation 2 / NULL runtime refuse op 7");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 1)
          == 0, "single leg");
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "no funding leg refused");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SPEND, 0)
          == 0, "SPEND sibling");
    CHECK(hk_exec(s4, &e, 2, NULL) == -1, "a non-SYSFUND sibling refused");

    /* ── A4. re-registration from RELEASED (design §11.4) ─────────── */
    {
        const uint64_t BREL = 2 * E_LEN;
        const uint64_t xs[2] = { BREL, BREL - 1u };   /* on / before it */
        for (int i = 0; i < 2; i++) {
            const uint64_t x = xs[i];
            av_k1(KO, 0);
            reads_set(DNA_V2_STORAGE_RELEASED, g_k[KO].fp, x, 0);
            CHECK(try_reg(s4, &e, call, g_k[KO].fp, BREL + E_LEN,
                          BREL + E_LEN + 5, BOND, CS_OK,
                          NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
                  "h = B_rel + E refused (the old life's last settlement "
                  "runs in that block)");
            CHECK(try_reg(s4, &e, call, g_k[KO].fp, x + 1u, x + 6u, BOND,
                          CS_OK, NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == -1,
                  "h = x + 1 refused");
            const uint64_t r = BREL + E_LEN + 1u;
            CHECK(try_reg(s4, &e, call, g_k[KO].fp, r, r + 5u, BOND, CS_OK,
                          NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
                  "h = B_rel + E + 1 accepted");
            memset(&ev, 0, sizeof(ev));
            CHECK(hk_exec(s4, &e, 2, &ev) == 0, "re-exec for the effect");
            uint8_t vh[64], want[STOR_REC_LEN];
            CHECK(dna_effect_value_hash(g_reads[0].value, STOR_REC_LEN, vh)
                  == 0, "observed value hash");
            CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
                  ev.eff[0].effect_kind == DNA_EFFECT_SET &&
                  ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
                  memcmp(ev.eff[0].expected_vhash, vh, 64) == 0,
                  "ONE SET bound to the observed RELEASED record");
            rec_make(want, g_k[KO].fp, DNA_V2_STORAGE_ACTIVE, r, 0);
            CHECK(memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
                  "a fresh ACTIVE record (registered h, exit 0, "
                  "fail_streak 0, grace_until 0)");
        }
        /* A2 (khan 2026-10-12): a DIFFERENT owner may revive it */
        const uint64_t r = BREL + E_LEN + 1u;
        reads_set(DNA_V2_STORAGE_RELEASED, g_k[KO].fp, BREL, 0);
        av_k1(KP, 0);
        CHECK(try_reg(s4, &e, call, g_k[KP].fp, r, r + 5u, BOND, CS_OK,
                      NODUS_RT_AUTHKIND_DSA87_MULTI_V1) == 0,
              "A2: a revive naming a different owner (KP) applies");
        memset(&ev, 0, sizeof(ev));
        CHECK(hk_exec(s4, &e, 2, &ev) == 0 && ev.effect_count == 1 &&
              memcmp(ev.buf + ev.val_off[0] + STOR_OWNER_OFF, g_k[KP].fp,
                     64) == 0, "A2: the new record names KP");
        av_k1(KO, 0);
        CHECK(hk_exec(s4, &e, 2, NULL) == -1,
              "A2: the OLD owner cannot sign a revive naming KP");
    }

    /* ── A5. EXIT ─────────────────────────────────────────────────── */
    ctx_at(H);
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "exit envelope");
    av_k1(KO, 0);
    reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 0);
    memset(&ev, 0, sizeof(ev));
    CHECK(hk_exec(s4, &e, 1, &ev) == 0, "EXIT by the row's owner (kind 1)");
    {
        uint8_t want[STOR_REC_LEN];
        memcpy(want, g_reads[0].value, STOR_REC_LEN);
        want[STOR_STAT_OFF] = DNA_V2_STORAGE_EXITING;
        put64(want + STOR_EXITH_OFF, H);
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              memcmp(ev.buf + ev.key_off[0], g_k[KN].fp, 64) == 0 &&
              memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
              "ONE SET on op 8 (the only op named): EXITING, exit_height "
              "h, every other column copied (fail_streak, grace_until)");
    }
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_am), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MSIG_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "kind-3 exit envelope");
    reads_set(DNA_V2_STORAGE_ACTIVE, g_am, 0, 0);
    av_k3(g_am, 1, 1);
    CHECK(hk_exec(s4, &e, 1, NULL) == 0, "EXIT by a kind-3 owner applies");
    av_k3(g_an, 1, 1);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "EXIT by another kind-3 address refused");
    /* C2 descriptor swap (SYSTEM): the call names vault N (the one its
     * signers were shown), the row is M's and M's satisfied descriptor is
     * swapped in — refused by the owner equality; and N signing the call
     * that names N is refused because the row is M's */
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_an), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MSIG_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "kind-3 exit naming N");
    av_k3(g_am, 1, 1);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "C2 kind 3: the row's vault descriptor swapped in for the call's");
    av_k3(g_an, 1, 1);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "C2 kind 3: the call's vault signs, the row is another's");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "exit envelope");
    reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 0);
    av_k1(KN, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "EXIT signed by the node key refused (no node authority, G1)");
    av_k1(KX, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "EXIT by a non-owner refused");
    /* C2 owner mismatch, kind 1: the call names KX and KX signs — the
     * row is KO's */
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KX].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "exit naming KX");
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "C2 kind 1: call owner != row owner (signer == call owner)");
    av_k1(KO, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1,
          "C2 kind 1: call owner != row owner (signer == row owner)");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "exit envelope");
    av_k1(KO, 0);
    reads_set(0, NULL, 0, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "EXIT with no row refused");
    reads_set(DNA_V2_STORAGE_EXITING, g_k[KO].fp, 5, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "duplicate EXIT (EXITING) refused");
    reads_set(DNA_V2_STORAGE_RELEASED, g_k[KO].fp, 5, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "EXIT from RELEASED refused");
    reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 0);
    memcpy(g_reads[0].value, g_k[KX].pk, PK_LEN);
    CHECK(hk_exec(s4, &e, 1, NULL) == -2,
          "a row whose node_pk does not hash to the key: -2");
    {
        /* 127 / 129 bytes, and the pre-C2 64-byte layout */
        uint8_t x129[STEXIT_LEN + 1];
        memcpy(x129, exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN);
        x129[STEXIT_LEN] = 0;
        const uint32_t bad_len[3] = { STEXIT_LEN - 1u, STEXIT_LEN + 1u, 64u };
        for (int d = 0; d < 3; d++) {
            CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT, x129, bad_len[d],
                           NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                           DNA_CORERULE_SYSFUND, 0) == 0, "exit ± 1 env");
            reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 0);
            av_k1(KO, 0);
            CHECK(hk_plan(s4, &e, rq, &n) == -1 &&
                  hk_exec(s4, &e, 1, NULL) == -1,
                  "EXIT call 127 / 129 / pre-C2 64 bytes refused (plan and "
                  "exec)");
        }
    }
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SPEND, 0)
          == 0, "exit with a SPEND sibling");
    reads_set(DNA_V2_STORAGE_ACTIVE, g_k[KO].fp, 0, 0);
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "EXIT: a non-SYSFUND sibling");
    CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT,
                   exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 1)
          == 0, "exit single leg");
    CHECK(hk_exec(s4, &e, 1, NULL) == -1, "EXIT: no funding leg");

    /* ── A6. SYSFUND: the pairing gate; third-party funding ───────── */
    CHECK(streg_call(call, g_chain, g_k[KO].fp, KN, EXP, BOND, CS_OK)
          == STREG_LEN &&
          hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, STREG_LEN,
                   NODUS_RT_AUTHKIND_DSA87_MULTI_V1, DNA_CORERULE_SYSFUND, 0)
          == 0, "register envelope");
    CHECK(nodus_rt_core_read_plan(c2, &e.view, 1, &g_ctx, rq,
                                  NODUS_RT_MAX_READS, &n) == -1,
          "generation-2 CORE refuses the storage pairing");
    CHECK(nodus_rt_core_read_plan(c4, &e.view, 1, &g_ctx, rq,
                                  NODUS_RT_MAX_READS, &n) == 0 && n == 2 &&
          rq[0].op_id == OP_UTXO && rq[1].op_id == OP_SUPPLY &&
          rq[1].key[0] == SEL_POOL, "GEN_STORAGE CORE plans input + pool");
    {
        /* leg 1 signed by KX (neither the owner nor the node), its coin
         * of exactly bond + fee: the funding equation holds */
        av_k1(KX, 0);
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;
        g_reads[0].value_len = UTXO_REC_LEN;
        memcpy(g_reads[0].value, g_k[KX].hex, 128);
        put64(g_reads[0].value + UTXO_AMT_OFF, BOND + FEE);
        put64(g_reads[0].value + UTXO_UNL_OFF, 0);
        g_reads[1].present = 1;
        g_reads[1].value_len = 8;
        put64(g_reads[1].value, 1000u);
        size_t rl = 0;
        CHECK(nodus_rt_core_exec(c4, &e.view, 1, &g_ctx, g_reads, 2, g_res,
                                 sizeof(g_res), &rl) == 0,
              "a third-party-funded REGISTER balances: Σin == fee + bond");
        put64(g_reads[0].value + UTXO_AMT_OFF, BOND + FEE + 1u);
        CHECK(nodus_rt_core_exec(c4, &e.view, 1, &g_ctx, g_reads, 2, g_res,
                                 sizeof(g_res), &rl) == -1,
              "one raw unit more breaks the equation");
        av_k1(KO, 0);
        reads_set(0, NULL, 0, 0);
        CHECK(hk_exec(s4, &e, 2, NULL) == 0,
              "and the SYSTEM leg of the same envelope, signed by the "
              "owner, applies");
    }
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint8_t          chain32[DNA_CHAIN_ID_LEN];
} fixture_t;

typedef struct { int key; uint8_t seed; uint64_t amount; } coin_def_t;
enum { CO0, CO1, CO4, CO5, CO6, CO7, CO8, CO9, CO2, CO3, CP1, CP2,
       CQ1, CQ2, CQ3, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [CO0] = { KO, 0xA0, BOND + FEE },        /* KO at 2 (generation 2)  */
    [CO1] = { KO, 0xA1, BOND + FEE + CHG },  /* KO registers KN at 4    */
    [CO4] = { KO, 0xA4, BOND + FEE },        /* KO again at 5 (ACTIVE)  */
    [CO5] = { KO, 0xA5, BOND + FEE },        /* the node key signs, 5   */
    [CO6] = { KO, 0xA6, BOND - 1u + FEE },   /* bond − 1 at 5           */
    [CO7] = { KO, 0xA7, BOND + FEE },        /* a foreign consent at 5  */
    [CO8] = { KO, 0xA8, FEE },               /* EXIT by the node key, 6 */
    [CO9] = { KO, 0xA9, FEE },               /* EXIT of no row, 6       */
    [CO2] = { KO, 0xA2, FEE },               /* KO exits at 2E          */
    [CO3] = { KO, 0xA3, BOND + FEE },        /* KO again at 3E          */
    [CP1] = { KP, 0xB1, BOND + FEE },        /* KP at 3E                */
    [CP2] = { KP, 0xB2, BOND + FEE },        /* KP at 3E + 1            */
    /* HF-6 slice 8a — the param-21 steps (STORAGE_BOND voted to 10^13) */
    [CQ1] = { KO, 0xC1, BOND + FEE },        /* KN2, bond 1M, 3E + 2    */
    [CQ2] = { KO, 0xC2, DNAC_HF6_STORAGE_BOND_MIN + FEE },
                                             /* KN3, bond 10^13, 3E + 2 */
    [CQ3] = { KO, 0xC3, BOND + FEE },        /* KN4, the fault, 3E + 3  */
};
static uint8_t g_nul[N_COINS][64];

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
    sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_k[COINS[c].key].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)COINS[c].amount);
    int rc = sqlite3_step(st);
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
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* the pre-seeded segment root of k (HOW IT CAN LIE) */
static int seg_root(uint64_t k, uint8_t out[64]) {
    uint8_t pre[20 + 8];
    memcpy(pre, "test_storage_reg/seg", 20);
    put64(pre + 20, k);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

#define H9   2u
#define HE   3u       /* EVM_ACTIVE (param 14): GEN_STORAGE is built on the
                       * EVM generation (K10) */
#define H14  4u       /* param 18: the generation-4 edge runs in block 3 */

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

/* A seeded generation-4 chain: seven real-key validators, pool 1 =
 * 10^16, the coins above, N_SEGS pre-seeded segments (published at 1). */
static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_storage_reg_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x36, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, D2, H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_ROLES, D4, H14, 13) != 0)
        return -1;
    uint64_t bonds = 0, coins = 0;
    for (int i = 0; i < N_VAL; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_k[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake = DNAC_SELF_STAKE_AMOUNT;
        v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memcpy(v.unstake_destination_fp, g_k[i].hex, 129);
        if (nodus_validator_insert(w, &v) != 0) return -1;
        bonds += DNAC_SELF_STAKE_AMOUNT;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", N_VAL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    for (uint32_t p = 1; p <= 9; p++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO v2_treasury (pool_id, "
                 "balance) VALUES (%u, %llu)", (unsigned)p,
                 (unsigned long long)(p == 1 ? POOL1 : 0ULL));
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c) != 0) return -1;
        coins += COINS[c].amount;
    }
    {
        const uint64_t supply = coins + bonds + POOL1;
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, 0)",
                 (unsigned long long)supply, (unsigned long long)supply);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    for (uint64_t k = 1; k <= N_SEGS; k++) {
        uint8_t r[64];
        sqlite3_stmt *st = NULL;
        if (seg_root(k, r) != 0 ||
            sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_segments (k, "
                               "root, published_height) VALUES (?1, ?2, 1)",
                               -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
        sqlite3_bind_blob(st, 2, r, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    return v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, fx->chain32);
}

/* every block from height 2 carries all seven COMMIT votes */
static uint8_t g_vaddr[N_VAL][32];
static int32_t g_vflag[N_VAL];

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

/* The committed SYSTEM head equals a fresh recomputation by the RESOLVED
 * runtime's own state-root hook. */
static int sys_head_recomputes(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    uint8_t committed[64], now[64];
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = 0", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(committed, (const uint8_t *)sqlite3_column_blob(st, 0) + 4,
               64);
        ok = 0;
    }
    sqlite3_finalize(st);
    const nodus_domain_runtime_t *rt = NULL;
    if (ok != 0 ||
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rt) != 0 ||
        !rt || !rt->state_root || rt->state_root(rt, w, now) != 0)
        return -1;
    return memcmp(committed, now, 64) == 0 ? 0 : -1;
}

/* the committed SYSTEM root equals the v5 composition */
static int sys_root_is_v5(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    uint8_t committed[64], v5[64];
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = 0", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(committed, (const uint8_t *)sqlite3_column_blob(st, 0) + 4,
               64);
        ok = 0;
    }
    sqlite3_finalize(st);
    if (ok != 0 || nodus_witness_system_root_v5(w, v5) != 0) return -1;
    return memcmp(committed, v5, 64) == 0 ? 0 : -1;
}

static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    nodus_v2_tx_result_t ra[8], rb[8];
    nodus_v2_block_t ba, bb;
    if (n > 8) return -1;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, envs, n);
    mk_block(&bb, h, envs, n);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 8;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 8;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (ra[i].code != rb[i].code) return -1;
        if (codes) codes[i] = ra[i].code;
    }
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0) {
        fprintf(stderr, "block %llu: twin global roots differ\n",
                (unsigned long long)h);
        return -1;
    }
    if (((h % E_LEN) == 0 || n > 0) &&
        (sys_head_recomputes(a->w) != 0 || sys_head_recomputes(b->w) != 0)) {
        fprintf(stderr, "block %llu: SYSTEM head does not recompute\n",
                (unsigned long long)h);
        return -1;
    }
    return 0;
}

static int run_idle(fixture_t *a, fixture_t *b, uint64_t *h,
                    uint64_t target) {
    while (*h < target) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

static int submit(fixture_t *A, fixture_t *B, uint64_t h, uint8_t **envs,
                  size_t *lens, size_t n, uint32_t *codes) {
    nodus_v2_envelope_t v[8];
    if (n > 8) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = envs[i];
        v[i].env_len = lens[i];
    }
    int rc = apply_both(A, B, h, v, n, codes);
    for (size_t i = 0; i < n; i++) { free(envs[i]); envs[i] = NULL; }
    return rc;
}

/* A 2-leg storage envelope against the registry's CURRENT manifests,
 * REALLY signed: the SYSTEM leg by `sys_signer` (the owner), the SYSFUND
 * leg by `core_signer` (the coin's owner), each over its own engine-
 * derived leg digest at `height`. The funding: coin `c` → change back to
 * its owner when the coin carries more than lock + fee. @return 0 / -1. */
static int st_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                  const uint8_t *sys_call, uint32_t sys_len, int c,
                  uint64_t lock, int sys_signer, int core_signer,
                  uint8_t **out, size_t *out_len) {
    static uint8_t fund[2 + 64 + OUT_LEN];
    static uint8_t auth[2][AUTH_LEN];
    dna_domain_manifest_t sys, core;
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    if (COINS[c].amount < lock + FEE) return -1;
    const uint64_t change = COINS[c].amount - lock - FEE;
    uint32_t fl = fund_call(fund, g_nul[c], COINS[c].key, change,
                            (uint8_t)(0x40 + c));

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = sys_len;
    legs[0].hdr.auth_len = AUTH_LEN;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = sys_call;
    legs[0].auth_data = auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH_LEN;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = auth[1];
    memset(auth, 0, sizeof(auth));

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
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        const int signer[2] = { sys_signer, core_signer };
        int bad = 0;
        for (int L = 0; L < 2 && !bad; L++) {
            size_t sl = 0;
            auth[L][0] = 1;
            memcpy(auth[L] + 1, g_k[signer[L]].pk, PK_LEN);
            if (qgp_dsa87_sign(auth[L] + 1 + PK_LEN, &sl,
                               pf->auth_digest[L], 64, g_k[signer[L]].sk)
                != 0)
                bad = 1;
        }
        if (bad) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* KN's REGISTER owned by `owner` (kind 1, signed by `sys_signer`), KN's
 * consent `variant` against the ENGINE's chain id, funded by coin `c`
 * (signed by its owner), at `height`. @return 0 / -1. */
static int reg_env_node(fixture_t *fx, uint64_t height, int node, int owner,
                        int c, uint64_t bond, int variant, int sys_signer,
                        uint8_t **out, size_t *out_len) {
    static uint8_t call[STREG_LEN];
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(fx->w, chain32) != 0) return -1;
    if (streg_call(call, chain32, g_k[owner].fp, node, height + 10u, bond,
                   variant) != STREG_LEN)
        return -1;
    return st_env(fx->w, height, DNA_SYSRULE_STORAGE_REGISTER, call,
                  STREG_LEN, c, bond, sys_signer, COINS[c].key, out,
                  out_len);
}

static int reg_env(fixture_t *fx, uint64_t height, int owner, int c,
                   uint64_t bond, int variant, int sys_signer,
                   uint8_t **out, size_t *out_len) {
    return reg_env_node(fx, height, KN, owner, c, bond, variant, sys_signer,
                        out, out_len);
}

/* the bond of node `node`'s registry row: 0 found / 1 absent / -1 */
static int node_bond(nodus_witness_t *w, int node, uint64_t *bond) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT bond FROM v2_storage_nodes "
                           "WHERE node_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_k[node].fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st), ret = -1;
    if (rc == SQLITE_DONE) ret = 1;
    else if (rc == SQLITE_ROW) {
        *bond = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* The STORAGE_REPORT call body (bytes §3). */
static uint32_t rep_call(uint8_t *dst, uint64_t h, uint32_t seat,
                         const uint8_t s[64], const uint8_t *bm,
                         uint16_t bl) {
    put64(dst, h);
    put32(dst + 8, seat);
    memcpy(dst + 12, s, 64);
    dst[76] = (uint8_t)(bl >> 8);
    dst[77] = (uint8_t)bl;
    if (bl) memcpy(dst + REP_FIXED, bm, bl);
    return REP_FIXED + bl;
}

/* A 1-leg STORAGE_REPORT envelope, fee 0, signed by validator `signer`. */
static int rep_env(nodus_witness_t *w, uint64_t height, const uint8_t *call,
                   uint32_t call_len, int signer, uint8_t **out,
                   size_t *out_len) {
    static uint8_t auth[AUTH_LEN];
    dna_domain_manifest_t sys;
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0)
        return -1;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    leg.hdr.ruleset_version = sys.ruleset_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = call_len;
    leg.hdr.auth_len = AUTH_LEN;
    leg.hdr.res_max_effects = 8;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data = call;
    leg.auth_data = auth;
    memset(auth, 0, sizeof(auth));
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = 0;
    in.res_max_total_units = 400000;
    in.leg_count = 1;
    in.legs = &leg;
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);
    size_t len = 0, used = 0;
    if (dna_env_encoded_size(&leg, 1, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, &lctx, 1,
                              pf) != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        auth[0] = 1;
        memcpy(auth + 1, g_k[signer].pk, PK_LEN);
        if (qgp_dsa87_sign(auth + 1 + PK_LEN, &sl, pf->auth_digest[0], 64,
                           g_k[signer].sk) != 0)
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

/* Every validator seat's report for epoch H, built at height `h`, with
 * EVERY member bit set. envs[0..N_VAL). */
static nodus_storage_set_t g_set_r;

static int reports_all(fixture_t *fx, uint64_t h, uint64_t H,
                       uint8_t **envs, size_t *lens) {
    nodus_storage_set_t *s = &g_set_r;
    if (nodus_witness_storage_set_get(fx->w, H, s) != 0) return -1;
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(fx->w, H, &snap, NULL,
                                                   NULL) != 0 || !snap)
        return -1;
    int ret = 0;
    for (int vk = 0; vk < N_VAL && ret == 0; vk++) {
        uint32_t seat = UINT32_MAX;
        for (uint32_t x = 0; x < snap->active_count; x++)
            if (memcmp(snap->entries[x].pubkey, g_k[vk].pk, PK_LEN) == 0)
                seat = x;
        if (seat == UINT32_MAX) { ret = -1; break; }
        uint8_t bm[32], call[REP_FIXED + 32];
        memset(bm, 0, sizeof(bm));
        const uint16_t bl = (uint16_t)((s->count + 7u) / 8u);
        for (uint32_t i = 0; i < s->count; i++)
            bm[i / 8u] |= (uint8_t)(1u << (i % 8u));
        uint32_t cl = rep_call(call, H, seat, s->set_hash, bm, bl);
        if (rep_env(fx->w, h, call, cl, vk, &envs[vk], &lens[vk]) != 0)
            ret = -1;
    }
    dna_vset_free(&snap);
    return ret;
}

/* ── observations ───────────────────────────────────────────────────── */

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* Σ native utxo + reward pool + storage bonds — the three buckets a
 * registration moves value between */
static int buckets(nodus_witness_t *w, uint64_t *sum, uint64_t *bonds,
                   uint64_t *pool) {
    uint64_t utxo = 0;
    if (q_u64(w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set", &utxo) != 0
        || q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
                 pool) != 0 ||
        nodus_witness_storage_bond_total(w, bonds) != 0)
        return -1;
    *sum = utxo + *pool + *bonds;
    return 0;
}

static int coin_live(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int accrual_of(nodus_witness_t *w, const uint8_t fp[64],
                      uint64_t *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? 0 : -1;
}

static int pool1_of(nodus_witness_t *w, uint64_t *out) {
    return q_u64(w, "SELECT balance FROM v2_treasury WHERE pool_id = 1",
                 out);
}

/* KN's registry row: 1 found (columns out, storage classes checked), 0
 * absent, -1 error. `owner` is the payee_fp column. */
typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], owner[64];
    uint64_t bond, status, regh, exith, fail, grace;
} st_row_t;

static int st_row(nodus_witness_t *w, st_row_t *r) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT node_pk, payee_fp, bond, status, "
                           "registered_height, exit_height, fail_streak, "
                           "grace_until, typeof(node_fp), typeof(node_pk), "
                           "typeof(payee_fp), typeof(bond), typeof(status), "
                           "typeof(registered_height), typeof(exit_height) "
                           "FROM v2_storage_nodes WHERE node_fp = ?1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_k[KN].fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW &&
               sqlite3_column_bytes(st, 0) == (int)PK_LEN &&
               sqlite3_column_bytes(st, 1) == 64) {
        static const char *const want[7] = {
            "blob", "blob", "blob", "integer", "integer", "integer",
            "integer" };
        int typed = 1;
        for (int i = 0; i < 7; i++)
            typed = typed &&
                    strcmp((const char *)sqlite3_column_text(st, 8 + i),
                           want[i]) == 0;
        if (typed) {
            memcpy(r->pk, sqlite3_column_blob(st, 0), PK_LEN);
            memcpy(r->owner, sqlite3_column_blob(st, 1), 64);
            r->bond   = (uint64_t)sqlite3_column_int64(st, 2);
            r->status = (uint64_t)sqlite3_column_int64(st, 3);
            r->regh   = (uint64_t)sqlite3_column_int64(st, 4);
            r->exith  = (uint64_t)sqlite3_column_int64(st, 5);
            r->fail   = (uint64_t)sqlite3_column_int64(st, 6);
            r->grace  = (uint64_t)sqlite3_column_int64(st, 7);
            ret = 1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int core_invariant(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rt) != 0 || !rt
        || !rt->invariant)
        return -1;
    return rt->invariant(rt, w);
}

static nodus_storage_set_t g_set_a;

static int t_engine(void) {
    fixture_t A, B;
    uint64_t h = 0, n = 0;
    uint32_t codes[8];
    uint8_t *e[8] = { NULL };
    size_t l[8] = { 0 };
    st_row_t r;
    uint64_t sum0 = 0, sum1 = 0, bonds = 0, pool0 = 0, pool1 = 0;

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    for (int i = 0; i < N_VAL; i++) {
        memcpy(g_vaddr[i], g_k[i].fp, 32);
        g_vflag[i] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (real committee, pool 1, segments 1..8)");

    /* block 1 — the param-9 edge */
    CHECK(run_idle(&A, &B, &h, 1) == 0, "block 1 (idle)");

    /* block 2 (generation 2): a registration is NOT applied */
    CHECK(reg_env(&A, 2, KO, CO0, BOND, CS_OK, KO, &e[0], &l[0]) == 0,
          "registration built against generation 2");
    CHECK(submit(&A, &B, 2, e, l, 1, codes) == 0, "block 2");
    CHECK(codes[0] != NODUS_V2_TX_OK, "generation 2 does not apply op 7");
    CHECK(st_row(A.w, &r) == 0, "no registry row");
    h = 2;

    /* block 3 = H14 − 1: the generation-4 edge */
    CHECK(run_idle(&A, &B, &h, 3) == 0, "block 3 (the storage edge)");
    {
        const nodus_domain_runtime_t *rs = NULL;
        CHECK(nodus_witness_v2_runtime_for(A.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs && rs->generation == NODUS_RT_GEN_STORAGE,
              "generation 4 judges block 4");
        CHECK(sys_root_is_v5(A.w) == 0, "the SYSTEM root is v5 from H-1");
    }

    /* block 4: KO registers KN */
    CHECK(buckets(A.w, &sum0, &bonds, &pool0) == 0 && bonds == 0,
          "buckets before (no bond)");
    uint8_t sys_before[64];
    CHECK(nodus_witness_system_root_v5(A.w, sys_before) == 0, "v5 before");
    CHECK(reg_env(&A, 4, KO, CO1, BOND, CS_OK, KO, &e[0], &l[0]) == 0,
          "KO's registration of KN");
    CHECK(submit(&A, &B, 4, e, l, 1, codes) == 0, "block 4");
    CHECK(codes[0] == NODUS_V2_TX_OK, "the registration applies");
    h = 4;
    CHECK(st_row(A.w, &r) == 1, "KN's row exists (typed columns)");
    CHECK(memcmp(r.pk, g_k[KN].pk, PK_LEN) == 0 &&
          memcmp(r.owner, g_k[KO].fp, 64) == 0 && r.bond == BOND &&
          r.status == DNA_V2_STORAGE_ACTIVE && r.regh == 4 && r.exith == 0,
          "row = (node_pk KN, owner KO, STORAGE_BOND, ACTIVE, 4, 0)");
    CHECK(coin_live(A.w, g_nul[CO1]) == 0, "the funding coin is spent");
    CHECK(buckets(A.w, &sum1, &bonds, &pool1) == 0, "buckets after");
    CHECK(bonds == BOND, "the storage-bond term holds the bond");
    CHECK(pool1 == pool0 + FEE, "the reward pool gained exactly the fee");
    CHECK(sum1 == sum0, "utxo + pool + bonds unchanged: supply conserved");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "the CORE supply invariant holds on both twins");
    {
        uint8_t now[64];
        CHECK(sys_root_is_v5(A.w) == 0, "committed SYSTEM root is v5");
        CHECK(nodus_witness_system_root_v5(A.w, now) == 0 &&
              memcmp(now, sys_before, 64) != 0,
              "the registry row moved the SYSTEM root");
    }

    /* block 5: four refusals with real signatures */
    {
        uint8_t rr0[64], rr1[64];
        CHECK(reg_env(&A, 5, KO, CO4, BOND, CS_OK, KO, &e[0], &l[0]) == 0 &&
              reg_env(&A, 5, KO, CO5, BOND, CS_OK, KN, &e[1], &l[1]) == 0 &&
              reg_env(&A, 5, KO, CO6, BOND - 1u, CS_OK, KO, &e[2], &l[2])
                  == 0 &&
              reg_env(&A, 5, KO, CO7, BOND, CS_KEY_OTHER, KO, &e[3], &l[3])
                  == 0, "four envelopes");
        CHECK(nodus_witness_storage_registry_root(A.w, rr0) == 0, "reg root");
        CHECK(submit(&A, &B, 5, e, l, 4, codes) == 0, "block 5");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
              "re-register while ACTIVE refused");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
              "the SYSTEM leg signed by the NODE key refused");
        CHECK(codes[2] == NODUS_V2_TX_ERR_EXEC, "bond - 1 refused");
        CHECK(codes[3] == NODUS_V2_TX_ERR_EXEC,
              "a consent signed by a foreign key refused");
        CHECK(nodus_witness_storage_registry_root(A.w, rr1) == 0 &&
              memcmp(rr0, rr1, 64) == 0, "the registry is unchanged");
        h = 5;
    }

    /* block 6: EXIT signed by the node key; EXIT of an unregistered node */
    CHECK(st_env(A.w, 6, DNA_SYSRULE_STORAGE_EXIT,
                 exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                 CO8, 0, KN, KO, &e[0], &l[0]) == 0 &&
          st_env(A.w, 6, DNA_SYSRULE_STORAGE_EXIT,
                 exit_call(g_k[KX].fp, g_k[KO].fp), STEXIT_LEN,
                 CO9, 0, KO, KO, &e[1], &l[1]) == 0, "two exits");
    CHECK(submit(&A, &B, 6, e, l, 2, codes) == 0, "block 6");
    CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
          "an EXIT signed by the node key (not the owner) refused");
    CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
          "an EXIT of an unregistered node refused");
    CHECK(st_row(A.w, &r) == 1 && r.status == DNA_V2_STORAGE_ACTIVE,
          "KN still ACTIVE");
    h = 6;

    /* boundary E: the first storage boundary — KN frozen, no grace */
    CHECK(run_idle(&A, &B, &h, E_LEN) == 0, "boundary E");
    CHECK(nodus_witness_storage_set_get(A.w, E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 1 && memcmp(g_set_a.fps[0], g_k[KN].fp, 64) == 0
          && g_set_a.grace_until[0] == 0,
          "set(E) = {KN}, not in grace (no set(0))");

    /* block 2E (a boundary block): KO exits; the boundary releases */
    const uint64_t BR = 2 * E_LEN;
    CHECK(run_idle(&A, &B, &h, BR - 1) == 0, "to 2E - 1");
    uint64_t utxo0 = 0, utxo1 = 0, bonds0 = 0, bonds1 = 0;
    CHECK(nodus_witness_storage_bond_total(A.w, &bonds0) == 0 &&
          q_u64(A.w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set",
                &utxo0) == 0 && bonds0 == BOND, "buckets before 2E");
    CHECK(st_env(A.w, BR, DNA_SYSRULE_STORAGE_EXIT,
                 exit_call(g_k[KN].fp, g_k[KO].fp), STEXIT_LEN,
                 CO2, 0, KO, KO, &e[0], &l[0]) == 0, "KO's exit");
    CHECK(submit(&A, &B, BR, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK,
          "KO's EXIT applies in the boundary block 2E");
    h = BR;
    CHECK(st_row(A.w, &r) == 1 && r.status == DNA_V2_STORAGE_RELEASED &&
          r.exith == BR && memcmp(r.owner, g_k[KO].fp, 64) == 0,
          "released in the same block (the exit runs before the boundary "
          "step): RELEASED, exit_height 2E, owner KO");
    {
        uint8_t id[64], nul[64];
        CHECK(dna_v2_storage_exit_id(A.chain32, BR, g_k[KN].fp, id) == 0 &&
              dna_v2_storage_exit_nullifier(id, nul) == 0, "exit id");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db, "SELECT owner, amount, tx_hash, "
              "output_index, block_height, unlock_block FROM utxo_set WHERE "
              "nullifier = ?1", -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        int good = sqlite3_step(st) == SQLITE_ROW &&
            sqlite3_column_bytes(st, 0) == 128 &&
            memcmp(sqlite3_column_text(st, 0), g_k[KO].hex, 128) == 0 &&
            (uint64_t)sqlite3_column_int64(st, 1) == BOND &&
            sqlite3_column_bytes(st, 2) == 64 &&
            memcmp(sqlite3_column_blob(st, 2), id, 64) == 0 &&
            sqlite3_column_int64(st, 3) == 201 &&
            (uint64_t)sqlite3_column_int64(st, 4) == BR &&
            (uint64_t)sqlite3_column_int64(st, 5) ==
                BR + (uint64_t)DNAC_STORAGE_EXIT_LOCK_EPOCHS * E_LEN;
        sqlite3_finalize(st);
        CHECK(good, "the bond is ONE locked UTXO owned by the OWNER KO "
              "(not the node): identity, amount, index 201, unlock 2E + "
              "12E");
    }
    CHECK(nodus_witness_storage_bond_total(A.w, &bonds1) == 0 &&
          q_u64(A.w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set",
                &utxo1) == 0, "buckets after 2E");
    CHECK(bonds1 == bonds0 - BOND && utxo1 + FEE == utxo0 + BOND,
          "the bond moved storage bonds -> utxo (the exit's fee coin "
          "spent)");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "the CORE invariant holds on both twins");
    CHECK(nodus_witness_storage_set_get(A.w, BR, &g_set_a) == 0 &&
          g_set_a.count == 0, "set(2E) excludes KN");

    /* 2E + 1: all seven seats report for H = E (KN's bit 1) */
    CHECK(reports_all(&A, BR + 1, E_LEN, e, l) == 0,
          "seven reports for H = E");
    CHECK(submit(&A, &B, BR + 1, e, l, N_VAL, codes) == 0, "2E + 1");
    for (int i = 0; i < N_VAL; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK, "report applies");
    h = BR + 1;

    /* block 3E (= B_rel + E): both re-registrations REFUSED; the boundary
     * of the same block pays the OLD owner for the old life */
    const uint64_t R0 = BR + E_LEN;
    uint64_t p0 = 0, p1 = 0, ao0 = 0, ao1 = 0, ap = 0, an = 0;
    CHECK(run_idle(&A, &B, &h, R0 - 1) == 0, "to 3E - 1");
    CHECK(pool1_of(A.w, &p0) == 0 && accrual_of(A.w, g_k[KO].fp, &ao0) == 0
          && ao0 == 0 && p0 == POOL1, "nothing paid to storage yet");
    CHECK(reg_env(&A, R0, KO, CO3, BOND, CS_OK, KO, &e[0], &l[0]) == 0 &&
          reg_env(&A, R0, KP, CP1, BOND, CS_OK, KP, &e[1], &l[1]) == 0,
          "KO's and KP's re-registrations at 3E");
    CHECK(submit(&A, &B, R0, e, l, 2, codes) == 0, "block 3E");
    CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
          "the same owner at B_rel + E: refused (design §11.4)");
    CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
          "a different owner at B_rel + E: refused");
    h = R0;
    CHECK(pool1_of(A.w, &p1) == 0 && accrual_of(A.w, g_k[KO].fp, &ao1) == 0
          && accrual_of(A.w, g_k[KP].fp, &ap) == 0 &&
          accrual_of(A.w, g_k[KN].fp, &an) == 0, "after 3E");
    CHECK(p1 < p0 && ao1 == p0 - p1,
          "the settlement of H = E credited the OLD owner KO exactly the "
          "pool-1 debit");
    CHECK(ap == 0 && an == 0, "neither the new owner nor the node key "
          "received anything");
    CHECK(st_row(A.w, &r) == 1 && r.status == DNA_V2_STORAGE_RELEASED &&
          memcmp(r.owner, g_k[KO].fp, 64) == 0,
          "the row still names KO");

    /* block 3E + 1: KP registers KN (A2, a different owner) */
    CHECK(reg_env(&A, R0 + 1, KP, CP2, BOND, CS_OK, KP, &e[0], &l[0]) == 0,
          "KP's registration");
    CHECK(submit(&A, &B, R0 + 1, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK,
          "B_rel + E + 1: the new owner's registration applies");
    h = R0 + 1;
    CHECK(st_row(A.w, &r) == 1 && r.status == DNA_V2_STORAGE_ACTIVE &&
          memcmp(r.owner, g_k[KP].fp, 64) == 0 && r.bond == BOND &&
          r.regh == R0 + 1 && r.exith == 0 && r.fail == 0 && r.grace == 0,
          "the row: ACTIVE, owner KP, registered 3E + 1, exit 0, "
          "fail_streak 0, grace_until 0");
    CHECK(st_row(B.w, &r) == 1 && memcmp(r.owner, g_k[KP].fp, 64) == 0,
          "the same on the twin");
    {
        uint64_t ao2 = 0;
        CHECK(accrual_of(A.w, g_k[KO].fp, &ao2) == 0 && ao2 == ao1,
              "KO's accrual unchanged by the new life");
    }
    CHECK(nodus_witness_storage_bond_total(A.w, &bonds) == 0 &&
          bonds == BOND, "one bond in the supply term");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_nodes", &n) == 0 &&
          n == 1, "still one registry row (revived, not duplicated)");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "the CORE invariant holds on both twins");

    /* ── HF-6 slice 8a: a committed param-21 (STORAGE_BOND) row IS the
     * exact bond. A row of 10^13 (the vote range's lower end) effective
     * at 3E + 2 is written into BOTH twins before block 3E + 2, whose
     * second item applies and so TOUCHES SYSTEM — the committed SYSTEM
     * root absorbs the row in that very block (phase 8's untouched-
     * domain guard never sees a root it did not commit; the SYSTEM head
     * recomputes after it). In block 3E + 2: KN2 with the compiled 1M is
     * REFUSED, KN3 with 10^13 APPLIES. */
    {
        const uint64_t BMIN = (uint64_t)DNAC_HF6_STORAGE_BOND_MIN;
        const uint64_t HQ = R0 + 2;
        uint64_t bq = 0;
        CHECK(cc_row(A.w, DNAC_CFG_STORAGE_BOND, BMIN, HQ, 21) == 0 &&
              cc_row(B.w, DNAC_CFG_STORAGE_BOND, BMIN, HQ, 21) == 0,
              "param-21 row 10^13 @ 3E + 2 on both twins");
        CHECK(reg_env_node(&A, HQ, KN2, KO, CQ1, BOND, CS_OK, KO, &e[0],
                           &l[0]) == 0 &&
              reg_env_node(&A, HQ, KN3, KO, CQ2, BMIN, CS_OK, KO, &e[1],
                           &l[1]) == 0, "KN2 (1M) and KN3 (10^13)");
        CHECK(submit(&A, &B, HQ, e, l, 2, codes) == 0, "block 3E + 2");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
              "the compiled 1M bond is refused under the voted 10^13");
        CHECK(codes[1] == NODUS_V2_TX_OK,
              "a bond of exactly the voted 10^13 applies");
        h = HQ;
        CHECK(node_bond(A.w, KN2, &bq) == 1, "no row for KN2");
        CHECK(node_bond(A.w, KN3, &bq) == 0 && bq == BMIN &&
              node_bond(B.w, KN3, &bq) == 0 && bq == BMIN,
              "KN3's row records the bond it paid, 10^13, on both twins");
        CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
              "the CORE invariant holds on both twins");
    }

    /* ── HF-6 slice 8a: a stored param-21 value no vote can produce
     * (10^14 + 1, above the khan's 1M ceiling) FAULTs the item's ctx fill
     * — never a default, never a verdict. Twin A only; the block aborts
     * whole at the authorization stage's fill (before phase 8) and its
     * reason names the param. */
    {
        const uint64_t HF = R0 + 3;
        uint64_t tip = 0;
        CHECK(cc_row(A.w, DNAC_CFG_STORAGE_BOND,
                     (uint64_t)DNAC_HF6_STORAGE_BOND_MAX + 1u, HF, 22) == 0,
              "an out-of-range param-21 row @ 3E + 3 on twin A");
        CHECK(reg_env_node(&A, HF, KN4, KO, CQ3, BOND, CS_OK, KO, &e[0],
                           &l[0]) == 0, "KN4's registration");
        nodus_v2_envelope_t v[1] = { { e[0], l[0] } };
        nodus_v2_tx_result_t ra[1];
        nodus_v2_block_t ba;
        memset(ra, 0, sizeof(ra));
        mk_block(&ba, HF, v, 1);
        ba.cmt.results = ra;
        ba.cmt.results_cap = 1;
        CHECK(v2x_cmt_apply(A.w, &ba) != 0,
              "3E + 3: the block does not apply (a node FAULT)");
        CHECK(strstr(ba.out_reason, "FAULT") != NULL &&
              strstr(ba.out_reason, "STORAGE_BOND") != NULL &&
              strstr(ba.out_reason, "no committed row can hold") != NULL,
              "the fault reason is the param-21 range check");
        free(e[0]); e[0] = NULL;
        CHECK(q_u64(A.w, "SELECT MAX(global_height) FROM v2_blocks", &tip)
              == 0 && tip == R0 + 2, "twin A's last block is still 3E + 2");
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
        { "hooks_register_exit_matrix", t_hooks },
        { "engine_owner_lifecycle",     t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0 || desc_make() != 0) {
        fprintf(stderr, "test_storage_reg: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-28s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_storage_reg: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
