/**
 * @file nodus/tests/test_storage_reg.c
 * @brief Storage reward v1, package B1 — STORAGE_REGISTER / STORAGE_EXIT:
 *        the hook-level rule matrix and registrations applied end to end
 *        on a GEN_STORAGE chain (registry rows, supply conservation, the
 *        SYSTEM "NDS.SYS.v5" root, twin determinism, refusals).
 *
 * Decision docs/plans/decisions/2026-10-04-storage-reward-approved.md;
 * design docs/plans/2026-10-04-storage-reward-v1-design.md rev 2.2 §1, §6;
 * call bytes docs/plans/2026-10-04-storage-reward-bytes.md item 5;
 * who earns docs/plans/decisions/2026-10-04-storage-reward-who-earns.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. HOOK LEVEL — nodus_rt_system_exec / _read_plan of the GEN_STORAGE
 *     SYSTEM runtime over fabricated engine facts (a decoded 2-leg
 *     envelope, a verdict, mediated-read results):
 *       A1 read plans: REGISTER = [row (op 8, key SHA3-512(node_pk)),
 *          live count (op 9, selector 1)]; EXIT = [row]; REPORT refused.
 *       A2 REGISTER happy path: one CREATE / ABSENT on op 8 keyed node_fp,
 *          the 2681-byte record = node_pk ‖ payee ‖ bond ‖ ACTIVE ‖ h ‖ 0.
 *       A3 refusals, each -1 (a verdict, never -2): signer fp != SHA3-512
 *          (node_pk); two signers; auth_kind 2; bond one under and one
 *          over DNAC_STORAGE_STAKE_MIN; payee_fp != node_fp; live count
 *          == NODUS_STORAGE_SET_MAX (and 255 accepted — the boundary);
 *          an existing ACTIVE row; an existing EXITING row; a single-leg
 *          envelope; a CORE sibling that is not SYSFUND; generation 1 /
 *          generation 2 / NULL runtime.
 *       A4 re-registration from RELEASED: one SET / EXISTS_VHASH bound to
 *          the observed record's value hash, a fresh ACTIVE record.
 *       A5 EXIT: from ACTIVE one SET / EXISTS_VHASH, status EXITING,
 *          exit_height = h, every other column unchanged; from EXITING
 *          (the duplicate exit) and RELEASED refused; no row refused;
 *          wrong signer refused.
 *       A6 the CORE SYSFUND leg pairs with a storage op only under
 *          GEN_STORAGE: its read plan is refused by the generation-2 CORE
 *          and accepted (inputs + pool) by the GEN_STORAGE CORE.
 *  B. ENGINE, twin fixtures (same seed, same genesis), production
 *     runtimes, HF-2 on from 1, param 9 at H9 = 2 and param 14 (the
 *     storage vote literal) at H14 = 4 committed at genesis, coins seeded
 *     for two node keys. Every block is applied to BOTH fixtures with the
 *     same bytes; after each the two committed global roots are equal and
 *     each equals a fresh recomputation.
 *       block 2 (generation 2): a registration is NOT applied (the
 *         generation-2 SYSTEM descriptor does not own op 7); no row.
 *       block 3 (= H14-1): the switch — idle.
 *       block 4: node A registers: code OK; the row (fp, pk, payee = fp,
 *         bond, ACTIVE, 4, 0) with exact storage classes; the coin gone,
 *         the change created; reward pool += fee; utxo + pool + storage
 *         bonds UNCHANGED (supply conservation: the bond moved utxo ->
 *         storage bond bucket) and the CORE invariant holds; the
 *         committed SYSTEM root equals nodus_witness_system_root_v5 and
 *         moved from the empty-registry root.
 *       block 5: A again (ACTIVE: refused), B with A's signature on the
 *         SYSTEM leg (wrong signer: refused), B with bond − 1 (refused),
 *         B with a foreign payee (refused) — four EXEC refusals; the
 *         registry unchanged.
 *       block 6: A exits: OK, row EXITING with exit_height 6, the bond
 *         still in the storage-bond term (no value moved; the release is
 *         package B2); B exits while unregistered: refused.
 *       block 7: A exits again (duplicate: refused); B registers: OK, the
 *         storage-bond term = 2 × bond, the invariant holds.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; DNAC_EPOCH_LENGTH must be
 * > 8 (no epoch boundary among heights 1..7 — checked; true for the
 * production 720 and the harness 15). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_storage_reg_* directory per fixture, removed at the end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - ⚠ The GEN_STORAGE pins and the storage vote literal are NOT FILLED
 *    (STORAGE-ORACLE markers, nodus_witness_runtime.c / dnac.h): until the
 *    independent oracle fills them the runtime selfcheck fails, so section
 *    B FAILS at its seeded genesis (and the A-level hooks still run — they
 *    do not consult the pins). A failure there before the pins are filled
 *    is expected, not a defect of this package.
 *  - Section A fabricates the verdict and the read results: it proves the
 *    hook's rule decisions, not the engine's read execution or signature
 *    verification (section B does those, on real signatures).
 *  - The cap (256 live rows) is proven at hook level only (a fabricated
 *    count of 255 / 256); no 256-node chain is built here.
 *  - The genesis is SEEDED with spendable UTXOs (V2X_SEED_NOT_REAL_UTXOS),
 *    a state the real derivation never writes. "Twin" is two fixtures in
 *    one process — a function of (state, block bytes), not a 7-machine
 *    run (the Genesis Protocol harness is that).
 *  - Refusals are asserted by item code and by the registry / bond
 *    observations, not by a whole-database digest. A refused item leaves
 *    its coin today (decision 2026-09-25-failed-tx-pays-fee.md approved,
 *    not implemented); every case uses its own coin.
 *  - The release of an EXITING bond at the boundary and the RELEASED state
 *    through the engine are package B2's; A4 / A5 reach RELEASED only
 *    through a fabricated read.
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
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
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
#define DS       ((uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define BOND     ((uint64_t)DNAC_STORAGE_STAKE_MIN)
#define CHG      700000000ULL
#define OUT_LEN  232u
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STOR        8u
#define OP_STORCNT     9u
#define STOR_REC_LEN   2681u
#define STOR_PAYEE_OFF 2592u
#define STOR_BOND_OFF  2656u
#define STOR_STAT_OFF  2664u
#define STOR_REGH_OFF  2665u
#define STOR_EXITH_OFF 2673u
#define STREG_LEN      (2592u + 8u + 64u)

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ══ keys ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];               /* SHA3-512(pk) = node_fp / verdict fp */
    char    hex[129];
} sk_key_t;

enum { KA, KB, KX, N_KEYS };
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
        memset(seed, 0x71 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* STORAGE_REGISTER call: node_pk ‖ bond ‖ payee_fp (bytes doc item 5) */
static uint32_t streg_call(uint8_t *dst, int node, uint64_t bond,
                           const uint8_t payee[64]) {
    memcpy(dst, g_k[node].pk, PK_LEN);
    put64(dst + PK_LEN, bond);
    memcpy(dst + PK_LEN + 8, payee, 64);
    return STREG_LEN;
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
    uint8_t  sys_call[STREG_LEN];
    uint8_t  fund[2 + 64 + OUT_LEN];
    uint8_t  auth[2][AUTH_LEN];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} hk_env_t;

/* a decoded envelope: leg 0 SYSTEM `op` (call), leg 1 CORE `core_op`
 * (a 1-input, 0-output funding call) unless `single`; auth bytes zero
 * (the hook reads the verdict, never the auth bytes) */
static int hk_build(hk_env_t *e, uint32_t op, const uint8_t *call,
                    uint32_t call_len, uint8_t sys_kind, uint32_t core_op,
                    int single) {
    memset(e, 0, sizeof(*e));
    uint8_t nul[64];
    memset(nul, 0xA5, sizeof(nul));
    uint32_t fl = fund_call(e->fund, nul, KA, 0, 0);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = 8;
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
    legs[1].hdr.ruleset_version = 6;
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

/* the engine facts: one signer `signer` (n = 1 unless `two`) */
static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];

static void hk_ctx(int signer, int two, uint64_t height) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = two ? 2 : 1;
    memcpy(g_av.signer_fp[0], g_k[signer].fp, 64);
    if (two) memcpy(g_av.signer_fp[1], g_k[KX].fp, 64);
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_intent, 0x5D, sizeof(g_intent));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = height;
    g_ctx.epoch = height / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

static nodus_rt_read_res_t g_reads[2];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* a fabricated registry record */
static void rec_make(uint8_t *r, int node, const uint8_t payee[64],
                     uint64_t bond, uint8_t status, uint64_t regh,
                     uint64_t exith) {
    memset(r, 0, STOR_REC_LEN);
    memcpy(r, g_k[node].pk, PK_LEN);
    memcpy(r + STOR_PAYEE_OFF, payee, 64);
    put64(r + STOR_BOND_OFF, bond);
    r[STOR_STAT_OFF] = status;
    put64(r + STOR_REGH_OFF, regh);
    put64(r + STOR_EXITH_OFF, exith);
}

/* reads: [0] the row (absent when status == 0), [1] the live count */
static void reads_set(int node, uint8_t status, uint64_t count) {
    memset(g_reads, 0, sizeof(g_reads));
    if (status != 0) {
        g_reads[0].present = 1;
        g_reads[0].value_len = STOR_REC_LEN;
        rec_make(g_reads[0].value, node, g_k[node].fp, BOND, status, 2,
                 status == DNA_V2_STORAGE_ACTIVE ? 0 : 3);
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

static int t_hooks(void) {
    const nodus_domain_runtime_t *s1 =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s1 && s2 && s3 && c2 && c3, "compiled generations");
    static hk_env_t e;
    static uint8_t call[STREG_LEN];
    dna_effect_view_t ev;
    const uint64_t H = 9;

    /* ── A1. read plans ───────────────────────────────────────────── */
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        uint32_t cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "register envelope");
        hk_ctx(KA, 0, H);
        CHECK(nodus_rt_system_read_plan(s3, &e.view, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2, "REGISTER plans two reads");
        CHECK(rq[0].op_id == OP_STOR && rq[0].key_len == 64 &&
              memcmp(rq[0].key, g_k[KA].fp, 64) == 0,
              "read 0 = the row, key SHA3-512(node_pk), untagged");
        CHECK(rq[1].op_id == OP_STORCNT && rq[1].key_len == 1 &&
              rq[1].key[0] == 1, "read 1 = the live count, selector 1");
        CHECK(nodus_rt_system_read_plan(s2, &e.view, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == -1,
              "generation 2 plans nothing for op 7");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT, g_k[KA].pk,
                       (uint32_t)PK_LEN, 1, DNA_CORERULE_SYSFUND, 0) == 0,
              "exit envelope");
        CHECK(nodus_rt_system_read_plan(s3, &e.view, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 1 && rq[0].op_id == OP_STOR &&
              memcmp(rq[0].key, g_k[KA].fp, 64) == 0, "EXIT plans the row");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REPORT, call, 8, 1,
                       DNA_CORERULE_SYSFUND, 1) == 0, "report envelope");
        CHECK(nodus_rt_system_read_plan(s3, &e.view, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == -1,
              "REPORT refused (package B2)");
        CHECK(hk_exec(s3, &e, 0, NULL) == -1, "REPORT exec refused");
    }

    /* ── A2. REGISTER happy path ──────────────────────────────────── */
    {
        uint32_t cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "register envelope");
        hk_ctx(KA, 0, H);
        reads_set(KA, 0, 0);
        memset(&ev, 0, sizeof(ev));
        CHECK(hk_exec(s3, &e, 2, &ev) == 0, "register applies");
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
              ev.eff[0].key_len == 64 && ev.eff[0].value_len == STOR_REC_LEN,
              "one CREATE / ABSENT on the registry op");
        uint8_t want[STOR_REC_LEN];
        rec_make(want, KA, g_k[KA].fp, BOND, DNA_V2_STORAGE_ACTIVE, H, 0);
        CHECK(memcmp(ev.buf + ev.key_off[0], g_k[KA].fp, 64) == 0,
              "keyed node_fp");
        CHECK(memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
              "record = pk ‖ payee ‖ bond ‖ ACTIVE ‖ h ‖ 0");
        /* the cap boundary: 255 live rows still admit one more */
        reads_set(KA, 0, (uint64_t)NODUS_STORAGE_SET_MAX - 1u);
        CHECK(hk_exec(s3, &e, 2, NULL) == 0, "255 live rows: admitted");
    }

    /* ── A3. refusals ─────────────────────────────────────────────── */
    {
        uint32_t cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "register envelope");
        reads_set(KA, 0, 0);
        hk_ctx(KB, 0, H);
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "signer is not the node");
        hk_ctx(KA, 1, H);
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "two signers refused");
        hk_ctx(KA, 0, H);
        reads_set(KA, 0, (uint64_t)NODUS_STORAGE_SET_MAX);
        CHECK(hk_exec(s3, &e, 2, NULL) == -1,
              "cap: ACTIVE + EXITING == 256 refused");
        reads_set(KA, DNA_V2_STORAGE_ACTIVE, 1);
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "re-register while ACTIVE");
        reads_set(KA, DNA_V2_STORAGE_EXITING, 1);
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "re-register while EXITING");
        reads_set(KA, 0, 0);
        CHECK(hk_exec(s1, &e, 2, NULL) == -1 && hk_exec(s2, &e, 2, NULL) == -1
              && hk_exec(NULL, &e, 2, NULL) == -1,
              "generations 1 / 2 / NULL refuse op 7");

        cl = streg_call(call, KA, BOND - 1u, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "bond - 1");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "bond one under refused");
        cl = streg_call(call, KA, BOND + 1u, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "bond + 1");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "bond one over refused");
        cl = streg_call(call, KA, BOND, g_k[KB].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "foreign payee");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1,
              "payee_fp != node_fp refused (until HF-5)");
        cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl,
                       NODUS_RT_AUTHKIND_DSA87_CC_V1, DNA_CORERULE_SYSFUND,
                       0) == 0, "kind-2 SYSTEM leg");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "auth_kind 2 refused");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 1) == 0, "single leg");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "no funding leg refused");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SPEND, 0) == 0, "SPEND sibling");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "a non-SYSFUND sibling");
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl - 1u, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "short call");
        CHECK(hk_exec(s3, &e, 2, NULL) == -1, "call one byte short");
    }

    /* ── A4. re-registration from RELEASED ────────────────────────── */
    {
        uint32_t cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "register envelope");
        hk_ctx(KA, 0, H);
        reads_set(KA, DNA_V2_STORAGE_RELEASED, 0);
        memset(&ev, 0, sizeof(ev));
        CHECK(hk_exec(s3, &e, 2, &ev) == 0, "revive from RELEASED");
        uint8_t vh[64];
        CHECK(dna_effect_value_hash(g_reads[0].value, STOR_REC_LEN, vh) == 0,
              "observed value hash");
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH &&
              memcmp(ev.eff[0].expected_vhash, vh, 64) == 0,
              "one SET bound to the observed RELEASED record");
        uint8_t want[STOR_REC_LEN];
        rec_make(want, KA, g_k[KA].fp, BOND, DNA_V2_STORAGE_ACTIVE, H, 0);
        CHECK(memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
              "a fresh ACTIVE record (registered_height h, exit 0)");
    }

    /* ── A5. EXIT ─────────────────────────────────────────────────── */
    {
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_EXIT, g_k[KA].pk,
                       (uint32_t)PK_LEN, 1, DNA_CORERULE_SYSFUND, 0) == 0,
              "exit envelope");
        hk_ctx(KA, 0, H);
        reads_set(KA, DNA_V2_STORAGE_ACTIVE, 0);
        memset(&ev, 0, sizeof(ev));
        CHECK(hk_exec(s3, &e, 1, &ev) == 0, "exit from ACTIVE applies");
        CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              ev.eff[0].precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH,
              "one SET / EXISTS_VHASH");
        uint8_t want[STOR_REC_LEN];
        memcpy(want, g_reads[0].value, STOR_REC_LEN);
        want[STOR_STAT_OFF] = DNA_V2_STORAGE_EXITING;
        put64(want + STOR_EXITH_OFF, H);
        CHECK(memcmp(ev.buf + ev.val_off[0], want, STOR_REC_LEN) == 0,
              "EXITING, exit_height = h, every other column unchanged");
        CHECK(get64(ev.buf + ev.val_off[0] + STOR_BOND_OFF) == BOND,
              "the bond stays on the row (released by B2)");
        reads_set(KA, DNA_V2_STORAGE_EXITING, 0);
        CHECK(hk_exec(s3, &e, 1, NULL) == -1, "duplicate exit refused");
        reads_set(KA, DNA_V2_STORAGE_RELEASED, 0);
        CHECK(hk_exec(s3, &e, 1, NULL) == -1, "exit from RELEASED refused");
        reads_set(KA, 0, 0);
        CHECK(hk_exec(s3, &e, 1, NULL) == -1, "exit with no row refused");
        reads_set(KA, DNA_V2_STORAGE_ACTIVE, 0);
        hk_ctx(KB, 0, H);
        CHECK(hk_exec(s3, &e, 1, NULL) == -1, "exit signed by another key");
        hk_ctx(KA, 0, H);
        CHECK(hk_exec(s2, &e, 1, NULL) == -1, "generation 2 refuses op 8");
    }

    /* ── A6. SYSFUND pairs with a storage op only under GEN_STORAGE ── */
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        uint32_t cl = streg_call(call, KA, BOND, g_k[KA].fp);
        CHECK(hk_build(&e, DNA_SYSRULE_STORAGE_REGISTER, call, cl, 1,
                       DNA_CORERULE_SYSFUND, 0) == 0, "register envelope");
        hk_ctx(KA, 0, H);
        CHECK(nodus_rt_core_read_plan(c2, &e.view, 1, &g_ctx, rq,
                                      NODUS_RT_MAX_READS, &n) == -1,
              "generation-2 CORE refuses the storage pairing");
        CHECK(nodus_rt_core_read_plan(c3, &e.view, 1, &g_ctx, rq,
                                      NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2, "GEN_STORAGE CORE plans input + pool");
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
enum { CA1, CA2, CA3, CA4, CA0, CB1, CB2, CB3, CB4, CB5, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [CA1] = { KA, 0xA1, BOND + FEE + CHG },  /* A registers at 4        */
    [CA2] = { KA, 0xA2, BOND + FEE },        /* A again at 5 (ACTIVE)   */
    [CA3] = { KA, 0xA3, FEE },               /* A exits at 6            */
    [CA4] = { KA, 0xA4, FEE },               /* A exits again at 7      */
    [CA0] = { KA, 0xA0, BOND + FEE },        /* A at 2 (generation 2)   */
    [CB1] = { KB, 0xB1, BOND + FEE },        /* B, A signs SYSTEM, at 5 */
    [CB2] = { KB, 0xB2, BOND - 1u + FEE },   /* B bond - 1 at 5         */
    [CB3] = { KB, 0xB3, BOND + FEE },        /* B foreign payee at 5    */
    [CB4] = { KB, 0xB4, FEE },               /* B exits unregistered, 6 */
    [CB5] = { KB, 0xB5, BOND + FEE },        /* B registers at 7        */
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

#define H9   2u
#define H14  4u

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
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, H9, 12) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_STORAGE, DS, H14, 13) != 0)
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

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* A 2-leg storage envelope against the registry's CURRENT manifests,
 * REALLY signed: the SYSTEM leg by `sys_signer`, the SYSFUND leg by
 * `core_signer` (the coin's owner), each over its own engine-derived leg
 * digest at `height` (the reg_env two-pass of test_hf4_names_engine.c).
 * The funding: coin `c` → change CHG back to its owner when the coin
 * carries it. @return 0 / -1. */
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
 * registration moves value between (everything else is untouched) */
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

/* the registry row of `node`: 1 found (columns out, storage classes
 * blob / blob / blob / integer ×4 checked), 0 absent, -1 error */
typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], payee[64];
    uint64_t bond, status, regh, exith;
} st_row_t;

static int st_row(nodus_witness_t *w, int node, st_row_t *r) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT node_pk, payee_fp, bond, status, "
                           "registered_height, exit_height, typeof(node_fp),"
                           " typeof(node_pk), typeof(payee_fp), "
                           "typeof(bond), typeof(status), "
                           "typeof(registered_height), typeof(exit_height) "
                           "FROM v2_storage_nodes WHERE node_fp = ?1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_k[node].fp, 64, SQLITE_TRANSIENT);
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
                    strcmp((const char *)sqlite3_column_text(st, 6 + i),
                           want[i]) == 0;
        if (typed) {
            memcpy(r->pk, sqlite3_column_blob(st, 0), PK_LEN);
            memcpy(r->payee, sqlite3_column_blob(st, 1), 64);
            r->bond   = (uint64_t)sqlite3_column_int64(st, 2);
            r->status = (uint64_t)sqlite3_column_int64(st, 3);
            r->regh   = (uint64_t)sqlite3_column_int64(st, 4);
            r->exith  = (uint64_t)sqlite3_column_int64(st, 5);
            ret = 1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int roots_agree(fixture_t *a, fixture_t *b) {
    uint8_t ca[64], cb[64], fa[64], fb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        nodus_witness_global_root_v2(a->w, fa, NULL, NULL, NULL) != 0 ||
        nodus_witness_global_root_v2(b->w, fb, NULL, NULL, NULL) != 0)
        return -1;
    if (memcmp(ca, fa, 64) != 0 || memcmp(cb, fb, 64) != 0) return -1;
    return memcmp(ca, cb, 64) == 0 ? 0 : -1;
}

static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    nodus_v2_tx_result_t ra[4], rb[4];
    nodus_v2_block_t ba, bb;
    if (n > 4) return -1;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, envs, n);
    mk_block(&bb, h, envs, n);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 4;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 4;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0)
        return -1;
    for (size_t i = 0; i < n; i++) {
        if (ra[i].code != rb[i].code) return -1;
        if (codes) codes[i] = ra[i].code;
    }
    return roots_agree(a, b);
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

static int core_invariant(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rt) != 0 || !rt
        || !rt->invariant)
        return -1;
    return rt->invariant(rt, w);
}

static int t_engine(void) {
    fixture_t A, B;
    uint32_t codes[4];
    uint8_t *e[4] = { NULL, NULL, NULL, NULL };
    size_t l[4] = { 0, 0, 0, 0 };
    static uint8_t call[4][STREG_LEN];
    st_row_t r;
    uint64_t sum0 = 0, sum1 = 0, bonds = 0, pool0 = 0, pool1 = 0;

    CHECK(E_LEN > 8, "no epoch boundary among heights 1..7");
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (param 9 at 2, param 14 at 4)");

    /* block 1 — the param-9 edge (generation 1 -> 2) */
    CHECK(apply_both(&A, &B, 1, NULL, 0, NULL) == 0, "block 1 (idle)");

    /* block 2 (generation 2): a registration is NOT applied */
    {
        uint32_t cl = streg_call(call[0], KA, BOND, g_k[KA].fp);
        CHECK(st_env(A.w, 2, DNA_SYSRULE_STORAGE_REGISTER, call[0], cl, CA0,
                     BOND, KA, KA, &e[0], &l[0]) == 0,
              "registration built against generation 2");
        nodus_v2_envelope_t v[1] = { { e[0], l[0] } };
        CHECK(apply_both(&A, &B, 2, v, 1, codes) == 0, "block 2");
        CHECK(codes[0] != NODUS_V2_TX_OK,
              "generation 2 does not apply op 7");
        CHECK(st_row(A.w, KA, &r) == 0, "no registry row");
        free(e[0]); e[0] = NULL;
    }

    /* block 3 = H14-1 — the storage edge (generation 2 -> GEN_STORAGE) */
    CHECK(apply_both(&A, &B, 3, NULL, 0, NULL) == 0, "block 3 (idle)");
    {
        const nodus_domain_runtime_t *rs = NULL;
        CHECK(nodus_witness_v2_runtime_for(A.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs && rs->generation == NODUS_RT_GEN_STORAGE,
              "GEN_STORAGE judges block 4");
        CHECK(sys_root_is_v5(A.w) == 0, "the SYSTEM root is v5 from H-1");
    }

    /* block 4: A registers */
    CHECK(buckets(A.w, &sum0, &bonds, &pool0) == 0 && bonds == 0,
          "buckets before (no bond)");
    uint8_t sys_before[64];
    CHECK(nodus_witness_system_root_v5(A.w, sys_before) == 0, "v5 before");
    {
        uint32_t cl = streg_call(call[0], KA, BOND, g_k[KA].fp);
        CHECK(st_env(A.w, 4, DNA_SYSRULE_STORAGE_REGISTER, call[0], cl, CA1,
                     BOND, KA, KA, &e[0], &l[0]) == 0, "A's registration");
        nodus_v2_envelope_t v[1] = { { e[0], l[0] } };
        CHECK(apply_both(&A, &B, 4, v, 1, codes) == 0, "block 4");
        CHECK(codes[0] == NODUS_V2_TX_OK, "the registration applies");
        free(e[0]); e[0] = NULL;
    }
    CHECK(st_row(A.w, KA, &r) == 1, "A's row exists (typed columns)");
    CHECK(memcmp(r.pk, g_k[KA].pk, PK_LEN) == 0 &&
          memcmp(r.payee, g_k[KA].fp, 64) == 0 && r.bond == BOND &&
          r.status == DNA_V2_STORAGE_ACTIVE && r.regh == 4 && r.exith == 0,
          "row = (pk, payee = fp, bond, ACTIVE, 4, 0)");
    CHECK(coin_live(A.w, g_nul[CA1]) == 0, "the funding coin is spent");
    CHECK(buckets(A.w, &sum1, &bonds, &pool1) == 0, "buckets after");
    CHECK(bonds == BOND, "the storage-bond term holds the bond");
    CHECK(pool1 == pool0 + FEE, "the pool gained exactly the fee");
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

    /* block 5: four refusals */
    {
        uint32_t c0 = streg_call(call[0], KA, BOND, g_k[KA].fp);
        uint32_t c1 = streg_call(call[1], KB, BOND, g_k[KB].fp);
        uint32_t c2 = streg_call(call[2], KB, BOND - 1u, g_k[KB].fp);
        uint32_t c3 = streg_call(call[3], KB, BOND, g_k[KX].fp);
        CHECK(st_env(A.w, 5, DNA_SYSRULE_STORAGE_REGISTER, call[0], c0, CA2,
                     BOND, KA, KA, &e[0], &l[0]) == 0 &&
              st_env(A.w, 5, DNA_SYSRULE_STORAGE_REGISTER, call[1], c1, CB1,
                     BOND, KA, KB, &e[1], &l[1]) == 0 &&
              st_env(A.w, 5, DNA_SYSRULE_STORAGE_REGISTER, call[2], c2, CB2,
                     BOND - 1u, KB, KB, &e[2], &l[2]) == 0 &&
              st_env(A.w, 5, DNA_SYSRULE_STORAGE_REGISTER, call[3], c3, CB3,
                     BOND, KB, KB, &e[3], &l[3]) == 0, "four envelopes");
        uint8_t rr0[64], rr1[64];
        CHECK(nodus_witness_storage_registry_root(A.w, rr0) == 0, "reg root");
        nodus_v2_envelope_t v[4] = { { e[0], l[0] }, { e[1], l[1] },
                                     { e[2], l[2] }, { e[3], l[3] } };
        CHECK(apply_both(&A, &B, 5, v, 4, codes) == 0, "block 5");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC,
              "re-register while ACTIVE refused");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
              "SYSTEM leg signed by another key refused");
        CHECK(codes[2] == NODUS_V2_TX_ERR_EXEC, "bond - 1 refused");
        CHECK(codes[3] == NODUS_V2_TX_ERR_EXEC, "foreign payee refused");
        CHECK(nodus_witness_storage_registry_root(A.w, rr1) == 0 &&
              memcmp(rr0, rr1, 64) == 0, "the registry is unchanged");
        CHECK(st_row(A.w, KB, &r) == 0, "B has no row");
        for (int i = 0; i < 4; i++) { free(e[i]); e[i] = NULL; }
    }

    /* block 6: A exits; B exits unregistered */
    {
        CHECK(st_env(A.w, 6, DNA_SYSRULE_STORAGE_EXIT, g_k[KA].pk,
                     (uint32_t)PK_LEN, CA3, 0, KA, KA, &e[0], &l[0]) == 0 &&
              st_env(A.w, 6, DNA_SYSRULE_STORAGE_EXIT, g_k[KB].pk,
                     (uint32_t)PK_LEN, CB4, 0, KB, KB, &e[1], &l[1]) == 0,
              "two exits");
        nodus_v2_envelope_t v[2] = { { e[0], l[0] }, { e[1], l[1] } };
        CHECK(apply_both(&A, &B, 6, v, 2, codes) == 0, "block 6");
        CHECK(codes[0] == NODUS_V2_TX_OK, "A's exit applies");
        CHECK(codes[1] == NODUS_V2_TX_ERR_EXEC,
              "an unregistered node's exit is refused");
        CHECK(st_row(A.w, KA, &r) == 1 &&
              r.status == DNA_V2_STORAGE_EXITING && r.exith == 6 &&
              r.regh == 4 && r.bond == BOND, "A is EXITING since 6");
        CHECK(nodus_witness_storage_bond_total(A.w, &bonds) == 0 &&
              bonds == BOND, "an EXITING bond stays in supply (B2 releases)");
        CHECK(core_invariant(A.w) == 0, "the invariant holds");
        for (int i = 0; i < 2; i++) { free(e[i]); e[i] = NULL; }
    }

    /* block 7: A's duplicate exit; B registers */
    {
        uint32_t cl = streg_call(call[0], KB, BOND, g_k[KB].fp);
        CHECK(st_env(A.w, 7, DNA_SYSRULE_STORAGE_EXIT, g_k[KA].pk,
                     (uint32_t)PK_LEN, CA4, 0, KA, KA, &e[0], &l[0]) == 0 &&
              st_env(A.w, 7, DNA_SYSRULE_STORAGE_REGISTER, call[0], cl, CB5,
                     BOND, KB, KB, &e[1], &l[1]) == 0, "two envelopes");
        nodus_v2_envelope_t v[2] = { { e[0], l[0] }, { e[1], l[1] } };
        CHECK(apply_both(&A, &B, 7, v, 2, codes) == 0, "block 7");
        CHECK(codes[0] == NODUS_V2_TX_ERR_EXEC, "duplicate exit refused");
        CHECK(codes[1] == NODUS_V2_TX_OK, "B registers");
        CHECK(st_row(B.w, KB, &r) == 1 && r.status == DNA_V2_STORAGE_ACTIVE
              && r.regh == 7, "B ACTIVE since 7 (on the twin too)");
        CHECK(nodus_witness_storage_bond_total(A.w, &bonds) == 0 &&
              bonds == 2u * BOND, "two bonds in supply");
        CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
              "the invariant holds on both twins");
        for (int i = 0; i < 2; i++) { free(e[i]); e[i] = NULL; }
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
        { "engine_register_exit",       t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0) {
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
