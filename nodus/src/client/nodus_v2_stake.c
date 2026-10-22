/**
 * @file nodus/src/client/nodus_v2_stake.c
 * @brief The shared version-3 staking envelope builder (STAKE, DELEGATE,
 *        UNSTAKE, UNDELEGATE) — see nodus_v2_stake.h for the contract.
 *
 * Moved out of nodus/tools/nodus-cli.c cmd_v2_stake (`v2-envelope stake |
 * delegate`): the fee rule, the coin filter, the ascending-nullifier
 * selection, both call layouts, the deterministic change seed, the two leg
 * headers and the two-pass signature are the CLI's, unchanged. What changed
 * is the surface: no printing (a refusal is a code plus the numbers in
 * nodus_v2_stake_err_t, the CLI prints), no network, the ruleset identity
 * is an input, and the built bytes are decoded back and compared with the
 * request before they are returned. UNDELEGATE is new: the DELEGATE call
 * layout under runtime_op 4 with a fee-only funding leg
 * (nodus_witness_rt_native.c rtn_sys_call_flow: lock 0, release = amount).
 * UNSTAKE (op 3) is new too: call = the signer's own 2592-byte key
 * (RTN_SYS_UNSTAKE_CALL_LEN) with a fee-only funding leg (rtn_sys_call_flow:
 * lock 0, release 0).
 * STORAGE_REGISTER (op 7) and STORAGE_EXIT (op 8), storage reward v1
 * package B2b-CLI: REGISTER = the STAKE class (lock = bond), EXIT = the
 * UNSTAKE class (fee-only funding).
 * HF-6 6f-1: generation-aware (req->generation): at the HF-6 generation
 * STAKE takes the 7301-byte owner + node-consent layout. Plus the
 * node-consent text container (nodus_v2_consent_text_*). The consent
 * codec itself is NOT called from this file (see the header).
 * HF-6 slice 6b: the storage ops exist only at the HF-6 generation and
 * take its layouts only — REGISTER owner_fp ‖ node_pk ‖ consent_sig ‖
 * expiry ‖ bond (7299 B, the owner signs, the node consents with op 3),
 * EXIT node_fp ‖ owner_fp (128 B since C2, the owner signs); the
 * storage-reward-v1 node-key layouts (2664 / 2592 B) are gone, and the
 * container accepts op 3.
 * HF-6 slice 7b: at the HF-6 generation DELEGATE / UNDELEGATE (136 B,
 * delegator_fp = SHA3-512(signer) ‖ validator_id ‖ amount), UNSTAKE (128 B,
 * validator_id ‖ owner_fp) and VALIDATOR_UPDATE (op 5, 130 B, validator_id
 * ‖ owner_fp ‖ commission) are built in their generation-4 layouts; below
 * it ops 2-4 keep the legacy layouts byte-identical and op 5 is refused
 * (ERR_GEN).
 * HF-6 D2 (khan decision docs/plans/decisions/2026-10-13-kurultay-18-
 * summary.md): ROTATE (op 10) is gone from this module — no generation
 * has it (item 1) — and the container refuses consent op 2; UNSTAKE,
 * VALIDATOR_UPDATE and STORAGE_EXIT name their owner in the call (item 2,
 * "C2"), the signer's fingerprint or the multisig address.
 * HF-6 kind-3 owner (decision 2026-09-29-general-multisig.md addendum
 * "çok bacaklı ortak imza dosyası v2"): with req->msig_desc every
 * generation-4 layout is built for the multisig address SHA3-512(desc) —
 * both legs auth_kind 3, K zero slots, UNSIGNED, returned with its two leg
 * auth digests (the co-signers sign them through nodus_v2_msig.c's v2
 * files); the decoder reads both kinds. The kind-1 path is unchanged.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_v2_stake.h"
#include "nodus/nodus_ruleset_pins.h"
#include "nodus/nodus_types.h"            /* NODUS_W_BASE_TX_FEE,
                                            * NODUS_CMT_APP_MAX_EXPIRY_AHEAD */
#include "witness/nodus_witness_runtime.h" /* DNA_SYSRULE_*, DNA_CORERULE_
                                            * SYSFUND, NODUS_RT_AUTH* — header
                                            * constants only, no witness link */
#include "dnac/dnac.h"                     /* DNAC_* amounts and bounds       */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define V2K_PK_LEN   2592u
#define V2K_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)   /* count 1 ‖ pk ‖ sig */

_Static_assert(V2K_PK_LEN == DNAC_PUBKEY_SIZE, "ML-DSA-87 public key width");
_Static_assert(NODUS_V2_STAKE_CALL_LEN == DNAC_PUBKEY_SIZE + 2u + 8u + 64u,
               "STAKE call = pk ‖ commission u16 ‖ bond u64 ‖ dest_fp");
_Static_assert(NODUS_V2_DELEG_CALL_LEN == 2u * DNAC_PUBKEY_SIZE + 8u,
               "DELEGATE / UNDELEGATE call = pk ‖ pk ‖ amount u64");
_Static_assert(NODUS_V2_UNSTAKE_CALL_LEN == DNAC_PUBKEY_SIZE,
               "UNSTAKE call = the validator pk (RTN_SYS_UNSTAKE_CALL_LEN)");
/* HF-6 6f-1 — the generation-4 STAKE (design rev 6 §2, K7; the chain's
 * rtn_stake2_parse offsets) */
_Static_assert(DNA_VALBIND_PUBKEY_LEN == DNAC_PUBKEY_SIZE &&
               DNA_VALBIND_OWNER_FP_LEN == 64u && DNA_VALBIND_ID_LEN == 64u,
               "consent widths are the engine's");
_Static_assert(NODUS_V2_STAKE2_CALL_LEN ==
                   64u + DNAC_PUBKEY_SIZE + DNA_VALBIND_SIG_LEN + 8u + 2u + 8u,
               "gen-4 STAKE = owner_fp ‖ consensus_pk ‖ consent_sig ‖ "
               "expiry u64 ‖ commission u16 ‖ bond u64 (7301)");
_Static_assert(NODUS_V2_STAKE2_CALL_LEN != NODUS_V2_STAKE_CALL_LEN,
               "the two STAKE layouts are told apart by length");
_Static_assert(DNA_VALBIND_OP_STAKE == 1u &&
               DNA_VALBIND_OP_STORAGE_REGISTER == 3u,
               "the consent op bytes (design §6.1)");
#define V2K_S2_OWNER_OFF  0u
#define V2K_S2_PK_OFF     64u
#define V2K_S2_SIG_OFF    (V2K_S2_PK_OFF + V2K_PK_LEN)
#define V2K_S2_EXP_OFF    (V2K_S2_SIG_OFF + DNA_VALBIND_SIG_LEN)
#define V2K_S2_COMM_OFF   (V2K_S2_EXP_OFF + 8u)
#define V2K_S2_BOND_OFF   (V2K_S2_COMM_OFF + 2u)
/* HF-6 slice 6b — the generation-4 storage calls (design rev 6 §2 /
 * §11.3 / §11.5; the chain's rtn_streg2_parse / rtn_stexit2_parse).
 * STORAGE_EXIT carries the owner since C2 (khan decision 2026-10-13,
 * Kurultay #18 item 2). */
_Static_assert(NODUS_V2_STREG_CALL_LEN ==
                   64u + DNAC_PUBKEY_SIZE + DNA_VALBIND_SIG_LEN + 8u + 8u,
               "STORAGE_REGISTER = owner_fp ‖ node_pk ‖ consent_sig ‖ "
               "expiry u64 ‖ bond u64 (7299)");
_Static_assert(NODUS_V2_STEXIT_CALL_LEN == 64u + 64u,
               "STORAGE_EXIT = node_fp ‖ owner_fp (128)");
#define V2K_SR_OWNER_OFF  0u
#define V2K_SR_PK_OFF     64u
#define V2K_SR_SIG_OFF    (V2K_SR_PK_OFF + V2K_PK_LEN)
#define V2K_SR_EXP_OFF    (V2K_SR_SIG_OFF + DNA_VALBIND_SIG_LEN)
#define V2K_SR_BOND_OFF   (V2K_SR_EXP_OFF + 8u)
#define V2K_SX_NODE_OFF   0u
#define V2K_SX_OWNER_OFF  64u
/* HF-6 slice 7b — the generation-4 calls of ops 2-5 (design rev 6 §2, K7;
 * the chain's rtn_deleg_parse_v2 / rtn_unstake_parse_v2 /
 * rtn_vupd_parse_v2); UNSTAKE and VALIDATOR_UPDATE carry the owner since
 * C2 */
_Static_assert(NODUS_V2_DELEG2_CALL_LEN == 64u + 64u + 8u,
               "gen-4 DELEGATE / UNDELEGATE = delegator_fp ‖ validator_id ‖ "
               "amount u64 (136)");
_Static_assert(NODUS_V2_UNSTAKE2_CALL_LEN == 64u + 64u,
               "gen-4 UNSTAKE = validator_id ‖ owner_fp (128)");
_Static_assert(NODUS_V2_VUPD2_CALL_LEN == 64u + 64u + 2u,
               "gen-4 VALIDATOR_UPDATE = validator_id ‖ owner_fp ‖ "
               "commission u16 (130)");
_Static_assert(NODUS_V2_DELEG2_CALL_LEN != NODUS_V2_DELEG_CALL_LEN &&
               NODUS_V2_UNSTAKE2_CALL_LEN != NODUS_V2_UNSTAKE_CALL_LEN,
               "the decoder tells the two layouts of ops 2-4 apart by length");
#define V2K_D2_DFP_OFF    0u
#define V2K_D2_VID_OFF    64u
#define V2K_D2_AMT_OFF    128u
#define V2K_U2_VID_OFF    0u
#define V2K_U2_OWNER_OFF  64u
#define V2K_U2_COMM_OFF   128u
_Static_assert(V2K_D2_AMT_OFF + 8u == NODUS_V2_DELEG2_CALL_LEN &&
               V2K_U2_OWNER_OFF + 64u == NODUS_V2_UNSTAKE2_CALL_LEN &&
               V2K_U2_COMM_OFF + 2u == NODUS_V2_VUPD2_CALL_LEN,
               "generation-4 ops 2-5 field offsets sum to the calls");
_Static_assert(V2K_S2_BOND_OFF + 8u == NODUS_V2_STAKE2_CALL_LEN &&
               V2K_SR_BOND_OFF + 8u == NODUS_V2_STREG_CALL_LEN &&
               V2K_SX_OWNER_OFF + 64u == NODUS_V2_STEXIT_CALL_LEN,
               "generation-4 field offsets sum to the calls");

_Static_assert((uint32_t)NODUS_V2_STAKE_OP_STAKE == DNA_SYSRULE_STAKE &&
               (uint32_t)NODUS_V2_STAKE_OP_DELEGATE == DNA_SYSRULE_DELEGATE &&
               (uint32_t)NODUS_V2_STAKE_OP_UNSTAKE == DNA_SYSRULE_UNSTAKE &&
               (uint32_t)NODUS_V2_STAKE_OP_UNDELEGATE == DNA_SYSRULE_UNDELEGATE &&
               (uint32_t)NODUS_V2_STAKE_OP_VALIDATOR_UPDATE ==
                   DNA_SYSRULE_VALIDATOR_UPDATE &&
               (uint32_t)NODUS_V2_STAKE_OP_STORAGE_REGISTER ==
                   DNA_SYSRULE_STORAGE_REGISTER &&
               (uint32_t)NODUS_V2_STAKE_OP_STORAGE_EXIT ==
                   DNA_SYSRULE_STORAGE_EXIT,
               "the op enum is the wire runtime_op");

/* HF-8 (design docs/plans/2026-10-07-delegate-name-required-design.md rev
 * 2 §1): once chain_config param 17 is active, the CORE SYSFUND leg of a
 * DELEGATE whose delegator is not the validator reads the delegator's
 * name too, so its input ceiling is 14, not NODUS_V2_SPEND_MAX_IN (15)
 * (nodus_witness_rt_native.c RTN_SYSFUND_DLG_MAX_IN, rtn_sysfund_name_
 * gate). The builder has no chain state, so it applies the 14 to EVERY
 * non-self DELEGATE — the same predicate minus the activation fact: an
 * envelope it builds is valid on both sides of the activation height. A
 * self-delegation and every other op keep 15. HF-6 slice 7b: so does a
 * generation-4 DELEGATE — under the HF-6 generation the CORE funding leg is
 * never name-gated (rtn_sysfund_name_gate's generation-4 arm, decision D3:
 * the name read is the SYSTEM leg's op 16), so its ceiling is 15. */
#define V2K_DLG_GATED_MAX_IN 14
_Static_assert(V2K_DLG_GATED_MAX_IN + 1 == (int)NODUS_V2_SPEND_MAX_IN,
               "HF-8: the gated DELEGATE funding ceiling is one input "
               "below the SPEND ceiling (the NAMEOWN read)");

static void err_reset(nodus_v2_stake_err_t *err) {
    if (err) memset(err, 0, sizeof(*err));
}

static int hex_lower_ok(const uint8_t *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* HF-6 kind-3 owner — a descriptor's header bounds, read from its bytes
 * WITHOUT the descriptor codec (shared/dnac/msig_wire.c is not linked
 * where this file is — see the header): its length is exactly
 * DNA_MSIG_DESC_LEN(N), 2 <= N <= DNA_MSIG_MAX_N, 1 <= M <= N, and the
 * signer count K satisfies M <= K <= N. The tag and the key order are the
 * codec's (the chain's rtn_auth_msig and nodus_v2_msig_review2 judge
 * them). @return 0 / -1. */
static int v2k_desc_bounds(const uint8_t *d, size_t dl, uint32_t k,
                           uint8_t *m_out, uint8_t *n_out) {
    if (!d || dl < DNA_MSIG_HDR_LEN || dl > DNA_MSIG_MAX_DESC_LEN) return -1;
    const uint8_t m = d[DNA_MSIG_TAG_LEN];
    const uint8_t n = d[DNA_MSIG_TAG_LEN + 1u];
    if (n < DNA_MSIG_MIN_N || n > DNA_MSIG_MAX_N || m < 1 || m > n ||
        dl != DNA_MSIG_DESC_LEN(n) || k < m || k > n)
        return -1;
    if (m_out) *m_out = m;
    if (n_out) *n_out = n;
    return 0;
}

/* The kind-3 auth blob of leg L (rtn_auth_msig's layout, one descriptor):
 * count K ‖ K × (pk ‖ sig) ‖ dcount 1 ‖ dlen u16 BE ‖ descriptor, consumed
 * exactly; nothing is read before its length is proved. The slots are not
 * judged (all zero in an unsigned export). @return 0 / -1. */
static int v2k_msig_blob(const dna_env_view_t *v, int L, uint32_t *k_out,
                         const uint8_t **desc_out, size_t *dlen_out) {
    const uint8_t *a = v->buf + v->auth_off[L];
    const uint64_t alen = v->leg[L].auth_len;
    if (alen < 1) return -1;
    const uint32_t k = a[0];
    if (k < 1 || k > NODUS_RT_AUTH_MAX_SIGNERS) return -1;
    const uint64_t off = 1u + (uint64_t)k * NODUS_RT_AUTH_SIGNER_LEN;
    if (alen < off + 3u || a[off] != 1) return -1;
    const size_t dl = ((size_t)a[off + 1] << 8) | a[off + 2];
    if (alen != off + 3u + dl) return -1;
    *k_out = k;
    *desc_out = a + off + 3;
    *dlen_out = dl;
    return 0;
}

/* ── the ruleset identity from the generated pins header ───────────── */

int nodus_v2_stake_ruleset_from_pins_gen(uint32_t generation,
                                         nodus_v2_stake_ruleset_t *out) {
    _Static_assert(NODUS_PIN_SYS_DOMAIN_ID == DNA_DOMAIN_SYSTEM,
                   "the pinned SYSTEM tuple is domain 0");
    _Static_assert(NODUS_PIN_CORE_DOMAIN_ID == DNA_DOMAIN_CORE,
                   "the pinned CORE tuple is domain 1");
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    /* HF-4: the ONE per-generation pins table (nodus_v2_spend.c) */
    return nodus_v2_pins_tuples(generation, &out->sys_ruleset_version,
                                out->sys_ruleset_hash,
                                &out->core_ruleset_version,
                                out->core_ruleset_hash);
}

int nodus_v2_stake_ruleset_from_pins(nodus_v2_stake_ruleset_t *out) {
    return nodus_v2_stake_ruleset_from_pins_gen(1, out);
}

/* ── read-back ──────────────────────────────────────────────────────── */

int nodus_v2_stake_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_stake_decoded_t *out) {
    if (!env || !out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    int rc = NODUS_V2_SPEND_ERR_DECODE;
    if (dna_env_decode(env, env_len, v) != 0 || v->leg_count != 2)
        goto done;
    const uint32_t op = v->leg[0].runtime_op;
    if (op != DNA_SYSRULE_STAKE && op != DNA_SYSRULE_DELEGATE &&
        op != DNA_SYSRULE_UNSTAKE && op != DNA_SYSRULE_UNDELEGATE &&
        op != DNA_SYSRULE_VALIDATOR_UPDATE &&
        op != DNA_SYSRULE_STORAGE_REGISTER && op != DNA_SYSRULE_STORAGE_EXIT)
        goto done;                       /* op 10 (the removed ROTATE)
                                          * included                     */
    if (v->leg[0].domain_id != DNA_DOMAIN_SYSTEM ||
        v->leg[1].domain_id != DNA_DOMAIN_CORE ||
        v->leg[1].runtime_op != DNA_CORERULE_SYSFUND)
        goto done;
    /* the auth kind: 1 (one signer) or — HF-6 kind-3 owner — 3 on BOTH
     * legs (the same owner proves the record and owns the funding) */
    const uint8_t akind = v->leg[0].auth_kind;
    if (akind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
        akind != NODUS_RT_AUTHKIND_DSA87_MSIG_V1)
        goto done;
    const int is_msig = akind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
    for (int L = 0; L < 2; L++)
        if (v->leg[L].access_mode != DNA_ENV_ACCESS_INVOKE ||
            v->leg[L].auth_kind != akind ||
            (!is_msig && v->leg[L].auth_len != V2K_AUTH_LEN))
            goto done;
    if (is_msig) {
        /* one descriptor, the same K, descriptor bytes and slot keys on
         * both legs; the signature bytes are each leg's own */
        uint32_t k0 = 0, k1 = 0;
        const uint8_t *d0 = NULL, *d1 = NULL;
        size_t dl0 = 0, dl1 = 0;
        if (v2k_msig_blob(v, 0, &k0, &d0, &dl0) != 0 ||
            v2k_msig_blob(v, 1, &k1, &d1, &dl1) != 0 ||
            k0 != k1 || dl0 != dl1 || memcmp(d0, d1, dl0) != 0 ||
            v2k_desc_bounds(d0, dl0, k0, &out->msig_m, &out->msig_n) != 0)
            goto done;
        const uint8_t *a0 = v->buf + v->auth_off[0];
        const uint8_t *a1 = v->buf + v->auth_off[1];
        for (uint32_t i = 0; i < k0; i++)
            if (memcmp(a0 + 1 + (size_t)i * NODUS_RT_AUTH_SIGNER_LEN,
                       a1 + 1 + (size_t)i * NODUS_RT_AUTH_SIGNER_LEN,
                       V2K_PK_LEN) != 0)
                goto done;
        if (qgp_sha3_512(d0, dl0, out->msig_addr) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        out->msig_signers = k0;
    }
    if (v->leg[0].res_max_effects != NODUS_V2_STAKE_SYS_EFFECTS ||
        v->leg[0].res_max_effect_bytes != NODUS_V2_STAKE_SYS_EFFECT_BYTES ||
        v->leg[1].res_max_effects != NODUS_V2_STAKE_FUND_EFFECTS ||
        v->leg[1].res_max_effect_bytes != NODUS_V2_STAKE_FUND_EFFECT_BYTES)
        goto done;

    /* leg0 — the record call; its length is proved before any read */
    const uint8_t *s = v->buf + v->call_off[0];
    const size_t slen = v->leg[0].call_len;
    /* HF-6 slice 7b: ops 2-4 are told apart from their legacy layouts by
     * length (136 / 128 vs 5192 / 2592, disjoint — rtn_sys_call_gen_of);
     * op 5 has no other layout in this module */
    const int is_deleg2 = (op == DNA_SYSRULE_DELEGATE ||
                           op == DNA_SYSRULE_UNDELEGATE) &&
                          slen == NODUS_V2_DELEG2_CALL_LEN;
    const int is_unstake2 = op == DNA_SYSRULE_UNSTAKE &&
                            slen == NODUS_V2_UNSTAKE2_CALL_LEN;
    if ((op == DNA_SYSRULE_STAKE && slen == NODUS_V2_STAKE2_CALL_LEN) ||
        op == DNA_SYSRULE_STORAGE_REGISTER ||
        op == DNA_SYSRULE_STORAGE_EXIT ||
        is_deleg2 || is_unstake2 ||
        op == DNA_SYSRULE_VALIDATOR_UPDATE) {
        /* HF-6 6f-1 / 6b / 7b — the generation-4 layouts (the storage ops
         * and VALIDATOR_UPDATE have no other here): the call carries no
         * key, so the record identity is the leg-0 signer (the owner /
         * delegator, rtn_sys_owner_auth kind 1; the loop below binds both
         * legs to it — auth_len == V2K_AUTH_LEN was proved above) or, kind
         * 3, the descriptor's address (rtn_sys_owner_auth kind 3; both
         * blobs proved alike above). `signer_fp` is that identity. */
        uint8_t signer_fp[64];
        if (is_msig) {
            memcpy(signer_fp, out->msig_addr, 64);
        } else {
            const uint8_t *a0 = v->buf + v->auth_off[0];
            if (a0[0] != 1) goto done;
            memcpy(out->identity_pk, a0 + 1, V2K_PK_LEN);
            if (qgp_sha3_512(out->identity_pk, V2K_PK_LEN, signer_fp) != 0) {
                rc = NODUS_V2_SPEND_ERR_HASH;
                goto done;
            }
        }
        out->gen4 = 1;
        if (op == DNA_SYSRULE_STAKE) {
            memcpy(out->owner_fp, s + V2K_S2_OWNER_OFF, 64);
            memcpy(out->consensus_pk, s + V2K_S2_PK_OFF, V2K_PK_LEN);
            memcpy(out->consent_sig, s + V2K_S2_SIG_OFF, DNA_VALBIND_SIG_LEN);
            out->consent_expiry = get_u64(s + V2K_S2_EXP_OFF);
            out->commission_bps = ((uint32_t)s[V2K_S2_COMM_OFF] << 8) |
                                  s[V2K_S2_COMM_OFF + 1];
            out->amount = get_u64(s + V2K_S2_BOND_OFF);
            /* the owner IS the identity (kind 1: the signer; kind 3: the
             * descriptor's address) — an envelope naming another owner is
             * not one this module builds */
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
        } else if (op == DNA_SYSRULE_STORAGE_REGISTER) {
            /* owner_fp ‖ node_pk ‖ consent_sig ‖ expiry ‖ bond
             * (rtn_streg2_parse) */
            if (slen != NODUS_V2_STREG_CALL_LEN) goto done;
            memcpy(out->owner_fp, s + V2K_SR_OWNER_OFF, 64);
            memcpy(out->consensus_pk, s + V2K_SR_PK_OFF, V2K_PK_LEN);
            memcpy(out->consent_sig, s + V2K_SR_SIG_OFF, DNA_VALBIND_SIG_LEN);
            out->consent_expiry = get_u64(s + V2K_SR_EXP_OFF);
            out->amount = get_u64(s + V2K_SR_BOND_OFF);
            if (qgp_sha3_512(out->consensus_pk, V2K_PK_LEN,
                             out->node_fp) != 0) {
                rc = NODUS_V2_SPEND_ERR_HASH;
                goto done;
            }
            /* kind 1, as STAKE */
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
        } else if (op == DNA_SYSRULE_STORAGE_EXIT) {
            /* node_fp ‖ owner_fp (rtn_stexit2_parse, C2); the chain
             * requires owner_fp == the ROW's owner — this module builds it
             * as the identity, so another owner is refused */
            if (slen != NODUS_V2_STEXIT_CALL_LEN) goto done;
            memcpy(out->node_fp, s + V2K_SX_NODE_OFF, 64);
            memcpy(out->owner_fp, s + V2K_SX_OWNER_OFF, 64);
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
        } else if (is_deleg2) {
            /* delegator_fp ‖ validator_id ‖ amount (rtn_deleg_parse_v2) */
            memcpy(out->owner_fp, s + V2K_D2_DFP_OFF, 64);
            memcpy(out->validator_id, s + V2K_D2_VID_OFF, 64);
            out->amount = get_u64(s + V2K_D2_AMT_OFF);
            /* kind 1: the delegator IS the signer (rtn_delegate2_exec /
             * rtn_undelegate2_exec bind delegator_fp to the verdict) */
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
            if (all_zero(out->validator_id, 64)) goto done;
        } else if (is_unstake2) {
            /* validator_id ‖ owner_fp (rtn_unstake_parse_v2, C2); the
             * chain requires owner_fp == the ROW's owner — built as the
             * identity here */
            memcpy(out->validator_id, s + V2K_U2_VID_OFF, 64);
            memcpy(out->owner_fp, s + V2K_U2_OWNER_OFF, 64);
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
            if (all_zero(out->validator_id, 64)) goto done;
        } else {
            /* VALIDATOR_UPDATE: validator_id ‖ owner_fp ‖ commission u16
             * (rtn_vupd_parse_v2 — its two decoder rejects restated: a
             * zero id, a bps above the bound; owner_fp as UNSTAKE) */
            if (slen != NODUS_V2_VUPD2_CALL_LEN) goto done;
            memcpy(out->validator_id, s + V2K_U2_VID_OFF, 64);
            memcpy(out->owner_fp, s + V2K_U2_OWNER_OFF, 64);
            out->commission_bps = ((uint32_t)s[V2K_U2_COMM_OFF] << 8) |
                                  s[V2K_U2_COMM_OFF + 1];
            if (memcmp(out->owner_fp, signer_fp, 64) != 0) goto done;
            if (all_zero(out->validator_id, 64) ||
                out->commission_bps > (uint32_t)DNAC_COMMISSION_BPS_MAX)
                goto done;
        }
    } else if (is_msig) {
        goto done;                       /* a legacy layout has no kind-3
                                          * owner (rtn_sys_stake_auth: one
                                          * signer, and the generation 1-3
                                          * SYSTEM allowlist has no kind 3) */
    } else if (op == DNA_SYSRULE_STAKE) {
        if (slen != NODUS_V2_STAKE_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
        out->commission_bps = ((uint32_t)s[V2K_PK_LEN] << 8) |
                              s[V2K_PK_LEN + 1];
        out->amount = get_u64(s + V2K_PK_LEN + 2);
        memcpy(out->dest_fp, s + V2K_PK_LEN + 10, 64);
    } else if (op == DNA_SYSRULE_UNSTAKE) {
        /* the call IS the validator key (rtn_sys_call_identity) */
        if (slen != NODUS_V2_UNSTAKE_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
    } else {
        if (slen != NODUS_V2_DELEG_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
        memcpy(out->validator_pk, s + V2K_PK_LEN, V2K_PK_LEN);
        out->amount = get_u64(s + 2 * V2K_PK_LEN);
    }

    /* both auth blobs: exactly one signer, and it is the record identity
     * (rtn_sys_stake_auth binds leg0's signer to the call's identity; the
     * funding coins are the same key's) */
    for (int L = 0; L < 2 && !is_msig; L++) {
        const uint8_t *a = v->buf + v->auth_off[L];
        if (a[0] != 1 || memcmp(a + 1, out->identity_pk, V2K_PK_LEN) != 0)
            goto done;
    }

    /* leg1 — in_count ‖ nullifiers ascending ‖ out_count (0/1) ‖ change */
    const uint8_t *c = v->buf + v->call_off[1];
    const size_t clen = v->leg[1].call_len;
    if (clen < 2 || c[0] < 1 || c[0] > NODUS_V2_SPEND_MAX_IN ||
        clen < 2 + (size_t)c[0] * 64)
        goto done;
    const int nin = c[0];
    const int nout = c[1 + (size_t)nin * 64];
    if (nout > 1 ||
        clen != 2 + (size_t)nin * 64 + (size_t)nout * NODUS_V2_SPEND_OUT_LEN)
        goto done;
    for (int i = 0; i < nin; i++) {
        memcpy(out->in_nul[i], c + 1 + (size_t)i * 64, 64);
        if (i > 0 && memcmp(out->in_nul[i - 1], out->in_nul[i], 64) >= 0)
            goto done;                           /* strictly ascending */
    }
    if (nout == 1) {
        static const uint8_t zero64[64] = {0};
        const uint8_t *r = c + 2 + (size_t)nin * 64;
        if (!hex_lower_ok(r, 128)) goto done;
        memcpy(out->change_owner, r, 128);
        out->change_owner[128] = '\0';
        out->change_amount = get_u64(r + 128);
        if (out->change_amount == 0) goto done;
        if (memcmp(r + 136, zero64, 64) != 0) goto done;   /* native only */
        uint8_t pre[160];
        memcpy(pre, r, 128);
        memcpy(pre + 128, r + 200, 32);
        if (qgp_sha3_512(pre, sizeof(pre), out->change_id) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
    }
    out->op                   = op;
    out->auth_kind            = akind;
    out->n_in                 = nin;
    out->n_out                = nout;
    out->expiry_height        = v->expiry_height;
    out->fee                  = v->fee_amount;
    out->units                = v->res_max_total_units;
    out->sys_ruleset_version  = v->leg[0].ruleset_version;
    out->core_ruleset_version = v->leg[1].ruleset_version;
    rc = NODUS_V2_SPEND_OK;
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(v);
    return rc;
}

/* ── build ──────────────────────────────────────────────────────────── */

void nodus_v2_stake_built_free(nodus_v2_stake_built_t *b) {
    if (!b) return;
    free(b->env);
    b->env = NULL;
    b->env_len = 0;
}

/* What the builder asked for — the read-back predicate's input. The flags
 * are the builder's own, derived once from the request. */
typedef struct {
    const nodus_v2_stake_req_t *req;
    nodus_v2_stake_op_t op;
    uint8_t        akind;
    uint64_t       fee, units;
    int            is_msig, is_stake, is_stake2, is_unstake, is_stexit,
                   is_vupd, is_role2, is_consented;
    const uint8_t *signer_raw;               /* SHA3-512 of the signer      */
    const char    *signer_fp;                /* 128 hex of it               */
    int            n_in;
    const uint8_t (*nulls)[64];              /* ascending, as on the wire   */
    uint8_t        out_count;
    uint64_t       change;
    const uint8_t *change_id;                /* 64 bytes                    */
} v2k_rb_t;

/* THE read-back predicate: decode `env` and refuse unless it is what the
 * request asked for — op, fee, units, expiry, both ruleset versions, auth
 * kind, the signer identity (key, or the multisig address and signer
 * count), the amount, the op-specific call fields, the exact funding inputs
 * and the change output. It runs on the UNSIGNED bytes before any signature
 * (v2k_presign_check; the signer hands over the pass-1 bytes with `count 1 ‖
 * pk` in each leg's auth blob and a zero signature, so the identity IS
 * compared pre-sign) and again on the signed bytes — and, for a kind-3
 * owner, on the unsigned export, which is never signed here: the same code
 * in every run. Only the signature is not judged here.
 * @return OK / _ERR_DECODE (mismatch) / the decoder's code. */
static int v2k_readback(const v2k_rb_t *rb, const uint8_t *env, size_t len,
                        nodus_v2_stake_decoded_t *d) {
    const nodus_v2_stake_req_t *req = rb->req;
    const int is_msig = rb->is_msig, is_stake = rb->is_stake,
              is_stake2 = rb->is_stake2, is_unstake = rb->is_unstake,
              is_stexit = rb->is_stexit, is_vupd = rb->is_vupd,
              is_role2 = rb->is_role2, is_consented = rb->is_consented;
    int rc = nodus_v2_stake_decode(env, len, d);
    if (rc != NODUS_V2_SPEND_OK) return rc;
    rc = NODUS_V2_SPEND_ERR_DECODE;
    if (d->op != (uint32_t)rb->op || d->fee != rb->fee ||
        d->units != rb->units ||
        d->expiry_height != req->expiry_height ||
        d->sys_ruleset_version != req->rs->sys_ruleset_version ||
        d->core_ruleset_version != req->rs->core_ruleset_version ||
        d->auth_kind != rb->akind ||
        (is_msig
             ? (d->msig_signers != req->msig_signers ||
                memcmp(d->msig_addr, rb->signer_raw, 64) != 0)
             : memcmp(d->identity_pk, req->pk, V2K_PK_LEN) != 0) ||
        (!is_unstake && !is_stexit && !is_vupd &&
         d->amount != req->amount) ||
        d->n_in != rb->n_in ||
        memcmp(d->in_nul, rb->nulls, (size_t)rb->n_in * 64) != 0 ||
        d->n_out != (int)rb->out_count ||
        d->gen4 != (is_consented || is_stexit || is_role2))
        return rc;
    if (is_role2) {
        /* HF-6 slice 7b: the signer's fingerprint (DELEGATE /
         * UNDELEGATE: the call's delegator_fp), the validator_id, and
         * no amount (UNSTAKE / VALIDATOR_UPDATE) */
        if (memcmp(d->owner_fp, rb->signer_raw, 64) != 0 ||
            memcmp(d->validator_id, req->validator_id, 64) != 0)
            return rc;
        if ((is_unstake || is_vupd) && d->amount != 0) return rc;
        if (is_vupd && d->commission_bps != req->commission_bps)
            return rc;
    } else if (is_consented) {
        if (memcmp(d->owner_fp, rb->signer_raw, 64) != 0 ||
            memcmp(d->consensus_pk, req->consensus_pk, V2K_PK_LEN) != 0 ||
            memcmp(d->consent_sig, req->consent_sig,
                   DNA_VALBIND_SIG_LEN) != 0 ||
            d->consent_expiry != req->consent_expiry)
            return rc;
        if (is_stake2 && d->commission_bps != req->commission_bps)
            return rc;
    } else if (is_stexit) {
        if (d->amount != 0 ||
            memcmp(d->owner_fp, rb->signer_raw, 64) != 0 ||
            memcmp(d->node_fp, req->node_fp, 64) != 0)
            return rc;
    } else if (is_stake) {
        if (d->commission_bps != req->commission_bps ||
            memcmp(d->dest_fp, req->dest_fp, 64) != 0)
            return rc;
    } else if (is_unstake) {
        if (d->amount != 0) return rc;   /* the call carries none */
    } else if (memcmp(d->validator_pk, req->validator_pk,
                      V2K_PK_LEN) != 0) {
        return rc;
    }
    if (rb->out_count &&
        (memcmp(d->change_owner, rb->signer_fp, 128) != 0 ||
         d->change_amount != rb->change ||
         memcmp(d->change_id, rb->change_id, 64) != 0))
        return rc;
    return NODUS_V2_SPEND_OK;
}

static int v2k_presign_check(const uint8_t *env, size_t len, void *ctx) {
    /* heap: the decoded struct carries three 2592-byte keys */
    nodus_v2_stake_decoded_t *d = calloc(1, sizeof(*d));
    if (!d) return -1;
    const int ok = v2k_readback((const v2k_rb_t *)ctx, env, len, d) ==
                   NODUS_V2_SPEND_OK;
    free(d);
    return ok ? 0 : -1;
}

int nodus_v2_stake_build(const nodus_v2_stake_req_t *req,
                         nodus_v2_stake_built_t *out,
                         nodus_v2_stake_err_t *err) {
    err_reset(err);
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->chain32 ||
        req->n_coins < 0 || (req->n_coins > 0 && !req->coins))
        return NODUS_V2_SPEND_ERR_ARG;
    /* HF-6 kind-3 owner: the descriptor replaces the signing key */
    const int is_msig = req->msig_desc != NULL;
    if (!is_msig && (!req->pk || !req->sk)) return NODUS_V2_SPEND_ERR_ARG;
    const nodus_v2_stake_op_t op = req->op;
    const int is_stake = op == NODUS_V2_STAKE_OP_STAKE;
    const int is_streg = op == NODUS_V2_STAKE_OP_STORAGE_REGISTER;
    const int is_stexit = op == NODUS_V2_STAKE_OP_STORAGE_EXIT;
    /* the call is the signer's own key alone (the legacy UNSTAKE) */
    const int is_unstake = op == NODUS_V2_STAKE_OP_UNSTAKE;
    const int is_deleg = op == NODUS_V2_STAKE_OP_DELEGATE ||
                         op == NODUS_V2_STAKE_OP_UNDELEGATE;
    const int is_vupd = op == NODUS_V2_STAKE_OP_VALIDATOR_UPDATE;
    if (!is_stake && !is_streg && !is_stexit && !is_unstake && !is_deleg &&
        !is_vupd)
        return NODUS_V2_STAKE_ERR_OP;    /* op 10 (the removed ROTATE)
                                          * included                     */
    /* HF-6 6f-1 — the generation decides the layout (design rev 6 §2) */
    const int gen4 = req->generation >= NODUS_RT_GEN_STORAGE;
    if ((is_streg || is_stexit || is_vupd) && !gen4)
        return NODUS_V2_STAKE_ERR_GEN;       /* ops 7, 8 exist from gen 4
                                              * only, in its layouts only
                                              * (HF-6 slice 6b: the storage
                                              * ops have no older layout);
                                              * op 5's legacy 2594-byte
                                              * layout was never built here
                                              * (HF-6 slice 7b)           */
    const int is_stake2 = is_stake && gen4;
    /* HF-6 slice 7b — the generation-4 calls of ops 2-5 (design §2): every
     * identity a 64-byte value, the target / validator a validator_id */
    const int is_role2 = gen4 && (is_deleg || is_unstake || is_vupd);
    /* the owner-signed, node-consented calls (design §2, §11.3) */
    const int is_consented = is_stake2 || is_streg;
    /* HF-6 kind-3 owner: the generation-4 layouts only (a legacy layout's
     * authority is one signer, rtn_sys_stake_auth), and the descriptor's
     * header bounds with M <= K <= N */
    if (is_msig) {
        if (!is_consented && !is_stexit && !is_role2)
            return NODUS_V2_STAKE_ERR_GEN;
        if (v2k_desc_bounds(req->msig_desc, req->msig_desc_len,
                            req->msig_signers, NULL, NULL) != 0)
            return NODUS_V2_SPEND_ERR_ARG;
    }
    if (is_consented) {
        if (!req->consensus_pk || !req->consent_sig)
            return NODUS_V2_SPEND_ERR_ARG;
    } else if (is_stexit) {
        if (!req->node_fp) return NODUS_V2_SPEND_ERR_ARG;
    } else if (is_role2) {
        /* no legal validator_id is all zero (rtn_val2_rec_ok; the VUPD
         * decoder rejects one, rtn_vupd_parse_v2) */
        if (!req->validator_id || all_zero(req->validator_id, 64))
            return NODUS_V2_SPEND_ERR_ARG;
    } else if (is_stake ? !req->dest_fp
                        : (is_deleg && !req->validator_pk)) {
        return NODUS_V2_SPEND_ERR_ARG;
    }

    /* what the call bytes alone decide (cmd_v2_stake's pre-I/O checks) */
    if (is_vupd) {
        /* rtn_vupd_parse_v2's bound — a decoder reject on the chain */
        if (req->commission_bps > (uint32_t)DNAC_COMMISSION_BPS_MAX)
            return NODUS_V2_STAKE_ERR_COMMISSION;
    } else if (is_stake2) {
        /* rtn_stake2_exec's call-alone rules: the commission bound and the
         * INTEGER bound of the bond (design §1.5). The STAKE_MIN floor is
         * chain state (rtn_stake_min_at — chain_config param 19, reported
         * by dnac_fee_info "stake_min"), the consent and its expiry window
         * the caller's. */
        if (req->commission_bps > (uint32_t)DNAC_COMMISSION_BPS_MAX)
            return NODUS_V2_STAKE_ERR_COMMISSION;
        if (req->amount < 1 || req->amount > (uint64_t)INT64_MAX)
            return NODUS_V2_STAKE_ERR_BOND;
    } else if (is_streg) {
        /* rtn_storage_register_exec's call-alone rules (design §11.3, G13):
         * 0 < bond <= INT64_MAX. The EXACT value is chain state (the
         * STORAGE_BOND in force, rtn_storage_bond_at — chain_config param
         * 21, reported by dnac_fee_info "storage_bond"), the consent and
         * its expiry window the caller's. */
        if (req->amount < 1 || req->amount > (uint64_t)INT64_MAX)
            return NODUS_V2_STAKE_ERR_STORAGE_BOND;
    } else if (is_stake) {
        /* tokenomics-v3 P3-8 (rtn_stake_exec) — the u16 wire field alone
         * would admit values the chain refuses */
        if (req->commission_bps > (uint32_t)DNAC_COMMISSION_BPS_MAX)
            return NODUS_V2_STAKE_ERR_COMMISSION;
        /* final pre-testnet wipe W-B (rtn_stake_exec): EXACTLY the
         * self-bond */
        if (req->amount != DNAC_SELF_STAKE_AMOUNT)
            return NODUS_V2_STAKE_ERR_BOND;
    } else if (!is_unstake && !is_stexit &&
               (req->amount < 1 || req->amount > DNAC_DEFAULT_TOTAL_SUPPLY)) {
        return NODUS_V2_STAKE_ERR_AMOUNT;          /* rtn_delegate_exec's
                                                    * scalar rule */
    }
    /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md 1);
     * a 0 tip is a FAIL-OPEN height read and is refused (CHECKTX-P1 r3) */
    if (req->tip == 0 || req->expiry_height <= req->tip ||
        req->expiry_height - req->tip > (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)
        return NODUS_V2_SPEND_ERR_EXPIRY;

    /* ── fee: the floor, raised under HF-1 to units × gas_price ─────── */
    const uint64_t units = NODUS_V2_STAKE_UNITS;
    uint64_t fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                 ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    if (req->gas_price != 0) {
        if (units > UINT64_MAX / req->gas_price) {
            if (err) { err->units = units; err->gas_price = req->gas_price; }
            return NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
        }
        const uint64_t required = units * req->gas_price;
        if (required > fee) fee = required;
    }

    /* ── need = lock + fee (rtn_sys_call_flow: UNSTAKE, UNDELEGATE,
     *    STORAGE_EXIT and VALIDATOR_UPDATE lock 0 — their funding leg pays
     *    the fee only; the same in both generations) ─────────────────── */
    const uint64_t lock = (is_unstake || is_stexit || is_vupd ||
                           op == NODUS_V2_STAKE_OP_UNDELEGATE)
                        ? 0 : req->amount;
    if (lock > UINT64_MAX - fee) {
        if (err) err->fee = fee;
        return NODUS_V2_SPEND_ERR_OVERFLOW;
    }
    const uint64_t need = lock + fee;

    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_coin_t *coins = NULL;
    uint8_t *scall = NULL, *fcall = NULL, *auth0 = NULL, *auth1 = NULL;
    uint8_t *env_bytes = NULL;
    size_t env_len = 0;
    dna_env_preflight_t *pf = NULL;

    /* ── select: native, unlocked, ascending by nullifier, until the sum
     *    covers `need` (the order the database-backed builder's SELECT
     *    used; cmd_v2_stake kept it) ─────────────────────────────────── */
    uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
    int n_in = 0;
    uint64_t sum_in = 0;
    /* HF-8: a non-self legacy DELEGATE funds from at most 14 coins; a
     * generation-4 DELEGATE's funding leg is never gated (above) */
    const int max_in =
        (op == NODUS_V2_STAKE_OP_DELEGATE && !is_role2 &&
         memcmp(req->pk, req->validator_pk, V2K_PK_LEN) != 0)
            ? V2K_DLG_GATED_MAX_IN : (int)NODUS_V2_SPEND_MAX_IN;
    {
        static const uint8_t native_tok[64] = {0};
        int n_coins = 0;
        coins = calloc((size_t)(req->n_coins > 0 ? req->n_coins : 1),
                       sizeof(*coins));
        if (!coins) goto done;
        for (int i = 0; i < req->n_coins; i++) {
            const nodus_v2_stake_coin_t *e = &req->coins[i];
            if (e->amount == 0) continue;
            if (memcmp(e->token, native_tok, 64) != 0) continue; /* non-native */
            if (e->unlock_block > req->tip) continue;            /* locked     */
            memcpy(coins[n_coins].nul, e->nul, 64);
            coins[n_coins].amount = e->amount;
            n_coins++;
        }
        qsort(coins, (size_t)n_coins, sizeof(*coins), nodus_v2_nul_cmp);
        for (int i = 0; i < n_coins && sum_in < need &&
                        n_in < max_in; i++) {
            if (sum_in > UINT64_MAX - coins[i].amount) {
                rc = NODUS_V2_SPEND_ERR_INPUT_SUM;
                goto done;
            }
            memcpy(nulls[n_in], coins[i].nul, 64);
            sum_in += coins[i].amount;
            n_in++;
        }
    }
    if (n_in < 1 || sum_in < need) {
        if (err) {
            err->fee = fee; err->need = need; err->sum_in = sum_in;
            err->n_in = n_in;
        }
        rc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
        goto done;
    }
    const uint64_t change = sum_in - need;

    /* ── leg0 — the SYSTEM record call ─────────────────────────────── */
    /* SHA3-512 of the signing key — or, HF-6 kind-3 owner, of the
     * descriptor (the multisig address, dna_msig_address's derivation):
     * the funding coins' owner and the change owner (leg1); for the
     * generation-4 STAKE / STORAGE_REGISTER / STORAGE_EXIT / UNSTAKE /
     * VALIDATOR_UPDATE also the call's owner_fp (C2 for the last three),
     * for DELEGATE / UNDELEGATE its delegator_fp */
    uint8_t signer_raw[64];
    if ((is_msig ? qgp_sha3_512(req->msig_desc, req->msig_desc_len,
                                signer_raw)
                 : qgp_sha3_512(req->pk, V2K_PK_LEN, signer_raw)) != 0) {
        rc = NODUS_V2_SPEND_ERR_HASH;
        goto done;
    }
    uint32_t scall_len;
    if (is_stake2) {
        /* owner_fp ‖ consensus_pk ‖ consent_sig ‖ expiry u64 ‖ commission
         * u16 ‖ bond u64 (rtn_stake2_parse); owner_fp = SHA3-512 of the
         * signer — the kind-1 owner rule (rtn_sys_owner_auth) */
        scall_len = NODUS_V2_STAKE2_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_S2_OWNER_OFF, signer_raw, 64);
        memcpy(scall + V2K_S2_PK_OFF, req->consensus_pk, V2K_PK_LEN);
        memcpy(scall + V2K_S2_SIG_OFF, req->consent_sig, DNA_VALBIND_SIG_LEN);
        put_u64(scall + V2K_S2_EXP_OFF, req->consent_expiry);
        scall[V2K_S2_COMM_OFF]     = (uint8_t)(req->commission_bps >> 8);
        scall[V2K_S2_COMM_OFF + 1] = (uint8_t)req->commission_bps;
        put_u64(scall + V2K_S2_BOND_OFF, req->amount);
    } else if (is_stake) {
        /* staker_pk ‖ commission u16 ‖ bond u64 ‖ dest_fp[64 RAW] */
        scall_len = NODUS_V2_STAKE_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
        scall[V2K_PK_LEN]     = (uint8_t)(req->commission_bps >> 8);
        scall[V2K_PK_LEN + 1] = (uint8_t)req->commission_bps;
        put_u64(scall + V2K_PK_LEN + 2, req->amount);
        memcpy(scall + V2K_PK_LEN + 10, req->dest_fp, 64);
    } else if (is_streg) {
        /* owner_fp ‖ node_pk ‖ consent_sig ‖ expiry u64 ‖ bond u64
         * (rtn_streg2_parse); owner_fp = SHA3-512 of the signer — the
         * kind-1 owner rule (rtn_sys_owner_auth) */
        scall_len = NODUS_V2_STREG_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_SR_OWNER_OFF, signer_raw, 64);
        memcpy(scall + V2K_SR_PK_OFF, req->consensus_pk, V2K_PK_LEN);
        memcpy(scall + V2K_SR_SIG_OFF, req->consent_sig, DNA_VALBIND_SIG_LEN);
        put_u64(scall + V2K_SR_EXP_OFF, req->consent_expiry);
        put_u64(scall + V2K_SR_BOND_OFF, req->amount);
    } else if (is_stexit) {
        /* node_fp ‖ owner_fp (rtn_stexit2_parse) — the registry key and
         * the owner the signers act for (C2); the chain requires owner_fp
         * == the row's owner */
        scall_len = NODUS_V2_STEXIT_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_SX_NODE_OFF, req->node_fp, 64);
        memcpy(scall + V2K_SX_OWNER_OFF, signer_raw, 64);
    } else if (is_role2 && is_deleg) {
        /* delegator_fp ‖ validator_id ‖ amount u64 — one layout for
         * DELEGATE and UNDELEGATE (rtn_deleg_parse_v2); delegator_fp =
         * SHA3-512 of the signer, the kind-1 rule rtn_delegate2_exec /
         * rtn_undelegate2_exec apply (rtn_sys_owner_auth) */
        scall_len = NODUS_V2_DELEG2_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_D2_DFP_OFF, signer_raw, 64);
        memcpy(scall + V2K_D2_VID_OFF, req->validator_id, 64);
        put_u64(scall + V2K_D2_AMT_OFF, req->amount);
    } else if (is_role2 && is_unstake) {
        /* validator_id ‖ owner_fp (rtn_unstake_parse_v2, C2); the chain
         * requires owner_fp == the ROW's owner_fp (rtn_unstake2_exec) */
        scall_len = NODUS_V2_UNSTAKE2_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_U2_VID_OFF, req->validator_id, 64);
        memcpy(scall + V2K_U2_OWNER_OFF, signer_raw, 64);
    } else if (is_vupd) {
        /* validator_id ‖ owner_fp ‖ commission u16 (rtn_vupd_parse_v2,
         * C2); the chain requires owner_fp == the ROW's owner_fp
         * (rtn_vupd2_exec) */
        scall_len = NODUS_V2_VUPD2_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall + V2K_U2_VID_OFF, req->validator_id, 64);
        memcpy(scall + V2K_U2_OWNER_OFF, signer_raw, 64);
        scall[V2K_U2_COMM_OFF]     = (uint8_t)(req->commission_bps >> 8);
        scall[V2K_U2_COMM_OFF + 1] = (uint8_t)req->commission_bps;
    } else if (is_unstake) {
        /* validator_pk — the signer itself (rtn_sys_stake_auth binds
         * SHA3-512(call) to the signer) */
        scall_len = NODUS_V2_UNSTAKE_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
    } else {
        /* delegator_pk (the signer) ‖ validator_pk ‖ amount u64 — one
         * layout for DELEGATE and UNDELEGATE (rtn_deleg_parse) */
        scall_len = NODUS_V2_DELEG_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
        memcpy(scall + V2K_PK_LEN, req->validator_pk, V2K_PK_LEN);
        put_u64(scall + 2 * V2K_PK_LEN, req->amount);
    }

    /* ── leg1 — the CORE SYSFUND transfer section ──────────────────── */
    char signer_fp[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(signer_raw, signer_fp);

    fcall = calloc(1, 2 + (size_t)NODUS_V2_SPEND_MAX_IN * 64 +
                          NODUS_V2_SPEND_OUT_LEN);
    if (!fcall) goto done;
    size_t off = 0;
    fcall[off++] = (uint8_t)n_in;
    for (int i = 0; i < n_in; i++) { memcpy(fcall + off, nulls[i], 64); off += 64; }
    const uint8_t out_count = change > 0 ? 1 : 0;
    fcall[off++] = out_count;
    uint8_t change_id[64];
    memset(change_id, 0, sizeof(change_id));
    if (out_count) {
        /* deterministic change seed = SHA3-512(input nullifiers)[0..31] —
         * unique per input set, so the derived output id never collides */
        uint8_t seed_full[64];
        if (qgp_sha3_512((const uint8_t *)nulls, (size_t)n_in * 64,
                         seed_full) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        nodus_v2_xfer_out_put(fcall + off, signer_fp, change, NULL /* native */,
                              seed_full);
        uint8_t pre[160];
        memcpy(pre, fcall + off, 128);
        memcpy(pre + 128, seed_full, 32);
        if (qgp_sha3_512(pre, sizeof(pre), change_id) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        off += NODUS_V2_SPEND_OUT_LEN;
    }
    const uint32_t fcall_len = (uint32_t)off;

    /* ── two legs, kind-1 single signer each — or, HF-6 kind-3 owner,
     *    the same unsigned kind-3 blob on each: K zero slots ‖ dcount 1 ‖
     *    dlen u16 BE ‖ descriptor (rtn_auth_msig; the shape of
     *    nodus_v2_msig_unsigned_auth, restated: that file is not linked
     *    where this one is) ─────────────────────────────────────────── */
    const uint8_t akind = is_msig ? NODUS_RT_AUTHKIND_DSA87_MSIG_V1
                                  : NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    const uint32_t alen = is_msig
        ? (uint32_t)(1u + (size_t)req->msig_signers * NODUS_RT_AUTH_SIGNER_LEN +
                     3u + req->msig_desc_len)
        : V2K_AUTH_LEN;
    auth0 = calloc(1, alen);
    auth1 = calloc(1, alen);
    pf    = calloc(1, sizeof(*pf));
    if (!auth0 || !auth1 || !pf) goto done;
    if (is_msig) {
        /* v2k_desc_bounds proved 1 <= K <= DNA_MSIG_MAX_N and dlen <=
         * DNA_MSIG_MAX_DESC_LEN (< 65536) above */
        uint8_t *ab[2] = { auth0, auth1 };
        const size_t toff = 1u + (size_t)req->msig_signers *
                                 NODUS_RT_AUTH_SIGNER_LEN;
        for (int L = 0; L < 2; L++) {
            ab[L][0] = (uint8_t)req->msig_signers;
            ab[L][toff]     = 1;                       /* dcount          */
            ab[L][toff + 1] = (uint8_t)(req->msig_desc_len >> 8);
            ab[L][toff + 2] = (uint8_t)req->msig_desc_len;
            memcpy(ab[L] + toff + 3, req->msig_desc, req->msig_desc_len);
        }
    }

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op           = (uint32_t)op;
    legs[0].hdr.ruleset_version      = req->rs->sys_ruleset_version;
    legs[0].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind            = akind;
    legs[0].hdr.call_len             = scall_len;
    legs[0].hdr.auth_len             = alen;
    legs[0].hdr.res_max_effects      = NODUS_V2_STAKE_SYS_EFFECTS;
    legs[0].hdr.res_max_effect_bytes = NODUS_V2_STAKE_SYS_EFFECT_BYTES;
    legs[0].call_data = scall;
    legs[0].auth_data = auth0;
    legs[1].hdr.domain_id            = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op           = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version      = req->rs->core_ruleset_version;
    legs[1].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind            = akind;
    legs[1].hdr.call_len             = fcall_len;
    legs[1].hdr.auth_len             = alen;
    legs[1].hdr.res_max_effects      = NODUS_V2_STAKE_FUND_EFFECTS;
    legs[1].hdr.res_max_effect_bytes = NODUS_V2_STAKE_FUND_EFFECT_BYTES;
    legs[1].call_data = fcall;
    legs[1].auth_data = auth1;

    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.expiry_height       = req->expiry_height;
    env_in.fee_amount          = fee;
    env_in.res_max_total_units = units;
    env_in.leg_count           = 2;
    env_in.legs                = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id       = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = req->rs->sys_ruleset_version;
    memcpy(lctx[0].ruleset_hash, req->rs->sys_ruleset_hash, 64);
    lctx[1].domain_id       = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = req->rs->core_ruleset_version;
    memcpy(lctx[1].ruleset_hash, req->rs->core_ruleset_hash, 64);

    v2k_rb_t rb;
    memset(&rb, 0, sizeof(rb));
    rb.req          = req;
    rb.op           = op;
    rb.akind        = akind;
    rb.fee          = fee;
    rb.units        = units;
    rb.is_msig      = is_msig;
    rb.is_stake     = is_stake;
    rb.is_stake2    = is_stake2;
    rb.is_unstake   = is_unstake;
    rb.is_stexit    = is_stexit;
    rb.is_vupd      = is_vupd;
    rb.is_role2     = is_role2;
    rb.is_consented = is_consented;
    rb.signer_raw   = signer_raw;
    rb.signer_fp    = signer_fp;
    rb.n_in         = n_in;
    rb.nulls        = (const uint8_t (*)[64])nulls;
    rb.out_count    = out_count;
    rb.change       = change;
    rb.change_id    = change_id;

    if (is_msig) {
        /* HF-6 kind-3 owner: NOTHING is signed here. The unsigned
         * envelope and its pass-1 leg auth digests (what each co-signer
         * signs — the slots and auth_len are fixed, so they do not move
         * when the signatures are written) */
        rc = NODUS_V2_SPEND_ERR_ENCODE;
        if (dna_env_encoded_size(legs, 2, &env_len) != 0) goto done;
        env_bytes = malloc(env_len);
        if (!env_bytes) { rc = NODUS_V2_SPEND_ERR_ALLOC; goto done; }
        size_t used = 0;
        if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
            used != env_len)
            goto done;
        if (dna_env_preflight(env_bytes, env_len, req->chain32, req->tip + 1,
                              lctx, 2, pf) != DNA_ENV_PF_OK) {
            rc = NODUS_V2_SPEND_ERR_PREFLIGHT1;
            goto done;
        }
        memcpy(out->leg_digest[0], pf->auth_digest[0], 64);
        memcpy(out->leg_digest[1], pf->auth_digest[1], 64);
    } else {
        /* one key signs BOTH legs: it is the record identity AND the
         * owner of the funding inputs */
        uint8_t *auths[2] = { auth0, auth1 };
        nodus_v2_spend_err_t se;
        memset(&se, 0, sizeof(se));
        /* "nothing is signed on a mismatch": v2k_readback runs on the
         * unsigned bytes first (a refusal is _ERR_PRESIGN_CHECK) */
        rc = nodus_v2_env_sign_one_key_checked(&env_in, auths, lctx,
                                               req->chain32, req->tip,
                                               req->pk, req->sk, &env_bytes,
                                               &env_len, pf, &se,
                                               v2k_presign_check, &rb);
        if (rc != NODUS_V2_SPEND_OK) {
            if (err) err->leg = se.leg;
            goto done;
        }
    }

    /* ── read back what was BUILT, and refuse if it is not what was
     *    asked ─────────────────────────────────────────────────────── */
    rc = v2k_readback(&rb, env_bytes, env_len, &out->dec);
    if (rc != NODUS_V2_SPEND_OK) goto done;

    /* kind 3: the unsigned envelope's wire_id is not the one that will be
     * submitted — left all zero (msig combine prints the final one); its
     * intent_id is (the intent excludes the auth blobs) */
    if (!is_msig) memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->auth_kind = akind;
    out->fee     = fee;
    out->sum_in  = sum_in;
    out->change  = change;
    out->n_in    = n_in;
    out->env     = env_bytes;
    out->env_len = env_len;
    env_bytes = NULL;
    rc = NODUS_V2_SPEND_OK;

done:
    if (rc != NODUS_V2_SPEND_OK) memset(&out->dec, 0, sizeof(out->dec));
    /* a refused signed buffer and the auth blobs that held its signatures
     * are wiped before they are freed (kind 3: the blob is the unsigned
     * descriptor — wiping it is harmless) */
    if (env_bytes) memset(env_bytes, 0, env_len);
    free(env_bytes);
    free(pf);
    if (auth0) memset(auth0, 0, V2K_AUTH_LEN);
    if (auth1) memset(auth1, 0, V2K_AUTH_LEN);
    free(auth0);
    free(auth1);
    free(fcall);
    free(scall);
    free(coins);
    return rc;
}

/* ── HF-6 6f-1: the node-consent container (format in the header) ──── */

#define V2K_CONSENT_LINES 7

static const char V2K_HEX[] = "0123456789abcdef";

static size_t put_hex(char *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = V2K_HEX[src[i] >> 4];
        dst[2 * i + 1] = V2K_HEX[src[i] & 15];
    }
    return 2 * n;
}

/* lowercase hex digit -> 0..15, anything else -1 */
static int hex_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* exactly 2n lowercase hex chars -> n bytes. @return 0 / -1. */
static int get_hex(const char *s, size_t sl, uint8_t *out, size_t n) {
    if (sl != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        const int hi = hex_nib(s[2 * i]), lo = hex_nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* u64 -> decimal, no leading zeros. @return the digit count (<= 20). */
static size_t put_dec(char *dst, uint64_t v) {
    char tmp[20];
    size_t n = 0;
    do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v != 0);
    for (size_t i = 0; i < n; i++) dst[i] = tmp[n - 1 - i];
    return n;
}

/* the canonical decimal put_dec writes (no sign, no leading zero unless
 * the value is 0, no overflow). @return 0 / -1. */
static int get_dec(const char *s, size_t sl, uint64_t *out) {
    if (sl == 0 || sl > 20 || (sl > 1 && s[0] == '0')) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < sl; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        const uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

/* the codec's op/subject rule (dna_valbind_consent_msg), restated over the
 * container's fields — the codec is not linked here. @return 0 / -1. */
static int consent_op_ok(uint8_t op, const uint8_t subject[64]) {
    const int zero = all_zero(subject, DNA_VALBIND_SUBJECT_LEN);
    if (op == DNA_VALBIND_OP_STAKE)  return zero ? 0 : -1;
    if (op == DNA_VALBIND_OP_STORAGE_REGISTER)   /* HF-6 6b, design §11.3 */
        return zero ? 0 : -1;
    return -1;                           /* no consent op this module
                                          * builds for — op 2 (ROTATE)
                                          * included: no generation has
                                          * the operation (HF-6 D2)      */
}

int nodus_v2_consent_text_encode(const nodus_v2_consent_t *c,
                                 char **text_out, size_t *len_out) {
    if (text_out) *text_out = NULL;
    if (len_out) *len_out = 0;
    if (!c || !text_out || !len_out) return NODUS_V2_SPEND_ERR_ARG;
    if (consent_op_ok(c->op, c->subject) != 0) return NODUS_V2_SPEND_ERR_ARG;
    static const char magic[] = NODUS_V2_CONSENT_MAGIC "\n";
    const size_t cap = (sizeof(magic) - 1) +
                       3 + 1 + 1 +
                       9 + 2 * DNA_VALBIND_CHAIN_LEN + 1 +
                       8 + 2 * DNA_VALBIND_SUBJECT_LEN + 1 +
                       6 + 2 * DNA_VALBIND_OWNER_FP_LEN + 1 +
                       13 + 2 * DNA_VALBIND_PUBKEY_LEN + 1 +
                       7 + 20 + 1 +
                       4 + 2 * DNA_VALBIND_SIG_LEN + 1 + 1;
    char *t = malloc(cap);
    if (!t) return NODUS_V2_SPEND_ERR_ALLOC;
    size_t p = 0;
    memcpy(t + p, magic, sizeof(magic) - 1);      p += sizeof(magic) - 1;
    memcpy(t + p, "op ", 3);                      p += 3;
    t[p++] = (char)('0' + c->op);
    t[p++] = '\n';
    memcpy(t + p, "chain_id ", 9);                p += 9;
    p += put_hex(t + p, c->chain32, DNA_VALBIND_CHAIN_LEN);
    t[p++] = '\n';
    memcpy(t + p, "subject ", 8);                 p += 8;
    p += put_hex(t + p, c->subject, DNA_VALBIND_SUBJECT_LEN);
    t[p++] = '\n';
    memcpy(t + p, "owner ", 6);                   p += 6;
    p += put_hex(t + p, c->owner_fp, DNA_VALBIND_OWNER_FP_LEN);
    t[p++] = '\n';
    memcpy(t + p, "consensus_pk ", 13);           p += 13;
    p += put_hex(t + p, c->consensus_pk, DNA_VALBIND_PUBKEY_LEN);
    t[p++] = '\n';
    memcpy(t + p, "expiry ", 7);                  p += 7;
    p += put_dec(t + p, c->expiry);
    t[p++] = '\n';
    memcpy(t + p, "sig ", 4);                     p += 4;
    p += put_hex(t + p, c->sig, DNA_VALBIND_SIG_LEN);
    t[p++] = '\n';
    t[p] = '\0';
    *text_out = t;
    *len_out = p;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_consent_text_parse(const char *text, size_t len,
                                nodus_v2_consent_t *c) {
    if (!c) return NODUS_V2_SPEND_ERR_ARG;
    memset(c, 0, sizeof(*c));
    if (!text) return NODUS_V2_SPEND_ERR_ARG;
    static const char *const keys[V2K_CONSENT_LINES] = {
        "op", "chain_id", "subject", "owner", "consensus_pk", "expiry", "sig"
    };
    const char *p = text, *const end = text + len;
    const size_t ml = sizeof(NODUS_V2_CONSENT_MAGIC) - 1;
    if (len < ml + 1 || memcmp(p, NODUS_V2_CONSENT_MAGIC, ml) != 0 ||
        p[ml] != '\n')
        goto bad;
    p += ml + 1;
    for (int k = 0; k < V2K_CONSENT_LINES; k++) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) goto bad;
        const size_t kl = strlen(keys[k]);
        if ((size_t)(nl - p) < kl + 1 || memcmp(p, keys[k], kl) != 0 ||
            p[kl] != ' ')
            goto bad;
        const char *val = p + kl + 1;
        const size_t vl = (size_t)(nl - val);
        int r;
        switch (k) {
        case 0: {
            uint64_t op = 0;
            r = get_dec(val, vl, &op);
            if (r == 0 && op > 255) r = -1;
            c->op = (uint8_t)op;
            break;
        }
        case 1: r = get_hex(val, vl, c->chain32, DNA_VALBIND_CHAIN_LEN); break;
        case 2: r = get_hex(val, vl, c->subject, DNA_VALBIND_SUBJECT_LEN); break;
        case 3: r = get_hex(val, vl, c->owner_fp, DNA_VALBIND_OWNER_FP_LEN); break;
        case 4: r = get_hex(val, vl, c->consensus_pk, DNA_VALBIND_PUBKEY_LEN); break;
        case 5: r = get_dec(val, vl, &c->expiry); break;
        default: r = get_hex(val, vl, c->sig, DNA_VALBIND_SIG_LEN); break;
        }
        if (r != 0) goto bad;
        p = nl + 1;
    }
    if (p != end) goto bad;                      /* nothing after the sig */
    if (consent_op_ok(c->op, c->subject) != 0) goto bad;
    return NODUS_V2_SPEND_OK;
bad:
    memset(c, 0, sizeof(*c));
    return NODUS_V2_SPEND_ERR_DECODE;
}
