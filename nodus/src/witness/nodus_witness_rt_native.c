/**
 * @file nodus_witness_rt_native.c
 * @brief Ledger V2 — native authorization + the first PRODUCTION
 *        SYSTEM/DNA_CORE runtime vertical slices (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. The compiled production
 * runtime table (nodus_witness_runtime.c) binds these hooks; only the
 * (still inactive) V2 apply engine invokes them, and only tests drive
 * that engine. Types 11/12/13 stay REJECT-unconditional and type 14
 * stays unassigned — nothing in this file touches shielded state.
 * ════════════════════════════════════════════════════════════════════════
 *
 * WHAT IS IMPLEMENTED (exactly two source-existing operations):
 *
 *   1. SYSTEM  / DNA_SYSRULE_CHAIN_CONFIG (runtime_op 6, legacy tx 10):
 *      the committee-voted consensus-parameter change. The SOURCE
 *      authority is preserved: quorum = dna_bft_quorum(committee at the
 *      signing height H-1), votes are ML-DSA-87 signatures over the ONE
 *      shipped proposal digest (nodus_chain_config_compute_digest),
 *      scalar rules / grace tiers come from the SAME exported helpers
 *      the legacy apply consumes (nodus_chain_config_scalar_rules /
 *      nodus_chain_config_grace_for_param), freshness and the
 *      INFLATION_START monotonicity rule are mirrored 1:1 from
 *      nodus_chain_config_apply (nodus_witness_chain_config.c:903).
 *
 *   2. DNA_CORE / DNA_CORERULE_SPEND (runtime_op 1, legacy tx 1): the
 *      canonical transparent DNAC UTXO transfer. Source semantics
 *      preserved: inputs exist+unspent (utxo_set row present), lock rule
 *      (unlock_block >= H rejects — the legacy "unlock > tip" gate,
 *      nodus_witness_verify.c:731), ownership = UTXO owner fingerprint
 *      is one of the VERIFIED signers (verify.c:740-751), output
 *      identity = SHA3-512(owner_fp_128 ‖ seed_32) (the shipped
 *      update_utxo_set derivation, nodus_witness_bft.c:852-860), fee =
 *      Σnative_in − Σnative_out, must equal the envelope's committed
 *      fee_amount and satisfy BOTH shipped floors (DNAC_MIN_FEE_RAW,
 *      verify.c:540; NODUS_W_BASE_TX_FEE, verify.c:833 — equal today,
 *      enforced as a conjunction so neither can silently drift), and the
 *      fee is BURNED exactly once into supply_tracking.total_burned
 *      (route_tx_fee → nodus_witness_supply_add_burned semantics).
 *
 * Every OTHER runtime_op the two descriptors own is a DETERMINISTIC
 * REJECT in these hooks until its own migration slice — ownership is
 * expressible, execution is fail-closed.
 *
 * ── The verified authorization boundary ───────────────────────────────
 * nodus_rt_auth_dsa87_v1 is the ONE compiled implementation of
 * auth_kind 1 (both production entries bind the same symbol — scheme
 * verification cannot fork per domain). It verifies every signature
 * against the ENGINE-derived leg auth_digest, which commits — through
 * auth_context_commit (env_wire.h) — the chain identity, expiry, fee,
 * resource ceilings, and every leg's domain / runtime_op / ruleset
 * identity / call bytes. Changing ANY of them invalidates every
 * signature; the signature bytes themselves are covered only by tx_id
 * (non-circularity). The verdict is ENGINE-owned: the caller cannot
 * supply one (no envelope field exists), the runtime cannot declare one
 * (exec only READS ctx->auth), and authorization work is priced once by
 * w_authbyte at reservation (no second charge anywhere).
 *
 * ── Canonical call_data encodings (JUDGMENT, independently tested) ────
 * The envelope framing layer treats call_data as opaque; the layouts
 * below are THIS release's canonical operation encodings, built by the
 * repository's standard conventions (fixed-width big-endian, exact
 * lengths, strictly ascending iteration, fail-closed decode).
 *
 * SPEND call v1 (exact length = 2 + 64*in + 232*out):
 *   in_count  u8   1..15   ── 15, not the legacy 16: the read budget is
 *                             NODUS_RT_MAX_READS(16) = 15 input reads +
 *                             1 supply read (honest narrowing, labeled)
 *   in_count × nullifier[64]              STRICTLY ascending
 *   out_count u8   1..16   (NODUS_T3_MAX_TX_OUTPUTS)
 *   out_count × ( owner_fp[128]           lowercase hex, exactly 128
 *               ‖ amount u64 BE
 *               ‖ token_id[64]            all-zero = native DNAC
 *               ‖ seed[32] )
 *
 * CHAIN_CONFIG call v1 (exact length = 42 + 7219*votes):
 *   param_id u8 ‖ new_value u64 ‖ effective u64 ‖ nonce u64
 *   ‖ signed_at u64 ‖ valid_before u64 ‖ vote_count u8 (5..8)
 *   ‖ vote_count × ( pubkey[2592] ‖ signature[4627] )
 *   Votes carry the FULL pubkey (the legacy cc wire carries witness_id
 *   and resolves pubkeys from the committee snapshot; here membership
 *   is checked against the mediated committee witness-id read and the
 *   signature against the carried pubkey — same authority, one read).
 *   The vote cap 8 is the envelope-ceiling fit (DNA_ENV_MAX_TOTAL_LEN);
 *   with quorum floor 5 the 7-seat devnet committee is fully covered;
 *   committees needing quorum > 8 are NOT expressible on envelope v1
 *   (honest label — a versioned envelope change, not a silent cap).
 *
 * ── Honest divergences from the legacy lane (all fail-closed) ─────────
 *   - PER-TOKEN conservation: Σin == Σout per non-native token and
 *     Σnative_in == Σnative_out + fee. The legacy verify sums tokens
 *     blindly (verify.c:753-758 / 792); the block-level supply gate is
 *     what caught native imbalance there. Here no value can be created
 *     or destroyed per token, at the transaction boundary.
 *   - NO spent-nullifier audit insert: V2 replay protection is the
 *     UTXO row itself (spend deletes it; re-spend = missing input) plus
 *     the engine's derived-id replay matrix. The legacy `nullifiers`
 *     table stays a legacy-lane structure.
 *   - Duplicate output identity REJECTS (legacy utxo_add dropped the
 *     row silently); an output whose identity equals a still-live row
 *     (including one of this leg's own inputs) rejects via the
 *     CREATE/ABSENT precondition — canonical order applies CREATEs
 *     before DELETEs.
 *   - created_at / created_at_unix are written 0: deterministic lane,
 *     no wall clock (both columns are audit-only — neither enters the
 *     UTXO merkle leaf (nodus_witness_merkle.c:136) nor the
 *     chain-config leaf (nodus_witness_chain_config.c:389)).
 *   - supply_tracking.last_tx_hash is left unchanged (audit column;
 *     the typed effect carries no side-band audit payload).
 *   - a SYSTEM CHAIN_CONFIG leg requires envelope fee_amount == 0:
 *     the legacy lane funds its fee from CORE inputs inside the same
 *     transaction; a single-leg SYSTEM envelope has no funding leg, and
 *     inventing a SYSTEM fee sink would be inventing economics. The
 *     cross-domain fee leg is a later season.
 *
 * ── Purity ────────────────────────────────────────────────────────────
 * The auth/read_plan/exec hooks touch NO database, NO clock, NO RNG and
 * allocate NOTHING (a hook has no node-fault-free failure channel for
 * allocation; -2 is reserved for hash/crypto backend failure). The
 * compiled adapters at the bottom are the ONLY storage-touching code,
 * reached exclusively through the engine's mediated read / validated
 * effect paths, always scoped by the resolved runtime's own domain id.
 *
 * @file nodus_witness_rt_native.c
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_committee.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"                 /* DNAC_MIN_FEE_RAW, DNAC_CFG_*   */
#include "dnac/ledger_ids.h"           /* dna_bft_quorum                 */
#include "dnac/chain_config_wire.h"    /* DNAC_CC_WIRE_MIN_SIGS          */
#include "dnac/effect_wire.h"
#include "dnac/res_meter.h"            /* dna_ck_add_u64                 */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h" /* qgp_dsa87_verify               */

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

/* ── Local wire helpers (BE, the shared/dnac discipline) ────────────── */
static uint64_t rtn_get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void rtn_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void rtn_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ══════════════════════════════════════════════════════════════════════
 * The shared auth_kind-1 implementation (contract: runtime.h)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_rt_auth_dsa87_v1(const nodus_domain_runtime_t *rt,
                           const dna_env_view_t *env, uint16_t leg_index,
                           const nodus_rt_exec_ctx_t *ctx,
                           nodus_rt_auth_verdict_t *out) {
    (void)rt;
    if (!env || !ctx || !ctx->leg_auth_digest || !out) return -2;
    memset(out, 0, sizeof(*out));
    if (leg_index >= env->leg_count || !env->buf) return -2;

    const dna_env_leg_hdr_t *h = &env->leg[leg_index];
    if (h->auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1)
        return -1;                       /* unsupported scheme: reject   */

    const uint8_t *a = env->buf + env->auth_off[leg_index];
    uint32_t alen = h->auth_len;
    if (alen < 1) return -1;
    uint32_t n = a[0];
    if (n < 1 || n > NODUS_RT_AUTH_MAX_SIGNERS) return -1;
    if (alen != 1u + n * NODUS_RT_AUTH_SIGNER_LEN) return -1;

    const uint8_t *prev_pk = NULL;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *pk  = a + 1 + (size_t)i * NODUS_RT_AUTH_SIGNER_LEN;
        const uint8_t *sig = pk + NODUS_CC_PUBKEY_SIZE;
        /* zero-pubkey reject (the verify.c:657 discipline) */
        int allz = 1;
        for (int k = 0; k < 32 && allz; k++)
            if (pk[k] != 0) allz = 0;
        if (allz) { memset(out, 0, sizeof(*out)); return -1; }
        /* strictly ascending pubkeys: ONE canonical encoding per signer
         * set — duplicates and disorder both reject */
        if (prev_pk && memcmp(prev_pk, pk, NODUS_CC_PUBKEY_SIZE) >= 0) {
            memset(out, 0, sizeof(*out));
            return -1;
        }
        prev_pk = pk;
        if (qgp_dsa87_verify(sig, NODUS_CC_SIG_SIZE,
                             ctx->leg_auth_digest, 64, pk) != 0) {
            memset(out, 0, sizeof(*out));
            return -1;                   /* invalid signature: reject    */
        }
        if (qgp_sha3_512(pk, NODUS_CC_PUBKEY_SIZE,
                         out->signer_fp[i]) != 0) {
            memset(out, 0, sizeof(*out));
            return -2;                   /* hash backend: NODE fault     */
        }
    }
    out->n_signers = (uint16_t)n;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * DNA_CORE — DNA_CORERULE_SPEND
 * ════════════════════════════════════════════════════════════════════ */

/* Compiled CORE adapter op ids (this adapter's own namespace). */
#define RTN_CORE_OP_UTXO    1u   /* CREATE + mediated read: utxo_set row */
#define RTN_CORE_OP_UTXDEL  2u   /* DELETE: utxo_set row                 */
#define RTN_CORE_OP_SUPPLY  3u   /* SET + mediated read: burned counter  */

/* The canonical UTXO record value (exact 284 bytes):
 *   [0..127]   owner fingerprint, exactly 128 lowercase-hex chars
 *   [128..135] amount        u64 BE
 *   [136..199] token_id      64 B (all-zero = native DNAC)
 *   [200..263] tx_hash       64 B (V2: the engine-derived tx_id)
 *   [264..267] output_index  u32 BE
 *   [268..275] block_height  u64 BE
 *   [276..283] unlock_block  u64 BE
 * Exactly the utxo_set columns the UTXO merkle leaf consumes
 * (nullifier ‖ owner ‖ amount ‖ token_id ‖ tx_hash ‖ output_index —
 * nodus_witness_merkle.c:136) plus the two spendability/provenance
 * columns; created_at is deliberately excluded (wall-clock audit). */
#define RTN_UTXO_REC_LEN      284u
#define RTN_UTXO_OWNER_OFF    0u
#define RTN_UTXO_AMOUNT_OFF   128u
#define RTN_UTXO_TOKEN_OFF    136u
#define RTN_UTXO_TXH_OFF      200u
#define RTN_UTXO_OIDX_OFF     264u
#define RTN_UTXO_BH_OFF       268u
#define RTN_UTXO_UNLOCK_OFF   276u

/* The supply selector key: byte 2 = total_burned (the ONE counter this
 * slice consumes; selector 1 = total_minted is reserved, unimplemented). */
#define RTN_SUPPLY_SEL_BURNED 2u

/* SPEND call v1 bounds (header block above). */
#define RTN_SPEND_MAX_IN      15u  /* NODUS_RT_MAX_READS - 1 supply read */
#define RTN_SPEND_MAX_OUT     16u  /* NODUS_T3_MAX_TX_OUTPUTS            */
#define RTN_SPEND_OUT_LEN     232u /* fp128 + amount8 + token64 + seed32 */

typedef struct {
    uint8_t        in_count;
    uint8_t        out_count;
    const uint8_t *ins;      /* in_count  × 64                          */
    const uint8_t *outs;     /* out_count × RTN_SPEND_OUT_LEN           */
} rtn_spend_call_t;

static int rtn_hex_lower_ok(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* Strict SPEND call parse — the ONE decoder both hooks consume.
 * @return 0 / -1 (deterministic reject). */
static int rtn_spend_parse(const dna_env_view_t *env, uint16_t leg,
                           rtn_spend_call_t *c) {
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    if (len < 2) return -1;
    uint8_t ic = p[0];
    if (ic < 1 || ic > RTN_SPEND_MAX_IN) return -1;
    size_t off = 1 + (size_t)ic * 64u;
    if (len < off + 1) return -1;
    uint8_t oc = p[off];
    if (oc < 1 || oc > RTN_SPEND_MAX_OUT) return -1;
    if ((size_t)len != off + 1 + (size_t)oc * RTN_SPEND_OUT_LEN)
        return -1;                       /* exact length, never a prefix */
    c->in_count = ic;
    c->out_count = oc;
    c->ins = p + 1;
    c->outs = p + off + 1;
    /* inputs strictly ascending (canonical form + free dedup) */
    for (uint8_t i = 1; i < ic; i++)
        if (memcmp(c->ins + (size_t)(i - 1) * 64,
                   c->ins + (size_t)i * 64, 64) >= 0)
            return -1;
    /* outputs: exactly-128 lowercase-hex owner fingerprints, and a
     * non-zero amount — the transparent-leg §6 rule (tx_wire.h:
     * `amount u64 BE ≥1`): a zero-value output names dust the ledger
     * would carry forever (R2/R4 review convergence; the legacy lane
     * had no floor — honest, fail-closed divergence) */
    for (uint8_t o = 0; o < oc; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (!rtn_hex_lower_ok(rec, 128)) return -1;
        if (rtn_get64(rec + 128) == 0) return -1;
    }
    return 0;
}

int nodus_rt_core_read_plan(const nodus_domain_runtime_t *rt,
                            const dna_env_view_t *env, uint16_t leg_index,
                            const nodus_rt_exec_ctx_t *ctx,
                            nodus_rt_read_req_t *reqs_out,
                            uint16_t max_reqs, uint16_t *n_out) {
    (void)rt;
    if (!env || !ctx || !reqs_out || !n_out) return -2;
    if (leg_index >= env->leg_count) return -2;
    if (env->leg[leg_index].runtime_op != DNA_CORERULE_SPEND)
        return -1;                       /* un-migrated op: fail closed  */
    rtn_spend_call_t c;
    if (rtn_spend_parse(env, leg_index, &c) != 0) return -1;
    uint16_t need = (uint16_t)(c.in_count + 1);
    if (need > max_reqs) return -1;
    for (uint8_t i = 0; i < c.in_count; i++) {
        memset(&reqs_out[i], 0, sizeof(reqs_out[i]));
        reqs_out[i].op_id = RTN_CORE_OP_UTXO;
        reqs_out[i].key_len = 64;
        memcpy(reqs_out[i].key, c.ins + (size_t)i * 64, 64);
    }
    memset(&reqs_out[c.in_count], 0, sizeof(reqs_out[0]));
    reqs_out[c.in_count].op_id = RTN_CORE_OP_SUPPLY;
    reqs_out[c.in_count].key_len = 1;
    reqs_out[c.in_count].key[0] = RTN_SUPPLY_SEL_BURNED;
    *n_out = need;
    return 0;
}

/* One (token_id → in/out sums) accumulator slot. */
typedef struct {
    const uint8_t *token;                /* borrowed 64-byte id          */
    uint64_t in_sum, out_sum;
} rtn_tok_sum_t;

static int rtn_tok_add(rtn_tok_sum_t *t, size_t *n, size_t cap,
                       const uint8_t *token, uint64_t amount, int is_in) {
    for (size_t i = 0; i < *n; i++) {
        if (memcmp(t[i].token, token, 64) == 0) {
            uint64_t *s = is_in ? &t[i].in_sum : &t[i].out_sum;
            uint64_t nv;
            if (dna_ck_add_u64(*s, amount, &nv) != 0) return -1;
            *s = nv;
            return 0;
        }
    }
    if (*n >= cap) return -1;
    t[*n].token = token;
    t[*n].in_sum = is_in ? amount : 0;
    t[*n].out_sum = is_in ? 0 : amount;
    (*n)++;
    return 0;
}

int nodus_rt_core_exec(const nodus_domain_runtime_t *rt,
                       const dna_env_view_t *env, uint16_t leg_index,
                       const nodus_rt_exec_ctx_t *ctx,
                       const nodus_rt_read_res_t *reads, uint16_t n_reads,
                       uint8_t *res_out, size_t res_cap,
                       size_t *res_len_out) {
    (void)rt;
    if (!env || !ctx || !ctx->tx_id || !res_out || !res_len_out) return -2;
    if (leg_index >= env->leg_count) return -2;
    if (env->leg[leg_index].runtime_op != DNA_CORERULE_SPEND) return -1;

    rtn_spend_call_t c;
    if (rtn_spend_parse(env, leg_index, &c) != 0) return -1;

    /* The ENGINE-verified authorization verdict is the ONLY ownership
     * authority. A commitment without a verdict never reaches here —
     * the engine refuses to execute an unverified leg — and this hook
     * additionally fails closed on a missing/empty verdict. */
    if (!ctx->auth || ctx->auth->n_signers < 1 ||
        ctx->auth->n_signers > NODUS_RT_AUTH_MAX_SIGNERS)
        return -1;
    if (!reads || n_reads != (uint16_t)(c.in_count + 1)) return -2;

    /* lowercase-hex fingerprints of the VERIFIED signers */
    static const char hexd[] = "0123456789abcdef";
    uint8_t sfp[NODUS_RT_AUTH_MAX_SIGNERS][128];
    for (uint16_t s = 0; s < ctx->auth->n_signers; s++)
        for (int b = 0; b < 64; b++) {
            sfp[s][2 * b]     = (uint8_t)hexd[ctx->auth->signer_fp[s][b] >> 4];
            sfp[s][2 * b + 1] = (uint8_t)hexd[ctx->auth->signer_fp[s][b] & 0xF];
        }

    static const uint8_t native_token[64] = { 0 };
    rtn_tok_sum_t toks[RTN_SPEND_MAX_IN + RTN_SPEND_MAX_OUT + 1];
    size_t n_toks = 0;
    memset(toks, 0, sizeof(toks));
    /* seed the native slot so a token-only flow still faces the native
     * fee equation below */
    toks[0].token = native_token;
    n_toks = 1;

    /* ── inputs: exist, unlocked, OWNED BY A VERIFIED SIGNER ────────── */
    for (uint8_t i = 0; i < c.in_count; i++) {
        const nodus_rt_read_res_t *r = &reads[i];
        if (!r->present) return -1;      /* missing OR already spent     */
        if (r->value_len != RTN_UTXO_REC_LEN) return -2;   /* own adapter
                                          * out of contract: node fault  */
        const uint8_t *rec = r->value;
        uint64_t unlock = rtn_get64(rec + RTN_UTXO_UNLOCK_OFF);
        if (unlock >= ctx->global_height) return -1;   /* locked (the
                                          * legacy unlock > tip gate)    */
        int owned = 0;
        for (uint16_t s = 0; s < ctx->auth->n_signers && !owned; s++)
            if (memcmp(rec + RTN_UTXO_OWNER_OFF, sfp[s], 128) == 0)
                owned = 1;
        if (!owned) return -1;           /* wrong owner                  */
        if (rtn_tok_add(toks, &n_toks,
                        sizeof(toks) / sizeof(toks[0]),
                        rec + RTN_UTXO_TOKEN_OFF,
                        rtn_get64(rec + RTN_UTXO_AMOUNT_OFF), 1) != 0)
            return -1;                   /* checked-add overflow         */
    }

    /* ── outputs ────────────────────────────────────────────────────── */
    for (uint8_t o = 0; o < c.out_count; o++) {
        const uint8_t *rec = c.outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (rtn_tok_add(toks, &n_toks,
                        sizeof(toks) / sizeof(toks[0]),
                        rec + 136, rtn_get64(rec + 128), 0) != 0)
            return -1;
    }

    /* ── conservation: native pays the fee, every token balances ────── */
    uint64_t fee = env->fee_amount;
    if (fee < DNAC_MIN_FEE_RAW || fee < NODUS_W_BASE_TX_FEE)
        return -1;                       /* BOTH shipped floors          */
    for (size_t t = 0; t < n_toks; t++) {
        if (memcmp(toks[t].token, native_token, 64) == 0) {
            uint64_t need;
            if (dna_ck_add_u64(toks[t].out_sum, fee, &need) != 0)
                return -1;
            if (toks[t].in_sum != need) return -1;   /* value mismatch /
                                          * fee != committed declaration */
        } else {
            if (toks[t].in_sum != toks[t].out_sum) return -1;
        }
    }

    /* ── deterministic output identities + duplicate reject ─────────── */
    uint8_t nul[RTN_SPEND_MAX_OUT][64];
    uint8_t sorted[RTN_SPEND_MAX_OUT];   /* output index, sorted by nul  */
    for (uint8_t o = 0; o < c.out_count; o++) {
        uint8_t pre[160];
        const uint8_t *rec = c.outs + (size_t)o * RTN_SPEND_OUT_LEN;
        memcpy(pre, rec, 128);                       /* fp (128 hex)     */
        memcpy(pre + 128, rec + 200, 32);            /* seed             */
        if (qgp_sha3_512(pre, sizeof(pre), nul[o]) != 0) return -2;
        sorted[o] = o;
    }
    for (uint8_t a = 1; a < c.out_count; a++) {      /* insertion sort   */
        uint8_t key = sorted[a];
        int b = a - 1;
        while (b >= 0 && memcmp(nul[sorted[b]], nul[key], 64) > 0) {
            sorted[b + 1] = sorted[b];
            b--;
        }
        sorted[b + 1] = key;
    }
    for (uint8_t a = 1; a < c.out_count; a++)
        if (memcmp(nul[sorted[a - 1]], nul[sorted[a]], 64) == 0)
            return -1;                   /* duplicate output identity    */

    /* ── canonical typed-effect result ──────────────────────────────── */
    dna_effect_in_t effs[RTN_SPEND_MAX_OUT + 1 + RTN_SPEND_MAX_IN];
    uint8_t crv[RTN_SPEND_MAX_OUT][RTN_UTXO_REC_LEN];
    uint8_t dvh[RTN_SPEND_MAX_IN][64];
    uint8_t supv[8];
    uint16_t ne = 0;
    memset(effs, 0, sizeof(effs));

    /* CREATEs first (kind 1), keys ascending */
    for (uint8_t a = 0; a < c.out_count; a++) {
        uint8_t o = sorted[a];
        const uint8_t *rec = c.outs + (size_t)o * RTN_SPEND_OUT_LEN;
        uint8_t *v = crv[a];
        memcpy(v + RTN_UTXO_OWNER_OFF, rec, 128);
        memcpy(v + RTN_UTXO_AMOUNT_OFF, rec + 128, 8);   /* already BE   */
        memcpy(v + RTN_UTXO_TOKEN_OFF, rec + 136, 64);
        memcpy(v + RTN_UTXO_TXH_OFF, ctx->tx_id, 64);
        rtn_put32(v + RTN_UTXO_OIDX_OFF, (uint32_t)o);
        rtn_put64(v + RTN_UTXO_BH_OFF, ctx->global_height);
        rtn_put64(v + RTN_UTXO_UNLOCK_OFF, 0);           /* legacy: all
                                          * non-UNSTAKE outputs unlocked */
        effs[ne].hdr.op_id = RTN_CORE_OP_UTXO;
        effs[ne].hdr.effect_kind = DNA_EFFECT_CREATE;
        effs[ne].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
        effs[ne].hdr.key_len = 64;
        effs[ne].hdr.value_len = RTN_UTXO_REC_LEN;
        effs[ne].key = nul[o];
        effs[ne].value = v;
        ne++;
    }
    /* the ONE burn (kind 2), bound to the observed pre-state counter */
    {
        const nodus_rt_read_res_t *r = &reads[c.in_count];
        if (!r->present) return -1;      /* no supply row: unfunded chain*/
        if (r->value_len != 8) return -2;
        uint64_t burned_old = rtn_get64(r->value);
        uint64_t burned_new;
        if (dna_ck_add_u64(burned_old, fee, &burned_new) != 0) return -1;
        rtn_put64(supv, burned_new);
        effs[ne].hdr.op_id = RTN_CORE_OP_SUPPLY;
        effs[ne].hdr.effect_kind = DNA_EFFECT_SET;
        effs[ne].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VERSION;
        effs[ne].hdr.expected_version = burned_old;
        effs[ne].hdr.key_len = 1;
        effs[ne].hdr.value_len = 8;
        effs[ne].key = (const uint8_t *)"\x02";
        effs[ne].value = supv;
        ne++;
    }
    /* DELETEs last (kind 3), keys ascending (= input order), each bound
     * by EXISTS_VHASH to the exact record the mediated read observed —
     * the read and the mutation cannot disagree about the row */
    for (uint8_t i = 0; i < c.in_count; i++) {
        if (dna_effect_value_hash(reads[i].value, RTN_UTXO_REC_LEN,
                                  dvh[i]) != 0)
            return -2;
        effs[ne].hdr.op_id = RTN_CORE_OP_UTXDEL;
        effs[ne].hdr.effect_kind = DNA_EFFECT_DELETE;
        effs[ne].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VHASH;
        memcpy(effs[ne].hdr.expected_vhash, dvh[i], 64);
        effs[ne].hdr.key_len = 64;
        effs[ne].hdr.value_len = 0;
        effs[ne].key = c.ins + (size_t)i * 64;
        effs[ne].value = NULL;
        ne++;
    }

    if (dna_effect_result_encode(effs, ne, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;                       /* unreachable for a leg this
                                          * function built: node fault   */
    return 0;
}

/* ── The compiled CORE storage adapter ──────────────────────────────── */

/* Build the canonical 284-byte record from one utxo_set row statement
 * positioned on a row (columns: owner, amount, token_id, tx_hash,
 * output_index, block_height, unlock_block). @return 0 / -1 malformed. */
static int rtn_core_row_record(sqlite3_stmt *st, uint8_t rec[RTN_UTXO_REC_LEN]) {
    const unsigned char *owner = sqlite3_column_text(st, 0);
    const uint8_t *token = sqlite3_column_blob(st, 2);
    const uint8_t *txh = sqlite3_column_blob(st, 3);
    if (!owner || strlen((const char *)owner) != 128) return -1;
    if (!token || sqlite3_column_bytes(st, 2) != 64) return -1;
    if (!txh || sqlite3_column_bytes(st, 3) != 64) return -1;
    /* a NEGATIVE stored integer is a malformed row: surfacing it as a
     * huge u64 would be a silent value (the "DB failure is never a
     * value" rule) — fail closed instead (R4 review) */
    sqlite3_int64 amount = sqlite3_column_int64(st, 1);
    sqlite3_int64 oidx   = sqlite3_column_int64(st, 4);
    sqlite3_int64 bh     = sqlite3_column_int64(st, 5);
    sqlite3_int64 unlock = sqlite3_column_int64(st, 6);
    if (amount < 0 || oidx < 0 || oidx > (sqlite3_int64)UINT32_MAX ||
        bh < 0 || unlock < 0)
        return -1;
    memcpy(rec + RTN_UTXO_OWNER_OFF, owner, 128);
    rtn_put64(rec + RTN_UTXO_AMOUNT_OFF, (uint64_t)amount);
    memcpy(rec + RTN_UTXO_TOKEN_OFF, token, 64);
    memcpy(rec + RTN_UTXO_TXH_OFF, txh, 64);
    rtn_put32(rec + RTN_UTXO_OIDX_OFF, (uint32_t)oidx);
    rtn_put64(rec + RTN_UTXO_BH_OFF, (uint64_t)bh);
    rtn_put64(rec + RTN_UTXO_UNLOCK_OFF, (uint64_t)unlock);
    return 0;
}

/* 0 = record built, 1 = absent, -1 = fault. */
static int rtn_core_utxo_fetch(nodus_witness_t *w, uint32_t dom,
                               const uint8_t *key, uint16_t key_len,
                               uint8_t rec[RTN_UTXO_REC_LEN]) {
    if (key_len != 64) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, amount, token_id, tx_hash, output_index, "
            "block_height, unlock_block FROM utxo_set "
            "WHERE nullifier = ?1 AND domain_id = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    int rc = sqlite3_step(st);
    int out;
    if (rc == SQLITE_ROW)
        out = rtn_core_row_record(st, rec) == 0 ? 0 : -1;
    else
        out = rc == SQLITE_DONE ? 1 : -1;
    sqlite3_finalize(st);
    return out;
}

/* 0 = value fetched, 1 = absent, -1 = fault. */
static int rtn_core_burned_fetch(nodus_witness_t *w, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT total_burned FROM supply_tracking WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (v < 0) return -1;
        *out = (uint64_t)v;
        return 0;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : -1;
}

static nodus_adapter_status_t rtn_core_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (op->op_id == RTN_CORE_OP_UTXO || op->op_id == RTN_CORE_OP_UTXDEL) {
        uint8_t rec[RTN_UTXO_REC_LEN];
        int rc = rtn_core_utxo_fetch(w, dom, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(rec + RTN_UTXO_AMOUNT_OFF);
            if (dna_effect_value_hash(rec, RTN_UTXO_REC_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_SUPPLY) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint64_t v = 0;
        int rc = rtn_core_burned_fetch(w, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            uint8_t vb[8];
            rtn_put64(vb, v);
            f->version = v;
            if (dna_effect_value_hash(vb, 8, f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t rtn_core_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    *present = 0;
    *vlen = 0;
    if (op->op_id == RTN_CORE_OP_UTXO || op->op_id == RTN_CORE_OP_UTXDEL) {
        uint8_t rec[RTN_UTXO_REC_LEN];
        int rc = rtn_core_utxo_fetch(w, dom, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < RTN_UTXO_REC_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, rec, RTN_UTXO_REC_LEN);
        *present = 1;
        *vlen = RTN_UTXO_REC_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_SUPPLY) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint64_t v = 0;
        int rc = rtn_core_burned_fetch(w, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        rtn_put64(value, v);
        *present = 1;
        *vlen = 8;
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t rtn_core_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (op->op_id == RTN_CORE_OP_UTXO && kind == DNA_EFFECT_CREATE) {
        if (key_len != 64 || value_len != RTN_UTXO_REC_LEN || !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO utxo_set (nullifier, owner, amount, "
                "token_id, tx_hash, output_index, block_height, "
                "created_at, unlock_block, domain_id) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, (const char *)(value + RTN_UTXO_OWNER_OFF),
                          128, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_AMOUNT_OFF));
        sqlite3_bind_blob(st, 4, value + RTN_UTXO_TOKEN_OFF, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, value + RTN_UTXO_TXH_OFF, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(
            ((uint32_t)value[RTN_UTXO_OIDX_OFF] << 24) |
            ((uint32_t)value[RTN_UTXO_OIDX_OFF + 1] << 16) |
            ((uint32_t)value[RTN_UTXO_OIDX_OFF + 2] << 8) |
            (uint32_t)value[RTN_UTXO_OIDX_OFF + 3]));
        sqlite3_bind_int64(st, 7,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_BH_OFF));
        sqlite3_bind_int64(st, 8,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_UNLOCK_OFF));
        sqlite3_bind_int64(st, 9, (sqlite3_int64)dom);
    } else if (op->op_id == RTN_CORE_OP_UTXDEL &&
               kind == DNA_EFFECT_DELETE) {
        if (key_len != 64) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM utxo_set WHERE nullifier = ?1 AND "
                "domain_id = ?2", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    } else if (op->op_id == RTN_CORE_OP_SUPPLY &&
               kind == DNA_EFFECT_SET) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED ||
            value_len != 8 || !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        /* absolute new counter; current_supply kept coherent by the
         * same derivation the legacy burn maintains (genesis + minted
         * − burned); last_tx_hash is audit-only and stays unchanged */
        if (sqlite3_prepare_v2(w->db,
                "UPDATE supply_tracking SET total_burned = ?1, "
                "current_supply = genesis_supply + total_minted - ?1, "
                "last_sequence = last_sequence + 1 WHERE id = 1",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)rtn_get64(value));
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (sqlite3_changes(w->db) != 1)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    return NODUS_ADAPTER_OK;
}

static const nodus_adapter_op_t RTN_CORE_OPS[3] = {
    { RTN_CORE_OP_UTXO,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
      64, 64, RTN_UTXO_REC_LEN, RTN_UTXO_REC_LEN },
    { RTN_CORE_OP_UTXDEL,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VHASH)),
      64, 64, 0, 0 },
    { RTN_CORE_OP_SUPPLY,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION)),
      1, 1, 8, 8 }
};

const nodus_domain_adapter_t NODUS_RT_CORE_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = RTN_CORE_OPS,
    .n_ops = 3,
    .probe = rtn_core_probe,
    .mutate = rtn_core_mutate,
    .read = rtn_core_read
};

/* ══════════════════════════════════════════════════════════════════════
 * SYSTEM — DNA_SYSRULE_CHAIN_CONFIG
 * ════════════════════════════════════════════════════════════════════ */

#define RTN_SYS_OP_CC        1u  /* CREATE: chain_config_history row     */
#define RTN_SYS_OP_COMMITTEE 2u  /* READ-ONLY: witness-id list at height */
#define RTN_SYS_OP_CCLATEST  3u  /* READ-ONLY: latest nonzero value      */

/* CC row canonical value (exact 88 bytes):
 *   [0..7]   new_value       u64 BE
 *   [8..15]  commit_block    u64 BE (the executing global height)
 *   [16..23] proposal_nonce  u64 BE
 *   [24..87] tx_hash         64 B  (V2: the engine-derived tx_id)
 * Exactly the columns the chain-config merkle leaf consumes
 * (param_id/new_value/effective/commit_block/nonce —
 * nodus_witness_chain_config.c:389) plus the audit tx_hash;
 * created_at_unix is written 0 (deterministic lane, audit-only). */
#define RTN_CC_VAL_LEN   88u
#define RTN_CC_KEY_LEN   12u     /* param_id u32 BE ‖ effective u64 BE  */

#define RTN_CC_VOTE_LEN  (NODUS_CC_PUBKEY_SIZE + NODUS_CC_SIG_SIZE)
#define RTN_CC_MIN_VOTES DNAC_CC_WIRE_MIN_SIGS       /* 5 — shape floor */
#define RTN_CC_MAX_VOTES 8u      /* envelope-ceiling fit (header block) */
#define RTN_CC_FIXED_LEN 42u

/* the committee read serves at most this many 32-byte witness ids —
 * DNA_MAX_ACTIVE_VALIDATORS(128) × 32 = 4096 ≤ the op's value bound */
#define RTN_CC_COMMITTEE_MAX_VAL (32u * DNA_MAX_ACTIVE_VALIDATORS)

typedef struct {
    uint8_t  param_id;
    uint64_t new_value, effective, nonce, signed_at, valid_before;
    uint8_t  vote_count;
    const uint8_t *votes;                /* vote_count × RTN_CC_VOTE_LEN */
} rtn_cc_call_t;

static int rtn_cc_parse(const dna_env_view_t *env, uint16_t leg,
                        rtn_cc_call_t *c) {
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    if (len < RTN_CC_FIXED_LEN) return -1;
    c->param_id     = p[0];
    c->new_value    = rtn_get64(p + 1);
    c->effective    = rtn_get64(p + 9);
    c->nonce        = rtn_get64(p + 17);
    c->signed_at    = rtn_get64(p + 25);
    c->valid_before = rtn_get64(p + 33);
    c->vote_count   = p[41];
    if (c->vote_count < RTN_CC_MIN_VOTES ||
        c->vote_count > RTN_CC_MAX_VOTES)
        return -1;
    if ((size_t)len != RTN_CC_FIXED_LEN +
                       (size_t)c->vote_count * RTN_CC_VOTE_LEN)
        return -1;
    c->votes = p + RTN_CC_FIXED_LEN;
    return 0;
}

int nodus_rt_system_read_plan(const nodus_domain_runtime_t *rt,
                              const dna_env_view_t *env, uint16_t leg_index,
                              const nodus_rt_exec_ctx_t *ctx,
                              nodus_rt_read_req_t *reqs_out,
                              uint16_t max_reqs, uint16_t *n_out) {
    (void)rt;
    if (!env || !ctx || !reqs_out || !n_out) return -2;
    if (leg_index >= env->leg_count) return -2;
    if (env->leg[leg_index].runtime_op != DNA_SYSRULE_CHAIN_CONFIG)
        return -1;                       /* un-migrated op: fail closed  */
    rtn_cc_call_t c;
    if (rtn_cc_parse(env, leg_index, &c) != 0) return -1;
    if (ctx->global_height == 0) return -1;   /* no signing-height
                                          * committee below genesis      */
    uint16_t need = (uint16_t)(c.param_id == DNAC_CFG_INFLATION_START_BLOCK
                                   ? 2 : 1);
    if (need > max_reqs) return -1;
    memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
    reqs_out[0].op_id = RTN_SYS_OP_COMMITTEE;
    reqs_out[0].key_len = 8;
    rtn_put64(reqs_out[0].key, ctx->global_height - 1);
    if (need == 2) {
        memset(&reqs_out[1], 0, sizeof(reqs_out[1]));
        reqs_out[1].op_id = RTN_SYS_OP_CCLATEST;
        reqs_out[1].key_len = 1;
        reqs_out[1].key[0] = c.param_id;
    }
    *n_out = need;
    return 0;
}

int nodus_rt_system_exec(const nodus_domain_runtime_t *rt,
                         const dna_env_view_t *env, uint16_t leg_index,
                         const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_read_res_t *reads, uint16_t n_reads,
                         uint8_t *res_out, size_t res_cap,
                         size_t *res_len_out) {
    (void)rt;
    if (!env || !ctx || !ctx->tx_id || !ctx->chain_id || !res_out ||
        !res_len_out)
        return -2;
    if (leg_index >= env->leg_count) return -2;
    if (env->leg[leg_index].runtime_op != DNA_SYSRULE_CHAIN_CONFIG)
        return -1;

    rtn_cc_call_t c;
    if (rtn_cc_parse(env, leg_index, &c) != 0) return -1;
    if (!ctx->auth || ctx->auth->n_signers < 1) return -1;   /* verified
                                          * submitter authorization      */
    if (env->fee_amount != 0) return -1;      /* header block: no SYSTEM
                                          * fee sink exists this season  */

    uint64_t H = ctx->global_height;
    if (H == 0) return -1;

    /* the SAME scalar authority the legacy apply consumes */
    if (nodus_chain_config_scalar_rules(c.param_id, c.new_value,
                                        c.signed_at, c.valid_before,
                                        c.effective) != 0)
        return -1;
    /* freshness (CC-G) + per-param grace (CC-C), 1:1 from
     * nodus_chain_config_apply */
    if (H > c.valid_before) return -1;
    {
        uint64_t floor_h;
        if (dna_ck_add_u64(H, nodus_chain_config_grace_for_param(
                                  c.param_id), &floor_h) != 0)
            return -1;
        if (c.effective < floor_h) return -1;
    }

    uint16_t expect_reads =
        (uint16_t)(c.param_id == DNAC_CFG_INFLATION_START_BLOCK ? 2 : 1);
    if (!reads || n_reads != expect_reads) return -2;

    /* ── committee membership + quorum (the SOURCE authority) ───────── */
    const nodus_rt_read_res_t *cm = &reads[0];
    if (!cm->present) return -1;         /* chain has no committee       */
    if (cm->value_len == 0 || cm->value_len % 32 != 0 ||
        cm->value_len > RTN_CC_COMMITTEE_MAX_VAL)
        return -2;                       /* own adapter out of contract  */
    uint32_t committee_n = cm->value_len / 32;
    if ((uint32_t)c.vote_count > committee_n) return -1;   /* CC-F shape */

    uint8_t digest[64];
    if (nodus_chain_config_compute_digest(ctx->chain_id, c.param_id,
                                          c.new_value, c.effective,
                                          c.nonce, c.signed_at,
                                          c.valid_before, digest) != 0)
        return -2;                       /* hash backend: node fault     */

    uint8_t seen_ids[RTN_CC_MAX_VOTES][32];
    for (uint8_t v = 0; v < c.vote_count; v++) {
        const uint8_t *pk  = c.votes + (size_t)v * RTN_CC_VOTE_LEN;
        const uint8_t *sig = pk + NODUS_CC_PUBKEY_SIZE;
        uint8_t full[64];
        if (qgp_sha3_512(pk, NODUS_CC_PUBKEY_SIZE, full) != 0) return -2;
        memcpy(seen_ids[v], full, 32);
        /* pairwise-distinct voters (verify_cc_local_rules discipline) */
        for (uint8_t u = 0; u < v; u++)
            if (memcmp(seen_ids[u], seen_ids[v], 32) == 0) return -1;
        /* membership in the SIGNING-HEIGHT committee */
        int member = 0;
        for (uint32_t m = 0; m < committee_n && !member; m++)
            if (memcmp(cm->value + (size_t)m * 32, seen_ids[v], 32) == 0)
                member = 1;
        if (!member) return -1;
        if (qgp_dsa87_verify(sig, NODUS_CC_SIG_SIZE, digest,
                             sizeof(digest), pk) != 0)
            return -1;
    }
    if ((uint32_t)c.vote_count < dna_bft_quorum(committee_n))
        return -1;                       /* Rule CC-F quorum             */

    /* ── INFLATION_START monotonicity (Q5 / CC-GOV-001, 1:1) ────────── */
    if (c.param_id == DNAC_CFG_INFLATION_START_BLOCK) {
        const nodus_rt_read_res_t *mono = &reads[1];
        if (mono->present) {
            if (mono->value_len != 8) return -2;
            if (c.new_value == 0) return -1;   /* cannot disable         */
            if (c.new_value > H) return -1;    /* cannot move past now   */
        }
    }

    /* ── the ONE effect: CREATE the committed history row ───────────── */
    uint8_t key[RTN_CC_KEY_LEN], val[RTN_CC_VAL_LEN];
    rtn_put32(key, (uint32_t)c.param_id);
    rtn_put64(key + 4, c.effective);
    rtn_put64(val, c.new_value);
    rtn_put64(val + 8, H);
    rtn_put64(val + 16, c.nonce);
    memcpy(val + 24, ctx->tx_id, 64);

    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id = RTN_SYS_OP_CC;
    eff.hdr.effect_kind = DNA_EFFECT_CREATE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;   /* PK replay reject   */
    eff.hdr.key_len = RTN_CC_KEY_LEN;
    eff.hdr.value_len = RTN_CC_VAL_LEN;
    eff.key = key;
    eff.value = val;
    if (dna_effect_result_encode(&eff, 1, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/* ── The compiled SYSTEM storage adapter ────────────────────────────── */

/* 0 = row found (val filled), 1 = absent, -1 = fault. */
static int rtn_sys_cc_fetch(nodus_witness_t *w, const uint8_t *key,
                            uint8_t val[RTN_CC_VAL_LEN]) {
    uint32_t param = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
                     ((uint32_t)key[2] << 8) | key[3];
    uint64_t eff = rtn_get64(key + 4);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT new_value, commit_block, proposal_nonce, tx_hash "
            "FROM chain_config_history "
            "WHERE param_id = ?1 AND effective_block = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)eff);
    int rc = sqlite3_step(st);
    int out = -1;
    if (rc == SQLITE_ROW) {
        const uint8_t *txh = sqlite3_column_blob(st, 3);
        sqlite3_int64 nv = sqlite3_column_int64(st, 0);
        sqlite3_int64 cb = sqlite3_column_int64(st, 1);
        sqlite3_int64 pn = sqlite3_column_int64(st, 2);
        /* negative stored integers = malformed row, fail closed (the
         * rtn_core_row_record rule) */
        if (txh && sqlite3_column_bytes(st, 3) == 64 &&
            nv >= 0 && cb >= 0 && pn >= 0) {
            rtn_put64(val, (uint64_t)nv);
            rtn_put64(val + 8, (uint64_t)cb);
            rtn_put64(val + 16, (uint64_t)pn);
            memcpy(val + 24, txh, 64);
            out = 0;
        }
    } else if (rc == SQLITE_DONE) {
        out = 1;
    }
    sqlite3_finalize(st);
    return out;
}

static nodus_adapter_status_t rtn_sys_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (op->op_id != RTN_SYS_OP_CC || key_len != RTN_CC_KEY_LEN)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;   /* read-only ops have
                                          * no probe surface             */
    uint8_t val[RTN_CC_VAL_LEN];
    int rc = rtn_sys_cc_fetch(w, key, val);
    if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    f->exists = (rc == 0);
    if (f->exists) {
        f->version = rtn_get64(val);
        if (dna_effect_value_hash(val, RTN_CC_VAL_LEN, f->value_hash) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t rtn_sys_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    *present = 0;
    *vlen = 0;
    if (op->op_id == RTN_SYS_OP_CC) {
        if (key_len != RTN_CC_KEY_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint8_t val[RTN_CC_VAL_LEN];
        int rc = rtn_sys_cc_fetch(w, key, val);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;
        if (cap < RTN_CC_VAL_LEN) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, val, RTN_CC_VAL_LEN);
        *present = 1;
        *vlen = RTN_CC_VAL_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_COMMITTEE) {
        if (key_len != 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint64_t h = rtn_get64(key);
        nodus_committee_member_t *mem =
            calloc((size_t)DNA_MAX_ACTIVE_VALIDATORS, sizeof(*mem));
        if (!mem) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        int count = 0;
        if (nodus_committee_get_for_block(w, h, mem,
                                          DNA_MAX_ACTIVE_VALIDATORS,
                                          &count) != 0) {
            free(mem);
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        if (count <= 0) { free(mem); return NODUS_ADAPTER_OK; } /* absent:
                                          * a chain with no committee    */
        if ((uint32_t)count * 32u > cap) {
            free(mem);
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        for (int i = 0; i < count; i++) {
            uint8_t full[64];
            if (qgp_sha3_512(mem[i].pubkey, NODUS_CC_PUBKEY_SIZE,
                             full) != 0) {
                free(mem);
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            }
            memcpy(value + (size_t)i * 32, full, 32);
        }
        free(mem);
        *present = 1;
        *vlen = (uint32_t)count * 32u;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_CCLATEST) {
        if (key_len != 1) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT new_value FROM chain_config_history "
                "WHERE param_id = ?1 AND new_value > 0 "
                "ORDER BY commit_block DESC LIMIT 1", -1, &st, NULL)
            != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)key[0]);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (cap < 8) {
                sqlite3_finalize(st);
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            }
            rtn_put64(value, (uint64_t)sqlite3_column_int64(st, 0));
            sqlite3_finalize(st);
            *present = 1;
            *vlen = 8;
            return NODUS_ADAPTER_OK;
        }
        sqlite3_finalize(st);
        return rc == SQLITE_DONE ? NODUS_ADAPTER_OK
                                 : NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t rtn_sys_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (op->op_id != RTN_SYS_OP_CC || kind != DNA_EFFECT_CREATE ||
        key_len != RTN_CC_KEY_LEN || value_len != RTN_CC_VAL_LEN || !value)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)(
        ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
        ((uint32_t)key[2] << 8) | (uint32_t)key[3]));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)rtn_get64(value));
    sqlite3_bind_int64(st, 3, (sqlite3_int64)rtn_get64(key + 4));
    sqlite3_bind_int64(st, 4, (sqlite3_int64)rtn_get64(value + 8));
    sqlite3_bind_blob(st, 5, value + 24, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)rtn_get64(value + 16));
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (sqlite3_changes(w->db) != 1)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    /* the legacy apply's cache-coherence rule (CC-OPS-004 / Q16): a
     * committed row must invalidate the warm lookup cache BEFORE the
     * outer transaction commits; on rollback a cold cache merely
     * re-warms from the database, which will not hold the row */
    w->chain_config_cache_warm = false;
    return NODUS_ADAPTER_OK;
}

static const nodus_adapter_op_t RTN_SYS_OPS[3] = {
    { RTN_SYS_OP_CC,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
      RTN_CC_KEY_LEN, RTN_CC_KEY_LEN, RTN_CC_VAL_LEN, RTN_CC_VAL_LEN },
    { RTN_SYS_OP_COMMITTEE, 0, 0, 8, 8, 0, RTN_CC_COMMITTEE_MAX_VAL },
    { RTN_SYS_OP_CCLATEST,  0, 0, 1, 1, 0, 8 }
};

const nodus_domain_adapter_t NODUS_RT_SYSTEM_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = RTN_SYS_OPS,
    .n_ops = 3,
    .probe = rtn_sys_probe,
    .mutate = rtn_sys_mutate,
    .read = rtn_sys_read
};
