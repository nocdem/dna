/**
 * @file test_native_verify_v3.c
 * @brief Ledger V2 S9 Gate 2 (W3) — dnac_v3_native_verify_stateless gate.
 *
 * Builds real Transaction Wire V3 transactions IN MEMORY through the shipped
 * encoders (dnac_txw3_tleg_encode -> dnac_txw3_shielded_encode ->
 * dnac_txw3_encode) and asserts the native verifier's EXACT status for the
 * honest shape of each type and for every per-type negative.
 *
 * ── What "honest" asserts here, and why it is not an accept ───────────────
 * A real aggregate STARK proof is not required by this gate (proving is
 * client-side and costs seconds); every transaction carries a STUB proof blob.
 * The honest cases therefore assert the DOCUMENTED STOP POINT, and each one is
 * distinguished from a wire failure by the EXPORT struct:
 *
 *   type 11 : every stateless step passes, the proof step runs, and
 *             dnac_shielded_verify_statement rejects the stub blob at the DZKF
 *             v4 decode -> ERR_DECODE. The export struct is POPULATED, which is
 *             what proves the run reached step 13 rather than dying at step 2
 *             (a wire-decode failure leaves the export ZEROED). The sighash the
 *             export carries is compared against an INDEPENDENTLY recomputed
 *             sighash_v5, so "we got past the binding" is proven, not assumed.
 *   type 12 : ERR_DECODE — S9 CORRECTION PASS: the old SEAM-2 deferral is GONE.
 *             Binding verified, signatures verified, and the transaction now
 *             enters the SAME real aggregate verifier type 11 uses, carrying
 *             its populated DNA.TLEG.v1 commitment. These fixtures ship a STUB
 *             proof blob, so the run ends at the DZKF v4 decode — identical to
 *             the type-11 case above. Real-proof ACCEPTS live in the zk-only
 *             gate test_native_verify_v3_proofs (this binary also builds inside
 *             nodus, where no prover is linked).
 *   type 13 : ERR_DECODE, same reason.
 *
 * ── Negative families ─────────────────────────────────────────────────────
 *   NULL/wire     : NULL args, truncation, trailing byte, V2 bytes at the V3
 *                   decoder, a type-11 body carrying a leg prefix
 *   type gate     : SPEND (1), GENESIS (0), unassigned (14)
 *   count windows : every per-type window bound, each on ERR_TYPE_RULE
 *   boundaries    : every per-type boundary equality, each on ERR_TYPE_RULE
 *   arithmetic    : u64 overflow in both checked sums, on ERR_TLEG_ARITH
 *   mirrors       : fee mirror (ERR_FEE), expiry mirror (ERR_TXBIND), min-fee
 *   context       : domain / pool / ruleset / statement_version / chain_id /
 *                   ruleset_hash
 *   binding       : tx_binding lane flip, destination flip, signer-pubkey flip,
 *                   and the SIGNATURE flip that must NOT move the commitment
 *   signatures    : NULL verifier, rejecting verifier, message identity, call
 *                   count, ordering vs the binding check
 *   nullifiers    : in-TX duplicate private nullifier
 *   leg decode    : version, caps, ordering/duplicate, zero amount, truncation
 *
 * NO-FLAKY: every assertion is a status-code or byte equality over
 * deterministic, hand-built inputs. No clock, no RNG, no I/O, no vector file.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_txbind.h"
#include "dnac/dnac.h"
#include "dnac/tx_wire.h"
#include "native_verify_v3.h"
#include "shielded_verify.h"

static int g_fails = 0;

static void check(const char *name, int ok, int got) {
    printf("  %-58s %s", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        printf(" (got %d)", got);
        g_fails++;
    }
    printf("\n");
}

/* ════════════════════════════════════════════════════════════════════════
 * Signature-verify stub (the caller-supplied hook, native_verify_v3.h SEAM 1)
 * ══════════════════════════════════════════════════════════════════════ */

static int      g_sig_calls;
static int      g_sig_result;        /* what the stub returns                */
static uint8_t  g_sig_require_first; /* 0 = accept any sig[0]                */
static uint8_t  g_sig_last_msg[DNAC_TXW_HASH_LEN];
static size_t   g_sig_last_msg_len;
static size_t   g_sig_last_sig_len;
static uint8_t  g_sig_last_pk_byte;

static void sig_stub_reset(int result) {
    g_sig_calls         = 0;
    g_sig_result        = result;
    g_sig_require_first = 0;
    g_sig_last_msg_len  = 0;
    g_sig_last_sig_len  = 0;
    g_sig_last_pk_byte  = 0;
    memset(g_sig_last_msg, 0, sizeof(g_sig_last_msg));
}

/* Signature-compatible with qgp_dsa87_verify (qgp_dilithium.h:49) — the same
 * shape the witness will hand in, so the call convention under test is the
 * production one. */
static int sig_stub(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                    size_t msg_len, const uint8_t *pubkey) {
    g_sig_calls++;
    g_sig_last_sig_len = sig_len;
    g_sig_last_msg_len = msg_len;
    if (msg && msg_len == sizeof(g_sig_last_msg))
        memcpy(g_sig_last_msg, msg, msg_len);
    if (pubkey) g_sig_last_pk_byte = pubkey[0];
    if (g_sig_require_first && sig && sig[0] != g_sig_require_first) return -1;
    return g_sig_result;
}

/* ════════════════════════════════════════════════════════════════════════
 * Fixture builders
 * ══════════════════════════════════════════════════════════════════════ */

#define TXBUF_CAP    ((size_t)DNAC_TXW3_MAX_TX_SIZE)
#define FRI_STUB_LEN 32u
#define TEST_FEE     ((uint64_t)DNAC_MIN_FEE_RAW)
#define TEST_EXPIRY  ((uint64_t)900000)
#define TEST_DOMAIN  ((uint32_t)1)
#define TEST_POOL    ((uint32_t)1)
#define TEST_RULESET ((uint32_t)1)
#define TEST_STMTVER ((uint32_t)1)

/* Canonical Goldilocks lanes (all far below p = 0xFFFFFFFF00000001). */
static void fill_lanes(uint64_t lanes[DNAC_TXW3_SHIELDED_LANES], uint64_t base) {
    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
        lanes[j] = base + j + 1u;
}

static void fill_bytes(uint8_t *p, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) p[i] = (uint8_t)(seed + (uint8_t)i);
}

static void base_ctx(dnac_v3_native_ctx_t *c) {
    memset(c, 0, sizeof(*c));
    for (unsigned i = 0; i < DNA_CHAIN_ID_LEN; i++) c->chain_id[i] = (uint8_t)(0xC0 + i);
    c->domain_id         = TEST_DOMAIN;
    c->pool_id           = TEST_POOL;
    c->ruleset_version   = TEST_RULESET;
    c->statement_version = TEST_STMTVER;
    for (unsigned i = 0; i < DNAC_TXW_HASH_LEN; i++) c->ruleset_hash[i] = (uint8_t)(0x40 + i);
    c->sig_verify = sig_stub;
}

static void base_header(dnac_txw3_header_t *h, uint8_t tx_type) {
    memset(h, 0, sizeof(*h));
    h->wire_version      = DNAC_TXW3_WIRE_VERSION;
    h->tx_type           = tx_type;
    h->domain_id         = TEST_DOMAIN;
    h->pool_id           = TEST_POOL;
    h->ruleset_version   = TEST_RULESET;
    h->statement_version = TEST_STMTVER;
    h->expiry_height     = TEST_EXPIRY;
    h->committed_fee     = TEST_FEE;
    /* S9 CORRECTION PASS: for types 11/12/13 the header timestamp is
     * CONSENSUS-INERT and its sole canonical value is 0 (OBL-S9-TS-BIND).
     * The fixture therefore carries 0; the N-TS-* cases below drive the
     * non-zero rejection explicitly. */
    h->timestamp         = 0ULL;
    /* tx_hash is not read by the decoder or by the native verifier (the V3
     * tx-hash recompute belongs to ingress, not to this stateless entry). */
}

/* Honest per-type statement + leg. */
static void base_statement(dnac_txw3_shielded_t *st, uint8_t tx_type) {
    memset(st, 0, sizeof(*st));
    st->sect_version  = DNAC_TXW3_SECT_VERSION;
    st->fee           = TEST_FEE;
    st->expiry_height = TEST_EXPIRY;
    st->fri_len       = FRI_STUB_LEN;

    if (tx_type == DNAC_TX_SHIELD) {
        /* SHIELD: no private input ⇒ the anchor MUST be all-zero (codec rule). */
        st->num_input   = 0;
        st->num_output  = 2;
        fill_lanes(st->output_commit[0], 0x2000);
        fill_lanes(st->output_commit[1], 0x3000);
        st->boundary_in  = 1234500000ULL;
        st->boundary_out = 0;
    } else if (tx_type == DNAC_TX_UNSHIELD) {
        fill_lanes(st->anchor, 0x1000);
        st->num_input  = 1;
        fill_lanes(st->nf_set[0], 0x4000);
        st->num_output = 1;
        fill_lanes(st->output_commit[0], 0x5000);
        st->boundary_in  = 0;
        /* == tout[0].amount (777000) + fee */
        st->boundary_out = 777000ULL + TEST_FEE;
    } else { /* DNAC_TX_SHIELDED (TRANSFER) */
        fill_lanes(st->anchor, 0x1000);
        st->num_input  = 1;
        fill_lanes(st->nf_set[0], 0x6000);
        st->num_output = 1;
        fill_lanes(st->output_commit[0], 0x7000);
        st->boundary_in  = 0;
        st->boundary_out = TEST_FEE; /* the fee is the only value leaving */
    }
}

static void base_leg(dnac_txw3_tleg_t *leg, uint8_t tx_type) {
    memset(leg, 0, sizeof(*leg));
    leg->tleg_version = DNAC_TXW3_TLEG_VERSION;

    if (tx_type == DNAC_TX_SHIELD) {
        leg->num_tin = 2;
        /* STRICTLY ascending (codec rule): leading byte 0x10 < 0x20. */
        fill_bytes(leg->tin_nullifier[0], DNAC_TXW_NULLIFIER_LEN, 0x10);
        fill_bytes(leg->tin_nullifier[1], DNAC_TXW_NULLIFIER_LEN, 0x20);
        leg->num_tout = 1;
        fill_bytes(leg->tout[0].fp, DNAC_TXW_FP_LEN, 0x31);
        leg->tout[0].amount = 5000;
        fill_bytes(leg->tout[0].nullifier_seed, DNAC_TXW_SEED_LEN, 0x41);
        leg->num_signers = 1;
        fill_bytes(leg->signer[0].pubkey, DNAC_TXW_PK_LEN, 0x51);
        fill_bytes(leg->signer[0].signature, DNAC_TXW_SIG_LEN, 0x61);
    } else { /* DNAC_TX_UNSHIELD */
        leg->num_tin  = 0;
        leg->num_tout = 1;
        fill_bytes(leg->tout[0].fp, DNAC_TXW_FP_LEN, 0x71);
        leg->tout[0].amount = 777000;
        fill_bytes(leg->tout[0].nullifier_seed, DNAC_TXW_SEED_LEN, 0x81);
        leg->num_signers = 0;
    }
}

/**
 * Compute the sighash_v5 an HONEST transaction of this shape binds to, exactly
 * the way the verifier will: caller-supplied context values, pinned wire and
 * section versions, populated leg commitment for 12/13 and the tagged-empty one
 * for 11, tagged-empty ct commitment.
 * @return 0 / -1.
 */
static int expected_sighash(const dnac_v3_native_ctx_t *c,
                            const dnac_txw3_header_t *h,
                            const dnac_txw3_shielded_t *st,
                            const dnac_txw3_tleg_t *leg, int has_leg,
                            uint8_t out[DNAC_TXW_HASH_LEN]) {
    dna_exec_context_t ectx;
    if (dna_exec_context_init(&ectx, c->chain_id, c->domain_id, c->pool_id,
                              h->tx_type, (uint8_t)DNAC_TXW3_WIRE_VERSION,
                              c->ruleset_version, c->statement_version) != 0)
        return -1;
    uint8_t tleg_c[DNAC_TXW_HASH_LEN];
    uint8_t ct_c[DNAC_TXW_HASH_LEN];
    if (has_leg) {
        if (dnac_tleg_commit(leg, tleg_c) != 0) return -1;
    } else {
        if (dnac_tleg_commit_empty(tleg_c) != 0) return -1;
    }
    if (dnac_ct_commit_empty(ct_c) != 0) return -1;
    return dnac_sighash_v5(&ectx, (uint8_t)DNAC_TXW3_SECT_VERSION,
                           c->ruleset_hash, st, tleg_c, ct_c, out);
}

/**
 * Assemble one serialized V3 transaction from the three structs.
 * When `rebind` is non-zero the statement's tx_binding is first recomputed from
 * the honest sighash_v5, so the assembled transaction binds correctly; passing
 * 0 is how the binding negatives are built (mutate a committed field, do NOT
 * re-bind).
 * @return 0 on success (*tx_len_out written), -1 if any encoder rejected.
 */
static int assemble(const dnac_v3_native_ctx_t *c, dnac_txw3_header_t *h,
                    dnac_txw3_shielded_t *st, const dnac_txw3_tleg_t *leg,
                    int has_leg, int rebind, uint8_t *tx, size_t *tx_len_out) {
    if (rebind) {
        uint8_t  sighash[DNAC_TXW_HASH_LEN];
        uint64_t txbind[CONF_TXBIND_LANES];
        if (expected_sighash(c, h, st, leg, has_leg, sighash) != 0) return -1;
        if (!conf_txbind_map(sighash, txbind)) return -1;
        for (unsigned j = 0; j < CONF_TXBIND_LANES; j++)
            st->tx_binding[j] = txbind[j];
    }

    static uint8_t body[TXBUF_CAP];
    size_t         body_used = 0;

    if (has_leg) {
        size_t leg_len = 0;
        if (dnac_txw3_tleg_encode(leg, body, sizeof(body), &leg_len) != 0)
            return -1;
        body_used = leg_len;
    }

    uint8_t fri[FRI_STUB_LEN];
    fill_bytes(fri, sizeof(fri), 0xAB);

    size_t sect_len = 0;
    if (dnac_txw3_shielded_encode(st, fri, (uint32_t)sizeof(fri),
                                  body + body_used, sizeof(body) - body_used,
                                  &sect_len) != 0)
        return -1;
    body_used += sect_len;

    size_t written = 0;
    if (dnac_txw3_encode(h, body, (uint32_t)body_used, tx, TXBUF_CAP,
                         &written) != 0)
        return -1;
    *tx_len_out = written;
    return 0;
}

/* Every honest fixture is built through this one path, so a builder mistake
 * shows up as a build failure rather than as a silently different negative. */
static int build_honest(uint8_t tx_type, const dnac_v3_native_ctx_t *c,
                        dnac_txw3_header_t *h, dnac_txw3_shielded_t *st,
                        dnac_txw3_tleg_t *leg, int *has_leg, uint8_t *tx,
                        size_t *tx_len) {
    base_header(h, tx_type);
    base_statement(st, tx_type);
    *has_leg = (tx_type != DNAC_TX_SHIELDED);
    if (*has_leg) base_leg(leg, tx_type);
    else memset(leg, 0, sizeof(*leg));
    return assemble(c, h, st, leg, *has_leg, 1, tx, tx_len);
}

static int out_is_zeroed(const dnac_v3_native_out_t *o) {
    dnac_v3_native_out_t zero;
    memset(&zero, 0, sizeof(zero));
    return memcmp(o, &zero, sizeof(zero)) == 0;
}

/* ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("============================================================\n");
    printf("Ledger V2 S9 W3 — NATIVE stateless V3 verifier\n");
    printf("  dnac_v3_native_verify_stateless: types 11 / 12 / 13\n");
    printf("============================================================\n");

    dnac_v3_native_ctx_t ctx;
    base_ctx(&ctx);

    uint8_t              *tx  = (uint8_t *)malloc(TXBUF_CAP);
    dnac_txw3_tleg_t     *leg = (dnac_txw3_tleg_t *)calloc(1, sizeof(*leg));
    if (!tx || !leg) {
        printf("FATAL: allocation failed\n");
        free(tx);
        free(leg);
        return 1;
    }
    dnac_txw3_header_t   hdr;
    dnac_txw3_shielded_t st;
    dnac_v3_native_out_t out;
    size_t               tx_len  = 0;
    int                  has_leg = 0;
    dnac_shielded_verify_status_t s;

    /* ══════════════════ A. Honest shapes / stop points ══════════════════ */
    printf("\n-- A. honest shapes (documented stop points) --\n");

    /* A-11: TRANSFER reaches the proof step; the stub blob dies in the DZKF v4
     * decode. The EXPORT struct is what distinguishes this from a wire reject. */
    sig_stub_reset(0);
    if (build_honest(DNAC_TX_SHIELDED, &ctx, &hdr, &st, leg, &has_leg, tx,
                     &tx_len) != 0) {
        check("A-11  build honest TRANSFER", 0, -1);
    } else {
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        uint8_t want[DNAC_TXW_HASH_LEN];
        int     have_sig = (expected_sighash(&ctx, &hdr, &st, leg, 0, want) == 0);
        int ok = (s == DNAC_SHIELDED_VERIFY_ERR_DECODE) && have_sig &&
                 memcmp(out.sighash, want, sizeof(want)) == 0 &&
                 out.tx_type == DNAC_TX_SHIELDED &&
                 out.num_nullifier == 1 && out.num_output_commit == 1 &&
                 out.num_tin == 0 && out.num_tout == 0 &&
                 out.boundary_in == 0 && out.boundary_out == TEST_FEE &&
                 out.committed_fee == TEST_FEE &&
                 out.expiry_height == TEST_EXPIRY &&
                 out.has_tin_sum_expected == 0;
        check("A-11  TRANSFER reaches proof step (stub -> ERR_DECODE)", ok,
              (int)s);
    }

    /* A-12: SHIELD passes every stateless step and stops at SEAM 2. */
    sig_stub_reset(0);
    if (build_honest(DNAC_TX_SHIELD, &ctx, &hdr, &st, leg, &has_leg, tx,
                     &tx_len) != 0) {
        check("A-12  build honest SHIELD", 0, -1);
    } else {
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        int ok = (s == DNAC_SHIELDED_VERIFY_ERR_DECODE) &&
                 out.tx_type == DNAC_TX_SHIELD && out.num_tin == 2 &&
                 out.num_tout == 1 && out.num_signers == 1 &&
                 out.num_nullifier == 0 && out.num_output_commit == 2 &&
                 out.boundary_out == 0 && out.boundary_in == 1234500000ULL &&
                 out.has_tin_sum_expected == 1 &&
                 out.tin_sum_expected == 1234500000ULL + 5000ULL + TEST_FEE &&
                 out.tout[0].amount == 5000 && g_sig_calls == 1;
        check("A-12  SHIELD -> proof step (stub->DECODE) + exported S10 expectation", ok,
              (int)s);

        /* The callback saw EXACTLY the 64-byte sighash_v5, not the txid and not
         * some other digest (user lock O-2). */
        uint8_t want[DNAC_TXW_HASH_LEN];
        int ok2 = (expected_sighash(&ctx, &hdr, &st, leg, 1, want) == 0) &&
                  g_sig_last_msg_len == DNAC_TXW_HASH_LEN &&
                  memcmp(g_sig_last_msg, want, sizeof(want)) == 0 &&
                  g_sig_last_sig_len == DNAC_TXW_SIG_LEN &&
                  g_sig_last_pk_byte == 0x51;
        check("A-12b signers are handed sighash_v5 (O-2), sig+pk widths", ok2,
              (int)g_sig_last_msg_len);
    }

    /* A-13: UNSHIELD, one change note (the O-1b upper end). */
    sig_stub_reset(0);
    if (build_honest(DNAC_TX_UNSHIELD, &ctx, &hdr, &st, leg, &has_leg, tx,
                     &tx_len) != 0) {
        check("A-13  build honest UNSHIELD", 0, -1);
    } else {
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        int ok = (s == DNAC_SHIELDED_VERIFY_ERR_DECODE) &&
                 out.tx_type == DNAC_TX_UNSHIELD && out.num_tin == 0 &&
                 out.num_tout == 1 && out.num_signers == 0 &&
                 out.num_nullifier == 1 && out.num_output_commit == 1 &&
                 out.boundary_in == 0 &&
                 out.boundary_out == 777000ULL + TEST_FEE &&
                 out.tout[0].amount == 777000 &&
                 out.has_tin_sum_expected == 0 && g_sig_calls == 0;
        check("A-13  UNSHIELD -> proof step (stub->DECODE) + recipient exported", ok,
              (int)s);
    }

    /* A-13b: zero private outputs is the O-1b LOWER end and must be legal. */
    base_header(&hdr, DNAC_TX_UNSHIELD);
    base_statement(&st, DNAC_TX_UNSHIELD);
    base_leg(leg, DNAC_TX_UNSHIELD);
    st.num_output = 0;
    memset(st.output_commit[0], 0, sizeof(st.output_commit[0])); /* slot zero */
    if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
        check("A-13b build UNSHIELD with 0 private outputs", 0, -1);
    } else {
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        check("A-13b UNSHIELD private_out == 0 is legal (O-1b)",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
    }

    /* A-12c: 16 change outputs is the SHIELD window's legal upper end. */
    base_header(&hdr, DNAC_TX_SHIELD);
    base_statement(&st, DNAC_TX_SHIELD);
    base_leg(leg, DNAC_TX_SHIELD);
    leg->num_tout = DNAC_TXW_MAX_OUTPUTS;
    for (unsigned i = 1; i < DNAC_TXW_MAX_OUTPUTS; i++) {
        fill_bytes(leg->tout[i].fp, DNAC_TXW_FP_LEN, (uint8_t)(0x90 + i));
        leg->tout[i].amount = 100 + i;
        fill_bytes(leg->tout[i].nullifier_seed, DNAC_TXW_SEED_LEN,
                   (uint8_t)(0xA0 + i));
    }
    sig_stub_reset(0);
    if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
        check("A-12c build SHIELD with 16 change outputs", 0, -1);
    } else {
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        check("A-12c SHIELD num_tout == 16 (window upper end) legal",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
    }

    /* ══════════════════ B. NULL + wire decode ══════════════════ */
    printf("\n-- B. NULL args + wire decode --\n");

    (void)build_honest(DNAC_TX_SHIELDED, &ctx, &hdr, &st, leg, &has_leg, tx,
                       &tx_len);
    {
        int ok = dnac_v3_native_verify_stateless(NULL, tx_len, &ctx, &out) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL &&
                 dnac_v3_native_verify_stateless(tx, 0, &ctx, &out) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL &&
                 dnac_v3_native_verify_stateless(tx, tx_len, NULL, &out) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL;
        check("B-1   NULL tx / zero len / NULL ctx -> ERR_NULL", ok, -1);
        check("B-1b  export struct zeroed on a NULL-arg reject",
              out_is_zeroed(&out), -1);
    }
    {
        s = dnac_v3_native_verify_stateless(tx, tx_len - 1, &ctx, &out);
        check("B-2   truncated by one byte -> ERR_DECODE",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        check("B-2b  export struct zeroed on a wire reject", out_is_zeroed(&out),
              -1);
    }
    {
        /* One trailing byte: the decoder's exact-length equality must reject. */
        tx[tx_len] = 0x00;
        s = dnac_v3_native_verify_stateless(tx, tx_len + 1, &ctx, &out);
        check("B-3   one trailing byte -> ERR_DECODE",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
    }
    {
        uint8_t save = tx[0];
        tx[0] = 2; /* legacy V2 wire-version byte at the V3 decoder */
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
        check("B-4   V2 wire-version byte -> ERR_DECODE",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        tx[0] = save;
    }

    /* ══════════════════ C. Type gate ══════════════════ */
    printf("\n-- C. type gate --\n");
    {
        const uint8_t bad_types[3] = {0, 1, 14};
        const char   *names[3] = {"C-1   tx_type 0 (GENESIS) -> ERR_TYPE_RULE",
                                  "C-2   tx_type 1 (SPEND)   -> ERR_TYPE_RULE",
                                  "C-3   tx_type 14 (unassigned) -> ERR_TYPE_RULE"};
        for (unsigned i = 0; i < 3; i++) {
            base_header(&hdr, DNAC_TX_SHIELDED);
            base_statement(&st, DNAC_TX_SHIELDED);
            hdr.tx_type = bad_types[i];
            /* Bind under the honest type, then rewrite the header type: the
             * type gate must fire before anything else looks at the body. */
            if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
                check(names[i], 0, -1);
                continue;
            }
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check(names[i], s == DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, (int)s);
        }
    }
    {
        /* A type-11 body that carries a transparent leg: type 11 has NO leg, so
         * the section's exact-length equality over the WHOLE body rejects. */
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        base_leg(leg, DNAC_TX_SHIELD);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("C-4   type-11 body with a leg prefix", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("C-4   type-11 body carrying a leg -> ERR_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        }
    }

    /* ═════════ C-TS. The timestamp rule (S9 CORRECTION, OBL-S9-TS-BIND) ═════
     * For 11/12/13 the header timestamp is consensus-inert with exactly one
     * canonical value: 0. Non-zero must reject DETERMINISTICALLY and BEFORE any
     * proof work — proven here by driving a transaction whose proof blob is a
     * stub: with timestamp 0 it reaches the decode (ERR_DECODE), with a
     * non-zero timestamp it dies earlier with ERR_TIMESTAMP. A rule that ran
     * after the proof step could not produce that ordering. */
    printf("\n-- C-TS. header timestamp is pinned to 0 (11/12/13) --\n");
    {
        const uint8_t ts_types[3] = { DNAC_TX_SHIELDED, DNAC_TX_SHIELD,
                                      DNAC_TX_UNSHIELD };
        const char *ok_names[3] = {
            "C-TS1 type 11 timestamp == 0 reaches the proof step",
            "C-TS2 type 12 timestamp == 0 reaches the proof step",
            "C-TS3 type 13 timestamp == 0 reaches the proof step" };
        const char *bad_names[3] = {
            "C-TS4 type 11 timestamp != 0 -> ERR_TIMESTAMP",
            "C-TS5 type 12 timestamp != 0 -> ERR_TIMESTAMP",
            "C-TS6 type 13 timestamp != 0 -> ERR_TIMESTAMP" };
        for (unsigned i = 0; i < 3; i++) {
            const int with_leg = (ts_types[i] != DNAC_TX_SHIELDED);
            base_header(&hdr, ts_types[i]);
            base_statement(&st, ts_types[i]);
            base_leg(leg, ts_types[i]);
            if (assemble(&ctx, &hdr, &st, leg, with_leg, 1, tx, &tx_len) != 0) {
                check(ok_names[i], 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check(ok_names[i], s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
            }
            /* Same transaction, bound under the same statement, with ONLY the
             * header timestamp moved — so the reject is attributable to the
             * timestamp alone and to nothing downstream of it. */
            base_header(&hdr, ts_types[i]);
            base_statement(&st, ts_types[i]);
            base_leg(leg, ts_types[i]);
            hdr.timestamp = 1ULL;
            if (assemble(&ctx, &hdr, &st, leg, with_leg, 1, tx, &tx_len) != 0) {
                check(bad_names[i], 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check(bad_names[i],
                      s == DNAC_SHIELDED_VERIFY_ERR_TIMESTAMP, (int)s);
            }
        }
        /* The extreme value must not be special-cased anywhere. */
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        hdr.timestamp = UINT64_MAX;
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) == 0) {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("C-TS7 timestamp == UINT64_MAX -> ERR_TIMESTAMP",
                  s == DNAC_SHIELDED_VERIFY_ERR_TIMESTAMP, (int)s);
        } else {
            check("C-TS7 timestamp == UINT64_MAX -> ERR_TIMESTAMP", 0, -1);
        }
    }

    /* ══════════════════ D. Type-11 windows + boundaries ══════════════════ */
    printf("\n-- D. type 11 (TRANSFER) count windows + boundaries --\n");
#define D11_CASE(label, mutation)                                              \
    do {                                                                       \
        base_header(&hdr, DNAC_TX_SHIELDED);                                   \
        base_statement(&st, DNAC_TX_SHIELDED);                                 \
        mutation;                                                              \
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {          \
            check(label, 0, -1);                                               \
        } else {                                                               \
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);       \
            check(label, s == DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, (int)s);     \
        }                                                                      \
    } while (0)

    D11_CASE("D-1   private_in == 0 -> TYPE_RULE (O-1)", {
        st.num_input = 0;
        memset(st.nf_set[0], 0, sizeof(st.nf_set[0]));
        memset(st.anchor, 0, sizeof(st.anchor)); /* codec: zero-in ⇒ zero anchor */
    });
    D11_CASE("D-2   private_out == 0 -> TYPE_RULE (O-1)", {
        st.num_output = 0;
        memset(st.output_commit[0], 0, sizeof(st.output_commit[0]));
    });
    D11_CASE("D-3   boundary_in != 0 -> TYPE_RULE", { st.boundary_in = 1; });
    D11_CASE("D-4   boundary_out != fee (fee+1) -> TYPE_RULE",
             { st.boundary_out = TEST_FEE + 1; });
    D11_CASE("D-5   boundary_out == 0 -> TYPE_RULE", { st.boundary_out = 0; });
#undef D11_CASE
    check("D-6   export struct zeroed on a TYPE_RULE reject",
          out_is_zeroed(&out), -1);

    /* ══════════════════ E. Type-12 windows + boundaries + arithmetic ══════ */
    printf("\n-- E. type 12 (SHIELD) count windows + boundaries --\n");
#define D12_CASE(label, want, mutation)                                        \
    do {                                                                       \
        base_header(&hdr, DNAC_TX_SHIELD);                                     \
        base_statement(&st, DNAC_TX_SHIELD);                                   \
        base_leg(leg, DNAC_TX_SHIELD);                                         \
        mutation;                                                              \
        sig_stub_reset(0);                                                     \
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {          \
            check(label, 0, -1);                                               \
        } else {                                                               \
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);       \
            check(label, s == (want), (int)s);                                 \
        }                                                                      \
    } while (0)

    D12_CASE("E-1   num_tin == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_tin = 0;
        memset(leg->tin_nullifier, 0, sizeof(leg->tin_nullifier));
    });
    D12_CASE("E-2   num_signers == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_signers = 0;
        memset(leg->signer, 0, sizeof(leg->signer));
    });
    D12_CASE("E-3   private_in != 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        st.num_input = 1;
        fill_lanes(st.nf_set[0], 0x8000);
        fill_lanes(st.anchor, 0x9000); /* nonzero anchor is legal once in > 0 */
    });
    D12_CASE("E-4   private_out == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        st.num_output = 0;
        memset(st.output_commit, 0, sizeof(st.output_commit));
    });
    D12_CASE("E-5   boundary_out != 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE,
             { st.boundary_out = 1; });
    D12_CASE("E-6   boundary_in == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE,
             { st.boundary_in = 0; });
    /* Overflow inside the Σ tout accumulation (two near-u64max amounts). */
    D12_CASE("E-7   Sigma(tout) overflows u64 -> TLEG_ARITH",
             DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH, {
                 leg->num_tout       = 2;
                 leg->tout[0].amount = UINT64_MAX;
                 fill_bytes(leg->tout[1].fp, DNAC_TXW_FP_LEN, 0xB1);
                 leg->tout[1].amount = 2;
                 fill_bytes(leg->tout[1].nullifier_seed, DNAC_TXW_SEED_LEN, 0xC1);
             });
    /* Overflow when boundary_in is added to a Σ tout that itself fits. */
    D12_CASE("E-8   b_in + Sigma(tout) overflows u64 -> TLEG_ARITH",
             DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH,
             { leg->tout[0].amount = UINT64_MAX - 1000; });
#undef D12_CASE

    /* ══════════════════ F. Type-13 windows + boundaries + arithmetic ══════ */
    printf("\n-- F. type 13 (UNSHIELD) count windows + boundaries --\n");
#define D13_CASE(label, want, mutation)                                        \
    do {                                                                       \
        base_header(&hdr, DNAC_TX_UNSHIELD);                                   \
        base_statement(&st, DNAC_TX_UNSHIELD);                                 \
        base_leg(leg, DNAC_TX_UNSHIELD);                                       \
        mutation;                                                              \
        sig_stub_reset(0);                                                     \
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {          \
            check(label, 0, -1);                                               \
        } else {                                                               \
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);       \
            check(label, s == (want), (int)s);                                 \
        }                                                                      \
    } while (0)

    D13_CASE("F-1   num_tin != 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_tin = 1;
        fill_bytes(leg->tin_nullifier[0], DNAC_TXW_NULLIFIER_LEN, 0x10);
    });
    D13_CASE("F-2   num_signers != 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_signers = 1;
        fill_bytes(leg->signer[0].pubkey, DNAC_TXW_PK_LEN, 0x51);
        fill_bytes(leg->signer[0].signature, DNAC_TXW_SIG_LEN, 0x61);
    });
    D13_CASE("F-3   num_tout == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_tout = 0;
        memset(leg->tout, 0, sizeof(leg->tout));
        st.boundary_out = TEST_FEE; /* keep the section canonical */
    });
    D13_CASE("F-4   num_tout == 2 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        leg->num_tout = 2;
        fill_bytes(leg->tout[1].fp, DNAC_TXW_FP_LEN, 0xD1);
        leg->tout[1].amount = 10;
        fill_bytes(leg->tout[1].nullifier_seed, DNAC_TXW_SEED_LEN, 0xE1);
    });
    D13_CASE("F-5   private_in == 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
        st.num_input = 0;
        memset(st.nf_set, 0, sizeof(st.nf_set));
        memset(st.anchor, 0, sizeof(st.anchor));
    });
    D13_CASE("F-6   private_out == 2 -> TYPE_RULE (O-1b)",
             DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, {
                 st.num_output = 2;
                 fill_lanes(st.output_commit[1], 0xA000);
             });
    D13_CASE("F-7   boundary_in != 0 -> TYPE_RULE", DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE,
             { st.boundary_in = 1; });
    D13_CASE("F-8   b_out != amount + fee -> TYPE_RULE",
             DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE,
             { st.boundary_out = 777000ULL + TEST_FEE + 1; });
    D13_CASE("F-9   b_out omits the fee -> TYPE_RULE",
             DNAC_SHIELDED_VERIFY_ERR_TYPE_RULE, { st.boundary_out = 777000ULL; });
    D13_CASE("F-10  amount + fee overflows u64 -> TLEG_ARITH",
             DNAC_SHIELDED_VERIFY_ERR_TLEG_ARITH,
             { leg->tout[0].amount = UINT64_MAX; });
#undef D13_CASE

    /* ══════════════════ G. Header mirrors + min fee ══════════════════ */
    printf("\n-- G. header mirrors + min-fee floor --\n");
    {
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        st.fee = TEST_FEE + 1; /* section disagrees with the header */
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("G-1   fee mirror mismatch", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("G-1   section fee != header fee -> ERR_FEE",
                  s == DNAC_SHIELDED_VERIFY_ERR_FEE, (int)s);
        }
    }
    {
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        st.expiry_height = TEST_EXPIRY + 1;
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("G-2   expiry mirror mismatch", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("G-2   section expiry != header expiry -> ERR_TXBIND",
                  s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
        }
    }
    {
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        hdr.committed_fee = DNAC_MIN_FEE_RAW - 1;
        st.fee            = DNAC_MIN_FEE_RAW - 1;
        st.boundary_out   = DNAC_MIN_FEE_RAW - 1; /* keep b_out == fee */
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("G-3   below-min fee", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("G-3   committed_fee < DNAC_MIN_FEE_RAW -> ERR_FEE",
                  s == DNAC_SHIELDED_VERIFY_ERR_FEE, (int)s);
        }
    }

    /* ══════════════════ H. Context provenance ══════════════════ */
    printf("\n-- H. context match (header copies vs consensus state) --\n");
    (void)build_honest(DNAC_TX_SHIELDED, &ctx, &hdr, &st, leg, &has_leg, tx,
                       &tx_len);
    {
        dnac_v3_native_ctx_t bad;
        base_ctx(&bad);
        bad.domain_id = TEST_DOMAIN + 1;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-1   domain_id mismatch -> ERR_TXBIND",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);

        base_ctx(&bad);
        bad.pool_id = TEST_POOL + 1;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-2   pool_id mismatch -> ERR_TXBIND",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);

        base_ctx(&bad);
        bad.ruleset_version = TEST_RULESET + 1;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-3   ruleset_version mismatch -> ERR_TXBIND",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);

        base_ctx(&bad);
        bad.statement_version = TEST_STMTVER + 1;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-4   statement_version mismatch -> ERR_STATEMENT_VERSION",
              s == DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION, (int)s);

        /* chain_id and ruleset_hash are NOT on the wire — they can only be
         * caught by the sighash they change. */
        base_ctx(&bad);
        bad.chain_id[0] ^= 0xFF;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-5   chain_id substitution -> ERR_TXBIND (sighash diverges)",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);

        base_ctx(&bad);
        bad.ruleset_hash[63] ^= 0xFF;
        s = dnac_v3_native_verify_stateless(tx, tx_len, &bad, &out);
        check("H-6   ruleset_hash substitution -> ERR_TXBIND",
              s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
    }

    /* ══════════════════ I. Statement binding ══════════════════ */
    printf("\n-- I. tx_binding --\n");
    {
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        /* Bind honestly, then overwrite one lane with a canonical constant. */
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("I-1   tx_binding lane flip", 0, -1);
        } else {
            st.tx_binding[0] = (st.tx_binding[0] == 7u) ? 8u : 7u;
            if (assemble(&ctx, &hdr, &st, leg, 0, 0, tx, &tx_len) != 0) {
                check("I-1   tx_binding lane flip", 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check("I-1   wrong tx_binding lane -> ERR_TXBIND",
                      s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
            }
        }
    }
    {
        /* SHIELD: a change output's AMOUNT is inside the leg commitment, so
         * moving it after binding must break the binding. */
        base_header(&hdr, DNAC_TX_SHIELD);
        base_statement(&st, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        sig_stub_reset(0);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("I-2   SHIELD change-amount flip", 0, -1);
        } else {
            leg->tout[0].amount = 6000;
            if (assemble(&ctx, &hdr, &st, leg, 1, 0, tx, &tx_len) != 0) {
                check("I-2   SHIELD change-amount flip", 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check("I-2   change amount moved after binding -> ERR_TXBIND",
                      s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
            }
        }
    }
    {
        /* UNSHIELD: the recipient fingerprint is committed. */
        base_header(&hdr, DNAC_TX_UNSHIELD);
        base_statement(&st, DNAC_TX_UNSHIELD);
        base_leg(leg, DNAC_TX_UNSHIELD);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("I-3   UNSHIELD recipient flip", 0, -1);
        } else {
            leg->tout[0].fp[0] ^= 0xFF;
            if (assemble(&ctx, &hdr, &st, leg, 1, 0, tx, &tx_len) != 0) {
                check("I-3   UNSHIELD recipient flip", 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check("I-3   recipient fp moved after binding -> ERR_TXBIND",
                      s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
            }
        }
    }
    {
        /* Signer PUBKEYS are committed; SIGNATURES are NOT (tx_wire.h §6).
         * Both halves of that rule are pinned here, on the same fixture. */
        base_header(&hdr, DNAC_TX_SHIELD);
        base_statement(&st, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        sig_stub_reset(0);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("I-4   signer pubkey flip", 0, -1);
        } else {
            /* static, not automatic: a leg struct is ~32 KB and the header
             * warns against putting two of them in one frame (tx_wire.h §6). */
            static dnac_txw3_tleg_t save;
            memcpy(&save, leg, sizeof(save));

            leg->signer[0].pubkey[0] ^= 0xFF;
            if (assemble(&ctx, &hdr, &st, leg, 1, 0, tx, &tx_len) == 0) {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check("I-4   signer PUBKEY moved after binding -> ERR_TXBIND",
                      s == DNAC_SHIELDED_VERIFY_ERR_TXBIND, (int)s);
            } else {
                check("I-4   signer PUBKEY moved after binding -> ERR_TXBIND", 0,
                      -1);
            }

            memcpy(leg, &save, sizeof(save));
            leg->signer[0].signature[0] ^= 0xFF;
            sig_stub_reset(0);
            if (assemble(&ctx, &hdr, &st, leg, 1, 0, tx, &tx_len) == 0) {
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                check("I-5   signature flip does NOT move the commitment",
                      s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
            } else {
                check("I-5   signature flip does NOT move the commitment", 0, -1);
            }
        }
    }

    /* ══════════════════ J. Signatures ══════════════════ */
    printf("\n-- J. type-12 spend authorization --\n");
    {
        base_header(&hdr, DNAC_TX_SHIELD);
        base_statement(&st, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        /* Three signers, so the per-signer loop is genuinely exercised. */
        leg->num_signers = 3;
        for (unsigned i = 1; i < 3; i++) {
            fill_bytes(leg->signer[i].pubkey, DNAC_TXW_PK_LEN,
                       (uint8_t)(0x52 + i));
            fill_bytes(leg->signer[i].signature, DNAC_TXW_SIG_LEN,
                       (uint8_t)(0x62 + i));
        }
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("J-1   three-signer fixture", 0, -1);
        } else {
            sig_stub_reset(0);
            s   = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            int ok = (s == DNAC_SHIELDED_VERIFY_ERR_DECODE) &&
                     g_sig_calls == 3 && out.num_signers == 3;
            check("J-1   every signer is verified (3 calls)", ok, g_sig_calls);

            sig_stub_reset(-1); /* verifier rejects */
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("J-2   rejecting verifier -> ERR_SIG",
                  s == DNAC_SHIELDED_VERIFY_ERR_SIG, (int)s);
            check("J-2b  stops at the FIRST bad signature", g_sig_calls == 1,
                  g_sig_calls);

            dnac_v3_native_ctx_t nosig;
            base_ctx(&nosig);
            nosig.sig_verify = NULL;
            s = dnac_v3_native_verify_stateless(tx, tx_len, &nosig, &out);
            check("J-3   NULL verifier on type 12 -> ERR_SIG (never a skip)",
                  s == DNAC_SHIELDED_VERIFY_ERR_SIG, (int)s);

            /* Only the SECOND signature is bad: the stub accepts exactly
             * signer[0]'s leading byte (0x61, base_leg) and rejects signer[1]'s
             * (0x63) — so the run must reach call 2 and then reject. Proves the
             * loop does not stop after the first SUCCESS. */
            sig_stub_reset(0);
            g_sig_require_first = 0x61;
            s   = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            int ok4 = (s == DNAC_SHIELDED_VERIFY_ERR_SIG) && g_sig_calls == 2;
            check("J-4   a bad NON-first signature still -> ERR_SIG", ok4,
                  (int)s);
        }
    }
    {
        /* Type 13 carries no signers, so no verifier is required at all. */
        base_header(&hdr, DNAC_TX_UNSHIELD);
        base_statement(&st, DNAC_TX_UNSHIELD);
        base_leg(leg, DNAC_TX_UNSHIELD);
        dnac_v3_native_ctx_t nosig;
        base_ctx(&nosig);
        nosig.sig_verify = NULL;
        if (assemble(&nosig, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("J-5   UNSHIELD without a verifier", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &nosig, &out);
            check("J-5   type 13 needs no verifier -> proof step (stub->DECODE)",
                  s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        }
    }
    {
        /* ORDERING: a transaction with BOTH a broken binding and a rejecting
         * verifier must report the BINDING failure — signatures are checked
         * after the statement is known to be the one on the wire. */
        base_header(&hdr, DNAC_TX_SHIELD);
        base_statement(&st, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) == 0) {
            st.tx_binding[0] = (st.tx_binding[0] == 7u) ? 8u : 7u;
            if (assemble(&ctx, &hdr, &st, leg, 1, 0, tx, &tx_len) == 0) {
                sig_stub_reset(-1);
                s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
                int ok = (s == DNAC_SHIELDED_VERIFY_ERR_TXBIND) &&
                         g_sig_calls == 0;
                check("J-6   binding is checked BEFORE signatures", ok, (int)s);
            } else {
                check("J-6   binding is checked BEFORE signatures", 0, -1);
            }
        } else {
            check("J-6   binding is checked BEFORE signatures", 0, -1);
        }
    }

    /* ══════════════════ K. In-TX nullifier duplication ══════════════════ */
    printf("\n-- K. in-TX private nullifier distinctness --\n");
    {
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        st.num_input = 2;
        fill_lanes(st.nf_set[0], 0x6000);
        fill_lanes(st.nf_set[1], 0x6000); /* identical => self-double-spend */
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("K-1   duplicate private nullifier", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("K-1   two identical private nullifiers -> ERR_NF_DUP",
                  s == DNAC_SHIELDED_VERIFY_ERR_NF_DUP, (int)s);
        }

        /* Control: the same shape with DISTINCT nullifiers must pass the check
         * and reach the proof step (so K-1 is not passing for another reason). */
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        st.num_input = 2;
        fill_lanes(st.nf_set[0], 0x6000);
        fill_lanes(st.nf_set[1], 0x6100);
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("K-2   distinct-nullifier control", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("K-2   control: distinct nullifiers reach the proof step",
                  s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        }

        /* One differing LANE is enough to be distinct. */
        base_header(&hdr, DNAC_TX_SHIELDED);
        base_statement(&st, DNAC_TX_SHIELDED);
        st.num_input = 2;
        fill_lanes(st.nf_set[0], 0x6000);
        fill_lanes(st.nf_set[1], 0x6000);
        st.nf_set[1][3] += 1;
        if (assemble(&ctx, &hdr, &st, leg, 0, 1, tx, &tx_len) != 0) {
            check("K-3   one-lane difference control", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("K-3   a single differing lane is NOT a duplicate",
                  s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        }
    }

    /* ══════════════════ L. Transparent-leg decode ══════════════════ */
    printf("\n-- L. transparent-leg decode (byte-level) --\n");
    {
        /* Every case below patches the LEG region of an honest SHIELD
         * transaction, which starts at DNAC_TXW3_BODY_OFF. */
        base_header(&hdr, DNAC_TX_SHIELD);
        base_statement(&st, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        if (assemble(&ctx, &hdr, &st, leg, 1, 1, tx, &tx_len) != 0) {
            check("L-*   leg fixture", 0, -1);
        } else {
            uint8_t *legp = tx + DNAC_TXW3_BODY_OFF;
            uint8_t  save;

            save     = legp[0];
            legp[0]  = 2; /* tleg_version != 1 */
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-1   tleg_version != 1 -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
            legp[0] = save;

            save    = legp[1];
            legp[1] = DNAC_TXW_MAX_INPUTS + 1; /* num_tin cap */
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-2   num_tin > 16 -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
            legp[1] = save;

            /* Duplicate transparent inputs: copy nullifier[0] over
             * nullifier[1]. This is the class the design reserved
             * ERR_TLEG_ORDER (19) for; the shared codec folds it into its one
             * -1, so the native layer reports ERR_TLEG_DECODE — the reserved
             * value stays DECLARED-NOT-ASSIGNED (shielded_verify.h). */
            uint8_t saved_nf[DNAC_TXW_NULLIFIER_LEN];
            memcpy(saved_nf, legp + 2 + DNAC_TXW_NULLIFIER_LEN,
                   DNAC_TXW_NULLIFIER_LEN);
            memcpy(legp + 2 + DNAC_TXW_NULLIFIER_LEN, legp + 2,
                   DNAC_TXW_NULLIFIER_LEN);
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-3   duplicate transparent input -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);

            /* Descending order (swap the two, keeping them distinct). */
            memcpy(legp + 2 + DNAC_TXW_NULLIFIER_LEN, legp + 2,
                   DNAC_TXW_NULLIFIER_LEN);
            memcpy(legp + 2, saved_nf, DNAC_TXW_NULLIFIER_LEN);
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-4   descending transparent inputs -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
            /* restore ascending order */
            memcpy(legp + 2, legp + 2 + DNAC_TXW_NULLIFIER_LEN,
                   DNAC_TXW_NULLIFIER_LEN);
            memcpy(legp + 2 + DNAC_TXW_NULLIFIER_LEN, saved_nf,
                   DNAC_TXW_NULLIFIER_LEN);

            /* Zero-amount transparent output: the amount sits at
             * fp(129) into the first tout, which follows the num_tout byte. */
            size_t   tout0 = 2 + (size_t)2 * DNAC_TXW_NULLIFIER_LEN + 1;
            uint8_t *amt   = legp + tout0 + DNAC_TXW_FP_LEN;
            uint8_t  saved_amt[8];
            memcpy(saved_amt, amt, 8);
            memset(amt, 0, 8);
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-5   zero-amount transparent output -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
            memcpy(amt, saved_amt, 8);

            /* num_signers cap: the byte after the single tout. */
            size_t   nsig_off = tout0 + DNAC_TXW3_TLEG_TOUT_LEN;
            uint8_t *nsig     = legp + nsig_off;
            save  = *nsig;
            *nsig = DNAC_TXW_MAX_SIGNERS + 1;
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-6   num_signers > 4 -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
            *nsig = save;

            /* Sanity: after every restore the fixture is honest again. */
            sig_stub_reset(0);
            s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, &out);
            check("L-7   fixture restored -> proof step (stub->DECODE)",
                  s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
        }
    }
    {
        /* Truncated leg: a body that is ONLY a 10-byte leg header claiming 16
         * transparent inputs. The walk cannot be satisfied, so the leg decode
         * rejects — deterministically, before any section byte is read. */
        base_header(&hdr, DNAC_TX_SHIELD);
        uint8_t stub_body[10];
        memset(stub_body, 0, sizeof(stub_body));
        stub_body[0] = DNAC_TXW3_TLEG_VERSION;
        stub_body[1] = DNAC_TXW_MAX_INPUTS; /* needs 1024 bytes, has 8 */
        size_t written = 0;
        if (dnac_txw3_encode(&hdr, stub_body, (uint32_t)sizeof(stub_body), tx,
                             TXBUF_CAP, &written) != 0) {
            check("L-8   truncated leg", 0, -1);
        } else {
            s = dnac_v3_native_verify_stateless(tx, written, &ctx, &out);
            check("L-8   truncated leg walk -> ERR_TLEG_DECODE",
                  s == DNAC_SHIELDED_VERIFY_ERR_TLEG_DECODE, (int)s);
        }
    }
    {
        /* A structurally valid leg followed by a MALFORMED shielded section:
         * the leg decode succeeds, the section decode rejects. Distinct class
         * from L-8, which proves the two decodes report separately. */
        base_header(&hdr, DNAC_TX_SHIELD);
        base_leg(leg, DNAC_TX_SHIELD);
        static uint8_t body2[TXBUF_CAP];
        size_t         leg_len = 0;
        if (dnac_txw3_tleg_encode(leg, body2, sizeof(body2), &leg_len) != 0) {
            check("L-9   leg + malformed section", 0, -1);
        } else {
            memset(body2 + leg_len, 0, 8); /* 8 bytes: far short of 359 */
            size_t written = 0;
            if (dnac_txw3_encode(&hdr, body2, (uint32_t)(leg_len + 8), tx,
                                 TXBUF_CAP, &written) != 0) {
                check("L-9   leg + malformed section", 0, -1);
            } else {
                s = dnac_v3_native_verify_stateless(tx, written, &ctx, &out);
                check("L-9   valid leg + short section -> ERR_DECODE",
                      s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
            }
        }
    }

    /* ══════════════════ M. NULL export argument ══════════════════ */
    printf("\n-- M. optional export argument --\n");
    {
        sig_stub_reset(0);
        (void)build_honest(DNAC_TX_UNSHIELD, &ctx, &hdr, &st, leg, &has_leg, tx,
                           &tx_len);
        s = dnac_v3_native_verify_stateless(tx, tx_len, &ctx, NULL);
        check("M-1   NULL export argument is legal (verdict unchanged)",
              s == DNAC_SHIELDED_VERIFY_ERR_DECODE, (int)s);
    }

    free(leg);
    free(tx);

    printf("------------------------------------------------------------\n");
    if (g_fails == 0) {
        printf("S9 W3 NATIVE VERIFY GATE: GREEN\n");
        printf("  all 3 types reach the REAL proof step (stub blob -> DECODE);\n"
               "  real-proof accepts: test_native_verify_v3_proofs (zk-only)\n");
        printf("  + per-type windows, boundaries, checked arithmetic, mirrors,\n");
        printf("  context provenance, binding, signatures, nullifier dedup and\n");
        printf("  byte-level leg-decode negatives.\n");
        printf("============================================================\n");
        return 0;
    }
    printf("S9 W3 NATIVE VERIFY GATE: RED (%d failures)\n", g_fails);
    return 1;
}
