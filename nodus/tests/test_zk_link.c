/**
 * @file test_zk_link.c
 * @brief Phase-C C1 — shielded ZK verify stack linkage gate.
 *
 * Proves the S6-roadmap C1 deliverable: libnodus carries the COMPLETE pinned
 * shielded verify chain. Calling the consensus entry here forces the linker to
 * pull every object of that chain out of libnodus.a — a missing source in the
 * CMake list is a LINK failure, not a latent C3 surprise.
 *
 * d4.d (2026-07-26) — RE-ANCHORED. T2/T3/T4 used to drive the v3 wrapper
 * dnac_fri_verify_wire_shielded, which is deleted along with the whole v3
 * uni-stark path. They now drive the SAME chain through the real consensus
 * entry dnac_shielded_verify_statement (shielded_verify.h), which decodes with
 * dnac_batch_wire_decode (DZKF v4) and verifies with dnac_batch_verify.
 * The pulled object set is NOT larger than before: T5 already called this same
 * entry (shielded_verify.c has been on the batched path since d4.c), so the
 * batched chain — codec + batched verify + batched priming + LogUp +
 * constraint fold + the agg fold AIR — was already forced out of libnodus.a.
 * What changes is that the set no longer includes the deleted v3 wrapper, and
 * that T3/T4 now exercise the LIVE decoder instead of a retired one.
 * Each case keeps its original intent:
 *   T1  dnac_shielded_fri_params() — the six pinned scalars (216-bit set).
 *       UNCHANGED.
 *   T2  fail-closed NULL contract. Was "NULL out_fri_status must not swallow
 *       the verdict"; the v4 entry returns its verdict by value, so the
 *       equivalent contract is that a NULL required argument fail-closes.
 *       ⚠ LEDGER-V2 S8 Gate 2 SPLIT this into two codes: a NULL `sf` is still
 *       DNAC_SHIELDED_VERIFY_ERR_NULL, but the second argument is no longer a
 *       chain_id — it is the dnac_shielded_verify_ctx_t, and a NULL context
 *       means "no declared statement version", i.e.
 *       DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION (shielded_verify.h:128-136).
 *   T3  garbage proof bytes are rejected by the decoder. Was BAD_MAGIC at the
 *       codec; on the v4 entry every codec error is folded into the single
 *       DNAC_SHIELDED_VERIFY_ERR_DECODE class (shielded_verify.h:83), so the
 *       assertion is DECODE. Reaching the decoder at all requires a wire
 *       statement that passes canonicalization + fee + txbind, so this case
 *       ALSO exercises the linked shared sighash_v5 + conf_txbind_map forward
 *       (T5 only proves they reject).
 *   T4  truncated DZKF header -> the same DECODE class, via a different
 *       decoder branch (magic OK, length/version truncated).
 *   T5  (C2.1) the cheap wire-side fail-close branches reject on their
 *       DISTINCT codes (NULL / oversize / count / fee / txbind). ⚠ S8: the
 *       count probe moved from num_input == 0 (now the LEGAL SHIELD shape) to
 *       num_input == MAX+1. Positive
 *       accept KATs (real production proof) live in the zk suite
 *       (shared/crypto/zk tests/test_shielded_verify.c) — they need a prover.
 *
 * NO consensus behavior is exercised — nothing in the witness calls these yet
 * (C2.2 wires the unconditional type-11 REJECT; the accept-flip is C3).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "conf_txbind.h"
#include "dnac/tx_wire.h" /* dna_exec_context_t + dnac_sighash_v5 (SHARED codec) */
#include "shielded_fri_params.h"
#include "shielded_verify.h"

/* Build a statement whose tx_binding MATCHES its own sighash, so
 * dnac_shielded_verify_statement runs past canonicalization / fee / txbind and
 * actually reaches the DZKF v4 decode of sf->fri_proof. Returns 0 on success.
 * S8 Gate 2: the binding moved off the libdna sighash_v4 symbol onto the SHARED
 * sighash_v5 codec (shared/dnac/tx_wire.c, compiled into libnodus AND libdna) —
 * assembled exactly as shielded_verify.c:222-270 does, with wire_version and
 * sect_version PINNED and tx_binding excluded from its own preimage. Uses the
 * LINKED codec + conf_txbind_map, never a re-implementation (G-DET-2). */
static int zl_bind_statement(dnac_tx_shielded_fields_t *sf,
                             const dnac_shielded_verify_ctx_t *vctx) {
    dna_exec_context_t ectx;
    if (dna_exec_context_init(&ectx, vctx->chain_id, vctx->domain_id,
                              vctx->pool_id, vctx->tx_type,
                              (uint8_t)DNAC_TXW3_WIRE_VERSION,
                              vctx->ruleset_version,
                              vctx->statement_version) != 0)
        return -1;

    dnac_txw3_shielded_t st;
    memset(&st, 0, sizeof st);
    st.sect_version = (uint8_t)DNAC_TXW3_SECT_VERSION;
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
        st.anchor[j] = sf->anchor[j];
    st.num_input = sf->num_input;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            st.nf_set[s][j] = sf->nf_set[s][j];
    st.num_output = sf->num_output;
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            st.output_commit[s][j] = sf->output_commit[s][j];
    st.fee = sf->fee;
    st.boundary_in = sf->boundary_in;
    st.boundary_out = sf->boundary_out;
    st.expiry_height = sf->expiry_height;
    st.fri_len = sf->fri_proof_len;

    uint8_t tleg[DNAC_TXW_HASH_LEN], ctc[DNAC_TXW_HASH_LEN];
    if (dnac_tleg_commit_empty(tleg) != 0 || dnac_ct_commit_empty(ctc) != 0)
        return -1;

    uint8_t  sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t txbind[CONF_TXBIND_LANES];
    if (dnac_sighash_v5(&ectx, (uint8_t)DNAC_TXW3_SECT_VERSION,
                        vctx->ruleset_hash, &st, tleg, ctc, sighash) != 0)
        return -1;
    if (!conf_txbind_map(sighash, txbind)) return -1;
    for (unsigned j = 0; j < CONF_TXBIND_LANES; j++) sf->tx_binding[j] = txbind[j];
    return 0;
}

int main(void) {
    int fails = 0;
    printf("=== Phase-C C1: shielded ZK verify linkage gate ===\n");

    /* T1: pinned consensus params visible + exact from the nodus build. */
    {
        const dnac_fri_params_t *p = dnac_shielded_fri_params();
        int ok = p != NULL &&
                 p->log_blowup == DNAC_SHIELDED_FRI_LOG_BLOWUP &&
                 p->log_final_poly_len == DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN &&
                 p->max_log_arity == DNAC_SHIELDED_FRI_MAX_LOG_ARITY &&
                 p->num_queries == DNAC_SHIELDED_FRI_NUM_QUERIES &&
                 p->commit_proof_of_work_bits == DNAC_SHIELDED_FRI_COMMIT_POW_BITS &&
                 p->query_proof_of_work_bits == DNAC_SHIELDED_FRI_QUERY_POW_BITS &&
                 dnac_fri_params_eq(p, p);
        printf("  T1 pinned shielded FRI params (100q/16-bit PoW)   %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* S8 Gate 2: the consensus-authoritative binding context replaces the bare
     * chain_id. Values are arbitrary-but-fixed — this gate proves the chain
     * LINKS and fails closed, not that any particular context is admissible. */
    dnac_shielded_verify_ctx_t vctx;
    memset(&vctx, 0, sizeof vctx);
    memset(vctx.chain_id, 0xC1, sizeof vctx.chain_id);
    vctx.domain_id = DNA_DOMAIN_CORE;
    vctx.pool_id = DNAC_SHIELDED_POOL_V1;
    vctx.tx_type = (uint8_t)DNAC_TXW_TYPE_SHIELDED; /* 11 */
    vctx.ruleset_version = 1u;
    vctx.statement_version = DNAC_SHIELDED_STATEMENT_VERSION;
    memset(vctx.ruleset_hash, 0x5A, sizeof vctx.ruleset_hash);

    /* A STATEMENT-CONSISTENT wire struct for T3/T4: its tx_binding is derived
     * from its own sighash_v5, so the verify runs past canonicalization / fee /
     * txbind and reaches the DZKF v4 decode. Both transparent legs are inside
     * the frozen B2 range, so the S8 boundary gate does not fire first. */
    dnac_tx_shielded_fields_t bound;
    memset(&bound, 0, sizeof bound);
    bound.num_input = 1;
    bound.num_output = 1;
    bound.fee = 42;
    bound.boundary_in = 0;
    bound.boundary_out = 0;
    bound.expiry_height = 0;
    const int bound_ok = zl_bind_statement(&bound, &vctx) == 0;
    if (!bound_ok) {
        printf("  !! sighash_v5/txbind fixture FAILED — T3/T4 cannot run\n");
        fails++;
    }

    /* T2: fail-closed NULL contract (red-team S0-M4). The v4 entry returns its
     * verdict by value, so the contract is: a missing REQUIRED argument must
     * reject, never be treated as "nothing to check".
     * ⚠ S8 Gate 2 CHANGED the second leg's expected code. It used to be
     * `dnac_shielded_verify_statement(&sf, NULL, 42) == ERR_NULL` with a bare
     * chain_id in that slot; the second argument is now the CONTEXT, and a NULL
     * context is ERR_STATEMENT_VERSION (there is no declared version at all —
     * shielded_verify.c:157-160). A wrong declared version is the same class,
     * asserted here too so the version pin itself is linked in. */
    {
        dnac_tx_shielded_fields_t sf = bound;
        uint8_t junk[8] = {0};
        sf.fri_proof = junk;
        sf.fri_proof_len = sizeof junk;
        dnac_shielded_verify_ctx_t badv = vctx;
        badv.statement_version = DNAC_SHIELDED_STATEMENT_VERSION + 1u;
        int ok = dnac_shielded_verify_statement(NULL, &vctx, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL &&
                 dnac_shielded_verify_statement(&sf, NULL, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION &&
                 dnac_shielded_verify_statement(&sf, &badv, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION;
        printf("  T2 NULL sf -> ERR_NULL; NULL/bad vctx -> VERSION  %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T3: garbage proof bytes on a statement-consistent wire — the DZKF v4
     * decoder rejects at the magic check (folded into ERR_DECODE). Pulls the
     * codec + the txbind/sighash chain forward, not just their reject paths. */
    {
        dnac_tx_shielded_fields_t sf = bound;
        uint8_t junk[64];
        memset(junk, 0xA5, sizeof junk);
        sf.fri_proof = junk;
        sf.fri_proof_len = sizeof junk;
        int ok = bound_ok &&
                 dnac_shielded_verify_statement(&sf, &vctx, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_DECODE;
        printf("  T3 garbage proof wire -> ERR_DECODE (bad magic)   %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T4: correct magic but a truncated header — a DIFFERENT decoder branch
     * (the 6-byte header availability check) reaching the same class. */
    {
        dnac_tx_shielded_fields_t sf = bound;
        uint8_t hdr[5] = {0x44, 0x5A, 0x4B, 0x46, 0x04}; /* "DZKF" + half ver */
        sf.fri_proof = hdr;
        sf.fri_proof_len = sizeof hdr;
        int ok = bound_ok &&
                 dnac_shielded_verify_statement(&sf, &vctx, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_DECODE;
        printf("  T4 truncated DZKF header -> ERR_DECODE            %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T5 (C2.1): the consensus statement-verify entry + its linked SHARED
     * sighash_v5 chain link out of libnodus.a, and the cheap wire-side
     * fail-close branches fire on their DISTINCT codes. No real proof here
     * (prover is client-side, deliberately absent from libnodus) — the
     * accept KAT lives in the zk suite. */
    {
        uint8_t junk_blob[16];
        memset(junk_blob, 0xA5, sizeof junk_blob);

        /* NOTE: deliberately NOT the `bound` fixture — tx_binding stays
         * all-zero here so the txbind gate below actually fires. */
        dnac_tx_shielded_fields_t sf;
        memset(&sf, 0, sizeof sf);
        sf.num_input = 1;
        sf.num_output = 1;
        sf.fee = 42;
        sf.fri_proof = junk_blob;
        sf.fri_proof_len = sizeof junk_blob;

        int ok = 1;
        /* NULL blob */
        {
            dnac_tx_shielded_fields_t t = sf;
            t.fri_proof = NULL;
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_NULL;
        }
        /* oversize length fail-closes before any blob read */
        {
            dnac_tx_shielded_fields_t t = sf;
            t.fri_proof_len = 0xFFFFFFFFu;
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_OVERSIZE;
        }
        /* count range.
         * ⚠ S8 Gate 2 CHANGED this leg. It used to set num_input = 0 and expect
         * ERR_COUNT; num_input == 0 is now the LEGAL SHIELD shape
         * (shielded_verify.c:162-169), so the out-of-range probe moved to the
         * UPPER bound. The zero-input semantics (nf slots / anchor) are asserted
         * in the zk suite's T-S1/T-S2, not here — this file stays a linkage +
         * fail-close gate. */
        {
            dnac_tx_shielded_fields_t t = sf;
            t.num_input = DNAC_SHIELDED_MAX_INPUTS + 1;
            ok = ok && dnac_shielded_verify_statement(&t, &vctx, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_COUNT;
        }
        /* fee != committed_fee (D7.2) — ERR_FEE, so the fee gate fires
         * BEFORE the txbind recompute */
        ok = ok && dnac_shielded_verify_statement(&sf, &vctx, 41) ==
                       DNAC_SHIELDED_VERIFY_ERR_FEE;
        /* txbind mismatch — executes the LINKED dnac_sighash_v5 +
         * conf_txbind_map over the wire fields (all-zero tx_binding cannot
         * match a real digest mapping except with prob ~2^-256) */
        ok = ok && dnac_shielded_verify_statement(&sf, &vctx, 42) ==
                       DNAC_SHIELDED_VERIFY_ERR_TXBIND;
        printf("  T5 C2.1 statement-verify chain links, fails closed %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    if (fails == 0) {
        printf("ZK LINKAGE GATE: GREEN — pinned shielded verify chain links "
               "and fails closed\n");
        return 0;
    }
    printf("ZK LINKAGE GATE: RED (%d failures)\n", fails);
    return 1;
}
