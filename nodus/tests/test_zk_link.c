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
 *       equivalent contract is that a NULL required argument fail-closes ->
 *       DNAC_SHIELDED_VERIFY_ERR_NULL.
 *   T3  garbage proof bytes are rejected by the decoder. Was BAD_MAGIC at the
 *       codec; on the v4 entry every codec error is folded into the single
 *       DNAC_SHIELDED_VERIFY_ERR_DECODE class (shielded_verify.h:83), so the
 *       assertion is DECODE. Reaching the decoder at all requires a wire
 *       statement that passes canonicalization + fee + txbind, so this case
 *       ALSO exercises the linked libdna sighash_v4 + conf_txbind_map forward
 *       (T5 only proves they reject).
 *   T4  truncated DZKF header -> the same DECODE class, via a different
 *       decoder branch (magic OK, length/version truncated).
 *   T5  (C2.1) the cheap wire-side fail-close branches reject on their
 *       DISTINCT codes (NULL / oversize / count / fee / txbind). Positive
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
#include "shielded_fri_params.h"
#include "shielded_verify.h"

/* Build a statement whose tx_binding MATCHES its own sighash, so
 * dnac_shielded_verify_statement runs past canonicalization / fee / txbind and
 * actually reaches the DZKF v4 decode of sf->fri_proof. Returns 0 on success.
 * Uses the LINKED libdna dnac_tx_shielded_sighash + conf_txbind_map — never a
 * re-implementation (G-DET-2). */
static int zl_bind_statement(dnac_tx_shielded_fields_t *sf,
                             const uint8_t chain_id[32]) {
    uint8_t  sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t txbind[CONF_TXBIND_LANES];
    if (dnac_tx_shielded_sighash(sf, chain_id, sighash) != 0) return -1;
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

    /* Shared chain_id + a STATEMENT-CONSISTENT wire struct for T3/T4: its
     * tx_binding is derived from its own sighash_v4, so the verify runs past
     * canonicalization / fee / txbind and reaches the DZKF v4 decode. */
    uint8_t chain_id[32];
    memset(chain_id, 0xC1, sizeof chain_id);

    dnac_tx_shielded_fields_t bound;
    memset(&bound, 0, sizeof bound);
    bound.num_input = 1;
    bound.num_output = 1;
    bound.fee = 42;
    const int bound_ok = zl_bind_statement(&bound, chain_id) == 0;
    if (!bound_ok) {
        printf("  !! sighash_v4/txbind fixture FAILED — T3/T4 cannot run\n");
        fails++;
    }

    /* T2: fail-closed NULL contract (red-team S0-M4). The v4 entry returns its
     * verdict by value, so the contract is: a missing REQUIRED argument must
     * reject, never be treated as "nothing to check". */
    {
        dnac_tx_shielded_fields_t sf = bound;
        uint8_t junk[8] = {0};
        sf.fri_proof = junk;
        sf.fri_proof_len = sizeof junk;
        int ok = dnac_shielded_verify_statement(NULL, chain_id, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL &&
                 dnac_shielded_verify_statement(&sf, NULL, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_NULL;
        printf("  T2 NULL sf / NULL chain_id -> ERR_NULL            %s\n",
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
                 dnac_shielded_verify_statement(&sf, chain_id, 42) ==
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
                 dnac_shielded_verify_statement(&sf, chain_id, 42) ==
                     DNAC_SHIELDED_VERIFY_ERR_DECODE;
        printf("  T4 truncated DZKF header -> ERR_DECODE            %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T5 (C2.1): the consensus statement-verify entry + its linked libdna
     * sighash chain link out of libnodus.a, and the cheap wire-side
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
            ok = ok && dnac_shielded_verify_statement(&t, chain_id, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_NULL;
        }
        /* oversize length fail-closes before any blob read */
        {
            dnac_tx_shielded_fields_t t = sf;
            t.fri_proof_len = 0xFFFFFFFFu;
            ok = ok && dnac_shielded_verify_statement(&t, chain_id, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_OVERSIZE;
        }
        /* count range */
        {
            dnac_tx_shielded_fields_t t = sf;
            t.num_input = 0;
            ok = ok && dnac_shielded_verify_statement(&t, chain_id, 42) ==
                           DNAC_SHIELDED_VERIFY_ERR_COUNT;
        }
        /* fee != committed_fee (D7.2) — ERR_FEE, so the fee gate fires
         * BEFORE the txbind recompute */
        ok = ok && dnac_shielded_verify_statement(&sf, chain_id, 41) ==
                       DNAC_SHIELDED_VERIFY_ERR_FEE;
        /* txbind mismatch — executes the LINKED dnac_tx_shielded_sighash +
         * conf_txbind_map over the wire fields (all-zero tx_binding cannot
         * match a real digest mapping except with prob ~2^-256) */
        ok = ok && dnac_shielded_verify_statement(&sf, chain_id, 42) ==
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
