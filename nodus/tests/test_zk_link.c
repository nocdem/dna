/**
 * @file test_zk_link.c
 * @brief Phase-C C1 — shielded ZK verify stack linkage gate.
 *
 * Proves the S6-roadmap C1 deliverable: libnodus carries the COMPLETE pinned
 * shielded verify chain (dnac_fri_verify_wire_shielded + codec v2 + FRI
 * verifier + transcript/sponge + Merkle-MMCS + Goldilocks field). Calling the
 * entry here forces the linker to pull every object of that chain out of
 * libnodus.a — a missing source in the CMake list is a LINK failure, not a
 * latent C2 surprise.
 *
 * Also pins, from the nodus side, the consensus constants the verifier will
 * gate value on at C2:
 *   T1  dnac_shielded_fri_params() — the six pinned scalars (216-bit set)
 *   T2  fail-closed NULL contract (out_fri_status==NULL -> ERR_NULL)
 *   T3  garbage bytes -> BAD_MAGIC and *out_fri_status stays rejecting
 *   T4  truncated header -> TRUNCATED (decode path exercised end-to-end)
 *   T5  (C2.1) dnac_shielded_verify_statement links out of libnodus.a with
 *       the LINKED libdna sighash (serialize.c) + conf_txbind map, and its
 *       cheap fail-close branches reject (NULL / oversize / count / fee /
 *       txbind — the txbind branch executes the full sighash_v4 recompute).
 *       Positive accept KATs (real production proof) live in the zk suite
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

#include "fri_proof_codec.h"
#include "shielded_fri_params.h"
#include "shielded_verify.h"

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

    /* T2: fail-closed NULL contract (red-team S0-M4). */
    {
        uint8_t junk[8] = {0};
        dnac_fri_codec_status_t cs =
            dnac_fri_verify_wire_shielded(junk, sizeof junk, NULL, NULL);
        int ok = cs == DNAC_FRI_CODEC_ERR_NULL;
        printf("  T2 NULL out_fri_status -> ERR_NULL (fail-closed)  %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T3: garbage bytes are rejected at the magic check; the verdict slot
     * stays at its rejecting preset. */
    {
        uint8_t junk[64];
        memset(junk, 0xA5, sizeof junk);
        dnac_fri_status_t fs = DNAC_FRI_OK; /* must be overwritten */
        dnac_fri_codec_status_t cs =
            dnac_fri_verify_wire_shielded(junk, sizeof junk, NULL, &fs);
        int ok = cs == DNAC_FRI_CODEC_ERR_BAD_MAGIC && fs != DNAC_FRI_OK;
        printf("  T3 garbage wire -> BAD_MAGIC, verdict rejecting   %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T4: correct magic but truncated header -> TRUNCATED. */
    {
        uint8_t hdr[5] = {0x44, 0x5A, 0x4B, 0x46, 0x02}; /* "DZKF" + half ver */
        dnac_fri_status_t fs = DNAC_FRI_OK;
        dnac_fri_codec_status_t cs =
            dnac_fri_verify_wire_shielded(hdr, sizeof hdr, NULL, &fs);
        int ok = cs == DNAC_FRI_CODEC_ERR_TRUNCATED && fs != DNAC_FRI_OK;
        printf("  T4 truncated header -> TRUNCATED                  %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    /* T5 (C2.1): the consensus statement-verify entry + its linked libdna
     * sighash chain link out of libnodus.a, and the cheap wire-side
     * fail-close branches fire on their DISTINCT codes. No real proof here
     * (prover is client-side, deliberately absent from libnodus) — the
     * accept KAT lives in the zk suite. */
    {
        uint8_t chain_id[32];
        memset(chain_id, 0xC1, sizeof chain_id);
        uint8_t junk_blob[16];
        memset(junk_blob, 0xA5, sizeof junk_blob);

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
