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
 *
 * NO consensus behavior is exercised — nothing in the witness calls this yet
 * (that is C2). This is linkage + constant pinning only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fri_proof_codec.h"
#include "shielded_fri_params.h"

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

    if (fails == 0) {
        printf("ZK LINKAGE GATE: GREEN — pinned shielded verify chain links "
               "and fails closed\n");
        return 0;
    }
    printf("ZK LINKAGE GATE: RED (%d failures)\n", fails);
    return 1;
}
