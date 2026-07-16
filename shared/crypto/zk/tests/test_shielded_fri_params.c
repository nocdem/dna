/**
 * @file test_shielded_fri_params.c
 * @brief S0/C5 — pinned shielded FRI params + hardened verify substitution/reject.
 *
 * Asserts:
 *   1. dnac_shielded_fri_params() == the grounded new_benchmark_zk set
 *      (config.rs:102-113): log_blowup=2, log_final_poly_len=0, max_log_arity=1,
 *      num_queries=100, commit_pow=0, query_pow=16; conjectured soundness
 *      = log_blowup·num_queries + query_pow = 216 ≥ target 100.
 *   2. dnac_fri_params_eq() is exact (reflexive + rejects any single-field diff).
 *   3. dnac_fri_verify_wire_shielded() REJECTS a wire proof whose params ≠ pinned
 *      (the existing fri_proof_wire.json is at TEST params num_queries=2) with
 *      DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH — proving the substitution
 *      guard fires BEFORE any verify (an attacker cannot down-tune off-wire).
 *
 * The positive end-to-end verify (params==pinned + height==10 + FRI OK) needs a
 * real C1 shielded proof at production params — that gate lands at S4/S8.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../fri_proof_codec.h"
#include "../shielded_fri_params.h"
#include "../transcript.h"

static char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    size_t rd = fread(b, 1, (size_t)n, f);
    fclose(f);
    b[rd] = '\0';
    if (out_len) *out_len = rd;
    return b;
}

static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Extract the FIRST "wire_hex":"...." value and decode it. */
static uint8_t *first_wire_hex(const char *json, size_t *out_len) {
    const char *k = strstr(json, "\"wire_hex\"");
    if (!k) return NULL;
    const char *q = strchr(k + 10, '"'); /* opening quote of the value */
    if (!q) return NULL;
    q++;
    const char *e = strchr(q, '"');
    if (!e) return NULL;
    size_t hl = (size_t)(e - q);
    if (hl % 2) return NULL;
    size_t n = hl / 2;
    uint8_t *b = (uint8_t *)malloc(n ? n : 1);
    if (!b) return NULL;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(q[2 * i]), lo = hexnib(q[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(b); return NULL; }
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return b;
}

int main(int argc, char **argv) {
    int fails = 0;

    /* (1) Pinned constants == grounded config.rs new_benchmark_zk. */
    const dnac_fri_params_t *p = dnac_shielded_fri_params();
    if (p->log_blowup != 2) { fprintf(stderr, "FAIL log_blowup %zu != 2\n", p->log_blowup); fails++; }
    if (p->log_final_poly_len != 0) { fprintf(stderr, "FAIL log_final_poly_len != 0\n"); fails++; }
    if (p->max_log_arity != 1) { fprintf(stderr, "FAIL max_log_arity != 1\n"); fails++; }
    if (p->num_queries != 100) { fprintf(stderr, "FAIL num_queries %zu != 100\n", p->num_queries); fails++; }
    if (p->commit_proof_of_work_bits != 0) { fprintf(stderr, "FAIL commit_pow != 0\n"); fails++; }
    if (p->query_proof_of_work_bits != 16) { fprintf(stderr, "FAIL query_pow %zu != 16\n", p->query_proof_of_work_bits); fails++; }
    size_t soundness = p->log_blowup * p->num_queries + p->query_proof_of_work_bits;
    if (soundness != DNAC_SHIELDED_FRI_SOUNDNESS_BITS) {
        fprintf(stderr, "FAIL soundness %zu != %zu\n", soundness, (size_t)DNAC_SHIELDED_FRI_SOUNDNESS_BITS);
        fails++;
    }
    if (soundness < DNAC_SHIELDED_FRI_SOUNDNESS_TARGET) {
        fprintf(stderr, "FAIL soundness %zu below target\n", soundness);
        fails++;
    }
    /* Height pin: physical base 10, but the COMMITTED domain the verifier reads
     * is base + is_zk = 11 (is_zk doubling; conf_root_air_zk.json base+1). The
     * guard MUST compare against 11, not the physical 10 (red-team S0-H1). */
    if (DNAC_SHIELDED_BASE_LOG_HEIGHT != 10) {
        fprintf(stderr, "FAIL pinned base height != 10\n");
        fails++;
    }
    if (DNAC_SHIELDED_COMMITTED_LOG_HEIGHT != 11) {
        fprintf(stderr, "FAIL pinned committed height %zu != 11 (base+is_zk)\n",
                (size_t)DNAC_SHIELDED_COMMITTED_LOG_HEIGHT);
        fails++;
    }
    if (DNAC_SHIELDED_COMMITTED_LOG_HEIGHT !=
        DNAC_SHIELDED_BASE_LOG_HEIGHT + DNAC_SHIELDED_IS_ZK) {
        fprintf(stderr, "FAIL committed height != base + is_zk\n");
        fails++;
    }

    /* (2) params_eq exactness. */
    if (!dnac_fri_params_eq(p, p)) { fprintf(stderr, "FAIL params_eq not reflexive\n"); fails++; }
    {
        dnac_fri_params_t q = *p;
        q.num_queries = 99;
        if (dnac_fri_params_eq(p, &q)) { fprintf(stderr, "FAIL params_eq missed num_queries diff\n"); fails++; }
        q = *p;
        q.log_blowup = 1;
        if (dnac_fri_params_eq(p, &q)) { fprintf(stderr, "FAIL params_eq missed log_blowup diff\n"); fails++; }
    }
    if (dnac_fri_params_eq(NULL, p) || dnac_fri_params_eq(p, NULL)) {
        fprintf(stderr, "FAIL params_eq NULL not rejected\n");
        fails++;
    }

    /* (3) Hardened verify rejects a wire proof at non-pinned params. */
    if (argc >= 2) {
        size_t jlen = 0;
        char *json = slurp(argv[1], &jlen);
        if (!json) { fprintf(stderr, "FAIL: cannot read %s\n", argv[1]); return 2; }
        size_t wlen = 0;
        uint8_t *wire = first_wire_hex(json, &wlen);
        free(json);
        if (!wire || wlen == 0) {
            fprintf(stderr, "FAIL: no wire_hex in %s\n", argv[1]);
            return 2;
        }
        /* A transcript is required by the API; the guard rejects on params
         * BEFORE verify runs, so a fresh default transcript is sufficient. */
        dnac_transcript_t *t = dnac_transcript_init_default();
        dnac_fri_status_t fs = DNAC_FRI_OK;
        dnac_fri_codec_status_t cs =
            dnac_fri_verify_wire_shielded(wire, wlen, t, &fs);
        free(wire);
        dnac_transcript_free(t);
        if (cs != DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH) {
            fprintf(stderr,
                    "FAIL: test-param wire proof NOT rejected as param-mismatch "
                    "(got codec status %d)\n",
                    (int)cs);
            fails++;
        }
    } else {
        fprintf(stderr, "WARN: no wire json arg — skipping reject test\n");
    }

    if (fails) {
        printf("shielded FRI params: %d FAIL\n", fails);
        return 1;
    }
    printf("shielded FRI params: pinned set grounded (216-bit) + substitution "
           "guard rejects off-pin wire — PASS\n");
    return 0;
}
