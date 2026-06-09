/**
 * @file test_stark_priming_integrated.c
 * @brief P6 integrated guard — DZKS -> DZKF -> priming -> dnac_fri_verify.
 *
 * For each DZKS vector argument, exercises the full B8 integration on the DNAC
 * stack (no STARK constraint check — priming + FRI only):
 *   1. dnac_stark_proof_decode  (DZKS wrapper -> degree_bits, public_values, inner DZKF)
 *   2. dnac_fri_proof_decode    (inner DZKF -> params, proof, CommitmentWithOpeningPoints)
 *   3. dnac_stark_prime_transcript  (priming input rebuilt from the decoded coms + scalars)
 *   4. assert the DERIVED zeta/zeta_next equal the wire opening points (verifier-derived,
 *      not wire-trusted — they must coincide for a valid proof)
 *   5. dnac_fri_verify  -> DNAC_FRI_OK
 *
 * Permanent regression guard for the FRI terminal-index fix: requires at least one
 * vector with log_final_poly_len > 0 (FibonacciAir). With the pre-fix verifier
 * (terminal Horner over the UNSHIFTED domain_index), that case returns
 * FINAL_POLY_MISMATCH; with the fix it returns DNAC_FRI_OK. Also exercises the
 * main_next=false / trace_next-absent path when a single-row vector is supplied.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_proof_codec.h"
#include "fri_verifier.h"
#include "stark_priming.h"
#include "stark_proof_codec.h"
#include "transcript.h"

/* ===== minimal JSON: extract a quoted-string value of `key` after `anchor` ===== */
static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *b = (char *)malloc((size_t)sz + 1);
    if (!b) { fclose(fp); return NULL; }
    size_t got = fread(b, 1, (size_t)sz, fp);
    fclose(fp);
    b[got] = '\0';
    if (out_len) *out_len = got;
    return b;
}
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint8_t *hex_to_buf(const char *hex, size_t *out_len) {
    size_t hl = strlen(hex);
    if (hl % 2) return NULL;
    size_t n = hl / 2;
    uint8_t *o = (uint8_t *)malloc(n ? n : 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(hex[2 * i]), lo = hexnib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(o); return NULL; }
        o[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return o;
}
/* Read the DZKS wire bytes from the vector's "valid":{...,"wire_hex":"..."} block. */
static uint8_t *read_valid_wire(const char *path, size_t *out_len) {
    size_t sl = 0;
    char *src = slurp(path, &sl);
    if (!src) return NULL;
    const char *v = strstr(src, "\"valid\"");
    const char *base = v ? v : src;
    const char *k = strstr(base, "\"wire_hex\"");
    uint8_t *out = NULL;
    if (k) {
        const char *colon = strchr(k, ':');
        const char *q1 = colon ? strchr(colon, '"') : NULL;
        const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
        if (q1 && q2) {
            size_t n = (size_t)(q2 - (q1 + 1));
            char *hex = (char *)malloc(n + 1);
            memcpy(hex, q1 + 1, n);
            hex[n] = '\0';
            out = hex_to_buf(hex, out_len);
            free(hex);
        }
    }
    free(src);
    return out;
}

#define MAXCH 16

/* Returns 0 on full success; else number of failures. Fills shape out-params. */
static int run_integrated(const char *path, int *out_log_final_poly_len,
                          int *out_has_trace_next, int *out_ok) {
    int fails = 0;
    *out_ok = 0;
    size_t dlen = 0;
    uint8_t *dzks = read_valid_wire(path, &dlen);
    if (!dzks) { fprintf(stderr, "MISMATCH %s stage=read_vector: cannot read valid.wire_hex\n", path); return 1; }

    /* 1. DZKS decode */
    dnac_stark_wire_decoded_t *sw = NULL;
    dnac_stark_wire_status_t ss = dnac_stark_proof_decode(dzks, dlen, &sw);
    if (ss != DNAC_STARK_WIRE_OK || !sw) {
        fprintf(stderr, "MISMATCH %s stage=DZKS_decode: status=%d (want 0)\n", path, (int)ss);
        free(dzks);
        return 1;
    }

    /* 2. inner DZKF decode */
    dnac_fri_wire_package_t *pkg = NULL;
    dnac_fri_codec_status_t cs = dnac_fri_proof_decode(sw->inner_dzkf, sw->inner_dzkf_len, &pkg);
    if (cs != DNAC_FRI_CODEC_OK || !pkg) {
        fprintf(stderr, "MISMATCH %s stage=DZKF_decode: codec_status=%d (want 0)\n", path, (int)cs);
        dnac_stark_wire_free(sw);
        free(dzks);
        return 1;
    }
    const dnac_fri_params_t *params = dnac_fri_wire_params(pkg);
    const dnac_fri_proof_t  *proof  = dnac_fri_wire_proof(pkg);
    size_t nc = 0;
    const dnac_fri_commitment_with_opening_points_t *coms = dnac_fri_wire_commitments(pkg, &nc);

    /* coms order = [trace, quotient] (verifier.rs:403-458, non-ZK). */
    if (nc != 2) {
        fprintf(stderr, "MISMATCH %s stage=coms: num_commitments=%zu (want 2: trace+quotient)\n", path, nc);
        fails++;
    }
    const dnac_fri_matrix_openings_t *trace_mat = &coms[0].matrices[0];
    int has_next = (trace_mat->num_points == 2);
    *out_has_trace_next = has_next;
    *out_log_final_poly_len = (int)params->log_final_poly_len;

    /* 3. rebuild the priming input from decoded coms + DZKS scalars. */
    const gold_fp2_t *qcptr[MAXCH];
    size_t            qclen[MAXCH];
    size_t num_qc = coms[1].num_matrices;
    if (num_qc > MAXCH) num_qc = MAXCH;
    for (size_t c = 0; c < num_qc; c++) {
        qcptr[c] = coms[1].matrices[c].points[0].claimed_evals;
        qclen[c] = coms[1].matrices[c].points[0].num_claimed_evals;
    }
    dnac_stark_priming_input_t in;
    memset(&in, 0, sizeof in);
    in.degree_bits = sw->degree_bits;
    in.is_zk = 0;
    in.preprocessed_width = 0;
    in.trace_commit = coms[0].commitment;
    in.quotient_commit = coms[1].commitment;
    in.public_values = sw->public_values;
    in.num_public_values = sw->num_public_values;
    in.trace_local = trace_mat->points[0].claimed_evals;
    in.trace_local_len = trace_mat->points[0].num_claimed_evals;
    in.trace_next = has_next ? trace_mat->points[1].claimed_evals : NULL;
    in.trace_next_len = has_next ? trace_mat->points[1].num_claimed_evals : 0;
    in.quotient_chunks = qcptr;
    in.quotient_chunk_lens = qclen;
    in.num_quotient_chunks = num_qc;

    /* 4. prime a fresh transcript (production default seed = wire init_state). */
    dnac_transcript_t *t = dnac_transcript_init_default();
    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof out);
    dnac_stark_priming_status_t ps = dnac_stark_prime_transcript(t, &in, &out);
    if (ps != DNAC_STARK_PRIMING_OK) {
        fprintf(stderr, "MISMATCH %s stage=priming: status=%d (want 0)\n", path, (int)ps);
        fails++;
    }
    /* derived zeta/zeta_next MUST equal the wire opening points (verifier-derived). */
    if (!gold_fp2_eq(out.zeta, trace_mat->points[0].point)) {
        fprintf(stderr, "MISMATCH %s stage=coms_assembly: derived zeta != wire trace point[0]\n", path);
        fails++;
    }
    if (has_next && !gold_fp2_eq(out.zeta_next, trace_mat->points[1].point)) {
        fprintf(stderr, "MISMATCH %s stage=coms_assembly: derived zeta_next != wire trace point[1]\n", path);
        fails++;
    }

    /* 5. FRI verify on the primed transcript. */
    dnac_fri_status_t fs = dnac_fri_verify(params, proof, t, coms, nc);
    if (fs != DNAC_FRI_OK) {
        fprintf(stderr, "MISMATCH %s stage=FRI_verify: dnac_fri_verify=%d (want 0=DNAC_FRI_OK) "
                "[log_blowup=%zu log_final_poly_len=%zu trace_points=%d]\n",
                path, (int)fs, params->log_blowup, params->log_final_poly_len, has_next ? 2 : 1);
        fails++;
    } else {
        *out_ok = 1;
    }

    printf("  [%s] %s: DZKS+DZKF decode OK | priming OK | dnac_fri_verify=%s | "
           "log_blowup=%zu log_final_poly_len=%zu | trace_next=%s | commitments=%zu | quotient_chunks=%zu\n",
           fails ? "FAIL" : "OK  ", path, (fs == DNAC_FRI_OK) ? "DNAC_FRI_OK" : "ERR",
           params->log_blowup, params->log_final_poly_len, has_next ? "present" : "ABSENT", nc, num_qc);

    dnac_transcript_free(t);
    dnac_fri_wire_free(pkg);
    dnac_stark_wire_free(sw);
    free(dzks);
    return fails;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <stark_proof_wire.json> [stark_proof_wire_no_next.json ...]\n", argv[0]);
        return 2;
    }
    int total_fails = 0;
    int saw_lfp_gt0 = 0;       /* log_final_poly_len > 0 regression guard hit */
    int saw_main_next_false = 0; /* trace_next absent path hit */
    int n_no_next_args = argc - 2; /* args after the first are expected main_next=false vectors */

    printf("P6 integrated: DZKS -> DZKF -> priming -> dnac_fri_verify\n");
    for (int i = 1; i < argc; i++) {
        int lfp = 0, has_next = 0, ok = 0;
        total_fails += run_integrated(argv[i], &lfp, &has_next, &ok);
        if (ok && lfp > 0) saw_lfp_gt0 = 1;
        if (ok && !has_next) saw_main_next_false = 1;
    }

    /* The terminal-index fix is only guarded by a log_final_poly_len > 0 case. */
    if (!saw_lfp_gt0) {
        fprintf(stderr, "MISMATCH guard: no vector verified with log_final_poly_len>0 "
                "(the terminal domain_index fix would be UNGUARDED)\n");
        total_fails++;
    }
    /* If main_next=false vectors were supplied, at least one must have exercised it. */
    if (n_no_next_args > 0 && !saw_main_next_false) {
        fprintf(stderr, "MISMATCH guard: main_next=false vector supplied but trace_next-absent path not exercised\n");
        total_fails++;
    }

    if (total_fails) {
        fprintf(stderr, "test_stark_priming_integrated: %d FAIL(s)\n", total_fails);
        return 1;
    }
    printf("test_stark_priming_integrated: PASS\n");
    printf("  log_final_poly_len>0 regression guard: HELD (terminal domain_index fix permanently guarded).\n");
    if (saw_main_next_false)
        printf("  main_next=false / trace_next-absent path: verified (DNAC_FRI_OK, no zeta_next trace point).\n");
    return 0;
}
