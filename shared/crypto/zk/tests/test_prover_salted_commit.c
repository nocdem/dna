/**
 * @file test_prover_salted_commit.c
 * @brief B1 Stage-2 M3b — pure-C SALTED trace-commitment byte-match vs the REAL
 *        Plonky3 salted proof (82cfad73). The core new prover primitive.
 *
 * Reconstructs the combined-conf-AIR trace LDE via the PUBLIC prover stages
 * (conf_root_air_generate -> dnac_prover_randomize_trace ->
 * dnac_prover_coset_lde_bitrev — the same S1/S2 the Stage-2 conf prover runs),
 * then builds the SALTED input-mmcs leaves (leaf = committed row ‖ SALT_ELEMS
 * salts; hiding_mmcs.rs:167-170) and commits them. The resulting root MUST equal
 * the REAL salted proof's commitments.trace.
 *
 * Salt draw model (GROUNDED + cross-checked vs conf_root_air_salted.json):
 *   - the input HidingValMmcs rng is a FRESH SmallRng(1) (make_hiding_mmcs(1)),
 *     consumed FIRST by the trace commit;
 *   - the trace LDE has height 8h; the salt matrix is RowMajorMatrix::rand(
 *     rng, 8h, SALT_ELEMS) (hiding_mmcs.rs:129), so committed-leaf-row i gets
 *     salt = draws[2i], draws[2i+1] (SALT_ELEMS=2, row-major);
 *   - the LDE is bit-reversed BEFORE commit (two_adic_pcs.rs:317-324), so salt
 *     row i aligns with the bit-reversed (committed) LDE row i.
 *   Verified: the salted vector's query-0 trace salt == SmallRng(1)[110,111]
 *   (leaf 55), query-1 == [38,39] (leaf 19).
 *   The codeword-randomize rng (stream C) is ALSO a fresh SmallRng(1), so both
 *   the trace_draws (S2 randomize) and the salts come from the SAME
 *   smallrng_goldilocks.json sequence at their respective positions.
 *
 * SCOPE: this session proves the SALTED TRACE COMMIT primitive in C. The full
 * salted prover (quotient-chunk + random-poly input-mmcs salts, and the
 * commit-phase FRI-mmcs salt stream, + salted openings + self-verify) is the
 * next increment — see RESUME.md / the M3b design doc.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_root_air.h"
#include "conf_commit_air.h"
#include "field_goldilocks.h"
#include "merkle_smt.h"
#include "stark_prover.h"

/* ---- minimal JSON helpers (hex root + draws array) ---- */
static char *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long s = ftell(f); fseek(f, 0, SEEK_SET);
    if (s < 0) { fclose(f); return NULL; }
    char *b = malloc((size_t)s + 1); if (!b) { fclose(f); return NULL; }
    size_t g = fread(b, 1, (size_t)s, f); fclose(f); b[g] = 0; if (n) *n = g; return b;
}
static int hexnib(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
/* find "key":"<hex>" and decode into buf (cap bytes) */
static int find_hex(const char *j, const char *key, uint8_t *buf, size_t cap) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat); if (!p) return -1;
    p = strchr(p + strlen(pat), '"'); if (!p) return -1; p++;   /* opening quote of value */
    const char *e = strchr(p, '"'); if (!e) return -1;
    size_t hl = (size_t)(e - p); if (hl % 2 || hl / 2 > cap) return -1;
    for (size_t i = 0; i < hl / 2; i++) { int hi = hexnib(p[2*i]), lo = hexnib(p[2*i+1]); if (hi<0||lo<0) return -1; buf[i] = (uint8_t)((hi<<4)|lo); }
    return (int)(hl / 2);
}
/* parse the "draws":[ "n", "n", ... ] array (decimal strings) into out[cap] */
static size_t parse_draws(const char *j, uint64_t *out, size_t cap) {
    const char *p = strstr(j, "\"draws\""); if (!p) return 0;
    p = strchr(p, '['); if (!p) return 0; p++;
    size_t n = 0;
    while (*p && *p != ']') {
        while (*p==' '||*p==','||*p=='\n'||*p=='\r'||*p=='\t') p++;
        if (*p != '"') break;
        p++;
        uint64_t v = strtoull(p, NULL, 10);
        while (*p && *p != '"') p++;
        if (*p == '"') p++;
        if (n < cap) out[n] = v;
        n++;
    }
    return n;
}
static void put_u64_le(uint8_t *b, uint64_t v){ for (int i=0;i<8;i++) b[i]=(uint8_t)(v>>(8*i)); }

/* splitmix64 blind gen — mirror of the oracle dump_conf_root_air_common. */
static uint64_t sm_next(uint64_t *x){
    *x += 0x9e3779b97f4a7c15ULL; uint64_t z = *x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z ^= z >> 31; return z % GOLDILOCKS_P;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <conf_root_air_salted.json> <smallrng_goldilocks.json>\n", argv[0]); return 2; }

    /* ---- h=8 conf instance (must match dump_conf_root_air_salted) ---- */
    const uint64_t outputs[4] = {10, 20, 30, 40};
    const size_t   n_out = 4, height = 8;
    const uint64_t fee = 7;
    const unsigned log_h = 3;
    const size_t   W = CONF_ROOT_WIDTH;      /* 614 */
    const size_t   NR = 4;                    /* num_random_codewords */
    const size_t   RW = W + NR;               /* 618 committed width */
    const size_t   lde_h = height << (2 + 1); /* 8h = 64 (blowup 2 + is_zk 1) */
    const size_t   SALT = 2;

    /* blinds: splitmix seed 0xB11D5EED00000000 ^ height (oracle mirror) */
    uint64_t *blind = malloc(2 * height * sizeof(uint64_t));
    { uint64_t x = 0xB11D5EED00000000ULL ^ (uint64_t)height;
      for (size_t i = 0; i < 2 * height; i++) blind[i] = sm_next(&x); }

    uint64_t claimed = fee; for (size_t i = 0; i < n_out; i++) claimed += outputs[i];

    /* S1: base combined trace (height x 614) */
    uint64_t *base = malloc(height * W * sizeof(uint64_t));
    uint64_t root_out[CONF_COMMIT_C_LANES];
    if (!conf_root_air_generate(outputs, n_out, claimed, fee, blind, log_h, base, root_out)) {
        fprintf(stderr, "conf_root_air_generate failed\n"); return 1;
    }

    /* ---- draws: codeword stream (S2 randomize) + salt stream, both fresh SmallRng(1) ---- */
    size_t rn = 0; char *rj = slurp(argv[2], &rn);
    if (!rj) { fprintf(stderr, "cannot read %s\n", argv[2]); return 2; }
    size_t need = height * (W + 2 * NR);          /* randomize draws = 8*(614+8)=4976 */
    uint64_t *draws = malloc((need > lde_h * SALT ? need : lde_h * SALT) * sizeof(uint64_t) + 16);
    size_t got = parse_draws(rj, draws, need > lde_h * SALT ? need : lde_h * SALT);
    free(rj);
    if (got < need) { fprintf(stderr, "draw stream too short: %zu < %zu\n", got, need); return 2; }

    /* S2: randomize (codeword stream [0:4976]) + coset LDE (bit-reversed) */
    uint64_t *rand_c = malloc((2 * height) * RW * sizeof(uint64_t));
    uint64_t *lde = malloc(lde_h * RW * sizeof(uint64_t));
    if (dnac_prover_randomize_trace(base, height, W, NR, draws, rand_c) != DNAC_PROVER_OK ||
        dnac_prover_coset_lde_bitrev(rand_c, 2 * height, RW, 2, 7, lde) != DNAC_PROVER_OK) {
        fprintf(stderr, "randomize/LDE failed\n"); return 1;
    }

    /* ---- SALTED leaves: committed row i ‖ salt draws[2i],draws[2i+1] ---- */
    const size_t salted_row_bytes = (RW + SALT) * 8;   /* (618+2)*8 = 4960 */
    uint8_t *salted = malloc(lde_h * salted_row_bytes);
    for (size_t i = 0; i < lde_h; i++) {
        uint8_t *o = salted + i * salted_row_bytes;
        for (size_t c = 0; c < RW; c++) put_u64_le(o + c * 8, lde[i * RW + c]);
        put_u64_le(o + RW * 8,       draws[2 * i]);       /* salt 0 (row-major) */
        put_u64_le(o + (RW + 1) * 8, draws[2 * i + 1]);   /* salt 1 */
    }
    dnac_merkle_digest_t root; dnac_merkle_tree_t *tree = NULL;
    if (dnac_merkle_commit(salted, salted_row_bytes, lde_h, &root, &tree) != DNAC_MERKLE_OK) {
        fprintf(stderr, "salted merkle commit failed\n"); return 1;
    }
    dnac_merkle_tree_free(tree);

    /* ---- byte-match the REAL salted proof's trace commitment ---- */
    size_t vn = 0; char *vj = slurp(argv[1], &vn);
    if (!vj) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    uint8_t vroot[DNAC_MERKLE_DIGEST_BYTES];
    if (find_hex(vj, "trace_commit_root_hex", vroot, sizeof vroot) != (int)DNAC_MERKLE_DIGEST_BYTES) {
        fprintf(stderr, "trace_commit_root_hex not found\n"); free(vj); return 1;
    }
    free(vj);

    int ok = memcmp(root.bytes, vroot, DNAC_MERKLE_DIGEST_BYTES) == 0;
    printf("  T1 conf trace LDE reconstructed (64x618, bit-reversed)   %s\n", "PASS");
    printf("  T2 SALTED leaf = row(618) || salt(2) = 4960 B, 64 leaves  %s\n", "PASS");
    printf("  T3 C salted TRACE root == REAL Plonky3 salted proof       %s\n", ok ? "PASS" : "FAIL");

    /* ---- SALTED RANDOM commit byte-match ----
     * Stream A random section: draws[1152 + 2i] for committed row i (h=8:
     * trace 0..128, quotient 128..1152, random 1152..1280). The R draws (stream
     * C) are the R section of the conf draw budget (708h = 5664 for h=8; R =
     * [696h : 708h] = draws[5568 : 5664], 12h = 96). dnac_prover_random_commit
     * builds the R LDE (2h<<blowup = 64 tall, C_CW=6 wide). */
    int rok = 0;
    {
        /* re-read enough draws: need up to R-section end 708h and salt 1280 */
        size_t rn2 = 0; char *rj2 = slurp(argv[2], &rn2);
        size_t big = 708 * height; /* 5664 */
        uint64_t *d2 = malloc(big * sizeof(uint64_t));
        size_t g2 = parse_draws(rj2, d2, big);
        free(rj2);
        if (g2 >= big) {
            const size_t CW = 6;
            const uint64_t *r_draws = d2 + 696 * height; /* stream C R section */
            uint64_t *r_lde = malloc(lde_h * CW * sizeof(uint64_t));
            dnac_merkle_digest_t rr; dnac_merkle_tree_t *rt = NULL;
            if (dnac_prover_random_commit(r_draws, 2 * height, CW, 2, NULL, 0, r_lde, rr.bytes, &rt) == DNAC_PROVER_OK) {
                dnac_merkle_tree_free(rt);
                /* salted commit: leaf i = r_lde row i (CW*8) || salt draws[1152+2i] */
                const size_t rsb = (CW + SALT) * 8;
                uint8_t *rsalted = malloc(lde_h * rsb);
                for (size_t i = 0; i < lde_h; i++) {
                    uint8_t *o = rsalted + i * rsb;
                    for (size_t c = 0; c < CW; c++) put_u64_le(o + c * 8, r_lde[i * CW + c]);
                    put_u64_le(o + CW * 8,       d2[1152 + 2 * i]);
                    put_u64_le(o + (CW + 1) * 8, d2[1152 + 2 * i + 1]);
                }
                dnac_merkle_digest_t rs; dnac_merkle_tree_t *rst = NULL;
                dnac_merkle_commit(rsalted, rsb, lde_h, &rs, &rst);
                dnac_merkle_tree_free(rst);
                uint8_t vrr[DNAC_MERKLE_DIGEST_BYTES];
                size_t vn2 = 0; char *vj2 = slurp(argv[1], &vn2);
                if (vj2 && find_hex(vj2, "random_commit_root_hex", vrr, sizeof vrr) == (int)DNAC_MERKLE_DIGEST_BYTES) {
                    rok = memcmp(rs.bytes, vrr, DNAC_MERKLE_DIGEST_BYTES) == 0;
                }
                free(vj2); free(rsalted);
            }
            free(r_lde);
        }
        free(d2);
    }
    printf("  T3b C salted RANDOM root == REAL Plonky3 salted proof     %s\n", rok ? "PASS" : "FAIL");

    /* teeth: a tampered salt must change the root */
    int teeth = 1;
    {
        uint8_t *o = salted + 5 * salted_row_bytes;
        uint64_t sv; memcpy(&sv, o + RW * 8, 8); sv ^= 1; memcpy(o + RW * 8, &sv, 8);
        dnac_merkle_digest_t r2; dnac_merkle_tree_t *t2 = NULL;
        dnac_merkle_commit(salted, salted_row_bytes, lde_h, &r2, &t2);
        dnac_merkle_tree_free(t2);
        if (memcmp(r2.bytes, root.bytes, DNAC_MERKLE_DIGEST_BYTES) == 0) teeth = 0;
    }
    printf("  T4 teeth: tampered salt -> different root                 %s\n", teeth ? "PASS" : "FAIL");

    free(blind); free(base); free(draws); free(rand_c); free(lde); free(salted);
    if (!ok || !teeth || !rok) { printf("test_prover_salted_commit: FAIL\n"); return 1; }
    printf("test_prover_salted_commit: PASS\n");
    printf("  pure-C SALTED trace + random commitments (leaf=row||salt, SALT_ELEMS=2)\n");
    printf("  byte-match the REAL Plonky3 salted is_zk=1 proof (82cfad73). Input-mmcs\n");
    printf("  salt streams (trace draws[0:128], random draws[1152:1280]) grounded.\n");
    return 0;
}
