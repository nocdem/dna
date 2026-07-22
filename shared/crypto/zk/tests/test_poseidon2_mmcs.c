/**
 * @file test_poseidon2_mmcs.c
 * @brief Byte-match the C Poseidon2 MMCS vs the Plonky3 oracle (P1b).
 *
 * Loads tools/vectors/poseidon2_mmcs.json (produced by
 * `plonky3_oracle dump-poseidon2-mmcs`, which drives the REAL
 * MerkleTreeMmcs / MerkleTreeHidingMmcs over default_goldilocks_poseidon2_8()
 * @ 82cfad73, cap 0, every opening verify_batch-checked in-oracle) and:
 *   - byte-matches the sponge (hash_iter) + compressor primitives;
 *   - bridges note_sponge_hash8 == dnac_p2_mmcs_hash_iter at length 8
 *     (the design's "reuse where identical" proof);
 *   - rebuilds every tree with dnac_p2_mmcs_commit — for SALTED trees the
 *     rows are reassembled as row ‖ salt (salts taken from the dumped
 *     openings, one per index) — and byte-matches the root;
 *   - byte-matches every opening's siblings via dnac_p2_mmcs_open;
 *   - verifies every opening via dnac_p2_mmcs_verify == OK;
 *   - negative gates: opened-lane tamper, sibling tamper, wrong index,
 *     wrong depth, non-canonical lane fail-close.
 *
 * Build (via Makefile):
 *   ./build/test_poseidon2_mmcs tools/vectors/poseidon2_mmcs.json
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../note_commit.h"
#include "../poseidon2_mmcs.h"

/* Vector-shape caps (largest oracle tree: h=16, 2 matrices, width 9,
 * salt_elems 2). */
#define MAX_ROWS 16
#define MAX_MATS 3
#define MAX_W 16
#define MAX_DEPTH 4
#define MAX_SPONGE_IN 16

static int g_fails = 0;

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    return buf;
}

static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

static bool read_quoted(const char *s, size_t *pos, char *out, size_t cap) {
    const char *q = strchr(s + *pos, '"');
    if (!q) return false;
    size_t p = (size_t)(q - s) + 1;
    const char *qe = strchr(s + p, '"');
    if (!qe) return false;
    size_t len = (size_t)(qe - s) - p;
    if (len >= cap) return false;
    memcpy(out, s + p, len);
    out[len] = '\0';
    *pos = (size_t)(qe - s) + 1;
    return true;
}

static bool read_quoted_u64(const char *s, size_t *pos, uint64_t *out) {
    char buf[32];
    if (!read_quoted(s, pos, buf, sizeof(buf))) return false;
    char *end = NULL;
    *out = strtoull(buf, &end, 10);
    return end && *end == '\0';
}

static void skip_ws(const char *s, size_t *p) {
    while (s[*p] == ' ' || s[*p] == '\n' || s[*p] == '\r' || s[*p] == '\t' ||
           s[*p] == ',')
        (*p)++;
}

/* Flat array of quoted u64s: [ "1", "2", ... ] */
static bool read_u64_array(const char *s, size_t *pos, uint64_t *out,
                           size_t cap, size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        skip_ws(s, &p);
        if (s[p] == ']') { p++; break; }
        if (s[p] != '"' || n >= cap) return false;
        if (!read_quoted_u64(s, &p, &out[n])) return false;
        n++;
    }
    *pos = p;
    *out_n = n;
    return true;
}

/* Nested array of flat arrays: [ [..], [..], ... ] (may be empty []). */
static bool read_nested(const char *s, size_t *pos,
                        uint64_t out[][MAX_ROWS * MAX_W], size_t *lens,
                        size_t outer_cap, size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        skip_ws(s, &p);
        if (s[p] == ']') { p++; break; }
        if (s[p] != '[' || n >= outer_cap) return false;
        if (!read_u64_array(s, &p, out[n], MAX_ROWS * MAX_W, &lens[n]))
            return false;
        n++;
    }
    *pos = p;
    *out_n = n;
    return true;
}

typedef struct {
    uint64_t index;
    uint64_t opened[MAX_MATS][MAX_ROWS * MAX_W];
    size_t   opened_len[MAX_MATS];
    size_t   n_opened;
    uint64_t salts[MAX_MATS][MAX_ROWS * MAX_W];
    size_t   salts_len[MAX_MATS];
    size_t   n_salts;
    dnac_p2_digest_t sib[MAX_DEPTH];
    size_t   n_sib;
} opening_t;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <poseidon2_mmcs.json>\n", argv[0]);
        return 2;
    }
    char *json = slurp(argv[1]);
    if (!json) {
        fprintf(stderr, "FAIL: cannot read %s\n", argv[1]);
        return 2;
    }
    size_t pos = 0;

    /* ---- sponge primitive KATs (+ note_sponge_hash8 bridge at n == 8) ---- */
    int sponge_cases = 0, bridged = 0;
    {
        size_t scan = pos;
        if (!find_key(json, &scan, "\"sponge_cases\"")) {
            fprintf(stderr, "FAIL: sponge_cases missing\n");
            free(json);
            return 1;
        }
        pos = scan;
        while (1) {
            size_t peek = pos;
            const char *nx_in = strstr(json + pos, "\"input\"");
            const char *nx_cc = strstr(json + pos, "\"compress_cases\"");
            if (!nx_in || (nx_cc && nx_cc < nx_in)) break;
            (void)peek;
            pos = (size_t)(nx_in - json) + strlen("\"input\"");
            uint64_t in[MAX_SPONGE_IN], expect[4], got[4];
            size_t n_in = 0, n_out = 0;
            if (!read_u64_array(json, &pos, in, MAX_SPONGE_IN, &n_in) ||
                !find_key(json, &pos, "\"out\"") ||
                !read_u64_array(json, &pos, expect, 4, &n_out) || n_out != 4) {
                fprintf(stderr, "FAIL: malformed sponge case %d\n", sponge_cases);
                g_fails++;
                break;
            }
            dnac_p2_mmcs_hash_iter(in, n_in, got);
            if (memcmp(got, expect, sizeof(expect)) != 0) {
                fprintf(stderr, "FAIL: sponge case %d (len %zu) mismatch\n",
                        sponge_cases, n_in);
                g_fails++;
            }
            if (n_in == 8) {
                uint64_t bridge[4];
                note_sponge_hash8(in, bridge);
                if (memcmp(bridge, got, sizeof(bridge)) != 0) {
                    fprintf(stderr,
                            "FAIL: note_sponge_hash8 bridge diverges at len 8\n");
                    g_fails++;
                }
                bridged++;
            }
            sponge_cases++;
        }
    }

    /* ---- compressor primitive KATs ---- */
    int compress_cases = 0;
    while (1) {
        const char *nx_l = strstr(json + pos, "\"left\"");
        const char *nx_tr = strstr(json + pos, "\"trees\"");
        if (!nx_l || (nx_tr && nx_tr < nx_l)) break;
        pos = (size_t)(nx_l - json) + strlen("\"left\"");
        uint64_t l[4], r[4], expect[4], got[4];
        size_t n = 0;
        if (!read_u64_array(json, &pos, l, 4, &n) || n != 4 ||
            !find_key(json, &pos, "\"right\"") ||
            !read_u64_array(json, &pos, r, 4, &n) || n != 4 ||
            !find_key(json, &pos, "\"out\"") ||
            !read_u64_array(json, &pos, expect, 4, &n) || n != 4) {
            fprintf(stderr, "FAIL: malformed compress case %d\n", compress_cases);
            g_fails++;
            break;
        }
        dnac_p2_mmcs_compress(l, r, got);
        if (memcmp(got, expect, sizeof(expect)) != 0) {
            fprintf(stderr, "FAIL: compress case %d mismatch\n", compress_cases);
            g_fails++;
        }
        compress_cases++;
    }

    /* ---- trees ---- */
    int trees = 0, openings_total = 0;
    char name[64];
    static opening_t ops[MAX_ROWS];
    static uint64_t mats[MAX_MATS][MAX_ROWS * MAX_W];
    static uint64_t eff[MAX_MATS][MAX_ROWS * MAX_W];
    while (find_key(json, &pos, "\"name\"")) {
        if (!read_quoted(json, &pos, name, sizeof(name))) break;
        uint64_t salted = 0, num_rows = 0;
        uint64_t widths[MAX_MATS];
        size_t n_mats = 0, tmp = 0;
        size_t mat_lens[MAX_MATS];
        dnac_p2_digest_t root;
        if (!find_key(json, &pos, "\"salted\"") ||
            !read_quoted_u64(json, &pos, &salted) ||
            !find_key(json, &pos, "\"num_rows\"") ||
            !read_quoted_u64(json, &pos, &num_rows) ||
            !find_key(json, &pos, "\"widths\"") ||
            !read_u64_array(json, &pos, widths, MAX_MATS, &n_mats) ||
            !find_key(json, &pos, "\"matrices\"") ||
            !read_nested(json, &pos, mats, mat_lens, MAX_MATS, &tmp) ||
            tmp != n_mats ||
            !find_key(json, &pos, "\"root\"") ||
            !read_u64_array(json, &pos, root.lanes, 4, &tmp) || tmp != 4) {
            fprintf(stderr, "FAIL [%s]: malformed tree record\n", name);
            g_fails++;
            break;
        }

        /* openings (one per index, ascending) */
        size_t n_ops = 0;
        for (uint64_t i = 0; i < num_rows; i++) {
            opening_t *o = &ops[n_ops];
            uint64_t sib_flat[MAX_DEPTH][MAX_ROWS * MAX_W];
            size_t sib_lens[MAX_DEPTH], n_sib = 0;
            if (!find_key(json, &pos, "\"index\"") ||
                !read_quoted_u64(json, &pos, &o->index) ||
                !find_key(json, &pos, "\"opened\"") ||
                !read_nested(json, &pos, o->opened, o->opened_len, MAX_MATS,
                             &o->n_opened) ||
                !find_key(json, &pos, "\"salts\"") ||
                !read_nested(json, &pos, o->salts, o->salts_len, MAX_MATS,
                             &o->n_salts) ||
                !find_key(json, &pos, "\"siblings\"") ||
                !read_nested(json, &pos, sib_flat, sib_lens, MAX_DEPTH,
                             &n_sib)) {
                fprintf(stderr, "FAIL [%s]: malformed opening %" PRIu64 "\n",
                        name, i);
                g_fails++;
                goto done;
            }
            o->n_sib = n_sib;
            for (size_t l = 0; l < n_sib; l++) {
                if (sib_lens[l] != 4) {
                    fprintf(stderr, "FAIL [%s]: sibling %zu not 4 lanes\n",
                            name, l);
                    g_fails++;
                    goto done;
                }
                memcpy(o->sib[l].lanes, sib_flat[l], sizeof(o->sib[l].lanes));
            }
            n_ops++;
        }

        /* Effective matrices: plain = as dumped; salted = row ‖ salt using
         * the per-index salts (HidingMmcs commit's HorizontalPair layout,
         * hiding_mmcs.rs:121-134). */
        size_t eff_w[MAX_MATS];
        const uint64_t *mat_ptrs[MAX_MATS];
        for (size_t m = 0; m < n_mats; m++) {
            size_t w = (size_t)widths[m];
            if (salted) {
                size_t se = ops[0].salts_len[m];
                eff_w[m] = w + se;
                for (uint64_t r = 0; r < num_rows; r++) {
                    memcpy(&eff[m][r * eff_w[m]], &mats[m][r * w],
                           w * sizeof(uint64_t));
                    memcpy(&eff[m][r * eff_w[m] + w], ops[r].salts[m],
                           se * sizeof(uint64_t));
                }
                mat_ptrs[m] = eff[m];
            } else {
                eff_w[m] = w;
                mat_ptrs[m] = mats[m];
            }
        }

        /* Commit — root byte-match. */
        dnac_p2_digest_t c_root;
        dnac_p2_mmcs_tree_t *tree = NULL;
        dnac_p2_mmcs_status_t st = dnac_p2_mmcs_commit(
            mat_ptrs, eff_w, n_mats, (size_t)num_rows, &c_root, &tree);
        if (st != DNAC_P2M_OK) {
            fprintf(stderr, "FAIL [%s]: commit status %d\n", name, (int)st);
            g_fails++;
            goto done;
        }
        if (memcmp(c_root.lanes, root.lanes, sizeof(root.lanes)) != 0) {
            fprintf(stderr, "FAIL [%s]: root mismatch\n", name);
            g_fails++;
        }

        /* Openings — sibling byte-match + verify OK. */
        for (size_t oi = 0; oi < n_ops; oi++) {
            opening_t *o = &ops[oi];
            dnac_p2_digest_t sib[MAX_DEPTH];
            size_t depth = 0;
            st = dnac_p2_mmcs_open(tree, o->index, sib, &depth);
            if (st != DNAC_P2M_OK || depth != o->n_sib ||
                memcmp(sib, o->sib, depth * sizeof(sib[0])) != 0) {
                fprintf(stderr, "FAIL [%s]: open(%" PRIu64 ") mismatch\n",
                        name, o->index);
                g_fails++;
            }
            /* verify rows = opened ‖ salt (salted) or opened (plain) */
            static uint64_t vrows[MAX_MATS][MAX_W + 4];
            const uint64_t *vptrs[MAX_MATS];
            for (size_t m = 0; m < n_mats; m++) {
                memcpy(vrows[m], o->opened[m],
                       o->opened_len[m] * sizeof(uint64_t));
                if (salted)
                    memcpy(vrows[m] + o->opened_len[m], o->salts[m],
                           o->salts_len[m] * sizeof(uint64_t));
                vptrs[m] = vrows[m];
            }
            st = dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                     (size_t)num_rows, o->index, o->sib,
                                     o->n_sib);
            if (st != DNAC_P2M_OK) {
                fprintf(stderr, "FAIL [%s]: verify(%" PRIu64 ") status %d\n",
                        name, o->index, (int)st);
                g_fails++;
            }
            openings_total++;

            /* Negative gates on the first opening of the first depth>0 tree */
            if (trees == 2 && oi == 0) {
                uint64_t save = vrows[0][0];
                vrows[0][0] = (save + 1) % GOLDILOCKS_P;
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, o->index, o->sib,
                                        o->n_sib) != DNAC_P2M_ERR_ROOT_MISMATCH) {
                    fprintf(stderr, "FAIL [%s]: lane tamper not caught\n", name);
                    g_fails++;
                }
                vrows[0][0] = GOLDILOCKS_P; /* non-canonical */
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, o->index, o->sib,
                                        o->n_sib) != DNAC_P2M_ERR_NONCANONICAL) {
                    fprintf(stderr,
                            "FAIL [%s]: non-canonical lane not fail-closed\n",
                            name);
                    g_fails++;
                }
                vrows[0][0] = save;
                dnac_p2_digest_t tsib[MAX_DEPTH];
                memcpy(tsib, o->sib, o->n_sib * sizeof(tsib[0]));
                tsib[0].lanes[0] ^= 1;
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, o->index, tsib,
                                        o->n_sib) != DNAC_P2M_ERR_ROOT_MISMATCH) {
                    fprintf(stderr, "FAIL [%s]: sibling tamper not caught\n",
                            name);
                    g_fails++;
                }
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, o->index ^ 1, o->sib,
                                        o->n_sib) != DNAC_P2M_ERR_ROOT_MISMATCH) {
                    fprintf(stderr, "FAIL [%s]: wrong index not caught\n", name);
                    g_fails++;
                }
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, o->index, o->sib,
                                        o->n_sib - 1) != DNAC_P2M_ERR_BAD_DEPTH) {
                    fprintf(stderr, "FAIL [%s]: wrong depth not caught\n", name);
                    g_fails++;
                }
                if (dnac_p2_mmcs_verify(&root, vptrs, eff_w, n_mats,
                                        (size_t)num_rows, num_rows, o->sib,
                                        o->n_sib) != DNAC_P2M_ERR_BAD_INDEX) {
                    fprintf(stderr, "FAIL [%s]: OOB index not caught\n", name);
                    g_fails++;
                }
            }
        }
        dnac_p2_mmcs_tree_free(tree);
        trees++;
    }

done:
    free(json);
    if (sponge_cases < 10 || compress_cases < 6 || trees < 9 || bridged < 1) {
        fprintf(stderr,
                "FAIL: coverage short (sponge %d/10, compress %d/6, trees "
                "%d/9, bridge %d/1)\n",
                sponge_cases, compress_cases, trees, bridged);
        g_fails++;
    }
    if (g_fails == 0) {
        printf("PASS: poseidon2_mmcs byte-match — %d sponge + %d compress "
               "KATs, %d trees (plain+salted), %d openings, "
               "note_sponge_hash8 bridge, negatives OK\n",
               sponge_cases, compress_cases, trees, openings_total);
        return 0;
    }
    fprintf(stderr, "FAILURES: %d\n", g_fails);
    return 1;
}
