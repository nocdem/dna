/**
 * @file test_poseidon2_mmcs_mixed.c
 * @brief P2L-d d1a — byte-match gate for the MIXED-height Poseidon2 MMCS vs
 *        Plonky3 MerkleTreeMmcs / MerkleTreeHidingMmcs.
 *
 * Loads tools/vectors/poseidon2_mmcs_mixed.json (7 trees: plain + salted,
 * incl. an insertion-order-scrambled tree proving the stable tallest-first
 * grouping, and a degenerate same-height pair through the mixed path; every
 * opening was verify_batch-checked in-oracle) and asserts:
 *   1. plain trees: dnac_p2_mmcs_commit_mixed reproduces the root;
 *      dnac_p2_mmcs_open_mixed reproduces every opening's reduced rows AND
 *      sibling path; dnac_p2_mmcs_verify_mixed accepts every opening.
 *   2. salted trees: dnac_p2_mmcs_verify_mixed accepts every opening with
 *      the salts appended to each opened row (the salt-agnostic caller
 *      contract, hiding_mmcs.rs:121-134/159-175).
 *   3. negatives: tampered row / tampered sibling / wrong index / wrong
 *      depth / non-pow2 height / non-canonical lane all fail-close.
 *
 * Exit codes: 0 all green, 1 mismatch, 2 load/parse error.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../logup.h" /* only for the shared test util include chain */
#include "../poseidon2_mmcs.h"
#include "logup_test_util.h"

static int g_total = 0, g_failed = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        g_total++;                                                             \
        if (!(cond)) {                                                         \
            g_failed++;                                                        \
            fprintf(stderr, "MISMATCH: " __VA_ARGS__);                         \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

static bool parse_u64_array(const jv_t *arr, uint64_t **out, size_t *n)
{
    if (!arr || arr->kind != JV_ARR) return false;
    *n = arr->n;
    *out = (uint64_t *)malloc(sizeof(uint64_t) * (arr->n ? arr->n : 1));
    if (!*out) return false;
    for (size_t i = 0; i < arr->n; i++) {
        if (!jv_u64(arr->items[i], &(*out)[i])) {
            free(*out);
            *out = NULL;
            return false;
        }
    }
    return true;
}

static bool digest_from_jv(const jv_t *arr, dnac_p2_digest_t *d)
{
    if (!arr || arr->kind != JV_ARR || arr->n != 4) return false;
    for (size_t i = 0; i < 4; i++) {
        if (!jv_u64(arr->items[i], &d->lanes[i])) return false;
    }
    return true;
}

static int run_tree(const jv_t *tr, size_t salt_elems)
{
    const jv_t *jname = jv_get(tr, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";
    uint64_t salted64 = 0;
    if (!jv_u64(jv_get(tr, "salted"), &salted64)) return 2;
    const int salted = salted64 != 0;

    const jv_t *jheights = jv_get(tr, "heights");
    const jv_t *jwidths = jv_get(tr, "widths");
    const jv_t *jmats = jv_get(tr, "matrices");
    const jv_t *jroot = jv_get(tr, "root");
    const jv_t *jops = jv_get(tr, "openings");
    if (!jheights || jheights->kind != JV_ARR || !jwidths ||
        jwidths->kind != JV_ARR || !jmats || jmats->kind != JV_ARR ||
        jheights->n != jwidths->n || jmats->n != jheights->n || !jroot ||
        !jops || jops->kind != JV_ARR || jheights->n > 8) {
        return 2;
    }
    const size_t nm = jheights->n;
    size_t heights[8], widths[8];
    uint64_t *mats[8] = { 0 };
    size_t max_h = 0;
    for (size_t m = 0; m < nm; m++) {
        uint64_t h, w;
        if (!jv_u64(jheights->items[m], &h) || !jv_u64(jwidths->items[m], &w))
            return 2;
        heights[m] = (size_t)h;
        widths[m] = (size_t)w;
        if (heights[m] > max_h) max_h = heights[m];
        size_t cnt;
        if (!parse_u64_array(jmats->items[m], &mats[m], &cnt) ||
            cnt != heights[m] * widths[m]) {
            return 2;
        }
    }
    dnac_p2_digest_t root;
    if (!digest_from_jv(jroot, &root)) return 2;
    const size_t depth = (size_t)(63 - __builtin_clzll((unsigned long long)max_h));

    /* ---- 1. plain: commit byte-match + open replay ---- */
    dnac_p2_mmcs_tree_t *tree = NULL;
    if (!salted) {
        dnac_p2_digest_t got_root;
        int rc = dnac_p2_mmcs_commit_mixed((const uint64_t *const *)mats,
                                           widths, heights, nm, &got_root,
                                           &tree);
        CHECK(rc == DNAC_P2M_OK, "[%s] commit rc=%d", name, rc);
        if (rc == DNAC_P2M_OK) {
            CHECK(memcmp(got_root.lanes, root.lanes, sizeof(root.lanes)) == 0,
                  "[%s] root", name);
        }
    }

    /* ---- per-opening checks ---- */
    for (size_t o = 0; o < jops->n; o++) {
        const jv_t *op = jops->items[o];
        uint64_t index;
        const jv_t *jopened = jv_get(op, "opened");
        const jv_t *jsalts = jv_get(op, "salts");
        const jv_t *jsibs = jv_get(op, "siblings");
        if (!jv_u64(jv_get(op, "index"), &index) || !jopened ||
            jopened->kind != JV_ARR || jopened->n != nm || !jsibs ||
            jsibs->kind != JV_ARR || jsibs->n != depth) {
            return 2;
        }
        /* opened rows (+ salts appended for the hiding form) */
        uint64_t *rows[8] = { 0 };
        size_t row_widths[8];
        for (size_t m = 0; m < nm; m++) {
            uint64_t *vals;
            size_t cnt;
            if (!parse_u64_array(jopened->items[m], &vals, &cnt) ||
                cnt != widths[m]) {
                return 2;
            }
            if (salted) {
                if (!jsalts || jsalts->kind != JV_ARR || jsalts->n != nm)
                    return 2;
                uint64_t *sv;
                size_t sn;
                if (!parse_u64_array(jsalts->items[m], &sv, &sn) ||
                    sn != salt_elems) {
                    return 2;
                }
                uint64_t *joined = (uint64_t *)malloc(
                    sizeof(uint64_t) * (cnt + sn));
                if (!joined) return 2;
                memcpy(joined, vals, cnt * sizeof(uint64_t));
                memcpy(joined + cnt, sv, sn * sizeof(uint64_t));
                free(vals);
                free(sv);
                rows[m] = joined;
                row_widths[m] = cnt + sn;
            } else {
                rows[m] = vals;
                row_widths[m] = cnt;
            }
        }
        dnac_p2_digest_t sibs[16];
        for (size_t s = 0; s < depth; s++) {
            if (!digest_from_jv(jsibs->items[s], &sibs[s])) return 2;
        }

        /* verify accepts */
        int rc = dnac_p2_mmcs_verify_mixed(&root, (const uint64_t *const *)rows,
                                           row_widths, heights, nm, index,
                                           sibs, depth);
        CHECK(rc == DNAC_P2M_OK, "[%s] verify idx=%" PRIu64 " rc=%d", name,
              index, rc);

        /* plain: open replay byte-match (rows + siblings) */
        if (!salted && tree) {
            const uint64_t *trows[8];
            dnac_p2_digest_t osibs[16];
            dnac_p2_proof_t proof = { 0, 0, 0, osibs };
            rc = dnac_p2_mmcs_open_mixed(tree, index, trows, &proof);
            CHECK(rc == DNAC_P2M_OK && proof.depth == depth,
                  "[%s] open idx=%" PRIu64 " rc=%d", name, index, rc);
            if (rc == DNAC_P2M_OK) {
                for (size_t m = 0; m < nm; m++) {
                    CHECK(memcmp(trows[m], rows[m],
                                 widths[m] * sizeof(uint64_t)) == 0,
                          "[%s] opened row m=%zu idx=%" PRIu64, name, m, index);
                }
                for (size_t s = 0; s < depth; s++) {
                    CHECK(memcmp(osibs[s].lanes, sibs[s].lanes,
                                 sizeof(sibs[s].lanes)) == 0,
                          "[%s] sibling %zu idx=%" PRIu64, name, s, index);
                }
            }
        }

        /* negatives on the first opening only (cheap) */
        if (o == 0 && depth > 0) {
            uint64_t saved = rows[0][0];
            rows[0][0] = (saved + 1) % GOLDILOCKS_P;
            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, heights, nm, index,
                                           sibs, depth);
            CHECK(rc == DNAC_P2M_ERR_ROOT_MISMATCH,
                  "[%s] tampered-row rc=%d", name, rc);
            rows[0][0] = saved;

            dnac_p2_digest_t sib_save = sibs[0];
            sibs[0].lanes[0] ^= 1;
            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, heights, nm, index,
                                           sibs, depth);
            CHECK(rc == DNAC_P2M_ERR_ROOT_MISMATCH,
                  "[%s] tampered-sibling rc=%d", name, rc);
            sibs[0] = sib_save;

            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, heights, nm, index,
                                           sibs, depth - 1);
            CHECK(rc == DNAC_P2M_ERR_BAD_DEPTH, "[%s] wrong-depth rc=%d", name,
                  rc);

            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, heights, nm,
                                           (uint64_t)max_h, sibs, depth);
            CHECK(rc == DNAC_P2M_ERR_BAD_INDEX, "[%s] oob-index rc=%d", name,
                  rc);

            size_t bad_heights[8];
            memcpy(bad_heights, heights, sizeof(bad_heights));
            bad_heights[0] = 3; /* not a power of two */
            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, bad_heights, nm, index,
                                           sibs, depth);
            CHECK(rc == DNAC_P2M_ERR_PARAM, "[%s] non-pow2 rc=%d", name, rc);

            rows[0][0] = GOLDILOCKS_P; /* non-canonical lane */
            rc = dnac_p2_mmcs_verify_mixed(&root,
                                           (const uint64_t *const *)rows,
                                           row_widths, heights, nm, index,
                                           sibs, depth);
            CHECK(rc == DNAC_P2M_ERR_NONCANONICAL, "[%s] noncanonical rc=%d",
                  name, rc);
            rows[0][0] = saved;
        }

        for (size_t m = 0; m < nm; m++) free(rows[m]);
    }

    dnac_p2_mmcs_tree_free(tree);
    for (size_t m = 0; m < nm; m++) free(mats[m]);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path =
        (argc > 1) ? argv[1] : "tools/vectors/poseidon2_mmcs_mixed.json";
    size_t len;
    char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    jp_t p = { buf, 0, len };
    jv_t *doc = jp_value(&p);
    if (!doc || doc->kind != JV_OBJ) {
        fprintf(stderr, "FAIL: JSON parse\n");
        free(buf);
        return 2;
    }
    uint64_t salt_elems = 0;
    const jv_t *trees = jv_get(doc, "trees");
    if (!jv_u64(jv_get(doc, "salt_elems"), &salt_elems) || !trees ||
        trees->kind != JV_ARR) {
        fprintf(stderr, "FAIL: top-level fields\n");
        jv_free(doc);
        free(buf);
        return 2;
    }
    for (size_t i = 0; i < trees->n; i++) {
        if (run_tree(trees->items[i], (size_t)salt_elems) == 2) {
            fprintf(stderr, "FAIL: tree %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("trees: %zu checked\n", trees->n);

    printf("\n%-32s %5d checks\n", "poseidon2_mmcs_mixed total", g_total);
    printf("%-32s %5d\n", "poseidon2_mmcs_mixed failed", g_failed);
    printf("\nP2L-d d1a MIXED MMCS GATE: %s\n", g_failed == 0 ? "GREEN" : "RED");

    jv_free(doc);
    free(buf);
    return g_failed == 0 ? 0 : 1;
}
