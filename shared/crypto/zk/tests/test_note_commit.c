/**
 * @file test_note_commit.c
 * @brief Byte-match the C note-commitment / Merkle-compress sponge vs Plonky3.
 *
 * Loads tools/vectors/note_commit_sponge.json (oracle `dump-note-commit-sponge`,
 * which runs the REAL `PaddingFreeSponge<default_goldilocks_poseidon2_8,8,4,4>`
 * @ 82cfad73) and asserts:
 *   1. note_sponge_hash8() reproduces every case's 4-lane digest exactly.
 *   2. note_commit() assembles the note preimage in the pinned order (checked
 *      against the "note/typical" case).
 *   3. note_merkle_compress() assembles (left‖right) correctly (against
 *      "compress/seq").
 *   4. DNAC_DOMSEP_NOTE in the header equals the oracle's derived domsep_note.
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

#include "../note_commit.h"

static char *slurp(const char *path, size_t *out_len) {
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
    if (out_len) *out_len = rd;
    return buf;
}

static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

/* Read the next `[`, then `count` quoted decimal u64 into out[], advance *pos. */
static bool read_u64_array(const char *s, size_t *pos, uint64_t *out, int count) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    for (int i = 0; i < count; i++) {
        const char *q = strchr(s + p, '"');
        if (!q) return false;
        p = (size_t)(q - s) + 1;
        out[i] = strtoull(s + p, NULL, 10);
        const char *qe = strchr(s + p, '"');
        if (!qe) return false;
        p = (size_t)(qe - s) + 1;
    }
    const char *rb = strchr(s + p, ']');
    if (!rb) return false;
    *pos = (size_t)(rb - s) + 1;
    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <note_commit_sponge.json>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    char *json = slurp(argv[1], &len);
    if (!json) {
        fprintf(stderr, "FAIL: cannot read %s\n", argv[1]);
        return 2;
    }

    /* Check 4: DOMSEP header constant == oracle-derived domsep_note. */
    {
        size_t p = 0;
        uint64_t ds = 0;
        if (find_key(json, &p, "\"domsep_note\"")) {
            /* value is `: "<decimal>"`; the next quote opens the value string. */
            const char *q = strchr(json + p, '"');
            if (q) ds = strtoull(q + 1, NULL, 10);
        }
        if (ds != DNAC_DOMSEP_NOTE) {
            fprintf(stderr,
                    "FAIL: DNAC_DOMSEP_NOTE 0x%016" PRIx64
                    " != oracle domsep_note %" PRIu64 "\n",
                    DNAC_DOMSEP_NOTE, ds);
            free(json);
            return 1;
        }
    }

    size_t pos = 0;
    int cases = 0, fails = 0;
    /* Iterate cases via their "input" arrays (8 elems), then "output" (4). */
    while (find_key(json, &pos, "\"input\"")) {
        uint64_t input[8], expect[4], got[4];
        if (!read_u64_array(json, &pos, input, 8)) {
            fprintf(stderr, "FAIL: malformed input (case %d)\n", cases);
            fails++;
            break;
        }
        if (!find_key(json, &pos, "\"output\"") ||
            !read_u64_array(json, &pos, expect, 4)) {
            fprintf(stderr, "FAIL: malformed output (case %d)\n", cases);
            fails++;
            break;
        }
        note_sponge_hash8(input, got);
        for (int i = 0; i < 4; i++) {
            if (got[i] != expect[i]) {
                fprintf(stderr,
                        "FAIL case %d lane %d: got %" PRIu64 " expected %" PRIu64
                        "\n",
                        cases, i, got[i], expect[i]);
                fails++;
            }
        }
        cases++;
    }

    /* Check 2: note_commit() preimage order == "note/typical" oracle case:
     * value=1000000, addr=[11,22,33,44], rcm=[57005,48879]. */
    {
        uint64_t addr[4] = {11, 22, 33, 44};
        uint64_t rcm[2] = {57005, 48879};
        uint64_t expect_in[8] = {1000000, 11, 22, 33, 44, 57005, 48879,
                                 DNAC_DOMSEP_NOTE};
        uint64_t via_hash8[4], via_commit[4];
        note_sponge_hash8(expect_in, via_hash8);
        note_commit(1000000, addr, rcm, via_commit);
        if (memcmp(via_hash8, via_commit, sizeof(via_hash8)) != 0) {
            fprintf(stderr, "FAIL: note_commit() preimage assembly mismatch\n");
            fails++;
        }
    }

    /* Check 3: note_merkle_compress() == "compress/seq" [1,2,3,4|5,6,7,8]. */
    {
        uint64_t left[4] = {1, 2, 3, 4};
        uint64_t right[4] = {5, 6, 7, 8};
        uint64_t in[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint64_t via_hash8[4], via_compress[4];
        note_sponge_hash8(in, via_hash8);
        note_merkle_compress(left, right, via_compress);
        if (memcmp(via_hash8, via_compress, sizeof(via_hash8)) != 0) {
            fprintf(stderr, "FAIL: note_merkle_compress() assembly mismatch\n");
            fails++;
        }
    }

    free(json);

    if (cases == 0) {
        fprintf(stderr, "FAIL: no cases parsed\n");
        return 1;
    }
    if (fails) {
        printf("note-commit sponge: %d case(s), %d FAIL\n", cases, fails);
        return 1;
    }
    printf("note-commit sponge: %d/%d cases byte-match Plonky3 + wrappers OK — "
           "PASS\n",
           cases, cases);
    return 0;
}
