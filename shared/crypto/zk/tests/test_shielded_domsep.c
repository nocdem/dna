/**
 * @file test_shielded_domsep.c
 * @brief Verify every shielded DOMSEP literal == SHA3-512("<string>")[0:8] BE,
 *        is canonical (< p), and all are pairwise-distinct (incl. vs B1's two).
 *
 * KAFADAN guard: the constants in shielded_domsep.h are asserted to be a pure
 * function of their named derivation strings — a hand-edited literal that drifts
 * from its string fails here, and a duplicated tag (domain confusion) fails the
 * distinctness check (dm-c4 G5). Also re-derives the two pre-existing B1
 * constants (DOMSEP_VAL, DOMSEP_ACC) to prove the derivation rule itself.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../hash/qgp_sha3.h"
#include "../conf_commit_air.h"
#include "../conf_root_air.h"
#include "../field_goldilocks.h"
#include "../shielded_domsep.h"

/* SHA3-512(str)[0:8] interpreted big-endian as u64. */
static uint64_t derive(const char *str) {
    uint8_t h[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512((const uint8_t *)str, strlen(str), h) != 0) {
        fprintf(stderr, "FAIL: sha3 error on \"%s\"\n", str);
        return 0;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | h[i];
    return v;
}

int main(void) {
    struct {
        const char *name;
        const char *str;
        uint64_t literal;
    } tbl[] = {
        {"DNAC_DOMSEP_NOTE", "DNAC note-commitment v1", DNAC_DOMSEP_NOTE},
        {"DNAC_DOMSEP_RHO", "DNAC nullifier-rho v1", DNAC_DOMSEP_RHO},
        {"DNAC_DOMSEP_NF", "DNAC nullifier-prf v1", DNAC_DOMSEP_NF},
        {"DNAC_DOMSEP_ADDR", "DNAC shielded-address v1", DNAC_DOMSEP_ADDR},
        {"DNAC_DOMSEP_MERKLE", "DNAC note-merkle-compress v1", DNAC_DOMSEP_MERKLE},
        /* B1 constants — prove the derivation rule reproduces the shipped ones. */
        {"CONF_COMMIT_DOMSEP_VAL", "DNAC value-commitment v1",
         CONF_COMMIT_DOMSEP_VAL},
        {"CONF_ROOT_DOMSEP_ACC", "DNAC commitment-accumulator v1",
         CONF_ROOT_DOMSEP_ACC},
    };
    const int n = (int)(sizeof(tbl) / sizeof(tbl[0]));
    int fails = 0;

    for (int i = 0; i < n; i++) {
        uint64_t d = derive(tbl[i].str);
        if (d != tbl[i].literal) {
            fprintf(stderr,
                    "FAIL: %s literal 0x%016" PRIx64 " != derived 0x%016" PRIx64
                    " from \"%s\"\n",
                    tbl[i].name, tbl[i].literal, d, tbl[i].str);
            fails++;
        }
        if (tbl[i].literal >= GOLDILOCKS_P) {
            fprintf(stderr, "FAIL: %s 0x%016" PRIx64 " NOT canonical (>= p)\n",
                    tbl[i].name, tbl[i].literal);
            fails++;
        }
    }

    /* Pairwise distinctness across ALL tags. */
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (tbl[i].literal == tbl[j].literal) {
                fprintf(stderr, "FAIL: %s == %s (0x%016" PRIx64 ") — domain collision\n",
                        tbl[i].name, tbl[j].name, tbl[i].literal);
                fails++;
            }
        }
    }

    if (fails) {
        printf("shielded DOMSEP: %d FAIL\n", fails);
        return 1;
    }
    printf("shielded DOMSEP: %d constants derived + canonical + distinct — PASS\n",
           n);
    return 0;
}
