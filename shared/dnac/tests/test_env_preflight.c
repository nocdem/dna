/**
 * @file shared/dnac/tests/test_env_preflight.c
 * @brief Ledger V2 — tests for the generic deterministic envelope preflight
 *        (shared/dnac/env_preflight.{h,c}).
 *
 * Four properties are pinned here, in increasing order of importance:
 *
 *   1. THE LOCKED EXPIRY COMPARISON — expiry is judged against the
 *      CANDIDATE block height, directly, with no +1 and no overflow
 *      boundary. The load-bearing case is expiry == H-1 (the PARENT
 *      height): an implementation that derived H from parent+1 would
 *      accept it. This suite asserts the reject.
 *   2. FULL 32-BYTE CHAIN-ID BINDING — every one of bytes 0, 15, 16 and 31
 *      moves auth_context_commit, every auth_digest and tx_id, while no
 *      call_commit moves at all. Bytes 16 and 31 are the TRUNCATION
 *      REGRESSION DETECTORS: the legacy witness chain_id zeroes bytes
 *      16..31, so an implementation that reached for it instead of the
 *      derived value would leave these two commitments unchanged.
 *   3. FAIL-CLOSED, TOTALLY — after EVERY reject the result is FULLY
 *      zeroed. A partially derived commitment set must never be readable,
 *      because the one field a caller wants (tx_id) is the one field a
 *      partial result would leave forgeable.
 *   4. NON-CIRCULARITY, through the preflight API — mutating auth_data
 *      moves tx_id ONLY and leaves auth_context_commit and every
 *      auth_digest byte-identical (env_wire.h:105-118).
 *
 * KAT values come from shared/dnac/tests/env_preflight_oracle.py, an
 * independent python3 hashlib.sha3_512 oracle written from the env_wire.h
 * specification that shares no code with the C.
 *   Reproduce:  python3 shared/dnac/tests/env_preflight_oracle.py
 *
 * Every dna_env_preflight_t is HEAP allocated: the struct is ~11 KB (the
 * measured size is printed by this binary), so the stack-local shape used
 * by smaller wire tests would not be safe here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/env_preflight.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int g_checks = 0;

#define CHECK(cond) do {                                                 \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    } else {                                                             \
        g_checks++;                                                      \
    }                                                                    \
} while (0)

/* Every allocation below is checked; a NULL would otherwise crash the whole
 * binary and report as a segfault rather than a test failure. */
#define MUST_ALLOC(p) do {                                               \
    if (!(p)) {                                                          \
        fprintf(stderr, "FATAL %s:%d: allocation failed\n",              \
                __FILE__, __LINE__);                                     \
        exit(2);                                                         \
    }                                                                    \
} while (0)

#define HASH_LEN  DNA_ENV_HASH_LEN

/* ══════════════════════════════════════════════════════════════════════
 * KAT — pinned from the independent oracle (see the file header).
 * ════════════════════════════════════════════════════════════════════ */

/* ORACLE: python3 hashlib.sha3_512 — env_preflight_oracle.py */
/* season fixture: 3 legs (domains 2/7/9), ENV_LEN = 340 */
static const uint8_t K_PF_ENV[340] = {
    0x44, 0x4e, 0x41, 0x2e, 0x45, 0x4e, 0x56, 0x57,
    0x49, 0x52, 0x45, 0x2e, 0x76, 0x31, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xf4, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xff, 0x00,
    0x00, 0x00, 0x02, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x10, 0x00, 0x61, 0x6c, 0x70,
    0x68, 0x61, 0x2d, 0x63, 0x61, 0x6c, 0x6c, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x41,
    0x55, 0x54, 0x48, 0x30, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee
};
static const uint8_t K_PF_CHAIN_ID[32] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};
static const uint8_t K_PF_RULESET0[64] = {
    0x58, 0x3f, 0x4f, 0x2a, 0x4e, 0xa4, 0x57, 0xb9,
    0x1a, 0xe6, 0xe9, 0x12, 0x34, 0xa6, 0x57, 0x39,
    0xc0, 0x60, 0x16, 0x51, 0x21, 0x61, 0x82, 0x29,
    0xc5, 0x84, 0x90, 0xbe, 0x45, 0x05, 0xdd, 0x7a,
    0x7b, 0x47, 0xce, 0x18, 0x12, 0xa6, 0x60, 0x70,
    0x96, 0x2c, 0xba, 0x4c, 0xca, 0x6f, 0x7d, 0xfd,
    0x4f, 0xf1, 0xfc, 0x6b, 0x07, 0xf3, 0x16, 0x55,
    0xe6, 0x68, 0x95, 0x6f, 0xa6, 0x06, 0x22, 0x91
};
static const uint8_t K_PF_RULESET1[64] = {
    0xac, 0x78, 0xfd, 0x0d, 0x28, 0x98, 0xca, 0x6e,
    0x56, 0x8d, 0xf0, 0xc5, 0x3c, 0xbd, 0x6d, 0x7f,
    0x72, 0x19, 0xc0, 0x2e, 0xb1, 0x4a, 0xa8, 0xe0,
    0x23, 0xa5, 0x35, 0x85, 0x11, 0xf1, 0xd3, 0xfe,
    0x22, 0xaf, 0x7d, 0xc7, 0x3f, 0x77, 0xa0, 0x9f,
    0x43, 0xd9, 0x02, 0xb0, 0x32, 0xdf, 0xb6, 0x1e,
    0x77, 0x88, 0xa0, 0x79, 0x46, 0x77, 0x11, 0x5a,
    0x96, 0x92, 0xf6, 0x12, 0xe9, 0x53, 0xf9, 0x2f
};
static const uint8_t K_PF_RULESET2[64] = {
    0x00, 0xd9, 0xf0, 0x2f, 0x4e, 0x73, 0x56, 0x61,
    0xa4, 0xa5, 0x0f, 0xc6, 0xd5, 0x60, 0xc3, 0x89,
    0x96, 0xdb, 0x0b, 0xc9, 0x8a, 0x78, 0x82, 0x21,
    0x64, 0x1c, 0x0b, 0xf8, 0xec, 0x9d, 0x92, 0x04,
    0x87, 0x28, 0xa1, 0x1f, 0xaf, 0x2a, 0x21, 0x5a,
    0x61, 0x24, 0xe3, 0xf5, 0x15, 0x78, 0xe5, 0x54,
    0x7e, 0xad, 0x9f, 0xc9, 0x4d, 0x50, 0xb6, 0xcc,
    0x5e, 0x89, 0x89, 0x59, 0xe2, 0xc8, 0xbe, 0xcb
};
static const uint8_t K_PF_CALL_COMMIT0[64] = {
    0x9d, 0x92, 0xb3, 0x89, 0x73, 0x41, 0xc7, 0x6a,
    0xfc, 0xe3, 0x65, 0x30, 0xdc, 0xed, 0x30, 0xd7,
    0xd9, 0x90, 0xe1, 0x5b, 0x5e, 0xe4, 0x5d, 0x81,
    0x76, 0xce, 0x68, 0x3c, 0x89, 0x74, 0x1f, 0xd2,
    0x61, 0x1e, 0x71, 0xea, 0x17, 0x7b, 0xbe, 0xf3,
    0xf6, 0x09, 0xdd, 0x7b, 0x2f, 0xfb, 0xa1, 0x4f,
    0x88, 0xf7, 0x36, 0x24, 0x70, 0xb3, 0x52, 0x4f,
    0x28, 0x4e, 0x80, 0x4a, 0x14, 0xab, 0x15, 0x22
};
static const uint8_t K_PF_CALL_COMMIT1[64] = {
    0x2b, 0xcf, 0xc0, 0x66, 0xee, 0xea, 0x53, 0x25,
    0xdf, 0x33, 0x88, 0x34, 0x52, 0xc2, 0xe8, 0x29,
    0xe1, 0xbe, 0xc9, 0x62, 0x8c, 0x69, 0xe7, 0xfd,
    0x4c, 0x8d, 0xee, 0x53, 0xa0, 0x8c, 0xf5, 0x16,
    0xf8, 0x7a, 0x92, 0x0c, 0xa9, 0xcb, 0x77, 0x1a,
    0x71, 0x25, 0xe6, 0xc0, 0x28, 0xa2, 0x14, 0x88,
    0xa8, 0xd9, 0x18, 0x25, 0xa3, 0x8d, 0x87, 0x47,
    0xfb, 0xe4, 0xc2, 0x19, 0xc3, 0x84, 0xf3, 0x7b
};
static const uint8_t K_PF_CALL_COMMIT2[64] = {
    0x1b, 0x44, 0x1d, 0x48, 0x47, 0xf2, 0xc8, 0xd3,
    0xf9, 0xfd, 0x5a, 0x3f, 0x7f, 0xdd, 0x12, 0xc5,
    0xbf, 0xb9, 0x20, 0x57, 0x3e, 0x2a, 0xb3, 0xb3,
    0x0c, 0x44, 0x13, 0xdd, 0x37, 0x0b, 0x77, 0x2d,
    0xe8, 0x94, 0xe6, 0xeb, 0x1b, 0x0e, 0x03, 0x6a,
    0xf3, 0x36, 0x45, 0xe5, 0xa9, 0x86, 0xa0, 0xea,
    0x64, 0xff, 0x52, 0x1c, 0x3b, 0xa8, 0x18, 0x93,
    0xf9, 0xde, 0x50, 0x2e, 0x32, 0x75, 0x21, 0x96
};
static const uint8_t K_PF_AUTHCTX[64] = {
    0x06, 0xe3, 0x94, 0x07, 0x22, 0x87, 0xd0, 0x7f,
    0xee, 0xa5, 0x03, 0x57, 0x45, 0x73, 0xf9, 0x87,
    0xd4, 0x12, 0x7f, 0x93, 0x7f, 0x35, 0xd8, 0xc3,
    0x7e, 0x94, 0x6d, 0x1d, 0xde, 0x60, 0x95, 0xfa,
    0x5c, 0xdb, 0x26, 0xaa, 0x6c, 0x50, 0xbd, 0xc4,
    0xce, 0xe7, 0x69, 0xb0, 0x10, 0xa6, 0x10, 0x90,
    0x61, 0x8a, 0xf0, 0x0d, 0xc1, 0xfe, 0xed, 0x98,
    0x2d, 0x92, 0x86, 0x7b, 0xf4, 0x10, 0xc1, 0x01
};
static const uint8_t K_PF_AUTH_DIGEST0[64] = {
    0x4d, 0x6a, 0x58, 0xd2, 0x67, 0x1d, 0x91, 0x17,
    0x1f, 0xc6, 0x98, 0xd0, 0x6f, 0x63, 0x14, 0xa0,
    0x17, 0x5a, 0x1f, 0x11, 0x59, 0x21, 0x0f, 0x92,
    0x55, 0x82, 0xd2, 0xbe, 0xf8, 0x8f, 0x1a, 0xee,
    0x45, 0x9c, 0x76, 0x9c, 0x6e, 0x91, 0x1b, 0xe2,
    0x69, 0x53, 0x89, 0xc4, 0x40, 0xc5, 0xf4, 0x4d,
    0x54, 0x8d, 0xb7, 0x5e, 0xe8, 0x88, 0xa2, 0xed,
    0x33, 0x5a, 0x93, 0x87, 0xe5, 0xf4, 0x53, 0x74
};
static const uint8_t K_PF_AUTH_DIGEST1[64] = {
    0xf7, 0x66, 0xda, 0x31, 0xc2, 0x5e, 0x8f, 0xa0,
    0x2e, 0xba, 0x83, 0xd0, 0x58, 0x0c, 0x17, 0xb4,
    0x13, 0xd0, 0x5c, 0x95, 0x01, 0x09, 0x63, 0xfb,
    0x53, 0xc5, 0x74, 0xd1, 0xed, 0x97, 0x92, 0x81,
    0x26, 0x0c, 0x6f, 0x40, 0xcf, 0x30, 0x92, 0xc8,
    0xc8, 0x8d, 0x8c, 0x28, 0x14, 0x99, 0x1c, 0x68,
    0x51, 0x19, 0xae, 0x9e, 0xe7, 0xc2, 0x9d, 0x73,
    0x48, 0x37, 0xf4, 0x4f, 0x78, 0xe1, 0x75, 0x81
};
static const uint8_t K_PF_AUTH_DIGEST2[64] = {
    0x28, 0xa7, 0x91, 0xae, 0x9c, 0x29, 0x02, 0xcc,
    0xb9, 0x14, 0x36, 0x04, 0xe0, 0xb2, 0x48, 0xfa,
    0xec, 0x33, 0x56, 0x7e, 0xbe, 0x7e, 0xc0, 0x5f,
    0x52, 0x0d, 0x36, 0xf1, 0x72, 0x8a, 0xa3, 0xc3,
    0x4f, 0x01, 0xa1, 0x53, 0x68, 0xd1, 0xfb, 0xe4,
    0x62, 0x66, 0x6d, 0xa4, 0xc9, 0xbd, 0x17, 0xc3,
    0xe6, 0x75, 0x74, 0xcb, 0x25, 0x7e, 0xd1, 0xd9,
    0xd5, 0x8b, 0x90, 0x6e, 0x1d, 0xa7, 0x77, 0x4c
};
static const uint8_t K_PF_TX_ID[64] = {
    0xfc, 0xc1, 0x9e, 0x90, 0x3f, 0xe1, 0x96, 0x55,
    0xa5, 0x5c, 0x04, 0xe2, 0x6d, 0xae, 0x87, 0x26,
    0x76, 0xea, 0x1a, 0x61, 0x5e, 0xa5, 0x62, 0x6a,
    0xd0, 0xde, 0x1a, 0xd3, 0x15, 0xb6, 0xe2, 0x31,
    0x6f, 0x9a, 0x6c, 0xc5, 0x0f, 0x85, 0x3a, 0x30,
    0x9a, 0x31, 0x44, 0x3a, 0x22, 0x6c, 0x38, 0x81,
    0xb1, 0xb4, 0x7a, 0x9c, 0x92, 0x3d, 0xa0, 0xd3,
    0x38, 0x3c, 0xa3, 0x40, 0x09, 0x44, 0xb4, 0x05
};
/* chain-id single-byte mutations (+1 mod 256) — each MUST move authctx,
 * every auth_digest and tx_id, and MUST NOT move any call_commit
 * (chain_id is absent from the call preimage, env_wire.h:78-84). */
static const uint8_t K_PF_CHAIN_B0_AUTHCTX[64] = {
    0xb1, 0x70, 0xa1, 0xaa, 0x89, 0x5d, 0x33, 0x0e,
    0x8c, 0x8d, 0x5e, 0x2e, 0x42, 0x0e, 0x15, 0x37,
    0x48, 0x12, 0xf3, 0x56, 0xfc, 0x14, 0x7f, 0x68,
    0xea, 0xaf, 0x23, 0x3e, 0x50, 0xe8, 0x9e, 0xbb,
    0x45, 0x17, 0xaa, 0xa6, 0xfd, 0x82, 0x6e, 0xdd,
    0x1a, 0x14, 0x4d, 0xbe, 0x2e, 0xcf, 0xb8, 0xc4,
    0x17, 0x80, 0x9b, 0xcc, 0x46, 0x01, 0x32, 0x9b,
    0xe5, 0xac, 0x53, 0x0f, 0x6b, 0x29, 0x52, 0x26
};
static const uint8_t K_PF_CHAIN_B0_AUTH_DIGEST0[64] = {
    0xce, 0xa9, 0x5b, 0xb6, 0x8f, 0x16, 0x5e, 0xc5,
    0x3e, 0x30, 0x1c, 0x47, 0x8b, 0x50, 0xb8, 0x12,
    0x5d, 0x84, 0x2a, 0x5e, 0x38, 0xf1, 0x7e, 0x75,
    0x69, 0x9b, 0xfb, 0x0b, 0xed, 0x27, 0x63, 0xbc,
    0xd8, 0xcf, 0x90, 0xcd, 0x2e, 0x77, 0x08, 0xbe,
    0xb6, 0x83, 0x31, 0xb0, 0x20, 0x4d, 0x99, 0x63,
    0x5b, 0x22, 0x75, 0x11, 0xf5, 0x66, 0x8d, 0xda,
    0x5b, 0x32, 0xd6, 0x83, 0x09, 0x5a, 0x55, 0x8d
};
static const uint8_t K_PF_CHAIN_B0_TX_ID[64] = {
    0xce, 0x66, 0x0e, 0x45, 0x2a, 0xc9, 0xc8, 0x94,
    0x4d, 0x51, 0x76, 0x1f, 0xdf, 0x0f, 0x24, 0x5c,
    0x06, 0xb7, 0x70, 0x91, 0xc0, 0x60, 0x96, 0x1a,
    0x0c, 0x1b, 0x99, 0x72, 0x4c, 0x12, 0xcb, 0xdd,
    0xe1, 0x8b, 0xce, 0x6c, 0xfa, 0x79, 0xfb, 0xc3,
    0xb0, 0x9d, 0xe4, 0x9e, 0xed, 0xa3, 0x77, 0x0f,
    0xe0, 0x68, 0x7b, 0x98, 0x9b, 0xea, 0xc3, 0x3f,
    0xd4, 0xbe, 0xdb, 0x6f, 0x3d, 0x79, 0xb6, 0x9e
};
static const uint8_t K_PF_CHAIN_B15_AUTHCTX[64] = {
    0xd8, 0x13, 0xfe, 0xa8, 0x7e, 0xe9, 0xde, 0x1d,
    0x45, 0x23, 0xee, 0x06, 0x05, 0x6c, 0xb5, 0x82,
    0x58, 0x76, 0x67, 0x98, 0x87, 0xdf, 0x41, 0xba,
    0x0e, 0x11, 0x21, 0x2f, 0xe2, 0x7c, 0x28, 0x77,
    0x23, 0x5e, 0x53, 0x46, 0xed, 0x9c, 0x0b, 0x0c,
    0xe1, 0x71, 0x5b, 0xd9, 0x48, 0xb4, 0x74, 0xac,
    0x22, 0xc4, 0x91, 0x6a, 0x5e, 0x19, 0x3f, 0x72,
    0x7a, 0xde, 0xdc, 0xd2, 0xe6, 0xa9, 0xf3, 0x89
};
static const uint8_t K_PF_CHAIN_B15_AUTH_DIGEST0[64] = {
    0x26, 0x0a, 0xd8, 0x79, 0x39, 0x39, 0x47, 0x63,
    0x7b, 0xc7, 0x68, 0xbb, 0x25, 0x3d, 0xee, 0x5b,
    0xd3, 0x52, 0x17, 0xce, 0xd9, 0x74, 0xf1, 0x80,
    0xfa, 0x4c, 0xe5, 0xa1, 0x0b, 0xee, 0x51, 0x6e,
    0xec, 0xad, 0xe6, 0xdd, 0xe8, 0x95, 0xa4, 0x97,
    0xb1, 0xae, 0xca, 0x1b, 0xaf, 0x58, 0x43, 0x1d,
    0x65, 0x13, 0xe2, 0x56, 0x30, 0xfd, 0x02, 0x56,
    0x4d, 0xe3, 0x11, 0xeb, 0x14, 0x98, 0xe1, 0x3f
};
static const uint8_t K_PF_CHAIN_B15_TX_ID[64] = {
    0x4c, 0x10, 0x29, 0x1e, 0x65, 0xf0, 0x13, 0xd9,
    0x68, 0xfb, 0x21, 0xe3, 0x10, 0xf4, 0x34, 0x45,
    0x94, 0xf2, 0x77, 0x77, 0x87, 0xa7, 0xdb, 0x5b,
    0x37, 0xad, 0x1c, 0x77, 0xd5, 0x2e, 0x5f, 0xd6,
    0x7b, 0x7e, 0x99, 0xe9, 0x24, 0x2c, 0x9d, 0x2c,
    0xf8, 0x87, 0x69, 0x3c, 0xdf, 0xf0, 0xd4, 0xd9,
    0x96, 0xb3, 0x85, 0x7e, 0x7b, 0x1d, 0x1e, 0xb1,
    0xb9, 0xfa, 0x92, 0xe2, 0x4a, 0xb8, 0xde, 0xd3
};
static const uint8_t K_PF_CHAIN_B16_AUTHCTX[64] = {
    0x6a, 0x16, 0x39, 0x5d, 0x44, 0xbe, 0xc9, 0xf4,
    0x9c, 0x73, 0x68, 0x5b, 0xbb, 0xd6, 0xab, 0x54,
    0xa8, 0x3b, 0xe3, 0xe1, 0xb6, 0x88, 0x9a, 0x9f,
    0x99, 0xa1, 0xe9, 0x61, 0xc6, 0x63, 0x6a, 0x00,
    0x5c, 0x11, 0xb1, 0xf9, 0x05, 0x79, 0x6f, 0x90,
    0x57, 0x79, 0x1c, 0xde, 0x1a, 0x4a, 0x3f, 0x9f,
    0xe8, 0x4f, 0x54, 0x04, 0x11, 0x0b, 0x4c, 0x60,
    0xd3, 0x4d, 0x97, 0xdd, 0x62, 0x8a, 0x9c, 0x54
};
static const uint8_t K_PF_CHAIN_B16_AUTH_DIGEST0[64] = {
    0xde, 0x6d, 0x2f, 0x7e, 0xad, 0x56, 0x45, 0xa0,
    0xf1, 0x5e, 0xeb, 0x48, 0x8d, 0x02, 0x7a, 0x85,
    0x4d, 0x66, 0x61, 0xa2, 0x9b, 0xb3, 0xd5, 0xc6,
    0x2c, 0x5f, 0xa8, 0x8a, 0x12, 0x9e, 0x65, 0x44,
    0xb2, 0x32, 0x23, 0x21, 0xe2, 0xc7, 0xba, 0x92,
    0xb8, 0x70, 0x66, 0x7e, 0x51, 0xbc, 0x22, 0x70,
    0x50, 0xcd, 0x85, 0x46, 0xca, 0x57, 0xef, 0xd3,
    0x5d, 0xa4, 0xc4, 0x07, 0x35, 0xe9, 0xd6, 0x88
};
static const uint8_t K_PF_CHAIN_B16_TX_ID[64] = {
    0x59, 0x97, 0xae, 0x9f, 0x2d, 0x66, 0xc5, 0x7e,
    0x8a, 0xac, 0x7b, 0x97, 0xe3, 0xa4, 0x99, 0xc4,
    0x9d, 0xcc, 0xfe, 0xd9, 0xfb, 0x52, 0x97, 0x95,
    0xa6, 0xee, 0x5d, 0x7a, 0xb7, 0x7c, 0x51, 0xba,
    0xed, 0x95, 0x97, 0x4f, 0xb5, 0x24, 0x58, 0x63,
    0x6f, 0x94, 0x00, 0x45, 0xbc, 0xf1, 0x2c, 0x99,
    0x8c, 0x87, 0x5b, 0x8d, 0x0a, 0x68, 0xb2, 0x7d,
    0x07, 0x97, 0x54, 0xa0, 0x0c, 0xb9, 0xd1, 0x11
};
static const uint8_t K_PF_CHAIN_B31_AUTHCTX[64] = {
    0x19, 0x3c, 0xae, 0x53, 0x07, 0x3e, 0x24, 0xec,
    0xd6, 0x30, 0x8e, 0x56, 0x3e, 0x9b, 0x7a, 0x7d,
    0x4d, 0x17, 0x27, 0xc3, 0xa0, 0xf4, 0x8a, 0x6b,
    0xbb, 0xfb, 0x13, 0x6d, 0xcf, 0x87, 0x8e, 0x88,
    0xd3, 0x65, 0xf1, 0x77, 0x54, 0xf8, 0x55, 0x37,
    0xfa, 0xe1, 0x21, 0xc6, 0x78, 0x2c, 0x9a, 0xd1,
    0xc1, 0xc0, 0x98, 0x52, 0x80, 0x69, 0x96, 0x13,
    0xb6, 0x1f, 0xa8, 0x18, 0x35, 0xe0, 0x14, 0xd8
};
static const uint8_t K_PF_CHAIN_B31_AUTH_DIGEST0[64] = {
    0xae, 0x80, 0x25, 0xe5, 0xef, 0xfe, 0x38, 0x95,
    0xf8, 0xe4, 0xc4, 0xc6, 0xe6, 0x6c, 0x99, 0x50,
    0xc7, 0xcd, 0x87, 0x15, 0x3f, 0xd1, 0xbc, 0xa6,
    0xa9, 0xdb, 0x53, 0xa5, 0xac, 0xfe, 0x0c, 0x82,
    0x5a, 0x68, 0x3c, 0xb2, 0x77, 0xdd, 0xf4, 0x7f,
    0xe4, 0x72, 0xc5, 0x13, 0x0d, 0xed, 0x76, 0x8d,
    0x76, 0x98, 0xc8, 0xd5, 0x28, 0xd1, 0x61, 0x9e,
    0x7f, 0xcf, 0x98, 0x44, 0xfe, 0xe5, 0x0f, 0xfb
};
static const uint8_t K_PF_CHAIN_B31_TX_ID[64] = {
    0x44, 0x04, 0xd5, 0x52, 0x79, 0xc9, 0xee, 0x35,
    0x92, 0x70, 0xdf, 0x09, 0x2f, 0xbb, 0x9e, 0xd3,
    0xdb, 0x8f, 0x93, 0x4e, 0x8d, 0x79, 0x2e, 0x64,
    0x60, 0xec, 0xb0, 0xa6, 0x60, 0xd9, 0x38, 0x07,
    0xa8, 0xad, 0x6c, 0x4e, 0x1d, 0x98, 0x34, 0x30,
    0x7a, 0xbd, 0x41, 0xee, 0x4c, 0x4a, 0xaa, 0xe0,
    0x3e, 0x7c, 0x90, 0x4b, 0x69, 0xd1, 0xbf, 0xb1,
    0x7b, 0x1b, 0x94, 0x48, 0xcc, 0x5a, 0x17, 0xae
};

/* ══════════════════════════════════════════════════════════════════════
 * Fixture: a mutable description of one envelope plus its CONTEXTUAL
 * inputs. Every mutation test clones a fixture, changes exactly one
 * thing, re-encodes, and re-runs the preflight.
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t          expiry;
    uint64_t          fee;
    uint64_t          res_total;
    uint16_t          n;
    dna_env_leg_hdr_t hdr[DNA_ENV_MAX_LEGS];
    uint8_t          *call[DNA_ENV_MAX_LEGS];
    uint8_t          *auth[DNA_ENV_MAX_LEGS];
    uint8_t           chain_id[DNA_ENV_CHAIN_ID_LEN];
    uint8_t           rh[DNA_ENV_MAX_LEGS][DNA_ENV_RULESET_HASH_LEN];
} fixture_t;

static void fx_blob(uint8_t **slot, uint32_t *len_field,
                    const uint8_t *src, uint32_t len) {
    free(*slot);
    *slot = NULL;
    if (len) {
        *slot = malloc(len);
        MUST_ALLOC(*slot);
        memcpy(*slot, src, len);
    }
    *len_field = len;
}

static void fx_free(fixture_t *f) {
    if (!f) return;
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        free(f->call[i]);
        free(f->auth[i]);
    }
    free(f);
}

/** Deep copy, so a mutation never disturbs the base fixture. */
static fixture_t *fx_clone(const fixture_t *src) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    *f = *src;
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        f->call[i] = NULL;
        f->auth[i] = NULL;
        if (src->hdr[i].call_len) {
            f->call[i] = malloc(src->hdr[i].call_len);
            MUST_ALLOC(f->call[i]);
            memcpy(f->call[i], src->call[i], src->hdr[i].call_len);
        }
        if (src->hdr[i].auth_len) {
            f->auth[i] = malloc(src->hdr[i].auth_len);
            MUST_ALLOC(f->auth[i]);
            memcpy(f->auth[i], src->auth[i], src->hdr[i].auth_len);
        }
    }
    return f;
}

/**
 * THE season fixture — field-for-field the envelope the oracle builds
 * (env_preflight_oracle.py season_fixture): 3 legs, domains 2/7/9,
 * runtime_ops 1/0/255, ruleset_versions 3/1/2, access INVOKE/READ/INVOKE,
 * auth_kinds 1/2/3. The KAT below asserts the encoding is byte-identical
 * to the oracle's, so the C and python fixtures cannot silently diverge.
 */
static fixture_t *fx_season(void) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    f->expiry    = 1000;
    f->fee       = 77;
    f->res_total = 500;
    f->n         = 3;

    static const uint32_t dom[3]  = { 2, 7, 9 };
    static const uint32_t op[3]   = { 1, 0, 255 };
    static const uint32_t rv[3]   = { 3, 1, 2 };
    static const uint8_t  am[3]   = { (uint8_t)DNA_ENV_ACCESS_INVOKE,
                                      (uint8_t)DNA_ENV_ACCESS_READ,
                                      (uint8_t)DNA_ENV_ACCESS_INVOKE };
    static const uint8_t  ak[3]   = { 1, 2, 3 };
    static const uint32_t rme[3]  = { 4, 0, 9 };
    static const uint32_t rmeb[3] = { 256, 0, 4096 };

    for (uint16_t i = 0; i < 3; i++) {
        f->hdr[i].domain_id            = dom[i];
        f->hdr[i].runtime_op           = op[i];
        f->hdr[i].ruleset_version      = rv[i];
        f->hdr[i].access_mode          = am[i];
        f->hdr[i].auth_kind            = ak[i];
        f->hdr[i].res_max_effects      = rme[i];
        f->hdr[i].res_max_effect_bytes = rmeb[i];
    }

    /* call_data: "alpha-call" / (empty) / 00..3f */
    fx_blob(&f->call[0], &f->hdr[0].call_len,
            (const uint8_t *)"alpha-call", 10);
    fx_blob(&f->call[1], &f->hdr[1].call_len, NULL, 0);
    {
        uint8_t seq[64];
        for (int j = 0; j < 64; j++) seq[j] = (uint8_t)j;
        fx_blob(&f->call[2], &f->hdr[2].call_len, seq, 64);
    }
    /* auth_data: "AUTH0" / (empty) / EE * 128 */
    fx_blob(&f->auth[0], &f->hdr[0].auth_len, (const uint8_t *)"AUTH0", 5);
    fx_blob(&f->auth[1], &f->hdr[1].auth_len, NULL, 0);
    {
        uint8_t ee[128];
        memset(ee, 0xEE, sizeof(ee));
        fx_blob(&f->auth[2], &f->hdr[2].auth_len, ee, 128);
    }

    memcpy(f->chain_id, K_PF_CHAIN_ID, DNA_ENV_CHAIN_ID_LEN);
    memcpy(f->rh[0], K_PF_RULESET0, DNA_ENV_RULESET_HASH_LEN);
    memcpy(f->rh[1], K_PF_RULESET1, DNA_ENV_RULESET_HASH_LEN);
    memcpy(f->rh[2], K_PF_RULESET2, DNA_ENV_RULESET_HASH_LEN);
    return f;
}

/** A 4th leg (domain 12), for the context-permutation battery. */
static fixture_t *fx_season4(void) {
    fixture_t *f = fx_season();
    f->n = 4;
    f->hdr[3].domain_id            = 12;
    f->hdr[3].runtime_op           = 5;
    f->hdr[3].ruleset_version      = 8;
    f->hdr[3].access_mode          = (uint8_t)DNA_ENV_ACCESS_READ;
    f->hdr[3].auth_kind            = 4;
    f->hdr[3].res_max_effects      = 1;
    f->hdr[3].res_max_effect_bytes = 32;
    fx_blob(&f->call[3], &f->hdr[3].call_len, (const uint8_t *)"delta", 5);
    fx_blob(&f->auth[3], &f->hdr[3].auth_len, (const uint8_t *)"D", 1);
    for (int j = 0; j < DNA_ENV_RULESET_HASH_LEN; j++)
        f->rh[3][j] = (uint8_t)(0xC0 + j);
    return f;
}

/* ── one preflight run, with its owned buffers ──────────────────────── */

typedef struct {
    uint8_t                   *bytes;   /* the encoded envelope, OWNED    */
    size_t                     len;
    dna_env_leg_ctx_t          ctx[DNA_ENV_MAX_LEGS];
    uint16_t                   nctx;
    dna_env_preflight_t       *pf;      /* HEAP: ~11 KB                   */
    dna_env_preflight_status_t st;
} run_t;

static void run_free(run_t *r) {
    if (!r) return;
    free(r->bytes);
    free(r->pf);
    free(r);
}

/** Encode the fixture, build the POSITIONAL context table, preflight. */
static run_t *fx_run(const fixture_t *f, uint64_t height) {
    run_t *r = calloc(1, sizeof(*r));
    MUST_ALLOC(r);
    r->pf = malloc(sizeof(*r->pf));
    MUST_ALLOC(r->pf);
    /* DIRTY, deliberately: every reject observed through fx_run is then a
     * proof the preflight zeroed the buffer, not an artifact of calloc. */
    memset(r->pf, 0xAA, sizeof(*r->pf));

    dna_env_leg_in_t legs[DNA_ENV_MAX_LEGS];
    memset(legs, 0, sizeof(legs));
    for (uint16_t i = 0; i < f->n; i++) {
        legs[i].hdr       = f->hdr[i];
        legs[i].call_data = f->call[i];
        legs[i].auth_data = f->auth[i];
    }
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = f->expiry;
    in.fee_amount          = f->fee;
    in.res_max_total_units = f->res_total;
    in.leg_count           = f->n;
    in.legs                = legs;

    size_t need = 0;
    if (dna_env_encoded_size(legs, f->n, &need) != 0) {
        fprintf(stderr, "FATAL %s:%d: fixture size\n", __FILE__, __LINE__);
        exit(2);
    }
    r->bytes = malloc(need);
    MUST_ALLOC(r->bytes);
    if (dna_env_encode(&in, r->bytes, need, &r->len) != 0) {
        fprintf(stderr, "FATAL %s:%d: fixture encode\n", __FILE__, __LINE__);
        exit(2);
    }

    r->nctx = f->n;
    for (uint16_t i = 0; i < f->n; i++) {
        r->ctx[i].domain_id       = f->hdr[i].domain_id;
        r->ctx[i].ruleset_version = f->hdr[i].ruleset_version;
        memcpy(r->ctx[i].ruleset_hash, f->rh[i], DNA_ENV_RULESET_HASH_LEN);
    }

    r->st = dna_env_preflight(r->bytes, r->len, f->chain_id, height,
                              r->ctx, r->nctx, r->pf);
    return r;
}

/* ── assertions ─────────────────────────────────────────────────────── */

static int all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

/**
 * After EVERY reject the result must be FULLY zeroed — no partial set.
 *
 * RAW-BYTE scan of the WHOLE struct, not a field sample: the contract is
 * "memset(out, 0, sizeof *out)" (env_preflight.h), so padding is zero too
 * and a full scan is sound. A field sample here let a mutant that zeroed
 * only the sampled fields pass the entire suite (independent test-review
 * catch, 2026-08-07) — the scan is what makes the guarantee enforced
 * rather than asserted. Pair with dirty_pf(): scanning a buffer that was
 * zero to begin with proves nothing.
 */
static void expect_zeroed(const dna_env_preflight_t *pf, const char *what) {
    int ok = all_zero((const uint8_t *)pf, sizeof(*pf));
    if (!ok) fprintf(stderr, "FAIL: result not zeroed after %s\n", what);
    CHECK(ok);
}

/** Pre-dirty a result buffer so a reject's zeroing is PROVEN, not vacuous. */
static dna_env_preflight_t *dirty_pf(dna_env_preflight_t *pf) {
    memset(pf, 0xAA, sizeof(*pf));
    return pf;
}

static void expect_kat(const char *what, const uint8_t *got,
                       const uint8_t *want) {
    int ok = memcmp(got, want, HASH_LEN) == 0;
    if (!ok) {
        fprintf(stderr, "FAIL KAT %s\n  got : ", what);
        for (int i = 0; i < HASH_LEN; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  want: ");
        for (int i = 0; i < HASH_LEN; i++) fprintf(stderr, "%02x", want[i]);
        fprintf(stderr, "\n");
    }
    CHECK(ok);
}

/* ══════════════════════════════════════════════════════════════════════
 * (a) EXPIRY — the locked comparison against the CANDIDATE height.
 * ════════════════════════════════════════════════════════════════════ */
static void test_expiry(void) {
    /* At H = 5: 0 accepts (no expiry), 4 rejects, 5/6/UINT64_MAX accept. */
    static const struct { uint64_t e; dna_env_preflight_status_t want; }
    at5[] = {
        { 0,              DNA_ENV_PF_OK },
        { 4,              DNA_ENV_PF_ERR_EXPIRED },
        { 5,              DNA_ENV_PF_OK },
        { 6,              DNA_ENV_PF_OK },
        { UINT64_MAX,     DNA_ENV_PF_OK },
    };
    for (size_t i = 0; i < sizeof(at5) / sizeof(at5[0]); i++) {
        fixture_t *f = fx_season();
        f->expiry = at5[i].e;
        run_t *r = fx_run(f, 5);
        CHECK(r->st == at5[i].want);
        if (r->st != DNA_ENV_PF_OK) expect_zeroed(r->pf, "expiry reject");
        run_free(r);
        fx_free(f);
    }

    /* At H = 0 nothing can be below the height, so both accept. */
    {
        fixture_t *f = fx_season();
        f->expiry = 0;
        run_t *r = fx_run(f, 0);
        CHECK(r->st == DNA_ENV_PF_OK);
        run_free(r);
        f->expiry = 1;
        r = fx_run(f, 0);
        CHECK(r->st == DNA_ENV_PF_OK);
        run_free(r);
        fx_free(f);
    }

    /* PARENT-vs-CANDIDATE, the load-bearing case: expiry == H-1 is the
     * PARENT height. An implementation that took the parent height and did
     * not increment it would compare `expiry < parent` and ACCEPT. Assert
     * the reject, at several heights so it cannot be a one-off. */
    {
        /* H = 1 is deliberately absent: its parent height is 0, and 0 is
         * the "no expiry" SENTINEL, not a height. That corner is pinned
         * separately below. */
        static const uint64_t heights[] = { 2, 100, 1000000, UINT64_MAX };
        for (size_t i = 0; i < sizeof(heights) / sizeof(heights[0]); i++) {
            fixture_t *f = fx_season();
            f->expiry = heights[i] - 1;      /* the parent height */
            run_t *r = fx_run(f, heights[i]);
            CHECK(r->st == DNA_ENV_PF_ERR_EXPIRED);
            expect_zeroed(r->pf, "parent-height expiry");
            run_free(r);
            /* and the candidate height itself still accepts */
            f->expiry = heights[i];
            r = fx_run(f, heights[i]);
            CHECK(r->st == DNA_ENV_PF_OK);
            run_free(r);
            fx_free(f);
        }
    }

    /* The sentinel corner the loop above excludes: at H = 1 the parent
     * height is 0, and expiry 0 means "never expires" — so it ACCEPTS.
     * 0 is a sentinel, not a height, and the gate must not treat it as
     * "expired one block ago". */
    {
        fixture_t *f = fx_season();
        f->expiry = 0;
        run_t *r = fx_run(f, 1);
        CHECK(r->st == DNA_ENV_PF_OK);
        run_free(r);
        /* while expiry 1 at H = 2 (a real parent height) still rejects */
        f->expiry = 1;
        r = fx_run(f, 2);
        CHECK(r->st == DNA_ENV_PF_ERR_EXPIRED);
        run_free(r);
        fx_free(f);
    }

    /* Order pin: an envelope that is BOTH expired AND carries a mismatched
     * context returns ERR_EXPIRED — expiry (step 3) precedes the context
     * gates (steps 4-5) and the order is the contract. */
    {
        fixture_t *f = fx_season();
        f->expiry = 4;
        run_t *base = fx_run(f, 0);          /* encode with expiry 4 */
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        MUST_ALLOC(pf);
        dna_env_leg_ctx_t bad[3];
        memcpy(bad, base->ctx, sizeof(bad));
        bad[0].domain_id ^= 0xFFu;           /* also a context mismatch */
        dna_env_preflight_status_t st =
            dna_env_preflight(base->bytes, base->len, f->chain_id, 5,
                              bad, 3, dirty_pf(pf));
        CHECK(st == DNA_ENV_PF_ERR_EXPIRED);
        expect_zeroed(pf, "expiry-before-context");
        free(pf);
        run_free(base);
        fx_free(f);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * (b) FULL 32-BYTE CHAIN-ID BINDING — bytes 16 and 31 are the truncation
 *     regression detectors.
 * ════════════════════════════════════════════════════════════════════ */
static void test_chain_id_binding(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    static const struct {
        int idx;
        const uint8_t *authctx;
        const uint8_t *digest0;
        const uint8_t *txid;
    } mut[] = {
        {  0, K_PF_CHAIN_B0_AUTHCTX,  K_PF_CHAIN_B0_AUTH_DIGEST0,
             K_PF_CHAIN_B0_TX_ID  },
        { 15, K_PF_CHAIN_B15_AUTHCTX, K_PF_CHAIN_B15_AUTH_DIGEST0,
             K_PF_CHAIN_B15_TX_ID },
        { 16, K_PF_CHAIN_B16_AUTHCTX, K_PF_CHAIN_B16_AUTH_DIGEST0,
             K_PF_CHAIN_B16_TX_ID },
        { 31, K_PF_CHAIN_B31_AUTHCTX, K_PF_CHAIN_B31_AUTH_DIGEST0,
             K_PF_CHAIN_B31_TX_ID },
    };

    for (size_t m = 0; m < sizeof(mut) / sizeof(mut[0]); m++) {
        fixture_t *g = fx_clone(f);
        g->chain_id[mut[m].idx] = (uint8_t)(g->chain_id[mut[m].idx] + 1u);
        run_t *r = fx_run(g, 0);
        CHECK(r->st == DNA_ENV_PF_OK);

        /* the wire bytes do not carry chain_id — the encoding is unchanged */
        CHECK(r->len == base->len);
        CHECK(memcmp(r->bytes, base->bytes, base->len) == 0);

        /* NO call_commit moves: chain_id is absent from the call preimage
         * (env_wire.h:78-84). */
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->call_commit[i], base->pf->call_commit[i],
                         HASH_LEN) == 0);

        /* ctx, EVERY auth_digest and tx_id all move */
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);

        /* and they move to the values the INDEPENDENT oracle predicts */
        expect_kat("chain-mutation authctx",  r->pf->auth_context_commit,
                   mut[m].authctx);
        expect_kat("chain-mutation digest0",  r->pf->auth_digest[0],
                   mut[m].digest0);
        expect_kat("chain-mutation tx_id",    r->pf->tx_id, mut[m].txid);

        run_free(r);
        fx_free(g);
    }

    /* The four mutated tx_ids are pairwise distinct: byte 16 and byte 31
     * are not aliases of byte 0 or of each other. */
    CHECK(memcmp(K_PF_CHAIN_B0_TX_ID,  K_PF_CHAIN_B16_TX_ID, HASH_LEN) != 0);
    CHECK(memcmp(K_PF_CHAIN_B15_TX_ID, K_PF_CHAIN_B16_TX_ID, HASH_LEN) != 0);
    CHECK(memcmp(K_PF_CHAIN_B16_TX_ID, K_PF_CHAIN_B31_TX_ID, HASH_LEN) != 0);
    CHECK(memcmp(K_PF_CHAIN_B0_TX_ID,  K_PF_CHAIN_B31_TX_ID, HASH_LEN) != 0);

    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (c) RULESET BINDING — contextual hash, serialized version, and the
 *     context-table gates.
 * ════════════════════════════════════════════════════════════════════ */
static void test_ruleset_binding(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    /* contextual ruleset_hash of leg 1 — binds THAT leg only */
    {
        fixture_t *g = fx_clone(f);
        g->rh[1][7] = (uint8_t)(g->rh[1][7] + 1u);
        run_t *r = fx_run(g, 0);
        CHECK(r->st == DNA_ENV_PF_OK);
        CHECK(memcmp(r->pf->call_commit[1], base->pf->call_commit[1],
                     HASH_LEN) != 0);
        CHECK(memcmp(r->pf->call_commit[0], base->pf->call_commit[0],
                     HASH_LEN) == 0);
        CHECK(memcmp(r->pf->call_commit[2], base->pf->call_commit[2],
                     HASH_LEN) == 0);
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        /* the wire bytes are untouched: ruleset_hash is CONTEXTUAL */
        CHECK(memcmp(r->bytes, base->bytes, base->len) == 0);
        run_free(r);
        fx_free(g);
    }

    /* SERIALIZED ruleset_version, with the context updated to match: the
     * envelope re-encodes and the identity moves. */
    {
        fixture_t *g = fx_clone(f);
        g->hdr[1].ruleset_version += 1;
        run_t *r = fx_run(g, 0);
        CHECK(r->st == DNA_ENV_PF_OK);
        CHECK(memcmp(r->bytes, base->bytes, base->len) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        run_free(r);
        fx_free(g);
    }

    /* context version != serialized version -> ERR_CTX_VERSION */
    {
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        MUST_ALLOC(pf);
        dna_env_leg_ctx_t bad[3];
        memcpy(bad, base->ctx, sizeof(bad));
        bad[2].ruleset_version += 1;
        CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                                bad, 3, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_VERSION);
        expect_zeroed(pf, "ctx version mismatch");
        free(pf);
    }

    /* context domain != serialized domain -> ERR_CTX_DOMAIN */
    {
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        MUST_ALLOC(pf);
        dna_env_leg_ctx_t bad[3];
        memcpy(bad, base->ctx, sizeof(bad));
        bad[1].domain_id = 4242;
        CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                                bad, 3, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_DOMAIN);
        expect_zeroed(pf, "ctx domain mismatch");
        free(pf);
    }

    /* count - 1 and count + 1 -> ERR_CTX_COUNT (never truncate/extend) */
    {
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        MUST_ALLOC(pf);
        dna_env_leg_ctx_t four[4];
        memcpy(four, base->ctx, 3 * sizeof(four[0]));
        memset(&four[3], 0, sizeof(four[3]));
        CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                                four, 2, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_COUNT);
        expect_zeroed(pf, "ctx count-1");
        CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                                four, 4, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_COUNT);
        expect_zeroed(pf, "ctx count+1");
        CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                                four, 0, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_COUNT);
        expect_zeroed(pf, "ctx count 0");
        free(pf);
    }

    /* SWAPPED 2-entry context: an envelope with legs for domains 2 and 7,
     * handed its contexts in the order 7, 2. Because envelope legs are
     * strictly ascending by domain_id, a swap can never align and lands on
     * ERR_CTX_DOMAIN rather than binding the wrong ruleset to a leg. */
    {
        fixture_t *g = fx_clone(f);
        g->n = 2;                                /* domains 2 and 7 */
        run_t *r = fx_run(g, 0);
        CHECK(r->st == DNA_ENV_PF_OK);

        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        MUST_ALLOC(pf);
        dna_env_leg_ctx_t swapped[2];
        swapped[0] = r->ctx[1];
        swapped[1] = r->ctx[0];
        CHECK(dna_env_preflight(r->bytes, r->len, g->chain_id, 0,
                                swapped, 2, dirty_pf(pf))
              == DNA_ENV_PF_ERR_CTX_DOMAIN);
        expect_zeroed(pf, "swapped 2-entry context");
        free(pf);
        run_free(r);
        fx_free(g);
    }

    /* Three DISTINCT contextual hashes really are distinct — otherwise the
     * per-leg binding above would be vacuous. */
    CHECK(memcmp(K_PF_RULESET0, K_PF_RULESET1, 64) != 0);
    CHECK(memcmp(K_PF_RULESET1, K_PF_RULESET2, 64) != 0);
    CHECK(memcmp(K_PF_RULESET0, K_PF_RULESET2, 64) != 0);

    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (d) KAT — every value pinned from the independent oracle.
 * ════════════════════════════════════════════════════════════════════ */
static void test_kat(void) {
    fixture_t *f = fx_season();
    run_t *r = fx_run(f, 0);
    CHECK(r->st == DNA_ENV_PF_OK);

    /* The C fixture encodes byte-identically to the oracle's — this is
     * what makes the digest KATs below meaningful rather than circular. */
    CHECK(r->len == sizeof(K_PF_ENV));
    if (r->len == sizeof(K_PF_ENV))
        CHECK(memcmp(r->bytes, K_PF_ENV, sizeof(K_PF_ENV)) == 0);

    /* Layout arithmetic, independent of any digest:
     * 43 + 3*30 + (10 + 0 + 64) + (5 + 0 + 128) = 340. */
    CHECK(r->len == 340);

    expect_kat("call_commit[0]",      r->pf->call_commit[0], K_PF_CALL_COMMIT0);
    expect_kat("call_commit[1]",      r->pf->call_commit[1], K_PF_CALL_COMMIT1);
    expect_kat("call_commit[2]",      r->pf->call_commit[2], K_PF_CALL_COMMIT2);
    expect_kat("auth_context_commit", r->pf->auth_context_commit,
               K_PF_AUTHCTX);
    expect_kat("auth_digest[0]",      r->pf->auth_digest[0], K_PF_AUTH_DIGEST0);
    expect_kat("auth_digest[1]",      r->pf->auth_digest[1], K_PF_AUTH_DIGEST1);
    expect_kat("auth_digest[2]",      r->pf->auth_digest[2], K_PF_AUTH_DIGEST2);
    expect_kat("tx_id",               r->pf->tx_id,          K_PF_TX_ID);

    /* Unused slots stay zero — no stale digest is readable past leg_count. */
    CHECK(all_zero(r->pf->call_commit[3], HASH_LEN));
    CHECK(all_zero(r->pf->auth_digest[3], HASH_LEN));
    CHECK(all_zero(r->pf->call_commit[DNA_ENV_MAX_LEGS - 1], HASH_LEN));

    /* The view describes the envelope, field by field (never a struct
     * memcmp: padding is not part of the contract). */
    CHECK(r->pf->view.leg_count == 3);
    CHECK(r->pf->view.envelope_version == DNA_ENV_VERSION);
    CHECK(r->pf->view.expiry_height == 1000);
    CHECK(r->pf->view.fee_amount == 77);
    CHECK(r->pf->view.res_max_total_units == 500);
    CHECK(r->pf->view.buf == r->bytes);      /* BORROWED, not copied */
    CHECK(r->pf->view.env_len == r->len);
    CHECK(r->pf->view.leg[0].domain_id == 2);
    CHECK(r->pf->view.leg[1].domain_id == 7);
    CHECK(r->pf->view.leg[2].domain_id == 9);
    CHECK(r->pf->view.leg[2].runtime_op == 255);

    run_free(r);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (e) EXISTING COMMITMENT INVARIANTS, through the preflight API.
 * ════════════════════════════════════════════════════════════════════ */
static void test_commitment_invariants(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 1000);
    CHECK(base->st == DNA_ENV_PF_OK);

    /* call_data mutation: that leg's call_commit moves, and everything
     * downstream of it moves; the other legs' call_commits do not. */
    {
        fixture_t *g = fx_clone(f);
        g->call[0][3] = (uint8_t)(g->call[0][3] + 1u);
        run_t *r = fx_run(g, 1000);
        CHECK(r->st == DNA_ENV_PF_OK);
        CHECK(memcmp(r->pf->call_commit[0], base->pf->call_commit[0],
                     HASH_LEN) != 0);
        CHECK(memcmp(r->pf->call_commit[1], base->pf->call_commit[1],
                     HASH_LEN) == 0);
        CHECK(memcmp(r->pf->call_commit[2], base->pf->call_commit[2],
                     HASH_LEN) == 0);
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        run_free(r);
        fx_free(g);
    }

    /* fee mutation: an envelope-level field. No call_commit moves (fee is
     * not in the call preimage); ctx, all digests and tx_id move. */
    {
        fixture_t *g = fx_clone(f);
        g->fee += 1;
        run_t *r = fx_run(g, 1000);
        CHECK(r->st == DNA_ENV_PF_OK);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->call_commit[i], base->pf->call_commit[i],
                         HASH_LEN) == 0);
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        run_free(r);
        fx_free(g);
    }

    /* expiry mutation 1000 -> 1001: same propagation as fee. Run at
     * H = 1000 so both values are ACCEPTED and the comparison is about
     * binding, not about the expiry gate. */
    {
        fixture_t *g = fx_clone(f);
        g->expiry = 1001;
        run_t *r = fx_run(g, 1000);
        CHECK(r->st == DNA_ENV_PF_OK);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->call_commit[i], base->pf->call_commit[i],
                         HASH_LEN) == 0);
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) != 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        run_free(r);
        fx_free(g);
    }

    /* THE NON-CIRCULARITY PIN: auth_data moves tx_id and NOTHING else.
     * If this ever breaks, a leg's authorization would have to sign a
     * value that depends on the signature itself (env_wire.h:105-118). */
    {
        fixture_t *g = fx_clone(f);
        g->auth[0][2] = (uint8_t)(g->auth[0][2] + 1u);
        run_t *r = fx_run(g, 1000);
        CHECK(r->st == DNA_ENV_PF_OK);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->call_commit[i], base->pf->call_commit[i],
                         HASH_LEN) == 0);
        CHECK(memcmp(r->pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) == 0);
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(r->pf->auth_digest[i], base->pf->auth_digest[i],
                         HASH_LEN) == 0);
        CHECK(memcmp(r->pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        run_free(r);
        fx_free(g);
    }

    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (f) MALFORMED ENVELOPES — one authority for framing rejection.
 * ════════════════════════════════════════════════════════════════════ */
static void test_malformed(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    MUST_ALLOC(pf);

    /* truncated by one byte */
    CHECK(dna_env_preflight(base->bytes, base->len - 1, f->chain_id, 0,
                            base->ctx, 3, dirty_pf(pf))
          == DNA_ENV_PF_ERR_DECODE);
    expect_zeroed(pf, "truncated envelope");

    /* one trailing byte (the buffer is over-allocated for this case) */
    {
        uint8_t *longer = malloc(base->len + 1);
        MUST_ALLOC(longer);
        memcpy(longer, base->bytes, base->len);
        longer[base->len] = 0x5A;
        CHECK(dna_env_preflight(longer, base->len + 1, f->chain_id, 0,
                                base->ctx, 3, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "trailing byte");
        free(longer);
    }

    /* corrupted wire-family tag */
    {
        uint8_t *bad = malloc(base->len);
        MUST_ALLOC(bad);
        memcpy(bad, base->bytes, base->len);
        bad[3] = (uint8_t)(bad[3] + 1u);
        CHECK(dna_env_preflight(bad, base->len, f->chain_id, 0,
                                base->ctx, 3, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "corrupt family tag");
        /* the family marker's zero PADDING is validated too */
        memcpy(bad, base->bytes, base->len);
        bad[15] = 0x01;
        CHECK(dna_env_preflight(bad, base->len, f->chain_id, 0,
                                base->ctx, 3, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "corrupt family padding");
        free(bad);
    }

    /* ZERO legs — hand-built, because the encoder refuses to emit it. */
    {
        uint8_t zero_legs[DNA_ENV_FIXED_HEAD];
        memcpy(zero_legs, base->bytes, DNA_ENV_FIXED_HEAD);
        zero_legs[41] = 0;
        zero_legs[42] = 0;
        CHECK(dna_env_preflight(zero_legs, sizeof(zero_legs), f->chain_id, 0,
                                base->ctx, 0, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "zero legs");
    }

    /* DESCENDING domain ids — hand-built for the same reason. Two legs,
     * both blobs empty, so the length is exactly 43 + 60 = 103. */
    {
        uint8_t desc[DNA_ENV_FIXED_HEAD + 2 * DNA_ENV_LEG_HDR_LEN];
        memset(desc, 0, sizeof(desc));
        memcpy(desc, base->bytes, DNA_ENV_FIXED_HEAD);
        desc[41] = 0; desc[42] = 2;                       /* leg_count = 2 */
        for (int leg = 0; leg < 2; leg++) {
            uint8_t *p = desc + DNA_ENV_FIXED_HEAD +
                         leg * DNA_ENV_LEG_HDR_LEN;
            p[3]  = leg == 0 ? 7 : 2;                     /* domain_id     */
            p[7]  = 1;                                    /* runtime_op    */
            p[11] = 1;                                    /* ruleset_ver   */
            p[12] = (uint8_t)DNA_ENV_ACCESS_INVOKE;
            p[13] = 1;                                    /* auth_kind     */
            /* call_len / auth_len / res_* stay 0 */
        }
        CHECK(dna_env_preflight(desc, sizeof(desc), f->chain_id, 0,
                                base->ctx, 2, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "descending domain ids");

        /* control: the SAME bytes with ascending domains decode fine, so
         * the reject above is about ORDER, not about the hand-built shape */
        desc[DNA_ENV_FIXED_HEAD + 3] = 2;
        desc[DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN + 3] = 7;
        dna_env_leg_ctx_t two[2];
        memset(two, 0, sizeof(two));
        two[0].domain_id = 2; two[0].ruleset_version = 1;
        two[1].domain_id = 7; two[1].ruleset_version = 1;
        CHECK(dna_env_preflight(desc, sizeof(desc), f->chain_id, 0,
                                two, 2, pf) == DNA_ENV_PF_OK);
    }

    /* DUPLICATE domain ids are non-canonical too (equal is not ascending) */
    {
        uint8_t dup[DNA_ENV_FIXED_HEAD + 2 * DNA_ENV_LEG_HDR_LEN];
        memset(dup, 0, sizeof(dup));
        memcpy(dup, base->bytes, DNA_ENV_FIXED_HEAD);
        dup[41] = 0; dup[42] = 2;
        for (int leg = 0; leg < 2; leg++) {
            uint8_t *p = dup + DNA_ENV_FIXED_HEAD +
                         leg * DNA_ENV_LEG_HDR_LEN;
            p[3]  = 5;                                    /* SAME domain   */
            p[11] = 1;
            p[12] = (uint8_t)DNA_ENV_ACCESS_READ;
            p[13] = 1;
        }
        dna_env_leg_ctx_t two[2];
        memset(two, 0, sizeof(two));
        two[0].domain_id = 5; two[0].ruleset_version = 1;
        two[1].domain_id = 5; two[1].ruleset_version = 1;
        CHECK(dna_env_preflight(dup, sizeof(dup), f->chain_id, 0,
                                two, 2, dirty_pf(pf))
              == DNA_ENV_PF_ERR_DECODE);
        expect_zeroed(pf, "duplicate domain ids");
    }

    free(pf);
    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (g) DETERMINISTIC PROPERTY TESTS — seeded, never time() or rand().
 * ════════════════════════════════════════════════════════════════════ */

/** splitmix64 with a PINNED literal seed: same sequence on every machine,
 *  every run, forever. A wall-clock or rand() seed here would make a
 *  failure unreproducible, which is the one thing a consensus test may
 *  never be. */
static uint64_t g_seed = 0x9E3779B97F4A7C15ULL;
static uint64_t g_rng_state;

static void rng_reset(void) { g_rng_state = g_seed; }

static uint64_t rng_next(void) {
    g_rng_state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g_rng_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void seed_note(const char *what, size_t iter) {
    fprintf(stderr, "  (reproduce: seed=0x%016llx %s iter=%zu)\n",
            (unsigned long long)g_seed, what, iter);
}

/** (g)(1) 500 single-byte envelope mutations. */
static void prop_envelope_mutations(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    uint8_t *mut = malloc(base->len);
    MUST_ALLOC(mut);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    MUST_ALLOC(pf);
    dna_env_view_t *probe = calloc(1, sizeof(*probe));
    MUST_ALLOC(probe);

    rng_reset();
    for (size_t it = 0; it < 500; it++) {
        int before = failures;
        memcpy(mut, base->bytes, base->len);
        size_t pos = (size_t)(rng_next() % (uint64_t)base->len);
        uint8_t delta = (uint8_t)(1u + (rng_next() % 255u));
        mut[pos] = (uint8_t)(mut[pos] + delta);

        /* The contextual table is rebuilt from the MUTATED envelope's own
         * legs, so a domain_id / ruleset_version flip cannot masquerade as
         * a context mismatch — the only two outcomes left are "the codec
         * rejected the bytes" and "OK with a different identity". Height 0
         * keeps the expiry gate out of the picture entirely (nothing can
         * be below 0). */
        int decodes = dna_env_decode(mut, base->len, probe) == 0;
        dna_env_leg_ctx_t ctx[DNA_ENV_MAX_LEGS];
        memset(ctx, 0, sizeof(ctx));
        uint16_t nctx = decodes ? probe->leg_count : 0;
        for (uint16_t i = 0; i < nctx; i++) {
            ctx[i].domain_id       = probe->leg[i].domain_id;
            ctx[i].ruleset_version = probe->leg[i].ruleset_version;
            memcpy(ctx[i].ruleset_hash, f->rh[i], DNA_ENV_RULESET_HASH_LEN);
        }

        dna_env_preflight_status_t st =
            dna_env_preflight(mut, base->len, f->chain_id, 0, ctx, nctx,
                              dirty_pf(pf));

        if (!decodes) {
            CHECK(st == DNA_ENV_PF_ERR_DECODE);
            expect_zeroed(pf, "mutation decode reject");
        } else {
            CHECK(st == DNA_ENV_PF_OK);
            /* NO mutation may leave the identity unchanged: tx_id covers
             * the complete envelope bytes. */
            CHECK(memcmp(pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        }
        if (failures != before) { seed_note("envelope-mutation", it); break; }
    }

    free(probe);
    free(pf);
    free(mut);
    run_free(base);
    fx_free(f);
}

/** (g)(2) 200 single-byte chain-id mutations. */
static void prop_chain_id_mutations(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    MUST_ALLOC(pf);

    rng_reset();
    for (size_t it = 0; it < 200; it++) {
        int before = failures;
        uint8_t chain[DNA_ENV_CHAIN_ID_LEN];
        memcpy(chain, f->chain_id, sizeof(chain));
        size_t pos = (size_t)(rng_next() % (uint64_t)DNA_ENV_CHAIN_ID_LEN);
        uint8_t delta = (uint8_t)(1u + (rng_next() % 255u));
        chain[pos] = (uint8_t)(chain[pos] + delta);

        dna_env_preflight_status_t st =
            dna_env_preflight(base->bytes, base->len, chain, 0,
                              base->ctx, base->nctx, pf);
        CHECK(st == DNA_ENV_PF_OK);
        CHECK(memcmp(pf->auth_context_commit,
                     base->pf->auth_context_commit, HASH_LEN) != 0);
        CHECK(memcmp(pf->tx_id, base->pf->tx_id, HASH_LEN) != 0);
        /* EVERY byte position matters, including 16..31 */
        for (uint16_t i = 0; i < 3; i++)
            CHECK(memcmp(pf->call_commit[i], base->pf->call_commit[i],
                         HASH_LEN) == 0);
        if (failures != before) { seed_note("chain-mutation", it); break; }
    }

    free(pf);
    run_free(base);
    fx_free(f);
}

/** (g)(3) 100 expiry values against the locked comparison. */
static void prop_expiry_values(void) {
    const uint64_t H = 5000;
    static const uint64_t fixed[] = {
        0, 1, 4998, 4999, 5000, 5001, 5002, UINT64_MAX,
        UINT64_MAX - 1, 2500
    };
    const size_t n_fixed = sizeof(fixed) / sizeof(fixed[0]);

    rng_reset();
    for (size_t it = 0; it < 100; it++) {
        int before = failures;
        uint64_t e = it < n_fixed ? fixed[it] : rng_next();
        /* Bias half the random draws into the interesting neighbourhood. */
        if (it >= n_fixed && (it % 2) == 0)
            e = H - 3 + (e % 7);

        fixture_t *f = fx_season();
        f->expiry = e;
        run_t *r = fx_run(f, H);

        dna_env_preflight_status_t want =
            (e != 0 && e < H) ? DNA_ENV_PF_ERR_EXPIRED : DNA_ENV_PF_OK;
        CHECK(r->st == want);
        if (want != DNA_ENV_PF_OK) expect_zeroed(r->pf, "expiry property");

        run_free(r);
        fx_free(f);
        if (failures != before) { seed_note("expiry-value", it); break; }
    }
}

/** (g)(4) all 24 context permutations of a 4-leg envelope. */
static void prop_context_permutations(void) {
    fixture_t *f = fx_season4();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);
    CHECK(base->pf->view.leg_count == 4);

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    MUST_ALLOC(pf);

    int accepted = 0;
    for (int a = 0; a < 4; a++)
    for (int b = 0; b < 4; b++)
    for (int c = 0; c < 4; c++)
    for (int d = 0; d < 4; d++) {
        if (a == b || a == c || a == d || b == c || b == d || c == d)
            continue;                                /* permutations only */
        const int perm[4] = { a, b, c, d };
        dna_env_leg_ctx_t shuffled[4];
        for (int i = 0; i < 4; i++) shuffled[i] = base->ctx[perm[i]];

        dna_env_preflight_status_t st =
            dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                              shuffled, 4, dirty_pf(pf));
        int identity = (a == 0 && b == 1 && c == 2 && d == 3);
        if (identity) {
            CHECK(st == DNA_ENV_PF_OK);
            CHECK(memcmp(pf->tx_id, base->pf->tx_id, HASH_LEN) == 0);
            accepted++;
        } else {
            /* Legs are strictly ascending by domain_id, so ANY non-identity
             * permutation misaligns at least one domain. */
            CHECK(st == DNA_ENV_PF_ERR_CTX_DOMAIN);
            expect_zeroed(pf, "permuted context");
        }
    }
    CHECK(accepted == 1);          /* exactly ONE order is the right order */

    free(pf);
    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (h) ARG / NULL matrix.
 * ════════════════════════════════════════════════════════════════════ */
static void test_arg_matrix(void) {
    fixture_t *f = fx_season();
    run_t *base = fx_run(f, 0);
    CHECK(base->st == DNA_ENV_PF_OK);

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    MUST_ALLOC(pf);

    /* NULL out: there is nothing to zero, so only the status is checked. */
    CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                            base->ctx, 3, NULL) == DNA_ENV_PF_ERR_ARG);

    CHECK(dna_env_preflight(NULL, base->len, f->chain_id, 0,
                            base->ctx, 3, dirty_pf(pf))
          == DNA_ENV_PF_ERR_ARG);
    expect_zeroed(pf, "NULL env_bytes");

    CHECK(dna_env_preflight(base->bytes, base->len, NULL, 0,
                            base->ctx, 3, dirty_pf(pf))
          == DNA_ENV_PF_ERR_ARG);
    expect_zeroed(pf, "NULL chain_id");

    CHECK(dna_env_preflight(base->bytes, base->len, f->chain_id, 0,
                            NULL, 3, dirty_pf(pf))
          == DNA_ENV_PF_ERR_ARG);
    expect_zeroed(pf, "NULL leg_ctx");

    /* A dirty out buffer is fully cleared even on the earliest reject —
     * pre-fill with a sentinel and prove none of it survives. */
    memset(pf, 0xAA, sizeof(*pf));
    CHECK(dna_env_preflight(NULL, 0, NULL, 0, NULL, 0, pf) ==
          DNA_ENV_PF_ERR_ARG);
    expect_zeroed(pf, "dirty buffer + NULL args");

    /* Zero length is a decode reject, not a crash. */
    memset(pf, 0xAA, sizeof(*pf));
    CHECK(dna_env_preflight(base->bytes, 0, f->chain_id, 0,
                            base->ctx, 3, pf) == DNA_ENV_PF_ERR_DECODE);
    expect_zeroed(pf, "zero length");

    free(pf);
    run_free(base);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * (i) DETERMINISM — the same inputs produce byte-identical results.
 * ════════════════════════════════════════════════════════════════════ */
static void test_determinism(void) {
    fixture_t *f = fx_season();
    run_t *a = fx_run(f, 1000);
    run_t *b = fx_run(f, 1000);
    CHECK(a->st == DNA_ENV_PF_OK);
    CHECK(b->st == DNA_ENV_PF_OK);
    CHECK(a->st == b->st);

    /* Field by field — never a struct memcmp, since padding is not part
     * of the contract. */
    for (uint16_t i = 0; i < 3; i++) {
        CHECK(memcmp(a->pf->call_commit[i], b->pf->call_commit[i],
                     HASH_LEN) == 0);
        CHECK(memcmp(a->pf->auth_digest[i], b->pf->auth_digest[i],
                     HASH_LEN) == 0);
    }
    CHECK(memcmp(a->pf->auth_context_commit, b->pf->auth_context_commit,
                 HASH_LEN) == 0);
    CHECK(memcmp(a->pf->tx_id, b->pf->tx_id, HASH_LEN) == 0);
    CHECK(a->pf->view.leg_count == b->pf->view.leg_count);
    CHECK(a->pf->view.expiry_height == b->pf->view.expiry_height);
    CHECK(a->pf->view.fee_amount == b->pf->view.fee_amount);
    CHECK(a->pf->view.env_len == b->pf->view.env_len);
    CHECK(a->len == b->len);
    CHECK(memcmp(a->bytes, b->bytes, a->len) == 0);

    /* The height is NOT part of any commitment — only of the gate. */
    run_t *c = fx_run(f, 0);
    CHECK(c->st == DNA_ENV_PF_OK);
    CHECK(memcmp(c->pf->tx_id, a->pf->tx_id, HASH_LEN) == 0);
    CHECK(memcmp(c->pf->auth_context_commit, a->pf->auth_context_commit,
                 HASH_LEN) == 0);

    run_free(c);
    run_free(b);
    run_free(a);
    fx_free(f);
}

int main(void) {
    printf("sizeof(dna_env_preflight_t) = %zu bytes "
           "(view %zu + commitments %zu)\n",
           sizeof(dna_env_preflight_t), sizeof(dna_env_view_t),
           sizeof(dna_env_preflight_t) - sizeof(dna_env_view_t));

    test_expiry();
    test_chain_id_binding();
    test_ruleset_binding();
    test_kat();
    test_commitment_invariants();
    test_malformed();
    prop_envelope_mutations();
    prop_chain_id_mutations();
    prop_expiry_values();
    prop_context_permutations();
    test_arg_matrix();
    test_determinism();

    if (failures) {
        fprintf(stderr, "test_env_preflight: %d check(s) failed "
                "(%d passed)\n", failures, g_checks);
        return 1;
    }
    printf("test_env_preflight: all %d checks passed\n", g_checks);
    return 0;
}
