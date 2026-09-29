/**
 * test_msig_wire.c — general multisig (decision 2026-09-29-general-
 * multisig.md, design §7 rev 2): the DESCRIPTOR codec and the multisig
 * ADDRESS (shared/dnac/msig_wire.{c,h}).
 *
 * What is pinned:
 *   1. the 16-byte tag bytes ("DNA.MSIG.v1" + 5 zero bytes);
 *   2. the validation matrix — N = 1 / 8 refused, M = 0 / M > N refused,
 *      descending / duplicate keys refused, a zero-prefix key refused
 *      (first 32 bytes zero — the kind-1 signer rule), wrong length /
 *      trailing byte / wrong tag refused; legal shapes accepted;
 *   3. the ADDRESS vectors of the independent oracle
 *      (shared/dnac/tests/multisig_oracle.py) for the same fake keys:
 *      2-of-3, 1-of-2, 7-of-7, 5-of-7, and 1/2/3-of-3 over one key set;
 *   4. M changes the address; a plain address SHA3-512(pubkey) never
 *      equals a multisig address over the same keys.
 *
 * The address constants below are PINNED (2026-09-29) from
 * `python3 shared/dnac/tests/multisig_oracle.py` (the lines
 * "<label>: address=…"), written by an agent that did not read this C —
 * never from this build's own encoder.
 *
 * HOW IT CAN LIE: the keys are the oracle's FAKE keys (SHA3-expanded
 * seeds), not ML-DSA-87 keys — the codec never interprets key bytes, so
 * this proves framing and hashing only. Agreement with the oracle proves
 * both implement the same written layout, not that the layout is sound.
 * Requires nothing beyond a default build.
 */

#include "dnac/msig_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,    \
                    __LINE__, msg);                                     \
            return 1;                                                   \
        }                                                               \
        g_checks++;                                                     \
    } while (0)

#define PK DNA_MSIG_PUBKEY_LEN

/* The oracle's fake_pubkey(seed): the first 2592 bytes of
 * SHA3-512("MSIG.ORACLE.PK" ‖ seed u32 BE ‖ ctr u32 BE), ctr = 0,1,… */
static int fake_pubkey(uint32_t seed, uint8_t out[PK]) {
    static const char dom[] = "MSIG.ORACLE.PK";   /* 14 bytes, no NUL */
    uint8_t pre[14 + 4 + 4];
    uint8_t h[64];
    size_t off = 0;
    for (uint32_t ctr = 0; off < PK; ctr++) {
        memcpy(pre, dom, 14);
        pre[14] = (uint8_t)(seed >> 24); pre[15] = (uint8_t)(seed >> 16);
        pre[16] = (uint8_t)(seed >> 8);  pre[17] = (uint8_t)seed;
        pre[18] = (uint8_t)(ctr >> 24);  pre[19] = (uint8_t)(ctr >> 16);
        pre[20] = (uint8_t)(ctr >> 8);   pre[21] = (uint8_t)ctr;
        if (qgp_sha3_512(pre, sizeof(pre), h) != 0) return -1;
        size_t take = (PK - off) < 64 ? (PK - off) : 64;
        memcpy(out + off, h, take);
        off += take;
    }
    return 0;
}

static int cmp_pk(const void *a, const void *b) {
    return memcmp(a, b, PK);
}

/* ── PINNED 2026-09-29 from shared/dnac/tests/multisig_oracle.py (written from
 * the design text by an agent that never saw this C; self-consistent, not an
 * external audit) ─────────────────────────────────────────────────────── */
static const uint8_t KAT_ADDR_2OF3[64] = { 0x3b, 0x66, 0x13, 0x41, 0x67, 0x43, 0xe4, 0x27, 0x20, 0xb1, 0x7e, 0x23, 0xb6, 0x8c, 0xf5, 0x54, 0x12, 0x18, 0x1b, 0x1b, 0x82, 0x5c, 0x7d, 0x8f, 0x82, 0x3a, 0xc2, 0x7d, 0x41, 0x7f, 0xbc, 0x64, 0xf0, 0x70, 0x6d, 0x31, 0x65, 0x71, 0xc6, 0x6f, 0x5f, 0x26, 0x0b, 0x3b, 0x80, 0x8b, 0xbf, 0xce, 0x5f, 0xb9, 0xc5, 0x7c, 0xe6, 0x29, 0x4d, 0x4a, 0x7e, 0xbc, 0x3f, 0xac, 0xd5, 0x5e, 0x51, 0x6b };
static const uint8_t KAT_ADDR_1OF2[64] = { 0x01, 0xe5, 0x87, 0xec, 0x58, 0x69, 0x0a, 0xd7, 0xf2, 0x94, 0x32, 0x67, 0x2e, 0xf4, 0xba, 0x1b, 0x71, 0x26, 0xa0, 0xed, 0x01, 0xc8, 0x52, 0x18, 0x27, 0x55, 0x02, 0x3c, 0x3e, 0x99, 0xd5, 0x92, 0x8e, 0xa4, 0x93, 0x72, 0xa6, 0x0a, 0x80, 0x0a, 0x8e, 0x5f, 0x1a, 0x6b, 0x73, 0x72, 0x5f, 0xda, 0x29, 0x9e, 0x27, 0xb0, 0x32, 0x32, 0x8a, 0x50, 0xaa, 0xed, 0xff, 0x50, 0x44, 0x8c, 0xe5, 0xbf };
static const uint8_t KAT_ADDR_7OF7[64] = { 0x09, 0xd8, 0x46, 0x77, 0xdc, 0xe3, 0x8b, 0xc7, 0xaf, 0xfa, 0x58, 0x17, 0x0d, 0xb8, 0xfb, 0x17, 0xb0, 0xda, 0xe4, 0x0f, 0xba, 0xc0, 0x1d, 0x3b, 0x9b, 0x27, 0x99, 0xaa, 0x92, 0x80, 0x5c, 0x44, 0x58, 0x44, 0xf1, 0x9b, 0x55, 0xe2, 0x26, 0xb7, 0xba, 0x2e, 0x8e, 0x4a, 0x76, 0x69, 0x58, 0x26, 0x05, 0x81, 0xe3, 0x6d, 0x7f, 0xc8, 0xc4, 0x6f, 0xdd, 0x3e, 0x5f, 0x17, 0x3e, 0xd6, 0xc9, 0x2e };
static const uint8_t KAT_ADDR_5OF7[64] = { 0x6d, 0x56, 0xd6, 0x9f, 0x70, 0xa8, 0x4c, 0xeb, 0xd5, 0xc9, 0x58, 0x05, 0xaf, 0xa5, 0xa4, 0xf3, 0x72, 0xb9, 0x61, 0x47, 0x2c, 0x2a, 0x79, 0xe2, 0x65, 0x65, 0x6d, 0x82, 0x5d, 0x74, 0xd3, 0x9c, 0x0a, 0x2b, 0x1b, 0x9e, 0x75, 0x63, 0xc1, 0x7c, 0x47, 0x7d, 0xd9, 0x38, 0xfe, 0xaf, 0x67, 0xc2, 0xed, 0x25, 0x10, 0xb9, 0x72, 0xc8, 0x65, 0x14, 0x04, 0xa1, 0x2e, 0xdd, 0xd3, 0xa4, 0x54, 0x05 };
static const uint8_t KAT_ADDR_1OF3[64] = { 0xa2, 0x7a, 0xa3, 0xea, 0x69, 0x83, 0xcc, 0xe3, 0x6c, 0xf4, 0x78, 0xb5, 0x85, 0xd4, 0x43, 0xd0, 0x4d, 0xbf, 0x67, 0xe4, 0x1c, 0x1b, 0x21, 0x9c, 0xbc, 0x8f, 0x6b, 0x18, 0x0f, 0xd2, 0x30, 0x28, 0xe5, 0xee, 0x0d, 0x2f, 0x0e, 0xed, 0x66, 0x1a, 0x8b, 0x0a, 0x2b, 0xdf, 0xf4, 0x34, 0x56, 0x13, 0x06, 0xae, 0x53, 0x00, 0xc4, 0x97, 0x76, 0x5b, 0x9c, 0xfa, 0x8f, 0x22, 0x10, 0x64, 0x7a, 0xa0 };
static const uint8_t KAT_ADDR_3OF3[64] = { 0xda, 0x6f, 0xd5, 0x20, 0xfb, 0x7d, 0xb7, 0x71, 0x1a, 0x45, 0xf7, 0xba, 0x4f, 0x12, 0xc8, 0x7d, 0xd1, 0xfa, 0xf6, 0xe2, 0x46, 0x76, 0x43, 0xce, 0xa6, 0x8e, 0x6f, 0xee, 0x25, 0x10, 0xd4, 0xf7, 0xa7, 0x35, 0xc8, 0x65, 0xad, 0x51, 0x45, 0x7e, 0x91, 0xf3, 0x06, 0xf5, 0xbc, 0xf4, 0xec, 0x40, 0x8e, 0xae, 0xc1, 0xbb, 0xed, 0xc7, 0x4b, 0xc9, 0xa5, 0x11, 0xf0, 0x1c, 0x61, 0x3b, 0x15, 0xfe };

int main(void) {
    /* k[i] = the i-th smallest of fake_pubkey(1..15) (the oracle's key
     * list); 15 × 2592 bytes on the heap. */
    uint8_t *k = malloc(15u * PK);
    uint8_t *d = malloc(DNA_MSIG_MAX_DESC_LEN + 1u);
    uint8_t *keys = malloc(8u * PK);
    CHECK(k && d && keys, "alloc");
    for (uint32_t s = 1; s <= 15; s++)
        CHECK(fake_pubkey(s, k + (size_t)(s - 1) * PK) == 0, "fake key");
    qsort(k, 15, PK, cmp_pk);
#define KEY(i) (k + (size_t)(i) * PK)

    /* ── 1. tag bytes ──────────────────────────────────────────────── */
    {
        static const uint8_t want[16] = {
            0x44, 0x4e, 0x41, 0x2e, 0x4d, 0x53, 0x49, 0x47,
            0x2e, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        size_t len = 0;
        CHECK(dna_msig_desc_encode(2, 3, KEY(0), d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) == 0, "2-of-3 encodes");
        CHECK(len == DNA_MSIG_DESC_LEN(3) && len == 7794u,
              "2-of-3 descriptor length = 18 + 3 x 2592");
        CHECK(memcmp(d, want, 16) == 0, "tag bytes");
        CHECK(d[16] == 2 && d[17] == 3, "M, N octets");
        CHECK(memcmp(d + 18, KEY(0), 3u * PK) == 0, "keys verbatim");
    }

    /* ── 2. validation matrix ──────────────────────────────────────── */
    {
        size_t len = 0;
        CHECK(dna_msig_desc_encode(1, 1, KEY(0), d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "N=1 refused");
        memcpy(keys, KEY(0), 7u * PK);
        memcpy(keys + 7u * PK, KEY(7), PK);
        CHECK(dna_msig_desc_encode(1, 8, keys, d, DNA_MSIG_MAX_DESC_LEN + 1u,
                                   &len) != 0, "N=8 refused");
        CHECK(dna_msig_desc_encode(0, 3, KEY(0), d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "M=0 refused");
        CHECK(dna_msig_desc_encode(4, 3, KEY(0), d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "M=4 > N=3 refused");
        /* descending */
        memcpy(keys, KEY(1), PK);
        memcpy(keys + PK, KEY(0), PK);
        memcpy(keys + 2u * PK, KEY(2), PK);
        CHECK(dna_msig_desc_encode(2, 3, keys, d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "descending keys refused");
        /* duplicate */
        memcpy(keys, KEY(0), PK);
        memcpy(keys + PK, KEY(0), PK);
        memcpy(keys + 2u * PK, KEY(1), PK);
        CHECK(dna_msig_desc_encode(2, 3, keys, d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "duplicate key refused");
        /* zero-prefix key (first 32 bytes zero, the rest non-zero) —
         * sorts first, so the order check is not what refuses it */
        memcpy(keys, KEY(0), PK);
        memset(keys, 0, 32);
        memcpy(keys + PK, KEY(1), PK);
        CHECK(dna_msig_desc_encode(1, 2, keys, d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) != 0, "zero-prefix key refused");
        /* capacity */
        CHECK(dna_msig_desc_encode(2, 3, KEY(0), d, DNA_MSIG_DESC_LEN(3) - 1u,
                                   &len) != 0, "short output refused");

        /* parse side: a legal 2-of-3, then byte-level mutants */
        CHECK(dna_msig_desc_encode(2, 3, KEY(0), d, DNA_MSIG_MAX_DESC_LEN,
                                   &len) == 0, "2-of-3 encodes");
        uint8_t m = 0, n = 0;
        const uint8_t *kp = NULL;
        CHECK(dna_msig_desc_parse(d, len, &m, &n, &kp) == 0 && m == 2 &&
              n == 3 && kp == d + 18, "legal descriptor parses");
        CHECK(dna_msig_desc_parse(d, len - 1u, NULL, NULL, NULL) != 0,
              "truncated descriptor refused");
        d[len] = 0;
        CHECK(dna_msig_desc_parse(d, len + 1u, NULL, NULL, NULL) != 0,
              "trailing byte refused");
        d[0] ^= 0x01;
        CHECK(dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0,
              "wrong tag refused");
        d[0] ^= 0x01;
        d[16] = 0;
        CHECK(dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0,
              "parsed M=0 refused");
        d[16] = 4;
        CHECK(dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0,
              "parsed M>N refused");
        d[16] = 2;
        d[17] = 2;
        CHECK(dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0,
              "N that disagrees with the length refused");
        d[17] = 3;
        memcpy(d + 18 + PK, KEY(0), PK);     /* key[1] := key[0]: dup     */
        CHECK(dna_msig_desc_parse(d, len, NULL, NULL, NULL) != 0,
              "parsed duplicate refused");
        uint8_t a[64];
        CHECK(dna_msig_address(d, len, a) == -1,
              "an invalid descriptor has no address");
    }

    /* ── 3. address vectors (oracle KATs) ──────────────────────────── */
    {
        struct { uint8_t m, n, first; const uint8_t *kat; const char *lbl; }
        cases[] = {
            { 2, 3, 0, KAT_ADDR_2OF3, "2-of-3" },
            { 1, 2, 0, KAT_ADDR_1OF2, "1-of-2" },
            { 7, 7, 0, KAT_ADDR_7OF7, "7-of-7" },
            { 5, 7, 0, KAT_ADDR_5OF7, "5-of-7" },
            { 1, 3, 0, KAT_ADDR_1OF3, "1-of-3" },
            { 3, 3, 0, KAT_ADDR_3OF3, "3-of-3" },
        };
        uint8_t addrs[6][64];
        for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            size_t len = 0;
            CHECK(dna_msig_desc_encode(cases[c].m, cases[c].n,
                                       KEY(cases[c].first), d,
                                       DNA_MSIG_MAX_DESC_LEN, &len) == 0,
                  "vector descriptor encodes");
            CHECK(dna_msig_address(d, len, addrs[c]) == 0, "address");
            uint8_t direct[64];
            CHECK(qgp_sha3_512(d, len, direct) == 0 &&
                  memcmp(direct, addrs[c], 64) == 0,
                  "address == SHA3-512(descriptor)");
            if (memcmp(addrs[c], cases[c].kat, 64) != 0) {
                fprintf(stderr, "KAT mismatch for %s (placeholder not yet "
                        "pasted from multisig_oracle.py?)\n", cases[c].lbl);
                return 1;
            }
            g_checks++;
        }
        /* ── 4. M changes the address; plain != multisig ──────────── */
        CHECK(memcmp(addrs[0], addrs[4], 64) != 0 &&
              memcmp(addrs[0], addrs[5], 64) != 0 &&
              memcmp(addrs[4], addrs[5], 64) != 0,
              "1/2/3-of-3 over the same keys are three addresses");
        for (int i = 0; i < 3; i++) {
            uint8_t plain[64];
            CHECK(qgp_sha3_512(KEY(i), PK, plain) == 0, "plain address");
            CHECK(memcmp(plain, addrs[0], 64) != 0 &&
                  memcmp(plain, addrs[4], 64) != 0 &&
                  memcmp(plain, addrs[5], 64) != 0,
                  "a plain address never equals a multisig address");
        }
    }

    free(k);
    free(d);
    free(keys);
    printf("test_msig_wire: %d checks OK\n", g_checks);
    return 0;
}
