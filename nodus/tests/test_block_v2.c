/**
 * Nodus — Ledger V2 S2: BlockHeader V2 + BlockID V2 tests (INACTIVE codec).
 *
 * KATs pinned from the independent python3 sha3_512 oracle (S2 report):
 * the 349-byte encoding (offset spot-checks + digest pin), BlockID, the
 * genesis BlockID + full-32-byte chain-id derivation, and the manifest-
 * mutation variant. Plus: strict decode negatives, a full field-mutation
 * sweep, and a DETERMINISTIC (seeded xorshift) fuzz pass over the decoder
 * and the domains-root input path — no RNG, byte-reproducible.
 *
 * @file test_block_v2.c
 */

#include "dnac/block_v2.h"
#include "dnac/ledger_roots_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void fill(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static int hex_eq(const uint8_t *h, size_t n, const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[257];
    for (size_t i = 0; i < n && i < 128; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[2 * (n < 128 ? n : 128)] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

/* python3-oracle literals */
static const char *KAT_ENC_SHA =
    "6b57e520049189934aea09aded30538f1d87f59a39a4e94ab3be2313d4985793"
    "14451a5bf3da3807764bb7dddefc09c14b41dceb710486992001f4b51ac9ef3b";
static const char *KAT_BLOCK_ID =
    "d7beb71ce44dc5b4676cf5f247e5210f2199a089cd10111303c20fe581c2f1da"
    "437997018d2936183900b82e85b71aa2d0ae013fb2fe953e0dbdc49ec98150be";
static const char *KAT_GENESIS_ID =
    "d4485cd6f0b044ad760742ca124f9633ae32c38aaf7257c8c860432c1f03ea38"
    "4bfec62599589bb593af1c2a1786f481637a3f79d5b627e87dae59a15ea17e47";
static const char *KAT_GENESIS_CHAIN =
    "d4485cd6f0b044ad760742ca124f9633ae32c38aaf7257c8c860432c1f03ea38";
static const char *KAT_GENESIS_ID_MUT =
    "e902ef055f75ecbf083b0bf0c1c143bbf252d09db203e650a824374df6c23da7"
    "1716fa1bd3c1e20fe83cae136955b47c69c6ace0dd488cfd0b1177a17000c6d5";

static void base_header(dna_block_header_v2_t *h) {
    memset(h, 0, sizeof(*h));
    h->header_version = 2;
    fill(h->chain_id, 32, 0xA0);
    h->block_height = 5;
    h->epoch = 2;
    fill(h->prev_block_id, 64, 0xC0);
    fill(h->global_state_root, 64, 0xD0);
    fill(h->tx_root, 64, 0xE0);
    fill(h->validator_set_hash, 64, 0xF0);
    h->tx_count = 3;
    fill(h->proposer_id, 32, 0x11);
    h->timestamp = 0x0102030405060708ULL;
}

/* The encoding is pinned two ways: OFFSET SPOT-CHECKS (every field at its
 * documented offset, literal bytes) + a digest of the full 349 bytes
 * pinned from the python oracle. */
#include "crypto/hash/qgp_sha3.h"

int main(void) {
    dna_block_header_v2_t h;
    base_header(&h);
    uint8_t enc[DNA_BH2_ENC_SIZE];
    CHECK(dna_bh2_encode(&h, enc) == 0, "encode"); OK();

    /* Offset spot checks per the documented table. */
    CHECK(enc[0] == 2, "version @0"); OK();
    CHECK(enc[1] == 0xA0 && enc[32] == (uint8_t)(0xA0 + 31 * 7),
          "chain_id @1"); OK();
    CHECK(enc[33] == 0 && enc[40] == 5, "height BE @33"); OK();
    CHECK(enc[41] == 0 && enc[48] == 2, "epoch BE @41"); OK();
    CHECK(enc[49] == 0xC0, "prev @49"); OK();
    CHECK(enc[113] == 0xD0, "gsr @113"); OK();
    CHECK(enc[177] == 0xE0, "tx_root @177"); OK();
    CHECK(enc[241] == 0xF0, "vset @241"); OK();
    CHECK(enc[305] == 0 && enc[308] == 3, "tx_count BE @305"); OK();
    CHECK(enc[309] == 0x11, "proposer @309"); OK();
    CHECK(enc[341] == 0x01 && enc[348] == 0x08, "timestamp BE @341"); OK();

    /* Whole-encoding digest pinned from the oracle. */
    uint8_t dg[64];
    CHECK(qgp_sha3_512(enc, sizeof(enc), dg) == 0, "sha");
    CHECK(hex_eq(dg, 64, KAT_ENC_SHA, "encoding digest"), "enc KAT"); OK();

    /* Round trip. */
    dna_block_header_v2_t back;
    CHECK(dna_bh2_decode(enc, sizeof(enc), &back) == 0, "decode"); OK();
    CHECK(back.header_version == 2 && back.block_height == 5 &&
          back.epoch == 2 && back.tx_count == 3 &&
          back.timestamp == h.timestamp &&
          memcmp(back.chain_id, h.chain_id, 32) == 0 &&
          memcmp(back.validator_set_hash, h.validator_set_hash, 64) == 0,
          "round trip"); OK();

    /* BlockID KAT + binding sweep. */
    uint8_t id[64], id2[64];
    CHECK(dna_bh2_block_id(&h, id) == 0, "block id");
    CHECK(hex_eq(id, 64, KAT_BLOCK_ID, "block id"), "id KAT"); OK();
    {
        dna_block_header_v2_t m;
        /* every field except timestamp changes the id */
        base_header(&m); m.chain_id[0] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "chain_id unbound"); OK();
        base_header(&m); m.block_height ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "height unbound"); OK();
        base_header(&m); m.epoch ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "epoch unbound"); OK();
        base_header(&m); m.prev_block_id[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "prev unbound"); OK();
        base_header(&m); m.global_state_root[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "gsr unbound"); OK();
        base_header(&m); m.tx_root[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "tx_root unbound"); OK();
        base_header(&m); m.validator_set_hash[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "vset unbound"); OK();
        base_header(&m); m.tx_count ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "tx_count unbound"); OK();
        base_header(&m); m.proposer_id[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "proposer unbound"); OK();
        /* timestamp is informational: mutation must NOT change the id */
        base_header(&m); m.timestamp ^= 0xFFFF;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) == 0,
              "timestamp leaked into BlockID"); OK();
        /* version gate on hashing */
        base_header(&m); m.header_version = 1;
        CHECK(dna_bh2_block_id(&m, id2) != 0, "v1 header hashed"); OK();
    }

    /* Decode negatives: truncation at every boundary class, trailing,
     * unknown versions. */
    {
        dna_block_header_v2_t t;
        const size_t cuts[7] = { 0, 1, 33, 113, 305, 341, 348 };
        for (int i = 0; i < 7; i++) {
            CHECK(dna_bh2_decode(enc, cuts[i], &t) != 0, "truncated ok'd"); OK();
        }
        uint8_t big[DNA_BH2_ENC_SIZE + 1];
        memcpy(big, enc, sizeof(enc)); big[DNA_BH2_ENC_SIZE] = 0;
        CHECK(dna_bh2_decode(big, sizeof(big), &t) != 0, "trailing ok'd"); OK();
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, enc, sizeof(bad)); bad[0] = 1;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v1 ok'd"); OK();
        memcpy(bad, enc, sizeof(bad)); bad[0] = 3;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v3 ok'd"); OK();
        CHECK(dna_bh2_decode(NULL, sizeof(enc), &t) != 0, "null ok'd"); OK();
    }

    /* Genesis: explicit semantics, manifest binding, 32-byte chain id. */
    {
        dna_block_header_v2_t g;
        base_header(&g);
        memset(g.chain_id, 0, 32);
        g.block_height = 0;
        g.epoch = 0;
        memset(g.prev_block_id, 0, 64);
        g.tx_count = 1;
        uint8_t manifest[64];
        memcpy(manifest, "DNA-TEST-MANIFEST-v1", 20);
        fill(manifest + 20, 44, 0x33);

        uint8_t gid[64], cid[32];
        CHECK(dna_bh2_genesis_block_id(&g, manifest, sizeof(manifest), gid) == 0,
              "genesis id");
        CHECK(hex_eq(gid, 64, KAT_GENESIS_ID, "genesis id"), "gid KAT"); OK();
        CHECK(dna_bh2_derive_chain_id(gid, cid) == 0, "derive");
        CHECK(hex_eq(cid, 32, KAT_GENESIS_CHAIN, "chain id"), "cid KAT"); OK();
        /* FULL 32-byte prefix: bytes 16..31 equal the id (never zeroed). */
        CHECK(memcmp(cid + 16, gid + 16, 16) == 0, "tail not from id"); OK();
        uint8_t z16[16] = { 0 };
        CHECK(memcmp(cid + 16, z16, 16) != 0, "tail zeroed (legacy bug)"); OK();

        /* Any manifest byte change changes genesis id AND chain id. */
        uint8_t gid2[64], cid2[32];
        manifest[0] ^= 1;
        CHECK(dna_bh2_genesis_block_id(&g, manifest, sizeof(manifest), gid2) == 0,
              "genesis id mut");
        CHECK(hex_eq(gid2, 64, KAT_GENESIS_ID_MUT, "genesis id mut"),
              "gid mut KAT"); OK();
        CHECK(dna_bh2_derive_chain_id(gid2, cid2) == 0 &&
              memcmp(cid, cid2, 32) != 0, "chain id not manifest-bound"); OK();
        manifest[0] ^= 1;

        /* Explicit genesis semantics enforced. */
        dna_block_header_v2_t badg = g;
        badg.block_height = 1;
        CHECK(dna_bh2_genesis_block_id(&badg, manifest, sizeof(manifest),
                                       gid2) != 0, "height!=0 ok'd"); OK();
        badg = g; badg.chain_id[3] = 1;
        CHECK(dna_bh2_genesis_block_id(&badg, manifest, sizeof(manifest),
                                       gid2) != 0, "nonzero chain ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, NULL, 0, gid2) != 0,
              "null manifest ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, manifest, 0, gid2) != 0,
              "empty manifest ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, manifest,
                                       (size_t)DNA_BH2_MANIFEST_MAX + 1,
                                       gid2) != 0, "oversize manifest ok'd");
        OK();

        /* Non-genesis wrong-chain rejection. */
        uint8_t expect_chain[32];
        fill(expect_chain, 32, 0xA0);
        CHECK(dna_bh2_check_chain(&h, expect_chain) == 0, "chain match"); OK();
        expect_chain[7] ^= 1;
        CHECK(dna_bh2_check_chain(&h, expect_chain) != 0,
              "wrong chain accepted"); OK();
    }

    /* ── Deterministic fuzz (seeded xorshift64 — reproducible, no RNG) ── */
    {
        uint64_t s = 0x53325F46555A5A31ULL;   /* fixed seed */
        #define XRND() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)
        uint8_t buf[512];
        dna_block_header_v2_t t;
        int decoded = 0;
        for (int it = 0; it < 20000; it++) {
            size_t len = (size_t)(XRND() % (sizeof(buf) + 1));
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)XRND();
            int rc = dna_bh2_decode(buf, len, &t);
            /* Structural invariant: success ⇒ exact size + version 2. */
            if (rc == 0) {
                decoded++;
                CHECK(len == (size_t)DNA_BH2_ENC_SIZE && buf[0] == 2,
                      "fuzz decode invariant");
            }
        }
        OK();
        /* Structured mutations of a valid frame: decode either rejects or
         * re-encodes byte-identically (canonicality). */
        for (int it = 0; it < 5000; it++) {
            uint8_t m[DNA_BH2_ENC_SIZE];
            memcpy(m, enc, sizeof(m));
            m[XRND() % sizeof(m)] ^= (uint8_t)(XRND() | 1);
            if (dna_bh2_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_BH2_ENC_SIZE];
                CHECK(dna_bh2_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0, "fuzz canonicality");
            }
        }
        OK();
        /* Domains-root input fuzz: random head lists — acceptance implies
         * the SYSTEM-first strictly-sorted invariant. */
        for (int it = 0; it < 5000; it++) {
            dna_v2_domain_head_t heads[5];
            memset(heads, 0, sizeof(heads));
            size_t n = 1 + (size_t)(XRND() % 5);
            for (size_t i = 0; i < n; i++) {
                heads[i].domain_id = (uint32_t)(XRND() % 6);
                heads[i].domain_state_root[0] = (uint8_t)XRND();
                heads[i].status = (uint8_t)(XRND() % 4);
            }
            uint8_t r[64];
            if (dna_v2_domains_root(heads, n, r) == 0) {
                CHECK(heads[0].domain_id == 0, "fuzz: SYSTEM-first violated");
                for (size_t i = 1; i < n; i++)
                    CHECK(heads[i - 1].domain_id < heads[i].domain_id,
                          "fuzz: sort invariant violated");
            }
        }
        OK();
        #undef XRND
    }

    printf("test_block_v2: %d checks OK\n", g_checks);
    return 0;
}
