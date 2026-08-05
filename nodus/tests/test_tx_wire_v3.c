/**
 * Nodus — Ledger V2 S1: Transaction Wire V3 + ExecutionContext codec tests.
 *
 * V3 is INACTIVE on the live chain (every active consensus path rejects
 * wire versions != 2); these tests pin the codec itself:
 *   - byte-exact encode KATs against HAND-WRITTEN literal expectations
 *     (not encode-then-decode circularity);
 *   - the V5 tx-hash against a literal computed with an INDEPENDENT
 *     SHA3-512 implementation (python3 hashlib.sha3_512 over the spec'd
 *     preimage bytes — see the capture note at the literal);
 *   - a full per-field mutation sweep (every header field, chain_id, body);
 *   - strict decode negatives: truncation at every boundary class,
 *     trailing garbage, body_len mismatch, unsupported version, over-cap
 *     body, checked-size overflow;
 *   - ExecutionContext init/validate/encode/decode incl. fail-closed
 *     negatives and the byte-exact 50-byte layout.
 *
 * @file test_tx_wire_v3.c
 */

#include "dnac/tx_wire.h"

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

static const uint8_t CHAIN_ID[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

static void base_header(dnac_txw3_header_t *h) {
    memset(h, 0, sizeof(*h));
    h->wire_version      = 3;
    h->tx_type           = 1;               /* SPEND */
    h->domain_id         = DNA_DOMAIN_CORE; /* 1 */
    h->pool_id           = DNA_POOL_NONE;   /* 0 */
    h->ruleset_version   = 7;
    h->statement_version = 0;
    h->expiry_height     = 1000;
    h->committed_fee     = 1000000;
    h->timestamp         = 0x0102030405060708ULL;
    fill(h->tx_hash, DNAC_TXW_HASH_LEN, 0xC0);
}

/* V5 hash of the base fixture with body "abc" — computed INDEPENDENTLY:
 *   python3 hashlib.sha3_512 over the byte string
 *   "DNAC_TX_V5"+6*\x00 ‖ CHAIN_ID ‖ 03 01 ‖ 00000001 ‖ 00000000 ‖
 *   00000007 ‖ 00000000 ‖ 00000000000003E8 ‖ 00000000000F4240 ‖
 *   0102030405060708 ‖ 00000003 ‖ "abc"
 * (capture command recorded in the S1 season report). */
static const char *V5_KAT_HEX =
    "2a04c794e052de62605de6cfdf0567d061b4f3725f340a50ee9d0178a8d93814"
    "adb8e4dde97bda378073f8170db04171dd2ce54bb32ae4cd3be56a664f0a4948";

static int hex_eq(const uint8_t h[64], const char *hex) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i]     = d[h[i] >> 4];
        got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "hash KAT mismatch:\n  pinned: %s\n  got:    %s\n", hex, got);
        return 0;
    }
    return 1;
}

/* ── ExecutionContext ────────────────────────────────────────────────── */
static int test_exec_context(void) {
    dna_exec_context_t ctx;

    /* Valid: DNA_CORE spend, no pool, no statement. */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, DNA_DOMAIN_CORE, DNA_POOL_NONE,
                                1, 3, 7, 0) == 0, "init valid"); OK();
    CHECK(dna_exec_context_validate(&ctx) == 0, "validate"); OK();

    /* Byte-exact 50-byte encoding (hand-written literal). */
    uint8_t enc[DNA_EXEC_CTX_WIRE_LEN];
    CHECK(dna_exec_context_encode(&ctx, enc) == 0, "encode"); OK();
    uint8_t expect[DNA_EXEC_CTX_WIRE_LEN];
    memcpy(expect, CHAIN_ID, 32);
    const uint8_t tail[18] = {
        0x00,0x00,0x00,0x01,   /* domain_id = 1  */
        0x00,0x00,0x00,0x00,   /* pool_id   = 0  */
        0x01,                  /* tx_type   = 1  */
        0x03,                  /* wire_ver  = 3  */
        0x00,0x00,0x00,0x07,   /* ruleset   = 7  */
        0x00,0x00,0x00,0x00    /* statement = 0  */
    };
    memcpy(expect + 32, tail, 18);
    CHECK(memcmp(enc, expect, DNA_EXEC_CTX_WIRE_LEN) == 0, "exec ctx KAT"); OK();

    /* Decode round trip + strict length. */
    dna_exec_context_t back;
    CHECK(dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0, "decode"); OK();
    CHECK(memcmp(&back.chain_id, CHAIN_ID, 32) == 0 &&
          back.domain_id == 1 && back.pool_id == 0 && back.tx_type == 1 &&
          back.wire_version == 3 && back.ruleset_version == 7 &&
          back.statement_version == 0, "decode fields"); OK();
    CHECK(dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN - 1, &back) != 0,
          "short decode accepted"); OK();
    CHECK(dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN + 1, &back) != 0,
          "long decode accepted"); OK();

    /* STRUCTURAL fail-closed negatives (the only rejects the generic
     * codec may make: null input, unsupported wire version). */
    CHECK(dna_exec_context_init(&ctx, NULL, 1, 0, 1, 3, 7, 0) != 0, "null chain"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 0, 1, 2, 7, 0) != 0,
          "legacy wire_version accepted"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 0, 1, 4, 7, 0) != 0,
          "unknown wire_version accepted"); OK();

    /* S1 correction #1 — FUTURE values are STRUCTURALLY legal: the generic
     * codec must encode/decode them without modification. They stay
     * inactive because no production admission route exists (S4/S9). */
    /* (a) unknown future domain_id */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 7, 0, 1, 3, 7, 0) == 0,
          "future domain rejected by codec"); OK();
    CHECK(dna_exec_context_encode(&ctx, enc) == 0 &&
          dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0 &&
          back.domain_id == 7, "future domain round trip"); OK();
    /* (b) future nonzero pool_id on a non-shielded type */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 7, 42, 1, 3, 7, 0) == 0,
          "future pool rejected by codec"); OK();
    CHECK(dna_exec_context_encode(&ctx, enc) == 0 &&
          dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0 &&
          back.pool_id == 42, "future pool round trip"); OK();
    /* (c) nonzero statement_version on a future proof-bearing type */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 7, 42, 14, 3, 7, 3) == 0,
          "future statement rejected by codec"); OK();
    CHECK(dna_exec_context_encode(&ctx, enc) == 0 &&
          dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0 &&
          back.statement_version == 3 && back.tx_type == 14,
          "future statement round trip"); OK();
    /* (d) unassigned transaction-type byte */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 0, 200, 3, 7, 0) == 0,
          "unassigned type rejected by codec"); OK();
    CHECK(dna_exec_context_encode(&ctx, enc) == 0 &&
          dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0 &&
          back.tx_type == 200, "unassigned type round trip"); OK();

    /* INITIAL-POLICY helper (separate layer, zero production callers):
     * the old S1 policy set now lives here — and ONLY here. */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, DNA_DOMAIN_CORE, 0, 1, 3, 7, 0) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) == 0,
          "policy: CORE spend"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, DNA_DOMAIN_CORE,
                                DNAC_SHIELDED_POOL_V1, 11, 3, 7, 5) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) == 0,
          "policy: shielded pool 1"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 2, 0, 1, 3, 7, 0) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) != 0,
          "policy: unknown domain passed"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 1, 1, 3, 7, 0) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) != 0,
          "policy: pool on non-shielded passed"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 0, 1, 3, 7, 5) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) != 0,
          "policy: statement on non-shielded passed"); OK();
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, 1, 0, 11, 3, 7, 5) == 0 &&
          dna_exec_context_check_initial_policy(&ctx) != 0,
          "policy: shielded with pool 0 passed"); OK();

    /* Valid shielded context round trip (structural). */
    CHECK(dna_exec_context_init(&ctx, CHAIN_ID, DNA_DOMAIN_CORE,
                                DNAC_SHIELDED_POOL_V1, 11, 3, 7, 5) == 0,
          "shielded ctx"); OK();
    CHECK(dna_exec_context_encode(&ctx, enc) == 0 &&
          dna_exec_context_decode(enc, DNA_EXEC_CTX_WIRE_LEN, &back) == 0 &&
          back.pool_id == 1 && back.statement_version == 5,
          "shielded round trip"); OK();

    /* Ownership metadata (informational). */
    CHECK(dna_tx_type_owner(1) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(4) == DNA_DOMAIN_SYSTEM &&
          dna_tx_type_owner(11) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(0) == DNA_TX_OWNER_NONE &&
          dna_tx_type_owner(8) == DNA_TX_OWNER_NONE &&
          dna_tx_type_owner(12) == DNA_TX_OWNER_NONE, "type ownership map"); OK();
    return 0;
}

/* ── Wire V3 ─────────────────────────────────────────────────────────── */
static int test_v3(void) {
    dnac_txw3_header_t hdr;
    base_header(&hdr);
    const uint8_t body[3] = { 'a', 'b', 'c' };

    /* Encoded-size arithmetic. */
    size_t need = 0;
    CHECK(dnac_txw3_encoded_size(3, &need) == 0 && need == 113, "size calc"); OK();
    CHECK(dnac_txw3_encoded_size(DNAC_TXW3_MAX_BODY_LEN, &need) == 0, "size cap ok"); OK();
    CHECK(dnac_txw3_encoded_size(DNAC_TXW3_MAX_BODY_LEN + 1, &need) != 0,
          "size over cap accepted"); OK();

    /* Byte-exact encode KAT (hand-written literal). */
    uint8_t wire[113];
    size_t written = 0;
    CHECK(dnac_txw3_encode(&hdr, body, 3, wire, sizeof(wire), &written) == 0 &&
          written == 113, "encode"); OK();
    {
        uint8_t expect[113];
        size_t o = 0;
        expect[o++] = 0x03;                                     /* wire_version */
        expect[o++] = 0x01;                                     /* tx_type      */
        const uint8_t mid[40] = {
            0x00,0x00,0x00,0x01,                                /* domain_id    */
            0x00,0x00,0x00,0x00,                                /* pool_id      */
            0x00,0x00,0x00,0x07,                                /* ruleset      */
            0x00,0x00,0x00,0x00,                                /* statement    */
            0x00,0x00,0x00,0x00,0x00,0x00,0x03,0xE8,            /* expiry=1000  */
            0x00,0x00,0x00,0x00,0x00,0x0F,0x42,0x40,            /* fee=1000000  */
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,            /* timestamp    */
        };
        memcpy(expect + o, mid, 40); o += 40;
        fill(expect + o, 64, 0xC0); o += 64;                    /* tx_hash      */
        const uint8_t blen[4] = { 0x00,0x00,0x00,0x03 };
        memcpy(expect + o, blen, 4); o += 4;
        memcpy(expect + o, body, 3); o += 3;
        CHECK(o == 113, "expect assembly");
        CHECK(memcmp(wire, expect, 113) == 0, "V3 encode KAT"); OK();
    }

    /* Decode round trip. */
    {
        dnac_txw3_header_t back;
        const uint8_t *b = NULL; uint32_t blen = 0;
        CHECK(dnac_txw3_decode(wire, 113, &back, &b, &blen) == 0, "decode"); OK();
        CHECK(back.wire_version == 3 && back.tx_type == 1 &&
              back.domain_id == 1 && back.pool_id == 0 &&
              back.ruleset_version == 7 && back.statement_version == 0 &&
              back.expiry_height == 1000 && back.committed_fee == 1000000 &&
              back.timestamp == 0x0102030405060708ULL &&
              memcmp(back.tx_hash, hdr.tx_hash, 64) == 0 &&
              blen == 3 && b && memcmp(b, body, 3) == 0, "decode fields"); OK();
    }

    /* V5 hash KAT (independent python3 sha3_512 oracle). */
    uint8_t base_hash[64];
    CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, body, 3, base_hash) == 0, "hash"); OK();
#ifndef V3_KAT_CAPTURE
    CHECK(hex_eq(base_hash, V5_KAT_HEX), "V5 hash KAT"); OK();
#else
    {
        static const char *d = "0123456789abcdef";
        char got[129];
        for (int i = 0; i < 64; i++) {
            got[2*i] = d[base_hash[i] >> 4]; got[2*i+1] = d[base_hash[i] & 0xf];
        }
        got[128] = 0;
        printf("V5KAT %s\n", got);
    }
#endif

    /* Determinism: same inputs → same hash. */
    {
        uint8_t again[64];
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, body, 3, again) == 0 &&
              memcmp(again, base_hash, 64) == 0, "hash determinism"); OK();
    }

    /* Mutation sweep — every bound field changes the hash. */
    {
        dnac_txw3_header_t m;
        uint8_t h[64];

        base_header(&m); m.tx_type ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "tx_type not bound"); OK();
        base_header(&m); m.domain_id ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "domain_id not bound"); OK();
        base_header(&m); m.pool_id ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "pool_id not bound"); OK();
        base_header(&m); m.ruleset_version ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "ruleset_version not bound"); OK();
        base_header(&m); m.statement_version ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "statement_version not bound"); OK();
        base_header(&m); m.expiry_height ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "expiry_height not bound"); OK();
        base_header(&m); m.committed_fee ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "committed_fee not bound"); OK();
        base_header(&m); m.timestamp ^= 1;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "timestamp not bound"); OK();

        uint8_t cid2[32];
        memcpy(cid2, CHAIN_ID, 32); cid2[31] ^= 1;
        base_header(&m);
        CHECK(dnac_txw3_tx_hash(&m, cid2, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "chain_id not bound"); OK();

        const uint8_t body2[3] = { 'a', 'b', 'd' };
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, body2, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "body not bound"); OK();
        /* Body ordering determinism: same bytes reordered → different hash. */
        const uint8_t body3[3] = { 'b', 'a', 'c' };
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, body3, 3, h) == 0 &&
              memcmp(h, base_hash, 64) != 0, "body order not bound"); OK();
        /* tx_hash field itself is NOT part of the preimage. */
        base_header(&m); m.tx_hash[0] ^= 0xFF;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) == 0 &&
              memcmp(h, base_hash, 64) == 0, "embedded tx_hash leaked"); OK();
        /* Unsupported wire version fails closed. */
        base_header(&m); m.wire_version = 2;
        CHECK(dnac_txw3_tx_hash(&m, CHAIN_ID, body, 3, h) != 0,
              "legacy version hashed"); OK();
    }

    /* Decode negatives. */
    {
        dnac_txw3_header_t back;
        const uint8_t *b = NULL; uint32_t blen = 0;

        /* Truncation at every boundary class. */
        const size_t cuts[6] = { 0, 1, 41, 105, 109, 112 };
        for (int i = 0; i < 6; i++) {
            CHECK(dnac_txw3_decode(wire, cuts[i], &back, &b, &blen) != 0,
                  "truncated accepted"); OK();
        }
        /* Trailing garbage. */
        uint8_t big[114];
        memcpy(big, wire, 113); big[113] = 0x00;
        CHECK(dnac_txw3_decode(big, 114, &back, &b, &blen) != 0,
              "trailing byte accepted"); OK();
        /* body_len mismatch (claims 4, total says 3). */
        uint8_t bad[113];
        memcpy(bad, wire, 113); bad[109] = 0x04;
        CHECK(dnac_txw3_decode(bad, 113, &back, &b, &blen) != 0,
              "body_len mismatch accepted"); OK();
        /* Unsupported version byte. */
        memcpy(bad, wire, 113); bad[0] = 0x02;
        CHECK(dnac_txw3_decode(bad, 113, &back, &b, &blen) != 0,
              "version 2 accepted"); OK();
        memcpy(bad, wire, 113); bad[0] = 0x04;
        CHECK(dnac_txw3_decode(bad, 113, &back, &b, &blen) != 0,
              "version 4 accepted"); OK();
        /* Over-cap body_len in the frame. */
        memcpy(bad, wire, 113);
        bad[106] = 0x00; bad[107] = 0x10; bad[108] = 0x00; bad[109] = 0x01;
        CHECK(dnac_txw3_decode(bad, 113, &back, &b, &blen) != 0,
              "over-cap body accepted"); OK();
        /* Null args. */
        CHECK(dnac_txw3_decode(NULL, 113, &back, &b, &blen) != 0, "null src"); OK();
        CHECK(dnac_txw3_encode(&hdr, NULL, 3, wire, sizeof(wire), &written) != 0,
              "null body with len"); OK();
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, NULL, 3, base_hash) != 0,
              "hash null body with len"); OK();
        /* Short dst. */
        CHECK(dnac_txw3_encode(&hdr, body, 3, wire, 112, &written) != 0,
              "short dst accepted"); OK();
    }

    /* EXACT-BOUNDARY tests (S1 correction #2): the authoritative limit is
     * the serialized-TX cap (65536, mirror of NODUS_T3_MAX_TX_SIZE); the
     * body cap is exactly cap − 110. */
    {
        uint32_t blen_max = DNAC_TXW3_MAX_BODY_LEN;
        CHECK(blen_max == 65536u - 110u, "body cap != tx cap - overhead"); OK();
        size_t total = 0;
        CHECK(dnac_txw3_encoded_size(blen_max, &total) == 0 &&
              total == DNAC_TXW3_MAX_TX_SIZE,
              "boundary total != authoritative tx cap"); OK();
        CHECK(dnac_txw3_encoded_size(blen_max + 1, &total) != 0,
              "boundary+1 accepted"); OK();

        uint8_t *bigbody = malloc(blen_max);
        CHECK(bigbody != NULL, "alloc");
        memset(bigbody, 0x5A, blen_max);
        CHECK(dnac_txw3_encoded_size(blen_max, &total) == 0, "max size");
        uint8_t *frame = malloc(total + 1);
        CHECK(frame != NULL, "alloc2");
        size_t w2 = 0;
        /* Exact-boundary acceptance: encode + decode + hash at cap. */
        CHECK(dnac_txw3_encode(&hdr, bigbody, blen_max, frame, total, &w2) == 0 &&
              w2 == total && w2 == 65536u, "boundary encode"); OK();
        dnac_txw3_header_t back;
        const uint8_t *b = NULL; uint32_t bl = 0;
        CHECK(dnac_txw3_decode(frame, total, &back, &b, &bl) == 0 &&
              bl == blen_max, "boundary decode"); OK();
        uint8_t h[64];
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, bigbody, blen_max, h) == 0,
              "boundary hash"); OK();
        /* Boundary+1 rejection on every entry: encode (via encoded_size),
         * hash, and decode of a frame CLAIMING body cap+1 with a matching
         * total length — the cap check fires before any use. */
        CHECK(dnac_txw3_encode(&hdr, bigbody, blen_max + 1, frame, total + 1,
                               &w2) != 0, "boundary+1 encode accepted"); OK();
        CHECK(dnac_txw3_tx_hash(&hdr, CHAIN_ID, bigbody, blen_max + 1, h) != 0,
              "boundary+1 hash accepted"); OK();
        {
            uint32_t claim = blen_max + 1;
            frame[DNAC_TXW3_BODYLEN_OFF]     = (uint8_t)(claim >> 24);
            frame[DNAC_TXW3_BODYLEN_OFF + 1] = (uint8_t)(claim >> 16);
            frame[DNAC_TXW3_BODYLEN_OFF + 2] = (uint8_t)(claim >> 8);
            frame[DNAC_TXW3_BODYLEN_OFF + 3] = (uint8_t)claim;
            CHECK(dnac_txw3_decode(frame, total + 1, &back, &b, &bl) != 0,
                  "boundary+1 frame accepted"); OK();
        }
        free(frame);
        free(bigbody);
    }
    return 0;
}

int main(void) {
    if (test_exec_context() != 0) return 1;
    if (test_v3() != 0) return 1;
    printf("test_tx_wire_v3: %d checks OK\n", g_checks);
    return 0;
}
