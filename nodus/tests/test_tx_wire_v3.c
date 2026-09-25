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
 * S9 Gate 2 slice W1 appends the V3 SHIELDED BODY CODEC suite (tx_wire.h
 * §4, tx_wire.c:624-722) — the 359-byte section + FRI blob that S8 shipped
 * with zero callers and zero tests:
 *   - round trips: the 2-in/1-out transfer shape, the zero-input SHIELD
 *     shape (all-zero anchor, all-zero nf slots) and the full 4-in/4-out
 *     shape at the canonical lane maximum p−1;
 *   - byte-exact section KAT: every documented offset (0/33/162/291/299/
 *     307/315/323/355/359) asserted against HAND-COMPUTED big-endian
 *     literals, then the whole 364-byte buffer memcmp'd — never against a
 *     decode of itself;
 *   - the complete tx_wire.c:590-622 reject list on BOTH entries: encode
 *     from a mutated struct, decode from mutated RAW BYTES;
 *   - fee/expiry mirror equality (dnac_txw3_shielded_check_header) and the
 *     NULL fail-closes of all three entries.
 *
 * S9 Gate 2 slice W2 appends the TRANSPARENT-LEG suite (tx_wire.h §6) and
 * tightens the W1 shielded-decode cases that documented a fail-close gap:
 *   - leg round trips at all four shapes that matter structurally —
 *     1/1/1, 0/1/0 (the UNSHIELD shape), 16/16/4 (maximal, 32608 B) and
 *     0/0/0 (minimal, 4 B) — plus the PREFIX contract: a leg followed by
 *     trailing bytes decodes with the right `consumed` and leaves the
 *     trailing bytes untouched;
 *   - byte-exact leg KAT at hand-written literal offsets (0/1/2/66/67/196/
 *     204/236/237/2829), then the whole 7456-byte buffer in one memcmp;
 *   - encode AND decode negatives over the whole §6 rule list: version,
 *     the three caps, non-ascending / duplicate inputs, zero-amount
 *     outputs, truncation at every field-class boundary, NULLs — and
 *     *out zeroed on EVERY decode reject;
 *   - dnac_tleg_commit against a literal computed with an INDEPENDENT
 *     SHA3-512 (python3 hashlib), the signature-exclusion equality, a
 *     per-field sensitivity sweep, and empty-tag domain distinctness;
 *   - the two shielded-decode length rejects (tx_wire.c:676/:682) now
 *     assert the *out zeroing that W1 could only document as missing.
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
          /* S9: 12/13 assigned SHIELD/UNSHIELD (DNA_CORE, V3-only); 14 stays free */
          dna_tx_type_owner(12) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(13) == DNA_DOMAIN_CORE &&
          dna_tx_type_owner(14) == DNA_TX_OWNER_NONE, "type ownership map"); OK();
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

/* ══════════════════════════════════════════════════════════════════════
 * S8 §4 — V3 shielded body codec (359-byte section ‖ FRI blob)
 *
 * Specification under test: tx_wire.h §4 (layout + canonicality list) and
 * its implementation tx_wire.c:590-722. Both entries run the SAME ordered
 * reject list (txw3_section_ok, tx_wire.c:607-622), so every canonicality
 * rule below is exercised twice: once from a mutated struct through
 * dnac_txw3_shielded_encode, once from mutated raw bytes through
 * dnac_txw3_shielded_decode.
 * ════════════════════════════════════════════════════════════════════ */

/** Goldilocks modulus — the canonicality bound every lane must be under
 *  (mirror of TXW3_FE_P, tx_wire.c:524; that constant is file-static). */
#define SHLD_P      ((uint64_t)0xFFFFFFFF00000001ULL)
/** FROZEN boundary bound: boundary_in/out MUST be < 2^63 (tx_wire.c:527). */
#define SHLD_2_63   ((uint64_t)1 << 63)
/** Fixed section size, spelled out so the offset KAT below is independent
 *  of the header constant it is checking. */
#define SHLD_FIXED  359

/* FRI blobs — opaque to the codec; only length and placement are pinned. */
static const uint8_t SHLD_FRI_A[5] = { 0x50,0x52,0x4F,0x4F,0x46 };  /* "PROOF" */
static const uint8_t SHLD_FRI_B[3] = { 0xAA,0xBB,0xCC };

static void poke_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void poke_be32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i));
}

/** Fixture A — canonical 2-input / 1-output (transfer-shaped) statement.
 *  Every numeric field distinct so the offset KAT cannot confuse two of
 *  them (fee / boundary_in / boundary_out / expiry_height all differ). */
static void shld_fixture_a(dnac_txw3_shielded_t *st) {
    memset(st, 0, sizeof(*st));
    st->sect_version = DNAC_TXW3_SECT_VERSION;
    st->anchor[0] = 0x0000000000000001ULL;
    st->anchor[1] = 0x0000000000000002ULL;
    st->anchor[2] = 0x0000000000000003ULL;
    st->anchor[3] = 0x00000000FFFFFFFFULL;
    st->num_input = 2;
    st->nf_set[0][0] = 0x0102030405060708ULL;
    st->nf_set[0][1] = 0x1112131415161718ULL;
    st->nf_set[0][2] = 0x2122232425262728ULL;
    st->nf_set[0][3] = 0x3132333435363738ULL;
    st->nf_set[1][0] = 0x4142434445464748ULL;
    st->nf_set[1][1] = 0x5152535455565758ULL;
    st->nf_set[1][2] = 0x6162636465666768ULL;
    st->nf_set[1][3] = 0x7172737475767778ULL;
    /* slots 2,3 stay all-zero — the unused-slot rule */
    st->num_output = 1;
    st->output_commit[0][0] = 0x8182838485868788ULL;
    st->output_commit[0][1] = 0x9192939495969798ULL;
    st->output_commit[0][2] = 0xA1A2A3A4A5A6A7A8ULL;
    st->output_commit[0][3] = 0xB1B2B3B4B5B6B7B8ULL;
    st->fee           = 1000000ULL;            /* 0x00000000000F4240 */
    st->boundary_in   = 0x0000000012345678ULL;
    st->boundary_out  = 0x000000000000ABCDULL;
    st->expiry_height = 1000ULL;               /* 0x00000000000003E8 */
    st->tx_binding[0] = 0xC1C2C3C4C5C6C7C8ULL;
    st->tx_binding[1] = 0xD1D2D3D4D5D6D7D8ULL;
    st->tx_binding[2] = 0xE1E2E3E4E5E6E7E8ULL;
    st->tx_binding[3] = 0xF1F2F3F4F5F6F7F8ULL;
    st->fri_len = 5;
}

/** Fixture B — the S8 SHIELD shape: zero private inputs, ALL nf slots
 *  zero, anchor ALL-ZERO (tx_wire.c:614-618 makes any other anchor for a
 *  zero-input statement a reject). */
static void shld_fixture_b(dnac_txw3_shielded_t *st) {
    memset(st, 0, sizeof(*st));
    st->sect_version = DNAC_TXW3_SECT_VERSION;
    /* anchor: all zero */
    st->num_input = 0;
    /* nf_set: all zero */
    st->num_output = 2;
    st->output_commit[0][0] = 0x0000000000000011ULL;
    st->output_commit[0][3] = 0x0000000000000044ULL;
    st->output_commit[1][1] = 0x0000000000000055ULL;
    st->output_commit[1][2] = 0x0000000000000066ULL;
    st->fee           = 1000000ULL;
    st->boundary_in   = 500000000ULL;
    st->boundary_out  = 0ULL;
    st->expiry_height = 0ULL;                  /* 0 = no expiry */
    st->tx_binding[0] = 0x1111111111111111ULL;
    st->tx_binding[3] = 0x4444444444444444ULL;
    st->fri_len = 3;
}

static int shld_eq(const dnac_txw3_shielded_t *a, const dnac_txw3_shielded_t *b) {
    if (a->sect_version != b->sect_version) return 0;
    if (a->num_input != b->num_input || a->num_output != b->num_output) return 0;
    if (a->fee != b->fee) return 0;
    if (a->boundary_in != b->boundary_in) return 0;
    if (a->boundary_out != b->boundary_out) return 0;
    if (a->expiry_height != b->expiry_height) return 0;
    if (a->fri_len != b->fri_len) return 0;
    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
        if (a->anchor[j] != b->anchor[j]) return 0;
        if (a->tx_binding[j] != b->tx_binding[j]) return 0;
    }
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            if (a->nf_set[s][j] != b->nf_set[s][j]) return 0;
    for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
            if (a->output_commit[s][j] != b->output_commit[s][j]) return 0;
    return 1;
}

/** The struct the decoder leaves behind on a canonicality reject: fully
 *  zeroed (tx_wire.c:704 memset, "fail closed"). */
static int shld_is_zeroed(const dnac_txw3_shielded_t *st) {
    dnac_txw3_shielded_t z;
    memset(&z, 0, sizeof(z));
    return memcmp(st, &z, sizeof(z)) == 0;
}

/** Encode fixture A into `dst` (must hold >= 364 bytes). Returns bytes. */
static size_t shld_encode_a(uint8_t *dst, size_t cap) {
    dnac_txw3_shielded_t st;
    size_t w = 0;
    shld_fixture_a(&st);
    if (dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, dst, cap, &w) != 0) return 0;
    return w;
}

/* ── A. Round trips ──────────────────────────────────────────────────── */
static int test_shielded_roundtrip(void) {
    dnac_txw3_shielded_t st, back;
    uint8_t buf[SHLD_FIXED + 8];
    size_t written = 0;
    const uint8_t *fri = NULL;
    uint32_t fri_len = 0;

    /* (A1) transfer shape: 2 nonzero canonical nf slots, 1 output. */
    shld_fixture_a(&st);
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf),
                                    &written) == 0 &&
          written == (size_t)SHLD_FIXED + 5, "A1 encode"); OK();
    CHECK(dnac_txw3_shielded_decode(buf, (uint32_t)written, &back, &fri,
                                    &fri_len) == 0, "A1 decode"); OK();
    CHECK(shld_eq(&st, &back), "A1 field-by-field equality"); OK();
    CHECK(fri == buf + SHLD_FIXED && fri_len == 5 &&
          memcmp(fri, SHLD_FRI_A, 5) == 0, "A1 fri pointer/len"); OK();
    {   /* a section that decodes re-encodes byte-identically
         * (tx_wire.c:592-594) */
        uint8_t re[SHLD_FIXED + 8];
        size_t w2 = 0;
        CHECK(dnac_txw3_shielded_encode(&back, fri, fri_len, re, sizeof(re),
                                        &w2) == 0 && w2 == written &&
              memcmp(re, buf, written) == 0, "A1 re-encode identity"); OK();
    }

    /* (A2) zero-input SHIELD shape: num_input 0, all nf slots zero,
     *      anchor ALL-ZERO. num_input == 0 is LEGAL (tx_wire.h:355-356). */
    {
        uint8_t bufb[SHLD_FIXED + 3];
        shld_fixture_b(&st);
        CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_B, 3, bufb, sizeof(bufb),
                                        &written) == 0 &&
              written == (size_t)SHLD_FIXED + 3, "A2 zero-input encode"); OK();
        CHECK(dnac_txw3_shielded_decode(bufb, (uint32_t)written, &back, &fri,
                                        &fri_len) == 0, "A2 decode"); OK();
        CHECK(shld_eq(&st, &back) && back.num_input == 0, "A2 equality"); OK();
        CHECK(back.anchor[0] == 0 && back.anchor[1] == 0 &&
              back.anchor[2] == 0 && back.anchor[3] == 0,
              "A2 anchor not all-zero"); OK();
        {
            int nf_zero = 1;
            for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
                for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                    if (back.nf_set[s][j] != 0) nf_zero = 0;
            CHECK(nf_zero, "A2 nf slots not all-zero"); OK();
        }
        CHECK(fri == bufb + SHLD_FIXED && fri_len == 3 &&
              memcmp(fri, SHLD_FRI_B, 3) == 0, "A2 fri pointer/len"); OK();
    }

    /* (A3) full 4-in / 4-out at the canonical lane MAXIMUM p−1 — the
     *      largest value tx_wire.c:569 accepts (>= p is the reject). */
    {
        shld_fixture_a(&st);
        st.num_input  = 4;
        st.num_output = 4;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_INPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                st.nf_set[s][j] = SHLD_P - 1;
        for (unsigned s = 0; s < DNAC_TXW3_SHIELDED_MAX_OUTPUTS; s++)
            for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++)
                st.output_commit[s][j] = SHLD_P - 1;
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
            st.anchor[j]     = SHLD_P - 1;
            st.tx_binding[j] = SHLD_P - 1;
        }
        CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf),
                                        &written) == 0, "A3 p-1 encode"); OK();
        CHECK(dnac_txw3_shielded_decode(buf, (uint32_t)written, &back, &fri,
                                        &fri_len) == 0 && shld_eq(&st, &back),
              "A3 p-1 round trip"); OK();
    }
    return 0;
}

/* ── B. Byte-exact section KAT (hand-computed BE literals) ───────────── */
static int test_shielded_offsets(void) {
    dnac_txw3_shielded_t st;
    uint8_t buf[SHLD_FIXED + 5];
    size_t written = 0;

    shld_fixture_a(&st);
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf),
                                    &written) == 0 && written == 364,
          "B encode"); OK();

    /* Hand-written literals, absolute offsets from tx_wire.h:328-340. */
    static const uint8_t k_anchor[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,
        0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF
    };
    static const uint8_t k_nf0[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38
    };
    static const uint8_t k_nf1[32] = {
        0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
        0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
        0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,
        0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78
    };
    static const uint8_t k_oc0[32] = {
        0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,
        0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,
        0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,
        0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8
    };
    static const uint8_t k_txb[32] = {
        0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,
        0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,
        0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,
        0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8
    };
    static const uint8_t k_fee[8]  = { 0x00,0x00,0x00,0x00,0x00,0x0F,0x42,0x40 };
    static const uint8_t k_bin[8]  = { 0x00,0x00,0x00,0x00,0x12,0x34,0x56,0x78 };
    static const uint8_t k_bout[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0xAB,0xCD };
    static const uint8_t k_exp[8]  = { 0x00,0x00,0x00,0x00,0x00,0x00,0x03,0xE8 };
    static const uint8_t k_fril[4] = { 0x00,0x00,0x00,0x05 };

    /* Per-offset assertions (the documented layout, one CHECK per field). */
    CHECK(buf[0] == 0x02, "B off 0 sect_version"); OK();
    CHECK(memcmp(buf + 1, k_anchor, 32) == 0, "B off 1 anchor"); OK();
    CHECK(buf[33] == 0x02, "B off 33 num_input"); OK();
    CHECK(memcmp(buf + 34, k_nf0, 32) == 0, "B off 34 nf_set[0]"); OK();
    CHECK(memcmp(buf + 66, k_nf1, 32) == 0, "B off 66 nf_set[1]"); OK();
    {   /* unused nf slots 2,3 = 64 zero bytes at 98..161 */
        int z = 1;
        for (int i = 98; i < 162; i++) if (buf[i] != 0) z = 0;
        CHECK(z, "B unused nf slots not zero on the wire"); OK();
    }
    CHECK(buf[162] == 0x01, "B off 162 num_output"); OK();
    CHECK(memcmp(buf + 163, k_oc0, 32) == 0, "B off 163 output_commit[0]"); OK();
    {   /* unused output slots 1..3 = 96 zero bytes at 195..290 */
        int z = 1;
        for (int i = 195; i < 291; i++) if (buf[i] != 0) z = 0;
        CHECK(z, "B unused output slots not zero on the wire"); OK();
    }
    CHECK(memcmp(buf + 291, k_fee,  8) == 0, "B off 291 fee"); OK();
    CHECK(memcmp(buf + 299, k_bin,  8) == 0, "B off 299 boundary_in"); OK();
    CHECK(memcmp(buf + 307, k_bout, 8) == 0, "B off 307 boundary_out"); OK();
    CHECK(memcmp(buf + 315, k_exp,  8) == 0, "B off 315 expiry_height"); OK();
    CHECK(memcmp(buf + 323, k_txb, 32) == 0, "B off 323 tx_binding"); OK();
    CHECK(memcmp(buf + 355, k_fril, 4) == 0, "B off 355 fri_len"); OK();
    CHECK(memcmp(buf + 359, SHLD_FRI_A, 5) == 0, "B off 359 blob"); OK();

    /* Whole-buffer KAT: assemble the 364 expected bytes from the literals
     * above at literal offsets, then compare in one shot. */
    {
        uint8_t expect[364];
        memset(expect, 0, sizeof(expect));
        expect[0] = 0x02;
        memcpy(expect + 1,   k_anchor, 32);
        expect[33] = 0x02;
        memcpy(expect + 34,  k_nf0, 32);
        memcpy(expect + 66,  k_nf1, 32);
        expect[162] = 0x01;
        memcpy(expect + 163, k_oc0, 32);
        memcpy(expect + 291, k_fee,  8);
        memcpy(expect + 299, k_bin,  8);
        memcpy(expect + 307, k_bout, 8);
        memcpy(expect + 315, k_exp,  8);
        memcpy(expect + 323, k_txb, 32);
        memcpy(expect + 355, k_fril, 4);
        memcpy(expect + 359, SHLD_FRI_A, 5);
        CHECK(memcmp(buf, expect, 364) == 0, "B whole-section KAT"); OK();
    }

    /* The fixed part is EXACTLY 359 bytes and the header constant agrees. */
    CHECK(DNAC_TXW3_SHIELDED_FIXED == SHLD_FIXED, "B fixed size drifted"); OK();
    return 0;
}

/* ── C. Encode negatives (every one must return -1) ──────────────────── */
static int test_shielded_encode_negatives(void) {
    dnac_txw3_shielded_t st;
    uint8_t buf[SHLD_FIXED + 8];
    size_t w = 0;

    /* fri_len disagrees with st->fri_len — neither side silently wins
     * (tx_wire.c:631). Both directions. */
    shld_fixture_a(&st);
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 4, buf, sizeof(buf), &w) != 0,
          "C fri_len < st->fri_len accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 6, buf, sizeof(buf), &w) != 0,
          "C fri_len > st->fri_len accepted"); OK();

    /* fri_len == 0 is not canonical (tx_wire.c:620). */
    shld_fixture_a(&st); st.fri_len = 0;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 0, buf, sizeof(buf), &w) != 0,
          "C fri_len 0 accepted"); OK();

    /* sect_version must be exactly 2 (tx_wire.c:608). */
    {
        const uint8_t bad_ver[4] = { 0x00, 0x01, 0x03, 0xFF };
        for (int i = 0; i < 4; i++) {
            shld_fixture_a(&st); st.sect_version = bad_ver[i];
            CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf,
                                            sizeof(buf), &w) != 0,
                  "C sect_version != 2 accepted"); OK();
        }
    }

    /* counts > 4 (tx_wire.c:565-566). */
    shld_fixture_a(&st); st.num_input = 5;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C num_input 5 accepted"); OK();
    shld_fixture_a(&st); st.num_input = 255;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C num_input 255 accepted"); OK();
    shld_fixture_a(&st); st.num_output = 5;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C num_output 5 accepted"); OK();
    shld_fixture_a(&st); st.num_output = 255;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C num_output 255 accepted"); OK();

    /* Non-canonical lane (>= p) in each of the four lane groups; both the
     * exact modulus and the all-ones extreme. */
    shld_fixture_a(&st); st.anchor[2] = SHLD_P;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C anchor lane == p accepted"); OK();
    shld_fixture_a(&st); st.anchor[0] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C anchor lane 2^64-1 accepted"); OK();
    shld_fixture_a(&st); st.nf_set[1][3] = SHLD_P;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C nf lane == p accepted"); OK();
    shld_fixture_a(&st); st.nf_set[0][0] = SHLD_P + 1;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C nf lane p+1 accepted"); OK();
    shld_fixture_a(&st); st.output_commit[0][1] = SHLD_P;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C output_commit lane == p accepted"); OK();
    shld_fixture_a(&st); st.tx_binding[3] = SHLD_P;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C tx_binding lane == p accepted"); OK();
    shld_fixture_a(&st); st.tx_binding[0] = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C tx_binding lane 2^64-1 accepted"); OK();

    /* Nonzero lane in an UNUSED slot (index >= its count). */
    shld_fixture_a(&st); st.nf_set[2][0] = 1;         /* num_input == 2 */
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C nonzero unused nf slot accepted"); OK();
    shld_fixture_a(&st); st.nf_set[3][3] = 1;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C nonzero unused nf slot 3 accepted"); OK();
    shld_fixture_a(&st); st.output_commit[1][3] = 1;  /* num_output == 1 */
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C nonzero unused output slot accepted"); OK();

    /* boundary_in / boundary_out must be < 2^63 (tx_wire.c:585-586). */
    shld_fixture_a(&st); st.boundary_in = SHLD_2_63;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C boundary_in 2^63 accepted"); OK();
    shld_fixture_a(&st); st.boundary_in = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C boundary_in 2^64-1 accepted"); OK();
    shld_fixture_a(&st); st.boundary_out = SHLD_2_63;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C boundary_out 2^63 accepted"); OK();
    shld_fixture_a(&st); st.boundary_out = SHLD_2_63 + 1;
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C boundary_out 2^63+1 accepted"); OK();

    /* num_input == 0 with a nonzero anchor lane — FROZEN reject
     * (tx_wire.c:614-618). Every lane position. */
    for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
        shld_fixture_b(&st);
        st.anchor[j] = 1;
        CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_B, 3, buf, sizeof(buf),
                                        &w) != 0,
              "C zero-input nonzero anchor accepted"); OK();
    }

    /* Short dst_cap: need is 364 exactly. */
    shld_fixture_a(&st);
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, 363, &w) != 0,
          "C dst_cap 363 accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, 359, &w) != 0,
          "C dst_cap 359 accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, 0, &w) != 0,
          "C dst_cap 0 accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, 364, &w) == 0 &&
          w == 364, "C exact dst_cap rejected"); OK();

    /* G — NULL fail-closes on encode (fri included: tx_wire.c:628). */
    CHECK(dnac_txw3_shielded_encode(NULL, SHLD_FRI_A, 5, buf, sizeof(buf), &w) != 0,
          "C null st accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, NULL, 5, buf, sizeof(buf), &w) != 0,
          "C null fri accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, NULL, sizeof(buf), &w) != 0,
          "C null dst accepted"); OK();
    CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf), NULL) != 0,
          "C null written_out accepted"); OK();
    return 0;
}

/* ── D. Decode negatives (raw bytes; every one must return -1) ───────── */
static int test_shielded_decode_negatives(void) {
    uint8_t good[SHLD_FIXED + 5];
    uint8_t bad[SHLD_FIXED + 8];
    dnac_txw3_shielded_t out;
    const uint8_t *fri = NULL;
    uint32_t fri_len = 0;
    size_t n = shld_encode_a(good, sizeof(good));

    CHECK(n == 364, "D fixture encode");

    /* Bodies shorter than the fixed section, incl. cuts at the documented
     * interior field boundaries (tx_wire.c:676).
     *
     * S9 W2 REPAIR: this early reject — and the fri_len one below — used to
     * return with *out UNTOUCHED, contradicting the header's "on any
     * rejection *out is zeroed". The memset now runs before the first byte
     * is examined (tx_wire.c:675), so both paths are held to the promise:
     * poison the struct with 0x5A, then require it clean afterwards. */
    {
        const uint32_t cuts[9] = { 0, 1, 33, 34, 162, 163, 291, 358, 100 };
        for (int i = 0; i < 9; i++) {
            memset(&out, 0x5A, sizeof(out));
            CHECK(dnac_txw3_shielded_decode(good, cuts[i], &out, &fri,
                                            &fri_len) != 0,
                  "D truncated body accepted"); OK();
            CHECK(shld_is_zeroed(&out),
                  "D truncated reject left *out dirty"); OK();
        }
    }

    /* Trailing bytes after the blob (length equality is EXACT). */
    memcpy(bad, good, n);
    bad[364] = 0x00;
    CHECK(dnac_txw3_shielded_decode(bad, 365, &out, &fri, &fri_len) != 0,
          "D trailing byte accepted"); OK();
    bad[365] = 0xFF;
    CHECK(dnac_txw3_shielded_decode(bad, 366, &out, &fri, &fri_len) != 0,
          "D two trailing bytes accepted"); OK();

    /* fri_len field disagreeing with body_len − 359, BOTH directions. This
     * is the SECOND S9 W2 path (the subtraction mismatch, tx_wire.c:682) —
     * it too must leave *out zeroed, so each case poisons and re-checks. */
    memcpy(bad, good, n); poke_be32(bad + 355, 4);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D fri_len too small accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D fri_len-small reject left *out dirty"); OK();
    memcpy(bad, good, n); poke_be32(bad + 355, 6);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D fri_len too large accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D fri_len-large reject left *out dirty"); OK();
    memcpy(bad, good, n); poke_be32(bad + 355, 0xFFFFFFFFu);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D fri_len 2^32-1 accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D fri_len 2^32-1 reject left *out dirty"); OK();

    /* fri_len == 0 with body_len == 359: the length equality PASSES
     * (359 − 359 == 0) and the canonicality rule must be what rejects. */
    memcpy(bad, good, 359); poke_be32(bad + 355, 0);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, 359, &out, &fri, &fri_len) != 0,
          "D fri_len 0 / body 359 accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D fri_len 0 left *out dirty"); OK();

    /* Wrong sect_version byte. */
    {
        const uint8_t bad_ver[4] = { 0x00, 0x01, 0x03, 0xFF };
        for (int i = 0; i < 4; i++) {
            memcpy(bad, good, n); bad[0] = bad_ver[i];
            memset(&out, 0x5A, sizeof(out));
            CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri,
                                            &fri_len) != 0,
                  "D sect_version != 2 accepted"); OK();
            CHECK(shld_is_zeroed(&out), "D bad sect_version left *out dirty"); OK();
        }
    }

    /* Counts over the slot bound, injected as raw bytes. */
    memcpy(bad, good, n); bad[33] = 5;
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D num_input 5 accepted"); OK();
    memcpy(bad, good, n); bad[33] = 0xFF;
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D num_input 255 accepted"); OK();
    memcpy(bad, good, n); bad[162] = 5;
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D num_output 5 accepted"); OK();
    memcpy(bad, good, n); bad[162] = 0xFF;
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D num_output 255 accepted"); OK();

    /* Non-canonical lanes injected as raw big-endian bytes:
     *   anchor lane 0        @   1, nf_set[1][3] @  90,
     *   output_commit[0][0]  @ 163, tx_binding[3] @ 347. */
    memcpy(bad, good, n); poke_be64(bad + 1, SHLD_P);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw anchor lane == p accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D non-canonical anchor left *out dirty"); OK();
    memcpy(bad, good, n); poke_be64(bad + 90, SHLD_P);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw nf lane == p accepted"); OK();
    memcpy(bad, good, n); poke_be64(bad + 163, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw output_commit lane 2^64-1 accepted"); OK();
    memcpy(bad, good, n); poke_be64(bad + 347, SHLD_P);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw tx_binding lane == p accepted"); OK();

    /* Nonzero lane in an unused slot, raw:
     *   nf slot 2 lane 0 @ 98 (num_input == 2),
     *   output slot 1 lane 3 @ 219 (num_output == 1). */
    memcpy(bad, good, n); poke_be64(bad + 98, 1);
    memset(&out, 0x5A, sizeof(out));
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw nonzero unused nf slot accepted"); OK();
    CHECK(shld_is_zeroed(&out), "D unused-slot reject left *out dirty"); OK();
    memcpy(bad, good, n); poke_be64(bad + 219, 1);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw nonzero unused output slot accepted"); OK();

    /* Boundaries >= 2^63, raw (top bit of the BE u64 at 299 / 307). */
    memcpy(bad, good, n); poke_be64(bad + 299, SHLD_2_63);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw boundary_in 2^63 accepted"); OK();
    memcpy(bad, good, n); poke_be64(bad + 307, SHLD_2_63);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw boundary_out 2^63 accepted"); OK();
    memcpy(bad, good, n); poke_be64(bad + 307, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dnac_txw3_shielded_decode(bad, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D raw boundary_out 2^64-1 accepted"); OK();

    /* Zero-input body carrying a nonzero anchor lane, raw. */
    {
        dnac_txw3_shielded_t stb;
        uint8_t zb[SHLD_FIXED + 3];
        size_t wb = 0;
        shld_fixture_b(&stb);
        CHECK(dnac_txw3_shielded_encode(&stb, SHLD_FRI_B, 3, zb, sizeof(zb),
                                        &wb) == 0 && wb == 362,
              "D zero-input fixture");
        for (unsigned j = 0; j < DNAC_TXW3_SHIELDED_LANES; j++) {
            uint8_t z2[SHLD_FIXED + 3];
            memcpy(z2, zb, wb);
            poke_be64(z2 + 1 + 8 * j, 1);
            memset(&out, 0x5A, sizeof(out));
            CHECK(dnac_txw3_shielded_decode(z2, (uint32_t)wb, &out, &fri,
                                            &fri_len) != 0,
                  "D raw zero-input nonzero anchor accepted"); OK();
            CHECK(shld_is_zeroed(&out),
                  "D zero-input anchor reject left *out dirty"); OK();
        }
        /* … and the untouched zero-input body still decodes. */
        CHECK(dnac_txw3_shielded_decode(zb, (uint32_t)wb, &out, &fri,
                                        &fri_len) == 0 && out.num_input == 0,
              "D zero-input control rejected"); OK();
    }

    /* G — NULL fail-closes on decode (tx_wire.c:669). */
    CHECK(dnac_txw3_shielded_decode(NULL, (uint32_t)n, &out, &fri, &fri_len) != 0,
          "D null body accepted"); OK();
    CHECK(dnac_txw3_shielded_decode(good, (uint32_t)n, NULL, &fri, &fri_len) != 0,
          "D null out accepted"); OK();
    CHECK(dnac_txw3_shielded_decode(good, (uint32_t)n, &out, NULL, &fri_len) != 0,
          "D null fri_out accepted"); OK();
    CHECK(dnac_txw3_shielded_decode(good, (uint32_t)n, &out, &fri, NULL) != 0,
          "D null fri_len_out accepted"); OK();

    /* G2 — the NULL-argument rejects must ALSO honour "on ANY rejection
     * *out is zeroed" (O6 verifier C5). A valid `out` with some OTHER
     * argument NULL used to return before the memset, leaving the caller's
     * buffer stale. Poison first, then require zeroed. */
    memset(&out, 0x5A, sizeof(out));
    (void)dnac_txw3_shielded_decode(NULL, (uint32_t)n, &out, &fri, &fri_len);
    CHECK(shld_is_zeroed(&out), "D null-body reject left *out dirty"); OK();
    memset(&out, 0x5A, sizeof(out));
    (void)dnac_txw3_shielded_decode(good, (uint32_t)n, &out, NULL, &fri_len);
    CHECK(shld_is_zeroed(&out), "D null-fri_out reject left *out dirty"); OK();
    memset(&out, 0x5A, sizeof(out));
    (void)dnac_txw3_shielded_decode(good, (uint32_t)n, &out, &fri, NULL);
    CHECK(shld_is_zeroed(&out), "D null-fri_len_out reject left *out dirty"); OK();
    return 0;
}

/* ── E/F. Header mirrors + the accepted boundary edge ────────────────── */
static int test_shielded_check_header(void) {
    dnac_txw3_header_t hdr;
    dnac_txw3_shielded_t st;

    base_header(&hdr);                 /* committed_fee 1000000, expiry 1000 */
    shld_fixture_a(&st);               /* fee 1000000, expiry_height 1000    */

    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) == 0,
          "E equal fee+expiry rejected"); OK();

    /* Fee mismatch, both directions. */
    st.fee = hdr.committed_fee + 1;
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E fee+1 accepted"); OK();
    st.fee = hdr.committed_fee - 1;
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E fee-1 accepted"); OK();
    st.fee = 0;
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E fee 0 accepted"); OK();

    /* Expiry mismatch (fee restored). */
    shld_fixture_a(&st);
    st.expiry_height = hdr.expiry_height + 1;
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E expiry+1 accepted"); OK();
    st.expiry_height = 0;              /* 0 = "no expiry", still a mismatch */
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E expiry 0 vs header 1000 accepted"); OK();

    /* Both wrong. */
    st.fee = 1; st.expiry_height = 1;
    CHECK(dnac_txw3_shielded_check_header(&hdr, &st) != 0,
          "E both mismatched accepted"); OK();

    /* Header authority is one-way: a zero-expiry header + zero-expiry
     * section agree (the mirror is equality, not a policy). */
    {
        dnac_txw3_header_t h0;
        base_header(&h0);
        h0.expiry_height = 0;
        h0.committed_fee = 1000000;
        shld_fixture_b(&st);           /* fee 1000000, expiry 0 */
        CHECK(dnac_txw3_shielded_check_header(&h0, &st) == 0,
              "E zero-expiry pair rejected"); OK();
    }

    /* G — NULLs. */
    shld_fixture_a(&st);
    CHECK(dnac_txw3_shielded_check_header(NULL, &st) != 0, "E null hdr"); OK();
    CHECK(dnac_txw3_shielded_check_header(&hdr, NULL) != 0, "E null st"); OK();
    CHECK(dnac_txw3_shielded_check_header(NULL, NULL) != 0, "E both null"); OK();

    /* F — the range gate is strict <: 2^63 − 1 is ACCEPTED on both
     *     boundaries and survives the round trip. */
    {
        uint8_t buf[SHLD_FIXED + 5];
        dnac_txw3_shielded_t back;
        const uint8_t *fri = NULL;
        uint32_t fri_len = 0;
        size_t w = 0;

        shld_fixture_a(&st);
        st.boundary_in  = SHLD_2_63 - 1;
        st.boundary_out = SHLD_2_63 - 1;
        CHECK(dnac_txw3_shielded_encode(&st, SHLD_FRI_A, 5, buf, sizeof(buf),
                                        &w) == 0 && w == 364,
              "F 2^63-1 boundaries rejected on encode"); OK();
        CHECK(dnac_txw3_shielded_decode(buf, (uint32_t)w, &back, &fri,
                                        &fri_len) == 0 &&
              back.boundary_in  == SHLD_2_63 - 1 &&
              back.boundary_out == SHLD_2_63 - 1,
              "F 2^63-1 boundaries rejected on decode"); OK();
        /* Wire proof: the top bit is clear, the rest set. */
        CHECK(buf[299] == 0x7F && buf[307] == 0x7F,
              "F 2^63-1 top byte"); OK();
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * S9 §6 — transparent-leg section v1 + DNA.TLEG.v1 commitment
 *
 * Specification under test: tx_wire.h §6 (layout, canonicality, PREFIX
 * contract, commitment preimage) and its implementation at the END of
 * tx_wire.c. Encode, decode and dnac_tleg_commit all run the SAME rule
 * list (txw3_tleg_ok), so each rule is exercised from BOTH directions:
 * once from a mutated struct, once from mutated RAW BYTES.
 *
 * The codec is POLICY-NEUTRAL: there is no per-type count window here, and
 * these tests deliberately accept shapes no transaction type would (a
 * 0-in/0-out/0-signer leg is structurally legal and must encode).
 * ════════════════════════════════════════════════════════════════════ */

/** Leg length for the three counts, spelled out so the assertions below are
 *  independent of the header macro they are checking. */
#define TLEG_LEN(nin, nout, nsig)                                          \
    (4u + 64u * (nin) + 169u * (nout) + 7219u * (nsig))
/** The KAT leg (1 in / 1 out / 1 signer) = 4 + 64 + 169 + 7219. */
#define TLEG_KAT_LEN   7456u
/** Worst legal leg (16 / 16 / 4) = 4 + 1024 + 2704 + 28876 (design §C.3). */
#define TLEG_MAX       32608u

/**
 * The KAT fixture — the ONE leg whose commitment digest is pinned below.
 * Field values chosen so the independent python3 oracle can reproduce them
 * exactly: every span is fill(seed) = seed + 7·i, amount is a literal.
 */
static void tleg_fixture_kat(dnac_txw3_tleg_t *t) {
    memset(t, 0, sizeof(*t));
    t->tleg_version = DNAC_TXW3_TLEG_VERSION;
    t->num_tin = 1;
    fill(t->tin_nullifier[0], DNAC_TXW_NULLIFIER_LEN, 0x11);
    t->num_tout = 1;
    fill(t->tout[0].fp, DNAC_TXW_FP_LEN, 0x22);
    t->tout[0].amount = 1337ULL;                    /* 0x0000000000000539 */
    fill(t->tout[0].nullifier_seed, DNAC_TXW_SEED_LEN, 0x33);
    t->num_signers = 1;
    fill(t->signer[0].pubkey, DNAC_TXW_PK_LEN, 0x44);
    fill(t->signer[0].signature, DNAC_TXW_SIG_LEN, 0x55);
}

/**
 * Generic canonical fixture at any legal shape. Input nullifiers get a
 * distinct LEADING byte (0x10 + i), which is what memcmp decides on, so the
 * set is strictly ascending for every count up to the 16 cap.
 */
static void tleg_fixture_multi(dnac_txw3_tleg_t *t,
                               unsigned nin, unsigned nout, unsigned nsig) {
    memset(t, 0, sizeof(*t));
    t->tleg_version = DNAC_TXW3_TLEG_VERSION;
    t->num_tin = (uint8_t)nin;
    for (unsigned i = 0; i < nin; i++) {
        fill(t->tin_nullifier[i], DNAC_TXW_NULLIFIER_LEN, (uint8_t)(0x11 + i));
        t->tin_nullifier[i][0] = (uint8_t)(0x10 + i);   /* strictly ascending */
    }
    t->num_tout = (uint8_t)nout;
    for (unsigned i = 0; i < nout; i++) {
        fill(t->tout[i].fp, DNAC_TXW_FP_LEN, (uint8_t)(0x22 + i));
        t->tout[i].amount = 1000ULL + i;                /* every one >= 1 */
        fill(t->tout[i].nullifier_seed, DNAC_TXW_SEED_LEN, (uint8_t)(0x33 + i));
    }
    t->num_signers = (uint8_t)nsig;
    for (unsigned i = 0; i < nsig; i++) {
        fill(t->signer[i].pubkey, DNAC_TXW_PK_LEN, (uint8_t)(0x44 + i));
        fill(t->signer[i].signature, DNAC_TXW_SIG_LEN, (uint8_t)(0x55 + i));
    }
}

/** Field-by-field equality over the USED slots only — slots at or beyond a
 *  count are not on the wire, so they are not part of the object. */
static int tleg_eq(const dnac_txw3_tleg_t *a, const dnac_txw3_tleg_t *b) {
    if (a->tleg_version != b->tleg_version) return 0;
    if (a->num_tin != b->num_tin || a->num_tout != b->num_tout ||
        a->num_signers != b->num_signers) return 0;
    for (unsigned i = 0; i < (unsigned)a->num_tin; i++)
        if (memcmp(a->tin_nullifier[i], b->tin_nullifier[i],
                   DNAC_TXW_NULLIFIER_LEN) != 0) return 0;
    for (unsigned i = 0; i < (unsigned)a->num_tout; i++) {
        if (memcmp(a->tout[i].fp, b->tout[i].fp, DNAC_TXW_FP_LEN) != 0) return 0;
        if (a->tout[i].amount != b->tout[i].amount) return 0;
        if (memcmp(a->tout[i].nullifier_seed, b->tout[i].nullifier_seed,
                   DNAC_TXW_SEED_LEN) != 0) return 0;
    }
    for (unsigned i = 0; i < (unsigned)a->num_signers; i++) {
        if (memcmp(a->signer[i].pubkey, b->signer[i].pubkey,
                   DNAC_TXW_PK_LEN) != 0) return 0;
        if (memcmp(a->signer[i].signature, b->signer[i].signature,
                   DNAC_TXW_SIG_LEN) != 0) return 0;
    }
    return 1;
}

/** What the decoder must leave behind on ANY reject: a fully zeroed struct
 *  (the memset runs before the first byte is examined). */
static int tleg_is_zeroed(const dnac_txw3_tleg_t *t) {
    const uint8_t *p = (const uint8_t *)t;
    for (size_t i = 0; i < sizeof(*t); i++) if (p[i] != 0) return 0;
    return 1;
}

/* ── T. Round trips + the PREFIX contract ────────────────────────────── */
static int test_tleg_roundtrip(void) {
    dnac_txw3_tleg_t *t    = calloc(1, sizeof(*t));
    dnac_txw3_tleg_t *back = calloc(1, sizeof(*back));
    uint8_t *buf = calloc(1, TLEG_MAX + 512);
    size_t written = 0, consumed = 0;

    CHECK(t && back && buf, "T alloc");

    /* Header constants agree with the hand-computed lengths. */
    CHECK(DNAC_TXW3_TLEG_VERSION == 1, "T version constant"); OK();
    CHECK(DNAC_TXW3_TLEG_TOUT_LEN == 169, "T tout size"); OK();
    CHECK(DNAC_TXW3_TLEG_SIGNER_LEN == 7219, "T signer size"); OK();
    CHECK(DNAC_TXW3_TLEG_FIXED == 4, "T fixed overhead"); OK();
    CHECK(DNAC_TXW3_TLEG_MAX_LEN == TLEG_MAX, "T max leg length"); OK();

    /* (T1) 1 in / 1 out / 1 signer — the KAT shape. */
    tleg_fixture_kat(t);
    {
        size_t need = 0;
        CHECK(dnac_txw3_tleg_encoded_size(1, 1, 1, &need) == 0 &&
              need == TLEG_KAT_LEN && need == TLEG_LEN(1u, 1u, 1u),
              "T1 encoded_size"); OK();
    }
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX + 512, &written) == 0 &&
          written == TLEG_KAT_LEN, "T1 encode"); OK();
    CHECK(dnac_txw3_tleg_decode(buf, written, back, &consumed) == 0 &&
          consumed == written, "T1 decode"); OK();
    CHECK(tleg_eq(t, back), "T1 field-by-field equality"); OK();
    /* The fixture was zero-initialised and the decoder zeroes first, so the
     * two structs must match BYTE-for-byte, unused slots included. */
    CHECK(memcmp(t, back, sizeof(*t)) == 0, "T1 whole-struct identity"); OK();
    {   /* a leg that decodes re-encodes byte-identically */
        uint8_t *re = calloc(1, TLEG_KAT_LEN);
        size_t w2 = 0;
        CHECK(re != NULL, "T1 alloc");
        CHECK(dnac_txw3_tleg_encode(back, re, TLEG_KAT_LEN, &w2) == 0 &&
              w2 == written && memcmp(re, buf, written) == 0,
              "T1 re-encode identity"); OK();
        free(re);
    }

    /* (T2) 0 in / 1 out / 0 signers — the UNSHIELD shape (the pool pays a
     *      transparent recipient; nothing transparent is being spent, so
     *      there is nothing to authorize with a signature). */
    tleg_fixture_multi(t, 0, 1, 0);
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX + 512, &written) == 0 &&
          written == TLEG_LEN(0u, 1u, 0u) && written == 173,
          "T2 encode"); OK();
    CHECK(buf[0] == 0x01 && buf[1] == 0x00 && buf[2] == 0x01 &&
          buf[172] == 0x00, "T2 count bytes on the wire"); OK();
    CHECK(dnac_txw3_tleg_decode(buf, written, back, &consumed) == 0 &&
          consumed == written && tleg_eq(t, back) &&
          back->num_tin == 0 && back->num_signers == 0, "T2 decode"); OK();

    /* (T3) 16 / 16 / 4 — the maximal legal leg. */
    tleg_fixture_multi(t, 16, 16, 4);
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX + 512, &written) == 0 &&
          written == TLEG_MAX && written == TLEG_LEN(16u, 16u, 4u),
          "T3 maximal encode"); OK();
    CHECK(dnac_txw3_tleg_decode(buf, written, back, &consumed) == 0 &&
          consumed == TLEG_MAX && tleg_eq(t, back), "T3 maximal decode"); OK();
    CHECK(memcmp(t, back, sizeof(*t)) == 0, "T3 whole-struct identity"); OK();
    /* Exact-capacity acceptance and one-byte-short rejection. */
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &written) == 0 &&
          written == TLEG_MAX, "T3 exact dst_cap rejected"); OK();
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX - 1, &written) != 0,
          "T3 dst_cap-1 accepted"); OK();

    /* (T4) 0 / 0 / 0 — structurally legal and exactly 4 bytes. No
     *      transaction type would accept it (count windows are NATIVE
     *      rules), which is exactly why the codec must. */
    tleg_fixture_multi(t, 0, 0, 0);
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX + 512, &written) == 0 &&
          written == 4 && written == TLEG_LEN(0u, 0u, 0u),
          "T4 minimal encode"); OK();
    CHECK(buf[0] == 0x01 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00,
          "T4 minimal bytes"); OK();
    CHECK(dnac_txw3_tleg_decode(buf, 4, back, &consumed) == 0 &&
          consumed == 4 && back->num_tin == 0 && back->num_tout == 0 &&
          back->num_signers == 0, "T4 minimal decode"); OK();

    /* (T5) PREFIX contract: a leg followed by trailing bytes decodes with
     *      the correct `consumed`, and the trailing bytes are untouched.
     *      Then the REAL composition — the remainder is handed to the §4
     *      shielded decoder, which is the caller's next step for a 12/13
     *      body. */
    {
        uint8_t sentinel[8];
        size_t leg_len = 0;

        tleg_fixture_multi(t, 2, 1, 1);
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX + 512, &leg_len) == 0 &&
              leg_len == TLEG_LEN(2u, 1u, 1u), "T5 leg encode"); OK();
        fill(sentinel, sizeof(sentinel), 0x9C);
        memcpy(buf + leg_len, sentinel, sizeof(sentinel));

        CHECK(dnac_txw3_tleg_decode(buf, leg_len + sizeof(sentinel), back,
                                    &consumed) == 0 && consumed == leg_len,
              "T5 prefix consumed"); OK();
        CHECK(tleg_eq(t, back), "T5 prefix fields"); OK();
        CHECK(memcmp(buf + leg_len, sentinel, sizeof(sentinel)) == 0,
              "T5 trailing bytes disturbed"); OK();
        /* A trailing byte is NOT a reject for the leg (unlike §2/§4). */
        CHECK(dnac_txw3_tleg_decode(buf, leg_len + 1, back, &consumed) == 0 &&
              consumed == leg_len, "T5 one trailing byte rejected"); OK();

        /* leg ‖ shielded section: split at `consumed`, decode both. */
        {
            dnac_txw3_shielded_t sh;
            const uint8_t *fri = NULL;
            uint32_t fri_len = 0;
            size_t sh_len = shld_encode_a(buf + leg_len, 512);
            CHECK(sh_len == 364, "T5 shielded fixture");
            CHECK(dnac_txw3_tleg_decode(buf, leg_len + sh_len, back,
                                        &consumed) == 0 && consumed == leg_len,
                  "T5 composed leg decode"); OK();
            CHECK(dnac_txw3_shielded_decode(buf + consumed,
                                            (uint32_t)(leg_len + sh_len - consumed),
                                            &sh, &fri, &fri_len) == 0 &&
                  fri_len == 5, "T5 composed shielded decode"); OK();
        }
    }

    free(buf); free(back); free(t);
    return 0;
}

/* ── U. Byte-exact leg KAT (hand-written literal offsets) ────────────── */
static int test_tleg_offsets(void) {
    dnac_txw3_tleg_t *t = calloc(1, sizeof(*t));
    uint8_t *buf    = calloc(1, TLEG_KAT_LEN);
    uint8_t *expect = calloc(1, TLEG_KAT_LEN);
    size_t written = 0;

    CHECK(t && buf && expect, "U alloc");
    tleg_fixture_kat(t);
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_KAT_LEN, &written) == 0 &&
          written == TLEG_KAT_LEN, "U encode"); OK();

    /* amount = 1337, big-endian — the one hand-written multi-byte literal;
     * every other span is a reproducible fill() pattern. */
    static const uint8_t k_amount[8] =
        { 0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x39 };
    /* First bytes of each fill() span, written out so a silently changed
     * generator cannot slip past the offset checks below. */
    CHECK(buf[2]   == 0x11, "U nullifier first byte"); OK();
    CHECK(buf[67]  == 0x22, "U fp first byte"); OK();
    CHECK(buf[204] == 0x33, "U seed first byte"); OK();
    CHECK(buf[237] == 0x44, "U pubkey first byte"); OK();
    CHECK(buf[2829] == 0x55, "U signature first byte"); OK();

    /* Per-offset assertions — the documented layout, one CHECK per field:
     *   0 ver · 1 num_tin · 2 nf(64) · 66 num_tout · 67 fp(129) ·
     *   196 amount(8) · 204 seed(32) · 236 num_signers · 237 pk(2592) ·
     *   2829 sig(4627) · end 7456 */
    {
        uint8_t span[DNAC_TXW_SIG_LEN];

        CHECK(buf[0] == 0x01, "U off 0 tleg_version"); OK();
        CHECK(buf[1] == 0x01, "U off 1 num_tin"); OK();
        fill(span, DNAC_TXW_NULLIFIER_LEN, 0x11);
        CHECK(memcmp(buf + 2, span, DNAC_TXW_NULLIFIER_LEN) == 0,
              "U off 2 tin nullifier"); OK();
        CHECK(buf[66] == 0x01, "U off 66 num_tout"); OK();
        fill(span, DNAC_TXW_FP_LEN, 0x22);
        CHECK(memcmp(buf + 67, span, DNAC_TXW_FP_LEN) == 0,
              "U off 67 tout fp"); OK();
        CHECK(memcmp(buf + 196, k_amount, 8) == 0, "U off 196 amount"); OK();
        fill(span, DNAC_TXW_SEED_LEN, 0x33);
        CHECK(memcmp(buf + 204, span, DNAC_TXW_SEED_LEN) == 0,
              "U off 204 nullifier_seed"); OK();
        CHECK(buf[236] == 0x01, "U off 236 num_signers"); OK();
        fill(span, DNAC_TXW_PK_LEN, 0x44);
        CHECK(memcmp(buf + 237, span, DNAC_TXW_PK_LEN) == 0,
              "U off 237 signer pubkey"); OK();
        fill(span, DNAC_TXW_SIG_LEN, 0x55);
        CHECK(memcmp(buf + 2829, span, DNAC_TXW_SIG_LEN) == 0,
              "U off 2829 signer signature"); OK();

        /* Whole-buffer KAT: assemble the 7456 expected bytes at literal
         * offsets, then compare in one shot — never against a decode of
         * itself. */
        expect[0] = 0x01;
        expect[1] = 0x01;
        fill(expect + 2, DNAC_TXW_NULLIFIER_LEN, 0x11);
        expect[66] = 0x01;
        fill(expect + 67, DNAC_TXW_FP_LEN, 0x22);
        memcpy(expect + 196, k_amount, 8);
        fill(expect + 204, DNAC_TXW_SEED_LEN, 0x33);
        expect[236] = 0x01;
        fill(expect + 237, DNAC_TXW_PK_LEN, 0x44);
        fill(expect + 2829, DNAC_TXW_SIG_LEN, 0x55);
        CHECK(memcmp(buf, expect, TLEG_KAT_LEN) == 0, "U whole-leg KAT"); OK();
    }

    free(expect); free(buf); free(t);
    return 0;
}

/* ── V. Encode negatives (every one must return -1) ──────────────────── */
static int test_tleg_encode_negatives(void) {
    dnac_txw3_tleg_t *t = calloc(1, sizeof(*t));
    uint8_t *buf = calloc(1, TLEG_MAX);
    size_t w = 0;

    CHECK(t && buf, "V alloc");

    /* encoded_size: caps + NULL, and *out is zeroed on every reject so a
     * caller that ignores the return value cannot read a stale length. */
    {
        size_t n = 0x5A5A5A5A;
        CHECK(dnac_txw3_tleg_encoded_size(17, 1, 1, &n) != 0 && n == 0,
              "V size num_tin 17 accepted"); OK();
        n = 0x5A5A5A5A;
        CHECK(dnac_txw3_tleg_encoded_size(1, 17, 1, &n) != 0 && n == 0,
              "V size num_tout 17 accepted"); OK();
        n = 0x5A5A5A5A;
        CHECK(dnac_txw3_tleg_encoded_size(1, 1, 5, &n) != 0 && n == 0,
              "V size num_signers 5 accepted"); OK();
        n = 0x5A5A5A5A;
        CHECK(dnac_txw3_tleg_encoded_size(255, 255, 255, &n) != 0 && n == 0,
              "V size all-255 accepted"); OK();
        CHECK(dnac_txw3_tleg_encoded_size(1, 1, 1, NULL) != 0,
              "V size null out accepted"); OK();
        /* The caps themselves are ACCEPTED (16/16/4 is the maximum). */
        CHECK(dnac_txw3_tleg_encoded_size(16, 16, 4, &n) == 0 && n == TLEG_MAX,
              "V size at the caps rejected"); OK();
        CHECK(dnac_txw3_tleg_encoded_size(0, 0, 0, &n) == 0 && n == 4,
              "V size 0/0/0 rejected"); OK();
    }

    /* tleg_version must be exactly 1. */
    {
        const uint8_t bad_ver[3] = { 0x00, 0x02, 0xFF };
        for (int i = 0; i < 3; i++) {
            tleg_fixture_multi(t, 1, 1, 1);
            t->tleg_version = bad_ver[i];
            CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
                  "V tleg_version != 1 accepted"); OK();
        }
    }

    /* Counts over the structural caps. */
    tleg_fixture_multi(t, 16, 1, 1); t->num_tin = 17;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_tin 17 accepted"); OK();
    tleg_fixture_multi(t, 1, 16, 1); t->num_tout = 17;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_tout 17 accepted"); OK();
    tleg_fixture_multi(t, 1, 1, 4); t->num_signers = 5;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_signers 5 accepted"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->num_tin = 0xFF;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_tin 255 accepted"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->num_tout = 0xFF;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_tout 255 accepted"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->num_signers = 0xFF;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V num_signers 255 accepted"); OK();

    /* Input ordering: descending, and the equal (duplicate) case. Both are
     * caught by the single strictly-ascending memcmp comparison. */
    {
        uint8_t swap[DNAC_TXW_NULLIFIER_LEN];
        tleg_fixture_multi(t, 2, 1, 1);
        memcpy(swap, t->tin_nullifier[0], sizeof(swap));
        memcpy(t->tin_nullifier[0], t->tin_nullifier[1], sizeof(swap));
        memcpy(t->tin_nullifier[1], swap, sizeof(swap));
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
              "V descending inputs accepted"); OK();

        tleg_fixture_multi(t, 2, 1, 1);
        memcpy(t->tin_nullifier[1], t->tin_nullifier[0], sizeof(swap));
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
              "V duplicate inputs accepted"); OK();

        /* A difference only in the LAST byte still orders — the comparison
         * is a full 64-byte memcmp, not a prefix check. */
        tleg_fixture_multi(t, 2, 1, 1);
        memcpy(t->tin_nullifier[1], t->tin_nullifier[0], sizeof(swap));
        t->tin_nullifier[1][DNAC_TXW_NULLIFIER_LEN - 1] =
            (uint8_t)(t->tin_nullifier[0][DNAC_TXW_NULLIFIER_LEN - 1] + 1);
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) == 0,
              "V last-byte ascending rejected"); OK();
        t->tin_nullifier[1][DNAC_TXW_NULLIFIER_LEN - 1] =
            (uint8_t)(t->tin_nullifier[0][DNAC_TXW_NULLIFIER_LEN - 1] - 1);
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
              "V last-byte descending accepted"); OK();

        /* A mis-ordered pair anywhere in a maximal set is caught. */
        tleg_fixture_multi(t, 16, 1, 1);
        memcpy(swap, t->tin_nullifier[9], sizeof(swap));
        memcpy(t->tin_nullifier[9], t->tin_nullifier[10], sizeof(swap));
        memcpy(t->tin_nullifier[10], swap, sizeof(swap));
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
              "V mid-set swap accepted"); OK();
    }

    /* Zero-amount output — a reject, never an encoding. Every position. */
    tleg_fixture_multi(t, 1, 1, 1); t->tout[0].amount = 0;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V zero amount accepted"); OK();
    tleg_fixture_multi(t, 1, 4, 1); t->tout[3].amount = 0;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V zero amount in last slot accepted"); OK();
    tleg_fixture_multi(t, 1, 16, 1); t->tout[15].amount = 0;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) != 0,
          "V zero amount at the cap accepted"); OK();
    /* amount == 1 is the smallest ACCEPTED value; so is 2^64−1. */
    tleg_fixture_multi(t, 1, 1, 1); t->tout[0].amount = 1;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) == 0,
          "V amount 1 rejected"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->tout[0].amount = 0xFFFFFFFFFFFFFFFFULL;
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) == 0,
          "V amount 2^64-1 rejected"); OK();
    /* Slots at or beyond a count are NOT judged and NOT emitted: poison
     * every unused output and input slot with values that would be rejects
     * if they were live, then require the SAME bytes as the clean leg. */
    {
        uint8_t *clean = calloc(1, TLEG_KAT_LEN);
        size_t w_clean = 0;
        CHECK(clean != NULL, "V alloc");
        tleg_fixture_multi(t, 1, 1, 1);
        CHECK(dnac_txw3_tleg_encode(t, clean, TLEG_KAT_LEN, &w_clean) == 0,
              "V clean encode");
        for (unsigned i = 1; i < DNAC_TXW_MAX_OUTPUTS; i++) {
            memset(t->tout[i].fp, 0xEE, DNAC_TXW_FP_LEN);
            t->tout[i].amount = 0;                     /* a live-slot reject */
            memset(t->tout[i].nullifier_seed, 0xEE, DNAC_TXW_SEED_LEN);
        }
        for (unsigned i = 1; i < DNAC_TXW_MAX_INPUTS; i++)
            memset(t->tin_nullifier[i], 0x00, DNAC_TXW_NULLIFIER_LEN);
        for (unsigned i = 1; i < DNAC_TXW_MAX_SIGNERS; i++)
            memset(t->signer[i].pubkey, 0xEE, DNAC_TXW_PK_LEN);
        CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, &w) == 0 &&
              w == w_clean && w == TLEG_LEN(1u, 1u, 1u) &&
              memcmp(buf, clean, w) == 0, "V unused slots judged/emitted"); OK();
        free(clean);
    }

    /* Short dst_cap: need is exactly TLEG_LEN(1,1,1). */
    tleg_fixture_multi(t, 1, 1, 1);
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_KAT_LEN - 1, &w) != 0,
          "V dst_cap-1 accepted"); OK();
    CHECK(dnac_txw3_tleg_encode(t, buf, 0, &w) != 0, "V dst_cap 0 accepted"); OK();
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_KAT_LEN, &w) == 0 &&
          w == TLEG_KAT_LEN, "V exact dst_cap rejected"); OK();

    /* NULL fail-closes. */
    CHECK(dnac_txw3_tleg_encode(NULL, buf, TLEG_MAX, &w) != 0,
          "V null t accepted"); OK();
    CHECK(dnac_txw3_tleg_encode(t, NULL, TLEG_MAX, &w) != 0,
          "V null dst accepted"); OK();
    CHECK(dnac_txw3_tleg_encode(t, buf, TLEG_MAX, NULL) != 0,
          "V null written_out accepted"); OK();

    free(buf); free(t);
    return 0;
}

/* ── W. Decode negatives (raw bytes; every one must return -1 AND leave
 *       *out zeroed) ─────────────────────────────────────────────────── */
static int test_tleg_decode_negatives(void) {
    dnac_txw3_tleg_t *t   = calloc(1, sizeof(*t));
    dnac_txw3_tleg_t *out = calloc(1, sizeof(*out));
    uint8_t *good = calloc(1, TLEG_KAT_LEN);
    uint8_t *bad  = calloc(1, TLEG_KAT_LEN);
    size_t n = 0, consumed = 0;

    CHECK(t && out && good && bad, "W alloc");
    tleg_fixture_kat(t);
    CHECK(dnac_txw3_tleg_encode(t, good, TLEG_KAT_LEN, &n) == 0 &&
          n == TLEG_KAT_LEN, "W fixture encode");

/* Every decode negative goes through this: poison *out, poison consumed,
 * require the reject, require *out zeroed, require consumed untouched. */
#define W_REJECT(body_, len_, msg_) do {                                   \
        memset(out, 0x5A, sizeof(*out));                                   \
        consumed = 0xDEADBEEF;                                             \
        CHECK(dnac_txw3_tleg_decode((body_), (len_), out, &consumed) != 0,  \
              msg_); OK();                                                 \
        CHECK(tleg_is_zeroed(out), msg_ " (left *out dirty)"); OK();       \
        CHECK(consumed == 0xDEADBEEF, msg_ " (wrote consumed)"); OK();     \
    } while (0)

    /* Truncation at every field-class boundary of the KAT leg:
     *   0,1      before/inside the two leading bytes
     *   2,65     nullifier absent / one byte short
     *   66       nullifier complete, num_tout byte missing
     *   67,195   output absent / fp one byte short
     *   203,204  amount short / seed absent
     *   235      seed one byte short
     *   236      output complete, num_signers byte missing
     *   237,2828 signer absent / pubkey one byte short
     *   2829,7455 signature absent / one byte short */
    {
        const size_t cuts[16] = { 0, 1, 2, 65, 66, 67, 195, 203,
                                  204, 235, 236, 237, 2828, 2829, 7455, 40 };
        for (int i = 0; i < 16; i++)
            W_REJECT(good, cuts[i], "W truncated leg accepted");
    }

    /* Bad version byte. */
    {
        const uint8_t bad_ver[3] = { 0x00, 0x02, 0xFF };
        for (int i = 0; i < 3; i++) {
            memcpy(bad, good, n); bad[0] = bad_ver[i];
            W_REJECT(bad, n, "W tleg_version != 1 accepted");
        }
    }

    /* Counts over the caps, injected raw. A count over its cap must be
     * rejected BEFORE it is used to index anything. */
    memcpy(bad, good, n); bad[1] = 17;
    W_REJECT(bad, n, "W num_tin 17 accepted");
    memcpy(bad, good, n); bad[1] = 0xFF;
    W_REJECT(bad, n, "W num_tin 255 accepted");
    memcpy(bad, good, n); bad[66] = 17;
    W_REJECT(bad, n, "W num_tout 17 accepted");
    memcpy(bad, good, n); bad[66] = 0xFF;
    W_REJECT(bad, n, "W num_tout 255 accepted");
    memcpy(bad, good, n); bad[236] = 5;
    W_REJECT(bad, n, "W num_signers 5 accepted");
    memcpy(bad, good, n); bad[236] = 0xFF;
    W_REJECT(bad, n, "W num_signers 255 accepted");

    /* Zero-amount output, injected raw at the amount's BE offset 196. */
    memcpy(bad, good, n); poke_be64(bad + 196, 0);
    W_REJECT(bad, n, "W raw zero amount accepted");
    /* … and amount 1 at the same offset is ACCEPTED (the gate is == 0). */
    memcpy(bad, good, n); poke_be64(bad + 196, 1);
    memset(out, 0x5A, sizeof(*out));
    CHECK(dnac_txw3_tleg_decode(bad, n, out, &consumed) == 0 &&
          out->tout[0].amount == 1, "W raw amount 1 rejected"); OK();

    /* Ordering / duplicates on a 2-input leg, injected raw. */
    {
        uint8_t *two = calloc(1, TLEG_MAX);
        size_t m = 0;
        CHECK(two != NULL, "W alloc2");
        tleg_fixture_multi(t, 2, 1, 1);
        CHECK(dnac_txw3_tleg_encode(t, two, TLEG_MAX, &m) == 0 &&
              m == TLEG_LEN(2u, 1u, 1u), "W two-input fixture");

        /* Control: untouched, it decodes. */
        memset(out, 0x5A, sizeof(*out));
        CHECK(dnac_txw3_tleg_decode(two, m, out, &consumed) == 0 &&
              consumed == m && out->num_tin == 2,
              "W two-input control rejected"); OK();

        /* Duplicate: copy nullifier[0] (off 2) over nullifier[1] (off 66). */
        {
            uint8_t *dup = calloc(1, TLEG_MAX);
            CHECK(dup != NULL, "W alloc3");
            memcpy(dup, two, m);
            memcpy(dup + 66, dup + 2, DNAC_TXW_NULLIFIER_LEN);
            W_REJECT(dup, m, "W raw duplicate inputs accepted");
            /* Descending: swap the two 64-byte spans. */
            memcpy(dup, two, m);
            memcpy(dup + 66, two + 2,  DNAC_TXW_NULLIFIER_LEN);
            memcpy(dup + 2,  two + 66, DNAC_TXW_NULLIFIER_LEN);
            W_REJECT(dup, m, "W raw descending inputs accepted");
            free(dup);
        }
        free(two);
    }

    /* NULL fail-closes. */
    CHECK(dnac_txw3_tleg_decode(NULL, n, out, &consumed) != 0,
          "W null body accepted"); OK();
    CHECK(dnac_txw3_tleg_decode(good, n, NULL, &consumed) != 0,
          "W null out accepted"); OK();
    CHECK(dnac_txw3_tleg_decode(good, n, out, NULL) != 0,
          "W null consumed_out accepted"); OK();

    /* Same contract as the shielded decoder (O6 verifier C5): a NULL-argument
     * reject must leave a valid *out zeroed, not stale. */
    memset(out, 0x5A, sizeof(*out));
    (void)dnac_txw3_tleg_decode(NULL, n, out, &consumed);
    CHECK(tleg_is_zeroed(out), "W null-body reject left *out dirty"); OK();
    memset(out, 0x5A, sizeof(*out));
    (void)dnac_txw3_tleg_decode(good, n, out, NULL);
    CHECK(tleg_is_zeroed(out), "W null-consumed_out reject left *out dirty"); OK();

#undef W_REJECT

    free(bad); free(good); free(out); free(t);
    return 0;
}

/* ── X. dnac_tleg_commit — KAT, exclusions, sensitivity, domains ─────── */

/* SHA3-512 of the DNA.TLEG.v1 preimage over the KAT fixture, computed
 * INDEPENDENTLY with python3 hashlib.sha3_512 (2844-byte preimage):
 *   "DNA.TLEG.v1" + 5*\x00                                     (16)
 *   ‖ \x01 ‖ fill(0x11,64)                                     (65)
 *   ‖ \x01 ‖ fill(0x22,129) ‖ 0000000000000539 ‖ fill(0x33,32) (170)
 *   ‖ \x01 ‖ fill(0x44,2592)                                   (2593)
 * where fill(s,n)[i] = (s + 7*i) & 0xFF — the same generator this file's
 * fill() uses. The signer's fill(0x55,4627) SIGNATURE is NOT in the
 * preimage; the digest below is what proves that. */
static const char *TLEG_COMMIT_KAT_HEX =
    "a5b8f80392fa2acfb5d7c02ef7b2efed081dd91d4a0c8a98dbf273bf72cd51bf"
    "d522c54f1f52a29b29623187b4761562a02fd8ab84be831f2c06e5237bc1b521";

static int test_tleg_commit(void) {
    dnac_txw3_tleg_t *t = calloc(1, sizeof(*t));
    uint8_t base[64], h[64];

    CHECK(t != NULL, "X alloc");

    /* (X1) KAT against the independent oracle. */
    tleg_fixture_kat(t);
    CHECK(dnac_tleg_commit(t, base) == 0, "X commit"); OK();
    CHECK(hex_eq(base, TLEG_COMMIT_KAT_HEX), "X commit KAT"); OK();
    /* Determinism: same leg → same digest. */
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) == 0,
          "X commit determinism"); OK();

    /* (X2) SIGNATURES ARE EXCLUDED: flipping signature bytes — including
     *      replacing the whole signature — leaves the digest EQUAL. */
    tleg_fixture_kat(t); t->signer[0].signature[0] ^= 0xFF;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) == 0,
          "X signature byte 0 leaked into the commitment"); OK();
    tleg_fixture_kat(t);
    t->signer[0].signature[DNAC_TXW_SIG_LEN - 1] ^= 0x01;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) == 0,
          "X signature last byte leaked"); OK();
    tleg_fixture_kat(t);
    memset(t->signer[0].signature, 0xA7, DNAC_TXW_SIG_LEN);
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) == 0,
          "X whole signature leaked"); OK();

    /* (X2b) tleg_version is EXCLUDED too — but only value 1 is canonical,
     *       so there is no second accepted version to compare against; the
     *       exclusion is asserted by the KAT preimage above, which does not
     *       contain the byte. A non-canonical version simply must not hash. */
    tleg_fixture_kat(t); t->tleg_version = 2;
    CHECK(dnac_tleg_commit(t, h) != 0, "X version 2 hashed"); OK();
    tleg_fixture_kat(t); t->tleg_version = 0;
    CHECK(dnac_tleg_commit(t, h) != 0, "X version 0 hashed"); OK();

    /* (X3) Sensitivity: every committed field changes the digest. */
    tleg_fixture_kat(t);
    t->num_tin = 0;                       /* count drops, nullifier drops out */
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X num_tin not bound"); OK();
    tleg_fixture_kat(t); t->tin_nullifier[0][63] ^= 0x01;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X nullifier byte not bound"); OK();
    tleg_fixture_kat(t); t->tout[0].fp[128] ^= 0x01;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X fp byte not bound"); OK();
    tleg_fixture_kat(t); t->tout[0].amount ^= 1;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X amount not bound"); OK();
    tleg_fixture_kat(t); t->tout[0].nullifier_seed[31] ^= 0x01;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X seed byte not bound"); OK();
    tleg_fixture_kat(t); t->num_tout = 0;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X num_tout not bound"); OK();
    tleg_fixture_kat(t); t->num_signers = 0;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X num_signers not bound"); OK();
    tleg_fixture_kat(t); t->signer[0].pubkey[2591] ^= 0x01;
    CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base, 64) != 0,
          "X pubkey byte not bound"); OK();
    /* The SECOND input is bound too (a leg is not summarised by its first
     * nullifier). The only canonical order is ascending, so two legs over
     * the same input set can never both commit. */
    {
        uint8_t base2[64];
        tleg_fixture_multi(t, 2, 1, 1);
        CHECK(dnac_tleg_commit(t, base2) == 0, "X two-input commit"); OK();
        CHECK(memcmp(base2, base, 64) != 0, "X two-input == one-input"); OK();
        tleg_fixture_multi(t, 2, 1, 1); t->tin_nullifier[1][63] ^= 0x01;
        CHECK(dnac_tleg_commit(t, h) == 0 && memcmp(h, base2, 64) != 0,
              "X second nullifier not bound"); OK();
    }

    /* (X4) A non-canonical leg MUST NOT hash — same rule list as encode. */
    tleg_fixture_multi(t, 2, 1, 1);
    memcpy(t->tin_nullifier[1], t->tin_nullifier[0], DNAC_TXW_NULLIFIER_LEN);
    CHECK(dnac_tleg_commit(t, h) != 0, "X duplicate inputs hashed"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->tout[0].amount = 0;
    CHECK(dnac_tleg_commit(t, h) != 0, "X zero amount hashed"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->num_tin = 17;
    CHECK(dnac_tleg_commit(t, h) != 0, "X num_tin 17 hashed"); OK();
    tleg_fixture_multi(t, 1, 1, 1); t->num_signers = 5;
    CHECK(dnac_tleg_commit(t, h) != 0, "X num_signers 5 hashed"); OK();

    /* (X5) EMPTY-TAG DISTINCTNESS: the 0/0/0 populated leg and the absent
     *      leg are different DOMAINS ("DNA.TLEG.v1" vs "DNA.E.TLEG.v1"), so
     *      a present-but-empty leg can never be mistaken for an absent one. */
    {
        uint8_t empty[64], zero_leg[64];
        tleg_fixture_multi(t, 0, 0, 0);
        CHECK(dnac_tleg_commit(t, zero_leg) == 0, "X 0/0/0 commit"); OK();
        CHECK(dnac_tleg_commit_empty(empty) == 0, "X empty commit"); OK();
        CHECK(memcmp(zero_leg, empty, 64) != 0,
              "X 0/0/0 leg collides with the empty commitment"); OK();
        /* Neither is an all-zero digest (no tag can produce one). */
        {
            uint8_t z[64];
            memset(z, 0, sizeof(z));
            CHECK(memcmp(zero_leg, z, 64) != 0 && memcmp(empty, z, 64) != 0,
                  "X all-zero digest"); OK();
        }
    }

    /* (X6) NULL fail-closes. */
    tleg_fixture_kat(t);
    CHECK(dnac_tleg_commit(NULL, h) != 0, "X null t accepted"); OK();
    CHECK(dnac_tleg_commit(t, NULL) != 0, "X null out accepted"); OK();

    free(t);
    return 0;
}

int main(void) {
    if (test_exec_context() != 0) return 1;
    if (test_v3() != 0) return 1;
    if (test_shielded_roundtrip() != 0) return 1;
    if (test_shielded_offsets() != 0) return 1;
    if (test_shielded_encode_negatives() != 0) return 1;
    if (test_shielded_decode_negatives() != 0) return 1;
    if (test_shielded_check_header() != 0) return 1;
    if (test_tleg_roundtrip() != 0) return 1;
    if (test_tleg_offsets() != 0) return 1;
    if (test_tleg_encode_negatives() != 0) return 1;
    if (test_tleg_decode_negatives() != 0) return 1;
    if (test_tleg_commit() != 0) return 1;
    printf("test_tx_wire_v3: %d checks OK\n", g_checks);
    return 0;
}
