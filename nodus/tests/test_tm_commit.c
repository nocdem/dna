/**
 * Nodus — Tendermint T3 wave 1: `nodus.commit.v1` certificate tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the commit certificate codec is the layout of T2 wire design §4.3,
 * that its verification is fail-closed, and that the BFT-time median is the
 * reference's walk. If this file failed, one of these would be false:
 *   · the 94-byte header sits at the published offsets and the height-1
 *     empty certificate is exactly those 94 bytes (built here by hand,
 *     WITHOUT the encoder);
 *   · an entry is 9 bytes when ABSENT and 4636 when it carries a signature,
 *     and the maximum at N = 128 is 593 502 bytes;
 *   · decode is strict: a wrong tag, a short buffer, one trailing byte, an
 *     unknown flag, an ABSENT entry with a non-zero timestamp, or n > 128
 *     all REJECT — and n is bounded before anything is allocated;
 *   · verification is FAIL-CLOSED: ONE corrupt signature rejects the whole
 *     certificate even when the surviving good ones would still reach
 *     quorum. This is the property that stops an attacker padding a
 *     certificate with garbage and still finalizing;
 *   · position is identity: entry i is checked against snapshot entry i's
 *     pubkey, so swapping two entries rejects;
 *   · NIL entries are VERIFIED but NOT COUNTED toward quorum, and ABSENT
 *     entries are neither;
 *   · the median is taken over the non-ABSENT entries with the reference's
 *     weighted-median walk at weight 1, matching the published KATs
 *     (total 1..6 → indices 0,0,0,1,1,2; 128 → 63) and the bft-time.md
 *     example {100, 98, 1000, 500} → 100.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no RNG. Safe under `ctest -j`. It allocates a ~580 KB
 * buffer for the N = 128 case and frees it.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The SHA3-512 value below is a SELF-CONSISTENT FREEZE, NOT AN EXTERNAL
 *     ORACLE FOR THE DESIGN. It was produced with python3 hashlib.sha3_512
 *     over the 94 bytes this file also builds by hand: it pins that our
 *     SHA3-512 agrees with an independent FIPS-202 implementation and that
 *     the empty certificate has not drifted. There is no published vector
 *     for `nodus.commit.v1`. Only reading T2 §4.3 against the pinned
 *     reference can establish that the layout is right.
 *  2. ML-DSA-87 signing here is HEDGED — signing the same preimage twice
 *     produces different bytes. So no digest is ever frozen over a
 *     certificate containing real signatures, and no two signatures are
 *     compared for equality. Every real-key assertion is on a VERIFY
 *     OUTCOME or on structural bytes. Keys themselves are derandomized
 *     (fixed seeds), so membership and pubkeys are bit-reproducible.
 *  3. The N = 128 section uses SYNTHETIC signature bytes, not real ones. It
 *     proves length, round-trip and bounds ONLY — it verifies nothing, and
 *     a green there is not evidence that 128 real signatures validate.
 *  4. The snapshot handed to verify is trusted here because this file built
 *     it. In production the HOST must resolve it from committed authority;
 *     that resolution is wave-2 work and is NOT covered.
 *  5. The median is tested as a pure function of a certificate. That the
 *     host feeds it the certificate of h-1, and compares the result to the
 *     header timestamp, is wave-2 work (valid() steps 14-15) and is NOT
 *     covered here.
 *
 * @file test_tm_commit.c
 */

#include "dnac/tm_commit.h"
#include "dnac/tm_vote.h"
#include "dnac/tm_bounds.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdint.h>
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

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* Local big-endian writers/readers: the expected bytes must be built
 * WITHOUT the library's helpers. */
static void t_be16(uint16_t v, uint8_t *o) {
    o[0] = (uint8_t)(v >> 8); o[1] = (uint8_t)v;
}
static void t_be32(uint32_t v, uint8_t *o) {
    for (int i = 0; i < 4; i++) o[i] = (uint8_t)(v >> (24 - 8 * i));
}
static void t_be64(uint64_t v, uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* The header layout, retyped as literals (T2 §4.3). */
#define T_OFF_HEIGHT    16u
#define T_OFF_ROUND     24u
#define T_OFF_BLOCK_ID  28u
#define T_OFF_N         92u
#define T_HDR           94u

/* SELF-CONSISTENT FREEZE — see the header, item 1. */
static const char *KAT_EMPTY94_HEX =
    /* "nodus.commit.v1" (15 ASCII) then 79 zero bytes: 1 tag pad + height 8
     * + round 4 + block_id 64 + n 2 = 94 bytes, 188 hex characters. */
    "6e6f6475732e636f6d6d69742e7631"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000";
static const char *KAT_EMPTY94_HASH =
    "5493ed1beef1b1c716967df92ac8b8d9f53b701af1a6af4dfe5ae39d0e259407"
    "0474c7ed6ce175cb36b1b948bce7073dd1644fab49fca2541efc449ab50085f9";

/* ── 1: derived bounds ──────────────────────────────────────────────────
 * tm_bounds.h's _Static_asserts fire at compile time; this section states
 * the same numbers at run time so a reader sees them, and prints them. */

static int test_bounds(void) {
    CHECK(DNA_TM_COMMIT_HDR_LEN == 94u, "header length drifted"); OK();
    CHECK(DNA_TM_COMMIT_ENTRY_ABSENT_LEN == 9u, "ABSENT entry drifted"); OK();
    CHECK(DNA_TM_COMMIT_ENTRY_SIGNED_LEN == 4636u, "signed entry drifted");
    OK();
    CHECK(DNA_TM_COMMIT_MAX_LEN == 593502u, "CERT_MAX drifted"); OK();
    CHECK(DNA_TM_COMMIT_MAX_LEN ==
              (size_t)DNA_TM_COMMIT_HDR_LEN +
              (size_t)DNA_MAX_ACTIVE_VALIDATORS * DNA_TM_COMMIT_ENTRY_SIGNED_LEN,
          "CERT_MAX is not its own formula"); OK();
    CHECK(DNA_TM_BODY_V2_MAX_LEN == 2691257u, "BODY_MAX drifted"); OK();
    CHECK(DNA_TM_VALUE_MAX_LEN == 2807586u, "VALUE_MAX drifted"); OK();
    CHECK(DNA_TM_COMMIT_EMPTY_LEN == DNA_TM_COMMIT_HDR_LEN,
          "empty certificate is not the bare header"); OK();
    CHECK(DNA_TM_COMMIT_TAG_LEN == 16, "tag length drifted"); OK();
    CHECK(dna_bft_quorum(4) == 3 && dna_bft_quorum(128) == 86,
          "quorum drifted"); OK();

    printf("  [bounds] CERT_ENTRY %u  CERT_MAX %llu  BODY_MAX %llu  "
           "VALUE_MAX %llu\n",
           (unsigned)DNA_TM_COMMIT_ENTRY_SIGNED_LEN,
           (unsigned long long)DNA_TM_COMMIT_MAX_LEN,
           (unsigned long long)DNA_TM_BODY_V2_MAX_LEN,
           (unsigned long long)DNA_TM_VALUE_MAX_LEN);
    return 0;
}

/* ── 2: the empty certificate (height 1) ────────────────────────────── */

static int test_empty(void) {
    /* Built by hand at the literal offsets, not by the encoder. */
    uint8_t want[T_HDR];
    memset(want, 0, sizeof(want));
    memcpy(want, "nodus.commit.v1", 15);      /* offset 15 stays 0x00 */
    t_be64(0, want + T_OFF_HEIGHT);
    t_be32(0, want + T_OFF_ROUND);
    /* block_id 64 × 0 already zeroed */
    t_be16(0, want + T_OFF_N);

    char hex[2 * T_HDR + 1];
    to_hex(want, T_HDR, hex);
    CHECK(strcmp(hex, KAT_EMPTY94_HEX) == 0, "empty certificate byte KAT");
    OK();
    CHECK(want[15] == 0, "tag padding not zero"); OK();

    dna_tm_commit_t *c = dna_tm_commit_alloc(0);
    CHECK(c != NULL, "alloc(0) failed"); OK();
    CHECK(c->n == 0 && c->entries == NULL, "alloc(0) is not the empty shape");
    OK();
    CHECK(dna_tm_commit_set_empty(c) == 0, "set_empty"); OK();
    CHECK(dna_tm_commit_is_empty(c) == 1, "set_empty is not empty"); OK();

    CHECK(dna_tm_commit_encoded_len(c) == T_HDR, "empty length != 94"); OK();
    uint8_t got[T_HDR];
    size_t w = 0;
    CHECK(dna_tm_commit_encode(c, got, sizeof(got), &w) == 0 && w == T_HDR,
          "empty encode");
    CHECK(memcmp(want, got, T_HDR) == 0,
          "encoded empty certificate != hand-built bytes"); OK();

    /* Frozen digest — self-consistent, not an external oracle (header). */
    uint8_t h[64];
    CHECK(dna_tm_commit_hash(got, T_HDR, h) == 0, "commit hash"); OK();
    char hh[129];
    to_hex(h, 64, hh);
    CHECK(strcmp(hh, KAT_EMPTY94_HASH) == 0, "empty certificate digest KAT");
    OK();
    /* Flat: no tag is prepended, so it is plain SHA3-512 of the bytes. */
    uint8_t h2[64];
    CHECK(qgp_sha3_512(got, T_HDR, h2) == 0, "sha3");
    CHECK(memcmp(h, h2, 64) == 0, "commit hash is not flat SHA3-512"); OK();

    /* Round-trip. */
    dna_tm_commit_t *d = NULL;
    CHECK(dna_tm_commit_decode(got, T_HDR, &d) == 0, "empty decode"); OK();
    CHECK(dna_tm_commit_is_empty(d) == 1, "decoded empty is not empty"); OK();
    CHECK(d->entries == NULL, "decoded empty allocated entries"); OK();
    dna_tm_commit_free(&d);
    CHECK(d == NULL, "free did not zero the pointer"); OK();

    /* expect_empty accepts ONLY the empty shape, and reads no snapshot. */
    CHECK(dna_tm_commit_verify(c, 1, 0, NULL, NULL, NULL, NULL) == 0,
          "empty certificate rejected under expect_empty"); OK();
    c->height = 1;
    CHECK(dna_tm_commit_is_empty(c) == 0, "height 1 counted as empty"); OK();
    CHECK(dna_tm_commit_verify(c, 1, 0, NULL, NULL, NULL, NULL) == -1,
          "non-empty accepted under expect_empty"); OK();
    c->height = 0;
    c->block_id[63] = 1;
    CHECK(dna_tm_commit_verify(c, 1, 0, NULL, NULL, NULL, NULL) == -1,
          "non-zero block_id accepted under expect_empty"); OK();
    c->block_id[63] = 0;
    c->round = 9;
    CHECK(dna_tm_commit_verify(c, 1, 0, NULL, NULL, NULL, NULL) == -1,
          "non-zero round accepted under expect_empty"); OK();

    CHECK(dna_tm_commit_verify(NULL, 1, 0, NULL, NULL, NULL, NULL) == -2,
          "NULL certificate is not a fault"); OK();
    CHECK(dna_tm_commit_is_empty(NULL) == 0, "NULL is empty"); OK();
    CHECK(dna_tm_commit_set_empty(NULL) == -1, "set_empty(NULL)"); OK();

    dna_tm_commit_free(&c);
    return 0;
}

/* ── 3: strict decode over hand-built buffers ───────────────────────── */

/** Writes the 94-byte header for `n` entries into dst. */
static void build_hdr(uint8_t *dst, uint64_t height, uint32_t round,
                      const uint8_t *block_id, uint16_t n) {
    memset(dst, 0, T_HDR);
    memcpy(dst, "nodus.commit.v1", 15);
    t_be64(height, dst + T_OFF_HEIGHT);
    t_be32(round, dst + T_OFF_ROUND);
    if (block_id) memcpy(dst + T_OFF_BLOCK_ID, block_id, 64);
    t_be16(n, dst + T_OFF_N);
}

static int test_decode_strict(void) {
    uint8_t bid[64];
    memset(bid, 0x5A, sizeof(bid));

    /* One ABSENT entry: 94 + 9 = 103 bytes. */
    uint8_t buf[T_HDR + 4636];
    dna_tm_commit_t *d = NULL;

    build_hdr(buf, 12, 3, bid, 1);
    buf[T_HDR] = DNA_TM_COMMIT_FLAG_ABSENT;
    t_be64(0, buf + T_HDR + 1);
    CHECK(dna_tm_commit_decode(buf, T_HDR + 9, &d) == 0, "ABSENT decode");
    OK();
    CHECK(d->height == 12 && d->round == 3 && d->n == 1, "header fields"); OK();
    CHECK(memcmp(d->block_id, bid, 64) == 0, "block_id"); OK();
    CHECK(d->entries[0].flag == DNA_TM_COMMIT_FLAG_ABSENT &&
          d->entries[0].timestamp_ms == 0, "ABSENT entry"); OK();
    CHECK(dna_tm_commit_encoded_len(d) == T_HDR + 9, "ABSENT length"); OK();
    dna_tm_commit_free(&d);

    /* ABSENT with a non-zero timestamp REJECTS on decode. */
    t_be64(1, buf + T_HDR + 1);
    CHECK(dna_tm_commit_decode(buf, T_HDR + 9, &d) == -1,
          "ABSENT with timestamp != 0 decoded"); OK();
    /* ... and the very last bit of the timestamp counts. */
    t_be64(0, buf + T_HDR + 1);
    buf[T_HDR + 8] = 0x01;
    CHECK(dna_tm_commit_decode(buf, T_HDR + 9, &d) == -1,
          "ABSENT timestamp LSB ignored"); OK();
    t_be64(0, buf + T_HDR + 1);

    /* Unknown flags reject. */
    const uint8_t bad_flags[] = { 0, 4, 5, 0x20, 0xFF };
    for (size_t i = 0; i < sizeof(bad_flags) / sizeof(bad_flags[0]); i++) {
        buf[T_HDR] = bad_flags[i];
        CHECK(dna_tm_commit_decode(buf, T_HDR + 9, &d) == -1,
              "unknown flag decoded");
    }
    OK();
    buf[T_HDR] = DNA_TM_COMMIT_FLAG_ABSENT;

    /* Exact length: truncation and trailing bytes both reject. */
    CHECK(dna_tm_commit_decode(buf, T_HDR + 8, &d) == -1, "truncated entry");
    OK();
    CHECK(dna_tm_commit_decode(buf, T_HDR + 10, &d) == -1, "trailing byte");
    OK();
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == -1,
          "n=1 with no entry bytes"); OK();

    /* A COMMIT entry needs its 4627-byte signature: 94 + 4636. */
    build_hdr(buf, 12, 3, bid, 1);
    buf[T_HDR] = DNA_TM_COMMIT_FLAG_COMMIT;
    t_be64(777, buf + T_HDR + 1);
    memset(buf + T_HDR + 9, 0xAB, 4627);
    CHECK(dna_tm_commit_decode(buf, T_HDR + 4636, &d) == 0, "COMMIT decode");
    OK();
    CHECK(d->entries[0].timestamp_ms == 777, "COMMIT timestamp"); OK();
    CHECK(d->entries[0].sig[0] == 0xAB && d->entries[0].sig[4626] == 0xAB,
          "COMMIT signature bytes"); OK();
    dna_tm_commit_free(&d);
    CHECK(dna_tm_commit_decode(buf, T_HDR + 4635, &d) == -1,
          "COMMIT one byte short"); OK();
    CHECK(dna_tm_commit_decode(buf, T_HDR + 9, &d) == -1,
          "COMMIT sized as ABSENT"); OK();

    /* Empty certificate: exactly 94, nothing more. */
    build_hdr(buf, 0, 0, NULL, 0);
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == 0, "n=0 decode"); OK();
    dna_tm_commit_free(&d);
    CHECK(dna_tm_commit_decode(buf, T_HDR + 1, &d) == -1,
          "n=0 with a trailing byte"); OK();
    CHECK(dna_tm_commit_decode(buf, T_HDR - 1, &d) == -1, "short header");
    OK();

    /* A wrong tag rejects — the marker is checked, not assumed. */
    build_hdr(buf, 0, 0, NULL, 0);
    buf[0] ^= 0xFF;
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == -1, "wrong tag decoded");
    OK();
    build_hdr(buf, 0, 0, NULL, 0);
    buf[15] = 'x';   /* the pad byte is part of the tag */
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == -1, "tag padding ignored");
    OK();

    /* n > 128 rejects, and does so BEFORE allocating: the buffer here is
     * only 94 bytes long, so any allocation attempt would be for entries
     * that do not exist. */
    build_hdr(buf, 0, 0, NULL, 129);
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == -1, "n=129 decoded"); OK();
    build_hdr(buf, 0, 0, NULL, 0xFFFF);
    CHECK(dna_tm_commit_decode(buf, T_HDR, &d) == -1, "n=65535 decoded"); OK();

    /* NULL arguments are a caller bug, not a verdict on bytes. */
    CHECK(dna_tm_commit_decode(NULL, T_HDR, &d) == -2, "NULL src"); OK();
    CHECK(dna_tm_commit_decode(buf, T_HDR, NULL) == -2, "NULL out"); OK();

    /* alloc bounds. */
    dna_tm_commit_t *big = dna_tm_commit_alloc(DNA_MAX_ACTIVE_VALIDATORS);
    CHECK(big != NULL && big->n == 128 && big->entries != NULL, "alloc(128)");
    OK();
    dna_tm_commit_free(&big);
    CHECK(dna_tm_commit_alloc(129) == NULL, "alloc(129) succeeded"); OK();

    /* Encode rejects what decode rejects: ABSENT carrying a time. */
    dna_tm_commit_t *e = dna_tm_commit_alloc(1);
    CHECK(e != NULL, "alloc(1)");
    e->entries[0].flag = DNA_TM_COMMIT_FLAG_ABSENT;
    e->entries[0].timestamp_ms = 5;
    CHECK(dna_tm_commit_encoded_len(e) == 0,
          "encoded_len accepted ABSENT with a timestamp"); OK();
    uint8_t small[T_HDR + 9];
    CHECK(dna_tm_commit_encode(e, small, sizeof(small), NULL) == -1,
          "encode accepted ABSENT with a timestamp"); OK();
    e->entries[0].timestamp_ms = 0;
    CHECK(dna_tm_commit_encode(e, small, sizeof(small), NULL) == 0,
          "encode rejected a valid ABSENT entry"); OK();
    /* Too small a buffer rejects rather than overflowing. */
    CHECK(dna_tm_commit_encode(e, small, sizeof(small) - 1, NULL) == -1,
          "encode ignored cap"); OK();
    e->entries[0].flag = 7;
    CHECK(dna_tm_commit_encode(e, small, sizeof(small), NULL) == -1,
          "encode accepted an unknown flag"); OK();
    /* A hand-built count above the ceiling never reaches the wire. */
    e->entries[0].flag = DNA_TM_COMMIT_FLAG_ABSENT;
    e->n = 129;
    CHECK(dna_tm_commit_encoded_len(e) == 0, "encoded_len accepted n=129");
    OK();
    CHECK(dna_tm_commit_median_time(e, NULL) == -1, "median NULL out"); OK();
    uint64_t ms = 0;
    CHECK(dna_tm_commit_median_time(e, &ms) == -1, "median accepted n=129");
    OK();
    e->n = 1;
    dna_tm_commit_free(&e);

    CHECK(dna_tm_commit_encode(NULL, small, sizeof(small), NULL) == -1,
          "encode(NULL)"); OK();
    CHECK(dna_tm_commit_encoded_len(NULL) == 0, "encoded_len(NULL)"); OK();
    return 0;
}

/* ── 4: the BFT-time median ─────────────────────────────────────────── */

/** Builds a certificate of `n` entries; flags[i] and times[i] per entry. */
static dna_tm_commit_t *make_cert(const uint8_t *flags, const uint64_t *times,
                                  uint16_t n) {
    dna_tm_commit_t *c = dna_tm_commit_alloc(n);
    if (!c) return NULL;
    for (size_t i = 0; i < (size_t)n; i++) {
        c->entries[i].flag = flags[i];
        c->entries[i].timestamp_ms = times[i];
    }
    return c;
}

static int test_median(void) {
    /* The published KATs: total 1..6 pick sorted indices 0,0,0,1,1,2. */
    const uint64_t asc[6] = { 10, 20, 30, 40, 50, 60 };
    const size_t   want_idx[6] = { 0, 0, 0, 1, 1, 2 };
    for (uint16_t total = 1; total <= 6; total++) {
        uint8_t flags[6];
        uint64_t times[6];
        /* Fed in DESCENDING order, so a missing sort is visible. */
        for (uint16_t i = 0; i < total; i++) {
            flags[i] = DNA_TM_COMMIT_FLAG_COMMIT;
            times[i] = asc[total - 1 - i];
        }
        dna_tm_commit_t *c = make_cert(flags, times, total);
        CHECK(c != NULL, "make_cert");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median");
        CHECK(ms == asc[want_idx[total - 1]], "median KAT total 1..6");
        /* The walk must agree with the closed form sorted[max(0,t/2-1)]. */
        size_t half = (size_t)total / 2u;
        size_t closed = (half == 0) ? 0 : half - 1;
        CHECK(ms == asc[closed], "walk disagrees with the closed form");
        dna_tm_commit_free(&c);
    }
    OK();

    /* bft-time.md's own example, with unit weights: {100, 98, 1000, 500}
     * sorts to [98, 100, 500, 1000], total 4, index 1 → 100. */
    {
        const uint8_t flags[4] = { DNA_TM_COMMIT_FLAG_COMMIT,
                                   DNA_TM_COMMIT_FLAG_COMMIT,
                                   DNA_TM_COMMIT_FLAG_COMMIT,
                                   DNA_TM_COMMIT_FLAG_COMMIT };
        const uint64_t times[4] = { 100, 98, 1000, 500 };
        dna_tm_commit_t *c = make_cert(flags, times, 4);
        CHECK(c != NULL, "make_cert bft-time");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median bft-time");
        CHECK(ms == 100, "bft-time.md example did not yield 100"); OK();
        dna_tm_commit_free(&c);
    }

    /* N = 128, all COMMIT: index 63. */
    {
        uint8_t flags[128];
        uint64_t times[128];
        for (size_t i = 0; i < 128; i++) {
            flags[i] = DNA_TM_COMMIT_FLAG_COMMIT;
            times[i] = 1000 + (uint64_t)(127 - i);   /* descending input */
        }
        dna_tm_commit_t *c = make_cert(flags, times, 128);
        CHECK(c != NULL, "make_cert 128");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median 128");
        CHECK(ms == 1000 + 63, "median at 128 is not sorted index 63"); OK();
        dna_tm_commit_free(&c);
    }

    /* ABSENT entries do NOT enter the median; NIL entries DO. */
    {
        const uint8_t flags[5] = { DNA_TM_COMMIT_FLAG_ABSENT,
                                   DNA_TM_COMMIT_FLAG_COMMIT,
                                   DNA_TM_COMMIT_FLAG_ABSENT,
                                   DNA_TM_COMMIT_FLAG_NIL,
                                   DNA_TM_COMMIT_FLAG_COMMIT };
        const uint64_t times[5] = { 0, 30, 0, 10, 20 };
        dna_tm_commit_t *c = make_cert(flags, times, 5);
        CHECK(c != NULL, "make_cert mixed");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median mixed");
        /* Non-ABSENT times [10, 20, 30]: total 3 → index 0 → 10. */
        CHECK(ms == 10, "ABSENT entries leaked into the median"); OK();

        /* Drop the NIL: [20, 30], total 2 → index 0 → 20. This is what
         * would change if NIL were skipped like ABSENT. */
        c->entries[3].flag = DNA_TM_COMMIT_FLAG_ABSENT;
        c->entries[3].timestamp_ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median without NIL");
        CHECK(ms == 20, "NIL is not counted in the median"); OK();
        dna_tm_commit_free(&c);
    }

    /* Every entry ABSENT → there is no median. */
    {
        const uint8_t flags[3] = { DNA_TM_COMMIT_FLAG_ABSENT,
                                   DNA_TM_COMMIT_FLAG_ABSENT,
                                   DNA_TM_COMMIT_FLAG_ABSENT };
        const uint64_t times[3] = { 0, 0, 0 };
        dna_tm_commit_t *c = make_cert(flags, times, 3);
        CHECK(c != NULL, "make_cert all absent");
        uint64_t ms = 12345;
        CHECK(dna_tm_commit_median_time(c, &ms) == -1,
              "all-ABSENT certificate produced a median"); OK();
        dna_tm_commit_free(&c);
    }

    /* The empty certificate has no median either. */
    {
        dna_tm_commit_t *c = dna_tm_commit_alloc(0);
        CHECK(c != NULL, "alloc(0)");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == -1,
              "empty certificate produced a median"); OK();
        dna_tm_commit_free(&c);
    }

    /* Equal timestamps are one value: the median is that value. */
    {
        uint8_t flags[4];
        uint64_t times[4];
        for (size_t i = 0; i < 4; i++) {
            flags[i] = DNA_TM_COMMIT_FLAG_COMMIT; times[i] = 999;
        }
        dna_tm_commit_t *c = make_cert(flags, times, 4);
        CHECK(c != NULL, "make_cert equal");
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0 && ms == 999,
              "equal timestamps"); OK();
        dna_tm_commit_free(&c);
    }

    CHECK(dna_tm_commit_median_time(NULL, NULL) == -1, "median(NULL)"); OK();
    return 0;
}

/* ── Real-key harness (N = 4) ───────────────────────────────────────── */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[DNA_VSET_VOTER_ID_LEN];
} keyset_t;

/** voter_id = SHA3-512(pubkey)[0..31] — the derivation test_qc_v2.c pins. */
static void derive_voter(const uint8_t *pk, uint8_t out[32]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, 32);
}

static int cmp_key(const void *a, const void *b) {
    return memcmp(((const keyset_t *)a)->voter, ((const keyset_t *)b)->voter,
                  DNA_VSET_VOTER_ID_LEN);
}

/** Deterministic keys: seed = 0x40 + index, repeated 32×, then sorted by
 *  voter_id so index i really IS the i-th ascending voter (set order). */
static int make_keys(keyset_t *ks, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(ks[i].pk, ks[i].sk, seed) != 0) return -1;
        derive_voter(ks[i].pk, ks[i].voter);
    }
    qsort(ks, (size_t)n, sizeof(ks[0]), cmp_key);
    return 0;
}

static dna_vset_snapshot_t *make_snapshot(const keyset_t *ks, int n) {
    dna_vset_snapshot_t *s = dna_vset_alloc((uint16_t)n);
    if (!s) return NULL;
    s->epoch = 720;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (int i = 0; i < n; i++) {
        memcpy(s->entries[i].voter_id, ks[i].voter, DNA_VSET_VOTER_ID_LEN);
        memcpy(s->entries[i].pubkey, ks[i].pk, DNA_VSET_PUBKEY_LEN);
        s->entries[i].total_stake    = 20000000000000000ULL - (uint64_t)i;
        s->entries[i].self_bond      = 10000000000000000ULL;
        s->entries[i].commission_bps = (uint16_t)(100 + i);
    }
    return s;
}

/**
 * Signs entry i as `flags[i]` over the PRECOMMIT preimage: block_id for
 * COMMIT, 64 × 0 for NIL, nothing for ABSENT.
 */
static dna_tm_commit_t *sign_cert(const keyset_t *ks, const uint8_t *flags,
                                  const uint64_t *times, uint16_t n,
                                  uint64_t height, uint32_t round,
                                  const uint8_t bid[64], const uint8_t chain[32],
                                  const uint8_t vsh[64]) {
    static const uint8_t NIL_ID[64] = { 0 };
    dna_tm_commit_t *c = dna_tm_commit_alloc(n);
    if (!c) return NULL;
    c->height = height;
    c->round = round;
    memcpy(c->block_id, bid, 64);

    for (size_t i = 0; i < (size_t)n; i++) {
        c->entries[i].flag = flags[i];
        if (flags[i] == DNA_TM_COMMIT_FLAG_ABSENT) {
            c->entries[i].timestamp_ms = 0;
            continue;
        }
        c->entries[i].timestamp_ms = times[i];
        const uint8_t *vote_bid =
            (flags[i] == DNA_TM_COMMIT_FLAG_COMMIT) ? bid : NIL_ID;
        uint8_t pre[DNA_TM_VOTE_PREIMAGE_LEN];
        if (dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, vote_bid,
                                 ks[i].voter, height, round, times[i],
                                 chain, vsh, pre) != 0) {
            dna_tm_commit_free(&c); return NULL;
        }
        size_t siglen = 0;
        if (qgp_dsa87_sign(c->entries[i].sig, &siglen, pre, sizeof(pre),
                           ks[i].sk) != 0 ||
            siglen != QGP_DSA87_SIGNATURE_BYTES) {
            dna_tm_commit_free(&c); return NULL;
        }
    }
    return c;
}

/* ── 5: real-key verification (N = 4, quorum 3) ─────────────────────── */

static int test_real_keys(void) {
    keyset_t ks[4];
    CHECK(make_keys(ks, 4) == 0, "keygen");

    dna_vset_snapshot_t *snap = make_snapshot(ks, 4);
    CHECK(snap != NULL, "snapshot");

    uint8_t vsh[DNA_VSET_HASH_LEN];
    CHECK(dna_vset_hash(snap, vsh) == 0, "vset hash");

    uint8_t bid[64], chain[32];
    memset(bid, 0x77, sizeof(bid));
    memset(chain, 0x66, sizeof(chain));
    const uint64_t H = 4242;
    const uint32_t R = 5;
    const uint64_t times[4] = { 1800000000000ULL, 1800000000001ULL,
                                1800000000002ULL, 1800000000003ULL };

    const uint8_t all_commit[4] = { 2, 2, 2, 2 };

    /* ── The accepting case. ── */
    dna_tm_commit_t *c = sign_cert(ks, all_commit, times, 4, H, R, bid,
                                   chain, vsh);
    CHECK(c != NULL, "sign_cert");
    CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, chain) == 0,
          "a fully signed certificate was rejected"); OK();

    /* Round-trip, then verify the DECODED object: the codec must not lose
     * or reorder anything the verifier depends on. */
    size_t need = dna_tm_commit_encoded_len(c);
    CHECK(need == (size_t)T_HDR + 4u * 4636u, "N=4 all-COMMIT length"); OK();
    uint8_t *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b1 && b2, "alloc");
    size_t w = 0;
    CHECK(dna_tm_commit_encode(c, b1, need, &w) == 0 && w == need, "encode");
    dna_tm_commit_t *d = NULL;
    CHECK(dna_tm_commit_decode(b1, need, &d) == 0, "decode"); OK();
    CHECK(dna_tm_commit_encode(d, b2, need, NULL) == 0 &&
          memcmp(b1, b2, need) == 0, "round-trip not byte-identical"); OK();
    CHECK(dna_tm_commit_verify(d, 0, H, bid, snap, vsh, chain) == 0,
          "decoded certificate was rejected"); OK();
    dna_tm_commit_free(&d);

    /* ── FAIL-CLOSED: one corrupt signature kills the whole certificate,
     *    even though the other three still reach quorum 3. ── */
    {
        dna_tm_commit_t *bad = sign_cert(ks, all_commit, times, 4, H, R, bid,
                                         chain, vsh);
        CHECK(bad != NULL, "sign_cert bad");
        bad->entries[2].sig[0] ^= 0xFF;
        CHECK(dna_bft_quorum(4) == 3, "quorum assumption"); OK();
        CHECK(dna_tm_commit_verify(bad, 0, H, bid, snap, vsh, chain) == -1,
              "a corrupt signature was tolerated because quorum still held");
        OK();
        /* Also the LAST byte, so the check is not a prefix comparison. */
        bad->entries[2].sig[0] ^= 0xFF;
        bad->entries[3].sig[QGP_DSA87_SIGNATURE_BYTES - 1] ^= 0xFF;
        CHECK(dna_tm_commit_verify(bad, 0, H, bid, snap, vsh, chain) == -1,
              "corrupt signature tail tolerated"); OK();
        dna_tm_commit_free(&bad);
    }

    /* ── Position is identity: swapping two entries rejects. ── */
    {
        dna_tm_commit_t *sw = sign_cert(ks, all_commit, times, 4, H, R, bid,
                                        chain, vsh);
        CHECK(sw != NULL, "sign_cert swap");
        dna_tm_commit_entry_t t = sw->entries[0];
        sw->entries[0] = sw->entries[1];
        sw->entries[1] = t;
        CHECK(dna_tm_commit_verify(sw, 0, H, bid, snap, vsh, chain) == -1,
              "entries out of set order were accepted"); OK();
        dna_tm_commit_free(&sw);
    }

    /* ── NIL: verified, never counted. ── */
    {
        const uint8_t f3c1n[4] = { 2, 2, 2, 3 };   /* 3 COMMIT + 1 NIL */
        dna_tm_commit_t *n1 = sign_cert(ks, f3c1n, times, 4, H, R, bid,
                                        chain, vsh);
        CHECK(n1 != NULL, "sign_cert 3+nil");
        CHECK(dna_tm_commit_verify(n1, 0, H, bid, snap, vsh, chain) == 0,
              "3 COMMIT + 1 NIL rejected"); OK();
        /* Its NIL signature really is over the zero block_id: corrupting
         * it must still reject, so it was actually checked. */
        n1->entries[3].sig[5] ^= 0xFF;
        CHECK(dna_tm_commit_verify(n1, 0, H, bid, snap, vsh, chain) == -1,
              "a NIL entry's signature was never verified"); OK();
        dna_tm_commit_free(&n1);

        /* 2 COMMIT + 2 NIL: every signature is valid, quorum is not met. */
        const uint8_t f2c2n[4] = { 2, 2, 3, 3 };
        dna_tm_commit_t *n2 = sign_cert(ks, f2c2n, times, 4, H, R, bid,
                                        chain, vsh);
        CHECK(n2 != NULL, "sign_cert 2+2nil");
        CHECK(dna_tm_commit_verify(n2, 0, H, bid, snap, vsh, chain) == -1,
              "NIL entries were counted toward quorum"); OK();
        dna_tm_commit_free(&n2);
    }

    /* ── Quorum boundary at N = 4: 2 rejects, 3 accepts. ── */
    {
        const uint8_t f2[4] = { 2, 2, 1, 1 };      /* 2 COMMIT + 2 ABSENT */
        dna_tm_commit_t *q2 = sign_cert(ks, f2, times, 4, H, R, bid, chain,
                                        vsh);
        CHECK(q2 != NULL, "sign_cert q2");
        CHECK(dna_tm_commit_verify(q2, 0, H, bid, snap, vsh, chain) == -1,
              "2 of 4 COMMIT reached quorum"); OK();
        dna_tm_commit_free(&q2);

        const uint8_t f3[4] = { 2, 2, 2, 1 };      /* 3 COMMIT + 1 ABSENT */
        dna_tm_commit_t *q3 = sign_cert(ks, f3, times, 4, H, R, bid, chain,
                                        vsh);
        CHECK(q3 != NULL, "sign_cert q3");
        CHECK(dna_tm_commit_verify(q3, 0, H, bid, snap, vsh, chain) == 0,
              "3 of 4 COMMIT did not reach quorum"); OK();
        /* The ABSENT entry is 9 bytes on the wire. */
        CHECK(dna_tm_commit_encoded_len(q3) ==
                  (size_t)T_HDR + 3u * 4636u + 9u,
              "mixed certificate length"); OK();
        /* An ABSENT entry that acquires a timestamp no longer encodes. */
        q3->entries[3].timestamp_ms = 1;
        CHECK(dna_tm_commit_encoded_len(q3) == 0,
              "ABSENT with a timestamp encoded"); OK();
        q3->entries[3].timestamp_ms = 0;
        dna_tm_commit_free(&q3);
    }

    /* ── Wrong context: every bound field must be the one asked for. ── */
    {
        uint8_t other_bid[64], other_chain[32], other_vsh[64];
        memcpy(other_bid, bid, 64);      other_bid[0] ^= 1;
        memcpy(other_chain, chain, 32);  other_chain[0] ^= 1;
        memcpy(other_vsh, vsh, 64);      other_vsh[0] ^= 1;

        CHECK(dna_tm_commit_verify(c, 0, H + 1, bid, snap, vsh, chain) == -1,
              "wrong height accepted"); OK();
        CHECK(dna_tm_commit_verify(c, 0, H, other_bid, snap, vsh, chain) == -1,
              "wrong block_id accepted"); OK();
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, other_vsh, chain) == -1,
              "a vset_hash that is not the snapshot's was accepted"); OK();
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, other_chain) == -1,
              "wrong chain_id accepted"); OK();

        /* The certificate's own round is bound into every preimage. */
        c->round = R + 1;
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, chain) == -1,
              "round is not bound into the vote preimage"); OK();
        c->round = R;

        /* A timestamp edited after signing invalidates its entry. */
        c->entries[1].timestamp_ms += 1;
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, chain) == -1,
              "entry timestamp is not bound into the signature"); OK();
        c->entries[1].timestamp_ms -= 1;
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, chain) == 0,
              "restoring the timestamp did not restore validity"); OK();
    }

    /* ── n must equal the snapshot's N. ── */
    {
        dna_vset_snapshot_t *snap3 = make_snapshot(ks, 3);
        CHECK(snap3 != NULL, "snapshot3");
        uint8_t vsh3[DNA_VSET_HASH_LEN];
        CHECK(dna_vset_hash(snap3, vsh3) == 0, "vset hash 3");
        /* A 4-entry certificate against a 3-member set: n != N. */
        CHECK(dna_tm_commit_verify(c, 0, H, bid, snap3, vsh3, chain) == -1,
              "n != N accepted"); OK();
        dna_vset_free(&snap3);
    }

    /* ── expect_empty on a real certificate, and its converse. ── */
    CHECK(dna_tm_commit_verify(c, 1, H, bid, snap, vsh, chain) == -1,
          "a populated certificate passed as the empty one"); OK();
    {
        dna_tm_commit_t *mt = dna_tm_commit_alloc(0);
        CHECK(mt != NULL, "alloc(0)");
        CHECK(dna_tm_commit_verify(mt, 0, H, bid, snap, vsh, chain) == -1,
              "the empty certificate passed as a real one"); OK();
        dna_tm_commit_free(&mt);
    }

    /* ── NULL arguments are faults, not verdicts. ── */
    CHECK(dna_tm_commit_verify(c, 0, H, NULL, snap, vsh, chain) == -2,
          "NULL block_id is not a fault"); OK();
    CHECK(dna_tm_commit_verify(c, 0, H, bid, NULL, vsh, chain) == -2,
          "NULL snapshot is not a fault"); OK();
    CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, NULL, chain) == -2,
          "NULL vset_hash is not a fault"); OK();
    CHECK(dna_tm_commit_verify(c, 0, H, bid, snap, vsh, NULL) == -2,
          "NULL chain_id is not a fault"); OK();

    /* ── The median over a real, signed certificate. ── */
    {
        uint64_t ms = 0;
        CHECK(dna_tm_commit_median_time(c, &ms) == 0, "median real");
        /* Four COMMIT stamps, sorted → index 1. */
        CHECK(ms == times[1], "median over a real certificate"); OK();
    }

    free(b1); free(b2);
    dna_tm_commit_free(&c);
    dna_vset_free(&snap);
    return 0;
}

/* ── 6: N = 128 — LENGTH AND ROUND-TRIP ONLY (synthetic signatures) ──── */

static int test_max_size(void) {
    uint8_t bid[64];
    memset(bid, 0x2B, sizeof(bid));

    dna_tm_commit_t *c = dna_tm_commit_alloc(DNA_MAX_ACTIVE_VALIDATORS);
    CHECK(c != NULL, "alloc(128)");
    c->height = 100000;
    c->round = 3;
    memcpy(c->block_id, bid, 64);
    for (size_t i = 0; i < (size_t)DNA_MAX_ACTIVE_VALIDATORS; i++) {
        c->entries[i].flag = DNA_TM_COMMIT_FLAG_COMMIT;
        c->entries[i].timestamp_ms = 1800000000000ULL + (uint64_t)i;
        /* SYNTHETIC bytes — this section verifies nothing (header, item 3). */
        memset(c->entries[i].sig, (uint8_t)(i & 0xFF),
               QGP_DSA87_SIGNATURE_BYTES);
    }

    size_t need = dna_tm_commit_encoded_len(c);
    CHECK(need == 593502u, "N=128 all-COMMIT length != 593 502"); OK();
    CHECK(need == DNA_TM_COMMIT_MAX_LEN, "N=128 length != CERT_MAX"); OK();

    uint8_t *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b1 && b2, "alloc 128");
    size_t w = 0;
    CHECK(dna_tm_commit_encode(c, b1, need, &w) == 0 && w == need,
          "encode 128"); OK();
    CHECK(dna_tm_commit_encode(c, b1, need - 1, NULL) == -1,
          "encode 128 ignored a short cap"); OK();

    dna_tm_commit_t *d = NULL;
    CHECK(dna_tm_commit_decode(b1, need, &d) == 0, "decode 128"); OK();
    CHECK(d->n == 128 && d->height == 100000 && d->round == 3,
          "decoded 128 header"); OK();
    CHECK(dna_tm_commit_encode(d, b2, need, NULL) == 0 &&
          memcmp(b1, b2, need) == 0, "128 round-trip not byte-identical");
    OK();
    /* Every entry survived at its own index. */
    CHECK(d->entries[127].timestamp_ms == 1800000000000ULL + 127 &&
          d->entries[127].sig[0] == 127, "entry 127 lost"); OK();
    dna_tm_commit_free(&d);

    /* One byte too many at the maximum still rejects. */
    uint8_t *bt = malloc(need + 1);
    CHECK(bt != NULL, "alloc trailing");
    memcpy(bt, b1, need);
    bt[need] = 0;
    CHECK(dna_tm_commit_decode(bt, need + 1, &d) == -1,
          "trailing byte at CERT_MAX"); OK();

    /* All ABSENT at N = 128: the smallest 128-entry certificate. */
    for (size_t i = 0; i < (size_t)DNA_MAX_ACTIVE_VALIDATORS; i++) {
        c->entries[i].flag = DNA_TM_COMMIT_FLAG_ABSENT;
        c->entries[i].timestamp_ms = 0;
    }
    CHECK(dna_tm_commit_encoded_len(c) == (size_t)T_HDR + 128u * 9u,
          "N=128 all-ABSENT length"); OK();

    /* The hash bound follows CERT_MAX, not the buffer handed in. */
    uint8_t h[64];
    CHECK(dna_tm_commit_hash(b1, need, h) == 0, "hash at CERT_MAX"); OK();
    CHECK(dna_tm_commit_hash(b1, need + 1, h) == -1,
          "hash accepted a length above CERT_MAX"); OK();
    CHECK(dna_tm_commit_hash(b1, T_HDR - 1, h) == -1,
          "hash accepted a length below the header"); OK();
    CHECK(dna_tm_commit_hash(NULL, need, h) == -1, "hash(NULL)"); OK();
    CHECK(dna_tm_commit_hash(b1, need, NULL) == -1, "hash(NULL out)"); OK();

    free(bt); free(b1); free(b2);
    dna_tm_commit_free(&c);
    return 0;
}

int main(void) {
    if (test_bounds() != 0) return 1;
    if (test_empty() != 0) return 1;
    if (test_decode_strict() != 0) return 1;
    if (test_median() != 0) return 1;
    if (test_real_keys() != 0) return 1;
    if (test_max_size() != 0) return 1;
    printf("test_tm_commit: %d checks OK\n", g_checks);
    return 0;
}
