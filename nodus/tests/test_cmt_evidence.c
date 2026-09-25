/**
 * Nodus — cometbft @709fd12b C port, wave R1-D: `types/evidence.go`
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a duplicate-vote evidence hashes to the bytes the reference's
 * construction produces, and that it is refused wherever the reference
 * refuses it. If this file failed, one of these would be false:
 *   · `DuplicateVoteEvidence.Bytes()` (evidence.go:95-103) is the marshal
 *     of the BARE message — 542 bytes for the fixture — and NOT of the
 *     `Evidence` oneof wrapper, which is 545 bytes and a different string;
 *   · `Hash()` (:106-108) is a FLAT SHA3-512 of those bare bytes, while
 *     `EvidenceList.Hash()` (:450-461) is the MERKLE root over them — the
 *     one-item root is `leafHash(bytes)` and is NOT the item's flat hash,
 *     which is the whole point of the 0x00 leaf separator;
 *   · an EMPTY evidence list hashes to H(""), not to 64 zero bytes;
 *   · `EvidenceData.Hash` (block.go:1380-1386) returns byte-for-byte what
 *     `cmt_evidence_list_hash` returns for the same items — the delegation
 *     wave R1-D introduced changed no bytes;
 *   · `ValidateBasic` (:126-145) refuses a missing vote, a malformed vote,
 *     a pair in the WRONG order and a pair with EQUAL BlockIDs, which
 *     `strings.Compare(...) >= 0` refuses together;
 *   · `DuplicateVoteEvidenceFromProto` (:162-200) refuses an item whose
 *     vote is malformed, and `EvidenceFromProto` (:527-540) refuses an
 *     unrecognised branch;
 *   · `Has` (:472-479) finds an item that is in the list and does not find
 *     one that is not.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no randomness — every byte in the fixtures is a
 * fixed pattern. Safe under `ctest -j`. Nothing is malloc'd by the test
 * itself; `cmt_dve_hash` and `cmt_evidence_list_hash` allocate internally
 * and free on every path.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The vectors come from shared/dnac/tests/cmt_evidence_oracle.py,
 *     which computes them from the pinned Go source and the K-1 rev 2 wire
 *     rules — NOT from cometbft's own test vectors, which do not exist for
 *     a 64-byte hash and a 4627-byte signature. A green proves that two
 *     independent implementations of the same READING agree; only reading
 *     evidence.go establishes that the reading is right.
 *  2. No real signature is verified here. The fixture's `signature` fields
 *     are 64-byte patterns that satisfy ValidateBasic's length rule and
 *     nothing more; `ValidateBasic` does not check signatures and neither
 *     does this file. Signature verification is test_cmt_validation.c's
 *     subject.
 *  3. `LightClientAttackEvidence` is never exercised, because it is not
 *     ported (scope rule). A green says nothing about branch 2 beyond the
 *     one assertion that an item with no branch set is REFUSED.
 *  4. The `cmt_ev_error_t` overflow value has no producer in this wave, so
 *     the test only pins its constructor's field assignment. That it is
 *     never CONSTRUCTED where the reference constructs it is not something
 *     this file can notice.
 *
 * @file test_cmt_evidence.c
 */

#include "dnac/cmt_evidence.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_pb.h"

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

/* ══ oracle vectors — shared/dnac/tests/cmt_evidence_oracle.py ════════ */

#define V_DVE1_BYTES_LEN 542
static const char V_DVE1_BYTES_SHA3[] =
    "09b852c6b782dd5a046f692da636ffaf98a4900a2476370b95fc920f81c29717"
    "ac37a063f99d80edcf034bcef0caff75689f22ff5e9e4616baec79a1e2678ba9";
#define V_DVE2_BYTES_LEN 538
static const char V_DVE2_BYTES_SHA3[] =
    "c2b36012f1aea969ae692876b1a2baf7980c159e512dffbf8ae2368cea63af1e"
    "81a4553316339df3b935d65e2e61a7df4dfb598a36b50d2fc197966e11ea7fa1";
#define V_DVE1_WRAPPED_LEN 545

/* evidence.go:106-108 — FLAT SHA3-512 of Bytes(). */
static const uint8_t V_DVE1_HASH[64] = {
    0x09, 0xb8, 0x52, 0xc6, 0xb7, 0x82, 0xdd, 0x5a, 0x04, 0x6f, 0x69, 0x2d,
    0xa6, 0x36, 0xff, 0xaf, 0x98, 0xa4, 0x90, 0x0a, 0x24, 0x76, 0x37, 0x0b,
    0x95, 0xfc, 0x92, 0x0f, 0x81, 0xc2, 0x97, 0x17, 0xac, 0x37, 0xa0, 0x63,
    0xf9, 0x9d, 0x80, 0xed, 0xcf, 0x03, 0x4b, 0xce, 0xf0, 0xca, 0xff, 0x75,
    0x68, 0x9f, 0x22, 0xff, 0x5e, 0x9e, 0x46, 0x16, 0xba, 0xec, 0x79, 0xa1,
    0xe2, 0x67, 0x8b, 0xa9,
};
static const uint8_t V_DVE2_HASH[64] = {
    0xc2, 0xb3, 0x60, 0x12, 0xf1, 0xae, 0xa9, 0x69, 0xae, 0x69, 0x28, 0x76,
    0xb1, 0xa2, 0xba, 0xf7, 0x98, 0x0c, 0x15, 0x9e, 0x51, 0x2d, 0xff, 0xbf,
    0x8a, 0xe2, 0x36, 0x8c, 0xea, 0x63, 0xaf, 0x1e, 0x81, 0xa4, 0x55, 0x33,
    0x16, 0x33, 0x9d, 0xf3, 0xb9, 0x35, 0xd6, 0x5e, 0x2e, 0x61, 0xa7, 0xdf,
    0x4d, 0xfb, 0x59, 0x8a, 0x36, 0xb5, 0x0d, 0x2f, 0xc1, 0x97, 0x96, 0x6e,
    0x11, 0xea, 0x7f, 0xa1,
};

/* evidence.go:450-461 — the MERKLE roots. */
static const uint8_t V_EVLIST0_ROOT[64] = {   /* H("") */
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc,
    0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
    0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a,
    0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
    0x28, 0x1d, 0xcd, 0x26,
};
static const uint8_t V_EVLIST1_ROOT[64] = {   /* leafHash(bytes) */
    0x6b, 0xa5, 0x91, 0xd8, 0x0e, 0xb6, 0xc4, 0x22, 0x8c, 0x3c, 0xbf, 0x4e,
    0x6c, 0xac, 0x39, 0xc6, 0xc2, 0x4c, 0xcf, 0x0a, 0xc7, 0x23, 0xdc, 0xa2,
    0x4e, 0x00, 0xbd, 0xea, 0xfc, 0x9d, 0xec, 0xb7, 0x98, 0x02, 0x6e, 0xfb,
    0x86, 0xf2, 0x4d, 0x9d, 0x44, 0x5e, 0x49, 0x56, 0x5d, 0x7d, 0x98, 0x41,
    0xed, 0x35, 0xcd, 0x63, 0x8c, 0x8c, 0xb9, 0xc7, 0x48, 0x50, 0x08, 0x60,
    0xec, 0x19, 0x4b, 0xfb,
};
static const uint8_t V_EVLIST2_ROOT[64] = {   /* inner(leaf(a), leaf(b)) */
    0xa6, 0x7c, 0xa2, 0x75, 0xda, 0x2b, 0xa4, 0x2d, 0x6e, 0xbf, 0xdd, 0xf0,
    0xab, 0xb7, 0xce, 0x79, 0x88, 0x27, 0x13, 0x54, 0x80, 0x89, 0x5d, 0xeb,
    0x90, 0xd4, 0x2b, 0x48, 0x27, 0xd2, 0x77, 0x26, 0x11, 0x76, 0x52, 0x30,
    0xd3, 0x3c, 0x65, 0xa7, 0xc9, 0xe9, 0x66, 0x3a, 0x86, 0x1a, 0x71, 0xb5,
    0x36, 0x6b, 0xc9, 0x00, 0xaf, 0x24, 0xf5, 0x70, 0x9c, 0xfd, 0x5a, 0x4f,
    0x13, 0xf6, 0x34, 0x47,
};

/* ══ helpers ══════════════════════════════════════════════════════════ */

static void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i]     = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* Compare an encoding against (length, SHA3-512 of the encoding). */
static int is_digest(const char *what, const uint8_t *got, size_t got_len,
                     size_t want_len, const char *want_sha3)
{
    uint8_t h[64];
    char    hex[129];

    if (got_len != want_len) {
        fprintf(stderr, "%s: length %zu, want %zu\n", what, got_len,
                want_len);
        return 0;
    }
    if (qgp_sha3_512(got, got_len, h) != 0) {
        fprintf(stderr, "%s: hash backend failed\n", what);
        return 0;
    }
    to_hex(h, sizeof(h), hex);
    if (strcmp(hex, want_sha3) != 0) {
        fprintf(stderr, "%s: digest mismatch\n  got  %s\n  want %s\n",
                what, hex, want_sha3);
        return 0;
    }
    return 1;
}

/* The oracle's `pat(n, seed)`: byte i = (seed + 7*i) mod 256. */
static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

/* ══ the fixture — identical to cmt_evidence_oracle.py's ══════════════ */

static void make_block_id(cmt_block_id_t *bid, uint8_t hash_seed,
                          uint8_t psh_seed)
{
    cmt_pb_block_id_init(bid);
    pat(bid->hash, 64, hash_seed);
    bid->hash_len                = 64u;
    bid->part_set_header.total   = 7u;
    pat(bid->part_set_header.hash, 64, psh_seed);
    bid->part_set_header.hash_len = 64u;
}

/* A PRECOMMIT with a COMPLETE BlockID and no extension — the shape that
 * passes Vote.ValidateBasic (vote.go:275-353); see the oracle. */
static void make_vote(cmt_vote_t *v, int64_t height, int32_t round,
                      uint8_t bid_hash_seed, uint8_t bid_psh_seed,
                      uint8_t sig_seed)
{
    cmt_pb_vote_init(v);
    v->type   = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    v->height = height;
    v->round  = round;
    make_block_id(&v->block_id, bid_hash_seed, bid_psh_seed);
    v->timestamp.seconds = 1700000000;
    v->timestamp.nanos   = 123456789;
    pat(v->validator_address, 32, 0x30);
    v->validator_address_len = 32u;
    v->validator_index       = 1;
    pat(v->signature, 64, sig_seed);
    v->signature_len = 64u;
}

/* DVE_1 of the oracle: votes at height 9 round 3, BlockIDs 0x10 and 0x90
 * so that Key(A) < Key(B). */
static void make_dve1(cmt_duplicate_vote_evidence_t *d)
{
    cmt_pb_duplicate_vote_evidence_init(d);
    make_vote(&d->vote_a, 9, 3, 0x10, 0x20, 0x40);
    make_vote(&d->vote_b, 9, 3, 0x90, 0x21, 0x41);
    d->has_vote_a         = true;
    d->has_vote_b         = true;
    d->total_voting_power = 150;
    d->validator_power    = 100;
    d->timestamp.seconds  = 1700000001;
    d->timestamp.nanos    = 500;
}

/* DVE_2 of the oracle: the same shape at height 11, round 0. */
static void make_dve2(cmt_duplicate_vote_evidence_t *d)
{
    cmt_pb_duplicate_vote_evidence_init(d);
    make_vote(&d->vote_a, 11, 0, 0x10, 0x20, 0x40);
    make_vote(&d->vote_b, 11, 0, 0x90, 0x21, 0x41);
    d->has_vote_a         = true;
    d->has_vote_b         = true;
    d->total_voting_power = 150;
    d->validator_power    = 100;
    d->timestamp.seconds  = 1700000001;
    d->timestamp.nanos    = 500;
}

/* ══ 1. Bytes / Hash — and the two strings that must NOT be confused ══ */

static int t_bytes_and_hash(void)
{
    cmt_duplicate_vote_evidence_t d1;
    cmt_duplicate_vote_evidence_t d2;
    cmt_pb_evidence_t             wrapped;
    uint8_t                      *buf;
    uint8_t                       h[64];
    size_t                        bound;
    size_t                        len;

    make_dve1(&d1);
    make_dve2(&d2);

    bound = cmt_dve_upper_bound(&d1);
    CHECK(bound >= V_DVE1_BYTES_LEN, "the bound must cover the encoding");
    OK();
    buf = (uint8_t *)malloc(bound);
    CHECK(buf != NULL, "malloc"); OK();

    CHECK(cmt_dve_bytes(&d1, buf, bound, &len) == CMT_OK, "Bytes()"); OK();
    CHECK(is_digest("DVE1 Bytes", buf, len, V_DVE1_BYTES_LEN,
                    V_DVE1_BYTES_SHA3),
          "Bytes() is the BARE DuplicateVoteEvidence marshal"); OK();

    /* The WRAPPER is a different, longer string. Hashing it instead would
     * be the single easiest way to get the header's EvidenceHash wrong. */
    CHECK(cmt_evidence_to_proto(&d1, &wrapped) == CMT_OK, "EvidenceToProto");
    OK();
    {
        uint8_t *wbuf = (uint8_t *)malloc(bound + 32u);
        size_t   wlen;

        CHECK(wbuf != NULL, "malloc"); OK();
        CHECK(cmt_pb_evidence_marshal(&wrapped, wbuf, bound + 32u, &wlen) ==
              CMT_OK, "marshal the wrapper"); OK();
        CHECK(wlen == V_DVE1_WRAPPED_LEN,
              "the wrapper is 545 bytes where the bare message is 542");
        OK();
        CHECK(wlen != len && memcmp(wbuf, buf, len) != 0,
              "the wrapper is NOT the hashed preimage"); OK();
        free(wbuf);
    }

    /* Hash() is FLAT — the plain digest of those bytes. */
    CHECK(cmt_dve_hash(&d1, h) == CMT_OK, "Hash()"); OK();
    CHECK(memcmp(h, V_DVE1_HASH, 64) == 0,
          "Hash() is a flat SHA3-512 of Bytes()"); OK();
    {
        uint8_t direct[64];
        CHECK(qgp_sha3_512(buf, len, direct) == 0, "hash"); OK();
        CHECK(memcmp(h, direct, 64) == 0,
              "and it is exactly that, computed here without the library");
        OK();
    }

    CHECK(cmt_dve_bytes(&d2, buf, bound, &len) == CMT_OK, "Bytes() 2"); OK();
    CHECK(is_digest("DVE2 Bytes", buf, len, V_DVE2_BYTES_LEN,
                    V_DVE2_BYTES_SHA3), "the second fixture's bytes"); OK();
    CHECK(cmt_dve_hash(&d2, h) == CMT_OK, "Hash() 2"); OK();
    CHECK(memcmp(h, V_DVE2_HASH, 64) == 0, "the second fixture's hash");
    OK();
    CHECK(memcmp(V_DVE1_HASH, V_DVE2_HASH, 64) != 0,
          "the two fixtures are distinct"); OK();

    /* A buffer one byte short REFUSES; it does not truncate.
     *
     * The short buffer is a SEPARATE, EXACT-SIZE allocation rather than a
     * short `cap` over the big one: passing a small cap over a large
     * buffer would leave an overrun invisible to the sanitiser, which is
     * the whole thing this negative is meant to catch. */
    {
        uint8_t *tight = (uint8_t *)malloc((size_t)V_DVE1_BYTES_LEN - 1u);

        CHECK(tight != NULL, "malloc"); OK();
        CHECK(cmt_dve_bytes(&d1, tight, (size_t)V_DVE1_BYTES_LEN - 1u,
                            &len) != CMT_OK,
              "a buffer one byte short is refused, not overrun"); OK();
        free(tight);
    }

    free(buf);
    return 0;
}

/* ══ 2. Height / Time ═════════════════════════════════════════════════ */

static int t_height_time(void)
{
    cmt_duplicate_vote_evidence_t d;
    cmt_time_t                    t;
    int64_t                       hgt;

    make_dve1(&d);
    CHECK(cmt_dve_height(&d, &hgt) == CMT_OK && hgt == 9,
          "Height() is VoteA.Height"); OK();
    CHECK(cmt_dve_time(&d, &t) == CMT_OK &&
          t.seconds == 1700000001 && t.nanos == 500,
          "Time() is the EVIDENCE's timestamp, not either vote's"); OK();
    CHECK(t.seconds != d.vote_a.timestamp.seconds,
          "and the two are genuinely different values here"); OK();

    /* The reference would nil-dereference on an absent VoteA; this port
     * refuses instead (deviation register R1B-10). */
    d.has_vote_a = false;
    CHECK(cmt_dve_height(&d, &hgt) == CMT_FAULT,
          "Height() on an absent VoteA is a FAULT, not a read"); OK();
    CHECK(cmt_dve_time(&d, &t) == CMT_OK,
          "Time() does not touch the votes and still answers"); OK();

    CHECK(cmt_dve_height(NULL, &hgt) == CMT_FAULT, "NULL"); OK();
    CHECK(cmt_dve_time(NULL, &t) == CMT_FAULT, "NULL"); OK();
    return 0;
}

/* ══ 3. ValidateBasic — the order rule above all ══════════════════════ */

static int t_validate_basic(void)
{
    cmt_duplicate_vote_evidence_t d;

    make_dve1(&d);
    CHECK(cmt_dve_validate_basic(&d) == CMT_OK,
          "the fixture is well-formed"); OK();

    /* :131-133 — one or both votes missing. */
    make_dve1(&d);
    d.has_vote_a = false;
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT, "VoteA missing"); OK();
    make_dve1(&d);
    d.has_vote_b = false;
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT, "VoteB missing"); OK();
    make_dve1(&d);
    d.has_vote_a = false;
    d.has_vote_b = false;
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT, "both missing"); OK();

    /* :134-139 — a malformed vote, refused through Vote.ValidateBasic.
     * Height 0 is refused by vote.go:283-285. */
    make_dve1(&d);
    d.vote_a.height = 0;
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT, "invalid VoteA"); OK();
    make_dve1(&d);
    d.vote_b.validator_address_len = 31u;
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT,
          "invalid VoteB — a 31-byte address"); OK();

    /* :140-143 — THE ORDER RULE. `strings.Compare(KeyA, KeyB) >= 0`
     * refuses, so both the reversed pair and an equal pair fail. */
    {
        cmt_duplicate_vote_evidence_t rev;

        cmt_pb_duplicate_vote_evidence_init(&rev);
        make_vote(&rev.vote_a, 9, 3, 0x90, 0x21, 0x41);   /* the LARGER  */
        make_vote(&rev.vote_b, 9, 3, 0x10, 0x20, 0x40);   /* the SMALLER */
        rev.has_vote_a = true;
        rev.has_vote_b = true;
        CHECK(cmt_dve_validate_basic(&rev) == CMT_REJECT,
              "the reversed pair is refused — evidence is canonical"); OK();
    }
    make_dve1(&d);
    d.vote_b.block_id = d.vote_a.block_id;   /* the SAME block */
    CHECK(cmt_dve_validate_basic(&d) == CMT_REJECT,
          "two votes for the SAME BlockID are not a conflict at all"); OK();

    /* The order is decided by Key(), which is hash ‖ psh-marshal — so a
     * pair whose hashes are equal is still ordered by the part set
     * header. Here A keeps psh seed 0x20 and B 0x21, and the marshalled
     * headers differ, so the pair is still strictly ordered. */
    make_dve1(&d);
    pat(d.vote_b.block_id.hash, 64, 0x10);   /* equal HASHES */
    CHECK(cmt_dve_validate_basic(&d) == CMT_OK,
          "equal hashes are still ordered by the PartSetHeader"); OK();

    CHECK(cmt_dve_validate_basic(NULL) == CMT_FAULT, "NULL"); OK();
    return 0;
}

/* ══ 4. the proto round trip ══════════════════════════════════════════ */

static int t_proto(void)
{
    cmt_duplicate_vote_evidence_t d;
    cmt_duplicate_vote_evidence_t back;
    cmt_pb_evidence_t             ev;

    make_dve1(&d);

    /* ToProto is the identity; FromProto validates.
     *
     * `back` is zeroed first so the memcmp below compares only fields: a
     * struct assignment is not required to copy PADDING, and `d` is
     * memset-clean from its _init while a stack `back` would not be. */
    memset(&back, 0, sizeof(back));
    CHECK(cmt_dve_to_proto(&d, &back) == CMT_OK, "ToProto"); OK();
    CHECK(memcmp(&back, &d, sizeof(d)) == 0, "ToProto is the identity");
    OK();
    CHECK(cmt_dve_from_proto(&d, &back) == CMT_OK, "FromProto"); OK();
    CHECK(back.total_voting_power == 150 && back.validator_power == 100,
          "and it carries the two power fields through"); OK();

    /* :174 / :186 — a malformed vote is refused by FromProto, BEFORE the
     * whole-object ValidateBasic at :199 would have seen it. */
    make_dve1(&d);
    d.vote_a.round = -1;
    CHECK(cmt_dve_from_proto(&d, &back) == CMT_REJECT,
          "FromProto refuses a vote with a negative round"); OK();

    /* :199 — the whole is ValidateBasic'd, so a wrongly ordered pair whose
     * votes are individually fine is still refused. */
    {
        cmt_duplicate_vote_evidence_t rev;

        cmt_pb_duplicate_vote_evidence_init(&rev);
        make_vote(&rev.vote_a, 9, 3, 0x90, 0x21, 0x41);
        make_vote(&rev.vote_b, 9, 3, 0x10, 0x20, 0x40);
        rev.has_vote_a = true;
        rev.has_vote_b = true;
        CHECK(cmt_dve_from_proto(&rev, &back) == CMT_REJECT,
              "FromProto ends in ValidateBasic (:199)"); OK();
    }

    /* The wrapper: branch 1 decodes, an unset branch is "not recognized". */
    make_dve1(&d);
    CHECK(cmt_evidence_to_proto(&d, &ev) == CMT_OK, "EvidenceToProto"); OK();
    CHECK(ev.has_duplicate_vote_evidence, "branch 1 is set"); OK();
    CHECK(cmt_evidence_from_proto(&ev, &back) == CMT_OK, "EvidenceFromProto");
    OK();
    CHECK(back.vote_a.height == 9, "and it round-trips"); OK();

    memset(&ev, 0, sizeof(ev));
    CHECK(!ev.has_duplicate_vote_evidence, "no branch set"); OK();
    CHECK(cmt_evidence_from_proto(&ev, &back) == CMT_REJECT,
          "an unrecognised branch is REFUSED, never skipped"); OK();

    CHECK(cmt_evidence_from_proto(NULL, &back) == CMT_FAULT, "NULL"); OK();
    CHECK(cmt_evidence_to_proto(NULL, &ev) == CMT_FAULT, "NULL"); OK();
    return 0;
}

/* ══ 5. EvidenceList.Hash, and the block's delegation to it ═══════════ */

static int t_list_hash(void)
{
    cmt_pb_evidence_t   items[2];
    cmt_evidence_data_t data;
    uint8_t             root[64];
    uint8_t             via_block[64];
    cmt_duplicate_vote_evidence_t d1;
    cmt_duplicate_vote_evidence_t d2;

    make_dve1(&d1);
    make_dve2(&d2);
    if (cmt_evidence_to_proto(&d1, &items[0]) != CMT_OK ||
        cmt_evidence_to_proto(&d2, &items[1]) != CMT_OK) {
        fprintf(stderr, "fixture build failed\n");
        return 1;
    }

    /* 0 items: the EMPTY TREE's root, not zeroes. */
    CHECK(cmt_evidence_list_hash(NULL, 0u, root) == CMT_OK, "0 items"); OK();
    CHECK(memcmp(root, V_EVLIST0_ROOT, 64) == 0,
          "an empty list hashes to H(\"\")"); OK();
    {
        uint8_t zeroes[64];
        memset(zeroes, 0, sizeof(zeroes));
        CHECK(memcmp(root, zeroes, 64) != 0,
              "and H(\"\") is not 64 zero bytes"); OK();
    }

    /* 1 item: leafHash(bytes) — and NOT the item's own flat Hash(). */
    CHECK(cmt_evidence_list_hash(items, 1u, root) == CMT_OK, "1 item"); OK();
    CHECK(memcmp(root, V_EVLIST1_ROOT, 64) == 0,
          "a one-item root is leafHash(bytes)"); OK();
    CHECK(memcmp(root, V_DVE1_HASH, 64) != 0,
          "the Merkle root of one item is NOT that item's flat Hash()");
    OK();

    /* 2 items. */
    CHECK(cmt_evidence_list_hash(items, 2u, root) == CMT_OK, "2 items"); OK();
    CHECK(memcmp(root, V_EVLIST2_ROOT, 64) == 0,
          "a two-item root is innerHash(leaf(a), leaf(b))"); OK();

    /* THE DELEGATION: block.go:1380-1386 must return exactly these bytes.
     * This is the second reading of the vectors test_cmt_block.c pins. */
    memset(&data, 0, sizeof(data));
    data.evidence     = items;
    data.evidence_cap = 2u;
    data.evidence_len = 2u;
    CHECK(cmt_evidence_data_hash(&data, via_block) == CMT_OK,
          "EvidenceData.Hash"); OK();
    CHECK(memcmp(via_block, root, 64) == 0,
          "EvidenceData.Hash is EvidenceList.Hash, byte for byte"); OK();

    data.evidence_len = 0u;
    CHECK(cmt_evidence_data_hash(&data, via_block) == CMT_OK, "empty data");
    OK();
    CHECK(memcmp(via_block, V_EVLIST0_ROOT, 64) == 0,
          "an empty EvidenceData hashes to H(\"\") too"); OK();
    CHECK(cmt_evidence_data_hash(NULL, via_block) == CMT_OK &&
          memcmp(via_block, V_EVLIST0_ROOT, 64) == 0,
          "and so does a NULL EvidenceData (block.go:1382-1384)"); OK();

    /* An item with no branch set cannot be hashed — refused, not skipped. */
    memset(&items[1], 0, sizeof(items[1]));
    CHECK(cmt_evidence_list_hash(items, 2u, root) == CMT_REJECT,
          "an unrecognised item REFUSES the whole root"); OK();

    CHECK(cmt_evidence_list_hash(NULL, 0u, NULL) == CMT_FAULT, "NULL out");
    OK();
    CHECK(cmt_evidence_list_hash(NULL, 1u, root) == CMT_FAULT,
          "a NULL list with a non-zero count is a FAULT"); OK();
    return 0;
}

/* ══ 6. Has ═══════════════════════════════════════════════════════════ */

static int t_has(void)
{
    cmt_pb_evidence_t             items[2];
    cmt_pb_evidence_t             needle;
    cmt_duplicate_vote_evidence_t d1;
    cmt_duplicate_vote_evidence_t d2;
    cmt_duplicate_vote_evidence_t d3;
    bool                          found;

    make_dve1(&d1);
    make_dve2(&d2);
    make_dve1(&d3);
    d3.vote_a.height = 21;      /* a third, absent item */
    d3.vote_b.height = 21;

    if (cmt_evidence_to_proto(&d1, &items[0]) != CMT_OK ||
        cmt_evidence_to_proto(&d2, &items[1]) != CMT_OK) {
        fprintf(stderr, "fixture build failed\n");
        return 1;
    }

    CHECK(cmt_evidence_to_proto(&d1, &needle) == CMT_OK, "needle 1"); OK();
    CHECK(cmt_evidence_list_has(items, 2u, &needle, &found) == CMT_OK &&
          found, "Has finds the first item"); OK();

    CHECK(cmt_evidence_to_proto(&d2, &needle) == CMT_OK, "needle 2"); OK();
    CHECK(cmt_evidence_list_has(items, 2u, &needle, &found) == CMT_OK &&
          found, "Has finds the second item"); OK();

    CHECK(cmt_evidence_to_proto(&d3, &needle) == CMT_OK, "needle 3"); OK();
    CHECK(cmt_evidence_list_has(items, 2u, &needle, &found) == CMT_OK &&
          !found, "Has does not find an item that is not there"); OK();

    CHECK(cmt_evidence_list_has(items, 0u, &needle, &found) == CMT_OK &&
          !found, "nothing is in an empty list"); OK();

    CHECK(cmt_evidence_list_has(items, 2u, NULL, &found) == CMT_FAULT,
          "NULL needle"); OK();
    CHECK(cmt_evidence_list_has(items, 2u, &needle, NULL) == CMT_FAULT,
          "NULL out"); OK();
    return 0;
}

/* ══ 7. the overflow error value ══════════════════════════════════════ */

static int t_error(void)
{
    cmt_ev_error_t e;

    CHECK(cmt_new_err_evidence_overflow(1000, 1500, &e) == CMT_OK,
          "NewErrEvidenceOverflow"); OK();
    CHECK(e.code == CMT_EV_ERR_OVERFLOW && e.max == 1000 && e.got == 1500,
          "it carries max and got, in that order"); OK();
    /* The reference's constructor does NOT check that got > max, and
     * neither does this one — faithfulness, not an omission. */
    CHECK(cmt_new_err_evidence_overflow(9, 1, &e) == CMT_OK &&
          e.max == 9 && e.got == 1,
          "and it does not second-guess its arguments"); OK();
    CHECK(cmt_new_err_evidence_overflow(0, 0, NULL) == CMT_FAULT, "NULL");
    OK();
    return 0;
}

int main(void)
{
    if (t_bytes_and_hash() != 0) return 1;
    if (t_height_time() != 0) return 1;
    if (t_validate_basic() != 0) return 1;
    if (t_proto() != 0) return 1;
    if (t_list_hash() != 0) return 1;
    if (t_has() != 0) return 1;
    if (t_error() != 0) return 1;
    printf("test_cmt_evidence: %d checks OK\n", g_checks);
    return 0;
}
