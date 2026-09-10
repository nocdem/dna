/**
 * Nodus — cometbft @709fd12b C port, wave R1-B: `types/part_set.go`
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a block can be cut into parts and put back together byte for byte,
 * and that a part set refuses everything the reference refuses. If this
 * file failed, one of these would be false:
 *   · splitting a 200 000-byte buffer at BlockPartSizeBytes gives FOUR
 *     parts of 65536/65536/65536/3392 bytes and the Merkle root an
 *     INDEPENDENT python oracle computed — that root is a PartSetHeader
 *     field, so it is inside BlockID and inside every vote signature;
 *   · every part's inclusion proof verifies against that root, and the
 *     first and last parts' aunt lists are the oracle's byte for byte;
 *   · AddPart REFUSES a part whose index is at or above `total`, REFUSES
 *     a part whose proof does not match the set, and reports a part it
 *     already holds as "not added" WITHOUT an error — the reference's
 *     three distinct outcomes;
 *   · IsComplete flips exactly at the last part, never before;
 *   · the reader reassembles the ORIGINAL 200 000 bytes, crossing part
 *     boundaries inside a single read;
 *   · ValidateBasic rejects an over-long part, a non-final part that is
 *     not exactly one part wide, and an index that disagrees with the
 *     proof;
 *   · a zero-length part set has total 0, is complete, and hashes to
 *     H(""), while a one-byte part set is a single leaf with no aunts.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock, no RNG. Safe under `ctest -j`. It
 * allocates two 200 000-byte buffers on the heap and frees them; the
 * four `cmt_part_t` slots (~29 KB) are a local array.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The root and the aunt lists come from shared/dnac/tests/
 *     cmt_block_oracle.py, which computes them from the pinned Go source
 *     and the K-1 rules with python3's own SHA3-512 — an implementation
 *     independent of qgp_sha3.c. It is NOT a vector published by
 *     cometbft: no such vector exists for SHA3-512 parts. It proves that
 *     two independent implementations of the SAME READING agree; only
 *     reading part_set.go against this port can establish that the
 *     reading is right.
 *  2. The payload is byte i = (0x11 + 7*i) mod 251. The modulus is 251
 *     and not 256 ON PURPOSE: a period of 256 divides the 65 536-byte
 *     part size, every full part would be identical, and a proof for the
 *     wrong part would then verify. If someone "simplifies" this to 256,
 *     the wrong-proof assertions below stop proving anything while still
 *     passing.
 *  3. Nothing here exercises a part set built from a REAL marshalled
 *     block; that is test_cmt_block.c's MakePartSet case. A green here
 *     says nothing about the block encoder.
 *  4. The part payloads are NOT copied into the part set (see
 *     cmt_part_set.h). This file keeps its buffers alive for the whole
 *     run, so it cannot catch a caller that does not.
 *
 * @file test_cmt_part_set.c
 */

#include "dnac/cmt_part_set.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_pb.h"

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

/* ══ oracle vectors — shared/dnac/tests/cmt_block_oracle.py ═══════════ */

#define V_PARTSET_DATA_LEN  200000
#define V_PARTSET_PART_SIZE 65536
#define V_PARTSET_TOTAL     4

static const uint8_t V_PARTSET_ROOT[64] = {
    0x5e, 0x22, 0x89, 0xe9, 0x96, 0xda, 0x25, 0x89, 0xc0, 0xcd, 0x60, 0xe6,
    0x4e, 0xc3, 0xc2, 0x1e, 0x17, 0x16, 0x52, 0x50, 0xc7, 0xa1, 0xac, 0xf6,
    0x95, 0xf1, 0x2a, 0x37, 0x82, 0xc2, 0x9d, 0x78, 0xfd, 0x53, 0x95, 0xe1,
    0x9c, 0x40, 0x62, 0x2e, 0x13, 0x36, 0xe9, 0x5a, 0x30, 0x28, 0xd8, 0xae,
    0x7c, 0x63, 0x9e, 0x21, 0x37, 0x69, 0xf5, 0x88, 0x53, 0xf4, 0xb2, 0xee,
    0x5a, 0x46, 0xda, 0x67,
};
static const uint8_t V_PARTSET_LEAF0[64] = {
    0x83, 0x24, 0xc8, 0xf8, 0x11, 0x91, 0x02, 0x9b, 0x9e, 0x9e, 0xbc, 0xab,
    0x4c, 0xa5, 0x1a, 0x4b, 0xad, 0x1b, 0x66, 0xd5, 0x16, 0x94, 0xed, 0xf2,
    0xa4, 0x7d, 0xda, 0xf6, 0xb0, 0x88, 0x76, 0x28, 0x3e, 0xbd, 0x26, 0x3e,
    0x00, 0xc2, 0x3d, 0xd5, 0xc8, 0x39, 0xf5, 0x48, 0x56, 0x12, 0xfa, 0x7f,
    0x8c, 0x00, 0xc0, 0x0c, 0xf6, 0x35, 0xc1, 0xb3, 0x18, 0x7a, 0xcd, 0xf7,
    0x20, 0x95, 0x21, 0x7a,
};
static const uint8_t V_PARTSET_P0_AUNTS[128] = {
    0x6e, 0x20, 0x52, 0xd8, 0xa3, 0xd2, 0x86, 0xf5, 0xa2, 0xd6, 0x9a, 0x41,
    0x84, 0xea, 0x5a, 0x5c, 0xc2, 0xef, 0x00, 0x70, 0x5e, 0x00, 0x1a, 0x96,
    0x95, 0xcc, 0x66, 0xc8, 0xba, 0xc5, 0x65, 0x98, 0x75, 0x3e, 0xc7, 0xe4,
    0xc4, 0xbe, 0x19, 0x99, 0xa9, 0x31, 0xc0, 0x65, 0x75, 0xff, 0x04, 0xa2,
    0xef, 0xc0, 0xb9, 0xf3, 0x39, 0x7c, 0xac, 0xa5, 0x97, 0x68, 0x90, 0xa9,
    0x84, 0x4b, 0x02, 0x92, 0x0c, 0xdf, 0xfa, 0xb8, 0x02, 0x77, 0xa9, 0xdf,
    0xe5, 0xb7, 0x77, 0x10, 0xaf, 0xd1, 0x8f, 0xef, 0x27, 0x4e, 0x76, 0x2c,
    0x14, 0xb5, 0xcd, 0x3e, 0xec, 0xce, 0x3d, 0xcc, 0xdc, 0xf5, 0xd2, 0xb9,
    0xd9, 0x3d, 0x03, 0x6c, 0x18, 0x0b, 0x11, 0xbc, 0x57, 0xe7, 0x10, 0xdb,
    0x6e, 0x75, 0x16, 0x52, 0x57, 0x22, 0x3f, 0xc9, 0x7a, 0x5c, 0x0e, 0x5b,
    0xf7, 0xf9, 0x78, 0x20, 0xa3, 0x48, 0xda, 0x7f,
};
static const uint8_t V_PARTSET_P3_AUNTS[128] = {
    0x96, 0x74, 0x96, 0x4a, 0x43, 0xe1, 0x67, 0x48, 0x44, 0x74, 0x15, 0x83,
    0x78, 0xd3, 0xe7, 0x55, 0xe8, 0x56, 0x8e, 0xf5, 0x9f, 0x9f, 0xbf, 0xb4,
    0x54, 0x7b, 0x4a, 0x25, 0x73, 0xf0, 0xf3, 0x86, 0x0c, 0x26, 0x61, 0xe6,
    0x59, 0x88, 0xdc, 0xab, 0xa5, 0xa7, 0xed, 0xde, 0x47, 0x2e, 0x29, 0x19,
    0xc7, 0x2f, 0x1d, 0xdc, 0x4f, 0x76, 0x89, 0xb7, 0xd2, 0x19, 0xf5, 0xa2,
    0xbb, 0x09, 0x4c, 0xee, 0x82, 0x8b, 0xb1, 0x58, 0x45, 0x0f, 0x63, 0x19,
    0x09, 0xe5, 0xee, 0x9f, 0xfb, 0x53, 0x08, 0xcc, 0xd9, 0x11, 0x30, 0xe8,
    0xeb, 0xd8, 0x89, 0xbf, 0x6a, 0xf1, 0x89, 0xd6, 0xe6, 0xbb, 0x08, 0xa5,
    0xbe, 0xfe, 0x20, 0x82, 0x37, 0x19, 0xfd, 0x71, 0x82, 0x67, 0x73, 0xce,
    0xdd, 0x27, 0x0b, 0x20, 0xb2, 0xc6, 0x43, 0x6b, 0xcb, 0xec, 0x4f, 0xc3,
    0xd6, 0xc8, 0x94, 0x81, 0xc6, 0xb7, 0xce, 0xe5,
};
static const uint8_t V_PARTSET_ONE_ROOT[64] = {
    0x7a, 0x5a, 0x5f, 0x85, 0x7b, 0x65, 0x33, 0x9b, 0xfd, 0xfa, 0xcb, 0xa1,
    0xbb, 0xec, 0xf8, 0x20, 0x15, 0x2b, 0xd8, 0xdf, 0x55, 0xde, 0x16, 0x90,
    0x6e, 0x21, 0xda, 0x29, 0x08, 0xc1, 0x5c, 0x94, 0x58, 0x83, 0x0d, 0x5a,
    0x86, 0x31, 0x65, 0xdb, 0xde, 0x31, 0x24, 0xa5, 0x45, 0x7e, 0x43, 0x37,
    0x7a, 0x82, 0xac, 0x09, 0x64, 0x5d, 0xff, 0x35, 0x8a, 0x5e, 0x31, 0xb4,
    0xef, 0x78, 0x22, 0x4b,
};
static const uint8_t V_PARTSET_EMPTY_ROOT[64] = {   /* = SHA3-512("") */
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc,
    0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
    0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a,
    0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
    0x28, 0x1d, 0xcd, 0x26,
};

/* The oracle's part_payload(): byte i = (0x11 + 7*i) mod 251. See the
 * header's "HOW IT CAN LIE" note 2 before changing the modulus. */
static void fill_payload(uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)((0x11u + 7u * (unsigned)(i % 251u)) % 251u);
    }
}

/* ══ ValidateHash (validation.go:196-204) ═════════════════════════════ */

static int test_validate_hash(void)
{
    uint8_t h[64];

    memset(h, 0xAB, sizeof(h));
    CHECK(cmt_validate_hash(NULL, 0) == CMT_OK, "empty hash is allowed"); OK();
    CHECK(cmt_validate_hash(h, 64) == CMT_OK, "64 bytes is one digest"); OK();
    CHECK(cmt_validate_hash(h, 32) == CMT_REJECT,
          "32 bytes is the REFERENCE width, not ours"); OK();
    CHECK(cmt_validate_hash(h, 63) == CMT_REJECT, "63 bytes rejects"); OK();
    CHECK(cmt_validate_hash(h, 1) == CMT_REJECT, "1 byte rejects"); OK();
    return 0;
}

/* ══ PartSetHeader (part_set.go:116-174) ══════════════════════════════ */

static int test_part_set_header(void)
{
    cmt_part_set_header_t a, b;
    cmt_pb_part_set_header_t pb;

    cmt_pb_part_set_header_init(&a);
    CHECK(cmt_psh_is_zero(&a), "a fresh header is zero"); OK();
    CHECK(cmt_proto_part_set_header_is_zero(&a),
          "and so is the wire predicate"); OK();
    CHECK(cmt_psh_validate_basic(&a) == CMT_OK,
          "an EMPTY hash is allowed — a Proposal's POL BlockID has none");
    OK();

    a.total = 4;
    memset(a.hash, 0x11, 64);
    a.hash_len = 64;
    CHECK(!cmt_psh_is_zero(&a), "a populated header is not zero"); OK();
    CHECK(cmt_psh_validate_basic(&a) == CMT_OK, "64-byte hash validates");
    OK();

    a.hash_len = 32;
    CHECK(cmt_psh_validate_basic(&a) == CMT_REJECT,
          "a 32-byte hash is refused"); OK();
    a.hash_len = 64;

    b = a;
    CHECK(cmt_psh_equals(&a, &b), "identical headers are equal"); OK();
    b.total = 5;
    CHECK(!cmt_psh_equals(&a, &b), "a different total is not equal"); OK();
    b = a;
    b.hash[0] = 0x12;
    CHECK(!cmt_psh_equals(&a, &b), "a different hash is not equal"); OK();

    CHECK(cmt_psh_to_proto(&a, &pb) == CMT_OK, "to_proto"); OK();
    CHECK(pb.total == 4 && pb.hash_len == 64, "to_proto is the identity");
    OK();
    CHECK(cmt_psh_from_proto(&pb, &b) == CMT_OK, "from_proto"); OK();
    CHECK(cmt_psh_equals(&a, &b), "round trip"); OK();
    pb.hash_len = 31;
    CHECK(cmt_psh_from_proto(&pb, &b) == CMT_REJECT,
          "from_proto ends in ValidateBasic (part_set.go:167)"); OK();
    CHECK(cmt_psh_to_proto(NULL, &pb) == CMT_OK && pb.total == 0,
          "a NULL receiver yields the zero header"); OK();
    return 0;
}

/* ══ Part.ValidateBasic (part_set.go:45-60) ═══════════════════════════ */

static int test_part_validate_basic(void)
{
    static cmt_part_t p;
    static uint8_t    payload[CMT_BLOCK_PART_SIZE_BYTES + 1];

    memset(payload, 0x5A, sizeof(payload));
    cmt_pb_part_init(&p);
    p.index           = 0;
    p.bytes.data      = payload;
    p.bytes.len       = 100;
    p.proof.total     = 1;
    p.proof.index     = 0;
    p.proof.leaf_hash_len = 64;
    p.proof.aunts_len = 0;
    CHECK(cmt_part_validate_basic(&p) == CMT_OK,
          "a lone short part is valid — it is the LAST part"); OK();

    p.bytes.len = (size_t)CMT_BLOCK_PART_SIZE_BYTES + 1u;
    CHECK(cmt_part_validate_basic(&p) == CMT_REJECT,
          "ErrPartTooBig: a part above BlockPartSizeBytes"); OK();

    p.bytes.len   = 100;
    p.proof.total = 3;
    CHECK(cmt_part_validate_basic(&p) == CMT_REJECT,
          "ErrPartInvalidSize: a non-final part must be exactly one part");
    OK();
    p.bytes.len = (size_t)CMT_BLOCK_PART_SIZE_BYTES;
    CHECK(cmt_part_validate_basic(&p) == CMT_OK,
          "a full non-final part is valid"); OK();

    p.index = 1;
    CHECK(cmt_part_validate_basic(&p) == CMT_REJECT,
          "index must equal proof index (part_set.go:53-55)"); OK();
    p.index = 0;

    p.proof.leaf_hash_len = 32;
    CHECK(cmt_part_validate_basic(&p) == CMT_REJECT,
          "a short leaf hash fails Proof.ValidateBasic"); OK();
    p.proof.leaf_hash_len = 64;

    CHECK(cmt_part_validate_basic(NULL) == CMT_FAULT, "NULL is a fault");
    OK();
    return 0;
}

/* ══ NewPartSetFromData (part_set.go:194-222) ═════════════════════════ */

static int test_from_data(uint8_t *data, cmt_part_t *parts,
                          cmt_part_set_t *ps)
{
    cmt_part_set_header_t hdr;
    cmt_bit_array_t       ba;
    uint8_t               root[64];
    uint8_t               aunts[128];
    size_t                i;

    CHECK(cmt_new_part_set_from_data(data, V_PARTSET_DATA_LEN,
                                     V_PARTSET_PART_SIZE, parts,
                                     V_PARTSET_TOTAL, ps) == CMT_OK,
          "split a 200 000-byte buffer"); OK();
    CHECK(cmt_part_set_total(ps) == V_PARTSET_TOTAL, "four parts"); OK();
    CHECK(cmt_part_set_count(ps) == V_PARTSET_TOTAL, "all present"); OK();
    CHECK(cmt_part_set_byte_size(ps) == V_PARTSET_DATA_LEN,
          "byte size is the whole buffer"); OK();
    CHECK(cmt_part_set_is_complete(ps), "a set built from data is complete");
    OK();

    CHECK(parts[0].bytes.len == V_PARTSET_PART_SIZE, "part 0 is full"); OK();
    CHECK(parts[2].bytes.len == V_PARTSET_PART_SIZE, "part 2 is full"); OK();
    CHECK(parts[3].bytes.len == 3392u, "part 3 is the remainder"); OK();
    CHECK(parts[3].bytes.data == data + 3u * V_PARTSET_PART_SIZE,
          "the parts point INTO the caller's buffer"); OK();

    CHECK(cmt_part_set_hash(ps, root) == CMT_OK, "the root"); OK();
    CHECK(memcmp(root, V_PARTSET_ROOT, 64) == 0,
          "the root is the oracle's"); OK();
    CHECK(cmt_part_set_hashes_to(ps, V_PARTSET_ROOT, 64), "HashesTo"); OK();
    CHECK(!cmt_part_set_hashes_to(ps, V_PARTSET_ROOT, 32),
          "HashesTo refuses a short hash"); OK();
    CHECK(!cmt_part_set_hashes_to(NULL, V_PARTSET_ROOT, 64),
          "HashesTo(NULL) is false"); OK();

    CHECK(cmt_part_set_header(ps, &hdr) == CMT_OK, "Header()"); OK();
    CHECK(hdr.total == V_PARTSET_TOTAL && hdr.hash_len == 64 &&
          memcmp(hdr.hash, V_PARTSET_ROOT, 64) == 0,
          "the header carries the total and the root"); OK();
    CHECK(cmt_part_set_has_header(ps, &hdr), "HasHeader"); OK();
    hdr.total = 5;
    CHECK(!cmt_part_set_has_header(ps, &hdr),
          "HasHeader refuses a different total"); OK();

    CHECK(cmt_part_set_bit_array(ps, &ba) == CMT_OK, "BitArray"); OK();
    CHECK(ba.bits == V_PARTSET_TOTAL, "four bits"); OK();
    for (i = 0; i < V_PARTSET_TOTAL; i++) {
        CHECK(cmt_bits_get_index(&ba, (int)i) == 1, "every bit is set");
    }
    OK();

    /* Every part's proof verifies against the root, and the first and
     * last parts' aunt lists are the oracle's byte for byte. */
    CHECK(memcmp(parts[0].proof.leaf_hash, V_PARTSET_LEAF0, 64) == 0,
          "leaf 0 is the oracle's"); OK();
    for (i = 0; i < V_PARTSET_TOTAL; i++) {
        CHECK(cmt_part_validate_basic(&parts[i]) == CMT_OK,
              "each part validates");
        CHECK(cmt_proof_verify(&parts[i].proof, V_PARTSET_ROOT,
                               parts[i].bytes.data,
                               parts[i].bytes.len) == CMT_OK,
              "each proof verifies against the root");
        CHECK(parts[i].proof.aunts_len == 2u, "two aunts at four leaves");
    }
    OK();
    memcpy(aunts, parts[0].proof.aunts[0], 64);
    memcpy(aunts + 64, parts[0].proof.aunts[1], 64);
    CHECK(memcmp(aunts, V_PARTSET_P0_AUNTS, 128) == 0,
          "part 0's aunts are the oracle's"); OK();
    memcpy(aunts, parts[3].proof.aunts[0], 64);
    memcpy(aunts + 64, parts[3].proof.aunts[1], 64);
    CHECK(memcmp(aunts, V_PARTSET_P3_AUNTS, 128) == 0,
          "part 3's aunts are the oracle's"); OK();

    /* A proof for the wrong part does NOT verify — which is only a real
     * assertion because the parts are pairwise distinct (note 2). */
    CHECK(cmt_proof_verify(&parts[0].proof, V_PARTSET_ROOT,
                           parts[1].bytes.data,
                           parts[1].bytes.len) == CMT_REJECT,
          "part 0's proof does not prove part 1"); OK();

    CHECK(cmt_new_part_set_from_data(data, V_PARTSET_DATA_LEN, 0,
                                     parts, V_PARTSET_TOTAL,
                                     ps) == CMT_REJECT,
          "part_size 0 refuses instead of dividing by zero"); OK();
    CHECK(cmt_new_part_set_from_data(data, V_PARTSET_DATA_LEN,
                                     V_PARTSET_PART_SIZE, parts, 3,
                                     ps) == CMT_REJECT,
          "too little caller storage refuses"); OK();
    /* Both refusals happen BEFORE anything is written, so *ps still holds
     * the good set; rebuilt anyway so what follows cannot depend on that. */
    CHECK(cmt_new_part_set_from_data(data, V_PARTSET_DATA_LEN,
                                     V_PARTSET_PART_SIZE, parts,
                                     V_PARTSET_TOTAL, ps) == CMT_OK,
          "rebuild"); OK();
    return 0;
}

/* ══ AddPart (part_set.go:295-331) ════════════════════════════════════ */

static int test_add_part(const cmt_part_t *src, cmt_part_t *slots)
{
    cmt_part_set_header_t hdr;
    cmt_part_set_t        ps;
    cmt_part_t            bad;
    bool                  added;
    size_t                i;

    cmt_pb_part_set_header_init(&hdr);
    hdr.total = V_PARTSET_TOTAL;
    memcpy(hdr.hash, V_PARTSET_ROOT, 64);
    hdr.hash_len = 64;

    CHECK(cmt_new_part_set_from_header(&hdr, slots, V_PARTSET_TOTAL,
                                       &ps) == CMT_OK,
          "an empty set from a header"); OK();
    CHECK(cmt_part_set_count(&ps) == 0u, "nothing held yet"); OK();
    CHECK(!cmt_part_set_is_complete(&ps), "not complete"); OK();
    CHECK(cmt_part_set_get_part(&ps, 0) == NULL,
          "GetPart on an absent slot is NULL"); OK();
    CHECK(cmt_part_set_get_part(&ps, 99) == NULL,
          "GetPart out of range is NULL, not a read past the end"); OK();

    /* An index at or above `total` is ErrPartSetUnexpectedIndex. */
    bad = src[0];
    bad.index = V_PARTSET_TOTAL;
    CHECK(cmt_part_set_add_part(&ps, &bad, &added) == CMT_REJECT &&
          !added, "an index at `total` is refused"); OK();

    /* A part whose proof does not match the set is ErrPartSetInvalidProof
     * — here part 1's payload carried under part 0's index and proof. */
    bad = src[0];
    bad.bytes = src[1].bytes;
    CHECK(cmt_part_set_add_part(&ps, &bad, &added) == CMT_REJECT &&
          !added, "a payload that does not match the proof is refused");
    OK();

    /* And a proof whose `total` disagrees with the set's. */
    bad = src[0];
    bad.proof.total = 5;
    CHECK(cmt_part_set_add_part(&ps, &bad, &added) == CMT_REJECT &&
          !added, "a proof for a different tree size is refused"); OK();

    CHECK(cmt_part_set_count(&ps) == 0u,
          "no refused part was stored"); OK();

    for (i = 0; i < V_PARTSET_TOTAL; i++) {
        CHECK(cmt_part_set_add_part(&ps, &src[i], &added) == CMT_OK &&
              added, "each real part is added");
        CHECK(cmt_part_set_count(&ps) == (uint32_t)(i + 1u),
              "the count follows");
        CHECK(cmt_part_set_is_complete(&ps) == (i + 1u == V_PARTSET_TOTAL),
              "IsComplete flips exactly at the last part");
    }
    OK();
    CHECK(cmt_part_set_byte_size(&ps) == V_PARTSET_DATA_LEN,
          "the byte size adds up to the original buffer"); OK();

    /* A part already held is (false, nil): not added, NOT an error. */
    CHECK(cmt_part_set_add_part(&ps, &src[2], &added) == CMT_OK && !added,
          "a duplicate part is reported as not added, without an error");
    OK();
    CHECK(cmt_part_set_count(&ps) == V_PARTSET_TOTAL,
          "and the count did not move"); OK();

    CHECK(cmt_part_set_get_part(&ps, 2) != NULL, "GetPart after AddPart");
    OK();

    /* A NULL part set is (false, nil) — part_set.go:298-300. */
    CHECK(cmt_part_set_add_part(NULL, &src[0], &added) == CMT_OK && !added,
          "AddPart on a NULL set is not an error"); OK();

    /* A header asking for more parts than the caller's storage refuses. */
    hdr.total = V_PARTSET_TOTAL + 1;
    CHECK(cmt_new_part_set_from_header(&hdr, slots, V_PARTSET_TOTAL,
                                       &ps) == CMT_REJECT,
          "a header above the caller's capacity refuses"); OK();
    hdr.total = (uint32_t)CMT_PART_SET_MAX_PARTS + 1u;
    CHECK(cmt_new_part_set_from_header(&hdr, slots, V_PARTSET_TOTAL,
                                       &ps) == CMT_REJECT,
          "a header above MaxBlockPartsCount refuses"); OK();
    return 0;
}

/* ══ the reader (part_set.go:343-383) ═════════════════════════════════ */

static int test_reader(const uint8_t *data, cmt_part_t *parts,
                       cmt_part_set_t *ps)
{
    cmt_part_set_reader_t r;
    uint8_t              *back;
    size_t                off = 0;
    size_t                n;
    int                   rc;

    back = (uint8_t *)malloc(V_PARTSET_DATA_LEN);
    CHECK(back != NULL, "alloc"); OK();

    CHECK(cmt_part_set_get_reader(ps, &r) == CMT_OK, "GetReader"); OK();
    /* 1000 does not divide 65536, so most reads straddle a part
     * boundary — the reference's recursion at part_set.go:368-375. */
    for (;;) {
        rc = cmt_part_set_reader_read(&r, back + off,
                                      (V_PARTSET_DATA_LEN - off) < 1000u
                                          ? (V_PARTSET_DATA_LEN - off)
                                          : 1000u,
                                      &n);
        if (rc == CMT_PART_SET_EOF) {
            break;
        }
        CHECK(rc == CMT_OK, "read");
        CHECK(n > 0u, "a CMT_OK read produced bytes");
        off += n;
        if (off == V_PARTSET_DATA_LEN) {
            break;
        }
    }
    OK();
    CHECK(off == V_PARTSET_DATA_LEN, "every byte came back"); OK();
    CHECK(memcmp(back, data, V_PARTSET_DATA_LEN) == 0,
          "the reassembled bytes are the original bytes"); OK();

    /* Past the end the reader reports EOF and produces nothing. */
    rc = cmt_part_set_reader_read(&r, back, 16u, &n);
    CHECK(rc == CMT_PART_SET_EOF && n == 0u, "EOF at the end"); OK();

    /* A zero-length request is (0, nil), not EOF. */
    CHECK(cmt_new_part_set_reader(parts, V_PARTSET_TOTAL, &r) == CMT_OK,
          "a fresh reader"); OK();
    CHECK(cmt_part_set_reader_read(&r, back, 0u, &n) == CMT_OK && n == 0u,
          "a zero-length read is CMT_OK with 0 bytes"); OK();

    /* One read that spans every part at once. */
    CHECK(cmt_new_part_set_reader(parts, V_PARTSET_TOTAL, &r) == CMT_OK,
          "a fresh reader"); OK();
    CHECK(cmt_part_set_reader_read(&r, back, V_PARTSET_DATA_LEN,
                                   &n) == CMT_OK &&
          n == V_PARTSET_DATA_LEN,
          "a single read crosses all four parts"); OK();
    CHECK(memcmp(back, data, V_PARTSET_DATA_LEN) == 0,
          "and delivers the original bytes"); OK();

    CHECK(cmt_new_part_set_reader(parts, 0, &r) == CMT_REJECT,
          "a reader over zero parts refuses (the reference indexes"
          " parts[0] and panics)"); OK();

    free(back);
    return 0;
}

/* ══ the two degenerate part sets ═════════════════════════════════════ */

static int test_degenerate(void)
{
    static cmt_part_t one[1];
    cmt_part_set_t    ps;
    uint8_t           root[64];
    uint8_t           byte = 0x2A;

    CHECK(cmt_new_part_set_from_data(NULL, 0, V_PARTSET_PART_SIZE, NULL, 0,
                                     &ps) == CMT_OK,
          "an empty buffer gives an empty part set"); OK();
    CHECK(cmt_part_set_total(&ps) == 0u, "total 0"); OK();
    CHECK(cmt_part_set_is_complete(&ps),
          "an empty part set is complete (0 == 0)"); OK();
    CHECK(ps.parts_bit_array_nil,
          "and its bit array is the reference's nil"); OK();
    CHECK(cmt_part_set_hash(&ps, root) == CMT_OK &&
          memcmp(root, V_PARTSET_EMPTY_ROOT, 64) == 0,
          "an empty part set hashes to H(\"\")"); OK();

    CHECK(cmt_new_part_set_from_data(&byte, 1, V_PARTSET_PART_SIZE, one, 1,
                                     &ps) == CMT_OK,
          "a one-byte buffer"); OK();
    CHECK(cmt_part_set_total(&ps) == 1u, "one part"); OK();
    CHECK(one[0].proof.aunts_len == 0u, "a lone leaf has no aunts"); OK();
    CHECK(cmt_part_set_hash(&ps, root) == CMT_OK &&
          memcmp(root, V_PARTSET_ONE_ROOT, 64) == 0,
          "and the root is the leaf hash"); OK();
    CHECK(cmt_proof_verify(&one[0].proof, root, &byte, 1) == CMT_OK,
          "its proof verifies"); OK();

    /* Hash() on a NULL part set is H("") — part_set.go:260-262. */
    CHECK(cmt_part_set_hash(NULL, root) == CMT_OK &&
          memcmp(root, V_PARTSET_EMPTY_ROOT, 64) == 0,
          "Hash(NULL) is H(\"\")"); OK();
    CHECK(cmt_part_set_total(NULL) == 0u && cmt_part_set_count(NULL) == 0u &&
          cmt_part_set_byte_size(NULL) == 0,
          "the NULL accessors answer 0"); OK();
    CHECK(!cmt_part_set_is_complete(NULL), "IsComplete(NULL) is false");
    OK();
    return 0;
}

int main(void)
{
    static cmt_part_t parts[V_PARTSET_TOTAL];
    static cmt_part_t slots[V_PARTSET_TOTAL];
    cmt_part_set_t    ps;
    uint8_t          *data;

    if (test_validate_hash() != 0) return 1;
    if (test_part_set_header() != 0) return 1;
    if (test_part_validate_basic() != 0) return 1;
    if (test_degenerate() != 0) return 1;

    data = (uint8_t *)malloc(V_PARTSET_DATA_LEN);
    if (data == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    fill_payload(data, V_PARTSET_DATA_LEN);

    if (test_from_data(data, parts, &ps) != 0) { free(data); return 1; }
    if (test_add_part(parts, slots) != 0)      { free(data); return 1; }
    if (test_reader(data, parts, &ps) != 0)    { free(data); return 1; }

    free(data);
    printf("test_cmt_part_set: %d checks OK\n", g_checks);
    return 0;
}
