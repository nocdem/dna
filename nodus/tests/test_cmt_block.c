/**
 * Nodus — cometbft @709fd12b C port, wave R1-B: `types/block.go`
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the block hash is the reference's Merkle tree over the reference's
 * fourteen leaves, that the derived size constants were re-derived and not
 * guessed, and that every ValidateBasic refuses what the reference
 * refuses. If this file failed, one of these would be false:
 *   · Header.Hash over a fully populated header, and over a genesis-like
 *     header whose LastBlockID is ZERO and whose AppHash and
 *     LastResultsHash are EMPTY, are the roots an independent python
 *     oracle computes — the zero LastBlockID contributing the leaf
 *     H(0x00 ‖ 12 00) and each empty field the nil leaf H(0x00);
 *   · Header.Hash is NIL when ValidatorsHash is empty (block.go:446-448),
 *     which is the reference's way of saying "this header is not finished";
 *   · CMT_MAX_HEADER_BYTES (790) IS the marshalled size of a header whose
 *     every field is at its widest — built here and MEASURED, exactly as
 *     the reference's own types/block_test.go:402-437 measures its 626;
 *   · CMT_MAX_COMMIT_SIG_BYTES (4685) and CMT_MAX_COMMIT_OVERHEAD_BYTES
 *     (159) are likewise measured, not copied;
 *   · Commit.Hash of the EMPTY height-1 commit is H(""), not a run of
 *     zero bytes (D-19 rev 6 item 4), and Commit.Hash over
 *     {Absent, Commit, Nil} is the oracle's root — so the certificate
 *     leaf really is the marshalled CommitSig, ADDRESS INCLUDED;
 *   · Data.Hash is the Merkle root over SHA3-512 of each transaction, so
 *     an empty transaction is a real leaf and an empty block hashes to
 *     H("");
 *   · an ABSENT CommitSig carrying an address, a timestamp or a
 *     signature is REFUSED, and its wire form is the fifteen bytes
 *     `08 01 1a 0b 08 …` — Go's zero time, not a memset;
 *   · ExtendedCommit.EnsureExtensions returns the FIRST refusing entry's
 *     verdict and accepts an ExtendedCommit with no entries at all —
 *     the reference's `range` over an empty slice never runs;
 *   · MaxDataBytes refuses instead of panicking when the block budget
 *     cannot hold the header and the commit, and returns exactly zero on
 *     the boundary;
 *   · a Block round-trips through MakePartSet: marshal, split, reassemble,
 *     and the bytes are identical.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock, no RNG. Safe under `ctest -j`.
 * MEMORY: the big fixtures are file-scope statics so the stack stays
 * small, and they are NOT small themselves — one `cmt_commit_sig_t` is
 * ~4.7 KB (a 4627-byte signature), one `cmt_extended_commit_sig_t` ~9.4 KB
 * and one `cmt_part_t` ~7.3 KB (a proof of up to 100 aunts × 64 bytes).
 * `parts[64]` alone is therefore ≈470 KB, and this file's statics come to
 * roughly 0.6 MB of BSS. Two buffers of a few kilobytes are malloc'd for
 * the block marshal and freed.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. Every hash vector comes from shared/dnac/tests/cmt_block_oracle.py,
 *     written from the pinned Go source with python3's SHA3-512. Cometbft
 *     publishes NO vector for a 64-byte-digest header, so this is two
 *     independent implementations of the same reading agreeing — not a
 *     check against the reference's own output. Only reading block.go
 *     establishes that the reading is right.
 *  2. The MaxHeaderBytes measurement proves the CONSTANT matches the
 *     header this file builds. It does not prove that header is the
 *     widest possible one; that follows from the field-by-field
 *     arithmetic in cmt_block.h, which a reader must check.
 *  3. The evidence path is EXERCISED ONLY EMPTY. `cmt_evidence_data_hash`
 *     is called with a zero-length list, so a green says nothing about
 *     the DuplicateVoteEvidence leaf. That leaf, and the list root over
 *     it, are test_cmt_evidence.c's subject (wave R1-D).
 *  4. `Block.ValidateBasic` here never sees a block with evidence, so the
 *     per-evidence ValidateBasic loop (block.go:92-97 — performed since
 *     wave R1-D through `cmt_evidence_from_proto`) is never reached from
 *     this file; a green says nothing about a block that carries evidence.
 *  5. The MakePartSet round trip uses a SMALL part size so the block is
 *     split at all. It therefore says nothing about a 65 536-byte split
 *     of a real block, and nothing about a block above the 100 MB cap.
 *
 * @file test_cmt_block.c
 */

#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"       /* CMT_VOTE_SIGN_BYTES_MAX (Delta B-1) */
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

/* ══ oracle vectors — cmt_block_oracle.py ═════════════════════════════ */

static const uint8_t V_HEADER_FULL_HASH[64] = {
    0x4b, 0x35, 0x29, 0x9f, 0x55, 0xbe, 0x3b, 0xa2, 0x4e, 0x6a, 0x3a, 0xae,
    0x75, 0x6a, 0x9d, 0xea, 0xbd, 0xda, 0x1f, 0x31, 0x1d, 0x66, 0x1b, 0x28,
    0x35, 0x78, 0xef, 0xff, 0xb7, 0x08, 0xe4, 0x58, 0x21, 0xbe, 0x5a, 0x3f,
    0x10, 0x0e, 0xef, 0x89, 0xee, 0xe2, 0x53, 0xf6, 0xfd, 0x3d, 0xf7, 0xe4,
    0xc4, 0x7f, 0x33, 0x63, 0xaa, 0xb6, 0x50, 0x2b, 0x23, 0x24, 0x80, 0x5d,
    0x7c, 0xc2, 0x8b, 0xee,
};
static const uint8_t V_HEADER_GENESIS_HASH[64] = {
    0x07, 0xf8, 0x3c, 0x4b, 0x26, 0x3f, 0x15, 0xf2, 0xb7, 0xae, 0x3e, 0xfb,
    0x5c, 0x65, 0x0c, 0xd8, 0x9f, 0xe3, 0x1f, 0xdf, 0xa7, 0x47, 0x68, 0x03,
    0x89, 0x5b, 0x26, 0x4e, 0xb6, 0x49, 0x0d, 0xf9, 0x40, 0x78, 0x04, 0x3e,
    0x5d, 0x39, 0x27, 0xb3, 0x23, 0xa2, 0xbf, 0x41, 0x0e, 0x27, 0x45, 0x2d,
    0x78, 0x1e, 0xf2, 0xe1, 0x58, 0x84, 0x70, 0xed, 0x80, 0x9f, 0xfd, 0xe6,
    0x49, 0x78, 0x2f, 0xde,
};
static const uint8_t V_HEADER_FULL_LEAF0[4]  = { 0x08, 0x0b, 0x10, 0x07 };
static const uint8_t V_HEADER_FULL_LEAF2[4]  = { 0x08, 0x87, 0xad, 0x4b };
static const uint8_t V_HEADER_FULL_LEAF3[11] = {
    0x08, 0x80, 0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a,
};
static const uint8_t V_HEADER_FULL_LEAF1[34] = {
    0x0a, 0x20, 0x50, 0x57, 0x5e, 0x65, 0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f,
    0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3,
    0xea, 0xf1, 0xf8, 0xff, 0x06, 0x0d, 0x14, 0x1b, 0x22, 0x29,
};
static const uint8_t V_COMMIT_EMPTY_HASH[64] = {   /* = SHA3-512("") */
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc,
    0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
    0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a,
    0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
    0x28, 0x1d, 0xcd, 0x26,
};
static const uint8_t V_COMMIT_THREE_HASH[64] = {
    0x31, 0x9c, 0xfa, 0x52, 0xab, 0x0d, 0x4b, 0x23, 0xe5, 0x89, 0x93, 0x57,
    0x0f, 0x35, 0x6a, 0x7d, 0xae, 0x59, 0x3e, 0xba, 0x79, 0x81, 0x43, 0xaf,
    0xc7, 0x5e, 0x96, 0x64, 0x1b, 0x19, 0x6e, 0x50, 0xa9, 0xa9, 0x87, 0xa1,
    0x32, 0x38, 0xb5, 0xd6, 0x5f, 0x55, 0xf7, 0x65, 0xa2, 0x49, 0x39, 0x7e,
    0x07, 0x97, 0xe9, 0xeb, 0x75, 0x41, 0xc4, 0xc6, 0x51, 0x4e, 0x07, 0xab,
    0x5a, 0x9f, 0x82, 0x65,
};
static const uint8_t V_COMMIT_SIG_ABSENT[15] = {
    0x08, 0x01, 0x1a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff,
    0xff, 0xff, 0x01,
};
static const uint8_t V_COMMIT_SIG_NIL[47] = {
    0x08, 0x03, 0x12, 0x20, 0x40, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71,
    0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2, 0xa9, 0xb0, 0xb7, 0xbe, 0xc5,
    0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef, 0xf6, 0xfd, 0x04, 0x0b, 0x12, 0x19,
    0x1a, 0x06, 0x08, 0x81, 0xe2, 0xcf, 0xaa, 0x06, 0x22, 0x01, 0x01,
};
static const uint8_t V_DATA_HASH_1[64] = {
    0x5d, 0x82, 0xaa, 0x8a, 0xc7, 0x3b, 0xfc, 0x08, 0x07, 0x5e, 0xdf, 0xfa,
    0xd0, 0x5d, 0x0d, 0x3f, 0x20, 0x02, 0x0a, 0xf5, 0x25, 0xce, 0x48, 0xfa,
    0xe8, 0xaf, 0xec, 0xf4, 0xad, 0xc6, 0x97, 0x78, 0x97, 0x19, 0xd0, 0x23,
    0x66, 0x8d, 0xfe, 0x8d, 0x17, 0x77, 0x9c, 0x9a, 0xf4, 0xa3, 0x9f, 0x98,
    0x72, 0x17, 0xa9, 0xe2, 0x0c, 0x0e, 0x86, 0xf1, 0x24, 0x61, 0x42, 0xd0,
    0xb9, 0x1b, 0xf2, 0xb5,
};
static const uint8_t V_DATA_HASH_3[64] = {
    0x1e, 0x08, 0xc3, 0xba, 0x3f, 0x8e, 0x18, 0x4c, 0x77, 0x6f, 0xbb, 0xb1,
    0x93, 0x2f, 0x3d, 0xd8, 0x4c, 0x6b, 0x0d, 0x8e, 0x62, 0x0d, 0x86, 0x8c,
    0xdd, 0x94, 0xdf, 0xa4, 0x17, 0xc8, 0xef, 0xfe, 0x0f, 0xe4, 0xd5, 0xec,
    0xef, 0x69, 0xd4, 0xf5, 0xfd, 0xc4, 0x61, 0x4d, 0xa7, 0x14, 0xe1, 0x3a,
    0x61, 0xdb, 0x65, 0x7a, 0x21, 0x7e, 0xc7, 0x9e, 0x71, 0x94, 0x27, 0xd7,
    0x17, 0xa0, 0x46, 0x5c,
};
/* The leaf of a ZERO LastBlockID: SHA3-512(00 ‖ 12 00). */
static const uint8_t V_LEAF_ZERO_BLOCK_ID[64] = {
    0x68, 0x70, 0xf4, 0x05, 0x02, 0xa5, 0xf5, 0x43, 0x6f, 0x15, 0x0b, 0x9b,
    0x6e, 0x8c, 0x8d, 0xa3, 0xc2, 0x69, 0x15, 0xc0, 0x03, 0xc0, 0xa7, 0xf4,
    0x84, 0x07, 0xfa, 0xe8, 0x66, 0xf6, 0xac, 0x89, 0xfb, 0xa3, 0xdc, 0xcd,
    0xd5, 0x73, 0xff, 0xaa, 0x17, 0x89, 0xf2, 0x14, 0x69, 0x48, 0x3f, 0x09,
    0x0a, 0xa3, 0xad, 0xb0, 0x71, 0xf6, 0x5c, 0x90, 0xcc, 0x6f, 0x19, 0xab,
    0x41, 0x06, 0x8b, 0x65,
};

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static void pat(uint8_t *p, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static uint8_t g_chain[32], g_addr[32];
static uint8_t g_h11[64], g_h22[64], g_h33[64], g_h44[64];
static uint8_t g_h55[64], g_h66[64], g_h77[64], g_h88[64];
static uint8_t g_h99[64], g_hAA[64];
static uint8_t g_sig_s[9];
static uint8_t g_empty[64];              /* SHA3-512("") */

static void fixtures(void)
{
    pat(g_chain, 32, 0x50);
    pat(g_addr, 32, 0x40);
    pat(g_h11, 64, 0x11);
    pat(g_h22, 64, 0x22);
    pat(g_h33, 64, 0x33);
    pat(g_h44, 64, 0x44);
    pat(g_h55, 64, 0x55);
    pat(g_h66, 64, 0x66);
    pat(g_h77, 64, 0x77);
    pat(g_h88, 64, 0x88);
    pat(g_h99, 64, 0x99);
    pat(g_hAA, 64, 0xAA);
    pat(g_sig_s, 9, 0x60);
    (void)cmt_merkle_empty_hash(g_empty);
}

static void set_hash(uint8_t *dst, size_t *len, const uint8_t *src)
{
    memcpy(dst, src, 64);
    *len = 64;
}

static void make_full_header(cmt_header_t *h)
{
    cmt_pb_header_init(h);
    h->version.block = 11;
    h->version.app   = 7;
    memcpy(h->chain_id, g_chain, 32);
    h->chain_id_len = 32;
    h->height       = 1234567;
    h->time.seconds = 1700000000;
    h->time.nanos   = 123456789;
    set_hash(h->last_block_id.hash, &h->last_block_id.hash_len, g_hAA);
    h->last_block_id.part_set_header.total = 9;
    set_hash(h->last_block_id.part_set_header.hash,
             &h->last_block_id.part_set_header.hash_len, g_h99);
    set_hash(h->last_commit_hash, &h->last_commit_hash_len, g_h11);
    set_hash(h->data_hash, &h->data_hash_len, g_h22);
    set_hash(h->validators_hash, &h->validators_hash_len, g_h33);
    set_hash(h->next_validators_hash, &h->next_validators_hash_len, g_h44);
    set_hash(h->consensus_hash, &h->consensus_hash_len, g_h55);
    set_hash(h->app_hash, &h->app_hash_len, g_h66);
    set_hash(h->last_results_hash, &h->last_results_hash_len, g_h77);
    set_hash(h->evidence_hash, &h->evidence_hash_len, g_h88);
    memcpy(h->proposer_address, g_addr, 32);
    h->proposer_address_len = 32;
}

static void make_genesis_header(cmt_header_t *h)
{
    cmt_pb_header_init(h);            /* time = Go's zero, NOT a memset */
    h->version.block = 11;
    h->version.app   = 0;
    memcpy(h->chain_id, g_chain, 32);
    h->chain_id_len = 32;
    h->height       = 1;
    /* last_block_id stays ZERO — its leaf is H(0x00 ‖ 12 00). */
    set_hash(h->last_commit_hash, &h->last_commit_hash_len, g_empty);
    set_hash(h->data_hash, &h->data_hash_len, g_empty);
    set_hash(h->validators_hash, &h->validators_hash_len, g_h33);
    set_hash(h->next_validators_hash, &h->next_validators_hash_len, g_h33);
    set_hash(h->consensus_hash, &h->consensus_hash_len, g_h55);
    /* app_hash and last_results_hash stay EMPTY — nil leaves. */
    set_hash(h->evidence_hash, &h->evidence_hash_len, g_empty);
    memcpy(h->proposer_address, g_addr, 32);
    h->proposer_address_len = 32;
}

/* ══ the re-derived size constants, MEASURED ══════════════════════════ */

static int test_constants(void)
{
    static cmt_header_t     h;
    static cmt_commit_sig_t cs;
    static cmt_commit_t     c;
    static uint8_t          buf[8192];
    size_t                  n;
    int64_t                 v;

    /* MaxHeaderBytes: the reference's own test (block_test.go:402-437)
     * builds a header whose every field is at its widest and asserts the
     * marshalled length. Same construction, DNA sizes. */
    cmt_pb_header_init(&h);
    h.version.block = (uint64_t)INT64_MAX;   /* 9-byte varint  */
    h.version.app   = (uint64_t)INT64_MAX;
    memset(h.chain_id, 0x41, CMT_PB_CHAINID_MAX);
    h.chain_id_len  = CMT_PB_CHAINID_MAX;    /* 32 raw bytes   */
    h.height        = INT64_MAX;             /* 9-byte varint  */
    h.time.seconds  = CMT_TIME_MIN_SECONDS;  /* 10-byte varint */
    h.time.nanos    = 999999999;             /* 5-byte varint  */
    memset(h.last_block_id.hash, 0x42, 64);
    h.last_block_id.hash_len = 64;
    h.last_block_id.part_set_header.total = UINT32_MAX;   /* 5 bytes */
    memset(h.last_block_id.part_set_header.hash, 0x43, 64);
    h.last_block_id.part_set_header.hash_len = 64;
    memset(h.last_commit_hash, 0x44, 64);     h.last_commit_hash_len = 64;
    memset(h.data_hash, 0x45, 64);            h.data_hash_len = 64;
    memset(h.validators_hash, 0x46, 64);      h.validators_hash_len = 64;
    memset(h.next_validators_hash, 0x47, 64); h.next_validators_hash_len = 64;
    memset(h.consensus_hash, 0x48, 64);       h.consensus_hash_len = 64;
    memset(h.app_hash, 0x49, 64);             h.app_hash_len = 64;
    memset(h.last_results_hash, 0x4A, 64);    h.last_results_hash_len = 64;
    memset(h.evidence_hash, 0x4B, 64);        h.evidence_hash_len = 64;
    memset(h.proposer_address, 0x4C, 32);     h.proposer_address_len = 32;
    CHECK(cmt_pb_header_marshal(&h, buf, sizeof(buf), &n) == CMT_OK,
          "marshal the widest header"); OK();
    CHECK((int64_t)n == CMT_MAX_HEADER_BYTES,
          "CMT_MAX_HEADER_BYTES is the MEASURED width of that header");
    OK();

    /* MaxCommitSigBytes: the widest CommitSig. */
    cmt_pb_commit_sig_init(&cs);
    cs.block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_NIL;
    memset(cs.validator_address, 0x51, 32);
    cs.validator_address_len = 32;
    cs.timestamp.seconds = CMT_TIME_MIN_SECONDS;
    cs.timestamp.nanos   = 999999999;
    memset(cs.signature, 0x52, CMT_PB_SIG_MAX);
    cs.signature_len = CMT_PB_SIG_MAX;
    CHECK(cmt_pb_commit_sig_marshal(&cs, buf, sizeof(buf), &n) == CMT_OK,
          "marshal the widest CommitSig"); OK();
    CHECK((int64_t)n == CMT_MAX_COMMIT_SIG_BYTES,
          "CMT_MAX_COMMIT_SIG_BYTES is measured"); OK();

    /* MaxCommitOverheadBytes: a Commit with NO signatures. */
    cmt_pb_commit_init(&c);
    c.height = INT64_MAX;
    c.round  = INT32_MAX;
    memset(c.block_id.hash, 0x61, 64);
    c.block_id.hash_len = 64;
    c.block_id.part_set_header.total = UINT32_MAX;
    memset(c.block_id.part_set_header.hash, 0x62, 64);
    c.block_id.part_set_header.hash_len = 64;
    CHECK(cmt_pb_commit_marshal(&c, buf, sizeof(buf), &n) == CMT_OK,
          "marshal a signature-less Commit"); OK();
    CHECK((int64_t)n == CMT_MAX_COMMIT_OVERHEAD_BYTES,
          "CMT_MAX_COMMIT_OVERHEAD_BYTES is measured"); OK();

    /* MaxOverheadForBlock depends only on MaxBlockSizeBytes and two field
     * numbers, neither substituted, so it is UNCHANGED at 11. It is an
     * estimate in the reference too and cannot be measured. */
    CHECK(CMT_MAX_OVERHEAD_FOR_BLOCK == 11,
          "MaxOverheadForBlock is unchanged"); OK();

    CHECK(cmt_max_commit_bytes(0, &v) == CMT_OK &&
          v == CMT_MAX_COMMIT_OVERHEAD_BYTES,
          "MaxCommitBytes(0) is the overhead alone"); OK();
    CHECK(cmt_max_commit_bytes(4, &v) == CMT_OK &&
          v == CMT_MAX_COMMIT_OVERHEAD_BYTES +
               4 * (CMT_MAX_COMMIT_SIG_BYTES + 2),
          "MaxCommitBytes(4) adds four entries plus their field frames");
    OK();
    CHECK(cmt_max_commit_bytes(-1, &v) == CMT_REJECT,
          "a negative count refuses"); OK();
    CHECK(cmt_max_commit_bytes(INT64_MAX, &v) == CMT_REJECT,
          "an overflow refuses instead of wrapping"); OK();
    return 0;
}

/* ══ BlockID (block.go:1462-1555) ═════════════════════════════════════ */

static int test_block_id(void)
{
    cmt_block_id_t a, b;
    uint8_t        key[256];
    size_t         key_len;

    cmt_pb_block_id_init(&a);
    CHECK(cmt_block_id_is_zero(&a), "a fresh BlockID is zero"); OK();
    CHECK(!cmt_block_id_is_complete(&a), "and not complete"); OK();
    CHECK(cmt_block_id_validate_basic(&a) == CMT_OK,
          "an EMPTY BlockID is VALID — a POL BlockID has no hash"); OK();
    CHECK(cmt_proto_block_id_is_nil(&a), "and the wire predicate agrees");
    OK();

    set_hash(a.hash, &a.hash_len, g_hAA);
    CHECK(!cmt_block_id_is_zero(&a), "a hash alone is not zero"); OK();
    CHECK(!cmt_block_id_is_complete(&a),
          "but it is not complete either — the half-filled shape"); OK();
    a.part_set_header.total = 9;
    set_hash(a.part_set_header.hash, &a.part_set_header.hash_len, g_h99);
    CHECK(cmt_block_id_is_complete(&a), "now it is complete"); OK();

    a.hash_len = 32;
    CHECK(cmt_block_id_validate_basic(&a) == CMT_REJECT,
          "a 32-byte hash is refused — tmhash.Size is 64 here"); OK();
    CHECK(!cmt_block_id_is_complete(&a), "and it is not complete"); OK();
    a.hash_len = 64;

    b = a;
    CHECK(cmt_block_id_equals(&a, &b), "equal"); OK();
    b.part_set_header.total = 10;
    CHECK(!cmt_block_id_equals(&a, &b), "a different total is not equal");
    OK();
    b = a;
    b.hash[63] ^= 0x01;
    CHECK(!cmt_block_id_equals(&a, &b), "a different hash is not equal");
    OK();

    CHECK(cmt_block_id_key(&a, key, sizeof(key), &key_len) == CMT_OK,
          "Key()"); OK();
    CHECK(key_len == 64u + 68u,
          "Key is the hash followed by the marshalled PartSetHeader"); OK();
    CHECK(memcmp(key, a.hash, 64) == 0, "the hash comes first"); OK();
    CHECK(cmt_block_id_key(&a, key, 8, &key_len) == CMT_REJECT,
          "a short Key buffer refuses"); OK();

    /* The zero BlockID marshals to the two bytes 12 00 — the ALWAYS-emitted
     * empty PartSetHeader — and its Merkle leaf is the oracle's. */
    {
        uint8_t z[8];
        size_t  zn;
        uint8_t leaf[64];

        cmt_pb_block_id_init(&b);
        CHECK(cmt_pb_block_id_marshal(&b, z, sizeof(z), &zn) == CMT_OK,
              "marshal the zero BlockID"); OK();
        CHECK(zn == 2u && z[0] == 0x12 && z[1] == 0x00,
              "the zero BlockID is 12 00, not zero bytes"); OK();
        CHECK(cmt_merkle_leaf_hash(z, zn, leaf) == CMT_OK, "its leaf"); OK();
        CHECK(memcmp(leaf, V_LEAF_ZERO_BLOCK_ID, 64) == 0,
              "and the leaf is SHA3-512(00 ‖ 12 00)"); OK();
    }
    return 0;
}

/* ══ Header.Hash and Header.ValidateBasic ═════════════════════════════ */

static int test_header(void)
{
    static cmt_header_t h;
    uint8_t             out[64];
    uint8_t             leaf[CMT_HEADER_LEAF_MAX];
    size_t              n;
    bool                is_nil;

    make_full_header(&h);
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "the full header is well-formed"); OK();
    CHECK(cmt_header_hash(&h, out) == CMT_OK, "hash it"); OK();
    CHECK(memcmp(out, V_HEADER_FULL_HASH, 64) == 0,
          "the header hash is the oracle's root"); OK();

    /* The first four leaves, pinned individually. */
    CHECK(cmt_pb_consensus_marshal(&h.version, leaf, sizeof(leaf),
                                   &n) == CMT_OK, "leaf 0"); OK();
    CHECK(n == sizeof(V_HEADER_FULL_LEAF0) &&
          memcmp(leaf, V_HEADER_FULL_LEAF0, n) == 0,
          "leaf 0 is the bare Consensus message"); OK();
    CHECK(cmt_pb_cdc_encode_string(h.chain_id, h.chain_id_len, leaf,
                                   sizeof(leaf), &n, &is_nil) == CMT_OK,
          "leaf 1"); OK();
    CHECK(!is_nil && n == sizeof(V_HEADER_FULL_LEAF1) &&
          memcmp(leaf, V_HEADER_FULL_LEAF1, n) == 0,
          "leaf 1 is StringValue{chain id}"); OK();
    CHECK(cmt_pb_cdc_encode_int64(h.height, leaf, sizeof(leaf), &n,
                                  &is_nil) == CMT_OK, "leaf 2"); OK();
    CHECK(!is_nil && n == sizeof(V_HEADER_FULL_LEAF2) &&
          memcmp(leaf, V_HEADER_FULL_LEAF2, n) == 0,
          "leaf 2 is Int64Value{height}"); OK();
    CHECK(cmt_pb_timestamp_marshal(&h.time, leaf, sizeof(leaf),
                                   &n) == CMT_OK, "leaf 3"); OK();
    CHECK(n == sizeof(V_HEADER_FULL_LEAF3) &&
          memcmp(leaf, V_HEADER_FULL_LEAF3, n) == 0,
          "leaf 3 is the BARE Timestamp, not a tagged field"); OK();

    /* An empty ValidatorsHash makes the hash NIL (block.go:446-448). */
    h.validators_hash_len = 0;
    CHECK(cmt_header_hash(&h, out) == CMT_HASH_NIL,
          "an empty ValidatorsHash gives a NIL header hash"); OK();
    make_full_header(&h);

    /* The genesis-like header: zero LastBlockID, empty AppHash and
     * LastResultsHash. */
    make_genesis_header(&h);
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "the genesis header is well-formed even with empty hashes"); OK();
    CHECK(cmt_header_hash(&h, out) == CMT_OK, "hash it"); OK();
    CHECK(memcmp(out, V_HEADER_GENESIS_HASH, 64) == 0,
          "the genesis header hash is the oracle's root"); OK();
    CHECK(cmt_pb_cdc_encode_bytes(h.app_hash, h.app_hash_len, leaf,
                                  sizeof(leaf), &n, &is_nil) == CMT_OK,
          "the AppHash leaf"); OK();
    CHECK(is_nil && n == 0u,
          "an empty AppHash is the reference's NIL leaf"); OK();

    /* ValidateBasic negatives, in the reference's order. */
    make_full_header(&h);
    CHECK(cmt_header_validate_basic(&h, 12) == CMT_REJECT,
          "a wrong block protocol is refused"); OK();
    h.chain_id_len = 0;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "an EMPTY chain id passes — only an over-long one is refused");
    OK();
    make_full_header(&h);
    h.height = 0;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "height 0 is refused"); OK();
    h.height = -1;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a negative height is refused"); OK();
    h.height = 1;
    h.last_block_id.hash_len = 31;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a malformed LastBlockID is refused"); OK();
    make_full_header(&h);
    h.last_commit_hash_len = 63;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a 63-byte LastCommitHash is refused"); OK();
    make_full_header(&h);
    h.proposer_address_len = 20;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a 20-byte proposer address is the REFERENCE width, not ours");
    OK();
    make_full_header(&h);
    h.app_hash_len = 7;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "AppHash is of ARBITRARY length and is NOT checked"
          " (block.go:431)"); OK();
    make_full_header(&h);
    h.last_results_hash_len = 7;
    CHECK(cmt_header_validate_basic(&h, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "but LastResultsHash IS checked"); OK();
    CHECK(cmt_header_validate_basic(NULL, CMT_BLOCK_PROTOCOL) == CMT_FAULT,
          "NULL is a fault"); OK();

    /* Populate fills the ten state-derived fields and no others. */
    {
        cmt_pb_consensus_t ver;
        cmt_block_id_t     lbid;
        cmt_time_t         t;

        cmt_pb_header_init(&h);
        cmt_pb_block_id_init(&lbid);
        ver.block = 11; ver.app = 3;
        t.seconds = 1700000000; t.nanos = 1;
        CHECK(cmt_header_populate(&h, &ver, g_chain, 32, t, &lbid,
                                  g_h33, 64, g_h44, 64, g_h55, 64,
                                  g_h66, 64, g_h77, 64, g_addr, 32)
              == CMT_OK, "Populate"); OK();
        CHECK(h.height == 0,
              "Populate does NOT set the height — MakeBlock does"); OK();
        CHECK(h.last_commit_hash_len == 0u && h.data_hash_len == 0u &&
              h.evidence_hash_len == 0u,
              "nor the three fields fillHeader computes"); OK();
        CHECK(cmt_header_populate(&h, &ver, g_chain, 33, t, &lbid,
                                  g_h33, 64, g_h44, 64, g_h55, 64,
                                  g_h66, 64, g_h77, 64, g_addr, 32)
              == CMT_REJECT, "an over-long chain id refuses"); OK();
    }
    return 0;
}

/* ══ CommitSig and Commit ═════════════════════════════════════════════ */

static cmt_commit_sig_t g_sigs[4];

static void make_three_sigs(void)
{
    /* {Absent, Commit, Nil} — the three the reference can produce. */
    cmt_new_commit_sig_absent(&g_sigs[0]);

    cmt_pb_commit_sig_init(&g_sigs[1]);
    g_sigs[1].block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    memcpy(g_sigs[1].validator_address, g_addr, 32);
    g_sigs[1].validator_address_len = 32;
    g_sigs[1].timestamp.seconds = 1700000000;
    g_sigs[1].timestamp.nanos   = 123456789;
    memcpy(g_sigs[1].signature, g_sig_s, 9);
    g_sigs[1].signature_len = 9;

    cmt_pb_commit_sig_init(&g_sigs[2]);
    g_sigs[2].block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_NIL;
    memcpy(g_sigs[2].validator_address, g_addr, 32);
    g_sigs[2].validator_address_len = 32;
    g_sigs[2].timestamp.seconds = 1700000001;
    g_sigs[2].timestamp.nanos   = 0;
    g_sigs[2].signature[0] = 0x01;
    g_sigs[2].signature_len = 1;
}

static int test_commit(void)
{
    static cmt_commit_sig_t clone_slots[4];
    cmt_commit_t            c;
    cmt_commit_t            c2;
    cmt_block_id_t          bid;
    cmt_pb_vote_t           v;
    uint8_t                 buf[8192];
    uint8_t                 out[64];
    size_t                  n;
    size_t                  i;

    make_three_sigs();

    /* The Absent entry's wire form, and its rules. */
    CHECK(cmt_pb_commit_sig_marshal(&g_sigs[0], buf, sizeof(buf),
                                    &n) == CMT_OK, "marshal Absent"); OK();
    CHECK(n == sizeof(V_COMMIT_SIG_ABSENT) &&
          memcmp(buf, V_COMMIT_SIG_ABSENT, n) == 0,
          "an Absent CommitSig is fifteen bytes carrying Go's zero time");
    OK();
    CHECK(cmt_commit_sig_validate_basic(&g_sigs[0]) == CMT_OK, "valid");
    OK();
    CHECK(cmt_pb_commit_sig_marshal(&g_sigs[2], buf, sizeof(buf),
                                    &n) == CMT_OK, "marshal Nil"); OK();
    CHECK(n == sizeof(V_COMMIT_SIG_NIL) &&
          memcmp(buf, V_COMMIT_SIG_NIL, n) == 0,
          "the Nil entry is the oracle's bytes"); OK();

    /* An Absent entry may carry NOTHING (block.go:664-673). */
    {
        cmt_commit_sig_t bad = g_sigs[0];

        bad.validator_address_len = 32;
        memcpy(bad.validator_address, g_addr, 32);
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "an Absent entry may not carry an address"); OK();
        bad = g_sigs[0];
        bad.timestamp.seconds = 0;   /* the UNIX epoch, not Go's zero */
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "an Absent entry's time must be GO'S zero, and 1970 is not"
              " it"); OK();
        bad = g_sigs[0];
        bad.signature_len = 1;
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "an Absent entry may not carry a signature"); OK();
        bad = g_sigs[1];
        bad.block_id_flag = 4;
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "an unknown flag is refused"); OK();
        bad = g_sigs[1];
        bad.validator_address_len = 20;
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "a non-Absent entry needs a 32-byte address"); OK();
        bad = g_sigs[1];
        bad.signature_len = 0;
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "and a signature"); OK();
        bad = g_sigs[1];
        bad.signature_len = (size_t)CMT_MAX_SIGNATURE_SIZE + 1u;
        CHECK(cmt_commit_sig_validate_basic(&bad) == CMT_REJECT,
              "which may not exceed 4627 bytes"); OK();
    }

    /* The EMPTY commit of height 1 hashes to H("") — D-19 rev 6 item 4.
     * The struct is zeroed before _init because cmt_pb_commit_init
     * PRESERVES the slot pointer and capacity it finds. */
    memset(&c, 0, sizeof(c));
    cmt_pb_commit_init(&c);
    c.height     = 1;
    c.signatures = g_sigs;
    c.signatures_cap = 4;
    c.signatures_len = 0;
    CHECK(cmt_commit_hash(&c, out) == CMT_OK, "hash the empty commit");
    OK();
    CHECK(memcmp(out, V_COMMIT_EMPTY_HASH, 64) == 0,
          "the empty commit hashes to H(\"\"), NOT to 64 zero bytes"); OK();
    CHECK(memcmp(out, g_empty, 64) == 0,
          "and that is exactly the empty Merkle root"); OK();
    CHECK(cmt_commit_hash(NULL, out) == CMT_HASH_NIL,
          "a NULL commit has a NIL hash"); OK();

    /* Three entries: the leaf is the MARSHALLED CommitSig, address and
     * all, in list order. */
    cmt_pb_block_id_init(&bid);
    set_hash(bid.hash, &bid.hash_len, g_hAA);
    bid.part_set_header.total = 9;
    set_hash(bid.part_set_header.hash, &bid.part_set_header.hash_len,
             g_h99);
    c.height   = 9;
    c.round    = 2;
    c.block_id = bid;
    c.signatures_len = 3;
    CHECK(cmt_commit_hash(&c, out) == CMT_OK, "hash three entries"); OK();
    CHECK(memcmp(out, V_COMMIT_THREE_HASH, 64) == 0,
          "the certificate root is the oracle's"); OK();
    CHECK(cmt_commit_validate_basic(&c) == CMT_OK, "and it validates"); OK();
    CHECK(cmt_commit_size(&c) == 3u, "Size"); OK();
    CHECK(cmt_commit_size(NULL) == 0u, "Size(NULL)"); OK();

    /* Order matters: swapping two entries changes the root. */
    {
        cmt_commit_sig_t tmp = g_sigs[1];
        uint8_t          other[64];

        g_sigs[1] = g_sigs[2];
        g_sigs[2] = tmp;
        CHECK(cmt_commit_hash(&c, other) == CMT_OK, "hash the swap"); OK();
        CHECK(memcmp(other, out, 64) != 0,
              "entry ORDER is part of the certificate root"); OK();
        g_sigs[2] = g_sigs[1];
        g_sigs[1] = tmp;
    }

    /* GetVote rebuilds the precommit behind entry i. */
    CHECK(cmt_commit_get_vote(&c, 1, &v) == CMT_OK, "GetVote"); OK();
    CHECK(v.type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT &&
          v.height == 9 && v.round == 2 && v.validator_index == 1,
          "it carries the commit's height and round"); OK();
    CHECK(cmt_block_id_equals(&v.block_id, &bid),
          "a COMMIT entry votes for the commit's BlockID"); OK();
    CHECK(cmt_commit_get_vote(&c, 2, &v) == CMT_OK, "GetVote nil"); OK();
    CHECK(cmt_block_id_is_zero(&v.block_id),
          "a NIL entry votes for the zero BlockID"); OK();
    CHECK(cmt_commit_get_vote(&c, 3, &v) == CMT_REJECT,
          "an index at Size() refuses where the reference panics"); OK();
    CHECK(cmt_commit_get_vote(&c, -1, &v) == CMT_REJECT,
          "and so does a negative one"); OK();

    /* The per-validator sign bytes differ only in the timestamp. */
    {
        uint8_t sb1[CMT_VOTE_SIGN_BYTES_MAX];
        uint8_t sb2[CMT_VOTE_SIGN_BYTES_MAX];
        size_t  n1, n2;

        CHECK(cmt_commit_vote_sign_bytes(&c, g_chain, 32, 1, sb1,
                                         sizeof(sb1), &n1) == CMT_OK,
              "sign bytes for entry 1"); OK();
        CHECK(cmt_commit_vote_sign_bytes(&c, g_chain, 32, 2, sb2,
                                         sizeof(sb2), &n2) == CMT_OK,
              "sign bytes for entry 2"); OK();
        CHECK(n1 != n2 || memcmp(sb1, sb2, n1) != 0,
              "a NIL vote and a COMMIT vote sign different bytes"); OK();
    }

    /* ValidateBasic at height >= 1. */
    c.signatures_len = 0;
    CHECK(cmt_commit_validate_basic(&c) == CMT_REJECT,
          "a commit at height >= 1 needs signatures"); OK();
    c.signatures_len = 3;
    cmt_pb_block_id_init(&c.block_id);
    CHECK(cmt_commit_validate_basic(&c) == CMT_REJECT,
          "a commit at height >= 1 cannot be for a nil block"); OK();
    c.block_id = bid;
    c.height = -1;
    CHECK(cmt_commit_validate_basic(&c) == CMT_REJECT,
          "a negative height is refused"); OK();
    c.height = 9;
    c.round = -1;
    CHECK(cmt_commit_validate_basic(&c) == CMT_REJECT,
          "a negative round is refused"); OK();
    c.round = 2;

    /* Clone is deep in the signature list. */
    CHECK(cmt_commit_clone(&c, clone_slots, 4, &c2) == CMT_OK, "Clone");
    OK();
    CHECK(c2.signatures == clone_slots && c2.signatures_len == 3u,
          "the clone owns its own slots"); OK();
    for (i = 0; i < 3; i++) {
        CHECK(clone_slots[i].block_id_flag == g_sigs[i].block_id_flag,
              "and the entries were copied");
    }
    OK();
    CHECK(cmt_commit_clone(&c, clone_slots, 2, &c2) == CMT_REJECT,
          "Clone refuses when the storage is too small"); OK();

    /* WrappedExtendedCommit keeps every CommitSig and adds nothing. */
    {
        static cmt_extended_commit_sig_t ecs[4];
        cmt_extended_commit_t            ec;
        cmt_bit_array_t                  ba;

        CHECK(cmt_commit_wrapped_extended_commit(&c, ecs, 4, &ec) == CMT_OK,
              "WrappedExtendedCommit"); OK();
        CHECK(ec.extended_signatures_len == 3u && ec.height == 9,
              "it carries the same entries"); OK();
        CHECK(ecs[1].extension.len == 0u &&
              ecs[1].extension_signature_len == 0u,
              "with EMPTY extension fields"); OK();
        CHECK(cmt_extended_commit_validate_basic(&ec) == CMT_OK,
              "and validates"); OK();

        /* EnsureExtensions (block.go:1121-1128) is the loop over
         * EnsureExtension, and the FIRST refusing entry wins. */
        CHECK(cmt_extended_commit_ensure_extensions(&ec, false) == CMT_OK,
              "with extensions disabled no entry carries either field");
        OK();
        CHECK(cmt_extended_commit_ensure_extensions(&ec, true) == CMT_REJECT,
              "with them enabled the COMMIT entry has no extension"
              " signature, so the loop refuses (block.go:773-778)"); OK();
        {
            cmt_extended_commit_t empty;

            memset(&empty, 0, sizeof(empty));
            CHECK(cmt_extended_commit_ensure_extensions(&empty, true) ==
                  CMT_OK,
                  "an ExtendedCommit with no entries is accepted — the"
                  " reference's range never runs"); OK();
            CHECK(cmt_extended_commit_ensure_extensions(NULL, true) ==
                  CMT_FAULT, "and NULL is a fault"); OK();
        }
        CHECK(cmt_extended_commit_size(&ec) == 3u, "Size"); OK();
        CHECK(cmt_extended_commit_is_commit(&ec), "IsCommit"); OK();
        CHECK(cmt_extended_commit_type(&ec) ==
              (uint8_t)CMT_PB_MSG_TYPE_PRECOMMIT, "Type is Precommit");
        OK();
        CHECK(cmt_extended_commit_get_height(&ec) == 9 &&
              cmt_extended_commit_get_round(&ec) == 2,
              "GetHeight / GetRound"); OK();

        CHECK(cmt_extended_commit_bit_array(&ec, &ba) == CMT_OK,
              "BitArray"); OK();
        CHECK(ba.bits == 3, "three bits"); OK();
        CHECK(cmt_bits_get_index(&ba, 0) == 0,
              "the ABSENT entry's bit is clear"); OK();
        CHECK(cmt_bits_get_index(&ba, 1) == 1 &&
              cmt_bits_get_index(&ba, 2) == 1,
              "and the COMMIT and NIL bits are set — the reference does"
              " NOT look at the BlockID here (block.go:1192-1193)"); OK();

        /* ToCommit drops the extension fields again. */
        CHECK(cmt_extended_commit_to_commit(&ec, clone_slots, 4,
                                            &c2) == CMT_OK, "ToCommit");
        OK();
        CHECK(c2.signatures_len == 3u && c2.height == 9,
              "and keeps the entries"); OK();

        /* An ExtendedCommitSig may not carry a signature-less extension. */
        ecs[1].extension.data = g_sig_s;
        ecs[1].extension.len  = 3;
        CHECK(cmt_ecs_validate_basic(&ecs[1]) == CMT_OK,
              "a COMMIT entry may carry an extension without a signature"
              " — ValidateBasic returns early for it (block.go:760)");
        OK();
        CHECK(cmt_ecs_ensure_extension(&ecs[1], true) == CMT_REJECT,
              "but EnsureExtension(true) demands the signature"); OK();
        CHECK(cmt_ecs_ensure_extension(&ecs[1], false) == CMT_REJECT,
              "and EnsureExtension(false) forbids the extension"); OK();
        CHECK(cmt_extended_commit_ensure_extensions(&ec, false) == CMT_REJECT,
              "and EnsureExtensions propagates that entry's refusal"); OK();
        ecs[2].extension.data = g_sig_s;
        ecs[2].extension.len  = 3;
        CHECK(cmt_ecs_validate_basic(&ecs[2]) == CMT_REJECT,
              "a NIL entry may NOT carry a signature-less extension"); OK();
        ecs[1].extension.len = 0;
        ecs[2].extension.len = 0;
    }
    return 0;
}

/* ══ Data.Hash (block.go:1302-1311) ═══════════════════════════════════ */

static int test_data(void)
{
    cmt_pb_bytes_t txs[3];
    cmt_data_t     d;
    uint8_t        out[64];

    memset(&d, 0, sizeof(d));   /* cmt_pb_data_init preserves txs/txs_cap */
    cmt_pb_data_init(&d);
    d.txs     = txs;
    d.txs_cap = 3;
    d.txs_len = 0;
    CHECK(cmt_data_hash(&d, out) == CMT_OK, "hash no transactions"); OK();
    CHECK(memcmp(out, g_empty, 64) == 0,
          "an empty block's DataHash is H(\"\")"); OK();
    CHECK(cmt_data_hash(NULL, out) == CMT_OK &&
          memcmp(out, g_empty, 64) == 0,
          "and so is a NULL Data's (block.go:1304-1306)"); OK();

    txs[0].data = (const uint8_t *)"tx0";
    txs[0].len  = 3;
    d.txs_len   = 1;
    CHECK(cmt_data_hash(&d, out) == CMT_OK, "hash one transaction"); OK();
    CHECK(memcmp(out, V_DATA_HASH_1, 64) == 0,
          "one transaction gives the oracle's root"); OK();

    txs[1].data = NULL;      /* an EMPTY transaction is still a leaf */
    txs[1].len  = 0;
    txs[2].data = (const uint8_t *)"tx2";
    txs[2].len  = 3;
    d.txs_len   = 3;
    CHECK(cmt_data_hash(&d, out) == CMT_OK, "hash three"); OK();
    CHECK(memcmp(out, V_DATA_HASH_3, 64) == 0,
          "an EMPTY transaction is a real leaf, hashed as SHA3-512(\"\")");
    OK();

    /* Tx.Hash is the leaf, so it is SHA3-512 of the transaction. */
    {
        uint8_t th[64];

        CHECK(cmt_tx_hash((const uint8_t *)"tx0", 3, th) == CMT_OK,
              "Tx.Hash"); OK();
        CHECK(cmt_tx_hash(NULL, 0, th) == CMT_OK &&
              memcmp(th, g_empty, 64) == 0,
              "an empty transaction hashes to SHA3-512(\"\")"); OK();
    }
    return 0;
}

/* ══ MaxDataBytes (block.go:281-321) ══════════════════════════════════ */

static int test_max_data_bytes(void)
{
    int64_t commit4;
    int64_t floor4;
    int64_t v;

    CHECK(cmt_max_commit_bytes(4, &commit4) == CMT_OK, "commit budget");
    OK();
    floor4 = CMT_MAX_OVERHEAD_FOR_BLOCK + CMT_MAX_HEADER_BYTES + commit4;

    CHECK(cmt_max_data_bytes_no_evidence(floor4, 4, &v) == CMT_OK && v == 0,
          "exactly on the boundary the budget for data is ZERO"); OK();
    CHECK(cmt_max_data_bytes_no_evidence(floor4 + 1, 4, &v) == CMT_OK &&
          v == 1, "one byte above it, one byte of data"); OK();
    CHECK(cmt_max_data_bytes_no_evidence(floor4 - 1, 4, &v) == CMT_REJECT,
          "one byte below it REFUSES where the reference PANICS"); OK();
    CHECK(cmt_max_data_bytes(floor4 + 100, 100, 4, &v) == CMT_OK &&
          v == 0, "evidence eats the same budget"); OK();
    CHECK(cmt_max_data_bytes(floor4 + 100, 101, 4, &v) == CMT_REJECT,
          "and pushes it negative"); OK();
    CHECK(cmt_max_data_bytes(1000, -1, 4, &v) == CMT_REJECT,
          "a negative evidence size refuses"); OK();
    CHECK(cmt_max_data_bytes(22020096, 0, 128, &v) == CMT_OK,
          "the default 22 MB block holds a 128-validator commit"); OK();
    CHECK(v > 21000000,
          "and still leaves more than 21 MB for transactions"); OK();
    return 0;
}

/* ══ Block: MakeBlock, fillHeader, ValidateBasic, MakePartSet ═════════ */

static int test_block(void)
{
    static cmt_commit_sig_t sigs[3];
    static cmt_part_t       parts[64];
    cmt_commit_t            last;
    cmt_block_t             b;
    cmt_data_t              d;
    cmt_pb_bytes_t          txs[2];
    cmt_block_id_t          bid;
    cmt_part_set_t          ps;
    cmt_part_set_reader_t   r;
    uint8_t                *scratch;
    uint8_t                *back;
    uint8_t                 hash[64];
    size_t                  mlen;
    size_t                  n;
    int                     rc;

    make_three_sigs();
    memcpy(sigs, g_sigs, sizeof(sigs));

    cmt_pb_block_id_init(&bid);
    set_hash(bid.hash, &bid.hash_len, g_hAA);
    bid.part_set_header.total = 9;
    set_hash(bid.part_set_header.hash, &bid.part_set_header.hash_len,
             g_h99);

    memset(&last, 0, sizeof(last));   /* _init preserves slots/cap */
    cmt_pb_commit_init(&last);
    last.height         = 8;
    last.round          = 1;
    last.block_id       = bid;
    last.signatures     = sigs;
    last.signatures_cap = 3;
    last.signatures_len = 3;

    txs[0].data = (const uint8_t *)"tx0";
    txs[0].len  = 3;
    txs[1].data = (const uint8_t *)"tx2";
    txs[1].len  = 3;
    memset(&d, 0, sizeof(d));         /* _init preserves txs/txs_cap */
    cmt_pb_data_init(&d);
    d.txs     = txs;
    d.txs_cap = 2;
    d.txs_len = 2;

    CHECK(cmt_make_block(9, CMT_BLOCK_PROTOCOL, 0, &d, &last, NULL, &b)
          == CMT_OK, "MakeBlock"); OK();
    CHECK(b.header.height == 9, "the height is set"); OK();
    CHECK(b.header.version.block == CMT_BLOCK_PROTOCOL &&
          b.header.version.app == 0,
          "the version is the HOST's, not a hard-coded constant"); OK();
    CHECK(b.header.last_commit_hash_len == 64u &&
          b.header.data_hash_len == 64u &&
          b.header.evidence_hash_len == 64u,
          "fillHeader computed the three body hashes"); OK();
    CHECK(memcmp(b.header.evidence_hash, g_empty, 64) == 0,
          "an empty evidence list hashes to H(\"\")"); OK();
    {
        uint8_t expect[64];

        CHECK(cmt_commit_hash(&last, expect) == CMT_OK, "commit hash"); OK();
        CHECK(memcmp(b.header.last_commit_hash, expect, 64) == 0,
              "LastCommitHash is the previous commit's root"); OK();
        CHECK(cmt_data_hash(&d, expect) == CMT_OK, "data hash"); OK();
        CHECK(memcmp(b.header.data_hash, expect, 64) == 0,
              "DataHash is the transaction root"); OK();
    }

    /* Block.Hash is nil until the header is complete. */
    CHECK(cmt_block_hash(&b, hash) == CMT_HASH_NIL,
          "a block whose ValidatorsHash is empty has a NIL hash"); OK();
    set_hash(b.header.validators_hash, &b.header.validators_hash_len,
             g_h33);
    set_hash(b.header.next_validators_hash,
             &b.header.next_validators_hash_len, g_h33);
    set_hash(b.header.consensus_hash, &b.header.consensus_hash_len, g_h55);
    set_hash(b.header.last_results_hash, &b.header.last_results_hash_len,
             g_empty);
    memcpy(b.header.chain_id, g_chain, 32);
    b.header.chain_id_len = 32;
    memcpy(b.header.proposer_address, g_addr, 32);
    b.header.proposer_address_len = 32;
    b.header.last_block_id = bid;
    CHECK(cmt_block_hash(&b, hash) == CMT_OK, "now it hashes"); OK();
    CHECK(cmt_block_hashes_to(&b, hash, 64), "HashesTo"); OK();
    CHECK(!cmt_block_hashes_to(&b, hash, 0), "HashesTo(empty) is false");
    OK();
    CHECK(!cmt_block_hashes_to(NULL, hash, 64), "HashesTo(NULL) is false");
    OK();

    CHECK(cmt_block_validate_basic(&b, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "the block is internally consistent"); OK();
    b.header.data_hash[0] ^= 0x01;
    CHECK(cmt_block_validate_basic(&b, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a DataHash that does not match the transactions is refused");
    OK();
    b.header.data_hash[0] ^= 0x01;
    b.header.last_commit_hash[0] ^= 0x01;
    CHECK(cmt_block_validate_basic(&b, CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "a LastCommitHash that does not match the commit is refused");
    OK();
    b.header.last_commit_hash[0] ^= 0x01;
    {
        cmt_commit_t *saved = b.last_commit;

        b.last_commit = NULL;
        CHECK(cmt_block_validate_basic(&b, CMT_BLOCK_PROTOCOL) ==
              CMT_REJECT, "a block with no LastCommit is refused"); OK();
        CHECK(cmt_block_hash(&b, hash) == CMT_HASH_NIL,
              "and its hash is NIL (block.go:131-133)"); OK();
        b.last_commit = saved;
    }

    /* Marshal, split into parts, reassemble. */
    scratch = (uint8_t *)malloc(65536);
    back    = (uint8_t *)malloc(65536);
    CHECK(scratch != NULL && back != NULL, "alloc"); OK();

    CHECK(cmt_block_marshal(&b, scratch, 65536, &mlen) == CMT_OK,
          "marshal the block"); OK();
    CHECK(mlen > 0u && scratch[0] == 0x0a,
          "the block starts with field 1 (header), tag 0a"); OK();
    CHECK(cmt_block_size(&b, back, 65536) == mlen,
          "Size() is the marshalled length"); OK();

    /* Field 4 (last_commit) is a POINTER and is omitted when absent. */
    {
        cmt_commit_t *saved = b.last_commit;
        size_t        shorter;

        b.last_commit = NULL;
        CHECK(cmt_block_marshal(&b, back, 65536, &shorter) == CMT_OK,
              "marshal without a LastCommit"); OK();
        CHECK(shorter < mlen,
              "a nil LastCommit is OMITTED, not written empty"); OK();
        b.last_commit = saved;
    }

    /* A 64-byte part size forces many parts, so the reader has to cross
     * boundaries; see "HOW IT CAN LIE" note 5. */
    CHECK(cmt_block_make_part_set(&b, 64, scratch, 65536, parts, 64,
                                  &ps) == CMT_OK, "MakePartSet"); OK();
    CHECK(cmt_part_set_total(&ps) == (uint32_t)((mlen + 63u) / 64u),
          "the part count is ceil(size / part size)"); OK();
    CHECK(cmt_part_set_is_complete(&ps), "and every part is present"); OK();
    CHECK(cmt_part_set_byte_size(&ps) == (int64_t)mlen,
          "the byte size is the marshalled block"); OK();

    CHECK(cmt_part_set_get_reader(&ps, &r) == CMT_OK, "GetReader"); OK();
    CHECK(cmt_part_set_reader_read(&r, back, 65536, &n) == CMT_OK &&
          n == mlen, "read it all back"); OK();
    CHECK(memcmp(back, scratch, mlen) == 0,
          "the block survives marshal → split → reassemble unchanged");
    OK();

    /* Every part's proof verifies against the header's root. */
    {
        cmt_part_set_header_t hdr;
        uint32_t              i;

        CHECK(cmt_part_set_header(&ps, &hdr) == CMT_OK, "Header()"); OK();
        for (i = 0; i < hdr.total; i++) {
            const cmt_part_t *p = cmt_part_set_get_part(&ps, i);
            CHECK(p != NULL, "every part is retrievable");
            rc = cmt_proof_verify(&p->proof, hdr.hash, p->bytes.data,
                                  p->bytes.len);
            CHECK(rc == CMT_OK, "and its proof verifies against the root");
        }
        OK();
    }

    /* Too little storage for the parts refuses rather than overflowing. */
    CHECK(cmt_block_make_part_set(&b, 64, scratch, 65536, parts, 2, &ps)
          == CMT_REJECT, "too few part slots refuses"); OK();
    /* And a scratch buffer that cannot hold the block refuses. */
    CHECK(cmt_block_make_part_set(&b, 64, scratch, 8, parts, 64, &ps)
          == CMT_REJECT, "a scratch buffer that is too small refuses");
    OK();

    free(scratch);
    free(back);
    return 0;
}

int main(void)
{
    fixtures();
    if (test_constants() != 0) return 1;
    if (test_block_id() != 0) return 1;
    if (test_header() != 0) return 1;
    if (test_commit() != 0) return 1;
    if (test_data() != 0) return 1;
    if (test_max_data_bytes() != 0) return 1;
    if (test_block() != 0) return 1;
    printf("test_cmt_block: %d checks OK\n", g_checks);
    return 0;
}
