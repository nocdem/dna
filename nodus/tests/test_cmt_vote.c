/**
 * Nodus — cometbft @709fd12b C port, wave R1-B: `types/vote.go`,
 * `types/proposal.go` and `types/canonical.go` (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the bytes a validator signs are the reference's, and that a vote or
 * a proposal is refused wherever the reference refuses it. If this file
 * failed, one of these would be false:
 *   · VoteSignBytes over the REV 3.2 golden case — PRECOMMIT, height 1,
 *     round 0, nil BlockID, Go's zero time, chain id "ab" — is the
 *     29 bytes `1c 08 02 11 …`, i.e. the varint length prefix, the
 *     sfixed64 height, NO block id field (a zero BlockID canonicalizes to
 *     nil) and the eleven-byte zero timestamp;
 *   · VoteSignBytes over a full vote, and ProposalSignBytes with POLRound
 *     -1 and 0, are the bytes an independent python oracle computes —
 *     POLRound -1 widening to a ten-byte int64 varint is the whole point
 *     of the CanonicalProposal re-typing;
 *   · a REAL ML-DSA-87 key pair signs and verifies a vote and a proposal,
 *     and verification FAILS on a single flipped sign byte, on a wrong
 *     chain id, and on a vote whose ValidatorAddress is not the address
 *     derived from the key;
 *   · Vote.ValidateBasic rejects each of: a proposal type, height 0, a
 *     negative round, a half-filled BlockID, a wrong-width address, a
 *     negative index, a missing signature, an over-long signature, an
 *     extension on a prevote, and an extension without its signature;
 *   · Proposal.ValidateBasic rejects a non-proposal type, a negative
 *     height/round, POLRound < -1, an INCOMPLETE BlockID, a missing
 *     signature and an over-long one;
 *   · CommitSig()/ExtendedCommitSig() map a complete BlockID to COMMIT, a
 *     zero one to NIL, a NULL vote to ABSENT, and REFUSE a half-filled
 *     one where the reference panics;
 *   · SignAndCheckVote adopts the timestamp the signer returned
 *     (vote.go:451) and refuses the four malformed-extension cases,
 *     marking only a signer failure recoverable.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock. It uses `qgp_dsa87_keypair_derand` with
 * fixed seeds, so it draws no randomness of its own. Safe under
 * `ctest -j`. Every buffer is a local or a file-scope array; nothing is
 * malloc'd here except inside cmt_vote_extension_sign_bytes.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The sign-byte vectors come from shared/dnac/tests/
 *     cmt_block_oracle.py and shared/dnac/tests/cmt_pb_oracle.py, written
 *     from the pinned .proto files and the K-1 rev 2 rules — NOT from
 *     cometbft's own test vectors, which do not exist for a 32-byte chain
 *     id and a 64-byte hash. A green proves that two independent
 *     implementations of the same reading agree; only reading vote.go,
 *     proposal.go and canonical.go establishes that the reading is right.
 *  2. ML-DSA-87 signing is HEDGED: signing the same message twice gives
 *     different bytes. No signature is ever frozen or compared for
 *     equality here — every real-key assertion is on a VERIFY OUTCOME.
 *     Keys are derandomized, so the derived addresses are reproducible.
 *  3. `cmt_pubkey_address` is checked against a hand-computed SHA3-512
 *     truncation, not against `nodus_chain_config_derive_witness_id`:
 *     shared/dnac must not link nodus/. If that function ever changes,
 *     this file will NOT notice — the two are kept equal by the citation
 *     in cmt_vote.h, not by a test.
 *  4. Nothing here signs through a real privValidator. `cmt_sign_vote_fn`
 *     is exercised with a local stub, so a green says nothing about the
 *     host's signer.
 *
 * @file test_cmt_vote.c
 */

#include "dnac/cmt_vote.h"
#include "dnac/cmt_proposal.h"
#include "dnac/cmt_canonical.h"
#include "dnac/cmt_block.h"

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

/* ══ oracle vectors — cmt_block_oracle.py ═════════════════════════════ */

/* REV 3.2 golden: CanonicalVote{PRECOMMIT, h=1, r=0, nil, zero-ts,
 * chain "ab"} under MarshalDelimited. */
static const uint8_t V_VOTE_SIGN_GOLDEN[29] = {
    0x1c, 0x08, 0x02, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff,
    0x01, 0x32, 0x02, 0x61, 0x62,
};
static const uint8_t V_VOTE_SIGN_FULL[208] = {
    0xce, 0x01, 0x08, 0x02, 0x11, 0x87, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x88,
    0x01, 0x0a, 0x40, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2,
    0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36,
    0x3d, 0x44, 0x4b, 0x52, 0x59, 0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a,
    0x91, 0x98, 0x9f, 0xa6, 0xad, 0xb4, 0xbb, 0xc2, 0xc9, 0xd0, 0xd7, 0xde,
    0xe5, 0xec, 0xf3, 0xfa, 0x01, 0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32,
    0x39, 0x40, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x12, 0x44, 0x08, 0x09, 0x12,
    0x40, 0x99, 0xa0, 0xa7, 0xae, 0xb5, 0xbc, 0xc3, 0xca, 0xd1, 0xd8, 0xdf,
    0xe6, 0xed, 0xf4, 0xfb, 0x02, 0x09, 0x10, 0x17, 0x1e, 0x25, 0x2c, 0x33,
    0x3a, 0x41, 0x48, 0x4f, 0x56, 0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80, 0x87,
    0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb,
    0xe2, 0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f,
    0x36, 0x3d, 0x44, 0x4b, 0x52, 0x2a, 0x0b, 0x08, 0x80, 0xe2, 0xcf, 0xaa,
    0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a, 0x32, 0x20, 0x50, 0x57, 0x5e, 0x65,
    0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9,
    0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea, 0xf1, 0xf8, 0xff, 0x06, 0x0d,
    0x14, 0x1b, 0x22, 0x29,
};
static const uint8_t V_PROPOSAL_SIGN_POLNEG[219] = {
    0xd9, 0x01, 0x08, 0x20, 0x11, 0x87, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x2a, 0x88, 0x01,
    0x0a, 0x40, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2, 0xe9,
    0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36, 0x3d,
    0x44, 0x4b, 0x52, 0x59, 0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91,
    0x98, 0x9f, 0xa6, 0xad, 0xb4, 0xbb, 0xc2, 0xc9, 0xd0, 0xd7, 0xde, 0xe5,
    0xec, 0xf3, 0xfa, 0x01, 0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39,
    0x40, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x12, 0x44, 0x08, 0x09, 0x12, 0x40,
    0x99, 0xa0, 0xa7, 0xae, 0xb5, 0xbc, 0xc3, 0xca, 0xd1, 0xd8, 0xdf, 0xe6,
    0xed, 0xf4, 0xfb, 0x02, 0x09, 0x10, 0x17, 0x1e, 0x25, 0x2c, 0x33, 0x3a,
    0x41, 0x48, 0x4f, 0x56, 0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80, 0x87, 0x8e,
    0x95, 0x9c, 0xa3, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2,
    0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36,
    0x3d, 0x44, 0x4b, 0x52, 0x32, 0x0b, 0x08, 0x80, 0xe2, 0xcf, 0xaa, 0x06,
    0x10, 0x95, 0x9a, 0xef, 0x3a, 0x3a, 0x20, 0x50, 0x57, 0x5e, 0x65, 0x6c,
    0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0,
    0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea, 0xf1, 0xf8, 0xff, 0x06, 0x0d, 0x14,
    0x1b, 0x22, 0x29,
};
static const uint8_t V_PROPOSAL_SIGN_POL0[208] = {
    0xce, 0x01, 0x08, 0x20, 0x11, 0x87, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x88,
    0x01, 0x0a, 0x40, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb, 0xe2,
    0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f, 0x36,
    0x3d, 0x44, 0x4b, 0x52, 0x59, 0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a,
    0x91, 0x98, 0x9f, 0xa6, 0xad, 0xb4, 0xbb, 0xc2, 0xc9, 0xd0, 0xd7, 0xde,
    0xe5, 0xec, 0xf3, 0xfa, 0x01, 0x08, 0x0f, 0x16, 0x1d, 0x24, 0x2b, 0x32,
    0x39, 0x40, 0x47, 0x4e, 0x55, 0x5c, 0x63, 0x12, 0x44, 0x08, 0x09, 0x12,
    0x40, 0x99, 0xa0, 0xa7, 0xae, 0xb5, 0xbc, 0xc3, 0xca, 0xd1, 0xd8, 0xdf,
    0xe6, 0xed, 0xf4, 0xfb, 0x02, 0x09, 0x10, 0x17, 0x1e, 0x25, 0x2c, 0x33,
    0x3a, 0x41, 0x48, 0x4f, 0x56, 0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80, 0x87,
    0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4, 0xdb,
    0xe2, 0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28, 0x2f,
    0x36, 0x3d, 0x44, 0x4b, 0x52, 0x32, 0x0b, 0x08, 0x80, 0xe2, 0xcf, 0xaa,
    0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a, 0x3a, 0x20, 0x50, 0x57, 0x5e, 0x65,
    0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9,
    0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea, 0xf1, 0xf8, 0xff, 0x06, 0x0d,
    0x14, 0x1b, 0x22, 0x29,
};

/* ══ fixtures — the oracle's pat(n, seed): byte i = (seed + 7*i) & 0xFF */

/* A local substring search — memmem is a GNU extension and this file
 * must build wherever the port does. */
static int contains(const uint8_t *hay, size_t hn,
                    const uint8_t *needle, size_t nn)
{
    size_t i;

    if (nn == 0u || hn < nn) {
        return 0;
    }
    for (i = 0; i + nn <= hn; i++) {
        if (memcmp(hay + i, needle, nn) == 0) {
            return 1;
        }
    }
    return 0;
}

static void pat(uint8_t *p, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static uint8_t g_chain[32];     /* pat(32, 0x50) */
static uint8_t g_addr[32];      /* pat(32, 0x40) */
static uint8_t g_bid_hash[64];  /* pat(64, 0xAA) */
static uint8_t g_psh_hash[64];  /* pat(64, 0x99) */
static uint8_t g_sig_s[9];      /* pat(9,  0x60) */

static void fixtures(void)
{
    pat(g_chain, sizeof(g_chain), 0x50);
    pat(g_addr, sizeof(g_addr), 0x40);
    pat(g_bid_hash, sizeof(g_bid_hash), 0xAA);
    pat(g_psh_hash, sizeof(g_psh_hash), 0x99);
    pat(g_sig_s, sizeof(g_sig_s), 0x60);
}

static void make_bid(cmt_block_id_t *bid)
{
    cmt_pb_block_id_init(bid);
    memcpy(bid->hash, g_bid_hash, 64);
    bid->hash_len = 64;
    bid->part_set_header.total = 9;
    memcpy(bid->part_set_header.hash, g_psh_hash, 64);
    bid->part_set_header.hash_len = 64;
}

/* The full vote of the oracle: PRECOMMIT, h=1234567, r=3, complete
 * BlockID, timestamp (1700000000, 123456789), address pat(32,0x40),
 * index 5, signature pat(9,0x60). */
static void make_full_vote(cmt_vote_t *v)
{
    cmt_pb_vote_init(v);
    v->type   = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    v->height = 1234567;
    v->round  = 3;
    make_bid(&v->block_id);
    v->timestamp.seconds = 1700000000;
    v->timestamp.nanos   = 123456789;
    memcpy(v->validator_address, g_addr, 32);
    v->validator_address_len = 32;
    v->validator_index = 5;
    memcpy(v->signature, g_sig_s, sizeof(g_sig_s));
    v->signature_len = sizeof(g_sig_s);
}

static void make_full_proposal(cmt_proposal_t *p, int32_t pol_round)
{
    cmt_pb_proposal_init(p);
    p->type      = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;
    p->height    = 1234567;
    p->round     = 3;
    p->pol_round = pol_round;
    make_bid(&p->block_id);
    p->timestamp.seconds = 1700000000;
    p->timestamp.nanos   = 123456789;
    memcpy(p->signature, g_sig_s, sizeof(g_sig_s));
    p->signature_len = sizeof(g_sig_s);
}

/* ══ sign bytes ═══════════════════════════════════════════════════════ */

static int test_sign_bytes(void)
{
    cmt_vote_t     v;
    cmt_proposal_t p;
    uint8_t        sb[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t         n;

    /* The REV 3.2 golden case. A ZERO BlockID canonicalizes to nil
     * (canonical.go:24-25), so field 4 is ABSENT from the bytes. */
    cmt_pb_vote_init(&v);
    v.type   = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    v.height = 1;
    v.round  = 0;
    CHECK(cmt_vote_sign_bytes((const uint8_t *)"ab", 2, &v, sb, sizeof(sb),
                              &n) == CMT_OK, "golden sign bytes"); OK();
    CHECK(n == sizeof(V_VOTE_SIGN_GOLDEN), "golden length"); OK();
    CHECK(memcmp(sb, V_VOTE_SIGN_GOLDEN, n) == 0,
          "the golden sign bytes are byte-identical"); OK();
    CHECK(sb[0] == 0x1c, "the MarshalDelimited prefix is 1c"); OK();

    make_full_vote(&v);
    CHECK(cmt_vote_sign_bytes(g_chain, 32, &v, sb, sizeof(sb), &n) == CMT_OK,
          "full vote sign bytes"); OK();
    CHECK(n == sizeof(V_VOTE_SIGN_FULL) &&
          memcmp(sb, V_VOTE_SIGN_FULL, n) == 0,
          "the full vote's sign bytes are the oracle's"); OK();
    /* Neither the address nor the index is inside them (canonical.go:54-56). */
    CHECK(!contains(sb, n, g_addr, 32),
          "the validator address is NOT in the sign bytes"); OK();

    make_full_proposal(&p, -1);
    CHECK(cmt_proposal_sign_bytes(g_chain, 32, &p, sb, sizeof(sb),
                                  &n) == CMT_OK, "proposal sign bytes");
    OK();
    CHECK(n == sizeof(V_PROPOSAL_SIGN_POLNEG) &&
          memcmp(sb, V_PROPOSAL_SIGN_POLNEG, n) == 0,
          "POLRound -1 is a ten-byte int64 varint"); OK();

    make_full_proposal(&p, 0);
    CHECK(cmt_proposal_sign_bytes(g_chain, 32, &p, sb, sizeof(sb),
                                  &n) == CMT_OK, "proposal sign bytes");
    OK();
    CHECK(n == sizeof(V_PROPOSAL_SIGN_POL0) &&
          memcmp(sb, V_PROPOSAL_SIGN_POL0, n) == 0,
          "POLRound 0 is omitted entirely"); OK();
    CHECK(sizeof(V_PROPOSAL_SIGN_POLNEG) - sizeof(V_PROPOSAL_SIGN_POL0)
          == 11u,
          "the -1 case is exactly one tag plus ten varint bytes longer");
    OK();

    /* A buffer one byte short refuses rather than truncating. */
    CHECK(cmt_vote_sign_bytes(g_chain, 32, &v, sb,
                              sizeof(V_VOTE_SIGN_FULL) - 1u,
                              &n) == CMT_REJECT,
          "a short buffer refuses"); OK();
    /* A chain id longer than the field refuses. */
    {
        uint8_t big[64];
        memset(big, 0x11, sizeof(big));
        CHECK(cmt_vote_sign_bytes(big, sizeof(big), &v, sb, sizeof(sb),
                                  &n) == CMT_REJECT,
              "an over-long chain id refuses"); OK();
    }
    return 0;
}

/* ══ canonicalization ═════════════════════════════════════════════════ */

static int test_canonical(void)
{
    cmt_pb_block_id_t           bid;
    cmt_pb_canonical_block_id_t cb;
    bool                        has;
    cmt_vote_t                  v;
    cmt_pb_canonical_vote_t     cv;

    cmt_pb_block_id_init(&bid);
    CHECK(cmt_canonicalize_block_id(&bid, &has, &cb) == CMT_OK && !has,
          "a zero BlockID canonicalizes to nil (canonical.go:24-25)"); OK();

    make_bid(&bid);
    CHECK(cmt_canonicalize_block_id(&bid, &has, &cb) == CMT_OK && has,
          "a complete BlockID canonicalizes to a value"); OK();
    CHECK(cb.hash_len == 64 && cb.part_set_header.total == 9,
          "and carries the hash and the part set header"); OK();

    /* A BlockID whose hash is the wrong width fails BlockIDFromProto, and
     * the reference PANICS there; this REJECTS. */
    bid.hash_len = 31;
    CHECK(cmt_canonicalize_block_id(&bid, &has, &cb) == CMT_REJECT,
          "a malformed BlockID refuses where the reference panics"); OK();

    /* CanonicalizeVote keeps the vote's OWN type, unlike the proposal's. */
    make_full_vote(&v);
    v.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    CHECK(cmt_canonicalize_vote(g_chain, 32, &v, &cv) == CMT_OK,
          "canonicalize a prevote"); OK();
    CHECK(cv.type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
          "the vote's type survives canonicalization"); OK();
    CHECK(cv.round == 3 && cv.height == 1234567,
          "height and round widen to int64"); OK();
    return 0;
}

/* ══ real ML-DSA-87 keys ══════════════════════════════════════════════ */

static int test_real_keys(void)
{
    static uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    static uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    static uint8_t pk2[QGP_DSA87_PUBLICKEYBYTES];
    static uint8_t sk2[QGP_DSA87_SECRETKEYBYTES];
    uint8_t        seed[32];
    uint8_t        addr[32];
    uint8_t        full[64];
    uint8_t        sb[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t         n;
    size_t         siglen;
    cmt_vote_t     v;
    cmt_proposal_t p;

    memset(seed, 0x01, sizeof(seed));
    CHECK(qgp_dsa87_keypair_derand(pk, sk, seed) == 0, "keypair 1"); OK();
    memset(seed, 0x02, sizeof(seed));
    CHECK(qgp_dsa87_keypair_derand(pk2, sk2, seed) == 0, "keypair 2"); OK();

    /* The address is the first 32 bytes of SHA3-512(pubkey) — computed
     * here WITHOUT the library helper. */
    CHECK(cmt_pubkey_address(pk, addr) == CMT_OK, "address"); OK();
    CHECK(qgp_sha3_512(pk, sizeof(pk), full) == 0, "hash the key"); OK();
    CHECK(memcmp(addr, full, 32) == 0,
          "Address() is the key hash truncated to 32 bytes"); OK();
    {
        uint8_t addr2[32];
        CHECK(cmt_pubkey_address(pk2, addr2) == CMT_OK, "address 2"); OK();
        CHECK(memcmp(addr, addr2, 32) != 0,
              "two keys give two addresses"); OK();
    }

    /* Sign a vote for real and verify it. */
    make_full_vote(&v);
    memcpy(v.validator_address, addr, 32);
    v.validator_address_len = 32;
    CHECK(cmt_vote_sign_bytes(g_chain, 32, &v, sb, sizeof(sb), &n) == CMT_OK,
          "sign bytes"); OK();
    CHECK(qgp_dsa87_sign(v.signature, &siglen, sb, n, sk) == 0, "sign");
    OK();
    v.signature_len = siglen;
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk) == CMT_OK,
          "a correctly signed vote verifies"); OK();
    CHECK(cmt_vote_validate_basic(&v) == CMT_OK,
          "and it is well-formed"); OK();

    /* A tampered sign byte: flip one bit of the round. Verification must
     * fail, because the round is inside the signed bytes. */
    v.round = 4;
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk) == CMT_REJECT,
          "a changed round breaks the signature"); OK();
    v.round = 3;
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk) == CMT_OK, "restored"); OK();

    /* A wrong chain id: the same vote on another chain must not verify —
     * this is the replay barrier canonicalization exists for. */
    {
        uint8_t other[32];
        memcpy(other, g_chain, 32);
        other[0] ^= 0x01;
        CHECK(cmt_vote_verify(other, 32, &v, pk) == CMT_REJECT,
              "the same vote does not verify on another chain"); OK();
    }

    /* The wrong key: both the address check and the signature would fail;
     * the address check is first (vote.go:220-222). */
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk2) == CMT_REJECT,
          "another validator's key does not verify this vote"); OK();

    /* An address that is not the key's, with a good signature. */
    v.validator_address[0] ^= 0xFF;
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk) == CMT_REJECT,
          "a vote whose address is not derived from the key is refused");
    OK();
    v.validator_address[0] ^= 0xFF;

    /* A flipped signature byte. */
    v.signature[0] ^= 0x01;
    CHECK(cmt_vote_verify(g_chain, 32, &v, pk) == CMT_REJECT,
          "a flipped signature byte is refused"); OK();
    v.signature[0] ^= 0x01;

    /* And a proposal, signed and verified the same way. There is no
     * Proposal.Verify in the reference, so this checks the sign bytes
     * against qgp_dsa87_verify directly. */
    make_full_proposal(&p, -1);
    CHECK(cmt_proposal_sign_bytes(g_chain, 32, &p, sb, sizeof(sb),
                                  &n) == CMT_OK, "proposal sign bytes");
    OK();
    CHECK(qgp_dsa87_sign(p.signature, &siglen, sb, n, sk) == 0,
          "sign the proposal"); OK();
    p.signature_len = siglen;
    CHECK(qgp_dsa87_verify(p.signature, p.signature_len, sb, n, pk) == 0,
          "the proposal signature verifies"); OK();
    CHECK(cmt_proposal_validate_basic(&p) == CMT_OK,
          "and the proposal is well-formed"); OK();
    sb[5] ^= 0x01;
    CHECK(qgp_dsa87_verify(p.signature, p.signature_len, sb, n, pk) != 0,
          "one tampered sign byte breaks the proposal signature"); OK();
    return 0;
}

/* ══ Vote.ValidateBasic (vote.go:275-353) ═════════════════════════════ */

static int test_vote_validate_basic(void)
{
    cmt_vote_t v;
    uint8_t    ext[4] = { 1, 2, 3, 4 };

    make_full_vote(&v);
    CHECK(cmt_vote_validate_basic(&v) == CMT_OK, "the full vote is valid");
    OK();

    v.type = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "PROPOSAL is not a vote type"); OK();
    v.type = (int32_t)CMT_PB_MSG_TYPE_UNKNOWN;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "UNKNOWN is not a vote type"); OK();
    v.type = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;

    v.height = 0;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT, "height 0 is refused");
    OK();
    v.height = -1;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a negative height is refused"); OK();
    v.height = 1234567;

    v.round = -1;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a negative round is refused"); OK();
    v.round = 3;

    /* A half-filled BlockID: hash present, part set header empty. */
    v.block_id.part_set_header.total    = 0;
    v.block_id.part_set_header.hash_len = 0;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a BlockID must be either EMPTY or COMPLETE (vote.go:299-301)");
    OK();
    make_bid(&v.block_id);

    v.validator_address_len = 20;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "20 bytes is the REFERENCE address width, not ours"); OK();
    v.validator_address_len = 33;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "33 bytes is refused"); OK();
    v.validator_address_len = 32;

    v.validator_index = -1;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a negative index is refused"); OK();
    v.validator_index = 5;

    v.signature_len = 0;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a missing signature is refused"); OK();
    v.signature_len = (size_t)CMT_MAX_SIGNATURE_SIZE;
    CHECK(cmt_vote_validate_basic(&v) == CMT_OK,
          "a full-size signature is allowed"); OK();
    v.signature_len = sizeof(g_sig_s);

    /* Extensions belong to non-nil precommits only. */
    v.type          = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    v.extension.data = ext;
    v.extension.len  = sizeof(ext);
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a prevote may not carry an extension"); OK();
    v.extension.data = NULL;
    v.extension.len  = 0;
    v.extension_signature_len = 4;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "a prevote may not carry an extension signature"); OK();
    v.extension_signature_len = 0;
    v.type = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;

    v.extension.data = ext;
    v.extension.len  = sizeof(ext);
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "an extension without its signature is refused (vote.go:347)");
    OK();
    v.extension_signature_len = 4;
    CHECK(cmt_vote_validate_basic(&v) == CMT_OK,
          "with the signature it is allowed"); OK();
    v.extension_signature_len = (size_t)CMT_MAX_SIGNATURE_SIZE + 1u;
    CHECK(cmt_vote_validate_basic(&v) == CMT_REJECT,
          "an over-long extension signature is refused"); OK();

    CHECK(cmt_vote_validate_basic(NULL) == CMT_FAULT, "NULL is a fault");
    OK();

    /* EnsureExtension: a non-nil precommit MUST have one. */
    v.extension_signature_len = 0;
    v.extension.data = NULL;
    v.extension.len  = 0;
    CHECK(cmt_vote_ensure_extension(&v) == CMT_REJECT,
          "EnsureExtension refuses a bare non-nil precommit"); OK();
    v.extension_signature_len = 4;
    CHECK(cmt_vote_ensure_extension(&v) == CMT_OK,
          "and accepts one that has a signature"); OK();
    v.extension_signature_len = 0;
    v.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    CHECK(cmt_vote_ensure_extension(&v) == CMT_OK,
          "a prevote needs none"); OK();
    return 0;
}

/* ══ Proposal.ValidateBasic (proposal.go:48-80) ═══════════════════════ */

static int test_proposal_validate_basic(void)
{
    cmt_proposal_t p;
    cmt_block_id_t bid;
    cmt_time_t     now;

    make_full_proposal(&p, -1);
    CHECK(cmt_proposal_validate_basic(&p) == CMT_OK, "valid"); OK();

    p.type = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "only PROPOSAL is a proposal type"); OK();
    p.type = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;

    p.height = -1;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "a negative height is refused"); OK();
    p.height = 0;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_OK,
          "height 0 IS allowed for a proposal — unlike a vote"); OK();
    p.height = 1234567;

    p.round = -1;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "a negative round is refused"); OK();
    p.round = 3;

    p.pol_round = -2;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "POLRound below -1 is refused"); OK();
    p.pol_round = -1;

    /* An EMPTY BlockID passes ValidateBasic but not IsComplete. */
    cmt_pb_block_id_init(&p.block_id);
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "a proposal needs a COMPLETE BlockID (proposal.go:66-68)"); OK();
    make_bid(&p.block_id);

    p.signature_len = 0;
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "a missing signature is refused"); OK();
    p.signature_len = sizeof(g_sig_s);

    CHECK(cmt_proposal_validate_basic(NULL) == CMT_FAULT, "NULL"); OK();

    /* NewProposal takes the time as a value; nothing reads a clock. */
    make_bid(&bid);
    now.seconds = 1700000000;
    now.nanos   = 5;
    CHECK(cmt_new_proposal(9, 2, -1, &bid, now, &p) == CMT_OK,
          "NewProposal"); OK();
    CHECK(p.type == (int32_t)CMT_PB_MSG_TYPE_PROPOSAL && p.height == 9 &&
          p.round == 2 && p.pol_round == -1 &&
          p.timestamp.seconds == 1700000000 && p.timestamp.nanos == 5,
          "it fills the six fields and adopts the host's time"); OK();
    CHECK(p.signature_len == 0u, "and leaves the proposal unsigned"); OK();
    CHECK(cmt_proposal_validate_basic(&p) == CMT_REJECT,
          "so ValidateBasic refuses it until a signer has run"); OK();
    return 0;
}

/* ══ CommitSig / ExtendedCommitSig from a vote (vote.go:101-138) ══════ */

static int test_commit_sig(void)
{
    cmt_vote_t                v;
    cmt_commit_sig_t          cs;
    cmt_extended_commit_sig_t ecs;
    uint8_t                   ext[3] = { 9, 9, 9 };

    make_full_vote(&v);
    CHECK(cmt_vote_commit_sig(&v, &cs) == CMT_OK, "commit sig"); OK();
    CHECK(cs.block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_COMMIT,
          "a complete BlockID gives a COMMIT entry"); OK();
    CHECK(cs.validator_address_len == 32 && cs.signature_len == 9,
          "it carries the address and the signature"); OK();
    CHECK(cs.timestamp.seconds == 1700000000,
          "and the vote's timestamp"); OK();

    cmt_pb_block_id_init(&v.block_id);
    CHECK(cmt_vote_commit_sig(&v, &cs) == CMT_OK &&
          cs.block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_NIL,
          "a zero BlockID gives a NIL entry"); OK();

    /* Half-filled: the reference PANICS (vote.go:113-115). */
    memcpy(v.block_id.hash, g_bid_hash, 64);
    v.block_id.hash_len = 64;
    CHECK(cmt_vote_commit_sig(&v, &cs) == CMT_REJECT,
          "a half-filled BlockID refuses where the reference panics"); OK();

    CHECK(cmt_vote_commit_sig(NULL, &cs) == CMT_OK &&
          cs.block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT,
          "a NULL vote gives an ABSENT entry"); OK();
    CHECK(cs.validator_address_len == 0u && cs.signature_len == 0u,
          "carrying nothing"); OK();
    CHECK(cs.timestamp.seconds == CMT_TIME_MIN_SECONDS &&
          cs.timestamp.nanos == 0,
          "with GO'S ZERO TIME, not a memset — that is what makes an"
          " Absent entry fifteen wire bytes"); OK();
    CHECK(cmt_commit_sig_validate_basic(&cs) == CMT_OK,
          "and the Absent entry is well-formed"); OK();

    make_full_vote(&v);
    v.extension.data = ext;
    v.extension.len  = sizeof(ext);
    v.extension_signature_len = 5;
    memset(v.extension_signature, 0x77, 5);
    CHECK(cmt_vote_extended_commit_sig(&v, &ecs) == CMT_OK,
          "extended commit sig"); OK();
    CHECK(ecs.commit_sig.block_id_flag ==
          (int32_t)CMT_BLOCK_ID_FLAG_COMMIT,
          "the embedded CommitSig is the same"); OK();
    CHECK(ecs.extension.len == 3u && ecs.extension_signature_len == 5u,
          "and the extension fields are carried"); OK();
    CHECK(cmt_ecs_validate_basic(&ecs) == CMT_OK, "and it validates"); OK();

    CHECK(cmt_vote_extended_commit_sig(NULL, &ecs) == CMT_OK &&
          ecs.commit_sig.block_id_flag ==
          (int32_t)CMT_BLOCK_ID_FLAG_ABSENT &&
          ecs.extension.len == 0u,
          "a NULL vote gives an ABSENT extended entry"); OK();
    return 0;
}

/* ══ SignAndCheckVote (vote.go:408-454) ═══════════════════════════════ */

struct signer_ctx {
    int        calls;
    int        fail;
    bool       emit_ext_sig;
    cmt_time_t stamp;
};

/* A stub privValidator. It does what the reference's does: writes a
 * signature, maybe an extension signature, and REPLACES the timestamp. */
static int stub_sign(void *ctx, const uint8_t *chain_id,
                     size_t chain_id_len, cmt_pb_vote_t *v)
{
    struct signer_ctx *s = (struct signer_ctx *)ctx;
    uint8_t            sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t             n;

    s->calls++;
    if (s->fail) {
        return CMT_FAULT;
    }
    /* Prove the callback really can compute the sign bytes it is given
     * the chain id for. */
    if (cmt_vote_sign_bytes(chain_id, chain_id_len, v, sb, sizeof(sb), &n)
        != CMT_OK) {
        return CMT_REJECT;
    }
    memset(v->signature, 0xC1, 8);
    v->signature_len = 8;
    if (s->emit_ext_sig) {
        memset(v->extension_signature, 0xC2, 6);
        v->extension_signature_len = 6;
    } else {
        v->extension_signature_len = 0;
    }
    v->timestamp = s->stamp;
    return CMT_OK;
}

static int test_sign_and_check(void)
{
    cmt_vote_t        v;
    struct signer_ctx s;
    bool              recoverable;

    memset(&s, 0, sizeof(s));
    s.stamp.seconds = 1800000000;
    s.stamp.nanos   = 42;

    make_full_vote(&v);
    v.signature_len = 0;
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, false,
                                  &recoverable) == CMT_OK,
          "a precommit signs"); OK();
    CHECK(v.signature_len == 8u, "the signature came back"); OK();
    CHECK(v.timestamp.seconds == 1800000000 && v.timestamp.nanos == 42,
          "THE SIGNER'S TIMESTAMP WINS (vote.go:451)"); OK();
    CHECK(v.extension_signature_len == 0u,
          "with extensions disabled the extension signature is dropped");
    OK();

    /* A signer failure is RECOVERABLE (vote.go:419-422). */
    s.fail = 1;
    make_full_vote(&v);
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, false,
                                  &recoverable) != CMT_OK && recoverable,
          "a signer failure is recoverable"); OK();
    s.fail = 0;

    /* A prevote with extensions enabled is non-recoverable (:426-429). */
    make_full_vote(&v);
    v.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, true,
                                  &recoverable) == CMT_REJECT &&
          !recoverable,
          "a prevote with extensions enabled is a caller error"); OK();

    /* An extension signature on a prevote is non-recoverable (:435-438). */
    s.emit_ext_sig = true;
    make_full_vote(&v);
    v.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, false,
                                  &recoverable) == CMT_REJECT &&
          !recoverable,
          "an extension signature on a prevote is malformed"); OK();

    /* A nil precommit may not carry one either. */
    make_full_vote(&v);
    cmt_pb_block_id_init(&v.block_id);
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, false,
                                  &recoverable) == CMT_REJECT &&
          !recoverable,
          "an extension signature on a nil precommit is malformed"); OK();

    /* With extensions enabled, a non-nil precommit KEEPS it. */
    make_full_vote(&v);
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, true,
                                  &recoverable) == CMT_OK,
          "a non-nil precommit with extensions enabled"); OK();
    CHECK(v.extension_signature_len == 6u,
          "and the extension signature is kept"); OK();

    /* With extensions enabled and NO extension signature, it is
     * non-recoverable (:443-446). */
    s.emit_ext_sig = false;
    make_full_vote(&v);
    CHECK(cmt_sign_and_check_vote(&v, stub_sign, &s, g_chain, 32, true,
                                  &recoverable) == CMT_REJECT &&
          !recoverable,
          "a missing extension signature is malformed"); OK();
    return 0;
}

/* ══ VoteFromProto / ToProto (vote.go:81-99, :371-390) ════════════════ */

static int test_vote_proto(void)
{
    cmt_vote_t    v;
    cmt_pb_vote_t pb;
    cmt_vote_t    back;

    make_full_vote(&v);
    CHECK(cmt_vote_to_proto(&v, &pb) == CMT_OK, "to_proto"); OK();
    CHECK(cmt_vote_from_proto(&pb, &back) == CMT_OK, "from_proto"); OK();
    CHECK(back.height == v.height && back.round == v.round &&
          back.validator_index == v.validator_index,
          "the round trip preserves the scalars"); OK();

    /* The asymmetry of vote.go:77-80 versus :82: the comment promises no
     * validation, but a malformed BlockID is still refused. */
    pb.block_id.hash_len = 31;
    CHECK(cmt_vote_from_proto(&pb, &back) == CMT_REJECT,
          "a malformed BlockID is refused despite the 'no validation'"
          " comment"); OK();
    pb.block_id.hash_len = 64;
    pb.signature_len = 0;
    CHECK(cmt_vote_from_proto(&pb, &back) == CMT_OK,
          "but a missing signature is NOT — VoteFromProto really does not"
          " call ValidateBasic"); OK();

    CHECK(cmt_vote_to_proto(NULL, &pb) == CMT_OK && pb.height == 0,
          "a NULL receiver yields the zero vote"); OK();

    /* VotesToProto (vote.go:392-406) DROPS a nil element rather than
     * emitting it — the reference's own comment at :400-402. */
    {
        cmt_vote_t         v2;
        const cmt_vote_t  *list[3];
        cmt_pb_vote_t      dst[3];
        size_t             got = 0;

        make_full_vote(&v2);
        v2.height = v.height + 1;
        list[0] = &v;
        list[1] = NULL;
        list[2] = &v2;
        CHECK(cmt_votes_to_proto(list, 3, dst, 3, &got) == CMT_OK,
              "VotesToProto"); OK();
        CHECK(got == 2u, "the NULL element is DROPPED, not emitted"); OK();
        CHECK(dst[0].height == v.height && dst[1].height == v2.height,
              "and the survivors keep their order"); OK();
        CHECK(cmt_votes_to_proto(list, 3, dst, 1, &got) == CMT_REJECT,
              "too little storage is REFUSED, not overrun"); OK();
        CHECK(cmt_votes_to_proto(NULL, 0, dst, 3, &got) == CMT_OK &&
              got == 0u, "a NULL list is the reference's nil slice"); OK();
    }

    /* Copy shares the extension bytes, as Go's struct copy shares the
     * backing array. */
    {
        uint8_t ext[2] = { 7, 7 };
        v.extension.data = ext;
        v.extension.len  = 2;
        CHECK(cmt_vote_copy(&v, &back) == CMT_OK, "copy"); OK();
        CHECK(back.extension.data == ext,
              "Copy SHARES the extension bytes"); OK();
    }
    return 0;
}

int main(void)
{
    fixtures();
    if (test_sign_bytes() != 0) return 1;
    if (test_canonical() != 0) return 1;
    if (test_vote_validate_basic() != 0) return 1;
    if (test_proposal_validate_basic() != 0) return 1;
    if (test_commit_sig() != 0) return 1;
    if (test_vote_proto() != 0) return 1;
    if (test_sign_and_check() != 0) return 1;
    if (test_real_keys() != 0) return 1;
    printf("test_cmt_vote: %d checks OK\n", g_checks);
    return 0;
}
