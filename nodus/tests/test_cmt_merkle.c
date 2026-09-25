/**
 * Nodus — cometbft @709fd12b C port, wave R1-A: `crypto/merkle` tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the Merkle tree that produces DataHash, LastCommitHash,
 * ValidatorsHash, LastResultsHash, EvidenceHash and Header.Hash is the
 * reference's RFC 6962 tree with SHA3-512 substituted for SHA-256. If this
 * file failed, one of these would be false:
 *   · the empty tree is H(""), a one-item tree is H(0x00 ‖ item), and an
 *     inner node is H(0x01 ‖ left ‖ right) — the three shapes every root
 *     in the chain is built from;
 *   · getSplitPoint is the largest power of two STRICTLY below n, which is
 *     what makes the tree RFC 6962 rather than a naive balanced tree;
 *   · the roots for n = 0, 1, 2, 3, 5, 8 are the frozen values, so a
 *     change in split rule, prefix or hash cannot pass unnoticed;
 *   · the recursive and the iterative implementations agree for every
 *     n in 0..16 — two different algorithms, one answer;
 *   · every index of a 5-leaf tree has an inclusion proof that verifies
 *     against the root, and TAMPERING WITH EITHER the leaf or any single
 *     aunt makes verification FAIL. That is the property an attacker
 *     attacks: a proof must not verify for a value that is not in the
 *     tree;
 *   · ValidateBasic refuses a negative total, a negative index, a leaf
 *     hash that is not 64 bytes, more than 100 aunts, and an aunt that is
 *     not 64 bytes;
 *   · computeHashFromAunts refuses index >= total, a negative index, a
 *     non-positive total, and the wrong number of aunts — the cases where
 *     a literal C translation of the Go would have indexed out of bounds.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no RNG. Safe under `ctest -j`. Peak allocation is a
 * few kilobytes (the proof arena for 5 leaves); everything is freed.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The SHA3-512 roots below are a SELF-CONSISTENT FREEZE, NOT AN
 *     EXTERNAL ORACLE FOR THE DESIGN. cometbft publishes SHA-256 vectors;
 *     no published vector exists for this tree with SHA3-512, because the
 *     hash substitution is ours. They were computed with python3
 *     hashlib.sha3_512 in shared/dnac/tests/cmt_pb_oracle.py, an
 *     implementation independent of shared/crypto/hash/qgp_sha3.c, so they
 *     pin two things: that our SHA3-512 agrees with an independent
 *     FIPS-202 implementation, and that the tree shape has not drifted.
 *     They do NOT establish that the shape is the reference's — only
 *     reading crypto/merkle/{hash,tree,proof}.go against this port can.
 *  2. The recursive-vs-iterative agreement is checked for n in 0..16 ONLY.
 *     Agreement outside that range is not tested here; the oracle checked
 *     0..129 while the port was written. Neither is a proof for all n.
 *  3. Nothing here exercises a 1601-leaf part set or a 128-leaf validator
 *     set. It proves the ALGEBRA of the tree, not any size limit.
 *  4. cmt_merkle_hash_from_byte_slices recurses; a stack-depth failure at
 *     a size this file never builds would not be caught here.
 *
 * @file test_cmt_merkle.c
 */

#include "dnac/cmt_merkle.h"
#include "dnac/cmt_tmhash.h"

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

/* ── frozen values, from shared/dnac/tests/cmt_pb_oracle.py ─────────── */

static const char H_EMPTY[] =
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
static const char H_NIL_LEAF[] =
    "7127aab211f82a18d06cf7578ff49d5089017944139aa60d8bee057811a15fb5"
    "5a53887600a3eceba004de51105139f32506fe5b53e1913bfa6b32e716fe97da";
/* leaf(BlockID{zero}.marshal()) = SHA3-512(00 12 00) — the header leaf a
 * zero LastBlockID produces (K-1 rev 2 rule d). */
static const char H_LEAF_BLOCKID_ZERO[] =
    "6870f40502a5f5436f150b9b6e8c8da3c26915c003c0a7f48407fae866f6ac89"
    "fba3dccdd573ffaa1789f21469483f090aa3adb071f65c90cc6f19ab41068b65";

/* Roots over items[i] = the single byte i, for i in [0, n). */
static const char ROOT_0[] =
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
static const char ROOT_1[] =
    "71cb4a0b4d323a3d9d6f8188db4d3266a298053c660a5152afebd0782d07820d"
    "7af7e4b1f327e150753fd5cc84b3cf949f33f7a64d62cd764c154f3eec100f7d";
static const char ROOT_2[] =
    "bbac954554b0bb2d052c4b8104e61d09b1671096ae78637e9d076fdf4d0faf94"
    "aeaebc5ae45041270abe17b32cb5c0bc4ac88e2922f4ecf0c9354095b85a09e4";
static const char ROOT_3[] =
    "b3661857cc661e80ee314a31b61710fc9fa6fee5f8c657f2bff72c8a995bde8f"
    "45f3c8bf5971b71b517b9523cbb7574e4ad757ba99facd095cdaf8f65d30b648";
static const char ROOT_5[] =
    "a76d96e3251e321c6b2e56adf453f0bf1798a7f230e58dac7c037459631f7ef1"
    "f8852c41ae64709b9bef6438e11dde3ef5e9cc4a990a5a952b3103b44211ee5c";
static const char ROOT_8[] =
    "50ed533423cab2e9a7c8f0ae817f72e9bfab19e7433890d14d7d7c90039051df"
    "bd2557bd5b4dab90f6df403ef72ad15b53932e5233a5ae238871aa856a59a915";

/* ── fixtures ───────────────────────────────────────────────────────── */

static uint8_t g_item_bytes[8];
static cmt_merkle_item_t g_items[8];

static void build_items(void)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        g_item_bytes[i] = (uint8_t)i;
        g_items[i].data = &g_item_bytes[i];
        g_items[i].len  = 1;
    }
}

static int root_is(size_t n, const char *want, const char *what)
{
    uint8_t h[CMT_TMHASH_SIZE];
    char    hex[2 * CMT_TMHASH_SIZE + 1];

    if (cmt_merkle_hash_from_byte_slices(g_items, n, h) != CMT_OK) {
        fprintf(stderr, "root(%zu) failed: %s\n", n, what);
        return 0;
    }
    to_hex(h, sizeof(h), hex);
    if (strcmp(hex, want) != 0) {
        fprintf(stderr, "root(%zu) mismatch (%s)\n  got  %s\n  want %s\n",
                n, what, hex, want);
        return 0;
    }
    return 1;
}

/* ── the three hash shapes ──────────────────────────────────────────── */

static int test_hash_shapes(void)
{
    uint8_t h[CMT_TMHASH_SIZE];
    uint8_t l[CMT_TMHASH_SIZE];
    uint8_t r[CMT_TMHASH_SIZE];
    uint8_t inner[CMT_TMHASH_SIZE];
    uint8_t manual[CMT_TMHASH_SIZE];
    uint8_t buf[1 + 2 * CMT_TMHASH_SIZE];
    char    hex[2 * CMT_TMHASH_SIZE + 1];
    static const uint8_t blockid_zero[2] = { 0x12, 0x00 };

    CHECK(cmt_merkle_empty_hash(h) == CMT_OK, "empty_hash");
    to_hex(h, sizeof(h), hex);
    CHECK(strcmp(hex, H_EMPTY) == 0, "emptyHash != SHA3-512(\"\")");
    OK();

    /* The nil leaf: what cdcEncode's nil-for-empty rule hashes to. A NULL
     * pointer with length 0 and a valid pointer with length 0 must give
     * the same answer — the reference's leafHash(nil) and leafHash([]). */
    CHECK(cmt_merkle_leaf_hash(NULL, 0, h) == CMT_OK, "leaf_hash(nil)");
    to_hex(h, sizeof(h), hex);
    CHECK(strcmp(hex, H_NIL_LEAF) == 0, "leafHash(nil) != SHA3-512(00)");
    CHECK(cmt_merkle_leaf_hash(buf, 0, l) == CMT_OK, "leaf_hash(empty)");
    CHECK(memcmp(h, l, sizeof(h)) == 0, "leafHash(nil) != leafHash([])");
    OK();

    CHECK(cmt_merkle_leaf_hash(blockid_zero, sizeof(blockid_zero), h)
          == CMT_OK, "leaf_hash(blockid zero)");
    to_hex(h, sizeof(h), hex);
    CHECK(strcmp(hex, H_LEAF_BLOCKID_ZERO) == 0,
          "leaf(zero BlockID marshal) drifted");
    OK();

    /* innerHash is exactly H(0x01 ‖ left ‖ right) — built here by hand,
     * WITHOUT the helper, so a change to the prefix cannot hide. */
    memset(l, 0xA5, sizeof(l));
    memset(r, 0x5A, sizeof(r));
    CHECK(cmt_merkle_inner_hash(l, r, inner) == CMT_OK, "inner_hash");
    buf[0] = 0x01;
    memcpy(buf + 1, l, CMT_TMHASH_SIZE);
    memcpy(buf + 1 + CMT_TMHASH_SIZE, r, CMT_TMHASH_SIZE);
    CHECK(cmt_tmhash_sum(buf, sizeof(buf), manual) == CMT_OK, "sum");
    CHECK(memcmp(inner, manual, sizeof(inner)) == 0,
          "innerHash is not H(0x01 || l || r)");
    OK();

    /* Order matters: swapping the children must change the node. */
    CHECK(cmt_merkle_inner_hash(r, l, manual) == CMT_OK, "inner_hash swap");
    CHECK(memcmp(inner, manual, sizeof(inner)) != 0,
          "innerHash is order-independent — the tree would be malleable");
    OK();
    return 0;
}

/* ── getSplitPoint ──────────────────────────────────────────────────── */

static int test_split_point(void)
{
    /* The reference's rule: the largest power of two STRICTLY less than
     * length. Note 4 -> 2 and 8 -> 4: an exact power of two halves again
     * (tree.go:108-110), which is what keeps the LEFT subtree perfect. */
    static const struct { int64_t n; int64_t k; } tbl[] = {
        { 1, 0 }, { 2, 1 }, { 3, 2 }, { 4, 2 }, { 5, 4 }, { 6, 4 },
        { 7, 4 }, { 8, 4 }, { 9, 8 }, { 100, 64 }, { 1601, 1024 },
    };
    size_t i;

    for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        int64_t got = cmt_merkle_get_split_point(tbl[i].n);

        if (got != tbl[i].k) {
            fprintf(stderr, "getSplitPoint(%lld) = %lld, want %lld\n",
                    (long long)tbl[i].n, (long long)got,
                    (long long)tbl[i].k);
            return 1;
        }
    }
    OK();

    /* Where the reference panics (length < 1) this returns -1. */
    CHECK(cmt_merkle_get_split_point(0) == -1, "split(0) must be -1");
    CHECK(cmt_merkle_get_split_point(-1) == -1, "split(-1) must be -1");
    CHECK(cmt_merkle_get_split_point(INT64_MIN) == -1, "split(min)");
    OK();
    return 0;
}

/* ── frozen roots + the two implementations ─────────────────────────── */

static int test_roots(void)
{
    size_t n;

    CHECK(root_is(0, ROOT_0, "empty tree"), "root 0");
    CHECK(root_is(1, ROOT_1, "single leaf"), "root 1");
    CHECK(root_is(2, ROOT_2, "two leaves"), "root 2");
    CHECK(root_is(3, ROOT_3, "odd split"), "root 3");
    CHECK(root_is(5, ROOT_5, "split at 4"), "root 5");
    CHECK(root_is(8, ROOT_8, "perfect tree"), "root 8");
    OK();

    /* The empty root IS emptyHash, not a leaf of nothing. */
    {
        uint8_t a[CMT_TMHASH_SIZE];
        uint8_t b[CMT_TMHASH_SIZE];

        CHECK(cmt_merkle_hash_from_byte_slices(NULL, 0, a) == CMT_OK,
              "root(NULL, 0)");
        CHECK(cmt_merkle_empty_hash(b) == CMT_OK, "empty");
        CHECK(memcmp(a, b, sizeof(a)) == 0, "root(0) != emptyHash");
        OK();
    }

    /* One leaf is a LEAF, never a bare hash of the item. */
    {
        uint8_t a[CMT_TMHASH_SIZE];
        uint8_t b[CMT_TMHASH_SIZE];

        CHECK(cmt_merkle_hash_from_byte_slices(g_items, 1, a) == CMT_OK,
              "root 1");
        CHECK(cmt_merkle_leaf_hash(g_items[0].data, g_items[0].len, b)
              == CMT_OK, "leaf 0");
        CHECK(memcmp(a, b, sizeof(a)) == 0, "root(1) != leafHash(item0)");
        CHECK(cmt_tmhash_sum(g_items[0].data, 1, b) == CMT_OK, "sum");
        CHECK(memcmp(a, b, sizeof(a)) != 0,
              "root(1) == H(item) — the 0x00 leaf prefix is missing");
        OK();
    }

    /* Recursive and iterative agree for every n in 0..16. Only 0..8 have
     * distinct items here, so the tail repeats bytes — which is fine, the
     * point is that the two algorithms fold the same list identically. */
    for (n = 0; n <= 16; n++) {
        cmt_merkle_item_t big[16];
        uint8_t           a[CMT_TMHASH_SIZE];
        uint8_t           b[CMT_TMHASH_SIZE];
        size_t            i;

        for (i = 0; i < n; i++) {
            big[i] = g_items[i % 8];
        }
        CHECK(cmt_merkle_hash_from_byte_slices(big, n, a) == CMT_OK,
              "recursive");
        CHECK(cmt_merkle_hash_from_byte_slices_iterative(big, n, b)
              == CMT_OK, "iterative");
        if (memcmp(a, b, sizeof(a)) != 0) {
            fprintf(stderr,
                    "recursive != iterative at n = %zu\n", n);
            return 1;
        }
    }
    OK();

    /* Leaf ORDER is part of the root: swapping two leaves must change it. */
    {
        cmt_merkle_item_t swapped[5];
        uint8_t           a[CMT_TMHASH_SIZE];
        uint8_t           b[CMT_TMHASH_SIZE];
        size_t            i;

        for (i = 0; i < 5; i++) {
            swapped[i] = g_items[i];
        }
        swapped[0] = g_items[1];
        swapped[1] = g_items[0];
        CHECK(cmt_merkle_hash_from_byte_slices(g_items, 5, a) == CMT_OK, "a");
        CHECK(cmt_merkle_hash_from_byte_slices(swapped, 5, b) == CMT_OK, "b");
        CHECK(memcmp(a, b, sizeof(a)) != 0,
              "swapping two leaves left the root unchanged");
        OK();
    }
    return 0;
}

/* ── proofs ─────────────────────────────────────────────────────────── */

static int test_proofs(void)
{
    uint8_t     root[CMT_TMHASH_SIZE];
    uint8_t     want_root[CMT_TMHASH_SIZE];
    cmt_proof_t proofs[8];
    char        hex[2 * CMT_TMHASH_SIZE + 1];
    size_t      n;

    for (n = 1; n <= 8; n++) {
        size_t i;

        CHECK(cmt_merkle_proofs_from_byte_slices(g_items, n, root, proofs)
              == CMT_OK, "proofs_from_byte_slices");
        CHECK(cmt_merkle_hash_from_byte_slices(g_items, n, want_root)
              == CMT_OK, "root");
        CHECK(memcmp(root, want_root, sizeof(root)) == 0,
              "ProofsFromByteSlices root != HashFromByteSlices root");

        for (i = 0; i < n; i++) {
            CHECK(proofs[i].total == (int64_t)n, "proof total");
            CHECK(proofs[i].index == (int64_t)i, "proof index");
            CHECK(proofs[i].leaf_hash_len == CMT_TMHASH_SIZE, "leaf len");
            CHECK(cmt_proof_validate_basic(&proofs[i]) == CMT_OK,
                  "a proof we built must pass ValidateBasic");
            CHECK(cmt_proof_verify(&proofs[i], root, g_items[i].data,
                                   g_items[i].len) == CMT_OK,
                  "a proof we built must verify");
        }
    }
    OK();

    /* The 5-leaf case, pinned: root and the aunt counts. Leaf 4 sits alone
     * on the right of the split at 4, so it has ONE aunt while the others
     * have three — the asymmetry the RFC 6962 split creates. */
    CHECK(cmt_merkle_proofs_from_byte_slices(g_items, 5, root, proofs)
          == CMT_OK, "proofs 5");
    to_hex(root, sizeof(root), hex);
    CHECK(strcmp(hex, ROOT_5) == 0, "5-leaf proof root drifted");
    CHECK(proofs[0].aunts_len == 3, "proof[0] aunts");
    CHECK(proofs[1].aunts_len == 3, "proof[1] aunts");
    CHECK(proofs[2].aunts_len == 3, "proof[2] aunts");
    CHECK(proofs[3].aunts_len == 3, "proof[3] aunts");
    CHECK(proofs[4].aunts_len == 1, "proof[4] aunts");
    OK();

    /* ── the attack cases ── */

    /* A proof must not verify for a leaf that is not the one it proves. */
    {
        uint8_t other = 0x99;

        CHECK(cmt_proof_verify(&proofs[0], root, &other, 1) == CMT_REJECT,
              "a proof verified for the wrong leaf");
        OK();
    }

    /* Tamper with any single aunt: verification must fail. */
    {
        size_t j;

        for (j = 0; j < proofs[0].aunts_len; j++) {
            cmt_proof_t bad = proofs[0];

            bad.aunts[j][0] ^= 0x01;
            CHECK(cmt_proof_verify(&bad, root, g_items[0].data,
                                   g_items[0].len) == CMT_REJECT,
                  "a proof verified with a corrupted aunt");
        }
        OK();
    }

    /* Tamper with the recorded leaf hash. */
    {
        cmt_proof_t bad = proofs[1];

        bad.leaf_hash[63] ^= 0x80;
        CHECK(cmt_proof_verify(&bad, root, g_items[1].data, g_items[1].len)
              == CMT_REJECT, "a proof verified with a corrupted leaf hash");
        OK();
    }

    /* Tamper with the root being proved against. */
    {
        uint8_t bad_root[CMT_TMHASH_SIZE];

        memcpy(bad_root, root, sizeof(bad_root));
        bad_root[0] ^= 0xFF;
        CHECK(cmt_proof_verify(&proofs[2], bad_root, g_items[2].data,
                               g_items[2].len) == CMT_REJECT,
              "a proof verified against the wrong root");
        OK();
    }

    /* Claim a different position in the same tree. */
    {
        cmt_proof_t bad = proofs[0];

        bad.index = 1;
        CHECK(cmt_proof_verify(&bad, root, g_items[0].data, g_items[0].len)
              == CMT_REJECT, "a proof verified at a moved index");
        OK();
    }

    /* Drop an aunt. */
    {
        cmt_proof_t bad = proofs[0];

        bad.aunts_len--;
        CHECK(cmt_proof_verify(&bad, root, g_items[0].data, g_items[0].len)
              != CMT_OK, "a proof verified with an aunt removed");
        OK();
    }

    /* A NULL root is refused, not dereferenced (proof.go:53-55). */
    CHECK(cmt_proof_verify(&proofs[0], NULL, g_items[0].data, 1)
          == CMT_REJECT, "NULL root must REJECT");
    OK();
    return 0;
}

/* ── ValidateBasic ──────────────────────────────────────────────────── */

static int test_validate_basic(void)
{
    cmt_proof_t p;
    size_t      i;

    memset(&p, 0, sizeof(p));
    p.total         = 1;
    p.index         = 0;
    p.leaf_hash_len = CMT_TMHASH_SIZE;
    CHECK(cmt_proof_validate_basic(&p) == CMT_OK, "baseline must pass");
    OK();

    { cmt_proof_t b = p; b.total = -1;
      CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT, "negative total"); }
    { cmt_proof_t b = p; b.index = -1;
      CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT, "negative index"); }
    { cmt_proof_t b = p; b.leaf_hash_len = 32;
      CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT, "32-byte leaf"); }
    { cmt_proof_t b = p; b.leaf_hash_len = 63;
      CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT, "63-byte leaf"); }
    { cmt_proof_t b = p; b.leaf_hash_len = 0;
      CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT, "empty leaf"); }
    OK();

    /* MaxAunts = 100 exactly: 100 passes, 101 refuses. */
    {
        cmt_proof_t b = p;

        b.aunts_len = CMT_MERKLE_MAX_AUNTS;
        for (i = 0; i < CMT_MERKLE_MAX_AUNTS; i++) {
            b.aunt_len[i] = CMT_TMHASH_SIZE;
        }
        CHECK(cmt_proof_validate_basic(&b) == CMT_OK, "100 aunts must pass");
        b.aunts_len = CMT_MERKLE_MAX_AUNTS + 1;
        CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT,
              "101 aunts must REJECT");
        b.aunts_len = CMT_MERKLE_MAX_AUNTS;
        b.aunt_len[57] = 63;
        CHECK(cmt_proof_validate_basic(&b) == CMT_REJECT,
              "a short aunt must REJECT");
        OK();
    }
    return 0;
}

/* ── computeHashFromAunts edge cases ────────────────────────────────── */

static int test_compute_hash_from_aunts(void)
{
    uint8_t leaf[CMT_TMHASH_SIZE];
    uint8_t out[CMT_TMHASH_SIZE];
    uint8_t aunts[2][CMT_TMHASH_SIZE];

    memset(leaf, 0x11, sizeof(leaf));
    memset(aunts, 0x22, sizeof(aunts));

    /* total == 1 with no aunts is the leaf itself (proof.go:173-177). */
    CHECK(cmt_compute_hash_from_aunts(0, 1, leaf, NULL, 0, out) == CMT_OK,
          "total 1");
    CHECK(memcmp(out, leaf, sizeof(out)) == 0, "total 1 must be the leaf");
    OK();

    /* total == 1 WITH aunts is refused (proof.go:174-176). */
    CHECK(cmt_compute_hash_from_aunts(0, 1, leaf, aunts, 1, out)
          == CMT_REJECT, "total 1 with an aunt must REJECT");
    /* the guard at proof.go:167 */
    CHECK(cmt_compute_hash_from_aunts(1, 1, leaf, NULL, 0, out)
          == CMT_REJECT, "index == total must REJECT");
    CHECK(cmt_compute_hash_from_aunts(5, 2, leaf, NULL, 0, out)
          == CMT_REJECT, "index > total must REJECT");
    CHECK(cmt_compute_hash_from_aunts(-1, 2, leaf, aunts, 1, out)
          == CMT_REJECT, "negative index must REJECT");
    CHECK(cmt_compute_hash_from_aunts(0, 0, leaf, NULL, 0, out)
          == CMT_REJECT, "total 0 must REJECT");
    CHECK(cmt_compute_hash_from_aunts(0, -3, leaf, NULL, 0, out)
          == CMT_REJECT, "negative total must REJECT");
    /* too few aunts for the depth (proof.go:179-181) */
    CHECK(cmt_compute_hash_from_aunts(0, 2, leaf, NULL, 0, out)
          == CMT_REJECT, "total 2 with no aunts must REJECT");
    CHECK(cmt_compute_hash_from_aunts(0, 4, leaf, aunts, 1, out)
          == CMT_REJECT, "total 4 with one aunt must REJECT");
    OK();

    /* total == 2, index 0: root = inner(leaf, aunt). Built by hand. */
    {
        uint8_t want[CMT_TMHASH_SIZE];

        CHECK(cmt_compute_hash_from_aunts(0, 2, leaf, aunts, 1, out)
              == CMT_OK, "total 2 index 0");
        CHECK(cmt_merkle_inner_hash(leaf, aunts[0], want) == CMT_OK, "inner");
        CHECK(memcmp(out, want, sizeof(out)) == 0, "left child placement");

        /* index 1 puts the aunt on the LEFT — the side matters. */
        CHECK(cmt_compute_hash_from_aunts(1, 2, leaf, aunts, 1, out)
              == CMT_OK, "total 2 index 1");
        CHECK(cmt_merkle_inner_hash(aunts[0], leaf, want) == CMT_OK, "inner");
        CHECK(memcmp(out, want, sizeof(out)) == 0, "right child placement");
        OK();
    }
    return 0;
}

/* ── trails / FlattenAunts ──────────────────────────────────────────── */

static int test_trails(void)
{
    cmt_merkle_trails_t t;
    uint8_t             root[CMT_TMHASH_SIZE];

    /* n == 0: the reference returns an empty trail list and a root node
     * holding emptyHash (proof.go:235-236). */
    CHECK(cmt_merkle_trails_from_byte_slices(NULL, 0, &t) == CMT_OK,
          "trails 0");
    CHECK(t.n == 0, "trails 0 count");
    CHECK(t.root != NULL, "trails 0 root");
    CHECK(cmt_merkle_empty_hash(root) == CMT_OK, "empty");
    CHECK(memcmp(t.root->hash, root, sizeof(root)) == 0,
          "trails 0 root != emptyHash");
    cmt_merkle_trails_free(&t);
    OK();

    /* n == 1: the single node is BOTH the trail and the root, and it has
     * no siblings — so FlattenAunts returns nothing. */
    CHECK(cmt_merkle_trails_from_byte_slices(g_items, 1, &t) == CMT_OK,
          "trails 1");
    CHECK(t.trails[0] == t.root, "trails 1: leaf must be the root");
    {
        uint8_t aunts[CMT_MERKLE_MAX_AUNTS][CMT_TMHASH_SIZE];
        size_t  n = CMT_MERKLE_MAX_AUNTS;

        CHECK(cmt_proof_node_flatten_aunts(t.root, aunts, &n) == CMT_OK,
              "flatten");
        CHECK(n == 0, "a lone root has no aunts");
    }
    cmt_merkle_trails_free(&t);
    OK();

    /* n == 5: every leaf reaches the same root by walking up. */
    CHECK(cmt_merkle_trails_from_byte_slices(g_items, 5, &t) == CMT_OK,
          "trails 5");
    {
        size_t i;

        for (i = 0; i < 5; i++) {
            const cmt_proof_node_t *p = t.trails[i];

            while (p->parent != NULL) {
                p = p->parent;
            }
            CHECK(p == t.root, "a leaf's ancestry did not end at the root");
            /* Exactly one of left/right is set on every non-root node. */
            CHECK((t.trails[i]->left != NULL) !=
                  (t.trails[i]->right != NULL),
                  "a leaf must have exactly one sibling");
        }
    }
    /* A capacity of zero is REJECTed, not written past. */
    {
        uint8_t aunts[1][CMT_TMHASH_SIZE];
        size_t  n = 0;

        CHECK(cmt_proof_node_flatten_aunts(t.trails[0], aunts, &n)
              == CMT_REJECT, "zero capacity must REJECT");
    }
    cmt_merkle_trails_free(&t);
    CHECK(t.arena == NULL && t.trails == NULL && t.n == 0,
          "free must zero the struct");
    OK();
    return 0;
}

int main(void)
{
    build_items();

    if (test_hash_shapes() != 0) { return 1; }
    if (test_split_point() != 0) { return 1; }
    if (test_roots() != 0) { return 1; }
    if (test_proofs() != 0) { return 1; }
    if (test_validate_basic() != 0) { return 1; }
    if (test_compute_hash_from_aunts() != 0) { return 1; }
    if (test_trails() != 0) { return 1; }

    printf("test_cmt_merkle: OK (%d groups)\n", g_checks);
    return 0;
}
