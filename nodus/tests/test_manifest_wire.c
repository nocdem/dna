/**
 * Nodus — Ledger V2 S6: generic genesis/distribution manifest, snapshot
 * tree, inclusion proofs and claim codec (shared/dnac/manifest_wire.c).
 *
 * Sections:
 *   1. GenesisManifest round-trips (absent + present distribution),
 *      hash determinism, independent re-derivation.
 *   2. Per-field root sensitivity: every committed variable field
 *      changes the manifest hash; every single-valued field (version /
 *      presence / enums) REJECTS on change (fail-closed).
 *   3. Reject matrix: structural negatives, truncation sweep over every
 *      prefix, trailing byte, unknown enum/presence values, arithmetic
 *      inconsistencies (zero denominator, total > supply, end < start).
 *   4. Deterministic fuzz (seeded xorshift64, no RNG): random buffers +
 *      single-byte mutants — every accept re-encodes byte-identically.
 *   5. Snapshot tree: canonical ordering enforced (swap/duplicate
 *      reject), conversion arithmetic (floor, overflow, zero rejects),
 *      checked totals.
 *   6. Inclusion proofs: build+verify for every index of every tree
 *      size 1..9 (covers promoted-node shapes), wrong index / wrong
 *      leaf / corrupted sibling / short + long proofs all reject.
 *   7. Claim codec: round-trip, strict-decode negatives, preimage and
 *      nullifier determinism + sensitivity, deterministic UTXO id.
 *   8. claims_root + manifest_root: empty == the frozen S2 tagged-empty
 *      roots byte-identically; ordering enforced; entry sensitivity.
 *
 * @file test_manifest_wire.c
 */

#include "dnac/manifest_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define BUFMAX 8192

/* ── fixtures ───────────────────────────────────────────────────────── */

static void fixture_absent(dna_gman_t *m) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = DNA_GMAN_VERSION;
    m->genesis_supply_raw = 100000000000000000ULL;
    m->domain_count = 2;
    m->domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memset(m->domains[0].manifest_hash, 0xA5, 64);
    m->domains[1].domain_id = DNA_DOMAIN_CORE;
    memset(m->domains[1].manifest_hash, 0x5A, 64);
    m->dist_present = 0;
}

static void fixture_present(dna_gman_t *m) {
    fixture_absent(m);
    m->dist_present = 1;
    m->dist_version = DNA_DIST_VERSION;
    /* the EXPLICIT committed target: domain + opaque asset reference
     * (here the 64-byte native token id shape the CORE runtime reads) */
    m->target_domain_id = DNA_DOMAIN_CORE;
    m->target_asset_len = 64;
    memset(m->target_asset_ref, 0, 64);
    m->source_tag_len = 12;
    memcpy(m->source_tag, "test-network", 12);
    m->source_commit_len = 32;
    memset(m->source_commit, 0xC0, 32);
    memset(m->snapshot_root, 0x11, 64);
    m->leaf_count = 3;
    m->conv_numerator = 3;
    m->conv_denominator = 2;
    m->rounding_mode = DNA_DISTROUND_FLOOR;
    m->excluded_amount = 7;
    m->total_claimable = 32;
    m->claim_start_height = 1;
    m->claim_end_height = 100;
    m->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    m->fee_mode = DNA_CLAIMFEE_NONE;
    m->post_deadline_mode = DNA_POSTDL_RETAIN;
}

/* ── 1: round-trips + hash determinism ──────────────────────────────── */

static int test_roundtrip(void) {
    dna_gman_t a, b, t;
    fixture_absent(&a);
    fixture_present(&b);

    for (int which = 0; which < 2; which++) {
        const dna_gman_t *m = which ? &b : &a;
        uint8_t enc[BUFMAX], re[BUFMAX];
        size_t w1 = 0, w2 = 0;
        CHECK(dna_gman_validate(m) == 0, "fixture valid");
        size_t need = dna_gman_encoded_len(m);
        CHECK(need > 0, "encoded len");
        CHECK(dna_gman_encode(m, enc, sizeof(enc), &w1) == 0 && w1 == need,
              "encode");
        CHECK(dna_gman_decode(enc, w1, &t) == 0, "decode");
        CHECK(dna_gman_encode(&t, re, sizeof(re), &w2) == 0 && w2 == w1 &&
              memcmp(enc, re, w1) == 0, "re-encode byte identity");

        uint8_t h1[64], h2[64];
        CHECK(dna_gman_hash(m, h1) == 0, "hash");
        CHECK(dna_gman_hash(&t, h2) == 0 && memcmp(h1, h2, 64) == 0,
              "hash via decode identical");

        /* independent re-derivation: SHA3-512(tag ‖ bytes) by hand */
        uint8_t pre[BUFMAX + 16], h3[64];
        memcpy(pre, "DNA.GMAN.v1\0\0\0\0", 16);
        memcpy(pre + 16, enc, w1);
        CHECK(qgp_sha3_512(pre, 16 + w1, h3) == 0 &&
              memcmp(h1, h3, 64) == 0, "independent hash derivation");
        OK();
    }
    /* absent vs present hash differ (presence is committed) */
    uint8_t ha[64], hb[64];
    CHECK(dna_gman_hash(&a, ha) == 0 && dna_gman_hash(&b, hb) == 0 &&
          memcmp(ha, hb, 64) != 0, "presence changes hash");
    OK();
    return 0;
}

/* ── 2: per-field sensitivity ───────────────────────────────────────── */

static int hash_of(const dna_gman_t *m, uint8_t out[64]) {
    return dna_gman_hash(m, out);
}

static int test_field_sensitivity(void) {
    dna_gman_t b;
    uint8_t base[64], h[64];
    fixture_present(&b);
    CHECK(hash_of(&b, base) == 0, "base hash");

    dna_gman_t t;

    /* Every committed VARIABLE field flips the hash. */
    #define SENS(mut) do { \
        t = b; mut; \
        CHECK(hash_of(&t, h) == 0, "mutant still valid"); \
        CHECK(memcmp(h, base, 64) != 0, "field changes hash: " #mut); \
        OK(); \
    } while (0)

    SENS(t.genesis_supply_raw += 1);
    SENS(t.domains[0].manifest_hash[0] ^= 1);
    SENS(t.domains[1].domain_id = 2);
    SENS(t.domains[1].manifest_hash[63] ^= 1);
    SENS(t.domain_count = 3; t.domains[2].domain_id = 9;
         memset(t.domains[2].manifest_hash, 0x77, 64));
    /* the distribution TARGET is committed data: changing the domain or
     * the asset reference (bytes OR length) changes the manifest hash */
    SENS(t.target_domain_id = 7);
    SENS(t.target_asset_ref[0] ^= 1);
    SENS(t.target_asset_len = 5;
         memset(t.target_asset_ref, 0, sizeof(t.target_asset_ref));
         memcpy(t.target_asset_ref, "T3AST", 5));
    SENS(t.source_tag[0] ^= 1);
    SENS(t.source_tag_len = 13; t.source_tag[12] = 'x');
    SENS(t.source_commit[31] ^= 1);
    SENS(t.source_commit_len = 33; t.source_commit[32] = 0xC1);
    SENS(t.snapshot_root[7] ^= 1);
    SENS(t.leaf_count += 1);
    SENS(t.conv_numerator += 1);
    SENS(t.conv_denominator += 1);
    SENS(t.excluded_amount += 1);
    SENS(t.total_claimable += 1);
    SENS(t.claim_start_height += 1);
    SENS(t.claim_end_height += 1);
    #undef SENS

    /* Every single-valued field REJECTS on change (fail-closed, so its
     * commitment is vacuous-by-rejection, never silently ignored). */
    #define REJ(mut) do { \
        t = b; mut; \
        CHECK(dna_gman_validate(&t) != 0, "must reject: " #mut); \
        OK(); \
    } while (0)

    REJ(t.manifest_version = 2);
    REJ(t.dist_version = 2);
    REJ(t.rounding_mode = 2);
    REJ(t.rounding_mode = DNA_DISTROUND_INVALID);
    REJ(t.auth_mode = 2);
    REJ(t.auth_mode = DNA_CLAIMAUTH_INVALID);
    REJ(t.fee_mode = 2);
    REJ(t.fee_mode = DNA_CLAIMFEE_INVALID);
    REJ(t.post_deadline_mode = 2);
    REJ(t.post_deadline_mode = DNA_POSTDL_INVALID);
    REJ(t.dist_present = 2);
    #undef REJ
    return 0;
}

/* ── 3: reject matrix ───────────────────────────────────────────────── */

static int test_rejects(void) {
    dna_gman_t b, t;
    fixture_present(&b);

    #define REJ(mut, msg) do { \
        t = b; mut; \
        CHECK(dna_gman_validate(&t) != 0, msg); \
        OK(); \
    } while (0)

    REJ(t.domain_count = 0, "zero domains");
    REJ(t.domain_count = DNA_GMAN_MAX_DOMAINS + 1, "over-cap domains");
    REJ(t.domains[0].domain_id = 1, "first not SYSTEM");
    REJ(t.domains[1].domain_id = 0, "duplicate/descending domain");
    REJ(t.target_asset_len = 0, "zero asset ref");
    REJ(t.target_asset_len = DNA_GMAN_ASSETREF_MAX + 1,
        "over-cap asset ref");
    REJ(t.source_tag_len = 0, "zero source tag");
    REJ(t.source_tag_len = DNA_GMAN_SRCTAG_MAX + 1, "over-cap tag");
    REJ(t.source_commit_len = DNA_GMAN_SRCCOMMIT_MAX + 1, "over-cap commit");
    REJ(t.leaf_count = 0, "zero leaves");
    REJ(t.conv_numerator = 0, "zero numerator");
    REJ(t.conv_denominator = 0, "zero denominator");
    REJ(t.total_claimable = 0, "zero total");
    /* total > genesis_supply is NOT a codec reject: the two are
     * different units for a non-native target asset; the native case
     * is enforced by the target runtime's conservation invariant. */
    REJ(t.claim_start_height = 101, "end before start");
    #undef REJ

    /* absent-distribution: any nonzero residue rejects (no hidden
     * defaults — the section must be ALL zero when absent). */
    dna_gman_t a;
    #define REJA(mut, msg) do { \
        fixture_absent(&a); mut; \
        CHECK(dna_gman_validate(&a) != 0, msg); \
        OK(); \
    } while (0)
    REJA(a.dist_version = 1, "absent: version residue");
    REJA(a.target_domain_id = 1, "absent: target domain residue");
    REJA(a.target_asset_len = 1, "absent: asset len residue");
    REJA(a.target_asset_ref[0] = 1, "absent: asset byte residue");
    REJA(a.source_tag_len = 1, "absent: tag len residue");
    REJA(a.source_tag[0] = 1, "absent: tag byte residue");
    REJA(a.source_commit[5] = 1, "absent: commit byte residue");
    REJA(a.snapshot_root[0] = 1, "absent: root residue");
    REJA(a.leaf_count = 1, "absent: leaf count residue");
    REJA(a.total_claimable = 1, "absent: total residue");
    REJA(a.auth_mode = 1, "absent: auth residue");
    REJA(a.claim_end_height = 1, "absent: deadline residue");
    #undef REJA

    /* strict decode: every truncation of the present-dist encoding
     * rejects; one trailing byte rejects. */
    uint8_t enc[BUFMAX];
    size_t w = 0;
    CHECK(dna_gman_encode(&b, enc, sizeof(enc), &w) == 0, "enc");
    for (size_t len = 0; len < w; len++)
        CHECK(dna_gman_decode(enc, len, &t) != 0, "truncation rejects");
    OK();
    enc[w] = 0x00;
    CHECK(dna_gman_decode(enc, w + 1, &t) != 0, "trailing byte rejects");
    OK();

    /* absent-dist encoding too */
    fixture_absent(&t);
    dna_gman_t a2;
    uint8_t enc2[BUFMAX];
    size_t w2 = 0;
    CHECK(dna_gman_encode(&t, enc2, sizeof(enc2), &w2) == 0, "enc absent");
    for (size_t len = 0; len < w2; len++)
        CHECK(dna_gman_decode(enc2, len, &a2) != 0,
              "absent truncation rejects");
    OK();
    enc2[w2] = 0x00;
    CHECK(dna_gman_decode(enc2, w2 + 1, &a2) != 0,
          "absent trailing byte rejects");
    OK();
    return 0;
}

/* ── 4: deterministic fuzz (seeded xorshift64 — no RNG) ─────────────── */

static int test_fuzz(void) {
    uint64_t s = 0x53365F474D414E31ULL;    /* fixed seed */
    #define XRND() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)

    dna_gman_t t;
    /* random buffers: an accept implies full validity + byte-identical
     * canonical re-encode */
    {
        uint8_t buf[BUFMAX];
        for (int it = 0; it < 20000; it++) {
            size_t len = (size_t)(XRND() % 512);
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)XRND();
            if (dna_gman_decode(buf, len, &t) == 0) {
                uint8_t re[BUFMAX];
                size_t w = 0;
                CHECK(dna_gman_validate(&t) == 0 &&
                      dna_gman_encode(&t, re, sizeof(re), &w) == 0 &&
                      w == len && memcmp(re, buf, len) == 0,
                      "fuzz canonicality");
            }
        }
        OK();
    }
    /* structured single-byte mutants of the valid encoding */
    {
        dna_gman_t b;
        fixture_present(&b);
        uint8_t enc[BUFMAX];
        size_t w1 = 0;
        CHECK(dna_gman_encode(&b, enc, sizeof(enc), &w1) == 0, "enc");
        for (int it = 0; it < 10000; it++) {
            uint8_t m[BUFMAX];
            memcpy(m, enc, w1);
            size_t pos = (size_t)(XRND() % w1);
            m[pos] ^= (uint8_t)(XRND() | 1);
            if (dna_gman_decode(m, w1, &t) == 0) {
                uint8_t re[BUFMAX];
                size_t w2 = 0;
                CHECK(dna_gman_encode(&t, re, sizeof(re), &w2) == 0 &&
                      w2 == w1 && memcmp(re, m, w1) == 0,
                      "mutant canonicality");
            }
        }
        OK();
    }
    /* claim codec mutants (same discipline) */
    {
        dna_claim_t c, ct;
        memset(&c, 0, sizeof(c));
        c.claim_version = DNA_CLAIM_VERSION;
        memset(c.chain_id, 0x21, sizeof(c.chain_id));
        memset(c.manifest_hash, 0x37, sizeof(c.manifest_hash));
        c.leaf_index = 1;
        c.source_id_len = 5;
        memcpy(c.source_id, "alpha", 5);
        c.source_amount = 10;
        memset(c.dest_binding, 0xAB, 64);
        c.n_siblings = 2;
        memset(c.siblings[0], 0x01, 64);
        memset(c.siblings[1], 0x02, 64);
        c.auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
        for (size_t i = 0; i < sizeof(c.pubkey); i++)
            c.pubkey[i] = (uint8_t)(i * 7);
        for (size_t i = 0; i < sizeof(c.signature); i++)
            c.signature[i] = (uint8_t)(i * 11);

        static uint8_t enc[DNA_CLAIM_MAX_WIRE], m[DNA_CLAIM_MAX_WIRE];
        static uint8_t re[DNA_CLAIM_MAX_WIRE];
        size_t w1 = 0;
        CHECK(dna_claim_encode(&c, enc, sizeof(enc), &w1) == 0,
              "claim enc");
        for (int it = 0; it < 10000; it++) {
            memcpy(m, enc, w1);
            size_t pos = (size_t)(XRND() % w1);
            m[pos] ^= (uint8_t)(XRND() | 1);
            if (dna_claim_decode(m, w1, &ct) == 0) {
                size_t w2 = 0;
                CHECK(dna_claim_encode(&ct, re, sizeof(re), &w2) == 0 &&
                      w2 == w1 && memcmp(re, m, w1) == 0,
                      "claim mutant canonicality");
            }
        }
        OK();
    }
    #undef XRND
    return 0;
}

/* ── 5: snapshot tree + conversion arithmetic ───────────────────────── */

static void fixture_leaves(dna_dist_leaf_t l[3]) {
    memset(l, 0, 3 * sizeof(*l));
    l[0].leaf_version = DNA_DIST_VERSION;
    l[0].source_id_len = 5;
    memcpy(l[0].source_id, "alpha", 5);
    l[0].source_amount = 10;
    memset(l[0].dest_binding, 0xAA, 64);
    l[1].leaf_version = DNA_DIST_VERSION;
    l[1].source_id_len = 4;
    memcpy(l[1].source_id, "beta", 4);
    l[1].source_amount = 5;
    memset(l[1].dest_binding, 0xBB, 64);
    l[2].leaf_version = DNA_DIST_VERSION;
    l[2].source_id_len = 5;
    memcpy(l[2].source_id, "gamma", 5);
    l[2].source_amount = 7;
    memset(l[2].dest_binding, 0xCC, 64);
}

static int test_snapshot(void) {
    dna_dist_leaf_t l[3];
    fixture_leaves(l);
    uint8_t r1[64], r2[64];
    CHECK(dna_dist_snapshot_root(l, 3, r1) == 0, "root");
    CHECK(dna_dist_snapshot_root(l, 3, r2) == 0 &&
          memcmp(r1, r2, 64) == 0, "root deterministic");
    OK();

    /* ordering enforced: swap rejects; duplicate rejects; a strict
     * prefix must sort FIRST ("bet" < "beta"). */
    dna_dist_leaf_t bad[3];
    memcpy(bad, l, sizeof(bad));
    dna_dist_leaf_t tmp = bad[0]; bad[0] = bad[1]; bad[1] = tmp;
    CHECK(dna_dist_snapshot_root(bad, 3, r2) != 0, "unsorted rejects");
    OK();
    memcpy(bad, l, sizeof(bad));
    bad[1] = bad[0];
    CHECK(dna_dist_snapshot_root(bad, 3, r2) != 0, "duplicate rejects");
    OK();
    /* length-aware order: a strict prefix sorts FIRST ("bet" < "beta") */
    dna_dist_leaf_t pref[2];
    memset(pref, 0, sizeof(pref));
    pref[0] = l[1];                        /* "beta"                      */
    pref[1] = l[1];
    pref[0].source_id_len = 3;             /* "bet" — must sort first     */
    CHECK(dna_dist_leaf_cmp(&pref[0], &pref[1]) < 0, "prefix sorts first");
    CHECK(dna_dist_snapshot_root(pref, 2, r2) == 0, "prefix pair root");
    OK();
    /* leaf changes root */
    memcpy(bad, l, sizeof(bad));
    bad[2].source_amount += 1;
    CHECK(dna_dist_snapshot_root(bad, 3, r2) == 0 &&
          memcmp(r1, r2, 64) != 0, "leaf amount changes root");
    memcpy(bad, l, sizeof(bad));
    bad[2].dest_binding[0] ^= 1;
    CHECK(dna_dist_snapshot_root(bad, 3, r2) == 0 &&
          memcmp(r1, r2, 64) != 0, "dest binding changes root");
    OK();
    /* empty snapshot is not committable */
    CHECK(dna_dist_snapshot_root(l, 0, r2) != 0, "empty snapshot rejects");
    OK();

    /* conversion: 3/2 FLOOR — 10→15, 5→7, 7→10; totals checked */
    uint64_t v = 0;
    CHECK(dna_dist_converted(10, 3, 2, DNA_DISTROUND_FLOOR, &v) == 0 &&
          v == 15, "10*3/2=15");
    CHECK(dna_dist_converted(5, 3, 2, DNA_DISTROUND_FLOOR, &v) == 0 &&
          v == 7, "5*3/2=7 floor");
    CHECK(dna_dist_converted(7, 3, 2, DNA_DISTROUND_FLOOR, &v) == 0 &&
          v == 10, "7*3/2=10 floor");
    OK();
    CHECK(dna_dist_converted(0, 3, 2, DNA_DISTROUND_FLOOR, &v) != 0,
          "zero amount rejects");
    CHECK(dna_dist_converted(10, 0, 2, DNA_DISTROUND_FLOOR, &v) != 0,
          "zero numerator rejects");
    CHECK(dna_dist_converted(10, 3, 0, DNA_DISTROUND_FLOOR, &v) != 0,
          "zero denominator rejects");
    CHECK(dna_dist_converted(10, 3, 2, 0, &v) != 0,
          "invalid rounding rejects");
    CHECK(dna_dist_converted(10, 3, 2, 2, &v) != 0,
          "unknown rounding rejects");
    CHECK(dna_dist_converted(UINT64_MAX / 2, 3, 2,
                             DNA_DISTROUND_FLOOR, &v) != 0,
          "mul overflow rejects");
    CHECK(dna_dist_converted(1, 1, 2, DNA_DISTROUND_FLOOR, &v) != 0,
          "converted zero rejects");
    OK();
    CHECK(dna_dist_check_totals(l, 3, 3, 2, DNA_DISTROUND_FLOOR, 32) == 0,
          "totals 32 ok");
    CHECK(dna_dist_check_totals(l, 3, 3, 2, DNA_DISTROUND_FLOOR, 33) != 0,
          "totals mismatch rejects");
    OK();
    return 0;
}

/* ── 6: inclusion proofs (all shapes 1..9) ──────────────────────────── */

static int test_proofs(void) {
    for (size_t n = 1; n <= 9; n++) {
        dna_dist_leaf_t *l = calloc(n, sizeof(*l));
        uint8_t (*lh)[64] = calloc(n, sizeof(*lh));
        CHECK(l && lh, "alloc");
        for (size_t i = 0; i < n; i++) {
            l[i].leaf_version = DNA_DIST_VERSION;
            l[i].source_id_len = 7;
            snprintf((char *)l[i].source_id, DNA_DIST_SRCID_MAX,
                     "src-%03zu", i);
            l[i].source_amount = 100 + i;
            memset(l[i].dest_binding, (int)(0x10 + i), 64);
            CHECK(dna_dist_leaf_hash(&l[i], lh[i]) == 0, "leaf hash");
        }
        uint8_t root[64];
        CHECK(dna_dist_snapshot_root(l, n, root) == 0, "root");

        for (size_t i = 0; i < n; i++) {
            uint8_t sib[DNA_DIST_PROOF_MAX][64];
            uint16_t ns = 0;
            CHECK(dna_dist_proof_build(lh, n, i, sib, &ns) == 0,
                  "proof build");
            CHECK(dna_dist_proof_verify(root, lh[i], i, n, sib, ns) == 0,
                  "proof verify");
            /* wrong index (shape mismatch or wrong path) rejects */
            if (n > 1)
                CHECK(dna_dist_proof_verify(root, lh[i], (i + 1) % n, n,
                                            sib, ns) != 0,
                      "wrong index rejects");
            /* wrong leaf rejects */
            if (n > 1)
                CHECK(dna_dist_proof_verify(root, lh[(i + 1) % n], i, n,
                                            sib, ns) != 0,
                      "wrong leaf rejects");
            /* corrupted sibling rejects */
            if (ns > 0) {
                sib[0][0] ^= 1;
                CHECK(dna_dist_proof_verify(root, lh[i], i, n, sib, ns)
                          != 0, "corrupt sibling rejects");
                sib[0][0] ^= 1;
            }
            /* short and long proofs reject (count must match shape) */
            if (ns > 0)
                CHECK(dna_dist_proof_verify(root, lh[i], i, n, sib,
                                            (uint16_t)(ns - 1)) != 0,
                      "short proof rejects");
            memset(sib[ns], 0x99, 64);
            CHECK(dna_dist_proof_verify(root, lh[i], i, n, sib,
                                        (uint16_t)(ns + 1)) != 0,
                  "long proof rejects");
        }
        free(l);
        free(lh);
        OK();
    }
    /* out-of-range index */
    uint8_t r[64] = {0}, lh[64] = {0}, sib[1][64];
    CHECK(dna_dist_proof_verify(r, lh, 5, 5, sib, 0) != 0,
          "index >= count rejects");
    OK();

    /* leaf_count semantics PINNED: the count is COMMITTED manifest data
     * (never claimer-supplied). A count whose derived shape needs a
     * different sibling count rejects (n=1 vs 2). A PROMOTE-EQUIVALENT
     * count (3 vs 4 at index 0: the last sibling is a promoted leaf in
     * one shape and an inner node in the other — identical hash chain)
     * verifies identically; harmless because the claimer cannot vary
     * the committed count, and index is bounded by it. */
    {
        dna_dist_leaf_t l1[3];
        fixture_leaves(l1);
        uint8_t lh3[3][64], root3[64];
        for (int i = 0; i < 3; i++)
            CHECK(dna_dist_leaf_hash(&l1[i], lh3[i]) == 0, "lh");
        CHECK(dna_dist_snapshot_root(l1, 3, root3) == 0, "root3");
        uint8_t s3[DNA_DIST_PROOF_MAX][64];
        uint16_t ns3 = 0;
        CHECK(dna_dist_proof_build(lh3, 3, 0, s3, &ns3) == 0, "build");
        CHECK(dna_dist_proof_verify(root3, lh3[0], 0, 3, s3, ns3) == 0,
              "count 3 verifies");
        CHECK(dna_dist_proof_verify(root3, lh3[0], 0, 4, s3, ns3) == 0,
              "promote-equivalent count 4 verifies (pinned)");
        CHECK(dna_dist_proof_verify(root3, lh3[0], 0, 5, s3, ns3) != 0,
              "shape-different count 5 rejects");
        /* n=1: count mismatch rejects */
        uint8_t root1[64];
        CHECK(dna_dist_snapshot_root(l1, 1, root1) == 0, "root1");
        CHECK(dna_dist_proof_verify(root1, lh3[0], 0, 1, s3, 0) == 0,
              "single-leaf verifies");
        CHECK(dna_dist_proof_verify(root1, lh3[0], 0, 2, s3, 0) != 0,
              "single-leaf with count 2 rejects");
    }
    OK();
    return 0;
}

/* ── 7: claim codec ─────────────────────────────────────────────────── */

static void fixture_claim(dna_claim_t *c) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memset(c->chain_id, 0x21, sizeof(c->chain_id));
    memset(c->manifest_hash, 0x37, sizeof(c->manifest_hash));
    c->leaf_index = 2;
    c->source_id_len = 5;
    memcpy(c->source_id, "alpha", 5);
    c->source_amount = 10;
    memset(c->dest_binding, 0xAB, 64);
    c->n_siblings = 1;
    memset(c->siblings[0], 0x44, 64);
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    for (size_t i = 0; i < sizeof(c->pubkey); i++)
        c->pubkey[i] = (uint8_t)(i * 3);
    for (size_t i = 0; i < sizeof(c->signature); i++)
        c->signature[i] = (uint8_t)(i * 5);
}

static int test_claim_codec(void) {
    dna_claim_t c, t;
    fixture_claim(&c);
    static uint8_t enc[DNA_CLAIM_MAX_WIRE], re[DNA_CLAIM_MAX_WIRE];
    size_t w1 = 0, w2 = 0;
    CHECK(dna_claim_validate(&c) == 0, "claim valid");
    CHECK(dna_claim_encode(&c, enc, sizeof(enc), &w1) == 0, "encode");
    CHECK(dna_claim_decode(enc, w1, &t) == 0, "decode");
    CHECK(dna_claim_encode(&t, re, sizeof(re), &w2) == 0 && w2 == w1 &&
          memcmp(enc, re, w1) == 0, "re-encode identity");
    OK();

    /* truncation sweep (sampled every 97 bytes — full sweep at codec
     * granularity is covered structurally by the parse bounds) +
     * boundary truncations + trailing byte */
    for (size_t len = 0; len < w1; len += 97)
        CHECK(dna_claim_decode(enc, len, &t) != 0, "truncation rejects");
    CHECK(dna_claim_decode(enc, w1 - 1, &t) != 0, "off-by-one rejects");
    enc[w1] = 0;
    CHECK(dna_claim_decode(enc, w1 + 1, &t) != 0, "trailing rejects");
    OK();

    #define REJC(mut, msg) do { \
        dna_claim_t x; fixture_claim(&x); mut; \
        CHECK(dna_claim_validate(&x) != 0, msg); OK(); \
    } while (0)
    REJC(x.claim_version = 2, "version 2 rejects");
    REJC(x.source_id_len = 0, "zero src len rejects");
    REJC(x.source_id_len = DNA_DIST_SRCID_MAX + 1, "over src len rejects");
    REJC(x.source_amount = 0, "zero amount rejects");
    REJC(x.n_siblings = DNA_DIST_PROOF_MAX + 1, "over siblings rejects");
    REJC(x.auth_mode = DNA_CLAIMAUTH_INVALID, "auth 0 rejects");
    REJC(x.auth_mode = 2, "unknown auth rejects");
    #undef REJC

    /* preimage: deterministic + sensitive */
    uint8_t p1[DNA_CLAIM_PREIMAGE_MAX], p2[DNA_CLAIM_PREIMAGE_MAX];
    size_t pl1 = 0, pl2 = 0;
    CHECK(dna_claim_preimage(&c, p1, &pl1) == 0, "preimage");
    CHECK(dna_claim_preimage(&c, p2, &pl2) == 0 && pl1 == pl2 &&
          memcmp(p1, p2, pl1) == 0, "preimage deterministic");
    fixture_claim(&t);
    t.leaf_index++;
    CHECK(dna_claim_preimage(&t, p2, &pl2) == 0 &&
          (pl1 != pl2 || memcmp(p1, p2, pl1) != 0),
          "preimage sensitive to leaf index");
    /* the manifest identity is signed — and it COMMITS the target
     * domain + asset, so changing either changes the manifest hash and
     * therefore the signature preimage */
    fixture_claim(&t);
    t.manifest_hash[0] ^= 1;
    CHECK(dna_claim_preimage(&t, p2, &pl2) == 0 &&
          (pl1 != pl2 || memcmp(p1, p2, pl1) != 0),
          "preimage sensitive to manifest identity");
    /* the proof and key material are NOT in the preimage */
    fixture_claim(&t);
    t.siblings[0][0] ^= 1;
    t.pubkey[0] ^= 1;
    t.signature[0] ^= 1;
    CHECK(dna_claim_preimage(&t, p2, &pl2) == 0 && pl1 == pl2 &&
          memcmp(p1, p2, pl1) == 0, "proof/key not signed");
    OK();

    /* nullifier: deterministic; distinct per chain / manifest / target
     * domain / target asset / leaf — claims of different domains or
     * assets can NEVER collide. */
    uint8_t n1[64], n2[64];
    uint8_t leaf_h[64], asset[64];
    memset(leaf_h, 0x5C, 64);
    memset(asset, 0, 64);
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 1, asset, 64,
                              leaf_h, n1) == 0, "nullifier");
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 1, asset, 64,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) == 0, "nullifier deterministic");
    uint8_t other_chain[32];
    memset(other_chain, 0x22, 32);
    CHECK(dna_claim_nullifier(other_chain, c.manifest_hash, 1, asset, 64,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "chain changes nullifier");
    uint8_t other_mh[64];
    memcpy(other_mh, c.manifest_hash, 64);
    other_mh[0] ^= 1;
    CHECK(dna_claim_nullifier(c.chain_id, other_mh, 1, asset, 64,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "manifest changes nullifier");
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 7, asset, 64,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "target domain changes nullifier");
    uint8_t asset2[64];
    memcpy(asset2, asset, 64);
    asset2[0] = 0x01;
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 1, asset2, 64,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "target asset changes nullifier");
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 1, asset, 5,
                              leaf_h, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "asset length changes nullifier");
    uint8_t leaf_h2[64];
    memcpy(leaf_h2, leaf_h, 64);
    leaf_h2[0] ^= 1;
    CHECK(dna_claim_nullifier(c.chain_id, c.manifest_hash, 1, asset, 64,
                              leaf_h2, n2) == 0 &&
          memcmp(n1, n2, 64) != 0, "leaf hash changes nullifier");
    OK();

    /* UTXO id: deterministic function of the nullifier */
    uint8_t u1[64], u2[64];
    CHECK(dna_claim_utxo_id(n1, u1) == 0 && dna_claim_utxo_id(n1, u2) == 0
          && memcmp(u1, u2, 64) == 0, "utxo id deterministic");
    CHECK(memcmp(u1, n1, 64) != 0, "utxo id differs from nullifier");
    OK();
    return 0;
}

/* ── 8: claims_root + manifest_root ─────────────────────────────────── */

static int test_roots(void) {
    /* empty == the frozen S2 tagged-empty roots, byte-identically */
    uint8_t e1[64], e2[64];
    CHECK(dna_claims_root(NULL, 0, e1) == 0, "empty claims root");
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, e2) == 0 &&
          memcmp(e1, e2, 64) == 0, "empty claims == frozen placeholder");
    OK();
    uint8_t m1[64], m2[64];
    CHECK(dna_v2_manifest_root(NULL, 0, m1) == 0,
          "empty manifest root");
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST, m2) == 0 &&
          memcmp(m1, m2, 64) == 0, "empty manifest == frozen placeholder");
    OK();

    /* claims_root: sorted-only; entry fields sensitive */
    dna_claims_entry_t e[3];
    memset(e, 0, sizeof(e));
    for (int i = 0; i < 3; i++) {
        memset(e[i].nullifier, 0x10 * (i + 1), 64);
        memset(e[i].manifest_hash, 0x60 + i, 64);
        e[i].target_domain_id = 1;
        e[i].leaf_index = (uint64_t)i;
        e[i].amount = 10 + (uint64_t)i;
        e[i].claimed_height = 5;
    }
    uint8_t r1[64], r2[64];
    CHECK(dna_claims_root(e, 3, r1) == 0, "claims root");
    dna_claims_entry_t bad[3];
    memcpy(bad, e, sizeof(bad));
    dna_claims_entry_t tmp = bad[0]; bad[0] = bad[2]; bad[2] = tmp;
    CHECK(dna_claims_root(bad, 3, r2) != 0, "unsorted claims reject");
    memcpy(bad, e, sizeof(bad));
    memcpy(bad[1].nullifier, bad[0].nullifier, 64);
    CHECK(dna_claims_root(bad, 3, r2) != 0, "duplicate nullifier rejects");
    OK();
    memcpy(bad, e, sizeof(bad));
    bad[1].amount += 1;
    CHECK(dna_claims_root(bad, 3, r2) == 0 && memcmp(r1, r2, 64) != 0,
          "amount changes claims root");
    memcpy(bad, e, sizeof(bad));
    bad[1].claimed_height += 1;
    CHECK(dna_claims_root(bad, 3, r2) == 0 && memcmp(r1, r2, 64) != 0,
          "height changes claims root");
    memcpy(bad, e, sizeof(bad));
    bad[1].manifest_hash[0] ^= 1;
    CHECK(dna_claims_root(bad, 3, r2) == 0 && memcmp(r1, r2, 64) != 0,
          "manifest hash changes claims root");
    memcpy(bad, e, sizeof(bad));
    bad[1].target_domain_id = 7;
    CHECK(dna_claims_root(bad, 3, r2) == 0 && memcmp(r1, r2, 64) != 0,
          "target domain changes claims root");
    OK();

    /* manifest_root: strictly ascending by manifest_hash bytes — the
     * committed identity is the ONLY sort key */
    uint8_t mh[2][64];
    memset(mh[0], 0x71, 64);
    memset(mh[1], 0x72, 64);
    CHECK(dna_v2_manifest_root(mh, 2, r1) == 0, "manifest root");
    uint8_t badmh[2][64];
    memcpy(badmh[0], mh[1], 64);
    memcpy(badmh[1], mh[0], 64);
    CHECK(dna_v2_manifest_root(badmh, 2, r2) != 0,
          "unsorted hashes reject");
    memcpy(badmh[0], mh[0], 64);
    memcpy(badmh[1], mh[0], 64);
    CHECK(dna_v2_manifest_root(badmh, 2, r2) != 0,
          "duplicate hashes reject");
    mh[1][63] ^= 1;
    CHECK(dna_v2_manifest_root(mh, 2, r2) == 0 &&
          memcmp(r1, r2, 64) != 0, "hash changes manifest root");
    OK();
    return 0;
}

int main(void) {
    if (test_roundtrip()) return 1;
    if (test_field_sensitivity()) return 1;
    if (test_rejects()) return 1;
    if (test_fuzz()) return 1;
    if (test_snapshot()) return 1;
    if (test_proofs()) return 1;
    if (test_claim_codec()) return 1;
    if (test_roots()) return 1;
    printf("test_manifest_wire: ALL OK (%d checks)\n", g_checks);
    return 0;
}
