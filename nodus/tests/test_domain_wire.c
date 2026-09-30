/**
 * Nodus — Ledger V2 S4: domain manifest / registry / readiness codec tests
 * (INACTIVE layer).
 *
 * Every pinned literal was produced by an INDEPENDENT implementation
 * (python3 hashlib.sha3_512 over the layouts in shared/dnac/domain_wire.h —
 * scratchpad s4_oracle.py), the same oracle discipline as test_vset_wire.c.
 * If the C encoder and a pinned KAT disagree, the ENCODER is wrong.
 *
 * Sections:
 *   1. Manifest: oracle KATs (length + hash), round-trip byte identity,
 *      ownership lookup.
 *   2. Manifest negatives: version, unknown enums (runtime_kind /
 *      fee_policy / upgrade_authority / readiness_policy), non-canonical
 *      name, duplicate + descending tx types, over-cap count, truncation,
 *      trailing bytes, forged count.
 *   3. Ruleset descriptor: KAT + negatives.
 *   4. Registry record: leaf KATs, root KATs (1/2/3 records incl. odd
 *      promote), empty root == frozen S2 tag, duplicate/unordered ids,
 *      SYSTEM-first rule, status-coherence negatives, exact-length decode.
 *   5. Proposal digest: KAT + every input axis changes the digest.
 *   6. Readiness signal: preimage KAT, wire round-trip, negatives.
 *
 * @file test_domain_wire.c
 */

#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"

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

static int hex_eq(const uint8_t h[64], const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

/* ── Pinned python3-oracle literals (s4_oracle.py) ──────────────────── */
/* Re-derived 2026-09-30 for the NDS. tag rename (decision
 * 2026-09-30-tag-rebrand-nds.md). */
static const char *KAT_MAN_A =
    "0084572db50700b49ac67e0a311fc1197fc20380518179078550f6d3cebb79da"
    "49caf708e7d348df9615260b0697a59bf7c4df319d088dea2eeb7e9c00f5553e";
static const char *KAT_MAN_B =
    "6c863e3e52825c9d6b8e2dee3fec3e49f4c17d63be276782712cdfbd9b0188a6"
    "ec5aac26da29c0e7fd3559f5c0d84a60403bb21b99fa01b99e6152978d0002c1";
/* RE-DERIVED for the execution season: RulesetDescriptor v2 appends the
 * committed meter_policy_digest (all-zero in this fixture) and bumps the
 * version field to 2 — the hash moves by construction. Oracle:
 * scratchpad exec_season_oracle.py. Re-derived 2026-09-30 for the NDS.
 * tag rename (decision 2026-09-30-tag-rebrand-nds.md). */
static const char *KAT_DESC =
    "0f4f3eb74b60e6f27f77824347f7b065aaa2250e3d7a112606a9941ca5c3bec6"
    "36168bc4b28f2495b25f31af7da86e239e53163c4fffcf3cfe6303499252b409";
static const char *KAT_LEAF_SYS =
    "f6359b1cade898493337c630ec98f30b83f65655f9e57b9de560ff3ae531da51"
    "e0ed13fd7b561db543f39d23892829de09a67120a94e096d6ae00cde44b38c6a";
static const char *KAT_LEAF_CORE =
    "e43f925d1536f93f4a3414d0d92e9eefa2d296149500052be3a5fdc6945037a4"
    "5ccdda9537b37a91098c7ede4b9b9752766ed7b42253f42e576af0cd630f2c37";
static const char *KAT_ROOT2 =
    "1a46586ae86ce437d7f4cad975bec1f6062a10bb0ae21eecfb1937f6fa3061c2"
    "aafb8a6970ca2e7500b3245310e405a4754d52ea6c9da3d236d483b4087bbb94";
static const char *KAT_ROOT3 =
    "a35660ab16bc8e9b6501032564e3444ac8bd16721160a4978e40785c3e55549d"
    "c46c27919ba87d3fa686eeca1e021b61621a0d3acb5b41ad03307b884b1925b3";
static const char *KAT_EMPTY_DOMREG =
    "07b4b225f5c073f998fc7bca7c9071142cb9bebfa619af849a2d47e9a5f61bf2"
    "b8633cfbd3b83a51daf6940548a8e66bbedb86aa94b0a1001ac378523761ecaf";
static const char *KAT_PROP =
    "1610ef8a7898555f91e6b552a84114e0e04c717bff1f5a41714209a652b2c2c0"
    "4825cd47fbdfc604a8c8059680e2800cb0a816d366c3470e43c4d5e8c55f3369";
static const char *KAT_RDY_PRE =
    "3d1c5890aae099df45b74ecd81be0c51258f6570c99756b64c779677492c6a6d"
    "c8050275c52863b6222444c0dc965a0bf1166b8669f0de7520aa320bbbb9845a";

/* Oracle fixtures */
static void fixture_manifest_a(dna_domain_manifest_t *m) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = 1;
    m->domain_id = 0;
    memcpy(m->name, "SYSTEM", 6);
    m->runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    m->runtime_abi = 1;
    m->ruleset_version = 1;
    for (int i = 0; i < 64; i++) m->ruleset_hash[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 64; i++) m->genesis_state_root[i] = (uint8_t)(i + 65);
    m->tx_type_count = 6;
    const uint8_t types[6] = { 4, 5, 6, 7, 9, 10 };
    memcpy(m->tx_types, types, 6);
    m->fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m->quota_tx_per_block = 0;
    m->quota_verify_cost = 0;
    m->upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m->activation_epoch = 0;
    m->readiness_policy = DNA_RDYPOL_STAGED_V1;
}

static void fixture_manifest_b(dna_domain_manifest_t *m) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = 1;
    m->domain_id = 1;
    memcpy(m->name, "DNA_CORE", 8);
    m->runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    m->runtime_abi = 1;
    m->ruleset_version = 2;
    memset(m->ruleset_hash, 0xAA, 64);
    memset(m->genesis_state_root, 0xBB, 64);
    m->tx_type_count = 4;
    const uint8_t types[4] = { 1, 2, 3, 11 };
    memcpy(m->tx_types, types, 4);
    m->fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m->quota_tx_per_block = 10;
    m->quota_verify_cost = 1000;
    m->upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m->activation_epoch = 720;
    m->readiness_policy = DNA_RDYPOL_STAGED_V1;
}

/* ── 1 + 2: manifest ────────────────────────────────────────────────── */
static int test_manifest(void) {
    dna_domain_manifest_t a, b;
    fixture_manifest_a(&a);
    fixture_manifest_b(&b);

    CHECK(dna_domman_encoded_len(&a) == 205, "manifest A length"); OK();
    CHECK(dna_domman_encoded_len(&b) == 203, "manifest B length"); OK();

    uint8_t ha[64], hb[64];
    CHECK(dna_domman_hash(&a, ha) == 0, "hash A"); OK();
    CHECK(hex_eq(ha, KAT_MAN_A, "manifest A"), "manifest A KAT"); OK();
    CHECK(dna_domman_hash(&b, hb) == 0, "hash B"); OK();
    CHECK(hex_eq(hb, KAT_MAN_B, "manifest B"), "manifest B KAT"); OK();

    /* Round-trip byte identity */
    uint8_t enc1[DNA_DOMMAN_MAX_ENC_LEN], enc2[DNA_DOMMAN_MAX_ENC_LEN];
    size_t w1 = 0, w2 = 0;
    CHECK(dna_domman_encode(&b, enc1, sizeof(enc1), &w1) == 0, "encode B");
    OK();
    dna_domain_manifest_t rt;
    CHECK(dna_domman_decode(enc1, w1, &rt) == 0, "decode B"); OK();
    CHECK(dna_domman_encode(&rt, enc2, sizeof(enc2), &w2) == 0, "re-encode");
    CHECK(w1 == w2 && memcmp(enc1, enc2, w1) == 0,
          "round-trip not byte-identical"); OK();

    /* Ownership lookup */
    CHECK(dna_domman_owns_type(&b, 11) == 0, "B owns 11"); OK();
    CHECK(dna_domman_owns_type(&b, 4) == 1, "B does not own 4"); OK();
    CHECK(dna_domman_owns_type(&b, 12) == 1, "B does not own 12"); OK();
    CHECK(dna_domman_owns_type(&a, 10) == 0, "A owns 10"); OK();

    /* Negatives — each mutation must reject at validate/encode */
    dna_domain_manifest_t n;

    fixture_manifest_b(&n); n.manifest_version = 2;
    CHECK(dna_domman_validate(&n) != 0, "version 2 accepted"); OK();

    fixture_manifest_b(&n); n.runtime_kind = DNA_RUNTIME_INVALID;
    CHECK(dna_domman_validate(&n) != 0, "runtime_kind 0 accepted"); OK();
    fixture_manifest_b(&n); n.runtime_kind = 2;
    CHECK(dna_domman_validate(&n) != 0, "runtime_kind 2 accepted"); OK();

    fixture_manifest_b(&n); n.fee_policy = DNA_FEEPOL_INVALID;
    CHECK(dna_domman_validate(&n) != 0, "fee_policy 0 accepted"); OK();
    fixture_manifest_b(&n); n.fee_policy = 2;
    CHECK(dna_domman_validate(&n) != 0, "fee_policy 2 accepted"); OK();

    fixture_manifest_b(&n); n.upgrade_authority = 0;
    CHECK(dna_domman_validate(&n) != 0, "upgauth 0 accepted"); OK();
    fixture_manifest_b(&n); n.upgrade_authority = 2;
    CHECK(dna_domman_validate(&n) != 0, "upgauth 2 accepted"); OK();

    fixture_manifest_b(&n); n.readiness_policy = 0;
    CHECK(dna_domman_validate(&n) != 0, "rdypol 0 accepted"); OK();
    fixture_manifest_b(&n); n.readiness_policy = 2;
    CHECK(dna_domman_validate(&n) != 0, "rdypol 2 accepted"); OK();

    fixture_manifest_b(&n); n.name[0] = 0;
    CHECK(dna_domman_validate(&n) != 0, "empty name accepted"); OK();
    fixture_manifest_b(&n); n.name[10] = 'X';        /* non-NUL after pad  */
    CHECK(dna_domman_validate(&n) != 0, "gap name accepted"); OK();
    fixture_manifest_b(&n); n.name[2] = 0x20;        /* space not allowed  */
    CHECK(dna_domman_validate(&n) != 0, "space in name accepted"); OK();

    fixture_manifest_b(&n); n.tx_types[1] = n.tx_types[0];   /* duplicate  */
    CHECK(dna_domman_validate(&n) != 0, "duplicate type accepted"); OK();
    fixture_manifest_b(&n);
    n.tx_types[0] = 3; n.tx_types[1] = 2;            /* descending         */
    CHECK(dna_domman_validate(&n) != 0, "descending types accepted"); OK();
    fixture_manifest_b(&n); n.tx_type_count = DNA_DOM_MAX_TX_TYPES + 1;
    CHECK(dna_domman_validate(&n) != 0, "over-cap count accepted"); OK();

    /* Max-capacity edge: all 256 possible u8 types, strictly ascending */
    fixture_manifest_b(&n);
    n.tx_type_count = DNA_DOM_MAX_TX_TYPES;
    for (int i = 0; i < DNA_DOM_MAX_TX_TYPES; i++)
        n.tx_types[i] = (uint8_t)i;
    CHECK(dna_domman_validate(&n) == 0, "full 256-type list rejected"); OK();
    CHECK(dna_domman_encoded_len(&n) == DNA_DOMMAN_MAX_ENC_LEN,
          "max length drifted"); OK();
    uint8_t encf[DNA_DOMMAN_MAX_ENC_LEN];
    size_t wf = 0;
    CHECK(dna_domman_encode(&n, encf, sizeof(encf), &wf) == 0, "encode 256");
    dna_domain_manifest_t rtf;
    CHECK(dna_domman_decode(encf, wf, &rtf) == 0, "decode 256"); OK();

    /* Malformed length: truncation by 1, trailing +1, forged count */
    CHECK(dna_domman_decode(enc1, w1 - 1, &rt) != 0, "truncated accepted");
    OK();
    uint8_t encpad[DNA_DOMMAN_MAX_ENC_LEN + 1];
    memcpy(encpad, enc1, w1);
    encpad[w1] = 0;
    CHECK(dna_domman_decode(encpad, w1 + 1, &rt) != 0, "trailing accepted");
    OK();
    memcpy(encpad, enc1, w1);
    encpad[177] = 0xff; encpad[178] = 0xff;          /* count = 65535      */
    CHECK(dna_domman_decode(encpad, w1, &rt) != 0, "forged count accepted");
    OK();

    /* Short-buffer encode reject */
    CHECK(dna_domman_encode(&b, enc1, 10, &w1) != 0, "short dst accepted");
    OK();
    return 0;
}

/* ── 3: ruleset descriptor ──────────────────────────────────────────── */
static int test_ruleset_desc(void) {
    const uint32_t rules[3] = { 100, 200, 300 };
    const uint8_t types[4] = { 1, 2, 3, 11 };
    dna_ruleset_desc_t d;
    memset(&d, 0, sizeof(d));
    d.descriptor_version = 2;            /* v2 (execution season)        */
    d.domain_id = 1;
    memcpy(d.name, "DNA_CORE", 8);
    d.runtime_abi = 1;
    d.ruleset_version = 2;
    d.rule_count = 3;  d.rule_ids = rules;
    d.tx_type_count = 4; d.tx_types = types;
    /* meter_policy_digest stays all-zero: "no policy declared" is a
     * legal committed value (the memset above IS the fixture) */

    uint8_t h[64];
    CHECK(dna_ruleset_desc_hash(&d, h) == 0, "desc hash"); OK();
    CHECK(hex_eq(h, KAT_DESC, "ruleset descriptor"), "desc KAT"); OK();

    /* the digest COMMITS the policy identity: flipping one byte of
     * meter_policy_digest must move the hash */
    {
        dna_ruleset_desc_t p = d;
        p.meter_policy_digest[0] ^= 1;
        uint8_t h2[64];
        CHECK(dna_ruleset_desc_hash(&p, h2) == 0, "desc hash 2");
        CHECK(memcmp(h, h2, 64) != 0,
              "meter_policy_digest not committed"); OK();
    }

    dna_ruleset_desc_t n = d;
    n.descriptor_version = 1;            /* v1 is RETIRED               */
    CHECK(dna_ruleset_desc_hash(&n, h) != 0, "desc v1 accepted"); OK();
    n = d; n.descriptor_version = 3;
    CHECK(dna_ruleset_desc_hash(&n, h) != 0, "desc v3 accepted"); OK();
    const uint32_t bad_rules[3] = { 100, 100, 300 };
    n = d; n.rule_ids = bad_rules;
    CHECK(dna_ruleset_desc_hash(&n, h) != 0, "dup rule accepted"); OK();
    n = d; n.rule_count = 1; n.rule_ids = NULL;
    CHECK(dna_ruleset_desc_hash(&n, h) != 0, "NULL rules accepted"); OK();
    n = d; n.rule_count = DNA_DOM_MAX_RULE_IDS + 1;
    CHECK(dna_ruleset_desc_hash(&n, h) != 0, "over-cap rules accepted"); OK();
    return 0;
}

/* ── 4: registry records + root ─────────────────────────────────────── */
static int fixture_record(dna_domreg_record_t *r, uint32_t id,
                          uint8_t status, const uint8_t cur[64]) {
    memset(r, 0, sizeof(*r));
    r->record_version = DNA_DOMREG_REC_VERSION;
    r->domain_id = id;
    r->status = status;
    memcpy(r->current_manifest_hash, cur, 64);
    return 0;
}

static int test_registry(void) {
    dna_domain_manifest_t ma, mb;
    fixture_manifest_a(&ma);
    fixture_manifest_b(&mb);
    uint8_t ha[64], hb[64];
    CHECK(dna_domman_hash(&ma, ha) == 0, "hash A"); OK();
    CHECK(dna_domman_hash(&mb, hb) == 0, "hash B"); OK();

    dna_domreg_record_t rs, rc;
    fixture_record(&rs, 0, DNA_DOMST_ACTIVE, ha);
    fixture_record(&rc, 1, DNA_DOMST_ACTIVE, hb);

    uint8_t leaf[64];
    CHECK(dna_domreg_record_leaf(&rs, leaf) == 0, "leaf SYS"); OK();
    CHECK(hex_eq(leaf, KAT_LEAF_SYS, "leaf SYS"), "leaf SYS KAT"); OK();
    CHECK(dna_domreg_record_leaf(&rc, leaf) == 0, "leaf CORE"); OK();
    CHECK(hex_eq(leaf, KAT_LEAF_CORE, "leaf CORE"), "leaf CORE KAT"); OK();

    /* Roots: 1 record (= the leaf), 2 records, 3 records (odd promote) */
    uint8_t root[64];
    dna_domreg_record_t recs[3];
    recs[0] = rs;
    CHECK(dna_domreg_root(recs, 1, root) == 0, "root n=1"); OK();
    CHECK(hex_eq(root, KAT_LEAF_SYS, "root n=1"), "root n=1 != leaf"); OK();

    recs[1] = rc;
    CHECK(dna_domreg_root(recs, 2, root) == 0, "root n=2"); OK();
    CHECK(hex_eq(root, KAT_ROOT2, "root n=2"), "root n=2 KAT"); OK();

    /* Third (test-only) domain id 7, REGISTERED with an initial-activation
     * proposal — the oracle's rec_c. Proves a third domain needs nothing
     * beyond one more leaf. */
    dna_domreg_record_t r3;
    uint8_t man_c[64], prop_c[64];
    /* oracle fixture inputs: raw SHA3-512 of two short strings */
    CHECK(qgp_sha3_512((const uint8_t *)"manifest-c", 10, man_c) == 0,
          "sha3 man_c");
    CHECK(qgp_sha3_512((const uint8_t *)"proposal-fixture", 16,
                       prop_c) == 0, "sha3 prop_c");
    fixture_record(&r3, 7, DNA_DOMST_REGISTERED, man_c);
    r3.proposal_present = 1;
    memcpy(r3.proposal_digest, prop_c, 64);
    recs[2] = r3;
    CHECK(dna_domreg_root(recs, 3, root) == 0, "root n=3"); OK();
    CHECK(hex_eq(root, KAT_ROOT3, "root n=3"), "root n=3 KAT"); OK();

    /* Empty registry root == the frozen S2 tagged empty root */
    CHECK(dna_domreg_root(NULL, 0, root) == 0, "empty root"); OK();
    CHECK(hex_eq(root, KAT_EMPTY_DOMREG, "empty domreg"),
          "empty root KAT"); OK();
    uint8_t s2_empty[64];
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_DOMREG, s2_empty) == 0, "s2 empty");
    CHECK(memcmp(root, s2_empty, 64) == 0,
          "empty registry root != frozen S2 placeholder"); OK();

    /* Ordering rules */
    dna_domreg_record_t bad[2];
    bad[0] = rc; bad[1] = rs;                        /* CORE before SYSTEM */
    CHECK(dna_domreg_root(bad, 2, root) != 0, "unordered accepted"); OK();
    bad[0] = rs; bad[1] = rs;                        /* duplicate id       */
    CHECK(dna_domreg_root(bad, 2, root) != 0, "duplicate id accepted"); OK();
    bad[0] = rc;                                     /* SYSTEM missing     */
    CHECK(dna_domreg_root(bad, 1, root) != 0, "SYSTEM-less accepted"); OK();

    /* Record round-trip + exact length */
    uint8_t enc[DNA_DOMREG_REC_ENC_LEN];
    CHECK(dna_domreg_record_encode(&r3, enc) == 0, "record encode"); OK();
    dna_domreg_record_t rt;
    CHECK(dna_domreg_record_decode(enc, sizeof(enc), &rt) == 0,
          "record decode"); OK();
    uint8_t enc2[DNA_DOMREG_REC_ENC_LEN];
    CHECK(dna_domreg_record_encode(&rt, enc2) == 0, "record re-encode");
    CHECK(memcmp(enc, enc2, sizeof(enc)) == 0,
          "record round-trip not byte-identical"); OK();
    CHECK(dna_domreg_record_decode(enc, sizeof(enc) - 1, &rt) != 0,
          "short record accepted"); OK();

    /* Status-coherence negatives */
    dna_domreg_record_t n;

    fixture_record(&n, 2, DNA_DOMST_INVALID, ha);
    CHECK(dna_domreg_record_validate(&n) != 0, "status 0 accepted"); OK();
    fixture_record(&n, 2, 6, ha);
    CHECK(dna_domreg_record_validate(&n) != 0, "status 6 accepted"); OK();

    /* absent flag but nonzero hash */
    fixture_record(&n, 2, DNA_DOMST_ACTIVE, ha);
    n.pending_manifest_hash[0] = 1;
    CHECK(dna_domreg_record_validate(&n) != 0,
          "ghost pending hash accepted"); OK();
    /* present flag but all-zero hash */
    fixture_record(&n, 2, DNA_DOMST_ACTIVE, ha);
    n.pending_present = 1; n.proposal_present = 1;
    memcpy(n.proposal_digest, prop_c, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "zero pending hash accepted"); OK();

    /* REGISTERED with pending */
    fixture_record(&n, 2, DNA_DOMST_REGISTERED, ha);
    n.pending_present = 1; memcpy(n.pending_manifest_hash, hb, 64);
    n.proposal_present = 1; memcpy(n.proposal_digest, prop_c, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "REGISTERED+pending accepted"); OK();

    /* SCHEDULED without proposal / without epochs */
    fixture_record(&n, 2, DNA_DOMST_SCHEDULED, ha);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "bare SCHEDULED accepted"); OK();
    fixture_record(&n, 2, DNA_DOMST_SCHEDULED, ha);
    n.proposal_present = 1; memcpy(n.proposal_digest, prop_c, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "SCHEDULED without epochs accepted"); OK();
    n.scheduled_activation_epoch = 2160;
    n.readiness_deadline_epoch = 1440;
    CHECK(dna_domreg_record_validate(&n) == 0, "valid SCHEDULED rejected");
    OK();

    /* scheduling fields must travel together */
    n.readiness_deadline_epoch = 0;
    CHECK(dna_domreg_record_validate(&n) != 0,
          "lone sched epoch accepted"); OK();

    /* ACTIVE upgrade coherence: proposal without pending */
    fixture_record(&n, 2, DNA_DOMST_ACTIVE, ha);
    n.proposal_present = 1; memcpy(n.proposal_digest, prop_c, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "ACTIVE proposal w/o pending accepted"); OK();

    /* PAUSED / RETIRED carry nothing */
    fixture_record(&n, 2, DNA_DOMST_PAUSED, ha);
    n.proposal_present = 1; memcpy(n.proposal_digest, prop_c, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "PAUSED+proposal accepted"); OK();
    fixture_record(&n, 2, DNA_DOMST_RETIRED, ha);
    n.pending_present = 1; memcpy(n.pending_manifest_hash, hb, 64);
    CHECK(dna_domreg_record_validate(&n) != 0,
          "RETIRED+pending accepted"); OK();

    /* postpone_count without a schedule */
    fixture_record(&n, 2, DNA_DOMST_ACTIVE, ha);
    n.postpone_count = 1;
    CHECK(dna_domreg_record_validate(&n) != 0,
          "postpone w/o schedule accepted"); OK();
    return 0;
}

/* ── 5: proposal digest ─────────────────────────────────────────────── */
static int test_proposal_digest(void) {
    uint8_t chain[32];
    for (int i = 0; i < 32; i++) chain[i] = (uint8_t)i;
    dna_domain_manifest_t mb;
    fixture_manifest_b(&mb);
    uint8_t hb[64];
    CHECK(dna_domman_hash(&mb, hb) == 0, "hash B"); OK();

    uint8_t d0[64], d1[64];
    CHECK(dna_domprop_digest(chain, 1, hb, 42, 1440, d0) == 0, "digest");
    OK();
    CHECK(hex_eq(d0, KAT_PROP, "proposal digest"), "proposal KAT"); OK();

    /* Every axis of the digest must change it (replay separation). */
    uint8_t chain2[32];
    memcpy(chain2, chain, 32); chain2[0] ^= 1;
    CHECK(dna_domprop_digest(chain2, 1, hb, 42, 1440, d1) == 0 &&
          memcmp(d0, d1, 64) != 0, "chain axis inert"); OK();
    CHECK(dna_domprop_digest(chain, 2, hb, 42, 1440, d1) == 0 &&
          memcmp(d0, d1, 64) != 0, "domain axis inert"); OK();
    uint8_t hb2[64];
    memcpy(hb2, hb, 64); hb2[63] ^= 1;
    CHECK(dna_domprop_digest(chain, 1, hb2, 42, 1440, d1) == 0 &&
          memcmp(d0, d1, 64) != 0, "manifest axis inert"); OK();
    CHECK(dna_domprop_digest(chain, 1, hb, 43, 1440, d1) == 0 &&
          memcmp(d0, d1, 64) != 0, "nonce axis inert"); OK();
    CHECK(dna_domprop_digest(chain, 1, hb, 42, 2160, d1) == 0 &&
          memcmp(d0, d1, 64) != 0, "epoch axis inert"); OK();
    return 0;
}

/* ── 6: readiness signal ────────────────────────────────────────────── */
static int test_readiness(void) {
    uint8_t chain[32];
    for (int i = 0; i < 32; i++) chain[i] = (uint8_t)i;
    dna_domain_manifest_t mb;
    fixture_manifest_b(&mb);
    uint8_t hb[64], prop[64];
    CHECK(dna_domman_hash(&mb, hb) == 0, "hash B"); OK();
    CHECK(dna_domprop_digest(chain, 1, hb, 42, 1440, prop) == 0, "prop");

    dna_readiness_signal_t s;
    memset(&s, 0, sizeof(s));
    s.msg_version = DNA_DOMRDY_MSG_VERSION;
    memcpy(s.chain_id, chain, 32);
    memset(s.voter_id, 0xCC, 32);
    s.domain_id = 1;
    s.runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    s.runtime_abi = 1;
    s.ruleset_version = 2;
    memset(s.ruleset_hash, 0xAA, 64);
    memcpy(s.proposal_digest, prop, 64);
    s.signal_epoch = 2160;
    memset(s.signature, 0x5A, DNA_DOM_SIG_LEN);      /* wire-only fixture  */

    uint8_t pre[DNA_DOMRDY_PREIMAGE_LEN];
    CHECK(dna_domrdy_preimage(&s, pre) == 0, "preimage"); OK();
    /* KAT is over SHA3-512(preimage) for a compact pin. */
    uint8_t ph[64];
    CHECK(qgp_sha3_512(pre, sizeof(pre), ph) == 0, "sha3 preimage");
    CHECK(hex_eq(ph, KAT_RDY_PRE, "readiness preimage"),
          "readiness preimage KAT"); OK();

    /* Wire round-trip byte identity */
    uint8_t w1[DNA_DOMRDY_WIRE_LEN], w2[DNA_DOMRDY_WIRE_LEN];
    CHECK(dna_domrdy_encode(&s, w1) == 0, "encode"); OK();
    dna_readiness_signal_t rt;
    CHECK(dna_domrdy_decode(w1, sizeof(w1), &rt) == 0, "decode"); OK();
    CHECK(dna_domrdy_encode(&rt, w2) == 0, "re-encode");
    CHECK(memcmp(w1, w2, sizeof(w1)) == 0, "wire round-trip"); OK();

    /* Negatives */
    dna_readiness_signal_t n = s;
    n.msg_version = 2;
    CHECK(dna_domrdy_preimage(&n, pre) != 0, "msg v2 accepted"); OK();
    n = s; n.runtime_kind = DNA_RUNTIME_INVALID;
    CHECK(dna_domrdy_preimage(&n, pre) != 0, "kind 0 accepted"); OK();
    n = s; n.runtime_kind = 2;
    CHECK(dna_domrdy_preimage(&n, pre) != 0, "kind 2 accepted"); OK();
    CHECK(dna_domrdy_decode(w1, sizeof(w1) - 1, &rt) != 0,
          "short wire accepted"); OK();

    /* The wire's kind byte forged to 2 must fail decode (fail-closed). */
    uint8_t wbad[DNA_DOMRDY_WIRE_LEN];
    memcpy(wbad, w1, sizeof(wbad));
    wbad[72] = 2;                       /* off 72 = runtime_kind (4+32+32+4) */
    CHECK(dna_domrdy_decode(wbad, sizeof(wbad), &rt) != 0,
          "forged kind accepted"); OK();
    return 0;
}

/* ── 7: deterministic fuzz (seeded xorshift64 — reproducible, no RNG;
 * the test_block_v2 discipline). 62,000 mutants total. ─────────────── */
static int test_fuzz(void) {
    uint64_t s = 0x53345F444F4D5A31ULL;   /* fixed seed */
    #define XRND() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)

    /* Manifest: random buffers — success implies full validity +
     * byte-identical canonical re-encode. */
    {
        uint8_t buf[DNA_DOMMAN_MAX_ENC_LEN];
        dna_domain_manifest_t t;
        for (int it = 0; it < 20000; it++) {
            size_t len = (size_t)(XRND() % (sizeof(buf) + 1));
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)XRND();
            if (dna_domman_decode(buf, len, &t) == 0) {
                uint8_t re[DNA_DOMMAN_MAX_ENC_LEN];
                size_t w = 0;
                CHECK(dna_domman_validate(&t) == 0 &&
                      dna_domman_encode(&t, re, sizeof(re), &w) == 0 &&
                      w == len && memcmp(re, buf, len) == 0,
                      "manifest fuzz canonicality");
            }
        }
        OK();
        /* Structured single-byte mutations of a valid encoding. */
        dna_domain_manifest_t b;
        fixture_manifest_b(&b);
        uint8_t enc[DNA_DOMMAN_MAX_ENC_LEN];
        size_t w1 = 0;
        CHECK(dna_domman_encode(&b, enc, sizeof(enc), &w1) == 0, "enc");
        for (int it = 0; it < 10000; it++) {
            uint8_t m[DNA_DOMMAN_MAX_ENC_LEN];
            memcpy(m, enc, w1);
            m[XRND() % w1] ^= (uint8_t)(XRND() | 1);
            if (dna_domman_decode(m, w1, &t) == 0) {
                uint8_t re[DNA_DOMMAN_MAX_ENC_LEN];
                size_t w2 = 0;
                CHECK(dna_domman_encode(&t, re, sizeof(re), &w2) == 0 &&
                      w2 == w1 && memcmp(re, m, w1) == 0,
                      "manifest mutation canonicality");
            }
        }
        OK();
    }

    /* Registry record: random 223-byte buffers + mutations. */
    {
        dna_domreg_record_t t;
        uint8_t buf[DNA_DOMREG_REC_ENC_LEN];
        for (int it = 0; it < 20000; it++) {
            for (size_t i = 0; i < sizeof(buf); i++)
                buf[i] = (uint8_t)XRND();
            if (dna_domreg_record_decode(buf, sizeof(buf), &t) == 0) {
                uint8_t re[DNA_DOMREG_REC_ENC_LEN];
                CHECK(dna_domreg_record_encode(&t, re) == 0 &&
                      memcmp(re, buf, sizeof(buf)) == 0,
                      "record fuzz canonicality");
            }
        }
        OK();
        dna_domain_manifest_t ma;
        fixture_manifest_a(&ma);
        uint8_t ha[64];
        CHECK(dna_domman_hash(&ma, ha) == 0, "hash");
        dna_domreg_record_t r;
        memset(&r, 0, sizeof(r));
        r.record_version = DNA_DOMREG_REC_VERSION;
        r.domain_id = 0;
        r.status = DNA_DOMST_ACTIVE;
        memcpy(r.current_manifest_hash, ha, 64);
        uint8_t enc[DNA_DOMREG_REC_ENC_LEN];
        CHECK(dna_domreg_record_encode(&r, enc) == 0, "enc");
        for (int it = 0; it < 10000; it++) {
            uint8_t m[DNA_DOMREG_REC_ENC_LEN];
            memcpy(m, enc, sizeof(m));
            m[XRND() % sizeof(m)] ^= (uint8_t)(XRND() | 1);
            if (dna_domreg_record_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_DOMREG_REC_ENC_LEN];
                CHECK(dna_domreg_record_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0,
                      "record mutation canonicality");
            }
        }
        OK();
    }

    /* Readiness wire: structured mutations of a valid 4844-byte frame. */
    {
        dna_readiness_signal_t sig, t;
        memset(&sig, 0, sizeof(sig));
        sig.msg_version = DNA_DOMRDY_MSG_VERSION;
        memset(sig.chain_id, 0x21, 32);
        memset(sig.voter_id, 0x22, 32);
        sig.domain_id = 1;
        sig.runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
        sig.runtime_abi = 1;
        sig.ruleset_version = 1;
        memset(sig.ruleset_hash, 0x23, 64);
        memset(sig.proposal_digest, 0x24, 64);
        sig.signal_epoch = 720;
        memset(sig.signature, 0x25, DNA_DOM_SIG_LEN);
        uint8_t enc[DNA_DOMRDY_WIRE_LEN];
        CHECK(dna_domrdy_encode(&sig, enc) == 0, "enc");
        for (int it = 0; it < 2000; it++) {
            uint8_t m[DNA_DOMRDY_WIRE_LEN];
            memcpy(m, enc, sizeof(m));
            m[XRND() % sizeof(m)] ^= (uint8_t)(XRND() | 1);
            if (dna_domrdy_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_DOMRDY_WIRE_LEN];
                CHECK(dna_domrdy_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0,
                      "readiness mutation canonicality");
            }
        }
        OK();
    }
    #undef XRND
    return 0;
}

/* ── 8 (S5): DomainUpdate v1 + updates-root + batch + touched list ──── */
static const char *KAT_DUPD =
    "7489f0ddd6bb616367e0f520353af65d13846d67cb611272a91ce17ec7ab94c0"
    "eb049ad5e0e49c314bdf99b6b92e5cf92376c1dc2c74e4cef8eefe042d93aade";
static const char *KAT_DUPD_ROOT2 =
    "4ad6f7646fb608980ea0d82309d6d96f43b3c9667ba9a660a1884c1a435d5f2a"
    "098c2790b8624cdf5906bfeecc273fe4f873dbdc84435954602111683ccd0d54";
static const char *KAT_E_DUPD =
    "7aba2b3b0d06b630e176dcb0f14063023ddcb99684260fdd75428358667faaff"
    "6773660ba1f229533334791b86503a91f4cebc447922d635c32355af852c2ec5";
static const char *KAT_DUPDPRV =
    "0eb8b1b7d86efcb41c8351e601070cdac5425e34cd9252007a1a6293c1c6ed60"
    "658103121e3ec4ed5aa36a0b9b7adc0ce12f5f7610cb37096bc18214a3b0e0a9";
static const char *KAT_TXB0 =
    "4ce5c9f81350b5a374f00b788a0d5e0ee6858b69cad0a1e5592a06b411ef0fc5"
    "62d6a1a0ec1293bb1432a92adaa7b50b1bc8369a4d2524de6f70b30429747186";
static const char *KAT_TXB2 =
    "633c6b83b33d43523818fded08491862d1609035377a645fabb170fec4615cd1"
    "fad62f431fefc1303e05ecb62a8876dffc6b49d2ceb5519976f6f9731d454f1c";

static void fixture_update_a(dna_domain_update_t *u) {
    memset(u, 0, sizeof(*u));
    u->update_version = DNA_DUPD_VERSION;
    u->domain_id = 0;
    u->old_height = 4;
    u->new_height = 5;
    u->global_height = 100;
    memset(u->pre_root, 0x11, 64);
    memset(u->post_root, 0x22, 64);
    memset(u->tx_batch_root, 0x33, 64);
    u->ruleset_version = 1;
    memset(u->ruleset_hash, 0x44, 64);
    u->res_tx_count = 3;
    u->res_verify_cost = 7;
    dna_dupd_prev_genesis(u->prev_update_hash);
}

static void fixture_update_b(dna_domain_update_t *u) {
    memset(u, 0, sizeof(*u));
    u->update_version = DNA_DUPD_VERSION;
    u->domain_id = 1;
    u->old_height = 9;
    u->new_height = 10;
    u->global_height = 100;
    memset(u->pre_root, 0x55, 64);
    memset(u->post_root, 0x66, 64);
    memset(u->tx_batch_root, 0x77, 64);
    u->ruleset_version = 2;
    memset(u->ruleset_hash, 0x88, 64);
    u->res_tx_count = 1;
    u->res_verify_cost = 2;
    memset(u->prev_update_hash, 0x99, 64);
}

static int test_domain_update(void) {
    uint8_t h[64];
    /* genesis prev-linkage KAT */
    CHECK(dna_dupd_prev_genesis(h) == 0, "prev genesis"); OK();
    CHECK(hex_eq(h, KAT_DUPDPRV, "prev genesis"), "prev KAT"); OK();

    dna_domain_update_t a, b;
    fixture_update_a(&a);
    fixture_update_b(&b);
    CHECK(dna_dupd_hash(&a, h) == 0, "dupd hash"); OK();
    CHECK(hex_eq(h, KAT_DUPD, "dupd A"), "dupd A KAT"); OK();

    /* round-trip byte identity + exact length */
    uint8_t enc[DNA_DUPD_ENC_LEN], enc2[DNA_DUPD_ENC_LEN];
    CHECK(dna_dupd_encode(&a, enc) == 0, "encode"); OK();
    dna_domain_update_t rt;
    CHECK(dna_dupd_decode(enc, sizeof(enc), &rt) == 0, "decode"); OK();
    CHECK(dna_dupd_encode(&rt, enc2) == 0 &&
          memcmp(enc, enc2, sizeof(enc)) == 0, "round-trip"); OK();
    CHECK(dna_dupd_decode(enc, sizeof(enc) - 1, &rt) != 0, "short"); OK();

    /* validate negatives: version, height rule, +1 overflow */
    dna_domain_update_t n = a;
    n.update_version = 2;
    CHECK(dna_dupd_validate(&n) != 0, "v2 accepted"); OK();
    n = a; n.new_height = n.old_height;        /* no advance */
    CHECK(dna_dupd_validate(&n) != 0, "height skip accepted"); OK();
    n = a; n.new_height = n.old_height + 2;    /* double advance */
    CHECK(dna_dupd_validate(&n) != 0, "double advance accepted"); OK();
    n = a; n.old_height = UINT64_MAX; n.new_height = 0;
    CHECK(dna_dupd_validate(&n) != 0, "height overflow accepted"); OK();

    /* updates root: 2 leaves KAT, single-leaf == leaf, empty KAT,
     * duplicate/descending reject */
    dna_domain_update_t both[2];
    both[0] = a; both[1] = b;
    CHECK(dna_v2_domain_updates_root(both, 2, h) == 0, "root2"); OK();
    CHECK(hex_eq(h, KAT_DUPD_ROOT2, "updates root2"), "root2 KAT"); OK();
    uint8_t leaf_a[64];
    CHECK(dna_dupd_hash(&a, leaf_a) == 0, "leaf a");
    CHECK(dna_v2_domain_updates_root(both, 1, h) == 0 &&
          memcmp(h, leaf_a, 64) == 0, "root1 != leaf"); OK();
    CHECK(dna_v2_domain_updates_root(NULL, 0, h) == 0, "empty root"); OK();
    CHECK(hex_eq(h, KAT_E_DUPD, "empty updates"), "empty KAT"); OK();
    both[0] = b; both[1] = a;                  /* descending */
    CHECK(dna_v2_domain_updates_root(both, 2, h) != 0, "descending ok'd");
    OK();
    both[0] = a; both[1] = a;                  /* duplicate */
    CHECK(dna_v2_domain_updates_root(both, 2, h) != 0, "duplicate ok'd");
    OK();

    /* tx-batch commitment KATs (0 and 2 ids) + order sensitivity */
    uint8_t ids[2][64];
    memset(ids[0], 0xA1, 64);
    memset(ids[1], 0xB2, 64);
    CHECK(dna_v2_tx_batch_root(NULL, 0, h) == 0, "txb0"); OK();
    CHECK(hex_eq(h, KAT_TXB0, "batch 0"), "txb0 KAT"); OK();
    CHECK(dna_v2_tx_batch_root(ids, 2, h) == 0, "txb2"); OK();
    CHECK(hex_eq(h, KAT_TXB2, "batch 2"), "txb2 KAT"); OK();
    uint8_t swapped[2][64];
    memcpy(swapped[0], ids[1], 64);
    memcpy(swapped[1], ids[0], 64);
    uint8_t h2[64];
    CHECK(dna_v2_tx_batch_root(swapped, 2, h2) == 0 &&
          memcmp(h, h2, 64) != 0, "batch order-insensitive"); OK();

    /* touched-domain list */
    const uint32_t tds[3] = { 0, 1, 7 };
    uint8_t tl[2 + 4 * DNA_TOUCHED_MAX];
    size_t w = 0;
    CHECK(dna_touched_encode(tds, 3, tl, sizeof(tl), &w) == 0 &&
          w == 14, "touched encode"); OK();
    uint32_t ids_out[DNA_TOUCHED_MAX];
    uint16_t n_out = 0;
    CHECK(dna_touched_decode(tl, w, ids_out, &n_out) == 0 && n_out == 3 &&
          ids_out[2] == 7, "touched decode"); OK();
    CHECK(dna_touched_decode(tl, w - 1, ids_out, &n_out) != 0,
          "touched short"); OK();
    const uint32_t dup[2] = { 1, 1 };
    CHECK(dna_touched_encode(dup, 2, tl, sizeof(tl), &w) != 0,
          "touched dup"); OK();
    const uint32_t desc[2] = { 2, 1 };
    CHECK(dna_touched_encode(desc, 2, tl, sizeof(tl), &w) != 0,
          "touched desc"); OK();
    CHECK(dna_touched_encode(tds, 0, tl, sizeof(tl), &w) != 0,
          "touched zero"); OK();

    /* deterministic fuzz over the 368-byte decoder (seeded, no RNG) */
    {
        uint64_t s = 0x53355F44555044ULL;
        #define XR() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)
        uint8_t m[DNA_DUPD_ENC_LEN];
        dna_domain_update_t t;
        for (int it = 0; it < 10000; it++) {
            memcpy(m, enc, sizeof(m));
            m[XR() % sizeof(m)] ^= (uint8_t)(XR() | 1);
            if (dna_dupd_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_DUPD_ENC_LEN];
                CHECK(dna_dupd_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0,
                      "dupd mutation canonicality");
            }
        }
        for (int it = 0; it < 10000; it++) {
            for (size_t i = 0; i < sizeof(m); i++) m[i] = (uint8_t)XR();
            if (dna_dupd_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_DUPD_ENC_LEN];
                CHECK(dna_dupd_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0,
                      "dupd random canonicality");
            }
        }
        #undef XR
        OK();
    }
    return 0;
}

int main(void) {
    if (test_manifest()) return 1;
    if (test_ruleset_desc()) return 1;
    if (test_registry()) return 1;
    if (test_proposal_digest()) return 1;
    if (test_readiness()) return 1;
    if (test_fuzz()) return 1;
    if (test_domain_update()) return 1;
    printf("test_domain_wire: ALL %d checks passed\n", g_checks);
    return 0;
}
