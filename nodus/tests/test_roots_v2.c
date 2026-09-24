/**
 * Nodus — Ledger V2 S2: tagged root-hierarchy tests (INACTIVE hierarchy).
 *
 * Every canonical preimage is pinned to a literal computed by an
 * INDEPENDENT implementation (python3 hashlib.sha3_512 — the oracle script
 * and its output are recorded in the S2 season report). Sections:
 *   1. Shared-layer KATs + negatives (empty tags, supply, tokens,
 *      DomainHead, domains_root incl. a THIRD future domain, composition
 *      incl. the SYSTEM payload root, subroot mutation sweep,
 *      supply-committed-once). The epoch v2 leaf/root KATs are GONE with
 *      the epoch_state leg (root-layout round K2, 2026-09-25).
 *   2. Witness loaders over real in-memory SQLite state: token-root
 *      insertion-order independence, duplicate/malformed/fail-closed,
 *      pre-genesis empty states.
 *   3. 7/7 determinism: seven independent witness instances with identical
 *      state compute identical SYSTEM/CORE/domains/global roots.
 *
 * @file test_roots_v2.c
 */

#include "dnac/ledger_roots_v2.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness.h"
#include "nodus/nodus_chain_config.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_claims.h"

#include <sqlite3.h>
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

/* Pinned python3-oracle literals (independent sha3_512 implementation). */
static const char *EMPTY_KAT[DNA_V2_EMPTY__COUNT] = {
    /* VSET   */ "fd1c65789de6e38765ae77ca7d302e7a7b95400233ef55218139df9f1b4e63487a3d88706303b0a5b8eeec695526d26d04d0267bcce826c995f2b8a5d8f2261b",
    /* DOMREG */ "107bae9d51c4a1567d25d1e75f1df56e671fac019b6325324407df76429089c0231074520edcbff6bcc01926ba5bcb4d1a905f52ea819be0fb9a9d2c59de74ea",
    /* MANIF  */ "90d5ec18e9745fae481baf31660bfb0b86150c147fb819ce978af5bdc538d8d1ab591defc2cd65334bc667bebd90c5c8cd55a16ae458adb8a9b05b521a4f9c18",
    /* POOLS  */ "fbba0c378530aa1214dbe5d8810c28b7487aba1b7cc6a44c291c62369dc1ae222727e09549ef48cc638c7face48758964b436107b661b91db82fcb308f3d8042",
    /* CLAIMS */ "b34a8d97ef88610cc933751fe9f2a8d61dd60c916f685a5ffc1667ca6c5d4f4abe0fe46a51e40251b859a870f28c6bb342b36cae3c45b525cccbdef051fba6a8",
    /* NAMES  */ "ef12a4d9657dc6711688a664ea0ac0a9295f8bdc595599121a7b60c7dae9467ec3e80e861e55a3cb99c76dfbf14c596e91fa0fa1b7a67317cbc155ce120db412",
    /* TOKENS */ "4098bc465307c3a6340c1374d020957372b82d4b670f5e2049b6a3fa13f9ade608eadcc34afe643079b6e4fcd890bab80f1b4582023e80c719bcffcf0ce093f3",
    /* EPOCH2 — DELETED with DNA_V2_EMPTY_EPOCH_V2 (root-layout round K2);
     * ATTND/ACCRU below keep their own values, only their index moved. */
    /* ATTND  */ "c917bcb22a2eef99ded15a92b70117d32a92996276f395ca3acbc8abfa17bcd66cda39856cc038582cc32f67e49ece48055434718ff5f4a94e95d1f6f60c0001",
    /* ACCRU  */ "225010d99df0cb442e76fc02469f95922ecf182b07678887e00924bdf4ee3f99bb010b0c983b5e66b92b44e39c9fb74cdbe3b3d20578cfc0d94cc6fd9e6c4ea8",
};
/* tokenomics-v3 P2 (P2-8) re-pin: the supply leaf gained reward_pool and
 * the tag "DNA.SUPPLY.v2"; the CORE composition gained a 7th leg
 * (accrual_root) and the tag "DNA.CORE.v2". SELF-CONSISTENT with
 * shared/dnac/tests/ledger_roots_v2_accrual_oracle.py (same author, same
 * day — see its PROVENANCE; not an external audit), which self-checks
 * against the retired KAT_SUPPLY / 6-leg KAT_CORE values below before
 * deriving the new ones. The values were computed by the executor with an
 * independent inline python3 hashlib calculator, NOT by running that
 * script; the ORCHESTRATOR runs the script to confirm.
 * RETIRED (historical notes, not live vectors — a changed preimage is a
 * new tag, never the same tag over different bytes):
 *   KAT_SUPPLY "DNA.SUPPLY.v1" (1e17, 500, 300):
 *     ef949407440c0a7adab9f6b0a0999e06074e57a4b2b04f7b1532cf2effb597f2e656e3f396f663a1b3d5237d6709165393ec076ddc5f47f35abe0de3b26e91b7
 *   KAT_CORE 6-leg "DNA.CORE.v1" (fill 0xB0..0xB5):
 *     ccaae1c6ced38cfd93a99f9a15f26c490c15fd343d18f9232116bab6d7ba1f7fc918b7a324b071cda8b6a556dbb89226da6082f9efc55aa2667659c2f4f8db3e */
static const char *KAT_SUPPLY_V2    = "0054849ba0b8141bbfd6d42088bb93ec10fdae6024d113f2ca12ee600a08101a418555e0ddeb731abbdbbe42a94e67f522722bdc578a013ad3a3c7f0d89a11bb";
static const char *KAT_ACC_LEAF     = "ce416c2f0fb6ae548afca3e2b8639d218d58535bfb6cbb8fe3f17e371fc83488a37a3ad7007c37426a40605cdbdd5abf36e7fa4c97332fa8d0777cb68b290fa2";
static const char *KAT_ACC_ROOT_2   = "3f29e12e3f3d682b270f5ae70e79b47da0a6b282eae3bfe099715a1df7bc8a68eeb5ce99ddbd2817acb7e87a2213b01d5d58ccb0cc21d06a69db4e1460e3c715";
static const char *KAT_ACC_ROOT_3   = "7cba36466f3e76be1ae037ec90b67067e6c8f397ce1b418a5dcce77cce022fd6ed999c664699d1eff13f12f7b6897fc2c2b0a417f287cda4c574ccdf3b292b51";
static const char *KAT_TOKEN_LEAF_A = "29c4c9998ab9a29fe1a90bbcb021d743287ef733c03d896b67131d07cee9f9ef54347e2d2d64430814f900e804e298d86c085c051c8159d9e8fe471c5e720d47";
static const char *KAT_TOKEN_ROOT   = "0b039f37cdf12fb0c30580bdd338246c393d9d434d686e9f21627152bf545efc8c88e4ddcaef74d0ebef915cbed1d293c45559ae84325e56cdd7d0f2e7bbb9d7";
/* Root-layout round K2: KAT_EPOCH_LEAF1 / KAT_EPOCH_ROOT ("DNA.EPOCH.v2"
 * leaf and "DNA.EPNODE.v2" root) are DELETED with the functions they
 * pinned — retired tags are removed, never re-derived. */
static const char *KAT_DOMHEAD_SYS = "e675d070c918dedf23fa5d1ebf8d2381345705b316ffb1340e85738b50b6e01d7753a3e0ef456f3ff588fddcd4bba1c35a1edf7274ee46c48d2bd988b645b0b5";
static const char *KAT_DOMAINS_2    = "bba32c948f2851a85dae113c7b27258d27f4a292ee423faca3a072f5e31634bcd80bb608386d0b664c934db4997539b0c02599c8ee1a5430dea4e5d68430838a";
static const char *KAT_DOMAINS_3    = "823492dabf1bddd0b76b907d31233e4affeaf5b4f85caaccf55488eb5f6af5ad04d3c7993d38472887915535ec6a6cd608d8688ac8c7d6daa40efd0105c97d4e";
/* GENERICITY CORRECTION re-pin (supply ownership): core_state_root is SIX
 * legs (supply appended last, issuance is the DNA_CORE runtime's asset
 * commitment). Re-derived with the SAME independent python3 sha3_512
 * oracle as the S2 originals; the oracle reproduces the retired
 * 8-leg/5-leg values byte-exactly (673b7a1e… / b35098ed…), proving
 * derivation continuity.
 *
 * tokenomics-v3 P1 (D-4, S-2) re-pin: system_state_root gained an 8th leg
 * (attendance_root) and moved from SEVEN legs / tag "DNA.SYS.v1" to EIGHT
 * legs / tag "DNA.SYS.v2" — see KAT_SYSTEM_8LEG below and
 * shared/dnac/tests/ledger_roots_v2_attendance_oracle.py, which
 * self-checks against the retired 7-leg value before deriving the new
 * one. */
/* RETIRED, tokenomics-v3 P1 (D-4, S-2): the 7-leg "DNA.SYS.v1" composition
 * was superseded by the 8-leg "DNA.SYS.v2" — a changed composition is a
 * new tag, never the same tag over different bytes, so this value is
 * never re-derived, only removed. Kept here as a one-line historical
 * note, not as a live vector:
 *   5de7c65076b43e882f7cf814971dce313ce35d39573c5bf73f78b420c5611986f5c9bcfe01b0841af5c9ef6ae469ea00b96067c3ddbf888b5d947e40572d6e57
 * RETIRED, root-layout round K2 (2026-09-25): the 8-leg "DNA.SYS.v2"
 * vector (legs fill 0x90..0x97, the 3rd = epoch_state_root_v2) is
 * superseded by the 7-leg "DNA.SYS.v3" below. Historical note only:
 *   KAT_SYSTEM_8LEG ec9fc33017c755d6555a867c02b618b39fec4bea9e9740733561446e064e9b9e578691a670352277e14f021751da58e97b03fda0651ab7510500c3649ba22122
 * Both retired values are re-derived as CONTROL LEGS by
 * shared/dnac/tests/ledger_roots_v2_attendance_oracle.py before it emits
 * the two vectors below (same author, same day — SELF-CONSISTENT, not
 * an external audit; see the script's PROVENANCE). No "DNA.SYSPAYL.v1"
 * vector was ever pinned, so KAT_SYSPAYL_V2 has no payload-root control;
 * it rests on the same method the two SYS controls prove.
 *   KAT_SYSTEM_7LEG_V3: DNA.SYS.v3, legs fill(0x90..0x96) in the order
 *     validator, delegation, chain_config, vset, domreg, manifest,
 *     attendance.
 *   KAT_SYSPAYL_V2: DNA.SYSPAYL.v2, legs fill(0xA0..0xA3) in the order
 *     validator, delegation, chain_config, vset. */
static const char *KAT_SYSTEM_7LEG_V3 = "841abb1a867749ac68b688469513bbbc447962a8bbead05663d14d97744fda86aaad6bc67230578050f743a7fc3b7e94176bb0074c7ee7f1b247b74fb9a356fd";
static const char *KAT_SYSPAYL_V2     = "0bf7a1b805467d9c580faec171895abb0c63e3e1e9be83aa9ebfc263307c7ce123d685e607d9d5aa9c4b21b44cdad92c62de6d00f779a27b56b2b655432cdd4b";
static const char *KAT_CORE_7LEG    = "6316f2646cbe34ef0fc5c5d0487d62a9f72b4e58ccdbf40b5b7c3217210aeecd96d1fff0a313ed25434f0ca0990aa98791e4787ff4546a4d57d948b8f326c765";
static const char *KAT_GLOBAL       = "0c0d2fce1984bf15c2e5841eeef72a067aefe4cdf8790a713332f09326393f79185dc7277f3d403a6f9d47fbfc68b049ddb117a654f2da59e0e4218e45f7e681";
/* ── tokenomics-v3 P1 (D-4, S-2) — attendance leg, SELF-CONSISTENT with
 * shared/dnac/tests/ledger_roots_v2_attendance_oracle.py (same author,
 * same day; see that script's PROVENANCE section — not an external
 * audit). epoch_start=720, two rows (voter_id ASC: fill(0x01,32) then
 * fill(0x02,32)), signed_count/last_signed_height (100,5000) /
 * (200,6000). */
static const char *KAT_ATT_DIGEST_2ROW =
    "44d1f8e3115517ab9022060668e00c197e1256350a2ac3f65c2b0e2f4d41a7e7c1dc5ca281331bf7dedb7733eaa005080cbb727bc2ce4c7e8a3b6575cf6b9dee";
static const char *KAT_ATT_LEAF =
    "e6d3230258462204cf4a68c4e97f586435d4190bb058d5f3de4a5e963a33df26e9171ba93e81bcce660acb4549c0f2786e873a1ab8c751bc31d66c98d51013fa";
static const char *KAT_ATT_ROOT_2ENTRY =
    "800f63b49e5a71474b665bfe750a9d68e51b4f39bef796f6438e8e0d14c19b45f947637027af27b5572c0a7313d898d1b7f0ec586edf8e0f2e9ebbd4f79f1576";

/* ── Fixture token leaves (must mirror the oracle) ──────────────────── */
static void make_tokens(dna_v2_token_leaf_t t[3],
                        char cfp_a[129], char cfp_b[129], char cfp_c[129]) {
    memset(t, 0, 3 * sizeof(*t));
    memset(cfp_a, 0, 129); memset(cfp_b, 0, 129); memset(cfp_c, 0, 129);
    for (int i = 0; i < 128; i += 2) {
        cfp_a[i] = 'a'; cfp_a[i + 1] = 'a';
        cfp_b[i] = 'b'; cfp_b[i + 1] = 'b';
        cfp_c[i] = 'c'; cfp_c[i + 1] = 'c';
    }
    fill(t[0].token_id, 64, 0x10);
    t[0].name = "Alpha"; t[0].name_len = 5;
    t[0].symbol = "ALP"; t[0].symbol_len = 3;
    t[0].creator_fp = cfp_a; t[0].creator_fp_len = 128;
    t[0].decimals = 8; t[0].flags = 0; t[0].supply = 1000;
    t[0].block_height = 42;
    fill(t[1].token_id, 64, 0x20);
    t[1].name = "Beta"; t[1].name_len = 4;
    t[1].symbol = "BET"; t[1].symbol_len = 3;
    t[1].creator_fp = cfp_b; t[1].creator_fp_len = 128;
    t[1].decimals = 6; t[1].flags = 1; t[1].supply = 999999;
    t[1].block_height = 100;
    fill(t[2].token_id, 64, 0x30);
    t[2].name = "Gamma"; t[2].name_len = 5;
    t[2].symbol = "GAM"; t[2].symbol_len = 3;
    t[2].creator_fp = cfp_c; t[2].creator_fp_len = 128;
    t[2].decimals = 0; t[2].flags = 0; t[2].supply = 1;
    t[2].block_height = 7;
}

static int test_shared_layer(void) {
    uint8_t h[64], h2[64];

    /* Empty roots: pinned, nonzero, pairwise distinct. */
    uint8_t empties[DNA_V2_EMPTY__COUNT][64];
    uint8_t zero64[64] = { 0 };
    for (int k = 0; k < DNA_V2_EMPTY__COUNT; k++) {
        CHECK(dna_v2_empty_root((dna_v2_empty_kind_t)k, empties[k]) == 0,
              "empty root");
        CHECK(hex_eq(empties[k], EMPTY_KAT[k], "empty tag"), "empty KAT"); OK();
        CHECK(memcmp(empties[k], zero64, 64) != 0, "empty root is zero"); OK();
    }
    for (int a = 0; a < DNA_V2_EMPTY__COUNT; a++)
        for (int b = a + 1; b < DNA_V2_EMPTY__COUNT; b++) {
            CHECK(memcmp(empties[a], empties[b], 64) != 0,
                  "empty roots not distinct"); OK();
        }

    /* supply_root KAT: different counters change supply_root (the
     * supply counters are committed exactly once, here). */
    CHECK(dna_v2_supply_root(100000000000000000ULL, 500, 300, 400, h) == 0,
          "supply");
    CHECK(hex_eq(h, KAT_SUPPLY_V2, "supply"), "supply KAT"); OK();
    CHECK(dna_v2_supply_root(100000000000000000ULL, 501, 300, 400, h2) == 0 &&
          memcmp(h, h2, 64) != 0, "minted not bound in supply_root"); OK();
    /* tokenomics-v3 P2 (P2-8): the reward pool is bound too. */
    CHECK(dna_v2_supply_root(100000000000000000ULL, 500, 300, 401, h2) == 0 &&
          memcmp(h, h2, 64) != 0, "reward_pool not bound in supply_root");
    OK();
    /* tokenomics-v3 P2 (P2-8): the accrual leg — leaf KAT, n==1 == leaf,
     * two- and three-row roots (the odd third node PROMOTED), order and
     * duplicate rejection, n==0 == tagged empty. */
    {
        uint8_t fps[3][64], acc_root[64], leaf[64];
        uint64_t amts[3] = { 12345, 67890, 1 };
        fill(fps[0], 64, 0x11);
        fill(fps[1], 64, 0x22);
        fill(fps[2], 64, 0x33);
        CHECK(dna_v2_accrual_leaf_hash(fps[0], amts[0], leaf) == 0 &&
              hex_eq(leaf, KAT_ACC_LEAF, "acc leaf"), "acc leaf KAT"); OK();
        CHECK(dna_v2_accrual_root((const uint8_t (*)[64])fps, amts, 1,
                                  acc_root) == 0 &&
              memcmp(acc_root, leaf, 64) == 0, "acc root n==1 != leaf"); OK();
        CHECK(dna_v2_accrual_root((const uint8_t (*)[64])fps, amts, 2,
                                  acc_root) == 0 &&
              hex_eq(acc_root, KAT_ACC_ROOT_2, "acc root 2"),
              "acc root n==2 KAT"); OK();
        CHECK(dna_v2_accrual_root((const uint8_t (*)[64])fps, amts, 3,
                                  acc_root) == 0 &&
              hex_eq(acc_root, KAT_ACC_ROOT_3, "acc root 3"),
              "acc root n==3 KAT"); OK();
        CHECK(dna_v2_accrual_root(NULL, NULL, 0, acc_root) == 0 &&
              hex_eq(acc_root, EMPTY_KAT[DNA_V2_EMPTY_ACCRUAL],
                     "acc root n0"), "acc root n==0 KAT"); OK();
        uint8_t swapped[2][64];
        uint64_t samts[2] = { amts[1], amts[0] };
        memcpy(swapped[0], fps[1], 64);
        memcpy(swapped[1], fps[0], 64);
        CHECK(dna_v2_accrual_root((const uint8_t (*)[64])swapped, samts, 2,
                                  acc_root) != 0,
              "descending owner_fp accepted"); OK();
        memcpy(swapped[1], fps[1], 64);
        CHECK(dna_v2_accrual_root((const uint8_t (*)[64])swapped, samts, 2,
                                  acc_root) != 0,
              "duplicate owner_fp accepted"); OK();
    }
    /* Tokens: leaf + root KATs, order/duplicate rejection, field mutation. */
    {
        dna_v2_token_leaf_t t[3];
        char ca[129], cb[129], cc[129];
        make_tokens(t, ca, cb, cc);
        CHECK(dna_v2_token_leaf_hash(&t[0], h) == 0, "tok leaf");
        CHECK(hex_eq(h, KAT_TOKEN_LEAF_A, "token leaf A"), "tok leaf KAT"); OK();
        CHECK(dna_v2_token_root(t, 3, h) == 0, "tok root");
        CHECK(hex_eq(h, KAT_TOKEN_ROOT, "token root"), "tok root KAT"); OK();

        dna_v2_token_leaf_t bad[3] = { t[1], t[0], t[2] };  /* unsorted */
        CHECK(dna_v2_token_root(bad, 3, h) != 0, "unsorted accepted"); OK();
        dna_v2_token_leaf_t dup[2] = { t[0], t[0] };        /* duplicate */
        CHECK(dna_v2_token_root(dup, 2, h) != 0, "duplicate accepted"); OK();

        /* Every leaf field is bound. */
        dna_v2_token_leaf_t m = t[0];
        m.supply ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(h, h2, 64) != 0, "supply not bound"); OK();
        m = t[0]; m.decimals ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0, "hash");
        uint8_t href[64];
        CHECK(dna_v2_token_leaf_hash(&t[0], href) == 0 &&
              memcmp(href, h2, 64) != 0, "decimals not bound"); OK();
        m = t[0]; m.flags ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "flags not bound"); OK();
        m = t[0]; m.block_height ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "height not bound"); OK();
        m = t[0]; m.name = "Alphb";
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "name not bound"); OK();
        m = t[0]; m.symbol = "ALQ";
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "symbol not bound"); OK();
        m = t[0]; ca[0] = 'x';
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "creator not bound"); OK();
        ca[0] = 'a';
    }

    /* DomainHead + domains_root: KATs, generic third domain, negatives,
     * untouched-head byte identity. */
    {
        dna_v2_domain_head_t d[3];
        memset(d, 0, sizeof(d));
        d[0].domain_id = 0; fill(d[0].domain_state_root, 64, 0x60);
        d[0].ruleset_version = 1;
        d[1].domain_id = 1; fill(d[1].domain_state_root, 64, 0x70);
        d[1].ruleset_version = 1;
        d[2].domain_id = 7; fill(d[2].domain_state_root, 64, 0x80);
        d[2].domain_height = 3; d[2].last_updated_global_height = 9;
        d[2].ruleset_version = 2; d[2].status = 1;

        CHECK(dna_v2_domain_head_hash(&d[0], h) == 0, "domhead");
        CHECK(hex_eq(h, KAT_DOMHEAD_SYS, "domhead"), "domhead KAT"); OK();
        CHECK(dna_v2_domains_root(d, 2, h) == 0, "domains2");
        CHECK(hex_eq(h, KAT_DOMAINS_2, "domains2"), "domains2 KAT"); OK();
        /* GENERIC: a future third domain needs no format change. */
        CHECK(dna_v2_domains_root(d, 3, h) == 0, "domains3");
        CHECK(hex_eq(h, KAT_DOMAINS_3, "domains3"), "domains3 KAT"); OK();

        /* Untouched head → byte-identical encoding + hash. */
        uint8_t e1[DNA_V2_DOMHEAD_ENC_LEN], e2[DNA_V2_DOMHEAD_ENC_LEN];
        CHECK(dna_v2_domain_head_encode(&d[1], e1) == 0 &&
              dna_v2_domain_head_encode(&d[1], e2) == 0 &&
              memcmp(e1, e2, sizeof(e1)) == 0, "untouched head drifted"); OK();

        dna_v2_domain_head_t bad2[2] = { d[1], d[0] };      /* unsorted */
        CHECK(dna_v2_domains_root(bad2, 2, h) != 0, "unsorted domains"); OK();
        dna_v2_domain_head_t dup2[2] = { d[0], d[0] };      /* duplicate */
        CHECK(dna_v2_domains_root(dup2, 2, h) != 0, "dup domains"); OK();
        dna_v2_domain_head_t nosys[2] = { d[1], d[2] };     /* no SYSTEM */
        CHECK(dna_v2_domains_root(nosys, 2, h) != 0, "SYSTEM missing ok'd"); OK();
        CHECK(dna_v2_domains_root(d, 0, h) != 0, "empty domains ok'd"); OK();
    }

    /* ── tokenomics-v3 P1 (D-4, S-2): the attendance leg ─────────────
     * digest -> leaf -> root, self-consistent with
     * shared/dnac/tests/ledger_roots_v2_attendance_oracle.py. */
    {
        uint8_t voter0[32], voter1[32];
        fill(voter0, 32, 0x01);
        fill(voter1, 32, 0x02);
        dna_v2_attendance_row_t rows[2] = {
            { .signed_count = 100, .last_signed_height = 5000 },
            { .signed_count = 200, .last_signed_height = 6000 },
        };
        memcpy(rows[0].voter_id, voter0, 32);
        memcpy(rows[1].voter_id, voter1, 32);
        CHECK(dna_v2_attendance_digest(720, rows, 2, h) == 0, "att digest");
        CHECK(hex_eq(h, KAT_ATT_DIGEST_2ROW, "att digest"),
              "att digest KAT"); OK();
        /* strictly ascending voter_id enforced: swap the rows, expect -1 */
        dna_v2_attendance_row_t rows_bad[2] = { rows[1], rows[0] };
        CHECK(dna_v2_attendance_digest(720, rows_bad, 2, h2) != 0,
              "non-ascending voter_id accepted"); OK();
        dna_v2_attendance_row_t dup[2] = { rows[0], rows[0] };
        CHECK(dna_v2_attendance_digest(720, dup, 2, h2) != 0,
              "duplicate voter_id accepted"); OK();
        /* n == 0 hashes over zero rows, no special case (unlike the
         * MERKLE ROOT's n==0, which is the tagged empty root instead). */
        CHECK(dna_v2_attendance_digest(720, NULL, 0, h2) == 0 &&
              memcmp(h, h2, 64) != 0, "n==0 digest collides with n==2"); OK();

        uint8_t digest2row[64];
        memcpy(digest2row, h, 64);
        CHECK(dna_v2_attendance_leaf_hash(720, digest2row, h) == 0,
              "att leaf");
        CHECK(hex_eq(h, KAT_ATT_LEAF, "att leaf"), "att leaf KAT"); OK();

        /* root: n==0 -> tagged empty; n==1 -> the leaf itself; n==2 -> a
         * real inner node. */
        CHECK(dna_v2_attendance_root(NULL, NULL, 0, h2) == 0 &&
              hex_eq(h2, EMPTY_KAT[DNA_V2_EMPTY_ATTENDANCE], "att root n0"),
              "att root n==0 KAT"); OK();
        {
            uint64_t es1[1] = { 720 };
            uint8_t  dg1[1][64];
            memcpy(dg1[0], digest2row, 64);
            CHECK(dna_v2_attendance_root(es1, dg1, 1, h2) == 0 &&
                  memcmp(h2, h, 64) == 0,
                  "att root n==1 must equal the single leaf"); OK();
        }
        {
            uint64_t es2[2] = { 720, 1440 };
            uint8_t  dg2[2][64];
            memcpy(dg2[0], digest2row, 64);
            fill(dg2[1], 64, 0x60);
            CHECK(dna_v2_attendance_root(es2, dg2, 2, h2) == 0, "att root2");
            CHECK(hex_eq(h2, KAT_ATT_ROOT_2ENTRY, "att root2"),
                  "att root n==2 KAT"); OK();
            uint64_t dup_es[2] = { 720, 720 };
            CHECK(dna_v2_attendance_root(dup_es, dg2, 2, h2) != 0,
                  "duplicate epoch_start accepted"); OK();
            uint64_t desc_es[2] = { 1440, 720 };
            CHECK(dna_v2_attendance_root(desc_es, dg2, 2, h2) != 0,
                  "descending epoch_start accepted"); OK();
        }
    }

    /* Composition KATs + full subroot mutation sweep. SYSTEM = 7 legs
     * (validator/delegation/chain_config/vset/domreg/manifest/attendance
     * — "DNA.SYS.v3", root-layout round K2 removed the epoch leg); the
     * SYSTEM payload root = 4 legs (validator/delegation/chain_config/
     * vset — "DNA.SYSPAYL.v2"); CORE = 7 legs
     * (utxo/token/pools/claims/names/SUPPLY/ACCRUAL — native issuance is
     * CORE's own asset commitment; the accrual leg and "DNA.CORE.v2" are
     * tokenomics-v3 P2, P2-8). */
    {
        uint8_t legs[7][64];
        for (int i = 0; i < 7; i++) fill(legs[i], 64, (uint8_t)(0x90 + i));
        CHECK(dna_v2_system_root(legs[0], legs[1], legs[2], legs[3], legs[4],
                                 legs[5], legs[6], h) == 0, "sys");
        CHECK(hex_eq(h, KAT_SYSTEM_7LEG_V3, "system"), "system KAT"); OK();
        for (int i = 0; i < 7; i++) {
            legs[i][0] ^= 1;
            CHECK(dna_v2_system_root(legs[0], legs[1], legs[2], legs[3],
                                     legs[4], legs[5], legs[6],
                                     h2) == 0 && memcmp(h, h2, 64) != 0,
                  "system leg not bound"); OK();
            legs[i][0] ^= 1;
        }
        /* Leg ORDER is bound: swapping two legs moves the root. */
        CHECK(dna_v2_system_root(legs[1], legs[0], legs[2], legs[3],
                                 legs[4], legs[5], legs[6], h2) == 0 &&
              memcmp(h, h2, 64) != 0, "system leg order not bound"); OK();

        uint8_t pl[4][64];
        for (int i = 0; i < 4; i++) fill(pl[i], 64, (uint8_t)(0xA0 + i));
        CHECK(dna_v2_system_payload_root(pl[0], pl[1], pl[2], pl[3], h) == 0,
              "payload");
        CHECK(hex_eq(h, KAT_SYSPAYL_V2, "system payload"),
              "system payload KAT"); OK();
        for (int i = 0; i < 4; i++) {
            pl[i][0] ^= 1;
            CHECK(dna_v2_system_payload_root(pl[0], pl[1], pl[2], pl[3],
                                             h2) == 0 &&
                  memcmp(h, h2, 64) != 0, "payload leg not bound"); OK();
            pl[i][0] ^= 1;
        }
        /* The payload root and the full SYSTEM root are distinct tags:
         * the same four legs padded with the 3 container-lifetime legs'
         * bytes must not collide with the payload root. */
        CHECK(dna_v2_system_root(pl[0], pl[1], pl[2], pl[3], pl[0], pl[1],
                                 pl[2], h2) == 0 && memcmp(h, h2, 64) != 0,
              "payload root collides with a system root"); OK();
        CHECK(dna_v2_system_payload_root(NULL, pl[1], pl[2], pl[3], h2) != 0,
              "payload root accepted a NULL leg"); OK();
        uint8_t cl[7][64];
        for (int i = 0; i < 7; i++) fill(cl[i], 64, (uint8_t)(0xB0 + i));
        CHECK(dna_v2_core_root(cl[0], cl[1], cl[2], cl[3], cl[4], cl[5],
                               cl[6], h) == 0, "core");
        CHECK(hex_eq(h, KAT_CORE_7LEG, "core"), "core KAT"); OK();
        for (int i = 0; i < 7; i++) {
            cl[i][0] ^= 1;
            CHECK(dna_v2_core_root(cl[0], cl[1], cl[2], cl[3], cl[4],
                                   cl[5], cl[6], h2) == 0
                  && memcmp(h, h2, 64) != 0, "core leg not bound"); OK();
            cl[i][0] ^= 1;
        }
        uint8_t dr[64];
        fill(dr, 64, 0xC5);
        CHECK(dna_v2_global_root(dr, h) == 0, "global");
        CHECK(hex_eq(h, KAT_GLOBAL, "global"), "global KAT"); OK();
        dr[0] ^= 1;
        CHECK(dna_v2_global_root(dr, h2) == 0 && memcmp(h, h2, 64) != 0,
              "domains_root not bound"); OK();
    }
    return 0;
}

/* ── Witness-loader fixtures ────────────────────────────────────────── */

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Production tokens schema (nodus_witness.c) — hand-created per the
 * established witness-test pattern (test_witness_merkle.c). */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS tokens ("
    "  token_id BLOB PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL,"
    "  decimals INTEGER NOT NULL DEFAULT 8, supply INTEGER NOT NULL,"
    "  creator_fp TEXT NOT NULL, flags INTEGER NOT NULL DEFAULT 0,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0);"
    /* Root-layout round K2: no `epoch_state` table (production's schema
     * no longer creates it). K1: `unlock_block` is read by the UTXO leaf
     * loader, so the hand-written utxo_set carries it as production's
     * migrated table does (nodus_witness_db.c). */
    "CREATE TABLE IF NOT EXISTS utxo_set ("
    "  nullifier BLOB PRIMARY KEY, owner TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL, tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL DEFAULT 0,"
    "  unlock_block INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS validators ("
    "  pubkey BLOB PRIMARY KEY, self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL DEFAULT 0,"
    "  external_delegated INTEGER NOT NULL DEFAULT 0,"
    "  commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  active_since_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_destination_fp BLOB,"
    "  unstake_destination_pubkey BLOB,"
    "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0);"
    /* tokenomics-v3 P1 (Q2): last_signed_block / signed_blocks_this_epoch
     * REMOVED — this table is never populated in this file (validator_root
     * is always computed over it EMPTY; see the S3 comment below), so the
     * column list only needs to match the production shape for honesty,
     * never for a live INSERT. */
    "CREATE TABLE IF NOT EXISTS delegations ("
    "  delegator_pubkey BLOB NOT NULL, validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL, delegated_at_block INTEGER NOT NULL,"
    "  PRIMARY KEY (delegator_pubkey, validator_pubkey));"
    /* S3: nodus_witness_system_root_v2's validator-set leg is no longer a
     * hard-coded tagged empty root — it now reads this table via
     * nodus_witness_vset_root, which fails closed if the table is absent.
     * These fixtures leave it EMPTY, and an empty table yields exactly the
     * DNA_V2_EMPTY_VSET tagged root the S2 placeholder produced, so every
     * expectation in this file is unchanged. Snapshot-bearing coverage
     * lives in test_vset_persist.c. */
    "CREATE TABLE IF NOT EXISTS validator_set_snapshots ("
    "  epoch_start INTEGER PRIMARY KEY, active_count INTEGER NOT NULL,"
    "  snapshot_hash BLOB NOT NULL, snapshot_blob BLOB NOT NULL,"
    "  created_at_height INTEGER NOT NULL);"
    /* S4: the domain-registry leg is real (nodus_witness_domreg_root).
     * These fixtures leave the table EMPTY, and an empty registry yields
     * exactly the DNA_V2_EMPTY_DOMREG tagged root the S2 placeholder
     * produced, so every expectation in this file is unchanged.
     * Registry-bearing coverage lives in test_domreg.c. */
    "CREATE TABLE IF NOT EXISTS domain_registry ("
    "  domain_id INTEGER PRIMARY KEY, record BLOB NOT NULL,"
    "  current_manifest BLOB NOT NULL, pending_manifest BLOB);"
    /* tokenomics-v3 P2 (P2-8): the accrual leg is FAIL-CLOSED on an
     * absent table (nodus_witness_roots_v2.c nodus_witness_accrual_root_v2
     * — the table is in WITNESS_DB_SCHEMA and the S16 rung, so absence is
     * a fault there). This hand-written schema must therefore carry it,
     * as production's does; left EMPTY here, it yields the tagged
     * DNA_V2_EMPTY_ACCRUAL root. */
    "CREATE TABLE IF NOT EXISTS v2_reward_accrual ("
    "  owner_fp BLOB PRIMARY KEY, amount INTEGER NOT NULL);";

static int setup_w(nodus_witness_t **w_out) {
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB: heap-alloc */
    if (!w) return -1;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) { free(w); return -1; }
    if (run_sql(w->db, SCHEMA_SQL) != 0) {
        sqlite3_close(w->db); free(w);
        return -1;
    }
    nodus_chain_config_db_migrate(w);   /* creates chain_config_history */
    *w_out = w;
    return 0;
}

static void teardown_w(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

static int insert_token(nodus_witness_t *w, uint8_t id_seed,
                        const char *name, const char *symbol,
                        int decimals, long long supply, const char *cfp,
                        int flags, long long height, long long ts) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO tokens (token_id,name,symbol,decimals,supply,"
            "creator_fp,flags,block_height,timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    uint8_t tid[64];
    fill(tid, 64, id_seed);
    sqlite3_bind_blob(st, 1, tid, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, symbol, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 4, decimals);
    sqlite3_bind_int64(st, 5, supply);
    sqlite3_bind_text(st, 6, cfp, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 7, flags);
    sqlite3_bind_int64(st, 8, height);
    sqlite3_bind_int64(st, 9, ts);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int populate_fixture(nodus_witness_t *w, int reversed,
                            long long ts_base) {
    char ca[129], cb[129], cc[129];
    memset(ca, 0, 129); memset(cb, 0, 129); memset(cc, 0, 129);
    for (int i = 0; i < 128; i += 2) {
        ca[i] = 'a'; ca[i + 1] = 'a';
        cb[i] = 'b'; cb[i + 1] = 'b';
        cc[i] = 'c'; cc[i + 1] = 'c';
    }
    /* Insertion order varies; the local-clock ts column varies too — the
     * root must be independent of BOTH. */
    if (!reversed) {
        if (insert_token(w, 0x10, "Alpha", "ALP", 8, 1000, ca, 0, 42,
                         ts_base + 1) != 0) return -1;
        if (insert_token(w, 0x20, "Beta", "BET", 6, 999999, cb, 1, 100,
                         ts_base + 2) != 0) return -1;
        if (insert_token(w, 0x30, "Gamma", "GAM", 0, 1, cc, 0, 7,
                         ts_base + 3) != 0) return -1;
    } else {
        if (insert_token(w, 0x30, "Gamma", "GAM", 0, 1, cc, 0, 7,
                         ts_base + 9) != 0) return -1;
        if (insert_token(w, 0x10, "Alpha", "ALP", 8, 1000, ca, 0, 42,
                         ts_base + 8) != 0) return -1;
        if (insert_token(w, 0x20, "Beta", "BET", 6, 999999, cb, 1, 100,
                         ts_base + 7) != 0) return -1;
    }
    /* Root-layout round K2: the epoch_state row this fixture used to
     * insert is gone with the table. */
    /* Supply row via the production initializer (creates supply_tracking). */
    uint8_t gh[64];
    fill(gh, 64, 0x77);
    /* tokenomics-v3 P2: reward pool 0 — the fixture's supply leaf then
     * hashes (1e17, 0, 0, 0). */
    if (nodus_witness_supply_init(w, 100000000000000000ULL, 0, gh) != 0)
        return -1;
    return 0;
}

static int test_loaders(void) {
    uint8_t r1[64], r2[64], h[64];

    /* Order independence: two DBs, different insertion order + different
     * local-clock timestamps → identical token_root (ts EXCLUDED). */
    nodus_witness_t *wa = NULL, *wb = NULL;
    CHECK(setup_w(&wa) == 0 && setup_w(&wb) == 0, "setup");
    CHECK(populate_fixture(wa, 0, 1000) == 0, "pop a");
    CHECK(populate_fixture(wb, 1, 555000) == 0, "pop b");
    CHECK(nodus_witness_token_root_v2(wa, r1) == 0, "tok root a");
    CHECK(nodus_witness_token_root_v2(wb, r2) == 0, "tok root b");
    CHECK(memcmp(r1, r2, 64) == 0,
          "insertion order / local ts influenced token_root"); OK();
    /* The DB-loaded root equals the shared-layer oracle-pinned root. */
    CHECK(hex_eq(r1, KAT_TOKEN_ROOT, "db token root"), "db tok KAT"); OK();

    /* Root-layout round K2: the DB-loaded SYSTEM compositions equal the
     * shared-layer functions over the individually loaded legs, IN THE
     * K2 ORDER — the witness wiring cannot drift from the pinned
     * composition (a leg dropped, duplicated or reordered moves it).
     * KILLED BY: re-adding an epoch leg, or swapping two legs, in
     * nodus_witness_system_root_v2 / _system_payload_root_v2. */
    {
        uint8_t v[64], dl[64], cc[64], vs[64], dr[64], mf[64], at[64];
        uint8_t expect[64];
        CHECK(nodus_witness_merkle_compute_validator_root(wa, v) == 0 &&
              nodus_witness_merkle_compute_delegation_root(wa, dl) == 0 &&
              nodus_chain_config_compute_root(wa, cc) == 0 &&
              nodus_witness_vset_root(wa, vs) == 0 &&
              nodus_witness_domreg_root(wa, dr) == 0 &&
              nodus_witness_manifest_root_v2(wa, mf) == 0 &&
              nodus_witness_attendance_root(wa, at) == 0, "legs");
        CHECK(nodus_witness_system_root_v2(wa, h) == 0 &&
              dna_v2_system_root(v, dl, cc, vs, dr, mf, at, expect) == 0 &&
              memcmp(h, expect, 64) == 0,
              "witness SYSTEM root != 7-leg DNA.SYS.v3 composition"); OK();
        CHECK(nodus_witness_system_payload_root_v2(wa, h) == 0 &&
              dna_v2_system_payload_root(v, dl, cc, vs, expect) == 0 &&
              memcmp(h, expect, 64) == 0,
              "witness payload root != 4-leg DNA.SYSPAYL.v2 composition");
        OK();
    }

    /* Supply root from DB (init writes genesis=1e17, minted=0, burned=0,
     * reward_pool=0). */
    {
        uint8_t expect[64];
        CHECK(nodus_witness_supply_root_v2(wa, h) == 0, "supply root");
        CHECK(dna_v2_supply_root(100000000000000000ULL, 0, 0, 0,
                                 expect) == 0 &&
              memcmp(h, expect, 64) == 0, "db supply root mismatch"); OK();
    }
    /* tokenomics-v3 P2 (P2-8): the reward pool is IN the supply leaf —
     * moving it moves the CORE root and NOT the SYSTEM root. KILLED BY:
     * dropping reward_pool from dna_v2_supply_root's preimage or from
     * nodus_witness_supply_root_v2's call. */
    {
        uint8_t sys0[64], core0[64], sys1[64], core1[64];
        CHECK(nodus_witness_system_root_v2(wa, sys0) == 0 &&
              nodus_witness_core_root_v2(wa, core0) == 0, "roots pre-pool");
        CHECK(run_sql(wa->db,
              "UPDATE supply_tracking SET reward_pool = reward_pool + 11")
                  == 0, "pool mutation");
        CHECK(nodus_witness_system_root_v2(wa, sys1) == 0 &&
              nodus_witness_core_root_v2(wa, core1) == 0, "roots post-pool");
        CHECK(memcmp(core0, core1, 64) != 0,
              "a reward-pool move must change the CORE root"); OK();
        CHECK(memcmp(sys0, sys1, 64) == 0,
              "a reward-pool move must NOT change the SYSTEM root"); OK();
        CHECK(run_sql(wa->db,
              "UPDATE supply_tracking SET reward_pool = reward_pool - 11")
                  == 0, "pool restore");
    }
    /* tokenomics-v3 P2 (P2-8): the accrual leg — an empty table is the
     * tagged empty root, a row moves the CORE root, a malformed row
     * (amount 0) FAILS it. KILLED BY: dropping accrual_root from the
     * CORE composition; skipping instead of failing on a bad row. */
    {
        uint8_t acc[64], empty[64], core0[64], core1[64];
        CHECK(nodus_witness_accrual_root_v2(wa, acc) == 0 &&
              dna_v2_empty_root(DNA_V2_EMPTY_ACCRUAL, empty) == 0 &&
              memcmp(acc, empty, 64) == 0,
              "empty accrual table must be the tagged empty root"); OK();
        CHECK(nodus_witness_core_root_v2(wa, core0) == 0, "core pre-acc");
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO v2_reward_accrual (owner_fp, amount) "
                 "VALUES (zeroblob(64), 5)");
        CHECK(run_sql(wa->db, sql) == 0, "accrual insert");
        CHECK(nodus_witness_core_root_v2(wa, core1) == 0 &&
              memcmp(core0, core1, 64) != 0,
              "an accrual row must change the CORE root"); OK();
        CHECK(run_sql(wa->db, "UPDATE v2_reward_accrual SET amount = 0")
                  == 0, "zero the accrual");
        CHECK(nodus_witness_accrual_root_v2(wa, acc) != 0,
              "a zero-amount accrual row must FAIL the root"); OK();
        CHECK(run_sql(wa->db, "DELETE FROM v2_reward_accrual") == 0,
              "accrual cleanup");
    }

    /* SUPPLY OWNERSHIP (locked correction): mutating native issuance
     * counters changes the DNA_CORE state root and does NOT change the
     * SYSTEM state root — SYSTEM no longer commits the supply leg. */
    {
        uint8_t sys0[64], core0[64], sys1[64], core1[64];
        CHECK(nodus_witness_system_root_v2(wa, sys0) == 0 &&
              nodus_witness_core_root_v2(wa, core0) == 0, "roots before");
        CHECK(run_sql(wa->db,
              "UPDATE supply_tracking SET total_minted = total_minted + 7")
                  == 0, "mint mutation");
        CHECK(nodus_witness_system_root_v2(wa, sys1) == 0 &&
              nodus_witness_core_root_v2(wa, core1) == 0, "roots after");
        CHECK(memcmp(core0, core1, 64) != 0,
              "issuance mutation must change the CORE root"); OK();
        CHECK(memcmp(sys0, sys1, 64) == 0,
              "issuance mutation must NOT change the SYSTEM root"); OK();
        CHECK(run_sql(wa->db,
              "UPDATE supply_tracking SET total_burned = total_burned + 3")
                  == 0, "burn mutation");
        uint8_t core2[64];
        CHECK(nodus_witness_core_root_v2(wa, core2) == 0 &&
              memcmp(core1, core2, 64) != 0,
              "burn must change the CORE root"); OK();
        CHECK(run_sql(wa->db,
              "UPDATE supply_tracking SET total_minted = total_minted - 7, "
              "total_burned = total_burned - 3") == 0, "restore");
    }

    /* Full assembly runs on real state. */
    {
        uint8_t g[64], d[64], s[64], c[64];
        CHECK(nodus_witness_global_root_v2(wa, g, d, s, c) == 0, "global");
        uint8_t g2[64];
        CHECK(nodus_witness_global_root_v2(wa, g2, NULL, NULL, NULL) == 0 &&
              memcmp(g, g2, 64) == 0, "global determinism"); OK();
    }

    /* Fail-closed: malformed token row (short token_id) fails the root. */
    {
        nodus_witness_t *wm = NULL;
        CHECK(setup_w(&wm) == 0, "setup m");
        CHECK(run_sql(wm->db,
            "INSERT INTO tokens (token_id,name,symbol,decimals,supply,"
            "creator_fp,flags,block_height,timestamp) "
            "VALUES (x'1122', 'Bad', 'BAD', 8, 1, 'ff', 0, 1, 0)") == 0,
            "insert bad");
        CHECK(nodus_witness_token_root_v2(wm, h) != 0,
              "malformed token row did not fail the root"); OK();
        teardown_w(wm);
    }
    /* Fail-closed: missing tokens table (schema-less DB) fails. */
    {
        nodus_witness_t *we = calloc(1, sizeof(*we));
        CHECK(we != NULL, "alloc");
        CHECK(sqlite3_open(":memory:", &we->db) == SQLITE_OK, "open");
        CHECK(nodus_witness_token_root_v2(we, h) != 0,
              "missing tokens table did not fail"); OK();
        /* Root-layout round K2: the "absent epoch table -> tagged empty
         * root" check that stood here is gone with the epoch leg. */
        teardown_w(we);
    }
    /* Empty (but present) registries: token_root = tagged empty. */
    {
        nodus_witness_t *w0 = NULL;
        CHECK(setup_w(&w0) == 0, "setup 0");
        uint8_t expect[64];
        CHECK(nodus_witness_token_root_v2(w0, h) == 0 &&
              dna_v2_empty_root(DNA_V2_EMPTY_TOKENS, expect) == 0 &&
              memcmp(h, expect, 64) == 0, "empty registry != tagged empty");
        OK();
        teardown_w(w0);
    }

    teardown_w(wa);
    teardown_w(wb);
    return 0;
}

/* ── 7/7 determinism: seven independent instances, identical state ───── */
static int test_7of7(void) {
    uint8_t g[7][64], d[7][64], s[7][64], c[7][64];
    for (int i = 0; i < 7; i++) {
        nodus_witness_t *w = NULL;
        CHECK(setup_w(&w) == 0, "setup i");
        /* Identical logical state; per-node local clock differs (ts_base)
         * and half the nodes saw a different insertion order — as on a
         * real cluster. */
        CHECK(populate_fixture(w, i & 1, 1000 + i * 7919) == 0, "pop i");
        CHECK(nodus_witness_global_root_v2(w, g[i], d[i], s[i], c[i]) == 0,
              "global i");
        teardown_w(w);
    }
    for (int i = 1; i < 7; i++) {
        CHECK(memcmp(g[0], g[i], 64) == 0, "global_root 7/7 divergence"); OK();
        CHECK(memcmp(d[0], d[i], 64) == 0, "domains_root 7/7 divergence"); OK();
        CHECK(memcmp(s[0], s[i], 64) == 0, "system_root 7/7 divergence"); OK();
        CHECK(memcmp(c[0], c[i], 64) == 0, "core_root 7/7 divergence"); OK();
    }
    printf("7/7 determinism: global=%02x%02x%02x%02x... identical across 7 "
           "independent instances\n", g[0][0], g[0][1], g[0][2], g[0][3]);
    return 0;
}

int main(void) {
    if (test_shared_layer() != 0) return 1;
    if (test_loaders() != 0) return 1;
    if (test_7of7() != 0) return 1;
    printf("test_roots_v2: %d checks OK\n", g_checks);
    return 0;
}
