/**
 * Nodus — HF-7 P1a: the §8.9 root functions against the independent KAT.
 *
 * WHAT IT PROVES. The C functions of shared/dnac/ledger_roots_v2.c that
 * implement the snapshot design's normative byte spec §8.9 S1-S8
 * (docs/plans/2026-09-11-nodus-ledger-snapshot-design.md, APPROVED by the
 * operator 2026-10-15) produce, byte for byte, every value of the
 * independent oracle's KAT nodus/tests/vectors/hf7_root_coverage_kat.json
 * (generator hf7_root_coverage_oracle.py, branch hf7 e7c1de2f6): every
 * leaf, every root (n = 0, 1, 2, 3, 5), the four empty roots, vstat, the
 * DomainHead v2 encoding + head hash, domains_root over v2 heads, SYSTEM
 * v6 and GLOBAL v2 — and refuse (-1) every ERROR vector the C signature
 * can express (out-of-range integer, unsorted keys, duplicate key, the
 * duplicate intent_id, the S6 empty list / first head not domain 0, the
 * S2 absent row). Every literal below is COPIED from the KAT JSON; none
 * was computed by the C under test.
 *
 * KAT VECTORS NOT EXECUTABLE THROUGH THE C SIGNATURE (8 of 87 — the
 * parameter type itself is the check, so no call can carry the defect):
 *   S1 validator_fp_len_63, S5 root_len_65, S7 intent_id_len_0,
 *   S8 domains_root_len_63 — fixed 64-byte arrays, a wrong length cannot
 *   be passed; S4 only_8_v5_legs — twelve named 64-byte parameters;
 *   S7 expiry_2^64 — expiry_height is uint64_t (khan decision D,
 *   2026-10-20: "the S7 root function takes u64"); S6 domain_id_2^32 and
 *   status_256 — the existing dna_v2_domain_head_t carries domain_id as
 *   uint32_t and status as uint8_t (§8.9 S6 reuses today's enc89).
 *   These are NOT passes and NOT skips: they are absent coverage at this
 *   layer, closed by the types; the caller (P1c) owns the narrowing from
 *   SQLite before the call.
 * Representation choices that ARE exercised: S1 kind and S3 fail_streak
 * are uint64_t row fields (range-checked, then encoded as u8 / u32), so
 * kind_2 and fail_streak_2^32 run; S1 amount_negative is passed as the
 * uint64_t a SQLite int64 -1 becomes (2^64 − 1), which is refused; S2
 * "absent" is a NULL pointer.
 *
 * REQUIRES. A default nodus build; no compile flag, no environment, no
 * network, no file read at run time (the vectors are compiled in).
 *
 * LEAVES BEHIND. Nothing.
 *
 * HOW IT CAN LIE. The KAT is SELF-CONSISTENT: the oracle was written from
 * the same §8.9 text by a different agent. A green run proves the C equals
 * the spec text as the oracle read it — NOT that the spec is sound, and
 * NOT that any caller uses these functions (P1a has no caller; the roots
 * are inert until P1c wires them by rule-set generation). The 8 vectors
 * above are not run. Error vectors assert only "-1", not which check
 * refused (the file's return convention has one error code).
 *
 * @file test_roots_hf7.c
 */

#include "dnac/ledger_roots_v2.h"

#include <stdint.h>
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

static int nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Lowercase hex of exactly 2·len characters → len bytes. 0 / -1. */
static int unhex(const char *hex, uint8_t *out, size_t len) {
    if (!hex || strlen(hex) != 2 * len) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int hex_eq_n(const uint8_t *h, size_t len, const char *hex,
                    const char *what) {
    static const char *d = "0123456789abcdef";
    char got[2 * 128 + 1];
    if (len > 128) return 0;
    for (size_t i = 0; i < len; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[2 * len] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

static int hex_eq(const uint8_t h[64], const char *hex, const char *what) {
    return hex_eq_n(h, 64, hex, what);
}

/* ── KAT row shapes (literals copied from the JSON) ────────────────────── */

typedef struct {
    uint64_t epoch_start;
    const char *validator_fp, *owner_fp;
    uint64_t kind, amount;
    const char *leaf;                    /* NULL in an ERROR vector      */
} kat_bc_t;
typedef struct {
    const char *name; const kat_bc_t *rows; size_t n; const char *root;
} kat_bc_set_t;

typedef struct { uint64_t active_count; const char *vstat; } kat_vstat_t;

typedef struct {
    uint64_t epoch_start;
    const char *node_fp;
    uint64_t fail_streak, grace_until;
    const char *leaf;
} kat_sm_t;
typedef struct {
    const char *name; const kat_sm_t *rows; size_t n; const char *root;
} kat_sm_set_t;

typedef struct {
    const char *name;
    const char *legs[12];                /* 9 v5 legs, bcopy, vstat, stmem */
    const char *root;
} kat_sys6_t;

typedef struct {
    uint64_t k;
    const char *root_k;
    uint64_t published_height;
    const char *leaf;
} kat_seg_t;
typedef struct {
    const char *name; const kat_seg_t *rows; size_t n; const char *root;
} kat_seg_set_t;

typedef struct {
    uint32_t domain_id;
    const char *domain_state_root;
    uint64_t domain_height, last_updated_global_height;
    uint32_t ruleset_version;
    uint8_t status;
    const char *last_upd_hash;
    const char *head_hash;
} kat_head_t;
typedef struct {
    const char *name; const kat_head_t *rows; size_t n; const char *root;
} kat_head_set_t;

typedef struct {
    const char *tx_id, *intent_id;
    uint64_t expiry_height;
    const char *leaf;
} kat_rp_t;
typedef struct {
    const char *name; const kat_rp_t *rows; size_t n; const char *root;
} kat_rp_set_t;

typedef struct {
    const char *name, *domains_root, *replay_root, *root;
} kat_glob_t;

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

/* ════════════════════════════════════════════════════════════════════════
 * KAT DATA — copied from nodus/tests/vectors/hf7_root_coverage_kat.json
 * ════════════════════════════════════════════════════════════════════════ */

/* ── S1 balance copy (KAT vectors.S1_balance_copy) ── */
static const kat_bc_t S1_R0[] = {
    { 0, NULL, NULL, 0, 0, NULL }
};
static const kat_bc_t S1_R1[] = {
    { UINT64_C(0),
      "71754c89bb5366f614bca395abc80e06bf82271eabbc985821a6bf8cff73ffce3492c63ee724eb7dc7abb969c275d228ab6a3f21b47a45900ab3d8657f870fb3",
      "830d96b5933a0ad9729706590bcdd7a745085d5621b617b75e43b2c032ed4716554356ba1aa70c585b32a846dd0d9f53c82c66db63adf5f3ae0169d1a6e212e2",
      UINT64_C(0), UINT64_C(0),
      "95bda9533353279411cc326cc625909e89e58b3d411c18f221ead93d6d63a13d4e4f2ee5a4f2cbd34357773d7f7ab3bd9216a4f952a86e9a54fe2b79fcd085a7" },
};
static const kat_bc_t S1_R2[] = {
    { UINT64_C(0),
      "f992c82cf20cee57581c56308a735e8470fd70415d52024737bf1a9967c9ceb640ca63b3041b4c176f727237245e315876aa870a6a9c0dbde48ad4d76ca1978b",
      "e9244a823bc3e443a5852fcc0d6ee416ffe7e09ac9000d942012317b25ba1b77be4db940027f7ab226de5d7b75d8aadc6835db517b17743cbb4a4df4b84f9bd4",
      UINT64_C(0), UINT64_C(0),
      "ee93b1d59f162a9caae91a637cfe6f39cd6631c2621bd13ea97d4faee42c16927dbca1fbe9663febf2a2f4642fa1d848207aca6d7549592738ddaf0d46ce8644" },
    { UINT64_C(0),
      "f992c82cf20cee57581c56308a735e8470fd70415d52024737bf1a9967c9ceb640ca63b3041b4c176f727237245e315876aa870a6a9c0dbde48ad4d76ca1978b",
      "e9244a823bc3e443a5852fcc0d6ee416ffe7e09ac9000d942012317b25ba1b77be4db940027f7ab226de5d7b75d8aadc6835db517b17743cbb4a4df4b84f9bd4",
      UINT64_C(1), UINT64_C(1),
      "7e6eef172038d5bbbbd9ded240e56a8f561976c5014df871de003df3a39e58c5d05c664e62db79d7c4bc26ec97146afcc4b98ac1966da03337793523c2dc81e7" },
};
static const kat_bc_t S1_R3[] = {
    { UINT64_C(0),
      "09df92a971c2f49ca444d6c73d1a53e57c1f40e355a8d46ad22022a185b11bbd61af966bca843910c933cead0c2c0b1a97cb4ce4d0f64bd37809803ea35369a3",
      "17ed319264df1047cc654d420066d2c7eae76a5279861303830180cd1f27f308668f617af14b3bbf971079542084ab8a84b070a9f7c21af37d8adfef60894048",
      UINT64_C(0), UINT64_C(0),
      "a667f519e6e734c3abc0706745e4648569fd01759a5dc56b6fd2480afa0102ae811fa58c0166402eb9044092ad6768a414472376bc1f608fea31f218d45cf7e1" },
    { UINT64_C(0),
      "09df92a971c2f49ca444d6c73d1a53e57c1f40e355a8d46ad22022a185b11bbd61af966bca843910c933cead0c2c0b1a97cb4ce4d0f64bd37809803ea35369a3",
      "17ed319264df1047cc654d420066d2c7eae76a5279861303830180cd1f27f308668f617af14b3bbf971079542084ab8a84b070a9f7c21af37d8adfef60894048",
      UINT64_C(1), UINT64_C(1),
      "440a1c50d4f41656d96a8c0e128cac41d4421883cdab2b5300740a7adb720ac3f6f4d35b943346d7c915ce78d27fa74f36eb473dc726108741d6f0f07fc26c61" },
    { UINT64_C(720),
      "09df92a971c2f49ca444d6c73d1a53e57c1f40e355a8d46ad22022a185b11bbd61af966bca843910c933cead0c2c0b1a97cb4ce4d0f64bd37809803ea35369a3",
      "6b3b2e95fa97c4b7c05e7cd460830bfb99d2e54dfd84351231fcb68b8faf8327a31ecb7f5891d9fd2bd9a23f06a5f753e8736b6a2fb0c02067a71eb7b61e9cec",
      UINT64_C(0), UINT64_C(1000000000000000),
      "c33c52e81c49043969b3eb93498904be128ca1cb4be5b4a3924781a38375fa3bc89eb55a6617d2f8566065d832453f64c3cf786a080b09078be6c6954ef5fddd" },
};
static const kat_bc_t S1_R5[] = {
    { UINT64_C(0),
      "5be3dadb1d9d6ce5e6e4d18e0861761110d978080bcb966aa15410ecbf925ee04b665da238d0ccf45d8efd55fb412feda642f814d0bb94ff1b5d6ceea5d00fbc",
      "96daa67d1ebafd930398a4d26886d71405225f5f014f2aa0b50862737b1cf6e47a5529c7215a4cb830f8d1dad1bcffaf4311afdeddb751b45f0bba2d3d06406b",
      UINT64_C(0), UINT64_C(0),
      "ac8716e577129ac8669faa70d959e2a0feb245d6468532167b72023078604a683510079bf503c12e539db30d426f469d82de0ad599df100a9cded8f638cc0ebb" },
    { UINT64_C(0),
      "5be3dadb1d9d6ce5e6e4d18e0861761110d978080bcb966aa15410ecbf925ee04b665da238d0ccf45d8efd55fb412feda642f814d0bb94ff1b5d6ceea5d00fbc",
      "96daa67d1ebafd930398a4d26886d71405225f5f014f2aa0b50862737b1cf6e47a5529c7215a4cb830f8d1dad1bcffaf4311afdeddb751b45f0bba2d3d06406b",
      UINT64_C(1), UINT64_C(1),
      "ab4f3c0ec3b19ff50a79d068f151250529ed45fbd1fda85721d7e67e802930c666825baf77e48158346ce25cc7b532a77b7450d60e6c4a621149f507eefd1cb7" },
    { UINT64_C(720),
      "5b326da620602fc7a43d52016880267fd98d45048a35de1203015f8f4f93b2349d557de2018303319d8aece7b45e8ad9f57cbed12a604ff777b4cae0d7e1f39b",
      "96daa67d1ebafd930398a4d26886d71405225f5f014f2aa0b50862737b1cf6e47a5529c7215a4cb830f8d1dad1bcffaf4311afdeddb751b45f0bba2d3d06406b",
      UINT64_C(1), UINT64_C(9223372036854775807),
      "7658010780f1106c153e608a7afa8fe2d17e4e766dbaeb390e6437950c1c30fc6b890f447e6857cd9de0d2b17216ccc739297b3522c671d64ba8f1ad703fb547" },
    { UINT64_C(720),
      "5be3dadb1d9d6ce5e6e4d18e0861761110d978080bcb966aa15410ecbf925ee04b665da238d0ccf45d8efd55fb412feda642f814d0bb94ff1b5d6ceea5d00fbc",
      "e6bfb28be5317502eef1ff2662a09f81f54eacfa4686230c1dceedaa45cc0d8e80281b72efaa6689c39b7867f1d4392275766adbc0bcbb302dcda513315d4f48",
      UINT64_C(0), UINT64_C(1000000000000000),
      "7500d3aef262532b6e88e25e4af8a9e5ed177a4c75c63923555f9ec1cc5e8f4d4a3805e844947ca1704d571e80d78baccede5e05676e21531a3be9021b19cff8" },
    { UINT64_C(9223372036854775807),
      "27164f04dc079a3cd22341746aa4b5043d404b56b7a95decd7fc5ea879691c9784c1906f1b5655e70f8a697ef4efbb596e99d11b783eb2431877b5da7ed0fa94",
      "fe91fcbe391669d49cda6978811cdaee02de59cbee480e6d3bb866dfea823e018c741e0ce6e419780a4e5d14f84ab02dc60242bd1c560d06734255cdec2bf796",
      UINT64_C(0), UINT64_C(123456789),
      "3c4af64a3d2d0f2ffb8b3ffe24e20786fc2fc216e038d3d67f2e51e0ce1cb4d40b8faaaead3febc1c11a6bd1164964d584f219ff435f4fc25ab1c078c2b29f98" },
};
static const kat_bc_set_t S1_ROOTS[] = {
    { "n=0", S1_R0, 0,
      "8c89eea63e93017d8c548c2a727a2c1764f1b287e6af1e065b9eeeb3dcf2a152b8e47d0eed8f807f23b2dfd60710c0c2d53371a456544461b30179af490bf4e5" },
    { "n=1", S1_R1, 1,
      "95bda9533353279411cc326cc625909e89e58b3d411c18f221ead93d6d63a13d4e4f2ee5a4f2cbd34357773d7f7ab3bd9216a4f952a86e9a54fe2b79fcd085a7" },
    { "n=2", S1_R2, 2,
      "37657a0ff8929e769a2d19ec082764237dfea1941530ba1d9dde714033fd596f51a6b6fff5948023a9f24c305a8f504b766d479946113b0e9e6cbdef5793b296" },
    { "n=3", S1_R3, 3,
      "c95bd4765de6bd9cc87c2f0c595f8828adc16a5c81bdfada9272e09ccb949e813b6a4aea9f64da56598b12064b347995b4f2f6d9b57a04649793e6e9c675f52b" },
    { "n=5", S1_R5, 5,
      "50b9e7970ba3ef5572c7537b69c05df6c52d7b161e529ecdfcbc95aecbe92fab0a158ab9940e4510eb504b04547c1ecc90c8ba16b0a78070c2f11b28b4484c17" },
};
static const kat_bc_t S1_E0[] = { /* epoch_start_2^63: out-of-range integer: epoch_start = 9223372036854775808, allowed 0..9223372036854775807 */
    { UINT64_C(9223372036854775808),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(1),
      NULL },
};
static const kat_bc_t S1_E1[] = { /* kind_2: out-of-range integer: kind = 2, allowed 0..1 */
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(2), UINT64_C(1),
      NULL },
};
static const kat_bc_t S1_E2[] = { /* amount_2^63: out-of-range integer: amount = 9223372036854775808, allowed 0..9223372036854775807 */
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(9223372036854775808),
      NULL },
};
/* amount_negative: the KAT's amount = -1 as the uint64_t a SQLite int64
 * -1 becomes (2^64 − 1) — refused by the 0..2^63−1 range. */
static const kat_bc_t S1_E3[] = { /* amount_negative: out-of-range integer: amount = -1, allowed 0..9223372036854775807 */
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(18446744073709551615),
      NULL },
};
static const kat_bc_t S1_E5[] = { /* unsorted_kind_descending: unsorted keys at index 1 */
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(1), UINT64_C(5),
      NULL },
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(5),
      NULL },
};
static const kat_bc_t S1_E6[] = { /* unsorted_validator_fp_memcmp: unsorted keys at index 1 */
    { UINT64_C(720),
      "e8831425c80de03b26039b745ed3efdbd1e9f8caf56cfa50c0b6df3e372e219cf64d958b39b948dba7ce3c74aeff18fd4635f640691a35961af06d018d765e87",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(5),
      NULL },
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(5),
      NULL },
};
static const kat_bc_t S1_E7[] = { /* unsorted_epoch_start: unsorted keys at index 1 */
    { UINT64_C(1440),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(5),
      NULL },
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(0), UINT64_C(5),
      NULL },
};
static const kat_bc_t S1_E8[] = { /* duplicate_key_amount_differs: duplicate key at index 1 */
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(1), UINT64_C(5),
      NULL },
    { UINT64_C(720),
      "80e5c6add42399c9c4286af3f24754d92abd187a000a5ca48378c11b09b5274fc49d2a51aa6db827b3b73fafd7679c4edb655dde5432eaaa5ff1be4138af4062",
      "87067ec8c3888292873165811681a933386d0680065c49a2a39622454818a645f68615c1f12b575264c04ada896e6991879af48324b2167586d9b1c433b80a4b",
      UINT64_C(1), UINT64_C(6),
      NULL },
};
/* S1 validator_fp_len_63 (KAT errors[4]) — not expressible: a fixed
 * 64-byte array (see the file header). */
static const kat_bc_set_t S1_ERRS[] = {
    { "epoch_start_2^63", S1_E0, 1, NULL },
    { "kind_2", S1_E1, 1, NULL },
    { "amount_2^63", S1_E2, 1, NULL },
    { "amount_negative", S1_E3, 1, NULL },
    { "unsorted_kind_descending", S1_E5, 2, NULL },
    { "unsorted_validator_fp_memcmp", S1_E6, 2, NULL },
    { "unsorted_epoch_start", S1_E7, 2, NULL },
    { "duplicate_key_amount_differs", S1_E8, 2, NULL },
};
/* ── S2 active count (KAT vectors.S2_active_count) ── */
static const kat_vstat_t S2_VALUES[] = {
    { UINT64_C(0),
      "b1a11ff599371df1fd8c6c9a1011522b8e5819fe74d53286bf5c1cb2197e72cd5ddbc49f1337711b88e92e64f2737a881f6cdeebf8dc17968097005d3dff2202" },
    { UINT64_C(1),
      "be8b33a346b928973efd3f417e70b34d8292792e97afa4da231a854961cba9ef7b993b6edfbfb237d2820410731f238be231931bbdcb0325286d2bcdf8b8c4f0" },
    { UINT64_C(9223372036854775807),
      "098f0b348b43d74790fed1bcf343e945d57f5a14c30a08398eb9fe6c24109e967901ef62a148e0c10b50a9a8b35e7f192beed8faacd8f1428fc9265676a9c20e" },
};
/* S2 errors (test_s2): {"active_count": "9223372036854775808"} -> out-of-range
 * integer; {"active_count": null} -> active_count row absent (NULL). */
/* ── S3 storage members (KAT vectors.S3_storage_members) ── */
static const kat_sm_t S3_R0[] = {
    { 0, NULL, 0, 0, NULL }
};
static const kat_sm_t S3_R1[] = {
    { UINT64_C(1),
      "6bfc10cd2c855f94489836e7083ce40ff8e1450b2f2856d0f9d347972845e1717de6db9e297b66f2261dd1885e862d4c032a7b86386b2c1373bd6d1e19026735",
      UINT64_C(0), UINT64_C(0),
      "fd2cb383ae30bb58aef109811361defa852212ef2d687a4bd74b15efc21caa11814153b10715eb4088184c463182b2b6c7f990e1ea946833435a7481f77c5972" },
};
static const kat_sm_t S3_R2[] = {
    { UINT64_C(1),
      "6fb21c3f5847f123026559a40996b5e3863518e3fc0793f22778e1b009d91f0f043fcf3a3f356daef9e48289e24dc67ae4e01da61e557c1513983e3fbdf3abd4",
      UINT64_C(4294967295), UINT64_C(9223372036854775807),
      "faf5cd85f500cb56a00a37c65161501ac003c0d197980d9beb988a18b279fdb9ac88d31f42f9ffc33feaec138571110a201827a37d2a9db347127decc1042e16" },
    { UINT64_C(1),
      "942ee2d67286defdf993ca978c6b58ee482bd52c25657c14c1c99c95fd4098f005f36c52db7d32257431bba769de43a0c6bb75940243d880e68e8370a1fd3ef6",
      UINT64_C(0), UINT64_C(0),
      "53e7eedee374331af1a4d10f92df0d1c66c504a061f320ac9fa40abbd4ad896c40b76dc6cf3efe241608a2cd79921663fe0abca32506e6d5f0a0cd2aad4ed92b" },
};
static const kat_sm_t S3_R3[] = {
    { UINT64_C(1),
      "03ce2662623dd4ef06bb4aa49c7e34ea0597a6ca5d5420ab4ab0f3718a228521d9849f952157b4dee9ae76b4c84ec1eaac95af1bf6321c681a38ccf9349c2740",
      UINT64_C(0), UINT64_C(0),
      "df8cb50cfd03ff21eb6af1110cf77d0e2cd01a51c683a62224c632c536445aefd60f3037c989ffdb44310cf3b633b0f6e0eb10434f38461b5086512be4b04806" },
    { UINT64_C(1),
      "40098d6b6148831d75908130dcd33a325b9758540c348c8bd137be2f6bd921c96b7c31b5f0176e8784816f6bc84765f40dc09ea4e12c67a03e168c88a949c158",
      UINT64_C(4294967295), UINT64_C(9223372036854775807),
      "0c8c740894c43fc9ac5e681b8653d54717757e7097afb1e0c6a96b965d256f89b3f336881dc3e704718d638b3bf2915f05a755c8d7d86bc1c6b3ff8afb97b974" },
    { UINT64_C(720),
      "03ce2662623dd4ef06bb4aa49c7e34ea0597a6ca5d5420ab4ab0f3718a228521d9849f952157b4dee9ae76b4c84ec1eaac95af1bf6321c681a38ccf9349c2740",
      UINT64_C(3), UINT64_C(1440),
      "fbde9a64da7dcc86a1cacdcd89a6433a20ca80e2cd1c15ac2eb9be4e7092d73e295c4cb0e1ebcbf284f6d82a4b3c8c2d5038f2476158f3b97bb62ed8a6655800" },
};
static const kat_sm_t S3_R5[] = {
    { UINT64_C(1),
      "21a6802c35449407aa0440dc674b531c5d020178f7e361dfb74e4a0729fa62f284667d54b6cafffd704f189d7e3a73869602827ae968b293a5f6c7c6d4e56d6f",
      UINT64_C(4294967295), UINT64_C(9223372036854775807),
      "859d3fa03558881fa72233cb55697a2bc644f5b12a10927b8ebe2d1174887cd8b03e2550994df0c13ab145e4efec53c0584ff7077230cfe5a7c876147276e86c" },
    { UINT64_C(1),
      "543feb9b600d40a978fcd17650e20c36d8a7c2479e046642fd186c772265929bcb998943f38676cd25f33fba5fd1aa727ce3d2c1d681c2ee376ab266ad962640",
      UINT64_C(0), UINT64_C(0),
      "ffc883a8b007fcbee84f9595acfec696a787a13b44c079330b60307c22ce59e6c69cf25f6e2a210acc8e345a3051dc1a88aca714975f23c6a6fa4cca14efc7c7" },
    { UINT64_C(720),
      "543feb9b600d40a978fcd17650e20c36d8a7c2479e046642fd186c772265929bcb998943f38676cd25f33fba5fd1aa727ce3d2c1d681c2ee376ab266ad962640",
      UINT64_C(3), UINT64_C(1440),
      "f20235a35431ad29d98f6f6cce9d77876b3f045677a8786ca8dfe3c3d960e28aae24f2548b8c0f259ba90919959acbdaa4e54c10186b296cab3519c4598188bc" },
    { UINT64_C(1440),
      "f099bdf8a3840dfa70d5737c02063f0d03572298b8c1a40585ba3e3677b704c374bee4dea61fa540e6f68dff70b2aba2ae3a3ec17abe508b78ae2c3a5df231f6",
      UINT64_C(1), UINT64_C(0),
      "5aef5e50ef0f6b01d8757f5ee2ad50197d2d498cd16c5fbcf0a572c43667494a3f9d590e46412a7a9278fd77a49042189e2c0f1e9e15343bc70c2759ea3c6180" },
    { UINT64_C(9223372036854775807),
      "18eb67c0b9cc71eac7d1dafb17fa157f508e7c0883aba902123ceda37a938430cf895e0ab0f997e477ee3d60f0d558c9a91b42173641e5d1e33efd8ed71673ff",
      UINT64_C(0), UINT64_C(9223372036854775807),
      "4e5e811b9a314d5804c624a668ea577a9446c5eccd518815179b314105b3791fd1718931a1a8a50d0a2b40b4ec51e2cbbd74bbe0bf9cb25b2d1f7460a51abf25" },
};
static const kat_sm_set_t S3_ROOTS[] = {
    { "n=0", S3_R0, 0,
      "e5f7fac90e74fb474457f1c1e2cddec4a8ec6e25c8d25aaaf87944b65ed8983ce21f95533a912be282480da398035d00a7e9cb38170e58028d3ee13e9ff57efe" },
    { "n=1", S3_R1, 1,
      "fd2cb383ae30bb58aef109811361defa852212ef2d687a4bd74b15efc21caa11814153b10715eb4088184c463182b2b6c7f990e1ea946833435a7481f77c5972" },
    { "n=2", S3_R2, 2,
      "0a1204bc95978162e1a321f96f5d02d1ea677114ec3165ceff97fb6d92a7e5f13013e0a858c436ab1daeacc28f32c7997931f047dac5dbc00e07d90f0c6a9226" },
    { "n=3", S3_R3, 3,
      "0d8970d9141877d9da7b69c846bca9a2342ac2fa59a63ab0e03d94ccb794ec2e2633fa6726d041b3ca49bffcd46fd9d0d126812f12fe149f81740f4bf442bbc8" },
    { "n=5", S3_R5, 5,
      "80e2f2120115b1bcac761edeac0f4b6c835b7dbbe98d4de0f0c14bc81bffdec478cce5a5c622c2c5a391d7b4ab658e0d6f33191930a31af0694a478403dce3a0" },
};
static const kat_sm_t S3_E0[] = { /* epoch_start_0: out-of-range integer: epoch_start = 0, allowed 1..9223372036854775807 */
    { UINT64_C(0),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
};
static const kat_sm_t S3_E1[] = { /* epoch_start_2^63: out-of-range integer: epoch_start = 9223372036854775808, allowed 1..9223372036854775807 */
    { UINT64_C(9223372036854775808),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
};
static const kat_sm_t S3_E2[] = { /* fail_streak_2^32: out-of-range integer: fail_streak = 4294967296, allowed 0..4294967295 */
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(4294967296), UINT64_C(0),
      NULL },
};
static const kat_sm_t S3_E3[] = { /* grace_until_2^63: out-of-range integer: grace_until = 9223372036854775808, allowed 0..9223372036854775807 */
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(9223372036854775808),
      NULL },
};
static const kat_sm_t S3_E4[] = { /* unsorted_epoch_start: unsorted keys at index 1 */
    { UINT64_C(1440),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
};
static const kat_sm_t S3_E5[] = { /* unsorted_node_fp_memcmp: unsorted keys at index 1 */
    { UINT64_C(720),
      "ab4a3e8c57feea61b6f49d483fb2be890e20065cd4de4085b8a915feb39b1959412c8c96e4f5968131599373292311673f8495c703274a5c3c1d9379aa64aa46",
      UINT64_C(0), UINT64_C(0),
      NULL },
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
};
static const kat_sm_t S3_E6[] = { /* duplicate_key_fail_streak_differs: duplicate key at index 1 */
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(0), UINT64_C(0),
      NULL },
    { UINT64_C(720),
      "2524da4a7d6928d3ce092f9d005453a46930c7f61f90aa7e8ce04f3bee5534de61851ec6acda4f0a4dbc8433b1150b09d406f19e42a042da49dc275a61c0a862",
      UINT64_C(1), UINT64_C(0),
      NULL },
};
static const kat_sm_set_t S3_ERRS[] = {
    { "epoch_start_0", S3_E0, 1, NULL },
    { "epoch_start_2^63", S3_E1, 1, NULL },
    { "fail_streak_2^32", S3_E2, 1, NULL },
    { "grace_until_2^63", S3_E3, 1, NULL },
    { "unsorted_epoch_start", S3_E4, 2, NULL },
    { "unsorted_node_fp_memcmp", S3_E5, 2, NULL },
    { "duplicate_key_fail_streak_differs", S3_E6, 2, NULL },
};
/* ── S4 SYSTEM v6 (KAT vectors.S4_system_v6) — legs: the nine v5 legs in
 *    v5 order (validator, delegation, chain_config, validator_set,
 *    domain_registry, manifest, attendance, treasury, storage), then
 *    bcopy_root, vstat, stmem_root. S4 only_8_v5_legs (KAT errors[0]) is
 *    not expressible: twelve named parameters (see the file header). ── */
static const kat_sys6_t S4_COMPS[] = {
    { "fixed_all_00", {
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      },
      "f67f4a3ac350254a0ec5ec0fea738ebcf360855cbad6390d338f1f096880a7dcd7761db082d2cd65f5fb85ce84e2ccea46145c6f609553a151b9e42322c0a507" },
    { "fixed_all_ff", {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
      "f4e47ee355ee3032b6736601bfa639c362c0e4dd20adb38166e43e2497fd683d4333fa31d9e02034af3a386c541fe6c5838b3a3d9f9324e659f4145d05d9f0b5" },
    { "fixed_input_i_is_byte_i", {
        "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
        "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
        "03030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
        "04040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
        "05050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505",
        "06060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606",
        "07070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707",
        "08080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808",
        "09090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909",
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      },
      "2a9abd7ee23ca7c9c12c84b53deb7d3f8fda93bd64097b979968511f6f9ca83387d66165ed28c4c8e387a736476b87299bfda93bdcb3a63c81e6484909e21a21" },
    { "random", {
        "34d6dc85a00dd01e05aacba50b1339610b495c21827875d9302bf943a38a1eba6042e6c14065181e8e62899abc77bd8a96600a27d037ce8121cdc28a875c14c2",
        "007327d5c46f8d4578474e955fe3e943e828be7a0643a03e0fea7d126279ecb890ddfc7f6be907c36ff6ac0f7c572640fb272b9ea894b26d8343d6ceb56d991a",
        "3ada29b0f26744169bcf7751a108aabd71e4be066bdf965885b4b80d9e5ca86fb41e17292b70d4eeea4fd7d183a80cf70a684249d2c6b9109cde86fbd252176f",
        "7f222e32711e8c3b64bc58e695bf8a96b292a9a4c252e0c2b080e5ac9515004f01703b7be336cf3adb40ea7b46e32b4b03e806829364b67b09ce9d3b0303d9da",
        "911ed6d086543138c3731fdcebb4d4cab14f128eb31b88449be122797e88e54719a45448e4b42ea863eff4c81db52e7bc2c3f4142b02c5b9462c9511a668feef",
        "ec31f62abbc5d6dff828cdb6b033ec80078d4029d3f1f1b3a3155252da7df1e6115de8884766cac3ab64b2582856f766b88590b0927963549311c9732b60bc91",
        "9a8650a8943c0e09f5771935f03d6457687afbcb1d4f43fe8791591e52f0cc4cb1b4ab4e89d329dbd2aa6fb91d6e2e48058fcb0fbf576dbce58b4cbd27eabf02",
        "3bf38f0343b4b3b9c4a3bdedc944523c52d0f226fdd2314a15be033b04ea28e22b87a10a3a05dc09d524065ff7767972d9d019b82ce9738c2c23bbb784c448c5",
        "7efae4b057522d07ddcf42ccb7b292e70a230e03a82bf204be0c0a68daf78e86d821630703292f3c204ab717de037bbaf632cff1c239aaf7e8df9b3a4b4043b7",
        "86f5ba22f9b128ce155a8a74114ab5bcbb4da11e3dfbabdffc58a16083fb54022701c3dc99ce6b1eccfd990608a302f5fd5fd777d5a015c127f8599a515c6541",
        "dc6a3739e6af5d3331d75925def89e16a2c4ab90db0bedb61a9def8019e6b51388828b622887a10bb000ef4c053f7c3085f6adc79acd6f780f068ca80b4a55e2",
        "eac2a9bd4042c4b3c6263bb03dcb1fc6b726b1fb5985e1a942ebc704ff728806afbb3e6b00011784be4eabfc36fafe48688ea27298f2827d847d580c5559315f",
      },
      "8c4370ee1c89d718d3fbfc86744600bfa9363c35087506b63e8a836086025f52d01fe9569d0f52cb9df9ec648f70393433e1bea0268cc2e4147fa300006f8a9f" },
    { "random_legs_new_legs_empty_vstat0", {
        "1f96668101fb08d85e7a21629bec8ccaa4589448c54dde00a24b7f5fa303cc3bc58754b106576e464c86cc3e4ec8dea2f484c003edc8bab56c142a3c55aa1cd4",
        "760c9b2325268804cb85724367464aa516b1b0f68359e8263dd33c5ea1e011ebff2e55b220156c61d7d83ab6afda2911191ac575e7658161cadd31704611fd5d",
        "ffa232d4d1a0b21196ba58b19757f5fa78728ff5e462d9b2f90aadbdb8ec6ca54f7fb555e2d6d0c1050b9834aee40e85b4c96d289da23722f017656a523527c4",
        "ddfcadad3443e615bf834a10abe1e8591370beb9abf96f7a0cdca189a32d654e4975ec4f39e54807a9d638e6ecab7f9a15cf49caa4a86f0bc1b47f3a877bbdda",
        "3539d03f66192fdb928f2473cb9e9590810e902462ade3b2695eb72e5e251e9d69d6c4b9084941953630fc07542eb1b468bdb475c0fb020344fe2edd8bd1832e",
        "11fa84ebf1431b76d836c0705a7dea7295ab0d67887c4ad93d35e585888e958f6ec58d324ae326266239021cb763430fc5a3125ce8835d1f46eff2caa0bd8112",
        "72d6decb26a90c23811ec0f41c999636eb05ccc7fd90b63868ade63e977d7ca10d59c4626f5708d313d34c187206970eb63c206a91e6679e0d9a3825d28c0e5b",
        "f77c489f866779ffd296299fb6f1b391cc85916208d9611f483307b628cf223996d07ec3250ea65e1668d231f2237d3c7addf03308d1ed7d50f75cd7c59cc84e",
        "bd3172fd5d63b3cb0740e424e694c613fc211bcb1c0c5d27918662cd236d1731916233833004eb388f4bc9884d040d9177d86edb502ac54f91dfb8ed7694f34e",
        "8c89eea63e93017d8c548c2a727a2c1764f1b287e6af1e065b9eeeb3dcf2a152b8e47d0eed8f807f23b2dfd60710c0c2d53371a456544461b30179af490bf4e5",
        "b1a11ff599371df1fd8c6c9a1011522b8e5819fe74d53286bf5c1cb2197e72cd5ddbc49f1337711b88e92e64f2737a881f6cdeebf8dc17968097005d3dff2202",
        "e5f7fac90e74fb474457f1c1e2cddec4a8ec6e25c8d25aaaf87944b65ed8983ce21f95533a912be282480da398035d00a7e9cb38170e58028d3ee13e9ff57efe",
      },
      "69feb116bf92d39679a30517c253fb074bdfed822045c80e32de3f9222e5cdba170dd28569784a0801a4d26da6a40f4097d20ba9f58f56585c8e678cb1a81245" },
    { "random_legs_new_legs_from_S1_S2_S3_n5", {
        "ddb7556189459ba49a9cff7133a060236892e1312b0509b6ef5e625514ef50b65030fd5f2e67dd76f28e020c45488d882bad87fe483aeb18365ecec9bf67b659",
        "06e4cab8b59dd168ca90eb08d3178c4a0ccf6fb71bf682c1394461552f35f06cc326030518a95414bd487d59c3b38946ca7fdb3023a16321ab76fd5b736b8fe4",
        "7c272685c37b14ffcbc66d622f833a416821330ade9182ef9acdf3dc77b8c31a284070b8702597b577ddf7224024d4af1ed7ebbd9ac3ee30b8e7d12f4cee5c73",
        "c81275a2e88a09693c9ce47b1370961629b90f1bee742e4b39315b1e9a8191996bfc204e1f759605be198da97965f0de68e50edff0f96a2a1daf6bae90bc9cb1",
        "34a017475fd715355e55f53a9a16e15f9801950e9d6a37237c371f8f1783537e389b31b55512fde5b6725133151b9ff03d7ca12bed304b5ce60c682ce3494340",
        "98db410757c29190d21658f201766506b5cc458463a3a379b11b3989963b07afa56527962ed6077a3dff71f08578d1dc4fad166ec0d44a294dec0dea9ce2d6ca",
        "b9c7f4063ab0e0b9597f4056d3112e72f45e4a6d3aae7a90da2e32a135ab93da8c2b1afb7d2326ac9c4d5f96aca58a9d396976971aa44a6c198c8e9801fe700c",
        "c58a69cde604dac0f3867cf441714b16ed9c19ed00893647490e6a3def26999330df6d835b868f4430e263a02783e1df91d8a433a0c44ae71b645ea552303f5a",
        "6de61a64012b08aa6a13a7ce91d4c528d59ce7012c45b09e08787e053c9254633547f4c47a93d00ba358112d26094ca1250e526dde1308be036a4d36e12602cc",
        "50b9e7970ba3ef5572c7537b69c05df6c52d7b161e529ecdfcbc95aecbe92fab0a158ab9940e4510eb504b04547c1ecc90c8ba16b0a78070c2f11b28b4484c17",
        "2b607128a4dcf5cde3ada8998ede9e138b0484b82f251b958f2eb0b7fa5536c710310ad0d777508306af6e3d419c97f8e4d3a569998a6a75d502073e06d8b715",
        "80e2f2120115b1bcac761edeac0f4b6c835b7dbbe98d4de0f0c14bc81bffdec478cce5a5c622c2c5a391d7b4ab658e0d6f33191930a31af0694a478403dce3a0",
      },
      "c7c902c5e5303093194b60dbb29f53e11508e481e882e213a26cb58991bf1109040bc122dbf015a90fc61e5ee272509313fa3228bce9682e9a5573006d0fbce0" },
};
/* ── S5 segment leaf v2 (KAT vectors.S5_segments_v2) ── */
static const kat_seg_t S5_R0[] = {
    { 0, NULL, 0, NULL }
};
static const kat_seg_t S5_R1[] = {
    { UINT64_C(1),
      "b741dc975b28fcf5ac77073fd7efc9d09d8f6263b060b20f8644a3da74f989a2c6682446e7e267f2c971df3232fc044bc8f34aea5692af4f4456afa54a1510fd",
      UINT64_C(1),
      "77fcff0df1ed806dff304b909e9bf8822e0cec5cd580e32a0f673ccd2fc79265368699aa4c4521c29e184501129c58cb514d958e3cd4c1ebd5978d992cab7bac" },
};
static const kat_seg_t S5_R2[] = {
    { UINT64_C(1),
      "5b0dc8d7b769cdb6f3b6da84115d9630fff634c2e752d9d262d20e0f7c9759ffc25422a4f3159b8961aaf65e42b3f9eaea568b958d09f53b80f85bfb5f507577",
      UINT64_C(1),
      "2fe4c2fc2d6890201fab1b55362f52ed12f86353ad349196f67d6c4bef318fd598f21ee176a3af362b6b4f16aa988032fed41ac8d3a11152f3819aff9c5b1b20" },
    { UINT64_C(2),
      "99dbb499b776b35ea77108cf22e7f83f2d8ec0f16c7ab6ffa59ae65d2126d821d3618e0e51249ee6e142937b7d307bd9a872286e0e2a5a9be48d810e310b9860",
      UINT64_C(17280),
      "7ac787971fb660fc16b572f5400a7be8b64b3555929237c3740874460eb0738383d9b62f82700e93b076ef31f1193783eeac884bdb1d0b783c39ef5b692e54a8" },
};
static const kat_seg_t S5_R3[] = {
    { UINT64_C(1),
      "b5d771700bfeb2e514c9b9189c94633db320dc8a3b6b4ad732ac47799833a5d0695c671e81aa68cd54b52355197cf8b7945b9436d3bd7e66f3d5df53717b694f",
      UINT64_C(1),
      "66816ec4a7e11049821e9008cb16bc37916f78d9030661129f35c9763d36b25adb2ce24334377f243f5d944dac757defd59b1063a4658607ee28ef13b812abbb" },
    { UINT64_C(2),
      "29c883bab3cd3e1e97c70c7e57f54b17c909d1470868618023e9d8d40ed7017ebc64e179fcca349d528ccecbbbe9f8b5822dfcbec23d26a3cd7c98dd0039f3fb",
      UINT64_C(17280),
      "412979084da2049c1dd6bd6a49e01243612212e4d6460fea437a2fa8d9ed540d44b60631ab554f3e129a94a89be15f8beb5bbb4edd386a70e6ccab40f9203762" },
    { UINT64_C(3),
      "672793b5aca5bb6fa03095ab7b7142c68dd176e6c1e93d79a361a865ead47697a53fa9f45809d2d9e8b2d401b3ee29934acfa5a83b7c55fc4a06ffcfd3dc4454",
      UINT64_C(9223372036854775807),
      "1bca366ff14c139c25f0cba36f211978882b4e7da95a80b5d21ffacddc352f6b70be0a920fec8d5af1fa02ea0d86ec4662fdd7f55ff1c52673d781b22b693741" },
};
static const kat_seg_t S5_R5[] = {
    { UINT64_C(1),
      "22a812689d362537aeee24d4f7bfc6fcca7a68eda7d8b1229869361c1222060e5220450ae570be1faf14498a003cef9270a02646db2346d912e0810c7e2d4377",
      UINT64_C(1),
      "a0b94df1b857f65aa68f53eb851493d61ef7296438451206d9bdd332b7ff98137985c4636abfd5b49a9fb556f457c258ed7cce96f695fadfb28d4a6bb79cbd3f" },
    { UINT64_C(2),
      "ea8cd6f57c7c100228b4190b6ba0b6c0fb05d8f71359188434914fbcf6129f66b3459fcf28d273dd4e3b59bee72edb504fb7b71fa09f1b9a4e78b29211948234",
      UINT64_C(17280),
      "31f687c0c2ef5e48282f48dffd745b85dc2896caf3eb134076f1b0ccd810d0ba7b4c17d5f0c12cdbfbcea50e0dd2bf446aa6435c2b5495b0454e22c5c63ba00a" },
    { UINT64_C(3),
      "f08786aac04c040c9dc6dff6594daa48e3dde28c6e31427177151115b623018dd2b901a43d70174096e0393fa1159d83f15e0a0bbd26dc53434b800f6aa316bb",
      UINT64_C(9223372036854775807),
      "7f63c4afdec6acdf46670f8f89490c8abb2951fdf9b6bafc39aa56e8cbec5b076c1fbfe5af7810b52eef809e99714bd10e34501ce93e148efa3f1132d0c94e98" },
    { UINT64_C(1000),
      "e59788843dc70ea02451da52a759ee514b8c4b7d58de5bb71e000629123da5f0bbda6a99d873472c7d687dd420c1ebcfc6fef9f55795a8f207410ebb2ac7e42e",
      UINT64_C(5),
      "988198c3f4621a2030acb768bc1cb482b2daa7cc3e78e19d085f177636ba0fec7821c5006a281aecdffda72efa8f71b48ee6d3a1b4fe03d603b5cc7b76463b83" },
    { UINT64_C(9223372036854775807),
      "639375e91e32a0c069e67a616320b49c371d9122ca5866815f74a7e55c603689bd7a121ad4df9d25b6e602d2c55fc1671a2e91ea550af0765f2e77c378553a7a",
      UINT64_C(9223372036854775807),
      "2047113266c9cfe77416af7d774cdafbf500caec40cc7410e6122813ca0531deb57ab9410ee679745dd6a9c24e55fb9da878fd0c50d4fdc2443be7a0ab8305a3" },
};
static const kat_seg_set_t S5_ROOTS[] = {
    { "n=0", S5_R0, 0,
      "d50e4a36ac95b3e6101193f47fc7b362b5e1706ef259aba91f4d08f8e7b4846341df6ff0c0f2452554cba06a75dc1c943696ec8fe49600717bb1a11fb03801fe" },
    { "n=1", S5_R1, 1,
      "77fcff0df1ed806dff304b909e9bf8822e0cec5cd580e32a0f673ccd2fc79265368699aa4c4521c29e184501129c58cb514d958e3cd4c1ebd5978d992cab7bac" },
    { "n=2", S5_R2, 2,
      "a1025cbb1da9af15f6a49f790a6e3c6fc6a2ae05aa2f0303fb6d036dc39fb912672f55ac2da08c8cd5041d6066b3c84fa830dffe79554d5f2b9386f80fd1f4b1" },
    { "n=3", S5_R3, 3,
      "02829398afddccd2b3fb59e722fed134fe7e4d5f309df9fcfbe9d836c955bb17d419c6faf2dcccdd3dcdd0985548d46092e793edc67b796be76e3f5cf38658db" },
    { "n=5", S5_R5, 5,
      "083f1fd97ffee0239eed603477efc4458b79a03d8dc62c1a3132c03c84da15bcc43d18c3582c5dfe9f7a34f3f756a3e68a130f15607379e8181d63e9fb86567a" },
};
static const kat_seg_t S5_E0[] = { /* k_0: out-of-range integer: k = 0, allowed 1..9223372036854775807 */
    { UINT64_C(0),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(1),
      NULL },
};
static const kat_seg_t S5_E1[] = { /* k_2^63: out-of-range integer: k = 9223372036854775808, allowed 1..9223372036854775807 */
    { UINT64_C(9223372036854775808),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(1),
      NULL },
};
static const kat_seg_t S5_E2[] = { /* published_height_0: out-of-range integer: published_height = 0, allowed 1..9223372036854775807 */
    { UINT64_C(1),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(0),
      NULL },
};
static const kat_seg_t S5_E3[] = { /* published_height_2^63: out-of-range integer: published_height = 9223372036854775808, allowed 1..9223372036854775807 */
    { UINT64_C(1),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(9223372036854775808),
      NULL },
};
static const kat_seg_t S5_E5[] = { /* unsorted_k: unsorted keys at index 1 */
    { UINT64_C(2),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(1),
      NULL },
    { UINT64_C(1),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(1),
      NULL },
};
static const kat_seg_t S5_E6[] = { /* duplicate_k: duplicate key at index 1 */
    { UINT64_C(1),
      "6d53d9b864da9ac26bb86e22dab8d08bf157a58c9d507554c4489c9e2e8a80daeafe3ebee54bdfc37e5dcb7f68d08723a081c23c02d2b8a3b79c5d675a40a724",
      UINT64_C(1),
      NULL },
    { UINT64_C(1),
      "79047121b5cd0c92f39797c60b7c629ecc3fb959e40655bc6f4a58a2238d244b5d432133e84413d0807c271f53948b7f058e2c22efd4c47e30f6b200909bbc15",
      UINT64_C(2),
      NULL },
};
/* S5 root_len_65 (KAT errors[4]) — not expressible: a fixed 64-byte
 * array (see the file header). */
static const kat_seg_set_t S5_ERRS[] = {
    { "k_0", S5_E0, 1, NULL },
    { "k_2^63", S5_E1, 1, NULL },
    { "published_height_0", S5_E2, 1, NULL },
    { "published_height_2^63", S5_E3, 1, NULL },
    { "unsorted_k", S5_E5, 2, NULL },
    { "duplicate_k", S5_E6, 2, NULL },
};
/* ── S6 DomainHead v2 (KAT vectors.S6_domainhead_v2) ── */
static const kat_head_t S6_HEADS[] = {
    /* fixed_all_00_domain0 */
    { 0u, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      UINT64_C(0), UINT64_C(0),
      0u, 0u,
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "58234480a3c255a26ad897b0b372ced0117fa7bda020539493b9a6d5e292e2a6a620733f326857dc0679b791d79e795e8aef31e4b010b7b81f25ae25c59b1a68" },
    /* fixed_all_ff_domain_max */
    { 4294967295u, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      UINT64_C(18446744073709551615), UINT64_C(18446744073709551615),
      4294967295u, 255u,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "c5ed7c9318a711600c1a13fe77b8124d05c0e92b5f1c3c0e5d14f4b26600774dc20e6fc6d46437f004771b48c488bdaa67454fb0a0937f6f53ffb571b17bf02d" },
    /* random_domain0 */
    { 0u, "b95a0b945c39b19edcf58956b3f1ef694c49dc30addbbd8efc3a96a7c68bf50131825e2c6a1a69a658a0b3b06737ff7135174719cbce9fc57ef800d5f906be73",
      UINT64_C(8773781945770082602), UINT64_C(681249932792139909),
      3310064646u, 221u,
      "1b567224df48ee0afdae76060f839f3312c434de810c147968a5baab8f59c236bcb339d3110ce235cd1f4b2c578aa1a346e3351a0ff7ae13b0c0fcdba8ecaa9b",
      "0d5459cf17ddb695cbac9629a6d4eaf42bd669ff926feefb6238864ace886dbc85f04de36fc7819f0c981a0bdc3bfe42db998e0a681eca883ddb6a82a37f3eef" },
    /* random_domain7 */
    { 7u, "a0badc76c55b1edb108d96195b874e3867f21c1d1dfaf19efbc8e888cfe19018b049e7f99e3fe22323ca55fd722cabca40e7b45fddcddc4aa30fbf72c7b1427e",
      UINT64_C(12122297810550717044), UINT64_C(3248638931764818548),
      4110896048u, 62u,
      "52d75f8d7acd561a6c725a4b8d34d1c1ce5f5a58740e103900a334aa32c65c23df8f8e3f82d07ad26d6e477b63cb899ecd3cadd9dd0612db172661ede2b643c0",
      "287ee37f22dad9873fd7363aad75d1a17b305b1e032a87f1228db7c0312b8af0d3b13b4becaa27bd4bd327e1639a586bbb53fc8763d24024a7ddace6077c339f" },
};
static const char *const S6_HEADS_ENC89[] = {
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "00000000b95a0b945c39b19edcf58956b3f1ef694c49dc30addbbd8efc3a96a7c68bf50131825e2c6a1a69a658a0b3b06737ff7135174719cbce9fc57ef800d5f906be7379c2bc31b65c812a0974493457559085c54b9406dd",
    "00000007a0badc76c55b1edb108d96195b874e3867f21c1d1dfaf19efbc8e888cfe19018b049e7f99e3fe22323ca55fd722cabca40e7b45fddcddc4aa30fbf72c7b1427ea83b0da1cb5efa742d157be57b58b274f5074bb03e",
};
static const kat_head_t S6_D0[] = { /* fixed_1_head */
    { 0u, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      UINT64_C(0), UINT64_C(0),
      0u, 0u,
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "58234480a3c255a26ad897b0b372ced0117fa7bda020539493b9a6d5e292e2a6a620733f326857dc0679b791d79e795e8aef31e4b010b7b81f25ae25c59b1a68" },
};
static const kat_head_t S6_D1[] = { /* fixed_3_heads */
    { 0u, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      UINT64_C(0), UINT64_C(0),
      0u, 0u,
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "58234480a3c255a26ad897b0b372ced0117fa7bda020539493b9a6d5e292e2a6a620733f326857dc0679b791d79e795e8aef31e4b010b7b81f25ae25c59b1a68" },
    { 1u, "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
      UINT64_C(17), UINT64_C(17),
      17u, 17u,
      "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
      "be5a5a2104f598e56519fd0a3937e4f1f1171cbcffc1eace426296b0846f95cfe0367dd143b166a3e77d2565d4dde215cca8bc4426a5280fb7127f3947d432c2" },
    { 4294967295u, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      UINT64_C(18446744073709551615), UINT64_C(18446744073709551615),
      4294967295u, 255u,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "c5ed7c9318a711600c1a13fe77b8124d05c0e92b5f1c3c0e5d14f4b26600774dc20e6fc6d46437f004771b48c488bdaa67454fb0a0937f6f53ffb571b17bf02d" },
};
static const kat_head_t S6_D2[] = { /* random_1_head */
    { 0u, "b6042f592102129c9f82b4a681bb57a99d23eaf04aada30dbeb26678884b053b43678c5afbc6f2567ad6ccfa5c86f01b4f80995a76a4821194c3934e28630078",
      UINT64_C(11699095296900440365), UINT64_C(7757025236832144519),
      2840675637u, 250u,
      "e965204213a50d4cd6fd8b98a72a0f26e338aee9070e1083bcdcbf7de69a6a41b4047a5e084e6ff546364f0a15d3d6c04455a63e5d7bcb4a7e45c1fd3a98adcf",
      "13a533f4128b6717cb542abaf0a7a7d738af171840b604d0fd04d1064e89d413698f0c6e3ce1d16073cbf86b4b6aaeed3c96acfb9c455792ec7d9d71ad828dad" },
};
static const kat_head_t S6_D3[] = { /* random_3_heads */
    { 0u, "60371dc7d313b1c6350398d0d3deca24002e6c1413907564703539b599262d159b1cf60c79fe39b3768ce721fa44a1cd9c05caf132a8ea3498e4cc3659e7a71b",
      UINT64_C(17439542152831775969), UINT64_C(8527174579943553012),
      224602712u, 122u,
      "67651ae31353c97a7c45fa731b02645b744a142b743299f33496db6d0d8e84f654dcd85e4efe953d8df838541afcfa71a6f9cd15c5b37c5cc9f2ff4d2ce2d78e",
      "47262ad28d55ec26401f91d9540393fb7f504acfd54abd22705e71008d62cf28d56a510949ed2ac4c25beb102b3639a886aa730ec5afc250021a6530c806910b" },
    { 1u, "ed75b91191c938104fe21b2c1f5fc72fccbd09c6a45d64fc99823076a6100b7133b2402d9b7a3a3fb2355fccd4cc93cc056d451846d82fcfb2b6ac6a56ef32b4",
      UINT64_C(18019056766997658916), UINT64_C(9227086420682885060),
      1921314635u, 165u,
      "bc1892ce1dbda97cebe5bcba7c4a29a9ba3f91c34e005e6f3dbc29015f5f221f40b19e796d78ce460f088a85ee86ca0f8e3e2aa09c3445639495869539837c62",
      "813d59334032fa45a7073234a0736e332fbb6ea38e1b0fa6fb739d4ec4af07bcbb4fa339d608ccaf340ef56b9b5d2d67a3c1ad5f185f8c0ad670f1a5d56dca17" },
    { 42u, "2c2555e8f0ab70b37b5ab045db7a299afad0c5996435f43b6827306b2b1f62981e2dd3e8997fd574bc9c118710c8300f22f3da4d2cd80269b5201cb4479e360d",
      UINT64_C(15956871329317201782), UINT64_C(17378217953489095470),
      934832915u, 14u,
      "2005e06a01e82fdc4c7784af789c25522dc928e1ff7d107e6ef2eafc4f38ce08ef86485606946c13169a568a06732d14e08c6295d8c993656cf050fc242d6cf5",
      "8e5cf37a2a53fcdb5e18bdb6505383568b8eed211a26e46c03a7350709057af1c6090d8b882dcb371cb4426a0ed2d0e450004b395c5876a670cadae7ff3a3e4d" },
};
static const kat_head_t S6_D4[] = { /* random_5_heads */
    { 0u, "3c275bde77e3f1e37a804f7717d16b9f025bdcac776e71eb74792356cc64b8e9cf02e7846ff010fbe9879e64995e074b1d8482c78049f57d4e73e13814eac227",
      UINT64_C(1885928505062316896), UINT64_C(8924724999567776035),
      267409698u, 221u,
      "520d6d7a601f7da972a7a111d1e74d98808a36fbc681c1943f9acfb5773da716aea41b98cb35cba4515901a4393955fce6e74e3f11dbadbd0d96e90e948cc650",
      "6d259defff8ebd5c938ea22804594d1a6f18f25632fd831c5031fa9caed3f44bb95cc8c4f5adab5a1cf1a1e7655a06a3c58e1272ef410f5992bb7bab1eb2aade" },
    { 1u, "1fb3a2a2df13bcdf184e71c7c789c2280bd5917fa26d7950522d80dc7776adca110eda14aa3ddf99f6a21d6ead00430a1c22f1c79bbffde562796a0ad19f6cfa",
      UINT64_C(12611533302191769788), UINT64_C(11672104241523407479),
      2126293094u, 51u,
      "cdff75c0db970a47ff697803b96bd23ee1310eec86b9e5257845824bece1912bbebf33f68ee566e88d2f5b9722cb21cbe10441e11e62ec3daf566addac37346f",
      "4ec2d55150a3911b55bd4274087926d12e3bc701f8603da867addfb5f267920ad811c3e5a854855145061462e0c481ee1fa44106a57fa7af78cd7856d2c2287d" },
    { 2u, "7de9fb1fba65eb79f804659ba3fa06ec8e39f5579ae859ef1c527c49923f926d98e59a869e5aa2e344ad12222ac5ba241e0168015bcc8341bd8b20ea35213926",
      UINT64_C(355225606911671282), UINT64_C(10090090260908428945),
      3900879391u, 151u,
      "8c6d7746922ebb06232eded0b1a03b19510ba3f0f57d6c68479b842c7b4208cc8dd1278c216b1b0ad42f17c3638c1cad852ebca3de8e4565451b1a99a0f60f76",
      "7af67b88d98e49740f55f7425a9167fa8a18b7e75b7ea0b87b39ee2f31ffcc23eedc4a127a45e1e0c1002a291233ef6f340e01bda9706c23b16b88b83f3d3aa4" },
    { 9u, "5abd92b2a4d69fbbbf518a87c4b807249ac34753b58c0120238620ae949b6e04f0fd23cc09433c52a38ce4ddf3f27249c374cdad22bf9e06e877049f41933d6d",
      UINT64_C(11243659687041729515), UINT64_C(12622405995713290699),
      3073493950u, 153u,
      "cb3a0b4ebbe6957e2517f3416cd9c56e4c749aa8c1029d32bb07a13d061ebe674006d3c18913c238e63459fcd1eb35c6484857ae215af6f15881950a210072e4",
      "d66fbb6b6885a298f80487c03da1371e35c15f4a03c685ea937e7f02313aed5c690a952cf9fc2940b576e9ced9d9f625c07f22987dbeb79a467bb6cf26a8e9fe" },
    { 1000u, "e8bb2ba8d62c955a95042fd3d4982633f936ea712842fc1e0835529ecf26615a876d856affc83c71002e60680e98197b9f7e4fda707a3b3f9b3a59a4027638eb",
      UINT64_C(13076542442814520724), UINT64_C(7527804989010294360),
      1784965769u, 51u,
      "4a931615db5f767a2ae8dd75dbaffa94c3fee1aeefa5908dfcf9d763e31aac642b28300417c7ea5ec88412710b6b14403a39832cd128f5446839588c4dd64f1f",
      "c0ce7c9db08977e8a466a1c0c2af9831602f1665a371f716bfa95144558d15342627e96e611d9ebd15808a0fc4f66cee5cc3f69a84182066ac4e5e5db29d4727" },
};
static const kat_head_set_t S6_ROOTS[] = {
    { "fixed_1_head", S6_D0, 1,
      "58234480a3c255a26ad897b0b372ced0117fa7bda020539493b9a6d5e292e2a6a620733f326857dc0679b791d79e795e8aef31e4b010b7b81f25ae25c59b1a68" },
    { "fixed_3_heads", S6_D1, 3,
      "e6b5890913d0ea7457ff95392d45dbeb74f3de1283cc805cb13322797401584f4ba2b8f358b4c73155c3e59ba98a509a893e44532f6d86d1630216e3d829197f" },
    { "random_1_head", S6_D2, 1,
      "13a533f4128b6717cb542abaf0a7a7d738af171840b604d0fd04d1064e89d413698f0c6e3ce1d16073cbf86b4b6aaeed3c96acfb9c455792ec7d9d71ad828dad" },
    { "random_3_heads", S6_D3, 3,
      "ecc42b0899017267f7b90f398a1549d558de75a757593a08ae8ab024f3e82d3ea9ddb68f9e981f04c6a7b44de73b886811b9b6631f238b26f9de62ef5ccc8a89" },
    { "random_5_heads", S6_D4, 5,
      "15ec8bcea66d3e7b9a2c152fd63b09fdc67826989c33b51d4d2fd22f9f28e44b0c61705611bcb2a83c2c7304ab82090a335d60b320630c44ca7df148590c29d6" },
};
/* S6 error empty_list (KAT errors[0]): n == 0 over a non-NULL buffer. */
static const kat_head_t S6_E1[] = { /* first_head_not_domain0: first head not domain 0 */
    { 1u, "142588088bb87b8975ccb07564279dbe67014db0273b7d6f96dea7ac34321eaeed7ef13e278abf2aad540cc161896ab3ddb46ae267f4c03d4ee056ca8f76eede",
      UINT64_C(8477573227403331846), UINT64_C(18226627717394160715),
      2966365218u, 205u,
      "a9170c72fc39b676a96198e578d930cf424387dce7d6ea624d06bb1d32183cd0e085371a21478c0bdd9a7e356810037f5bb8bafc811e3fcb2437da85e0434807",
      NULL },
    { 2u, "baa5a9db233b8b2f30f46c768a2e58ff052e79afa6a88bcc0a528152aaffe8e7409679a227735c297af289a614d4f09c86af921c6b3ad38e15f97d671d29c567",
      UINT64_C(4444250372502182098), UINT64_C(10514562482312535897),
      653564727u, 151u,
      "52db75b07b8b1ea08da0c33cb949fd6b8a945c8af8a15ea2e1df0dc4b75a692ad0e8e57a6e12b9d32e0de07a3a2bb7a846e418907c5265c6e33d8c87f7f1824a",
      NULL },
};
static const kat_head_t S6_E2[] = { /* unsorted_domain_ids: unsorted keys at index 2 */
    { 0u, "6e40f8d864901338369ebfbddf62d03ca8246e564462c3d96ae16682c68dd7c161a55c28947d23d729fa96a7aefbe06668ca9b87cf93a44f81b04f58accf3f77",
      UINT64_C(224915506339610007), UINT64_C(11086098317244895857),
      791989979u, 227u,
      "ec54393df851766a7dc1bb49c66b2f112b0cd5cc2d1f190d6a20c801bdee21af333796db4815937ba57b3bd8005a47fe2b83c8d605fd12e1dfa412ae6441ec5f",
      NULL },
    { 5u, "85d1fd46e42c32e4838cce11d79e8a2ebddcebcbc311b51d791eca0f4ac2e59be11593b4fab4eb921642c8df85faacfaa7f81cb504a198e76d2d3fd2a91e8959",
      UINT64_C(15915696886115496699), UINT64_C(13044206634878032),
      1564401039u, 106u,
      "e418064c3bdd772ab029fbe00175f321df053a396fb7a4710255e662da12b6759e4d2c3f72f9e9d7592156c3185214e08e576363b2c7a0204507368b45c9e860",
      NULL },
    { 3u, "ed809e5495beac309136d2ac3c679ea616043e5dd12c02fc8fcea2d070557a38b718963a308770c7713f054e282e55d94f5bade166da0cd43f08436f5701d72c",
      UINT64_C(5926874384336821990), UINT64_C(3436401769771304209),
      1829115565u, 43u,
      "75d36b508315bee92c119b94cdbadb15eb57b9b8fc57c78a7b6cffab4815e184040b46d90d292cc0aabd88bc4beca852f90e66e4d750604ed21214413323b412",
      NULL },
};
static const kat_head_t S6_E3[] = { /* duplicate_domain_id: duplicate key at index 2 */
    { 0u, "6e40f8d864901338369ebfbddf62d03ca8246e564462c3d96ae16682c68dd7c161a55c28947d23d729fa96a7aefbe06668ca9b87cf93a44f81b04f58accf3f77",
      UINT64_C(224915506339610007), UINT64_C(11086098317244895857),
      791989979u, 227u,
      "ec54393df851766a7dc1bb49c66b2f112b0cd5cc2d1f190d6a20c801bdee21af333796db4815937ba57b3bd8005a47fe2b83c8d605fd12e1dfa412ae6441ec5f",
      NULL },
    { 4u, "6c78bb5af887ab58598ec89571ffd7a1690b0a51d5bc6bc074ead7f3f92d3aab042ecce53f222e1f057fa06edea1be43d427aadd0e5bf157c83d89db7e3296cc",
      UINT64_C(3345944444229369933), UINT64_C(2460920164313798984),
      3894975218u, 220u,
      "033218b7d6f4df97ab8daa78d288cdaee7de37a70bd605079e39c10c59a6289f2133616b77cc94acef7e4ef9758a28e30e26187f6def82c3baf2af3e2a3e3caf",
      NULL },
    { 4u, "227fa1da7e0995cd51b22c0efc0bc8b398a7c7ff2fd43d1e4f042603e910a4cf5b0975874eca272e564cc4ab4e9e79d4bc95fd69be62d86af02eb0f89421f833",
      UINT64_C(5460106120417126833), UINT64_C(4580021668605939797),
      5689433u, 24u,
      "72cedca428a836578e70d3ca3884f2af0b65e417cf1643ee2a331b6c8576a989674a45f2df2178f9ecb6f8ecf18ef3f94317edc8cd1b0119cab587fb52536f34",
      NULL },
};
/* S6 domain_id_2^32, status_256 (KAT errors[4], [5]) — not expressible:
 * dna_v2_domain_head_t's uint32_t / uint8_t (see the file header). */
static const kat_head_set_t S6_ERRS[] = {
    { "empty_list", S6_HEADS, 0, NULL },
    { "first_head_not_domain0", S6_E1, 2, NULL },
    { "unsorted_domain_ids", S6_E2, 3, NULL },
    { "duplicate_domain_id", S6_E3, 3, NULL },
};
/* ── S7 replay (KAT vectors.S7_replay) ── */
static const kat_rp_t S7_R0[] = {
    { NULL, NULL, 0, NULL }
};
static const kat_rp_t S7_R1[] = {
    { "7a27f84fbd966f6860056652831b096baaf785a9ef0f9a345ad10fa0f4c0c6b825224d36b6d80f203b94fcfeeed6a81a69fc7fad9657c2d5cd763f460ce7deeb",
      "02e30f0b84a3c1c48c701c8cb96ffe5b50fef3ffe7fb29b8c03575c0bdef2dc806ae8b322ebbb21b72c7e97c91b1b3916afc82e59d422a6c835f1d81f8388f6f",
      UINT64_C(1),
      "1ea689e9f8e05b73ac80e30a2d0d2e7abadf61c1a49de4290c8f9404bb427bb501b6c98a569e8120b8cd8aecc07d72803e690f5efd0890867f97bb861b30a031" },
};
static const kat_rp_t S7_R2[] = {
    { "0bfd89a9c429daa01a23ece75d197dd36726abfcbf2d4787ab07494866096172152a71010135989491c4c786ac865e28556c57ef21eb7c03698b51c80b9b8375",
      "b1db5f3c00dad6badf0fc6eb1d69f27e2c4c0004558283173971d171712598f0edb132c1681627b9b20f9dcf1c9261a2b4971e928ff40ffacfa0c85bd30fd330",
      UINT64_C(1),
      "9ca39d2e096135c930c10b152a84b04a11695f0fa8f43b57e1f9b3ff3cd6b2e83bc611350c8d8c16163d5705e8845bb1f0c5d34d03c680ad506751dfa3e450a9" },
    { "9e15a51736b7129493ac0b54452727c2f0b454b367c10bc86b1463ff4ae3801c15b274ee95a7b9b8147f518a80fd62a9c0cdc6c1e601638b0a694370b50fd7df",
      "1028aad47f4a676ff76f89df5f340c8d27c76570f78ed10f40575220ce13324714ca9e08c869beecc2d37073ca75aa37e5ae4d767486327315e3652bf35353b0",
      UINT64_C(18446744073709551615),
      "c9a7aed6b63741ec6acf95ad82005d27746bfd70b04cacc4e318cf1c53c8c56061cb8e4d1464c556faab9588d6207ed7c5357681200c0179f297ae408bc80889" },
};
static const kat_rp_t S7_R3[] = {
    { "255115cb7b54d387e5adaaa6f2ee282430621c382873d05db4286db574381416b1832eb7772c4174f251a97f9137db599494c7c853ba20f30ccbb4053381dcce",
      "a5360856280925c91b1a869fcc1cbb7275289e4283271681e92df46c7d15852ea79c888c2d7828c47b9ca017e48b1474f101942c0e6766505573a5b273f6584a",
      UINT64_C(1),
      "d0074d7b44d137b3ec12d2753d431b408ff9c6c4cf3cc4a0221de7342ff96254a6a4a1b244333d8a26479c86690b37473dedb740c38e0362a6deecf434f53aa1" },
    { "356845c0d755fae1757af67a4adcb9f4d00ca5a9fd0e0758f234f0ea49ab11f9aca2f8ec3b15c67ee43668fb1ecfed17a46bf241419d0801eac9b59307405ba6",
      "2a52f26fb9513778a500e8382ebe040961e8a48be1a8e94d26c96dbaaaac23268eb5e9896f61cd46682831b93e3193703013a2894bb0dd1b0a3158846e039617",
      UINT64_C(720),
      "064175ac094cc70ce3766f79f6eaf58bfc4ece34605ff9389790e7fdd78b5ad31f253e257114b4d9e5902e0a7ea36ba869abea674bf3fa11a103ea9f70d2b3de" },
    { "589862a194ccc32157abc948d6aa0e2554edda8d839a7185c108e8fdf9116fb3af61349df8198c09c503cfd188eea3d21bee4a33c430af9d05ff01f3817cbad1",
      "f5be8eefd1d035608add15ce1f8e68220e61b9e95a7753489105dbc42bc82611059c5b83026980b6e6c58fdfa54cc575cadb8f63d9763243d1d357bf2c82a5a0",
      UINT64_C(18446744073709551615),
      "9da661dd745b7147fea10cec4a88c07df75b10b0d17e5bc95092fcb4c190fd108bea357f63c5581676b92a241297c21eb25bf4bc3a47100d478e3e87f0a0570a" },
};
static const kat_rp_t S7_R5[] = {
    { "802cdefdc1b9e522d075d8affa9d03d7f25f2f101b270a93339251a339af861faeb70c82e60908a3bb4a9af95b616e3584a7b4d86f8d94e4637d6f414ff666f6",
      "5d18019578523604ecd4c9ae92a4d24d38ea2e727d5639ff956ae16fd929d208b407033bb6d743ce2c3e34de14379c3f353103f2df89da2fede921087b8e0c0c",
      UINT64_C(1),
      "b1c650d3c697ec6cbd72d7bbfb88b9e584f5364e67d3e66369c82dd2ea215752728733fed83768b17656aa43479221a7840f2b96e4a0c35ff2898bc343a817a6" },
    { "b4ae3b77453ae762154db4df8253d56d2b719fa520e355ccacd3b927c340243a424dd8cf6bc330d409ed7818313ceae72f1e8678a801d26ed1a60f9dc855b89d",
      "1e493fc7ae7440d1947101afb54262f3cc0634bb2c835a65e2ae2909a2470e5bb99223b8ff4ce9aa5eb13edeeff4d134433ab2dd2ecbc893815e5c7658c6b802",
      UINT64_C(9223372036854775808),
      "fb770539addae1ea48cd595d360743477249711c4947eb41f4dbb4d8b337d545093a896a8f51238ae1e09a2197a88888be77f509ebe583035948dd5c30f48dc9" },
    { "b8190205f1099c053e4cd98f67dd8828c8d6b07da544fcb989ef730a5651fa6a014fd33c31c1a55ba1d7056daf37c7be11a533860522f6c81899f234a4877e05",
      "380e80659663550bc4e8d520306e203a0800b68719a070db1f15c3c98d4a7d071a6162f79288bca6024e6884882cc0665fd5fc90dab89dbcc990800c3c2d9b48",
      UINT64_C(100),
      "527850b8d7ac491aeede5bed2314c0b139a076cb609c87b9d627b10102e8366b0e09f165305bcfdffa87ceeb9791dc181d06af63824002a56a0cd51e679b3ea7" },
    { "c680d747b27b37e1b7cc2430e7a081b5d9f5262479c80595e8f1aaefdbb6f1a2f1ae211eb5aea4630bbc7b614bf86f079edd2c4c0ce63c6d1beb7088a3420b97",
      "ef1e0dca49c0e1c66e0eb18788e151a90d34bfda92933b61bff49df5d862896629ddb4b0794d3dc6df06624b71b26cb19857e12dee43a514f22786f71b3f1e00",
      UINT64_C(720),
      "f24d4f0c7deea1c43a11d5c3238903d026398d88fb256555584c5e0baf941de90cd358acb2ead8c7142e8a633402140b0a2c5eca27b42870b95ac416744feb38" },
    { "e138354d0fe16b07ceaf8fc6ad8666aaf1388820e73dff8ef75b37c5aef958ad821a58ec86bb63bc722795fef2c3519bd002b1a3b7a652544304f331dc495e00",
      "33e496f8e69f4a6c0b1318415ff6661fc8231aa383a535d34d3ae99b908644e73fbd8e0a7d097a18fac23f5c260bdf8cf1059322e38893b829cbd85a6d0d277b",
      UINT64_C(18446744073709551615),
      "dc7b635006c8d4a01d72de472788c0b970494b7140749b578cabc0ec46ed60e1429f514727c1ea15cc13c79005af30ba146c7eaf0ff2be79bf4d31bdccb69891" },
};
static const kat_rp_set_t S7_ROOTS[] = {
    { "n=0", S7_R0, 0,
      "8156613c0353dfbba44c463035f5a88204c04fbe865283ace9599a144828c379dc97a7fe684124f6be72413f8d2b0ceb6552e33a23a800b01b7213f671543ac0" },
    { "n=1", S7_R1, 1,
      "1ea689e9f8e05b73ac80e30a2d0d2e7abadf61c1a49de4290c8f9404bb427bb501b6c98a569e8120b8cd8aecc07d72803e690f5efd0890867f97bb861b30a031" },
    { "n=2", S7_R2, 2,
      "7ce141042964baea1d41ac6669736cac389aaac62c5e1c6ab86c2517daf33e8ba549739b949b702831a9edd6e050f033ee97048b86cad196b0aba9b078e8a148" },
    { "n=3", S7_R3, 3,
      "b118b92dd91a57c8fbfefa286337f35d45241abd2c114f488de274ade8598128740173139e03f471c50689670346c1778aa8453987baa6fdca3ed424f17272c1" },
    { "n=5", S7_R5, 5,
      "f2a3732a28dc3070c6442dafbadd1d932aa8be12cf11612aaf81fb164070cff343ee5676adc75fb489e303451a73c7ef91926f025b4230b30b529c282ca9e1e8" },
};
static const kat_rp_t S7_E0[] = { /* expiry_0: out-of-range integer: expiry_height = 0, allowed 1..18446744073709551615 */
    { "2571ab5c1d48e11e0c35d607d57161cea0766427975e5849a5e8040b7fa126695f0a0987736da1e5d95c07943968de194036b236ef4fc0114e75d32455bb6e2b",
      "5cfe2ba5da36d54c2291313799954230b80d5dcba85e46a2b951364ba41f9a53643a03862a1deb3f48e81b04ff2b0beb842914dc4feafd5e076dc9fbc8f13b75",
      UINT64_C(0),
      NULL },
};
/* S7 expiry_2^64, intent_id_len_0 (KAT errors[1], [2]) — not
 * expressible: uint64_t expiry_height, a fixed 64-byte intent_id (see
 * the file header). */
static const kat_rp_t S7_E3[] = { /* unsorted_tx_id_memcmp: unsorted keys at index 1 */
    { "df6532963e345d34b2c22ff7539dc216d42780040e625c915dbb65cc1c8de8747ebb4e7b96b244841ea9d2d0c5372b6ea2afe0cbbbe403de4196593d04253b70",
      "5cfe2ba5da36d54c2291313799954230b80d5dcba85e46a2b951364ba41f9a53643a03862a1deb3f48e81b04ff2b0beb842914dc4feafd5e076dc9fbc8f13b75",
      UINT64_C(1),
      NULL },
    { "2571ab5c1d48e11e0c35d607d57161cea0766427975e5849a5e8040b7fa126695f0a0987736da1e5d95c07943968de194036b236ef4fc0114e75d32455bb6e2b",
      "9b72ddebafe952ac3895fe8c5fc79f9ce2071f14da89d9339086ecfda53176c2cd1a731df852b2b7807c7daf765378afdbac6a29e537911e93e405d118797431",
      UINT64_C(1),
      NULL },
};
static const kat_rp_t S7_E4[] = { /* duplicate_key_tx_id: duplicate key at index 1 */
    { "2571ab5c1d48e11e0c35d607d57161cea0766427975e5849a5e8040b7fa126695f0a0987736da1e5d95c07943968de194036b236ef4fc0114e75d32455bb6e2b",
      "5cfe2ba5da36d54c2291313799954230b80d5dcba85e46a2b951364ba41f9a53643a03862a1deb3f48e81b04ff2b0beb842914dc4feafd5e076dc9fbc8f13b75",
      UINT64_C(1),
      NULL },
    { "2571ab5c1d48e11e0c35d607d57161cea0766427975e5849a5e8040b7fa126695f0a0987736da1e5d95c07943968de194036b236ef4fc0114e75d32455bb6e2b",
      "9b72ddebafe952ac3895fe8c5fc79f9ce2071f14da89d9339086ecfda53176c2cd1a731df852b2b7807c7daf765378afdbac6a29e537911e93e405d118797431",
      UINT64_C(2),
      NULL },
};
static const kat_rp_t S7_E5[] = { /* duplicate_intent_id: duplicate intent_id at index 1 */
    { "2571ab5c1d48e11e0c35d607d57161cea0766427975e5849a5e8040b7fa126695f0a0987736da1e5d95c07943968de194036b236ef4fc0114e75d32455bb6e2b",
      "5cfe2ba5da36d54c2291313799954230b80d5dcba85e46a2b951364ba41f9a53643a03862a1deb3f48e81b04ff2b0beb842914dc4feafd5e076dc9fbc8f13b75",
      UINT64_C(1),
      NULL },
    { "df6532963e345d34b2c22ff7539dc216d42780040e625c915dbb65cc1c8de8747ebb4e7b96b244841ea9d2d0c5372b6ea2afe0cbbbe403de4196593d04253b70",
      "5cfe2ba5da36d54c2291313799954230b80d5dcba85e46a2b951364ba41f9a53643a03862a1deb3f48e81b04ff2b0beb842914dc4feafd5e076dc9fbc8f13b75",
      UINT64_C(2),
      NULL },
};
static const kat_rp_set_t S7_ERRS[] = {
    { "expiry_0", S7_E0, 1, NULL },
    { "unsorted_tx_id_memcmp", S7_E3, 2, NULL },
    { "duplicate_key_tx_id", S7_E4, 2, NULL },
    { "duplicate_intent_id", S7_E5, 2, NULL },
};
/* ── S8 GLOBAL v2 (KAT vectors.S8_global_v2). S8 domains_root_len_63
 *    (KAT errors[0]) is not expressible: a fixed 64-byte array. ── */
static const kat_glob_t S8_COMPS[] = {
    { "fixed_all_00",
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "3ce25983041c762fe73a5d144fbee60da6d5145cb14f4a818e37e2801ada6ec3e4ddae9894385eb4831a26feba7c6bc6b5a76ddcb7de4fe7b6d699055a5392b1" },
    { "fixed_all_ff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "2f96ae00f04b5bd587fb9b5165ac5acbfe51bc2587d7bc1efdaf6e417e446e8eea510c1def98fd86e944043077e7040d820db33b8b1429ee00a14bb3863aff4f" },
    { "fixed_01_02",
      "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
      "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
      "471c4afb70e2ecb990c395fa6dea5e62cc51fe007ca3bce672282f58583611934ee4c4c17c17b5cb8dc40bb60e28c383a75097e07df2208bbfaf8f92ee3abca6" },
    { "random",
      "bdcf389bc4e3a98e0f1e481c519e03c6d4a93f31ae8b0856a70af778a42863afd796033edc778646f695c45083a160c6d3f2f2a3d0b7738c79345aeb9d544b7d",
      "f94494c38c9c81b2f9e37845e64c40edc3099baeb3af87d962cff59b24801db75ca81f8b3a7e099a01deae54883dba3cdfdab04e0d1ce323e8867590eca84ff0",
      "cc912dc83c596e2f9bd5d527d417296cb7502165e873cd1853e56806a40de35695640f063a89ae89306328f0861c0bdd07e438c8a994f8c16137aea24db3f891" },
    { "S6_random_3_heads_with_empty_replay",
      "ecc42b0899017267f7b90f398a1549d558de75a757593a08ae8ab024f3e82d3ea9ddb68f9e981f04c6a7b44de73b886811b9b6631f238b26f9de62ef5ccc8a89",
      "8156613c0353dfbba44c463035f5a88204c04fbe865283ace9599a144828c379dc97a7fe684124f6be72413f8d2b0ceb6552e33a23a800b01b7213f671543ac0",
      "e18bae393b6051e13c80d84359a48a7ecd5ebe3178804a362dafc8ce3e01ae8796faf2e20013b869fd3b77852450046aed9d7a483f26ebc15871352e82c9f3a6" },
    { "S6_random_3_heads_with_S7_n5",
      "ecc42b0899017267f7b90f398a1549d558de75a757593a08ae8ab024f3e82d3ea9ddb68f9e981f04c6a7b44de73b886811b9b6631f238b26f9de62ef5ccc8a89",
      "f2a3732a28dc3070c6442dafbadd1d932aa8be12cf11612aaf81fb164070cff343ee5676adc75fb489e303451a73c7ef91926f025b4230b30b529c282ca9e1e8",
      "45633f7ea9808990aab8d15d1651a8e6968783f6555d60fa04685ef409289fc39f7cdaeed9b0256e30588256e5131817ffef9f94296329bff3e929bf483d7c26" },
};

/* ════════════════════════════════════════════════════════════════════════
 * Checks
 * ════════════════════════════════════════════════════════════════════════ */

/* Empty roots (C7): the three new kinds + the unchanged STSEG kind. */
static int test_empty(void) {
    static const struct { dna_v2_empty_kind_t k; const char *hex; } E[] = {
        { DNA_V2_EMPTY_BCOPY,
          "8c89eea63e93017d8c548c2a727a2c1764f1b287e6af1e065b9eeeb3dcf2a152b8e47d0eed8f807f23b2dfd60710c0c2d53371a456544461b30179af490bf4e5" },
        { DNA_V2_EMPTY_STMEM,
          "e5f7fac90e74fb474457f1c1e2cddec4a8ec6e25c8d25aaaf87944b65ed8983ce21f95533a912be282480da398035d00a7e9cb38170e58028d3ee13e9ff57efe" },
        { DNA_V2_EMPTY_STORAGE_SEGS,
          "d50e4a36ac95b3e6101193f47fc7b362b5e1706ef259aba91f4d08f8e7b4846341df6ff0c0f2452554cba06a75dc1c943696ec8fe49600717bb1a11fb03801fe" },
        { DNA_V2_EMPTY_REPLAY,
          "8156613c0353dfbba44c463035f5a88204c04fbe865283ace9599a144828c379dc97a7fe684124f6be72413f8d2b0ceb6552e33a23a800b01b7213f671543ac0" },
    };
    for (size_t i = 0; i < NELEM(E); i++) {
        uint8_t h[64];
        CHECK(dna_v2_empty_root(E[i].k, h) == 0, "empty root");
        CHECK(hex_eq(h, E[i].hex, "empty root"), "empty root KAT");
        OK();
    }
    return 0;
}

/* S1 — rows from literals; leaf per row (valid sets), root or -1. */
static int bc_rows(const kat_bc_t *k, size_t n, dna_v2_bcopy_row_t *r) {
    for (size_t i = 0; i < n; i++) {
        memset(&r[i], 0, sizeof(r[i]));
        r[i].epoch_start = k[i].epoch_start;
        if (unhex(k[i].validator_fp, r[i].validator_fp, 64) != 0) return -1;
        if (unhex(k[i].owner_fp, r[i].owner_fp, 64) != 0) return -1;
        r[i].kind = k[i].kind;
        r[i].amount = k[i].amount;
    }
    return 0;
}

static int test_s1(void) {
    dna_v2_bcopy_row_t r[8];
    uint8_t h[64];
    for (size_t s = 0; s < NELEM(S1_ROOTS); s++) {
        const kat_bc_set_t *v = &S1_ROOTS[s];
        CHECK(v->n <= NELEM(r), "S1 fixture size");
        CHECK(bc_rows(v->rows, v->n, r) == 0, "S1 fixture hex");
        for (size_t i = 0; i < v->n; i++) {
            CHECK(dna_v2_bcopy_leaf_hash(&r[i], h) == 0, "S1 leaf");
            CHECK(hex_eq(h, v->rows[i].leaf, "S1 leaf"), "S1 leaf KAT");
            OK();
        }
        CHECK(dna_v2_bcopy_root(r, v->n, h) == 0, "S1 root");
        CHECK(hex_eq(h, v->root, v->name), "S1 root KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S1_ERRS); s++) {
        const kat_bc_set_t *v = &S1_ERRS[s];
        CHECK(v->n <= NELEM(r), "S1 fixture size");
        CHECK(bc_rows(v->rows, v->n, r) == 0, "S1 fixture hex");
        if (dna_v2_bcopy_root(r, v->n, h) != -1) {
            fprintf(stderr, "S1 ERROR vector accepted: %s\n", v->name);
            return 1;
        }
        OK();
    }
    /* the single-row range vectors are refused by the leaf too */
    CHECK(bc_rows(S1_E0, 1, r) == 0 && dna_v2_bcopy_leaf_hash(r, h) == -1,
          "S1 leaf epoch_start 2^63");
    CHECK(bc_rows(S1_E1, 1, r) == 0 && dna_v2_bcopy_leaf_hash(r, h) == -1,
          "S1 leaf kind 2");
    CHECK(bc_rows(S1_E2, 1, r) == 0 && dna_v2_bcopy_leaf_hash(r, h) == -1,
          "S1 leaf amount 2^63");
    CHECK(bc_rows(S1_E3, 1, r) == 0 && dna_v2_bcopy_leaf_hash(r, h) == -1,
          "S1 leaf amount -1");
    OK();
    return 0;
}

/* S2 — vstat values; the out-of-range value and the absent row. */
static int test_s2(void) {
    uint8_t h[64];
    for (size_t i = 0; i < NELEM(S2_VALUES); i++) {
        CHECK(dna_v2_vstat_hash(&S2_VALUES[i].active_count, h) == 0, "S2");
        CHECK(hex_eq(h, S2_VALUES[i].vstat, "S2 vstat"), "S2 KAT");
        OK();
    }
    const uint64_t over = UINT64_C(9223372036854775808);   /* 2^63      */
    CHECK(dna_v2_vstat_hash(&over, h) == -1, "S2 active_count 2^63");
    OK();
    CHECK(dna_v2_vstat_hash(NULL, h) == -1, "S2 absent row");
    OK();
    return 0;
}

/* S3 */
static int sm_rows(const kat_sm_t *k, size_t n, dna_v2_stmem_row_t *r) {
    for (size_t i = 0; i < n; i++) {
        memset(&r[i], 0, sizeof(r[i]));
        r[i].epoch_start = k[i].epoch_start;
        if (unhex(k[i].node_fp, r[i].node_fp, 64) != 0) return -1;
        r[i].fail_streak = k[i].fail_streak;
        r[i].grace_until = k[i].grace_until;
    }
    return 0;
}

static int test_s3(void) {
    dna_v2_stmem_row_t r[8];
    uint8_t h[64];
    for (size_t s = 0; s < NELEM(S3_ROOTS); s++) {
        const kat_sm_set_t *v = &S3_ROOTS[s];
        CHECK(v->n <= NELEM(r), "S3 fixture size");
        CHECK(sm_rows(v->rows, v->n, r) == 0, "S3 fixture hex");
        for (size_t i = 0; i < v->n; i++) {
            CHECK(dna_v2_stmem_leaf_hash(&r[i], h) == 0, "S3 leaf");
            CHECK(hex_eq(h, v->rows[i].leaf, "S3 leaf"), "S3 leaf KAT");
            OK();
        }
        CHECK(dna_v2_stmem_root(r, v->n, h) == 0, "S3 root");
        CHECK(hex_eq(h, v->root, v->name), "S3 root KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S3_ERRS); s++) {
        const kat_sm_set_t *v = &S3_ERRS[s];
        CHECK(v->n <= NELEM(r), "S3 fixture size");
        CHECK(sm_rows(v->rows, v->n, r) == 0, "S3 fixture hex");
        if (dna_v2_stmem_root(r, v->n, h) != -1) {
            fprintf(stderr, "S3 ERROR vector accepted: %s\n", v->name);
            return 1;
        }
        OK();
    }
    return 0;
}

/* S4 */
static int test_s4(void) {
    for (size_t s = 0; s < NELEM(S4_COMPS); s++) {
        uint8_t L[12][64], h[64];
        for (int i = 0; i < 12; i++)
            CHECK(unhex(S4_COMPS[s].legs[i], L[i], 64) == 0, "S4 hex");
        CHECK(dna_v2_system_root_v6(L[0], L[1], L[2], L[3], L[4], L[5],
                                    L[6], L[7], L[8], L[9], L[10], L[11],
                                    h) == 0, "S4");
        CHECK(hex_eq(h, S4_COMPS[s].root, S4_COMPS[s].name), "S4 KAT");
        OK();
    }
    return 0;
}

/* S5 */
static int seg_cols(const kat_seg_t *k, size_t n, uint64_t *ks,
                    uint8_t (*roots)[64], uint64_t *ph) {
    for (size_t i = 0; i < n; i++) {
        ks[i] = k[i].k;
        ph[i] = k[i].published_height;
        if (unhex(k[i].root_k, roots[i], 64) != 0) return -1;
    }
    return 0;
}

static int test_s5(void) {
    uint64_t ks[8], ph[8];
    uint8_t roots[8][64], h[64];
    for (size_t s = 0; s < NELEM(S5_ROOTS); s++) {
        const kat_seg_set_t *v = &S5_ROOTS[s];
        CHECK(v->n <= NELEM(ks), "S5 fixture size");
        CHECK(seg_cols(v->rows, v->n, ks, roots, ph) == 0, "S5 hex");
        for (size_t i = 0; i < v->n; i++) {
            CHECK(dna_v2_segment_leaf_hash_v2(ks[i], roots[i], ph[i], h)
                  == 0, "S5 leaf");
            CHECK(hex_eq(h, v->rows[i].leaf, "S5 leaf"), "S5 leaf KAT");
            OK();
        }
        CHECK(dna_v2_segments_root_v2(ks, (const uint8_t (*)[64])roots, ph,
                                      v->n, h) == 0, "S5 root");
        CHECK(hex_eq(h, v->root, v->name), "S5 root KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S5_ERRS); s++) {
        const kat_seg_set_t *v = &S5_ERRS[s];
        CHECK(v->n <= NELEM(ks), "S5 fixture size");
        CHECK(seg_cols(v->rows, v->n, ks, roots, ph) == 0, "S5 hex");
        if (dna_v2_segments_root_v2(ks, (const uint8_t (*)[64])roots, ph,
                                    v->n, h) != -1) {
            fprintf(stderr, "S5 ERROR vector accepted: %s\n", v->name);
            return 1;
        }
        OK();
    }
    return 0;
}

/* S6 */
static int head_cols(const kat_head_t *k, size_t n, dna_v2_domain_head_t *hd,
                     uint8_t (*luh)[64]) {
    for (size_t i = 0; i < n; i++) {
        memset(&hd[i], 0, sizeof(hd[i]));
        hd[i].domain_id = k[i].domain_id;
        if (unhex(k[i].domain_state_root, hd[i].domain_state_root, 64) != 0)
            return -1;
        hd[i].domain_height = k[i].domain_height;
        hd[i].last_updated_global_height = k[i].last_updated_global_height;
        hd[i].ruleset_version = k[i].ruleset_version;
        hd[i].status = k[i].status;
        if (unhex(k[i].last_upd_hash, luh[i], 64) != 0) return -1;
    }
    return 0;
}

static int test_s6(void) {
    dna_v2_domain_head_t hd[8];
    uint8_t luh[8][64], h[64];
    CHECK(NELEM(S6_HEADS) == NELEM(S6_HEADS_ENC89), "S6 fixture");
    CHECK(NELEM(S6_HEADS) <= NELEM(hd), "S6 fixture size");
    CHECK(head_cols(S6_HEADS, NELEM(S6_HEADS), hd, luh) == 0, "S6 hex");
    for (size_t i = 0; i < NELEM(S6_HEADS); i++) {
        uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN];
        CHECK(dna_v2_domain_head_encode(&hd[i], enc) == 0, "S6 enc89");
        CHECK(hex_eq_n(enc, sizeof(enc), S6_HEADS_ENC89[i], "S6 enc89"),
              "S6 enc89 KAT");
        CHECK(dna_v2_domain_head_hash_v2(&hd[i], luh[i], h) == 0, "S6 head");
        CHECK(hex_eq(h, S6_HEADS[i].head_hash, "S6 head"), "S6 head KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S6_ROOTS); s++) {
        const kat_head_set_t *v = &S6_ROOTS[s];
        CHECK(v->n <= NELEM(hd), "S6 fixture size");
        CHECK(head_cols(v->rows, v->n, hd, luh) == 0, "S6 hex");
        for (size_t i = 0; i < v->n; i++) {
            CHECK(dna_v2_domain_head_hash_v2(&hd[i], luh[i], h) == 0,
                  "S6 head");
            CHECK(hex_eq(h, v->rows[i].head_hash, "S6 head"), "S6 head KAT");
            OK();
        }
        CHECK(dna_v2_domains_root_v2(hd, (const uint8_t (*)[64])luh, v->n,
                                     h) == 0, "S6 domains_root");
        CHECK(hex_eq(h, v->root, v->name), "S6 domains_root KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S6_ERRS); s++) {
        const kat_head_set_t *v = &S6_ERRS[s];
        CHECK(v->n <= NELEM(hd), "S6 fixture size");
        CHECK(head_cols(v->rows, v->n, hd, luh) == 0, "S6 hex");
        /* non-NULL buffers even for n == 0: the refusal under test is
         * the empty list, not a NULL argument */
        if (dna_v2_domains_root_v2(hd, (const uint8_t (*)[64])luh, v->n,
                                   h) != -1) {
            fprintf(stderr, "S6 ERROR vector accepted: %s\n", v->name);
            return 1;
        }
        OK();
    }
    return 0;
}

/* S7 */
static int rp_rows(const kat_rp_t *k, size_t n, dna_v2_replay_row_t *r) {
    for (size_t i = 0; i < n; i++) {
        memset(&r[i], 0, sizeof(r[i]));
        if (unhex(k[i].tx_id, r[i].tx_id, 64) != 0) return -1;
        if (unhex(k[i].intent_id, r[i].intent_id, 64) != 0) return -1;
        r[i].expiry_height = k[i].expiry_height;
    }
    return 0;
}

static int test_s7(void) {
    dna_v2_replay_row_t r[8];
    uint8_t h[64];
    for (size_t s = 0; s < NELEM(S7_ROOTS); s++) {
        const kat_rp_set_t *v = &S7_ROOTS[s];
        CHECK(v->n <= NELEM(r), "S7 fixture size");
        CHECK(rp_rows(v->rows, v->n, r) == 0, "S7 fixture hex");
        for (size_t i = 0; i < v->n; i++) {
            CHECK(dna_v2_replay_leaf_hash(&r[i], h) == 0, "S7 leaf");
            CHECK(hex_eq(h, v->rows[i].leaf, "S7 leaf"), "S7 leaf KAT");
            OK();
        }
        CHECK(dna_v2_replay_root(r, v->n, h) == 0, "S7 root");
        CHECK(hex_eq(h, v->root, v->name), "S7 root KAT");
        OK();
    }
    for (size_t s = 0; s < NELEM(S7_ERRS); s++) {
        const kat_rp_set_t *v = &S7_ERRS[s];
        CHECK(v->n <= NELEM(r), "S7 fixture size");
        CHECK(rp_rows(v->rows, v->n, r) == 0, "S7 fixture hex");
        if (dna_v2_replay_root(r, v->n, h) != -1) {
            fprintf(stderr, "S7 ERROR vector accepted: %s\n", v->name);
            return 1;
        }
        OK();
    }
    /* KAT R5: a tx_id equal to ANOTHER row's intent_id is not a
     * conflict (uniqueness is per column) — built from S7_R2's rows. */
    CHECK(rp_rows(S7_R2, 2, r) == 0, "S7 fixture hex");
    memcpy(r[1].intent_id, r[0].tx_id, 64);
    CHECK(memcmp(r[0].intent_id, r[1].intent_id, 64) != 0,
          "S7 cross-column fixture");
    CHECK(dna_v2_replay_root(r, 2, h) == 0,
          "S7 tx_id == other intent_id accepted");
    OK();
    return 0;
}

/* S8 */
static int test_s8(void) {
    for (size_t s = 0; s < NELEM(S8_COMPS); s++) {
        uint8_t d[64], rr[64], h[64];
        CHECK(unhex(S8_COMPS[s].domains_root, d, 64) == 0, "S8 hex");
        CHECK(unhex(S8_COMPS[s].replay_root, rr, 64) == 0, "S8 hex");
        CHECK(dna_v2_global_root_v2(d, rr, h) == 0, "S8");
        CHECK(hex_eq(h, S8_COMPS[s].root, S8_COMPS[s].name), "S8 KAT");
        OK();
    }
    return 0;
}

int main(void) {
    if (test_empty() || test_s1() || test_s2() || test_s3() || test_s4() ||
        test_s5() || test_s6() || test_s7() || test_s8()) {
        fprintf(stderr, "test_roots_hf7: FAIL\n");
        return 1;
    }
    printf("test_roots_hf7: PASS (%d checks)\n", g_checks);
    return 0;
}
