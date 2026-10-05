/**
 * @file nodus/tests/test_storage_b2.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2a — the
 *        chain side: byte layouts against the independent oracle, segment
 *        publication over v2_blocks, the STORAGE_REPORT rule, and twin
 *        GEN_STORAGE chains through freeze / report / settlement /
 *        fail_streak / handoff / exit release.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (R = 3, G = 1, amount = block count, 3 failed epochs →
 * skipped, K5 return after 12 settled epochs, K5a an OK epoch with
 * eligible blocks resets to 0 even at 3 or more), 2026-10-05-archive-
 * reward-bytes-approved.md, 2026-10-05-
 * kurultay-7-archive-reward-summary.md, 2026-10-04-storage-reward-
 * approved.md (kept parts), 2026-10-04-storage-reward-who-earns.md.
 * Design docs/plans/2026-10-05-archive-reward-design.md rev 4 + kept rev
 * 2.2 §1, §2, §4, §5; bytes docs/plans/2026-10-05-archive-reward-bytes.md
 * items 1-5 and §6, docs/plans/2026-10-04-storage-reward-bytes.md items
 * 2, 3, 6.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. KAT — every vector of nodus/tests/vectors/archive_reward_kat.json
 *     (the independent oracle archive_reward_oracle.py) the C computes,
 *     byte for byte: the empty roots, the synthetic block hashes, Root(k)
 *     (first / last hash, the concatenation checksum, the root) for k =
 *     1..5, 1000 and 2^32+7, the segment leaf, segments_root (each entry's
 *     leaf), A(k), holders (each member's node hash and distance, the
 *     eligible count, the holders by rank), registry leaf v2 and root v2,
 *     storage_root v2, and the §6 sample derivation (x_i, the two integer
 *     reads, block index for every B, part index for every parts_total).
 *     The tag section is checked against the padded names. Any unknown
 *     section FAILS (a new vector is never skipped silently).
 *  B. PUBLICATION over 51,850 synthetic v2_blocks rows (hash[h] = the
 *     KAT's SHA3-512("ARCHIVE-KAT-H" ‖ h)): Root(1..3) from the table ==
 *     the oracle's roots; at B = 2P + 2E exactly k = 1, 2 are published
 *     (k = 3 is immature), at 3P + 2E − E nothing more, at 3P + 2E k = 3;
 *     the segments_root then equals the oracle's n = 3 root; a twin
 *     database publishes byte-identically; a missing v2_blocks row and a
 *     malformed block_id are FAULTS (no publication, no partial row).
 *  C. HOOK LEVEL — the STORAGE_REPORT read plan and exec over fabricated
 *     reads: the three reads in order; the CREATE / ABSENT row; refusals
 *     (each -1): generations 1, 2 and NULL; two legs; auth kind 2; fee
 *     != 0; a call one byte short / long; bitmap_len 33; H not a boundary;
 *     the window's both edges (H+E and H+E+E/2+1 refused, H+E+1 and
 *     H+E+E/2 accepted); no frozen set; S(H) differs; bitmap_len !=
 *     ceil(count/8); an unused high bit set; the seat absent; the signer
 *     not the seat; two signers; an existing (H, seat) row.
 *  D. ENGINE, twin fixtures (same seed, same genesis, every block applied
 *     to both; after each block the committed global roots are equal and
 *     each committed SYSTEM head equals its runtime's recomputation):
 *     seven seeded validators with REAL keys (every block carries their
 *     COMMIT votes, so Rule N retires nobody), treasury pool 1 = 10^16,
 *     param 9 at 2, param 14 at 4, eight segments PRE-SEEDED (k = 1..8,
 *     published_height 1 — see HOW IT CAN LIE). A, B, C and D (= validator
 *     0's key: the dual-role node) register at 4; X at E + 5.
 *       boundary E    first storage boundary: set(E) = {A,B,C,D}, no
 *                     settlement, no publication (k = 9 is not due);
 *       boundary 2E   set(2E) = {A,B,C,D,X};
 *       2E + 1        three seats report for H = E (F1 floor not met);
 *       boundary 3E   settle H = E: nothing eligible yet (W == 0) — no
 *                     credit, pool 1 and every fail_streak unchanged;
 *       3E + 1        all seven report for H = 2E: only N (the always-OK
 *                     member) has every other bit; D sets only its own
 *                     bit (F2: ignored → D NOT OK); a duplicate (H, seat)
 *                     at 3E + 2 and reports at 3E and 3E + E/2 + 1 are
 *                     refused;
 *       boundary 4E   settle H = 2E ("one OK"): weights = block count of
 *                     holders(k, set(E)) ∩ set(2E) (X is new: weight 0 —
 *                     G = 1); N alone credited floor(budget·w/W); pool 1
 *                     debited exactly Σ credited (the remainder stays);
 *                     fail_streak +1 for every NOT OK member with weight
 *                     (every streak checked by the rule incl. K5, K5a);
 *       4E + 3        B exits;
 *       boundary 5E   settle H = 3E (all OK except M); the HANDOFF: the
 *                     eligible lists for H = 2E and H = 3E equal the
 *                     test's own holders(k, set(H−E)) ∩ set(H) — a holder
 *                     X displaced keeps its segment through the overlap
 *                     epoch, X earns nothing for it until H = 3E; B's
 *                     bond RELEASED as one locked UTXO (identity, owner,
 *                     amount, unlock 5E + 12E), storage bonds − BOND,
 *                     utxo + BOND, the CORE invariant holds; set(5E)
 *                     excludes B;
 *       boundary 6E   settle H = 4E (all OK except M): M's fail_streak is
 *                     3 and set(6E) freezes it at 3 — holders over set(6E)
 *                     never name M;
 *       boundary 7E   settle H = 5E (all OK except M; M with weight from
 *                     set(4E), where M was frozen at 1): M at 3, NOT OK,
 *                     adds one, 4 (the skipped branch, K5);
 *       boundary 8E   settle H = 6E ("all OK", M included; M with weight
 *                     from set(5E), where M was frozen at 2): K5a — M at
 *                     4, with weight and OK, resets to 0;
 *       boundary 9E   no report for H = 7E: F1 not met — every
 *                     fail_streak (M's 0 included) and pool 1 unchanged;
 *                     M, frozen at 3 in set(6E), has weight 0 in H = 7E.
 *  D0. FAIL_STREAK RULE, pure (nodus_storage_fail_streak_next + holders
 *     over a hand-built 4-member frozen set): below 3 the old rule; at 3
 *     .. 14 weight and OK → 0 (K5a); at 3 .. 13 +1 for the other three
 *     (weight, verdict) pairs; 14 → 0 for them; the arc 3 failures →
 *     skipped → 12 settled epochs skipped (half with no eligible block,
 *     never weight and OK together) → 0 and placed again → 3 new failures
 *     → skipped again → one OK epoch with weight → 0. The 15 → 0 return,
 *     the re-placement and the "≥ 3 with weight 0 adds one" branch are
 *     proven HERE, not through the engine (the return would need 12 more
 *     settled epochs of twin chains; the engine's only member at 3 or
 *     more is M, and M has weight in the two epochs it settles there).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; json-c (JSONC_FOUND) for
 * section A — built without it, section A FAILS (never skips). Any
 * DNAC_EPOCH_LENGTH that divides nothing in particular works (every
 * height is derived from it); it must be >= 8 so heights 1..7 hold no
 * boundary. Environment: none. Cost: section D applies 9E blocks to
 * each of two fixtures (≈ 13,000 block applications at the production
 * E = 720, each followed by a SYSTEM-root recomputation) and section B
 * inserts ≈ 120,000 synthetic v2_blocks rows — minutes, not seconds.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_storage_b2_* directory per fixture, removed at the end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The GEN_STORAGE pins and the storage vote literal are independent-
 *    oracle literals (shared/dnac/tests/storage_oracle.py,
 *    nodus_witness_runtime.c / dnac.h). If they stop re-deriving, the
 *    runtime selfcheck fails and section D FAILS at its seeded genesis.
 *    Sections A, B and C do not consult the pins.
 *  - Section D's eight segments are PRE-SEEDED rows (roots = SHA3-512 of
 *    a test string, published_height 1), a state the chain never writes:
 *    a real publication needs 17,280 + 2E blocks. They are absorbed into
 *    the first v5 SYSTEM root at the storage edge (H14 − 1). Publication
 *    from v2_blocks is section B's subject, on synthetic rows, through
 *    the boundary's own publication step — not through a full chain.
 *  - Section C fabricates the reads and the verdict; section D drives the
 *    real engine with real signatures.
 *  - Which member is M (the always-failing one) and which is N is chosen
 *    at run time from the eligible lists (the first of A, C with weight in
 *    all three settled epochs); with eight segments the absence of such a
 *    member is improbable but would FAIL the test, never pass it.
 *  - D's accrual row also receives its validator distribution (the
 *    merged-accrual design rev 2.2 §5.4), so D's storage credit is proven
 *    only through the pool-1 debit, never per row.
 *  - "Twin" is two fixtures in one process, not a 7-machine run.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_validator.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#ifdef ARCHIVE_REWARD_KAT_PATH
#include <json-c/json.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define P_LEN    ((uint64_t)DNA_V2_SEGMENT_BLOCKS)
#define D2       ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define DS       ((uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define BOND     ((uint64_t)DNAC_STORAGE_STAKE_MIN)
#define POOL1    10000000000000000ULL          /* 10^16 raw (pool 1)     */
#define OUT_LEN  232u
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define N_SEGS   8u

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STSET       10u
#define OP_SNAPSEAT    11u
#define OP_STREP       12u
#define STREG_LEN      (2592u + 8u + 64u)
#define REP_FIXED      78u

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* The KAT's synthetic block hash: SHA3-512("ARCHIVE-KAT-H" (13 raw
 * bytes) ‖ h u64 BE) — archive_reward_kat.json "conventions". */
static int synth_hash(uint64_t h, uint8_t out[64]) {
    uint8_t pre[13 + 8];
    memcpy(pre, "ARCHIVE-KAT-H", 13);
    put64(pre + 13, h);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int hex_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_to(const char *s, uint8_t *out, size_t len) {
    if (!s || strlen(s) != 2 * len) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = hex_nib(s[2 * i]), lo = hex_nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* The oracle's Root(1), Root(2), Root(3) and the n = 3 segments_root
 * (archive_reward_kat.json "segment_root" / "segments_root" — pinned here
 * so section B runs without json-c; section A re-reads them from the
 * file). */
static const char *ORACLE_ROOT[3] = {
    "da016b6a78f98b9b9cb76fe2b030844322af56154d06be2d26e725784c2a9b749e6abd33b8dbb39d0f891fca8187aa57a8422da3e65d38fd4ac6bdd30341415b",
    "d614eb7d4192493cda429a1a74b2844beaef5e9ad205275a7bc41634effc31f727693680da269132384f22ddc30b05b9c3d395d67222088e76fc5c161b1c3f0e",
    "972921963540807a2905460c541ce8f0634b4cf2e8c187b5c91b953817bc8897bd98f3ce376add65e89c084fc36770b47f49385ba761e188d37e492963e36cfe",
};

/* ══ A. KAT ═══════════════════════════════════════════════════════════ */

#ifdef ARCHIVE_REWARD_KAT_PATH

static char g_kv[96];

static json_object *kj(json_object *o, const char *key) {
    json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v)) return NULL;
    return v;
}

static int kat_hex(json_object *o, const char *key, uint8_t *out,
                   size_t len) {
    json_object *v = kj(o, key);
    if (v && json_object_is_type(v, json_type_string) &&
        hex_to(json_object_get_string(v), out, len) == 0)
        return 0;
    fprintf(stderr, "KAT vector %s: field \"%s\" missing or not %zu hex "
            "bytes\n", g_kv, key, len);
    return -1;
}

static int kat_u64_of(json_object *v, uint64_t *out) {
    if (v && json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        char *end = NULL;
        errno = 0;
        unsigned long long x = strtoull(s, &end, 10);
        if (s[0] >= '0' && s[0] <= '9' && end && *end == 0 && errno == 0) {
            *out = (uint64_t)x;
            return 0;
        }
    } else if (v && json_object_is_type(v, json_type_int)) {
        int64_t x = json_object_get_int64(v);
        if (x >= 0) { *out = (uint64_t)x; return 0; }
    }
    return -1;
}

static int kat_uint(json_object *o, const char *key, uint64_t max,
                    uint64_t *out) {
    if (kat_u64_of(kj(o, key), out) == 0 && *out <= max) return 0;
    fprintf(stderr, "KAT vector %s: field \"%s\" missing, not an unsigned "
            "integer or above %llu\n", g_kv, key, (unsigned long long)max);
    return -1;
}

static json_object *kat_arr(json_object *o, const char *key, size_t *n) {
    json_object *v = kj(o, key);
    if (v && json_object_is_type(v, json_type_array)) {
        *n = json_object_array_length(v);
        return v;
    }
    fprintf(stderr, "KAT vector %s: field \"%s\" is not an array\n", g_kv,
            key);
    return NULL;
}

static int kat_eq(const uint8_t got[64], json_object *o, const char *key) {
    uint8_t exp[64];
    if (kat_hex(o, key, exp, 64) != 0) return 0;
    if (memcmp(got, exp, 64) == 0) { g_checks++; return 1; }
    static const char *d = "0123456789abcdef";
    char g[129];
    for (int i = 0; i < 64; i++) {
        g[2 * i] = d[got[i] >> 4]; g[2 * i + 1] = d[got[i] & 0xf];
    }
    g[128] = 0;
    fprintf(stderr, "KAT MISMATCH vector %s field \"%s\":\n  expected: %s\n"
            "  got:      %s\n", g_kv, key,
            json_object_get_string(kj(o, key)), g);
    return 0;
}

static void kat_name(const char *sec, json_object *v, size_t i) {
    json_object *nm = kj(v, "name");
    if (nm && json_object_is_type(nm, json_type_string))
        snprintf(g_kv, sizeof(g_kv), "%s[%s]", sec,
                 json_object_get_string(nm));
    else
        snprintf(g_kv, sizeof(g_kv), "%s[%zu]", sec, i);
}

static int kat_row_v2(json_object *r, dna_v2_storage_node_row_t *row) {
    uint64_t st = 0, fs = 0;
    memset(row, 0, sizeof(*row));
    if (kat_hex(r, "node_fp", row->node_fp, 64) != 0 ||
        kat_hex(r, "payee_fp", row->payee_fp, 64) != 0 ||
        kat_uint(r, "bond", UINT64_MAX, &row->bond) != 0 ||
        kat_uint(r, "status", 0xFF, &st) != 0 ||
        kat_uint(r, "registered_height", UINT64_MAX,
                 &row->registered_height) != 0 ||
        kat_uint(r, "exit_height", UINT64_MAX, &row->exit_height) != 0 ||
        kat_uint(r, "fail_streak", UINT32_MAX, &fs) != 0)
        return -1;
    row->status = (uint8_t)st;
    row->fail_streak = (uint32_t)fs;
    return 0;
}

#define KCHECK(cond) do { if (!(cond)) { rc = 1; goto out; } } while (0)

static int t_kat(void) {
    static dna_v2_storage_node_row_t rows[DNA_V2_STORAGE_SET_MAX];
    static uint8_t fps[DNA_V2_STORAGE_SET_MAX][64];
    static uint32_t streaks[DNA_V2_STORAGE_SET_MAX];
    static uint8_t pk[2592];
    uint8_t (*hashes)[64] = malloc((size_t)P_LEN * 64);
    uint8_t h[64];
    int rc = 0, compared = 0;
    const int checks0 = g_checks;
    json_object *root = NULL;
    if (!hashes) return 1;

    root = json_object_from_file(ARCHIVE_REWARD_KAT_PATH);
    if (!root) {
        fprintf(stderr, "KAT: cannot read %s\n", ARCHIVE_REWARD_KAT_PATH);
        free(hashes);
        return 1;
    }
    json_object *vec = kj(root, "vectors");
    snprintf(g_kv, sizeof(g_kv), "%s", "(file)");
    KCHECK(vec && json_object_is_type(vec, json_type_object));
    {
        uint64_t sb = 0;
        KCHECK(kat_uint(kj(root, "conventions"), "segment_blocks",
                        UINT64_MAX, &sb) == 0 && sb == P_LEN);
    }

    json_object_object_foreach(vec, sec, sval) {
        (void)sval;
        static const char *known[] = {
            "tags", "empty_roots", "synthetic_hash", "segment_root",
            "segment_leaf", "segments_root", "assignment_key", "holders",
            "registry_leaf_v2", "registry_root_v2", "storage_root_v2",
            "sample_derivation"
        };
        int found = 0;
        for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
            if (strcmp(sec, known[i]) == 0) found = 1;
        if (!found) {
            fprintf(stderr, "KAT: unknown vector section \"%s\" — compare "
                    "it or name it\n", sec);
            KCHECK(0);
        }
    }

    /* tags: each 16-byte value is its name, right-padded with 0x00 (the
     * C tags themselves are checked through every hash below) */
    {
        json_object *t = kj(vec, "tags");
        KCHECK(t && json_object_is_type(t, json_type_object));
        json_object_object_foreach(t, name, val) {
            uint8_t want[16], got[16];
            snprintf(g_kv, sizeof(g_kv), "tags[%s]", name);
            KCHECK(strlen(name) <= 16);
            memset(want, 0, sizeof(want));
            memcpy(want, name, strlen(name));
            KCHECK(json_object_is_type(val, json_type_string) &&
                   hex_to(json_object_get_string(val), got, 16) == 0 &&
                   memcmp(want, got, 16) == 0);
            g_checks++;
        }
    }

    /* empty_roots */
    {
        static const struct { const char *tag; dna_v2_empty_kind_t k; } EM[] = {
            { "NDS.E.STSEG.v1", DNA_V2_EMPTY_STORAGE_SEGS },
            { "NDS.E.STREG.v1", DNA_V2_EMPTY_STORAGE_REG },
            { "NDS.E.STSET.v1", DNA_V2_EMPTY_STORAGE_SETS },
            { "NDS.E.STREP.v1", DNA_V2_EMPTY_STORAGE_REPORTS },
        };
        json_object *er = kj(vec, "empty_roots");
        KCHECK(er && json_object_object_length(er) == 4);
        for (size_t i = 0; i < 4; i++) {
            snprintf(g_kv, sizeof(g_kv), "empty_roots[%s]", EM[i].tag);
            KCHECK(dna_v2_empty_root(EM[i].k, h) == 0);
            KCHECK(kat_eq(h, er, EM[i].tag));
            compared++;
        }
    }

    /* synthetic_hash */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "synthetic_hash");
        json_object *a = kat_arr(vec, "synthetic_hash", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint64_t hh = 0;
            kat_name("synthetic_hash", v, i);
            KCHECK(kat_uint(v, "height", UINT64_MAX, &hh) == 0);
            KCHECK(synth_hash(hh, h) == 0);
            KCHECK(kat_eq(h, v, "hash"));
            compared++;
        }
    }

    /* segment_root — Root(k) over hash[(k−1)P+1 .. kP] */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "segment_root");
        json_object *a = kat_arr(vec, "segment_root", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint64_t k = 0, first = 0, last = 0, plen = 0;
            snprintf(g_kv, sizeof(g_kv), "segment_root[%zu]", i);
            KCHECK(kat_uint(v, "k", UINT64_MAX, &k) == 0 &&
                   kat_uint(v, "first_height", UINT64_MAX, &first) == 0 &&
                   kat_uint(v, "last_height", UINT64_MAX, &last) == 0 &&
                   kat_uint(v, "preimage_len", UINT64_MAX, &plen) == 0);
            snprintf(g_kv, sizeof(g_kv), "segment_root[k=%llu]",
                     (unsigned long long)k);
            KCHECK(k >= 1 && first == (k - 1) * P_LEN + 1 &&
                   last == k * P_LEN);
            KCHECK(plen == 16u + 8u + 4u + P_LEN * 64u);
            for (uint64_t j = 0; j < P_LEN; j++)
                KCHECK(synth_hash(first + j, hashes[j]) == 0);
            KCHECK(kat_eq(hashes[0], v, "first_hash"));
            KCHECK(kat_eq(hashes[P_LEN - 1], v, "last_hash"));
            KCHECK(qgp_sha3_512((const uint8_t *)hashes,
                                (size_t)P_LEN * 64, h) == 0);
            KCHECK(kat_eq(h, v, "hashes_sha3"));
            KCHECK(dna_v2_segment_root(k, (const uint8_t (*)[64])hashes,
                                       h) == 0);
            KCHECK(kat_eq(h, v, "root"));
            compared++;
        }
        /* k == 0 and a k whose last height overflows are refused */
        KCHECK(dna_v2_segment_root(0, (const uint8_t (*)[64])hashes, h) != 0);
        KCHECK(dna_v2_segment_root(UINT64_MAX / P_LEN + 1,
                                   (const uint8_t (*)[64])hashes, h) != 0);
        g_checks += 2;
    }

    /* segment_leaf */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "segment_leaf");
        json_object *a = kat_arr(vec, "segment_leaf", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint64_t k = 0;
            uint8_t r[64];
            snprintf(g_kv, sizeof(g_kv), "segment_leaf[%zu]", i);
            KCHECK(kat_uint(v, "k", UINT64_MAX, &k) == 0 &&
                   kat_hex(v, "root", r, 64) == 0);
            KCHECK(dna_v2_segment_leaf_hash(k, r, h) == 0);
            KCHECK(kat_eq(h, v, "leaf"));
            compared++;
        }
    }

    /* segments_root — each entry's leaf, then the root */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "segments_root");
        json_object *a = kat_arr(vec, "segments_root", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            static uint64_t ks[64];
            static uint8_t rs[64][64];
            size_t m = 0;
            kat_name("segments_root", v, i);
            json_object *es = kat_arr(v, "entries", &m);
            KCHECK(es && m <= 64);
            for (size_t j = 0; j < m; j++) {
                json_object *e = json_object_array_get_idx(es, j);
                KCHECK(kat_uint(e, "k", UINT64_MAX, &ks[j]) == 0 &&
                       kat_hex(e, "root", rs[j], 64) == 0);
                KCHECK(dna_v2_segment_leaf_hash(ks[j], rs[j], h) == 0);
                KCHECK(kat_eq(h, e, "leaf"));
            }
            KCHECK(dna_v2_segments_root(ks, (const uint8_t (*)[64])rs, m,
                                        h) == 0);
            KCHECK(kat_eq(h, v, "segments_root"));
            compared++;
        }
    }

    /* assignment_key */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "assignment_key");
        json_object *a = kat_arr(vec, "assignment_key", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint8_t r[64];
            snprintf(g_kv, sizeof(g_kv), "assignment_key[%zu]", i);
            KCHECK(kat_hex(v, "root", r, 64) == 0);
            KCHECK(dna_v2_segment_assign_key(r, h) == 0);
            KCHECK(kat_eq(h, v, "A"));
            compared++;
        }
    }

    /* holders — node hashes, distances, the eligible count, the ranks */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "holders");
        json_object *a = kat_arr(vec, "holders", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint8_t r[64], A[64];
            size_t m = 0, nr = 0, idx[DNA_V2_STORAGE_HOLDERS], nh = 0;
            uint64_t want_elig = 0;
            kat_name("holders", v, i);
            KCHECK(kat_hex(v, "root", r, 64) == 0);
            KCHECK(dna_v2_segment_assign_key(r, A) == 0);
            KCHECK(kat_eq(A, v, "A"));
            json_object *ms = kat_arr(v, "members", &m);
            KCHECK(ms && m <= DNA_V2_STORAGE_SET_MAX);
            size_t elig = 0;
            for (size_t j = 0; j < m; j++) {
                json_object *mem = json_object_array_get_idx(ms, j);
                uint64_t fs = 0;
                KCHECK(kat_hex(mem, "node_pk", pk, sizeof(pk)) == 0 &&
                       kat_uint(mem, "fail_streak", UINT32_MAX, &fs) == 0);
                KCHECK(qgp_sha3_512(pk, sizeof(pk), fps[j]) == 0);
                KCHECK(kat_eq(fps[j], mem, "node_hash"));
                streaks[j] = (uint32_t)fs;
                if (streaks[j] < DNA_V2_STORAGE_FAIL_LIMIT) elig++;
                if (kj(mem, "distance")) {
                    uint8_t d[64];
                    for (int b = 0; b < 64; b++) d[b] = A[b] ^ fps[j][b];
                    KCHECK(kat_eq(d, mem, "distance"));
                }
            }
            KCHECK(kat_uint(v, "eligible_count", DNA_V2_STORAGE_SET_MAX,
                            &want_elig) == 0 && want_elig == elig);
            KCHECK(dna_v2_segment_holders(A, (const uint8_t (*)[64])fps,
                                          streaks, m, idx, &nh) == 0);
            json_object *rk = kat_arr(v, "holders_by_rank", &nr);
            KCHECK(rk && nr == nh);
            for (size_t j = 0; j < nh; j++) {
                uint8_t want[64];
                json_object *s = json_object_array_get_idx(rk, j);
                KCHECK(json_object_is_type(s, json_type_string) &&
                       hex_to(json_object_get_string(s), want, 64) == 0);
                KCHECK(memcmp(want, fps[idx[j]], 64) == 0);
                g_checks++;
            }
            compared++;
        }
    }

    /* registry_leaf_v2 */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "registry_leaf_v2");
        json_object *a = kat_arr(vec, "registry_leaf_v2", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            kat_name("registry_leaf_v2", v, i);
            KCHECK(kat_row_v2(v, &rows[0]) == 0);
            KCHECK(dna_v2_storage_node_leaf_hash(&rows[0], h) == 0);
            KCHECK(kat_eq(h, v, "leaf"));
            compared++;
        }
    }

    /* registry_root_v2 */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "registry_root_v2");
        json_object *a = kat_arr(vec, "registry_root_v2", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            size_t m = 0;
            snprintf(g_kv, sizeof(g_kv), "registry_root_v2[%zu]", i);
            json_object *rs = kat_arr(v, "rows_sorted", &m);
            KCHECK(rs && m <= DNA_V2_STORAGE_SET_MAX);
            for (size_t j = 0; j < m; j++) {
                json_object *r = json_object_array_get_idx(rs, j);
                KCHECK(kat_row_v2(r, &rows[j]) == 0);
                KCHECK(dna_v2_storage_node_leaf_hash(&rows[j], h) == 0);
                KCHECK(kat_eq(h, r, "leaf"));
            }
            KCHECK(dna_v2_storage_registry_root(rows, m, h) == 0);
            KCHECK(kat_eq(h, v, "registry_root"));
            compared++;
        }
    }

    /* storage_root_v2 */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "storage_root_v2");
        json_object *a = kat_arr(vec, "storage_root_v2", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint8_t rr[64], sr[64], pr[64], gr[64];
            kat_name("storage_root_v2", v, i);
            KCHECK(kat_hex(v, "registry_root", rr, 64) == 0 &&
                   kat_hex(v, "sets_root", sr, 64) == 0 &&
                   kat_hex(v, "reports_root", pr, 64) == 0 &&
                   kat_hex(v, "segments_root", gr, 64) == 0);
            KCHECK(dna_v2_storage_root(rr, sr, pr, gr, h) == 0);
            KCHECK(kat_eq(h, v, "storage_root"));
            compared++;
        }
    }

    /* sample_derivation — x_i, the two reads, every block / part index */
    {
        size_t n = 0;
        snprintf(g_kv, sizeof(g_kv), "%s", "sample_derivation");
        json_object *a = kat_arr(vec, "sample_derivation", &n);
        KCHECK(a && n > 0);
        for (size_t i = 0; i < n; i++) {
            json_object *v = json_object_array_get_idx(a, i);
            uint8_t nonce[32], tfp[64];
            size_t m = 0;
            kat_name("sample_derivation", v, i);
            KCHECK(kat_hex(v, "nonce", nonce, 32) == 0 &&
                   kat_hex(v, "target_fp", tfp, 64) == 0);
            json_object *ss = kat_arr(v, "samples", &m);
            KCHECK(ss && m == DNA_V2_STORAGE_SAMPLES);
            for (size_t j = 0; j < m; j++) {
                json_object *s = json_object_array_get_idx(ss, j);
                uint64_t si = 0, u64v = 0, u32v = 0;
                KCHECK(kat_uint(s, "i", UINT32_MAX, &si) == 0 && si == j);
                KCHECK(dna_v2_storage_sample_x(nonce, tfp, (uint32_t)si,
                                               h) == 0);
                KCHECK(kat_eq(h, s, "x"));
                KCHECK(kat_uint(s, "u64_x_0_8", UINT64_MAX, &u64v) == 0 &&
                       kat_uint(s, "u32_x_8_12", UINT32_MAX, &u32v) == 0);
                {
                    uint64_t b = 0;
                    uint32_t p = 0;
                    /* modulus 2^64−1 / 2^32−1 never reduces below the
                     * value except at the maximum; the reads themselves
                     * are checked through B = UINT64_MAX */
                    KCHECK(dna_v2_storage_sample_index(h, UINT64_MAX,
                                                       UINT32_MAX, &b,
                                                       &p) == 0);
                    KCHECK(b == u64v % UINT64_MAX && p == u32v % UINT32_MAX);
                    g_checks++;
                }
                json_object *bi = kj(s, "block_index");
                json_object *pi = kj(s, "part_index");
                KCHECK(bi && json_object_is_type(bi, json_type_object) &&
                       pi && json_object_is_type(pi, json_type_object));
                json_object_object_foreach(bi, bk, bv) {
                    uint64_t want = 0, got = 0;
                    const uint64_t B = strtoull(bk, NULL, 10);
                    KCHECK(B > 0 && kat_u64_of(bv, &want) == 0);
                    KCHECK(dna_v2_storage_sample_index(h, B, 1, &got,
                                                       NULL) == 0);
                    KCHECK(got == want);
                    g_checks++;
                }
                json_object_object_foreach(pi, pk2, pv) {
                    uint64_t T = strtoull(pk2, NULL, 10), want = 0;
                    uint32_t got = 0;
                    KCHECK(T > 0 && T <= UINT32_MAX &&
                           kat_u64_of(pv, &want) == 0);
                    KCHECK(dna_v2_storage_sample_index(h, 1, (uint32_t)T,
                                                       NULL, &got) == 0);
                    KCHECK((uint64_t)got == want);
                    g_checks++;
                }
                /* B == 0 and parts_total == 0 are refused */
                KCHECK(dna_v2_storage_sample_index(h, 0, 1, NULL, NULL)
                       != 0 &&
                       dna_v2_storage_sample_index(h, 1, 0, NULL, NULL)
                       != 0);
            }
            compared++;
        }
    }

    printf("archive reward oracle: %d vectors compared, %d values equal\n",
           compared, g_checks - checks0);
out:
    json_object_put(root);
    free(hashes);
    return rc;
}

#else  /* !ARCHIVE_REWARD_KAT_PATH */

static int t_kat(void) {
    fprintf(stderr, "test_storage_b2 was built without json-c "
            "(ARCHIVE_REWARD_KAT_PATH unset): the archive reward oracle "
            "vectors were NOT compared\n");
    return 1;
}

#endif /* ARCHIVE_REWARD_KAT_PATH */

/* ══ shared fixture plumbing ═══════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint8_t          chain32[DNA_CHAIN_ID_LEN];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int fx_dir(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_storage_b2_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x5B, sizeof(fx->chain16));
    return 0;
}

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* ══ B. publication over synthetic v2_blocks ═══════════════════════════ */

static int pub_seed_blocks(nodus_witness_t *w, uint64_t last) {
    if (v2x_sql(w->db, "BEGIN") != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_blocks (global_height, block_id, prev_block_id, "
            "epoch, tx_root, domain_updates_root, domains_root, global_root, "
            "vset_hash, tx_count) VALUES (?1, ?2, zeroblob(64), 0, "
            "zeroblob(64), zeroblob(64), zeroblob(64), zeroblob(64), "
            "zeroblob(64), 0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ok = 0;
    for (uint64_t h = 1; h <= last && ok == 0; h++) {
        uint8_t id[64];
        if (synth_hash(h, id) != 0) { ok = -1; break; }
        sqlite3_reset(st);
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        sqlite3_bind_blob(st, 2, id, 64, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) ok = -1;
    }
    sqlite3_finalize(st);
    if (v2x_sql(w->db, ok == 0 ? "COMMIT" : "ROLLBACK") != 0) return -1;
    return ok;
}

static int pub_open(fixture_t *fx, const char *tag, uint64_t last) {
    if (fx_dir(fx, tag) != 0) return -1;
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    return pub_seed_blocks(fx->w, last);
}

static int t_publication(void) {
    fixture_t A, B;
    const uint64_t last = 3 * P_LEN + 10;
    uint8_t r[64], want[64];
    uint64_t n = 0;
    CHECK(pub_open(&A, "pa", last) == 0 && pub_open(&B, "pb", last) == 0,
          "two prepared databases with synthetic v2_blocks 1..3P+10");

    /* Root(k) from the table == the oracle's */
    for (uint64_t k = 1; k <= 3; k++) {
        CHECK(nodus_witness_storage_segment_root_compute(A.w, k, r) == 0,
              "Root(k) computes from v2_blocks");
        CHECK(hex_to(ORACLE_ROOT[k - 1], want, 64) == 0 &&
              memcmp(r, want, 64) == 0,
              "Root(k) from v2_blocks == the oracle's Root(k)");
    }
    CHECK(nodus_witness_storage_segment_root_compute(A.w, 4, r) != 0,
          "a segment past the last v2_blocks row is a FAULT");
    CHECK(nodus_witness_storage_segment_root_compute(A.w, 0, r) != 0,
          "k = 0 refused");

    /* the publication step: immature never, due always, once */
    uint32_t np = 0;
    const uint64_t b1 = 2 * P_LEN + 2 * E_LEN;
    CHECK(nodus_witness_storage_publish_due(A.w, b1, &np) == 0 && np == 2,
          "at 2P + 2E exactly k = 1, 2 are published (backfill)");
    CHECK(nodus_witness_storage_publish_due(B.w, b1, &np) == 0 && np == 2,
          "the twin publishes the same");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_segments", &n) == 0
          && n == 2, "two rows");
    CHECK(nodus_witness_storage_publish_due(A.w, 3 * P_LEN + E_LEN, &np) == 0
          && np == 0, "k = 3 is immature at 3P + E: not published");
    CHECK(nodus_witness_storage_publish_due(A.w, 3 * P_LEN + 2 * E_LEN,
                                            &np) == 0 && np == 1,
          "k = 3 published at 3P + 2E");
    CHECK(nodus_witness_storage_publish_due(B.w, 3 * P_LEN + 2 * E_LEN,
                                            &np) == 0 && np == 1,
          "the twin too");
    {
        uint8_t sa[64], sb[64];
        uint64_t ks[3] = { 1, 2, 3 };
        uint8_t rs[3][64];
        for (int i = 0; i < 3; i++)
            CHECK(hex_to(ORACLE_ROOT[i], rs[i], 64) == 0, "oracle root");
        CHECK(nodus_witness_storage_segments_root(A.w, sa) == 0 &&
              nodus_witness_storage_segments_root(B.w, sb) == 0 &&
              memcmp(sa, sb, 64) == 0, "twin segments_root identical");
        CHECK(dna_v2_segments_root(ks, (const uint8_t (*)[64])rs, 3, want)
              == 0 && memcmp(sa, want, 64) == 0,
              "segments_root == the list of the oracle's roots");
        CHECK(q_u64(A.w, "SELECT published_height FROM v2_storage_segments "
                    "WHERE k = 1", &n) == 0 && n == b1,
              "k = 1 carries the backfill boundary as published_height");
    }

    /* faults: a malformed and a missing row (no partial publication) */
    CHECK(v2x_sql(A.w->db, "UPDATE v2_blocks SET block_id = X'00' WHERE "
                  "global_height = 5") == 0, "corrupt one block_id");
    CHECK(nodus_witness_storage_segment_root_compute(A.w, 1, r) != 0,
          "a non-64-byte block_id is a FAULT");
    {
        /* extend B to 4P + 10 except height 60000 (inside segment 4) */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(B.w->db, "INSERT INTO v2_blocks "
              "(global_height, block_id, prev_block_id, epoch, tx_root, "
              "domain_updates_root, domains_root, global_root, vset_hash, "
              "tx_count) VALUES (?1, ?2, zeroblob(64), 0, zeroblob(64), "
              "zeroblob(64), zeroblob(64), zeroblob(64), zeroblob(64), 0)",
              -1, &st, NULL) == SQLITE_OK, "prepare");
        CHECK(v2x_sql(B.w->db, "BEGIN") == 0, "begin");
        for (uint64_t h = last + 1; h <= 4 * P_LEN + 10; h++) {
            uint8_t id[64];
            if (h == 60000) continue;
            CHECK(synth_hash(h, id) == 0, "hash");
            sqlite3_reset(st);
            sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
            sqlite3_bind_blob(st, 2, id, 64, SQLITE_TRANSIENT);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "insert");
        }
        sqlite3_finalize(st);
        CHECK(v2x_sql(B.w->db, "COMMIT") == 0, "commit");
    }
    CHECK(nodus_witness_storage_publish_due(B.w, 4 * P_LEN + 2 * E_LEN, &np)
          != 0, "a missing v2_blocks row is a FAULT at publication");
    CHECK(q_u64(B.w, "SELECT COUNT(*) FROM v2_storage_segments", &n) == 0 &&
          n == 3, "no partial row written for segment 4");

    /* pure helper: position → height */
    {
        uint64_t ks[2] = { 2, 5 }, hh = 0;
        CHECK(nodus_storage_eligible_height(ks, 2, 0, &hh) == 0 &&
              hh == P_LEN + 1, "position 0 = first height of k = 2");
        CHECK(nodus_storage_eligible_height(ks, 2, P_LEN, &hh) == 0 &&
              hh == 4 * P_LEN + 1, "position P = first height of k = 5");
        CHECK(nodus_storage_eligible_height(ks, 2, 2 * P_LEN, &hh) != 0,
              "past the last block refused");
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ keys ══════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} sk_key_t;

/* V0..V6 the validators (V0 is also the dual-role storage node D);
 * KA, KB, KC, KX the storage-only nodes. */
enum { V0, V1, V2, V3, V4, V5, V6, KA, KB, KC, KX, N_KEYS };
#define N_VAL 7
#define KD    V0
static sk_key_t g_k[N_KEYS];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x21 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* ══ C. hook level: STORAGE_REPORT ═════════════════════════════════════ */

typedef struct {
    uint8_t  call[REP_FIXED + DNA_V2_STORAGE_BITMAP_MAX + 2];
    uint8_t  auth[2][AUTH_LEN];
    uint8_t  bytes[32768];
    size_t   len;
    dna_env_view_t view;
} rh_env_t;

static uint32_t rep_call(uint8_t *dst, uint64_t h, uint32_t seat,
                         const uint8_t s[64], const uint8_t *bm,
                         uint16_t bl) {
    put64(dst, h);
    put32(dst + 8, seat);
    memcpy(dst + 12, s, 64);
    dst[76] = (uint8_t)(bl >> 8);
    dst[77] = (uint8_t)bl;
    if (bl) memcpy(dst + REP_FIXED, bm, bl);
    return REP_FIXED + bl;
}

/* A decoded report envelope: leg 0 SYSTEM REPORT over `call_len` bytes
 * of e->call, fee `fee`, auth kind `kind`; with legs == 2 a second CORE
 * SYSFUND leg (legs are strictly ascending by domain on the wire, so the
 * second leg of a 2-leg envelope cannot be SYSTEM again). */
static int rh_build(rh_env_t *e, uint32_t call_len, uint64_t fee,
                    uint8_t kind, int legs) {
    static uint8_t fund[66];
    memset(fund, 0xA5, sizeof(fund));
    fund[0] = 1;
    fund[65] = 0;
    dna_env_leg_in_t lg[2];
    memset(lg, 0, sizeof(lg));
    lg[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    lg[0].hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    lg[0].hdr.ruleset_version = 8;
    lg[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    lg[0].hdr.auth_kind = kind;
    lg[0].hdr.call_len = call_len;
    lg[0].hdr.auth_len = AUTH_LEN;
    lg[0].hdr.res_max_effects = 8;
    lg[0].hdr.res_max_effect_bytes = 16384;
    lg[0].call_data = e->call;
    lg[0].auth_data = e->auth[0];
    lg[1].hdr.domain_id = DNA_DOMAIN_CORE;
    lg[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    lg[1].hdr.ruleset_version = 6;
    lg[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    lg[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    lg[1].hdr.call_len = sizeof(fund);
    lg[1].hdr.auth_len = AUTH_LEN;
    lg[1].hdr.res_max_effects = 40;
    lg[1].hdr.res_max_effect_bytes = 16384;
    lg[1].call_data = fund;
    lg[1].auth_data = e->auth[1];
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = fee;
    in.res_max_total_units = 400000;
    in.leg_count = (uint16_t)legs;
    in.legs = lg;
    if (dna_env_encode(&in, e->bytes, sizeof(e->bytes), &e->len) != 0)
        return -1;
    return dna_env_decode(e->bytes, e->len, &e->view);
}

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_chain[DNA_CHAIN_ID_LEN], g_intent[64], g_dig[64];
static nodus_rt_read_res_t g_reads[3];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

static void rh_ctx(int signer, int two, uint64_t height) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = two ? 2 : 1;
    memcpy(g_av.signer_fp[0], g_k[signer].fp, 64);
    if (two) memcpy(g_av.signer_fp[1], g_k[KX].fp, 64);
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_intent, 0x6E, sizeof(g_intent));
    g_ctx.chain_id = g_chain;
    g_ctx.global_height = height;
    g_ctx.epoch = height / E_LEN;
    g_ctx.wire_id = g_intent;
    g_ctx.intent_id = g_intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

/* reads: [0] set (S, count) present unless count == UINT32_MAX, [1] the
 * seat's pubkey (key `seat_key`, absent when < 0), [2] an existing report
 * when `dup` */
static void rh_reads(const uint8_t s[64], uint32_t count, int seat_key,
                     int dup) {
    memset(g_reads, 0, sizeof(g_reads));
    if (count != UINT32_MAX) {
        g_reads[0].present = 1;
        g_reads[0].value_len = 68;
        memcpy(g_reads[0].value, s, 64);
        put32(g_reads[0].value + 64, count);
    }
    if (seat_key >= 0) {
        g_reads[1].present = 1;
        g_reads[1].value_len = (uint32_t)PK_LEN;
        memcpy(g_reads[1].value, g_k[seat_key].pk, PK_LEN);
    }
    if (dup) {
        g_reads[2].present = 1;
        g_reads[2].value_len = 67;
    }
}

static int rh_exec(const nodus_domain_runtime_t *rt, const rh_env_t *e,
                   dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, &e->view, 0, &g_ctx, g_reads, 3,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int t_report_hooks(void) {
    const nodus_domain_runtime_t *s1 =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s2 =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    CHECK(s1 && s2 && s3, "compiled generations");
    static rh_env_t e;
    dna_effect_view_t ev;
    const uint64_t H = 2 * E_LEN;
    const uint64_t in_lo = H + E_LEN + 1, in_hi = H + E_LEN + E_LEN / 2;
    uint8_t S[64], bm[2] = { 0x15, 0x01 };   /* count 9: bits 0,2,4,8 */
    memset(S, 0x3C, sizeof(S));
    const uint32_t count = 9, seat = 4;
    nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
    uint16_t nr = 0;

    /* read plan */
    uint32_t cl = rep_call(e.call, H, seat, S, bm, 2);
    CHECK(rh_build(&e, cl, 0, 1, 1) == 0, "report envelope");
    rh_ctx(V3, 0, in_lo);
    CHECK(nodus_rt_system_read_plan(s3, &e.view, 0, &g_ctx, rq,
                                    NODUS_RT_MAX_READS, &nr) == 0 && nr == 3,
          "REPORT plans three reads");
    {
        uint8_t k8[8], k12[12];
        put64(k8, H);
        memcpy(k12, k8, 8);
        put32(k12 + 8, seat);
        CHECK(rq[0].op_id == OP_STSET && rq[0].key_len == 8 &&
              memcmp(rq[0].key, k8, 8) == 0, "read 0 = storage_set(H)");
        CHECK(rq[1].op_id == OP_SNAPSEAT && rq[1].key_len == 12 &&
              memcmp(rq[1].key, k12, 12) == 0, "read 1 = snapshot seat");
        CHECK(rq[2].op_id == OP_STREP && rq[2].key_len == 12 &&
              memcmp(rq[2].key, k12, 12) == 0, "read 2 = the report row");
    }
    CHECK(nodus_rt_system_read_plan(s2, &e.view, 0, &g_ctx, rq,
                                    NODUS_RT_MAX_READS, &nr) == -1 &&
          nodus_rt_system_read_plan(NULL, &e.view, 0, &g_ctx, rq,
                                    NODUS_RT_MAX_READS, &nr) == -1,
          "generation 2 / NULL plan nothing");

    /* happy path at both window edges */
    rh_reads(S, count, V3, 0);
    memset(&ev, 0, sizeof(ev));
    CHECK(rh_exec(s3, &e, &ev) == 0, "a report at H+E+1 applies");
    CHECK(ev.effect_count == 1 && ev.eff[0].op_id == OP_STREP &&
          ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
          ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT &&
          ev.eff[0].key_len == 12 && ev.eff[0].value_len == 66 + 2,
          "one CREATE / ABSENT, value S ‖ len ‖ bitmap");
    CHECK(memcmp(ev.buf + ev.val_off[0], S, 64) == 0 &&
          ev.buf[ev.val_off[0] + 64] == 0 && ev.buf[ev.val_off[0] + 65] == 2
          && memcmp(ev.buf + ev.val_off[0] + 66, bm, 2) == 0,
          "the committed value");
    rh_ctx(V3, 0, in_hi);
    CHECK(rh_exec(s3, &e, NULL) == 0, "a report at H+E+E/2 applies");

    /* refusals — each a VERDICT */
    rh_ctx(V3, 0, H + E_LEN);
    CHECK(rh_exec(s3, &e, NULL) == -1, "at H+E (epoch not over) refused");
    rh_ctx(V3, 0, in_hi + 1);
    CHECK(rh_exec(s3, &e, NULL) == -1, "at H+E+E/2+1 refused");
    rh_ctx(V3, 0, in_lo);
    CHECK(rh_exec(s1, &e, NULL) == -1 && rh_exec(s2, &e, NULL) == -1 &&
          rh_exec(NULL, &e, NULL) == -1, "generations 1 / 2 / NULL refuse");
    rh_ctx(V4, 0, in_lo);
    CHECK(rh_exec(s3, &e, NULL) == -1, "signer is not the seat");
    rh_ctx(V3, 1, in_lo);
    CHECK(rh_exec(s3, &e, NULL) == -1, "two signers refused");
    rh_ctx(V3, 0, in_lo);
    rh_reads(S, UINT32_MAX, V3, 0);
    CHECK(rh_exec(s3, &e, NULL) == -1, "no frozen set at H refused");
    {
        uint8_t S2[64];
        memcpy(S2, S, 64);
        S2[0] ^= 1;
        rh_reads(S2, count, V3, 0);
        CHECK(rh_exec(s3, &e, NULL) == -1, "S(H) differs refused");
    }
    rh_reads(S, 17, V3, 0);
    CHECK(rh_exec(s3, &e, NULL) == -1, "bitmap_len != ceil(count/8)");
    rh_reads(S, count, -1, 0);
    CHECK(rh_exec(s3, &e, NULL) == -1, "seat absent from snapshot(H)");
    rh_reads(S, count, V3, 1);
    CHECK(rh_exec(s3, &e, NULL) == -1, "an existing (H, seat) refused");
    rh_reads(S, count, V3, 0);
    {
        uint8_t hb[2] = { 0x15, 0x03 };      /* bit 9 >= count 9 */
        cl = rep_call(e.call, H, seat, S, hb, 2);
        CHECK(rh_build(&e, cl, 0, 1, 1) == 0, "env");
        CHECK(rh_exec(s3, &e, NULL) == -1, "an unused high bit refused");
    }
    cl = rep_call(e.call, H, seat, S, bm, 2);
    CHECK(rh_build(&e, cl, FEE, 1, 1) == 0, "env fee");
    CHECK(rh_exec(s3, &e, NULL) == -1, "fee != 0 refused");
    CHECK(rh_build(&e, cl, 0, NODUS_RT_AUTHKIND_DSA87_CC_V1, 1) == 0, "env");
    CHECK(rh_exec(s3, &e, NULL) == -1, "auth kind 2 refused");
    CHECK(rh_build(&e, cl, 0, 1, 2) == 0, "env 2 legs");
    CHECK(rh_exec(s3, &e, NULL) == -1, "two legs refused");
    CHECK(rh_build(&e, cl - 1, 0, 1, 1) == 0, "env short");
    CHECK(rh_exec(s3, &e, NULL) == -1, "a call one byte short refused");
    e.call[cl] = 0;
    CHECK(rh_build(&e, cl + 1, 0, 1, 1) == 0, "env long");
    CHECK(rh_exec(s3, &e, NULL) == -1, "a call one byte long refused");
    {
        uint8_t big[33];
        memset(big, 0, sizeof(big));
        cl = rep_call(e.call, H, seat, S, big, 33);
        CHECK(rh_build(&e, cl, 0, 1, 1) == 0, "env 33");
        CHECK(rh_exec(s3, &e, NULL) == -1, "bitmap_len 33 refused");
    }
    cl = rep_call(e.call, H + 1, seat, S, bm, 2);
    CHECK(rh_build(&e, cl, 0, 1, 1) == 0, "env");
    rh_ctx(V3, 0, in_lo + 1);
    CHECK(rh_exec(s3, &e, NULL) == -1, "H not a boundary refused");
    return 0;
}

/* ══ D. engine twins ═══════════════════════════════════════════════════ */

typedef struct { int key; uint8_t seed; uint64_t amount; } coin_def_t;
enum { CA, CB, CC, CD, CX, CBX, N_COINS };
static const coin_def_t COINS[N_COINS] = {
    [CA]  = { KA, 0xA1, BOND + FEE },        /* A registers at 4        */
    [CB]  = { KB, 0xB1, BOND + FEE },        /* B registers at 4        */
    [CC]  = { KC, 0xC1, BOND + FEE },        /* C registers at 4        */
    [CD]  = { KD, 0xD1, BOND + FEE },        /* D (validator 0) at 4    */
    [CX]  = { KX, 0xE1, BOND + FEE },        /* X registers at E + 5    */
    [CBX] = { KB, 0xB2, FEE },               /* B exits at 4E + 3       */
};
static uint8_t g_nul[N_COINS][64];

static int coin_nul(int c, uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[COINS[c].key].hex, 128);
    memset(pre + 128, COINS[c].seed, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w, int c) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_nul[c], 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_k[COINS[c].key].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)COINS[c].amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

#define H9   2u
#define H14  4u

/* the pre-seeded segment root of k (HOW IT CAN LIE) */
static int seg_root(uint64_t k, uint8_t out[64]) {
    uint8_t pre[24];
    memcpy(pre, "test_storage_b2/seg", 16);
    put64(pre + 16, k);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int fx_open(fixture_t *fx, const char *tag) {
    if (fx_dir(fx, tag) != 0) return -1;
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, D2, H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_STORAGE, DS, H14, 13) != 0)
        return -1;
    /* the committee: seven genesis seats with REAL keys */
    uint64_t bonds = 0;
    for (int i = 0; i < N_VAL; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_k[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake = DNAC_SELF_STAKE_AMOUNT;
        v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memcpy(v.unstake_destination_fp, g_k[i].hex, 129);
        if (nodus_validator_insert(w, &v) != 0) return -1;
        bonds += DNAC_SELF_STAKE_AMOUNT;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", N_VAL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    /* treasury: pool 1 funds the storage reward, the other eight 0 */
    for (uint32_t p = 1; p <= 9; p++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO v2_treasury (pool_id, "
                 "balance) VALUES (%u, %llu)", (unsigned)p,
                 (unsigned long long)(p == 1 ? POOL1 : 0ULL));
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    uint64_t coins = 0;
    for (int c = 0; c < N_COINS; c++) {
        if (seed_coin(w, c) != 0) return -1;
        coins += COINS[c].amount;
    }
    {
        const uint64_t supply = coins + bonds + POOL1;
        char sql[320];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence) VALUES (1, %llu, 0, 0, "
                 "%llu, zeroblob(64), 0)",
                 (unsigned long long)supply, (unsigned long long)supply);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    /* the pre-seeded segment list k = 1..N_SEGS */
    for (uint64_t k = 1; k <= N_SEGS; k++) {
        uint8_t r[64];
        sqlite3_stmt *st = NULL;
        if (seg_root(k, r) != 0 ||
            sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_segments (k, "
                               "root, published_height) VALUES (?1, ?2, 1)",
                               -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
        sqlite3_bind_blob(st, 2, r, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, fx->chain32) != 0)
        return -1;
    return 0;
}

/* every block from height 2 carries all seven COMMIT votes */
static uint8_t g_vaddr[N_VAL][32];
static int32_t g_vflag[N_VAL];

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = N_VAL;
    }
}

static int sys_head_recomputes(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    uint8_t committed[64], now[64];
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = 0", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(committed, (const uint8_t *)sqlite3_column_blob(st, 0) + 4,
               64);
        ok = 0;
    }
    sqlite3_finalize(st);
    const nodus_domain_runtime_t *rt = NULL;
    if (ok != 0 ||
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rt) != 0 ||
        !rt || !rt->state_root || rt->state_root(rt, w, now) != 0)
        return -1;
    return memcmp(committed, now, 64) == 0 ? 0 : -1;
}

static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    nodus_v2_tx_result_t ra[8], rb[8];
    nodus_v2_block_t ba, bb;
    if (n > 8) return -1;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, envs, n);
    mk_block(&bb, h, envs, n);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 8;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 8;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (ra[i].code != rb[i].code) return -1;
        if (codes) codes[i] = ra[i].code;
    }
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0)
        return -1;
    if (sys_head_recomputes(a->w) != 0 || sys_head_recomputes(b->w) != 0)
        return -1;
    return 0;
}

static int run_idle(fixture_t *a, fixture_t *b, uint64_t *h,
                    uint64_t target) {
    while (*h < target) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66;
}

/* A 2-leg storage envelope (REGISTER / EXIT), really signed by the
 * node's key on both legs (the coin's owner is the node). */
static int st_env(nodus_witness_t *w, uint64_t height, uint32_t op,
                  const uint8_t *sys_call, uint32_t sys_len, int c,
                  int signer, uint8_t **out, size_t *out_len) {
    static uint8_t fund[66];
    static uint8_t auth[2][AUTH_LEN];
    dna_domain_manifest_t sys, core;
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul[c]);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = op;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = sys_len;
    legs[0].hdr.auth_len = AUTH_LEN;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = sys_call;
    legs[0].auth_data = auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH_LEN;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = auth[1];
    memset(auth, 0, sizeof(auth));

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        int bad = 0;
        for (int L = 0; L < 2 && !bad; L++) {
            size_t sl = 0;
            auth[L][0] = 1;
            memcpy(auth[L] + 1, g_k[signer].pk, PK_LEN);
            if (qgp_dsa87_sign(auth[L] + 1 + PK_LEN, &sl,
                               pf->auth_digest[L], 64, g_k[signer].sk) != 0)
                bad = 1;
        }
        if (bad) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* A 1-leg STORAGE_REPORT envelope, fee 0, signed by validator `signer`. */
static int rep_env(nodus_witness_t *w, uint64_t height, const uint8_t *call,
                   uint32_t call_len, int signer, uint8_t **out,
                   size_t *out_len) {
    static uint8_t auth[AUTH_LEN];
    dna_domain_manifest_t sys;
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0)
        return -1;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    leg.hdr.ruleset_version = sys.ruleset_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = call_len;
    leg.hdr.auth_len = AUTH_LEN;
    leg.hdr.res_max_effects = 8;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data = call;
    leg.auth_data = auth;
    memset(auth, 0, sizeof(auth));
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = 0;
    in.res_max_total_units = 400000;
    in.leg_count = 1;
    in.legs = &leg;
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);
    size_t len = 0, used = 0;
    if (dna_env_encoded_size(&leg, 1, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, &lctx, 1,
                              pf) != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        auth[0] = 1;
        memcpy(auth + 1, g_k[signer].pk, PK_LEN);
        if (qgp_dsa87_sign(auth + 1 + PK_LEN, &sl, pf->auth_digest[0], 64,
                           g_k[signer].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* observations */
static int accrual_of(nodus_witness_t *w, const uint8_t fp[64],
                      uint64_t *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? 0 : -1;
}

static int pool1_of(nodus_witness_t *w, uint64_t *out) {
    return q_u64(w, "SELECT balance FROM v2_treasury WHERE pool_id = 1",
                 out);
}

static int streak_of(nodus_witness_t *w, const uint8_t fp[64],
                     uint32_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT fail_streak FROM v2_storage_nodes "
                           "WHERE node_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        *out = (uint32_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

static int core_invariant(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rt) != 0 || !rt
        || !rt->invariant)
        return -1;
    return rt->invariant(rt, w);
}

/* the storage-node keys in node_fp order are looked up through this */
static int key_of_fp(const uint8_t fp[64]) {
    for (int i = 0; i < N_KEYS; i++)
        if (memcmp(g_k[i].fp, fp, 64) == 0) return i;
    return -1;
}

/* the test's OWN eligibility: for each member of set(H), the eligible
 * block count = P × |{k : m ∈ holders(k, set(H−E))}| over the N_SEGS
 * pre-seeded segments (all published at 1 <= H−E), computed with the
 * pure layer only */
static int expect_weights(const nodus_storage_set_t *cur,
                          const nodus_storage_set_t *prev,
                          uint64_t w_out[DNA_V2_STORAGE_SET_MAX]) {
    memset(w_out, 0, DNA_V2_STORAGE_SET_MAX * sizeof(uint64_t));
    if (!prev || prev->count == 0) return 0;
    for (uint64_t k = 1; k <= N_SEGS; k++) {
        uint8_t r[64], A[64];
        size_t idx[3], nh = 0;
        if (seg_root(k, r) != 0 || dna_v2_segment_assign_key(r, A) != 0)
            return -1;
        if (dna_v2_segment_holders(A, (const uint8_t (*)[64])prev->fps,
                                   prev->fail_streak, prev->count, idx,
                                   &nh) != 0)
            return -1;
        for (size_t j = 0; j < nh; j++)
            for (uint32_t m = 0; m < cur->count; m++)
                if (memcmp(cur->fps[m], prev->fps[idx[j]], 64) == 0)
                    w_out[m] += P_LEN;
    }
    return 0;
}

static nodus_storage_set_t g_set_a, g_set_b;   /* scratch (17 KB each) */

/* Build every seat's report for epoch H at height `h`: bit i of seat s
 * is set iff ok_from(s, member i). Returns the n envelopes. */
typedef int (*bit_fn)(int seat_key, int member_key);

static int reports_for(fixture_t *fx, uint64_t h, uint64_t H,
                       const int *seats, size_t n_seats, bit_fn bit,
                       uint8_t **envs, size_t *lens) {
    nodus_storage_set_t *s = &g_set_a;
    if (nodus_witness_storage_set_get(fx->w, H, s) != 0) return -1;
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(fx->w, H, &snap, NULL,
                                                   NULL) != 0 || !snap)
        return -1;
    int ret = 0;
    for (size_t r = 0; r < n_seats && ret == 0; r++) {
        int vk = seats[r];
        uint32_t seat = UINT32_MAX;
        for (uint32_t x = 0; x < snap->active_count; x++)
            if (memcmp(snap->entries[x].pubkey, g_k[vk].pk, PK_LEN) == 0)
                seat = x;
        if (seat == UINT32_MAX) { ret = -1; break; }
        uint8_t bm[32], call[REP_FIXED + 32];
        memset(bm, 0, sizeof(bm));
        const uint16_t bl = (uint16_t)((s->count + 7u) / 8u);
        for (uint32_t i = 0; i < s->count; i++)
            if (bit(vk, key_of_fp(s->fps[i])))
                bm[i / 8u] |= (uint8_t)(1u << (i % 8u));
        uint32_t cl = rep_call(call, H, seat, s->set_hash, bm, bl);
        if (rep_env(fx->w, h, call, cl, vk, &envs[r], &lens[r]) != 0)
            ret = -1;
    }
    dna_vset_free(&snap);
    return ret;
}

static int g_M = -1, g_N = -1;    /* the failing / the always-OK member */

/* 4E (H = 2E): only N has every other bit; D's own report sets D's bit
 * only (F2: ignored) */
static int bit_one_ok(int seat_key, int member) {
    if (member == g_N) return 1;
    if (member == KD && seat_key == KD) return 1;
    return 0;
}
/* 5E, 6E: everyone except M */
static int bit_all_but_m(int seat_key, int member) {
    (void)seat_key;
    return member != g_M;
}
/* 7E: everyone */
static int bit_all(int seat_key, int member) {
    (void)seat_key; (void)member;
    return 1;
}

/* Settlement check for epoch H at boundary B on fixture A: weights from
 * the test's own holders, OK flags `okf`, pool-1 debit == Σ shares, each
 * non-validator member's accrual delta == its share, fail_streak per the
 * rule. `acc0` / `pool0` / `streak0` are the readings before B. */
typedef struct {
    uint64_t acc[N_KEYS];
    uint32_t streak[N_KEYS];
    uint64_t pool1;
} snap_t;

static int take(nodus_witness_t *w, snap_t *s) {
    memset(s, 0, sizeof(*s));
    for (int k = 0; k < N_KEYS; k++) {
        if (accrual_of(w, g_k[k].fp, &s->acc[k]) != 0) return -1;
        if (streak_of(w, g_k[k].fp, &s->streak[k]) != 0) s->streak[k] = 0;
    }
    return pool1_of(w, &s->pool1);
}

/* The expected weights of epoch (H, H+E], computed BEFORE the settling
 * boundary B = H + 2E: that boundary prunes set(H−E) (sets below B−2E),
 * so they cannot be recomputed after it. */
typedef struct {
    nodus_storage_set_t cur;                      /* set(H)             */
    uint64_t wt[DNA_V2_STORAGE_SET_MAX];          /* per member of cur  */
} expect_t;
static expect_t g_ex;

static int prep_expect(nodus_witness_t *w, uint64_t H, expect_t *ex) {
    memset(ex, 0, sizeof(*ex));
    if (nodus_witness_storage_set_get(w, H, &ex->cur) != 0) return -1;
    int prc = nodus_witness_storage_set_get(w, H - E_LEN, &g_set_b);
    if (prc < 0) return -1;
    return expect_weights(&ex->cur, prc == 0 ? &g_set_b : NULL, ex->wt);
}

static int check_settle(const expect_t *ex, const snap_t *b0,
                        const snap_t *b1, int (*okf)(int member),
                        uint64_t *W_out) {
    const nodus_storage_set_t *cur = &ex->cur;
    const uint64_t *wt = ex->wt;
    uint64_t W = 0, total = 0;
    for (uint32_t i = 0; i < cur->count; i++) W += wt[i];
    *W_out = W;
    const uint64_t budget = b0->pool1 >> 16;
    for (uint32_t i = 0; i < cur->count; i++) {
        int k = key_of_fp(cur->fps[i]);
        if (k < 0) return -1;
        const int ok = okf(k);
        uint64_t share = 0;
        if (W > 0 && ok && wt[i] > 0) {
            unsigned __int128 num = (unsigned __int128)budget * wt[i];
            share = (uint64_t)(num / W);
        }
        total += share;
        if (k >= N_VAL && b1->acc[k] - b0->acc[k] != share) {
            fprintf(stderr, "member key %d: accrual delta %llu, expected "
                    "%llu\n", k, (unsigned long long)(b1->acc[k] -
                    b0->acc[k]), (unsigned long long)share);
            return -1;
        }
        /* the rule restated (bytes item 4 + K5 + K5a) — a SETTLED epoch
         * only: weight and OK → 0 whatever the old value; else at 3 or
         * more +1, 14 → 0; else weight (NOT OK) +1; else unchanged */
        uint32_t want = b0->streak[k];
        if (wt[i] > 0 && ok) want = 0u;
        else if (want >= 3u) want = (want + 1u >= 15u) ? 0u : want + 1u;
        else if (wt[i] > 0)  want = want + 1u;
        if (b1->streak[k] != want) {
            fprintf(stderr, "member key %d: fail_streak %u, expected %u\n",
                    k, (unsigned)b1->streak[k], (unsigned)want);
            return -1;
        }
    }
    if (total > budget) return -1;
    if (b0->pool1 - b1->pool1 != total) {
        fprintf(stderr, "pool 1 debited %llu, Σ shares %llu\n",
                (unsigned long long)(b0->pool1 - b1->pool1),
                (unsigned long long)total);
        return -1;
    }
    return 0;
}

static int ok_one(int m)      { return m == g_N; }
static int ok_all_but_m(int m){ return m != g_M; }
static int ok_all(int m)      { (void)m; return 1; }

static int submit(fixture_t *A, fixture_t *B, uint64_t h, uint8_t **envs,
                  size_t *lens, size_t n, uint32_t *codes) {
    nodus_v2_envelope_t v[8];
    if (n > 8) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = envs[i];
        v[i].env_len = lens[i];
    }
    int rc = apply_both(A, B, h, v, n, codes);
    for (size_t i = 0; i < n; i++) { free(envs[i]); envs[i] = NULL; }
    return rc;
}

/* D0. The fail_streak rule (bytes item 4 + K5 + K5a), pure: the full skip /
 * return arc the engine run does not reach (15 needs 12 more settled
 * epochs), each value fed to holders over a hand-built frozen set. */
static nodus_storage_set_t g_set_p;

static int m_holds(uint64_t k, uint32_t streak_m, int *holds) {
    uint8_t r[64], hf[DNA_V2_STORAGE_HOLDERS][64];
    size_t nh = 0;
    g_set_p.fail_streak[0] = streak_m;
    if (seg_root(k, r) != 0 ||
        nodus_witness_storage_holders(&g_set_p, r, hf, &nh) != 0)
        return -1;
    *holds = 0;
    for (size_t j = 0; j < nh; j++)
        if (memcmp(hf[j], g_set_p.fps[0], 64) == 0) *holds = 1;
    return 0;
}

static int t_streak_rule(void) {
    /* below 3: the old rule */
    CHECK(nodus_storage_fail_streak_next(0, 0, 0) == 0, "0, no weight: 0");
    CHECK(nodus_storage_fail_streak_next(2, 0, 0) == 2, "2, no weight: 2");
    CHECK(nodus_storage_fail_streak_next(2, 0, 1) == 2, "2, no weight, OK: 2");
    CHECK(nodus_storage_fail_streak_next(0, 1, 0) == 1, "0, NOT OK: 1");
    CHECK(nodus_storage_fail_streak_next(1, 1, 1) == 0, "1, OK: 0");
    CHECK(nodus_storage_fail_streak_next(2, 1, 0) == 3, "2, NOT OK: 3");
    /* at 3 or more: weight and OK → 0 (K5a); otherwise +1; 14 → 0 */
    for (uint32_t s = 3; s <= 14; s++)
        CHECK(nodus_storage_fail_streak_next(s, 1, 1) == 0,
              "K5a: ≥ 3 with weight and OK → 0");
    for (uint32_t s = 3; s < 14; s++)
        for (int e = 0; e < 2; e++)
            for (int ok = 0; ok < 2; ok++)
                if (!(e && ok))
                    CHECK(nodus_storage_fail_streak_next(s, e, ok) == s + 1,
                          "skipped: +1 unless weight and OK");
    for (int e = 0; e < 2; e++)
        for (int ok = 0; ok < 2; ok++)
            CHECK(nodus_storage_fail_streak_next(14, e, ok) == 0,
                  "14 → 0 (the stored value never reaches 15)");

    /* a frozen set of four members; member 0 is M */
    memset(&g_set_p, 0, sizeof(g_set_p));
    g_set_p.count = 4;
    for (uint32_t i = 0; i < 4; i++) {
        uint8_t pre[24];
        memcpy(pre, "test_storage_b2/mem", 16);
        put64(pre + 16, i);
        CHECK(qgp_sha3_512(pre, sizeof(pre), g_set_p.fps[i]) == 0, "fp");
    }
    uint64_t km = 0;
    for (uint64_t k = 1; k <= N_SEGS && km == 0; k++) {
        int holds = 0;
        CHECK(m_holds(k, 0, &holds) == 0, "holders");
        if (holds) km = k;
    }
    CHECK(km != 0, "M holds a segment when its streak is 0");

    /* the arc: 3 failures → skipped; 12 settled epochs while skipped
     * (half of them with no eligible block; OK only in epochs with none,
     * since weight and OK together resets — K5a) → 0, placed again; 3 new
     * failures → skipped again; one OK epoch with weight → 0 (K5a) */
    uint32_t s = 0;
    int holds = 0;
    for (int f = 0; f < 3; f++) {
        CHECK(m_holds(km, s, &holds) == 0 && holds, "placed below 3");
        s = nodus_storage_fail_streak_next(s, 1, 0);
    }
    CHECK(s == 3, "three failures: 3");
    for (int ep = 1; ep <= 12; ep++) {
        CHECK(m_holds(km, s, &holds) == 0 && !holds, "skipped at 3..14");
        s = nodus_storage_fail_streak_next(s, ep % 2,
                                           ep % 2 == 0 && ep % 3 == 0);
        if (ep < 12)
            CHECK(s == 3u + (uint32_t)ep, "skipped: one per settled epoch");
    }
    CHECK(s == 0, "the 12th skipped epoch resets to 0");
    CHECK(m_holds(km, s, &holds) == 0 && holds, "placed again at 0");
    for (int f = 0; f < 3; f++)
        s = nodus_storage_fail_streak_next(s, 1, 0);
    CHECK(s == 3, "three new failures: 3");
    CHECK(m_holds(km, s, &holds) == 0 && !holds, "skipped again");
    s = nodus_storage_fail_streak_next(s, 1, 1);
    CHECK(s == 0, "K5a: an OK epoch with weight at 3 resets to 0");
    CHECK(m_holds(km, s, &holds) == 0 && holds, "placed again at once");
    return 0;
}

static int t_engine(void) {
    fixture_t A, B;
    uint64_t h = 0, n = 0;
    uint32_t codes[8];
    uint8_t *e[8] = { NULL };
    size_t l[8] = { 0 };
    static uint8_t call[4][STREG_LEN];
    const int all_seats[N_VAL] = { V0, V1, V2, V3, V4, V5, V6 };

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    for (int i = 0; i < N_VAL; i++) {
        memcpy(g_vaddr[i], g_k[i].fp, 32);
        g_vflag[i] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    for (int c = 0; c < N_COINS; c++)
        CHECK(coin_nul(c, g_nul[c]) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a") == 0 && fx_open(&B, "b") == 0,
          "twin seeded chains (real committee, pool 1, segments 1..8)");

    CHECK(run_idle(&A, &B, &h, H14 - 1) == 0, "blocks 1..3 (both edges)");

    /* block 4: A, B, C, D register */
    {
        const int who[4] = { KA, KB, KC, KD };
        const int coin[4] = { CA, CB, CC, CD };
        for (int i = 0; i < 4; i++) {
            memcpy(call[i], g_k[who[i]].pk, PK_LEN);
            put64(call[i] + PK_LEN, BOND);
            memcpy(call[i] + PK_LEN + 8, g_k[who[i]].fp, 64);
            CHECK(st_env(A.w, H14, DNA_SYSRULE_STORAGE_REGISTER, call[i],
                         STREG_LEN, coin[i], who[i], &e[i], &l[i]) == 0,
                  "registration envelope");
        }
        CHECK(submit(&A, &B, H14, e, l, 4, codes) == 0, "block 4");
        for (int i = 0; i < 4; i++)
            CHECK(codes[i] == NODUS_V2_TX_OK, "registration applies");
        h = H14;
    }
    CHECK(core_invariant(A.w) == 0, "invariant after registrations");

    /* boundary E: the first storage boundary */
    CHECK(run_idle(&A, &B, &h, E_LEN) == 0, "to E");
    CHECK(nodus_witness_storage_set_get(A.w, E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 4, "set(E) = {A, B, C, D}");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_segments", &n) == 0 &&
          n == N_SEGS, "no publication at E (k = 9 not due)");

    /* E + 5: X registers */
    CHECK(run_idle(&A, &B, &h, E_LEN + 4) == 0, "to E+4");
    memcpy(call[0], g_k[KX].pk, PK_LEN);
    put64(call[0] + PK_LEN, BOND);
    memcpy(call[0] + PK_LEN + 8, g_k[KX].fp, 64);
    CHECK(st_env(A.w, E_LEN + 5, DNA_SYSRULE_STORAGE_REGISTER, call[0],
                 STREG_LEN, CX, KX, &e[0], &l[0]) == 0, "X envelope");
    CHECK(submit(&A, &B, E_LEN + 5, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK, "X registers at E+5");
    h = E_LEN + 5;

    /* boundary 2E */
    CHECK(run_idle(&A, &B, &h, 2 * E_LEN) == 0, "to 2E");
    CHECK(nodus_witness_storage_set_get(A.w, 2 * E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 5, "set(2E) = {A, B, C, D, X}");

    /* choose M and N: of A, C, the first with weight in H = 2E, 3E, 4E
     * (set(3E), set(4E) have the same members as set(2E) — X joined
     * before 2E, B leaves after 4E) */
    {
        uint64_t w2[DNA_V2_STORAGE_SET_MAX], w3[DNA_V2_STORAGE_SET_MAX];
        CHECK(nodus_witness_storage_set_get(A.w, E_LEN, &g_set_b) == 0,
              "set(E)");
        CHECK(expect_weights(&g_set_a, &g_set_b, w2) == 0, "w(2E)");
        CHECK(expect_weights(&g_set_a, &g_set_a, w3) == 0, "w(3E)");
        const int cand[2] = { KA, KC };
        for (int c = 0; c < 2 && g_M < 0; c++) {
            for (uint32_t i = 0; i < g_set_a.count; i++)
                if (key_of_fp(g_set_a.fps[i]) == cand[c] && w2[i] > 0 &&
                    w3[i] > 0)
                    g_M = cand[c];
        }
        CHECK(g_M >= 0, "a member of {A, C} holds a segment in every "
              "settled epoch (re-seed the fixture keys otherwise)");
        g_N = (g_M == KA) ? KC : KA;
    }

    /* 2E + 1: three seats report for H = E (F1 not met) */
    {
        const int three[3] = { V1, V2, V3 };
        CHECK(reports_for(&A, 2 * E_LEN + 1, E_LEN, three, 3, bit_all, e,
                          l) == 0, "three reports for H = E");
        CHECK(submit(&A, &B, 2 * E_LEN + 1, e, l, 3, codes) == 0, "2E+1");
        for (int i = 0; i < 3; i++)
            CHECK(codes[i] == NODUS_V2_TX_OK, "report applies");
        h = 2 * E_LEN + 1;
        CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_reports", &n) == 0
              && n == 3, "three committed reports");
    }

    /* boundary 3E: settle H = E — nothing eligible (W == 0) */
    snap_t s0, s1;
    CHECK(run_idle(&A, &B, &h, 3 * E_LEN - 1) == 0, "to 3E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, E_LEN, &g_ex) == 0,
          "before 3E");
    CHECK(run_idle(&A, &B, &h, 3 * E_LEN) == 0, "boundary 3E");
    CHECK(take(A.w, &s1) == 0, "after 3E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_all, &W) == 0 && W == 0,
              "H = E: W == 0 — no credit, pool and streaks unchanged");
        CHECK(s0.pool1 == s1.pool1, "pool 1 untouched");
        CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_reports", &n) == 0
              && n == 0, "the reports for H = E are pruned");
    }

    /* 3E: a report for H = 2E is refused (the epoch is not over) */
    /* (the window opens at 3E + 1) — built at 3E + 1's height but the
     * check is the exec's; covered in section C. 3E + 1: all seven. */
    CHECK(reports_for(&A, 3 * E_LEN + 1, 2 * E_LEN, all_seats, N_VAL,
                      bit_one_ok, e, l) == 0, "seven reports for H = 2E");
    CHECK(submit(&A, &B, 3 * E_LEN + 1, e, l, N_VAL, codes) == 0, "3E+1");
    for (int i = 0; i < N_VAL; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK, "report applies");
    h = 3 * E_LEN + 1;
    {
        const int one[1] = { V2 };
        CHECK(reports_for(&A, 3 * E_LEN + 2, 2 * E_LEN, one, 1, bit_all, e,
                          l) == 0, "a duplicate (H, seat)");
        CHECK(submit(&A, &B, 3 * E_LEN + 2, e, l, 1, codes) == 0 &&
              codes[0] != NODUS_V2_TX_OK, "the duplicate is refused");
        h = 3 * E_LEN + 2;
        CHECK(run_idle(&A, &B, &h, 3 * E_LEN + E_LEN / 2) == 0,
              "to the window's end");
        CHECK(reports_for(&A, h + 1, 2 * E_LEN, one, 1, bit_all, e, l) == 0,
              "a late report");
        CHECK(submit(&A, &B, h + 1, e, l, 1, codes) == 0 &&
              codes[0] != NODUS_V2_TX_OK, "a report past the window refused");
        h++;
    }

    /* boundary 4E: settle H = 2E ("one OK") */
    CHECK(run_idle(&A, &B, &h, 4 * E_LEN - 1) == 0, "to 4E-1");
    /* the HANDOFF, at 4E − 1 (sets E, 2E, 3E all still retained): the
     * engine's eligible lists equal the test's own */
    for (uint64_t H = 2 * E_LEN; H <= 3 * E_LEN; H += E_LEN) {
        CHECK(nodus_witness_storage_set_get(A.w, H, &g_set_a) == 0 &&
              nodus_witness_storage_set_get(A.w, H - E_LEN, &g_set_b) == 0,
              "sets");
        uint64_t wt[DNA_V2_STORAGE_SET_MAX];
        CHECK(expect_weights(&g_set_a, &g_set_b, wt) == 0, "weights");
        for (uint32_t i = 0; i < g_set_a.count; i++) {
            uint64_t ks[N_SEGS];
            size_t nk = 0;
            uint8_t fp[64];
            memcpy(fp, g_set_a.fps[i], 64);
            CHECK(nodus_witness_storage_eligible_segments(A.w, H, fp, ks,
                                                          N_SEGS, &nk) == 0,
                  "eligible segments");
            CHECK((uint64_t)nk * P_LEN == wt[i],
                  "engine eligibility == holders(k, set(H−E)) ∩ set(H)");
        }
    }
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 2 * E_LEN, &g_ex) == 0,
          "before 4E");
    CHECK(run_idle(&A, &B, &h, 4 * E_LEN) == 0, "boundary 4E");
    CHECK(take(A.w, &s1) == 0, "after 4E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_one, &W) == 0 && W > 0,
              "H = 2E: weighted pay to N alone, remainder stays, "
              "fail_streak +1 for every failing member with weight");
        CHECK(s1.streak[KX] == 0, "X (new at 2E) has weight 0: unchanged");
        CHECK(s1.streak[g_M] == 1, "M failed once");
    }

    /* 4E + 1: all report for H = 3E (all OK but M); 4E + 3: B exits */
    CHECK(reports_for(&A, 4 * E_LEN + 1, 3 * E_LEN, all_seats, N_VAL,
                      bit_all_but_m, e, l) == 0, "reports for H = 3E");
    CHECK(submit(&A, &B, 4 * E_LEN + 1, e, l, N_VAL, codes) == 0, "4E+1");
    h = 4 * E_LEN + 1;
    CHECK(run_idle(&A, &B, &h, 4 * E_LEN + 2) == 0, "to 4E+2");
    CHECK(st_env(A.w, 4 * E_LEN + 3, DNA_SYSRULE_STORAGE_EXIT, g_k[KB].pk,
                 (uint32_t)PK_LEN, CBX, KB, &e[0], &l[0]) == 0, "B exit");
    CHECK(submit(&A, &B, 4 * E_LEN + 3, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK, "B exits at 4E+3");
    h = 4 * E_LEN + 3;

    /* boundary 5E: settle H = 3E; B released */
    uint64_t bonds0 = 0, bonds1 = 0, utxo0 = 0, utxo1 = 0;
    CHECK(run_idle(&A, &B, &h, 5 * E_LEN - 1) == 0, "to 5E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 3 * E_LEN, &g_ex) == 0,
          "before 5E");
    CHECK(nodus_witness_storage_bond_total(A.w, &bonds0) == 0 &&
          q_u64(A.w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set",
                &utxo0) == 0, "buckets before 5E");
    CHECK(run_idle(&A, &B, &h, 5 * E_LEN) == 0, "boundary 5E");
    CHECK(take(A.w, &s1) == 0, "after 5E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_all_but_m, &W) == 0 && W > 0,
              "H = 3E: all OK but M");
        CHECK(s1.streak[g_M] == 2, "M failed twice");
    }
    {
        uint8_t id[64], nul[64];
        CHECK(dna_v2_storage_exit_id(A.chain32, 5 * E_LEN, g_k[KB].fp, id)
              == 0 && dna_v2_storage_exit_nullifier(id, nul) == 0, "exit id");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db, "SELECT owner, amount, tx_hash, "
              "output_index, block_height, unlock_block FROM utxo_set WHERE "
              "nullifier = ?1", -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        int found = sqlite3_step(st) == SQLITE_ROW;
        int good = found &&
            sqlite3_column_bytes(st, 0) == 128 &&
            memcmp(sqlite3_column_text(st, 0), g_k[KB].hex, 128) == 0 &&
            (uint64_t)sqlite3_column_int64(st, 1) == BOND &&
            sqlite3_column_bytes(st, 2) == 64 &&
            memcmp(sqlite3_column_blob(st, 2), id, 64) == 0 &&
            sqlite3_column_int64(st, 3) == 201 &&
            (uint64_t)sqlite3_column_int64(st, 4) == 5 * E_LEN &&
            (uint64_t)sqlite3_column_int64(st, 5) ==
                5 * E_LEN + (uint64_t)DNAC_STORAGE_EXIT_LOCK_EPOCHS * E_LEN;
        sqlite3_finalize(st);
        CHECK(good, "B's bond is ONE locked UTXO: identity, owner, amount, "
              "index 201, unlock 5E + 12E");
        CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_nodes WHERE "
                    "status = 3", &n) == 0 && n == 1, "B RELEASED");
        CHECK(nodus_witness_storage_bond_total(A.w, &bonds1) == 0 &&
              q_u64(A.w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set",
                    &utxo1) == 0, "buckets after 5E");
        CHECK(bonds1 == bonds0 - BOND && utxo1 == utxo0 + BOND,
              "the bond moved storage bonds -> utxo");
        CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
              "the CORE invariant holds on both twins");
        CHECK(nodus_witness_storage_set_get(A.w, 5 * E_LEN, &g_set_a) == 0
              && g_set_a.count == 4, "set(5E) excludes B");
    }

    /* 5E + 1: reports for H = 4E (all OK but M) */
    CHECK(reports_for(&A, 5 * E_LEN + 1, 4 * E_LEN, all_seats, N_VAL,
                      bit_all_but_m, e, l) == 0, "reports for H = 4E");
    CHECK(submit(&A, &B, 5 * E_LEN + 1, e, l, N_VAL, codes) == 0, "5E+1");
    h = 5 * E_LEN + 1;
    CHECK(run_idle(&A, &B, &h, 6 * E_LEN - 1) == 0, "to 6E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 4 * E_LEN, &g_ex) == 0,
          "before 6E");
    CHECK(run_idle(&A, &B, &h, 6 * E_LEN) == 0, "boundary 6E");
    CHECK(take(A.w, &s1) == 0, "after 6E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_all_but_m, &W) == 0 && W > 0,
              "H = 4E: all OK but M");
        CHECK(s1.streak[g_M] == 3, "M failed three settled epochs");
        CHECK(nodus_witness_storage_set_get(A.w, 6 * E_LEN, &g_set_a) == 0,
              "set(6E)");
        int seen = 0;
        for (uint32_t i = 0; i < g_set_a.count; i++)
            if (key_of_fp(g_set_a.fps[i]) == g_M) {
                seen = 1;
                CHECK(g_set_a.fail_streak[i] == 3,
                      "set(6E) freezes M's fail_streak 3");
            }
        CHECK(seen, "M stays in the set (registered, bonded)");
        for (uint64_t k = 1; k <= N_SEGS; k++) {
            uint8_t r[64], hf[3][64];
            size_t nh = 0;
            CHECK(seg_root(k, r) == 0 &&
                  nodus_witness_storage_holders(&g_set_a, r, hf, &nh) == 0,
                  "holders over set(6E)");
            for (size_t j = 0; j < nh; j++)
                CHECK(key_of_fp(hf[j]) != g_M,
                      "M (fail_streak 3) is skipped for placement");
        }
    }

    /* 6E + 1: reports for H = 5E (all OK but M) */
    CHECK(reports_for(&A, 6 * E_LEN + 1, 5 * E_LEN, all_seats, N_VAL,
                      bit_all_but_m, e, l) == 0, "reports for H = 5E");
    CHECK(submit(&A, &B, 6 * E_LEN + 1, e, l, N_VAL, codes) == 0, "6E+1");
    h = 6 * E_LEN + 1;
    CHECK(run_idle(&A, &B, &h, 7 * E_LEN - 1) == 0, "to 7E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 5 * E_LEN, &g_ex) == 0,
          "before 7E");
    CHECK(run_idle(&A, &B, &h, 7 * E_LEN) == 0, "boundary 7E");
    CHECK(take(A.w, &s1) == 0, "after 7E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_all_but_m, &W) == 0 && W > 0,
              "H = 5E: all OK but M");
        int mw = 0;
        for (uint32_t i = 0; i < g_ex.cur.count; i++)
            if (key_of_fp(g_ex.cur.fps[i]) == g_M && g_ex.wt[i] > 0) mw = 1;
        CHECK(mw, "M has weight in H = 5E (eligibility from set(4E), "
              "where M was frozen at 1)");
        CHECK(s1.streak[g_M] == 4, "K5: M at 3, with weight and NOT OK, "
              "adds one");
    }

    /* 7E + 1: reports for H = 6E ("all OK", M too); M's weight comes from
     * set(5E), where M was frozen at 2 (below 3, so placed) */
    CHECK(reports_for(&A, 7 * E_LEN + 1, 6 * E_LEN, all_seats, N_VAL,
                      bit_all, e, l) == 0, "reports for H = 6E");
    CHECK(submit(&A, &B, 7 * E_LEN + 1, e, l, N_VAL, codes) == 0, "7E+1");
    h = 7 * E_LEN + 1;
    CHECK(run_idle(&A, &B, &h, 8 * E_LEN - 1) == 0, "to 8E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 6 * E_LEN, &g_ex) == 0,
          "before 8E");
    CHECK(s0.streak[g_M] == 4, "M at 4 before 8E");
    {
        int mw = 0;
        for (uint32_t i = 0; i < g_ex.cur.count; i++)
            if (key_of_fp(g_ex.cur.fps[i]) == g_M && g_ex.wt[i] > 0) mw = 1;
        CHECK(mw, "M has weight in H = 6E (eligibility from set(5E), "
              "where M was frozen at 2)");
    }
    CHECK(run_idle(&A, &B, &h, 8 * E_LEN) == 0, "boundary 8E");
    CHECK(take(A.w, &s1) == 0, "after 8E");
    {
        uint64_t W = 0;
        CHECK(check_settle(&g_ex, &s0, &s1, ok_all, &W) == 0 && W > 0,
              "H = 6E: all OK");
        CHECK(s1.streak[g_M] == 0, "K5a: M at 4, with weight and OK, "
              "resets to 0");
    }

    /* boundary 9E: no report for H = 7E — F1 not met, nothing moves. M,
     * frozen at 3 in set(6E), has no eligible block in (7E, 8E] */
    CHECK(run_idle(&A, &B, &h, 9 * E_LEN - 1) == 0, "to 9E-1");
    CHECK(take(A.w, &s0) == 0 && prep_expect(A.w, 7 * E_LEN, &g_ex) == 0,
          "before 9E");
    {
        int in_cur = 0;
        for (uint32_t i = 0; i < g_ex.cur.count; i++)
            if (key_of_fp(g_ex.cur.fps[i]) == g_M) {
                in_cur = 1;
                CHECK(g_ex.wt[i] == 0, "M (skipped in set(6E)) has weight 0 "
                      "in H = 7E");
            }
        CHECK(in_cur, "M is a member of set(7E)");
    }
    CHECK(run_idle(&A, &B, &h, 9 * E_LEN) == 0, "boundary 9E");
    CHECK(take(A.w, &s1) == 0, "after 9E");
    for (int k = 0; k < N_KEYS; k++)
        CHECK(s1.streak[k] == s0.streak[k],
              "F1 not met: every fail_streak unchanged (M's at 0 included)");
    CHECK(s1.pool1 == s0.pool1, "F1 not met: pool 1 untouched");
    CHECK(s1.streak[g_M] == 0, "M stays at 0");
    CHECK(core_invariant(A.w) == 0, "the invariant holds at the end");

    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "archive_kat",          t_kat },
        { "segment_publication",  t_publication },
        { "report_hooks",         t_report_hooks },
        { "fail_streak_rule",     t_streak_rule },
        { "engine_twins",         t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0) {
        fprintf(stderr, "test_storage_b2: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-22s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_storage_b2: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
