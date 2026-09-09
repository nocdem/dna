/**
 * Nodus — Tendermint T3 wave 1: `nodus.vote.v1` preimage tests (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the bytes a validator signs are EXACTLY the 229-byte layout of T2
 * wire design §4.1, field by field, and that the two pure helpers built on
 * it behave as the reference's rules require. If this file failed, one of
 * these would be false:
 *   · every field sits at the published offset and occupies the published
 *     width (checked against a byte array this file builds itself, from the
 *     tm_vote.h offset constants, WITHOUT calling the builder);
 *   · a PREVOTE and a PRECOMMIT over otherwise identical fields differ in
 *     exactly one byte, offset 16 (T2 §4.1 KAT);
 *   · a nil PRECOMMIT zeroes offsets 17..80 and nothing else;
 *   · two votes 1 ms apart differ ONLY inside offsets 125..132, so the
 *     signer's "timestamp-only" branch (privval/file.go:335-343) can be
 *     recognised, and a change anywhere else is classified as conflicting;
 *   · own-vote stamping is max(now, ref + 1) when a reference exists and
 *     `now` otherwise — arithmetic only, no clock;
 *   · a type byte outside {0x01, 0x02} is refused, so ProposalType (0x20)
 *     can never enter a vote preimage (D-12).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no RNG. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The SHA3-512 values below are a SELF-CONSISTENT FREEZE, NOT AN
 *     EXTERNAL ORACLE FOR THE DESIGN. They were produced with python3
 *     hashlib.sha3_512 over the byte string this file also builds by hand,
 *     so they pin (a) that our SHA3-512 agrees with an independent FIPS-202
 *     implementation and (b) that the layout has not silently drifted since
 *     they were frozen. There is NO published vector for `nodus.vote.v1` —
 *     these digests are evidence of stability, never evidence that the
 *     layout matches CometBFT. Only reading T2 §4.1 against the pinned
 *     reference can establish that.
 *  2. The KAT's voter_id (32 × 0xDD) is this file's own choice: T2 §4.1
 *     fixes chain_id, vset_hash, height, round, block_id and timestamp but
 *     not the voter. A different voter changes every digest here.
 *  3. Nothing here signs anything. A green run says the PREIMAGE is right;
 *     it says nothing about ML-DSA-87 signing or verification — that is
 *     test_tm_commit.c's real-key suite.
 *  4. `dna_tm_vote_time` is tested as arithmetic. That the HOST feeds it
 *     the right `now_ms` and the right reference (locked value, else
 *     proposal) is wave-2 behaviour and is NOT covered here.
 *
 * @file test_tm_vote.c
 */

#include "dnac/tm_vote.h"
#include "dnac/ledger_ids.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* Local big-endian writers: the expected bytes must be built WITHOUT the
 * library's helpers, or the test would only prove the code agrees with
 * itself. */
static void t_be32(uint32_t v, uint8_t *o) {
    o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16);
    o[2] = (uint8_t)(v >> 8);  o[3] = (uint8_t)v;
}
static void t_be64(uint64_t v, uint8_t *o) {
    for (int i = 0; i < 8; i++) o[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* ── T2 §4.1 KAT inputs ─────────────────────────────────────────────────
 * chain_id 32×0xAA, vset_hash 64×0xBB, height 7, round 2,
 * block_id 64×0xCC, timestamp 1 800 000 000 000 ms.
 * voter_id is NOT fixed by §4.1; this file picks 32×0xDD (see "how it can
 * lie", item 2). */
#define KAT_HEIGHT 7ULL
#define KAT_ROUND  2U
#define KAT_TS     1800000000000ULL

/* First 48 bytes: tag ‖ type ‖ the first 31 bytes of block_id. */
static const char *KAT_PREVOTE_PRE48 =
    "6e6f6475732e766f74652e763100000001cccccccccccccc"
    "cccccccccccccccccccccccccccccccccccccccccccccccc";

/* SELF-CONSISTENT FREEZE — see the header, item 1. */
static const char *KAT_HASH_PREVOTE =
    "1f230c8c8052613434fa3842c90a2257e3f273682d0bd72a14cec389fe68b2f9"
    "7da5f5264f25424396ee16e51a5a97387c2a8c20a631502feb1b48f7eb449605";
static const char *KAT_HASH_PRECOMMIT =
    "c839776eefe9fd104873c6bbb7ba8dd27937b96d84cfbd61d2f7a61759d301c5"
    "8b16bb31846a6cbe0a44827894fda0306f3741d7c80bcd50ed84adb5d502c268";
static const char *KAT_HASH_NIL_PRECOMMIT =
    "716d431f29fecee216fd980df2d4901f2b90541447d5697a8e83f9a8f83a7f4f"
    "daa4640d9850f32cb55d43d80b4a17a3e118d36317699e7142725fb6b118f050";

/* ── 1: the layout, offset by offset ────────────────────────────────── */

/**
 * Builds the expected 229 bytes by hand at the published offsets and
 * compares. A field written at the wrong offset, at the wrong width, or in
 * the wrong byte order fails here.
 */
static int test_layout(void) {
    CHECK(DNA_TM_VOTE_PREIMAGE_LEN == 229, "preimage length drifted"); OK();
    CHECK(DNA_TM_VOTE_TAG_LEN == 16, "tag length drifted"); OK();
    CHECK(DNA_TM_BLOCK_ID_LEN == 64, "block_id width drifted"); OK();
    CHECK(DNA_TM_VOTER_ID_LEN == 32, "voter_id width drifted"); OK();

    /* The published offsets, retyped as literals: if tm_vote.h moves one,
     * this test — and every hand-built array below — disagrees. */
    CHECK(DNA_TM_VOTE_OFF_TYPE      == 16,  "off type");      OK();
    CHECK(DNA_TM_VOTE_OFF_BLOCK_ID  == 17,  "off block_id");  OK();
    CHECK(DNA_TM_VOTE_OFF_VOTER_ID  == 81,  "off voter_id");  OK();
    CHECK(DNA_TM_VOTE_OFF_HEIGHT    == 113, "off height");    OK();
    CHECK(DNA_TM_VOTE_OFF_ROUND     == 121, "off round");     OK();
    CHECK(DNA_TM_VOTE_OFF_TIMESTAMP == 125, "off timestamp"); OK();
    CHECK(DNA_TM_VOTE_OFF_CHAIN_ID  == 133, "off chain_id");  OK();
    CHECK(DNA_TM_VOTE_OFF_VSET_HASH == 165, "off vset_hash"); OK();
    CHECK(DNA_TM_VOTE_PREVOTE == 0x01 && DNA_TM_VOTE_PRECOMMIT == 0x02,
          "vote type bytes drifted from signing.md:21-25"); OK();

    uint8_t bid[64], voter[32], chain[32], vsh[64];
    memset(bid, 0xCC, sizeof(bid));
    memset(voter, 0xDD, sizeof(voter));
    memset(chain, 0xAA, sizeof(chain));
    memset(vsh, 0xBB, sizeof(vsh));

    uint8_t want[DNA_TM_VOTE_PREIMAGE_LEN];
    memset(want, 0, sizeof(want));
    memcpy(want, "nodus.vote.v1", 13);        /* offsets 13..15 stay 0x00 */
    want[DNA_TM_VOTE_OFF_TYPE] = DNA_TM_VOTE_PRECOMMIT;
    memcpy(want + DNA_TM_VOTE_OFF_BLOCK_ID, bid, 64);
    memcpy(want + DNA_TM_VOTE_OFF_VOTER_ID, voter, 32);
    t_be64(KAT_HEIGHT, want + DNA_TM_VOTE_OFF_HEIGHT);
    t_be32(KAT_ROUND,  want + DNA_TM_VOTE_OFF_ROUND);
    t_be64(KAT_TS,     want + DNA_TM_VOTE_OFF_TIMESTAMP);
    memcpy(want + DNA_TM_VOTE_OFF_CHAIN_ID, chain, 32);
    memcpy(want + DNA_TM_VOTE_OFF_VSET_HASH, vsh, 64);

    uint8_t got[DNA_TM_VOTE_PREIMAGE_LEN];
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, got) == 0,
          "preimage build");
    CHECK(memcmp(want, got, sizeof(want)) == 0,
          "preimage does not match the hand-built layout"); OK();

    /* The tag's three pad bytes are zero, not garbage. */
    CHECK(got[13] == 0 && got[14] == 0 && got[15] == 0,
          "tag padding not zero"); OK();

    /* Big-endian, not little: height 7 ends in 0x07. */
    CHECK(got[DNA_TM_VOTE_OFF_HEIGHT + 7] == 7 &&
          got[DNA_TM_VOTE_OFF_HEIGHT] == 0, "height not big-endian"); OK();
    CHECK(got[DNA_TM_VOTE_OFF_ROUND + 3] == 2 &&
          got[DNA_TM_VOTE_OFF_ROUND] == 0, "round not big-endian"); OK();
    return 0;
}

/* ── 2: T2 §4.1 KATs ────────────────────────────────────────────────── */

static int test_kat(void) {
    uint8_t bid[64], voter[32], chain[32], vsh[64], nil[64];
    memset(bid, 0xCC, sizeof(bid));
    memset(voter, 0xDD, sizeof(voter));
    memset(chain, 0xAA, sizeof(chain));
    memset(vsh, 0xBB, sizeof(vsh));
    memset(nil, 0x00, sizeof(nil));

    uint8_t pv[229], pc[229], pn[229];
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PREVOTE, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, pv) == 0, "pv");
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, pc) == 0, "pc");
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, nil, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, pn) == 0, "pn");

    /* PREVOTE vs PRECOMMIT: exactly one differing byte, at offset 16. */
    int diffs = 0, where = -1;
    for (int i = 0; i < 229; i++) {
        if (pv[i] != pc[i]) { diffs++; where = i; }
    }
    CHECK(diffs == 1 && where == DNA_TM_VOTE_OFF_TYPE,
          "PREVOTE/PRECOMMIT differ outside offset 16"); OK();

    /* nil PRECOMMIT: offsets 17..80 zero, everything else unchanged. */
    for (int i = DNA_TM_VOTE_OFF_BLOCK_ID;
         i < DNA_TM_VOTE_OFF_BLOCK_ID + DNA_TM_BLOCK_ID_LEN; i++) {
        CHECK(pn[i] == 0, "nil block_id not zero");
    }
    OK();
    CHECK(memcmp(pn, pc, DNA_TM_VOTE_OFF_BLOCK_ID) == 0 &&
          memcmp(pn + DNA_TM_VOTE_OFF_VOTER_ID, pc + DNA_TM_VOTE_OFF_VOTER_ID,
                 229 - DNA_TM_VOTE_OFF_VOTER_ID) == 0,
          "nil vote changed a field other than block_id"); OK();

    char hex[2 * 48 + 1];
    to_hex(pv, 48, hex);
    CHECK(strcmp(hex, KAT_PREVOTE_PRE48) == 0, "PREVOTE prefix KAT"); OK();

    /* Frozen digests — self-consistent, not an external oracle (header). */
    struct { const uint8_t *p; const char *want; const char *name; } t[] = {
        { pv, KAT_HASH_PREVOTE,       "PREVOTE digest KAT"       },
        { pc, KAT_HASH_PRECOMMIT,     "PRECOMMIT digest KAT"     },
        { pn, KAT_HASH_NIL_PRECOMMIT, "nil PRECOMMIT digest KAT" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        uint8_t h[64];
        CHECK(qgp_sha3_512(t[i].p, 229, h) == 0, "sha3");
        char hh[129];
        to_hex(h, 64, hh);
        CHECK(strcmp(hh, t[i].want) == 0, t[i].name); OK();
    }

    /* Every field is bound: change one input, the preimage must change. */
    uint8_t p2[229];
    voter[0] ^= 1;
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == 0 &&
          memcmp(pc, p2, 229) != 0, "voter_id not bound"); OK();
    voter[0] ^= 1;
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT + 1,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == 0 &&
          memcmp(pc, p2, 229) != 0, "height not bound"); OK();
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND + 1, KAT_TS, chain, vsh, p2) == 0 &&
          memcmp(pc, p2, 229) != 0, "round not bound"); OK();
    chain[31] ^= 1;
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == 0 &&
          memcmp(pc, p2, 229) != 0, "chain_id not bound"); OK();
    chain[31] ^= 1;
    vsh[63] ^= 1;
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == 0 &&
          memcmp(pc, p2, 229) != 0, "vset_hash not bound"); OK();
    vsh[63] ^= 1;

    /* Type gate: only the two SignedMsgType values the design allows. */
    CHECK(dna_tm_vote_preimage(0x00, bid, voter, KAT_HEIGHT, KAT_ROUND,
                               KAT_TS, chain, vsh, p2) == -1,
          "type 0 accepted"); OK();
    CHECK(dna_tm_vote_preimage(0x03, bid, voter, KAT_HEIGHT, KAT_ROUND,
                               KAT_TS, chain, vsh, p2) == -1,
          "type 3 accepted"); OK();
    CHECK(dna_tm_vote_preimage(0x20, bid, voter, KAT_HEIGHT, KAT_ROUND,
                               KAT_TS, chain, vsh, p2) == -1,
          "ProposalType 0x20 accepted in a vote preimage"); OK();

    /* NULL guards. */
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, NULL, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == -1,
          "NULL block_id"); OK();
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, NULL, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, p2) == -1,
          "NULL voter_id"); OK();
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, NULL, vsh, p2) == -1,
          "NULL chain_id"); OK();
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, NULL, p2) == -1,
          "NULL vset_hash"); OK();
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, NULL) == -1,
          "NULL out"); OK();
    return 0;
}

/* ── 3: the signer's timestamp-only branch ──────────────────────────── */

static int test_diff_class(void) {
    uint8_t bid[64], voter[32], chain[32], vsh[64];
    memset(bid, 0xCC, sizeof(bid));
    memset(voter, 0xDD, sizeof(voter));
    memset(chain, 0xAA, sizeof(chain));
    memset(vsh, 0xBB, sizeof(vsh));

    uint8_t a[229], b[229], c[229];
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS, chain, vsh, a) == 0, "a");
    /* One millisecond later — the reference's "timestamp-only" case. */
    CHECK(dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid, voter, KAT_HEIGHT,
                               KAT_ROUND, KAT_TS + 1, chain, vsh, b) == 0, "b");
    memcpy(c, a, sizeof(c));

    CHECK(dna_tm_vote_preimage_diff_class(a, c) == 0, "identical != 0"); OK();

    /* The 1 ms difference must land entirely inside 125..132. */
    for (int i = 0; i < 229; i++) {
        if (i >= DNA_TM_VOTE_OFF_TIMESTAMP &&
            i < DNA_TM_VOTE_OFF_TIMESTAMP + 8) continue;
        CHECK(a[i] == b[i], "1 ms apart differs outside the timestamp");
    }
    OK();
    CHECK(dna_tm_vote_preimage_diff_class(a, b) == 1,
          "timestamp-only difference not classified 1"); OK();
    CHECK(dna_tm_vote_preimage_diff_class(b, a) == 1,
          "diff_class not symmetric"); OK();

    /* Every byte of the timestamp window counts as class 1. */
    for (int i = DNA_TM_VOTE_OFF_TIMESTAMP;
         i < DNA_TM_VOTE_OFF_TIMESTAMP + 8; i++) {
        memcpy(c, a, sizeof(c));
        c[i] ^= 0xFF;
        CHECK(dna_tm_vote_preimage_diff_class(a, c) == 1,
              "timestamp byte not classified 1");
    }
    OK();

    /* A change anywhere else is "conflicting data" — class 2. Sweep the
     * boundaries of the window as well as one byte of every other field. */
    const int elsewhere[] = {
        0, 15,                                  /* tag                     */
        DNA_TM_VOTE_OFF_TYPE,                   /* type                    */
        DNA_TM_VOTE_OFF_BLOCK_ID, 80,           /* block_id, last byte     */
        DNA_TM_VOTE_OFF_VOTER_ID, 112,          /* voter_id, last byte     */
        DNA_TM_VOTE_OFF_HEIGHT, 120,            /* height, last byte       */
        DNA_TM_VOTE_OFF_ROUND, 124,             /* round, last byte —
                                                 * one before the window   */
        DNA_TM_VOTE_OFF_CHAIN_ID,               /* one AFTER the window    */
        164, DNA_TM_VOTE_OFF_VSET_HASH, 228,    /* chain_id end, vset_hash */
    };
    for (size_t i = 0; i < sizeof(elsewhere) / sizeof(elsewhere[0]); i++) {
        memcpy(c, a, sizeof(c));
        c[elsewhere[i]] ^= 0xFF;
        CHECK(dna_tm_vote_preimage_diff_class(a, c) == 2,
              "non-timestamp difference not classified 2");
    }
    OK();

    /* A timestamp change TOGETHER with another field is still class 2. */
    memcpy(c, b, sizeof(c));
    c[DNA_TM_VOTE_OFF_ROUND] ^= 0xFF;
    CHECK(dna_tm_vote_preimage_diff_class(a, c) == 2,
          "timestamp + other field not classified 2"); OK();

    CHECK(dna_tm_vote_preimage_diff_class(NULL, b) == -1, "NULL a"); OK();
    CHECK(dna_tm_vote_preimage_diff_class(a, NULL) == -1, "NULL b"); OK();
    return 0;
}

/* ── 4: own-vote stamping ───────────────────────────────────────────── */

static int test_vote_time(void) {
    uint64_t ts = 0;

    /* No reference: the stamp is `now`, untouched. */
    CHECK(dna_tm_vote_time(1000, 0, 0, &ts) == 0 && ts == 1000,
          "have_ref=0 did not return now"); OK();
    CHECK(dna_tm_vote_time(0, 0, 0, &ts) == 0 && ts == 0,
          "now=0 with no reference"); OK();

    /* now < ref + 1 → ref + 1. */
    CHECK(dna_tm_vote_time(500, 1, 1000, &ts) == 0 && ts == 1001,
          "now well below ref did not become ref+1"); OK();
    CHECK(dna_tm_vote_time(1000, 1, 1000, &ts) == 0 && ts == 1001,
          "now == ref did not become ref+1"); OK();

    /* now >= ref + 1 → now. */
    CHECK(dna_tm_vote_time(1001, 1, 1000, &ts) == 0 && ts == 1001,
          "now == ref+1 changed"); OK();
    CHECK(dna_tm_vote_time(9000, 1, 1000, &ts) == 0 && ts == 9000,
          "now above ref+1 changed"); OK();

    /* A reference of 0 is a real reference, not "absent". */
    CHECK(dna_tm_vote_time(0, 1, 0, &ts) == 0 && ts == 1,
          "ref 0 not treated as a reference"); OK();

    /* UINT64_MAX would wrap ref+1 to 0 — refused in BOTH branches. */
    CHECK(dna_tm_vote_time(1000, 1, UINT64_MAX, &ts) == -1,
          "ref UINT64_MAX accepted with have_ref=1"); OK();
    CHECK(dna_tm_vote_time(1000, 0, UINT64_MAX, &ts) == -1,
          "ref UINT64_MAX accepted with have_ref=0"); OK();
    /* One below the wrap point still works. */
    CHECK(dna_tm_vote_time(0, 1, UINT64_MAX - 1, &ts) == 0 &&
          ts == UINT64_MAX, "ref UINT64_MAX-1 rejected"); OK();

    CHECK(dna_tm_vote_time(1000, 1, 500, NULL) == -1, "NULL out"); OK();

    /* Determinism: the same arguments always give the same answer, and no
     * hidden clock can make a second call differ. */
    uint64_t t1 = 0, t2 = 0;
    CHECK(dna_tm_vote_time(1234, 1, 5678, &t1) == 0, "det 1");
    CHECK(dna_tm_vote_time(1234, 1, 5678, &t2) == 0, "det 2");
    CHECK(t1 == t2 && t1 == 5679, "dna_tm_vote_time is not a pure function");
    OK();
    return 0;
}

int main(void) {
    if (test_layout() != 0) return 1;
    if (test_kat() != 0) return 1;
    if (test_diff_class() != 0) return 1;
    if (test_vote_time() != 0) return 1;
    printf("test_tm_vote: %d checks OK\n", g_checks);
    return 0;
}
