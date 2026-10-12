/**
 * Nodus — Ledger V2 S3: validator-set snapshot persistence tests
 * (INACTIVE layer).
 *
 * Runs against a REAL witness chain DB (temp directory, production schema
 * via nodus_witness_create_chain_db), following the fixture pattern of
 * test_committee_election.c. nodus_witness_t is multi-MB, so every
 * instance is calloc'd — never a stack object.
 *
 * Sections:
 *   1. insert / get round-trip, idempotent re-insert, conflicting blob
 *      (-2), missing epoch (1), and both corruption paths (blob mutated,
 *      hash mutated) failing closed.
 *   2. validator_set_root: oracle-pinned KATs at 1, 2 and 3 rows;
 *      insertion-order independence; the empty-table tagged root; and the
 *      proof that root() reads stored HASHES ONLY and never decodes.
 *   3. Close/reopen identity.
 *   4. nodus_witness_vset_build_for_epoch over seeded validators: top-N
 *      by FROZEN stake (balance copy e_start − 2E, tokenomics-v3 P3-1),
 *      self_bond taken from the frozen own row (not
 *      total_stake), voter_id == SHA3-512(pubkey)[0..31], and the
 *      production derivation helper agreeing with that definition;
 *      HF-6 5c: below key generation 4 the core emits zero ids and the
 *      entry fill's ruleset-1 / ruleset-2 behaviour.
 *   5. HF-6 slice 5c — both rulesets through the store (test_both_
 *      rulesets: its own WHAT IT PROVES / HOW IT CAN LIE block).
 *
 * Pinned literals come from an INDEPENDENT python3 hashlib.sha3_512
 * oracle over the layouts in shared/dnac/vset_wire.h and
 * shared/dnac/ledger_roots_v2.h.
 *
 * @file test_vset_persist.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_epoch.h"   /* key generation (5c)     */
#include "witness/nodus_witness_runtime.h"    /* NODUS_RT_GEN_STORAGE    */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_roots_v2.h"

#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── Pinned python3-oracle literals ─────────────────────────────────── */
/* Snapshot hashes of fixtures A (epoch 720, 2 entries) and B (1440, 1).
 * ROOT_1..3 re-derived 2026-09-30 for the NDS. tag rename (decision
 * 2026-09-30-tag-rebrand-nds.md). */
static const char *ROOT_1 =   /* {720:A}                                */
    "c6377f7816a815c4744602913dfa8522be661d4b56c085908d5bc4a70bfad519"
    "ae1409bce2703ebf877b3ee23ecbf4dca71790ef7bcccd7c1ea85ba5ea6cf3f9";
static const char *ROOT_2 =   /* {720:A, 1440:B}                        */
    "85bcb8a42ccc7de85875507f3bd9c60230c3a58d283d3df8c6a4015c197571af"
    "f3389bf868d13e110867a43baedc6806d3d97453e662703f17ca667f2d583a4c";
static const char *ROOT_3 =   /* {720:A, 1440:B, 2160:third}            */
    "37d24842fe59edfaefee115382fae2d190b6c19355b51e3ba7ac7094f602a2d4"
    "f2cc837efad55d7be0081152fbd6d9d547b58bc0e5202e6e874606687827f9a8";
/* SHA3-512("kat-third-snapshot") — an OPAQUE 64-byte hash, deliberately
 * NOT a dna_vset_hash of anything. See the note at insert_raw_row. */
static const char *THIRD_HASH =
    "8a6a78686a9ca1f807eedeb0502d901364a185ba5b260821827600dbc65fea9c"
    "e85b20a851d539c20a48c4bd66c15a1bc62cb7864452e8007923ea6e1f9bb82c";

/* ── Small helpers ──────────────────────────────────────────────────── */

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

static int from_hex(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/** Oracle fixture builder — mirrors test_vset_wire.c exactly. */
static dna_vset_snapshot_t *make_fixture(uint64_t epoch, uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    if (!s) return NULL;
    s->epoch             = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (uint16_t i = 0; i < n; i++) {
        memset(s->entries[i].voter_id, (uint8_t)(i + 1),
               DNA_VSET_VOTER_ID_LEN);
        memset(s->entries[i].pubkey, (uint8_t)(0xA0 + i), DNA_VSET_PUBKEY_LEN);
        s->entries[i].total_stake    = 2000000000000000ULL - i;
        s->entries[i].self_bond      = 1000000000000000ULL;
        s->entries[i].commission_bps = (uint16_t)(500 + i);
    }
    return s;
}

/** Encode a fixture into a freshly malloc'd blob + its hash. */
static int fixture_blob(uint64_t epoch, uint16_t n,
                        uint8_t **blob_out, size_t *len_out,
                        uint8_t hash_out[64]) {
    dna_vset_snapshot_t *s = make_fixture(epoch, n);
    if (!s) return -1;
    size_t need = dna_vset_encoded_len(s);
    uint8_t *b = malloc(need);
    if (!b) { dna_vset_free(&s); return -1; }
    if (dna_vset_encode(s, b, need, NULL) != 0 ||
        dna_vset_hash_bytes(b, need, hash_out) != 0) {
        free(b); dna_vset_free(&s);
        return -1;
    }
    dna_vset_free(&s);
    *blob_out = b;
    *len_out  = need;
    return 0;
}

/* ── Witness fixture ────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id[16];
} fixture_t;

static int fx_open(fixture_t *fx, uint8_t chain_fill) {
    /* nodus_witness_t is multi-MB — ALWAYS heap. */
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_vset_persist_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id, chain_fill, sizeof(fx->chain_id));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id) != 0) {
        rmrf(fx->dir);
        free(fx->w);
        fx->w = NULL;
        return -1;
    }
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/**
 * Write a row with DIRECT SQL, bypassing nodus_witness_vset_insert.
 *
 * WHY THIS EXISTS: _insert re-derives the hash with dna_vset_hash_bytes,
 * which is TAG-PREFIXED (SHA3-512("NDS.VSET.v1" ‖ blob)), so it can only
 * ever store a row whose hash is a real snapshot commitment. The third
 * root-KAT row is deliberately an OPAQUE hash over an undecodable blob —
 * exactly the case that proves nodus_witness_vset_root reads stored
 * HASHES ONLY and never decodes a blob. Such a row cannot be produced
 * through the public insert path, so the test writes it directly.
 */
static int insert_raw_row(nodus_witness_t *w, uint64_t epoch,
                          int active_count,
                          const uint8_t *hash64,
                          const void *blob, int blob_len) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO validator_set_snapshots "
            "(epoch_start, active_count, snapshot_hash, snapshot_blob, "
            " created_at_height) VALUES (?,?,?,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_int  (st, 2, active_count);
    sqlite3_bind_blob (st, 3, hash64, 64, SQLITE_STATIC);
    sqlite3_bind_blob (st, 4, blob, blob_len, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── 1: insert / get / conflict / corruption ────────────────────────── */

static int test_insert_get(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xC1) == 0, "open");

    uint8_t *blobA = NULL, hashA[64];
    size_t lenA = 0;
    CHECK(fixture_blob(720, 2, &blobA, &lenA, hashA) == 0, "fixture A");
    CHECK(lenA == 5362u, "fixture A length"); OK();

    /* Missing epoch reads as 1 (absent), not an error. */
    dna_vset_snapshot_t *got = NULL;
    CHECK(nodus_witness_vset_get(fx.w, 720, &got, NULL) == 1,
          "absent epoch did not read as 1"); OK();
    CHECK(got == NULL, "absent read wrote an output"); OK();

    /* An empty table roots to the tagged empty value. */
    {
        uint8_t r[64], expect[64];
        CHECK(nodus_witness_vset_root(fx.w, r) == 0, "empty root");
        CHECK(dna_v2_empty_root(DNA_V2_EMPTY_VSET, expect) == 0, "empty tag");
        CHECK(memcmp(r, expect, 64) == 0,
              "empty table != tagged empty root"); OK();
    }

    /* Insert, then read back and compare field by field. */
    CHECK(nodus_witness_vset_insert(fx.w, 720, blobA, lenA, hashA, 900) == 0,
          "insert"); OK();
    uint8_t got_hash[64];
    CHECK(nodus_witness_vset_get(fx.w, 720, &got, got_hash) == 0, "get"); OK();
    CHECK(memcmp(got_hash, hashA, 64) == 0, "hash round-trip"); OK();
    CHECK(got->epoch == 720 && got->active_count == 2, "header round-trip");
    OK();
    {
        dna_vset_snapshot_t *ref = make_fixture(720, 2);
        CHECK(ref != NULL, "ref");
        for (int i = 0; i < 2; i++) {
            CHECK(memcmp(got->entries[i].voter_id, ref->entries[i].voter_id,
                         DNA_VSET_VOTER_ID_LEN) == 0, "voter"); OK();
            CHECK(memcmp(got->entries[i].pubkey, ref->entries[i].pubkey,
                         DNA_VSET_PUBKEY_LEN) == 0, "pubkey"); OK();
            CHECK(got->entries[i].total_stake == ref->entries[i].total_stake &&
                  got->entries[i].self_bond == ref->entries[i].self_bond &&
                  got->entries[i].commission_bps ==
                      ref->entries[i].commission_bps, "entry fields"); OK();
        }
        dna_vset_free(&ref);
    }
    dna_vset_free(&got);

    /* Re-inserting the SAME bytes is idempotent. */
    CHECK(nodus_witness_vset_insert(fx.w, 720, blobA, lenA, hashA, 900) == 0,
          "identical re-insert not idempotent"); OK();
    /* ...even from a different height (provenance is not hashed). */
    CHECK(nodus_witness_vset_insert(fx.w, 720, blobA, lenA, hashA, 999) == 0,
          "re-insert at another height"); OK();

    /* A DIFFERENT snapshot for the same epoch is a CONFLICT (-2). */
    {
        dna_vset_snapshot_t *alt = make_fixture(720, 2);
        CHECK(alt != NULL, "alt");
        alt->entries[0].total_stake ^= 1ULL;      /* one bit is enough */
        uint8_t *bA2 = malloc(lenA);
        CHECK(bA2 != NULL, "alloc");
        uint8_t hA2[64];
        CHECK(dna_vset_encode(alt, bA2, lenA, NULL) == 0, "encode alt");
        CHECK(dna_vset_hash_bytes(bA2, lenA, hA2) == 0, "hash alt");
        CHECK(memcmp(hA2, hashA, 64) != 0, "alt collided"); OK();
        CHECK(nodus_witness_vset_insert(fx.w, 720, bA2, lenA, hA2, 900) == -2,
              "conflicting snapshot was not reported as -2"); OK();
        /* The stored row must be UNCHANGED after a rejected conflict. */
        uint8_t h_after[64];
        dna_vset_snapshot_t *after = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 720, &after, h_after) == 0, "get");
        CHECK(memcmp(h_after, hashA, 64) == 0,
              "a conflicting insert modified the stored row"); OK();
        dna_vset_free(&after);
        free(bA2);
        dna_vset_free(&alt);
    }

    /* A hash that does not match its blob is refused outright (-1). */
    {
        uint8_t bogus[64];
        memcpy(bogus, hashA, 64);
        bogus[0] ^= 1;
        CHECK(nodus_witness_vset_insert(fx.w, 1440, blobA, lenA, bogus, 1) == -1,
              "stored a blob under a hash that is not its own"); OK();
        CHECK(nodus_witness_vset_get(fx.w, 1440, &got, NULL) == 1,
              "the refused insert left a row"); OK();
    }

    /* Argument guards. */
    CHECK(nodus_witness_vset_insert(fx.w, 5, NULL, lenA, hashA, 1) == -1,
          "NULL blob"); OK();
    CHECK(nodus_witness_vset_insert(fx.w, 5, blobA, 0, hashA, 1) == -1,
          "zero-length blob"); OK();
    /* HF-6 5c: the outer cap is the ruleset-2 ceiling; a v1 header above
     * the v1 ceiling is refused by the hash (before any byte past the
     * header is read). Both refusals leave no row. */
    CHECK(nodus_witness_vset_insert(fx.w, 5, blobA,
                                    DNA_VSET_MAX_ENC_LEN_V2 + 1, hashA, 1)
          == -1, "over-cap blob"); OK();
    CHECK(nodus_witness_vset_insert(fx.w, 5, blobA,
                                    DNA_VSET_MAX_ENC_LEN + 1, hashA, 1) == -1,
          "a v1 header above the v1 ceiling"); OK();
    CHECK(nodus_witness_vset_get(fx.w, 720, NULL, NULL) == -1,
          "NULL out"); OK();

    /* ── Corruption: mutate the stored BLOB. get() must fail closed. ── */
    CHECK(run_sql(fx.w->db,
        "UPDATE validator_set_snapshots SET snapshot_blob = "
        "  substr(snapshot_blob,1,100) || x'FF' || "
        "  substr(snapshot_blob,102) WHERE epoch_start = 720") == 0,
        "corrupt blob");
    CHECK(nodus_witness_vset_get(fx.w, 720, &got, NULL) == -1,
          "a corrupted blob was returned as valid"); OK();
    CHECK(got == NULL, "corrupt read wrote an output"); OK();
    /* root() still succeeds: it reads hashes, not blobs. */
    {
        uint8_t r[64];
        CHECK(nodus_witness_vset_root(fx.w, r) == 0,
              "root failed on an intact hash"); OK();
    }

    /* ── Corruption: restore the blob, mutate the stored HASH. ── */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
            "UPDATE validator_set_snapshots SET snapshot_blob = ? "
            "WHERE epoch_start = 720", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, blobA, (int)lenA, SQLITE_STATIC);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore blob");
        sqlite3_finalize(st);
        CHECK(nodus_witness_vset_get(fx.w, 720, &got, NULL) == 0,
              "restore failed"); OK();
        dna_vset_free(&got);

        uint8_t bad_hash[64];
        memcpy(bad_hash, hashA, 64);
        bad_hash[63] ^= 0x01;
        st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
            "UPDATE validator_set_snapshots SET snapshot_hash = ? "
            "WHERE epoch_start = 720", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, bad_hash, 64, SQLITE_STATIC);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "corrupt hash");
        sqlite3_finalize(st);
        CHECK(nodus_witness_vset_get(fx.w, 720, &got, NULL) == -1,
              "a mismatched stored hash was accepted"); OK();
    }

    /* ── A short stored hash fails the ROOT scan (never skipped). ── */
    CHECK(run_sql(fx.w->db,
        "UPDATE validator_set_snapshots SET snapshot_hash = x'1122' "
        "WHERE epoch_start = 720") == 0, "short hash");
    {
        uint8_t r[64];
        CHECK(nodus_witness_vset_root(fx.w, r) != 0,
              "a malformed hash row did not fail the root"); OK();
    }

    /* ── The row's denormalised active_count must agree with the blob. ── */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
            "UPDATE validator_set_snapshots SET snapshot_hash = ?, "
            "active_count = 7 WHERE epoch_start = 720",
            -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, hashA, 64, SQLITE_STATIC);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "reset");
        sqlite3_finalize(st);
        CHECK(nodus_witness_vset_get(fx.w, 720, &got, NULL) == -1,
              "a row whose count disagrees with its blob was accepted"); OK();
    }

    free(blobA);
    fx_close(&fx);
    return 0;
}

/* ── 2: validator_set_root ──────────────────────────────────────────── */

static int store_fixture(nodus_witness_t *w, uint64_t epoch, uint16_t n) {
    uint8_t *b = NULL, h[64];
    size_t len = 0;
    if (fixture_blob(epoch, n, &b, &len, h) != 0) return -1;
    int rc = nodus_witness_vset_insert(w, epoch, b, len, h, epoch);
    free(b);
    return rc;
}

static int test_root(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xC2) == 0, "open");
    uint8_t r[64];

    CHECK(store_fixture(fx.w, 720, 2) == 0, "store A");
    CHECK(nodus_witness_vset_root(fx.w, r) == 0, "root 1");
    CHECK(hex_eq(r, ROOT_1, "root 1 leaf"), "ROOT_1 KAT"); OK();

    CHECK(store_fixture(fx.w, 1440, 1) == 0, "store B");
    CHECK(nodus_witness_vset_root(fx.w, r) == 0, "root 2");
    CHECK(hex_eq(r, ROOT_2, "root 2 leaves"), "ROOT_2 KAT"); OK();

    /* Third row: an OPAQUE hash over an undecodable blob. root() must
     * still produce the pinned 3-leaf value, and get() must refuse the
     * row — together that is the proof that root() reads hashes only. */
    {
        uint8_t th[64];
        CHECK(from_hex(THIRD_HASH, th, 64) == 0, "third hash hex");
        const char *raw = "kat-third-snapshot";
        CHECK(insert_raw_row(fx.w, 2160, 0, th, raw, (int)strlen(raw)) == 0,
              "raw row");
        CHECK(nodus_witness_vset_root(fx.w, r) == 0, "root 3");
        CHECK(hex_eq(r, ROOT_3, "root 3 leaves"), "ROOT_3 KAT"); OK();

        dna_vset_snapshot_t *g = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 2160, &g, NULL) == -1,
              "get() decoded an undecodable blob"); OK();
        CHECK(g == NULL, "get wrote an output on failure"); OK();
    }

    /* Close / reopen: the same file must yield the same root, and the
     * stored snapshot must still read back. */
    {
        uint8_t r_before[64];
        memcpy(r_before, r, 64);
        sqlite3_close(fx.w->db);
        fx.w->db = NULL;
        CHECK(nodus_witness_create_chain_db(fx.w, fx.chain_id) == 0,
              "reopen");
        uint8_t r_after[64];
        CHECK(nodus_witness_vset_root(fx.w, r_after) == 0, "root after");
        CHECK(memcmp(r_before, r_after, 64) == 0,
              "root changed across a close/reopen"); OK();
        dna_vset_snapshot_t *g = NULL;
        uint8_t gh[64];
        CHECK(nodus_witness_vset_get(fx.w, 720, &g, gh) == 0,
              "get after reopen"); OK();
        CHECK(g->epoch == 720 && g->active_count == 2, "reopened row"); OK();
        dna_vset_free(&g);
    }
    fx_close(&fx);

    /* Insertion-order independence: 1440 first, then 720 → ROOT_2. */
    {
        fixture_t fy;
        CHECK(fx_open(&fy, 0xC3) == 0, "open y");
        CHECK(store_fixture(fy.w, 1440, 1) == 0, "store B first");
        CHECK(store_fixture(fy.w, 720, 2) == 0, "store A second");
        uint8_t r2[64];
        CHECK(nodus_witness_vset_root(fy.w, r2) == 0, "root y");
        CHECK(hex_eq(r2, ROOT_2, "reverse insertion order"),
              "insertion order changed the root"); OK();
        fx_close(&fy);
    }
    return 0;
}

/* ── 5 (HF-6 slice 5c): both rulesets through the store ────────────── */

/** A RULESET-2 fixture: voter_id = SHA3-512(pubkey)[0..31] (the v2 codec
 *  recomputes and enforces it); pubkey 0xA0 bytes and validator_id 0x40
 *  bytes with i (u16 BE) in their first two bytes, so 128 entries stay
 *  distinct and no id is all-zero; owner_fp byte 0x80 + (i & 0x3F)
 *  (owners need not be distinct). */
static dna_vset_snapshot_t *make_fixture_v2(uint64_t epoch, uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    if (!s) return NULL;
    s->epoch             = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V2;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        memset(e->pubkey, 0xA0, DNA_VSET_PUBKEY_LEN);
        e->pubkey[0] = (uint8_t)(i >> 8);
        e->pubkey[1] = (uint8_t)i;
        uint8_t d[64];
        if (qgp_sha3_512(e->pubkey, DNA_VSET_PUBKEY_LEN, d) != 0) {
            dna_vset_free(&s);
            return NULL;
        }
        memcpy(e->voter_id, d, DNA_VSET_VOTER_ID_LEN);
        memset(e->validator_id, 0x40, DNA_VSET_VALIDATOR_ID_LEN);
        e->validator_id[0] = (uint8_t)(i >> 8);
        e->validator_id[1] = (uint8_t)i;
        memset(e->owner_fp, (uint8_t)(0x80 + (i & 0x3F)),
               DNA_VSET_OWNER_FP_LEN);
        e->total_stake    = 2000000000000000ULL - i;
        e->self_bond      = 1000000000000000ULL;
        e->commission_bps = (uint16_t)(500 + i);
    }
    return s;
}

/** Encode `s` (any ruleset) through the `_ex` family into a malloc'd blob
 *  + its hash under the tag its header names. */
static int blob_ex(const dna_vset_snapshot_t *s, uint8_t **blob_out,
                   size_t *len_out, uint8_t hash_out[64]) {
    size_t need = dna_vset_encoded_len_ex(s, DNA_VSET_RULESET_TOPN_V2);
    if (need == 0) return -1;
    uint8_t *b = malloc(need);
    if (!b) return -1;
    if (dna_vset_encode_ex(s, DNA_VSET_RULESET_TOPN_V2, b, need, NULL) != 0 ||
        dna_vset_hash_bytes_ex(b, need, DNA_VSET_RULESET_TOPN_V2,
                               hash_out) != 0) {
        free(b);
        return -1;
    }
    *blob_out = b;
    *len_out  = need;
    return 0;
}

/** SHA3-512(tag16 ‖ blob), computed HERE, not through the codec. */
static int tagged_hash(const char *tag, const uint8_t *blob, size_t len,
                       uint8_t out[64]) {
    uint8_t *pre = calloc(1, 16 + len);
    if (!pre) return -1;
    memcpy(pre, tag, strlen(tag));        /* zero-padded to 16 by calloc */
    memcpy(pre + 16, blob, len);
    int rc = qgp_sha3_512(pre, 16 + len, out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

/*
 * WHAT IT PROVES (HF-6 slice 5c, design rev 6 §6.5 "Her okuyucu zincir
 * ömrü boyunca iki sürümü de kabul eder. v1 çıktıları bayt bayt
 * değişmez"; plan tasks/hf6-slice5-plan.md §2 "5c", §4 rows 1-2):
 *   - a ruleset-2 snapshot is stored and read back through
 *     nodus_witness_vset_insert / _get: ruleset 2, every entry field
 *     including validator_id / owner_fp, and the stored hash ==
 *     SHA3-512("NDS.VSET.v2" + 5×0x00 ‖ blob) computed here, != the same
 *     bytes under the v1 tag;
 *   - the ruleset-2 length ceiling: a 128-entry v2 blob of exactly
 *     DNA_VSET_MAX_ENC_LEN_V2 (354638) bytes — above the v1 ceiling —
 *     is stored and read; one byte more is refused before any read;
 *   - a PRE-SWITCH row: a v1 blob written with direct SQL under the
 *     hash the pre-5c code stored (the legacy v1-tag hash_bytes, which
 *     never read the header) reads back through the `_ex` path with
 *     exactly that hash, decodes field for field to the fixture, and
 *     dna_vset_hash_bytes_ex(…, 2) re-derives the stored hash;
 *   - a v2 blob offered for an epoch that holds a v1 row is the -2
 *     conflict, and the stored v1 row is untouched.
 * REQUIRES: a default build. LEAVES: one /tmp/test_vset_persist_* dir,
 * removed at the end (left behind when a CHECK aborts).
 * HOW IT CAN LIE: the fixtures are hand-built snapshots, not ones a
 * chain's builder produced (the builder still builds ruleset 1 until
 * slice 5d); the tag literal is the design's §6.5 text, not an
 * independent oracle run.
 */
static int test_both_rulesets(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xC6) == 0, "open");

    /* ── ruleset 2, 3 entries ── */
    dna_vset_snapshot_t *s2 = make_fixture_v2(720, 3);
    CHECK(s2 != NULL, "v2 fixture");
    uint8_t *b2 = NULL, h2[64];
    size_t l2 = 0;
    CHECK(blob_ex(s2, &b2, &l2, h2) == 0, "encode v2");
    CHECK(l2 == (size_t)DNA_VSET_HDR_LEN + 3u * DNA_VSET_ENTRY_LEN_V2,
          "v2 length = 78 + 3 × 2770"); OK();
    {
        uint8_t want[64], v1tag[64];
        CHECK(tagged_hash("NDS.VSET.v2", b2, l2, want) == 0, "v2 tag hash");
        CHECK(memcmp(want, h2, 64) == 0,
              "the v2 hash is SHA3-512(\"NDS.VSET.v2\" ‖ blob)"); OK();
        CHECK(tagged_hash("NDS.VSET.v1", b2, l2, v1tag) == 0, "v1 tag hash");
        CHECK(memcmp(v1tag, h2, 64) != 0,
              "the v2 hash is not the v1-tag hash of the same bytes"); OK();
    }
    CHECK(nodus_witness_vset_insert(fx.w, 720, b2, l2, h2, 700) == 0,
          "a ruleset-2 snapshot stores"); OK();
    CHECK(nodus_witness_vset_insert(fx.w, 720, b2, l2, h2, 701) == 0,
          "an identical v2 re-insert is idempotent"); OK();
    {
        dna_vset_snapshot_t *got = NULL;
        uint8_t gh[64];
        CHECK(nodus_witness_vset_get(fx.w, 720, &got, gh) == 0,
              "a ruleset-2 snapshot reads back"); OK();
        CHECK(memcmp(gh, h2, 64) == 0, "stored hash"); OK();
        CHECK(got->selection_ruleset == DNA_VSET_RULESET_TOPN_V2 &&
              got->epoch == 720 && got->active_count == 3, "v2 header");
        OK();
        for (int i = 0; i < 3; i++) {
            const dna_vset_entry_t *a = &got->entries[i], *b = &s2->entries[i];
            CHECK(memcmp(a->voter_id, b->voter_id, DNA_VSET_VOTER_ID_LEN) == 0
                  && memcmp(a->pubkey, b->pubkey, DNA_VSET_PUBKEY_LEN) == 0 &&
                  memcmp(a->validator_id, b->validator_id,
                         DNA_VSET_VALIDATOR_ID_LEN) == 0 &&
                  memcmp(a->owner_fp, b->owner_fp, DNA_VSET_OWNER_FP_LEN) == 0
                  && a->total_stake == b->total_stake &&
                  a->self_bond == b->self_bond &&
                  a->commission_bps == b->commission_bps,
                  "every v2 entry field round-trips"); OK();
        }
        dna_vset_free(&got);
    }
    free(b2);
    dna_vset_free(&s2);

    /* ── the ruleset-2 ceiling: 128 entries, exactly 354638 bytes ── */
    {
        dna_vset_snapshot_t *big = make_fixture_v2(1440, 128);
        CHECK(big != NULL, "128-entry v2 fixture");
        uint8_t *bb = NULL, hb[64];
        size_t lb = 0;
        CHECK(blob_ex(big, &bb, &lb, hb) == 0, "encode 128 v2");
        CHECK(lb == (size_t)DNA_VSET_MAX_ENC_LEN_V2 && lb == 354638u &&
              lb > (size_t)DNA_VSET_MAX_ENC_LEN,
              "128 v2 entries = the v2 ceiling, above the v1 one"); OK();
        CHECK(nodus_witness_vset_insert(fx.w, 1440, bb, lb, hb, 1) == 0,
              "a v2 blob at the v2 ceiling stores"); OK();
        dna_vset_snapshot_t *got = NULL;
        CHECK(nodus_witness_vset_get(fx.w, 1440, &got, NULL) == 0 &&
              got->active_count == 128 &&
              got->selection_ruleset == DNA_VSET_RULESET_TOPN_V2 &&
              memcmp(got->entries[127].validator_id,
                     big->entries[127].validator_id, 64) == 0,
              "...and reads back"); OK();
        dna_vset_free(&got);
        CHECK(nodus_witness_vset_insert(fx.w, 2160, bb, lb + 1, hb, 1) == -1,
              "one byte past the v2 ceiling is refused"); OK();
        free(bb);
        dna_vset_free(&big);
    }

    /* ── a PRE-SWITCH ruleset-1 row (written the pre-5c way) ── */
    {
        uint8_t *b1 = NULL, h1_legacy[64];
        size_t l1 = 0;
        /* fixture_blob hashes with the legacy v1-tag dna_vset_hash_bytes —
         * exactly the hash the pre-5c insert stored */
        CHECK(fixture_blob(2880, 2, &b1, &l1, h1_legacy) == 0, "v1 fixture");
        CHECK(insert_raw_row(fx.w, 2880, 2, h1_legacy, b1, (int)l1) == 0,
              "a v1 row written as the pre-5c code wrote it");
        uint8_t h1_ex[64];
        CHECK(dna_vset_hash_bytes_ex(b1, l1, DNA_VSET_RULESET_TOPN_V2,
                                     h1_ex) == 0 &&
              memcmp(h1_ex, h1_legacy, 64) == 0,
              "a v1 blob re-hashes through _ex to its stored hash"); OK();
        dna_vset_snapshot_t *got = NULL, *ref = make_fixture(2880, 2);
        uint8_t gh[64];
        CHECK(ref != NULL, "ref");
        CHECK(nodus_witness_vset_get(fx.w, 2880, &got, gh) == 0,
              "the pre-switch row reads through the _ex path"); OK();
        CHECK(memcmp(gh, h1_legacy, 64) == 0, "its stored hash"); OK();
        CHECK(got->selection_ruleset == DNA_VSET_RULESET_TOPN_V1, "ruleset 1");
        OK();
        for (int i = 0; i < 2; i++) {
            const dna_vset_entry_t *a = &got->entries[i], *b = &ref->entries[i];
            static const uint8_t z[64] = { 0 };
            CHECK(memcmp(a->voter_id, b->voter_id, DNA_VSET_VOTER_ID_LEN) == 0
                  && memcmp(a->pubkey, b->pubkey, DNA_VSET_PUBKEY_LEN) == 0 &&
                  a->total_stake == b->total_stake &&
                  a->self_bond == b->self_bond &&
                  a->commission_bps == b->commission_bps &&
                  memcmp(a->validator_id, z, 64) == 0 &&
                  memcmp(a->owner_fp, z, 64) == 0,
                  "decodes identically, ids zero"); OK();
        }
        dna_vset_free(&got);
        dna_vset_free(&ref);

        /* a v2 blob for the epoch a v1 row holds: CONFLICT, row intact */
        dna_vset_snapshot_t *s = make_fixture_v2(2880, 2);
        uint8_t *bv = NULL, hv[64];
        size_t lv = 0;
        CHECK(s != NULL && blob_ex(s, &bv, &lv, hv) == 0, "v2 for 2880");
        CHECK(nodus_witness_vset_insert(fx.w, 2880, bv, lv, hv, 1) == -2,
              "a v2 blob over a stored v1 row is a conflict"); OK();
        CHECK(nodus_witness_vset_get(fx.w, 2880, &got, gh) == 0 &&
              memcmp(gh, h1_legacy, 64) == 0 &&
              got->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
              "the v1 row is untouched"); OK();
        dna_vset_free(&got);
        free(bv);
        dna_vset_free(&s);
        free(b1);
    }

    fx_close(&fx);
    return 0;
}

/* ── 4: build_for_epoch ─────────────────────────────────────────────── */

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                           uint64_t active_since, uint64_t self_stake,
                           uint64_t external_delegated, int status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake         = self_stake;
    v->total_delegated    = external_delegated;
    v->external_delegated = external_delegated;
    v->commission_bps     = (uint16_t)(1000 + pub_fill);
    v->status             = status;
    v->active_since_block = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2 * i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2 * i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

/* Seed a block row so the committee's lookback state_seed exists. */
static int insert_block_row(nodus_witness_t *w, uint64_t height,
                            const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, prev_hash, "
        " state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return -1;
    uint8_t zeros[64] = { 0 };
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, state_seed, 64, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Tokenomics-v3 P3-1 (okuma B): the builder for snapshot(e_start) ranks by
 * FROZEN totals read from the balance copy at the epoch start of its
 * lookback block, copy(e_start − 2E) (nodus_witness_committee.c). Write
 * that copy from the live rows: one own row (owner_fp == validator_fp) of
 * self_stake, and one delegator row of external_delegated under a fixed
 * foreign owner. frozen total == live total, frozen self == live self. */
static int write_frozen_copy(nodus_witness_t *w, uint64_t epoch,
                             const dnac_validator_record_t *v) {
    uint8_t vfp[64], dfp[64], dpk[DNAC_PUBKEY_SIZE];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, vfp);
    memset(dpk, 0xDD, sizeof(dpk));
    qgp_sha3_512(dpk, DNAC_PUBKEY_SIZE, dfp);
    const uint64_t amt[2] = { v->self_stake, v->external_delegated };
    for (int k = 0; k < 2; k++) {
        if (amt[k] == 0) continue;
        sqlite3_stmt *ins = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_balance_copy (epoch_start, validator_fp, "
                "owner_fp, kind, amount) VALUES (?, ?, ?, ?, ?)", -1, &ins,
                NULL)
            != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(ins, 1, (int64_t)epoch);
        sqlite3_bind_blob (ins, 2, vfp, 64, SQLITE_STATIC);
        sqlite3_bind_blob (ins, 3, k == 0 ? vfp : dfp, 64, SQLITE_STATIC);
        sqlite3_bind_int  (ins, 4, k);   /* kind: 0 the bond, 1 a delegation */
        sqlite3_bind_int64(ins, 5, (int64_t)amt[k]);
        int rc = sqlite3_step(ins);
        sqlite3_finalize(ins);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int test_build(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xC4) == 0, "open");

    const uint64_t e_start  = (uint64_t)DNAC_EPOCH_LENGTH * 4;
    const uint64_t lookback = e_start - (uint64_t)DNAC_EPOCH_LENGTH - 1;
    uint8_t seed[64];
    memset(seed, 0xAA, sizeof(seed));
    CHECK(insert_block_row(fx.w, lookback, seed) == 0, "block row");

    /* self_stake deliberately DIFFERS from total_stake so a builder that
     * wrote total_stake into self_bond would be caught. */
    dnac_validator_record_t v1, v2, v3;
    init_validator(&v1, 0x11, 1, 100, 5, DNAC_VALIDATOR_ACTIVE);  /* 105 */
    init_validator(&v2, 0x22, 1, 200, 7, DNAC_VALIDATOR_ACTIVE);  /* 207 */
    init_validator(&v3, 0x33, 1, 300, 9, DNAC_VALIDATOR_ACTIVE);  /* 309 */
    CHECK(nodus_validator_insert(fx.w, &v1) == 0, "insert v1");
    CHECK(nodus_validator_insert(fx.w, &v2) == 0, "insert v2");
    CHECK(nodus_validator_insert(fx.w, &v3) == 0, "insert v3");
    {
        const uint64_t copy_epoch = e_start - 2ULL * DNAC_EPOCH_LENGTH;
        CHECK(write_frozen_copy(fx.w, copy_epoch, &v1) == 0, "copy v1");
        CHECK(write_frozen_copy(fx.w, copy_epoch, &v2) == 0, "copy v2");
        CHECK(write_frozen_copy(fx.w, copy_epoch, &v3) == 0, "copy v3");
    }

    /* max_active bounds. */
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, e_start, 0, NULL, NULL,
                                             NULL, NULL) == -1,
          "max_active 0 accepted"); OK();
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, e_start, 129, NULL, NULL,
                                             NULL, NULL) == -1,
          "max_active 129 accepted"); OK();

    dna_vset_snapshot_t *snap = NULL;
    uint8_t *blob = NULL, hash[64];
    size_t blob_len = 0;
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, e_start, 2, &snap, &blob,
                                             &blob_len, hash) == 0, "build");
    OK();
    CHECK(snap->epoch == e_start, "snapshot epoch"); OK();
    CHECK(snap->active_count == 2, "top-2 not returned"); OK();
    CHECK(snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V1, "ruleset");
    OK();
    {
        uint8_t zero_seed[DNA_VSET_SEED_LEN] = { 0 };
        CHECK(memcmp(snap->sortition_seed, zero_seed,
                     DNA_VSET_SEED_LEN) == 0, "seed not zeroed"); OK();
    }

    /* Ranked by stake DESC: v3 (309) then v2 (207); v1 (105) is cut. */
    CHECK(snap->entries[0].total_stake == 309, "rank 0 stake"); OK();
    CHECK(snap->entries[1].total_stake == 207, "rank 1 stake"); OK();
    /* self_bond is the OWN bond, NOT total_stake. */
    CHECK(snap->entries[0].self_bond == 300, "rank 0 self_bond"); OK();
    CHECK(snap->entries[1].self_bond == 200, "rank 1 self_bond"); OK();
    CHECK(snap->entries[0].commission_bps == (uint16_t)(1000 + 0x33),
          "rank 0 commission"); OK();
    CHECK(snap->entries[1].commission_bps == (uint16_t)(1000 + 0x22),
          "rank 1 commission"); OK();
    {
        uint8_t pk3[DNAC_PUBKEY_SIZE], pk2[DNAC_PUBKEY_SIZE];
        memset(pk3, 0x33, sizeof(pk3));
        memset(pk2, 0x22, sizeof(pk2));
        CHECK(memcmp(snap->entries[0].pubkey, pk3, DNAC_PUBKEY_SIZE) == 0,
              "rank 0 pubkey"); OK();
        CHECK(memcmp(snap->entries[1].pubkey, pk2, DNAC_PUBKEY_SIZE) == 0,
              "rank 1 pubkey"); OK();

        /* voter_id == SHA3-512(pubkey)[0..31], computed here INDEPENDENTLY
         * of the production helper — and the production helper must agree,
         * which is what test_qc_v2.c's local replica relies on. */
        for (int i = 0; i < 2; i++) {
            uint8_t full[64], expect[32], via_helper[32];
            qgp_sha3_512(snap->entries[i].pubkey, DNAC_PUBKEY_SIZE, full);
            memcpy(expect, full, 32);
            CHECK(memcmp(snap->entries[i].voter_id, expect, 32) == 0,
                  "voter_id != SHA3-512(pubkey)[0..31]"); OK();
            CHECK(nodus_chain_config_derive_witness_id(
                      snap->entries[i].pubkey, via_helper) == 0, "derive");
            CHECK(memcmp(via_helper, expect, 32) == 0,
                  "derive_witness_id disagrees with SHA3-512(pubkey)[0..31]");
            OK();
        }
    }

    /* The three outputs are mutually consistent, and the snapshot
     * round-trips through the persistence layer unchanged. */
    {
        uint8_t h2[64];
        CHECK(dna_vset_hash(snap, h2) == 0, "hash snap");
        CHECK(memcmp(h2, hash, 64) == 0, "hash != blob hash"); OK();
        CHECK(blob_len == dna_vset_encoded_len(snap), "blob length"); OK();

        CHECK(nodus_witness_vset_insert(fx.w, e_start, blob, blob_len, hash,
                                        e_start) == 0, "insert built"); OK();
        dna_vset_snapshot_t *back = NULL;
        CHECK(nodus_witness_vset_get(fx.w, e_start, &back, NULL) == 0,
              "get built"); OK();
        CHECK(back->active_count == snap->active_count &&
              back->epoch == snap->epoch &&
              memcmp(back->entries[0].voter_id, snap->entries[0].voter_id,
                     32) == 0 &&
              back->entries[0].self_bond == snap->entries[0].self_bond,
              "built snapshot did not survive the round trip"); OK();
        dna_vset_free(&back);

        /* Building twice must produce identical bytes — determinism. */
        uint8_t *blob2 = NULL, hash2[64];
        size_t len2 = 0;
        CHECK(nodus_witness_vset_build_for_epoch(fx.w, e_start, 2, NULL,
                                                 &blob2, &len2, hash2) == 0,
              "rebuild"); OK();
        CHECK(len2 == blob_len && memcmp(blob2, blob, blob_len) == 0,
              "two builds of one epoch differ"); OK();
        CHECK(memcmp(hash2, hash, 64) == 0, "rebuild hash differs"); OK();
        free(blob2);
    }

    free(blob);
    dna_vset_free(&snap);

    /* HF-6 5c (ORCHESTRATOR decision D6): below key generation 4 the
     * selection core emits ZERO validator_id / owner_fp (and power 0) —
     * written, not inherited from the caller's buffer (pre-filled 0xEE
     * here) — and the entry fill writes zero ids into a ruleset-1 entry
     * whatever the member carries, copies them into a ruleset-2 one, and
     * a ruleset-2 snapshot built from zero ids is refused by the v2
     * encoder. (Generation 4's ids: test_hf6_readers.) */
    {
        uint32_t gen = 99;
        CHECK(nodus_witness_v2_key_generation(fx.w, &gen) == 0 &&
              gen < NODUS_RT_GEN_STORAGE, "this fixture is below gen 4");
        nodus_committee_member_t *m = malloc(4 * sizeof(*m));
        CHECK(m != NULL, "alloc");
        memset(m, 0xEE, 4 * sizeof(*m));
        int cnt = 0;
        CHECK(nodus_committee_compute_for_epoch(fx.w, e_start, m, 4, &cnt)
              == 0 && cnt == 3, "compute below gen 4"); OK();
        static const uint8_t z[64] = { 0 };
        for (int i = 0; i < cnt; i++) {
            CHECK(memcmp(m[i].validator_id, z, 64) == 0 &&
                  memcmp(m[i].owner_fp, z, 64) == 0 && m[i].power == 0,
                  "gen < 4: ids zero, power 0"); OK();
        }

        dna_vset_entry_t e;
        memset(m[0].validator_id, 0x11, sizeof(m[0].validator_id));
        memset(m[0].owner_fp, 0x22, sizeof(m[0].owner_fp));
        memset(&e, 0xEE, sizeof(e));
        CHECK(nodus_witness_vset_entry_from_member(
                  &m[0], DNA_VSET_RULESET_TOPN_V1, &e) == 0 &&
              memcmp(e.validator_id, z, 64) == 0 &&
              memcmp(e.owner_fp, z, 64) == 0 &&
              memcmp(e.pubkey, m[0].pubkey, DNAC_PUBKEY_SIZE) == 0 &&
              e.total_stake == m[0].total_stake &&
              e.self_bond == m[0].self_stake &&
              e.commission_bps == m[0].commission_bps,
              "ruleset 1: the member's fields, ids written zero"); OK();
        CHECK(nodus_witness_vset_entry_from_member(
                  &m[0], DNA_VSET_RULESET_TOPN_V2, &e) == 0 &&
              e.validator_id[0] == 0x11 && e.validator_id[63] == 0x11 &&
              e.owner_fp[0] == 0x22 && e.owner_fp[63] == 0x22,
              "ruleset 2: the member's ids copied"); OK();
        CHECK(nodus_witness_vset_entry_from_member(&m[0], 3u, &e) == -1 &&
              nodus_witness_vset_entry_from_member(
                  &m[0], DNA_VSET_RULESET_INVALID, &e) == -1 &&
              nodus_witness_vset_entry_from_member(
                  NULL, DNA_VSET_RULESET_TOPN_V1, &e) == -1,
              "ruleset 0 / 3 and NULL refused"); OK();

        /* members 1, 2 still carry the zero ids gen < 4 emitted */
        dna_vset_snapshot_t *z2 = dna_vset_alloc(2);
        CHECK(z2 != NULL, "alloc");
        z2->epoch = e_start;
        z2->selection_ruleset = DNA_VSET_RULESET_TOPN_V2;
        CHECK(nodus_witness_vset_entry_from_member(
                  &m[1], DNA_VSET_RULESET_TOPN_V2, &z2->entries[0]) == 0 &&
              nodus_witness_vset_entry_from_member(
                  &m[2], DNA_VSET_RULESET_TOPN_V2, &z2->entries[1]) == 0,
              "fill");
        CHECK(dna_vset_encoded_len_ex(z2, DNA_VSET_RULESET_TOPN_V2) == 0,
              "a v2 snapshot from gen < 4 members (zero ids) does not "
              "encode"); OK();
        dna_vset_free(&z2);
        free(m);
    }

    /* An empty validator table has NO snapshot. */
    {
        fixture_t fe;
        CHECK(fx_open(&fe, 0xC5) == 0, "open e");
        CHECK(insert_block_row(fe.w, lookback, seed) == 0, "block row e");
        CHECK(nodus_witness_vset_build_for_epoch(fe.w, e_start, 2, NULL, NULL,
                                                 NULL, NULL) == -1,
              "an empty validator set produced a snapshot"); OK();
        fx_close(&fe);
    }

    fx_close(&fx);
    return 0;
}

int main(void) {
    if (test_insert_get() != 0) return 1;
    if (test_root() != 0) return 1;
    if (test_both_rulesets() != 0) return 1;
    if (test_build() != 0) return 1;
    printf("test_vset_persist: %d checks OK\n", g_checks);
    return 0;
}
