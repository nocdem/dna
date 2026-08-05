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
 *      by stake, self_bond taken from the validator record (not
 *      total_stake), voter_id == SHA3-512(pubkey)[0..31], and the
 *      production derivation helper agreeing with that definition.
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
/* Snapshot hashes of fixtures A (epoch 720, 2 entries) and B (1440, 1). */
static const char *ROOT_1 =   /* {720:A}                                */
    "cd702985b5432034945617a93c7d2ef84808966660f6fefb978e1fcb0df832e2"
    "dabca6324d640a25d945332887815cfcab6c699e51a27454bc67eaf96c02bb85";
static const char *ROOT_2 =   /* {720:A, 1440:B}                        */
    "d2b8febe16786470b901119424f33305397a21a28fb2b318ad43dd46e504feb0"
    "f0d177a27059c787dc34783599b95c3e464b0b58e91583475d7cbebf9d70e7f9";
static const char *ROOT_3 =   /* {720:A, 1440:B, 2160:third}            */
    "a431ae020cc30fc376a7c77185c43ef87cbdb4139006ccb110564880b8f58529"
    "495450b77c0633f2e6e1b16984af49fc4711c45f4dcb5442736e4f93c031aa00";
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
 * which is TAG-PREFIXED (SHA3-512("DNA.VSET.v1" ‖ blob)), so it can only
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
    CHECK(nodus_witness_vset_insert(fx.w, 5, blobA,
                                    DNA_VSET_MAX_ENC_LEN + 1, hashA, 1) == -1,
          "over-cap blob"); OK();
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
    if (test_build() != 0) return 1;
    printf("test_vset_persist: %d checks OK\n", g_checks);
    return 0;
}
