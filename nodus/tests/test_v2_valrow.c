/**
 * Nodus — HF-6 sub-slice 3a: the v2 validator / delegation row access
 * (INERT layer — no production caller yet; sub-slices 3b/3d consume it).
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.2, §6.3, §6.4, §7; plan tasks/hf6-slice3-plan.md §1 + §2 "3a"
 * (decision D1 option (i): keys re-valued in place, the three new
 * validator fields in the side table v2_validator_roles).
 *
 * What it proves (each would be false if the matching check failed):
 *   1. v2 get returns the JOIN of a re-keyed validators row (pubkey_hash
 *      = validator_id) and its roles row, every field byte-equal to what
 *      was written (the read by consensus pubkey, get_by_pubkey, is
 *      deleted — HF-6 red-team round 1 close-out: no production caller);
 *   2. absent (1) and fault (-1) are distinct: an unknown key is 1; a
 *      validators row without its roles row, an orphan roles row, a
 *      malformed roles row and a missing roles table are all -1 — never
 *      "absent", never a value; a second validators row holding the same
 *      consensus pubkey under its own id leaves both keyed reads intact;
 *   3. v2 update writes BOTH tables inside the caller's transaction and
 *      round-trips; it refuses autocommit mode, ANY pending key or
 *      effective epoch that is not zero (HF-6 D1, khan decision
 *      2026-10-13-kurultay-18-summary.md item 4: the §6.3 fields are
 *      always zero — the slice-6 consistent "pending rotation" shape is
 *      malformed too), a changed owner_fp (no TRANSFER_OWNER) and a
 *      changed consensus pubkey, and reports an unknown key as 1; a
 *      STORED non-zero pending key is a fault on read (-1);
 *   4. the gen-4 bonded_tenured arm returns each candidate's re-keyed
 *      pubkey_hash AS its validator_id, with the v1 function's filters and
 *      pubkey ASC collect order (the v1 function, unchanged, returns the
 *      same candidates); more rows than the cap and a candidate without a
 *      roles row are faults;
 *   5. v2 delegation get / delete / count / list are keyed by
 *      (delegator_fp, validator_id) as given (no hashing), list is ordered
 *      by delegator_fp ASC and never truncates (more than cap = fault), a
 *      malformed row (amount 0) is a fault.
 *
 * Requires: a default build; no environment. Uses a real witness chain DB
 * in a mkdtemp directory (heap fixture — nodus_witness_t is multi-MB).
 * Leaves behind: nothing (each fixture's directory is removed).
 * How it can lie: the rows are written by hand (raw SQL re-key + roles
 * insert) because the migration that writes them in production (3b) does
 * not exist yet — this pins the ACCESS layer against hand-built rows, not
 * the migration's output.
 *
 * @file test_v2_valrow.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "dnac/validator.h"
#include "dnac/dnac.h"

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

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_valrow_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x6B, sizeof(chain_id16));
    if (nodus_witness_create_chain_db(fx->w, chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
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

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void make_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                           uint64_t active_since, uint8_t status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = 1000000000000000ULL;
    v->total_delegated         = 0;
    v->external_delegated      = 0;
    v->commission_bps          = 500;
    v->status                  = status;
    v->active_since_block      = active_since;
    memset(v->unstake_destination_fp, 'a', 128);
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, 0x77, DNAC_PUBKEY_SIZE);
}

/* The "manual re-key" of plan §2 3a: what the HF-6 edge (3b) does to one
 * row — validators.pubkey_hash := vid — plus its roles row (owner, no
 * pending key). `with_roles` = 0 leaves the row half-migrated. */
static int rekey(sqlite3 *db, const uint8_t *pubkey, const uint8_t vid[64],
                 const uint8_t owner[64], int with_roles) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE validators SET pubkey_hash = ? "
                           "WHERE pubkey = ?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, vid, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int ch = sqlite3_changes(db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || ch != 1) return -1;
    if (!with_roles) return 0;
    st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO v2_validator_roles (validator_id,"
                           " owner_fp, pending_consensus_pubkey, "
                           "consensus_key_effective_epoch) VALUES "
                           "(?, ?, zeroblob(2592), 0)", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, vid, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, owner, 64, SQLITE_STATIC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int roles_insert_only(sqlite3 *db, const uint8_t vid[64],
                             const uint8_t owner[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO v2_validator_roles VALUES "
                           "(?, ?, zeroblob(2592), 0)", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, vid, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, owner, 64, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int deleg_insert(sqlite3 *db, const uint8_t dfp[64],
                        const uint8_t vid[64], int64_t amount, int64_t at) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO delegations (delegator_hash, "
                           "validator_hash, delegator_pubkey, "
                           "validator_pubkey, amount, delegated_at_block) "
                           "VALUES (?, ?, x'', x'', ?, ?)", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, dfp, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, vid, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, amount);
    sqlite3_bind_int64(st, 4, at);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int rec_eq(const dnac_validator_record_t *a,
                  const dnac_validator_record_t *b) {
    return memcmp(a->pubkey, b->pubkey, DNAC_PUBKEY_SIZE) == 0 &&
           a->self_stake == b->self_stake &&
           a->total_delegated == b->total_delegated &&
           a->external_delegated == b->external_delegated &&
           a->commission_bps == b->commission_bps &&
           a->pending_commission_bps == b->pending_commission_bps &&
           a->pending_effective_block == b->pending_effective_block &&
           a->status == b->status &&
           a->active_since_block == b->active_since_block &&
           a->unstake_commit_block == b->unstake_commit_block &&
           strcmp((const char *)a->unstake_destination_fp,
                  (const char *)b->unstake_destination_fp) == 0 &&
           memcmp(a->unstake_destination_pubkey,
                  b->unstake_destination_pubkey, DNAC_PUBKEY_SIZE) == 0 &&
           a->last_validator_update_block == b->last_validator_update_block &&
           a->consecutive_missed_epochs == b->consecutive_missed_epochs;
}

static int row_eq(const nodus_v2_validator_row_t *a,
                  const nodus_v2_validator_row_t *b) {
    return rec_eq(&a->rec, &b->rec) &&
           memcmp(a->validator_id, b->validator_id, 64) == 0 &&
           memcmp(a->owner_fp, b->owner_fp, 64) == 0 &&
           memcmp(a->pending_consensus_pubkey, b->pending_consensus_pubkey,
                  DNAC_PUBKEY_SIZE) == 0 &&
           a->consensus_key_effective_epoch ==
               b->consensus_key_effective_epoch;
}

/* ── 1-3. get / get_by_pubkey / update ────────────────────────────────── */

static int t_get_update(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();

    static nodus_v2_validator_row_t want, got, tmp;
    uint8_t vidA[64], ownA[64];
    memset(vidA, 0xA1, 64);
    memset(ownA, 0xB1, 64);

    memset(&want, 0, sizeof(want));
    make_validator(&want.rec, 0x11, 1, DNAC_VALIDATOR_ACTIVE);
    CHECK(nodus_validator_insert(fx.w, &want.rec) == 0, "insert A");
    CHECK(rekey(fx.w->db, want.rec.pubkey, vidA, ownA, 1) == 0,
          "re-key A + its roles row"); OK();
    memcpy(want.validator_id, vidA, 64);
    memcpy(want.owner_fp, ownA, 64);

    /* 1. the keyed reader returns the joined row */
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0, "v2_get A"); OK();
    CHECK(row_eq(&want, &got), "v2_get: every field round-trips"); OK();
    /* the v1 get by pubkey no longer finds the re-keyed row (its key is
     * the tagged hash) — the reason the v2 readers exist */
    CHECK(nodus_validator_get(fx.w, want.rec.pubkey, &got.rec) == 1,
          "v1 get misses a re-keyed row"); OK();

    /* 2. absent */
    uint8_t vidX[64];
    memset(vidX, 0xEE, 64);
    CHECK(nodus_validator_v2_get(fx.w, vidX, &got) == 1, "unknown id = 1");
    OK();

    /* 3. update round trip, inside a transaction */
    want.rec.self_stake = 200000000000000ULL;
    want.rec.total_delegated = 800000000000000ULL;
    want.rec.external_delegated = 800000000000000ULL;
    want.rec.commission_bps = 1200;
    want.rec.status = DNAC_VALIDATOR_ELIGIBLE;
    want.rec.consecutive_missed_epochs = 2;
    /* the pending fields stay zero: HF-6 has no key rotation (khan
     * decision 2026-10-13-kurultay-18-summary.md item 4) */
    memset(want.pending_consensus_pubkey, 0, DNAC_PUBKEY_SIZE);
    want.consensus_key_effective_epoch = 0;
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "begin");
    CHECK(nodus_validator_v2_update(fx.w, &want) == 0, "v2_update"); OK();
    CHECK(run_sql(fx.w->db, "COMMIT") == 0, "commit");
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
          row_eq(&want, &got), "update round-trips both tables"); OK();

    /* autocommit mode is refused, nothing written */
    tmp = want;
    tmp.rec.commission_bps = 4000;
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "update outside a transaction = -1"); OK();
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
          row_eq(&want, &got), "and wrote nothing"); OK();

    /* a pending field that is not zero is refused — each alone and both
     * together (the slice-6 "consistent pending key" is malformed too) */
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "begin");
    tmp = want;
    memset(tmp.pending_consensus_pubkey, 0x5A, DNAC_PUBKEY_SIZE);
    tmp.consensus_key_effective_epoch = 0;          /* key set, epoch 0  */
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "nonzero pending key with epoch 0 = -1"); OK();
    tmp = want;
    tmp.consensus_key_effective_epoch = 3;          /* no key, epoch 3   */
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "zero pending key with epoch 3 = -1"); OK();
    tmp = want;
    memset(tmp.pending_consensus_pubkey, 0x5A, DNAC_PUBKEY_SIZE);
    tmp.consensus_key_effective_epoch = 7;          /* key set, epoch 7  */
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "nonzero pending key with epoch 7 = -1 (no rotation)"); OK();
    /* a changed owner is refused (no TRANSFER_OWNER in HF-6) */
    tmp = want;
    memset(tmp.owner_fp, 0xB2, 64);
    tmp.rec.commission_bps = 4000;
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "owner_fp mismatch = -1"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
          row_eq(&want, &got), "the rolled-back faults left the row"); OK();

    /* a changed consensus pubkey is refused */
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "begin");
    tmp = want;
    memset(tmp.rec.pubkey, 0x12, DNAC_PUBKEY_SIZE);
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "consensus pubkey mismatch = -1"); OK();
    /* an unknown key is 1 */
    tmp = want;
    memcpy(tmp.validator_id, vidX, 64);
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == 1,
          "update of an unknown key = 1"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");

    /* half-migrated: a validators row without its roles row */
    static nodus_v2_validator_row_t b;
    uint8_t vidB[64];
    memset(vidB, 0xA2, 64);
    memset(&b, 0, sizeof(b));
    make_validator(&b.rec, 0x22, 1, DNAC_VALIDATOR_ACTIVE);
    CHECK(nodus_validator_insert(fx.w, &b.rec) == 0, "insert B");
    CHECK(rekey(fx.w->db, b.rec.pubkey, vidB, ownA, 0) == 0,
          "re-key B WITHOUT a roles row");
    CHECK(nodus_validator_v2_get(fx.w, vidB, &got) == -1,
          "v2_get: validators row without roles = -1 (not absent)"); OK();
    memcpy(b.validator_id, vidB, 64);
    memcpy(b.owner_fp, ownA, 64);
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "begin");
    CHECK(nodus_validator_v2_update(fx.w, &b) == -1,
          "update of a half-migrated row = -1"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");

    /* an orphan roles row (no validators row) */
    uint8_t vidC[64];
    memset(vidC, 0xA3, 64);
    CHECK(roles_insert_only(fx.w->db, vidC, ownA) == 0, "orphan roles row");
    CHECK(nodus_validator_v2_get(fx.w, vidC, &got) == -1,
          "v2_get: an orphan roles row = -1 (not absent)"); OK();
    tmp = want;
    memcpy(tmp.validator_id, vidC, 64);
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "begin");
    CHECK(nodus_validator_v2_update(fx.w, &tmp) == -1,
          "update against an orphan roles row = -1"); OK();
    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");

    /* two validators rows with A's pubkey: the v1 insert keys by the
     * tagged hash, which A no longer occupies; re-key it to vidD with a
     * roles row — each keyed read still resolves its own row */
    {
        static dnac_validator_record_t dup;
        dup = want.rec;
        uint8_t vidD[64];
        memset(vidD, 0xA4, 64);
        CHECK(nodus_validator_insert(fx.w, &dup) == 0, "second row, A's pk");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db, "UPDATE validators SET "
              "pubkey_hash = ? WHERE pubkey = ? AND pubkey_hash <> ?", -1,
              &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, vidD, 64, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, dup.pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, vidA, 64, SQLITE_STATIC);
        int rc = sqlite3_step(st);
        int ch = sqlite3_changes(fx.w->db);
        sqlite3_finalize(st);
        CHECK(rc == SQLITE_DONE && ch == 1, "re-key the duplicate");
        CHECK(roles_insert_only(fx.w->db, vidD, ownA) == 0, "its roles row");
        CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
              row_eq(&want, &got),
              "the keyed read is unaffected"); OK();
        CHECK(nodus_validator_v2_get(fx.w, vidD, &got) == 0 &&
              memcmp(got.validator_id, vidD, 64) == 0 &&
              memcmp(got.rec.pubkey, want.rec.pubkey, DNAC_PUBKEY_SIZE) == 0,
              "the duplicate resolves by its own id"); OK();
        CHECK(run_sql(fx.w->db, "DELETE FROM validators WHERE pubkey_hash = "
                      "x'" "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4"
                      "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4"
                      "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4"
                      "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4'") == 0,
              "remove the duplicate");
        CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
              row_eq(&want, &got), "one row again: A found"); OK();
        CHECK(nodus_validator_v2_get(fx.w, vidD, &got) == -1,
              "the duplicate's roles row left alone = -1 (orphan)"); OK();
    }

    /* a STORED non-zero pending key + epoch (the slice-6 "pending
     * rotation" shape) is a malformed row on READ — HF-6 D1: the fields
     * are always zero; restored, the row reads again */
    {
        uint8_t ppk[DNAC_PUBKEY_SIZE];
        sqlite3_stmt *st = NULL;
        memset(ppk, 0x5A, sizeof(ppk));
        int ok = sqlite3_prepare_v2(fx.w->db, "UPDATE v2_validator_roles "
                     "SET pending_consensus_pubkey = ?1, "
                     "consensus_key_effective_epoch = 7 "
                     "WHERE validator_id = ?2", -1, &st, NULL) == SQLITE_OK &&
                 sqlite3_bind_blob(st, 1, ppk, (int)sizeof(ppk),
                                   SQLITE_STATIC) == SQLITE_OK &&
                 sqlite3_bind_blob(st, 2, vidA, 64, SQLITE_STATIC)
                     == SQLITE_OK &&
                 sqlite3_step(st) == SQLITE_DONE &&
                 sqlite3_changes(fx.w->db) == 1;
        if (st) sqlite3_finalize(st);
        CHECK(ok, "plant a pending key");
    }
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == -1,
          "a stored pending key = -1 (malformed)"); OK();
    CHECK(run_sql(fx.w->db, "UPDATE v2_validator_roles SET "
                  "pending_consensus_pubkey = zeroblob(2592), "
                  "consensus_key_effective_epoch = 0 WHERE validator_id = x'"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'") == 0,
          "zero it again");
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == 0 &&
          row_eq(&want, &got), "zeroed: the row reads again"); OK();

    /* a malformed roles row (owner_fp 63 bytes) is a fault */
    CHECK(run_sql(fx.w->db, "UPDATE v2_validator_roles SET owner_fp = "
                  "zeroblob(63) WHERE validator_id = x'"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'") == 0, "corrupt owner");
    CHECK(nodus_validator_v2_get(fx.w, vidA, &got) == -1,
          "malformed roles row = -1"); OK();

    /* the roles table missing = a fault, not "absent" */
    CHECK(run_sql(fx.w->db, "DROP TABLE v2_validator_roles") == 0, "drop");
    CHECK(nodus_validator_v2_get(fx.w, vidX, &got) == -1,
          "v2_get with no roles table = -1 (not absent)"); OK();

    fx_close(&fx);
    return 0;
}

/* ── 4. the gen-4 bonded_tenured arm ──────────────────────────────────── */

static int t_bonded_tenured(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();

    static dnac_validator_record_t vp, vq, vr;
    uint8_t vidP[64], vidQ[64], vidR[64], own[64];
    /* validator_id order is the REVERSE of the pubkey order, so the
     * collect order (pubkey ASC) is told apart from a key order */
    memset(vidP, 0xC9, 64);
    memset(vidQ, 0xC2, 64);
    memset(vidR, 0xC1, 64);
    memset(own, 0xB7, 64);
    make_validator(&vp, 0x31, 1, DNAC_VALIDATOR_ACTIVE);
    make_validator(&vq, 0x32, 1, DNAC_VALIDATOR_ELIGIBLE);
    make_validator(&vr, 0x33, 1, DNAC_VALIDATOR_RETIRING);
    CHECK(nodus_validator_insert(fx.w, &vq) == 0 &&
          nodus_validator_insert(fx.w, &vr) == 0 &&
          nodus_validator_insert(fx.w, &vp) == 0, "insert P Q R");

    /* the v1 function before the re-key (generations 1-3) */
    static dnac_validator_record_t v1out[4];
    int n1 = -1;
    CHECK(nodus_validator_bonded_tenured(fx.w, 1000, v1out, 4, &n1) == 0 &&
          n1 == 2, "v1 arm: two bonded candidates"); OK();

    CHECK(rekey(fx.w->db, vp.pubkey, vidP, own, 1) == 0 &&
          rekey(fx.w->db, vq.pubkey, vidQ, own, 1) == 0 &&
          rekey(fx.w->db, vr.pubkey, vidR, own, 1) == 0,
          "manual re-key of all three"); OK();

    nodus_v2_validator_row_t *out = calloc(4, sizeof(*out));
    CHECK(out != NULL, "heap rows");
    int n = -1;
    if (nodus_validator_v2_bonded_tenured(fx.w, 1000, out, 4, &n) != 0 ||
        n != 2) {
        free(out);
        CHECK(0, "v2 arm: two bonded candidates");
    }
    OK();
    int ord = memcmp(out[0].rec.pubkey, vp.pubkey, DNAC_PUBKEY_SIZE) == 0 &&
              memcmp(out[1].rec.pubkey, vq.pubkey, DNAC_PUBKEY_SIZE) == 0;
    int ids = memcmp(out[0].validator_id, vidP, 64) == 0 &&
              memcmp(out[1].validator_id, vidQ, 64) == 0 &&
              memcmp(out[0].owner_fp, own, 64) == 0;
    if (!ord || !ids) free(out);
    CHECK(ord, "pubkey ASC collect order (not validator_id order)"); OK();
    CHECK(ids, "each candidate's pubkey_hash is returned AS validator_id");
    OK();

    /* the v1 function, unchanged, still returns the same candidates (it
     * reads values, not keys) */
    n1 = -1;
    if (nodus_validator_bonded_tenured(fx.w, 1000, v1out, 4, &n1) != 0 ||
        n1 != 2 || !rec_eq(&v1out[0], &out[0].rec) ||
        !rec_eq(&v1out[1], &out[1].rec)) {
        free(out);
        CHECK(0, "v1 arm after the re-key: the same two records");
    }
    OK();

    /* tenure: a later joiner is not tenured at a small anchor */
    CHECK(run_sql(fx.w->db, "UPDATE validators SET active_since_block = "
                  "5000 WHERE status = 4") == 0, "Q joins at 5000");
    n = -1;
    int rc = nodus_validator_v2_bonded_tenured(fx.w, 1000, out, 4, &n);
    if (rc != 0 || n != 1 || memcmp(out[0].validator_id, vidP, 64) != 0) {
        free(out);
        CHECK(0, "the tenure filter is the v1 one");
    }
    OK();
    CHECK(run_sql(fx.w->db, "UPDATE validators SET active_since_block = 1 "
                  "WHERE status = 4") == 0, "Q back to genesis");

    /* more rows than the cap: a fault, never a truncation */
    n = -1;
    rc = nodus_validator_v2_bonded_tenured(fx.w, 1000, out, 1, &n);
    if (rc != -1) free(out);
    CHECK(rc == -1, "cap 1 with two candidates = -1"); OK();

    /* a candidate without its roles row: a fault */
    CHECK(run_sql(fx.w->db, "DELETE FROM v2_validator_roles WHERE "
                  "validator_id = x'"
                  "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"
                  "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"
                  "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"
                  "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2'") == 0, "drop Q's role");
    rc = nodus_validator_v2_bonded_tenured(fx.w, 1000, out, 4, &n);
    free(out);
    CHECK(rc == -1, "a candidate without roles = -1"); OK();

    fx_close(&fx);
    return 0;
}

/* ── 5. v2 delegations ────────────────────────────────────────────────── */

static int t_delegation_v2(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();

    uint8_t vidP[64], vidQ[64], vidR[64], vidX[64];
    uint8_t d0[64], d1[64], d2[64];
    memset(vidP, 0xC1, 64);
    memset(vidQ, 0xC2, 64);
    memset(vidR, 0xC3, 64);
    memset(vidX, 0xCF, 64);
    memset(d0, 0xD0, 64);
    memset(d1, 0xD1, 64);
    memset(d2, 0xD2, 64);
    /* inserted out of key order */
    CHECK(deleg_insert(fx.w->db, d1, vidP, 100, 5) == 0 &&
          deleg_insert(fx.w->db, d2, vidQ, 300, 7) == 0 &&
          deleg_insert(fx.w->db, d0, vidP, 200, 6) == 0, "seed"); OK();

    nodus_v2_delegation_row_t r;
    CHECK(nodus_delegation_v2_get(fx.w, d1, vidP, &r) == 0 &&
          memcmp(r.delegator_fp, d1, 64) == 0 &&
          memcmp(r.validator_id, vidP, 64) == 0 &&
          r.amount == 100 && r.delegated_at_block == 5,
          "get (d1, P): every field, keys bound as given"); OK();
    CHECK(nodus_delegation_v2_get(fx.w, d1, vidQ, &r) == 1,
          "get of an absent pair = 1"); OK();

    int c = -1;
    CHECK(nodus_delegation_v2_count_by_validator(fx.w, vidP, &c) == 0 &&
          c == 2, "count P = 2"); OK();
    CHECK(nodus_delegation_v2_count_by_validator(fx.w, vidQ, &c) == 0 &&
          c == 1, "count Q = 1"); OK();
    CHECK(nodus_delegation_v2_count_by_validator(fx.w, vidX, &c) == 0 &&
          c == 0, "count of an unknown validator = 0"); OK();

    nodus_v2_delegation_row_t L[4];
    int n = -1;
    CHECK(nodus_delegation_v2_list_by_validator(fx.w, vidP, L, 4, &n) == 0 &&
          n == 2, "list P = 2 rows"); OK();
    CHECK(memcmp(L[0].delegator_fp, d0, 64) == 0 && L[0].amount == 200 &&
          memcmp(L[1].delegator_fp, d1, 64) == 0 && L[1].amount == 100,
          "delegator_fp ASC, independent of insert order"); OK();
    CHECK(nodus_delegation_v2_list_by_validator(fx.w, vidX, L, 4, &n) == 0 &&
          n == 0, "list of an unknown validator = 0 rows"); OK();
    CHECK(nodus_delegation_v2_list_by_validator(fx.w, vidP, L, 1, &n) == -1,
          "more rows than the cap = -1, never a truncation"); OK();

    /* a malformed committed row (amount 0) is a fault */
    CHECK(deleg_insert(fx.w->db, d0, vidR, 0, 9) == 0, "amount-0 row");
    CHECK(nodus_delegation_v2_get(fx.w, d0, vidR, &r) == -1,
          "get of a malformed row = -1"); OK();
    CHECK(nodus_delegation_v2_list_by_validator(fx.w, vidR, L, 4, &n) == -1,
          "list over a malformed row = -1"); OK();

    CHECK(nodus_delegation_v2_delete(fx.w, d1, vidP) == 0, "delete (d1, P)");
    OK();
    CHECK(nodus_delegation_v2_delete(fx.w, d1, vidP) == 1,
          "delete again = 1 (absent)"); OK();
    CHECK(nodus_delegation_v2_count_by_validator(fx.w, vidP, &c) == 0 &&
          c == 1, "count P = 1 after the delete"); OK();
    CHECK(nodus_delegation_v2_get(fx.w, d0, vidP, &r) == 0 &&
          r.amount == 200, "the other row of P untouched"); OK();

    /* the table missing = a fault */
    CHECK(run_sql(fx.w->db, "DROP TABLE delegations") == 0, "drop");
    CHECK(nodus_delegation_v2_count_by_validator(fx.w, vidP, &c) == -1,
          "count with no table = -1"); OK();
    CHECK(nodus_delegation_v2_get(fx.w, d0, vidP, &r) == -1,
          "get with no table = -1 (not absent)"); OK();

    fx_close(&fx);
    return 0;
}

int main(void) {
    if (t_get_update() != 0) return 1;
    if (t_bonded_tenured() != 0) return 1;
    if (t_delegation_v2() != 0) return 1;
    printf("test_v2_valrow: ALL %d checks passed\n", g_checks);
    return 0;
}
