/**
 * Nodus — cometbft @v0.38.26 C port: `light/store` — the Store interface
 * and `light/store/db/db.go` over SQLite (shared/dnac/cmt_light_store.c).
 * Light client package 1, 2026-10-16 (Kurultay #25 item 1); no node path
 * opens a light store yet.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · the reference's behaviour: an empty store reports -1 for its first
 *     and last height; a saved block is found, counted and deletable;
 *     LightBlockBefore returns the greatest height strictly below; Prune
 *     keeps the newest `size` blocks; a height <= 0 is the reference's
 *     panic (CMT_FAULT);
 *   · the deviations Kurultay #25 item 7 requires (cmt_light_store.h
 *     D1-D7): re-saving a height does not change the count and replaces
 *     the bytes (D2); deleting an absent height does not change it (D4);
 *     the count after a prune is the count on disk after a restart (D3);
 *     a restart keeps every block and the count; two prefixes in one
 *     file keep separate counts (D5); a file whose stored count was
 *     altered is refused at open (D6); a row whose block is not the
 *     height it is stored under is refused (D7);
 *   · the Store callback table reaches the same functions;
 *   · a FAILED COMMIT (a second connection holds a read lock, so COMMIT
 *     cannot take the EXCLUSIVE lock and returns SQLITE_BUSY) is rolled
 *     back: the save is CMT_FAULT, Size() is unchanged, the row is not
 *     visible on the store's own connection, and once the lock is gone
 *     the next save succeeds. With the pre-fix code (COMMIT failure left
 *     the transaction open) the row WOULD be visible on the store's
 *     connection and the next save's BEGIN IMMEDIATE would fail — so this
 *     row tells the two apart.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, NO CLOCK — every time is a fixed value. Keys come from
 * `qgp_dsa87_keypair_derand` with fixed seeds. Each case makes its own
 * SQLite file with `mkstemp("test_cmt_light_store.XXXXXX")` in the
 * WORKING DIRECTORY (ctest runs it in the build directory), so parallel
 * runs never share a file. Large fixtures are heap-allocated.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success or failure of a check: every case unlinks its file
 * and the `-journal` beside it before it returns. A crash (a signal)
 * mid-case can leave one `test_cmt_light_store.XXXXXX` file in the
 * working directory.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The reference's `randLightBlock` (db_test.go:172-196) is ADAPTED:
 *     random chain id / hashes / address / `time.Now()` are fixed
 *     patterns, tmhash is 64 bytes and an address 32 (so the header
 *     passes this port's HeaderFromProto, as the reference's passes its
 *     own), and `RandValidatorSet(2, 1)` uses two fixed keys. Its
 *     ValidatorsHash does NOT match its set — as in the reference — so
 *     these blocks would fail LightBlock.ValidateBasic; the store never
 *     calls it, by the reference either.
 *  2. The D6 and D7 rows write the file through a SECOND SQLite
 *     connection while the store is idle (D7) or closed (D6). They prove
 *     the store's checks, not that an outside writer is impossible.
 *  2a. The failed-COMMIT row relies on SQLite's rollback-journal locking
 *     (the store leaves journal_mode at its DELETE default): a reader's
 *     SHARED lock does not block BEGIN IMMEDIATE (RESERVED) but does block
 *     COMMIT (EXCLUSIVE), and no busy timeout is set on either side. The
 *     row first PROBES that on a third connection in the same lock state
 *     (BEGIN IMMEDIATE ok, write ok, COMMIT == SQLITE_BUSY) and fails —
 *     rather than passing vacuously — if this SQLite build behaves
 *     otherwise. The store's own CMT_FAULT is then attributed to COMMIT by
 *     that probe plus the "row not visible" check; the store does not
 *     expose which statement failed.
 *  3. Durability (`PRAGMA synchronous=FULL`) is NOT exercised: a restart
 *     here is close + reopen, not a power cut.
 *  4. Test_Concurrency (db_test.go:130-170) is NOT ported: the port's
 *     store is single-owner by design (cmt_light_store.h, "mtx").
 *
 * ── REFERENCE CASES PORTED ─────────────────────────────────────────────
 * light/store/db/db_test.go: TestLast_FirstLightBlockHeight (:21-44),
 * Test_SaveLightBlock (:46-73), Test_LightBlockBefore (:75-91 — the
 * `assert.Panics` row is CMT_FAULT), Test_Prune (:93-128).
 * NOT PORTED: Test_Concurrency (:130-170), see 4 above.
 * PROJECT-AUTHORED: every deviation row, restart, prefixes, the failed
 * COMMIT, the callback
 * table, the NULL rows.
 *
 * @file test_cmt_light_store.c
 */

#include "dnac/cmt_light_store.h"
#include "dnac/cmt_light_block.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_tmhash.h"

#include "crypto/sign/qgp_dilithium.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        goto fail; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define NKEYS 2
#define T_SECONDS ((int64_t)1700000000)
#define BP CMT_BLOCK_PROTOCOL

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];

static cmt_valset_scratch_t  *g_scratch;
static cmt_light_block_buf_t *g_buf;

/* ══ fixtures ═════════════════════════════════════════════════════════ */

/* One light block of the shape db_test.go:172-196 builds. */
typedef struct {
    cmt_validator_t     storage[NKEYS];
    cmt_validator_set_t vs;
    cmt_header_t        h;
    cmt_commit_t        c;          /* `&types.Commit{}` (:192) */
    cmt_signed_header_t sh;
    cmt_light_block_t   lb;
} tlb_t;

static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 13u * (unsigned)i) & 0xFFu);
    }
}

static int build_keys(void)
{
    uint8_t seed[32];
    uint8_t addr[CMT_ADDRESS_SIZE];
    int     i;

    for (i = 0; i < NKEYS; i++) {
        memset(seed, (uint8_t)(0x71 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0 ||
            cmt_pubkey_address(g_pk[i], addr) != CMT_OK) {
            fprintf(stderr, "key %d failed\n", i);
            return 1;
        }
    }
    return 0;
}

/* db_test.go:172-196 `randLightBlock(height)`, ADAPTED (header, 1).
 * `app_seed` varies AppHash so that two blocks of one height differ. */
static int rand_light_block(tlb_t *t, int64_t height, uint8_t app_seed)
{
    cmt_validator_t     list[NKEYS];
    cmt_pb_public_key_t pk;
    size_t              i;
    static const char   chain[] = "abcdefghijkl";   /* cmtrand.Str(12) */

    /* :173 `RandValidatorSet(2, 1)`. */
    for (i = 0; i < NKEYS; i++) {
        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, 1, &list[i]) != CMT_OK) {
            return 1;
        }
    }
    if (cmt_validator_set_init(&t->vs, t->storage, NKEYS) != CMT_OK ||
        cmt_validator_set_new(&t->vs, list, NKEYS, g_scratch) != CMT_OK) {
        return 1;
    }

    cmt_pb_header_init(&t->h);
    t->h.version.block = BP;                                   /* :177 */
    t->h.version.app   = 0;
    memcpy(t->h.chain_id, chain, sizeof(chain) - 1u);          /* :178 */
    t->h.chain_id_len  = sizeof(chain) - 1u;
    t->h.height        = height;                               /* :179 */
    t->h.time.seconds  = T_SECONDS;                            /* :180 */
    t->h.time.nanos    = 0;
    /* :181 LastBlockID stays zero. :182-190 the hashes and address. */
    pat(t->h.last_commit_hash, CMT_TMHASH_SIZE, 0x01);
    t->h.last_commit_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.data_hash, CMT_TMHASH_SIZE, 0x02);
    t->h.data_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.validators_hash, CMT_TMHASH_SIZE, 0x03);
    t->h.validators_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.next_validators_hash, CMT_TMHASH_SIZE, 0x04);
    t->h.next_validators_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.consensus_hash, CMT_TMHASH_SIZE, 0x05);
    t->h.consensus_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.app_hash, CMT_TMHASH_SIZE, app_seed);
    t->h.app_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.last_results_hash, CMT_TMHASH_SIZE, 0x07);
    t->h.last_results_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.evidence_hash, CMT_TMHASH_SIZE, 0x08);
    t->h.evidence_hash_len = CMT_TMHASH_SIZE;
    pat(t->h.proposer_address, CMT_ADDRESS_SIZE, 0x09);
    t->h.proposer_address_len = CMT_ADDRESS_SIZE;

    cmt_pb_commit_init(&t->c);                                 /* :192 */
    t->c.signatures     = NULL;
    t->c.signatures_cap = 0u;

    t->sh.header        = &t->h;
    t->sh.commit        = &t->c;
    t->lb.signed_header = &t->sh;
    t->lb.validator_set = &t->vs;
    return 0;
}

/* Save rand_light_block(height). */
static int save_h(cmt_light_store_db_t *s, int64_t height)
{
    tlb_t *t = calloc(1, sizeof(*t));
    int    rc;

    if (t == NULL || rand_light_block(t, height, 0x06) != 0) {
        free(t);
        return CMT_FAULT;
    }
    rc = cmt_light_store_db_save_light_block(s, &t->lb);
    free(t);
    return rc;
}

static uint64_t size_of(cmt_light_store_db_t *s)
{
    uint64_t n = UINT64_MAX;

    (void)cmt_light_store_db_size(s, &n);
    return n;
}

/* A fresh temporary file in the working directory. */
static int temp_path(char *path, size_t cap)
{
    int fd;

    if (cap < sizeof("test_cmt_light_store.XXXXXX")) {
        return 1;
    }
    memcpy(path, "test_cmt_light_store.XXXXXX",
           sizeof("test_cmt_light_store.XXXXXX"));
    fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed\n");
        return 1;
    }
    (void)close(fd);
    return 0;
}

static void remove_db(const char *path)
{
    char journal[96];

    (void)unlink(path);
    (void)snprintf(journal, sizeof(journal), "%s-journal", path);
    (void)unlink(journal);
}

/* Run one SQL statement on a SECOND connection to `path`. */
static int raw_exec(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int      rc;

    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : 1;
}

/* ══ 1. TestLast_FirstLightBlockHeight (db_test.go:21-44) ════════════ */

static int t_last_first(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    int64_t               h = 0;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"TestLast_FirstLightBlockHeight",
                                  30, BP, &s) == CMT_OK, "open");
    /* :24-31 Empty store. */
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == -1, "empty last");
    CHECK(cmt_light_store_db_first_light_block_height(s, &h) == CMT_OK &&
          h == -1, "empty first");
    OK();
    /* :33-43 1 key. */
    CHECK(save_h(s, 1) == CMT_OK, "save 1");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == 1, "last 1");
    CHECK(cmt_light_store_db_first_light_block_height(s, &h) == CMT_OK &&
          h == 1, "first 1");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* ══ 2. Test_SaveLightBlock (db_test.go:46-73) ═══════════════════════ */

static int t_save(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    bool                  found = true;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"Test_SaveLightBlockAndValidatorSet",
                                  34, BP, &s) == CMT_OK, "open");
    /* :49-52 Empty store — not found. */
    CHECK(cmt_light_store_db_light_block(s, 1, g_buf, &found) == CMT_OK &&
          !found && g_buf->lb.signed_header == NULL, "empty get");
    OK();
    /* :54-64 1 key. */
    CHECK(save_h(s, 1) == CMT_OK, "save");
    CHECK(size_of(s) == 1u, "size 1");
    CHECK(cmt_light_store_db_light_block(s, 1, g_buf, &found) == CMT_OK &&
          found && g_buf->lb.signed_header != NULL &&
          g_buf->lb.signed_header->header != NULL &&
          g_buf->lb.signed_header->header->height == 1 &&
          g_buf->lb.validator_set != NULL &&
          g_buf->lb.validator_set->validators_len == NKEYS, "get 1");
    OK();
    /* :66-72 Delete → not found again. */
    CHECK(cmt_light_store_db_delete_light_block(s, 1) == CMT_OK, "delete");
    CHECK(cmt_light_store_db_light_block(s, 1, g_buf, &found) == CMT_OK &&
          !found, "get after delete");
    CHECK(size_of(s) == 0u, "size 0");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* ══ 3. Test_LightBlockBefore (db_test.go:75-91) ═════════════════════ */

static int t_before(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    bool                  found = true;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"Test_LightBlockBefore",
                                  21, BP, &s) == CMT_OK, "open");
    /* :78-81 — `assert.Panics(LightBlockBefore(0))` → CMT_FAULT. The
     * second call inside that closure (LightBlockBefore(100)) is never
     * reached in the reference: the first one panics. */
    CHECK(cmt_light_store_db_light_block_before(s, 0, g_buf, &found)
              == CMT_FAULT, "before 0");
    OK();
    /* PROJECT-AUTHORED: on an empty store, nothing is before 100. */
    CHECK(cmt_light_store_db_light_block_before(s, 100, g_buf, &found)
              == CMT_OK && !found, "before 100 empty");
    OK();
    /* :83-90 */
    CHECK(save_h(s, 2) == CMT_OK, "save 2");
    CHECK(cmt_light_store_db_light_block_before(s, 3, g_buf, &found)
              == CMT_OK && found &&
          g_buf->lb.signed_header->header->height == 2, "before 3");
    OK();
    /* PROJECT-AUTHORED: the bound is strict — nothing is before 2. */
    CHECK(cmt_light_store_db_light_block_before(s, 2, g_buf, &found)
              == CMT_OK && !found, "before 2");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* ══ 4. Test_Prune (db_test.go:93-128) ═══════════════════════════════ */

static int t_prune(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    int64_t               h = 0;
    int                   i;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"Test_Prune", 10,
                                  BP, &s) == CMT_OK, "open");
    /* :96-99 Empty store. */
    CHECK(size_of(s) == 0u, "empty size");
    CHECK(cmt_light_store_db_prune(s, 0) == CMT_OK, "prune 0 empty");
    OK();
    /* :101-113 One header. */
    CHECK(save_h(s, 2) == CMT_OK, "save 2");
    CHECK(size_of(s) == 1u, "size 1");
    CHECK(cmt_light_store_db_prune(s, 1) == CMT_OK && size_of(s) == 1u,
          "prune 1");
    CHECK(cmt_light_store_db_prune(s, 0) == CMT_OK && size_of(s) == 0u,
          "prune 0");
    OK();
    /* :115-127 Multiple headers. */
    for (i = 1; i <= 10; i++) {
        CHECK(save_h(s, i) == CMT_OK, "save i");
    }
    CHECK(cmt_light_store_db_prune(s, 11) == CMT_OK && size_of(s) == 10u,
          "prune 11");
    CHECK(cmt_light_store_db_prune(s, 7) == CMT_OK && size_of(s) == 7u,
          "prune 7");
    OK();
    /* PROJECT-AUTHORED: Prune removed the OLDEST (db.go:233-257). */
    CHECK(cmt_light_store_db_first_light_block_height(s, &h) == CMT_OK &&
          h == 4, "first after prune");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == 10, "last after prune");
    OK();
    /* D3: the count after a prune is the count on disk. */
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"Test_Prune", 10,
                                  BP, &s) == CMT_OK && size_of(s) == 7u,
          "count after prune survives restart");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* ══ 5. the deviations (PROJECT-AUTHORED) ════════════════════════════ */

/* D2 idempotent save, D4 delete of an absent height. */
static int t_idempotent(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    tlb_t                *t = calloc(1, sizeof(*t));
    bool                  found = false;

    if (t == NULL) {
        return 1;
    }
    if (temp_path(path, sizeof(path)) != 0) {
        free(t);
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK, "open");
    CHECK(save_h(s, 1) == CMT_OK && save_h(s, 1) == CMT_OK, "save twice");
    CHECK(size_of(s) == 1u, "D2: re-save does not count");
    OK();
    /* A re-save with other bytes REPLACES them (db.go:62 `Set`). */
    CHECK(rand_light_block(t, 1, 0x66) == 0 &&
          cmt_light_store_db_save_light_block(s, &t->lb) == CMT_OK &&
          size_of(s) == 1u, "re-save other bytes");
    CHECK(cmt_light_store_db_light_block(s, 1, g_buf, &found) == CMT_OK &&
          found && g_buf->lb.signed_header->header->app_hash[0] == 0x66u,
          "replaced bytes");
    OK();
    /* D4: deleting an absent height leaves the count. */
    CHECK(cmt_light_store_db_delete_light_block(s, 9) == CMT_OK &&
          size_of(s) == 1u, "D4: delete absent");
    OK();
    /* The count on disk agrees (D6 would refuse the reopen otherwise). */
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK &&
          size_of(s) == 1u, "reopen");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    free(t);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    free(t);
    return 1;
}

/* Restart persistence: close + reopen keeps the blocks and the count. */
static int t_restart(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    int64_t               h = 0;
    bool                  found = false;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"r", 1, BP, &s)
              == CMT_OK, "open");
    CHECK(save_h(s, 1) == CMT_OK && save_h(s, 2) == CMT_OK &&
          save_h(s, 3) == CMT_OK, "save 1..3");
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"r", 1, BP, &s)
              == CMT_OK, "reopen");
    CHECK(size_of(s) == 3u, "size after restart");
    CHECK(cmt_light_store_db_first_light_block_height(s, &h) == CMT_OK &&
          h == 1, "first after restart");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == 3, "last after restart");
    CHECK(cmt_light_store_db_light_block(s, 2, g_buf, &found) == CMT_OK &&
          found && g_buf->lb.signed_header->header->height == 2,
          "block after restart");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* D5 a count per prefix, D6 an altered count is refused at open. */
static int t_prefix_and_count_check(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    int64_t               h = 0;
    uint8_t               long_prefix[CMT_LIGHT_STORE_PREFIX_MAX + 1u];

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"a", 1, BP, &s)
              == CMT_OK, "open a");
    CHECK(save_h(s, 1) == CMT_OK && save_h(s, 2) == CMT_OK, "save a");
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"b", 1, BP, &s)
              == CMT_OK, "open b");
    CHECK(size_of(s) == 0u, "D5: b starts empty");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == -1, "D5: b sees no block of a");
    CHECK(save_h(s, 1) == CMT_OK && size_of(s) == 1u, "save b");
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"a", 1, BP, &s)
              == CMT_OK && size_of(s) == 2u, "D5: a keeps its count");
    cmt_light_store_db_close(s);
    s = NULL;
    OK();

    /* D6: alter the stored count of "a" (prefix BLOB x'61'). */
    CHECK(raw_exec(path, "UPDATE cmt_light_size SET size = 99"
                         " WHERE prefix = x'61'") == 0, "tamper");
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"a", 1, BP, &s)
              == CMT_REJECT && s == NULL, "D6: altered count refused");
    OK();
    /* The other prefix is untouched and still opens. */
    CHECK(cmt_light_store_db_open(path, (const uint8_t *)"b", 1, BP, &s)
              == CMT_OK && size_of(s) == 1u, "b still opens");
    cmt_light_store_db_close(s);
    s = NULL;
    OK();

    /* A prefix above CMT_LIGHT_STORE_PREFIX_MAX is refused. */
    memset(long_prefix, 'p', sizeof(long_prefix));
    CHECK(cmt_light_store_db_open(path, long_prefix, sizeof(long_prefix),
                                  BP, &s) == CMT_REJECT && s == NULL,
          "long prefix");
    OK();
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* D7 a row whose block is not the height it is stored under. */
static int t_height_mismatch(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    bool                  found = true;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK, "open");
    CHECK(save_h(s, 5) == CMT_OK, "save 5");
    /* Move the row's KEY to 6 behind the store's back; the bytes still
     * hold height 5. The count is unchanged (one row, count 1). */
    CHECK(raw_exec(path, "UPDATE cmt_light_block SET height = 6"
                         " WHERE height = 5") == 0, "move key");
    CHECK(cmt_light_store_db_light_block(s, 6, g_buf, &found) == CMT_REJECT &&
          !found && g_buf->lb.signed_header == NULL, "D7: refused");
    CHECK(cmt_light_store_db_light_block(s, 5, g_buf, &found) == CMT_OK &&
          !found, "nothing at 5");
    /* LightBlockBefore reaches the same check (db.go:206). */
    CHECK(cmt_light_store_db_light_block_before(s, 7, g_buf, &found)
              == CMT_REJECT && !found, "D7 via before");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* A COMMIT that fails is rolled back (cmt_light_store.c tx_finish). */
static int t_commit_fails(void)
{
    char                  path[64];
    cmt_light_store_db_t *s      = NULL;
    sqlite3              *reader = NULL;
    sqlite3              *probe  = NULL;
    int64_t               h      = 0;
    int                   prc;

    if (temp_path(path, sizeof(path)) != 0) {
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK, "open");
    CHECK(save_h(s, 1) == CMT_OK && size_of(s) == 1u, "save 1");

    /* A second connection opens a read transaction and keeps its SHARED
     * lock until it commits. */
    CHECK(sqlite3_open(path, &reader) == SQLITE_OK, "open reader");
    CHECK(sqlite3_exec(reader, "BEGIN; SELECT COUNT(*) FROM cmt_light_block;",
                       NULL, NULL, NULL) == SQLITE_OK, "reader lock");

    /* PROBE (see header 2a): in this lock state BEGIN IMMEDIATE and a
     * write succeed, and COMMIT is SQLITE_BUSY. */
    CHECK(sqlite3_open(path, &probe) == SQLITE_OK, "open probe");
    CHECK(sqlite3_exec(probe, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK,
          "probe: BEGIN IMMEDIATE is not blocked by a reader");
    CHECK(sqlite3_exec(probe, "INSERT INTO cmt_light_size (prefix, size)"
                              " VALUES (x'7a7a', 0)", NULL, NULL, NULL)
              == SQLITE_OK, "probe: write");
    prc = sqlite3_exec(probe, "COMMIT", NULL, NULL, NULL);
    (void)sqlite3_exec(probe, "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(probe);
    probe = NULL;
    CHECK(prc == SQLITE_BUSY,
          "probe: COMMIT is SQLITE_BUSY under a reader (else this row "
          "cannot exercise the failed-COMMIT path)");
    OK();

    /* The store's save reaches COMMIT, which fails: FAULT, nothing kept. */
    CHECK(save_h(s, 2) == CMT_FAULT, "save under a reader is FAULT");
    CHECK(size_of(s) == 1u, "Size unchanged");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == 1, "the uncommitted row is not visible");
    OK();

    /* Release the lock; the store is usable again. */
    CHECK(sqlite3_exec(reader, "COMMIT", NULL, NULL, NULL) == SQLITE_OK,
          "reader release");
    sqlite3_close(reader);
    reader = NULL;
    CHECK(save_h(s, 2) == CMT_OK && size_of(s) == 2u, "next save succeeds");
    CHECK(cmt_light_store_db_last_light_block_height(s, &h) == CMT_OK &&
          h == 2, "row 2 now visible");
    /* The count on disk agrees (D6 would refuse the reopen otherwise). */
    cmt_light_store_db_close(s);
    s = NULL;
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK &&
          size_of(s) == 2u, "reopen");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    return 0;
fail:
    if (probe != NULL) {
        sqlite3_close(probe);
    }
    if (reader != NULL) {
        (void)sqlite3_exec(reader, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(reader);
    }
    cmt_light_store_db_close(s);
    remove_db(path);
    return 1;
}

/* The Store table (store.go:5-48) and the reference's panics as FAULT. */
static int t_table_and_faults(void)
{
    char                  path[64];
    cmt_light_store_db_t *s = NULL;
    cmt_light_store_t     st;
    tlb_t                *t = calloc(1, sizeof(*t));
    cmt_light_block_t     no_header;
    cmt_signed_header_t   sh_nil;
    uint64_t              n = 0u;
    int64_t               h = 0;
    bool                  found = false;

    if (t == NULL) {
        return 1;
    }
    if (temp_path(path, sizeof(path)) != 0) {
        free(t);
        return 1;
    }
    CHECK(cmt_light_store_db_open(path, NULL, 0, BP, &s) == CMT_OK, "open");
    cmt_light_store_db_bind(s, &st);
    CHECK(rand_light_block(t, 4, 0x06) == 0 &&
          st.save_light_block(st.ctx, &t->lb) == CMT_OK, "table save");
    CHECK(st.size(st.ctx, &n) == CMT_OK && n == 1u, "table size");
    CHECK(st.light_block(st.ctx, 4, g_buf, &found) == CMT_OK && found,
          "table get");
    CHECK(st.last_light_block_height(st.ctx, &h) == CMT_OK && h == 4 &&
          st.first_light_block_height(st.ctx, &h) == CMT_OK && h == 4,
          "table first / last");
    CHECK(st.light_block_before(st.ctx, 5, g_buf, &found) == CMT_OK && found,
          "table before");
    CHECK(st.prune(st.ctx, 0) == CMT_OK && st.size(st.ctx, &n) == CMT_OK &&
          n == 0u, "table prune");
    CHECK(st.delete_light_block(st.ctx, 4) == CMT_OK, "table delete");
    OK();

    /* db.go:43-45, :81-83, :108-110 — height <= 0 panics → FAULT. */
    t->h.height = 0;
    CHECK(cmt_light_store_db_save_light_block(s, &t->lb) == CMT_FAULT,
          "save height 0");
    CHECK(cmt_light_store_db_delete_light_block(s, 0) == CMT_FAULT &&
          cmt_light_store_db_delete_light_block(s, -1) == CMT_FAULT,
          "delete height <= 0");
    CHECK(cmt_light_store_db_light_block(s, 0, g_buf, &found) == CMT_FAULT,
          "get height 0");
    /* A nil signed header / header is the dereference panic of :43. */
    sh_nil.header = NULL;
    sh_nil.commit = NULL;
    no_header.signed_header = &sh_nil;
    no_header.validator_set = &t->vs;
    CHECK(cmt_light_store_db_save_light_block(s, &no_header) == CMT_FAULT,
          "save without header");
    no_header.signed_header = NULL;
    CHECK(cmt_light_store_db_save_light_block(s, &no_header) == CMT_FAULT,
          "save without signed header");
    CHECK(cmt_light_store_db_save_light_block(NULL, &t->lb) == CMT_FAULT &&
          cmt_light_store_db_size(s, NULL) == CMT_FAULT, "NULL");
    CHECK(size_of(s) == 0u, "faults left the count alone");
    OK();
    cmt_light_store_db_close(s);
    remove_db(path);
    free(t);
    return 0;
fail:
    cmt_light_store_db_close(s);
    remove_db(path);
    free(t);
    return 1;
}

int main(void)
{
    int rc = 1;

    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    g_buf     = cmt_light_block_buf_new();
    if (g_scratch == NULL || g_buf == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    if (build_keys() != 0) goto out;
    if (t_last_first() != 0) goto out;
    if (t_save() != 0) goto out;
    if (t_before() != 0) goto out;
    if (t_prune() != 0) goto out;
    if (t_idempotent() != 0) goto out;
    if (t_restart() != 0) goto out;
    if (t_prefix_and_count_check() != 0) goto out;
    if (t_height_mismatch() != 0) goto out;
    if (t_table_and_faults() != 0) goto out;
    if (t_commit_fails() != 0) goto out;

    printf("test_cmt_light_store: %d checks OK\n", g_checks);
    rc = 0;
out:
    cmt_light_block_buf_free(g_buf);
    free(g_scratch);
    return rc;
}
