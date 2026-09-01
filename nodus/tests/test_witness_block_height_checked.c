/**
 * Nodus — O15O Faz 1 — a DB failure is never a height
 *
 * WHAT THIS PROVES.
 *   nodus_witness_block_height_checked separates the two answers the old
 *   accessor collapsed into a bare 0: "this chain is empty" (rc 0, *out 0)
 *   and "the query did not run" (rc -1, *out untouched). If that
 *   separation were false, every consensus consumer converted in O15O
 *   Faz 1 — the round anchor, the committee resolved at height+1, leader
 *   election, the signed VIEW_OK preimage — would resume treating a
 *   transient sqlite failure as "this chain is at genesis".
 *   Bug ref: nodus/BUGS.md O15N-L2. Rule: nodus/CLAUDE.md, "A DB failure
 *   is never a value."
 *
 *   Cases 7 and 8 prove the SECOND half of that separation, which is not
 *   symmetric: a missing database is itself two states, and the accessor
 *   splits them on chain_id along the O15L DG-1 matrix — the same split
 *   nodus_witness_bft.c's load_committee_at_height makes at :673-683. They
 *   are written as a PAIR on purpose: collapsing the matrix back to one
 *   verdict turns exactly one of them red, so neither alone would catch
 *   it. Case 7 in particular is what keeps a fresh cluster able to reach
 *   genesis at all.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: none beyond a default nodus build. The test is
 *   registered through register_witness_test, which supplies
 *   NODUS_WITNESS_INTERNAL_API; no fault-injection option, no
 *   QGP_FAULT_INJECT, no O15H_DIAG. Environment: none — no STAGEF_*, no
 *   NODUS_FAULT_*, no network, no files on disk. Every database is
 *   sqlite ":memory:", created and destroyed inside this process.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. No node directories, no arm files, no processes. The one
 *   external resource is the temporary file used to capture stderr in
 *   case 6; it is created with mkstemp, unlinked immediately, and the
 *   original stderr is restored before the test reports.
 *
 * HOW IT CAN LIE.
 *   - The fault is injected by DROPPING the queried table so
 *     sqlite3_prepare_v2 genuinely returns "no such table". If a future
 *     schema change made `blocks` / `v2_blocks` re-creatable behind the
 *     accessor's back, the prepare would succeed and cases 3/5/6 would
 *     pass while testing nothing. Each of those cases therefore ALSO
 *     asserts the sentinel in *out is untouched, which a successful
 *     prepare would overwrite — a silently-healed fault fails the test
 *     rather than passing it.
 *   - Case 7 asserts a SUCCESS with *out == 0, which is also what a
 *     stubbed-out accessor returning 0 unconditionally would produce. It
 *     is case 8, one chain_id byte away, that makes case 7 mean
 *     something: the pair cannot both pass unless the split is real.
 *   - Case 6 asserts the wrapper logged by capturing stderr. In a nodus
 *     build QGP_LOG_* resolves to nodus/src/nodus_log_shim.c, whose
 *     qgp_log_ring_add writes straight to stderr. Were the shim replaced
 *     by the real qgp_log.c (messenger tree), the ring buffer is disabled
 *     by default and NOTHING would be written — case 6's log assertion
 *     would then fail rather than silently pass, which is the intended
 *     direction.
 *   - There is no skip path. Every case runs unconditionally or the
 *     binary exits non-zero.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

/* A value no legitimate height can be, pre-loaded into *out before every
 * fault case. The contract says *out is UNTOUCHED on -1, so finding this
 * afterwards is the assertion; finding anything else means the accessor
 * wrote through on a fault, which is the fail-open being re-introduced. */
#define SENTINEL 0xDEADBEEFCAFEF00DULL

/* Only the two tables this accessor reads. The rest of the witness schema
 * is irrelevant here: no code path under test writes a block, applies a
 * transaction or computes a state_root, so a fuller fixture would add
 * surface without adding coverage. */
static const char *SCHEMA_LEGACY =
    "CREATE TABLE blocks (height INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  tx_root BLOB NOT NULL, tx_count INTEGER NOT NULL DEFAULT 1,"
    "  timestamp INTEGER NOT NULL, proposer_id BLOB,"
    "  prev_hash BLOB NOT NULL DEFAULT x'',"
    "  state_root BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0, chain_def_blob BLOB);";

/* Column list copied from the production DDL so this fixture cannot drift
 * away from it: nodus_witness_v2_schema.c, V2_TABLES_DDL. */
static const char *SCHEMA_V2 =
    "CREATE TABLE v2_blocks ("
    "  global_height INTEGER PRIMARY KEY,"
    "  block_id BLOB NOT NULL UNIQUE,"
    "  prev_block_id BLOB NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  tx_root BLOB NOT NULL,"
    "  domain_updates_root BLOB NOT NULL,"
    "  domains_root BLOB NOT NULL,"
    "  global_root BLOB NOT NULL,"
    "  vset_hash BLOB NOT NULL,"
    "  tx_count INTEGER NOT NULL,"
    "  qc BLOB);";

static void exec_or_die(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s\n  (%s)\n", err ? err : "(null)", sql);
        sqlite3_free(err);
        exit(1);
    }
}

/* nodus_witness_t is multi-MB — heap, never stack (repo discipline;
 * mirrors tests/test_bft_liveness.c:107). */
static nodus_witness_t *witness_new(const char *schema) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);
    CHECK(sqlite3_open(":memory:", &w->db) == SQLITE_OK);
    exec_or_die(w->db, schema);
    return w;
}

static void witness_free(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

int main(void) {
    printf("\nO15O Faz 1 — nodus_witness_block_height_checked\n");

    /* ── 1. An EMPTY legacy chain is SUCCESS at height 0 ───────────────
     * MAX(height) over an empty table yields one row holding NULL. This
     * is the case the whole change exists to keep distinguishable from a
     * fault, so it is asserted first: rc 0 AND *out written to 0. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_LEGACY);
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), 0);
        CHECK_EQ(out, 0);
        /* The fail-open wrapper agrees on the honest-empty answer. */
        CHECK_EQ(nodus_witness_block_height(w), 0);
        witness_free(w);
        printf("  1. empty legacy chain      -> rc=0, height=0        OK\n");
    }

    /* ── 2. A POPULATED legacy chain reports its tip ───────────────────
     * Three rows at 1/2/3; MAX is 3. Written directly rather than through
     * commit_batch: this test is about the accessor, and the block
     * machinery would drag in state_root, supply and committee fixtures
     * that cannot fail in a way this test would notice. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_LEGACY);
        exec_or_die(w->db,
            "INSERT INTO blocks (height, tx_root, timestamp, state_root) "
            "VALUES (1, x'AA', 1700000000, x'BB'),"
            "       (2, x'AA', 1700000001, x'BB'),"
            "       (3, x'AA', 1700000002, x'BB');");
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), 0);
        CHECK_EQ(out, 3);
        CHECK_EQ(nodus_witness_block_height(w), 3);
        witness_free(w);
        printf("  2. populated legacy chain  -> rc=0, height=3        OK\n");
    }

    /* ── 3. A LEGACY DB FAULT is -1, and *out is UNTOUCHED ─────────────
     * DROP TABLE blocks makes sqlite3_prepare_v2 return "no such table",
     * a genuine prepare failure — no mock, no injected predicate, no
     * compile flag. Before O15O this returned 0 and the caller could not
     * tell it from case 1. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_LEGACY);
        exec_or_die(w->db, "DROP TABLE blocks;");
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), -1);
        CHECK_EQ(out, SENTINEL);
        witness_free(w);
        printf("  3. legacy prepare fault    -> rc=-1, out untouched  OK\n");
    }

    /* ── 4. The SUCCESSOR branch has the same two answers ──────────────
     * v2_successor routes the accessor to v2_blocks. Empty is success at
     * 0; a row at global_height 7 is success at 7. Asserting the healthy
     * successor path here is what makes case 5 meaningful — otherwise a
     * successor branch that faulted unconditionally would pass case 5. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_V2);
        w->v2_successor = true;
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), 0);
        CHECK_EQ(out, 0);

        exec_or_die(w->db,
            "INSERT INTO v2_blocks (global_height, block_id, prev_block_id,"
            "  epoch, tx_root, domain_updates_root, domains_root,"
            "  global_root, vset_hash, tx_count) "
            "VALUES (7, x'01', x'00', 0, x'02', x'03', x'04', x'05',"
            "        x'06', 1);");
        out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), 0);
        CHECK_EQ(out, 7);
        CHECK_EQ(nodus_witness_block_height(w), 7);
        witness_free(w);
        printf("  4. successor chain         -> rc=0, empty 0 / tip 7 OK\n");
    }

    /* ── 5. A SUCCESSOR DB FAULT is -1, and *out is UNTOUCHED ──────────
     * The successor branch had the same fail-open and needs its own
     * evidence: a `blocks` table is deliberately left present and
     * populated, so a regression that fell through to the legacy branch
     * would answer 5 instead of faulting and this case would catch it. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_V2);
        exec_or_die(w->db, SCHEMA_LEGACY);
        exec_or_die(w->db,
            "INSERT INTO blocks (height, tx_root, timestamp, state_root) "
            "VALUES (5, x'AA', 1700000000, x'BB');");
        w->v2_successor = true;
        exec_or_die(w->db, "DROP TABLE v2_blocks;");
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), -1);
        CHECK_EQ(out, SENTINEL);
        witness_free(w);
        printf("  5. successor prepare fault -> rc=-1, out untouched  OK\n");
    }

    /* ── 6. The FAIL-OPEN wrapper still answers 0 on that same fault,
     *       AND it is not silent ────────────────────────────────────────
     * Two halves, and both are load-bearing. The 0 pins that O15O did NOT
     * change behaviour for the display / RPC callers deliberately left on
     * the wrapper (they are enumerated in the block comment above its
     * definition). The log is what makes the surviving fail-open
     * observable: without it an operator sees a chain that merely appears
     * to be at genesis, which is exactly how O15N-L2 stayed invisible.
     *
     * stderr is captured by swapping fd 2 onto a temp file and restoring
     * it afterwards, so a later CHECK failure still reports normally. */
    {
        nodus_witness_t *w = witness_new(SCHEMA_LEGACY);
        exec_or_die(w->db,
            "INSERT INTO blocks (height, tx_root, timestamp, state_root) "
            "VALUES (9, x'AA', 1700000000, x'BB');");
        /* Sanity: the wrapper reports the real tip while the table is
         * there, so the 0 below is caused by the DROP and nothing else. */
        CHECK_EQ(nodus_witness_block_height(w), 9);
        exec_or_die(w->db, "DROP TABLE blocks;");

        char tmpl[] = "/tmp/nodus_bh_checked_XXXXXX";
        int tmpfd = mkstemp(tmpl);
        CHECK(tmpfd >= 0);
        CHECK(unlink(tmpl) == 0);          /* leaves nothing behind */

        /* Every rc is captured, and stderr is restored BEFORE anything is
         * asserted — otherwise a failing CHECK inside the redirected
         * window would write its diagnosis into the temp file and the
         * test would exit 1 saying nothing. */
        fflush(stderr);
        int saved = dup(2);
        int redirected = (saved >= 0) ? dup2(tmpfd, 2) : -1;

        uint64_t open_answer = redirected >= 0
                                 ? nodus_witness_block_height(w)
                                 : 1;      /* not 0: forces a failure
                                            * rather than a false pass if
                                            * the redirect never happened */
        fflush(stderr);
        int restored = (saved >= 0) ? dup2(saved, 2) : -1;
        if (saved >= 0) close(saved);

        CHECK(redirected >= 0);
        CHECK(restored >= 0);
        CHECK_EQ(open_answer, 0);          /* fail-open preserved */

        /* It logged SOMETHING. If a future edit made both the checked
         * form and the wrapper silent, this is the assertion that goes
         * red — the fail-open would then be invisible again, which is the
         * defect O15N-L2 describes. */
        long end = (long)lseek(tmpfd, 0, SEEK_END);
        CHECK(end > 0);
        CHECK(lseek(tmpfd, 0, SEEK_SET) == 0);
        char buf[8192];
        ssize_t n = read(tmpfd, buf, sizeof(buf) - 1);
        CHECK(n > 0);
        buf[n] = '\0';
        close(tmpfd);

        /* Both lines: the checked form's sqlite diagnosis, and the
         * wrapper naming the fail-open it just took. */
        CHECK(strstr(buf, "prepare failed") != NULL);
        CHECK(strstr(buf, "FAIL-OPEN") != NULL);

        witness_free(w);
        printf("  6. wrapper on same fault   -> 0, and logged loudly  OK\n");
    }

    /* ── 7. NO DATABASE, chain_id ZERO — GENUINE PRE-GENESIS, SUCCESS ──
     *
     * THIS IS THE CASE THAT KEEPS A FRESH CLUSTER ABLE TO START. A node
     * running the genesis round has no chain database yet, because
     * nodus_witness_commit_genesis is what creates it
     * (nodus_witness_bft.c, nodus_witness_commit_genesis' opening
     * `if (!w->db)` bootstrap — named by FUNCTION, not by line, because
     * that file's comment blocks move its line numbers constantly).
     * If this answered -1, every converted
     * consumer would refuse at once — is_leader would not lead,
     * start_round would not open, handle_propose and handle_commit would
     * reject the genesis proposal — on every node simultaneously, and the
     * chain would never produce block 0.
     *
     * The rule is the O15L DG-1 matrix, and it is deliberately the SAME
     * rule nodus_witness_bft.c's load_committee_at_height applies at
     * :673-683 with the same 32-byte comparison. If one of those two gates
     * is ever changed without the other, a node takes its height from one
     * row of the matrix and its committee from the other; this case and
     * case 8 are the pair that pins them together. */
    {
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(NULL, &out), -1);
        CHECK_EQ(out, SENTINEL);

        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL);
        CHECK(w->db == NULL);          /* calloc leaves chain_id all zeros */
        out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), 0);
        CHECK_EQ(out, 0);
        /* The wrapper agrees, so the pre-genesis consumers still on it
         * (IDENT advert, RPC status) are unchanged. */
        CHECK_EQ(nodus_witness_block_height(w), 0);

        /* NULL out: -1, and no crash — checked before w is dereferenced. */
        CHECK_EQ(nodus_witness_block_height_checked(w, NULL), -1);
        free(w);
        printf("  7. pre-genesis, no database-> rc=0, height=0        OK\n");
    }

    /* ── 8. NO DATABASE, chain_id NON-ZERO — DG-1 ROW 2, FAULT ─────────
     *
     * The other arm, and the one that carries the O15N-L2 defect: a node
     * that HOLDS a chain and cannot read it. O15K's fix A produces this
     * state deliberately (the identity is installed before the database is
     * opened, so a failed open keeps it). Answering 0 here is not an
     * answer, it is the ABSENCE of one — and consumers of that 0 went on
     * to resolve a committee at height 1 for a chain that is not at
     * height 1.
     *
     * Only ONE byte of chain_id differs from case 7. That is the whole
     * discrimination, and it is why this case exists next to that one:
     * a regression that collapsed the matrix back to a single verdict
     * turns exactly one of the two red, never both. */
    {
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL);
        CHECK(w->db == NULL);
        w->chain_id[31] = 0x01;        /* holds a chain */
        uint64_t out = SENTINEL;
        CHECK_EQ(nodus_witness_block_height_checked(w, &out), -1);
        CHECK_EQ(out, SENTINEL);
        /* The wrapper still answers 0 — that is the surviving fail-open it
         * is named for, and the reason it logs. */
        CHECK_EQ(nodus_witness_block_height(w), 0);
        free(w);
        printf("  8. DG-1 row 2 (chain, no db)-> rc=-1, out untouched OK\n");
    }

    printf("O15O Faz 1 PASS\n");
    return 0;
}
