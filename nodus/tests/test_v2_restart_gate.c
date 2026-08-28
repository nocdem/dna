/**
 * @file nodus/tests/test_v2_restart_gate.c
 * @brief O15A obligation 6 — every path that brings a chain database to a
 *        usable state runs the SAME integrity gate.
 *
 * ── THE BYPASS ────────────────────────────────────────────────────────
 * A chain database becomes live two ways:
 *   1. nodus_witness_create_chain_db — used ONCE, at creation.
 *   2. witness_scan_chain_db          — used on EVERY ordinary restart.
 *
 * The S7 pool-state verification and the O14 version-firewall selfcheck
 * lived inline in (1) only. So a database that would have been refused at
 * creation was accepted on every subsequent boot — and since creation
 * happens once and restarts happen forever, the checked path was the rare
 * one. O14 noted the seam and left it unowned; O15A closes it.
 *
 * ── AND TWO MORE DEFECTS IN THE SAME FUNCTION ─────────────────────────
 * The scanner also derived this node's chain identity from the FILENAME,
 * with a parse that failed OPEN (any length 2..64, remaining bytes left
 * zero, a bad hex digit silently truncating), and picked the FIRST match
 * from readdir — an order the filesystem defines, not a stable total key.
 * The archive helper's own comment records that first-match-wins once
 * activated the wrong chain in production (EU-6, 2026-04-10).
 *
 * ── AND, SINCE O15L FAZ 4, THE OTHER DIRECTION (case 12) ─────────────
 * The same file also owns the reverse transition: what a node keeps when
 * its chain database is DROPPED. drop_witness_db zeroed `chain_id` but
 * left `v2_successor` and `v2_chain32` behind, so a dropped successor
 * chain left the node claiming to be a successor of a chain it no longer
 * had. Case 12 pins that the legacy identity and the V2 identity are
 * cleared together. It needs nothing beyond a default build and leaves
 * its mkdtemp directory (with the armed recovery sentinel) behind.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>   /* access/F_OK — case 12 proves the drop unlinked */
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
/* O15L Faz 4 / F-6 — the halt-recovery entry is the ONLY caller-visible
 * door to drop_witness_db (which is file-static in nodus_witness_sync.c),
 * and deriving a peer's witness_id is how the recovery quorum matches a
 * peer to the halt-time committee snapshot. */
#include "witness/nodus_witness_sync.h"
#include "nodus/nodus_chain_config.h"

/* ── O15L Faz 1 — the two chain-identity gates under test ─────────────
 *
 *   verify_chain_id               defined in nodus_witness_bft.c
 *   witness_chain_quorum_observe  defined in nodus_witness_peer.c
 *
 * Both are non-static in the library for exactly the reason the header
 * block of nodus_witness_bft_internal.h already records for this
 * project: "static + test linkage is incompatible in CMake's normal
 * flow ... the protection is 'no public header references them' rather
 * than 'static qualifier'." Production code reaching for either symbol
 * is a code-review failure, not a linker error.
 *
 * O15L Faz 5 — this file used to REPEAT both prototypes locally, and C
 * accepts that silently: linkage does not compare signatures, so a local
 * copy that drifted from its definition would surface as a wrong-ABI
 * call at run time, never as a compile error. The canonical prototypes
 * now live in nodus_witness_bft_internal.h, and the test_v2_restart_gate
 * target carries NODUS_WITNESS_INTERNAL_API (nodus/CMakeLists.txt), which
 * is what opens that header's #error gate for this translation unit.
 * Including it makes every call below signature-checked against the one
 * declaration instead of against a copy.
 *
 * The check runs in ONE direction only, and the two definitions say so
 * in their own comments: nodus_witness_bft.c and nodus_witness_peer.c do
 * NOT include this header. Its gate demands a macro the build system
 * attaches to test executables and to no library target — the single
 * library TU that has it, nodus_witness_fault.c, #defines it for itself
 * under QGP_FAULT_INJECT, so reaching in is never silent — and whose
 * name CMakeLists.txt additionally turns into a FATAL_ERROR if set as a
 * CMake variable in a Release configure. So a signature change breaks
 * the compile of THIS test, which is the intended alarm; it does not
 * make the definitions and the header agree, and that pairing stays a
 * review obligation. */
#include "witness/nodus_witness_bft_internal.h"

/* ── O15L Faz 2 — the scan's THREE outcomes, MIRRORED ─────────────────
 *
 * nodus_witness_scan_chain_db used to answer a yes/no question, and its
 * caller printed "no chain DB found — pre-genesis state" for every no —
 * including the no that means "a chain database is RIGHT THERE and I
 * could not open it". The function now separates:
 *
 *    0   the chain database is open and gated
 *   -1   ABSENT              the directory was READ and holds no chain DB
 *   -2   UNUSABLE_TRANSIENT  present; a transient fault outlived the
 *                            bounded in-process retries
 *   -3   UNUSABLE_PERMANENT  present; a permanent fault — or the data
 *                            directory itself could not be read
 *
 * The values live as file-local #defines in nodus_witness.c because
 * nodus/src/witness/nodus_witness.h — their proper home — is outside the
 * write whitelist of the dispatch that added them. C does not check a
 * caller's idea of a return code against the callee's, so these three
 * lines MUST be kept in step with nodus_witness.c BY HAND — they still
 * carry the copy-drift risk the two prototypes above shed when their
 * canonical declaration moved into a header this file includes. */
#define W_SCAN_ABSENT              (-1)
#define W_SCAN_UNUSABLE_TRANSIENT  (-2)
#define W_SCAN_UNUSABLE_PERMANENT  (-3)

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

/* nodus_witness_open() is the production restart entry: it scans the data
 * directory and adopts whatever chain database it finds. */
static nodus_witness_t *fresh_witness(const char *dir) {
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB — heap */
    if (!w) return NULL;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    return w;
}

static void close_witness(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

/* ── O15L — a witness pinned into ONE cell of the DG-1 matrix.
 *
 * `cid16` NULL means the all-zero identity; a non-NULL one is installed
 * in the canonical 16-bytes-then-zero layout nodus_witness_set_chain_id
 * produces. `with_db` attaches a REAL in-memory handle — never a fake
 * pointer, because close_witness calls sqlite3_close on it.
 *
 * The witness is heap-allocated (multi-MB struct) and one is built per
 * case, so a quarantine latched by one case cannot bleed into the next:
 * witness_chain_quorum_observe's flag is sticky by design. */
static nodus_witness_t *matrix_witness(const uint8_t *cid16, int with_db) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (cid16) {
        memcpy(w->chain_id, cid16, 16);
        memset(w->chain_id + 16, 0, 16);
    }
    if (with_db && sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    /* The observation window (WITNESS_CHAIN_QUORUM_WINDOW_SEC, 300 s from
     * activated_at_sec) is checked AFTER the identity matrix. Left at the
     * calloc'd zero it has always expired, so every observation would be
     * skipped for a reason that has nothing to do with the matrix and the
     * ENFORCE rows below would pass while proving nothing. */
    w->activated_at_sec = (uint64_t)time(NULL);
    return w;
}

/* Create a chain database in `dir`, then close the handle, leaving the
 * file on disk exactly as a restart would find it. */
static int seed_chain(const char *dir, const uint8_t cid16[16],
                      char *path_out, size_t path_cap) {
    nodus_witness_t *w = fresh_witness(dir);
    if (!w) return -1;
    if (nodus_witness_create_chain_db(w, cid16) != 0) {
        close_witness(w);
        return -1;
    }
    char hex[33];
    for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02x", cid16[i]);
    snprintf(path_out, path_cap, "%s/witness_%s.db", dir, hex);
    close_witness(w);
    return 0;
}

int main(void) {
    printf("=== O15A obligation 6 — restart runs the same gate ===\n");

    char dir[256];
    snprintf(dir, sizeof(dir), "/tmp/test_v2_restart_XXXXXX");
    CHECK(mkdtemp(dir) != NULL, "tmpdir");

    uint8_t cid[16];
    memset(cid, 0x5c, sizeof(cid));
    char db_path[512];
    CHECK(seed_chain(dir, cid, db_path, sizeof(db_path)) == 0, "seed chain");

    /* ── 1. BASELINE: a healthy database reopens through the restart
     * path. Without this the refusal tests below could pass on a scanner
     * that never succeeds at all. */
    {
        nodus_witness_t *w = fresh_witness(dir);
        CHECK(w != NULL, "alloc");
        int rc = nodus_witness_scan_chain_db(w);
        CHECK(rc == 0, "healthy database must reopen");
        CHECK(w->db != NULL, "reopen must leave an open handle");
        /* The adopted chain id must be the one in the filename, in the
         * canonical 16-byte-then-zero layout. */
        CHECK(memcmp(w->chain_id, cid, 16) == 0, "chain id adopted");
        for (int i = 16; i < 32; i++)
            CHECK(w->chain_id[i] == 0, "chain id upper half must be zero");
        close_witness(w);
    }

    /* ── 2. REPEATED restart is idempotent and does not mutate. */
    {
        for (int i = 0; i < 3; i++) {
            nodus_witness_t *w = fresh_witness(dir);
            CHECK(w != NULL, "alloc");
            CHECK(nodus_witness_scan_chain_db(w) == 0, "repeated restart");
            close_witness(w);
        }
    }

    /* ── 3. THE GATE IS ACTUALLY RUN ON RESTART.
     * Corrupt the S7 pool state so the startup check must refuse, then
     * restart. Before O15A this database opened happily, because the
     * scanner ran no checks at all. */
    {
        /* Bring the database to a version where pool state exists, then
         * plant a nullifier row that the committed accumulator cannot
         * account for — the exact disagreement the S7 check exists to
         * catch. */
        nodus_witness_t *w = fresh_witness(dir);
        CHECK(w != NULL, "alloc");
        CHECK(nodus_witness_scan_chain_db(w) == 0, "open for corruption");
        CHECK(nodus_witness_db_migrate_v2s9(w) == 0, "migrate to v9");

        /* nul_count = 5 against an EMPTY v2_pool_nullifiers log: committed
         * state its own tables cannot reproduce, which is precisely the
         * disagreement the S7 replay exists to detect. */
        int have_pools = (sqlite3_exec(w->db,
                "INSERT INTO v2_pools (domain_id, pool_id, config_version,"
                " tree_depth, history_limit, asset_ref, note_count,"
                " note_root, frontier, nul_count, nul_root, balance,"
                " hist_count, hist_next_seq)"
                " VALUES (1, 1, 1, 24, 720, x'00', 0, x'00', x'00',"
                " 5, x'00', 0, 0, 0)",
                NULL, NULL, NULL) == SQLITE_OK);
        sqlite3_close(w->db);
        w->db = NULL;
        close_witness(w);

        if (have_pools) {
            /* nul_count = 5 with an empty nullifier log is a committed
             * state its own tables cannot reproduce. */
            nodus_witness_t *w2 = fresh_witness(dir);
            CHECK(w2 != NULL, "alloc");
            int rc = nodus_witness_scan_chain_db(w2);
            CHECK(rc != 0,
                  "RESTART MUST REFUSE A DATABASE THAT FAILS THE S7 GATE");
            CHECK(w2->db == NULL,
                  "a refused restart must not leave the database open");
            close_witness(w2);
        } else {
            printf("  (v2_pools shape differs — S7 corruption case skipped)\n");
        }
    }

    /* ── 4. FILENAME PARSING FAILS CLOSED.
     * Names that do not carry exactly 32 hex characters must be IGNORED,
     * not partially parsed into a zero-padded chain id. Each of these was
     * accepted by the old parser. */
    {
        char d2[256];
        snprintf(d2, sizeof(d2), "/tmp/test_v2_restart_names_XXXXXX");
        CHECK(mkdtemp(d2) != NULL, "tmpdir 2");

        const char *bad[] = {
            "witness_dead.db",                      /* far too short     */
            "witness_.db",                          /* empty hex         */
            "witness_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.db", /* non-hex     */
            "witness_5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c.db",   /* 30 chars    */
            "witness_5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c.db" /* 34 chars   */
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char p[512];
            snprintf(p, sizeof(p), "%s/%s", d2, bad[i]);
            FILE *fp = fopen(p, "wb");
            CHECK(fp != NULL, "write decoy");
            fputs("not a database", fp);
            fclose(fp);
        }

        nodus_witness_t *w = fresh_witness(d2);
        CHECK(w != NULL, "alloc");
        CHECK(nodus_witness_scan_chain_db(w) != 0,
              "malformed chain-db names must ALL be ignored");
        close_witness(w);
    }

    /* ── 5. SELECTION IS DETERMINISTIC.
     * With several validly-named databases present, the choice must be a
     * function of the names, not of readdir order. Repeated scans over
     * the same directory must adopt the same chain every time — the
     * property first-match-wins could not offer. */
    {
        char d3[256];
        snprintf(d3, sizeof(d3), "/tmp/test_v2_restart_multi_XXXXXX");
        CHECK(mkdtemp(d3) != NULL, "tmpdir 3");

        uint8_t a[16], b[16], c[16];
        memset(a, 0xa0, sizeof(a));
        memset(b, 0x0b, sizeof(b));   /* lexicographically smallest name */
        memset(c, 0xc0, sizeof(c));
        char p[512];
        CHECK(seed_chain(d3, a, p, sizeof(p)) == 0, "seed a");
        CHECK(seed_chain(d3, c, p, sizeof(p)) == 0, "seed c");
        CHECK(seed_chain(d3, b, p, sizeof(p)) == 0, "seed b");

        uint8_t first[32];
        int adopted = 0;
        for (int i = 0; i < 5; i++) {
            nodus_witness_t *w = fresh_witness(d3);
            CHECK(w != NULL, "alloc");
            if (nodus_witness_scan_chain_db(w) == 0) {
                if (!adopted) {
                    memcpy(first, w->chain_id, 32);
                    adopted = 1;
                } else {
                    CHECK(memcmp(first, w->chain_id, 32) == 0,
                          "REPEATED SCANS MUST ADOPT THE SAME CHAIN");
                }
            }
            close_witness(w);
        }
        if (adopted) {
            /* And it must be the smallest name, not whichever the
             * filesystem happened to return first. */
            CHECK(memcmp(first, b, 16) == 0,
                  "selection must follow a stable total order over names");
        }
    }

    /* ── 5. O15K E1/E2/A — A CONTENDED OPEN MUST NOT PRODUCE A HALF-OPEN
     *      NODE WITH A ZEROED CHAIN ID.
     *
     * WHAT THIS PROVES. A witness `kill -9`'d and restarted races the
     * dying process's SQLite lock. Before O15K the schema exec failed
     * immediately with "database is locked", witness_db_open_path
     * returned -1 WITHOUT closing the handle, and the scanner returned
     * before installing the chain id. The node then ran with
     * `db != NULL` (reporting chain_db=active) and `chain_id == 0` —
     * which BOTH verify_chain_id (nodus_witness_bft.c, CRITICAL-2
     * cross-chain replay protection) and witness_chain_quorum_observe
     * (nodus_witness_peer.c, the self-quarantine detector) read as
     * "pre-genesis" and skip. It could never verify a certificate again
     * and could not notice its own divergence. Found by the O15K harness
     * run; full write-up in nodus/BUGS.md.
     *
     * HOW IT COULD LIE. If the interloper's lock were not actually held
     * when the scan runs, the open would simply succeed and every
     * assertion below would pass for the wrong reason. So the lock is
     * taken with BEGIN EXCLUSIVE and its acquisition is asserted first,
     * and the outcome is split: whichever way the open resolves, the two
     * invariants this season added must hold. There is deliberately no
     * assertion that the open FAILS — with E1's busy timeout it may now
     * legitimately win the race, and demanding a failure would make the
     * test fail because the fix works.
     *
     * ⚠ E1 IS NOT DIRECTLY ASSERTED HERE. A busy timeout is a timing
     * property; pinning it would mean sleeping and calibrating to this
     * machine, which this project forbids. What is asserted is the
     * property that made the defect fatal — the fail-closed handle and
     * the retained identity — and those hold whether or not the timeout
     * wins any particular race. */
    {
        char d4[256];
        snprintf(d4, sizeof(d4), "/tmp/test_v2_restart_lock_XXXXXX");
        CHECK(mkdtemp(d4) != NULL, "tmpdir 4");

        uint8_t lc[16];
        memset(lc, 0x7b, sizeof(lc));
        char lpath[512];
        CHECK(seed_chain(d4, lc, lpath, sizeof(lpath)) == 0, "seed locked");

        /* An independent connection holds a write lock on the file the
         * scanner is about to open. */
        sqlite3 *hold = NULL;
        CHECK(sqlite3_open(lpath, &hold) == SQLITE_OK, "interloper opens");
        CHECK(sqlite3_exec(hold, "BEGIN EXCLUSIVE;", NULL, NULL, NULL)
              == SQLITE_OK,
              "interloper HOLDS the write lock — without this the case "
              "below would pass on an uncontended open and prove nothing");

        nodus_witness_t *w = fresh_witness(d4);
        CHECK(w != NULL, "alloc");
        int rc = nodus_witness_scan_chain_db(w);

        /* A — the identity is parsed from the FILENAME, so it survives
         * whatever the open does. Pre-O15K this was installed only after
         * a successful open and a contended open threw it away. */
        CHECK(memcmp(w->chain_id, lc, 16) == 0,
              "the chain id is retained even when the open is contended — "
              "it comes from the filename, not from the database");

        /* E2 — and the handle must never be left half-open. Pre-O15K a
         * failed schema exec returned -1 with witness->db still assigned,
         * so the node reported chain_db=active while init had already
         * logged "no chain DB found". */
        if (rc != 0)
            CHECK(w->db == NULL,
                  "a FAILED open must leave no handle behind — a witness "
                  "that reports an active chain DB it does not have is "
                  "the shape 'a DB failure is never a value' forbids");
        else
            CHECK(w->db != NULL,
                  "a SUCCEEDED open must leave a usable handle");

        close_witness(w);
        sqlite3_exec(hold, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(hold);
    }

    /* ── 6. O15L Faz 1 / DG-1 · G1, G2 — THE CHAIN-IDENTITY DECISION IS
     *      A TOTAL FUNCTION OF (chain_id, db).
     *
     * WHAT THIS PROVES. verify_chain_id is CRITICAL-2, the cross-chain
     * replay guard on all five BFT handlers. It used to exempt itself
     * whenever the local chain_id was all-zero — "absence of an answer"
     * treated as "an answer that permits", which is the shape that forks
     * a chain. The replacement is the four-state matrix of the O15L
     * design §1 DG-1:
     *
     *   id != 0, db != NULL  healthy                 -> ENFORCE
     *   id != 0, db == NULL  open failed, id kept    -> ENFORCE
     *   id == 0, db == NULL  genuine pre-genesis     -> EXEMPT (the only one)
     *   id == 0, db != NULL  invariant violation     -> FAIL CLOSED
     *
     * ⚠ ROW 2 IS THE REGRESSION PIN. nodus/BUGS.md option B proposed
     * "the sound test is w->db == NULL". Applied literally that INVERTS
     * O15K's fix A: a node whose open failed holds exactly
     * (db == NULL, chain_id != 0) — the state fix A exists to produce —
     * and a bare `db == NULL -> exempt` re-exempts precisely that node.
     * The identity is the authority; the handle only disambiguates a
     * ZERO identity. An implementation that gets this backwards passes
     * rows 1, 3 and 4 and fails row 2 alone.
     *
     * HOW IT COULD LIE. If the matrix were read as "always enforce",
     * row 3 would fail — so the exemption is asserted positively, not
     * merely left untested. And each ENFORCE row asserts BOTH the
     * matching verdict and the mismatching one, so a gate stuck at
     * `return false` cannot pass. */
    {
        uint8_t mine[16], other[16];
        memset(mine, 0x11, sizeof(mine));
        memset(other, 0x22, sizeof(other));

        uint8_t mine32[32], other32[32], zero32[32];
        memset(mine32, 0, sizeof(mine32));
        memset(other32, 0, sizeof(other32));
        memset(zero32, 0, sizeof(zero32));
        memcpy(mine32, mine, 16);
        memcpy(other32, other, 16);

        /* Row 1 — (id != 0, db != NULL): ENFORCE. */
        {
            nodus_witness_t *w = matrix_witness(mine, 1);
            CHECK(w != NULL, "alloc row 1");
            CHECK(verify_chain_id(w, mine32) == true,
                  "row 1: a matching chain_id must be accepted");
            CHECK(verify_chain_id(w, other32) == false,
                  "row 1: a foreign chain_id must be rejected");
            close_witness(w);
        }

        /* Row 2 — (id != 0, db == NULL): ENFORCE ANYWAY.  ← THE PIN */
        {
            nodus_witness_t *w = matrix_witness(mine, 0);
            CHECK(w != NULL, "alloc row 2");
            CHECK(verify_chain_id(w, other32) == false,
                  "ROW 2: A NODE WHOSE OPEN FAILED STILL HOLDS ITS "
                  "IDENTITY AND MUST STILL ENFORCE IT — a bare "
                  "'db == NULL -> exempt' test reverts O15K fix A here");
            CHECK(verify_chain_id(w, mine32) == true,
                  "row 2: ENFORCE means COMPARE, not refuse everything");
            close_witness(w);
        }

        /* Row 3 — (id == 0, db == NULL): the ONE exemption.
         * Structurally load-bearing: genesis flows through these same
         * handlers, so a node with no chain must accept those frames or
         * no chain can ever start (O15L design §8, Q1 -> option 1). */
        {
            nodus_witness_t *w = matrix_witness(NULL, 0);
            CHECK(w != NULL, "alloc row 3");
            CHECK(verify_chain_id(w, other32) == true,
                  "row 3: genuine pre-genesis is exempt — without this a "
                  "new node could never join");
            CHECK(verify_chain_id(w, zero32) == true,
                  "row 3: exempt for an all-zero message id too");
            close_witness(w);
        }

        /* Row 4 — (id == 0, db != NULL): FAIL CLOSED.
         * Unreachable through the ordinary open paths, but reachable
         * with write access to the data directory: a planted
         * witness_000...0.db parses as a valid name and yields
         * set_chain_id(0) on a SUCCESSFUL open (O15L design §4, F-5).
         * That is why this arm is kept rather than treated as dead. */
        {
            nodus_witness_t *w = matrix_witness(NULL, 1);
            CHECK(w != NULL, "alloc row 4");
            CHECK(verify_chain_id(w, other32) == false,
                  "ROW 4: A ZERO IDENTITY WITH AN OPEN DATABASE IS AN "
                  "INVARIANT VIOLATION AND MUST NOT PERMIT ANYTHING");
            CHECK(verify_chain_id(w, zero32) == false,
                  "row 4: fail closed unconditionally, including for an "
                  "all-zero message id");
            close_witness(w);
        }
    }

    /* ── 7. O15L Faz 1 / DG-2 · G3 — THE SELF-QUARANTINE DETECTOR TAKES
     *      THE SAME MATRIX.
     *
     * WHAT THIS PROVES. witness_chain_quorum_observe carried the identical
     * `chain_id == 0 -> return` exemption. Fixing only verify_chain_id
     * would leave a node able to reject foreign messages but unable to
     * notice that IT is the diverged one — the detector blinded by the
     * very condition it exists to catch. Both consumers move together.
     *
     * The function returns void, so the observable is whether the
     * observation was COUNTED: chain_agree_count / chain_dissent_count.
     * ENFORCE rows count; EXEMPT and FAIL-CLOSED rows do not (a node with
     * no identity has no opinion to compare against). Rows 3 and 4 are
     * therefore count-identical and differ only in row 4's loud log.
     *
     * HOW IT COULD LIE. Every case sets activated_at_sec to now in
     * matrix_witness — left at zero the 300 s window has expired and
     * NOTHING is ever counted, which would make the two zero-count rows
     * pass for entirely the wrong reason. Case A counting proves the
     * window is genuinely open, so the zero-count rows below mean what
     * they say. */
    {
        uint8_t mine[16], other[16];
        memset(mine, 0x11, sizeof(mine));
        memset(other, 0x22, sizeof(other));

        uint8_t mine32[32], other32[32], zero32[32];
        memset(mine32, 0, sizeof(mine32));
        memset(other32, 0, sizeof(other32));
        memset(zero32, 0, sizeof(zero32));
        memcpy(mine32, mine, 16);
        memcpy(other32, other, 16);

        /* One observation per case against a fresh witness, so a single
         * peer id cannot collide with the dedup list of another case. */
        uint8_t peer[NODUS_T3_WITNESS_ID_LEN];
        memset(peer, 0x91, sizeof(peer));

        /* Row 1 — (id != 0, db != NULL), peer agrees: counted as agree. */
        {
            nodus_witness_t *w = matrix_witness(mine, 1);
            CHECK(w != NULL, "alloc observe row 1 agree");
            witness_chain_quorum_observe(w, peer, mine32);
            CHECK(w->chain_agree_count == 1,
                  "row 1: an agreeing peer must be counted — if this is 0 "
                  "the 300 s window is shut and the whole section is void");
            CHECK(w->chain_dissent_count == 0, "row 1: not a dissenter");
            close_witness(w);
        }

        /* Row 1 — same cell, peer dissents: counted as dissent. */
        {
            nodus_witness_t *w = matrix_witness(mine, 1);
            CHECK(w != NULL, "alloc observe row 1 dissent");
            witness_chain_quorum_observe(w, peer, other32);
            CHECK(w->chain_dissent_count == 1,
                  "row 1: a dissenting peer must be counted");
            CHECK(w->chain_agree_count == 0, "row 1: not an agreer");
            close_witness(w);
        }

        /* Row 2 — (id != 0, db == NULL): STILL OBSERVES.  ← THE PIN
         * The node that lost its database is exactly the node most
         * likely to be the diverged one; blinding it here is how the
         * O15K defect stayed invisible. */
        {
            nodus_witness_t *w = matrix_witness(mine, 0);
            CHECK(w != NULL, "alloc observe row 2");
            witness_chain_quorum_observe(w, peer, other32);
            CHECK(w->chain_dissent_count == 1,
                  "ROW 2: A NODE WITH AN IDENTITY BUT NO DATABASE MUST "
                  "STILL SEE ITS OWN DISSENT — a 'db == NULL -> skip' "
                  "detector can never self-quarantine after a failed open");
            close_witness(w);
        }

        /* Row 3 — (id == 0, db == NULL): no identity, no opinion. */
        {
            nodus_witness_t *w = matrix_witness(NULL, 0);
            CHECK(w != NULL, "alloc observe row 3");
            witness_chain_quorum_observe(w, peer, other32);
            CHECK(w->chain_dissent_count == 0 && w->chain_agree_count == 0,
                  "row 3: genuine pre-genesis has nothing to compare "
                  "against, so nothing is counted");
            close_witness(w);
        }

        /* Row 4 — (id == 0, db != NULL): invariant violation, counts
         * nothing and says so loudly. */
        {
            nodus_witness_t *w = matrix_witness(NULL, 1);
            CHECK(w != NULL, "alloc observe row 4");
            witness_chain_quorum_observe(w, peer, other32);
            CHECK(w->chain_dissent_count == 0 && w->chain_agree_count == 0,
                  "row 4: a zero identity with an open database must not "
                  "feed the quarantine tally");
            close_witness(w);
        }

        /* PRESERVED — a peer that is itself pre-genesis has no opinion,
         * and that check is untouched by this season. Row 1 cell, so the
         * only thing that can suppress the count is the peer's own
         * all-zero id. */
        {
            nodus_witness_t *w = matrix_witness(mine, 1);
            CHECK(w != NULL, "alloc observe peer-zero");
            witness_chain_quorum_observe(w, peer, zero32);
            CHECK(w->chain_dissent_count == 0 && w->chain_agree_count == 0,
                  "a peer with an all-zero chain_id expresses no opinion "
                  "and must still be ignored");
            close_witness(w);
        }
    }

    /* ── 8. O15L Faz 1 item 3 / DG-1 · F-4 — THE CREATE PATH INSTALLS
     *      THE IDENTITY BEFORE THE OPEN, AS THE SCAN PATH DOES.
     *
     * WHAT THIS PROVES. nodus_witness_create_chain_db opened first and
     * called nodus_witness_set_chain_id after, the mirror image of the
     * scan path that O15K fix A already corrected. Because the function
     * closes any previous handle WITHOUT clearing chain_id, the old
     * order also left a window in which the pair was (db != NULL,
     * id = STALE). Both live callers happen to enter with chain_id == 0
     * today, so it is latent rather than live — but the two paths must
     * read the same way or the next reader re-derives the bug.
     *
     * HOW IT COULD LIE. If the open SUCCEEDED, the identity would be
     * present either way and the assertion would pass on the old order
     * too. So creation is aimed at a directory that does not exist: the
     * open cannot succeed, and the only way the identity can be present
     * afterwards is if it was installed BEFORE the open. */
    {
        char d5[256];
        snprintf(d5, sizeof(d5), "/tmp/test_v2_restart_create_XXXXXX");
        CHECK(mkdtemp(d5) != NULL, "tmpdir 5");

        char missing[512];
        snprintf(missing, sizeof(missing), "%s/no_such_dir", d5);

        uint8_t ccid[16];
        memset(ccid, 0x3e, sizeof(ccid));

        nodus_witness_t *w = fresh_witness(missing);
        CHECK(w != NULL, "alloc");
        int rc = nodus_witness_create_chain_db(w, ccid);

        CHECK(rc != 0,
              "creating a chain DB under a nonexistent directory must "
              "fail — without this the case proves nothing");
        CHECK(w->db == NULL,
              "a failed create must leave no handle behind (O15K E2)");
        CHECK(memcmp(w->chain_id, ccid, 16) == 0,
              "THE CREATE PATH MUST INSTALL THE CHAIN ID BEFORE THE OPEN, "
              "MIRRORING THE SCAN PATH — an identity thrown away by a "
              "failed open is read as 'pre-genesis' by both gates above");
        for (int i = 16; i < 32; i++)
            CHECK(w->chain_id[i] == 0,
                  "chain id upper half must be zero");
        close_witness(w);
    }

    /* ── 9. O15L Faz 2 / G2, G6 — A CHAIN DB THAT IS PRESENT AND
     *      UNREADABLE IS NEVER REPORTED AS ABSENT.
     *
     * WHAT THIS PROVES. Every non-zero return of the scanner used to be
     * printed by nodus_witness_init as "no chain DB found — pre-genesis
     * state". A node whose chain database exists but cannot be opened
     * therefore announced, in the only line an operator reads, that it
     * had never had a chain — the same class of lie O15K removed from
     * MEMPOOL_BLOCK_TIME.md and the same one that let the O15K half-open
     * node report chain_db=active. The scanner now answers three
     * different questions with three different codes, and this case pins
     * the one that is a PERMANENT fault: a file carrying a perfectly
     * valid witness_<32 hex>.db name whose contents are not a database.
     *
     * WHAT IT REQUIRES. Nothing beyond a default build — no compile flag
     * and no environment variable. WHAT IT LEAVES BEHIND: its own
     * mkdtemp directory holding one junk file, as every case here leaves
     * its fixture directory.
     *
     * HOW IT COULD LIE. If the assertion were merely `rc != 0` it would
     * pass on the OLD scanner too, since the old one also failed here —
     * it just could not say why. The code is therefore asserted by exact
     * value, and W_SCAN_ABSENT is the value that must NOT come back.
     * The expectation is that SQLite calls a malformed image NOTADB (or
     * CORRUPT), both of which the classifier calls permanent. If some
     * build instead answered a transient code here, this case FAILS
     * loudly rather than passing quietly — which is the right way round
     * for an assumption about a library's exact result code. */
    {
        char d6[256];
        snprintf(d6, sizeof(d6), "/tmp/test_v2_restart_notadb_XXXXXX");
        CHECK(mkdtemp(d6) != NULL, "tmpdir 6");

        uint8_t pcid[16];
        memset(pcid, 0x4d, sizeof(pcid));
        char phex[33];
        for (int i = 0; i < 16; i++)
            snprintf(phex + i * 2, 3, "%02x", pcid[i]);

        char ppath[512];
        snprintf(ppath, sizeof(ppath), "%s/witness_%s.db", d6, phex);

        unsigned char junk[512];
        memset(junk, 0xab, sizeof(junk));
        FILE *fp = fopen(ppath, "wb");
        CHECK(fp != NULL, "create a decoy carrying a VALID chain-db name");
        CHECK(fwrite(junk, 1, sizeof(junk), fp) == sizeof(junk),
              "decoy written");
        fclose(fp);

        nodus_witness_t *w = fresh_witness(d6);
        CHECK(w != NULL, "alloc");
        int rc = nodus_witness_scan_chain_db(w);

        CHECK(rc == W_SCAN_UNUSABLE_PERMANENT,
              "A CHAIN DB THAT EXISTS AND CANNOT BE READ MUST BE REPORTED "
              "AS PRESENT-AND-UNUSABLE, NEVER AS ABSENCE — the caller "
              "prints 'pre-genesis' on absence, and that sentence about a "
              "node that holds a chain is exactly the lie this closes");
        CHECK(rc != W_SCAN_ABSENT,
              "and specifically not the pre-genesis code");
        CHECK(w->db == NULL,
              "a refused open must leave no handle behind (O15K E2)");
        CHECK(memcmp(w->chain_id, pcid, 16) == 0,
              "the filename-derived identity is retained across the "
              "refusal — DG-1 row 2, the state O15K fix A produces");
        close_witness(w);
    }

    /* ── 10. O15L Faz 2 / G2 — GENUINE ABSENCE IS STILL ABSENCE, AND AN
     *       UNREADABLE DIRECTORY IS NOT ABSENCE.
     *
     * WHAT THIS PROVES. Two halves of the same separation. A fresh node
     * with an empty data directory MUST still reach the pre-genesis
     * branch, or no chain could ever be bootstrapped — the exemption of
     * DG-1 row 3 is structurally load-bearing (design §8, Q1). And a data
     * directory that cannot be read at all is an operator fault, not an
     * observation: reporting it as "no chain DB found" would let a node
     * that owns a chain announce it has none, which is the case-9 lie
     * arriving through opendir instead of sqlite3_open.
     *
     * HOW IT COULD LIE. The absence half alone would pass on a scanner
     * that returns ABSENT for everything, so the unreadable half is
     * asserted beside it, and case 9 pins the third code. The identity is
     * asserted to stay all-zero on the absence path — a pre-genesis node
     * whose chain_id were non-zero would fail closed at both O15L Faz 1
     * gates and could never join. */
    {
        char d7[256];
        snprintf(d7, sizeof(d7), "/tmp/test_v2_restart_empty_XXXXXX");
        CHECK(mkdtemp(d7) != NULL, "tmpdir 7");

        nodus_witness_t *w = fresh_witness(d7);
        CHECK(w != NULL, "alloc");
        CHECK(nodus_witness_scan_chain_db(w) == W_SCAN_ABSENT,
              "AN EMPTY DATA DIRECTORY IS GENUINE PRE-GENESIS — the one "
              "outcome on which init may continue");
        CHECK(w->db == NULL, "pre-genesis leaves no handle");
        for (int i = 0; i < 32; i++)
            CHECK(w->chain_id[i] == 0,
                  "pre-genesis keeps the all-zero identity, the only cell "
                  "of the DG-1 matrix that is exempt");
        close_witness(w);

        char missing[512];
        snprintf(missing, sizeof(missing), "%s/no_such_dir", d7);
        nodus_witness_t *w2 = fresh_witness(missing);
        CHECK(w2 != NULL, "alloc");
        CHECK(nodus_witness_scan_chain_db(w2) == W_SCAN_UNUSABLE_PERMANENT,
              "A DATA DIRECTORY THAT CANNOT BE READ IS NOT AN OBSERVATION "
              "OF ABSENCE — a node that owns a chain must never announce "
              "it has none because its own directory was unreadable");
        CHECK(w2->db == NULL, "no handle from a failed directory read");
        close_witness(w2);
    }

    /* ── 11. O15L Faz 2 — A LOCKED CHAIN DB IS CLASSIFIED TRANSIENT, AND
     *       AN EXHAUSTED RETRY IS STILL 'PRESENT AND UNUSABLE'.
     *
     * WHAT THIS PROVES. The error classes are not cosmetic: SQLITE_BUSY /
     * SQLITE_LOCKED are the classes a `kill -9` + restart produces while
     * the dying process's WAL recovery settles, and they must be RETRIED
     * in-process, then — if they outlive the retries — reported as
     * present-and-unusable rather than as absence or as a permanent
     * corruption. The interloper below holds BEGIN EXCLUSIVE for the whole
     * scan, so if the classifier called BUSY permanent, this case fails.
     *
     * WHAT IT REQUIRES. A default build; no flag, no environment
     * variable. WHAT IT LEAVES BEHIND: its mkdtemp directory with a
     * seeded chain database in it. The interloper connection is rolled
     * back and closed on the way out, so no lock outlives the case.
     *
     * ⚠ RUN TIME. This case deliberately loses a race it cannot win, so it
     * pays the full open budget: NODUS_W_DB_OPEN_ATTEMPTS attempts, each
     * of which lets several write statements wait out the per-attempt
     * busy timeout. That is bounded by design and is the SAME aggregate
     * wait section 5 already pays — the retry loop divides the one
     * NODUS_W_DB_BUSY_TIMEOUT_MS budget across attempts rather than
     * spending it once per attempt — but expect this case to take tens of
     * seconds. There is NO duration assertion anywhere in it.
     *
     * ⚠ HOW IT COULD LIE, AND WHAT IT DOES ABOUT IT. Whether a held
     * EXCLUSIVE lock makes every step of the open fail is a property of
     * SQLite, not of this tree, so the outcome is split rather than
     * asserted: if the open nevertheless SUCCEEDS the case says out loud
     * that the transient class went UNEXERCISED — a skip reported as a
     * skip — and asserts only the handle. It never converts that into a
     * green for the classification. The dangerous direction is the one
     * that is pinned: a failure MUST be TRANSIENT, not PERMANENT and not
     * ABSENT. The retry COUNT and the backoff are deliberately not
     * asserted: pinning either would mean measuring time, which this
     * project forbids in tests. */
    {
        char d8[256];
        snprintf(d8, sizeof(d8), "/tmp/test_v2_restart_busy_XXXXXX");
        CHECK(mkdtemp(d8) != NULL, "tmpdir 8");

        uint8_t tc[16];
        memset(tc, 0x2f, sizeof(tc));
        char tpath[512];
        CHECK(seed_chain(d8, tc, tpath, sizeof(tpath)) == 0, "seed busy");

        sqlite3 *hold = NULL;
        CHECK(sqlite3_open(tpath, &hold) == SQLITE_OK, "interloper opens");
        CHECK(sqlite3_exec(hold, "BEGIN EXCLUSIVE;", NULL, NULL, NULL)
              == SQLITE_OK,
              "interloper HOLDS the write lock — without this the case "
              "would run uncontended and prove nothing");

        nodus_witness_t *w = fresh_witness(d8);
        CHECK(w != NULL, "alloc");
        int rc = nodus_witness_scan_chain_db(w);

        if (rc == 0) {
            printf("  (contended open SUCCEEDED — the TRANSIENT class was "
                   "NOT exercised by this run; the classification is "
                   "unproven here, not proven)\n");
            CHECK(w->db != NULL,
                  "a succeeded open must leave a usable handle");
            /* Section 5's discipline: the O15K invariants are asserted in
             * BOTH branches, so the branch that skips the classification
             * still proves something. The identity comes from the
             * filename, so it is present either way. */
            CHECK(memcmp(w->chain_id, tc, 16) == 0,
                  "the identity is installed before the open, so it is "
                  "present whichever way the race resolves");
        } else {
            CHECK(rc == W_SCAN_UNUSABLE_TRANSIENT,
                  "A LOCKED CHAIN DB IS A TRANSIENT FAULT: after the "
                  "retries are exhausted it is reported as PRESENT AND "
                  "UNUSABLE — not as a permanent corruption, and above "
                  "all not as absence");
            CHECK(rc != W_SCAN_UNUSABLE_PERMANENT,
                  "a lock is not a corruption");
            CHECK(rc != W_SCAN_ABSENT,
                  "a locked database is not a missing one");
            CHECK(w->db == NULL,
                  "an exhausted open must leave no handle behind");
            CHECK(memcmp(w->chain_id, tc, 16) == 0,
                  "the identity survives the exhausted open — DG-1 row 2");
        }

        close_witness(w);
        sqlite3_exec(hold, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(hold);
    }

    /* ── 12. O15L Faz 4 / F-6 — DROPPING THE CHAIN DROPS THE V2 IDENTITY
     *       WITH IT.
     *
     * WHAT THIS PROVES. drop_witness_db closes the handle, unlinks the
     * file and zeroes chain_id — and used to leave `v2_successor` true
     * and `v2_chain32` populated. The resulting triple
     * (chain_id == 0, db == NULL, v2_successor == true) is read by the
     * O15L DG-1 matrix as row 3, "genuine pre-genesis, exempt", while
     * every bare `if (w->v2_successor)` branch still steers the successor
     * lane at a NULL handle: one node holding two irreconcilable answers
     * about which chain it is on. This case pins that all three are
     * cleared together, so the node lands in exactly one cell of the
     * matrix. After the Faz 4 loader change the stake is higher still —
     * the committee lookup keys on chain_id and would call this node
     * pre-genesis while the V2 lanes called it a successor.
     *
     * HOW THE DROP IS REACHED. drop_witness_db is file-static in
     * nodus_witness_sync.c, so this drives it through its production
     * caller, nodus_witness_halt_recovery_check, by satisfying that
     * function's real preconditions rather than by reaching around them:
     * safety_halt latched, halt_auto_recover opted IN (it is OFF by
     * default and that default is asserted elsewhere — see
     * test_halt_auto_recover_default_off), a one-member halt-time
     * committee snapshot (so dna_bft_quorum(1) == 1), and one identified
     * peer whose witness_id derives from that snapshot's pubkey and whose
     * remote_checksum disagrees with ours. cached_state_root_valid short-
     * circuits the Merkle recompute, which is not this case's subject.
     *
     * WHAT IT REQUIRES. A default build; no compile flag, no environment
     * variable. WHAT IT LEAVES BEHIND: its own mkdtemp directory,
     * containing the armed .recovery_in_progress sentinel that the
     * production drop path writes before dropping — the drop deletes the
     * chain database, not the sentinel.
     *
     * HOW IT COULD LIE, AND WHAT IT DOES ABOUT IT. The three "cleared"
     * assertions would all pass vacuously on a fixture that never set the
     * fields in the first place, and they would ALSO pass on a
     * halt_recovery_check that declined to drop anything at all. Both
     * doors are closed: the stale V2 state is asserted PRESENT
     * immediately before the call, and the drop is asserted to have
     * actually happened (handle gone, file gone, halt cleared) — so a
     * no-op recovery check fails this case rather than passing it.
     *
     * NO TIMING. The cooldown is passed by leaving halt_timestamp at 0,
     * which halt_recovery_check reads as "not in the future and not
     * within the window", never by sleeping or by measuring elapsed
     * time. */
    {
        char d9[256];
        snprintf(d9, sizeof(d9), "/tmp/test_v2_restart_drop_XXXXXX");
        CHECK(mkdtemp(d9) != NULL, "tmpdir 9");

        uint8_t dcid[16];
        memset(dcid, 0x3e, sizeof(dcid));

        nodus_witness_t *w = fresh_witness(d9);
        CHECK(w != NULL, "alloc");
        CHECK(nodus_witness_create_chain_db(w, dcid) == 0, "seed drop chain");
        CHECK(w->db != NULL, "the drop needs an OPEN database to close");

        char dpath[512];
        {
            char hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(hex + i * 2, 3, "%02x", dcid[i]);
            snprintf(dpath, sizeof(dpath), "%s/witness_%s.db", d9, hex);
        }

        /* The stale V2 identity a successor chain carries at runtime.
         * Planted directly because the production deriver needs a
         * committed successor genesis manifest, which is a different
         * subject from what happens to the fields when the chain goes
         * away. */
        w->v2_successor = true;
        memset(w->v2_chain32, 0xC2, sizeof(w->v2_chain32));

        /* Halt state + the one-member halt-time committee. */
        w->safety_halt = true;
        w->halt_block_height = 10;
        w->halt_timestamp = 0;          /* cooldown already elapsed */
        w->config.halt_auto_recover = true;
        memset(w->halt_committee_pubkeys[0], 0x41, DNAC_PUBKEY_SIZE);
        w->halt_committee_count = 1;

        /* Our own state root, and one committee peer that disagrees with
         * it — the disagree-quorum the recovery check requires. */
        w->cached_state_root_valid = true;
        memset(w->cached_state_root, 0x01, sizeof(w->cached_state_root));

        w->peer_count = 1;
        w->peers[0].identified = true;
        memset(w->peers[0].remote_checksum, 0x02,
               sizeof(w->peers[0].remote_checksum));
        CHECK(nodus_chain_config_derive_witness_id(
                  w->halt_committee_pubkeys[0], w->peers[0].witness_id) == 0,
              "derive the peer's witness_id from the halt-time snapshot — "
              "a peer outside that snapshot is ignored as a phantom and "
              "the quorum would never be reached");

        /* The premises, asserted rather than assumed: without these the
         * three post-conditions below would be vacuous. */
        CHECK(w->v2_successor,
              "premise: the fixture really is carrying successor state");
        {
            int nonzero = 0;
            for (size_t i = 0; i < sizeof(w->v2_chain32); i++)
                if (w->v2_chain32[i]) nonzero = 1;
            CHECK(nonzero, "premise: v2_chain32 really is populated");
        }

        nodus_witness_halt_recovery_check(w);

        /* The drop ACTUALLY happened — otherwise every assertion after
         * this one is about a fixture nobody touched. */
        CHECK(w->db == NULL, "the drop closed and NULLed the handle");
        CHECK(access(dpath, F_OK) != 0,
              "the drop unlinked the chain database file");
        CHECK(!w->safety_halt,
              "the recovery path cleared the halt after a successful drop");

        for (int i = 0; i < 32; i++)
            CHECK(w->chain_id[i] == 0,
                  "the drop zeroed the legacy chain identity (pre-existing "
                  "behaviour, asserted so the V2 half below is measured "
                  "against a known baseline)");

        CHECK(w->v2_successor == false,
              "F-6: A DROPPED CHAIN LEAVES NO SUCCESSOR CLAIM BEHIND — "
              "(chain_id == 0, db == NULL, v2_successor == true) reads as "
              "genuine pre-genesis at the identity matrix while every "
              "successor branch still fires at a NULL database");
        for (size_t i = 0; i < sizeof(w->v2_chain32); i++)
            CHECK(w->v2_chain32[i] == 0,
                  "F-6: the cached V2 chain id goes with the chain it was "
                  "derived from — it authenticates QC certs and envelope "
                  "admission, and a stale one authenticates them for a "
                  "chain this node no longer has");
        CHECK(!w->cached_state_root_valid,
              "the cached state root of a deleted chain is not a value");

        close_witness(w);
    }

    printf("test_v2_restart_gate: ALL %d checks passed\n", checks);
    return 0;
}
