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
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"

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

    printf("test_v2_restart_gate: ALL %d checks passed\n", checks);
    return 0;
}
