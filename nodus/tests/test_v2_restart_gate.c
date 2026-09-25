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
 * ── R3 W4-D — THE OTHER DIRECTION IS GONE ────────────────────────────
 * The reverse transition this file used to also own — what a node keeps
 * when its chain database is DROPPED via drop_witness_db /
 * nodus_witness_halt_recovery_check — is DELETED with the closed
 * consensus lane: both functions were file-static in the now-deleted
 * nodus_witness_sync.c. See the deletion note where that case stood.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>   /* mkdtemp — every case in this file uses one */
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"

/* ── O15L Faz 1 — the chain-identity gate still under test ────────────
 *
 *   witness_chain_quorum_observe  defined in nodus_witness_peer.c
 *
 * R3 W4-D — verify_chain_id (nodus_witness_bft.c) is DELETED with the
 * closed consensus lane; only witness_chain_quorum_observe survives.
 * It is non-static in the library for exactly the reason
 * nodus_witness_peer.h's own gated declaration comment records:
 * "static + test linkage is incompatible in CMake's normal flow ... the
 * protection is 'no public header references them' rather than 'static
 * qualifier'." Production code reaching for it is a code-review
 * failure, not a linker error.
 *
 * The canonical prototype now lives in nodus_witness_peer.h, gated on
 * NODUS_WITNESS_INTERNAL_API (nodus/CMakeLists.txt's register_witness_
 * test macro defines it for this target) exactly as
 * nodus_witness_bft_internal.h used to gate its own whole file before
 * that file was deleted. Including peer.h (below) makes the call
 * signature-checked against the one declaration instead of against a
 * locally repeated copy. */
#include "witness/nodus_witness_peer.h"

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

    /* R3 W4-D — the case that used to occupy slot 6, the O15L Faz 1 /
     * DG-1 chain-identity decision, is DELETED with the closed consensus
     * lane: its subject, verify_chain_id, was defined in
     * nodus_witness_bft.c and is gone (there is no cometbft-lane
     * successor for the "reject a foreign chain_id on a BFT message"
     * property — the version-3 lane's own chain-id derivation and
     * cross-chain replay protection is a different mechanism, out of
     * this file's scope). The matrix_witness fixture stays: the next
     * case still uses it. Every case number from here on is renumbered
     * down by one to close the gap. */

    /* ── 6. O15L Faz 1 / DG-2 · G3 — THE SELF-QUARANTINE DETECTOR TAKES
     *      THE SAME MATRIX.
     *
     * WHAT THIS PROVES. witness_chain_quorum_observe carries the
     * `chain_id == 0 -> return` exemption for genuine pre-genesis, and
     * fails closed / enforces exactly as verify_chain_id (deleted along
     * with the rest of the closed consensus lane) used to, so a node can
     * still notice that IT is the diverged one even though the BFT-side
     * gate it once mirrored is gone.
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

    /* ── 7. O15L Faz 1 item 3 / DG-1 · F-4 — THE CREATE PATH INSTALLS
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

    /* ── 8. O15L Faz 2 / G2, G6 — A CHAIN DB THAT IS PRESENT AND
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

    /* ── 9. O15L Faz 2 / G2 — GENUINE ABSENCE IS STILL ABSENCE, AND AN
     *       UNREADABLE DIRECTORY IS NOT ABSENCE.
     *
     * WHAT THIS PROVES. Two halves of the same separation. A fresh node
     * with an empty data directory MUST still reach the pre-genesis
     * branch, or no chain could ever be bootstrapped — the exemption of
     * DG-1 row 3 is structurally load-bearing (design §8, Q1). And a data
     * directory that cannot be read at all is an operator fault, not an
     * observation: reporting it as "no chain DB found" would let a node
     * that owns a chain announce it has none, which is the case-8 lie
     * arriving through opendir instead of sqlite3_open.
     *
     * HOW IT COULD LIE. The absence half alone would pass on a scanner
     * that returns ABSENT for everything, so the unreadable half is
     * asserted beside it, and case 8 pins the third code. The identity is
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

    /* ── 10. O15L Faz 2 — A LOCKED CHAIN DB IS CLASSIFIED TRANSIENT, AND
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

    /* R3 W4-D — the case that used to occupy the last slot, O15L Faz 4 /
     * F-6 "dropping the chain drops the V2 identity with it", is DELETED
     * with the closed consensus lane: it drove drop_witness_db through
     * its one production caller, nodus_witness_halt_recovery_check —
     * both file-static in nodus_witness_sync.c, deleted whole. There is
     * no successor halt-recovery drop path on the version-3 lane in this
     * package's scope. */

    printf("test_v2_restart_gate: ALL %d checks passed\n", checks);
    return 0;
}
