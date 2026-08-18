/**
 * @file messenger/tests/test_wallet_locked_utxo.c
 * @brief O15B §7 — coin selection must never choose a UTXO that consensus
 *        is guaranteed to reject.
 *
 * ── THE DEFECT THIS PINS ──────────────────────────────────────────────
 * Consensus enforces a cooldown lock on the post-UNSTAKE principal release:
 *
 *     Rule D, nodus/src/witness/nodus_witness_verify.c:730
 *         if (utxo_unlock_block > current_block) -> reject
 *
 * The wallet had no idea such a thing existed. `unlock_block` was not
 * SELECTed by the witness's `dnac_utxo` query, not carried on that RPC's
 * wire, and had no column in the client's own `dnac_utxos` table — so coin
 * selection could, and did, pick a locked coin.
 *
 * The transaction that resulted was then rejected by ALL SEVEN validators,
 * every round, forever. It could never reach quorum, so it could never
 * commit, so the submitter's 60-second commit-wait always expired and the
 * user saw only "Operation timed out". Reproduced on the O15B baseline:
 * `stagef_mk_funded_user` failed for five Genesis Protocol scenarios with
 * "fund failed after 3 attempts (chain verified empty)", while node1's log
 * showed `batch TX 0 rejected: input 1: UTXO locked (unlock_block=17289 >
 * current=9)` — 17289 = 9 + DNAC_UNSTAKE_COOLDOWN_BLOCKS.
 *
 * ── WHAT THIS FILE DOES AND DOES NOT COVER ────────────────────────────
 * It exercises the PERSISTENCE half against a REAL wallet database built by
 * the production migration: that the column exists, that the lock height
 * survives a store/load round trip, that a later sync CORRECTS a stale
 * value rather than keeping it, and that the observed height round-trips.
 *
 * It does NOT call any selection function. An earlier version of this
 * comment claimed it "drives the REAL selection entry points" — it does
 * not, and review R3 was right to call that out: reverting
 * `dnac/src/wallet/selection.c` entirely would leave every check here
 * passing. Selection needs a live `dnac_context_t`, so that half is covered
 * end to end by the Genesis Protocol harness, where the original failure
 * reproduced and where the fix was observed to work
 * (`Payment sent successfully! Block: 11`, zero `UTXO locked` rejections).
 *
 * Stating the boundary is the point: a test that overclaims its coverage is
 * worse than one that admits a gap, because the gap then goes unfilled.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "dnac/dnac.h"
#include "dnac/db.h"
#include "dnac/wallet.h"

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

static const char *FP =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void mk_utxo(dnac_utxo_t *u, uint8_t seed, uint64_t amount,
                    uint64_t unlock_block) {
    memset(u, 0, sizeof(*u));
    u->version = 1;
    memset(u->tx_hash,   seed, DNAC_TX_HASH_SIZE);
    memset(u->nullifier, seed, DNAC_NULLIFIER_SIZE);
    u->output_index = seed;
    u->amount       = amount;
    u->status       = DNAC_UTXO_UNSPENT;
    u->received_at  = 1000;
    u->unlock_block = unlock_block;
    snprintf(u->owner_fingerprint, sizeof(u->owner_fingerprint), "%s", FP);
}

int main(void) {
    printf("=== O15B §7 — locked-UTXO coin selection ===\n");

    char dir[] = "/tmp/test_wallet_locked_XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "temp dir");
    char path[512];
    snprintf(path, sizeof(path), "%s/wallet.db", dir);

    sqlite3 *db = NULL;
    CHECK(sqlite3_open(path, &db) == SQLITE_OK, "wallet db opens");
    /* The PRODUCTION schema path, including the new v7 migration. A
     * hand-rolled table would not prove the migration adds the column. */
    CHECK(dnac_db_init(db) == DNAC_SUCCESS, "production schema init");

    /* ── 1. THE MIGRATION ADDED THE COLUMN ────────────────────────────
     * Asserted against the live table shape, not against the migration
     * source, so a migration that silently no-ops is caught. */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(db, "PRAGMA table_info(dnac_utxos)",
                                 -1, &st, NULL) == SQLITE_OK, "table_info");
        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *n = sqlite3_column_text(st, 1);
            if (n && strcmp((const char *)n, "unlock_block") == 0) found = 1;
        }
        sqlite3_finalize(st);
        CHECK(found, "dnac_utxos.unlock_block EXISTS after migration");
    }

    /* ── 2. STORE AND READ BACK ───────────────────────────────────────
     * One spendable coin and one still inside its cooldown, with the same
     * amount so nothing but the lock can distinguish them. */
    {
        dnac_utxo_t spendable, locked;
        mk_utxo(&spendable, 0x11, 5000, 0);
        mk_utxo(&locked,    0x22, 5000, 17289);   /* the real shape */
        CHECK(dnac_db_store_utxo(db, &spendable) == DNAC_SUCCESS, "store 1");
        CHECK(dnac_db_store_utxo(db, &locked)    == DNAC_SUCCESS, "store 2");

        dnac_utxo_t *rows = NULL;
        int n = 0;
        CHECK(dnac_db_get_unspent_utxos(db, FP, &rows, &n) == DNAC_SUCCESS,
              "read back");
        CHECK(n == 2, "both rows stored");
        int saw_locked = 0, saw_free = 0;
        for (int i = 0; i < n; i++) {
            if (rows[i].unlock_block == 17289) saw_locked = 1;
            if (rows[i].unlock_block == 0)      saw_free   = 1;
        }
        CHECK(saw_locked, "the cooldown height SURVIVES a store/load round trip");
        CHECK(saw_free, "an ordinary coin reads back as unlocked");
        free(rows);
    }

    /* ── 3. THE LOCK HEIGHT IS REFRESHED ON RE-SYNC ───────────────────
     * Callers use the store as INSERT-OR-IGNORE, which is right for the
     * immutable fields and WRONG for this one: rows written before the
     * migration, or synced from a pre-O15B witness, carry the default 0
     * and would claim to be spendable forever. */
    {
        dnac_utxo_t again;
        mk_utxo(&again, 0x22, 5000, 99999);      /* same nullifier */
        CHECK(dnac_db_store_utxo(db, &again) == DNAC_SUCCESS, "re-store");

        dnac_utxo_t *rows = NULL;
        int n = 0;
        CHECK(dnac_db_get_unspent_utxos(db, FP, &rows, &n) == DNAC_SUCCESS,
              "read back");
        CHECK(n == 2, "no duplicate row was created");
        int refreshed = 0;
        for (int i = 0; i < n; i++)
            if (rows[i].unlock_block == 99999) refreshed = 1;
        CHECK(refreshed,
              "a later sync CORRECTS a stale unlock_block instead of "
              "silently keeping the old value");
        free(rows);

        /* Put it back to the realistic value for the sections below. */
        mk_utxo(&again, 0x22, 5000, 17289);
        CHECK(dnac_db_store_utxo(db, &again) == DNAC_SUCCESS, "restore");
    }

    /* ── 4. THE OBSERVED HEIGHT ROUND-TRIPS ───────────────────────────
     * Stored big-endian so the value does not depend on host byte order. */
    {
        uint64_t h = 0;
        CHECK(dnac_db_get_observed_height(db, &h) == DNAC_ERROR_NOT_FOUND,
              "an unsynced wallet reports NOT_FOUND, not a silent 0");
        CHECK(h == 0, "and leaves the output at 0");
        CHECK(dnac_db_set_observed_height(db, 9) == DNAC_SUCCESS, "set 9");
        CHECK(dnac_db_get_observed_height(db, &h) == DNAC_SUCCESS, "get");
        CHECK(h == 9, "observed height round-trips");
        CHECK(dnac_db_set_observed_height(db, 0xFEDCBA9876543210ULL)
                  == DNAC_SUCCESS, "set a large height");
        CHECK(dnac_db_get_observed_height(db, &h) == DNAC_SUCCESS, "get");
        CHECK(h == 0xFEDCBA9876543210ULL, "a full 64-bit height round-trips");
        CHECK(dnac_db_set_observed_height(db, 9) == DNAC_SUCCESS, "back to 9");
    }

    sqlite3_close(db);

    printf("test_wallet_locked_utxo: ALL %d checks passed\n", checks);
    printf("  NOTE: selection-level coverage (a locked coin must never be\n"
           "  chosen) needs a dnac_context_t and lives in the Genesis\n"
           "  Protocol harness, where the original failure reproduced.\n");
    return 0;
}
