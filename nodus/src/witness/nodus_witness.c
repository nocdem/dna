/**
 * Nodus — Witness Module Implementation
 *
 * Skeleton init/shutdown + lifecycle hooks.
 * BFT consensus, peer mesh, and handlers are in separate files.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_sync.h"
#include "witness/nodus_witness_mempool.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "crypto/nodus_identity.h"
#include "transport/nodus_tcp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS"

/* ── Database schema ─────────────────────────────────────────────── */

static const char *WITNESS_DB_SCHEMA =
    "CREATE TABLE IF NOT EXISTS nullifiers ("
    "  nullifier BLOB PRIMARY KEY,"
    "  tx_hash BLOB NOT NULL,"
    "  added_at INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS ledger_entries ("
    "  sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  tx_hash BLOB NOT NULL,"
    "  tx_type INTEGER NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  nullifier_count INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS utxo_set ("
    "  nullifier BLOB PRIMARY KEY,"
    "  owner TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL DEFAULT x'"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "',"
    "  tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
    ");"
    /* Multi-tx block refactor (Phase 1 / Task 1.2):
     *   tx_root    = RFC 6962 Merkle root over the block's TX hashes.
     *                Replaces the legacy tx_hash column which assumed
     *                exactly one TX per block.
     *   tx_count   = number of TXs the block carries (1..NODUS_W_MAX_BLOCK_TXS).
     *   tx_type    = column DELETED. Per-TX type lives on
     *                committed_transactions.tx_type — a block can carry
     *                a mix of GENESIS/SPEND/BURN/TOKEN_CREATE TXs. */
    /* Schema v14 (Phase 2 / Task 7 — anchored merkle proofs):
     *   chain_def_blob = serialized dnac_chain_definition_t for genesis
     *                    blocks only. NULL on non-genesis blocks. */
    "CREATE TABLE IF NOT EXISTS blocks ("
    "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  tx_root BLOB NOT NULL,"
    "  tx_count INTEGER NOT NULL DEFAULT 1,"
    "  timestamp INTEGER NOT NULL,"
    "  proposer_id BLOB,"
    "  prev_hash BLOB NOT NULL DEFAULT x'',"
    "  state_root BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT (strftime('%%s','now')),"
    "  chain_def_blob BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS genesis_state ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  tx_hash BLOB NOT NULL,"
    "  total_supply INTEGER NOT NULL,"
    "  commitment BLOB,"
    "  created_at INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS committed_transactions ("
    "  tx_hash BLOB PRIMARY KEY,"
    "  tx_type INTEGER NOT NULL,"
    "  tx_data BLOB NOT NULL,"
    "  tx_len  INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  tx_index INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT (strftime('%%s','now')),"
    "  sender_fp TEXT,"
    "  fee INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS tx_outputs ("
    "  tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  owner_fp TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL DEFAULT x'"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "',"
    "  PRIMARY KEY (tx_hash, output_index)"
    ");"
    "CREATE TABLE IF NOT EXISTS commit_certificates ("
    "  block_height INTEGER NOT NULL,"
    "  voter_id BLOB NOT NULL,"
    "  vote INTEGER NOT NULL,"
    "  signature BLOB NOT NULL,"
    "  PRIMARY KEY (block_height, voter_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS tokens ("
    "  token_id BLOB PRIMARY KEY,"
    "  name TEXT NOT NULL,"
    "  symbol TEXT NOT NULL,"
    "  decimals INTEGER NOT NULL DEFAULT 8,"
    "  supply INTEGER NOT NULL,"
    "  creator_fp TEXT NOT NULL,"
    "  flags INTEGER NOT NULL DEFAULT 0,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_utxo_owner ON utxo_set(owner);"
    "CREATE INDEX IF NOT EXISTS idx_utxo_token ON utxo_set(token_id);"
    "CREATE INDEX IF NOT EXISTS idx_ledger_epoch ON ledger_entries(epoch);"
    "CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger_entries(tx_hash);"
    /* Composite (block_height, tx_index) for per-block ordering — schema v12 */
    "CREATE INDEX IF NOT EXISTS idx_ctx_block ON committed_transactions(block_height, tx_index);"
    "CREATE INDEX IF NOT EXISTS idx_ctx_sender ON committed_transactions(sender_fp);"
    "CREATE INDEX IF NOT EXISTS idx_txout_owner ON tx_outputs(owner_fp);"
    /* ── Task 11 — stake/delegation/reward tables (design §3.7) ───── */
    "CREATE TABLE IF NOT EXISTS validators ("
    "  pubkey_hash BLOB PRIMARY KEY,"
    "  pubkey BLOB NOT NULL,"
    "  self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL DEFAULT 0,"
    "  external_delegated INTEGER NOT NULL DEFAULT 0,"
    "  commission_bps INTEGER NOT NULL,"
    "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
    "  status INTEGER NOT NULL,"
    "  active_since_block INTEGER NOT NULL,"
    "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_destination_fp TEXT NOT NULL,"
    "  unstake_destination_pubkey BLOB NOT NULL,"
    "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
    "  last_signed_block INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_validator_rank "
    "ON validators ((self_stake + external_delegated) DESC);"
    "CREATE TABLE IF NOT EXISTS delegations ("
    "  delegator_hash BLOB,"
    "  validator_hash BLOB,"
    "  delegator_pubkey BLOB NOT NULL,"
    "  validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  delegated_at_block INTEGER NOT NULL,"
    "  reward_snapshot BLOB NOT NULL,"
    "  PRIMARY KEY (delegator_hash, validator_hash)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_delegator ON delegations (delegator_hash);"
    "CREATE INDEX IF NOT EXISTS idx_validator ON delegations (validator_hash);"
    "CREATE TABLE IF NOT EXISTS rewards ("
    "  validator_hash BLOB PRIMARY KEY,"
    "  accumulator BLOB NOT NULL,"
    "  validator_unclaimed INTEGER NOT NULL,"
    "  last_update_block INTEGER NOT NULL,"
    "  residual_dust INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS validator_stats ("
    "  key TEXT PRIMARY KEY,"
    "  value INTEGER NOT NULL"
    ");"
    "INSERT OR IGNORE INTO validator_stats (key, value) VALUES ('active_count', 0);";

/* ── Set chain ID ────────────────────────────────────────────────── */

void nodus_witness_set_chain_id(nodus_witness_t *witness,
                                const uint8_t *chain_id) {
    if (!witness || !chain_id) return;
    /* Canonical chain_id is 16 bytes; we store 32 for wire symmetry with
     * T3 headers but bytes 16-31 are ALWAYS zero. Any path that computes
     * chain_id (live genesis derive, filename scan, DB load) must agree
     * on this layout so CHAIN_QUORUM comparisons are stable across
     * restarts. See nodus_derive_chain_id in nodus_witness_bft.c. */
    memcpy(witness->chain_id, chain_id, 16);
    memset(witness->chain_id + 16, 0, 16);

    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", witness->chain_id[i]);
    fprintf(stderr, "%s: chain_id set: %s\n", LOG_TAG, hex);
}

/* ── Open a witness chain DB by full path ────────────────────────── */

static int witness_db_open_path(nodus_witness_t *witness, const char *db_path) {
    int rc = sqlite3_open(db_path, &witness->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: failed to open %s: %s\n",
                LOG_TAG, db_path, sqlite3_errmsg(witness->db));
        return -1;
    }

    sqlite3_exec(witness->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(witness->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* ── Migration: add sender_fp/fee columns to committed_transactions.
     * Must run BEFORE schema exec because indexes reference these columns.
     * ALTER errors (duplicate column) are silently ignored. */
    sqlite3_exec(witness->db,
        "ALTER TABLE committed_transactions ADD COLUMN sender_fp TEXT;",
        NULL, NULL, NULL);
    sqlite3_exec(witness->db,
        "ALTER TABLE committed_transactions ADD COLUMN fee INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    /* Legacy columns from v0.10.25 — kept for backwards compat, unused */
    sqlite3_exec(witness->db,
        "ALTER TABLE committed_transactions ADD COLUMN receiver_fp TEXT;",
        NULL, NULL, NULL);
    sqlite3_exec(witness->db,
        "ALTER TABLE committed_transactions ADD COLUMN amount INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    /* Multi-token: per-output token_id for transaction history filtering */
    {
        const char *alter_sql =
            "ALTER TABLE tx_outputs ADD COLUMN token_id BLOB NOT NULL DEFAULT x'"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "';";
        sqlite3_exec(witness->db, alter_sql, NULL, NULL, NULL);
    }

    char *err_msg = NULL;
    rc = sqlite3_exec(witness->db, WITNESS_DB_SCHEMA, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: schema creation failed: %s\n", LOG_TAG, err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Schema v12 migration (Phase 1 / Task 1.1). Idempotent; aborts on
     * unrecoverable error. */
    nodus_witness_db_migrate_v12(witness);

    fprintf(stderr, "%s: opened database %s\n", LOG_TAG, db_path);
    return 0;
}

/* ── Scan data dir for existing witness_*.db → load chain_id ─────── */
/* TODO: Legacy migration — if DB was created with old naming (raw tx_hash as chain_id),
 * derive new chain_id from genesis TX data in DB and rename file.
 * Not needed yet — all current deployments are pre-genesis. */

static int witness_scan_chain_db(nodus_witness_t *witness) {
    const char *data_path = witness->data_path;
    DIR *dir = opendir(data_path);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Match witness_<hex>.db */
        if (strncmp(entry->d_name, "witness_", 8) != 0) continue;
        const char *hex_start = entry->d_name + 8;
        const char *dot = strstr(hex_start, ".db");
        if (!dot || dot == hex_start) continue;

        size_t hex_len = (size_t)(dot - hex_start);
        if (hex_len < 2 || hex_len > 64) continue;

        /* Parse chain_id from hex prefix in filename */
        uint8_t chain_id[32] = {0};
        size_t bytes = hex_len / 2;
        if (bytes > 32) bytes = 32;
        for (size_t i = 0; i < bytes; i++) {
            unsigned int byte;
            if (sscanf(hex_start + i * 2, "%2x", &byte) != 1) break;
            chain_id[i] = (uint8_t)byte;
        }

        /* Open this chain DB */
        char db_path[512];
        snprintf(db_path, sizeof(db_path), "%s/%s", data_path, entry->d_name);

        if (witness_db_open_path(witness, db_path) == 0) {
            nodus_witness_set_chain_id(witness, chain_id);

            char hex[17];
            for (int i = 0; i < 8; i++)
                snprintf(hex + i * 2, 3, "%02x", chain_id[i]);
            fprintf(stderr, "%s: loaded chain %s from %s\n",
                    LOG_TAG, hex, entry->d_name);

            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;  /* No chain DB found — pre-genesis */
}

/* ── Archive stale chain DB files (Fix 1 — prevent orphan forks) ──
 *
 * Before creating a new witness_<chain>.db, move every existing
 * witness_<other>.db (and its -wal / -shm siblings) into <data>/archive/.
 * Never deletes — only renames atomically so we can recover for forensics.
 *
 * This plugs the orphan-DB class of bug that produced the EU-6 fork on
 * 2026-04-10: the scanner's first-match-wins behavior silently picks up
 * a stale file from a prior chain lifecycle and activates the wrong chain.
 */
static int witness_archive_stale_chain_dbs(nodus_witness_t *witness,
                                           const char *keep_filename) {
    const char *data_path = witness->data_path;

    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", data_path);
    /* mkdir -p; ignore EEXIST */
    if (mkdir(archive_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "%s: archive mkdir failed: %s (continuing)\n",
                LOG_TAG, strerror(errno));
        return -1;
    }

    DIR *dir = opendir(data_path);
    if (!dir) return -1;

    int archived = 0;
    uint64_t ts = (uint64_t)time(NULL);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Only match witness_<hex>.db* (db, db-wal, db-shm) */
        if (strncmp(entry->d_name, "witness_", 8) != 0) continue;
        /* Skip the file we're about to open — match its prefix exactly */
        const char *dot_db = strstr(entry->d_name, ".db");
        if (!dot_db) continue;
        size_t prefix_len = (size_t)(dot_db - entry->d_name) + 3;  /* include ".db" */
        if (prefix_len > strlen(entry->d_name)) continue;
        if (strncmp(entry->d_name, keep_filename, prefix_len) == 0) continue;

        char src[768];
        char dst[1024];
        snprintf(src, sizeof(src), "%s/%s", data_path, entry->d_name);
        snprintf(dst, sizeof(dst), "%s/%" PRIu64 "_%s",
                 archive_dir, ts, entry->d_name);

        if (rename(src, dst) == 0) {
            fprintf(stderr, "%s: archived stale chain file %s -> %s\n",
                    LOG_TAG, entry->d_name, dst);
            archived++;
        } else {
            fprintf(stderr, "%s: failed to archive %s: %s\n",
                    LOG_TAG, src, strerror(errno));
        }
    }
    closedir(dir);

    if (archived > 0)
        fprintf(stderr, "%s: archived %d stale chain file(s) before creating new chain DB\n",
                LOG_TAG, archived);
    return 0;
}

/* ── Create chain DB on genesis commit (called from BFT) ────────── */

int nodus_witness_create_chain_db(nodus_witness_t *witness,
                                    const uint8_t *chain_id) {
    if (!witness || !chain_id) return -1;

    /* Close old DB if any */
    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }

    /* Build filename: witness_<first16bytes_hex>.db */
    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", chain_id[i]);

    char basename[128];
    snprintf(basename, sizeof(basename), "witness_%s.db", hex);

    /* Fix 1: atomically archive any pre-existing witness_*.db files that
     * do NOT match the target chain. Prevents orphaned chain DBs from
     * co-existing on disk and fooling the next restart's scanner. */
    witness_archive_stale_chain_dbs(witness, basename);

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/%s", witness->data_path, basename);

    if (witness_db_open_path(witness, db_path) != 0)
        return -1;

    nodus_witness_set_chain_id(witness, chain_id);

    fprintf(stderr, "%s: created chain DB %s\n", LOG_TAG, db_path);
    return 0;
}

/* ── Identity setup ──────────────────────────────────────────────── */

static void witness_setup_identity(nodus_witness_t *witness) {
    /* Derive witness_id from first 32 bytes of server's node_id (SHA3-512 of pk) */
    memcpy(witness->my_id, witness->server->identity.node_id.bytes,
           NODUS_T3_WITNESS_ID_LEN);
}

/* ── Roster initialization ───────────────────────────────────────── */

static void witness_init_roster(nodus_witness_t *witness) {
    memset(&witness->roster, 0, sizeof(witness->roster));
    witness->roster.version = 1;
    witness->my_index = -1;
    witness->last_epoch = 0;
    witness->pending_roster_ready = false;
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_witness_init(nodus_witness_t *witness,
                       struct nodus_server *server,
                       const nodus_witness_config_t *config) {
    if (!witness || !server || !config) return -1;

    /* Preserve tcp pointer (set by server before init) */
    void *saved_tcp = witness->tcp;
    memset(witness, 0, sizeof(*witness));
    witness->server = server;
    witness->tcp = saved_tcp;  /* Restore dedicated witness TCP transport */
    witness->config = *config;
    witness->my_index = -1;
    witness->running = true;

    /* Setup identity from server keys */
    witness_setup_identity(witness);

    /* Save data path for chain DB creation on genesis */
    snprintf(witness->data_path, sizeof(witness->data_path), "%s",
             server->config.data_path);

    /* Scan for existing chain DB (witness_<chain_id>.db).
     * If found: opens DB + sets chain_id.
     * If not found: db = NULL (pre-genesis state, waiting for genesis TX). */
    if (witness_scan_chain_db(witness) != 0) {
        fprintf(stderr, "%s: no chain DB found — pre-genesis state\n", LOG_TAG);
    }

    /* Fix 3: record activation time for the chain_id quorum-check window.
     * Within the first 300s after activation, every incoming w_ident is
     * compared against our local chain_id; if a strict majority of
     * observed peers disagree (and >=2 dissenters), the witness
     * quarantines itself. See nodus_witness_peer_handle_ident. */
    witness->activated_at_sec = (uint64_t)time(NULL);
    witness->quarantined = false;
    witness->chain_dissent_count = 0;
    witness->chain_agree_count = 0;

    /* Initialize roster */
    witness_init_roster(witness);

    /* Initialize peer mesh (builds roster, connects seeds on witness port) */
    nodus_witness_peer_init(witness);

    fprintf(stderr, "%s: initialized (roster=%d witnesses, my_index=%d, "
            "chain_db=%s)\n",
            LOG_TAG, witness->roster.n_witnesses, witness->my_index,
            witness->db ? "active" : "pre-genesis");

    return 0;
}

/* ── Block timer: propose batch from mempool ────────────────────── */

/* Phase 7 / Task 7.2 — body moved to nodus_witness_bft.c as
 * nodus_witness_bft_start_round_from_mempool. The static helpers
 * nodus_compute_output_nullifier and nodus_extract_output_nullifiers
 * moved with it. The block timer at line ~654 below now calls the
 * public API directly. */

#define WITNESS_EPOCH_SECS  60

void nodus_witness_tick(nodus_witness_t *witness) {
    if (!witness || !witness->running) return;

    /* Poll dedicated witness TCP transport (port 4004) */
    if (witness->tcp)
        nodus_tcp_poll((nodus_tcp_t *)witness->tcp, 50);

    /* BFT timeout checks */
    nodus_witness_bft_check_timeout(witness);

    /* H-15: Pending forward timeout (30s) */
    {
        uint64_t now_s = nodus_time_now();
        for (int pfi = 0; pfi < NODUS_W_MAX_PENDING_FWD; pfi++) {
            if (!witness->pending_forwards[pfi].active) continue;
            if (now_s - witness->pending_forwards[pfi].started_at > 30) {
                fprintf(stderr, "WITNESS: pending_forward[%d] timed out after 30s\n", pfi);
                witness->pending_forwards[pfi].active = false;
                witness->pending_forwards[pfi].client_conn = NULL;
            }
        }
    }

    /* Block timer: propose batch if mempool has TXs and interval elapsed */
    if (nodus_witness_bft_is_leader(witness) &&
        witness->round_state.phase == NODUS_W_PHASE_IDLE &&
        witness->mempool.count > 0) {

        uint64_t now_ms = nodus_time_now() * 1000ULL;
        if (now_ms - witness->mempool.last_block_time_ms >=
            NODUS_W_BLOCK_INTERVAL_MS) {
            (void)nodus_witness_bft_start_round_from_mempool(witness);
        }
    }

    /* Drain stale mempool entries when no longer leader.
     * Only check once per epoch (60s) to avoid flap-induced drops.
     * Forwarded entries (client_conn == NULL) would be stranded forever
     * since no client disconnect would trigger remove_by_conn. */
    if (!nodus_witness_bft_is_leader(witness) &&
        witness->mempool.count > 0 &&
        nodus_time_now() - witness->last_epoch < 2) {
        /* Runs once right after epoch tick rebuilds roster */
        fprintf(stderr, "WITNESS: not leader, draining %d mempool entries\n",
                witness->mempool.count);
        nodus_witness_mempool_clear(&witness->mempool);
    }

    /* Peer mesh: reconnection, IDENT exchange */
    nodus_witness_peer_tick(witness);

    /* Epoch tick: rebuild roster every 60s */
    uint64_t now = nodus_time_now();
    if (now - witness->last_epoch >= WITNESS_EPOCH_SECS) {
        witness->last_epoch = now;

        /* Build new roster from DHT registry + witness peer connections */
        nodus_witness_rebuild_roster_from_peers(witness, &witness->pending_roster);
        nodus_witness_bft_config_init(&witness->pending_bft_config,
                                       witness->pending_roster.n_witnesses);

        /* Check if roster actually changed */
        bool changed = (witness->pending_roster.n_witnesses != witness->roster.n_witnesses);
        if (!changed) {
            for (uint32_t i = 0; i < witness->roster.n_witnesses; i++) {
                if (memcmp(witness->roster.witnesses[i].witness_id,
                           witness->pending_roster.witnesses[i].witness_id,
                           NODUS_T3_WITNESS_ID_LEN) != 0) {
                    changed = true;
                    break;
                }
            }
        }

        if (!changed) {
            /* No change — skip swap */
            return;
        }

        /* Try to swap immediately if IDLE */
        if (witness->round_state.phase == NODUS_W_PHASE_IDLE) {
            /* Swap roster */
            memcpy(&witness->roster, &witness->pending_roster,
                   sizeof(nodus_witness_roster_t));
            memcpy(&witness->bft_config, &witness->pending_bft_config,
                   sizeof(nodus_witness_bft_config_t));
            witness->pending_roster_ready = false;

            /* Recalculate my_index */
            witness->my_index = nodus_witness_roster_find(&witness->roster,
                                                            witness->my_id);

            fprintf(stderr, "WITNESS: epoch roster swap: %u witnesses, "
                    "quorum=%u, my_index=%d\n",
                    witness->roster.n_witnesses,
                    witness->bft_config.quorum,
                    witness->my_index);
        } else {
            /* Round active — defer swap to next IDLE */
            witness->pending_roster_ready = true;
            fprintf(stderr, "WITNESS: epoch roster pending (round active, "
                    "phase=%d, pending=%u witnesses)\n",
                    witness->round_state.phase,
                    witness->pending_roster.n_witnesses);
        }
    }

    /* Check if deferred roster swap can happen now */
    if (witness->pending_roster_ready &&
        witness->round_state.phase == NODUS_W_PHASE_IDLE) {
        memcpy(&witness->roster, &witness->pending_roster,
               sizeof(nodus_witness_roster_t));
        memcpy(&witness->bft_config, &witness->pending_bft_config,
               sizeof(nodus_witness_bft_config_t));
        witness->pending_roster_ready = false;

        witness->my_index = nodus_witness_roster_find(&witness->roster,
                                                        witness->my_id);

        fprintf(stderr, "WITNESS: deferred roster swap: %u witnesses, "
                "quorum=%u, my_index=%d\n",
                witness->roster.n_witnesses,
                witness->bft_config.quorum,
                witness->my_index);
    }

    /* State sync: check if behind peers and need to catch up */
    nodus_witness_sync_check(witness);
}

/* ── Tier 3 dispatch (BFT message routing) ───────────────────────── */

void nodus_witness_dispatch_t3(nodus_witness_t *witness,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len) {
    if (!witness || !payload || len == 0) return;

    /* Decode T3 message */
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    if (nodus_t3_decode(payload, len, &msg) != 0) {
        /* Malformed T3 frame — log with context for diagnosis */
        char hex[49] = {0};
        size_t dump_len = len < 24 ? len : 24;
        for (size_t i = 0; i < dump_len; i++)
            snprintf(hex + i*2, 3, "%02x", payload[i]);
        fprintf(stderr, "%s: T3 decode failed (%zu bytes) src=%s:%u head=%s\n",
                LOG_TAG, len,
                conn ? conn->ip : "?", conn ? conn->port : 0, hex);
        return;
    }

    /* Look up sender in roster to get public key for verification */
    int sender_idx = nodus_witness_roster_find(&witness->roster,
                                                 msg.header.sender_id);

    /* IDENT messages may come from unknown senders (Phase 5) */
    if (msg.type != NODUS_T3_IDENT) {
        if (sender_idx < 0) {
            fprintf(stderr, "%s: T3 %s from unknown sender, ignoring\n",
                    LOG_TAG, msg.method);
            return;
        }

        /* Verify wsig against sender's roster public key */
        nodus_pubkey_t pk;
        memcpy(pk.bytes,
               witness->roster.witnesses[sender_idx].pubkey,
               NODUS_PK_BYTES);

        if (nodus_t3_verify(&msg, &pk) != 0) {
            fprintf(stderr, "%s: T3 %s wsig verification failed (roster %d)\n",
                    LOG_TAG, msg.method, sender_idx);
            return;
        }
    }

    /* Register inbound conn as peer so broadcasts reach this sender */
    if (sender_idx >= 0 && conn)
        nodus_witness_peer_ensure(witness, msg.header.sender_id, conn);

    /* Fix 3: if we have self-quarantined due to chain_id disagreement with a
     * majority of peers on startup, refuse to participate in BFT consensus.
     * Still accept IDENT / ROST_Q/R (so the peer mesh stays alive) and SYNC
     * messages (read-only, can't affect chain state) so an operator can
     * diagnose and recover without tearing the node down. */
    if (witness->quarantined) {
        switch (msg.type) {
        case NODUS_T3_PROPOSE:
        case NODUS_T3_PREVOTE:
        case NODUS_T3_PRECOMMIT:
        case NODUS_T3_COMMIT:
        case NODUS_T3_VIEWCHG:
        case NODUS_T3_NEWVIEW:
        case NODUS_T3_FWD_REQ:
        case NODUS_T3_FWD_RSP:
            fprintf(stderr, "%s: QUARANTINED — dropping %s (chain_id disagreement with quorum)\n",
                    LOG_TAG, msg.method);
            return;
        default:
            break;
        }
    }

    /* Route to appropriate handler */
    switch (msg.type) {
    case NODUS_T3_PROPOSE:
        nodus_witness_bft_handle_propose(witness, &msg);
        break;
    case NODUS_T3_PREVOTE:
    case NODUS_T3_PRECOMMIT:
        nodus_witness_bft_handle_vote(witness, &msg);
        break;
    case NODUS_T3_COMMIT:
        nodus_witness_bft_handle_commit(witness, &msg);
        break;
    case NODUS_T3_VIEWCHG:
        nodus_witness_bft_handle_viewchg(witness, &msg);
        break;
    case NODUS_T3_NEWVIEW:
        nodus_witness_bft_handle_newview(witness, &msg);
        break;

    /* Peer mesh messages */
    case NODUS_T3_FWD_REQ:
        nodus_witness_peer_handle_fwd_req(witness, &msg);
        break;
    case NODUS_T3_FWD_RSP:
        nodus_witness_peer_handle_fwd_rsp(witness, &msg);
        break;
    case NODUS_T3_ROST_Q:
        nodus_witness_peer_handle_rost_q(witness, conn, &msg);
        break;
    case NODUS_T3_ROST_R:
        nodus_witness_peer_handle_rost_r(witness, &msg);
        break;
    case NODUS_T3_IDENT:
        nodus_witness_peer_handle_ident(witness, conn, &msg);
        break;

    /* State sync messages */
    case NODUS_T3_SYNC_REQ:
        nodus_witness_sync_handle_req(witness, conn, &msg);
        break;
    case NODUS_T3_SYNC_RSP:
        nodus_witness_sync_handle_rsp(witness, &msg);
        break;

    default:
        fprintf(stderr, "%s: unknown T3 message type %d\n",
                LOG_TAG, msg.type);
        break;
    }
}

void nodus_witness_dispatch_dnac(nodus_witness_t *witness,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t *payload, size_t payload_len,
                                 const char *method, uint32_t txn_id) {
    if (!witness || !conn || !payload || !method) return;

    nodus_witness_handle_dnac(witness, conn, payload, payload_len,
                                method, txn_id);
}

/* ── Shutdown ────────────────────────────────────────────────────── */

void nodus_witness_close(nodus_witness_t *witness) {
    if (!witness) return;

    witness->running = false;

    /* Free any in-flight batch entries (prevents leak / corruption on shutdown) */
    for (int i = 0; i < witness->round_state.batch_count; i++) {
        if (witness->round_state.batch_entries[i]) {
            nodus_witness_mempool_entry_free(witness->round_state.batch_entries[i]);
            witness->round_state.batch_entries[i] = NULL;
        }
    }
    witness->round_state.batch_count = 0;

    /* Clear mempool */
    nodus_witness_mempool_clear(&witness->mempool);

    /* Close peer mesh (clears conn references) */
    nodus_witness_peer_close(witness);

    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }

    fprintf(stderr, "%s: shutdown complete\n", LOG_TAG);
}
