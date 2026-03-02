/**
 * Nodus v5 — Witness Module Implementation
 *
 * Skeleton init/shutdown + lifecycle hooks.
 * BFT consensus, peer mesh, and handlers are in separate files.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_handlers.h"
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_TAG "WITNESS"

/* ── Database initialization ─────────────────────────────────────── */

static int witness_db_open(nodus_witness_t *witness, const char *data_path) {
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/witness.db",
             data_path[0] ? data_path : "/tmp");

    int rc = sqlite3_open(db_path, &witness->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: failed to open %s: %s\n",
                LOG_TAG, db_path, sqlite3_errmsg(witness->db));
        return -1;
    }

    /* WAL mode for better concurrent read performance */
    sqlite3_exec(witness->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(witness->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create tables (Phase 2 will populate these) */
    const char *schema =
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
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
        ");"
        "CREATE TABLE IF NOT EXISTS blocks ("
        "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_hash BLOB NOT NULL,"
        "  tx_type INTEGER NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  proposer_id BLOB,"
        "  created_at INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
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
        "  timestamp INTEGER NOT NULL DEFAULT (strftime('%%s','now'))"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_utxo_owner ON utxo_set(owner);"
        "CREATE INDEX IF NOT EXISTS idx_ledger_epoch ON ledger_entries(epoch);"
        "CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger_entries(tx_hash);"
        "CREATE INDEX IF NOT EXISTS idx_ctx_height ON committed_transactions(block_height);";

    char *err_msg = NULL;
    rc = sqlite3_exec(witness->db, schema, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: schema creation failed: %s\n", LOG_TAG, err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    fprintf(stderr, "%s: opened database %s\n", LOG_TAG, db_path);
    return 0;
}

/* ── Identity setup ──────────────────────────────────────────────── */

static void witness_setup_identity(nodus_witness_t *witness) {
    /* Derive witness_id from first 32 bytes of server's node_id (SHA3-512 of pk) */
    memcpy(witness->my_id, witness->server->identity.node_id.bytes,
           NODUS_T3_WITNESS_ID_LEN);
}

/* ── Roster initialization ───────────────────────────────────────── */

static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return strcmp(ea->address, eb->address);
}

static void witness_init_roster(nodus_witness_t *witness) {
    memset(&witness->roster, 0, sizeof(witness->roster));
    witness->roster.version = 1;
    witness->my_index = -1;

    /* Add self to roster if address is configured */
    if (witness->config.address[0]) {
        nodus_witness_roster_entry_t *self =
            &witness->roster.witnesses[0];
        memcpy(self->witness_id, witness->my_id, NODUS_T3_WITNESS_ID_LEN);
        memcpy(self->pubkey, witness->server->identity.pk.bytes, NODUS_PK_BYTES);
        snprintf(self->address, sizeof(self->address), "%s",
                 witness->config.address);
        self->active = true;
        witness->roster.n_witnesses = 1;
        witness->my_index = 0;
    }

    /* BFT config recalculated after roster file is loaded */
}

/**
 * Sort roster by address for deterministic ordering across all nodes.
 * Must be called after roster file is loaded.
 */
static void witness_sort_roster(nodus_witness_t *witness) {
    uint32_t n = witness->roster.n_witnesses;
    if (n < 2) return;

    qsort(witness->roster.witnesses, n,
          sizeof(nodus_witness_roster_entry_t), roster_cmp);

    /* Recalculate my_index after sort */
    witness->my_index = -1;
    for (uint32_t i = 0; i < n; i++) {
        if (memcmp(witness->roster.witnesses[i].witness_id,
                   witness->my_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
            witness->my_index = (int)i;
            break;
        }
    }

    /* Recalculate BFT config with final roster size */
    nodus_witness_bft_config_init(&witness->bft_config, n);
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_witness_init(nodus_witness_t *witness,
                       struct nodus_server *server,
                       const nodus_witness_config_t *config) {
    if (!witness || !server || !config) return -1;

    memset(witness, 0, sizeof(*witness));
    witness->server = server;
    witness->config = *config;
    witness->my_index = -1;
    witness->running = true;

    /* Setup identity from server keys */
    witness_setup_identity(witness);

    /* Open witness database */
    if (witness_db_open(witness, server->config.data_path) != 0)
        return -1;

    /* Initialize roster */
    witness_init_roster(witness);

    /* Initialize peer mesh (loads roster file, connects to peers) */
    nodus_witness_peer_init(witness);

    /* Sort roster for deterministic leader election across all nodes */
    witness_sort_roster(witness);

    fprintf(stderr, "%s: initialized (address=%s, roster=%d witnesses, my_index=%d)\n",
            LOG_TAG, config->address, witness->roster.n_witnesses,
            witness->my_index);

    return 0;
}

void nodus_witness_tick(nodus_witness_t *witness) {
    if (!witness || !witness->running) return;

    /* BFT timeout checks */
    nodus_witness_bft_check_timeout(witness);

    /* Peer mesh: reconnection, IDENT exchange */
    nodus_witness_peer_tick(witness);
}

/* ── Tier 3 dispatch (BFT message routing) ───────────────────────── */

void nodus_witness_dispatch_t3(nodus_witness_t *witness,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len) {
    (void)conn;
    if (!witness || !payload || len == 0) return;

    /* Decode T3 message */
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    if (nodus_t3_decode(payload, len, &msg) != 0) {
        fprintf(stderr, "%s: T3 decode failed (%zu bytes)\n", LOG_TAG, len);
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

    /* Close peer mesh (clears conn references) */
    nodus_witness_peer_close(witness);

    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }

    fprintf(stderr, "%s: shutdown complete\n", LOG_TAG);
}
