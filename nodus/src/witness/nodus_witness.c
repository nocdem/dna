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
#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness_v2_pools.h"  /* S7 startup check      */
#include "witness/nodus_witness_v2_finalize.h" /* O14 version firewall */
#include "witness/nodus_witness_v2_gate.h"      /* O15B activation gate  */
#include "witness/nodus_witness_v2_ingress.h"   /* O15B ingress arming   */
#include "witness/nodus_witness_v2_preflight.h" /* O15A readiness report */
/* O15J Faz 3 — chain-role derivation is what makes a Ledger V2 database
 * refuse every legacy lane. With the activation ceremony gone there is
 * exactly ONE way a V2 chain comes into being, and exactly one probe for
 * it: nodus_witness_v2_gen_is_pure. */
#include "witness/nodus_witness_v2_gen.h"       /* O15J pure-V2 chain role   */
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_sync2.h"     /* O15E successor sync seam */
#include "witness/nodus_witness_v2_join.h"      /* O15E pinned-genesis joiner */
/* O15I V1 — the committed-INTENT authority behind the P3(c) reaper and
 * the P3(a) demand predicate: the envelope preflight seam, the entry
 * classifier + tip helper, and the domain registry the contextual ruleset
 * table is resolved from. */
#include "witness/nodus_witness_v2_env.h"       /* env preflight seam    */
#include "witness/nodus_witness_v2_produce.h"   /* classify_entry / tip  */
#include "witness/nodus_witness_domreg.h"       /* contextual rulesets   */
#include "nodus/nodus_chain_config.h"  /* Stage C.2 vote-req handler */
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_tier2.h"  /* MED-27: pending_forward timeout error */
#include "server/nodus_server.h"
#include "crypto/nodus_identity.h"
#include "transport/nodus_tcp.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS"

/* ── Database schema ─────────────────────────────────────────────── */

static const char *WITNESS_DB_SCHEMA =
    "CREATE TABLE IF NOT EXISTS nullifiers ("
    "  nullifier BLOB PRIMARY KEY,"
    "  tx_hash BLOB NOT NULL,"
    "  added_at INTEGER NOT NULL DEFAULT 0"
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
    "  created_at INTEGER NOT NULL DEFAULT 0"
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
    "  created_at INTEGER NOT NULL DEFAULT 0,"
    "  chain_def_blob BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS genesis_state ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  tx_hash BLOB NOT NULL,"
    "  total_supply INTEGER NOT NULL,"
    "  commitment BLOB,"
    "  created_at INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS committed_transactions ("
    "  tx_hash BLOB PRIMARY KEY,"
    "  tx_type INTEGER NOT NULL,"
    "  tx_data BLOB NOT NULL,"
    "  tx_len  INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  tx_index INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0,"
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
    "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
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
    "  PRIMARY KEY (delegator_hash, validator_hash)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_delegator ON delegations (delegator_hash);"
    "CREATE INDEX IF NOT EXISTS idx_validator ON delegations (validator_hash);"
    /* v0.16 stage B.1 — push-settlement epoch state. At most one row
     * is active at a time (previous epoch deleted at settlement in
     * Stage E). */
    "CREATE TABLE IF NOT EXISTS epoch_state ("
    "  epoch_start_height INTEGER PRIMARY KEY,"
    "  epoch_pool_accum   INTEGER NOT NULL DEFAULT 0,"
    "  snapshot_hash      BLOB NOT NULL,"
    "  snapshot_blob      BLOB"
    ");"
    /* Supply counters. Historically this table was created ONLY by
     * nodus_witness_supply_init (nodus_witness_db.c:879-888), which runs
     * at genesis commit — so a node that created its chain DB and then
     * joined before replaying genesis had no such table at all, and every
     * supply read/write against it silently no-op'd. Definition is
     * column-for-column the one in supply_init (including the
     * total_minted column that the ALTER at nodus_witness_db.c:892-894
     * back-fills into pre-v0.16 DBs); supply_init's own
     * CREATE TABLE IF NOT EXISTS stays and is a no-op once we are here.
     * NO row is inserted: an absent id=1 row is the correct pre-genesis
     * state, and nodus_witness_supply_get already treats "no row" as
     * "not initialised" (nodus_witness_db.c:925-928). */
    "CREATE TABLE IF NOT EXISTS supply_tracking ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  genesis_supply INTEGER NOT NULL,"
    "  total_burned INTEGER NOT NULL DEFAULT 0,"
    "  total_minted INTEGER NOT NULL DEFAULT 0,"
    "  current_supply INTEGER NOT NULL,"
    "  last_tx_hash BLOB NOT NULL,"
    "  last_sequence INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS validator_stats ("
    "  key TEXT PRIMARY KEY,"
    "  value INTEGER NOT NULL"
    ");"
    /* ── Ledger V2 S3 — per-epoch validator-set snapshots (INACTIVE).
     * Rows are written by nodus_witness_vset_insert and read back by
     * nodus_witness_vset_get / nodus_witness_vset_root. Nothing on the
     * live consensus path writes or reads this table yet; a later wave
     * wires the genesis/epoch-boundary calls. Creating it here (rather
     * than lazily) keeps a node that made its DB before genesis from
     * silently having no such table — the class of bug the supply_tracking
     * comment above records.
     *   epoch_start       EPOCH START HEIGHT, the canonical epoch key
     *                     (same value as epoch_state.epoch_start_height).
     *   snapshot_hash     64 bytes, dna_vset_hash of snapshot_blob.
     *   snapshot_blob     the canonical bytes (shared/dnac/vset_wire.h).
     *   created_at_height the block height that produced the row —
     *                     provenance only, never hashed. */
    "CREATE TABLE IF NOT EXISTS validator_set_snapshots ("
    "  epoch_start INTEGER PRIMARY KEY,"
    "  active_count INTEGER NOT NULL,"
    "  snapshot_hash BLOB NOT NULL,"
    "  snapshot_blob BLOB NOT NULL,"
    "  created_at_height INTEGER NOT NULL"
    ");"

    /* Ledger V2 S4 (INACTIVE until the V2 devnet reset) — domain registry.
     *   record            the 223-byte canonical DomainRegistryRecord
     *                     (shared/dnac/domain_wire.h); decoded + validated
     *                     fail-closed on every read.
     *   current_manifest  canonical DomainManifest bytes; its DOMMAN hash
     *                     must equal the record's current_manifest_hash.
     *   pending_manifest  canonical bytes of a pending upgrade target, or
     *                     NULL; present IFF the record says so. */
    "CREATE TABLE IF NOT EXISTS domain_registry ("
    "  domain_id INTEGER PRIMARY KEY,"
    "  record BLOB NOT NULL,"
    "  current_manifest BLOB NOT NULL,"
    "  pending_manifest BLOB"
    ");"

    /* Ledger V2 S4 — validator runtime-readiness signals, keyed by the
     * proposal digest they are cast for. The 4844-byte wire signal is
     * stored verbatim; the PRIMARY KEY makes a duplicate (proposal, voter)
     * structurally unable to increase any count. */
    "CREATE TABLE IF NOT EXISTS domain_readiness ("
    "  proposal_digest BLOB NOT NULL,"
    "  voter_id BLOB NOT NULL,"
    "  signal BLOB NOT NULL,"
    "  PRIMARY KEY (proposal_digest, voter_id)"
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

/* O15K E2 — FAIL CLOSED. Every failure exit of witness_db_open_path goes
 * through here, because a half-open handle is the shape this project
 * forbids under "A DB failure is never a value": sqlite3_open can succeed
 * and a later step fail, and the old code returned -1 while LEAVING
 * witness->db assigned. The caller (nodus_witness_scan_chain_db) discards
 * the rc, so the node came up reporting `chain_db=active` while
 * nodus_witness_init had already logged "no chain DB found — pre-genesis
 * state". Worse, the chain id was never installed, and a zeroed chain id
 * is read as "pre-genesis" by BOTH nodus_witness_bft.c's verify_chain_id
 * (CRITICAL-2 cross-chain replay protection) and
 * nodus_witness_peer.c's witness_chain_quorum_observe (the self-quarantine
 * safety net) — so the node ran with its replay guard off and its
 * divergence detector blind, and could never verify a certificate again.
 * Full write-up: nodus/BUGS.md, the top OPEN entry. */
static int witness_db_open_fail(nodus_witness_t *witness) {
    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }
    return -1;
}

static int witness_db_open_path(nodus_witness_t *witness, const char *db_path) {
    int rc = sqlite3_open(db_path, &witness->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: failed to open %s: %s\n",
                LOG_TAG, db_path, sqlite3_errmsg(witness->db));
        return witness_db_open_fail(witness);
    }

    /* O15K E1 — WAIT THE LOCK OUT; do not fail on a transient one.
     * Without a busy timeout SQLite returns SQLITE_BUSY immediately, so a
     * node restarted while the previous process's WAL recovery is still
     * settling — the ordinary `kill -9` + restart an operator performs —
     * failed the schema exec below with "database is locked" and fell
     * through to the half-open state described above. This is the same
     * class O15J's f08fbcdc fixed by putting a busy timeout on the V2
     * probe connection (nodus_witness_v2_gen.c); the MAIN chain-DB
     * connection never got one, and it is the one every restart uses.
     *
     * It also draws the transient/permanent line without inventing a
     * mechanism: SQLite retries internally for the timeout, so a BUSY
     * that survives it is a genuinely persistent lock and failing is then
     * the correct answer. */
    sqlite3_busy_timeout(witness->db, NODUS_W_DB_BUSY_TIMEOUT_MS);

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
        return witness_db_open_fail(witness);
    }

    /* Schema v12 migration (Phase 1 / Task 1.1). Idempotent; aborts on
     * unrecoverable error. */
    nodus_witness_db_migrate_v12(witness);

    /* PR 3 Yol B / H-5: restore PBFT runtime state across restart.
     * MUST happen after migrate_v12 (which creates the pbft_state
     * table) and BEFORE this witness participates in any consensus
     * round. Fresh DB or NULL row leaves current_view at 0 and
     * last_prepared.present at false — same as today's behaviour. */
    nodus_witness_db_load_pbft_state(witness);

    fprintf(stderr, "%s: opened database %s\n", LOG_TAG, db_path);
    return 0;
}

/* ── Scan data dir for existing witness_*.db → load chain_id ─────── */
/* TODO: Legacy migration — if DB was created with old naming (raw tx_hash as chain_id),
 * derive new chain_id from genesis TX data in DB and rename file.
 * Not needed yet — all current deployments are pre-genesis. */

/* ── O15A: the ONE post-open integrity gate ──────────────────────────
 *
 * Every path that brings a chain database to a usable state must run the
 * SAME checks. Before O15A these two lived inline in
 * nodus_witness_create_chain_db only, so an ordinary RESTART — which
 * reaches the database through witness_scan_chain_db instead — ran
 * neither, and a database that would have been refused at creation was
 * accepted on every subsequent boot. Restart is the common case, since
 * creation happens once.
 *
 * Both checks are legacy-safe by construction, which is why they can be
 * hoisted onto the live restart path without changing how a legacy chain
 * opens: the S7 pool check passes vacuously on a pre-v7 database, and the
 * O14 selfcheck is pure and inert (every probe returns from the version
 * dispatch, so it resolves no snapshot, verifies no certificate, reads no
 * row and requires no schema version).
 *
 * On failure the database is CLOSED and refused — never repaired.
 * Returns 0 when the database may be used, -1 when it must not be.
 */
static int witness_post_open_gate(nodus_witness_t *witness,
                                  const char *db_path) {
    /* Ledger V2 S7 — fail-closed pool-state startup verification:
     * full ordered nullifier-log replay + derived note-table shape,
     * BEFORE the witness may validate or apply any Ledger V2 block. */
    if (nodus_witness_v2_pools_startup_check(witness) != 0) {
        fprintf(stderr, "%s: S7 pool-state startup verification FAILED "
                "for %s — refusing the database (fail closed)\n",
                LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    /* Ledger V2 O14 — assert this build's V2 version firewall at open:
     * a RETIRED (v2) header and an UNKNOWN header must both be verdicts
     * and must never be reinterpreted under the v3 layout, and a NULL
     * argument must stay a node fault. */
    if (nodus_witness_v2_finalize_selfcheck(witness) != 0) {
        fprintf(stderr, "%s: V2 header version firewall SELFCHECK FAILED "
                "for %s — refusing the database (fail closed)\n",
                LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    /* ── Ledger V2 O15B — ACTIVATION ORDERING, ENFORCED HERE ──────────
     *
     * O15B built the V2 network surface (wire codec, ingress adapter,
     * bounded sync) and ships it PRODUCTION-DORMANT. This block is where
     * "dormant" is established on every database open, in the order §12
     * requires: the node is DISARMED first, the preflight then runs, and
     * only a passing gate could arm anything — so ingress can never become
     * reachable before readiness has been evaluated.
     *
     * Explicitly disarming rather than relying on zero-initialisation is
     * deliberate: this runs on REOPEN as well as creation, and a handle
     * reused across a close/open must not inherit an armed flag from a
     * previous life.
     *
     * The arm attempt is REAL, not a formality. It drives the production
     * gate on every open, so if a future change ever made the gate open
     * without committed authority, this would arm a node and the preflight
     * would immediately raise INGRESS_ENABLED — instead of the condition
     * going unnoticed because nothing exercised it.
     *
     * A refusal is the EXPECTED outcome and is NOT an error: the database
     * is fine, this build simply cannot activate Ledger V2. It never
     * refuses the database, because a legacy chain's open must not come to
     * depend on Ledger V2 state.
     */
    /* O15J Faz 3 — the at-open migration of the two activation tables is
     * deleted with the ceremony. It ran only in the ceremony's rehearsal
     * builds, and the tables it created no longer exist in the schema
     * ladder (nodus_witness_v2_schema.c, S10). Nothing replaces it: a
     * pure-V2 database is migrated once, by its builder. */

    nodus_witness_v2_ingress_disarm(witness);

    nodus_v2_preflight_report_t pf;
    if (nodus_witness_v2_preflight(witness, &pf) == 0) {
        if (!pf.ready) {
            fprintf(stderr,
                    "%s: Ledger V2 NOT ACTIVATED — preflight reports %zu "
                    "blocking issue(s); first: %s\n",
                    LOG_TAG, pf.n_issues,
                    pf.n_issues ? nodus_witness_v2_preflight_issue_name(
                                      pf.issues[0])
                                : "none");
        }
    } else {
        fprintf(stderr, "%s: Ledger V2 preflight could not be evaluated — "
                "treating as NOT READY\n", LOG_TAG);
    }

    if (nodus_witness_v2_ingress_arm(witness) != 0) {
        fprintf(stderr, "%s: Ledger V2 ingress remains CLOSED (gate: %s)\n",
                LOG_TAG,
                nodus_witness_v2_gate_state_name(
                    nodus_witness_v2_gate_state(witness)));
    }

    /* ── Ledger V2 O15D — chain-role derivation, COMMITTED STATE ONLY ──
     *
     * Deriving the role here — on BOTH open paths — is what lets every
     * legacy lane refuse on a Ledger V2 chain. Without it, a node pointed
     * at a V2 database treats it as an empty legacy chain and could
     * commit a LEGACY genesis into it.
     *
     * O15J Faz 3: the role is now derived from ONE probe. The seam
     * successor (a chain derived from a terminal legacy chain, bound by
     * the "DNA.LEGACY.TERM.v1" source tag) is gone with the activation
     * ceremony, so a pure-V2 chain — height-0 genesis manifest tagged
     * "DNA.GENESIS.v1" — is the only V2 chain there is.
     *
     * A V2 chain whose committed chain id cannot be derived is malformed
     * and is REFUSED, never half-adopted. */
    witness->v2_successor = false;
    memset(witness->v2_chain32, 0, sizeof(witness->v2_chain32));
    memset(&witness->v2_certpool, 0, sizeof(witness->v2_certpool));

    /* ── O15J — a PURE-V2 chain IS the V2 chain ────────────────────────
     *
     * A chain built by nodus_witness_v2_gen carries the "DNA.GENESIS.v1"
     * source tag and has no legacy ancestor. Recognising it here is what
     * stops every consumer taking the LEGACY branch: without it,
     * nodus_witness_block_height reads the empty `blocks` table and
     * advertises height 0, nodus_witness_genesis_exists is false so the
     * admission precheck would ADMIT a legacy GENESIS transaction into
     * the V2 database (the exact hazard the comment above records), every
     * V2 lane refuses, and the first non-bootstrap epoch halts because
     * the committee seed reads the empty `blocks` table. Review R2 found
     * it; the season's own test had MASKED it by hard-setting the flag
     * after create_chain_db.
     *
     * A probe FAULT (-1) refuses the database: a chain whose role cannot
     * be determined must not be opened as though it had no role, which is
     * precisely the failure being fixed. */
    int pure_rc = nodus_witness_v2_gen_is_pure(db_path);
    if (pure_rc < 0) {
        fprintf(stderr, "%s: chain role undeterminable for %s — refusing "
                "the database (fail closed)\n", LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    if (pure_rc == 1) {
        if (nodus_witness_v2_chain_id(witness,
                                      witness->v2_chain32) != 0) {
            fprintf(stderr, "%s: Ledger V2 chain id underivable for %s — "
                    "refusing the database (fail closed)\n",
                    LOG_TAG, db_path);
            sqlite3_close(witness->db);
            witness->db = NULL;
            return -1;
        }
        witness->v2_successor = true;
        fprintf(stderr, "%s: chain role: LEDGER V2 (legacy lanes refuse; "
                "production %s)\n", LOG_TAG,
                witness->v2_ingress_armed ? "ARMED" : "not armed");
    }

    return 0;
}

/* Parse the canonical 16-byte chain id out of a `witness_<hex>.db` name.
 *
 * O15A — FAIL CLOSED. The canonical chain id is exactly 16 bytes
 * (nodus_witness_set_chain_id), so the filename must carry exactly 32 hex
 * characters. The previous parse accepted any even-ish length from 2 to
 * 64, took `hex_len / 2` bytes and left the remainder ZERO, and on a bad
 * digit it simply stopped and kept what it had — so a truncated or
 * garbled filename produced a partially-zero chain id that was then
 * installed as this node's identity without complaint.
 *
 * Returns 0 and fills `out16` only for a fully valid name.
 */
static int witness_chain_id_from_name(const char *d_name, uint8_t out16[16]) {
    if (strncmp(d_name, "witness_", 8) != 0) return -1;
    const char *hex_start = d_name + 8;
    const char *dot = strstr(hex_start, ".db");
    if (!dot) return -1;
    if (dot[3] != '\0') return -1;            /* reject .db-wal / .db-shm */
    if ((size_t)(dot - hex_start) != 32) return -1;   /* EXACTLY 16 bytes */

    for (size_t i = 0; i < 16; i++) {
        unsigned int byte;
        char pair[3] = { hex_start[i * 2], hex_start[i * 2 + 1], '\0' };
        /* O15A (reviewer R1): LOWERCASE ONLY. isxdigit alone would accept
         * 'A'-'F', giving a second, non-canonical filename for the same
         * chain — and since selection takes the lexicographically
         * smallest name, an uppercase alias sorts BEFORE the canonical
         * lowercase one and would win. create_chain_db always writes
         * lowercase ("%02x"), so anything else is not a name this node
         * produced. */
        if (!isxdigit((unsigned char)pair[0]) ||
            !isxdigit((unsigned char)pair[1]))
            return -1;                        /* a bad digit is a REJECT */
        if (isupper((unsigned char)pair[0]) || isupper((unsigned char)pair[1]))
            return -1;                        /* non-canonical alias      */
        if (sscanf(pair, "%2x", &byte) != 1) return -1;
        out16[i] = (uint8_t)byte;
    }
    return 0;
}

int nodus_witness_scan_chain_db(nodus_witness_t *witness) {
    if (!witness) return -1;
    const char *data_path = witness->data_path;
    DIR *dir = opendir(data_path);
    if (!dir) return -1;

    /* O15A — DETERMINISTIC SELECTION.
     *
     * This loop used to take the FIRST match from readdir, whose order is
     * filesystem-defined and not a stable total key. The comment on
     * witness_archive_stale_chain_dbs records that this exact behaviour
     * once activated the wrong chain from a stale file (EU-6, 2026-04-10);
     * the mitigation then was to archive stale files, which removes the
     * usual cause without making the choice itself deterministic. Two
     * nodes with the same directory contents must reach the same
     * decision, so the candidates are collected and the
     * lexicographically smallest name is chosen.
     */
    char best[256];
    int  have_best = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        uint8_t probe[16];
        if (witness_chain_id_from_name(entry->d_name, probe) != 0) continue;
        if (!have_best || strcmp(entry->d_name, best) < 0) {
            snprintf(best, sizeof(best), "%s", entry->d_name);
            have_best = 1;
        }
        /* O15J Faz 3 — the second pass that let a seam SUCCESSOR outrank
         * every legacy candidate is deleted with the activation ceremony:
         * a chain is never derived beside its predecessor any more, so no
         * data directory holds both and there is nothing to rank. The
         * lexicographically smallest name is again the only rule, and it
         * stays a stable total key. */
    }
    closedir(dir);
    if (!have_best) return -1;      /* No chain DB found — pre-genesis */

    uint8_t chain_id[16];
    if (witness_chain_id_from_name(best, chain_id) != 0) return -1;

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/%s", data_path, best);

    /* O15C — the handle's chain id is installed BEFORE the gate: the
     * preflight's chain-id agreement check (issue 8) compares the id
     * DERIVED from committed state against the handle's, and running it
     * against a still-zeroed handle mis-reported CHAIN_ID_DISAGREEMENT
     * on every V2 successor restart (found by the O15C rehearsal). The
     * filename-derived id is available here either way; the gate only
     * READS it.
     *
     * ⚠ O15K A — AND NOW IT IS INSTALLED BEFORE THE **OPEN**, not merely
     * before the gate. That comment's own words — "available here either
     * way" — were true and the call still sat below an open that can
     * fail, so a failed open threw away an identity we already held. The
     * consequence was not cosmetic: a zeroed chain id is read as
     * "pre-genesis" by verify_chain_id (nodus_witness_bft.c, CRITICAL-2)
     * and by witness_chain_quorum_observe (nodus_witness_peer.c, the
     * self-quarantine detector), so the node ran with its cross-chain
     * replay guard off and could not notice its own divergence.
     *
     * Safe because the id does not come from the database: it is parsed
     * from the FILENAME above by witness_chain_id_from_name, which O15A
     * made fail-closed (exactly 32 lowercase hex, isxdigit-validated),
     * and `best` was chosen by a stable total order. Nothing between here
     * and the open reads witness->chain_id, and witness_db_open_path
     * never reads it at all — so moving the call earlier changes no
     * successful path, only the failing one. */
    nodus_witness_set_chain_id(witness, chain_id);

    if (witness_db_open_path(witness, db_path) != 0) return -1;

    /* O15A: the restart path now runs the SAME gate as creation. */
    if (witness_post_open_gate(witness, db_path) != 0) return -1;

    /* O15J Faz 3 — the restart-side seam retry (re-deriving a successor
     * chain whose derivation was interrupted) is deleted with the
     * activation ceremony. Nothing derives a chain at open any more. */

    char hex[17];
    for (int i = 0; i < 8; i++)
        snprintf(hex + i * 2, 3, "%02x", chain_id[i]);
    fprintf(stderr, "%s: loaded chain %s from %s\n", LOG_TAG, hex, best);
    return 0;
}

/* ── Archive stale chain DB files (Fix 1 — prevent orphan forks) ──
 *
 * Move every existing witness_<hex>.db* file (db, db-wal, db-shm)
 * under <data_path> into <data_path>/archive/, except those matching
 * `keep_filename` (basename comparison). Pass keep_filename = NULL to
 * archive ALL chain DB files unconditionally — used by the PR 3 / E0
 * orphan-sentinel recovery path.
 *
 * Never deletes — only renames atomically so we can recover for forensics.
 *
 * Originally written for the EU-6 fork (2026-04-10): the scanner's
 * first-match-wins behavior silently picked up a stale file from a
 * prior chain lifecycle and activated the wrong chain.
 */
static int witness_archive_stale_chain_dbs(const char *data_path,
                                           const char *keep_filename) {
    if (!data_path) return -1;

    char archive_dir[512];
    snprintf(archive_dir, sizeof(archive_dir), "%s/archive", data_path);
    /* mkdir -p; ignore EEXIST */
    if (mkdir(archive_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "%s: archive mkdir failed: %s\n",
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
        /* Compare against keep_filename's basename prefix */
        const char *dot_db = strstr(entry->d_name, ".db");
        if (!dot_db) continue;
        size_t prefix_len = (size_t)(dot_db - entry->d_name) + 3;  /* include ".db" */
        if (prefix_len > strlen(entry->d_name)) continue;
        if (keep_filename != NULL &&
            strncmp(entry->d_name, keep_filename, prefix_len) == 0)
            continue;

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
        fprintf(stderr, "%s: archived %d stale chain file(s)\n",
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
    witness_archive_stale_chain_dbs(witness->data_path, basename);

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/%s", witness->data_path, basename);

    if (witness_db_open_path(witness, db_path) != 0)
        return -1;

    nodus_witness_set_chain_id(witness, chain_id);

    /* O15A: the SAME gate the restart path runs — see
     * witness_post_open_gate. Previously these two checks lived here
     * only, which is exactly how an ordinary restart came to skip them. */
    if (witness_post_open_gate(witness, db_path) != 0) return -1;

    /* PR 3 Yol B — transition bootstrap state to DONE the moment a
     * valid chain DB exists, regardless of which path created it.
     *
     * Two call sites:
     *   1. nodus_witness_bft.c:commit_genesis — legacy genesis BFT
     *      path. Without this transition, every node in a freshly
     *      bootstrapped cluster stays in DISCOVER permanently. The
     *      C-2 cabal protection in handle_chain_q then drops every
     *      CHAIN_Q from any later joiner, breaking auto-bootstrap
     *      recovery (caught by stagef test_bootstrap_join_live).
     *   2. nodus_witness_bootstrap.c:handle_genesis_rsp — the
     *      bootstrap FETCH_GENESIS path's own create. The handler
     *      also re-asserts state=DONE a few lines later, which
     *      becomes a redundant-but-harmless write.
     *
     * settle_until_ms is intentionally NOT set here: the legacy
     * caller has already participated in the BFT round committing
     * genesis, so no settle window applies; the bootstrap caller
     * sets it explicitly after this returns. */
    witness->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DONE;

    /* PR 3 / E5 (revised) — drop the genesis marker that gates the
     * server-side partial-wipe XOR check. The marker's presence tells
     * a future boot "this node has crossed the genesis boundary at
     * least once, so the all-or-nothing DB invariant now applies."
     * Failure to write is not fatal — worst case the gate stays open
     * after a partial wipe — but log loudly so an operator can
     * investigate. fopen("w") + fclose is sufficient: the file's
     * presence is the signal, contents are not read. */
    char marker[640];
    int nm = snprintf(marker, sizeof(marker), "%s/%s",
                      witness->data_path,
                      NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    if (nm > 0 && (size_t)nm < sizeof(marker)) {
        FILE *fp = fopen(marker, "w");
        if (fp) {
            fclose(fp);
        } else {
            fprintf(stderr,
                "%s: warning: failed to write partial-wipe genesis "
                "marker at %s: %s — partial-wipe gate will stay open "
                "on next boot of this node\n",
                LOG_TAG, marker, strerror(errno));
        }
    }

    fprintf(stderr, "%s: created chain DB %s\n", LOG_TAG, db_path);
    return 0;
}

/* ── PR 3 / E0 — Orphan bootstrap sentinel check ─────────────────── */

int nodus_witness_check_orphan_bootstrap_sentinel(const char *data_path) {
    if (!data_path) return -1;

    char sentinel[640];
    int n = snprintf(sentinel, sizeof(sentinel),
                     "%s/.bootstrap_in_progress", data_path);
    if (n < 0 || (size_t)n >= sizeof(sentinel)) return -1;

    struct stat st;
    if (stat(sentinel, &st) != 0) {
        if (errno == ENOENT) return 0;  /* clean state */
        fprintf(stderr,
            "%s: orphan-sentinel stat failed at %s: %s — refusing init\n",
            LOG_TAG, sentinel, strerror(errno));
        return -1;
    }

    fprintf(stderr,
        "%s: ORPHAN BOOTSTRAP SENTINEL detected at %s "
        "(prior FETCH_GENESIS crashed) — archiving any partial "
        "witness_*.db files and clearing sentinel\n",
        LOG_TAG, sentinel);

    /* Pass keep_filename=NULL to archive every witness_<hex>.db* file
     * in data_path. The placeholder block 1 row that the partial DB
     * may contain is NOT authoritative (state_root=zeros, prev_hash
     * empty) — keeping it would let witness_scan_chain_db pick up the
     * stale file and fool the next bootstrap. */
    if (witness_archive_stale_chain_dbs(data_path, NULL) != 0) {
        fprintf(stderr,
            "%s: orphan-sentinel cleanup: archive failed — refusing init\n",
            LOG_TAG);
        return -1;
    }

    if (unlink(sentinel) != 0) {
        fprintf(stderr,
            "%s: orphan-sentinel cleanup: unlink failed at %s: %s — "
            "refusing init\n",
            LOG_TAG, sentinel, strerror(errno));
        return -1;
    }

    fprintf(stderr,
        "%s: orphan-sentinel cleanup complete — DISCOVER will restart\n",
        LOG_TAG);
    return 1;
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
    witness->last_epoch = 0;
    /* O15I V1 — the reaper latch is defined RELATIVE to last_epoch, so it
     * is reset with it. Not load-bearing (a stale stamp can never equal
     * the fresh `now` the next epoch tick writes) but leaving the pair
     * out of step would be state carried across a lifecycle boundary for
     * no reason. */
    witness->last_evict_epoch = 0;
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
    witness->running = true;


    /* Phase 10 / Task 53 — invalidate the committee cache. UINT64_MAX
     * is the sentinel meaning "no epoch cached yet"; a real epoch
     * start is always < UINT64_MAX. */
    witness->cached_committee_epoch_start = UINT64_MAX;
    witness->cached_committee_count = 0;

    /* Setup identity from server keys */
    witness_setup_identity(witness);

#ifdef QGP_FAULT_INJECT
    /* O15C-D.1 — install the env-described T3 drop predicate, if this
     * process was launched for a fault-injection run. The predicate is
     * inert until the harness creates its arm file, so genesis (view 0)
     * commits normally during bring-up.
     * O15C-D.3 — placed AFTER witness_setup_identity because the
     * per-node VIEW_CHANGE drop set derives from our own witness id.
     * See nodus_witness_fault.c. */
    nodus_witness_fault_init_from_env(witness->my_id);
#endif

    /* Save data path for chain DB creation on genesis */
    snprintf(witness->data_path, sizeof(witness->data_path), "%s",
             server->config.data_path);

    /* Faz 4D follow-up 2026-05-02 — recovery sentinel boot gate (B-2
     * closure). If a previous halt_recovery_check armed the sentinel
     * but crashed before clearing it (between drop_witness_db and
     * the first replayed block), this node MUST NOT silently boot as
     * a fresh witness — the chain DB is gone but the halt context is
     * lost, and joining the cluster would mask the original divergence
     * forensically. Refuse startup; operator must investigate +
     * delete the sentinel by hand. */
    {
        uint64_t prior_halt_height = 0;
        int sc = nodus_witness_recovery_sentinel_check(witness->data_path,
                                                         &prior_halt_height);
        if (sc < 0) {
            fprintf(stderr,
                "%s: recovery sentinel check failed at %s — refusing init\n",
                LOG_TAG, witness->data_path);
            return -1;
        }
        if (sc > 0) {
            fprintf(stderr,
                "%s: REFUSING START — recovery sentinel present "
                "(prior halt at h=%llu). Investigate divergence root "
                "cause, then `rm %s/.recovery_in_progress` to clear.\n",
                LOG_TAG, (unsigned long long)prior_halt_height,
                witness->data_path);
            return -1;
        }
    }

    /* PR 3 / E0 — orphan bootstrap sentinel boot gate (H-7 closure).
     * The bootstrap path's FETCH_GENESIS handler writes
     * .bootstrap_in_progress BEFORE create_chain_db and unlinks it on
     * the success path. If we boot and the file is still present, a
     * previous bootstrap crashed mid-write — any partial witness_*.db
     * is NOT authoritative (state_root = zeros, prev_hash empty) and
     * MUST be archived before witness_scan_chain_db runs, or the
     * scanner would silently pick up the stale file and skip
     * DISCOVER. */
    {
        int rc = nodus_witness_check_orphan_bootstrap_sentinel(
            witness->data_path);
        if (rc < 0) {
            fprintf(stderr,
                "%s: orphan-sentinel boot gate failed — refusing init\n",
                LOG_TAG);
            return -1;
        }
        /* rc == 1 -> recovery performed, fall through to scan (which
         * will now find an empty data_path and report pre-genesis).
         * rc == 0 -> no sentinel, normal boot path. */
    }

    /* Scan for existing chain DB (witness_<chain_id>.db).
     * If found: opens DB + sets chain_id.
     * If not found: db = NULL (pre-genesis state, waiting for genesis TX). */
    if (nodus_witness_scan_chain_db(witness) != 0) {
        fprintf(stderr, "%s: no chain DB found — pre-genesis state\n", LOG_TAG);
    }

    /* O15E Faz D — arm the pinned-genesis joiner if this fresh node has
     * no chain and an operator-supplied successor genesis pin. A no-op
     * when a chain was found or no pin was given. The joiner tick then
     * pulls the bundle and adopts on a pin match. */
    (void)nodus_witness_v2_join_arm(witness);

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

    /* PR 3 Yol B / C6 — kick off the auto-bootstrap state machine.
     *
     * - HAVE_CHAIN branch: refresh bft_config from the on-chain
     *   committee, set H-4 settle window, transition to DONE
     *   immediately. The existing sync_check + replay path catches up
     *   to the actual tip.
     * - DISCOVER branch (chain DB absent): C-1 startup gate first
     *   (seed_count >= committee_size); on pass schedules round 1 to
     *   fire on the next nodus_witness_tick. On C-1 fail returns -1
     *   so init aborts cleanly with an explicit operator-facing log.
     * - DB error: returns -1, init aborts.
     *
     * Pre-PR-3 behaviour was "silent pre-genesis wait". The new fail-
     * fast on C-1 is intentional: a misconfigured fresh node is
     * better stopped at startup than running in a partially-bootstrapped
     * state. */
    if (nodus_witness_bootstrap_start(witness) != 0) {
        fprintf(stderr,
                "%s: bootstrap_start returned -1 — refusing init\n",
                LOG_TAG);
        return -1;
    }

    fprintf(stderr, "%s: initialized (roster=%d witnesses, "
            "chain_db=%s)\n",
            LOG_TAG, witness->roster.n_witnesses,
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

/* H-15 / MED-27 (O15C-D) — expire pending forwards older than
 * NODUS_W_PENDING_FWD_TIMEOUT_S and answer the waiting clients.
 *
 * Extracted from nodus_witness_tick so the contract is reachable from a
 * regression without a live cluster: `now_s` is injected rather than
 * read from the clock. Returns the number of slots expired.
 *
 * The contract being enforced: dnac_spend owes the caller EXACTLY ONE
 * terminal answer. Before this, expiry dropped the slot silently — the
 * client stayed blocked until its own 60 s RPC timeout
 * (nodus_client.c, nodus_client_dnac_spend) with no reason to report,
 * and pending_forward_count was never decremented here even though
 * every other clear path decrements it. The 30 s expiry sits well
 * inside the client's 60 s window, so the error lands on a pending slot
 * that is still live. */
int nodus_witness_pending_forward_expire(nodus_witness_t *witness,
                                           uint64_t now_s) {
    if (!witness) return 0;

    int expired = 0;
    for (int pfi = 0; pfi < NODUS_W_MAX_PENDING_FWD; pfi++) {
        if (!witness->pending_forwards[pfi].active) continue;
        if (now_s - witness->pending_forwards[pfi].started_at <=
            NODUS_W_PENDING_FWD_TIMEOUT_S)
            continue;

        struct nodus_tcp_conn *cc = witness->pending_forwards[pfi].client_conn;
        uint32_t ctxn = witness->pending_forwards[pfi].client_txn_id;

        fprintf(stderr, "WITNESS: pending_forward[%d] timed out after %ds "
                "(txn=%u, client=%s)\n", pfi,
                (int)NODUS_W_PENDING_FWD_TIMEOUT_S, ctxn,
                cc ? "notified" : "gone");

        witness->pending_forwards[pfi].active = false;
        witness->pending_forwards[pfi].client_conn = NULL;
        if (witness->pending_forward_count > 0)
            witness->pending_forward_count--;
        expired++;

        if (cc) {
            uint8_t err_buf[512];
            size_t err_len = 0;
            if (nodus_t2_error(ctxn, NODUS_ERR_TIMEOUT,
                                "leader did not answer forwarded spend "
                                "in time",
                                err_buf, sizeof(err_buf), &err_len) == 0 &&
                err_len > 0)
                nodus_tcp_send(cc, err_buf, err_len);
        }
    }
    return expired;
}

/* O15I V1 — see the contract on nodus_witness.h.
 *
 * THE FAIL DIRECTION IS PER-CAUSE, not blanket. The first cut of this
 * function collapsed every non-OK outcome to "not committed", which was
 * right for ERR_HASH and wrong for the rest: it left an EXPIRED envelope
 * permanently undeletable and permanently counted as demand, i.e. the
 * exact churn V1 exists to remove, re-entered through a different door.
 * The line the source itself draws is the line used here —
 *   - ERR_HASH is "THIS NODE could not compute", and a consensus caller
 *     "MUST NOT translate it into a transaction rejection"
 *     (env_preflight.h:100-110) -> UNJUDGED, keep;
 *   - ERR_EXPIRED is "expiry_height below the candidate"
 *     (env_preflight.h:91), a verdict about the ENVELOPE derived from its
 *     own bytes against a tip that only advances -> EXPIRED, finished;
 *   - ERR_DECODE comes from a codec that allocates nothing and is a pure
 *     function of its input (env_wire.h:401-403), so it cannot be
 *     node-local either -> MALFORMED, finished.
 * Everything else stays UNJUDGED, which is the conservative side. */
nodus_witness_entry_verdict_t nodus_witness_v2_entry_verdict(
        nodus_witness_t *witness, const uint8_t *tx_data, uint32_t tx_len) {
    if (!witness || !witness->db || !witness->v2_successor ||
        !tx_data || tx_len == 0)
        return NODUS_W_ENTRY_UNJUDGED;

    /* Class gate FIRST, and it is what keeps every legacy chain and every
     * class-201 claim byte-identical to the pre-V1 behaviour: only the
     * wire-family-marked ENVELOPE has an intent id at all, and only it
     * reaches the derivation cost below. */
    if (nodus_witness_v2_classify_entry(tx_data, tx_len) !=
        NODUS_W_TX_V2_ENVELOPE)
        return NODUS_W_ENTRY_UNJUDGED;

    /* A local view, used ONLY to learn which domains the legs address so
     * the POSITIONAL contextual table can be built. ~2.6 KB automatic, no
     * recursion, exactly as nodus_witness_v2_env.c declares it.
     *
     * This private per-leg assembly used to be shared with
     * nodus_witness_v2_produce_batch_check. It is NOT any more, and the
     * divergence is deliberate: the batch check decides what a BLOCK may
     * contain, so it must ask the engine's own block-start context
     * (nodus_witness_v2_block_ctx_build) or it admits what the engine
     * rejects. This function decides only whether a POOLED ENTRY is
     * FINISHED, and every contextual mismatch it can hit collapses to
     * UNJUDGED — "keep it" — which is the conservative side of a reaper.
     * Using the engine's ACTIVE-only table here would turn a domain that
     * is merely not ACTIVE YET into a reason to evict, which is exactly
     * the wrong direction. See the ORDERING CAVEAT below.
     *
     * A rejection here is the SAME verdict the seam would return for the
     * same bytes (it is the same strict decoder, called deterministically
     * on the same input — the equivalence nodus_witness_v2_env.c documents
     * at its own pre-decode), so it is reported directly. */
    dna_env_view_t view;
    if (dna_env_decode(tx_data, (size_t)tx_len, &view) != 0)
        return NODUS_W_ENTRY_MALFORMED;

    dna_env_leg_ctx_t rulesets[DNA_ENV_MAX_LEGS];
    size_t n_rulesets = 0;
    for (uint16_t l = 0; l < view.leg_count; l++) {
        uint32_t dom = view.leg[l].domain_id;
        /* Insertion sort into STRICTLY ASCENDING order — the seam rejects
         * any other order, and a duplicate domain must collapse to one
         * entry rather than appear twice. */
        size_t k = 0;
        while (k < n_rulesets && rulesets[k].domain_id < dom) k++;
        if (k < n_rulesets && rulesets[k].domain_id == dom) continue;
        if (n_rulesets >= DNA_ENV_MAX_LEGS) return NODUS_W_ENTRY_UNJUDGED;

        dna_domain_manifest_t man;
        if (nodus_witness_domreg_get(witness, dom, NULL, &man, NULL) != 0)
            return NODUS_W_ENTRY_UNJUDGED;  /* unregistered domain, or a
                                             * registry fault — and see
                                             * the ORDERING CAVEAT on the
                                             * contract: this is reached
                                             * BEFORE expiry, so it is
                                             * deliberately the more
                                             * conservative answer */
        memmove(&rulesets[k + 1], &rulesets[k],
                (n_rulesets - k) * sizeof(rulesets[0]));
        rulesets[k].domain_id       = dom;
        rulesets[k].ruleset_version = man.ruleset_version;
        memcpy(rulesets[k].ruleset_hash, man.ruleset_hash,
               DNA_ENV_RULESET_HASH_LEN);
        n_rulesets++;
    }
    if (n_rulesets == 0) return NODUS_W_ENTRY_UNJUDGED;

    /* The CANDIDATE height, exactly as the producer derives it: the
     * height this envelope would be included in, never the parent's. It
     * is the expiry gate's only input, so it must not be guessed. */
    uint64_t candidate = 0;
    if (nodus_witness_v2_tip_height(witness, &candidate) != 0)
        return NODUS_W_ENTRY_UNJUDGED;
    candidate += 1;

    /* dna_env_preflight_t is ~15 KB (env_preflight.h size audit) — heap,
     * never the stack, which is the discipline every other caller of this
     * seam already follows. */
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return NODUS_W_ENTRY_UNJUDGED;

    nodus_v2_envelope_t env;
    env.env_bytes = tx_data;
    env.env_len   = (size_t)tx_len;

    size_t fail_i = 0;
    dna_env_preflight_status_t pst = DNA_ENV_PF_OK;
    nodus_witness_entry_verdict_t verdict = NODUS_W_ENTRY_UNJUDGED;

    nodus_v2_env_status_t est = nodus_witness_v2_env_preflight_batch(
            witness, candidate, rulesets, n_rulesets, &env, 1, pf,
            &fail_i, &pst);

    if (est == NODUS_V2_ENV_OK) {
        /* BYTE-IDENTICAL to the apply engine's replay guard — one
         * authority for "this intent is already committed", asked the
         * same way from both sides. A query that cannot run leaves the
         * verdict UNJUDGED rather than claiming the entry is live: this
         * node has no answer, and the fail-closed side is "keep". */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(witness->db,
                "SELECT 1 FROM v2_intent_index WHERE intent_id = ?1",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(st, 1, pf->intent_id, DNA_ENV_HASH_LEN,
                              SQLITE_STATIC);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc == SQLITE_ROW)       verdict = NODUS_W_ENTRY_COMMITTED;
            else if (rc == SQLITE_DONE) verdict = NODUS_W_ENTRY_LIVE;
        }
    } else if (est == NODUS_V2_ENV_ERR_PREFLIGHT) {
        /* The seam's status is the ONLY place expiry is decided; the
         * comparison env_preflight.h locks is not re-implemented here. */
        if (pst == DNA_ENV_PF_ERR_EXPIRED)     verdict = NODUS_W_ENTRY_EXPIRED;
        else if (pst == DNA_ENV_PF_ERR_DECODE) verdict = NODUS_W_ENTRY_MALFORMED;
        /* ERR_HASH and the contextual mismatches stay UNJUDGED. */
    }
    /* ERR_ARG / ERR_CHAIN / ERR_RULESETS / ERR_CTX_MISSING stay UNJUDGED.
     * The two duplicate statuses cannot arise: both dedup loops compare
     * j = i+1 over a batch of one. */

    free(pf);
    return verdict;
}

/* O15I V1 — THE ONE collapse rule. See the contract on nodus_witness.h:
 * open-coding this list at either consumer is how the reaper and the P3
 * demand predicate would fall out of step. */
bool nodus_witness_v2_entry_is_decided(nodus_witness_entry_verdict_t v) {
    return v == NODUS_W_ENTRY_COMMITTED ||
           v == NODUS_W_ENTRY_EXPIRED   ||
           v == NODUS_W_ENTRY_MALFORMED;
}

/* O15I P3(c) — see the contract on nodus_witness.h. */
int nodus_witness_mempool_evict_committed(nodus_witness_t *witness) {
    if (!witness) return 0;

    nodus_witness_mempool_t *mp = &witness->mempool;
    int evicted = 0;
    int write_idx = 0;

    for (int i = 0; i < mp->count; i++) {
        nodus_witness_mempool_entry_t *e = mp->entries[i];
        if (!e) continue;

        /* An entry NEITHER predicate can judge is KEPT: "I have no
         * evidence" must never read as "already committed", which would
         * turn this reaper back into the unconditional wipe it replaces.
         *
         * nodus_witness_nullifier_exists is FAIL-CLOSED (it answers
         * "spent" on a missing DB or a query error, nodus_witness_db.c).
         * That inherited posture is deliberate and kept: on a broken DB
         * this reaper drops rather than accumulates, which is the safe
         * direction for a bounded 64-slot pool. ⚠ That sentence describes
         * the LEGACY walk ONLY — since O15K V-3 a class-201 claim is
         * judged by a different table and fails the OTHER way (keep), for
         * the reason spelled out on the branch below. */
        bool decided = false;

        /* O15K V-3 — ROUTE THE QUESTION BY ENTRY CLASS, because the two
         * lanes commit a nullifier to two different tables.
         *
         * A class-201 CLAIM's nullifier is written to `v2_claims_spent`
         * (nodus_witness_v2_claim_spend_insert); the legacy walk below
         * reads `nullifiers`, whose only writer is the legacy commit path
         * a successor commit bypasses. Asking the legacy table about a
         * claim therefore always answered "not decided", and the class
         * gate in nodus_witness_v2_entry_verdict answers UNJUDGED for a
         * 201, so BOTH halves stayed silent: the entry was never reaped,
         * read as live demand forever, and rotated the view every
         * round_timeout_ms against a healthy leader until the pool
         * filled at NODUS_W_MAX_MEMPOOL and real demand was refused.
         *
         * ⚠ THE TWO BRANCHES FAIL IN OPPOSITE DIRECTIONS, DELIBERATELY.
         * DO NOT UNIFY THEM. nodus_witness_nullifier_exists is
         * fail-closed to SPENT (drop) — correct for its own callers and
         * kept byte-identical here. The claim lookup is a TRI-STATE and
         * ONLY 1 means decided: a -1 fault maps to NOT SPENT, i.e. KEEP.
         * This branch DELETES, and a wrong deletion silently loses a
         * transaction a client is waiting on, so the unknown answer must
         * leave the entry alone. See the table on
         * nodus_witness_v2_claim_nullifier_spent.
         *
         * The claims table is NEVER consulted for a non-claim entry and
         * the legacy table is never consulted for a claim: the two
         * nullifier namespaces are distinct, and conflating them could
         * manufacture a false "spent" verdict on the legacy
         * double-spend path — worse than the defect this closes. */
        if (e->tx_type == NODUS_W_TX_V2_CLAIM) {
            for (int j = 0; j < e->nullifier_count; j++) {
                if (nodus_witness_v2_claim_nullifier_spent(
                        witness, e->nullifiers[j]) == 1) {
                    decided = true;
                    break;
                }
            }
        } else {
            for (int j = 0; j < e->nullifier_count; j++) {
                if (nodus_witness_nullifier_exists(witness, e->nullifiers[j])) {
                    decided = true;
                    break;
                }
            }
        }

        /* O15I V1 — THE SECOND HALF, and the only one that can judge a
         * successor class-200 envelope. Those are pooled with
         * nullifier_count == 0 (the legacy nullifier walk is skipped on a
         * successor, nodus_witness_peer.c), so the loop above never even
         * runs for them and NOTHING could ever remove one: mempool_pop_
         * batch is leader-only, remove_by_conn needs a client_conn a
         * forwarded entry does not have, and mempool_clear is teardown.
         * A finished envelope therefore sat in a follower's pool forever
         * and armed the P3 deadman against a healthy leader.
         *
         * Asked SECOND and only when the cheap predicate said nothing:
         * the derivation is a decode plus the full commitment chain.
         * The collapse is the SHARED rule, never open-coded here — that
         * is what keeps this reaper and bft_p3_live_demand agreeing on
         * exactly which entries are finished. */
        if (!decided &&
            nodus_witness_v2_entry_is_decided(
                nodus_witness_v2_entry_verdict(witness, e->tx_data,
                                               e->tx_len)))
            decided = true;

        if (decided) {
            nodus_witness_mempool_entry_free(e);
            mp->entries[i] = NULL;
            evicted++;
        } else {
            /* Stable compaction — survivors keep their relative order,
             * so the fee ranking mempool_add established is untouched. */
            mp->entries[write_idx++] = e;
        }
    }

    for (int i = write_idx; i < mp->count; i++)
        mp->entries[i] = NULL;
    mp->count = write_idx;

    return evicted;
}

/*
 * Drain DECIDED mempool entries, once per epoch.
 *
 * Forwarded entries (client_conn == NULL) would otherwise be stranded
 * forever, since no client disconnect triggers remove_by_conn for them.
 *
 * O15I P3(c) — the VERDICT: this used to nodus_witness_mempool_clear()
 * the whole mempool. Under P3(b) a follower legitimately holds forwarded
 * work so a dead leader's demand exists on more than one node, and those
 * entries are exactly what arms the P3(a) deadman — a blind wipe deleted
 * the evidence of the stall, once a minute, while the stall was still
 * happening. The reaper now drops an entry only when it is FINISHED —
 * its nullifier already committed, or (O15I V1, successor class-200)
 * nodus_witness_v2_entry_verdict saying its intent is committed, its
 * expiry has passed, or its bytes no longer decode. Every one of those
 * is a test the leader's own batch selection applies too. Full
 * rationale: nodus_witness.h.
 *
 * O15I V1 — THE LATCH. The epoch gate is a ~2 s WINDOW, not an edge, and
 * the tick runs ~20x/s, so the scan ran ~40 times per epoch. The verdict
 * now includes the successor entry derivation (a decode plus the full
 * commitment chain per class-200 entry, which cannot be cached on the
 * entry), so ~40 passes is no longer a rounding error. `last_evict_epoch`
 * records the epoch stamp this reaper last ran FOR, collapsing the window
 * back to one scan. It is set INSIDE the body, after the pool gate: an
 * epoch in which this node holds nothing must not burn the latch for an
 * epoch in which it later holds work.
 *
 * ── capacity season: THE ROLE GATE IS GONE ────────────────────────────
 * This used to require `!nodus_witness_bft_is_leader(witness)`, so a node
 * never cleaned its pool while it was leading — and a leader is precisely
 * the node whose pool matters, because it is the one selecting batches
 * from it. The only remover left for a leader's stale entries was batch
 * selection itself: the entry had to be POPPED into a candidate batch and
 * BURNED through the seam before it could be freed. Measured in the
 * 164744Z rehearsal, node1 pooled 26 entries, proposed exactly ONCE, and
 * that single proposal had to drop 13 stale claims through the seam
 * before it could form a block. Reaping is read-only over committed state
 * and cannot touch a round in flight — entries in a live batch were
 * removed from the pool by mempool_pop_batch — so there was never a
 * reason for the role to gate it. Every OTHER gate (a non-empty pool, the
 * epoch window, the last_evict_epoch latch) is unchanged.
 *
 * Non-static so test executables (compiled with NODUS_WITNESS_INTERNAL_API
 * via register_witness_test) can drive the GATE, not just the body — the
 * removed role condition is only provable by calling this with a witness
 * that IS the leader. Not declared in any public header; the one
 * production caller is nodus_witness_tick.
 *
 * @return the number of entries evicted, or -1 when a gate declined.
 */
int nodus_witness_mempool_reap_epoch(nodus_witness_t *witness) {
    if (!witness) return -1;
    if (witness->mempool.count <= 0) return -1;
    if (nodus_time_now() - witness->last_epoch >= 2) return -1;
    if (witness->last_evict_epoch == witness->last_epoch) return -1;

    /* Runs once right after the epoch tick rebuilds the roster. */
    witness->last_evict_epoch = witness->last_epoch;
    int before = witness->mempool.count;
    int dropped = nodus_witness_mempool_evict_committed(witness);
    if (dropped > 0)
        fprintf(stderr, "WITNESS: evicted %d/%d decided mempool entries "
                "(%d still pending)\n",
                dropped, before, witness->mempool.count);
    return dropped;
}

void nodus_witness_tick(nodus_witness_t *witness) {
    if (!witness || !witness->running) return;

    /* Poll dedicated witness TCP transport (port 4004) */
    if (witness->tcp)
        nodus_tcp_poll((nodus_tcp_t *)witness->tcp, 50);

    /* BFT timeout checks */
    nodus_witness_bft_check_timeout(witness);

        /* PR 3 Yol B — bootstrap state machine retry/timeout. */
    nodus_witness_bootstrap_tick(witness);

    /* H-15: Pending forward timeout (30s) */
    (void)nodus_witness_pending_forward_expire(witness, nodus_time_now());

    /* O15E Faz B — successor sync driver: head-hint broadcast +
     * in-flight range expiry. Self-throttled; a no-op on legacy chains
     * and on unarmed nodes (the gate is asked inside). */
    nodus_witness_v2_sync_tick(witness);

    /* O15E Faz D — pinned-genesis joiner: pull the genesis bundle while
     * a fresh node has a pin but no successor chain yet. No-op once
     * adopted or when this node is not a joiner. */
    nodus_witness_v2_join_tick(witness);

    /* MED-28: drop the retained reproposal batch once the chain has
     * advanced past its height — the C5 binding it exists to satisfy can
     * no longer be issued, so holding the entries would leak them. */
    if (witness->retained_batch.present &&
        witness->retained_batch.height <= nodus_witness_block_height(witness)) {
        fprintf(stderr, "WITNESS: MED-28 retained batch superseded "
                "(height=%llu committed) — releasing\n",
                (unsigned long long)witness->retained_batch.height);
        nodus_witness_retained_batch_clear(witness);
    }

    /* O15C-D.1 — release a C5 binding whose height the chain has already
     * reached. handle_propose clears the binding when the matching
     * PROPOSE arrives, but a node that instead learns the block through
     * SYNC never runs that gate, and the stale binding would then reject
     * every proposal at every later height. */
    if (witness->reproposal_required &&
        nodus_witness_block_height(witness) >= witness->reproposal_height) {
        fprintf(stderr, "WITNESS: C5 binding at height %llu satisfied by "
                "committed chain — releasing\n",
                (unsigned long long)witness->reproposal_height);
        witness->reproposal_required = false;
        witness->reproposal_height = 0;
        witness->reproposal_prepared_view = 0;
        memset(witness->reproposal_tx_hash, 0, NODUS_T3_TX_HASH_LEN);
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

    (void)nodus_witness_mempool_reap_epoch(witness);

    /* Peer mesh: reconnection, IDENT exchange */
    nodus_witness_peer_tick(witness);

    /* Epoch tick: rebuild roster every 60s */
    uint64_t now = nodus_time_now();
    if (now - witness->last_epoch >= WITNESS_EPOCH_SECS) {
        witness->last_epoch = now;

        /* F17 A2 — rebuild transport-layer peer discovery roster. BFT
         * config is NOT derived from this roster; it's recomputed from
         * the chain-derived committee at round-start. */
        nodus_witness_rebuild_roster_from_peers(witness, &witness->pending_roster);

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
            /* F17 A2 — transport-only swap. BFT config is now refreshed
             * from the chain committee at round-start (no gossip-driven
             * quorum changes). */
            memcpy(&witness->roster, &witness->pending_roster,
                   sizeof(nodus_witness_roster_t));
            witness->pending_roster_ready = false;

            fprintf(stderr, "WITNESS: epoch roster swap: %u witnesses "
                    "(transport)\n",
                    witness->roster.n_witnesses);
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
        /* F17 A2 — transport-only swap (see comment at immediate-swap
         * branch above). */
        memcpy(&witness->roster, &witness->pending_roster,
               sizeof(nodus_witness_roster_t));
        witness->pending_roster_ready = false;

        fprintf(stderr, "WITNESS: deferred roster swap: %u witnesses "
                "(transport)\n",
                witness->roster.n_witnesses);
    }

    /* State sync: check if behind peers and need to catch up */
    nodus_witness_sync_check(witness);
    /* Faz 4D 2026-05-02 — halt recovery (Hybrid model). No-op unless
     * safety_halt latched AND config.halt_auto_recover enabled AND
     * historical committee snapshot present. Default: false / no-op. */
    nodus_witness_halt_recovery_check(witness);
}

/* ── Tier 3 dispatch (BFT message routing) ───────────────────────── */

#ifdef QGP_FAULT_INJECT
/* Faz 5.4 — fault-inject drop predicate (test-build-only). */
static nodus_witness_drop_predicate_t g_drop_pred = NULL;

void nodus_witness_test_inject_drop(nodus_witness_drop_predicate_t pred) {
    g_drop_pred = pred;
}
#endif

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

#ifdef QGP_FAULT_INJECT
    /* Faz 5.4 — drop predicate check (post-decode, pre-handler).
     * The drop is silent: no log spam, no state mutation, no peer
     * upsert. Tests can install a predicate scoped to specific
     * msg.type / sender_id combinations to simulate partition. */
    if (g_drop_pred && g_drop_pred(&msg, msg.header.sender_id))
        return;
#endif

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

    /* ── O15C-D.4 — CONSENSUS PROTOCOL VERSION GATE ──────────────────
     *
     * Placed HERE deliberately: after the wsig verification above, so the
     * version we act on is the AUTHENTICATED one (hdr->version lives
     * inside the Dilithium5 envelope preimage — nodus_tier3.c enc_wh, via
     * enc_sign_payload — so a peer signs version and args TOGETHER and
     * cannot advertise one while another party signs a different one);
     * and BEFORE nodus_witness_peer_ensure below, which is the first
     * state mutation on this path. A rejected message therefore leaves
     * zero residue: no peer registration, no vote, no BFT state.
     *
     * WHY THIS EXISTS. O15C-D.3 added three proof-bearing NEW_VIEW keys
     * (rpv/rns/rsg). CBOR decoders SKIP unknown keys, and nothing read
     * hdr->version, so a v2 node silently processed a v3 NEW_VIEW under
     * the pre-D.3 local-subset semantics. Reproduced on real binaries
     * (bc0ff148 vs c65c8cd1): the legacy node committed byte-identical
     * blocks AND its vote counted toward quorum — with two current nodes
     * stopped, 4 current + 1 legacy = 5 advanced the chain. Different
     * rules, same messages, silent participation.
     *
     * SCOPE. Exactly the consensus-affecting set the quarantine switch
     * below already treats as such — that list is the source's own
     * definition, not a new judgement. Bootstrap (version 1, runs before
     * a committee exists), IDENT, roster and sync traffic are NOT gated:
     * IDENT is not wsig-verified at this point, so its version claim is
     * unauthenticated and must not be acted on. A stale peer may still
     * become known to the mesh; it simply cannot influence consensus.
     *
     * BOTH directions fail closed: an older version and an unknown newer
     * version are equally rejected by the exact-match test. */
    switch (msg.type) {
    case NODUS_T3_PROPOSE:
    case NODUS_T3_PREVOTE:
    case NODUS_T3_PRECOMMIT:
    case NODUS_T3_COMMIT:
    case NODUS_T3_VIEWCHG:
    case NODUS_T3_NEWVIEW:
    case NODUS_T3_FWD_REQ:
    case NODUS_T3_FWD_RSP:
        if (msg.header.version != NODUS_T3_BFT_PROTOCOL_VER) {
            fprintf(stderr,
                    "%s: INCOMPATIBLE PEER — dropping %s from roster %d: "
                    "BFT protocol v%u, this node requires v%u. The peer "
                    "cannot participate in consensus until both run the "
                    "same protocol version.\n",
                    LOG_TAG, msg.method, sender_idx,
                    (unsigned)msg.header.version,
                    (unsigned)NODUS_T3_BFT_PROTOCOL_VER);
            return;
        }
        break;
    default:
        break;
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

    /* Hard-Fork v1 Stage C.2 — chain_config vote-collect. */
    case NODUS_T3_CC_VOTE_REQ:
        nodus_witness_handle_cc_vote_req(witness, conn, &msg);
        break;

    /* PR 3 Yol B — witness auto-bootstrap dispatch (C3). */
    case NODUS_T3_CHAIN_Q:
        nodus_witness_bootstrap_handle_chain_q(witness, conn, &msg);
        break;
    case NODUS_T3_CHAIN_R:
        nodus_witness_bootstrap_handle_chain_r(witness, &msg);
        break;
    case NODUS_T3_GENESIS_REQ:
        nodus_witness_bootstrap_handle_genesis_req(witness, conn, &msg);
        break;
    case NODUS_T3_GENESIS_RSP:
        nodus_witness_bootstrap_handle_genesis_rsp(witness, &msg);
        break;
    case NODUS_T3_CC_VOTE_RSP:
        /* Receiver-side: handled by CLI proposer's client helper when
         * it ships in Stage E. A nodus-server that isn't expecting a
         * response (i.e., didn't open the session) can safely ignore. */
        break;

    /* ── O15E Faz B — Ledger V2 successor sync (verbs 20-23) ─────────
     * Every handler asks the activation gate before touching a byte;
     * a non-successor or unarmed node answers NOTHING (no residue). */
    case NODUS_T3_V2_BLOCK:
        nodus_witness_v2_sync_handle_block_q(witness, conn, &msg);
        break;
    case NODUS_T3_V2_HEAD:
        nodus_witness_v2_sync_handle_head(witness, conn, &msg);
        break;
    case NODUS_T3_V2_RANGE_REQ:
        nodus_witness_v2_sync_handle_range_q(witness, conn, &msg);
        break;
    case NODUS_T3_V2_RANGE_RSP:
        nodus_witness_v2_sync_handle_range_r(witness, conn, &msg);
        break;
    case NODUS_T3_V2_GBUNDLE_REQ:
        nodus_witness_v2_sync_handle_gbundle_q(witness, conn, &msg);
        break;
    case NODUS_T3_V2_GBUNDLE_RSP:
        /* Joiner-side accumulation (O15E Faz D) is handled by the joiner
         * bootstrap module, wired where the joiner state lives; a
         * committed successor node has nothing to do with a bundle
         * response. */
        nodus_witness_v2_join_handle_gbundle_r(witness, conn, &msg);
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

    /* MED-28 — same for the retained reproposal batch. */
    nodus_witness_retained_batch_clear(witness);

    /* Clear mempool */
    nodus_witness_mempool_clear(&witness->mempool);

    /* S3 — drain the view-change records' heap-owned prepared-sig arrays.
     * nodus_witness_vc_record_t::prepared::sigs became a heap pointer when
     * the array grew to DNAC_MAX_ACTIVE_VALIDATORS records (an in-struct
     * sigs[128] would have been ~76 MB); the whole array is swept here so
     * a shutdown mid-view-change does not leak. Idempotent — clearing an
     * already-empty record is a free(NULL) plus a memset. */
    for (int i = 0; i < DNAC_MAX_ACTIVE_VALIDATORS; i++)
        nodus_witness_vc_record_clear(&witness->view_changes[i]);
    witness->view_change_count = 0;

    /* Close peer mesh (clears conn references) */
    nodus_witness_peer_close(witness);

    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }

    fprintf(stderr, "%s: shutdown complete\n", LOG_TAG);
}
