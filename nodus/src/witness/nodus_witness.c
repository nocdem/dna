/**
 * Nodus — Witness Module Implementation
 *
 * Skeleton init/shutdown + lifecycle hooks.
 * BFT consensus, peer mesh, and handlers are in separate files.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_v2_pools.h"  /* S7 startup check      */
#include "witness/nodus_witness_v2_gate.h"      /* O15B activation gate  */
#include "witness/nodus_witness_v2_preflight.h" /* O15A readiness report */
/* O15J Faz 3 — chain-role derivation is what makes a Ledger V2 database
 * refuse every legacy lane. With the activation ceremony gone there is
 * exactly ONE way a V2 chain comes into being, and exactly one probe for
 * it: nodus_witness_v2_gen_is_pure. */
#include "witness/nodus_witness_v2_gen.h"       /* O15J pure-V2 chain role   */
/* ORCHESTRATOR delta 1, FIX A: RESTORED. This agent's earlier removal
 * was wrong — the O15K reaper (below, the P3(c) nullifier-spent check)
 * still calls nodus_witness_v2_claim_nullifier_spent, which this header
 * declares. witness_post_open_gate's chain-role probe still calls
 * nodus_witness_v2_gen_stored_chain_id directly (NOT
 * nodus_witness_v2_chain_id) for the reason recorded at that function's
 * comment; that reason concerns which function the GATE uses, not
 * whether this header is needed at all. */
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_chain_id,
                                                  * nodus_witness_v2_claim_nullifier_spent */
#include "witness/nodus_witness_v2_sync2.h"     /* O15E successor sync seam */
#include "witness/nodus_witness_v2_join.h"      /* O15E pinned-genesis joiner */
/* O15I V1 — the committed-INTENT authority behind the P3(c) reaper and
 * the P3(a) demand predicate: the envelope preflight seam, the entry
 * classifier + tip helper, and the domain registry the contextual ruleset
 * table is resolved from. */
#include "witness/nodus_witness_v2_env.h"       /* env preflight seam    */
#include "witness/nodus_witness_v2_produce.h"   /* classify_entry / tip  */
#include "witness/nodus_witness_domreg.h"       /* contextual rulesets   */
/* FLEET-TM-R3 W3 package C2a — the cometbft server binding: the startup
 * table, the transport glue (package C2b) and the two reactors it binds.
 * nodus_witness.h declares cmt_node/cmt_net/cmt_conr/cmt_memr as `void *`
 * for exactly the circular-include reason these headers exist below the
 * types they need — see that struct's comment. */
#include "witness/nodus_witness_cmt_node.h"
#include "witness/nodus_witness_cmt_net.h"
#include "dnac/cmt_conr.h"
#include "dnac/cmt_memr.h"
#include "crypto/sign/qgp_dilithium.h"          /* ML-DSA-87 raw_sign    */
#include "nodus/nodus_chain_config.h"  /* w_cc_appr_req handler (D-16 rev 7) */
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

/* FLEET-TM-R3 W3 package C2a — witness_cmt_tick's per-tick cmt_cs_step
 * bound (item 3(b)). D-23 rev 7 (19)'s own arithmetic: one maximal block
 * is ~337 parts (CMT_BITS_BLOCK_PART_SIZE_BYTES 65 536,
 * DefaultBlockParams().max_bytes 22 020 096 — nodus_witness_cmt_net.h's
 * "THE RECEIVE ARENA" note). This bound is comfortably above that so an
 * ordinary tick drains a whole proposal in one pass; it exists only to
 * stop a pathological flood of events (many peers' votes/precommits
 * arriving in the same tick) from starving nodus_cmt_net_tick's peer
 * scan and deferred-close pass for an unbounded time. */
#define WITNESS_CMT_STEP_BUDGET 512

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
    /* R3 W4 — this table's only WRITER (nodus_witness_cert_store) is
     * deleted with the closed consensus lane: nothing commits a row to
     * it again. The table itself stays: nodus_witness_cert_get, the
     * READER, is still called by handle_dnac_block (dnac_block query
     * handler, explicitly kept — the client query surface, not
     * consensus), so the table must still exist for that query to run
     * (rather than fail) — it answers an empty cert list on every
     * version-3 chain, which is the honest legacy-table answer the
     * hub/spoke handlers are recorded as giving. */
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
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0"
    /* tokenomics-v3 P1 (Q2, clean path): `last_signed_block` and
     * `signed_blocks_this_epoch` are DROPPED here for every NEW database;
     * an existing database created before this change still carries them
     * until the S15 migration (nodus_witness_v2_schema.c) issues its own
     * `ALTER TABLE validators DROP COLUMN` — see that rung for why this
     * base DDL cannot simply omit them for everyone at once. */
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
    /* Root-layout round (K2, 2026-09-25): the v0.16 `epoch_state` table
     * (push-settlement epoch pool + snapshot) is no longer created. Its
     * last writer died with tokenomics-v3 P2; it was a constant leg of
     * the SYSTEM root, the genesis payload root and the genesis bundle,
     * and all three drop it (DNA.SYS.v3 / DNA.SYSPAYL.v2 /
     * DNA.GBUNDLE.v4). A database an older build created keeps the
     * (empty) table; nothing reads it — the planned devnet wipe removes
     * it. */
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
    "  last_sequence INTEGER NOT NULL,"
    /* tokenomics-v3 P2 (P2-1): the reward reserve — seeded at genesis
     * with the document's reward_pool_initial, + every fee, − every
     * epoch distribution. A DB an older build created gains it through
     * nodus_witness_db_migrate_v18_supply_reward_pool (every open) and
     * the S16 rung (nodus_witness_v2_schema.c). */
    "  reward_pool INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS validator_stats ("
    "  key TEXT PRIMARY KEY,"
    "  value INTEGER NOT NULL"
    ");"
    /* tokenomics-v3 P1 (round 2, R2-1): the two attendance tables are
     * LANE-INDEPENDENT bookkeeping — nothing about them depends on which
     * schema rung (S9, S14, S15, ...) a given chain DB has migrated to,
     * exactly like validators/validator_stats above. They
     * belong in the base schema so every chain DB has them from its
     * FIRST open, at any rung, not only once S15 runs. The S15 migration
     * (nodus_witness_v2_schema.c) keeps its own `CREATE TABLE IF NOT
     * EXISTS` for both — idempotent here, and still the ONLY path that
     * back-fills them into a database an OLDER build already created —
     * and keeps verifying their shape; S15's real remaining work is the
     * `ALTER TABLE validators DROP COLUMN` pair (Q2, clean path).
     * Column definitions here are byte-identical to the S15 rung's.
     *   v2_attendance        voter_id = SHA3-512(pubkey)[0..31] (the
     *                        cometbft address, vset_wire.h). NOT a leg
     *                        of any root (ledger_roots_v2.h
     *                        "attendance_root" — only the per-epoch
     *                        digest below enters a root).
     *   v2_attendance_epoch  one row per epoch boundary; digest is the
     *                        SHA3-512 fold of v2_attendance at that
     *                        boundary (nodus_witness_v2_epoch.c). */
    "CREATE TABLE IF NOT EXISTS v2_attendance ("
    "  voter_id BLOB PRIMARY KEY,"
    "  signed_count INTEGER NOT NULL,"
    "  last_signed_height INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_attendance_epoch ("
    "  epoch_start INTEGER PRIMARY KEY,"
    "  digest BLOB NOT NULL"
    ");"
    /* tokenomics-v3 P2 (P2-5, P2-8): the two reward tables, in the base
     * schema for the reason the attendance tables above are — they are
     * lane-independent bookkeeping every chain DB needs from its FIRST
     * open, at any rung. The S16 rung (nodus_witness_v2_schema.c) keeps
     * its own CREATE TABLE IF NOT EXISTS (the only path that back-fills
     * them into a DB an OLDER build created) and verifies both shapes.
     * Column definitions here are byte-identical to the S16 rung's.
     *   v2_reward_accrual  owner_fp = the recipient's raw 64-byte
     *                      SHA3-512(pubkey). What each owner earned at
     *                      past epoch boundaries and has not yet been
     *                      paid; a leg of core_state_root (accrual_root,
     *                      shared/dnac/ledger_roots_v2.h). A row is keyed
     *                      by the RECIPIENT, never by a delegation or
     *                      validator row, so an exit (UNDELEGATE deletes
     *                      the delegation row) never erases an accrual
     *                      (decision §3 "P2 tasarım soruları").
     *   v2_balance_copy    the frozen bonded balances at each epoch
     *                      boundary: one row per validator with
     *                      self_stake > 0 (owner = the validator) and one
     *                      per delegation. OUT of every root — derived
     *                      at the boundary from committed (rooted)
     *                      tables; a node whose copy diverged pays a
     *                      different accrual at the next boundary and is
     *                      caught there by accrual_root. Only the H-E and
     *                      H copies are kept. */
    "CREATE TABLE IF NOT EXISTS v2_reward_accrual ("
    "  owner_fp BLOB PRIMARY KEY,"
    "  amount INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS v2_balance_copy ("
    "  epoch_start INTEGER NOT NULL,"
    "  validator_fp BLOB NOT NULL,"
    "  owner_fp BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  PRIMARY KEY (epoch_start, validator_fp, owner_fp)"
    ");"
    /* ── Ledger V2 S3 — per-epoch validator-set snapshots (INACTIVE).
     * Rows are written by nodus_witness_vset_insert and read back by
     * nodus_witness_vset_get / nodus_witness_vset_root. Nothing on the
     * live consensus path writes or reads this table yet; a later wave
     * wires the genesis/epoch-boundary calls. Creating it here (rather
     * than lazily) keeps a node that made its DB before genesis from
     * silently having no such table — the class of bug the supply_tracking
     * comment above records.
     *   epoch_start       EPOCH START HEIGHT, the canonical epoch key.
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

/* ── O15L Faz 2 — THE TWO ERROR CLASSES OF A CHAIN-DB OPEN ────────────
 *
 * Before O15L every non-OK sqlite return of the open path took the same
 * exit: refuse, and let nodus_witness_init print "no chain DB found —
 * pre-genesis state" over it. Two different situations were being folded
 * into one answer, and neither was served well.
 *
 *   TRANSIENT — the fault may not be there a moment from now. This is
 *   the `kill -9` + restart case O15K E1 was written for: the dying
 *   process's WAL recovery is still settling, so the open sees BUSY /
 *   LOCKED. It is also every fault that has nothing to do with THIS
 *   database's contents — an I/O error, a full filesystem, a failed
 *   allocation, a file we could not open yet, a WAL protocol collision.
 *   sqlite3_busy_timeout waits out ONLY the lock classes; IOERR, FULL,
 *   CANTOPEN, NOMEM and PROTOCOL were never waited for at all.
 *
 *   PERMANENT — the fault is a property of the file or of our access to
 *   it and will be there after any amount of waiting: NOTADB, CORRUPT,
 *   PERM, AUTH. Retrying these buys nothing and delays the refusal.
 *   Everything not named transient lands here, so an unrecognised code
 *   fails closed rather than looping.
 *
 * THE CLASSIFICATION IS ON THE PRIMARY CODE (`rc & 0xff`). SQLite may
 * return an EXTENDED result code, and SQLITE_BUSY_RECOVERY — the
 * extended form of BUSY — is precisely the WAL-recovery case above. A
 * switch over the raw value would send it to the permanent arm and
 * invert the fix it exists to carry.
 */
typedef enum {
    WITNESS_DB_ERR_TRANSIENT = 0,
    WITNESS_DB_ERR_PERMANENT = 1
} witness_db_err_class_t;

static witness_db_err_class_t witness_db_err_class(int rc) {
    switch (rc & 0xff) {
    case SQLITE_BUSY:      /* incl. SQLITE_BUSY_RECOVERY / _SNAPSHOT     */
    case SQLITE_LOCKED:
    case SQLITE_IOERR:     /* every extended IOERR_* folds to this       */
    case SQLITE_FULL:
    case SQLITE_CANTOPEN:
    case SQLITE_NOMEM:
    case SQLITE_PROTOCOL:
        return WITNESS_DB_ERR_TRANSIENT;
    default:
        /* SQLITE_NOTADB, SQLITE_CORRUPT, SQLITE_PERM, SQLITE_AUTH and
         * anything this build does not recognise. */
        return WITNESS_DB_ERR_PERMANENT;
    }
}

/* ── O15L Faz 2 — THE RETRY BUDGET, FIXED AND DETERMINISTIC ───────────
 *
 * ⚠ NO FLAKINESS IS BEING BOUGHT HERE. The attempt count and the pause
 * between attempts are compile-time constants: no rand(), no clock read,
 * no branch on wall time, and no "raise it until it goes green". The
 * budget is spent identically on every node and on every run; what may
 * differ is only whether a transient fault happens to clear inside it,
 * and BOTH outcomes are fail-closed — either the database opens and is
 * gated, or the node refuses to start its witness role. There is no
 * third state in which a node runs on a half-opened chain.
 *
 * WHY IN-PROCESS AT ALL — this reverses the earlier "no in-process
 * retry; the supervisor restart IS the backoff" position, on evidence
 * read out of the shipped unit file. nodus/deploy/nodus.service carries
 * Restart=on-failure, RestartSec=5, StartLimitBurst=3 and
 * StartLimitIntervalSec=300: exiting to be restarted spends a FINITE
 * budget of three attempts in five minutes, after which systemd stops
 * the unit permanently — and it would retire the node's DHT role, which
 * has nothing wrong with it, along with the witness role. Waiting in
 * process is not bounded by that limit and costs nobody else anything.
 *
 * WHY THREE ATTEMPTS — it mirrors the supervisor's own answer to "how
 * many tries is a transient fault worth", StartLimitBurst=3, paid where
 * it does not consume the supervisor's budget.
 *
 * RELATIONSHIP TO NODUS_W_DB_BUSY_TIMEOUT_MS (5000, nodus_types.h:241).
 * That constant is the tree's ONE answer to "how long is a database lock
 * transient" — O15K E1 set it on this connection and O15J's f08fbcdc set
 * the same value on the V2 probe connection. The retry loop does NOT add
 * a second, larger answer: the budget is DIVIDED across the attempts
 * (NODUS_W_DB_BUSY_TIMEOUT_MS / NODUS_W_DB_OPEN_ATTEMPTS per attempt), so
 * the AGGREGATE time this code will wait out a lock is unchanged — only
 * its shape changes, from one long wait on one connection into three
 * shorter waits on freshly opened ones. Integer division leaves the
 * aggregate two milliseconds short of 5000 rather than over it, which is
 * the right direction: the budget is a ceiling.
 *
 * THE PAUSE (250 ms) IS A JUDGMENT VALUE, and the only one here. The
 * non-lock transient classes get no wait from the busy timeout at all,
 * so without a pause a SQLITE_NOMEM would be retried three times inside
 * a few microseconds and the retries would prove nothing. 250 ms is long
 * enough that an I/O or memory condition can clear and short enough that
 * it adds at most 500 ms (two pauses) to the worst case.
 *
 * WORST CASE, stated so nobody has to derive it: a database locked for
 * the whole open costs the same aggregate lock wait as before this
 * change, plus 500 ms of pause. A permanent fault costs ONE attempt —
 * permanent errors are never retried.
 */
#define NODUS_W_DB_OPEN_ATTEMPTS 3
#define NODUS_W_DB_OPEN_ATTEMPT_BUSY_MS \
    (NODUS_W_DB_BUSY_TIMEOUT_MS / NODUS_W_DB_OPEN_ATTEMPTS)
#define NODUS_W_DB_OPEN_RETRY_PAUSE_MS 250

/* Fixed-duration sleep. This translation unit is already POSIX-only
 * (dirent.h, sys/stat.h), so the _WIN32 arm nodus_client.c:68-75 carries
 * would be unreachable here. */
static void witness_sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* O15K E2 — FAIL CLOSED. Every failure exit of witness_db_open_attempt
 * passes here — and so, transitively, does every failing attempt of
 * witness_db_open_path — because a half-open handle is the shape this
 * project forbids under "A DB failure is never a value": sqlite3_open can
 * succeed and a later step fail, and the old code returned -1 while
 * LEAVING witness->db assigned. The caller
 * (nodus_witness_scan_chain_db) discarded the rc, so the node came up
 * reporting `chain_db=active` while
 * nodus_witness_init had already logged "no chain DB found — pre-genesis
 * state". Worse, the chain id was never installed, and a zeroed chain id
 * is read as "pre-genesis" by BOTH nodus_witness_bft.c's verify_chain_id
 * (CRITICAL-2 cross-chain replay protection) and
 * nodus_witness_peer.c's witness_chain_quorum_observe (the self-quarantine
 * safety net) — so the node ran with its replay guard off and its
 * divergence detector blind, and could never verify a certificate again.
 * Full write-up: nodus/BUGS.md, the entry headed "RESOLVED (O15L,
 * 2026-08-28): a transient SQLite lock at open left the witness RUNNING
 * with a ZEROED chain_id". Cited by its heading, not by its position:
 * this pointer used to read "the top OPEN entry" and rotted the moment
 * that entry was resolved and a newer one (F-10) took the top slot. */
static int witness_db_open_fail(nodus_witness_t *witness) {
    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }
    return -1;
}

/* ONE attempt at bringing `db_path` to a usable handle. Returns SQLITE_OK
 * on success, otherwise the sqlite code that decided the failure — and on
 * any failure the handle is CLOSED and NULLed by witness_db_open_fail, so
 * an attempt never leaves a half-open handle for the next one to inherit.
 *
 * Re-entering this function after a failed attempt is safe because every
 * step in it is idempotent by construction: the ALTERs ignore their
 * duplicate-column errors, the schema is CREATE TABLE IF NOT EXISTS
 * throughout, and nodus_witness_db_migrate_v12's own header records it
 * as idempotent. */
static int witness_db_open_attempt(nodus_witness_t *witness,
                                   const char *db_path) {
    int rc = sqlite3_open(db_path, &witness->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: failed to open %s: %s\n",
                LOG_TAG, db_path, sqlite3_errmsg(witness->db));
        witness_db_open_fail(witness);
        return rc;
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
     * O15L Faz 2 — the value is now the PER-ATTEMPT share of that same
     * budget (see NODUS_W_DB_OPEN_ATTEMPT_BUSY_MS above): three attempts
     * wait out the identical aggregate NODUS_W_DB_BUSY_TIMEOUT_MS, so the
     * tree still holds ONE answer to "how long is a lock transient".
     * O15K E1's second paragraph — "a BUSY that survives the timeout is
     * genuinely persistent, so failing is the correct answer" — is
     * preserved exactly: that judgement now fires when the AGGREGATE
     * budget is exhausted rather than after the first share of it, and it
     * is the caller's transient-exhausted refusal. */
    sqlite3_busy_timeout(witness->db, NODUS_W_DB_OPEN_ATTEMPT_BUSY_MS);

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
        witness_db_open_fail(witness);
        return rc;
    }

    /* Schema v12 migration (Phase 1 / Task 1.1). Idempotent; aborts on
     * unrecoverable error. */
    nodus_witness_db_migrate_v12(witness);

    /* R3 W4 — the H-5 restore of the pbft_state singleton row
     * (last_prepared + the discarded current_view) stood here. Both the
     * row and the counter it partly restored are deleted with the closed
     * consensus lane: nodus_witness_db_load_pbft_state, the pbft_state
     * table itself, and `w->current_view`/`w->last_prepared` are gone. */

    fprintf(stderr, "%s: opened database %s\n", LOG_TAG, db_path);
    return SQLITE_OK;
}

/* Open `db_path`, retrying ONLY the transient error classes and only
 * within the fixed budget documented above. Returns 0 on success, -1 on
 * refusal; on refusal `*out_class` (optional) says WHICH refusal it was,
 * so the caller can report a present-but-unusable chain database honestly
 * instead of letting it be printed as "no chain DB found".
 *
 * On every refusal the handle is already closed and NULLed (O15K E2). */
static int witness_db_open_path(nodus_witness_t *witness, const char *db_path,
                                witness_db_err_class_t *out_class) {
    /* Fail closed by default: a caller that reads *out_class after an
     * unexpected exit must see the class that stops the node, not the one
     * that keeps it waiting. */
    if (out_class) *out_class = WITNESS_DB_ERR_PERMANENT;

    for (int attempt = 1; attempt <= NODUS_W_DB_OPEN_ATTEMPTS; attempt++) {
        int rc = witness_db_open_attempt(witness, db_path);
        if (rc == SQLITE_OK) return 0;

        witness_db_err_class_t cls = witness_db_err_class(rc);
        if (cls == WITNESS_DB_ERR_PERMANENT) {
            /* A property of the file or of our access to it. Waiting
             * changes nothing, so the refusal is immediate and says so. */
            fprintf(stderr,
                    "%s: chain DB %s is PRESENT but UNUSABLE — PERMANENT "
                    "sqlite fault %d (%s) on attempt %d/%d; not retried\n",
                    LOG_TAG, db_path, rc, sqlite3_errstr(rc),
                    attempt, NODUS_W_DB_OPEN_ATTEMPTS);
            if (out_class) *out_class = WITNESS_DB_ERR_PERMANENT;
            return -1;
        }

        if (attempt < NODUS_W_DB_OPEN_ATTEMPTS) {
            fprintf(stderr,
                    "%s: chain DB %s not opened — TRANSIENT sqlite fault %d "
                    "(%s) on attempt %d/%d; retrying in %d ms\n",
                    LOG_TAG, db_path, rc, sqlite3_errstr(rc),
                    attempt, NODUS_W_DB_OPEN_ATTEMPTS,
                    NODUS_W_DB_OPEN_RETRY_PAUSE_MS);
            witness_sleep_ms(NODUS_W_DB_OPEN_RETRY_PAUSE_MS);
            continue;
        }

        /* Budget spent. O15K E1's rule, applied to the aggregate: a
         * transient fault that outlives the whole budget is treated as
         * persistent — the node refuses rather than looping forever. */
        fprintf(stderr,
                "%s: chain DB %s is PRESENT but UNUSABLE — TRANSIENT sqlite "
                "fault %d (%s) survived all %d attempts (aggregate lock wait "
                "%d ms); treating it as persistent\n",
                LOG_TAG, db_path, rc, sqlite3_errstr(rc),
                NODUS_W_DB_OPEN_ATTEMPTS,
                NODUS_W_DB_OPEN_ATTEMPTS * NODUS_W_DB_OPEN_ATTEMPT_BUSY_MS);
        if (out_class) *out_class = WITNESS_DB_ERR_TRANSIENT;
        return -1;
    }

    /* Unreachable: the loop returns on every path. Fail closed anyway. */
    return witness_db_open_fail(witness);
}

/* ── Scan data dir for existing witness_*.db → load chain_id ─────── */
/* TODO: Legacy migration — if DB was created with old naming (raw tx_hash as chain_id),
 * derive new chain_id from genesis TX data in DB and rename file.
 * Not needed yet — all current deployments are pre-genesis. */

/* ── FLEET-TM-R3 W3 package C2a — the post-open chain-role probes ─────
 *
 * Three-valued, the same discipline nodus_witness_scan_chain_db already
 * applies (absent / fault / present): SQLITE_ROW is presence (1),
 * SQLITE_DONE is absence (0), anything else — a prepare failure or a step
 * that returns neither — is a FAULT (-1) and must never be read as
 * absence (O15J review R2-F4; gen_probe_pure, nodus_witness_v2_gen.c,
 * repeats the same rule for the identical reason). `select_sql` /
 * `count_sql` are always a literal compiled into the caller, never
 * built from external input. */
static int witness_gate_table_exists(sqlite3 *db, const char *select_sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, select_sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

static int witness_gate_table_has_rows(sqlite3 *db, const char *count_sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, count_sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW)
        ret = (sqlite3_column_int64(st, 0) > 0) ? 1 : 0;
    sqlite3_finalize(st);
    return ret;
}

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

    /* R3 W4 — the O14 "V2 version firewall" selfcheck stood here. It
     * existed to prove nodus_witness_v2_finalize_block (and, through it,
     * nodus_witness_v2_qc_verify) stayed linked into the binary; both are
     * deleted with the closed consensus lane's QC-verified block-commit
     * path, so there is nothing left for a selfcheck to selfcheck. */

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

    /* ── FLEET-TM-R3 W3 — CHAIN ROLE AT OPEN, COMETBFT-ONLY (D-17 rev 10
     * item 9, atlas-dec-9d96e2ec31ad4840cf258df21732b67f, APPROVED) ─────
     *
     * "the witness's post-open gate REFUSES a chain database that is not
     * a version-3 chain (no canonical stored genesis document) — fail
     * closed, logged". This SUPERSEDES O15J Faz 3's "a pure-V2 chain IS
     * the V2 chain" rule below, which admitted every schema from S1
     * onward via nodus_witness_v2_gen_is_pure and is now too wide: the
     * old lane (legacy V1, and pre-Comet Ledger V2 schemas S1-S13) is
     * CLOSED in W3, not deleted — its bytes are untouched, this node
     * simply will not run it.
     *
     * THREE OUTCOMES, the same discipline nodus_witness_scan_chain_db
     * already applies (absent / fault / present), not two:
     *
     *   (a) the S14 Comet stores (cmt_state, cmt_blockstore — created
     *       together by the single S13->S14 migration rung, D-17 rev 5)
     *       exist AND carry a canonical-strict genesis document
     *       (nodus_witness_v2_gen_stored_chain_id, D-18 rev 4/5) — a
     *       version-3 chain. Accepted; v2_successor = true, v2_chain32 =
     *       the document's own chain id.
     *
     *       nodus_witness_v2_chain_id (claims.c) is deliberately NOT used
     *       for this test: it still accepts a pre-Comet height-0
     *       v2_blocks row via its row-present branch — exactly the
     *       schema this gate must refuse. (BLOCKED for this package:
     *       nodus_witness_v2_claims.c is outside the C2a whitelist: D-23
     *       rev 7's brief asks that function to become "stored-document
     *       only", removing that now-dead row-present branch. Behaviour
     *       is unaffected either way — this gate never calls it — but
     *       the cleanup itself is not done here.)
     *
     *   (b) the S14 stores do NOT exist, and the database holds no
     *       committed content at all (`blocks` empty AND
     *       nodus_witness_v2_gen_is_pure reports 0) — genuinely
     *       PRE-GENESIS: an ordinary fresh boot, OR the ceremony's own
     *       scratch witness (nodus_witness_v2_gen_derive_v3 calls
     *       nodus_witness_create_chain_db, which reaches this gate from
     *       `nodus_witness_create_chain_db` before the derivation's
     *       first migration step runs). Accepted, no role assigned
     *       (v2_successor stays false) — exactly today's pre-open
     *       behaviour; a literal "no stored document ⇒ refuse" reading
     *       of D-17 rev 10 (9) would refuse the ceremony's own database
     *       and is NOT what is implemented here (flagged for the
     *       ORCHESTRATOR as a question, not resolved unilaterally).
     *
     *   (c) anything else — the S14 stores are absent AND the database
     *       holds committed content that is not version-3 (a nonempty
     *       legacy `blocks` table, or a pre-Comet Ledger V2 chain tagged
     *       "DNA.GENESIS.v1" at schema < S14) — REFUSED, fail closed.
     *       Delta 6, item B: EXACTLY ONE of `cmt_state`/`cmt_blockstore`
     *       existing is ALSO (c), refused explicitly, BEFORE it can ever
     *       fall through to (b)'s pre-genesis branch — the S14 rung
     *       creates both tables together in one transaction (D-17 rev 5),
     *       so a half-present catalogue is a corrupt or interrupted
     *       migration, never a fresh chain the node may build on.
     *
     * A catalogue-read FAULT at any step folds into (c)'s refusal —
     * "chain role undeterminable" must never be read as (b)'s absence. */
    witness->v2_successor = false;
    memset(witness->v2_chain32, 0, sizeof(witness->v2_chain32));

    int cmt_state_present = witness_gate_table_exists(witness->db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cmt_state'");
    int cmt_blockstore_present = (cmt_state_present < 0) ? -1 :
        witness_gate_table_exists(witness->db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cmt_blockstore'");

    if (cmt_state_present < 0 || cmt_blockstore_present < 0) {
        fprintf(stderr, "%s: chain role undeterminable for %s (S14 store "
                "catalogue read failed) — refusing the database (fail "
                "closed)\n", LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    if (cmt_state_present == 1 && cmt_blockstore_present == 1) {
        uint8_t v3_id[NODUS_V2_GEN_CHAIN_ID_LEN];
        if (nodus_witness_v2_gen_stored_chain_id(witness, v3_id) != 0) {
            fprintf(stderr, "%s: S14 stores present but no canonical "
                    "stored genesis document for %s — refusing the "
                    "database (fail closed)\n", LOG_TAG, db_path);
            sqlite3_close(witness->db);
            witness->db = NULL;
            return -1;
        }
        witness->v2_successor = true;
        memcpy(witness->v2_chain32, v3_id, sizeof(witness->v2_chain32));
        fprintf(stderr, "%s: chain role: COMETBFT (version 3; the legacy "
                "and pre-Comet lanes are closed)\n", LOG_TAG);
        return 0;
    }

    /* ORCHESTRATOR delta 6, item B — the (a)/(c) BOUNDARY: EXACTLY ONE
     * of the two S14 stores existing is a half-present catalogue, never
     * a fresh chain. The S14 rung creates cmt_state AND cmt_blockstore
     * together, in the SAME migration transaction (D-17 rev 5), so this
     * can only mean a corrupt database or a migration interrupted
     * mid-transaction — falling through to the "no S14 stores" branch
     * below would treat it as (b), PRE-GENESIS, and let the node build a
     * fresh chain ON TOP of the surviving half. Refused here, fail
     * closed, before that branch is ever reached. */
    if (cmt_state_present != cmt_blockstore_present) {
        fprintf(stderr, "%s: S14 catalogue inconsistent for %s "
                "(cmt_state present=%d, cmt_blockstore present=%d) — a "
                "half-migrated schema is never a fresh chain; refusing "
                "the database (fail closed)\n", LOG_TAG, db_path,
                cmt_state_present, cmt_blockstore_present);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    /* No S14 stores — (b) genuinely empty, or (c) closed-lane content. */
    int has_legacy_blocks =
        witness_gate_table_has_rows(witness->db, "SELECT COUNT(*) FROM blocks");
    if (has_legacy_blocks < 0) {
        fprintf(stderr, "%s: chain role undeterminable for %s (legacy "
                "block count read failed) — refusing the database (fail "
                "closed)\n", LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }
    if (has_legacy_blocks == 1) {
        fprintf(stderr, "%s: chain role: LEGACY V1 for %s — the old "
                "consensus lane is CLOSED in W3 (D-17 rev 10); refusing "
                "the database (fail closed)\n", LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    /* O15J's own probe: a pre-Comet Ledger V2 chain (S1-S13) carries the
     * "DNA.GENESIS.v1" source tag with no S14 stores yet. A probe FAULT
     * (-1) refuses the database exactly as it did before W3. */
    int pure_rc = nodus_witness_v2_gen_is_pure(db_path);
    if (pure_rc < 0) {
        fprintf(stderr, "%s: chain role undeterminable for %s — refusing "
                "the database (fail closed)\n", LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }
    if (pure_rc == 1) {
        fprintf(stderr, "%s: chain role: PRE-COMET LEDGER V2 (schema "
                "below S14) for %s — the old consensus lane is CLOSED in "
                "W3 (D-17 rev 10); refusing the database (fail closed)\n",
                LOG_TAG, db_path);
        sqlite3_close(witness->db);
        witness->db = NULL;
        return -1;
    }

    /* (b) — no S14 stores, no legacy content, no pre-Comet V2 manifest:
     * genuinely pre-genesis. No role assigned; the caller (an ordinary
     * fresh boot, or the ceremony's own scratch witness) proceeds to
     * build one. */
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

/* ── O15L Faz 2 — THE SCAN HAS THREE OUTCOMES, NOT TWO ────────────────
 *
 * nodus_witness_scan_chain_db returned 0 or -1, and its caller printed
 * "no chain DB found — pre-genesis state" for EVERY -1. A node whose
 * chain database sat right there on disk and merely could not be opened
 * therefore announced — in the one line an operator reads at startup —
 * that it had never had a chain at all. That is the same class of lie
 * O15K removed from the docs and the same one that let the half-open
 * node report `chain_db=active`: a failure being reported as a value.
 *
 * The three answers now have three codes. Only ABSENT means pre-genesis,
 * and it requires the directory to have been READ SUCCESSFULLY and found
 * to hold no chain database. Everything that is a failure to LOOK — a
 * NULL handle, an unreadable data directory — is a fault, not an
 * observation of absence, and must never license the pre-genesis branch.
 *
 * The codes are file-local because the function's declaration lives in
 * nodus_witness.h, which the dispatch that added them could not write.
 * They are mirrored, with the same warning, in
 * nodus/tests/test_v2_restart_gate.c. Every existing caller tests
 * `!= 0` (nodus_witness_v2_join.c:187, nodus_witness_init below), so no
 * caller changes meaning until it opts in.
 */
#define NODUS_W_SCAN_ABSENT              (-1)
#define NODUS_W_SCAN_UNUSABLE_TRANSIENT  (-2)
#define NODUS_W_SCAN_UNUSABLE_PERMANENT  (-3)

int nodus_witness_scan_chain_db(nodus_witness_t *witness) {
    /* A NULL handle is a node fault, not an observation that there is no
     * chain — hence PERMANENT rather than ABSENT. */
    if (!witness) return NODUS_W_SCAN_UNUSABLE_PERMANENT;
    const char *data_path = witness->data_path;
    DIR *dir = opendir(data_path);
    if (!dir) {
        /* We did not look and find nothing; we could not look. A node
         * that owns a chain must never announce it has none because its
         * own data directory was unreadable. */
        fprintf(stderr,
                "%s: data directory %s could not be read (%s) — this is NOT "
                "pre-genesis, it is a failure to look\n",
                LOG_TAG, data_path, strerror(errno));
        return NODUS_W_SCAN_UNUSABLE_PERMANENT;
    }

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
    /* THE one outcome that is genuine pre-genesis: the directory was read
     * and holds no chain database. */
    if (!have_best) return NODUS_W_SCAN_ABSENT;

    uint8_t chain_id[16];
    if (witness_chain_id_from_name(best, chain_id) != 0) {
        /* Unreachable — `best` only ever holds a name this same parser
         * already accepted — but if the two ever disagreed we would be
         * holding a chain file we cannot name, which is a fault and not
         * an absence. */
        fprintf(stderr,
                "%s: chain DB %s passed selection but not re-parsing — "
                "refusing (fail closed)\n", LOG_TAG, best);
        return NODUS_W_SCAN_UNUSABLE_PERMANENT;
    }

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

    /* O15L Faz 2 — from here on the chain database is PRESENT. Whatever
     * happens next, this scan may no longer report absence: the two exits
     * below are "present and unusable", and they differ only in whether
     * waiting could ever have helped. */
    witness_db_err_class_t open_cls = WITNESS_DB_ERR_PERMANENT;
    if (witness_db_open_path(witness, db_path, &open_cls) != 0) {
        fprintf(stderr,
                "%s: chain DB present but unusable: %s (%s) — this node "
                "HOLDS a chain it cannot read; it is NOT pre-genesis\n",
                LOG_TAG, best,
                open_cls == WITNESS_DB_ERR_TRANSIENT
                    ? "transient fault, retries exhausted"
                    : "permanent fault");
        return open_cls == WITNESS_DB_ERR_TRANSIENT
                   ? NODUS_W_SCAN_UNUSABLE_TRANSIENT
                   : NODUS_W_SCAN_UNUSABLE_PERMANENT;
    }

    /* O15A: the restart path now runs the SAME gate as creation.
     * A gate refusal is a judgement about the CONTENTS of a database that
     * opened fine — S7 pool state that its own tables cannot reproduce, a
     * failed version firewall, an underivable chain role. Waiting cannot
     * change any of those, so it is permanent, and it is emphatically not
     * absence: the gate's own log lines above name what it refused. */
    if (witness_post_open_gate(witness, db_path) != 0) {
        fprintf(stderr,
                "%s: chain DB present but unusable: %s (refused by the "
                "post-open integrity gate) — this node HOLDS a chain it "
                "must not use; it is NOT pre-genesis\n", LOG_TAG, best);
        return NODUS_W_SCAN_UNUSABLE_PERMANENT;
    }

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

    /* ⚠ O15L Faz 1 item 3 — THE IDENTITY IS INSTALLED BEFORE THE OPEN,
     * mirroring the scan path (the O15K A block above the
     * nodus_witness_set_chain_id call in nodus_witness_scan_chain_db).
     * Creation used to open first and set the id afterwards — the exact
     * asymmetry O15K corrected on the scan side and left standing here.
     *
     * It is not merely tidiness. This function closes any previous handle
     * above WITHOUT clearing witness->chain_id, so under the old order a
     * successful open produced a window in which the pair was
     * (db != NULL, chain_id = STALE) — an identity belonging to the chain
     * we just closed, presented as the identity of the one we just
     * opened. Both live callers happen to enter with chain_id == 0
     * today (nodus_witness_bft.c commit_genesis and
     * nodus_witness_bootstrap.c handle_genesis_rsp), so it is latent
     * rather than live; the two paths must still read the same way or the
     * next reader re-derives the bug.
     *
     * Safe for the same reason it is safe on the scan path: chain_id is
     * the caller's argument, not something read out of the database, and
     * nothing between here and the open reads witness->chain_id —
     * witness_db_open_path never reads it at all. A FAILED open now
     * leaves (db == NULL, chain_id != 0), which is DG-1 row 2: the node
     * keeps enforcing the identity it holds instead of falling back to
     * the permissive all-zero reading. That retention is the point; do
     * NOT add a rollback to zero here. */
    nodus_witness_set_chain_id(witness, chain_id);

    /* O15L Faz 2 — the creation path takes the SAME retrying open as the
     * restart path, and for the same reason O15A hoisted the post-open
     * gate: two entrances to one database must not have two different
     * ideas of what a transient fault is. The class is not consulted here
     * because this caller has exactly one answer to a failed creation —
     * there is no chain yet, so there is nothing to report as present. */
    if (witness_db_open_path(witness, db_path, NULL) != 0)
        return -1;

    /* O15A: the SAME gate the restart path runs — see
     * witness_post_open_gate. Previously these two checks lived here
     * only, which is exactly how an ordinary restart came to skip them. */
    if (witness_post_open_gate(witness, db_path) != 0) return -1;

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

/* ── Recovery sentinel boot gate (audit B-2, 2026-05-02) ─────────────
 *
 * R3 W4 — moved verbatim (the read-only half only) from
 * nodus_witness_sync.c, deleted with the closed consensus lane. The
 * writer half (nodus_witness_recovery_sentinel_create/_clear) armed and
 * cleared this sentinel only from nodus_witness_halt_recovery_check,
 * which is deleted with it — no code path can create a NEW sentinel file
 * going forward. This check stays: a data directory carrying a sentinel
 * left by an OLDER binary that crashed mid halt-recovery must still
 * refuse to boot silently (nodus_witness_init calls this before the
 * chain-DB scan), so the file's meaning is preserved even though nothing
 * in this tree can write one again. Made static and file-local: nothing
 * else in the tree references it now that the writer is gone. */
#define NODUS_W_RECOVERY_SENTINEL_NAME ".recovery_in_progress"
#define NODUS_W_RECOVERY_SENTINEL_LEN  40

static void witness_recovery_sentinel_path(const char *data_path,
                                            char *out, size_t out_len) {
    snprintf(out, out_len, "%s/" NODUS_W_RECOVERY_SENTINEL_NAME, data_path);
}

/* Returns 0 if absent (clean boot), 1 if present (admin clear required),
 * -1 on read error. Reads halt_height into *out_halt_height when present. */
static int nodus_witness_recovery_sentinel_check(const char *data_path,
                                                  uint64_t *out_halt_height) {
    char path[512];
    witness_recovery_sentinel_path(data_path, path, sizeof(path));
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "%s: sentinel check open failed at %s: %s\n",
                LOG_TAG, path, strerror(errno));
        return -1;
    }
    uint8_t buf[NODUS_W_RECOVERY_SENTINEL_LEN];
    size_t got = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (got != NODUS_W_RECOVERY_SENTINEL_LEN) {
        fprintf(stderr, "%s: sentinel truncated at %s (got %zu, need %d)\n",
                LOG_TAG, path, got, NODUS_W_RECOVERY_SENTINEL_LEN);
        return -1;
    }
    if (out_halt_height) {
        uint64_t h = 0;
        for (int i = 0; i < 8; i++)
            h |= ((uint64_t)buf[32 + i]) << (i * 8);
        *out_halt_height = h;
    }
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
}

/* ── FLEET-TM-R3 W3 package C2a — the cometbft server binding ────────── */

/**
 * The ONE production `cmt_now_fn` on this chain (BFT-time POLICY,
 * atlas-dec-4ac0423068085c100fdfa3e264ca16bc, APPROVED): the reference's
 * `Now()` (types/time/time.go:9-11) is read only to stamp a validator's
 * OWN vote/proposal and to evaluate the genesis-time wait / timer
 * deadlines in the tick — never for a validation, threshold or state
 * derivation, which is exactly the scope this policy allows. CLOCK_
 * REALTIME, never MONOTONIC: the value this feeds ends up inside a
 * signed vote/proposal preimage and must be wall-clock UTC.
 */
static int witness_cmt_now(void *ctx, cmt_time_t *out) {
    (void)ctx;
    struct timespec ts;
    if (!out || clock_gettime(CLOCK_REALTIME, &ts) != 0) return CMT_FAULT;
    cmt_time_t raw;
    raw.seconds = (int64_t)ts.tv_sec;
    raw.nanos   = (int32_t)ts.tv_nsec;
    return cmt_time_canonical(raw, out);
}

/**
 * Item 5 — `raw_sign` = ML-DSA-87 over the EXACT bytes handed in: the
 * reference's `PrivKey.Sign(signBytes)` (privval/file.go:328, :359,
 * :403). `sign_bytes` is already the pinned cometbft canonical preimage
 * (`CanonicalizeVote` / `CanonicalizeProposal`) — the reference's OWN
 * domain separation via the embedded `SignedMsgType` and chain_id
 * fields. Nodus's own "NDS1" + purpose-byte wrapper
 * (nodus/src/crypto/nodus_sign.h) is deliberately NOT applied here:
 * wrapping these bytes would change what is signed and break
 * verification against the reference's canonical form, which every peer
 * reproduces byte-for-byte from the wire message — this is a wire-format
 * boundary, not a place to add local domain separation.
 */
static int witness_cmt_raw_sign(void *ctx, const uint8_t *sign_bytes,
                                size_t len,
                                uint8_t sig_out[CMT_MAX_SIGNATURE_SIZE],
                                size_t *sig_len) {
    nodus_witness_t *w = (nodus_witness_t *)ctx;
    size_t siglen = 0;

    if (!w || !w->server || !sign_bytes || !sig_out || !sig_len)
        return CMT_FAULT;
    if (qgp_dsa87_sign(sig_out, &siglen, sign_bytes, len,
                       w->server->identity.sk.bytes) != 0) {
        return CMT_FAULT;
    }
    *sig_len = siglen;
    return CMT_OK;
}

/**
 * Item 2 — constructs the startup table (`nodus_cmt_node_init`,
 * node.go:285-422) and the transport glue (package C2b,
 * `nodus_cmt_net_init` + `cmt_conr_init` + `cmt_memr_init` +
 * `nodus_cmt_net_bind`), then runs `nodus_cmt_node_start`'s WAL-only half
 * (node.go's OnStart, state.go:319-336). Called ONLY when
 * `witness->v2_successor` is true — the post-open gate above has already
 * refused every chain database that is not version-3, and
 * `nodus_cmt_net_init`'s precondition (item I, nodus_witness_cmt_net.h)
 * that `v2_chain32` is populated is satisfied by that same gate.
 *
 * The two REACTORS (`cmt_conr_start` / `cmt_memr_start`, which is what
 * reaches `cmt_cs_start` — nodus_witness_cmt_node.c's own comment) are
 * NOT started here: node.go:518-524's genesis-time wait cannot block
 * inside this call, so the tick starts them once due (witness_cmt_tick).
 *
 * ORCHESTRATOR delta 10 — TWO CALLERS BY DESIGN, not one: (1)
 * `nodus_witness_init` (this file, process start on an already-adopted
 * chain — unchanged, below); (2) the pinned-genesis joiner's
 * `join_adopt` (nodus_witness_v2_join.c), meant to call this function
 * immediately after its own `nodus_witness_scan_chain_db(w)` succeeds
 * (:187) — package C2c's own follow-up delta wires that call; this
 * function is exported here (public, no longer `static`) so it can.
 * NAMES A LIVE DEFECT this export closes: measured by the Genesis
 * Protocol harness (`test_v2_join.sh`) — an adopted joiner held the
 * chain (role set, the gate printed "chain role: COMETBFT") but nothing
 * ever built the startup table, so `witness_cmt_tick` returned
 * INT64_MAX forever (`cmt_node == NULL`, :1653 below) and the node
 * never caught up — there is no blocksync in this port; catch-up IS the
 * reactor's stored-part gossip, which needs the reactor. In the
 * reference there is no mid-life adoption (a node starts with its
 * genesis document already); the honest port of "the node now starts
 * with this genesis" is to run, after adoption, exactly the
 * construction a process start runs.
 *
 * Every precondition below is satisfied by BOTH callers via the SAME
 * gate: `v2_successor`/`v2_chain32` are set by `witness_post_open_gate`,
 * reached through `nodus_witness_create_chain_db` (path 1, at process
 * start) or `nodus_witness_scan_chain_db` (path 2, called directly by
 * `join_adopt` at nodus_witness_v2_join.c:187, which itself calls
 * `witness_post_open_gate` at nodus_witness.c:1150); `w->server` and
 * `w->data_path` are set once, at process start
 * (`nodus_witness_init`/the server's own construction), and `join_adopt`
 * never touches the LIVE witness's copies of either (it only sets them
 * on its own throwaway scratch handle, nodus_witness_v2_join.c:108/:110)
 * — so both are already populated by the time the joiner reaches this
 * call. The entry guard right below (delta 8, item C) is exactly right
 * for caller (2) as much as for a hypothetical accidental double call
 * from caller (1): a joiner can only ever adopt once (`join_adopt`
 * returns before this function on every earlier attempt that failed to
 * re-derive or open), so the guard is never expected to fire in
 * practice, but it is the correct backstop either way.
 *
 * @return 0 on success (witness->cmt_node/net/conr/memr populated,
 *         cmt_live false); -1 on any failure, with every partial
 *         allocation released and the witness fields left NULL.
 */
int nodus_witness_cmt_live_init(nodus_witness_t *witness) {
    /* delta 8, item C — an explicit entry guard, not an assumption: this
     * function now has TWO legitimate callers (delta 10's doc comment
     * above), and a second call over an already-built construction would
     * leak the first one's four heap objects and its running node
     * underneath the caller regardless of which caller it was. Made
     * explicit so that stays true even if a future caller ever gets this
     * wrong. */
    if (witness->cmt_node || witness->cmt_net || witness->cmt_conr ||
        witness->cmt_memr) {
        fprintf(stderr, "%s: nodus_witness_cmt_live_init called on an "
                "already-constructed cometbft server binding — refusing "
                "to leak the first one\n", LOG_TAG);
        return -1;
    }
    nodus_cmt_node_t *node = (nodus_cmt_node_t *)calloc(1, sizeof(*node));
    nodus_cmt_net_t  *net  = (nodus_cmt_net_t  *)calloc(1, sizeof(*net));
    cmt_conr_t       *conr = (cmt_conr_t       *)calloc(1, sizeof(*conr));
    cmt_memr_t       *memr = (cmt_memr_t       *)calloc(1, sizeof(*memr));
    char pvpath[768];
    int  pn;

    if (!node || !net || !conr || !memr) {
        fprintf(stderr, "%s: out of memory constructing the cometbft "
                "server binding\n", LOG_TAG);
        goto fail;
    }

    pn = snprintf(pvpath, sizeof(pvpath), "%s/priv_validator_state.json",
                  witness->data_path);
    if (pn < 0 || (size_t)pn >= sizeof(pvpath)) {
        fprintf(stderr, "%s: data path too long for the priv-validator "
                "state file path\n", LOG_TAG);
        goto fail;
    }

    {
        nodus_cmt_node_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.privval_state_path = pvpath;
        opts.now                = witness_cmt_now;
        opts.now_ctx            = NULL;
        opts.raw_sign           = witness_cmt_raw_sign;
        opts.sign_ctx           = witness;
        /* genesis_doc_bytes left NULL: the post-open gate already proved
         * a canonical stored genesis document exists
         * (nodus_witness_v2_gen_stored_chain_id succeeded), so the
         * provider branch (setup.go:563) is never reached on this path.
         * limits left zeroed: nodus_cmt_node_init's own defaults. */
        if (nodus_cmt_node_init(node, witness, &opts) != CMT_OK) {
            fprintf(stderr, "%s: the cometbft startup table could not be "
                    "built — this node cannot run its chain\n", LOG_TAG);
            goto fail;
        }
    }

    if (nodus_cmt_net_init(net, witness, &node->store, witness_cmt_now,
                           NULL) != CMT_OK) {
        fprintf(stderr, "%s: the cometbft transport glue could not be "
                "built\n", LOG_TAG);
        goto fail;
    }

    /* D-23 rev 7 item 18 — wait_sync is ALWAYS false, recorded deviation:
     * block sync is not ported (R3-S); a node behind its peers catches
     * up through the consensus reactor's own stored-part gossip
     * (reactor.go:575-590, ported), never a separate blocksync reactor.
     * recv_arena = net->recv_arena, per nodus_witness_cmt_net.h's own
     * "THE RECEIVE ARENA" note — see this package's report for the
     * discrepancy against D-23 rev 7 (17)'s "the node's ext_arena". */
    if (cmt_conr_init(conr, node->cs, /*wait_sync=*/false, &net->conr_host,
                      net, &net->recv_arena) != CMT_OK) {
        fprintf(stderr, "%s: the consensus reactor could not be built\n",
                LOG_TAG);
        goto fail;
    }
    if (cmt_memr_init(memr, &node->mem_config, node->mem, &net->memr_host)
        != CMT_OK) {
        fprintf(stderr, "%s: the mempool reactor could not be built\n",
                LOG_TAG);
        goto fail;
    }
    if (nodus_cmt_net_bind(net, conr, memr) != CMT_OK) {
        fprintf(stderr, "%s: the transport glue could not be bound to its "
                "reactors\n", LOG_TAG);
        goto fail;
    }

    if (nodus_cmt_node_start(node) != CMT_OK) {
        fprintf(stderr, "%s: the cometbft consensus WAL could not be "
                "started\n", LOG_TAG);
        goto fail;
    }

    witness->cmt_node = node;
    witness->cmt_net  = net;
    witness->cmt_conr = conr;
    witness->cmt_memr = memr;
    witness->cmt_live = false;   /* the tick starts the reactors */
    fprintf(stderr, "%s: cometbft startup table built at height %llu — "
            "the consensus and mempool reactors start once genesis time "
            "is reached\n", LOG_TAG,
            (unsigned long long)node->state->last_block_height);
    return 0;

fail:
    if (conr) { cmt_conr_free(conr); free(conr); }
    if (memr) { cmt_memr_free(memr); free(memr); }
    if (net)  { nodus_cmt_net_free(net); free(net); }
    if (node) { nodus_cmt_node_release(node); free(node); }
    return -1;
}

/**
 * Item 3 — the Comet lane's share of the tick, run in place of the
 * legacy tick body on a version-3 chain. Runs AFTER the witness
 * transport poll (item 3(a), already done by the caller) and drives:
 * (b) the state machine, bounded per tick; (c) the transport glue's peer
 * scan, deferred closes and both reactors' own ticks; (d) the host's
 * timer when due; returns (e) the earlier of the two next deadlines.
 *
 * A CMT_FAULT anywhere is node-local (the W1.7 rule): logged, and this
 * node stops participating in consensus by clearing `witness->running`
 * — the SAME flag `nodus_witness_tick`'s own top-of-function guard
 * already reads, so a halted node's tick becomes a no-op from the next
 * call on. It is never turned into a peer blame. Inbound Comet frames
 * (verbs 35-39) also stop being routed once halted — see the dispatch
 * function's `witness->running` check.
 *
 * @return the earliest of the glue's and the timer's next deadline, in
 *         nanoseconds (host clock); INT64_MAX when neither is pending
 *         or the lane is not yet live. NOT currently threaded into the
 *         server's poll wait (nodus_server.c still polls at a fixed
 *         50 ms) — see this package's report, item 3, for why that is
 *         reported as a simplification rather than implemented.
 *
 * ORCHESTRATOR delta 8, item A — NO UNIT TEST DRIVES THE CLOCK-FAULT
 * BRANCHES (both `n->now(...) != CMT_OK` sites below). `n->now` is
 * wired to the static, production-only `witness_cmt_now` by
 * `nodus_witness_cmt_live_init`, with no test seam — injecting a fault
 * would need a production hook this file does not add (a forbidden
 * pattern, not merely an omitted one), and `witness_cmt_tick` itself is
 * `static` to this file, so no test outside it can even call in.
 * Reported here plainly, rather than manufacturing a hook to claim
 * coverage that does not exist.
 *
 * ORCHESTRATOR delta 10 — `cmt_node`/`net`/`conr`/`memr` stay NULL
 * between `join_adopt`'s `nodus_witness_scan_chain_db(w)` call
 * (nodus_witness_v2_join.c:187, which sets `v2_successor`) and its
 * FOLLOW-UP call to `nodus_witness_cmt_live_init` (package C2c's own
 * delta, not made here — this file's whitelist does not include
 * join.c). Confirmed by reading: `join_adopt` runs synchronously inside
 * `nodus_witness_v2_join_tick`, itself called synchronously from
 * `nodus_witness_tick`'s own body (this file) — one function call
 * inside one tick, no thread, no re-entrant call, no yield point — so
 * once `join_adopt` calls `nodus_witness_cmt_live_init` immediately
 * after its scan (as it must, to close the defect this delta's
 * register row names), NO OTHER TICK can ever land in the gap between
 * them: the guard just below returns INT64_MAX at most zero times on
 * this path, a harmless no-op by construction rather than by luck. */
static int64_t witness_cmt_tick(nodus_witness_t *witness) {
    nodus_cmt_node_t *n    = (nodus_cmt_node_t *)witness->cmt_node;
    nodus_cmt_net_t  *net  = (nodus_cmt_net_t  *)witness->cmt_net;
    cmt_conr_t       *conr = (cmt_conr_t       *)witness->cmt_conr;
    cmt_memr_t       *memr = (cmt_memr_t       *)witness->cmt_memr;

    /* delta 10: a harmless no-op, never observed to actually happen — see
     * this function's own doc comment above for why no tick can land
     * here between join_adopt's scan and its live_init call. */
    if (!n || !net || !conr || !memr) return INT64_MAX;

    /* node.go:518-524 — the genesis-time wait. Not blockable inside an
     * event loop: checked here, once per tick, logged once on the
     * transition. Peers are admitted only once both reactors are
     * running (nodus_witness_cmt_net.h), so a frame arriving before this
     * point is dropped with a WARN by the glue, never faulted. */
    if (!witness->cmt_live) {
        cmt_time_t now_t;
        if (n->now(n->now_ctx, &now_t) != CMT_OK) {
            /* delta 8, item A — a clock fault here is node-local (the
             * W1.7 rule), the same as every other CMT_FAULT this
             * function conforms to below: logged, and this node stops
             * participating rather than silently never going live. */
            fprintf(stderr, "%s: CMT_FAULT reading the clock for the "
                    "genesis-time check — consensus participation "
                    "stops\n", LOG_TAG);
            witness->running = false;
            return INT64_MAX;
        }
        if (cmt_time_unix_nano(now_t) <
            cmt_time_unix_nano(n->doc.genesis_time)) {
            return INT64_MAX;
        }
        if (cmt_memr_start(memr) != CMT_OK) {
            fprintf(stderr, "%s: CMT_FAULT starting the mempool reactor — "
                    "consensus participation stops\n", LOG_TAG);
            witness->running = false;
            return INT64_MAX;
        }
        int rc = cmt_conr_start(conr);   /* reaches cmt_cs_start inside */
        if (rc != CMT_OK) {
            fprintf(stderr, "%s: the consensus reactor failed to start "
                    "(rc %d) — consensus participation stops\n", LOG_TAG,
                    rc);
            witness->running = false;
            return INT64_MAX;
        }
        n->cs_started = true;   /* nodus_witness_cmt_node.h's contract:
                                  * the caller sets this once cmt_conr_start
                                  * has actually reached cmt_cs_start. */
        witness->cmt_live = true;
        fprintf(stderr, "%s: cometbft lane LIVE — genesis time reached\n",
                LOG_TAG);
    }

    /* (b) drain the state machine. Bounded: D-23 rev 7 (19)'s own
     * arithmetic is ~337 parts for one maximal block (cmt_conr.h's
     * arena note, 22 020 096 / 65 536), so this many steps comfortably
     * drains one full proposal in a single tick without starving (c)'s
     * peer scan and deferred closes for the whole tick when many events
     * arrive at once (a vote flood, or a catch-up replay of stored
     * parts); the remainder, if any, runs on the next tick. */
    for (int i = 0; i < WITNESS_CMT_STEP_BUDGET; i++) {
        if (!cmt_cs_has_work(n->cs)) break;
        bool worked = false;
        if (cmt_cs_step(n->cs, &worked) != CMT_OK) {
            fprintf(stderr, "%s: CMT_FAULT in cmt_cs_step — consensus "
                    "participation stops\n", LOG_TAG);
            witness->running = false;
            return INT64_MAX;
        }
        if (!worked) break;
    }

    /* (c) — peer-mesh maintenance and both reactors' own ticks, every
     * iteration, AFTER the transport poll and never from inside an
     * on_frame callback (nodus_cmt_net.h's CALLER CONTRACT — this
     * function is reached only from nodus_witness_tick, never from
     * nodus_witness_dispatch_t3). */
    int64_t net_deadline = INT64_MAX;
    if (nodus_cmt_net_tick(net, &net_deadline) != CMT_OK) {
        fprintf(stderr, "%s: CMT_FAULT in nodus_cmt_net_tick — consensus "
                "participation stops\n", LOG_TAG);
        witness->running = false;
        return INT64_MAX;
    }

    /* (d) — fire the timer if due, then drain again (bounded, as above). */
    cmt_time_t now_t2;
    if (n->now(n->now_ctx, &now_t2) != CMT_OK) {
        /* delta 8, item A — this used to silently skip the timer check
         * on a clock fault (the `&&` short-circuit read the fault the
         * same as "not due yet"), which is exactly the permanent silent
         * stall the W1.7 rule forbids: logged, and this node stops. */
        fprintf(stderr, "%s: CMT_FAULT reading the clock for the "
                "timer-due check — consensus participation stops\n",
                LOG_TAG);
        witness->running = false;
        return INT64_MAX;
    }
    if (nodus_cmt_host_timer_due(n->be, cmt_time_unix_nano(now_t2))) {
        if (cmt_cs_on_timer_expired(n->cs) != CMT_OK) {
            fprintf(stderr, "%s: CMT_FAULT firing the consensus timer — "
                    "consensus participation stops\n", LOG_TAG);
            witness->running = false;
            return INT64_MAX;
        }
        for (int i = 0; i < WITNESS_CMT_STEP_BUDGET; i++) {
            if (!cmt_cs_has_work(n->cs)) break;
            bool worked = false;
            if (cmt_cs_step(n->cs, &worked) != CMT_OK) {
                fprintf(stderr, "%s: CMT_FAULT in cmt_cs_step (post-timer) "
                        "— consensus participation stops\n", LOG_TAG);
                witness->running = false;
                return INT64_MAX;
            }
            if (!worked) break;
        }
    }

    /* (e) — the earlier of the two deadlines. */
    int64_t timer_deadline = INT64_MAX;
    (void)nodus_cmt_host_next_deadline(n->be, &timer_deadline);
    return net_deadline < timer_deadline ? net_deadline : timer_deadline;
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

    /* ORCHESTRATOR delta 1, item C — explicit, not the memset's zero:
     * 0 would read as "already due" on the very first tick's poll-wait
     * calculation, forcing a needless non-blocking poll before
     * witness_cmt_tick has ever run once. */
    witness->cmt_next_deadline_ns = INT64_MAX;


    /* Phase 10 / Task 53 — invalidate the committee cache. UINT64_MAX
     * is the sentinel meaning "no epoch cached yet"; a real epoch
     * start is always < UINT64_MAX. */
    witness->cached_committee_epoch_start = UINT64_MAX;
    witness->cached_committee_count = 0;

    /* Setup identity from server keys */
    witness_setup_identity(witness);

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
     * If not found: db = NULL (pre-genesis state, waiting for genesis TX).
     *
     * ⚠ O15L Faz 2 — THE PRE-GENESIS LINE IS PRINTED FOR ABSENCE ONLY.
     * It used to be printed for every non-zero return, including the ones
     * that mean "the chain database is right there and I could not open
     * it". That sentence is what an operator reads, and on a node that
     * HOLDS a chain it is false — the same class of lie O15K found in the
     * docs and the same one the half-open handle told with
     * `chain_db=active`.
     *
     * A present-but-unusable chain database now REFUSES the witness init
     * rather than continuing as a pretend-fresh node. That is not
     * severity theatre: a node that believes it is pre-genesis enters the
     * bootstrap state machine, and a bootstrapping node may create a
     * chain database or adopt a peer's genesis — beside the chain it
     * already has and cannot see. The transient class has already spent
     * its whole retry budget inside the scan by the time it arrives here
     * (witness_db_open_path), so there is nothing left to wait for. */
    int scan_rc = nodus_witness_scan_chain_db(witness);
    if (scan_rc == NODUS_W_SCAN_ABSENT) {
        fprintf(stderr, "%s: no chain DB found — pre-genesis state\n", LOG_TAG);
    } else if (scan_rc != 0) {
        /* Deliberately NOT worded as "a chain database is present": the
         * permanent class also covers a data directory that could not be
         * read, where presence is exactly what we failed to determine.
         * Over-claiming here would be the same defect in the opposite
         * direction. */
        fprintf(stderr,
                "%s: REFUSING START — this node could NOT establish that it "
                "has no chain (%s) in %s. It is not pre-genesis: either a "
                "chain database is present and unusable, or the data "
                "directory itself could not be read. Starting as though it "
                "were fresh would let it bootstrap a SECOND chain beside one "
                "it cannot see. The WITNESS lines above name the exact "
                "fault; fix it, then restart.\n",
                LOG_TAG,
                scan_rc == NODUS_W_SCAN_UNUSABLE_TRANSIENT
                    ? "transient fault, in-process retries exhausted"
                    : "permanent fault",
                witness->data_path);
        return -1;
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

    /* R3 W4 — the PR 3 Yol B / C6 auto-bootstrap state machine
     * (nodus_witness_bootstrap_start, DISCOVER/HAVE_CHAIN/FETCH_GENESIS)
     * stood here. It is deleted with the closed consensus lane: its
     * HAVE_CHAIN branch only refreshed the legacy bft_config and logged
     * "state=DONE branch=HAVE_CHAIN"; its pinned-joiner branch only
     * logged and returned — the joiner itself is armed above by
     * nodus_witness_v2_join_arm, which already logs "fresh successor
     * joiner armed" on its own (nodus_witness_v2_join.c). Nothing
     * replaces the DISCOVER round-1 scheduling: a fresh node with no
     * pin and no chain simply has no role (witness_post_open_gate's
     * outcome (b)) until an operator drives the version-3 genesis
     * ceremony or a pin arrives. */

    /* FLEET-TM-R3 W3 (D-23 rev 7, package C2a) — on a version-3 chain,
     * build the cometbft server binding. witness->v2_successor is true
     * ONLY when witness_post_open_gate accepted a version-3 chain, so
     * this never runs against a pre-genesis node (no chain database yet)
     * or a legacy/pre-Comet chain (both already refused above). */
    if (witness->v2_successor) {
        if (nodus_witness_cmt_live_init(witness) != 0) {
            fprintf(stderr,
                    "%s: the cometbft server binding could not be built — "
                    "refusing init\n", LOG_TAG);
            return -1;
        }
    }

    fprintf(stderr, "%s: initialized (roster=%d witnesses, "
            "chain_db=%s)\n",
            LOG_TAG, witness->roster.n_witnesses,
            witness->db ? "active" : "pre-genesis");

    return 0;
}

/* R3 W4 — the epoch-tick roster rebuild interval. Named alongside the
 * legacy block timer for historical reasons; the block timer itself
 * (mempool-driven batch proposal) is deleted with the closed consensus
 * lane, but the transport-mesh epoch rebuild in witness_mesh_tick still
 * uses this constant. */
#define WITNESS_EPOCH_SECS  60

/* R3 W4 — nodus_witness_pending_forward_expire, nodus_witness_v2_entry_verdict,
 * nodus_witness_v2_entry_is_decided, nodus_witness_mempool_evict_committed and
 * nodus_witness_mempool_reap_epoch are DELETED with the closed consensus
 * lane: they judged and drained the legacy `pending_forwards` table and the
 * legacy in-memory mempool, both deleted (the version-3 lane's mempool is
 * the Comet reactor's own, cmt_mem.c). The full contracts, including the
 * class-routed nullifier-vs-claims judgement O15K V-3 and O15I V1 built up,
 * are gone with the state they judged. */

/**
 * MESH MAINTENANCE. Called unconditionally, once per tick, before the
 * role-specific branch: dead-connection cleanup, dialing every roster
 * witness with backoff, the IDENT exchange that sets `peers[i].identified`
 * (`nodus_witness_peer_tick`), then the 60 s epoch roster rebuild below.
 * Both surviving roles need it — a version-3 successor needs identified
 * peers for the Comet transport glue's `net_scan_peers`, and a pre-genesis
 * node needs them for the pinned joiner's gbundle fetch — so it no longer
 * has a legacy-only call site to be unchanged at.
 *
 * @return true when there was NO roster change this tick (the epoch
 *         timer fired and the rebuilt roster is identical to the
 *         current one). THE CALLER MUST IGNORE THIS RETURN VALUE ON A
 *         VERSION-3 CHAIN: there is no legacy round phase left to defer
 *         a swap for, so the swap below is always the IMMEDIATE branch,
 *         and "no change" is simply nothing left to do this tick — never
 *         a reason to skip draining the Comet state machine.
 */
static bool witness_mesh_tick(nodus_witness_t *witness) {
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
            /* No change — skip swap. See this function's own doc
             * comment for how each call site treats this return. */
            return true;
        }

        /* R3 W4 — always immediate: there is no legacy round-active
         * window left to defer a swap for (the legacy round_state and
         * its phase are deleted with the closed consensus lane). F17
         * A2 — transport-only swap; BFT config is refreshed from the
         * chain committee at round-start (no gossip-driven quorum
         * changes). */
        memcpy(&witness->roster, &witness->pending_roster,
               sizeof(nodus_witness_roster_t));

        fprintf(stderr, "WITNESS: epoch roster swap: %u witnesses "
                "(transport)\n",
                witness->roster.n_witnesses);
    }

    return false;
}

void nodus_witness_tick(nodus_witness_t *witness) {
    if (!witness || !witness->running) return;

    /* ── ORCHESTRATOR delta 1, item C (D-23 rev 7 (19)) — THE POLL WAIT,
     * APPLIED TO THE WITNESS TRANSPORT'S OWN WAIT ONLY ──────────────────
     *
     * The reference's "poll wait = min(50 ms, the earliest deadline)"
     * governs the ONE wait this port controls without touching
     * nodus_server.c's multi-poll loop: the witness TCP poll below.
     * witness->cmt_next_deadline_ns is what the PREVIOUS tick's
     * witness_cmt_tick returned (INT64_MAX — the doc default — until a
     * version-3 chain's Comet lane has run at least once); the server's
     * other polls (client TCP, inter-node TCP, channel, UDP) are
     * untouched, exactly as before this change. */
    int witness_poll_timeout_ms = 50;
    if (witness->v2_successor &&
        witness->cmt_next_deadline_ns != INT64_MAX) {
        cmt_time_t now_t;
        if (witness_cmt_now(NULL, &now_t) == CMT_OK) {
            int64_t now_ns    = cmt_time_unix_nano(now_t);
            int64_t remain_ns = witness->cmt_next_deadline_ns - now_ns;
            int64_t remain_ms = remain_ns / 1000000;
            if (remain_ms < 0) remain_ms = 0;
            if (remain_ms < (int64_t)witness_poll_timeout_ms)
                witness_poll_timeout_ms = (int)remain_ms;
        }
    }

    /* Poll dedicated witness TCP transport (port 4004) — item 3(a). This
     * runs UNCONDITIONALLY, on both a legacy and a version-3 chain: it is
     * what feeds nodus_witness_dispatch_t3, which routes verbs 35-39 into
     * the Comet lane below regardless of which tick body runs. The
     * timeout computed above narrows this wait on a version-3 chain;
     * a legacy chain keeps the fixed 50 ms it always had. */
    if (witness->tcp)
        nodus_tcp_poll((nodus_tcp_t *)witness->tcp, witness_poll_timeout_ms);

    /* R3 W4 — THE OLD LANE IS DELETED, NOT MERELY CLOSED. Mesh
     * maintenance runs unconditionally (poll -> peer tick -> roster
     * refresh), because BOTH remaining roles need it: a version-3
     * successor needs identified peers for the Comet transport glue's
     * net_scan_peers, and a pre-genesis node needs them for the pinned
     * joiner's gbundle fetch (see witness_mesh_tick's own doc comment).
     * What runs next is role-exclusive: a successor drains the Comet
     * lane; anything else (pre-genesis, no role assigned yet —
     * witness_post_open_gate's outcome (b)) drives the pinned-genesis
     * joiner tick instead. There is no third role: the post-open gate
     * refuses every chain that is not version-3 at open. */
    (void)witness_mesh_tick(witness);
    if (witness->v2_successor) {
        witness->cmt_next_deadline_ns = witness_cmt_tick(witness);
    } else {
        /* O15E Faz D — pinned-genesis joiner: pull the genesis bundle
         * while a fresh node has a pin but no successor chain yet.
         * No-op once adopted or when this node is not a joiner. */
        nodus_witness_v2_join_tick(witness);
    }
}

/* ── Tier 3 dispatch (BFT message routing) ───────────────────────── */

/**
 * NETSTATS receive counting (nodus 0.19.76) — OBSERVATION ONLY: the
 * counters live in the Comet transport glue's own object
 * (nodus_cmt_net_t.stats, next to the send-side counters net_send
 * writes), so both directions are emitted by one snapshot. Nothing reads
 * them back on any decision path. The price of keeping them there
 * rather than on nodus_witness_t: a frame received while
 * `witness->cmt_net` is NULL (a node before its version-3 lane is
 * constructed — pre-genesis roster/ident/bundle traffic) is not counted.
 */
static void witness_netstats_rx(nodus_witness_t *witness,
                                const nodus_t3_msg_t *msg, size_t frame_len,
                                bool verified, bool verify_ok) {
    if (witness->cmt_net)
        nodus_cmt_net_stats_rx((nodus_cmt_net_t *)witness->cmt_net, msg,
                               frame_len, verified, verify_ok);
}

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

    /* NETSTATS (observation only): true once nodus_t3_verify below has
     * run AND passed; IDENT is never verified here. Each path below
     * counts the frame exactly once, where it concludes — the order of
     * the checks is unchanged. */
    bool netstats_verified = false;

    /* IDENT messages may come from unknown senders (Phase 5) */
    if (msg.type != NODUS_T3_IDENT) {
        if (sender_idx < 0) {
            fprintf(stderr, "%s: T3 %s from unknown sender, ignoring\n",
                    LOG_TAG, msg.method);
            witness_netstats_rx(witness, &msg, len, false, false);
            return;
        }

        /* Verify wsig against sender's roster public key.
         *
         * ── KNOWN, ACCEPTED RESIDUAL (nodus/BUGS.md O15N-L4) ────────────
         *
         * This verify authorizes the FRAME on the transport roster, and the
         * roster admits any self-published DHT `nodus:pk` record that has a
         * valid signature, is unexpired and is not a duplicate — there is
         * no committee filter (nodus_witness_peer.c). A T3 sender identity
         * therefore costs one Dilithium keypair plus one DHT put.
         *
         * O15O Faz 4 closed the consequence that mattered: every
         * consensus-affecting T3 consumer re-authorizes the sender against
         * the chain-derived committee inside its own handler. The closed
         * lane's COMMIT handler did this at bft.c's own gate; on the
         * version-3 lane the equivalent authority is the Comet reactor's
         * own validator-set check, inside the transport glue below.
         *
         * BINDING THIS VERIFY ITSELF TO THE COMMITTEE IS NOT DONE, AND NOT
         * AN OVERSIGHT. Resolving a committee requires a height, and no
         * height is authenticated at this point — the message has not been
         * signature-checked yet, so nothing inside it can be trusted to
         * select an authority. The only height available here is this
         * node's LOCAL tip, and using it would make a node that is BEHIND
         * refuse frames from a legitimately-seated new validator, including
         * the very frames that would let it catch up. The residual is
         * therefore accepted deliberately: an unadmitted identity can spend
         * this node's Dilithium verify budget on the epoll thread, but it
         * cannot influence consensus state. */
        nodus_pubkey_t pk;
        memcpy(pk.bytes,
               witness->roster.witnesses[sender_idx].pubkey,
               NODUS_PK_BYTES);

        if (nodus_t3_verify(&msg, &pk) != 0) {
            fprintf(stderr, "%s: T3 %s wsig verification failed (roster %d)\n",
                    LOG_TAG, msg.method, sender_idx);
            witness_netstats_rx(witness, &msg, len, true, false);
            return;
        }
        netstats_verified = true;
    }
    witness_netstats_rx(witness, &msg, len, netstats_verified, true);

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
     * definition, not a new judgement. R3 W4 deleted the legacy
     * bootstrap/sync verbs this comment used to name; the gate list is
     * now exactly verbs 35-39. IDENT and roster (9-11) are NOT gated:
     * IDENT is not wsig-verified at this point, so its version claim is
     * unauthenticated and must not be acted on. A stale peer may still
     * become known to the mesh; it simply cannot influence consensus.
     * The SYSTEM-governance approval-collection RPC (40-41, D-16 rev 7,
     * W4-CC — replacing the retired vote-collect pair 14-15) and the
     * genesis bundle (24-25) are not gated either — 40 is routed to its
     * own handler below regardless of version (it is a governance RPC,
     * not a BFT round primitive) and 41 falls to the dispatcher's
     * `default:` log-and-drop (a server never receives it), while 24-25
     * is pre-consensus bootstrap traffic, not a live BFT round.
     *
     * BOTH directions fail closed: an older version and an unknown newer
     * version are equally rejected by the exact-match test.
     *
     * FLEET-TM-R3 W3/W4 (D-16 rev 5, atlas-dec-0c86593601db977cd5af648b78910004
     * rev 5, APPROVED) — THIS LIST IS EXACTLY VERBS 35-39. The old lane's
     * eight consensus-affecting verbs (PROPOSE/PREVOTE/PRECOMMIT/COMMIT/
     * VIEWCHG/NEWVIEW/FWD_REQ/FWD_RSP) and the two view-authority verbs
     * (VIEWOK/VIEWOK_REQ) are DELETED, not merely unheld here: their enum
     * values are retired and their decoders are gone, so a frame naming
     * one never reaches this authenticated gate at all — there is no
     * protocol version of the OLD lane left to protect. The identical
     * list in the quarantine switch below must move with this one. */
    switch (msg.type) {
    case NODUS_T3_CMT_STATE:
    case NODUS_T3_CMT_DATA:
    case NODUS_T3_CMT_VOTE:
    case NODUS_T3_CMT_VOTE_SET_BITS:
    case NODUS_T3_CMT_TXS:
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
     * R3 W4 deleted the legacy sync verbs this comment used to name; the
     * quarantine switch below refuses exactly verbs 35-39 (the only
     * consensus-affecting set) and lets everything else through — IDENT /
     * ROST_Q/R (so the peer mesh stays alive), the SYSTEM-governance
     * approval-collection RPC (40-41, W4-CC — 40 routed normally, 41
     * dropped at `default:` regardless, a server never receives it) and
     * the genesis bundle (24-25) — so an operator can diagnose and
     * recover without tearing the node down. */
    if (witness->quarantined) {
        switch (msg.type) {
        /* FLEET-TM-R3 W3 (D-16 rev 5) — the same list as the version gate
         * above, for the same reason: only verbs 35-39 are consensus in
         * the Comet lane now. */
        case NODUS_T3_CMT_STATE:
        case NODUS_T3_CMT_DATA:
        case NODUS_T3_CMT_VOTE:
        case NODUS_T3_CMT_VOTE_SET_BITS:
        case NODUS_T3_CMT_TXS:
            fprintf(stderr, "%s: QUARANTINED — dropping %s (chain_id disagreement with quorum)\n",
                    LOG_TAG, msg.method);
            return;
        default:
            break;
        }
    }

    /* Route to appropriate handler.
     *
     * R3 W4 — verbs 1-8 (legacy consensus + forward), 12-13/16-23
     * (legacy sync, bootstrap discovery/genesis fetch, old-lane V2 block
     * sync) and 26-27 (view authority) are DELETED, not merely dropped:
     * their enum values are retired numbers (see nodus_tier3.h) and
     * their decoders are gone, so a frame naming one never reaches
     * nodus_t3_decode successfully and never reaches this switch at all
     * — the `default:` case below is what answers it.
     *
     * D-16 rev 7 (W4-CC) retires verbs 14-15 (chain_config vote-collect)
     * and REBUILDS the RPC as verbs 40-41 over the pre-auth envelope: 40
     * (w_cc_appr_req) has a live case below, routed to
     * nodus_witness_handle_cc_appr_req regardless of chain version (a
     * governance RPC, not a BFT round primitive — NOT gated above); 41
     * (w_cc_appr_rsp) is a client-only reply a server never receives —
     * it has no case here and falls to `default:`, which logs and drops
     * it, the same shape 14-15 fell to before this rewire.
     *
     * Verbs 9-11 (roster, ident — the transport mesh) and 24-25 (genesis
     * bundle) are KEPT, byte-identical to before. Verbs 35-39 (the
     * cometbft envelope) are the verb IS the channel: this layer decodes
     * nothing inside it — nodus_cmt_net_receive routes by channel to the
     * reactor that marshalled the bytes. */
    switch (msg.type) {
    /* Peer mesh messages — KEPT (D-16 rev 5): the transport mesh, not
     * consensus. */
    case NODUS_T3_ROST_Q:
        nodus_witness_peer_handle_rost_q(witness, conn, &msg);
        break;
    case NODUS_T3_ROST_R:
        nodus_witness_peer_handle_rost_r(witness, &msg);
        break;
    case NODUS_T3_IDENT:
        nodus_witness_peer_handle_ident(witness, conn, &msg);
        break;

    /* ── cometbft envelope verbs 35-39 (D-16 rev 5) ───────────────────
     * Routed whole to the transport glue; a CMT_FAULT from the glue is
     * node-local (the W1.7 rule) and is handled by the tick, which is
     * where witness->running is cleared — not here. A halted node
     * (witness->running false) or a node whose Comet lane never came up
     * (witness->cmt_net NULL — not a version-3 chain, or construction
     * failed at init) drops the frame silently: routing into a state
     * machine that is not running would either no-op inside the glue's
     * own guards or, for a halted node, feed a state machine this node
     * has deliberately stopped trusting. */
    case NODUS_T3_CMT_STATE:
    case NODUS_T3_CMT_DATA:
    case NODUS_T3_CMT_VOTE:
    case NODUS_T3_CMT_VOTE_SET_BITS:
    case NODUS_T3_CMT_TXS:
        if (!witness->running || !witness->cmt_net) break;
        (void)nodus_cmt_net_receive((nodus_cmt_net_t *)witness->cmt_net,
                                    msg.header.sender_id, &msg);
        break;

    /* ── O15E Faz D — Ledger V2 successor genesis bundle (verbs 24-25) —
     * KEPT (D-16 rev 5): package C2c's, not consensus. */
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

    /* ── SYSTEM-governance approval collection (verb 40; D-16 rev 7,
     * W4-CC) — a governance RPC, not a consensus verb: routed regardless
     * of chain version or quarantine state (neither switch above gates
     * it). Verb 41 (the reply) is client-only and falls to `default:`
     * below, unchanged from how 14-15 fell there before this rewire. */
    case NODUS_T3_CC_APPR_REQ:
        nodus_witness_handle_cc_appr_req(witness, conn, &msg);
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

    /* R3 W4 — the in-flight batch_entries sweep, the retained reproposal
     * batch, the parked next-view PROPOSE and the view-change records'
     * heap-owned prepared-sig arrays are deleted with the closed
     * consensus lane: round_state, retained_batch, parked_propose and
     * view_changes[] no longer exist on nodus_witness_t. */

    /* Close peer mesh (clears conn references) */
    nodus_witness_peer_close(witness);

    /* FLEET-TM-R3 W3 (package C2a) — the cometbft server binding, torn
     * down in reverse construction order, BEFORE witness->db closes.
     * cmt_conr_stop reaches cmt_cs_stop itself (reactor.go:95-103), ahead
     * of nodus_cmt_node_release's own (idempotent — "already stopped" is
     * a CMT_REJECT, not a fault) cmt_cs_stop call. */
    {
        cmt_memr_t       *memr = (cmt_memr_t *)witness->cmt_memr;
        cmt_conr_t       *conr = (cmt_conr_t *)witness->cmt_conr;
        nodus_cmt_net_t  *net  = (nodus_cmt_net_t *)witness->cmt_net;
        nodus_cmt_node_t *node = (nodus_cmt_node_t *)witness->cmt_node;

        if (memr && witness->cmt_live) (void)cmt_memr_stop(memr);
        if (conr && witness->cmt_live) (void)cmt_conr_stop(conr);
        if (memr) { cmt_memr_free(memr); free(memr); }
        if (conr) { cmt_conr_free(conr); free(conr); }
        /* NETSTATS (observation only): the final cumulative snapshot,
         * so the counters since the last periodic line are not lost. */
        if (net)  nodus_cmt_net_stats_emit(net, "shutdown");
        if (net)  { nodus_cmt_net_free(net); free(net); }
        if (node) { nodus_cmt_node_release(node); free(node); }
        witness->cmt_memr = NULL;
        witness->cmt_conr = NULL;
        witness->cmt_net  = NULL;
        witness->cmt_node = NULL;
        witness->cmt_live = false;
    }

    if (witness->db) {
        sqlite3_close(witness->db);
        witness->db = NULL;
    }

    fprintf(stderr, "%s: shutdown complete\n", LOG_TAG);
}
