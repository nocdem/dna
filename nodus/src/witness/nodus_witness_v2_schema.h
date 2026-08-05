/**
 * @file nodus_witness_v2_schema.h
 * @brief Ledger V2 Season 5 — versioned schema + atomic migration for the
 *        INACTIVE V2 persistence layer.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path runs this migration or reads any v2_* table.
 * Tests (and, later, the Ledger V2 devnet reset) drive it. A migrated DB
 * remains fully usable by the current V1 software: every added structure
 * is new-table or additive-column, every existing INSERT uses an explicit
 * column list (verified: nodus_witness_bft.c:3061, nodus_witness_db.c:172),
 * and no V1 root computation reads the new column.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── Schema versioning ─────────────────────────────────────────────────
 * `PRAGMA user_version` is the schema version register (transactional in
 * SQLite — it rolls back with the enclosing transaction):
 *   0  every pre-S5 database (fresh, legacy/V1, or S4 — none ever set it)
 *   5  Ledger V2 S5 schema present
 *   6  Ledger V2 S6 schema present (S5 + the three generic
 *      manifest/claim tables below)
 * Any OTHER value is unknown/newer state and FAILS CLOSED: this build
 * refuses to touch a database whose schema it does not understand.
 *
 * ── S6 migration (nodus_witness_db_migrate_v2s6) ──────────────────────
 * Version 0 first runs the (atomic) S5 migration, then ONE atomic
 * BEGIN IMMEDIATE … COMMIT performs 5 → 6, in order:
 *   1. create the three S6 tables (IF NOT EXISTS);
 *   2. verify every required table actually exists;
 *   3. PRAGMA user_version = 6.
 * ANY failure rolls the 5 → 6 transaction back (a crash between the two
 * stages leaves a VALID version-5 database; re-running resumes).
 * Re-running after success is a no-op. Version 6 is required by the S6
 * apply engine and V2 genesis; any other value fails closed.
 *
 * ── S6 tables (generic names only) ────────────────────────────────────
 *   v2_manifests     manifest_seq PK · manifest_hash UNIQUE (64) ·
 *                    manifest (canonical GenesisManifest v1 bytes) ·
 *                    committed_height — the committed manifest set;
 *                    manifest_root is computed over it
 *   v2_dist_state    manifest_seq PK · remaining — the generic
 *                    unclaimed-distribution amount (the ONE supply
 *                    owner of unclaimed genesis-distribution value)
 *   v2_claims_spent  nullifier PK (64) · manifest_seq · leaf_index ·
 *                    amount · claimed_height · utxo_id (64) — the
 *                    spent-claim set; claims_root is computed over it
 *                    and every row deterministically reconstructs its
 *                    claim effect
 *
 * ── Migration (nodus_witness_db_migrate_v2s5) ─────────────────────────
 * One atomic BEGIN IMMEDIATE … COMMIT containing, in order:
 *   1. create the six v2_* tables (IF NOT EXISTS);
 *   2. ALTER TABLE utxo_set ADD COLUMN domain_id INTEGER NOT NULL
 *      DEFAULT 1 — every existing (legacy) UTXO is thereby owned by
 *      DNA_CORE exactly once; the guard tolerates an already-present
 *      column (re-entry) and nothing else;
 *   3. verify every required table + column actually exists (a DDL that
 *      silently did nothing is a fault, not a success);
 *   4. PRAGMA user_version = 5.
 * ANY failure rolls the whole transaction back: no half-created schema,
 * the previous shape stays untouched and usable, and startup fails closed.
 * Re-running after success is a no-op (version short-circuit). The _ex
 * variant exposes deterministic fault-injection stages for the tests.
 *
 * ── UTXO domain ownership ─────────────────────────────────────────────
 * utxo_set.domain_id: NOT NULL, single column ⇒ exactly one owning domain
 * per UTXO, never nullable, never duplicated. Initial mapping: every
 * existing native/token UTXO → DNA_CORE (1). SYSTEM owns no spendable
 * UTXOs (current source defines no consensus-owned spendable class —
 * verified: bonds/delegations live in validators/delegations tables, not
 * utxo_set). There is no CPUNK ownership.
 *
 * ── v2_* tables (columns/keys) ────────────────────────────────────────
 *   v2_blocks           global_height PK · block_id UNIQUE · prev_block_id
 *                       · epoch · tx_root · domain_updates_root ·
 *                       domains_root · system_root · core_root ·
 *                       global_root · vset_hash · tx_count · qc (NULL
 *                       until QC V2 activates — slot only)
 *   v2_domain_heads     domain_id PK · head (89-byte S2 canonical
 *                       encoding, dna_v2_domain_head_encode) ·
 *                       domain_height + last_updated_global mirrors
 *                       (validated against the blob on every read)
 *   v2_domain_updates   (global_height, domain_id) PK · upd (358-byte
 *                       canonical DomainUpdate v1) · upd_hash (64)
 *   v2_root_history     (domain_id, domain_height) PK · global_height ·
 *                       state_root · upd_hash · ruleset_version ·
 *                       ruleset_hash — append-only under commits
 *   v2_tx_index         (global_height, global_index) PK · tx_id UNIQUE ·
 *                       owner_domain (DNA_TX_OWNER_NONE sentinel when a
 *                       cross-domain tx has no single owner — never NULL)
 *                       · touched (canonical list: count u16 BE + u32 BE
 *                       ids strictly ascending) · wire_version
 *   v2_tx_local_index   (domain_id, domain_height, local_index) PK ·
 *                       (tx_id, domain_id) UNIQUE
 *
 * @file nodus_witness_v2_schema.h
 */

#ifndef NODUS_WITNESS_V2_SCHEMA_H
#define NODUS_WITNESS_V2_SCHEMA_H

#include "witness/nodus_witness.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The S5 schema version stored in PRAGMA user_version. */
#define NODUS_V2_SCHEMA_VERSION  5u

/** The S6 schema version — required by the S6 apply engine/genesis. */
#define NODUS_V2_SCHEMA_VERSION_S6  6u

/** Deterministic fault-injection stages for the migration tests. */
typedef enum {
    V2MIG_FAIL_NONE = 0,
    V2MIG_FAIL_AFTER_BEGIN,       /* after BEGIN, before any DDL          */
    V2MIG_FAIL_AFTER_TABLES,      /* six tables created                   */
    V2MIG_FAIL_AFTER_ALTER,       /* utxo_set.domain_id added             */
    V2MIG_FAIL_AFTER_VERIFY,      /* schema verification passed           */
    V2MIG_FAIL_BEFORE_COMMIT      /* user_version written, pre-COMMIT     */
} nodus_v2_mig_fail_t;

/** Deterministic fault-injection stages for the S6 migration tests
 *  (the 5 → 6 transaction only — the embedded S5 stage has its own). */
typedef enum {
    V2S6MIG_FAIL_NONE = 0,
    V2S6MIG_FAIL_AFTER_BEGIN,     /* after BEGIN, before any DDL          */
    V2S6MIG_FAIL_AFTER_TABLES,    /* three S6 tables created              */
    V2S6MIG_FAIL_AFTER_VERIFY,    /* schema verification passed           */
    V2S6MIG_FAIL_BEFORE_COMMIT    /* user_version written, pre-COMMIT     */
} nodus_v2s6_mig_fail_t;

/** Read the schema version. @return 0 with *out set, -1 on fault. */
int nodus_witness_db_schema_version(nodus_witness_t *w, uint32_t *out);

/**
 * Atomic S5 migration (header contract above).
 * @return 0 migrated or already at version 5 (idempotent);
 *         -1 failure (full rollback — previous schema intact) — including
 *         an UNKNOWN user_version (neither 0 nor 5): fail closed.
 */
int nodus_witness_db_migrate_v2s5(nodus_witness_t *w);

/** Test variant: abort deterministically at `fail_at` (rolls back, -1). */
int nodus_witness_db_migrate_v2s5_ex(nodus_witness_t *w,
                                     nodus_v2_mig_fail_t fail_at);

/**
 * Atomic S6 migration (header contract above). Version 0 runs the S5
 * migration first (its own atomic transaction), then 5 → 6 atomically.
 * @return 0 migrated or already at version 6 (idempotent);
 *         -1 failure (full rollback of the running stage) — including
 *         an UNKNOWN user_version (neither 0, 5 nor 6): fail closed.
 */
int nodus_witness_db_migrate_v2s6(nodus_witness_t *w);

/** Test variant: abort deterministically at `fail_at` inside the 5 → 6
 *  transaction (rolls back, -1; the DB stays a valid version-5 schema). */
int nodus_witness_db_migrate_v2s6_ex(nodus_witness_t *w,
                                     nodus_v2s6_mig_fail_t fail_at);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SCHEMA_H */
