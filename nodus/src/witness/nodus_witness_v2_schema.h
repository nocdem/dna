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
 *   7  Ledger V2 S7 schema present (S6 + the four generic pool-state
 *      tables below)
 *   8  Ledger V2 intent-season schema present (S7 + v2_intent_index —
 *      the semantic transaction index; see the S8 block below)
 * Any OTHER value is unknown/newer state and FAILS CLOSED: this build
 * refuses to touch a database whose schema it does not understand
 * (version 9+ rejects — no forward compatibility is ever assumed).
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
 *   v2_manifests     manifest_seq PK (INTERNAL LOCATOR ONLY — appears in
 *                    no signature, nullifier, root or replay key) ·
 *                    manifest_hash UNIQUE (64, the COMMITTED identity) ·
 *                    manifest (canonical GenesisManifest v1 bytes) ·
 *                    committed_height — the committed manifest set;
 *                    manifest_root is computed over the hashes
 *   v2_dist_state    manifest_hash PK · target_domain_id ·
 *                    target_asset_ref · remaining — unclaimed
 *                    distribution value, namespaced by committed
 *                    identity + explicit target domain/asset (each
 *                    target runtime owns the rows targeting it; no
 *                    domain default exists)
 *   v2_claims_spent  nullifier PK (64) · manifest_hash · target_domain_id
 *                    · target_asset_ref · leaf_index · amount ·
 *                    claimed_height · output_id (64, the target
 *                    runtime's domain-local output identity) — the
 *                    spent-claim set; each runtime's claims_root is
 *                    computed over the rows targeting ITS domain
 *
 * ── S7 migration (nodus_witness_db_migrate_v2s7) ──────────────────────
 * Version 0/5 first runs the (atomic) S6 migration chain, then ONE
 * atomic BEGIN IMMEDIATE … COMMIT performs 6 → 7, in order:
 *   1. create the four S7 tables (IF NOT EXISTS);
 *   2. verify every required table exists AND carries EXACTLY the
 *      expected column sequence (column drift / partial tables reject);
 *   3. PRAGMA user_version = 7.
 * ANY failure rolls the 6 → 7 transaction back (a crash between stages
 * leaves a VALID version-6 database; re-running resumes). Re-running at
 * version 7 is a no-op. Version 8+ fails closed. The S7 apply engine
 * and V2 genesis require version 7.
 *
 * ── S7 tables (generic pool state — namespaced (domain_id, pool_id);
 *    NO domain or pool default exists anywhere) ───────────────────────
 *   v2_pools            (domain_id, pool_id) PK · config_version ·
 *                       tree_depth · history_limit · asset_ref (opaque,
 *                       target-runtime-interpreted) · note_count ·
 *                       note_root (32 = 4 u64 BE canonical lanes) ·
 *                       frontier (D×32 canonical filled-subtree blob;
 *                       non-meaningful levels zeroed) · nul_count ·
 *                       nul_root (64) · balance · hist_count ·
 *                       hist_next_seq — the O(D) consensus pool state
 *   v2_pool_notes       (domain_id, pool_id, position) PK · commitment
 *                       (32) · global_height · tx_index · output_slot —
 *                       the O(count) DERIVED/rebuildable commitment
 *                       list for future path serving; NOT independently
 *                       committed by pools_root (count+root are)
 *   v2_pool_nullifiers  (domain_id, pool_id, nullifier) PK ·
 *                       position UNIQUE per pool · global_height ·
 *                       tx_index · input_slot — strict-insert spent set
 *   v2_pool_roots       (domain_id, pool_id, seq) PK · note_root
 *                       (UNIQUE per pool among retained) ·
 *                       global_height — the retained newest-R
 *                       finalized-root window (R consensus-committed in
 *                       the pool config)
 *
 * ── Migration (nodus_witness_db_migrate_v2s5) ─────────────────────────
 * One atomic BEGIN IMMEDIATE … COMMIT containing, in order:
 *   1. create the six v2_* tables (IF NOT EXISTS);
 *   2. rebuild utxo_set with domain_id INTEGER NOT NULL and NO default;
 *      the copy SELECT assigns every existing (legacy) UTXO to
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
 * utxo_set.domain_id: NOT NULL, single column, NO SCHEMA DEFAULT ⇒
 * exactly one owning domain per UTXO, written EXPLICITLY by every
 * insert. The migration rebuilds the table; the one-time legacy
 * assignment (pre-existing DNA rows → the configured legacy CORE
 * domain, id 1) is an explicit literal in the copy SELECT — a migration
 * rule, never a lasting default. SYSTEM owns no spendable UTXOs
 * (verified: bonds/delegations live in validators/delegations tables,
 * not utxo_set).
 *
 * ── v2_* tables (columns/keys) ────────────────────────────────────────
 *   v2_blocks           global_height PK · block_id UNIQUE · prev_block_id
 *                       · epoch · tx_root · domain_updates_root ·
 *                       domains_root · global_root · vset_hash ·
 *                       tx_count · qc (NULL until QC V2 activates — slot
 *                       only). GENERIC commitments only: per-domain
 *                       roots live in v2_domain_heads/v2_root_history —
 *                       no named-domain column exists in any global
 *                       structure.
 *   v2_domain_heads     domain_id PK · head (89-byte S2 canonical
 *                       encoding, dna_v2_domain_head_encode) ·
 *                       domain_height + last_updated_global mirrors
 *                       (validated against the blob on every read)
 *   v2_domain_updates   (global_height, domain_id) PK · upd (358-byte
 *                       canonical DomainUpdate v1) · upd_hash (64)
 *   v2_root_history     (domain_id, domain_height) PK · global_height ·
 *                       state_root · upd_hash · ruleset_version ·
 *                       ruleset_hash — append-only under commits
 *   v2_tx_index         (global_height, global_index) PK · tx_id UNIQUE
 *                       (the FULL-WIRE identity — env_preflight wire_id;
 *                       the column name is the frozen S5 shape) ·
 *                       owner_domain (DNA_TX_OWNER_NONE sentinel when a
 *                       cross-domain tx has no single owner — never NULL)
 *                       · touched (canonical list: count u16 BE + u32 BE
 *                       ids strictly ascending) · wire_version
 *   v2_tx_local_index   (domain_id, domain_height, local_index) PK ·
 *                       (tx_id, domain_id) UNIQUE — tx_id is the
 *                       FULL-WIRE identity here too
 *   v2_intent_index     intent_id PK (64, the canonical WITNESS-
 *                       INDEPENDENT semantic identity, dna_env_intent_id)
 *                       · tx_id UNIQUE (64, the ONE accepted full-wire
 *                       realization) · global_height · global_index —
 *                       S8, the semantic replay backstop
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

/** The S6 schema version. */
#define NODUS_V2_SCHEMA_VERSION_S6  6u

/** The S7 schema version. */
#define NODUS_V2_SCHEMA_VERSION_S7  7u

/** The S8 schema version (intent season). */
#define NODUS_V2_SCHEMA_VERSION_S8  8u

/**
 * The O14 schema version (block-identity season) — required by the apply
 * engine/genesis.
 *
 * ADDS `v2_blocks.header BLOB NOT NULL`: the canonical 413-byte
 * BlockHeader v3 the engine built from LOCALLY DERIVED results. Before
 * O14 the row carried only the decomposed commitment columns, which
 * CANNOT reconstruct the header — `header_version`, `chain_id`,
 * `proposer_id` and `timestamp` were nowhere in the table, and three of
 * those four are inside the 405 BlockID-bound bytes. Storing the exact
 * bytes is what makes "the stored header reproduces the same BlockID
 * after restart" a checkable property rather than an assumption.
 *
 * FAILS CLOSED (pre-BEGIN) on a POPULATED `v2_blocks`, exactly as S8
 * refuses a populated `v2_tx_index` and for the same reason: a committed
 * block's header bytes cannot be back-derived from the columns that were
 * kept, so migrating anyway would leave rows whose stored identity
 * nothing can re-verify. No live chain carries V2 rows (the surface is
 * inactive; the devnet reset starts fresh), so refusal is the honest
 * answer rather than a NULL hole in the identity chain.
 */
#define NODUS_V2_SCHEMA_VERSION_S9  9u

/** Deterministic fault-injection stages for the migration tests. */
typedef enum {
    V2MIG_FAIL_NONE = 0,
    V2MIG_FAIL_AFTER_BEGIN,       /* after BEGIN, before any DDL          */
    V2MIG_FAIL_AFTER_TABLES,      /* six tables created                   */
    V2MIG_FAIL_AFTER_ALTER,       /* utxo_set.domain_id added             */
    V2MIG_FAIL_AFTER_VERIFY,      /* schema verification passed           */
    V2MIG_FAIL_BEFORE_COMMIT,     /* user_version written, pre-COMMIT     */
    /* O15B §9 — APPENDED, deliberately not inserted after AFTER_BEGIN
     * where it happens in execution order: the values above are pinned by
     * shipped tests, and renumbering them to make the enum read
     * chronologically would silently re-target every existing fault case. */
    V2MIG_FAIL_AFTER_REVALIDATE   /* in-transaction version re-read passed */
} nodus_v2_mig_fail_t;

/** Deterministic fault-injection stages for the S6 migration tests
 *  (the 5 → 6 transaction only — the embedded S5 stage has its own). */
typedef enum {
    V2S6MIG_FAIL_NONE = 0,
    V2S6MIG_FAIL_AFTER_BEGIN,     /* after BEGIN, before any DDL          */
    V2S6MIG_FAIL_AFTER_TABLES,    /* three S6 tables created              */
    V2S6MIG_FAIL_AFTER_VERIFY,    /* schema verification passed           */
    V2S6MIG_FAIL_BEFORE_COMMIT,   /* user_version written, pre-COMMIT     */
    V2S6MIG_FAIL_AFTER_REVALIDATE /* O15B: in-txn version re-read passed  */
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

/** Deterministic fault-injection stages for the S7 migration tests
 *  (the 6 → 7 transaction only — earlier stages have their own). */
typedef enum {
    V2S7MIG_FAIL_NONE = 0,
    V2S7MIG_FAIL_AFTER_BEGIN,     /* after BEGIN, before any DDL          */
    V2S7MIG_FAIL_AFTER_TABLES,    /* four S7 tables created               */
    V2S7MIG_FAIL_AFTER_VERIFY,    /* schema-shape verification passed     */
    V2S7MIG_FAIL_BEFORE_COMMIT,   /* user_version written, pre-COMMIT     */
    V2S7MIG_FAIL_AFTER_REVALIDATE /* O15B: in-txn version re-read passed  */
} nodus_v2s7_mig_fail_t;

/**
 * Atomic S7 migration (header contract above). Version 0/5 runs the S6
 * migration chain first (its own atomic transactions), then 6 → 7
 * atomically.
 * @return 0 migrated or already at version 7 (idempotent);
 *         -1 failure (full rollback of the running stage) — including
 *         an UNKNOWN user_version (neither 0, 5, 6 nor 7): fail closed.
 */
int nodus_witness_db_migrate_v2s7(nodus_witness_t *w);

/** Test variant: abort deterministically at `fail_at` inside the 6 → 7
 *  transaction (rolls back, -1; the DB stays a valid version-6 schema). */
int nodus_witness_db_migrate_v2s7_ex(nodus_witness_t *w,
                                     nodus_v2s7_mig_fail_t fail_at);

/** Deterministic fault-injection stages for the S8 migration tests
 *  (the 7 → 8 transaction only — earlier stages have their own). */
typedef enum {
    V2S8MIG_FAIL_NONE = 0,
    V2S8MIG_FAIL_AFTER_BEGIN,     /* after BEGIN, before any DDL          */
    V2S8MIG_FAIL_AFTER_TABLES,    /* v2_intent_index created              */
    V2S8MIG_FAIL_AFTER_VERIFY,    /* schema-shape verification passed     */
    V2S8MIG_FAIL_BEFORE_COMMIT,   /* user_version written, pre-COMMIT     */
    /* O15B §9 — fires after BOTH in-transaction re-checks: the schema
     * version AND the populated-`v2_tx_index` refusal, which used to run
     * pre-BEGIN where a concurrent commit could slip past it. */
    V2S8MIG_FAIL_AFTER_REVALIDATE
} nodus_v2s8_mig_fail_t;

/**
 * Atomic S8 migration (intent season). Version 0/5/6 runs the S7
 * migration chain first (its own atomic transactions), then 7 → 8
 * atomically: create v2_intent_index (intent_id BLOB PK — the canonical
 * witness-independent identity; tx_id BLOB UNIQUE — the ONE accepted
 * full-wire realization; global_height; global_index), verify the exact
 * column shape, set user_version = 8.
 *
 * FAILS CLOSED (pre-BEGIN, read-only) on a POPULATED v2_tx_index: an
 * intent_id is derivable only from the original envelope bytes, which
 * the wire index does not store, so committed pre-S8 transactions cannot
 * be backfilled — migrating anyway would leave them silently unguarded
 * against semantic replay. No live chain carries V2 rows (inactive
 * surface; the devnet reset starts fresh).
 *
 * @return 0 migrated or already at version 8 (idempotent);
 *         -1 failure (full rollback of the running stage) — including an
 *         UNKNOWN user_version (neither 0, 5, 6, 7 nor 8) and the
 *         populated-wire-index refusal above: fail closed.
 */
int nodus_witness_db_migrate_v2s8(nodus_witness_t *w);

/** Test variant: abort deterministically at `fail_at` inside the 7 → 8
 *  transaction (rolls back, -1; the DB stays a valid version-7 schema). */
int nodus_witness_db_migrate_v2s8_ex(nodus_witness_t *w,
                                     nodus_v2s8_mig_fail_t fail_at);

/** Deterministic fault-injection stages for the O14 migration tests
 *  (the 8 → 9 transaction only — earlier stages have their own). */
typedef enum {
    V2S9MIG_FAIL_NONE = 0,
    V2S9MIG_FAIL_AFTER_BEGIN,     /* after BEGIN, before any DDL          */
    V2S9MIG_FAIL_AFTER_REVALIDATE,/* O15A: in-transaction re-validation
                                   * passed, still before any mutation —
                                   * the point that proves the protected
                                   * snapshot was taken and nothing has
                                   * been dropped yet                     */
    V2S9MIG_FAIL_AFTER_TABLES,    /* v2_blocks rebuilt with `header`      */
    V2S9MIG_FAIL_AFTER_VERIFY,    /* schema-shape verification passed     */
    V2S9MIG_FAIL_BEFORE_COMMIT    /* user_version written, pre-COMMIT     */
} nodus_v2s9_mig_fail_t;

/**
 * Atomic O14 migration (block-identity season). Version 0/5/6/7 runs the
 * S8 migration chain first (its own atomic transactions), then 8 → 9
 * atomically: rebuild `v2_blocks` carrying the new `header BLOB NOT NULL`
 * column, verify the exact column shape, set user_version = 9.
 *
 * The table is REBUILT rather than ALTERed because the column is
 * NOT NULL and SQLite cannot add a NOT NULL column without a default —
 * and a defaulted header would be exactly the silent hole this column
 * exists to close. The rebuild is safe precisely because the migration
 * refuses to run on a populated table.
 *
 * FAILS CLOSED (pre-BEGIN, read-only) on a POPULATED v2_blocks: the
 * canonical header bytes of an already-committed block cannot be
 * reconstructed from the decomposed columns (proposer_id and timestamp
 * were never stored, and proposer_id is BlockID-bound), so a backfill
 * would have to invent them.
 *
 * @return 0 migrated or already at version 9 (idempotent);
 *         -1 failure (full rollback of the running stage) — including an
 *         UNKNOWN user_version and the populated-blocks refusal above.
 */
int nodus_witness_db_migrate_v2s9(nodus_witness_t *w);

/** Test variant: abort deterministically at `fail_at` inside the 8 → 9
 *  transaction (rolls back, -1; the DB stays a valid version-8 schema). */
int nodus_witness_db_migrate_v2s9_ex(nodus_witness_t *w,
                                     nodus_v2s9_mig_fail_t fail_at);

/* ── S10 migration (O15C — activation authority; now an EMPTY RUNG) ────
 *
 * O15C added the two activation-authority tables here (`v2_activation`
 * singleton + `v2_activation_readiness`, DDL single-sourced from the
 * activation module). O15J Faz 3 deleted the activation ceremony and
 * both tables with it, so THIS STAGE CREATES NO TABLE: it only advances
 * user_version 9 → 10.
 *
 * The rung is kept rather than collapsed, and that is a deliberate
 * choice, not inertia. The ladder is a chain of EXACT predecessors — S11
 * refuses any version but 10, and the pure-V2 builder climbs to S12
 * through it — and version-10 databases exist. Renumbering the ladder to
 * close the gap would invalidate every rung above it for no gain, and a
 * schema version is a permanent identifier of a shape, not a counter.
 *
 * Still purely ADDITIVE (it now adds nothing), so there is no
 * populated-data refusal. Version 11+ fails closed. */
#define NODUS_V2_SCHEMA_VERSION_S10  10u

/* The two mid-stage injection points are RETAINED at their numbers even
 * though the steps they named are gone: removing them would renumber
 * V2S10MIG_FAIL_BEFORE_COMMIT, silently repointing any caller that
 * passes it. They now abort a stage that writes only the version. */
typedef enum {
    V2S10MIG_FAIL_NONE = 0,
    V2S10MIG_FAIL_AFTER_BEGIN,      /* after BEGIN, before any DDL        */
    V2S10MIG_FAIL_AFTER_REVALIDATE, /* in-txn version re-read passed      */
    V2S10MIG_FAIL_AFTER_TABLES,     /* RETIRED step — no table is created */
    V2S10MIG_FAIL_AFTER_VERIFY,     /* RETIRED step — nothing to verify   */
    V2S10MIG_FAIL_BEFORE_COMMIT     /* user_version written, pre-COMMIT   */
} nodus_v2s10_mig_fail_t;

/** Atomic 9 → 10 version bump. Version 0/5/6/7/8 runs the S9 chain
 *  first, then 9 → 10 atomically with the O15B in-transaction
 *  revalidation. Creates no table since O15J Faz 3.
 *  @return 0 migrated or already at 10 (idempotent); -1 failure. */
int nodus_witness_db_migrate_v2s10(nodus_witness_t *w);

/** Test variant: deterministic abort inside the 9 → 10 transaction. */
int nodus_witness_db_migrate_v2s10_ex(nodus_witness_t *w,
                                      nodus_v2s10_mig_fail_t fail_at);

/* ── S11 migration (O15E Faz B — canonical envelope availability) ─────
 *
 * Adds `v2_tx_bytes`: the canonical envelope WIRE bytes of every
 * transaction the apply engine commits from S11 onward, written inside
 * the block's ONE transaction (apply.c phase 12) — the byte material a
 * peer needs to re-verify and re-apply the block (BlockMessage v1
 * assembly: stored header + stored QC + these bytes).
 *
 * Purely ADDITIVE — no table is dropped or rebuilt, so there is no
 * populated-data refusal. Blocks committed BEFORE this migration have
 * no rows here and CANNOT be backfilled (the engine never persisted
 * their input bytes — apply.h labels reconstruction "a sync concern
 * ... deliberately out of scope"); serving such heights FAILS CLOSED.
 * Version 12+ fails closed. */
#define NODUS_V2_SCHEMA_VERSION_S11  11u

typedef enum {
    V2S11MIG_FAIL_NONE = 0,
    V2S11MIG_FAIL_AFTER_BEGIN,      /* after BEGIN, before any DDL        */
    V2S11MIG_FAIL_AFTER_REVALIDATE, /* in-txn version re-read passed      */
    V2S11MIG_FAIL_AFTER_TABLES,     /* v2_tx_bytes created                */
    V2S11MIG_FAIL_AFTER_VERIFY,     /* schema-shape verification passed   */
    V2S11MIG_FAIL_BEFORE_COMMIT     /* user_version written, pre-COMMIT   */
} nodus_v2s11_mig_fail_t;

/** Atomic O15E migration. Versions below 10 run the S9+S10 chain
 *  first, then 10 → 11 atomically with the in-transaction
 *  revalidation. @return 0 migrated or already at 11 (idempotent);
 *  -1 failure. */
int nodus_witness_db_migrate_v2s11(nodus_witness_t *w);

/** Test variant: deterministic abort inside the 10 → 11 transaction. */
int nodus_witness_db_migrate_v2s11_ex(nodus_witness_t *w,
                                      nodus_v2s11_mig_fail_t fail_at);

/* ── S12 migration (O15F Task 4): per-block canonical claim bytes ─────
 *
 * Adds TWO tables recording every committed block's applied claims:
 *
 *   v2_claim_bytes   the canonical dna_claim_encode WIRE bytes of every
 *                    claim the apply engine commits from S12 onward,
 *                    written inside the block's ONE apply transaction
 *                    (apply.c phase 12c) in block claim order — the byte
 *                    material a peer needs to re-verify and re-apply the
 *                    claim (the SAME canonical bytes admission verified).
 *   v2_claim_counts  one row per COMMITTED block (claims or not) carrying
 *                    the block's claim count. The count row is what lets a
 *                    serving seam distinguish "this block had zero claims"
 *                    from "this height predates S12" — the latter fails
 *                    closed (no row), the former serves an empty claim set.
 *
 * Purely ADDITIVE — no table is dropped or rebuilt, so there is no
 * populated-data refusal. Blocks committed BEFORE this migration have no
 * rows here and CANNOT be backfilled (the engine never persisted their
 * claim input bytes — apply.h labels claim reconstruction "a sync concern
 * ... deliberately out of scope"); serving such heights FAILS CLOSED.
 * Version 13+ fails closed. */
#define NODUS_V2_SCHEMA_VERSION_S12  12u

typedef enum {
    V2S12MIG_FAIL_NONE = 0,
    V2S12MIG_FAIL_AFTER_BEGIN,      /* after BEGIN, before any DDL        */
    V2S12MIG_FAIL_AFTER_REVALIDATE, /* in-txn version re-read passed      */
    V2S12MIG_FAIL_AFTER_TABLES,     /* both claim tables created          */
    V2S12MIG_FAIL_AFTER_VERIFY,     /* schema-shape verification passed   */
    V2S12MIG_FAIL_BEFORE_COMMIT     /* user_version written, pre-COMMIT   */
} nodus_v2s12_mig_fail_t;

/** Atomic O15F migration. Versions below 11 run the S9+S10+S11 chain
 *  first, then 11 → 12 atomically with the in-transaction
 *  revalidation. @return 0 migrated or already at 12 (idempotent);
 *  -1 failure (full rollback of the running stage) — including an
 *  UNKNOWN user_version (13+): fail closed. */
int nodus_witness_db_migrate_v2s12(nodus_witness_t *w);

/** Test variant: deterministic abort inside the 11 → 12 transaction. */
int nodus_witness_db_migrate_v2s12_ex(nodus_witness_t *w,
                                      nodus_v2s12_mig_fail_t fail_at);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SCHEMA_H */
