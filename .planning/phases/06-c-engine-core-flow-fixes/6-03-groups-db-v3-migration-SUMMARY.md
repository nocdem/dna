---
phase: 6
plan: 3
subsystem: c-engine / groups database
tags: [groups, sqlite, migration, dht-salt, CORE-04]
requires: [6-01]
provides:
  - groups.db schema v3 with dht_salt + has_dht_salt columns
  - group_database_{has,get,set}_dht_salt accessors
  - foundation for plan 6-04 group outbox salt hard cutover
affects:
  - messenger/messenger/group_database.c
  - messenger/messenger/group_database.h
  - messenger/include/dna/version.h
  - messenger/docs/MESSAGE_SYSTEM.md
tech-stack:
  added: []
  patterns:
    - "Versioned ALTER TABLE migration chain (v1->v2->v3)"
    - "Per-entity 32-byte DHT salt storage mirroring contacts_db"
key-files:
  created: []
  modified:
    - messenger/messenger/group_database.c
    - messenger/messenger/group_database.h
    - messenger/include/dna/version.h
    - messenger/docs/MESSAGE_SYSTEM.md
key-decisions:
  - "Migration chain uses ALTER TABLE ADD COLUMN only (RC project, no DROP/recreate)"
  - "Accessors mirror contacts_db_{set,get}_salt shape so plan 04 has the same mental model"
  - "has_dht_salt is a separate INTEGER flag (not NULL-blob inference) to match contacts pattern"
  - "Migration chain explicitly bumps schema_version in-memory so v1 dbs flow v1->v2->v3 in one init"
requirements-completed: [CORE-04]
duration: "~15 min"
completed: 2026-04-14
---

# Phase 6 Plan 3: groups.db v3 migration Summary

Added `dht_salt BLOB` and `has_dht_salt INTEGER` columns to `groups.db` via a v2→v3 schema migration plus three accessor functions, unblocking plan 6-04's group outbox salt hard cutover.

## Scope

- Schema: `CREATE TABLE groups` gains two columns, `SCHEMA_SQL` metadata version bumped to `'3'`.
- Migration: `MIGRATION_V2_TO_V3` runs after `MIGRATION_V1_TO_V2` so a v1 database flows through both passes in a single init. Idempotent — re-running init on a v3 database is a no-op.
- API: `group_database_has_dht_salt`, `group_database_get_dht_salt`, `group_database_set_dht_salt` added to `group_database.h`, implemented in `group_database.c` using the singleton `g_instance->db` handle (same pattern as `group_database_get_stats`).
- Docs: `MESSAGE_SYSTEM.md` §10.5 updated with the v3 columns and a CORE-04 paragraph.
- Version: `DNA_VERSION_PATCH` 194 → 195 (C library only).

## Execution

| Task | Description | Commit |
| ---- | ----------- | ------ |
| 1 | v2→v3 migration + SCHEMA_SQL update + 3 accessor functions | `fdeceea9` |
| 2 | Version bump + MESSAGE_SYSTEM.md docs update | `dc7a8ae6` |

## Verification

- `cd messenger/build && make -j$(nproc)` — 0 warnings, 0 errors.
- `ctest -R '^test_group_database_migration_v3$'` — **PASS** (3.17s). RED → GREEN as required.
- `ctest -R group` — `test_group_database_migration_v3` PASS; `test_group_channel` PASS; `test_group_outbox_make_key_salted` remains RED by design (plan 6-04 RED guard, `#if 0` block, not in scope here).
- Acceptance criteria all verified on disk:
  - `MIGRATION_V2_TO_V3` string present in `group_database.c`
  - `ADD COLUMN dht_salt BLOB` + `ADD COLUMN has_dht_salt INTEGER` present
  - `UPDATE metadata SET value = '3'` present
  - Header declares all three accessors
  - `MESSAGE_SYSTEM.md`: 6 occurrences of `dht_salt`, 6 occurrences of `v3`/`Schema version 3`
  - `DNA_VERSION_PATCH` = 195 (previous value 194 from plan 6-02)

## Key Decisions

- **No mutex added.** `group_database.c` has no dedicated mutex today — it shares the sqlite3 handle across modules and relies on `sqlite3_busy_timeout(5000)` + SQLite's serialized threading mode set at open. The three new accessors follow the same pattern as `group_database_get_stats`. If plan 6-04 finds this insufficient under contention, that's a separate concurrency refactor, not a migration concern.
- **`has_dht_salt` as explicit INTEGER flag.** The plan called for this and it matches the `contacts_db` shape. Relying on `dht_salt IS NULL` would work today but forces every caller to handle NULL semantics rather than a boolean. Explicit flag is easier to reason about and matches the DM salt reference implementation.
- **Migration chain reuses the lenient error path** from v1→v2 — if `ALTER TABLE` fails because a column already exists, fall back to `UPDATE metadata SET value='3'`. Matches existing resilience idiom.
- **`schema_version = 3` after v2->v3 block** — mirrors the v1->v2 bump I added so future v3->v4 work in later phases can just drop another `if (schema_version == 3)` block without re-reading from the db.

## Deviations from Plan

### Auto-fixed

**1. [Rule 1 - Bug] Migration chain did not update `schema_version` between passes**

- **Found during:** Task 1
- **Issue:** The existing v1->v2 migration block did not set `schema_version = 2` after running, so a v2->v3 block gated on `schema_version == 2` would be skipped for a database that was just v1.
- **Fix:** Added `schema_version = 2;` at the end of the v1->v2 block and `schema_version = 3;` at the end of the v2->v3 block so a v1 database correctly chains through both migrations in a single `group_database_init` call.
- **Files modified:** `messenger/messenger/group_database.c`
- **Verification:** Fresh init test path in `test_group_database_migration_v3` exercises both flows (pre-populated v2 and fresh init) — both PASS.
- **Commit:** `fdeceea9`

### Out-of-scope / deferred

- **`test_gek_ratchet` build failure** — pre-existing (`implicit declaration of gek_hkdf_sha3_256`), reproduces on a clean stash. Not caused by this plan. Logged here rather than fixed to respect scope boundary.
- **`MESSENGER_SECURITY_AUDIT.md`** — plan instructions wanted an audit doc update for CORE-04, but root `CLAUDE.md` forbids committing `*AUDIT*.md` files (covered by `.gitignore`). Per executor instructions, skipped this specific doc and updated `MESSAGE_SYSTEM.md` instead (which is the authoritative groups schema doc).

**Total deviations:** 1 auto-fixed (Rule 1 bug — migration chain version tracking). **Impact:** Migration correctness for v1→v3 upgrade path. Zero user-visible impact but would have been a latent bug if left unfixed.

## Authentication Gates

None.

## Known Stubs

None. All new symbols are wired end-to-end with real SQLite calls; no placeholder data, no TODOs. Accessors are not yet *called* from anywhere — that's plan 6-04's job — but they are complete, not stubbed.

## Issues Encountered

None in scope. Pre-existing `test_gek_ratchet` build failure noted above is unrelated and pre-dates this plan.

## Self-Check: PASSED

- `[ -f messenger/messenger/group_database.c ]` — FOUND
- `[ -f messenger/messenger/group_database.h ]` — FOUND
- `[ -f messenger/include/dna/version.h ]` — FOUND
- `[ -f messenger/docs/MESSAGE_SYSTEM.md ]` — FOUND
- Commit `fdeceea9` — FOUND in `git log`
- Commit `dc7a8ae6` — FOUND in `git log`
- `MIGRATION_V2_TO_V3` present in `group_database.c` — confirmed
- `group_database_set_dht_salt` declared in header — confirmed
- `DNA_VERSION_PATCH 195` — confirmed
- `test_group_database_migration_v3` exit 0 — confirmed (3.17s)

Ready for plan 6-04 (group outbox salt hard cutover).
