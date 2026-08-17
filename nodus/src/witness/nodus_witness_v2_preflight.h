/**
 * @file nodus/src/witness/nodus_witness_v2_preflight.h
 * @brief Ledger V2 O15A — deterministic, read-only activation-readiness
 *        preflight.
 *
 * INACTIVE, AND IT KEEPS IT THAT WAY. This module answers one question —
 * "could Ledger V2 be activated on this database?" — and is structurally
 * incapable of acting on the answer. It NEVER activates V2, never writes
 * an activation height, never opens ingress, and never modifies state to
 * make a check pass.
 *
 * CALLERS: NONE in production today — this is deliberately stated rather
 * than implied. Nothing under `nodus/src` calls
 * `nodus_witness_v2_preflight`; its only callers are its tests. It is
 * compiled into libnodus so the activation season can wire it, and so
 * that its contract and its tests exist BEFORE anything depends on the
 * answer. An earlier draft of this comment claimed "its only production
 * entry is a local call at database open" — that was simply untrue, and
 * a reader would have taken the gate for something already running.
 *
 * ── WHY IT IS READ-ONLY, AND WHY THAT IS TESTABLE ─────────────────────
 * A readiness check that can repair what it inspects is not a readiness
 * check — it is a migration with an opinion. Keeping it read-only means
 * "the answer was yes" and "the database was left alone" are the same
 * fact, and the test proves it the only way that means anything: by
 * comparing a whole-database digest across the call.
 *
 * ── DETERMINISM ───────────────────────────────────────────────────────
 * Issues are reported in CANONICAL ORDER — ascending issue id, which is
 * the declaration order below — not in discovery order, so two nodes
 * inspecting identical databases produce byte-identical reports, and a
 * report is stable across restarts. No wall-clock time is read. The
 * preflight does NOT stop at the first problem: an operator needs the
 * whole list, and hiding later issues behind the first turns readiness
 * into a guessing game.
 *
 * ── ISSUE IDS ARE STABLE ──────────────────────────────────────────────
 * The numeric values are part of the contract: tooling and tests pin
 * them. Append new issues at the end; never renumber, never reuse.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_PREFLIGHT_H
#define NODUS_WITNESS_V2_PREFLIGHT_H

#include <stdint.h>
#include <stddef.h>

#include "witness/nodus_witness.h"

/**
 * One reason Ledger V2 must not be activated on this database.
 *
 * Ordering is the report's canonical order. Values are STABLE.
 */
typedef enum {
    /** Schema is not the exact version this build activates on. */
    NODUS_V2_PF_SCHEMA_UNSUPPORTED            = 1,
    /** A required v2_* table is missing or has drifted from its shape. */
    NODUS_V2_PF_SCHEMA_SHAPE_DRIFT            = 2,
    /** No committed genesis block — nothing to activate against. */
    NODUS_V2_PF_GENESIS_ABSENT                = 3,
    /** The committed genesis row is malformed (bad id/header width). */
    NODUS_V2_PF_GENESIS_MALFORMED             = 4,
    /** A committed genesis exists but its genesis manifest does not. */
    NODUS_V2_PF_GENESIS_MANIFEST_ABSENT       = 5,
    /** The stored genesis header does not reproduce the stored BlockID. */
    NODUS_V2_PF_GENESIS_IDENTITY_MISMATCH     = 6,
    /** The V2 chain id cannot be derived from committed state. */
    NODUS_V2_PF_CHAIN_ID_UNRESOLVABLE         = 7,
    /**
     * The chain id this witness handle is running under disagrees with
     * the one derived from committed genesis. The handle's value comes
     * from the database FILENAME; committed state is authoritative, and
     * two disagreeing authorities is exactly what must not be activated.
     */
    NODUS_V2_PF_CHAIN_ID_DISAGREEMENT         = 8,
    /** No committed validator-set snapshot governs epoch 0. */
    NODUS_V2_PF_VSET_SNAPSHOT_ABSENT          = 9,
    /** A committed snapshot exists but fails hash/decode verification. */
    NODUS_V2_PF_VSET_SNAPSHOT_INVALID         = 10,
    /** DNAC supply conservation does not hold over committed state. */
    NODUS_V2_PF_SUPPLY_INCONSISTENT           = 11,
    /**
     * Rule N (liveness / AUTO_RETIRED) has no attendance source under
     * Ledger V2. `last_signed_block` is written EXCLUSIVELY by the legacy
     * BFT commit path, so on a V2-only chain the watermark would freeze,
     * the blamed leader would be charged a miss at every boundary, the
     * reset would never fire, and validators would be auto-retired for
     * being unable to prove liveness the engine cannot observe. Both
     * counters are validators-merkle-leaf fields, so this is committed
     * consensus state, not bookkeeping.
     *
     * O15A deliberately does NOT enforce Rule N in the V2 boundary —
     * inventing an attendance oracle is the class of fabrication this
     * tree forbids. Instead the obligation is made structurally
     * fail-closed here: while this issue stands, the preflight can never
     * report ready, so V2 cannot be activated with the rule unenforceable.
     */
    NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT = 12,
    /** V2 external ingress is reachable — activation must not proceed. */
    NODUS_V2_PF_INGRESS_ENABLED               = 13,
    /** A read failed; readiness is UNKNOWN, which is not readiness. */
    NODUS_V2_PF_INSPECTION_FAULT              = 14
} nodus_v2_pf_issue_t;

/** Upper bound on distinct issues (one slot per id above). */
#define NODUS_V2_PF_MAX_ISSUES 32

typedef struct {
    /** Issues in canonical (ascending id) order; no duplicates. */
    nodus_v2_pf_issue_t issues[NODUS_V2_PF_MAX_ISSUES];
    size_t              n_issues;
    /**
     * 1 only when n_issues == 0. Deliberately not a separate judgement:
     * "ready" is defined as "nothing was found", so a check that is added
     * later cannot be accidentally excluded from the verdict.
     */
    int                 ready;
} nodus_v2_preflight_report_t;

/**
 * Inspect `w`'s database and report every reason Ledger V2 must not be
 * activated on it.
 *
 * READ-ONLY. Performs no writes, takes no write lock, reads no clock,
 * accepts no caller-supplied roots or authority, and cannot activate
 * anything. Running it twice on an unchanged database yields byte-
 * identical reports.
 *
 * @param w   witness handle with an open database.
 * @param out [out] the report; fully zeroed before use.
 * @return 0 when the inspection completed (whether or not it found
 *         issues — check `out->ready`), -1 when the inspection itself
 *         could not be performed (NULL args, no database). A -1 is NOT
 *         "ready"; it is the absence of an answer.
 */
int nodus_witness_v2_preflight(nodus_witness_t *w,
                               nodus_v2_preflight_report_t *out);

/** Stable human-readable name for an issue id (never NULL). */
const char *nodus_witness_v2_preflight_issue_name(nodus_v2_pf_issue_t id);

#endif /* NODUS_WITNESS_V2_PREFLIGHT_H */
