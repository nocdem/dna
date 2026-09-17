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
 * ⚠ APPENDING AN ID IS NOT THE SAME AS APPENDING ITS CHECK.
 * `NODUS_V2_PF_INGRESS_ENABLED` (13) is computed from
 * `out->n_issues == 0` sampled at its own check site, so that check MUST
 * remain the LAST one in `nodus_witness_v2_preflight()`. A new issue whose
 * *check* is placed after it would be invisible to that sample, and an
 * armed node with authority and only the new issue outstanding would
 * compute "the gate would be open" and silently fail to raise 13 — the
 * exact state 13 exists to flag. Add the ENUM VALUE at the end; add the
 * CHECK before the ingress block. Review R2 raised this drift hazard.
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
    /**
     * No committed genesis to activate against.
     *
     * R3 W3 (D-17 rev 10 (8)): a version-3 chain writes no height-0
     * `v2_blocks` row (D-19 rev 6 withdrew the genesis block), so this is
     * now raised when the stored genesis DOCUMENT itself — the
     * "genesisDoc" row in `cmt_state`, the reference's own key
     * (node/setup.go:551) — is absent. Probed directly, before the
     * canonical-strict reader runs, so this id keeps meaning "nothing was
     * ever written" and never overlaps with id 4's "something was written
     * and it is wrong".
     */
    NODUS_V2_PF_GENESIS_ABSENT                = 3,
    /**
     * The committed genesis is malformed.
     *
     * R3 W3 (D-17 rev 10 (8)): raised when the "genesisDoc" row IS present
     * but `nodus_witness_v2_gen_stored_doc`'s canonical-strict reader
     * refuses it — any of its four checks (strict decode, the shared
     * genesis content rules, canonical form, or the stored `chain_id`
     * field hashing to the document) failing collapses to this one id.
     * The four are load-bearing individually inside the reader (see its
     * doc comment for why none subsumes another); this preflight does not
     * need to tell them apart, because every one of them means the same
     * thing here — this database's genesis identity cannot be trusted.
     */
    NODUS_V2_PF_GENESIS_MALFORMED             = 4,
    /** A committed genesis exists but its genesis manifest does not. */
    NODUS_V2_PF_GENESIS_MANIFEST_ABSENT       = 5,
    /**
     * RETIRED VALUE — kept for id stability, NEVER RAISED under the R3 W3
     * live flip (D-17 rev 10 (8)).
     *
     * Before the flip this meant "the stored genesis header does not
     * reproduce the stored BlockID" — a version-2 concept with no
     * version-3 equivalent (there is no header or BlockID at height 0 any
     * more, D-19 rev 6). The nearest version-3 question — "does the
     * genesis's own claimed identity field match what genesis actually
     * produced?" — is a DIFFERENT id, not a reinterpretation of this one:
     * `NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH` (17), appended rather than
     * reusing this value, because "never renumber, never reuse" (this
     * header's own rule) means an id's MEANING is pinned as tightly as its
     * number — tooling that logged this id under its old meaning must not
     * silently start seeing it mean something else.
     */
    NODUS_V2_PF_GENESIS_IDENTITY_MISMATCH     = 6,
    /**
     * RETIRED VALUE — kept for id stability, NEVER RAISED under the R3 W3
     * live flip (D-17 rev 10 (8)).
     *
     * Before the flip, a genesis identity was derived from the committed
     * height-0 `v2_blocks` row and its header, and this id covered the
     * case where that derivation itself failed while the row was present
     * and well-shaped. Since D-19 rev 6 withdrew the genesis block, a
     * version-3 chain has no such row (`nodus_witness_v2_genesis_cmt`
     * writes none), and this build accepts version-3 chains only
     * (NODUS_V2_PF_SCHEMA_UNSUPPORTED, S14 alone). The genesis identity is
     * now the stored genesis DOCUMENT, read through ONE canonical-strict
     * accessor (`nodus_witness_v2_gen_stored_doc`) whose only failure
     * modes are "no row" (id 3) and "the row fails one of the four
     * checks" (id 4) — there is no longer a distinguishable third state
     * of "the row is there, is shaped correctly, but the id could not be
     * resolved". The check is deleted, the id is not reused.
     */
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
     * RETIRED VALUE — kept for id stability, NEVER RAISED since O15C.
     *
     * O15A raised this UNCONDITIONALLY because Ledger V2 had no producer
     * for `last_signed_block`: enforcing Rule N without its writer would
     * freeze the watermark and walk the validator set down, and inventing
     * an attendance oracle is forbidden. O15C supplied the real source:
     * the V2 apply engine credits the committed header proposer inside
     * the block transaction, before root computation
     * (nodus_witness_v2_record_attendance), and the V2 epoch boundary
     * runs the transplanted leader-blame settlement
     * (nodus_witness_v2_epoch.c). With the writer in this build, the
     * obligation the unconditional raise stood for is DISCHARGED — the
     * check is deleted, the id is not reused.
     */
    NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT = 12,
    /** V2 external ingress is reachable — activation must not proceed. */
    NODUS_V2_PF_INGRESS_ENABLED               = 13,
    /** A read failed; readiness is UNKNOWN, which is not readiness. */
    NODUS_V2_PF_INSPECTION_FAULT              = 14,
    /**
     * RETIRED VALUE — kept for id stability, NEVER RAISED since O15J.
     *
     * O15C raised this when a committed activation record existed but was
     * malformed (unknown record_version / state, wrong blob widths): a
     * committed authority this binary could not interpret had to stop it
     * rather than be silently ignored. O15J Faz 3 deleted the activation
     * ceremony — no table stores an activation record, no transaction
     * writes one and no build reads one — so the condition cannot arise.
     * The check is deleted, the id is not reused.
     */
    NODUS_V2_PF_ACTIVATION_AUTHORITY_MALFORMED = 15,
    /**
     * RETIRED VALUE — kept for id stability, NEVER RAISED since O15J.
     *
     * O15C raised this when the committed activation target digest D
     * differed from the build's compiled target (ruleset tuples / header
     * version / schema version): the chain had scheduled a runtime this
     * binary was not, so the node had to stay out of the activation.
     * O15J Faz 3 deleted the ceremony, and with it both the committed
     * target and the compiled one. The check is deleted, the id is not
     * reused.
     */
    NODUS_V2_PF_TARGET_MISMATCH               = 16,
    /**
     * R3 W3 (D-17 rev 10 (8)), NEW: the stored genesis document's
     * `app_hash` field (D-19 rev 6 (1): AppHash carries the ledger's
     * global state root) does not equal the app hash the chain actually
     * started from. HEIGHT-AWARE (delta 8 fix, live defect found by the
     * Genesis Protocol harness at production constants): while the chain
     * has committed no block yet (`v2_blocks` empty), that is
     * `nodus_witness_v2_committed_global_root()` — the ledger's CURRENT
     * committed root, recomputed from the committed DomainHeads exactly
     * as `nodus_witness_v2_genesis_cmt` composed them, since there is no
     * block row to read it back from yet. From the FIRST committed block
     * on, the current root is no longer the genesis one (this ledger's
     * global root changes at every block — Rule N attendance), so the
     * comparison target becomes block 1's header `AppHash`, read from
     * the Comet blockstore: cometbft @709fd12b `state/state.go`
     * `MakeGenesisState` sets it from the genesis document and
     * `state/validation.go` `validateBlock` requires every block's
     * `AppHash` to equal the running `state.AppHash`, so block 1's header
     * carries the genesis app hash for the life of the chain, certified
     * by +2/3 of the committee that decided it. Either way, a mismatch
     * means the manifest this database actually applied is not the one
     * the document's `app_hash` was computed against — the check's
     * MEANING is unchanged; only which committed fact it reads to answer
     * it depends on height.
     */
    NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH     = 17
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
