/**
 * @file nodus/src/witness/nodus_witness_v2_gate.h
 * @brief Ledger V2 O15B — the ONE production activation gate.
 *
 * ═══ WHAT THIS FILE IS FOR ══════════════════════════════════════════════
 * O15B builds the whole V2 network surface — canonical wire, ingress
 * adapters, sync, recovery — and ships it PRODUCTION-DORMANT. This module
 * is what makes "dormant" a structural property instead of a promise.
 *
 * Every production path that would advertise, accept, propose, vote for,
 * finalize, sync or replay a Ledger V2 block asks exactly one question
 * here, and gets one of three answers. Two of them mean "do not proceed".
 *
 * ═══ WHY IT CAN NEVER OPEN IN THIS BUILD ════════════════════════════════
 * Opening requires BOTH conditions, and BOTH are absent:
 *
 *  1. COMMITTED ACTIVATION AUTHORITY — a rule, carried in committed chain
 *     state, that says Ledger V2 is active from some height. **No such
 *     mechanism exists in this tree.** The committed chain-config parameter
 *     space is `DNAC_CFG_MAX_TXS_PER_BLOCK`(1) ..
 *     `DNAC_CFG_TARGET_ACTIVE_COUNT`(4), and
 *     `DNAC_CFG_PARAM_MAX_ID == DNAC_CFG_TARGET_ACTIVE_COUNT`
 *     (dnac/include/dnac/dnac.h:323-327). There is no activation parameter,
 *     no `chain_def` activation field, and no activation table.
 *
 *     O15B deliberately does NOT add one. Choosing an activation mechanism
 *     is a governance decision about an RC chain — which parameter, which
 *     range, which grace class, how a mixed-version network converges — and
 *     inventing it inside an implementation season is exactly the
 *     fabrication this tree forbids. It is the named work of a separate
 *     authorized season (O15C).
 *
 *  2. PREFLIGHT READINESS — `nodus_witness_v2_preflight()` reporting zero
 *     issues. It raises `NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT`
 *     UNCONDITIONALLY (nodus_witness_v2_preflight.h:86-102), because Rule N
 *     has no attendance source under V2, so `ready` is structurally always
 *     0 on every database.
 *
 * Either one alone would keep the gate shut. Both hold. The gate is
 * therefore CLOSED on every database, in every configuration, always — and
 * that is a property of the source, provable by reading it, not a default
 * someone can flip.
 *
 * ═══ WHAT CANNOT OPEN IT ════════════════════════════════════════════════
 * By construction there is NO input through which any of these could:
 *
 *   - an environment variable          (nothing here reads getenv)
 *   - a command-line flag              (no parameter carries intent)
 *   - a local database bit             (authority is committed-chain-state
 *                                       only, and no such state exists)
 *   - an operator override / config    (no file is consulted)
 *   - a peer, a header, or a message   (no network value reaches this)
 *
 * `nodus_witness_v2_gate_state()` takes ONE argument, a witness handle, and
 * there is no second argument through which a caller could propose that the
 * lane is active. That is the same discipline
 * `nodus_witness_v2_qc_verify()` uses for validator authority: the absence
 * of a parameter is the guarantee.
 *
 * ═══ THE TEST-ONLY FIXTURE ══════════════════════════════════════════════
 * Component and end-to-end tests must be able to exercise the ARMED path —
 * otherwise the ingress, sync and recovery code would ship untested, which
 * is its own hazard. They do so through `nodus_witness_v2_gate_test_arm()`,
 * which is compiled ONLY when `NODUS_V2_TEST_AUTHORITY` is defined. That
 * macro is set exclusively on test targets in `nodus/CMakeLists.txt` and on
 * NO library or server target, so the symbol is ABSENT from libnodus and
 * from `nodus-server`. `test_v2_gate_linked` proves that absence against
 * the linked production binary with `nm`, rather than asserting it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_GATE_H
#define NODUS_WITNESS_V2_GATE_H

#include "witness/nodus_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Why the Ledger V2 lane is or is not active on this node.
 *
 * Ordered by how far the node got, and reported by the most fundamental
 * missing condition first: authority is checked before readiness, because
 * "there is no rule that could activate this" is a more basic answer than
 * "the rule exists but the database is not ready".
 */
typedef enum {
    /**
     * No committed activation authority exists. This is what this build
     * always returns; see the file comment. It is deliberately distinct
     * from NOT_READY so an operator can tell "this software cannot
     * activate V2 at all" from "this database is not ready yet".
     */
    NODUS_V2_GATE_NO_AUTHORITY = 0,
    /** Authority exists, but the preflight found blocking issues. */
    NODUS_V2_GATE_NOT_READY    = 1,
    /** Both conditions hold. Unreachable in this build. */
    NODUS_V2_GATE_OPEN         = 2,
    /**
     * The gate itself could not be evaluated (NULL handle, no database, a
     * read fault inside the preflight). Fail-closed and distinct: "we could
     * not tell" must never be silently reported as "not ready", because the
     * two call for different operator responses.
     */
    NODUS_V2_GATE_FAULT        = 3
} nodus_v2_gate_state_t;

/** Stable human-readable name for a gate state (never NULL). */
const char *nodus_witness_v2_gate_state_name(nodus_v2_gate_state_t s);

/**
 * Condition 1 alone: does committed activation authority exist?
 *
 * Exposed separately because it is the ONLY half of the gate that can be
 * evaluated without running the preflight — and the preflight itself needs
 * it, to compute issue 13, without calling back into
 * `nodus_witness_v2_gate_state()` and recursing forever. Splitting the two
 * conditions at the header is what keeps that impossible rather than
 * merely avoided.
 *
 * @return 1 if committed activation authority exists, 0 otherwise. Always
 *         0 in this build; see the file comment for why, and why O15B
 *         deliberately did not add one.
 */
int nodus_witness_v2_gate_authority_present(nodus_witness_t *w);

/**
 * Evaluate the activation gate.
 *
 * READ-ONLY: takes no write lock, writes no row, reads no clock, reads no
 * environment and reads no file. Deterministic — two nodes with identical
 * committed state get identical answers.
 *
 * @param w witness handle.
 * @return the gate state; NODUS_V2_GATE_FAULT when it could not be
 *         evaluated. NEVER NODUS_V2_GATE_OPEN in this build.
 */
nodus_v2_gate_state_t nodus_witness_v2_gate_state(nodus_witness_t *w);

/**
 * The one-line question every production V2 entrypoint asks first.
 *
 * @return 1 only when the gate is OPEN. 0 for NO_AUTHORITY, NOT_READY and
 *         FAULT alike — all three mean "do not proceed", and folding them
 *         here is safe precisely because the fold is one-directional
 *         (nothing becomes MORE permitted). Callers that must DISTINGUISH
 *         them for reporting use nodus_witness_v2_gate_state().
 */
int nodus_witness_v2_activation_permitted(nodus_witness_t *w);

/* ── Ingress reachability ────────────────────────────────────────────────
 *
 * Distinct from the gate, and the distinction is the point of O15B's
 * preflight issue 13.
 *
 * "Ingress is reachable" does NOT mean the ingress code was compiled — that
 * is true in every build from this season onward and says nothing. It means
 * this running node has ARMED the V2 message handlers, so a V2 frame
 * arriving on the wire would be dispatched into them.
 *
 * Arming is the only way to become reachable, `nodus_witness_v2_ingress_arm`
 * refuses unless the gate is OPEN, and the gate can never be OPEN here — so
 * a production node is never reachable. The preflight computes reachability
 * from the ACTUAL armed state rather than assuming it, so if some future
 * build ever arms ingress without authority, the preflight says so instead
 * of continuing to argue from a structural claim that has expired.
 */

/**
 * Arm V2 ingress on this node.
 *
 * @return 0 armed, -1 refused. Refuses whenever
 *         nodus_witness_v2_activation_permitted() is 0, which in this build
 *         is always. On refusal the node is left UNARMED — there is no
 *         partial arming.
 */
int nodus_witness_v2_ingress_arm(nodus_witness_t *w);

/** Disarm V2 ingress. Always succeeds; disarming is never refused. */
void nodus_witness_v2_ingress_disarm(nodus_witness_t *w);

/**
 * Is V2 ingress reachable on this running node RIGHT NOW?
 *
 * @return 1 armed, 0 not armed or NULL handle. This is the fact preflight
 *         issue 13 is computed from.
 */
int nodus_witness_v2_ingress_is_armed(nodus_witness_t *w);

#ifdef NODUS_V2_TEST_AUTHORITY
/**
 * TEST-ONLY: grant this handle synthetic activation authority.
 *
 * Compiled ONLY under NODUS_V2_TEST_AUTHORITY, which `nodus/CMakeLists.txt`
 * defines on test targets and on NOTHING else. It is absent from libnodus
 * and from nodus-server, and `test_v2_gate_linked` proves that with `nm`
 * against the linked binaries.
 *
 * It grants ONLY the authority half. Preflight readiness is still evaluated
 * for real, so a test that arms ingress must also present a database the
 * preflight accepts — which no database does while Rule N stands. Tests
 * that need the armed path therefore also pass `allow_unready`, and that
 * second parameter exists so the two conditions can never be conflated even
 * inside a test.
 *
 * @param w             witness handle.
 * @param allow_unready non-zero to also bypass the readiness half.
 */
void nodus_witness_v2_gate_test_arm(nodus_witness_t *w, int allow_unready);

/** TEST-ONLY: revoke everything nodus_witness_v2_gate_test_arm granted. */
void nodus_witness_v2_gate_test_clear(nodus_witness_t *w);
#endif /* NODUS_V2_TEST_AUTHORITY */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_GATE_H */
