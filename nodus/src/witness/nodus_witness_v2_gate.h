/**
 * @file nodus/src/witness/nodus_witness_v2_gate.h
 * @brief Ledger V2 O15B — the ONE production activation gate.
 *
 * ═══ WHAT THIS FILE IS FOR ══════════════════════════════════════════════
 * O15B built the whole V2 network surface — canonical wire, ingress
 * adapters, sync, recovery — and shipped it PRODUCTION-DORMANT, with this
 * module making "dormant" a structural property instead of a promise.
 *
 * O15J Faz 3 ENDED THE DORMANCY. The V2 lane is no longer something a
 * future ceremony switches on: a chain is born V2, and this module is now
 * what decides whether THIS DATABASE IS THAT CHAIN. On a pure-V2 database
 * a default production build opens the gate, arms ingress and runs the
 * lane; on anything else it stays shut, and that refusal is still
 * structural rather than configured.
 *
 * Every production path that would advertise, accept, propose, vote for,
 * finalize, sync or replay a Ledger V2 block asks exactly one question
 * here, and gets one of FOUR answers. Exactly one of them —
 * NODUS_V2_GATE_OPEN — means "proceed"; NO_AUTHORITY, NOT_READY and FAULT
 * all mean "do not", and they are kept distinct because they call for
 * different operator responses.
 *
 * ═══ WHAT OPENS IT ══════════════════════════════════════════════════════
 * Opening requires BOTH conditions:
 *
 *  1. COMMITTED AUTHORITY — the chain's OWN GENESIS IDENTITY.
 *
 *     O15J Faz 3 removed the activation ceremony. There is no longer a
 *     V1→V2 transition to authorize: a Ledger V2 chain is BORN V2, built
 *     from an operator config by `nodus_witness_v2_gen_derive` with no
 *     legacy ancestor. So the authority this gate reads is not a rule
 *     naming a future height — it is the committed fact that THIS
 *     DATABASE IS A PURE-V2 CHAIN.
 *
 *     Concretely: a height-0 row in `v2_manifests` whose decoded genesis
 *     manifest has `dist_present == 1` and `source_tag ==
 *     NODUS_V2_GEN_SOURCE_TAG` ("DNA.GENESIS.v1",
 *     nodus_witness_v2_gen.h:184-185). That manifest's hash IS the chain
 *     id, so the predicate rests on the most committed bytes the database
 *     holds — not on a flag, a build option or an operator decision.
 *
 *     `NODUS_V2_GATE_NO_AUTHORITY` therefore now means "THIS IS NOT A
 *     PURE-V2 CHAIN", not "this software cannot activate V2". The
 *     historical readings — O15B's structural constant 0, and O15C's
 *     committed activation record / "DNA.LEGACY.TERM.v1" successor
 *     binding — are both deleted with the ceremony.
 *
 *  2. PREFLIGHT READINESS — `nodus_witness_v2_preflight()` reporting zero
 *     issues over the committed state of that same database.
 *
 * Either one alone keeps the gate shut, and each is evaluated against
 * committed bytes only.
 *
 * ═══ WHAT CANNOT OPEN IT ════════════════════════════════════════════════
 * By construction there is NO input through which any of these could:
 *
 *   - an environment variable          (nothing here reads getenv)
 *   - a command-line flag              (no parameter carries intent)
 *   - a build option                   (the ceremony's compile gate is
 *                                       gone; there is no second variant)
 *   - an operator override / config    (no file is consulted)
 *   - a peer, a header, or a message   (no network value reaches this)
 *
 * `nodus_witness_v2_gate_state()` takes ONE argument, a witness handle, and
 * there is no second argument through which a caller could propose that the
 * lane is active. That is the same discipline
 * `nodus_witness_v2_qc_verify()` uses for validator authority: the absence
 * of a parameter is the guarantee.
 *
 * ═══ UNKNOWN IS NOT "NO" ════════════════════════════════════════════════
 * The authority probe is THREE-VALUED. A prepare failure on a table that
 * exists, a mid-step SQLITE_IOERR/SQLITE_CORRUPT, a NULL/empty manifest
 * blob or one that fails to decode is a FAULT, reported as
 * `NODUS_V2_GATE_FAULT` — never folded into NO_AUTHORITY. An absent
 * `v2_manifests` table, an absent height-0 row, or a row carrying some
 * other source tag are genuine NO_AUTHORITY answers.
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
     * No committed authority: THIS IS NOT A PURE-V2 CHAIN. The database
     * carries no height-0 genesis manifest with the pure-V2 source tag —
     * see the file comment. Deliberately distinct from NOT_READY so an
     * operator can tell "this is the wrong database for the V2 lane" from
     * "this is the right database and it is not ready yet".
     */
    NODUS_V2_GATE_NO_AUTHORITY = 0,
    /** Authority exists, but the preflight found blocking issues. */
    NODUS_V2_GATE_NOT_READY    = 1,
    /** Both conditions hold: a pure-V2 chain with a clean preflight. */
    NODUS_V2_GATE_OPEN         = 2,
    /**
     * The gate itself could not be evaluated (NULL handle, no database, a
     * read fault in the authority probe or inside the preflight).
     * Fail-closed and distinct: "we could not tell" must never be silently
     * reported as "no authority" or as "not ready", because all three call
     * for different operator responses.
     */
    NODUS_V2_GATE_FAULT        = 3
} nodus_v2_gate_state_t;

/** Stable human-readable name for a gate state (never NULL). */
const char *nodus_witness_v2_gate_state_name(nodus_v2_gate_state_t s);

/**
 * Condition 1 alone: does committed authority exist — is this a pure-V2
 * chain?
 *
 * Exposed separately because it is the ONLY half of the gate that can be
 * evaluated without running the preflight — and the preflight itself needs
 * it, to compute issue 13, without calling back into
 * `nodus_witness_v2_gate_state()` and recursing forever. Splitting the two
 * conditions at the header is what keeps that impossible rather than
 * merely avoided.
 *
 * READS THE DATABASE. Since O15J Faz 3 this is a committed-state query
 * (the height-0 genesis manifest), not the structural constant O15B
 * shipped — callers on a per-frame hot path should establish the answer
 * once rather than re-deriving it.
 *
 * @return 1 if committed authority exists, 0 otherwise. The 0 FOLDS two
 *         distinct answers — genuinely absent, and could-not-be-read —
 *         because every caller of this form consumes it as "may this
 *         proceed?", where UNKNOWN must read as no. To DISTINGUISH them,
 *         call nodus_witness_v2_gate_state() and test for
 *         NODUS_V2_GATE_FAULT.
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
 *         evaluated — including an authority probe that could not read the
 *         database, which is never reported as NO_AUTHORITY.
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
 * Arming is the only way to become reachable and
 * `nodus_witness_v2_ingress_arm` refuses unless the gate is OPEN, so a node
 * holding anything other than a ready pure-V2 chain is never reachable. The
 * preflight computes reachability from the ACTUAL armed state rather than
 * assuming it, so if some future build ever arms ingress without authority,
 * the preflight says so instead of continuing to argue from a structural
 * claim that has expired.
 */

/**
 * Arm V2 ingress on this node.
 *
 * @return 0 armed, -1 refused. Refuses whenever
 *         nodus_witness_v2_activation_permitted() is 0. On refusal the node
 *         is left UNARMED — there is no partial arming.
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
 * preflight accepts — which a synthetic fixture database generally is not.
 * Tests that need the armed path therefore also pass `allow_unready`, and
 * that second parameter exists so the two conditions can never be conflated
 * even inside a test.
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
