/**
 * @file nodus/src/witness/nodus_witness_v2_gate.c
 * @brief Ledger V2 O15B — the ONE production activation gate.
 *
 * Contract, rationale and the proof that this can never open in this build:
 * nodus_witness_v2_gate.h. Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_preflight.h"

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2GATE"

const char *nodus_witness_v2_gate_state_name(nodus_v2_gate_state_t s) {
    switch (s) {
    case NODUS_V2_GATE_NO_AUTHORITY: return "NO_AUTHORITY";
    case NODUS_V2_GATE_NOT_READY:    return "NOT_READY";
    case NODUS_V2_GATE_OPEN:         return "OPEN";
    case NODUS_V2_GATE_FAULT:        return "FAULT";
    }
    return "UNKNOWN";
}

/* ── Condition 1: committed activation authority ──────────────────────
 *
 * THIS FUNCTION IS THE WHOLE MECHANISM, AND IT HAS NOTHING TO CONSULT.
 *
 * A committed activation authority would be a rule in committed chain
 * state naming the height from which Ledger V2 is active. The tree has no
 * such rule: the committed chain-config parameter space ends at
 * DNAC_CFG_TARGET_ACTIVE_COUNT == DNAC_CFG_PARAM_MAX_ID == 4
 * (dnac/include/dnac/dnac.h:323-327), there is no activation field in
 * `chain_def`, and no table records one.
 *
 * So this returns 0. Not because a default says so, and not because a
 * feature is switched off — because the thing it would read does not
 * exist. Adding it is a governance decision (which parameter, which range,
 * which grace class, how a mixed-version network converges) and is the
 * named work of the separate O15C season.
 *
 * NOTE FOR WHOEVER WRITES O15C: the ONLY correct place to add it is here,
 * and it must read COMMITTED state. If it ever reads getenv, argv, a config
 * file, a local-only table, or anything a peer supplies, the gate stops
 * being consensus authority and becomes an operator switch — which is
 * exactly what this season was forbidden to build.
 */
int nodus_witness_v2_gate_authority_present(nodus_witness_t *w) {
#ifdef NODUS_V2_TEST_AUTHORITY
    if (w && w->v2_gate_test_authority) return 1;
#else
    (void)w;
#endif
    return 0;
}

/* ── Condition 2: preflight readiness ─────────────────────────────────
 *
 * Delegated in full to the O15A preflight, which is read-only and
 * deterministic. `ready` is DEFINED there as "no issues found", so a check
 * added later cannot be accidentally excluded from this gate either.
 *
 * A preflight that cannot complete is NOT ready — it is unknown, and
 * unknown is not readiness. That maps to FAULT below, never to OPEN.
 */
static int v2_preflight_ready(nodus_witness_t *w, int *fault_out) {
    *fault_out = 0;

#ifdef NODUS_V2_TEST_AUTHORITY
    if (w && w->v2_gate_test_allow_unready) return 1;
#endif

    nodus_v2_preflight_report_t rep;
    if (nodus_witness_v2_preflight(w, &rep) != 0) {
        *fault_out = 1;
        return 0;
    }
    return rep.ready ? 1 : 0;
}

nodus_v2_gate_state_t nodus_witness_v2_gate_state(nodus_witness_t *w) {
    if (!w || !w->db) return NODUS_V2_GATE_FAULT;

    /* Authority first: "no rule could activate this" is a more fundamental
     * answer than "the rule exists but the database is not ready", and
     * reporting the deeper one is what lets an operator tell a software
     * limitation from a database state. */
    if (!nodus_witness_v2_gate_authority_present(w))
        return NODUS_V2_GATE_NO_AUTHORITY;

    int fault = 0;
    if (!v2_preflight_ready(w, &fault))
        return fault ? NODUS_V2_GATE_FAULT : NODUS_V2_GATE_NOT_READY;

    return NODUS_V2_GATE_OPEN;
}

int nodus_witness_v2_activation_permitted(nodus_witness_t *w) {
    return nodus_witness_v2_gate_state(w) == NODUS_V2_GATE_OPEN ? 1 : 0;
}

/* ── Ingress reachability ─────────────────────────────────────────────── */

int nodus_witness_v2_ingress_arm(nodus_witness_t *w) {
    if (!w) return -1;

    nodus_v2_gate_state_t s = nodus_witness_v2_gate_state(w);
    if (s != NODUS_V2_GATE_OPEN) {
        /* Leave the node UNARMED. There is no partial arming: a node is
         * either dispatching V2 frames or it is not. */
        w->v2_ingress_armed = false;
        QGP_LOG_WARN(LOG_TAG,
                     "refusing to arm Ledger V2 ingress — gate is %s",
                     nodus_witness_v2_gate_state_name(s));
        return -1;
    }

    w->v2_ingress_armed = true;
    QGP_LOG_INFO(LOG_TAG, "%s", "Ledger V2 ingress ARMED (gate OPEN)");
    return 0;
}

void nodus_witness_v2_ingress_disarm(nodus_witness_t *w) {
    if (!w) return;
    if (w->v2_ingress_armed)
        QGP_LOG_INFO(LOG_TAG, "%s", "Ledger V2 ingress disarmed");
    w->v2_ingress_armed = false;
}

int nodus_witness_v2_ingress_is_armed(nodus_witness_t *w) {
    return (w && w->v2_ingress_armed) ? 1 : 0;
}

#ifdef NODUS_V2_TEST_AUTHORITY
void nodus_witness_v2_gate_test_arm(nodus_witness_t *w, int allow_unready) {
    if (!w) return;
    w->v2_gate_test_authority    = true;
    w->v2_gate_test_allow_unready = allow_unready ? true : false;
}

void nodus_witness_v2_gate_test_clear(nodus_witness_t *w) {
    if (!w) return;
    w->v2_gate_test_authority     = false;
    w->v2_gate_test_allow_unready = false;
    w->v2_ingress_armed           = false;
}
#endif /* NODUS_V2_TEST_AUTHORITY */
