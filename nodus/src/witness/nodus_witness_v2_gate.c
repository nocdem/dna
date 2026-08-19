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
#ifdef NODUS_V2_ACTIVATION_AUTHORITY
#include "witness/nodus_witness_v2_activation.h"
#include "dnac/manifest_wire.h"
#include <sqlite3.h>
#include <string.h>
#endif

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
#endif
#ifdef NODUS_V2_ACTIVATION_AUTHORITY
    /* O15C — the committed authority this function existed to read.
     * Compiled ONLY in activation-authority builds (CMake option, OFF by
     * default): a production binary keeps the constant 0 above, exactly
     * as O15B shipped it. Two committed forms, both fail-closed:
     *
     *  1. The LEGACY chain's activation record in state READY or ACTIVE
     *     (quorum-scheduled, all-active-readiness — the O15C-A machine).
     *     SCHEDULED is deliberately NOT authority: collection is not a
     *     decision.
     *  2. The SUCCESSOR chain's own committed genesis manifest carrying
     *     the terminal-legacy source binding (source_tag
     *     "DNA.LEGACY.TERM.v1") — a V2 chain born by the seam holds its
     *     authority in the genesis identity itself (manifest hash →
     *     chain id), which only the committed legacy record could have
     *     authorized deriving.
     *
     * Malformation is NEVER authority (the preflight raises issue 15 and
     * blocks readiness — the gate then reports NOT_READY/FAULT). */
    if (w && w->db) {
        nodus_v2_act_record_t rec;
        int arc = nodus_witness_v2_activation_get(w, &rec);
        if (arc == 0 && (rec.state == DNA_ACT_STATE_READY ||
                         rec.state == DNA_ACT_STATE_ACTIVE))
            return 1;

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT manifest FROM v2_manifests "
                "WHERE committed_height = 0 "
                "ORDER BY manifest_seq ASC LIMIT 1",
                -1, &st, NULL) == SQLITE_OK) {
            int have = 0;
            if (sqlite3_step(st) == SQLITE_ROW) {
                dna_gman_t m;
                const void *mb = sqlite3_column_blob(st, 0);
                int ml = sqlite3_column_bytes(st, 0);
                if (mb && ml > 0 &&
                    dna_gman_decode((const uint8_t *)mb, (size_t)ml,
                                    &m) == 0 &&
                    m.dist_present == 1 &&
                    m.source_tag_len == DNA_ACT_SOURCE_TAG_LEN &&
                    memcmp(m.source_tag, DNA_ACT_SOURCE_TAG,
                           DNA_ACT_SOURCE_TAG_LEN) == 0)
                    have = 1;
            }
            sqlite3_finalize(st);
            if (have) return 1;
        }
    }
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
