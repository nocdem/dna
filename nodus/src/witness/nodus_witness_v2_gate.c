/**
 * @file nodus/src/witness/nodus_witness_v2_gate.c
 * @brief Ledger V2 O15B — the ONE production activation gate.
 *
 * Contract, rationale and what each state means:
 * nodus_witness_v2_gate.h. Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "witness/nodus_witness_v2_gen.h"   /* NODUS_V2_GEN_SOURCE_TAG   */
#include "dnac/manifest_wire.h"             /* dna_gman_decode           */
#include <sqlite3.h>
#include <string.h>

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

/* ── Condition 1: committed authority — the PURE-V2 GENESIS BINDING ───
 *
 * O15J Faz 3 — THE ACTIVATION CEREMONY IS GONE, AND SO IS THE QUESTION
 * IT ANSWERED.
 *
 * O15B shipped this as a constant 0: no committed rule could name a
 * height from which Ledger V2 became active, so the gate could not open.
 * O15C added a build-gated arm that read one — either the LEGACY chain's
 * committed activation record, or a successor chain's genesis manifest
 * carrying the terminal-legacy source binding "DNA.LEGACY.TERM.v1".
 * Both are deleted. There is no V1→V2 transition left to authorize,
 * because a V2 chain is now BORN V2 (nodus_witness_v2_gen.c).
 *
 * So authority is no longer a permission slip for a transition. It is
 * the chain's OWN GENESIS IDENTITY: a pure-V2 chain commits, at height
 * 0, a genesis manifest whose distribution is present and whose
 * source_tag is NODUS_V2_GEN_SOURCE_TAG ("DNA.GENESIS.v1",
 * nodus_witness_v2_gen.h:184-185). That manifest's hash IS the chain id
 * (nodus_witness_v2_chain_id), so this predicate reads the most
 * committed bytes the database holds.
 *
 * WHAT NO_AUTHORITY NOW MEANS: not "this software cannot activate V2",
 * but "THIS IS NOT A PURE-V2 CHAIN" — the database carries no height-0
 * genesis manifest this builder produced.
 *
 * The query and the predicate are DELIBERATELY the same ones
 * nodus_witness_v2_gen_is_pure() runs (nodus_witness_v2_gen.c:262-289);
 * only the connection differs. That probe opens the file by path before
 * a handle exists; here the handle is already open, and opening a second
 * connection to the same file would be a second reader that could
 * disagree with the first. One handle, one answer.
 *
 * THREE-VALUED, AND THE THIRD VALUE IS THE POINT. A prepare failure on a
 * table that exists, a mid-step SQLITE_IOERR/SQLITE_CORRUPT, a NULL or
 * empty blob, or a manifest that does not decode is a FAULT — "we could
 * not tell" — and nodus/CLAUDE.md bans one error code meaning both
 * absent and failed. The O15C arm this replaces fell through to
 * `return 0` on every one of those, so a transient read error read as a
 * considered "no authority" and the gate reported NO_AUTHORITY on a
 * chain that has it. An ABSENT v2_manifests table, an absent height-0
 * row, or a row whose tag simply does not match are genuine 0s.
 *
 * READ-ONLY, and unchanged in the O15B discipline that matters: no
 * clock, no getenv, no argv, no config file and no peer-supplied value
 * reaches this. The only thing that changed is that the committed bytes
 * it consults now exist.
 */
static int v2_authority_present(nodus_witness_t *w, int *fault_out) {
    *fault_out = 0;

#ifdef NODUS_V2_TEST_AUTHORITY
    if (w && w->v2_gate_test_authority) return 1;
#endif

    if (!w || !w->db) return 0;

    /* Table existence is probed EXPLICITLY rather than inferred from a
     * prepare failure: a database with no v2_manifests table is simply
     * not a pure-V2 chain, and that is a definitive 0, not a fault. Only
     * a genuine catalogue read failure is a fault. Same three-valued
     * shape as nodus_witness_v2_gen.c:236-262 and table_exists() in
     * nodus_witness_v2_claims.c:38. */
    {
        sqlite3_stmt *tq = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='v2_manifests'", -1, &tq, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                "authority probe: could not prepare the catalogue read — "
                "authority is UNKNOWN, not absent");
            *fault_out = 1;
            return 0;
        }
        int trc = sqlite3_step(tq);
        sqlite3_finalize(tq);
        if (trc == SQLITE_DONE) return 0;   /* not a pure-V2 chain */
        if (trc != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG,
                "authority probe: catalogue read failed (sqlite rc=%d) — "
                "authority is UNKNOWN, not absent", trc);
            *fault_out = 1;
            return 0;
        }
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT manifest FROM v2_manifests "
            "WHERE committed_height = 0 "
            "ORDER BY manifest_seq ASC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "authority probe: prepare failed on a table that exists — "
            "authority is UNKNOWN, not absent");
        *fault_out = 1;
        return 0;
    }

    int present = 0;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        present = 0;                    /* no genesis manifest: not ours */
    } else if (rc == SQLITE_ROW) {
        const void *mb = sqlite3_column_blob(st, 0);
        int ml = sqlite3_column_bytes(st, 0);
        dna_gman_t m;
        if (!mb || ml <= 0) {
            *fault_out = 1;             /* NULL/empty blob: unreadable   */
        } else if (dna_gman_decode((const uint8_t *)mb, (size_t)ml, &m)
                   != 0) {
            *fault_out = 1;             /* undecodable: cannot classify  */
        } else {
            present = (m.dist_present == 1 &&
                       m.source_tag_len == NODUS_V2_GEN_SOURCE_TAG_LEN &&
                       memcmp(m.source_tag, NODUS_V2_GEN_SOURCE_TAG,
                              NODUS_V2_GEN_SOURCE_TAG_LEN) == 0) ? 1 : 0;
        }
    } else {
        *fault_out = 1;                 /* IOERR / CORRUPT / ...         */
    }
    sqlite3_finalize(st);

    if (*fault_out) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "authority probe: the committed genesis manifest could not be "
            "read or decoded — authority is UNKNOWN, not absent");
        return 0;
    }
    return present;
}

int nodus_witness_v2_gate_authority_present(nodus_witness_t *w) {
    /* The public form FOLDS fault into 0, and the fold is safe because it
     * is one-directional: nothing becomes MORE permitted. Its two callers
     * outside this module — nodus_witness_v2_ingress.c:405 and
     * nodus_witness_v2_preflight.c:368 — both consume the answer as "may
     * this proceed?", where UNKNOWN must read as no. A caller that must
     * DISTINGUISH absent from unreadable uses
     * nodus_witness_v2_gate_state(), which reports NODUS_V2_GATE_FAULT. */
    int fault = 0;
    return v2_authority_present(w, &fault);
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

    /* Authority first: "this is not a pure-V2 chain" is a more
     * fundamental answer than "it is one, but the database is not ready",
     * and reporting the deeper one is what lets an operator tell a
     * wrong-database problem from a database-state problem.
     *
     * An authority probe that could not COMPLETE is a FAULT, never
     * NO_AUTHORITY: a database that could not be read must not be
     * reported as a database that answered "no". */
    int afault = 0;
    if (!v2_authority_present(w, &afault))
        return afault ? NODUS_V2_GATE_FAULT : NODUS_V2_GATE_NO_AUTHORITY;

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
