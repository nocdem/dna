/**
 * Nodus — Faz 5.4 fault injection: env-driven drop-predicate installer.
 *
 * O15C-D.1. The dispatch hook (nodus_witness_test_inject_drop,
 * nodus_witness.c) has existed since Faz 5.4, but installing a
 * predicate required calling a C function — which only an in-process
 * test can do. The stagef harness runs seven SEPARATE nodus-server
 * processes, so the end-to-end partition scenario the hook was built
 * for was never reachable and was recorded as deferred
 * (tests/test_fault_inject_round_skip.c header).
 *
 * This TU closes that gap: the predicate is described by environment
 * variables, which stagef_up.sh's child processes inherit.
 *
 * ── Why an ARM FILE and not just the env var ──────────────────────
 *
 * Environment is read once, at process start. But genesis commits
 * DURING stagef_up.sh, at view 0 — so a predicate that dropped view-0
 * PRECOMMITs from the moment the process started would prevent the
 * cluster from ever committing genesis, and the harness would die
 * before any test began.
 *
 * The env therefore names a path, and the predicate only bites while
 * a file exists at that path. The harness brings the cluster up, funds
 * what it needs, creates the arm file, and only THEN submits the spend
 * the scenario targets. Arming is strictly-before the round starts,
 * which makes this a deterministic control-plane switch rather than a
 * timing race — nothing here depends on how long a step takes.
 *
 * The scope is `view == <N>` (default 0), so the file does NOT need to
 * be removed to let the cluster recover: the round re-proposed under
 * view 1 is not matched by the predicate and commits normally. That
 * keeps teardown out of the critical path too.
 *
 * ⚠ Compiled ONLY under -DQGP_FAULT_INJECT=ON, which CMake rejects for
 * Release builds (CMakeLists.txt: "the drop predicate hook would be
 * live in the shipped binary"). This file is empty in every normal
 * build.
 */

#ifdef QGP_FAULT_INJECT

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_TAG "WITNESS-FAULT"

/* Resolved once at install time — the predicate itself does no
 * allocation and no getenv, so it stays cheap enough to run against
 * every inbound T3 frame. */
static char     g_arm_path[512];
static uint32_t g_drop_view;
static nodus_t3_msg_type_t g_drop_type;

/* Armed == the file exists. A stat() per inbound T3 frame is
 * acceptable in a test-only build and keeps the switch observable from
 * the harness with nothing more than `touch`. */
static bool fault_armed(void) {
    struct stat st;
    return stat(g_arm_path, &st) == 0;
}

/* O15C-D.3 — sender-scoped VIEW_CHANGE drop.
 *
 * Manufactures GENUINELY DIFFERENT first-2f+1 VIEW_CHANGE collections on
 * a live cluster, so honest nodes legitimately end up with different (but
 * individually valid) subsets for the same target view. That is the state
 * the O15C-D.3 record is about, and it cannot be produced by timing alone
 * in a reproducible way.
 *
 * Env: NODUS_FAULT_DROP_VC_ROTATE=<k>.
 *
 * stagef spawns all seven nodes with the SAME environment, so a static
 * sender list would give every node the same subset — vacuous. The drop
 * set is therefore derived from each node's OWN id: node X ignores
 * VIEW_CHANGE from the `k` senders whose id-byte distance from X falls in
 * [1, k]. One shared env var, a DIFFERENT set on every node, and fully
 * deterministic — no timing, no randomness. */
static uint8_t g_my_tag;
static int     g_vc_drop_k;
/* O15E Faz C: victim-scoped drop — when set (>=0), ONLY the node whose
 * my_id[0] equals this tag actually drops, so a single victim misses
 * inbound COMMITs while every other node exchanges them and attaches a
 * QC. -1 = all nodes (the legacy cluster-wide behaviour). Env:
 * NODUS_FAULT_ONLY_TAG (hex). Test-only build (QGP_FAULT_INJECT). */
static int     g_only_tag = -1;

static bool vc_sender_dropped(const uint8_t *sender_id) {
    if (g_vc_drop_k <= 0 || !sender_id) return false;
    /* Distance in a small ring keyed on the first id byte. Distinct
     * validators have distinct ids, so distinct nodes drop distinct
     * senders. */
    int d = (int)((uint8_t)(sender_id[0] - g_my_tag) % 7u);
    return d >= 1 && d <= g_vc_drop_k;
}

static bool fault_drop_pred(const void *msg_v, const uint8_t *peer_id) {
    (void)peer_id;
    const nodus_t3_msg_t *msg = (const nodus_t3_msg_t *)msg_v;
    if (!msg) return false;
    if (!fault_armed()) return false;

    /* Rule 2 — sender-scoped VIEW_CHANGE drop (differing subsets). */
    if (msg->type == NODUS_T3_VIEWCHG &&
        vc_sender_dropped(msg->header.sender_id))
        return true;

    /* Rule 1 — type (+ view) scoped drop. COMMIT carries no view the
     * predicate can key on (it is a finalization certificate, not a
     * round-state message — nodus_witness_v2_produce.h), so for that
     * type the drop is type-scoped only. Every other type keeps the
     * view scope (the MED-28 round-failure rule). */
    if (msg->type != g_drop_type) return false;
    if (g_only_tag >= 0 && g_my_tag != (uint8_t)g_only_tag) return false;
    if (g_drop_type != NODUS_T3_COMMIT &&
        msg->header.view != g_drop_view) return false;
    return true;
}

void nodus_witness_fault_init_from_env(const uint8_t *my_id) {
    const char *arm = getenv("NODUS_FAULT_ARM_FILE");
    if (!arm || !arm[0]) return;          /* not a fault-injection run */

    snprintf(g_arm_path, sizeof(g_arm_path), "%s", arm);

    const char *view_s = getenv("NODUS_FAULT_DROP_VIEW");
    g_drop_view = view_s ? (uint32_t)strtoul(view_s, NULL, 10) : 0u;

    /* Only the two vote types are meaningful to drop for the MED-28
     * scenario; anything else is a typo and must fail loudly rather
     * than silently install a predicate that never matches. */
    const char *type_s = getenv("NODUS_FAULT_DROP_TYPE");
    if (!type_s || strcmp(type_s, "precommit") == 0) {
        g_drop_type = NODUS_T3_PRECOMMIT;
    } else if (strcmp(type_s, "prevote") == 0) {
        g_drop_type = NODUS_T3_PREVOTE;
    } else if (strcmp(type_s, "commit") == 0) {
        /* O15E Faz C — drop INBOUND COMMIT frames on this node. A
         * successor commits its own block via its PRECOMMIT quorum
         * (produce.c own-quorum path), but the DNA.CERT.v2 certificates
         * that assemble the QC ride peers' COMMIT broadcasts. Dropping
         * them leaves this node committed-but-uncertified (qc NULL) while
         * peers, which still exchange COMMITs among themselves, reach
         * quorum and attach — exactly the missing-QC window Faz C
         * recovery closes. Not view-scoped: a commit carries no view the
         * predicate keys on, so any NODUS_FAULT_DROP_VIEW is ignored for
         * this type and the drop bites until the arm file is removed. */
        g_drop_type = NODUS_T3_COMMIT;
    } else {
        fprintf(stderr, "%s: unknown NODUS_FAULT_DROP_TYPE='%s' — "
                "refusing to install a predicate\n", LOG_TAG, type_s);
        return;
    }

    /* O15C-D.3 — per-node VIEW_CHANGE drop width (differing subsets). */
    const char *vck = getenv("NODUS_FAULT_DROP_VC_ROTATE");
    g_vc_drop_k = vck ? (int)strtol(vck, NULL, 10) : 0;
    if (g_vc_drop_k < 0) g_vc_drop_k = 0;
    g_my_tag = my_id ? my_id[0] : 0;

    /* O15E Faz C: victim-scoped drop — only the node whose my_id[0]
     * matches NODUS_FAULT_ONLY_TAG (hex) actually drops. */
    const char *only = getenv("NODUS_FAULT_ONLY_TAG");
    g_only_tag = only ? (int)strtol(only, NULL, 16) : -1;

    nodus_witness_test_inject_drop(fault_drop_pred);
    fprintf(stderr, "%s: drop predicate installed (type=%d view=%u "
            "vc_drop_senders=%d my_tag=%02x arm_file=%s)\n", LOG_TAG,
            (int)g_drop_type, g_drop_view, g_vc_drop_k, g_my_tag,
            g_arm_path);
}

#endif /* QGP_FAULT_INJECT */
