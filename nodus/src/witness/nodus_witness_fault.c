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

static bool fault_drop_pred(const void *msg_v, const uint8_t *peer_id) {
    (void)peer_id;
    const nodus_t3_msg_t *msg = (const nodus_t3_msg_t *)msg_v;
    if (!msg) return false;
    if (msg->type != g_drop_type) return false;
    if (msg->header.view != g_drop_view) return false;
    return fault_armed();
}

void nodus_witness_fault_init_from_env(void) {
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
    } else {
        fprintf(stderr, "%s: unknown NODUS_FAULT_DROP_TYPE='%s' — "
                "refusing to install a predicate\n", LOG_TAG, type_s);
        return;
    }

    nodus_witness_test_inject_drop(fault_drop_pred);
    fprintf(stderr, "%s: drop predicate installed (type=%d view=%u "
            "arm_file=%s)\n", LOG_TAG, (int)g_drop_type, g_drop_view,
            g_arm_path);
}

#endif /* QGP_FAULT_INJECT */
