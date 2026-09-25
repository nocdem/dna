/**
 * Nodus — a stop delivered during init must not be resurrected (O15B.1).
 *
 * `nodus-server` installs nodus_server_stop() as its SIGINT/SIGTERM
 * handler, and nodus_server_run() used to open with an unconditional
 * `srv->running = true`. nodus_server_init() is a long operation —
 * storage migration, an incremental VACUUM, identity generation, witness
 * init — so a signal that lands inside it set `running = false` and was
 * then overwritten a moment later. The process ignored the signal for
 * the rest of its life: the run loop only ever polls with a 50 ms
 * timeout, so it is never interrupted again and nothing re-checks.
 *
 * The Stage F harness kills its short-lived identity-generation spawns
 * in exactly that window (stagef_up.sh waits for nodus.pk/sk/fp, which
 * appear well before init finishes, then kills and `wait`s). When the
 * race landed, stagef_up.sh blocked in `wait` forever — one of the shapes
 * behind the "harness is unstable on this machine" report.
 *
 * `stop_requested` is the latch that fixes it. These checks pin the
 * contract: setting it before run() means run() refuses to start, and the
 * latch survives whatever `running` does.
 *
 * Reverting nodus_server_run()'s early return, or nodus_server_stop()'s
 * latch, fails this test.
 */

#include "server/nodus_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* nodus_server_t embeds multi-MB transport/session arrays — heap only.
 * A zeroed struct is all these checks need: the paths under test read
 * stop_requested and running and nothing else before returning. */
static nodus_server_t *fresh_server(void) {
    return (nodus_server_t *)calloc(1, sizeof(nodus_server_t));
}

static void test_stop_sets_the_latch(void) {
    TEST("nodus_server_stop latches stop_requested, not just running");

    nodus_server_t *srv = fresh_server();
    if (!srv) { FAIL("calloc"); return; }

    srv->running = true;
    nodus_server_stop(srv);

    if (srv->running) { FAIL("running still true"); free(srv); return; }
    if (!srv->stop_requested) { FAIL("stop_requested not latched"); free(srv); return; }

    free(srv);
    PASS();
}

static void test_run_refuses_after_stop(void) {
    TEST("a stop delivered during init makes run() refuse to start");

    nodus_server_t *srv = fresh_server();
    if (!srv) { FAIL("calloc"); return; }

    /* The signal lands while init is still working. */
    nodus_server_stop(srv);

    /* Whatever init would have left behind, run() must not start. If it
     * did, it would enter the poll loop on a half-built server and never
     * come back — which is the hang this test exists to prevent. */
    int rc = nodus_server_run(srv);

    if (rc != 0) { FAIL("run() did not return 0"); free(srv); return; }
    if (srv->running) { FAIL("run() started anyway (running == true)"); free(srv); return; }

    free(srv);
    PASS();
}

static void test_latch_is_not_cleared_by_running(void) {
    TEST("the latch outlives a later write to running");

    nodus_server_t *srv = fresh_server();
    if (!srv) { FAIL("calloc"); return; }

    nodus_server_stop(srv);
    srv->running = true;            /* what run() used to do unconditionally */

    if (!srv->stop_requested) { FAIL("latch cleared"); free(srv); return; }
    if (nodus_server_run(srv) != 0) { FAIL("run() started despite the latch"); free(srv); return; }

    free(srv);
    PASS();
}

int main(void) {
    printf("\n=== Nodus stop-during-init latch (O15B.1) ===\n\n");

    test_stop_sets_the_latch();
    test_run_refuses_after_stop();
    test_latch_is_not_cleared_by_running();

    printf("\n  %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
