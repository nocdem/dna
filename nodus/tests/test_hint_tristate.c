/**
 * Nodus — the hinted-handoff retry deletes a durable row ONLY on an
 * authenticated write (DHT v2 3b-2, Kurultay #43 mandatory fix "no hint-row
 * deletion on queued", rolling deploy)
 *
 * PROVES (nodus_dht_tick -> dht_hinted_retry in nodus/src/dht/
 * nodus_dht_server.c, driven with a host whose inter_send returns a fixed
 * nodus_inter_send_t):
 *   H1  WRITTEN (an authenticated session took the frame): the row is
 *       deleted.
 *   H2  QUEUED (the session is not authenticated yet — the frame waits in a
 *       memory queue that dies with a failed handshake, e.g. an old-build
 *       peer during a rolling deploy): the row STAYS.
 *   H3  FAILED (nothing queued): the row stays (retry counted, expiry by the
 *       hint TTL / retry cap as before).
 *
 * HOW: one forked child per case, because dht_hinted_retry keeps a
 * function-static "last retry" time (it runs on the first tick only). Each
 * child opens a real DHT on a private temp directory, stores one hint row for
 * a peer, ticks once, and exits 0 iff the number of rows left is the
 * expected one.
 *
 * REQUIRES: a default build; /tmp writable. LEAVES: nothing (temp dirs
 * removed). HOW IT CAN LIE: the child must have run the retry at all — it
 * checks the stub was called (a tick that skipped the retry would leave the
 * row in H1 and the stub uncalled, and FAIL there).
 */

#include "dht/nodus_dht.h"
#include "server/nodus_inter_dial.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_mode;      /* the nodus_inter_send_t the stub returns */
static int g_calls;

static int stub_inter_send(void *ctx, const char *ip, uint16_t port,
                           const nodus_key_t *expected_peer_id,
                           const uint8_t *frame, size_t flen) {
    (void)ctx; (void)ip; (void)port; (void)expected_peer_id; (void)frame; (void)flen;
    g_calls++;
    return g_mode;
}

static bool stub_hint_wanted(void *ctx, const nodus_key_t *id) {
    (void)ctx; (void)id;
    return false;
}

/* Child: returns the process exit code. */
static int run_case(int mode, int rows_expected) {
    g_mode = mode;
    static nodus_identity_t id;
    if (nodus_identity_generate(&id) != 0) return 10;

    char dir[] = "/tmp/nodus_hint_tristate_XXXXXX";
    if (!mkdtemp(dir)) return 11;

    static nodus_dht_t dht;
    nodus_dht_host_t host;
    memset(&host, 0, sizeof(host));
    host.identity    = &id;
    host.inter_send  = stub_inter_send;
    host.hint_wanted = stub_hint_wanted;
    int rc = 20;
    if (nodus_dht_init(&dht, &host) != 0) goto out;
    if (nodus_dht_open(&dht, dir, "127.0.0.1", 4002) != 0) { rc = 21; goto out_close; }

    nodus_key_t peer;
    memset(&peer, 0x33, sizeof(peer));
    static const uint8_t frame[] = { 'h', 'i', 'n', 't', '-', 'f', 'r', 'a', 'm', 'e' };
    if (nodus_storage_hinted_insert(&dht.storage, &peer, "127.0.0.1", 4002,
                                    frame, sizeof(frame)) != 0) { rc = 22; goto out_close; }
    if (nodus_storage_hinted_count(&dht.storage) != 1) { rc = 23; goto out_close; }

    nodus_dht_tick(&dht);

    if (g_calls < 1) { rc = 24; goto out_close; }          /* the retry never ran */
    rc = nodus_storage_hinted_count(&dht.storage) == rows_expected ? 0 : 25;
out_close:
    nodus_dht_close(&dht);
out:
    nodus_dht_stop(&dht);
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) rc = rc ? rc : 26;
    return rc;
}

static int run_forked(int mode, int rows_expected) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) _exit(run_case(mode, rows_expected));
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -2;
}

int main(void) {
    int passed = 0, failed = 0;
    printf("=== hinted-handoff retry vs the send tri-state ===\n");
    struct { const char *name; int mode; int rows_left; } cases[] = {
        { "H1 WRITTEN: the row is deleted",       NODUS_INTER_SEND_WRITTEN, 0 },
        { "H2 QUEUED: the row stays",             NODUS_INTER_SEND_QUEUED,  1 },
        { "H3 FAILED: the row stays",             NODUS_INTER_SEND_FAILED,  1 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        printf("  %-60s", cases[i].name);
        int rc = run_forked(cases[i].mode, cases[i].rows_left);
        if (rc == 0) { printf("PASS\n"); passed++; }
        else { printf("FAIL: child exit %d\n", rc); failed++; }
    }
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
