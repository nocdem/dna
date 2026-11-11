/**
 * Nodus — client init reports a failed transport open (BUGS.md C-14)
 *
 * What it proves: when nodus_tcp_init() cannot create its epoll descriptor,
 * nodus_client_init() and nodus_channel_init() return -1 instead of success
 * with an unusable transport, and the failed inits leave no secret key copy
 * in the caller's struct.
 *   F1  nodus_client_init returns -1 when epoll_create1 fails, and
 *       client->identity secret keys are all zero afterwards (C-12 path).
 *   F2  nodus_channel_init returns -1 when epoll_create1 fails, and
 *       ch->identity secret keys are all zero afterwards.
 *   F3  control: with epoll_create1 unarmed, both inits succeed (0), so the
 *       -1 above is caused by the epoll failure, not by the config.
 *
 * Isolation: epoll_create1 is interposed at link time (-Wl,--wrap=epoll_create1,
 * see CMakeLists.txt) and made to fail with EMFILE only while armed. Unlike a
 * full descriptor table, this leaves eventfd() working, so the later
 * nodus_inter_session_new() step (src/server/nodus_inter_session.c:292) would still
 * succeed: a client that ignores the nodus_tcp_init result returns 0 here and
 * F1 FAILS. Reverting only the client check therefore fails F1; reverting only
 * the channel check fails F2.
 *
 * Compile flags: none; link option -Wl,--wrap=epoll_create1. Environment:
 * none. Opens no ports and no files; leaves nothing behind.
 *
 * How it can lie: --wrap only catches calls resolved to the symbol
 * epoll_create1 from the linked objects (nodus_tcp.c is in the static nodus
 * library, which the linker wraps too); if the transport ever creates its
 * epoll another way, the F3 control still passes and F1/F2 would fail loudly
 * (init returns 0), not pass silently. The zero check covers the sk fields of
 * the identity, not copies elsewhere. Linux epoll native build only.
 */

#define _DEFAULT_SOURCE 1

#include "nodus/nodus.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/epoll.h>

static int passed = 0, failed = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS %s\n", name); passed++; } \
    else { printf("  FAIL %s\n", name); failed++; } } while (0)

static int g_fail_epoll = 0;

int __real_epoll_create1(int flags);
int __wrap_epoll_create1(int flags) {
    if (g_fail_epoll) {
        errno = EMFILE;
        return -1;
    }
    return __real_epoll_create1(flags);
}

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0) return 0;
    return 1;
}

static int secrets_wiped(const nodus_identity_t *id) {
    return all_zero(id->sk.bytes, NODUS_SK_BYTES) &&
           all_zero(id->kyber_sk, NODUS_KYBER_SK_BYTES) &&
           all_zero(id->mlkem_sk, NODUS_MLKEM_SK_BYTES);
}

static void make_cfg(nodus_client_config_t *cfg, nodus_key_t *fps) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->servers[0].ip, sizeof(cfg->servers[0].ip), "127.0.0.1");
    cfg->servers[0].port = 1;
    cfg->server_count = 1;
    cfg->pinned_server_fps = fps;
    cfg->pinned_server_fp_count = 1;
    memset(cfg->chain_id, 0x11, 32);
    cfg->has_chain_id = true;
}

int main(void) {
    printf("=== client init transport failure (C-14) ===\n");
    nodus_identity_t *id = calloc(1, sizeof(*id));
    if (!id || nodus_identity_generate(id) != 0) return 1;
    CHECK(!secrets_wiped(id), "precondition: generated identity has secret bytes");

    nodus_key_t fps[1];
    memset(fps, 0x22, sizeof(fps));
    nodus_client_config_t cfg;
    make_cfg(&cfg, fps);
    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_ch_conn_t *ch = calloc(1, sizeof(*ch));
    if (!c || !ch) return 1;

    g_fail_epoll = 1;
    int crc = nodus_client_init(c, &cfg, id);
    int hrc = nodus_channel_init(ch, "127.0.0.1", 1, id, NULL, NULL);
    g_fail_epoll = 0;
    CHECK(crc == -1, "F1 client init returns -1 when the transport cannot open");
    CHECK(secrets_wiped(&c->identity), "F1 client identity wiped after the failed init");
    CHECK(hrc == -1, "F2 channel init returns -1 when the transport cannot open");
    CHECK(secrets_wiped(&ch->identity), "F2 channel identity wiped after the failed init");

    /* F1t: local tool mode returns before the session module is created, so
     * the nodus_tcp_init check is the only thing that can refuse. */
    nodus_client_config_t tcfg;
    memset(&tcfg, 0, sizeof(tcfg));
    tcfg.local_tool_sock = "/nonexistent/nodus-tool.sock";
    memset(c, 0, sizeof(*c));
    g_fail_epoll = 1;
    crc = nodus_client_init(c, &tcfg, id);
    g_fail_epoll = 0;
    CHECK(crc == -1, "F1t tool-mode client init returns -1 when the transport cannot open");
    CHECK(secrets_wiped(&c->identity), "F1t tool-mode client identity wiped after the failed init");

    /* F3 control (normal mode and tool mode) */
    memset(c, 0, sizeof(*c));
    crc = nodus_client_init(c, &tcfg, id);
    CHECK(crc == 0, "F3 control: tool-mode init succeeds with epoll available");
    if (crc == 0) nodus_client_close(c);
    memset(c, 0, sizeof(*c));
    memset(ch, 0, sizeof(*ch));
    crc = nodus_client_init(c, &cfg, id);
    hrc = nodus_channel_init(ch, "127.0.0.1", 1, id, NULL, NULL);
    CHECK(crc == 0 && hrc == 0, "F3 control: both inits succeed with epoll available");
    if (crc == 0) nodus_client_close(c);
    if (hrc == 0) nodus_channel_close(ch);

    free(c);
    free(ch);
    nodus_identity_clear(id);
    free(id);
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
