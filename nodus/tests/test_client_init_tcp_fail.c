/**
 * Nodus — client init reports a failed transport open (BUGS.md C-14)
 *
 * What it proves: when nodus_tcp_init() cannot create its epoll descriptor
 * (descriptor table full, EMFILE), nodus_client_init() and nodus_channel_init()
 * return -1 instead of success with an unusable transport.
 *   F1  nodus_client_init returns -1 with the descriptor table full.
 *   F2  nodus_channel_init returns -1 with the descriptor table full.
 *   F3  control: after the descriptors are released, the same calls succeed
 *       (0) — so the -1 above is caused by the exhaustion, not by the config.
 *
 * The exhaustion runs in a forked child (the table is filled by dup() of
 * /dev/null until it fails; the parent's descriptors are untouched). The
 * child exits 0 when F1/F2 held, 1 otherwise; the parent runs F3 itself.
 *
 * Compile flags: none. Environment: none. Opens no ports, no files kept;
 * leaves nothing behind.
 *
 * How it can lie: init refuses for other reasons first (config), which F3
 * rules out; if the child cannot open /dev/null at all, it still fills
 * nothing and F1 would then fail on the control rather than pass falsely
 * (the child checks that at least one descriptor was taken, and that
 * epoll_create1 itself fails before the calls). Native Linux epoll build only.
 */

#define _DEFAULT_SOURCE 1

#include "nodus/nodus.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/wait.h>

static int passed = 0, failed = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS %s\n", name); passed++; } \
    else { printf("  FAIL %s\n", name); failed++; } } while (0)

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

static int run_calls(nodus_identity_t *id, int *client_rc, int *chan_rc) {
    nodus_key_t fps[1];
    memset(fps, 0x22, sizeof(fps));
    nodus_client_config_t cfg;
    make_cfg(&cfg, fps);
    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_ch_conn_t *ch = calloc(1, sizeof(*ch));
    if (!c || !ch) return -1;
    *client_rc = nodus_client_init(c, &cfg, id);
    *chan_rc = nodus_channel_init(ch, "127.0.0.1", 1, id, NULL, NULL);
    if (*client_rc == 0) nodus_client_close(c);
    if (*chan_rc == 0) nodus_channel_close(ch);
    free(c);
    free(ch);
    return 0;
}

int main(void) {
    printf("=== client init transport failure (C-14) ===\n");
    nodus_identity_t *id = calloc(1, sizeof(*id));
    if (!id || nodus_identity_generate(id) != 0) return 1;

    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        int taken = 0, fd;
        while ((fd = open("/dev/null", O_RDONLY)) >= 0) taken++;
        int ec = epoll_create1(EPOLL_CLOEXEC);
        if (taken == 0 || ec >= 0) _exit(2);   /* exhaustion did not work */
        int crc = 0, hrc = 0;
        if (run_calls(id, &crc, &hrc) != 0) _exit(3);
        _exit((crc == -1 && hrc == -1) ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    CHECK(code != 2, "exhaustion setup worked in the child");
    CHECK(code == 0, "F1/F2 client and channel init return -1 with no descriptor left");

    int crc = -9, hrc = -9;
    CHECK(run_calls(id, &crc, &hrc) == 0 && crc == 0 && hrc == 0,
          "F3 control: both inits succeed with descriptors available");

    nodus_identity_clear(id);
    free(id);
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
