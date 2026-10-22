/**
 * @file nodus/src/client/nodus_node_package.c
 * @brief `nodus-cli package` — see nodus_node_package.h for the contract.
 *
 * Not consensus code. The only clock read is CLOCK_MONOTONIC, to bound a
 * child process; a timeout always means "unknown -> refuse", never "allow".
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_node_package.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "client/nodus_consent_req.h"   /* identity_path + tcp_port          */
#include "client/nodus_node_status.h"   /* data_path                         */
#include "crypto/nodus_identity.h"      /* nodus_identity_load_readonly      */
#include "nodus/nodus_types.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

static const char *const NP_UNIT_NAMES[NODUS_NP_UNIT_COUNT] = {
    "nodus", "nodus-core", "nodus-storage", "nodus-witness"
};

const char *nodus_node_package_unit_name(nodus_np_unit_t unit) {
    if ((int)unit < 0 || (int)unit >= (int)NODUS_NP_UNIT_COUNT) return NULL;
    return NP_UNIT_NAMES[unit];
}

static const char *np_pkg_name(nodus_np_pkg_t pkg) {
    return pkg == NODUS_NP_PKG_WITNESS ? "witness" : "storage";
}

static nodus_np_unit_t np_pkg_unit(nodus_np_pkg_t pkg) {
    return pkg == NODUS_NP_PKG_WITNESS ? NODUS_NP_UNIT_WITNESS
                                       : NODUS_NP_UNIT_STORAGE;
}

static void np_err(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void np_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ── layout ──────────────────────────────────────────────────────── */

nodus_np_layout_t nodus_node_package_layout(const nodus_np_units_t *u) {
    if (!u) return NODUS_NP_LAYOUT_UNKNOWN;
    for (int i = 0; i < (int)NODUS_NP_UNIT_COUNT; i++)
        if (u->enabled[i] != NODUS_NP_ON && u->enabled[i] != NODUS_NP_OFF)
            return NODUS_NP_LAYOUT_UNKNOWN;
    const bool nodus   = u->enabled[NODUS_NP_UNIT_NODUS]   == NODUS_NP_ON;
    const bool core    = u->enabled[NODUS_NP_UNIT_CORE]    == NODUS_NP_ON;
    const bool storage = u->enabled[NODUS_NP_UNIT_STORAGE] == NODUS_NP_ON;
    const bool witness = u->enabled[NODUS_NP_UNIT_WITNESS] == NODUS_NP_ON;
    if (nodus) return (core || storage || witness) ? NODUS_NP_LAYOUT_AMBIGUOUS
                                                   : NODUS_NP_LAYOUT_COMBINED;
    if (core) return NODUS_NP_LAYOUT_SPLIT;
    if (storage || witness) return NODUS_NP_LAYOUT_AMBIGUOUS;
    return NODUS_NP_LAYOUT_NONE;
}

/* ── the verdict ─────────────────────────────────────────────────── */

bool nodus_node_package_unavailable(nodus_np_action_t action,
                                    nodus_np_pkg_t pkg) {
    return action == NODUS_NP_ACT_REMOVE && pkg == NODUS_NP_PKG_STORAGE;
}

/* True only for the two `systemctl is-active` words that mean "not running"
 * (inactive, failed). The busy words (active, activating, deactivating,
 * reloading, refreshing — website/install-node.sh unit_busy), every other
 * word and an unread "" are NOT idle. */
static bool np_combined_idle(const char *word) {
    return word && (strcmp(word, "inactive") == 0 ||
                    strcmp(word, "failed") == 0);
}

static void np_refuse(nodus_np_verdict_t *v, nodus_np_reason_t r) {
    v->outcome = NODUS_NP_OUT_REFUSE;
    v->reason  = r;
}

void nodus_node_package_verdict(const nodus_np_units_t *units,
                                nodus_np_action_t action, nodus_np_pkg_t pkg,
                                const nodus_dnac_node_duties_t *duties,
                                const char *read_error,
                                nodus_np_verdict_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

    /* 1. khan B: not in this version, whatever the states are */
    if (nodus_node_package_unavailable(action, pkg)) {
        np_refuse(out, NODUS_NP_R_STORAGE_UNAVAILABLE);
        return;
    }
    /* 2/3. every state read, and a clear three-service layout */
    const nodus_np_layout_t layout = nodus_node_package_layout(units);
    switch (layout) {
    case NODUS_NP_LAYOUT_UNKNOWN:   np_refuse(out, NODUS_NP_R_UNIT_UNKNOWN); return;
    case NODUS_NP_LAYOUT_COMBINED:  np_refuse(out, NODUS_NP_R_COMBINED);     return;
    case NODUS_NP_LAYOUT_AMBIGUOUS: np_refuse(out, NODUS_NP_R_AMBIGUOUS);    return;
    case NODUS_NP_LAYOUT_NONE:      np_refuse(out, NODUS_NP_R_NO_LAYOUT);    return;
    case NODUS_NP_LAYOUT_SPLIT:     break;
    }
    if ((int)action != NODUS_NP_ACT_ADD && (int)action != NODUS_NP_ACT_REMOVE) {
        np_refuse(out, NODUS_NP_R_UNIT_UNKNOWN);
        return;
    }
    /* 3b. a running combined server in a split-enabled host is a mixed
     * state: enabling a split unit (Conflicts= nodus.service) would stop
     * it, and its witness, with no duty read. Only the two idle words are
     * safe; an unread or unknown word refuses too. */
    if (!np_combined_idle(units->active[NODUS_NP_UNIT_NODUS])) {
        np_refuse(out, NODUS_NP_R_COMBINED_RUNNING);
        snprintf(out->why, sizeof(out->why), "%s",
                 units->active[NODUS_NP_UNIT_NODUS]);
        return;
    }

    const nodus_np_unit_t target = np_pkg_unit(pkg);
    const bool is_on = units->enabled[target] == NODUS_NP_ON;

    /* 4/5. add */
    if (action == NODUS_NP_ACT_ADD) {
        out->outcome = is_on ? NODUS_NP_OUT_ALREADY : NODUS_NP_OUT_DO;
        return;
    }
    /* 4. remove of one that is off: no chain read */
    if (!is_on) {
        out->outcome = NODUS_NP_OUT_ALREADY;
        return;
    }
    /* 6. decision item 12: nodus-core never runs alone. The other package
     * is the one that is not the target. */
    const nodus_np_unit_t other = target == NODUS_NP_UNIT_WITNESS
                                      ? NODUS_NP_UNIT_STORAGE
                                      : NODUS_NP_UNIT_WITNESS;
    if (units->enabled[other] != NODUS_NP_ON) {
        np_refuse(out, NODUS_NP_R_CORE_ALONE);
        return;
    }

    /* 7. remove witness of a witness that is on */
    if (!duties) {
        np_refuse(out, NODUS_NP_R_NOT_READ);
        snprintf(out->why, sizeof(out->why), "%s",
                 (read_error && read_error[0]) ? read_error : "not read");
        return;
    }
    if (duties->state == NODUS_DNAC_DUTIES_UNKNOWN ||
        (duties->state != NODUS_DNAC_DUTIES_CLEAR &&
         duties->state != NODUS_DNAC_DUTIES_BLOCKED)) {
        np_refuse(out, NODUS_NP_R_UNKNOWN);
        snprintf(out->why, sizeof(out->why), "%s",
                 duties->why[0] ? duties->why : "the witness could not "
                 "establish it");
        return;
    }
    if (!duties->fresh) {
        np_refuse(out, NODUS_NP_R_NOT_FRESH);
        return;
    }
    if (duties->state == NODUS_DNAC_DUTIES_CLEAR) {
        if (duties->n_blockers != 0) {         /* inconsistent: never allow */
            np_refuse(out, NODUS_NP_R_UNKNOWN);
            snprintf(out->why, sizeof(out->why), "inconsistent reply");
            return;
        }
        out->outcome = NODUS_NP_OUT_DO;
        return;
    }
    /* BLOCKED */
    if (duties->n_blockers == 0 ||
        duties->n_blockers > NODUS_DNAC_DUTIES_BL_MAX) {
        np_refuse(out, NODUS_NP_R_UNKNOWN);
        snprintf(out->why, sizeof(out->why), "inconsistent reply");
        return;
    }
    bool registered = false, leaving = false;
    for (size_t i = 0; i < duties->n_blockers; i++) {
        const uint8_t c = duties->blockers[i].code;
        const uint64_t eh = duties->blockers[i].end_height;
        if (c >= 1 && c <= NODUS_DNAC_DUTY_MAX)
            out->blocker_mask |= (uint32_t)1u << c;
        if (eh > out->end_height) out->end_height = eh;
        if (c == NODUS_DNAC_DUTY_WITNESS_REGISTERED ||
            c == NODUS_DNAC_DUTY_STORAGE_REGISTERED)
            registered = true;
        if (c == NODUS_DNAC_DUTY_WITNESS_LEAVING ||
            c == NODUS_DNAC_DUTY_STORAGE_LEAVING)
            leaving = true;
    }
    out->n_owners = duties->n_owners > NODUS_DNAC_DUTIES_OWNERS_MAX
                        ? NODUS_DNAC_DUTIES_OWNERS_MAX : duties->n_owners;
    for (size_t i = 0; i < out->n_owners; i++)
        snprintf(out->owners[i], sizeof(out->owners[i]), "%s",
                 duties->owners[i]);
    np_refuse(out, registered ? NODUS_NP_R_REGISTERED
                              : leaving ? NODUS_NP_R_LEAVING
                                        : NODUS_NP_R_DUTIES);
}

/* ── texts ───────────────────────────────────────────────────────── */

#define NP_NOTHING_CHANGED "Nothing was changed."

static const char *np_duty_name(unsigned c) {
    switch (c) {
    case NODUS_DNAC_DUTY_WITNESS_REGISTERED: return "registered as a witness";
    case NODUS_DNAC_DUTY_WITNESS_LEAVING:    return "leaving as a witness";
    case NODUS_DNAC_DUTY_SEATED_NOW:         return "seated in the current committee";
    case NODUS_DNAC_DUTY_SEATED_NEXT:        return "seated in the next committee";
    case NODUS_DNAC_DUTY_CMT_TRANSITION:     return "validator-set transition";
    case NODUS_DNAC_DUTY_STORAGE_REGISTERED: return "registered as a storage node";
    case NODUS_DNAC_DUTY_STORAGE_LEAVING:    return "leaving as a storage node";
    case NODUS_DNAC_DUTY_ARCHIVE_OVERLAP:    return "archive hand-over";
    case NODUS_DNAC_DUTY_STORAGE_REPORT:     return "storage report window";
    default:                                 return "unknown duty";
    }
}

/* append to out at *n (bounded, always terminated). A text that does not
 * fit sets *n = cap — the "overflowed" mark (a real length is always
 * < cap); every later np_cat is then a no-op. */
static void np_cat(char *out, size_t cap, size_t *n, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void np_cat(char *out, size_t cap, size_t *n, const char *fmt, ...) {
    if (*n >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    const int w = vsnprintf(out + *n, cap - *n, fmt, ap);
    va_end(ap);
    if (w < 0) return;
    if ((size_t)w < cap - *n) *n += (size_t)w;
    else *n = cap;
}

/* The fixed message of a text that did not fit: short, and it says that
 * nothing was changed (every long text is a refusal). */
#define NP_TOO_LONG "This answer is too long to show here. " NP_NOTHING_CHANGED "\n"

static size_t np_text_build(const nodus_np_verdict_t *v,
                            nodus_np_action_t action, nodus_np_pkg_t pkg,
                            char *out, size_t cap);

void nodus_node_package_verdict_text(const nodus_np_verdict_t *v,
                                     nodus_np_action_t action,
                                     nodus_np_pkg_t pkg,
                                     char *out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!v) return;
    if (np_text_build(v, action, pkg, out, cap) >= cap)
        snprintf(out, cap, "%s", NP_TOO_LONG);   /* fail closed */
}

static size_t np_text_build(const nodus_np_verdict_t *v,
                            nodus_np_action_t action, nodus_np_pkg_t pkg,
                            char *out, size_t cap) {
    size_t n = 0;
    const char *pn = np_pkg_name(pkg);
    switch (v->reason) {
    case NODUS_NP_R_NONE:
        if (v->outcome == NODUS_NP_OUT_ALREADY)
            np_cat(out, cap, &n, "%s is already %s. %s\n", pn,
                   action == NODUS_NP_ACT_ADD ? "on" : "off",
                   NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_UNIT_UNKNOWN:
        np_cat(out, cap, &n, "Cannot read the state of the Nodus services "
               "(systemctl did not answer as expected). %s\n",
               NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_COMBINED_RUNNING:
        np_cat(out, cap, &n, "nodus.service (the single-service layout) is "
               "%s on this node \xe2\x80\x94 a mixed state this command does "
               "not touch. %s\n",
               v->why[0] ? v->why : "in an unreadable state",
               NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_COMBINED:
        np_cat(out, cap, &n, "This node runs the single-service layout "
               "(nodus.service). Packages can be added or removed only on "
               "the three-service layout (nodus-core, nodus-storage, "
               "nodus-witness). %s\n", NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_AMBIGUOUS:
        np_cat(out, cap, &n, "The service layout is not clear: the "
               "single-service and the three-service units are both enabled, "
               "or a package is enabled without nodus-core. Repair that "
               "first (sudo nodus-cli status). %s\n", NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_NO_LAYOUT:
        np_cat(out, cap, &n, "No Nodus service is enabled on this host. %s\n",
               NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_CORE_ALONE:
        np_cat(out, cap, &n, "Cannot turn off %s: nodus-core never runs "
               "alone, and no other package is on. Turn the other package on "
               "first. %s\n", pn, NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_STORAGE_UNAVAILABLE:
        np_cat(out, cap, &n, "not available yet: a known DHT defect "
               "(BUGS.md D-23) must be fixed first \xe2\x80\x94 nothing was "
               "changed\n");
        break;
    case NODUS_NP_R_NOT_READ:
    case NODUS_NP_R_UNKNOWN:
    case NODUS_NP_R_NOT_FRESH:
        np_cat(out, cap, &n, "Cannot check whether this node is registered "
               "(%s). %s Start or repair the witness (sudo nodus-cli "
               "status), then try again.\n",
               v->reason == NODUS_NP_R_NOT_FRESH
                   ? "this node is not caught up with the chain; wait and "
                     "retry"
                   : v->why,
               NP_NOTHING_CHANGED);
        break;
    case NODUS_NP_R_REGISTERED: {
        const bool w = (v->blocker_mask >> NODUS_DNAC_DUTY_WITNESS_REGISTERED) & 1u;
        const bool s = (v->blocker_mask >> NODUS_DNAC_DUTY_STORAGE_REGISTERED) & 1u;
        np_cat(out, cap, &n, "Cannot turn off witness: this node is "
               "registered as %s owned by ",
               (w && s) ? "a witness and a storage node"
                        : s ? "a storage node" : "a witness");
        if (v->n_owners == 0) np_cat(out, cap, &n, "an owner unknown to this "
                                     "reply");
        for (size_t i = 0; i < v->n_owners; i++)
            np_cat(out, cap, &n, "%s%s", i ? ", " : "", v->owners[i]);
        np_cat(out, cap, &n, ". The owner must leave first in Nodus Connect "
               "(More \xe2\x86\x92 Nodus \xe2\x86\x92 My registered nodes). "
               "%s\n", NP_NOTHING_CHANGED);
        break;
    }
    case NODUS_NP_R_LEAVING: {
        const bool w = (v->blocker_mask >> NODUS_DNAC_DUTY_WITNESS_LEAVING) & 1u;
        const bool s = (v->blocker_mask >> NODUS_DNAC_DUTY_STORAGE_LEAVING) & 1u;
        np_cat(out, cap, &n, "This node is leaving as %s; nothing more is "
               "needed from the owner. Keep witness running until block "
               "%llu, then try again. %s\n",
               (w && s) ? "a witness and a storage node"
                        : s ? "a storage node" : "a witness",
               (unsigned long long)v->end_height, NP_NOTHING_CHANGED);
        break;
    }
    case NODUS_NP_R_DUTIES: {
        np_cat(out, cap, &n, "This node has left, but still has duties until "
               "block %llu (", (unsigned long long)v->end_height);
        bool first = true;
        for (unsigned c = 1; c <= NODUS_DNAC_DUTY_MAX; c++) {
            if (!((v->blocker_mask >> c) & 1u)) continue;
            np_cat(out, cap, &n, "%s%s", first ? "" : ", ", np_duty_name(c));
            first = false;
        }
        np_cat(out, cap, &n, "). Try again after block %llu. %s\n",
               (unsigned long long)v->end_height, NP_NOTHING_CHANGED);
        break;
    }
    }
    return n;
}

/* ── the child runner (systemd adapter) ──────────────────────────── */

typedef struct {
    bool ran;          /* the child was started and reaped               */
    bool timed_out;    /* killed past its deadline                       */
    int  exit_code;    /* WEXITSTATUS, -1 when it did not exit normally  */
    char line[64];     /* first stdout line (sanitised)                  */
} np_run_t;

static int64_t np_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void np_ms_sleep(long ms) {
    struct timespec ts = { 0, ms * 1000000L };
    nanosleep(&ts, NULL);
}

/* The path must be a regular file (stat follows a symlink such as the
 * usr-merge /bin) that this user may execute. */
static int np_exe_ok(const char *path) {
    struct stat st;
    if (!path || path[0] != '/') return 0;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    return access(path, X_OK) == 0;
}

/* argv is fixed by the caller (argv[0] = absolute path). stdin and stderr
 * are /dev/null, stdout is a pipe, the environment is a fixed minimum. */
static void np_run(const char *const argv[], int deadline_ms, np_run_t *r) {
    memset(r, 0, sizeof(*r));
    r->exit_code = -1;
    int pfd[2];
    if (pipe(pfd) != 0) return;
    /* close-on-exec on both ends: the child's stdout is a dup2 copy */
    if (fcntl(pfd[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pfd[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(pfd[0]);
        close(pfd[1]);
        return;
    }
    const int64_t end = np_now_ms() + (deadline_ms > 0 ? deadline_ms : 1);
    const pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return;
    }
    if (pid == 0) {
        static char *const envp[] = { (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                                      (char *)"LC_ALL=C", NULL };
        const int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) {
            dup2(nul, STDIN_FILENO);
            dup2(nul, STDERR_FILENO);
        }
        dup2(pfd[1], STDOUT_FILENO);   /* dup2 clears O_CLOEXEC on the copy */
        execve(argv[0], (char *const *)argv, envp);
        _exit(127);
    }
    close(pfd[1]);

    char raw[64];
    size_t got = 0;
    bool eof = false;
    while (!eof) {
        const int64_t left = end - np_now_ms();
        if (left <= 0) { r->timed_out = true; break; }
        struct pollfd p = { pfd[0], POLLIN, 0 };
        const int pr = poll(&p, 1, left > 1000000 ? 1000000 : (int)left);
        if (pr < 0) {
            if (errno == EINTR) continue;
            r->timed_out = true;       /* cannot supervise it: treat as lost */
            break;
        }
        if (pr == 0) continue;         /* the deadline check is at the top */
        char buf[64];
        const ssize_t k = read(pfd[0], buf, sizeof(buf));
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { eof = true; break; }
        for (ssize_t i = 0; i < k && got + 1u < sizeof(raw); i++)
            raw[got++] = buf[i];
    }
    close(pfd[0]);

    int status = 0;
    bool reaped = false;
    if (!r->timed_out) {
        for (;;) {
            const pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid) { reaped = true; break; }
            if (w < 0 && errno != EINTR) break;
            if (np_now_ms() >= end) { r->timed_out = true; break; }
            np_ms_sleep(2);
        }
    }
    if (!reaped) {                      /* past the deadline: kill and reap */
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }
    r->ran = true;
    r->exit_code = (reaped && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;

    raw[got] = '\0';
    size_t o = 0;
    for (size_t i = 0; i < got && raw[i] != '\n' && raw[i] != '\r' &&
                       o + 1u < sizeof(r->line); i++)
        r->line[o++] = (raw[i] >= 0x20 && raw[i] < 0x7f) ? raw[i] : '?';
    r->line[o] = '\0';
}

/* The fixed argument table: a verb is one row, the unit name comes from
 * NP_UNIT_NAMES. Nothing the user typed reaches an argv. */
typedef enum { NP_V_IS_ENABLED, NP_V_IS_ACTIVE, NP_V_ENABLE_NOW,
               NP_V_DISABLE_NOW } np_verb_t;

static void np_exec(const nodus_np_sysd_t *s, np_verb_t verb,
                    nodus_np_unit_t unit, np_run_t *r) {
    const char *const name = NP_UNIT_NAMES[unit];
    const char *av[5];
    int n = 0;
    av[n++] = s->systemctl;
    int ms = s->query_ms;
    switch (verb) {
    case NP_V_IS_ENABLED:  av[n++] = "is-enabled"; break;
    case NP_V_IS_ACTIVE:   av[n++] = "is-active";  break;
    case NP_V_ENABLE_NOW:  av[n++] = "enable";  av[n++] = "--now";
                           ms = s->change_ms; break;
    case NP_V_DISABLE_NOW: av[n++] = "disable"; av[n++] = "--now";
                           ms = s->change_ms; break;
    }
    av[n++] = name;
    av[n]   = NULL;
    np_run(av, ms, r);
}

static bool np_ran_ok(const np_run_t *r) {
    return r->ran && !r->timed_out && r->exit_code != 127 &&
           r->exit_code != -1;
}

void nodus_node_package_sysd_default(nodus_np_sysd_t *s) {
    if (!s) return;
    s->systemctl = NODUS_NODE_PACKAGE_SYSTEMCTL;
    s->query_ms  = NODUS_NODE_PACKAGE_QUERY_MS;
    s->change_ms = NODUS_NODE_PACKAGE_CHANGE_MS;
}

static nodus_np_state_t np_state_of(const np_run_t *r) {
    if (!np_ran_ok(r)) return NODUS_NP_UNKNOWN;
    if (strcmp(r->line, "enabled") == 0)  return NODUS_NP_ON;
    if (strcmp(r->line, "disabled") == 0) return NODUS_NP_OFF;
    return NODUS_NP_UNKNOWN;
}

int nodus_node_package_read_units(const nodus_np_sysd_t *s,
                                  nodus_np_units_t *out,
                                  char *err, size_t errcap) {
    if (!s || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!np_exe_ok(s->systemctl)) {
        np_err(err, errcap, "%s is not an executable regular file",
               s->systemctl ? s->systemctl : "(null)");
        return -1;
    }
    for (int u = 0; u < (int)NODUS_NP_UNIT_COUNT; u++) {
        np_run_t r;
        np_exec(s, NP_V_IS_ENABLED, (nodus_np_unit_t)u, &r);
        out->enabled[u] = np_state_of(&r);
        np_exec(s, NP_V_IS_ACTIVE, (nodus_np_unit_t)u, &r);
        /* is-active exits non-zero for every state but "active"; only a
         * child that did not run / was killed leaves the text empty */
        if (np_ran_ok(&r))
            snprintf(out->active[u], sizeof(out->active[u]), "%s", r.line);
    }
    return 0;
}

int nodus_node_package_change(const nodus_np_sysd_t *s, nodus_np_unit_t unit,
                              bool enable, char *err, size_t errcap) {
    /* only the two packages may be changed; core and the combined unit
     * never */
    if (!s || (unit != NODUS_NP_UNIT_STORAGE && unit != NODUS_NP_UNIT_WITNESS)) {
        np_err(err, errcap, "internal error: unit not changeable");
        return -1;
    }
    if (!np_exe_ok(s->systemctl)) {
        np_err(err, errcap, "%s is not an executable regular file",
               s->systemctl ? s->systemctl : "(null)");
        return -1;
    }
    np_run_t r;
    np_exec(s, enable ? NP_V_ENABLE_NOW : NP_V_DISABLE_NOW, unit, &r);
    if (r.timed_out) {
        np_err(err, errcap, "systemctl did not finish in time and was "
               "stopped; the unit may be half-changed (check: systemctl "
               "status %s)", NP_UNIT_NAMES[unit]);
        return -1;
    }
    if (!r.ran || r.exit_code != 0) {
        np_err(err, errcap, "systemctl %s --now %s failed (exit %d); the "
               "unit may be half-changed (check: systemctl status %s)",
               enable ? "enable" : "disable", NP_UNIT_NAMES[unit],
               r.exit_code, NP_UNIT_NAMES[unit]);
        return -1;
    }
    np_exec(s, NP_V_IS_ENABLED, unit, &r);
    const nodus_np_state_t post = np_state_of(&r);
    if (post != (enable ? NODUS_NP_ON : NODUS_NP_OFF)) {
        np_err(err, errcap, "systemctl said it succeeded, but %s is not %s "
               "afterwards (is-enabled: \"%s\"); check: systemctl status %s",
               NP_UNIT_NAMES[unit], enable ? "enabled" : "disabled",
               r.line, NP_UNIT_NAMES[unit]);
        return -1;
    }
    return 0;
}

/* ── the host lock ───────────────────────────────────────────────── */

/* the file at `path` is not one this tool may lock (see the header) */
static int np_lock_unsafe(const char *path, char *err, size_t errcap) {
    np_err(err, errcap, "%s is not a root-owned 0600 regular file; remove it "
           "and retry. " NP_NOTHING_CHANGED, path);
    return -2;
}

int nodus_node_package_lock_take(const char *path, uid_t owner, int *fd_out,
                                 char *err, size_t errcap) {
    if (!path || !fd_out) return -1;
    *fd_out = -1;
    int fd = -1;
    /* an existing file first; created only when missing. Two tries cover
     * another process creating it between our open and our create.
     * O_NOFOLLOW: a symlink planted in /run/lock is refused (ELOOP);
     * O_NONBLOCK: a planted FIFO cannot hang the open. */
    for (int attempt = 0; attempt < 2 && fd < 0; attempt++) {
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (fd >= 0) break;
        if (errno == ELOOP) return np_lock_unsafe(path, err, errcap);
        if (errno != ENOENT) {
            np_err(err, errcap, "cannot open the host lock %s: %s", path,
                   strerror(errno));
            return -1;
        }
        fd = open(path, O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                            O_NONBLOCK, 0600);
        if (fd >= 0) {
            /* the umask must not decide the mode */
            if (fchmod(fd, 0600) != 0) {
                np_err(err, errcap, "cannot set the mode of %s: %s", path,
                       strerror(errno));
                close(fd);
                return -1;
            }
            break;
        }
        if (errno == ELOOP) return np_lock_unsafe(path, err, errcap);
        if (errno != EEXIST) {
            np_err(err, errcap, "cannot create the host lock %s: %s", path,
                   strerror(errno));
            return -1;
        }
    }
    if (fd < 0) {
        np_err(err, errcap, "cannot open the host lock %s", path);
        return -1;
    }
    /* fstat on the open descriptor: what is vetted is what is locked */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        np_err(err, errcap, "cannot inspect the host lock %s: %s", path,
               strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(fd);
        return np_lock_unsafe(path, err, errcap);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        const int e = errno;
        close(fd);
        if (e == EWOULDBLOCK) return 1;
        np_err(err, errcap, "cannot lock %s: %s", path, strerror(e));
        return -1;
    }
    *fd_out = fd;
    return 0;
}

void nodus_node_package_lock_release(int fd) {
    if (fd >= 0) close(fd);     /* closing drops the flock */
}

/* ── registration read ───────────────────────────────────────────── */

int nodus_node_package_read_duties(const char *config_path,
                                   nodus_dnac_node_duties_t *out,
                                   char *err, size_t errcap) {
    if (!config_path || !out) return -1;
    memset(out, 0, sizeof(*out));
    char identity_path[512];
    uint16_t port = NODUS_DEFAULT_TCP_PORT;
    char cerr[256] = "";
    if (nodus_consent_req_read_config(config_path, identity_path,
                                      sizeof(identity_path), &port, cerr,
                                      sizeof(cerr)) != 0) {
        np_err(err, errcap, "cannot read the node config: %s", cerr);
        return -1;
    }
    /* the loader that never writes a file (only nodus-core writes the
     * identity); nodus_identity_load is NOT used */
    nodus_identity_t id;
    memset(&id, 0, sizeof(id));
    if (nodus_identity_load_readonly(identity_path, &id) != 0) {
        nodus_identity_clear(&id);
        np_err(err, errcap, "cannot load the node key from %s (run with "
               "sudo?)", identity_path);
        return -1;
    }
    /* the pin: this node's own id; the array outlives the client */
    nodus_key_t pin = id.node_id;

    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port        = port;
    cfg.server_count           = 1;
    cfg.auto_reconnect         = false;
    cfg.connect_timeout_ms     = 5000;
    cfg.request_timeout_ms     = 10000;
    cfg.pinned_server_fps      = &pin;
    cfg.pinned_server_fp_count = 1;

    int rc = -1;
    if (nodus_client_init(&client, &cfg, &id) != 0) {
        np_err(err, errcap, "cannot start a client session");
        goto done;
    }
    if (nodus_client_connect(&client) != 0) {
        np_err(err, errcap, "no pinned, authenticated session to "
               "127.0.0.1:%u (the witness is down, or the node there does "
               "not hold this node's key)", (unsigned)port);
        nodus_client_close(&client);
        goto done;
    }
    {
        const int q = nodus_client_dnac_node_duties(&client, out);
        nodus_client_close(&client);
        if (q == 0) {
            rc = 0;
        } else {
            memset(out, 0, sizeof(*out));
            switch (q) {
            case NODUS_ERR_NOT_AUTHENTICATED:
                np_err(err, errcap, "the node did not accept its own key "
                       "for this question"); break;
            case NODUS_ERR_TIMEOUT:
                np_err(err, errcap, "the node did not answer in time"); break;
            case NODUS_ERR_NOT_FOUND:
                np_err(err, errcap, "the node has no chain yet"); break;
            case NODUS_ERR_PROTOCOL_ERROR:
                np_err(err, errcap, "the node answered an error or a reply "
                       "this tool cannot read (is the witness running and "
                       "up to date? \"witness module not enabled\" also "
                       "lands here)"); break;
            case -1:
                np_err(err, errcap, "no usable reply"); break;
            default:
                np_err(err, errcap, "the node answered error %d", q); break;
            }
        }
    }
done:
    nodus_identity_clear(&id);
    return rc;
}

/* ── addr_seq (decision item 21) ─────────────────────────────────── */

static int np_present(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

int nodus_node_package_addr_seq(const char *identity_path,
                                const char *data_path, bool *moved,
                                char *err, size_t errcap) {
    if (moved) *moved = false;
    if (!identity_path || !data_path) return -1;
    if (strcmp(identity_path, data_path) == 0) return 0;
    char old_p[1024], new_p[1024];
    if (snprintf(old_p, sizeof(old_p), "%s/%s", identity_path,
                 NODUS_NODE_PACKAGE_ADDR_SEQ) >= (int)sizeof(old_p) ||
        snprintf(new_p, sizeof(new_p), "%s/%s", data_path,
                 NODUS_NODE_PACKAGE_ADDR_SEQ) >= (int)sizeof(new_p)) {
        np_err(err, errcap, "the identity or data path is too long");
        return -1;
    }
    const int has_old = np_present(old_p), has_new = np_present(new_p);
    if (has_old && has_new) {
        np_err(err, errcap, "both %s and %s exist \xe2\x80\x94 cannot tell "
               "which address-record sequence is current. Keep the right "
               "one, remove the other, run again", old_p, new_p);
        return -1;
    }
    if (!has_old) return 0;
    if (rename(old_p, new_p) != 0) {
        np_err(err, errcap, "cannot move %s to %s: %s", old_p, new_p,
               strerror(errno));
        return -1;
    }
    if (moved) *moved = true;
    return 0;
}

/* ── the command ─────────────────────────────────────────────────── */

static const char *np_en_text(nodus_np_state_t s) {
    return s == NODUS_NP_ON ? "enabled" : s == NODUS_NP_OFF ? "disabled"
                                                            : "unknown";
}

#define NP_USAGE "Usage: sudo nodus-cli package list | add <witness|storage> " \
                 "| remove <witness|storage>\n"

static int np_list(const nodus_np_sysd_t *sysd, char *out, size_t cap) {
    size_t n = 0;
    nodus_np_units_t u;
    char e[160] = "";
    if (nodus_node_package_read_units(sysd, &u, e, sizeof(e)) != 0) {
        np_cat(out, cap, &n, "Cannot read the Nodus services: %s\n", e);
        return 1;
    }
    switch (nodus_node_package_layout(&u)) {
    case NODUS_NP_LAYOUT_COMBINED:
        np_cat(out, cap, &n, "Layout: single-service (nodus.service)\n"
               "This node runs the single-service layout; packages exist "
               "only on the three-service layout (nodus-core, "
               "nodus-storage, nodus-witness).\n");
        return 0;
    case NODUS_NP_LAYOUT_SPLIT:
        np_cat(out, cap, &n, "Layout: three-service (nodus-core + packages)\n");
        break;
    case NODUS_NP_LAYOUT_AMBIGUOUS:
        np_cat(out, cap, &n, "Layout: unclear (the single-service and the "
               "three-service units are both enabled, or a package is "
               "enabled without nodus-core)\n");
        break;
    case NODUS_NP_LAYOUT_NONE:
        np_cat(out, cap, &n, "Layout: none (no Nodus service is enabled)\n");
        break;
    case NODUS_NP_LAYOUT_UNKNOWN:
        np_cat(out, cap, &n, "Layout: unknown (a service state could not be "
               "read)\n");
        break;
    }
    /* `list` only reports it; add / remove refuse (NODUS_NP_R_COMBINED_RUNNING) */
    if (!np_combined_idle(u.active[NODUS_NP_UNIT_NODUS]))
        np_cat(out, cap, &n, "Warning: nodus.service (the single-service "
               "layout) is %s on this node \xe2\x80\x94 a mixed state; "
               "package add and remove are refused until it is stopped.\n",
               u.active[NODUS_NP_UNIT_NODUS][0]
                   ? u.active[NODUS_NP_UNIT_NODUS] : "in an unreadable state");
    np_cat(out, cap, &n, "nodus-core: %s, %s\n",
           np_en_text(u.enabled[NODUS_NP_UNIT_CORE]),
           u.active[NODUS_NP_UNIT_CORE][0] ? u.active[NODUS_NP_UNIT_CORE]
                                           : "unknown");
    for (int p = 0; p < 2; p++) {
        const nodus_np_pkg_t pkg = p == 0 ? NODUS_NP_PKG_WITNESS
                                          : NODUS_NP_PKG_STORAGE;
        const nodus_np_unit_t un = np_pkg_unit(pkg);
        const nodus_np_state_t st = u.enabled[un];
        np_cat(out, cap, &n, "%s: %s (%s: %s, %s)\n", np_pkg_name(pkg),
               st == NODUS_NP_ON ? "on" : st == NODUS_NP_OFF ? "off"
                                                             : "unknown",
               NP_UNIT_NAMES[un], np_en_text(st),
               u.active[un][0] ? u.active[un] : "unknown");
    }
    return 0;
}

int nodus_node_package_main(const char *const *args, int nargs,
                            const nodus_np_sysd_t *sysd,
                            const char *lock_path, uid_t lock_owner,
                            const char *config_path,
                            char *out, size_t outcap) {
    if (!out || outcap == 0) return 1;
    out[0] = '\0';
    size_t n = 0;
    if (!args || nargs < 1 || !sysd || !lock_path || !config_path) {
        np_cat(out, outcap, &n, NP_USAGE);
        return 1;
    }
    if (strcmp(args[0], "list") == 0) {
        if (nargs != 1) { np_cat(out, outcap, &n, NP_USAGE); return 1; }
        return np_list(sysd, out, outcap);
    }
    nodus_np_action_t action;
    if (strcmp(args[0], "add") == 0) action = NODUS_NP_ACT_ADD;
    else if (strcmp(args[0], "remove") == 0) action = NODUS_NP_ACT_REMOVE;
    else { np_cat(out, outcap, &n, NP_USAGE); return 1; }
    if (nargs != 2) { np_cat(out, outcap, &n, NP_USAGE); return 1; }
    nodus_np_pkg_t pkg;
    if (strcmp(args[1], "witness") == 0) pkg = NODUS_NP_PKG_WITNESS;
    else if (strcmp(args[1], "storage") == 0) pkg = NODUS_NP_PKG_STORAGE;
    else { np_cat(out, outcap, &n, NP_USAGE); return 1; }

    nodus_np_verdict_t v;

    /* not available in this version: no lock, no state read needed */
    if (nodus_node_package_unavailable(action, pkg)) {
        nodus_node_package_verdict(NULL, action, pkg, NULL, NULL, &v);
        nodus_node_package_verdict_text(&v, action, pkg, out, outcap);
        return 1;
    }

    /* the host lock: taken BEFORE any unit state is read, held until the
     * command ends */
    int lock_fd = -1;
    char e[512] = "";
    const int lk = nodus_node_package_lock_take(lock_path, lock_owner,
                                                &lock_fd, e, sizeof(e));
    if (lk == 1) {
        np_cat(out, outcap, &n, "another Nodus install, update or package "
               "change is running on this host \xe2\x80\x94 nothing was "
               "changed\n");
        return 1;
    }
    if (lk == -2) {              /* the lock file itself is not acceptable */
        np_cat(out, outcap, &n, "%s\n", e);
        return 1;
    }
    if (lk != 0) {
        np_cat(out, outcap, &n, "Cannot take the host lock: %s. %s\n", e,
               NP_NOTHING_CHANGED);
        return 1;
    }

    int rc = 1;
    nodus_np_units_t units;
    if (nodus_node_package_read_units(sysd, &units, e, sizeof(e)) != 0) {
        np_cat(out, outcap, &n, "Cannot read the Nodus services: %s. %s\n", e,
               NP_NOTHING_CHANGED);
        goto done;
    }

    /* first pass without a reply: only `remove witness` of a witness that
     * is on, in a clear three-service layout and not leaving core alone,
     * comes back NOT_READ — exactly the case that needs the chain read */
    nodus_node_package_verdict(&units, action, pkg, NULL, "not read", &v);
    if (v.outcome == NODUS_NP_OUT_REFUSE && v.reason == NODUS_NP_R_NOT_READ) {
        nodus_dnac_node_duties_t d;
        char rerr[256] = "";
        if (nodus_node_package_read_duties(config_path, &d, rerr,
                                           sizeof(rerr)) == 0)
            nodus_node_package_verdict(&units, action, pkg, &d, NULL, &v);
        else
            nodus_node_package_verdict(&units, action, pkg, NULL, rerr, &v);
    }

    /* out is still empty here (every earlier path returned), so the text is
     * built straight into it: a refusal too long for `out` becomes the
     * short fixed "Nothing was changed." message, never a cut sentence */
    if (v.outcome == NODUS_NP_OUT_REFUSE) {
        nodus_node_package_verdict_text(&v, action, pkg, out, outcap);
        goto done;
    }
    if (v.outcome == NODUS_NP_OUT_ALREADY) {
        nodus_node_package_verdict_text(&v, action, pkg, out, outcap);
        rc = 0;
        goto done;
    }

    /* DO. `add witness`: the item-21 rule before the first start */
    if (action == NODUS_NP_ACT_ADD && pkg == NODUS_NP_PKG_WITNESS) {
        char idp[512];
        uint16_t port = NODUS_DEFAULT_TCP_PORT;
        nodus_node_status_config_t cfg;
        char cerr[256] = "";
        if (nodus_consent_req_read_config(config_path, idp, sizeof(idp),
                                          &port, cerr, sizeof(cerr)) != 0 ||
            nodus_node_status_read_config(config_path, &cfg, cerr,
                                          sizeof(cerr)) != 0) {
            np_cat(out, outcap, &n, "Cannot read the node config (%s). %s\n",
                   cerr, NP_NOTHING_CHANGED);
            goto done;
        }
        bool moved = false;
        if (nodus_node_package_addr_seq(idp, cfg.data_path, &moved, e,
                                        sizeof(e)) != 0) {
            np_cat(out, outcap, &n, "Cannot turn on witness: %s. %s\n", e,
                   NP_NOTHING_CHANGED);
            goto done;
        }
        if (moved)
            np_cat(out, outcap, &n, "Moved %s/%s to %s/%s.\n", idp,
                   NODUS_NODE_PACKAGE_ADDR_SEQ, cfg.data_path,
                   NODUS_NODE_PACKAGE_ADDR_SEQ);
    }

    if (nodus_node_package_change(sysd, np_pkg_unit(pkg),
                                  action == NODUS_NP_ACT_ADD, e,
                                  sizeof(e)) != 0) {
        np_cat(out, outcap, &n, "Cannot turn %s %s: %s\n",
               action == NODUS_NP_ACT_ADD ? "on" : "off", np_pkg_name(pkg), e);
        goto done;
    }
    if (action == NODUS_NP_ACT_ADD)
        np_cat(out, outcap, &n, "%s is now on (enabled and started).\n",
               np_pkg_name(pkg));
    else
        np_cat(out, outcap, &n, "%s is now off (stopped and disabled). Its "
               "data and the node identity were kept.\n", np_pkg_name(pkg));
    rc = 0;
done:
    nodus_node_package_lock_release(lock_fd);
    return rc;
}
