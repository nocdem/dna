/**
 * test_nodus_log_shim — the opt-in log file of src/nodus_log_shim.c
 * (operator 2026-11-11 "log DOSYASI!", givens item 106).
 *
 * Selected by `ctest -R log_shim` (and by `ctest -R amm`: the bot's log file is
 * this sink; the registration sits next to the AMM tests).
 *
 * PROVES
 *   L1  off by default: a WARN line before nodus_log_file_open() creates no
 *       file in the directory; bad arguments to open are refused and open
 *       nothing.
 *   L2  after open, a WARN line lands in <dir>/nodus-amm.log as
 *       "YYYY-MM-DDTHH:MM:SS.mmmZ [WRN] TAG: text" (format checked by position),
 *       one line per call, a newline inside the text does not make a second
 *       line, mode 0640; a line of 3000 bytes is cut below 1024 and still ends
 *       with one newline; an INFO line is written, and the file is appended to
 *       by a second open (not truncated).
 *   L3  rotation: with max_bytes 200 and keep 3, enough lines make .log, .1, .2
 *       and .3 and never a .4; the newest lines are in .log.
 *   L4  two threads writing 400 lines each concurrently: every line of the file
 *       is whole (format and payload intact), 800 lines in total, none lost, none
 *       interleaved.
 *   L5  after nodus_log_file_close() a line writes nothing more.
 * BUILD FLAGS: default (the standalone nodus build, whose logger is the shim).
 * ENVIRONMENT: none. LEAVES BEHIND: nothing (one mkdtemp directory under /tmp,
 *   its files removed at the end).
 * HOW IT CAN FALSELY PASS: the timestamp is checked for shape (digits, 'T', 'Z',
 *   milliseconds), not for being the current time; the concurrency check proves
 *   whole lines in one run of 800, not the absence of every race; "off by
 *   default" is checked only in a fresh process (this one), as the first step.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "nodus_log_shim.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static char g_dir[64];

static int count_entries(void) {
    DIR *d = opendir(g_dir);
    int n = 0;
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    if (d) closedir(d);
    return n;
}

static char *slurp(const char *name, size_t *len) {
    char path[160];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { *len = 0; return NULL; }
    char *buf = malloc(1 << 20);
    *len = fread(buf, 1, (1 << 20) - 1, f);
    buf[*len] = '\0';
    fclose(f);
    return buf;
}

/* "2026-11-11T18:12:40.123Z [WRN] " at the start of `s` */
static int has_stamp(const char *s, const char *lvl) {
    static const char pat[] = "dddd-dd-ddTdd:dd:dd.dddZ [";
    for (size_t i = 0; pat[i]; i++) {
        if (pat[i] == 'd' ? !isdigit((unsigned char)s[i]) : s[i] != pat[i]) return 0;
    }
    return !strncmp(s + 26, lvl, 3) && !strncmp(s + 29, "] ", 2);
}

static int count_lines(const char *s) {
    int n = 0;
    for (; *s; s++) n += (*s == '\n');
    return n;
}

static void l1_off(void) {
    printf("L1 off by default, bad arguments\n");
    QGP_LOG_WARN("T1", "before open %d", 1);
    CHECK(count_entries() == 0, "a WARN line before open creates no file");
    CHECK(nodus_log_file_open(NULL, 100, 1) != 0 && nodus_log_file_open("", 100, 1) != 0 &&
          nodus_log_file_open(g_dir, 0, 1) != 0 && nodus_log_file_open(g_dir, 100, 0) != 0,
          "open refuses a NULL or empty directory, max_bytes 0 and keep 0");
    char longd[300];
    memset(longd, 'a', sizeof(longd) - 1); longd[0] = '/'; longd[299] = '\0';
    CHECK(nodus_log_file_open(longd, 100, 1) != 0, "open refuses a directory over 200 bytes");
    CHECK(nodus_log_file_open("/proc/nonexistent-dir/x", 100, 1) != 0,
          "open refuses a directory it cannot use");
    QGP_LOG_WARN("T1", "after refused opens");
    CHECK(count_entries() == 0, "refused opens left the sink off");
}

static void l2_line(void) {
    printf("L2 the line\n");
    CHECK(nodus_log_file_open(g_dir, 1 << 20, 3) == 0, "open");
    QGP_LOG_WARN("AMM_RPC", "hello %d", 42);
    QGP_LOG_INFO("TAGB", "info line");
    QGP_LOG_WARN("TAGC", "two\nlines\r\nin one call\n");
    char big[3001];
    memset(big, 'x', 3000); big[3000] = '\0';
    QGP_LOG_ERROR("BIG", "%s", big);
    size_t len;
    char *s = slurp("nodus-amm.log", &len);
    CHECK(s != NULL, "the file nodus-amm.log exists");
    if (!s) return;
    CHECK(count_lines(s) == 4, "four calls, four lines (a newline inside the text is not a second line)");
    CHECK(has_stamp(s, "WRN") && !strncmp(s + 31, "AMM_RPC: hello 42\n", 18),
          "first line: UTC stamp with milliseconds, [WRN], tag, text");
    char *l2 = strchr(s, '\n') + 1;
    CHECK(has_stamp(l2, "INF") && !strncmp(l2 + 31, "TAGB: info line\n", 16), "an INFO line is written");
    char *l3 = strchr(l2, '\n') + 1;
    CHECK(has_stamp(l3, "WRN") && !strncmp(l3 + 31, "TAGC: two lines  in one call\n", 29),
          "newlines inside the text became spaces, the trailing ones are dropped");
    char *l4 = strchr(l3, '\n') + 1;
    size_t l4len = strlen(l4);
    CHECK(has_stamp(l4, "ERR") && l4len < 1024 && l4len > 900 && l4[l4len - 1] == '\n',
          "a 3000-byte text is cut below 1024 bytes and still ends in one newline");
    free(s);
    struct stat st;
    char path[160];
    snprintf(path, sizeof(path), "%s/nodus-amm.log", g_dir);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640, "mode 0640 (umask 022 here)");
    nodus_log_file_close();
    QGP_LOG_WARN("T2", "second session");
    CHECK(nodus_log_file_open(g_dir, 1 << 20, 3) == 0, "open again");
    QGP_LOG_WARN("T2", "second session");
    s = slurp("nodus-amm.log", &len);
    CHECK(s && count_lines(s) == 5 && strstr(s, "AMM_RPC: hello 42") != NULL,
          "a second open appends; the first lines are still there; the line while closed is absent");
    free(s);
    nodus_log_file_close();
}

static void l3_rotation(void) {
    printf("L3 rotation\n");
    CHECK(nodus_log_file_open(g_dir, 200, 3) == 0, "open with max_bytes 200, keep 3");
    for (int i = 0; i < 40; i++) QGP_LOG_WARN("ROT", "line number %02d padding padding", i);
    nodus_log_file_close();
    char name[32];
    int have[6] = {0};
    for (int i = 1; i <= 5; i++) {
        snprintf(name, sizeof(name), "nodus-amm.log.%d", i);
        char path[160];
        snprintf(path, sizeof(path), "%s/%s", g_dir, name);
        have[i] = access(path, F_OK) == 0;
    }
    CHECK(have[1] && have[2] && have[3], "nodus-amm.log.1, .2 and .3 exist");
    CHECK(!have[4] && !have[5], "no .4: at most keep_files rotated files");
    size_t len;
    char *s = slurp("nodus-amm.log", &len);
    CHECK(s && strstr(s, "ROT: line number 39 ") != NULL, "the newest line is in the current file");
    free(s);
    s = slurp("nodus-amm.log.1", &len);
    CHECK(s && len >= 200 && strstr(s, "ROT: line number") != NULL, ".1 holds a full older file");
    free(s);
}

#define THREAD_LINES 400
static void *writer(void *arg) {
    const char *tag = arg;
    for (int i = 0; i < THREAD_LINES; i++) QGP_LOG_WARN(tag, "payload-%s-%04d-end", tag, i);
    return NULL;
}

static void l4_threads(void) {
    printf("L4 two threads\n");
    char path[160];
    snprintf(path, sizeof(path), "%s/nodus-amm.log", g_dir);
    unlink(path);
    CHECK(nodus_log_file_open(g_dir, 1u << 30, 1) == 0, "open with a large max_bytes");
    pthread_t a, b;
    pthread_create(&a, NULL, writer, "TA");
    pthread_create(&b, NULL, writer, "TB");
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    nodus_log_file_close();
    size_t len;
    char *s = slurp("nodus-amm.log", &len);
    CHECK(s != NULL && count_lines(s) == 2 * THREAD_LINES, "800 lines, none lost");
    int whole = 1, na = 0, nb = 0;
    for (char *p = s; s && *p; ) {
        char *nl = strchr(p, '\n');
        if (!nl) { whole = 0; break; }
        *nl = '\0';
        char exp[48];
        if (!has_stamp(p, "WRN")) whole = 0;
        else if (!strncmp(p + 31, "TA: ", 4)) {
            snprintf(exp, sizeof(exp), "payload-TA-%04d-end", na++);
            if (strcmp(p + 35, exp)) whole = 0;
        } else if (!strncmp(p + 31, "TB: ", 4)) {
            snprintf(exp, sizeof(exp), "payload-TB-%04d-end", nb++);
            if (strcmp(p + 35, exp)) whole = 0;
        } else whole = 0;
        p = nl + 1;
    }
    CHECK(whole && na == THREAD_LINES && nb == THREAD_LINES,
          "every line is whole and each thread's lines are complete and in order");
    free(s);
}

static void cleanup(void) {
    DIR *d = opendir(g_dir);
    for (struct dirent *e = d ? readdir(d) : NULL; e; e = readdir(d)) {
        char p[sizeof(g_dir) + 1 + 256];
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(p, sizeof(p), "%s/%s", g_dir, e->d_name);
        unlink(p);
    }
    if (d) closedir(d);
    rmdir(g_dir);
}

int main(void) {
    printf("test_nodus_log_shim\n");
    umask(022);
    snprintf(g_dir, sizeof(g_dir), "/tmp/nodus-log-shim-XXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    l1_off();
    l2_line();
    l3_rotation();
    l4_threads();
    printf("L5 closed\n");
    size_t len;
    char *s = slurp("nodus-amm.log", &len);
    size_t before = len;
    free(s);
    QGP_LOG_WARN("T5", "after close");
    s = slurp("nodus-amm.log", &len);
    CHECK(len == before, "after close a line writes nothing more");
    free(s);
    cleanup();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
