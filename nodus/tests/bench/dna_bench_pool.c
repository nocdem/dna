/* dna_bench_pool.c — pool layout, paths, persistence helpers.
 *
 * Pool root: $BENCH_HOME (test override) | ~/.dna_bench (default).
 * Layout (per design 2026-04-27 "Wallet pool — state and layout"):
 *   <root>/
 *   ├── pool.json
 *   ├── wallets/wNN/.dna/    (CLI's HOME data dir; mode 0700)
 *   ├── wallets/wNN/fp.txt   (129-hex fingerprint cache)
 *   └── runs/<UTC-ts>/run.json + tx_hashes.txt + stream.jsonl
 *
 * Mnemonics are NEVER written to disk (red-team B1, B2, B3 fix).
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE          /* vasprintf */

#include "dna_bench_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Sysexits-ish OOM/internal-error code (no sysexits.h to keep portable). */
#define EX_OOM_OR_INTERNAL 71

static char *xstrdup(const char *s) {
    char *r = strdup(s ? s : "");
    if (!r) { perror("strdup"); exit(EX_OOM_OR_INTERNAL); }
    return r;
}

static char *xasprintf(const char *fmt, ...) {
    char *out = NULL;
    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(&out, fmt, ap);
    va_end(ap);
    if (n < 0 || !out) { perror("vasprintf"); exit(EX_OOM_OR_INTERNAL); }
    return out;
}

char *dna_bench_root(void) {
    const char *env = getenv("BENCH_HOME");
    if (env && *env) return xstrdup(env);
    const char *home = getenv("HOME");
    if (!home || !*home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    return xasprintf("%s/.dna_bench", home);
}

char *dna_bench_wallet_dir(int idx) {
    char *root = dna_bench_root();
    char *p = xasprintf("%s/wallets/w%02d", root, idx);
    free(root);
    return p;
}

char *dna_bench_wallet_fp_path(int idx) {
    char *dir = dna_bench_wallet_dir(idx);
    char *p = xasprintf("%s/fp.txt", dir);
    free(dir);
    return p;
}

char *dna_bench_pool_metadata_path(void) {
    char *root = dna_bench_root();
    char *p = xasprintf("%s/pool.json", root);
    free(root);
    return p;
}

int dna_bench_mkdir_p_secure(const char *path) {
    /* mkdir -p with mode 0700 on every component we create. */
    char buf[4096];
    if (strlen(path) >= sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

char *dna_bench_run_dir_new(void) {
    char *root = dna_bench_root();
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm);
    char *runs = xasprintf("%s/runs", root);
    (void)dna_bench_mkdir_p_secure(runs);
    free(runs);
    char *dir = xasprintf("%s/runs/%s", root, ts);
    if (dna_bench_mkdir_p_secure(dir) != 0) {
        fprintf(stderr, "[dna-bench] mkdir failed: %s: %s\n", dir, strerror(errno));
    }
    free(root);
    return dir;
}

bool dna_bench_pool_exists(void) {
    char *p = dna_bench_pool_metadata_path();
    struct stat st;
    bool ok = (stat(p, &st) == 0 && S_ISREG(st.st_mode));
    free(p);
    return ok;
}

/* Tiny JSON reader — looks for "key":<value>. Supports int, uint64, string.
 * Not a general parser; sufficient for the small pool.json schema. */
static const char *find_key(const char *buf, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    return strstr(buf, needle);
}

static int read_int_after(const char *p, int *out) {
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = (int)v;
    return 0;
}

static int read_u64_after(const char *p, uint64_t *out) {
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    char *end;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int read_str_after(const char *p, char *out, size_t n) {
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < n) out[i++] = *p++;
    out[i] = '\0';
    return *p == '"' ? 0 : -1;
}

int dna_bench_pool_load(struct dna_bench_pool *out) {
    char *path = dna_bench_pool_metadata_path();
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f) return -1;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    memset(out, 0, sizeof(*out));
    const char *p;
    if ((p = find_key(buf, "count")) == NULL) return -2;
    if (read_int_after(p + strlen("\"count\""), &out->count) != 0) return -2;
    if ((p = find_key(buf, "fund_per_wallet_raw"))) {
        if (read_u64_after(p + strlen("\"fund_per_wallet_raw\""),
                           &out->fund_per_wallet_raw) != 0) return -2;
    }
    if ((p = find_key(buf, "created_at"))) {
        read_str_after(p + strlen("\"created_at\""),
                       out->created_at, sizeof(out->created_at));
    }
    if ((p = find_key(buf, "chain_genesis_id"))) {
        read_str_after(p + strlen("\"chain_genesis_id\""),
                       out->chain_genesis_id, sizeof(out->chain_genesis_id));
    }
    return 0;
}

int dna_bench_pool_save(const struct dna_bench_pool *p) {
    char *root = dna_bench_root();
    if (dna_bench_mkdir_p_secure(root) != 0) {
        fprintf(stderr, "[dna-bench] cannot create pool root %s: %s\n",
                root, strerror(errno));
        free(root);
        return -1;
    }
    free(root);

    char *path = dna_bench_pool_metadata_path();
    char *tmp = xasprintf("%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[dna-bench] open %s: %s\n", tmp, strerror(errno));
        free(path); free(tmp);
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); free(path); free(tmp); return -1; }

    char ts[32];
    if (p->created_at[0]) {
        strncpy(ts, p->created_at, sizeof(ts) - 1);
        ts[sizeof(ts) - 1] = '\0';
    } else {
        time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": 1,\n");
    fprintf(f, "  \"count\": %d,\n", p->count);
    fprintf(f, "  \"fund_per_wallet_raw\": %llu,\n",
            (unsigned long long)p->fund_per_wallet_raw);
    fprintf(f, "  \"created_at\": \"%s\",\n", ts);
    fprintf(f, "  \"chain_genesis_id\": \"%s\"\n", p->chain_genesis_id);
    fprintf(f, "}\n");
    fclose(f);

    if (rename(tmp, path) != 0) {
        fprintf(stderr, "[dna-bench] rename %s -> %s: %s\n",
                tmp, path, strerror(errno));
        unlink(tmp);
        free(path); free(tmp);
        return -1;
    }
    free(path); free(tmp);
    return 0;
}

char *dna_bench_read_first_line(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return NULL; }
    fclose(f);
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' '  || buf[len - 1] == '\t')) {
        buf[--len] = '\0';
    }
    return xstrdup(buf);
}

const char *dna_bench_cli_bin(void) {
    static char cached[1024];
    static int  resolved = 0;
    if (resolved) return cached;

    const char *env = getenv("BENCH_CLI_BIN");
    if (env && *env) {
        snprintf(cached, sizeof(cached), "%s", env);
        resolved = 1;
        return cached;
    }
    /* Default: assume dev tree layout. */
    const char *def = "/opt/dna/messenger/build/cli/dna-connect-cli";
    if (access(def, X_OK) == 0) {
        snprintf(cached, sizeof(cached), "%s", def);
    } else {
        snprintf(cached, sizeof(cached), "dna-connect-cli");
    }
    resolved = 1;
    return cached;
}
