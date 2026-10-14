/**
 * @file nodus/src/client/nodus_node_status.c
 * @brief The local, network-free half of `nodus-cli status` — see
 *        nodus_node_status.h for the contract.
 *
 * READ-ONLY: files are opened for reading, directories are listed; the
 * only process started is the fixed argv the caller passes to
 * nodus_node_status_run. No clock, no randomness, nothing here is a
 * consensus input.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_node_status.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>
#endif

#include "nodus/nodus_types.h"          /* NODUS_DEFAULT_*_PORT          */
#include "witness/nodus_witness.h"      /* NODUS_SEG_DIR_DEFAULT         */

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

static void ns_err(char *err, size_t errcap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void ns_err(char *err, size_t errcap, const char *fmt, ...) {
    if (!err || errcap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errcap, fmt, ap);
    va_end(ap);
}

/* "a/b" into out; 0 / -1 (does not fit) */
static int ns_join(char *out, size_t cap, const char *a, const char *b) {
    int n = snprintf(out, cap, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* remove trailing "\r\n" */
static void ns_chomp(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

/* ── config ──────────────────────────────────────────────────────── */

#ifdef NODUS_HAS_JSONC
/* A string key into dst (refused when it is not a string or does not
 * fit). @return 1 present and copied, 0 absent, -1 refused. */
static int ns_cfg_str(struct json_object *root, const char *key, char *dst,
                      size_t cap, const char *path, char *err,
                      size_t errcap) {
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return 0;
    if (!json_object_is_type(v, json_type_string)) {
        ns_err(err, errcap, "\"%s\" in %s is not a string", key, path);
        return -1;
    }
    const char *s = json_object_get_string(v);
    const size_t sl = s ? strlen(s) : 0;
    if (sl >= cap) {
        ns_err(err, errcap, "\"%s\" in %s is too long", key, path);
        return -1;
    }
    memcpy(dst, s ? s : "", sl + 1u);
    return 1;
}

/* A port key: an integer 1..65535. @return 0 (absent or set) / -1. */
static int ns_cfg_port(struct json_object *root, const char *key,
                       uint16_t *dst, const char *path, char *err,
                       size_t errcap) {
    struct json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return 0;
    if (!json_object_is_type(v, json_type_int)) {
        ns_err(err, errcap, "\"%s\" in %s is not an integer", key, path);
        return -1;
    }
    errno = 0;
    const int64_t p = json_object_get_int64(v);
    if (errno != 0 || p < 1 || p > 65535) {
        ns_err(err, errcap, "\"%s\" in %s must be 1..65535", key, path);
        return -1;
    }
    *dst = (uint16_t)p;
    return 0;
}
#endif

int nodus_node_status_read_config(const char *path,
                                  nodus_node_status_config_t *out,
                                  char *err, size_t errcap) {
    if (!path || !out) {
        ns_err(err, errcap, "no config path given");
        return -1;
    }
    memset(out, 0, sizeof(*out));
    snprintf(out->data_path, sizeof(out->data_path), "%s",
             NODUS_NODE_STATUS_DATA_PATH_DEFAULT);
    snprintf(out->segment_dir, sizeof(out->segment_dir), "%s",
             NODUS_SEG_DIR_DEFAULT);
    out->udp_port     = NODUS_DEFAULT_UDP_PORT;
    out->tcp_port     = NODUS_DEFAULT_TCP_PORT;
    out->peer_port    = NODUS_DEFAULT_PEER_PORT;
    out->witness_port = NODUS_DEFAULT_WITNESS_PORT;
#ifndef NODUS_HAS_JSONC
    ns_err(err, errcap, "this build cannot read the node config");
    return -1;
#else
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        ns_err(err, errcap, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    char *buf = malloc((size_t)NODUS_NODE_STATUS_CONFIG_MAX + 1u);
    if (!buf) {
        fclose(fp);
        ns_err(err, errcap, "out of memory reading %s", path);
        return -1;
    }
    /* one byte past the bound tells "too large" from "exactly the bound" */
    const size_t n = fread(buf, 1, (size_t)NODUS_NODE_STATUS_CONFIG_MAX + 1u,
                           fp);
    const int rerr = ferror(fp);
    fclose(fp);
    if (rerr) {
        free(buf);
        ns_err(err, errcap, "cannot read %s", path);
        return -1;
    }
    if (n > NODUS_NODE_STATUS_CONFIG_MAX) {
        free(buf);
        ns_err(err, errcap, "%s is larger than %u bytes", path,
               (unsigned)NODUS_NODE_STATUS_CONFIG_MAX);
        return -1;
    }
    buf[n] = '\0';

    struct json_tokener *tok = json_tokener_new();
    if (!tok) {
        free(buf);
        ns_err(err, errcap, "out of memory parsing %s", path);
        return -1;
    }
    struct json_object *root = json_tokener_parse_ex(tok, buf, (int)n);
    const enum json_tokener_error jerr = json_tokener_get_error(tok);
    json_tokener_free(tok);
    free(buf);
    if (!root || jerr != json_tokener_success ||
        !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        ns_err(err, errcap, "%s is not a JSON object", path);
        return -1;
    }

    int rc = -1;
    int s;
    s = ns_cfg_str(root, "data_path", out->data_path,
                   sizeof(out->data_path), path, err, errcap);
    if (s < 0) goto done;
    out->has_data_path = s == 1;
    if (ns_cfg_str(root, "network_file", out->network_file,
                   sizeof(out->network_file), path, err, errcap) < 0)
        goto done;
    if (ns_cfg_str(root, "external_ip", out->external_ip,
                   sizeof(out->external_ip), path, err, errcap) < 0)
        goto done;
    s = ns_cfg_str(root, "segment_dir", out->segment_dir,
                   sizeof(out->segment_dir), path, err, errcap);
    if (s < 0) goto done;
    /* the node's own rule (tools/nodus_node_config.c): one plain
     * directory name under the data directory */
    if (s == 1 && (!out->segment_dir[0] || strchr(out->segment_dir, '/') ||
                   !strcmp(out->segment_dir, ".") ||
                   !strcmp(out->segment_dir, ".."))) {
        ns_err(err, errcap, "\"segment_dir\" in %s must be one directory "
               "name under the data directory", path);
        goto done;
    }
    if (ns_cfg_port(root, "udp_port", &out->udp_port, path, err,
                    errcap) != 0 ||
        ns_cfg_port(root, "tcp_port", &out->tcp_port, path, err,
                    errcap) != 0 ||
        ns_cfg_port(root, "peer_port", &out->peer_port, path, err,
                    errcap) != 0 ||
        ns_cfg_port(root, "witness_port", &out->witness_port, path, err,
                    errcap) != 0)
        goto done;
    {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(root, "retain_blocks", &v)) {
            if (!json_object_is_type(v, json_type_int)) {
                ns_err(err, errcap, "\"retain_blocks\" in %s is not an "
                       "integer", path);
                goto done;
            }
            errno = 0;
            const int64_t rb = json_object_get_int64(v);
            if (errno != 0 || rb < 0) {
                ns_err(err, errcap, "\"retain_blocks\" in %s must be >= 0",
                       path);
                goto done;
            }
            out->has_retain_blocks = true;
            out->retain_blocks = rb;
        }
    }
    rc = 0;
done:
    json_object_put(root);
    return rc;
#endif
}

/* ── network file peer ───────────────────────────────────────────── */

int nodus_node_status_peer_host(const char *peer, char *host, size_t cap) {
    if (!peer || !host || cap == 0) return -1;
    const char *at = strchr(peer, '@');
    if (!at) return -1;
    const char *h = at + 1;
    const char *colon = strrchr(h, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - h);
    if (hl >= 2 && h[0] == '[' && h[hl - 1] == ']') {
        h++;
        hl -= 2;
    }
    if (hl == 0 || hl >= cap) return -1;
    memcpy(host, h, hl);
    host[hl] = '\0';
    return 0;
}

/* ── small files ─────────────────────────────────────────────────── */

int nodus_node_status_first_line(const char *path, char *out, size_t cap) {
    if (!path || !out || cap == 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    const char *got = fgets(line, sizeof(line), f);
    fclose(f);
    if (!got) return -1;
    ns_chomp(line);
    const size_t n = strlen(line);
    if (n == 0 || n >= cap) return -1;
    memcpy(out, line, n + 1u);
    return 0;
}

int nodus_node_status_loadavg(const char *path, double out[3]) {
    if (!path || !out) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    double a = 0, b = 0, c = 0;
    const int k = fscanf(f, "%lf %lf %lf", &a, &b, &c);
    fclose(f);
    if (k != 3) return -1;
    out[0] = a;
    out[1] = b;
    out[2] = c;
    return 0;
}

int nodus_node_status_meminfo(const char *path, uint64_t *total_kb,
                              uint64_t *avail_kb) {
    if (!path || !total_kb || !avail_kb) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    int have_t = 0, have_a = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long v = 0;
        if (sscanf(line, "MemTotal: %llu kB", &v) == 1) {
            *total_kb = (uint64_t)v;
            have_t = 1;
        } else if (sscanf(line, "MemAvailable: %llu kB", &v) == 1) {
            *avail_kb = (uint64_t)v;
            have_a = 1;
        }
    }
    fclose(f);
    return (have_t && have_a) ? 0 : -1;
}

/* 1 when s is all decimal digits (and not empty) */
static int ns_digits(const char *s) {
    if (!*s) return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return 0;
    return 1;
}

int nodus_node_status_proc_rss(const char *proc_root, const char *comm,
                               uint64_t *rss_kb, int *pid) {
    if (!proc_root || !comm || !rss_kb || !pid) return -1;
    DIR *d = opendir(proc_root);
    if (!d) return -1;
    long best = -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!ns_digits(e->d_name) || strlen(e->d_name) > 9) continue;
        const long p = strtol(e->d_name, NULL, 10);
        if (best >= 0 && p >= best) continue;
        char path[512], dir[512];
        if (ns_join(dir, sizeof(dir), proc_root, e->d_name) != 0 ||
            ns_join(path, sizeof(path), dir, "comm") != 0)
            continue;
        char name[64];
        if (nodus_node_status_first_line(path, name, sizeof(name)) != 0)
            continue;
        if (strcmp(name, comm) == 0) best = p;
    }
    closedir(d);
    if (best < 0) return 1;

    char dir[512], path[512], pidstr[16];
    snprintf(pidstr, sizeof(pidstr), "%ld", best);
    if (ns_join(dir, sizeof(dir), proc_root, pidstr) != 0 ||
        ns_join(path, sizeof(path), dir, "status") != 0)
        return 1;
    FILE *f = fopen(path, "r");
    if (!f) return 1;     /* the process ended between the two reads */
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long v = 0;
        if (sscanf(line, "VmRSS: %llu kB", &v) == 1) {
            *rss_kb = (uint64_t)v;
            found = 1;
            break;
        }
    }
    fclose(f);
    if (!found) return 1;  /* a kernel thread or a zombie has no VmRSS */
    *pid = (int)best;
    return 0;
}

/* ── segment directory ───────────────────────────────────────────── */

/* "seg-<k>.ok", k one or more decimal digits — the completeness marker
 * (witness/nodus_witness_storage_segment.h, THE FILES) */
static int ns_seg_ok_name(const char *s) {
    if (strncmp(s, "seg-", 4) != 0) return 0;
    const char *k = s + 4;
    const char *dot = strchr(k, '.');
    if (!dot || dot == k || strcmp(dot, ".ok") != 0) return 0;
    for (const char *c = k; c < dot; c++)
        if (*c < '0' || *c > '9') return 0;
    return 1;
}

int nodus_node_status_segments(const char *dir, uint64_t *n_ok,
                               uint64_t *total_bytes) {
    if (!dir || !n_ok || !total_bytes) return -1;
    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? 1 : -1;
    uint64_t n = 0, b = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char p[1024];
        if (ns_join(p, sizeof(p), dir, e->d_name) != 0) continue;
        struct stat st;
        if (lstat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        b += (uint64_t)st.st_size;
        if (ns_seg_ok_name(e->d_name)) n++;
    }
    closedir(d);
    *n_ok = n;
    *total_bytes = b;
    return 0;
}

/* ── chain database ──────────────────────────────────────────────── */

/* witness/nodus_witness_network_file.c chain_db_name_ok, restated (it is
 * file-static): "witness_" + exactly 32 lowercase hex + ".db", nothing
 * after. */
static int ns_chain_db_name(const char *s) {
    if (strncmp(s, "witness_", 8) != 0) return 0;
    const char *hex = s + 8;
    const char *dot = strstr(hex, ".db");
    if (!dot || dot[3] != '\0' || (size_t)(dot - hex) != 32) return 0;
    for (size_t i = 0; i < 32; i++) {
        const char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* size of dir/name + suffix, 0 when absent */
static uint64_t ns_size(const char *dir, const char *name,
                        const char *suffix) {
    char f[512], p[1024];
    int n = snprintf(f, sizeof(f), "%s%s", name, suffix);
    if (n < 0 || (size_t)n >= sizeof(f)) return 0;
    if (ns_join(p, sizeof(p), dir, f) != 0) return 0;
    struct stat st;
    if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    return (uint64_t)st.st_size;
}

int nodus_node_status_chain_db(const char *data_path, char *name, size_t cap,
                               uint64_t *total_bytes) {
    if (!data_path || !name || cap == 0 || !total_bytes) return -1;
    DIR *d = opendir(data_path);
    if (!d) return -1;
    char best[64] = "";
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!ns_chain_db_name(e->d_name)) continue;
        if (!best[0] || strcmp(e->d_name, best) < 0)
            snprintf(best, sizeof(best), "%s", e->d_name);
    }
    closedir(d);
    if (!best[0]) return 1;
    if (strlen(best) >= cap) return -1;
    memcpy(name, best, strlen(best) + 1u);
    *total_bytes = ns_size(data_path, best, "") +
                   ns_size(data_path, best, "-wal") +
                   ns_size(data_path, best, "-shm");
    return 0;
}

/* ── disk ────────────────────────────────────────────────────────── */

int nodus_node_status_disk(const char *path, uint64_t *avail_bytes,
                           uint64_t *total_bytes) {
    if (!path || !avail_bytes || !total_bytes) return -1;
    struct statvfs sv;
    if (statvfs(path, &sv) != 0 || sv.f_blocks == 0) return -1;
    *avail_bytes = (uint64_t)sv.f_bavail * (uint64_t)sv.f_frsize;
    *total_bytes = (uint64_t)sv.f_blocks * (uint64_t)sv.f_frsize;
    return 0;
}

/* ── fixed-argv runner ───────────────────────────────────────────── */

int nodus_node_status_run(const char *const argv[], char *out, size_t cap,
                          int *exit_code) {
    if (!argv || !argv[0] || !out || cap == 0 || !exit_code) return -1;
    out[0] = '\0';
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    const pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        /* child: stdout → the pipe, stdin / stderr → /dev/null */
        const int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) {
            dup2(nul, STDIN_FILENO);
            dup2(nul, STDERR_FILENO);
        }
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        if (nul > STDERR_FILENO) close(nul);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    /* read all of it (a child blocked on a full pipe would never exit);
     * keep the first cap-1 bytes */
    size_t got = 0;
    char buf[256];
    for (;;) {
        const ssize_t r = read(pfd[0], buf, sizeof(buf));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        for (ssize_t i = 0; i < r && got + 1u < cap; i++) out[got++] = buf[i];
    }
    out[got] = '\0';
    close(pfd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    ns_chomp(out);
    *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return 0;
}

/* ── answers / judgements ────────────────────────────────────────── */

int nodus_node_status_yes_no(const char *s) {
    if (!s) return -1;
    if (strcmp(s, "yes") == 0) return 1;
    if (strcmp(s, "no") == 0) return 0;
    return -1;
}

int nodus_node_status_in_sync(uint64_t local, uint64_t network) {
    if (local >= network) return 1;
    return (network - local) <= (uint64_t)NODUS_NODE_STATUS_BEHIND_OK;
}
