/**
 * Nodus — `nodus-cli status` local helpers tests
 *
 * The module behind the network-free half of `nodus-cli status`
 * (src/client/nodus_node_status.c):
 *   - the config reader: every key it shows, the defaults when a key is
 *     absent, retain_blocks present / absent, and the refusals (bad port,
 *     wrong type, negative retain_blocks, non-JSON, missing file);
 *   - a network-file peer "id@ip:port" → its host (IPv4, bracketed IPv6,
 *     malformed entries refused);
 *   - the first-line reader (install-commit);
 *   - /proc/loadavg and /proc/meminfo parsers on fixture files;
 *   - RSS by process name on a fixture proc tree (lowest pid wins, a
 *     missing name is "not found");
 *   - the segment directory count (only seg-<k>.ok counts; .ok.tmp and
 *     other names do not) and its byte total; a missing directory;
 *   - the chain database: the smallest canonical witness_<32hex>.db is
 *     chosen, its -wal / -shm are added, non-canonical names are ignored;
 *   - the fixed-argv runner, the yes/no answer and the in-sync judgement.
 * Fixtures are created under a mkdtemp directory in /tmp and removed. No
 * network; the runner test starts /bin/echo only.
 */

#include "client/nodus_node_status.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static char ROOT[64];

/* write `body` to ROOT/rel (parent directories must exist) */
static int put(const char *rel, const char *body) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", ROOT, rel);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    size_t n = strlen(body);
    int ok = fwrite(body, 1, n, f) == n;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

/* a file of exactly `size` bytes */
static int put_size(const char *rel, size_t size) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", ROOT, rel);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    for (size_t i = 0; i < size; i++) fputc('x', f);
    return fclose(f) == 0 ? 0 : -1;
}

static int mkd(const char *rel) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", ROOT, rel);
    return mkdir(p, 0700);
}

static void path_of(const char *rel, char *out, size_t cap) {
    snprintf(out, cap, "%s/%s", ROOT, rel);
}

/* remove ROOT recursively (two levels deep is all the fixtures use) */
static void rm_tree(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) rm_tree(p);
        else unlink(p);
    }
    closedir(d);
    rmdir(dir);
}

/* ── config reader ────────────────────────────────────────────────── */

#ifdef NODUS_HAS_JSONC
static void test_cfg_full(void) {
    TEST("config: every key read");
    char p[512];
    path_of("full.conf", p, sizeof(p));
    put("full.conf",
        "{ \"bind_ip\": \"0.0.0.0\", \"external_ip\": \"203.0.113.10\",\n"
        "  \"udp_port\": 5000, \"tcp_port\": 5001, \"peer_port\": 5002,\n"
        "  \"witness_port\": 5004, \"identity_path\": \"/x/identity\",\n"
        "  \"data_path\": \"/x/data\", \"network_file\": \"/x/net.json\",\n"
        "  \"retain_blocks\": 120960, \"segment_dir\": \"segs\" }\n");
    nodus_node_status_config_t c;
    char err[256] = "";
    if (nodus_node_status_read_config(p, &c, err, sizeof(err)) != 0) {
        FAIL(err); return;
    }
    if (strcmp(c.data_path, "/x/data") || !c.has_data_path ||
        strcmp(c.network_file, "/x/net.json") ||
        strcmp(c.external_ip, "203.0.113.10") ||
        strcmp(c.segment_dir, "segs") || !c.has_retain_blocks ||
        c.retain_blocks != 120960 || c.udp_port != 5000 ||
        c.tcp_port != 5001 || c.peer_port != 5002 || c.witness_port != 5004) {
        FAIL("a field differs"); return;
    }
    PASS();
}

static void test_cfg_defaults(void) {
    TEST("config: absent keys keep the node's defaults");
    char p[512];
    path_of("min.conf", p, sizeof(p));
    put("min.conf", "{ \"identity_path\": \"/x/identity\" }");
    nodus_node_status_config_t c;
    char err[256] = "";
    if (nodus_node_status_read_config(p, &c, err, sizeof(err)) != 0) {
        FAIL(err); return;
    }
    if (strcmp(c.data_path, NODUS_NODE_STATUS_DATA_PATH_DEFAULT) ||
        c.has_data_path || c.network_file[0] || c.external_ip[0] ||
        strcmp(c.segment_dir, "segments") || c.has_retain_blocks ||
        c.udp_port != 4000 || c.tcp_port != 4001 || c.peer_port != 4002 ||
        c.witness_port != 4004) {
        FAIL("a default differs"); return;
    }
    PASS();
}

static int cfg_refused(const char *body) {
    char p[512];
    path_of("bad.conf", p, sizeof(p));
    if (put("bad.conf", body) != 0) return 0;
    nodus_node_status_config_t c;
    char err[256] = "";
    return nodus_node_status_read_config(p, &c, err, sizeof(err)) == -1 &&
           err[0] != '\0';
}

static void test_cfg_refusals(void) {
    TEST("config: refused values");
    if (!cfg_refused("{ \"tcp_port\": 0 }"))          { FAIL("port 0"); return; }
    if (!cfg_refused("{ \"tcp_port\": 65536 }"))      { FAIL("port 65536"); return; }
    if (!cfg_refused("{ \"witness_port\": \"4004\" }")) { FAIL("port string"); return; }
    if (!cfg_refused("{ \"retain_blocks\": -1 }"))    { FAIL("retain -1"); return; }
    if (!cfg_refused("{ \"retain_blocks\": \"x\" }")) { FAIL("retain string"); return; }
    if (!cfg_refused("{ \"data_path\": 5 }"))         { FAIL("data_path int"); return; }
    if (!cfg_refused("{ \"segment_dir\": \"a/b\" }")) { FAIL("segment_dir /"); return; }
    if (!cfg_refused("[1, 2]"))                       { FAIL("array"); return; }
    if (!cfg_refused("not json"))                     { FAIL("not json"); return; }
    PASS();
}
#else
static void test_cfg_no_jsonc(void) {
    TEST("config: refused without json-c");
    nodus_node_status_config_t c;
    char err[256] = "";
    if (nodus_node_status_read_config("/etc/nodus.conf", &c, err,
                                      sizeof(err)) != -1 || !err[0]) {
        FAIL("accepted"); return;
    }
    PASS();
}
#endif

static void test_cfg_missing(void) {
    TEST("config: missing file refused");
    char p[512];
    path_of("does-not-exist.conf", p, sizeof(p));
    nodus_node_status_config_t c;
    char err[256] = "";
    if (nodus_node_status_read_config(p, &c, err, sizeof(err)) != -1 ||
        !err[0]) {
        FAIL("accepted"); return;
    }
    PASS();
}

/* ── peer host ────────────────────────────────────────────────────── */

static void test_peer_host(void) {
    TEST("network file peer: id@ip:port -> ip");
    char h[64];
    if (nodus_node_status_peer_host(
            "fd429639366cbc41d98db7603d51166ed5542d2d@161.97.85.25:4004",
            h, sizeof(h)) != 0 || strcmp(h, "161.97.85.25")) {
        FAIL("ipv4"); return;
    }
    if (nodus_node_status_peer_host("abcd@[2001:db8::1]:4004", h,
                                    sizeof(h)) != 0 ||
        strcmp(h, "2001:db8::1")) {
        FAIL("ipv6"); return;
    }
    if (nodus_node_status_peer_host("161.97.85.25:4004", h, sizeof(h)) == 0) {
        FAIL("no id accepted"); return;
    }
    if (nodus_node_status_peer_host("abcd@161.97.85.25", h, sizeof(h)) == 0) {
        FAIL("no port accepted"); return;
    }
    if (nodus_node_status_peer_host("abcd@:4004", h, sizeof(h)) == 0) {
        FAIL("empty host accepted"); return;
    }
    char tiny[4];
    if (nodus_node_status_peer_host("abcd@161.97.85.25:4004", tiny,
                                    sizeof(tiny)) == 0) {
        FAIL("overflow accepted"); return;
    }
    if (nodus_node_status_peer_host(NULL, h, sizeof(h)) == 0) {
        FAIL("NULL accepted"); return;
    }
    PASS();
}

/* ── first line ───────────────────────────────────────────────────── */

static void test_first_line(void) {
    TEST("first line: install-commit");
    char p[512], out[64];
    path_of("install-commit", p, sizeof(p));
    put("install-commit", "9a413b715deadbeef\r\nsecond line\n");
    if (nodus_node_status_first_line(p, out, sizeof(out)) != 0 ||
        strcmp(out, "9a413b715deadbeef")) {
        FAIL("read"); return;
    }
    put("install-commit", "\n");
    if (nodus_node_status_first_line(p, out, sizeof(out)) == 0) {
        FAIL("empty accepted"); return;
    }
    path_of("no-such-file", p, sizeof(p));
    if (nodus_node_status_first_line(p, out, sizeof(out)) == 0) {
        FAIL("missing accepted"); return;
    }
    PASS();
}

/* ── /proc parsers ────────────────────────────────────────────────── */

static void test_loadavg(void) {
    TEST("/proc/loadavg");
    char p[512];
    path_of("loadavg", p, sizeof(p));
    put("loadavg", "0.52 0.40 1.75 2/345 6789\n");
    double l[3];
    if (nodus_node_status_loadavg(p, l) != 0 || l[0] != 0.52 ||
        l[1] != 0.40 || l[2] != 1.75) {
        FAIL("values"); return;
    }
    put("loadavg", "garbage\n");
    if (nodus_node_status_loadavg(p, l) == 0) { FAIL("garbage accepted"); return; }
    PASS();
}

static void test_meminfo(void) {
    TEST("/proc/meminfo");
    char p[512];
    path_of("meminfo", p, sizeof(p));
    put("meminfo",
        "MemTotal:       16314404 kB\n"
        "MemFree:          813296 kB\n"
        "MemAvailable:   12001234 kB\n"
        "Buffers:          300000 kB\n");
    uint64_t t = 0, a = 0;
    if (nodus_node_status_meminfo(p, &t, &a) != 0 || t != 16314404u ||
        a != 12001234u) {
        FAIL("values"); return;
    }
    put("meminfo", "MemTotal:       16314404 kB\n");
    if (nodus_node_status_meminfo(p, &t, &a) == 0) {
        FAIL("missing MemAvailable accepted"); return;
    }
    PASS();
}

static void test_proc_rss(void) {
    TEST("RSS by process name (fixture proc tree)");
    mkd("proc");
    mkd("proc/1"); put("proc/1/comm", "systemd\n");
    put("proc/1/status", "Name:\tsystemd\nVmRSS:\t   9000 kB\n");
    mkd("proc/900"); put("proc/900/comm", "nodus-witness\n");
    put("proc/900/status", "Name:\tnodus-witness\nVmRSS:\t  51200 kB\n");
    mkd("proc/412"); put("proc/412/comm", "nodus-witness\n");
    put("proc/412/status", "Name:\tnodus-witness\nVmRSS:\t 204800 kB\n");
    mkd("proc/self-not-a-pid");
    char root[512];
    path_of("proc", root, sizeof(root));
    uint64_t rss = 0;
    int pid = 0;
    if (nodus_node_status_proc_rss(root, "nodus-witness", &rss, &pid) != 0 ||
        pid != 412 || rss != 204800u) {
        FAIL("lowest pid / value"); return;
    }
    if (nodus_node_status_proc_rss(root, "nodus-core", &rss, &pid) != 1) {
        FAIL("absent name not 1"); return;
    }
    char nope[512];
    path_of("no-proc", nope, sizeof(nope));
    if (nodus_node_status_proc_rss(nope, "x", &rss, &pid) != -1) {
        FAIL("missing root not -1"); return;
    }
    PASS();
}

/* ── segment directory ────────────────────────────────────────────── */

static void test_segments(void) {
    TEST("segment dir: seg-<k>.ok count + byte total");
    mkd("segments");
    put_size("segments/seg-1.dat", 1000);
    put_size("segments/seg-1.idx", 100);
    put_size("segments/seg-1.ok", 10);
    put_size("segments/seg-2.dat", 500);
    put_size("segments/seg-2.ok", 10);
    put_size("segments/seg-3.dat.tmp", 300);
    put_size("segments/seg-3.ok.tmp", 10);   /* not complete         */
    put_size("segments/seg-.ok", 1);         /* no k: not a segment  */
    put_size("segments/seg-4x.ok", 1);       /* k not decimal        */
    char d[512];
    path_of("segments", d, sizeof(d));
    uint64_t n = 0, b = 0;
    if (nodus_node_status_segments(d, &n, &b) != 0) { FAIL("rc"); return; }
    if (n != 2) { FAIL("ok count"); return; }
    if (b != 1000u + 100u + 10u + 500u + 10u + 300u + 10u + 1u + 1u) {
        FAIL("byte total"); return;
    }
    path_of("no-segments", d, sizeof(d));
    if (nodus_node_status_segments(d, &n, &b) != 1) {
        FAIL("missing dir not 1"); return;
    }
    PASS();
}

/* ── chain database ───────────────────────────────────────────────── */

static void test_chain_db(void) {
    TEST("chain db: smallest canonical name, + -wal / -shm");
    mkd("data");
    char d[512];
    path_of("data", d, sizeof(d));
    char name[128];
    uint64_t b = 0;
    if (nodus_node_status_chain_db(d, name, sizeof(name), &b) != 1) {
        FAIL("empty dir not 1"); return;
    }
    put_size("data/witness_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.db", 7);
    put_size("data/witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db", 4000);
    put_size("data/witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db-wal", 300);
    put_size("data/witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db-shm", 20);
    put_size("data/witness_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.db", 1);  /* upper */
    put_size("data/witness_0000.db", 1);                              /* short */
    put_size("data/witness_00000000000000000000000000000000.db.bak", 1);
    if (nodus_node_status_chain_db(d, name, sizeof(name), &b) != 0) {
        FAIL("rc"); return;
    }
    if (strcmp(name, "witness_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.db")) {
        FAIL("name"); return;
    }
    if (b != 4000u + 300u + 20u) { FAIL("bytes"); return; }
    char nope[512];
    path_of("no-data", nope, sizeof(nope));
    if (nodus_node_status_chain_db(nope, name, sizeof(name), &b) != -1) {
        FAIL("missing dir not -1"); return;
    }
    PASS();
}

/* ── disk ─────────────────────────────────────────────────────────── */

static void test_disk(void) {
    TEST("disk: statvfs of the fixture root");
    uint64_t a = 0, t = 0;
    if (nodus_node_status_disk(ROOT, &a, &t) != 0 || t == 0 || a > t) {
        FAIL("values"); return;
    }
    char nope[512];
    path_of("no-such-dir", nope, sizeof(nope));
    if (nodus_node_status_disk(nope, &a, &t) == 0) {
        FAIL("missing path accepted"); return;
    }
    PASS();
}

/* ── runner, answers, judgement ───────────────────────────────────── */

static void test_run(void) {
    TEST("runner: fixed argv, first stdout line, exit status");
    const char *const ok[] = { "echo", "active", NULL };
    char out[64];
    int code = -2;
    if (nodus_node_status_run(ok, out, sizeof(out), &code) != 0 ||
        code != 0 || strcmp(out, "active")) {
        FAIL("echo"); return;
    }
    const char *const no[] = { "nodus-status-test-no-such-program", NULL };
    code = -2;
    if (nodus_node_status_run(no, out, sizeof(out), &code) == 0 &&
        code == 0) {
        FAIL("missing program reported success"); return;
    }
    PASS();
}

static void test_yes_no(void) {
    TEST("yes/no answer");
    if (nodus_node_status_yes_no("yes") != 1 ||
        nodus_node_status_yes_no("no") != 0 ||
        nodus_node_status_yes_no("") != -1 ||
        nodus_node_status_yes_no("YES") != -1 ||
        nodus_node_status_yes_no(NULL) != -1) {
        FAIL("mapping"); return;
    }
    PASS();
}

static void test_in_sync(void) {
    TEST("in sync: behind by <= 2");
    if (!nodus_node_status_in_sync(100, 100) ||
        !nodus_node_status_in_sync(98, 100) ||
        nodus_node_status_in_sync(97, 100) ||
        !nodus_node_status_in_sync(105, 100) ||
        nodus_node_status_in_sync(0, 100)) {
        FAIL("judgement"); return;
    }
    PASS();
}

int main(void) {
    snprintf(ROOT, sizeof(ROOT), "/tmp/test_node_status.XXXXXX");
    if (!mkdtemp(ROOT)) {
        printf("mkdtemp failed\n");
        return 1;
    }

    printf("nodus-cli status helper tests\n");
#ifdef NODUS_HAS_JSONC
    test_cfg_full();
    test_cfg_defaults();
    test_cfg_refusals();
#else
    test_cfg_no_jsonc();
#endif
    test_cfg_missing();
    test_peer_host();
    test_first_line();
    test_loadavg();
    test_meminfo();
    test_proc_rss();
    test_segments();
    test_chain_db();
    test_disk();
    test_run();
    test_yes_no();
    test_in_sync();

    rm_tree(ROOT);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
