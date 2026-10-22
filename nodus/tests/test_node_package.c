/**
 * Nodus — `nodus-cli package` tests
 *
 * The module behind `sudo nodus-cli package list|add|remove`
 * (src/client/nodus_node_package.c; decisions 2026-10-22-nodus-packages-
 * add-remove.md, 2026-10-22-kurultay-36-summary.md; design 2026-10-22-
 * nodus-packages-design.md):
 *   - the pure verdict: every layout x action x preflight-reply case —
 *     combined / ambiguous / none / unknown units, already on / off,
 *     core-alone, `remove storage` refused, and for `remove witness` of a
 *     witness that is on: allowed ONLY for a decoded CLEAR + fresh reply;
 *     CLEAR + !fresh, UNKNOWN, an inconsistent reply, a reply that was not
 *     read, and every blocker code refuse (reason, end height, owners);
 *   - the exact refusal texts;
 *   - the systemd adapter against a fake systemctl script (its argv is
 *     recorded; states are scripted): is-enabled / is-active parsing, the
 *     exact-word rule, enable / disable --now with the post-state check,
 *     a child killed past a small deadline, a systemctl path that is not
 *     an executable regular file, and that core / the combined unit can
 *     never be changed;
 *   - nodus.service running while the split units are enabled (active /
 *     activating / deactivating / reloading / refreshing, an unknown or
 *     unread is-active word) refuses add and remove; inactive / failed do
 *     not; `list` reports it;
 *   - the host lock: free -> taken, held by a second open file
 *     description -> busy, missing file -> created 0600 under umask 077;
 *     a file that is a symlink, a FIFO, group/other-accessible or owned by
 *     another uid is refused (-2, "not a root-owned 0600 regular file"),
 *     never reported as busy (the test passes geteuid() as the required
 *     owner, the CLI passes 0);
 *   - the longest refusal (16 owners x 128 hex) fits without a cut, and a
 *     refusal that does not fit becomes the short fixed message that ends
 *     "Nothing was changed.";
 *   - the addr_seq rule (neither / only old / only new / both / same dir);
 *   - nodus_node_package_main with the fake systemctl: list, usage,
 *     remove storage, busy lock, combined, already on / off, add witness
 *     (incl. the addr_seq move) and the `remove witness` refusal when the
 *     registration cannot be read.
 * Fixtures live under a mkdtemp directory in /tmp and are removed. No
 * network, no real systemctl, nothing runs as root. The deadline case only
 * relies on "a script that sleeps 30 s was killed after a deadline of
 * 100 ms" — the assertion is the refusal, not a measured time.
 */

#include "client/nodus_node_package.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-62s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(cond, msg) do { if (cond) { PASS(); } else { FAIL(msg); } } while(0)

static int passed = 0;
static int failed = 0;

static char ROOT[64];

/* ── fixtures ────────────────────────────────────────────────────── */

static void path_of(char *out, size_t cap, const char *rel) {
    snprintf(out, cap, "%s/%s", ROOT, rel);
}

static int put(const char *rel, const char *body) {
    char p[512];
    path_of(p, sizeof(p), rel);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    const size_t n = strlen(body);
    const int ok = fwrite(body, 1, n, f) == n;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

static int exists(const char *rel) {
    char p[512];
    path_of(p, sizeof(p), rel);
    struct stat st;
    return lstat(p, &st) == 0;
}

static void rm(const char *rel) {
    char p[512];
    path_of(p, sizeof(p), rel);
    unlink(p);
}

/* contents of ROOT/rel into buf ("" when absent) */
static void slurp(const char *rel, char *buf, size_t cap) {
    char p[512];
    path_of(p, sizeof(p), rel);
    buf[0] = '\0';
    FILE *f = fopen(p, "rb");
    if (!f) return;
    const size_t n = fread(buf, 1, cap - 1u, f);
    buf[n] = '\0';
    fclose(f);
}

/* the fake systemctl. State files in ROOT: en.<unit>, act.<unit>; flags:
 * hang (sleep 30 on every call), fail (enable/disable exit 5), noop
 * (enable/disable exit 0 and change nothing). argv.log gets every call. */
static int write_fake(void) {
    char body[2048];
    snprintf(body, sizeof(body),
        "#!/bin/sh\n"
        "D=\"%s\"\n"
        "echo \"$@\" >> \"$D/argv.log\"\n"
        "[ -f \"$D/hang\" ] && exec sleep 30\n"
        "case \"$1\" in\n"
        "  is-enabled)\n"
        "    [ -f \"$D/en.$2\" ] || exit 1\n"
        "    cat \"$D/en.$2\"; read w < \"$D/en.$2\"\n"
        "    [ \"$w\" = enabled ] && exit 0; exit 1 ;;\n"
        "  is-active)\n"
        "    [ -f \"$D/act.$2\" ] || exit 3\n"
        "    cat \"$D/act.$2\"; read w < \"$D/act.$2\"\n"
        "    [ \"$w\" = active ] && exit 0; exit 3 ;;\n"
        "  enable|disable)\n"
        "    [ \"$2\" = --now ] || exit 2\n"
        "    [ -f \"$D/fail\" ] && exit 5\n"
        "    [ -f \"$D/noop\" ] && exit 0\n"
        "    if [ \"$1\" = enable ]; then echo enabled > \"$D/en.$3\"; "
        "echo active > \"$D/act.$3\"; "
        "else echo disabled > \"$D/en.$3\"; echo inactive > \"$D/act.$3\"; fi\n"
        "    exit 0 ;;\n"
        "esac\n"
        "exit 2\n", ROOT);
    if (put("systemctl", body) != 0) return -1;
    char p[512];
    path_of(p, sizeof(p), "systemctl");
    return chmod(p, 0755);
}

/* scripted unit states: "enabled"/"disabled"/NULL (no file) */
static void set_units(const char *nodus, const char *core, const char *storage,
                      const char *witness) {
    static const char *const names[4] = { "nodus", "nodus-core",
                                          "nodus-storage", "nodus-witness" };
    const char *const en[4] = { nodus, core, storage, witness };
    for (int i = 0; i < 4; i++) {
        char f[96], a[96];
        snprintf(f, sizeof(f), "en.%s", names[i]);
        snprintf(a, sizeof(a), "act.%s", names[i]);
        if (en[i]) {
            put(f, en[i]);
            put(a, strcmp(en[i], "enabled\n") == 0 ? "active\n"
                                                   : "inactive\n");
        } else {
            rm(f);
            rm(a);
        }
    }
}

static void clear_flags(void) {
    rm("hang");
    rm("fail");
    rm("noop");
    rm("argv.log");
}

static nodus_np_sysd_t fake_sysd(int query_ms, int change_ms) {
    static char path[512];
    path_of(path, sizeof(path), "systemctl");
    nodus_np_sysd_t s = { path, query_ms, change_ms };
    return s;
}

/* ── verdict helpers ─────────────────────────────────────────────── */

static nodus_np_units_t units(nodus_np_state_t nodus, nodus_np_state_t core,
                              nodus_np_state_t storage,
                              nodus_np_state_t witness) {
    nodus_np_units_t u;
    memset(&u, 0, sizeof(u));
    u.enabled[NODUS_NP_UNIT_NODUS]   = nodus;
    u.enabled[NODUS_NP_UNIT_CORE]    = core;
    u.enabled[NODUS_NP_UNIT_STORAGE] = storage;
    u.enabled[NODUS_NP_UNIT_WITNESS] = witness;
    /* the combined unit is not running (the verdict reads this word) */
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "inactive");
    return u;
}

#define ON  NODUS_NP_ON
#define OFF NODUS_NP_OFF
#define UNK NODUS_NP_UNKNOWN

static nodus_np_verdict_t verdict(const nodus_np_units_t *u,
                                  nodus_np_action_t a, nodus_np_pkg_t p,
                                  const nodus_dnac_node_duties_t *d,
                                  const char *e) {
    nodus_np_verdict_t v;
    nodus_node_package_verdict(u, a, p, d, e, &v);
    return v;
}

static nodus_dnac_node_duties_t clear_fresh(void) {
    nodus_dnac_node_duties_t d;
    memset(&d, 0, sizeof(d));
    d.committed_height = 1000;
    d.fresh   = true;
    d.cs_started = true;
    d.n_peers = 3;
    d.max_peer_height = 1001;
    d.state   = NODUS_DNAC_DUTIES_CLEAR;
    return d;
}

static nodus_dnac_node_duties_t blocked(uint8_t code, uint64_t eh) {
    nodus_dnac_node_duties_t d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_BLOCKED;
    d.n_blockers = 1;
    d.blockers[0].code = code;
    d.blockers[0].end_height = eh;
    return d;
}

/* ── tests ───────────────────────────────────────────────────────── */

static void test_layout(void) {
    printf("layout\n");
    nodus_np_units_t u;
    TEST("nodus-core on, nodus off -> SPLIT");
    u = units(OFF, ON, ON, ON);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_SPLIT, "split");
    TEST("core alone is still SPLIT");
    u = units(OFF, ON, OFF, OFF);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_SPLIT, "split");
    TEST("nodus on, nothing else -> COMBINED");
    u = units(ON, OFF, OFF, OFF);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_COMBINED, "comb");
    TEST("nodus + core -> AMBIGUOUS");
    u = units(ON, ON, OFF, OFF);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_AMBIGUOUS, "amb");
    TEST("nodus + witness (no core) -> AMBIGUOUS");
    u = units(ON, OFF, OFF, ON);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_AMBIGUOUS, "amb");
    TEST("witness without core -> AMBIGUOUS");
    u = units(OFF, OFF, OFF, ON);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_AMBIGUOUS, "amb");
    TEST("storage without core -> AMBIGUOUS");
    u = units(OFF, OFF, ON, OFF);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_AMBIGUOUS, "amb");
    TEST("all off -> NONE");
    u = units(OFF, OFF, OFF, OFF);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_NONE, "none");
    TEST("any unit UNKNOWN -> UNKNOWN");
    u = units(OFF, ON, ON, UNK);
    CHECK(nodus_node_package_layout(&u) == NODUS_NP_LAYOUT_UNKNOWN, "unk");
    TEST("NULL -> UNKNOWN");
    CHECK(nodus_node_package_layout(NULL) == NODUS_NP_LAYOUT_UNKNOWN, "null");
}

static void test_verdict_layouts(void) {
    printf("verdict: layouts and add / remove without a chain read\n");
    nodus_np_units_t u;
    nodus_np_verdict_t v;

    TEST("remove storage refused (all on)");
    u = units(OFF, ON, ON, ON);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
          v.reason == NODUS_NP_R_STORAGE_UNAVAILABLE, "remove storage");
    TEST("remove storage refused (storage already off)");
    u = units(OFF, ON, OFF, ON);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_STORAGE_UNAVAILABLE, "remove storage");
    TEST("remove storage refused even with NULL units");
    v = verdict(NULL, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_STORAGE_UNAVAILABLE, "null units");
    TEST("unavailable predicate: only remove storage");
    CHECK(nodus_node_package_unavailable(NODUS_NP_ACT_REMOVE,
                                         NODUS_NP_PKG_STORAGE) &&
          !nodus_node_package_unavailable(NODUS_NP_ACT_ADD,
                                          NODUS_NP_PKG_STORAGE) &&
          !nodus_node_package_unavailable(NODUS_NP_ACT_REMOVE,
                                          NODUS_NP_PKG_WITNESS), "pred");

    TEST("add witness: combined layout refused");
    u = units(ON, OFF, OFF, OFF);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE && v.reason == NODUS_NP_R_COMBINED,
          "combined");
    TEST("remove witness: combined layout refused");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_COMBINED, "combined");
    TEST("add storage: both layouts enabled refused");
    u = units(ON, ON, ON, ON);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_AMBIGUOUS, "ambiguous");
    TEST("add witness: witness enabled without core refused");
    u = units(OFF, OFF, OFF, ON);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_AMBIGUOUS, "ambiguous");
    TEST("remove witness: nothing enabled refused");
    u = units(OFF, OFF, OFF, OFF);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_NO_LAYOUT, "none");
    TEST("a unit state UNKNOWN refuses add");
    u = units(OFF, ON, UNK, OFF);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_UNIT_UNKNOWN, "unknown unit");
    TEST("a unit state UNKNOWN refuses remove (even of an off package)");
    u = units(UNK, ON, ON, OFF);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_UNIT_UNKNOWN, "unknown unit");

    TEST("add witness already on -> ALREADY");
    u = units(OFF, ON, ON, ON);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_ALREADY, "already");
    TEST("add storage already on -> ALREADY");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_ALREADY, "already");
    TEST("add witness while off -> DO");
    u = units(OFF, ON, ON, OFF);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO, "do");
    TEST("add storage while off -> DO");
    u = units(OFF, ON, OFF, ON);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO, "do");
    TEST("add witness with core alone -> DO");
    u = units(OFF, ON, OFF, OFF);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO, "do");

    TEST("remove witness already off -> ALREADY, no reply needed");
    u = units(OFF, ON, ON, OFF);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_ALREADY, "already off");
    TEST("remove witness already off, core alone -> ALREADY");
    u = units(OFF, ON, OFF, OFF);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_ALREADY, "already off");
    TEST("remove witness that would leave core alone refused");
    u = units(OFF, ON, OFF, ON);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
          v.reason == NODUS_NP_R_CORE_ALONE, "core alone");
    TEST("core-alone is judged before any reply is consulted");
    {
        nodus_dnac_node_duties_t d = clear_fresh();
        v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
        CHECK(v.reason == NODUS_NP_R_CORE_ALONE, "core alone with CLEAR");
    }
}

static void test_verdict_replies(void) {
    printf("verdict: remove witness (witness on, storage on) by reply\n");
    const nodus_np_units_t u = units(OFF, ON, ON, ON);
    nodus_np_verdict_t v;
    nodus_dnac_node_duties_t d;

    TEST("reply not read -> NOT_READ, error kept");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL,
                "no pinned session");
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
          v.reason == NODUS_NP_R_NOT_READ &&
          strcmp(v.why, "no pinned session") == 0, "not read");
    TEST("reply not read, no error text -> NOT_READ");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_NOT_READ && v.why[0] != '\0', "not read");

    TEST("CLEAR + fresh -> DO (the only allow)");
    d = clear_fresh();
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO && v.reason == NODUS_NP_R_NONE, "do");
    TEST("CLEAR + !fresh -> NOT_FRESH");
    d = clear_fresh();
    d.fresh = false;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
          v.reason == NODUS_NP_R_NOT_FRESH, "not fresh");
    TEST("UNKNOWN (fresh) -> UNKNOWN with the witness's why");
    d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_UNKNOWN;
    snprintf(d.why, sizeof(d.why), "validators read failed");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.reason == NODUS_NP_R_UNKNOWN &&
          strcmp(v.why, "validators read failed") == 0, "unknown");
    TEST("UNKNOWN without a why still refuses");
    d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_UNKNOWN;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.reason == NODUS_NP_R_UNKNOWN && v.why[0] != '\0', "unknown");
    TEST("a state value outside 0..2 refuses");
    d = clear_fresh();
    d.state = 9;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE && v.reason == NODUS_NP_R_UNKNOWN,
          "bad state");
    TEST("CLEAR that carries a blocker (inconsistent) refuses");
    d = blocked(NODUS_DNAC_DUTY_SEATED_NOW, 50);
    d.state = NODUS_DNAC_DUTIES_CLEAR;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE && v.reason == NODUS_NP_R_UNKNOWN,
          "inconsistent");
    TEST("BLOCKED with no blocker (inconsistent) refuses");
    d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_BLOCKED;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_REFUSE && v.reason == NODUS_NP_R_UNKNOWN,
          "blocked empty");
    TEST("BLOCKED + !fresh -> NOT_FRESH (the view is not trusted)");
    d = blocked(NODUS_DNAC_DUTY_WITNESS_REGISTERED, 0);
    d.fresh = false;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.reason == NODUS_NP_R_NOT_FRESH, "not fresh");

    /* every blocker code */
    static const struct {
        uint8_t code;
        uint64_t eh;
        nodus_np_reason_t reason;
        const char *name;
    } B[] = {
        { NODUS_DNAC_DUTY_WITNESS_REGISTERED, 0,   NODUS_NP_R_REGISTERED, "WITNESS_REGISTERED" },
        { NODUS_DNAC_DUTY_WITNESS_LEAVING,    900, NODUS_NP_R_LEAVING,    "WITNESS_LEAVING" },
        { NODUS_DNAC_DUTY_SEATED_NOW,         720, NODUS_NP_R_DUTIES,     "SEATED_NOW" },
        { NODUS_DNAC_DUTY_SEATED_NEXT,        1440, NODUS_NP_R_DUTIES,    "SEATED_NEXT" },
        { NODUS_DNAC_DUTY_CMT_TRANSITION,     721, NODUS_NP_R_DUTIES,     "CMT_TRANSITION" },
        { NODUS_DNAC_DUTY_STORAGE_REGISTERED, 0,   NODUS_NP_R_REGISTERED, "STORAGE_REGISTERED" },
        { NODUS_DNAC_DUTY_STORAGE_LEAVING,    720, NODUS_NP_R_LEAVING,    "STORAGE_LEAVING" },
        { NODUS_DNAC_DUTY_ARCHIVE_OVERLAP,    1440, NODUS_NP_R_DUTIES,    "ARCHIVE_OVERLAP" },
        { NODUS_DNAC_DUTY_STORAGE_REPORT,     1080, NODUS_NP_R_DUTIES,    "STORAGE_REPORT" },
    };
    for (size_t i = 0; i < sizeof(B) / sizeof(B[0]); i++) {
        char name[96];
        snprintf(name, sizeof(name), "BLOCKED %s refuses with its reason",
                 B[i].name);
        TEST(name);
        d = blocked(B[i].code, B[i].eh);
        v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
        CHECK(v.outcome == NODUS_NP_OUT_REFUSE && v.reason == B[i].reason &&
              v.end_height == B[i].eh &&
              (v.blocker_mask & ((uint32_t)1u << B[i].code)) != 0, B[i].name);
    }

    TEST("several blockers: end height is the max, registered wins");
    d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_BLOCKED;
    d.n_blockers = 3;
    d.blockers[0].code = NODUS_DNAC_DUTY_WITNESS_REGISTERED;
    d.blockers[0].end_height = 0;
    d.blockers[1].code = NODUS_DNAC_DUTY_SEATED_NOW;
    d.blockers[1].end_height = 1440;
    d.blockers[2].code = NODUS_DNAC_DUTY_ARCHIVE_OVERLAP;
    d.blockers[2].end_height = 2160;
    d.n_owners = 2;
    snprintf(d.owners[0], sizeof(d.owners[0]), "aa");
    snprintf(d.owners[1], sizeof(d.owners[1]), "bb");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.reason == NODUS_NP_R_REGISTERED && v.end_height == 2160 &&
          v.n_owners == 2 && strcmp(v.owners[0], "aa") == 0 &&
          strcmp(v.owners[1], "bb") == 0, "several");
    TEST("leaving + duties: leaving wins, end is the max");
    d = clear_fresh();
    d.state = NODUS_DNAC_DUTIES_BLOCKED;
    d.n_blockers = 2;
    d.blockers[0].code = NODUS_DNAC_DUTY_WITNESS_LEAVING;
    d.blockers[0].end_height = 1500;
    d.blockers[1].code = NODUS_DNAC_DUTY_STORAGE_REPORT;
    d.blockers[1].end_height = 1800;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    CHECK(v.reason == NODUS_NP_R_LEAVING && v.end_height == 1800, "leaving");
}

static void test_combined_running(void) {
    printf("verdict: nodus.service running while the split units are enabled\n");
    nodus_np_units_t u;
    nodus_np_verdict_t v;
    char t[NODUS_NODE_PACKAGE_TEXT_MAX];
    /* busy words, then words the verdict does not know, then unread "" */
    static const char *const REFUSED[] = {
        "active", "activating", "deactivating", "reloading", "refreshing",
        "maintenance", "Active", "garbage", ""
    };
    for (size_t i = 0; i < sizeof(REFUSED) / sizeof(REFUSED[0]); i++) {
        char name[96];
        snprintf(name, sizeof(name), "is-active \"%s\": add storage refused",
                 REFUSED[i]);
        TEST(name);
        u = units(OFF, ON, OFF, ON);
        snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "%s",
                 REFUSED[i]);
        v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
        CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
              v.reason == NODUS_NP_R_COMBINED_RUNNING &&
              strcmp(v.why, REFUSED[i]) == 0, "refuse");
    }
    TEST("remove witness (CLEAR + fresh) is refused too: no stop");
    u = units(OFF, ON, ON, ON);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    {
        nodus_dnac_node_duties_t d = clear_fresh();
        v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
        CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
              v.reason == NODUS_NP_R_COMBINED_RUNNING, "remove");
    }
    TEST("add of a package that is already on is refused as well");
    u = units(OFF, ON, ON, ON);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_COMBINED_RUNNING, "already-on");
    TEST("remove witness of an off witness is refused as well");
    u = units(OFF, ON, ON, OFF);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_COMBINED_RUNNING, "already-off");

    TEST("inactive: add storage allowed");
    u = units(OFF, ON, OFF, ON);
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO, "inactive");
    TEST("failed: add storage allowed");
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "failed");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.outcome == NODUS_NP_OUT_DO, "failed");

    TEST("an unreadable nodus enabled state still reports UNIT_UNKNOWN first");
    u = units(UNK, ON, OFF, ON);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_UNIT_UNKNOWN, "unit unknown");
    TEST("the enabled-combined layout keeps its own reason (COMBINED)");
    u = units(ON, OFF, OFF, OFF);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    CHECK(v.reason == NODUS_NP_R_COMBINED, "combined");

    TEST("text: the exact message with the state");
    u = units(OFF, ON, OFF, ON);
    snprintf(u.active[NODUS_NP_UNIT_NODUS], sizeof(u.active[0]), "active");
    v = verdict(&u, NODUS_NP_ACT_ADD, NODUS_NP_PKG_STORAGE, NULL, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_ADD,
                                    NODUS_NP_PKG_STORAGE, t, sizeof(t));
    CHECK(strcmp(t, "nodus.service (the single-service layout) is active on "
                    "this node \xe2\x80\x94 a mixed state this command does "
                    "not touch. Nothing was changed.\n") == 0, t);
}

static void test_long_text(void) {
    printf("texts: the longest message and the fail-closed fallback\n");
    const nodus_np_units_t u = units(OFF, ON, ON, ON);
    nodus_np_verdict_t v;
    nodus_dnac_node_duties_t d = blocked(NODUS_DNAC_DUTY_WITNESS_REGISTERED, 0);
    char t[NODUS_NODE_PACKAGE_TEXT_MAX];
    char last[129];

    d.n_owners = NODUS_DNAC_DUTIES_OWNERS_MAX;
    for (size_t i = 0; i < NODUS_DNAC_DUTIES_OWNERS_MAX; i++) {
        for (size_t k = 0; k < 128; k++)
            d.owners[i][k] = (char)('a' + (int)((i + k) % 6));
        d.owners[i][128] = '\0';
    }
    snprintf(last, sizeof(last), "%s", d.owners[NODUS_DNAC_DUTIES_OWNERS_MAX - 1u]);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);

    TEST("16 owners x 128 hex: every owner is in the text, uncut");
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    {
        bool all = true;
        for (size_t i = 0; i < NODUS_DNAC_DUTIES_OWNERS_MAX; i++)
            if (!strstr(t, d.owners[i])) all = false;
        const size_t len = strlen(t);
        CHECK(all && strstr(t, last) && len < sizeof(t) - 1u &&
              len > 20 && strcmp(t + len - 22, " Nothing was changed.\n") == 0,
              "uncut");
    }
    TEST("a buffer that is too small gives the short fixed message");
    {
        char small[512];
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                        NODUS_NP_PKG_WITNESS, small,
                                        sizeof(small));
        const size_t len = strlen(small);
        CHECK(len > 20 && len < sizeof(small) - 1u &&
              strcmp(small + len - 22, " Nothing was changed.\n") == 0 &&
              strstr(small, last) == NULL, small);
    }
    TEST("a buffer that is one byte too small also fails closed");
    {
        const size_t need = strlen(t) + 1u;      /* t holds the full text */
        char *buf = malloc(need - 1u);
        if (!buf) { FAIL("malloc"); return; }
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                        NODUS_NP_PKG_WITNESS, buf, need - 1u);
        const size_t len = strlen(buf);
        CHECK(strstr(buf, last) == NULL && len > 20 &&
              strcmp(buf + len - 22, " Nothing was changed.\n") == 0, buf);
        free(buf);
    }
    TEST("a buffer of exactly the needed size keeps the full text");
    {
        const size_t need = strlen(t) + 1u;
        char *buf = malloc(need);
        if (!buf) { FAIL("malloc"); return; }
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                        NODUS_NP_PKG_WITNESS, buf, need);
        CHECK(strcmp(buf, t) == 0, "exact");
        free(buf);
    }
}

static void test_texts(void) {
    printf("texts\n");
    const nodus_np_units_t u = units(OFF, ON, ON, ON);
    nodus_np_verdict_t v;
    nodus_dnac_node_duties_t d;
    char t[1024];

    TEST("remove storage: the exact message");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_STORAGE, NULL, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_STORAGE, t, sizeof(t));
    CHECK(strcmp(t, "not available yet: a known DHT defect (BUGS.md D-23) "
                    "must be fixed first \xe2\x80\x94 nothing was changed\n")
          == 0, t);
    TEST("registered: names the owner and where to leave");
    d = blocked(NODUS_DNAC_DUTY_WITNESS_REGISTERED, 0);
    d.n_owners = 1;
    snprintf(d.owners[0], sizeof(d.owners[0]), "abc123");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strstr(t, "registered as a witness owned by abc123") &&
          strstr(t, "The owner must leave first in Nodus Connect (More "
                    "\xe2\x86\x92 Nodus \xe2\x86\x92 My registered nodes)") &&
          strstr(t, "Nothing was changed."), t);
    TEST("registered storage node row: says storage node");
    d = blocked(NODUS_DNAC_DUTY_STORAGE_REGISTERED, 0);
    d.n_owners = 1;
    snprintf(d.owners[0], sizeof(d.owners[0]), "def456");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strstr(t, "registered as a storage node owned by def456") != NULL,
          t);
    TEST("leaving: names the block to retry after");
    d = blocked(NODUS_DNAC_DUTY_WITNESS_LEAVING, 4321);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strstr(t, "leaving as a witness") &&
          strstr(t, "Keep witness running until block 4321, then try again.")
          && strstr(t, "Nothing was changed."), t);
    TEST("duties: names the block and the duty");
    d = blocked(NODUS_DNAC_DUTY_STORAGE_REPORT, 1080);
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strstr(t, "has left, but still has duties until block 1080 "
                    "(storage report window)") &&
          strstr(t, "Try again after block 1080.") &&
          strstr(t, "Nothing was changed."), t);
    TEST("not read: the cannot-check text with the reason");
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL,
                "the node did not answer in time");
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strcmp(t, "Cannot check whether this node is registered (the node "
                    "did not answer in time). Nothing was changed. Start or "
                    "repair the witness (sudo nodus-cli status), then try "
                    "again.\n") == 0, t);
    TEST("not fresh: the cannot-check text says to wait");
    d = clear_fresh();
    d.fresh = false;
    v = verdict(&u, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, &d, NULL);
    nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                    NODUS_NP_PKG_WITNESS, t, sizeof(t));
    CHECK(strstr(t, "Cannot check whether this node is registered (this "
                    "node is not caught up with the chain; wait and retry)")
          != NULL, t);
    TEST("already: 'witness is already off. Nothing was changed.'");
    {
        const nodus_np_units_t o = units(OFF, ON, ON, OFF);
        v = verdict(&o, NODUS_NP_ACT_REMOVE, NODUS_NP_PKG_WITNESS, NULL, NULL);
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_REMOVE,
                                        NODUS_NP_PKG_WITNESS, t, sizeof(t));
        CHECK(strcmp(t, "witness is already off. Nothing was changed.\n") == 0,
              t);
    }
    TEST("combined: says packages exist only on the three-service layout");
    {
        const nodus_np_units_t c = units(ON, OFF, OFF, OFF);
        v = verdict(&c, NODUS_NP_ACT_ADD, NODUS_NP_PKG_WITNESS, NULL, NULL);
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_ADD,
                                        NODUS_NP_PKG_WITNESS, t, sizeof(t));
        CHECK(strstr(t, "single-service layout") &&
              strstr(t, "three-service layout") &&
              strstr(t, "Nothing was changed."), t);
    }
    TEST("a tiny buffer never overruns");
    {
        char small[16];
        memset(small, 'x', sizeof(small));
        nodus_node_package_verdict_text(&v, NODUS_NP_ACT_ADD,
                                        NODUS_NP_PKG_WITNESS, small,
                                        sizeof(small));
        CHECK(memchr(small, '\0', sizeof(small)) != NULL, "terminated");
    }
}

static void test_adapter(void) {
    printf("systemd adapter (fake systemctl)\n");
    nodus_np_units_t u;
    char err[256];
    nodus_np_sysd_t s = fake_sysd(5000, 5000);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    TEST("read_units: states and active text");
    CHECK(nodus_node_package_read_units(&s, &u, err, sizeof(err)) == 0 &&
          u.enabled[NODUS_NP_UNIT_NODUS] == OFF &&
          u.enabled[NODUS_NP_UNIT_CORE] == ON &&
          u.enabled[NODUS_NP_UNIT_STORAGE] == ON &&
          u.enabled[NODUS_NP_UNIT_WITNESS] == OFF &&
          strcmp(u.active[NODUS_NP_UNIT_CORE], "active") == 0 &&
          strcmp(u.active[NODUS_NP_UNIT_WITNESS], "inactive") == 0, "states");
    {
        char log[4096];
        slurp("argv.log", log, sizeof(log));
        TEST("read_units: only fixed is-enabled / is-active calls");
        CHECK(strstr(log, "is-enabled nodus-witness\n") &&
              strstr(log, "is-active nodus-core\n") &&
              !strstr(log, "enable --now") && !strstr(log, "disable"),
              log);
    }

    clear_flags();
    set_units("masked\n", "enabled-runtime\n", "static\n", NULL);
    TEST("read_units: any word but enabled / disabled is UNKNOWN");
    CHECK(nodus_node_package_read_units(&s, &u, err, sizeof(err)) == 0 &&
          u.enabled[NODUS_NP_UNIT_NODUS] == UNK &&
          u.enabled[NODUS_NP_UNIT_CORE] == UNK &&
          u.enabled[NODUS_NP_UNIT_STORAGE] == UNK &&
          u.enabled[NODUS_NP_UNIT_WITNESS] == UNK, "unknown words");

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "enabled\n");
    put("hang", "");
    {
        nodus_np_sysd_t quick = fake_sysd(100, 100);
        TEST("read_units: a child past its deadline is killed -> UNKNOWN");
        CHECK(nodus_node_package_read_units(&quick, &u, err, sizeof(err)) == 0
              && u.enabled[NODUS_NP_UNIT_CORE] == UNK &&
              u.enabled[NODUS_NP_UNIT_WITNESS] == UNK &&
              u.active[NODUS_NP_UNIT_CORE][0] == '\0', "killed");
        nodus_np_verdict_t v = verdict(&u, NODUS_NP_ACT_ADD,
                                       NODUS_NP_PKG_WITNESS, NULL, NULL);
        TEST("... and the verdict on that is a refusal");
        CHECK(v.outcome == NODUS_NP_OUT_REFUSE &&
              v.reason == NODUS_NP_R_UNIT_UNKNOWN, "refuse");
    }

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    TEST("change: enable --now nodus-witness, post-state enabled");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_WITNESS, true, err,
                                    sizeof(err)) == 0, err);
    {
        char log[4096];
        slurp("argv.log", log, sizeof(log));
        TEST("change: the argv was exactly 'enable --now nodus-witness'");
        CHECK(strstr(log, "enable --now nodus-witness\n") != NULL, log);
    }
    TEST("change: disable --now nodus-storage, post-state disabled");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_STORAGE, false, err,
                                    sizeof(err)) == 0, err);
    {
        char log[4096];
        slurp("argv.log", log, sizeof(log));
        CHECK(strstr(log, "disable --now nodus-storage\n") != NULL, log);
    }

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    put("fail", "");
    TEST("change: a non-zero exit is a failure");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_WITNESS, true, err,
                                    sizeof(err)) != 0 &&
          strstr(err, "failed (exit 5)"), err);

    clear_flags();
    put("noop", "");
    TEST("change: exit 0 but the post-state unchanged -> failure");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_WITNESS, true, err,
                                    sizeof(err)) != 0 &&
          strstr(err, "not enabled afterwards"), err);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "enabled\n");
    put("hang", "");
    {
        nodus_np_sysd_t quick = fake_sysd(100, 100);
        TEST("change: a child past its deadline is killed -> failure");
        CHECK(nodus_node_package_change(&quick, NODUS_NP_UNIT_WITNESS, false,
                                        err, sizeof(err)) != 0 &&
              strstr(err, "did not finish in time"), err);
    }

    clear_flags();
    TEST("change: nodus-core can never be changed");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_CORE, false, err,
                                    sizeof(err)) != 0 &&
          !exists("argv.log"), "core");
    TEST("change: the combined unit can never be changed");
    CHECK(nodus_node_package_change(&s, NODUS_NP_UNIT_NODUS, true, err,
                                    sizeof(err)) != 0 &&
          !exists("argv.log"), "nodus");

    {
        char p[512];
        TEST("a missing systemctl path is refused");
        nodus_np_sysd_t bad = { "/nonexistent/systemctl", 100, 100 };
        CHECK(nodus_node_package_read_units(&bad, &u, err, sizeof(err)) != 0,
              "missing");
        TEST("a systemctl that is not executable is refused");
        put("plain", "#!/bin/sh\nexit 0\n");
        path_of(p, sizeof(p), "plain");
        chmod(p, 0644);
        nodus_np_sysd_t nx = { p, 100, 100 };
        CHECK(nodus_node_package_change(&nx, NODUS_NP_UNIT_WITNESS, true,
                                        err, sizeof(err)) != 0, "not exec");
        TEST("a directory as systemctl is refused");
        nodus_np_sysd_t dir = { ROOT, 100, 100 };
        CHECK(nodus_node_package_read_units(&dir, &u, err, sizeof(err)) != 0,
              "dir");
        TEST("a relative systemctl path is refused");
        nodus_np_sysd_t rel = { "systemctl", 100, 100 };
        CHECK(nodus_node_package_read_units(&rel, &u, err, sizeof(err)) != 0,
              "relative");
    }
    TEST("default adapter: fixed /bin/systemctl and the two deadlines");
    {
        nodus_np_sysd_t d;
        nodus_node_package_sysd_default(&d);
        CHECK(strcmp(d.systemctl, "/bin/systemctl") == 0 &&
              d.query_ms == NODUS_NODE_PACKAGE_QUERY_MS &&
              d.change_ms == NODUS_NODE_PACKAGE_CHANGE_MS, "default");
    }
}

static void test_lock(void) {
    printf("host lock\n");
    char p[512], err[256];
    path_of(p, sizeof(p), "lock/nodus-admin.lock");
    char dir[512];
    path_of(dir, sizeof(dir), "lock");
    mkdir(dir, 0755);

    /* the required owner: the CLI passes 0 (root); a test cannot be root */
    const uid_t me = geteuid();

    TEST("missing file: created with mode 0600 under umask 077, taken");
    const mode_t old = umask(077);
    int fd1 = -1, fd2 = -1;
    const int r1 = nodus_node_package_lock_take(p, me, &fd1, err, sizeof(err));
    umask(old);
    struct stat st;
    CHECK(r1 == 0 && fd1 >= 0 && stat(p, &st) == 0 &&
          (st.st_mode & 07777) == 0600 && S_ISREG(st.st_mode) &&
          st.st_uid == me, "created");

    TEST("missing file: created 0600 under umask 000 too (fchmod)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/umask0.lock");
        int fd = -1;
        const mode_t o2 = umask(000);
        const int r = nodus_node_package_lock_take(q, me, &fd, err,
                                                   sizeof(err));
        umask(o2);
        CHECK(r == 0 && stat(q, &st) == 0 && (st.st_mode & 07777) == 0600,
              "0600");
        nodus_node_package_lock_release(fd);
        unlink(q);
    }

    TEST("held by another open file description -> busy (1)");
    const int r2 = nodus_node_package_lock_take(p, me, &fd2, err, sizeof(err));
    CHECK(r2 == 1 && fd2 == -1, "busy");

    TEST("released -> taken again");
    nodus_node_package_lock_release(fd1);
    const int r3 = nodus_node_package_lock_take(p, me, &fd2, err, sizeof(err));
    CHECK(r3 == 0 && fd2 >= 0, "retaken");
    nodus_node_package_lock_release(fd2);

    TEST("the lock fd is close-on-exec");
    {
        int fd = -1;
        const int r = nodus_node_package_lock_take(p, me, &fd, err,
                                                   sizeof(err));
        CHECK(r == 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC), "cloexec");
        nodus_node_package_lock_release(fd);
    }
    TEST("a directory that does not exist -> error (-1)");
    {
        char bad[512];
        path_of(bad, sizeof(bad), "nodir/x.lock");
        int fd = -1;
        CHECK(nodus_node_package_lock_take(bad, me, &fd, err,
                                           sizeof(err)) == -1 &&
              err[0] != '\0', "noent");
    }

    /* A file that is not the vetted kind is refused with -2 and the
     * message — never reported as "busy" (1), never locked. */
    static const char WANT[] = " is not a root-owned 0600 regular file; "
                               "remove it and retry. Nothing was changed.";
    TEST("a symlink as the lock file is refused (-2, not busy)");
    {
        char ln[512];
        path_of(ln, sizeof(ln), "lock/link.lock");
        int fd = -1;
        err[0] = '\0';
        const int r = symlink(p, ln) == 0
                          ? nodus_node_package_lock_take(ln, me, &fd, err,
                                                         sizeof(err))
                          : 99;
        CHECK(r == -2 && fd == -1 && strstr(err, ln) && strstr(err, WANT),
              err);
        unlink(ln);
    }
    TEST("a dangling symlink is refused too (-2)");
    {
        char ln[512], gone[512];
        path_of(ln, sizeof(ln), "lock/dangling.lock");
        path_of(gone, sizeof(gone), "lock/does-not-exist");
        int fd = -1;
        const int r = symlink(gone, ln) == 0
                          ? nodus_node_package_lock_take(ln, me, &fd, err,
                                                         sizeof(err))
                          : 99;
        CHECK(r == -2 && fd == -1 && !exists("lock/does-not-exist"), "dangling");
        unlink(ln);
    }
    TEST("an existing file with a group bit (0640) is refused (-2)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/g.lock");
        int fd = -1;
        err[0] = '\0';
        CHECK(put("lock/g.lock", "") == 0 && chmod(q, 0640) == 0 &&
              nodus_node_package_lock_take(q, me, &fd, err, sizeof(err)) == -2
              && fd == -1 && strstr(err, WANT), err);
        unlink(q);
    }
    TEST("an existing file with an other bit (0604) is refused (-2)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/o.lock");
        int fd = -1;
        CHECK(put("lock/o.lock", "") == 0 && chmod(q, 0604) == 0 &&
              nodus_node_package_lock_take(q, me, &fd, err, sizeof(err)) == -2
              && fd == -1, "other bit");
        unlink(q);
    }
    TEST("the old 0644 lock file is refused, not adopted (-2)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/old.lock");
        int fd = -1;
        CHECK(put("lock/old.lock", "") == 0 && chmod(q, 0644) == 0 &&
              nodus_node_package_lock_take(q, me, &fd, err, sizeof(err)) == -2,
              "0644");
        unlink(q);
    }
    TEST("a file owned by another uid is refused (-2)");
    {
        int fd = -1;
        CHECK(nodus_node_package_lock_take(p, (uid_t)(me + 1u), &fd, err,
                                           sizeof(err)) == -2 && fd == -1 &&
              strstr(err, WANT), err);
    }
    TEST("a FIFO as the lock file is refused and does not hang the open (-2)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/fifo.lock");
        int fd = -1;
        CHECK(mkfifo(q, 0600) == 0 &&
              nodus_node_package_lock_take(q, me, &fd, err, sizeof(err)) == -2
              && fd == -1, "fifo");
        unlink(q);
    }
    TEST("a directory as the lock file is refused (-2 or error, never taken)");
    {
        char q[512];
        path_of(q, sizeof(q), "lock/dir.lock");
        int fd = -1;
        const int r = mkdir(q, 0700) == 0
                          ? nodus_node_package_lock_take(q, me, &fd, err,
                                                         sizeof(err))
                          : 99;
        CHECK((r == -2 || r == -1) && fd == -1, "directory");
        rmdir(q);
    }
    unlink(p);
    rmdir(dir);
}

static void test_addr_seq(void) {
    printf("addr_seq rule\n");
    char idp[512], dap[512], err[256];
    path_of(idp, sizeof(idp), "ident");
    path_of(dap, sizeof(dap), "data");
    mkdir(idp, 0755);
    mkdir(dap, 0755);
    bool moved = true;

    TEST("neither file -> nothing");
    CHECK(nodus_node_package_addr_seq(idp, dap, &moved, err, sizeof(err)) == 0
          && !moved, "neither");
    TEST("only the data one -> nothing");
    put("data/nodus.addr_seq", "7");
    CHECK(nodus_node_package_addr_seq(idp, dap, &moved, err, sizeof(err)) == 0
          && !moved && exists("data/nodus.addr_seq"), "only new");
    TEST("both -> refused, nothing moved");
    put("ident/nodus.addr_seq", "3");
    CHECK(nodus_node_package_addr_seq(idp, dap, &moved, err, sizeof(err)) != 0
          && strstr(err, "cannot tell which") &&
          exists("ident/nodus.addr_seq") && exists("data/nodus.addr_seq"),
          err);
    TEST("only the identity one -> moved into data_path");
    rm("data/nodus.addr_seq");
    {
        char before[16], after[16];
        slurp("ident/nodus.addr_seq", before, sizeof(before));
        const int rc = nodus_node_package_addr_seq(idp, dap, &moved, err,
                                                   sizeof(err));
        slurp("data/nodus.addr_seq", after, sizeof(after));
        CHECK(rc == 0 && moved && !exists("ident/nodus.addr_seq") &&
              strcmp(before, after) == 0 && strcmp(after, "3") == 0, "moved");
    }
    TEST("identity_path == data_path -> nothing");
    put("ident/nodus.addr_seq", "4");
    CHECK(nodus_node_package_addr_seq(idp, idp, &moved, err, sizeof(err)) == 0
          && !moved && exists("ident/nodus.addr_seq"), "same dir");
    rm("ident/nodus.addr_seq");
    rm("data/nodus.addr_seq");
    rmdir(idp);
    rmdir(dap);
}

static int run_main(const char *a0, const char *a1, const nodus_np_sysd_t *s,
                    const char *lock, const char *cfg, char *out,
                    size_t cap) {
    const char *args[2];
    int n = 0;
    if (a0) args[n++] = a0;
    if (a1) args[n++] = a1;
    /* the lock file is owned by the test user, not root */
    return nodus_node_package_main(args, n, s, lock, geteuid(), cfg, out, cap);
}

static void test_main(void) {
    printf("nodus_node_package_main (fake systemctl)\n");
    char lock[512], cfg[512], out[4096], log[4096];
    path_of(lock, sizeof(lock), "main.lock");
    path_of(cfg, sizeof(cfg), "missing.conf");
    nodus_np_sysd_t s = fake_sysd(5000, 5000);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    TEST("list: one line per package and the layout, no lock taken");
    CHECK(run_main("list", NULL, &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "Layout: three-service") &&
          strstr(out, "witness: off (nodus-witness: disabled, inactive)") &&
          strstr(out, "storage: on (nodus-storage: enabled, active)") &&
          !exists("main.lock"), out);

    clear_flags();
    set_units("enabled\n", "disabled\n", "disabled\n", "disabled\n");
    TEST("list on the combined layout explains it");
    CHECK(run_main("list", NULL, &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "single-service") &&
          strstr(out, "only on the three-service layout"), out);

    TEST("usage: no argument, unknown subcommand, unknown package, extra");
    CHECK(run_main(NULL, NULL, &s, lock, cfg, out, sizeof(out)) == 1 &&
          strstr(out, "Usage:") &&
          run_main("frobnicate", NULL, &s, lock, cfg, out, sizeof(out)) == 1 &&
          run_main("add", "core", &s, lock, cfg, out, sizeof(out)) == 1 &&
          run_main("add", NULL, &s, lock, cfg, out, sizeof(out)) == 1 &&
          run_main("list", "x", &s, lock, cfg, out, sizeof(out)) == 1,
          "usage");

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "enabled\n");
    TEST("remove storage: refused, no lock, no systemctl call");
    CHECK(run_main("remove", "storage", &s, lock, cfg, out, sizeof(out)) == 1
          && strstr(out, "not available yet: a known DHT defect (BUGS.md "
                         "D-23)") && !exists("main.lock") &&
          !exists("argv.log"), out);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    TEST("busy lock: refused with the lock message, no systemctl call");
    {
        int held = -1;
        char e[128];
        const int lk = nodus_node_package_lock_take(lock, geteuid(), &held, e,
                                                    sizeof(e));
        const int rc = run_main("add", "witness", &s, lock, cfg, out,
                                sizeof(out));
        CHECK(lk == 0 && rc == 1 &&
              strstr(out, "another Nodus install, update or package change "
                          "is running on this host") &&
              strstr(out, "nothing was changed") && !exists("argv.log"),
              out);
        nodus_node_package_lock_release(held);
    }

    /* a lock file that is not 0600 / not ours: refused, not "busy", and no
     * unit is read or changed */
    clear_flags();
    set_units("disabled\n", "enabled\n", "disabled\n", "enabled\n");
    TEST("unsafe lock file (0644): refused with its own message, not busy");
    {
        char lp[512];
        path_of(lp, sizeof(lp), "main.lock");
        CHECK(put("main.lock", "") == 0 && chmod(lp, 0644) == 0 &&
              run_main("add", "storage", &s, lock, cfg, out, sizeof(out)) == 1
              && strstr(out, "is not a root-owned 0600 regular file; remove "
                             "it and retry. Nothing was changed.") &&
              !strstr(out, "is running") && !exists("argv.log"), out);
        unlink(lp);
    }

    /* R1: nodus.service running, split units enabled */
    clear_flags();
    set_units("disabled\n", "enabled\n", "disabled\n", "enabled\n");
    put("act.nodus", "active\n");
    TEST("nodus.service active, split enabled: add storage refused, no enable");
    CHECK(run_main("add", "storage", &s, lock, cfg, out, sizeof(out)) == 1 &&
          strstr(out, "nodus.service (the single-service layout) is active "
                      "on this node") &&
          strstr(out, "a mixed state this command does not touch. Nothing "
                      "was changed."), out);
    slurp("argv.log", log, sizeof(log));
    TEST("... and systemctl was never asked to enable or disable");
    CHECK(!strstr(log, "enable --now") && !strstr(log, "disable --now") &&
          strstr(log, "is-enabled nodus") != NULL, log);
    TEST("nodus.service activating: remove witness refused, nothing stopped");
    clear_flags();
    put("act.nodus", "activating\n");
    CHECK(run_main("remove", "witness", &s, lock, cfg, out, sizeof(out)) == 1
          && strstr(out, "is activating on this node"), out);
    slurp("argv.log", log, sizeof(log));
    CHECK(!strstr(log, "--now"), log);
    TEST("nodus.service with an unknown is-active word: refused");
    clear_flags();
    put("act.nodus", "bogus\n");
    CHECK(run_main("add", "storage", &s, lock, cfg, out, sizeof(out)) == 1 &&
          strstr(out, "is bogus on this node"), out);
    TEST("list reports a running nodus.service and exits 0");
    clear_flags();
    put("act.nodus", "active\n");
    CHECK(run_main("list", NULL, &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "Warning: nodus.service (the single-service layout) is "
                      "active on this node") &&
          strstr(out, "package add and remove are refused"), out);
    TEST("nodus.service inactive again: add storage goes ahead");
    clear_flags();
    set_units("disabled\n", "enabled\n", "disabled\n", "enabled\n");
    CHECK(run_main("add", "storage", &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "storage is now on"), out);

    clear_flags();
    set_units("enabled\n", "disabled\n", "disabled\n", "disabled\n");
    TEST("combined layout: add refused, nothing changed");
    CHECK(run_main("add", "witness", &s, lock, cfg, out, sizeof(out)) == 1 &&
          strstr(out, "single-service layout"), out);
    slurp("argv.log", log, sizeof(log));
    TEST("... and systemctl was only asked for states");
    CHECK(!strstr(log, "--now"), log);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "enabled\n");
    TEST("add witness already on: success, no change");
    CHECK(run_main("add", "witness", &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "witness is already on."), out);
    slurp("argv.log", log, sizeof(log));
    CHECK(!strstr(log, "--now"), log);

    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    clear_flags();
    TEST("remove witness already off: success, no chain read");
    CHECK(run_main("remove", "witness", &s, lock, cfg, out, sizeof(out)) == 0
          && strstr(out, "witness is already off."), out);

    clear_flags();
    set_units("disabled\n", "enabled\n", "disabled\n", "enabled\n");
    TEST("remove witness that would leave core alone: refused");
    CHECK(run_main("remove", "witness", &s, lock, cfg, out, sizeof(out)) == 1
          && strstr(out, "nodus-core never runs alone"), out);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "enabled\n");
    TEST("remove witness, registration unreadable: refused, not stopped");
    CHECK(run_main("remove", "witness", &s, lock, cfg, out, sizeof(out)) == 1
          && strstr(out, "Cannot check whether this node is registered (") &&
          strstr(out, "Nothing was changed."), out);
    slurp("argv.log", log, sizeof(log));
    CHECK(!strstr(log, "disable") && !strstr(log, "--now"), log);

    clear_flags();
    set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
    TEST("add witness, node config unreadable: refused, not started");
    CHECK(run_main("add", "witness", &s, lock, cfg, out, sizeof(out)) == 1 &&
          strstr(out, "Cannot read the node config"), out);
    slurp("argv.log", log, sizeof(log));
    CHECK(!strstr(log, "--now"), log);

    clear_flags();
    set_units("disabled\n", "enabled\n", "disabled\n", "enabled\n");
    TEST("add storage while off: enabled and started");
    CHECK(run_main("add", "storage", &s, lock, cfg, out, sizeof(out)) == 0 &&
          strstr(out, "storage is now on"), out);
    slurp("argv.log", log, sizeof(log));
    CHECK(strstr(log, "enable --now nodus-storage\n") != NULL, log);

#ifdef NODUS_HAS_JSONC
    {
        char c2[512];
        path_of(c2, sizeof(c2), "ok.conf");
        char body[1024], idp[512], dap[512];
        path_of(idp, sizeof(idp), "ident2");
        path_of(dap, sizeof(dap), "data2");
        mkdir(idp, 0755);
        mkdir(dap, 0755);
        snprintf(body, sizeof(body),
                 "{\"identity_path\":\"%s\",\"data_path\":\"%s\"}", idp, dap);
        put("ok.conf", body);
        put("ident2/nodus.addr_seq", "9");

        clear_flags();
        set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
        TEST("add witness: addr_seq moved, then enabled and started");
        CHECK(run_main("add", "witness", &s, lock, c2, out, sizeof(out)) == 0
              && strstr(out, "witness is now on") &&
              !exists("ident2/nodus.addr_seq") &&
              exists("data2/nodus.addr_seq"), out);
        slurp("argv.log", log, sizeof(log));
        CHECK(strstr(log, "enable --now nodus-witness\n") != NULL, log);

        clear_flags();
        set_units("disabled\n", "enabled\n", "enabled\n", "disabled\n");
        put("ident2/nodus.addr_seq", "9");
        TEST("add witness with both addr_seq files: refused, not started");
        CHECK(run_main("add", "witness", &s, lock, c2, out, sizeof(out)) == 1
              && strstr(out, "cannot tell which") &&
              exists("ident2/nodus.addr_seq") &&
              exists("data2/nodus.addr_seq"), out);
        slurp("argv.log", log, sizeof(log));
        CHECK(!strstr(log, "--now"), log);

        rm("ident2/nodus.addr_seq");
        rm("data2/nodus.addr_seq");
        rmdir(idp);
        rmdir(dap);
    }
#else
    printf("  (json-c not in this build: the config-driven add-witness "
           "cases are not compiled — coverage ABSENT, not passed)\n");
#endif
    unlink(lock);
}

static void rmtree(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) rmtree(p);
        else unlink(p);
    }
    closedir(d);
    rmdir(dir);
}

int main(void) {
    printf("=== nodus-cli package ===\n");
    snprintf(ROOT, sizeof(ROOT), "/tmp/test_node_package_XXXXXX");
    if (!mkdtemp(ROOT)) {
        printf("cannot create the fixture directory\n");
        return 1;
    }
    if (write_fake() != 0) {
        printf("cannot write the fake systemctl\n");
        rmtree(ROOT);
        return 1;
    }
    test_layout();
    test_verdict_layouts();
    test_verdict_replies();
    test_combined_running();
    test_long_text();
    test_texts();
    test_adapter();
    test_lock();
    test_addr_seq();
    test_main();
    rmtree(ROOT);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
