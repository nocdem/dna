/**
 * Nodus — nodus_server_identity_load_or_create
 *
 * The server's identity start-up rule (decision
 * 2026-10-01-nodus-component-split item 10): an identity is created only
 * when NEITHER nodus.pk NOR nodus.sk exists; an existing identity that
 * cannot be loaded (missing half, truncated, unreadable) is refused with
 * the directory left byte-identical, and a first-start identity that
 * cannot be saved is refused too.
 *
 * In-process, no network, no clock. mkdtemp dirs under /tmp, removed at
 * the end. The two permission cases print SKIP (never PASS) under euid 0,
 * which bypasses file modes.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp under -std=c11 */

#include "server/nodus_server.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define SKIP(msg)  do { printf("SKIP: %s\n", msg); skipped++; } while(0)

static int passed = 0;
static int failed = 0;
static int skipped = 0;

/* ── Directory snapshot: every regular file's name + bytes ─────────── */

#define SNAP_MAX_FILES 16

typedef struct {
    int     n;
    char    name[SNAP_MAX_FILES][64];
    uint8_t *data[SNAP_MAX_FILES];
    size_t  len[SNAP_MAX_FILES];
    mode_t  mode[SNAP_MAX_FILES];
} dir_snap_t;

static void snap_free(dir_snap_t *s) {
    for (int i = 0; i < s->n; i++)
        free(s->data[i]);
    memset(s, 0, sizeof(*s));
}

static int snap_find(const dir_snap_t *s, const char *name) {
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->name[i], name) == 0)
            return i;
    return -1;
}

/* Reads every entry of `dir`; a file it cannot read (mode 0000) is
 * recorded with its mode and no data. 0 / -1. */
static int snap_take(const char *dir, dir_snap_t *s) {
    memset(s, 0, sizeof(*s));
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (s->n >= SNAP_MAX_FILES ||
            strlen(e->d_name) >= sizeof(s->name[0])) {
            rc = -1;
            break;
        }
        int i = s->n++;
        snprintf(s->name[i], sizeof(s->name[i]), "%s", e->d_name);
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) { rc = -1; break; }
        s->mode[i] = st.st_mode;
        FILE *f = fopen(p, "rb");
        if (!f) continue;               /* unreadable: mode only */
        s->data[i] = malloc((size_t)st.st_size + 1);
        if (!s->data[i]) { fclose(f); rc = -1; break; }
        s->len[i] = fread(s->data[i], 1, (size_t)st.st_size, f);
        fclose(f);
        if (s->len[i] != (size_t)st.st_size) { rc = -1; break; }
    }
    closedir(d);
    if (rc != 0) snap_free(s);
    return rc;
}

static bool snap_equal(const dir_snap_t *a, const dir_snap_t *b) {
    if (a->n != b->n) return false;
    for (int i = 0; i < a->n; i++) {
        int j = snap_find(b, a->name[i]);
        if (j < 0) return false;
        if (a->mode[i] != b->mode[j]) return false;
        if ((a->data[i] == NULL) != (b->data[j] == NULL)) return false;
        if (a->len[i] != b->len[j]) return false;
        if (a->data[i] && memcmp(a->data[i], b->data[j], a->len[i]) != 0)
            return false;
    }
    return true;
}

/* ── Helpers ───────────────────────────────────────────────────────── */

static bool make_tmpdir(char *buf, size_t cap) {
    snprintf(buf, cap, "/tmp/nodus_idloc_XXXXXX");
    return mkdtemp(buf) != NULL;
}

static void rm_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            struct stat st;
            if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
                chmod(p, 0700);
                rm_dir(p);
            } else {
                unlink(p);
            }
        }
        closedir(d);
    }
    rmdir(dir);
}

static bool file_exists(const char *dir, const char *name) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return lstat(p, &st) == 0;
}

static bool is_zeroed(const nodus_identity_t *id) {
    const uint8_t *b = (const uint8_t *)id;
    for (size_t i = 0; i < sizeof(*id); i++)
        if (b[i] != 0) return false;
    return true;
}

/* A full, valid identity saved to `dir` the way the server saves one. */
static bool seed_identity(const char *dir, nodus_identity_t *saved) {
    if (nodus_identity_generate(saved) != 0) return false;
    return nodus_identity_save(saved, dir) == 0;
}

/* ── (1) empty dir → created; a second call loads the same node_id ─── */

static void test_first_start_creates(void) {
    TEST("empty dir: created (1), second call loads same id (0)");
    char dir[64];
    if (!make_tmpdir(dir, sizeof(dir))) { FAIL("mkdtemp"); return; }

    nodus_identity_t a, b;
    int rc1 = nodus_server_identity_load_or_create(dir, &a);
    bool files = file_exists(dir, "nodus.pk") && file_exists(dir, "nodus.sk");
    int rc2 = nodus_server_identity_load_or_create(dir, &b);

    if (rc1 != 1)
        FAIL("first call did not return 1 (created)");
    else if (!files)
        FAIL("nodus.pk / nodus.sk not written");
    else if (rc2 != 0)
        FAIL("second call did not return 0 (loaded)");
    else if (nodus_key_cmp(&a.node_id, &b.node_id) != 0 ||
             memcmp(a.sk.bytes, b.sk.bytes, NODUS_SK_BYTES) != 0)
        FAIL("second call loaded a different identity");
    else
        PASS();

    nodus_identity_clear(&a);
    nodus_identity_clear(&b);
    rm_dir(dir);
}

/* ── (2) valid identity → loaded, directory byte-identical ─────────── */

static void test_valid_loaded_untouched(void) {
    TEST("valid identity: loaded (0), directory byte-identical");
    char dir[64];
    if (!make_tmpdir(dir, sizeof(dir))) { FAIL("mkdtemp"); return; }

    nodus_identity_t saved, got;
    dir_snap_t before, after;
    if (!seed_identity(dir, &saved) || snap_take(dir, &before) != 0) {
        FAIL("setup");
        nodus_identity_clear(&saved);
        rm_dir(dir);
        return;
    }
    int rc = nodus_server_identity_load_or_create(dir, &got);
    int src = snap_take(dir, &after);

    if (rc != 0)
        FAIL("did not return 0");
    else if (nodus_key_cmp(&saved.node_id, &got.node_id) != 0)
        FAIL("loaded node_id differs from the saved one");
    else if (src != 0 || !snap_equal(&before, &after))
        FAIL("directory changed");
    else
        PASS();

    snap_free(&before);
    if (src == 0) snap_free(&after);
    nodus_identity_clear(&saved);
    nodus_identity_clear(&got);
    rm_dir(dir);
}

/* Shared body of the refusal cases: `mutate` damages a valid identity,
 * then the call must return -1, clear `out`, and leave the directory as
 * it was after the damage. */
typedef bool (*mutate_fn)(const char *dir);

static void expect_refused(const char *name, mutate_fn mutate,
                           const char *must_not_exist) {
    TEST(name);
    char dir[64];
    if (!make_tmpdir(dir, sizeof(dir))) { FAIL("mkdtemp"); return; }

    nodus_identity_t saved, got;
    dir_snap_t before, after;
    if (!seed_identity(dir, &saved) || !mutate(dir) ||
        snap_take(dir, &before) != 0) {
        FAIL("setup");
        nodus_identity_clear(&saved);
        rm_dir(dir);
        return;
    }
    memset(&got, 0xA5, sizeof(got));
    int rc = nodus_server_identity_load_or_create(dir, &got);
    int src = snap_take(dir, &after);

    if (rc != -1)
        FAIL("did not return -1");
    else if (!is_zeroed(&got))
        FAIL("out not cleared on -1");
    else if (src != 0 || !snap_equal(&before, &after))
        FAIL("directory changed");
    else if (must_not_exist && file_exists(dir, must_not_exist))
        FAIL("a missing key file was created");
    else
        PASS();

    snap_free(&before);
    if (src == 0) snap_free(&after);
    nodus_identity_clear(&saved);
    rm_dir(dir);
}

static bool mutate_delete_sk(const char *dir) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/nodus.sk", dir);
    return unlink(p) == 0;
}

static bool mutate_truncate_sk(const char *dir) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/nodus.sk", dir);
    return truncate(p, NODUS_SK_BYTES / 2) == 0;
}

static bool mutate_sk_mode_0000(const char *dir) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/nodus.sk", dir);
    return chmod(p, 0000) == 0;
}

/* ── (3) nodus.sk deleted, nodus.pk kept → -1, nothing written ─────── */

static void test_missing_sk_refused(void) {
    expect_refused("nodus.sk missing, nodus.pk kept: refused (-1)",
                   mutate_delete_sk, "nodus.sk");
}

/* ── (4) nodus.sk truncated → -1, both files untouched ─────────────── */

static void test_truncated_sk_refused(void) {
    expect_refused("nodus.sk truncated: refused (-1), untouched",
                   mutate_truncate_sk, NULL);
}

/* ── (5) nodus.sk mode 0000 → -1, untouched ────────────────────────── */

static void test_unreadable_sk_refused(void) {
    if (geteuid() == 0) {
        TEST("nodus.sk mode 0000: refused (-1), untouched");
        SKIP("running as root — file modes are not enforced");
        return;
    }
    expect_refused("nodus.sk mode 0000: refused (-1), untouched",
                   mutate_sk_mode_0000, NULL);
}

/* ── (6) first start whose save fails → -1 ─────────────────────────── */

/* (6a) the identity directory does not exist: both key files are absent
 * (ENOENT), so this is a first start, and the save fails. */
static void test_save_fails_missing_dir(void) {
    TEST("first start, directory missing: save fails, refused (-1)");
    char base[64];
    if (!make_tmpdir(base, sizeof(base))) { FAIL("mkdtemp"); return; }
    char dir[128];
    snprintf(dir, sizeof(dir), "%s/absent", base);

    nodus_identity_t got;
    memset(&got, 0xA5, sizeof(got));
    int rc = nodus_server_identity_load_or_create(dir, &got);
    struct stat st;
    bool created = lstat(dir, &st) == 0;

    if (rc != -1)
        FAIL("did not return -1");
    else if (!is_zeroed(&got))
        FAIL("out not cleared on -1");
    else if (created)
        FAIL("the directory was created");
    else
        PASS();

    rm_dir(base);
}

/* (6b) the identity directory exists, is empty and is not writable. */
static void test_save_fails_readonly_dir(void) {
    TEST("first start, directory read-only: save fails, refused (-1)");
    if (geteuid() == 0) {
        SKIP("running as root — directory modes are not enforced");
        return;
    }
    char dir[64];
    if (!make_tmpdir(dir, sizeof(dir))) { FAIL("mkdtemp"); return; }
    if (chmod(dir, 0500) != 0) { FAIL("chmod"); rm_dir(dir); return; }

    nodus_identity_t got;
    memset(&got, 0xA5, sizeof(got));
    int rc = nodus_server_identity_load_or_create(dir, &got);
    bool any = file_exists(dir, "nodus.pk") || file_exists(dir, "nodus.sk");

    if (rc != -1)
        FAIL("did not return -1");
    else if (!is_zeroed(&got))
        FAIL("out not cleared on -1");
    else if (any)
        FAIL("a key file was written");
    else
        PASS();

    chmod(dir, 0700);
    rm_dir(dir);
}

int main(void) {
    printf("nodus_server_identity_load_or_create tests\n");

    test_first_start_creates();
    test_valid_loaded_untouched();
    test_missing_sk_refused();
    test_truncated_sk_refused();
    test_unreadable_sk_refused();
    test_save_fails_missing_dir();
    test_save_fails_readonly_dir();

    printf("\n%d passed, %d failed, %d skipped\n", passed, failed, skipped);
    return failed > 0 ? 1 : 0;
}
