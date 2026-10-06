/**
 * qgp_state.c - trust directory, accepted-versions record (R2-5), dpkg-deb
 * field read, package policy. Linux only (memfd_create, flock).
 */
#define _GNU_SOURCE
#include "qgp_state.h"
#include "qgp_debver.h"
#include "qgp_io.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "QGP_STATE"

#define DPKG_DEB_PATH   "/usr/bin/dpkg-deb"
#define DPKG_OUT_MAX    (64u * 1024u)

static qgp_rc_t join(const char *dir, const char *name, char *out, size_t out_n)
{
    if (!dir || !name)
        return QGP_E_ARG;
    int n = snprintf(out, out_n, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_n)
        return QGP_E_ARG;
    return QGP_OK;
}

qgp_rc_t qgp_state_lock(const char *dir, int *fd_out)
{
    char path[PATH_MAX];
    if (!fd_out)
        return QGP_E_ARG;
    *fd_out = -1;
    qgp_rc_t rc = join(dir, QGP_STATE_LOCK_FILE, path, sizeof(path));
    if (rc != QGP_OK)
        return rc;
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "lock %s: %s", path, strerror(errno));
        return QGP_E_IO;
    }
    int r;
    do {
        r = flock(fd, LOCK_EX);
    } while (r != 0 && errno == EINTR);
    if (r != 0) {
        close(fd);
        return QGP_E_IO;
    }
    *fd_out = fd;
    return QGP_OK;
}

void qgp_state_unlock(int fd)
{
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
}

qgp_rc_t qgp_state_load_trust(const char *dir, qgp_trust_stored_t *out)
{
    char path[PATH_MAX];
    if (!out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    qgp_rc_t rc = join(dir, QGP_STATE_TRUST_FILE, path, sizeof(path));
    if (rc != QGP_OK)
        return rc;
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return QGP_E_NO_TRUST_STATE;
        return QGP_E_IO;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    rc = qgp_io_read_file(path, QGP_TRUST_FILE_MAX, &buf, &len);
    if (rc == QGP_E_TOO_LARGE)
        rc = QGP_E_STATE_CORRUPT;
    if (rc != QGP_OK)
        return rc;
    rc = qgp_trust_stored_load(buf, len, out);
    free(buf);
    if (rc != QGP_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s does not parse: %s", path, qgp_rc_str(rc));
        return QGP_E_STATE_CORRUPT;
    }
    return QGP_OK;
}

qgp_rc_t qgp_state_store_trust(const char *dir, const uint8_t *f, size_t len)
{
    char path[PATH_MAX];
    qgp_rc_t rc = join(dir, QGP_STATE_TRUST_FILE, path, sizeof(path));
    if (rc != QGP_OK)
        return rc;
    return qgp_io_write_atomic(path, f, len, 0644);
}

/* ---- accepted-versions ------------------------------------------------- */

void qgp_accepted_free(qgp_accepted_list_t *l)
{
    if (!l)
        return;
    for (size_t i = 0; i < l->n; i++) {
        free(l->v[i].pkg);
        free(l->v[i].ver);
    }
    free(l->v);
    memset(l, 0, sizeof(*l));
}

static char *dup_n(const char *s, size_t n)
{
    char *c = malloc(n + 1);
    if (!c)
        return NULL;
    memcpy(c, s, n);
    c[n] = '\0';
    return c;
}

qgp_rc_t qgp_accepted_parse(const uint8_t *buf, size_t len, qgp_accepted_list_t *out)
{
    if (!out || (!buf && len))
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    if (len > QGP_ACCEPTED_MAX)
        return QGP_E_STATE_CORRUPT;
    if (len == 0)
        return QGP_OK;
    if (buf[len - 1] != '\n')
        return QGP_E_STATE_CORRUPT;
    size_t n_lines = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n')
            n_lines++;
    out->v = calloc(n_lines, sizeof(*out->v));
    if (!out->v)
        return QGP_E_NOMEM;

    qgp_rc_t rc = QGP_OK;
    size_t start = 0;
    for (size_t i = 0; i < len && rc == QGP_OK; i++) {
        if (buf[i] != '\n')
            continue;
        const char *ln = (const char *)buf + start;
        size_t n = i - start;
        start = i + 1;
        const char *sp = memchr(ln, ' ', n);
        if (!sp) { rc = QGP_E_STATE_CORRUPT; break; }
        size_t pn = (size_t)(sp - ln);
        size_t vn = n - pn - 1;
        if (!qgp_debpkg_name_valid(ln, pn) || pn > QGP_FIELD_MAX ||
            vn > QGP_FIELD_MAX || qgp_debver_check(sp + 1, vn) != QGP_OK) {
            rc = QGP_E_STATE_CORRUPT;
            break;
        }
        if (out->n > 0) {
            const char *prev = out->v[out->n - 1].pkg;
            size_t prev_n = strlen(prev);
            size_t m = prev_n < pn ? prev_n : pn;
            int c = memcmp(prev, ln, m);
            if (c > 0 || (c == 0 && prev_n >= pn)) {   /* strictly increasing */
                rc = QGP_E_STATE_CORRUPT;
                break;
            }
        }
        out->v[out->n].pkg = dup_n(ln, pn);
        out->v[out->n].ver = dup_n(sp + 1, vn);
        if (!out->v[out->n].pkg || !out->v[out->n].ver) {
            free(out->v[out->n].pkg);
            free(out->v[out->n].ver);
            rc = QGP_E_NOMEM;
            break;
        }
        out->n++;
    }
    if (rc != QGP_OK)
        qgp_accepted_free(out);
    return rc;
}

qgp_rc_t qgp_accepted_serialize(const qgp_accepted_list_t *l, uint8_t **out, size_t *out_len)
{
    if (!l || !out || !out_len)
        return QGP_E_ARG;
    size_t total = 0;
    for (size_t i = 0; i < l->n; i++)
        total += strlen(l->v[i].pkg) + 1 + strlen(l->v[i].ver) + 1;
    if (total > QGP_ACCEPTED_MAX)
        return QGP_E_TOO_LARGE;
    uint8_t *b = malloc(total ? total : 1);
    if (!b)
        return QGP_E_NOMEM;
    size_t o = 0;
    for (size_t i = 0; i < l->n; i++) {
        size_t pn = strlen(l->v[i].pkg), vn = strlen(l->v[i].ver);
        memcpy(b + o, l->v[i].pkg, pn); o += pn;
        b[o++] = ' ';
        memcpy(b + o, l->v[i].ver, vn); o += vn;
        b[o++] = '\n';
    }
    *out = b;
    *out_len = total;
    return QGP_OK;
}

const char *qgp_accepted_get(const qgp_accepted_list_t *l, const char *pkg)
{
    if (!l || !pkg)
        return NULL;
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i].pkg, pkg) == 0)
            return l->v[i].ver;
    return NULL;
}

qgp_rc_t qgp_accepted_set(qgp_accepted_list_t *l, const char *pkg, const char *ver)
{
    if (!l || !pkg || !ver)
        return QGP_E_ARG;
    size_t pn = strlen(pkg), vn = strlen(ver);
    if (!qgp_debpkg_name_valid(pkg, pn) || pn > QGP_FIELD_MAX)
        return QGP_E_BAD_PACKAGE_NAME;
    if (vn > QGP_FIELD_MAX || qgp_debver_check(ver, vn) != QGP_OK)
        return QGP_E_BAD_VERSION;
    size_t pos = 0;
    while (pos < l->n && strcmp(l->v[pos].pkg, pkg) < 0)
        pos++;
    char *nv = dup_n(ver, vn);
    if (!nv)
        return QGP_E_NOMEM;
    if (pos < l->n && strcmp(l->v[pos].pkg, pkg) == 0) {
        free(l->v[pos].ver);
        l->v[pos].ver = nv;
        return QGP_OK;
    }
    char *np = dup_n(pkg, pn);
    qgp_accepted_t *grown = realloc(l->v, (l->n + 1) * sizeof(*l->v));
    if (!np || !grown) {
        free(np);
        free(nv);
        if (grown)
            l->v = grown;
        return QGP_E_NOMEM;
    }
    l->v = grown;
    memmove(&l->v[pos + 1], &l->v[pos], (l->n - pos) * sizeof(*l->v));
    l->v[pos].pkg = np;
    l->v[pos].ver = nv;
    l->n++;
    return QGP_OK;
}

qgp_rc_t qgp_state_load_accepted(const char *dir, qgp_accepted_list_t *out)
{
    char path[PATH_MAX];
    if (!out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    qgp_rc_t rc = join(dir, QGP_STATE_ACCEPTED_FILE, path, sizeof(path));
    if (rc != QGP_OK)
        return rc;
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return QGP_OK;
        return QGP_E_IO;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    rc = qgp_io_read_file(path, QGP_ACCEPTED_MAX, &buf, &len);
    if (rc == QGP_E_TOO_LARGE)
        rc = QGP_E_STATE_CORRUPT;
    if (rc != QGP_OK)
        return rc;
    rc = qgp_accepted_parse(buf, len, out);
    free(buf);
    if (rc != QGP_OK)
        QGP_LOG_ERROR(LOG_TAG, "%s does not parse: %s", path, qgp_rc_str(rc));
    return rc;
}

qgp_rc_t qgp_state_store_accepted(const char *dir, const qgp_accepted_list_t *l)
{
    char path[PATH_MAX];
    qgp_rc_t rc = join(dir, QGP_STATE_ACCEPTED_FILE, path, sizeof(path));
    if (rc != QGP_OK)
        return rc;
    uint8_t *buf = NULL;
    size_t len = 0;
    rc = qgp_accepted_serialize(l, &buf, &len);
    if (rc != QGP_OK)
        return rc;
    rc = qgp_io_write_atomic(path, buf, len, 0644);
    free(buf);
    return rc;
}

/* ---- dpkg-deb -f -------------------------------------------------------- */

static int arch_valid(const char *s, size_t n)
{
    if (n == 0)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

qgp_rc_t qgp_control_fields_parse(const char *out, size_t n, qgp_control_fields_t *f)
{
    if (!out || !f)
        return QGP_E_ARG;
    memset(f, 0, sizeof(*f));
    if (n == 0 || out[n - 1] != '\n')
        return QGP_E_BAD_CONTROL_FIELDS;
    int seen_pkg = 0, seen_ver = 0, seen_arch = 0;
    size_t start = 0;
    for (size_t i = 0; i < n; i++) {
        if (out[i] != '\n')
            continue;
        const char *ln = out + start;
        size_t ln_n = i - start;
        start = i + 1;
        const char *colon = memchr(ln, ':', ln_n);
        if (!colon)
            return QGP_E_BAD_CONTROL_FIELDS;
        size_t name_n = (size_t)(colon - ln);
        if ((size_t)(colon - ln) + 2 > ln_n || colon[1] != ' ')
            return QGP_E_BAD_CONTROL_FIELDS;
        const char *val = colon + 2;
        size_t val_n = ln_n - name_n - 2;
        if (val_n == 0 || val_n > QGP_FIELD_MAX)
            return QGP_E_BAD_CONTROL_FIELDS;
        char *dst;
        int *seen;
        if (name_n == 7 && strncasecmp(ln, "Package", 7) == 0) {
            if (!qgp_debpkg_name_valid(val, val_n))
                return QGP_E_BAD_PACKAGE_NAME;
            dst = f->pkg; seen = &seen_pkg;
        } else if (name_n == 7 && strncasecmp(ln, "Version", 7) == 0) {
            if (qgp_debver_check(val, val_n) != QGP_OK)
                return QGP_E_BAD_VERSION;
            dst = f->ver; seen = &seen_ver;
        } else if (name_n == 12 && strncasecmp(ln, "Architecture", 12) == 0) {
            if (!arch_valid(val, val_n))
                return QGP_E_BAD_ARCHITECTURE;
            dst = f->arch; seen = &seen_arch;
        } else {
            return QGP_E_BAD_CONTROL_FIELDS;
        }
        if (*seen)
            return QGP_E_BAD_CONTROL_FIELDS;
        *seen = 1;
        memcpy(dst, val, val_n);
        dst[val_n] = '\0';
    }
    if (!seen_pkg || !seen_ver || !seen_arch)
        return QGP_E_BAD_CONTROL_FIELDS;
    return QGP_OK;
}

qgp_rc_t qgp_deb_read_control_fields(const uint8_t *d, size_t len, qgp_control_fields_t *f)
{
    if (!d || !f)
        return QGP_E_ARG;
    memset(f, 0, sizeof(*f));

    int mfd = memfd_create("qgp-verified-deb", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mfd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "memfd_create: %s", strerror(errno));
        return QGP_E_IO;
    }
    if (mfd < 3) {                       /* keep clear of stdin/stdout/stderr */
        int moved = fcntl(mfd, F_DUPFD_CLOEXEC, 3);
        close(mfd);
        if (moved < 0)
            return QGP_E_IO;
        mfd = moved;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(mfd, d + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(mfd);
            return QGP_E_IO;
        }
        off += (size_t)w;
    }
    if (fcntl(mfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "memfd seal: %s", strerror(errno));
        close(mfd);
        return QGP_E_IO;
    }

    char fdpath[32];
    int pn = snprintf(fdpath, sizeof(fdpath), "/dev/fd/%d", mfd);
    if (pn < 0 || (size_t)pn >= sizeof(fdpath)) {
        close(mfd);
        return QGP_E_IO;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        close(mfd);
        return QGP_E_IO;
    }
    int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        close(mfd);
        close(pipefd[0]);
        close(pipefd[1]);
        return QGP_E_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(mfd);
        close(pipefd[0]);
        close(pipefd[1]);
        close(devnull);
        return QGP_E_IO;
    }
    if (pid == 0) {
        /* child: stdin /dev/null, stdout -> pipe, memfd inherited by number */
        if (dup2(devnull, 0) < 0 || dup2(pipefd[1], 1) < 0)
            _exit(127);
        if (fcntl(mfd, F_SETFD, 0) != 0)
            _exit(127);
        char *const argv[] = { "dpkg-deb", "-f", fdpath,
                               "Package", "Version", "Architecture", NULL };
        char *const envp[] = { "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(DPKG_DEB_PATH, argv, envp);
        _exit(127);
    }

    close(pipefd[1]);
    close(devnull);
    close(mfd);

    char *buf = malloc(DPKG_OUT_MAX + 1);
    qgp_rc_t rc = buf ? QGP_OK : QGP_E_NOMEM;
    size_t got = 0;
    while (rc == QGP_OK) {
        ssize_t r = read(pipefd[0], buf + got, DPKG_OUT_MAX + 1 - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            rc = QGP_E_IO;
            break;
        }
        if (r == 0)
            break;
        got += (size_t)r;
        if (got > DPKG_OUT_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "dpkg-deb output exceeds %u bytes", DPKG_OUT_MAX);
            rc = QGP_E_DPKG_DEB;
            kill(pid, SIGKILL);
            break;
        }
    }
    close(pipefd[0]);

    int status = 0;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
    if (rc == QGP_OK && (w != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "dpkg-deb -f failed (status 0x%x)", (unsigned)status);
        rc = QGP_E_DPKG_DEB;
    }
    if (rc == QGP_OK)
        rc = qgp_control_fields_parse(buf, got, f);
    free(buf);
    return rc;
}

/* ---- policy -------------------------------------------------------------- */

qgp_rc_t qgp_policy_check(const qgp_trust_state_t *st, const qgp_accepted_list_t *acc,
                          const char *pkg, const char *ver, int allow_downgrade, int *record)
{
    if (!st || !acc || !pkg || !ver || !record)
        return QGP_E_ARG;
    *record = 0;
    size_t pn = strlen(pkg), vn = strlen(ver);
    if (!qgp_debpkg_name_valid(pkg, pn))
        return QGP_E_BAD_PACKAGE_NAME;
    if (qgp_debver_check(ver, vn) != QGP_OK)
        return QGP_E_BAD_VERSION;

    int cmp = 0;
    const qgp_trust_floor_t *fl = qgp_trust_find_floor(st, pkg, pn);
    if (fl) {
        if (qgp_debver_cmp(ver, vn, fl->ver, fl->ver_n, &cmp) != QGP_OK)
            return QGP_E_BAD_VERSION;
        if (cmp < 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s %s is below the trust floor %s", pkg, ver, fl->ver);
            return QGP_E_BELOW_FLOOR;
        }
    }

    const char *hi = qgp_accepted_get(acc, pkg);
    if (!hi) {
        *record = 1;
        return QGP_OK;
    }
    if (qgp_debver_cmp(ver, vn, hi, strlen(hi), &cmp) != QGP_OK)
        return QGP_E_STATE_CORRUPT;
    if (cmp < 0) {
        if (!allow_downgrade) {
            QGP_LOG_ERROR(LOG_TAG, "%s %s is below the highest accepted %s", pkg, ver, hi);
            return QGP_E_DOWNGRADE;
        }
        QGP_LOG_WARN(LOG_TAG, "DOWNGRADE OVERRIDE: accepting %s %s below the highest accepted %s",
                     pkg, ver, hi);
        return QGP_OK;
    }
    *record = cmp > 0;
    return QGP_OK;
}
