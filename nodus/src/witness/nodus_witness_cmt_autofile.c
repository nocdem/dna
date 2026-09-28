/**
 * @file nodus_witness_cmt_autofile.c
 * @brief cometbft @709fd12b `libs/autofile` (AutoFile, Group,
 *        GroupReader) — only what consensus/wal.go uses. Contract and
 *        citations: nodus_witness_cmt_autofile.h.
 */

#include "witness/nodus_witness_cmt_autofile.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_CMTAUTOFILE"

/* ══ directory durability (HARDENING, no reference counterpart) ═════════ */

/* filepath.Dir / filepath.Base of a path, into caller buffers. */
static int g_split(const char *path, char *dir, size_t dcap,
                   const char **base)
{
    const char *slash = strrchr(path, '/');
    size_t      dl;

    if (!slash) {
        if (dcap < 2) {
            return CMT_FAULT;
        }
        dir[0] = '.';
        dir[1] = '\0';
        *base = path;
        return CMT_OK;
    }
    dl = (size_t)(slash - path);
    if (dl == 0) {
        dl = 1;                                          /* "/wal" → "/" */
    }
    if (dl >= dcap) {
        return CMT_FAULT;
    }
    memcpy(dir, path, dl);
    dir[dl] = '\0';
    *base = slash + 1;
    return CMT_OK;
}

int nodus_cmt_fsync_dir(const char *dir)
{
    int fd;
    int rc;

    if (!dir || !dir[0]) {
        return CMT_FAULT;
    }
    do {
        fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "open directory %s: %s", dir, strerror(errno));
        return CMT_FAULT;
    }
    do {
        rc = fsync(fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "fsync directory %s: %s", dir,
                      strerror(errno));
    }
    (void)close(fd);
    return rc == 0 ? CMT_OK : CMT_FAULT;
}

/* nodus_cmt_fsync_dir of the directory holding `path`. */
static int af_fsync_parent(const char *path)
{
    char        dir[NODUS_CMT_AUTOFILE_PATH_MAX];
    const char *base = NULL;

    if (g_split(path, dir, sizeof(dir), &base) != CMT_OK) {
        return CMT_FAULT;
    }
    return nodus_cmt_fsync_dir(dir);
}

/* ══ AutoFile (autofile.go) ═════════════════════════════════════════════ */

/* autofile.go:160-174 `openFile`.
 *
 * HARDENING (decision 2026-09-27-p2p-fix-2.md 1(c); no reference
 * counterpart — autofile.go:161 is one `os.OpenFile(O_RDWR|O_CREATE|
 * O_APPEND)` and nothing makes the new directory entry durable): the file
 * is first opened O_CREAT|O_EXCL; when that CREATED it, the directory is
 * fsynced, so a power cut cannot lose the head's name after records were
 * fsynced into it. When the directory fsync fails the fresh (empty) file
 * is removed again, so the next open creates it — and fsyncs — anew
 * instead of finding it and skipping the fsync. An existing file is
 * opened exactly as before (O_RDWR|O_APPEND). */
static int af_open_file(nodus_cmt_autofile_t *af)
{
    int fd;

    do {
        fd = open(af->path, O_RDWR | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC,
                  NODUS_CMT_AUTOFILE_PERMS);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
        if (af_fsync_parent(af->path) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "created %s but its directory entry is "
                          "not durable; removing it", af->path);
            (void)close(fd);
            (void)unlink(af->path);
            return CMT_FAULT;
        }
        af->fd = fd;
        return CMT_OK;
    }
    if (errno != EEXIST) {
        QGP_LOG_ERROR(LOG_TAG, "open %s failed: %s", af->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    do {
        fd = open(af->path, O_RDWR | O_APPEND | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "open %s failed: %s", af->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    af->fd = fd;
    return CMT_OK;
}

int nodus_cmt_autofile_open(nodus_cmt_autofile_t *af, const char *path)
{
    size_t len;

    if (!af || !path) {
        return CMT_FAULT;
    }
    af->fd = -1;
    len = strlen(path);
    if (len == 0 || len >= sizeof(af->path)) {
        QGP_LOG_ERROR(LOG_TAG, "autofile path empty or too long (%zu)", len);
        return CMT_FAULT;
    }
    memcpy(af->path, path, len + 1);
    return af_open_file(af);                             /* autofile.go:72 */
}

int nodus_cmt_autofile_close_file(nodus_cmt_autofile_t *af)
{
    int fd;

    if (!af || af->fd < 0) {
        return CMT_OK;                                   /* :117-120 */
    }
    fd = af->fd;
    af->fd = -1;                                         /* :122 */
    if (close(fd) != 0) {                                /* :123 */
        QGP_LOG_ERROR(LOG_TAG, "close %s failed: %s", af->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_autofile_write(nodus_cmt_autofile_t *af, const uint8_t *p,
                             size_t n, size_t *out_n)
{
    size_t nn = 0;

    if (out_n) {
        *out_n = 0;
    }
    if (!af || (!p && n > 0)) {
        return CMT_FAULT;
    }
    if (af->fd < 0 && af_open_file(af) != CMT_OK) {      /* :134-138 */
        return CMT_FAULT;
    }
    /* :140 `af.file.Write(b)` — Go's File.Write loops until every byte
     * is written, retrying EINTR (fd_unix.go:374-399); a zero-byte
     * write is io.ErrUnexpectedEOF there (:395-396). */
    while (nn < n) {
        ssize_t w = write(af->fd, p + nn, n - nn);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            QGP_LOG_ERROR(LOG_TAG, "write %s failed: %s", af->path,
                          strerror(errno));
            break;
        }
        if (w == 0) {
            QGP_LOG_ERROR(LOG_TAG, "write %s wrote 0 bytes", af->path);
            break;
        }
        nn += (size_t)w;
    }
    if (out_n) {
        *out_n = nn;
    }
    return nn == n ? CMT_OK : CMT_FAULT;
}

int nodus_cmt_autofile_sync(nodus_cmt_autofile_t *af)
{
    int rc;

    if (!af) {
        return CMT_FAULT;
    }
    if (af->fd < 0 && af_open_file(af) != CMT_OK) {      /* :152-156 */
        return CMT_FAULT;
    }
    do {
        rc = fsync(af->fd);                              /* :157 */
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "fsync %s failed: %s", af->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_autofile_size(nodus_cmt_autofile_t *af, int64_t *out)
{
    struct stat st;

    if (!af || !out) {
        return CMT_FAULT;
    }
    *out = -1;
    if (af->fd < 0 && af_open_file(af) != CMT_OK) {      /* :183-187 */
        return CMT_FAULT;
    }
    if (fstat(af->fd, &st) != 0) {                       /* :189-192 */
        QGP_LOG_ERROR(LOG_TAG, "stat %s failed: %s", af->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    *out = (int64_t)st.st_size;                          /* :193 */
    return CMT_OK;
}

/* HARDENING, no reference counterpart (AutoFile has no Truncate; decision
 * 2026-09-27-p2p-fix-2.md 1(a)). */
int nodus_cmt_autofile_truncate(nodus_cmt_autofile_t *af, int64_t size)
{
    int rc;

    if (!af || size < 0) {
        return CMT_FAULT;
    }
    if (af->fd < 0 && af_open_file(af) != CMT_OK) {
        return CMT_FAULT;
    }
    do {
        rc = ftruncate(af->fd, (off_t)size);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "truncate %s to %lld failed: %s", af->path,
                      (long long)size, strerror(errno));
        return CMT_FAULT;
    }
    return nodus_cmt_autofile_sync(af);
}

/* ══ Group (group.go) ═══════════════════════════════════════════════════ */

/* bufio.go:635-656 `Flush` over the head AutoFile. */
static int g_buf_flush(nodus_cmt_group_t *g)
{
    size_t n = 0;
    int    rc;

    if (g->head_buf_err != 0) {
        return CMT_FAULT;                                /* :636-638 */
    }
    if (g->head_buf_n == 0) {
        return CMT_OK;                                   /* :639-641 */
    }
    rc = nodus_cmt_autofile_write(&g->head, g->head_buf, g->head_buf_n, &n);
    if (rc != CMT_OK) {                                  /* :643-653 */
        if (n > 0 && n < g->head_buf_n) {
            memmove(g->head_buf, g->head_buf + n, g->head_buf_n - n);
        }
        g->head_buf_n -= n;
        g->head_buf_err = true;
        return CMT_FAULT;
    }
    g->head_buf_n = 0;                                   /* :654 */
    return CMT_OK;
}

int nodus_cmt_group_open(nodus_cmt_group_t *g, const char *head_path)
{
    nodus_cmt_group_info_t gi;

    if (!g || !head_path) {
        return CMT_FAULT;
    }
    memset(g, 0, sizeof(*g));
    g->head.fd = -1;
    /* :85-88 OpenAutoFile(headPath) */
    if (nodus_cmt_autofile_open(&g->head, head_path) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :90-101 */
    g->head_buf_cap = NODUS_CMT_GROUP_HEAD_BUF_SIZE;     /* :93 */
    g->head_buf = (uint8_t *)malloc(g->head_buf_cap);
    if (!g->head_buf) {
        (void)nodus_cmt_autofile_close_file(&g->head);
        return CMT_FAULT;
    }
    g->head_size_limit = NODUS_CMT_GROUP_HEAD_SIZE_LIMIT;             /* :95 */
    g->total_size_limit = NODUS_CMT_GROUP_TOTAL_SIZE_LIMIT;           /* :96 */
    g->group_check_duration_ns = NODUS_CMT_GROUP_CHECK_DURATION_NS;   /* :97 */
    /* :109-111 */
    if (nodus_cmt_group_read_info(g, &gi) != CMT_OK) {
        nodus_cmt_group_close(g);
        return CMT_FAULT;
    }
    g->min_index = gi.min_index;
    g->max_index = gi.max_index;
    return CMT_OK;
}

void nodus_cmt_group_start(nodus_cmt_group_t *g, int64_t now_ns)
{
    if (!g) {
        return;
    }
    g->check_armed = true;                               /* :139 */
    g->check_deadline_ns = now_ns + g->group_check_duration_ns;
}

void nodus_cmt_group_stop(nodus_cmt_group_t *g)
{
    if (!g) {
        return;
    }
    g->check_armed = false;                              /* :147 */
    if (nodus_cmt_group_flush_and_sync(g) != CMT_OK) {   /* :148-150 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "Error flushin to disk");
    }
}

void nodus_cmt_group_close(nodus_cmt_group_t *g)
{
    /* Only an opened group owns a head buffer; a zeroed handle's fd 0 is
     * not ours to close. The head fd may be -1 after a rotation (it is
     * reopened lazily), so the flush below must not depend on it. */
    if (!g || !g->head_buf) {
        return;
    }
    if (nodus_cmt_group_flush_and_sync(g) != CMT_OK) {   /* :162-164 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "Error flushin to disk");
    }
    (void)nodus_cmt_autofile_close_file(&g->head);       /* :166-168 */
    free(g->head_buf);
    g->head_buf = NULL;
    g->head_buf_cap = g->head_buf_n = 0;
    g->check_armed = false;
}

int nodus_cmt_group_write(nodus_cmt_group_t *g, const uint8_t *p, size_t n)
{
    if (!g || !g->head_buf || (!p && n > 0)) {
        return CMT_FAULT;
    }
    /* bufio.go:676-700 */
    while (n > g->head_buf_cap - g->head_buf_n && g->head_buf_err == 0) {
        size_t m;

        if (g->head_buf_n == 0) {
            /* :679-682 large write, empty buffer: straight to the file */
            if (nodus_cmt_autofile_write(&g->head, p, n, &m) != CMT_OK) {
                g->head_buf_err = true;
            }
        } else {
            /* :683-686 fill the buffer, flush it */
            m = g->head_buf_cap - g->head_buf_n;
            memcpy(g->head_buf + g->head_buf_n, p, m);
            g->head_buf_n += m;
            (void)g_buf_flush(g);
        }
        p += m;
        n -= m;
    }
    if (g->head_buf_err != 0) {
        return CMT_FAULT;                                /* :691-693 */
    }
    memcpy(g->head_buf + g->head_buf_n, p, n);           /* :694-696 */
    g->head_buf_n += n;
    return CMT_OK;
}

size_t nodus_cmt_group_buffered(const nodus_cmt_group_t *g)
{
    return g ? g->head_buf_n : 0;
}

int nodus_cmt_group_flush_and_sync(nodus_cmt_group_t *g)
{
    if (!g || !g->head_buf) {
        return CMT_FAULT;
    }
    if (g_buf_flush(g) != CMT_OK) {                      /* :232 */
        return CMT_FAULT;
    }
    return nodus_cmt_autofile_sync(&g->head);            /* :233-235 */
}

bool nodus_cmt_group_next_check_deadline(const nodus_cmt_group_t *g,
                                         int64_t *out_deadline_ns)
{
    if (!g || !g->check_armed) {
        return false;
    }
    if (out_deadline_ns) {
        *out_deadline_ns = g->check_deadline_ns;
    }
    return true;
}

int nodus_cmt_group_check_if_due(nodus_cmt_group_t *g, int64_t now_ns)
{
    int64_t period;
    int     rc;
    int     rc2;

    if (!g) {
        return CMT_FAULT;
    }
    if (!g->check_armed || now_ns < g->check_deadline_ns) {
        return CMT_OK;
    }
    /* Go 1.21.5 runtime/time.go:854-857 — the ticker's next `when`. */
    period = g->group_check_duration_ns;
    if (period > 0) {
        int64_t delta = g->check_deadline_ns - now_ns;   /* <= 0 here */

        g->check_deadline_ns += period * (1 + -delta / period);
    }
    rc  = nodus_cmt_group_check_head_size_limit(g);      /* group.go:244 */
    rc2 = nodus_cmt_group_check_total_size_limit(g);     /* group.go:245 */
    return (rc == CMT_OK && rc2 == CMT_OK) ? CMT_OK : CMT_FAULT;
}

int nodus_cmt_group_check_head_size_limit(nodus_cmt_group_t *g)
{
    int64_t size = -1;

    if (!g) {
        return CMT_FAULT;
    }
    if (g->head_size_limit == 0) {                       /* :254-257 */
        return CMT_OK;
    }
    if (nodus_cmt_autofile_size(&g->head, &size) != CMT_OK) {   /* :258-262 */
        QGP_LOG_ERROR(LOG_TAG, "Group's head may grow without bound "
                      "(head %s: size unreadable)", g->head.path);
        return CMT_OK;
    }
    if (size >= g->head_size_limit) {                    /* :263-265 */
        return nodus_cmt_group_rotate_file(g);
    }
    return CMT_OK;
}

int nodus_cmt_group_check_total_size_limit(nodus_cmt_group_t *g)
{
    nodus_cmt_group_info_t gi;
    int64_t total_size;
    int     i;

    if (!g) {
        return CMT_FAULT;
    }
    if (g->total_size_limit == 0) {                      /* :270-272 */
        return CMT_OK;
    }
    if (nodus_cmt_group_read_info(g, &gi) != CMT_OK) {   /* :274 */
        return CMT_FAULT;
    }
    total_size = gi.total_size;                          /* :275 */
    for (i = 0; i < NODUS_CMT_GROUP_MAX_FILES_TO_REMOVE; i++) {   /* :276 */
        int         index = gi.min_index + i;            /* :277 */
        char        path[NODUS_CMT_AUTOFILE_PATH_MAX];
        struct stat st;

        if (total_size < g->total_size_limit) {          /* :278-280 */
            return CMT_OK;
        }
        if (index == gi.max_index) {                     /* :281-285 */
            QGP_LOG_ERROR(LOG_TAG, "Group's head may grow without bound "
                          "(head %s, %lld bytes, limit %lld)", g->head.path,
                          (long long)total_size,
                          (long long)g->total_size_limit);
            return CMT_OK;
        }
        if (nodus_cmt_group_file_path_for_index(g->head.path, index,
                                                gi.max_index, path,
                                                sizeof(path)) != CMT_OK) {
            return CMT_FAULT;
        }
        if (stat(path, &st) != 0) {                      /* :287-291 */
            QGP_LOG_ERROR(LOG_TAG, "Failed to fetch info for file %s", path);
            continue;
        }
        if (remove(path) != 0) {                         /* :292-296 */
            QGP_LOG_ERROR(LOG_TAG, "Failed to remove path %s", path);
            return CMT_OK;
        }
        QGP_LOG_INFO(LOG_TAG, "removed %s (%lld bytes; group was %lld, "
                     "limit %lld)", path, (long long)st.st_size,
                     (long long)total_size, (long long)g->total_size_limit);
        total_size -= (int64_t)st.st_size;               /* :297 */
    }
    return CMT_OK;
}

int nodus_cmt_group_rotate_file(nodus_cmt_group_t *g)
{
    char index_path[NODUS_CMT_AUTOFILE_PATH_MAX];

    if (!g || !g->head_buf) {
        return CMT_FAULT;
    }
    /* :309-311 flush, :313-315 sync, :317-319 close — each a panic in
     * the reference */
    if (g_buf_flush(g) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "rotate: flush of %s failed", g->head.path);
        return CMT_FAULT;
    }
    if (nodus_cmt_autofile_sync(&g->head) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "rotate: sync of %s failed", g->head.path);
        return CMT_FAULT;
    }
    if (nodus_cmt_autofile_close_file(&g->head) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :321-324 */
    if (nodus_cmt_group_file_path_for_index(g->head.path, g->max_index,
                                            g->max_index + 1, index_path,
                                            sizeof(index_path)) != CMT_OK) {
        return CMT_FAULT;
    }
    if (rename(g->head.path, index_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "rotate: rename %s -> %s failed: %s",
                      g->head.path, index_path, strerror(errno));
        return CMT_FAULT;
    }
    g->max_index++;                                      /* :326 */
    QGP_LOG_INFO(LOG_TAG, "rotated head to %s", index_path);
    /* HARDENING (decision 2026-09-27-p2p-fix-2.md 1(c)); group.go:321-324
     * renames and never fsyncs the directory, so a power cut can undo the
     * rename while the next head's records are already durable. The
     * index is advanced first: the rename has happened either way. */
    if (af_fsync_parent(index_path) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "rotate: the rename to %s is not durable",
                      index_path);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* group.go:383 `^.+\.([0-9]{3,})$` — at least one character, a dot, then
 * three or more digits to the end. Only the LAST dot can precede an
 * all-digit tail, so that is the one tested. Go's `strconv.Atoi` failing
 * (:387-390, a panic) is an index that does not fit an int here.
 * @return 1 matched (*out set), 0 no match, -1 the digits overflow. */
static int g_match_index(const char *name, int *out)
{
    const char *dot = strrchr(name, '.');
    const char *d;
    size_t      nd;
    long long   v = 0;

    if (!dot || dot == name) {
        return 0;
    }
    d = dot + 1;
    nd = strlen(d);
    if (nd < 3) {
        return 0;
    }
    for (size_t i = 0; i < nd; i++) {
        if (d[i] < '0' || d[i] > '9') {
            return 0;
        }
    }
    for (size_t i = 0; i < nd; i++) {
        v = v * 10 + (d[i] - '0');
        if (v > 0x7FFFFFFFLL) {
            return -1;
        }
    }
    *out = (int)v;
    return 1;
}

int nodus_cmt_group_read_info(const nodus_cmt_group_t *g,
                              nodus_cmt_group_info_t *out)
{
    char           dir[NODUS_CMT_AUTOFILE_PATH_MAX];
    const char    *head_base = NULL;
    size_t         base_len;
    DIR           *dp;
    struct dirent *ent;
    int            min_index = -1, max_index = -1;       /* :360 */
    int64_t        total_size = 0, head_size = 0;        /* :361 */
    int            rc = CMT_OK;

    if (!g || !out) {
        return CMT_FAULT;
    }
    if (g_split(g->head.path, dir, sizeof(dir), &head_base) != CMT_OK) {
        return CMT_FAULT;
    }
    base_len = strlen(head_base);
    dp = opendir(dir);                                   /* :363-366 */
    if (!dp) {
        QGP_LOG_ERROR(LOG_TAG, "open dir %s failed: %s", dir,
                      strerror(errno));
        return CMT_FAULT;
    }
    /* :374-399 — sum, min and max: independent of readdir order.
     * HARDENING (decision 2026-09-27-p2p-fix-2.md 1(d)): readdir(3)
     * reports an error only as NULL with errno set, so errno is cleared
     * before every call; the reference fails on its `Readdir` error
     * (group.go:367-371, a panic) — here CMT_FAULT, checked below. */
    for (;;) {
        struct stat st;
        int         idx = 0;
        int         m;

        errno = 0;
        ent = readdir(dp);
        if (!ent) {
            if (errno != 0) {
                QGP_LOG_ERROR(LOG_TAG, "read dir %s failed: %s", dir,
                              strerror(errno));
                rc = CMT_FAULT;
            }
            break;
        }

        if (strncmp(ent->d_name, head_base, base_len) != 0) {
            continue;                                    /* :380 prefix */
        }
        /* Go's Readdir reports lstat sizes */
        if (fstatat(dirfd(dp), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "stat %s/%s failed: %s", dir,
                          ent->d_name, strerror(errno));
            rc = CMT_FAULT;                              /* :368-371 */
            break;
        }
        if (strcmp(ent->d_name, head_base) == 0) {       /* :375-379 */
            total_size += (int64_t)st.st_size;
            head_size = (int64_t)st.st_size;
            continue;
        }
        total_size += (int64_t)st.st_size;               /* :381-382 */
        m = g_match_index(ent->d_name, &idx);            /* :383-397 */
        if (m < 0) {
            QGP_LOG_ERROR(LOG_TAG, "file index of %s does not fit an int",
                          ent->d_name);
            rc = CMT_FAULT;
            break;
        }
        if (m == 1) {
            if (max_index < idx) {
                max_index = idx;
            }
            if (min_index == -1 || idx < min_index) {
                min_index = idx;
            }
        }
    }
    closedir(dp);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :401-409 — account for the head */
    if (min_index == -1) {
        min_index = 0;
        max_index = 0;
    } else {
        max_index++;
    }
    out->min_index = min_index;
    out->max_index = max_index;
    out->total_size = total_size;
    out->head_size = head_size;
    return CMT_OK;
}

int nodus_cmt_group_file_path_for_index(const char *head_path, int index,
                                        int max_index, char *out,
                                        size_t cap)
{
    int n;

    if (!head_path || !out || cap == 0) {
        return CMT_FAULT;
    }
    if (index == max_index) {                            /* :414-416 */
        n = snprintf(out, cap, "%s", head_path);
    } else {
        n = snprintf(out, cap, "%s.%03d", head_path, index);   /* :417 */
    }
    if (n < 0 || (size_t)n >= cap) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ══ GroupReader (group.go:422-540) ═════════════════════════════════════ */

/* group.go:500-525 `openFile`. */
static int gr_open_file(nodus_cmt_group_reader_t *gr, int index)
{
    char path[NODUS_CMT_AUTOFILE_PATH_MAX];
    int  fd;

    if (index > gr->g->max_index) {                      /* :505-507 */
        return NODUS_CMT_GROUP_READ_EOF;
    }
    if (nodus_cmt_group_file_path_for_index(gr->g->head.path, index,
                                            gr->g->max_index, path,
                                            sizeof(path)) != CMT_OK) {
        return NODUS_CMT_GROUP_READ_IO;
    }
    /* :510 O_RDONLY|O_CREATE — the reference CREATES a missing index
     * file here (an empty one), and so does this. */
    do {
        fd = open(path, O_RDONLY | O_CREAT | O_CLOEXEC,
                  NODUS_CMT_AUTOFILE_PERMS);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {                                        /* :511-513 */
        QGP_LOG_ERROR(LOG_TAG, "open %s for reading failed: %s", path,
                      strerror(errno));
        return NODUS_CMT_GROUP_READ_IO;
    }
    if (gr->cur_fd >= 0) {                               /* :517-519 */
        (void)close(gr->cur_fd);
    }
    gr->cur_index = index;                               /* :520-523 */
    gr->cur_fd = fd;
    gr->r = gr->w = 0;                                   /* :514 new bufio */
    return NODUS_CMT_GROUP_READ_OK;
}

int nodus_cmt_group_new_reader(const nodus_cmt_group_t *g, int index,
                               nodus_cmt_group_reader_t *gr)
{
    if (!g || !gr) {
        return NODUS_CMT_GROUP_READ_IO;
    }
    /* :432-440 newGroupReader */
    gr->g = g;
    gr->cur_index = 0;
    gr->cur_fd = -1;
    gr->r = gr->w = 0;
    return gr_open_file(gr, index);                      /* :333, :536-540 */
}

/* Go 1.21.5 bufio.go:215-260 `(*Reader).Read` over the current file,
 * for a non-empty `p`: serve buffered bytes, else one read(2) (straight
 * into `p` when it is at least the buffer's size). read(2) returning 0 is
 * Go's io.EOF; nothing is sticky (bufio's readErr clears it, :129-133),
 * so bytes appended to the file later are seen by the next call. */
static int gr_buf_read(nodus_cmt_group_reader_t *gr, uint8_t *p, size_t len,
                       size_t *out_n)
{
    ssize_t n;

    *out_n = 0;
    if (gr->r == gr->w) {
        uint8_t *dst = (len >= sizeof(gr->buf)) ? p : gr->buf;
        size_t   cap = (len >= sizeof(gr->buf)) ? len : sizeof(gr->buf);

        do {
            n = read(gr->cur_fd, dst, cap);
        } while (n < 0 && errno == EINTR);
        if (n < 0) {
            QGP_LOG_ERROR(LOG_TAG, "read failed: %s", strerror(errno));
            return NODUS_CMT_GROUP_READ_IO;
        }
        if (n == 0) {
            return NODUS_CMT_GROUP_READ_EOF;
        }
        if (dst == p) {
            *out_n = (size_t)n;
            return NODUS_CMT_GROUP_READ_OK;
        }
        gr->r = 0;
        gr->w = (size_t)n;
    }
    {
        size_t avail = gr->w - gr->r;
        size_t c = avail < len ? avail : len;

        memcpy(p, gr->buf + gr->r, c);
        gr->r += c;
        *out_n = c;
    }
    return NODUS_CMT_GROUP_READ_OK;
}

int nodus_cmt_group_reader_read(nodus_cmt_group_reader_t *gr, uint8_t *p,
                                size_t len, size_t *out_n)
{
    size_t n = 0;

    if (out_n) {
        *out_n = 0;
    }
    if (!gr || !gr->g || (!p && len > 0)) {
        return NODUS_CMT_GROUP_READ_IO;
    }
    if (len == 0) {                                      /* :462-464 */
        return NODUS_CMT_GROUP_READ_EMPTY;
    }
    if (gr->cur_fd < 0) {                                /* :469-474 */
        int rc = gr_open_file(gr, gr->cur_index);

        if (rc != NODUS_CMT_GROUP_READ_OK) {
            return rc;
        }
    }
    /* :476-495 — iterate over files until enough bytes are read */
    for (;;) {
        size_t nn = 0;
        int    rc;

        if (n >= len) {
            /* :492-493: bufio's Read of an empty slice is (0, nil) */
            break;
        }
        rc = gr_buf_read(gr, p + n, len - n, &nn);
        n += nn;
        if (rc == NODUS_CMT_GROUP_READ_EOF) {            /* :482-489 */
            int orc;

            if (n >= len) {
                break;
            }
            orc = gr_open_file(gr, gr->cur_index + 1);
            if (orc != NODUS_CMT_GROUP_READ_OK) {
                if (out_n) {
                    *out_n = n;
                }
                return orc;
            }
            continue;
        }
        if (rc != NODUS_CMT_GROUP_READ_OK) {             /* :490-491 */
            if (out_n) {
                *out_n = n;
            }
            return rc;
        }
    }
    if (out_n) {
        *out_n = n;
    }
    return NODUS_CMT_GROUP_READ_OK;
}

void nodus_cmt_group_reader_close(nodus_cmt_group_reader_t *gr)
{
    if (!gr) {
        return;
    }
    if (gr->cur_fd >= 0) {                               /* :447-454 */
        (void)close(gr->cur_fd);
    }
    gr->cur_index = 0;
    gr->cur_fd = -1;
    gr->r = gr->w = 0;
}
