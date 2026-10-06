/**
 * qgp_io.c - bounded reads, exclusive create, atomic replace, key files.
 * Linux/POSIX only: qgp targets Debian 12/13 and Ubuntu 24.04 validators.
 */
#define _GNU_SOURCE
#include "qgp_io.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "QGP_IO"

static qgp_rc_t write_all(int fd, const uint8_t *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return QGP_E_IO;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return QGP_OK;
}

/* private_only: refuse (QGP_E_KEY_FILE) a file whose mode grants group/other
 * access — checked on the opened descriptor, not by a separate stat(). */
static qgp_rc_t read_file_ex(const char *path, size_t max, uint8_t **buf, size_t *len,
                             int private_only)
{
    if (!path || !buf || !len)
        return QGP_E_ARG;
    *buf = NULL;
    *len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "open %s: %s", path, strerror(errno));
        return QGP_E_IO;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s: not a regular file", path);
        close(fd);
        return QGP_E_IO;
    }
    if (private_only && (st.st_mode & 077) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s: secret key file is accessible by group/others (mode %o)",
                      path, (unsigned)(st.st_mode & 0777));
        close(fd);
        return QGP_E_KEY_FILE;
    }
    if ((uint64_t)st.st_size > (uint64_t)max) {
        QGP_LOG_ERROR(LOG_TAG, "%s: %lld bytes exceeds the limit %llu", path,
                      (long long)st.st_size, (unsigned long long)max);
        close(fd);
        return QGP_E_TOO_LARGE;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *b = malloc(size ? size : 1);
    if (!b) {
        close(fd);
        return QGP_E_NOMEM;
    }
    size_t got = 0;
    while (got < size) {
        ssize_t r = read(fd, b + got, size - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            break;
        got += (size_t)r;
    }
    uint8_t extra;
    ssize_t tail;
    do {
        tail = read(fd, &extra, 1);
    } while (tail < 0 && errno == EINTR);
    close(fd);
    if (got != size || tail != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s: size changed while reading", path);
        free(b);
        return QGP_E_IO;
    }
    *buf = b;
    *len = size;
    return QGP_OK;
}

qgp_rc_t qgp_io_read_file(const char *path, size_t max, uint8_t **buf, size_t *len)
{
    return read_file_ex(path, max, buf, len, 0);
}

qgp_rc_t qgp_io_create_excl(const char *path, const uint8_t *data, size_t len, mode_t mode)
{
    if (!path || (!data && len))
        return QGP_E_ARG;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "create %s: %s", path, strerror(errno));
        return QGP_E_IO;
    }
    qgp_rc_t rc = QGP_OK;
    if (fchmod(fd, mode) != 0)          /* exact mode regardless of umask */
        rc = QGP_E_IO;
    if (rc == QGP_OK)
        rc = write_all(fd, data, len);
    if (rc == QGP_OK && fsync(fd) != 0)
        rc = QGP_E_IO;
    if (close(fd) != 0 && rc == QGP_OK)
        rc = QGP_E_IO;
    if (rc != QGP_OK) {
        QGP_LOG_ERROR(LOG_TAG, "write %s failed", path);
        unlink(path);
    }
    return rc;
}

/* Directory part of `path` ("." when there is none). */
static qgp_rc_t dir_of(const char *path, char *out, size_t out_n)
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (out_n < 2)
            return QGP_E_ARG;
        out[0] = '.';
        out[1] = '\0';
        return QGP_OK;
    }
    size_t n = (size_t)(slash - path);
    if (n == 0)
        n = 1;                          /* "/file" -> "/" */
    if (n + 1 > out_n)
        return QGP_E_ARG;
    memcpy(out, path, n);
    out[n] = '\0';
    return QGP_OK;
}

qgp_rc_t qgp_io_write_atomic(const char *path, const uint8_t *data, size_t len, mode_t mode)
{
    if (!path || (!data && len))
        return QGP_E_ARG;
    char tmp[PATH_MAX];
    char dir[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return QGP_E_ARG;
    if (dir_of(path, dir, sizeof(dir)) != QGP_OK)
        return QGP_E_ARG;

    int fd = mkostemp(tmp, O_CLOEXEC);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "temp file for %s: %s", path, strerror(errno));
        return QGP_E_IO;
    }
    qgp_rc_t rc = QGP_OK;
    if (fchmod(fd, mode) != 0)
        rc = QGP_E_IO;
    if (rc == QGP_OK)
        rc = write_all(fd, data, len);
    if (rc == QGP_OK && fsync(fd) != 0)
        rc = QGP_E_IO;
    if (close(fd) != 0 && rc == QGP_OK)
        rc = QGP_E_IO;
    if (rc == QGP_OK && rename(tmp, path) != 0)
        rc = QGP_E_IO;
    if (rc != QGP_OK) {
        QGP_LOG_ERROR(LOG_TAG, "atomic write of %s failed: %s", path, strerror(errno));
        unlink(tmp);
        return rc;
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
        return QGP_E_IO;
    if (fsync(dfd) != 0)
        rc = QGP_E_IO;
    close(dfd);
    return rc;
}

qgp_rc_t qgp_key_pub_path(const char *sk_path, char *out, size_t out_n)
{
    if (!sk_path || !out)
        return QGP_E_ARG;
    int n = snprintf(out, out_n, "%s.pub", sk_path);
    if (n < 0 || (size_t)n >= out_n)
        return QGP_E_ARG;
    return QGP_OK;
}

qgp_rc_t qgp_key_generate(const char *sk_path, uint8_t key_id_out[QGP_HASH_LEN])
{
    char pub[PATH_MAX];
    if (!sk_path || !key_id_out)
        return QGP_E_ARG;
    if (qgp_key_pub_path(sk_path, pub, sizeof(pub)) != QGP_OK)
        return QGP_E_ARG;

    uint8_t *sk = malloc(QGP_SK_LEN);
    uint8_t pk[QGP_PK_LEN];
    if (!sk)
        return QGP_E_NOMEM;
    qgp_rc_t rc = QGP_OK;
    if (qgp_dsa87_keypair(pk, sk) != 0)
        rc = QGP_E_CRYPTO;
    if (rc == QGP_OK && qgp_sha3_512(pk, QGP_PK_LEN, key_id_out) != 0)
        rc = QGP_E_CRYPTO;
    if (rc == QGP_OK)
        rc = qgp_io_create_excl(sk_path, sk, QGP_SK_LEN, 0600);
    if (rc == QGP_OK) {
        rc = qgp_io_create_excl(pub, pk, QGP_PK_LEN, 0644);
        if (rc != QGP_OK)
            unlink(sk_path);            /* never leave a secret key without its public key */
    }
    qgp_secure_memzero(sk, QGP_SK_LEN);
    free(sk);
    return rc;
}

static qgp_rc_t load_exact(const char *path, uint8_t *out, size_t want, int secret)
{
    if (!path || !out)
        return QGP_E_ARG;
    uint8_t *buf = NULL;
    size_t len = 0;
    qgp_rc_t rc = read_file_ex(path, want, &buf, &len, secret);
    if (rc == QGP_E_TOO_LARGE)
        rc = QGP_E_KEY_FILE;
    if (rc != QGP_OK)
        return rc;
    if (len != want) {
        QGP_LOG_ERROR(LOG_TAG, "%s: %zu bytes, expected %zu", path, len, want);
        qgp_secure_memzero(buf, len);
        free(buf);
        return QGP_E_KEY_FILE;
    }
    memcpy(out, buf, want);
    qgp_secure_memzero(buf, len);
    free(buf);
    return QGP_OK;
}

qgp_rc_t qgp_key_load_sk(const char *path, uint8_t sk[QGP_SK_LEN])
{
    return load_exact(path, sk, QGP_SK_LEN, 1);
}

qgp_rc_t qgp_key_load_pk(const char *path, uint8_t pk[QGP_PK_LEN])
{
    return load_exact(path, pk, QGP_PK_LEN, 0);
}
