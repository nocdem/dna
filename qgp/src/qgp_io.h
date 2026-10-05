/**
 * qgp_io.h - bounded file reads, exclusive create, atomic replace, key files.
 */
#ifndef QGP_IO_H
#define QGP_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "qgp_core.h"

/* Read a whole regular file. The size is checked against `max` BEFORE any
 * allocation; a file that changes size while it is read refuses. *buf is
 * malloc'd (at least 1 byte) and owned by the caller. */
qgp_rc_t qgp_io_read_file(const char *path, size_t max, uint8_t **buf, size_t *len);

/* Create `path` with O_CREAT|O_EXCL (never overwrites, never follows a final
 * symlink), write `data`, fsync. */
qgp_rc_t qgp_io_create_excl(const char *path, const uint8_t *data, size_t len, mode_t mode);

/* Replace `path` atomically: write a temp file in the same directory, fsync,
 * rename over `path`, fsync the directory. */
qgp_rc_t qgp_io_write_atomic(const char *path, const uint8_t *data, size_t len, mode_t mode);

/* Key files: raw bytes, exact length. The secret key file must not be
 * accessible by group or others (mode & 077 == 0); the public key is
 * `<sk_path>.pub`. */
qgp_rc_t qgp_key_generate(const char *sk_path, uint8_t key_id_out[QGP_HASH_LEN]);
qgp_rc_t qgp_key_load_sk(const char *path, uint8_t sk[QGP_SK_LEN]);
qgp_rc_t qgp_key_load_pk(const char *path, uint8_t pk[QGP_PK_LEN]);
/* "<sk_path>.pub" into out (size out_n). */
qgp_rc_t qgp_key_pub_path(const char *sk_path, char *out, size_t out_n);

#endif /* QGP_IO_H */
