/**
 * qgp_state.h - the validator-local trust directory and the package policy.
 *
 * Directory layout (`--trust <dir>`):
 *   <dir>/qgp-trust          the last ACCEPTED trust file, byte for byte (§2);
 *                            its SHA3-512 is the next file's prev_digest (R2-3)
 *   <dir>/accepted-versions  highest version accepted per package (R2-5):
 *                            "<package> <version>\n" lines, sorted bytewise by
 *                            package, one line per package
 *   <dir>/.lock              flock(2) target serialising every writer
 * Both data files are replaced atomically (temp file + rename).
 */
#ifndef QGP_STATE_H
#define QGP_STATE_H

#include <stddef.h>
#include <stdint.h>

#include "qgp_core.h"
#include "qgp_trust.h"

#define QGP_STATE_TRUST_FILE    "qgp-trust"
#define QGP_STATE_ACCEPTED_FILE "accepted-versions"
#define QGP_STATE_LOCK_FILE     ".lock"
#define QGP_ACCEPTED_MAX        (1u << 20)   /* accepted-versions file bound */
#define QGP_FIELD_MAX           256          /* Package / Version / Architecture value bound */

qgp_rc_t qgp_state_lock(const char *dir, int *fd_out);
void qgp_state_unlock(int fd);

/* QGP_E_NO_TRUST_STATE when <dir>/qgp-trust does not exist;
 * QGP_E_STATE_CORRUPT when it exists but does not parse. */
qgp_rc_t qgp_state_load_trust(const char *dir, qgp_trust_stored_t *out);
qgp_rc_t qgp_state_store_trust(const char *dir, const uint8_t *f, size_t len);

typedef struct {
    char *pkg;
    char *ver;
} qgp_accepted_t;

typedef struct {
    qgp_accepted_t *v;
    size_t          n;
} qgp_accepted_list_t;

qgp_rc_t qgp_accepted_parse(const uint8_t *buf, size_t len, qgp_accepted_list_t *out);
qgp_rc_t qgp_accepted_serialize(const qgp_accepted_list_t *l, uint8_t **out, size_t *out_len);
const char *qgp_accepted_get(const qgp_accepted_list_t *l, const char *pkg);
qgp_rc_t qgp_accepted_set(qgp_accepted_list_t *l, const char *pkg, const char *ver);
void qgp_accepted_free(qgp_accepted_list_t *l);

/* Missing file = empty list; a present file that does not parse = QGP_E_STATE_CORRUPT. */
qgp_rc_t qgp_state_load_accepted(const char *dir, qgp_accepted_list_t *out);
qgp_rc_t qgp_state_store_accepted(const char *dir, const qgp_accepted_list_t *l);

typedef struct {
    char pkg[QGP_FIELD_MAX + 1];
    char ver[QGP_FIELD_MAX + 1];
    char arch[QGP_FIELD_MAX + 1];
} qgp_control_fields_t;

/* Parse the stdout of `dpkg-deb -f <deb> Package Version Architecture`:
 * exactly three "Name: value" lines (names case-insensitive, each once, any
 * order — dpkg-deb(1) prints them "in the order in which they appear in the
 * control file"), values validated (deb-src-control(5) name, deb-version(7)
 * version, architecture [a-z0-9-]+). */
qgp_rc_t qgp_control_fields_parse(const char *out, size_t n, qgp_control_fields_t *f);

/* Run /usr/bin/dpkg-deb -f on the SAME bytes `d` that were verified: they are
 * copied into a sealed memfd and passed as /dev/fd/<n>, so the file on disk is
 * not read a second time. */
qgp_rc_t qgp_deb_read_control_fields(const uint8_t *d, size_t len, qgp_control_fields_t *f);

/* Trust floor (§1 verify) and local highest-accepted version (R2-5).
 * Refuses QGP_E_BELOW_FLOOR when ver < floor (no override), QGP_E_DOWNGRADE when
 * ver < the recorded highest unless allow_downgrade (then a WARN is logged).
 * *record = 1 when the record must be raised to `ver`. */
qgp_rc_t qgp_policy_check(const qgp_trust_state_t *st, const qgp_accepted_list_t *acc,
                          const char *pkg, const char *ver, int allow_downgrade, int *record);

#endif /* QGP_STATE_H */
