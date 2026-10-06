/**
 * qgp_debver.h - Debian version syntax + comparison, Debian package-name syntax.
 *
 * Reference (read on the build machine, dpkg suite 1.21.23):
 *   deb-version(7)      — version format and the "Sorting algorithm" section;
 *   deb-src-control(5)  — package-name grammar ("Source:" field).
 */
#ifndef QGP_DEBVER_H
#define QGP_DEBVER_H

#include <stddef.h>

#include "qgp_core.h"

/* Validate a version string of length n (no NUL required) per deb-version(7):
 *   [epoch:]upstream-version[-debian-revision]
 * Returns QGP_OK or QGP_E_BAD_VERSION. */
qgp_rc_t qgp_debver_check(const char *v, size_t n);

/* Compare two VALID versions. *cmp < 0, 0, > 0 like strcmp.
 * Returns QGP_E_BAD_VERSION if either is not valid (nothing is compared). */
qgp_rc_t qgp_debver_cmp(const char *a, size_t an, const char *b, size_t bn, int *cmp);

/* Package name per deb-src-control(5): only a-z 0-9 + - . ; at least two
 * characters; starts with a-z or 0-9. Returns 1 if valid, else 0. */
int qgp_debpkg_name_valid(const char *s, size_t n);

#endif /* QGP_DEBVER_H */
