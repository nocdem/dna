/**
 * qgp_debver.c - Debian version comparison, written from deb-version(7)
 * (dpkg suite 1.21.23, "Sorting algorithm"), and package-name syntax from
 * deb-src-control(5).
 *
 * deb-version(7), quoted where the code depends on it:
 *  - "[epoch:]upstream-version[-debian-revision]"
 *  - epoch: "a single (generally small) unsigned integer. It may be omitted, in
 *    which case zero is assumed."
 *  - upstream-version: "may contain only alphanumerics ("A-Za-z0-9") and the
 *    characters . + - : ~ ... and should start with a digit. If there is no
 *    debian-revision then hyphens are not allowed; if there is no epoch then
 *    colons are not allowed." "The upstream-version portion of the version
 *    number is mandatory."
 *  - debian-revision: "may contain only alphanumerics and the characters + . ~"
 *    "Dpkg will break the version number apart at the last hyphen".
 *  - Sorting: compare non-digit prefixes "lexically ... modified so that all the
 *    letters sort earlier than all the non-letters and so that a tilde sorts
 *    before anything, even the end of a part"; then digit runs by numerical
 *    value, "an empty string ... counts as zero"; repeat.
 *
 * Readings (stricter than "should", fail-closed; flagged in the report):
 *  - upstream MUST start with a digit (the man page says "should");
 *  - an empty epoch ("":1.0) or an empty revision ("1.0-") is refused;
 *  - the epoch is limited to 9 decimal digits so it fits an int.
 *  - An absent revision is compared as the empty string by the same algorithm,
 *    so "1.0" and "1.0-0" compare EQUAL (the digit run of "" counts as zero).
 *    The man page's sentence "The absence of a debian-revision compares earlier
 *    than the presence of one" holds for every revision whose value is not zero.
 */
#include "qgp_debver.h"

#include <string.h>

#include "crypto/utils/qgp_safe_string.h"

static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static int is_alnum(char c) { return is_digit(c) || is_alpha(c); }

typedef struct {
    unsigned long epoch;
    const char *up;   size_t up_n;
    const char *rev;  size_t rev_n;   /* rev_n == 0: absent */
} debver_t;

static qgp_rc_t debver_split(const char *v, size_t n, debver_t *out)
{
    if (!v || n == 0)
        return QGP_E_BAD_VERSION;
    memset(out, 0, sizeof(*out));

    /* epoch: up to the FIRST ':' */
    const char *colon = memchr(v, ':', n);
    const char *rest = v;
    size_t rest_n = n;
    int has_epoch = 0;
    if (colon) {
        size_t en = (size_t)(colon - v);
        if (en == 0 || en > 9)
            return QGP_E_BAD_VERSION;
        unsigned long e = 0;
        for (size_t i = 0; i < en; i++) {
            if (!is_digit(v[i]))
                return QGP_E_BAD_VERSION;
            e = e * 10u + (unsigned long)(v[i] - '0');
        }
        out->epoch = e;
        rest = colon + 1;
        rest_n = n - en - 1;
        has_epoch = 1;
    }

    /* revision: after the LAST '-' */
    const char *dash = NULL;
    for (size_t i = rest_n; i > 0; i--) {
        if (rest[i - 1] == '-') { dash = rest + i - 1; break; }
    }
    if (dash) {
        out->up = rest;
        out->up_n = (size_t)(dash - rest);
        out->rev = dash + 1;
        out->rev_n = rest_n - out->up_n - 1;
        if (out->rev_n == 0)
            return QGP_E_BAD_VERSION;
    } else {
        out->up = rest;
        out->up_n = rest_n;
        out->rev = rest + rest_n;
        out->rev_n = 0;
    }

    if (out->up_n == 0 || !is_digit(out->up[0]))
        return QGP_E_BAD_VERSION;
    for (size_t i = 0; i < out->up_n; i++) {
        char c = out->up[i];
        if (is_alnum(c) || c == '.' || c == '+' || c == '~')
            continue;
        if (c == '-' && dash)       /* hyphens only with a revision */
            continue;
        if (c == ':' && has_epoch)  /* colons only with an epoch */
            continue;
        return QGP_E_BAD_VERSION;
    }
    for (size_t i = 0; i < out->rev_n; i++) {
        char c = out->rev[i];
        if (!(is_alnum(c) || c == '+' || c == '.' || c == '~'))
            return QGP_E_BAD_VERSION;
    }
    return QGP_OK;
}

qgp_rc_t qgp_debver_check(const char *v, size_t n)
{
    debver_t d;
    return debver_split(v, n, &d);
}

/* Lexical weight of one non-digit position (deb-version(7)): tilde before
 * everything including the end of the part; the end of the part next; then all
 * letters (ASCII order); then all non-letters (ASCII order). */
static int lex_weight(const char *s, size_t n, size_t i)
{
    if (i >= n)
        return 0;                 /* end of the part */
    char c = s[i];
    if (c == '~')
        return -1;
    if (is_alpha(c))
        return (unsigned char)c;
    return (unsigned char)c + 256;
}

/* The deb-version(7) sorting algorithm over one part (upstream or revision). */
static int part_cmp(const char *a, size_t an, const char *b, size_t bn)
{
    size_t i = 0, j = 0;
    while (i < an || j < bn) {
        /* 1. initial non-digit runs, compared lexically */
        while ((i < an && !is_digit(a[i])) || (j < bn && !is_digit(b[j]))) {
            int wa = (i < an && !is_digit(a[i])) ? lex_weight(a, an, i) : 0;
            int wb = (j < bn && !is_digit(b[j])) ? lex_weight(b, bn, j) : 0;
            if (wa != wb)
                return wa < wb ? -1 : 1;
            if (i < an && !is_digit(a[i])) i++;
            if (j < bn && !is_digit(b[j])) j++;
        }
        /* 2. initial digit runs, compared by numerical value (empty = 0).
         * Arbitrary length: skip leading zeros, then the longer run is larger,
         * equal lengths compare digit by digit. */
        while (i < an && a[i] == '0') i++;
        while (j < bn && b[j] == '0') j++;
        size_t ai = i, bj = j;
        while (i < an && is_digit(a[i])) i++;
        while (j < bn && is_digit(b[j])) j++;
        size_t alen = i - ai, blen = j - bj;
        if (alen != blen)
            return alen < blen ? -1 : 1;
        for (size_t k = 0; k < alen; k++) {
            if (a[ai + k] != b[bj + k])
                return a[ai + k] < b[bj + k] ? -1 : 1;
        }
    }
    return 0;
}

qgp_rc_t qgp_debver_cmp(const char *a, size_t an, const char *b, size_t bn, int *cmp)
{
    debver_t da, db;
    if (!cmp)
        return QGP_E_ARG;
    if (debver_split(a, an, &da) != QGP_OK || debver_split(b, bn, &db) != QGP_OK)
        return QGP_E_BAD_VERSION;
    if (da.epoch != db.epoch) {
        *cmp = da.epoch < db.epoch ? -1 : 1;
        return QGP_OK;
    }
    int r = part_cmp(da.up, da.up_n, db.up, db.up_n);
    if (r == 0)
        r = part_cmp(da.rev, da.rev_n, db.rev, db.rev_n);
    *cmp = r;
    return QGP_OK;
}

int qgp_debpkg_name_valid(const char *s, size_t n)
{
    if (!s || n < 2)
        return 0;
    if (!((s[0] >= 'a' && s[0] <= 'z') || is_digit(s[0])))
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || is_digit(c) || c == '+' || c == '-' || c == '.')
            continue;
        return 0;
    }
    return 1;
}
