/*
 * qgp_safe_string.h - Anti-regression poison guard for unsafe string ops
 *
 * This header poisons strcpy() and sprintf() at the translation-unit level.
 * Any first-party .c file that includes this header CANNOT use strcpy or
 * sprintf — the compiler will reject it. Vendor code that does NOT include
 * this header is unaffected.
 *
 * Replacement: snprintf(dst, sizeof(dst), "%s", src) for copies,
 *              snprintf(dst, sizeof(dst), "fmt", args...) for formatted writes.
 *
 * See: .planning/phases/03-unsafe-c-pattern-remediation/
 */

#ifndef QGP_SAFE_STRING_H
#define QGP_SAFE_STRING_H

#pragma GCC poison strcpy sprintf

#endif /* QGP_SAFE_STRING_H */
