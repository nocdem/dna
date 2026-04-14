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

#ifdef _WIN32
/* Windows system headers (rpcndr.h, stralign.h via windows.h) reference
 * strcpy/sprintf as tokens in macro definitions (MIDL_ascii_strcpy,
 * ua_tcscpy). #pragma GCC poison triggers on any subsequent occurrence
 * of these tokens — even inside unused macro bodies. Pre-include
 * <windows.h> so those macros are parsed before the poison takes
 * effect; any user TU that later pulls <winsock2.h> / <windows.h>
 * will just see the header guards and skip re-parsing. */
#include <windows.h>
#endif

#pragma GCC poison strcpy sprintf

#endif /* QGP_SAFE_STRING_H */
