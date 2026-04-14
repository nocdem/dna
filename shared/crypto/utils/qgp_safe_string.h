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

/* NOTE (Windows): <winsock2.h> / <windows.h> reference strcpy/sprintf in
 * macro bodies (rpcndr.h MIDL_ascii_strcpy, stralign.h ua_tcscpy). Any TU
 * that pulls them AFTER this header trips the poison pragma below.
 * Per-file fix: include the Windows networking headers BEFORE this header.
 * We intentionally do NOT pre-include <windows.h> here — doing so drags
 * the entire Win32 namespace into every TU and collides with single-letter
 * macros (D, N, Q, L, K) used by vendored crypto code like pq-crystals
 * Dilithium. See dht_gek_storage.c / dht_contact_request.c for the pattern. */
#pragma GCC poison strcpy sprintf

#endif /* QGP_SAFE_STRING_H */
