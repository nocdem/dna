/* exp_json — DNAC Explorer minimal growable-buffer JSON emitter.
 *
 * A hand-rolled emitter, not a parser/DOM: callers build a JSON document by
 * appending structural characters (exp_json_raw) interleaved with escaped
 * string values (exp_json_str), decimal integers (exp_json_u64), and
 * lowercase hex-string values (exp_json_hex). There is no validation that
 * the resulting document is well-formed JSON — callers (exp_http.c) are
 * responsible for balancing braces/brackets/commas.
 *
 * Ownership: exp_json_init() starts an empty, NUL-terminated buffer.
 * exp_json_freebuf() releases it. `buf` is always NUL-terminated after any
 * append call that didn't hit OOM (mid-append truncation on OOM leaves the
 * buffer as much as was successfully appended, still NUL-terminated — never
 * garbage/uninitialized past `len`).
 */
#ifndef EXP_JSON_H
#define EXP_JSON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} exp_json_t;

void exp_json_init(exp_json_t *j);
void exp_json_freebuf(exp_json_t *j);

/* Appends `s` verbatim — for structural JSON characters/keys the caller
 * already knows to be well-formed (e.g. "{\"height\":"), never for
 * caller-controlled/untrusted string content (use exp_json_str for that). */
void exp_json_raw(exp_json_t *j, const char *s);

/* Appends a JSON string literal: `"` + escaped(s) + `"`. Escapes '"', '\\',
 * and control characters (0x00-0x1F) per RFC 8259 (named escapes for
 * \n \r \t \b \f, \u00XX for the rest). s == NULL is treated as "" (emits
 * `""`), not a crash — defensive against a caller forgetting a NULL check
 * on optional string fields. */
void exp_json_str(exp_json_t *j, const char *s);

/* Appends an unsigned 64-bit integer in decimal, no quotes. */
void exp_json_u64(exp_json_t *j, uint64_t v);

/* Appends `"` + lowercase-hex(b[0..n)) + `"`. n == 0 or b == NULL emits an
 * empty string `""`. */
void exp_json_hex(exp_json_t *j, const uint8_t *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* EXP_JSON_H */
