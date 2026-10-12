/* Nodus Connect core — JavaScript-compatible helpers for the P1 rules
 * (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2, §2-§5).
 *
 * The rules ported to C (nc_payload.h) are specified by the JavaScript of
 * src/connect/ui/actions.js. This unit gives them the JavaScript building
 * blocks they use, each written to the ECMAScript behaviour, not to a C
 * habit:
 *
 *   - JSON.parse: a hand-written parser (no json-c) that accepts exactly
 *     the RFC 8259 grammar JSON.parse accepts — whitespace only SP HT LF
 *     CR, no comments, no NaN / Infinity, numbers
 *     -?(0|[1-9]d*)(.d+)?([eE][+-]?d+)?, no raw byte < 0x20 inside a
 *     string, the whole input one value — and builds what JSON.parse
 *     builds:
 *       strings: every escape decoded; \u0000 kept as a NUL byte (in values
 *         AND keys); an escaped pair joined into one code point; an
 *         unpaired escaped surrogate kept as that lone code unit (WTF-8);
 *       numbers: the double JSON.parse produces (strtod, correctly
 *         rounded), whatever the literal's size: 100000000000000000000 is
 *         1e20, 1e400 is Infinity, -0 is -0;
 *       objects: a repeated key keeps its LAST value (earlier pairs are
 *         marked dead); a key "__proto__" is an ordinary own key.
 *     Input bytes that are not well-formed UTF-8 (no JS string holds them)
 *     are a syntax error. json-c 0.17 strict could not be used for this: it
 *     is wider than JSON.parse (a raw control character in a string,
 *     "Infinity", "NaN", "1.", "01.5") and cannot carry a lone surrogate
 *     (U+FFFD), an integer literal outside int64/uint64 (ERANGE) or a NUL
 *     in a key (C-string keys) — json_tokener.c 0.17 :494-496, :535-560,
 *     :640-660, :748-865, :959-975, :1037-1056, :1204.
 *     ONE documented difference: nesting deeper than NC_JS_MAX_NEST is
 *     refused (NC_JS_DEPTH). V8's JSON.parse has no fixed nesting limit of
 *     its own (it ends at the engine's stack / memory limit); no vector
 *     covers this case.
 *   - JSON.stringify of a string: short escapes \b \t \n \f \r \" \\,
 *     lowercase \u00xx for every other byte < 0x20, '/' not escaped, 0x7F
 *     and U+2028 / U+2029 raw, a lone surrogate as lowercase \udxxx.
 *   - Number::toString (ECMA-262 §6.1.6.1.20): the shortest round-trip
 *     digits, the closest of them, in the ECMAScript layout (exponent form
 *     from 1e21 and below 1e-6).
 *   - String(x) for the JSON scalars, strict equality (===) of scalars,
 *     truthiness, Number.isInteger.
 *   - Strings: compared by length + memcmp, never strcmp (a JSON string
 *     carries NUL). Internally UTF-8; a lone surrogate (which only a JS
 *     string can hold) is the 3-byte WTF-8 form ED A0..BF xx, so lengths in
 *     UTF-16 units and code points match JavaScript's.
 *   - The ECMAScript WhiteSpace + LineTerminator set (String.prototype.trim,
 *     StringToBigInt): U+0009 U+000B U+000C U+0020 U+00A0 U+FEFF U+1680
 *     U+2000-U+200A U+202F U+205F U+3000 U+000A U+000D U+2028 U+2029.
 *   - BigInt: an arbitrary-precision signed integer (base 10^9 limbs) for
 *     BigInt(x) on JSON scalars (StringToBigInt with 0x / 0o / 0b, sign,
 *     surrounding whitespace; a non-integer Number is a RangeError), + and
 *     comparison. A 0x / 0o / 0b literal longer than NC_BIG_RADIX_MAX
 *     digits is NOT converted (NC_BIG_UNSUPPORTED): the conversion is
 *     quadratic; JavaScript converts any length.
 *
 * Pure: no clock, no randomness, no global state.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#ifndef NC_JSJSON_H
#define NC_JSJSON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── growable byte buffer ───────────────────────────────────────────── */

typedef struct {
    char  *p;      /* always NUL-terminated when non-NULL                 */
    size_t len;
    size_t cap;
    int    oom;    /* sticky: an append failed; the content is incomplete */
} nc_sb_t;

void  nc_sb_init(nc_sb_t *b);
void  nc_sb_free(nc_sb_t *b);
void  nc_sb_reset(nc_sb_t *b);                     /* len = 0, keeps oom */
int   nc_sb_put(nc_sb_t *b, const void *p, size_t n);
int   nc_sb_putc(nc_sb_t *b, char c);
int   nc_sb_puts(nc_sb_t *b, const char *s);       /* a C literal         */
/* The buffer (malloc'd, NUL-terminated, never NULL unless oom) and its
 * length; `b` is reset to empty. NULL if any append failed. */
char *nc_sb_take(nc_sb_t *b, size_t *len);

/* ── JSON.parse ─────────────────────────────────────────────────────── */

/* Deepest nesting of arrays / objects accepted (the one documented
 * difference from JSON.parse, see above). The app's payloads nest 2 deep,
 * the rule arguments 5; 512 keeps the recursive nc_jv_free of a tree well
 * inside the 1 MiB wasm stack (the parser itself is iterative). */
#define NC_JS_MAX_NEST 512

typedef enum {
    NC_JS_OK     = 0,   /* *out = the value (any JSON value)               */
    NC_JS_SYNTAX = 1,   /* JSON.parse would throw SyntaxError (or the bytes
                           are not UTF-8)                                  */
    NC_JS_DEPTH  = 2,   /* nesting > NC_JS_MAX_NEST                        */
    NC_JS_NOMEM  = 3
} nc_js_parse_t;

/* A parsed JSON value. */
typedef enum {
    NC_JV_NULL = 0, NC_JV_FALSE, NC_JV_TRUE, NC_JV_NUM, NC_JV_STR, NC_JV_ARR, NC_JV_OBJ
} nc_jvkind_t;

typedef struct nc_jv nc_jv_t;
struct nc_jv {
    nc_jvkind_t    kind;
    double         num;     /* NC_JV_NUM                                    */
    char          *s;       /* NC_JV_STR: n bytes of WTF-8 (+ a NUL after
                               them; the bytes may themselves hold NUL)     */
    size_t         n;
    nc_jv_t      **v;       /* NC_JV_ARR elements / NC_JV_OBJ values, in
                               input order                                  */
    size_t         len, cap;
    char         **k;       /* NC_JV_OBJ keys (WTF-8, may hold NUL) ...     */
    size_t        *kn;      /* ... and their lengths                        */
    unsigned char *dead;    /* NC_JV_OBJ: 1 = a later pair repeats the key
                               (JSON.parse keeps the last); NULL if none    */
};

/* Parse `len` bytes (NUL bytes are data, never an end). On NC_JS_OK *out
 * is the tree (nc_jv_free); otherwise *out = NULL. */
nc_js_parse_t nc_js_parse(const char *text, size_t len, nc_jv_t **out);
void          nc_jv_free(nc_jv_t *o);
/* obj[key] (a C literal key): the value of the LAST pair with that key, or
 * NULL when absent (JSON null is a node of kind NC_JV_NULL) or when `o` is
 * not an object. */
const nc_jv_t *nc_jv_get(const nc_jv_t *o, const char *key);

/* ── JSON.stringify ─────────────────────────────────────────────────── */

void nc_js_write_string(nc_sb_t *b, const char *s, size_t n);
/* A finite number as JSON.stringify writes it (Number::toString); a
 * non-finite one as null. */
void nc_js_write_number(nc_sb_t *b, double d);

/* Number::toString(d) (radix 10). Longest output: "-1.2345678901234567e-308"
 * = 24 chars. */
#define NC_JS_NUMSTR_MAX 32
void nc_js_number_to_string(double d, char out[NC_JS_NUMSTR_MAX]);

/* ── JS scalar values ───────────────────────────────────────────────── */

typedef enum {
    NC_V_UNDEF = 0,   /* absent property (undefined)                      */
    NC_V_NULL,
    NC_V_FALSE,
    NC_V_TRUE,
    NC_V_NUM,         /* every JSON number is a JS double                  */
    NC_V_STR
} nc_vkind_t;

typedef struct {
    nc_vkind_t  kind;
    double      num;  /* NC_V_NUM                                          */
    const char *s;    /* NC_V_STR: not NUL-terminated, may contain NUL     */
    size_t      n;
} nc_val_t;

nc_val_t nc_val_undef(void);
nc_val_t nc_val_str(const char *s, size_t n);

/* `o` as a scalar (NULL = absent = undefined). -1 if it is an array or an
 * object. The string points into the tree. */
int nc_val_from_jv(const nc_jv_t *o, nc_val_t *out);

/* String(v), appended. */
void nc_val_tostring(const nc_val_t *v, nc_sb_t *b);
/* ToBoolean(v). */
int  nc_val_truthy(const nc_val_t *v);
/* a === b. */
int  nc_val_strict_eq(const nc_val_t *a, const nc_val_t *b);
/* v === "<lit>" (a C literal). */
int  nc_val_is(const nc_val_t *v, const char *lit);
/* Number.isInteger(d). */
int  nc_js_is_integer(double d);

/* length + memcmp; `lit` is a C literal. */
int  nc_js_str_eq(const char *s, size_t n, const char *lit);

/* ── strings: UTF-8 / WTF-8, UTF-16 units, code points, whitespace ──── */

/* Bytes of the character starting at s[0] (1..4; 1 for a stray byte). */
size_t nc_utf8_char_len(const unsigned char *s, size_t n);
/* The character at s[0] is a lone HIGH surrogate (WTF-8 ED A0..AF xx). */
int    nc_utf8_is_lone_high(const unsigned char *s, size_t n);
/* JavaScript's .length (UTF-16 code units). */
size_t nc_js_utf16_len(const char *s, size_t n);
/* [...s].length (code points; a lone surrogate counts one). */
size_t nc_js_code_points(const char *s, size_t n);
/* Bytes of an ECMAScript WhiteSpace / LineTerminator character at s[0],
 * or 0. */
size_t nc_js_ws_at(const char *s, size_t n);
/* s.trim(): [*start, *end) of s. */
void   nc_js_trim(const char *s, size_t n, size_t *start, size_t *end);
/* ASCII-only toLowerCase, appended (see nc_payload.h for where this is
 * not JavaScript's full-Unicode toLowerCase). */
void   nc_js_lower_ascii(nc_sb_t *b, const char *s, size_t n);
/* TextEncoder().encode(s): a lone surrogate becomes U+FFFD. Appended. */
void   nc_js_to_utf8(nc_sb_t *b, const char *s, size_t n);

/* ── BigInt ─────────────────────────────────────────────────────────── */

#define NC_BIG_RADIX_MAX 4096u   /* digits of a 0x / 0o / 0b literal     */

typedef struct {
    int       neg;               /* never set for zero                   */
    uint32_t *limb;              /* base 10^9, least significant first   */
    size_t    n;                 /* 0 = zero                             */
    size_t    cap;
} nc_big_t;

typedef enum {
    NC_BIG_OK = 0,
    NC_BIG_SYNTAX,               /* BigInt(x) throws SyntaxError         */
    NC_BIG_RANGE,                /* RangeError (a non-integer Number)    */
    NC_BIG_TYPE,                 /* TypeError (undefined, null)          */
    NC_BIG_UNSUPPORTED,          /* a radix literal over NC_BIG_RADIX_MAX */
    NC_BIG_NOMEM
} nc_big_rc_t;

void        nc_big_init(nc_big_t *a);
void        nc_big_free(nc_big_t *a);
/* BigInt(v) for a JSON scalar. */
nc_big_rc_t nc_big_from_val(nc_big_t *a, const nc_val_t *v);
nc_big_rc_t nc_big_from_u128(nc_big_t *a, unsigned __int128 v);
/* acc += b */
nc_big_rc_t nc_big_add(nc_big_t *acc, const nc_big_t *b);
/* -1, 0, 1 */
int         nc_big_cmp(const nc_big_t *a, const nc_big_t *b);
/* String(a), appended. */
void        nc_big_to_string(const nc_big_t *a, nc_sb_t *b);

/* Decimal of an unsigned 128-bit value, appended. */
void        nc_u128_to_string(unsigned __int128 v, nc_sb_t *b);

#ifdef __cplusplus
}
#endif
#endif /* NC_JSJSON_H */
