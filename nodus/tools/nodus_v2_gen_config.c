/**
 * @file nodus/tools/nodus_v2_gen_config.c
 * @brief O16A / D2 — the genesis config text parser.
 *
 * Format, ownership contract and the reason the three forced constants
 * are not settable: the header. This file is the determinism argument
 * (design invariant D-I5) expressed as code, so every rule below states
 * the divergence it prevents rather than what it does.
 *
 * ── OUTPUT CONVENTION ───────────────────────────────────────────────
 * fprintf(stderr), NOT QGP_LOG_*. This is the tools/ CLI surface, the
 * same one nodus-server.c's own option errors use (:209-211, :299-300)
 * and the same one nodus_witness_bootstrap.c uses for its operator
 * lines. Every message here is read by a human standing at a terminal
 * during a ceremony, must appear whatever the log level is set to, and
 * must not be prefixed with a module tag that means nothing to them.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus_v2_gen_config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── bounds ──────────────────────────────────────────────────────────
 * The longest legal line is a validator pubkey: 26 characters of key
 * name, spaces around '=', and 2 * DNAC_PUBKEY_SIZE = 5184 hex
 * characters. 8192 leaves room for generous alignment padding and a
 * trailing comment while still being a bound, and an over-long line is
 * a REFUSAL, never a silent truncation — a truncated 5184-char pubkey
 * that still parsed would be a different validator, hence a different
 * chain, reported as success. */
#define NV2GC_MAX_LINE   8192u

/* Longest key name we accept, plus room to echo an unknown one back to
 * the operator without truncating the thing they typed. */
#define NV2GC_MAX_KEY    64u

/* Allocation array growth. The ceiling is the builder's
 * NODUS_V2_GEN_MAX_ALLOCS; this is only the doubling step. */
#define NV2GC_ALLOC_STEP 64u

/* ── the open scope ───────────────────────────────────────────────── */

typedef enum {
    NV2GC_SCOPE_TOP = 0,
    NV2GC_SCOPE_VALIDATOR,
    NV2GC_SCOPE_ALLOCATION
} nv2gc_scope_t;

/* Every key of the open scope, as a bit in a "seen" mask. The mask is
 * how BOTH the duplicate-key refusal and the missing-key refusal are
 * expressed: one bit set twice is a duplicate, a bit still clear when
 * the scope closes is an absent required key. Neither is a precedence
 * rule, because there is no precedence rule to have — see the header.
 *
 * The three groups DELIBERATELY reuse the same bit values: only one
 * scope is ever open, `seen` is cleared on every scope change, and each
 * group is only ever tested against its own REQUIRED mask. Do not
 * "fix" them into 13 distinct bits — that would suggest the masks are
 * comparable across scopes, which they are not. */
enum {
    /* NV2GC_SCOPE_TOP */
    NV2GC_K_TOTAL_SUPPLY   = 1u << 0,
    NV2GC_K_EPOCH_LENGTH   = 1u << 1,
    NV2GC_K_BLOCKS_YEAR    = 1u << 2,
    NV2GC_K_DECIMAL_UNIT   = 1u << 3,
    NV2GC_K_INFL_START     = 1u << 4,
    NV2GC_TOP_REQUIRED     = NV2GC_K_TOTAL_SUPPLY | NV2GC_K_EPOCH_LENGTH |
                             NV2GC_K_BLOCKS_YEAR  | NV2GC_K_DECIMAL_UNIT |
                             NV2GC_K_INFL_START,

    /* NV2GC_SCOPE_VALIDATOR */
    NV2GC_K_PUBKEY         = 1u << 0,
    NV2GC_K_UNSTAKE_PK     = 1u << 1,
    NV2GC_K_UNSTAKE_FP     = 1u << 2,
    NV2GC_K_SELF_STAKE     = 1u << 3,
    NV2GC_K_COMMISSION     = 1u << 4,
    NV2GC_VAL_REQUIRED     = NV2GC_K_PUBKEY     | NV2GC_K_UNSTAKE_PK |
                             NV2GC_K_UNSTAKE_FP | NV2GC_K_SELF_STAKE |
                             NV2GC_K_COMMISSION,

    /* NV2GC_SCOPE_ALLOCATION */
    NV2GC_K_SOURCE_ID      = 1u << 0,
    NV2GC_K_DEST_BINDING   = 1u << 1,
    NV2GC_K_AMOUNT         = 1u << 2,
    NV2GC_ALLOC_REQUIRED   = NV2GC_K_SOURCE_ID | NV2GC_K_DEST_BINDING |
                             NV2GC_K_AMOUNT
};

/* ── byte classification: EXPLICIT, never <ctype.h> ──────────────────
 * isspace()/isdigit()/isxdigit() are LOCALE-SENSITIVE by definition
 * (C11 7.4p1: their behaviour depends on the current LC_CTYPE). Two
 * operators whose machines differ in LANG could then split one file
 * into two structs, which is one chain each. Nothing on this path is
 * allowed to consult a locale, so the classification is written out. */

static int nv2gc_is_hspace(char c) { return c == ' ' || c == '\t'; }
static int nv2gc_is_digit(char c)  { return c >= '0' && c <= '9'; }
static int nv2gc_is_lhex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}
/* Key names in this format are lowercase ASCII words. Validating the
 * charset means an unknown-key message can be printed back verbatim
 * without the possibility of emitting control bytes at a terminal. */
static int nv2gc_is_keychar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static uint8_t nv2gc_hexval(char c) {
    return (uint8_t)((c <= '9') ? (c - '0') : (c - 'a' + 10));
}

/* Echo an arbitrary line back to the operator with every byte outside
 * printable ASCII replaced by '?'.
 *
 * WHY THIS EXISTS, given the note above about key charsets. That note is
 * true for KEY names and false for two other messages: the unknown block
 * header and the "not 'key = value'" line both print `s` verbatim, and
 * `s` has only been screened for CR and NUL. An ESC byte survives, so a
 * malformed line could emit a terminal control sequence into an
 * operator's session. It is not an attack — a hostile config file means
 * a hostile operator, which is out of scope — but the file claimed the
 * possibility away, and a claim that does not hold is worse than no
 * claim. Truncation is explicit rather than silent: the operator gets a
 * bounded prefix and is told it is one.
 *
 * Diagnostic only. It never touches a byte that reaches the struct. */
#define NV2GC_ECHO_MAX 96
static void nv2gc_echo(const char *s, char out[NV2GC_ECHO_MAX + 4]) {
    size_t i = 0;
    for (; s[i] && i < NV2GC_ECHO_MAX; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i] = (c >= 0x20 && c <= 0x7E) ? (char)c : '?';
    }
    if (s[i]) { out[i++] = '.'; out[i++] = '.'; out[i++] = '.'; }
    out[i] = 0;
}

/* Does this line begin with a UTF-8 byte-order mark?
 *
 * A Windows or macOS editor writes EF BB BF at byte 0 and shows nothing.
 * Without this the file still refuses — correctly — but with a message
 * about an unparseable line or a bad key character, and the operator
 * looks at a line that appears perfectly fine. The ceremony is performed
 * once, under time pressure, by someone who cannot see the bytes; a
 * refusal that does not name the cause costs an hour. */
static int nv2gc_has_bom(const char *s) {
    const unsigned char *u = (const unsigned char *)s;
    return u[0] == 0xEF && u[1] == 0xBB && u[2] == 0xBF;
}

/* ── strict scalar parsers ───────────────────────────────────────────
 * NO strtoull, NO atoi, at any strength of "careful". strtoull accepts
 * a leading sign, leading whitespace whose definition is locale-bound,
 * and 0x/0 prefixes; atoi cannot report overflow at all and clamps or
 * wraps depending on the implementation. A clamp is the worst outcome
 * available here: it turns "the operator typed one digit too many" into
 * a DIFFERENT, silently derivable supply. */

/* Base-10 uint64. Requires: at least one digit, digits only, no sign,
 * no whitespace, no prefix, no trailing byte, no overflow. 0 / -1. */
static int nv2gc_u64(const char *s, uint64_t *out) {
    if (!s || !s[0]) return -1;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (!nv2gc_is_digit(*p)) return -1;
        uint64_t d = (uint64_t)(*p - '0');
        if (v > UINT64_MAX / 10u) return -1;
        v *= 10u;
        if (v > UINT64_MAX - d) return -1;
        v += d;
    }
    *out = v;
    return 0;
}

/* Exactly `want` bytes of LOWERCASE hex, decoded. Uppercase REFUSES:
 * accepting it here would let one file produce two byte strings
 * depending on how the operator's editor cased it. 0 / -1. */
static int nv2gc_hex(const char *s, size_t want, uint8_t *out) {
    if (!s) return -1;
    size_t n = strlen(s);
    if (n != want * 2u) return -1;
    for (size_t i = 0; i < want; i++) {
        char hi = s[2 * i], lo = s[2 * i + 1];
        if (!nv2gc_is_lhex(hi) || !nv2gc_is_lhex(lo)) return -1;
        out[i] = (uint8_t)((nv2gc_hexval(hi) << 4) | nv2gc_hexval(lo));
    }
    return 0;
}

/* The fingerprint field is NOT decoded: `unstake_destination_fp` stores
 * the 128 hex CHARACTERS themselves plus a NUL at index 128, which is
 * the shape the graduation predicate demands (v2ep_fp_ok,
 * nodus_witness_v2_epoch.c:93-99, reached through
 * nodus_witness_v2_epoch_val_rec_ok at nodus_witness_v2_gen.c:602).
 *
 * That predicate accepts LOWERCASE ONLY. Accepting an uppercase digit
 * here would build a config that derives a complete chain and then
 * HALTS it at the first RETIRING graduation, with no recovery — so the
 * case rule is enforced at the first point that can see it. 0 / -1. */
static int nv2gc_fp(const char *s, uint8_t out[DNAC_FINGERPRINT_SIZE]) {
    if (!s) return -1;
    if (strlen(s) != 128u) return -1;
    for (size_t i = 0; i < 128u; i++) {
        if (!nv2gc_is_lhex(s[i])) return -1;
        out[i] = (uint8_t)s[i];
    }
    out[128] = 0;
    return 0;
}

/* ── the line reader ─────────────────────────────────────────────────
 * Byte-oriented on purpose. fgets() cannot distinguish "the line was
 * longer than the buffer" from "the last line has no newline" without a
 * second read, and it happily stores an embedded NUL that would then
 * truncate every strlen() downstream — a file with a stray 0x00 would
 * parse as a PREFIX of itself and derive a chain nobody meant.
 *
 * @return 1 a line was read, 0 clean EOF with no bytes, -1 refused
 *         (over-long, embedded NUL, CR, or a read fault). */
static int nv2gc_readline(FILE *fp, char *buf, size_t cap, size_t lineno) {
    size_t n = 0;
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n') { buf[n] = 0; return 1; }
        if (c == '\r') {
            /* A CRLF file is NOT normalised silently. Normalisation is a
             * transformation of the operator's bytes, and this parser's
             * whole contract is that it performs none: it says what is
             * wrong and stops. */
            fprintf(stderr,
                    "genesis config line %zu: carriage return (0x0D) in the "
                    "file — this parser reads LF-terminated ASCII and will "
                    "not silently rewrite your bytes. Convert the file to "
                    "Unix line endings and re-run.\n", lineno);
            return -1;
        }
        if (c == 0) {
            fprintf(stderr,
                    "genesis config line %zu: embedded NUL byte — this is "
                    "not a text config file.\n", lineno);
            return -1;
        }
        if (n + 1u >= cap) {
            fprintf(stderr,
                    "genesis config line %zu: longer than the %u-byte limit "
                    "— REFUSED rather than truncated. A truncated hex field "
                    "would still parse and would derive a different chain.\n",
                    lineno, (unsigned)(cap - 1u));
            return -1;
        }
        buf[n++] = (char)c;
    }
    if (ferror(fp)) {
        fprintf(stderr, "genesis config line %zu: read error.\n", lineno);
        return -1;
    }
    if (n == 0) return 0;              /* clean EOF, nothing pending    */
    buf[n] = 0;                        /* final line without a newline  */
    return 1;
}

/* ── the parse state ─────────────────────────────────────────────── */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;   /* grown; handed to cfg at the end */
    uint32_t               allocs_cap;
    uint32_t               n_allocs;
    nv2gc_scope_t          scope;
    unsigned               seen;     /* key bits of the OPEN scope      */
    size_t                 scope_line; /* where the open scope started  */
} nv2gc_state_t;

/* Close the open scope: every one of its keys must have been seen
 * exactly once. The "exactly once" half is the duplicate check at the
 * assignment site; this is the "at least once" half. */
static int nv2gc_close_scope(nv2gc_state_t *st, size_t lineno) {
    unsigned need;
    const char *what;
    switch (st->scope) {
        case NV2GC_SCOPE_VALIDATOR:  need = NV2GC_VAL_REQUIRED;
                                     what = "a [validator] block";  break;
        case NV2GC_SCOPE_ALLOCATION: need = NV2GC_ALLOC_REQUIRED;
                                     what = "an [allocation] block"; break;
        default:                     need = NV2GC_TOP_REQUIRED;
                                     what = "the top-level section";  break;
    }
    if ((st->seen & need) == need) return 0;

    /* Name the block by the line it OPENED on: in a seven-validator
     * ceremony file "a [validator] block is incomplete" without a
     * position is not actionable. The top-level section has no opening
     * line, so it is named rather than located. */
    if (st->scope == NV2GC_SCOPE_TOP) {
        fprintf(stderr,
                "genesis config line %zu: %s is missing a required key. It "
                "must carry all of total_supply_raw, epoch_length, "
                "blocks_per_year, decimal_unit and inflation_start_block, "
                "before the first block header. An absent key is REFUSED, "
                "never defaulted — a default would silently decide a value "
                "that reaches the chain id.\n", lineno, what);
    } else {
        fprintf(stderr,
                "genesis config line %zu: %s opened at line %zu is missing a "
                "required key. Every key of a block must appear exactly once "
                "before the next block header or EOF; an absent key is "
                "REFUSED, never defaulted.\n", lineno, what, st->scope_line);
    }
    return -1;
}

/* Reserve room for one more allocation. */
static int nv2gc_alloc_grow(nv2gc_state_t *st, size_t lineno) {
    if (st->n_allocs < st->allocs_cap) return 0;
    if (st->allocs_cap >= NODUS_V2_GEN_MAX_ALLOCS) {
        fprintf(stderr,
                "genesis config line %zu: more than %u [allocation] blocks "
                "— the builder's ceiling.\n",
                lineno, (unsigned)NODUS_V2_GEN_MAX_ALLOCS);
        return -1;
    }
    uint32_t cap = st->allocs_cap ? st->allocs_cap * 2u : NV2GC_ALLOC_STEP;
    if (cap > NODUS_V2_GEN_MAX_ALLOCS) cap = NODUS_V2_GEN_MAX_ALLOCS;
    nodus_v2_gen_alloc_t *p =
        realloc(st->allocs, (size_t)cap * sizeof(*p));
    if (!p) {
        fprintf(stderr, "genesis config line %zu: out of memory.\n", lineno);
        return -1;
    }
    memset(p + st->allocs_cap, 0,
           (size_t)(cap - st->allocs_cap) * sizeof(*p));
    st->allocs = p;
    st->allocs_cap = cap;
    return 0;
}

/* Open a new block. Closes the current one first, so a header is also
 * the point at which the previous block's completeness is decided. */
static int nv2gc_open_scope(nv2gc_state_t *st, nv2gc_scope_t s,
                            size_t lineno) {
    if (nv2gc_close_scope(st, lineno) != 0) return -1;

    if (s == NV2GC_SCOPE_VALIDATOR) {
        if (st->cfg->n_validators >= NODUS_V2_GEN_MAX_VALIDATORS) {
            /* The parser owns the ARRAY BOUND only. The exact-count rule
             * (n_validators == DNAC_COMMITTEE_SIZE, Rule P.1) belongs to
             * gen_plan_build (nodus_witness_v2_gen.c:559-564) and is
             * deliberately NOT restated here: two copies of a genesis
             * rule are two rules that can drift. */
            fprintf(stderr,
                    "genesis config line %zu: more than %u [validator] "
                    "blocks — the config array bound.\n",
                    lineno, (unsigned)NODUS_V2_GEN_MAX_VALIDATORS);
            return -1;
        }
        st->cfg->n_validators = (uint16_t)(st->cfg->n_validators + 1u);
    } else if (s == NV2GC_SCOPE_ALLOCATION) {
        if (nv2gc_alloc_grow(st, lineno) != 0) return -1;
        st->n_allocs++;
    }

    st->scope = s;
    st->seen = 0;
    st->scope_line = lineno;
    return 0;
}

/* Mark a key seen, refusing a repeat. The refusal is the point: a
 * duplicate has two defensible resolutions (first-wins, last-wins) and
 * a parser that silently picks one is a parser another build could
 * disagree with. */
static int nv2gc_mark(nv2gc_state_t *st, unsigned bit, const char *key,
                      size_t lineno) {
    if (st->seen & bit) {
        fprintf(stderr,
                "genesis config line %zu: duplicate key '%s' in the block "
                "opened at line %zu — REFUSED. There is no first-wins or "
                "last-wins rule here; two rules would be two chains.\n",
                lineno, key, st->scope_line);
        return -1;
    }
    st->seen |= bit;
    return 0;
}

/* ── key dispatch ────────────────────────────────────────────────── */

static void nv2gc_bad_value(size_t lineno, const char *key,
                            const char *expected) {
    fprintf(stderr, "genesis config line %zu: key '%s' — %s\n",
            lineno, key, expected);
}

static int nv2gc_assign_top(nv2gc_state_t *st, const char *key,
                            const char *val, size_t lineno) {
    struct { const char *name; unsigned bit; uint64_t *dst; } tbl[] = {
        { "total_supply_raw",      NV2GC_K_TOTAL_SUPPLY,
          &st->cfg->total_supply_raw },
        { "epoch_length",          NV2GC_K_EPOCH_LENGTH,
          &st->cfg->epoch_length },
        { "blocks_per_year",       NV2GC_K_BLOCKS_YEAR,
          &st->cfg->blocks_per_year },
        { "decimal_unit",          NV2GC_K_DECIMAL_UNIT,
          &st->cfg->decimal_unit },
        { "inflation_start_block", NV2GC_K_INFL_START,
          &st->cfg->inflation_start_block },
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strcmp(key, tbl[i].name) != 0) continue;
        if (nv2gc_mark(st, tbl[i].bit, key, lineno) != 0) return -1;
        if (nv2gc_u64(val, tbl[i].dst) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected a base-10 unsigned 64-bit integer with no sign, "
                "no spaces inside the value and no trailing characters. "
                "An out-of-range value is REFUSED, never clamped.");
            return -1;
        }
        return 0;
    }
    return 1;                                     /* not a top-level key */
}

static int nv2gc_assign_validator(nv2gc_state_t *st, const char *key,
                                  const char *val, size_t lineno) {
    /* n_validators >= 1 here by construction: the ONLY way this scope
     * becomes open is nv2gc_open_scope(VALIDATOR), which increments the
     * count — after its bound check — before it sets the scope. */
    nodus_v2_gen_validator_t *v =
        &st->cfg->validators[st->cfg->n_validators - 1u];

    if (strcmp(key, "pubkey") == 0) {
        if (nv2gc_mark(st, NV2GC_K_PUBKEY, key, lineno) != 0) return -1;
        if (nv2gc_hex(val, DNAC_PUBKEY_SIZE, v->pubkey) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected exactly 5184 LOWERCASE hex characters "
                "(DNAC_PUBKEY_SIZE = 2592 bytes).");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "unstake_destination_pubkey") == 0) {
        if (nv2gc_mark(st, NV2GC_K_UNSTAKE_PK, key, lineno) != 0) return -1;
        if (nv2gc_hex(val, DNAC_PUBKEY_SIZE,
                      v->unstake_destination_pubkey) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected exactly 5184 LOWERCASE hex characters "
                "(DNAC_PUBKEY_SIZE = 2592 bytes).");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "unstake_destination_fp") == 0) {
        if (nv2gc_mark(st, NV2GC_K_UNSTAKE_FP, key, lineno) != 0) return -1;
        if (nv2gc_fp(val, v->unstake_destination_fp) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected exactly 128 LOWERCASE hex characters = "
                "SHA3-512(unstake_destination_pubkey). Uppercase is "
                "refused: the graduation predicate that later reads this "
                "field accepts lowercase only, so an uppercase digit "
                "would derive a chain that HALTS at its first retirement.");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "self_stake") == 0) {
        if (nv2gc_mark(st, NV2GC_K_SELF_STAKE, key, lineno) != 0) return -1;
        if (nv2gc_u64(val, &v->self_stake) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected a base-10 unsigned 64-bit integer (raw units).");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "commission_bps") == 0) {
        if (nv2gc_mark(st, NV2GC_K_COMMISSION, key, lineno) != 0) return -1;
        uint64_t tmp = 0;
        /* Two separate obligations, and only the first is the parser's:
         * the field is a uint16_t, so a value above 65535 is not
         * REPRESENTABLE and truncating it would store a number the
         * operator never typed. The POLICY ceiling
         * (DNAC_COMMISSION_BPS_MAX) stays with gen_plan_build
         * (nodus_witness_v2_gen.c:584-589) — one authority per rule. */
        if (nv2gc_u64(val, &tmp) != 0 || tmp > (uint64_t)UINT16_MAX) {
            nv2gc_bad_value(lineno, key,
                "expected a base-10 integer in [0, 65535] — the field is a "
                "uint16_t and an out-of-range value is refused, not "
                "truncated.");
            return -1;
        }
        v->commission_bps = (uint16_t)tmp;
        return 0;
    }
    return 1;                                     /* not a validator key */
}

static int nv2gc_assign_alloc(nv2gc_state_t *st, const char *key,
                              const char *val, size_t lineno) {
    /* n_allocs >= 1 and the slot exists here by construction: this scope
     * is only opened by nv2gc_open_scope(ALLOCATION), which grows the
     * array and then increments the count before setting the scope. */
    nodus_v2_gen_alloc_t *a = &st->allocs[st->n_allocs - 1u];

    if (strcmp(key, "source_id") == 0) {
        if (nv2gc_mark(st, NV2GC_K_SOURCE_ID, key, lineno) != 0) return -1;
        if (nv2gc_hex(val, NODUS_V2_GEN_SRCID_LEN, a->source_id) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected exactly 128 LOWERCASE hex characters (64 bytes).");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "dest_binding") == 0) {
        if (nv2gc_mark(st, NV2GC_K_DEST_BINDING, key, lineno) != 0) return -1;
        if (nv2gc_hex(val, 64u, a->dest_binding) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected exactly 128 LOWERCASE hex characters = "
                "SHA3-512(claimant pubkey) — the claim pipeline compares "
                "this field byte-for-byte.");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "amount") == 0) {
        if (nv2gc_mark(st, NV2GC_K_AMOUNT, key, lineno) != 0) return -1;
        if (nv2gc_u64(val, &a->amount) != 0) {
            nv2gc_bad_value(lineno, key,
                "expected a base-10 unsigned 64-bit integer (raw units).");
            return -1;
        }
        return 0;
    }
    return 1;                                    /* not an allocation key */
}

/* ── the parse ───────────────────────────────────────────────────── */

void nodus_v2_gen_config_free(nodus_v2_gen_config_t *cfg) {
    if (!cfg) return;
    /* `allocs` is const in the struct because the BUILDER never writes
     * through it (nodus_witness_v2_gen.h:279). This module allocated the
     * storage, so discarding that qualifier here is discarding a
     * statement about mutation, not one about ownership. */
    void *owned = (void *)(uintptr_t)cfg->allocs;
    free(owned);
    free(cfg);
}

int nodus_v2_gen_config_parse_file(const char *path,
                                   nodus_v2_gen_config_t **out_cfg) {
    if (!out_cfg) return -1;
    *out_cfg = NULL;
    if (!path || !path[0]) {
        fprintf(stderr, "genesis config: no path given.\n");
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "genesis config: cannot open %s\n", path);
        return -1;
    }

    nv2gc_state_t st;
    memset(&st, 0, sizeof(st));
    st.scope = NV2GC_SCOPE_TOP;
    st.scope_line = 0;

    /* ⚠ ~160 KB. calloc, never a stack instance — the type says so at
     * nodus_witness_v2_gen.h:246-249 and a stack copy overflows the
     * default thread stack the same way nodus_witness_t does. calloc
     * also means every byte this parser does not write is zero, which
     * matters for the pad the config encoder walks. */
    st.cfg = calloc(1, sizeof(*st.cfg));
    char *line = malloc(NV2GC_MAX_LINE);
    if (!st.cfg || !line) {
        fprintf(stderr, "genesis config: out of memory.\n");
        free(st.cfg);
        free(line);
        fclose(fp);
        return -1;
    }

    int rc = -1;
    size_t lineno = 0;
    for (;;) {
        lineno++;
        int lr = nv2gc_readline(fp, line, NV2GC_MAX_LINE, lineno);
        if (lr < 0) goto out;
        if (lr == 0) break;                                    /* EOF   */

        /* A '#' begins a comment wherever it appears. No value in this
         * format may legally contain one — every value is decimal digits
         * or lowercase hex — so there is no quoting rule to get wrong
         * and no way for a comment to eat a byte that mattered. */
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;

        /* Trim horizontal whitespace at both ends. Note what is NOT
         * trimmed: whitespace INSIDE a value. The value parsers reject
         * any non-digit / non-hex byte, so "1 000" and " 12" (after the
         * '=' had its own padding removed) are refusals, not 1000 and
         * 12. That is the "no leading whitespace inside the value" rule
         * — it is enforced by the charset, so it cannot be forgotten at
         * one call site and kept at another. */
        char *s = line;
        while (*s && nv2gc_is_hspace(*s)) s++;
        size_t slen = strlen(s);
        while (slen > 0 && nv2gc_is_hspace(s[slen - 1])) s[--slen] = 0;
        if (slen == 0) continue;                        /* blank/comment */

        /* Block header. */
        if (s[0] == '[') {
            if (strcmp(s, "[validator]") == 0) {
                if (nv2gc_open_scope(&st, NV2GC_SCOPE_VALIDATOR,
                                     lineno) != 0) goto out;
            } else if (strcmp(s, "[allocation]") == 0) {
                if (nv2gc_open_scope(&st, NV2GC_SCOPE_ALLOCATION,
                                     lineno) != 0) goto out;
            } else {
                char echo[NV2GC_ECHO_MAX + 4];
                nv2gc_echo(s, echo);
                fprintf(stderr,
                        "genesis config line %zu: unknown block header '%s' "
                        "— only [validator] and [allocation] exist.\n",
                        lineno, echo);
                goto out;
            }
            continue;
        }

        /* key = value */
        char *eq = strchr(s, '=');
        if (!eq) {
            char echo[NV2GC_ECHO_MAX + 4];
            nv2gc_echo(s, echo);
            if (nv2gc_has_bom(s)) {
                fprintf(stderr,
                        "genesis config line %zu: the file begins with a "
                        "UTF-8 byte-order mark (EF BB BF). The line looks "
                        "correct in an editor because the BOM is invisible. "
                        "Save the file as UTF-8 WITHOUT a BOM, or strip the "
                        "first three bytes.\n", lineno);
            } else {
                fprintf(stderr,
                        "genesis config line %zu: not 'key = value' and not "
                        "a block header: '%s'\n", lineno, echo);
            }
            goto out;
        }
        *eq = 0;
        char *key = s;
        char *val = eq + 1;

        size_t klen = strlen(key);
        while (klen > 0 && nv2gc_is_hspace(key[klen - 1])) key[--klen] = 0;
        while (*val && nv2gc_is_hspace(*val)) val++;
        size_t vlen = strlen(val);
        while (vlen > 0 && nv2gc_is_hspace(val[vlen - 1])) val[--vlen] = 0;

        if (klen == 0 || klen >= NV2GC_MAX_KEY) {
            fprintf(stderr,
                    "genesis config line %zu: empty or over-long key name.\n",
                    lineno);
            goto out;
        }
        for (size_t i = 0; i < klen; i++) {
            if (nv2gc_is_keychar(key[i])) continue;
            /* The BOM lands here when line 1 is a key rather than a
             * comment, and "a byte that is not [a-z0-9_]" is true but
             * useless: the operator sees a key that looks perfect. */
            if (i == 0 && nv2gc_has_bom(key)) {
                fprintf(stderr,
                        "genesis config line %zu: the file begins with a "
                        "UTF-8 byte-order mark (EF BB BF) glued to the key "
                        "name. It is invisible in an editor. Save as UTF-8 "
                        "WITHOUT a BOM, or strip the first three bytes.\n",
                        lineno);
            } else {
                fprintf(stderr,
                        "genesis config line %zu: key name contains a byte "
                        "that is not [a-z0-9_].\n", lineno);
            }
            goto out;
        }
        if (vlen == 0) {
            fprintf(stderr,
                    "genesis config line %zu: key '%s' has an empty value. "
                    "An empty value is REFUSED, not read as zero.\n",
                    lineno, key);
            goto out;
        }

        int ar;
        switch (st.scope) {
            case NV2GC_SCOPE_VALIDATOR:
                ar = nv2gc_assign_validator(&st, key, val, lineno); break;
            case NV2GC_SCOPE_ALLOCATION:
                ar = nv2gc_assign_alloc(&st, key, val, lineno); break;
            default:
                ar = nv2gc_assign_top(&st, key, val, lineno); break;
        }
        if (ar < 0) goto out;
        if (ar > 0) {
            /* Not a key of the OPEN scope. This is where a top-level key
             * typed after a [validator] header lands, and it is treated
             * as exactly what it is — a key that does not belong here.
             * The alternative (silently reopening the top-level scope)
             * would let a config be written whose meaning depends on
             * where the reader thinks a block ends. */
            fprintf(stderr,
                    "genesis config line %zu: unknown key '%s' in %s. An "
                    "unrecognised key is REFUSED — a typo must not leave a "
                    "structural default sitting in the slot you meant to "
                    "fill, because that default would reach the chain id.\n",
                    lineno, key,
                    st.scope == NV2GC_SCOPE_VALIDATOR  ? "a [validator] block"
                    : st.scope == NV2GC_SCOPE_ALLOCATION ? "an [allocation] block"
                    : "the top-level section");
            goto out;
        }
    }

    /* EOF closes the LAST open scope, whichever it is.
     *
     * The top-level section is covered even when the file ends inside a
     * block: nv2gc_open_scope calls nv2gc_close_scope BEFORE it
     * overwrites `seen`, so the FIRST block header is exactly where the
     * top-level section's completeness was decided. A file that opens a
     * [validator] block without having named all five economic keys
     * therefore refuses at that header, and a file that names no keys at
     * all and opens no blocks refuses right here. Both paths run through
     * the one mask, so there is no second place for the rule to drift. */
    if (nv2gc_close_scope(&st, lineno) != 0) goto out;

    /* ── the three forced constants ───────────────────────────────────
     * Set here and NOT settable from the file. Each has exactly one
     * legal value and the builder refuses every other one — the version
     * at nodus_witness_v2_gen.c:467-472, the claim window at :544-553 —
     * so this is not a hidden default: there is no second value a
     * default could be masking. Naming any of them in the file is an
     * unknown key, which is how the operator learns they are not knobs.
     */
    st.cfg->config_version     = NODUS_V2_GEN_CONFIG_VERSION;
    st.cfg->claim_start_height = 0;
    st.cfg->claim_end_height   = UINT64_MAX;

    /* AT LEAST ONE [allocation] — refused HERE, not left to the builder.
     *
     * gen_plan_build does reject n_allocs == 0, so nothing unsafe could
     * reach a chain either way. But the two refusals are not equally
     * useful to the person who has to fix the file: this one can say
     * "your config file has no [allocation] block", while the builder's
     * arrives after the derivation has begun and names a struct field.
     * A gap found by a coverage review of the test file, not by a
     * failure — the parser accepted it and nothing downstream cared,
     * which is exactly the shape that survives review. */
    if (st.n_allocs == 0) {
        fprintf(stderr,
                "genesis config: not one [allocation] block in the whole "
                "file. A chain with no distribution has nothing claimable "
                "and is refused — add at least one, or this is the wrong "
                "config file.\n");
        goto out;
    }

    st.cfg->n_allocs = st.n_allocs;
    st.cfg->allocs   = st.allocs;      /* ownership moves to the config */
    st.allocs = NULL;

    *out_cfg = st.cfg;
    st.cfg = NULL;
    rc = 0;

out:
    free(line);
    free(st.allocs);
    free(st.cfg);
    fclose(fp);
    return rc;
}
