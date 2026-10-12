/* P1 rules — the shared vectors through the C dispatcher, natively
 * (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2, §2).
 *
 * WHAT IT PROVES: for every vector in every .json file of
 * test/vectors/connect-rules/ (payload.json generated FROM the JavaScript
 * of src/connect/ui/actions.js, rules.json FROM src/connect/ui/text.js and
 * src/connect/core.js acceptanceMayAutoApprove, both by
 * test/tools/gen-connect-rule-vectors.mjs), nc_rule_call(rule, args)
 * returns byte-for-byte the JSON the JS function's result encodes to
 * (nc_rules_json.h). A vector is
 *   { "rule": "<name>", "args": "<JSON text>", "expect": "<JSON text>",
 *     "gap": "<reason>" (optional) }
 * args and expect are JSON TEXTS (strings), so the C side receives the
 * exact bytes JavaScript produced and is compared with the exact bytes it
 * expects (a re-serialised value could hide a difference on both sides
 * at once). A vector marked "gap" is a behaviour the C port knowingly does
 * not reproduce (today: full-Unicode toLowerCase); it is run and its
 * mismatch is a FAILURE like any other — the mark only names the reason.
 * Then direct malformed-input cases: embedded NUL, trailing junk, depth,
 * over the cap, invalid UTF-8, JSON.parse-invalid numbers and literals,
 * what JSON.parse keeps that a C JSON library would not (lone surrogates,
 * integer literals of any size, NUL and repeats in keys), unknown rule,
 * NULL arguments, and Number::toString cases — no crash, the documented
 * result. Then direct P1a cases (p1a_cases): the argument contract of the
 * text.js rules (nested records, non-scalar Set elements, a non-flat
 * dmSync, an array state, a bad state.removed / map), and how an echoed
 * JS object is written back — array-index keys first, a repeated key at
 * its first place with its last value, an own "__proto__" key, an
 * undefined field left out, a deleted repeated key (each checked against
 * node 22 when written) — plus BigInt of a 2^64 double, u64 edges and
 * V8's sort error order.
 *
 * WHAT IT REQUIRES: the vector files (the ORCHESTRATOR runs the generator;
 * no vector file = FAIL, never a skip). Built with
 * -fsanitize=address,undefined (connect/tests/CMakeLists.txt), so a
 * memory error or UB in the rules aborts the run.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: it proves C == the vectors, and the vectors == today's
 * JS only when they were generated from the tree under test; a stale
 * vector file proves agreement with an older JS.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_rules_json.h"
#include "nc_jsjson.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VECTORS_DIR
#error "VECTORS_DIR (test/vectors/connect-rules) is set by CMakeLists.txt"
#endif

static int g_fail, g_pass;

static void check(const char *what, const char *name, const char *args, size_t len, const char *want) {
    char *got = NULL;
    if (nc_rule_call(name, args, len, &got) != 0 || !got) {
        printf("FAIL %s: nc_rule_call returned no result\n", what);
        g_fail++;
        return;
    }
    if (strcmp(got, want) != 0) {
        printf("FAIL %s\n  got:    %s\n  expect: %s\n", what, got, want);
        g_fail++;
    } else {
        g_pass++;
    }
    free(got);
}

static void checks(const char *what, const char *name, const char *args, const char *want) {
    check(what, name, args, strlen(args), want);
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n + 65536 + 1 > cap) {
            cap = cap ? cap * 2 : 1 << 20;
            char *q = realloc(buf, cap);
            if (!q) { free(buf); fclose(f); return NULL; }
            buf = q;
        }
        size_t r = fread(buf + n, 1, 65536, f);
        n += r;
        if (r < 65536) break;
    }
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return buf;
}

static int cmp_names(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static const char *jstr(const nc_jv_t *o, const char *key, size_t *n) {
    const nc_jv_t *v = nc_jv_get(o, key);
    if (!v || v->kind != NC_JV_STR) return NULL;
    if (n) *n = v->n;
    return v->s;
}

static int run_vector_file(const char *path) {
    size_t len;
    char *text = read_file(path, &len);
    if (!text) { printf("FAIL cannot read %s\n", path); g_fail++; return 0; }
    nc_jv_t *arr = NULL;
    nc_js_parse_t pr = nc_js_parse(text, len, &arr);
    free(text);
    if (pr != NC_JS_OK || arr->kind != NC_JV_ARR) {
        printf("FAIL %s: not a JSON array of vectors (parse %d)\n", path, (int)pr);
        g_fail++;
        nc_jv_free(arr);
        return 0;
    }
    size_t nv = arr->len;
    int ran = 0;
    for (size_t i = 0; i < nv; i++) {
        const nc_jv_t *v = arr->v[i];
        size_t alen = 0, elen = 0;
        const char *rule = v ? jstr(v, "rule", NULL) : NULL;
        const char *args = v ? jstr(v, "args", &alen) : NULL;
        const char *expect = v ? jstr(v, "expect", &elen) : NULL;
        const char *gap = v ? jstr(v, "gap", NULL) : NULL;
        if (!rule || !args || !expect) {
            printf("FAIL %s[%zu]: malformed vector\n", path, i);
            g_fail++;
            continue;
        }
        char *got = NULL;
        ran++;
        if (nc_rule_call(rule, args, alen, &got) != 0 || !got) {
            printf("FAIL %s[%zu] %s: no result\n", path, i, rule);
            g_fail++;
            continue;
        }
        if (strlen(got) != elen || memcmp(got, expect, elen) != 0) {
            printf("FAIL %s[%zu] %s%s%s%s\n  args:   %s\n  got:    %s\n  expect: %s\n",
                   path, i, rule, gap ? " (known gap: " : "", gap ? gap : "", gap ? ")" : "",
                   args, got, expect);
            g_fail++;
        } else {
            g_pass++;
        }
        free(got);
    }
    nc_jv_free(arr);
    return ran;
}

static void run_vectors(void) {
    DIR *d = opendir(VECTORS_DIR);
    if (!d) {
        printf("FAIL no vector directory %s (run test/tools/gen-connect-rule-vectors.mjs)\n", VECTORS_DIR);
        g_fail++;
        return;
    }
    char *names[256];
    size_t nn = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && nn < 256) {
        size_t l = strlen(e->d_name);
        if (l > 5 && strcmp(e->d_name + l - 5, ".json") == 0) names[nn++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, nn, sizeof(names[0]), cmp_names);
    int total = 0;
    for (size_t i = 0; i < nn; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", VECTORS_DIR, names[i]);
        int ran = run_vector_file(path);
        printf("%s: %d vectors\n", names[i], ran);
        total += ran;
        free(names[i]);
    }
    if (total == 0) {
        printf("FAIL no vectors ran (an empty run is not a pass)\n");
        g_fail++;
    }
}

static void number_cases(void) {
    static const struct { double d; const char *s; } C[] = {
        { 0.0, "0" }, { -0.0, "0" }, { 1.0, "1" }, { -1.5, "-1.5" }, { 0.1, "0.1" },
        { 0.1 + 0.2, "0.30000000000000004" }, { 123.456, "123.456" },
        { 1e20, "100000000000000000000" }, { 1e21, "1e+21" }, { 1e23, "1e+23" },
        { 18446744073709551616.0, "18446744073709552000" },
        { 9007199254740993.0, "9007199254740992" },
        { 0.000001, "0.000001" }, { 1e-7, "1e-7" }, { 1.2345e-10, "1.2345e-10" },
        { 5e-324, "5e-324" }, { 1.7976931348623157e308, "1.7976931348623157e+308" },
    };
    for (size_t i = 0; i < sizeof(C) / sizeof(C[0]); i++) {
        char t[NC_JS_NUMSTR_MAX];
        nc_js_number_to_string(C[i].d, t);
        if (strcmp(t, C[i].s) != 0) {
            printf("FAIL Number::toString: got %s, expect %s\n", t, C[i].s);
            g_fail++;
        } else {
            g_pass++;
        }
    }
}

#define E_JSON  "{\"error\":\"nc_rule: invalid JSON\"}"
#define E_BAD   "{\"error\":\"nc_rule: bad arguments\"}"

static void malformed_cases(void) {
    /* embedded NUL: a raw NUL inside a JSON string is a control character
     * (JSON.parse throws); the length, not strlen, bounds the input */
    static const char nul_in[] = "{\"text\":\"a\0b\"}";
    check("raw NUL in a string", "parseReply", nul_in, sizeof(nul_in) - 1, E_JSON);
    static const char nul_after[] = "{\"text\":\"ab\"}\0";
    check("NUL after the value", "parseReply", nul_after, sizeof(nul_after) - 1, E_JSON);
    /* an escaped NUL is data: parseReply does not cut at NUL */
    checks("escaped NUL kept by parseReply", "parseReply",
           "{\"text\":\"\\u21a9 Re: a\\u0000b\\n> q\\nt\\u0000u\"}",
           "{\"sender\":\"a\\u0000b\",\"quoted\":\"q\",\"text\":\"t\\u0000u\"}");

    checks("trailing junk", "parseReply", "{\"text\":\"x\"} x", E_JSON);
    checks("trailing comma", "parseReply", "{\"text\":\"x\",}", E_JSON);
    checks("comment", "parseReply", "{\"text\":\"x\"}/**/", E_JSON);
    checks("trailing whitespace is JSON", "parseReply", "{\"text\":\"x\"} \t\r\n", "null");
    checks("vertical tab is not JSON whitespace", "parseReply", "{\"text\":\"x\"}\v", E_JSON);
    checks("single quotes", "parseReply", "{'text':'x'}", E_JSON);
    checks("Infinity", "parseReply", "{\"text\":Infinity}", E_JSON);
    checks("NaN", "parseReply", "{\"text\":NaN}", E_JSON);
    checks("1.", "parseReply", "{\"text\":1.}", E_JSON);
    checks("01", "parseReply", "{\"text\":01}", E_JSON);
    checks("01.5", "parseReply", "{\"text\":01.5}", E_JSON);
    checks(".5", "parseReply", "{\"text\":.5}", E_JSON);
    checks("1e", "parseReply", "{\"text\":1e}", E_JSON);
    checks("-", "parseReply", "{\"text\":-}", E_JSON);
    checks("raw tab in a string", "parseReply", "{\"text\":\"a\tb\"}", E_JSON);
    checks("bad escape", "parseReply", "{\"text\":\"\\x41\"}", E_JSON);
    checks("short \\u", "parseReply", "{\"text\":\"\\u12\"}", E_JSON);
    checks("unterminated", "parseReply", "{\"text\":\"abc", E_JSON);
    checks("empty input", "parseReply", "", E_JSON);

    /* invalid UTF-8 (a JS string cannot hold it): refused */
    checks("bad continuation", "parseReply", "{\"text\":\"\xC3\x28\"}", E_JSON);
    checks("overlong", "parseReply", "{\"text\":\"\xC0\xAF\"}", E_JSON);
    checks("encoded surrogate", "parseReply", "{\"text\":\"\xED\xA0\x80\"}", E_JSON);
    checks("over U+10FFFF", "parseReply", "{\"text\":\"\xF4\x90\x80\x80\"}", E_JSON);
    checks("truncated sequence", "parseReply", "{\"text\":\"\xE2\x82\"}", E_JSON);
    checks("byte outside a string", "parseReply", "{\"text\":\"x\"}\xC3\xA9", E_JSON);

    /* what JSON.parse keeps (and a C JSON library typically would not):
     * echoed through buildReply ("↩ Re: a\n> <quoted>\n<text>") */
#define RP "\"\xE2\x86\xA9 Re: a\\n> "
    checks("lone high surrogate kept", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"\\ud800\",\"text\":\"b\"}", RP "\\ud800\\nb\"");
    checks("lone low surrogate kept", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"\\udc00x\",\"text\":\"b\"}", RP "\\udc00x\\nb\"");
    checks("high + non-low", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"\\ud800\\u0041\",\"text\":\"b\"}", RP "\\ud800A\\nb\"");
    checks("low + high stay two lone units", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"\\ude00\\ud83d\",\"text\":\"b\"}", RP "\\ude00\\ud83d\\nb\"");
    checks("an escaped pair joins", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"\\ud83d\\ude00\",\"text\":\"b\"}", RP "\xF0\x9F\x98\x80\\nb\"");
    checks("2^64 literal is the double", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":18446744073709551616}", RP "q\\n18446744073709552000\"");
    checks("1e20 literal", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":100000000000000000000}", RP "q\\n100000000000000000000\"");
    checks("below int64 min", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":-9223372036854775809}", RP "q\\n-9223372036854776000\"");
    checks("1e400 is Infinity", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":1e400}", RP "q\\nInfinity\"");
    checks("-0 prints 0", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":-0}", RP "q\\n0\"");
    checks("NUL in a key is another key", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"te\\u0000xt\":\"z\"}", RP "q\\nundefined\"");
    checks("NUL key next to the real one", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\\u0000\":\"z\",\"text\":\"t\"}", RP "q\\nt\"");
    checks("a repeated key keeps the last value", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"text\":\"t1\",\"text\":\"t2\"}", RP "q\\nt2\"");
    checks("lone surrogate in a key", "buildReply",
           "{\"senderLabel\":\"a\",\"quoted\":\"q\",\"\\ud800\":1,\"text\":\"t\"}", RP "q\\nt\"");
    checks("a dead compound value is not a field", "messageHash",
           "{\"m\":{\"dir\":{\"x\":1},\"dir\":\"local\"},\"ownFp\":\"a\"}", "null");
    checks("a live compound value is", "messageHash",
           "{\"m\":{\"dir\":\"local\",\"dir\":{\"x\":1}},\"ownFp\":\"a\"}", E_BAD);
#undef RP
    checks("uint64 max is a number", "parseReply", "{\"text\":18446744073709551615}", "null");
    checks("int64 min is a number", "parseReply", "{\"text\":-9223372036854775808}", "null");
    /* the same forms INSIDE a payload */
    checks("payload lone surrogate", "parseTransfer",
           "{\"text\":\"{\\\"type\\\":\\\"token_transfer\\\",\\\"recipientName\\\":\\\"\\\\ud800\\\"}\"}",
           "{\"chain\":\"\",\"amount\":\"\",\"token\":\"\",\"wire\":\"\",\"to\":\"\",\"name\":\"\\ud800\"}");
    checks("payload NUL key beside type", "parseDelete",
           "{\"text\":\"{\\\"type\\\\u0000\\\":\\\"x\\\",\\\"type\\\":\\\"delete\\\"}\"}",
           "{\"action\":0,\"hashes\":[]}");
    checks("payload action 1e20 literal", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\",\\\"action\\\":100000000000000000000}\"}",
           "{\"action\":100000000000000000000,\"hashes\":[]}");
    checks("payload Infinity", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\",\\\"action\\\":Infinity}\"}", "null");
    checks("payload trailing junk", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\"}x\"}", "null");
    checks("payload cut at NUL", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\"}\\u0000junk\"}", "{\"action\":0,\"hashes\":[]}");
    checks("payload action 1e21", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\",\\\"action\\\":1e21}\"}", "{\"action\":1e+21,\"hashes\":[]}");
    checks("payload action 1.5", "parseDelete",
           "{\"text\":\"{\\\"type\\\":\\\"delete\\\",\\\"action\\\":1.5}\"}", "{\"action\":0,\"hashes\":[]}");

    /* depth */
    {
        size_t deep = NC_JS_MAX_NEST + 8;
        size_t len = 9 + 2 * deep + 1;
        char *s = malloc(len + 1);
        if (s) {
            memcpy(s, "{\"text\":", 8);
            for (size_t i = 0; i < deep; i++) s[8 + i] = '[';
            for (size_t i = 0; i < deep; i++) s[8 + deep + i] = ']';
            s[8 + 2 * deep] = '}';
            s[9 + 2 * deep] = '\0';
            check("nesting over the limit", "parseReply", s, strlen(s), "{\"error\":\"nc_rule: nesting too deep\"}");
            free(s);
        }
    }
    /* over the cap: checked before parsing (the bytes are not JSON) */
    {
        size_t len = NC_RULE_IN_MAX + 1;
        char *s = malloc(len);
        if (s) {
            memset(s, '[', len);
            check("over the cap", "parseReply", s, len, "{\"error\":\"nc_rule: input too large\"}");
            free(s);
        }
    }
    /* the boundary */
    checks("unknown rule", "noSuchRule", "{}", "{\"error\":\"nc_rule: unknown rule\"}");
    check("NULL name", NULL, "{}", 2, "{\"error\":\"nc_rule: unknown rule\"}");
    check("NULL args", "parseReply", NULL, 0, E_JSON);
    checks("args not an object", "parseReply", "[\"x\"]", E_BAD);
    checks("args a scalar", "parseReply", "\"x\"", E_BAD);
    checks("compound scalar argument", "parseReply", "{\"text\":[\"x\"]}", E_BAD);
    checks("records not an array", "reactionSummary", "{\"records\":{},\"ownFp\":\"a\"}", E_BAD);
    checks("nested record field", "messageHash", "{\"m\":{\"dir\":{\"x\":1}},\"ownFp\":\"a\"}", E_BAD);
    checks("hashes length", "deletions", "{\"records\":[{}],\"ownFp\":\"a\",\"hashes\":[]}", E_BAD);
    checks("copyCards order not canonical", "copyCards",
           "{\"cards\":[{\"state\":\"confirmed\",\"order\":\"07\"}]}", E_BAD);
    /* BigInt(e.amount) of a 0x literal: at NC_BIG_RADIX_MAX digits it is
     * converted (and is not the card's amount: mismatch); one digit more is
     * the documented refusal. opts {} : incoming and counterparty
     * undefined, so card.to (absent) === counterparty and e.peer (absent)
     * === counterparty, as in JS. */
    for (int over = 0; over <= 1; over++) {
        size_t digits = NC_BIG_RADIX_MAX + (size_t)over;
        nc_sb_t b;
        nc_sb_init(&b);
        nc_sb_puts(&b, "{\"card\":{\"chain\":\"nodus\",\"token\":\"NODUS\",\"amount\":\"1\",\"wire\":\"");
        for (int i = 0; i < 128; i++) nc_sb_putc(&b, 'e');
        nc_sb_puts(&b, "\"},\"entries\":[{\"wire\":\"");
        for (int i = 0; i < 128; i++) nc_sb_putc(&b, 'e');
        nc_sb_puts(&b, "\",\"kind\":\"spend_out\",\"token\":\"");
        for (int i = 0; i < 128; i++) nc_sb_putc(&b, '0');
        nc_sb_puts(&b, "\",\"amount\":\"0x");
        for (size_t i = 0; i < digits; i++) nc_sb_putc(&b, 'f');
        nc_sb_puts(&b, "\",\"h\":\"1\"}],\"opts\":{}}");
        if (!b.oom)
            check(over ? "BigInt radix literal over the cap" : "BigInt radix literal at the cap",
                  "transferVerdict", b.p, b.len,
                  over ? "{\"error\":\"nc_rule: unsupported BigInt literal\"}" : "{\"state\":\"mismatch\"}");
        nc_sb_free(&b);
    }
}

/* P1a direct cases. '@' in a template stands for the 128-hex ID "ab…ab". */
static char *with_fp(const char *tmpl) {
    nc_sb_t b;
    nc_sb_init(&b);
    for (const char *p = tmpl; *p; p++) {
        if (*p != '@') { nc_sb_putc(&b, *p); continue; }
        for (int i = 0; i < 64; i++) nc_sb_puts(&b, "ab");
    }
    size_t len;
    return nc_sb_take(&b, &len);
}
static void checkfp(const char *what, const char *name, const char *args_tmpl, const char *want_tmpl) {
    char *args = with_fp(args_tmpl), *want = with_fp(want_tmpl);
    if (args && want) checks(what, name, args, want);
    else { printf("FAIL %s: out of memory\n", what); g_fail++; }
    free(args);
    free(want);
}

static void p1a_cases(void) {
    /* the argument contract (nc_rules_json.h) */
    checks("record with a nested field", "pendingOutbox",
           "{\"messages\":[{\"dir\":{\"x\":1}}],\"fp\":\"a\",\"nowSeconds\":\"1\"}", E_BAD);
    checks("Set element not a scalar", "acceptanceMayAutoApprove",
           "{\"request\":{},\"pendingOutgoing\":[[\"x\"]]}", E_BAD);
    checks("Set element not a scalar (publishedBefore)", "markDelivered",
           "{\"messages\":[],\"fp\":\"a\",\"ackTs\":\"5\",\"publishedBefore\":[{\"a\":1}],\"nowSeconds\":\"1\"}", E_BAD);
    checks("dmSync a string", "contactNeedsFullSync", "{\"fp\":\"a\",\"dmSync\":\"abc\",\"now\":\"1\"}", E_BAD);
    checks("dmSync an array", "contactNeedsFullSync", "{\"fp\":\"a\",\"dmSync\":[1],\"now\":\"1\"}", E_BAD);
    checks("dmSync not flat", "contactNeedsFullSync", "{\"fp\":\"a\",\"dmSync\":{\"a\":{\"b\":1}},\"now\":\"1\"}", E_BAD);
    checks("dmSync null", "contactNeedsFullSync", "{\"fp\":\"a\",\"dmSync\":null,\"now\":\"1\"}", "true");
    checks("contactFps element not a scalar", "needFullSync", "{\"contactFps\":[{\"a\":1}],\"now\":\"1\"}", E_BAD);
    checks("state an array", "removeContact", "{\"state\":[],\"fp\":\"a\"}", E_BAD);
    checks("state.removed a string", "removeContact", "{\"state\":{\"removed\":\"x\"},\"fp\":\"a\"}", E_BAD);
    checks("state.removed with an object", "unremoveContact", "{\"state\":{\"removed\":[{}]},\"fp\":\"a\"}", E_BAD);
    checks("state.dmSync a number", "removeContact", "{\"state\":{\"dmSync\":5},\"fp\":\"a\"}", E_BAD);
    checks("state.seenOwn an array", "markOwnRecordSeen", "{\"state\":{\"seenOwn\":[]},\"kind\":\"list\"}", E_BAD);
    checks("state contact not flat", "removeContact", "{\"state\":{\"contacts\":[{\"fp\":{\"a\":1}}]},\"fp\":\"a\"}", E_BAD);
    checks("a state map with nested values is fine", "removeContact",
           "{\"state\":{\"contacts\":[],\"profileCache\":{\"a\":{\"id\":\"x\"}}},\"fp\":\"a\"}",
           "{\"result\":false,\"state\":{\"contacts\":[],\"profileCache\":{\"a\":{\"id\":\"x\"}}}}");

    /* echoed objects: { ...m, published: true } in JavaScript key order */
    checkfp("array-index keys first, an existing key keeps its place", "markPublished",
            "{\"messages\":[{\"fp\":\"@\",\"10\":\"x\",\"dir\":\"out\",\"2\":\"y\",\"seq\":\"1\",\"published\":false}],"
            "\"fp\":\"@\",\"set\":[{\"seq\":\"1\"}]}",
            "[{\"2\":\"y\",\"10\":\"x\",\"fp\":\"@\",\"dir\":\"out\",\"seq\":\"1\",\"published\":true}]");
    checkfp("4294967295 is not an array index", "markPublished",
            "{\"messages\":[{\"4294967295\":1,\"4294967294\":2,\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\"}],"
            "\"fp\":\"@\",\"set\":[{\"seq\":\"1\"}]}",
            "[{\"4294967294\":2,\"4294967295\":1,\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\",\"published\":true}]");
    checkfp("a repeated key: first place, last value", "markPublished",
            "{\"messages\":[{\"dir\":\"in\",\"fp\":\"@\",\"seq\":\"1\",\"dir\":\"out\"}],\"fp\":\"@\",\"set\":[{\"seq\":\"1\"}]}",
            "[{\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\",\"published\":true}]");
    checkfp("an own __proto__ key is echoed", "markPublished",
            "{\"messages\":[{\"__proto__\":\"p\",\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\"}],\"fp\":\"@\",\"set\":[{\"seq\":\"1\"}]}",
            "[{\"__proto__\":\"p\",\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\",\"published\":true}]");
    checkfp("delivered and deliveredAt appended in that order", "markDelivered",
            "{\"messages\":[{\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\",\"ts\":\"5\"}],\"fp\":\"@\",\"ackTs\":\"6\","
            "\"publishedBefore\":[\"1\"],\"nowSeconds\":\"9\"}",
            "[{\"dir\":\"out\",\"fp\":\"@\",\"seq\":\"1\",\"ts\":\"5\",\"delivered\":true,\"deliveredAt\":\"9\"}]");
    checkfp("an undefined field is left out", "pendingOutbox",
            "{\"messages\":[{\"seq\":\"1\",\"fp\":\"@\",\"dir\":\"out\",\"ts\":\"5\"}],\"fp\":\"@\",\"nowSeconds\":\"10\"}",
            "[{\"seq\":\"1\",\"ts\":\"5\"}]");

    /* mutators: { result, state } */
    checks("delete removes a repeated key", "removeContact",
           "{\"state\":{\"contacts\":[{\"fp\":\"k\"}],\"removed\":[],\"dmSync\":{\"k\":\"1\",\"x\":\"2\",\"k\":\"3\"},"
           "\"profileCache\":{},\"chainNames\":{}},\"fp\":\"k\"}",
           "{\"result\":true,\"state\":{\"contacts\":[],\"removed\":[\"k\"],\"dmSync\":{\"x\":\"2\"},"
           "\"profileCache\":{},\"chainNames\":{}}}");
    checks("a repeated state key: the last value at the first place", "removeContact",
           "{\"state\":{\"contacts\":[{\"fp\":\"z\"}],\"removed\":[],\"dmSync\":{},\"profileCache\":{},\"chainNames\":{},"
           "\"contacts\":[{\"fp\":\"k\"}]},\"fp\":\"k\"}",
           "{\"result\":true,\"state\":{\"contacts\":[],\"removed\":[\"k\"],\"dmSync\":{},\"profileCache\":{},\"chainNames\":{}}}");
    checks("seenOwn null replaced in place", "markOwnRecordSeen",
           "{\"state\":{\"a\":1,\"seenOwn\":null},\"kind\":\"profile\",\"nowSec\":\"5\"}",
           "{\"result\":true,\"state\":{\"a\":1,\"seenOwn\":{\"profile\":\"5\"}}}");
    checks("no state: the state is left out", "markOwnRecordSeen", "{\"kind\":\"profile\",\"nowSec\":\"5\"}",
           "{\"result\":false}");
    checkfp("a pushed contact", "mergeListedContacts",
            "{\"state\":{\"contacts\":[],\"removed\":[]},\"entries\":[{\"fp\":\"@\",\"salt\":\"s\"}],\"ownFp\":\"x\"}",
            "{\"result\":true,\"state\":{\"contacts\":[{\"fp\":\"@\",\"salt\":\"s\",\"listed\":true}],\"removed\":[]}}");
    checks("unremoveContact returns undefined", "unremoveContact",
           "{\"state\":{\"removed\":[\"a\",\"b\",\"a\"]},\"fp\":\"a\"}", "{\"state\":{\"removed\":[\"b\"]}}");

    /* numbers */
    checks("compareLocal >", "compareLocal", "{\"a\":{\"seq\":\"10\"},\"b\":{\"seq\":\"9\"}}", "1");
    checks("compareLocal =", "compareLocal", "{\"a\":{\"seq\":\"0x10\"},\"b\":{\"seq\":16}}", "0");
    checks("compareLocal <", "compareLocal", "{\"a\":{\"seq\":\"-1\"},\"b\":{\"seq\":\"99999999999999999999999\"}}", "-1");
    checks("BigInt of the double 2^64", "ackToSend",
           "{\"messages\":[{\"dir\":\"in\",\"fp\":\"f\",\"senderTs\":18446744073709551616}],\"fp\":\"f\"}",
           "\"18446744073709551616\"");
    checks("fullDays at 10^20 - 1", "fullDays", "{\"today\":\"99999999999999999999\"}",
           "[\"99999999999999999993\",\"99999999999999999994\",\"99999999999999999995\",\"99999999999999999996\","
           "\"99999999999999999997\",\"99999999999999999998\",\"99999999999999999999\",\"100000000000000000000\"]");
    checks("recentDays at 0", "recentDays", "{\"today\":\"0\"}", "[\"0\",\"1\"]");
    checks("fullDays at 3", "fullDays", "{\"today\":\"3\"}", "[\"0\",\"1\",\"2\",\"3\",\"4\"]");

    /* NUL is data in these strings */
    checkfp("HIGH-7: a message with a NUL is not the accepted one", "acceptanceMayAutoApprove",
            "{\"request\":{\"sender\":\"@\",\"acceptance\":true,\"message\":\"Contact request accepted\\u0000x\"},"
            "\"pendingOutgoing\":[\"@\"]}", "false");
    checkfp("HIGH-7: honoured with our pending request", "acceptanceMayAutoApprove",
            "{\"request\":{\"sender\":\"@\",\"acceptance\":true,\"message\":\"Contact request accepted\"},"
            "\"pendingOutgoing\":[\"@\"]}", "true");
    checks("parseContactId: NUL is not whitespace", "parseContactId", "{\"value\":\"ab\\u0000\"}",
           "{\"error\":\"That is not a valid ID. An ID is 128 characters, letters a\xE2\x80\x93" "f and digits.\"}");

    /* V8's sort: compare(a[1], a[0]) first, so a[1]'s RangeError wins */
    checkfp("sort error order", "pendingOutbox",
            "{\"messages\":[{\"seq\":\"abc\",\"fp\":\"@\",\"dir\":\"out\",\"text\":\"a\",\"ts\":\"5\"},"
            "{\"seq\":1.5,\"fp\":\"@\",\"dir\":\"out\",\"text\":\"b\",\"ts\":\"5\"}],\"fp\":\"@\",\"nowSeconds\":\"9\"}",
            "{\"error\":\"RangeError\"}");
}

int main(void) {
    run_vectors();
    number_cases();
    malformed_cases();
    p1a_cases();
    printf("test_nc_rules: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
