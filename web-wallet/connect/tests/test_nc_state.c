/* P7 stage 1 — the state schema v2 codec against the shared vectors,
 * natively (docs/plans/2026-10-13-connect-core-p7-state-design.md rev 2,
 * "Test plan"; connect/nc_state.h).
 *
 * WHAT IT PROVES: for every vector of every .json file of
 * test/vectors/connect-state/ (hand-specified; the same files
 * test/connect-state-wasm.test.js runs through the wasm module):
 *   - kind "project": nc_state_project_json(state, map) returns byte for
 *     byte the result the vector names — {"status":"ok","nextSeq",
 *     "header","records":[{"id","fp","json"}]} with the header and record
 *     TEXTS exactly as given, or {"status":"invalid","reason"};
 *   - a "project" vector with "v1" (the round trip, design §2.1): loading
 *     the expected records gives {"status":"ok","state":<v1>,"map":{fp:
 *     id, … in record order}}, and projecting that v1 with that map gives
 *     the same records again (v1 -> v2 -> v1 is the identity on the
 *     canonical form, and the canonical form is a fixed point);
 *   - kind "load": nc_state_load_json({header, records}) returns
 *     {"status":"ok","state","map"} or {"status":"damaged","reason"} as
 *     named (fail closed, design §2.5).
 * Texts are compared as bytes; the expected result is assembled from the
 * vector's texts with the JSON.stringify string form (nc_js_write_string),
 * which is how the node test assembles it too.
 * A vector may carry "fills": { "<token>": [["<fp>", <count>], …] } — every
 * JSON string "<token>" (quotes included) in its texts stands for a JSON
 * array of those fps, each repeated <count> times, in that order (the
 * removed-cap vector needs 1,001 entries). The short tokens of the files
 * (#A# = 128 'a', #c7# = c00000000000000000007, … — project.json "doc")
 * are expanded in the whole file text before it is parsed.
 * Then direct cases: NULL arguments, a non-JSON input, a load wrapper that
 * is not one, nesting deeper than the parser takes.
 *
 * WHAT IT REQUIRES: the vector files (none = FAIL, never a skip). Built with
 * -fsanitize=address,undefined (connect/tests/CMakeLists.txt), so a memory
 * error or UB in the codec aborts the run.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the vectors are hand-specified from the design text and
 * store.js / messages.js; it proves C == the vectors, not that the vectors
 * are the design. The checkState parity half (that every "checkState"
 * refusal is a refusal of the real JavaScript checkState, and every other
 * vector passes it) is in the node test, which runs store.js itself.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_state.h"
#include "nc_jsjson.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VECTORS_DIR
#error "VECTORS_DIR (test/vectors/connect-state) is set by CMakeLists.txt"
#endif

static int g_fail, g_pass;

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

static const nc_jv_t *jstrv(const nc_jv_t *o, const char *key) {
    const nc_jv_t *v = nc_jv_get(o, key);
    return v && v->kind == NC_JV_STR ? v : NULL;
}

/* The tokens of project.json's "doc" entry: #1# #A#..#E# #V# #W# (128
 * characters), #SA# #SB# #SC# #G# (64), #<c|p|v|g><digits># (a record id).
 * They expand to hex and digits only, so the whole vector FILE is expanded
 * before it is parsed (the node runner does the same).
 * `s` with every token replaced; malloc'd, NUL-terminated. */
static char *tokens(const char *s, size_t n, size_t *out_len) {
    static const struct { const char *tok; char c; size_t len; } T[] = {
        { "1", '1', 128 }, { "A", 'a', 128 }, { "B", 'b', 128 }, { "C", 'c', 128 },
        { "D", 'd', 128 }, { "E", 'e', 128 }, { "V", '9', 128 }, { "W", '8', 128 },
        { "SA", 'a', 64 }, { "SB", 'b', 64 }, { "SC", 'c', 64 }, { "G", 'f', 64 },
    };
    nc_sb_t b;
    nc_sb_init(&b);
    size_t i = 0;
    while (i < n) {
        const char *end = s[i] == '#' ? memchr(s + i + 1, '#', n - i - 1) : NULL;
        size_t k = end ? (size_t)(end - (s + i + 1)) : 0;
        const char *body = s + i + 1;
        int done = 0;
        for (size_t t = 0; end && !done && t < sizeof(T) / sizeof(T[0]); t++) {
            if (k == strlen(T[t].tok) && memcmp(body, T[t].tok, k) == 0) {
                for (size_t c = 0; c < T[t].len; c++) nc_sb_putc(&b, T[t].c);
                done = 1;
            }
        }
        if (end && !done && k >= 2 && k <= 21 && strchr("cpvg", body[0])) {
            int digits = 1;
            for (size_t c = 1; c < k; c++) if (body[c] < '0' || body[c] > '9') digits = 0;
            if (digits) {
                nc_sb_putc(&b, body[0]);
                for (size_t c = k - 1; c < 20; c++) nc_sb_putc(&b, '0');
                nc_sb_put(&b, body + 1, k - 1);
                done = 1;
            }
        }
        /* as the node runner's /#([^#]{1,21})#/g: a span of 1..21 that is
         * no token is kept as it is, its closing '#' included */
        if (!done && end && k >= 1 && k <= 21) { nc_sb_put(&b, s + i, k + 2); done = 1; }
        if (done) i += k + 2;
        else nc_sb_putc(&b, s[i++]);
    }
    return nc_sb_take(&b, out_len);
}

/* `text` with every "<token>" of `fills` replaced (see the header);
 * malloc'd, NUL-terminated. NULL when out of memory or fills is malformed. */
static char *expand(const char *s, size_t n, const nc_jv_t *fills, size_t *out_len) {
    nc_sb_t b;
    nc_sb_init(&b);
    size_t i = 0;
    while (i < n) {
        int done = 0;
        for (size_t f = 0; fills && f < fills->len && !done; f++) {
            nc_sb_t tok;
            nc_sb_init(&tok);
            nc_js_write_string(&tok, fills->k[f], fills->kn[f]);
            if (!tok.oom && tok.len <= n - i && memcmp(s + i, tok.p, tok.len) == 0) {
                const nc_jv_t *list = fills->v[f];
                if (list->kind != NC_JV_ARR) { nc_sb_free(&tok); nc_sb_free(&b); return NULL; }
                nc_sb_putc(&b, '[');
                int first = 1;
                for (size_t j = 0; j < list->len; j++) {
                    const nc_jv_t *pair = list->v[j];
                    if (pair->kind != NC_JV_ARR || pair->len != 2 || pair->v[0]->kind != NC_JV_STR ||
                        pair->v[1]->kind != NC_JV_NUM || pair->v[1]->num < 0) {
                        nc_sb_free(&tok); nc_sb_free(&b); return NULL;
                    }
                    for (size_t c = 0; c < (size_t)pair->v[1]->num; c++) {
                        if (!first) nc_sb_putc(&b, ',');
                        first = 0;
                        nc_js_write_string(&b, pair->v[0]->s, pair->v[0]->n);
                    }
                }
                nc_sb_putc(&b, ']');
                i += tok.len;
                done = 1;
            }
            nc_sb_free(&tok);
        }
        if (!done) nc_sb_putc(&b, s[i++]);
    }
    return nc_sb_take(&b, out_len);
}

static char *xv(const nc_jv_t *v, const nc_jv_t *fills, size_t *len) {
    return expand(v->s, v->n, fills, len);
}

static void compare(const char *where, const char *got, size_t got_len, const char *want, size_t want_len) {
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("FAIL %s\n  got:    %s\n  expect: %s\n", where, got, want);
        g_fail++;
    } else {
        g_pass++;
    }
}

/* {"status":"<s>","reason":"<r>"} */
static char *refusal(const char *status, const nc_jv_t *reason, size_t *len) {
    nc_sb_t b;
    nc_sb_init(&b);
    nc_sb_puts(&b, "{\"status\":");
    nc_js_write_string(&b, status, strlen(status));
    nc_sb_puts(&b, ",\"reason\":");
    nc_js_write_string(&b, reason->s, reason->n);
    nc_sb_putc(&b, '}');
    return nc_sb_take(&b, len);
}

/* One "project" vector; returns 1 when it ran. */
static int run_project(const char *where, const nc_jv_t *v) {
    const nc_jv_t *fills = nc_jv_get(v, "fills");
    const nc_jv_t *st = jstrv(v, "state"), *mp = jstrv(v, "map"), *ex = nc_jv_get(v, "expect");
    const nc_jv_t *status = jstrv(ex, "status");
    if (!st || !mp || !status) { printf("FAIL %s: malformed vector\n", where); g_fail++; return 0; }
    size_t sl, el = 0;
    char *state = xv(st, fills, &sl), *want = NULL;
    nc_sb_t lw, mapb;
    nc_sb_init(&lw);
    nc_sb_init(&mapb);
    char *v1 = NULL;
    size_t v1l = 0;
    if (nc_js_str_eq(status->s, status->n, "ok")) {
        const nc_jv_t *next = jstrv(ex, "nextSeq"), *header = jstrv(ex, "header"), *recs = nc_jv_get(ex, "records");
        if (!next || !header || !recs || recs->kind != NC_JV_ARR) { printf("FAIL %s: malformed expect\n", where); g_fail++; free(state); return 0; }
        size_t hl;
        char *h = xv(header, fills, &hl);
        nc_sb_t b;
        nc_sb_init(&b);
        nc_sb_puts(&b, "{\"status\":\"ok\",\"nextSeq\":");
        nc_js_write_string(&b, next->s, next->n);
        nc_sb_puts(&b, ",\"header\":");
        nc_js_write_string(&b, h, hl);
        nc_sb_puts(&b, ",\"records\":[");
        /* the load input and the map for the round trip, from the same texts */
        nc_sb_puts(&lw, "{\"header\":");
        nc_js_write_string(&lw, h, hl);
        nc_sb_puts(&lw, ",\"records\":[");
        nc_sb_putc(&mapb, '{');
        for (size_t i = 0; i < recs->len; i++) {
            const nc_jv_t *r = recs->v[i];
            const nc_jv_t *id = jstrv(r, "id"), *fp = jstrv(r, "fp"), *js = jstrv(r, "json");
            if (!id || !fp || !js) { printf("FAIL %s: malformed record %zu\n", where, i); g_fail++; continue; }
            size_t jl;
            char *j = xv(js, fills, &jl);
            if (i) { nc_sb_putc(&b, ','); nc_sb_putc(&lw, ','); nc_sb_putc(&mapb, ','); }
            nc_sb_puts(&b, "{\"id\":");
            nc_js_write_string(&b, id->s, id->n);
            nc_sb_puts(&b, ",\"fp\":");
            nc_js_write_string(&b, fp->s, fp->n);
            nc_sb_puts(&b, ",\"json\":");
            nc_js_write_string(&b, j, jl);
            nc_sb_putc(&b, '}');
            nc_sb_puts(&lw, "{\"id\":");
            nc_js_write_string(&lw, id->s, id->n);
            nc_sb_puts(&lw, ",\"json\":");
            nc_js_write_string(&lw, j, jl);
            nc_sb_putc(&lw, '}');
            nc_js_write_string(&mapb, fp->s, fp->n);
            nc_sb_putc(&mapb, ':');
            nc_js_write_string(&mapb, id->s, id->n);
            free(j);
        }
        nc_sb_puts(&b, "]}");
        nc_sb_puts(&lw, "]}");
        nc_sb_putc(&mapb, '}');
        free(h);
        want = nc_sb_take(&b, &el);
        const nc_jv_t *v1v = jstrv(ex, "v1");
        if (v1v) v1 = xv(v1v, fills, &v1l);
    } else {
        const nc_jv_t *reason = jstrv(ex, "reason");
        if (!reason) { printf("FAIL %s: malformed expect\n", where); g_fail++; free(state); return 0; }
        want = refusal("invalid", reason, &el);
    }
    char *got = NULL;
    size_t gl = 0;
    if (!state || !want || nc_state_project_json(state, sl, mp->s, mp->n, &got, &gl) != 0 || !got) {
        printf("FAIL %s: no result\n", where);
        g_fail++;
    } else {
        compare(where, got, gl, want, el);
    }
    free(got);
    if (v1 && !lw.oom && !mapb.oom) {
        /* the round trip: load gives v1 and the map ... */
        nc_sb_t lx;
        nc_sb_init(&lx);
        nc_sb_puts(&lx, "{\"status\":\"ok\",\"state\":");
        nc_sb_put(&lx, v1, v1l);
        nc_sb_puts(&lx, ",\"map\":");
        nc_sb_put(&lx, mapb.p, mapb.len);
        nc_sb_putc(&lx, '}');
        char *lwant = NULL;
        size_t lwl = 0;
        lwant = nc_sb_take(&lx, &lwl);
        char where2[600];
        snprintf(where2, sizeof(where2), "%s (round trip: load)", where);
        got = NULL;
        if (!lwant || nc_state_load_json(lw.p, lw.len, &got, &gl) != 0 || !got) { printf("FAIL %s: no result\n", where2); g_fail++; }
        else compare(where2, got, gl, lwant, lwl);
        free(got);
        free(lwant);
        /* ... and v1 with that map projects to the same records */
        snprintf(where2, sizeof(where2), "%s (round trip: project again)", where);
        got = NULL;
        if (nc_state_project_json(v1, v1l, mapb.p, mapb.len, &got, &gl) != 0 || !got) { printf("FAIL %s: no result\n", where2); g_fail++; }
        else compare(where2, got, gl, want, el);
        free(got);
    }
    free(v1);
    free(state);
    free(want);
    nc_sb_free(&lw);
    nc_sb_free(&mapb);
    return 1;
}

/* One "load" vector. */
static int run_load(const char *where, const nc_jv_t *v) {
    const nc_jv_t *fills = nc_jv_get(v, "fills");
    const nc_jv_t *header = jstrv(v, "header"), *recs = nc_jv_get(v, "records"), *ex = nc_jv_get(v, "expect");
    const nc_jv_t *status = jstrv(ex, "status");
    if (!header || !recs || recs->kind != NC_JV_ARR || !status) { printf("FAIL %s: malformed vector\n", where); g_fail++; return 0; }
    nc_sb_t in;
    nc_sb_init(&in);
    size_t hl;
    char *h = xv(header, fills, &hl);
    nc_sb_puts(&in, "{\"header\":");
    if (h) nc_js_write_string(&in, h, hl);
    free(h);
    nc_sb_puts(&in, ",\"records\":[");
    for (size_t i = 0; i < recs->len; i++) {
        const nc_jv_t *id = jstrv(recs->v[i], "id"), *js = jstrv(recs->v[i], "json");
        if (!id || !js) { printf("FAIL %s: malformed record %zu\n", where, i); g_fail++; nc_sb_free(&in); return 0; }
        size_t jl;
        char *j = xv(js, fills, &jl);
        if (i) nc_sb_putc(&in, ',');
        nc_sb_puts(&in, "{\"id\":");
        nc_js_write_string(&in, id->s, id->n);
        nc_sb_puts(&in, ",\"json\":");
        if (j) nc_js_write_string(&in, j, jl);
        nc_sb_putc(&in, '}');
        free(j);
    }
    nc_sb_puts(&in, "]}");
    char *want = NULL;
    size_t el = 0;
    if (nc_js_str_eq(status->s, status->n, "ok")) {
        const nc_jv_t *st = jstrv(ex, "state"), *map = nc_jv_get(ex, "map");
        if (!st || !map || map->kind != NC_JV_OBJ) { printf("FAIL %s: malformed expect\n", where); g_fail++; nc_sb_free(&in); return 0; }
        size_t sl;
        char *s = xv(st, fills, &sl);
        nc_sb_t b;
        nc_sb_init(&b);
        nc_sb_puts(&b, "{\"status\":\"ok\",\"state\":");
        if (s) nc_sb_put(&b, s, sl);
        nc_sb_puts(&b, ",\"map\":{");
        for (size_t i = 0; i < map->len; i++) {
            if (i) nc_sb_putc(&b, ',');
            nc_js_write_string(&b, map->k[i], map->kn[i]);
            nc_sb_putc(&b, ':');
            if (map->v[i]->kind == NC_JV_STR) nc_js_write_string(&b, map->v[i]->s, map->v[i]->n);
        }
        nc_sb_puts(&b, "}}");
        free(s);
        want = nc_sb_take(&b, &el);
    } else {
        const nc_jv_t *reason = jstrv(ex, "reason");
        if (!reason) { printf("FAIL %s: malformed expect\n", where); g_fail++; nc_sb_free(&in); return 0; }
        want = refusal("damaged", reason, &el);
    }
    char *got = NULL;
    size_t gl = 0;
    if (in.oom || !want || nc_state_load_json(in.p, in.len, &got, &gl) != 0 || !got) {
        printf("FAIL %s: no result\n", where);
        g_fail++;
    } else {
        compare(where, got, gl, want, el);
    }
    free(got);
    free(want);
    nc_sb_free(&in);
    return 1;
}

static int run_vector_file(const char *path) {
    size_t len;
    char *raw = read_file(path, &len);
    char *text = raw ? tokens(raw, len, &len) : NULL;
    free(raw);
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
    int ran = 0;
    for (size_t i = 0; i < arr->len; i++) {
        const nc_jv_t *v = arr->v[i];
        const nc_jv_t *kind = jstrv(v, "kind"), *name = jstrv(v, "name");
        char where[512];
        snprintf(where, sizeof(where), "%s[%zu] %s", path, i, name ? name->s : "?");
        if (kind && nc_js_str_eq(kind->s, kind->n, "project")) ran += run_project(where, v);
        else if (kind && nc_js_str_eq(kind->s, kind->n, "load")) ran += run_load(where, v);
        else { printf("FAIL %s: unknown kind\n", where); g_fail++; }
    }
    nc_jv_free(arr);
    return ran;
}

static void run_vectors(void) {
    DIR *d = opendir(VECTORS_DIR);
    if (!d) {
        printf("FAIL no vector directory %s\n", VECTORS_DIR);
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

static void expect_text(const char *what, int rc, char *got, const char *want) {
    if (rc != 0 || !got) { printf("FAIL %s: no result\n", what); g_fail++; free(got); return; }
    compare(what, got, strlen(got), want, strlen(want));
    free(got);
}

static void direct_cases(void) {
    char *got = NULL;
    size_t gl = 0;
    if (nc_state_project_json(NULL, 0, "{}", 2, &got, &gl) != -1 || got) { printf("FAIL project NULL state\n"); g_fail++; } else g_pass++;
    if (nc_state_project_json("{}", 2, NULL, 0, &got, &gl) != -1 || got) { printf("FAIL project NULL map\n"); g_fail++; } else g_pass++;
    if (nc_state_project_json("{}", 2, "{}", 2, NULL, &gl) != -1) { printf("FAIL project NULL out\n"); g_fail++; } else g_pass++;
    if (nc_state_load_json(NULL, 0, &got, &gl) != -1 || got) { printf("FAIL load NULL\n"); g_fail++; } else g_pass++;

    got = NULL;
    expect_text("project: empty input", nc_state_project_json("", 0, "{}", 2, &got, &gl), got,
                "{\"status\":\"invalid\",\"reason\":\"json\"}");
    got = NULL;
    expect_text("project: trailing junk", nc_state_project_json("{}x", 3, "{}", 2, &got, &gl), got,
                "{\"status\":\"invalid\",\"reason\":\"json\"}");
    got = NULL;
    expect_text("project: embedded NUL", nc_state_project_json("{}\0", 3, "{}", 2, &got, &gl), got,
                "{\"status\":\"invalid\",\"reason\":\"json\"}");
    got = NULL;
    expect_text("load: empty input", nc_state_load_json("", 0, &got, &gl), got,
                "{\"status\":\"damaged\",\"reason\":\"input\"}");
    got = NULL;
    expect_text("load: an array", nc_state_load_json("[]", 2, &got, &gl), got,
                "{\"status\":\"damaged\",\"reason\":\"input\"}");
    got = NULL;
    static const char NOT_ARRAY[] = "{\"header\":\"{}\",\"records\":{}}";
    expect_text("load: records not an array", nc_state_load_json(NOT_ARRAY, strlen(NOT_ARRAY), &got, &gl), got,
                "{\"status\":\"damaged\",\"reason\":\"input\"}");
    got = NULL;
    static const char BAD_HEADER[] = "{\"header\":\"{\",\"records\":[]}";
    expect_text("load: header not JSON", nc_state_load_json(BAD_HEADER, strlen(BAD_HEADER), &got, &gl), got,
                "{\"status\":\"damaged\",\"reason\":\"header\"}");

    /* nesting past NC_JS_MAX_NEST in the state: refused as JSON, no crash */
    size_t depth = NC_JS_MAX_NEST + 8, n = 2 * depth;
    char *deep = malloc(n);
    if (!deep) { printf("FAIL out of memory\n"); g_fail++; return; }
    memset(deep, '[', depth);
    memset(deep + depth, ']', depth);
    got = NULL;
    expect_text("project: deep nesting", nc_state_project_json(deep, n, "{}", 2, &got, &gl), got,
                "{\"status\":\"invalid\",\"reason\":\"json\"}");
    free(deep);
}

int main(void) {
    run_vectors();
    direct_cases();
    printf("test_nc_state: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
