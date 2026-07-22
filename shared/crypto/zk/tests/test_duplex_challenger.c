/**
 * @file test_duplex_challenger.c
 * @brief Byte-match the C DuplexChallenger vs the Plonky3 oracle (P1a).
 *
 * Loads tools/vectors/duplex_challenger.json (produced by
 * `plonky3_oracle dump-duplex-challenger`, which drives the REAL
 * DuplexChallenger<Goldilocks, Poseidon2Goldilocks<8>, 8, 4> over
 * default_goldilocks_poseidon2_8() @ 82cfad73) and replays every scenario
 * step against dnac_duplex_*, asserting:
 *   - every op result (sample / sample_fp2 / sample_bits / check_witness /
 *     grind witness) matches exactly, and
 *   - the FULL post-op state (sponge_state / input_buffer / output_buffer,
 *     storage order) matches exactly.
 * This pins overwrite-absorb, eager duplex at RATE, observe-clears-output,
 * LIFO pop (first sample after duplex = state[RATE-1]), fp2 basis order,
 * sample_bits mask semantics, check_witness fail/pass/bits==0 no-op, and the
 * least-witness grind — the P1 design doc §4.2 v2 KAT surface (incl. the
 * round-2 N2/N5 vectors: ds_prefix case = prefix-then-immediate-sample).
 *
 * Additional C-side gates (no oracle needed):
 *   - DNAC_DUPLEX_DS_PREFIX limbs == LE-chunk encoding of the 25-byte Q1
 *     domain-separator string (local re-derivation) == vector's ds_prefix.
 *   - dnac_duplex_init_default == dnac_duplex_init + 4 explicit DS observes.
 *
 * Build (via Makefile):
 *   ./build/test_duplex_challenger tools/vectors/duplex_challenger.json
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../duplex_challenger.h"

/* Read the whole file into a heap buffer (NUL-terminated). */
static char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

/* Advance *pos past the next occurrence of `key` (e.g. "\"op\""). */
static bool find_key(const char *s, size_t *pos, const char *key) {
    const char *hit = strstr(s + *pos, key);
    if (!hit) return false;
    *pos = (size_t)(hit - s) + strlen(key);
    return true;
}

/* From *pos, read the next quoted string into out (cap-1 chars). */
static bool read_quoted(const char *s, size_t *pos, char *out, size_t cap) {
    const char *q = strchr(s + *pos, '"');
    if (!q) return false;
    size_t p = (size_t)(q - s) + 1;
    const char *qe = strchr(s + p, '"');
    if (!qe) return false;
    size_t len = (size_t)(qe - s) - p;
    if (len >= cap) return false;
    memcpy(out, s + p, len);
    out[len] = '\0';
    *pos = (size_t)(qe - s) + 1;
    return true;
}

/* From *pos, read the next quoted decimal u64. */
static bool read_quoted_u64(const char *s, size_t *pos, uint64_t *out) {
    char buf[32];
    if (!read_quoted(s, pos, buf, sizeof(buf))) return false;
    char *end = NULL;
    *out = strtoull(buf, &end, 10);
    return end && *end == '\0';
}

/* From *pos: expect `[`, read quoted u64s until `]` (max cap). */
static bool read_u64_array(const char *s, size_t *pos, uint64_t *out,
                           size_t cap, size_t *out_n) {
    const char *lb = strchr(s + *pos, '[');
    if (!lb) return false;
    size_t p = (size_t)(lb - s) + 1;
    size_t n = 0;
    for (;;) {
        /* next non-space char decides: '"' = value, ']' = end */
        while (s[p] == ' ' || s[p] == '\n' || s[p] == '\r' || s[p] == '\t' ||
               s[p] == ',')
            p++;
        if (s[p] == ']') { p++; break; }
        if (s[p] != '"') return false;
        if (n >= cap) return false;
        size_t vp = p;
        if (!read_quoted_u64(s, &vp, &out[n])) return false;
        n++;
        p = vp;
    }
    *pos = p;
    *out_n = n;
    return true;
}

static int g_fails = 0;

static void check_state(const char *json, size_t *pos, const dnac_duplex_t *c,
                        const char *case_name, int step_idx) {
    uint64_t st[DNAC_DUPLEX_WIDTH];
    uint64_t in[DNAC_DUPLEX_RATE + 1];
    uint64_t out[DNAC_DUPLEX_RATE + 1];
    size_t nst = 0, nin = 0, nout = 0;
    if (!find_key(json, pos, "\"state\"") ||
        !read_u64_array(json, pos, st, DNAC_DUPLEX_WIDTH, &nst) || nst != 8 ||
        !find_key(json, pos, "\"input\"") ||
        !read_u64_array(json, pos, in, DNAC_DUPLEX_RATE, &nin) ||
        !find_key(json, pos, "\"output\"") ||
        !read_u64_array(json, pos, out, DNAC_DUPLEX_RATE, &nout)) {
        fprintf(stderr, "FAIL [%s step %d]: malformed snapshot\n", case_name,
                step_idx);
        g_fails++;
        return;
    }
    for (size_t i = 0; i < DNAC_DUPLEX_WIDTH; i++) {
        if (c->sponge_state[i] != st[i]) {
            fprintf(stderr,
                    "FAIL [%s step %d]: state[%zu] C=%" PRIu64 " oracle=%" PRIu64
                    "\n",
                    case_name, step_idx, i, c->sponge_state[i], st[i]);
            g_fails++;
            return;
        }
    }
    if (c->input_len != nin) {
        fprintf(stderr, "FAIL [%s step %d]: input_len C=%zu oracle=%zu\n",
                case_name, step_idx, c->input_len, nin);
        g_fails++;
        return;
    }
    for (size_t i = 0; i < nin; i++) {
        if (c->input_buffer[i] != in[i]) {
            fprintf(stderr, "FAIL [%s step %d]: input[%zu] mismatch\n",
                    case_name, step_idx, i);
            g_fails++;
            return;
        }
    }
    if (c->output_len != nout) {
        fprintf(stderr, "FAIL [%s step %d]: output_len C=%zu oracle=%zu\n",
                case_name, step_idx, c->output_len, nout);
        g_fails++;
        return;
    }
    for (size_t i = 0; i < nout; i++) {
        if (c->output_buffer[i] != out[i]) {
            fprintf(stderr, "FAIL [%s step %d]: output[%zu] mismatch\n",
                    case_name, step_idx, i);
            g_fails++;
            return;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <duplex_challenger.json>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    char *json = slurp(argv[1], &len);
    if (!json) {
        fprintf(stderr, "FAIL: cannot read %s\n", argv[1]);
        return 2;
    }

    /* --- Gate A: DS prefix derivation (local re-derivation of the Q1 25-byte
     * string as LE u64 chunks == the exported constant). */
    {
        static const uint8_t ds[25] = "DNAC|ZK|FRI|TRANSCRIPT|V1";
        uint64_t limbs[4] = {0, 0, 0, 0};
        for (size_t i = 0; i < 25; i++)
            limbs[i / 8] |= (uint64_t)ds[i] << (8 * (i % 8));
        for (size_t i = 0; i < 4; i++) {
            if (limbs[i] != DNAC_DUPLEX_DS_PREFIX[i]) {
                fprintf(stderr,
                        "FAIL: DS limb %zu derived=%" PRIu64 " constant=%" PRIu64
                        "\n",
                        i, limbs[i], DNAC_DUPLEX_DS_PREFIX[i]);
                g_fails++;
            }
        }
    }

    /* --- Gate B: vector ds_prefix == the exported constant. */
    size_t pos = 0;
    {
        uint64_t vp[4];
        size_t n = 0;
        if (!find_key(json, &pos, "\"ds_prefix\"") ||
            !read_u64_array(json, &pos, vp, 4, &n) || n != 4) {
            fprintf(stderr, "FAIL: vector ds_prefix missing/malformed\n");
            g_fails++;
        } else {
            for (size_t i = 0; i < 4; i++) {
                if (vp[i] != DNAC_DUPLEX_DS_PREFIX[i]) {
                    fprintf(stderr, "FAIL: vector ds_prefix[%zu] mismatch\n", i);
                    g_fails++;
                }
            }
        }
    }

    /* --- Gate C: init_default == init + 4 explicit DS observes. */
    {
        dnac_duplex_t a, b;
        dnac_duplex_init_default(&a);
        dnac_duplex_init(&b);
        for (size_t i = 0; i < 4; i++)
            dnac_duplex_observe_fp(&b, gold_fp_from_u64(DNAC_DUPLEX_DS_PREFIX[i]));
        if (memcmp(&a, &b, sizeof(a)) != 0) {
            fprintf(stderr, "FAIL: init_default != init + 4 DS observes\n");
            g_fails++;
        }
        if (a.output_len != DNAC_DUPLEX_RATE) {
            fprintf(stderr, "FAIL: init_default did not fire the prefix duplex\n");
            g_fails++;
        }
    }

    /* --- Gate D: oracle scenario replay. */
    int cases = 0, steps_total = 0;
    char case_name[64];
    while (find_key(json, &pos, "\"name\"")) {
        if (!read_quoted(json, &pos, case_name, sizeof(case_name))) {
            fprintf(stderr, "FAIL: malformed case name\n");
            g_fails++;
            break;
        }
        dnac_duplex_t ch;
        dnac_duplex_init(&ch);
        int step_idx = 0;
        for (;;) {
            /* Peek: next key is either "op" (a step) or "name" (next case) /
             * EOF. */
            const char *next_op = strstr(json + pos, "\"op\"");
            const char *next_name = strstr(json + pos, "\"name\"");
            if (!next_op || (next_name && next_name < next_op)) break;
            pos = (size_t)(next_op - json) + strlen("\"op\"");

            char op[24];
            uint64_t a0, a1, r0, r1;
            if (!read_quoted(json, &pos, op, sizeof(op)) ||
                !find_key(json, &pos, "\"a0\"") ||
                !read_quoted_u64(json, &pos, &a0) ||
                !find_key(json, &pos, "\"a1\"") ||
                !read_quoted_u64(json, &pos, &a1) ||
                !find_key(json, &pos, "\"r0\"") ||
                !read_quoted_u64(json, &pos, &r0) ||
                !find_key(json, &pos, "\"r1\"") ||
                !read_quoted_u64(json, &pos, &r1)) {
                fprintf(stderr, "FAIL [%s step %d]: malformed step\n", case_name,
                        step_idx);
                g_fails++;
                goto done;
            }

            if (strcmp(op, "observe") == 0) {
                dnac_duplex_observe_fp(&ch, gold_fp_from_u64(a0));
            } else if (strcmp(op, "observe_fp2") == 0) {
                gold_fp2_t v;
                v.a = gold_fp_from_u64(a0);
                v.b = gold_fp_from_u64(a1);
                dnac_duplex_observe_fp2(&ch, v);
            } else if (strcmp(op, "sample") == 0) {
                uint64_t got = gold_fp_to_u64(dnac_duplex_sample_fp(&ch));
                if (got != r0) {
                    fprintf(stderr,
                            "FAIL [%s step %d]: sample C=%" PRIu64
                            " oracle=%" PRIu64 "\n",
                            case_name, step_idx, got, r0);
                    g_fails++;
                }
            } else if (strcmp(op, "sample_fp2") == 0) {
                gold_fp2_t got = dnac_duplex_sample_fp2(&ch);
                if (gold_fp_to_u64(got.a) != r0 || gold_fp_to_u64(got.b) != r1) {
                    fprintf(stderr, "FAIL [%s step %d]: sample_fp2 mismatch\n",
                            case_name, step_idx);
                    g_fails++;
                }
            } else if (strcmp(op, "sample_bits") == 0) {
                uint64_t got = dnac_duplex_sample_bits(&ch, (size_t)a0);
                if (got != r0) {
                    fprintf(stderr,
                            "FAIL [%s step %d]: sample_bits(%" PRIu64
                            ") C=%" PRIu64 " oracle=%" PRIu64 "\n",
                            case_name, step_idx, a0, got, r0);
                    g_fails++;
                }
            } else if (strcmp(op, "check_witness") == 0) {
                bool got = dnac_duplex_check_witness(&ch, (size_t)a0,
                                                     gold_fp_from_u64(a1));
                if ((uint64_t)got != r0) {
                    fprintf(stderr,
                            "FAIL [%s step %d]: check_witness C=%d oracle=%" PRIu64
                            "\n",
                            case_name, step_idx, (int)got, r0);
                    g_fails++;
                }
            } else if (strcmp(op, "grind") == 0) {
                uint64_t got = gold_fp_to_u64(dnac_duplex_grind(&ch, (size_t)a0));
                if (got != r0) {
                    fprintf(stderr,
                            "FAIL [%s step %d]: grind witness C=%" PRIu64
                            " oracle=%" PRIu64 "\n",
                            case_name, step_idx, got, r0);
                    g_fails++;
                }
            } else {
                fprintf(stderr, "FAIL [%s step %d]: unknown op '%s'\n",
                        case_name, step_idx, op);
                g_fails++;
                goto done;
            }

            check_state(json, &pos, &ch, case_name, step_idx);
            step_idx++;
            steps_total++;
        }
        cases++;
    }
done:
    free(json);
    if (cases < 13) { /* P1e-D: +grind16 case (was 12) */
        fprintf(stderr, "FAIL: expected >= 13 cases, replayed %d\n", cases);
        g_fails++;
    }
    if (steps_total < 76) { /* P1e (S1a-LOW2): a degenerate/truncated vector must
                             * not pass with too few replayed steps. */
        fprintf(stderr, "FAIL: expected >= 76 steps, replayed %d\n", steps_total);
        g_fails++;
    }
    if (g_fails == 0) {
        printf("PASS: duplex_challenger byte-match — %d cases, %d steps "
               "(+DS-derivation, +vector-prefix, +init_default gates)\n",
               cases, steps_total);
        return 0;
    }
    fprintf(stderr, "FAILURES: %d\n", g_fails);
    return 1;
}
