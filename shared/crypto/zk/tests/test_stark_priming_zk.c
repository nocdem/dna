/**
 * @file test_stark_priming_zk.c
 * @brief M2 replay test — is_zk=1 (hiding) STARK/PCS transcript priming (82cfad73).
 *
 * Parses tools/vectors/stark_priming_zk.json (produced by a REAL is_zk=1
 * p3_uni_stark::prove over HidingFriPcs + salted MerkleTreeHidingMmcs — M1
 * sandbox confidential milestone), runs dnac_stark_prime_transcript with
 * is_zk=1, and byte-matches:
 *   - sampled alpha / zeta / zeta_next       (verifier.rs:379 / :391 / :398)
 *   - primed transcript input_buf + output_buf_remaining at verify_fri entry
 *   - input_buf_len == 288, output_buf_remaining_len == 0
 *   - is_zk augmentation: random-commit observe (verifier.rs:383-385) +
 *     random opened round FIRST (verifier.rs:403-411).
 *
 * This proves the C is_zk transcript augmentation is byte-exact against the
 * real Plonky3 verifier. The FRI-query verification of the is_zk proof
 * (random codewords in the batch) is M2b. Compiled with
 * -DDNAC_TRANSCRIPT_TESTING=1 for the snapshot accessors.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stark_priming.h"

/* ===== Minimal JSON scanner (same idiom as tests/test_fri_verifier_valid.c) ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;

static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}
static bool js_peek(js_t *s, char c) { js_skip_ws(s); return s->pos < s->len && s->src[s->pos] == c; }
static bool js_match(js_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}
static char *js_read_string(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len || s->src[s->pos] != '"') return NULL;
    s->pos++;
    size_t start = s->pos;
    while (s->pos < s->len && s->src[s->pos] != '"') s->pos++;
    if (s->pos >= s->len) return NULL;
    size_t slen = s->pos - start;
    s->pos++;
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, s->src + start, slen);
    out[slen] = '\0';
    return out;
}
static bool js_read_u64(js_t *s, uint64_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}
static bool js_skip_value(js_t *s);
static bool js_skip_object(js_t *s) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) return false;
        free(k);
        if (!js_match(s, ':')) return false;
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_array(js_t *s) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_value(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '{') return js_skip_object(s);
    if (c == '[') return js_skip_array(s);
    if (c == '"') { char *t = js_read_string(s); if (!t) return false; free(t); return true; }
    if (c == 't') { s->pos += 4; return true; }
    if (c == 'f') { s->pos += 5; return true; }
    if (c == 'n') { s->pos += 4; return true; }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') s->pos++;
        else break;
    }
    return true;
}
static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex_decode(const char *hex, uint8_t *buf, size_t cap) {
    size_t hl = strlen(hex);
    if (hl % 2) return (size_t)-1;
    size_t n = hl / 2;
    if (n > cap) return (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(hex[2 * i]), lo = hexnib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}
/* {c0_decimal:"..", c1_decimal:".."} -> fp2 (a=c0 constant term, b=c1 X coeff) */
static gold_fp2_t parse_fp2_decimal(js_t *s) {
    uint64_t c0 = 0, c1 = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        char *v = js_peek(s, '"') ? js_read_string(s) : NULL;
        if (v && strcmp(k, "c0_decimal") == 0) c0 = strtoull(v, NULL, 10);
        else if (v && strcmp(k, "c1_decimal") == 0) c1 = strtoull(v, NULL, 10);
        else if (!v) js_skip_value(s);
        free(v);
        free(k);
    }
    return gold_fp2_new(gold_fp_from_u64(c0), gold_fp_from_u64(c1));
}
/* [ {c0,c1}, ... ] -> fp2 array; returns count */
static size_t parse_fp2_array(js_t *s, gold_fp2_t *out, size_t cap) {
    size_t n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        gold_fp2_t f = parse_fp2_decimal(s);
        if (n < cap) out[n] = f;
        n++;
    }
    return n;
}

/* ===== fixture ===== */
#define SP_MAXPUB 16
#define SP_MAXEVAL 32
#define SP_MAXCHUNK 16
#define SP_MAXBUF 1024
typedef struct {
    uint64_t degree_bits, base_degree_bits, preprocessed_width, num_quotient_chunks;
    uint8_t init_state[256];
    size_t init_state_len;
    dnac_merkle_digest_t trace_commit, quotient_commit;
    dnac_merkle_digest_t random_commit;      /* is_zk=1 */
    bool has_random_commit;
    gold_fp2_t random_local[SP_MAXEVAL];     /* is_zk=1 random opened round */
    size_t random_local_len;
    gold_fp_t public_values[SP_MAXPUB];
    size_t num_public_values;
    gold_fp2_t alpha, zeta, zeta_next;
    gold_fp2_t trace_local[SP_MAXEVAL];
    size_t trace_local_len;
    bool has_trace_next;
    gold_fp2_t trace_next[SP_MAXEVAL];
    size_t trace_next_len;
    gold_fp2_t quotient_chunks[SP_MAXCHUNK][SP_MAXEVAL];
    size_t quotient_chunk_lens[SP_MAXCHUNK];
    size_t num_quotient_chunks_parsed;
    uint8_t input_buf[SP_MAXBUF];
    size_t input_buf_len;
    uint64_t input_buf_len_field;
    uint8_t output_buf[SP_MAXBUF];
    size_t output_buf_len;
    uint64_t output_buf_len_field;
} sp_fixture_t;

static void parse_instance(js_t *s, sp_fixture_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        uint64_t v = 0;
        if (strcmp(k, "degree_bits") == 0) { js_read_u64(s, &v); fx->degree_bits = v; }
        else if (strcmp(k, "base_degree_bits") == 0) { js_read_u64(s, &v); fx->base_degree_bits = v; }
        else if (strcmp(k, "preprocessed_width") == 0) { js_read_u64(s, &v); fx->preprocessed_width = v; }
        else if (strcmp(k, "num_quotient_chunks") == 0) { js_read_u64(s, &v); fx->num_quotient_chunks = v; }
        else js_skip_value(s);
        free(k);
    }
}
static void parse_commitments(js_t *s, sp_fixture_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        if (strcmp(k, "trace_commit_root_hex") == 0) {
            char *v = js_read_string(s);
            hex_decode(v, fx->trace_commit.bytes, DNAC_MERKLE_DIGEST_BYTES);
            free(v);
        } else if (strcmp(k, "quotient_commit_root_hex") == 0) {
            char *v = js_read_string(s);
            hex_decode(v, fx->quotient_commit.bytes, DNAC_MERKLE_DIGEST_BYTES);
            free(v);
        } else if (strcmp(k, "random_commit_root_hex") == 0) {
            char *v = js_read_string(s);
            hex_decode(v, fx->random_commit.bytes, DNAC_MERKLE_DIGEST_BYTES);
            fx->has_random_commit = true;
            free(v);
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}
static void parse_public_values(js_t *s, sp_fixture_t *fx) {
    js_match(s, '[');
    size_t n = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *v = js_read_string(s);
        if (v && n < SP_MAXPUB) fx->public_values[n] = gold_fp_from_u64(strtoull(v, NULL, 10));
        free(v);
        n++;
    }
    fx->num_public_values = n;
}
static void parse_challenges(js_t *s, sp_fixture_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        if (strcmp(k, "stark_alpha_fp2") == 0) fx->alpha = parse_fp2_decimal(s);
        else if (strcmp(k, "zeta_fp2") == 0) fx->zeta = parse_fp2_decimal(s);
        else if (strcmp(k, "zeta_next_fp2") == 0) fx->zeta_next = parse_fp2_decimal(s);
        else js_skip_value(s);
        free(k);
    }
}
static void parse_opened_values(js_t *s, sp_fixture_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        if (strcmp(k, "random") == 0) {
            fx->random_local_len = parse_fp2_array(s, fx->random_local, SP_MAXEVAL);
        } else if (strcmp(k, "trace_local") == 0) {
            fx->trace_local_len = parse_fp2_array(s, fx->trace_local, SP_MAXEVAL);
        } else if (strcmp(k, "trace_next") == 0) {
            if (js_peek(s, '[')) {
                fx->trace_next_len = parse_fp2_array(s, fx->trace_next, SP_MAXEVAL);
                fx->has_trace_next = true;
            } else {
                js_skip_value(s); /* null */
                fx->has_trace_next = false;
            }
        } else if (strcmp(k, "quotient_chunks") == 0) {
            js_match(s, '[');
            size_t c = 0;
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (c < SP_MAXCHUNK) {
                    fx->quotient_chunk_lens[c] = parse_fp2_array(s, fx->quotient_chunks[c], SP_MAXEVAL);
                } else {
                    js_skip_value(s);
                }
                c++;
            }
            fx->num_quotient_chunks_parsed = c;
        } else {
            js_skip_value(s); /* preprocessed: null, etc. */
        }
        free(k);
    }
}
static void parse_snapshot(js_t *s, sp_fixture_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        if (strcmp(k, "input_buf_hex") == 0) {
            char *v = js_read_string(s);
            fx->input_buf_len = hex_decode(v, fx->input_buf, SP_MAXBUF);
            free(v);
        } else if (strcmp(k, "output_buf_remaining_hex") == 0) {
            char *v = js_read_string(s);
            fx->output_buf_len = hex_decode(v, fx->output_buf, SP_MAXBUF);
            free(v);
        } else if (strcmp(k, "input_buf_len") == 0) {
            js_read_u64(s, &fx->input_buf_len_field);
        } else if (strcmp(k, "output_buf_remaining_len") == 0) {
            js_read_u64(s, &fx->output_buf_len_field);
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}
static bool parse_top(js_t *s, sp_fixture_t *fx) {
    if (!js_match(s, '{')) return false;
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) return false;
        js_match(s, ':');
        if (strcmp(k, "instance") == 0) parse_instance(s, fx);
        else if (strcmp(k, "init_state_hex") == 0) {
            char *v = js_read_string(s);
            fx->init_state_len = hex_decode(v, fx->init_state, sizeof fx->init_state);
            free(v);
        } else if (strcmp(k, "commitments") == 0) parse_commitments(s, fx);
        else if (strcmp(k, "public_values") == 0) parse_public_values(s, fx);
        else if (strcmp(k, "challenges") == 0) parse_challenges(s, fx);
        else if (strcmp(k, "opened_values") == 0) parse_opened_values(s, fx);
        else if (strcmp(k, "transcript_snapshot_at_verify_fri_entry") == 0) parse_snapshot(s, fx);
        else js_skip_value(s);
        free(k);
    }
    return true;
}

/* ===== diagnostics ===== */
static void print_hex(const char *label, const uint8_t *b, size_t n) {
    fprintf(stderr, "    %s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}
static int check_fp2(const char *field, gold_fp2_t got, gold_fp2_t exp,
                     const char *p3line, const char *cause) {
    if (gold_fp2_eq(got, exp)) return 0;
    fprintf(stderr, "MISMATCH field=%s\n", field);
    fprintf(stderr, "    expected (stark_priming.json): c0=%llu c1=%llu\n",
            (unsigned long long)gold_fp_to_u64(exp.a), (unsigned long long)gold_fp_to_u64(exp.b));
    fprintf(stderr, "    actual   (dnac_stark_prime):   c0=%llu c1=%llu\n",
            (unsigned long long)gold_fp_to_u64(got.a), (unsigned long long)gold_fp_to_u64(got.b));
    fprintf(stderr, "    Plonky3 source: %s\n", p3line);
    fprintf(stderr, "    suspected cause: %s\n", cause);
    return 1;
}
static int check_bytes(const char *field, const uint8_t *got, size_t gotn,
                       const uint8_t *exp, size_t expn, const char *p3line, const char *cause) {
    if (gotn == expn && (expn == 0 || memcmp(got, exp, expn) == 0)) return 0;
    fprintf(stderr, "MISMATCH field=%s (got_len=%zu expected_len=%zu)\n", field, gotn, expn);
    print_hex("expected (stark_priming.json)", exp, expn);
    print_hex("actual   (primed transcript) ", got, gotn);
    fprintf(stderr, "    Plonky3 source: %s\n", p3line);
    fprintf(stderr, "    suspected cause: %s\n", cause);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <stark_priming.json>\n", argv[0]); return 2; }
    size_t srclen = 0;
    char *src = slurp(argv[1], &srclen);
    if (!src) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    sp_fixture_t fx;
    memset(&fx, 0, sizeof fx);
    js_t s = { src, 0, srclen };
    if (!parse_top(&s, &fx)) { fprintf(stderr, "JSON parse failed\n"); free(src); return 2; }
    free(src);

    /* Init transcript from the vector's init_state (= DNAC production seed). */
    dnac_transcript_t *t = dnac_transcript_init(fx.init_state, fx.init_state_len);
    if (!t) { fprintf(stderr, "transcript init failed\n"); return 2; }

    /* Assemble the priming input. is_zk / preprocessed_width are CONFIG (not wire). */
    const gold_fp2_t *qc_ptrs[SP_MAXCHUNK];
    for (size_t i = 0; i < fx.num_quotient_chunks_parsed; i++) qc_ptrs[i] = fx.quotient_chunks[i];

    dnac_stark_priming_input_t in;
    memset(&in, 0, sizeof in);
    in.degree_bits = (size_t)fx.degree_bits;
    in.is_zk = 1;                                   /* M1 sandbox confidential (HidingFriPcs) */
    in.preprocessed_width = (size_t)fx.preprocessed_width;
    in.trace_commit = fx.trace_commit;
    in.quotient_commit = fx.quotient_commit;
    in.preprocessed_commit = NULL;
    in.random_commit = fx.has_random_commit ? &fx.random_commit : NULL;
    in.random_local = fx.random_local;
    in.random_local_len = fx.random_local_len;
    in.public_values = fx.public_values;
    in.num_public_values = fx.num_public_values;
    in.trace_local = fx.trace_local;
    in.trace_local_len = fx.trace_local_len;
    in.trace_next = fx.has_trace_next ? fx.trace_next : NULL;
    in.trace_next_len = fx.trace_next_len;
    in.quotient_chunks = qc_ptrs;
    in.quotient_chunk_lens = fx.quotient_chunk_lens;
    in.num_quotient_chunks = fx.num_quotient_chunks_parsed;

    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof out);
    dnac_stark_priming_status_t st = dnac_stark_prime_transcript(t, &in, &out);

    int fails = 0;

    if (st != DNAC_STARK_PRIMING_OK) {
        fprintf(stderr, "MISMATCH field=status: dnac_stark_prime_transcript returned %d (want OK=0)\n", (int)st);
        fails++;
    }

    /* 3-5. sampled challenges */
    fails += check_fp2("stark_alpha_fp2", out.alpha, fx.alpha, "verifier.rs:379",
                       "alpha sampling / observe order before alpha");
    fails += check_fp2("zeta_fp2", out.zeta, fx.zeta, "verifier.rs:391",
                       "zeta sampling / observe order (quotient commit) before zeta");
    fails += check_fp2("zeta_next_fp2", out.zeta_next, fx.zeta_next, "verifier.rs:398 / coset.rs:92",
                       "zeta_next generator (must be two_adic_generator(base_degree_bits), shift=ONE)");

    /* 6-7. transcript state at verify_fri entry */
    const uint8_t *ib = dnac_transcript_test_input_buf_ptr(t);
    size_t ibl = dnac_transcript_test_input_buf_len(t);
    fails += check_bytes("input_buf", ib, ibl, fx.input_buf, fx.input_buf_len,
                         "two_adic_pcs.rs:687-693 / verifier.rs:360-391",
                         "observe order / fp|fp2|commitment serialization / sampling positions");
    const uint8_t *ob = dnac_transcript_test_output_buf_ptr(t);
    size_t obl = dnac_transcript_test_output_buf_remaining(t);
    fails += check_bytes("output_buf_remaining", ob, obl, fx.output_buf, fx.output_buf_len,
                         "hash_challenger.rs flush", "sampling / final observe must clear output_buf");

    /* 8-9. exact lengths */
    if (ibl != 288 || (uint64_t)ibl != fx.input_buf_len_field) {
        fprintf(stderr, "MISMATCH field=input_buf_len: got %zu, expected 288 (vector field %llu)\n",
                ibl, (unsigned long long)fx.input_buf_len_field);
        fails++;
    }
    if (obl != 0 || (uint64_t)obl != fx.output_buf_len_field) {
        fprintf(stderr, "MISMATCH field=output_buf_remaining_len: got %zu, expected 0 (vector field %llu)\n",
                obl, (unsigned long long)fx.output_buf_len_field);
        fails++;
    }

    /* 10-12. config-branch confirmations */
    if (in.is_zk != 1) { fprintf(stderr, "MISMATCH field=is_zk: is_zk=%zu (want 1)\n", in.is_zk); fails++; }
    if (in.random_commit == NULL || in.random_local_len == 0) {
        fprintf(stderr, "MISMATCH field=random_round: random_commit=%p random_local_len=%zu (want present)\n",
                (const void *)in.random_commit, in.random_local_len); fails++;
    }
    if (in.preprocessed_width != 0 || fx.preprocessed_width != 0) {
        fprintf(stderr, "MISMATCH field=preprocessed_width: in=%zu vector=%llu (want 0)\n",
                in.preprocessed_width, (unsigned long long)fx.preprocessed_width);
        fails++;
    }
    if (!fx.has_trace_next || fx.trace_next_len == 0) {
        fprintf(stderr, "MISMATCH field=trace_next_present: has=%d len=%zu (FibonacciAir => present)\n",
                (int)fx.has_trace_next, fx.trace_next_len);
        fails++;
    }
    if (out.base_degree_bits != fx.base_degree_bits) {
        fprintf(stderr, "MISMATCH field=base_degree_bits: got %zu, expected %llu\n",
                out.base_degree_bits, (unsigned long long)fx.base_degree_bits);
        fails++;
    }

    dnac_transcript_free(t);

    if (fails) {
        fprintf(stderr, "test_stark_priming: %d FAIL(s)\n", fails);
        return 1;
    }

    /* CommitmentWithOpeningPoints assembly summary (order proven by the input_buf
     * byte-match above; this is the human-readable confirmation of §5/§7 shape). */
    printf("test_stark_priming_zk: PASS\n");
    printf("  GATE: dnac_stark_prime_transcript = OK; alpha/zeta/zeta_next byte-match vector.\n");
    printf("  transcript primed to verify_fri entry: input_buf=%zu bytes, output_buf_remaining=%zu.\n",
           ibl, obl);
    printf("  is_zk=1 (hiding), random round first (len=%zu), preprocessed_width=0, trace_next present (len=%zu), base_degree_bits=%zu.\n",
           fx.random_local_len,
           fx.trace_next_len, out.base_degree_bits);
    printf("  public_values: %zu (order verified via input_buf byte-match).\n", fx.num_public_values);
    printf("  CommitmentWithOpeningPoints order: [trace(zeta,zeta_next), quotient x%zu (zeta)]; "
           "quotient opening domains = natural_domain_for_degree (shift=ONE).\n",
           fx.num_quotient_chunks_parsed);
    return 0;
}
