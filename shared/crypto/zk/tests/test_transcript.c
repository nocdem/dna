/**
 * @file test_transcript.c
 * @brief Cross-validate transcript.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/transcript.json, replays each scenario step-by-step,
 * asserts state + counter + challenge outputs byte-match the oracle.
 *
 * Build:
 *   gcc -std=c99 -O2 -Wall -Wextra -I.. -I../../.. \
 *       tests/test_transcript.c transcript.c field_goldilocks.c \
 *       ../hash/qgp_sha3.c \
 *       -lcrypto -o test_transcript
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../transcript.h"
#include "../field_goldilocks.h"

/* ============================================================================
 * Minimal JSON tokenizer (shared style)
 * ========================================================================== */

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} json_scanner_t;

static void js_skip_ws(json_scanner_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}
static bool js_match(json_scanner_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}
static bool js_match_key(json_scanner_t *s, const char *key) {
    js_skip_ws(s);
    size_t klen = strlen(key);
    if (s->pos + klen + 2 > s->len) return false;
    if (s->src[s->pos] != '"') return false;
    if (memcmp(s->src + s->pos + 1, key, klen) != 0) return false;
    if (s->src[s->pos + 1 + klen] != '"') return false;
    s->pos += klen + 2;
    return true;
}
static char *js_read_string(json_scanner_t *s) {
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
static bool js_read_u32(json_scanner_t *s, uint32_t *out) {
    js_skip_ws(s);
    uint64_t v = 0;
    bool any = false;
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint64_t)(c - '0');
        s->pos++;
        any = true;
    }
    if (!any) return false;
    *out = (uint32_t)v;
    return true;
}
static bool js_read_u64(json_scanner_t *s, uint64_t *out) {
    js_skip_ws(s);
    uint64_t v = 0;
    bool any = false;
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint64_t)(c - '0');
        s->pos++;
        any = true;
    }
    if (!any) return false;
    *out = v;
    return true;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
static int hex_decode(const char *hex, uint8_t **out_buf) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t bytes = hlen / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes + 1);
    if (!buf) return -1;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_buf = buf;
    return (int)bytes;
}
static bool hex_decode_fixed(const char *hex, uint8_t *out, size_t expected) {
    if (strlen(hex) != expected * 2) return false;
    for (size_t i = 0; i < expected; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* Skip value helpers (for unknown keys). */
static void js_skip_value(json_scanner_t *s);
static void js_skip_array(json_scanner_t *s) {
    if (!js_match(s, '[')) return;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; return; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        js_skip_value(s);
    }
}
static void js_skip_object(json_scanner_t *s) {
    if (!js_match(s, '{')) return;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == '}') { s->pos++; return; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        char *k = js_read_string(s);
        if (k) free(k);
        js_match(s, ':');
        js_skip_value(s);
    }
}
static void js_skip_value(json_scanner_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return;
    char c = s->src[s->pos];
    if (c == '"') { char *v = js_read_string(s); if (v) free(v); return; }
    if (c == '[') { js_skip_array(s); return; }
    if (c == '{') { js_skip_object(s); return; }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\n' ||
            d == '\t' || d == '\r') break;
        s->pos++;
    }
}

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

/* ============================================================================
 * Scenario replay
 * ========================================================================== */

typedef struct {
    int total_passed;
    int total_failed;
} stats_t;

/* Verify transcript state matches expected hex.  Returns true on match. */
static bool check_state(const transcript_t *t, const char *expected_hex,
                        const char *scenario, const char *step_name) {
    uint8_t expected[TRANSCRIPT_HASH_SIZE];
    if (!hex_decode_fixed(expected_hex, expected, TRANSCRIPT_HASH_SIZE)) {
        fprintf(stderr, "  bad expected_hex in %s/%s\n", scenario, step_name);
        return false;
    }
    if (memcmp(t->state, expected, TRANSCRIPT_HASH_SIZE) != 0) {
        fprintf(stderr, "  STATE MISMATCH %s/%s\n", scenario, step_name);
        return false;
    }
    return true;
}

/* Parse and replay one scenario's steps[] array. */
static int replay_steps(json_scanner_t *s, transcript_t *t,
                        const char *scenario_name, stats_t *stats) {
    if (!js_match(s, '[')) {
        fprintf(stderr, "expected '[' for steps in %s\n", scenario_name);
        return -1;
    }
    int step_idx = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) { fprintf(stderr, "EOF in steps\n"); return -1; }
        if (s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') { fprintf(stderr, "bad step\n"); return -1; }
        s->pos++;

        char *action = NULL;
        /* Common fields */
        char *msg_hex = NULL;
        char *state_after_hex = NULL;
        uint32_t counter_before = 0, counter_after = 0;
        uint32_t max_index = 0;
        uint32_t expected_query = 0;
        char *expected_a0_str = NULL, *expected_a1_str = NULL;
        bool got_counter_before = false, got_counter_after = false;
        bool got_max_index = false, got_expected_query = false;

        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "action")) {
                js_match(s, ':');
                action = js_read_string(s);
            } else if (js_match_key(s, "msg_hex")) {
                js_match(s, ':');
                msg_hex = js_read_string(s);
            } else if (js_match_key(s, "state_after_hex")) {
                js_match(s, ':');
                state_after_hex = js_read_string(s);
            } else if (js_match_key(s, "counter_before")) {
                js_match(s, ':');
                got_counter_before = js_read_u32(s, &counter_before);
            } else if (js_match_key(s, "counter_after")) {
                js_match(s, ':');
                got_counter_after = js_read_u32(s, &counter_after);
            } else if (js_match_key(s, "max_index")) {
                js_match(s, ':');
                got_max_index = js_read_u32(s, &max_index);
            } else if (js_match_key(s, "expected")) {
                js_match(s, ':');
                got_expected_query = js_read_u32(s, &expected_query);
            } else if (js_match_key(s, "expected_a0")) {
                js_match(s, ':');
                expected_a0_str = js_read_string(s);
            } else if (js_match_key(s, "expected_a1")) {
                js_match(s, ':');
                expected_a1_str = js_read_string(s);
            } else {
                /* Unknown key — skip its value. */
                char *unknown = js_read_string(s);
                if (unknown) free(unknown);
                js_match(s, ':');
                js_skip_value(s);
            }
        }

        char step_label[64];
        snprintf(step_label, sizeof(step_label), "step%d:%s", step_idx,
                 action ? action : "?");

        bool ok = true;
        if (action && strcmp(action, "absorb") == 0) {
            uint8_t *msg = NULL;
            int mlen = hex_decode(msg_hex, &msg);
            if (mlen < 0) { fprintf(stderr, "bad msg_hex %s\n", step_label); ok = false; }
            else { transcript_absorb(t, msg, (size_t)mlen); }
            if (msg) free(msg);
            if (ok && state_after_hex) ok = check_state(t, state_after_hex, scenario_name, step_label);
        } else if (action && strcmp(action, "challenge_fp2") == 0) {
            if (got_counter_before && t->challenge_counter != counter_before) {
                fprintf(stderr, "  counter_before mismatch %s: have=%u want=%u\n",
                        step_label, t->challenge_counter, counter_before);
                ok = false;
            }
            gold_fp2_t r = transcript_challenge_fp2(t);
            uint64_t got_a0 = gold_fp_to_u64(r.a);
            uint64_t got_a1 = gold_fp_to_u64(r.b);
            uint64_t exp_a0 = expected_a0_str ? strtoull(expected_a0_str, NULL, 10) : 0;
            uint64_t exp_a1 = expected_a1_str ? strtoull(expected_a1_str, NULL, 10) : 0;
            if (got_a0 != exp_a0 || got_a1 != exp_a1) {
                fprintf(stderr, "  CHAL mismatch %s: got(%"PRIu64",%"PRIu64") want(%"PRIu64",%"PRIu64")\n",
                        step_label, got_a0, got_a1, exp_a0, exp_a1);
                ok = false;
            }
            if (got_counter_after && t->challenge_counter != counter_after) {
                fprintf(stderr, "  counter_after mismatch %s: have=%u want=%u\n",
                        step_label, t->challenge_counter, counter_after);
                ok = false;
            }
            if (ok && state_after_hex) ok = check_state(t, state_after_hex, scenario_name, step_label);
        } else if (action && strcmp(action, "challenge_query_index") == 0) {
            if (got_counter_before && t->challenge_counter != counter_before) {
                fprintf(stderr, "  counter_before mismatch %s: have=%u want=%u\n",
                        step_label, t->challenge_counter, counter_before);
                ok = false;
            }
            if (!got_max_index || !got_expected_query) {
                fprintf(stderr, "  missing max_index/expected in %s\n", step_label);
                ok = false;
            } else {
                uint32_t got = transcript_challenge_query_index(t, max_index);
                if (got != expected_query) {
                    fprintf(stderr, "  QRY mismatch %s (max=%u): got=%u want=%u\n",
                            step_label, max_index, got, expected_query);
                    ok = false;
                }
            }
            if (got_counter_after && t->challenge_counter != counter_after) {
                fprintf(stderr, "  counter_after mismatch %s: have=%u want=%u\n",
                        step_label, t->challenge_counter, counter_after);
                ok = false;
            }
            if (ok && state_after_hex) ok = check_state(t, state_after_hex, scenario_name, step_label);
        } else {
            fprintf(stderr, "unknown action in %s: %s\n", scenario_name, action ? action : "(null)");
            ok = false;
        }

        if (ok) stats->total_passed++;
        else    stats->total_failed++;

        free(action);
        free(msg_hex);
        free(state_after_hex);
        free(expected_a0_str);
        free(expected_a1_str);
        step_idx++;
    }
    return 0;
}

/* Parse one scenario object: name, init, steps. */
static int run_scenario(json_scanner_t *s, stats_t *stats) {
    if (!js_match(s, '{')) {
        fprintf(stderr, "expected '{' for scenario\n");
        return -1;
    }
    char *name = NULL;
    char *chain_id_hex = NULL, *public_input_hex = NULL, *initial_state_hex = NULL;
    uint64_t block_height = 0;
    uint32_t tx_index = 0;
    bool got_height = false, got_tx_idx = false;
    bool steps_done = false;
    transcript_t t = {0};

    while (1) {
        js_skip_ws(s);
        if (s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (js_match_key(s, "name")) {
            js_match(s, ':');
            name = js_read_string(s);
        } else if (js_match_key(s, "init")) {
            js_match(s, ':');
            if (!js_match(s, '{')) { fprintf(stderr, "bad init\n"); return -1; }
            while (1) {
                js_skip_ws(s);
                if (s->src[s->pos] == '}') { s->pos++; break; }
                if (s->src[s->pos] == ',') { s->pos++; continue; }
                if (js_match_key(s, "chain_id_hex")) { js_match(s, ':'); chain_id_hex = js_read_string(s); }
                else if (js_match_key(s, "block_height")) { js_match(s, ':'); got_height = js_read_u64(s, &block_height); }
                else if (js_match_key(s, "tx_index")) { js_match(s, ':'); got_tx_idx = js_read_u32(s, &tx_index); }
                else if (js_match_key(s, "public_input_hex")) { js_match(s, ':'); public_input_hex = js_read_string(s); }
                else if (js_match_key(s, "initial_state_hex")) { js_match(s, ':'); initial_state_hex = js_read_string(s); }
                else { char *k = js_read_string(s); if (k) free(k); js_match(s, ':'); js_skip_value(s); }
            }
            if (!chain_id_hex || !got_height || !got_tx_idx || !public_input_hex || !initial_state_hex) {
                fprintf(stderr, "missing init field\n"); return -1;
            }
            /* Initialize transcript. */
            uint8_t chain_id[32];
            if (!hex_decode_fixed(chain_id_hex, chain_id, 32)) {
                fprintf(stderr, "bad chain_id_hex\n"); return -1;
            }
            uint8_t *pubin = NULL;
            int pubin_len = hex_decode(public_input_hex, &pubin);
            if (pubin_len < 0) { fprintf(stderr, "bad public_input_hex\n"); return -1; }
            transcript_init(&t, chain_id, block_height, tx_index, pubin, (size_t)pubin_len);
            free(pubin);
            /* Verify initial state matches oracle. */
            if (!check_state(&t, initial_state_hex, name ? name : "?", "init")) {
                stats->total_failed++;
            } else {
                stats->total_passed++;
            }
        } else if (js_match_key(s, "steps")) {
            js_match(s, ':');
            if (replay_steps(s, &t, name ? name : "?", stats) < 0) return -1;
            steps_done = true;
        } else {
            char *k = js_read_string(s); if (k) free(k); js_match(s, ':'); js_skip_value(s);
        }
    }

    if (name) printf("  scenario %-24s done\n", name);
    free(name);
    free(chain_id_hex);
    free(public_input_hex);
    free(initial_state_hex);
    (void)steps_done;
    return 0;
}

/* Walk the scenarios[] array. */
static int run_all_scenarios(json_scanner_t *s, stats_t *stats) {
    /* Find "scenarios": [ */
    s->pos = 0;
    const char *needle = "\"scenarios\"";
    size_t nlen = strlen(needle);
    while (s->pos + nlen < s->len) {
        if (memcmp(s->src + s->pos, needle, nlen) == 0) {
            s->pos += nlen;
            js_skip_ws(s);
            if (s->src[s->pos] == ':') { s->pos++; }
            js_skip_ws(s);
            if (s->src[s->pos] == '[') { s->pos++; break; }
        }
        s->pos++;
    }

    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) return -1;
        if (s->src[s->pos] == ']') { s->pos++; return 0; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (run_scenario(s, stats) < 0) return -1;
    }
}

int main(int argc, char **argv) {
    const char *path = "tools/vectors/transcript.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};
    stats_t stats = {0, 0};

    if (run_all_scenarios(&s, &stats) < 0) {
        fprintf(stderr, "scenario walker error\n");
        free(src);
        return 2;
    }

    printf("\nTotal: %d passed, %d failed\n", stats.total_passed, stats.total_failed);

    free(src);
    if (stats.total_failed == 0) {
        printf("SPRINT 1.5 GATE: GREEN — transcript byte-matches Plonky3 oracle\n");
        return 0;
    } else {
        printf("SPRINT 1.5 GATE: RED — %d total mismatches\n", stats.total_failed);
        return 1;
    }
}
