/*
 * DNA Connect - Reaction JSON helpers implementation
 */
#include "dna/reaction_json.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

int dna_reaction_parse_target(const char *json, char *out, size_t out_len) {
    if (!json || !out || out_len < 65) return -1;
    const char *p = strstr(json, "\"target\":\"");
    if (!p) return -1;
    p += 10;
    const char *end = strchr(p, '"');
    if (!end || (end - p) != 64) return -1;
    memcpy(out, p, 64);
    out[64] = '\0';
    /* Validate hex */
    for (int i = 0; i < 64; i++) {
        char c = out[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return -1;
        }
    }
    return 0;
}

int dna_reaction_parse_emoji(const char *json, char *out, size_t out_len) {
    if (!json || !out || out_len < 8) return -1;
    const char *p = strstr(json, "\"emoji\":\"");
    if (!p) return -1;
    p += 9;
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - p);
    if (len >= out_len) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

int dna_reaction_parse_op(const char *json, char *out, size_t out_len) {
    if (!json || !out || out_len < 8) return -1;
    const char *p = strstr(json, "\"op\":\"");
    if (!p) return -1;
    p += 6;
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - p);
    if (len >= out_len) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

int dna_reaction_build_json(const char *target_hash, const char *emoji, const char *op,
                            char *out, size_t out_len) {
    if (!target_hash || !emoji || !op || !out) return -1;
    int n = snprintf(out, out_len, "{\"target\":\"%s\",\"emoji\":\"%s\",\"op\":\"%s\"}",
                     target_hash, emoji, op);
    return (n > 0 && (size_t)n < out_len) ? 0 : -1;
}
