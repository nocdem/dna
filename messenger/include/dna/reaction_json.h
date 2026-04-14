/*
 * DNA Connect - Reaction JSON helpers
 *
 * Minimal parse/build for the reaction payload:
 *   {"target":"<64hex>","emoji":"<utf8>","op":"<add|remove>"}
 *
 * We use a tiny substring extractor instead of a full JSON parser because
 * the payload shape is fixed and controlled entirely by our own code.
 */
#ifndef DNA_REACTION_JSON_H
#define DNA_REACTION_JSON_H

#include <stddef.h>

/* Parse the "target" field (64 hex chars). Returns 0 on success, -1 on error.
 * out must be at least 65 bytes. */
int dna_reaction_parse_target(const char *json, char *out, size_t out_len);

/* Parse the "emoji" field (UTF-8, up to 7 bytes). out must be at least 8 bytes. */
int dna_reaction_parse_emoji(const char *json, char *out, size_t out_len);

/* Parse the "op" field ("add" or "remove"). out must be at least 8 bytes. */
int dna_reaction_parse_op(const char *json, char *out, size_t out_len);

/* Build a reaction JSON payload. Returns 0 on success, -1 if out_len too small. */
int dna_reaction_build_json(const char *target_hash, const char *emoji, const char *op,
                            char *out, size_t out_len);

#endif
