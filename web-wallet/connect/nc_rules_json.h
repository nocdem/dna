/* Nodus Connect core — ONE JSON dispatcher over the P1 rules
 * (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2, §1, §5).
 *
 * Native ctest (connect/tests/test_nc_rules.c) and the parity wasm's test
 * export (connect/nc_wasm.c nc_rule_test) run the shared vectors
 * (every .json file of test/vectors/connect-rules/) through this one
 * function, so both
 * exercise identical code. NOT a shipped boundary: the web is not switched
 * to C in P1 (design rev 2 change 1).
 *
 *   int nc_rule_call(name, args_json, args_len, &out_json)
 *
 * `name` is the JS function's name (actions.js): contentHash, messageHash,
 * buildReaction, parseReaction, reactionSummary, ownReactionOn,
 * buildDelete, parseDelete, deletions, nodusUnits, buildTransfer,
 * parseTransfer, validNodusCard, transferVerdict, copyCards, buildReply,
 * parseReply. `args_json` is a JSON object of named arguments:
 *   contentHash      {senderFp, recipientFp, text, ts}
 *   messageHash      {m, ownFp}
 *   buildReaction    {target, emoji, op}
 *   parseReaction    {text}            parseDelete {text}
 *   parseTransfer    {text}            parseReply  {text}
 *   reactionSummary  {records, ownFp}
 *   ownReactionOn    {summary, target, emoji}   summary = the Map as
 *                    [[key, [items...]], ...] in insertion order
 *   buildDelete      {hashes}
 *   deletions        {records, ownFp, hashes}   hashes[i] = hashOf(records[i])
 *                    (a string or null), same length as records
 *   nodusUnits       {amount}
 *   buildTransfer    {detail}          the destructured object argument
 *   validNodusCard   {card}
 *   transferVerdict  {card, entries, opts}       opts = {incoming,
 *                    counterparty, ownFp}
 *   copyCards        {cards}           a confirmed card's `order` is the
 *                    BigInt as a canonical decimal string ("-12", "0", "7")
 *   buildReply       {senderLabel, quoted, text}
 * An absent argument is undefined.
 *
 * THE ARGUMENT CONTRACT (the boundary, enforced identically by the JS
 * harness test/tools/gen-connect-rule-vectors.mjs, so a vector outside it
 * is the same error on both sides): a scalar argument is a JSON scalar or
 * absent; an object argument or list element that is a JSON object is
 * FLAT (every value a scalar); the list shapes above. Outside it:
 * {"error":"nc_rule: bad arguments"}. Inside it, the result is the JS
 * function's, encoded as:
 *   the value as JSON.stringify writes it; a Set -> an array in insertion
 *   order; a Map -> an array of [key, value] pairs in insertion order; a
 *   BigInt -> its decimal string; a throw new Error(msg) -> {"error":msg};
 *   an engine TypeError / RangeError / SyntaxError -> {"error":"<name>"}
 *   (the engines word their messages differently; the class is fixed).
 * Boundary errors (never produced by a JS function):
 *   {"error":"nc_rule: input too large"}         args_len > NC_RULE_IN_MAX
 *   {"error":"nc_rule: invalid JSON"}            JSON.parse would throw (or
 *                                                the bytes are not UTF-8)
 *   {"error":"nc_rule: nesting too deep"}        > NC_JS_MAX_NEST (the one
 *       documented difference from JSON.parse, nc_jsjson.h)
 *   {"error":"nc_rule: unknown rule"}
 *   {"error":"nc_rule: bad arguments"}
 *   {"error":"nc_rule: unsupported BigInt literal"}  a 0x/0o/0b string
 *       over NC_BIG_RADIX_MAX digits (JS would convert it)
 *
 * Returns 0 with *out_json = a malloc'd NUL-terminated JSON text (never
 * containing a raw NUL: the writer escapes it), or -1 (out of memory,
 * *out_json = NULL). Pure: no clock, no randomness, no session, no keys.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#ifndef NC_RULES_JSON_H
#define NC_RULES_JSON_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hard input cap, checked before parsing: 1 MiB. Ample for the vectors (a
 * conversation of reaction records is a few hundred bytes per record); a
 * chat text has a 4000-character composer limit but a received one has
 * none (design §R R1), so the cap is the boundary's, not the payload's. */
#define NC_RULE_IN_MAX (1024u * 1024u)

int nc_rule_call(const char *name, const char *args_json, size_t args_len, char **out_json);

#ifdef __cplusplus
}
#endif
#endif /* NC_RULES_JSON_H */
