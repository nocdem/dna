/* Nodus Connect core — P1b: the app's payload forms, ported from
 * src/connect/ui/actions.js (web 0.1.101) to C
 * (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2).
 *
 * THE JAVASCRIPT IS THE SPECIFICATION. Each function below is the JS
 * function of the same name (actions.js line in its comment) over plain
 * structs, with the JS accept sets, edge cases and error cases copied:
 *   - a JS argument that the function passes through String() / a RegExp
 *     test arrives as an nc_val_t (a JSON scalar or undefined) and is
 *     coerced here exactly as String() does (nc_jsjson.h);
 *   - fields compared with === keep their JS type (nc_val_strict_eq), so
 *     undefined === undefined holds where it holds in JS (deletions with a
 *     missing fp, transferVerdict with a missing counterparty);
 *   - BigInt arithmetic is arbitrary-precision or unsigned 128-bit, never
 *     a wrapping uint64 (R2, R5): a card amount reaches 10^20 - 1 units;
 *   - Map / Set results keep insertion order; every sort is stable (JS
 *     Array.prototype.sort is), ties keep input order.
 * Where JS would throw, the function returns the throw (NC_P_THROW with
 * the function's own message, or the engine error's class).
 *
 * NOT reproduced (reported, design §R R10): String.prototype.toLowerCase
 * is full-Unicode in JS; here it is ASCII-only. It differs only for
 * non-ASCII text in parseTransfer's chain / txHash / recipientAddress and
 * ownReactionOn's target (every other lowercased value has passed an ASCII
 * hex test first).
 *
 * Pure: no clock, no randomness, no global state, no network, no keys.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#ifndef NC_PAYLOAD_H
#define NC_PAYLOAD_H

#include "nc_jsjson.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NC_P_OK          = 0,
    NC_P_NULL        = 1,   /* the function returns null                    */
    NC_P_THROW       = 2,   /* throw new Error(<the function's message>)    */
    NC_P_TYPE_ERROR  = 3,   /* the engine throws TypeError                  */
    NC_P_RANGE_ERROR = 4,   /* RangeError (BigInt of a non-integer Number)  */
    NC_P_SYNTAX_ERROR= 5,   /* SyntaxError (BigInt of a non-integer string) */
    NC_P_UNSUPPORTED = 6,   /* NC_BIG_UNSUPPORTED (nc_jsjson.h)             */
    NC_P_NOMEM       = -1
} nc_p_rc_t;

/* The messages of the functions' own throws. */
#define NC_P_MSG_REACTION "Invalid reaction."
#define NC_P_MSG_DELETE   "Invalid delete notice."
#define NC_P_MSG_CARD     "Invalid payment card."

#define NC_DELETE_HASHES_MAX 100     /* actions.js:121 DELETE_HASHES_MAX */
#define NC_QUOTE_MAX         100     /* actions.js:243 QUOTE_MAX         */
#define NC_CARD_NAME_UNITS   64      /* actions.js:183 .slice(0, 64)     */
#define NC_REACTION_EMOJIS   8       /* actions.js:32 REACTION_EMOJIS    */

/* REACTION_EMOJIS (actions.js:32), UTF-8, in their order. */
extern const char *const nc_reaction_emojis[NC_REACTION_EMOJIS];

/* What a list element / an object argument is. */
typedef enum {
    NC_ELEM_OBJECT = 0,  /* a (flat) object: its fields are read            */
    NC_ELEM_NULL,        /* null (or, for an argument, undefined): reading a
                            property throws TypeError                       */
    NC_ELEM_OTHER        /* any other value: every property is undefined    */
} nc_elem_t;

/* `x || []` then a method call: falsy -> empty, array -> the elements,
 * any other truthy value -> TypeError when the list is used. */
typedef enum { NC_LIST_EMPTY = 0, NC_LIST_ARRAY, NC_LIST_BAD } nc_list_t;

/* A stored 1:1 message record (the fields these rules read). */
typedef struct {
    nc_elem_t elem;
    nc_val_t  dir, fp, text, ts, sender_ts, seq, kind, target;
} nc_msg_t;

/* contentHash (actions.js:39): SHA3-256 over sender ‖ recipient ‖
 * text-up-to-NUL ‖ String(BigInt(ts)), lowercase hex (the app's
 * compute_content_hash, messenger/message_backup.c:122-160). out[65].
 * NC_P_OK, NC_P_NULL, NC_P_NOMEM. */
int nc_content_hash(const nc_val_t *sender_fp, const nc_val_t *recipient_fp,
                    const nc_val_t *text, const nc_val_t *ts, char out[65]);

/* messageHash (actions.js:46). */
int nc_message_hash(const nc_msg_t *m, const nc_val_t *own_fp, char out[65]);

/* buildReaction (actions.js:54). NC_P_OK (out = the plaintext), NC_P_THROW. */
int nc_build_reaction(const nc_val_t *target, const nc_val_t *emoji,
                      const nc_val_t *op, nc_sb_t *out);

/* parseReaction (actions.js:67) over s = String(text). The fields point
 * into s. NC_P_OK or NC_P_NULL. */
typedef struct {
    const char *target; size_t target_n;
    const char *emoji;  size_t emoji_n;     /* 1..7 bytes */
    const char *op;     size_t op_n;
} nc_reaction_t;
int nc_parse_reaction(const char *s, size_t n, nc_reaction_t *out);

/* reactionSummary (actions.js:81): Map target -> [{emoji, count, mine}]. */
typedef struct { char emoji[8]; size_t emoji_n; size_t count; int mine; } nc_react_item_t;
typedef struct { char target[65]; nc_react_item_t *items; size_t n_items; } nc_react_target_t;
typedef struct { nc_react_target_t *t; size_t n; } nc_react_summary_t;
int  nc_reaction_summary(const nc_msg_t *recs, size_t n, const nc_val_t *own_fp,
                         nc_react_summary_t *out);
void nc_react_summary_free(nc_react_summary_t *s);

/* ownReactionOn (actions.js:116) over a summary given as Map entries
 * (key, list) in insertion order (a repeated key: the last list, as
 * new Map(entries) keeps it). *on = the result. NC_P_OK or
 * NC_P_TYPE_ERROR (a null list item reached before a match). */
typedef struct { nc_elem_t elem; nc_val_t emoji, mine; } nc_react_in_item_t;
typedef struct {
    const char *key; size_t key_n;
    const nc_react_in_item_t *items; size_t n_items;
} nc_react_in_pair_t;
int nc_own_reaction_on(const nc_react_in_pair_t *pairs, size_t n,
                       const nc_val_t *target, const nc_val_t *emoji, int *on);

/* buildDelete (actions.js:122): `is_array` = Array.isArray(hashes).
 * NC_P_OK or NC_P_THROW. */
int nc_build_delete(int is_array, const nc_val_t *hashes, size_t n, nc_sb_t *out);

/* parseDelete (actions.js:126) over s = String(text). */
typedef struct {
    double action;
    size_t n;
    char   hashes[NC_DELETE_HASHES_MAX][65];   /* lowercase */
} nc_delete_t;
int nc_parse_delete(const char *s, size_t n, nc_delete_t *out);

/* An insertion-ordered set of 64-hex hashes. */
typedef struct { char (*h)[65]; size_t n, cap; } nc_hashset_t;
void nc_hashset_free(nc_hashset_t *s);

/* deletions (actions.js:141). hashOf(m) is given per record: hash_of[i]
 * (a string, or null / undefined for none). NC_P_OK, NC_P_TYPE_ERROR,
 * NC_P_NOMEM. */
int nc_deletions(const nc_msg_t *recs, size_t n, const nc_val_t *own_fp,
                 const nc_val_t *hash_of, nc_hashset_t *deleted, nc_hashset_t *hidden);

/* nodusUnits (actions.js:169). NC_P_OK (*units) or NC_P_NULL. */
int nc_nodus_units(const nc_val_t *amount, unsigned __int128 *units);

/* buildTransfer (actions.js:174) over its destructured argument; `elem`
 * NC_ELEM_NULL = null / undefined (TypeError). NC_P_OK, NC_P_THROW,
 * NC_P_TYPE_ERROR. */
typedef struct { nc_elem_t elem; nc_val_t amount, wire, to, name; } nc_transfer_in_t;
int nc_build_transfer(const nc_transfer_in_t *d, nc_sb_t *out);

/* parseTransfer (actions.js:188) over s = String(text). */
typedef struct { nc_sb_t chain, amount, token, wire, to, name; } nc_transfer_t;
void nc_transfer_init(nc_transfer_t *t);
void nc_transfer_free(nc_transfer_t *t);
int  nc_parse_transfer(const char *s, size_t n, nc_transfer_t *out);

/* A card as validNodusCard / transferVerdict read it. */
typedef struct { nc_elem_t elem; nc_val_t chain, amount, token, wire, to; } nc_card_t;

/* validNodusCard (actions.js:197). */
int nc_valid_nodus_card(const nc_card_t *c);

/* transferVerdict (actions.js:208). */
typedef struct { nc_elem_t elem; nc_val_t wire, kind, peer, token, amount, h; } nc_entry_t;
typedef struct { nc_elem_t elem; nc_val_t incoming, counterparty, own_fp; } nc_verdict_opts_t;
typedef enum {
    NC_VERDICT_CONFIRMED = 0, NC_VERDICT_MISMATCH, NC_VERDICT_PENDING, NC_VERDICT_UNVERIFIABLE
} nc_verdict_state_t;
typedef struct {
    nc_verdict_state_t state;
    nc_sb_t  height;        /* CONFIRMED: String(own[0].h)                 */
    nc_val_t chain;         /* UNVERIFIABLE: card?.chain || '' (points into
                               the card or is the empty string)            */
} nc_verdict_t;
void nc_verdict_init(nc_verdict_t *v);
void nc_verdict_free(nc_verdict_t *v);
int  nc_transfer_verdict(const nc_card_t *card, nc_list_t entries_kind,
                         const nc_entry_t *entries, size_t n,
                         const nc_verdict_opts_t *opts, nc_verdict_t *out);

/* copyCards (actions.js:232). `order` is the card's BigInt (required for a
 * confirmed card object). *copies = malloc'd indices into `cards` of the
 * copies, in the JS output order. NC_P_OK, NC_P_TYPE_ERROR, NC_P_NOMEM. */
typedef struct { nc_elem_t elem; nc_val_t key, dir, wire, state; const nc_big_t *order; } nc_copy_card_t;
int nc_copy_cards(nc_list_t kind, const nc_copy_card_t *cards, size_t n,
                  size_t **copies, size_t *n_copies);

/* buildReply (actions.js:246) over String() of its three arguments. */
int nc_build_reply(const char *sender, size_t sender_n, const char *quoted, size_t quoted_n,
                   const char *text, size_t text_n, nc_sb_t *out);

/* parseReply (actions.js:252) over s = String(text). Fields point into s. */
typedef struct {
    const char *sender; size_t sender_n;
    const char *quoted; size_t quoted_n;
    const char *text;   size_t text_n;
} nc_reply_t;
int nc_parse_reply(const char *s, size_t n, nc_reply_t *out);

#ifdef __cplusplus
}
#endif
#endif /* NC_PAYLOAD_H */
