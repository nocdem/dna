/* Nodus Connect core — P1a: the contact-request, delivery, check-scheduling
 * and contact-state rules, ported from src/connect/ui/text.js and
 * src/connect/core.js (web 0.1.101; checkOrder web 0.1.111) to C
 * (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2).
 *
 * THE JAVASCRIPT IS THE SPECIFICATION. Each function below is the JS
 * function of the same name (text.js / core.js line in its comment) over
 * plain structs, with the JS accept sets, evaluation order, short-circuits
 * and throws copied (conventions of nc_payload.h, whose return codes and
 * element kinds this unit reuses):
 *   - a value the JS reads arrives as an nc_val_t (a JSON scalar or
 *     undefined); String(), ===, ToBoolean are the nc_jsjson.h ones;
 *   - numbers follow BigInt, never a wrapping uint64 (design §R R2, R5):
 *     a value that passed U64 (/^(0|[1-9]\d{0,19})$/, up to 10^20 - 1) is
 *     held in unsigned 128 bits and every JS difference `a - b > k` is
 *     computed as `a > b + k`, so a "future" time (negative difference) is
 *     exact; a value given to BigInt() WITHOUT a U64 test first (the seq of
 *     compareLocal, the ts of pendingOutbox / hasUndelivered) is an
 *     arbitrary-precision nc_big_t and throws as BigInt() throws;
 *   - BigInt(x) and BigInt(String(x)) are kept apart: for a Number above
 *     2^53 they differ (2^64 as a double: BigInt(x) = 18446744073709551616,
 *     BigInt(String(x)) = 18446744073709552000). Each site uses the one its
 *     JS line uses;
 *   - Map / Set results keep insertion order, a Map.set on an existing key
 *     keeps its place; every sort is stable (JS Array.prototype.sort is);
 *   - obj[key] for a dynamic key (dmSync[fp], seenOwn[kind],
 *     profileCache[ownFp]) is ToPropertyKey(key) = String(key); a key that
 *     names an Object.prototype property (constructor, toString, __proto__,
 *     … — the 12 of V8, nc_rules.c OBJ_PROTO) reads that inherited value
 *     when the object has no own key of that name: never undefined, always
 *     truthy, never a U64.
 * Where JS would throw, the function returns the throw: NC_P_THROW with
 * *msg = the function's own message, or the engine error's class.
 *
 * ONE engine-specific behaviour is copied: when several messages of
 * pendingOutbox's sort have a seq BigInt() refuses, WHICH error is thrown
 * depends on the order the engine's sort calls the comparator. The order
 * copied is V8's TimSort (the vectors' engine; v8 third_party array-sort.tq
 * CountAndMakeRun / BinaryInsertionSort, observed with node 22: the first
 * call is compare(a[1], a[0])). Other engines may throw another class for
 * the same input; the function throws in every engine.
 *
 * inGrace (text.js:385) is private in the JS; here it is a static of
 * nc_rules.c, reached (and vectored) only through nc_pending_outbox.
 *
 * Pure: no clock (time is an argument, decimal seconds as in JS), no
 * randomness, no global state, no network, no keys.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#ifndef NC_RULES_H
#define NC_RULES_H

#include "nc_payload.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned __int128 nc_u128_t;

/* The functions' own throw messages (text.js:24, :309, :44). */
#define NC_R_MSG_TIME "Invalid time."
#define NC_R_MSG_DAY  "Invalid day."
#define NC_R_MSG_ID   "That is not a valid ID. An ID is 128 characters, letters a\xE2\x80\x93" "f and digits."

/* requestRefusal's answers (text.js:62-67). */
#define NC_R_REFUSE_OWN       "That is your own ID."
#define NC_R_REFUSE_CONTACT   "This person is already a contact."
#define NC_R_REFUSE_REQUESTED "You already sent this person a request."

/* core.js:189 CONTACT_ACCEPTED_MSG (the app's CONTACT_ACCEPTED_MSG,
 * dna_engine_contacts.c:560-562). */
#define NC_CONTACT_ACCEPTED_MSG "Contact request accepted"

#define NC_DECLINE_KEEP_SECONDS    604800u   /* text.js:20 7n * 86400n        */
#define NC_DECLINE_MAX             200u      /* text.js:21                    */
#define NC_SMART_SYNC_FULL_SECONDS 259200u   /* text.js:255 3 * 86400         */
#define NC_PROFILE_CACHE_SECONDS   604800u   /* text.js:317 7 * 24 * 3600     */
#define NC_DELIVERED_GRACE_SECONDS 3600u     /* text.js:374 3600n             */
#define NC_OUTBOX_MAX              50u       /* text.js:431                   */
#define NC_OUTBOX_LIFETIME_SECONDS 604800u   /* text.js:432 7n * 86400n       */

/* ── inputs ─────────────────────────────────────────────────────────── */

/* A stored 1:1 message record as these rules read it (elem: nc_payload.h;
 * a non-object element reads every field as undefined). */
typedef struct {
    nc_elem_t elem;
    nc_val_t  dir, fp, ts, sender_ts, seq, kind, text, published, delivered, delivered_at, at;
} nc_rmsg_t;

/* A JS object used as a map (dmSync, profileCache, seenOwn, …): its own
 * keys, each once, with the value JSON.parse kept. object = 0: the map is
 * undefined / null. A value that is an object or an array has
 * compound[i] = 1 (val[i] is then undefined and only its truthiness, true,
 * is used). */
typedef struct {
    int                  object;
    size_t               n;
    const char *const   *key;
    const size_t        *key_n;
    const nc_val_t      *val;
    const unsigned char *compound;
} nc_rmap_t;

/* An element of a declined list (text.js:22 declinedFp): a string (is_str,
 * str = the ID), an object (elem OBJECT: fp, at), or anything else. */
typedef struct {
    nc_elem_t elem;
    int       is_str;
    nc_val_t  str, fp, at;
} nc_decl_t;

/* A { fp, at } entry declinedNow builds: fp points to the 128 hex bytes of
 * the input; at is the decimal string (a U64, at most 20 digits). */
typedef struct {
    const char *fp;
    char        at[24];
    size_t      at_n;
} nc_decl_out_t;

/* ── requests (text.js:20-67, core.js:197) ──────────────────────────── */

/* declinedNow (text.js:23). `list` / `n`: the array's elements (n = 0 for
 * a non-array, read as []). *out malloc'd (may be NULL when n_out = 0).
 * NC_P_OK, NC_P_THROW (NC_R_MSG_TIME), NC_P_NOMEM. */
int nc_declined_now(const nc_decl_t *list, size_t n, const nc_val_t *now_seconds,
                    nc_decl_out_t **out, size_t *n_out, const char **msg);
/* isDeclined (text.js:36). */
int nc_is_declined(const nc_decl_t *list, size_t n, const nc_val_t *fp);
/* addDeclined (text.js:37). Same results as nc_declined_now. */
int nc_add_declined(const nc_decl_t *list, size_t n, const nc_val_t *fp, const nc_val_t *now_seconds,
                    nc_decl_out_t **out, size_t *n_out, const char **msg);
/* undecline (text.js:40): *keep = malloc'd indices of the elements kept,
 * in order. NC_P_OK, NC_P_NOMEM. */
int nc_undecline(const nc_decl_t *list, size_t n, const nc_val_t *fp, size_t **keep, size_t *n_keep);

/* parseContactId (text.js:42): out = the 128 hex characters + NUL.
 * NC_P_OK or NC_P_THROW (NC_R_MSG_ID). JS lowercases with full-Unicode
 * toLowerCase; here ASCII only — the same result for every input: no
 * non-ASCII code point lowercases to [0-9a-f] (the only lowercase
 * mappings into ASCII are U+212A KELVIN SIGN -> 'k' and U+0130 -> 'i'
 * U+0307), so any non-ASCII character left after the whitespace removal
 * fails /^[0-9a-f]{128}$/ in both. */
int nc_parse_contact_id(const nc_val_t *value, char out[129], const char **msg);

/* requestRefusal (text.js:62): the second argument destructured with
 * defaults. absent = 1: the argument is undefined (= {}); elem NULL: null
 * (TypeError). *text = one of the NC_R_REFUSE_* or "". NC_P_OK or
 * NC_P_TYPE_ERROR. */
typedef struct { int absent; nc_elem_t elem; nc_val_t own_fp, is_contact, is_requested; } nc_refusal_opts_t;
int nc_request_refusal(const nc_val_t *fp, const nc_refusal_opts_t *opts, const char **text);

/* acceptanceMayAutoApprove (core.js:197, the app's HIGH-7 rule,
 * dna_engine_contacts.c:555-562): the acceptance is honoured only with a
 * pending outgoing request to that sender. pending_is_set: the second
 * argument is a Set (its elements `pending`); otherwise false. There is no
 * own-ID test here: the caller skips its own ID first (messages.js
 * syncRequests). */
typedef struct { nc_elem_t elem; nc_val_t acceptance, message, sender; } nc_accept_req_t;
int nc_acceptance_may_auto_approve(const nc_accept_req_t *request, int pending_is_set,
                                   const nc_val_t *pending, size_t n_pending);

/* acceptedSalt (text.js): `mine?.salt || request.salt || null` — the salt
 * a contact completed by an acceptance keeps. The web keeps OUR offered
 * salt; the frozen app stores the accepter's (dna_engine_contacts.c:
 * 570-574): deliberate, Kurultay #17 item 5. *out = the value (a truthy
 * scalar) or null. NC_P_OK or NC_P_TYPE_ERROR (request null / undefined
 * and mine has no truthy salt). */
typedef struct { nc_elem_t elem; nc_val_t salt; } nc_salt_of_t;
int nc_accepted_salt(const nc_salt_of_t *mine, const nc_salt_of_t *request, nc_val_t *out);

/* ── delivery (text.js:349-486) ─────────────────────────────────────── */

/* isDelivered (text.js:349): message?.delivered === true. */
int nc_is_delivered(const nc_rmsg_t *m);
/* messageStatus (text.js:352): "delivered", "sent" or "waiting to send". */
const char *nc_message_status(const nc_rmsg_t *m);

/* The list arguments: kind = NC_LIST_ARRAY with the elements, NC_LIST_BAD
 * when the JS method call / iteration throws TypeError on it, or
 * NC_LIST_EMPTY where the JS reads it as no elements (`x || []` of a
 * falsy value, or for…of over a string: its one-character strings have no
 * field the rule reads). */

/* publishedSeqs (text.js:358): *first = malloc'd indices of the messages
 * whose String(seq) enters the Set first, in Set order. NC_P_OK,
 * NC_P_TYPE_ERROR, NC_P_NOMEM. */
int nc_published_seqs(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      size_t **first, size_t *n_first);

/* markPublished (text.js:364): `set` = the published entries (their seq is
 * read). *idx = malloc'd indices of the messages copied as
 * { ...m, published: true }. */
int nc_mark_published(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      nc_list_t set_kind, const nc_rmsg_t *set, size_t n_set,
                      size_t **idx, size_t *n_idx);

/* markDelivered (text.js:375): before_is_set: publishedBefore is a Set
 * (its elements `before`). *idx = the messages copied as
 * { ...m, delivered: true, deliveredAt: nowSeconds }. NC_P_OK, NC_P_THROW
 * (NC_R_MSG_TIME, only after the ackTs / Set test), NC_P_TYPE_ERROR,
 * NC_P_NOMEM. */
int nc_mark_delivered(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      const nc_val_t *ack_ts, int before_is_set, const nc_val_t *before, size_t n_before,
                      const nc_val_t *now_seconds, size_t **idx, size_t *n_idx, const char **msg);

/* ackToSend (text.js:395): *has = 0 for null, else *value. */
int nc_ack_to_send(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                   const nc_val_t *last_sent, int *has, nc_u128_t *value);

/* ackAllowed (text.js:412) over its destructured argument; elem NULL:
 * null / undefined (TypeError). */
typedef struct { nc_elem_t elem; nc_val_t persistent, complete, lost; } nc_ack_flags_t;
int nc_ack_allowed(const nc_ack_flags_t *f, int *allowed);

/* pendingOutbox (text.js:433): *out = malloc'd indices of the messages
 * sent as { seq, ts, text }, in the JS order. NC_P_OK, NC_P_THROW
 * (NC_R_MSG_TIME), NC_P_TYPE_ERROR / NC_P_RANGE_ERROR / NC_P_SYNTAX_ERROR
 * (BigInt of a ts or seq; or reading a field of null), NC_P_UNSUPPORTED,
 * NC_P_NOMEM. */
int nc_pending_outbox(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      const nc_val_t *now_seconds, size_t **out, size_t *n_out, const char **msg);

/* hasUndelivered (text.js:469). */
int nc_has_undelivered(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                       const nc_val_t *now_seconds, int *has, const char **msg);

/* compareLocal (text.js:477): *order = -1, 0 or 1. a / b elem NULL: null or
 * undefined. */
int nc_compare_local(const nc_rmsg_t *a, const nc_rmsg_t *b, int *order);

/* receivedKey (text.js:484): out = JSON.stringify([fp, String(seq),
 * String(senderTs), text]). NC_P_OK, NC_P_TYPE_ERROR, NC_P_NOMEM. */
int nc_received_key(const nc_val_t *fp, const nc_rmsg_t *m, nc_sb_t *out);

/* ── check scheduling (text.js:256-329) ─────────────────────────────── */

/* contactNeedsFullSync (text.js:266). NC_P_OK or NC_P_THROW (time). */
int nc_contact_needs_full_sync(const nc_val_t *fp, const nc_rmap_t *dm_sync, const nc_val_t *now,
                               int *full, const char **msg);
/* needFullSync (text.js:256): fps = contactFps' elements. */
int nc_need_full_sync(nc_list_t kind, const nc_val_t *fps, size_t n, const nc_rmap_t *dm_sync,
                      const nc_val_t *now, int *full, const char **msg);
/* fullDays (text.js:308) / recentDays (:325): days[] in order, at most 8.
 * NC_P_OK or NC_P_THROW (NC_R_MSG_DAY). */
int nc_full_days(const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg);
int nc_recent_days(const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg);
/* contactDays (text.js:273). */
int nc_contact_days(const nc_val_t *fp, const nc_rmap_t *dm_sync, const nc_val_t *now,
                    const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg);

/* checkOrder (text.js:320, web 0.1.111): contacts (elem, fp read) and
 * messages (elem, fp, seq, at, dir, senderTs read). A message counts when
 * its fp is a string, String(seq) passes U64 and `at` is a Number that is
 * a safe integer (|at| <= 2^53 - 1); its time is shownAt (text.js:257):
 * for dir 'in' with a U64 senderTs string s, s * 1000 when that is a safe
 * integer and <= at, else at. Every time compared is therefore a safe
 * integer, held exactly in int64 — no floating-point comparison. Contacts
 * with a counted message come first, newest time first, then greater seq
 * (BigInt(String(seq))); then the rest; ties keep list order. *order =
 * malloc'd indices into contacts: the JS returns the SAME contact objects
 * in this order (a caller outside JS must map them back by fp, design §R
 * R3). msg_kind NC_LIST_EMPTY: `messages || []` of a falsy value, or a
 * string. */
int nc_check_order(nc_list_t kind, const nc_rmsg_t *contacts, size_t n,
                   nc_list_t msg_kind, const nc_rmsg_t *msgs, size_t n_msgs,
                   size_t **order);

/* profileFresh (text.js:318): entry elem + at (the `at` field read). */
int nc_profile_fresh(const nc_rmsg_t *entry, const nc_val_t *entry_at, const nc_val_t *now);

/* ── contact state (text.js:494-565) ─────────────────────────────────── */

typedef struct { nc_elem_t elem; nc_val_t fp, salt, listed; } nc_rcontact_t;

/* The Messages state as the contact-state rules read it.
 *   elem      NULL: null / undefined; OTHER: a non-null scalar (every field
 *             undefined); OBJECT.
 *   falsy     ToBoolean(state) is false.
 *   contacts  kind ARRAY with the elements, else BAD (not an array).
 *   removed   removed_array: an array (its elements); else undefined / null.
 *   the maps  .object = 0 when undefined / null. */
typedef struct {
    nc_elem_t            elem;
    int                  falsy;
    nc_list_t            contacts_kind;
    const nc_rcontact_t *contacts;
    size_t               n_contacts;
    int                  removed_array;
    const nc_val_t      *removed;
    size_t               n_removed;
    nc_rmap_t            dm_sync, profile_cache, chain_names, chain_no_name, seen_own;
} nc_rstate_t;

/* mergeListedContacts (text.js:494): the edits the JS makes, in its order:
 *   PUSH    state.contacts.push({ fp: entry.fp, salt: entry.salt || null,
 *           listed: true }) — the new contact's index is `contact`;
 *   SALT    contacts[contact].salt = entries[entry].salt;
 *   LISTED  contacts[contact].listed = true.
 * *edits malloc'd; *changed = the return value. NC_P_OK, NC_P_TYPE_ERROR,
 * NC_P_NOMEM. */
typedef enum { NC_EDIT_PUSH = 0, NC_EDIT_SALT, NC_EDIT_LISTED } nc_edit_kind_t;
typedef struct { nc_edit_kind_t kind; size_t contact; size_t entry; } nc_contact_edit_t;
int nc_merge_listed_contacts(const nc_rstate_t *state, nc_list_t entries_kind,
                             const nc_rcontact_t *entries, size_t n_entries, const nc_val_t *own_fp,
                             nc_contact_edit_t **edits, size_t *n_edits, int *changed);

/* removeContact (text.js:517): when *removed, the JS spliced contacts[index],
 * pushed fp to state.removed when push_removed, deleted String(fp) from
 * dmSync, profileCache, chainNames, and from chainNoName when
 * del_no_name. NC_P_OK or NC_P_TYPE_ERROR. */
typedef struct { int removed; size_t index; int push_removed; int del_no_name; } nc_remove_out_t;
int nc_remove_contact(const nc_rstate_t *state, const nc_val_t *fp, nc_remove_out_t *out);

/* unremoveContact (text.js:531): *keep = the indices of state.removed kept.
 * NC_P_OK, NC_P_TYPE_ERROR, NC_P_NOMEM. */
int nc_unremove_contact(const nc_rstate_t *state, const nc_val_t *fp, size_t **keep, size_t *n_keep);

/* ownRecordSeen (text.js:547) / firstRecordAllowed (:554). */
int nc_own_record_seen(const nc_rstate_t *state, const nc_val_t *own_fp, const nc_val_t *kind);
int nc_first_record_allowed(const nc_rstate_t *state, const nc_val_t *own_fp, const nc_val_t *kind);

/* markOwnRecordSeen (text.js:559): *result = the return value; when it is
 * true the JS set state.seenOwn = {} first when create_seen_own, then
 * state.seenOwn[kind] = String(nowSec). A truthy non-object state throws
 * TypeError (state.seenOwn = {} assigns a property to a primitive, which
 * strict mode — an ES module — refuses). NC_P_OK or NC_P_TYPE_ERROR. */
typedef struct { int result; int create_seen_own; } nc_mark_seen_out_t;
int nc_mark_own_record_seen(const nc_rstate_t *state, const nc_val_t *kind, nc_mark_seen_out_t *out);

/* profileCache[ownFp] / seenOwn[kind]-style own-or-inherited lookup of
 * a map (see the header): 0 undefined, 1 own (*v, *compound), 2 inherited
 * from Object.prototype. */
int nc_rmap_get(const nc_rmap_t *m, const char *key, size_t key_n, nc_val_t *v, int *compound);

/* A stable merge sort of indices (ties keep their order, as JS
 * Array.prototype.sort): idx[0..n) reordered by cmp(ctx, idx_a, idx_b).
 * 0, or -1 when out of memory (idx unchanged). Also used by the JSON
 * layer (nc_rules_json.c) to order an object's keys as JavaScript does. */
int nc_stable_sort(size_t *idx, size_t n, int (*cmp)(const void *ctx, size_t a, size_t b), const void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* NC_RULES_H */
