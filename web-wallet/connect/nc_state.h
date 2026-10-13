/* Nodus Connect core — P7 stage 1: the Messages state schema version 2
 * and its codec (docs/plans/2026-10-13-connect-core-p7-state-design.md
 * rev 2: §2.0, §2.1, §2.2, §2.5, D1, D2; Kurultay #19,
 * decisions/2026-10-13-kurultay-19-summary.md; Kurultay #17 item 4,
 * decisions/2026-10-12-kurultay-17-summary.md).
 *
 * STAGE 2 (rev 2.1): used by the web storage backend, src/connect/store.js,
 * through the wasm exports nc_state_project / nc_state_load (nc_wasm.c).
 * The page keeps its in-memory state in the v1 shape until P3 (design
 * §2.0); this codec turns it into the v2 records on save (PROJECTION) and
 * back on open (LOAD). The commit protocol (reservation, one commit in
 * flight, baseline, diff) is the platform backend's (§2.0, §2.3) and is
 * NOT here.
 *
 * Pure: no I/O, no clock (D4), no keys, no randomness, no global state.
 * JSON is read with nc_jsjson.h (JSON.parse exact) and written by hand in
 * the JSON.stringify form (nc_js_write_string); no new number semantics —
 * every u64 is the decimal text the JavaScript regex U64
 * /^(0|[1-9]\d{0,19})$/ accepts (store.js:66), up to 10^20 − 1, held in
 * unsigned __int128 where arithmetic is needed.
 *
 * ── PROJECTION (v1 -> v2), nc_state_project_json ───────────────────────
 * Input: the v1 state as JSON text (the page's JSON.stringify of its
 * in-memory object — the same bytes store.js plaintextBytes seals today)
 * and the previous fp -> id map as JSON text ({} on migration, §2.2).
 *   1. The v1 GATE: store.js checkState (:246-269), exactly — the defaults
 *      for absent keys (:250, :252) and every test it makes, including
 *      String(x) of a non-string (String(["5"]) is "5", String([1,2]) is
 *      "1,2", an object is "[object Object]"). A refusal is
 *      reason "checkState" (the page's 'The stored contact list is
 *      damaged.').
 *   2. DROPPED (design rev 2.1 item 1: a v1 state that passes checkState
 *      ALWAYS migrates, G5). checkState leaves fields unchecked that v2
 *      has to give a typed destination (§2.1). A key no code reads is
 *      left out; a known field whose value v2 cannot hold takes the
 *      field's default; an entry that has no default is left out whole.
 *      Each is listed in the result's "dropped" (below) — never refused:
 *        - top level: a key other than the v1 keys (emptyState,
 *          store.js:230) and listTaken (messages.js:524/535) -> "<key>";
 *        - contacts[i] / outgoing[i] that is not an object with a 128
 *          lowercase hex fp: the entry -> "contacts[i]" (no default exists
 *          for an ID);
 *        - contacts[i]: a key other than {fp, salt, listed} ->
 *          "contacts[i].<key>"; salt not absent / null / 64 lowercase hex
 *          -> none (null), "contacts[i].salt"; listed not absent / boolean
 *          -> false, "contacts[i].listed" (the values messages.js:500 /
 *          text.js:534 write);
 *        - outgoing[i]: a key other than {fp, salt, at}; salt as above;
 *          at not U64 by String() -> "0", "outgoing[i].at" (messages.js:2478
 *          writes it; NO page code reads it — messages.js pendingOf :480 and
 *          the "Sent by you" list :1870 use fp and salt — so the request
 *          and its salt are kept rather than lost; "0" is no clock, D4);
 *        - declined[i] that is an object: a key other than {fp, at};
 *        - acks: a NON-EMPTY array (checkState lets an array through; an
 *          empty one is simply {}) -> {}, "acks";
 *        - acks / ackSent: an entry whose key is not 128 hex or whose value
 *          is not U64 by String() (messages.js:1003, :1084 write U64
 *          strings) -> absent, "acks[j]"; profileCache / dmSync: an entry
 *          whose key is not 128 hex (checkState checks only the values,
 *          store.js:262-264) -> absent, "profileCache[j]" — j is the
 *          entry's position among the map's keys in input order, NOT the
 *          key: a key is an ID, and these paths go to the session log;
 *        - a key other than {id, at, name} in a profileCache value, {name,
 *          at} in a chainNames value, {id, at} in a vaults / groups value
 *          -> "profileCache[j].<key>" (likewise);
 *        - listTaken not absent / boolean -> absent (false), "listTaken".
 *      "dropped" is sorted ascending by bytes ("contacts[10]" before
 *      "contacts[2]") with each path once. The checks are made for every
 *      entry, also one the dedup below then does not keep.
 *      The ONLY refusals of a JSON state are therefore "checkState" — plus
 *      "map" (the previous map, not the state) and "nextSeq" (an
 *      allocation past 10^20 − 1), below.
 *   3. The dedup rules of the page, verbatim (§2.2 item 2, D1):
 *        contacts — the FIRST entry of an fp wins (contactOf,
 *        messages.js:469); outgoing — `new Map(outgoing.map(o => [o.fp,
 *        o])).values()` (messages.js:317): the LAST entry's value at the
 *        FIRST entry's position.
 *   4. IDs (§2.1 "IDs stay stable", §2.2 item 3): an fp in the previous map
 *      keeps its id; the others get 'c' + 20 digits from nextSeq, in this
 *      order: the contacts (kept contacts[] order), then the outgoing-only
 *      fps (kept outgoing order), then every other fp of a per-ID map
 *      (acks, ackSent, profileCache, dmSync, chainNames, chainNoName),
 *      ascending by fp. nextSeq advances by the count allocated. The map
 *      is refused (reason "map") unless it is an object of 128-hex keys and
 *      'c' + 20-digit values, no id twice, every id below nextSeq (an id at
 *      or above it would collide with the next allocation). An fp of the
 *      map that no longer has a field is dropped; its id is not reused.
 *      An allocation past 10^20 − 1 is refused (reason "nextSeq").
 *   5. removed: the LAST NC_STATE_REMOVED_MAX entries are kept (the oldest,
 *      earliest, are dropped; §2.1 Bounds). declined: kept as it is — the
 *      7-day / 200 rule (text.js declinedNow) needs a clock and stays where
 *      it is applied today; a bare-ID entry stays a bare ID.
 * Output: { "status": "ok", "nextSeq": "<advanced>", "header": "<text>",
 *   "records": [ { "id": "c…", "fp": "<128 hex>", "json": "<text>" }, … ],
 *   "dropped": [ "<path>", … ] } with the records ascending by id, or
 *   { "status": "invalid", "reason": "…" } — reason "json" (the input is
 *   not JSON), "checkState", "map" or "nextSeq".
 *
 * ── CANONICAL BYTES (D2) ───────────────────────────────────────────────
 * No whitespace; the §2.1 field order; an absent optional is left out;
 * every u64 a decimal STRING (String(x) of the v1 value); version and net.v
 * the numbers 2 and 1; strings written as JSON.stringify writes them.
 * Maps keyed by an address (vaults, groups) are ascending by key; seenOwn
 * is in the order profile, list (store.js SEEN_OWN_KINDS) — §2.1 does not
 * order these, this file does.
 *   header ('state'):
 *     {"version":2,"nextSeq":"N","ids":["c…",…ascending],"removed":[…],
 *      "declined":[<"fp"> | {"fp":…,"at":"N"}, …],
 *      "vaults":{"<addr>":{"id":"v…","at":"N"},…},
 *      "groups":{"<gid>":{"id":"g…","at":"N"},…},
 *      "net":{"v":1[,"seenOwn":{["profile":"N"][,"list":"N"]}][,"listTaken":true]}}
 *   known ID ('c' + 20 digits):
 *     {"fp":"<128 hex>"[,"contact":{}][,"pending":{"at":"N"}]
 *      [,"profile":{"id":"p…","at":"N","name":"…"}]
 *      [,"chainName":{"name":"…","at":"N"}][,"chainNoName":"N"]
 *      [,"net":{"v":1[,"salt":"…"][,"pendingSalt":"…"][,"listed":true]
 *               [,"ack":"N"][,"ackSent":"N"][,"dmSync":"N"]}]}
 *   "net" is present only when one of its fields is; "listed" only when
 *   true; a record exists iff a field besides fp is set (§2.1 Lifetime).
 *
 * ── LOAD (v2 -> v1), nc_state_load_json ────────────────────────────────
 * Input: { "header": "<text>", "records": [ { "id": "c…", "json":
 * "<text>" }, … ] } — every 'c…' record the page read (unlisted ones are
 * ignored: only the header's ids are authoritative, §2.5).
 * Fail closed (§2.5) -> { "status": "damaged", "reason": … }:
 *   "input"          the wrapper is not that shape, or an id twice;
 *   "header"         the header is not a JSON object with an ids array of
 *                    'c' + 20-digit strings;
 *   "version"        header.version is not the number 2, or a net.v (header
 *                    or record) is not the number 1;
 *   "missing record" an id the header lists has no record;
 *   "bad record"     a listed record is not a JSON object with a 128-hex fp;
 *   "duplicate fp"   two listed records have the same fp;
 *   "not canonical"  the v1 object rebuilt from the records, projected
 *                    again with the loaded fp -> id map, does not give back
 *                    the stored header and records byte for byte, or drops
 *                    anything (any bad field, unknown field, wrong order, a
 *                    record holding only its fp, a removed list over the
 *                    cap, a pending flag without its time, …). Load never
 *                    applies the DROPPED defaults: they are for the v1 →
 *                    v2 migration only.
 * Otherwise { "status": "ok", "state": <the canonical v1 object>,
 *             "map": { "<fp>": "c…", … } }.
 * The canonical v1 object: the keys of emptyState in its order
 * (version, nextSeq, contacts, outgoing, declined, removed, acks, ackSent,
 * profileCache, dmSync, chainNames, chainNoName, vaults, groups, seenOwn)
 * then "listTaken": true when set; contacts {fp, salt (hex | null),
 * listed} and outgoing {fp, salt (hex | null), at}, both in ascending id
 * order, as are the per-ID maps. Because LOAD is checked by re-projection,
 * v1 -> v2 -> v1 is the identity on this canonical form (§2.1), and
 * projecting the loaded object with the loaded map gives the same bytes.
 * A v1 contact order that differs from id order (an fp that had a record
 * before it became a contact) comes back in id order: v2 keeps no other
 * order (§2.1 has no order field).
 *
 * MIGRATION (§2.2) = PROJECTION with the map {}.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#ifndef NC_STATE_H
#define NC_STATE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_STATE_VERSION      2      /* header.version                 */
#define NC_STATE_NET_V        1      /* net.v (DHT-protocol fields, §2.0) */
#define NC_STATE_REMOVED_MAX  1000   /* §2.1 Bounds                     */

/* v1 state + previous map -> the v2 records (see above). Both inputs are
 * bytes (not NUL-terminated; a NUL is data). On success *out is a
 * malloc'd NUL-terminated JSON text (the result object) of *out_len bytes
 * and 0 is returned; -1 only when out of memory or an argument pointer is
 * NULL. A refused input is a result ("invalid"), not -1. */
int nc_state_project_json(const char *state, size_t state_len,
                          const char *map, size_t map_len,
                          char **out, size_t *out_len);

/* The same, both inputs in ONE text: { "state": "<the v1 state as JSON
 * text>", "map": "<the map as JSON text>" } — two JSON STRINGS, so that
 * the wasm export (nc_wasm.c nc_state_project, one heap input buffer)
 * answers exactly what nc_state_project_json answers for those two texts,
 * the shared vectors included. Not that shape -> "invalid" with reason
 * "json" (not an object, or "state" not a string) or "map" ("map" not a
 * string). Same return convention. */
int nc_state_project_wrapped_json(const char *in, size_t in_len, char **out, size_t *out_len);

/* The v2 records -> the v1 state and the fp -> id map, or "damaged". Same
 * return convention. */
int nc_state_load_json(const char *in, size_t in_len, char **out, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* NC_STATE_H */
