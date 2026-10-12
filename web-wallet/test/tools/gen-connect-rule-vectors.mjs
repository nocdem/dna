// P1 rules — the shared vectors, generated FROM the JavaScript
// (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2, §2, §5).
//
//   node test/tools/gen-connect-rule-vectors.mjs
//     -> test/vectors/connect-rules/payload.json   (P1b: actions.js)
//     -> test/vectors/connect-rules/rules.json     (P1a: text.js, and
//        core.js acceptanceMayAutoApprove)
//
// The functions of src/connect/ui/actions.js, src/connect/ui/text.js and
// src/connect/core.js are the specification: every
// vector's "expect" is what the JS function returns for its "args", through
// the SAME argument contract and result encoding as the C dispatcher
// (connect/nc_rules_json.h). A mutator (mergeListedContacts, removeContact,
// unremoveContact, markOwnRecordSeen) is encoded as { result, state }: its
// return value and the state object after the call (an undefined one left
// out, as JSON.stringify does). A vector is
//   { "rule": "<JS function name>", "args": "<JSON text>",
//     "expect": "<JSON text>", "gap": "<reason>" (only when known) }
// args / expect are JSON TEXTS so both sides compare exact bytes.
//
// Encoding (design rev 2 §5): a Set -> an array in insertion order; a Map ->
// an array of [key, value] pairs in insertion order; a BigInt -> its decimal
// string; `throw new Error(msg)` -> {"error": msg}; an engine TypeError /
// RangeError / SyntaxError -> {"error": "<name>"} (the class, not the
// engine's wording). Anything else this generator would have to serialise —
// a Map, Set, BigInt or function outside those places, undefined, a symbol,
// a non-finite number, a class instance — makes it THROW instead of writing
// a wrong expectation (JSON.stringify would turn a Set into {} silently).
//
// "gap": a behaviour the C port knowingly does not reproduce, marked by
// hand on the case that shows it. Today one: full-Unicode toLowerCase (C
// lowercases ASCII only; whether the JS changes is the operator's call). It
// is written and run like every vector; on the C side it FAILS — a failure
// like any other. The mark only names the reason. Lone surrogates, integer
// literals of any size and NUL / repeated keys are NOT gaps: the C JSON
// front-end (connect/nc_jsjson.h) keeps them as JSON.parse does.
//
// This module is also imported by test/connect-rules-vectors.test.js
// (jsRule, the argument contract + encoding); it writes only when run.
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import * as A from '../../src/connect/ui/actions.js';
import * as T from '../../src/connect/ui/text.js';
import { acceptanceMayAutoApprove, CONTACT_ACCEPTED_MSG } from '../../src/connect/core.js';
import { emptyState } from '../../src/connect/store.js';

// ── the argument contract (mirror of connect/nc_rules_json.c) ────────────
const BAD = JSON.stringify({ error: 'nc_rule: bad arguments' });
class Bad extends Error {}
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isScalar = v => v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);

function scalar(args, key) {
  if (!own(args, key)) return undefined;
  if (!isScalar(args[key])) throw new Bad();
  return args[key];
}
// an object argument / list element: a JSON object must be flat
function elem(v) {
  if (isObject(v) && !Object.values(v).every(isScalar)) throw new Bad();
  return v;
}
function elemArg(args, key) { return own(args, key) ? elem(args[key]) : undefined; }
function records(args) {
  if (!own(args, 'records') || !Array.isArray(args.records)) throw new Bad();
  return args.records.map(elem);
}
// `x || []` lists: an array's elements follow the element rule
function listArg(args, key) {
  if (!own(args, key)) return undefined;
  const v = args[key];
  if (Array.isArray(v)) return v.map(elem);
  return v;
}
const CANONICAL_BIGINT = /^(0|-?[1-9][0-9]*)$/;

// P1a (text.js, core.js) — mirror of nc_rules_json.c's P1a readers.
// A Set argument: an array is the Set's elements in insertion order (each a
// scalar); anything else is passed as it is (not a Set).
function setArg(args, key) {
  if (!own(args, key)) return undefined;
  const v = args[key];
  if (!Array.isArray(v)) return v;
  if (!v.every(isScalar)) throw new Bad();
  return new Set(v);
}
// A list of scalars (contactFps): an array's elements must be scalars.
function scalarListArg(args, key) {
  if (!own(args, key)) return undefined;
  const v = args[key];
  if (Array.isArray(v) && !v.every(isScalar)) throw new Bad();
  return v;
}
// dmSync as an argument: absent, null or a flat object.
function flatMapArg(args, key) {
  if (!own(args, key)) return undefined;
  const v = args[key];
  if (v === null || (isObject(v) && Object.values(v).every(isScalar))) return v;
  throw new Bad();
}
// The Messages state: not an array; when an object — contacts (if an array)
// of flat elements; removed absent, null or an array of scalars; the maps
// absent, null or a non-array object (any values); other fields anything.
const STATE_MAPS = ['dmSync', 'profileCache', 'chainNames', 'chainNoName', 'seenOwn'];
function stateArg(args) {
  if (!own(args, 'state')) return undefined;
  const s = args.state;
  if (Array.isArray(s)) throw new Bad();
  if (!isObject(s)) return s;
  if (Array.isArray(s.contacts)) s.contacts.forEach(elem);
  if (own(s, 'removed') && s.removed !== null && !(Array.isArray(s.removed) && s.removed.every(isScalar))) throw new Bad();
  for (const k of STATE_MAPS) if (own(s, k) && s[k] !== null && !isObject(s[k])) throw new Bad();
  return s;
}
// A mutator's result: its return value and the state after the call.
function mutated(state, result) {
  const out = {};
  if (result !== undefined) out.result = result;
  if (state !== undefined) out.state = state;
  return out;
}

const RULES = {
  contentHash: a => A.contentHash(scalar(a, 'senderFp'), scalar(a, 'recipientFp'), scalar(a, 'text'), scalar(a, 'ts')),
  messageHash: a => { const ownFp = scalar(a, 'ownFp'); return A.messageHash(elemArg(a, 'm'), ownFp); },
  buildReaction: a => { const t = scalar(a, 'target'), e = scalar(a, 'emoji'), o = scalar(a, 'op'); return A.buildReaction(t, e, o); },
  parseReaction: a => A.parseReaction(scalar(a, 'text')),
  reactionSummary: a => { const o = scalar(a, 'ownFp'); return A.reactionSummary(records(a), o); },
  ownReactionOn: a => {
    const t = scalar(a, 'target'), e = scalar(a, 'emoji');
    if (!own(a, 'summary') || !Array.isArray(a.summary)) throw new Bad();
    for (const p of a.summary) {
      if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== 'string' || !Array.isArray(p[1])) throw new Bad();
      p[1].forEach(elem);
    }
    return A.ownReactionOn(new Map(a.summary), t, e);
  },
  buildDelete: a => {
    const h = own(a, 'hashes') ? a.hashes : undefined;
    if (Array.isArray(h) && !h.every(isScalar)) throw new Bad();
    return A.buildDelete(h);
  },
  parseDelete: a => A.parseDelete(scalar(a, 'text')),
  deletions: a => {
    const o = scalar(a, 'ownFp');
    const recs = records(a);
    if (!own(a, 'hashes') || !Array.isArray(a.hashes) || a.hashes.length !== recs.length ||
        !a.hashes.every(h => h === null || typeof h === 'string')) throw new Bad();
    const index = new Map(recs.map((m, i) => [m, i]));
    return A.deletions(recs, o, m => a.hashes[index.get(m)]);
  },
  nodusUnits: a => A.nodusUnits(scalar(a, 'amount')),
  buildTransfer: a => A.buildTransfer(elemArg(a, 'detail')),
  parseTransfer: a => A.parseTransfer(scalar(a, 'text')),
  validNodusCard: a => A.validNodusCard(elemArg(a, 'card')),
  transferVerdict: a => {
    const card = elemArg(a, 'card'), entries = listArg(a, 'entries'), opts = elemArg(a, 'opts');
    return A.transferVerdict(card, entries, opts);
  },
  copyCards: a => {
    let cards = listArg(a, 'cards');
    if (Array.isArray(cards)) {
      cards = cards.map(c => {
        if (!isObject(c) || c.state !== 'confirmed') return c;
        if (typeof c.order !== 'string' || !CANONICAL_BIGINT.test(c.order)) throw new Bad();
        return { ...c, order: BigInt(c.order) };            // the BigInt the page passes
      });
    }
    return A.copyCards(cards);
  },
  buildReply: a => { const s = scalar(a, 'senderLabel'), q = scalar(a, 'quoted'), t = scalar(a, 'text'); return A.buildReply(s, q, t); },
  parseReply: a => A.parseReply(scalar(a, 'text')),

  // P1a: text.js and core.js
  declinedNow: a => { const l = listArg(a, 'list'), n = scalar(a, 'nowSeconds'); return T.declinedNow(l, n); },
  isDeclined: a => { const l = listArg(a, 'list'), f = scalar(a, 'fp'); return T.isDeclined(l, f); },
  addDeclined: a => { const l = listArg(a, 'list'), f = scalar(a, 'fp'), n = scalar(a, 'nowSeconds'); return T.addDeclined(l, f, n); },
  undecline: a => { const l = listArg(a, 'list'), f = scalar(a, 'fp'); return T.undecline(l, f); },
  parseContactId: a => T.parseContactId(scalar(a, 'value')),
  requestRefusal: a => { const f = scalar(a, 'fp'), o = elemArg(a, 'opts'); return T.requestRefusal(f, o); },
  acceptanceMayAutoApprove: a => { const r = elemArg(a, 'request'), p = setArg(a, 'pendingOutgoing'); return acceptanceMayAutoApprove(r, p); },
  acceptedSalt: a => { const m = elemArg(a, 'mine'), r = elemArg(a, 'request'); return T.acceptedSalt(m, r); },
  isDelivered: a => T.isDelivered(elemArg(a, 'message')),
  messageStatus: a => T.messageStatus(elemArg(a, 'message')),
  publishedSeqs: a => { const m = listArg(a, 'messages'), f = scalar(a, 'fp'); return T.publishedSeqs(m, f); },
  markPublished: a => { const m = listArg(a, 'messages'), f = scalar(a, 'fp'), s = listArg(a, 'set'); return T.markPublished(m, f, s); },
  markDelivered: a => {
    const m = listArg(a, 'messages'), f = scalar(a, 'fp'), k = scalar(a, 'ackTs'), b = setArg(a, 'publishedBefore'), n = scalar(a, 'nowSeconds');
    return T.markDelivered(m, f, k, b, n);
  },
  ackToSend: a => { const m = listArg(a, 'messages'), f = scalar(a, 'fp'), l = scalar(a, 'lastSent'); return T.ackToSend(m, f, l); },
  ackAllowed: a => T.ackAllowed(elemArg(a, 'flags')),
  pendingOutbox: a => { const m = listArg(a, 'messages'), f = scalar(a, 'fp'), n = scalar(a, 'nowSeconds'); return T.pendingOutbox(m, f, n); },
  hasUndelivered: a => { const m = listArg(a, 'messages'), f = scalar(a, 'fp'), n = scalar(a, 'nowSeconds'); return T.hasUndelivered(m, f, n); },
  compareLocal: a => { const x = elemArg(a, 'a'), y = elemArg(a, 'b'); return T.compareLocal(x, y); },
  receivedKey: a => { const f = scalar(a, 'fp'), m = elemArg(a, 'message'); return T.receivedKey(f, m); },
  contactNeedsFullSync: a => { const f = scalar(a, 'fp'), d = flatMapArg(a, 'dmSync'), n = scalar(a, 'now'); return T.contactNeedsFullSync(f, d, n); },
  needFullSync: a => { const c = scalarListArg(a, 'contactFps'), d = flatMapArg(a, 'dmSync'), n = scalar(a, 'now'); return T.needFullSync(c, d, n); },
  contactDays: a => {
    const f = scalar(a, 'fp'), d = flatMapArg(a, 'dmSync'), n = scalar(a, 'now'), t = scalar(a, 'today');
    return T.contactDays(f, d, n, t);
  },
  fullDays: a => T.fullDays(scalar(a, 'today')),
  recentDays: a => T.recentDays(scalar(a, 'today')),
  checkOrder: a => { const c = listArg(a, 'contacts'), d = flatMapArg(a, 'dmSync'), m = listArg(a, 'messages'); return T.checkOrder(c, d, m); },
  profileFresh: a => { const e = elemArg(a, 'entry'), n = scalar(a, 'now'); return T.profileFresh(e, n); },
  mergeListedContacts: a => {
    const s = stateArg(a), e = listArg(a, 'entries'), o = scalar(a, 'ownFp');
    const r = T.mergeListedContacts(s, e, o);
    return mutated(s, r);
  },
  removeContact: a => { const s = stateArg(a), f = scalar(a, 'fp'); const r = T.removeContact(s, f); return mutated(s, r); },
  unremoveContact: a => { const s = stateArg(a), f = scalar(a, 'fp'); const r = T.unremoveContact(s, f); return mutated(s, r); },
  ownRecordSeen: a => { const s = stateArg(a), o = scalar(a, 'ownFp'), k = scalar(a, 'kind'); return T.ownRecordSeen(s, o, k); },
  firstRecordAllowed: a => { const s = stateArg(a), o = scalar(a, 'ownFp'), k = scalar(a, 'kind'); return T.firstRecordAllowed(s, o, k); },
  markOwnRecordSeen: a => { const s = stateArg(a), k = scalar(a, 'kind'), n = scalar(a, 'nowSec'); const r = T.markOwnRecordSeen(s, k, n); return mutated(s, r); }
};
export const RULE_NAMES = Object.freeze(Object.keys(RULES));

// ── the result encoding (design rev 2 §5) ────────────────────────────────
export function encode(v) {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error(`refused: non-finite number ${v}`); return v; }
  if (typeof v === 'bigint') return v.toString();
  if (v instanceof Set) return [...v].map(encode);
  if (v instanceof Map) return [...v].map(([k, x]) => [encode(k), encode(x)]);
  if (Array.isArray(v)) return v.map(x => (x === undefined ? null : encode(x)));   // JSON.stringify: undefined -> null in an array
  if (typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (x === undefined) throw new Error(`refused: undefined property ${k}`);
      // an own data property, also for the key "__proto__" (JSON.parse
      // makes one; `out[k] = …` would set the prototype and drop the key)
      Object.defineProperty(out, k, { value: encode(x), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  throw new Error(`refused: cannot encode ${typeof v} ${Object.prototype.toString.call(v)}`);
}

// The C dispatcher's result for (rule, args JSON text), computed in JS.
export function jsRule(rule, argsText) {
  if (!own(RULES, rule)) return JSON.stringify({ error: 'nc_rule: unknown rule' });
  let args;
  try { args = JSON.parse(argsText); } catch { return JSON.stringify({ error: 'nc_rule: invalid JSON' }); }
  if (!isObject(args)) return BAD;
  let result;
  try {
    result = RULES[rule](args);
  } catch (e) {
    if (e instanceof Bad) return BAD;
    if (e && e.constructor === Error) return JSON.stringify({ error: e.message });
    if (e instanceof TypeError || e instanceof RangeError || e instanceof SyntaxError) return JSON.stringify({ error: e.name });
    throw e;
  }
  return JSON.stringify(encode(result));
}

// Arguments must be plain JSON before they are written: no Map, Set,
// BigInt, function, undefined or class instance (refused, never coerced).
function assertPlainJson(v, path = 'args') {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return;
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error(`refused: ${path} is ${v}`); return; }
  if (Array.isArray(v)) { v.forEach((x, i) => assertPlainJson(x, `${path}[${i}]`)); return; }
  if (typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    for (const [k, x] of Object.entries(v)) assertPlainJson(x, `${path}.${k}`);
    return;
  }
  throw new Error(`refused: ${path} is ${typeof v} ${Object.prototype.toString.call(v)} — encode it first (design §5)`);
}

// `knownGap`: a behaviour the C port knowingly does not reproduce, named
// by the case that exercises it (see the header).
export function vector(rule, args, knownGap) {
  assertPlainJson(args);
  const argsText = JSON.stringify(args);
  const v = { rule, args: argsText, expect: jsRule(rule, argsText) };
  if (knownGap) v.gap = knownGap;
  return v;
}

// ── the cases ────────────────────────────────────────────────────────────
// test/connect-actions.test.js, carried over, plus the edges of design §R.
const FA = '7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd';
const FB = '9c9d9b0ed03421fd7889660905e37c735cbfb673e39c567c1de2a73497f9f5fc725f667566507a36d510039f49e22c9518649b3644265f2174dd17f92830ddec';
// the libdna-attributed content hashes (test/connect-actions.test.js ORACLE)
const ORACLE = [
  { s: FA, r: FB, text: 'hello', ts: '1791500000' },
  { s: FB, r: FA, text: 'Merhaba dünya 👋 — çok güzel', ts: '1791500123' },
  { s: FA, r: FB, text: '↩ Re: me\n> hello\nyes', ts: '1791600000' }
];
const [HEART, UP, LAUGH] = A.REACTION_EMOJIS;
const W = 'ee'.repeat(64), NATIVE = '0'.repeat(128), TOK = 'ab'.repeat(64), C3 = '3c'.repeat(64);

export function cases() {
  const V = [];
  const add = (rule, args, gap) => V.push(vector(rule, args, gap));

  // contentHash (actions.js:39)
  for (const o of ORACLE) add('contentHash', { senderFp: o.s, recipientFp: o.r, text: o.text, ts: o.ts });
  add('contentHash', { senderFp: 'nope', recipientFp: FB, text: 'x', ts: '1' });
  add('contentHash', { senderFp: FA, recipientFp: FB, text: 'x', ts: '-1' });
  add('contentHash', { senderFp: FA, recipientFp: FB, text: 'hello\0tail', ts: '1791500000' });
  add('contentHash', { senderFp: FA, recipientFp: FB, text: '\0hello', ts: '1791500000' });
  add('contentHash', { senderFp: FA.toUpperCase(), recipientFp: FB, text: 'x', ts: '1' });
  for (const ts of ['0', '01', '18446744073709551615', '18446744073709551616', '99999999999999999999', '100000000000000000000', ' 1', '1 ', '1.0', ''])
    add('contentHash', { senderFp: FA, recipientFp: FB, text: 'x', ts });
  for (const ts of [1791500000, 9007199254740993, 0, -0, 1.5, true, null])
    add('contentHash', { senderFp: FA, recipientFp: FB, text: 'hello', ts });
  add('contentHash', { senderFp: FA, recipientFp: FB, ts: '1' });                 // text undefined
  add('contentHash', { senderFp: FA, recipientFp: FB, text: 123, ts: '1' });
  add('contentHash', { senderFp: FA, recipientFp: FB, text: null, ts: '1' });

  // messageHash (actions.js:46)
  add('messageHash', { m: { dir: 'out', fp: FB, text: 'hello', ts: '1791500000' }, ownFp: FA });
  add('messageHash', { m: { dir: 'in', fp: FB, text: ORACLE[1].text, senderTs: '1791500123' }, ownFp: FA });
  add('messageHash', { m: { dir: 'in', fp: FB, text: 'hello', ts: '1791500000' }, ownFp: FA });   // in uses senderTs
  add('messageHash', { m: { dir: 'local', fp: FB, text: 'x', ts: '1' }, ownFp: FA });
  add('messageHash', { m: { dir: 'out', text: 'x', ts: '1' }, ownFp: FA });
  add('messageHash', { m: { dir: 'out', fp: FB, ts: '1' }, ownFp: FA });                         // text undefined
  add('messageHash', { m: null, ownFp: FA });
  add('messageHash', { m: 5, ownFp: FA });
  add('messageHash', { ownFp: FA });

  // buildReaction (actions.js:54)
  const T = 'aB'.repeat(32), t0 = '12bb3fd8ecde894049bf3a089ff34941946eaf879210978015b8dafc5c4d53c1';
  for (const e of A.REACTION_EMOJIS) add('buildReaction', { target: t0, emoji: e, op: 'add' });
  add('buildReaction', { target: T, emoji: UP, op: 'remove' });
  add('buildReaction', { target: t0, emoji: '"', op: 'add' });
  add('buildReaction', { target: 'zz', emoji: HEART, op: 'add' });
  add('buildReaction', { target: t0, emoji: HEART, op: 'maybe' });
  add('buildReaction', { target: t0, emoji: 'x', op: 'add' });
  add('buildReaction', { target: t0, emoji: '❤', op: 'add' });                       // U+2764 without U+FE0F
  add('buildReaction', { target: t0 + '\0', emoji: HEART, op: 'add' });
  add('buildReaction', { target: 7, emoji: HEART, op: 'add' });
  add('buildReaction', { emoji: HEART, op: 'add' });

  // parseReaction (actions.js:67): the app's substring reader, char[8]
  const rt = (e, op = 'add', target = t0) => `{"target":"${target}","emoji":"${e}","op":"${op}"}`;
  add('parseReaction', { text: rt(HEART) });
  add('parseReaction', { text: rt(UP, 'remove', T) });                                 // target NOT lowercased
  add('parseReaction', { text: '{"target":"short","emoji":"x","op":"add"}' });
  add('parseReaction', { text: rt('x', 'maybe') });
  add('parseReaction', { text: rt('1234567') });                                       // 7 bytes kept
  add('parseReaction', { text: rt('12345678') });                                      // 8 bytes dropped
  add('parseReaction', { text: rt('👍abc') });                                         // 4+3 = 7 bytes
  add('parseReaction', { text: rt('👍abcd') });                                        // 8 bytes
  add('parseReaction', { text: rt('PAID 100 NODUS') });
  add('parseReaction', { text: rt('🎉🎉') });
  add('parseReaction', { text: rt('') });
  add('parseReaction', { text: `{"op":"add","emoji":"${HEART}","target":"${t0}"}` });  // any order
  add('parseReaction', { text: `junk "target":"${t0}" "emoji":"x" "op":"remove" more` });
  add('parseReaction', { text: `\0${rt(HEART)}` });                                    // cut at NUL: nothing left
  add('parseReaction', { text: `${rt(HEART)}\0tail` });
  add('parseReaction', { text: `{"target":"${t0}","emoji":"x\0y","op":"add"}` });      // NUL cuts inside the emoji
  add('parseReaction', { text: `{"target":"${t0}","emoji":"x","op":"add` });           // no closing quote
  add('parseReaction', { text: 'hello' });
  add('parseReaction', { text: 12345 });
  add('parseReaction', {});

  // reactionSummary / ownReactionOn (actions.js:81, :116)
  const rec = (dir, fp, emoji, op, ts, seq, target = t0) => ({ dir, fp, kind: 'reaction', text: A.buildReaction(target, emoji, op), ts, senderTs: ts, seq });
  const base = [
    rec('in', FB, HEART, 'add', '10', '1'),
    rec('out', FB, HEART, 'add', '11', '2'),
    rec('out', FB, UP, 'add', '12', '3'),
    rec('out', FB, UP, 'remove', '13', '4'),
    rec('in', FB, UP, 'add', '9', '5'),
    { dir: 'in', fp: FB, kind: 'chat', text: 'not a reaction', senderTs: '1', seq: '6' }
  ];
  add('reactionSummary', { records: base, ownFp: FA });
  add('reactionSummary', { records: [rec('in', FB, HEART, 'remove', '20', '1'), rec('in', FB, HEART, 'add', '15', '2')], ownFp: FA });
  add('reactionSummary', { records: [], ownFp: FA });
  // Map insertion order on remove + re-add: other emojis keep first-seen order
  const custom = (e, op, ts) => ({ dir: 'in', fp: FB, kind: 'reaction', text: `{"target":"${t0}","emoji":"${e}","op":"${op}"}`, senderTs: ts, seq: ts });
  add('reactionSummary', { records: [custom('y', 'add', '1'), custom('x', 'add', '2'), custom('y', 'remove', '3'), custom('y', 'add', '4'), rec('in', FB, LAUGH, 'add', '5', '5'), rec('in', FB, HEART, 'add', '6', '6')], ownFp: FA });
  // two targets; the first emptied then filled again keeps its place; an upper-case target is the same key
  const t1 = 'cd'.repeat(32);
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '1', '1', t0), rec('in', FB, HEART, 'add', '2', '2', t1), rec('in', FB, HEART, 'remove', '3', '3', t0), rec('in', FB, UP, 'add', '4', '4', t0.toUpperCase())], ownFp: FA });
  // ties: the same sender time ordered by seq as a BigInt ("10" after "9"), then input order
  add('reactionSummary', { records: [rec('in', FB, HEART, 'remove', '5', '10'), rec('in', FB, HEART, 'add', '5', '9')], ownFp: FA });
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '5', '1'), rec('in', FB, HEART, 'remove', '5', '1')], ownFp: FA });
  // seq as StringToBigInt reads it
  for (const seq of [' 7 ', '0x10', '-5', '+3', '', null, true, 3, '0b11'])
    add('reactionSummary', { records: [rec('in', FB, HEART, 'remove', '5', seq), rec('in', FB, HEART, 'add', '5', '4')], ownFp: FA });
  add('reactionSummary', { records: [{ dir: 'in', fp: FB, kind: 'reaction', text: rt(HEART), senderTs: '5' }, rec('in', FB, HEART, 'remove', '5', '-1')], ownFp: FA }); // seq absent -> 0
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '5', 'abc')], ownFp: FA });          // SyntaxError
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '5', '1.5')], ownFp: FA });          // SyntaxError
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '5', 1.5)], ownFp: FA });            // RangeError
  add('reactionSummary', { records: [rec('in', FB, HEART, 'add', '5', '1'), null], ownFp: FA });      // TypeError
  add('reactionSummary', { records: [5, 'x', true, [1], rec('in', FB, HEART, 'add', '5', '1')], ownFp: FA });
  // sender time: out uses ts, in uses senderTs; a Number time; an invalid one is skipped
  add('reactionSummary', { records: [{ dir: 'out', fp: FB, kind: 'reaction', text: rt(HEART), ts: 7, senderTs: 'x', seq: '1' }, { dir: 'in', fp: FB, kind: 'reaction', text: rt(HEART, 'remove'), ts: '1', senderTs: '01', seq: '2' }], ownFp: FA });
  // reactors without fp: undefined === undefined is one reactor
  add('reactionSummary', { records: [{ dir: 'in', kind: 'reaction', text: rt(HEART), senderTs: '1' }, { dir: 'in', kind: 'reaction', text: rt(UP), senderTs: '2' }, { dir: 'x', kind: 'reaction', text: rt(HEART, 'remove'), senderTs: '3' }], ownFp: FA });
  add('reactionSummary', { records: [{ dir: 'in', fp: FB, kind: 'reaction', text: rt('12345678'), senderTs: '1' }, { dir: 'in', fp: FB, kind: 'reaction', text: rt('1234567'), senderTs: '2' }], ownFp: FA });

  const summary = encode(A.reactionSummary(base, FA));
  add('ownReactionOn', { summary, target: t0, emoji: HEART });
  add('ownReactionOn', { summary, target: t0, emoji: UP });
  add('ownReactionOn', { summary, target: t0.toUpperCase(), emoji: HEART });
  add('ownReactionOn', { summary, target: t1, emoji: HEART });
  add('ownReactionOn', { summary, emoji: HEART });
  add('ownReactionOn', { summary: [[t0, [{ emoji: HEART, mine: true }, null]]], target: t0, emoji: HEART });   // match before null
  add('ownReactionOn', { summary: [[t0, [null, { emoji: HEART, mine: true }]]], target: t0, emoji: HEART });   // TypeError
  add('ownReactionOn', { summary: [[t0, [5, { emoji: HEART, mine: 1 }]]], target: t0, emoji: HEART });
  add('ownReactionOn', { summary: [[t0, [{ emoji: HEART, mine: true }]], [t0, [{ emoji: HEART, mine: false }]]], target: t0, emoji: HEART }); // last wins
  add('ownReactionOn', { summary: [[t0, [{ mine: true }]]], target: t0 });                                       // undefined === undefined

  // buildDelete / parseDelete (actions.js:122, :126)
  const hMine = A.messageHash({ dir: 'out', fp: FB, text: 'hello', ts: '1791500000' }, FA);
  const hTheirs = A.messageHash({ dir: 'in', fp: FB, text: ORACLE[1].text, senderTs: '1791500123' }, FA);
  add('buildDelete', { hashes: [hMine] });
  add('buildDelete', { hashes: [hMine.toUpperCase(), hTheirs] });
  add('buildDelete', { hashes: [] });
  add('buildDelete', { hashes: Array(100).fill(hMine) });
  add('buildDelete', { hashes: Array(101).fill(hMine) });
  add('buildDelete', { hashes: [hMine, 'zz'] });
  add('buildDelete', { hashes: [5] });
  add('buildDelete', { hashes: 'abc' });
  add('buildDelete', {});
  add('parseDelete', { text: '{ "type": "delete", "action": 0, "hashes": [ "' + hMine.toUpperCase() + '" ] }' });
  add('parseDelete', { text: '{"type":"other"}' });
  for (const action of ['0', '1', '1.0', '1e0', '-0', '"1"', '1.5', '1e21', '1E2', 'true', 'null', '-3', '9007199254740993', '18446744073709551615'])
    add('parseDelete', { text: `{"type":"delete","action":${action},"hashes":["${hMine}"]}` });
  add('parseDelete', { text: `{"type":"delete","action":100000000000000000000,"hashes":[]}` });          // beyond uint64: the double 1e20
  add('parseDelete', { text: `{"type":"delete","hashes":["${hMine}",5,null,"zz",{"a":1},"${hTheirs.toUpperCase()}"]}` });
  add('parseDelete', { text: JSON.stringify({ type: 'delete', hashes: Array.from({ length: 150 }, (_, i) => i.toString(16).padStart(64, '0')) }) });
  add('parseDelete', { text: `{"type":"delete","hashes":"${hMine}"}` });
  add('parseDelete', { text: '{"type":"delete"} x' });                                // trailing junk
  add('parseDelete', { text: '{"type":"delete"}\0 junk' });                           // cut at NUL
  add('parseDelete', { text: '{"type":"delete",\0"hashes":[]}' });                    // cut inside
  add('parseDelete', { text: '{"type":"delete"} \t\r\n' });
  add('parseDelete', { text: '{"type":"delete"} ' });                            // NBSP is not JSON whitespace
  add('parseDelete', { text: '{"type":"delete","type":"other"}' });                   // last key wins
  add('parseDelete', { text: '{"type":"other","type":"delete"}' });
  add('parseDelete', { text: '[{"type":"delete"}]' });
  add('parseDelete', { text: '"delete"' });
  add('parseDelete', { text: 'null' });
  add('parseDelete', { text: '{"type":"delete","action":Infinity}' });
  add('parseDelete', { text: '{"type":"delete","action":NaN}' });
  add('parseDelete', { text: '{"type":"delete","action":01}' });
  add('parseDelete', { text: '{"type":"delete","action":1.}' });
  add('parseDelete', { text: '{"type":"delete","x":"a\tb"}' });                       // raw control char
  add('parseDelete', { text: '{"type":"delete",}' });
  add('parseDelete', { text: '{"type":"del\\u0065te"}' });                            // escapes decoded
  add('parseDelete', { text: '{"type":"delete","__proto__":{"type":"x"}}' });
  add('parseDelete', { text: '{"ty\\u0000pe":"delete"}' });                           // NUL in a key: not "type"
  add('parseDelete', { text: '{"type\\u0000":"x","type":"delete"}' });                // NUL in a key: another key than "type"
  add('parseDelete', { text: 42 });
  add('parseDelete', {});

  // deletions (actions.js:141)
  const mine = { dir: 'out', fp: FB, kind: 'chat', text: 'hello', ts: '1791500000', seq: '1' };
  const theirs = { dir: 'in', fp: FB, kind: 'chat', text: ORACLE[1].text, senderTs: '1791500123', seq: '2' };
  const hashesOf = recs => recs.map(m => (m && typeof m === 'object' && !Array.isArray(m) ? A.messageHash(m, FA) : null));
  const del = recs => add('deletions', { records: recs, ownFp: FA, hashes: hashesOf(recs) });
  const fromB = { dir: 'in', fp: FB, kind: 'delete', text: A.buildDelete([hTheirs, hMine]), senderTs: '1791600000', seq: '3' };
  const fromMe = { dir: 'out', fp: FB, kind: 'delete', text: A.buildDelete([hMine]), ts: '1791600001', seq: '4' };
  del([mine, theirs, fromB]);
  del([mine, theirs, fromMe]);
  del([mine, { ...fromMe, text: JSON.stringify({ type: 'delete', action: 1, hashes: [hMine] }) }]);
  del([theirs, { dir: 'local', fp: FB, kind: 'hide', target: hTheirs, seq: '5' }]);
  del([theirs, { dir: 'local', kind: 'hide', target: hTheirs.toUpperCase() }, { kind: 'hide', target: hTheirs }, { kind: 'hide', target: 'zz' }, { kind: 'hide', target: 5 }]);
  del([mine, { ...fromMe, text: `{"type":"delete","action":-0,"hashes":["${hMine.toUpperCase()}"]}` }]);
  del([mine, { ...fromMe, text: `{"type":"delete","action":0.0,"hashes":["${hMine}"]}` }]);
  del([mine, theirs, { ...fromB, text: A.buildDelete([hTheirs]) + '\0x' }]);
  del([{ ...theirs, kind: undefined }, { ...fromB, text: A.buildDelete([hTheirs]) }].map(m => JSON.parse(JSON.stringify(m))));
  // the deleter's fp missing: bySender.get(h) (undefined for an unknown hash) === undefined
  del([mine, { dir: 'in', kind: 'delete', text: A.buildDelete(['ab'.repeat(32)]) }]);
  del([{ dir: 'in', kind: 'chat', text: 'x', senderTs: '1' }, { dir: 'in', kind: 'delete', text: A.buildDelete([hMine]) }]);
  del([mine, theirs, null, fromB]);                                                   // TypeError
  del([mine, 7, 'x', fromMe]);
  add('deletions', { records: [mine, fromMe], ownFp: FA, hashes: [null, null] });
  add('deletions', { records: [mine, fromMe], ownFp: FA, hashes: ['', null] });
  add('deletions', { records: [mine, mine, fromMe], ownFp: FA, hashes: [hMine, hMine, null] });

  // nodusUnits (actions.js:169)
  for (const amount of ['1', '1.5', '0.00000001', '0', '0.0', '999999999999.99999999', '184467440737.09551615', '184467440737.09551616', '184467440737.09551617', '1000000000000', '', '1.', '.5', '01', '1.123456789', '-1', '1e3', ' 1', '1 ', '١', 7, null, true])
    add('nodusUnits', { amount });
  add('nodusUnits', {});

  // buildTransfer (actions.js:174) and the card name (:182)
  const bt = (detail, gap) => add('buildTransfer', { detail }, gap);
  bt({ amount: '2.5', wire: W, to: FB, name: 'bob' });
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(70) });
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(63) + '😀' });                 // the split emoji is dropped
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(62) + '😀' });
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(64) + '😀' });
  bt({ amount: '1', wire: W, to: FB, name: '😀'.repeat(40) });
  bt({ amount: '1', wire: W, to: FB, name: 'é'.repeat(70) });                         // 2-byte chars: 64 units
  bt({ amount: '1', wire: W, to: FB, name: 'a/b\u0001\u001f"\\\b\f\n\r\t\u007f  </x>' });
  bt({ amount: '1', wire: W, to: FB, name: 'a\0b' });                                  // not cut at NUL
  bt({ amount: '1', wire: W, to: FB });                                                 // name = ''
  bt({ amount: '1', wire: W, to: FB, name: null });
  bt({ amount: '1', wire: W, to: FB, name: 12.5 });
  bt({ amount: '999999999999.99999999', wire: W, to: FB, name: '' });
  bt({ amount: '0', wire: W, to: FB });
  bt({ amount: '0.00000000', wire: W, to: FB });
  bt({ amount: '1', wire: 'xx', to: FB });
  bt({ amount: '1', wire: W.toUpperCase(), to: FB });
  bt({ amount: '1', wire: W, to: 'nope' });
  bt({ amount: 1, wire: W, to: FB });
  bt(null);
  bt(5);
  add('buildTransfer', {});
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(10) + '\ud800' });              // lone high at the end
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(62) + '\ud800😀' });            // lone high, then a split pair
  bt({ amount: '1', wire: W, to: FB, name: 'x'.repeat(63) + '\udc00y' });             // lone low at unit 63

  // parseTransfer (actions.js:188)
  const card = A.buildTransfer({ amount: '2.5', wire: W, to: FB, name: 'bob' });
  add('parseTransfer', { text: card });
  add('parseTransfer', { text: 'hello' });
  add('parseTransfer', { text: '{"type":"other"}' });
  add('parseTransfer', { text: `[${card}]` });
  add('parseTransfer', { text: `{"type":"token_transfer","chain":"NoDuS","txHash":"${W.toUpperCase()}","recipientAddress":"${FB.toUpperCase()}","amount":5,"token":null,"recipientName":["x"]}` });
  add('parseTransfer', { text: '{"type":"token_transfer"}' });
  add('parseTransfer', { text: `${card}\0junk` });
  add('parseTransfer', { text: `${card} junk` });
  add('parseTransfer', { text: '{"type":"token_transfer","recipientName":"a\\u0000b\\/c"}' });
  add('parseTransfer', { text: '{"type":"token_transfer","recipientName":"\\ud83d\\ude00"}' });
  add('parseTransfer', { text: '{"type":"token_transfer","recipientName":"\\ud800"}' });            // lone surrogate in the payload
  add('parseTransfer', { text: '{"type":"token_transfer","chain":"NÖDUS"}' }, 'full-Unicode toLowerCase (C lowercases ASCII only)');

  // validNodusCard (actions.js:197)
  const ok = A.parseTransfer(A.buildTransfer({ amount: '1', wire: W, to: FB }));
  add('validNodusCard', { card: ok });
  for (const bad of [{ token: 'X' }, { wire: 'zz' }, { to: 'nope' }, { amount: '1..5' }, { chain: 'cellframe' }, { amount: 1 }, { wire: W.toUpperCase() }])
    add('validNodusCard', { card: { ...ok, ...bad } });
  add('validNodusCard', { card: null });
  add('validNodusCard', { card: 5 });
  add('validNodusCard', {});

  // transferVerdict (actions.js:208)
  const row = (kind, peer, amount, extra = {}) => ({ h: '900', kind, peer, amount: String(amount), token: NATIVE, wire: W, ...extra });
  const pcard = A.parseTransfer(card);
  const inCard = A.parseTransfer(A.buildTransfer({ amount: '2.5', wire: W, to: FB }));
  const tv = (c, entries, opts) => add('transferVerdict', { card: c, entries, opts });
  tv(pcard, [row('spend_out', FB, 250000000)], { incoming: false, counterparty: FB, ownFp: FA });
  tv(inCard, [row('spend_in', FA, 250000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 200000000), row('spend_in', FA, 50000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 1, { wire: 'dd'.repeat(64) })], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 1)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', C3, 250000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 250000000, { token: TOK })], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_out', FA, 250000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(A.parseTransfer(A.buildTransfer({ amount: '2.5', wire: W, to: C3 })), [row('spend_in', FA, 250000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...pcard, chain: 'cellframe' }, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...pcard, amount: 'lots' }, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...pcard, chain: 5 }, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...pcard, chain: '' }, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...pcard, chain: true, token: 'X' }, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv(null, [], { incoming: true, counterparty: FA, ownFp: FB });
  tv(0, [], { incoming: true, counterparty: FA, ownFp: FB });
  // u64 edges (design §R R2): amounts above 2^64 - 1 are exact, never wrapped
  const big = (amount, rows) => tv({ ...inCard, amount }, rows.map(a => row('spend_in', FA, a)), { incoming: true, counterparty: FA, ownFp: FB });
  big('184467440737.09551615', ['18446744073709551615']);
  big('184467440737.09551616', ['18446744073709551616']);
  big('184467440737.09551617', ['18446744073709551617']);
  big('0.00000001', ['18446744073709551617']);                          // a wrapping u64 would read 1
  big('184467440737.09551617', ['18446744073709551615', '2']);          // the sum passes 2^64
  big('0.00000001', ['18446744073709551615', '2']);
  big('999999999999.99999999', ['99999999999999999999']);
  big('0.00000016', ['-5', '21']);
  big('0.00000016', [' 0x10 ']);
  big('0.00000016', ['0o20']);
  big('0.00000001', ['']);                                               // BigInt('') = 0n
  big('0.00000001', ['1.5']);                                            // SyntaxError
  tv(inCard, [row('spend_in', FA, 0, { amount: 1.5 })], { incoming: true, counterparty: FA, ownFp: FB });        // RangeError
  tv(inCard, [row('spend_in', FA, 0, { amount: null })], { incoming: true, counterparty: FA, ownFp: FB });       // TypeError
  tv(inCard, [{ kind: 'spend_in', peer: FA, token: NATIVE, wire: W, h: '1' }], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...inCard, amount: '0.00000001' }, [row('spend_in', FA, 0, { amount: true })], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...inCard, amount: '0.00000001' }, [row('spend_in', FA, 0, { amount: 1, h: 900 })], { incoming: true, counterparty: FA, ownFp: FB });
  tv({ ...inCard, amount: '0.00000001' }, [{ kind: 'spend_in', peer: FA, token: NATIVE, wire: W, amount: '1' }], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 0, { token: TOK, amount: 'not a number' })], { incoming: true, counterparty: FA, ownFp: FB }); // token first
  tv(inCard, null, { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, 'abc', { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, {}, { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [null, 5, 'x', row('spend_in', FA, 250000000)], { incoming: true, counterparty: FA, ownFp: FB });
  tv(inCard, [row('spend_in', FA, 250000000)], null);
  add('transferVerdict', { card: inCard, entries: [] });
  tv(inCard, [row('spend_in', FA, 250000000)], 5);
  {
    // no recipient, no peer, no counterparty: undefined === undefined, as in JS
    const { to: _to, ...noTo } = inCard;
    const { peer: _peer, ...noPeer } = row('spend_in', FA, 250000000);
    tv(noTo, [noPeer], { incoming: 0 });
  }
  tv({ ...pcard, to: FA }, [row('spend_out', FB, 250000000)], { incoming: false, counterparty: FB, ownFp: FA });

  // copyCards (actions.js:232)
  const W1 = 'e1'.repeat(64), W2 = 'e2'.repeat(64);
  const cards = [
    { key: 'b|8', dir: 'in', wire: W1, order: '8', state: 'confirmed' },
    { key: 'b|6', dir: 'in', wire: W1, order: '6', state: 'confirmed' },
    { key: 'b|7', dir: 'in', wire: W2, order: '7', state: 'confirmed' },
    { key: 'b|9', dir: 'out', wire: W1, order: '9', state: 'confirmed' },
    { key: 'b|10', dir: 'in', wire: W1, order: '10', state: 'pending' }
  ];
  add('copyCards', { cards });
  add('copyCards', { cards: cards.slice(0, 1) });
  add('copyCards', { cards: [] });
  add('copyCards', { cards: null });
  add('copyCards', {});
  add('copyCards', { cards: 'abc' });
  add('copyCards', { cards: [{ key: 'a', dir: 'in', wire: W1, order: '10', state: 'confirmed' }, { key: 'b', dir: 'in', wire: W1, order: '9', state: 'confirmed' }] });   // numeric, not string order
  add('copyCards', { cards: [{ key: 'a', dir: 'in', wire: W1, order: '5', state: 'confirmed' }, { key: 'b', dir: 'in', wire: W1, order: '5', state: 'confirmed' }, { key: 'c', dir: 'in', wire: W1, order: '-1', state: 'confirmed' }] });
  add('copyCards', { cards: [{ dir: 'in', wire: W1, order: '1', state: 'confirmed' }, { dir: 'in', wire: W1, order: '2', state: 'confirmed' }, { key: 3, dir: 'in', wire: W1, order: '3', state: 'confirmed' }] });
  add('copyCards', { cards: [{ key: 'a', wire: W1, order: '1', state: 'confirmed' }, { key: 'b', dir: 'undefined', wire: W1, order: '2', state: 'confirmed' }] });   // `${undefined}`
  add('copyCards', { cards: [null, 0, 'x', { key: 'a', dir: 'in', wire: W1, order: '1', state: 'confirmed' }, { key: 'b', dir: 'in', wire: W1, order: 'x', state: 'pending' }] });

  // buildReply / parseReply (actions.js:246, :252)
  const br = (senderLabel, quoted, text) => add('buildReply', { senderLabel, quoted, text });
  br('me', 'hello', 'yes');
  br('Bob', 'x'.repeat(105), 'ok');
  br('Bob\nEvil', 'line one\nline two', 'answer\nsecond line');
  br('a', '👋'.repeat(150), 'b');
  br('a', 'x'.repeat(100), 'b');                                                   // exactly 100: no "..."
  br('a', ('ab\r\n'.repeat(25) + 'c'.repeat(50)), 'b');                            // 100 code points after the newlines fold
  br('a', 'a\n'.repeat(50), 'b');
  br('a', 'é'.repeat(101), 'b');
  br('   　﻿ ', 'q', 't');                                           // trims to '' -> 'them'
  br('\r\n\r\n', 'q', 't');
  br(' Bob ', 'q', 't');                                                 // trim, not the CR/LF fold
  br('​Bob', 'q', 't');                                                       // U+200B is not whitespace
  br('a\0b', 'q\0r', 't\0u');                                                      // never cut at NUL
  add('buildReply', { quoted: null, text: 5 });                                   // String(undefined), String(null)
  br('a', 'x'.repeat(99) + '\ud800' + 'yz', 'b');                                  // a lone surrogate counts one
  const pr = text => add('parseReply', { text });
  pr('↩ Re: me\n> hello\nyes');
  pr(A.buildReply('Bob\nEvil', 'line one\nline two', 'answer\nsecond line'));
  pr('hello');
  pr('↩ Re: me\nno quote');
  pr('↩ Re: \n> \n');
  pr('↩ Re: a\n>x\nb');
  pr('↩ Re: a\n> q');
  pr('↩ Re:a\n> q\nt');
  pr('↩ Re: a\0b\n> q\0\nt\0');                                                    // NUL is data here
  pr(' ↩ Re: a\n> q\nt');
  pr(12);
  add('parseReply', {});
  return V;
}

// ── P1a cases: text.js / core.js ──────────────────────────────────────────
// test/connect-ui.test.js and test/address-book.test.js, carried over, plus
// HIGH-7 (no unit test before), the acceptance salt (Kurultay #17 item 5)
// and the edges of design §R (signed differences, u64 extremes, the outbox
// cap with reactions, malformed values that make the JS throw).
const FP = 'ab'.repeat(64), OTHER = 'cd'.repeat(64);
const hexFp = ch => ch.repeat(128);
const U64_MAX = '18446744073709551615', U64_OVER = '18446744073709551616', U64_OVER1 = '18446744073709551617';
const D20 = '99999999999999999999';                      // the largest U64-accepted value (10^20 - 1)

export function rulesCases() {
  const V = [];
  // An undefined property in a case is the ABSENT argument / field: it is
  // dropped (JSON.stringify drops it) before the plain-JSON check. No case
  // puts undefined inside an array.
  const absentDropped = v => JSON.parse(JSON.stringify(v));
  const add = (rule, args, gap) => V.push(vector(rule, absentDropped(args), gap));

  // ── declined senders (text.js:20-40; connect-ui.test.js 'declined senders')
  {
    const DA = 'a1'.repeat(64), DB = 'b2'.repeat(64), now = '2000000000';
    add('addDeclined', { list: [], fp: DA, nowSeconds: now });
    add('addDeclined', { list: [{ fp: DA, at: now }], fp: DA, nowSeconds: now });         // one entry per sender
    add('isDeclined', { list: [{ fp: DA, at: now }], fp: DA });
    add('isDeclined', { list: [{ fp: DA, at: now }], fp: DB });
    add('declinedNow', { list: [DA, 'nonsense', { fp: DB, at: '1' }], nowSeconds: now });  // bare ID counts from now
    const later = String(BigInt(now) + T.DECLINE_KEEP_SECONDS + 1n);
    add('declinedNow', { list: [{ fp: DA, at: now }], nowSeconds: later });                // forgotten after 7 days
    add('undecline', { list: [{ fp: DA, at: now }], fp: DA });
    let many = [];
    for (let i = 0; i < T.DECLINE_MAX + 49; i++) many = T.addDeclined(many, i.toString(16).padStart(128, '0'), String(BigInt(now) + BigInt(i)));
    const n = T.DECLINE_MAX + 49;
    add('addDeclined', { list: many, fp: n.toString(16).padStart(128, '0'), nowSeconds: String(BigInt(now) + BigInt(n)) }); // the cap: the newest 200
    add('declinedNow', { list: Array.from({ length: 250 }, (_, i) => ({ fp: (i + 1).toString(16).padStart(128, '0'), at: String(1000 + (i % 7)) })), nowSeconds: '1010' });
    // the 7-day edge: exactly KEEP old stays, one second more goes
    add('declinedNow', { list: [{ fp: DA, at: String(BigInt(now) - T.DECLINE_KEEP_SECONDS) }, { fp: DB, at: String(BigInt(now) - T.DECLINE_KEEP_SECONDS - 1n) }], nowSeconds: now });
    // a future `at` (negative difference) stays
    add('declinedNow', { list: [{ fp: DA, at: String(BigInt(now) + 1000n) }], nowSeconds: now });
    add('declinedNow', { list: [{ fp: DA, at: U64_OVER }, { fp: DB, at: D20 }], nowSeconds: '1' });
    add('declinedNow', { list: [{ fp: DA, at: '99999999999999999000' }], nowSeconds: D20 });
    // ties: equal at keeps the Map order (first sighting of each fp)
    add('declinedNow', { list: [{ fp: DB, at: '5' }, { fp: DA, at: '5' }], nowSeconds: '10' });
    add('declinedNow', { list: [{ fp: DA, at: '5' }, { fp: DB, at: '6' }, { fp: DA, at: '7' }], nowSeconds: '10' });  // A keeps its place, takes 7
    add('declinedNow', { list: [{ fp: DA, at: '7' }, { fp: DB, at: '7' }, { fp: DA, at: '5' }], nowSeconds: '10' });  // a smaller at does not replace
    add('declinedNow', { list: [DB, { fp: DA, at: '10' }], nowSeconds: '10' });                                      // bare ID at now: a tie
    // at forms: String(d.at)
    add('declinedNow', { list: [{ fp: DA, at: 5 }, { fp: DB, at: 1e21 }], nowSeconds: '10' });
    add('declinedNow', { list: [{ fp: DA, at: null }, { fp: DB }, { fp: hexFp('c'), at: '05' }, { fp: DA.toUpperCase(), at: '5' }, null, 5, [DA], true], nowSeconds: '10' });
    for (const nowSeconds of ['01', '', 5, null, D20 + '0'])
      add('declinedNow', { list: [{ fp: DA, at: '1' }], nowSeconds });
    add('declinedNow', { list: [{ fp: DA, at: '1' }] });
    add('declinedNow', { list: 'abc', nowSeconds: '10' });
    add('declinedNow', { list: { fp: DA, at: '1' }, nowSeconds: '10' });
    add('addDeclined', { list: [DA, { fp: DB, at: '3' }], fp: DA, nowSeconds: 'x' });         // the time is checked
    add('addDeclined', { list: [DA, { fp: DB, at: '3' }], fp: 'not an id', nowSeconds: '5' });
    add('addDeclined', { list: [DA, { fp: DB, at: '3' }], fp: DB, nowSeconds: '5' });
    // isDeclined / undecline compare with === (undefined === undefined)
    add('isDeclined', { list: [null] });
    add('isDeclined', { list: [5, { at: '1' }] });
    add('isDeclined', { list: [DA], fp: DA });
    add('isDeclined', { list: 'x', fp: DA });
    add('undecline', { list: [DA, { fp: hexFp('e'), at: '1', note: 'x', 10: 'p', 2: 'q' }, { fp: DA, at: '3' }, { fp: DB, at: '2' }, null, 7], fp: DA });
    add('undecline', { list: [DA, null, 7, [1]] });
    add('undecline', { list: null, fp: DA });
  }

  // ── parseContactId (text.js:42)
  add('parseContactId', { value: ` ${FP.toUpperCase().slice(0, 64)}\n${FP.slice(64)} ` });
  add('parseContactId', { value: FP.slice(1) });
  add('parseContactId', { value: 'zz'.repeat(64) });
  // (code points, so no invisible character sits in this file)
  for (const ws of [0xa0, 0x3000, 0xfeff, 0x2028, 0x2029, 0x200a, 0x1680, 0x202f, 0x205f, 0x0b, 0x0c].map(c => String.fromCodePoint(c)).concat(['\t\r\n']))
    add('parseContactId', { value: FP.slice(0, 50) + ws + FP.slice(50) });           // ECMAScript \s: removed
  for (const notWs of [0x200b, 0x180e, 0x85, 0x2060].map(c => String.fromCodePoint(c)))
    add('parseContactId', { value: FP.slice(0, 50) + notWs + FP.slice(50) });        // not \s: refused
  add('parseContactId', { value: FP.slice(0, 127) + String.fromCodePoint(0xff21) });  // fullwidth A
  add('parseContactId', { value: FP.slice(0, 127) + String.fromCodePoint(0x212a) });                     // KELVIN SIGN lowercases to k (U+212A)
  add('parseContactId', { value: FP + 'a' });
  add('parseContactId', { value: FP.slice(0, 127) + '\ud800' });
  add('parseContactId', { value: 123 });
  add('parseContactId', {});
  add('parseContactId', { value: '' });

  // ── requestRefusal (text.js:62)
  add('requestRefusal', { fp: FP, opts: { ownFp: FP } });
  add('requestRefusal', { fp: OTHER, opts: { ownFp: FP, isContact: true } });
  add('requestRefusal', { fp: OTHER, opts: { ownFp: FP, isRequested: true } });
  add('requestRefusal', { fp: OTHER, opts: { ownFp: FP } });
  add('requestRefusal', { fp: OTHER, opts: { ownFp: FP, isContact: 1, isRequested: true } });
  add('requestRefusal', { fp: OTHER, opts: { ownFp: FP, isContact: 0, isRequested: 'yes' } });
  add('requestRefusal', { fp: OTHER });                                                  // opts = {}
  add('requestRefusal', {});                                                             // undefined === undefined
  add('requestRefusal', { fp: OTHER, opts: null });                                      // TypeError
  add('requestRefusal', { fp: OTHER, opts: 'x' });

  // ── acceptanceMayAutoApprove (core.js:197, HIGH-7)
  {
    const acc = (extra = {}) => ({ sender: OTHER, acceptance: true, message: CONTACT_ACCEPTED_MSG, ...extra });
    const am = (request, pendingOutgoing) => add('acceptanceMayAutoApprove', { request, pendingOutgoing });
    am(acc(), [OTHER]);                                                                   // our pending request: honoured
    am(acc(), [FP, hexFp('e'), OTHER]);
    am(acc(), []);                                                                        // no pending entry
    am(acc(), [hexFp('e')]);                                                              // our request to OTHER withdrawn: another stays
    am(acc({ message: 'Contact request accepted.' }), [OTHER]);
    am(acc({ message: 'contact request accepted' }), [OTHER]);
    am(acc({ message: 'Contact request accepted\u0000x' }), [OTHER]);                     // the app's strcmp would stop at NUL; JS does not
    am(acc({ message: '' }), [OTHER]);
    am(acc({ message: undefined }), [OTHER]);
    am(acc({ acceptance: false }), [OTHER]);
    am(acc({ acceptance: 'true' }), [OTHER]);
    am(acc({ acceptance: 1 }), [OTHER]);
    am({ sender: OTHER, message: CONTACT_ACCEPTED_MSG }, [OTHER]);
    am(acc({ sender: OTHER.toUpperCase() }), [OTHER.toUpperCase()]);                      // sender not 128 lowercase hex
    am(acc({ sender: OTHER.slice(1) }), [OTHER.slice(1)]);
    am(acc({ sender: 5 }), [5]);
    am(acc({ sender: FP }), [FP]);                                                        // own ID: no check here (messages.js syncRequests skips it)
    am(acc(), undefined);
    am(acc(), null);
    am(acc(), OTHER);                                                                     // not a Set
    am(acc(), { [OTHER]: true });
    am(null, [OTHER]);
    am(5, [OTHER]);
    am(undefined, [OTHER]);
  }

  // ── acceptedSalt (text.js; messages.js completeOutgoing; Kurultay #17 item 5)
  {
    const S1 = '11'.repeat(32), S2 = '22'.repeat(32);
    const as = (mine, request) => add('acceptedSalt', { mine, request });
    as({ fp: OTHER, salt: S1 }, { sender: OTHER, salt: S2 });                             // OUR offered salt wins
    as({ fp: OTHER }, { sender: OTHER, salt: S2 });                                       // ours had none: theirs
    as(undefined, { sender: OTHER, salt: S2 });                                           // no outgoing entry
    as(null, { sender: OTHER, salt: S2 });
    as({ fp: OTHER, salt: '' }, { sender: OTHER, salt: S2 });
    as({ fp: OTHER, salt: null }, { sender: OTHER });                                     // none: null
    as(undefined, { sender: OTHER });
    as({ fp: OTHER, salt: S1 }, null);                                                    // request not read
    as({ fp: OTHER }, null);                                                              // TypeError
    as({ fp: OTHER, salt: true }, { salt: 5 });
    as('x', { salt: S2 });
    add('acceptedSalt', { mine: { salt: S1 } });
    add('acceptedSalt', {});
  }

  // ── isDelivered / messageStatus (text.js:349, :352)
  for (const message of [{ ts: '5' }, { ts: '5', published: true }, { ts: '5', delivered: true }, { published: true, delivered: true },
    { delivered: 'true' }, { delivered: 1, published: 1 }, {}, null, 'x', 5]) {
    add('isDelivered', { message });
    add('messageStatus', { message });
  }
  add('isDelivered', {});
  add('messageStatus', {});

  // ── publishedSeqs / markPublished / markDelivered (text.js:358-382)
  {
    const msgs = [
      { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '100', published: true },
      { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '100' },
      { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '200', published: true },
      { seq: '4', fp: FP, dir: 'in', text: 'x', senderTs: '50' },
      { seq: '5', fp: OTHER, dir: 'out', text: 'o', ts: '10', published: true },
      { seq: '6', fp: FP, dir: 'out', text: 'd', ts: '90', published: true, delivered: true }
    ];
    add('publishedSeqs', { messages: msgs, fp: FP });
    const before = [...T.publishedSeqs(msgs, FP)];
    const after = msgs.map((m, i) => (i === 1 ? { ...m, published: true } : m));   // a publish completed after the snapshot
    add('markDelivered', { messages: after, fp: FP, ackTs: '150', publishedBefore: before, nowSeconds: '5000' });
    for (const ackTs of ['0', '', 'x', undefined, '-1', 150, '01'])
      add('markDelivered', { messages: after, fp: FP, ackTs, publishedBefore: before, nowSeconds: '5000' });
    add('markDelivered', { messages: after, fp: FP, ackTs: '150', publishedBefore: before });           // time checked after the ACK
    add('markDelivered', { messages: after, fp: FP, ackTs: '0', publishedBefore: before });             // [] before the time check
    add('markDelivered', { messages: after, fp: FP, ackTs: '150', nowSeconds: '5000' });               // not a Set: []
    add('markDelivered', { messages: after, fp: FP, ackTs: '150', publishedBefore: '1', nowSeconds: '5000' });
    // strict < at the ACK's own second (RT2 L2 F1)
    const two = [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '150', published: true }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '149', published: true }];
    add('markDelivered', { messages: two, fp: FP, ackTs: '150', publishedBefore: ['1', '2'], nowSeconds: '1000' });
    // BigInt(m.ts) is the Number's own value: 2^64 as a double
    const n64 = [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: 18446744073709551616 }];
    for (const ackTs of [U64_OVER, U64_OVER1, '18446744073709552000', '18446744073709552001'])
      add('markDelivered', { messages: n64, fp: FP, ackTs, publishedBefore: ['1'], nowSeconds: '1' });
    add('markDelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: U64_MAX }], fp: FP, ackTs: U64_OVER, publishedBefore: ['1'], nowSeconds: D20 });
    add('markDelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: D20 }], fp: FP, ackTs: D20, publishedBefore: ['1'], nowSeconds: '1' });
    add('markDelivered', { messages: [{ seq: 1, fp: FP, dir: 'out', ts: '5' }, { seq: '2', fp: FP, dir: 'out', ts: '5' }], fp: FP, ackTs: '9', publishedBefore: [1, '2'], nowSeconds: '1' }); // Set.has('1') vs 1
    // every unknown field echoed, in JS key order; an existing delivered / deliveredAt keeps its place
    add('markDelivered', { messages: [{ 10: 'x', seq: '1', delivered: false, fp: FP, dir: 'out', ts: '5', 2: 'y', deliveredAt: 'old', note: 'n' }], fp: FP, ackTs: '9', publishedBefore: ['1'], nowSeconds: '7' });
    add('markDelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', ts: '1.5' }, { seq: '2', fp: FP, dir: 'out', ts: ' 1' }, { seq: '3', fp: FP, dir: 'out', ts: 1 }], fp: FP, ackTs: '9', publishedBefore: ['1', '2', '3'], nowSeconds: '7' });
    add('markDelivered', { messages: [null], fp: FP, ackTs: '9', publishedBefore: [], nowSeconds: '7' });
    add('markDelivered', { messages: 'x', fp: FP, ackTs: '9', publishedBefore: [], nowSeconds: '7' });

    add('markPublished', { messages: msgs.map(m => ({ ...m })), fp: FP, set: [{ seq: '1' }, { seq: '2' }, { seq: '3' }] });
    add('markPublished', { messages: [{ seq: 2, fp: FP, dir: 'out', note: 'kept', 10: 1, published: false }, { seq: '3', fp: FP, dir: 'out' }], fp: FP, set: [{ seq: '2' }, { seq: 3 }, 'x', 7, []] });
    add('markPublished', { messages: [{ seq: 'undefined', fp: FP, dir: 'out' }], fp: FP, set: ['x'] });   // String(('x').seq)
    add('markPublished', { messages: msgs, fp: FP, set: [null] });                    // TypeError (set first)
    add('markPublished', { messages: [null], fp: FP, set: [] });
    add('markPublished', { messages: msgs, fp: FP, set: 'abc' });
    add('markPublished', { messages: msgs, fp: FP });
    add('publishedSeqs', { messages: [{ seq: 1, fp: FP, dir: 'out', published: true }, { seq: '1', fp: FP, dir: 'out', published: true }, { seq: '01', fp: FP, dir: 'out', published: true }, { fp: FP, dir: 'out', published: true }], fp: FP });
    add('publishedSeqs', { messages: [{ seq: '1', fp: FP, dir: 'out', published: 'true' }, 5, 'x'], fp: FP });
    add('publishedSeqs', { messages: [null], fp: FP });
    add('publishedSeqs', { messages: {}, fp: FP });
    add('publishedSeqs', { fp: FP });
  }

  // ── ackToSend / ackAllowed (text.js:395, :412)
  {
    const msgs = [
      { seq: '1', fp: FP, dir: 'in', text: 'a', senderTs: '900' },
      { seq: '2', fp: FP, dir: 'in', text: 'b', senderTs: '1000' },
      { seq: '3', fp: FP, dir: 'in', text: 'c', senderTs: '950' },
      { seq: '4', fp: FP, dir: 'out', text: 'mine', ts: '99999' },
      { seq: '5', fp: OTHER, dir: 'in', text: 'o', senderTs: '5000' }
    ];
    for (const lastSent of [undefined, '999', '1000', '2000', 999, '01', ''])
      add('ackToSend', { messages: msgs, fp: FP, lastSent });
    add('ackToSend', { messages: [], fp: FP });
    add('ackToSend', { messages: [{ seq: '1', fp: FP, dir: 'in', text: 'z', senderTs: '0' }], fp: FP });
    add('ackToSend', { messages: [{ seq: '1', fp: FP, dir: 'in', text: 'z', senderTs: 'bad' }], fp: FP });
    add('ackToSend', { messages: [...msgs, { seq: '9', fp: FP, dir: 'in', text: 'm', senderTs: U64_MAX }], fp: FP, lastSent: '18446744073709551614' });
    add('ackToSend', { messages: [{ seq: '9', fp: FP, dir: 'in', senderTs: D20 }, { seq: '8', fp: FP, dir: 'in', senderTs: U64_OVER }], fp: FP, lastSent: U64_OVER });
    add('ackToSend', { messages: [{ seq: '9', fp: FP, dir: 'in', senderTs: 18446744073709551616 }], fp: FP });   // BigInt of the double
    add('ackToSend', { messages: [{ seq: '9', fp: FP, dir: 'in', senderTs: 1000 }], fp: FP, lastSent: '999' });
    add('ackToSend', { messages: 'abc', fp: FP });                                     // for…of a string: nothing stored
    add('ackToSend', { fp: FP });                                                      // TypeError
    add('ackToSend', { messages: {}, fp: FP });
    add('ackToSend', { messages: [null], fp: FP });
    add('ackToSend', { messages: [5, 'x', [1], msgs[1]], fp: FP });
    for (const flags of [{ persistent: true, complete: true, lost: 0 }, { persistent: false, complete: true, lost: 0 },
      { persistent: true, complete: true, lost: 1 }, { persistent: true, complete: false, lost: 0 },
      { persistent: 'yes', complete: 1, lost: 0 }, { persistent: true, complete: true }, { persistent: true, complete: true, lost: '' },
      { persistent: true, complete: true, lost: '0' }, null, 'x', 5])
      add('ackAllowed', { flags });
    add('ackAllowed', {});
  }

  // ── pendingOutbox / hasUndelivered (text.js:433, :469)
  {
    const now = '1000000';
    const msgs = [
      { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '999990' },
      { seq: '1', fp: FP, dir: 'out', text: 'a', ts: '999000' },
      { seq: '2', fp: FP, dir: 'in', text: 'x', senderTs: '999500' },
      { seq: '4', fp: OTHER, dir: 'out', text: 'o', ts: '999999' },
      { seq: '5', fp: FP, dir: 'out', text: 'old', ts: String(1000000 - 7 * 86400) }
    ];
    add('pendingOutbox', { messages: msgs, fp: FP, nowSeconds: now });
    const d1 = msgs.map((m, i) => (i === 1 ? { ...m, delivered: true } : m));
    add('pendingOutbox', { messages: d1, fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: d1.map((m, i) => (i === 0 ? { ...m, delivered: true } : m)), fp: FP, nowSeconds: now });
    const many = Array.from({ length: T.OUTBOX_MAX + 5 }, (_, i) => ({ seq: String(i + 1), fp: FP, dir: 'out', text: 't', ts: now }));
    add('pendingOutbox', { messages: many, fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [...many].reverse(), fp: FP, nowSeconds: now });          // local order, not input order
    // 0.1.90: over the limit reactions give way first
    const T64 = 'ab'.repeat(32), R = (e, op, t = T64) => `{"target":"${t}","emoji":"${e}","op":"${op}"}`;
    const mixed = [
      { seq: '1', fp: FP, dir: 'out', text: 'first chat', ts: now },
      { seq: '2', fp: FP, dir: 'out', text: R('👍', 'add'), ts: now, kind: 'reaction' },
      { seq: '3', fp: FP, dir: 'out', text: R('🔥', 'add'), ts: now, kind: 'reaction' },
      ...Array.from({ length: T.OUTBOX_MAX - 3 }, (_, i) => ({ seq: String(i + 4), fp: FP, dir: 'out', text: 'm', ts: now })),
      { seq: '100', fp: FP, dir: 'out', text: R('👍', 'remove'), ts: now, kind: 'reaction' },
      { seq: '101', fp: FP, dir: 'out', text: R('🎉', 'add'), ts: now, kind: 'reaction' }
    ];
    add('pendingOutbox', { messages: mixed, fp: FP, nowSeconds: now });
    // W-12 (0.1.101): the clock stepped back — the receiver replays by sender time, so the ADD stays
    const back = [
      { seq: '1', fp: FP, dir: 'out', text: R('👍', 'add'), ts: '100', kind: 'reaction' },
      { seq: '2', fp: FP, dir: 'out', text: R('👍', 'remove'), ts: '99', kind: 'reaction' },
      ...Array.from({ length: T.OUTBOX_MAX - 1 }, (_, i) => ({ seq: String(i + 3), fp: FP, dir: 'out', text: 'm', ts: '100' }))
    ];
    add('pendingOutbox', { messages: back, fp: FP, nowSeconds: '200' });
    // replay ties: equal sender time -> the larger seq is newer; an upper-case target is the same key
    const tie = [
      { seq: '2', fp: FP, dir: 'out', text: R('👍', 'remove', T64.toUpperCase()), ts: '100', kind: 'reaction' },
      { seq: '10', fp: FP, dir: 'out', text: R('👍', 'add'), ts: '100', kind: 'reaction' },
      ...Array.from({ length: T.OUTBOX_MAX - 1 }, (_, i) => ({ seq: String(i + 20), fp: FP, dir: 'out', text: 'm', ts: '100' }))
    ];
    add('pendingOutbox', { messages: tie, fp: FP, nowSeconds: '200' });
    // reactions that are not moot are dropped oldest first, an unparseable 'reaction' counts as one; then the oldest of the rest
    const heavy = [
      ...Array.from({ length: 30 }, (_, i) => ({ seq: String(i + 1), fp: FP, dir: 'out', text: R(A.REACTION_EMOJIS[i % 8], 'add', ('0' + i.toString(16)).slice(-2).repeat(32)), ts: '100', kind: 'reaction' })),
      { seq: '31', fp: FP, dir: 'out', text: 'not a reaction', ts: '100', kind: 'reaction' },
      ...Array.from({ length: 40 }, (_, i) => ({ seq: String(i + 40), fp: FP, dir: 'out', text: 'm', ts: '100' }))
    ];
    add('pendingOutbox', { messages: heavy, fp: FP, nowSeconds: '200' });
    add('pendingOutbox', { messages: Array.from({ length: 60 }, (_, i) => ({ seq: String(i + 1), fp: FP, dir: 'out', text: 'm' + i, ts: '100', kind: i % 2 ? 'chat' : 'reaction' })), fp: FP, nowSeconds: '200' });
    // the delivered grace: deliveredAt 1000, 3600 s (inGrace, text.js:385)
    const marked = [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '150', published: true },
      { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '149', published: true, delivered: true, deliveredAt: '1000' }];
    for (const t of [1100, 1000 + 3599, 1000 + 3600, 1000 + 3601]) add('pendingOutbox', { messages: marked, fp: FP, nowSeconds: String(t) });
    add('pendingOutbox', { messages: [{ ...marked[1], deliveredAt: undefined }], fp: FP, nowSeconds: '1100' });
    add('pendingOutbox', { messages: [{ ...marked[1], deliveredAt: 1000 }, { ...marked[1], seq: '3', deliveredAt: '01000' }], fp: FP, nowSeconds: '1100' });
    add('pendingOutbox', { messages: [{ ...marked[1], deliveredAt: U64_MAX }], fp: FP, nowSeconds: D20 });
    add('pendingOutbox', { messages: [{ ...marked[1], delivered: 'true' }], fp: FP, nowSeconds: '99999' });
    add('hasUndelivered', { messages: [marked[1]], fp: FP, nowSeconds: '1100' });
    add('hasUndelivered', { messages: marked, fp: FP, nowSeconds: '1100' });
    // the 7-day life; now below 7 days (a negative cutoff)
    for (const ts of [String(1000000 - 604800), String(1000000 - 604799)]) add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '1' }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '0' }], fp: FP, nowSeconds: '100' });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '0' }], fp: FP, nowSeconds: '0' });
    add('hasUndelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '0' }], fp: FP, nowSeconds: '0' });
    // u64 extremes and BigInt(m.ts) forms
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: U64_MAX }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: U64_OVER }], fp: FP, nowSeconds: U64_OVER });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '1' }], fp: FP, nowSeconds: D20 });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: '99999999999999999999999' }], fp: FP, nowSeconds: D20 });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: ' 0x10 ' }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: '-5' }, { seq: '3', fp: FP, dir: 'out', text: 'c', ts: '' }, { seq: '4', fp: FP, dir: 'out', text: 'd', ts: true }], fp: FP, nowSeconds: '10' });
    // malformed values that make the JS throw
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: 'abc' }], fp: FP, nowSeconds: now });    // SyntaxError
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: 1.5 }], fp: FP, nowSeconds: now });      // RangeError
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a' }], fp: FP, nowSeconds: now });               // TypeError
    add('pendingOutbox', { messages: [{ seq: '1', fp: OTHER, dir: 'out', text: 'a', ts: 'abc' }], fp: FP, nowSeconds: now }); // not read
    add('pendingOutbox', { messages: [{ seq: 'abc', fp: FP, dir: 'out', text: 'a', ts: now }], fp: FP, nowSeconds: now });    // one element: no comparison
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }, { seq: 'abc', fp: FP, dir: 'out', text: 'b', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }, { fp: FP, dir: 'out', text: 'b', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }, { seq: 2.5, fp: FP, dir: 'out', text: 'b', ts: now }], fp: FP, nowSeconds: now });
    // two differently malformed seqs: V8's first comparator call is compare(a[1], a[0]) (nc_rules.h)
    add('pendingOutbox', { messages: [{ seq: 'abc', fp: FP, dir: 'out', text: 'a', ts: now }, { seq: 1.5, fp: FP, dir: 'out', text: 'b', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: now }, { seq: 1.5, fp: FP, dir: 'out', text: 'c', ts: now }, { seq: 'x', fp: FP, dir: 'out', text: 'd', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '3', fp: FP, dir: 'out', text: 'a', ts: now }, { seq: '2', fp: FP, dir: 'out', text: 'b', ts: now }, { seq: '5', fp: FP, dir: 'out', text: 'c', ts: now }, { seq: 'x', fp: FP, dir: 'out', text: 'd', ts: now }, { seq: 1.5, fp: FP, dir: 'out', text: 'e', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [{ seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }, null], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: [5, 'x', [1], { seq: '1', fp: FP, dir: 'out', text: 'a', ts: now }], fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: 'abc', fp: FP, nowSeconds: now });
    add('pendingOutbox', { messages: 'abc', fp: FP, nowSeconds: 'x' });                // the time first
    add('pendingOutbox', { messages: msgs, fp: FP, nowSeconds: 1000000 });
    add('pendingOutbox', { messages: [{ seq: 7, fp: FP, dir: 'out', text: 5, ts: 1000 }], fp: FP, nowSeconds: '2000' });   // raw values echoed
    add('hasUndelivered', { messages: msgs, fp: FP, nowSeconds: now });
    add('hasUndelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', ts: 'abc' }], fp: FP, nowSeconds: now });
    add('hasUndelivered', { messages: [{ seq: '1', fp: FP, dir: 'out', ts: now }, null], fp: FP, nowSeconds: now });   // .some stops at the hit
    add('hasUndelivered', { messages: [null, { seq: '1', fp: FP, dir: 'out', ts: now }], fp: FP, nowSeconds: now });
    add('hasUndelivered', { messages: {}, fp: FP, nowSeconds: now });
    add('hasUndelivered', { messages: [], fp: FP, nowSeconds: '-1' });
  }

  // ── compareLocal / receivedKey (text.js:477, :484)
  {
    const cl = (a, b) => add('compareLocal', { a, b });
    cl({ seq: '10' }, { seq: '9' });
    cl({ seq: '9' }, { seq: '100' });
    cl({ seq: '5' }, { seq: 5 });
    cl({ seq: '0x10' }, { seq: ' 16 ' });
    cl({ seq: '99999999999999999999999' }, { seq: '1' });
    cl({ seq: 'abc' }, { seq: '1' });
    cl({ seq: '1' }, { seq: 1.5 });
    cl({ seq: 'abc' }, null);                                                         // a is read first
    cl(null, { seq: '1' });
    cl({}, { seq: '1' });
    cl('x', { seq: '1' });
    add('compareLocal', { a: { seq: '1' } });
    const rk = (fp, message) => add('receivedKey', { fp, message });
    rk(FP, { seq: '1', senderTs: '5', text: 'hi' });
    rk(FP, { seq: 1, senderTs: 5, text: 'hi' });
    rk(OTHER, { seq: '1', senderTs: '5', text: 'hi' });
    rk(FP, { seq: '1', senderTs: '5', text: 'hi!' });
    rk(FP, { seq: '1', senderTs: '5', text: 'a "quoted" \\ /\n\u0000 é 👋 ' + String.fromCodePoint(0x2028) });
    rk(FP, { seq: '1', senderTs: '5' });                                              // text undefined -> null
    rk(FP, { seq: '1', senderTs: '5', text: 12.5 });
    rk(undefined, { seq: '1', senderTs: '5', text: 'x' });
    rk(5, 'x');
    rk(FP, null);
    add('receivedKey', { fp: FP });
  }

  // ── check scheduling (text.js:256-329)
  {
    const a = hexFp('a'), b = hexFp('b'), c = hexFp('c'), now = '1790000000', today = '20000';
    const F = T.SMART_SYNC_FULL_SECONDS;
    add('needFullSync', { contactFps: [a], dmSync: {}, now });
    add('needFullSync', { contactFps: [a], dmSync: { [a]: now }, now });
    add('needFullSync', { contactFps: [a], dmSync: { [a]: String(1790000000 - F) }, now });
    add('needFullSync', { contactFps: [a], dmSync: { [a]: String(1790000000 - F - 1) }, now });
    add('needFullSync', { contactFps: [a, b], dmSync: { [a]: now }, now });
    add('needFullSync', { contactFps: [], dmSync: {}, now });
    add('needFullSync', { contactFps: [], dmSync: {}, now: 'x' });
    add('needFullSync', { contactFps: 'abc', dmSync: {}, now });                      // TypeError after the time check
    add('needFullSync', { contactFps: 'abc', dmSync: {}, now: 'x' });
    add('needFullSync', { contactFps: [a], dmSync: null, now });
    const dmSync = { [a]: now, [b]: String(1790000000 - F - 1), [c]: '0' };
    for (const fp of [a, b, c, hexFp('d')]) add('contactNeedsFullSync', { fp, dmSync, now });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: String(1790000000 - F) }, now });   // exactly 3 days: recent
    add('contactNeedsFullSync', { fp: a, now });
    add('contactNeedsFullSync', { fp: a, dmSync, now: 'x' });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: String(1790000000 + 999999) }, now });   // a future check time
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: 1790000000 }, now: 1790000000 });   // Numbers: String() then BigInt
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: 18446744073709551616 }, now: '18446744073709552000' });   // String(2^64) = "18446744073709552000"
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: 18446744073709551616 }, now: String(18446744073709552000n + 259201n) });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: U64_MAX }, now: D20 });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: D20 }, now: D20 });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: '01' }, now });
    add('contactNeedsFullSync', { fp: 'constructor', dmSync: {}, now });               // an inherited property is no time
    add('contactNeedsFullSync', { fp: 5, dmSync: { 5: now }, now });                   // the key is String(fp)
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: null }, now });
    add('contactNeedsFullSync', { fp: a, dmSync: { [a]: now }, now: null });
    add('contactDays', { fp: a, dmSync, now, today });
    add('contactDays', { fp: b, dmSync, now, today });
    add('contactDays', { fp: b, dmSync, now: 'x', today: 'y' });                      // time before day
    add('contactDays', { fp: b, dmSync, now, today: 'y' });
    add('contactDays', { fp: a, dmSync, now, today: 20000 });
    for (const t of ['20000', '3', '0', '5', '6', '7', '1', U64_MAX, D20])
      { add('fullDays', { today: t }); add('recentDays', { today: t }); }
    for (const t of ['x', '-1', '01', 20000, '', null]) { add('fullDays', { today: t }); add('recentDays', { today: t }); }
    add('fullDays', {});
  }

  // ── checkOrder (text.js:287)
  {
    const now = '1790000000';
    const contacts = ['1', '2', '3', '4', '5', '6'].map(ch => ({ fp: hexFp(ch) }));
    const dmSync = { [hexFp('1')]: now, [hexFp('2')]: now, [hexFp('3')]: now, [hexFp('5')]: '0', [hexFp('6')]: now };
    const messages = [
      { fp: hexFp('1'), dir: 'out', seq: '7' },
      { fp: hexFp('3'), dir: 'in', seq: '9' },
      { fp: hexFp('1'), dir: 'in', seq: '8' },
      { fp: hexFp('6'), dir: 'in', seq: 'x' },
      { fp: hexFp('9'), dir: 'in', seq: '99' }
    ];
    add('checkOrder', { contacts, dmSync, messages });
    add('checkOrder', { contacts: [{ fp: hexFp('2') }, { fp: hexFp('1') }], dmSync: { [hexFp('1')]: now, [hexFp('2')]: now }, messages: [{ fp: hexFp('1'), seq: '5' }, { fp: hexFp('2'), seq: '5' }] });   // tie: list order
    add('checkOrder', { contacts: [{ fp: hexFp('1') }, { fp: hexFp('2') }], dmSync: { [hexFp('1')]: now, [hexFp('2')]: now }, messages: [{ fp: hexFp('1'), seq: '9' }, { fp: hexFp('2'), seq: '10' }] });
    add('checkOrder', { contacts, dmSync: {}, messages: [] });
    add('checkOrder', { contacts });
    add('checkOrder', { contacts: [], dmSync: {}, messages });
    // ties inside each rank, seq forms, extra fields echoed
    add('checkOrder', {
      contacts: [{ fp: hexFp('1'), salt: 's', listed: true, 10: 'x' }, { fp: hexFp('2') }, { fp: hexFp('3') }, { fp: hexFp('4') }, { fp: hexFp('5') }, 'x', 7, [1]],
      dmSync: { [hexFp('1')]: now, [hexFp('2')]: now, [hexFp('3')]: now, [hexFp('4')]: 5, 5: now },
      messages: [{ fp: hexFp('2'), seq: 9 }, { fp: hexFp('3'), seq: '9' }, { fp: hexFp('1'), seq: D20 }, { fp: hexFp('4'), seq: '01' }, null, 0, 'x', { seq: '5' }]
    });
    add('checkOrder', { contacts: [{ fp: hexFp('1') }], dmSync: { [hexFp('1')]: now }, messages: [{ fp: hexFp('1'), seq: 18446744073709551616 }] });
    add('checkOrder', { contacts, dmSync, messages: 'abc' });                          // for…of a string
    add('checkOrder', { contacts, dmSync, messages: 5 });                              // TypeError
    add('checkOrder', { contacts, dmSync, messages: {} });
    add('checkOrder', { contacts: [{ fp: hexFp('1') }, null], dmSync, messages });
    add('checkOrder', { contacts: 'abc', dmSync, messages });
    add('checkOrder', { contacts: 'abc', dmSync, messages: 5 });                       // the messages loop runs first
  }

  // ── profileFresh (text.js:318)
  {
    const at = 1790000000, P = T.PROFILE_CACHE_SECONDS;
    for (const [entry, now] of [[{ at: String(at) }, String(at)], [{ at: String(at) }, String(at + P - 1)], [{ at: String(at) }, String(at + P)],
      [{ at: String(at + 10) }, String(at)], [undefined, String(at)], [null, String(at)], ['x', String(at)], [{ at }, at],
      [{ at: String(at) }, 'x'], [{ at: String(at) }, undefined], [{ at: '01' }, String(at)], [{ at: U64_MAX }, U64_OVER], [{ at: '0' }, D20]])
      add('profileFresh', { entry, now });
  }

  // ── contact state (text.js:494-565; address-book.test.js 'contacts')
  {
    const OWN = hexFp('1'), CA = hexFp('2'), CB = hexFp('3'), CC = hexFp('4');
    const s = emptyState();
    const e1 = [{ fp: CA, salt: 'aa' }, { fp: CB }, { fp: OWN }, { fp: 'bad' }, null];
    add('mergeListedContacts', { state: s, entries: e1, ownFp: OWN });
    T.mergeListedContacts(s, e1, OWN);
    add('mergeListedContacts', { state: s, entries: [{ fp: CA, salt: 'aa' }, { fp: CB }], ownFp: OWN });
    s.dmSync[CA] = '100'; s.profileCache[CA] = { id: 'p' + '1'.padStart(20, '0'), at: '1', name: '' }; s.chainNames[CA] = { name: 'alice', at: '1' };
    s.acks[CA] = '5'; s.ackSent[CA] = '5'; s.chainNoName[CA] = '1790000000';
    add('removeContact', { state: s, fp: CA });
    T.removeContact(s, CA);
    add('removeContact', { state: s, fp: CA });
    const e2 = [{ fp: CA, salt: 'aa' }, { fp: CB }, { fp: CC }];
    add('mergeListedContacts', { state: s, entries: e2, ownFp: OWN });                 // removed stays removed
    T.mergeListedContacts(s, e2, OWN);
    add('unremoveContact', { state: s, fp: CA });
    T.unremoveContact(s, CA);
    add('mergeListedContacts', { state: s, entries: [{ fp: CA, salt: 'aa' }], ownFp: OWN });
    // salt filled, listed set — in the order the JS assigns them
    add('mergeListedContacts', { state: { contacts: [{ fp: CA, listed: false, note: 'n' }, { fp: CB, salt: '', listed: true }], removed: [] }, entries: [{ fp: CA }, { fp: CA, salt: 's2' }, { fp: CB, salt: 's3' }], ownFp: OWN });
    add('mergeListedContacts', { state: { contacts: [{ fp: CA, salt: 'kept' }], removed: null }, entries: [{ fp: CA, salt: 'other' }, { fp: CC }, { fp: CC, salt: 'cc' }], ownFp: OWN });   // a new one, then its salt
    add('mergeListedContacts', { state: { contacts: [{ fp: CA, salt: 1, listed: 'yes' }], removed: [CB, 5] }, entries: [{ fp: CA, salt: 2 }, { fp: CB }, { fp: CC, salt: 0 }, { fp: CC.toUpperCase() }, 'x', 7], ownFp: OWN });
    add('mergeListedContacts', { state: { contacts: [{ fp: CA }, null], removed: [] }, entries: [{ fp: CA }], ownFp: OWN });   // null after the match
    add('mergeListedContacts', { state: { contacts: [null, { fp: CA }], removed: [] }, entries: [{ fp: CA }], ownFp: OWN });   // TypeError
    add('mergeListedContacts', { state: { removed: [] }, entries: [{ fp: CA }], ownFp: OWN });                               // TypeError
    add('mergeListedContacts', { state: { removed: [] }, entries: [{ fp: OWN }], ownFp: OWN });                              // never reaches contacts
    add('mergeListedContacts', { state: { contacts: [], removed: [] }, entries: 'abc', ownFp: OWN });
    add('mergeListedContacts', { state: { contacts: [], removed: [] }, entries: 5, ownFp: OWN });
    add('mergeListedContacts', { state: { contacts: [], removed: [] }, ownFp: OWN });
    add('mergeListedContacts', { state: 5, entries: [], ownFp: OWN });
    add('mergeListedContacts', { state: 5, entries: [{ fp: CA }], ownFp: OWN });
    add('mergeListedContacts', { state: null, entries: [], ownFp: OWN });
    add('mergeListedContacts', { entries: [], ownFp: OWN });
    // removeContact: the maps' keys and the echo order (array-index keys first)
    add('removeContact', { state: { contacts: [{ fp: CB }, { fp: CA, salt: 'x' }], removed: [CC], dmSync: { [CA]: '1', 10: 'a', [CB]: '2' }, profileCache: { 2: { id: 'x' }, [CA]: { id: 'y' } }, chainNames: {}, keep: { nested: [1, { a: 2 }] } }, fp: CA });
    add('removeContact', { state: { contacts: [{ fp: CA }], removed: [CA], dmSync: {}, profileCache: {}, chainNames: {}, chainNoName: null }, fp: CA });   // already in removed
    add('removeContact', { state: { contacts: [{ fp: CA }], removed: null, dmSync: {}, profileCache: {}, chainNames: {} }, fp: CA });          // TypeError
    add('removeContact', { state: { contacts: [{ fp: CA }], removed: [], profileCache: {}, chainNames: {} }, fp: CA });                       // no dmSync: TypeError
    add('removeContact', { state: { contacts: [{ fp: CB }], removed: null }, fp: CA });                                                      // not found: nothing read
    add('removeContact', { state: { contacts: [{ salt: 's' }, { fp: CA }], removed: [], dmSync: { undefined: '1' }, profileCache: {}, chainNames: {} } });   // fp undefined: the first without fp
    add('removeContact', { state: { contacts: [7, { fp: CA }], removed: [], dmSync: {}, profileCache: {}, chainNames: {} } });
    add('removeContact', { state: { contacts: [{ fp: 5 }], removed: [], dmSync: { 5: 'x' }, profileCache: {}, chainNames: {} }, fp: 5 });
    add('removeContact', { state: { contacts: [null, { fp: CA }], removed: [], dmSync: {}, profileCache: {}, chainNames: {} }, fp: CA });
    add('removeContact', { state: 5, fp: CA });
    add('removeContact', { fp: CA });
    add('unremoveContact', { state: { removed: [CA, CB, CA, 5, null] }, fp: CA });
    add('unremoveContact', { state: { removed: [CA, 5] }, fp: 5 });
    add('unremoveContact', { state: { removed: [] } });
    add('unremoveContact', { state: { removed: null }, fp: CA });
    add('unremoveContact', { state: {}, fp: CA });
    add('unremoveContact', { state: 5, fp: CA });
  }

  // ── first records (text.js:547-565; connect-ui.test.js 'first records')
  {
    const own = 'ab'.repeat(64), other = 'cd'.repeat(64);
    const s = emptyState();
    add('firstRecordAllowed', { state: s, ownFp: own, kind: 'profile' });
    add('firstRecordAllowed', { state: s, ownFp: own, kind: 'list' });
    add('markOwnRecordSeen', { state: s, kind: 'profile', nowSec: '1791500000' });
    T.markOwnRecordSeen(s, 'profile', '1791500000');
    add('markOwnRecordSeen', { state: s, kind: 'profile', nowSec: '1791600000' });     // the first sighting is kept
    add('firstRecordAllowed', { state: s, ownFp: own, kind: 'profile' });
    add('firstRecordAllowed', { state: s, ownFp: own, kind: 'list' });
    const old = emptyState(); delete old.seenOwn;
    old.profileCache[own] = { id: 'p' + '1'.padStart(20, '0'), at: '1', name: '' };
    add('ownRecordSeen', { state: old, ownFp: own, kind: 'profile' });
    add('ownRecordSeen', { state: old, ownFp: other, kind: 'profile' });
    old.contacts.push({ fp: other, salt: null, listed: false });
    add('ownRecordSeen', { state: old, ownFp: own, kind: 'list' });
    old.contacts[0].listed = true;
    add('ownRecordSeen', { state: old, ownFp: own, kind: 'list' });
    add('firstRecordAllowed', { state: s, ownFp: own, kind: 'salt' });
    add('firstRecordAllowed', { state: null, ownFp: own, kind: 'profile' });
    add('markOwnRecordSeen', { state: s, kind: 'salt', nowSec: '1' });
    // edges
    add('ownRecordSeen', { ownFp: own, kind: 'profile' });                             // no state: true
    for (const st of [0, '', false]) add('ownRecordSeen', { state: st, ownFp: own, kind: 'profile' });
    for (const kind of ['profile', 'list', 'x']) add('ownRecordSeen', { state: 5, ownFp: own, kind });
    add('ownRecordSeen', { state: { seenOwn: { profile: '1' } }, ownFp: own, kind: 'profile' });
    add('ownRecordSeen', { state: { seenOwn: { profile: null } }, ownFp: own, kind: 'profile' });   // present, even null
    add('ownRecordSeen', { state: { seenOwn: null, profileCache: { [own]: 0 } }, ownFp: own, kind: 'profile' });
    add('ownRecordSeen', { state: { profileCache: { [own]: 'x' } }, ownFp: '', kind: 'profile' });
    add('ownRecordSeen', { state: { profileCache: {} }, ownFp: 'constructor', kind: 'profile' });   // an inherited property is truthy
    add('ownRecordSeen', { state: { profileCache: {} }, ownFp: 'hasOwnProperty', kind: 'profile' });
    add('ownRecordSeen', { state: { profileCache: {} }, ownFp: 'nothing', kind: 'profile' });
    add('ownRecordSeen', { state: { contacts: [null, 'x', { listed: 'true' }, { listed: true }] }, ownFp: own, kind: 'list' });
    add('ownRecordSeen', { state: { contacts: 'x' }, ownFp: own, kind: 'list' });
    add('markOwnRecordSeen', { state: { a: 1, seenOwn: null }, kind: 'list', nowSec: 5 });   // replaced in place, String(5)
    add('markOwnRecordSeen', { state: { a: 1 }, kind: 'list', nowSec: 1791500000 });
    add('markOwnRecordSeen', { state: { seenOwn: { list: '1' } }, kind: 'list', nowSec: '2' });
    add('markOwnRecordSeen', { state: { seenOwn: { 10: 'x', z: 'y' } }, kind: 'profile' });   // String(undefined)
    add('markOwnRecordSeen', { state: 5, kind: 'profile', nowSec: '1' });               // TypeError: a property on a primitive
    add('markOwnRecordSeen', { state: 5, kind: 'other', nowSec: '1' });
    add('markOwnRecordSeen', { state: null, kind: 'profile', nowSec: '1' });
    add('markOwnRecordSeen', { kind: 'profile', nowSec: '1' });
  }
  return V;
}

function main() {
  const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'connect-rules');
  mkdirSync(out, { recursive: true });
  for (const [file, make] of [['payload.json', cases], ['rules.json', rulesCases]]) {
    const vectors = make();
    writeFileSync(join(out, file), JSON.stringify(vectors, null, 1) + '\n');
    const gaps = vectors.filter(v => v.gap).length;
    console.log(`${file}: ${vectors.length} vectors (${gaps} marked gap)`);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
