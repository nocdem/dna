// P1 rules — the shared vectors, generated FROM the JavaScript
// (docs/plans/2026-10-12-connect-core-p1-rules-design.md rev 2, §2, §5).
//
//   node test/tools/gen-connect-rule-vectors.mjs
//     -> test/vectors/connect-rules/payload.json
//
// The functions of src/connect/ui/actions.js are the specification: every
// vector's "expect" is what the JS function returns for its "args", through
// the SAME argument contract and result encoding as the C dispatcher
// (connect/nc_rules_json.h). A vector is
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
  parseReply: a => A.parseReply(scalar(a, 'text'))
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
      out[k] = encode(x);
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

function main() {
  const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'connect-rules');
  mkdirSync(out, { recursive: true });
  const vectors = cases();
  writeFileSync(join(out, 'payload.json'), JSON.stringify(vectors, null, 1) + '\n');
  const gaps = vectors.filter(v => v.gap).length;
  console.log(`payload.json: ${vectors.length} vectors (${gaps} marked gap)`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
