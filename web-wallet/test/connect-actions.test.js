// Message actions (web 0.1.89, src/connect/ui/actions.js): the content hash
// against the DNA Connect library's OWN stored hashes, and the app's
// reaction / delete / reply forms.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  contentHash, messageHash, REACTION_EMOJIS, buildReaction, parseReaction, reactionSummary, ownReactionOn,
  buildDelete, parseDelete, deletions, buildReply, parseReply, QUOTE_MAX
} from '../src/connect/ui/actions.js';

const A = '7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd';
const B = '9c9d9b0ed03421fd7889660905e37c735cbfb673e39c567c1de2a73497f9f5fc725f667566507a36d510039f49e22c9518649b3644265f2174dd17f92830ddec';

// Produced 2026-10-09 by a scratch program linked against messenger/build/
// libdna.so (main 0bfb1099): message_backup_save(sender, recipient, text,
// sender, ts, ...) into a scratch SQLite, then the content_hash column read
// back with message_backup_get_conversation — the app library's own value.
const ORACLE = [
  { s: A, r: B, text: 'hello', ts: '1791500000', hash: '12bb3fd8ecde894049bf3a089ff34941946eaf879210978015b8dafc5c4d53c1' },
  { s: B, r: A, text: 'Merhaba dünya 👋 — çok güzel', ts: '1791500123', hash: '1f4307973e2c188eac07e419f6f5dc19651795da1077a7b66ff295e720f333f2' },
  { s: A, r: B, text: '↩ Re: me\n> hello\nyes', ts: '1791600000', hash: '52b39061cca43c060b837bd76ed3877d8178a88ef25217f650e3cab27212c236' }
];

test('actions: the content hash equals the app library\'s stored hash', () => {
  for (const v of ORACLE) assert.equal(contentHash(v.s, v.r, v.text, v.ts), v.hash, v.text);
  // a record of this page: own send (ts) and a received one (senderTs)
  assert.equal(messageHash({ dir: 'out', fp: B, text: 'hello', ts: '1791500000' }, A), ORACLE[0].hash);
  assert.equal(messageHash({ dir: 'in', fp: B, text: ORACLE[1].text, senderTs: '1791500123' }, A), ORACLE[1].hash);
  assert.equal(contentHash('nope', B, 'x', '1'), null);
  assert.equal(contentHash(A, B, 'x', '-1'), null);
  assert.equal(contentHash(A, B, 'hello\0tail', '1791500000'), ORACLE[0].hash, 'read up to the first NUL, as the app');
});

test('actions: reactions — the app\'s exact form, toggles replayed in sender-time order', () => {
  const t = ORACLE[0].hash;
  const add = buildReaction(t, REACTION_EMOJIS[0], 'add');
  assert.equal(add, `{"target":"${t}","emoji":"${REACTION_EMOJIS[0]}","op":"add"}`);
  assert.deepEqual(parseReaction(add), { target: t, emoji: REACTION_EMOJIS[0], op: 'add' });
  assert.throws(() => buildReaction(t, '"', 'add'), /Invalid reaction/);
  assert.throws(() => buildReaction('zz', REACTION_EMOJIS[0], 'add'), /Invalid reaction/);
  assert.equal(parseReaction('{"target":"short","emoji":"x","op":"add"}'), null);
  assert.equal(parseReaction(`{"target":"${t}","emoji":"x","op":"maybe"}`), null);
  // the app's char[8]: up to 7 bytes kept, 8 and more dropped
  assert.equal(parseReaction(`{"target":"${t}","emoji":"1234567","op":"add"}`).emoji, '1234567');
  assert.equal(parseReaction(`{"target":"${t}","emoji":"12345678","op":"add"}`), null);
  assert.equal(parseReaction(`{"target":"${t}","emoji":"PAID 100 NODUS","op":"add"}`), null);
  assert.equal(parseReaction(`{"target":"${t}","emoji":"🎉🎉","op":"add"}`), null);
  const rec = (dir, fp, emoji, op, ts, seq) => ({ dir, fp, kind: 'reaction', text: buildReaction(t, emoji, op), ts, senderTs: ts, seq });
  const [heart, up] = REACTION_EMOJIS;
  const records = [
    rec('in', B, heart, 'add', '10', '1'),
    rec('out', B, heart, 'add', '11', '2'),
    rec('out', B, up, 'add', '12', '3'),
    rec('out', B, up, 'remove', '13', '4'),        // own 👍 taken back
    rec('in', B, up, 'add', '9', '5'),             // older than nothing else for B/👍
    { dir: 'in', fp: B, kind: 'chat', text: 'not a reaction', senderTs: '1', seq: '6' }
  ];
  const s = reactionSummary(records, A);
  assert.deepEqual(s.get(t), [{ emoji: heart, count: 2, mine: true }, { emoji: up, count: 1, mine: false }]);
  assert.equal(ownReactionOn(s, t, heart), true);
  assert.equal(ownReactionOn(s, t, up), false);
  // the same toggle arriving out of local order is ordered by sender time
  const late = reactionSummary([rec('in', B, heart, 'remove', '20', '1'), rec('in', B, heart, 'add', '15', '2')], A);
  assert.equal(late.get(t), undefined, 'remove at 20 wins over add at 15');
});

test('actions: delete notices apply only to the deleter\'s own messages; hide is local', () => {
  const mine = { dir: 'out', fp: B, kind: 'chat', text: 'hello', ts: '1791500000', seq: '1' };
  const theirs = { dir: 'in', fp: B, kind: 'chat', text: ORACLE[1].text, senderTs: '1791500123', seq: '2' };
  const hashOf = m => messageHash(m, A);
  const hMine = hashOf(mine), hTheirs = hashOf(theirs);
  assert.equal(buildDelete([hMine]), `{"type":"delete","action":0,"hashes":["${hMine}"]}`);
  assert.throws(() => buildDelete([]), /Invalid delete/);
  assert.deepEqual(parseDelete('{ "type": "delete", "action": 0, "hashes": [ "' + hMine.toUpperCase() + '" ] }'), { action: 0, hashes: [hMine] });
  assert.equal(parseDelete('{"type":"other"}'), null);
  // B deletes its own message and (maliciously) mine: only its own counts
  const fromB = { dir: 'in', fp: B, kind: 'delete', text: buildDelete([hTheirs, hMine]), senderTs: '1791600000', seq: '3' };
  let d = deletions([mine, theirs, fromB], A, hashOf);
  assert.deepEqual([...d.deleted], [hTheirs]);
  // I delete mine
  const fromMe = { dir: 'out', fp: B, kind: 'delete', text: buildDelete([hMine]), ts: '1791600001', seq: '4' };
  d = deletions([mine, theirs, fromMe], A, hashOf);
  assert.deepEqual([...d.deleted], [hMine]);
  // a notice for another action (whole conversation) is not applied here
  d = deletions([mine, { ...fromMe, text: JSON.stringify({ type: 'delete', action: 1, hashes: [hMine] }) }], A, hashOf);
  assert.equal(d.deleted.size, 0);
  // hidden on this device
  d = deletions([theirs, { dir: 'local', fp: B, kind: 'hide', target: hTheirs, seq: '5' }], A, hashOf);
  assert.deepEqual([...d.hidden], [hTheirs]);
});

test('actions: replies in the app\'s form; the quote stays one line', () => {
  const r = buildReply('me', 'hello', 'yes');
  assert.equal(r, '↩ Re: me\n> hello\nyes');
  assert.deepEqual(parseReply(r), { sender: 'me', quoted: 'hello', text: 'yes' });
  const long = 'x'.repeat(QUOTE_MAX + 5);
  assert.equal(parseReply(buildReply('Bob', long, 'ok')).quoted, `${'x'.repeat(QUOTE_MAX)}...`);
  const multi = buildReply('Bob\nEvil', 'line one\nline two', 'answer\nsecond line');
  assert.deepEqual(parseReply(multi), { sender: 'Bob Evil', quoted: 'line one line two', text: 'answer\nsecond line' });
  assert.equal(parseReply('hello'), null);
  assert.equal(parseReply('↩ Re: me\nno quote'), null);
  assert.equal([...parseReply(buildReply('a', '👋'.repeat(150), 'b')).quoted].length, QUOTE_MAX + 3, 'counted in characters, never a split emoji');
});

// Web 0.1.90: payment cards are claims — the verdict comes from this
// device's own address history (design 2026-10-09-connect-nodus-in-chat).
import { nodusUnits, buildTransfer, parseTransfer, transferVerdict } from '../src/connect/ui/actions.js';
test('payment cards: the app\'s form, amounts exact, the verdict from own history only', () => {
  const W = 'ee'.repeat(64), N = '0'.repeat(128), TOK = 'ab'.repeat(64);
  assert.equal(nodusUnits('1'), 100000000n);
  assert.equal(nodusUnits('1.5'), 150000000n);
  assert.equal(nodusUnits('0.00000001'), 1n);
  for (const bad of ['', '1.', '.5', '01', '1.123456789', '-1', '1e3', ' 1', 7]) assert.equal(nodusUnits(bad), null, String(bad));
  const text = buildTransfer({ amount: '2.5', wire: W, to: B, name: 'bob' });
  assert.deepEqual(JSON.parse(text), { type: 'token_transfer', amount: '2.5', token: 'NODUS', network: 'Nodus', chain: 'nodus', txHash: W, recipientAddress: B, recipientName: 'bob' });
  assert.throws(() => buildTransfer({ amount: '0', wire: W, to: B }), /Invalid payment card/);
  assert.throws(() => buildTransfer({ amount: '1', wire: 'xx', to: B }), /Invalid payment card/);
  const card = parseTransfer(text);
  assert.equal(parseTransfer('hello'), null);
  assert.equal(parseTransfer('{"type":"other"}'), null);
  const row = (kind, peer, amount, extra = {}) => ({ h: 900n, kind, peer, amount: BigInt(amount), token: N, wire: W, ...extra });
  // I (A) sent 2.5 to B: my spend_out to B confirms; B's card to me must name ME as recipient.
  assert.deepEqual(transferVerdict(card, [row('spend_out', B, 250000000)], { incoming: false, counterparty: B, ownFp: A }), { state: 'confirmed', height: '900' });
  // B receives it: its spend_in from A
  const inCard = parseTransfer(buildTransfer({ amount: '2.5', wire: W, to: B }));
  assert.deepEqual(transferVerdict(inCard, [row('spend_in', A, 250000000)], { incoming: true, counterparty: A, ownFp: B }).state, 'confirmed');
  // two coins to the same person in one item add up
  assert.equal(transferVerdict(inCard, [row('spend_in', A, 200000000), row('spend_in', A, 50000000)], { incoming: true, counterparty: A, ownFp: B }).state, 'confirmed');
  // nothing on the chain yet
  assert.equal(transferVerdict(inCard, [], { incoming: true, counterparty: A, ownFp: B }).state, 'pending');
  assert.equal(transferVerdict(inCard, [row('spend_in', A, 1, { wire: 'dd'.repeat(64) })], { incoming: true, counterparty: A, ownFp: B }).state, 'pending');
  // forged: a smaller real payment under the same wire, another payer, another token, another recipient named
  assert.equal(transferVerdict(inCard, [row('spend_in', A, 1)], { incoming: true, counterparty: A, ownFp: B }).state, 'mismatch');
  assert.equal(transferVerdict(inCard, [row('spend_in', '3c'.repeat(64), 250000000)], { incoming: true, counterparty: A, ownFp: B }).state, 'mismatch');
  assert.equal(transferVerdict(inCard, [row('spend_in', A, 250000000, { token: TOK })], { incoming: true, counterparty: A, ownFp: B }).state, 'mismatch');
  assert.equal(transferVerdict(inCard, [row('spend_out', A, 250000000)], { incoming: true, counterparty: A, ownFp: B }).state, 'mismatch', 'an outgoing row is no receipt');
  const toSomeoneElse = parseTransfer(buildTransfer({ amount: '2.5', wire: W, to: '3c'.repeat(64) }));
  assert.equal(transferVerdict(toSomeoneElse, [row('spend_in', A, 250000000)], { incoming: true, counterparty: A, ownFp: B }).state, 'mismatch');
  // another chain or a malformed card: cannot be checked here
  assert.deepEqual(transferVerdict({ ...card, chain: 'cellframe' }, [], { incoming: true, counterparty: A, ownFp: B }), { state: 'unverifiable', chain: 'cellframe' });
  assert.equal(transferVerdict({ ...card, amount: 'lots' }, [], { incoming: true, counterparty: A, ownFp: B }).state, 'unverifiable');
});

import { validNodusCard } from '../src/connect/ui/actions.js';
test('payment cards: only a well-formed NODUS card is shown and checked', () => {
  const W = 'ee'.repeat(64);
  const ok = parseTransfer(buildTransfer({ amount: '1', wire: W, to: B }));
  assert.equal(validNodusCard(ok), true);
  for (const bad of [{ token: 'X' }, { wire: 'zz' }, { to: 'nope' }, { amount: '1..5' }, { chain: 'cellframe' }]) assert.equal(validNodusCard({ ...ok, ...bad }), false, JSON.stringify(bad));
  assert.equal(validNodusCard(null), false);
});
