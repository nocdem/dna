// Run the actual unexported mutation/undo functions extracted from Messages.
// The real remove/unremove/undecline helpers supply interleaved local actions.
// Node22, no flags, DOM, network, persistence, or files left behind. This tests
// mutation ownership only; browser-contact-recovery covers real history/store.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { removeContact, unremoveContact, undecline } from '../src/connect/ui/text.js';
const source = readFileSync(new URL('../src/connect/ui/messages.js', import.meta.url), 'utf8');
function actual(name) {
  const matches = [...source.matchAll(new RegExp(`function ${name}\\([^]*?\\n\\}`, 'g'))];
  assert.equal(matches.length, 1, `must extract exactly one production ${name}`);
  return matches[0][0];
}
const factory = new Function('state', 'unremoveContact', 'undecline',
  `const contactOf = fp => state.contacts.find(c => c.fp === fp);\n${actual('addContactLocal')}\n${actual('prepareContactApproval')}\nreturn prepareContactApproval;`);
const A = '1a'.repeat(64), B = '2b'.repeat(64), SALT = '3c'.repeat(32);
const setup = () => ({ contacts: [{ fp: B, salt: SALT }], removed: [A], outgoing: [{ fp: A }],
  declined: [{ fp: A, at: '1' }], dmSync: {}, profileCache: {}, chainNames: {}, chainNoName: {}, history: ['kept'] });

test('failed approval restores only its own removal membership and keeps unrelated interleaved removal', () => {
  const state = setup(), history = state.history;
  const approve = factory(state, unremoveContact, undecline);
  const undo = approve(A, SALT);
  assert.equal(removeContact(state, B), true);
  undo(); undo();
  assert.deepEqual(state.contacts, []);
  assert.deepEqual([...state.removed].sort(), [A, B].sort());
  assert.deepEqual(state.outgoing, [{ fp: A }]);
  assert.deepEqual(state.declined, [{ fp: A, at: '1' }]);
  assert.equal(state.history, history);
});

test('approval rollback cannot undo a new removal of that same established contact', () => {
  const state = setup(); state.contacts.push({ fp: A, salt: SALT }); state.removed = [];
  const approve = factory(state, unremoveContact, undecline);
  const undo = approve(A, '4d'.repeat(32));
  assert.equal(removeContact(state, A), true); undo();
  assert.equal(state.contacts.some(c => c.fp === A), false);
  assert.ok(state.removed.includes(A));
  assert.deepEqual(state.history, ['kept']);
});
