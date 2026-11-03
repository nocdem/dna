// REVEAL RECOVERY PHRASE — shared block (src/reveal-phrase.js), plan
// docs/plans/approved/2026-11-03-reveal-phrase.md sections 2.1 and 5.
//
// What each test proves:
//   1. renderRevealBlock builds the extension's block (same tags, texts, ids,
//      attributes, order); submitting passes the typed value to `reveal` with
//      the hidden container, and the input is empty before `reveal` runs.
//   2. setPasswordRequired(false) hides label and input and removes `required`
//      (the form is then the "Reveal phrase" button only); submitting calls
//      `reveal` with no password; setPasswordRequired(true) restores them.
//   3. showRevealedPhrase fills 24 read-only inputs with ids reveal-phrase-1..24
//      (never phrase-N, so they cannot duplicate the restore form's ids) and
//      un-hides the container; clearRevealedPhrase removes every node and
//      hides the container again.
//   4. createPhraseFields keeps its default ids (phrase-N, phrase-suggestions-N).
// What it needs: node:test only; no network, no storage, no browser.
// What it leaves behind: nothing (the fake document is removed after each test).
// How it can falsely pass: the fake document is not a browser (no layout, no
// real `hidden` semantics); the browser tests (test/browser-smoke.js,
// test/connect-smoke.js, test/browser-security.js) cover the real page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderRevealBlock, showRevealedPhrase, clearRevealedPhrase } from '../src/reveal-phrase.js';
import { createPhraseFields } from '../src/phrase-fields.js';

class Node extends EventTarget {
  constructor(tag) {
    super(); this.tagName = tag; this.children = []; this.attributes = {};
    this.value = ''; this.hidden = false; this.text = ''; this.className = ''; this.id = '';
  }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.text = ''; this.children = nodes; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() {}
}
const fakeDocument = { createElement: tag => new Node(tag) };
function descendants(node, predicate) {
  return node.children.flatMap(child => [...(predicate(child) ? [child] : []), ...descendants(child, predicate)]);
}
function withDocument(t) {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'document');
  globalThis.document = fakeDocument;
  t.after(() => { if (saved) Object.defineProperty(globalThis, 'document', saved); else delete globalThis.document; });
}
const PHRASE = Array.from({ length: 24 }, (_, index) => `word${index + 1}`).join(' ');

test('renderRevealBlock builds the extension block and passes the typed value, emptied first', async () => {
  const calls = [];
  let inputAtCall;
  const built = renderRevealBlock(fakeDocument, {
    reveal: (password, container) => { inputAtCall = built.password.value; calls.push([password, container]); },
  });
  const { block, password, recovery } = built;
  assert.equal(block.tagName, 'div'); assert.equal(block.className, 'page-block');
  assert.deepEqual(block.children.map(node => node.tagName), ['h2', 'form', 'div']);
  assert.equal(block.children[0].textContent, 'Reveal recovery phrase');
  assert.equal(block.children[2], recovery); assert.equal(recovery.hidden, true);
  const form = block.children[1];
  assert.deepEqual(form.children.map(node => node.tagName), ['label', 'input', 'button']);
  const [label, input, submit] = form.children;
  assert.equal(input, password);
  assert.equal(label.textContent, 'Re-enter your password'); assert.equal(label.htmlFor, 'reveal-password');
  assert.equal(input.id, 'reveal-password'); assert.equal(input.type, 'password');
  assert.equal(input.autocomplete, 'current-password'); assert.equal(input.required, true); assert.equal(input.maxLength, 1024);
  assert.equal(submit.textContent, 'Reveal phrase'); assert.equal(submit.type, 'submit');
  input.value = 'freshly-entered-password';
  let prevented = false;
  await form.onsubmit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.deepEqual(calls, [['freshly-entered-password', recovery]]);
  assert.equal(inputAtCall, ''); assert.equal(input.value, '');
});

test('setPasswordRequired(false) leaves only the button; (true) restores the form', async () => {
  const calls = [];
  const built = renderRevealBlock(fakeDocument, { reveal: (password, container) => calls.push([password, container]) });
  const form = built.block.children[1];
  const [label, input, submit] = form.children;
  built.setPasswordRequired(false);
  assert.equal(label.hidden, true); assert.equal(input.hidden, true); assert.equal(input.required, false);
  assert.equal(submit.hidden, false);
  await form.onsubmit({ preventDefault() {} });
  assert.deepEqual(calls, [['', built.recovery]]);
  built.setPasswordRequired(true);
  assert.equal(label.hidden, false); assert.equal(input.hidden, false); assert.equal(input.required, true);
});

test('showRevealedPhrase shows 24 read-only words under reveal-phrase-N ids; clearRevealedPhrase removes them', t => {
  withDocument(t);
  const container = new Node('div'); container.hidden = true;
  showRevealedPhrase(fakeDocument, container, PHRASE);
  assert.equal(container.hidden, false);
  const inputs = descendants(container, node => node.tagName === 'input');
  assert.equal(inputs.length, 24);
  assert.deepEqual(inputs.map(input => input.id), Array.from({ length: 24 }, (_, index) => `reveal-phrase-${index + 1}`));
  assert.ok(inputs.every(input => input.readOnly === true));
  assert.equal(inputs.map(input => input.value).join(' '), PHRASE);
  assert.equal(descendants(container, node => node.id === 'phrase-1').length, 0);
  clearRevealedPhrase(container);
  assert.equal(container.children.length, 0); assert.equal(container.hidden, true);
  assert.equal(descendants(container, node => node.tagName === 'input').length, 0);
  assert.equal(container.textContent.includes('word1'), false);
});

test('createPhraseFields keeps the default ids and honours an id prefix', t => {
  withDocument(t);
  const plain = new Node('div'), prefixed = new Node('div');
  createPhraseFields(plain, new Node('p'));
  createPhraseFields(prefixed, new Node('p'), { idPrefix: 'reveal-phrase' });
  const ids = grid => descendants(grid, node => node.tagName === 'input' || (node.tagName === 'div' && node.id)).map(node => node.id);
  assert.equal(ids(plain)[0], 'phrase-1'); assert.ok(ids(plain).includes('phrase-suggestions-1'));
  assert.equal(ids(prefixed)[0], 'reveal-phrase-1'); assert.ok(ids(prefixed).includes('reveal-phrase-suggestions-1'));
  assert.equal(ids(prefixed).some(id => id.startsWith('phrase-')), false);
});
