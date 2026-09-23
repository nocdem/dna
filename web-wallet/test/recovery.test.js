import test from 'node:test';
import assert from 'node:assert/strict';
import { Mnemonic } from 'ethers';
import { newPhrase, deriveWallet } from '../src/keys.js';
import { validateNodusPhrase, wordSuggestions } from '../src/recovery.js';
import { encryptVault } from '../src/vault.js';

test('Nodus creation and recovery use only a valid 24-word base phrase', async () => {
  const created = newPhrase(); assert.equal(created.split(' ').length, 24);
  assert.equal(validateNodusPhrase(created), created);
  for (const size of [16, 20, 24, 28]) {
    const phrase = Mnemonic.entropyToPhrase(new Uint8Array(size));
    assert.throws(() => validateNodusPhrase(phrase), /24-word/);
    assert.throws(() => deriveWallet(phrase), /24-word/);
    await assert.rejects(encryptVault(phrase, 'violet river telescope orchard'), /24-word/);
  }
  assert.throws(() => validateNodusPhrase('abandon '.repeat(24)), /invalid/);
});

test('local suggestions follow the current word prefix and position, including edits in the middle', () => {
  const a = wordSuggestions('a', 1); assert.equal(a.position, 1);
  assert.ok(a.words.length > 1); assert.ok(a.words.every(word => word.startsWith('a')));
  const ab = wordSuggestions('ab', 2); assert.ok(ab.words.every(word => word.startsWith('ab')));
  assert.ok(ab.words.includes('abandon')); assert.ok(ab.words.includes('about'));
  const middle = wordSuggestions('ability ab zoo', 10);
  assert.equal(middle.position, 2); assert.equal(middle.start, 8); assert.equal(middle.end, 10);
  assert.deepEqual(middle.words, ab.words);
  assert.equal(wordSuggestions('ability ', 8), null);
  assert.equal(wordSuggestions('a1', 2), null);
  assert.equal(wordSuggestions('abandon '.repeat(24) + 'a', 193), null);
  assert.equal(wordSuggestions('a', -1), null);
});
