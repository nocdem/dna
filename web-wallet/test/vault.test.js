import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptVault, decryptVault, parseVault, validateNewPassword } from '../src/vault.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const password = 'public-test-password-123';
test('vault uses randomized authenticated encryption, rejects wrong password and metadata/ciphertext tampering', async () => {
  const a = await encryptVault(phrase, password), b = await encryptVault(phrase, password);
  assert.notEqual(a, b); assert.ok(!a.includes(phrase)); assert.ok(!a.includes(password));
  assert.equal((await decryptVault(a, password)).phrase, phrase);
  await assert.rejects(decryptVault(a, 'incorrect-password-123'), /Incorrect password/);
  for (const field of ['id', 'salt', 'iv', 'ciphertext']) {
    const changed = JSON.parse(a); changed[field] = (changed[field][0] === 'A' ? 'B' : 'A') + changed[field].slice(1);
    await assert.rejects(decryptVault(JSON.stringify(changed), password));
  }
  for (const field of ['version', 'iterations', 'cipher', 'kdf']) { const changed = JSON.parse(a); changed[field] = 0; assert.throws(() => parseVault(JSON.stringify(changed))); }
  assert.throws(() => parseVault(' '.repeat(6001)));
  await assert.rejects(encryptVault(phrase, 'short'), /16/);
  const changed = await encryptVault(phrase, 'changed-password-123', parseVault(a).id);
  assert.equal((await decryptVault(changed, 'changed-password-123')).id, parseVault(a).id);
  await assert.rejects(decryptVault(changed, password), /Incorrect password/);
});
test('encrypted history is bounded, scoped, rechecked after reload and excludes provider credentials', async () => {
  const addresses = { ethereum: '0xabc' };
  const row = { chain: 'ethereum', address: '0xabc', to: '0xdef', symbol: 'ETH', amount: '1', hash: '0x' + 'a'.repeat(64), endpoint: 'https://rpc.example/private-api-key?secret=abc', createdAt: new Date().toISOString(), status: 'confirmed', recoveryPhrase: phrase };
  const id = btoa('0123456789abcdef'), key = await activityKeyFor(phrase, id);
  const text = await serializeActivity(id, Array(101).fill(row), key);
  assert.ok(!text.includes('private-api-key')); assert.ok(!text.includes(phrase));
  const parsed = await parseActivity(text, id, addresses, key); assert.equal(parsed.length, 100); assert.equal(parsed[0].status, 'pending');
  assert.equal(parsed[0].endpoint, 'https://ethereum-rpc.publicnode.com');
  await assert.rejects(parseActivity(text, 'wrong', addresses, key));
  await assert.rejects(parseActivity(text, id, { ethereum: 'other' }, key));
});
test('saved activity keeps an abandoned mark permanent, resets other statuses to pending on reload, and validates a saved nonce', async () => {
  const addresses = { ethereum: '0xabc' };
  const id = btoa('fedcba9876543210'), key = await activityKeyFor(phrase, id);
  const base = { chain: 'ethereum', address: '0xabc', to: '0xdef', symbol: 'ETH', amount: '1', createdAt: new Date().toISOString() };
  const rows = [
    { ...base, hash: '0x' + 'a'.repeat(64), status: 'abandoned', nonce: 3 },
    { ...base, hash: '0x' + 'b'.repeat(64), status: 'replaced', nonce: 4 },
    { ...base, hash: '0x' + 'c'.repeat(64), status: 'confirmed' },
  ];
  const text = await serializeActivity(id, rows, key);
  const parsed = await parseActivity(text, id, addresses, key);
  assert.deepEqual(parsed.map(row => row.status), ['abandoned', 'pending', 'pending']);
  assert.equal(parsed[0].note, 'Marked abandoned by you; the network may still include it. Check the explorer.');
  assert.equal(parsed[0].nonce, 3); assert.equal(parsed[1].nonce, 4); assert.equal(parsed[2].nonce, undefined);
  const badNonce = await serializeActivity(id, [{ ...base, hash: '0x' + 'd'.repeat(64), status: 'pending', nonce: 1.5 }], key);
  await assert.rejects(parseActivity(badNonce, id, addresses, key), /Invalid saved activity/);
  const stringNonce = await serializeActivity(id, [{ ...base, hash: '0x' + 'e'.repeat(64), status: 'pending', nonce: '3' }], key);
  await assert.rejects(parseActivity(stringNonce, id, addresses, key), /Invalid saved activity/);
});
test('new local password rules close the anchored-regex bypass and reject common, patterned or low-diversity passwords', () => {
  // Passwords under 16 characters are rejected by the length rule first and are therefore not part of this vector set.
  for (const password of ['passwordwallet1!', 'Password12345678', 'qwertyuiop123456', 'nodus-wallet-2026', 'aaaaaaaaaaaaaaaa', 'abcdefghijklmnop1', 'administrator123']) assert.throws(() => validateNewPassword(password), /too easy to guess/, password);
  for (const password of ['correct horse battery staple', 'T7#kq9!zLm2@wpXe', 'blue-otter-piano-cloud-42']) assert.doesNotThrow(() => validateNewPassword(password), password);
});
