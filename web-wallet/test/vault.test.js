import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptVault, decryptVault, parseVault } from '../src/vault.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
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
