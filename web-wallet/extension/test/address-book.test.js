import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, phrase } from './fixtures/wallet-session.js';
import { addressBookKeyFor, serializeAddressBook } from '../../src/activity-storage.js';
import { ADDRESS_BOOK_KEY } from '../../src/vault.js';

// Package C: cross-read the unchanged web-wallet format. No flags/network or
// artifacts. Extension-only round trips could pass with a different format.
test('address book reads the web-wallet ciphertext and locks away its in-memory copy', async t => {
  const entries = [{ id: 'a1', label: 'Public recipient', network: 'ethereum', address: '0x0000000000000000000000000000000000000001' }];
  const { nodus, values, lockCoordinator } = await walletSession(t, { beforeOpen: async ({ values, id }) => {
    values[ADDRESS_BOOK_KEY] = await serializeAddressBook(id, entries, await addressBookKeyFor(phrase, id));
  } });
  assert.deepEqual(nodus.getAddressBook().entries, entries);
  await nodus.setAddressBook(entries);
  assert.ok(!values[ADDRESS_BOOK_KEY].includes(entries[0].label));
  await lockCoordinator.lock(); assert.throws(() => nodus.getAddressBook(), /locked/);
});
