// Address book (src/address-book.js, stored by src/activity-storage.js) and
// removing a contact in Messages (src/connect/ui/text.js, src/connect/store.js).
// Operator 2026-10-03: contacts can be added and removed in Contacts; an
// address book of saved recipients for every network the wallet sends on.
import test from 'node:test';
import assert from 'node:assert/strict';
import { getAddress } from 'ethers';
import {
  ADDRESS_BOOK_MAX, ADDRESS_LABEL_MAX, addressLabel, checkAddress, addAddress, updateAddress, removeAddress,
  addressesFor, findAddress, sortAddressBook, checkAddressBook
} from '../src/address-book.js';
import { addressBookKeyFor, serializeAddressBook, parseAddressBook, balancesKeyFor, serializeBalances, parseBalances } from '../src/activity-storage.js';
import { isRecipientAddress as evmAddress } from '../src/adapters/evm.js';
import { nodusRecipient } from '../src/adapters/nodus.js';
import { validateCellframeAddress } from '../src/cpunk-protocol.js';
import { mergeListedContacts, removeContact, unremoveContact } from '../src/connect/ui/text.js';
import { emptyState, checkState } from '../src/connect/store.js';

// The checks src/app.js hands in (ADDRESS_CHECKS), minus TRON / Solana,
// whose adapters are covered by their own tests; `tronLike` stands for a
// case-sensitive check that keeps the text as typed.
const evm = text => { if (!evmAddress(text)) throw new Error('Enter an Ethereum address.'); return getAddress(text); };
const tronLike = text => { if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(text)) throw new Error('Enter a TRON address.'); return text; };
const validators = { ethereum: evm, bsc: evm, nodus: nodusRecipient, cellframe: validateCellframeAddress, tron: tronLike };

const ETH = '0x52908400098527886e0f7030069857d2e4169ee7';            // EIP-55 test vector, all lower case
const ETH_SUM = '0x52908400098527886E0F7030069857D2E4169EE7';        // its checksummed form
const NODUS = 'ab'.repeat(64);
const TRON = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const id = Buffer.alloc(16, 7).toString('base64'), otherId = Buffer.alloc(16, 8).toString('base64');

test('address book: a name is required, trimmed, bounded, without line breaks, invisible or direction characters or mixed alphabets', () => {
  assert.equal(addressLabel('  Mum  '), 'Mum');
  assert.equal(addressLabel('Ayşe Öztürk'), 'Ayşe Öztürk');
  assert.equal(addressLabel('x'.repeat(ADDRESS_LABEL_MAX)), 'x'.repeat(ADDRESS_LABEL_MAX));
  for (const bad of ['', '   ', 'x'.repeat(ADDRESS_LABEL_MAX + 1), 'a\nb', 'a b', 'ab‮', 'a​b', 'pаypal' /* Cyrillic а */, 42, null]) {
    assert.throws(() => addressLabel(bad), Error, String(bad));
  }
});

test('address book: each address is checked by its own network and saved in that check\'s form', () => {
  assert.equal(checkAddress('ethereum', ETH, validators), ETH_SUM);
  assert.equal(checkAddress('nodus', ` ${NODUS.toUpperCase()} `, validators), NODUS);
  assert.equal(checkAddress('tron', TRON, validators), TRON);
  // an Ethereum address with a wrong mixed-case checksum is refused
  assert.throws(() => checkAddress('ethereum', '0x52908400098527886E0F7030069857D2E4169Ee7', validators));
  // an address of another network is refused by this network's check
  assert.throws(() => checkAddress('tron', ETH, validators), /TRON/);
  assert.throws(() => checkAddress('nodus', ETH, validators), /Nodus/);
  // a network without a check (not in this build) cannot be saved
  assert.throws(() => checkAddress('ixios', ETH, validators), /cannot be saved/);
  assert.throws(() => checkAddress('ethereum', '  ', validators), /Enter the address/);
});

test('address book: add, the same address on the same network once, the same address on another network allowed', () => {
  let list = addAddress([], { label: 'Bob', network: 'ethereum', address: ETH }, validators);
  assert.deepEqual(list, [{ id: 'a1', label: 'Bob', network: 'ethereum', address: ETH_SUM }]);
  assert.throws(() => addAddress(list, { label: 'Bob again', network: 'ethereum', address: ETH_SUM }, validators), /already saved as “Bob”/);
  list = addAddress(list, { label: 'Bob', network: 'bsc', address: ETH }, validators);
  list = addAddress(list, { label: 'alice', network: 'tron', address: TRON }, validators);
  // shown by name (letter case ignored), then by network
  assert.deepEqual(list.map(e => [e.id, e.label, e.network]), [['a3', 'alice', 'tron'], ['a2', 'Bob', 'bsc'], ['a1', 'Bob', 'ethereum']]);
  // the send form of a network sees only that network's entries
  assert.deepEqual(addressesFor(list, 'tron').map(e => e.address), [TRON]);
  assert.deepEqual(addressesFor(list, 'solana'), []);
  assert.equal(findAddress(list, 'bsc', ETH_SUM).id, 'a2');
  assert.equal(findAddress(list, 'bsc', TRON), undefined);
});

test('address book: edit and delete; ids are not reused while their entry exists; the list never changes in place', () => {
  const one = addAddress([], { label: 'Bob', network: 'nodus', address: NODUS }, validators);
  const two = addAddress(one, { label: 'Carol', network: 'tron', address: TRON }, validators);
  assert.equal(one.length, 1);
  const edited = updateAddress(two, 'a1', { label: 'Robert', network: 'nodus', address: NODUS }, validators);
  assert.deepEqual(edited.find(e => e.id === 'a1'), { id: 'a1', label: 'Robert', network: 'nodus', address: NODUS });
  assert.equal(two.find(e => e.id === 'a1').label, 'Bob');
  assert.throws(() => updateAddress(two, 'a1', { label: 'Bob', network: 'tron', address: TRON }, validators), /already saved as “Carol”/);
  assert.throws(() => updateAddress(two, 'a9', { label: 'X', network: 'nodus', address: NODUS }, validators), /no longer/);
  const removed = removeAddress(two, 'a1');
  assert.deepEqual(removed.map(e => e.id), ['a2']);
  assert.equal(addAddress(removed, { label: 'Dan', network: 'nodus', address: NODUS }, validators).find(e => e.label === 'Dan').id, 'a3');
});

test('address book: at most ADDRESS_BOOK_MAX entries; the order is the same for the same list', () => {
  let list = [];
  for (let i = 0; i < ADDRESS_BOOK_MAX; i++) list.push({ id: `a${i + 1}`, label: `n${i}`, network: 'nodus', address: i.toString(16).padStart(128, '0') });
  assert.throws(() => addAddress(list, { label: 'one more', network: 'tron', address: TRON }, validators), /full/);
  const shuffled = [...list].reverse();
  assert.deepEqual(sortAddressBook(shuffled), sortAddressBook(list));
});

test('address book: a stored list is checked entry by entry; an entry of a network this build has no check for is kept only as plain text', () => {
  const list = addAddress(addAddress([], { label: 'Bob', network: 'ethereum', address: ETH }, validators), { label: 'Ix', network: 'tron', address: TRON }, validators);
  assert.deepEqual(checkAddressBook(structuredClone(list), validators), list);
  // a build without the TRON check keeps the entry as saved
  const noTron = { ...validators }; delete noTron.tron;
  assert.deepEqual(checkAddressBook(structuredClone(list), noTron), list);
  for (const bad of [
    {}, [list[0], list[0]],
    [{ ...list[0], id: 'b1' }], [{ ...list[0], extra: 1 }], [{ ...list[0], label: 'a‮b' }],
    [{ ...list[0], address: ETH }],                       // not the saved (checksummed) form
    [{ ...list[0], network: 'Ethereum' }],
    [{ id: 'a1', label: 'x', network: 'ixios', address: 'has space' }],
    [{ ...list[0] }, { ...list[0], id: 'a7' }]             // same network + address twice
  ]) assert.throws(() => checkAddressBook(bad, validators), /Invalid saved address book/);
  assert.throws(() => checkAddressBook(Array.from({ length: ADDRESS_BOOK_MAX + 1 }, () => list[0]), validators), /Invalid saved address book/);
});

test('address book storage: encrypted under its own key, bound to the vault id, refused when changed', async () => {
  const key = await addressBookKeyFor(phrase, id);
  const list = addAddress([], { label: 'Bob', network: 'nodus', address: NODUS }, validators);
  const text = await serializeAddressBook(id, list, key);
  // The plaintext never appears: only the sealed record's five fields are
  // stored, and no JSON fragment of an entry is in it. (The old check,
  // !text.includes('Bob'), failed by chance whenever the random base64 iv
  // or ciphertext happened to contain those three letters.)
  assert.deepEqual(Object.keys(JSON.parse(text)).sort(), ['cipher', 'ciphertext', 'id', 'iv', 'version']);
  assert.ok(!text.includes('"label"') && !text.includes('"Bob"') && !text.includes(`"${NODUS}"`));
  assert.deepEqual(await parseAddressBook(text, id, key, validators), list);
  assert.deepEqual(await parseAddressBook(null, id, key, validators), []);
  await assert.rejects(parseAddressBook(text, otherId, key, validators), /do not match/);
  await assert.rejects(parseAddressBook(text, id, await balancesKeyFor(phrase, id), validators), /authentication failed/);
  const data = JSON.parse(text);
  const ct = Buffer.from(data.ciphertext, 'base64'); ct[0] ^= 1;
  await assert.rejects(parseAddressBook(JSON.stringify({ ...data, ciphertext: ct.toString('base64') }), id, key, validators), /authentication failed/);
  // and the address book key cannot read balances
  const balances = await serializeBalances(id, {}, await balancesKeyFor(phrase, id));
  await assert.rejects(parseBalances(balances, id, key), /authentication failed/);
  // a sealed list that does not check out is refused after decryption
  await assert.rejects(parseAddressBook(await serializeAddressBook(id, [{ id: 'a1', label: '', network: 'nodus', address: NODUS }], key), id, key, validators), /Invalid saved address book/);
});

const FP = n => n.toString(16).repeat(128).slice(0, 128);
const OWN = FP(1), A = FP(2), B = FP(3), C = FP(4);

test('contacts: the network list is merged in, but a contact removed on this device is not added back', () => {
  const state = emptyState();
  assert.equal(mergeListedContacts(state, [{ fp: A, salt: 'aa' }, { fp: B }, { fp: OWN }, { fp: 'bad' }, null], OWN), true);
  assert.deepEqual(state.contacts.map(c => c.fp), [A, B]);
  assert.equal(mergeListedContacts(state, [{ fp: A, salt: 'aa' }, { fp: B }], OWN), false);

  state.dmSync[A] = '100'; state.profileCache[A] = { id: 'p' + '1'.padStart(20, '0'), at: '1', name: '' }; state.chainNames[A] = { name: 'alice', at: '1' };
  state.acks[A] = '5'; state.ackSent[A] = '5';
  assert.equal(removeContact(state, A), true);
  assert.deepEqual(state.contacts.map(c => c.fp), [B]);
  assert.deepEqual(state.removed, [A]);
  assert.equal(state.dmSync[A], undefined);
  assert.equal(state.profileCache[A], undefined);
  assert.equal(state.chainNames[A], undefined);
  // the ACK values stay (no second ACK of messages already acknowledged)
  assert.equal(state.acks[A], '5'); assert.equal(state.ackSent[A], '5');
  assert.equal(removeContact(state, A), false);
  assert.deepEqual(state.removed, [A]);

  // the network list still holds A (merge-only): it stays removed; C is new
  assert.equal(mergeListedContacts(state, [{ fp: A, salt: 'aa' }, { fp: B }, { fp: C }], OWN), true);
  assert.deepEqual(state.contacts.map(c => c.fp), [B, C]);

  // added again (a request accepted): the removal is forgotten, the list merges it again
  unremoveContact(state, A);
  assert.deepEqual(state.removed, []);
  assert.equal(mergeListedContacts(state, [{ fp: A, salt: 'aa' }], OWN), true);
  assert.deepEqual(state.contacts.map(c => c.fp), [B, C, A]);
  assert.deepEqual(checkState(state), state);
});

test('contacts: the removed list is part of the saved state; an older state gets an empty one; a bad entry is refused', () => {
  assert.deepEqual(emptyState().removed, []);
  const old = emptyState(); delete old.removed;
  assert.deepEqual(checkState(old).removed, []);
  assert.throws(() => checkState({ ...emptyState(), removed: {} }));
  assert.throws(() => checkState({ ...emptyState(), removed: ['xyz'] }));
  assert.deepEqual(checkState({ ...emptyState(), removed: [A] }).removed, [A]);
});
