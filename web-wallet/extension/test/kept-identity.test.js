import test from 'node:test';
import assert from 'node:assert/strict';
import { walletSession, phrase, address } from './fixtures/wallet-session.js';
import { identityKeyFor, parseIdentity, serializeIdentity } from '../../src/activity-storage.js';
import { IDENTITY_KEY } from '../../src/vault.js';

// The kept own identity of the extension's saved wallet (decision 2026-10-02-device-cache-only-when-saved): the own
// name and addresses are kept encrypted in the extension's storage, shown at once as an unconfirmed name, replaced by the
// lookup's answer, and unreadable after lock. Environment: Node >=22.14, the real background nodus session with a
// controllable Nodus module (nameOf), in-memory storage; no flags, no network, nothing left on disk.
const module = nameOf => ({ nameOf, async nameLookup() { return { found: false, committedHeight: '10' }; }, async profileAddress() { throw new Error('Unexpected profile read.'); } });
const turns = async () => { for (let i = 0; i < 20; i++) await new Promise(resolve => setImmediate(resolve)); };
// A kept record with a name and NO addresses: the own addresses in a record read back later can only come from the save
// the unlock makes.
const seeded = name => async ({ values, id }) => { values[IDENTITY_KEY] = await serializeIdentity(id, { name, addresses: {} }, await identityKeyFor(phrase, id)); };
// Waits until every save queued before it has finished: the background's saves share one ordered chain, and a balances save
// joins the end of it. (No fixed number of event-loop turns: the encryption takes real time.)
const flushed = nodus => nodus.keepBalances({});
// Two lookups answering the same name at once: the second must not return before the record holds that name.
test('a second answer with the same name returns only after the record is saved', async t => {
  const { nodus, values, id } = await walletSession(t, { module: module(async () => ({ found: true, name: 'samename', committedHeight: '10' })) });
  const first = nodus.getOwnName(), second = nodus.getOwnName();
  await second;
  assert.equal((await parseIdentity(values[IDENTITY_KEY], id, await identityKeyFor(phrase, id))).name, 'samename');
  await first;
});

// Proves the kept name is in the public state the moment the wallet is unlocked, while the lookup is still pending, and
// that the answer replaces it (found: the new name is saved; the saved record decrypts to it), while getOwnName itself
// still waits for the network rather than answering from the unconfirmed name. Could falsely pass if the state's name came
// from the lookup: the lookup is held closed until after the first assertions.
test('the kept name is shown before the lookup answers and the answer replaces and saves it', async t => {
  let release; const gate = new Promise(resolve => { release = resolve; });
  const { nodus, values, id } = await walletSession(t, { beforeOpen: seeded('keptname'), module: module(async () => { await gate; return { found: true, name: 'newname', committedHeight: '10' }; }) });
  assert.equal(nodus.getState().keptOwnName, 'keptname');
  let answered = false; const reading = nodus.getOwnName().then(own => { answered = true; return own; });
  await turns(); assert.equal(answered, false, 'getOwnName waits for the network: the kept name is unconfirmed');
  release(); assert.deepEqual(await reading, { found: true, name: 'newname' });
  assert.equal(nodus.getState().keptOwnName, 'newname'); await turns();
  assert.equal((await parseIdentity(values[IDENTITY_KEY], id, await identityKeyFor(phrase, id))).name, 'newname');
});

// Proves a lookup that answers "no name" removes the kept name from the state and from the saved record. Could falsely
// pass if the record never held a name; the seed has one and the first assertion shows it.
test('a not-found answer removes the kept name', async t => {
  const { nodus, values, id } = await walletSession(t, { beforeOpen: seeded('keptname'), module: module(async () => ({ found: false, committedHeight: '10' })) });
  assert.equal(nodus.getState().keptOwnName, 'keptname');
  assert.deepEqual(await nodus.getOwnName(), { found: false }); await turns();
  assert.equal(nodus.getState().keptOwnName, '');
  const saved = await parseIdentity(values[IDENTITY_KEY], id, await identityKeyFor(phrase, id));
  assert.equal(saved.name, undefined); assert.equal(saved.addresses.nodus, address);
});

// Proves a failed lookup leaves the kept name (the network could not say), and that the own addresses are kept at
// unlock. Could falsely pass if the failure were never reached; the read count guards that.
test('a failed lookup keeps the name, and the addresses are saved at unlock', async t => {
  let reads = 0;
  const { nodus, values, id } = await walletSession(t, { beforeOpen: seeded('keptname'), module: module(async () => { reads++; throw new Error('network error'); }) });
  await assert.rejects(nodus.getOwnName(), /network error/); assert.equal(reads, 1);
  assert.equal(nodus.getState().keptOwnName, 'keptname'); await flushed(nodus);
  const saved = await parseIdentity(values[IDENTITY_KEY], id, await identityKeyFor(phrase, id));
  assert.equal(saved.name, 'keptname'); assert.equal(saved.addresses.nodus, address);
});

// Proves nothing is readable after lock: the state holds no name, the stored record is ciphertext (neither the name nor
// the address appears in it) and is bound to this wallet's id (another id is refused). Could falsely pass if the record were empty; it is
// checked to exist first.
test('after lock the kept name is gone from the state and the stored record is only ciphertext', async t => {
  const { nodus, values, id, lockCoordinator } = await walletSession(t, { beforeOpen: seeded('keptname'), module: module(async () => ({ found: true, name: 'keptname', committedHeight: '10' })) });
  assert.equal(nodus.getState().keptOwnName, 'keptname'); await flushed(nodus);
  assert.ok(values[IDENTITY_KEY]); await lockCoordinator.lock();
  assert.equal(nodus.getState().keptOwnName, '');
  assert.ok(!values[IDENTITY_KEY].includes('keptname') && !values[IDENTITY_KEY].includes(address));
  await assert.rejects(parseIdentity(values[IDENTITY_KEY], Buffer.alloc(16, 8).toString('base64'), await identityKeyFor(phrase, id)), /do not match/);
  assert.notEqual(id, Buffer.alloc(16, 8).toString('base64'));
});
