import test from 'node:test';
import assert from 'node:assert/strict';
import { Messenger } from '@metamask/messenger';
import { createPersistedStore, STATE_KEY } from '../src/background/store.js';

// Node >=22.14; no flags/network/disk output. Storage and controllers below are explicit fixtures.
function storageFixture(initial = {}) {
  const values = structuredClone(initial), writes = [];
  return { values, writes,
    async get(key) { return { [key]: structuredClone(values[key]) }; },
    async set(items) { writes.push(structuredClone(items)); Object.assign(values, structuredClone(items)); },
  };
}

// Proves initial/update/backup projection overrides stock vault metadata; checking only the final write could miss a transient second vault.
test('the named single-vault metadata firewall covers every persistence path', async () => {
  const storage = storageFixture({ [STATE_KEY]: { KeyringController: { vault: 'old-keyring-vault', public: ['account'] } } });
  const messenger = new Messenger({ namespace: 'Background' });
  const child = messenger.buildChild({ namespace: 'KeyringController' });
  const controller = { name: 'KeyringController', metadata: { vault: { persist: true }, public: { persist: true }, phrase: { persist: false } },
    state: { vault: 'new-keyring-vault', public: ['account'], phrase: 'public phrase sentinel' } };
  const store = await createPersistedStore({ storage, messenger });
  assert.deepEqual(store.getInitialState(controller.name, controller.metadata), { public: ['account'] });
  store.registerControllers({ KeyringController: controller });
  await store.flush();
  child.publish('KeyringController:stateChange', { ...controller.state, vault: 'updated-vault', public: ['changed'] }, [{ path: ['public'] }]);
  await store.flush();
  assert.deepEqual(store.backup(), { KeyringController: { public: ['changed'] } });
  assert.ok(storage.writes.length >= 2);
  for (const write of storage.writes) {
    const serialized = JSON.stringify(write);
    assert.equal(serialized.includes('vault'), false);
    assert.equal(serialized.includes('phrase'), false);
  }
  store.destroy();
});

// Proves metadata persist transforms and nonpersistent patch filtering survive the port; an empty store could satisfy vault-only negative assertions.
test('persistent controller data is written and storage failures reach flush', async () => {
  const storage = storageFixture(), messenger = new Messenger({ namespace: 'Background' });
  const child = messenger.buildChild({ namespace: 'Fixture' });
  const controller = { name: 'Fixture', state: { saved: 3, session: 4 }, metadata: { saved: { persist: value => value * 2 }, session: { persist: false } } };
  const store = await createPersistedStore({ storage, messenger });
  store.registerControllers({ Fixture: controller }); await store.flush();
  assert.deepEqual(storage.values[STATE_KEY], { Fixture: { saved: 6 } });
  const count = storage.writes.length;
  child.publish('Fixture:stateChange', { saved: 3, session: 8 }, [{ path: ['session'] }]);
  await store.flush(); assert.equal(storage.writes.length, count);
  storage.set = async () => { throw new Error('storage fixture failure'); };
  child.publish('Fixture:stateChange', { saved: 5, session: 8 }, [{ path: ['saved'] }]);
  await assert.rejects(store.flush(), /storage fixture failure/);
  store.destroy();
});
