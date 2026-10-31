import { readFileSync } from 'node:fs';
import { createNodus } from '../../src/background/nodus.js';
import { createLockCoordinator } from '../../src/background/lock.js';
import { encryptVault, parseVault, VAULT_KEY } from '../../../src/vault.js';
import { nodusSigningSeed } from '../../../src/nodus/derive.js';
import { deriveWallet, disposeWallet } from '../../../src/keys.js';

export const phrase = 'abandon '.repeat(23) + 'art', password = 'public-test-password-123';
export const { address } = JSON.parse(readFileSync(new URL('../../../test/fixtures/nodus-addresses.json', import.meta.url))).vectors[0];
export const input = 'cd'.repeat(64), intent = 'ef'.repeat(64);
export async function walletSession(t, { module: additions = {}, beforeOpen } = {}) {
  const values = { [VAULT_KEY]: await encryptVault(phrase, password) }, id = parseVault(values[VAULT_KEY]).id;
  const wallet = deriveWallet(phrase), addresses = { ...wallet.addresses, nodus: address };
  const storage = { async get(keys) { return keys === null ? structuredClone(values) : Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map(key => [key, values[key]])); },
    async set(items) { Object.assign(values, structuredClone(items)); }, async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; } };
  const calls = [], module = {
    memory: { buffer: new ArrayBuffer(256) }, async unlock() { return { fingerprint: address, chainId: '12'.repeat(32) }; },
    async identify() { return { fingerprint: address, chainId: '12'.repeat(32) }; },
    async connectNetwork() {},
    async balance() { return { total: '500000000', spendable: '500000000' }; },
    async list() { return { tip: '10', coins: [{ nullifier: input, amount: '500000000' }], truncated: false }; },
    async rulesetInfo() { return { generation: '1', tip: '10', gen2Height: '0' }; },
    async buildAndSign() { throw new Error('Unexpected fixture build.'); }, async submit() { calls.push('submit'); assertSaved(); return { accepted: true }; },
    async scanConfirm() { return { found: false, tip: '10' }; }, async tick() {}, cancel() {}, lock() {}, release() {}, ...additions,
  };
  function assertSaved() { if (!Object.keys(values).some(key => key.includes('activity'))) throw new Error('Activity must be durable before submit.'); }
  const lockCoordinator = createLockCoordinator();
  const nodus = createNodus({ storage, lockCoordinator, getAddresses: () => addresses, factory: async () => module, getWords: () => phrase });
  await beforeOpen?.({ values, id, addresses });
  await lockCoordinator.unlock(() => nodus.consumeNodusSeed(nodusSigningSeed(phrase), { phrase, id, addresses,
    nodusWasmBytes: readFileSync(new URL('../../../src/nodus/mldsa87.wasm', import.meta.url)) }));
  nodus.startNetwork();
  const readyDeadline=performance.now()+2000;
  while(nodus.getState().state!=='ready') {
    if(performance.now()>readyDeadline)throw new Error('fixture connection never became ready');
    await new Promise(resolve=>setImmediate(resolve));
  }
  t.after(async () => { await lockCoordinator.lock(); disposeWallet(wallet); });
  return { nodus, lockCoordinator, values, id, addresses, storage, calls };
}
