// Tests of extension.js (the extension's EXISTING site methods) against a stub window and a stub provider.
//
// PROVES: the provider is found through EIP-6963 (rdns io.nodusnetwork.wallet, name "Nodus Wallet") and another
//   announcement is ignored; connect() asks nodus_requestAccounts then eth_requestAccounts and lower-cases the Ethereum
//   address; a chain name the extension adds (3 to 36 of a-z and 0-9) is kept and anything else is dropped; the withdraw's signing call is provider.request({ method: 'nodus_signMessage', params: [ '0x' + hex of the
//   text bytes, the account's Nodus address ] }) and its answer is returned unchanged; with no extension the calls reject
//   with code no_extension.
// ENVIRONMENT: node >= 20, `node --test website/swap-site/test/*.test.js`; no browser, no network.
// LEAVES BEHIND: nothing (the 1 ms wait of the no-extension case).
// FALSE PASS: the stub window imitates the events by hand; a real extension's announcement timing or the method's real
//   checks (permitted account, approval screen) are not exercised.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createExtension } from '../extension.js';

const NODUS_ADDR = 'ab'.repeat(64);

function stubWindow(announcements) {
  const listeners = [];
  return {
    Event: class { constructor(type) { this.type = type; } },
    addEventListener(type, fn) { if (type === 'eip6963:announceProvider') listeners.push(fn); },
    dispatchEvent(event) {
      if (event.type === 'eip6963:requestProvider') for (const detail of announcements) for (const fn of listeners) fn({ detail });
      return true;
    },
  };
}
function stubProvider(answers) {
  const calls = [];
  return { calls, request: async ({ method, params }) => { calls.push({ method, params }); return answers[method]; } };
}
const info = { rdns: 'io.nodusnetwork.wallet', name: 'Nodus Wallet' };

test('the withdraw signing call: nodus_signMessage with the hex of the text and the account address', async () => {
  const provider = stubProvider({ nodus_signMessage: `0x${'ee'.repeat(4627)}` });
  const other = stubProvider({});
  const ext = createExtension({ window: stubWindow([{ info: { rdns: 'other.wallet', name: 'Other' }, provider: other }, { info, provider }]), waitMs: 1 });
  const signature = await ext.signNodusText('Hi\nA', NODUS_ADDR);
  assert.equal(signature, `0x${'ee'.repeat(4627)}`);
  assert.deepEqual(provider.calls, [{ method: 'nodus_signMessage', params: ['0x48690a41', NODUS_ADDR] }]);   // H=48 i=69 LF=0a A=41
  assert.deepEqual(other.calls, []);
});

test('connect: nodus_requestAccounts then eth_requestAccounts; the Ethereum address is lower-cased', async () => {
  const provider = stubProvider({
    nodus_requestAccounts: [{ address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}` }],
    eth_requestAccounts: [`0x${'AB'.repeat(20)}`],
  });
  const ext = createExtension({ window: stubWindow([{ info, provider }]), waitMs: 1 });
  const a = await ext.connect();
  assert.deepEqual(provider.calls.map(c => c.method), ['nodus_requestAccounts', 'eth_requestAccounts']);
  assert.deepEqual(a, { nodus: { address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}` }, ethereum: `0x${'ab'.repeat(20)}` });
  const named = stubProvider({ nodus_requestAccounts: [{ address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}`, name: 'alice7' }], eth_requestAccounts: [`0x${'ab'.repeat(20)}`] });
  assert.equal((await createExtension({ window: stubWindow([{ info, provider: named }]), waitMs: 1 }).connect()).nodus.name, 'alice7', 'a chain name from the extension is kept');
  for (const bad of ['Al', 'a b c', 'x'.repeat(37), 42, '<b>x</b>']) {
    const odd = stubProvider({ nodus_requestAccounts: [{ address: NODUS_ADDR, publicKey: `0x${'cd'.repeat(2592)}`, name: bad }], eth_requestAccounts: [`0x${'ab'.repeat(20)}`] });
    assert.equal('name' in (await createExtension({ window: stubWindow([{ info, provider: odd }]), waitMs: 1 }).connect()).nodus, false, `not a chain name is dropped: ${bad}`);
  }
  const empty = stubProvider({ nodus_requestAccounts: [], eth_requestAccounts: [] });
  await assert.rejects(createExtension({ window: stubWindow([{ info, provider: empty }]), waitMs: 1 }).connect(), /no account/);
});

test('no extension: connect and signNodusText reject with no_extension', async () => {
  const ext = createExtension({ window: stubWindow([]), waitMs: 1 });
  await assert.rejects(ext.connect(), e => e.code === 'no_extension');
  await assert.rejects(ext.signNodusText('x', NODUS_ADDR), e => e.code === 'no_extension');
});
