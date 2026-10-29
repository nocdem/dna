import test from 'node:test';
import assert from 'node:assert/strict';
import { mountNameBlock } from '../src/ui/name-block.js';

// Public trusted-client replies and minimal DOM fixtures; no flags, network or
// artifacts. Pins greeting/name-read wiring and stale-response clearing. This
// cannot prove browser visibility/navigation or live-chain replies; the mounted
// popup/full-page cases in ui-layout.test.js cover visibility and registration.
function fixture(own, registrable = true) {
  const ids = ['wallet-heading', 'wallet-title', 'wallet-register-name', 'own-name',
    'name-fields', 'quick-name', 'name-prices', 'name-review', 'name-quote', 'name-input', 'name-check', 'name-block'];
  const nodes = Object.fromEntries(ids.map(id => [id, Object.assign(new EventTarget(), { hidden: true, textContent: '', value: '' })]));
  const calls = [], ui = { state: { addresses: { nodus: 'public-wallet' }, nodus: { state: 'ready', nameable: true, registrable } },
    async request(method) {
      calls.push(method);
      if (method === 'getOwnName') return own();
      if (method === 'getNamePrices') return { text: 'public fixture prices' };
      assert.fail(`Unexpected name fixture method: ${method}`);
    } };
  const names = mountNameBlock({ root: { querySelector: selector => nodes[selector.slice(1)] }, ui,
    selected: () => 'nodus', run: action => action(), showReview: () => assert.fail('No registration was prepared.') });
  return { nodes, names, ui, calls };
}

test('wallet greeting uses the name returned by getOwnName', async () => {
  const { nodes, names, calls } = fixture(() => ({ found: true, name: 'publicname' }), false);
  await names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, publicname');
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-register-name'].hidden, true);
  assert.deepEqual(calls, ['getOwnName']);
});

test('confirmed unnamed wallet offers registration when it is available', async () => {
  const { nodes, names, calls } = fixture(() => ({ found: false }));
  await names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-register-name'].hidden, false);
  assert.equal(nodes['name-fields'].hidden, false);
  assert.deepEqual(calls, ['getOwnName', 'getNamePrices']);
});

test('name refresh clears the previous greeting before the reply and after failure', async () => {
  let next = () => ({ found: true, name: 'publicname' }), reply;
  const { nodes, names } = fixture(() => next());
  await names.refresh();
  next = () => new Promise(resolve => { reply = resolve; });
  const pending = names.refresh();
  assert.equal(nodes['wallet-heading'].hidden, true);
  assert.equal(nodes['wallet-title'].textContent, '');
  assert.equal(nodes['wallet-register-name'].hidden, true);
  reply({ found: false }); await pending;
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  next = () => { throw new Error('Public fixture read failed'); };
  await names.refresh();
  assert.equal(nodes['wallet-heading'].hidden, true);
  assert.equal(nodes['wallet-title'].textContent, '');
  assert.equal(nodes['wallet-register-name'].hidden, true);
});

test('unavailable name support clears the greeting and fences a pending reply', async () => {
  let next = () => ({ found: true, name: 'publicname' }), reply;
  const { nodes, names, ui } = fixture(() => next());
  await names.refresh();
  ui.state.nodus.nameable = false; names.update();
  assert.equal(nodes['wallet-heading'].hidden, true);
  assert.equal(nodes['wallet-title'].textContent, '');
  next = () => new Promise(resolve => { reply = resolve; });
  ui.state.nodus.nameable = true; names.update();
  ui.state.nodus.nameable = false; names.update();
  reply({ found: true, name: 'stalename' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nodes['wallet-heading'].hidden, true);
  assert.equal(nodes['wallet-title'].textContent, '');
});

test('disposing a name block prevents a late name from restoring its greeting', async () => {
  let reply;
  const { nodes, names } = fixture(() => new Promise(resolve => { reply = resolve; }));
  const pending = names.refresh(); names.dispose();
  reply({ found: true, name: 'stalename' }); await pending;
  assert.equal(nodes['wallet-heading'].hidden, true);
  assert.equal(nodes['wallet-title'].textContent, '');
});
