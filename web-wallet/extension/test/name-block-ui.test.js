import test from 'node:test';
import assert from 'node:assert/strict';
import { mountNameBlock } from '../src/ui/name-block.js';

// Public trusted-client replies and minimal DOM fixtures; no flags, network or
// artifacts. Pins greeting/name-read wiring and stale-response clearing. This
// cannot prove browser visibility/navigation or live-chain replies; the mounted
// popup/full-page cases in ui-layout.test.js cover visibility and registration.
function fixture(own, registrable = true) {
  const ids = ['wallet-heading', 'wallet-title', 'wallet-register-name', 'own-name',
    'name-fields', 'name-prices', 'name-review', 'name-quote', 'name-input', 'name-check', 'name-block'];
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

test('wallet greeting is visible while the first name read is pending', async () => {
  let reply;
  const { nodes, names, calls } = fixture(() => new Promise(resolve => { reply = resolve; }));
  const pending = names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-register-name'].hidden, true);
  assert.deepEqual(calls, ['getOwnName']);
  reply({ found: true, name: 'publicname' }); await pending;
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, publicname');
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-register-name'].hidden, true);
});

// Proves the kept (unconfirmed) name from the background's public state is on the screen before getOwnName answers,
// that a found answer replaces it, and that a not-found answer takes it away and offers registration. Could falsely pass if
// the text came from the answer: the reply is held, and the greeting is read before it is released.
test('the kept name is shown before the lookup answers; the answer replaces or removes it', async () => {
  let reply;
  const { nodes, names, ui } = fixture(() => new Promise(resolve => { reply = resolve; }));
  ui.state.nodus.keptOwnName = 'keptname';
  const pending = names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, keptname');
  assert.match(nodes['own-name'].textContent, /"keptname" \(last known; confirming/);
  reply({ found: true, name: 'newname' }); await pending;
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, newname');
  const second = names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, keptname');
  reply({ found: false }); await second;
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back'); assert.equal(nodes['wallet-register-name'].hidden, false);
});

// Proves the kept name is on the greeting while the Nodus connection is still opening or unavailable (not nameable), with
// no lookup asked, and that a later nameable state starts the lookup that confirms it. Could falsely pass if update() were
// never reached with that state; the first assertion reads the greeting after update() and the request list stays empty.
test('the kept name is shown at once while the connection is not ready', async () => {
  const { nodes, names, ui, calls } = fixture(() => ({ found: true, name: 'keptname' }));
  ui.state.nodus = { state: 'connecting', connection: 1, nameable: false, registrable: false, keptOwnName: 'keptname' };
  names.update();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back, keptname');
  assert.match(nodes['own-name'].textContent, /"keptname" \(last known/);
  assert.deepEqual(calls, []);
  ui.state.nodus = { ...ui.state.nodus, state: 'ready', nameable: true };
  names.update(); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['getOwnName']);
});

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

test('name refresh resets to the generic greeting before the reply and after failure', async () => {
  let next = () => ({ found: true, name: 'publicname' }), reply;
  const { nodes, names } = fixture(() => next());
  await names.refresh();
  next = () => new Promise(resolve => { reply = resolve; });
  const pending = names.refresh();
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, true);
  reply({ found: false }); await pending;
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, false);
  next = () => { throw new Error('Public fixture read failed'); };
  await names.refresh();
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, true);
});

test('confirmed unnamed wallet keeps the generic greeting when registration is unavailable', async () => {
  const { nodes, names, calls } = fixture(() => ({ found: false }), false);
  await names.refresh();
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-register-name'].hidden, true);
  assert.deepEqual(calls, ['getOwnName']);
});

test('unavailable name support keeps the generic greeting and fences a pending reply', async () => {
  let next = () => ({ found: true, name: 'publicname' }), reply;
  const { nodes, names, ui } = fixture(() => next());
  await names.refresh();
  ui.state.nodus.nameable = false; names.update();
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, true);
  next = () => new Promise(resolve => { reply = resolve; });
  ui.state.nodus.nameable = true; names.update();
  ui.state.nodus.nameable = false; names.update();
  reply({ found: true, name: 'stalename' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, true);
});

test('disposing a name block prevents a late name from replacing the generic greeting', async () => {
  let reply;
  const { nodes, names } = fixture(() => new Promise(resolve => { reply = resolve; }));
  const pending = names.refresh(); names.dispose();
  reply({ found: true, name: 'stalename' }); await pending;
  assert.equal(nodes['wallet-heading'].hidden, false);
  assert.equal(nodes['wallet-title'].textContent, 'Welcome back');
  assert.equal(nodes['wallet-register-name'].hidden, true);
});
