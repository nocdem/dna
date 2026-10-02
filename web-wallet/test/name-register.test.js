// HF-4 chain-name REGISTRATION on the wallet side (decision
// docs/plans/decisions/2026-10-02-onchain-names.md items 2-6, 10, 11, 16;
// design docs/plans/2026-10-02-onchain-names-design.md rev 4 §2) against
// the TEST-ONLY mock module (test/nodus-mock-module.js).
//
// What each test proves:
//   - the client offers registration only when the module carries BOTH
//     namePrices and nameBuild (and the name lookups); a module without
//     them still unlocks and still resolves names;
//   - the node's price list is checked (parseNamePrices) and the tier is
//     picked by length (namePriceFor: 3, 4, 5, 6+);
//   - the quote before anything is built: this ID already holds a name /
//     the name is taken / available with the NODE's price for its length;
//     text that is not a chain name is refused; typed uppercase is
//     lower-cased ASCII-only;
//   - prepareName: nothing is built under rule-set generation 1, with all
//     coins held by pending transactions, or for a taken name; the review
//     values come from the module's read-back and every field is checked
//     (name, owner, price, expiry, chain, inputs, inputs = price + fee +
//     change); a price that changed between the quote and the build is
//     refused; the review carries the name, the price, the network fee, the
//     total and the rules; a scheduled price change before expiry is
//     warned about; confirm() records the pending registration BEFORE it
//     submits, and only once;
//   - the price is never chosen by the wallet: nameBuild is called with no
//     price field.
// What it does NOT prove: the real module (no node — the module's C side
// is pinned by test/nodus-send-wasm.test.js parity and the nodus ctest
// test_v2_name_build), nor the page wiring in src/app.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient } from '../src/nodus/client.js';
import { parseNamePrices, namePriceFor, namePriceList, nameQuote, prepareName, ownChainName, NAME_PRICE_PARAMS } from '../src/adapters/nodus.js';
import { recordActivity } from '../src/activity.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, INTENT_ID, coin } from './nodus-mock-module.js';

async function readyClient(prepare = () => {}) {
  const mock = createMockNodusModule();
  // generation 2: chain names are open
  mock.state.ruleset = { tip: '1000', generation: '2', gen2Height: '500' };
  prepare(mock);
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}
const reviewMap = prepared => new Map(prepared.review);

test('registration is offered only by a module with namePrices + nameBuild; without them names still resolve', async () => {
  const { client } = await readyClient();
  assert.equal(client.registrable, true);
  const { client: bare } = await readyClient(mock => { delete mock.module.namePrices; delete mock.module.nameBuild; });
  assert.equal(bare.registrable, false);
  assert.equal(bare.nameable, true);
  await assert.rejects(bare.namePrices(), /Registering a chain name is not available/);
  await assert.rejects(nameQuote({ client: bare, from: FINGERPRINT, name: 'punk' }), /not available right now/);
  const { client: noNames } = await readyClient(mock => { delete mock.module.nameLookup; });
  assert.equal(noNames.registrable, false, 'registering needs the name lookups too');
});

test('the node price list is checked and the tier is picked by length', () => {
  const ok = parseNamePrices({ prices: ['100000000000', '50000000000', '10000000000', '100000000'], scheduled: [{ param: 11, value: '60000000000', effective: '1050' }] });
  assert.deepEqual(ok.prices, [100000000000n, 50000000000n, 10000000000n, 100000000n]);
  assert.deepEqual(ok.scheduled, [{ param: 11, value: 60000000000n, effective: 1050n }]);
  assert.deepEqual(NAME_PRICE_PARAMS, [10, 11, 12, 13]);
  for (const bad of [null, {}, { prices: ['1', '1', '1'], scheduled: [] }, { prices: ['1', '1', '1', '0'], scheduled: [] }, { prices: ['1', '1', '1', '01'], scheduled: [] },
    { prices: ['1', '1', '1', '1'], scheduled: [{ param: 9, value: '1', effective: '1' }] }, { prices: ['1', '1', '1', '1'], scheduled: [{ param: 10, value: '0', effective: '1' }] },
    { prices: ['1', '1', '1', '1'], scheduled: Array(17).fill({ param: 10, value: '1', effective: '1' }) }, { prices: ['1', '1', '1', '1'] }]) {
    assert.throws(() => parseNamePrices(bad), /invalid/, JSON.stringify(bad)?.slice(0, 80));
  }
  const tiers = [3n, 4n, 5n, 6n];
  assert.equal(namePriceFor(tiers, 'abc'), 3n);
  assert.equal(namePriceFor(tiers, 'abcd'), 4n);
  assert.equal(namePriceFor(tiers, 'abcde'), 5n);
  assert.equal(namePriceFor(tiers, 'abcdef'), 6n);
  assert.equal(namePriceFor(tiers, 'a'.repeat(36)), 6n);
  assert.throws(() => namePriceFor(tiers, 'ab'), /Not a chain name/);
  assert.throws(() => namePriceFor(tiers, 'Abc'), /Not a chain name/);
  // ethers formatUnits keeps one decimal on whole amounts ("1.0")
  assert.equal(namePriceList([100000000000n, 50000000000n, 10000000000n, 100000000n]), '3 characters: 1000.0 NODUS · 4 characters: 500.0 NODUS · 5 characters: 100.0 NODUS · 6 or more characters: 1.0 NODUS');
});

test('quote: available with the node price, taken, this ID already named, not a name', async () => {
  const { mock, client } = await readyClient();
  const quote = await nameQuote({ client, from: FINGERPRINT, name: '  PuNk ' });
  assert.equal(quote.status, 'available');
  assert.equal(quote.name, 'punk', 'ASCII-only lower-casing');
  assert.equal(quote.price, 50000000000n, 'the 4-character price the node reported');
  assert.equal(quote.priceText, '500.0 NODUS');
  mock.state.names.punk = RECIPIENT;
  assert.deepEqual(await nameQuote({ client, from: FINGERPRINT, name: 'punk' }), { status: 'taken', name: 'punk' });
  mock.state.names.bios = FINGERPRINT;
  assert.deepEqual(await nameQuote({ client, from: FINGERPRINT, name: 'other' }), { status: 'has-name', ownName: 'bios' });
  assert.deepEqual(await ownChainName({ client, from: FINGERPRINT }), { found: true, name: 'bios' });
  for (const bad of ['ab', 'a-b', 'deadbeef', 'p ınk', 'a'.repeat(37)]) await assert.rejects(nameQuote({ client, from: FINGERPRINT, name: bad }), /A chain name is 3 to 36/, bad);
  await assert.rejects(nameQuote({ client, from: RECIPIENT, name: 'punk' }), /does not match/);
});

test('prepareName: generation 1, held coins, a taken name and an owned name build nothing', async () => {
  const { mock, client } = await readyClient(m => { m.state.ruleset = { tip: '1000', generation: '1', gen2Height: '1200' }; });
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), /Chain names open at block 1200/);
  assert.equal(mock.state.lastNameBuild, null);
  mock.state.ruleset = { tip: '1000', generation: '1', gen2Height: '0' };
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), /not open/);
  mock.state.ruleset = { tip: '1000', generation: '2', gen2Height: '500' };
  const locked = new Set(mock.state.coins.map(c => c.nullifier));
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker', locked }), /held by a pending transaction/);
  mock.state.names.punker = RECIPIENT;
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), /already registered/);
  mock.state.names = { mine: FINGERPRINT };
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), /already has the chain name "mine"/);
  assert.equal(mock.state.lastNameBuild, null, 'nothing reached the builder');
});

test('prepareName: the review comes from the read-back, the price from the node, and confirm records before it submits', async () => {
  const { mock, client } = await readyClient();
  const prepared = await prepareName({ client, from: FINGERPRINT, name: 'Punker' });
  const req = mock.state.lastNameBuild;
  assert.equal(req.name, 'punker');
  assert.equal(req.expiryHeight, '1090', 'tip + 90');
  assert.ok(!('price' in req), 'the wallet never hands the module a price');
  assert.equal(prepared.kind, 'name');
  assert.equal(prepared.name, 'punker');
  assert.equal(prepared.to, FINGERPRINT, 'the owner is this wallet');
  assert.equal(prepared.amount, '1.0', 'the 6+ price: 1 NODUS');
  const rows = reviewMap(prepared);
  assert.equal(rows.get('Action'), 'Register a chain name');
  assert.equal(rows.get('Name'), 'punker');
  assert.equal(rows.get('Owner (your Nodus ID)'), FINGERPRINT);
  assert.equal(rows.get('Price'), '1.0 NODUS');
  assert.equal(rows.get('Network fee'), '0.00001 NODUS');
  assert.equal(rows.get('Total'), '1.00001 NODUS');
  assert.match(rows.get('Rules'), /First come, first served.*price is not charged.*one name.*does not expire/);
  assert.equal(rows.get('Valid until block'), '1090');
  assert.ok(!rows.has('Price change'));
  // confirm: the record first, then the submission, once
  const order = [];
  const origSubmit = mock.module.submit;
  mock.module.submit = args => { order.push('submit'); return origSubmit(args); };
  let details;
  const hash = await prepared.confirm(async d => { order.push('record'); details = d; });
  assert.deepEqual(order, ['record', 'submit']);
  assert.equal(hash, INTENT_ID);
  assert.deepEqual(details.inputs, [coin(2, '300000000').nullifier]);
  const record = recordActivity(prepared, details);
  assert.equal(record.kind, 'name');
  assert.equal(record.name, 'punker');
  await assert.rejects(prepared.confirm(async () => {}), /already closed/);
});

test('prepareName: every read-back field is checked; a price change between quote and build is refused', async () => {
  const tampers = [
    [{ name: 'punkers' }, /does not match/], [{ owner: RECIPIENT }, /does not match/], [{ expiryHeight: '1089' }, /does not match/],
    [{ chainId: 'f'.repeat(64) }, /does not match/], [{ inputs: ['7'.repeat(128)] }, /may not use/], [{ change: '1' }, /does not add up/],
    [{ price: '99' }, /price of this name changed/], [{ name: 'Punker' }, /invalid transaction/], [{ inputs: [] }, /invalid transaction/]
  ];
  for (const [tamper, error] of tampers) {
    const { client } = await readyClient(m => { m.state.nameTamper = tamper; });
    await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), error, JSON.stringify(tamper));
  }
  const { client } = await readyClient(m => { m.state.buildPrices = { prices: ['100000000000', '50000000000', '10000000000', '200000000'] }; });
  await assert.rejects(prepareName({ client, from: FINGERPRINT, name: 'punker' }), /changed while it was being prepared \(now 2\.0 NODUS\)/);
});

test('prepareName: a scheduled price change before expiry is shown; one after it is not', async () => {
  const { client } = await readyClient(m => { m.state.namePrices.scheduled = [{ param: 13, value: '200000000', effective: '1050' }, { param: 12, value: '20000000000', effective: '1040' }]; });
  assert.match(reviewMap(await prepareName({ client, from: FINGERPRINT, name: 'punker' })).get('Price change'), /scheduled at block 1040/);
  const { client: later } = await readyClient(m => { m.state.namePrices.scheduled = [{ param: 13, value: '200000000', effective: '5000' }]; });
  assert.ok(!reviewMap(await prepareName({ client: later, from: FINGERPRINT, name: 'punker' })).has('Price change'));
});
