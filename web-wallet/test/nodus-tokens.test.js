// Connect shows and sends the pinned test token (tUSDT) — the wallet side of
// design docs/plans/2026-10-22-connect-native-tokens-design.md §6 (rev 3) and
// the "Get testnet coins" button (docs/plans/2026-10-22-testnet-faucet-design.md
// §6 item 11). Operator answers (decision 2026-10-22-testnet-test-tokens-
// faucet-dex.md): "Yalnız tUSDT", "6" decimals, "tUSDT'yi kapat" (metadata
// not equal to the pin = unavailable), "Cüzdanın içinde" (the faucet button),
// "İlk sürümde yok" (no vault names).
//
// What it proves (against the TEST-ONLY mock module, test/nodus-mock-module.js
// — the wallet-side rules, nothing about the real module, the node or the
// chain; the C module's own refusals and the byte parity are in
// test/nodus-send-wasm.test.js):
//   1. the asset identity { chain, tokenId } is REQUIRED at every hop: a send
//      with no / malformed / foreign identity is refused in prepareTransfer
//      BEFORE any module call; NODUS and tUSDT go through the same application
//      path (prepareTransfer -> adapter -> module -> decoded -> review);
//      prepare() refuses when the decoded token differs from the requested one;
//   2. a token that is not pinned, or whose metadata the module reports as
//      not equal to the pin (available false), cannot be sent;
//   3. shortfalls say which side is short; an unlisted token coin list is
//      "unavailable", never a mixed list; a missing balance row is not a zero;
//   4. the review rows: amount (tUSDT, 6 decimals), fee (NODUS, decoded), tUSDT
//      change, NODUS change — and a NODUS send keeps its old rows;
//   5. balances: one row per pinned token, an unavailable one says so, a bad
//      one is an error row that never touches the NODUS row;
//   6. the network lists the module's pins (nodusTokens) and the portfolio's
//      balance mapping carries `unavailable`;
//   7. Activity: tokenId survives save / reload, a legacy row (no tokenId) is
//      a native row, an unknown tokenId keeps the row and its locked inputs
//      and shows "unknown token", one token row never costs the file;
//   8. history rows show pinned tokens with symbol + decimals, fees stay NODUS;
//   9. the faucet: the button gate (testnet chain only), the request shape,
//      polling to a final state, a bounded poll ending "pending", never
//      "failed", checked answers only.
// How it can lie: the mock models the module's rules (it does not run them);
// the DOM wiring in src/app.js (asset <option> values, the faucet button, the
// nodusSent gate) has no unit seam here — absent coverage, not a pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient } from '../src/nodus/client.js';
import { nodusNetworkFor, nodusTokens, NODUS_ASSET, NODUS_TOKEN_ID, NODUS_NETWORK } from '../src/nodus/network.js';
import { prepareTransfer } from '../src/wallet.js';
import { balances, lockedInputs, faucetAvailable, claimTestnetCoins, parseFaucetClaim, NODUS_TESTNET_CHAIN_ID, FAUCET_MAX_POLLS, FAUCET_PENDING_TEXT } from '../src/adapters/nodus.js';
import { chainBalances } from '../src/portfolio.js';
import { recordActivity, activitySymbol } from '../src/activity.js';
import { serializeActivity, parseActivity, activityKeyFor } from '../src/activity-storage.js';
import { parseAddrHistory, nodusHistoryRow } from '../src/nodus/history.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, CHAIN_ID, INTENT_ID, FEE, coin, tokenCoin, NODUS_NATIVE, ZERO_TOKEN, TUSDT, TUSDT_ID } from './nodus-mock-module.js';

async function readyClient(setup = () => {}) {
  const mock = createMockNodusModule();
  setup(mock.state);
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 7, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}
const walletFor = client => ({ addresses: { nodus: FINGERPRINT }, nodusClient: client });
// tUSDT held: 5 tUSDT in two coins (6 decimals), NODUS for the fee.
const withTokens = (state, { pin = TUSDT } = {}) => {
  state.pins = [pin];
  state.tokenBalances = [{ tokenId: TUSDT_ID, total: '5000000', spendable: '5000000' }];
  state.tokenCoins = [tokenCoin(7, '3000000'), tokenCoin(8, '2000000')];
  state.tokenListing = [{ tokenId: TUSDT_ID, listed: true, truncated: false }];
};
const asset = tokenId => ({ chain: 'nodus', tokenId });
const send = (client, over = {}) => prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'tUSDT', asset: asset(TUSDT_ID), to: RECIPIENT, amount: '2.5', ...over });
const rows = transfer => Object.fromEntries(transfer.review);

// ── 1. the asset identity at every hop ───────────────────────────────────
test('tUSDT through the application path: asset identity -> module token build -> decoded -> review (amount in tUSDT, fee in NODUS, both changes)', async () => {
  const { mock, client } = await readyClient(state => withTokens(state));
  const transfer = await send(client);
  assert.equal(transfer.chain, 'nodus'); assert.equal(transfer.symbol, 'tUSDT'); assert.equal(transfer.tokenId, TUSDT_ID);
  assert.equal(transfer.amount, '2.5'); assert.equal(transfer.to, RECIPIENT);
  const r = rows(transfer);
  assert.equal(r.Amount, '2.5 tUSDT');
  assert.equal(r['Network fee'], '0.00001 NODUS', 'the fee is NODUS, decoded from the bytes');
  assert.equal(r['tUSDT change back to you'], '0.5 tUSDT');
  assert.equal(r['NODUS change back to you'], '2.99999 NODUS', 'the largest NODUS coin (3 NODUS) minus the 1000-raw fee');
  assert.equal(FEE, '1000');
  assert.equal(r['Change back to you'], undefined, 'a token send names its two changes, not the old single row');
  // the request that reached the module: token id, 6-decimal raw units, native + token candidates
  assert.equal(mock.state.lastTokenBuild.tokenId, TUSDT_ID);
  assert.equal(mock.state.lastTokenBuild.amount, '2500000');
  assert.equal(mock.state.lastBuild, null, 'the NODUS build was not used');
  const nodusCoins = mock.state.coins.map(c => c.nullifier), tokenCoins = mock.state.tokenCoins.map(c => c.nullifier);
  assert.deepEqual(mock.state.lastTokenBuild.coins.map(c => c.nullifier).sort(), [...nodusCoins, ...tokenCoins].sort());
  transfer.cancel(); client.lock();
});

test('NODUS through the same path (asset = the all-zero token id): the native build, the old review rows, a NODUS record', async () => {
  const { mock, client } = await readyClient(state => withTokens(state));
  const transfer = await send(client, { symbol: 'NODUS', asset: NODUS_NATIVE, amount: '1.5' });
  assert.equal(transfer.symbol, 'NODUS'); assert.equal(transfer.tokenId, ZERO_TOKEN); assert.equal(transfer.amount, '1.5');
  const r = rows(transfer);
  assert.equal(r.Amount, '1.5 NODUS'); assert.ok('Change back to you' in r); assert.ok(!('tUSDT change back to you' in r));
  assert.equal(mock.state.lastTokenBuild, null); assert.equal(mock.state.lastBuild.amount, '150000000');
  assert.ok(mock.state.lastBuild.coins.every(c => mock.state.coins.some(n => n.nullifier === c.nullifier)), 'only NODUS coins are offered to the NODUS build');
  transfer.cancel(); client.lock();
});

test('no hop defaults to native: a missing, malformed or foreign asset identity is refused before any module call', async () => {
  const { mock, client } = await readyClient(state => withTokens(state));
  const before = mock.log.length;
  for (const bad of [undefined, null, {}, { chain: 'nodus' }, { chain: 'nodus', tokenId: '' }, { chain: 'nodus', tokenId: 'NODUS' }, { chain: 'nodus', tokenId: '0'.repeat(127) }, { chain: 'nodus', tokenId: TUSDT_ID.toUpperCase() }, { chain: 'ethereum', tokenId: ZERO_TOKEN }, { tokenId: ZERO_TOKEN }]) {
    await assert.rejects(send(client, { asset: bad }), /Choose the asset to send/, JSON.stringify(bad));
  }
  assert.equal(mock.log.length, before, 'no module call was made');
  assert.equal(mock.state.lastBuild, null); assert.equal(mock.state.lastTokenBuild, null);
  client.lock();
});

test('a token the module does not pin, or reports unavailable, cannot be sent', async () => {
  const other = 'cc'.repeat(64);
  let { mock, client } = await readyClient(state => withTokens(state));
  await assert.rejects(send(client, { asset: asset(other) }), /not supported by this wallet/);
  assert.equal(mock.state.lastTokenBuild, null); client.lock();
  ({ mock, client } = await readyClient(state => withTokens(state, { pin: { ...TUSDT, available: false } })));
  await assert.rejects(send(client), /tUSDT is unavailable right now/);
  assert.equal(mock.state.lastTokenBuild, null, 'nothing was built');
  assert.equal(mock.log.includes('list:start'), false, 'refused before any listing');
  client.lock();
  // a module without the token group sends NODUS as before and no token
  const mockOld = createMockNodusModule(); delete mockOld.module.tokenPins; delete mockOld.module.tokenBuildAndSign;
  const old = createNodusClient({ factory: mockOld.factory, setInterval: () => 7, clearInterval: () => {} });
  await old.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  assert.equal(old.tokenable, false); assert.deepEqual(old.tokenPins(), []);
  await assert.rejects(send(old), /not supported by this wallet/);
  const native = await send(old, { symbol: 'NODUS', asset: NODUS_NATIVE, amount: '1' });
  native.cancel(); old.lock();
});

test('prepare() refuses when the decoded token differs from the requested one (or a token change appears on a NODUS send)', async () => {
  const mismatched = [
    [{ tokenId: ZERO_TOKEN }, asset(TUSDT_ID), 'tUSDT'],
    [{ tokenId: 'dd'.repeat(64) }, asset(TUSDT_ID), 'tUSDT'],
    [{ tokenId: TUSDT_ID }, NODUS_NATIVE, 'NODUS'],
    [{ tokenChange: '7' }, NODUS_NATIVE, 'NODUS']
  ];
  for (const [tamper, id, symbol] of mismatched) {
    const { mock, client } = await readyClient(state => withTokens(state));
    mock.state.tamper = tamper;
    await assert.rejects(send(client, { asset: id, symbol, amount: '1' }), /does not match your request/, JSON.stringify(tamper));
    client.lock();
  }
  // a module that does not report the token at all is refused, never read as NODUS
  const { mock, client } = await readyClient(state => withTokens(state));
  mock.state.tamper = { tokenId: undefined };
  await assert.rejects(send(client, { asset: NODUS_NATIVE, symbol: 'NODUS', amount: '1' }), /invalid transaction/);
  client.lock();
});

// ── 3. shortfalls, unlisted coin list, balance rows ──────────────────────
test('shortfalls name the short side; an unlisted coin list is unavailable; no balance row is not a zero', async () => {
  let { client } = await readyClient(state => withTokens(state));
  await assert.rejects(send(client, { amount: '5.000001' }), /Not enough tUSDT\./);
  client.lock();
  ({ client } = await readyClient(state => { withTokens(state); state.coins = []; state.total = state.spendable = '0'; }));
  await assert.rejects(send(client), /Not enough NODUS for the network fee\./);
  client.lock();
  // a node that ignores the token filter: listed false — never another token's coins
  ({ client } = await readyClient(state => { withTokens(state); state.tokenListing = [{ tokenId: TUSDT_ID, listed: false, truncated: false }]; }));
  await assert.rejects(send(client), /tUSDT coin list is unavailable right now/);
  client.lock();
  // balance says 5 tUSDT but the listing holds no token coin: a read failure, not "insufficient"
  ({ client } = await readyClient(state => { withTokens(state); state.tokenCoins = []; }));
  await assert.rejects(send(client), /tUSDT coin list could not be read/);
  client.lock();
  // no balance row for the pin
  ({ client } = await readyClient(state => { withTokens(state); state.tokenBalances = []; }));
  await assert.rejects(send(client), /tUSDT balance could not be read/);
  client.lock();
  // coins held by a pending send are not offered
  const { mock, client: c2 } = await readyClient(state => withTokens(state));
  const locked = new Set([mock.state.tokenCoins[0].nullifier]);
  await assert.rejects(send(c2, { amount: '4', nodusLocked: locked }), /held by a pending send/);
  const ok = await send(c2, { amount: '1.5', nodusLocked: locked });
  assert.ok(!mock.state.lastTokenBuild.coins.some(c => locked.has(c.nullifier)), 'a locked token coin is not a candidate');
  ok.cancel(); c2.lock();
});

test('a truncated token coin list is said on the review', async () => {
  const { client } = await readyClient(state => { withTokens(state); state.tokenListing = [{ tokenId: TUSDT_ID, listed: true, truncated: true }]; });
  const transfer = await send(client);
  assert.ok(transfer.review.some(([k]) => k === 'Coin list'));
  transfer.cancel(); client.lock();
});

// ── 5. balances ──────────────────────────────────────────────────────────
test('balances: NODUS first, then one row per pinned token in the token\'s decimals; unavailable and invalid rows stay apart from NODUS', async () => {
  let { client } = await readyClient(state => withTokens(state));
  assert.deepEqual(await balances('nodus', FINGERPRINT, undefined, { client }), [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', balance: '5.0' }]);
  client.lock();
  ({ client } = await readyClient(state => withTokens(state, { pin: { ...TUSDT, available: false } })));
  assert.deepEqual(await balances('nodus', FINGERPRINT, undefined, { client }), [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', error: true, unavailable: true }]);
  client.lock();
  for (const bad of [[], [{ tokenId: TUSDT_ID, total: '1', spendable: '2' }], [{ tokenId: TUSDT_ID, total: '-1', spendable: '0' }]]) {
    ({ client } = await readyClient(state => { withTokens(state); state.tokenBalances = bad; }));
    assert.deepEqual(await balances('nodus', FINGERPRINT, undefined, { client }), [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', error: true }], JSON.stringify(bad));
    client.lock();
  }
  // a module without pins: NODUS only, as before
  ({ client } = await readyClient());
  assert.deepEqual(await balances('nodus', FINGERPRINT, undefined, { client }), [{ symbol: 'NODUS', balance: '4.5' }]);
  client.lock();
});

test('portfolio: the tUSDT row reads from the balance rows by symbol; an unavailable token is flagged, never a zero', () => {
  const assets = [{ ...NODUS_ASSET }, { chain: 'nodus', symbol: 'tUSDT', decimals: 6, tokenId: TUSDT_ID, key: 'nodus:tUSDT' }];
  const ok = chainBalances('nodus', [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', balance: '5.0' }], 1000, assets);
  assert.equal(ok['nodus:tUSDT'].state, 'ready'); assert.equal(ok['nodus:tUSDT'].units, 5000000n);
  const off = chainBalances('nodus', [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', error: true, unavailable: true }], 1000, assets);
  assert.equal(off['nodus:NODUS'].state, 'ready'); assert.equal(off['nodus:tUSDT'].state, 'error'); assert.equal(off['nodus:tUSDT'].unavailable, true); assert.equal(off['nodus:tUSDT'].units, undefined);
  const bad = chainBalances('nodus', [{ symbol: 'NODUS', balance: '4.5' }, { symbol: 'tUSDT', error: true }], 1000, assets);
  assert.equal(bad['nodus:tUSDT'].state, 'error'); assert.equal(bad['nodus:tUSDT'].unavailable, undefined);
  const missing = chainBalances('nodus', [{ symbol: 'NODUS', balance: '4.5' }], 1000, assets);
  assert.equal(missing['nodus:tUSDT'].state, 'error', 'no row is not a zero');
  const tooMany = chainBalances('nodus', [{ symbol: 'tUSDT', balance: '1.0000001' }], 1000, assets);
  assert.equal(tooMany['nodus:tUSDT'].state, 'error', 'more decimals than the token has');
});

// ── 6. the network's token list ──────────────────────────────────────────
test('the NODUS network lists the module\'s pinned tokens (and only well-formed ones); without any it is exactly as before', () => {
  assert.equal(nodusNetworkFor(true, { tokens: [] }), nodusNetworkFor(true));
  const network = nodusNetworkFor(true, { module: true, tokens: [TUSDT] });
  assert.equal(network.receiveOnly, false); assert.deepEqual(network.tokens, [TUSDT]);
  assert.deepEqual(NODUS_NETWORK.tokens, [], 'the static network carries no token of its own');
  // not ready: tokens are never listed
  assert.equal(nodusNetworkFor(false, { module: true, tokens: [TUSDT] }).tokens.length, 0);
  const junk = [null, {}, { ...TUSDT, tokenId: ZERO_TOKEN }, { ...TUSDT, tokenId: 'xy' }, { ...TUSDT, symbol: 'NODUS' }, { ...TUSDT, symbol: 'has space' }, { ...TUSDT, name: '' }, { ...TUSDT, decimals: 19 }, { ...TUSDT, decimals: 1.5 }, TUSDT, TUSDT];
  assert.deepEqual(nodusTokens(junk), [TUSDT], 'one well-formed pin, listed once');
  assert.deepEqual(nodusTokens('x'), []);
  assert.deepEqual(nodusTokens([{ ...TUSDT, available: 'yes' }]), [{ ...TUSDT, available: false }], 'only a literal true is available');
  assert.equal(NODUS_ASSET.tokenId, NODUS_TOKEN_ID);
});

// ── 7. Activity ──────────────────────────────────────────────────────────
const phrase = 'abandon '.repeat(23) + 'art';
const walletId = Buffer.alloc(16, 5).toString('base64');
const hex128 = n => n.toString(16).padStart(128, '0');
function savedRow(n, extra = {}) {
  return { chain: 'nodus', address: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', amount: '1.5', hash: hex128(n + 1), createdAt: new Date(Date.UTC(2026, 9, 22) + n * 1000).toISOString(), status: 'pending', expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(100000 + n)], ...extra };
}
async function roundTrip(rowsIn) {
  const key = await activityKeyFor(phrase, walletId);
  return parseActivity(await serializeActivity(walletId, rowsIn, key), walletId, { nodus: FINGERPRINT }, key);
}
test('Activity: a token send keeps its tokenId across save and reload; a legacy row (no tokenId) stays a native row', async () => {
  const token = recordActivity({ chain: 'nodus', from: FINGERPRINT, to: RECIPIENT, symbol: 'tUSDT', tokenId: TUSDT_ID, amount: '2.5' }, { hash: INTENT_ID, expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(1)] });
  assert.equal(token.tokenId, TUSDT_ID); assert.equal(token.symbol, 'tUSDT');
  const native = recordActivity({ chain: 'nodus', from: FINGERPRINT, to: RECIPIENT, symbol: 'NODUS', tokenId: ZERO_TOKEN, amount: '1' }, { hash: hex128(9), expiryHeight: '1090', fromHeight: '1001', inputs: [hex128(2)] });
  assert.equal('tokenId' in native, false, 'a NODUS send writes no tokenId: the saved format of a native row is unchanged');
  const back = await roundTrip([token, native, savedRow(5)]);
  assert.equal(back.length, 3);
  assert.equal(back[0].tokenId, TUSDT_ID); assert.equal(back[0].symbol, 'tUSDT'); assert.equal(back[0].amount, '2.5');
  assert.equal(back[1].tokenId, undefined); assert.equal(back[2].tokenId, undefined, 'a legacy row has none: a native row');
  assert.equal(back[2].symbol, 'NODUS');
  // its coins stay held while it is unresolved, whatever its token
  assert.deepEqual([...lockedInputs(back)].sort(), [hex128(1), hex128(2), hex128(100005)].sort());
});

test('Activity: an unknown tokenId keeps the row and its locked inputs, shown "unknown token"; one token row never costs the file', async () => {
  const gone = savedRow(1, { symbol: 'tOLD', tokenId: 'ab'.repeat(64) });
  const back = await roundTrip([savedRow(0), gone, savedRow(2)]);
  assert.equal(back.length, 3, 'the whole file is kept');
  assert.equal(back[1].tokenId, gone.tokenId);
  assert.ok(lockedInputs(back).has(gone.inputs[0]), 'its coins stay locked');
  assert.equal(activitySymbol(back[1], [TUSDT], true), 'unknown token', 'not pinned any more');
  assert.equal(activitySymbol(back[1], [TUSDT], false), 'tOLD', 'pins not known yet: the saved symbol');
  assert.equal(activitySymbol({ ...back[1], tokenId: TUSDT_ID }, [TUSDT], true), 'tUSDT');
  assert.equal(activitySymbol(back[0], [TUSDT], true), 'NODUS', 'a native row is never judged');
  assert.equal(activitySymbol({ chain: 'ethereum', symbol: 'ETH' }, [TUSDT], true), 'ETH');
});

test('Activity: a malformed tokenId is refused as a row of this wallet\'s own file (all zero, short, wrong symbol, another network)', async () => {
  for (const bad of [{ tokenId: ZERO_TOKEN, symbol: 'tUSDT' }, { tokenId: 'ab'.repeat(63), symbol: 'tUSDT' }, { tokenId: 'AB'.repeat(64), symbol: 'tUSDT' }, { tokenId: TUSDT_ID, symbol: 'NOT OK' }, { tokenId: TUSDT_ID, symbol: '' }, { tokenId: 7, symbol: 'tUSDT' }]) {
    await assert.rejects(roundTrip([savedRow(0, bad)]), /Invalid saved activity/, JSON.stringify(bad));
  }
  // a NODUS row with a token symbol but no tokenId is not a legacy row
  await assert.rejects(roundTrip([savedRow(0, { symbol: 'tUSDT' })]), /Invalid saved activity/);
});

// ── 8. history ───────────────────────────────────────────────────────────
test('history: a pinned token\'s row shows symbol and 6 decimals; fees stay NODUS; another token keeps raw units', () => {
  const entry = (kind, more) => ({ h: '200', i: '0', q: '0', kind, amount: '0', token: ZERO_TOKEN, fee: '0', peer: RECIPIENT, wire: hex128(5), ts: '1790000200', ...more });
  const page = parseAddrHistory({ enabled: true, from_height: '100', entries: [
    entry('spend_in', { amount: '2500000', token: TUSDT_ID }),
    { ...entry('spend_out', { amount: '1500000', token: TUSDT_ID, fee: '10000' }), q: '0', i: '1', h: '199' },
    { ...entry('fee', { fee: '10000', token: TUSDT_ID }), h: '198' },
    { ...entry('spend_in', { amount: '1000', token: 'ab'.repeat(64) }), h: '197' },
    { ...entry('spend_in', { amount: '100000000' }), h: '196' }
  ] });
  const [received, sent, fee, other, native] = page.entries.map(e => nodusHistoryRow(e, { tokens: [TUSDT] }));
  assert.equal(received.amount, '2.5 tUSDT'); assert.equal(received.sign, '+');
  assert.equal(sent.amount, '1.5 tUSDT'); assert.match(sent.detail, /fee 0\.0001 NODUS/);
  assert.equal(fee.amount, '0.0001 NODUS', 'a fee is NODUS whatever token the row names');
  assert.match(other.amount, /^1000 units of token abababab…/);
  assert.equal(native.amount, '1.0 NODUS');
  // without the pins the same row keeps the raw units (nothing invented)
  assert.match(nodusHistoryRow(page.entries[0]).amount, /^2500000 units of token 7142460f…/);
});

// ── 9. the faucet ────────────────────────────────────────────────────────
const claimBody = (state, extra = {}) => ({ claim_id: 'ab'.repeat(16), state, kind: 'full', message: `state ${state}`, ...extra });
const jsonResponse = body => ({ ok: true, json: async () => body });
function fakeFetch(...answers) {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, init });
    const next = answers.length > 1 ? answers.shift() : answers[0];
    if (next instanceof Error) throw next;
    return typeof next?.json === 'function' ? next : jsonResponse(next);   // a raw response, or a body
  };
  return { fetcher, calls };
}
const noSleep = async () => {};
const testnetClient = { state: 'ready', chainId: NODUS_TESTNET_CHAIN_ID, fingerprint: FINGERPRINT };

test('faucet: the button is for the connected identity on the testnet chain only', () => {
  assert.equal(NODUS_TESTNET_CHAIN_ID, 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114');
  assert.equal(faucetAvailable(testnetClient, FINGERPRINT), true);
  assert.equal(faucetAvailable({ ...testnetClient, chainId: CHAIN_ID }, FINGERPRINT), false, 'another chain (a mainnet build): no faucet');
  assert.equal(faucetAvailable({ ...testnetClient, state: 'identified' }, FINGERPRINT), false);
  assert.equal(faucetAvailable(testnetClient, 'cd'.repeat(64)), false, 'not this identity\'s address');
  assert.equal(faucetAvailable(testnetClient, 'xyz'), false);
  assert.equal(faucetAvailable(undefined, FINGERPRINT), false);
});

test('faucet: POST /faucet/claim with the own address on the page\'s origin, then polls GET /faucet/claim/<id> to a final state', async () => {
  const { fetcher, calls } = fakeFetch(claimBody('planned'), claimBody('submitted'), claimBody('confirmed', { message: 'Sent: 100000 NODUS and 100 tUSDT.' }));
  const seen = [];
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep, onState: c => seen.push(c.state) });
  assert.deepEqual(claim, { claimId: 'ab'.repeat(16), state: 'confirmed', kind: 'full', message: 'Sent: 100000 NODUS and 100 tUSDT.' });
  assert.deepEqual(seen, ['planned', 'submitted', 'confirmed']);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, '/faucet/claim'); assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), { address: FINGERPRINT }, 'only the personal address is sent');
  assert.equal(calls[0].init.credentials, 'omit');
  assert.equal(calls[1].url, `/faucet/claim/${'ab'.repeat(16)}`); assert.equal(calls[1].init.method, 'GET');
});

test('faucet: every final state ends the polling at once (refused, expired, unknown, paused, confirmed)', async () => {
  for (const state of ['confirmed', 'expired', 'refused', 'unknown', 'paused']) {
    const { fetcher, calls } = fakeFetch(claimBody(state, { kind: 'none', message: `final ${state}` }));
    const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep });
    assert.equal(claim.state, state); assert.equal(claim.message, `final ${state}`); assert.equal(calls.length, 1, `no poll after ${state}`);
  }
});

test('faucet: a claim not final within the bounded polls is "pending — check again later", never "failed"', async () => {
  const { fetcher, calls } = fakeFetch(claimBody('submitted'));
  let slept = 0;
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: async () => { slept++; } });
  assert.equal(claim.state, 'pending'); assert.equal(claim.message, FAUCET_PENDING_TEXT); assert.match(claim.message, /^Pending — check again later/);
  assert.doesNotMatch(claim.message, /fail/i);
  assert.equal(calls.length, 1 + FAUCET_MAX_POLLS, 'one POST and a bounded number of polls');
  assert.equal(slept, FAUCET_MAX_POLLS);
  // polls that fail count against the same bound and are not "failed" either
  const flaky = fakeFetch(claimBody('planned'), new Error('offline'), { ok: false, json: async () => { throw new Error('html'); } });
  const again = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: flaky.fetcher, sleep: noSleep });
  assert.equal(again.state, 'pending'); assert.equal(flaky.calls.length, 1 + FAUCET_MAX_POLLS);
  // the wallet closing mid-way ends the polling quietly
  let stop = false;
  const closing = fakeFetch(claimBody('planned'));
  const ended = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: closing.fetcher, sleep: async () => { stop = true; }, stopped: () => stop });
  assert.equal(ended.state, 'pending'); assert.equal(closing.calls.length, 1);
});

test('faucet: only checked answers are trusted; a poll answering for another claim is ignored; no usable first answer rejects', async () => {
  for (const bad of [null, [], 'x', {}, claimBody('paid'), claimBody('planned', { kind: 'all' }), claimBody('planned', { claim_id: 'XYZ' }), claimBody('planned', { claim_id: 'ab' }), claimBody('planned', { message: 7 }), claimBody('planned', { message: 'x'.repeat(501) })]) {
    assert.throws(() => parseFaucetClaim(bad), /does not understand/, JSON.stringify(bad)?.slice(0, 60));
    await assert.rejects(claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: fakeFetch(bad).fetcher, sleep: noSleep }), /does not understand|not available right now/);
  }
  await assert.rejects(claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: fakeFetch(new Error('down')).fetcher, sleep: noSleep }), /could not be reached/);
  await assert.rejects(claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher: fakeFetch({ ok: false, json: async () => { throw new Error('<html>'); } }).fetcher, sleep: noSleep }), /not available right now/);
  // another claim's answer is not this claim's state
  const { fetcher } = fakeFetch(claimBody('planned'), claimBody('confirmed', { claim_id: 'cd'.repeat(16) }), claimBody('refused'));
  const claim = await claimTestnetCoins({ client: testnetClient, address: FINGERPRINT, fetcher, sleep: noSleep });
  assert.equal(claim.state, 'refused', 'the foreign "confirmed" was skipped');
  // not on another chain, not for another address, not before the connection is ready
  for (const [client, address] of [[{ ...testnetClient, chainId: CHAIN_ID }, FINGERPRINT], [testnetClient, 'cd'.repeat(64)], [{ ...testnetClient, state: 'connecting' }, FINGERPRINT]]) {
    const { fetcher: f, calls } = fakeFetch(claimBody('planned'));
    await assert.rejects(claimTestnetCoins({ client, address, fetcher: f, sleep: noSleep }), /only on the Nodus testnet/);
    assert.equal(calls.length, 0, 'no request left the wallet');
  }
});
