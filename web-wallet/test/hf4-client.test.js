// HF-4 client side (design docs/plans/2026-10-02-onchain-names-design.md
// rev 4 §1.6, §2 "Clients", §4 R3/R6/R12; decisions
// 2026-10-02-onchain-names.md and 2026-10-02-device-cache-only-when-saved.md)
// against the TEST-ONLY mock module (test/nodus-mock-module.js) and, when
// the parity builds exist, the module's own C rules.
//
// What each test proves:
//   - the JS chain-name rule equals the shared vector list
//     (test/chain-name-vectors.js) and lower-cases ASCII only;
//   - with NODUS_SEND_PARITY_OUT: the C rule the module uses
//     (nsw_name_ok -> dnac_name_bytes_ok) equals the SAME list, and the
//     module's generation choice (nsw_gen_match through the TEST-only
//     exports) matches each pinned tuple to its own generation and refuses
//     any changed field. Without it those tests SKIP (a skip is not a pass);
//   - the expiry rule (expiryHeightFor — the rule of nodus-cli
//     cli_env_expiry) before H, at H-1 and with no valid expiry, and the
//     review rows that warn about a capped expiry;
//   - an older node / an unknown generation (the module's refusal) and a
//     module without rulesetInfo build nothing;
//   - send to a chain name: NODUS (owner fingerprint) and another coin (the
//     owner's signed profile address), with the name, the address and the
//     source on the review; an unresolvable name, a refused (unsigned /
//     unreadable) profile and a missing field are errors, never a fallback;
//     an address always wins over a name;
//   - Connect: the title is the chain name (verified), else the profile
//     name (not verified), else the short ID; the short ID is under every
//     name (decision 2026-10-03-connect-name-display.md); the saved
//     state's chainNames is defaulted and checked.
// What it does NOT prove: the real module's network paths (no node), the
// browser UI wiring (src/app.js, src/connect/ui/messages.js DOM).
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chainNameOk, chainName, asciiLower, parseNameOf } from '../src/nodus/names.js';
import { NAME_BYTE_VECTORS, NAME_INPUT_VECTORS } from './chain-name-vectors.js';
import { createNodusClient } from '../src/nodus/client.js';
import { prepareTransfer, adapters } from '../src/wallet.js';
import { expiryHeightFor, parseRulesetInfo, expiryCapRows, NODUS_REVIEW_MS, NODUS_MIN_BLOCK_MS, parseNameLookup, PROFILE_ADDRESS_FIELD } from '../src/adapters/nodus.js';
import { contactNames, shortId } from '../src/connect/ui/text.js';
import { emptyState, checkState, StorageError } from '../src/connect/store.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT } from './nodus-mock-module.js';

async function readyClient(prepare = () => {}) {
  const mock = createMockNodusModule();
  prepare(mock);
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}
const walletFor = client => ({ addresses: { nodus: FINGERPRINT, ethereum: '0x' + '22'.repeat(20) }, nodusClient: client });
const sendNodus = (client, to, amount = '1') => prepareTransfer({ wallet: walletFor(client), chain: 'nodus', symbol: 'NODUS', to, amount });

// ── the chain-name rule ──────────────────────────────────────────────────
test('chain names: the JS byte rule equals the shared vector list', () => {
  for (const { text, ok } of NAME_BYTE_VECTORS) assert.equal(chainNameOk(text), ok, JSON.stringify(text));
  for (const bad of [undefined, null, 123, ['abc']]) assert.equal(chainNameOk(bad), false);
});

test('chain names: typed text -> name with an ASCII-only lower-casing (never a locale one)', () => {
  for (const { typed, name } of NAME_INPUT_VECTORS) assert.equal(chainName(typed), name, JSON.stringify(typed));
  assert.equal(asciiLower('ABCxyzİI'), 'abcxyzİi');           // only A-Z moves
  assert.equal(asciiLower('PUNK'), 'punk');
});

test('chain names: the module answer is checked (parseNameOf, parseNameLookup)', () => {
  assert.deepEqual(parseNameOf({ found: true, name: 'punk', committedHeight: '10', registeredHeight: '5' }), { found: true, name: 'punk' });
  assert.deepEqual(parseNameOf({ found: false, committedHeight: '10' }), { found: false });
  for (const bad of [null, {}, { found: true, name: 'Punk', committedHeight: '1' }, { found: true, name: 'deadbeef', committedHeight: '1' }, { found: 'yes', committedHeight: '1' }, { found: false, committedHeight: '01' }]) assert.throws(() => parseNameOf(bad), /invalid name/);
  assert.equal(parseNameLookup({ found: true, owner: RECIPIENT, committedHeight: '10', registeredHeight: '5' }).owner, RECIPIENT);
  for (const bad of [{ found: true, owner: 'xy', committedHeight: '10', registeredHeight: '5' }, { found: true, owner: RECIPIENT, committedHeight: '10', registeredHeight: '0' }, { found: true, owner: RECIPIENT.toUpperCase(), committedHeight: '1', registeredHeight: '1' }]) assert.throws(() => parseNameLookup(bad), /invalid/);
});

// ── the module's own C rules (parity build) ──────────────────────────────
const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT;
const skipParity = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (scripts/build-nodus-send-wasm.sh parity)' : false;
async function parityModule(file) {
  const path = join(PARITY_OUT, file);
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  return create();
}

test('chain names: the module\'s C rule (nsw_name_ok -> dnac_name_bytes_ok) equals the SAME vector list', { skip: skipParity }, async () => {
  for (const file of ['send-node.mjs', 'send-test-node.mjs']) {
    const M = await parityModule(file);
    for (const { text, ok } of NAME_BYTE_VECTORS) assert.equal(M.ccall('nsw_name_ok', 'number', ['string'], [text]), ok ? 1 : 0, `${file} ${JSON.stringify(text)}`);
  }
});

test('generation choice in the module: each pinned tuple selects its own generation; any changed field selects none', { skip: skipParity }, async () => {
  const M = await parityModule('send-test-node.mjs');
  const tuple = gen => M.ccall('nsw_test_pins_tuple', 'string', ['number'], [gen]);
  const match = (sv, sh, cv, ch) => M.ccall('nsw_test_gen_match', 'number', ['string', 'string', 'string', 'string'], [sv, sh, cv, ch]);
  const gens = [];
  for (let gen = 1; tuple(gen); gen++) gens.push(gen);
  assert.ok(gens.length >= 2, 'the pins header carries generation 1 and 2 (HF-4)');
  assert.equal(tuple(0), ''); assert.equal(tuple(gens.length + 1), '');
  const flip = hex => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
  for (const gen of gens) {
    const [sv, sh, cv, ch] = tuple(gen).split(':');
    assert.equal(match(sv, sh, cv, ch), gen, `generation ${gen}`);
    assert.equal(match(String(Number(sv) + 1), sh, cv, ch), 0, `generation ${gen}: SYSTEM version changed`);
    assert.equal(match(sv, flip(sh), cv, ch), 0, `generation ${gen}: SYSTEM hash changed`);
    assert.equal(match(sv, sh, String(Number(cv) + 1), ch), 0, `generation ${gen}: CORE version changed`);
    assert.equal(match(sv, sh, cv, flip(ch)), 0, `generation ${gen}: CORE hash changed`);
  }
  // A mixed tuple (generation 1 SYSTEM with generation 2 CORE) is no generation.
  const [sv1, sh1] = tuple(1).split(':'), [, , cv2, ch2] = tuple(2).split(':');
  assert.equal(match(sv1, sh1, cv2, ch2), 0);
  assert.equal(match('x', sh1, cv2, ch2), -1);
});

// ── the expiry rule ──────────────────────────────────────────────────────
test('expiry cap: no switch -> tip + 90; before H capped at H-1; no valid expiry refused; generation 2 never capped', () => {
  const rs = (generation, gen2Height, tip = 1000n) => ({ generation, gen2Height, tip });
  assert.equal(expiryHeightFor(1000n, rs(1n, 0n)), 1090n);                  // no vote committed
  assert.equal(expiryHeightFor(1000n, rs(1n, 1200n)), 1090n);               // H far: not reached
  assert.equal(expiryHeightFor(1000n, rs(1n, 1050n)), 1049n);               // capped at H-1
  assert.equal(expiryHeightFor(1000n, rs(1n, 1091n)), 1090n);               // H-1 == tip+90
  assert.equal(expiryHeightFor(1000n, rs(1n, 1002n)), 1001n);               // only the next block left
  assert.throws(() => expiryHeightFor(1000n, rs(1n, 1001n)), /switches to new transaction rules at block 1001.*try again after block 1001/);
  assert.throws(() => expiryHeightFor(1000n, rs(1n, 900n)), /try again after block 900/);
  // the MORE conservative tip judges validity: the ruleset answer's
  assert.throws(() => expiryHeightFor(1000n, rs(1n, 1002n, 1001n)), /block 1002/);
  // ...or the listing's
  assert.throws(() => expiryHeightFor(1001n, rs(1n, 1002n, 1000n)), /block 1002/);
  // a generation-2 envelope is built for the rules after H: never capped
  assert.equal(expiryHeightFor(1000n, rs(2n, 1050n)), 1090n);
  assert.throws(() => expiryHeightFor(2n ** 64n - 10n, rs(1n, 0n)), /out of range/);
  // the module's answer is parsed strictly
  assert.deepEqual(parseRulesetInfo({ tip: '7', generation: '2', gen2Height: '0' }), { tip: 7n, generation: 2n, gen2Height: 0n });
  for (const bad of [null, { tip: '7', generation: '0', gen2Height: '0' }, { tip: '7', generation: '1' }, { tip: '-1', generation: '1', gen2Height: '0' }]) assert.throws(() => parseRulesetInfo(bad));
});

test('expiry cap: the review says so, and warns when it may expire while the review is open', () => {
  const rs = { generation: 1n, gen2Height: 1050n, tip: 1000n };
  assert.equal(NODUS_REVIEW_MS, 60000); assert.equal(NODUS_MIN_BLOCK_MS, 4000);
  assert.deepEqual(expiryCapRows(1000n, 1090n, rs), []);                     // not capped
  const capped = Object.fromEntries(expiryCapRows(1000n, 1049n, rs));
  assert.match(capped['Rule change'], /block 1050.*up to block 1049/);
  assert.equal(capped.Timing, undefined);                                    // 49 blocks > 15
  // 60 s / 4 s = 15 blocks can pass while the review is open
  assert.match(Object.fromEntries(expiryCapRows(1000n, 1015n, rs)).Timing, /Only 15 blocks remain/);
  assert.equal(Object.fromEntries(expiryCapRows(1000n, 1016n, rs)).Timing, undefined);
  assert.match(Object.fromEntries(expiryCapRows(1000n, 1001n, rs)).Timing, /Only 1 block remains/);
});

test('expiry cap end to end: the request carries H-1, the review says why; no valid expiry builds nothing', async () => {
  const { mock, client } = await readyClient(m => { m.state.ruleset = { tip: '1000', generation: '1', gen2Height: '1011' }; });
  const transfer = await sendNodus(client, RECIPIENT);
  assert.equal(mock.state.lastBuild.expiryHeight, '1010');
  const review = Object.fromEntries(transfer.review);
  assert.equal(review['Valid until block'], '1010');
  assert.match(review['Rule change'], /block 1011/); assert.match(review.Timing, /Only 10 blocks remain/);
  transfer.cancel();
  mock.state.ruleset = { tip: '1000', generation: '1', gen2Height: '1001' };
  const builds = mock.log.filter(entry => entry === 'buildAndSign:start').length;
  await assert.rejects(sendNodus(client, RECIPIENT), /try again after block 1001/);
  assert.equal(mock.log.filter(entry => entry === 'buildAndSign:start').length, builds, 'nothing built');
  client.lock();
});

// ── the generation refusals (R12: fail closed) ───────────────────────────
test('generation: an older node or an unknown generation (the module refuses) builds nothing', async () => {
  for (const message of ['This Nodus node did not say which transaction rules it runs (an older node, or an unreadable answer; rc=7). Nothing was built.',
    'This page is out of date: the Nodus network runs transaction rules this page does not know (generation 3). Reload the page. Nothing was built.']) {
    const { mock, client } = await readyClient(m => { m.state.rulesetError = new Error(message); });
    await assert.rejects(sendNodus(client, RECIPIENT), error => error.message === message);
    assert.ok(!mock.log.includes('buildAndSign:start'), 'nothing built');
    client.lock();
  }
  // A malformed answer is refused by the wallet as well.
  const { mock, client } = await readyClient(m => { m.state.ruleset = { tip: '1000', generation: '0', gen2Height: '0' }; });
  await assert.rejects(sendNodus(client, RECIPIENT), /invalid network rules/);
  assert.ok(!mock.log.includes('buildAndSign:start'));
  client.lock();
});

test('generation: a module without rulesetInfo does not match this wallet (no build path without it)', async () => {
  const mock = createMockNodusModule();
  delete mock.module.rulesetInfo;
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await assert.rejects(client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT }), /does not match this wallet version/);
  assert.equal(client.state, 'error');
});

// ── send to a chain name: NODUS ──────────────────────────────────────────
test('send to a chain name (NODUS): the owner is the recipient; the review shows name, address and source', async () => {
  const { mock, client } = await readyClient(m => { m.state.names = { punk: RECIPIENT }; });
  const transfer = await sendNodus(client, '  Punk ');
  assert.equal(transfer.to, RECIPIENT); assert.equal(transfer.recipientName, 'punk');
  assert.equal(mock.state.lastBuild.to, RECIPIENT);
  const review = Object.fromEntries(transfer.review);
  assert.equal(review['To (chain name)'], 'punk'); assert.equal(review.To, RECIPIENT);
  assert.match(review['Recipient source'], /^Chain name — looked up on one Nodus node \(state of block 1000\)\.$/);
  assert.match(review['Name check'], /look alike/); assert.equal(review['Address check'], undefined);
  transfer.cancel();
  // A typed address is still an address: no lookup.
  const lookups = mock.log.filter(entry => entry === 'nameLookup:start').length;
  const direct = await sendNodus(client, RECIPIENT);
  assert.equal(mock.log.filter(entry => entry === 'nameLookup:start').length, lookups);
  assert.equal(direct.recipientName, undefined); assert.ok(Object.fromEntries(direct.review)['Address check']);
  direct.cancel();
  client.lock();
});

test('send to a chain name (NODUS): an unregistered or malformed name is an error; nothing is built', async () => {
  const { mock, client } = await readyClient(m => { m.state.names = { punk: RECIPIENT }; });
  await assert.rejects(sendNodus(client, 'nobody'), /No one has registered the chain name "nobody"/);
  await assert.rejects(sendNodus(client, 'pu-nk'), /Nodus address .* or a chain name/);
  await assert.rejects(sendNodus(client, 'DEADBEEF'), /Nodus address .* or a chain name/);
  mock.state.nameError = new Error('The chain name could not be looked up (an older node, or no readable answer; rc=7).');
  await assert.rejects(sendNodus(client, 'punk'), /could not be looked up/);
  assert.ok(!mock.log.includes('buildAndSign:start'), 'nothing built');
  client.lock();
  // A module without the name operations: a name never resolves.
  const bare = await readyClient(m => { delete m.module.nameLookup; });
  assert.equal(bare.client.nameable, false);
  await assert.rejects(sendNodus(bare.client, 'punk'), /needs the Nodus network connection/);
  bare.client.lock();
});

// ── send to a chain name: another coin ───────────────────────────────────
const EVM_TO = '0x' + '11'.repeat(20);
function evmStub(seen) {
  return {
    isRecipientAddress: text => typeof text === 'string' && /^0x[0-9a-fA-F]{40}$/.test(text),
    prepare: async ({ to }) => { seen.push(to); return { expiresAt: Date.now() + 10000, fee: '0.001', nonce: 1, send: async () => 'hash' }; }
  };
}
const sendEvm = (client, to, implementations, chain = 'ethereum') => prepareTransfer({ wallet: walletFor(client), chain, symbol: chain === 'bsc' ? 'BNB' : 'ETH', to, amount: '1', endpoint: 'https://rpc.example' }, implementations);

test('send to a chain name (other coin): the owner\'s signed profile address is used; the review data names its source', async () => {
  assert.deepEqual({ ...PROFILE_ADDRESS_FIELD }, { ethereum: 'eth', bsc: 'bsc', solana: 'sol', tron: 'trx' });
  const { mock, client } = await readyClient(m => { m.state.names = { punk: RECIPIENT }; m.state.profiles = { [RECIPIENT]: { eth: EVM_TO } }; });
  const seen = [];
  const transfer = await sendEvm(client, 'PUNK', { ethereum: evmStub(seen), nodus: adapters.nodus });
  assert.deepEqual(seen, [EVM_TO]); assert.equal(transfer.to, EVM_TO);
  assert.equal(transfer.named.name, 'punk'); assert.equal(transfer.named.owner, RECIPIENT); assert.equal(transfer.named.address, EVM_TO);
  const rows = Object.fromEntries(adapters.nodus.nameReviewRows(transfer.named, { via: 'the address published in the owner’s signed profile' }));
  assert.equal(rows['To (chain name)'], 'punk'); assert.equal(rows['Name owner (Nodus ID)'], RECIPIENT);
  assert.match(rows['Recipient source'], /signed profile — looked up on one Nodus node/);
  transfer.cancel();
  // An address always wins: no lookup at all.
  const lookups = mock.log.filter(entry => entry === 'nameLookup:start').length;
  (await sendEvm(client, EVM_TO, { ethereum: evmStub(seen), nodus: adapters.nodus })).cancel();
  assert.equal(mock.log.filter(entry => entry === 'nameLookup:start').length, lookups);
  client.lock();
});

test('send to a chain name (other coin): no field for that network, an unsigned / unreadable profile, an unknown name — errors, no fallback', async () => {
  const { mock, client } = await readyClient(m => { m.state.names = { punk: RECIPIENT }; m.state.profiles = { [RECIPIENT]: { eth: EVM_TO } }; });
  const seen = [];
  const impl = { ethereum: evmStub(seen), bsc: evmStub(seen), nodus: adapters.nodus };
  // BNB Smart Chain reads the "bsc" field only — never the "eth" one.
  await assert.rejects(sendEvm(client, 'punk', impl, 'bsc'), /no address for this network/);
  mock.state.profileError = new Error('The profile of this name\'s owner could not be read, or did not pass its signature check. Nothing was sent.');
  await assert.rejects(sendEvm(client, 'punk', impl), /signature check/);
  mock.state.profileError = null;
  await assert.rejects(sendEvm(client, 'nobody', impl), /No one has registered the chain name "nobody"/);
  assert.deepEqual(seen, [], 'the coin\'s adapter never ran');
  // Chain names on a network without a profile field are refused.
  await assert.rejects(adapters.nodus.resolveNameAddress({ client, chain: 'cellframe', name: 'punk' }), /cannot be used on this network/);
  client.lock();
  // Without a ready NODUS connection a name cannot be resolved.
  await assert.rejects(sendEvm(undefined, 'punk', impl), /needs the Nodus network connection/);
  assert.deepEqual(seen, []);
});

// ── address-shaped text is never a chain name ────────────────────────────
// The real adapters' isRecipientAddress / looksLikeAddress with a stub
// prepare; the mock module's log is the spy on the name lookup.
const TRON_VALID = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';          // src/config.js USDT (TRON)
const TRX_OWNER_ADDR = 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8';      // src/config.js USDC (TRON)
function addressStub(adapter, seen) {
  return { isRecipientAddress: adapter.isRecipientAddress, looksLikeAddress: adapter.looksLikeAddress, prepare: async ({ to }) => { seen.push(to); return { expiresAt: Date.now() + 10000, fee: '1', nonce: 1, send: async () => 'hash' }; } };
}
const sendOn = (client, chain, to, implementations) => prepareTransfer({ wallet: walletFor(client), chain, symbol: { tron: 'TRX', ethereum: 'ETH', bsc: 'BNB' }[chain], to, amount: '1' }, implementations);

test('address-shaped text is never a chain name: TRON (34 x T/t, 41+40 hex) and EVM (0x / 0X)', async () => {
  const tronAdapter = adapters.tron, evmAdapter = adapters.ethereum;
  // A 34-char lower-cased TRON text is a legal chain name — the reason for this rule.
  assert.equal(chainName(TRON_VALID.toLowerCase()), TRON_VALID.toLowerCase());
  const { mock, client } = await readyClient(m => {
    // the lower-cased TRON text IS a registered name here: only the shape rule keeps it from resolving
    m.state.names = { punk: RECIPIENT, [TRON_VALID.toLowerCase()]: RECIPIENT };
    m.state.profiles = { [RECIPIENT]: { trx: TRX_OWNER_ADDR, eth: EVM_TO, bsc: EVM_TO } };
  });
  const lookups = () => mock.log.filter(entry => entry === 'nameLookup:start').length;
  const seen = [];
  const impl = { tron: addressStub(tronAdapter, seen), ethereum: addressStub(evmAdapter, seen), bsc: addressStub(evmAdapter, seen), nodus: adapters.nodus };
  const before = lookups();
  // a valid TRON address goes straight to the adapter
  (await sendOn(client, 'tron', TRON_VALID, impl)).cancel();
  assert.deepEqual(seen, [TRON_VALID]);
  // case-mangled (lower / upper) and a bad checksum: refused, never looked up
  for (const bad of [TRON_VALID.toLowerCase(), TRON_VALID.toUpperCase(), TRON_VALID.slice(0, -1) + 'u']) {
    assert.equal(tronAdapter.isRecipientAddress(bad), false, bad);
    assert.equal(tronAdapter.looksLikeAddress(bad), true, bad);
    await assert.rejects(sendOn(client, 'tron', bad, impl), /Invalid TRON address\./, bad);
  }
  assert.deepEqual(seen, [TRON_VALID], 'no adapter build for a refused address');
  // the 41 + 40 hex form is an address attempt: to the adapter if TronWeb
  // accepts it, refused otherwise — never a lookup either way
  const hex41 = '41' + 'ab'.repeat(20);
  assert.equal(tronAdapter.looksLikeAddress(hex41), true);
  if (tronAdapter.isRecipientAddress(hex41)) { (await sendOn(client, 'tron', hex41, impl)).cancel(); assert.equal(seen.pop(), hex41); }
  else await assert.rejects(sendOn(client, 'tron', hex41, impl), /Invalid TRON address\./);
  // EVM: anything starting with 0x / 0X is an address attempt
  for (const bad of ['0x' + 'ab'.repeat(17), '0X' + 'ab'.repeat(20), '0xpunk']) {
    assert.equal(evmAdapter.looksLikeAddress(bad), true, bad);
    await assert.rejects(sendOn(client, 'ethereum', bad, impl), /Invalid Ethereum address\./, bad);
    await assert.rejects(sendOn(client, 'bsc', bad, impl), /Invalid BNB Smart Chain address\./, bad);
  }
  assert.equal(lookups(), before, 'no name lookup for any address-shaped text');
  assert.deepEqual(seen, [TRON_VALID], 'no adapter build for a refused address');
  // a real name still resolves on TRON and on EVM
  (await sendOn(client, 'tron', 'punk', impl)).cancel();
  (await sendOn(client, 'ethereum', 'Punk', impl)).cancel();
  assert.equal(lookups(), before + 2);
  assert.deepEqual(seen, [TRON_VALID, TRX_OWNER_ADDR, EVM_TO]);
  // Solana is unchanged: no looksLikeAddress (real addresses are 43-44 chars, names at most 36)
  assert.equal(adapters.solana.looksLikeAddress, undefined);
  client.lock();
});

// ── Connect: one name per contact, ID underneath ─────────────────────────
// Decision docs/plans/decisions/2026-10-03-connect-name-display.md.
test('Connect names: chain name (verified), else profile name (not verified), else short ID; the short ID under any name', () => {
  const fp = RECIPIENT;
  assert.deepEqual(contactNames(fp, { chain: 'punk', profile: 'Punk Official', claimed: 'x' }),
    { title: 'punk', verified: true, fromProfile: false, id: shortId(fp), claimed: '' });    // no second name beside it
  assert.deepEqual(contactNames(fp, { chain: 'punk', profile: 'punk' }),
    { title: 'punk', verified: true, fromProfile: false, id: shortId(fp), claimed: '' });
  assert.deepEqual(contactNames(fp, { profile: 'alice', claimed: 'x' }),
    { title: 'alice', verified: false, fromProfile: true, id: shortId(fp), claimed: '' });   // a profile name is the title, never verified
  assert.deepEqual(contactNames(fp, { claimed: 'bob' }),
    { title: shortId(fp), verified: false, fromProfile: false, id: '', claimed: 'bob' });    // a claim only when nothing better is known
  assert.deepEqual(contactNames(fp), { title: shortId(fp), verified: false, fromProfile: false, id: '', claimed: '' });
});

test('Connect store: chainNames defaults on an older state, keeps a valid entry, refuses a malformed one', () => {
  const older = { ...emptyState() }; delete older.chainNames;
  assert.deepEqual(checkState(older).chainNames, {});
  const fp = RECIPIENT;
  assert.doesNotThrow(() => checkState({ ...emptyState(), chainNames: { [fp]: { name: 'punk', at: '1790000000' } } }));
  for (const bad of [
    { [fp]: { name: 'Punk', at: '1' } }, { [fp]: { name: 'deadbeef', at: '1' } }, { [fp]: { name: '', at: '1' } },
    { [fp]: { name: 'punk', at: 'x' } }, { [fp.toUpperCase()]: { name: 'punk', at: '1' } }, { short: { name: 'punk', at: '1' } }, { [fp]: 'punk' }
  ]) assert.throws(() => checkState({ ...emptyState(), chainNames: bad }), StorageError, JSON.stringify(bad));
  assert.throws(() => checkState({ ...emptyState(), chainNames: [] }), StorageError);
});
