// Smart contracts — the client side of the EVM read RPC (design
// docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §18), the
// receipt encoding (§7) and the one-pending-per-sender queue (operator
// decision 2026-10-04-nodus-evm-kurultay-k2-summary.md #2).
// What it proves:
//   - a module without evmQuery / evmBuild: every smart-contract call says
//     "not available", nothing reaches the module;
//   - each §18 method sends exactly the documented CBOR keys, tagged
//     (['b', hex] byte string / ['u', decimal]), and refuses bad arguments
//     before the module is called;
//   - malformed replies are refused, never shown;
//   - a receipt's digest is re-computed from its fields: the bytes are
//     assembled HERE, independently, from the §7 layout (and the node
//     encoder nodus_witness_rt_evm.c rcpt_build), hashed with node:crypto's
//     SHA3-512; a tampered field or digest is refused;
//   - EvmAccount builds the second transaction only after the first one's
//     receipt arrived;
//   - red-team 1 F8: confirm() records the transaction through the host's
//     onBroadcast BEFORE the envelope is submitted, in the NODUS row shape
//     (validNodusPending) whose inputs lockedInputs holds; without that
//     record nothing is sent; a refused submission and a receipt-polling
//     error keep the reservation; a reservation restored from Activity
//     blocks the first build;
//   - red-team 2: a record callback that refuses an unsaved wallet
//     (requireSavedForEvm, the check src/app.js recordEvmActivity makes
//     first) sends nothing and leaves no reservation — app.js's call itself
//     is not loaded here (it needs the page);
//   - red-team 1 F9: an estimate with gu > ge, ge = 0 or ge above the cap is
//     refused before anything is built; a built fee above EVM_MAX_FEE_RAW
//     is refused, one at it is offered;
//   - red-team 1 F11: decodeEvmBuilt carries the module's computed CREATE
//     address only on a CREATE; createdCheck tells match / mismatch /
//     unchecked / none;
//   - red-team 1 F4 (evm_logs is a bounded cursor scan): a request cursor
//     crosses as "c" = ['U', [h, x, li]] and is refused outside
//     fh <= h <= th or past 2^32; parseLogs takes a page exactly when the
//     C SDK does (nodus_client.c evm_dec_logs + evm_logs_page_check): "c"
//     present exactly when more, an empty page with more + c accepted,
//     logs strictly increasing in (h, x, li), inside [fh, th], at or after
//     the start, at most `lim` of them, the cursor inside [fh, th], not
//     behind the start and strictly after the last log; send-module.js
//     evmQuery writes the 'U' tag as `key=U:a,b,c` (1..3 u64) and refuses
//     anything else before the module is called (a stub module glue).
// Requires nothing beyond `npm ci`. The F8 refused-submission case waits
// for one receipt poll (POLL_MIN_MS, 2 s). How it can lie: the module is the
// TEST-ONLY mock (test/nodus-mock-module.js) extended with canned evmQuery /
// evmBuild answers — no node, no CBOR, no real envelope; the receipt values
// are synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createNodusClient } from '../src/nodus/client.js';
import { createNodusSendModule, NODUS_SEND_NETWORK } from '../src/nodus/send-module.js';
import { parseReceipt, receiptDigest, parseAccount, parseCall, parseLogs, EMPTY_CODE_HASH } from '../src/evm/rpc.js';
import { EvmAccount, decodeEvmBuilt, createdCheck, EVM_MAX_FEE_RAW } from '../src/evm/contract.js';
import { recordActivity, validNodusPending } from '../src/activity.js';
import { requireSavedForEvm } from '../src/activity-storage.js';
import { lockedInputs } from '../src/adapters/nodus.js';
import { createMockNodusModule, FINGERPRINT, CHAIN_ID, coin } from './nodus-mock-module.js';

async function readyClient(extend = () => {}, { generation = '3' } = {}) {
  const mock = createMockNodusModule();
  // the module names the EVM generation; the node runs it (or, with
  // `generation`, an older one)
  mock.module.evmGeneration = 3;
  mock.state.ruleset = { ...mock.state.ruleset, generation };
  extend(mock);
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(3), fingerprint: FINGERPRINT });
  return { mock, client };
}
const ADDR = 'ab'.repeat(32);

// §7, assembled independently: tag(16) ‖ status ‖ op ‖ gas u64 ‖ created32 ‖
// output_len u32 ‖ output ‖ n_logs u32 ‖ logs ‖ wei_destroyed32 ‖ n_tickets
// u16 ‖ ticket ids
function referenceReceiptHex(r) {
  const u = (v, n) => BigInt(v).toString(16).padStart(2 * n, '0');
  let s = Buffer.concat([Buffer.from('NDS.EVMRCPT.v1'), Buffer.alloc(2)]).toString('hex');
  s += u(r.s, 1) + u(r.op, 1) + u(r.gu, 8) + (r.cr ?? '00'.repeat(32));
  s += u(r.o.length / 2, 4) + r.o + u(r.logs.length, 4);
  for (const l of r.logs) s += l.a + u(l.t.length, 1) + l.t.join('') + u(l.d.length / 2, 4) + l.d;
  s += r.wd + u(r.tk.length, 2) + r.tk.join('');
  return s;
}
function wireReceipt(over = {}) {
  const r = {
    h: '120', x: '3', s: '1', op: '1', gu: '53210', o: 'c0ffee', wd: '00'.repeat(31) + '05',
    logs: [{ a: ADDR, t: ['11'.repeat(32), '22'.repeat(32)], d: 'beef' }, { a: 'cd'.repeat(32), t: [], d: '' }],
    tk: ['77'.repeat(64)], ...over
  };
  if (!('dg' in over)) r.dg = createHash('sha3-512').update(Buffer.from(referenceReceiptHex(r), 'hex')).digest('hex');
  return r;
}

test('a module without the smart-contract operations: nothing is offered and nothing reaches it', async () => {
  const { client, mock } = await readyClient();
  assert.equal(client.evmBuildable, false);
  assert.equal(client.evmReadable, false);
  await assert.rejects(client.evmAccount({ address: ADDR }), /not available/);
  await assert.rejects(client.evmBuild({ op: 'deposit' }), /not available/);
  assert.ok(!mock.log.some(entry => String(entry).startsWith('evm')));
});

test('a node below the EVM generation: neither group is offered (the panel stays hidden)', async () => {
  const { client, mock } = await readyClient(m => {
    m.module.evmQuery = async () => ({});
    m.module.evmBuild = async () => { throw new Error('must not be reached'); };
  }, { generation: '2' });
  assert.equal(client.evmBuildable, false);
  assert.equal(client.evmReadable, false);
  await assert.rejects(client.evmAccount({ address: ADDR }), /not available/);
  assert.ok(mock.log.includes('rulesetInfo:start'), 'the node was asked which rules it runs');
});

test('§18 requests carry exactly the documented keys, tagged; bad arguments never reach the module', async () => {
  const seen = [];
  const { client } = await readyClient(mock => {
    mock.module.evmQuery = async request => {
      seen.push(request);
      if (request.method === 'evm_account') return { n: '7', b: '00'.repeat(31) + '0a', ch: EMPTY_CODE_HASH, cs: '0', h: '99' };
      if (request.method === 'evm_call') return { s: '1', o: '00'.repeat(32), gu: '21000', h: '99' };
      if (request.method === 'evm_logs') return { logs: [], more: false };
      return {};
    };
  });
  assert.equal(client.evmReadable, true);
  const acct = await client.evmAccount({ address: ADDR });
  assert.deepEqual(acct, { nonce: 7n, balanceWei: 10n, codeHash: EMPTY_CODE_HASH, codeSize: 0n, height: 99n });
  await client.evmCall({ from: ADDR, to: 'cd'.repeat(32), data: 'a9059cbb', value: '00'.repeat(32), gas: '50000' });
  await client.evmCall({ from: ADDR, data: '6080' });                 // no `t`: a CREATE simulation
  await client.evmLogs({ fromHeight: '1', toHeight: '100', address: ADDR, topics: [null, '11'.repeat(32)], limit: '10' });
  assert.equal(await client.evmReceipt({ intentId: '9'.repeat(128) }), null);
  assert.deepEqual(seen, [
    { method: 'evm_account', args: { a: ['b', ADDR] } },
    { method: 'evm_call', args: { f: ['b', ADDR], d: ['b', 'a9059cbb'], t: ['b', 'cd'.repeat(32)], v: ['b', '00'.repeat(32)], g: ['u', '50000'] } },
    { method: 'evm_call', args: { f: ['b', ADDR], d: ['b', '6080'] } },
    { method: 'evm_logs', args: { fh: ['u', '1'], th: ['u', '100'], lim: ['u', '10'], a: ['b', ADDR], t1: ['b', '11'.repeat(32)] } },
    { method: 'evm_receipt', args: { i: ['b', '9'.repeat(128)] } }
  ]);
  const before = seen.length;
  await assert.rejects(client.evmAccount({ address: ADDR.toUpperCase() }), /Invalid address/);
  await assert.rejects(client.evmAccount({ address: 'ab'.repeat(20) }), /Invalid address/);
  await assert.rejects(client.evmCall({ from: ADDR, data: 'abc' }), /call data/);
  await assert.rejects(client.evmLogs({ fromHeight: '1', toHeight: '10001' }), /block range/);
  await assert.rejects(client.evmLogs({ fromHeight: '5', toHeight: '4' }), /block range/);
  await assert.rejects(client.evmLogs({ fromHeight: '1', toHeight: '2', limit: '1001' }), /limit/);
  await assert.rejects(client.evmTicket({ id: 'ab' }), /ticket/);
  assert.equal(seen.length, before);
});

test('malformed replies are refused', () => {
  const good = { n: '1', b: '00'.repeat(32), ch: '11'.repeat(32), cs: '3', h: '5' };
  assert.equal(parseAccount(good).nonce, 1n);
  for (const bad of [null, [], { ...good, n: '-1' }, { ...good, n: '18446744073709551616' }, { ...good, b: '00'.repeat(31) }, { ...good, ch: 'XX'.repeat(32) }, { ...good, cs: '4294967296' }, { ...good, h: 5 }]) {
    assert.throws(() => parseAccount(bad), /malformed/, JSON.stringify(bad));
  }
  assert.throws(() => parseCall({ s: '2', o: '', gu: '0', h: '1' }), /status/);
  assert.throws(() => parseLogs({ logs: [], more: 'no' }), /logs/);
  assert.throws(() => parseLogs({ logs: [{ h: '1', x: '0', li: '0', a: ADDR, t: Array(5).fill('11'.repeat(32)), d: '', i: '9'.repeat(128) }], more: false }), /topics/);
});

test('a receipt is accepted only when its digest matches the §7 encoding of its fields', () => {
  const r = parseReceipt(wireReceipt());
  assert.equal(r.status, 'applied-success');
  assert.equal(r.gasUsed, 53210n);
  assert.equal(r.weiDestroyed, 5n);
  assert.equal(receiptDigest(r), r.digest);
  const failed = parseReceipt(wireReceipt({ s: '0', o: '', logs: [], tk: [], wd: '00'.repeat(32) }));
  assert.equal(failed.status, 'applied-failed');
  const created = parseReceipt(wireReceipt({ op: '2', cr: 'ee'.repeat(32) }));
  assert.equal(created.created, 'ee'.repeat(32));
  // a created address on anything but a successful CREATE is malformed
  assert.throws(() => parseReceipt(wireReceipt({ op: '1', cr: 'ee'.repeat(32) })), /created/);
  // tamper with one field after the digest was made
  const tampered = wireReceipt();
  tampered.gu = '53211';
  assert.throws(() => parseReceipt(tampered), /does not match its own digest/);
  assert.throws(() => parseReceipt(wireReceipt({ dg: '00'.repeat(64) })), /does not match/);
  assert.equal(parseReceipt({}), null);
});

test('one pending transaction per account: the next build waits for the previous receipt', async () => {
  let receiptReady = false;
  const builds = [];
  const intent = n => String(n).repeat(128);
  const { client } = await readyClient(mock => {
    mock.module.evmQuery = async ({ method }) => {
      if (method === 'evm_account') return { n: String(builds.length), b: '00'.repeat(32), ch: EMPTY_CODE_HASH, cs: '0', h: '1000' };
      if (method === 'evm_receipt') return receiptReady ? wireReceipt({ op: '3', s: '1', o: '', logs: [], tk: [], wd: '00'.repeat(32) }) : {};
      return {};
    };
    mock.module.evmBuild = async req => {
      builds.push(req);
      return {
        envelope: Uint8Array.of(1, 2, 3), intentId: intent(builds.length),
        decoded: {
          op: req.op, to: '', valueWei: '', gasLimit: '', nonce: req.nonce, units: '500', amount: req.amount, dest: '', ticketId: '',
          dataLength: 0, recipient: FINGERPRINT, fee: '1000', change: String(BigInt(req.coins[0].amount) - BigInt(req.amount) - 1000n),
          expiryHeight: req.expiryHeight, chainId: CHAIN_ID, inputs: [req.coins[0].nullifier]
        }
      };
    };
  });
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
  const first = await account.deposit(1000n);
  assert.equal(builds.length, 1);
  assert.equal(builds[0].nonce, '0');
  const sent = await first.confirm(async () => {});
  const secondPrepared = account.deposit(2000n);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(builds.length, 1, 'the second build must wait for the first receipt');
  receiptReady = true;
  const outcome = await sent.receipt;
  assert.equal(outcome.status, 'applied-success');
  const second = await secondPrepared;
  assert.equal(builds.length, 2);
  assert.equal(builds[1].nonce, '1');
  second.cancel();
});

// ── red-team 1: F8 (durable reservation), F9 (estimate / fee), F11 ─────

// A module answering DEPOSIT builds (fee `fee`) and evm_receipt through
// `receipt()` (an Error thrown = the node could not be read).
function depositModule({ receipt = () => ({}), fee = '1000', estimate = null } = {}) {
  const builds = [];
  const extend = mock => {
    mock.module.evmQuery = async ({ method }) => {
      if (method === 'evm_account') return { n: String(builds.length), b: '00'.repeat(32), ch: EMPTY_CODE_HASH, cs: '0', h: '1000' };
      if (method === 'evm_receipt') return receipt();
      if (method === 'evm_estimate' && estimate) return estimate;
      return {};
    };
    mock.module.evmBuild = async req => {
      builds.push(req);
      return {
        // never equal to a coin nullifier: an intent id equal to its only
        // input is the claim-record marker (src/adapters/nodus.js isClaimRow)
        envelope: Uint8Array.of(1, 2, 3), intentId: 'e'.repeat(127) + String(builds.length),
        decoded: {
          op: req.op, to: '', valueWei: '', gasLimit: '', nonce: req.nonce, units: '500', amount: req.amount, dest: '', ticketId: '',
          dataLength: 0, recipient: FINGERPRINT, fee, change: String(BigInt(req.coins[0].amount) - BigInt(req.amount) - BigInt(fee)),
          expiryHeight: req.expiryHeight, chainId: CHAIN_ID, inputs: [req.coins[0].nullifier]
        }
      };
    };
  };
  return { builds, extend };
}
const DEPOSIT_RECEIPT = () => wireReceipt({ op: '3', s: '1', o: '', logs: [], tk: [], wd: '00'.repeat(32) });
const unreadable = () => { throw new Error('node unreachable'); };

test('F8: the Activity record is made before the envelope is sent, in the shape that holds its coins', async () => {
  const m = depositModule({ receipt: DEPOSIT_RECEIPT });
  const { client, mock } = await readyClient(m.extend);
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
  const view = await account.deposit(1000n);
  let recorded = null;
  const sent = await view.confirm(async details => {
    assert.equal(mock.state.submitted, undefined, 'recorded before anything was submitted');
    recorded = details;
  });
  assert.ok(mock.state.submitted, 'submitted after the record');
  assert.equal(recorded.hash, sent.intentId);
  assert.ok(validNodusPending(recorded), 'the NODUS pending-send shape');
  // the wallet's row (src/app.js recordEvmActivity) holds exactly these coins
  const row = recordActivity({ chain: 'nodus', from: FINGERPRINT, to: FINGERPRINT, symbol: 'NODUS', amount: '0.00002' }, recorded);
  assert.deepEqual([...lockedInputs([row])], recorded.inputs);
  assert.equal((await sent.receipt).status, 'applied-success');
});

test('F8: without the host record nothing is sent, and the queue moves on', async () => {
  const m = depositModule();
  const { client, mock } = await readyClient(m.extend);
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
  const view = await account.deposit(1000n);
  await assert.rejects(view.confirm(), /cannot be recorded/);
  assert.equal(mock.state.submitted, undefined);
  const next = await account.deposit(1000n);
  assert.equal(m.builds.length, 2);
  next.cancel();
});

test('red-team 2: an unsaved wallet\'s confirm sends nothing (the record callback refuses first)', async () => {
  const m = depositModule();
  const { client, mock } = await readyClient(m.extend);
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
  const view = await account.deposit(1000n);
  let written = false;
  // the shape of src/app.js recordEvmActivity: the saved-wallet check
  // comes before any row is written
  const record = async () => { requireSavedForEvm(false); written = true; };
  await assert.rejects(view.confirm(record), /saved in this browser first.*Nothing was sent/);
  assert.equal(written, false);
  assert.equal(mock.state.submitted, undefined, 'nothing was submitted');
  assert.equal(account.waiting(), false, 'no reservation was left behind');
  const next = await account.deposit(1000n);
  assert.equal(m.builds.length, 2, 'the queue moved on');
  next.cancel();
});

test('F8: a refused submission keeps the reservation; the next build waits for the receipt', async () => {
  let receiptReady = false;
  const m = depositModule({ receipt: () => (receiptReady ? DEPOSIT_RECEIPT() : {}) });
  const { client, mock } = await readyClient(m.extend);
  mock.state.accepted = false;
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
  const view = await account.deposit(1000n);
  const error = await view.confirm(async () => {}).then(() => null, e => e);
  assert.ok(error?.sent, 'the uncertain outcome carries the sent transaction');
  assert.match(error.message, /did not accept.*tracked in Activity/);
  assert.equal(account.waiting(), true);
  const secondPrepared = account.deposit(2000n);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(m.builds.length, 1, 'the second build waits for the first one');
  receiptReady = true;
  assert.equal((await error.sent.receipt).status, 'applied-success');
  const second = await secondPrepared;
  assert.equal(m.builds.length, 2);
  second.cancel();
});

test('F8: a receipt-polling error does not release a recorded reservation', async () => {
  const m = depositModule({ receipt: unreadable });
  const { client } = await readyClient(m.extend);
  const rows = [];                                   // the host's unresolved Activity rows
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT, reservations: () => rows });
  const view = await account.deposit(1000n);
  const sent = await view.confirm(async details => { rows.push({ hash: details.hash, expiryHeight: details.expiryHeight }); });
  await assert.rejects(sent.receipt, /node unreachable/);
  await assert.rejects(account.deposit(2000n), /still waiting/);
  assert.equal(m.builds.length, 1, 'nothing was built while the reservation stands');
  rows.length = 0;                                   // the Activity tracker resolved the row
  const next = await account.deposit(2000n);
  assert.equal(m.builds.length, 2);
  next.cancel();
});

test('F8: a reservation restored from Activity blocks the first build', async () => {
  const m = depositModule();
  const { client } = await readyClient(m.extend);
  const account = new EvmAccount({ client, fingerprint: FINGERPRINT, reservations: () => [{ hash: '9'.repeat(128), expiryHeight: '1090' }] });
  assert.equal(account.waiting(), true);
  await assert.rejects(account.deposit(1000n), /still waiting/);
  assert.equal(m.builds.length, 0);
});

test('F9: a malformed estimate is refused before anything is built', async () => {
  const good = { s: '1', o: '', gu: '50000', h: '1000', ge: '50000', ue: '60000', fe: '7260000' };
  for (const bad of [{ gu: '60000' }, { ge: '30000001', gu: '1' }, { ge: '0', gu: '0' }]) {
    const m = depositModule({ estimate: { ...good, ...bad } });
    const { client } = await readyClient(m.extend);
    const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
    await assert.rejects(account.prepare({ op: 'call', to: 'cd'.repeat(32), data: Uint8Array.of(1, 2, 3, 4) }), /estimate for this transaction is malformed/, JSON.stringify(bad));
    assert.equal(m.builds.length, 0);
  }
});

test('F9: a built fee above the local limit is refused; one at the limit is offered', async () => {
  for (const [fee, ok] of [[EVM_MAX_FEE_RAW + 1n, false], [EVM_MAX_FEE_RAW, true]]) {
    const m = depositModule({ fee: fee.toString() });
    const { client, mock } = await readyClient(m.extend);
    mock.state.coins = [coin(4, '9000000000')];
    mock.state.total = mock.state.spendable = '9000000000';
    const account = new EvmAccount({ client, fingerprint: FINGERPRINT });
    if (ok) (await account.deposit(1000n)).cancel();
    else await assert.rejects(account.deposit(1000n), /above this wallet's limit/);
  }
});

test("F11: the computed CREATE address travels only on a CREATE; createdCheck compares it with the receipt's", () => {
  const built = created => ({
    envelope: Uint8Array.of(1), intentId: '1'.repeat(128),
    decoded: {
      op: 'create', chainId: CHAIN_ID, inputs: ['2'.repeat(128)], to: '', valueWei: '00'.repeat(32), gasLimit: '100000', nonce: '0',
      units: '1', amount: '', dest: '', ticketId: '', dataLength: 2, fee: '1', change: '0', expiryHeight: '1090', ...(created === undefined ? {} : { created })
    }
  });
  assert.equal(decodeEvmBuilt(built('ee'.repeat(32))).created, 'ee'.repeat(32));
  assert.equal(decodeEvmBuilt(built(undefined)).created, null, 'a module without the export');
  assert.equal(decodeEvmBuilt(built('')).created, null);
  assert.throws(() => decodeEvmBuilt(built('EE'.repeat(32))), /invalid transaction/);
  const call = built('ee'.repeat(32));
  Object.assign(call.decoded, { op: 'call', to: 'cd'.repeat(32) });
  assert.throws(() => decodeEvmBuilt(call), /invalid transaction/, 'a created address on a call');
  const ok = { op: 2, success: true, created: 'ee'.repeat(32) };
  assert.equal(createdCheck(ok, 'ee'.repeat(32)), 'match');
  assert.equal(createdCheck(ok, 'ff'.repeat(32)), 'mismatch');
  assert.equal(createdCheck({ ...ok, created: null }, 'ee'.repeat(32)), 'mismatch', 'a successful CREATE with no address');
  assert.equal(createdCheck(ok, null), 'unchecked');
  assert.equal(createdCheck({ ...ok, success: false, created: null }, 'ee'.repeat(32)), 'none');
  assert.equal(createdCheck({ op: 1, success: true, created: null }, null), 'none');
});

// ── red-team 1 F4: evm_logs is a bounded cursor scan ────────────────────
// (nodus_witness_handlers.c handle_evm_logs; the C SDK's page check
// nodus_client.c evm_dec_logs + evm_logs_page_check is the reference)
const LG = (h, x, li) => ({ h, x, li, a: ADDR, t: [], d: '', i: '9'.repeat(128) });
const Q = { fh: ['u', '10'], th: ['u', '20'], lim: ['u', '3'] };

test('evm_logs cursor request: "c" = [h, x, li] crosses tagged; out of range never reaches the module', async () => {
  const seen = [];
  const { client } = await readyClient(mock => {
    mock.module.evmQuery = async request => {
      seen.push(request);
      return seen.length === 1 ? { logs: [LG('10', '0', '0')], more: true, c: ['15', '3', '0'] } : { logs: [], more: false };
    };
  });
  const first = await client.evmLogs({ fromHeight: '10', toHeight: '20', limit: '5' });
  assert.deepEqual(first.cursor, { height: 15n, index: 3n, logIndex: 0n });
  // the reply's cursor, handed back as decimal strings, resumes the scan
  const c = first.cursor;
  const second = await client.evmLogs({ fromHeight: '10', toHeight: '20', limit: '5', cursor: { height: String(c.height), index: String(c.index), logIndex: String(c.logIndex) } });
  assert.deepEqual(second, { logs: [], more: false, cursor: null });
  assert.deepEqual(seen[1], { method: 'evm_logs', args: { fh: ['u', '10'], th: ['u', '20'], lim: ['u', '5'], c: ['U', ['15', '3', '0']] } });
  // the bounds: fh <= h <= th, x / li <= 2^32 (nodus.h NODUS_EVM_LOGS_CURSOR_POS_MAX)
  await client.evmLogs({ fromHeight: '10', toHeight: '20', cursor: { height: '20', index: '4294967296', logIndex: '4294967296' } });
  assert.deepEqual(seen[2].args.c, ['U', ['20', '4294967296', '4294967296']]);
  await client.evmLogs({ fromHeight: '10', toHeight: '20', cursor: { height: '10', index: '0', logIndex: '0' } });
  assert.deepEqual(seen[3].args.c, ['U', ['10', '0', '0']]);
  const before = seen.length;
  const base = { fromHeight: '10', toHeight: '20' };
  for (const cursor of [
    { height: '9', index: '0', logIndex: '0' }, { height: '21', index: '0', logIndex: '0' },
    { height: '15', index: '4294967297', logIndex: '0' }, { height: '15', index: '0', logIndex: '4294967297' },
    { height: '15', index: '0' }, { height: 15, index: '0', logIndex: '0' }, { height: '015', index: '0', logIndex: '0' },
    { height: '18446744073709551616', index: '0', logIndex: '0' }, '15:0:0', null, ['15', '0', '0']
  ]) {
    await assert.rejects(client.evmLogs({ ...base, cursor }), /Invalid cursor/, JSON.stringify(cursor));
  }
  assert.equal(seen.length, before);
});

test('evm_logs page: taken exactly when the C SDK takes it', () => {
  // an empty page that stopped before th: more + c, zero logs
  assert.deepEqual(parseLogs({ logs: [], more: true, c: ['12', '0', '0'] }, Q), { logs: [], more: true, cursor: { height: 12n, index: 0n, logIndex: 0n } });
  // the last page: no c
  const last = parseLogs({ logs: [LG('10', '0', '0'), LG('10', '0', '1'), LG('20', '4294967295', '0')], more: false }, Q);
  assert.equal(last.cursor, null);
  assert.deepEqual(last.logs.map(l => [l.height, l.index, l.logIndex]), [[10n, 0n, 0n], [10n, 0n, 1n], [20n, 4294967295n, 0n]]);
  // "c" exactly when more
  assert.throws(() => parseLogs({ logs: [], more: false, c: ['12', '0', '0'] }, Q), /cursor/);
  assert.throws(() => parseLogs({ logs: [], more: true }, Q), /cursor/);
  assert.throws(() => parseLogs({ logs: [], more: true }), /cursor/, 'without the request too');
  // the cursor's shape: [h, x, li], x / li <= 2^32
  for (const c of [['12', '0'], ['12', '0', '0', '0'], ['12', '4294967297', '0'], ['12', '0', '4294967297'], ['12', '0', -1], '12,0,0', { h: '12' }, null]) {
    assert.throws(() => parseLogs({ logs: [], more: true, c }, Q), /cursor/, JSON.stringify(c));
  }
  assert.equal(parseLogs({ logs: [], more: true, c: ['20', '4294967296', '4294967296'] }, Q).cursor.index, 4294967296n);
  // the cursor strictly after the last returned log
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '0')], more: true, c: ['12', '1', '0'] }, Q), /cursor/, 'cursor at the last log');
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '0')], more: true, c: ['12', '0', '5'] }, Q), /cursor/, 'cursor behind the last log');
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '0')], more: true, c: ['11', '9', '9'] }), /cursor/, 'behind the last log, no request');
  assert.equal(parseLogs({ logs: [LG('12', '1', '0')], more: true, c: ['12', '1', '1'] }, Q).cursor.logIndex, 1n);
  // logs strictly increasing in (h, x, li)
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '0'), LG('12', '0', '5')], more: false }, Q), /order/);
  assert.throws(() => parseLogs({ logs: [LG('13', '0', '0'), LG('12', '9', '9')], more: false }, Q), /order/);
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '0'), LG('12', '1', '0')], more: false }, Q), /order/, 'a repeated log');
  assert.throws(() => parseLogs({ logs: [LG('12', '1', '1'), LG('12', '1', '0')], more: false }), /order/, 'without the request too');
  // against the request: [fh, th], at most lim
  assert.throws(() => parseLogs({ logs: [LG('9', '0', '0')], more: false }, Q), /range/);
  assert.throws(() => parseLogs({ logs: [LG('21', '0', '0')], more: false }, Q), /range/);
  assert.throws(() => parseLogs({ logs: [LG('10', '0', '0'), LG('10', '0', '1'), LG('10', '0', '2'), LG('10', '0', '3')], more: false }, Q), /logs/);
  assert.throws(() => parseLogs({ logs: [], more: true, c: ['21', '0', '0'] }, Q), /cursor/, 'cursor past th');
  assert.throws(() => parseLogs({ logs: [], more: true, c: ['9', '0', '0'] }, Q), /cursor/, 'cursor before fh');
  // a resumed scan: nothing before the request's cursor; the reply's
  // cursor not behind it (equal is what the SDK accepts)
  const QC = { ...Q, c: ['U', ['15', '2', '0']] };
  assert.throws(() => parseLogs({ logs: [LG('15', '1', '9')], more: false }, QC), /range/);
  assert.equal(parseLogs({ logs: [LG('15', '2', '0')], more: false }, QC).logs.length, 1);
  assert.throws(() => parseLogs({ logs: [], more: true, c: ['15', '1', '0'] }, QC), /cursor/);
  assert.deepEqual(parseLogs({ logs: [], more: true, c: ['15', '2', '0'] }, QC).cursor, { height: 15n, index: 2n, logIndex: 0n });
});

// A stand-in for the Emscripten glue: every export answers 0 / "", the
// query buffer is at a fixed place, the query reply is "{}".
function stubGlue() {
  const calls = [], HEAPU8 = new Uint8Array(1 << 16), AT = 1024;
  const M = {
    HEAPU8,
    ccall(name, ret, types, args) {
      // the query text is read NOW: the buffer is reused by the next call
      calls.push([name, name === 'nsw_evm_query' ? [args[0], new TextDecoder().decode(HEAPU8.subarray(AT, AT + args[1]))] : args]);
      if (name === 'nsw_evm_query_buf') return AT;
      if (ret === 'string') return name === 'nsw_evm_query_json' ? '{}' : '';
      return 0;
    }
  };
  const sent = () => calls.filter(([name]) => name === 'nsw_evm_query').map(([, pair]) => pair);
  return { sent, loadGlue: async () => ({ default: async () => M }) };
}

test('send-module evmQuery: the U tag (1..3 u64) is written as key=U:a,b,c; anything else never reaches the module', async () => {
  const glue = stubGlue();
  const mod = await createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: glue.loadGlue });
  await mod.evmQuery({ method: 'evm_logs', args: { fh: ['u', '1'], c: ['U', ['15', '2', '4294967296']] } });
  await mod.evmQuery({ method: 'evm_logs', args: { c: ['U', ['0']] } });
  await mod.evmQuery({ method: 'evm_logs', args: { c: ['U', ['18446744073709551615', '0']] } });
  assert.deepEqual(glue.sent(), [['evm_logs', 'fh=u:1;c=U:15,2,4294967296'], ['evm_logs', 'c=U:0'], ['evm_logs', 'c=U:18446744073709551615,0']]);
  for (const tagged of [['U', []], ['U', ['1', '2', '3', '4']], ['U', ['01']], ['U', ['18446744073709551616']], ['U', ['']], ['U', ['1,2']],
    ['U', ['1', 2]], ['U', '1,2,3'], ['U', [1]], ['U', ['-1']], ['U', ['1'], 'x'], ['u', ['1']], ['b', ['00']]]) {
    await assert.rejects(mod.evmQuery({ method: 'evm_logs', args: { c: tagged } }), /Invalid smart-contract request/, JSON.stringify(tagged));
  }
  assert.equal(glue.sent().length, 3);
});
