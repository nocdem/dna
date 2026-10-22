// A busy node (web 0.1.119). nodus 0.26.1 answers a session over its chain
// budget NODUS_ERR_RATE_LIMITED (4) and forwards nothing
// (nodus/docs/ARCHITECTURE.md §5 "Client port front door"); the module
// turns that into the "network is busy" text and a busy mark
// (crypto/nodus-send-wasm.c nsw_fail_rc / nsw_error_busy, connect/nc_wasm.c
// fail_rc / nc_error_busy). These tests prove the JavaScript side: the mark
// reaches the Error as `busy` from the module's getter (never from the
// text), it passes through the client's queue, the session stays ready, and
// the same user action succeeds once the node answers again. The C mapping
// itself (rc 4 -> text + mark, other rcs unchanged) is pinned in
// test/nodus-send-wasm.test.js "busy:" (parity build).
// NOT covered here (DOM wiring, no unit seam): the Messages check round's
// "checked again on the next round" note (src/connect/ui/messages.js sync)
// and the account-history read that keeps its page (src/app.js
// loadNodusHistory) — those are absent coverage, not passes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNodusClient, isNodusBusy, NODUS_BUSY_TEXT } from '../src/nodus/client.js';
import { createNodusSendModule, NODUS_SEND_NETWORK } from '../src/nodus/send-module.js';
import { createNodusConnectCore } from '../src/connect/core.js';
import { prepareTransfer } from '../src/wallet.js';
import { createMockNodusModule, FINGERPRINT, RECIPIENT, BUSY_TEXT, busyError, NODUS_NATIVE } from './nodus-mock-module.js';

const BALANCE_TEXT = 'Balance unavailable (rc=6).';

// A stand-in for the Emscripten glue: nsw_balance fails with the text and
// mark the test chooses; every other export answers 0 / "".
function failingGlue({ text, busy }) {
  const M = {
    HEAPU8: new Uint8Array(1 << 16),
    ccall(name, ret) {
      if (name === 'nsw_balance') return -1;
      if (name === 'nsw_error') return text;
      if (name === 'nsw_error_busy') return busy;
      return ret === 'string' ? '' : 0;
    }
  };
  return async () => ({ default: async () => M });
}

test('busy: the texts agree, and isNodusBusy reads only the mark', () => {
  assert.equal(NODUS_BUSY_TEXT, BUSY_TEXT);
  assert.equal(isNodusBusy(busyError()), true);
  assert.equal(isNodusBusy(new Error(NODUS_BUSY_TEXT)), false, 'the English text alone is not the mark');
  assert.equal(isNodusBusy(Object.assign(new Error('x'), { busy: 1 })), false);
  for (const value of [undefined, null, 'busy', {}]) assert.equal(isNodusBusy(value), false);
});

test('busy: send-module failure() marks the Error from nsw_error_busy; another failure keeps its own text, unmarked', async () => {
  const busy = await createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: failingGlue({ text: NODUS_BUSY_TEXT, busy: 1 }), startIndex: 0 });
  const e1 = await busy.balance().then(() => null, error => error);
  assert.ok(e1 instanceof Error);
  assert.equal(e1.message, NODUS_BUSY_TEXT);
  assert.equal(e1.busy, true);
  assert.equal(isNodusBusy(e1), true);
  const plain = await createNodusSendModule(NODUS_SEND_NETWORK, { loadGlue: failingGlue({ text: BALANCE_TEXT, busy: 0 }), startIndex: 0 });
  const e2 = await plain.balance().then(() => null, error => error);
  assert.equal(e2.message, BALANCE_TEXT);
  assert.equal(e2.busy, undefined);
  assert.equal(isNodusBusy(e2), false);
});

// A fake wallet client for src/connect/core.js (the shape of
// test/connect-core.test.js fakeNodus): nc_request_withdraw fails, nc_error
// and nc_error_busy answer what the test chose.
function connectFake({ text, busy }) {
  let last;
  const api = {
    num: name => { last = name; if (name === 'nc_words_alloc') return 64; if (name === 'nc_error_busy') return busy; return 0; },
    call: async name => { last = name; return name === 'nc_request_withdraw' ? -1 : 0; },
    str: name => (name === 'nc_error' ? text : name === 'nc_result' ? JSON.stringify(last === 'nc_unlock' ? { fingerprint: FINGERPRINT, fresh: false } : {}) : ''),
    heap: () => new Uint8Array(4096)
  };
  return {
    state: 'ready', fingerprint: FINGERPRINT, localConnectable: true,
    connect: async run => run(api), connectLocal: async run => run(api), connectSync: run => run(api)
  };
}

test('busy: a Messages send that met a busy node rejects with the busy text, marked from nc_error_busy', async () => {
  const core = createNodusConnectCore({ nodus: connectFake({ text: NODUS_BUSY_TEXT, busy: 1 }) });
  await core.unlock({ words: new TextEncoder().encode('alpha beta') });
  const error = await core.requestCancel(RECIPIENT).then(() => null, e => e);
  assert.equal(error.message, NODUS_BUSY_TEXT);
  assert.equal(isNodusBusy(error), true);
  const other = createNodusConnectCore({ nodus: connectFake({ text: 'Request was not withdrawn (-1).', busy: 0 }) });
  await other.unlock({ words: new TextEncoder().encode('alpha beta') });
  const plain = await other.requestCancel(RECIPIENT).then(() => null, e => e);
  assert.equal(plain.message, 'Request was not withdrawn (-1).');
  assert.equal(isNodusBusy(plain), false);
});

async function readyClient() {
  const mock = createMockNodusModule();
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 7, clearInterval: () => {} });
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  return { mock, client };
}

test('busy, background read: the mark passes the queue, the session stays ready, the next round reads normally', async () => {
  const { mock, client } = await readyClient();
  mock.state.busy.add('balance');
  const error = await client.balance().then(() => null, e => e);
  assert.equal(isNodusBusy(error), true);
  assert.equal(error.message, BUSY_TEXT);
  // Transient: no session drop (only NODUS_SESSION_LOST_TEXT does that),
  // nothing queued behind it is refused.
  assert.equal(client.state, 'ready');
  mock.state.busy.delete('balance');
  assert.deepEqual(await client.balance(), { total: mock.state.total, spendable: mock.state.spendable });
  client.lock();
});

test('busy, user action: Review build shows the busy text, nothing is built or held, the same request succeeds when pressed again', async () => {
  const { mock, client } = await readyClient();
  const wallet = { addresses: { nodus: FINGERPRINT }, nodusClient: client };
  const request = { wallet, chain: 'nodus', symbol: 'NODUS', asset: NODUS_NATIVE, to: RECIPIENT, amount: '1' };
  mock.state.busy.add('list');
  const error = await prepareTransfer(request).then(() => null, e => e);
  assert.equal(error.message, BUSY_TEXT, 'the user sees the busy text as it is');
  assert.equal(isNodusBusy(error), true);
  assert.equal(mock.state.lastBuild, null, 'nothing was built');
  assert.equal(client.state, 'ready');
  mock.state.busy.delete('list');
  const transfer = await prepareTransfer(request);
  assert.equal(transfer.to, RECIPIENT);
  assert.equal(mock.state.lastBuild.to, RECIPIENT);
  transfer.cancel();
  client.lock();
});
