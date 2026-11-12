import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, phrase, password, account, token, payTo, BOT, foundationNodus, nodusSignature } from './swap-fixture.js';
import { nodusToUsdtText } from '../src/background/swap-texts.js';
import { SWAP_METHODS } from '../src/constants/swap.js';
import { DEBUG_LOG_PREFIX, debugLog, errorFields, hostOf, onDebugLine, setDebugLogSink, timed } from '../../src/debug-log.js';
import { rpcFetch } from '../../src/rpc-transport.js';

// Environment: Node >=22.14, the swap fixture (stub Ethereum RPC, stub bot, mock Nodus module); no flags, no network,
// no files. The sink of the debug logger is replaced by a list for the test and put back afterwards.

// Proves the logger's structural limits: only scalar values are written (an error, a byte array, an object and a
// function become a type word), a field whose name says it holds a secret is dropped, errorFields gives code and
// class name and never the message, and hostOf gives the host only. Could falsely pass if the sink were not the one
// the logger calls; the first assertion checks that a line arrived with the prefix.
test('the debug logger writes scalars only, drops secret-named fields and never an error message', () => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line));
  try {
    const error = Object.assign(new Error('secret words abandon abandon'), { code: 4001 });
    debugLog('test', 'event', { id: 7, ms: 12.345, ok: true, error, bytes: new Uint8Array([1, 2, 3]), nested: { a: 'leak' }, fn() {}, seed: 'leak', password: 'leak', signature: 'leak', text: 'leak', ...errorFields(error) });
    debugLog('test', 'url', { host: hostOf('https://user:pw@rpc.example:8545/path?key=leak') });
  } finally { restore(); }
  assert.equal(lines.length, 2); assert.ok(lines[0].startsWith(`${DEBUG_LOG_PREFIX} `));
  assert.match(lines[0], / test event id=7 ms=12.35 ok=true error=\[object\] bytes=\[object\] nested=\[object\] fn=\[function\] outcome=error code=4001 name=Error$/);
  assert.ok(!lines.join('\n').includes('leak') && !lines.join('\n').includes('abandon'));
  assert.match(lines[1], / test url host=rpc.example:8545$/);
});

// Proves that a Nodus hold, a signed NODUS -> USDT request and a signed USDT -> NODUS request with its USDT payment,
// all driven through the real background with the fixture stubs, write the expected events, and that none of the lines
// contains the test seed words, the password, any signature, the signed texts, the typed-data fields, the signed
// transaction or the full RPC or bot URL. Could falsely pass if the sink saw no lines (the expected-event checks
// would then fail) or if a secret were written in a form not on the list (hex of a signature is checked both bare and
// prefixed; a transformed copy would not be found).
test('debug lines cover a hold, a signed swap request and an EVM payment, and carry no secret', async t => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line)); t.after(restore);
  const f = await setup(t), remote = f.site();
  await f.connectEthereum(remote); const nodusAccount = await f.connectNodus(remote);
  // A hold, then the text of NODUS -> USDT signed, posted, and the held transfer sent.
  const holding = remote.request(SWAP_METHODS.holdTransfer, [{ account: nodusAccount.address, to: foundationNodus, amount: '200000000' }]);
  await f.walk(holding, ['nodus_swapPayment']); const held = (await holding).result;
  const text = nodusToUsdtText({ sender: nodusAccount.address, destination: account.toLowerCase(), amount: 200000000n, minimumToReceive: 4950000n,
    transferId: held.transferId, chainId: held.chainId, requestNumber: '123456789' });
  const sending = remote.request(SWAP_METHODS.sendNodusToUsdt, [{ holdId: held.holdId, botUrl: BOT, text }]);
  await f.walk(sending, ['nodus_signMessage']); assert.equal((await sending).error, undefined);
  // USDT -> NODUS: typed request signed, posted, USDT payment approved and broadcast.
  const destination = 'ef'.repeat(64);
  const swapping = remote.request(SWAP_METHODS.sendUsdtToNodus, [{ from: account, botUrl: BOT, token, payTo, destination, amount: '25000000', minimumToReceive: '240000000000', requestNumber: '123456789' }]);
  await f.walk(swapping, ['eth_signTypedData', 'nodus_swapPayment']); const paid = await swapping; assert.equal(paid.error, undefined);

  const joined = lines.join('\n');
  for (const expected of ['request done', 'approvals added','nodus-hold started', 'nodus-hold approval-shown', 'nodus-hold approval-approved', 'nodus-hold stored',
    'nodus-prepare balance', 'nodus-prepare build-and-sign', 'swap signature-asked', 'swap signature-given', 'swap delivery', 'swap payment-sent', 'evm approval-approved',
    'evm fee-reads', 'evm transaction-sent', 'rpc call', 'lock unlocked', 'worker start']) {
    assert.ok(lines.some(line => line.includes(` ${expected}`)), `missing event: ${expected}`);
  }
  assert.ok(lines.every(line => line.startsWith(`${DEBUG_LOG_PREFIX} `)));
  assert.ok(lines.some(line => line.includes('swap delivery') && line.includes('host=swap.nodusnetwork.io') && line.includes('path=/amm/swap') && line.includes('status=200')));
  assert.ok(lines.some(line => line.includes('rpc call') && line.includes('method=eth_sendRawTransaction')));
  const ethSignature = f.botCalls.find(call => call.body.kind === 'usdt_to_nodus').body.signature;
  const secrets = { 'seed words': phrase, 'first seed words': 'abandon abandon', password, 'nodus signature': nodusSignature, 'ethereum signature': ethSignature.replace(/^0x/, ''),
    'signed text': text, 'signed text hex': Buffer.from(text).toString('hex'), 'typed field name': 'Nodus Swap', 'typed destination': destination, 'typed amount': '"amount"',
    'signed transaction': f.raw[0].replace(/^0x/, ''), 'bot url': `${BOT}/amm`, 'rpc path or key': '/v3/', 'nodus public key': '12'.repeat(40) };
  for (const [name, secret] of Object.entries(secrets)) assert.ok(!joined.includes(secret), `a debug line contains the ${name}`);
});

// Proves a property read done only for a log line never changes the result: an error whose code and name getters throw
// still gives a line (without code and name) and timed() rethrows that very error. Could falsely pass if the getters were
// not reached; the throw counters guard that.
test('a throwing error property does not change what timed rethrows', async () => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line)); let reads = 0;
  const error = new Error('x'); for (const key of ['code', 'name']) Object.defineProperty(error, key, { get() { reads++; throw new Error('getter'); } });
  try {
    await assert.rejects(timed('test', 'work', {}, async () => { throw error; }), caught => caught === error);
  } finally { restore(); }
  assert.ok(reads >= 2); assert.equal(lines.length, 1); assert.match(lines[0], / test work ms=\d+ outcome=error$/);
});

// Proves what a web page chooses cannot reach a request line as free text: a string id and an unknown method carrying
// marker text appear nowhere in the lines, which show a fixed form instead. Could falsely pass if the request never
// reached the logging middleware; the fixed-form 'request done' line is asserted.
test('a page-chosen request id and method are written in a fixed form only', async t => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line)); t.after(restore);
  const f = await setup(t), { engine } = f.background.engine.setupProviderEngineEip1193({ origin: 'https://site.example', subjectType: 'website' });
  t.after(() => engine.destroy());
  await engine.handle({ id: 'MARKER-ID-31337 text to sign', jsonrpc: '2.0', method: 'x_MARKER_METHOD_31337', params: [] });
  await engine.handle({ id: 7, jsonrpc: '2.0', method: 'eth_chainId', params: [] });
  const joined = lines.join('\n');
  assert.ok(!joined.includes('MARKER'), 'page text reached a debug line');
  assert.ok(lines.some(line => / request done /.test(line) && line.includes('method=other') && line.includes('id=string')));
  assert.ok(lines.some(line => / request done /.test(line) && line.includes('method=eth_chainId') && line.includes('id=7')));
});

// Proves building the line (spreading the fields) cannot replace the outcome: a fields object with a throwing getter
// still gives timed()'s own result on success and its own rejection on failure. Could falsely pass if the getter were not
// reached; the read counter guards that.
test('a throwing field getter does not change what timed returns or rethrows', async () => {
  const restore = setDebugLogSink(() => {}); let reads = 0;
  const fields = { get bad() { reads++; throw new Error('getter'); } };
  try {
    assert.equal(await timed('test', 'work', fields, async () => 'result'), 'result');
    const error = new Error('own');
    await assert.rejects(timed('test', 'work', fields, async () => { throw error; }), caught => caught === error);
  } finally { restore(); }
  assert.equal(reads, 2);
});


// Proves the listener hook of the debug logger: a listener is called with the area, the event and the finished line AFTER the
// sink has taken it (so the console output is unchanged), a listener that throws changes nothing for the caller or the other
// listeners, and the returned remover stops it. Could falsely pass if the listener were called before the sink: the order is
// asserted from one shared list.
test('a debug-line listener is called after the sink, a throwing listener changes nothing, and it can be removed', () => {
  const order = []; const restore = setDebugLogSink(line => order.push(['sink', line]));
  const stopBad = onDebugLine(() => { throw new Error('listener broke'); });
  const stop = onDebugLine(({ area, event, line }) => order.push(['listener', area, event, line]));
  try {
    debugLog('area', 'one', { id: 1 });
    stop(); stopBad(); debugLog('area', 'two', { id: 2 });
  } finally { restore(); }
  assert.equal(order.length, 3);
  assert.equal(order[0][0], 'sink'); assert.deepEqual(order[1].slice(0, 3), ['listener', 'area', 'one']); assert.equal(order[1][3], order[0][1]);
  assert.equal(order[2][0], 'sink', 'after removal only the sink sees the next line');
});

// Proves, through the real background and the real rpcFetch: a FAILED RPC call (a refused connection, and an HTTP 503) adds exactly
// one 'net' error line to the background session log (the log the extension's copied log merges) with the host, the method, the
// duration and the error name or HTTP status exactly as the debug line has them; a successful call adds nothing; the debug line
// still reaches the sink; no logged line holds "https://", the URL path, the address or any parameter of the call; the session
// log is empty after lock. The line text is the debug line without its "nodus-debug <time>" prefix, so no second formatter exists.
// Note: the session log's scrubbing turns digits-dot-digits into '#', so an IP-literal host would be shown scrubbed; all our RPC
// hosts are domain names. Could falsely pass if the fixture's own calls wrote 'net' rpc lines: the test counts only lines of the
// test host, and the success case asserts the count stays 1.
test('a failed RPC call writes one net line to the background session log; a success writes none', async t => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line)); t.after(restore);
  const f = await setup(t), address = '0x' + '11'.repeat(20);
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [address, 'latest'] });
  const call = fetcher => rpcFetch('https://rpc.example.test/v1/pathleak', { method: 'POST', body }, { fetcher });
  const netLines = () => f.background.nodus.getSessionLog().entries.filter(line => line.category === 'net' && line.text.includes('rpc.example.test'));
  await call(async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x0' })));
  assert.deepEqual(netLines(), [], 'a successful call writes nothing');
  await assert.rejects(call(async () => { throw new TypeError('fetch failed'); }));
  assert.equal(netLines().length, 1); assert.equal(netLines()[0].error, true);
  assert.match(netLines()[0].text, /^rpc call host=rpc\.example\.test method=eth_getBalance ms=\d+ outcome=error name=TypeError$/);
  await call(async () => new Response('{}', { status: 503 }));
  assert.equal(netLines().length, 2); assert.match(netLines()[1].text, /^rpc call host=rpc\.example\.test method=eth_getBalance ms=\d+ status=503 outcome=error$/);
  assert.equal(lines.filter(line => line.includes('rpc call host=rpc.example.test')).length, 3, 'the sink still gets every line');
  for (const entry of f.background.nodus.getSessionLog().entries) for (const secret of ['https://', 'pathleak', address, 'latest', 'fetch failed']) assert.ok(!entry.text.includes(secret), `${secret} in ${entry.text}`);
  await f.background.lock();
  assert.deepEqual(f.background.nodus.getSessionLog().entries, [], 'cleared on lock');
});

// Proves the sink gets the same bytes with and without a listener: the prefix "nodus-debug ", the ISO time, area, event and the
// fields in the order they were passed, compared literally for an rpc call line and a failed one (the lines other tools read
// from the console). Time is pinned with a mocked Date. Could falsely pass if the expected text were copied from a changed
// layout: it is written out here by hand, field by field, as the line looked before onDebugLine existed.
test('the sink receives the literal same line with and without a listener', t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-11-12T10:20:30.456Z') });
  const run = () => {
    const lines = []; const restore = setDebugLogSink(line => lines.push(line));
    try {
      debugLog('rpc', 'call', { host: 'rpc.example.test', method: 'eth_chainId', ms: 5, status: 200, outcome: 'ok' });
      debugLog('rpc', 'call', { host: 'rpc.example.test', method: 'eth_getBalance', ms: 15000, ...errorFields(Object.assign(new Error('x'), { name: 'TimeoutError' })) });
    } finally { restore(); }
    return lines;
  };
  const expected = [
    'nodus-debug 2026-11-12T10:20:30.456Z rpc call host=rpc.example.test method=eth_chainId ms=5 status=200 outcome=ok',
    'nodus-debug 2026-11-12T10:20:30.456Z rpc call host=rpc.example.test method=eth_getBalance ms=15000 outcome=error name=TimeoutError',
  ];
  assert.deepEqual(run(), expected);
  const stop = onDebugLine(() => {});
  try { assert.deepEqual(run(), expected); } finally { stop(); }
});
