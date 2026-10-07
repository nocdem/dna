// The session log (src/session-log.js): a bounded, memory-only ring that is
// cleared on lock and never carries a secret, a full ID, an address, a
// quoted name or an amount; its filters; the connection-step lines the
// NODUS client's `steps` produce (attempt, duration, outcome, "stuck").
// What it proves: the pure module. It says nothing about the DOM view
// (mountSessionLogView) or about which app.js / messages.js call sites log.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionLog, scrubLogText, stepLog, logPageErrors, logFileName, groupedMs, SESSION_LOG_MAX, LOG_CATEGORIES } from '../src/session-log.js';

const fixedClock = () => {
  const clock = { at: Date.UTC(2026, 9, 7, 16, 2, 11) };
  clock.now = () => clock.at;
  return clock;
};
const SEED_HEX = 'ab'.repeat(32), FULL_ID = 'cd'.repeat(64), EVM = `0x${'1f'.repeat(20)}`, SOLANA = '9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin';
const WORDS = 'abandon ability able about above absent absorb abstract absurd abuse access accident';

test('the ring keeps at most SESSION_LOG_MAX lines, the newest ones', () => {
  assert.equal(SESSION_LOG_MAX, 500);
  const log = createSessionLog({ max: 5 });
  for (let i = 0; i < 12; i++) log.log('net', `line ${i}`);
  assert.equal(log.size, 5);
  assert.deepEqual(log.entries().map(e => e.text), ['line 7', 'line 8', 'line 9', 'line 10', 'line 11']);
  const big = createSessionLog();
  for (let i = 0; i < SESSION_LOG_MAX + 40; i++) big.log('wallet', `entry ${i}`);
  assert.equal(big.size, SESSION_LOG_MAX);
  assert.equal(big.entries()[0].text, 'entry 40');
});

test('clear() (run on lock) empties the log, its running steps, and starts a new session', () => {
  const clock = fixedClock();
  const log = createSessionLog({ now: clock.now });
  log.log('net', 'connected'); log.begin('net', 'connect', { label: 'attempt 1' });
  let changes = 0; log.subscribe(() => { changes++; });
  clock.at += 60000;
  log.clear();
  assert.equal(log.size, 0); assert.equal(log.text(), ''); assert.deepEqual(log.runningLines(), []);
  assert.equal(log.startedAt, clock.at);
  assert.equal(changes, 1, 'the view is told');
});

test('scrub: no seed hex, full ID, EVM or base58 address, quoted name or amount survives; a short ID prefix does', () => {
  const dirty = `seed ${SEED_HEX} id ${FULL_ID} to ${EVM} sol ${SOLANA} name "alice" sent 1.5 NODUS and 250 USDT, fee 0.0001; ID ${FULL_ID.slice(0, 8)}…${FULL_ID.slice(-4)}\u0007`;
  const clean = scrubLogText(dirty);
  for (const secret of [SEED_HEX, FULL_ID, EVM, SOLANA, 'alice', '1.5', '250', '0.0001', '\u0007']) assert.ok(!clean.includes(secret), `${secret} removed: ${clean}`);
  assert.match(clean, /ID cdcdcdcd…cdcd/, 'the short prefix used by the UI passes');
  assert.match(clean, /# NODUS/); assert.match(clean, /# USDT/);
  assert.ok(scrubLogText('x'.repeat(1000)).length <= 300);
  assert.equal(scrubLogText(new Error(`bad key ${SEED_HEX}`)), 'bad key …');
  // what the log keeps is scrubbed, whatever the caller passed
  const log = createSessionLog();
  log.log('send', `Transfer of 3 NODUS to ${FULL_ID} refused: CheckTx code 12: insufficient funds`, { error: true });
  const [entry] = log.entries();
  assert.equal(entry.text, 'Transfer of # NODUS to … refused: CheckTx code 12: insufficient funds');
  assert.equal(entry.error, true);
});

test('the export carries the header and every line, and no secret, full ID, recovery word or amount', () => {
  const clock = fixedClock();
  const log = createSessionLog({ now: clock.now });
  log.log('net', `attempt 1 · identify ok for ${FULL_ID}`);
  log.log('wallet', `Wallet open with "${WORDS}"`);
  log.log('send', `Sent 12.5 NODUS to ${EVM}`, { error: false });
  log.log('messages', `Messages closed: key ${SEED_HEX}`, { error: true });
  const text = log.exportText({ version: '0.1.70', page: 'connect', userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Test/1.0\nInjected' });
  assert.match(text, /^Nodus Connect session log\nVersion: 0\.1\.70\nPage: connect\nBrowser: Mozilla\/5\.0 \(X11; Linux x86_64\) Test\/1\.0 Injected\nSession start: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \(local time\)\n/);
  assert.match(text, /Only this session\. Nothing is sent automatically\./);
  for (const secret of [FULL_ID, SEED_HEX, EVM, '12.5', ...WORDS.split(' ')]) assert.ok(!text.includes(secret), `${secret} not exported`);
  assert.equal(text.split('\n').filter(line => /\[(net|wallet|send|messages)\]/.test(line)).length, 4);
  assert.match(log.exportText({ page: 'wallet' }), /^Nodus Wallet session log\n/);
  assert.equal(logFileName('connect', new Date(2026, 9, 7, 18, 2).getTime()), 'nodus-connect-log-20261007-1802.txt');
  assert.equal(logFileName('wallet', new Date(2026, 0, 2, 3, 4).getTime()), 'nodus-wallet-log-20260102-0304.txt');
});

test('filters: All / Network / Messages / Wallet / Errors', () => {
  const log = createSessionLog();
  log.log('net', 'net line'); log.log('messages', 'messages line'); log.log('send', 'send line');
  log.log('stake', 'stake line', { error: true }); log.log('vault', 'vault line'); log.log('ui-error', 'page error');
  log.log('bogus', 'unknown category');
  const texts = filter => log.entries(filter).map(e => e.text);
  assert.equal(texts('all').length, 7);
  assert.deepEqual(texts('network'), ['net line']);
  assert.deepEqual(texts('messages'), ['messages line']);
  assert.deepEqual(texts('wallet'), ['send line', 'stake line', 'vault line', 'unknown category']);
  assert.deepEqual(texts('errors'), ['stake line', 'page error']);
  assert.deepEqual(texts('no-such-filter'), texts('all'));
  assert.ok(LOG_CATEGORIES.includes('ui-error'));
  assert.match(log.text('errors'), /\[stake\] ! stake line/);
});

test('connection steps: "attempt N · step <ms> ok|failed|timed out", once; running and stuck lines past the bound', () => {
  const clock = fixedClock();
  const log = createSessionLog({ now: clock.now });
  let attempt = 2;
  const steps = stepLog(log, 'net', () => attempt, 30000);
  const ok = steps.begin('identify'); clock.at += 120; ok.end('ok');
  const failed = steps.begin('connect'); clock.at += 5012; failed.end('failed', new Error(`no node answered (${FULL_ID})`));
  attempt = 3;
  const hung = steps.begin('connect');
  clock.at += 12000;
  assert.match(log.text('network'), /attempt 3 · connect running 12 s$/);
  clock.at += 20000;
  assert.match(log.text('network'), /attempt 3 · connect running 32 s — stuck$/);
  assert.match(log.text('errors'), /running 32 s — stuck/, 'a stuck step shows under Errors');
  const timeout = Object.assign(new Error('The Nodus network did not answer within 30 seconds (step: connect).'), { timedOut: true, step: 'connect' });
  hung.end('timed out', timeout);
  hung.end('failed', new Error('Wallet is locked.')); // the late second end of an abandoned step is ignored
  assert.deepEqual(log.entries().map(e => [e.text, e.error]), [
    ['attempt 2 · identify 120 ms ok', false],
    ['attempt 2 · connect 5 012 ms failed (no node answered (…))', true],
    ['attempt 3 · connect timed out after 32 000 ms (The Nodus network did not answer within 30 seconds (step: connect).)', true]
  ]);
  assert.deepEqual(log.runningLines(), []);
  assert.equal(groupedMs(1234567), '1 234 567');
});

test('page errors: the message only; a throwing listener or a bad value never breaks the caller', () => {
  const log = createSessionLog();
  const handlers = {};
  logPageErrors({ addEventListener: (name, fn) => { handlers[name] = fn; } }, log);
  handlers.error({ message: `boom at ${FULL_ID}`, error: new Error('stack data') });
  handlers.unhandledrejection({ reason: new Error('rejected') });
  handlers.unhandledrejection({ reason: { secret: SEED_HEX } });
  assert.deepEqual(log.entries('errors').map(e => e.text), ['Page error: boom at …', 'Unhandled failure: rejected', 'Unhandled failure: unknown error']);
  log.subscribe(() => { throw new Error('view failed'); });
  assert.doesNotThrow(() => log.log('net', 'still logged'));
  assert.equal(log.entries().at(-1).text, 'still logged');
  assert.doesNotThrow(() => log.log('net', { toString() { throw new Error('bad value'); } }));
});
