// Loader and call discipline for the NODUS send module — package (c3) of
// docs/plans/2026-09-25-web-wallet-nodus-send-design.md (§0a.3 "(d)", §1.5).
// The module itself (C→WASM: nodus tier-2 client + SPEND builder) is NOT built
// yet; src/nodus/send-module.js is its registration point and holds `null`
// until (c3) lands, so nothing in this file runs on the live site today.
//
// MODULE CONTRACT — what (c3)'s JS glue must return from its factory:
//
//   factory() -> Promise<module>, where module has
//
//   Asynchronous operations (may suspend inside the module through Asyncify;
//   this client never has two of them running at once, see "queue" below):
//     unlock({ seed })           seed: Uint8Array(32), the ML-DSA-87 signing
//                                seed (src/nodus/derive.js nodusSigningSeed).
//                                The glue copies it into module memory, builds
//                                the identity, opens the tier-2 session over
//                                wss:// and checks the chain id pinned in its
//                                own build. Resolves { fingerprint: 128 lower-
//                                case hex, chainId: 64 lowercase hex }.
//     balance()                  Own native-token balance (dnac_balance).
//                                Resolves { total, spendable } — raw-unit
//                                decimal integer strings (1 NODUS = 10^8).
//                                Must reject on any read error, never resolve 0.
//     list()                     Own coins (dnac_utxo). Resolves { tip, coins:
//                                [{ nullifier: 128 hex, amount }], truncated }
//                                — tip and amounts raw decimal strings; tip is
//                                the block_height the node reported ("0" is
//                                passed through, the wallet refuses it).
//     buildAndSign({ to, amount, expiryHeight, coins })
//                                Builds and signs one CORE SPEND envelope from
//                                the candidate `coins` only (the wallet has
//                                already removed coins locked by pending sends).
//                                Resolves { envelope: Uint8Array, intentId: 128
//                                hex, decoded: { recipient, amount, fee, change,
//                                expiryHeight, chainId, inputs: [nullifier] } }
//                                where `decoded` is read back FROM THE ENVELOPE
//                                BYTES, never echoed from the request (G1).
//     submit({ envelope })       dnac_spend. Resolves { accepted: boolean,
//                                message?: string } (mempool CheckTx only).
//     scanConfirm({ intentId, fromHeight, toHeight })
//                                dnac_v3_block scan for an applied element with
//                                this intent_id. Resolves { tip, found,
//                                height? } (raw decimal strings); `found:
//                                false` must mean every block from fromHeight
//                                to min(tip, toHeight) was read and none holds
//                                it (a partial read rejects instead).
//     tick()                     Keepalive ping (the thread-less stand-in for
//                                nodus_client.c's 60 s read-thread ping; the
//                                server drops an idle session at 180 s).
//
//   Synchronous exports (MUST NOT reach emscripten_sleep: they are called while
//   another export may be suspended, and a second suspension would corrupt the
//   single Asyncify currData — emsdk libasync.js `currData`):
//     cancel()                   Sets the C-level cancel flag; a suspended call
//                                returns at its next wake-up.
//     lock()                     Closes the WebSocket / tier-2 session.
//     release()                  Drops the instance so that no pending wake-up
//                                resumes compiled code (Emscripten: set ABORT —
//                                libasync.js handleSleep's wake-up callback
//                                returns early when ABORT is set).
//     memory                     The module's WebAssembly.Memory.
//
// Amounts and heights cross the boundary only as decimal integer strings of raw
// units; the wallet converts them with BigInt (never Number).
//
// LOCK ORDER (§1.5): stop the queue -> cancel() -> lock() (WebSocket closed) ->
// zero the whole linear memory (src/nodus/derive.js deriveNodusAddress pattern)
// -> release(). Each step runs even if an earlier one throws, so a failing
// export can never skip the wipe.
const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/;
export const NODUS_TICK_MS = 60000;
const ASYNC_OPS = ['unlock', 'balance', 'list', 'buildAndSign', 'submit', 'scanConfirm', 'tick'];
const SYNC_OPS = ['cancel', 'lock', 'release'];
const lockedError = () => new Error('Wallet is locked.');

export function createNodusClient({ factory, onState, setInterval: every = globalThis.setInterval, clearInterval: stopEvery = globalThis.clearInterval } = {}) {
  if (typeof factory !== 'function') throw new Error('The Nodus send module is not available.');
  let module, state = 'idle', stopped = false, started = false, timer, inFlight, tickQueued = false, fingerprint, chainId;
  // ONE operation queue: Asyncify keeps a single global currData, so a second
  // export entered while the first is suspended corrupts the first. `tail`
  // settles only when the module call itself has returned, never merely when
  // its caller gave up waiting.
  let tail = Promise.resolve();
  const waiting = new Set();
  function setState(next) { if (state === next) return; state = next; onState?.(next); }
  function enqueue(op, args, { signal } = {}) {
    if (stopped || !module) return Promise.reject(lockedError());
    if (signal?.aborted) return Promise.reject(new Error('Request cancelled.'));
    const entry = {};
    const result = new Promise((resolve, reject) => { entry.resolve = resolve; entry.reject = reject; });
    waiting.add(entry);
    // A caller that stops waiting leaves the queue only if its call has not
    // started; a started call keeps the queue until the module returns.
    signal?.addEventListener('abort', () => { if (waiting.delete(entry)) entry.reject(new Error('Request cancelled.')); }, { once: true });
    const run = async () => {
      if (!waiting.delete(entry)) return;
      if (stopped || !module) { entry.reject(lockedError()); return; }
      inFlight = entry;
      try {
        const value = await module[op](args);
        if (stopped) throw lockedError();
        entry.resolve(value);
      } catch (error) { entry.reject(stopped ? lockedError() : error); }
      finally { if (inFlight === entry) inFlight = undefined; }
    };
    tail = tail.then(run);
    return result;
  }
  function ready() { if (state !== 'ready') throw new Error('Nodus connection is not ready.'); }
  function tick() {
    // One queued keepalive at most: a slow call must not pile ticks up behind it.
    if (tickQueued || state !== 'ready') return;
    tickQueued = true;
    enqueue('tick').catch(() => { if (!stopped) setState('error'); }).finally(() => { tickQueued = false; });
  }
  function lock() {
    stopped = true;
    if (timer !== undefined) { stopEvery(timer); timer = undefined; }
    // 1. Stop the queue: nothing queued will start, and nobody waits on the
    //    call in flight (its late result is discarded).
    for (const entry of waiting) entry.reject(lockedError());
    waiting.clear();
    inFlight?.reject(lockedError()); inFlight = undefined;
    const current = module; module = undefined; fingerprint = undefined; chainId = undefined;
    if (current) {
      try { current.cancel(); } catch { /* the wipe below must still run */ }
      try { current.lock(); } catch { /* the wipe below must still run */ }
      try { new Uint8Array(current.memory.buffer).fill(0); } catch { /* release below must still run */ }
      try { current.release(); } catch { /* nothing left to do */ }
    }
    setState('locked');
  }
  async function unlock({ seed, fingerprint: expected } = {}) {
    // Refusals that touch no module: a used client (ready, failed or locked)
    // stays exactly as it is.
    if (started || stopped) { if (seed instanceof Uint8Array) seed.fill(0); throw new Error('This Nodus connection was already used. Lock and reopen your wallet.'); }
    if (!(seed instanceof Uint8Array) || seed.length !== 32) { if (seed instanceof Uint8Array) seed.fill(0); throw new Error('Nodus signing seed must be 32 bytes.'); }
    if (typeof expected !== 'string' || !HEX128.test(expected)) { seed.fill(0); throw new Error('Nodus address is not available yet.'); }
    started = true;
    try {
      setState('connecting');
      const loaded = await factory();
      if (stopped) {
        // Locked while the module was loading: it is wiped and dropped unused.
        module = loaded; lock(); throw lockedError();
      }
      if (!loaded || ![...ASYNC_OPS, ...SYNC_OPS].every(name => typeof loaded[name] === 'function') || !(loaded.memory?.buffer instanceof ArrayBuffer)) {
        module = loaded; throw new Error('The Nodus send module does not match this wallet version.');
      }
      module = loaded;
      const info = await enqueue('unlock', { seed });
      if (!info || typeof info.fingerprint !== 'string' || !HEX128.test(info.fingerprint) || typeof info.chainId !== 'string' || !HEX64.test(info.chainId)) throw new Error('The Nodus send module returned an invalid identity.');
      // The module derives the identity from the seed on its own; it must be
      // the same address this wallet derived and shows (src/nodus/derive.js).
      if (info.fingerprint !== expected) throw new Error('The Nodus send module derived a different address. Nothing was connected.');
      fingerprint = info.fingerprint; chainId = info.chainId;
      timer = every(tick, NODUS_TICK_MS);
      setState('ready');
      return { fingerprint, chainId };
    } catch (error) {
      if (!stopped) { lock(); setState('error'); }
      throw error;
    } finally { seed.fill(0); }
  }
  const call = op => (args, options) => { try { ready(); } catch (error) { return Promise.reject(error); } return enqueue(op, args, options); };
  return {
    get state() { return state; },
    get fingerprint() { return fingerprint; },
    get chainId() { return chainId; },
    unlock,
    balance: (options) => call('balance')(undefined, options),
    list: (options) => call('list')(undefined, options),
    buildAndSign: call('buildAndSign'),
    submit: call('submit'),
    scanConfirm: call('scanConfirm'),
    lock
  };
}
