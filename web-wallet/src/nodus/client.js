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
//     identify({ seed }) / connectNetwork()
//                                OPTIONAL (local-first open): the same
//                                unlock in two steps. identify builds the
//                                identity only — no session, nothing sent —
//                                and resolves like unlock; connectNetwork
//                                opens the session and checks the chain id.
//                                A connectNetwork failure may be retried;
//                                one whose error has `final: true` (the node
//                                serves another chain) may not. A module
//                                without both still unlocks (unlock()); this
//                                client then refuses identify().
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
//                                The same scan also finds an applied genesis
//                                claim whose created coin has this id (a
//                                claim's tracking id is that coin id).
//     claimStatus() / claimBuild() / claimSubmit({ bytes })
//                                OPTIONAL (0.1.26, genesis claim — shapes in
//                                src/nodus/send-module.js). A module without
//                                all three still unlocks; this client then
//                                answers every claim call "not available".
//     validators() / delegations() / stakeBuild({ ... }) + stakingRules
//                                OPTIONAL (0.1.29, staking — shapes in
//                                src/nodus/send-module.js), same rule.
//     connect(run) / connectSync(run)
//                                OPTIONAL (NC-4b, Messages — shapes in
//                                src/nodus/send-module.js), same rule. The
//                                Messages exports live in THIS module and use
//                                its session: connect() is queued like every
//                                other operation; connectSync() never
//                                suspends.
//     rulesetInfo()              HF-4: dnac_ruleset_info. Resolves { tip,
//                                generation, gen2Height } (decimal strings):
//                                the pinned rule-set generation whose tuple
//                                equals the node's answer, the answer's tip
//                                and "H" (0 = no switch committed). Must
//                                reject for an older node or an unknown
//                                generation ("this page is out of date").
//                                REQUIRED: without it nothing is built.
//     nameLookup({ name }) / nameOf({ owner }) / profileAddress({ owner, field })
//                                OPTIONAL (HF-4, chain names — shapes in
//                                src/nodus/send-module.js), same rule as
//                                the claim operations.
//     namePrices() / nameBuild({ name, expiryHeight, coins })
//                                OPTIONAL (HF-4, chain-name registration —
//                                shapes in src/nodus/send-module.js), its
//                                own group: a module without both still
//                                unlocks and still resolves names; this
//                                client then answers "registering is not
//                                available". The registration envelope is
//                                submitted with submit().
//     vaultCreate / vaultOpen / vaultBalance / vaultScan / vaultPropose /
//     vaultReview / vaultApprove / vaultSubmit
//                                OPTIONAL (shared vaults, general multisig —
//                                shapes in src/nodus/send-module.js), its own
//                                group, same rule as the claim operations.
//     evmBuild({ op, ... })      OPTIONAL (smart contracts, the EVM domain —
//                                shapes in src/nodus/send-module.js "SMART
//                                CONTRACTS"), its own group: builds and signs
//                                one [CORE EVMFUND] + [EVM op] envelope
//                                (design docs/plans/2026-10-04-nodus-evm-chain-
//                                integration-design.md rev 3 §2), submitted
//                                with submit().
//     evmQuery({ method, args }) OPTIONAL (smart contracts, design §18): one
//                                read RPC on this session. `method` is one of
//                                EVM_QUERY_METHODS; `args` maps each CBOR key
//                                to a tagged value ['b', lowercase hex] (byte
//                                string) or ['u', decimal] (unsigned). Resolves
//                                the node's reply map decoded into plain JS
//                                (uint -> decimal string, bstr -> lowercase
//                                hex, bool, array, map -> object); this client
//                                checks it (src/evm/rpc.js). The module's
//                                nsw_evm_query over the nodus client's
//                                nodus_client_dnac_query_raw (Nodus EVM Faz 4).
//     evmGeneration              number — REQUIRED beside evmBuild /
//                                evmQuery: the rule-set generation that
//                                carries the EVM (nodus_witness_runtime.h
//                                NODUS_RT_GEN_EVM). Once the session is open
//                                (unlock, or connectNetwork's success) this
//                                client asks rulesetInfo(); a node whose generation
//                                is below it has not voted the EVM in, and
//                                neither group is offered (the panel stays
//                                hidden) for this session.
//     tick()                   Keepalive ping (the thread-less stand-in for
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
import { parseAccount, parseCode, parseStorage, parseCall, parseEstimate, parseReceipt, parseLogs, parseTicket } from '../evm/rpc.js';

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/;
export const NODUS_TICK_MS = 60000;
const ASYNC_OPS = ['unlock', 'balance', 'list', 'buildAndSign', 'submit', 'scanConfirm', 'tick', 'rulesetInfo'];
const SYNC_OPS = ['cancel', 'lock', 'release'];
const CLAIM_OPS = ['claimStatus', 'claimBuild', 'claimSubmit'];
// OPTIONAL (0.1.29, staking — shapes in src/nodus/send-module.js): a module
// without all three (and its `stakingRules`) still unlocks; this client then
// answers every staking call "not available". Staking envelopes are
// submitted with submit().
const STAKE_OPS = ['validators', 'delegations', 'stakeBuild'];
// OPTIONAL (NC-4b, Messages — shapes in src/nodus/send-module.js):
// connect(run) is an asynchronous operation of THIS queue (the Messages
// exports share the module, its one session and its one Asyncify state);
// connectSync(run) never reaches emscripten_sleep. A module without both
// still unlocks; this client then answers "Messages is not available".
// src/connect/core.js is the only caller.
const CONNECT_OPS = ['connect', 'connectSync'];
// OPTIONAL (HF-4, chain names — shapes in src/nodus/send-module.js): a
// module without all three still unlocks; this client then answers every
// name call "not available" (a name never resolves to anything).
const NAME_OPS = ['nameLookup', 'nameOf', 'profileAddress'];
// OPTIONAL (HF-4, chain-name registration — shapes in
// src/nodus/send-module.js): a group of its own, so a module that resolves
// names but cannot register keeps send-to-name. Registering also needs the
// name lookups above (the availability check).
const NAME_REG_OPS = ['namePrices', 'nameBuild'];
// OPTIONAL (shared vaults, general multisig — shapes in
// src/nodus/send-module.js "SHARED VAULTS"): a module without all of them
// still unlocks; this client then answers "Shared vaults are not available".
const VAULT_OPS = ['vaultCreate', 'vaultOpen', 'vaultBalance', 'vaultScan', 'vaultPropose', 'vaultReview', 'vaultApprove', 'vaultSubmit'];
// OPTIONAL (smart contracts): building / signing, and the §18 reads, each a
// group of its own — a module that can build but not read (or the reverse)
// offers only what it has.
const EVM_BUILD_OPS = ['evmBuild'];
const EVM_QUERY_OPS = ['evmQuery'];
export const EVM_QUERY_METHODS = Object.freeze(['evm_account', 'evm_code', 'evm_storage', 'evm_call', 'evm_estimate', 'evm_receipt', 'evm_logs', 'evm_ticket']);
const HEX32B = /^[0-9a-f]{64}$/, EVEN_HEX = /^([0-9a-f]{2})*$/, U64DEC = /^(0|[1-9]\d{0,19})$/;
function evmArgs(method, args) {
  const a = args || {};
  const bad = what => { throw new Error(`Invalid ${what}.`); };
  const addr = (v, what = 'address') => (typeof v === 'string' && HEX32B.test(v) ? ['b', v] : bad(what));
  const u64 = (v, what) => (typeof v === 'string' && U64DEC.test(v) && BigInt(v) < 2n ** 64n ? ['u', v] : bad(what));
  switch (method) {
    case 'evm_account': case 'evm_code': return { a: addr(a.address) };
    case 'evm_storage': return { a: addr(a.address), k: addr(a.key, 'storage key') };
    case 'evm_call': case 'evm_estimate': {
      const out = { f: addr(a.from, 'sender'), d: typeof a.data === 'string' && EVEN_HEX.test(a.data) ? ['b', a.data] : bad('call data') };
      if (a.to !== undefined) out.t = addr(a.to, 'contract address');
      if (a.value !== undefined) out.v = addr(a.value, 'value');
      if (a.gas !== undefined) out.g = u64(a.gas, 'gas limit');
      return out;
    }
    case 'evm_receipt': return { i: typeof a.intentId === 'string' && HEX128.test(a.intentId) ? ['b', a.intentId] : bad('transaction id') };
    case 'evm_logs': {
      const out = { fh: u64(a.fromHeight, 'block height'), th: u64(a.toHeight, 'block height'), lim: u64(a.limit ?? '1000', 'limit') };
      if (BigInt(out.th[1]) < BigInt(out.fh[1]) || BigInt(out.th[1]) - BigInt(out.fh[1]) >= 10000n) bad('block range (at most 10,000 blocks)');
      if (BigInt(out.lim[1]) < 1n || BigInt(out.lim[1]) > 1000n) bad('limit');
      if (a.address !== undefined) out.a = addr(a.address);
      (a.topics || []).forEach((t, i) => { if (i > 3) bad('topics'); if (t !== null && t !== undefined) out[`t${i}`] = addr(t, 'topic'); });
      // red-team 1 F4: resume where a previous reply's cursor points (send
      // the SAME range / address / topics as that request). As the C SDK
      // (nodus_client.c nodus_client_evm_logs): fh <= height <= th, index /
      // logIndex <= 2^32 (nodus.h NODUS_EVM_LOGS_CURSOR_POS_MAX).
      if (a.cursor !== undefined) {
        const c = a.cursor;
        if (!c || typeof c !== 'object' || Array.isArray(c)) bad('cursor');
        const pos = [c.height, c.index, c.logIndex].map(v => u64(v, 'cursor')[1]);
        if (BigInt(pos[0]) < BigInt(out.fh[1]) || BigInt(pos[0]) > BigInt(out.th[1]) || BigInt(pos[1]) > 2n ** 32n || BigInt(pos[2]) > 2n ** 32n) bad('cursor');
        out.c = ['U', pos];
      }
      return out;
    }
    case 'evm_ticket': return { id: typeof a.id === 'string' && HEX128.test(a.id) ? ['b', a.id] : bad('ticket') };
    default: return bad('smart-contract request');
  }
}
// OPTIONAL (local-first open): the unlock in two steps.
//
// STATES of this client:
//   idle -> 'connecting' (unlock) -> 'ready'
//   idle -> 'identifying' (identify) -> 'identified'
//        -> 'connecting' (connectNetwork) -> 'ready'
//                                         -> 'identified' (failed: retry)
//                                         -> 'error' + locked (final)
//   'ready' -> 'error' (a keepalive or a resume check failed, or the
//              module said its session is gone — NODUS_SESSION_LOST_TEXT
//              below; the caller locks it)
//   'ready' -> 'locked' (a resume check did not settle within
//              NODUS_CONNECT_BOUND_MS — checkLiveness)
//   any -> 'locked' (lock(); a failed unlock / identify locks too)
// Once the identity is known (identified, 'connecting' after it, 'ready')
// connectLocal runs the Messages exports that need only the identity;
// every other operation, connect() included, needs 'ready'. The module
// refuses every network call before its connect succeeded on its own as
// well (nodus-send-wasm.c nsw_session_ok, connect/nc_wasm.c session_ok).
const SPLIT_OPS = ['identify', 'connectNetwork'];
const RAW_RULE = /^[1-9]\d{0,19}$/;
function validRules(rules) {
  return !!rules && ['minDelegation', 'selfStake', 'commissionMaxBps', 'undelegateLockEpochs', 'epochLength', 'maxDelegators'].every(key => typeof rules[key] === 'string' && RAW_RULE.test(rules[key]) && BigInt(rules[key]) < 2n ** 64n);
}
const lockedError = () => new Error('Wallet is locked.');
// CONNECT WATCHDOG (operator 2026-10-07: "sometimes when I open Connect it
// stays in 'connecting'"). A connection step that never settles left the
// client in 'connecting' with nothing to retry it: the retries in src/app.js
// (RECONNECT) and src/connect/ui/standalone.js (connectLoop) run only once
// an attempt has failed. Now one attempt — identify / unlock (module load
// + identity, unlock also the session and rule-set check), or
// connectNetwork (session + rule-set check) — must settle within this bound.
// 30 s is the operator's choice (2026-10-07); the module's own steps are
// bounded by the 5 s connect timeout of nodus_client.c, so a healthy attempt
// that walks several nodes still fits. Past it the attempt has TIMED OUT:
// the client locks itself (lock() below: the call in flight is abandoned —
// the module serialises every call through one queue and a hung call holds
// it, so the same client cannot be tried again) and the attempt rejects
// with an error marked `timedOut: true` and `step`. The caller then starts
// a NEW client (src/app.js connectNodus / startNodusSend). Not random, and
// no clock decides anything but this one wait.
export const NODUS_CONNECT_BOUND_MS = 30000;

// SESSION LOST (web 0.1.72; operator's phone log 2026-10-07: after the screen
// was off for minutes every read failed at once, the next round said "Nodus
// connection is not ready", and the wallet never reconnected — the bar
// still said connected). The module reconnects inside its keepalive
// (nodus-send-wasm.c nsw_tick -> nodus_client_tick -> try_reconnect) and
// its tick SUCCEEDS while the session is down and being retried
// (nsw_tick returns 0 for NODUS_CLIENT_RECONNECTING), so a failed keepalive
// never reported it. What the module does report: every network export
// refuses with exactly this text when its session is not open
// (nodus-send-wasm.c nsw_session_ok: unlocked, but nodus_client_is_ready()
// false; the Messages exports through connect/nc_wasm.c session_ok, the
// same check and the same text). A 'ready' client that sees it from the
// module is no longer ready: it goes to 'error' (the caller makes a new
// client, src/app.js RECONNECT). The text WITHOUT " Try again shortly." is
// a different case (never connected, or this client's own ready() guard)
// and is not matched.
export const NODUS_SESSION_LOST_TEXT = 'Nodus connection is not ready. Try again shortly.';

// `steps` (optional): { begin(name) -> { end(outcome, error) } } — told when
// each connection step starts and how it ended ('ok' / 'failed' /
// 'timed out'), for the session log (src/session-log.js stepLog). Step
// names: 'load', 'identify', 'unlock', 'connect', 'ruleset', 'first tick',
// 'resume check' (checkLiveness).
// A throwing logger never changes what the client does.
//
// `onState(next, why)`: every state change. `why` is given for a change to
// 'error' out of 'ready': { reason: 'keepalive' | 'resume check' |
// 'session lost', error } — for the session log only.
export function createNodusClient({ factory, onState, steps, setInterval: every = globalThis.setInterval, clearInterval: stopEvery = globalThis.clearInterval, setTimeout: after = globalThis.setTimeout, clearTimeout: stopAfter = globalThis.clearTimeout } = {}) {
  if (typeof factory !== 'function') throw new Error('The Nodus send module is not available.');
  let module, state = 'idle', stopped = false, started = false, timer, inFlight, tickQueued = false, fingerprint, chainId, claimable = false, stakeable = false, stakingRules, connectable = false, nameable = false, registrable = false, vaultable = false, splittable = false, connecting, evmGen = 0, evmBuildable = false, evmReadable = false;
  // The connection step running now ({ name, handle }) and whether the first
  // keepalive after 'ready' is still to be logged.
  let currentStep, firstTick = false;
  // The keepalive queued or running now (its promise), and the resume check
  // running now (checkLiveness).
  let pendingTick, probing;
  // ONE operation queue: Asyncify keeps a single global currData, so a second
  // export entered while the first is suspended corrupts the first. `tail`
  // settles only when the module call itself has returned, never merely when
  // its caller gave up waiting.
  let tail = Promise.resolve();
  const waiting = new Set();
  function setState(next, why) { if (state === next) return; state = next; onState?.(next, why); }
  // A 'ready' client that has lost its session (see the callers).
  function failReady(reason, error) { if (!stopped && state === 'ready') setState('error', { reason, error }); }
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
      } catch (error) {
        // The module's own "session not open" refusal (NODUS_SESSION_LOST_TEXT).
        if (error?.message === NODUS_SESSION_LOST_TEXT) failReady('session lost', error);
        entry.reject(stopped ? lockedError() : error);
      }
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
    const first = firstTick; firstTick = false;
    const op = first ? runStep('first tick', () => enqueue('tick')) : enqueue('tick');
    pendingTick = op;
    op.catch(error => { if (!stopped) setState('error', state === 'ready' ? { reason: 'keepalive', error } : undefined); })
      .finally(() => { tickQueued = false; if (pendingTick === op) pendingTick = undefined; });
  }
  // RESUME CHECK (web 0.1.72; the caller runs it when the page is shown
  // again or the browser is back online — src/app.js). While a phone's
  // screen was off one read held the one queue 5.5 minutes (operator's log
  // 2026-10-07), so no keepalive ran either (the tick waits in the same
  // queue) and the server may drop a session idle for 180 s. The check runs the keepalive at once — the one already
  // queued, if any, so there is never a second — under the CONNECT
  // WATCHDOG (NODUS_CONNECT_BOUND_MS, bounded): the module's tick also
  // runs its reconnect when one is due (nsw_tick -> nodus_client_tick).
  //   failed    -> 'error' (the caller makes a new client)
  //   timed out -> the client locked itself (bounded), 'locked'
  //   ok        -> stays 'ready'. NOT a proof that the session is open: the
  //                module's tick succeeds while it is still reconnecting
  //                (NODUS_SESSION_LOST_TEXT above); the next network call
  //                then reports it.
  // Only from 'ready'; called again while one runs, the same promise.
  // Resolves 'ok' | 'failed' | 'timed out' | 'skipped', never rejects.
  function checkLiveness() {
    if (stopped || !module || state !== 'ready') return Promise.resolve('skipped');
    if (probing) return probing;
    const run = bounded(() => runStep('resume check', () => pendingTick || enqueue('tick')))
      .then(() => 'ok', error => {
        if (error?.timedOut === true) return 'timed out';
        failReady('resume check', error);
        return 'failed';
      })
      .finally(() => { if (probing === run) probing = undefined; });
    probing = run;
    return run;
  }
  // One connection step, told to `steps`: its start, then its outcome ONCE
  // (a step the watchdog ended 'timed out' is not ended again by the lock's
  // rejection that follows).
  function endStep(step, outcome, error) {
    if (!step || step.done) return;
    step.done = true;
    try { step.handle?.end(outcome, error); } catch { /* the log never changes the connection */ }
  }
  async function runStep(name, work) {
    let handle;
    try { handle = steps?.begin?.(name); } catch { handle = undefined; }
    const mine = { name, handle, done: false };
    currentStep = mine;
    try {
      const value = await work();
      endStep(mine, 'ok');
      return value;
    } catch (error) {
      endStep(mine, 'failed', error);
      throw error;
    } finally { if (currentStep === mine) currentStep = undefined; }
  }
  // One attempt under the CONNECT WATCHDOG (NODUS_CONNECT_BOUND_MS above).
  // Whichever settles first wins; the timer is cleared either way. On
  // expiry the running step is logged 'timed out', the client locks itself
  // (its lock() abandons the call in flight; a late result of it is
  // discarded there — `stopped`), and the attempt rejects with the timeout
  // error — also when the lock's own rejection reaches `work` first.
  function bounded(work) {
    let watchdog, timedOut, settled = false;
    const expired = new Promise((resolve, reject) => {
      watchdog = after(() => {
        watchdog = undefined;
        // A late firing (the attempt already settled) or a locked client: nothing to do.
        if (settled || stopped) return;
        const where = currentStep?.name || 'start';
        timedOut = new Error(`The Nodus network did not answer within ${NODUS_CONNECT_BOUND_MS / 1000} seconds (step: ${where}).`);
        timedOut.timedOut = true; timedOut.step = where;
        endStep(currentStep, 'timed out', timedOut);
        lock();
        reject(timedOut);
      }, NODUS_CONNECT_BOUND_MS);
    });
    expired.catch(() => { /* answered through the race below */ });
    const attempt = (async () => work())().catch(error => { throw timedOut || error; });
    return Promise.race([attempt, expired]).finally(() => {
      settled = true;
      if (watchdog !== undefined) { stopAfter(watchdog); watchdog = undefined; }
    });
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
  // Refusals that touch no module: a used client (identified, ready, failed
  // or locked) stays exactly as it is. Returns the checked seed.
  function claimStart(seed, expected) {
    if (started || stopped) { if (seed instanceof Uint8Array) seed.fill(0); throw new Error('This Nodus connection was already used. Lock and reopen your wallet.'); }
    if (!(seed instanceof Uint8Array) || seed.length !== 32) { if (seed instanceof Uint8Array) seed.fill(0); throw new Error('Nodus signing seed must be 32 bytes.'); }
    if (typeof expected !== 'string' || !HEX128.test(expected)) { seed.fill(0); throw new Error('Nodus address is not available yet.'); }
    started = true;
  }
  async function load() {
    const loaded = await factory();
    if (stopped) {
      // Locked while the module was loading: it is wiped and dropped unused.
      module = loaded; lock(); throw lockedError();
    }
    if (!loaded || ![...ASYNC_OPS, ...SYNC_OPS].every(name => typeof loaded[name] === 'function') || !(loaded.memory?.buffer instanceof ArrayBuffer)) {
      module = loaded; throw new Error('The Nodus send module does not match this wallet version.');
    }
    module = loaded;
    claimable = CLAIM_OPS.every(name => typeof loaded[name] === 'function');
    stakeable = STAKE_OPS.every(name => typeof loaded[name] === 'function') && validRules(loaded.stakingRules);
    stakingRules = stakeable ? Object.freeze({ ...loaded.stakingRules }) : undefined;
    connectable = CONNECT_OPS.every(name => typeof loaded[name] === 'function');
    nameable = NAME_OPS.every(name => typeof loaded[name] === 'function');
    registrable = nameable && NAME_REG_OPS.every(name => typeof loaded[name] === 'function');
    vaultable = VAULT_OPS.every(name => typeof loaded[name] === 'function');
    splittable = SPLIT_OPS.every(name => typeof loaded[name] === 'function');
    evmGen = Number.isSafeInteger(loaded.evmGeneration) && loaded.evmGeneration > 0 ? loaded.evmGeneration : 0;
    evmBuildable = evmGen > 0 && EVM_BUILD_OPS.every(name => typeof loaded[name] === 'function');
    evmReadable = evmGen > 0 && EVM_QUERY_OPS.every(name => typeof loaded[name] === 'function');
  }
  // Smart contracts only where the node runs the EVM generation: a node
  // that has not voted the EVM in (or does not say) offers neither group
  // for this session — the panel stays hidden. Never fails the connection.
  // Runs once the session is open (unlock, or connectNetwork's success),
  // before the client reports 'ready'.
  async function evmGate() {
    if (!evmBuildable && !evmReadable) return;
    let active = false;
    try {
      const ri = await runStep('ruleset', () => enqueue('rulesetInfo'));
      active = typeof ri?.generation === 'string' && /^[1-9]\d{0,9}$/.test(ri.generation) && Number(ri.generation) >= evmGen;
    } catch { active = false; }
    if (stopped) throw lockedError();
    if (!active) { evmBuildable = false; evmReadable = false; }
  }
  function takeIdentity(info, expected) {
    if (!info || typeof info.fingerprint !== 'string' || !HEX128.test(info.fingerprint) || typeof info.chainId !== 'string' || !HEX64.test(info.chainId)) throw new Error('The Nodus send module returned an invalid identity.');
    // The module derives the identity from the seed on its own; it must be
    // the same address this wallet derived and shows (src/nodus/derive.js).
    if (info.fingerprint !== expected) throw new Error('The Nodus send module derived a different address. Nothing was connected.');
    fingerprint = info.fingerprint; chainId = info.chainId;
  }
  async function unlock({ seed, fingerprint: expected } = {}) {
    claimStart(seed, expected);
    try {
      setState('connecting');
      await bounded(async () => {
        await runStep('load', load);
        takeIdentity(await runStep('unlock', () => enqueue('unlock', { seed })), expected);
        await evmGate();
      });
      timer = every(tick, NODUS_TICK_MS);
      firstTick = true;
      setState('ready');
      return { fingerprint, chainId };
    } catch (error) {
      if (!stopped) { lock(); setState('error'); }
      throw error;
    } finally { seed.fill(0); }
  }
  // The local half of unlock: the identity, no session. Afterwards the
  // Messages exports that need only the identity run (connectLocal); the
  // network waits for connectNetwork(). A failure locks, as unlock's does.
  async function identify({ seed, fingerprint: expected } = {}) {
    claimStart(seed, expected);
    try {
      setState('identifying');
      await bounded(async () => {
        await runStep('load', load);
        if (!splittable) throw new Error('The Nodus send module does not match this wallet version.');
        takeIdentity(await runStep('identify', () => enqueue('identify', { seed })), expected);
      });
      setState('identified');
      return { fingerprint, chainId };
    } catch (error) {
      if (!stopped) { lock(); setState('error'); }
      throw error;
    } finally { seed.fill(0); }
  }
  // The network half: one attempt, queued like every operation. A failed
  // attempt returns to 'identified' and may be tried again (nothing is
  // wiped); a `final` one (the node serves another chain) locks the client.
  // Called again while an attempt runs: that attempt's promise. An attempt
  // that does not settle within NODUS_CONNECT_BOUND_MS (session + rule-set
  // check together) locks the client and rejects `timedOut` (bounded).
  function connectNetwork() {
    if (stopped) return Promise.reject(lockedError());
    if (state === 'ready') return Promise.resolve();
    if (connecting) return connecting;
    if (!module || state !== 'identified') return Promise.reject(new Error('Nodus connection is not ready.'));
    setState('connecting');
    connecting = bounded(async () => {
      try {
        await runStep('connect', () => enqueue('connectNetwork'));
      } catch (error) {
        if (stopped) throw lockedError();
        if (error?.final === true) { lock(); setState('error'); }
        else setState('identified');
        throw error;
      }
      if (stopped) throw lockedError();
      await evmGate();
      timer = every(tick, NODUS_TICK_MS);
      firstTick = true;
      setState('ready');
    }).finally(() => { connecting = undefined; });
    return connecting;
  }
  const identified = () => !stopped && !!module && fingerprint !== undefined && (state === 'identified' || state === 'connecting' || state === 'ready');
  const call = op => (args, options) => { try { ready(); } catch (error) { return Promise.reject(error); } return enqueue(op, args, options); };
  const claimCall = op => (args, options) => claimable ? call(op)(args, options) : Promise.reject(new Error('Claiming is not available in this wallet version.'));
  const stakeCall = op => (args, options) => stakeable ? call(op)(args, options) : Promise.reject(new Error('Staking is not available in this wallet version.'));
  const noMessages = () => new Error('Messages is not available in this wallet version.');
  const nameCall = op => (args, options) => nameable ? call(op)(args, options) : Promise.reject(new Error('Chain names are not available in this wallet version.'));
  const registerCall = op => (args, options) => registrable ? call(op)(args, options) : Promise.reject(new Error('Registering a chain name is not available in this wallet version.'));
  const vaultCall = op => (args, options) => vaultable ? call(op)(args, options) : Promise.reject(new Error('Shared vaults are not available in this wallet version.'));
  const evmBuildCall = op => (args, options) => evmBuildable ? call(op)(args, options) : Promise.reject(new Error('Smart contracts are not available in this wallet version.'));
  // One §18 read: arguments checked and tagged here, the reply checked by
  // `parse` (src/evm/rpc.js) before anyone sees it — against the tagged
  // request it answers (parseLogs needs the range, limit and cursor).
  const evmRead = (method, parse) => async (args, options) => {
    if (!evmReadable) throw new Error('Reading smart contracts from the network is not available in this wallet version.');
    const tagged = evmArgs(method, args);
    return parse(await call('evmQuery')({ method, args: tagged }, options), tagged);
  };
  return {
    get state() { return state; },
    get fingerprint() { return fingerprint; },
    get chainId() { return chainId; },
    // Whether the loaded module offers the genesis claim (CLAIM_OPS).
    get claimable() { return claimable && state === 'ready'; },
    // The identity is known (identify or unlock finished) and the client is
    // not failed or locked: 'identified', 'connecting' after it, or 'ready'.
    get identified() { return identified(); },
    unlock,
    identify,
    connectNetwork,
    checkLiveness,
    balance: (options) => call('balance')(undefined, options),
    list: (options) => call('list')(undefined, options),
    buildAndSign: call('buildAndSign'),
    submit: call('submit'),
    scanConfirm: call('scanConfirm'),
    rulesetInfo: (options) => call('rulesetInfo')(undefined, options),
    // Whether the loaded module resolves chain names (NAME_OPS).
    get nameable() { return nameable && state === 'ready'; },
    nameLookup: nameCall('nameLookup'),
    nameOf: nameCall('nameOf'),
    profileAddress: nameCall('profileAddress'),
    // Whether the loaded module can register a chain name (NAME_REG_OPS).
    get registrable() { return registrable && state === 'ready'; },
    namePrices: (options) => registerCall('namePrices')(undefined, options),
    nameBuild: registerCall('nameBuild'),
    claimStatus: (options) => claimCall('claimStatus')(undefined, options),
    claimBuild: (options) => claimCall('claimBuild')(undefined, options),
    claimSubmit: claimCall('claimSubmit'),
    // Whether the loaded module offers staking (STAKE_OPS), and its chain
    // constants (raw decimal strings, from the module's own build).
    get stakeable() { return stakeable && state === 'ready'; },
    get stakingRules() { return stakeable && state === 'ready' ? stakingRules : undefined; },
    // Shared vaults (VAULT_OPS): whether the loaded module offers them, and
    // the operations (each one queue slot; shapes in send-module.js).
    get vaultable() { return vaultable && state === 'ready'; },
    vaultCreate: vaultCall('vaultCreate'),
    vaultOpen: vaultCall('vaultOpen'),
    vaultBalance: vaultCall('vaultBalance'),
    vaultScan: vaultCall('vaultScan'),
    vaultPropose: vaultCall('vaultPropose'),
    vaultReview: vaultCall('vaultReview'),
    vaultApprove: vaultCall('vaultApprove'),
    vaultSubmit: vaultCall('vaultSubmit'),
    // Smart contracts (the EVM domain): whether the loaded module builds EVM
    // envelopes (EVM_BUILD_OPS) and whether it reads EVM state (§18,
    // EVM_QUERY_OPS); the build, and one method per §18 query. Every
    // answer is ONE node's committed tip state.
    get evmBuildable() { return evmBuildable && state === 'ready'; },
    get evmReadable() { return evmReadable && state === 'ready'; },
    evmBuild: evmBuildCall('evmBuild'),
    evmAccount: evmRead('evm_account', parseAccount),       // { address }
    evmCode: evmRead('evm_code', parseCode),                // { address }
    evmStorage: evmRead('evm_storage', parseStorage),       // { address, key }
    evmCall: evmRead('evm_call', parseCall),                // { from, to?, value?, data, gas? }
    evmEstimate: evmRead('evm_estimate', parseEstimate),    // same as evmCall
    evmReceipt: evmRead('evm_receipt', parseReceipt),       // { intentId } -> receipt | null
    evmLogs: evmRead('evm_logs', parseLogs),                // { fromHeight, toHeight, address?, topics?, limit?, cursor? } -> { logs, more, cursor }
    evmTicket: evmRead('evm_ticket', parseTicket),          // { id }
    validators: (options) => stakeCall('validators')(undefined, options),
    delegations: (options) => stakeCall('delegations')(undefined, options),
    stakeBuild: stakeCall('stakeBuild'),
    // Messages (NC-4b): whether the loaded module carries the Nodus Connect
    // exports; connect(run) runs `run` in this queue on the module's
    // session; connectSync(run) runs it now (non-waiting exports only; also
    // outside 'ready', so Messages can wipe its keys (nc_lock) while the
    // wallet's connection is in 'error').
    get connectable() { return connectable && state === 'ready'; },
    connect: (run, options) => {
      if (!connectable) return Promise.reject(noMessages());
      if (typeof run !== 'function') return Promise.reject(new Error('Invalid Messages operation.'));
      return call('connect')(run, options);
    },
    // connectLocal(run): the same queue slot as connect(run), already once
    // identified — for the Messages exports that need only the identity
    // (keys, history key and records, kept-profile checks; src/connect/
    // core.js). The module refuses any network call made through it before
    // its connect succeeded.
    get localConnectable() { return connectable && identified(); },
    connectLocal: (run, options) => {
      if (stopped) return Promise.reject(lockedError());
      if (!connectable) return Promise.reject(noMessages());
      if (typeof run !== 'function') return Promise.reject(new Error('Invalid Messages operation.'));
      if (!identified()) return Promise.reject(new Error('Nodus connection is not ready.'));
      return enqueue('connect', run, options);
    },
    connectSync(run) {
      if (stopped || !module) throw lockedError();
      if (!connectable) throw noMessages();
      if (typeof run !== 'function') throw new Error('Invalid Messages operation.');
      return module.connectSync(run);
    },
    lock
  };
}
