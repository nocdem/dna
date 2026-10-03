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
const RAW_RULE = /^[1-9]\d{0,19}$/;
function validRules(rules) {
  return !!rules && ['minDelegation', 'selfStake', 'commissionMaxBps', 'undelegateLockEpochs', 'epochLength', 'maxDelegators'].every(key => typeof rules[key] === 'string' && RAW_RULE.test(rules[key]) && BigInt(rules[key]) < 2n ** 64n);
}
const lockedError = () => new Error('Wallet is locked.');

export function createNodusClient({ factory, onState, setInterval: every = globalThis.setInterval, clearInterval: stopEvery = globalThis.clearInterval } = {}) {
  if (typeof factory !== 'function') throw new Error('The Nodus send module is not available.');
  let module, state = 'idle', stopped = false, started = false, timer, inFlight, tickQueued = false, fingerprint, chainId, claimable = false, stakeable = false, stakingRules, connectable = false, nameable = false, registrable = false, vaultable = false;
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
      claimable = CLAIM_OPS.every(name => typeof loaded[name] === 'function');
      stakeable = STAKE_OPS.every(name => typeof loaded[name] === 'function') && validRules(loaded.stakingRules);
      stakingRules = stakeable ? Object.freeze({ ...loaded.stakingRules }) : undefined;
      connectable = CONNECT_OPS.every(name => typeof loaded[name] === 'function');
      nameable = NAME_OPS.every(name => typeof loaded[name] === 'function');
      registrable = nameable && NAME_REG_OPS.every(name => typeof loaded[name] === 'function');
      vaultable = VAULT_OPS.every(name => typeof loaded[name] === 'function');
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
  const claimCall = op => (args, options) => claimable ? call(op)(args, options) : Promise.reject(new Error('Claiming is not available in this wallet version.'));
  const stakeCall = op => (args, options) => stakeable ? call(op)(args, options) : Promise.reject(new Error('Staking is not available in this wallet version.'));
  const noMessages = () => new Error('Messages is not available in this wallet version.');
  const nameCall = op => (args, options) => nameable ? call(op)(args, options) : Promise.reject(new Error('Chain names are not available in this wallet version.'));
  const registerCall = op => (args, options) => registrable ? call(op)(args, options) : Promise.reject(new Error('Registering a chain name is not available in this wallet version.'));
  const vaultCall = op => (args, options) => vaultable ? call(op)(args, options) : Promise.reject(new Error('Shared vaults are not available in this wallet version.'));
  return {
    get state() { return state; },
    get fingerprint() { return fingerprint; },
    get chainId() { return chainId; },
    // Whether the loaded module offers the genesis claim (CLAIM_OPS).
    get claimable() { return claimable && state === 'ready'; },
    unlock,
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
    connectSync(run) {
      if (stopped || !module) throw lockedError();
      if (!connectable) throw noMessages();
      if (typeof run !== 'function') throw new Error('Invalid Messages operation.');
      return module.connectSync(run);
    },
    lock
  };
}
