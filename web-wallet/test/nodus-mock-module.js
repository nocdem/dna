// TEST-ONLY stand-in for the NODUS send module (package (c3), not built yet).
// It implements the JS contract written at the top of src/nodus/client.js with
// canned chain data and no cryptography: the envelope is three fixed bytes and
// `decoded` is produced from the request (optionally tampered by a test).
// It proves the wallet-side discipline (queue, lock order, G1 checks, expiry,
// pending-send record) — nothing about the real module or the chain.
export const FINGERPRINT = 'ab'.repeat(64);
export const RECIPIENT = 'cd'.repeat(64);
export const CHAIN_ID = 'e'.repeat(64);
export const INTENT_ID = '9'.repeat(128);
export const FEE = '1000';
export const coin = (digit, amount) => ({ nullifier: String(digit).repeat(128), amount });
// The asset identity of a NODUS send (src/wallet.js prepareTransfer `asset`):
// the all-zero token id is NODUS itself.
export const ZERO_TOKEN = '0'.repeat(128);
export const NODUS_NATIVE = { chain: 'nodus', tokenId: ZERO_TOKEN };
// The pinned test token of the token tests (the module's table, crypto/
// nodus-send-wasm.c NSW_PINS: tUSDT, 6 decimals) and a made-up coin of it.
export const TUSDT_ID = '7142460f5dd73ce7123905c423e1eb17fbff36f14b031e24837a4b6d7bedd5677baaa3a3e6015e6d6fc706b0b0d8799a88d7fd63f6d1e7807dbb88577b7c3b50';
export const TUSDT = { tokenId: TUSDT_ID, name: 'Test USDT', symbol: 'tUSDT', decimals: 6, available: true };
export const tokenCoin = (digit, amount, tokenId = TUSDT_ID) => ({ nullifier: String(digit).repeat(128), amount, tokenId });
const SEED_AT = 4096;
// The module's error for a node's RATE_LIMITED answer (web 0.1.119,
// src/nodus/send-module.js failure: the text of nsw_fail_rc, `busy` from
// nsw_error_busy).
export const BUSY_TEXT = 'The network is busy right now. Try again in a few seconds.';
export const busyError = () => Object.assign(new Error(BUSY_TEXT), { busy: true });

export function createMockNodusModule() {
  const log = [];
  const memory = new WebAssembly.Memory({ initial: 1 });
  const gates = {};
  let active = 0;
  const state = {
    fingerprint: FINGERPRINT, chainId: CHAIN_ID, tip: '1000', total: '450000000', spendable: '450000000',
    coins: [coin(1, '100000000'), coin(2, '300000000'), coin(3, '50000000')], truncated: false,
    accepted: true, scan: { tip: '1000', found: false }, tamper: null, tickFails: false, lastBuild: null,
    overlap: false, seedAtLock: null, zeroAtRelease: null, failCancel: false,
    // HF-4: rulesetInfo's answer (generation 1, no switch), or an Error the
    // module would raise (an older node / an unknown generation).
    ruleset: { tip: '1000', generation: '1', gen2Height: '0' }, rulesetError: null,
    // web 0.1.129: rulesetCompat's answer (the module's JS form,
    // send-module.js rulesetCompat; outcome 0 = this module carries the
    // node's rules), or an Error the module would raise (no readable answer).
    compat: { outcome: 0, generation: '5', nextGeneration: '0', nextHeight: '0', tip: '1000', maxGeneration: '5' }, compatError: null,
    // HF-4 chain names: name -> owner fingerprint; owner -> { eth, bsc, sol,
    // trx } profile addresses; profileError: the module's refusal of an
    // unreadable / unsigned profile.
    names: {}, profiles: {}, profileError: null, nameError: null,
    // HF-4 chain-name registration: the node's prices (3, 4, 5, 6+
    // characters; raw decimal strings — test values, the module's are the
    // node's), scheduled price rows, the price the BUILD reads (null = the
    // same list; a test sets it to model a price change between the quote
    // and the build), a tamper of the build's read-back, the last request.
    namePrices: { prices: ['100000000000', '50000000000', '10000000000', '100000000'], scheduled: [] },
    buildPrices: null, nameTamper: null, lastNameBuild: null,
    // The split unlock (identify / connectNetwork): the errors the next
    // connectNetwork calls raise, one per call (an Error with `final: true`
    // models a node of another chain); empty = connected.
    connectErrors: [], connected: false,
    // Account history (0.1.78): the page addrHistory answers (the module's
    // JSON form, send-module.js addrHistory), or an Error the module would
    // raise; the last request; a wire id the builds return (null = none,
    // like a module without nsw_built_wire).
    history: { enabled: true, from_height: '1', entries: [] }, historyError: null, lastHistory: null, wireId: null,
    // web 0.1.119: names of the operations the node answers "busy"
    // (busyError) until the test removes them.
    busy: new Set(),
    // web 0.1.124: every envelope handed to submit(), in order — busy
    // answers included (a copy of the bytes at the call). `hedged`: each
    // build returns different bytes (a fourth byte counting the builds),
    // as the real module's hedged signature does; off = the fixed three
    // bytes the older tests compare.
    submissions: [], hedged: false, builds: 0,
    // Tokens: the module's pinned list (tokenPins), and — set by a test —
    // the balance rows, the pinned tokens' coins and their listing status.
    pins: [], tokenBalances: null, tokenCoins: null, tokenListing: null, lastTokenBuild: null
  };
  const bytes = () => new Uint8Array(memory.buffer);
  async function op(name, fn) {
    log.push(`${name}:start`);
    if (active) state.overlap = true; // a second export entered while one runs
    active++;
    try {
      const gate = gates[name]?.shift();
      if (gate) await gate;
      if (state.busy.has(name)) throw busyError();
      return await fn();
    } finally { active--; log.push(`${name}:end`); }
  }
  const module = {
    memory,
    unlock: ({ seed }) => op('unlock', async () => { bytes().set(seed, SEED_AT); state.connected = true; return { fingerprint: state.fingerprint, chainId: state.chainId }; }),
    identify: ({ seed }) => op('identify', async () => { bytes().set(seed, SEED_AT); return { fingerprint: state.fingerprint, chainId: state.chainId }; }),
    connectNetwork: () => op('connectNetwork', async () => {
      const error = state.connectErrors.shift();
      if (error) throw error;
      state.connected = true;
    }),
    // Messages (NC-4b) stand-ins: `run` gets an empty API (the tests only
    // follow the queue and the state gates).
    connect: run => op('connect', async () => run({})),
    connectSync: run => run({}),
    // The token group (src/nodus/client.js TOKEN_OPS): `state.pins` is the
    // module's pinned list as tokenPins() reports it ([] = none, the default);
    // `state.tokenBalances` / `state.tokenCoins` / `state.tokenListing` add
    // the token rows to balance() / list() only when a test sets them, so the
    // older tests see the exact shapes they always did.
    tokenPins: () => state.pins.map(pin => ({ ...pin })),
    balance: () => op('balance', async () => ({ total: state.total, spendable: state.spendable, ...(state.tokenBalances ? { tokens: state.tokenBalances.map(row => ({ ...row })) } : {}) })),
    list: () => op('list', async () => ({ tip: state.tip, coins: state.coins, truncated: state.truncated, ...(state.tokenCoins ? { tokenCoins: state.tokenCoins.map(c => ({ ...c })), tokens: (state.tokenListing || []).map(t => ({ ...t })) } : {}) })),
    // The module's token rules, modelled: the token must be pinned and
    // available, the token coins (the request's coins that the listing holds
    // as that token's) cover the amount ("Not enough tUSDT."), the NODUS
    // coins cover the fee ("Not enough NODUS for the network fee."),
    // largest-first; the read-back is produced from the request (optionally
    // tampered by a test, state.tamper).
    tokenBuildAndSign: request => op('tokenBuildAndSign', async () => {
      state.lastTokenBuild = request;
      const pin = state.pins.find(p => p.tokenId === request.tokenId);
      if (!pin) throw new Error('This token is not supported by this wallet.');
      if (!pin.available) throw new Error(`${pin.symbol} is unavailable right now. Nothing was sent.`);
      const tokenIds = new Map((state.tokenCoins || []).map(c => [c.nullifier, c.tokenId]));
      const byAmount = (a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : BigInt(b.amount) < BigInt(a.amount) ? -1 : 0);
      const tokens = request.coins.filter(c => tokenIds.get(c.nullifier) === request.tokenId).sort(byAmount);
      const natives = request.coins.filter(c => !tokenIds.has(c.nullifier)).sort(byAmount);
      const pick = (list, need) => { const inputs = []; let sum = 0n; for (const c of list) { if (sum >= need) break; inputs.push(c.nullifier); sum += BigInt(c.amount); } return { inputs, sum }; };
      const t = pick(tokens, BigInt(request.amount));
      if (t.sum < BigInt(request.amount)) throw new Error(`Not enough ${pin.symbol}.`);
      const n = pick(natives, BigInt(FEE));
      if (n.sum < BigInt(FEE)) throw new Error('Not enough NODUS for the network fee.');
      state.builds++;
      const decoded = { recipient: request.to, amount: request.amount, fee: FEE, change: (n.sum - BigInt(FEE)).toString(), tokenId: request.tokenId, tokenChange: (t.sum - BigInt(request.amount)).toString(), expiryHeight: request.expiryHeight, chainId: state.chainId, inputs: [...t.inputs, ...n.inputs] };
      return { envelope: Uint8Array.of(7, 7, 7, state.builds), intentId: INTENT_ID, decoded: { ...decoded, ...(state.tamper || {}) } };
    }),
    buildAndSign: request => op('buildAndSign', async () => {
      // the module's rule: the explicit all-zero token id is required
      if (request.tokenId !== ZERO_TOKEN) throw new Error('Invalid token.');
      state.lastBuild = request;
      const need = BigInt(request.amount) + BigInt(FEE), inputs = [];
      let sum = 0n;
      for (const c of [...request.coins].sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : BigInt(b.amount) < BigInt(a.amount) ? -1 : 0))) {
        if (sum >= need) break;
        inputs.push(c.nullifier); sum += BigInt(c.amount);
      }
      if (sum < need) throw new Error('Insufficient NODUS balance.');
      const decoded = { recipient: request.to, amount: request.amount, fee: FEE, change: (sum - need).toString(), tokenId: ZERO_TOKEN, tokenChange: '0', expiryHeight: request.expiryHeight, chainId: state.chainId, inputs };
      state.builds++;
      return { envelope: state.hedged ? Uint8Array.of(1, 2, 3, state.builds) : Uint8Array.of(1, 2, 3), intentId: INTENT_ID, ...(state.wireId ? { wireId: state.wireId } : {}), decoded: { ...decoded, ...(state.tamper || {}) } };
    }),
    addrHistory: request => op('addrHistory', async () => {
      state.lastHistory = request;
      if (state.historyError) throw state.historyError;
      return JSON.parse(JSON.stringify(state.history));
    }),
    submit: ({ envelope }) => { state.submissions.push(envelope instanceof Uint8Array ? envelope.slice() : envelope); return op('submit', async () => { state.submitted = envelope; return { accepted: state.accepted }; }); },
    scanConfirm: request => op('scanConfirm', async () => { state.lastScan = request; return state.scan; }),
    tick: () => op('tick', async () => { if (state.tickFails) throw new Error('session closed'); }),
    rulesetInfo: () => op('rulesetInfo', async () => { if (state.rulesetError) throw state.rulesetError; return { ...state.ruleset }; }),
    rulesetCompat: () => op('rulesetCompat', async () => { if (state.compatError) throw state.compatError; return { ...state.compat }; }),
    nameLookup: ({ name }) => op('nameLookup', async () => {
      if (state.nameError) throw state.nameError;
      const owner = state.names[name];
      return owner ? { found: true, committedHeight: '1000', owner, registeredHeight: '900' } : { found: false, committedHeight: '1000' };
    }),
    nameOf: ({ owner }) => op('nameOf', async () => {
      if (state.nameError) throw state.nameError;
      const name = Object.keys(state.names).find(key => state.names[key] === owner);
      return name ? { found: true, committedHeight: '1000', name, registeredHeight: '900' } : { found: false, committedHeight: '1000' };
    }),
    profileAddress: ({ owner, field }) => op('profileAddress', async () => {
      if (state.profileError) throw state.profileError;
      const address = state.profiles[owner]?.[field];
      if (!address) throw new Error('The owner of this name has no address for this network in their profile. Nothing was sent.');
      return { address };
    }),
    namePrices: () => op('namePrices', async () => ({ prices: [...state.namePrices.prices], scheduled: state.namePrices.scheduled.map(row => ({ ...row })) })),
    // The module's rules, modelled: the name must be free and this ID must
    // hold none (it asks the node itself), the price is ITS OWN read of the
    // node (never the caller's), largest-first coins until price + fee.
    nameBuild: request => op('nameBuild', async () => {
      state.lastNameBuild = request;
      if (state.names[request.name]) throw new Error(`The name "${request.name}" is already registered. Nothing was built.`);
      if (Object.values(state.names).includes(state.fingerprint)) throw new Error('This wallet already has a chain name. Nothing was built.');
      const prices = (state.buildPrices || state.namePrices).prices;
      const price = prices[request.name.length >= 6 ? 3 : request.name.length - 3];
      const need = BigInt(price) + BigInt(FEE), inputs = [];
      let sum = 0n;
      for (const c of [...request.coins].sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : BigInt(b.amount) < BigInt(a.amount) ? -1 : 0))) {
        if (sum >= need) break;
        inputs.push(c.nullifier); sum += BigInt(c.amount);
      }
      if (sum < need) throw new Error("Not enough spendable NODUS for the name's price plus the network fee.");
      const decoded = { name: request.name, price, owner: state.fingerprint, fee: FEE, change: (sum - need).toString(), expiryHeight: request.expiryHeight, chainId: state.chainId, inputs };
      return { envelope: Uint8Array.of(8, 8, 8), intentId: INTENT_ID, decoded: { ...decoded, ...(state.nameTamper || {}) } };
    }),
    cancel() { log.push('cancel'); if (state.failCancel) throw new Error('cancel failed'); },
    lock() { log.push('lock'); state.seedAtLock = bytes().subarray(SEED_AT, SEED_AT + 32).some(b => b !== 0); },
    release() { log.push('release'); state.zeroAtRelease = bytes().every(b => b === 0); }
  };
  // Holds the next call of `name` until the returned function is called.
  const gate = name => { let open; (gates[name] ||= []).push(new Promise(resolve => { open = resolve; })); return open; };
  return { module, factory: async () => module, log, state, gate };
}
