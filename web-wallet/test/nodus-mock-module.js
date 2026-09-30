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
const SEED_AT = 4096;

export function createMockNodusModule() {
  const log = [];
  const memory = new WebAssembly.Memory({ initial: 1 });
  const gates = {};
  let active = 0;
  const state = {
    fingerprint: FINGERPRINT, chainId: CHAIN_ID, tip: '1000', total: '450000000', spendable: '450000000',
    coins: [coin(1, '100000000'), coin(2, '300000000'), coin(3, '50000000')], truncated: false,
    accepted: true, scan: { tip: '1000', found: false }, tamper: null, tickFails: false, lastBuild: null,
    overlap: false, seedAtLock: null, zeroAtRelease: null, failCancel: false
  };
  const bytes = () => new Uint8Array(memory.buffer);
  async function op(name, fn) {
    log.push(`${name}:start`);
    if (active) state.overlap = true; // a second export entered while one runs
    active++;
    try {
      const gate = gates[name]?.shift();
      if (gate) await gate;
      return await fn();
    } finally { active--; log.push(`${name}:end`); }
  }
  const module = {
    memory,
    unlock: ({ seed }) => op('unlock', async () => { bytes().set(seed, SEED_AT); return { fingerprint: state.fingerprint, chainId: state.chainId }; }),
    balance: () => op('balance', async () => ({ total: state.total, spendable: state.spendable })),
    list: () => op('list', async () => ({ tip: state.tip, coins: state.coins, truncated: state.truncated })),
    buildAndSign: request => op('buildAndSign', async () => {
      state.lastBuild = request;
      const need = BigInt(request.amount) + BigInt(FEE), inputs = [];
      let sum = 0n;
      for (const c of [...request.coins].sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : BigInt(b.amount) < BigInt(a.amount) ? -1 : 0))) {
        if (sum >= need) break;
        inputs.push(c.nullifier); sum += BigInt(c.amount);
      }
      if (sum < need) throw new Error('Insufficient NODUS balance.');
      const decoded = { recipient: request.to, amount: request.amount, fee: FEE, change: (sum - need).toString(), expiryHeight: request.expiryHeight, chainId: state.chainId, inputs };
      return { envelope: Uint8Array.of(1, 2, 3), intentId: INTENT_ID, decoded: { ...decoded, ...(state.tamper || {}) } };
    }),
    submit: ({ envelope }) => op('submit', async () => { state.submitted = envelope; return { accepted: state.accepted }; }),
    scanConfirm: request => op('scanConfirm', async () => { state.lastScan = request; return state.scan; }),
    tick: () => op('tick', async () => { if (state.tickFails) throw new Error('session closed'); }),
    cancel() { log.push('cancel'); if (state.failCancel) throw new Error('cancel failed'); },
    lock() { log.push('lock'); state.seedAtLock = bytes().subarray(SEED_AT, SEED_AT + 32).some(b => b !== 0); },
    release() { log.push('release'); state.zeroAtRelease = bytes().every(b => b === 0); }
  };
  // Holds the next call of `name` until the returned function is called.
  const gate = name => { let open; (gates[name] ||= []).push(new Promise(resolve => { open = resolve; })); return open; };
  return { module, factory: async () => module, log, state, gate };
}
