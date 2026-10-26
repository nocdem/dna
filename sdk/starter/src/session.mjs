import { acquireJournal } from './journal.mjs';

// Dependencies are explicit for offline tests. The CLI passes only the real SDK.
export async function withAccount({ sdk, phrase, config, stateDir, write, confirm, run }) {
  if (write && typeof confirm !== 'function') throw new Error('A confirm function is required.');
  const identity = await sdk.deriveIdentity(phrase);
  const journal = await acquireJournal({ stateDir, chainId: config.network.chainId, fingerprint: identity.fingerprint });
  let evm;
  try {
    evm = await sdk.NodusEvm.open({ phrase, network: config.network, evm: config.evm, pending: journal.pending() });
    if (evm.fingerprint !== identity.fingerprint || evm.chainId !== config.network.chainId) throw new Error('SDK identity or chain differs from the journal.');
    await evm.connect();
    if (!evm.evmActive) throw new Error('Smart contracts are not active on the connected node.');
    await evm.checkPending();
    await journal.replace(evm.pending());
    if (write && evm.pending().length) throw new Error('A pending transaction still reserves this identity. Run pending again after it is included or expires; do not replace it.');
    const result = await run(evm, { maxFee: config.maxFee, confirm, onRecord: row => journal.record(row) });
    if (write) {
      if (!['applied-success', 'applied-failed', 'refused'].includes(result?.status)) throw new Error('Write outcome is not definitive; pending record retained.');
      await journal.replace(evm.pending());
    }
    return result;
  } finally {
    // Never copy the SDK map back on an exception: onRecord may have renamed
    // pending.json and then failed its directory fsync BEFORE SDK map insertion.
    try { evm?.close(); } finally { await journal.close(); }
  }
}
