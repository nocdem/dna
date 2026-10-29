import { deriveWallet, disposeWallet } from '../../../src/keys.js';
import { nodusSigningSeed } from '../../../src/nodus/derive.js';
import { deriveCpunkAddress } from '../../../src/cpunk/derive.js';

export function createWalletKeys({ lockCoordinator, consumeNodusSeed }) {
  if (typeof consumeNodusSeed !== 'function') throw new Error('A Nodus seed consumer is required.');
  let current = null, generation = 0, deriving = false;

  function dispose(session) {
    if (!session) return;
    session.abort.abort();
    session.seed?.fill(0);
    session.wallet.nodusClient = null;
    disposeWallet(session.wallet);
    session.addresses = null;
  }

  function lock() {
    generation++;
    const previous = current;
    current = null;
    dispose(previous);
  }
  lockCoordinator.register('webWallet', { lock });

  function assertCurrent(session, started) {
    if (!session || session !== current || generation !== started) throw new Error('Wallet is locked.');
  }

  async function unlock(phrase, { cpunkWasmBytes, nodusWasmBytes, id, assertReady } = {}) {
    if (deriving || current) throw new Error('Lock the wallet before unlocking again.');
    // Approved plan §3.5:375-387, Q-28 "a": use the web wallet's keys,
    // not a second implementation of the snap derivation boundary.
    const session = { wallet: deriveWallet(phrase), abort: new AbortController(), seed: null, addresses: null, assertReady };
    const started = generation;
    current = session; deriving = true;
    // Operator package 5: retain deriveWallet's ethers signer in this holder.
    // disposeWallet (src/keys.js:44-49) drops it on the shared lock.
    session.wallet.recoveryPhrase = null;
    try {
      const seed = nodusSigningSeed(phrase);
      session.seed = seed;
      let identity;
      try { identity = await consumeNodusSeed(seed, { signal: session.abort.signal, phrase, id,
        addresses: session.wallet.addresses, nodusWasmBytes, assertReady }); }
      finally { seed.fill(0); session.seed = null; }
      assertCurrent(session, started);
      // src/app.js:1166,1868: other-chain recipient names use this same client.
      if (identity) {
        session.wallet.addresses.nodus = identity.fingerprint;
        session.wallet.nodusClient = identity.client;
      }
      const cpunk = await deriveCpunkAddress(phrase, { wasmBytes: cpunkWasmBytes, signal: session.abort.signal });
      assertCurrent(session, started);
      session.addresses = { ...session.wallet.addresses, cpunk };
      return { ...session.addresses };
    } catch (error) {
      const stale = session !== current || generation !== started;
      if (current === session) current = null;
      dispose(session);
      if (stale) throw new Error('Wallet is locked.');
      throw error;
    } finally { phrase = null; deriving = false; }
  }

  function activeWallet() {
    lockCoordinator.assertUnlocked();
    if (!current?.addresses || current.wallet.locked) throw new Error('Wallet is locked.');
    current.assertReady?.();
    return current;
  }

  // Library handlers must call these at the point of key use, including after
  // queued work resumes. A Solana buffer handed out here is the owned buffer
  // disposeWallet zeroes (keys.js:43-49); Tron strings can only lose references.
  // The Nodus consumer owns its module identity and joins the 'nodus' lock
  // holder (plan §3.5:407-420).
  return {
    unlock,
    getAddresses: () => ({ ...activeWallet().addresses }),
    getEvmWallet: () => activeWallet().wallet,
    getSolanaKeypair: () => activeWallet().wallet.solana,
    getTronPrivateKey: () => activeWallet().wallet.tronPrivateKey,
  };
}
