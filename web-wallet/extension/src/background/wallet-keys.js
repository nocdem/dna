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

  async function unlock(phrase, { cpunkWasmBytes, assertReady } = {}) {
    if (deriving || current) throw new Error('Lock the wallet before unlocking again.');
    // Approved plan §3.5:375-387, Q-28 "a": use the web wallet's keys,
    // not a second implementation of the snap derivation boundary.
    const session = { wallet: deriveWallet(phrase), abort: new AbortController(), seed: null, addresses: null, assertReady };
    const started = generation;
    current = session; deriving = true;
    // EVM custody is the HD keyring; this holder needs neither the phrase nor
    // deriveWallet's extra EVM signer after the synchronous derivation.
    session.wallet.recoveryPhrase = null;
    session.wallet.evm = null;
    try {
      const seed = nodusSigningSeed(phrase);
      session.seed = seed;
      try { await consumeNodusSeed(seed, { signal: session.abort.signal }); }
      finally { seed.fill(0); session.seed = null; }
      assertCurrent(session, started);
      const cpunk = await deriveCpunkAddress(phrase, { wasmBytes: cpunkWasmBytes, signal: session.abort.signal });
      assertCurrent(session, started);
      session.addresses = { solana: session.wallet.addresses.solana, tron: session.wallet.addresses.tron, cpunk };
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
  // The supplied Nodus consumer owns its module identity and registers the
  // separate 'nodus' lock holder in package 6 (plan §3.5:407-420).
  return {
    unlock,
    getAddresses: () => ({ ...activeWallet().addresses }),
    getSolanaKeypair: () => activeWallet().wallet.solana,
    getTronPrivateKey: () => activeWallet().wallet.tronPrivateKey,
  };
}
