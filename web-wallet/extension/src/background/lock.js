// Approved extension plan §3.5: keyring, web-wallet disposal, complete Nodus
// client lock, then the two chain libraries. Later packages supply the holders.
export const LOCK_ORDER = Object.freeze(['keyring', 'webWallet', 'nodus', 'solana', 'tron']);

export function createLockCoordinator() {
  const holders = new Map();
  let locked = true, generation = 0, pendingLock = null;

  function assertUnlocked() {
    if (locked) throw new Error('Wallet is locked.');
  }

  function register(name, holder) {
    if (!LOCK_ORDER.includes(name)) throw new Error('Unknown key holder.');
    if (typeof holder?.lock !== 'function') throw new Error('A key holder must provide lock().');
    if (holders.has(name)) throw new Error('Key holder is already registered.');
    if (pendingLock) throw new Error('Wallet is locked while disposal is pending.');
    holders.set(name, holder);
  }

  // The vault supplies the authentication operation; a lock invalidates any
  // authentication already waiting on storage or password derivation.
  async function unlock(authenticate) {
    if (pendingLock) throw new Error('Wallet is locked while disposal is pending.');
    if (typeof authenticate !== 'function') throw new Error('Unlock requires authentication.');
    const started = generation;
    const result = await authenticate();
    if (generation !== started || pendingLock) throw new Error('Wallet is locked.');
    locked = false;
    return result;
  }

  function lock() {
    if (pendingLock) return pendingLock;
    locked = true;
    generation++;
    const registered = LOCK_ORDER.filter(name => holders.has(name)).map(name => [name, holders.get(name)]);
    let complete;
    const result = new Promise(resolve => { complete = resolve; });
    pendingLock = result;
    // Publish the locked state and shared promise before invoking any holder.
    // Return failures to the caller without allowing one holder to skip others.
    (async () => {
      const errors = [];
      for (const [name, holder] of registered) {
        try { await holder.lock(); }
        catch (error) { errors.push({ name, error }); }
      }
      pendingLock = null;
      complete(errors);
    })();
    return result;
  }

  return { register, unlock, lock, assertUnlocked, get isLocked() { return locked; } };
}
