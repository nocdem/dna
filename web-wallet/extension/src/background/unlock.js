export function createUnlock({ vaultStore, lockCoordinator, walletKeys }) {
  let pending = false;

  // vault-store's inner unlock opens the coordinator before the outer one
  // finishes. Both holders also consult this guard at the point of key use.
  function assertReady() {
    if (pending) throw new Error('Wallet is locked.');
  }

  return async function unlock(password, options) {
    if (pending) throw new Error('Unlock is already pending.');
    pending = true;
    try {
      // Dispose a previous identity before authenticating a replacement.
      const errors = await lockCoordinator.lock();
      if (errors.length) throw errors[0].error;
      return await lockCoordinator.unlock(async () => {
        let authenticated;
        try {
          // vault-store already uses this same coordinator. The outer unlock
          // spans both derivations too, so a lock invalidates the entire hand-over.
          authenticated = await vaultStore.unlock(password);
          lockCoordinator.assertUnlocked();
          password = null;
          const deriving = walletKeys.unlock(authenticated.phrase, { ...options, assertReady });
          authenticated.phrase = null;
          const addresses = await deriving;
          lockCoordinator.assertUnlocked();
          return { id: authenticated.id, addresses };
        } finally {
          if (authenticated) authenticated.phrase = null;
          password = null;
        }
      });
    } catch (error) {
      // Authentication can succeed before a later derivation fails. Roll back
      // through the one lock operation, including the injected Nodus holder.
      await lockCoordinator.lock();
      throw error;
    } finally { password = null; pending = false; }
  };
}
