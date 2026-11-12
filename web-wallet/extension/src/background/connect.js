import { createMessagesSession } from '../../../src/connect/ui/messages.js';
import { counterStorageKey, deleteVaultHistory, StorageError, MAX_INVOCATIONS } from '../../../src/connect/store.js';

const ACTIONS = new Set([
  'sync', 'retry', 'markRead', 'contactAdd', 'contactAccept', 'contactDecline',
  'contactWithdraw', 'contactRemove', 'messageSend', 'messageReact', 'messageDelete',
  'profileSave', 'avatarSave', 'historyErase', 'transferCheck', 'peerRefresh', 'payStart',
  'groupCheckPeople', 'groupCreate', 'groupInvite', 'groupAccept', 'groupIgnore',
  'groupLeave', 'groupRemove', 'groupSend', 'groupMarkRead', 'vaultSend', 'vaultKeep', 'vaultDrop'
]);

// The worker is the sole history owner across every trusted wallet window.
// Counter operations share a queue, including removal after a saved-wallet
// delete. Closing a session prevents a late reservation from being sealed.
export function createConnect({ storage, sessionFactory = createMessagesSession,
  deleteHistory = deleteVaultHistory, onChange } = {}) {
  let epoch = 0, client, session, pending = Promise.resolve();
  let closingText = 'Messages opens as soon as your wallet is open.';
  const enqueue = run => {
    const job = pending.catch(() => {}).then(run);
    pending = job; return job;
  };
  const counterStorage = {
    read(name) {
      return enqueue(async () => {
        const key = counterStorageKey(name), saved = await storage.get(key), value = saved[key];
        if (value === undefined) return 0n;
        if (typeof value !== 'string' || !/^(0|[1-9]\d{0,19})$/.test(value) || BigInt(value) > MAX_INVOCATIONS) throw new StorageError('The stored message counter is damaged.');
        return BigInt(value);
      });
    },
    write(name, count) {
      return enqueue(async () => {
        if (typeof count !== 'bigint' || count < 0n || count > MAX_INVOCATIONS) throw new StorageError('Invalid counter.');
        try { await storage.set({ [counterStorageKey(name)]: count.toString() }); }
        catch { throw new StorageError('Message history could not be saved (the message counter could not be stored).'); }
      });
    },
    remove: name => enqueue(() => storage.remove(counterStorageKey(name)))
  };
  function close(expectedClient) {
    if (expectedClient && client !== expectedClient) return;
    epoch++;
    const previous = session; session = undefined; client = undefined;
    // Synchronous cancellation and core/store disposal precede client.lock.
    try { previous?.close(); } finally { onChange?.(); }
  }
  async function open(detail) {
    if (client === detail.client && session) return;
    close();
    const currentEpoch = epoch;
    client = detail.client;
    let opened;
    opened = session = sessionFactory({ counterStorage, onChange: () => {
      if (epoch === currentEpoch && session === opened) onChange?.();
    } });
    try { await opened.open(detail); }
    catch (error) {
      if (epoch !== currentEpoch || session !== opened) return;
      closingText = 'Your messages on this device could not be opened right now. Try again.';
      opened.closeMessages?.(closingText, { retry: true });
    }
    if (epoch === currentEpoch && session === opened) onChange?.();
  }
  function ready(readyClient) {
    if (client === readyClient && session) session.ready({ client: readyClient });
  }
  function getState() {
    return { epoch, ...(session ? session.snapshot() : {
      phase: 'waiting', title: 'Messages', text: closingText, retry: false,
      online: false, caughtUp: false, ownFp: null, persistent: false,
      contacts: [], outgoing: [], requests: [], messages: [], profiles: [], groups: [], invitations: [], vaults: []
    }) };
  }
  async function action(requestEpoch, name, fields = {}) {
    const current = session, currentClient = client;
    const assertCurrent = () => {
      if (!current || requestEpoch !== epoch || session !== current || client !== currentClient) throw new Error('This Connect session has closed.');
    };
    assertCurrent();
    if (!ACTIONS.has(name) || !fields || typeof fields !== 'object' || Array.isArray(fields)) throw new Error('Invalid Connect action.');
    const result = await current.action(name, fields);
    assertCurrent(); onChange?.(); return result;
  }
  const unread = () => session?.unread?.() ?? { count: 0, caughtUp: false };
  return { open, ready, close, getState, action, unread,
    sent: detail => session?.walletExtension.nodusSent(detail),
    async deleteHistory(vaultId) { close(); await deleteHistory(vaultId, undefined, counterStorage); }
  };
}
