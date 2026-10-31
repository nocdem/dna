import { createMessagesSession } from '../../../src/connect/ui/messages.js';
import { mountReferenceWallet } from './wallet-screen.js';
import '../../../src/connect/ui/messenger.css';
import './connect.css';

// Both views retain their forms in this window. Only the worker owns the
// Connect session; closing a window drops this public projection and drafts.
export function mountWalletAndConnect(options) {
  const { document, root, ui } = options;
  const walletRoot = document.createElement('div'), connectRoot = document.createElement('section');
  const corner = document.createElement('div'), toggle = document.createElement('button');
  const connectLock = document.createElement('button'), result = document.createElement('p');
  corner.className = 'wallet-connect-switch'; toggle.type = connectLock.type = 'button';
  toggle.id = 'wallet-connect-switch'; toggle.textContent = 'Connect';
  toggle.setAttribute('aria-label', 'Switch to Connect'); toggle.setAttribute('aria-pressed', 'false');
  connectLock.textContent = 'Lock wallet'; connectLock.className = 'secondary small'; connectLock.hidden = true;
  connectRoot.id = 'extension-connect'; connectRoot.hidden = true;
  connectRoot.setAttribute('aria-label', 'Nodus Connect');
  result.className = 'hint'; result.setAttribute('role', 'status');
  const messagesRoot = document.createElement('div'); connectRoot.append(messagesRoot, result);
  corner.append(toggle, connectLock); root.replaceChildren(corner, walletRoot, connectRoot);
  let disposed = false, showing = false, epoch, identity, reading = false, readAgain = false;
  let wallet;
  const remote = async (action, fields) => {
    if (disposed || epoch === undefined) throw new Error('Connect is opening.');
    const started = epoch;
    try {
      const value = await ui.request('connectAction', [started, action, fields]);
      if (disposed || epoch !== started) throw new Error('This Connect session has closed.');
      await refresh(); return value;
    } catch (error) {
      if (!disposed && epoch === started) result.textContent = error.message;
      throw error;
    }
  };
  const session = createMessagesSession({ remote });
  session.mountMessages(messagesRoot, { payContact(fp) { show(false); wallet.payContact(fp); } });
  ui.connectHost = session.vaultHost;
  wallet = mountReferenceWallet({ ...options, root: walletRoot });
  function show(connect) {
    showing = connect;
    walletRoot.hidden = showing; connectRoot.hidden = !showing; connectLock.hidden = !showing;
    toggle.textContent = showing ? 'Wallet' : 'Connect';
    toggle.setAttribute('aria-label', showing ? 'Switch to Wallet' : 'Switch to Connect');
    toggle.setAttribute('aria-pressed', String(showing));
    if (showing) { session.setVisible(true); void refresh(); }
    else session.setVisible(false);
  }
  toggle.onclick = () => show(!showing);
  connectLock.onclick = options.lock;
  async function refresh() {
    if (disposed) return;
    if (reading) { readAgain = true; return; }
    reading = true;
    try {
      do {
        readAgain = false;
        const value = await ui.request('getConnectState');
        if (disposed || !ui.state.isUnlocked) return;
        if (epoch !== undefined && value.epoch < epoch) continue;
        const nextIdentity = value.ownFp;
        if ((identity && nextIdentity && identity !== nextIdentity) || (epoch !== undefined && value.epoch !== epoch)) {
          session.resetMessages(); result.textContent = '';
        }
        epoch = value.epoch; identity = nextIdentity || identity;
        session.applySnapshot(value);
      } while (readAgain && !disposed);
    } catch (error) { if (!disposed && showing) result.textContent = error.message; }
    finally { reading = false; }
  }
  session.setVisible(false); void refresh();
  return {
    refreshConnect() { void refresh(); },
    update() { if (!disposed) { wallet.update(); void refresh(); } },
    loadBalances: force => wallet.loadBalances(force),
    dispose() {
      disposed = true; epoch = undefined; identity = undefined;
      session.dispose(); ui.connectHost = undefined;
      wallet.dispose(); connectRoot.replaceChildren(); corner.remove();
    }
  };
}
