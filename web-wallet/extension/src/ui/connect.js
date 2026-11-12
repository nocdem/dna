import { createMessagesSession } from '../../../src/connect/ui/messages.js';
import { mountReferenceWallet } from './wallet-screen.js';
import '../../../src/connect/ui/messenger.css';
import './connect.css';

// Icons of the approved mockup (ext-mock.mjs, mode icons3). Static markup, no data.
const BAR_ICONS = {
  connect: '<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M5 5h14v10H9l-4 4z"/></svg>',
  wallet: '<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="6" width="18" height="13" rx="2.5"/><path d="M16 12.5h2.5"/><path d="M3 9h15"/></svg>',
  settings: '<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
};

// Both views retain their forms in this window. Only the worker owns the
// Connect session; closing a window drops this public projection and drafts.
// The bottom bar (Connect, Wallet, Settings) switches between them; locking
// stays on the wallet home's lock icon (#lock) only.
export function mountWalletAndConnect(options) {
  const { document, root, ui } = options;
  const walletRoot = document.createElement('div'), connectRoot = document.createElement('section');
  const result = document.createElement('p');
  connectRoot.id = 'extension-connect'; connectRoot.hidden = true;
  connectRoot.setAttribute('aria-label', 'Nodus Connect');
  result.className = 'hint'; result.setAttribute('role', 'status');
  const messagesRoot = document.createElement('div'); connectRoot.append(messagesRoot, result);
  const bar = document.createElement('nav'), buttons = {}, badge = document.createElement('span');
  bar.id = 'extension-bottom-bar'; bar.className = 'extension-bottom-bar'; bar.setAttribute('aria-label', 'Wallet and Connect');
  badge.className = 'extension-bottom-badge'; badge.setAttribute('aria-hidden', 'true'); badge.hidden = true;
  for (const [key, label] of [['connect', 'Connect'], ['wallet', 'Wallet'], ['settings', 'Settings']]) {
    const entry = document.createElement('button'); entry.type = 'button'; entry.innerHTML = BAR_ICONS[key];
    entry.setAttribute('aria-label', label); buttons[key] = entry; bar.append(entry);
  }
  buttons.connect.append(badge);
  root.replaceChildren(walletRoot, connectRoot, bar);
  let disposed = false, showing = false, epoch, identity, reading = false, readAgain = false;
  let wallet, walletPage = null, unread = 0;
  function updateBar() {
    const current = showing ? 'connect' : walletPage === 'settings' ? 'settings' : 'wallet';
    for (const [key, entry] of Object.entries(buttons)) {
      if (key === current) entry.setAttribute('aria-current', 'page'); else entry.removeAttribute('aria-current');
    }
    const count = showing ? 0 : unread;
    badge.hidden = count <= 0; badge.textContent = count > 99 ? '99+' : String(Math.max(count, 0));
    buttons.connect.setAttribute('aria-label', count > 0 ? `Connect, ${count} new` : 'Connect');
  }
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
  session.mountMessages(messagesRoot, {
    payContact(fp) { show(false); wallet.payContact(fp); },
    onUnread(count) { unread = Number(count) || 0; updateBar(); },
  });
  ui.connectHost = session.vaultHost;
  wallet = mountReferenceWallet({ ...options, root: walletRoot, onPage(name) { walletPage = name; updateBar(); } });
  // "Send NODUS" in a chat is offered only while the wallet's NODUS network can send.
  const syncSendNodus = () => session.walletExtension.nodusSendable({ sendable: wallet.canSend('nodus') });
  syncSendNodus();
  function show(connect) {
    showing = connect;
    walletRoot.hidden = showing; connectRoot.hidden = !showing;
    if (showing) { session.setVisible(true); void refresh(); }
    else { session.setVisible(false); wallet.resetAssetView(); }
    updateBar();
  }
  // Shown recovery words go with the Settings page (approved rule: removed on leaving Settings).
  buttons.connect.onclick = () => showConnect();
  buttons.wallet.onclick = () => {
    if (showing) show(false);
    // Any other kept wallet page (for example a Send draft) stays, as the former switch kept it.
    if (walletPage === 'settings') wallet.navigate(null);
  };
  buttons.settings.onclick = () => {
    if (showing) show(false);
    if (walletPage !== 'settings') wallet.navigate('settings');
  };
  updateBar();
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
  // The same steps as pressing the Connect button; also the entry for a page asked to show Connect.
  const showConnect = () => { if (disposed || showing) return; wallet.leaveSettings(); show(true); };
  if (options.startConnect) showConnect();
  return {
    showConnect,
    refreshConnect() { void refresh(); },
    update() { if (!disposed) { wallet.update(); syncSendNodus(); void refresh(); } },
    loadBalances: force => wallet.loadBalances(force),
    dispose() {
      disposed = true; epoch = undefined; identity = undefined;
      session.dispose(); ui.connectHost = undefined;
      wallet.dispose(); connectRoot.replaceChildren(); bar.remove();
    }
  };
}
