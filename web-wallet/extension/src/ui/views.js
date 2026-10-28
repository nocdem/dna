import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { NODUS_NETWORK } from '../../../src/nodus/network.js';
import { renderQr } from '../../../src/qr.js';
import { AUTO_LOCK_CHOICES } from '../../../src/auto-lock.js';
import { Caip25CaveatType, Caip25EndowmentPermissionName, getEthAccounts } from '@metamask/chain-agnostic-permission';
import { connectDetails, extensionAutoLockNote } from './wallet-ui.js';
import { NODUS_PERMISSION, NODUS_ACCOUNT_CAVEAT } from '../background/permissions.js';

// Approved plan §3.6/§7: web-wallet networks; package 5 adds real EVM balances.
export const NETWORKS = { nodus: NODUS_NETWORK, ...CHAINS, cellframe: CELLFRAME };
const addressFor = (addresses, key) => addresses?.[key === 'cellframe' ? 'cpunk' : key];
function element(document, tag, className = '', text) {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
export function actionButton(document, text, action, secondary = true) {
  const button = element(document, 'button', secondary ? 'secondary small' : '', text);
  button.type = 'button'; button.onclick = action; return button;
}
function heading(document, container, text) { container.append(element(document, 'h1', '', text)); }

export function renderHome(document, container, state, receive, send, refreshBalances, history, contracts) {
  container.replaceChildren(); heading(document, container, 'Your wallet');
  const list = element(document, 'div', 'extension-addresses');
  for (const [key, network] of Object.entries(NETWORKS)) {
    const row = element(document, 'article', 'extension-network');
    const icon = element(document, 'img', 'coin-icon');
    icon.src = new URL(`../../../src/assets/coins/${network.icon}`, import.meta.url).href; icon.alt = ''; icon.width = 36; icon.height = 36;
    const name = element(document, 'h2', '', network.name), address = addressFor(state.addresses, key);
    row.append(icon, name);
    if (address) row.append(element(document, 'code', '', address));
    else row.append(element(document, 'p', 'hint', 'Address is unavailable.'));
    const receiveButton = actionButton(document, 'Receive', () => receive(key)); receiveButton.disabled = !address;
    row.append(receiveButton); list.append(row);
    if (key === 'ethereum' || key === 'bsc') {
      const balances = state.evmBalances?.[key];
      if (Array.isArray(balances)) for (const asset of balances) row.append(element(document, 'p', 'hint', asset.error ? `${asset.symbol}: ${asset.error}` : `${asset.balance} ${asset.symbol}`));
      else row.append(element(document, 'p', 'hint', balances?.error ?? 'Balances have not been loaded.'));
      if (send) { const control = actionButton(document, 'Send', () => send(key)); control.disabled = !address; row.append(control); }
    }
    if (key === 'nodus') {
      const balances = state.nodusBalances;
      if (Array.isArray(balances)) for (const asset of balances) row.append(element(document, 'p', 'hint', asset.error ? `${asset.symbol}: Balance unavailable` : `${asset.balance} ${asset.symbol}`));
      else row.append(element(document, 'p', 'hint', balances?.error ?? 'Balances have not been loaded.'));
      if (send) { const control = actionButton(document, 'Send', () => send(key)); control.disabled = !address || state.nodus?.state !== 'ready'; row.append(control); }
      if (history) { const control = actionButton(document, 'History', history); control.disabled = !address; row.append(control); }
      if (contracts && (state.nodus?.evmBuildable || state.nodus?.evmReadable)) row.append(actionButton(document, 'Smart contracts', contracts));
    }
    if (key === 'cellframe') row.append(element(document, 'p', 'hint', state.cpunkBalance?.error ?? (state.cpunkBalance ? `${state.cpunkBalance.balance} CPUNK` : 'Balances have not been loaded.')));
  }
  container.append(list);
  if (refreshBalances) container.append(actionButton(document, 'Refresh balances', refreshBalances));
}

// src/app.js:44-47: the QR and copy control use the same raw address. No URI or amount is added.
export function renderReceive(document, container, key, addresses, copy) {
  const network = NETWORKS[key], address = addressFor(addresses, key);
  if (!network || !address) throw new Error('Receive address is unavailable.');
  container.replaceChildren(); heading(document, container, `Receive on ${network.name}`);
  const panel = element(document, 'div', 'receive-panel'), qr = element(document, 'div', 'receive-qr');
  const row = element(document, 'div', 'address-row');
  row.append(element(document, 'code', '', address), actionButton(document, 'Copy', () => copy(address)));
  panel.append(qr, row); container.append(panel); renderQr(qr, address);
}

// Port: permissions-connect.tsx:668-701, pinned v13.54.0 (799dbd71812040a5aa151095b13c68eab721719b).
// The requested accounts and networks remain explicit, editable inputs to the real pending permission request.
export function renderConnect(document, container, state, pending, { approve, reject }) {
  container.replaceChildren(); heading(document, container, 'Connect to site');
  container.append(element(document, 'p', 'extension-origin', pending.origin));
  const accountChoices = [], networkChoices = [];
  function choices(title, values, target) {
    const group = element(document, 'fieldset', 'extension-choices'); group.append(element(document, 'legend', '', title));
    for (const { value, text } of values) {
      const label = element(document, 'label', 'check'), input = element(document, 'input');
      input.type = 'checkbox'; input.value = value; input.checked = true;
      label.append(input, element(document, 'span', '', text)); group.append(label); target.push(input);
    }
    container.append(group);
  }
  let supported = true;
  try {
    const { networks } = connectDetails(pending);
    choices('Accounts to permit', (state.accounts || []).map(address => ({ value: address, text: address })), accountChoices);
    choices('Networks to permit', networks.map(network => ({ value: network.chainId, text: network.name })), networkChoices);
  } catch (error) { supported = false; container.append(element(document, 'p', 'field-error', error.message)); }
  const actions = element(document, 'div', 'actions');
  const connect = actionButton(document, 'Connect', () => approve(pending, accountChoices.filter(input => input.checked).map(input => input.value), networkChoices.filter(input => input.checked).map(input => input.value)), false);
  connect.disabled = !supported || accountChoices.length === 0;
  actions.append(actionButton(document, 'Reject', () => reject(pending)), connect); container.append(actions);
}

export function renderSites(document, container, state, revoke) {
  container.replaceChildren(); heading(document, container, 'Connected sites');
  const sites = Object.entries(state.subjects || {}).filter(([, subject]) => subject.permissions?.[Caip25EndowmentPermissionName] || subject.permissions?.[NODUS_PERMISSION]);
  if (!sites.length) container.append(element(document, 'p', 'hint', 'No connected sites.'));
  for (const [origin, subject] of sites) {
    const row = element(document, 'article', 'extension-site'), grant = subject.permissions[Caip25EndowmentPermissionName];
    row.append(element(document, 'h2', 'extension-origin', origin));
    const caveat = grant?.caveats?.find(item => item.type === Caip25CaveatType);
    if (caveat) for (const account of getEthAccounts(caveat.value)) row.append(element(document, 'code', '', account));
    const nodusAccount = subject.permissions[NODUS_PERMISSION]?.caveats?.find(item => item.type === NODUS_ACCOUNT_CAVEAT)?.value;
    if (nodusAccount) row.append(element(document, 'code', '', nodusAccount.address));
    row.append(actionButton(document, 'Disconnect', () => revoke(origin))); container.append(row);
  }
}

export function renderSettings(document, container, state, { setAutoLock, reveal, selectEvmNetwork, setEvmEndpoint, discardActivity }) {
  container.replaceChildren(); heading(document, container, 'Settings');
  const label = element(document, 'label', '', 'Auto-lock'), select = element(document, 'select');
  select.id = 'auto-lock-minutes'; label.htmlFor = select.id;
  for (const minutes of AUTO_LOCK_CHOICES) {
    const option = element(document, 'option', '', minutes === 0 ? 'Never' : minutes === 60 ? '1 hour' : `${minutes} minutes`);
    option.value = String(minutes); select.append(option);
  }
  select.value = String(state.preferences.autoLockTimeLimit);
  select.onchange = () => setAutoLock(Number(select.value));
  const note = element(document, 'p', 'hint', extensionAutoLockNote(state.preferences.autoLockTimeLimit));
  container.append(label, select, note);
  // src/app.js:2559-2560, 2672-2690: explicit recovery in saved-wallet settings.
  if (state.nodus?.activityError || state.nodus?.quarantinedCount) {
    container.append(element(document, 'h2', '', 'Saved activity'));
    if (state.nodus.activityError) container.append(element(document, 'p', 'field-error', state.nodus.activityError));
    else container.append(element(document, 'p', 'hint', `${state.nodus.quarantinedCount} saved records could not be read; their coins stay held.`));
    container.append(element(document, 'p', 'hint', 'Check the explorer before discarding the unreadable history or resending any previous payment.'),
      actionButton(document, 'Discard unreadable history', discardActivity));
  }
  if (state.evm) {
    const caption = element(document, 'label', '', 'Selected EVM network'), network = element(document, 'select');
    caption.htmlFor = network.id = 'evm-network';
    for (const chain of ['ethereum', 'bsc']) {
      const option = element(document, 'option', '', CHAINS[chain].name); option.value = chain; network.append(option);
    }
    network.value = state.evm.selectedChain; network.onchange = () => selectEvmNetwork(network.value);
    container.append(caption, network, element(document, 'p', 'hint', 'Every connected site uses this network.'));
    for (const chain of ['ethereum', 'bsc']) {
      const rpcLabel = element(document, 'label', '', `${CHAINS[chain].name} RPC provider`), rpc = element(document, 'select');
      rpcLabel.htmlFor = rpc.id = `evm-rpc-${chain}`;
      for (const provider of CHAINS[chain].rpcOptions) {
        const option = element(document, 'option', '', provider.note ? `${provider.label} — ${provider.note}` : provider.label); option.value = provider.url; rpc.append(option);
      }
      rpc.value = state.evm.endpoints[chain]; rpc.onchange = () => setEvmEndpoint(chain, rpc.value); container.append(rpcLabel, rpc);
    }
  }
  container.append(element(document, 'h2', '', 'Reveal recovery phrase'));
  const form = element(document, 'form'), passwordLabel = element(document, 'label', '', 'Re-enter your password');
  const password = element(document, 'input'); password.id = 'reveal-password'; password.type = 'password';
  password.autocomplete = 'current-password'; password.required = true; password.maxLength = 1024; passwordLabel.htmlFor = password.id;
  const submit = element(document, 'button', '', 'Reveal phrase'); submit.type = 'submit';
  const recovery = element(document, 'div'); recovery.hidden = true;
  form.append(passwordLabel, password, submit);
  form.onsubmit = event => { event.preventDefault(); const entered = password.value; password.value = ''; return reveal(entered, recovery); };
  container.append(form, recovery);
  return { password, recovery, select };
}
