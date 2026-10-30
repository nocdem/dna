import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { NODUS_NETWORK } from '../../../src/nodus/network.js';
import { renderQr } from '../../../src/qr.js';
import { AUTO_LOCK_CHOICES } from '../../../src/auto-lock.js';
import { Caip25CaveatType, Caip25EndowmentPermissionName, getEthAccounts } from '@metamask/chain-agnostic-permission';
import { connectDetails, extensionAutoLockNote } from './wallet-ui.js';
import { NODUS_PERMISSION, NODUS_ACCOUNT_CAVEAT } from '../background/permissions.js';
import { CHAIN_NETWORKS, chainNetwork } from '../constants/networks.js';
import { appIcon, pageHeading } from './presentation.js';
import { displayAmount } from '../../../src/portfolio.js';

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
function heading(document, container, text, icon) { container.append(pageHeading(document, text, icon)); }

export function renderHome(document, container, state, receive, send, refreshBalances, history, contracts, solanaTronHistory, sections = []) {
  container.replaceChildren();
  const card = element(document, 'section', 'portfolio-card'), cardHead = element(document, 'div', 'portfolio-heading');
  card.setAttribute('aria-labelledby', 'portfolio-label');
  const label = element(document, 'p', 'eyebrow', state.portfolio?.label ?? 'Estimated portfolio value'); label.id = 'portfolio-label';
  const total = element(document, 'span', '', state.portfolio?.total ?? '—'); total.id = 'portfolio-total';
  const status = element(document, 'p', '', state.portfolio?.status ?? 'Balances load when you open your wallet.');
  status.id = 'portfolio-status'; status.role = 'status';
  const amount = element(document, 'p', 'portfolio-amount'); amount.append(total, element(document, 'span', 'portfolio-currency', 'USD'));
  cardHead.append(amount); card.append(cardHead, label, status);
  if (refreshBalances) {
    const refresh = actionButton(document, 'Refresh balances', refreshBalances); refresh.id = 'portfolio-refresh'; card.append(refresh);
  }
  const source = element(document, 'p', 'price-source', 'Indicative USD prices from '), link = element(document, 'a', '', 'DefiLlama');
  link.href = 'https://defillama.com/'; link.target = '_blank'; link.rel = 'noopener noreferrer';
  source.append(link, element(document, 'span', '', '. This estimate is not a sale quote.'));
  container.append(card);
  if (sections.length) {
    const navigation = element(document, 'nav', 'wallet-navigation'); navigation.setAttribute('aria-label', 'Wallet sections');
    for (const { label, icon, run } of sections) {
      const button = actionButton(document, '', run); button.className = 'extension-section';
      button.append(appIcon(document, icon), element(document, 'span', 'nav-name', label)); navigation.append(button);
    }
    container.append(navigation);
  }
  const assets = element(document, 'section', 'dashboard-panel assets-panel'), head = element(document, 'div', 'panel-heading');
  head.append(element(document, 'h2', '', 'Your assets')); assets.append(head);
  const list = element(document, 'div', 'extension-addresses');
  for (const [key, network] of Object.entries(NETWORKS)) {
    const row = element(document, 'article', 'extension-network');
    const icon = element(document, 'img', 'coin-icon');
    icon.src = new URL(`../../../src/assets/coins/${network.icon}`, import.meta.url).href; icon.alt = ''; icon.width = 36; icon.height = 36;
    const selected = chainNetwork(key, state.networks?.[key]);
    const name = element(document, 'h2', '', `${network.name}${selected.id === 'mainnet' ? '' : ` · ${selected.label}`}`), address = addressFor(state.addresses, key);
    const header = element(document, 'div', 'extension-network-head'), identity = element(document, 'div', 'extension-network-name');
    identity.append(name);
    if (address) { const code = element(document, 'code', '', address); code.title = address; identity.append(code); }
    else identity.append(element(document, 'p', 'hint', 'Address is unavailable.'));
    header.append(icon, identity); row.append(header);
    const actionsRow = element(document, 'div', 'extension-holding-actions'), actions = element(document, 'div', 'holding-actions');
    const holding = (symbol, balance, error) => {
      const entry = element(document, 'div', 'chain-holding extension-holding');
      const text = error ? `${symbol}: ${error}` : `${displayAmount(balance)} ${symbol}`;
      const amount = element(document, 'strong', error ? 'field-error' : '', text); amount.title = error ? text : `${balance} ${symbol}`;
      entry.append(element(document, 'span', 'holding-network', symbol), amount); row.append(entry);
    };
    const sendButton = disabled => {
      if (!send) return;
      const control = actionButton(document, 'Send', () => send(key), false);
      control.className = 'small extension-send'; control.disabled = disabled; actions.append(control);
    };
    const receiveButton = actionButton(document, 'Receive', () => receive(key)); receiveButton.disabled = !address;
    receiveButton.className += ' extension-receive';
    if (key === 'ethereum' || key === 'bsc') {
      const balances = state.evmBalances?.[key];
      if (Array.isArray(balances)) for (const asset of balances) holding(asset.symbol, asset.balance, asset.error);
      else row.append(element(document, 'p', 'hint', balances?.error ?? 'Balances have not been loaded.'));
      sendButton(!address);
    }
    // Package 7a uses the web-wallet adapters/config, alongside package 5's
    // EVM rows; Receive already renders these same background addresses.
    if (key === 'solana' || key === 'tron') {
      const balances = state.solanaTronBalances?.[key];
      if (Array.isArray(balances)) for (const asset of balances) holding(asset.symbol, asset.balance, asset.error);
      else row.append(element(document, 'p', 'hint', balances?.error ?? 'Balances have not been loaded.'));
      sendButton(!address);
    }
    if (key === 'nodus') {
      const balances = state.nodusBalances;
      if (Array.isArray(balances)) for (const asset of balances) holding(asset.symbol, asset.balance, asset.error ? 'Balance unavailable' : undefined);
      else row.append(element(document, 'p', 'hint', balances?.error ?? 'Balances have not been loaded.'));
      sendButton(!address || state.nodus?.state !== 'ready');
    }
    if (key === 'cellframe') {
      if (state.cpunkBalance && !state.cpunkBalance.error) holding('CPUNK', state.cpunkBalance.balance);
      else row.append(element(document, 'p', 'hint', state.cpunkBalance?.error ?? 'Balances have not been loaded.'));
    }
    actions.append(receiveButton);
    if (key === 'nodus') {
      if (history) { const control = actionButton(document, 'History', history); control.disabled = !address; actions.append(control); }
      if (contracts && (state.nodus?.evmBuildable || state.nodus?.evmReadable)) actions.append(actionButton(document, 'Smart contracts', contracts));
    }
    if ((key === 'solana' || key === 'tron') && solanaTronHistory) { const control = actionButton(document, 'History', () => solanaTronHistory(key)); control.disabled = !address; actions.append(control); }
    actionsRow.append(actions); row.append(actionsRow); list.append(row);
  }
  assets.append(list, source); container.append(assets);
  return { label, total, status };
}

// src/app.js:44-47: the QR and copy control use the same raw address. No URI or amount is added.
export function renderReceive(document, container, key, addresses, copy) {
  const network = NETWORKS[key], address = addressFor(addresses, key);
  if (!network || !address) throw new Error('Receive address is unavailable.');
  container.replaceChildren(); heading(document, container, `Receive on ${network.name}`, 'receive');
  const panel = element(document, 'div', 'receive-panel'), qr = element(document, 'div', 'receive-qr');
  const row = element(document, 'div', 'address-row');
  row.append(element(document, 'code', '', address), actionButton(document, 'Copy', () => copy(address)));
  panel.append(qr, row); container.append(panel); renderQr(qr, address);
}

// Port: permissions-connect.tsx:668-701, pinned v13.54.0 (799dbd71812040a5aa151095b13c68eab721719b).
// The requested accounts and networks remain explicit, editable inputs to the real pending permission request.
export function renderConnect(document, container, state, pending, { approve, reject }) {
  container.replaceChildren(); heading(document, container, 'Connect to site', 'sites');
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
  container.replaceChildren(); heading(document, container, 'Connected sites', 'sites');
  const sites = Object.entries(state.subjects || {}).filter(([, subject]) => subject.permissions?.[Caip25EndowmentPermissionName] || subject.permissions?.[NODUS_PERMISSION]);
  if (!sites.length) { container.append(element(document, 'p', 'hint', 'No connected sites.')); return; }
  const list = element(document, 'div', 'address-book-list');
  for (const [origin, subject] of sites) {
    const row = element(document, 'article', 'extension-site address-book-row'), grant = subject.permissions[Caip25EndowmentPermissionName];
    const main = element(document, 'div', 'address-book-main');
    main.append(element(document, 'h2', '', origin));
    const caveat = grant?.caveats?.find(item => item.type === Caip25CaveatType);
    if (caveat) for (const account of getEthAccounts(caveat.value)) main.append(element(document, 'code', 'address-book-address', account));
    const nodusAccount = subject.permissions[NODUS_PERMISSION]?.caveats?.find(item => item.type === NODUS_ACCOUNT_CAVEAT)?.value;
    if (nodusAccount) main.append(element(document, 'code', 'address-book-address', nodusAccount.address));
    row.append(main, actionButton(document, 'Disconnect', () => revoke(origin))); list.append(row);
  }
  container.append(list);
}

export function renderSettings(document, container, state, { setAutoLock, reveal, selectEvmNetwork, setEvmEndpoint, discardActivity, setChainNetwork }) {
  container.replaceChildren(); heading(document, container, 'Settings', 'settings');
  const label = element(document, 'label', '', 'Auto-lock'), select = element(document, 'select');
  select.id = 'auto-lock-minutes'; label.htmlFor = select.id;
  for (const minutes of AUTO_LOCK_CHOICES) {
    const option = element(document, 'option', '', minutes === 0 ? 'Never' : minutes === 60 ? '1 hour' : `${minutes} minutes`);
    option.value = String(minutes); select.append(option);
  }
  select.value = String(state.preferences.autoLockTimeLimit);
  select.onchange = () => setAutoLock(Number(select.value));
  const note = element(document, 'p', 'hint', extensionAutoLockNote(state.preferences.autoLockTimeLimit));
  const autoLock = element(document, 'div', 'page-block auto-lock'); autoLock.append(label, select, note); container.append(autoLock);
  const chainNetworks = element(document, 'div', 'page-block');
  // Operator §0 / plan §5.6: selectors belong here; no switch at the top.
  for (const [chain, choices] of Object.entries(CHAIN_NETWORKS)) {
    const caption = element(document, 'label', '', `${NETWORKS[chain].name} network`), network = element(document, 'select');
    caption.htmlFor = network.id = `network-${chain}`;
    for (const choice of choices) {
      const option = element(document, 'option', '', choice.label); option.value = choice.id; network.append(option);
    }
    network.value = chainNetwork(chain, state.networks?.[chain]).id;
    network.onchange = () => setChainNetwork(chain, network.value);
    chainNetworks.append(caption, network);
  }
  container.append(chainNetworks);
  // src/app.js:2559-2560, 2672-2690: explicit recovery in saved-wallet settings.
  if (state.nodus?.activityError || state.nodus?.quarantinedCount) {
    const activity = element(document, 'div', 'page-block'); activity.append(element(document, 'h2', '', 'Saved activity'));
    if (state.nodus.activityError) activity.append(element(document, 'p', 'field-error', state.nodus.activityError));
    else activity.append(element(document, 'p', 'hint', `${state.nodus.quarantinedCount} saved records could not be read; their coins stay held.`));
    activity.append(element(document, 'p', 'hint', 'Check the explorer before discarding the unreadable history or resending any previous payment.'),
      actionButton(document, 'Discard unreadable history', discardActivity));
    container.append(activity);
  }
  if (state.evm) {
    const evm = element(document, 'div', 'page-block');
    const caption = element(document, 'label', '', 'Selected EVM network'), network = element(document, 'select');
    caption.htmlFor = network.id = 'evm-network';
    for (const chain of ['ethereum', 'bsc']) {
      const option = element(document, 'option', '', CHAINS[chain].name); option.value = chain; network.append(option);
    }
    network.value = state.evm.selectedChain; network.onchange = () => selectEvmNetwork(network.value);
    evm.append(caption, network, element(document, 'p', 'hint', 'Every connected site uses this network.'));
    for (const chain of ['ethereum', 'bsc']) {
      const rpcLabel = element(document, 'label', '', `${CHAINS[chain].name} RPC provider`), rpc = element(document, 'select');
      rpcLabel.htmlFor = rpc.id = `evm-rpc-${chain}`;
      for (const provider of CHAINS[chain].rpcOptions) {
        const option = element(document, 'option', '', provider.note ? `${provider.label} — ${provider.note}` : provider.label); option.value = provider.url; rpc.append(option);
      }
      rpc.value = state.evm.endpoints[chain]; rpc.onchange = () => setEvmEndpoint(chain, rpc.value); evm.append(rpcLabel, rpc);
    }
    container.append(evm);
  }
  const revealBlock = element(document, 'div', 'page-block'); revealBlock.append(element(document, 'h2', '', 'Reveal recovery phrase'));
  const form = element(document, 'form'), passwordLabel = element(document, 'label', '', 'Re-enter your password');
  const password = element(document, 'input'); password.id = 'reveal-password'; password.type = 'password';
  password.autocomplete = 'current-password'; password.required = true; password.maxLength = 1024; passwordLabel.htmlFor = password.id;
  const submit = element(document, 'button', '', 'Reveal phrase'); submit.type = 'submit';
  const recovery = element(document, 'div'); recovery.hidden = true;
  form.append(passwordLabel, password, submit);
  form.onsubmit = event => { event.preventDefault(); const entered = password.value; password.value = ''; return reveal(entered, recovery); };
  revealBlock.append(form, recovery); container.append(revealBlock);
  return { password, recovery, select };
}
