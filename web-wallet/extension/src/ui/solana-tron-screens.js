import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { renderEvmSend } from './evm-screens.js';
import { actionButton } from './views.js';
import { pageHeading } from './presentation.js';
import { displayAmount } from '../../../src/portfolio.js';
import { chainNetwork } from '../constants/networks.js';
import { terminal } from '../../../src/activity.js';

function element(document, tag, text, className = '') {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

// The existing form already lists the web-wallet config's native/token assets.
// Review rows come from the background's src/app.js:2327-2338 adaptation.
export function renderSolanaTronSend(document, container, { chain, account, review, network: networkId }, actions) {
  const network = chainNetwork(chain, review?.network ?? networkId);
  if (!review) {
    // Native-only testnets: web-wallet/src/config.js:29-30,33-35 lists mainnet
    // token addresses; no testnet deployments were supplied.
    const config = network.id === 'mainnet' ? CHAINS[chain] : { ...CHAINS[chain], tokens: [] };
    renderEvmSend(document, container, { chain, account, config }, actions);
    // web-wallet/index.html:42, src/app.js:2066.
    if (chain === 'solana' && network.id === 'mainnet') container.append(element(document, 'p', 'Token transfers use your primary associated token account. Balances held in other token accounts are included above but cannot be sent here.', 'hint'));
    if (network.id !== 'mainnet') container.append(element(document, 'p', `${network.label}. Testnet token deployments are not configured.`, 'hint'));
    return;
  }
  container.replaceChildren(pageHeading(document, `Send on ${CHAINS[chain].name}`, 'send'));
  // src/app.js:1615-1627: mainnet notice, every field as text, expiry and
  // 600 ms before confirmation. Disposal closes the timer on navigation/lock.
  container.append(element(document, 'p', `${network.label} transaction. Sending cannot be undone.`, 'notice'));
  for (const [label, value] of [...review.review, ['Review expires', new Date(review.expiresAt).toLocaleTimeString()]]) {
    container.append(element(document, 'h2', label, 'extension-field-label'), element(document, 'pre', value, 'log-line evm-result'));
  }
  const cancel = actionButton(document, 'Cancel', actions.cancel);
  const confirm = actionButton(document, 'Confirm send', () => {
    if (confirm.disabled) return;
    confirm.disabled = cancel.disabled = true; return actions.confirm(review.id);
  }, false);
  confirm.disabled = true;
  const buttons = element(document, 'div', undefined, 'actions'); buttons.append(cancel, confirm); container.append(buttons);
  const timer = setTimeout(() => { confirm.disabled = false; }, 600);
  return () => clearTimeout(timer);
}

function explorer(document, container, chain, networkId, hash) {
  container.append(element(document, 'code', hash));
  const network = chainNetwork(chain, networkId);
  // No Solana testnet explorer was supplied in the pinned references.
  if (!network.explorer) return;
  const link = element(document, 'a', 'View transaction');
  link.href = network.explorer + encodeURIComponent(hash); link.target = '_blank'; link.rel = 'noopener noreferrer';
  container.append(link);
}

// src/app.js:300-326,485-529: account transfers plus local sends with their
// network outcome/note and explorer link. All provider text uses textContent.
export function renderSolanaTronHistory(document, container, { chain, history }, { refresh, abandon }) {
  container.replaceChildren(pageHeading(document, `${(chain === 'cellframe' ? CELLFRAME : CHAINS[chain]).name} history`, 'history'));
  container.append(actionButton(document, 'Refresh history', refresh));
  if (!history) { container.append(element(document, 'p', 'Account history has not been read yet.', 'hint')); return; }
  if (history.activityError) container.append(element(document, 'p', history.activityError, 'field-error'));
  container.append(element(document, 'h2', 'Sent from here', 'activity-subhead'));
  const local = element(document, 'div', undefined, 'activity-list');
  for (const row of history.local ?? []) {
    const article = element(document, 'article', undefined, 'activity-row');
    const status = element(document, 'p', row.status, 'status-badge'); status.setAttribute('data-status', row.status);
    article.append(element(document, 'h2', `${row.amount} ${row.symbol}`), element(document, 'p', `To ${row.to}`),
      status, element(document, 'p', row.readError || row.note),
      element(document, 'time', new Date(row.createdAt).toLocaleString()));
    explorer(document, article, chain, row.network ?? history.network, row.hash);
    if (!terminal(row.status) && abandon) {
      let armed = false;
      const button = actionButton(document, 'Mark as abandoned', () => {
        if (armed) return abandon(row.hash);
        armed = true; button.textContent = 'Confirm abandon';
      }); article.append(button);
    }
    local.append(article);
  }
  container.append(local, element(document, 'h2', 'Account history', 'activity-subhead'), element(document, 'p', history.status, 'hint'));
  if (history.error) container.append(element(document, 'p', history.error, 'field-error'));
  const account = element(document, 'div', undefined, 'activity-list');
  for (const row of history.rows ?? []) {
    const article = element(document, 'article', undefined, `activity-row history-dir-${row.dir}`);
    const sign = row.dir === 'in' ? '+' : row.dir === 'out' ? '−' : '';
    // src/app.js:299,310-314: shorten peers and reuse displayAmount.
    const shortPeer = peer => peer.length > 18 ? `${peer.slice(0, 8)}…${peer.slice(-6)}` : peer;
    const what = row.dir === 'self' ? 'to yourself' : row.peer ? `${row.dir === 'in' ? 'from' : 'to'} ${shortPeer(row.peer)}` : row.dir === 'in' ? 'received' : 'sent';
    // src/app.js:311-324: compact reference rows, with transaction details
    // in their own footer. Local sends above keep their pending actions.
    const main = element(document, 'span', undefined, 'activity-main');
    main.append(element(document, 'strong', `${sign}${displayAmount(row.amount)} ${row.symbol}`), element(document, 'small', what));
    const side = element(document, 'span', undefined, 'activity-side');
    const status = element(document, 'span', row.status, 'status-badge'); status.setAttribute('data-status', row.status);
    const when = element(document, 'time', new Date(row.time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
    when.dateTime = new Date(row.time).toISOString(); side.append(status, when);
    const footer = element(document, 'div', undefined, 'activity-footer');
    const network = chainNetwork(chain, history.network);
    if (network.explorer) {
      const link = element(document, 'a', 'View transaction');
      link.href = network.explorer + encodeURIComponent(row.hash); link.target = '_blank'; link.rel = 'noopener noreferrer'; footer.append(link);
    } else footer.append(element(document, 'span', `Transaction ID ${row.hash}`, 'activity-id'));
    article.append(main, side, footer); account.append(article);
  }
  container.append(account);
}
