import { CHAINS } from '../../../src/config.js';
import { renderEvmSend } from './evm-screens.js';
import { actionButton } from './views.js';

function element(document, tag, text, className = '') {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

// The existing form already lists the web-wallet config's native/token assets.
// Review rows come from the background's src/app.js:2327-2338 adaptation.
export function renderSolanaTronSend(document, container, { chain, account, review }, actions) {
  if (!review) {
    renderEvmSend(document, container, { chain, account }, actions);
    // web-wallet/index.html:42, src/app.js:2066.
    if (chain === 'solana') container.append(element(document, 'p', 'Token transfers use your primary associated token account. Balances held in other token accounts are included above but cannot be sent here.', 'hint'));
    return;
  }
  container.replaceChildren(element(document, 'h1', `Send on ${CHAINS[chain].name}`));
  // src/app.js:1615-1627: mainnet notice, every field as text, expiry and
  // 600 ms before confirmation. Disposal closes the timer on navigation/lock.
  container.append(element(document, 'p', 'Mainnet transaction. Sending cannot be undone.', 'notice'));
  for (const [label, value] of [...review.review, ['Review expires', new Date(review.expiresAt).toLocaleTimeString()]]) {
    container.append(element(document, 'h2', label), element(document, 'pre', value, 'log-line evm-result'));
  }
  const cancel = actionButton(document, 'Cancel', actions.cancel);
  const confirm = actionButton(document, 'Confirm send', () => {
    if (confirm.disabled) return;
    confirm.disabled = cancel.disabled = true; return actions.confirm(review.id);
  }, false);
  confirm.disabled = true;
  container.append(cancel, confirm);
  const timer = setTimeout(() => { confirm.disabled = false; }, 600);
  return () => clearTimeout(timer);
}

function explorer(document, container, chain, hash) {
  const link = element(document, 'a', 'View transaction');
  link.href = CHAINS[chain].explorer + encodeURIComponent(hash); link.target = '_blank'; link.rel = 'noopener noreferrer';
  container.append(element(document, 'code', hash), link);
}

// src/app.js:300-326,485-529: account transfers plus local sends with their
// network outcome/note and explorer link. All provider text uses textContent.
export function renderSolanaTronHistory(document, container, { chain, history }, { refresh }) {
  container.replaceChildren(element(document, 'h1', `${CHAINS[chain].name} history`));
  container.append(actionButton(document, 'Refresh history', refresh));
  if (!history) { container.append(element(document, 'p', 'Account history has not been read yet.', 'hint')); return; }
  if (history.activityError) container.append(element(document, 'p', history.activityError, 'field-error'));
  container.append(element(document, 'h2', 'Sent from here'));
  for (const row of history.local ?? []) {
    const article = element(document, 'article', undefined, 'extension-network');
    article.append(element(document, 'h2', `${row.amount} ${row.symbol}`), element(document, 'p', `To ${row.to}`),
      element(document, 'p', row.status), element(document, 'p', row.readError || row.note),
      element(document, 'time', new Date(row.createdAt).toLocaleString()));
    explorer(document, article, chain, row.hash); container.append(article);
  }
  container.append(element(document, 'h2', 'Account history'), element(document, 'p', history.status, 'hint'));
  if (history.error) container.append(element(document, 'p', history.error, 'field-error'));
  for (const row of history.rows ?? []) {
    const article = element(document, 'article', undefined, 'extension-network');
    const sign = row.dir === 'in' ? '+' : row.dir === 'out' ? '−' : '';
    const what = row.dir === 'self' ? 'to yourself' : row.peer ? `${row.dir === 'in' ? 'from' : 'to'} ${row.peer}` : row.dir === 'in' ? 'received' : 'sent';
    article.append(element(document, 'h2', `${sign}${row.amount} ${row.symbol}`), element(document, 'p', what),
      element(document, 'p', row.status), element(document, 'time', new Date(row.time).toLocaleString()));
    explorer(document, article, chain, row.hash); container.append(article);
  }
}
