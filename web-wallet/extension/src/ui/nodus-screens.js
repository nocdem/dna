import { NODUS_TOKEN_ID } from '../../../src/nodus/network.js';
import { nodusHistoryStatus } from '../../../src/nodus/history.js';
import { actionButton } from './views.js';
import { pageHeading } from './presentation.js';

function element(document, tag, text, className = '') {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// src/wallet.js:31-38: every review row is the module's decoded envelope,
// including recipient, asset, amount, fee, changes, chain and expiry.
export function renderNodusSend(document, container, { account, tokens = [], review, title = 'Send on Nodus' }, { prepare, confirm, cancel }) {
  container.replaceChildren(pageHeading(document, title, 'send'));
  if (review) {
    // src/app.js:2323-2325, 1615-1627: display the review deadline and give
    // the user 600 ms before enabling transfer confirmation.
    const entries = [...review.review, ['Review expires', new Date(review.expiresAt).toLocaleTimeString()]];
    for (const [label, value] of entries) container.append(element(document, 'h2', label, 'extension-field-label'), element(document, 'pre', value, 'log-line evm-result'));
    const confirmButton = actionButton(document, 'Confirm send', () => {
      if (confirmButton.disabled) return;
      confirmButton.disabled = true; return confirm(review.id);
    }, false);
    confirmButton.disabled = true;
    const actions = element(document, 'div', undefined, 'actions');
    actions.append(actionButton(document, 'Cancel', cancel), confirmButton); container.append(actions);
    const timer = setTimeout(() => { confirmButton.disabled = false; }, 600);
    return () => clearTimeout(timer);
  }
  container.append(element(document, 'code', account));
  const form = element(document, 'form', undefined, 'send-block'), to = element(document, 'input'), amount = element(document, 'input'), asset = element(document, 'select');
  to.id = 'nodus-send-to'; to.type = 'text'; to.required = true; to.autocomplete = 'off';
  amount.id = 'nodus-send-amount'; amount.type = 'text'; amount.inputMode = 'decimal'; amount.required = true; amount.autocomplete = 'off';
  asset.id = 'nodus-send-asset';
  for (const token of [{ tokenId: NODUS_TOKEN_ID, symbol: 'NODUS', available: true }, ...tokens]) {
    const option = element(document, 'option', token.available ? token.symbol : `${token.symbol} — Unavailable right now`);
    option.value = token.tokenId; option.disabled = !token.available; asset.append(option);
  }
  asset.value = NODUS_TOKEN_ID;
  for (const [text, input] of [['Asset', asset], ['To', to], ['Amount', amount]]) {
    const label = element(document, 'label', text); label.htmlFor = input.id; form.append(label, input);
  }
  const submit = element(document, 'button', 'Review transfer'); submit.type = 'submit';
  form.append(submit, actionButton(document, 'Cancel', cancel)); container.append(form);
  form.onsubmit = event => { event.preventDefault(); return prepare({ to: to.value, amount: amount.value, tokenId: asset.value }); };
}

// src/nodus/history.js supplies node provenance and row text; local pending
// activity remains visible when the node's account-history read fails.
export function renderNodusHistory(document, container, history, { refresh, resubmit }) {
  container.replaceChildren(pageHeading(document, 'Nodus history', 'history'));
  container.append(actionButton(document, 'Refresh history', refresh));
  if (!history) { container.append(element(document, 'p', nodusHistoryStatus(), 'hint')); return; }
  if (history.activityError) container.append(element(document, 'p', history.activityError, 'field-error'));
  const local = element(document, 'div', undefined, 'activity-list');
  for (const row of history.local ?? []) {
    const article = element(document, 'article', undefined, 'activity-row');
    article.append(element(document, 'h2', row.amountText ?? `${row.amount} ${row.symbol}`), element(document, 'p', `${row.status}: ${row.note}`), element(document, 'code', row.hash));
    if (row.detail) article.append(element(document, 'p', row.detail));
    if (row.canResubmit) article.append(actionButton(document, 'Try again', () => resubmit(row.hash)));
    local.append(article);
  }
  container.append(local);
  container.append(element(document, 'p', history.error ? nodusHistoryStatus({ error: history.error }) : history.status, history.error ? 'field-error' : 'hint'));
  const account = element(document, 'div', undefined, 'activity-list');
  for (const row of history.rows ?? []) {
    const article = element(document, 'article', undefined, 'activity-row');
    article.append(element(document, 'h2', row.title), element(document, 'p', `${row.sign}${row.amount}`), element(document, 'p', row.detail), element(document, 'p', `Block ${row.height}`));
    if (row.wire) article.append(element(document, 'code', row.wire));
    account.append(article);
  }
  container.append(account);
}
