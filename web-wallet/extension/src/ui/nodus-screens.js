import { NODUS_TOKEN_ID } from '../../../src/nodus/network.js';
import { nodusHistoryStatus } from '../../../src/nodus/history.js';
import { actionButton } from './views.js';

function element(document, tag, text, className = '') {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// src/wallet.js:31-38: every review row is the module's decoded envelope,
// including recipient, asset, amount, fee, changes, chain and expiry.
export function renderNodusSend(document, container, { account, tokens = [], review, title = 'Send on Nodus' }, { prepare, confirm, cancel }) {
  container.replaceChildren(element(document, 'h1', title));
  if (review) {
    // src/app.js:2323-2325, 1615-1627: display the review deadline and give
    // the user 600 ms before enabling transfer confirmation.
    const entries = [...review.review, ['Review expires', new Date(review.expiresAt).toLocaleTimeString()]];
    for (const [label, value] of entries) container.append(element(document, 'h2', label), element(document, 'pre', value, 'log-line evm-result'));
    const confirmButton = actionButton(document, 'Confirm send', () => {
      if (confirmButton.disabled) return;
      confirmButton.disabled = true; return confirm(review.id);
    }, false);
    confirmButton.disabled = true;
    container.append(actionButton(document, 'Cancel', cancel), confirmButton);
    const timer = setTimeout(() => { confirmButton.disabled = false; }, 600);
    return () => clearTimeout(timer);
  }
  container.append(element(document, 'code', account));
  const form = element(document, 'form'), to = element(document, 'input'), amount = element(document, 'input'), asset = element(document, 'select');
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
  container.replaceChildren(element(document, 'h1', 'Nodus history'));
  container.append(actionButton(document, 'Refresh history', refresh));
  if (!history) { container.append(element(document, 'p', nodusHistoryStatus(), 'hint')); return; }
  if (history.activityError) container.append(element(document, 'p', history.activityError, 'field-error'));
  for (const row of history.local ?? []) {
    const article = element(document, 'article', undefined, 'extension-network');
    article.append(element(document, 'h2', row.amountText ?? `${row.amount} ${row.symbol}`), element(document, 'p', `${row.status}: ${row.note}`), element(document, 'code', row.hash));
    if (row.detail) article.append(element(document, 'p', row.detail));
    if (row.canResubmit) article.append(actionButton(document, 'Try again', () => resubmit(row.hash)));
    container.append(article);
  }
  container.append(element(document, 'p', history.error ? nodusHistoryStatus({ error: history.error }) : history.status, history.error ? 'field-error' : 'hint'));
  for (const row of history.rows ?? []) {
    const article = element(document, 'article', undefined, 'extension-network');
    article.append(element(document, 'h2', row.title), element(document, 'p', `${row.sign}${row.amount}`), element(document, 'p', row.detail), element(document, 'p', `Block ${row.height}`));
    if (row.wire) article.append(element(document, 'code', row.wire));
    container.append(article);
  }
}

// src/evm/ui.js bridge/contract/deployment actions use the same Contract and
// EvmAccount code in the background; only form fields and rendered text cross the port.
export function renderNodusContracts(document, container, { account, readable, buildable, result, review }, actions) {
  if (review) {
    // src/evm/ui.js:129-168: decoded rows, immediate confirmation, and a failed
    // review keeps its error and Close button rather than the transfer outcome note.
    container.replaceChildren(element(document, 'h1', 'Review smart-contract transaction'));
    container.append(element(document, 'p', 'Testnet transaction. Check every line; sending cannot be undone.', 'notice'));
    for (const [label, value] of review.review) container.append(element(document, 'h2', label), element(document, 'pre', value, 'log-line evm-result'));
    const error = element(document, 'p', review.error ?? '', 'field-error'); error.role = 'alert';
    const cancel = actionButton(document, review.error ? 'Close' : 'Cancel', actions.cancel); cancel.disabled = false;
    const confirm = actionButton(document, 'Confirm & send', () => {
      if (confirm.disabled) return;
      confirm.disabled = true; cancel.disabled = true; return actions.confirm(review.id);
    }, false);
    confirm.disabled = Boolean(review.error);
    container.append(error, cancel, confirm); return;
  }
  container.replaceChildren(element(document, 'h1', 'Nodus smart contracts'));
  container.append(element(document, 'p', 'The network fee shown for a transaction is the most it can cost.', 'hint'));
  if (readable) container.append(actionButton(document, 'Read account', () => actions.read({ action: 'account' })));
  if (result) container.append(element(document, 'pre', result, 'log-line evm-result'));
  function field(form, labelText, tag = 'input', value = '') {
    const input = element(document, tag); input.value = value; input.autocomplete = 'off';
    const label = element(document, 'label', labelText); label.append(input); form.append(label); return input;
  }
  function select(form, label, choices) {
    const input = field(form, label, 'select');
    for (const [value, title] of choices) { const option = element(document, 'option', title); option.value = value; input.append(option); }
    input.value = choices[0][0]; return input;
  }
  if (buildable) {
    const bridge = element(document, 'form'); bridge.append(element(document, 'h2', 'Move NODUS'));
    const action = select(bridge, 'Action', [['deposit', 'Move NODUS to smart contracts'], ['withdraw', 'Move NODUS back'], ['redeem', 'Collect a withdrawal ticket']]);
    const amount = field(bridge, 'Amount (NODUS)'), dest = field(bridge, 'Nodus recipient', 'input', account), ticketId = field(bridge, 'Withdrawal ticket');
    const submit = element(document, 'button', 'Review transaction'); submit.type = 'submit'; bridge.append(submit); container.append(bridge);
    bridge.onsubmit = event => { event.preventDefault(); return actions.prepare({ action: action.value, amount: amount.value, dest: dest.value, ticketId: ticketId.value }); };
  }
  if (readable) {
    const form = element(document, 'form'); form.append(element(document, 'h2', 'Contract'));
    const choices = [['read', 'Read contract'], ['estimate', 'Estimate contract call'], ...(buildable ? [['call', 'Call contract'], ['deploy', 'Deploy contract']] : [])];
    const action = select(form, 'Action', choices), address = field(form, 'Contract address'), abi = field(form, 'ABI (JSON)', 'textarea');
    const fn = field(form, 'Function signature'), args = field(form, 'Arguments (JSON array; use strings for integers)', 'textarea', '[]');
    const value = field(form, 'Value (NODUS)', 'input', '0'), bytecode = field(form, 'Deployment bytecode');
    const submit = element(document, 'button', 'Continue'); submit.type = 'submit'; form.append(submit); container.append(form);
    form.onsubmit = event => {
      event.preventDefault();
      const fields = { action: action.value, address: address.value, abi: abi.value, fn: fn.value, args: args.value, value: value.value, bytecode: bytecode.value };
      return (['read', 'estimate'].includes(action.value) ? actions.read : actions.prepare)(fields);
    };
    const ticket = element(document, 'form'), ticketId = field(ticket, 'Withdrawal ticket');
    const read = element(document, 'button', 'Inspect ticket'); read.type = 'submit'; ticket.append(read); container.append(ticket);
    ticket.onsubmit = event => { event.preventDefault(); return actions.read({ action: 'ticket', ticketId: ticketId.value }); };
  }
}
