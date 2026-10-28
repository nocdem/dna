import { CHAINS } from '../../../src/config.js';
import { actionButton } from './views.js';

function element(document, tag, text, className = '') {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function detail(document, container, title, text) {
  container.append(element(document, 'h2', title), element(document, 'pre', String(text ?? ''), 'log-line evm-result'));
}

// Approved plan §3.6: origin/account plus the complete message or transaction
// as text. The web-wallet styling comes from extension.css and src/style.css.
export function renderEvmApproval(document, container, pending, { approve, reject }) {
  const data = pending.requestData;
  const transaction = pending.type === 'transaction', switching = pending.type === 'wallet_switchEthereumChain';
  container.replaceChildren(element(document, 'h1', switching ? 'Switch network' : transaction ? 'Review transaction' : 'Signature request'));
  container.append(element(document, 'p', pending.origin, 'extension-origin'));
  detail(document, container, 'Account', data.account);
  detail(document, container, 'Network', CHAINS[data.chain].name);
  if (switching) {
    detail(document, container, 'Requested network', CHAINS[data.targetChain].name);
    container.append(element(document, 'p', 'This changes the selected network for every connected site.', 'hint'));
  } else if (transaction) {
    detail(document, container, 'To', data.to ?? 'Contract creation');
    detail(document, container, 'Value (wei)', data.value);
    detail(document, container, 'Data', data.data);
    detail(document, container, 'Network fee', data.fee);
  } else {
    detail(document, container, pending.type === 'personal_sign' ? 'Message' : 'Typed data', data.text);
    if (data.data !== undefined && data.data !== data.text) detail(document, container, 'Message bytes', data.data);
  }
  const actions = element(document, 'div', undefined, 'actions');
  actions.append(actionButton(document, 'Reject', () => reject(pending)), actionButton(document, 'Approve', () => approve(pending), false));
  container.append(actions);
}

// Web-wallet src/wallet.js:29-69 and src/app.js send/review flow: prepare first,
// display the adapter fee, then confirm that one background-owned review.
export function renderEvmSend(document, container, { chain, review, account, config = CHAINS[chain] }, { prepare, confirm, cancel }) {
  container.replaceChildren(element(document, 'h1', `Send on ${config.name}`));
  if (account) detail(document, container, 'From', account);
  if (review) {
    detail(document, container, 'To', review.to);
    detail(document, container, 'Amount', `${review.amount} ${review.symbol}`);
    detail(document, container, 'Network fee', review.fee);
    const actions = element(document, 'div', undefined, 'actions');
    actions.append(actionButton(document, 'Cancel', cancel), actionButton(document, 'Confirm send', () => confirm(review.id), false));
    container.append(actions); return;
  }
  const form = element(document, 'form'), to = element(document, 'input'), amount = element(document, 'input'), asset = element(document, 'select');
  to.id = 'evm-send-to'; to.type = 'text'; to.required = true; to.autocomplete = 'off';
  amount.id = 'evm-send-amount'; amount.type = 'text'; amount.inputMode = 'decimal'; amount.required = true; amount.autocomplete = 'off';
  asset.id = 'evm-send-asset';
  for (const symbol of [config.symbol, ...config.tokens.map(token => token.symbol)]) {
    const option = element(document, 'option', symbol); option.value = symbol; asset.append(option);
  }
  asset.value = config.symbol;
  for (const [text, input] of [['Asset', asset], ['To', to], ['Amount', amount]]) {
    const label = element(document, 'label', text); label.htmlFor = input.id; form.append(label, input);
  }
  const submit = element(document, 'button', 'Review transfer'); submit.type = 'submit';
  form.append(submit, actionButton(document, 'Cancel', cancel)); container.append(form);
  form.onsubmit = event => { event.preventDefault(); return prepare({ chain, symbol: asset.value, to: to.value, amount: amount.value }); };
}
