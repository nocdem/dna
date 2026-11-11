import { actionButton } from './views.js';
import { pageHeading } from './presentation.js';

function detail(document, container, title, value) {
  const label = document.createElement('h2'), text = document.createElement('pre');
  label.textContent = title; text.textContent = value; text.className = 'log-line evm-result';
  label.className = 'extension-field-label';
  container.append(label, text);
}

// MetaMask v13.54.0 personal-sign.tsx:139-164 under
// ui/pages/confirmations/components/confirm/info/personal-sign: origin,
// signing account and the message text (no separate bytes row). All page-controlled strings use textContent.
export function renderNodusSiteApproval(document, container, pending, { approve, reject }) {
  const heading = pageHeading(document, 'Nodus signature request', 'sites'), origin = document.createElement('p');
  origin.textContent = pending.origin; origin.className = 'extension-origin';
  container.replaceChildren(heading, origin);
  // The chain name is shown only when the background holds one confirmed for this account; the address stays visible.
  const { account, accountName } = pending.requestData;
  if (accountName) { detail(document, container, 'Account', accountName); detail(document, container, 'Address', account); }
  else detail(document, container, 'Account', account);
  detail(document, container, 'Message', pending.requestData.text);
  const actions = document.createElement('div'); actions.className = 'actions';
  actions.append(actionButton(document, 'Reject', () => reject(pending)), actionButton(document, 'Approve', () => approve(pending), false)); container.append(actions);
}

// A payment of a swap or a liquidity add (plan section 18 change 1): the held NODUS transfer or the USDT transfer,
// each with its exact amount, destination, token, fee and the bot that received the request. `rows` are built by the
// background from the prepared (signed or estimated) transaction; every page-controlled string uses textContent.
export function renderSwapPaymentApproval(document, container, pending, { approve, reject }) {
  const heading = pageHeading(document, pending.requestData.title, 'sites'), origin = document.createElement('p');
  origin.textContent = pending.origin; origin.className = 'extension-origin';
  container.replaceChildren(heading, origin);
  for (const [label, value] of pending.requestData.rows) detail(document, container, label, value);
  if (pending.requestData.note) {
    const note = document.createElement('p'); note.className = 'hint'; note.textContent = pending.requestData.note; container.append(note);
  }
  const actions = document.createElement('div'); actions.className = 'actions';
  actions.append(actionButton(document, 'Reject', () => reject(pending)), actionButton(document, 'Approve', () => approve(pending), false)); container.append(actions);
}

// Same permission approval controls as views.js renderConnect; the decision
// chooses one Nodus identity, so there is no EVM account/network selection.
export function renderNodusConnect(document, container, state, pending, { approve, reject }) {
  const heading = pageHeading(document, 'Connect Nodus to site', 'sites'), origin = document.createElement('p');
  origin.textContent = pending.origin; origin.className = 'extension-origin';
  container.replaceChildren(heading, origin);
  detail(document, container, 'Nodus address', state.addresses.nodus);
  detail(document, container, 'ML-DSA-87 public key', state.nodus?.publicKey ?? 'Unavailable');
  const connect = actionButton(document, 'Connect', () => approve(pending), false);
  connect.disabled = !state.addresses.nodus || !state.nodus?.publicKey;
  const actions = document.createElement('div'); actions.className = 'actions';
  actions.append(actionButton(document, 'Reject', () => reject(pending)), connect); container.append(actions);
}
