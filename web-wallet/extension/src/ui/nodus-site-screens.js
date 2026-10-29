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
// signing account and full message. All page-controlled strings use textContent.
export function renderNodusSiteApproval(document, container, pending, { approve, reject }) {
  const heading = pageHeading(document, 'Nodus signature request', 'sites'), origin = document.createElement('p');
  origin.textContent = pending.origin; origin.className = 'extension-origin';
  container.replaceChildren(heading, origin);
  detail(document, container, 'Account', pending.requestData.account);
  detail(document, container, 'Message', pending.requestData.text);
  if (pending.requestData.data !== pending.requestData.text) detail(document, container, 'Message bytes', pending.requestData.data);
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
