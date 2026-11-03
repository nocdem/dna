import { createPhraseFields } from './phrase-fields.js';

// "Reveal recovery phrase" — the part shared by the extension, the web wallet
// and Nodus Connect (decision 2026-10-31-wallet-three-surfaces). The block is
// the one the extension has always built (extension/src/ui/views.js
// renderSettings); the password check and the clearing rules belong to each
// surface. The words go only into the read-only inputs of `container`; they
// are never stored, logged or put in a status line.

function element(document, tag, className = '', text) {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// reveal(password, container): called on submit with the typed value; the
// input is emptied before the call. setPasswordRequired(false) leaves the
// form as the "Reveal phrase" button only (a wallet that is not saved);
// (true) restores the extension's form.
export function renderRevealBlock(document, { reveal }) {
  const block = element(document, 'div', 'page-block'); block.append(
    element(document, 'h2', '', 'Reveal recovery phrase'),
    element(document, 'p', 'reveal-note', 'Your 24 words control your wallet. Never send them to anyone, including a person claiming to be from Nodus.'),
  );
  const form = element(document, 'form'), passwordLabel = element(document, 'label', '', 'Re-enter your password');
  const password = element(document, 'input'); password.id = 'reveal-password'; password.type = 'password';
  password.autocomplete = 'current-password'; password.required = true; password.maxLength = 1024; passwordLabel.htmlFor = password.id;
  const submit = element(document, 'button', '', 'Reveal phrase'); submit.type = 'submit';
  const recovery = element(document, 'div'); recovery.hidden = true;
  form.append(passwordLabel, password, submit);
  form.onsubmit = event => { event.preventDefault(); const entered = password.value; password.value = ''; return reveal(entered, recovery); };
  block.append(form, recovery);
  function setPasswordRequired(required) {
    passwordLabel.hidden = !required; password.hidden = !required; password.required = !!required;
  }
  return { block, password, recovery, setPasswordRequired };
}

// The display steps of extension/src/ui/app.js (reveal): 24 read-only inputs
// inside one wrapper, so every clear path that empties `container` removes the
// frame, the words and the Copy button together. The ids carry their own
// prefix: the restore form on the web page already owns phrase-1 ... phrase-24.
// "Copy phrase" reads the shown inputs only at the click and writes only to
// the clipboard: no status line, log, console or storage, and a failed write
// shows nothing.
export function showRevealedPhrase(document, container, phrase, { clipboard = globalThis.navigator?.clipboard } = {}) {
  container.hidden = false;
  const wrapper = element(document, 'div', 'reveal-words');
  const grid = element(document, 'div', 'phrase-grid'), error = element(document, 'p', 'field-error');
  const actions = element(document, 'div', 'reveal-actions');
  const copy = element(document, 'button', 'secondary', 'Copy phrase'); copy.type = 'button';
  const fields = createPhraseFields(grid, error, { idPrefix: 'reveal-phrase' });
  copy.onclick = async () => {
    try { await clipboard?.writeText(fields.read()); } catch { /* nothing is shown or logged */ }
  };
  actions.append(copy, element(document, 'p', 'hint', 'Copied words stay on the clipboard until you copy something else.'));
  wrapper.append(grid, error, actions);
  container.replaceChildren(wrapper);
  fields.set(phrase, true);
}

// The nodes are removed, not hidden.
export function clearRevealedPhrase(container) {
  container.replaceChildren(); container.hidden = true;
}
