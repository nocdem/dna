// Nodus Connect Messages UI — DOM builders (package NC-4c; design rev 5 §1.9
// DOM contract). Every piece of text goes in through textContent; nothing
// here parses HTML. Text written by someone else goes into a <bdi> (isolated
// direction) and gets a visible "unusual characters" marker when
// inspectUntrusted flags it.
import { inspectUntrusted, httpsLink, avatarSource } from './text.js';

export function el(tag, { className, text } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const child of children) if (child) node.append(child);
  return node;
}

// `name`: the value is a claimed name — also marked "check carefully" when it
// has no Latin letter or has fullwidth Latin (text.js inspectUntrusted).
export function untrusted(value, className, { name = false } = {}) {
  const { text, unusual, check } = inspectUntrusted(value, { name });
  const wrap = el('span', { className });
  wrap.append(el('bdi', { text }));
  if (unusual) wrap.append(el('span', { className: 'nc-unusual', text: ' (contains unusual characters)' }));
  else if (check) wrap.append(el('span', { className: 'nc-unusual', text: ' (check carefully: may look like another name)' }));
  return wrap;
}

export function button(label, onClick, className) {
  const node = el('button', { className, text: label });
  node.type = 'button';
  node.onclick = onClick;
  return node;
}

// A round avatar: the profile picture when text.js avatarSource accepts it
// (set as a data: URL property, nothing parsed as markup), else the
// initials. A picture the browser cannot decode falls back to the initials.
export function fillAvatar(node, initials, b64) {
  const src = avatarSource(b64);
  node.textContent = src ? '' : initials;
  if (src) {
    const img = el('img', { className: 'avatar-img' });
    img.alt = ''; img.decoding = 'async'; img.draggable = false;
    img.onerror = () => { node.textContent = initials; };
    img.src = src;
    node.append(img);
  }
  return node;
}

// A website: link text only for a checked https: URL; otherwise plain text.
export function website(value) {
  const href = httpsLink(value);
  if (!href) return value ? untrusted(value) : null;
  const link = el('a', { text: href });
  link.href = href; link.target = '_blank'; link.rel = 'noopener noreferrer';
  return link;
}
