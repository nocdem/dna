// Nodus Connect Messages UI — DOM builders (package NC-4c; design rev 5 §1.9
// DOM contract). Every piece of text goes in through textContent; nothing
// here parses HTML. Text written by someone else goes into a <bdi> (isolated
// direction) and gets a visible "unusual characters" marker when
// inspectUntrusted flags it.
import { inspectUntrusted, httpsLink } from './text.js';

export function el(tag, { className, text } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const child of children) if (child) node.append(child);
  return node;
}

export function untrusted(value, className) {
  const { text, unusual } = inspectUntrusted(value);
  const wrap = el('span', { className });
  wrap.append(el('bdi', { text }));
  if (unusual) wrap.append(el('span', { className: 'nc-unusual', text: ' (contains unusual characters)' }));
  return wrap;
}

export function button(label, onClick, className) {
  const node = el('button', { className, text: label });
  node.type = 'button';
  node.onclick = onClick;
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
