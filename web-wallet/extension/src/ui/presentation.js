// Web-wallet index.html:27,35,58,62,82: use the same identity, section icons
// and page-heading structure. The extension keeps its existing screen names.
const paths = {
  send: ['M7 20V7M3 11l4-4 4 4', 'M17 4v13M13 13l4 4 4-4'],
  receive: ['M7 20V7M3 11l4-4 4 4', 'M17 4v13M13 13l4 4 4-4'],
  history: ['M3 12h4l3-7 4 14 3-7h4'],
  contracts: ['M9 7l-5 5 5 5', 'M15 7l5 5-5 5', 'M13 5l-2 14'],
  sites: ['M8 21h8M12 17v4M9 10l2 2 4-4'],
  settings: ['M12 15a3 3 0 1 0 0-6a3 3 0 1 0 0 6z', 'M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 0 0-2.1-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2.1 1.2l-2.3-.9-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-.9a7 7 0 0 0 2.1 1.2L10 21h4l.5-2.6a7 7 0 0 0 2.1-1.2l2.3.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z'],
};
function element(document, tag, className, text) {
  const node = document.createElement(tag); node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
export function appIcon(document, name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'app-icon'); svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('aria-hidden', 'true');
  if (name === 'sites') {
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    for (const [key, value] of Object.entries({ x: 3, y: 4, width: 18, height: 13, rx: 2 })) rect.setAttribute(key, value);
    svg.append(rect);
  }
  for (const d of paths[name]) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', d); svg.append(path);
  }
  return svg;
}
export function walletHeading(document, title) {
  const header = element(document, 'header', 'section-head'), mark = element(document, 'img', 'wallet-mark');
  mark.src = '/assets/nodus-mark.svg'; mark.alt = ''; mark.width = mark.height = 40;
  const text = element(document, 'div', '');
  text.append(element(document, 'p', 'eyebrow', 'A WALLET THAT’S YOURS'), element(document, 'h1', '', title));
  header.append(mark, text); return header;
}
export function pageHeading(document, title, icon) {
  const header = element(document, 'header', 'panel-heading page-heading'), symbol = element(document, 'span', 'page-icon');
  symbol.setAttribute('aria-hidden', 'true'); symbol.append(appIcon(document, icon));
  const text = element(document, 'div', 'page-heading-text'); text.append(element(document, 'h1', '', title));
  header.append(symbol, text); return header;
}
