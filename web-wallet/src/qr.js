import qrcode from 'qrcode-generator';

// QR code for the receive address (0.1.22). It encodes exactly the text shown
// in #receive-address — no URI scheme, no prefix — so scanning it yields the
// same characters the Copy button copies.
//
// Drawn as SVG DOM nodes (one background <rect>, one <path> for the dark
// modules). No markup string, data URL, innerHTML or inline style is produced:
// the page CSP is `style-src 'self'`, and fill / shape-rendering below are SVG
// presentation attributes, not style attributes. Size comes from style.css.
const SVG = 'http://www.w3.org/2000/svg';
const QUIET_ZONE = 4; // modules of light margin on each side
// qrcode-generator's default Byte-mode encoder keeps only the low 8 bits of each
// UTF-16 code unit (`qrcode.stringToBytes`, dist/qrcode.mjs:735-742), so only
// printable ASCII is encoded exactly. Every address this wallet shows is ASCII;
// anything else draws no QR rather than a code for different characters.
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

export function renderQr(container, text) {
  container.replaceChildren();
  if (!text || !PRINTABLE_ASCII.test(text)) return;
  const qr = qrcode(0, 'M'); // type 0 = smallest version that fits
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount(), size = count + 2 * QUIET_ZONE;
  const svg = document.createElementNS(SVG, 'svg');
  for (const [name, value] of [['viewBox', `0 0 ${size} ${size}`], ['width', String(size)], ['height', String(size)], ['shape-rendering', 'crispEdges'], ['role', 'img'], ['aria-label', 'QR code for the receive address']]) svg.setAttribute(name, value);
  const background = document.createElementNS(SVG, 'rect');
  for (const [name, value] of [['width', String(size)], ['height', String(size)], ['fill', '#ffffff']]) background.setAttribute(name, value);
  let d = '';
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) if (qr.isDark(row, col)) d += `M${col + QUIET_ZONE} ${row + QUIET_ZONE}h1v1h-1z`;
  }
  const modules = document.createElementNS(SVG, 'path');
  modules.setAttribute('d', d); modules.setAttribute('fill', '#000000');
  svg.append(background, modules);
  container.append(svg);
}
