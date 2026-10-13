// Zero balances in the asset list (web 0.1.113; operator 2026-10-13: "sıfır
// olan bakiyeleri göstermenin bir anlamı yok … settings olması lazım, bir
// tane sıfır bakiyeleri gizli gibi … Hiç olmayan … Kaç dolar olduğu değil, bir
// şey olup olmadığı önemli"). Hidden by default; Device & settings can show
// them. Which rows count as zero: src/portfolio.js zeroRow (by the amount,
// never the dollar value; NODUS and unread rows always stay). A per-device
// convenience in this browser's localStorage, like the automatic lock
// (src/auto-lock.js): a missing or unknown value gives the default.
export const SHOW_ZERO_KEY = 'nodus.showZeroBalances';

export function readShowZero(storage) {
  try { return storage?.getItem(SHOW_ZERO_KEY) === '1'; }
  catch { return false; }
}

// True when the choice was kept (a browser that refuses storage keeps it for
// this page only).
export function writeShowZero(storage, show) {
  try { storage.setItem(SHOW_ZERO_KEY, show === true ? '1' : '0'); return true; }
  catch { return false; }
}

export function showZeroNote(show) {
  return show
    ? 'Every asset is listed, including those you do not hold.'
    : 'Assets you do not hold are left out of the list. NODUS, and any asset whose balance could not be read, always stay.';
}
