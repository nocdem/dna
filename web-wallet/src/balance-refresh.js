// Automatic balance updates (web 0.1.93; operator 2026-10-12: "bir süre
// sonra kaç para değerimiz olduğu siliniyor … silinmeden önce refresh etse …
// settings'e koyabilirsin, 5 dakikada bir 10 dakikada bir arka planda").
// While the wallet is open and the page is shown, the portfolio reads every
// network's balance and the market prices again every this many minutes
// (src/portfolio-view.js setAutoRefresh), keeping the values on screen while
// it reads. 0 = off (Refresh only, as before). A per-device convenience kept
// in this browser's localStorage, like the automatic lock (src/auto-lock.js):
// a missing, unreadable or unknown value gives the default.
export const BALANCE_REFRESH_KEY = 'nodus.balanceRefreshMinutes';
export const BALANCE_REFRESH_CHOICES = Object.freeze([2, 5, 10, 0]);
export const BALANCE_REFRESH_DEFAULT = 5;

export function parseBalanceRefresh(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d?)$/.test(value)) return BALANCE_REFRESH_DEFAULT;
  const minutes = Number(value);
  return BALANCE_REFRESH_CHOICES.includes(minutes) ? minutes : BALANCE_REFRESH_DEFAULT;
}

export function balanceRefreshNote(minutes) {
  if (minutes === 0) return 'Off: balances and prices are read when the wallet opens and when you press Refresh. A balance older than 5 minutes is shown as last read and leaves the total.';
  return `Balances and prices are read again every ${minutes} minutes while this page is shown, and a network again when you choose it. Values stay on screen while they are read.`;
}

export function readBalanceRefresh(storage) {
  try { return parseBalanceRefresh(storage?.getItem(BALANCE_REFRESH_KEY) ?? undefined); }
  catch { return BALANCE_REFRESH_DEFAULT; }
}

// True when the choice was kept (a browser that refuses storage keeps it for
// this page only).
export function writeBalanceRefresh(storage, minutes) {
  if (!BALANCE_REFRESH_CHOICES.includes(minutes)) return false;
  try { storage.setItem(BALANCE_REFRESH_KEY, String(minutes)); return true; }
  catch { return false; }
}
