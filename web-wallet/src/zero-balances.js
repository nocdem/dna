// Per-device preference retained under the existing key: true means show all
// networks, false means hide only networks with fresh exact-zero holdings.
// The UI checkbox is labelled Hide zero networks and inverts this value.
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

export function showZeroNote(show) { return show ? 'All networks and their holdings are listed.' : 'Only networks with a fresh exact zero for every holding are hidden. Unread, failed and stale balances stay visible.'; }
