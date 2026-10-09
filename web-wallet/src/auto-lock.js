// Automatic lock after a time without use (web 0.1.89; operator 2026-10-09:
// "auto log off … değiştirebilelim ya da kapatabilelim ama default'ta açık
// olsun … default 15 min"). The wallet (and Messages with it) locks after
// this many minutes without a pointer, key or input event (src/app.js
// activity). 0 = never. The choice is a per-device convenience kept in this
// browser's localStorage (never part of the encrypted wallet): a missing,
// unreadable or unknown value falls back to the default, so a broken
// storage can only ever give the default lock, never "never".
export const AUTO_LOCK_KEY = 'nodus.autoLockMinutes';
export const AUTO_LOCK_CHOICES = Object.freeze([5, 10, 15, 30, 60, 0]);
export const AUTO_LOCK_DEFAULT = 15;

// A stored or selected value -> minutes (one of AUTO_LOCK_CHOICES).
export function parseAutoLock(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,2})$/.test(value)) return AUTO_LOCK_DEFAULT;
  const minutes = Number(value);
  return AUTO_LOCK_CHOICES.includes(minutes) ? minutes : AUTO_LOCK_DEFAULT;
}

// The line under the choice.
export function autoLockNote(minutes) {
  if (minutes === 0) return 'Never: this wallet and your messages stay open on this device until you press Lock or close the page (recovery words on screen are still cleared after 10 minutes). Do not choose this on a shared or public device.';
  return `This wallet and your messages lock after ${minutes === 60 ? '1 hour' : `${minutes} minutes`} without use. Closing the page always locks; recovery words on screen are always cleared after 10 minutes.`;
}

export function readAutoLock(storage) {
  try { return parseAutoLock(storage?.getItem(AUTO_LOCK_KEY) ?? undefined); }
  catch { return AUTO_LOCK_DEFAULT; }
}

// True when the choice was kept (a browser that refuses storage keeps it for
// this page only).
export function writeAutoLock(storage, minutes) {
  if (!AUTO_LOCK_CHOICES.includes(minutes)) return false;
  try { storage.setItem(AUTO_LOCK_KEY, String(minutes)); return true; }
  catch { return false; }
}
