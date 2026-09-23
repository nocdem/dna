import { Mnemonic } from 'ethers';
import { validateNodusPhrase } from './recovery.js';
export const VAULT_KEY = 'nodus.wallet.v1', ACTIVITY_KEY = 'nodus.activity.v1';
const ITERATIONS = 600000;
const encode = bytes => btoa(String.fromCharCode(...bytes));
function decode(value, length) {
  if (typeof value !== 'string' || value.length > 4096 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid saved wallet.');
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (encode(bytes) !== value || (length && bytes.length !== length)) throw new Error('Invalid saved wallet.');
  return bytes;
}
function passwordBytes(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('Use a local password of 12–1024 characters.');
  return new TextEncoder().encode(password);
}
export function validateNewPassword(password) {
  // New saves/changes only: existing v1 wallets must remain unlockable.
  if (typeof password !== 'string' || password.length < 16 || password.length > 1024) throw new Error('Use a unique local password of 16–1024 characters. A password manager can generate one.');
  const folded = password.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  // Closes the previous anchored-regex bypass (`^(word)[0-9]*$` was defeated by a
  // single trailing character that was not a digit). Every occurrence of a common
  // word is removed from the folded password wherever it appears, not just as a
  // whole-string prefix; what remains must still carry at least 8 characters.
  const common = ['password', 'passphrase', 'qwerty', 'letmein', 'welcome', 'admin', 'administrator', 'iloveyou', 'changeme', 'nodus', 'wallet', 'secret', 'monkey', 'dragon', 'master', 'login', 'abc123', '123456', '1234567890', 'football', 'baseball', 'sunshine', 'princess', 'trustno1'];
  // Removal order matters for a compound word that contains a shorter one
  // (e.g. "administrator" contains "admin"): sort longest-first, stably, so the
  // compound word is stripped before a shorter word inside it can fragment it
  // into a longer-looking remainder.
  const residual = [...common].sort((a, b) => b.length - a.length).reduce((text, word) => text.split(word).join(''), folded);
  // The spec's own per-word rule, independent of removal order: a single common
  // word close to the whole password (fewer than 8 characters left over) rejects
  // on its own, even for a word the cumulative removal above did not reach first.
  const tooClose = common.some(word => folded.includes(word) && folded.length - word.length < 8);
  const sequences = ['0123456789', '1234567890', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm'];
  const runs = sequences.flatMap(value => [value.repeat(4), value.split('').reverse().join('').repeat(4)]);
  // Repeated-pattern and sequential-run checks scan every 8+ character window of
  // the folded password, not only the password taken as a whole, so a pattern
  // padded with unrelated characters on either side is still caught.
  let patterned = false;
  for (let start = 0; start < folded.length && !patterned; start++) {
    const eight = folded.slice(start, start + 8);
    if (eight.length === 8 && runs.some(run => run.includes(eight))) { patterned = true; break; }
    for (let end = start + 8; end <= Math.min(start + 16, folded.length) && !patterned; end++) {
      if (/^(.{1,8})\1+$/u.test(folded.slice(start, end))) patterned = true;
    }
  }
  const classes = new Set();
  for (const char of password) classes.add(/\p{L}/u.test(char) ? 'letter' : /\p{N}/u.test(char) ? 'digit' : 'other');
  if (residual.length < 8 || tooClose || patterned || (password.length < 24 && classes.size < 2)) throw new Error('This password is too easy to guess. Use a unique generated password or several unrelated words.');
}
function header(vault) { return { version: vault.version, id: vault.id, kdf: vault.kdf, iterations: vault.iterations, salt: vault.salt, cipher: vault.cipher, iv: vault.iv }; }
export function parseVault(text) {
  if (typeof text !== 'string' || text.length > 6000) throw new Error('Saved wallet is too large or invalid.');
  let vault; try { vault = JSON.parse(text); } catch { throw new Error('Invalid saved wallet.'); }
  if (!vault || Array.isArray(vault) || Object.keys(vault).sort().join() !== 'cipher,ciphertext,id,iterations,iv,kdf,salt,version' || vault.version !== 1 || vault.kdf !== 'PBKDF2-SHA256' || vault.iterations !== ITERATIONS || vault.cipher !== 'AES-256-GCM') throw new Error('Unsupported saved wallet format.');
  decode(vault.id, 16); decode(vault.salt, 16); decode(vault.iv, 12);
  const ciphertext = decode(vault.ciphertext); if (ciphertext.length < 17 || ciphertext.length > 2048) throw new Error('Invalid saved wallet.');
  return vault;
}
async function keyFor(password, salt, usage) {
  const bytes = passwordBytes(password);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, [usage]);
  } finally { bytes.fill(0); }
}
export async function encryptVault(phrase, password, id) {
  validateNewPassword(password);
  phrase = validateNodusPhrase(phrase);
  const vault = { version: 1, id: id || encode(crypto.getRandomValues(new Uint8Array(16))), kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: encode(crypto.getRandomValues(new Uint8Array(16))), cipher: 'AES-256-GCM', iv: encode(crypto.getRandomValues(new Uint8Array(12))) };
  decode(vault.id, 16);
  const key = await keyFor(password, decode(vault.salt), 'encrypt'), bytes = new TextEncoder().encode(phrase);
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(vault.iv), additionalData: new TextEncoder().encode(JSON.stringify(header(vault))), tagLength: 128 }, key, bytes);
    return JSON.stringify({ ...vault, ciphertext: encode(new Uint8Array(ciphertext)) });
  } finally { bytes.fill(0); }
}
export async function decryptVault(text, password) {
  const vault = parseVault(text), key = await keyFor(password, decode(vault.salt), 'decrypt');
  let bytes;
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(vault.iv), additionalData: new TextEncoder().encode(JSON.stringify(header(vault))), tagLength: 128 }, key, decode(vault.ciphertext)));
    const phrase = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!Mnemonic.isValidMnemonic(phrase)) throw new Error('Invalid recovery phrase.');
    return { phrase, id: vault.id };
  } catch { throw new Error('Incorrect password or damaged saved wallet.'); }
  finally { bytes?.fill(0); }
}
