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
  const common = /^(password|passphrase|qwerty|letmein|welcome|admin|administrator|iloveyou|changeme|nodus|wallet|1234567890)[0-9]*$/;
  const repeated = /^(.{1,8})\1+$/u.test(password.toLowerCase());
  const sequence = ['0123456789', '1234567890', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm'].some(value => value.repeat(4).includes(folded) || value.split('').reverse().join('').repeat(4).includes(folded));
  if (folded.length < 8 || common.test(folded) || repeated || sequence) throw new Error('This password is too easy to guess. Use a unique generated password or several unrelated words.');
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
