import { sha3_256 } from '@noble/hashes/sha3';
import { Mnemonic } from 'ethers';
import { normalizePhrase } from '../keys.js';
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function encodeAddress(bytes) {
  let n = BigInt('0x' + Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('')), out = '';
  while (n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = '1' + out; }
  return out;
}
export function validateDerivedAddress(address) {
  if (typeof address !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{100,110}$/.test(address)) throw new Error('Invalid Cellframe address.');
  let n = 0n; for (const char of address) n = n * 58n + BigInt(alphabet.indexOf(char));
  const bytes = []; while (n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (const char of address) { if (char !== '1') break; bytes.unshift(0); }
  const raw = Uint8Array.from(bytes), view = new DataView(raw.buffer);
  if (raw.length !== 77 || raw[0] !== 1 || view.getBigUint64(1, true) !== 0x0404202200000000n || view.getUint32(9, true) !== 0x0102) throw new Error('Address is not a Backbone Dilithium address.');
  const checksum = sha3_256(raw.subarray(0, 45));
  if (!checksum.every((byte, i) => byte === raw[45 + i])) throw new Error('Cellframe address checksum does not match.');
  return address;
}
export async function deriveCpunkAddress(phrase, { wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  const normalized = normalizePhrase(phrase);
  if (!Mnemonic.isValidMnemonic(normalized)) throw new Error('Open a wallet with a valid recovery phrase first.');
  let instance, input, seed;
  try {
    let binary = wasmBytes;
    if (!binary) {
      const timeout = AbortSignal.timeout(15000);
      const response = await fetch(new URL('./legacy-dilithium.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
      if (!response.ok) throw new Error('Cellframe address module could not load. Reload to retry.');
      binary = await response.arrayBuffer();
    }
    signal?.throwIfAborted();
    const fail = () => { throw new Error('Cellframe derivation failed.'); };
    ({ instance } = await WebAssembly.instantiate(binary, { wasi_snapshot_preview1: { proc_exit: fail, fd_write: fail, fd_close: fail, fd_seek: fail, fd_fdstat_get: fail, random_get: (ptr, len) => { if (!instance || len > 65536) return 28; crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer, ptr, len)); return 0; } } }));
    signal?.throwIfAborted();
    instance.exports._initialize?.();
    input = new TextEncoder().encode(normalized); seed = sha3_256(input); input.fill(0);
    const memory = new Uint8Array(instance.exports.memory.buffer);
    memory.set(seed, instance.exports.cpunk_input());
    if (instance.exports.cpunk_derive() !== 0) throw new Error('Cellframe derivation failed.');
    const serialized = new Uint8Array(1196), header = new DataView(serialized.buffer);
    header.setBigUint64(0, 1196n, true); header.setUint32(8, 1, true);
    serialized.set(new Uint8Array(instance.exports.memory.buffer).subarray(instance.exports.cpunk_output(), instance.exports.cpunk_output() + 1184), 12);
    const raw = new Uint8Array(77), view = new DataView(raw.buffer);
    raw[0] = 1; view.setBigUint64(1, 0x0404202200000000n, true); view.setUint32(9, 0x0102, true);
    raw.set(sha3_256(serialized), 13); raw.set(sha3_256(raw.subarray(0, 45)), 45);
    return validateDerivedAddress(encodeAddress(raw));
  } finally { input?.fill(0); seed?.fill(0); if (instance) new Uint8Array(instance.exports.memory.buffer).fill(0); }
}
