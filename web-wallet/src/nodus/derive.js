import { Mnemonic, getBytes } from 'ethers';
import { sha3_512, shake256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { validateNodusPhrase } from '../recovery.js';

// Same derivation as shared/crypto/key/bip39/seed_derivation.c and
// messenger/messenger/keygen.c. The qgp-signing-v1 bytes are compatibility data.
export async function deriveNodusAddress(phrase, { wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  const normalized = validateNodusPhrase(phrase);
  // Fetch the public module before deriving any mutable secret buffers.
  let binary = wasmBytes;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./mldsa87.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Nodus address module could not load. Reload to retry.');
    binary = await response.arrayBuffer();
  }
  let instance, master, input, signingSeed;
  try {
    signal?.throwIfAborted();
    ({ instance } = await WebAssembly.instantiate(binary, {}));
    signal?.throwIfAborted();
    instance.exports._initialize?.();
    master = getBytes(Mnemonic.fromPhrase(normalized).computeSeed());
    const context = new TextEncoder().encode('qgp-signing-v1');
    input = new Uint8Array(master.length + context.length);
    input.set(master); input.set(context, master.length);
    signingSeed = shake256(input, { dkLen: 32 });
    const memory = new Uint8Array(instance.exports.memory.buffer);
    memory.set(signingSeed, instance.exports.nodus_input());
    if (instance.exports.nodus_derive() !== 0) throw new Error('Nodus address derivation failed.');
    const offset = instance.exports.nodus_output();
    return bytesToHex(sha3_512(memory.subarray(offset, offset + 2592)));
  } finally {
    master?.fill(0); input?.fill(0); signingSeed?.fill(0);
    // Includes key-generation stack temporaries; every call owns a fresh instance.
    if (instance) new Uint8Array(instance.exports.memory.buffer).fill(0);
  }
}
