import { Mnemonic, getBytes } from 'ethers';
import { sha3_512, shake256 } from '@noble/hashes/sha3';
import { validateNodusPhrase } from '../recovery.js';

// Ixios ML-DSA-87 signing seed — DELIBERATELY a different key than the Nodus/
// messenger one derived by src/nodus/derive.js (same 'qgp-signing-v1' pattern,
// different label). See docs/plans/decisions/2026-09-23-ixios-separate-mldsa-key.md:
// same phrase, label-only domain separation, so a messenger identity cannot be
// linked to an Ixios balance. Signing (src/pq/sign.js mldsa87Sign) and address
// display (deriveIxiosAddress below) both start from this 32-byte seed.
// The caller owns the returned seed and must wipe it.
export function ixiosSigningSeed(phrase) {
  const normalized = validateNodusPhrase(phrase);
  let master, input, seed;
  try {
    master = getBytes(Mnemonic.fromPhrase(normalized).computeSeed());
    const label = new TextEncoder().encode('ixios-mldsa87-v1');
    input = new Uint8Array(master.length + label.length);
    input.set(master); input.set(label, master.length);
    seed = shake256(input, { dkLen: 32 });
    return seed;
  } finally {
    master?.fill(0); input?.fill(0);
  }
}

// Ixios PQ address = trailing 48 bytes of SHA3-512(public key).
// Reference: ixiosSpark crypto/crypto.go PubkeyBytesToAddressWithType, case 0x01
// (hash[len(hash)-common.AddressLength:], common/types.go:38 AddressLength = 48).
export function ixiosAddressBytes(publicKey) {
  return sha3_512(publicKey).slice(16);
}

// Receive-only address display. Key generation uses the audited keygen-only
// module src/nodus/mldsa87.wasm (no signing export), NOT src/pq/mldsa87-sign.wasm;
// only the seed label differs from deriveNodusAddress(). Returns the 48 address bytes.
export async function deriveIxiosAddress(phrase, { wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  const normalized = validateNodusPhrase(phrase);
  // Fetch the public module before deriving any mutable secret buffers.
  let binary = wasmBytes;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    // Same file as the Nodus derivation; the "ixios" query only makes this
    // request distinguishable from it (static servers ignore the query), so a
    // test holding the Nodus request does not depend on which fetch runs first.
    const moduleUrl = new URL('../nodus/mldsa87.wasm', import.meta.url);
    moduleUrl.search = 'ixios';
    const response = await fetch(moduleUrl, { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Ixios address module could not load. Reload to retry.');
    binary = await response.arrayBuffer();
  }
  let instance, signingSeed;
  try {
    signal?.throwIfAborted();
    ({ instance } = await WebAssembly.instantiate(binary, {}));
    signal?.throwIfAborted();
    instance.exports._initialize?.();
    // ixiosSigningSeed() wipes its own master seed and SHAKE input.
    signingSeed = ixiosSigningSeed(normalized);
    const memory = new Uint8Array(instance.exports.memory.buffer);
    memory.set(signingSeed, instance.exports.nodus_input());
    if (instance.exports.nodus_derive() !== 0) throw new Error('Ixios address derivation failed.');
    const offset = instance.exports.nodus_output();
    return ixiosAddressBytes(memory.subarray(offset, offset + 2592));
  } finally {
    signingSeed?.fill(0);
    // Includes key-generation stack temporaries; every call owns a fresh instance.
    if (instance) new Uint8Array(instance.exports.memory.buffer).fill(0);
  }
}
