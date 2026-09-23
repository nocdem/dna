import { Mnemonic, getBytes } from 'ethers';
import { sha3_512, shake256 } from '@noble/hashes/sha3';
import { validateNodusPhrase } from '../recovery.js';

// Ixios ML-DSA-87 signing seed — DELIBERATELY a different key than the Nodus/
// messenger one derived by src/nodus/derive.js (same 'qgp-signing-v1' pattern,
// different label). See docs/plans/decisions/2026-09-23-ixios-separate-mldsa-key.md:
// same phrase, label-only domain separation, so a messenger identity cannot be
// linked to an Ixios balance. No WASM here — key generation itself happens in
// src/pq/sign.js via mldsa87Sign(); this only derives the 32-byte seed it needs.
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
