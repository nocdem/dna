// Smart contracts (the Nodus EVM domain) — addresses.
//
// An EVM address on Nodus is 32 bytes (decision 2026-10-04-nodus-evm-domain.md
// item 3). An account's address is the first 32 bytes of its Nodus
// fingerprint, SHA3-512(ML-DSA-87 public key) (design
// docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §2: "EVM
// göndereni = o imzacının parmak izi[0..32]").
//
// Text form: "0x" + 64 hex digits. Checksum: the EIP-55 rule applied to the
// 64 digits — keccak256 of the 64 lowercase ASCII hex characters; the i-th
// letter is upper case iff the i-th hex nibble of that hash is >= 8. This is
// the rule the Nodus solc applies to 64-digit address literals
// (nodus/tools/evm/solc/README.md, "Semantic rules" 4:
// util::getChecksummedAddress32). A 20-byte Ethereum address is NOT a Nodus
// address; it is refused, never padded.
import { keccak_256, sha3_512 } from '@noble/hashes/sha3';

const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/;
const enc = new TextEncoder();

export function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex.');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// The checksummed text of a 32-byte address (64 hex digits, any case, with or
// without 0x).
export function toChecksumAddress(address) {
  const lower = String(address).replace(/^0x/, '').toLowerCase();
  if (!HEX64.test(lower)) throw new Error('A Nodus contract address has 64 hex characters after 0x.');
  const hash = bytesToHex(keccak_256(enc.encode(lower)));
  let out = '0x';
  for (let i = 0; i < 64; i++) {
    const c = lower[i];
    out += c >= 'a' && c <= 'f' && parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

// Parse a user-entered address -> 64 lowercase hex (no 0x). All-lowercase
// and all-uppercase forms are accepted as they are; a mixed-case form must
// carry the correct checksum (EIP-55's rule: mixed case means "checksummed").
export function parseAddress(text) {
  if (typeof text !== 'string') throw new Error('Enter an address.');
  const t = text.trim();
  const body = t.replace(/^0x/, '');
  if (/^[0-9a-fA-F]{40}$/.test(body)) throw new Error('This is a 20-byte Ethereum address. Nodus contract addresses are 32 bytes (64 hex characters).');
  if (!/^[0-9a-fA-F]{64}$/.test(body)) throw new Error('A Nodus contract address is 0x followed by 64 hex characters.');
  const lower = body.toLowerCase();
  const mixed = body !== lower && body !== body.toUpperCase();
  if (mixed && toChecksumAddress(lower) !== `0x${body}`) throw new Error('This address has a typing error (its capital letters do not match). Check it and try again.');
  return lower;
}

export function isAddress(text) {
  try { parseAddress(text); return true; } catch { return false; }
}

// The EVM address of a Nodus account, from its fingerprint (128 hex) ->
// 64 lowercase hex.
export function evmAddressFromFingerprint(fingerprint) {
  if (typeof fingerprint !== 'string' || !HEX128.test(fingerprint)) throw new Error('Invalid Nodus address.');
  return fingerprint.slice(0, 64);
}

// ... or from the ML-DSA-87 public key itself (2592 bytes).
export function evmAddressFromPublicKey(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 2592) throw new Error('Invalid public key.');
  return bytesToHex(sha3_512(publicKey).subarray(0, 32));
}

// The ticket system address (design §5): SHA3-512("NDS.EVMWITHDRAW.v1")[0..32],
// the 18 ASCII bytes without a terminator (nodus_witness_rt_evm.h
// nodus_rt_evm_ticket_addr). A contract opens a withdrawal ticket by a plain
// CALL to it with value > 0, value % 10^10 == 0 and exactly 64 bytes of
// calldata (the destination fingerprint).
export const EVM_WITHDRAW_ADDRESS = bytesToHex(sha3_512(enc.encode('NDS.EVMWITHDRAW.v1')).subarray(0, 32));
