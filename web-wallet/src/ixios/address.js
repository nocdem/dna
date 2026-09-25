import { keccak_512 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Mixed-case checksum for 48-byte Ixios addresses. Rule from ixiosSpark
// common/types.go checksumHex (commit 874f6d6c): the digest is legacy
// Keccak-512 (NOT SHA3-512) over the ASCII of the lowercase hex without "0x";
// hex character i is upper-cased when it is a letter and nibble i of the
// digest (even i: high nibble, odd i: low nibble of byte i/2) is greater than 7.
export function ixiosChecksumAddress(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 48) throw new Error('An Ixios address is 48 bytes.');
  const hex = bytesToHex(bytes);
  const digest = keccak_512(new TextEncoder().encode(hex));
  let out = '0x';
  for (let i = 0; i < hex.length; i++) {
    const nibble = i % 2 === 0 ? digest[i >> 1] >> 4 : digest[i >> 1] & 0x0f;
    out += hex[i] > '9' && nibble > 7 ? hex[i].toUpperCase() : hex[i];
  }
  return out;
}

// Accepts only "0x" + exactly 96 hex characters (48 bytes). The 20- and 32-byte
// forms are rejected: the Ixios RPC zero-pads them to 48 bytes
// (common/address_compat.go decodeAddressText), which would send to a different
// account. All-lowercase or all-uppercase input is accepted as unchecksummed;
// mixed case must match ixiosChecksumAddress() exactly. Returns the 48 bytes.
export function parseIxiosAddress(text) {
  if (typeof text !== 'string' || !/^0x[0-9a-fA-F]{96}$/.test(text)) throw new Error('Enter a 48-byte Ixios address: 0x followed by 96 hex characters.');
  const hex = text.slice(2);
  const bytes = hexToBytes(hex.toLowerCase());
  if (hex !== hex.toLowerCase() && hex !== hex.toUpperCase() && ixiosChecksumAddress(bytes) !== text) throw new Error('Ixios address checksum does not match. Check the address.');
  return bytes;
}
