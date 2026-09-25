import { HDNodeWallet, Mnemonic, randomBytes, getBytes } from 'ethers';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { getAddressDecoder } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519';
import { TronWeb } from 'tronweb';
import { validateNodusPhrase } from './recovery.js';
export { normalizePhrase } from './recovery.js';
export function newPhrase() { return Mnemonic.entropyToPhrase(randomBytes(32)); }
export function solanaSeed(seed) {
  let digest = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
  for (const index of [44, 501, 0, 0]) {
    const data = new Uint8Array(37);
    data.set(digest.slice(0, 32), 1);
    new DataView(data.buffer).setUint32(33, index + 0x80000000, false);
    const next = hmac(sha512, digest.slice(32), data);
    digest.fill(0); data.fill(0); digest = next;
  }
  const key = digest.slice(0, 32); digest.fill(0); return key;
}
export function deriveWallet(phrase) {
  const normalized = validateNodusPhrase(phrase);
  const mnemonic = Mnemonic.fromPhrase(normalized);
  const seed = getBytes(mnemonic.computeSeed());
  try {
    const root = HDNodeWallet.fromSeed(seed);
    const evm = root.derivePath("m/44'/60'/0'/0/0");
    const tron = root.derivePath("m/44'/195'/0'/0/0");
    const solSeed = solanaSeed(seed);
    // The wallet owns the one long-lived signing buffer: seed (0-31) + public key
    // (32-63). Solana signing reads its first 32 bytes in place (adapters/solana.js),
    // so disposal overwrites the material actually used to sign.
    let solana;
    try {
      const publicBytes = ed25519.getPublicKey(solSeed), secretKey = new Uint8Array(64);
      secretKey.set(solSeed); secretKey.set(publicBytes, 32);
      solana = { publicKey: getAddressDecoder().decode(publicBytes), secretKey };
    } finally { solSeed.fill(0); }
    return { recoveryPhrase: normalized, evm, solana, tronPrivateKey: tron.privateKey.slice(2), addresses: { ethereum: evm.address, bsc: evm.address, solana: solana.publicKey, tron: TronWeb.address.fromPrivateKey(tron.privateKey.slice(2)) } };
  } finally { seed.fill(0); }
}
// Keys live only in this tab. JS strings cannot be reliably wiped; locking drops references.
export function assertWalletActive(wallet) { if (!wallet || wallet.locked) throw new Error('Wallet is locked.'); }
export function disposeWallet(wallet) {
  if (!wallet) return;
  wallet.locked = true; wallet.recoveryPhrase = null;
  wallet.solana?.secretKey.fill(0);
  wallet.solana = null; wallet.evm = null; wallet.tronPrivateKey = null;
}
