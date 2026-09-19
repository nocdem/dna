import { HDNodeWallet, Mnemonic, randomBytes, getBytes } from 'ethers';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { Keypair } from '@solana/web3.js';
import { TronWeb } from 'tronweb';
export function newPhrase() { return Mnemonic.entropyToPhrase(randomBytes(32)); }
export function normalizePhrase(value) { return value.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' '); }
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
  const normalized = normalizePhrase(phrase);
  if (!Mnemonic.isValidMnemonic(normalized)) throw new Error('Recovery phrase is invalid. Check the words and order.');
  const mnemonic = Mnemonic.fromPhrase(normalized);
  const seed = getBytes(mnemonic.computeSeed());
  try {
    const root = HDNodeWallet.fromSeed(seed);
    const evm = root.derivePath("m/44'/60'/0'/0/0");
    const tron = root.derivePath("m/44'/195'/0'/0/0");
    const solSeed = solanaSeed(seed);
    const solana = Keypair.fromSeed(solSeed); solSeed.fill(0);
    return { evm, solana, tronPrivateKey: tron.privateKey.slice(2), addresses: { ethereum: evm.address, bsc: evm.address, solana: solana.publicKey.toBase58(), tron: TronWeb.address.fromPrivateKey(tron.privateKey.slice(2)) } };
  } finally { seed.fill(0); }
}
// Keys live only in this tab. JS strings cannot be reliably wiped; locking drops references.
export function assertWalletActive(wallet) { if (!wallet || wallet.locked) throw new Error('Wallet is locked.'); }
export function disposeWallet(wallet) {
  if (!wallet) return;
  wallet.locked = true;
  wallet.solana?.secretKey.fill(0);
  wallet.solana = null; wallet.evm = null; wallet.tronPrivateKey = null;
}
