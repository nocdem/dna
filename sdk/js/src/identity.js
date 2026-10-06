// Identity from a 24-word recovery phrase — exactly the wallet's derivation
// (web-wallet/src/nodus/derive.js): BIP39 seed -> SHAKE256(seed ‖
// "qgp-signing-v1") = the 32-byte ML-DSA-87 signing seed -> the key pair
// (web-wallet/src/nodus/mldsa87.wasm, the wallet's own derivation module) ->
// the Nodus address SHA3-512(public key) (128 hex). The EVM address is its
// first 32 bytes (web-wallet/src/evm/address.js evmAddressFromFingerprint;
// decision 2026-10-04-nodus-evm-domain.md item 3: 32-byte addresses).
//
// Nothing here touches the network. The phrase is held only as long as the
// call runs; JavaScript strings cannot be wiped, so a caller that cares keeps
// the phrase out of long-lived variables (README "Security").
import { readFile } from 'node:fs/promises';
import { deriveNodusAddress, nodusSigningSeed, evmAddressFromFingerprint, toChecksumAddress } from './wallet.js';

const MLDSA_WASM = new URL('../../../web-wallet/src/nodus/mldsa87.wasm', import.meta.url);
let mldsaBytes;

async function derivationModule() {
  mldsaBytes ??= await readFile(MLDSA_WASM);
  return mldsaBytes;
}

// phrase -> { fingerprint: 128 hex (the Nodus address), evmAddress: 64
// lowercase hex, displayAddress: "0x" + checksummed 64 hex }
export async function deriveIdentity(phrase) {
  const fingerprint = await deriveNodusAddress(phrase, { wasmBytes: await derivationModule() });
  const evmAddress = evmAddressFromFingerprint(fingerprint);
  return { fingerprint, evmAddress, displayAddress: toChecksumAddress(evmAddress) };
}

// phrase -> the 32-byte signing seed. The caller owns it and must wipe it
// (fill(0)); the SDK hands it to the send module's client, which wipes it on
// every path (web-wallet/src/nodus/client.js unlock / identify).
export function signingSeed(phrase) {
  return nodusSigningSeed(phrase);
}
