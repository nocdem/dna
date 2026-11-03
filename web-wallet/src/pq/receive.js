import { Mnemonic, getBytes } from 'ethers';
import { sha256, sha512, sha512_256 } from '@noble/hashes/sha2';
import { sha3_256, shake256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { blake2b } from '@noble/hashes/blake2b';
import { blake3 } from '@noble/hashes/blake3';
import { hmac } from '@noble/hashes/hmac';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { base32nopad, bech32, bech32m } from '@scure/base';
import { validateNodusPhrase } from '../recovery.js';
import { PQ_NETWORKS, isPqChain, pqNetwork } from './networks.js';

// Nodus recovery policy v1: dedicated labels for Algorand, CKB, QTC and Asentum. The
// tidecoin label is kept only for the unregistered legacy send stack (tidecoin-wallet-sign.js);
// Soqucoin, XION, Splendor and Tidecoin receive addresses follow each chain's own wallet
// (plan docs/plans/approved/2026-11-03-pq-native.md section 1) and do not use these labels.
const ROOTS = Object.freeze({
  algorand: ['algorand-falcon1024-v1', 32],
  tidecoin: ['tidecoin-falcon512-v1', 32],
  ckb: ['ckb-slh-dsa-sha2-256s-v1', 96],
  qtc: ['qtc-pq-v1', 32],
  asentum: ['asentum-mldsa65-v1', 32],
});
const HARDENED = 0x80000000;
const SECP_N = secp256k1.CURVE.n;
const SAFE_ERROR = 'Receive address could not be derived.';
const ascii = text => new TextEncoder().encode(text);
const bytes = (...values) => Uint8Array.of(...values);
function join(...parts) {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function wipe(...arrays) { for (const array of arrays) array?.fill(0); }
function hash(algorithm, ...parts) {
  const state = algorithm.create();
  try { for (const part of parts) state.update(part); return state.digest(); }
  finally { state.destroy(); }
}
function mac(algorithm, key, ...parts) {
  const state = hmac.create(algorithm, key);
  try { for (const part of parts) state.update(part); return state.digest(); }
  finally { state.destroy(); }
}
function uint32(value, littleEndian = false) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, littleEndian);
  return out;
}
function exactBytes(value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new Error('Invalid public key.');
}
function taggedHash(tag, ...parts) {
  const prefix = hash(sha256, ascii(tag));
  try { return hash(sha256, prefix, prefix, ...parts); }
  finally { wipe(prefix); }
}
function hash160(publicKey) {
  const digest = hash(sha256, publicKey);
  try { return hash(ripemd160, digest); } finally { wipe(digest); }
}
function bigFromBytes(value) { return BigInt('0x' + bytesToHex(value)); }
function bytesFromBig(value) {
  const out = new Uint8Array(32);
  for (let index = 31; index >= 0; index--) { out[index] = Number(value & 0xffn); value >>= 8n; }
  return out;
}
const phraseSeed = normalized => getBytes(Mnemonic.fromPhrase(normalized).computeSeed());

// XION: Cosmos SDK v0.55.0 crypto/hd/hdpath.go (64fd208a), ported as written; plan section 1.2.
// Public key of PrivKeyFromBytes(k): decred reduces k mod n, and the zero scalar gives the point
// at infinity, serialised by decred as 0x02 || 32 zero bytes (static trace, plan section 1.2).
// @noble/curves refuses the zero scalar, so that case is decided here, before it is called.
export function xionCompressedPublicKey(key) {
  exactBytes(key, 32);
  let scalar;
  try {
    scalar = bytesFromBig(bigFromBytes(key) % SECP_N);
    if (scalar.every(byte => byte === 0)) return join(bytes(2), new Uint8Array(32));
    return secp256k1.getPublicKey(scalar, true);
  } finally { wipe(scalar); }
}
// derivePrivateKey(key, chain, index, harden): index carries the 0x80000000 bit when hardened.
export function xionHdChild(key, chain, index) {
  exactBytes(key, 32); exactBytes(chain, 32);
  let publicKey, data, digest, sum;
  try {
    if (index >= HARDENED) data = join(bytes(0), key, uint32(index));
    else { publicKey = xionCompressedPublicKey(key); data = join(publicKey, uint32(index)); }
    digest = mac(sha512, chain, data);
    sum = bytesFromBig((bigFromBytes(digest.subarray(0, 32)) + bigFromBytes(key)) % SECP_N);
    return { key: sum, chain: digest.slice(32) };
  } finally { wipe(publicKey, data, digest); }
}
const XION_PATH = Object.freeze([44 + HARDENED, 118 + HARDENED, HARDENED, 0, 0]);
function xionKey(master) {
  let digest, key, chain, child;
  try {
    digest = mac(sha512, ascii('Bitcoin seed'), master);
    key = digest.slice(0, 32); chain = digest.slice(32);
    for (const index of XION_PATH) {
      child = xionHdChild(key, chain, index);
      wipe(key, chain); key = child.key; chain = child.chain; child = undefined;
    }
    const result = key; key = undefined;
    return result;
  } finally { wipe(digest, key, chain, child?.key, child?.chain); }
}

// Soqucoin: SoquShield cb3e842a lib/services/key_service.dart, account 0; plan section 1.1.
function soqucoinKeySeed(master, retry) {
  let info, salt, prk;
  try {
    info = join(ascii('soqucoin-pqwallet-v1'), uint32(44 + HARDENED), uint32(21329 + HARDENED),
      uint32(HARDENED), uint32(0), uint32(0), retry > 0 ? bytes(retry) : new Uint8Array(0));
    salt = hash(sha256, master);
    prk = mac(sha256, salt, master);
    return mac(sha256, prk, info, bytes(1));
  } finally { wipe(info, salt, prk); }
}

export function pqChainSeed(phrase, chain) {
  if (!isPqChain(chain)) throw new Error('Unknown PQ chain.');
  if (chain === 'soqucoin') throw new Error('Soqucoin signing seed needs soqucoinSigningSeed.');
  const normalized = validateNodusPhrase(phrase);
  if (chain === 'splendor') {
    // sqc-wallet 38ac3ded cmd/wallet/seed.go: the seed is the BIP39 entropy, no PBKDF2.
    const entropy = getBytes(Mnemonic.fromPhrase(normalized).entropy);
    if (entropy.length !== 32) { wipe(entropy); throw new Error('Invalid Splendor seed.'); }
    return entropy;
  }
  let master, input, state;
  try {
    master = phraseSeed(normalized);
    if (chain === 'xion') return xionKey(master);
    input = join(master, ascii(ROOTS[chain][0]));
    state = shake256.create({ dkLen: ROOTS[chain][1] });
    return state.update(input).digest();
  } finally { state?.destroy(); wipe(master, input); }
}

// Address contracts and pinned sources: web-wallet/README.md, "PQ receive — recovery contract v1".
// Falcon header checks match the corresponding native verification formats.
export function pqAddressFromPublicKeys(chain, networkId, publicKey, backupPublicKey) {
  if (typeof networkId !== 'string') throw new Error('Unknown PQ network.');
  pqNetwork(chain, networkId);
  if (chain !== 'qtc' && backupPublicKey !== undefined) throw new Error('Unexpected backup public key.');
  if (chain === 'algorand') {
    exactBytes(publicKey, 1793);
    if (publicKey[0] !== 10) throw new Error('Invalid Falcon public key.');
    for (let salt = 0; salt < 256; salt++) {
      const candidate = hash(sha512_256, ascii('PQA'), ascii('f1'), bytes(salt), publicKey);
      let decodable = true;
      try { ed25519.ExtendedPoint.fromHex(candidate, true); } catch { decodable = false; }
      if (!decodable) {
        const checksum = hash(sha512_256, candidate);
        try { return base32nopad.encode(join(candidate, checksum.subarray(28))); }
        finally { wipe(candidate, checksum); }
      }
      wipe(candidate);
    }
    throw new Error('No canonical PQ address.');
  }
  if (chain === 'tidecoin') {
    exactBytes(publicKey, 897);
    if (publicKey[0] !== 9) throw new Error('Invalid Falcon public key.');
    const serialized = join(bytes(7), publicKey);
    const id = hash160(serialized);
    // Tidecoin Wallet 0.3.1 default account: P2WPKH, Bech32 witness v0, HRP tbc, program HASH160(0x07 || pk).
    try { return bech32.encode('tbc', [0, ...bech32.toWords(id)]); }
    finally { wipe(serialized, id); }
  }
  if (chain === 'soqucoin') {
    exactBytes(publicKey, 1312);
    if (publicKey[0] === 255) throw new Error('Invalid Soqucoin public key.');
    const program = hash(sha256, publicKey);
    try { return bech32m.encode('sq', [1, ...bech32m.toWords(program)]); }
    finally { wipe(program); }
  }
  if (chain === 'ckb') {
    exactBytes(publicKey, 64);
    const config = join(bytes(0x80, 1, 1, 1, 0x6a), publicKey);
    const state = blake2b.create({ dkLen: 32, personalization: ascii('ckb-sphincs+-sct') });
    let args, payload;
    try {
      args = state.update(config).digest();
      const main = networkId === 'mainnet';
      const code = hexToBytes(main
        ? '302d35982f865ebcbedb9a9360e40530ed32adb8e10b42fbbe70d8312ff7cedf'
        : '147ecbb5c5127d982ee1362d2c2bb4267803da2eb006d150e88af6caaa0a7eaf');
      payload = join(bytes(0), code, bytes(main ? 1 : 2), args);
      return bech32m.encode(main ? 'ckb' : 'ckt', bech32m.toWords(payload), 1023);
    } finally { state.destroy(); wipe(config, args, payload); }
  }
  if (chain === 'qtc') {
    exactBytes(publicKey, 1312); exactBytes(backupPublicKey, 32);
    const primaryScript = join(bytes(0x4d, 0x20, 0x05), publicKey, bytes(0xbb));
    const backupScript = join(bytes(0x20), backupPublicKey, bytes(0xbc));
    const primary = taggedHash('P2MRLeaf', bytes(0xc2, 0xfd, 0x24, 0x05), primaryScript);
    const backup = taggedHash('P2MRLeaf', bytes(0xc2, 0x22), backupScript);
    let root;
    try {
      let primaryFirst = false;
      for (let index = 0; index < 32; index++) {
        if (primary[index] !== backup[index]) {
          primaryFirst = primary[index] < backup[index]; break;
        }
      }
      root = taggedHash('P2MRBranch', ...(primaryFirst ? [primary, backup] : [backup, primary]));
      return bech32m.encode(networkId === 'mainnet' ? 'qtc' : 'tqtc', [2, ...bech32m.toWords(root)]);
    } finally { wipe(primaryScript, backupScript, primary, backup, root); }
  }
  exactBytes(publicKey, 1952);
  const digest = hash(chain === 'xion' ? sha256 : chain === 'splendor' ? sha3_256 : blake3, publicKey);
  try {
    if (chain === 'splendor') return 'SQ:' + bytesToHex(digest);
    return bech32.encode(chain === 'xion' ? 'xion' : 'ase', bech32.toWords(digest.subarray(0, 20)));
  } finally { wipe(digest); }
}

async function yieldToLock(signal) {
  signal?.throwIfAborted();
  await new Promise(resolve => setTimeout(resolve, 0));
  signal?.throwIfAborted();
}
class KeygenFailure extends Error {}
const TIDECOIN_SECRET_SIZE = 1281;
// wantSecret is accepted for kind 2 / parameter 512 only (Tidecoin Falcon-512): the module
// keeps that secret key after a successful derivation until pq_receive_clear, and it is copied
// here before the unconditional module cleanup in `finally` (success, error and cancellation).
async function deriveKeys(binary, kind, param, seed, publicSize, signal, wantSecret = false) {
  let instance, secret;
  try {
    signal?.throwIfAborted();
    const result = await WebAssembly.instantiate(binary, {});
    instance = result.instance ?? result;
    signal?.throwIfAborted();
    const api = instance.exports;
    api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) ||
        ['pq_receive_input', 'pq_receive_output', 'pq_receive_seed_size',
          'pq_receive_public_size', 'pq_receive_derive', 'pq_receive_clear']
          .some(name => typeof api[name] !== 'function')) throw new Error('Invalid receive module.');
    if (api.pq_receive_seed_size(kind, param) !== seed.length ||
        api.pq_receive_public_size(kind, param) !== publicSize) throw new Error('Invalid receive module sizes.');
    if (wantSecret && (kind !== 2 || param !== 512 ||
        typeof api.pq_receive_secret !== 'function' || typeof api.pq_receive_secret_size !== 'function' ||
        api.pq_receive_secret_size(kind, param) !== TIDECOIN_SECRET_SIZE)) throw new Error('Invalid receive module secret.');
    const memory = new Uint8Array(api.memory.buffer);
    const input = api.pq_receive_input();
    if (!Number.isInteger(input) || input < 0 || input + seed.length > memory.length)
      throw new Error('Invalid receive module input.');
    memory.set(seed, input);
    signal?.throwIfAborted();
    const status = api.pq_receive_derive(kind, param, seed.length);
    signal?.throwIfAborted();
    if (status !== 0) throw new KeygenFailure('Key generation failed.');
    await yieldToLock(signal);
    const output = api.pq_receive_output();
    const currentMemory = new Uint8Array(api.memory.buffer);
    if (!Number.isInteger(output) || output < 0 || output + publicSize > currentMemory.length)
      throw new Error('Invalid receive module output.');
    const publicKey = currentMemory.slice(output, output + publicSize);
    if (wantSecret) {
      const offset = api.pq_receive_secret();
      if (!Number.isInteger(offset) || offset < 0 || offset + TIDECOIN_SECRET_SIZE > currentMemory.length)
        throw new Error('Invalid receive module secret.');
      secret = currentMemory.slice(offset, offset + TIDECOIN_SECRET_SIZE);
    }
    const keys = { publicKey, secret };
    secret = undefined;
    return keys;
  } finally {
    wipe(secret);
    if (instance) {
      try { instance.exports.pq_receive_clear?.(); }
      finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); }
    }
  }
}
async function keygen(binary, kind, param, seed, publicSize, signal) {
  return (await deriveKeys(binary, kind, param, seed, publicSize, signal)).publicKey;
}

// Tidecoin Wallet extension 0.3.1, default restore; plan section 1.4 steps 3-7. Every PBKDF2 is
// HMAC-SHA512 with 10 iterations. A keygen failure is an error, never a retry.
const TIDECOIN_PATH = Object.freeze([84 + HARDENED, HARDENED, HARDENED, 0]);
const tidecoinKdf = (password, salt, length) => pbkdf2(sha512, password, salt, { c: 10, dkLen: length });
async function tidecoinPublicKey(binary, phrase, signal) {
  let seed64, node, seed, chain, publicKey, secret, data;
  try {
    seed64 = tidecoinKdf(ascii(phrase), ascii('mnemonic'), 64);
    node = tidecoinKdf(ascii('Tidecoin seed'), seed64, 96);
    for (let step = 0; ; step++) {
      seed = node.slice(0, 48); chain = node.slice(48); wipe(node); node = undefined;
      await yieldToLock(signal);
      const next = TIDECOIN_PATH[step];
      // The secret key is needed only where the next step is hardened.
      ({ publicKey, secret } = await deriveKeys(binary, 2, 512, seed, 897, signal, next >= HARDENED));
      wipe(seed); seed = undefined;
      if (next === undefined) return publicKey;
      data = next >= HARDENED ? join(bytes(0), secret, uint32(next)) : join(bytes(7), publicKey, uint32(next));
      wipe(secret); secret = undefined;
      node = tidecoinKdf(data, chain, 96);
      wipe(data, chain, publicKey); data = chain = publicKey = undefined;
    }
  } finally { wipe(seed64, node, seed, chain, secret, data); }
}

// Soqucoin: first of retry 0..8 whose public key does not start with 0xFF (key_service.dart);
// all nine failing is an error. Returns the selected 32-byte seed and its public key.
async function soqucoinSelect(binary, phrase, signal) {
  let master, seed;
  try {
    master = phraseSeed(phrase);
    for (let retry = 0; retry <= 8; retry++) {
      await yieldToLock(signal);
      seed = soqucoinKeySeed(master, retry);
      const publicKey = await keygen(binary, 3, 44, seed, 1312, signal);
      if (publicKey[0] !== 255) { const selected = seed; seed = undefined; return { seed: selected, publicKey }; }
      wipe(seed, publicKey); seed = undefined;
    }
    throw new Error('No valid Soqucoin key for this account.');
  } finally { wipe(master, seed); }
}

function qtcKeySeed(root, networkId, algo) {
  let prk, material, entropy, block;
  try {
    prk = mac(sha256, ascii('QTC-PQ-BIP87-HKDF-V1'), root);
    material = mac(sha256, prk, ascii('m/87h'), uint32(0x80000000 + 87),
      uint32(0x80000000 + (networkId === 'mainnet' ? 0 : 1)), uint32(0x80000000),
      uint32(0), uint32(0), bytes(algo), bytes(1));
    entropy = new Uint8Array(128);
    for (let counter = 0; counter < 4; counter++) {
      block = hash(sha256, material, uint32(counter, true));
      entropy.set(block, counter * 32); wipe(block); block = undefined;
    }
    return entropy.slice(0, algo === 0 ? 32 : 48);
  } finally { wipe(prk, material, entropy, block); }
}

async function chainPublicKeys(binary, chain, root, signal) {
  let seed;
  try {
    if (chain === 'algorand') {
      seed = hash(sha512_256, ascii('PQK'), ascii('f1'), root);
      return await keygen(binary, 1, 1024, seed, 1793, signal);
    }
    if (chain === 'ckb') return await keygen(binary, 4, 5, root, 64, signal);
    return await keygen(binary, 3, 65, root, 1952, signal);
  } finally { wipe(seed); }
}

// The only receive-module loader (the extension build rewrites exactly one URL expression here).
async function loadReceiveModule(signal) {
  const timeout = AbortSignal.timeout(15000);
  const response = await fetch(new URL('./receive-keygen.wasm', import.meta.url), {
    credentials: 'omit', redirect: 'error',
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
  });
  if (!response.ok) throw new Error('Receive module could not load.');
  return response.arrayBuffer();
}

// Seed handed to the ML-DSA-44 signer for the Soqucoin account: the retry-selected HKDF output.
export async function soqucoinSigningSeed(phrase, { wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  const normalized = validateNodusPhrase(phrase);
  const binary = wasmBytes ?? await loadReceiveModule(signal);
  signal?.throwIfAborted();
  const { seed, publicKey } = await soqucoinSelect(binary, normalized, signal);
  wipe(publicKey);
  return seed;
}

export async function derivePqAddresses(phrase, { wasmBytes, signal, onAddress } = {}) {
  signal?.throwIfAborted();
  const normalized = validateNodusPhrase(phrase);
  const addresses = {}, errors = {};
  let binary = wasmBytes;
  try {
    if (!binary) binary = await loadReceiveModule(signal);
    signal?.throwIfAborted();
  } catch {
    signal?.throwIfAborted();
    for (const chain of Object.keys(PQ_NETWORKS)) errors[chain] = SAFE_ERROR;
    return { addresses, errors };
  }
  for (const [chain, network] of Object.entries(PQ_NETWORKS)) {
    await yieldToLock(signal);
    let root, publicKey, backupKey, seed;
    try {
      signal?.throwIfAborted();
      // Tidecoin and Soqucoin keys come straight from the phrase (native rules, plan section 1);
      // their seeds never pass through pqChainSeed.
      if (chain === 'tidecoin') publicKey = await tidecoinPublicKey(binary, normalized, signal);
      else if (chain === 'soqucoin') {
        const selected = await soqucoinSelect(binary, normalized, signal);
        wipe(selected.seed); publicKey = selected.publicKey;
      } else {
        root = pqChainSeed(normalized, chain);
        if (chain !== 'qtc') publicKey = await chainPublicKeys(binary, chain, root, signal);
      }
      for (const { id } of network.networks) {
        if (chain === 'qtc') {
          await yieldToLock(signal);
          seed = qtcKeySeed(root, id, 0);
          try { publicKey = await keygen(binary, 3, 44, seed, 1312, signal); }
          finally { wipe(seed); seed = undefined; }
          await yieldToLock(signal);
          seed = qtcKeySeed(root, id, 1);
          try { backupKey = await keygen(binary, 4, 7, seed, 32, signal); }
          finally { wipe(seed); seed = undefined; }
        }
        signal?.throwIfAborted();
        const address = pqAddressFromPublicKeys(chain, id, publicKey, backupKey);
        signal?.throwIfAborted();
        (addresses[chain] ??= {})[id] = address;
        onAddress?.(chain, id, address);
        signal?.throwIfAborted();
        if (chain === 'qtc') { wipe(publicKey, backupKey); publicKey = backupKey = undefined; }
      }
    } catch {
      signal?.throwIfAborted();
      errors[chain] = SAFE_ERROR;
    } finally { wipe(root, publicKey, backupKey, seed); }
  }
  signal?.throwIfAborted();
  return { addresses, errors };
}
