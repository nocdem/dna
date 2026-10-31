import { Mnemonic, getBytes } from 'ethers';
import { sha256, sha512, sha512_256 } from '@noble/hashes/sha2';
import { sha3_256, shake256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { blake2b } from '@noble/hashes/blake2b';
import { blake3 } from '@noble/hashes/blake3';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { base32nopad, createBase58check, bech32, bech32m } from '@scure/base';
import { validateNodusPhrase } from '../recovery.js';
import { PQ_NETWORKS, isPqChain, pqNetwork } from './networks.js';

// Nodus recovery policy v1: dedicated labels, not native-chain mnemonic claims.
const ROOTS = Object.freeze({
  algorand: ['algorand-falcon1024-v1', 32],
  tidecoin: ['tidecoin-falcon512-v1', 32],
  ckb: ['ckb-slh-dsa-sha2-256s-v1', 96],
  soqucoin: ['soqucoin-mldsa44-v1', 32],
  qtc: ['qtc-pq-v1', 32],
  xion: ['xion-mldsa65-v1', 32],
  splendor: ['splendor-mldsa65-v1', 32],
  asentum: ['asentum-mldsa65-v1', 32],
});
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
const base58check = createBase58check(sha256);

export function pqChainSeed(phrase, chain) {
  if (!isPqChain(chain)) throw new Error('Unknown PQ chain.');
  const normalized = validateNodusPhrase(phrase);
  let master, input, state;
  try {
    master = getBytes(Mnemonic.fromPhrase(normalized).computeSeed());
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
    try { return base58check.encode(join(bytes(0x21), id)); }
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
async function keygen(binary, kind, param, seed, publicSize, signal) {
  let instance;
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
    return currentMemory.slice(output, output + publicSize);
  } finally {
    if (instance) {
      try { instance.exports.pq_receive_clear?.(); }
      finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); }
    }
  }
}

function tidecoinStreamKey(root) {
  const path = [10007, 6868, 7, 0, 0, 0].map(index => uint32(index + 0x80000000));
  let node, child, prk;
  try {
    node = mac(sha512, ascii('Tidecoin PQHD seed'), root);
    for (const index of path) {
      child = mac(sha512, node.subarray(32), bytes(0), node.subarray(0, 32), index);
      wipe(node); node = child; child = undefined;
    }
    prk = mac(sha512, ascii('Tidecoin PQHD hkdf v1'), node.subarray(0, 32));
    return mac(sha512, prk, ascii('Tidecoin PQHD stream key v1'), uint32(7), ...path, bytes(1));
  } finally { wipe(node, child, prk, ...path); }
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
  let seed, stream, block;
  try {
    if (chain === 'algorand') {
      seed = hash(sha512_256, ascii('PQK'), ascii('f1'), root);
      return await keygen(binary, 1, 1024, seed, 1793, signal);
    }
    if (chain === 'tidecoin') {
      stream = tidecoinStreamKey(root);
      for (let counter = 0; counter < 1024; counter++) {
        await yieldToLock(signal);
        block = mac(sha512, stream, ascii('Tidecoin PQHD rng v1'), uint32(counter));
        seed = block.slice(0, 48);
        try { return await keygen(binary, 2, 512, seed, 897, signal); }
        catch (error) { signal?.throwIfAborted(); if (!(error instanceof KeygenFailure)) throw error; }
        finally { wipe(seed, block); seed = block = undefined; }
      }
      throw new KeygenFailure('Key generation failed.');
    }
    if (chain === 'ckb') return await keygen(binary, 4, 5, root, 64, signal);
    return await keygen(binary, 3, chain === 'soqucoin' ? 44 : 65,
      root, chain === 'soqucoin' ? 1312 : 1952, signal);
  } finally { wipe(seed, stream, block); }
}

export async function derivePqAddresses(phrase, { wasmBytes, signal, onAddress } = {}) {
  signal?.throwIfAborted();
  const normalized = validateNodusPhrase(phrase);
  const addresses = {}, errors = {};
  let binary = wasmBytes;
  try {
    if (!binary) {
      const timeout = AbortSignal.timeout(15000);
      const response = await fetch(new URL('./receive-keygen.wasm', import.meta.url), {
        credentials: 'omit', redirect: 'error',
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
      if (!response.ok) throw new Error('Receive module could not load.');
      binary = await response.arrayBuffer();
    }
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
      root = pqChainSeed(normalized, chain);
      if (chain !== 'qtc') publicKey = await chainPublicKeys(binary, chain, root, signal);
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
