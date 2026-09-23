// ML-DSA-87 (FIPS 204) sizes — shared/crypto/sign/qgp_dilithium.h:12-14.
const QGP_DSA87_PUBLICKEYBYTES = 2592;
const QGP_DSA87_SIGNATURE_BYTES = 4627;

// Hedged (randomized) ML-DSA-87 signing over an already-computed 32-byte hash.
// Decision: docs/plans/decisions/2026-09-23-web-wallet-mldsa-hedged-signing.md.
// Same fetch/instantiate/wipe shape as src/nodus/derive.js:12-18, :25-36, :35-39 —
// separate module (src/pq/mldsa87-sign.wasm), separate WASM instance per call.
export async function mldsa87Sign({ seed, hash, rnd, wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Signing seed must be 32 bytes.');
  if (!(hash instanceof Uint8Array) || hash.length !== 32) throw new Error('Signing hash must be 32 bytes.');
  if (rnd !== undefined && (!(rnd instanceof Uint8Array) || rnd.length !== 32)) throw new Error('Signing rnd must be 32 bytes.');
  // Fetch the public module before generating any mutable secret buffer.
  let binary = wasmBytes;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./mldsa87-sign.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Signing module could not load. Reload to retry.');
    binary = await response.arrayBuffer();
  }
  let instance, ownRnd;
  try {
    signal?.throwIfAborted();
    ({ instance } = await WebAssembly.instantiate(binary, {}));
    signal?.throwIfAborted();
    instance.exports._initialize?.();
    if (rnd === undefined) rnd = ownRnd = crypto.getRandomValues(new Uint8Array(32));
    const memory = new Uint8Array(instance.exports.memory.buffer);
    memory.set(seed, instance.exports.mldsa_seed());
    memory.set(hash, instance.exports.mldsa_hash());
    memory.set(rnd, instance.exports.mldsa_rnd());
    if (instance.exports.mldsa_sign() !== 0) throw new Error('Signing failed.');
    const pkOffset = instance.exports.mldsa_pk();
    const sigOffset = instance.exports.mldsa_sig();
    return {
      publicKey: memory.slice(pkOffset, pkOffset + QGP_DSA87_PUBLICKEYBYTES),
      signature: memory.slice(sigOffset, sigOffset + QGP_DSA87_SIGNATURE_BYTES),
    };
  } finally {
    ownRnd?.fill(0);
    // Includes sk and every other private temporary the signing call used;
    // every call owns a fresh instance. The caller's seed/hash are NOT ours to
    // wipe — the caller owns them (only our own generated rnd, above, is ours).
    if (instance) new Uint8Array(instance.exports.memory.buffer).fill(0);
  }
}
