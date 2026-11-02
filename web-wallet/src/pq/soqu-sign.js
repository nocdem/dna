// Offline native SOQ signature. Does not derive a wallet, choose inputs or broadcast.
export async function soquSignDigest({ seed, digest, rnd, wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  for (const value of [seed, digest, ...(rnd === undefined ? [] : [rnd])]) if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('SOQ signing inputs must be 32 bytes.');
  let binary = wasmBytes, instance, ownRnd;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./mldsa44-sign.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Signing module could not load.');
    binary = await response.arrayBuffer();
  }
  try {
    signal?.throwIfAborted();
    const result = await WebAssembly.instantiate(binary, {}); instance = result.instance ?? result;
    signal?.throwIfAborted();
    const api = instance.exports; api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) || ['seed', 'message', 'random', 'public_key', 'signature', 'sign', 'clear'].some(s => typeof api[`mldsa44_${s}`] !== 'function')) throw new Error('Invalid SOQ signing module.');
    const memory = new Uint8Array(api.memory.buffer);
    const at = (name, length) => { const offset = api[`mldsa44_${name}`](); if (!Number.isInteger(offset) || offset < 0 || offset + length > memory.length) throw new Error('Invalid SOQ signing memory.'); return offset; };
    if (!rnd) rnd = ownRnd = crypto.getRandomValues(new Uint8Array(32));
    memory.set(seed, at('seed', 32)); memory.set(digest, at('message', 32)); memory.set(rnd, at('random', 32));
    signal?.throwIfAborted();
    if (api.mldsa44_sign() !== 0) throw new Error('SOQ signing failed.');
    signal?.throwIfAborted();
    return { publicKey: memory.slice(at('public_key', 1312), at('public_key', 1312) + 1312), signature: memory.slice(at('signature', 2420), at('signature', 2420) + 2420) };
  } finally {
    ownRnd?.fill(0);
    if (instance) { try { instance.exports.mldsa44_clear?.(); } finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); } }
  }
}
