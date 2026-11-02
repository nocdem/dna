// Deterministic compressed Algorand Falcon1024, not generic Falcon or FN-DSA.
// seed is SHA512_256('PQK' || 'f1' || Nodus chain root), as receive.js derives.
// message must be raw TX || canonical-msgpack(txn); no implicit hashing here.
const exportsNeeded = ['algo_seed','algo_message','algo_public_key','algo_signature',
  'algo_signature_length','algo_sign','algo_clear'];
export async function algorandFalconSign({ seed, message, wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Invalid Falcon signing seed.');
  if (!(message instanceof Uint8Array) || message.length < 3 || message.length > 4096 || message[0] !== 0x54 || message[1] !== 0x58) throw new Error('Invalid Algorand transaction preimage.');
  let binary = wasmBytes, instance;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./algorand-sign.wasm', import.meta.url), {
      credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
    if (!response.ok) throw new Error('Falcon signing module unavailable.');
    binary = await response.arrayBuffer();
  }
  try {
    signal?.throwIfAborted();
    const result = await WebAssembly.instantiate(binary, {});
    instance = result.instance ?? result;
    signal?.throwIfAborted();
    const api = instance.exports;
    api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) || exportsNeeded.some(name => typeof api[name] !== 'function')) throw new Error('Invalid Falcon signing module.');
    const memory = new Uint8Array(api.memory.buffer);
    const region = (offset, length) => {
      if (!Number.isSafeInteger(offset) || offset < 0 || offset + length > memory.length) throw new Error('Invalid Falcon memory region.');
      return offset;
    };
    memory.set(seed, region(api.algo_seed(), 32));
    memory.set(message, region(api.algo_message(), message.length));
    signal?.throwIfAborted();
    if (api.algo_sign(message.length) !== 0) throw new Error('Falcon signing failed.');
    // Let a pending lock/cancel run before copying public results.
    await new Promise(resolve => setTimeout(resolve, 0));
    signal?.throwIfAborted();
    const size = api.algo_signature_length();
    if (!Number.isInteger(size) || size < 2 || size > 1423) throw new Error('Invalid Falcon signature length.');
    const publicKey = memory.slice(region(api.algo_public_key(), 1793), api.algo_public_key() + 1793);
    const signature = memory.slice(region(api.algo_signature(), size), api.algo_signature() + size);
    if (publicKey[0] !== 10 || signature[0] !== 0xba) throw new Error('Invalid Falcon output encoding.');
    return { publicKey, signature };
  } finally {
    if (instance) {
      try { instance.exports.algo_clear?.(); }
      finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); }
    }
  }
}
