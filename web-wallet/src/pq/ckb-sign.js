// Offline CKB quantum-lock SHA2-256s signature; no wallet access or broadcasting.
export async function ckbSignMessage({ seed, message, rnd, wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  if (!(seed instanceof Uint8Array) || seed.length !== 96) throw new Error('CKB seed must be 96 bytes.');
  for (const value of [message, ...(rnd === undefined ? [] : [rnd])]) if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error('CKB message/randomness must be 32 bytes.');
  let binary = wasmBytes, instance, ownRnd;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./ckb-slh-sign.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Signing module could not load.');
    binary = await response.arrayBuffer();
  }
  try {
    signal?.throwIfAborted();
    const result = await WebAssembly.instantiate(binary, {}); instance = result.instance ?? result;
    signal?.throwIfAborted();
    const api = instance.exports; api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) || ['seed', 'message', 'random', 'public_key', 'signature', 'sign', 'clear'].some(s => typeof api[`ckb_slh_${s}`] !== 'function')) throw new Error('Invalid CKB signing module.');
    const memory = new Uint8Array(api.memory.buffer);
    const at = (name, length) => { const offset = api[`ckb_slh_${name}`](); if (!Number.isInteger(offset) || offset < 0 || offset + length > memory.length) throw new Error('Invalid CKB signing memory.'); return offset; };
    if (!rnd) rnd = ownRnd = crypto.getRandomValues(new Uint8Array(32));
    memory.set(seed, at('seed', 96)); memory.set(message, at('message', 32)); memory.set(rnd, at('random', 32));
    signal?.throwIfAborted();
    if (api.ckb_slh_sign() !== 0) throw new Error('CKB signing failed.');
    signal?.throwIfAborted();
    return { publicKey: memory.slice(at('public_key', 64), at('public_key', 64) + 64), signature: memory.slice(at('signature', 29792), at('signature', 29792) + 29792) };
  } finally {
    ownRnd?.fill(0);
    if (instance) { try { instance.exports.ckb_slh_clear?.(); } finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); } }
  }
}
