// Offline legacy Tidecoin Falcon-512 digest signature; NO transaction serialization or send gate. Does not derive a wallet, choose inputs or broadcast.
export async function tidecoinSignDigest({ seed, digest, rnd, wasmBytes, signal } = {}) {
  signal?.throwIfAborted();
  for (const [value,length] of [[seed,48],[digest,32],...(rnd===undefined?[]:[[rnd,88]])]) if (!(value instanceof Uint8Array)||value.length!==length) throw new Error('Invalid TDC native signing input.');
  let binary = wasmBytes, instance, ownRnd;
  if (!binary) {
    const timeout = AbortSignal.timeout(15000);
    const response = await fetch(new URL('./tidecoin-sign.wasm', import.meta.url), { credentials: 'omit', redirect: 'error', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!response.ok) throw new Error('Signing module could not load.');
    binary = await response.arrayBuffer();
  }
  try {
    signal?.throwIfAborted();
    const result = await WebAssembly.instantiate(binary, {}); instance = result.instance ?? result;
    signal?.throwIfAborted();
    const api = instance.exports; api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) || ['seed', 'message', 'random', 'public_key', 'signature', 'signature_length', 'sign', 'clear'].some(s => typeof api[`tdc_${s}`] !== 'function')) throw new Error('Invalid TDC signing module.');
    const memory = new Uint8Array(api.memory.buffer);
    const at = (name, length) => { const offset = api[`tdc_${name}`](); if (!Number.isInteger(offset) || offset < 0 || offset + length > memory.length) throw new Error('Invalid TDC signing memory.'); return offset; };
    if (!rnd) rnd = ownRnd = crypto.getRandomValues(new Uint8Array(88));
    memory.set(seed, at('seed', 48)); memory.set(digest, at('message', 32)); memory.set(rnd, at('random', 88));
    signal?.throwIfAborted();
    if (api.tdc_sign() !== 0) throw new Error('TDC signing failed.');
    signal?.throwIfAborted();
    const length=api.tdc_signature_length();
    if (!Number.isInteger(length)||length<41||length>688)throw new Error('Invalid TDC signature length.');
    return { publicKey: memory.slice(at('public_key', 897), at('public_key', 897) + 897), signature: memory.slice(at('signature', length), at('signature', length) + length) };
  } finally {
    ownRnd?.fill(0);
    if (instance) { try { instance.exports.tdc_clear?.(); } finally { if (instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0); } }
  }
}
