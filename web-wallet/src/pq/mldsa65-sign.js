// Protocol-specific ML-DSA-65; deterministic as required by the pinned
// XION/Comet, Asentum SDK and Splendor implementations. Not a transaction broadcaster.
export async function mldsa65Sign({seed,message,context,wasmBytes,signal}={}) {
  signal?.throwIfAborted();
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Signing seed must be 32 bytes.');
  if (!(message instanceof Uint8Array) || message.length > 65536) throw new Error('Invalid signing message.');
  if (context !== 'xion' && context !== 'asentum' && context !== 'splendor') throw new Error('Invalid signing context.');
  let binary=wasmBytes;
  if (!binary) {
    const timeout=AbortSignal.timeout(15000);
    const response=await fetch(new URL('./mldsa65-sign.wasm',import.meta.url),{credentials:'omit',redirect:'error',signal:signal?AbortSignal.any([signal,timeout]):timeout});
    if (!response.ok) throw new Error('Signing module could not load. Reload to retry.');
    binary=await response.arrayBuffer();
  }
  let instance;
  try {
    signal?.throwIfAborted();
    const result=await WebAssembly.instantiate(binary,{}); instance=result.instance ?? result;
    signal?.throwIfAborted();
    const api=instance.exports; api._initialize?.();
    if (!(api.memory instanceof WebAssembly.Memory) || ['mldsa65_seed','mldsa65_message','mldsa65_public_key','mldsa65_signature','mldsa65_sign','mldsa65_clear'].some(name=>typeof api[name]!=='function')) throw new Error('Invalid signing module.');
    const memory=new Uint8Array(api.memory.buffer);
    const at=(name,size)=>{ const offset=api[name](); if(!Number.isInteger(offset)||offset<0||offset+size>memory.length) throw new Error('Invalid signing module memory.');return offset; };
    memory.set(seed,at('mldsa65_seed',32));memory.set(message,at('mldsa65_message',message.length));
    signal?.throwIfAborted();
    if(api.mldsa65_sign(message.length,context==='splendor'?1:0)!==0) throw new Error('Signing failed.');
    signal?.throwIfAborted();
    return {publicKey:memory.slice(at('mldsa65_public_key',1952),at('mldsa65_public_key',1952)+1952),signature:memory.slice(at('mldsa65_signature',3309),at('mldsa65_signature',3309)+3309)};
  } finally {
    if(instance) { try {instance.exports.mldsa65_clear?.();} finally {if(instance.exports.memory) new Uint8Array(instance.exports.memory.buffer).fill(0);} }
  }
}
