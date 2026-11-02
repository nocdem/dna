// Offline composition only: the caller obtains chain state, controls approval,
// and is responsible for any eventual submission. No broadcast occurs here.
import { buildXionDirectSignDoc, encodeXionTxRaw } from './xion-sign-doc.js';
import { mldsa65Sign } from './mldsa65-sign.js';
export async function signXionTransfer({seed,publicKey,wasmBytes,signal,...fields}={}) {
  signal?.throwIfAborted();
  const {bodyBytes,authInfoBytes,signDocBytes}=buildXionDirectSignDoc({...fields,publicKey});
  const signed=await mldsa65Sign({seed,message:signDocBytes,context:'xion',wasmBytes,signal});
  try {
    signal?.throwIfAborted();
    let mismatch=signed.publicKey.length ^ publicKey.length;
    for(let i=0;i<signed.publicKey.length;i++) mismatch |= signed.publicKey[i] ^ publicKey[i];
    if(mismatch) throw new Error('Signing key does not match XION sender.');
    return encodeXionTxRaw({bodyBytes,authInfoBytes,signature:signed.signature});
  } finally { signed.publicKey.fill(0);signed.signature.fill(0); }
}
