// Offline Splendor transfer construction only; never broadcasts or obtains
// network state. Exact body schema: pinned core/types/transaction.go at
// 38ac3ded57d6fa931dba3036d490c5d66b0fbcbc.
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { base64 } from '@scure/base';
import { splendorTransferBody } from './splendor-transfer-body.js';
import { mldsa65Sign } from './mldsa65-sign.js';
export async function signSplendorTransfer({seed,wasmBytes,signal,...fields}={}) {
  signal?.throwIfAborted();
  const body=splendorTransferBody(fields);
  const hash=sha3_256(new TextEncoder().encode(body));
  const signed=await mldsa65Sign({seed,message:hash,context:'splendor',wasmBytes,signal});
  try {
    signal?.throwIfAborted();
    const address='SQ:'+bytesToHex(sha3_256(signed.publicKey));
    if(address!==fields.from) throw new Error('Signing key does not match Splendor sender.');
    // Go Transaction struct appends optional public_key and signature after body.
    const publicKey=fields.nonce==='0' ? `,"public_key":"${base64.encode(signed.publicKey)}"` : '';
    const wireJson=body.slice(0,-1)+publicKey+`,"signature":"${base64.encode(signed.signature)}"}`;
    const txHash=bytesToHex(sha3_256(new TextEncoder().encode(wireJson)));
    return {wireJson,txHash};
  } finally { hash.fill(0);signed.publicKey.fill(0);signed.signature.fill(0); }
}
