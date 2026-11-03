// Offline Asentum 0.2.0 SDK-compatible legacy public-key transfer only.
// Source: official @asentum/sdk 0.2.0 tarball SHA-512 integrity
// Axwe/di3BRgxp8oj+EqelcZ3xqQWzV00yHi4F/cPjWmL7W4970qFO+o7ODf+S/u5Fk4ZhwcuBvBHWs4ynKgMvA==
// No RPC, fee estimation, approval, nonce allocation or broadcast here.
import { bech32 } from '@scure/base';
import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex } from '@noble/hashes/utils';
import { mldsa65Sign } from './mldsa65-sign.js';
function address(s) {
 try { if(typeof s!=='string'||s!==s.toLowerCase()) throw 0;
  const d=bech32.decode(s),b=Uint8Array.from(bech32.fromWords(d.words));
  if(d.prefix!=='ase'||b.length!==20||bech32.encode('ase',bech32.toWords(b))!==s) throw 0; return b;
 } catch {throw new Error('Invalid Asentum address.');}
}
function integer(s,bits,name,positive=false) {
 if(typeof s!=='string'||!/^(0|[1-9]\d{0,77})$/.test(s)) throw new Error(`Invalid ${name}.`);
 let n=BigInt(s);if(n>=(1n<<BigInt(bits))||(positive&&n===0n)) throw new Error(`Invalid ${name}.`);return n;
}
function le(n,length){const out=new Uint8Array(length);for(let i=0;i<length;i++){out[i]=Number(n&255n);n>>=8n;}return out;}
function join(...xs){const out=new Uint8Array(xs.reduce((n,x)=>n+x.length,0));let p=0;for(const x of xs){out.set(x,p);p+=x.length;}return out;}
export function asentumTransferBody({networkId,from,to,amount,nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas='0'}={}) {
 if(networkId!=='testnet')throw new Error('Unsupported Asentum network.');address(from);const recipient=address(to);
 const value=integer(amount,256,'amount',true), n=integer(nonce,64,'nonce'), gas=integer(gasLimit,64,'gas limit',true), max=integer(maxFeePerGas,256,'max fee',true), tip=integer(maxPriorityFeePerGas,256,'priority fee');
 if(tip>max)throw new Error('Priority fee exceeds max fee.');
 // SSZ TransactionBody fixed section = 144; empty data follows the offset.
 return join(le(1423n,8),le(n,8),le(tip,32),le(max,32),le(gas,8),recipient,le(value,32),le(144n,4));
}
export async function signAsentumTransfer({seed,wasmBytes,signal,...fields}={}) {
 signal?.throwIfAborted();const body=asentumTransferBody(fields),digest=blake3(body);
 const signed=await mldsa65Sign({seed,message:digest,context:'asentum',wasmBytes,signal});
 try { signal?.throwIfAborted();const derived=bech32.encode('ase',bech32.toWords(blake3(signed.publicKey).subarray(0,20)));
  if(derived!==fields.from)throw new Error('Signing key does not match Asentum sender.');
  // SSZ LegacySignedTransaction fixed section = offset + pubkey + signature.
  const raw=join(le(4n+1952n+3309n,4),signed.publicKey,signed.signature,body);
  return {rawTx:'0x'+bytesToHex(raw),txHash:'0x'+bytesToHex(blake3(raw))};
 } finally {digest.fill(0);signed.publicKey.fill(0);signed.signature.fill(0);}
}
