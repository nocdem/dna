// Offline native Falcon payment assembly. No network access or broadcast.
// go-algorand v5.0.0-stable data/transactions/{signedtxn,pqsig}.go:
// one pqsig only, no sig/msig/lsig or redundant AuthAddr. Zero salt omitted.
import { sha512_256 } from '@noble/hashes/sha512';
import { base32nopad, base64 } from '@scure/base';
import { algorandNetwork } from './algorand.js';
import { pqAddressFromPublicKeys } from './receive.js';
import { encodeAlgorandPayment, algorandFalconPaymentPreimage } from './algorand-send.js';
import { algorandFalconSign } from './algorand-sign.js';
const ascii=s=>new TextEncoder().encode(s);
const join=(...parts)=>{const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let i=0;for(const p of parts){out.set(p,i);i+=p.length;}return out;};
const str=s=>join(Uint8Array.of(0xa0+s.length),ascii(s));
const bin=b=>join(b.length<=255?Uint8Array.of(0xc4,b.length):Uint8Array.of(0xc5,b.length>>8,b.length&255),b);
export async function signAlgorandPayment({seed,payment,networkId,wasmBytes,signal}={}) {
  if(!['mainnet','testnet'].includes(networkId))throw new Error('Unsupported Algorand network.');
  signal?.throwIfAborted();
  // Clone all public review fields before awaiting the signer: caller mutation
  // cannot make the signed message differ from the returned envelope.
  const frozen={...payment,sender:payment?.sender?.slice(),receiver:payment?.receiver?.slice(),genesisHash:payment?.genesisHash?.slice()};
  const network=algorandNetwork(networkId),genesis=base64.decode(network.genesisHash);
  if(!(frozen.genesisHash instanceof Uint8Array) || frozen.genesisHash.length!==32 || !genesis.every((v,i)=>v===frozen.genesisHash[i]) || frozen.genesisId!==`${networkId}-v1.0`)throw new Error('Algorand payment has wrong network identity.');
  const transaction=encodeAlgorandPayment(frozen),preimage=algorandFalconPaymentPreimage(frozen);
  const signed=await algorandFalconSign({seed,message:preimage,wasmBytes,signal});
  try {
    signal?.throwIfAborted();
    const from=pqAddressFromPublicKeys('algorand',networkId,signed.publicKey);
    const decoded=base32nopad.decode(from).slice(0,32);
    if(!decoded.every((v,i)=>v===frozen.sender[i]))throw new Error('Signing key does not match Algorand sender.');
    let salt=-1;
    for(let i=0;i<256;i++) {
      const candidate=sha512_256(join(ascii('PQA'),ascii('f1'),Uint8Array.of(i),signed.publicKey));
      if(candidate.every((v,j)=>v===decoded[j])) {salt=i;break;}
    }
    if(salt<0)throw new Error('Invalid Algorand PQ salt.');
    const saltBytes=salt<128?Uint8Array.of(salt):Uint8Array.of(0xcc,salt);
    const proof=join(Uint8Array.of(salt===0?0x83:0x84),str('pk'),bin(signed.publicKey),str('sch'),bin(ascii('f1')),str('sig'),bin(signed.signature),...(salt===0?[]:[str('slt'),saltBytes]));
    return {signedBytes:join(Uint8Array.of(0x82),str('pqsig'),proof,str('txn'),transaction),transactionId:base32nopad.encode(sha512_256(preimage)),from};
  } finally { signed.publicKey.fill(0);signed.signature.fill(0); }
}
