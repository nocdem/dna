// Source port: ixiosSpark v1.1.1 ccd1345eed8873a6d0174b3e9a076da67ceb7750,
// core/types/{tx_legacy,transaction_signing,signature_payload,mldsa87}.go.
// Only protected legacy native transfers with full 48-byte recipient, signed for one
// listed network (src/pq/ixios/network.js): the chain id of its entry is in the signed
// preimage and gives v = 2 * chain id + 35.
// No transport, preflight, durable reservation, or broadcast in this module.
import {encodeRlp,decodeRlp,keccak256} from 'ethers';
import {parseIxiosAddress,ixiosChecksumAddress} from './address.js';
import {ixiosNetwork} from './network.js';
import {ixiosAddressBytes} from './derive.js';
import {mldsa87Sign} from '../sign.js';
const hex=b=>'0x'+Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const uint=(v,bits,name)=>{if(typeof v!=='bigint'||v<0n||v>=(1n<<BigInt(bits)))throw Error(`Invalid Ixios ${name}.`);return v;};
const intHex=n=>n===0n?'0x':'0x'+(n.toString(16).length%2?'0':'')+n.toString(16);
const bytes=s=>Uint8Array.from(s.slice(2).match(/../g)??[],x=>parseInt(x,16));
function fields({to,amount,nonce,gasPrice,gasLimit}={}){
 const full=parseIxiosAddress(to),dest=full.slice(0,16).every(x=>x===0)?full.slice(16):full;uint(amount,256,'amount');uint(nonce,64,'nonce');uint(gasPrice,256,'gas price');uint(gasLimit,64,'gas limit');if(amount===0n||gasPrice===0n||gasLimit!==1000n)throw Error('Invalid Ixios transfer limits.');return [intHex(nonce),intHex(gasPrice),intHex(gasLimit),hex(dest),intHex(amount),'0x'];
}
const chainIdOf=networkId=>BigInt(ixiosNetwork(networkId).chainId),vOf=networkId=>intHex(2n*chainIdOf(networkId)+35n);
export function ixiosSigningHash(transfer,{networkId='mainnet'}={}){return keccak256(encodeRlp([...fields(transfer),intHex(chainIdOf(networkId)),'0x','0x']));}
export async function signIxiosTransfer(transfer,{seed,rnd,wasmBytes,signal,networkId='mainnet'}={}){
 signal?.throwIfAborted();const base=fields(transfer),digest=ixiosSigningHash(transfer,{networkId}),v=vOf(networkId),{publicKey,signature}=await mldsa87Sign({seed,hash:bytes(digest),rnd,wasmBytes,signal});signal?.throwIfAborted();
 const raw=encodeRlp([...base,v,'0x','0x','0x01',hex(publicKey),hex(signature)]),hash=keccak256(raw),from=ixiosChecksumAddress(ixiosAddressBytes(publicKey));return {raw,hash,from,signingHash:digest,publicKey,signature};
}
export function parseIxiosSignedTransfer(raw,{networkId='mainnet'}={}){
 const v=vOf(networkId);if(typeof raw!=='string'||!/^0x(?:[0-9a-f]{2})+$/.test(raw)||raw.length>20000)throw Error('Invalid Ixios signed transaction.');let a;try{a=decodeRlp(raw);}catch{throw Error('Invalid Ixios RLP.');}if(!Array.isArray(a)||a.length!==12||a.some(x=>typeof x!=='string')||encodeRlp(a)!==raw||a[5]!=='0x'||a[6]!==v||a[7]!=='0x'||a[8]!=='0x'||a[9]!=='0x01'||a[10].length!==2+2592*2||a[11].length!==2+4627*2)throw Error('Unsupported Ixios signed transaction.');
 const number=(s,bits)=>{if(!/^0x(?:[0-9a-f]{2})*$/.test(s)||(s!=='0x'&&s.startsWith('0x00')))throw Error('Noncanonical Ixios integer.');return uint(s==='0x'?0n:BigInt(s),bits,'integer');};const toBytes=bytes(a[3]);if(toBytes.length!==32&&toBytes.length!==48)throw Error('Invalid Ixios recipient wire length.');if(toBytes.length===48&&toBytes.slice(0,16).every(x=>x===0))throw Error('Noncanonical Ixios recipient encoding.');const full=toBytes.length===32?Uint8Array.from([...new Uint8Array(16),...toBytes]):toBytes;const transfer={nonce:number(a[0],64),gasPrice:number(a[1],256),gasLimit:number(a[2],64),to:ixiosChecksumAddress(full),amount:number(a[4],256)};fields(transfer);return {...transfer,raw,hash:keccak256(raw),signingHash:ixiosSigningHash(transfer,{networkId}),from:ixiosChecksumAddress(ixiosAddressBytes(bytes(a[10]))),publicKey:bytes(a[10]),signature:bytes(a[11])};
}
