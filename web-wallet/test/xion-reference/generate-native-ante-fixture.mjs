// Public, synthetic-only phrase and synthetic-xion chain ID. Never broadcast.
import {readFileSync,writeFileSync} from 'node:fs';
import {base64,bech32} from '@scure/base';
import {hexToBytes} from '@noble/hashes/utils';
import {pqChainSeed} from '../../src/pq/receive.js';
import {mldsa65Sign} from '../../src/pq/mldsa65-sign.js';
import {buildXionDirectSignDoc,encodeXionTxRaw} from '../../src/pq/xion-sign-doc.js';
const f=JSON.parse(readFileSync(new URL('../fixtures/pq-receive.json',import.meta.url))).vectors[0];
const wasmBytes=readFileSync(new URL('../../src/pq/mldsa65-sign.wasm',import.meta.url));
const seed=pqChainSeed(f.phrase,'xion'),publicKey=hexToBytes(f.keys.xion.pk),from=f.addresses.xion.mainnet,to=bech32.encode('xion',bech32.toWords(new Uint8Array(20).fill(2)));
async function tx({chain='synthetic-xion',account='0',sequence='0',fee='30000',bad=false}={}){
 const doc=buildXionDirectSignDoc({networkId:'mainnet',from,to,amount:'1',fee,gas:'1000000',sequence,accountNumber:account,publicKey});
 const bytes=Buffer.from(doc.signDocBytes),needle=Buffer.from('xion-mainnet-1'),offset=bytes.indexOf(needle);
 if(offset<0||chain.length!==needle.length)throw Error('Unexpected chain encoding.');bytes.set(Buffer.from(chain),offset);
 const signed=await mldsa65Sign({seed,message:bytes,wasmBytes,context:'xion'});if(bad)signed.signature[0]^=1;
 return base64.encode(encodeXionTxRaw({...doc,signature:signed.signature}));
}

async function timeoutFixtures(){
 const doc=buildXionDirectSignDoc({networkId:'mainnet',from,to,amount:'1',fee:'30000',gas:'1000000',sequence:'0',accountNumber:'0',publicKey});
 const vi=n=>{let x=BigInt(n),a=[];do{let v=Number(x&127n);x>>=7n;if(x)v|=128;a.push(v);}while(x);return Uint8Array.from(a);};
 const cat=(...xs)=>Uint8Array.from(xs.flatMap(x=>Array.from(x))),field=(tag,b)=>cat(vi(tag*8+2),vi(b.length),b);
 const body=cat(doc.bodyBytes,Uint8Array.of(0x18,0x02));
 const signDoc=cat(field(1,body),field(2,doc.authInfoBytes),field(3,new TextEncoder().encode('synthetic-xion')));
 const signed=await mldsa65Sign({seed,message:signDoc,wasmBytes,context:'xion'});
 return {timeout2:base64.encode(encodeXionTxRaw({bodyBytes:body,authInfoBytes:doc.authInfoBytes,signature:signed.signature})),tamperedTimeout:base64.encode(encodeXionTxRaw({bodyBytes:cat(doc.bodyBytes,Uint8Array.of(0x18,0x03)),authInfoBytes:doc.authInfoBytes,signature:signed.signature}))};
}
try{
 const out={from,to,publicKey:base64.encode(publicKey),good:await tx(),highAccount:await tx({account:'9223372036854775808'}),badSignature:await tx({bad:true}),badChain:await tx({chain:'wrong-chain-01'}),badAccount:await tx({account:'1'}),badSequence:await tx({sequence:'1'}),lowFee:await tx({fee:'1'}),...await timeoutFixtures()};
 writeFileSync(process.argv[2]??new URL('./native-ante-synthetic.json',import.meta.url),JSON.stringify(out));
}finally{seed.fill(0);}
