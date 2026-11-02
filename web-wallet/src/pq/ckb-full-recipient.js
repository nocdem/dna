// Full-format recipient parser. The send controller separately gates broad recipients.
// RFC 0021: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
// Hash types: https://docs.nervos.org/docs/tech-explanation/hash-type
// Empty-data/type occupied size: https://docs.nervos.org/docs/tech-explanation/capacity
import {bech32m} from '@scure/base';
import {concatBytes,bytesToHex} from '@noble/hashes/utils';
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;};
function table(...items){let offset=4+4*items.length;const offsets=items.map(x=>{const n=offset;offset+=x.length;return u32(n);});return concatBytes(u32(offset),...offsets,...items);}
export function parseCkbFullRecipient(address,networkId='mainnet'){
 const prefix=networkId==='mainnet'?'ckb':networkId==='testnet'?'ckt':null;if(!prefix)throw Error('Unsupported CKB network.');
 let decoded,payload;try{if(typeof address!=='string'||address!==address.toLowerCase()||address.length>1023)throw Error();decoded=bech32m.decode(address,1023);payload=bech32m.fromWords(decoded.words);if(bech32m.encode(decoded.prefix,bech32m.toWords(payload),1023)!==address)throw Error();}catch{throw Error('Invalid canonical CKB Bech32m address.');}
 if(decoded.prefix!==prefix)throw Error('CKB recipient belongs to a different network.');if(payload.length<34||payload[0]!==0)throw Error('Only full-format CKB addresses are supported.');
 const typeNames={0:'data',1:'type',2:'data1',4:'data2'},hashType=typeNames[payload[33]];if(!hashType)throw Error('Unsupported CKB script hash type.');
 const args=payload.slice(34),code=payload.slice(1,33),script=table(code,Uint8Array.of(payload[33]),concatBytes(u32(args.length),args));
 return {script,lock:{code_hash:'0x'+bytesToHex(code),hash_type:hashType,args:'0x'+bytesToHex(args)},minimumCapacity:BigInt(8+32+1+args.length)*100000000n};
}
