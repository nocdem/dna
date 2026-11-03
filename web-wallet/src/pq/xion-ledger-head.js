// Fixed configured-node observation, NOT a cryptographic light-client proof.
// Fail closed on syncing, stale/future header, wrong chain, malformed hash or
// incompatible heights; no account, signed transaction or fee query here.
import {base64} from '@scure/base';
import {integerJson} from './integer-json.js';
const NETS=Object.freeze({mainnet:{url:'https://api.xion-mainnet-1.burnt.com',chain:'xion-mainnet-1'},testnet:{url:'https://api.xion-testnet-2.burnt.com',chain:'xion-testnet-2'}});
const MAX=2n**63n-1n;
const height=v=>typeof v==='string'&&/^[1-9]\d{0,18}$/.test(v)&&BigInt(v)<=MAX;
const stamp=v=>{if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v))return false;const n=Date.parse(v);return Number.isFinite(n)&&new Date(n).toISOString().slice(0,19)===v.slice(0,19);};
export async function readXionLedgerHead({networkId,signal,fetcher,now=Date.now()}={}){
 if(!Object.hasOwn(NETS,networkId)||!Number.isSafeInteger(now))throw Error('Invalid XION ledger request.');
 const net=NETS[networkId],opts={signal,fetcher};
 const info=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/node_info',opts);signal?.throwIfAborted();if(info.default_node_info?.network!==net.chain)throw Error('XION ledger network mismatch.');
 const sync=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/syncing',opts);signal?.throwIfAborted();if(sync.syncing!==false||!height(sync.latest_block_height))throw Error('XION node is syncing or has invalid height.');
 const data=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/blocks/latest',opts);signal?.throwIfAborted();const h=data.sdk_block?.header,legacy=data.block?.header,hash=data.block_id?.hash;
 if(!h||h.chain_id!==net.chain||!height(h.height)||!stamp(h.time)||!legacy||legacy.chain_id!==h.chain_id||legacy.height!==h.height||legacy.time!==h.time)throw Error('Invalid XION latest block.');
 const n=BigInt(h.height),s=BigInt(sync.latest_block_height);if(n<s||n-s>5n)throw Error('Inconsistent XION node heights.');const blockMs=Date.parse(h.time);if(now-blockMs>90000||blockMs-now>30000)throw Error('XION latest block is stale or in the future.');
 let b;try{if(typeof hash!=='string')throw 0;b=base64.decode(hash);if(b.length!==32||b.every(x=>x===0)||base64.encode(b)!==hash)throw 0;}catch{throw Error('Invalid XION block hash.');}
 return Object.freeze({height:h.height,blockHash:Array.from(b,x=>x.toString(16).padStart(2,'0')).join(''),blockTime:h.time,observedAt:new Date(now).toISOString(),source:'configured-rpc'});
}
