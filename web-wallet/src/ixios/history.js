// Bounded, provider-reported post-Aegis IXIOS direct native history candidate.
// No indexer, light-client proof, internal-call trace, token scan, or claim of
// completeness. ixiosSpark v1.1.1 internal/ethapi/api.go RPCMarshalBlock,
// RPCTransaction, marshalReceipt; params/config.go AegisBlock=32,400,000;
// consensus/fastClique/fastClique.go compares block Time with UnixMilli().
import {rpc,formatUnits} from '../core.js';import {parseIxiosAddress} from './address.js';import {IXIOS_GENESIS_HASH} from './balance.js';import {IXIOS_NETWORK} from './network.js';
const AEGIS=32400000,MAX_BLOCKS=50,MAX_TRANSACTIONS=500,MAX_MATCHES=25,HASH=/^0x[0-9a-f]{64}$/;
const quantity=(x,max=(1n<<256n)-1n)=>{if(typeof x!=='string'||!/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(x))throw Error('Invalid Ixios RPC quantity.');const n=BigInt(x);if(n>max)throw Error('Ixios RPC quantity out of range.');return n;};
const safe=(x)=>Number(quantity(x,BigInt(Number.MAX_SAFE_INTEGER)));
const address=x=>{parseIxiosAddress(x);return x.toLowerCase();};
const number=n=>'0x'+BigInt(n).toString(16);
function header(b,expected){if(!b||typeof b!=='object'||safe(b.number)!==expected||!HASH.test(b.hash??'')||!HASH.test(b.parentHash??''))throw Error('Invalid Ixios block identity.');const time=safe(b.timestamp);if(time<1||!Number.isFinite(new Date(time).getTime()))throw Error('Invalid Ixios block timestamp.');return {number:expected,hash:b.hash,parentHash:b.parentHash,time};}
export async function readIxiosRecentNativeHistory(account,{endpoint=IXIOS_NETWORK.endpoint,startHeight,endHeight,limit=20,signal,call=rpc}={}){
 const own=address(account),opts={signal},get=(method,params)=>{signal?.throwIfAborted();return call(endpoint,method,params,opts);};
 if(!Number.isSafeInteger(limit)||limit<1||limit>MAX_BLOCKS)throw Error('Ixios history window must be 1–50 blocks.');
 const genesis=await get('eth_getBlockByNumber',['0x1',false]);signal?.throwIfAborted();if(genesis?.number!=='0x1'||genesis.parentHash!==IXIOS_GENESIS_HASH)throw Error('Ixios provider is connected to the wrong network.');
 const initial=await get('eth_getBlockByNumber',['latest',false]);signal?.throwIfAborted();if(!initial||typeof initial!=='object')throw Error('Invalid Ixios head.');const headNumber=safe(initial.number),head=header(initial,headNumber);if(headNumber<AEGIS)throw Error('Ixios post-Aegis history is unavailable.');
 const end=endHeight===undefined?headNumber:endHeight,start=startHeight===undefined?Math.max(AEGIS,end-limit+1):startHeight;if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<AEGIS||end<start||end>headNumber||end-start+1>MAX_BLOCKS)throw Error('Invalid Ixios history range.');
 const anchorRaw=await get('eth_getBlockByNumber',[number(start-1),false]);const anchor=header(anchorRaw,start-1);let parent=anchor.hash,matches=0,last;const rows=[],seen=new Set();
 for(let height=start;height<=end;height++){
  const block=await get('eth_getBlockByNumber',[number(height),true]);signal?.throwIfAborted();const h=header(block,height);if(h.parentHash!==parent)throw Error('Ixios block continuity changed.');parent=h.hash;last=h;if(!Array.isArray(block.transactions)||block.transactions.length>MAX_TRANSACTIONS)throw Error('Ixios block transaction bound exceeded.');
  for(let index=0;index<block.transactions.length;index++){
   const tx=block.transactions[index];if(!tx||typeof tx!=='object'||!HASH.test(tx.hash??'')||tx.blockHash!==h.hash||safe(tx.blockNumber)!==height||safe(tx.transactionIndex)!==index||typeof tx.input!=='string'||!/^0x(?:[0-9a-f]{2})*$/.test(tx.input))throw Error('Invalid Ixios transaction.');if(seen.has(tx.hash))throw Error('Duplicate Ixios transaction.');seen.add(tx.hash);
   const from=address(tx.from),to=tx.to===null?null:address(tx.to),value=quantity(tx.value);if(!to||tx.input!=='0x'||value===0n||(from!==own&&to!==own))continue;if(++matches>MAX_MATCHES)throw Error('Ixios matching transaction bound exceeded.');
   // Empty calldata and no code at both adjacent block states exclude ordinary
   // calls to persistent contracts. They cannot rule out a contract created
   // and destroyed inside one block; see returned limitation.
   const before=await get('eth_getCode',[tx.to,number(height-1)]),after=await get('eth_getCode',[tx.to,number(height)]);signal?.throwIfAborted();if(typeof before!=='string'||typeof after!=='string'||!/^0x(?:[0-9a-f]{2})*$/.test(before)||!/^0x(?:[0-9a-f]{2})*$/.test(after))throw Error('Invalid Ixios account code.');if(before!=='0x'||after!=='0x')continue;
   const receipt=await get('eth_getTransactionReceipt',[tx.hash]);signal?.throwIfAborted();if(!receipt||receipt.transactionHash!==tx.hash||receipt.blockHash!==h.hash||safe(receipt.blockNumber)!==height||safe(receipt.transactionIndex)!==index||address(receipt.from)!==from||address(receipt.to)!==to||receipt.contractAddress!==null||!['0x0','0x1'].includes(receipt.status))throw Error('Conflicting Ixios receipt.');
   const success=receipt.status==='0x1';rows.push({hash:tx.hash,blockHeight:height,blockHash:h.hash,time:h.time,from:tx.from,to:tx.to,direction:from===own&&to===own?'self':from===own?'out':'in',amount:success?formatUnits(value,18):'0.0',attemptedAmount:formatUnits(value,18),symbol:'IXIOS',status:success?'included':'failed'});
  }
 }
 const endRaw=await get('eth_getBlockByNumber',[number(end),false]);signal?.throwIfAborted();const endCheck=header(endRaw,end);if(endCheck.hash!==last.hash||endCheck.parentHash!==last.parentHash||endCheck.time!==last.time||(end===headNumber&&last.hash!==head.hash))throw Error('Ixios scanned range changed during history read.');
 const recheckRaw=await get('eth_getBlockByNumber',[number(headNumber),false]);signal?.throwIfAborted();const recheck=header(recheckRaw,headNumber);if(recheck.hash!==head.hash||recheck.parentHash!==head.parentHash||recheck.time!==head.time)throw Error('Ixios head changed during history read.');
 return {rows:rows.reverse(),startHeight:start,endHeight:end,head:{number:headNumber,hash:head.hash},status:'Recent provider-reported direct native transactions only; bounded window, not complete or inclusion-proven. Internal transfers and token events are not represented. Empty-code checks cannot rule out a contract created and destroyed within a block.'};
}
