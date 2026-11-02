// Read-only untrusted-provider checks for CKB simple quantum cells; not an
// inclusion proof, reservation, fee estimator, or authorization to broadcast.
// RPC schema: nervosnetwork/ckb RPC docs get_indexer_tip/get_cells,
// get_transaction, get_live_cell and get_tip_header. Excludes ALL cellbase
// outputs, even mature ones, rather than approximating epoch-based maturity.
import {bech32m} from '@scure/base';
import {concatBytes,hexToBytes} from '@noble/hashes/utils';
import {rpcFetch} from '../rpc-transport.js';
import {parseExactJson} from './integer-json.js';
import {ckbNetwork} from './ckb.js';
import {parseCkbFullRecipient} from './ckb-full-recipient.js';
import {ckbQuantumAddressLock} from './ckb-quantum-transaction.js';
const cat=(...a)=>concatBytes(...a), hash=s=>typeof s==='string'&&/^0x[0-9a-f]{64}$/.test(s);
const uint=(s,bits=64)=>{if(typeof s!=='string'||!/^0x(0|[1-9a-f][0-9a-f]*)$/.test(s)||BigInt(s)>=(1n<<BigInt(bits)))throw Error('Invalid CKB integer.');return BigInt(s);};
function u32(n){const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,Number(n),true);return b;}
function u64(n){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,true);return b;}
function table(...f){let o=4+4*f.length;const off=f.map(x=>{const n=o;o+=x.length;return u32(n);});return cat(u32(o),...off,...f);}
const sameLock=(a,b)=>a&&a.code_hash===b.code_hash&&a.hash_type===b.hash_type&&a.args===b.args;
function lockOf(address,network){ckbQuantumAddressLock(address,network.networkId);const d=bech32m.decode(address,1023),p=bech32m.fromWords(d.words);return {code_hash:network.codeHash,hash_type:network.hashType,args:'0x'+Array.from(p.slice(34),x=>x.toString(16).padStart(2,'0')).join('')};}
async function call(network,method,params,{signal,fetcher}){
 if(!['get_block_hash','get_tip_header','get_indexer_tip','get_cells','get_transaction','get_live_cell','tx_pool_info','get_fee_rate_statistics','test_tx_pool_accept'].includes(method))throw Error('Unsupported CKB RPC method.');
 signal?.throwIfAborted();const id='nodus-ckb-'+method;
 const response=await rpcFetch(network.rpc,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id,method,params}),signal},{fetcher});
 signal?.throwIfAborted();if(!response.ok)throw Error(`CKB RPC HTTP ${response.status}.`);const body=parseExactJson(await response.text());
 if(!body||body.jsonrpc!=='2.0'||body.id!==id||body.error!=null||!Object.hasOwn(body,'result'))throw Error('Invalid CKB RPC response.');return body.result;
}
async function snapshot(network,options){
 if(await call(network,'get_block_hash',['0x0'],options)!==network.genesisHash)throw Error('Wrong CKB genesis.');
 const h=await call(network,'get_tip_header',[],options);if(!h||!hash(h.hash))throw Error('Invalid CKB tip.');const height=uint(h.number),timestamp=uint(h.timestamp);
 const now=BigInt(Date.now());if(height===0n||timestamp>now+600000n||timestamp+7200000n<now)throw Error('CKB node tip is stale.');
 if(await call(network,'get_block_hash',[h.number],options)!==h.hash)throw Error('CKB tip changed.');return {height,hash:h.hash,number:h.number};
}
// Discovers at most one page, then independently checks each candidate against
// committed node transaction and tx-pool-aware live-cell state. truncated=true
// means more pages might exist; never interpret this as full wallet balance.
export async function findCkbQuantumCells(address,{networkId='mainnet',signal,fetcher,limit=10}={}){
 if(!Number.isInteger(limit)||limit<1||limit>20)throw Error('Invalid CKB candidate limit.');
 const network=ckbNetwork(networkId),lock=lockOf(address,network),lockBytes=ckbQuantumAddressLock(address,networkId),options={signal,fetcher};
 const tip=await snapshot(network,options), index=await call(network,'get_indexer_tip',[],options);
 if(!index||!hash(index.block_hash))throw Error('CKB indexer unavailable.');const indexed=uint(index.block_number);
 if(indexed>tip.height||tip.height-indexed>24n||await call(network,'get_block_hash',[index.block_number],options)!==index.block_hash)throw Error('CKB indexer is stale or on another chain.');
 const search={script:lock,script_type:'lock',script_search_mode:'exact',filter:{script_len_range:['0x0','0x1'],output_data_len_range:['0x0','0x1']},with_data:true};
 const page=await call(network,'get_cells',[search,'asc','0x'+limit.toString(16)],options);
 if(!page||!Array.isArray(page.objects)||page.objects.length>limit||typeof page.last_cursor!=='string'||!/^0x(?:[0-9a-f]{2})*$/.test(page.last_cursor))throw Error('Invalid CKB indexer page.');
 const cells=[],seen=new Set();
 for(const row of page.objects){
  if(!row||!row.out_point||!hash(row.out_point.tx_hash))throw Error('Invalid CKB outpoint.');const vout=uint(row.out_point.index,32),height=uint(row.block_number),position=uint(row.tx_index,32),key=row.out_point.tx_hash+':'+vout;
  if(seen.has(key)||height>indexed||height===0n)throw Error('Invalid CKB indexer cell.');seen.add(key);
  if(position===0n)continue; // Never use a cellbase output, regardless of age.
  if(row.output_data!=='0x'||row.output?.type!==null||!sameLock(row.output.lock,lock))throw Error('Unexpected CKB cell profile.');const capacity=uint(row.output.capacity);if(capacity<7300000000n)throw Error('Invalid CKB cell capacity.');
  const t=await call(network,'get_transaction',[row.out_point.tx_hash,'0x2',true],options),status=t?.tx_status,tx=t?.transaction;
  if(status?.status!=='committed'||status.block_number!==row.block_number||status.tx_index!==row.tx_index||!hash(status.block_hash)||tx?.hash!==row.out_point.tx_hash||!Array.isArray(tx.inputs)||!tx.inputs.length||!Array.isArray(tx.outputs)||!Array.isArray(tx.outputs_data)||vout>=BigInt(tx.outputs.length)||tx.outputs_data[Number(vout)]!=='0x')throw Error('CKB transaction is not committed or mismatched.');
  for(const input of tx.inputs){if(!hash(input?.previous_output?.tx_hash))throw Error('Invalid CKB transaction input.');uint(input.previous_output.index,32);if(input.previous_output.tx_hash==='0x'+'00'.repeat(32))throw Error('Cellbase CKB inputs are excluded.');}
  const out=tx.outputs[Number(vout)];if(out?.capacity!==row.output.capacity||out?.type!==null||!sameLock(out?.lock,lock))throw Error('CKB indexer and transaction disagree.');
  if(await call(network,'get_block_hash',[row.block_number],options)!==status.block_hash)throw Error('CKB transaction block changed.');
  const live=await call(network,'get_live_cell',[row.out_point,true,true],options);
  if(live?.status!=='live'||live.cell?.data?.content!=='0x'||live.cell?.output?.type!==null||live.cell?.output?.capacity!==row.output.capacity||!sameLock(live.cell.output.lock,lock))throw Error('CKB cell is not live or changed.');
  cells.push({outpoint:cat(hexToBytes(row.out_point.tx_hash.slice(2)),u32(vout)),output:table(u64(capacity),lockBytes,new Uint8Array()),data:new Uint8Array(),capacity});
 }
 const end=await call(network,'get_tip_header',[],options);if(end?.hash!==tip.hash||end?.number!==tip.number)throw Error('CKB tip changed during preflight.');
 return {cells,truncated:page.objects.length===limit,tip};
}

// Revalidate exact previously discovered cells immediately before a potential
// later submission. This is still a node assertion, not an atomic reservation.
export async function recheckCkbQuantumCells(address,inputs,{networkId='mainnet',signal,fetcher}={}){
 const network=ckbNetwork(networkId),lock=lockOf(address,network),lockBytes=ckbQuantumAddressLock(address,networkId),options={signal,fetcher};
 if(!Array.isArray(inputs)||!inputs.length||inputs.length>80)throw Error('Invalid CKB inputs.');const tip=await snapshot(network,options),seen=new Set();
 for(const input of inputs){
  if(!(input?.outpoint instanceof Uint8Array)||input.outpoint.length!==36||!(input.output instanceof Uint8Array)||!(input.data instanceof Uint8Array)||input.data.length)throw Error('Invalid CKB input.');
  const h='0x'+Array.from(input.outpoint.slice(0,32),b=>b.toString(16).padStart(2,'0')).join(''),index=new DataView(input.outpoint.buffer,input.outpoint.byteOffset+32,4).getUint32(0,true),outPoint={tx_hash:h,index:'0x'+index.toString(16)},key=h+':'+index;
  if(seen.has(key))throw Error('Duplicate CKB input.');seen.add(key);
  const live=await call(network,'get_live_cell',[outPoint,true,true],options),output=live?.cell?.output;
  if(live?.status!=='live'||live.cell?.data?.content!=='0x'||output?.type!==null||!sameLock(output.lock,lock))throw Error('CKB cell is not live or changed.');
  const capacity=uint(output.capacity);if(capacity<7300000000n)throw Error('Invalid CKB capacity.');const encoded=table(u64(capacity),lockBytes,new Uint8Array());
  if(encoded.length!==input.output.length||!encoded.every((v,i)=>v===input.output[i]))throw Error('CKB cell differs from reviewed input.');
 }
 const end=await call(network,'get_tip_header',[],options);if(end?.hash!==tip.hash||end?.number!==tip.number)throw Error('CKB tip changed during recheck.');return tip;
}

// Node-local pool floor and observed historical statistics in shannons per
// 1,000 weight units; neither guarantees relay or confirmation. Callers must
// display the rate and enforce their own rate/fee and cycle ceilings.
export async function readCkbFeeRates({networkId='mainnet',signal,fetcher}={}){
 const network=ckbNetwork(networkId),options={signal,fetcher},tip=await snapshot(network,options);
 const pool=await call(network,'tx_pool_info',[],options);
 if(pool?.tip_hash!==tip.hash||pool?.tip_number!==tip.number)throw Error('CKB fee pool tip changed.');
 const minimum=uint(pool.min_fee_rate),sizeLimit=uint(pool.tx_size_limit);
 if(!minimum||!sizeLimit)throw Error('Invalid CKB pool limits.');
 const stats=await call(network,'get_fee_rate_statistics',[],options);
 if(!stats)throw Error('CKB fee statistics unavailable.');const mean=uint(stats.mean),median=uint(stats.median);
 if(!mean||!median)throw Error('Invalid CKB fee statistics.');
 const end=await call(network,'get_tip_header',[],options);if(end?.hash!==tip.hash||end?.number!==tip.number)throw Error('CKB tip changed during fee read.');
 return {minimum,mean,median,sizeLimit,tip};
}

// Explicit read-only pool simulation: this discloses the fully signed raw
// transaction to the selected configured public node, which could retain or
// relay it. Call only after user confirmation and with a durable hold in place.
// The RPC itself is documented not to insert or relay a transaction. It does
// not return a txid; the caller must locally bind txid to the exact RPC object.
export async function simulateCkbAtConfiguredNode({rpcTransaction,txid,expectedFee,networkId='mainnet',signal,fetcher}={}){
 if(!rpcTransaction||typeof rpcTransaction!=='object'||Array.isArray(rpcTransaction)||!hash(txid)||typeof expectedFee!=='bigint'||expectedFee<=0n)throw Error('Invalid CKB simulation request.');
 const network=ckbNetwork(networkId),result=await call(network,'test_tx_pool_accept',[rpcTransaction,'passthrough'],{signal,fetcher});
 if(!result||uint(result.fee)!==expectedFee)throw Error('CKB simulation fee differs from review.');const cycles=uint(result.cycles);if(cycles===0n)throw Error('Invalid CKB simulation cycles.');return {txid,cycles};
}

// Bounded observation of an authenticated pending transaction. 24-deep is a
// local reorg-risk policy, NOT economic finality or a cryptographic proof.
// A missing/rejected/uncommitted tx never releases the durable hold.
export async function observeCkbSubmission(row,{signal,fetcher}={}){
 const {validCkbPending}=await import('./ckb-pending.js');if(!validCkbPending(row))throw Error('Invalid CKB pending record.');
 const network=ckbNetwork(row.networkId),options={signal,fetcher},tip=await snapshot(network,options),result=await call(network,'get_transaction',[row.hash,'0x2',false],options);
 if(!result||result.tx_status?.status!=='committed')return {state:'pending',hash:row.hash};
 const status=result.tx_status,tx=result.transaction,height=uint(status.block_number);if(!hash(status.block_hash)||height===0n||height>tip.height||uint(status.tx_index,32)===0n||tx?.hash!==row.hash)throw Error('Invalid CKB committed transaction.');
 if(await call(network,'get_block_hash',[status.block_number],options)!==status.block_hash)throw Error('CKB inclusion is not canonical.');
 const depHash=row.networkId==='mainnet'?'0x4598d00df2f3dc8bc40eee38689a539c94f6cc3720b7a2a6746736daa60f500a':'0x631d9a6049fb1fc3790e89d9daf35abe535b5e754cd8c3404319319710f0b106';
 if(tx.version!=='0x0'||!Array.isArray(tx.cell_deps)||tx.cell_deps.length!==1||tx.cell_deps[0]?.dep_type!=='code'||tx.cell_deps[0]?.out_point?.tx_hash!==depHash||tx.cell_deps[0]?.out_point?.index!=='0x0'||!Array.isArray(tx.header_deps)||tx.header_deps.length!==0||!Array.isArray(tx.inputs)||tx.inputs.length!==row.inputs.length||!Array.isArray(tx.outputs)||!Array.isArray(tx.outputs_data)||!Array.isArray(tx.witnesses))throw Error('Invalid CKB committed transaction shape.');
 const lock=lockOf(row.address,network),lockBytes=ckbQuantumAddressLock(row.address,row.networkId),resolved=[];
 for(let i=0;i<row.inputs.length;i++){
  const b=hexToBytes(row.inputs[i]),h='0x'+Array.from(b.slice(0,32),x=>x.toString(16).padStart(2,'0')).join(''),v=new DataView(b.buffer,b.byteOffset+32,4).getUint32(0,true),prev=tx.inputs[i]?.previous_output;
  if(prev?.tx_hash!==h||uint(prev.index,32)!==BigInt(v)||tx.inputs[i]?.since!=='0x0')throw Error('CKB committed inputs differ from the hold.');
  const origin=await call(network,'get_transaction',[h,'0x2',true],options),o=origin?.transaction?.outputs?.[v];
  if(origin?.tx_status?.status!=='committed'||origin.transaction?.hash!==h||o?.type!==null||!sameLock(o?.lock,lock)||origin.transaction?.outputs_data?.[v]!=='0x')throw Error('CKB original input cannot be verified.');
  const capacity=uint(o.capacity);resolved.push({outpoint:b,output:table(u64(capacity),lockBytes,new Uint8Array()),data:new Uint8Array()});
 }
 const {prepareCkbQuantumTransaction}=await import('./ckb-quantum-transaction.js');
 const p=prepareCkbQuantumTransaction({networkId:row.networkId,from:row.address,to:row.to,inputs:resolved,amount:BigInt(row.amountAtoms),fee:BigInt(row.feeAtoms)});
 const {blake2b}=await import('@noble/hashes/blake2b');const {bytesToHex,utf8ToBytes}=await import('@noble/hashes/utils');
 const txid='0x'+bytesToHex(blake2b(p.rawTransaction,{dkLen:32,personalization:utf8ToBytes('ckb-default-hash')}));if(txid!==row.hash)throw Error('CKB committed transaction hash does not match review.');
 // Node's returned output fields must describe the same locally rebuilt raw tx.
 const dest=parseCkbFullRecipient(row.to,row.networkId).lock,expected=[{capacity:'0x'+p.amount.toString(16),lock:dest,type:null}];if(p.change)expected.push({capacity:'0x'+p.change.toString(16),lock,type:null});
 if(tx.outputs.length!==expected.length||tx.outputs_data.length!==expected.length||tx.outputs_data.some(x=>x!=='0x')||tx.outputs.some((o,i)=>o?.capacity!==expected[i].capacity||o.type!==null||!sameLock(o.lock,expected[i].lock)))throw Error('CKB committed outputs differ from review.');
 const end=await call(network,'get_tip_header',[],options);if(end?.hash!==tip.hash||end?.number!==tip.number)throw Error('CKB tip changed during status check.');
 const confirmations=tip.height-height+1n;return {state:confirmations>=24n?'confirmed':'pending',hash:row.hash,confirmations};
}
