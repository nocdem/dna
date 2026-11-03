// Public QTC explorer candidate and fee reads. The explorer's UTXO index
// excludes mempool spends and is not an independent node / inclusion proof.
// These are candidate checks, NOT spendability or broadcast authorization.
// Source: qtcchain/qtc-explorer@73a6076 internal/web/server.go; QTC consensus
// coinbase maturity=100 (qtcchain/qtc@5adbc7d5 src/consensus/consensus.h).
import {integerJson,atoms} from './integer-json.js';import {qtcScript} from './qtc-transaction.js';
const networks={mainnet:{url:'https://qtc.events',chain:'main',genesis:'d5f04a8a320b4e7bb454c7c564ca9cf191f70d7521d2486b62274df776f4eb24'},testnet:{url:'https://testnet.qtc.events',chain:'test',genesis:'efcba50d2de7cb16fd92423df899eba29e750b2271ef0ea64efe8cfeb4382ddf'}};
const hash=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
function network(id){if(!Object.hasOwn(networks,id))throw Error('Unsupported QTC network.');return networks[id];}
async function tip(n,o){
 const chain=await integerJson(`${n.url}/api/v1/chain`,o);if(chain.chain!==n.chain||!hash(chain.hash))throw Error('Wrong QTC chain.');
 const height=atoms(chain.height),node=atoms(chain.node_height),lag=atoms(chain.indexer_lag),time=atoms(chain.time),now=BigInt(Math.floor(Date.now()/1000));
 if(height===0n||node!==height||lag!==0n||time>now+600n||time+7200n<now)throw Error('QTC explorer is stale or lagging.');
 const genesis=await integerJson(`${n.url}/api/v1/block/0`,o);if(genesis?.block?.hash!==n.genesis||atoms(genesis.block.height)!==0n)throw Error('Wrong QTC genesis.');
 return {height,hash:chain.hash};
}
export async function findQtcCandidates(address,{networkId='mainnet',signal,fetcher,limit=20}={}){
 if(!Number.isInteger(limit)||limit<1||limit>50)throw Error('Invalid QTC candidate limit.');const n=network(networkId),script=qtcScript(address,networkId),options={signal,fetcher},snapshot=await tip(n,options);
 const page=await integerJson(`${n.url}/api/v1/address/${encodeURIComponent(address)}/utxo?from=0&limit=${limit}`,options);
 if(page.address!==address||!Array.isArray(page.utxos)||page.utxos.length>limit||atoms(page.tip_height)!==snapshot.height)throw Error('Invalid QTC UTXO page.');
 const total=atoms(page.total);if(total<BigInt(page.utxos.length)||(page.utxos.length===0&&total!==0n)||(total>BigInt(page.utxos.length)&&atoms(page.next)!==BigInt(page.utxos.length))||(total===BigInt(page.utxos.length)&&page.next!==undefined))throw Error('Inconsistent QTC pagination.');
 if(page.utxos.length&&page.script_pubkey!==script)throw Error('Wrong QTC account script.');
 const seen=new Set(),candidates=[];
 for(const u of page.utxos){
  if(!u||!hash(u.txid)||u.script_pubkey!==script||typeof u.coinbase!=='boolean')throw Error('Invalid QTC candidate.');const vout=atoms(u.vout),height=atoms(u.height),value=atoms(u.value),conf=atoms(u.confirmations),key=u.txid+':'+vout;
  if(vout>0xffffffffn||height===0n||height>snapshot.height||conf!==snapshot.height-height+1n||value===0n||value>2100000000000000n||seen.has(key))throw Error('Invalid QTC candidate fields.');seen.add(key);
  if(u.coinbase&&conf<100n)continue;
  const tx=await integerJson(`${n.url}/api/v1/tx/${u.txid}`,options);
  if(tx.txid!==u.txid||tx.unconfirmed!==false||tx.coinbase!==u.coinbase||atoms(tx.height)!==height||atoms(tx.confirmations)!==conf||!Array.isArray(tx.vout)||vout>=BigInt(tx.vout.length))throw Error('QTC candidate transaction mismatch.');
  const output=tx.vout[Number(vout)];if(atoms(output?.n)!==vout||atoms(output?.value)!==value||output.script!==script||output.address!==address||output.spent_by)throw Error('QTC candidate output mismatch.');
  candidates.push({txid:u.txid,vout:Number(vout),value,script_pubkey:script,height,coinbase:u.coinbase});
 }
 const end=await integerJson(`${n.url}/api/v1/chain`,options);if(end.chain!==n.chain||end.hash!==snapshot.hash||atoms(end.height)!==snapshot.height||atoms(end.node_height)!==snapshot.height||atoms(end.indexer_lag)!==0n)throw Error('QTC explorer tip changed.');
 return {candidates,truncated:total>BigInt(page.utxos.length),tip:snapshot};
}
export async function readQtcFeeRates({networkId='mainnet',signal,fetcher}={}){
 const n=network(networkId),options={signal,fetcher},snapshot=await tip(n,options),f=await integerJson(`${n.url}/api/v1/fees`,options);
 if(f.unit!=='atoms_per_byte')throw Error('Invalid QTC fee unit.');const rates={};for(const t of ['1','3','6','12'])rates[t]=f[t]===null?null:atoms(f[t]);if(Object.values(rates).every(v=>v===null))throw Error('QTC fee estimate unavailable.');
 const end=await integerJson(`${n.url}/api/v1/chain`,options);if(end.chain!==n.chain||end.hash!==snapshot.hash||atoms(end.height)!==snapshot.height||atoms(end.node_height)!==snapshot.height||atoms(end.indexer_lag)!==0n)throw Error('QTC explorer tip changed.');return {rates,tip:snapshot};
}
