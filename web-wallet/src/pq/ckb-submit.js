// Explicit one-shot CKB submission, never retried. Only call after the reviewed
// signed transaction has an authenticated durable outpoint hold. JSON-RPC
// `send_transaction` admission is asynchronous and is NOT confirmation.
import {rpcFetch} from '../rpc-transport.js';import {parseExactJson} from './integer-json.js';import {ckbNetwork} from './ckb.js';
export async function submitCkbTransaction({networkId,rpcTransaction,txid,expiresAt,signal,fetcher}={}){
 const net=ckbNetwork(networkId);if(!Number.isSafeInteger(expiresAt)||Date.now()>=expiresAt||!rpcTransaction||typeof rpcTransaction!=='object'||Array.isArray(rpcTransaction)||typeof txid!=='string'||!/^0x[0-9a-f]{64}$/.test(txid))throw Error('Invalid CKB submission.');
 async function call(method,params){signal?.throwIfAborted();const id='nodus-ckb-'+method,response=await rpcFetch(net.rpc,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id,method,params}),signal},{fetcher});signal?.throwIfAborted();if(!response.ok)throw Error(`CKB RPC HTTP ${response.status}.`);const data=parseExactJson(await response.text());if(!data||data.jsonrpc!=='2.0'||data.id!==id||data.error!=null||!Object.hasOwn(data,'result'))throw Error('Invalid CKB RPC response.');return data.result;}
 if(await call('get_block_hash',['0x0'])!==net.genesisHash)throw Error('Wrong CKB genesis.');signal?.throwIfAborted();if(Date.now()>=expiresAt)throw Error('CKB review expired before submission.');
 const result=await call('send_transaction',[rpcTransaction,'passthrough']);if(result!==txid)throw Error('CKB submission returned a different transaction ID; outcome is uncertain.');return txid;
}
