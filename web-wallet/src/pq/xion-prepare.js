// Read-only untrusted node snapshot; does not reserve sequence, simulate gas,
// estimate fees, prove state, sign or submit. Caller supplies gas/fee.
import {base64} from '@scure/base';
import {integerJson,parseExactJson} from './integer-json.js';
import {rpcFetch} from '../rpc-transport.js';
import {buildXionDirectSignDoc} from './xion-sign-doc.js';
const nets=Object.freeze({mainnet:{url:'https://api.xion-mainnet-1.burnt.com',chain:'xion-mainnet-1'},testnet:{url:'https://api.xion-testnet-2.burnt.com',chain:'xion-testnet-2'}});
function uint(s,bits,label){if(typeof s!=='string'||!/^(0|[1-9]\d{0,77})$/.test(s)||BigInt(s)>=2n**BigInt(bits))throw new Error(`Invalid ${label}.`);return s;}
export async function prepareXionTransfer({networkId,from,to,amount,fee,gas,publicKey,timeoutHeight,queryHeight,signal,fetcher}={}) {
 const params={networkId,from,to,amount,fee,gas,publicKey,timeoutHeight,sequence:'0',accountNumber:'0'};
 buildXionDirectSignDoc(params);const net=nets[networkId],opts={signal,fetcher};signal?.throwIfAborted();
 if(queryHeight!==undefined&&(typeof queryHeight!=='string'||!/^[1-9]\d{0,18}$/.test(queryHeight)||BigInt(queryHeight)>2n**63n-1n))throw Error('Invalid XION query height.');
 const stateAt=async url=>{if(queryHeight===undefined)return integerJson(url,opts);const r=await rpcFetch(url,{method:'GET',headers:{'x-cosmos-block-height':queryHeight},signal},{fetcher});signal?.throwIfAborted();if(!r.ok||r.headers.get('x-cosmos-block-height')!==queryHeight)throw Error('XION account state height mismatch.');const value=parseExactJson(await r.text());if(!value||typeof value!=='object'||Array.isArray(value)||value.error||value.Error||value.success===false)throw Error('Invalid XION state response.');return value;};
 const info=await integerJson(net.url+'/cosmos/base/tendermint/v1beta1/node_info',opts);signal?.throwIfAborted();
 if(info.default_node_info?.network!==net.chain)throw new Error('XION provider is connected to the wrong network.');
 const state=await stateAt(`${net.url}/cosmos/auth/v1beta1/accounts/${encodeURIComponent(from)}`);signal?.throwIfAborted();
 const a=state.account;
 if(!a||a['@type']!=='/cosmos.auth.v1beta1.BaseAccount'||a.address!==from)throw new Error('Unsupported XION account type or address.');
 const accountNumber=uint(a.account_number,64,'account number'),sequence=uint(a.sequence,64,'sequence');
 if(a.pub_key!==null) {
  if(!a.pub_key||a.pub_key['@type']!=='/cosmos.crypto.mldsa65.PubKey'||typeof a.pub_key.key!=='string')throw new Error('Unsupported XION account public key.');
  let key;try{key=base64.decode(a.pub_key.key);}catch{throw new Error('Invalid XION account public key.');}
  if(key.length!==publicKey.length||key.some((b,i)=>b!==publicKey[i]))throw new Error('XION account public key does not match sender.');
 }
 const result=await stateAt(`${net.url}/cosmos/bank/v1beta1/spendable_balances/${encodeURIComponent(from)}/by_denom?denom=uxion`);signal?.throwIfAborted();
 if(result.balance?.denom!=='uxion')throw new Error('Invalid XION spendable balance.');
 const balance=uint(result.balance.amount,256,'spendable balance');
 return {...params,accountNumber,sequence,balance,sufficient:BigInt(balance)>=BigInt(amount)+BigInt(fee)};
}
