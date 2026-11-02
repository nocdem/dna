// Read-only Cosmos SDK Simulate endpoint. It executes a synthetic TxRaw with
// an all-zero signature; never signs, reserves sequence or broadcasts. Gas is
// only a state-dependent estimate, not a fee quote or acceptance guarantee.
import {base64} from '@scure/base';
import {request} from '../core.js';
import {buildXionDirectSignDoc,encodeXionTxRaw} from './xion-sign-doc.js';
const nets=Object.freeze({mainnet:{url:'https://api.xion-mainnet-1.burnt.com',chain:'xion-mainnet-1'},testnet:{url:'https://api.xion-testnet-2.burnt.com',chain:'xion-testnet-2'}});
export async function simulateXionTransfer({networkId,signal,fetcher,...fields}={}) {
 if(!Object.hasOwn(nets,networkId))throw new Error('Unsupported XION network.');
 const doc=buildXionDirectSignDoc({networkId,...fields});
 const tx=encodeXionTxRaw({...doc,signature:new Uint8Array(3309)}),net=nets[networkId],opts={signal,fetcher};
 signal?.throwIfAborted();const info=await request(net.url+'/cosmos/base/tendermint/v1beta1/node_info',undefined,opts);signal?.throwIfAborted();
 if(info.default_node_info?.network!==net.chain)throw new Error('XION provider is connected to the wrong network.');
 const result=await request(net.url+'/cosmos/tx/v1beta1/simulate',{tx_bytes:base64.encode(tx)},opts);signal?.throwIfAborted();
 const gas=result.gas_info?.gas_used;
 if(typeof gas!=='string'||!/^(0|[1-9]\d{0,19})$/.test(gas)||BigInt(gas)>=2n**64n)throw new Error('Invalid XION gas simulation response.');
 return {gasUsed:gas};
}
