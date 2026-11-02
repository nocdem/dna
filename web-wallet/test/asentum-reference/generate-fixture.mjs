// Optional synthetic-only oracle. Install integrity-pinned @asentum/sdk 0.2.0
// and its exact lockfile dependencies separately; never use with a real wallet.
import {AsentumWallet} from '@asentum/sdk';
const seed=Uint8Array.from({length:32},(_,i)=>i);
const wallet=AsentumWallet.fromSeed({getChainId:async()=>1423n},seed);
const result=await wallet.signTransfer({to:'ase1qgpqyqszqgpqyqszqgpqyqszqgpqyqszyd8yg3',amountWei:123456789012345678901n,nonce:7n,gasLimit:21000n,maxFeePerGas:1n});
console.log(JSON.stringify({from:wallet.address,hash:result.hash,rawLength:(result.rawTx.length-2)/2}));
