// Offline validation only; never signs, broadcasts or infers non-submission.
// Intended for a future explicitly confirmed, encrypted same-byte recovery.
import {bech32} from '@scure/base';import{blake3}from'@noble/hashes/blake3';import{hexToBytes,bytesToHex}from'@noble/hashes/utils';import{asentumTransferBody}from'./asentum-sign.js';
export function validateAsentumSignedPayload(row){
 if(!row||row.signedPayload?.encoding!=='hex'||typeof row.signedPayload.data!=='string'||!/^0x[0-9a-f]{10818}$/.test(row.signedPayload.data)||typeof row.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(row.hash))throw new Error('Invalid Asentum signed payload.');
 const raw=hexToBytes(row.signedPayload.data.slice(2));if(raw[0]!==0x91||raw[1]!==0x14||raw[2]!==0||raw[3]!==0)throw new Error('Invalid Asentum SSZ offset.');
 const pub=raw.subarray(4,1956),from=bech32.encode('ase',bech32.toWords(blake3(pub).subarray(0,20)));if(from!==row.address)throw new Error('Asentum signed key does not match sender.');
 const body=asentumTransferBody({networkId:row.networkId,from:row.address,to:row.to,amount:row.amountAtoms,nonce:row.nonce,gasLimit:row.gasLimit,maxFeePerGas:row.maxFeePerGas,maxPriorityFeePerGas:'0'});
 if(raw.subarray(5265).some((b,i)=>b!==body[i])||'0x'+bytesToHex(blake3(raw))!==row.hash)throw new Error('Asentum signed transaction does not match review.');return row.signedPayload.data;
}
