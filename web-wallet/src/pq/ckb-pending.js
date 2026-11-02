// Authenticated durable CKB pending identity. The signed payload is stored
// encrypted for exact recovery; private keys are never stored with it.
// Unresolved rows retain their consumed outpoints across restart.
import {parseCkbFullRecipient} from './ckb-full-recipient.js';
import {ckbQuantumAddressLock} from './ckb-quantum-transaction.js';
const decimal=x=>typeof x==='string'&&/^(0|[1-9]\d{0,19})$/.test(x)&&BigInt(x)<=0xffffffffffffffffn;
export function validCkbPending(p){try{
 if(!p||!['mainnet','testnet'].includes(p.networkId)||typeof p.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(p.hash)||typeof p.submissionId!=='string'||!/^[0-9a-f]{32}$/.test(p.submissionId)||!decimal(p.amountAtoms)||!decimal(p.feeAtoms)||BigInt(p.feeAtoms)<=0n||BigInt(p.feeAtoms)>100000000n)return false;
 ckbQuantumAddressLock(p.address,p.networkId);if(BigInt(p.amountAtoms)<parseCkbFullRecipient(p.to,p.networkId).minimumCapacity)return false;
 if(p.inputCapacities!==undefined&&(!Array.isArray(p.inputCapacities)||p.inputCapacities.length!==p.inputs?.length||p.inputCapacities.some(x=>!decimal(x)||BigInt(x)<7300000000n)))return false;
 if(p.signedPayload!==undefined&&!Array.isArray(p.inputCapacities))return false;
 if(!Array.isArray(p.inputs)||p.inputs.length<1||p.inputs.length>80||p.inputs.some(i=>typeof i!=='string'||!/^[0-9a-f]{72}$/.test(i))||new Set(p.inputs).size!==p.inputs.length)return false;
 return true;
}catch{return false;}}
