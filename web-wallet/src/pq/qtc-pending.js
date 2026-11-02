// Authenticated QTC pending identity. An unresolved signed exposure reserves
// its inputs indefinitely: explorer absence is not proof of non-submission.
import {qtcScript} from './qtc-transaction.js';
const atoms=x=>typeof x==='string'&&/^(0|[1-9]\d{0,15})$/.test(x)&&BigInt(x)<=2100000000000000n;
export function validQtcPending(p){try{
 if(!p||!['mainnet','testnet'].includes(p.networkId)||typeof p.hash!=='string'||!/^([0-9a-f]{64})$/.test(p.hash)||typeof p.submissionId!=='string'||!/^([0-9a-f]{32})$/.test(p.submissionId)||!atoms(p.amountAtoms)||BigInt(p.amountAtoms)<11583n||!atoms(p.feeAtoms)||BigInt(p.feeAtoms)<=0n||BigInt(p.feeAtoms)>100000000n)return false;
 qtcScript(p.address,p.networkId);qtcScript(p.to,p.networkId);
 if(!Array.isArray(p.inputs)||p.inputs.length<1||p.inputs.length>80||new Set(p.inputs).size!==p.inputs.length)return false;
 return p.inputs.every(i=>typeof i==='string'&&/^[0-9a-f]{64}:(0|[1-9]\d{0,9})$/.test(i)&&BigInt(i.split(':')[1])<=0xffffffffn);
}catch{return false;}}
