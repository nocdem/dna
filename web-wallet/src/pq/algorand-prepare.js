// Read-only preparation. Does not sign or submit. Only the verified v42 native
// Falcon protocol is admitted; future/older protocols require explicit review.
// Source: go-algorand v5.0.0-stable protocol/consensus.go + config/consensus.go.
import {base32nopad,base64} from '@scure/base';
import {sha512_256} from '@noble/hashes/sha512';
import {algorandNetwork} from './algorand.js';
import {integerJson} from './integer-json.js';
import {quoteAlgorandFalconFee,checkAlgorandSpend} from './algorand-send.js';
export const ALGORAND_FALCON_PROTOCOL='https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f';
const max=(1n<<64n)-1n;
function uint(value){if(typeof value!=='string'||!/^(0|[1-9]\d{0,19})$/.test(value)||BigInt(value)>max)throw new Error('Invalid Algorand integer.');return BigInt(value);}
export function algorandAddressBytes(value){
 try {
  if(typeof value!=='string'||!/^[A-Z2-7]{58}$/.test(value))throw 0;
  const bytes=base32nopad.decode(value),key=bytes.slice(0,32),checksum=sha512_256(key).slice(-4);
  if(bytes.length!==36||!checksum.every((v,i)=>v===bytes[i+32])||base32nopad.encode(bytes)!==value)throw 0;
  return key;
 }catch{throw new Error('Invalid Algorand address.');}
}
export async function prepareAlgorandPayment({from,to,amountAtoms,maxFeeAtoms,networkId='mainnet',signal,fetcher}={}){
 const sender=algorandAddressBytes(from),receiver=algorandAddressBytes(to),amount=uint(amountAtoms),cap=uint(maxFeeAtoms);
 if(!amount||!cap)throw new Error('Amount and fee cap must be positive.');
 const network=algorandNetwork(networkId),options={signal,fetcher};
 const params=await integerJson(`${network.algod}/v2/transactions/params`,options);
 if(params['genesis-hash']!==network.genesisHash||params['genesis-id']!==`${networkId}-v1.0`)throw new Error('Algorand provider is connected to the wrong network.');
 if(params['consensus-version']!==ALGORAND_FALCON_PROTOCOL)throw new Error('Native Falcon is not verified for this Algorand protocol.');
 const first=uint(params['last-round']),last=first+100n;
 if(!first||last>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Invalid Algorand validity rounds.');
 // 4096 covers the limited payment and maximum compressed Falcon envelope.
 // No notes, apps, groups, close-out or rekey fields are supported here.
 const fee=quoteAlgorandFalconFee({minFee:uint(params['min-fee']),feePerByte:uint(params.fee),signedSize:4096,maxFee:cap});
 const account=await integerJson(`${network.algod}/v2/accounts/${from}?exclude=all`,options);
 if(account.address!==from)throw new Error('Algorand returned a different account.');
 if(account['auth-addr'])throw new Error('Rekeyed Algorand accounts are not supported.');
 const round=uint(account.round);
 if(round<first||round>last)throw new Error('Algorand account snapshot is out of date.');
 const balance=uint(account.amount),minimumBalance=uint(account['min-balance']);
 checkAlgorandSpend({balance,minimumBalance,amount,fee});
 signal?.throwIfAborted();
 return {networkId,from,to,feeAtoms:String(fee),amountAtoms:String(amount),
  expiresAt:Date.now()+60000,payment:{sender,receiver,amount:String(amount),fee:String(fee),
   firstValid:String(first),lastValid:String(last),genesisHash:base64.decode(network.genesisHash),genesisId:params['genesis-id']}};
}
