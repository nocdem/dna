// Read-only, untrusted tip snapshot. Caller supplies fee cap/gas; no fee quote,
// signing, nonce reservation, approval or broadcasting occurs here.
import { bech32 } from '@scure/base';
import { integerJson } from './integer-json.js';
import { asentumTransferBody } from './asentum-sign.js';
const genesis='0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3';
function uint(value,bits,label) {
 if(typeof value==='number') {if(!Number.isSafeInteger(value)||value<0)throw new Error(`Invalid ${label}.`);value=String(value);}
 if(typeof value!=='string'||!/^(0|[1-9]\d{0,77})$/.test(value)||BigInt(value)>=2n**BigInt(bits))throw new Error(`Invalid ${label}.`);return value;
}
export async function prepareAsentumTransfer({networkId,from,to,amount,gasLimit,maxFeePerGas,maxPriorityFeePerGas='0',signal,fetcher}={}) {
 const params={networkId,from,to,amount,nonce:'0',gasLimit,maxFeePerGas,maxPriorityFeePerGas};
 asentumTransferBody(params); // reject malformed inputs before I/O
 const options={signal,fetcher}, url='https://testnet.asentum.com'; signal?.throwIfAborted();
 const chain=await integerJson(url+'/chain',options);signal?.throwIfAborted();
 const g=await integerJson(url+'/genesis',options);signal?.throwIfAborted();
 if(chain.chainId!=='1423'||g.chainId!=='1423'||g.genesisHash!==genesis)throw new Error('Asentum provider is connected to the wrong network.');
 const account=await integerJson(`${url}/balance/${encodeURIComponent(from)}`,options);signal?.throwIfAborted();
 const hex='0x'+Array.from(bech32.fromWords(bech32.decode(from).words),b=>b.toString(16).padStart(2,'0')).join('');
 if(account.address!==from&&account.address!==hex)throw new Error('Asentum returned a different account.');
 const balance=uint(account.balance,256,'balance'),nonce=uint(account.pendingNonce??account.nonce,64,'nonce');
 const baseFee=uint(chain.latestHeader?.baseFeePerGas,256,'base fee');
 const maximumFee=(BigInt(gasLimit)*BigInt(maxFeePerGas)).toString();
 return {...params,nonce,balance,baseFee,feeAdequate:BigInt(maxFeePerGas)>=BigInt(baseFee),maximumFee,sufficient:BigInt(balance)>=BigInt(amount)+BigInt(maximumFee)};
}
