// Read-only node snapshot. min_fee and account state can change immediately.
// No nonce reservation, sign, submit or confirmation is performed here.
import {integerJson} from './integer-json.js';
import {sha3_256} from '@noble/hashes/sha3';
import {hexToBytes,bytesToHex} from '@noble/hashes/utils';
import {splendorTransferBody} from './splendor-transfer-body.js';
const nets=Object.freeze({mainnet:{url:'https://quantum-rpc.splendor.org',chain:'splendor-quantum-1',genesis:'d865193d3bd88fb4446626940e63b5658275342a0153638079cf9e962332a257'},testnet:{url:'https://quantum-rpc-testnet.splendor.org',chain:'splendor-quantum-testnet-1',genesis:'324d7f561493ae6d08062288cb99adfbb3f83297d352b783f611171251a1289f'}});
function uint(s,bits,label){if(typeof s!=='string'||!/^(0|[1-9]\d{0,77})$/.test(s)||BigInt(s)>=2n**BigInt(bits))throw new Error(`Invalid ${label}.`);return s;}
export async function prepareSplendorTransfer({networkId,from,to,amount,fee,timestamp,signal,fetcher}={}) {
 const params={networkId,from,to,amount,fee,nonce:'0',timestamp};splendorTransferBody(params);
 const network=nets[networkId],opts={signal,fetcher};signal?.throwIfAborted();
 const status=await integerJson(network.url+'/status',opts);signal?.throwIfAborted();
 if(status.chain_id!==network.chain||status.genesis_hash!==network.genesis||status.decimals!=='18'||status.fee_unit!=='smallest_spld')throw new Error('Splendor provider is connected to the wrong network.');
 const minimumFee=uint(status.min_fee,256,'minimum fee');
 const account=await integerJson(`${network.url}/state/account/${encodeURIComponent(from)}`,opts);signal?.throwIfAborted();
 if(account.address!==from)throw new Error('Splendor returned a different account.');
 const balance=uint(account.balance,256,'balance'),nonce=uint(account.nonce,64,'nonce');
 if(typeof account.has_public_key!=='boolean'||(nonce!=='0'&&!account.has_public_key)||typeof account.state_root!=='string'||!/^[0-9a-f]{64}$/.test(account.state_root)||typeof account.block_height!=='string'||!/^(0|[1-9]\d{0,19})$/.test(account.block_height))throw new Error('Invalid Splendor account state.');
 if(account.has_public_key){if(account.address_verified!==true||typeof account.public_key_hex!=='string'||!/^[0-9a-f]{3904}$/.test(account.public_key_hex)||'SQ:'+bytesToHex(sha3_256(hexToBytes(account.public_key_hex)))!==from)throw new Error('Splendor registered public key does not match account.');}
 return {...params,nonce,balance,minimumFee,feeAdequate:BigInt(fee)>=BigInt(minimumFee),sufficient:BigInt(balance)>=BigInt(amount)+BigInt(fee)};
}
