// Offline validation for a future explicit exact-byte recovery action. This
// module does not fetch, sign, broadcast or infer idempotence/expiry. The
// payload must already come from this wallet's authenticated encrypted record.
import {base64} from '@scure/base';
import {sha3_256} from '@noble/hashes/sha3';
import {bytesToHex} from '@noble/hashes/utils';
import {splendorTransferBody} from './splendor-transfer-body.js';
function decode(s,n){let b;try{b=base64.decode(s);}catch{throw new Error('Invalid Splendor signed payload.');}if(b.length!==n||base64.encode(b)!==s)throw new Error('Invalid Splendor signed payload.');return b;}
export function validateSplendorSignedPayload(row){
 if(!row||!row.signedPayload||row.signedPayload.encoding!=='json'||typeof row.signedPayload.data!=='string'||row.signedPayload.data.length>10000||typeof row.hash!=='string'||!/^[0-9a-f]{64}$/.test(row.hash))throw new Error('Invalid Splendor signed payload.');
 const body=splendorTransferBody({networkId:row.networkId,from:row.address,to:row.to,amount:row.amountAtoms,fee:row.feeAtoms,nonce:row.nonce,timestamp:row.timestamp});
 const wire=row.signedPayload.data,prefix=body.slice(0,-1);if(!wire.startsWith(prefix))throw new Error('Signed Splendor transaction does not match review.');
 const tail=wire.slice(prefix.length),match=tail.match(row.nonce==='0'?/^,"public_key":"([A-Za-z0-9+/]+={0,2})","signature":"([A-Za-z0-9+/]+={0,2})"\}$/:/^,"signature":"([A-Za-z0-9+/]+={0,2})"\}$/);
 if(!match)throw new Error('Invalid Splendor signed payload.');
 if(row.nonce==='0'){const pk=decode(match[1],1952);if('SQ:'+bytesToHex(sha3_256(pk))!==row.address)throw new Error('Signed Splendor key does not match sender.');decode(match[2],3309);}else decode(match[1],3309);
 if(bytesToHex(sha3_256(new TextEncoder().encode(wire)))!==row.hash)throw new Error('Signed Splendor transaction hash mismatch.');
 return wire;
}
