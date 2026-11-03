// Content-addressed transparent prevout evidence. This proves txid/output bytes,
// not canonical-chain inclusion, maturity, or mempool unspentness.
import {sha256} from '@noble/hashes/sha256';
import {hexToBytes,bytesToHex,concatBytes} from '@noble/hashes/utils';
export function decodeQtcPrevoutTransaction(hex){
 if(typeof hex!=='string'||hex.length>262144||!/^([0-9a-f]{2})+$/.test(hex))throw Error('Invalid QTC previous transaction bytes.');
 const raw=hexToBytes(hex);let at=0;
 const take=n=>{if(!Number.isSafeInteger(n)||n<0||at+n>raw.length)throw Error('Truncated QTC previous transaction.');const b=raw.subarray(at,at+n);at+=n;return b;};
 const uint=n=>{let v=0n;const b=take(n);for(let i=n-1;i>=0;i--)v=v*256n+BigInt(b[i]);return v;};
 const compact=()=>{const first=Number(uint(1));if(first<253)return first;if(first!==253)throw Error('Oversized QTC previous transaction field.');const n=Number(uint(2));if(n<253)throw Error('Noncanonical QTC compact integer.');return n;};
 const version=uint(4);if(version!==1n&&version!==2n)throw Error('Unsupported QTC previous transaction version.');
 let witness=false;if(raw[at]===0){take(1);if(uint(1)!==1n)throw Error('Unsupported QTC witness flag.');witness=true;}
 const bodyStart=at,count=compact();if(count<1||count>4096)throw Error('Invalid QTC previous input count.');let coinbase=false;
 for(let i=0;i<count;i++){const hash=take(32),vout=uint(4);if(i===0&&count===1&&hash.every(b=>b===0)&&vout===0xffffffffn)coinbase=true;take(compact());uint(4);}
 const n=compact();if(n<1||n>4096)throw Error('Invalid QTC previous output count.');const outputs=[];let total=0n;
 for(let i=0;i<n;i++){const value=uint(8);total+=value;if(total>2100000000000000n)throw Error('Invalid QTC previous output value.');outputs.push({value,script:bytesToHex(take(compact()))});}
 const bodyEnd=at;let nonempty=false;if(witness)for(let i=0;i<count;i++){const stack=compact();if(stack>100)throw Error('Oversized QTC previous witness.');if(stack)nonempty=true;for(let j=0;j<stack;j++)take(compact());}if(witness&&!nonempty)throw Error('Superfluous QTC witness marker.');
 const lockStart=at;uint(4);if(at!==raw.length)throw Error('Trailing QTC previous transaction bytes.');
 const stripped=concatBytes(raw.subarray(0,4),raw.subarray(bodyStart,bodyEnd),raw.subarray(lockStart));
 return {txid:bytesToHex(sha256(sha256(stripped)).reverse()),outputs,coinbase};
}
