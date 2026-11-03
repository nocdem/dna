// Optional independent reference; google-protobuf@3.21.4 is deliberately not
// a production dependency. See README.md. Synthetic public key only.
import jspb from 'google-protobuf';
import {createHash} from 'node:crypto';
import {bech32} from '@scure/base';
import {sha256} from '@noble/hashes/sha2';
const pk=new Uint8Array(1952).fill(3),from=bech32.encode('xion',bech32.toWords(sha256(pk).subarray(0,20))),to=bech32.encode('xion',bech32.toWords(new Uint8Array(20).fill(2)));
const w=fn=>{const x=new jspb.BinaryWriter();fn(x);return x.getResultBuffer();};
const any=(type,value)=>w(x=>{x.writeString(1,type);x.writeBytes(2,value);});
const coin=value=>w(x=>{x.writeString(1,'uxion');x.writeString(2,value);});
const msg=w(x=>{x.writeString(1,from);x.writeString(2,to);x.writeBytes(3,coin('9007199254740993'));});
const body=w(x=>x.writeBytes(1,any('/cosmos.bank.v1beta1.MsgSend',msg)));
for(const test of [false,true]){
 const pub=any('/cosmos.crypto.mldsa65.PubKey',w(x=>x.writeBytes(1,pk)));
 const mode=w(x=>x.writeBytes(1,w(y=>y.writeEnum(1,1))));
 const signer=w(x=>{x.writeBytes(1,pub);x.writeBytes(2,mode);if(!test)x.writeUint64String(3,'18446744073709551615');});
 const fee=w(x=>{if(!test)x.writeBytes(1,coin('7'));x.writeUint64String(2,'200000');});
 const auth=w(x=>{x.writeBytes(1,signer);x.writeBytes(2,fee);});
 const sign=w(x=>{x.writeBytes(1,body);x.writeBytes(2,auth);x.writeString(3,test?'xion-testnet-2':'xion-mainnet-1');if(!test)x.writeUint64String(4,'9223372036854775808');});
 console.log([body,auth,sign].map(x=>createHash('sha256').update(x).digest('hex')));
}
