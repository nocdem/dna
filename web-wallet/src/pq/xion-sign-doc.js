// Offline, unsigned Cosmos SIGN_MODE_DIRECT encoding experiment. This module
// does not establish that XION accepts this account key type, sign, or submit.
// Pinned SDK proto: 64fd208a11fb54f7ffdca1a1290c2cfbbc254e49,
// cosmos/{tx/v1beta1/tx.proto,bank/v1beta1/tx.proto,crypto/mldsa65/keys.proto}.
// keys.proto warns this PubKey is validator-only; account acceptance is unresolved.
import { bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
const encoder = new TextEncoder();
const chains = Object.freeze({mainnet:'xion-mainnet-1',testnet:'xion-testnet-2'});
const MAX64 = (1n << 64n)-1n, MAX_HEIGHT=(1n << 63n)-1n, MAX256=(1n<<256n)-1n;
function number(s, max, name, positive=false) {
  if (typeof s !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(s) || BigInt(s)>max || (positive && s==='0')) throw new Error(`Invalid ${name}.`);
  return BigInt(s);
}
function address(s) {
  try {
    if (typeof s !== 'string' || s !== s.toLowerCase()) throw 0;
    const d=bech32.decode(s), b=bech32.fromWords(d.words);
    if(d.prefix!=='xion'||b.length!==20||bech32.encode('xion',bech32.toWords(b))!==s) throw 0;
  } catch { throw new Error('Invalid XION address.'); }
}
function join(...xs) { let n=0; for(const x of xs)n+=x.length; const r=new Uint8Array(n); let p=0; for(const x of xs){r.set(x,p);p+=x.length;} return r; }
function varint(x) { const r=[]; do { let b=Number(x&127n);x>>=7n;if(x)b|=128;r.push(b); }while(x);return Uint8Array.from(r); }
function bytesField(i,b) { return join(varint(BigInt(i*8+2)),varint(BigInt(b.length)),b); }
function stringField(i,s) { return bytesField(i,encoder.encode(s)); }
function uintField(i,n) { return n===0n ? new Uint8Array() : join(varint(BigInt(i*8)),varint(n)); }
function any(type,value) { return join(stringField(1,type),bytesField(2,value)); }
function coin(amount) { return join(stringField(1,'uxion'),stringField(2,amount)); }
/** Returns fresh byte arrays {bodyBytes, authInfoBytes, signDocBytes}; not signed. */
export function buildXionDirectSignDoc({networkId,from,to,amount,fee,gas,sequence,accountNumber,publicKey,timeoutHeight}={}) {
  if(!Object.hasOwn(chains,networkId)) throw new Error('Unsupported XION network.');
  address(from);address(to);
  number(amount,MAX256,'amount',true);number(fee,MAX256,'fee');
  const g=number(gas,MAX64,'gas',true), seq=number(sequence,MAX64,'sequence'), acct=number(accountNumber,MAX64,'account number');
  if(!(publicKey instanceof Uint8Array)||publicKey.length!==1952) throw new Error('Invalid XION public key.');
  if (bech32.encode('xion',bech32.toWords(sha256(publicKey).subarray(0,20))) !== from) throw new Error('XION public key does not match sender.');
  const msg=join(stringField(1,from),stringField(2,to),bytesField(3,coin(amount)));
  const timeout=timeoutHeight===undefined ? 0n : number(timeoutHeight,MAX_HEIGHT,'timeout height',true);
  const bodyBytes=join(bytesField(1,any('/cosmos.bank.v1beta1.MsgSend',msg)),uintField(3,timeout));
  const pub=any('/cosmos.crypto.mldsa65.PubKey',bytesField(1,publicKey));
  // ModeInfo.Single { mode: SIGN_MODE_DIRECT (1) }.
  const signer=join(bytesField(1,pub),bytesField(2,bytesField(1,uintField(1,1n))),uintField(3,seq));
  const feeBytes=join(...(fee==='0'?[]:[bytesField(1,coin(fee))]),uintField(2,g));
  const authInfoBytes=join(bytesField(1,signer),bytesField(2,feeBytes));
  const signDocBytes=join(bytesField(1,bodyBytes),bytesField(2,authInfoBytes),stringField(3,chains[networkId]),uintField(4,acct));
  return {bodyBytes,authInfoBytes,signDocBytes};
}

/** Serialize one already-signed direct transaction; this does not verify a signature. */
export function encodeXionTxRaw({bodyBytes,authInfoBytes,signature}={}) {
  if (!(bodyBytes instanceof Uint8Array) || !bodyBytes.length || !(authInfoBytes instanceof Uint8Array) || !authInfoBytes.length || !(signature instanceof Uint8Array) || signature.length !== 3309) throw new Error('Invalid XION signed transaction components.');
  return join(bytesField(1,bodyBytes),bytesField(2,authInfoBytes),bytesField(3,signature));
}
