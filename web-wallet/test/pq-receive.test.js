// Parent-written independent address/recovery gates. Committed expectations
// come from test/receive-reference, never from src/pq. Public phrases only.
// Runs offline with the built keygen artifact. No skips, persistent secrets,
// broadcasts or compiler flags; no claim of an on-chain spend test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import { derivePqAddresses, pqAddressFromPublicKeys, pqChainSeed } from '../src/pq/receive.js';
import { PQ_NETWORKS, PQ_ENTRIES, pqNetwork, isPqChain } from '../src/pq/networks.js';
import { encryptVault, decryptVault } from '../src/vault.js';
import { prepareTransfer, adapters } from '../src/wallet.js';
import { receiveWasmBytes } from './fixtures/pq-port-vectors.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/pq-receive.json', import.meta.url)));
const algorand = JSON.parse(readFileSync(new URL('./fixtures/pq-receive-algorand.json', import.meta.url)));
const fromHex = hex => Uint8Array.from(Buffer.from(hex,'hex'));
const wasmBytes = receiveWasmBytes();
const phrase = fixture.vectors[0].phrase;

test('complete listed networks are receive-only, unavailable balances and no send adapter', async () => {
  assert.equal(PQ_ENTRIES.length,8);
  assert.equal(Object.values(PQ_NETWORKS).reduce((n,c)=>n+c.networks.length,0),13);
  for (const [chain,c] of Object.entries(PQ_NETWORKS)) {
    assert.equal(c.receiveOnly,true); assert.equal(c.balanceUnavailable,true);
    assert.equal(adapters[chain],undefined);
    for (const network of c.networks) assert.equal(pqNetwork(chain,network.id),network);
    await assert.rejects(prepareTransfer({wallet:{addresses:{}},chain,symbol:c.symbol,to:'unused',amount:'1'}),/Open a wallet/);
    assert.throws(()=>pqNetwork(chain,'regtest'));
  }
  for (const chain of ['__proto__','constructor','toString','',null,{}]) {
    assert.equal(isPqChain(chain),false); assert.throws(()=>pqNetwork(chain));
    assert.throws(()=>pqChainSeed(phrase,chain));
  }
  assert.throws(()=>pqNetwork('asentum','mainnet'));
  assert.throws(()=>pqNetwork('tidecoin','testnet'));
  assert.throws(()=>pqNetwork('soqucoin','testnet'));
});

test('Algorand native 32-byte seed known-answer addresses and exact Go point predicate', () => {
  assert.equal(algorand.rows.length,5);
  for (const row of algorand.rows) for (const network of ['mainnet','testnet'])
    assert.equal(pqAddressFromPublicKeys('algorand',network,fromHex(row.pk)),row.address);
  assert.equal(fixture.curve.length,110);
  for (const row of fixture.curve) {
    let accepted=true;
    try { ed25519.ExtendedPoint.fromHex(fromHex(row.bytes),true); } catch { accepted=false; }
    assert.equal(accepted,row.decodable,`point decoder differs for ${row.bytes}`);
  }
});

for (const [index,row] of fixture.vectors.entries()) {
  test(`Nodus recovery roots match independent Python BIP39/SHAKE: phrase ${index}`, () => {
    assert.equal(Object.keys(row.roots).length,8);
    for (const [chain,expected] of Object.entries(row.roots)) {
      const root=pqChainSeed(row.phrase,chain);
      try { assert.equal(Buffer.from(root).toString('hex'),expected); } finally { root.fill(0); }
    }
    assert.equal(new Set(Object.values(row.roots)).size,8);
  });
  test(`all public-key address formats match independent chain oracles: phrase ${index}`, () => {
    let count=0;
    for (const [chain,networks] of Object.entries(row.addresses)) for (const [network,expected] of Object.entries(networks)) {
      const key=chain==='qtc'?row.keys[chain][network]:row.keys[chain];
      const pk=fromHex(key.pk),before=pk.slice();
      assert.equal(pqAddressFromPublicKeys(chain,network,pk,key.backupPk?fromHex(key.backupPk):undefined),expected);
      assert.deepEqual(pk,before,'encoder must not mutate caller public key'); count++;
    }
    assert.equal(count,13);
  });
  test(`actual WASM + chain KDF + encoding match complete recovery fixture: phrase ${index}`, async () => {
    const published={};
    const result=await derivePqAddresses(row.phrase,{wasmBytes,onAddress(chain,network,address){(published[chain]??={})[network]=address;}});
    assert.deepEqual(result.errors,{});
    assert.deepEqual(result.addresses,row.addresses);
    assert.deepEqual(published,row.addresses);
  });
}

test('native Soqucoin invalid marker and malformed inputs fail closed', () => {
  assert.equal(fixture.soquInvalidMarker.pk.slice(0,2),'ff');
  assert.throws(()=>pqAddressFromPublicKeys('soqucoin','mainnet',fromHex(fixture.soquInvalidMarker.pk)),/Soqucoin/);
  for (const [chain,c] of Object.entries(PQ_NETWORKS)) {
    const key=chain==='qtc'?fixture.vectors[0].keys.qtc.mainnet:fixture.vectors[0].keys[chain];
    const pk=fromHex(key.pk),backup=key.backupPk?fromHex(key.backupPk):undefined;
    for (const bad of [pk.subarray(1),new Uint8Array(pk.length+1),Array.from(pk),null,'00'])
      assert.throws(()=>pqAddressFromPublicKeys(chain,c.defaultNetwork,bad,backup));
    assert.throws(()=>pqAddressFromPublicKeys(chain,'unknown',pk,backup));
  }
  assert.throws(()=>pqAddressFromPublicKeys('qtc','mainnet',fromHex(fixture.vectors[0].keys.qtc.mainnet.pk)));
});

test('full instance memories are zeroed and distinct on successful derivation', async t => {
  const original=WebAssembly.instantiate,instances=[];
  t.mock.method(WebAssembly,'instantiate',async (...args)=>{const result=await original(...args);instances.push(result.instance??result);return result;});
  assert.deepEqual((await derivePqAddresses(phrase,{wasmBytes})).addresses,fixture.vectors[0].addresses);
  assert.equal(instances.length,11);assert.equal(new Set(instances).size,11);
  for (const instance of instances) assert.ok(new Uint8Array(instance.exports.memory.buffer).every(x=>x===0));
});

test('abort after first published address stops all later publication and wipes memory', async t => {
  const original=WebAssembly.instantiate,instances=[],controller=new AbortController();let callbacks=0;
  t.mock.method(WebAssembly,'instantiate',async (...args)=>{const result=await original(...args);instances.push(result.instance??result);return result;});
  await assert.rejects(derivePqAddresses(phrase,{wasmBytes,signal:controller.signal,onAddress(){callbacks++;controller.abort();}}),{name:'AbortError'});
  assert.equal(callbacks,1);assert.equal(instances.length,1);
  for (const instance of instances) assert.ok(new Uint8Array(instance.exports.memory.buffer).every(x=>x===0));
  await assert.rejects(derivePqAddresses(phrase,{wasmBytes,signal:controller.signal}),{name:'AbortError'});
});

test('missing/corrupt module never falls back or publishes a synthetic address', async t => {
  for (const bytes of [new Uint8Array(),Uint8Array.of(0,1,2,3)]) {
    const result=await derivePqAddresses(phrase,{wasmBytes:bytes});
    assert.deepEqual(result.addresses,{});assert.equal(Object.keys(result.errors).length,8);
    assert.ok(Object.values(result.errors).every(x=>!x.includes(phrase)));
  }
  t.mock.method(globalThis,'fetch',async ()=>{throw new Error('network failure with secret-looking text');});
  const result=await derivePqAddresses(phrase);
  assert.deepEqual(result.addresses,{});assert.equal(Object.keys(result.errors).length,8);
  assert.ok(Object.values(result.errors).every(x=>!x.includes('secret-looking')));
  await assert.rejects(derivePqAddresses('abandon',{wasmBytes}));
});

test('existing encrypted vault recovers all addresses without new vault schema or key storage', async () => {
  const password='Pq9!Velvet-Cedar-Moon$47';
  const encrypted=await encryptVault(phrase,password),saved=JSON.parse(encrypted);
  assert.equal(saved.version,1);assert.ok(!encrypted.includes(phrase));
  assert.deepEqual(Object.keys(saved).sort(),['cipher','ciphertext','id','iterations','iv','kdf','salt','version']);
  const restored=await decryptVault(encrypted,password);
  assert.deepEqual((await derivePqAddresses(restored.phrase,{wasmBytes})).addresses,fixture.vectors[0].addresses);
});
