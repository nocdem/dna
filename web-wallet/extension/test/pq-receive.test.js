// Parent tests actual keygen artifacts + existing vault/lock/trusted port.
// Public fixtures only; setup intercepts all transport; no broadcasts/skips.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createLockCoordinator } from '../src/background/lock.js';
import { createWalletKeys } from '../src/background/wallet-keys.js';
import { setup, password, unlockOptions } from './solana-tron-fixture.js';

const fixture=JSON.parse(readFileSync(new URL('../../test/fixtures/pq-receive.json',import.meta.url))).vectors[0];
const options={...unlockOptions,pqWasmBytes:readFileSync(new URL('../../src/pq/receive-keygen.wasm',import.meta.url))};

test('extension holder regenerates every PQ address and returns isolated public copies', async () => {
  const lockCoordinator=createLockCoordinator(),keys=createWalletKeys({lockCoordinator,consumeNodusSeed:()=>null});
  assert.throws(keys.getPqAddresses,/locked/);assert.throws(keys.getPqErrors,/locked/);
  try {
    await lockCoordinator.unlock(()=>keys.unlock(fixture.phrase,options));
    assert.deepEqual(keys.getPqAddresses(),fixture.addresses);assert.deepEqual(keys.getPqErrors(),{});
    const copy=keys.getPqAddresses();copy.qtc.mainnet='modified';delete copy.algorand;
    assert.deepEqual(keys.getPqAddresses(),fixture.addresses);
    assert.equal(typeof keys.getAddresses().ethereum,'string');assert.equal(keys.getAddresses().qtc,undefined);
    await lockCoordinator.lock();
    assert.throws(keys.getPqAddresses,/locked/);assert.throws(keys.getPqErrors,/locked/);
    await lockCoordinator.unlock(()=>keys.unlock(fixture.phrase,options));
    assert.deepEqual(keys.getPqAddresses(),fixture.addresses);
  } finally {await lockCoordinator.lock();}
});

test('a PQ module failure leaves existing wallet addresses usable and new addresses unavailable', async () => {
  const lockCoordinator=createLockCoordinator(),keys=createWalletKeys({lockCoordinator,consumeNodusSeed:()=>null});
  try {
    await lockCoordinator.unlock(()=>keys.unlock(fixture.phrase,{...options,pqWasmBytes:new Uint8Array()}));
    assert.equal(keys.getAddresses().ethereum,'0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
    assert.ok(keys.getAddresses().cpunk);assert.deepEqual(keys.getPqAddresses(),{});
    assert.equal(Object.keys(keys.getPqErrors()).length,8);
  } finally {await lockCoordinator.lock();}
});

test('lock during pending PQ WASM instantiation prevents late session publication', async t => {
  const lockCoordinator=createLockCoordinator(),keys=createWalletKeys({lockCoordinator,consumeNodusSeed:()=>null});
  const original=WebAssembly.instantiate;let entered,release,held;
  const started=new Promise(resolve=>{entered=resolve;}),gate=new Promise(resolve=>{release=resolve;});
  t.mock.method(WebAssembly,'instantiate',async (...args)=>{
    const result=await original(...args),instance=result.instance??result;
    if(instance.exports.pq_receive_derive && !held){held=instance;entered();await gate;}
    return result;
  });
  const pending=lockCoordinator.unlock(()=>keys.unlock(fixture.phrase,options));
  const rejected=assert.rejects(pending,/locked/i);
  await started;
  try {await lockCoordinator.lock();assert.throws(keys.getPqAddresses,/locked/);}
  finally {release();}
  await rejected;
  assert.ok(new Uint8Array(held.exports.memory.buffer).every(x=>x===0));
  assert.equal(lockCoordinator.isLocked,true);assert.throws(keys.getPqAddresses,/locked/);
});

test('trusted state flattens the selected environment, persists only selection, clears on lock', async t => {
  const {background,client,values}=await setup(t);
  await background.lock();await background.unlock(password,options);
  for (const [chain,networks] of Object.entries(fixture.addresses)) for (const [network,address] of Object.entries(networks)) {
    await client.request('setChainNetwork',[chain,network]);
    const state=await client.request('getState');
    assert.equal(state.addresses[chain],address);assert.equal(state.networks[chain],network);
    assert.deepEqual(state.pqAddresses,fixture.addresses);assert.deepEqual(state.pqErrors,{});
    assert.ok(!JSON.stringify(state).includes(fixture.phrase));
  }
  await assert.rejects(client.request('setChainNetwork',['qtc','regtest']),/network/i);
  await assert.rejects(client.request('setChainNetwork',['asentum','mainnet']),/network/i);
  if(values) assert.ok(!JSON.stringify(values).includes(fixture.phrase));
  await background.lock();
  const locked=await client.request('getState');
  assert.deepEqual(locked.addresses,{});assert.deepEqual(locked.pqAddresses,{});assert.deepEqual(locked.pqErrors,{});
});
