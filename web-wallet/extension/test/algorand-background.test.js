import test from 'node:test';
import assert from 'node:assert/strict';
import { createAlgorand } from '../src/background/algorand.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createWalletUi } from '../src/ui/wallet-ui.js';

const defer=()=>{let resolve;return {promise:new Promise(r=>{resolve=r;}),get resolve(){return resolve;}};};
async function setup(options={}) {
  const lockCoordinator=createLockCoordinator();await lockCoordinator.unlock(async()=>{});
  const rows=[],events=[];let page=null,network='mainnet',secretReads=0,cancels=0;
  const activity={ready:Promise.resolve(),rows:()=>rows,history:()=>page,error:()=>'',assertSendable(){},
    append(review,details){const row={...review,...details,status:'pending'};rows.push(row);events.push('append');return row;},
    async persist(){events.push('persist');await options.persist?.();},async saveHistory(value){page=value;}};
  const prepare=options.prepare??(async fields=>({...fields,from:'main-address',fee:'0.001 ALGO',expiresAt:Date.now()+10000,review:[['Network','Algorand mainnet']],cancel(){cancels++;},async confirm(before){assert.equal(fields.wallet.recoveryPhrase,'synthetic words');await before({hash:'A'.repeat(52),lastValidBlockHeight:123});if(options.error)throw options.error;events.push('post');return 'A'.repeat(52);}}));
  const controller=createAlgorand({lockCoordinator,getWalletKeys:()=>({getPqAddresses:()=>({algorand:{mainnet:'main-address',testnet:'test-address'}}),getRecoveryPhrase(){secretReads++;return 'synthetic words';}}),getActivity:(chain,id)=>{events.push(`activity:${chain}:${id}`);return activity;},getNetwork:()=>({id:network}),prepare,
    readBalances:options.readBalances??(async(address,{networkId})=>[{symbol:'ALGO',balance:address+networkId}]),readHistory:async()=>[],watch:()=>()=>{},...options.dependencies});
  return {controller,lockCoordinator,rows,events,activity,setNetwork(id){network=id;controller.networkChanged();},get secretReads(){return secretReads;},get cancels(){return cancels;}};
}
const fields={symbol:'ALGO',to:'recipient',amount:'1'};
test('trusted Algorand review is public, durable before submission, and consumed once',async()=>{
  const s=await setup(),r=await s.controller.prepareSend(fields);
  assert.equal(s.secretReads,0);assert.equal(JSON.stringify(r).includes('wallet'),false);
  assert.equal(await s.controller.confirmSend(r.id),'A'.repeat(52));
  assert.deepEqual(s.events,['activity:algorand:mainnet','append','persist','post']);
  assert.equal(s.secretReads,1);await assert.rejects(s.controller.confirmSend(r.id),/already closed/);
  await assert.rejects(s.controller.prepareSend(fields),/unresolved/);
});
test('lock and network change cancel reviews; testnet send never derives signing material',async()=>{
  const s=await setup(),r=await s.controller.prepareSend(fields);s.setNetwork('testnet');
  assert.equal(s.cancels,1);await assert.rejects(s.controller.confirmSend(r.id),/already closed/);
  await assert.rejects(s.controller.prepareSend(fields),/mainnet/);assert.equal(s.secretReads,0);
  assert.deepEqual(await s.controller.getBalances(),[{symbol:'ALGO',balance:'test-addresstestnet'}]);
  await s.lockCoordinator.lock();await assert.rejects(s.controller.getHistory(),/locked/);
});
test('late prepare and reads cannot escape a locked session',async()=>{
  const p=defer();let cancelled=0;const s=await setup({prepare:()=>p.promise});
  const result=s.controller.prepareSend(fields);await new Promise(r=>setImmediate(r));
  await s.lockCoordinator.lock();await assert.rejects(result,/changed/);
  p.resolve({cancel(){cancelled++;}});await new Promise(r=>setImmediate(r));assert.equal(cancelled,1);
});
test('pre-submit marker is persisted as failed; uncertain submission remains held',async()=>{
  for(const notSubmitted of [true,false]){
    const error=Object.assign(new Error('synthetic failure'),notSubmitted?{algorandNotSubmitted:true}:{});
    const s=await setup({error}),r=await s.controller.prepareSend(fields);
    await assert.rejects(s.controller.confirmSend(r.id),e=>e.data.activityTracked===true);
    assert.equal(s.rows[0].status,notSubmitted?'failed':'unknown');assert.equal(s.rows[0].notSubmitted,notSubmitted?true:undefined);
    assert.equal(s.events.filter(e=>e==='persist').length,2);assert.ok(!s.events.includes('post'));
  }
});
test('lock while durable storage is pending prevents submission',async()=>{
  const gate=defer(),s=await setup({persist:()=>gate.promise}),r=await s.controller.prepareSend(fields);
  const result=s.controller.confirmSend(r.id);await new Promise(r=>setImmediate(r));await s.lockCoordinator.lock();
  await assert.rejects(result,/changed/);gate.resolve();await new Promise(r=>setImmediate(r));assert.ok(!s.events.includes('post'));
});
test('Algorand UI sends only trusted RPCs and drops stale network history',async()=>{
  const calls=[],gate=defer();let network='mainnet';
  const ui=createWalletUi({async request(method,args){calls.push([method,args]);if(method==='getState')return {isUnlocked:true,addresses:{},pqAddresses:{algorand:{mainnet:'a',testnet:'b'}},networks:{algorand:network}};if(method==='getAlgorandHistory')return gate.promise;return {};}});
  await ui.refresh();await ui.prepareSolanaTronSend({chain:'algorand',...fields});await ui.confirmSolanaTronSend('algorand','r');await ui.cancelSolanaTronSend('algorand','r');
  const pending=ui.loadSolanaTronHistory('algorand');network='testnet';await ui.refresh();gate.resolve({network:'mainnet',rows:[]});await pending;
  assert.equal(ui.state.solanaTronHistory.algorand,undefined);
  assert.deepEqual(calls.slice(1,4).map(c=>c[0]),['prepareAlgorandSend','confirmAlgorandSend','cancelAlgorandSend']);
});

test('real guarded recovery derivation signs Falcon and durably encrypts network activity before mocked POST',async t=>{
  const {readFile}=await import('node:fs/promises');
  const {createNetworkActivity}=await import('../src/background/network-activity.js');
  const {activityKeyFor,historyKeyFor,parseActivity}=await import('../../src/activity-storage.js');
  const {ACTIVITY_KEY,VAULT_KEY}=await import('../../src/vault.js');
  const {algorandNetwork}=await import('../../src/pq/algorand.js');
  const {ALGORAND_FALCON_PROTOCOL}=await import('../../src/pq/algorand-prepare.js');
  const {sha512_256}=await import('@noble/hashes/sha512');
  const {base32nopad}=await import('@scure/base');
  const fixture=JSON.parse(await readFile(new URL('../../test/fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];
  const address=fixture.addresses.algorand.mainnet,id=Buffer.alloc(16,3).toString('base64');
  const network={id:'mainnet',endpoint:algorandNetwork().algod},bucket=`${ACTIVITY_KEY}.algorand.mainnet`,values={[VAULT_KEY]:'synthetic vault'};
  const session={id,addresses:{algorand:address},vault:values[VAULT_KEY],key:await activityKeyFor(fixture.phrase,id),historyKey:await historyKeyFor(fixture.phrase,id)};
  const storage={async get(keys){return Object.fromEntries(keys.map(k=>[k,values[k]]));},async set(v){Object.assign(values,v);}};
  const activity=createNetworkActivity({chain:'algorand',network,session,storage,current(){}});
  const lockCoordinator=createLockCoordinator();await lockCoordinator.unlock(async()=>{});
  let posts=0,secretReads=0;const savedFetch=globalThis.fetch;t.after(()=>{globalThis.fetch=savedFetch;});
  globalThis.fetch=async(target,options={})=>{
    const url=String(target);
    if(url===new URL('../../src/pq/algorand-sign.wasm',import.meta.url).href)return new Response(await readFile(new URL(url)));
    assert.ok(url.startsWith(network.endpoint+'/v2/'),'unexpected network request');
    if(options.method==='POST'){
      posts++;const restored=await parseActivity(values[bucket],id,session.addresses,session.key);
      assert.equal(restored.length,1);assert.equal(restored[0].lastValidBlockHeight,200);
      const body=Buffer.from(options.body);assert.equal(body[0],0x82);assert.equal(body.subarray(1,7).toString('hex'),'a57071736967');
      const marker=body.indexOf(Buffer.from([0xa3,0x74,0x78,0x6e]));assert.ok(marker>3000);
      const tx=body.subarray(marker+4);assert.equal(tx[0]&0xf0,0x80);
      const txId=base32nopad.encode(sha512_256(Buffer.concat([Buffer.from('TX'),tx])));
      assert.equal(restored[0].hash,txId);assert.ok(!JSON.stringify(values).includes(fixture.phrase));
      return new Response(JSON.stringify({txId}));
    }
    if(url.endsWith('/transactions/params'))return new Response(JSON.stringify({'consensus-version':ALGORAND_FALCON_PROTOCOL,'genesis-hash':algorandNetwork().genesisHash,'genesis-id':'mainnet-v1.0','last-round':100,'min-fee':1000,fee:0}));
    if(url===`${network.endpoint}/v2/accounts/${address}?exclude=all`)return new Response(JSON.stringify({address,round:100,amount:10000000,'min-balance':100000}));
    throw Error('Unexpected synthetic request '+url);
  };
  const controller=createAlgorand({lockCoordinator,getWalletKeys:()=>({getPqAddresses:()=>({algorand:{mainnet:address}}),getRecoveryPhrase(){secretReads++;return fixture.phrase;}}),getActivity:()=>activity,getNetwork:()=>network,watch:()=>()=>{}});
  const review=await controller.prepareSend({symbol:'ALGO',to:address,amount:'0.000001'});assert.equal(secretReads,0);assert.equal(posts,0);
  const hash=await controller.confirmSend(review.id);assert.match(hash,/^[A-Z2-7]{52}$/);assert.equal(posts,1);assert.equal(secretReads,1);
  await assert.rejects(controller.confirmSend(review.id),/already closed/);assert.equal(posts,1);
  const testBucket=createNetworkActivity({chain:'algorand',network:{id:'testnet',endpoint:algorandNetwork('testnet').algod},session,storage,current(){}});await testBucket.ready;assert.deepEqual(testBucket.rows(),[]);
  activity.rows()[0].status='failed';activity.rows()[0].notSubmitted=true;await activity.persist();
  const restored=await parseActivity(values[bucket],id,session.addresses,session.key);assert.equal(restored[0].notSubmitted,true);
  await lockCoordinator.lock();
});

test('extension ALGO send is mainnet only; shared registry and ALGO testnet stay receive-only',async()=>{
  const {extensionCapabilitiesFor,extensionPageSupported,extensionNetworkConfig}=await import('../src/constants/capabilities.js');
  const {capabilitiesFor}=await import('../../src/capabilities.js');const {PQ_NETWORKS}=await import('../../src/pq/networks.js');
  assert.equal(extensionCapabilitiesFor('algorand','mainnet').send,true);
  assert.equal(extensionPageSupported('algorand','send','mainnet'),true);
  for(const id of ['testnet',undefined,'unknown']){assert.equal(extensionCapabilitiesFor('algorand',id).send,false);assert.equal(extensionNetworkConfig('algorand',PQ_NETWORKS.algorand,id).receiveOnly,true);}
  assert.equal(extensionNetworkConfig('algorand',PQ_NETWORKS.algorand,'mainnet').receiveOnly,false);
  assert.equal(capabilitiesFor('algorand').send,false);assert.equal(PQ_NETWORKS.algorand.receiveOnly,true);
  for(const chain of ['tidecoin','qtc','xion','asentum'])assert.equal(capabilitiesFor(chain).send,false); // No global/Connect permission expansion.
});

test('extension saved recipients validate Algorand checksum rather than accepting address-shaped text',async()=>{
 const {ADDRESS_CHECKS}=await import('../src/ui/address-book-page.js');const {readFile}=await import('node:fs/promises');
 const fixture=JSON.parse(await readFile(new URL('../../test/fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0];const address=fixture.addresses.algorand.mainnet;
 assert.equal(ADDRESS_CHECKS.algorand(address),address);assert.throws(()=>ADDRESS_CHECKS.algorand('A'.repeat(58)));assert.throws(()=>ADDRESS_CHECKS.algorand(address.toLowerCase()));
});
