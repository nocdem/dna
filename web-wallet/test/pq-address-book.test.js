import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {bech32m} from '@scure/base';
import {pqAddressBookChecks} from '../src/pq/address-book-checks.js';
import {addAddress,ADDRESS_MAX} from '../src/address-book.js';
const addresses=JSON.parse(await readFile(new URL('./fixtures/pq-receive.json',import.meta.url),'utf8')).vectors[0].addresses;
test('new PQ saved recipients use the send-format checks without changing send gates',async()=>{
  const {ADDRESS_CHECKS}=await import('../extension/src/ui/address-book-page.js');
  for(const chain of Object.keys(pqAddressBookChecks)){
    const address=addresses[chain][chain==='asentum'?'testnet':'mainnet'];
    assert.equal(pqAddressBookChecks[chain](address),address);assert.equal(ADDRESS_CHECKS[chain](address),address);
    assert.equal(addAddress([],{network:chain,address,label:'Public synthetic recipient'},pqAddressBookChecks)[0].address,address);
  }
});
test('PQ recipient checks reject malformed, wrong checksum/network and zero SPLD',()=>{
  for(const chain of Object.keys(pqAddressBookChecks))assert.throws(()=>pqAddressBookChecks[chain]('not an address'));
  for(const chain of ['ckb','qtc'])assert.throws(()=>pqAddressBookChecks[chain](addresses[chain].testnet));
  assert.throws(()=>pqAddressBookChecks.asentum(addresses.asentum.testnet.slice(0,-1)+'x'));
  assert.throws(()=>pqAddressBookChecks.splendor('SQ:'+'0'.repeat(64)));
});
test('long full-format CKB can validate for sending but existing saved-address storage limit remains explicit',()=>{
  const payload=new Uint8Array(134);payload[33]=1;
  const address=bech32m.encode('ckb',bech32m.toWords(payload),1023);
  assert.ok(address.length>128);assert.equal(pqAddressBookChecks.ckb(address),address);assert.equal(ADDRESS_MAX,128);
  assert.throws(()=>addAddress([],{network:'ckb',address,label:'Long recipient'},pqAddressBookChecks),/cannot be saved/);
});
