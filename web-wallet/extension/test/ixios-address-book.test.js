import test from 'node:test';import assert from 'node:assert/strict';
import {ADDRESS_CHECKS} from '../src/ui/address-book-page.js';
import {ixiosChecksumAddress} from '../../src/ixios/address.js';
test('IXIOS saved recipient preserves exact 48-byte identity and rejects Ethereum-width addresses',()=>{
 const bytes=Uint8Array.from({length:48},(_,i)=>i+20),checked=ixiosChecksumAddress(bytes);
 assert.equal(ADDRESS_CHECKS.ixios(checked.toLowerCase()),checked);
 assert.equal(ADDRESS_CHECKS.ixios(checked),checked);
 assert.throws(()=>ADDRESS_CHECKS.ixios('0x'+'11'.repeat(20)),/48-byte/);
 assert.throws(()=>ADDRESS_CHECKS.ixios('0x'+'11'.repeat(32)),/48-byte/);
 const letter=[...checked].findIndex((c,i)=>i>1&&/[A-Fa-f]/.test(c));const bad=checked.slice(0,letter)+(checked[letter]===checked[letter].toUpperCase()?checked[letter].toLowerCase():checked[letter].toUpperCase())+checked.slice(letter+1);
 assert.throws(()=>ADDRESS_CHECKS.ixios(bad),/checksum/);
});
