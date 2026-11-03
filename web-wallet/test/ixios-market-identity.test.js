import test from 'node:test';import assert from 'node:assert/strict';
import {IXIOS_ASSET} from '../src/pq/ixios/network.js';import {PRICE_URL,PRICE_ASSETS} from '../src/portfolio.js';
test('IXIOS absent verified USD feed remains unpriced, never Ixian or a silent USDT peg',()=>{
 assert.equal(IXIOS_ASSET.symbol,'IXIOS');assert.equal(IXIOS_ASSET.priceId,undefined);
 assert.equal(PRICE_ASSETS.some(asset=>asset.chain==='ixios'),false);
 assert.equal(PRICE_URL.toLowerCase().includes('ixian'),false);
});
