import test from 'node:test';
import assert from 'node:assert/strict';
import { PQ_PRICE_IDS, validatedAssetPrices } from '../src/pq/prices.js';
import { PQ_ENTRIES } from '../src/pq/networks.js';
const now = 1800000000000;
const assets = PQ_ENTRIES.map(({asset}) => asset);
const row = { symbol: 'ALGO', price: .2, confidence: .99, timestamp: now / 1000 };
const parse = coins => validatedAssetPrices({coins}, assets, now, 900000);
test('known native identities are priced only with validated live quotes', () => {
  assert.equal(PQ_PRICE_IDS.algorand, 'coingecko:algorand');
  assert.deepEqual(parse({'coingecko:algorand': row}), {'algorand:ALGO': {units: 20000000n, observedAt: now}});
  assert.deepEqual(parse({}), {});
  for (const chain of ['qtc','splendor','asentum']) assert.equal(PQ_PRICE_IDS[chain], undefined);
});
test('stale, untrusted, symbol-confused, invalid and unavailable prices never become zero', () => {
  for (const bad of [{timestamp: now/1000-901}, {timestamp: now/1000+61}, {confidence:.89}, {confidence:1.1}, {symbol:'QTC'}, {price:0}, {price:-1}, {price:NaN}, {price:Infinity}, {price:1e10}]) {
    assert.deepEqual(parse({'coingecko:algorand': {...row,...bad}}), {});
  }
});
test('testnet identity cannot produce USD values', () => {
  assert.deepEqual(validatedAssetPrices({coins:{'coingecko:algorand':row}}, [{...assets[0],testnet:true}], now,900000), {});
  assert.deepEqual(validatedAssetPrices({coins:{'coingecko:algorand':row}}, [{...assets[0],priceId:undefined}],now,900000), {});
});
