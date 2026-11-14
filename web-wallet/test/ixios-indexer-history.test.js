// Ixios account history from the network's explorer indexer (src/pq/ixios/indexer-history.js), its saved form
// (src/activity-storage.js serializeHistory / parseHistory with the Ixios network id), the gas cap the send form starts
// with (src/pq/ixios/preflight.js readIxiosGasCap) and the pending note with the confirmation count (src/activity.js).
// What this proves: the reader asks only the selected network's indexer, once, for this address; it keeps a row only
// when it involves this address with a well-formed hash, peer, time, positive amount and the status success or failed
// (pending, unknown, zero, malformed and foreign rows are left out); an answer about another address is refused; the
// rows pass the saved-history check and come back from the encrypted record with their network id; a record naming a
// network id on another chain, or an unknown one, is refused; the gas cap is the protocol floor at the checked tip.
// The row shapes are those observed on nx-api.ixoflow.io and ixios-api.ixoflow.io on 2026-11-14.
// Compile flags / environment: none. Leaves nothing behind.
// Falsely passes if: the stub answered any URL (it asserts the URL) or the fixture rows were produced by the code under
// test (they are written here by hand in the indexer's observed shape).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readIxiosHistory, parseIxiosIndexerHistory } from '../src/pq/ixios/indexer-history.js';
import { checkHistoryRows, historySupported, HISTORY_SOURCES } from '../src/history.js';
import { serializeHistory, parseHistory, historyKeyFor } from '../src/activity-storage.js';
import { readIxiosGasCap, ixiosMinimumGasPrice } from '../src/pq/ixios/preflight.js';
import { IXIOS_NETWORKS } from '../src/pq/ixios/network.js';
import { ixiosChecksumAddress } from '../src/pq/ixios/address.js';

const hex = (byte, n) => byte.repeat(n);
const own = '213f17383855d03c1245179d4d769bd3c2d04a9207622c3921e70409ddaf927d3831259ffadb3c26ea3eb065e471f60d';
const peer = '1b7bba86bf3e465c7bc81089677f76d2ad6061b1c70ddaa2eb7fd983e9226f29bc55c57e3803190e120631c8045de278';
const ownAddress = ixiosChecksumAddress(Buffer.from(own, 'hex'));
const row = (over = {}) => ({ hash: hex('a1', 32), from: own, to: peer, amount: '1', txfee: '100', block: 258000, timestamp: 1794665000000, status: 'success', signatureType: 'MLDSA87', ...over });
const answer = rows => ({ address: own, transactions: { page: 0, totalPages: 1, totalCount: rows.length, data: rows } });

test('indexer rows: direction, peer, status and amounts; only rows of this address that check out', () => {
  const rows = parseIxiosIndexerHistory(answer([
    row(),
    row({ hash: hex('b2', 32), from: peer, to: own, amount: '10000', timestamp: 1794665100000 }),
    row({ hash: hex('c3', 32), to: own, amount: '0.5', timestamp: 1794665200000 }),
    row({ hash: hex('d4', 32), status: 'failed', timestamp: 1794664000000 }),
    row({ hash: hex('e5', 32), status: 'pending' }), row({ hash: hex('e6', 32), status: 'unknown' }),
    row({ hash: hex('f7', 32), amount: '0' }), row({ hash: hex('f8', 32), amount: '-1' }), row({ hash: hex('f9', 32), amount: '1.0000000000000000001' }),
    row({ hash: 'zz' }), row({ hash: hex('fa', 32), from: peer, to: peer }), row({ hash: hex('fb', 32), to: 'abc' }), row({ hash: hex('fc', 32), timestamp: '1794665000000' }),
  ]), ownAddress);
  assert.deepEqual(rows.map(r => [r.hash.slice(0, 4), r.dir, r.amount, r.status]),
    [['0xc3', 'self', '0.5', 'confirmed'], ['0xb2', 'in', '10000.0', 'confirmed'], ['0xa1', 'out', '1.0', 'confirmed'], ['0xd4', 'out', '1.0', 'failed']]);
  assert.equal(rows[1].peer, ixiosChecksumAddress(Buffer.from(peer, 'hex')));
  assert.equal(rows[0].peer, '');
  assert.ok(rows.every(r => r.chain === 'ixios' && r.symbol === 'IXIOS' && /^0x[0-9a-f]{64}$/.test(r.hash)));
  assert.deepEqual(checkHistoryRows('ixios', rows), rows);
  assert.ok(historySupported('ixios'));
  assert.equal(HISTORY_SOURCES.ixios, 'IXOFlow indexer');
});

test('a saved Ixios row whose peer is not empty or a 48-byte address is refused', () => {
  const [good] = parseIxiosIndexerHistory(answer([row()]), ownAddress);
  for (const peer of ['abc', '0x' + 'ab'.repeat(20), 'ab'.repeat(48)]) assert.throws(() => checkHistoryRows('ixios', [{ ...good, peer }]), /Invalid saved history/);
  assert.deepEqual(checkHistoryRows('ixios', [{ ...good, peer: '' }]), [{ ...good, peer: '' }]);
});

test('an answer about another address, or without one, is refused', () => {
  assert.throws(() => parseIxiosIndexerHistory({ ...answer([row()]), address: peer }, ownAddress), /Unexpected history response/);
  assert.throws(() => parseIxiosIndexerHistory({ transactions: { data: [row()] } }, ownAddress), /Unexpected history response/);
  assert.deepEqual(parseIxiosIndexerHistory({ address: '0x' + own.toUpperCase() }, ownAddress), []);
});

test('one GET to the selected network\'s indexer for this address', async () => {
  for (const networkId of ['mainnet', 'testnet']) {
    const urls = [];
    const fetcher = async (url, options) => { urls.push([url, options?.method]); return Response.json(answer([row()])); };
    const rows = await readIxiosHistory(ownAddress, { networkId, fetcher });
    assert.equal(rows.length, 1);
    assert.deepEqual(urls, [[`${IXIOS_NETWORKS[networkId].indexer}/v1/address/0x${own}`, 'GET']]);
  }
  assert.equal(IXIOS_NETWORKS.mainnet.indexer, 'https://ixios-api.ixoflow.io');
  assert.equal(IXIOS_NETWORKS.testnet.indexer, 'https://nx-api.ixoflow.io');
  await assert.rejects(readIxiosHistory(ownAddress, { networkId: 'regtest', fetcher: async () => Response.json({}) }), /Unknown Ixios network/);
});

test('saved history keeps the Ixios network id; a misplaced or unknown id is refused', async () => {
  const id = Buffer.alloc(16, 3).toString('base64'), key = await historyKeyFor('abandon '.repeat(23) + 'art', id);
  const rows = parseIxiosIndexerHistory(answer([row()]), ownAddress);
  const back = await parseHistory(await serializeHistory(id, { ixios: { address: ownAddress, networkId: 'testnet', readAt: 1794665000000, rows } }, key), id, key, 1794665000000);
  assert.deepEqual(back.ixios, { address: ownAddress, readAt: 1794665000000, rows, networkId: 'testnet' });
  const plain = await parseHistory(await serializeHistory(id, { ixios: { address: ownAddress, readAt: 1794665000000, rows } }, key), id, key, 1794665000000);
  assert.equal(Object.hasOwn(plain.ixios, 'networkId'), false);
  await assert.rejects(parseHistory(await serializeHistory(id, { ixios: { address: ownAddress, networkId: 'regtest', readAt: 1794665000000, rows } }, key), id, key, 1794665000000), /Invalid saved history/);
});

test('the gas cap is the protocol floor at the checked tip of the selected network', async () => {
  const node = (net, height) => async (_url, options) => {
    const q = JSON.parse(options.body), name = q.method.slice(q.method.indexOf('_') + 1);
    const result = name === 'chainId' ? '0x' + net.chainId.toString(16)
      : q.params[0] === '0x1' ? { number: '0x1', parentHash: net.genesisHash }
      : { number: '0x' + height.toString(16), hash: '0x' + hex('ab', 32), timestamp: '0x' + Date.now().toString(16) };
    return Response.json({ jsonrpc: '2.0', id: q.id, result });
  };
  assert.equal(await readIxiosGasCap({ networkId: 'mainnet', fetcher: node(IXIOS_NETWORKS.mainnet, 32794185n) }), '93000000000000000');
  assert.equal(await readIxiosGasCap({ networkId: 'testnet', fetcher: node(IXIOS_NETWORKS.testnet, 258815n) }), '100000000000000000');
  assert.equal(ixiosMinimumGasPrice(258815n, 300n), 100000000000000000n);
  await assert.rejects(readIxiosGasCap({ networkId: 'testnet', fetcher: node(IXIOS_NETWORKS.mainnet, 258815n) }), /Wrong Ixios network/);
});
