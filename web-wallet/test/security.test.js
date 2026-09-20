import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { FetchRequest } from 'ethers';
import { Connection } from '@solana/web3.js';
import { TronWeb, utils } from 'tronweb';
import { deriveWallet, disposeWallet } from '../src/keys.js';
import { validateNewPassword, encryptVault, decryptVault } from '../src/vault.js';
import { activityKeyFor, serializeActivity, parseActivity } from '../src/activity-storage.js';
import { rpcFetch, boundedBytes, ethersGetUrl } from '../src/rpc-transport.js';
import { rawInteger, request } from '../src/core.js';
import { createTronClient, prepare as prepareTron, checkNetwork as checkTronNetwork } from '../src/adapters/tron.js';
import { CHAINS } from '../src/config.js';
const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
const endpoint = 'https://rpc.example';
test('RT-02 disposal wipes the original Solana signer buffer, including retained references', () => {
  const wallet = deriveWallet(phrase), retained = wallet.solana, bytes = retained.secretKey;
  assert.ok(bytes.some(Boolean)); assert.equal(retained.secretKey, bytes);
  disposeWallet(wallet);
  assert.equal(wallet.solana, null); assert.ok(bytes.every(byte => byte === 0)); assert.ok(retained.secretKey.every(byte => byte === 0));
});
test('RT-03 weak new passwords fail while legacy weak-password vaults still unlock', async () => {
  for (const password of ['aaaaaaaaaaaa', 'aaaaaaaaaaaaaaaa', 'abcdabcdabcdabcd', 'password12345678', '1234567890123456', 'abcdefghijklmnop', '                ']) {
    assert.throws(() => validateNewPassword(password)); await assert.rejects(encryptVault(phrase, password));
  }
  assert.doesNotThrow(() => validateNewPassword('violet river telescope orchard'));
  const legacy = readFileSync(new URL('./fixtures/legacy-weak-vault.json', import.meta.url), 'utf8');
  const legacyPhrase = (await decryptVault(legacy, 'aaaaaaaaaaaa')).phrase;
  assert.equal(legacyPhrase, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  // Preserve the old encrypted data, but the new Nodus UI only accepts 24 words.
  assert.throws(() => deriveWallet(legacyPhrase), /24-word/);
});
test('RT-04 encrypted activity rejects tampering, different wallet keys and forged v1 history', async () => {
  const id = btoa('0123456789abcdef'), key = await activityKeyFor(phrase, id), wallet = deriveWallet(phrase);
  const row = { chain: 'ethereum', address: wallet.addresses.ethereum, to: '0x' + '1'.repeat(40), symbol: 'ETH', amount: '1', hash: '0x' + '2'.repeat(64), status: 'confirmed', createdAt: new Date().toISOString(), endpoint: 'https://rpc.example?apikey=secret' };
  const a = await serializeActivity(id, [row], key), b = await serializeActivity(id, [row], key);
  assert.notEqual(a, b); for (const plain of [row.address, row.to, row.hash, 'apikey', phrase]) assert.ok(!a.includes(plain));
  assert.equal((await parseActivity(a, id, wallet.addresses, key))[0].status, 'pending');
  for (const field of ['iv', 'ciphertext']) {
    const changed = JSON.parse(a); changed[field] = (changed[field][0] === 'A' ? 'B' : 'A') + changed[field].slice(1);
    await assert.rejects(parseActivity(JSON.stringify(changed), id, wallet.addresses, key), /authentication/);
  }
  for (const field of ['id', 'version', 'cipher']) {
    const changed = JSON.parse(a); changed[field] = 'wrong'; await assert.rejects(parseActivity(JSON.stringify(changed), id, wallet.addresses, key));
  }
  const otherKey = await activityKeyFor('legal winner thank year wave sausage worth useful legal winner thank yellow', id);
  await assert.rejects(parseActivity(a, id, wallet.addresses, otherKey), /authentication/);
  await assert.rejects(parseActivity(JSON.stringify({ version: 1, id, rows: [{ ...row, amount: '999' }] }), id, wallet.addresses, key), /not authenticated/);
  disposeWallet(wallet);
});
test('RT-05 RPC bounds actual streams, declared sizes, JSON complexity and numeric lengths', async () => {
  let cancelled = false;
  const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(100000)); }, cancel() { cancelled = true; } });
  await assert.rejects(request(endpoint, {}, { fetcher: async () => new Response(stream) }), /too large/); assert.ok(cancelled);
  await assert.rejects(rpcFetch(endpoint, {}, { fetcher: async () => new Response('{}', { headers: { 'content-length': '99999999' } }) }), /too large/);
  await assert.rejects(rpcFetch(endpoint, {}, { fetcher: async () => Response.json({ result: Array(4097).fill(1) }) }), /too many/);
  let deep = 1; for (let i = 0; i < 26; i++) deep = { child: deep };
  await assert.rejects(rpcFetch(endpoint, {}, { fetcher: async () => Response.json(deep) }), /data limits/);
  for (const value of ['9'.repeat(100000), '0x' + 'a'.repeat(65), [1], true]) assert.throws(() => rawInteger(value));
  const body = JSON.stringify({ method: 'getTokenAccountsByOwner' });
  const largeValid = { value: Array.from({ length: 1000 }, () => ({ note: 'a'.repeat(400) })) };
  assert.ok((await rpcFetch(endpoint, { method: 'POST', body }, { fetcher: async () => Response.json(largeValid) })).ok);
});
test('RT-05 abort cancels a stalled response body', async () => {
  let cancelled = false;
  const controller = new AbortController();
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }));
  const pending = boundedBytes(response, 1000, controller.signal); controller.abort();
  await assert.rejects(pending, /abort/i); assert.ok(cancelled);
});
test('RT-05 bounds the real Ethers, Solana and TRON SDK transport paths', async t => {
  const old = globalThis.fetch; t.after(() => { globalThis.fetch = old; });
  globalThis.fetch = async () => Response.json({ result: 'x'.repeat(1024 * 1024) });
  const req = new FetchRequest(endpoint); req.getUrlFunc = ethersGetUrl; req.body = JSON.stringify({ method: 'eth_chainId' });
  await assert.rejects(req.send(), /too large/);
  const sol = new Connection(endpoint, { fetch: rpcFetch, disableRetryOnRateLimit: true });
  await assert.rejects(sol.getGenesisHash(), /too large/);
  const tron = createTronClient(endpoint); await assert.rejects(tron.trx.getCurrentBlock(), /too large/);
  let seen;
  globalThis.fetch = async (url, options) => { seen = { url, options }; return Response.json({ blockID: 'example', block_header: {} }); };
  assert.equal((await tron.trx.getCurrentBlock()).blockID, 'example');
  assert.equal(seen.options.redirect, 'error'); assert.equal(seen.options.credentials, 'omit');
  assert.ok(seen.url.endsWith('/wallet/getnowblock'));
});
test('bounded TRON transport preserves native/TRC20 signing and rechecks lock after async persistence', async t => {
  const old = globalThis.fetch; t.after(() => { globalThis.fetch = old; });
  const wallet = deriveWallet(phrase), to = TronWeb.address.fromPrivateKey('2'.repeat(64));
  let broadcasts = 0, persisted = false;
  const timestamp = Date.now();
  globalThis.fetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : {};
    assert.ok(!JSON.stringify(body).includes(phrase)); assert.ok(!JSON.stringify(body).includes(wallet.tronPrivateKey || 'never-a-key'));
    if (url.endsWith('/wallet/getblockbynum')) return Response.json({ blockID: CHAINS.tron.genesisHash });
    if (url.endsWith('/wallet/getblock')) return Response.json({ blockID: 'a'.repeat(64), block_header: { raw_data: { number: 100, timestamp } } });
    if (url.endsWith('/wallet/triggersmartcontract')) {
      const transaction = { visible: false, raw_data: { ref_block_bytes: '0064', ref_block_hash: 'a'.repeat(16), timestamp, expiration: timestamp + 60000, fee_limit: body.fee_limit, contract: [{ type: 'TriggerSmartContract', parameter: { type_url: 'type.googleapis.com/protocol.TriggerSmartContract', value: { owner_address: body.owner_address, contract_address: body.contract_address, data: 'a9059cbb' + body.parameter, call_value: 0 } } }] } };
      const pb = utils.transaction.txJsonToPb(transaction); transaction.raw_data_hex = utils.transaction.txPbToRawDataHex(pb); transaction.txID = utils.transaction.txPbToTxID(pb).replace(/^0x/, '');
      return Response.json({ result: { result: true }, transaction });
    }
    if (url.endsWith('/wallet/broadcasttransaction')) {
      assert.ok(persisted); assert.equal(body.signature.length, 1); assert.ok(utils.transaction.txCheck(body)); broadcasts++;
      return Response.json({ result: true, txid: body.txID });
    }
    throw new Error('Unexpected TRON request ' + url);
  };
  for (const asset of [{ symbol: 'TRX', decimals: 6 }, CHAINS.tron.tokens[0]]) {
    persisted = false;
    const transfer = await prepareTron({ wallet, to, asset, units: 1000000n, endpoint: CHAINS.tron.endpoint });
    await transfer.send(async () => { await Promise.resolve(); persisted = true; });
  }
  assert.equal(broadcasts, 2);
  const transfer = await prepareTron({ wallet, to, asset: { symbol: 'TRX' }, units: 1000000n, endpoint: CHAINS.tron.endpoint });
  await assert.rejects(transfer.send(async () => { await Promise.resolve(); disposeWallet(wallet); }), /locked/);
  assert.equal(broadcasts, 2);
});
test('TRON checks mainnet identity before preparing and immediately before signing', async t => {
  const old = globalThis.fetch; t.after(() => { globalThis.fetch = old; });
  const wallet = deriveWallet(phrase), to = TronWeb.address.fromPrivateKey('2'.repeat(64));
  t.after(() => disposeWallet(wallet));
  const timestamp = Date.now(); let genesis = 'wrong', builds = 0, broadcasts = 0, persisted = 0;
  globalThis.fetch = async url => {
    if (url.endsWith('/wallet/getblockbynum')) return Response.json({ blockID: genesis });
    if (url.endsWith('/wallet/getblock')) { builds++; return Response.json({ blockID: 'a'.repeat(64), block_header: { raw_data: { number: 100, timestamp } } }); }
    broadcasts++; throw new Error('Unexpected request');
  };
  const args = { wallet, to, asset: { symbol: 'TRX' }, units: 1n, endpoint: CHAINS.tron.endpoint + '/' };
  await assert.rejects(prepareTron(args), /not TRON mainnet/); assert.equal(builds, 0);
  genesis = CHAINS.tron.genesisHash;
  await checkTronNetwork(args.endpoint);
  const transfer = await prepareTron(args); genesis = 'wrong';
  await assert.rejects(transfer.send(() => { persisted++; }), /not TRON mainnet/);
  assert.equal(persisted, 0); assert.equal(broadcasts, 0);
});
